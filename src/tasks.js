// Ported from AdaptixC2 (https://github.com/Adaptix-Framework/AdaptixC2),
// AdaptixServer/extenders/beacon_agent/src_beacon/beacon/pl_packer.go (PackArray LE / Parse* BE) + Packer.cpp + Commander.cpp (task framing) — GPLv3, (c) the
// AdaptixC2 authors. Structural fidelity is deliberate; deviations are noted inline.
// tasks.js — Adaptix beacon task-channel framing (server -> agent -> server).
//
// The protocol is ASYMMETRIC (verified against pl_packer.go / Packer.cpp):
//
//  server->agent (after RC4): LITTLE-ENDIAN
//    u32le total_size            (payload length, NOT counting itself)
//    per task:  u32le command_id | <args: u32le ints, u32le len + bytes + NUL> | u32le task_id
//    (written by Go PackArray; read by C++ Unpack32 = raw memcpy = LE on x86)
//
//  agent->server (after RC4): BIG-ENDIAN
//    u32be total_size            (counts ITSELF — C++ Set32(0, datasize()))
//    per result: u32be task_id | u32be command_id | <result fields>
//    result ints: u32be; result strings/bytes: u32be length + raw bytes (no NUL)
//    (written by C++ Packer::Pack32/PackBytes; read by Go ParseInt32 BigEndian)
//
// Sources: extenders/beacon_agent/pl_packer.go (PackArray LE / Parse* BE),
//          src_beacon/beacon/Packer.cpp (Pack32 BE, PackBytes BE len + raw),
//          src_beacon/beacon/Commander.cpp (task parse + reply layout),
//          src_beacon/beacon/MainAgent.cpp (Set32 self-counting size),
//          pl_main.go ProcessData (server-side result parse).

const CP = {
  PWD: 4,
  TERMINATE: 10,
  PROFILE: 21,
  GETUID: 22,
  DISKS: 15,
  REV2SELF: 23,
  PS_LIST: 41,
  JOB_LIST: 46,
  JOB_KILL: 47,
  CD: 8,
  LS: 14,
  CAT: 24,
  RM: 17,
  MKDIR: 27,
  PS_KILL: 42,
  SHELL_START: 71,
  EXEC_BOF: 50,
  EXEC_BOF_OUT: 51,
};

// commands with NO args before the trailing task_id (safe generic replies)
// (JOB_LIST 46 is NOT here — bof.js answers it with the live async-BOF table)
const NO_ARG_COMMANDS = new Set([CP.PWD, CP.TERMINATE, CP.DISKS, CP.GETUID, CP.REV2SELF]);

// ---- INBOUND reader (server->agent, LITTLE-endian) -----------------------
class TaskReader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
    if (buf.length >= 4) {
      const total = buf.readUInt32LE(0);
      this.end = Math.min(buf.length, 4 + total); // total = payload length
      this.pos = 4;
    } else {
      this.end = buf.length;
    }
  }
  get hasMore() { return this.pos + 8 <= this.end; }
  u32() { if (this.pos + 4 > this.end) throw new Error('task stream underrun (u32)'); const v = this.buf.readUInt32LE(this.pos); this.pos += 4; return v; }
  u8() { if (this.pos + 1 > this.end) throw new Error('task stream underrun (u8)'); const v = this.buf[this.pos]; this.pos += 1; return v; }
  str() {
    const len = this.u32();
    if (this.pos + len > this.end) throw new Error('task stream underrun (str)');
    let s = this.buf.slice(this.pos, this.pos + len); this.pos += len;
    while (s.length && s[s.length - 1] === 0) s = s.slice(0, -1); // strip NUL(s)
    return s.toString('utf8');
  }
  raw() {
    const len = this.u32();
    if (this.pos + len > this.end) throw new Error('task stream underrun (bytes)');
    const b = this.buf.slice(this.pos, this.pos + len); this.pos += len;
    return b;
  }
}

// ---- OUTBOUND packer (agent->server, BIG-ENDIAN) --------------------------
class OutPacker {
  constructor() { this.parts = []; }
  u32(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0, 0); this.parts.push(b); return this; }
  u8(v) { this.parts.push(Buffer.from([v & 0xff])); return this; }
  u16(v) { const b = Buffer.alloc(2); b.writeUInt16BE(v & 0xffff, 0); this.parts.push(b); return this; }
  u64(v) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v) & 0xffffffffffffffffn, 0); this.parts.push(b); return this; }
  bytes(data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    this.parts.push(len, data); // u32be length + raw bytes (C++ PackBytes)
    return this;
  }
  str(s) {
    const data = Buffer.from(String(s), 'utf8');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0); // BE length, raw bytes, NO NUL (C++ PackBytes semantics)
    this.parts.push(len, data);
    return this;
  }
  // full stream: u32be total + payload, where total counts ITSELF (+4)
  build() {
    const payload = Buffer.concat(this.parts);
    const size = Buffer.alloc(4);
    size.writeUInt32BE(payload.length + 4, 0);
    return Buffer.concat([size, payload]);
  }
}

// Parse one task at the cursor: {commandId, reader} — the caller dispatches on
// commandId and reads args BEFORE taskId (C++ Commander layout).
function* iterateTasks(buf) {
  const r = new TaskReader(buf);
  while (r.hasMore) {
    const commandId = r.u32();
    yield { commandId, reader: r, at: r.pos };
  }
}

module.exports = { TaskReader, OutPacker, iterateTasks, CP, NO_ARG_COMMANDS };
