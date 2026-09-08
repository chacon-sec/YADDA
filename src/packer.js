// Ported from AdaptixC2 (https://github.com/Adaptix-Framework/AdaptixC2),
// AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Packer.h/Packer.cpp (big-endian Packer/Unpacker) — GPLv3, (c) the
// AdaptixC2 authors. Structural fidelity is deliberate; deviations are noted inline.
// packer.js — byte-exact port of Adaptix's beacon Packer (Packer.cpp).
// All integers BIG-ENDIAN. PackBytes = u32(len)+bytes. PackStringA = PackBytes(utf8, strlen) — NO null terminator.
class Packer {
  constructor() { this.buf = Buffer.alloc(0); }
  _need(n) {
    if (this.buf.length + n > this.buf.length) this.buf = Buffer.concat([this.buf, Buffer.alloc(n)]);
  }
  pack8(v) { this.buf = Buffer.concat([this.buf, Buffer.from([v & 0xff])]); return this; }
  pack16(v) { const b = Buffer.allocUnsafe(2); b.writeUInt16BE(v & 0xffff, 0); this.buf = Buffer.concat([this.buf, b]); return this; }
  pack32(v) { const b = Buffer.allocUnsafe(4); b.writeUInt32BE(v >>> 0, 0); this.buf = Buffer.concat([this.buf, b]); return this; }
  pack64(v) { const b = Buffer.allocUnsafe(8); b.writeBigUInt64BE(BigInt(v), 0); this.buf = Buffer.concat([this.buf, b]); return this; }
  packBytes(data, size) {
    size = size ?? data.length;
    this.pack32(size);
    this.buf = Buffer.concat([this.buf, data.subarray(0, size)]);
    return this;
  }
  // PackStringA: length = strlen (no NUL); string passed as Buffer or JS string.
  packStringA(str) {
    const b = Buffer.isBuffer(str) ? str : Buffer.from(String(str), 'utf8');
    this.packBytes(b, b.length);
    return this;
  }
  data() { return this.buf; }
  size() { return this.buf.length; }
}

// Unpack counterpart for the test harness / response parsing.
class Unpacker {
  constructor(buf) { this.buf = buf; this.i = 0; }
  get pos() { return this.i; }
  eob() { return this.i >= this.buf.length; }
  read8() { if (this.i + 1 > this.buf.length) throw new Error('eob'); const v = this.buf[this.i]; this.i += 1; return v; }
  read16() { if (this.i + 2 > this.buf.length) throw new Error('eob'); const v = this.buf.readUInt16BE(this.i); this.i += 2; return v; }
  read32() { if (this.i + 4 > this.buf.length) throw new Error('eob'); const v = this.buf.readUInt32BE(this.i); this.i += 4; return v >>> 0; }
  readBytes(size) {
    if (!Number.isInteger(size)) size = this.read32();
    if (this.i + size > this.buf.length) throw new Error('eob');
    const out = this.buf.subarray(this.i, this.i + size); this.i += size; return out;
  }
  readStringA() {
    const size = this.read32();
    const s = this.readBytes(size).toString('utf8');
    return s;
  }
}

module.exports = { Packer, Unpacker };
