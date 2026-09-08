#!/usr/bin/env node
// asar.js — zero-dependency ASAR archive reader/writer (Chromium "archive"
// format used by Electron: app.asar).
//
// Format (reverse-engineered from Electron's bundled asar fs + default_app.asar,
// cross-checked against @electron/asar's pickle):
//
//   [u32le 4]                 pickle header: payload size of the NEXT pickle
//   [u32le headerSize]        size of the header pickle that follows
//   [u32le jsonLen]           header pickle: payload size = 4 + jsonLen + pad
//   [u32le jsonLen]           header pickle: string length (readString)
//   [jsonLen bytes JSON]      the index: {"files": {...}}, padded with 0x00
//   [file data...]            file contents; JSON "offset" (decimal string) is
//                             relative to the END of the header pickle
//
// Index entry shapes:
//   file: {"size": n, "offset": "123", "integrity": {...}, "unpacked": bool}
//   dir : {"files": { ... }}
//   integrity (emitted when --integrity, validated by newer Electron):
//     {"algorithm":"SHA256","hash":"<hex of whole file>","blockSize":4194304,
//      "blocks":["<hex of each 4 MiB block>"]}
//
// CLI:
//   node scripts/asar.js list   <archive>
//   node scripts/asar.js pack   <srcDir> <archive> [--integrity]
//   node scripts/asar.js extract <archive> <destDir>
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BLOCK_SIZE = 4 * 1024 * 1024; // matches @electron/asar integrity blocks

// ---------------------------------------------------------------- pickle ----
// Chromium pickle: [u32le payloadSize][payload 4-byte aligned]
function pickleFromString(s) {
  const len = Buffer.byteLength(s, 'utf8');
  const payloadLen = 4 + len;
  const padded = (payloadLen + 3) & ~3;
  const buf = Buffer.alloc(4 + padded);
  buf.writeUInt32LE(padded, 0);       // payload size (excludes this 4-byte field)
  buf.writeUInt32LE(len, 4);
  buf.write(s, 8, 'utf8');            // rest stays zero-padded
  return buf;
}
function pickleFromUInt32(v) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32LE(4, 0);
  buf.writeUInt32LE(v, 4);
  return buf;
}

// ----------------------------------------------------------------- read -----
function readArchive(archivePath) {
  const fd = fs.openSync(archivePath, 'r');
  try {
    const sizeBuf = Buffer.alloc(8);
    if (fs.readSync(fd, sizeBuf, 0, 8, 0) !== 8) throw new Error('short read: header size');
    if (sizeBuf.readUInt32LE(0) !== 4) throw new Error(`bad pickle magic: ${sizeBuf.readUInt32LE(0)} (expected 4)`);
    const headerSize = sizeBuf.readUInt32LE(4);
    const headerBuf = Buffer.alloc(headerSize);
    if (fs.readSync(fd, headerBuf, 0, headerSize, 8) !== headerSize) throw new Error('short read: header');
    const jsonLen = headerBuf.readUInt32LE(4);
    const json = headerBuf.slice(8, 8 + jsonLen).toString('utf8');
    return {
      header: JSON.parse(json),
      headerString: json,
      headerSize,
      dataOffset: 8 + headerSize,     // absolute offset of the data section
      fileSize: fs.fstatSync(fd).size,
    };
  } finally { fs.closeSync(fd); }
}

function readFileBytes(archivePath, arch, entry) {
  const fd = fs.openSync(archivePath, 'r');
  try {
    const abs = arch.dataOffset + parseInt(entry.offset, 10);
    const buf = Buffer.alloc(entry.size);
    if (fs.readSync(fd, buf, 0, entry.size, abs) !== entry.size) throw new Error('short read: content');
    return buf;
  } finally { fs.closeSync(fd); }
}

// walk the index, calling cb(path, entry) for every file entry
function walk(header, cb) {
  const visit = (node, prefix) => {
    for (const [name, e] of Object.entries(node.files || {})) {
      const p = prefix ? `${prefix}/${name}` : name;
      if (e.files) visit(e, p);
      else if (e.offset !== undefined) cb(p, e);
    }
  };
  visit(header, '');
}

// --------------------------------------------------------------- extract ----
function extract(archivePath, destDir) {
  const arch = readArchive(archivePath);
  let n = 0;
  walk(arch.header, (p, entry) => {
    const dest = path.join(destDir, p);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, readFileBytes(archivePath, arch, entry));
    n++;
  });
  return { files: n, header: arch.header };
}

// ----------------------------------------------------------------- pack -----
function integrityFor(buf) {
  return {
    algorithm: 'SHA256',
    hash: crypto.createHash('sha256').update(buf).digest('hex'),
    blockSize: BLOCK_SIZE,
    blocks: (() => {
      const out = [];
      for (let off = 0; off < buf.length; off += BLOCK_SIZE) {
        out.push(crypto.createHash('sha256').update(buf.slice(off, off + BLOCK_SIZE)).digest('hex'));
      }
      return out;
    })(),
  };
}

function pack(srcDir, opts) {
  const files = [];   // {rel, abs}
  (function scan(dir, prefix) {
    for (const name of fs.readdirSync(dir).sort()) {
      const abs = path.join(dir, name);
      const rel = prefix ? `${prefix}/${name}` : name;
      const st = fs.statSync(abs);
      if (st.isDirectory()) scan(abs, rel);
      else files.push({ rel, abs, size: st.size });
    }
  })(srcDir, '');

  // build the data section first (offsets depend on layout)
  const chunks = [];
  const index = { files: {} };
  let off = 0;
  for (const f of files) {
    const buf = fs.readFileSync(f.abs);
    chunks.push(buf);
    const entry = { size: buf.length, offset: String(off) };
    if (opts && opts.integrity) entry.integrity = integrityFor(buf);
    // nested index insertion
    let node = index.files;
    const parts = f.rel.split('/');
    for (let i = 0; i < parts.length - 1; i++) {
      node[parts[i]] = node[parts[i]] || { files: {} };
      node = node[parts[i]].files;
    }
    node[parts[parts.length - 1]] = entry;
    off += buf.length;
  }

  const json = JSON.stringify(index);
  const headerBuf = pickleFromString(json);
  const sizeBuf = pickleFromUInt32(headerBuf.length);
  return { header: index, headerString: json, sizeBuf, headerBuf, data: Buffer.concat(chunks) };
}

function writeArchive(destPath, packed) {
  fs.writeFileSync(destPath, Buffer.concat([packed.sizeBuf, packed.headerBuf, packed.data]));
}

// ------------------------------------------------------------------ CLI -----
if (require.main === module) {
  const [, , cmd, ...rest] = process.argv;
  const die = (m) => { console.error('[asar] ' + m); process.exit(1); };
  if (cmd === 'list') {
    const arch = readArchive(rest[0]);
    walk(arch.header, (p, e) => console.log(`${String(e.size).padStart(9)}  ${p}`));
    console.log(`[asar] header=${arch.headerSize}B data@${arch.dataOffset} file=${arch.fileSize}B`);
  } else if (cmd === 'pack') {
    const [src, dest] = rest;
    const packed = pack(src, { integrity: process.argv.includes('--integrity') });
    writeArchive(dest, packed);
    console.log(`[asar] packed ${src} -> ${dest} (header ${packed.headerBuf.length}B, data ${packed.data.length}B)`);
  } else if (cmd === 'extract') {
    const [archive, dest] = rest;
    const { files } = extract(archive, dest);
    console.log(`[asar] extracted ${files} file(s) -> ${dest}`);
  } else die('usage: asar.js list|pack|extract ...');
}

module.exports = { readArchive, readFileBytes, walk, extract, pack, writeArchive, integrityFor };
