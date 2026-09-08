// asar_patch_inplace.js — same-length in-place patch for asar-integrity apps.
// NOTE (lab-verified against Slack 4.51): Electron's documented asar integrity
// validates the HEADER hash only — but Slack additionally rejects even
// same-length CONTENT changes (exits 0xC0000005 before main). For such apps
// use the app.asar.unpacked script-jack instead (see README §2l). This tool
// remains valid for header-only-validating apps.
//
// Modern Electron apps (Slack 4.5x, Discord, ...) enable the
// EnableEmbeddedAsarIntegrityValidation fuse: the signed binary pins a SHA256
// of the asar HEADER (offsets/sizes) and refuses to boot on any repack, and
// OnlyLoadAppFromAsar blocks the app/-directory fallback. But only the header
// is hashed — file CONTENTS beyond it are not validated.
//
// So: replace an inert, same-length region inside a startup-loaded bundle with
// a short hook that requires the payload from resources/ (outside the asar).
// The bundle's trailing `//# sourceMappingURL=...` comment is the ideal slot:
// inert in production, always present, and comfortably longer than the hook.
// The hook is space-padded to the exact byte length of what it replaces.
//
// Usage:
//   node scripts/asar_patch_inplace.js --asar <app.asar> [--file dist/boot.bundle.cjs]
//        [--hook "require(process.resourcesPath+'/adpt.payload.js');"]
//        [--check]   (verify the patch landed + header is untouched, no write)
const fs = require('fs');
const { readArchive, walk } = require('./asar');

const arg = (n, d) => {
  const i = process.argv.indexOf(`--${n}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : d;
};
const ASAR = arg('asar');
const FILE = arg('file', 'dist/boot.bundle.cjs');
const HOOK = arg('hook', "require(process.resourcesPath+'/a');");
const CHECK = process.argv.includes('--check');

if (!ASAR) { console.error('usage: asar_patch_inplace.js --asar <path> [--file f] [--hook s] [--check]'); process.exit(1); }

const arch = readArchive(ASAR);
const headerBefore = fs.readFileSync(ASAR).slice(0, arch.dataOffset); // for compare after

let entry = null;
walk(arch.header, (p, e) => { if (p === FILE.replace(/\\/g, '/')) entry = e; });
if (!entry) { console.error(`[patch] ${FILE} not in archive`); process.exit(1); }

const fd = fs.openSync(ASAR, CHECK ? 'r' : 'r+');
try {
  const abs = arch.dataOffset + parseInt(entry.offset, 10);
  const buf = Buffer.alloc(entry.size);
  fs.readSync(fd, buf, 0, entry.size, abs);

  // find the LAST sourceMappingURL comment >= hook length (source maps are
  // inert in production builds — never executed, never read at runtime)
  const text = buf.toString('latin1');
  const matches = [...text.matchAll(/\/\/# sourceMappingURL=\S+/g)];
  let slot = null;
  for (const m of matches) {
    if (m[0].length >= HOOK.length) { slot = { at: m.index, len: m[0].length, what: m[0].slice(0, 60) }; }
  }
  // fallback: only OTHER `//#` pragma comments (never live code or strings)
  if (!slot) {
    for (const m of text.matchAll(/\/\/# [^\n]{10,}/g)) {
      if (m[0].length >= HOOK.length) { slot = { at: m.index, len: m[0].length, what: m[0].slice(0, 60) }; }
    }
  }
  if (!slot) { console.error(`[patch] no safe same-length slot >= ${HOOK.length}B found in ${FILE}`); process.exit(1); }

  const patch = Buffer.alloc(slot.len, 0x20); // space pad to exact length
  patch.write(HOOK, 0, 'latin1');

  if (CHECK) {
    const cur = buf.slice(slot.at, slot.at + slot.len).toString('latin1');
    console.log(`[check] slot @${slot.at} len=${slot.len} was: ${JSON.stringify(slot.what)}`);
    console.log(`[check] current: ${JSON.stringify(cur.slice(0, HOOK.length + 8))}`);
    console.log(`[check] ${cur.startsWith(HOOK) ? 'PATCHED' : 'not patched'}`);
    process.exit(0);
  }

  fs.writeSync(fd, patch, 0, slot.len, abs + slot.at);
  console.log(`[patch] ${FILE}: replaced ${slot.len}B @${slot.at} (was ${JSON.stringify(slot.what)})`);
  console.log(`[patch] hook: ${HOOK} (${HOOK.length}B, space-padded ${slot.len - HOOK.length}B)`);
} finally { fs.closeSync(fd); }

// verify: header untouched (integrity fuse food), patch landed
const after = fs.readFileSync(ASAR);
if (!after.slice(0, arch.dataOffset).equals(headerBefore)) {
  console.error('[patch] FATAL: header changed — integrity would break');
  process.exit(1);
}
readArchive(ASAR); // still parses
console.log('[patch] header byte-identical (integrity fuse happy), archive parses OK');
