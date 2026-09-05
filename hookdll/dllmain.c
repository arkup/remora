#include <windows.h>
#include <intrin.h>
#include <string.h>
#include "hookengine.h"
#include "eat_hook.h"
#include "ipc_client.h"
#include "hook_defs.h"
#include "jail_defs.h"
#include "jail_shared.h"
#include <strsafe.h>

void *g_hook_handlers[HOOK_COUNT] = {0};
static JailAction g_jail[HOOK_COUNT];
IpcClient g_ipc;
static InlineHook g_ldr_load_hook;
static InlineHook g_ldr_getproc_hook;
static CRITICAL_SECTION g_ldr_cs;
static DWORD g_tls_index = TLS_OUT_OF_INDEXES;
static HANDLE g_jail_shared_mapping = NULL;
JailSharedMem *g_jail_shared = NULL;
static DWORD g_host_pid = 0;

static int tls_get_in_hook(void) {
    if (g_tls_index == TLS_OUT_OF_INDEXES) return 0;
    return (int)(UINT_PTR)TlsGetValue(g_tls_index);
}

void tls_set_in_hook(int val) {
    if (g_tls_index != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_tls_index, (LPVOID)(UINT_PTR)val);
}

int RemoraIsInHook(void) {
    return tls_get_in_hook();
}

typedef NTSTATUS (NTAPI *fn_LdrLoadDll)(PWCHAR, PULONG, PVOID, PHANDLE);
typedef NTSTATUS (NTAPI *fn_LdrGetProcedureAddress)(HMODULE, PVOID, WORD, PVOID*);

static fn_LdrLoadDll g_orig_LdrLoadDll;
static fn_LdrGetProcedureAddress g_orig_LdrGetProcAddr;

void RemoraLog(DWORD hook_id, DWORD arg_count, UINT64 *args, void *ret_addr) {
    if (tls_get_in_hook()) return;
    tls_set_in_hook(1);

    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_HOOK_CALL;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    QueryPerformanceCounter((LARGE_INTEGER *)&msg.timestamp);
    msg.arg_count = arg_count;
    for (DWORD i = 0; i < arg_count && i < IPC_MAX_ARGS; i++)
        msg.args[i] = args[i];
    msg.ret_addr = (UINT64)ret_addr;
    IpcClientSend(&g_ipc, &msg, NULL, 0);

    tls_set_in_hook(0);
}

void RemoraLogReturn(DWORD hook_id, UINT64 ret_value) {
    if (tls_get_in_hook()) return;
    tls_set_in_hook(1);

    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_HOOK_RETURN;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.ret_value = ret_value;
    IpcClientSend(&g_ipc, &msg, NULL, 0);

    tls_set_in_hook(0);
}



JailAction RemoraAskJail(DWORD hook_id, const char *extra_text, void *ret_addr);

static DWORD SafeBufferCopy(const void *src, void *dst, DWORD requested) {
    DWORD copied = 0;
    const BYTE *p = (const BYTE *)src;
    BYTE *out = (BYTE *)dst;
    while (copied < requested) {
        DWORD_PTR page_base = (DWORD_PTR)p & ~(DWORD_PTR)0xFFF;
        DWORD_PTR page_end  = page_base + 0x1000;
        DWORD chunk = (DWORD)(page_end - (DWORD_PTR)p);
        if (chunk > (requested - copied))
            chunk = requested - copied;
        __try {
            memcpy(out, p, chunk);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        copied += chunk;
        p      += chunk;
        out    += chunk;
    }
    return copied;
}

void RemoraSendBuffer(DWORD hook_id, int buf_type, const void *data, DWORD data_len) {
    if (!g_jail_shared || !g_jail_shared->capture_enabled) return;
    if (!data || data_len == 0) return;

    DWORD max_cap = g_jail_shared->capture_max_bytes;
    if (max_cap == 0) max_cap = CAPTURE_DEFAULT_MAX;
    if (max_cap > CAPTURE_MAX_BYTES_LIMIT) max_cap = CAPTURE_MAX_BYTES_LIMIT;
    DWORD want = (data_len < max_cap) ? data_len : max_cap;

    BYTE *local_buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, want);
    if (!local_buf) return;

    DWORD got = SafeBufferCopy(data, local_buf, want);
    if (got == 0) {
        HeapFree(GetProcessHeap(), 0, local_buf);
        return;
    }

    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_HOOK_BUFFER;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.args[0] = (UINT64)buf_type;
    msg.args[1] = (UINT64)data_len;
    msg.extra_len = got;
    IpcClientSend(&g_ipc, &msg, local_buf, got);

    HeapFree(GetProcessHeap(), 0, local_buf);
}

JailAction RemoraGetJailRaw(DWORD hook_id) {
    if (hook_id >= HOOK_COUNT) return JAIL_ALLOW;
    if (g_jail_shared)
        return (JailAction)g_jail_shared->actions[hook_id];
    return g_jail[hook_id];
}

JailAction RemoraGetJail(DWORD hook_id) {
    JailAction action = RemoraGetJailRaw(hook_id);
    if (action == JAIL_ASK) {
        const char *name = (hook_id < HOOK_DEF_COUNT) ? g_hook_defs[hook_id].api_name : "???";
        char buf[256];
        StringCchPrintfA(buf, sizeof(buf), "%s(...)", name);
        action = RemoraAskJail(hook_id, buf, _ReturnAddress());
    }
    return action;
}

void *RemoraGetOriginal(DWORD hook_id) {
    return EatHookGetOriginal(hook_id);
}

JailAction RemoraAskJail(DWORD hook_id, const char *extra_text, void *ret_addr) {
    if (!g_jail_shared) return JAIL_ALLOW;

    DWORD tid = GetCurrentThreadId();

    int slot_idx = -1;
    for (int i = 0; i < JAIL_ASK_MAX_PENDING; i++) {
        DWORD expected = 0;
        if (InterlockedCompareExchange((volatile LONG *)&g_jail_shared->slots[i].tid, tid, expected) == 0) {
            slot_idx = i;
            break;
        }
    }
    if (slot_idx < 0) {
        tls_set_in_hook(1);
        IPC_MSG_HEADER omsg = {0};
        omsg.msg_type = MSG_LOG_TEXT;
        omsg.hook_id = hook_id;
        omsg.tid = tid;
        const char *warn = "[!] JAIL_ASK overflow -- blocked (no free slot)";
        omsg.extra_len = (DWORD)strlen(warn) + 1;
        IpcClientSend(&g_ipc, &omsg, warn, omsg.extra_len);
        tls_set_in_hook(0);
        return JAIL_BLOCK;
    }

    g_jail_shared->slots[slot_idx].hook_id = hook_id;
    g_jail_shared->slots[slot_idx].action = JAIL_ALLOW;

    char evt_name[128];
    JailEventName(evt_name, sizeof(evt_name), GetCurrentProcessId(), tid);
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, evt_name);
    if (!hEvent) {
        InterlockedExchange((volatile LONG *)&g_jail_shared->slots[slot_idx].tid, 0);
        return JAIL_ALLOW;
    }

    tls_set_in_hook(1);
    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_JAIL_ASK;
    msg.hook_id = hook_id;
    msg.tid = tid;
    msg.ret_addr = (UINT64)ret_addr;
    QueryPerformanceCounter((LARGE_INTEGER *)&msg.timestamp);
    DWORD extra_len = extra_text ? (DWORD)strlen(extra_text) + 1 : 0;
    msg.extra_len = extra_len;
    IpcClientSend(&g_ipc, &msg, extra_text, extra_len);

    void *frames[IPC_MAX_STACK_FRAMES];
    USHORT frame_count = RtlCaptureStackBackTrace(2, IPC_MAX_STACK_FRAMES, frames, NULL);
    if (frame_count > 0) {
        UINT64 addrs[IPC_MAX_STACK_FRAMES];
        for (USHORT i = 0; i < frame_count; i++)
            addrs[i] = (UINT64)frames[i];
        IPC_MSG_HEADER smsg = {0};
        smsg.msg_type = MSG_HOOK_CALLSTACK;
        smsg.hook_id = hook_id;
        smsg.tid = tid;
        smsg.arg_count = frame_count;
        smsg.extra_len = (DWORD)(frame_count * sizeof(UINT64));
        IpcClientSend(&g_ipc, &smsg, addrs, smsg.extra_len);
    }
    DWORD wait = WaitForSingleObject(hEvent, JAIL_ASK_TIMEOUT_MS);
    tls_set_in_hook(0);
    JailAction result = JAIL_ALLOW;
    if (wait == WAIT_OBJECT_0)
        result = (JailAction)g_jail_shared->slots[slot_idx].action;

    InterlockedExchange((volatile LONG *)&g_jail_shared->slots[slot_idx].tid, 0);
    CloseHandle(hEvent);
    return result;
}

static void notify_dll_loaded(const char *name, HMODULE hMod) {
    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_DLL_LOADED;
    msg.args[0] = (UINT64)hMod;
    DWORD name_len = (DWORD)strlen(name) + 1;
    msg.extra_len = name_len;
    IpcClientSend(&g_ipc, &msg, name, name_len);
}

static NTSTATUS NTAPI hooked_LdrLoadDll(PWCHAR search_path, PULONG flags, PVOID module_name, PHANDLE module_handle) {
    NTSTATUS status = g_orig_LdrLoadDll(search_path, flags, module_name, module_handle);

    if (status == 0 && module_handle && *module_handle) {
        HMODULE hMod = (HMODULE)*module_handle;

        char dll_name[MAX_PATH];
        if (GetModuleFileNameA(hMod, dll_name, MAX_PATH)) {
            char *slash = strrchr(dll_name, '\\');
            char *name = slash ? slash + 1 : dll_name;

            EnterCriticalSection(&g_ldr_cs);
            notify_dll_loaded(name, hMod);
            EatHookPatchNewModule(hMod, name);
            LeaveCriticalSection(&g_ldr_cs);
        }
    }

    return status;
}

static NTSTATUS NTAPI hooked_LdrGetProcAddr(HMODULE hMod, PVOID func_name, WORD ordinal, PVOID *out_addr) {
    return g_orig_LdrGetProcAddr(hMod, func_name, ordinal, out_addr);
}

static void install_bootstrap_hooks(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    void *pLdrLoadDll = (void *)GetProcAddress(ntdll, "LdrLoadDll");
    void *pLdrGetProc = (void *)GetProcAddress(ntdll, "LdrGetProcedureAddress");

    if (pLdrLoadDll) {
        if (HookEngineInstall(&g_ldr_load_hook, pLdrLoadDll, hooked_LdrLoadDll))
            g_orig_LdrLoadDll = (fn_LdrLoadDll)HookEngineGetOriginal(&g_ldr_load_hook);
    }

    if (pLdrGetProc) {
        if (HookEngineInstall(&g_ldr_getproc_hook, pLdrGetProc, hooked_LdrGetProcAddr))
            g_orig_LdrGetProcAddr = (fn_LdrGetProcedureAddress)HookEngineGetOriginal(&g_ldr_getproc_hook);
    }
}

extern void RegisterAllHookHandlers(void);

static void send_diag(const char *text) {
    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_DLL_LOADED;
    DWORD len = (DWORD)strlen(text) + 1;
    msg.extra_len = len;
    IpcClientSend(&g_ipc, &msg, text, len);
}

static void hook_already_loaded_dlls(void) {
    const char *target_dlls[] = {
        "kernelbase.dll", "kernel32.dll", "user32.dll", "advapi32.dll",
        "ws2_32.dll", "wininet.dll", "bcrypt.dll", NULL
    };

    for (int i = 0; target_dlls[i]; i++) {
        HMODULE hMod = GetModuleHandleA(target_dlls[i]);
        if (hMod) {
            char diag[256];
            StringCchPrintfA(diag, sizeof(diag), "[diag] Hooking %s @ %p...", target_dlls[i], (void *)hMod);
            send_diag(diag);
            BOOL result = EatHookModule(hMod, target_dlls[i]);
            StringCchPrintfA(diag, sizeof(diag), "[diag] %s result=%d hooks_total=%u",
                target_dlls[i], result, EatHookGetCount());
            send_diag(diag);
        }
    }
}

static void HookInit(void) {
    memcpy(g_jail, g_default_jail, sizeof(g_jail));

    DWORD host_pid = 0;
    char env_buf[32];
    if (GetEnvironmentVariableA("REMORA_HOST_PID", env_buf, sizeof(env_buf)))
        host_pid = (DWORD)atoi(env_buf);

    if (!host_pid) {
        OutputDebugStringA("[remora] ERROR: REMORA_HOST_PID not set\n");
        return;
    }

    g_host_pid = host_pid;

    if (!IpcClientConnect(&g_ipc, host_pid)) {
        OutputDebugStringA("[remora] ERROR: IPC connect failed\n");
        return;
    }

    send_diag("[diag] IPC connected");

    char shared_name[128];
    JailSharedName(shared_name, sizeof(shared_name), host_pid);
    g_jail_shared_mapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, shared_name);
    if (g_jail_shared_mapping) {
        g_jail_shared = (JailSharedMem *)MapViewOfFile(
            g_jail_shared_mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(JailSharedMem));
    }
    if (g_jail_shared)
        send_diag("[diag] Jail shared memory mapped");
    else
        send_diag("[diag] WARN: Jail shared memory not available (ASK disabled)");

    RegisterAllHookHandlers();
    send_diag("[diag] Handlers registered");

    HookEngineInit();
    send_diag("[diag] HookEngine init done");

    {
        HMODULE hSelf = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (LPCSTR)HookInit, &hSelf);
        char diag[256];
        StringCchPrintfA(diag, sizeof(diag), "[diag] hookdll.dll @ %p", (void *)hSelf);
        send_diag(diag);
    }

    if (!EatHookInit()) {
        send_diag("[diag] ERROR: EatHookInit FAILED");
    } else {
        send_diag("[diag] EatHookInit OK");
    }

    hook_already_loaded_dlls();
    EatHookCommit();

    {
        DWORD overflow = EatHookGetOverflowCount();
        if (overflow > 0) {
            char diag[256];
            StringCchPrintfA(diag, sizeof(diag), "[diag] WARNING: %u stubs failed rel32 overflow (hookdll too far from pool)", overflow);
            send_diag(diag);
        }
    }

    send_diag("[diag] Already-loaded DLLs hooked (commit)");

    install_bootstrap_hooks();
    send_diag("[diag] Bootstrap hooks installed");

    {
        DWORD iat_count = EatHookPatchIATsByName(GetModuleHandleA(NULL));
        char diag[128];
        StringCchPrintfA(diag, sizeof(diag), "[diag] EXE IAT patched: %u entries redirected", iat_count);
        send_diag(diag);
    }

    {
        extern void HandleTableInitStdHandles(void);
        HandleTableInitStdHandles();
    }

    IPC_MSG_HEADER ready = {0};
    ready.msg_type = MSG_HOOK_READY;
    IpcClientSend(&g_ipc, &ready, NULL, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_tls_index = TlsAlloc();
        InitializeCriticalSection(&g_ldr_cs);
        HookInit();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        HookEngineRemove(&g_ldr_load_hook);
        HookEngineRemove(&g_ldr_getproc_hook);
        if (g_jail_shared) {
            UnmapViewOfFile(g_jail_shared);
            g_jail_shared = NULL;
        }
        if (g_jail_shared_mapping) {
            CloseHandle(g_jail_shared_mapping);
            g_jail_shared_mapping = NULL;
        }
        IpcClientDisconnect(&g_ipc);
        DeleteCriticalSection(&g_ldr_cs);
        if (g_tls_index != TLS_OUT_OF_INDEXES)
            TlsFree(g_tls_index);
    }
    return TRUE;
}
