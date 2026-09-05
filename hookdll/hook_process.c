#include <windows.h>
#include <intrin.h>
#include "hook_defs.h"
#include "jail_defs.h"
#include "eat_hook.h"

extern void RemoraLog(DWORD hook_id, DWORD arg_count, UINT64 *args, void *ret_addr);
extern void RemoraLogReturn(DWORD hook_id, UINT64 ret_value);
extern JailAction RemoraGetJail(DWORD hook_id);
extern JailAction RemoraGetJailRaw(DWORD hook_id);
extern JailAction RemoraAskJail(DWORD hook_id, const char *extra_text, void *ret_addr);
extern JailAction RemoraEvalRules(DWORD hook_id, const char *str_field, UINT64 num_field);
extern void *g_hook_handlers[];
extern int RemoraIsInHook(void);

#include "ipc_client.h"
#include <strsafe.h>
extern IpcClient g_ipc;

static const char *prot_name(DWORD prot) {
    switch (prot & 0xFF) {
    case 0x01: return "NOACCESS";
    case 0x02: return "READONLY";
    case 0x04: return "READWRITE";
    case 0x08: return "WRITECOPY";
    case 0x10: return "EXECUTE";
    case 0x20: return "EXECUTE_READ";
    case 0x40: return "EXECUTE_READWRITE";
    case 0x80: return "EXECUTE_WRITECOPY";
    default:   return NULL;
    }
}

static void format_prot(DWORD prot, char *buf, int bufsize) {
    const char *name = prot_name(prot & 0xFF);
    DWORD guard = prot & (PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    if (name && !guard)
        lstrcpynA(buf, name, bufsize);
    else if (name)
        StringCchPrintfA(buf, (size_t)bufsize, "%s|0x%X", name, guard);
    else
        StringCchPrintfA(buf, (size_t)bufsize, "0x%X", prot);
}

typedef BOOL (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *fn_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef HANDLE (WINAPI *fn_OpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *fn_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef LPVOID (WINAPI *fn_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *fn_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *fn_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINAPI *fn_CreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
typedef DWORD (WINAPI *fn_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef BOOL (WINAPI *fn_TerminateProcess)(HANDLE, UINT);

static void decode_creation_flags(DWORD flags, char *buf, int bufsize) {
    buf[0] = 0;
    int pos = 0;
    struct { DWORD flag; const char *name; } known[] = {
        { 0x00000004, "CREATE_SUSPENDED" },
        { 0x00000008, "CREATE_NEW_CONSOLE" },
        { 0x00000010, "CREATE_NEW_PROCESS_GROUP" },
        { 0x00000020, "NORMAL_PRIORITY_CLASS" },
        { 0x00000200, "CREATE_SEPARATE_WOW_VDM" },
        { 0x00000400, "CREATE_UNICODE_ENVIRONMENT" },
        { 0x08000000, "CREATE_NO_WINDOW" },
        { 0x00000001, "DEBUG_PROCESS" },
        { 0x00000002, "DEBUG_ONLY_THIS_PROCESS" },
        { 0x00000040, "IDLE_PRIORITY_CLASS" },
        { 0x00000080, "HIGH_PRIORITY_CLASS" },
        { 0x00000100, "REALTIME_PRIORITY_CLASS" },
        { 0x01000000, "CREATE_DEFAULT_ERROR_MODE" },
        { 0x04000000, "DETACHED_PROCESS" },
        { 0x02000000, "CREATE_PROTECTED_PROCESS" },
    };
    DWORD remaining = flags;
    for (int i = 0; i < sizeof(known)/sizeof(known[0]); i++) {
        if (flags & known[i].flag) {
            if (pos > 0 && pos < bufsize - 1) buf[pos++] = '|';
            int n = lstrlenA(known[i].name);
            if (pos + n < bufsize) {
                lstrcpynA(buf + pos, known[i].name, bufsize - pos);
                pos += n;
            }
            remaining &= ~known[i].flag;
        }
    }
    if (remaining) {
        if (pos > 0 && pos < bufsize - 1) buf[pos++] = '|';
        StringCchPrintfA(buf + pos, (size_t)(bufsize - pos), "0x%X", remaining);
    }
    if (pos == 0)
        StringCchPrintfA(buf, (size_t)bufsize, "0x%X", flags);
}

static void send_createprocess_log(DWORD hook_id, const void *app_name, const void *cmd_line,
    BOOL wide, DWORD flags, void *ret_addr) {
    char buf[1024];
    char app_str[256] = "(null)";
    char cmd_str[512] = "(null)";

    if (wide) {
        if (app_name)
            WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)app_name, -1, app_str, sizeof(app_str), NULL, NULL);
        if (cmd_line)
            WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)cmd_line, -1, cmd_str, sizeof(cmd_str), NULL, NULL);
    } else {
        if (app_name) lstrcpynA(app_str, (LPCSTR)app_name, sizeof(app_str));
        if (cmd_line) lstrcpynA(cmd_str, (LPCSTR)cmd_line, sizeof(cmd_str));
    }

    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_LOG_TEXT;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.ret_addr = (UINT64)ret_addr;

    char flag_str[256];
    decode_creation_flags(flags, flag_str, sizeof(flag_str));
    StringCchPrintfA(buf, sizeof(buf), "%s(\"%s\", \"%s\", %s)",
        wide ? "CreateProcessW" : "CreateProcessA", app_str, cmd_str, flag_str);
    msg.extra_len = (DWORD)strlen(buf) + 1;
    IpcClientSend(&g_ipc, &msg, buf, msg.extra_len);
}

static BOOL WINAPI hook_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir,
    LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi) {
    if (RemoraIsInHook()) {
        fn_CreateProcessA orig = (fn_CreateProcessA)EatHookGetOriginal(HOOK_CreateProcessA);
        return orig(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    }
    JailAction action = RemoraEvalRules(HOOK_CreateProcessA, app ? app : (cmd ? cmd : ""), 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_CreateProcessA);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "CreateProcessA(\"%s\", \"%s\")",
            app ? app : "(null)", cmd ? cmd : "(null)");
        action = RemoraAskJail(HOOK_CreateProcessA, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_LOG)
        send_createprocess_log(HOOK_CreateProcessA, app, cmd, FALSE, flags, _ReturnAddress());
    if (action >= JAIL_BLOCK)
        return FALSE;
    fn_CreateProcessA orig = (fn_CreateProcessA)EatHookGetOriginal(HOOK_CreateProcessA);
    BOOL ret = orig(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    if (action >= JAIL_LOG)
        RemoraLogReturn(HOOK_CreateProcessA, (UINT64)ret);
    return ret;
}

static BOOL WINAPI hook_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    if (RemoraIsInHook()) {
        fn_CreateProcessW orig = (fn_CreateProcessW)EatHookGetOriginal(HOOK_CreateProcessW);
        return orig(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    }
    char cp_app_str[256] = "", cp_cmd_str[256] = "";
    if (app) WideCharToMultiByte(CP_UTF8, 0, app, -1, cp_app_str, sizeof(cp_app_str), NULL, NULL);
    if (cmd) WideCharToMultiByte(CP_UTF8, 0, cmd, -1, cp_cmd_str, sizeof(cp_cmd_str), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_CreateProcessA, cp_app_str[0] ? cp_app_str : cp_cmd_str, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_CreateProcessW);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "CreateProcessW(\"%s\", \"%s\")",
            cp_app_str[0] ? cp_app_str : "(null)", cp_cmd_str[0] ? cp_cmd_str : "(null)");
        action = RemoraAskJail(HOOK_CreateProcessW, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_LOG)
        send_createprocess_log(HOOK_CreateProcessW, app, cmd, TRUE, flags, _ReturnAddress());
    if (action >= JAIL_BLOCK)
        return FALSE;
    fn_CreateProcessW orig = (fn_CreateProcessW)EatHookGetOriginal(HOOK_CreateProcessW);
    BOOL ret = orig(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    if (action >= JAIL_LOG)
        RemoraLogReturn(HOOK_CreateProcessW, (UINT64)ret);
    return ret;
}

static void decode_process_access(DWORD access, char *buf, int bufsize) {
    buf[0] = 0;
    int pos = 0;
    struct { DWORD flag; const char *name; } flags[] = {
        { 0x100000, "SYNCHRONIZE" },
        { 0x0001, "TERMINATE" },
        { 0x0002, "CREATE_THREAD" },
        { 0x0008, "VM_OPERATION" },
        { 0x0010, "VM_READ" },
        { 0x0020, "VM_WRITE" },
        { 0x0040, "DUP_HANDLE" },
        { 0x0080, "CREATE_PROCESS" },
        { 0x0100, "SET_QUOTA" },
        { 0x0200, "SET_INFORMATION" },
        { 0x0400, "QUERY_INFORMATION" },
        { 0x0800, "SUSPEND_RESUME" },
        { 0x1000, "QUERY_LIMITED_INFORMATION" },
    };
    if (access == 0x1F0FFF) {
        lstrcpynA(buf, "ALL_ACCESS", bufsize);
        return;
    }
    if (access == 0x1FFFFF) {
        lstrcpynA(buf, "ALL_ACCESS(full)", bufsize);
        return;
    }
    DWORD remaining = access;
    for (int i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
        if (access & flags[i].flag) {
            if (pos > 0 && pos < bufsize - 1) buf[pos++] = '|';
            int n = lstrlenA(flags[i].name);
            if (pos + n < bufsize) {
                lstrcpynA(buf + pos, flags[i].name, bufsize - pos);
                pos += n;
            }
            remaining &= ~flags[i].flag;
        }
    }
    if (remaining) {
        if (pos > 0 && pos < bufsize - 1) buf[pos++] = '|';
        StringCchPrintfA(buf + pos, (size_t)(bufsize - pos), "0x%X", remaining);
    }
    if (pos == 0)
        StringCchPrintfA(buf, (size_t)bufsize, "0x%X", access);
}

static void resolve_pid_name(DWORD pid, char *buf, int bufsize) {
    buf[0] = 0;
    fn_OpenProcess orig = (fn_OpenProcess)EatHookGetOriginal(HOOK_OpenProcess);
    HANDLE hProc = orig(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        DWORD len = (DWORD)bufsize;
        if (QueryFullProcessImageNameA(hProc, 0, buf, &len)) {
            char *slash = strrchr(buf, '\\');
            if (slash) memmove(buf, slash + 1, lstrlenA(slash + 1) + 1);
        }
        CloseHandle(hProc);
    }
}

static void send_openprocess_log(DWORD access, BOOL inherit, DWORD pid, HANDLE result,
    const char *proc_name, void *ret_addr) {
    char buf[512];
    char access_str[256];
    decode_process_access(access, access_str, sizeof(access_str));

    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_LOG_TEXT;
    msg.hook_id = HOOK_OpenProcess;
    msg.tid = GetCurrentThreadId();
    msg.ret_addr = (UINT64)ret_addr;

    StringCchPrintfA(buf, sizeof(buf), "OpenProcess(%s, PID=%u", access_str, pid);
    if (proc_name && proc_name[0]) {
        int len = (int)strlen(buf);
        StringCchPrintfA(buf + len, sizeof(buf) - (size_t)len, " \"%s\"", proc_name);
    }
    {
        int len = (int)strlen(buf);
        if (result)
            StringCchPrintfA(buf + len, sizeof(buf) - (size_t)len, ") -> 0x%I64X", (UINT64)(UINT_PTR)result);
        else
            StringCchPrintfA(buf + len, sizeof(buf) - (size_t)len, ") -> NULL");
    }
    msg.extra_len = (DWORD)strlen(buf) + 1;
    IpcClientSend(&g_ipc, &msg, buf, msg.extra_len);
}

static HANDLE WINAPI hook_OpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    JailAction action = RemoraEvalRules(HOOK_OpenProcess, "", (UINT64)pid);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_OpenProcess);
    char proc_name[128] = "";
    if (action >= JAIL_LOG || action == JAIL_ASK)
        resolve_pid_name(pid, proc_name, sizeof(proc_name));
    if (action == JAIL_ASK) {
        char ask_buf[384];
        char access_str[128];
        decode_process_access(access, access_str, sizeof(access_str));
        if (proc_name[0])
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "OpenProcess(%s, PID=%u \"%s\")", access_str, pid, proc_name);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "OpenProcess(%s, PID=%u)", access_str, pid);
        action = RemoraAskJail(HOOK_OpenProcess, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG)
            send_openprocess_log(access, inherit, pid, NULL, proc_name, _ReturnAddress());
        return NULL;
    }
    fn_OpenProcess orig = (fn_OpenProcess)EatHookGetOriginal(HOOK_OpenProcess);
    HANDLE ret = orig(access, inherit, pid);
    if (action >= JAIL_LOG)
        send_openprocess_log(access, inherit, pid, ret, proc_name, _ReturnAddress());
    return ret;
}

static BOOL WINAPI hook_WriteProcessMemory(HANDLE proc, LPVOID base, LPCVOID buf, SIZE_T size, SIZE_T *written) {
    if (RemoraIsInHook()) {
        fn_WriteProcessMemory orig = (fn_WriteProcessMemory)EatHookGetOriginal(HOOK_WriteProcessMemory);
        return orig(proc, base, buf, size, written);
    }
    JailAction action = RemoraEvalRules(HOOK_WriteProcessMemory, "", (UINT64)size);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_WriteProcessMemory);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "WriteProcessMemory(proc=0x%I64X, addr=0x%I64X, %I64u bytes)",
            (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)base, (UINT64)size);
        action = RemoraAskJail(HOOK_WriteProcessMemory, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[256];
            StringCchPrintfA(log_buf, sizeof(log_buf), "WriteProcessMemory(proc=0x%I64X, addr=0x%I64X, %I64u bytes) -> BLOCKED",
                (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)base, (UINT64)size);
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_WriteProcessMemory;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return FALSE;
    }
    fn_WriteProcessMemory orig = (fn_WriteProcessMemory)EatHookGetOriginal(HOOK_WriteProcessMemory);
    BOOL ret = orig(proc, base, buf, size, written);
    if (action >= JAIL_LOG) {
        char log_buf[256];
        StringCchPrintfA(log_buf, sizeof(log_buf), "WriteProcessMemory(proc=0x%I64X, addr=0x%I64X, %I64u bytes) -> %s",
            (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)base, (UINT64)size, ret ? "TRUE" : "FALSE");
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_WriteProcessMemory;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

static LPVOID WINAPI hook_VirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD prot) {
    JailAction action = RemoraEvalRules(HOOK_VirtualAllocEx, "", (UINT64)prot);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_VirtualAllocEx);
    if (action == JAIL_ASK) {
        char ask_buf[256], prot_str[64];
        format_prot(prot, prot_str, sizeof(prot_str));
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "VirtualAllocEx(proc=0x%I64X, %I64u bytes, %s)",
            (UINT64)(UINT_PTR)proc, (UINT64)size, prot_str);
        action = RemoraAskJail(HOOK_VirtualAllocEx, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[256], prot_str[64];
            format_prot(prot, prot_str, sizeof(prot_str));
            StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualAllocEx(proc=0x%I64X, %I64u bytes, %s) -> BLOCKED",
                (UINT64)(UINT_PTR)proc, (UINT64)size, prot_str);
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_VirtualAllocEx;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return NULL;
    }
    fn_VirtualAllocEx orig = (fn_VirtualAllocEx)EatHookGetOriginal(HOOK_VirtualAllocEx);
    LPVOID ret = orig(proc, addr, size, type, prot);
    if (action >= JAIL_LOG) {
        char log_buf[256], prot_str[64];
        format_prot(prot, prot_str, sizeof(prot_str));
        StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualAllocEx(proc=0x%I64X, %I64u bytes, %s) -> 0x%I64X",
            (UINT64)(UINT_PTR)proc, (UINT64)size, prot_str, (UINT64)(UINT_PTR)ret);
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_VirtualAllocEx;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

static BOOL WINAPI hook_VirtualProtectEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD prot, PDWORD old) {
    JailAction action = RemoraEvalRules(HOOK_VirtualProtectEx, "", (UINT64)prot);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_VirtualProtectEx);
    if (action == JAIL_ASK) {
        char ask_buf[256], prot_str[64];
        format_prot(prot, prot_str, sizeof(prot_str));
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "VirtualProtectEx(proc=0x%I64X, addr=0x%I64X, %I64u bytes, %s)",
            (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str);
        action = RemoraAskJail(HOOK_VirtualProtectEx, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[256], prot_str[64];
            format_prot(prot, prot_str, sizeof(prot_str));
            StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualProtectEx(proc=0x%I64X, addr=0x%I64X, %I64u bytes, %s) -> BLOCKED",
                (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str);
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_VirtualProtectEx;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return FALSE;
    }
    fn_VirtualProtectEx orig = (fn_VirtualProtectEx)EatHookGetOriginal(HOOK_VirtualProtectEx);
    BOOL ret = orig(proc, addr, size, prot, old);
    if (action >= JAIL_LOG) {
        char log_buf[256], prot_str[64];
        format_prot(prot, prot_str, sizeof(prot_str));
        StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualProtectEx(proc=0x%I64X, addr=0x%I64X, %I64u bytes, %s) -> %s",
            (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str, ret ? "TRUE" : "FALSE");
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_VirtualProtectEx;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

static HANDLE WINAPI hook_CreateRemoteThread(HANDLE proc, LPSECURITY_ATTRIBUTES sa, SIZE_T stack,
    LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD tid) {
    if (RemoraIsInHook()) {
        fn_CreateRemoteThread orig = (fn_CreateRemoteThread)EatHookGetOriginal(HOOK_CreateRemoteThread);
        return orig(proc, sa, stack, start, param, flags, tid);
    }
    JailAction action = RemoraEvalRules(HOOK_CreateRemoteThread, "", (UINT64)(UINT_PTR)start);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_CreateRemoteThread);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "CreateRemoteThread(proc=0x%I64X, start=0x%I64X)",
            (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)start);
        action = RemoraAskJail(HOOK_CreateRemoteThread, ask_buf, _ReturnAddress());
    }
    UINT64 args[4] = { (UINT64)proc, (UINT64)start, (UINT64)param, flags };
    if (action >= JAIL_LOG)
        RemoraLog(HOOK_CreateRemoteThread, 4, args, _ReturnAddress());
    if (action >= JAIL_BLOCK)
        return NULL;
    fn_CreateRemoteThread orig = (fn_CreateRemoteThread)EatHookGetOriginal(HOOK_CreateRemoteThread);
    return orig(proc, sa, stack, start, param, flags, tid);
}

static HANDLE WINAPI hook_CreateRemoteThreadEx(HANDLE proc, LPSECURITY_ATTRIBUTES sa, SIZE_T stack,
    LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPPROC_THREAD_ATTRIBUTE_LIST attrs, LPDWORD tid) {
    if (RemoraIsInHook()) {
        fn_CreateRemoteThreadEx orig = (fn_CreateRemoteThreadEx)EatHookGetOriginal(HOOK_CreateRemoteThreadEx);
        return orig(proc, sa, stack, start, param, flags, attrs, tid);
    }
    JailAction action = RemoraEvalRules(HOOK_CreateRemoteThreadEx, "", (UINT64)(UINT_PTR)start);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_CreateRemoteThreadEx);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "CreateRemoteThreadEx(proc=0x%I64X, start=0x%I64X)",
            (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)start);
        action = RemoraAskJail(HOOK_CreateRemoteThreadEx, ask_buf, _ReturnAddress());
    }
    UINT64 args[4] = { (UINT64)proc, (UINT64)start, (UINT64)param, flags };
    if (action >= JAIL_LOG)
        RemoraLog(HOOK_CreateRemoteThreadEx, 4, args, _ReturnAddress());
    if (action >= JAIL_BLOCK)
        return NULL;
    fn_CreateRemoteThreadEx orig = (fn_CreateRemoteThreadEx)EatHookGetOriginal(HOOK_CreateRemoteThreadEx);
    return orig(proc, sa, stack, start, param, flags, attrs, tid);
}

static DWORD WINAPI hook_QueueUserAPC(PAPCFUNC func, HANDLE thread, ULONG_PTR data) {
    if (RemoraIsInHook()) {
        fn_QueueUserAPC orig = (fn_QueueUserAPC)EatHookGetOriginal(HOOK_QueueUserAPC);
        return orig(func, thread, data);
    }
    JailAction action = RemoraEvalRules(HOOK_QueueUserAPC, "", (UINT64)(UINT_PTR)func);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_QueueUserAPC);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "QueueUserAPC(func=0x%I64X, thread=0x%I64X)",
            (UINT64)(UINT_PTR)func, (UINT64)(UINT_PTR)thread);
        action = RemoraAskJail(HOOK_QueueUserAPC, ask_buf, _ReturnAddress());
    }
    UINT64 args[3] = { (UINT64)(UINT_PTR)func, (UINT64)(UINT_PTR)thread, (UINT64)data };
    if (action >= JAIL_LOG)
        RemoraLog(HOOK_QueueUserAPC, 3, args, _ReturnAddress());
    if (action >= JAIL_BLOCK)
        return 0;
    fn_QueueUserAPC orig = (fn_QueueUserAPC)EatHookGetOriginal(HOOK_QueueUserAPC);
    return orig(func, thread, data);
}

static BOOL WINAPI hook_TerminateProcess(HANDLE proc, UINT exit_code) {
    if (RemoraIsInHook()) {
        fn_TerminateProcess orig = (fn_TerminateProcess)EatHookGetOriginal(HOOK_TerminateProcess);
        return orig(proc, exit_code);
    }
    JailAction action = RemoraEvalRules(HOOK_TerminateProcess, "", (UINT64)exit_code);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_TerminateProcess);
    DWORD pid = GetProcessId(proc);
    char proc_name[128] = "";
    if (action >= JAIL_LOG || action == JAIL_ASK)
        resolve_pid_name(pid, proc_name, sizeof(proc_name));
    if (action == JAIL_ASK) {
        char ask_buf[384];
        if (proc_name[0])
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "TerminateProcess(hProcess=0x%llX, PID=%u \"%s\", exit_code=%u)", (UINT64)(uintptr_t)proc, pid, proc_name, exit_code);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "TerminateProcess(hProcess=0x%llX, PID=%u, exit_code=%u)", (UINT64)(uintptr_t)proc, pid, exit_code);
        action = RemoraAskJail(HOOK_TerminateProcess, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[384];
            if (proc_name[0])
                StringCchPrintfA(log_buf, sizeof(log_buf), "TerminateProcess(hProcess=0x%llX, PID=%u \"%s\", exit_code=%u) -> BLOCKED", (UINT64)(uintptr_t)proc, pid, proc_name, exit_code);
            else
                StringCchPrintfA(log_buf, sizeof(log_buf), "TerminateProcess(hProcess=0x%llX, PID=%u, exit_code=%u) -> BLOCKED", (UINT64)(uintptr_t)proc, pid, exit_code);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_TerminateProcess;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.extra_len = (DWORD)strlen(log_buf) + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return FALSE;
    }
    fn_TerminateProcess orig = (fn_TerminateProcess)EatHookGetOriginal(HOOK_TerminateProcess);
    BOOL ret = orig(proc, exit_code);
    if (action >= JAIL_LOG) {
        char log_buf[384];
        if (proc_name[0])
            StringCchPrintfA(log_buf, sizeof(log_buf), "TerminateProcess(hProcess=0x%llX, PID=%u \"%s\", exit_code=%u) -> %s", (UINT64)(uintptr_t)proc, pid, proc_name, exit_code, ret ? "TRUE" : "FALSE");
        else
            StringCchPrintfA(log_buf, sizeof(log_buf), "TerminateProcess(hProcess=0x%llX, PID=%u, exit_code=%u) -> %s", (UINT64)(uintptr_t)proc, pid, exit_code, ret ? "TRUE" : "FALSE");
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_TerminateProcess;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.extra_len = (DWORD)strlen(log_buf) + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

void RegisterProcessHooks(void) {
    g_hook_handlers[HOOK_CreateProcessA] = hook_CreateProcessA;
    g_hook_handlers[HOOK_CreateProcessW] = hook_CreateProcessW;
    g_hook_handlers[HOOK_OpenProcess] = hook_OpenProcess;
    g_hook_handlers[HOOK_WriteProcessMemory] = hook_WriteProcessMemory;
    g_hook_handlers[HOOK_VirtualAllocEx] = hook_VirtualAllocEx;
    g_hook_handlers[HOOK_VirtualProtectEx] = hook_VirtualProtectEx;
    g_hook_handlers[HOOK_CreateRemoteThread] = hook_CreateRemoteThread;
    g_hook_handlers[HOOK_CreateRemoteThreadEx] = hook_CreateRemoteThreadEx;
    g_hook_handlers[HOOK_QueueUserAPC] = hook_QueueUserAPC;
    g_hook_handlers[HOOK_TerminateProcess] = hook_TerminateProcess;
}
