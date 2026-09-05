#include <windows.h>
#include <intrin.h>
#include "hook_defs.h"
#include "jail_defs.h"
#include "jail_shared.h"
#include "eat_hook.h"
#include "ipc_client.h"
#include <strsafe.h>

extern int RemoraIsInHook(void);
extern void RemoraLog(DWORD hook_id, DWORD arg_count, UINT64 *args, void *ret_addr);
extern JailAction RemoraGetJail(DWORD hook_id);
extern JailAction RemoraGetJailRaw(DWORD hook_id);
extern JailAction RemoraAskJail(DWORD hook_id, const char *extra_text, void *ret_addr);
extern JailAction RemoraEvalRules(DWORD hook_id, const char *str_field, UINT64 num_field);
extern void *g_hook_handlers[];
extern IpcClient g_ipc;
extern JailSharedMem *g_jail_shared;

static const char *prot_name(DWORD prot) {
    switch (prot & 0xFF) {
    case PAGE_NOACCESS:          return "NOACCESS";
    case PAGE_READONLY:          return "R";
    case PAGE_READWRITE:         return "RW";
    case PAGE_WRITECOPY:         return "RWC";
    case PAGE_EXECUTE:           return "X";
    case PAGE_EXECUTE_READ:      return "RX";
    case PAGE_EXECUTE_READWRITE: return "RWX";
    case PAGE_EXECUTE_WRITECOPY: return "RWXC";
    default:                     return NULL;
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

typedef LPVOID (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *fn_ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);

static LPVOID WINAPI hook_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD prot) {
    fn_VirtualAlloc orig = (fn_VirtualAlloc)EatHookGetOriginal(HOOK_VirtualAlloc);
    if (RemoraIsInHook()) return orig(addr, size, type, prot);
    JailAction action = RemoraEvalRules(HOOK_VirtualAlloc, "", (UINT64)prot);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_VirtualAlloc);
    if (action == JAIL_ASK) {
        char ask_buf[256], prot_str[64];
        format_prot(prot, prot_str, sizeof(prot_str));
        if (addr)
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "VirtualAlloc(0x%I64X, 0x%I64X, %s)",
                (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "VirtualAlloc(NULL, 0x%I64X, %s)", (UINT64)size, prot_str);
        action = RemoraAskJail(HOOK_VirtualAlloc, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[256], prot_str[64];
            format_prot(prot, prot_str, sizeof(prot_str));
            if (addr)
                StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualAlloc(0x%I64X, 0x%I64X, %s) -> NULL (BLOCKED)",
                    (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str);
            else
                StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualAlloc(NULL, 0x%I64X, %s) -> NULL (BLOCKED)",
                    (UINT64)size, prot_str);
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_VirtualAlloc;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.arg_count = 4;
            msg.args[0] = (UINT64)(UINT_PTR)addr; msg.args[1] = size;
            msg.args[2] = type; msg.args[3] = prot;
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return NULL;
    }
    LPVOID ret = orig(addr, size, type, prot);
    if (action >= JAIL_LOG) {
        char log_buf[256], prot_str[64];
        format_prot(prot, prot_str, sizeof(prot_str));
        if (addr)
            StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualAlloc(0x%I64X, 0x%I64X, %s) -> 0x%I64X",
                (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str, (UINT64)(UINT_PTR)ret);
        else
            StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualAlloc(NULL, 0x%I64X, %s) -> 0x%I64X",
                (UINT64)size, prot_str, (UINT64)(UINT_PTR)ret);
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_VirtualAlloc;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.arg_count = 4;
        msg.args[0] = (UINT64)(UINT_PTR)addr; msg.args[1] = size;
        msg.args[2] = type; msg.args[3] = prot;
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

static DWORD ProtToAdumpMask(DWORD prot) {
    switch (prot & 0xFF) {
    case PAGE_EXECUTE:           return ADUMP_PROT_X;
    case PAGE_EXECUTE_READ:      return ADUMP_PROT_RX;
    case PAGE_EXECUTE_READWRITE: return ADUMP_PROT_RWX;
    case PAGE_EXECUTE_WRITECOPY: return ADUMP_PROT_RWX;
    default:                     return 0;
    }
}

static BOOL WINAPI hook_VirtualProtect(LPVOID addr, SIZE_T size, DWORD prot, PDWORD old) {
    fn_VirtualProtect orig = (fn_VirtualProtect)EatHookGetOriginal(HOOK_VirtualProtect);
    if (RemoraIsInHook()) return orig(addr, size, prot, old);
    JailAction action = RemoraEvalRules(HOOK_VirtualProtect, "", (UINT64)prot);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_VirtualProtect);
    if (action == JAIL_ASK) {
        char ask_buf[256], prot_str[64];
        format_prot(prot, prot_str, sizeof(prot_str));
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "VirtualProtect(0x%I64X, 0x%I64X, %s)",
            (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str);
        action = RemoraAskJail(HOOK_VirtualProtect, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[256], prot_str[64];
            format_prot(prot, prot_str, sizeof(prot_str));
            StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualProtect(0x%I64X, 0x%I64X, %s) -> BLOCKED",
                (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str);
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_VirtualProtect;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.arg_count = 3;
            msg.args[0] = (UINT64)(UINT_PTR)addr; msg.args[1] = size;
            msg.args[2] = prot;
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return FALSE;
    }
    BOOL ret = orig(addr, size, prot, old);
    if (action >= JAIL_LOG) {
        char log_buf[256], prot_str[64];
        format_prot(prot, prot_str, sizeof(prot_str));
        StringCchPrintfA(log_buf, sizeof(log_buf), "VirtualProtect(0x%I64X, 0x%I64X, %s) -> %s",
            (UINT64)(UINT_PTR)addr, (UINT64)size, prot_str, ret ? "True" : "False");
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_VirtualProtect;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.arg_count = 3;
        msg.args[0] = (UINT64)(UINT_PTR)addr; msg.args[1] = size;
        msg.args[2] = prot;
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }

    if (ret && g_jail_shared && g_jail_shared->autodump.enabled) {
        DWORD match = ProtToAdumpMask(prot);
        if (match && (match & g_jail_shared->autodump.prot_mask) &&
            size >= g_jail_shared->autodump.min_size) {
            IPC_MSG_HEADER msg2 = {0};
            msg2.msg_type = MSG_AUTO_DUMP;
            msg2.tid = GetCurrentThreadId();
            AutoDumpRequest req;
            req.address  = (UINT64)(UINT_PTR)addr;
            req.size     = (UINT64)size;
            req.new_prot = prot;
            msg2.extra_len = sizeof(req);
            IpcClientSend(&g_ipc, &msg2, &req, sizeof(req));
        }
    }

    return ret;
}

static BOOL WINAPI hook_ReadProcessMemory(HANDLE proc, LPCVOID base, LPVOID buf, SIZE_T size, SIZE_T *read_out) {
    fn_ReadProcessMemory orig = (fn_ReadProcessMemory)EatHookGetOriginal(HOOK_ReadProcessMemory);
    if (RemoraIsInHook()) return orig(proc, base, buf, size, read_out);
    JailAction action = RemoraEvalRules(HOOK_ReadProcessMemory, "", (UINT64)size);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_ReadProcessMemory);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "ReadProcessMemory(proc=0x%I64X, addr=0x%I64X, %I64u bytes)",
            (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)base, (UINT64)size);
        action = RemoraAskJail(HOOK_ReadProcessMemory, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[256];
            StringCchPrintfA(log_buf, sizeof(log_buf), "ReadProcessMemory(proc=0x%I64X, addr=0x%I64X, %I64u bytes) -> BLOCKED",
                (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)base, (UINT64)size);
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_ReadProcessMemory;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return FALSE;
    }
    BOOL ret = orig(proc, base, buf, size, read_out);
    if (action >= JAIL_LOG) {
        char log_buf[256];
        StringCchPrintfA(log_buf, sizeof(log_buf), "ReadProcessMemory(proc=0x%I64X, addr=0x%I64X, %I64u bytes) -> %s",
            (UINT64)(UINT_PTR)proc, (UINT64)(UINT_PTR)base, (UINT64)size, ret ? "TRUE" : "FALSE");
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_ReadProcessMemory;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

void RegisterMemoryHooks(void) {
    g_hook_handlers[HOOK_VirtualAlloc] = hook_VirtualAlloc;
    g_hook_handlers[HOOK_VirtualProtect] = hook_VirtualProtect;
    g_hook_handlers[HOOK_ReadProcessMemory] = hook_ReadProcessMemory;
}
