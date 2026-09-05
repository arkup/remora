#include <windows.h>
#include <intrin.h>
#include <stdarg.h>
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

#include "ipc_client.h"
#include <strsafe.h>
extern IpcClient g_ipc;

typedef HMODULE (WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef HMODULE (WINAPI *fn_GetModuleHandleW)(LPCWSTR);
typedef DWORD (WINAPI *fn_GetModuleFileNameA)(HMODULE, LPSTR, DWORD);
typedef DWORD (WINAPI *fn_GetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);

static void send_text_log(DWORD hook_id, void *ret_addr, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    StringCchVPrintfA(buf, sizeof(buf), fmt, ap);
    int len = (int)strlen(buf);
    va_end(ap);

    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_LOG_TEXT;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.ret_addr = (UINT64)ret_addr;
    msg.extra_len = (DWORD)len + 1;
    IpcClientSend(&g_ipc, &msg, buf, msg.extra_len);
}

extern int RemoraIsInHook(void);
extern void tls_set_in_hook(int val);

static void get_module_basename(HMODULE hMod, char *out, int outsize) {
    out[0] = 0;
    char path[MAX_PATH];
    fn_GetModuleFileNameA real_gmfn = (fn_GetModuleFileNameA)EatHookGetOriginal(HOOK_GetModuleFileNameA);
    if (!real_gmfn) {
        StringCchPrintfA(out, (size_t)outsize, "0x%I64X", (UINT64)(UINT_PTR)hMod);
        return;
    }
    DWORD len = real_gmfn(hMod, path, MAX_PATH);
    if (len == 0) {
        StringCchPrintfA(out, (size_t)outsize, "0x%I64X", (UINT64)(UINT_PTR)hMod);
        return;
    }
    const char *base = path;
    for (const char *p = path; *p; p++) {
        if (*p == '\\' || *p == '/')
            base = p + 1;
    }
    lstrcpynA(out, base, outsize);
}

static HMODULE WINAPI hook_GetModuleHandleA(LPCSTR name) {
    fn_GetModuleHandleA orig = (fn_GetModuleHandleA)EatHookGetOriginal(HOOK_GetModuleHandleA);
    if (RemoraIsInHook())
        return orig(name);
    JailAction action = RemoraEvalRules(HOOK_GetModuleHandleA, name ? name : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_GetModuleHandleA);
    if (action == JAIL_ASK) {
        char ask_buf[256];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetModuleHandleA(%s)", name ? name : "NULL");
        action = RemoraAskJail(HOOK_GetModuleHandleA, ask_buf, _ReturnAddress());
    }
    HMODULE ret = orig(name);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        if (name)
            send_text_log(HOOK_GetModuleHandleA, _ReturnAddress(),
                "GetModuleHandleA(\"%s\") -> 0x%I64X", name, (UINT64)(UINT_PTR)ret);
        else
            send_text_log(HOOK_GetModuleHandleA, _ReturnAddress(),
                "GetModuleHandleA(NULL) -> 0x%I64X", (UINT64)(UINT_PTR)ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static HMODULE WINAPI hook_GetModuleHandleW(LPCWSTR name) {
    fn_GetModuleHandleW orig = (fn_GetModuleHandleW)EatHookGetOriginal(HOOK_GetModuleHandleW);
    if (RemoraIsInHook())
        return orig(name);
    char gmh_name_utf8[256];
    if (name) WideCharToMultiByte(CP_UTF8, 0, name, -1, gmh_name_utf8, sizeof(gmh_name_utf8), NULL, NULL);
    else gmh_name_utf8[0] = 0;
    JailAction action = RemoraEvalRules(HOOK_GetModuleHandleA, gmh_name_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_GetModuleHandleW);
    if (action == JAIL_ASK) {
        char ask_buf[256];
        if (gmh_name_utf8[0])
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetModuleHandleW(\"%s\")", gmh_name_utf8);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetModuleHandleW(NULL)");
        action = RemoraAskJail(HOOK_GetModuleHandleW, ask_buf, _ReturnAddress());
    }
    HMODULE ret = orig(name);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        if (name) {
            char name_a[256];
            WideCharToMultiByte(CP_UTF8, 0, name, -1, name_a, sizeof(name_a), NULL, NULL);
            send_text_log(HOOK_GetModuleHandleW, _ReturnAddress(),
                "GetModuleHandleW(\"%s\") -> 0x%I64X", name_a, (UINT64)(UINT_PTR)ret);
        } else {
            send_text_log(HOOK_GetModuleHandleW, _ReturnAddress(),
                "GetModuleHandleW(NULL) -> 0x%I64X", (UINT64)(UINT_PTR)ret);
        }
        tls_set_in_hook(0);
    }
    return ret;
}

static DWORD WINAPI hook_GetModuleFileNameA(HMODULE hMod, LPSTR lpFilename, DWORD nSize) {
    fn_GetModuleFileNameA orig = (fn_GetModuleFileNameA)EatHookGetOriginal(HOOK_GetModuleFileNameA);
    if (RemoraIsInHook())
        return orig(hMod, lpFilename, nSize);
    JailAction action = RemoraEvalRules(HOOK_GetModuleFileNameA, "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_GetModuleFileNameA);
    if (action == JAIL_ASK) {
        char ask_buf[64];
        if (hMod)
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetModuleFileNameA(0x%I64X)", (UINT64)(UINT_PTR)hMod);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetModuleFileNameA(NULL)");
        action = RemoraAskJail(HOOK_GetModuleFileNameA, ask_buf, _ReturnAddress());
    }
    DWORD ret = orig(hMod, lpFilename, nSize);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        if (hMod)
            send_text_log(HOOK_GetModuleFileNameA, _ReturnAddress(),
                "GetModuleFileNameA(0x%I64X) -> \"%s\"", (UINT64)(UINT_PTR)hMod, ret ? lpFilename : "");
        else
            send_text_log(HOOK_GetModuleFileNameA, _ReturnAddress(),
                "GetModuleFileNameA(NULL) -> \"%s\"", ret ? lpFilename : "");
        tls_set_in_hook(0);
    }
    return ret;
}

static DWORD WINAPI hook_GetModuleFileNameW(HMODULE hMod, LPWSTR lpFilename, DWORD nSize) {
    fn_GetModuleFileNameW orig = (fn_GetModuleFileNameW)EatHookGetOriginal(HOOK_GetModuleFileNameW);
    if (RemoraIsInHook())
        return orig(hMod, lpFilename, nSize);
    JailAction action = RemoraEvalRules(HOOK_GetModuleFileNameA, "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_GetModuleFileNameW);
    if (action == JAIL_ASK) {
        char ask_buf[64];
        if (hMod)
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetModuleFileNameW(0x%I64X)", (UINT64)(UINT_PTR)hMod);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetModuleFileNameW(NULL)");
        action = RemoraAskJail(HOOK_GetModuleFileNameW, ask_buf, _ReturnAddress());
    }
    DWORD ret = orig(hMod, lpFilename, nSize);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char path_a[MAX_PATH] = "";
        if (ret && lpFilename)
            WideCharToMultiByte(CP_UTF8, 0, lpFilename, -1, path_a, sizeof(path_a), NULL, NULL);
        if (hMod)
            send_text_log(HOOK_GetModuleFileNameW, _ReturnAddress(),
                "GetModuleFileNameW(0x%I64X) -> \"%s\"", (UINT64)(UINT_PTR)hMod, path_a);
        else
            send_text_log(HOOK_GetModuleFileNameW, _ReturnAddress(),
                "GetModuleFileNameW(NULL) -> \"%s\"", path_a);
        tls_set_in_hook(0);
    }
    return ret;
}

static FARPROC WINAPI hook_GetProcAddress(HMODULE hMod, LPCSTR name) {
    fn_GetProcAddress orig = (fn_GetProcAddress)EatHookGetOriginal(HOOK_GetProcAddress);
    if (RemoraIsInHook())
        return orig(hMod, name);
    const char *gpa_str = ((UINT_PTR)name > 0xFFFF) ? name : "";
    JailAction action = RemoraEvalRules(HOOK_GetProcAddress, gpa_str, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_GetProcAddress);
    if (action == JAIL_ASK) {
        char ask_buf[256], mod_name[128];
        tls_set_in_hook(1);
        get_module_basename(hMod, mod_name, sizeof(mod_name));
        tls_set_in_hook(0);
        if ((UINT_PTR)name > 0xFFFF)
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetProcAddress(%s, \"%s\")", mod_name, name);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetProcAddress(%s, #%u)", mod_name, (DWORD)(UINT_PTR)name);
        action = RemoraAskJail(HOOK_GetProcAddress, ask_buf, _ReturnAddress());
    }
    FARPROC ret = orig(hMod, name);
    if (action >= JAIL_LOG) {
        char mod_name[128];
        tls_set_in_hook(1);
        get_module_basename(hMod, mod_name, sizeof(mod_name));
        if ((UINT_PTR)name > 0xFFFF)
            send_text_log(HOOK_GetProcAddress, _ReturnAddress(),
                "GetProcAddress(%s, \"%s\") -> 0x%I64X", mod_name, name, (UINT64)(UINT_PTR)ret);
        else
            send_text_log(HOOK_GetProcAddress, _ReturnAddress(),
                "GetProcAddress(%s, #%u) -> 0x%I64X", mod_name, (DWORD)(UINT_PTR)name, (UINT64)(UINT_PTR)ret);
        tls_set_in_hook(0);
    }
    if (ret && (UINT_PTR)name > 0xFFFF) {
        for (DWORD h = 0; h < HOOK_DEF_COUNT; h++) {
            if (!g_hook_handlers[g_hook_defs[h].id]) continue;
            if (strcmp(g_hook_defs[h].api_name, name) == 0) {
                void *o = EatHookGetOriginal(g_hook_defs[h].id);
                if (!o) {
                    extern void *EatHookSetOriginal(DWORD hook_id, void *addr);
                    EatHookSetOriginal(g_hook_defs[h].id, (void *)ret);
                }
                break;
            }
        }
    }
    return ret;
}

void RegisterModuleHooks(void) {
    g_hook_handlers[HOOK_GetModuleHandleA] = hook_GetModuleHandleA;
    g_hook_handlers[HOOK_GetModuleHandleW] = hook_GetModuleHandleW;
    g_hook_handlers[HOOK_GetModuleFileNameA] = hook_GetModuleFileNameA;
    g_hook_handlers[HOOK_GetModuleFileNameW] = hook_GetModuleFileNameW;
    g_hook_handlers[HOOK_GetProcAddress] = hook_GetProcAddress;
}

void RegisterAllHookHandlers(void) {
    extern void RegisterFileHooks(void);
    extern void RegisterProcessHooks(void);
    extern void RegisterMemoryHooks(void);
    extern void RegisterRegistryHooks(void);
    extern void RegisterNetworkHooks(void);
    extern void RegisterHttpHooks(void);
    extern void RegisterCryptoHooks(void);
    RegisterFileHooks();
    RegisterProcessHooks();
    RegisterMemoryHooks();
    RegisterRegistryHooks();
    RegisterNetworkHooks();
    RegisterHttpHooks();
    RegisterCryptoHooks();
    RegisterModuleHooks();
}
