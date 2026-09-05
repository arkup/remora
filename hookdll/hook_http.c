#include <windows.h>
#include <intrin.h>
#include <wininet.h>
#include "hook_defs.h"
#include "jail_defs.h"
#include "eat_hook.h"
#include "ipc_client.h"
#include <strsafe.h>

extern void RemoraLog(DWORD hook_id, DWORD arg_count, UINT64 *args, void *ret_addr);
extern void RemoraLogReturn(DWORD hook_id, UINT64 ret_value);
extern JailAction RemoraGetJail(DWORD hook_id);
extern JailAction RemoraGetJailRaw(DWORD hook_id);
extern JailAction RemoraAskJail(DWORD hook_id, const char *extra_text, void *ret_addr);
extern JailAction RemoraEvalRules(DWORD hook_id, const char *str_field, UINT64 num_field);
extern int RemoraIsInHook(void);
extern void tls_set_in_hook(int val);
extern void *g_hook_handlers[];
extern IpcClient g_ipc;
extern void RemoraSendBuffer(DWORD hook_id, int buf_type, const void *data, DWORD data_len);

typedef HINTERNET (WINAPI *fn_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *fn_InternetOpenW)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *fn_InternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *fn_InternetConnectW)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *fn_HttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *fn_HttpOpenRequestW)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *fn_HttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *fn_HttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
typedef HINTERNET (WINAPI *fn_InternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *fn_InternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *fn_InternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);

static void send_http_log(DWORD hook_id, void *ret_addr, const char *text) {
    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_LOG_TEXT;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.ret_addr = (UINT64)ret_addr;
    msg.extra_len = (DWORD)lstrlenA(text) + 1;
    IpcClientSend(&g_ipc, &msg, text, msg.extra_len);
}

static void wide_to_utf8(LPCWSTR src, char *dst, int dst_size) {
    if (src)
        WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dst_size, NULL, NULL);
    else
        lstrcpyA(dst, "(null)");
}

static const char *access_type_name(DWORD type) {
    switch (type) {
    case 1:  return "DIRECT";
    case 0:  return "PRECONFIG";
    case 3:  return "PROXY";
    case 4:  return "PRECONFIG_WITH_NO_AUTOPROXY";
    default: return NULL;
    }
}

static void format_inet_flags(DWORD flags, char *out, int out_size) {
    out[0] = 0;
    struct { DWORD flag; const char *name; } known[] = {
        { 0x00800000, "SECURE" },
        { 0x80000000, "RELOAD" },
        { 0x04000000, "NO_CACHE_WRITE" },
        { 0x10000000, "NO_COOKIES" },
        { 0x00400000, "KEEP_CONNECTION" },
        { 0x00200000, "NO_AUTO_REDIRECT" },
        { 0x20000000, "NO_UI" },
        { 0x08000000, "PRAGMA_NOCACHE" },
        { 0x02000000, "IGNORE_CERT_CN_INVALID" },
        { 0x00001000, "IGNORE_CERT_DATE_INVALID" },
    };
    int pos = 0;
    DWORD remaining = flags;
    for (int i = 0; i < sizeof(known)/sizeof(known[0]); i++) {
        if (flags & known[i].flag) {
            if (pos > 0 && pos < out_size - 1) out[pos++] = '|';
            int n = lstrlenA(known[i].name);
            if (pos + n < out_size) {
                lstrcpynA(out + pos, known[i].name, out_size - pos);
                pos += n;
            }
            remaining &= ~known[i].flag;
        }
    }
    if (remaining) {
        if (pos > 0 && pos < out_size - 1) out[pos++] = '|';
        StringCchPrintfA(out + pos, (size_t)(out_size - pos), "0x%X", remaining);
    }
    if (pos == 0)
        lstrcpyA(out, "0");
}

static const char *fmt_hinet(HINTERNET h, char *out) {
    if (!h) { lstrcpyA(out, "NULL"); return out; }
    StringCchPrintfA(out, 32, "0x%X", (DWORD)(DWORD_PTR)h);
    return out;
}

/* ==================== InternetOpen ==================== */

static HINTERNET WINAPI hook_InternetOpenA(LPCSTR agent, DWORD access, LPCSTR proxy, LPCSTR bypass, DWORD flags) {
    fn_InternetOpenA orig = (fn_InternetOpenA)EatHookGetOriginal(HOOK_InternetOpenA);
    if (RemoraIsInHook()) return orig(agent, access, proxy, bypass, flags);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_InternetOpenA, agent ? agent : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_InternetOpenA);
    if (action == JAIL_ASK) {
        char ask_buf[256];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "InternetOpenA(\"%s\")", agent ? agent : "(null)");
        action = RemoraAskJail(HOOK_InternetOpenA, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return NULL;
    HINTERNET ret = orig(agent, access, proxy, bypass, flags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[512];
        char rv[32];
        const char *at = access_type_name(access);
        if (at)
            StringCchPrintfA(buf, sizeof(buf), "InternetOpenA(\"%s\", %s) -> %s",
                agent ? agent : "(null)", at, fmt_hinet(ret, rv));
        else
            StringCchPrintfA(buf, sizeof(buf), "InternetOpenA(\"%s\", type=%u) -> %s",
                agent ? agent : "(null)", access, fmt_hinet(ret, rv));
        send_http_log(HOOK_InternetOpenA, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

static HINTERNET WINAPI hook_InternetOpenW(LPCWSTR agent, DWORD access, LPCWSTR proxy, LPCWSTR bypass, DWORD flags) {
    fn_InternetOpenW orig = (fn_InternetOpenW)EatHookGetOriginal(HOOK_InternetOpenW);
    if (RemoraIsInHook()) return orig(agent, access, proxy, bypass, flags);
    void *caller = _ReturnAddress();
    char agent_str[256];
    wide_to_utf8(agent, agent_str, sizeof(agent_str));
    JailAction action = RemoraEvalRules(HOOK_InternetOpenA, agent ? agent_str : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_InternetOpenW);
    if (action == JAIL_ASK) {
        char ask_buf[300];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "InternetOpenW(\"%s\")", agent_str);
        action = RemoraAskJail(HOOK_InternetOpenW, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return NULL;
    HINTERNET ret = orig(agent, access, proxy, bypass, flags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[512];
        char rv[32];
        const char *at = access_type_name(access);
        if (at)
            StringCchPrintfA(buf, sizeof(buf), "InternetOpenW(\"%s\", %s) -> %s",
                agent_str, at, fmt_hinet(ret, rv));
        else
            StringCchPrintfA(buf, sizeof(buf), "InternetOpenW(\"%s\", type=%u) -> %s",
                agent_str, access, fmt_hinet(ret, rv));
        send_http_log(HOOK_InternetOpenW, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

/* ==================== InternetConnect ==================== */

static HINTERNET WINAPI hook_InternetConnectA(HINTERNET inet, LPCSTR server, INTERNET_PORT port,
    LPCSTR user, LPCSTR pass, DWORD service, DWORD flags, DWORD_PTR ctx) {
    fn_InternetConnectA orig = (fn_InternetConnectA)EatHookGetOriginal(HOOK_InternetConnectA);
    if (RemoraIsInHook()) return orig(inet, server, port, user, pass, service, flags, ctx);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_InternetConnectA, server ? server : "", (UINT64)port);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_InternetConnectA);
    if (action == JAIL_ASK) {
        char ask_buf[300];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "InternetConnectA(\"%s\":%u)", server ? server : "(null)", (unsigned)port);
        action = RemoraAskJail(HOOK_InternetConnectA, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return NULL;
    HINTERNET ret = orig(inet, server, port, user, pass, service, flags, ctx);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[512];
        char rv[32];
        StringCchPrintfA(buf, sizeof(buf), "InternetConnectA(\"%s\":%u) -> %s",
            server ? server : "(null)", (unsigned)port, fmt_hinet(ret, rv));
        send_http_log(HOOK_InternetConnectA, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

static HINTERNET WINAPI hook_InternetConnectW(HINTERNET inet, LPCWSTR server, INTERNET_PORT port,
    LPCWSTR user, LPCWSTR pass, DWORD service, DWORD flags, DWORD_PTR ctx) {
    fn_InternetConnectW orig = (fn_InternetConnectW)EatHookGetOriginal(HOOK_InternetConnectW);
    if (RemoraIsInHook()) return orig(inet, server, port, user, pass, service, flags, ctx);
    void *caller = _ReturnAddress();
    char server_str[256];
    wide_to_utf8(server, server_str, sizeof(server_str));
    JailAction action = RemoraEvalRules(HOOK_InternetConnectA, server ? server_str : "", (UINT64)port);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_InternetConnectW);
    if (action == JAIL_ASK) {
        char ask_buf[300];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "InternetConnectW(\"%s\":%u)", server_str, (unsigned)port);
        action = RemoraAskJail(HOOK_InternetConnectW, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return NULL;
    HINTERNET ret = orig(inet, server, port, user, pass, service, flags, ctx);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[512];
        char rv[32];
        StringCchPrintfA(buf, sizeof(buf), "InternetConnectW(\"%s\":%u) -> %s",
            server_str, (unsigned)port, fmt_hinet(ret, rv));
        send_http_log(HOOK_InternetConnectW, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

/* ==================== HttpOpenRequest ==================== */

static HINTERNET WINAPI hook_HttpOpenRequestA(HINTERNET conn, LPCSTR verb, LPCSTR obj,
    LPCSTR ver, LPCSTR ref, LPCSTR *types, DWORD flags, DWORD_PTR ctx) {
    fn_HttpOpenRequestA orig = (fn_HttpOpenRequestA)EatHookGetOriginal(HOOK_HttpOpenRequestA);
    if (RemoraIsInHook()) return orig(conn, verb, obj, ver, ref, types, flags, ctx);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_HttpOpenRequestA, obj ? obj : "/", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_HttpOpenRequestA);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "HttpOpenRequestA(\"%s\", \"%s\")",
            verb ? verb : "GET", obj ? obj : "/");
        action = RemoraAskJail(HOOK_HttpOpenRequestA, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return NULL;
    HINTERNET ret = orig(conn, verb, obj, ver, ref, types, flags, ctx);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[512];
        char f_str[256];
        format_inet_flags(flags, f_str, sizeof(f_str));
        char rv[32];
        StringCchPrintfA(buf, sizeof(buf), "HttpOpenRequestA(\"%s\", \"%s\", %s) -> %s",
            verb ? verb : "GET", obj ? obj : "/", f_str, fmt_hinet(ret, rv));
        send_http_log(HOOK_HttpOpenRequestA, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

static HINTERNET WINAPI hook_HttpOpenRequestW(HINTERNET conn, LPCWSTR verb, LPCWSTR obj,
    LPCWSTR ver, LPCWSTR ref, LPCWSTR *types, DWORD flags, DWORD_PTR ctx) {
    fn_HttpOpenRequestW orig = (fn_HttpOpenRequestW)EatHookGetOriginal(HOOK_HttpOpenRequestW);
    if (RemoraIsInHook()) return orig(conn, verb, obj, ver, ref, types, flags, ctx);
    void *caller = _ReturnAddress();
    char verb_str[64], obj_str[512];
    wide_to_utf8(verb, verb_str, sizeof(verb_str));
    wide_to_utf8(obj, obj_str, sizeof(obj_str));
    if (!verb) lstrcpyA(verb_str, "GET");
    if (!obj) lstrcpyA(obj_str, "/");
    JailAction action = RemoraEvalRules(HOOK_HttpOpenRequestA, obj_str, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_HttpOpenRequestW);
    if (action == JAIL_ASK) {
        char ask_buf[600];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "HttpOpenRequestW(\"%s\", \"%s\")", verb_str, obj_str);
        action = RemoraAskJail(HOOK_HttpOpenRequestW, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return NULL;
    HINTERNET ret = orig(conn, verb, obj, ver, ref, types, flags, ctx);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[600];
        char f_str[256];
        format_inet_flags(flags, f_str, sizeof(f_str));
        char rv[32];
        StringCchPrintfA(buf, sizeof(buf), "HttpOpenRequestW(\"%s\", \"%s\", %s) -> %s",
            verb_str, obj_str, f_str, fmt_hinet(ret, rv));
        send_http_log(HOOK_HttpOpenRequestW, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

/* ==================== HttpSendRequest ==================== */

static void get_headers_a(LPCSTR hdrs, DWORD hdr_len, char *out, int out_size) {
    out[0] = 0;
    if (!hdrs || hdr_len == 0) return;
    DWORD len = (hdr_len == (DWORD)-1) ? (DWORD)lstrlenA(hdrs) : hdr_len;
    if (len == 0) return;
    if ((int)len >= out_size) len = out_size - 1;
    memcpy(out, hdrs, len);
    out[len] = 0;
    for (int i = 0; i < (int)len; i++)
        if (out[i] == '\r' || out[i] == '\n') out[i] = ' ';
}

static void get_headers_w(LPCWSTR hdrs, DWORD hdr_len, char *out, int out_size) {
    out[0] = 0;
    if (!hdrs || hdr_len == 0) return;
    int wlen = (hdr_len == (DWORD)-1) ? lstrlenW(hdrs) : (int)hdr_len;
    if (wlen <= 0) return;
    int wrote = WideCharToMultiByte(CP_UTF8, 0, hdrs, wlen, out, out_size - 1, NULL, NULL);
    if (wrote <= 0) return;
    out[wrote] = 0;
    for (int i = 0; i < wrote; i++)
        if (out[i] == '\r' || out[i] == '\n') out[i] = ' ';
}

static BOOL WINAPI hook_HttpSendRequestA(HINTERNET req, LPCSTR hdrs, DWORD hdr_len, LPVOID opt, DWORD opt_len) {
    fn_HttpSendRequestA orig = (fn_HttpSendRequestA)EatHookGetOriginal(HOOK_HttpSendRequestA);
    if (RemoraIsInHook()) return orig(req, hdrs, hdr_len, opt, opt_len);
    void *caller = _ReturnAddress();
    char hdr_str[512];
    get_headers_a(hdrs, hdr_len, hdr_str, sizeof(hdr_str));
    JailAction action = RemoraEvalRules(HOOK_HttpSendRequestA, hdr_str, (UINT64)opt_len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_HttpSendRequestA);
    if (action == JAIL_ASK) {
        char ask_buf[256];
        if (hdr_str[0]) {
            char trunc[128];
            lstrcpynA(trunc, hdr_str, sizeof(trunc));
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "HttpSendRequestA(hdrs=\"%.120s\", %u opt bytes)", trunc, opt_len);
        } else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "HttpSendRequestA(no hdrs, %u opt bytes)", opt_len);
        action = RemoraAskJail(HOOK_HttpSendRequestA, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return FALSE;
    BOOL ret = orig(req, hdrs, hdr_len, opt, opt_len);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[768];
        if (hdr_str[0])
            StringCchPrintfA(buf, sizeof(buf), "HttpSendRequestA(hdrs=\"%s\", %u opt bytes) -> %s",
                hdr_str, opt_len, ret ? "TRUE" : "FALSE");
        else
            StringCchPrintfA(buf, sizeof(buf), "HttpSendRequestA(no hdrs, %u opt bytes) -> %s",
                opt_len, ret ? "TRUE" : "FALSE");
        send_http_log(HOOK_HttpSendRequestA, caller, buf);
        if (opt && opt_len > 0)
            RemoraSendBuffer(HOOK_HttpSendRequestA, BUFFER_INPUT, opt, opt_len);
        tls_set_in_hook(0);
    }
    return ret;
}

static BOOL WINAPI hook_HttpSendRequestW(HINTERNET req, LPCWSTR hdrs, DWORD hdr_len, LPVOID opt, DWORD opt_len) {
    fn_HttpSendRequestW orig = (fn_HttpSendRequestW)EatHookGetOriginal(HOOK_HttpSendRequestW);
    if (RemoraIsInHook()) return orig(req, hdrs, hdr_len, opt, opt_len);
    void *caller = _ReturnAddress();
    char hdr_str[512];
    get_headers_w(hdrs, hdr_len, hdr_str, sizeof(hdr_str));
    JailAction action = RemoraEvalRules(HOOK_HttpSendRequestW, hdr_str, (UINT64)opt_len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_HttpSendRequestW);
    if (action == JAIL_ASK) {
        char ask_buf[256];
        if (hdr_str[0]) {
            char trunc[128];
            lstrcpynA(trunc, hdr_str, sizeof(trunc));
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "HttpSendRequestW(hdrs=\"%.120s\", %u opt bytes)", trunc, opt_len);
        } else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "HttpSendRequestW(no hdrs, %u opt bytes)", opt_len);
        action = RemoraAskJail(HOOK_HttpSendRequestW, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return FALSE;
    BOOL ret = orig(req, hdrs, hdr_len, opt, opt_len);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[768];
        if (hdr_str[0])
            StringCchPrintfA(buf, sizeof(buf), "HttpSendRequestW(hdrs=\"%s\", %u opt bytes) -> %s",
                hdr_str, opt_len, ret ? "TRUE" : "FALSE");
        else
            StringCchPrintfA(buf, sizeof(buf), "HttpSendRequestW(no hdrs, %u opt bytes) -> %s",
                opt_len, ret ? "TRUE" : "FALSE");
        send_http_log(HOOK_HttpSendRequestW, caller, buf);
        if (opt && opt_len > 0)
            RemoraSendBuffer(HOOK_HttpSendRequestW, BUFFER_INPUT, opt, opt_len);
        tls_set_in_hook(0);
    }
    return ret;
}

/* ==================== InternetOpenUrl ==================== */

static HINTERNET WINAPI hook_InternetOpenUrlA(HINTERNET inet, LPCSTR url, LPCSTR hdrs,
    DWORD hdr_len, DWORD flags, DWORD_PTR ctx) {
    fn_InternetOpenUrlA orig = (fn_InternetOpenUrlA)EatHookGetOriginal(HOOK_InternetOpenUrlA);
    if (RemoraIsInHook()) return orig(inet, url, hdrs, hdr_len, flags, ctx);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_InternetOpenUrlA, url ? url : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_InternetOpenUrlA);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "InternetOpenUrlA(\"%s\")", url ? url : "(null)");
        action = RemoraAskJail(HOOK_InternetOpenUrlA, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return NULL;
    HINTERNET ret = orig(inet, url, hdrs, hdr_len, flags, ctx);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[600];
        char f_str[256];
        format_inet_flags(flags, f_str, sizeof(f_str));
        char rv[32];
        StringCchPrintfA(buf, sizeof(buf), "InternetOpenUrlA(\"%s\", %s) -> %s",
            url ? url : "(null)", f_str, fmt_hinet(ret, rv));
        send_http_log(HOOK_InternetOpenUrlA, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

static HINTERNET WINAPI hook_InternetOpenUrlW(HINTERNET inet, LPCWSTR url, LPCWSTR hdrs,
    DWORD hdr_len, DWORD flags, DWORD_PTR ctx) {
    fn_InternetOpenUrlW orig = (fn_InternetOpenUrlW)EatHookGetOriginal(HOOK_InternetOpenUrlW);
    if (RemoraIsInHook()) return orig(inet, url, hdrs, hdr_len, flags, ctx);
    void *caller = _ReturnAddress();
    char url_str[512];
    wide_to_utf8(url, url_str, sizeof(url_str));
    JailAction action = RemoraEvalRules(HOOK_InternetOpenUrlA, url ? url_str : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_InternetOpenUrlW);
    if (action == JAIL_ASK) {
        char ask_buf[560];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "InternetOpenUrlW(\"%s\")", url_str);
        action = RemoraAskJail(HOOK_InternetOpenUrlW, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return NULL;
    HINTERNET ret = orig(inet, url, hdrs, hdr_len, flags, ctx);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[600];
        char f_str[256];
        format_inet_flags(flags, f_str, sizeof(f_str));
        char rv[32];
        StringCchPrintfA(buf, sizeof(buf), "InternetOpenUrlW(\"%s\", %s) -> %s",
            url_str, f_str, fmt_hinet(ret, rv));
        send_http_log(HOOK_InternetOpenUrlW, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

/* ==================== InternetReadFile ==================== */

static BOOL WINAPI hook_InternetReadFile(HINTERNET hFile, LPVOID buf, DWORD len, LPDWORD read_out) {
    fn_InternetReadFile orig = (fn_InternetReadFile)EatHookGetOriginal(HOOK_InternetReadFile);
    if (RemoraIsInHook()) return orig(hFile, buf, len, read_out);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_InternetReadFile, "", (UINT64)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_InternetReadFile);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "InternetReadFile(handle=0x%I64X, %u bytes)",
            (UINT64)(UINT_PTR)hFile, len);
        action = RemoraAskJail(HOOK_InternetReadFile, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (read_out) *read_out = 0;
        return FALSE;
    }
    BOOL ret = orig(hFile, buf, len, read_out);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        DWORD bytes_read = (read_out && ret) ? *read_out : 0;
        char log_buf[256];
        StringCchPrintfA(log_buf, sizeof(log_buf), "InternetReadFile(handle=0x%I64X, %u bytes) -> %s, read %u/%u",
            (UINT64)(UINT_PTR)hFile, len, ret ? "TRUE" : "FALSE", bytes_read, len);
        send_http_log(HOOK_InternetReadFile, caller, log_buf);
        tls_set_in_hook(0);
    }
    return ret;
}

void RegisterHttpHooks(void) {
    g_hook_handlers[HOOK_InternetOpenA] = hook_InternetOpenA;
    g_hook_handlers[HOOK_InternetOpenW] = hook_InternetOpenW;
    g_hook_handlers[HOOK_InternetConnectA] = hook_InternetConnectA;
    g_hook_handlers[HOOK_InternetConnectW] = hook_InternetConnectW;
    g_hook_handlers[HOOK_HttpOpenRequestA] = hook_HttpOpenRequestA;
    g_hook_handlers[HOOK_HttpOpenRequestW] = hook_HttpOpenRequestW;
    g_hook_handlers[HOOK_HttpSendRequestA] = hook_HttpSendRequestA;
    g_hook_handlers[HOOK_HttpSendRequestW] = hook_HttpSendRequestW;
    g_hook_handlers[HOOK_InternetOpenUrlA] = hook_InternetOpenUrlA;
    g_hook_handlers[HOOK_InternetOpenUrlW] = hook_InternetOpenUrlW;
    g_hook_handlers[HOOK_InternetReadFile] = hook_InternetReadFile;
}
