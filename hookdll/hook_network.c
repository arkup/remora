#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <intrin.h>
#include <stdarg.h>
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

typedef int (WINAPI *fn_connect)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI *fn_send)(SOCKET, const char*, int, int);
typedef int (WINAPI *fn_sendto)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WINAPI *fn_recv)(SOCKET, char*, int, int);
typedef int (WINAPI *fn_recvfrom)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef INT (WINAPI *fn_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef INT (WINAPI *fn_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef INT (WINAPI *fn_GetAddrInfoExW)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW*,
    PADDRINFOEXW*, struct timeval*, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
typedef int (WINAPI *fn_closesocket)(SOCKET);
typedef int (WINAPI *fn_WSAConnect)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int (WINAPI *fn_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static void send_text_log(DWORD hook_id, void *ret_addr, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    StringCchVPrintfA(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_LOG_TEXT;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.ret_addr = (UINT64)ret_addr;
    msg.extra_len = (DWORD)strlen(buf) + 1;
    IpcClientSend(&g_ipc, &msg, buf, msg.extra_len);
}

static void format_sockaddr(const struct sockaddr *addr, int addrlen, char *out, int out_size) {
    if (!addr || addrlen < (int)sizeof(struct sockaddr_in)) {
        StringCchPrintfA(out, (size_t)out_size, "???");
        return;
    }
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        BYTE *ip = (BYTE *)&sin->sin_addr;
        StringCchPrintfA(out, (size_t)out_size, "%u.%u.%u.%u:%u", ip[0], ip[1], ip[2], ip[3], ntohs(sin->sin_port));
    } else if (addr->sa_family == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        StringCchPrintfA(out, (size_t)out_size, "[::ipv6]:%u", ntohs(sin6->sin6_port));
    } else {
        StringCchPrintfA(out, (size_t)out_size, "af=%u", addr->sa_family);
    }
}

static void format_send_flags(int flags, char *out, int out_size) {
    if (flags == 0) { lstrcpyA(out, "0"); return; }
    out[0] = 0;
    int pos = 0;
    struct { int flag; const char *name; } known[] = {
        { 0x1, "MSG_OOB" },
        { 0x2, "MSG_PEEK" },
        { 0x4, "MSG_DONTROUTE" },
        { 0x20, "MSG_WAITALL" },
    };
    int remaining = flags;
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
        StringCchPrintfA(out, (size_t)out_size, "0x%X", flags);
}

static const char *gai_error_name(INT err) {
    switch (err) {
    case 0:      return "0";
    case 11001:  return "WSAHOST_NOT_FOUND";
    case 11002:  return "WSATRY_AGAIN";
    case 11003:  return "WSANO_RECOVERY";
    case 11004:  return "WSANO_DATA";
    case 10044:  return "WSAESOCKTNOSUPPORT";
    case 10047:  return "WSAEAFNOSUPPORT";
    case 10109:  return "WSATYPE_NOT_FOUND";
    case 8:      return "WSA_NOT_ENOUGH_MEMORY";
    default:     return NULL;
    }
}

static int WINAPI hook_connect(SOCKET s, const struct sockaddr *addr, int addrlen) {
    fn_connect orig = (fn_connect)EatHookGetOriginal(HOOK_connect);
    if (!orig) return SOCKET_ERROR;
    if (RemoraIsInHook()) return orig(s, addr, addrlen);
    char addr_str[128];
    format_sockaddr(addr, addrlen, addr_str, sizeof(addr_str));
    UINT64 port_num = 0;
    if (addr && addrlen >= (int)sizeof(struct sockaddr_in) && addr->sa_family == AF_INET)
        port_num = (UINT64)ntohs(((struct sockaddr_in *)addr)->sin_port);
    JailAction action = RemoraEvalRules(HOOK_connect, addr_str, port_num);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_connect);
    if (action == JAIL_ASK) {
        char ask_buf[256];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "connect(sock=%u, %s)", (DWORD)s, addr_str);
        action = RemoraAskJail(HOOK_connect, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return SOCKET_ERROR;
    int ret = orig(s, addr, addrlen);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        send_text_log(HOOK_connect, _ReturnAddress(),
            "connect(sock=%u, %s) -> %d", (DWORD)s, addr_str, ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static int WINAPI hook_send(SOCKET s, const char *buf, int len, int flags) {
    fn_send orig = (fn_send)EatHookGetOriginal(HOOK_send);
    if (!orig) return SOCKET_ERROR;
    if (RemoraIsInHook()) return orig(s, buf, len, flags);
    JailAction action = RemoraEvalRules(HOOK_send, "", (UINT64)(unsigned)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_send);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "send(sock=%u, %d bytes)", (DWORD)s, len);
        action = RemoraAskJail(HOOK_send, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return SOCKET_ERROR;
    int ret = orig(s, buf, len, flags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char sf[64];
        format_send_flags(flags, sf, sizeof(sf));
        send_text_log(HOOK_send, _ReturnAddress(),
            "send(sock=%u, len=%d, flags=%s) -> %d", (DWORD)s, len, sf, ret);
        if (ret > 0)
            RemoraSendBuffer(HOOK_send, BUFFER_INPUT, buf, (DWORD)ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static int WINAPI hook_sendto(SOCKET s, const char *buf, int len, int flags,
    const struct sockaddr *to, int tolen) {
    fn_sendto orig = (fn_sendto)EatHookGetOriginal(HOOK_sendto);
    if (!orig) return SOCKET_ERROR;
    if (RemoraIsInHook()) return orig(s, buf, len, flags, to, tolen);
    char st_addr_str[128];
    format_sockaddr(to, tolen, st_addr_str, sizeof(st_addr_str));
    JailAction action = RemoraEvalRules(HOOK_sendto, st_addr_str, (UINT64)(unsigned)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_sendto);
    if (action == JAIL_ASK) {
        char ask_buf[256];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "sendto(sock=%u, %d bytes, %s)", (DWORD)s, len, st_addr_str);
        action = RemoraAskJail(HOOK_sendto, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return SOCKET_ERROR;
    int ret = orig(s, buf, len, flags, to, tolen);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char sf[64];
        format_send_flags(flags, sf, sizeof(sf));
        send_text_log(HOOK_sendto, _ReturnAddress(),
            "sendto(sock=%u, len=%d, %s, flags=%s) -> %d", (DWORD)s, len, st_addr_str, sf, ret);
        if (ret > 0)
            RemoraSendBuffer(HOOK_sendto, BUFFER_INPUT, buf, (DWORD)ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static int WINAPI hook_recv(SOCKET s, char *buf, int len, int flags) {
    fn_recv orig = (fn_recv)EatHookGetOriginal(HOOK_recv);
    if (!orig) return SOCKET_ERROR;
    if (RemoraIsInHook()) return orig(s, buf, len, flags);
    JailAction action = RemoraEvalRules(HOOK_recv, "", (UINT64)(unsigned)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_recv);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "recv(sock=%u, %d bytes)", (DWORD)s, len);
        action = RemoraAskJail(HOOK_recv, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return SOCKET_ERROR;
    int ret = orig(s, buf, len, flags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        send_text_log(HOOK_recv, _ReturnAddress(),
            "recv(sock=%u, len=%d) -> %d", (DWORD)s, len, ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static int WINAPI hook_recvfrom(SOCKET s, char *buf, int len, int flags,
    struct sockaddr *from, int *fromlen) {
    fn_recvfrom orig = (fn_recvfrom)EatHookGetOriginal(HOOK_recvfrom);
    if (!orig) return SOCKET_ERROR;
    if (RemoraIsInHook()) return orig(s, buf, len, flags, from, fromlen);
    JailAction action = RemoraEvalRules(HOOK_recvfrom, "", (UINT64)(unsigned)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_recvfrom);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "recvfrom(sock=%u, %d bytes)", (DWORD)s, len);
        action = RemoraAskJail(HOOK_recvfrom, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return SOCKET_ERROR;
    int ret = orig(s, buf, len, flags, from, fromlen);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char addr_str[128] = "???";
        if (from && fromlen && *fromlen > 0)
            format_sockaddr(from, *fromlen, addr_str, sizeof(addr_str));
        send_text_log(HOOK_recvfrom, _ReturnAddress(),
            "recvfrom(sock=%u, len=%d, %s) -> %d", (DWORD)s, len, addr_str, ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static INT WINAPI hook_getaddrinfo(PCSTR node, PCSTR service,
    const ADDRINFOA *hints, PADDRINFOA *res) {
    fn_getaddrinfo orig = (fn_getaddrinfo)EatHookGetOriginal(HOOK_getaddrinfo);
    if (!orig) return WSAHOST_NOT_FOUND;
    if (RemoraIsInHook()) return orig(node, service, hints, res);
    JailAction action = RemoraEvalRules(HOOK_getaddrinfo, node ? node : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_getaddrinfo);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "getaddrinfo(\"%s\", \"%s\")",
            node ? node : "NULL", service ? service : "NULL");
        action = RemoraAskJail(HOOK_getaddrinfo, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return WSAHOST_NOT_FOUND;
    INT ret = orig(node, service, hints, res);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        const char *ename = gai_error_name(ret);
        if (ename)
            send_text_log(HOOK_getaddrinfo, _ReturnAddress(),
                "getaddrinfo(\"%s\", \"%s\") -> %s",
                node ? node : "NULL", service ? service : "NULL", ename);
        else
            send_text_log(HOOK_getaddrinfo, _ReturnAddress(),
                "getaddrinfo(\"%s\", \"%s\") -> %d",
                node ? node : "NULL", service ? service : "NULL", ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static INT WINAPI hook_GetAddrInfoW(PCWSTR node, PCWSTR service,
    const ADDRINFOW *hints, PADDRINFOW *res) {
    fn_GetAddrInfoW orig = (fn_GetAddrInfoW)EatHookGetOriginal(HOOK_GetAddrInfoW);
    if (!orig) return WSAHOST_NOT_FOUND;
    if (RemoraIsInHook()) return orig(node, service, hints, res);
    char node_a[256] = "NULL";
    if (node) WideCharToMultiByte(CP_UTF8, 0, node, -1, node_a, sizeof(node_a), NULL, NULL);
    char svc_a[64] = "NULL";
    if (service) WideCharToMultiByte(CP_UTF8, 0, service, -1, svc_a, sizeof(svc_a), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_GetAddrInfoW, node_a, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_GetAddrInfoW);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetAddrInfoW(\"%s\", \"%s\")", node_a, svc_a);
        action = RemoraAskJail(HOOK_GetAddrInfoW, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return WSAHOST_NOT_FOUND;
    INT ret = orig(node, service, hints, res);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        const char *ename = gai_error_name(ret);
        if (ename)
            send_text_log(HOOK_GetAddrInfoW, _ReturnAddress(),
                "GetAddrInfoW(\"%s\", \"%s\") -> %s", node_a, svc_a, ename);
        else
            send_text_log(HOOK_GetAddrInfoW, _ReturnAddress(),
                "GetAddrInfoW(\"%s\", \"%s\") -> %d", node_a, svc_a, ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static INT WINAPI hook_GetAddrInfoExW(PCWSTR name, PCWSTR service_name,
    DWORD ns, LPGUID ns_id, const ADDRINFOEXW *hints, PADDRINFOEXW *result,
    struct timeval *timeout, LPOVERLAPPED overlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE completion, LPHANDLE cancel_handle) {
    fn_GetAddrInfoExW orig = (fn_GetAddrInfoExW)EatHookGetOriginal(HOOK_GetAddrInfoExW);
    if (!orig) return WSAHOST_NOT_FOUND;
    if (RemoraIsInHook()) return orig(name, service_name, ns, ns_id, hints, result,
        timeout, overlapped, completion, cancel_handle);
    char name_a[256] = "NULL";
    if (name) WideCharToMultiByte(CP_UTF8, 0, name, -1, name_a, sizeof(name_a), NULL, NULL);
    char svc_a[64] = "NULL";
    if (service_name) WideCharToMultiByte(CP_UTF8, 0, service_name, -1, svc_a, sizeof(svc_a), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_GetAddrInfoExW, name_a, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_GetAddrInfoExW);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "GetAddrInfoExW(\"%s\", \"%s\")", name_a, svc_a);
        action = RemoraAskJail(HOOK_GetAddrInfoExW, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return WSAHOST_NOT_FOUND;
    INT ret = orig(name, service_name, ns, ns_id, hints, result,
        timeout, overlapped, completion, cancel_handle);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        int is_async = (ret == WSA_IO_PENDING);
        if (is_async)
            send_text_log(HOOK_GetAddrInfoExW, _ReturnAddress(),
                "GetAddrInfoExW(\"%s\", \"%s\") -> WSA_IO_PENDING (async)", name_a, svc_a);
        else {
            const char *ename = gai_error_name(ret);
            if (ename)
                send_text_log(HOOK_GetAddrInfoExW, _ReturnAddress(),
                    "GetAddrInfoExW(\"%s\", \"%s\") -> %s", name_a, svc_a, ename);
            else
                send_text_log(HOOK_GetAddrInfoExW, _ReturnAddress(),
                    "GetAddrInfoExW(\"%s\", \"%s\") -> %d", name_a, svc_a, ret);
        }
        tls_set_in_hook(0);
    }
    return ret;
}

static int WINAPI hook_closesocket(SOCKET s) {
    fn_closesocket orig = (fn_closesocket)EatHookGetOriginal(HOOK_closesocket);
    if (!orig) return SOCKET_ERROR;
    if (RemoraIsInHook()) return orig(s);
    JailAction action = RemoraEvalRules(HOOK_closesocket, "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_closesocket);
    if (action == JAIL_ASK) {
        char ask_buf[64];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "closesocket(sock=%u)", (DWORD)s);
        action = RemoraAskJail(HOOK_closesocket, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return SOCKET_ERROR;
    int ret = orig(s);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        send_text_log(HOOK_closesocket, _ReturnAddress(),
            "closesocket(sock=%u) -> %d", (DWORD)s, ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static int WINAPI hook_WSAConnect(SOCKET s, const struct sockaddr *addr, int addrlen,
    LPWSABUF caller_data, LPWSABUF callee_data, LPQOS sqos, LPQOS gqos) {
    fn_WSAConnect orig = (fn_WSAConnect)EatHookGetOriginal(HOOK_WSAConnect);
    if (!orig) return SOCKET_ERROR;
    if (RemoraIsInHook()) return orig(s, addr, addrlen, caller_data, callee_data, sqos, gqos);
    char addr_str[128];
    format_sockaddr(addr, addrlen, addr_str, sizeof(addr_str));
    UINT64 port_num = 0;
    if (addr && addrlen >= (int)sizeof(struct sockaddr_in) && addr->sa_family == AF_INET)
        port_num = (UINT64)ntohs(((struct sockaddr_in *)addr)->sin_port);
    JailAction action = RemoraEvalRules(HOOK_WSAConnect, addr_str, port_num);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_WSAConnect);
    if (action == JAIL_ASK) {
        char ask_buf[256];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "WSAConnect(sock=%u, %s)", (DWORD)s, addr_str);
        action = RemoraAskJail(HOOK_WSAConnect, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return SOCKET_ERROR;
    int ret = orig(s, addr, addrlen, caller_data, callee_data, sqos, gqos);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        send_text_log(HOOK_WSAConnect, _ReturnAddress(),
            "WSAConnect(sock=%u, %s) -> %d", (DWORD)s, addr_str, ret);
        tls_set_in_hook(0);
    }
    return ret;
}

static int WINAPI hook_WSASend(SOCKET s, LPWSABUF bufs, DWORD buf_count, LPDWORD bytes_sent,
    DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    fn_WSASend orig = (fn_WSASend)EatHookGetOriginal(HOOK_WSASend);
    if (!orig) return SOCKET_ERROR;
    if (RemoraIsInHook()) return orig(s, bufs, buf_count, bytes_sent, flags, overlapped, completion);
    DWORD total_len = 0;
    for (DWORD i = 0; i < buf_count; i++)
        total_len += bufs[i].len;
    JailAction action = RemoraEvalRules(HOOK_WSASend, "", (UINT64)total_len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_WSASend);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "WSASend(sock=%u, %u bufs, %u bytes)", (DWORD)s, buf_count, total_len);
        action = RemoraAskJail(HOOK_WSASend, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) return SOCKET_ERROR;
    int ret = orig(s, bufs, buf_count, bytes_sent, flags, overlapped, completion);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        DWORD sent = (bytes_sent && ret == 0) ? *bytes_sent : 0;
        send_text_log(HOOK_WSASend, _ReturnAddress(),
            "WSASend(sock=%u, %u bufs, %u bytes) -> %d (sent=%u)",
            (DWORD)s, buf_count, total_len, ret, sent);
        if (ret == 0 && buf_count > 0 && bufs[0].buf && bufs[0].len > 0)
            RemoraSendBuffer(HOOK_WSASend, BUFFER_INPUT, bufs[0].buf, bufs[0].len);
        tls_set_in_hook(0);
    }
    return ret;
}

void RegisterNetworkHooks(void) {
    g_hook_handlers[HOOK_connect] = hook_connect;
    g_hook_handlers[HOOK_send] = hook_send;
    g_hook_handlers[HOOK_sendto] = hook_sendto;
    g_hook_handlers[HOOK_recv] = hook_recv;
    g_hook_handlers[HOOK_recvfrom] = hook_recvfrom;
    g_hook_handlers[HOOK_getaddrinfo] = hook_getaddrinfo;
    g_hook_handlers[HOOK_GetAddrInfoW] = hook_GetAddrInfoW;
    g_hook_handlers[HOOK_GetAddrInfoExW] = hook_GetAddrInfoExW;
    g_hook_handlers[HOOK_closesocket] = hook_closesocket;
    g_hook_handlers[HOOK_WSAConnect] = hook_WSAConnect;
    g_hook_handlers[HOOK_WSASend] = hook_WSASend;
}
