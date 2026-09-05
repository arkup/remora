#include <windows.h>
#include <intrin.h>
#include "hook_defs.h"
#include "jail_defs.h"
#include "eat_hook.h"
#include "ipc_client.h"
#include <strsafe.h>

extern IpcClient g_ipc;
extern JailAction RemoraGetJailRaw(DWORD hook_id);
extern JailAction RemoraAskJail(DWORD hook_id, const char *extra_text, void *ret_addr);
extern JailAction RemoraEvalRules(DWORD hook_id, const char *str_field, UINT64 num_field);
extern void *g_hook_handlers[];
extern void RemoraSendBuffer(DWORD hook_id, int buf_type, const void *data, DWORD data_len);

static void send_reg_log(DWORD hook_id, void *ret_addr, const char *text) {
    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_LOG_TEXT;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.ret_addr = (UINT64)ret_addr;
    msg.extra_len = (DWORD)lstrlenA(text) + 1;
    IpcClientSend(&g_ipc, &msg, text, msg.extra_len);
}

static const char *hkey_name(HKEY key) {
    if (key == HKEY_CLASSES_ROOT)        return "HKCR";
    if (key == HKEY_CURRENT_USER)        return "HKCU";
    if (key == HKEY_LOCAL_MACHINE)        return "HKLM";
    if (key == HKEY_USERS)               return "HKU";
    if (key == HKEY_CURRENT_CONFIG)      return "HKCC";
    return NULL;
}

static const char *lstatus_name(LONG status) {
    switch (status) {
    case ERROR_SUCCESS:           return "ERROR_SUCCESS";
    case ERROR_FILE_NOT_FOUND:    return "ERROR_FILE_NOT_FOUND";
    case ERROR_ACCESS_DENIED:     return "ERROR_ACCESS_DENIED";
    case ERROR_INVALID_HANDLE:    return "ERROR_INVALID_HANDLE";
    case ERROR_INVALID_PARAMETER: return "ERROR_INVALID_PARAMETER";
    case ERROR_MORE_DATA:         return "ERROR_MORE_DATA";
    case ERROR_NO_MORE_ITEMS:     return "ERROR_NO_MORE_ITEMS";
    case ERROR_KEY_DELETED:       return "ERROR_KEY_DELETED";
    default:                      return NULL;
    }
}

static void append_status(char *buf, int buf_size, LONG status) {
    const char *name = lstatus_name(status);
    int len = lstrlenA(buf);
    if (name)
        StringCchPrintfA(buf + len, (size_t)(buf_size - len), " -> %s", name);
    else
        StringCchPrintfA(buf + len, (size_t)(buf_size - len), " -> 0x%X", status);
}

static const char *reg_type_name(DWORD type) {
    switch (type) {
    case REG_SZ:             return "REG_SZ";
    case REG_EXPAND_SZ:      return "REG_EXPAND_SZ";
    case REG_BINARY:         return "REG_BINARY";
    case REG_DWORD:          return "REG_DWORD";
    case REG_QWORD:          return "REG_QWORD";
    case REG_MULTI_SZ:       return "REG_MULTI_SZ";
    case REG_NONE:           return "REG_NONE";
    default:                 return NULL;
    }
}

static void decode_regsam(REGSAM sam, char *buf, int bufsize) {
    buf[0] = 0;
    if (sam == (KEY_ALL_ACCESS)) { lstrcpynA(buf, "KEY_ALL_ACCESS", bufsize); return; }
    if (sam == (KEY_READ)) { lstrcpynA(buf, "KEY_READ", bufsize); return; }
    if (sam == (KEY_WRITE)) { lstrcpynA(buf, "KEY_WRITE", bufsize); return; }
    if (sam == (KEY_READ | KEY_WRITE)) { lstrcpynA(buf, "KEY_READ|KEY_WRITE", bufsize); return; }
    int pos = 0;
    struct { DWORD flag; const char *name; } known[] = {
        { KEY_QUERY_VALUE,         "QUERY_VALUE" },
        { KEY_SET_VALUE,           "SET_VALUE" },
        { KEY_CREATE_SUB_KEY,      "CREATE_SUB_KEY" },
        { KEY_ENUMERATE_SUB_KEYS,  "ENUM_SUB_KEYS" },
        { KEY_NOTIFY,              "NOTIFY" },
        { KEY_CREATE_LINK,         "CREATE_LINK" },
        { KEY_WOW64_64KEY,         "WOW64_64KEY" },
        { KEY_WOW64_32KEY,         "WOW64_32KEY" },
    };
    DWORD remaining = sam;
    for (int i = 0; i < sizeof(known)/sizeof(known[0]); i++) {
        if (sam & known[i].flag) {
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
        StringCchPrintfA(buf, (size_t)bufsize, "0x%X", sam);
}

typedef LONG (WINAPI *fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG (WINAPI *fn_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LONG (WINAPI *fn_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LONG (WINAPI *fn_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LONG (WINAPI *fn_RegDeleteKeyA)(HKEY, LPCSTR);
typedef LONG (WINAPI *fn_RegDeleteKeyW)(HKEY, LPCWSTR);
typedef LONG (WINAPI *fn_RegDeleteKeyExA)(HKEY, LPCSTR, REGSAM, DWORD);
typedef LONG (WINAPI *fn_RegDeleteKeyExW)(HKEY, LPCWSTR, REGSAM, DWORD);
typedef LONG (WINAPI *fn_RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG (WINAPI *fn_RegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG (WINAPI *fn_RegDeleteValueA)(HKEY, LPCSTR);
typedef LONG (WINAPI *fn_RegDeleteValueW)(HKEY, LPCWSTR);

static LONG WINAPI hook_RegOpenKeyExA(HKEY key, LPCSTR sub, DWORD opts, REGSAM sam, PHKEY out) {
    JailAction action = RemoraEvalRules(HOOK_RegOpenKeyExA, sub ? sub : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegOpenKeyExA);
    char desc[512], sam_str[128];
    decode_regsam(sam, sam_str, sizeof(sam_str));
    const char *root = hkey_name(key);
    if (root)
        StringCchPrintfA(desc, sizeof(desc), "RegOpenKeyExA(%s\\%s, %s)", root, sub ? sub : "", sam_str);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegOpenKeyExA(0x%I64X, \"%s\", %s)", (UINT64)(UINT_PTR)key, sub ? sub : "", sam_str);
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegOpenKeyExA, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegOpenKeyExA, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegOpenKeyExA orig = (fn_RegOpenKeyExA)EatHookGetOriginal(HOOK_RegOpenKeyExA);
    LONG ret = orig(key, sub, opts, sam, out);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegOpenKeyExA, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegOpenKeyExW(HKEY key, LPCWSTR sub, DWORD opts, REGSAM sam, PHKEY out) {
    char sub_utf8[512] = "";
    if (sub) WideCharToMultiByte(CP_UTF8, 0, sub, -1, sub_utf8, sizeof(sub_utf8), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_RegOpenKeyExA, sub_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegOpenKeyExW);
    char desc[600], sam_str[128];
    decode_regsam(sam, sam_str, sizeof(sam_str));
    const char *root = hkey_name(key);
    if (root)
        StringCchPrintfA(desc, sizeof(desc), "RegOpenKeyExW(%s\\%s, %s)", root, sub_utf8, sam_str);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegOpenKeyExW(0x%I64X, \"%s\", %s)", (UINT64)(UINT_PTR)key, sub_utf8, sam_str);
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegOpenKeyExW, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegOpenKeyExW, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegOpenKeyExW orig = (fn_RegOpenKeyExW)EatHookGetOriginal(HOOK_RegOpenKeyExW);
    LONG ret = orig(key, sub, opts, sam, out);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegOpenKeyExW, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegSetValueExA(HKEY key, LPCSTR name, DWORD res, DWORD type, const BYTE *data, DWORD len) {
    JailAction action = RemoraEvalRules(HOOK_RegSetValueExA, name ? name : "", (UINT64)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegSetValueExA);
    char desc[512];
    const char *tname = reg_type_name(type);
    if (tname)
        StringCchPrintfA(desc, sizeof(desc), "RegSetValueExA(\"%s\", %s, %u bytes", name ? name : "", tname, len);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegSetValueExA(\"%s\", type=%u, %u bytes", name ? name : "", type, len);
    int dpos = (int)strlen(desc);
    if (data && len > 0) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            char val_preview[128];
            lstrcpynA(val_preview, (const char *)data, min(len, sizeof(val_preview)));
            StringCchPrintfA(desc + dpos, sizeof(desc) - (size_t)dpos, ", \"%s\"", val_preview);
            dpos = (int)strlen(desc);
        } else if (type == REG_DWORD && len >= 4) {
            StringCchPrintfA(desc + dpos, sizeof(desc) - (size_t)dpos, ", 0x%X", *(DWORD *)data);
            dpos = (int)strlen(desc);
        }
    }
    StringCchPrintfA(desc + dpos, sizeof(desc) - (size_t)dpos, ")");
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegSetValueExA, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegSetValueExA, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegSetValueExA orig = (fn_RegSetValueExA)EatHookGetOriginal(HOOK_RegSetValueExA);
    LONG ret = orig(key, name, res, type, data, len);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegSetValueExA, _ReturnAddress(), desc);
        if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_DWORD)
            RemoraSendBuffer(HOOK_RegSetValueExA, BUFFER_INPUT, data, len);
    }
    return ret;
}

static LONG WINAPI hook_RegSetValueExW(HKEY key, LPCWSTR name, DWORD res, DWORD type, const BYTE *data, DWORD len) {
    char name_utf8[256] = "";
    if (name) WideCharToMultiByte(CP_UTF8, 0, name, -1, name_utf8, sizeof(name_utf8), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_RegSetValueExA, name_utf8, (UINT64)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegSetValueExW);
    char desc[512];
    const char *tname = reg_type_name(type);
    if (tname)
        StringCchPrintfA(desc, sizeof(desc), "RegSetValueExW(\"%s\", %s, %u bytes", name_utf8, tname, len);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegSetValueExW(\"%s\", type=%u, %u bytes", name_utf8, type, len);
    int dpos = (int)strlen(desc);
    if (data && len > 0) {
        if ((type == REG_SZ || type == REG_EXPAND_SZ) && len >= 2) {
            char val_utf8[128];
            WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)data, len / 2, val_utf8, sizeof(val_utf8) - 1, NULL, NULL);
            val_utf8[sizeof(val_utf8) - 1] = 0;
            StringCchPrintfA(desc + dpos, sizeof(desc) - (size_t)dpos, ", \"%s\"", val_utf8);
            dpos = (int)strlen(desc);
        } else if (type == REG_DWORD && len >= 4) {
            StringCchPrintfA(desc + dpos, sizeof(desc) - (size_t)dpos, ", 0x%X", *(DWORD *)data);
            dpos = (int)strlen(desc);
        }
    }
    StringCchPrintfA(desc + dpos, sizeof(desc) - (size_t)dpos, ")");
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegSetValueExW, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegSetValueExW, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegSetValueExW orig = (fn_RegSetValueExW)EatHookGetOriginal(HOOK_RegSetValueExW);
    LONG ret = orig(key, name, res, type, data, len);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegSetValueExW, _ReturnAddress(), desc);
        if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_DWORD)
            RemoraSendBuffer(HOOK_RegSetValueExW, BUFFER_INPUT, data, len);
    }
    return ret;
}

static LONG WINAPI hook_RegDeleteKeyA(HKEY key, LPCSTR sub) {
    JailAction action = RemoraEvalRules(HOOK_RegDeleteKeyA, sub ? sub : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegDeleteKeyA);
    char desc[512];
    const char *root = hkey_name(key);
    if (root)
        StringCchPrintfA(desc, sizeof(desc), "RegDeleteKeyA(%s\\%s)", root, sub ? sub : "");
    else
        StringCchPrintfA(desc, sizeof(desc), "RegDeleteKeyA(0x%I64X, \"%s\")", (UINT64)(UINT_PTR)key, sub ? sub : "");
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegDeleteKeyA, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegDeleteKeyA, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegDeleteKeyA orig = (fn_RegDeleteKeyA)EatHookGetOriginal(HOOK_RegDeleteKeyA);
    LONG ret = orig(key, sub);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegDeleteKeyA, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegDeleteKeyW(HKEY key, LPCWSTR sub) {
    char sub_utf8[512] = "";
    if (sub) WideCharToMultiByte(CP_UTF8, 0, sub, -1, sub_utf8, sizeof(sub_utf8), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_RegDeleteKeyA, sub_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegDeleteKeyW);
    char desc[600];
    const char *root = hkey_name(key);
    if (root)
        StringCchPrintfA(desc, sizeof(desc), "RegDeleteKeyW(%s\\%s)", root, sub_utf8);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegDeleteKeyW(0x%I64X, \"%s\")", (UINT64)(UINT_PTR)key, sub_utf8);
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegDeleteKeyW, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegDeleteKeyW, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegDeleteKeyW orig = (fn_RegDeleteKeyW)EatHookGetOriginal(HOOK_RegDeleteKeyW);
    LONG ret = orig(key, sub);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegDeleteKeyW, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegDeleteKeyExA(HKEY key, LPCSTR sub, REGSAM sam, DWORD reserved) {
    JailAction action = RemoraEvalRules(HOOK_RegDeleteKeyExA, sub ? sub : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegDeleteKeyExA);
    char desc[512], sam_str[128];
    decode_regsam(sam, sam_str, sizeof(sam_str));
    const char *root = hkey_name(key);
    if (root)
        StringCchPrintfA(desc, sizeof(desc), "RegDeleteKeyExA(%s\\%s, %s)", root, sub ? sub : "", sam_str);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegDeleteKeyExA(0x%I64X, \"%s\", %s)", (UINT64)(UINT_PTR)key, sub ? sub : "", sam_str);
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegDeleteKeyExA, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegDeleteKeyExA, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegDeleteKeyExA orig = (fn_RegDeleteKeyExA)EatHookGetOriginal(HOOK_RegDeleteKeyExA);
    LONG ret = orig(key, sub, sam, reserved);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegDeleteKeyExA, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegDeleteKeyExW(HKEY key, LPCWSTR sub, REGSAM sam, DWORD reserved) {
    char sub_utf8[512] = "";
    if (sub) WideCharToMultiByte(CP_UTF8, 0, sub, -1, sub_utf8, sizeof(sub_utf8), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_RegDeleteKeyExW, sub_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegDeleteKeyExW);
    char desc[600], sam_str[128];
    decode_regsam(sam, sam_str, sizeof(sam_str));
    const char *root = hkey_name(key);
    if (root)
        StringCchPrintfA(desc, sizeof(desc), "RegDeleteKeyExW(%s\\%s, %s)", root, sub_utf8, sam_str);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegDeleteKeyExW(0x%I64X, \"%s\", %s)", (UINT64)(UINT_PTR)key, sub_utf8, sam_str);
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegDeleteKeyExW, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegDeleteKeyExW, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegDeleteKeyExW orig = (fn_RegDeleteKeyExW)EatHookGetOriginal(HOOK_RegDeleteKeyExW);
    LONG ret = orig(key, sub, sam, reserved);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegDeleteKeyExW, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegCreateKeyExA(HKEY key, LPCSTR sub, DWORD reserved, LPSTR cls,
    DWORD opts, REGSAM sam, LPSECURITY_ATTRIBUTES sa, PHKEY out, LPDWORD disp) {
    JailAction action = RemoraEvalRules(HOOK_RegCreateKeyExA, sub ? sub : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegCreateKeyExA);
    char desc[512], sam_str[128];
    decode_regsam(sam, sam_str, sizeof(sam_str));
    const char *root = hkey_name(key);
    if (root)
        StringCchPrintfA(desc, sizeof(desc), "RegCreateKeyExA(%s\\%s, %s)", root, sub ? sub : "", sam_str);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegCreateKeyExA(0x%I64X, \"%s\", %s)", (UINT64)(UINT_PTR)key, sub ? sub : "", sam_str);
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegCreateKeyExA, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegCreateKeyExA, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegCreateKeyExA orig = (fn_RegCreateKeyExA)EatHookGetOriginal(HOOK_RegCreateKeyExA);
    LONG ret = orig(key, sub, reserved, cls, opts, sam, sa, out, disp);
    if (action >= JAIL_LOG) {
        if (disp && ret == ERROR_SUCCESS) {
            const char *d = (*disp == REG_CREATED_NEW_KEY) ? "CREATED" : "OPENED";
            int len = lstrlenA(desc);
            StringCchPrintfA(desc + len, sizeof(desc) - (size_t)len, " [%s]", d);
        }
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegCreateKeyExA, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegCreateKeyExW(HKEY key, LPCWSTR sub, DWORD reserved, LPWSTR cls,
    DWORD opts, REGSAM sam, LPSECURITY_ATTRIBUTES sa, PHKEY out, LPDWORD disp) {
    char sub_utf8[512] = "";
    if (sub) WideCharToMultiByte(CP_UTF8, 0, sub, -1, sub_utf8, sizeof(sub_utf8), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_RegCreateKeyExA, sub_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegCreateKeyExW);
    char desc[600], sam_str[128];
    decode_regsam(sam, sam_str, sizeof(sam_str));
    const char *root = hkey_name(key);
    if (root)
        StringCchPrintfA(desc, sizeof(desc), "RegCreateKeyExW(%s\\%s, %s)", root, sub_utf8, sam_str);
    else
        StringCchPrintfA(desc, sizeof(desc), "RegCreateKeyExW(0x%I64X, \"%s\", %s)", (UINT64)(UINT_PTR)key, sub_utf8, sam_str);
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegCreateKeyExW, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegCreateKeyExW, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegCreateKeyExW orig = (fn_RegCreateKeyExW)EatHookGetOriginal(HOOK_RegCreateKeyExW);
    LONG ret = orig(key, sub, reserved, cls, opts, sam, sa, out, disp);
    if (action >= JAIL_LOG) {
        if (disp && ret == ERROR_SUCCESS) {
            const char *d = (*disp == REG_CREATED_NEW_KEY) ? "CREATED" : "OPENED";
            int len = lstrlenA(desc);
            StringCchPrintfA(desc + len, sizeof(desc) - (size_t)len, " [%s]", d);
        }
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegCreateKeyExW, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegDeleteValueA(HKEY key, LPCSTR name) {
    JailAction action = RemoraEvalRules(HOOK_RegDeleteValueA, name ? name : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegDeleteValueA);
    char desc[512];
    StringCchPrintfA(desc, sizeof(desc), "RegDeleteValueA(0x%I64X, \"%s\")", (UINT64)(UINT_PTR)key, name ? name : "");
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegDeleteValueA, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegDeleteValueA, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegDeleteValueA orig = (fn_RegDeleteValueA)EatHookGetOriginal(HOOK_RegDeleteValueA);
    LONG ret = orig(key, name);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegDeleteValueA, _ReturnAddress(), desc);
    }
    return ret;
}

static LONG WINAPI hook_RegDeleteValueW(HKEY key, LPCWSTR name) {
    char name_utf8[256] = "";
    if (name) WideCharToMultiByte(CP_UTF8, 0, name, -1, name_utf8, sizeof(name_utf8), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_RegDeleteValueA, name_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_RegDeleteValueW);
    char desc[512];
    StringCchPrintfA(desc, sizeof(desc), "RegDeleteValueW(0x%I64X, \"%s\")", (UINT64)(UINT_PTR)key, name_utf8);
    if (action == JAIL_ASK)
        action = RemoraAskJail(HOOK_RegDeleteValueW, desc, _ReturnAddress());
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            lstrcatA(desc, " -> BLOCKED");
            send_reg_log(HOOK_RegDeleteValueW, _ReturnAddress(), desc);
        }
        return ERROR_ACCESS_DENIED;
    }
    fn_RegDeleteValueW orig = (fn_RegDeleteValueW)EatHookGetOriginal(HOOK_RegDeleteValueW);
    LONG ret = orig(key, name);
    if (action >= JAIL_LOG) {
        append_status(desc, sizeof(desc), ret);
        send_reg_log(HOOK_RegDeleteValueW, _ReturnAddress(), desc);
    }
    return ret;
}

void RegisterRegistryHooks(void) {
    g_hook_handlers[HOOK_RegOpenKeyExA] = hook_RegOpenKeyExA;
    g_hook_handlers[HOOK_RegOpenKeyExW] = hook_RegOpenKeyExW;
    g_hook_handlers[HOOK_RegSetValueExA] = hook_RegSetValueExA;
    g_hook_handlers[HOOK_RegSetValueExW] = hook_RegSetValueExW;
    g_hook_handlers[HOOK_RegDeleteKeyA] = hook_RegDeleteKeyA;
    g_hook_handlers[HOOK_RegDeleteKeyW] = hook_RegDeleteKeyW;
    g_hook_handlers[HOOK_RegDeleteKeyExA] = hook_RegDeleteKeyExA;
    g_hook_handlers[HOOK_RegDeleteKeyExW] = hook_RegDeleteKeyExW;
    g_hook_handlers[HOOK_RegCreateKeyExA] = hook_RegCreateKeyExA;
    g_hook_handlers[HOOK_RegCreateKeyExW] = hook_RegCreateKeyExW;
    g_hook_handlers[HOOK_RegDeleteValueA] = hook_RegDeleteValueA;
    g_hook_handlers[HOOK_RegDeleteValueW] = hook_RegDeleteValueW;
}
