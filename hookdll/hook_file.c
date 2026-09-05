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
extern void tls_set_in_hook(int val);

#include "ipc_client.h"
#include <strsafe.h>
extern IpcClient g_ipc;
extern void RemoraSendBuffer(DWORD hook_id, int buf_type, const void *data, DWORD data_len);

typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *fn_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *fn_DeleteFileA)(LPCSTR);
typedef BOOL (WINAPI *fn_DeleteFileW)(LPCWSTR);
typedef BOOL (WINAPI *fn_CloseHandle)(HANDLE);
typedef HANDLE (WINAPI *fn_FindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef HANDLE (WINAPI *fn_FindFirstFileW)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef HANDLE (WINAPI *fn_FindFirstFileExA)(LPCSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
typedef HANDLE (WINAPI *fn_FindFirstFileExW)(LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);

/* ==================== Handle-to-filename table ==================== */

#define HANDLE_TABLE_SIZE 1024
#define HANDLE_NAME_LEN 64

typedef struct {
    HANDLE handle;
    char name[HANDLE_NAME_LEN];
} HandleEntry;

static HandleEntry g_handle_table[HANDLE_TABLE_SIZE];
static LONG g_handle_next;

static void handle_table_add(HANDLE h, const char *basename) {
    if (!h || h == INVALID_HANDLE_VALUE) return;
    for (int i = 0; i < HANDLE_TABLE_SIZE; i++) {
        if (g_handle_table[i].handle == h) {
            lstrcpynA(g_handle_table[i].name, basename, HANDLE_NAME_LEN);
            return;
        }
    }
    LONG idx = InterlockedIncrement(&g_handle_next) - 1;
    idx = idx % HANDLE_TABLE_SIZE;
    g_handle_table[idx].handle = h;
    lstrcpynA(g_handle_table[idx].name, basename, HANDLE_NAME_LEN);
}

static void handle_table_remove(HANDLE h) {
    for (int i = 0; i < HANDLE_TABLE_SIZE; i++) {
        if (g_handle_table[i].handle == h) {
            g_handle_table[i].handle = NULL;
            g_handle_table[i].name[0] = 0;
            return;
        }
    }
}

static const char *handle_table_lookup(HANDLE h) {
    for (int i = 0; i < HANDLE_TABLE_SIZE; i++) {
        if (g_handle_table[i].handle == h && g_handle_table[i].name[0])
            return g_handle_table[i].name;
    }
    return NULL;
}

void HandleTableInitStdHandles(void) {
    HANDLE h;
    h = GetStdHandle(STD_INPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) handle_table_add(h, "<stdin>");
    h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) handle_table_add(h, "<stdout>");
    h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) handle_table_add(h, "<stderr>");
}

static const char *extract_basename(const char *path) {
    const char *p = path;
    const char *last = path;
    while (*p) {
        if (*p == '\\' || *p == '/')
            last = p + 1;
        p++;
    }
    return last;
}

static void handle_table_add_path(HANDLE h, const void *path, BOOL wide) {
    char utf8[512];
    if (wide && path)
        WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)path, -1, utf8, sizeof(utf8), NULL, NULL);
    else if (path)
        lstrcpynA(utf8, (LPCSTR)path, sizeof(utf8));
    else
        return;
    handle_table_add(h, extract_basename(utf8));
}

/* ==================== Access flag formatting ==================== */

static void fa_append(char *out, int out_size, int *pos, const char *s) {
    int slen = lstrlenA(s);
    if (*pos + slen < out_size) {
        lstrcpynA(out + *pos, s, out_size - *pos);
        *pos += slen;
    }
}

static void format_access(DWORD access, char *out, int out_size) {
    out[0] = 0;
    int pos = 0;
    if (access & GENERIC_READ)    fa_append(out, out_size, &pos, "READ|");
    if (access & GENERIC_WRITE)   fa_append(out, out_size, &pos, "WRITE|");
    if (access & GENERIC_EXECUTE) fa_append(out, out_size, &pos, "EXEC|");
    if (access & GENERIC_ALL)     fa_append(out, out_size, &pos, "ALL|");
    if (access & DELETE)           fa_append(out, out_size, &pos, "DELETE|");
    if (access & 0x00100000)      fa_append(out, out_size, &pos, "SYNC|");
    DWORD low = access & 0x01FF;
    if (low & 0x0001) fa_append(out, out_size, &pos, "READ_DATA|");
    if (low & 0x0002) fa_append(out, out_size, &pos, "WRITE_DATA|");
    if (low & 0x0004) fa_append(out, out_size, &pos, "APPEND|");
    if (low & 0x0008) fa_append(out, out_size, &pos, "READ_EA|");
    if (low & 0x0010) fa_append(out, out_size, &pos, "WRITE_EA|");
    if (low & 0x0020) fa_append(out, out_size, &pos, "EXECUTE|");
    if (low & 0x0040) fa_append(out, out_size, &pos, "DEL_CHILD|");
    if (low & 0x0080) fa_append(out, out_size, &pos, "READ_ATTR|");
    if (low & 0x0100) fa_append(out, out_size, &pos, "WRITE_ATTR|");
    if (pos > 0) out[pos - 1] = 0;
    else StringCchPrintfA(out, (size_t)out_size, "0x%X", access);
}

static void format_file_flags(DWORD flags, char *out, int out_size) {
    out[0] = 0;
    struct { DWORD flag; const char *name; } known[] = {
        { 0x00000001, "READONLY" },
        { 0x00000002, "HIDDEN" },
        { 0x00000004, "SYSTEM" },
        { 0x00000010, "DIRECTORY" },
        { 0x00000020, "ARCHIVE" },
        { 0x00000080, "NORMAL" },
        { 0x00000100, "TEMPORARY" },
        { 0x00000800, "COMPRESSED" },
        { 0x00002000, "NOT_CONTENT_INDEXED" },
        { 0x00004000, "ENCRYPTED" },
        { 0x00200000, "OPEN_NO_RECALL" },
        { 0x00100000, "OPEN_REPARSE_POINT" },
        { 0x80000000, "WRITE_THROUGH" },
        { 0x40000000, "OVERLAPPED" },
        { 0x20000000, "NO_BUFFERING" },
        { 0x10000000, "RANDOM_ACCESS" },
        { 0x08000000, "SEQUENTIAL_SCAN" },
        { 0x04000000, "DELETE_ON_CLOSE" },
        { 0x02000000, "BACKUP_SEMANTICS" },
        { 0x01000000, "POSIX_SEMANTICS" },
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

/* ==================== CreateFile ==================== */

static void send_createfile_log(DWORD hook_id, const void *path, BOOL wide,
    DWORD access, DWORD share, DWORD disp, DWORD flags, HANDLE ret, void *ret_addr) {
    char buf[1024];
    char path_str[512];

    if (wide && path)
        WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)path, -1, path_str, sizeof(path_str), NULL, NULL);
    else if (path)
        lstrcpynA(path_str, (LPCSTR)path, sizeof(path_str));
    else
        lstrcpyA(path_str, "(null)");

    char acc_str[128];
    format_access(access, acc_str, sizeof(acc_str));

    char share_str[64] = "";
    if (share & FILE_SHARE_READ) lstrcatA(share_str, "SHARE_READ|");
    if (share & FILE_SHARE_WRITE) lstrcatA(share_str, "SHARE_WRITE|");
    if (share & FILE_SHARE_DELETE) lstrcatA(share_str, "SHARE_DELETE|");
    if (share_str[0]) share_str[lstrlenA(share_str) - 1] = 0;
    else lstrcpyA(share_str, "0");

    const char *disp_str = "???";
    switch (disp) {
        case 1: disp_str = "CREATE_NEW"; break;
        case 2: disp_str = "CREATE_ALWAYS"; break;
        case 3: disp_str = "OPEN_EXISTING"; break;
        case 4: disp_str = "OPEN_ALWAYS"; break;
        case 5: disp_str = "TRUNCATE_EXISTING"; break;
    }

    char flags_str[256];
    format_file_flags(flags, flags_str, sizeof(flags_str));

    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_LOG_TEXT;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.ret_addr = (UINT64)ret_addr;

    if (ret == INVALID_HANDLE_VALUE)
        StringCchPrintfA(buf, sizeof(buf), "%s(\"%s\", %s, %s, %s, %s) -> INVALID",
            wide ? "CreateFileW" : "CreateFileA", path_str, acc_str, share_str, disp_str, flags_str);
    else
        StringCchPrintfA(buf, sizeof(buf), "%s(\"%s\", %s, %s, %s, %s) -> 0x%I64X",
            wide ? "CreateFileW" : "CreateFileA", path_str, acc_str, share_str, disp_str, flags_str,
            (UINT64)(UINT_PTR)ret);
    msg.extra_len = (DWORD)strlen(buf) + 1;
    IpcClientSend(&g_ipc, &msg, buf, msg.extra_len);
}

static HANDLE WINAPI hook_CreateFileA(LPCSTR path, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE templ) {
    fn_CreateFileA orig = (fn_CreateFileA)EatHookGetOriginal(HOOK_CreateFileA);
    if (RemoraIsInHook())
        return orig(path, access, share, sa, disp, flags, templ);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_CreateFileA, path ? path : "", (UINT64)access);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_CreateFileA);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "CreateFileA(\"%s\")", path ? path : "(null)");
        action = RemoraAskJail(HOOK_CreateFileA, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG)
            send_createfile_log(HOOK_CreateFileA, path, FALSE, access, share, disp, flags, INVALID_HANDLE_VALUE, caller);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE ret = orig(path, access, share, sa, disp, flags, templ);
    if (ret != INVALID_HANDLE_VALUE)
        handle_table_add_path(ret, path, FALSE);
    if (action >= JAIL_LOG)
        send_createfile_log(HOOK_CreateFileA, path, FALSE, access, share, disp, flags, ret, caller);
    return ret;
}

static HANDLE WINAPI hook_CreateFileW(LPCWSTR path, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE templ) {
    fn_CreateFileW orig = (fn_CreateFileW)EatHookGetOriginal(HOOK_CreateFileW);
    if (RemoraIsInHook())
        return orig(path, access, share, sa, disp, flags, templ);
    void *caller = _ReturnAddress();
    char path_utf8[512];
    if (path)
        WideCharToMultiByte(CP_UTF8, 0, path, -1, path_utf8, sizeof(path_utf8), NULL, NULL);
    else
        path_utf8[0] = 0;
    JailAction action = RemoraEvalRules(HOOK_CreateFileA, path_utf8, (UINT64)access);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_CreateFileW);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "CreateFileW(\"%s\")", path_utf8);
        action = RemoraAskJail(HOOK_CreateFileW, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG)
            send_createfile_log(HOOK_CreateFileW, path, TRUE, access, share, disp, flags, INVALID_HANDLE_VALUE, caller);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE ret = orig(path, access, share, sa, disp, flags, templ);
    if (ret != INVALID_HANDLE_VALUE)
        handle_table_add_path(ret, path, TRUE);
    if (action >= JAIL_LOG)
        send_createfile_log(HOOK_CreateFileW, path, TRUE, access, share, disp, flags, ret, caller);
    return ret;
}

/* ==================== WriteFile ==================== */

static BOOL WINAPI hook_WriteFile(HANDLE hFile, LPCVOID buf, DWORD len, LPDWORD written, LPOVERLAPPED ovl) {
    fn_WriteFile orig = (fn_WriteFile)EatHookGetOriginal(HOOK_WriteFile);
    if (RemoraIsInHook())
        return orig(hFile, buf, len, written, ovl);
    void *caller = _ReturnAddress();
    const char *hname = handle_table_lookup(hFile);
    JailAction action = RemoraEvalRules(HOOK_WriteFile, hname ? hname : "", (UINT64)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_WriteFile);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        if (hname)
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "WriteFile(\"%s\", %u bytes)", hname, len);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "WriteFile(0x%I64X, %u bytes)", (UINT64)(UINT_PTR)hFile, len);
        action = RemoraAskJail(HOOK_WriteFile, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            tls_set_in_hook(1);
            char log_buf[256];
            const char *name = handle_table_lookup(hFile);
            if (name)
                StringCchPrintfA(log_buf, sizeof(log_buf), "WriteFile(\"%s\", %u bytes) -> BLOCKED", name, len);
            else
                StringCchPrintfA(log_buf, sizeof(log_buf), "WriteFile(0x%I64X, %u bytes) -> BLOCKED", (UINT64)(UINT_PTR)hFile, len);
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_WriteFile;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)caller;
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
            RemoraSendBuffer(HOOK_WriteFile, BUFFER_INPUT, buf, len);
            tls_set_in_hook(0);
        }
        if (written) *written = len;
        return TRUE;
    }
    BOOL ret = orig(hFile, buf, len, written, ovl);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char log_buf[256];
        const char *name = handle_table_lookup(hFile);
        if (name)
            StringCchPrintfA(log_buf, sizeof(log_buf), "WriteFile(\"%s\", %u bytes) -> %s", name, len, ret ? "TRUE" : "FALSE");
        else
            StringCchPrintfA(log_buf, sizeof(log_buf), "WriteFile(0x%I64X, %u bytes) -> %s", (UINT64)(UINT_PTR)hFile, len, ret ? "TRUE" : "FALSE");
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_WriteFile;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)caller;
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        RemoraSendBuffer(HOOK_WriteFile, BUFFER_INPUT, buf, len);
        tls_set_in_hook(0);
    }
    return ret;
}

/* ==================== ReadFile ==================== */

static BOOL WINAPI hook_ReadFile(HANDLE hFile, LPVOID buf, DWORD len, LPDWORD read_out, LPOVERLAPPED ovl) {
    fn_ReadFile orig = (fn_ReadFile)EatHookGetOriginal(HOOK_ReadFile);
    if (RemoraIsInHook())
        return orig(hFile, buf, len, read_out, ovl);
    void *caller = _ReturnAddress();
    const char *hname_r = handle_table_lookup(hFile);
    JailAction action = RemoraEvalRules(HOOK_ReadFile, hname_r ? hname_r : "", (UINT64)len);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_ReadFile);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        if (hname_r)
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "ReadFile(\"%s\", %u bytes)", hname_r, len);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "ReadFile(0x%I64X, %u bytes)", (UINT64)(UINT_PTR)hFile, len);
        action = RemoraAskJail(HOOK_ReadFile, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (read_out) *read_out = 0;
        return FALSE;
    }
    BOOL ret = orig(hFile, buf, len, read_out, ovl);
    if (action >= JAIL_LOG) {
        char log_buf[256];
        const char *name = handle_table_lookup(hFile);
        if (name)
            StringCchPrintfA(log_buf, sizeof(log_buf), "ReadFile(\"%s\", %u bytes) -> %s", name, len, ret ? "TRUE" : "FALSE");
        else
            StringCchPrintfA(log_buf, sizeof(log_buf), "ReadFile(0x%I64X, %u bytes) -> %s", (UINT64)(UINT_PTR)hFile, len, ret ? "TRUE" : "FALSE");
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_ReadFile;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)caller;
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

/* ==================== DeleteFile ==================== */

static BOOL WINAPI hook_DeleteFileA(LPCSTR path) {
    if (RemoraIsInHook()) {
        fn_DeleteFileA orig = (fn_DeleteFileA)EatHookGetOriginal(HOOK_DeleteFileA);
        return orig(path);
    }
    JailAction action = RemoraEvalRules(HOOK_DeleteFileA, path ? path : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_DeleteFileA);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "DeleteFileA(\"%s\")", path ? path : "(null)");
        action = RemoraAskJail(HOOK_DeleteFileA, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[512];
            StringCchPrintfA(log_buf, sizeof(log_buf), "DeleteFileA(\"%s\") -> BLOCKED", path ? path : "(null)");
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_DeleteFileA;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return FALSE;
    }
    fn_DeleteFileA orig = (fn_DeleteFileA)EatHookGetOriginal(HOOK_DeleteFileA);
    BOOL ret = orig(path);
    if (action >= JAIL_LOG) {
        char log_buf[512];
        StringCchPrintfA(log_buf, sizeof(log_buf), "DeleteFileA(\"%s\") -> %s", path ? path : "(null)", ret ? "TRUE" : "FALSE");
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_DeleteFileA;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

static BOOL WINAPI hook_DeleteFileW(LPCWSTR path) {
    if (RemoraIsInHook()) {
        fn_DeleteFileW orig = (fn_DeleteFileW)EatHookGetOriginal(HOOK_DeleteFileW);
        return orig(path);
    }
    char del_path_utf8[512];
    if (path)
        WideCharToMultiByte(CP_UTF8, 0, path, -1, del_path_utf8, sizeof(del_path_utf8), NULL, NULL);
    else
        del_path_utf8[0] = 0;
    JailAction action = RemoraEvalRules(HOOK_DeleteFileA, del_path_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_DeleteFileW);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "DeleteFileW(\"%s\")", del_path_utf8);
        action = RemoraAskJail(HOOK_DeleteFileW, ask_buf, _ReturnAddress());
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[512];
            StringCchPrintfA(log_buf, sizeof(log_buf), "DeleteFileW(\"%s\") -> BLOCKED", del_path_utf8);
            int log_len = (int)strlen(log_buf);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_DeleteFileW;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)_ReturnAddress();
            msg.extra_len = (DWORD)log_len + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        return FALSE;
    }
    fn_DeleteFileW orig = (fn_DeleteFileW)EatHookGetOriginal(HOOK_DeleteFileW);
    BOOL ret = orig(path);
    if (action >= JAIL_LOG) {
        char log_buf[512];
        StringCchPrintfA(log_buf, sizeof(log_buf), "DeleteFileW(\"%s\") -> %s", del_path_utf8, ret ? "TRUE" : "FALSE");
        int log_len = (int)strlen(log_buf);
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_DeleteFileW;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)_ReturnAddress();
        msg.extra_len = (DWORD)log_len + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

/* ==================== FindFirstFile ==================== */

static HANDLE WINAPI hook_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    fn_FindFirstFileA orig = (fn_FindFirstFileA)EatHookGetOriginal(HOOK_FindFirstFileA);
    if (RemoraIsInHook())
        return orig(lpFileName, lpFindFileData);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_FindFirstFileA, lpFileName ? lpFileName : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_FindFirstFileA);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "FindFirstFileA(\"%s\")", lpFileName ? lpFileName : "(null)");
        action = RemoraAskJail(HOOK_FindFirstFileA, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[512];
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileA(\"%s\") -> BLOCKED", lpFileName ? lpFileName : "(null)");
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_FindFirstFileA;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)caller;
            msg.extra_len = (DWORD)strlen(log_buf) + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE ret = orig(lpFileName, lpFindFileData);
    if (action >= JAIL_LOG) {
        char log_buf[512];
        if (ret == INVALID_HANDLE_VALUE)
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileA(\"%s\") -> INVALID (err=%u)",
                lpFileName ? lpFileName : "(null)", GetLastError());
        else
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileA(\"%s\") -> 0x%I64X (\"%s\")",
                lpFileName ? lpFileName : "(null)", (UINT64)(UINT_PTR)ret,
                lpFindFileData ? lpFindFileData->cFileName : "?");
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_FindFirstFileA;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)caller;
        msg.extra_len = (DWORD)strlen(log_buf) + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

static HANDLE WINAPI hook_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    fn_FindFirstFileW orig = (fn_FindFirstFileW)EatHookGetOriginal(HOOK_FindFirstFileW);
    if (RemoraIsInHook())
        return orig(lpFileName, lpFindFileData);
    void *caller = _ReturnAddress();
    char path_utf8[512];
    if (lpFileName)
        WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1, path_utf8, sizeof(path_utf8), NULL, NULL);
    else
        path_utf8[0] = 0;
    JailAction action = RemoraEvalRules(HOOK_FindFirstFileW, path_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_FindFirstFileW);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "FindFirstFileW(\"%s\")", path_utf8);
        action = RemoraAskJail(HOOK_FindFirstFileW, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[512];
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileW(\"%s\") -> BLOCKED", path_utf8);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_FindFirstFileW;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)caller;
            msg.extra_len = (DWORD)strlen(log_buf) + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE ret = orig(lpFileName, lpFindFileData);
    if (action >= JAIL_LOG) {
        char log_buf[512];
        if (ret == INVALID_HANDLE_VALUE) {
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileW(\"%s\") -> INVALID (err=%u)",
                path_utf8, GetLastError());
        } else {
            char first_match[280];
            if (lpFindFileData)
                WideCharToMultiByte(CP_UTF8, 0, lpFindFileData->cFileName, -1,
                    first_match, sizeof(first_match), NULL, NULL);
            else
                lstrcpyA(first_match, "?");
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileW(\"%s\") -> 0x%I64X (\"%s\")",
                path_utf8, (UINT64)(UINT_PTR)ret, first_match);
        }
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_FindFirstFileW;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)caller;
        msg.extra_len = (DWORD)strlen(log_buf) + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

/* ==================== FindFirstFileEx ==================== */

static HANDLE WINAPI hook_FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) {
    fn_FindFirstFileExA orig = (fn_FindFirstFileExA)EatHookGetOriginal(HOOK_FindFirstFileExA);
    if (RemoraIsInHook())
        return orig(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_FindFirstFileA, lpFileName ? lpFileName : "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_FindFirstFileA);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "FindFirstFileExA(\"%s\")", lpFileName ? lpFileName : "(null)");
        action = RemoraAskJail(HOOK_FindFirstFileA, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[512];
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileExA(\"%s\") -> BLOCKED", lpFileName ? lpFileName : "(null)");
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_FindFirstFileExA;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)caller;
            msg.extra_len = (DWORD)strlen(log_buf) + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE ret = orig(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    if (action >= JAIL_LOG) {
        char log_buf[512];
        if (ret == INVALID_HANDLE_VALUE)
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileExA(\"%s\") -> INVALID (err=%u)",
                lpFileName ? lpFileName : "(null)", GetLastError());
        else {
            const char *first = "?";
            if (lpFindFileData && fInfoLevelId == FindExInfoStandard)
                first = ((WIN32_FIND_DATAA *)lpFindFileData)->cFileName;
            else if (lpFindFileData && fInfoLevelId == FindExInfoBasic)
                first = ((WIN32_FIND_DATAA *)lpFindFileData)->cFileName;
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileExA(\"%s\") -> 0x%I64X (\"%s\")",
                lpFileName ? lpFileName : "(null)", (UINT64)(UINT_PTR)ret, first);
        }
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_FindFirstFileExA;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)caller;
        msg.extra_len = (DWORD)strlen(log_buf) + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

static HANDLE WINAPI hook_FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) {
    fn_FindFirstFileExW orig = (fn_FindFirstFileExW)EatHookGetOriginal(HOOK_FindFirstFileExW);
    if (RemoraIsInHook())
        return orig(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    void *caller = _ReturnAddress();
    char path_utf8[512];
    if (lpFileName)
        WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1, path_utf8, sizeof(path_utf8), NULL, NULL);
    else
        path_utf8[0] = 0;
    JailAction action = RemoraEvalRules(HOOK_FindFirstFileA, path_utf8, 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_FindFirstFileW);
    if (action == JAIL_ASK) {
        char ask_buf[512];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "FindFirstFileExW(\"%s\")", path_utf8);
        action = RemoraAskJail(HOOK_FindFirstFileW, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) {
        if (action >= JAIL_LOG) {
            char log_buf[512];
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileExW(\"%s\") -> BLOCKED", path_utf8);
            IPC_MSG_HEADER msg = {0};
            msg.msg_type = MSG_LOG_TEXT;
            msg.hook_id = HOOK_FindFirstFileExW;
            msg.tid = GetCurrentThreadId();
            msg.ret_addr = (UINT64)caller;
            msg.extra_len = (DWORD)strlen(log_buf) + 1;
            IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
        }
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE ret = orig(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    if (action >= JAIL_LOG) {
        char log_buf[512];
        if (ret == INVALID_HANDLE_VALUE) {
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileExW(\"%s\") -> INVALID (err=%u)",
                path_utf8, GetLastError());
        } else {
            char first_match[280];
            if (lpFindFileData && (fInfoLevelId == FindExInfoStandard || fInfoLevelId == FindExInfoBasic))
                WideCharToMultiByte(CP_UTF8, 0, ((WIN32_FIND_DATAW *)lpFindFileData)->cFileName, -1,
                    first_match, sizeof(first_match), NULL, NULL);
            else
                lstrcpyA(first_match, "?");
            StringCchPrintfA(log_buf, sizeof(log_buf), "FindFirstFileExW(\"%s\") -> 0x%I64X (\"%s\")",
                path_utf8, (UINT64)(UINT_PTR)ret, first_match);
        }
        IPC_MSG_HEADER msg = {0};
        msg.msg_type = MSG_LOG_TEXT;
        msg.hook_id = HOOK_FindFirstFileExW;
        msg.tid = GetCurrentThreadId();
        msg.ret_addr = (UINT64)caller;
        msg.extra_len = (DWORD)strlen(log_buf) + 1;
        IpcClientSend(&g_ipc, &msg, log_buf, msg.extra_len);
    }
    return ret;
}

/* ==================== CloseHandle ==================== */

static BOOL WINAPI hook_CloseHandle(HANDLE hObject) {
    fn_CloseHandle orig = (fn_CloseHandle)EatHookGetOriginal(HOOK_CloseHandle);
    if (RemoraIsInHook())
        return orig(hObject);
    handle_table_remove(hObject);
    return orig(hObject);
}

/* ==================== Registration ==================== */

void RegisterFileHooks(void) {
    g_hook_handlers[HOOK_CreateFileA] = hook_CreateFileA;
    g_hook_handlers[HOOK_CreateFileW] = hook_CreateFileW;
    g_hook_handlers[HOOK_WriteFile] = hook_WriteFile;
    g_hook_handlers[HOOK_ReadFile] = hook_ReadFile;
    g_hook_handlers[HOOK_DeleteFileA] = hook_DeleteFileA;
    g_hook_handlers[HOOK_DeleteFileW] = hook_DeleteFileW;
    g_hook_handlers[HOOK_CloseHandle] = hook_CloseHandle;
    g_hook_handlers[HOOK_FindFirstFileA] = hook_FindFirstFileA;
    g_hook_handlers[HOOK_FindFirstFileW] = hook_FindFirstFileW;
    g_hook_handlers[HOOK_FindFirstFileExA] = hook_FindFirstFileExA;
    g_hook_handlers[HOOK_FindFirstFileExW] = hook_FindFirstFileExW;
}
