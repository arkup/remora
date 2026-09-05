#include <windows.h>
#include <intrin.h>
#include <bcrypt.h>
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

typedef NTSTATUS (WINAPI *fn_BCryptEncrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);

typedef BOOL (WINAPI *fn_CryptEncrypt)(ULONG_PTR hKey, ULONG_PTR hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);
typedef BOOL (WINAPI *fn_CryptDecrypt)(ULONG_PTR hKey, ULONG_PTR hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);

static void send_crypto_log(DWORD hook_id, void *ret_addr, const char *text) {
    IPC_MSG_HEADER msg = {0};
    msg.msg_type = MSG_LOG_TEXT;
    msg.hook_id = hook_id;
    msg.tid = GetCurrentThreadId();
    msg.ret_addr = (UINT64)ret_addr;
    msg.extra_len = (DWORD)lstrlenA(text) + 1;
    IpcClientSend(&g_ipc, &msg, text, msg.extra_len);
}

static const char *ntstatus_name(NTSTATUS st) {
    switch ((unsigned long)st) {
    case 0x00000000: return "STATUS_SUCCESS";
    case 0xC0000001: return "STATUS_UNSUCCESSFUL";
    case 0xC0000002: return "STATUS_NOT_IMPLEMENTED";
    case 0xC0000003: return "STATUS_INVALID_INFO_CLASS";
    case 0xC0000005: return "STATUS_ACCESS_VIOLATION";
    case 0xC0000008: return "STATUS_INVALID_HANDLE";
    case 0xC000000D: return "STATUS_INVALID_PARAMETER";
    case 0xC0000017: return "STATUS_NO_MEMORY";
    case 0xC0000022: return "STATUS_ACCESS_DENIED";
    case 0xC0000023: return "STATUS_BUFFER_TOO_SMALL";
    case 0xC000000E: return "STATUS_NO_SUCH_DEVICE";
    case 0xC0000033: return "STATUS_OBJECT_NAME_INVALID";
    case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
    case 0xC0000035: return "STATUS_OBJECT_NAME_COLLISION";
    case 0xC000003A: return "STATUS_OBJECT_PATH_NOT_FOUND";
    case 0xC0000043: return "STATUS_SHARING_VIOLATION";
    case 0xC0000061: return "STATUS_PRIVILEGE_NOT_HELD";
    case 0xC0000BBB: return "STATUS_NOT_SUPPORTED";
    case 0xC0000225: return "STATUS_NOT_FOUND";
    case 0xC0009000: return "STATUS_AUTH_TAG_MISMATCH";
    case 0xC0000024: return "STATUS_OBJECT_TYPE_MISMATCH";
    default: return NULL;
    }
}

static int fmt_ntstatus(char *buf, size_t remaining, NTSTATUS st) {
    const char *name = ntstatus_name(st);
    if (remaining == 0) return 0;
    if (name)
        StringCchPrintfA(buf, remaining, "%s", name);
    else
        StringCchPrintfA(buf, remaining, "0x%08X", (unsigned)st);
    return (int)strlen(buf);
}

static const char *bcrypt_flags_str(ULONG flags) {
    switch (flags) {
    case 0:           return NULL;
    case 0x00000001:  return "BCRYPT_BLOCK_PADDING";
    case 0x00000020:  return "BCRYPT_PAD_PKCS1";
    case 0x00000008:  return "BCRYPT_PAD_OAEP";
    case 0x00000004:  return "BCRYPT_PAD_PSS";
    case 0x00000002:  return "BCRYPT_PAD_NONE";
    default:          return NULL;
    }
}

/* ==================== BCrypt ==================== */

static NTSTATUS WINAPI hook_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput,
    VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput,
    ULONG *pcbResult, ULONG dwFlags) {
    fn_BCryptEncrypt orig = (fn_BCryptEncrypt)EatHookGetOriginal(HOOK_BCryptEncrypt);
    if (RemoraIsInHook()) return orig(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_BCryptEncrypt, "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_BCryptEncrypt);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "BCryptEncrypt(hKey=0x%I64X, %u bytes)",
            (UINT64)(UINT_PTR)hKey, cbInput);
        action = RemoraAskJail(HOOK_BCryptEncrypt, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return (NTSTATUS)0xC0000001L;
    if (action >= JAIL_LOG)
        RemoraSendBuffer(HOOK_BCryptEncrypt, BUFFER_INPUT, pbInput, cbInput);
    NTSTATUS ret = orig(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        ULONG result_len = (pcbResult && ret == 0) ? *pcbResult : 0;
        char buf[256];
        const char *fstr = bcrypt_flags_str(dwFlags);
        if (fstr)
            StringCchPrintfA(buf, sizeof(buf), "BCryptEncrypt(hKey=0x%I64X, %u bytes, iv=%u, %s) -> ",
                (UINT64)(UINT_PTR)hKey, cbInput, cbIV, fstr);
        else if (dwFlags)
            StringCchPrintfA(buf, sizeof(buf), "BCryptEncrypt(hKey=0x%I64X, %u bytes, iv=%u, flags=0x%X) -> ",
                (UINT64)(UINT_PTR)hKey, cbInput, cbIV, dwFlags);
        else
            StringCchPrintfA(buf, sizeof(buf), "BCryptEncrypt(hKey=0x%I64X, %u bytes, iv=%u) -> ",
                (UINT64)(UINT_PTR)hKey, cbInput, cbIV);
        int pos = (int)strlen(buf);
        pos += fmt_ntstatus(buf + pos, sizeof(buf) - (size_t)pos, ret);
        StringCchPrintfA(buf + pos, sizeof(buf) - (size_t)pos, " (out %u bytes)", result_len);
        send_crypto_log(HOOK_BCryptEncrypt, caller, buf);
        if (ret == 0 && pcbResult && *pcbResult > 0)
            RemoraSendBuffer(HOOK_BCryptEncrypt, BUFFER_OUTPUT, pbOutput, *pcbResult);
        tls_set_in_hook(0);
    }
    return ret;
}

static NTSTATUS WINAPI hook_BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput,
    VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput,
    ULONG *pcbResult, ULONG dwFlags) {
    fn_BCryptDecrypt orig = (fn_BCryptDecrypt)EatHookGetOriginal(HOOK_BCryptDecrypt);
    if (RemoraIsInHook()) return orig(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_BCryptDecrypt, "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_BCryptDecrypt);
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "BCryptDecrypt(hKey=0x%I64X, %u bytes)",
            (UINT64)(UINT_PTR)hKey, cbInput);
        action = RemoraAskJail(HOOK_BCryptDecrypt, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return (NTSTATUS)0xC0000001L;
    if (action >= JAIL_LOG)
        RemoraSendBuffer(HOOK_BCryptDecrypt, BUFFER_INPUT, pbInput, cbInput);
    NTSTATUS ret = orig(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        ULONG result_len = (pcbResult && ret == 0) ? *pcbResult : 0;
        char buf[256];
        const char *fstr = bcrypt_flags_str(dwFlags);
        if (fstr)
            StringCchPrintfA(buf, sizeof(buf), "BCryptDecrypt(hKey=0x%I64X, %u bytes, iv=%u, %s) -> ",
                (UINT64)(UINT_PTR)hKey, cbInput, cbIV, fstr);
        else if (dwFlags)
            StringCchPrintfA(buf, sizeof(buf), "BCryptDecrypt(hKey=0x%I64X, %u bytes, iv=%u, flags=0x%X) -> ",
                (UINT64)(UINT_PTR)hKey, cbInput, cbIV, dwFlags);
        else
            StringCchPrintfA(buf, sizeof(buf), "BCryptDecrypt(hKey=0x%I64X, %u bytes, iv=%u) -> ",
                (UINT64)(UINT_PTR)hKey, cbInput, cbIV);
        int pos = (int)strlen(buf);
        pos += fmt_ntstatus(buf + pos, sizeof(buf) - (size_t)pos, ret);
        StringCchPrintfA(buf + pos, sizeof(buf) - (size_t)pos, " (out %u bytes)", result_len);
        send_crypto_log(HOOK_BCryptDecrypt, caller, buf);
        if (ret == 0 && pcbResult && *pcbResult > 0)
            RemoraSendBuffer(HOOK_BCryptDecrypt, BUFFER_OUTPUT, pbOutput, *pcbResult);
        tls_set_in_hook(0);
    }
    return ret;
}

/* ==================== CryptoAPI (legacy) ==================== */

static BOOL WINAPI hook_CryptEncrypt(ULONG_PTR hKey, ULONG_PTR hHash, BOOL Final, DWORD dwFlags,
    BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {
    fn_CryptEncrypt orig = (fn_CryptEncrypt)EatHookGetOriginal(HOOK_CryptEncrypt);
    if (RemoraIsInHook()) return orig(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_CryptEncrypt, "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_CryptEncrypt);
    DWORD data_len = pdwDataLen ? *pdwDataLen : 0;
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "CryptEncrypt(hKey=0x%I64X, %u bytes, final=%d)",
            (UINT64)hKey, data_len, Final);
        action = RemoraAskJail(HOOK_CryptEncrypt, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return FALSE;
    if (action >= JAIL_LOG)
        RemoraSendBuffer(HOOK_CryptEncrypt, BUFFER_INPUT, pbData, data_len);
    BOOL ret = orig(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        DWORD out_len = (pdwDataLen && ret) ? *pdwDataLen : 0;
        char buf[256];
        StringCchPrintfA(buf, sizeof(buf), "CryptEncrypt(hKey=0x%I64X, %u bytes, final=%d) -> %u (out %u)",
            (UINT64)hKey, data_len, Final, (unsigned)ret, out_len);
        send_crypto_log(HOOK_CryptEncrypt, caller, buf);
        if (ret && out_len > 0)
            RemoraSendBuffer(HOOK_CryptEncrypt, BUFFER_OUTPUT, pbData, out_len);
        tls_set_in_hook(0);
    }
    return ret;
}

static BOOL WINAPI hook_CryptDecrypt(ULONG_PTR hKey, ULONG_PTR hHash, BOOL Final, DWORD dwFlags,
    BYTE *pbData, DWORD *pdwDataLen) {
    fn_CryptDecrypt orig = (fn_CryptDecrypt)EatHookGetOriginal(HOOK_CryptDecrypt);
    if (RemoraIsInHook()) return orig(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_CryptDecrypt, "", 0);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_CryptDecrypt);
    DWORD data_len = pdwDataLen ? *pdwDataLen : 0;
    if (action == JAIL_ASK) {
        char ask_buf[128];
        StringCchPrintfA(ask_buf, sizeof(ask_buf), "CryptDecrypt(hKey=0x%I64X, %u bytes, final=%d)",
            (UINT64)hKey, data_len, Final);
        action = RemoraAskJail(HOOK_CryptDecrypt, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return FALSE;
    if (action >= JAIL_LOG)
        RemoraSendBuffer(HOOK_CryptDecrypt, BUFFER_INPUT, pbData, data_len);
    BOOL ret = orig(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        DWORD out_len = (pdwDataLen && ret) ? *pdwDataLen : 0;
        char buf[256];
        StringCchPrintfA(buf, sizeof(buf), "CryptDecrypt(hKey=0x%I64X, %u bytes, final=%d) -> %u (out %u)",
            (UINT64)hKey, data_len, Final, (unsigned)ret, out_len);
        send_crypto_log(HOOK_CryptDecrypt, caller, buf);
        if (ret && out_len > 0)
            RemoraSendBuffer(HOOK_CryptDecrypt, BUFFER_OUTPUT, pbData, out_len);
        tls_set_in_hook(0);
    }
    return ret;
}

/* ==================== BCrypt key generation ==================== */

static void get_alg_name(BCRYPT_ALG_HANDLE hAlg, char *out, int outsize) {
    out[0] = 0;
    WCHAR namew[64] = {0};
    ULONG cbResult = 0;
    NTSTATUS st = BCryptGetProperty(hAlg, BCRYPT_ALGORITHM_NAME, (PUCHAR)namew, sizeof(namew), &cbResult, 0);
    if (st == 0 && namew[0])
        WideCharToMultiByte(CP_UTF8, 0, namew, -1, out, outsize, NULL, NULL);
}

typedef NTSTATUS (WINAPI *fn_BCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptGenerateKeyPair)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptImportKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);

static NTSTATUS WINAPI hook_BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE *phKey,
    PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags) {
    fn_BCryptGenerateSymmetricKey orig = (fn_BCryptGenerateSymmetricKey)EatHookGetOriginal(HOOK_BCryptGenerateSymmetricKey);
    if (RemoraIsInHook()) return orig(hAlg, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_BCryptGenerateSymmetricKey, "", (UINT64)cbSecret);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_BCryptGenerateSymmetricKey);
    if (action == JAIL_ASK) {
        char ask_buf[320], alg[64] = "";
        get_alg_name(hAlg, alg, sizeof(alg));
        if (alg[0])
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "BCryptGenerateSymmetricKey(\"%s\", %u bytes", alg, cbSecret);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "BCryptGenerateSymmetricKey(0x%I64X, %u bytes", (UINT64)(UINT_PTR)hAlg, cbSecret);
        int pos = (int)strlen(ask_buf);
        if (pbSecret && cbSecret > 0 && cbSecret <= 64) {
            StringCchPrintfA(ask_buf + pos, sizeof(ask_buf) - (size_t)pos, ", key=");
            pos = (int)strlen(ask_buf);
            for (ULONG i = 0; i < cbSecret; i++) {
                StringCchPrintfA(ask_buf + pos, sizeof(ask_buf) - (size_t)pos, "%02X", pbSecret[i]);
                pos = (int)strlen(ask_buf);
            }
        }
        StringCchPrintfA(ask_buf + pos, sizeof(ask_buf) - (size_t)pos, ")");
        action = RemoraAskJail(HOOK_BCryptGenerateSymmetricKey, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return (NTSTATUS)0xC0000001L;
    NTSTATUS ret = orig(hAlg, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[512], alg[64] = "";
        get_alg_name(hAlg, alg, sizeof(alg));
        BCRYPT_KEY_HANDLE key = (phKey && ret == 0) ? *phKey : NULL;
        if (alg[0])
            StringCchPrintfA(buf, sizeof(buf), "BCryptGenerateSymmetricKey(\"%s\", %u bytes", alg, cbSecret);
        else
            StringCchPrintfA(buf, sizeof(buf), "BCryptGenerateSymmetricKey(0x%I64X, %u bytes", (UINT64)(UINT_PTR)hAlg, cbSecret);
        int pos = (int)strlen(buf);
        if (pbSecret && cbSecret > 0 && cbSecret <= 64) {
            StringCchPrintfA(buf + pos, sizeof(buf) - (size_t)pos, ", key=");
            pos = (int)strlen(buf);
            ULONG dump = cbSecret;
            for (ULONG i = 0; i < dump; i++) {
                StringCchPrintfA(buf + pos, sizeof(buf) - (size_t)pos, "%02X", pbSecret[i]);
                pos = (int)strlen(buf);
            }
        }
        StringCchPrintfA(buf + pos, sizeof(buf) - (size_t)pos, ") -> ");
        pos = (int)strlen(buf);
        pos += fmt_ntstatus(buf + pos, sizeof(buf) - (size_t)pos, ret);
        StringCchPrintfA(buf + pos, sizeof(buf) - (size_t)pos, " (hKey=0x%I64X)", (UINT64)(UINT_PTR)key);
        send_crypto_log(HOOK_BCryptGenerateSymmetricKey, caller, buf);
        if (ret == 0 && pbSecret && cbSecret > 0)
            RemoraSendBuffer(HOOK_BCryptGenerateSymmetricKey, BUFFER_KEY, pbSecret, cbSecret);
        tls_set_in_hook(0);
    }
    return ret;
}

static NTSTATUS WINAPI hook_BCryptGenerateKeyPair(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE *phKey,
    ULONG dwLength, ULONG dwFlags) {
    fn_BCryptGenerateKeyPair orig = (fn_BCryptGenerateKeyPair)EatHookGetOriginal(HOOK_BCryptGenerateKeyPair);
    if (RemoraIsInHook()) return orig(hAlg, phKey, dwLength, dwFlags);
    void *caller = _ReturnAddress();
    JailAction action = RemoraEvalRules(HOOK_BCryptGenerateKeyPair, "", (UINT64)dwLength);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_BCryptGenerateKeyPair);
    if (action == JAIL_ASK) {
        char ask_buf[128], alg[64] = "";
        get_alg_name(hAlg, alg, sizeof(alg));
        if (alg[0])
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "BCryptGenerateKeyPair(\"%s\", %u bits)", alg, dwLength);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "BCryptGenerateKeyPair(0x%I64X, %u bits)", (UINT64)(UINT_PTR)hAlg, dwLength);
        action = RemoraAskJail(HOOK_BCryptGenerateKeyPair, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return (NTSTATUS)0xC0000001L;
    NTSTATUS ret = orig(hAlg, phKey, dwLength, dwFlags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[256], alg[64] = "";
        get_alg_name(hAlg, alg, sizeof(alg));
        BCRYPT_KEY_HANDLE key = (phKey && ret == 0) ? *phKey : NULL;
        if (alg[0])
            StringCchPrintfA(buf, sizeof(buf), "BCryptGenerateKeyPair(\"%s\", %u bits) -> ", alg, dwLength);
        else
            StringCchPrintfA(buf, sizeof(buf), "BCryptGenerateKeyPair(0x%I64X, %u bits) -> ", (UINT64)(UINT_PTR)hAlg, dwLength);
        int pos = (int)strlen(buf);
        pos += fmt_ntstatus(buf + pos, sizeof(buf) - (size_t)pos, ret);
        StringCchPrintfA(buf + pos, sizeof(buf) - (size_t)pos, " (hKey=0x%I64X)", (UINT64)(UINT_PTR)key);
        send_crypto_log(HOOK_BCryptGenerateKeyPair, caller, buf);
        tls_set_in_hook(0);
    }
    return ret;
}

static NTSTATUS WINAPI hook_BCryptImportKey(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hImportKey,
    LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE *phKey, PUCHAR pbKeyObject, ULONG cbKeyObject,
    PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    fn_BCryptImportKey orig = (fn_BCryptImportKey)EatHookGetOriginal(HOOK_BCryptImportKey);
    if (RemoraIsInHook()) return orig(hAlg, hImportKey, pszBlobType, phKey, pbKeyObject, cbKeyObject, pbInput, cbInput, dwFlags);
    void *caller = _ReturnAddress();
    char blob_type[64] = "";
    if (pszBlobType)
        WideCharToMultiByte(CP_UTF8, 0, pszBlobType, -1, blob_type, sizeof(blob_type), NULL, NULL);
    JailAction action = RemoraEvalRules(HOOK_BCryptImportKey, blob_type, (UINT64)cbInput);
    if ((int)action < 0)
        action = RemoraGetJailRaw(HOOK_BCryptImportKey);
    if (action == JAIL_ASK) {
        char ask_buf[192], alg[64] = "";
        get_alg_name(hAlg, alg, sizeof(alg));
        if (alg[0])
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "BCryptImportKey(\"%s\", \"%s\", %u bytes)", alg, blob_type, cbInput);
        else
            StringCchPrintfA(ask_buf, sizeof(ask_buf), "BCryptImportKey(0x%I64X, \"%s\", %u bytes)", (UINT64)(UINT_PTR)hAlg, blob_type, cbInput);
        action = RemoraAskJail(HOOK_BCryptImportKey, ask_buf, caller);
    }
    if (action >= JAIL_BLOCK) return (NTSTATUS)0xC0000001L;
    NTSTATUS ret = orig(hAlg, hImportKey, pszBlobType, phKey, pbKeyObject, cbKeyObject, pbInput, cbInput, dwFlags);
    if (action >= JAIL_LOG) {
        tls_set_in_hook(1);
        char buf[256], alg[64] = "";
        get_alg_name(hAlg, alg, sizeof(alg));
        BCRYPT_KEY_HANDLE key = (phKey && ret == 0) ? *phKey : NULL;
        if (alg[0])
            StringCchPrintfA(buf, sizeof(buf), "BCryptImportKey(\"%s\", \"%s\", %u bytes) -> ", alg, blob_type, cbInput);
        else
            StringCchPrintfA(buf, sizeof(buf), "BCryptImportKey(0x%I64X, \"%s\", %u bytes) -> ", (UINT64)(UINT_PTR)hAlg, blob_type, cbInput);
        int pos = (int)strlen(buf);
        pos += fmt_ntstatus(buf + pos, sizeof(buf) - (size_t)pos, ret);
        StringCchPrintfA(buf + pos, sizeof(buf) - (size_t)pos, " (hKey=0x%I64X)", (UINT64)(UINT_PTR)key);
        send_crypto_log(HOOK_BCryptImportKey, caller, buf);
        if (ret == 0 && pbInput && cbInput > 0)
            RemoraSendBuffer(HOOK_BCryptImportKey, BUFFER_KEY, pbInput, cbInput);
        tls_set_in_hook(0);
    }
    return ret;
}

void RegisterCryptoHooks(void) {
    g_hook_handlers[HOOK_BCryptEncrypt] = hook_BCryptEncrypt;
    g_hook_handlers[HOOK_BCryptDecrypt] = hook_BCryptDecrypt;
    g_hook_handlers[HOOK_CryptEncrypt] = hook_CryptEncrypt;
    g_hook_handlers[HOOK_CryptDecrypt] = hook_CryptDecrypt;
    g_hook_handlers[HOOK_BCryptGenerateSymmetricKey] = hook_BCryptGenerateSymmetricKey;
    g_hook_handlers[HOOK_BCryptGenerateKeyPair] = hook_BCryptGenerateKeyPair;
    g_hook_handlers[HOOK_BCryptImportKey] = hook_BCryptImportKey;
}
