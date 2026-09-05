#ifndef HOOK_DEFS_H
#define HOOK_DEFS_H

typedef enum {
    HOOK_CAT_FILE = 0,
    HOOK_CAT_PROCESS,
    HOOK_CAT_MEMORY,
    HOOK_CAT_REGISTRY,
    HOOK_CAT_NETWORK,
    HOOK_CAT_HTTP,
    HOOK_CAT_MODULE,
    HOOK_CAT_CRYPTO,
    HOOK_CAT_COUNT
} HookCategory;

typedef enum {
    // File I/O
    HOOK_CreateFileA = 0,
    HOOK_CreateFileW,
    HOOK_WriteFile,
    HOOK_ReadFile,
    HOOK_DeleteFileA,
    HOOK_DeleteFileW,
    HOOK_CloseHandle,
    HOOK_FindFirstFileA,
    HOOK_FindFirstFileW,
    HOOK_FindFirstFileExA,
    HOOK_FindFirstFileExW,

    // Process
    HOOK_CreateProcessA,
    HOOK_CreateProcessW,
    HOOK_OpenProcess,
    HOOK_WriteProcessMemory,
    HOOK_VirtualAllocEx,
    HOOK_VirtualProtectEx,
    HOOK_CreateRemoteThread,
    HOOK_CreateRemoteThreadEx,
    HOOK_QueueUserAPC,
    HOOK_TerminateProcess,

    // Memory
    HOOK_VirtualAlloc,
    HOOK_VirtualProtect,
    HOOK_ReadProcessMemory,

    // Registry
    HOOK_RegOpenKeyExA,
    HOOK_RegOpenKeyExW,
    HOOK_RegSetValueExA,
    HOOK_RegSetValueExW,
    HOOK_RegCreateKeyExA,
    HOOK_RegCreateKeyExW,
    HOOK_RegDeleteKeyA,
    HOOK_RegDeleteKeyW,
    HOOK_RegDeleteKeyExA,
    HOOK_RegDeleteKeyExW,
    HOOK_RegDeleteValueA,
    HOOK_RegDeleteValueW,

    // Network
    HOOK_connect,
    HOOK_WSAConnect,
    HOOK_send,
    HOOK_sendto,
    HOOK_WSASend,
    HOOK_recv,
    HOOK_recvfrom,
    HOOK_getaddrinfo,
    HOOK_GetAddrInfoW,
    HOOK_GetAddrInfoExW,
    HOOK_closesocket,

    // HTTP
    HOOK_InternetOpenA,
    HOOK_InternetOpenW,
    HOOK_InternetConnectA,
    HOOK_InternetConnectW,
    HOOK_HttpOpenRequestA,
    HOOK_HttpOpenRequestW,
    HOOK_HttpSendRequestA,
    HOOK_HttpSendRequestW,
    HOOK_InternetOpenUrlA,
    HOOK_InternetOpenUrlW,
    HOOK_InternetReadFile,

    // Module
    HOOK_GetModuleHandleA,
    HOOK_GetModuleHandleW,
    HOOK_GetModuleFileNameA,
    HOOK_GetModuleFileNameW,
    HOOK_GetProcAddress,

    // Crypto
    HOOK_CryptEncrypt,
    HOOK_CryptDecrypt,
    HOOK_BCryptEncrypt,
    HOOK_BCryptDecrypt,
    HOOK_BCryptGenerateSymmetricKey,
    HOOK_BCryptGenerateKeyPair,
    HOOK_BCryptImportKey,

    HOOK_COUNT
} HookId;

typedef struct {
    HookId id;
    HookCategory category;
    const char *api_name;
    const char *dll_name;
} HookDef;

static const HookDef g_hook_defs[] = {
    // File I/O
    { HOOK_CreateFileA,          HOOK_CAT_FILE,     "CreateFileA",          "kernel32.dll" },
    { HOOK_CreateFileW,          HOOK_CAT_FILE,     "CreateFileW",          "kernel32.dll" },
    { HOOK_WriteFile,            HOOK_CAT_FILE,     "WriteFile",            "kernel32.dll" },
    { HOOK_ReadFile,             HOOK_CAT_FILE,     "ReadFile",             "kernel32.dll" },
    { HOOK_DeleteFileA,          HOOK_CAT_FILE,     "DeleteFileA",          "kernel32.dll" },
    { HOOK_DeleteFileW,          HOOK_CAT_FILE,     "DeleteFileW",          "kernel32.dll" },
    { HOOK_CloseHandle,          HOOK_CAT_FILE,     "CloseHandle",          "kernel32.dll" },
    { HOOK_FindFirstFileA,       HOOK_CAT_FILE,     "FindFirstFileA",       "kernel32.dll" },
    { HOOK_FindFirstFileW,       HOOK_CAT_FILE,     "FindFirstFileW",       "kernel32.dll" },
    { HOOK_FindFirstFileExA,     HOOK_CAT_FILE,     "FindFirstFileExA",     "kernel32.dll" },
    { HOOK_FindFirstFileExW,     HOOK_CAT_FILE,     "FindFirstFileExW",     "kernel32.dll" },

    // Process
    { HOOK_CreateProcessA,       HOOK_CAT_PROCESS,  "CreateProcessA",       "kernel32.dll" },
    { HOOK_CreateProcessW,       HOOK_CAT_PROCESS,  "CreateProcessW",       "kernel32.dll" },
    { HOOK_OpenProcess,          HOOK_CAT_PROCESS,  "OpenProcess",          "kernel32.dll" },
    { HOOK_WriteProcessMemory,   HOOK_CAT_PROCESS,  "WriteProcessMemory",   "kernel32.dll" },
    { HOOK_VirtualAllocEx,       HOOK_CAT_PROCESS,  "VirtualAllocEx",       "kernel32.dll" },
    { HOOK_VirtualProtectEx,     HOOK_CAT_PROCESS,  "VirtualProtectEx",     "kernel32.dll" },
    { HOOK_CreateRemoteThread,   HOOK_CAT_PROCESS,  "CreateRemoteThread",   "kernel32.dll" },
    { HOOK_CreateRemoteThreadEx, HOOK_CAT_PROCESS,  "CreateRemoteThreadEx", "kernel32.dll" },
    { HOOK_QueueUserAPC,         HOOK_CAT_PROCESS,  "QueueUserAPC",         "kernel32.dll" },
    { HOOK_TerminateProcess,     HOOK_CAT_PROCESS,  "TerminateProcess",     "kernel32.dll" },

    // Memory
    { HOOK_VirtualAlloc,         HOOK_CAT_MEMORY,   "VirtualAlloc",         "kernel32.dll" },
    { HOOK_VirtualProtect,       HOOK_CAT_MEMORY,   "VirtualProtect",       "kernel32.dll" },
    { HOOK_ReadProcessMemory,    HOOK_CAT_MEMORY,   "ReadProcessMemory",    "kernel32.dll" },

    // Registry
    { HOOK_RegOpenKeyExA,        HOOK_CAT_REGISTRY, "RegOpenKeyExA",        "advapi32.dll" },
    { HOOK_RegOpenKeyExW,        HOOK_CAT_REGISTRY, "RegOpenKeyExW",        "advapi32.dll" },
    { HOOK_RegSetValueExA,       HOOK_CAT_REGISTRY, "RegSetValueExA",       "advapi32.dll" },
    { HOOK_RegSetValueExW,       HOOK_CAT_REGISTRY, "RegSetValueExW",       "advapi32.dll" },
    { HOOK_RegCreateKeyExA,      HOOK_CAT_REGISTRY, "RegCreateKeyExA",      "advapi32.dll" },
    { HOOK_RegCreateKeyExW,      HOOK_CAT_REGISTRY, "RegCreateKeyExW",      "advapi32.dll" },
    { HOOK_RegDeleteKeyA,        HOOK_CAT_REGISTRY, "RegDeleteKeyA",        "advapi32.dll" },
    { HOOK_RegDeleteKeyW,        HOOK_CAT_REGISTRY, "RegDeleteKeyW",        "advapi32.dll" },
    { HOOK_RegDeleteKeyExA,      HOOK_CAT_REGISTRY, "RegDeleteKeyExA",      "advapi32.dll" },
    { HOOK_RegDeleteKeyExW,      HOOK_CAT_REGISTRY, "RegDeleteKeyExW",      "advapi32.dll" },
    { HOOK_RegDeleteValueA,      HOOK_CAT_REGISTRY, "RegDeleteValueA",      "advapi32.dll" },
    { HOOK_RegDeleteValueW,      HOOK_CAT_REGISTRY, "RegDeleteValueW",      "advapi32.dll" },

    // Network
    { HOOK_connect,              HOOK_CAT_NETWORK,  "connect",              "ws2_32.dll" },
    { HOOK_WSAConnect,           HOOK_CAT_NETWORK,  "WSAConnect",           "ws2_32.dll" },
    { HOOK_send,                 HOOK_CAT_NETWORK,  "send",                 "ws2_32.dll" },
    { HOOK_sendto,               HOOK_CAT_NETWORK,  "sendto",              "ws2_32.dll" },
    { HOOK_WSASend,              HOOK_CAT_NETWORK,  "WSASend",              "ws2_32.dll" },
    { HOOK_recv,                 HOOK_CAT_NETWORK,  "recv",                 "ws2_32.dll" },
    { HOOK_recvfrom,             HOOK_CAT_NETWORK,  "recvfrom",             "ws2_32.dll" },
    { HOOK_getaddrinfo,          HOOK_CAT_NETWORK,  "getaddrinfo",          "ws2_32.dll" },
    { HOOK_GetAddrInfoW,         HOOK_CAT_NETWORK,  "GetAddrInfoW",         "ws2_32.dll" },
    { HOOK_GetAddrInfoExW,       HOOK_CAT_NETWORK,  "GetAddrInfoExW",       "ws2_32.dll" },
    { HOOK_closesocket,          HOOK_CAT_NETWORK,  "closesocket",          "ws2_32.dll" },

    // HTTP
    { HOOK_InternetOpenA,        HOOK_CAT_HTTP,     "InternetOpenA",        "wininet.dll" },
    { HOOK_InternetOpenW,        HOOK_CAT_HTTP,     "InternetOpenW",        "wininet.dll" },
    { HOOK_InternetConnectA,     HOOK_CAT_HTTP,     "InternetConnectA",     "wininet.dll" },
    { HOOK_InternetConnectW,     HOOK_CAT_HTTP,     "InternetConnectW",     "wininet.dll" },
    { HOOK_HttpOpenRequestA,     HOOK_CAT_HTTP,     "HttpOpenRequestA",     "wininet.dll" },
    { HOOK_HttpOpenRequestW,     HOOK_CAT_HTTP,     "HttpOpenRequestW",     "wininet.dll" },
    { HOOK_HttpSendRequestA,     HOOK_CAT_HTTP,     "HttpSendRequestA",     "wininet.dll" },
    { HOOK_HttpSendRequestW,     HOOK_CAT_HTTP,     "HttpSendRequestW",     "wininet.dll" },
    { HOOK_InternetOpenUrlA,     HOOK_CAT_HTTP,     "InternetOpenUrlA",     "wininet.dll" },
    { HOOK_InternetOpenUrlW,     HOOK_CAT_HTTP,     "InternetOpenUrlW",     "wininet.dll" },
    { HOOK_InternetReadFile,     HOOK_CAT_HTTP,     "InternetReadFile",     "wininet.dll" },

    // Module
    { HOOK_GetModuleHandleA,     HOOK_CAT_MODULE,   "GetModuleHandleA",     "kernel32.dll" },
    { HOOK_GetModuleHandleW,     HOOK_CAT_MODULE,   "GetModuleHandleW",     "kernel32.dll" },
    { HOOK_GetModuleFileNameA,   HOOK_CAT_MODULE,   "GetModuleFileNameA",   "kernel32.dll" },
    { HOOK_GetModuleFileNameW,   HOOK_CAT_MODULE,   "GetModuleFileNameW",   "kernel32.dll" },
    { HOOK_GetProcAddress,       HOOK_CAT_MODULE,   "GetProcAddress",       "kernel32.dll" },

    // Crypto
    { HOOK_CryptEncrypt,         HOOK_CAT_CRYPTO,   "CryptEncrypt",         "advapi32.dll" },
    { HOOK_CryptDecrypt,         HOOK_CAT_CRYPTO,   "CryptDecrypt",         "advapi32.dll" },
    { HOOK_BCryptEncrypt,        HOOK_CAT_CRYPTO,   "BCryptEncrypt",        "bcrypt.dll" },
    { HOOK_BCryptDecrypt,        HOOK_CAT_CRYPTO,   "BCryptDecrypt",        "bcrypt.dll" },
    { HOOK_BCryptGenerateSymmetricKey, HOOK_CAT_CRYPTO, "BCryptGenerateSymmetricKey", "bcrypt.dll" },
    { HOOK_BCryptGenerateKeyPair, HOOK_CAT_CRYPTO,  "BCryptGenerateKeyPair", "bcrypt.dll" },
    { HOOK_BCryptImportKey,      HOOK_CAT_CRYPTO,   "BCryptImportKey",      "bcrypt.dll" },
};

#define HOOK_DEF_COUNT (sizeof(g_hook_defs) / sizeof(g_hook_defs[0]))

#endif
