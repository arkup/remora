#ifndef JAIL_DEFS_H
#define JAIL_DEFS_H

#include "hook_defs.h"

typedef enum {
    JAIL_ALLOW = 0,
    JAIL_LOG   = 1,
    JAIL_ASK   = 2,
    JAIL_BLOCK = 3,
} JailAction;

static const JailAction g_default_jail[HOOK_COUNT] = {
    // File I/O
    [HOOK_CreateFileA]          = JAIL_LOG,
    [HOOK_CreateFileW]          = JAIL_LOG,
    [HOOK_WriteFile]            = JAIL_LOG,
    [HOOK_ReadFile]             = JAIL_LOG,
    [HOOK_DeleteFileA]          = JAIL_LOG,
    [HOOK_DeleteFileW]          = JAIL_LOG,
    [HOOK_CloseHandle]          = JAIL_ALLOW,
    [HOOK_FindFirstFileA]       = JAIL_LOG,
    [HOOK_FindFirstFileW]       = JAIL_LOG,
    [HOOK_FindFirstFileExA]     = JAIL_LOG,
    [HOOK_FindFirstFileExW]     = JAIL_LOG,

    // Process
    [HOOK_CreateProcessA]       = JAIL_LOG,
    [HOOK_CreateProcessW]       = JAIL_LOG,
    [HOOK_OpenProcess]          = JAIL_LOG,
    [HOOK_WriteProcessMemory]   = JAIL_LOG,
    [HOOK_VirtualAllocEx]       = JAIL_LOG,
    [HOOK_VirtualProtectEx]     = JAIL_LOG,
    [HOOK_CreateRemoteThread]   = JAIL_LOG,
    [HOOK_CreateRemoteThreadEx] = JAIL_LOG,
    [HOOK_QueueUserAPC]         = JAIL_LOG,
    [HOOK_TerminateProcess]     = JAIL_LOG,

    // Memory
    [HOOK_VirtualAlloc]         = JAIL_LOG,
    [HOOK_VirtualProtect]       = JAIL_LOG,
    [HOOK_ReadProcessMemory]    = JAIL_LOG,

    // Registry
    [HOOK_RegOpenKeyExA]        = JAIL_LOG,
    [HOOK_RegOpenKeyExW]        = JAIL_LOG,
    [HOOK_RegSetValueExA]       = JAIL_LOG,
    [HOOK_RegSetValueExW]       = JAIL_LOG,
    [HOOK_RegCreateKeyExA]      = JAIL_LOG,
    [HOOK_RegCreateKeyExW]      = JAIL_LOG,
    [HOOK_RegDeleteKeyA]        = JAIL_LOG,
    [HOOK_RegDeleteKeyW]        = JAIL_LOG,
    [HOOK_RegDeleteKeyExA]      = JAIL_LOG,
    [HOOK_RegDeleteKeyExW]      = JAIL_LOG,
    [HOOK_RegDeleteValueA]      = JAIL_LOG,
    [HOOK_RegDeleteValueW]      = JAIL_LOG,

    // Network
    [HOOK_connect]              = JAIL_LOG,
    [HOOK_WSAConnect]           = JAIL_LOG,
    [HOOK_send]                 = JAIL_LOG,
    [HOOK_sendto]               = JAIL_LOG,
    [HOOK_WSASend]              = JAIL_LOG,
    [HOOK_recv]                 = JAIL_LOG,
    [HOOK_recvfrom]             = JAIL_LOG,
    [HOOK_getaddrinfo]          = JAIL_LOG,
    [HOOK_GetAddrInfoW]         = JAIL_LOG,
    [HOOK_GetAddrInfoExW]       = JAIL_LOG,
    [HOOK_closesocket]          = JAIL_LOG,

    // HTTP
    [HOOK_InternetOpenA]        = JAIL_LOG,
    [HOOK_InternetOpenW]        = JAIL_LOG,
    [HOOK_InternetConnectA]     = JAIL_LOG,
    [HOOK_InternetConnectW]     = JAIL_LOG,
    [HOOK_HttpOpenRequestA]     = JAIL_LOG,
    [HOOK_HttpOpenRequestW]     = JAIL_LOG,
    [HOOK_HttpSendRequestA]     = JAIL_LOG,
    [HOOK_HttpSendRequestW]     = JAIL_LOG,
    [HOOK_InternetOpenUrlA]     = JAIL_LOG,
    [HOOK_InternetOpenUrlW]     = JAIL_LOG,
    [HOOK_InternetReadFile]     = JAIL_LOG,

    // Module
    [HOOK_GetModuleHandleA]     = JAIL_LOG,
    [HOOK_GetModuleHandleW]     = JAIL_LOG,
    [HOOK_GetModuleFileNameA]   = JAIL_LOG,
    [HOOK_GetModuleFileNameW]   = JAIL_LOG,
    [HOOK_GetProcAddress]       = JAIL_LOG,

    // Crypto
    [HOOK_CryptEncrypt]         = JAIL_LOG,
    [HOOK_CryptDecrypt]         = JAIL_LOG,
    [HOOK_BCryptEncrypt]        = JAIL_LOG,
    [HOOK_BCryptDecrypt]        = JAIL_LOG,
    [HOOK_BCryptGenerateSymmetricKey] = JAIL_LOG,
    [HOOK_BCryptGenerateKeyPair] = JAIL_LOG,
    [HOOK_BCryptImportKey]      = JAIL_LOG,
};

#endif
