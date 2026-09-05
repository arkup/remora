#ifndef IPC_CLIENT_H
#define IPC_CLIENT_H

#include <windows.h>
#include "ipc_common.h"

typedef BOOL (WINAPI *fn_WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

typedef struct {
    HANDLE hPipe;
    char pipe_name[128];
    fn_WriteFile_t real_WriteFile;
} IpcClient;

BOOL IpcClientConnect(IpcClient *cli, DWORD host_pid);
void IpcClientDisconnect(IpcClient *cli);
BOOL IpcClientSend(IpcClient *cli, const IPC_MSG_HEADER *hdr, const void *extra, DWORD extra_len);
BOOL IpcClientRecv(IpcClient *cli, IPC_MSG_HEADER *hdr);

#endif
