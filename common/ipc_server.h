#ifndef IPC_SERVER_H
#define IPC_SERVER_H

#include <windows.h>
#include "ipc_common.h"

typedef void (*IpcMsgCallback)(const IPC_MSG_HEADER *hdr, const void *extra_data, void *user);

typedef struct {
    HANDLE hPipe;
    HANDLE hThread;
    IpcMsgCallback callback;
    void *user_data;
    volatile BOOL running;
    DWORD target_pid;
    char pipe_name[128];
} IpcServer;

BOOL IpcServerCreate(IpcServer *srv, DWORD target_pid, IpcMsgCallback cb, void *user);
void IpcServerDestroy(IpcServer *srv);
BOOL IpcServerSendResponse(IpcServer *srv, DWORD msg_type, DWORD hook_id, UINT64 value);

#endif
