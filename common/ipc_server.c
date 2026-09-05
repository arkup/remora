#include "ipc_server.h"
#include <stdio.h>
#include <sddl.h>

static DWORD WINAPI ipc_server_thread(LPVOID param) {
    IpcServer *srv = (IpcServer *)param;
    BYTE *buffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, IPC_BUFFER_SIZE);
    if (!buffer) return 1;
    DWORD bytes_read;

    while (srv->running) {
        if (!ConnectNamedPipe(srv->hPipe, NULL)) {
            if (GetLastError() != ERROR_PIPE_CONNECTED)
                continue;
        }

        while (srv->running) {
            if (!ReadFile(srv->hPipe, buffer, IPC_BUFFER_SIZE, &bytes_read, NULL) || bytes_read == 0)
                break;

            if (bytes_read >= sizeof(IPC_MSG_HEADER)) {
                IPC_MSG_HEADER *hdr = (IPC_MSG_HEADER *)buffer;
                DWORD actual_extra = bytes_read - sizeof(IPC_MSG_HEADER);
                if (hdr->extra_len > actual_extra)
                    hdr->extra_len = actual_extra;
                void *extra = (actual_extra > 0) ? buffer + sizeof(IPC_MSG_HEADER) : NULL;
                if (srv->callback)
                    srv->callback(hdr, extra, srv->user_data);
            }
        }

        DisconnectNamedPipe(srv->hPipe);
    }
    HeapFree(GetProcessHeap(), 0, buffer);
    return 0;
}

BOOL IpcServerCreate(IpcServer *srv, DWORD target_pid, IpcMsgCallback cb, void *user) {
    memset(srv, 0, sizeof(*srv));
    srv->target_pid = target_pid;
    srv->callback = cb;
    srv->user_data = user;

    sprintf(srv->pipe_name, "%s%u", REMORA_PIPE_PREFIX, target_pid);

    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    /* DACL: allow full access to the current user only (owner) */
    BOOL sd_ok = ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:(A;;GA;;;OW)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL);

    srv->hPipe = CreateNamedPipeA(
        srv->pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, IPC_BUFFER_SIZE, IPC_BUFFER_SIZE, 0, sd_ok ? &sa : NULL);

    if (sa.lpSecurityDescriptor)
        LocalFree(sa.lpSecurityDescriptor);

    if (srv->hPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    srv->running = TRUE;
    srv->hThread = CreateThread(NULL, 0, ipc_server_thread, srv, 0, NULL);
    return srv->hThread != NULL;
}

void IpcServerDestroy(IpcServer *srv) {
    srv->running = FALSE;
    if (srv->hPipe != INVALID_HANDLE_VALUE) {
        CancelIoEx(srv->hPipe, NULL);
        CloseHandle(srv->hPipe);
        srv->hPipe = INVALID_HANDLE_VALUE;
    }
    if (srv->hThread) {
        WaitForSingleObject(srv->hThread, 2000);
        CloseHandle(srv->hThread);
        srv->hThread = NULL;
    }
}

BOOL IpcServerSendResponse(IpcServer *srv, DWORD msg_type, DWORD hook_id, UINT64 value) {
    IPC_MSG_HEADER resp = {0};
    resp.msg_type = msg_type;
    resp.hook_id = hook_id;
    resp.ret_value = value;
    DWORD written;
    return WriteFile(srv->hPipe, &resp, sizeof(resp), &written, NULL);
}
