#include "ipc_client.h"
#include <stdio.h>
#include <malloc.h>

BOOL IpcClientConnect(IpcClient *cli, DWORD host_pid) {
    memset(cli, 0, sizeof(*cli));
    sprintf(cli->pipe_name, "%s%u", REMORA_PIPE_PREFIX, host_pid);

    cli->real_WriteFile = (fn_WriteFile_t)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "WriteFile");

    for (int i = 0; i < 200; i++) {
        cli->hPipe = CreateFileA(
            cli->pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);

        if (cli->hPipe != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(cli->hPipe, &mode, NULL, NULL);
            return TRUE;
        }
        Sleep(10);
    }
    return FALSE;
}

void IpcClientDisconnect(IpcClient *cli) {
    if (cli->hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(cli->hPipe);
        cli->hPipe = INVALID_HANDLE_VALUE;
    }
}

BOOL IpcClientSend(IpcClient *cli, const IPC_MSG_HEADER *hdr, const void *extra, DWORD extra_len) {
    DWORD written;
    DWORD total = sizeof(IPC_MSG_HEADER) + extra_len;
    BOOL use_heap = (total > 4096);
    BYTE *buf = use_heap ? (BYTE *)HeapAlloc(GetProcessHeap(), 0, total) : (BYTE *)alloca(total);
    if (!buf) return FALSE;
    memcpy(buf, hdr, sizeof(IPC_MSG_HEADER));
    if (extra && extra_len > 0)
        memcpy(buf + sizeof(IPC_MSG_HEADER), extra, extra_len);
    BOOL ok;
    if (cli->real_WriteFile)
        ok = cli->real_WriteFile(cli->hPipe, buf, total, &written, NULL);
    else
        ok = WriteFile(cli->hPipe, buf, total, &written, NULL);
    if (use_heap) HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

BOOL IpcClientRecv(IpcClient *cli, IPC_MSG_HEADER *hdr) {
    DWORD bytes_read;
    return ReadFile(cli->hPipe, hdr, sizeof(*hdr), &bytes_read, NULL) && bytes_read == sizeof(*hdr);
}
