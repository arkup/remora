#ifndef IPC_COMMON_H
#define IPC_COMMON_H

#include <windows.h>

#define REMORA_PIPE_PREFIX "\\\\.\\pipe\\remora_"
#define IPC_BUFFER_SIZE (65536 + 256)
#define IPC_MAX_ARGS 8

typedef enum {
    MSG_HOOK_CALL = 1,
    MSG_HOOK_RETURN,
    MSG_LOG_TEXT,
    MSG_JAIL_ASK,
    MSG_JAIL_RESPONSE,
    MSG_HOOK_READY,
    MSG_DLL_LOADED,
    MSG_HOOK_CALLSTACK,
    MSG_AUTO_DUMP,
    MSG_HOOK_BUFFER,
} IpcMsgType;

typedef enum {
    BUFFER_INPUT = 0,
    BUFFER_OUTPUT,
    BUFFER_KEY,
} BufferType;

#define ADUMP_PROT_RX   0x01
#define ADUMP_PROT_RWX  0x02
#define ADUMP_PROT_X    0x04

#pragma pack(push, 1)
typedef struct {
    DWORD enabled;
    DWORD min_size;
    DWORD prot_mask;
} AutoDumpCfg;

typedef struct {
    UINT64 address;
    UINT64 size;
    DWORD  new_prot;
} AutoDumpRequest;
#pragma pack(pop)

#define CAPTURE_MAX_BYTES_LIMIT 65536
#define CAPTURE_DEFAULT_MAX     4096

/*
 * MSG_HOOK_BUFFER uses the standard IPC_MSG_HEADER:
 *   hdr.msg_type  = MSG_HOOK_BUFFER
 *   hdr.hook_id   = HookId
 *   hdr.tid       = thread id
 *   hdr.args[0]   = BufferType (BUFFER_INPUT / BUFFER_OUTPUT / BUFFER_KEY)
 *   hdr.args[1]   = total buffer length (may exceed captured)
 *   hdr.extra_len = captured byte count (follows header)
 */

#define IPC_MAX_STACK_FRAMES 8

#pragma pack(push, 1)
typedef struct {
    DWORD msg_type;
    DWORD hook_id;
    DWORD tid;
    UINT64 timestamp;
    UINT64 ret_addr;
    DWORD arg_count;
    UINT64 args[IPC_MAX_ARGS];
    UINT64 ret_value;
    DWORD extra_len;
} IPC_MSG_HEADER;
#pragma pack(pop)

#endif
