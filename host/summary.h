#ifndef SUMMARY_H
#define SUMMARY_H

#include <windows.h>
#include "ipc_common.h"
#include "hook_defs.h"

#define SUMMARY_MAX_FILES     256
#define SUMMARY_MAX_REG       256
#define SUMMARY_MAX_NET       128
#define SUMMARY_MAX_HTTP      128
#define SUMMARY_MAX_PROC      64
#define SUMMARY_MAX_SUSPICIOUS 32

typedef struct {
    char path[260];
    DWORD create_count;
    DWORD write_count;
    UINT64 write_bytes;
    DWORD read_count;
    DWORD delete_count;
    BOOL was_blocked;
} SummaryFileEntry;

typedef struct {
    char key[512];
    DWORD open_count;
    DWORD set_count;
    DWORD create_count;
    DWORD delete_count;
    BOOL was_blocked;
} SummaryRegEntry;

typedef struct {
    char addr[128];
    DWORD connect_count;
    DWORD send_count;
    UINT64 send_bytes;
    DWORD recv_count;
    UINT64 recv_bytes;
} SummaryNetEntry;

typedef struct {
    char desc[512];
    DWORD count;
} SummaryHttpEntry;

typedef struct {
    char desc[512];
    DWORD count;
} SummaryProcEntry;

typedef struct {
    DWORD total_calls;
    DWORD blocked_count;
    DWORD calls_per_hook[HOOK_COUNT];
    DWORD blocked_per_hook[HOOK_COUNT];
    UINT64 start_tick;
    UINT64 end_tick;

    SummaryFileEntry files[SUMMARY_MAX_FILES];
    int file_count;
    int file_overflow;

    SummaryRegEntry regs[SUMMARY_MAX_REG];
    int reg_count;
    int reg_overflow;

    SummaryNetEntry nets[SUMMARY_MAX_NET];
    int net_count;
    int net_overflow;

    SummaryHttpEntry https[SUMMARY_MAX_HTTP];
    int http_count;
    int http_overflow;

    SummaryProcEntry proc_created[SUMMARY_MAX_PROC];
    int proc_created_count;
    SummaryProcEntry proc_opened[SUMMARY_MAX_PROC];
    int proc_opened_count;
    SummaryProcEntry proc_terminated[SUMMARY_MAX_PROC];
    int proc_terminated_count;

    int keys_generated;
    int encrypt_calls;
    UINT64 encrypt_bytes;
    int decrypt_calls;
    UINT64 decrypt_bytes;

    int valloc_total;
    int valloc_exec_count;
    int vprot_total;
    int vprot_rw_to_rx;

    char suspicious[SUMMARY_MAX_SUSPICIOUS][128];
    int suspicious_count;
} SummaryAccumulator;

void SummaryInit(SummaryAccumulator *acc);
void SummaryDetectSuspicious(SummaryAccumulator *acc);
void SummaryAccumulate(SummaryAccumulator *acc, const IPC_MSG_HEADER *hdr,
                       const char *extra, DWORD extra_len);
BOOL SummaryRenderText(SummaryAccumulator *acc, const char *target_name, DWORD target_pid, FILE *out);

#endif
