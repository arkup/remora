#ifndef JAIL_SHARED_H
#define JAIL_SHARED_H

#include <windows.h>
#include "jail_defs.h"
#include "jail_rules.h"
#include "ipc_common.h"

#define JAIL_ASK_MAX_PENDING 64
#define JAIL_ASK_TIMEOUT_MS  INFINITE
#define JAIL_COND_MAX_LEN    256

#define JAIL_SHARED_PREFIX   "RemoraJail_"
#define JAIL_EVENT_PREFIX    "RemoraAsk_"

typedef struct {
    volatile DWORD tid;
    volatile DWORD hook_id;
    volatile DWORD action;
} JailAskSlot;

typedef struct {
    volatile DWORD actions[HOOK_COUNT];
    char conditions[HOOK_COUNT][JAIL_COND_MAX_LEN];
    JailAskSlot slots[JAIL_ASK_MAX_PENDING];
    JailRulesShared rules;
    AutoDumpCfg autodump;
    volatile DWORD capture_enabled;
    volatile DWORD capture_max_bytes;
} JailSharedMem;

static inline void JailSharedName(char *buf, DWORD buf_size, DWORD pid) {
    wsprintfA(buf, "%s%u", JAIL_SHARED_PREFIX, pid);
}

static inline void JailEventName(char *buf, DWORD buf_size, DWORD pid, DWORD tid) {
    wsprintfA(buf, "%s%u_%u", JAIL_EVENT_PREFIX, pid, tid);
}

#endif
