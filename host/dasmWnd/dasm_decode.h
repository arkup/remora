#ifndef DASM_DECODE_H
#define DASM_DECODE_H

#include <windows.h>

#define DASM_MAX_LINES 256

typedef struct {
    UINT64 address;
    BYTE   length;
    BYTE   bytes[15];
    char   text[128];
    BOOL   is_branch;
    BOOL   is_call;
    BOOL   indirect_resolved;  /* call/jmp [mem] whose text was rewritten to show symbol */
    UINT64 branch_target;
    UINT64 slot_address;       /* for indirect call/jmp [mem]: the memory slot address */
} DecodedInsn;

void DasmDecodeInit(HANDLE hProcess);
int  DasmDecodeForward(UINT64 startAddr, int maxInsns, DecodedInsn *out);
int  DasmDecodeBackward(UINT64 targetAddr, int want, DecodedInsn *out);

#endif
