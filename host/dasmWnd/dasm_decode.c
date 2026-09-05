#include "dasm_decode.h"
#include "dasm_symbols.h"
#include <Zydis/Zydis.h>
#include <stdio.h>
#include <string.h>

static HANDLE g_proc = NULL;

void DasmDecodeInit(HANDLE hProcess) {
    g_proc = hProcess;
}

int DasmDecodeForward(UINT64 startAddr, int maxInsns, DecodedInsn *out) {
    if (!g_proc || maxInsns <= 0) return 0;

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
            ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return 0;

    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
        return 0;

    /* Read enough bytes for up to maxInsns instructions (max 15 bytes each) */
    int readLen = maxInsns * 15 + 15;
    if (readLen > 4096) readLen = 4096;
    BYTE *buf = (BYTE *)LocalAlloc(LMEM_FIXED, readLen);
    if (!buf) return 0;

    SIZE_T bytesRead = 0;
    ReadProcessMemory(g_proc, (LPCVOID)(UINT_PTR)startAddr, buf, readLen, &bytesRead);
    if (bytesRead == 0) { LocalFree(buf); return 0; }

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    int count = 0;
    SIZE_T offset = 0;
    while (count < maxInsns && offset < bytesRead) {
        SIZE_T remaining = bytesRead - offset;
        ZyanStatus st = ZydisDecoderDecodeFull(&decoder,
            buf + offset, remaining, &instr, operands);

        DecodedInsn *di = &out[count++];
        di->is_branch         = FALSE;
        di->is_call           = FALSE;
        di->indirect_resolved = FALSE;
        di->branch_target     = 0;
        di->slot_address      = 0;

        if (!ZYAN_SUCCESS(st)) {
            di->address  = startAddr + offset;
            di->length   = 1;
            di->bytes[0] = buf[offset];
            snprintf(di->text, sizeof(di->text), "db %02Xh", buf[offset]);
            offset++;
            continue;
        }

        di->address = startAddr + offset;
        di->length  = (BYTE)instr.length;
        if (instr.length <= 15)
            memcpy(di->bytes, buf + offset, instr.length);

        ZydisFormatterFormatInstruction(&formatter, &instr, operands,
            instr.operand_count_visible,
            di->text, sizeof(di->text),
            startAddr + offset, NULL);

        ZydisInstructionCategory cat = instr.meta.category;
        if (cat == ZYDIS_CATEGORY_COND_BR   ||
            cat == ZYDIS_CATEGORY_UNCOND_BR  ||
            cat == ZYDIS_CATEGORY_CALL       ||
            cat == ZYDIS_CATEGORY_RET) {
            di->is_branch = TRUE;
            di->is_call   = (cat == ZYDIS_CATEGORY_CALL);
        }

        /* Resolve branch targets */
        if (di->is_branch &&
            instr.operand_count_visible > 0 &&
            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            UINT64 target = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[0],
                    startAddr + offset, &target)))
                di->branch_target = target;
        } else if (di->is_branch &&
                   instr.operand_count_visible > 0 &&
                   operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            /* Indirect call/jmp [mem]. Resolve slot -> function pointer -> symbol. */
            UINT64 slotAddr = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[0],
                    startAddr + offset, &slotAddr))) {
                di->slot_address = slotAddr;
                UINT64 fnPtr = 0;
                SIZE_T rd = 0;
                if (ReadProcessMemory(g_proc, (LPCVOID)(UINT_PTR)slotAddr,
                        &fnPtr, sizeof(fnPtr), &rd) && rd == sizeof(fnPtr) && fnPtr) {
                    di->branch_target = fnPtr;
                    char symBuf[96];
                    const char *sym = DasmSymbolLookup(fnPtr, symBuf, sizeof(symBuf));
                    if (!sym)
                        sym = DasmSymbolLookupImport(slotAddr, symBuf, sizeof(symBuf));
                    if (sym) {
                        char *lb = strchr(di->text, '[');
                        char *rb = strrchr(di->text, ']');
                        if (lb && rb && rb > lb) {
                            char newText[128];
                            int prefix = (int)(lb - di->text);
                            snprintf(newText, sizeof(newText), "%.*s[%s]", prefix, di->text, sym);
                            strncpy(di->text, newText, sizeof(di->text) - 1);
                            di->text[sizeof(di->text) - 1] = '\0';
                            di->indirect_resolved = TRUE;
                        }
                    }
                }
            }
        }

        offset += instr.length;
    }

    LocalFree(buf);
    return count;
}

int DasmDecodeBackward(UINT64 targetAddr, int want, DecodedInsn *out) {
    if (!g_proc || want <= 0 || targetAddr == 0) return 0;

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
            ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return 0;

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    /*
     * Forward-sweep convergence: read a window before targetAddr, try
     * multiple starting offsets, forward-decode each, and vote on where
     * real instruction boundaries are.  x86 instruction streams converge
     * quickly, so most candidates agree on the last N boundaries.
     */
    int windowSize = 15 * (want + 8);
    if (windowSize < 256) windowSize = 256;
    if (windowSize > 1024) windowSize = 1024;
    if ((UINT64)windowSize > targetAddr) windowSize = (int)targetAddr;
    if (windowSize <= 0) return 0;

    BYTE *buf = (BYTE *)LocalAlloc(LMEM_FIXED, windowSize);
    if (!buf) return 0;

    UINT64 windowStart = targetAddr - windowSize;
    SIZE_T bytesRead = 0;
    ReadProcessMemory(g_proc, (LPCVOID)(UINT_PTR)windowStart,
                      buf, windowSize, &bytesRead);

    if ((int)bytesRead < windowSize) {
        UINT64 pageStart = targetAddr & ~(UINT64)0xFFF;
        if (pageStart < targetAddr) {
            windowSize = (int)(targetAddr - pageStart);
            windowStart = pageStart;
            ReadProcessMemory(g_proc, (LPCVOID)(UINT_PTR)windowStart,
                              buf, windowSize, &bytesRead);
        }
    }
    if ((int)bytesRead < windowSize) {
        LocalFree(buf);
        return 0;
    }

    /* votes[i] = how many candidate forward-decodes place an instruction
       boundary at window offset i.  targetAddr = offset windowSize. */
    BYTE *votes = (BYTE *)LocalAlloc(LMEM_ZEROINIT, windowSize + 1);
    if (!votes) { LocalFree(buf); return 0; }

    int numCandidates = 15;
    if (numCandidates > windowSize) numCandidates = windowSize;

    for (int c = 0; c < numCandidates; c++) {
        SIZE_T pos = (SIZE_T)c;
        if (votes[pos] < 255) votes[pos]++;
        while (pos < (SIZE_T)windowSize) {
            SIZE_T remaining = (SIZE_T)windowSize - pos;
            ZyanStatus st = ZydisDecoderDecodeFull(&decoder,
                buf + pos, remaining, &instr, operands);
            pos += ZYAN_SUCCESS(st) ? instr.length : 1;
            if (pos <= (SIZE_T)windowSize && votes[pos] < 255)
                votes[pos]++;
        }
    }

    /* Walk backward from targetAddr picking highest-voted boundaries */
    int chain[DASM_MAX_LINES + 1];
    int chainLen = 0;
    int curOff = windowSize;

    while (chainLen < want && curOff > 0) {
        int bestBack = 0, bestVotes = -1;
        for (int back = 1; back <= 15 && back <= curOff; back++) {
            if ((int)votes[curOff - back] > bestVotes) {
                bestVotes = (int)votes[curOff - back];
                bestBack = back;
            }
        }
        if (bestBack == 0) break;
        curOff -= bestBack;
        chain[chainLen++] = curOff;
    }

    LocalFree(votes);
    LocalFree(buf);

    if (chainLen == 0) return 0;

    /* Forward-decode from the earliest boundary so DasmDecodeForward
       handles all field population (symbols, indirect resolution, etc.) */
    UINT64 startAddr = windowStart + chain[chainLen - 1];
    int maxInsns = chainLen + 4;
    DecodedInsn *tmpBuf = (DecodedInsn *)LocalAlloc(LMEM_FIXED,
        maxInsns * sizeof(DecodedInsn));
    if (!tmpBuf) return 0;

    int decoded = DasmDecodeForward(startAddr, maxInsns, tmpBuf);

    int usable = 0;
    for (int i = 0; i < decoded; i++) {
        if (tmpBuf[i].address >= targetAddr) break;
        usable = i + 1;
    }

    int take = usable < want ? usable : want;
    int skip = usable - take;
    for (int i = 0; i < take; i++)
        out[i] = tmpBuf[skip + i];

    LocalFree(tmpBuf);
    return take;
}
