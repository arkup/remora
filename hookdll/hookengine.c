#include "hookengine.h"
#include <Zydis/Zydis.h>
#include <string.h>

#define TRAMPOLINE_SIZE 128
#define SEARCH_RANGE 0x40000000ULL

BOOL HookEngineInit(void) {
    return TRUE;
}

static void *find_nearby_page(void *target, SIZE_T size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    UINT_PTR base = (UINT_PTR)target;
    UINT_PTR low = (base > SEARCH_RANGE) ? base - SEARCH_RANGE : (UINT_PTR)si.lpMinimumApplicationAddress;
    UINT_PTR high = base + SEARCH_RANGE;
    if (high < base) high = (UINT_PTR)si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    UINT_PTR addr = low;

    while (addr < high) {
        if (VirtualQuery((void *)addr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            UINT_PTR aligned = (addr + 0xFFFF) & ~0xFFFFULL;
            if (aligned + size < high) {
                void *p = VirtualAlloc((void *)aligned, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (p) return p;
            }
        }
        addr = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;
    }
    return NULL;
}

void *AllocateNearby(void *target, SIZE_T size) {
    return find_nearby_page(target, size);
}

static BOOL relocate_instruction(ZydisDecodedInstruction *instr, ZydisDecodedOperand *operands,
                                  BYTE *src, BYTE *dst) {
    UINT_PTR src_rip = (UINT_PTR)src + instr->length;
    UINT_PTR dst_rip = (UINT_PTR)dst + instr->length;

    memcpy(dst, src, instr->length);

    for (int i = 0; i < instr->operand_count_visible; i++) {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[i].mem.base == ZYDIS_REGISTER_RIP) {
            INT64 target_addr = (INT64)src_rip + operands[i].mem.disp.value;
            INT64 new_disp = target_addr - (INT64)dst_rip;

            if (new_disp > 0x7FFFFFFF || new_disp < -0x7FFFFFFFLL)
                return FALSE;

            ZyanU8 disp_offset = instr->raw.disp.offset;
            *(INT32 *)(dst + disp_offset) = (INT32)new_disp;
            return TRUE;
        }
    }

    if (instr->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE &&
        instr->raw.imm[0].is_relative) {
        INT64 target_addr = (INT64)src_rip + (INT64)instr->raw.imm[0].value.s;
        INT64 new_disp = target_addr - (INT64)dst_rip;

        if (new_disp > 0x7FFFFFFF || new_disp < -0x7FFFFFFFLL)
            return FALSE;

        ZyanU8 imm_offset = instr->raw.imm[0].offset;
        ZyanU8 imm_size = instr->raw.imm[0].size / 8;
        if (imm_size == 4)
            *(INT32 *)(dst + imm_offset) = (INT32)new_disp;
        else if (imm_size == 1)
            *(INT8 *)(dst + imm_offset) = (INT8)new_disp;
        return TRUE;
    }

    return TRUE;
}

BOOL HookEngineInstall(InlineHook *hook, void *target, void *handler) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    BYTE *code = (BYTE *)target;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    DWORD offset = 0;

    // Disassemble enough bytes at function entry to fit a 5-byte JMP
    while (offset < 5) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + offset, 15, &instr, operands)))
            return FALSE;
        offset += instr.length;
    }

    DWORD bytes_to_steal = offset;

    BYTE *trampoline = (BYTE *)find_nearby_page(code, TRAMPOLINE_SIZE);
    if (!trampoline)
        return FALSE;

    // Build trampoline: relocated displaced instructions + JMP back
    DWORD tramp_offset = 0;
    DWORD src_offset = 0;
    while (src_offset < bytes_to_steal) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + src_offset, 15, &instr, operands))) {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return FALSE;
        }
        if (!relocate_instruction(&instr, operands, code + src_offset, trampoline + tramp_offset)) {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return FALSE;
        }
        tramp_offset += instr.length;
        src_offset += instr.length;
    }

    // JMP back to original code after stolen bytes
    INT64 jmp_back_target = (INT64)(code + bytes_to_steal);
    INT64 jmp_back_rip = (INT64)(trampoline + tramp_offset + 5);
    INT32 jmp_back_disp = (INT32)(jmp_back_target - jmp_back_rip);
    trampoline[tramp_offset] = 0xE9;
    *(INT32 *)(trampoline + tramp_offset + 1) = jmp_back_disp;
    tramp_offset += 5;

    DWORD old_prot;

    // Build relay stub in trampoline: absolute JMP to handler
    // Layout: [displaced bytes + jmp back] [relay: ff 25 + abs addr]
    DWORD relay_offset = tramp_offset;
    trampoline[tramp_offset] = 0xFF;
    trampoline[tramp_offset + 1] = 0x25;
    *(INT32 *)(trampoline + tramp_offset + 2) = 0;
    *(UINT64 *)(trampoline + tramp_offset + 6) = (UINT64)handler;
    tramp_offset += 14;

    VirtualProtect(trampoline, TRAMPOLINE_SIZE, PAGE_EXECUTE_READ, &old_prot);

    // Patch function entry with JMP rel32 to relay stub (always within 2GB)
    VirtualProtect(code, bytes_to_steal, PAGE_EXECUTE_READWRITE, &old_prot);

    INT64 relay_addr = (INT64)(trampoline + relay_offset);
    INT64 hook_rip = (INT64)(code + 5);
    INT32 hook_disp = (INT32)(relay_addr - hook_rip);

    code[0] = 0xE9;
    *(INT32 *)(code + 1) = hook_disp;

    for (DWORD i = 5; i < bytes_to_steal; i++)
        code[i] = 0x90;

    VirtualProtect(code, bytes_to_steal, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), code, bytes_to_steal);

    hook->target_func = target;
    hook->hook_func = handler;
    hook->trampoline = trampoline;
    hook->hook_site = code;
    hook->hook_site_offset = 0;
    hook->displaced_size = bytes_to_steal;

    return TRUE;
}

BOOL HookEngineRemove(InlineHook *hook) {
    if (!hook->hook_site || !hook->trampoline)
        return FALSE;

    DWORD old_prot;
    VirtualProtect(hook->hook_site, hook->displaced_size, PAGE_EXECUTE_READWRITE, &old_prot);

    BYTE *tramp = (BYTE *)hook->trampoline;
    memcpy(hook->hook_site, tramp, hook->displaced_size);

    VirtualProtect(hook->hook_site, hook->displaced_size, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), hook->hook_site, hook->displaced_size);

    VirtualFree(hook->trampoline, 0, MEM_RELEASE);
    hook->trampoline = NULL;
    hook->hook_site = NULL;

    return TRUE;
}

void *HookEngineGetOriginal(InlineHook *hook) {
    return hook->trampoline;
}
