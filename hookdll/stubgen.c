#include "stubgen.h"
#include <string.h>

static StubEntry g_stub_entries[4096];
static DWORD g_stub_count = 0;

typedef struct {
    BYTE bytes[4];
    BYTE len;
} JunkInstr;

static const JunkInstr g_junk_pool[] = {
    { {0x48, 0x89, 0xC9},       3 },   // mov rcx, rcx
    { {0x48, 0x89, 0xD2},       3 },   // mov rdx, rdx
    { {0x48, 0x89, 0xDB},       3 },   // mov rbx, rbx
    { {0x48, 0x89, 0xED},       3 },   // mov rbp, rbp
    { {0x48, 0x89, 0xF6},       3 },   // mov rsi, rsi
    { {0x48, 0x89, 0xC0},       3 },   // mov rax, rax
    { {0x48, 0x8D, 0x09},       3 },   // lea rcx, [rcx]
    { {0x48, 0x8D, 0x00},       3 },   // lea rax, [rax]
    { {0x48, 0x8D, 0x1B},       3 },   // lea rbx, [rbx]
    { {0x48, 0x87, 0xC0},       3 },   // xchg rax, rax
};

#define JUNK_POOL_COUNT (sizeof(g_junk_pool) / sizeof(g_junk_pool[0]))

static DWORD g_junk_seed = 0x52656D6F;

static DWORD junk_rand(void) {
    g_junk_seed ^= g_junk_seed << 13;
    g_junk_seed ^= g_junk_seed >> 17;
    g_junk_seed ^= g_junk_seed << 5;
    return g_junk_seed;
}

BOOL StubPoolInit(StubPool *pool, void *near_addr, DWORD num_pages) {
    DWORD size = num_pages * STUB_POOL_PAGE_SIZE;
    void *mem = NULL;

    UINT_PTR base = (UINT_PTR)near_addr;
    UINT_PTR low = base;
    UINT_PTR high = base + 0x7FFF0000ULL;

    MEMORY_BASIC_INFORMATION mbi;
    UINT_PTR addr = low;
    while (addr < high) {
        if (VirtualQuery((void *)addr, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            UINT_PTR aligned = (addr + 0xFFFF) & ~0xFFFFULL;
            if (aligned >= base) {
                mem = VirtualAlloc((void *)aligned, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (mem) break;
            }
        }
        addr = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!mem) return FALSE;

    pool->pool_base = (BYTE *)mem;
    pool->pool_size = size;
    pool->next_slot = 0;
    pool->total_slots = size / STUB_SIZE;
    pool->overflow_count = 0;

    g_junk_seed = (DWORD)(UINT_PTR)near_addr ^ 0xDEADBEEF;
    return TRUE;
}

void StubPoolDestroy(StubPool *pool) {
    if (pool->pool_base) {
        VirtualFree(pool->pool_base, 0, MEM_RELEASE);
        pool->pool_base = NULL;
    }
}

StubEntry *StubPoolAllocate(StubPool *pool, void *handler, void *original, DWORD hook_id) {
    if (pool->next_slot >= pool->total_slots)
        return NULL;

    BYTE *stub = pool->pool_base + (pool->next_slot * STUB_SIZE);
    DWORD off = 0;

    // Junk instruction 1
    DWORD j1 = junk_rand() % JUNK_POOL_COUNT;
    memcpy(stub + off, g_junk_pool[j1].bytes, g_junk_pool[j1].len);
    off += g_junk_pool[j1].len;

    // Junk instruction 2
    DWORD j2 = junk_rand() % JUNK_POOL_COUNT;
    while (j2 == j1) j2 = junk_rand() % JUNK_POOL_COUNT;
    memcpy(stub + off, g_junk_pool[j2].bytes, g_junk_pool[j2].len);
    off += g_junk_pool[j2].len;

    // jnz short +2 (skip past the jz to the trampoline)
    stub[off] = 0x75;
    stub[off + 1] = 0x02;
    off += 2;

    // jz short +0 (falls through to trampoline)
    stub[off] = 0x74;
    stub[off + 1] = 0x00;
    off += 2;

    // mov rax, imm64 (absolute handler address)
    stub[off] = 0x48;
    stub[off + 1] = 0xB8;
    *(UINT64 *)(stub + off + 2) = (UINT64)handler;
    off += 10;

    // jmp rax
    stub[off] = 0xFF;
    stub[off + 1] = 0xE0;
    off += 2;

    // Fill remainder with int3 (safety net)
    memset(stub + off, 0xCC, STUB_SIZE - off);

    StubEntry *entry = &g_stub_entries[g_stub_count++];
    entry->stub_addr = stub;
    entry->handler = handler;
    entry->original_func = original;
    entry->hook_id = hook_id;

    pool->next_slot++;
    return entry;
}

void StubPoolFinalize(StubPool *pool) {
    DWORD old_prot;
    VirtualProtect(pool->pool_base, pool->pool_size, PAGE_EXECUTE_READ, &old_prot);
}

BOOL StubPoolMakeWritable(StubPool *pool) {
    DWORD old_prot;
    return VirtualProtect(pool->pool_base, pool->pool_size, PAGE_EXECUTE_READWRITE, &old_prot);
}
