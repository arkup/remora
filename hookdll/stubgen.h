#ifndef STUBGEN_H
#define STUBGEN_H

#include <windows.h>

#define STUB_SIZE 32
#define STUB_POOL_PAGE_SIZE 4096
#define STUBS_PER_PAGE (STUB_POOL_PAGE_SIZE / STUB_SIZE)

typedef struct {
    BYTE *pool_base;
    DWORD pool_size;
    DWORD next_slot;
    DWORD total_slots;
    DWORD overflow_count;
} StubPool;

typedef struct {
    BYTE *stub_addr;
    void *handler;
    void *original_func;
    DWORD hook_id;
} StubEntry;

BOOL StubPoolInit(StubPool *pool, void *near_addr, DWORD num_pages);
void StubPoolDestroy(StubPool *pool);
StubEntry *StubPoolAllocate(StubPool *pool, void *handler, void *original, DWORD hook_id);
void StubPoolFinalize(StubPool *pool);
BOOL StubPoolMakeWritable(StubPool *pool);

#endif
