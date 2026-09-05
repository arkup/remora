#include "eat_hook.h"
#include "exports.h"
#include "hook_defs.h"
#include "ipc_client.h"
#include <string.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <strsafe.h>

extern IpcClient g_ipc;

static StubPool g_pool;
static BOOL g_pool_ready = FALSE;
static void *g_originals[HOOK_COUNT] = {0};

typedef struct {
    DWORD *patch_addr;
    DWORD new_rva;
} PendingEatPatch;

static PendingEatPatch g_pending[4096];
static DWORD g_pending_count = 0;

static HMODULE g_eat_patched_modules[128];
static DWORD g_eat_patched_count = 0;

static BOOL EatHookAlreadyPatched(HMODULE hMod) {
    for (DWORD i = 0; i < g_eat_patched_count; i++) {
        if (g_eat_patched_modules[i] == hMod) return TRUE;
    }
    return FALSE;
}

static void EatHookMarkPatched(HMODULE hMod) {
    if (g_eat_patched_count < 128)
        g_eat_patched_modules[g_eat_patched_count++] = hMod;
}

static HMODULE g_iat_patched_modules[512];
static DWORD g_iat_patched_count = 0;

static BOOL IatAlreadyPatched(HMODULE hMod) {
    for (DWORD i = 0; i < g_iat_patched_count; i++) {
        if (g_iat_patched_modules[i] == hMod) return TRUE;
    }
    return FALSE;
}

static void IatMarkPatched(HMODULE hMod) {
    if (g_iat_patched_count < 512)
        g_iat_patched_modules[g_iat_patched_count++] = hMod;
}

extern void *g_hook_handlers[HOOK_COUNT];

BOOL EatHookInit(void) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return FALSE;

    if (!StubPoolInit(&g_pool, hKernel32, 4))
        return FALSE;

    g_pool_ready = TRUE;

    {
        char dbg[256];
        StringCchPrintfA(dbg, sizeof(dbg), "[diag] StubPool: base=%p, module=%p, offset=+0x%X, size=0x%X, slots=%u",
            g_pool.pool_base, hKernel32,
            (DWORD)(g_pool.pool_base - (BYTE *)hKernel32),
            g_pool.pool_size, g_pool.total_slots);
        IPC_MSG_HEADER dmsg = {0};
        dmsg.msg_type = 7;
        dmsg.extra_len = (DWORD)strlen(dbg) + 1;
        IpcClientSend(&g_ipc, &dmsg, dbg, dmsg.extra_len);
    }

    return TRUE;
}

static DWORD bsearch_export_name(BYTE *base, DWORD *names, DWORD count, const char *target) {
    DWORD lo = 0, hi = count;
    while (lo < hi) {
        DWORD mid = (lo + hi) / 2;
        int cmp = strcmp((const char *)(base + names[mid]), target);
        if (cmp < 0) lo = mid + 1;
        else if (cmp > 0) hi = mid;
        else return mid;
    }
    return (DWORD)-1;
}

BOOL EatHookModule(HMODULE hMod, const char *dll_name) {
    if (!g_pool_ready) return FALSE;
    if (EatHookAlreadyPatched(hMod)) return TRUE;

    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!export_rva) return FALSE;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + export_rva);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ordinals = (WORD *)(base + exp->AddressOfNameOrdinals);

    if (g_pool.pool_base < base) {
        char dbg[256];
        StringCchPrintfA(dbg, sizeof(dbg), "[diag] EAT skip %s: pool=%p < module=%p (pool is below module)",
            dll_name, g_pool.pool_base, base);
        IPC_MSG_HEADER dmsg = {0};
        dmsg.msg_type = 7;
        dmsg.extra_len = (DWORD)strlen(dbg) + 1;
        IpcClientSend(&g_ipc, &dmsg, dbg, dmsg.extra_len);
        return FALSE;
    }
    UINT64 rva_check = (UINT64)(g_pool.pool_base - base);
    if (rva_check > 0x7FFFFFFF) {
        char dbg[256];
        StringCchPrintfA(dbg, sizeof(dbg), "[diag] EAT skip %s: pool=%p module=%p delta=0x%I64X > 0x7FFFFFFF",
            dll_name, g_pool.pool_base, base, rva_check);
        IPC_MSG_HEADER dmsg = {0};
        dmsg.msg_type = 7;
        dmsg.extra_len = (DWORD)strlen(dbg) + 1;
        IpcClientSend(&g_ipc, &dmsg, dbg, dmsg.extra_len);
        return FALSE;
    }

    DWORD hooked = 0;
    DWORD matched = 0;
    DWORD no_export = 0;
    DWORD no_handler = 0;

    for (DWORD h = 0; h < HOOK_DEF_COUNT; h++) {
        if (_stricmp(g_hook_defs[h].dll_name, dll_name) != 0)
            continue;
        matched++;
        if (!g_hook_handlers[g_hook_defs[h].id]) {
            no_handler++;
            continue;
        }

        DWORD idx = bsearch_export_name(base, names, exp->NumberOfNames, g_hook_defs[h].api_name);
        if (idx == (DWORD)-1) {
            no_export++;
            continue;
        }

        WORD ord = ordinals[idx];
        void *func_addr = base + funcs[ord];

        BOOL is_forwarded = ((DWORD)((BYTE*)func_addr - base) >= export_rva &&
                             (DWORD)((BYTE*)func_addr - base) < export_rva + export_size);

        if (is_forwarded)
            func_addr = (void *)GetProcAddress(hMod, g_hook_defs[h].api_name);
        if (!func_addr)
            continue;

        if (!g_originals[g_hook_defs[h].id])
            g_originals[g_hook_defs[h].id] = func_addr;

        StubEntry *stub = StubPoolAllocate(
            &g_pool,
            g_hook_handlers[g_hook_defs[h].id],
            func_addr,
            g_hook_defs[h].id);

        if (!stub) {
            char dbg[256];
            StringCchPrintfA(dbg, sizeof(dbg), "[diag] EAT stub FAILED %s: handler=%p pool=%p (rel32 overflow?)",
                g_hook_defs[h].api_name, g_hook_handlers[g_hook_defs[h].id], g_pool.pool_base);
            IPC_MSG_HEADER dmsg = {0};
            dmsg.msg_type = 7;
            dmsg.extra_len = (DWORD)strlen(dbg) + 1;
            IpcClientSend(&g_ipc, &dmsg, dbg, dmsg.extra_len);
            continue;
        }

        if (g_pending_count < 4096) {
            DWORD new_rva = (DWORD)(stub->stub_addr - base);
            g_pending[g_pending_count].patch_addr = &funcs[ord];
            g_pending[g_pending_count].new_rva = new_rva;
            g_pending_count++;
            hooked++;

            if (g_hook_defs[h].id == HOOK_CreateProcessA || g_hook_defs[h].id == HOOK_CreateProcessW) {
                char dbg[256];
                StringCchPrintfA(dbg, sizeof(dbg), "[diag] Pending %s in %s: rva=0x%08X fwd=%d",
                    g_hook_defs[h].api_name, dll_name, new_rva, is_forwarded);
                IPC_MSG_HEADER dmsg = {0};
                dmsg.msg_type = 7;
                dmsg.extra_len = (DWORD)strlen(dbg) + 1;
                IpcClientSend(&g_ipc, &dmsg, dbg, dmsg.extra_len);
            }
        }
    }

    if (hooked > 0)
        EatHookMarkPatched(hMod);

    if (hooked == 0) {
        char dbg[256];
        if (matched == 0)
            StringCchPrintfA(dbg, sizeof(dbg), "[diag] EAT %s: no hook_defs target this module", dll_name);
        else
            StringCchPrintfA(dbg, sizeof(dbg), "[diag] EAT %s: 0 hooked (defs=%u no_handler=%u no_export=%u) base=%p pool=%p",
                dll_name, matched, no_handler, no_export, base, g_pool.pool_base);
        IPC_MSG_HEADER dmsg = {0};
        dmsg.msg_type = 7;
        dmsg.extra_len = (DWORD)strlen(dbg) + 1;
        IpcClientSend(&g_ipc, &dmsg, dbg, dmsg.extra_len);
    }

    return hooked > 0;
}

void EatHookFinalize(void) {
    if (g_pool_ready && g_pool.next_slot > 0)
        StubPoolFinalize(&g_pool);
}

void EatHookCommit(void) {
    if (!g_pool_ready) return;

    if (g_pool.next_slot > 0)
        StubPoolFinalize(&g_pool);

    for (DWORD i = 0; i < g_pending_count; i++) {
        DWORD old_prot;
        VirtualProtect(g_pending[i].patch_addr, sizeof(DWORD), PAGE_READWRITE, &old_prot);
        *g_pending[i].patch_addr = g_pending[i].new_rva;
        VirtualProtect(g_pending[i].patch_addr, sizeof(DWORD), old_prot, &old_prot);
    }
    g_pending_count = 0;
}

void EatHookPatchModuleIAT(HMODULE hMod) {
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva) return;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp_rva);
    for (; imp->Name; imp++) {
        UINT64 *thunk = (UINT64 *)(base + imp->FirstThunk);
        for (; *thunk; thunk++) {
            for (DWORD h = 0; h < HOOK_COUNT; h++) {
                if (!g_originals[h] || !g_hook_handlers[h]) continue;
                if ((void *)*thunk == g_originals[h]) {
                    DWORD old_prot;
                    VirtualProtect(thunk, sizeof(*thunk), PAGE_READWRITE, &old_prot);
                    *thunk = (UINT64)g_hook_handlers[h];
                    VirtualProtect(thunk, sizeof(*thunk), old_prot, &old_prot);
                }
            }
        }
    }
}

void EatHookPatchIATs(void) {
    HMODULE mods[512];
    DWORD needed;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return;
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD m = 0; m < count; m++)
        EatHookPatchModuleIAT(mods[m]);
}

static DWORD rva_to_offset(IMAGE_NT_HEADERS64 *nt, DWORD rva) {
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].SizeOfRawData) {
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
        }
    }
    return 0;
}

static const char *resolve_export_name_by_ordinal(HMODULE hMod, WORD ordinal) {
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + export_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *name_ordinals = (WORD *)(base + exp->AddressOfNameOrdinals);

    WORD biased = ordinal - (WORD)exp->Base;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (name_ordinals[i] == biased)
            return (const char *)(base + names[i]);
    }
    return NULL;
}

DWORD EatHookPatchIATsByName(HMODULE hMod) {
    DWORD iat_patched = 0;
    char mod_path[MAX_PATH];
    if (!GetModuleFileNameA(hMod, mod_path, MAX_PATH)) return 0;

    HANDLE hFile = CreateFileA(mod_path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == 0 || file_size > 256 * 1024 * 1024) { CloseHandle(hFile); return 0; }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    BYTE *disk = (BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!disk) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    IMAGE_DOS_HEADER *disk_dos = (IMAGE_DOS_HEADER *)disk;
    if (disk_dos->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;

    IMAGE_NT_HEADERS64 *disk_nt = (IMAGE_NT_HEADERS64 *)(disk + disk_dos->e_lfanew);
    if (disk_nt->Signature != IMAGE_NT_SIGNATURE) goto cleanup;

    DWORD imp_rva = disk_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva) goto cleanup;

    DWORD imp_offset = rva_to_offset(disk_nt, imp_rva);
    if (!imp_offset) goto cleanup;

    BYTE *mem_base = (BYTE *)hMod;
    IMAGE_IMPORT_DESCRIPTOR *disk_imp = (IMAGE_IMPORT_DESCRIPTOR *)(disk + imp_offset);

    for (; disk_imp->Name; disk_imp++) {
        DWORD name_offset = rva_to_offset(disk_nt, disk_imp->Name);
        if (!name_offset) continue;
        const char *dll_name = (const char *)(disk + name_offset);

        BOOL has_hooks = FALSE;
        for (DWORD h = 0; h < HOOK_DEF_COUNT; h++) {
            if (_stricmp(g_hook_defs[h].dll_name, dll_name) == 0 && g_hook_handlers[g_hook_defs[h].id]) {
                has_hooks = TRUE;
                break;
            }
        }
        if (!has_hooks) continue;

        // Read function names from disk (unresolved FirstThunk or OriginalFirstThunk)
        DWORD name_table_rva = disk_imp->OriginalFirstThunk ? disk_imp->OriginalFirstThunk : disk_imp->FirstThunk;
        DWORD name_table_offset = rva_to_offset(disk_nt, name_table_rva);
        if (!name_table_offset) continue;

        UINT64 *disk_names = (UINT64 *)(disk + name_table_offset);
        UINT64 *mem_iat = (UINT64 *)(mem_base + disk_imp->FirstThunk);

        HMODULE hImpDll = GetModuleHandleA(dll_name);

        for (DWORD i = 0; disk_names[i]; i++) {
            const char *func_name = NULL;

            if (disk_names[i] & 0x8000000000000000ULL) {
                WORD ordinal = (WORD)(disk_names[i] & 0xFFFF);
                if (hImpDll) {
                    func_name = resolve_export_name_by_ordinal(hImpDll, ordinal);
                }
                if (!func_name) continue;
            } else {
                DWORD hint_offset = rva_to_offset(disk_nt, (DWORD)disk_names[i]);
                if (!hint_offset) continue;
                IMAGE_IMPORT_BY_NAME *hint = (IMAGE_IMPORT_BY_NAME *)(disk + hint_offset);
                func_name = (const char *)hint->Name;
            }

            for (DWORD h = 0; h < HOOK_DEF_COUNT; h++) {
                if (!g_hook_handlers[g_hook_defs[h].id]) continue;
                if (_stricmp(g_hook_defs[h].dll_name, dll_name) != 0) continue;
                if (strcmp(g_hook_defs[h].api_name, func_name) != 0) continue;

                if (!g_originals[g_hook_defs[h].id])
                    g_originals[g_hook_defs[h].id] = (void *)mem_iat[i];

                if ((void *)mem_iat[i] != g_hook_handlers[g_hook_defs[h].id]) {
                    DWORD old_prot;
                    VirtualProtect(&mem_iat[i], sizeof(UINT64), PAGE_READWRITE, &old_prot);
                    mem_iat[i] = (UINT64)g_hook_handlers[g_hook_defs[h].id];
                    VirtualProtect(&mem_iat[i], sizeof(UINT64), old_prot, &old_prot);
                    iat_patched++;
                }
                break;
            }
        }
    }

cleanup:
    UnmapViewOfFile(disk);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return iat_patched;
}

void EatHookPatchAllIATsByName(void) {
    HMODULE mods[512];
    DWORD needed;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return;
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD m = 0; m < count; m++)
        EatHookPatchIATsByName(mods[m]);
}

void EatHookPatchIATsInline(void) {
    typedef struct _PEB_LDR_DATA2 {
        BYTE Reserved1[8];
        PVOID Reserved2[3];
        LIST_ENTRY InMemoryOrderModuleList;
    } PEB_LDR_DATA2;

    typedef struct _LDR_DATA_TABLE_ENTRY2 {
        PVOID Reserved1[2];
        LIST_ENTRY InMemoryOrderLinks;
        PVOID Reserved2[2];
        PVOID DllBase;
    } LDR_DATA_TABLE_ENTRY2;

#if defined(_M_X64)
    PEB_LDR_DATA2 *ldr = *(PEB_LDR_DATA2 **)((BYTE *)__readgsqword(0x60) + 0x18);
#else
    PEB_LDR_DATA2 *ldr = *(PEB_LDR_DATA2 **)((BYTE *)__readfsdword(0x30) + 0x0C);
#endif

    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *cur = head->Flink;
    while (cur != head) {
        LDR_DATA_TABLE_ENTRY2 *entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY2, InMemoryOrderLinks);
        if (entry->DllBase)
            EatHookPatchModuleIAT((HMODULE)entry->DllBase);
        cur = cur->Flink;
    }
}

void *EatHookGetOriginal(DWORD hook_id) {
    if (hook_id >= HOOK_COUNT) return NULL;
    return g_originals[hook_id];
}

void *EatHookSetOriginal(DWORD hook_id, void *addr) {
    if (hook_id >= HOOK_COUNT) return NULL;
    if (!g_originals[hook_id])
        g_originals[hook_id] = addr;
    return g_originals[hook_id];
}

DWORD EatHookGetCount(void) {
    return g_pool.next_slot;
}

DWORD EatHookGetOverflowCount(void) {
    return g_pool.overflow_count;
}

void EatHookPatchNewModule(HMODULE hMod, const char *dll_name) {
    if (!g_pool_ready) return;

    if (!EatHookAlreadyPatched(hMod)) {
        BOOL is_target = FALSE;
        for (DWORD h = 0; h < HOOK_DEF_COUNT; h++) {
            if (_stricmp(g_hook_defs[h].dll_name, dll_name) == 0) {
                is_target = TRUE;
                break;
            }
        }

        if (is_target) {
            StubPoolMakeWritable(&g_pool);
            EatHookModule(hMod, dll_name);
            EatHookCommit();
        }
    }

    if (!IatAlreadyPatched(hMod)) {
        EatHookPatchModuleIAT(hMod);
        IatMarkPatched(hMod);
    }
}
