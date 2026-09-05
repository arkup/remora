#include "dasm_symbols.h"
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    UINT64 addr;
    char   name[128];
} Symbol;

typedef struct {
    UINT64 base;
    UINT64 end;
    char   name[64];
} ModuleRange;

static Symbol      *g_syms    = NULL;
static int          g_symCount = 0;
static int          g_symCap   = 0;

static ModuleRange *g_mods    = NULL;
static int          g_modCount = 0;
static int          g_modCap   = 0;

static HANDLE       g_symProc = NULL;

static void sym_push(UINT64 addr, const char *name) {
    if (g_symCount >= g_symCap) {
        int newCap = g_symCap ? g_symCap * 2 : 1024;
        Symbol *p = (Symbol *)realloc(g_syms, newCap * sizeof(Symbol));
        if (!p) return;
        g_syms   = p;
        g_symCap = newCap;
    }
    g_syms[g_symCount].addr = addr;
    strncpy(g_syms[g_symCount].name, name, 127);
    g_syms[g_symCount].name[127] = '\0';
    g_symCount++;
}

static void mod_push(UINT64 base, UINT64 end, const char *name) {
    if (g_modCount >= g_modCap) {
        int newCap = g_modCap ? g_modCap * 2 : 64;
        ModuleRange *p = (ModuleRange *)realloc(g_mods, newCap * sizeof(ModuleRange));
        if (!p) return;
        g_mods   = p;
        g_modCap = newCap;
    }
    g_mods[g_modCount].base = base;
    g_mods[g_modCount].end  = end;
    strncpy(g_mods[g_modCount].name, name, 63);
    g_mods[g_modCount].name[63] = '\0';
    g_modCount++;
}

static int sym_cmp(const void *a, const void *b) {
    const Symbol *sa = (const Symbol *)a;
    const Symbol *sb = (const Symbol *)b;
    if (sa->addr < sb->addr) return -1;
    if (sa->addr > sb->addr) return  1;
    return 0;
}

static void parse_module_exports(HANDLE hProcess, HMODULE hMod, const char *modName) {
    BYTE hdrs[4096];
    SIZE_T bytesRead = 0;
    UINT64 base = (UINT64)(UINT_PTR)hMod;

    if (!ReadProcessMemory(hProcess, hMod, hdrs, sizeof(hdrs), &bytesRead) || bytesRead < 64)
        return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdrs;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    if (dos->e_lfanew < 0 || dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > bytesRead) return;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(hdrs + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;

    IMAGE_DATA_DIRECTORY expDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 || expDir.Size == 0) return;

    /* Read export directory */
    DWORD expSize = expDir.Size;
    if (expSize > 512 * 1024) expSize = 512 * 1024;
    BYTE *expBuf = (BYTE *)malloc(expSize);
    if (!expBuf) return;

    bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)(base + expDir.VirtualAddress),
                           expBuf, expSize, &bytesRead) || bytesRead < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        free(expBuf);
        return;
    }

    IMAGE_EXPORT_DIRECTORY *ied = (IMAGE_EXPORT_DIRECTORY *)expBuf;
    DWORD numNames    = ied->NumberOfNames;
    DWORD numFuncs    = ied->NumberOfFunctions;
    DWORD addrRva     = ied->AddressOfFunctions;
    DWORD nameRva     = ied->AddressOfNames;
    DWORD ordinalRva  = ied->AddressOfNameOrdinals;
    DWORD ordinalBase = ied->Base;

    if (numNames > 65536 || numFuncs > 65536) { free(expBuf); return; }

    /* Helper: read a DWORD from the export buffer by RVA */
    #define EXP_RVA_OK(rva, n) ((rva) >= expDir.VirtualAddress && \
        (rva) + (n) <= expDir.VirtualAddress + expSize)

    #define EXP_PTR(rva) (expBuf + ((rva) - expDir.VirtualAddress))

    /* Walk named exports */
    for (DWORD i = 0; i < numNames; i++) {
        DWORD nameArrayOff = nameRva - expDir.VirtualAddress + i * 4;
        DWORD ordArrayOff  = ordinalRva - expDir.VirtualAddress + i * 2;

        if (!EXP_RVA_OK(nameRva + i * 4, 4)) continue;
        if (!EXP_RVA_OK(ordinalRva + i * 2, 2)) continue;

        DWORD  fnNameRva = *(DWORD *)(expBuf + nameArrayOff);
        WORD   ordIdx    = *(WORD  *)(expBuf + ordArrayOff);

        if (!EXP_RVA_OK(addrRva + ordIdx * 4, 4)) continue;
        DWORD funcRva = *(DWORD *)(expBuf + (addrRva - expDir.VirtualAddress) + ordIdx * 4);

        /* Skip forwarded exports (RVA inside the export dir range) */
        if (funcRva >= expDir.VirtualAddress &&
            funcRva <  expDir.VirtualAddress + expDir.Size)
            continue;

        /* Get the name string */
        if (!EXP_RVA_OK(fnNameRva, 1)) continue;
        char *fnName = (char *)EXP_PTR(fnNameRva);
        /* Ensure null-terminated within buffer */
        int maxLen = (int)(expSize - (fnNameRva - expDir.VirtualAddress));
        if (maxLen <= 0) continue;

        char symName[192];
        int  snLen = maxLen < 127 ? maxLen : 127;
        strncpy(symName, fnName, snLen);
        symName[snLen] = '\0';

        sym_push(base + funcRva, symName);
    }

    #undef EXP_RVA_OK
    #undef EXP_PTR

    free(expBuf);
}

void DasmSymbolBuild(HANDLE hProcess) {
    DasmSymbolFree();
    if (!hProcess) return;
    g_symProc = hProcess;

    HMODULE mods[512];
    DWORD needed = 0;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) return;
    int count = (int)(needed / sizeof(HMODULE));
    if (count > 512) count = 512;

    for (int i = 0; i < count; i++) {
        MODULEINFO mi;
        if (!GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi))) continue;

        char path[MAX_PATH] = {0};
        GetModuleFileNameExA(hProcess, mods[i], path, MAX_PATH);
        char *slash = strrchr(path, '\\');
        const char *modName = slash ? slash + 1 : path;

        UINT64 base = (UINT64)(UINT_PTR)mi.lpBaseOfDll;
        mod_push(base, base + mi.SizeOfImage, modName);

        parse_module_exports(hProcess, mods[i], modName);
    }

    if (g_symCount > 1)
        qsort(g_syms, g_symCount, sizeof(Symbol), sym_cmp);
}

const char *DasmSymbolLookup(UINT64 addr, char *buf, int bufSize) {
    if (!g_syms || g_symCount == 0 || !buf || bufSize <= 0) return NULL;

    /* Binary search for largest addr <= target */
    int lo = 0, hi = g_symCount - 1, best = -1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (g_syms[mid].addr <= addr) {
            best = mid;
            lo   = mid + 1;
        } else {
            hi   = mid - 1;
        }
    }
    if (best < 0) return NULL;

    UINT64 offset = addr - g_syms[best].addr;
    if (offset >= 4096) return NULL;

    if (offset == 0)
        snprintf(buf, bufSize, "%s", g_syms[best].name);
    else
        snprintf(buf, bufSize, "%s+0x%llX", g_syms[best].name, (unsigned long long)offset);

    return buf;
}

const char *DasmModuleName(UINT64 addr, char *buf, int bufSize) {
    for (int i = 0; i < g_modCount; i++) {
        if (addr >= g_mods[i].base && addr < g_mods[i].end) {
            strncpy(buf, g_mods[i].name, bufSize - 1);
            buf[bufSize - 1] = '\0';
            return buf;
        }
    }
    return NULL;
}

const char *DasmSymbolLookupImport(UINT64 slotAddr, char *buf, int bufSize) {
    if (!buf || bufSize <= 0 || !g_mods || g_modCount == 0 || !g_symProc) return NULL;

    HANDLE hProcess = g_symProc;
    for (int m = 0; m < g_modCount; m++) {
        if (slotAddr < g_mods[m].base || slotAddr >= g_mods[m].end) continue;

        UINT64 base = g_mods[m].base;
        BYTE hdrs[4096];
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)base,
                hdrs, sizeof(hdrs), &bytesRead) || bytesRead < 64)
            return NULL;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdrs;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
        if (dos->e_lfanew < 0 || dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > bytesRead)
            return NULL;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(hdrs + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;

        IMAGE_DATA_DIRECTORY impDir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir.VirtualAddress == 0 || impDir.Size == 0) return NULL;

        DWORD slotRva = (DWORD)(slotAddr - base);

        IMAGE_IMPORT_DESCRIPTOR iid;
        UINT64 descAddr = base + impDir.VirtualAddress;

        for (;;) {
            bytesRead = 0;
            if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)descAddr,
                    &iid, sizeof(iid), &bytesRead) || bytesRead < sizeof(iid))
                break;
            if (iid.FirstThunk == 0 && iid.OriginalFirstThunk == 0) break;

            DWORD iatStart = iid.FirstThunk;
            DWORD hintRva  = iid.OriginalFirstThunk ? iid.OriginalFirstThunk : iid.FirstThunk;

            if (slotRva >= iatStart) {
                DWORD idx = (slotRva - iatStart) / 8;
                if (idx < 4096 && (slotRva - iatStart) % 8 == 0) {
                    UINT64 hintEntry = 0;
                    UINT64 hintAddr  = base + hintRva + idx * 8;
                    bytesRead = 0;
                    if (ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)hintAddr,
                            &hintEntry, sizeof(hintEntry), &bytesRead) &&
                        bytesRead == sizeof(hintEntry)) {
                        if (hintEntry & ((UINT64)1 << 63)) {
                            snprintf(buf, bufSize, "ord#%llu",
                                (unsigned long long)(hintEntry & 0xFFFF));
                            return buf;
                        }
                        UINT64 nameAddr = base + (DWORD)hintEntry + 2;
                        char nameBuf[128] = {0};
                        bytesRead = 0;
                        if (ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)nameAddr,
                                nameBuf, sizeof(nameBuf) - 1, &bytesRead) && bytesRead > 0) {
                            nameBuf[sizeof(nameBuf) - 1] = '\0';
                            strncpy(buf, nameBuf, bufSize - 1);
                            buf[bufSize - 1] = '\0';
                            return buf;
                        }
                    }
                }
            }
            descAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
        return NULL;
    }
    return NULL;
}

BOOL DasmSymbolFind(const char *query, UINT64 *outAddr) {
    if (!query || !outAddr || !g_syms || g_symCount == 0) return FALSE;

    const char *bang = strchr(query, '!');
    const char *symName = bang ? bang + 1 : query;
    char modFilter[64] = {0};

    if (bang) {
        int mlen = (int)(bang - query);
        if (mlen > 63) mlen = 63;
        memcpy(modFilter, query, mlen);
        modFilter[mlen] = '\0';
    }

    for (int i = 0; i < g_symCount; i++) {
        if (_stricmp(g_syms[i].name, symName) != 0) continue;

        if (modFilter[0]) {
            BOOL inMod = FALSE;
            for (int m = 0; m < g_modCount; m++) {
                if (g_syms[i].addr >= g_mods[m].base &&
                    g_syms[i].addr <  g_mods[m].end) {
                    if (_strnicmp(g_mods[m].name, modFilter, strlen(modFilter)) == 0)
                        inMod = TRUE;
                    break;
                }
            }
            if (!inMod) continue;
        }

        *outAddr = g_syms[i].addr;
        return TRUE;
    }
    return FALSE;
}

void DasmSymbolFree(void) {
    free(g_syms); g_syms = NULL; g_symCount = 0; g_symCap = 0;
    free(g_mods); g_mods = NULL; g_modCount = 0; g_modCap = 0;
    g_symProc = NULL;
}
