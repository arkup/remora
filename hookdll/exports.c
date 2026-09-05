#include "exports.h"
#include <stdlib.h>
#include <string.h>

BOOL ExportTableParse(ExportTable *tbl, HMODULE hMod) {
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

    tbl->entries = (ExportEntry *)malloc(exp->NumberOfNames * sizeof(ExportEntry));
    if (!tbl->entries) return FALSE;

    tbl->count = 0;
    tbl->hModule = hMod;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        ExportEntry *e = &tbl->entries[tbl->count];
        e->name = (const char *)(base + names[i]);
        e->ordinal = ordinals[i] + (WORD)exp->Base;
        e->address = base + funcs[ordinals[i]];
        e->is_forwarded = (funcs[ordinals[i]] >= export_rva &&
                           funcs[ordinals[i]] < export_rva + export_size);
        tbl->count++;
    }

    return TRUE;
}

void ExportTableFree(ExportTable *tbl) {
    if (tbl->entries) {
        free(tbl->entries);
        tbl->entries = NULL;
    }
    tbl->count = 0;
}

void *ExportTableFind(ExportTable *tbl, const char *name) {
    for (DWORD i = 0; i < tbl->count; i++) {
        if (!tbl->entries[i].is_forwarded && strcmp(tbl->entries[i].name, name) == 0)
            return tbl->entries[i].address;
    }
    return NULL;
}
