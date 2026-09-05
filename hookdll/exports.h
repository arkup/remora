#ifndef EXPORTS_H
#define EXPORTS_H

#include <windows.h>

typedef struct {
    const char *name;
    WORD ordinal;
    void *address;
    BOOL is_forwarded;
} ExportEntry;

typedef struct {
    ExportEntry *entries;
    DWORD count;
    HMODULE hModule;
} ExportTable;

BOOL ExportTableParse(ExportTable *tbl, HMODULE hMod);
void ExportTableFree(ExportTable *tbl);
void *ExportTableFind(ExportTable *tbl, const char *name);

#endif
