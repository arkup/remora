#ifndef DASM_SYMBOLS_H
#define DASM_SYMBOLS_H

#include <windows.h>

/* Build symbol table from target process exports. */
void DasmSymbolBuild(HANDLE hProcess);

/* Lookup nearest symbol <= addr.
   Writes "Name" or "Name+0xNN" into buf.
   Returns buf on success, NULL if no match or offset >= 4096. */
const char *DasmSymbolLookup(UINT64 addr, char *buf, int bufSize);

/* Returns base module name for addr (e.g. "ntdll.dll"), or NULL. */
const char *DasmModuleName(UINT64 addr, char *buf, int bufSize);

/* Lookup IAT import name by slot address.
   Given a memory address that falls inside a module's IAT, parses the PE
   import directory to find the import name (e.g. "InternetReadFile").
   Returns buf on success, NULL if the slot is not in any known IAT. */
const char *DasmSymbolLookupImport(UINT64 slotAddr, char *buf, int bufSize);

/* Reverse lookup: find address by name.
   Accepts "Name" or "module!Name" (case-insensitive).
   Returns TRUE and writes addr on success. */
BOOL DasmSymbolFind(const char *query, UINT64 *outAddr);

void DasmSymbolFree(void);

#endif
