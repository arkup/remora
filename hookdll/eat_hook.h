#ifndef EAT_HOOK_H
#define EAT_HOOK_H

#include <windows.h>
#include "stubgen.h"

typedef struct {
    HMODULE hModule;
    char dll_name[64];
    DWORD *pAddressOfFunctions;
    DWORD *pOriginalRVAs;
    DWORD num_hooked;
} EatHookContext;

BOOL EatHookInit(void);
BOOL EatHookModule(HMODULE hMod, const char *dll_name);
void EatHookFinalize(void);
void EatHookCommit(void);
void EatHookPatchModuleIAT(HMODULE hMod);
void EatHookPatchIATs(void);
void EatHookPatchIATsInline(void);
DWORD EatHookPatchIATsByName(HMODULE hMod);
void EatHookPatchAllIATsByName(void);
void *EatHookGetOriginal(DWORD hook_id);
void *EatHookSetOriginal(DWORD hook_id, void *addr);
DWORD EatHookGetCount(void);
DWORD EatHookGetOverflowCount(void);
void EatHookPatchNewModule(HMODULE hMod, const char *dll_name);

#endif
