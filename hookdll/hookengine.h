#ifndef HOOKENGINE_H
#define HOOKENGINE_H

#include <windows.h>

#define HOOK_SKIP_BYTES 0

typedef struct {
    void *target_func;
    void *hook_func;
    void *trampoline;
    BYTE *hook_site;
    DWORD hook_site_offset;
    DWORD displaced_size;
} InlineHook;

BOOL HookEngineInit(void);
BOOL HookEngineInstall(InlineHook *hook, void *target, void *handler);
BOOL HookEngineRemove(InlineHook *hook);
void *HookEngineGetOriginal(InlineHook *hook);

void *AllocateNearby(void *target, SIZE_T size);

#endif
