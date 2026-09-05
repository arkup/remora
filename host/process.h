#ifndef PROCESS_H
#define PROCESS_H

#include <windows.h>

typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD pid;
    DWORD tid;
    BOOL suspended;
    BOOL user_suspended;
    BOOL dll_loaded;
    void *remote_dll_path;
    BOOL ep_patched;
    UINT64 ep_addr;
    UINT64 image_base;
    DWORD  image_size;
    BYTE ep_orig[4];
    char exe_path[MAX_PATH];
} TargetProcess;

BOOL ProcessCreate(TargetProcess *proc, const char *exe_path, const char *args);
BOOL ProcessInjectDll(TargetProcess *proc, const char *dll_path);
BOOL ProcessPatchEntryPoint(TargetProcess *proc);
BOOL ProcessRestoreEntryPoint(TargetProcess *proc);
BOOL ProcessResume(TargetProcess *proc);
BOOL ProcessSuspendAll(TargetProcess *proc);
BOOL ProcessResumeAll(TargetProcess *proc);
BOOL ProcessTerminate(TargetProcess *proc);
BOOL ProcessIsAlive(TargetProcess *proc);
void ProcessClose(TargetProcess *proc);

#endif
