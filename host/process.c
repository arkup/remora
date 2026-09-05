#include "process.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winternl.h>

static BOOL BuildEnvBlock(char *out, DWORD out_size) {
    char *src = GetEnvironmentStrings();
    if (!src) return FALSE;

    char *p = src;
    DWORD offset = 0;

    while (*p) {
        DWORD len = (DWORD)strlen(p) + 1;
        if (offset + len >= out_size - 256) break;
        memcpy(out + offset, p, len);
        offset += len;
        p += len;
    }
    FreeEnvironmentStrings(src);

    char extra[64];
    snprintf(extra, sizeof(extra), "REMORA_HOST_PID=%u", GetCurrentProcessId());
    DWORD extra_len = (DWORD)strlen(extra) + 1;
    memcpy(out + offset, extra, extra_len);
    offset += extra_len;

    out[offset] = '\0';
    return TRUE;
}

BOOL ProcessCreate(TargetProcess *proc, const char *exe_path, const char *args) {
    memset(proc, 0, sizeof(*proc));
    strncpy(proc->exe_path, exe_path, MAX_PATH - 1);

    char cmdline[4096];
    if (args && args[0])
        snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", exe_path, args);
    else
        snprintf(cmdline, sizeof(cmdline), "\"%s\"", exe_path);

    char exe_dir[MAX_PATH] = "";
    {
        char full[MAX_PATH];
        if (GetFullPathNameA(exe_path, MAX_PATH, full, NULL)) {
            strncpy(exe_dir, full, MAX_PATH - 1);
            char *last_sep = strrchr(exe_dir, '\\');
            if (last_sep) *last_sep = '\0';
            else exe_dir[0] = '\0';
        }
    }

    char *env_block = (char *)malloc(65536);
    if (!env_block) return FALSE;
    BuildEnvBlock(env_block, 65536);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    BOOL ok = CreateProcessA(exe_path, cmdline, NULL, NULL, FALSE,
        CREATE_SUSPENDED, env_block, exe_dir[0] ? exe_dir : NULL, &si, &pi);

    free(env_block);
    if (!ok) return FALSE;

    proc->hProcess = pi.hProcess;
    proc->hThread = pi.hThread;
    proc->pid = pi.dwProcessId;
    proc->tid = pi.dwThreadId;
    proc->suspended = TRUE;

    return TRUE;
}

BOOL ProcessInjectDll(TargetProcess *proc, const char *dll_path) {
    SIZE_T path_len = strlen(dll_path) + 1;

    DWORD attrib = GetFileAttributesA(dll_path);
    if (attrib == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    void *remote_buf = VirtualAllocEx(proc->hProcess, NULL, path_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) return FALSE;

    if (!WriteProcessMemory(proc->hProcess, remote_buf, dll_path, path_len, NULL)) {
        VirtualFreeEx(proc->hProcess, remote_buf, 0, MEM_RELEASE);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

    DWORD queued = QueueUserAPC((PAPCFUNC)pLoadLibrary, proc->hThread,
        (ULONG_PTR)remote_buf);

    if (!queued) {
        VirtualFreeEx(proc->hProcess, remote_buf, 0, MEM_RELEASE);
        return FALSE;
    }

    proc->dll_loaded = TRUE;
    proc->remote_dll_path = remote_buf;
    return TRUE;
}

BOOL ProcessPatchEntryPoint(TargetProcess *proc) {
    BYTE headers[4096];
    SIZE_T rd;
    UINT_PTR base = 0;

    PROCESS_BASIC_INFORMATION pbi;
    typedef NTSTATUS (NTAPI *fn_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    fn_NtQueryInformationProcess pNtQIP = (fn_NtQueryInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!pNtQIP) {
        LoggerAppend("[!] OEP-patch: NtQueryInformationProcess not found\n", LOG_COLOR_BLOCK);
        return FALSE;
    }

    NTSTATUS st = pNtQIP(proc->hProcess, 0, &pbi, sizeof(pbi), NULL);
    if (st != 0) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] OEP-patch: NtQIP failed (NTSTATUS 0x%08X)\n", (unsigned)st);
        return FALSE;
    }

    if (!ReadProcessMemory(proc->hProcess, (BYTE *)pbi.PebBaseAddress + 0x10,
                           &base, sizeof(base), &rd)) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] OEP-patch: RPM PEB.ImageBaseAddress failed (PEB=%p, err=%u)\n",
            pbi.PebBaseAddress, GetLastError());
        return FALSE;
    }

    if (base == 0) {
        LoggerAppend("[!] OEP-patch: PEB.ImageBaseAddress is NULL\n", LOG_COLOR_BLOCK);
        return FALSE;
    }

    if (!ReadProcessMemory(proc->hProcess, (void *)base, headers, sizeof(headers), &rd)) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] OEP-patch: RPM PE headers failed (base=0x%llX, err=%u)\n",
            (unsigned long long)base, GetLastError());
        return FALSE;
    }

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)headers;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] OEP-patch: bad DOS signature 0x%04X at base 0x%llX\n",
            dos->e_magic, (unsigned long long)base);
        return FALSE;
    }
    if (dos->e_lfanew < 0 || (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(headers)) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] OEP-patch: e_lfanew out of range (%d)\n", dos->e_lfanew);
        return FALSE;
    }

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(headers + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] OEP-patch: bad NT signature 0x%08X\n", (unsigned)nt->Signature);
        return FALSE;
    }

    proc->image_base = base;
    proc->image_size = nt->OptionalHeader.SizeOfImage;
    proc->ep_addr = base + nt->OptionalHeader.AddressOfEntryPoint;

    if (!ReadProcessMemory(proc->hProcess, (void *)proc->ep_addr,
                           proc->ep_orig, 4, &rd)) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] OEP-patch: RPM entry point failed (ep=0x%llX, err=%u)\n",
            (unsigned long long)proc->ep_addr, GetLastError());
        return FALSE;
    }

    BYTE jmp_self[2] = { 0xEB, 0xFE };
    if (!WriteProcessMemory(proc->hProcess, (void *)proc->ep_addr, jmp_self, 2, &rd)) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] OEP-patch: WPM entry point failed (ep=0x%llX, err=%u)\n",
            (unsigned long long)proc->ep_addr, GetLastError());
        return FALSE;
    }

    FlushInstructionCache(proc->hProcess, (void *)proc->ep_addr, 2);

    BYTE verify[2] = {0};
    if (ReadProcessMemory(proc->hProcess, (void *)proc->ep_addr, verify, 2, &rd)) {
        if (verify[0] != 0xEB || verify[1] != 0xFE) {
            LoggerAppendFmt(LOG_COLOR_BLOCK,
                "[!] OEP-patch: read-back mismatch at 0x%llX -- got %02X %02X, expected EB FE\n",
                (unsigned long long)proc->ep_addr, verify[0], verify[1]);
            return FALSE;
        }
    }

    proc->ep_patched = TRUE;
    LoggerAppendFmt(LOG_COLOR_VERBOSE, "[*] OEP-patch: OK at 0x%llX (orig: %02X %02X)\n",
        (unsigned long long)proc->ep_addr, proc->ep_orig[0], proc->ep_orig[1]);
    return TRUE;
}

BOOL ProcessRestoreEntryPoint(TargetProcess *proc) {
    if (!proc->ep_patched) return FALSE;

    SIZE_T wr;
    if (!WriteProcessMemory(proc->hProcess, (void *)proc->ep_addr,
                            proc->ep_orig, 2, &wr))
        return FALSE;

    FlushInstructionCache(proc->hProcess, (void *)proc->ep_addr, 2);
    proc->ep_patched = FALSE;
    return TRUE;
}

BOOL ProcessResume(TargetProcess *proc) {
    if (!proc->suspended) return FALSE;
    if (ResumeThread(proc->hThread) == (DWORD)-1) return FALSE;
    proc->suspended = FALSE;
    return TRUE;
}

BOOL ProcessSuspendAll(TargetProcess *proc) {
    if (!proc->hProcess) return FALSE;
    typedef NTSTATUS (NTAPI *fn_NtSuspendProcess)(HANDLE);
    fn_NtSuspendProcess pSuspend = (fn_NtSuspendProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");
    if (!pSuspend) return FALSE;
    if (pSuspend(proc->hProcess) != 0) return FALSE;
    proc->user_suspended = TRUE;
    return TRUE;
}

BOOL ProcessResumeAll(TargetProcess *proc) {
    if (!proc->hProcess) return FALSE;
    typedef NTSTATUS (NTAPI *fn_NtResumeProcess)(HANDLE);
    fn_NtResumeProcess pResume = (fn_NtResumeProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeProcess");
    if (!pResume) return FALSE;
    if (pResume(proc->hProcess) != 0) return FALSE;
    proc->user_suspended = FALSE;
    return TRUE;
}

BOOL ProcessTerminate(TargetProcess *proc) {
    if (!proc->hProcess) return FALSE;
    return TerminateProcess(proc->hProcess, 1);
}

BOOL ProcessIsAlive(TargetProcess *proc) {
    if (!proc->hProcess) return FALSE;
    DWORD code;
    return GetExitCodeProcess(proc->hProcess, &code) && code == STILL_ACTIVE;
}

void ProcessClose(TargetProcess *proc) {
    if (proc->remote_dll_path && proc->hProcess) {
        VirtualFreeEx(proc->hProcess, proc->remote_dll_path, 0, MEM_RELEASE);
        proc->remote_dll_path = NULL;
    }
    if (proc->hThread) { CloseHandle(proc->hThread); proc->hThread = NULL; }
    if (proc->hProcess) { CloseHandle(proc->hProcess); proc->hProcess = NULL; }
}
