#ifndef MEMVIEW_H
#define MEMVIEW_H

#include <windows.h>

void MemViewCreate(HWND hParent, HANDLE hProcess);
void MemViewOpenAt(HWND hParent, HANDLE hProcess, UINT64 addr);
void MemViewGoto(UINT64 address);
void MemViewClose(void);
void StackViewOpen(HWND hwndParent, HANDLE hProcess, HANDLE hThread);
void ModuleMapOpen(HWND hwndParent, HANDLE hProcess);

#endif
