#ifndef DASM_H
#define DASM_H

#include <windows.h>

void DasmOpen(HWND hParent, HANDLE hProcess);
void DasmGotoAddress(UINT64 addr);
void DasmClose(void);

#endif
