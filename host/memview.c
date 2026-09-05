#include <windows.h>
#include <commdlg.h>
#include <psapi.h>
#include <stdio.h>
#include <ctype.h>
#include "memview.h"
#include "logger.h"
#include "dasmWnd/dasm.h"

/* ------------------------------------------------------------------ */
/* Remote process state                                                 */
/* ------------------------------------------------------------------ */

static HANDLE g_remoteProcess = NULL;
static HANDLE g_remoteThread  = NULL;

/* ------------------------------------------------------------------ */
/* Memory Viewer - hex dump with edit, db/dd/dq, scroll, goto           */
/* ------------------------------------------------------------------ */

#define MV_BYTES_PER_ROW 16
#define MV_ADDR_CHARS    18   /* "0000000000000000  " */

typedef enum { MV_BYTE, MV_DWORD, MV_QWORD } MvMode;

static const char* MV_CLASS = "RemoraMemView";
static HWND  g_mvHwnd     = NULL;
static HWND  g_mvHexView  = NULL;
static HWND  g_mvGotoEdit = NULL;
static HWND  g_mvGotoBtn  = NULL;
static HWND  g_mvModeCombo = NULL;
static HWND  g_mvStatusBar = NULL;
static HFONT g_mvFont     = NULL;

static UINT_PTR g_mvBaseAddr  = 0;
static UINT_PTR g_mvCursorOff = 0;
static MvMode   g_mvMode     = MV_BYTE;
static int      g_mvRowCount = 0;
static int      g_mvCharW    = 8;
static int      g_mvCharH    = 16;
static BOOL     g_mvEditing  = FALSE;
static BOOL     g_mvAsciiMode = FALSE;
static int      g_mvEditNibble = 0;
static UINT_PTR g_mvSelStart = 0;
static UINT_PTR g_mvSelEnd   = 0;
static BOOL     g_mvHasSel   = FALSE;

#define MV_SNAP_MAX_BYTES (256 * MV_BYTES_PER_ROW)
static BYTE     g_mvSnapBytes[MV_SNAP_MAX_BYTES];
static BOOL     g_mvSnapValid[MV_SNAP_MAX_BYTES];
static BOOL     g_mvSnapChanged[MV_SNAP_MAX_BYTES];
static UINT_PTR g_mvSnapBase = 0;
static int      g_mvSnapRows = 0;
static BOOL     g_mvSnapReady = FALSE;

#define IDM_MV_COPY        5001
#define IDM_MV_COPY_ADDR   5002
#define IDM_MV_SELECT_ALL  5003
#define IDM_MV_DISASM      5004
#define IDM_MV_DUMP        5005

#define IDC_MV_GOTO_EDIT 3001
#define IDC_MV_GOTO_BTN  3002
#define IDC_MV_MODE      3003
#define IDC_MV_DUMP_BTN  3004

/* ------------------------------------------------------------------ */
/* Safe memory read/write via ReadProcessMemory/WriteProcessMemory      */
/* ------------------------------------------------------------------ */

static BOOL SafeReadByte(UINT_PTR addr, BYTE* out)
{
    if (!g_remoteProcess) return FALSE;
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(g_remoteProcess, (LPCVOID)addr, out, 1, &bytesRead) && bytesRead == 1;
}

static BOOL SafeWriteByte(UINT_PTR addr, BYTE val)
{
    if (!g_remoteProcess) return FALSE;
    DWORD oldProt;
    VirtualProtectEx(g_remoteProcess, (LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T bytesWritten = 0;
    BOOL ok = WriteProcessMemory(g_remoteProcess, (LPVOID)addr, &val, 1, &bytesWritten) && bytesWritten == 1;
    VirtualProtectEx(g_remoteProcess, (LPVOID)addr, 1, oldProt, &oldProt);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Format a single row                                                  */
/* ------------------------------------------------------------------ */

static void FormatRow(UINT_PTR rowAddr, char* buf, int bufSize)
{
    char hex[128] = {0};
    char ascii[20] = {0};
    BYTE bytes[MV_BYTES_PER_ROW];
    BOOL readable[MV_BYTES_PER_ROW];

    for (int i = 0; i < MV_BYTES_PER_ROW; i++) {
        readable[i] = SafeReadByte(rowAddr + i, &bytes[i]);
    }

    int hpos = 0;
    switch (g_mvMode) {
    case MV_BYTE:
        for (int i = 0; i < MV_BYTES_PER_ROW; i++) {
            if (readable[i])
                hpos += sprintf(hex + hpos, "%02X ", bytes[i]);
            else
                hpos += sprintf(hex + hpos, "?? ");
            if (i == 7) hex[hpos++] = ' ';
        }
        break;
    case MV_DWORD:
        for (int i = 0; i < MV_BYTES_PER_ROW; i += 4) {
            BOOL allOk = readable[i] && readable[i+1] && readable[i+2] && readable[i+3];
            if (allOk) {
                DWORD val = *(DWORD*)&bytes[i];
                hpos += sprintf(hex + hpos, "%08X ", val);
            } else {
                hpos += sprintf(hex + hpos, "???????? ");
            }
        }
        break;
    case MV_QWORD:
        for (int i = 0; i < MV_BYTES_PER_ROW; i += 8) {
            BOOL allOk = TRUE;
            for (int j = 0; j < 8; j++) if (!readable[i+j]) allOk = FALSE;
            if (allOk) {
                UINT64 val = *(UINT64*)&bytes[i];
                hpos += sprintf(hex + hpos, "%016llX ", val);
            } else {
                hpos += sprintf(hex + hpos, "???????????????? ");
            }
        }
        break;
    }

    for (int i = 0; i < MV_BYTES_PER_ROW; i++) {
        if (readable[i] && bytes[i] >= 0x20 && bytes[i] < 0x7F)
            ascii[i] = (char)bytes[i];
        else
            ascii[i] = '.';
    }
    ascii[MV_BYTES_PER_ROW] = '\0';

    _snprintf(buf, bufSize, "%016llX  %-50s %s", (UINT64)rowAddr, hex, ascii);
    buf[bufSize - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* Snapshot and change detection                                        */
/* ------------------------------------------------------------------ */

static void UpdateSnapshot(void)
{
    int rows = g_mvRowCount;
    if (rows > 256) rows = 256;
    int totalBytes = rows * MV_BYTES_PER_ROW;

    if (g_mvBaseAddr != g_mvSnapBase || rows != g_mvSnapRows) {
        g_mvSnapBase = g_mvBaseAddr;
        g_mvSnapRows = rows;
        memset(g_mvSnapChanged, 0, sizeof(g_mvSnapChanged));

        for (int i = 0; i < totalBytes; i++) {
            g_mvSnapValid[i] = SafeReadByte(g_mvSnapBase + i, &g_mvSnapBytes[i]);
        }
        g_mvSnapReady = TRUE;
        return;
    }

    for (int i = 0; i < totalBytes; i++) {
        BYTE cur;
        BOOL readable = SafeReadByte(g_mvSnapBase + i, &cur);

        if (g_mvSnapReady) {
            if (readable && g_mvSnapValid[i]) {
                g_mvSnapChanged[i] = (cur != g_mvSnapBytes[i]);
            } else if (readable != g_mvSnapValid[i]) {
                g_mvSnapChanged[i] = TRUE;
            } else {
                g_mvSnapChanged[i] = FALSE;
            }
        }

        g_mvSnapBytes[i] = cur;
        g_mvSnapValid[i] = readable;
    }
    g_mvSnapReady = TRUE;
}

/* ------------------------------------------------------------------ */
/* Copy selection to clipboard                                          */
/* ------------------------------------------------------------------ */

static void CopySelectionToClipboard(HWND hwnd)
{
    UINT_PTR selLo, selHi;
    if (g_mvHasSel) {
        selLo = (g_mvSelStart < g_mvSelEnd) ? g_mvSelStart : g_mvSelEnd;
        selHi = (g_mvSelStart < g_mvSelEnd) ? g_mvSelEnd : g_mvSelStart;
    } else {
        selLo = (g_mvCursorOff / MV_BYTES_PER_ROW) * MV_BYTES_PER_ROW;
        selHi = selLo + MV_BYTES_PER_ROW - 1;
    }

    UINT_PTR startRow = selLo / MV_BYTES_PER_ROW;
    UINT_PTR endRow = selHi / MV_BYTES_PER_ROW;
    int rowCount = (int)(endRow - startRow + 1);

    int bufSize = rowCount * 100 + 1;
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!buf) return;

    int pos = 0;
    for (int r = 0; r < rowCount; r++) {
        UINT_PTR rowAddr = g_mvBaseAddr + (startRow + r) * MV_BYTES_PER_ROW;
        char line[256];
        FormatRow(rowAddr, line, sizeof(line));
        int len = (int)strlen(line);
        if (pos + len + 3 < bufSize) {
            memcpy(buf + pos, line, len);
            pos += len;
            buf[pos++] = '\r';
            buf[pos++] = '\n';
        }
    }
    buf[pos] = '\0';

    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, pos + 1);
        if (hMem) {
            char* p = (char*)GlobalLock(hMem);
            memcpy(p, buf, pos + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
    HeapFree(GetProcessHeap(), 0, buf);
}

static void CopyAddressToClipboard(HWND hwnd)
{
    char buf[32];
    UINT_PTR addr = g_mvBaseAddr + g_mvCursorOff;
    sprintf(buf, "0x%016llX", (UINT64)addr);

    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, strlen(buf) + 1);
        if (hMem) {
            char* p = (char*)GlobalLock(hMem);
            memcpy(p, buf, strlen(buf) + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

/* ------------------------------------------------------------------ */
/* Dump region to file                                                  */
/* ------------------------------------------------------------------ */

#define IDD_DUMP_START 200
#define IDD_DUMP_END   201

typedef struct { char startBuf[32]; char endBuf[32]; } DumpDlgData;

static INT_PTR CALLBACK DumpDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG: {
        DumpDlgData *d = (DumpDlgData *)lp;
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, (LONG_PTR)d);
        SetDlgItemTextA(hwnd, IDD_DUMP_START, d->startBuf);
        SetDlgItemTextA(hwnd, IDD_DUMP_END, d->endBuf);
        SendDlgItemMessageA(hwnd, IDD_DUMP_START, EM_SETSEL, 0, -1);
        SetFocus(GetDlgItem(hwnd, IDD_DUMP_START));
        return FALSE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            DumpDlgData *d = (DumpDlgData *)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
            GetDlgItemTextA(hwnd, IDD_DUMP_START, d->startBuf, sizeof(d->startBuf));
            GetDlgItemTextA(hwnd, IDD_DUMP_END, d->endBuf, sizeof(d->endBuf));
            EndDialog(hwnd, 1);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            EndDialog(hwnd, 0);
            return TRUE;
        }
        break;
    case WM_CLOSE:
        EndDialog(hwnd, 0);
        return TRUE;
    }
    return FALSE;
}

static WORD *DumpAlignDword(WORD *p) {
    ULONG_PTR addr = (ULONG_PTR)p;
    addr = (addr + 3) & ~(ULONG_PTR)3;
    return (WORD *)addr;
}

static BOOL ShowDumpDialog(HWND hParent, char *startBuf, char *endBuf) {
    DumpDlgData d;
    strncpy(d.startBuf, startBuf, 31); d.startBuf[31] = '\0';
    strncpy(d.endBuf, endBuf, 31); d.endBuf[31] = '\0';

    BYTE tmpl[1024];
    memset(tmpl, 0, sizeof(tmpl));
    WORD *p = (WORD *)tmpl;

    DLGTEMPLATE *hdr = (DLGTEMPLATE *)p;
    hdr->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU;
    hdr->cdit  = 5;
    hdr->cx    = 200;
    hdr->cy    = 70;
    p = (WORD *)(hdr + 1);
    *p++ = 0; *p++ = 0; *p++ = 0;

    /* Label "Start:" */
    p = DumpAlignDword(p);
    DLGITEMTEMPLATE *itm = (DLGITEMTEMPLATE *)p;
    itm->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    itm->x = 4; itm->y = 6; itm->cx = 28; itm->cy = 10;
    itm->id = (WORD)-1;
    p = (WORD *)(itm + 1);
    *p++ = 0xFFFF; *p++ = 0x0082;
    WCHAR *ws = (WCHAR *)p;
    ws[0]='S'; ws[1]='t'; ws[2]='a'; ws[3]='r'; ws[4]='t'; ws[5]=':'; ws[6]=0;
    p = (WORD *)(ws + 7);
    *p++ = 0;

    /* Edit: start address */
    p = DumpAlignDword(p);
    itm = (DLGITEMTEMPLATE *)p;
    itm->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL;
    itm->x = 34; itm->y = 4; itm->cx = 120; itm->cy = 13;
    itm->id = IDD_DUMP_START;
    p = (WORD *)(itm + 1);
    *p++ = 0xFFFF; *p++ = 0x0081;
    *p++ = 0; *p++ = 0;

    /* Label "End:" */
    p = DumpAlignDword(p);
    itm = (DLGITEMTEMPLATE *)p;
    itm->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    itm->x = 4; itm->y = 22; itm->cx = 28; itm->cy = 10;
    itm->id = (WORD)-1;
    p = (WORD *)(itm + 1);
    *p++ = 0xFFFF; *p++ = 0x0082;
    ws = (WCHAR *)p;
    ws[0]='E'; ws[1]='n'; ws[2]='d'; ws[3]=':'; ws[4]=0;
    p = (WORD *)(ws + 5);
    *p++ = 0;

    /* Edit: end address */
    p = DumpAlignDword(p);
    itm = (DLGITEMTEMPLATE *)p;
    itm->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL;
    itm->x = 34; itm->y = 20; itm->cx = 120; itm->cy = 13;
    itm->id = IDD_DUMP_END;
    p = (WORD *)(itm + 1);
    *p++ = 0xFFFF; *p++ = 0x0081;
    *p++ = 0; *p++ = 0;

    /* OK button */
    p = DumpAlignDword(p);
    itm = (DLGITEMTEMPLATE *)p;
    itm->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
    itm->x = 160; itm->y = 4; itm->cx = 34; itm->cy = 13;
    itm->id = IDOK;
    p = (WORD *)(itm + 1);
    *p++ = 0xFFFF; *p++ = 0x0080;
    ws = (WCHAR *)p;
    ws[0]='O'; ws[1]='K'; ws[2]=0;
    p = (WORD *)(ws + 3);
    *p++ = 0;

    INT_PTR ret = DialogBoxIndirectParamA(GetModuleHandleA(NULL),
        (DLGTEMPLATE *)tmpl, hParent, DumpDlgProc, (LPARAM)&d);

    if (ret == 1) {
        strncpy(startBuf, d.startBuf, 31); startBuf[31] = '\0';
        strncpy(endBuf, d.endBuf, 31); endBuf[31] = '\0';
        return TRUE;
    }
    return FALSE;
}

static UINT64 ParseHexInput(const char *s) {
    while (*s == ' ') s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    UINT64 v = 0;
    sscanf(s, "%llX", &v);
    return v;
}

static void DoDumpRegion(HWND hwnd) {
    char startBuf[32], endBuf[32];
    sprintf(startBuf, "%llX", (UINT64)g_mvBaseAddr);
    sprintf(endBuf, "%llX", (UINT64)(g_mvBaseAddr + (UINT_PTR)g_mvRowCount * MV_BYTES_PER_ROW));

    if (!ShowDumpDialog(hwnd, startBuf, endBuf)) return;

    UINT64 startAddr = ParseHexInput(startBuf);
    UINT64 endAddr   = ParseHexInput(endBuf);
    if (endAddr <= startAddr || !g_remoteProcess) return;
    UINT64 size = endAddr - startAddr;
    if (size > 256 * 1024 * 1024) {
        MessageBoxA(hwnd, "Region too large (max 256 MB).", "Dump", MB_OK | MB_ICONWARNING);
        return;
    }

    OPENFILENAMEA ofn = {0};
    char path[MAX_PATH];
    sprintf(path, "dump_%llX_%llX.bin",
        (unsigned long long)startAddr, (unsigned long long)endAddr);
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = hwnd;
    ofn.lpstrFilter = "Binary files (*.bin)\0*.bin\0All files (*.*)\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = "bin";
    if (!GetSaveFileNameA(&ofn)) return;

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[DUMP] Failed to create file: %s\n", path);
        return;
    }

    BYTE chunk[4096];
    UINT64 offset = 0;
    UINT64 written = 0;
    while (offset < size) {
        SIZE_T toRead = (size - offset > 4096) ? 4096 : (SIZE_T)(size - offset);
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(g_remoteProcess, (LPCVOID)(UINT_PTR)(startAddr + offset),
                chunk, toRead, &bytesRead) && bytesRead > 0) {
            DWORD bw = 0;
            WriteFile(hFile, chunk, (DWORD)bytesRead, &bw, NULL);
            written += bw;
        } else {
            memset(chunk, 0, toRead);
            DWORD bw = 0;
            WriteFile(hFile, chunk, (DWORD)toRead, &bw, NULL);
            written += bw;
        }
        offset += toRead;
    }
    CloseHandle(hFile);

    LoggerAppendFmt(LOG_COLOR_RETURN,
        "[DUMP] Saved %llu bytes: 0x%llX - 0x%llX -> %s\n",
        (unsigned long long)written,
        (unsigned long long)startAddr,
        (unsigned long long)endAddr, path);
}

/* ------------------------------------------------------------------ */
/* Paint the hex view                                                   */
/* ------------------------------------------------------------------ */

static void PaintHexView(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc;
    GetClientRect(hwnd, &rc);

    HFONT oldFont = (HFONT)SelectObject(hdc, g_mvFont);
    SetBkColor(hdc, RGB(0, 0, 0));
    SetTextColor(hdc, RGB(200, 200, 200));

    HBRUSH hBgBrush = CreateSolidBrush(RGB(0, 0, 0));
    FillRect(hdc, &rc, hBgBrush);
    DeleteObject(hBgBrush);

    g_mvRowCount = (rc.bottom - rc.top) / g_mvCharH;
    if (g_mvRowCount < 1) g_mvRowCount = 1;

    char lineBuf[256];
    for (int row = 0; row < g_mvRowCount; row++) {
        UINT_PTR rowAddr = g_mvBaseAddr + (UINT_PTR)row * MV_BYTES_PER_ROW;
        FormatRow(rowAddr, lineBuf, sizeof(lineBuf));

        int y = row * g_mvCharH;

        int contentW = 2 + (MV_ADDR_CHARS + 51 + MV_BYTES_PER_ROW) * g_mvCharW;
        UINT_PTR cursorRow = g_mvCursorOff / MV_BYTES_PER_ROW;
        BOOL isSelected = FALSE;
        if (g_mvHasSel) {
            UINT_PTR selLoRow = ((g_mvSelStart < g_mvSelEnd) ? g_mvSelStart : g_mvSelEnd) / MV_BYTES_PER_ROW;
            UINT_PTR selHiRow = ((g_mvSelStart < g_mvSelEnd) ? g_mvSelEnd : g_mvSelStart) / MV_BYTES_PER_ROW;
            if ((UINT_PTR)row >= selLoRow && (UINT_PTR)row <= selHiRow)
                isSelected = TRUE;
        }

        if (isSelected) {
            RECT hlrc = { 0, y, contentW, y + g_mvCharH };
            HBRUSH hHlBrush = CreateSolidBrush(RGB(50, 50, 100));
            FillRect(hdc, &hlrc, hHlBrush);
            DeleteObject(hHlBrush);
        } else if ((UINT_PTR)row == cursorRow) {
            RECT hlrc = { 0, y, contentW, y + g_mvCharH };
            HBRUSH hHlBrush = CreateSolidBrush(RGB(40, 40, 80));
            FillRect(hdc, &hlrc, hHlBrush);
            DeleteObject(hHlBrush);
        }

        SetBkMode(hdc, TRANSPARENT);

        SetTextColor(hdc, RGB(100, 180, 100));
        TextOutA(hdc, 2, y, lineBuf, MV_ADDR_CHARS);

        char* hexStart = lineBuf + MV_ADDR_CHARS;
        int hexLen = (int)strlen(hexStart);
        if (hexLen > 50) hexLen = 50;
        SetTextColor(hdc, RGB(200, 220, 255));
        TextOutA(hdc, 2 + MV_ADDR_CHARS * g_mvCharW, y, hexStart, hexLen);

        if ((int)strlen(lineBuf) > MV_ADDR_CHARS + 51) {
            char* asciiStart = lineBuf + MV_ADDR_CHARS + 51;
            SetTextColor(hdc, RGB(0, 200, 100));
            TextOutA(hdc, 2 + (MV_ADDR_CHARS + 51) * g_mvCharW, y, asciiStart, MV_BYTES_PER_ROW);
        }

        /* Overdraw changed bytes in red */
        int snapOff = row * MV_BYTES_PER_ROW;
        if (g_mvSnapReady) {
            int hexX = 2 + MV_ADDR_CHARS * g_mvCharW;
            int asciiX = 2 + (MV_ADDR_CHARS + 51) * g_mvCharW;
            char* asciiP = (strlen(lineBuf) > (size_t)(MV_ADDR_CHARS + 51)) ?
                           lineBuf + MV_ADDR_CHARS + 51 : NULL;

            for (int b = 0; b < MV_BYTES_PER_ROW; b++) {
                if (snapOff + b >= MV_SNAP_MAX_BYTES) break;
                if (!g_mvSnapChanged[snapOff + b]) continue;

                SetTextColor(hdc, RGB(255, 80, 80));

                if (g_mvMode == MV_BYTE) {
                    int charOff = b * 3 + (b >= 8 ? 1 : 0);
                    TextOutA(hdc, hexX + charOff * g_mvCharW, y,
                             lineBuf + MV_ADDR_CHARS + charOff, 2);
                }

                if (asciiP) {
                    TextOutA(hdc, asciiX + b * g_mvCharW, y, &asciiP[b], 1);
                }
            }

            if (g_mvMode == MV_DWORD) {
                for (int g = 0; g < MV_BYTES_PER_ROW; g += 4) {
                    BOOL any = FALSE;
                    for (int j = 0; j < 4; j++)
                        if (snapOff+g+j < MV_SNAP_MAX_BYTES && g_mvSnapChanged[snapOff+g+j]) any = TRUE;
                    if (any) {
                        int charOff = (g / 4) * 9;
                        SetTextColor(hdc, RGB(255, 80, 80));
                        TextOutA(hdc, hexX + charOff * g_mvCharW, y,
                                 lineBuf + MV_ADDR_CHARS + charOff, 8);
                    }
                }
            } else if (g_mvMode == MV_QWORD) {
                for (int g = 0; g < MV_BYTES_PER_ROW; g += 8) {
                    BOOL any = FALSE;
                    for (int j = 0; j < 8; j++)
                        if (snapOff+g+j < MV_SNAP_MAX_BYTES && g_mvSnapChanged[snapOff+g+j]) any = TRUE;
                    if (any) {
                        int charOff = (g / 8) * 17;
                        SetTextColor(hdc, RGB(255, 80, 80));
                        TextOutA(hdc, hexX + charOff * g_mvCharW, y,
                                 lineBuf + MV_ADDR_CHARS + charOff, 16);
                    }
                }
            }
        }

        /* Highlight edited byte cursor */
        if ((UINT_PTR)row == cursorRow && g_mvEditing) {
            int col = (int)(g_mvCursorOff % MV_BYTES_PER_ROW);
            RECT curRc;
            if (g_mvAsciiMode) {
                int asciiX = 2 + (MV_ADDR_CHARS + 51) * g_mvCharW;
                curRc.left = asciiX + col * g_mvCharW;
                curRc.right = curRc.left + g_mvCharW;
                curRc.top = y;
                curRc.bottom = y + g_mvCharH;
            } else {
                int hexCharOff = MV_ADDR_CHARS + col * 3 + (col >= 8 ? 1 : 0);
                curRc.left = 2 + hexCharOff * g_mvCharW;
                curRc.right = 2 + (hexCharOff + 2) * g_mvCharW;
                curRc.top = y;
                curRc.bottom = y + g_mvCharH;
            }
            HBRUSH hCurBrush = CreateSolidBrush(RGB(180, 60, 60));
            FrameRect(hdc, &curRc, hCurBrush);
            DeleteObject(hCurBrush);
        }
    }

    SelectObject(hdc, oldFont);
    EndPaint(hwnd, &ps);
}

/* ------------------------------------------------------------------ */
/* Hex view window proc                                                 */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK HexViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT:
        PaintHexView(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_MOUSEWHEEL: {
        short delta = (short)HIWORD(wParam);
        int lines = delta / WHEEL_DELTA * 3;
        INT_PTR newBase = (INT_PTR)g_mvBaseAddr - (INT_PTR)(lines * MV_BYTES_PER_ROW);
        if (newBase < 0) newBase = 0;
        g_mvBaseAddr = (UINT_PTR)newBase;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_KEYDOWN:
        if (GetKeyState(VK_CONTROL) & 0x8000) {
            if (wParam == 'C') {
                CopySelectionToClipboard(hwnd);
                return 0;
            }
            if (wParam == 'A') {
                g_mvSelStart = 0;
                g_mvSelEnd = (UINT_PTR)(g_mvRowCount - 1) * MV_BYTES_PER_ROW + MV_BYTES_PER_ROW - 1;
                g_mvHasSel = TRUE;
                InvalidateRect(hwnd, NULL, FALSE);
                return 0;
            }
        }
        switch (wParam) {
        case VK_DOWN:
            g_mvCursorOff += MV_BYTES_PER_ROW;
            if (g_mvCursorOff >= (UINT_PTR)g_mvRowCount * MV_BYTES_PER_ROW) {
                g_mvBaseAddr += MV_BYTES_PER_ROW;
                g_mvCursorOff -= MV_BYTES_PER_ROW;
            }
            g_mvEditNibble = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        case VK_UP:
            if (g_mvCursorOff >= MV_BYTES_PER_ROW) {
                g_mvCursorOff -= MV_BYTES_PER_ROW;
            } else if (g_mvBaseAddr >= MV_BYTES_PER_ROW) {
                g_mvBaseAddr -= MV_BYTES_PER_ROW;
            }
            g_mvEditNibble = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        case VK_LEFT:
            if (g_mvCursorOff > 0) g_mvCursorOff--;
            g_mvEditNibble = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        case VK_RIGHT:
            g_mvCursorOff++;
            if (g_mvCursorOff >= (UINT_PTR)g_mvRowCount * MV_BYTES_PER_ROW) {
                g_mvBaseAddr += MV_BYTES_PER_ROW;
                g_mvCursorOff -= MV_BYTES_PER_ROW;
            }
            g_mvEditNibble = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        case VK_PRIOR:
            if (g_mvBaseAddr >= (UINT_PTR)(g_mvRowCount * MV_BYTES_PER_ROW))
                g_mvBaseAddr -= (UINT_PTR)(g_mvRowCount * MV_BYTES_PER_ROW);
            else
                g_mvBaseAddr = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        case VK_NEXT:
            g_mvBaseAddr += (UINT_PTR)(g_mvRowCount * MV_BYTES_PER_ROW);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        case VK_HOME:
            g_mvCursorOff = 0;
            g_mvEditNibble = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        case VK_END:
            g_mvCursorOff = (UINT_PTR)(g_mvRowCount - 1) * MV_BYTES_PER_ROW;
            g_mvEditNibble = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        break;

    case WM_CHAR: {
        char ch = (char)wParam;

        if (g_mvAsciiMode && g_mvMode == MV_BYTE && ch >= 0x20 && ch < 0x7F) {
            g_mvEditing = TRUE;
            UINT_PTR editAddr = g_mvBaseAddr + g_mvCursorOff;
            if (!SafeWriteByte(editAddr, (BYTE)ch)) {
                LoggerAppendFmt(LOG_COLOR_WARN, "[MEM] Write failed at 0x%016llX\n", (UINT64)editAddr);
            }
            g_mvCursorOff++;
            if (g_mvCursorOff >= (UINT_PTR)g_mvRowCount * MV_BYTES_PER_ROW) {
                g_mvBaseAddr += MV_BYTES_PER_ROW;
                g_mvCursorOff -= MV_BYTES_PER_ROW;
            }
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        int nibVal = -1;
        if (ch >= '0' && ch <= '9') nibVal = ch - '0';
        else if (ch >= 'a' && ch <= 'f') nibVal = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') nibVal = ch - 'A' + 10;

        if (nibVal >= 0 && g_mvMode == MV_BYTE && !g_mvAsciiMode) {
            g_mvEditing = TRUE;
            UINT_PTR editAddr = g_mvBaseAddr + g_mvCursorOff;
            BYTE cur = 0;
            SafeReadByte(editAddr, &cur);

            if (g_mvEditNibble == 0) {
                cur = (BYTE)((nibVal << 4) | (cur & 0x0F));
                g_mvEditNibble = 1;
            } else {
                cur = (BYTE)((cur & 0xF0) | nibVal);
                g_mvEditNibble = 0;
                g_mvCursorOff++;
                if (g_mvCursorOff >= (UINT_PTR)g_mvRowCount * MV_BYTES_PER_ROW) {
                    g_mvBaseAddr += MV_BYTES_PER_ROW;
                    g_mvCursorOff -= MV_BYTES_PER_ROW;
                }
            }
            if (!SafeWriteByte(editAddr, cur)) {
                LoggerAppendFmt(LOG_COLOR_WARN, "[MEM] Write failed at 0x%016llX\n", (UINT64)editAddr);
            }
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        break;
    }

    case WM_LBUTTONDOWN: {
        SetFocus(hwnd);
        int x = (int)(short)LOWORD(lParam);
        int y = (int)(short)HIWORD(lParam);
        int row = y / g_mvCharH;
        if (row < 0) row = 0;
        if (row >= g_mvRowCount) row = g_mvRowCount - 1;

        int hexAreaStart = 2 + MV_ADDR_CHARS * g_mvCharW;
        int hexAreaEnd = hexAreaStart + 49 * g_mvCharW;
        int asciiAreaStart = 2 + (MV_ADDR_CHARS + 51) * g_mvCharW;
        int asciiAreaEnd = asciiAreaStart + MV_BYTES_PER_ROW * g_mvCharW;
        int col = (int)(g_mvCursorOff % MV_BYTES_PER_ROW);
        BOOL clickedAscii = FALSE;

        if (x >= asciiAreaStart && x < asciiAreaEnd) {
            col = (x - asciiAreaStart) / g_mvCharW;
            if (col < 0) col = 0;
            if (col >= MV_BYTES_PER_ROW) col = MV_BYTES_PER_ROW - 1;
            clickedAscii = TRUE;
        } else if (x >= hexAreaStart && x < hexAreaEnd && g_mvMode == MV_BYTE) {
            int xInHex = x - hexAreaStart;
            int charCol = xInHex / g_mvCharW;
            if (charCol < 24) {
                col = charCol / 3;
            } else {
                col = (charCol - 1) / 3;
            }
            if (col < 0) col = 0;
            if (col >= MV_BYTES_PER_ROW) col = MV_BYTES_PER_ROW - 1;
            clickedAscii = FALSE;
        }

        UINT_PTR newOff = (UINT_PTR)row * MV_BYTES_PER_ROW + col;

        if (GetKeyState(VK_SHIFT) & 0x8000) {
            if (!g_mvHasSel) g_mvSelStart = g_mvCursorOff;
            g_mvSelEnd = newOff;
            g_mvHasSel = TRUE;
        } else {
            g_mvHasSel = FALSE;
        }

        g_mvCursorOff = newOff;
        g_mvEditNibble = 0;
        g_mvAsciiMode = clickedAscii;
        g_mvEditing = TRUE;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    case WM_RBUTTONUP: {
        HMENU hCtx = CreatePopupMenu();
        AppendMenuA(hCtx, MF_STRING, IDM_MV_COPY, "Copy Rows\tCtrl+C");
        AppendMenuA(hCtx, MF_STRING, IDM_MV_COPY_ADDR, "Copy Address");
        AppendMenuA(hCtx, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hCtx, MF_STRING, IDM_MV_SELECT_ALL, "Select All\tCtrl+A");
        AppendMenuA(hCtx, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hCtx, MF_STRING, IDM_MV_DISASM, "Disassemble at cursor");
        AppendMenuA(hCtx, MF_STRING, IDM_MV_DUMP, "Dump Region...");
        POINT pt;
        GetCursorPos(&pt);
        int cmd = TrackPopupMenu(hCtx, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(hCtx);
        switch (cmd) {
        case IDM_MV_COPY:
            CopySelectionToClipboard(hwnd);
            break;
        case IDM_MV_COPY_ADDR:
            CopyAddressToClipboard(hwnd);
            break;
        case IDM_MV_SELECT_ALL:
            g_mvSelStart = 0;
            g_mvSelEnd = (UINT_PTR)(g_mvRowCount - 1) * MV_BYTES_PER_ROW + MV_BYTES_PER_ROW - 1;
            g_mvHasSel = TRUE;
            InvalidateRect(hwnd, NULL, FALSE);
            break;
        case IDM_MV_DISASM:
            if (g_remoteProcess) {
                DasmOpen(GetParent(hwnd), g_remoteProcess);
                DasmGotoAddress((UINT64)(g_mvBaseAddr + g_mvCursorOff));
            }
            break;
        case IDM_MV_DUMP:
            DoDumpRegion(GetParent(hwnd));
            break;
        }
        return 0;
    }

    case WM_SETFOCUS:
        g_mvEditing = TRUE;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_KILLFOCUS:
        g_mvEditing = FALSE;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Main memory viewer window proc                                       */
/* ------------------------------------------------------------------ */

static void DoGoto(HWND hwndParent)
{
    (void)hwndParent;
    char buf[64] = {0};
    GetWindowTextA(g_mvGotoEdit, buf, sizeof(buf));

    char* p = buf;
    while (*p == ' ') p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    UINT64 addr = 0;
    if (sscanf(p, "%llX", &addr) == 1) {
        g_mvBaseAddr = (UINT_PTR)addr;
        g_mvCursorOff = 0;
        g_mvEditNibble = 0;
        InvalidateRect(g_mvHexView, NULL, FALSE);
    }
}

static LRESULT CALLBACK MemViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = GetModuleHandle(NULL);
        HFONT hUIFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

        HWND hLbl = CreateWindowExA(0, "STATIC", "Goto:",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            4, 6, 40, 22, hwnd, NULL, hInst, NULL);

        g_mvGotoEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
            48, 4, 200, 24, hwnd, (HMENU)(INT_PTR)IDC_MV_GOTO_EDIT, hInst, NULL);

        g_mvGotoBtn = CreateWindowExA(0, "BUTTON", "Go",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            254, 4, 40, 24, hwnd, (HMENU)(INT_PTR)IDC_MV_GOTO_BTN, hInst, NULL);

        HWND hModeLbl = CreateWindowExA(0, "STATIC", "Mode:",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            310, 6, 40, 22, hwnd, NULL, hInst, NULL);

        g_mvModeCombo = CreateWindowExA(0, "COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_TABSTOP,
            354, 4, 70, 120, hwnd, (HMENU)(INT_PTR)IDC_MV_MODE, hInst, NULL);

        SendMessageA(g_mvModeCombo, CB_ADDSTRING, 0, (LPARAM)"db");
        SendMessageA(g_mvModeCombo, CB_ADDSTRING, 0, (LPARAM)"dd");
        SendMessageA(g_mvModeCombo, CB_ADDSTRING, 0, (LPARAM)"dq");
        SendMessageA(g_mvModeCombo, CB_SETCURSEL, 0, 0);

        HWND hDumpBtn = CreateWindowExA(0, "BUTTON", "Dump...",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            434, 4, 60, 24, hwnd, (HMENU)(INT_PTR)IDC_MV_DUMP_BTN, hInst, NULL);

        g_mvStatusBar = CreateWindowExA(0, "STATIC", "Address: 0x0000000000000000  Offset: 0x0000",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
            4, 0, 600, 20, hwnd, NULL, hInst, NULL);

        SendMessage(hLbl, WM_SETFONT, (WPARAM)hUIFont, TRUE);
        SendMessage(g_mvGotoEdit, WM_SETFONT, (WPARAM)hUIFont, TRUE);
        SendMessage(g_mvGotoBtn, WM_SETFONT, (WPARAM)hUIFont, TRUE);
        SendMessage(hModeLbl, WM_SETFONT, (WPARAM)hUIFont, TRUE);
        SendMessage(g_mvModeCombo, WM_SETFONT, (WPARAM)hUIFont, TRUE);
        SendMessage(hDumpBtn, WM_SETFONT, (WPARAM)hUIFont, TRUE);
        SendMessage(g_mvStatusBar, WM_SETFONT, (WPARAM)hUIFont, TRUE);

        g_mvFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        HDC hdc = GetDC(hwnd);
        HFONT old = (HFONT)SelectObject(hdc, g_mvFont);
        TEXTMETRICA tm;
        GetTextMetricsA(hdc, &tm);
        g_mvCharW = tm.tmAveCharWidth;
        g_mvCharH = tm.tmHeight;
        SelectObject(hdc, old);
        ReleaseDC(hwnd, hdc);

        static BOOL hexClassReg = FALSE;
        if (!hexClassReg) {
            WNDCLASSEXA wcHex = {0};
            wcHex.cbSize = sizeof(wcHex);
            wcHex.lpfnWndProc = HexViewProc;
            wcHex.hInstance = hInst;
            wcHex.hCursor = LoadCursor(NULL, IDC_IBEAM);
            wcHex.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
            wcHex.lpszClassName = "RemoraHexView";
            RegisterClassExA(&wcHex);
            hexClassReg = TRUE;
        }

        g_mvHexView = CreateWindowExA(WS_EX_CLIENTEDGE, "RemoraHexView", "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0, 32, 100, 100, hwnd, NULL, hInst, NULL);

        SetFocus(g_mvHexView);
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        int toolbarH = 32;
        int statusH = 22;
        if (g_mvHexView)
            MoveWindow(g_mvHexView, 0, toolbarH, rc.right, rc.bottom - toolbarH - statusH, TRUE);
        if (g_mvStatusBar)
            MoveWindow(g_mvStatusBar, 4, rc.bottom - statusH, rc.right - 8, statusH, TRUE);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_MV_GOTO_BTN:
            DoGoto(hwnd);
            return 0;
        case IDC_MV_DUMP_BTN:
            DoDumpRegion(hwnd);
            return 0;
        case IDM_MV_DUMP:
            DoDumpRegion(hwnd);
            return 0;
        case IDC_MV_MODE:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                int sel = (int)SendMessageA(g_mvModeCombo, CB_GETCURSEL, 0, 0);
                if (sel == 0) g_mvMode = MV_BYTE;
                else if (sel == 1) g_mvMode = MV_DWORD;
                else g_mvMode = MV_QWORD;
                InvalidateRect(g_mvHexView, NULL, FALSE);
            }
            return 0;
        }
        break;

    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE) {
            SendMessage(hwnd, WM_CLOSE, 0, 0);
            return 0;
        }
        if (wParam == VK_RETURN) {
            HWND hFocus = GetFocus();
            if (hFocus == g_mvGotoEdit) {
                DoGoto(hwnd);
                return 0;
            }
        }
        break;

    case WM_ACTIVATE:
        if (LOWORD(wParam) != WA_INACTIVE) {
            InvalidateRect(g_mvHexView, NULL, FALSE);
        }
        return 0;

    case WM_TIMER:
        if (wParam == 1) {
            UpdateSnapshot();
            char status[128];
            UINT_PTR curAddr = g_mvBaseAddr + g_mvCursorOff;
            BYTE val = 0;
            BOOL ok = SafeReadByte(curAddr, &val);
            _snprintf(status, sizeof(status),
                      " Addr: 0x%016llX  Offset: +0x%04llX  Value: %s  Mode: %s",
                      (UINT64)curAddr, (UINT64)g_mvCursorOff,
                      ok ? "OK" : "??",
                      g_mvMode == MV_BYTE ? "db" : (g_mvMode == MV_DWORD ? "dd" : "dq"));
            SetWindowTextA(g_mvStatusBar, status);
            InvalidateRect(g_mvHexView, NULL, FALSE);
        }
        return 0;

    case WM_CLOSE:
        KillTimer(hwnd, 1);
        DestroyWindow(hwnd);
        g_mvHwnd = NULL;
        return 0;

    case WM_DESTROY:
        if (g_mvFont) { DeleteObject(g_mvFont); g_mvFont = NULL; }
        g_mvHwnd = NULL;
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void MemViewOpenAt(HWND hwndParent, HANDLE hProcess, UINT64 addr)
{
    g_remoteProcess = hProcess;

    if (g_mvHwnd) {
        SetForegroundWindow(g_mvHwnd);
        if (addr) {
            g_mvBaseAddr = (UINT_PTR)addr;
            g_mvCursorOff = 0;
            g_mvEditNibble = 0;
            InvalidateRect(g_mvHexView, NULL, FALSE);
        }
        return;
    }

    static BOOL registered = FALSE;
    if (!registered) {
        WNDCLASSEXA wc = {0};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = MemViewWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = MV_CLASS;
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        RegisterClassExA(&wc);
        registered = TRUE;
    }

    if (addr) {
        g_mvBaseAddr = (UINT_PTR)addr;
    } else if (hProcess) {
        HMODULE hMod = NULL;
        DWORD needed = 0;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &needed) && hMod)
            g_mvBaseAddr = (UINT_PTR)hMod;
        else
            g_mvBaseAddr = 0;
    } else {
        g_mvBaseAddr = 0;
    }

    g_mvCursorOff = 0;
    g_mvEditNibble = 0;
    g_mvMode = MV_BYTE;
    g_mvSnapReady = FALSE;

    int w = 820, h = 520;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    g_mvHwnd = CreateWindowExA(
        0, MV_CLASS, "Memory Viewer",
        WS_OVERLAPPEDWINDOW,
        (screenW - w) / 2, (screenH - h) / 2, w, h,
        hwndParent, NULL, GetModuleHandle(NULL), NULL);

    if (g_mvHwnd) {
        ShowWindow(g_mvHwnd, SW_SHOW);
        UpdateWindow(g_mvHwnd);
        SetTimer(g_mvHwnd, 1, 500, NULL);
    }
}

void MemViewCreate(HWND hParent, HANDLE hProcess)
{
    MemViewOpenAt(hParent, hProcess, 0);
}

void MemViewGoto(UINT64 address)
{
    g_mvBaseAddr = (UINT_PTR)address;
    g_mvCursorOff = 0;
    g_mvEditNibble = 0;
    if (g_mvHexView)
        InvalidateRect(g_mvHexView, NULL, FALSE);
}

void MemViewClose(void)
{
    if (g_mvHwnd) {
        DestroyWindow(g_mvHwnd);
        g_mvHwnd = NULL;
    }
}

/* ================================================================== */
/* Stack View                                                           */
/* ================================================================== */

static HWND g_svHwnd = NULL;
static const char* SV_CLASS = "RemoraStackView";
static HANDLE g_svProcess = NULL;
static HANDLE g_svThread = NULL;

#define IDM_LB_COPY_ROW  6001
#define IDM_LB_COPY_VIEW 6002

static void ListBoxCopyRow(HWND hList)
{
    int sel = (int)SendMessageA(hList, LB_GETCURSEL, 0, 0);
    if (sel < 0) return;
    char text[512] = {0};
    SendMessageA(hList, LB_GETTEXT, sel, (LPARAM)text);
    int len = (int)strlen(text);
    if (OpenClipboard(hList)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len + 1);
        if (hMem) {
            char* p = (char*)GlobalLock(hMem);
            memcpy(p, text, len + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

static void ListBoxCopyAll(HWND hList)
{
    int count = (int)SendMessageA(hList, LB_GETCOUNT, 0, 0);
    if (count <= 0) return;

    int totalLen = 0;
    for (int i = 0; i < count; i++) {
        totalLen += (int)SendMessageA(hList, LB_GETTEXTLEN, i, 0) + 2;
    }

    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, totalLen + 1);
    if (!buf) return;

    int pos = 0;
    for (int i = 0; i < count; i++) {
        int len = (int)SendMessageA(hList, LB_GETTEXT, i, (LPARAM)(buf + pos));
        pos += len;
        buf[pos++] = '\r';
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';

    if (OpenClipboard(hList)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, pos + 1);
        if (hMem) {
            char* p = (char*)GlobalLock(hMem);
            memcpy(p, buf, pos + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
    HeapFree(GetProcessHeap(), 0, buf);
}

static void ShowListBoxContextMenu(HWND hList, LPARAM lParam)
{
    POINT pt;
    pt.x = (int)(short)LOWORD(lParam);
    pt.y = (int)(short)HIWORD(lParam);
    if (pt.x == -1 && pt.y == -1) GetCursorPos(&pt);

    HMENU hCtx = CreatePopupMenu();
    AppendMenuA(hCtx, MF_STRING, IDM_LB_COPY_ROW, "Copy Row");
    AppendMenuA(hCtx, MF_STRING, IDM_LB_COPY_VIEW, "Copy All");
    int cmd = TrackPopupMenu(hCtx, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, hList, NULL);
    DestroyMenu(hCtx);

    switch (cmd) {
    case IDM_LB_COPY_ROW:  ListBoxCopyRow(hList); break;
    case IDM_LB_COPY_VIEW: ListBoxCopyAll(hList); break;
    }
}

static void RefreshStackView(HWND hList)
{
    SendMessageA(hList, LB_RESETCONTENT, 0, 0);

    if (!g_svThread) {
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)"(no target thread)");
        return;
    }

    DWORD sc = SuspendThread(g_svThread);
    if (sc == (DWORD)-1) {
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)"(failed to suspend thread)");
        return;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(g_svThread, &ctx)) {
        ResumeThread(g_svThread);
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)"(GetThreadContext failed)");
        return;
    }

    char line[128];
    sprintf(line, "RIP = 0x%016llX", ctx.Rip);
    SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)line);
    sprintf(line, "RSP = 0x%016llX  RBP = 0x%016llX", ctx.Rsp, ctx.Rbp);
    SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)line);
    SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)"--- Stack (RSP) ---");

    UINT_PTR rsp = (UINT_PTR)ctx.Rsp;
    BYTE stackBuf[64 * 8];
    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(g_svProcess, (LPCVOID)rsp, stackBuf, sizeof(stackBuf), &bytesRead);
    int qwords = ok ? (int)(bytesRead / 8) : 0;

    for (int i = 0; i < 64; i++) {
        UINT_PTR addr = rsp + (UINT_PTR)i * 8;
        if (i < qwords) {
            UINT64 val = *(UINT64*)(stackBuf + i * 8);
            MEMORY_BASIC_INFORMATION mbi;
            BOOL isCode = FALSE;
            if (VirtualQueryEx(g_svProcess, (LPCVOID)(UINT_PTR)val, &mbi, sizeof(mbi))) {
                if (mbi.Protect == PAGE_EXECUTE ||
                    mbi.Protect == PAGE_EXECUTE_READ ||
                    mbi.Protect == PAGE_EXECUTE_READWRITE ||
                    mbi.Protect == PAGE_EXECUTE_WRITECOPY)
                    isCode = TRUE;
            }
            if (isCode)
                sprintf(line, "  RSP+%04X  [%016llX]  %016llX  <-- code", i * 8, (UINT64)addr, val);
            else
                sprintf(line, "  RSP+%04X  [%016llX]  %016llX", i * 8, (UINT64)addr, val);
        } else {
            sprintf(line, "  RSP+%04X  [%016llX]  ????????????????", i * 8, (UINT64)addr);
        }
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)line);
    }

    ResumeThread(g_svThread);
}

static LRESULT CALLBACK StackViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND hList = NULL;
    static HWND hRefreshBtn = NULL;
    static HFONT hMonoFont = NULL;

    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = GetModuleHandle(NULL);
        hMonoFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        hRefreshBtn = CreateWindowExA(0, "BUTTON", "Refresh",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            4, 4, 80, 26, hwnd, (HMENU)1, hInst, NULL);

        hList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS | LBS_NOTIFY,
            0, 34, 100, 100, hwnd, (HMENU)2, hInst, NULL);

        SendMessage(hList, WM_SETFONT, (WPARAM)hMonoFont, TRUE);

        HFONT hUI = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        SendMessage(hRefreshBtn, WM_SETFONT, (WPARAM)hUI, TRUE);

        RefreshStackView(hList);
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        if (hList) MoveWindow(hList, 0, 34, rc.right, rc.bottom - 34, TRUE);
        return 0;
    }

    case WM_CONTEXTMENU:
        if ((HWND)wParam == hList) {
            ShowListBoxContextMenu(hList, lParam);
            return 0;
        }
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            RefreshStackView(hList);
            return 0;
        }
        if (LOWORD(wParam) == 2 && HIWORD(wParam) == LBN_DBLCLK) {
            int sel = (int)SendMessageA(hList, LB_GETCURSEL, 0, 0);
            if (sel >= 0) {
                char text[256] = {0};
                SendMessageA(hList, LB_GETTEXT, sel, (LPARAM)text);

                /* H3: "<-- code" line -- open disassembly at the stack VALUE */
                if (strstr(text, "<-- code")) {
                    /* Format: "  RSP+XXXX  [STACKADDR]  CODEVALUE  <-- code"
                       The code value is the third 16-hex-digit run */
                    UINT64 val = 0;
                    int hexRuns = 0;
                    for (int i = 0; text[i] && hexRuns < 3; i++) {
                        int j = 0;
                        while (isxdigit((unsigned char)text[i + j])) j++;
                        if (j >= 16) {
                            if (++hexRuns == 3)
                                sscanf(text + i, "%16I64x", &val);
                            i += j - 1;
                        }
                    }
                    if (val && g_svProcess) {
                        DasmOpen(GetParent(hwnd), g_svProcess);
                        DasmGotoAddress(val);
                    }
                    return 0;
                }

                /* H3: "RIP = 0x..." line -- open disassembly at RIP */
                if (strncmp(text, "RIP", 3) == 0) {
                    const char *eq = strchr(text, '=');
                    if (eq) {
                        const char *p = eq + 2;
                        if (p[0]=='0' && (p[1]=='x'||p[1]=='X')) p += 2;
                        UINT64 rip = 0;
                        sscanf(p, "%16I64x", &rip);
                        if (rip && g_svProcess) {
                            DasmOpen(GetParent(hwnd), g_svProcess);
                            DasmGotoAddress(rip);
                        }
                    }
                    return 0;
                }

                /* Default: open memview at stack address */
                char *bracket = strchr(text, '[');
                if (bracket) {
                    UINT64 addr = 0;
                    if (sscanf(bracket + 1, "%llX", &addr) == 1)
                        MemViewOpenAt(GetParent(hwnd), g_svProcess, addr);
                }
            }
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        g_svHwnd = NULL;
        return 0;

    case WM_DESTROY:
        if (hMonoFont) { DeleteObject(hMonoFont); hMonoFont = NULL; }
        hList = NULL;
        g_svHwnd = NULL;
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

void StackViewOpen(HWND hwndParent, HANDLE hProcess, HANDLE hThread)
{
    g_svProcess = hProcess;
    g_svThread = hThread;

    if (g_svHwnd) {
        SetForegroundWindow(g_svHwnd);
        return;
    }

    static BOOL registered = FALSE;
    if (!registered) {
        WNDCLASSEXA wc = {0};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = StackViewWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = SV_CLASS;
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        RegisterClassExA(&wc);
        registered = TRUE;
    }

    int w = 700, h = 500;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    g_svHwnd = CreateWindowExA(0, SV_CLASS, "Stack View",
        WS_OVERLAPPEDWINDOW,
        (screenW - w) / 2, (screenH - h) / 2, w, h,
        hwndParent, NULL, GetModuleHandle(NULL), NULL);

    if (g_svHwnd) {
        ShowWindow(g_svHwnd, SW_SHOW);
        UpdateWindow(g_svHwnd);
    }
}

/* ================================================================== */
/* Module Map                                                           */
/* ================================================================== */

static HWND g_mmHwnd = NULL;
static const char* MM_CLASS = "RemoraModuleMap";
static HANDLE g_mmProcess = NULL;

static void RefreshModuleMap(HWND hList)
{
    SendMessageA(hList, LB_RESETCONTENT, 0, 0);

    char header[128];
    sprintf(header, "%-18s %-18s %-10s  %s", "Base", "End", "Size", "Module");
    SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)header);
    SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)"----------------------------------------------------------------------");

    if (!g_mmProcess) {
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)"(no target process)");
        return;
    }

    HMODULE hMods[512];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(g_mmProcess, hMods, sizeof(hMods), &needed, LIST_MODULES_ALL))
        return;

    int count = needed / sizeof(HMODULE);
    if (count > 512) count = 512;

    for (int i = 0; i < count; i++) {
        MODULEINFO mi;
        if (!GetModuleInformation(g_mmProcess, hMods[i], &mi, sizeof(mi)))
            continue;

        char name[MAX_PATH] = {0};
        GetModuleFileNameExA(g_mmProcess, hMods[i], name, MAX_PATH);
        char* slash = strrchr(name, '\\');
        if (slash) memmove(name, slash + 1, strlen(slash + 1) + 1);

        UINT_PTR base = (UINT_PTR)mi.lpBaseOfDll;
        UINT_PTR end = base + mi.SizeOfImage;
        char line[256];
        sprintf(line, "0x%016llX  0x%016llX  %8lluK  %s",
                (UINT64)base, (UINT64)end,
                (UINT64)(mi.SizeOfImage / 1024), name);
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)line);
    }
}

static LRESULT CALLBACK ModuleMapWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND hList = NULL;
    static HWND hRefreshBtn = NULL;
    static HFONT hMonoFont = NULL;

    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = GetModuleHandle(NULL);
        hMonoFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        hRefreshBtn = CreateWindowExA(0, "BUTTON", "Refresh",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            4, 4, 80, 26, hwnd, (HMENU)1, hInst, NULL);

        hList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS | LBS_NOTIFY,
            0, 34, 100, 100, hwnd, (HMENU)2, hInst, NULL);

        SendMessage(hList, WM_SETFONT, (WPARAM)hMonoFont, TRUE);
        SendMessageA(hList, LB_SETHORIZONTALEXTENT, 1200, 0);

        HFONT hUI = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        SendMessage(hRefreshBtn, WM_SETFONT, (WPARAM)hUI, TRUE);

        RefreshModuleMap(hList);
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        if (hList) MoveWindow(hList, 0, 34, rc.right, rc.bottom - 34, TRUE);
        return 0;
    }

    case WM_CONTEXTMENU:
        if ((HWND)wParam == hList) {
            ShowListBoxContextMenu(hList, lParam);
            return 0;
        }
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            RefreshModuleMap(hList);
            return 0;
        }
        if (LOWORD(wParam) == 2 && HIWORD(wParam) == LBN_DBLCLK) {
            int sel = (int)SendMessageA(hList, LB_GETCURSEL, 0, 0);
            if (sel >= 2) {
                char text[256] = {0};
                SendMessageA(hList, LB_GETTEXT, sel, (LPARAM)text);
                char* p = text;
                while (*p == ' ') p++;
                if (p[0] == '0' && p[1] == 'x') p += 2;
                UINT64 addr = 0;
                if (sscanf(p, "%llX", &addr) == 1) {
                    MemViewOpenAt(GetParent(hwnd), g_mmProcess, addr);
                }
            }
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        g_mmHwnd = NULL;
        return 0;

    case WM_DESTROY:
        if (hMonoFont) { DeleteObject(hMonoFont); hMonoFont = NULL; }
        hList = NULL;
        g_mmHwnd = NULL;
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

void ModuleMapOpen(HWND hwndParent, HANDLE hProcess)
{
    g_mmProcess = hProcess;

    if (g_mmHwnd) {
        SetForegroundWindow(g_mmHwnd);
        return;
    }

    static BOOL registered = FALSE;
    if (!registered) {
        WNDCLASSEXA wc = {0};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = ModuleMapWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = MM_CLASS;
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        RegisterClassExA(&wc);
        registered = TRUE;
    }

    int w = 750, h = 450;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    g_mmHwnd = CreateWindowExA(0, MM_CLASS, "Module Map",
        WS_OVERLAPPEDWINDOW,
        (screenW - w) / 2, (screenH - h) / 2, w, h,
        hwndParent, NULL, GetModuleHandle(NULL), NULL);

    if (g_mmHwnd) {
        ShowWindow(g_mmHwnd, SW_SHOW);
        UpdateWindow(g_mmHwnd);
    }
}
