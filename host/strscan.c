#include <windows.h>
#include <commctrl.h>
#include <psapi.h>
#include <stdio.h>
#include <ctype.h>
#include "strscan.h"
#include "memview.h"

/* ------------------------------------------------------------------ */
/* String scanner - find ASCII/Wide strings in the target PE image      */
/* ------------------------------------------------------------------ */

static const char* SS_CLASS = "RemoraStrScan";
static HWND  g_ssHwnd       = NULL;
static HWND  g_ssListView   = NULL;
static HWND  g_ssScanBtn    = NULL;
static HWND  g_ssFilterEdit = NULL;
static HWND  g_ssMinLenEdit = NULL;
static HWND  g_ssCountLabel = NULL;
static HFONT g_ssFont       = NULL;
static HFONT g_ssUIFont     = NULL;
static HANDLE g_ssProcess   = NULL;

#define IDC_SS_SCAN      4001
#define IDC_SS_FILTER    4002
#define IDC_SS_MINLEN    4003
#define IDC_SS_LIST      4004

#define SS_MAX_STRINGS   100000

typedef struct {
    UINT_PTR addr;
    int      length;
    BOOL     isWide;
    char     text[256];
} ScanResult;

static ScanResult* g_ssResults = NULL;
static int         g_ssResultCount = 0;

/* ------------------------------------------------------------------ */
/* Scanning logic                                                       */
/* ------------------------------------------------------------------ */

static BOOL IsPrintableAscii(BYTE b)
{
    return b >= 0x20 && b < 0x7F;
}

static void ScanBuffer(BYTE* buf, SIZE_T size, UINT_PTR baseAddr, int minLen)
{
    SIZE_T runStart = 0;
    int runLen = 0;

    for (SIZE_T i = 0; i < size && g_ssResultCount < SS_MAX_STRINGS; i++) {
        BYTE b = buf[i];
        if (IsPrintableAscii(b) || b == '\t' || b == '\r' || b == '\n') {
            if (runLen == 0) runStart = i;
            runLen++;
        } else {
            if (runLen >= minLen) {
                ScanResult* r = &g_ssResults[g_ssResultCount];
                r->addr = baseAddr + runStart;
                r->length = runLen;
                r->isWide = FALSE;
                int copyLen = runLen < 255 ? runLen : 255;
                memcpy(r->text, buf + runStart, copyLen);
                r->text[copyLen] = '\0';
                g_ssResultCount++;
            }
            runLen = 0;
        }
    }
    if (runLen >= minLen && g_ssResultCount < SS_MAX_STRINGS) {
        ScanResult* r = &g_ssResults[g_ssResultCount];
        r->addr = baseAddr + runStart;
        r->length = runLen;
        r->isWide = FALSE;
        int copyLen = runLen < 255 ? runLen : 255;
        memcpy(r->text, buf + runStart, copyLen);
        r->text[copyLen] = '\0';
        g_ssResultCount++;
    }

    /* Wide (UTF-16LE) strings */
    runLen = 0;
    runStart = 0;

    for (SIZE_T i = 0; i + 1 < size && g_ssResultCount < SS_MAX_STRINGS; i += 2) {
        BYTE lo = buf[i];
        BYTE hi = buf[i + 1];
        if (hi == 0 && (IsPrintableAscii(lo) || lo == '\t' || lo == '\r' || lo == '\n')) {
            if (runLen == 0) runStart = i;
            runLen++;
        } else {
            if (runLen >= minLen) {
                ScanResult* r = &g_ssResults[g_ssResultCount];
                r->addr = baseAddr + runStart;
                r->length = runLen;
                r->isWide = TRUE;
                int copyLen = runLen < 255 ? runLen : 255;
                for (int c = 0; c < copyLen; c++)
                    r->text[c] = (char)buf[runStart + c * 2];
                r->text[copyLen] = '\0';
                g_ssResultCount++;
            }
            runLen = 0;
        }
    }
    if (runLen >= minLen && g_ssResultCount < SS_MAX_STRINGS) {
        ScanResult* r = &g_ssResults[g_ssResultCount];
        r->addr = baseAddr + runStart;
        r->length = runLen;
        r->isWide = TRUE;
        int copyLen = runLen < 255 ? runLen : 255;
        for (int c = 0; c < copyLen; c++)
            r->text[c] = (char)buf[runStart + c * 2];
        r->text[copyLen] = '\0';
        g_ssResultCount++;
    }
}

static void DoScan(int minLen)
{
    if (!g_ssProcess) {
        MessageBoxA(g_ssHwnd, "No target process.", "String Scan", MB_OK | MB_ICONWARNING);
        return;
    }

    PBYTE base = NULL;
    SIZE_T size = 0;

    HMODULE hMod = NULL;
    DWORD needed = 0;
    if (EnumProcessModules(g_ssProcess, &hMod, sizeof(hMod), &needed) && hMod) {
        MODULEINFO mi;
        if (GetModuleInformation(g_ssProcess, hMod, &mi, sizeof(mi))) {
            base = (PBYTE)mi.lpBaseOfDll;
            size = mi.SizeOfImage;
        }
    }

    if (!base || !size) {
        MessageBoxA(g_ssHwnd, "Cannot determine target image.", "String Scan", MB_OK | MB_ICONWARNING);
        return;
    }

    if (!g_ssResults) {
        g_ssResults = (ScanResult*)HeapAlloc(GetProcessHeap(), 0,
                                             sizeof(ScanResult) * SS_MAX_STRINGS);
        if (!g_ssResults) return;
    }
    g_ssResultCount = 0;

    #define SCAN_CHUNK (64 * 1024)
    BYTE* chunk = (BYTE*)HeapAlloc(GetProcessHeap(), 0, SCAN_CHUNK);
    if (!chunk) return;

    for (SIZE_T off = 0; off < size && g_ssResultCount < SS_MAX_STRINGS; off += SCAN_CHUNK) {
        SIZE_T toRead = size - off;
        if (toRead > SCAN_CHUNK) toRead = SCAN_CHUNK;

        SIZE_T bytesGot = 0;
        BOOL ok = ReadProcessMemory(g_ssProcess, base + off, chunk, toRead, &bytesGot);

        if (ok && bytesGot > 0)
            ScanBuffer(chunk, bytesGot, (UINT_PTR)(base + off), minLen);
    }

    HeapFree(GetProcessHeap(), 0, chunk);
}

/* ------------------------------------------------------------------ */
/* Populate / filter the listview                                       */
/* ------------------------------------------------------------------ */

static void PopulateList(const char* filter)
{
    SendMessageA(g_ssListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_ssListView);

    int displayed = 0;
    for (int i = 0; i < g_ssResultCount; i++) {
        ScanResult* r = &g_ssResults[i];

        if (filter && filter[0]) {
            BOOL match = FALSE;
            int flen = (int)strlen(filter);
            int tlen = (int)strlen(r->text);
            for (int j = 0; j <= tlen - flen; j++) {
                BOOL eq = TRUE;
                for (int k = 0; k < flen; k++) {
                    char a = (char)tolower((unsigned char)r->text[j + k]);
                    char b = (char)tolower((unsigned char)filter[k]);
                    if (a != b) { eq = FALSE; break; }
                }
                if (eq) { match = TRUE; break; }
            }
            if (!match) continue;
        }

        char addrBuf[32];
        sprintf(addrBuf, "0x%016llX", (UINT64)r->addr);

        char lenBuf[16];
        sprintf(lenBuf, "%d", r->length);

        LVITEMA lvi = {0};
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = displayed;
        lvi.pszText = addrBuf;
        lvi.lParam = (LPARAM)i;
        ListView_InsertItem(g_ssListView, &lvi);

        ListView_SetItemText(g_ssListView, displayed, 1, lenBuf);
        ListView_SetItemText(g_ssListView, displayed, 2, (char*)(r->isWide ? "W" : "A"));
        ListView_SetItemText(g_ssListView, displayed, 3, r->text);

        displayed++;
    }

    SendMessageA(g_ssListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_ssListView, NULL, TRUE);

    char countBuf[64];
    sprintf(countBuf, "%d / %d strings", displayed, g_ssResultCount);
    SetWindowTextA(g_ssCountLabel, countBuf);
}

/* ------------------------------------------------------------------ */
/* Window proc                                                          */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK StrScanWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = GetModuleHandle(NULL);

        g_ssUIFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_ssFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

        int x = 4;
        HWND hLbl = CreateWindowExA(0, "STATIC", "Min len:",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            x, 6, 54, 22, hwnd, NULL, hInst, NULL);
        SendMessage(hLbl, WM_SETFONT, (WPARAM)g_ssUIFont, TRUE);
        x += 56;

        g_ssMinLenEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "4",
            WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_AUTOHSCROLL,
            x, 4, 40, 24, hwnd, (HMENU)(INT_PTR)IDC_SS_MINLEN, hInst, NULL);
        SendMessage(g_ssMinLenEdit, WM_SETFONT, (WPARAM)g_ssUIFont, TRUE);
        x += 46;

        g_ssScanBtn = CreateWindowExA(0, "BUTTON", "Scan",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, 4, 60, 24, hwnd, (HMENU)(INT_PTR)IDC_SS_SCAN, hInst, NULL);
        SendMessage(g_ssScanBtn, WM_SETFONT, (WPARAM)g_ssUIFont, TRUE);
        x += 70;

        HWND hFLbl = CreateWindowExA(0, "STATIC", "Filter:",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            x, 6, 44, 22, hwnd, NULL, hInst, NULL);
        SendMessage(hFLbl, WM_SETFONT, (WPARAM)g_ssUIFont, TRUE);
        x += 46;

        g_ssFilterEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            x, 4, 200, 24, hwnd, (HMENU)(INT_PTR)IDC_SS_FILTER, hInst, NULL);
        SendMessage(g_ssFilterEdit, WM_SETFONT, (WPARAM)g_ssUIFont, TRUE);
        x += 210;

        g_ssCountLabel = CreateWindowExA(0, "STATIC", "0 strings",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            x, 6, 200, 22, hwnd, NULL, hInst, NULL);
        SendMessage(g_ssCountLabel, WM_SETFONT, (WPARAM)g_ssUIFont, TRUE);

        g_ssListView = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, 32, 100, 100, hwnd, (HMENU)(INT_PTR)IDC_SS_LIST, hInst, NULL);

        ListView_SetExtendedListViewStyle(g_ssListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        SendMessage(g_ssListView, WM_SETFONT, (WPARAM)g_ssFont, TRUE);

        LVCOLUMNA col = {0};
        col.mask = LVCF_TEXT | LVCF_WIDTH;

        col.pszText = "Address";
        col.cx = 160;
        ListView_InsertColumn(g_ssListView, 0, &col);

        col.pszText = "Len";
        col.cx = 50;
        ListView_InsertColumn(g_ssListView, 1, &col);

        col.pszText = "Type";
        col.cx = 42;
        ListView_InsertColumn(g_ssListView, 2, &col);

        col.pszText = "String";
        col.cx = 500;
        ListView_InsertColumn(g_ssListView, 3, &col);

        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        if (g_ssListView)
            MoveWindow(g_ssListView, 0, 32, rc.right, rc.bottom - 32, TRUE);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_SS_SCAN: {
            char minBuf[16] = {0};
            GetWindowTextA(g_ssMinLenEdit, minBuf, sizeof(minBuf));
            int minLen = atoi(minBuf);
            if (minLen < 1) minLen = 4;

            SetWindowTextA(g_ssCountLabel, "Scanning...");
            UpdateWindow(g_ssCountLabel);

            DoScan(minLen);

            char filterBuf[256] = {0};
            GetWindowTextA(g_ssFilterEdit, filterBuf, sizeof(filterBuf));
            PopulateList(filterBuf);
            return 0;
        }
        case IDC_SS_FILTER:
            if (HIWORD(wParam) == EN_CHANGE) {
                char filterBuf[256] = {0};
                GetWindowTextA(g_ssFilterEdit, filterBuf, sizeof(filterBuf));
                PopulateList(filterBuf);
            }
            return 0;
        }
        break;

    case WM_NOTIFY: {
        NMHDR* pnm = (NMHDR*)lParam;
        if (pnm->idFrom == IDC_SS_LIST && pnm->code == NM_DBLCLK) {
            int sel = ListView_GetNextItem(g_ssListView, -1, LVNI_SELECTED);
            if (sel >= 0) {
                LVITEMA lvi = {0};
                lvi.mask = LVIF_PARAM;
                lvi.iItem = sel;
                ListView_GetItem(g_ssListView, &lvi);
                int idx = (int)lvi.lParam;
                if (idx >= 0 && idx < g_ssResultCount) {
                    MemViewOpenAt(GetParent(hwnd), g_ssProcess, g_ssResults[idx].addr);
                }
            }
            return 0;
        }
        break;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        g_ssHwnd = NULL;
        return 0;

    case WM_DESTROY:
        if (g_ssFont) { DeleteObject(g_ssFont); g_ssFont = NULL; }
        if (g_ssUIFont) { DeleteObject(g_ssUIFont); g_ssUIFont = NULL; }
        if (g_ssResults) {
            HeapFree(GetProcessHeap(), 0, g_ssResults);
            g_ssResults = NULL;
        }
        g_ssResultCount = 0;
        g_ssHwnd = NULL;
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void StrScanOpen(HWND hwndParent, HANDLE hProcess)
{
    g_ssProcess = hProcess;

    if (g_ssHwnd) {
        SetForegroundWindow(g_ssHwnd);
        return;
    }

    static BOOL registered = FALSE;
    if (!registered) {
        WNDCLASSEXA wc = {0};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = StrScanWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = SS_CLASS;
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        RegisterClassExA(&wc);
        registered = TRUE;
    }

    int w = 850, h = 520;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    g_ssHwnd = CreateWindowExA(0, SS_CLASS, "String Scanner",
        WS_OVERLAPPEDWINDOW,
        (screenW - w) / 2, (screenH - h) / 2, w, h,
        hwndParent, NULL, GetModuleHandle(NULL), NULL);

    if (g_ssHwnd) {
        ShowWindow(g_ssHwnd, SW_SHOW);
        UpdateWindow(g_ssHwnd);
    }
}

void StrScanClose(void)
{
    if (g_ssHwnd) {
        DestroyWindow(g_ssHwnd);
        g_ssHwnd = NULL;
    }
}
