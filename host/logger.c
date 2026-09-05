#include "logger.h"
#include <richedit.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define LOG_MAX_LINES 10000
#define LOG_TRIM_LINES (LOG_MAX_LINES / 4)
#define LOG_BATCH_MAX 512

typedef struct {
    char text[2048];
    COLORREF color;
} LogBatchEntry;

static HWND g_hRichEdit;
static CRITICAL_SECTION g_cs;
static char g_filter[256] = {0};
static LogBatchEntry g_batch[LOG_BATCH_MAX];
static int g_batch_count = 0;

static HANDLE g_backingFile = INVALID_HANDLE_VALUE;
static char g_backingPath[MAX_PATH] = {0};
static DWORD g_total_lines = 0;
static BOOL g_banner_shown = FALSE;
static BOOL g_autoscroll = TRUE;
static BOOL g_force_scroll = FALSE;

void LoggerInit(HWND hRichEdit) {
    g_hRichEdit = hRichEdit;
    InitializeCriticalSection(&g_cs);

    SendMessage(hRichEdit, EM_SETBKGNDCOLOR, 0, RGB(0, 0, 0));
    SendMessage(hRichEdit, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);

    CHARFORMAT2 cf = {0};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR;
    cf.yHeight = 200;
    cf.crTextColor = RGB(255, 255, 255);
    strcpy(cf.szFaceName, "Consolas");
    SendMessage(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    snprintf(g_backingPath, MAX_PATH, "%sremora_log_%u.txt", tmp, GetCurrentProcessId());
    g_backingFile = CreateFileA(g_backingPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void LoggerShutdown(void) {
    if (g_backingFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_backingFile);
        g_backingFile = INVALID_HANDLE_VALUE;
    }
    if (g_backingPath[0])
        DeleteFileA(g_backingPath);
    DeleteCriticalSection(&g_cs);
}

void LoggerAppend(const char *text, COLORREF color) {
    if (!g_hRichEdit) return;

    EnterCriticalSection(&g_cs);

    if (g_backingFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_backingFile, text, (DWORD)strlen(text), &written, NULL);
    }
    g_total_lines++;

    if (g_filter[0] && !strstr(text, g_filter)) {
        LeaveCriticalSection(&g_cs);
        return;
    }

    if (g_batch_count < LOG_BATCH_MAX) {
        strncpy(g_batch[g_batch_count].text, text, sizeof(g_batch[0].text) - 1);
        g_batch[g_batch_count].text[sizeof(g_batch[0].text) - 1] = 0;
        g_batch[g_batch_count].color = color;
        g_batch_count++;
    }

    LeaveCriticalSection(&g_cs);

    if (g_batch_count >= LOG_BATCH_MAX)
        LoggerFlush();
}

void LoggerFlush(void) {
    if (!g_hRichEdit) return;

    EnterCriticalSection(&g_cs);
    if (g_batch_count == 0) {
        LeaveCriticalSection(&g_cs);
        return;
    }

    int count = g_batch_count;
    LogBatchEntry *local = (LogBatchEntry *)malloc(count * sizeof(LogBatchEntry));
    if (!local) {
        LeaveCriticalSection(&g_cs);
        return;
    }
    memcpy(local, g_batch, count * sizeof(LogBatchEntry));
    g_batch_count = 0;
    LeaveCriticalSection(&g_cs);

    BOOL should_scroll = FALSE;
    int save_first_line = 0;
    if (g_force_scroll) {
        should_scroll = TRUE;
        g_force_scroll = FALSE;
    } else if (g_autoscroll) {
        SCROLLINFO si = {0};
        si.cbSize = sizeof(si);
        si.fMask = SIF_ALL;
        GetScrollInfo(g_hRichEdit, SB_VERT, &si);
        should_scroll = (si.nPos + (int)si.nPage >= si.nMax - 1);
    }
    if (!should_scroll)
        save_first_line = (int)SendMessage(g_hRichEdit, EM_GETFIRSTVISIBLELINE, 0, 0);

    SendMessage(g_hRichEdit, WM_SETREDRAW, FALSE, 0);

    DWORD line_count = (DWORD)SendMessage(g_hRichEdit, EM_GETLINECOUNT, 0, 0);
    if (line_count > LOG_MAX_LINES) {
        LRESULT trim_end = SendMessage(g_hRichEdit, EM_LINEINDEX, LOG_TRIM_LINES, 0);
        if (g_banner_shown) {
            LRESULT banner_end = SendMessage(g_hRichEdit, EM_LINEINDEX, 1, 0);
            SendMessage(g_hRichEdit, EM_SETSEL, 0, banner_end);
            SendMessage(g_hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)"");
            trim_end -= banner_end;
        }
        SendMessage(g_hRichEdit, EM_SETSEL, 0, trim_end);
        SendMessage(g_hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)"");

        char banner[128];
        snprintf(banner, sizeof(banner),
            "[... showing last %d of %u lines -- Save Log (Ctrl+S) exports all ...]\n",
            LOG_MAX_LINES, g_total_lines);
        SendMessage(g_hRichEdit, EM_SETSEL, 0, 0);
        CHARFORMAT2 bcf = {0};
        bcf.cbSize = sizeof(bcf);
        bcf.dwMask = CFM_COLOR;
        bcf.crTextColor = RGB(255, 255, 0);
        SendMessage(g_hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&bcf);
        SendMessage(g_hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)banner);
        g_banner_shown = TRUE;
    }

    for (int i = 0; i < count; i++) {
        int len = GetWindowTextLength(g_hRichEdit);
        SendMessage(g_hRichEdit, EM_SETSEL, len, len);

        CHARFORMAT2 cf = {0};
        cf.cbSize = sizeof(cf);
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = local[i].color;
        SendMessage(g_hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

        SendMessage(g_hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)local[i].text);
    }

    if (!should_scroll) {
        int cur_first = (int)SendMessage(g_hRichEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
        SendMessage(g_hRichEdit, EM_LINESCROLL, 0, save_first_line - cur_first);
    }

    SendMessage(g_hRichEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hRichEdit, NULL, TRUE);
    if (should_scroll)
        SendMessage(g_hRichEdit, WM_VSCROLL, SB_BOTTOM, 0);

    free(local);
}

void LoggerAppendFmt(COLORREF color, const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LoggerAppend(buf, color);
}

void LoggerClear(void) {
    if (!g_hRichEdit) return;
    EnterCriticalSection(&g_cs);
    g_batch_count = 0;
    LeaveCriticalSection(&g_cs);
    SetWindowText(g_hRichEdit, "");
    g_total_lines = 0;
    g_banner_shown = FALSE;
    if (g_backingFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(g_backingFile, 0, NULL, FILE_BEGIN);
        SetEndOfFile(g_backingFile);
    }
}

BOOL LoggerSaveToFile(const char *path) {
    if (g_backingFile == INVALID_HANDLE_VALUE)
        return FALSE;

    FlushFileBuffers(g_backingFile);
    return CopyFileA(g_backingPath, path, FALSE);
}

DWORD LoggerGetTotalLines(void) {
    return g_total_lines;
}

void LoggerSetFilter(const char *filter) {
    EnterCriticalSection(&g_cs);
    if (filter)
        strncpy(g_filter, filter, sizeof(g_filter) - 1);
    else
        g_filter[0] = 0;
    LeaveCriticalSection(&g_cs);
}

DWORD LoggerGetLineCount(void) {
    return (DWORD)SendMessage(g_hRichEdit, EM_GETLINECOUNT, 0, 0);
}

int LoggerFindNext(const char *needle, BOOL forward) {
    if (!g_hRichEdit || !needle || !needle[0]) return -1;

    LoggerFlush();

    WCHAR wneedle[256];
    MultiByteToWideChar(CP_UTF8, 0, needle, -1, wneedle, 256);
    int needle_len = (int)wcslen(wneedle);

    DWORD sel_start = 0, sel_end = 0;
    SendMessage(g_hRichEdit, EM_GETSEL, (WPARAM)&sel_start, (LPARAM)&sel_end);

    int text_len = GetWindowTextLengthW(g_hRichEdit);

    FINDTEXTW ft = {0};
    ft.lpstrText = wneedle;

    if (forward) {
        ft.chrg.cpMin = sel_end;
        ft.chrg.cpMax = text_len;
    } else {
        ft.chrg.cpMin = (sel_start > 0) ? sel_start - 1 : 0;
        ft.chrg.cpMax = 0;
    }

    DWORD flags = forward ? FR_DOWN : 0;
    int pos = (int)SendMessageW(g_hRichEdit, EM_FINDTEXTW, flags, (LPARAM)&ft);

    if (pos < 0 && forward) {
        ft.chrg.cpMin = 0;
        ft.chrg.cpMax = text_len;
        pos = (int)SendMessageW(g_hRichEdit, EM_FINDTEXTW, FR_DOWN, (LPARAM)&ft);
    } else if (pos < 0 && !forward) {
        ft.chrg.cpMin = text_len;
        ft.chrg.cpMax = 0;
        pos = (int)SendMessageW(g_hRichEdit, EM_FINDTEXTW, 0, (LPARAM)&ft);
    }

    if (pos >= 0) {
        SendMessage(g_hRichEdit, EM_SETSEL, pos, pos + needle_len);
        int line = (int)SendMessage(g_hRichEdit, EM_LINEFROMCHAR, pos, 0);
        int first = (int)SendMessage(g_hRichEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
        int target = line - 3;
        if (target < 0) target = 0;
        if (target != first)
            SendMessage(g_hRichEdit, EM_LINESCROLL, 0, target - first);
    }
    return pos;
}

void LoggerHighlightAll(const char *needle) {
    if (!g_hRichEdit || !needle || !needle[0]) return;

    LoggerFlush();

    WCHAR wneedle[256];
    MultiByteToWideChar(CP_UTF8, 0, needle, -1, wneedle, 256);
    int needle_len = (int)wcslen(wneedle);
    int text_len = GetWindowTextLengthW(g_hRichEdit);

    SendMessage(g_hRichEdit, WM_SETREDRAW, FALSE, 0);

    DWORD old_start = 0, old_end = 0;
    SendMessage(g_hRichEdit, EM_GETSEL, (WPARAM)&old_start, (LPARAM)&old_end);

    FINDTEXTW ft = {0};
    ft.lpstrText = wneedle;
    ft.chrg.cpMin = 0;
    ft.chrg.cpMax = text_len;

    CHARFORMAT2 cf = {0};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_BACKCOLOR;
    cf.crBackColor = RGB(180, 180, 0);

    int pos;
    while ((pos = (int)SendMessageW(g_hRichEdit, EM_FINDTEXTW, FR_DOWN, (LPARAM)&ft)) >= 0) {
        SendMessage(g_hRichEdit, EM_SETSEL, pos, pos + needle_len);
        SendMessage(g_hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
        ft.chrg.cpMin = pos + needle_len;
        if (ft.chrg.cpMin >= text_len) break;
    }

    SendMessage(g_hRichEdit, EM_SETSEL, old_start, old_end);
    SendMessage(g_hRichEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hRichEdit, NULL, TRUE);
}

void LoggerSetAutoScroll(BOOL enable) { g_autoscroll = enable; }
BOOL LoggerGetAutoScroll(void) { return g_autoscroll; }
void LoggerScrollToBottom(void) {
    g_force_scroll = TRUE;
}

void LoggerClearHighlight(void) {
    if (!g_hRichEdit) return;

    SendMessage(g_hRichEdit, WM_SETREDRAW, FALSE, 0);

    DWORD old_start = 0, old_end = 0;
    SendMessage(g_hRichEdit, EM_GETSEL, (WPARAM)&old_start, (LPARAM)&old_end);

    int text_len = GetWindowTextLengthW(g_hRichEdit);
    SendMessage(g_hRichEdit, EM_SETSEL, 0, text_len);

    CHARFORMAT2 cf = {0};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_BACKCOLOR;
    cf.dwEffects = CFE_AUTOBACKCOLOR;
    SendMessage(g_hRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

    SendMessage(g_hRichEdit, EM_SETSEL, old_start, old_end);
    SendMessage(g_hRichEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hRichEdit, NULL, TRUE);
}
