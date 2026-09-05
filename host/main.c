#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <commctrl.h>
#include <richedit.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <psapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <strsafe.h>

#pragma comment(lib, "psapi.lib")
#include "resource.h"
#include "logger.h"
#include "process.h"
#include "jail.h"
#include "jail_rules.h"
#include "memview.h"
#include "strscan.h"
#include "dasmWnd/dasm.h"
#include "ipc_server.h"
#include "hook_defs.h"
#include "jail_shared.h"
#include "summary.h"
#include "sandbox_report.h"

#pragma comment(lib, "comctl32.lib")

static HWND g_hWnd;
static HWND g_hRichEdit;
static HWND g_hToolbar;
static HWND g_hStatus;
static HWND g_hAskBar;
static HWND g_hAskLabel;
static HWND g_hBtnAllow;
static HWND g_hBtnBlock;
static HWND g_hBtnAllowAll;
static HWND g_hBtnStack;
static TargetProcess g_target;
static IpcServer g_ipc;
static HFONT g_hFont;
static BOOL g_debuglog = FALSE;
static BOOL g_dasm_dblclk = TRUE;
static FILE *g_logfile = NULL;
static HANDLE g_jail_shared_mapping = NULL;
static JailSharedMem *g_jail_shared = NULL;
static DWORD g_ask_pending_tid = 0;
static DWORD g_ask_pending_hook = 0;
static HBRUSH g_hAskBrush = NULL;
static UINT64 g_ask_stack_frames[IPC_MAX_STACK_FRAMES];
static DWORD g_ask_stack_count = 0;
static HWND g_hFindEdit;
static HWND g_hBtnFindNext;
static HWND g_hBtnFindPrev;
static HWND g_hBtnFindClose;
static BOOL g_find_visible = FALSE;
static HIMAGELIST g_hToolbarIml = NULL;
static BOOL g_catFilter[FILT_COUNT] = { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE };
static HANDLE g_hProcessWait = NULL;
static char g_autodump_folder[MAX_PATH] = {0};
static int g_autodump_counter = 0;
static char g_last_exe[MAX_PATH] = {0};
static char g_last_args[1024] = {0};
static SummaryAccumulator g_summary;

static BOOL g_break_at_oep = TRUE;
static BOOL g_silence_boring = FALSE;
static BOOL g_coalesce = FALSE;
#define COALESCE_SLOTS 64
#define COALESCE_TIMEOUT_MS 500
typedef struct {
    DWORD tid;
    DWORD hook_id;
    char  key[512];
    DWORD count;
    DWORD tick;
} CoalesceSlot;
static CoalesceSlot g_coal[COALESCE_SLOTS];
static int g_coal_count = 0;

static void GetConfigIniPath(char *out, int size) {
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    char *slash = strrchr(exe, '\\');
    if (slash) *(slash + 1) = 0;
    wsprintfA(out, "%sremora_config.ini", exe);
}

static void SaveWindowPos(HWND hWnd) {
    WINDOWPLACEMENT wp = { .length = sizeof(wp) };
    GetWindowPlacement(hWnd, &wp);
    RECT *r = &wp.rcNormalPosition;
    char ini[MAX_PATH], buf[32];
    GetConfigIniPath(ini, MAX_PATH);
    wsprintfA(buf, "%d", (int)(r->left));
    WritePrivateProfileStringA("Window", "X", buf, ini);
    wsprintfA(buf, "%d", (int)(r->top));
    WritePrivateProfileStringA("Window", "Y", buf, ini);
    wsprintfA(buf, "%d", (int)(r->right - r->left));
    WritePrivateProfileStringA("Window", "W", buf, ini);
    wsprintfA(buf, "%d", (int)(r->bottom - r->top));
    WritePrivateProfileStringA("Window", "H", buf, ini);
    wsprintfA(buf, "%u", wp.showCmd);
    WritePrivateProfileStringA("Window", "ShowCmd", buf, ini);
}

static void SaveConfigToggles(const char *ini) {
    char buf[8];
    wsprintfA(buf, "%d", LoggerGetAutoScroll());
    WritePrivateProfileStringA("Config", "AutoScroll", buf, ini);
    wsprintfA(buf, "%d", g_coalesce);
    WritePrivateProfileStringA("Config", "TrimNoise", buf, ini);
    wsprintfA(buf, "%d", g_break_at_oep);
    WritePrivateProfileStringA("Config", "BreakAtOEP", buf, ini);
    wsprintfA(buf, "%d", g_silence_boring);
    WritePrivateProfileStringA("Config", "SilenceBoring", buf, ini);
    wsprintfA(buf, "%d", g_dasm_dblclk);
    WritePrivateProfileStringA("Config", "DasmDblClk", buf, ini);
}

static void LoadConfigToggles(const char *ini, HWND hWnd) {
    int v = GetPrivateProfileIntA("Config", "AutoScroll", -1, ini);
    if (v < 0) return;
    LoggerSetAutoScroll(v);
    CheckMenuItem(GetMenu(hWnd), IDM_CFG_AUTOSCROLL,
        v ? MF_CHECKED : MF_UNCHECKED);

    g_coalesce = GetPrivateProfileIntA("Config", "TrimNoise", 0, ini);
    CheckMenuItem(GetMenu(hWnd), IDM_CFG_COALESCE,
        g_coalesce ? MF_CHECKED : MF_UNCHECKED);
    if (g_coalesce)
        SetTimer(hWnd, IDT_COALESCE_FLUSH, COALESCE_TIMEOUT_MS, NULL);

    g_break_at_oep = GetPrivateProfileIntA("Config", "BreakAtOEP", 1, ini);
    CheckMenuItem(GetMenu(hWnd), IDM_CFG_BREAK_OEP,
        g_break_at_oep ? MF_CHECKED : MF_UNCHECKED);

    g_silence_boring = GetPrivateProfileIntA("Config", "SilenceBoring", 0, ini);
    CheckMenuItem(GetMenu(hWnd), IDM_CFG_SILENCE_BORING,
        g_silence_boring ? MF_CHECKED : MF_UNCHECKED);

    g_dasm_dblclk = GetPrivateProfileIntA("Config", "DasmDblClk", 1, ini);
    CheckMenuItem(GetMenu(hWnd), IDM_CFG_DASM_DBLCLK,
        g_dasm_dblclk ? MF_CHECKED : MF_UNCHECKED);
}

static BOOL LoadWindowPos(int *x, int *y, int *w, int *h) {
    char ini[MAX_PATH];
    GetConfigIniPath(ini, MAX_PATH);
    int cx = GetPrivateProfileIntA("Window", "X", -99999, ini);
    if (cx == -99999) return FALSE;
    *x = cx;
    *y = GetPrivateProfileIntA("Window", "Y", 0, ini);
    *w = GetPrivateProfileIntA("Window", "W", 1100, ini);
    *h = GetPrivateProfileIntA("Window", "H", 700, ini);
    if (*w < 200) *w = 200;
    if (*h < 150) *h = 150;
    return TRUE;
}

static void CoalesceMakeKey(char *key, int keysize, const char *text) {
    strncpy(key, text, keysize - 1);
    key[keysize - 1] = 0;
    char *arrow = strstr(key, ") -> ");
    if (arrow)
        arrow[1] = 0;
    if (strncmp(key, "VirtualAlloc(0x", 15) == 0
        || strncmp(key, "VirtualProtect(0x", 17) == 0) {
        char *open = strchr(key, '(');
        char *comma = strchr(open, ',');
        if (open && comma) {
            memmove(open + 2, comma, strlen(comma) + 1);
            open[1] = '*';
        }
    }
}

static void CoalesceFlushSlot(int idx) {
    if (g_coal[idx].count > 1)
        LoggerAppendFmt(LOG_COLOR_VERBOSE, "  [TID:%04X] ... %s x%u\n",
            g_coal[idx].tid, g_coal[idx].key, g_coal[idx].count);
    if (idx < g_coal_count - 1)
        g_coal[idx] = g_coal[g_coal_count - 1];
    g_coal_count--;
}

static void CoalesceFlushAll(void) {
    while (g_coal_count > 0)
        CoalesceFlushSlot(0);
}

static void CoalesceFlushStale(void) {
    DWORD now = GetTickCount();
    for (int i = g_coal_count - 1; i >= 0; i--) {
        if (now - g_coal[i].tick >= COALESCE_TIMEOUT_MS)
            CoalesceFlushSlot(i);
    }
}

static BOOL CoalesceTryMerge(DWORD tid, DWORD hook_id, const char *text) {
    if (!g_coalesce) return FALSE;
    char key[512];
    CoalesceMakeKey(key, sizeof(key), text);
    for (int i = 0; i < g_coal_count; i++) {
        if (g_coal[i].tid == tid && g_coal[i].hook_id == hook_id
            && strcmp(g_coal[i].key, key) == 0) {
            g_coal[i].count++;
            g_coal[i].tick = GetTickCount();
            return TRUE;
        }
    }
    if (g_coal_count < COALESCE_SLOTS) {
        CoalesceSlot *s = &g_coal[g_coal_count++];
        s->tid = tid;
        s->hook_id = hook_id;
        strncpy(s->key, key, sizeof(s->key) - 1);
        s->key[sizeof(s->key) - 1] = 0;
        s->count = 1;
        s->tick = GetTickCount();
    }
    return FALSE;
}

#define TB_STATE_IDLE    0
#define TB_STATE_LOADING 1
#define TB_STATE_READY   2
static int g_tb_state = TB_STATE_IDLE;

static void EnableStartButton(BOOL enable) {
    SendMessage(g_hToolbar, TB_ENABLEBUTTON, IDM_TB_START, enable);
    EnableMenuItem(GetMenu(g_hWnd), IDM_FILE_LAUNCH,
        MF_BYCOMMAND | (enable ? MF_ENABLED : MF_GRAYED));
}

typedef struct {
    IPC_MSG_HEADER hdr;
    char extra[512];
} IpcQueueEntry;

/* ------------------------------------------------------------------ */
/* Toolbar helpers                                                      */
/* ------------------------------------------------------------------ */

static HBITMAP CreateCircleBitmap(COLORREF color) {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, 16, 16);
    HBITMAP hOld = (HBITMAP)SelectObject(hdcMem, hbm);

    RECT rc = {0, 0, 16, 16};
    HBRUSH hBg = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
    FillRect(hdcMem, &rc, hBg);
    DeleteObject(hBg);

    HBRUSH hBr = CreateSolidBrush(color);
    HBRUSH hOldBr = (HBRUSH)SelectObject(hdcMem, hBr);
    HPEN hPen = CreatePen(PS_SOLID, 1, color);
    HPEN hOldPen = (HPEN)SelectObject(hdcMem, hPen);
    Ellipse(hdcMem, 3, 3, 13, 13);
    SelectObject(hdcMem, hOldPen);
    SelectObject(hdcMem, hOldBr);
    DeleteObject(hPen);
    DeleteObject(hBr);

    SelectObject(hdcMem, hOld);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    return hbm;
}

static void ToolbarUpdateIcon(int state) {
    if (!g_hToolbarIml) return;
    g_tb_state = state;

    COLORREF color;
    switch (state) {
        case TB_STATE_LOADING: color = RGB(200, 40, 40); break;
        case TB_STATE_READY:   color = RGB(40, 180, 40); break;
        default:               color = RGB(60, 120, 220); break;
    }
    HBITMAP hbm = CreateCircleBitmap(color);
    ImageList_Replace(g_hToolbarIml, 0, hbm, NULL);
    DeleteObject(hbm);
    InvalidateRect(g_hToolbar, NULL, TRUE);
    UpdateWindow(g_hToolbar);
}

static void CreateMainToolbar(HWND hwndParent) {
    g_hToolbar = CreateWindowExA(0, TOOLBARCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS |
        CCS_NODIVIDER | CCS_TOP,
        0, 0, 0, 0,
        hwndParent, (HMENU)(UINT_PTR)IDC_TOOLBAR,
        GetModuleHandle(NULL), NULL);

    SendMessage(g_hToolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    SendMessage(g_hToolbar, TB_SETBITMAPSIZE, 0, MAKELPARAM(16, 16));
    SendMessage(g_hToolbar, TB_SETBUTTONSIZE, 0, MAKELPARAM(16, 16));
    SendMessage(g_hToolbar, TB_SETPADDING, 0, MAKELPARAM(0, 0));

    g_hToolbarIml = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1 + FILT_COUNT, 0);
    HBITMAP hbm = CreateCircleBitmap(RGB(60, 120, 220));
    ImageList_Add(g_hToolbarIml, hbm, NULL);
    DeleteObject(hbm);

    struct { const char *dll; int idx; } filt_icons[FILT_COUNT] = {
        { "shell32.dll",   1 },  /* File */
        { "shell32.dll",  15 },  /* Process (gear) */
        { "shell32.dll",  48 },  /* Memory (shield) */
        { "regedit.exe",   0 },  /* Registry */
        { "shell32.dll",  18 },  /* Network */
        { "shell32.dll",  14 },  /* HTTP (globe) */
        { "shell32.dll",  72 },  /* Module (DLL) */
        { "shell32.dll",  44 },  /* Crypto */
        { "shell32.dll",   2 },  /* General (app) */
    };
    for (int i = 0; i < FILT_COUNT; i++) {
        HICON hIcon = NULL;
        ExtractIconExA(filt_icons[i].dll, filt_icons[i].idx, NULL, &hIcon, 1);
        if (hIcon) {
            ImageList_AddIcon(g_hToolbarIml, hIcon);
            DestroyIcon(hIcon);
        } else {
            ImageList_AddIcon(g_hToolbarIml, LoadIcon(NULL, IDI_APPLICATION));
        }
    }

    SendMessage(g_hToolbar, TB_SETIMAGELIST, 0, (LPARAM)g_hToolbarIml);

    TBBUTTON buttons[2 + FILT_COUNT];
    memset(buttons, 0, sizeof(buttons));

    buttons[0].iBitmap = 0;
    buttons[0].idCommand = IDM_TB_START;
    buttons[0].fsState = TBSTATE_ENABLED;
    buttons[0].fsStyle = BTNS_BUTTON;
    buttons[0].iString = -1;

    buttons[1].fsStyle = BTNS_SEP;

    for (int i = 0; i < FILT_COUNT; i++) {
        buttons[2 + i].iBitmap = 1 + i;
        buttons[2 + i].idCommand = IDM_TB_FILT_BASE + i;
        buttons[2 + i].fsState = TBSTATE_ENABLED | TBSTATE_CHECKED;
        buttons[2 + i].fsStyle = BTNS_CHECK;
        buttons[2 + i].iString = -1;
    }

    SendMessage(g_hToolbar, TB_ADDBUTTONS, 2 + FILT_COUNT, (LPARAM)buttons);
    for (int i = 0; i < FILT_COUNT; i++)
        SendMessage(g_hToolbar, TB_CHECKBUTTON, IDM_TB_FILT_BASE + i, TRUE);
    SendMessage(g_hToolbar, TB_AUTOSIZE, 0, 0);
}

static int GetToolbarHeight(void) {
    if (!g_hToolbar) return 0;
    RECT rc;
    GetWindowRect(g_hToolbar, &rc);
    return rc.bottom - rc.top;
}

/* ------------------------------------------------------------------ */
/* Open Target dialog (OFN with Arguments field via template)           */
/* ------------------------------------------------------------------ */

typedef struct {
    char exe_path[MAX_PATH];
    char arguments[1024];
} OpenTargetResult;

static OpenTargetResult *g_ofn_result = NULL;

static UINT_PTR CALLBACK OFNHookProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)wParam;
    switch (msg) {
        case WM_INITDIALOG: {
            OPENFILENAMEA *ofn = (OPENFILENAMEA *)lParam;
            g_ofn_result = (OpenTargetResult *)ofn->lCustData;
            if (g_ofn_result && g_ofn_result->arguments[0]) {
                HWND hEdit = GetDlgItem(hdlg, IDC_OT_ARGS_EDIT);
                if (hEdit)
                    SetWindowTextA(hEdit, g_ofn_result->arguments);
            }
            return TRUE;
        }
        case WM_NOTIFY: {
            OFNOTIFY *notify = (OFNOTIFY *)lParam;
            if (notify->hdr.code == CDN_FILEOK) {
                HWND hEdit = GetDlgItem(hdlg, IDC_OT_ARGS_EDIT);
                if (hEdit && g_ofn_result)
                    GetWindowTextA(hEdit, g_ofn_result->arguments, sizeof(g_ofn_result->arguments));
            }
            break;
        }
    }
    return 0;
}

static BOOL ShowOpenTargetDialog(HWND hwndParent, OpenTargetResult *result) {
    char init_dir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, init_dir);

    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwndParent;
    ofn.hInstance = GetModuleHandle(NULL);
    ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = result->exe_path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrInitialDir = init_dir;
    ofn.lpstrTitle = "Open Target";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY |
                OFN_ENABLEHOOK | OFN_ENABLETEMPLATE | OFN_ENABLESIZING | OFN_EXPLORER;
    ofn.lpfnHook = OFNHookProc;
    ofn.lpTemplateName = MAKEINTRESOURCE(IDD_OFN_ARGS);
    ofn.lCustData = (LPARAM)result;

    if (GetOpenFileNameA(&ofn))
        return TRUE;
    return FALSE;
}

static void FindBarShow(void) {
    if (g_find_visible) {
        SetFocus(g_hFindEdit);
        SendMessage(g_hFindEdit, EM_SETSEL, 0, -1);
        return;
    }
    g_find_visible = TRUE;
    ShowWindow(g_hFindEdit, SW_SHOW);
    ShowWindow(g_hBtnFindNext, SW_SHOW);
    ShowWindow(g_hBtnFindPrev, SW_SHOW);
    ShowWindow(g_hBtnFindClose, SW_SHOW);
    SendMessage(g_hWnd, WM_SIZE, 0, 0);
    SetFocus(g_hFindEdit);
    SendMessage(g_hFindEdit, EM_SETSEL, 0, -1);
}

static void FindBarHide(void) {
    if (!g_find_visible) return;
    g_find_visible = FALSE;
    ShowWindow(g_hFindEdit, SW_HIDE);
    ShowWindow(g_hBtnFindNext, SW_HIDE);
    ShowWindow(g_hBtnFindPrev, SW_HIDE);
    ShowWindow(g_hBtnFindClose, SW_HIDE);
    LoggerClearHighlight();
    SendMessage(g_hWnd, WM_SIZE, 0, 0);
    SetFocus(g_hRichEdit);
}

static void FindBarDoSearch(BOOL forward) {
    char needle[256];
    GetWindowTextA(g_hFindEdit, needle, sizeof(needle));
    if (!needle[0]) return;
    LoggerClearHighlight();
    LoggerHighlightAll(needle);
    LoggerFindNext(needle, forward);
    SetFocus(g_hFindEdit);
}

static void ResolveModuleName(HANDLE hProcess, UINT64 addr, char *out, int out_size) {
    out[0] = 0;
    HMODULE mods[256];
    DWORD needed = 0;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
        return;
    int count = needed / sizeof(HMODULE);
    if (count > 256) count = 256;
    for (int i = 0; i < count; i++) {
        MODULEINFO mi = {0};
        if (!GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi)))
            continue;
        UINT64 base = (UINT64)(UINT_PTR)mi.lpBaseOfDll;
        if (addr >= base && addr < base + mi.SizeOfImage) {
            char path[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, mods[i], path, MAX_PATH)) {
                char *slash = strrchr(path, '\\');
                char *name = slash ? slash + 1 : path;
                _snprintf(out, out_size, "%s+0x%llX", name, (unsigned long long)(addr - base));
                out[out_size - 1] = 0;
            }
            return;
        }
    }
    _snprintf(out, out_size, "0x%016llX", (unsigned long long)addr);
    out[out_size - 1] = 0;
}

static LRESULT CALLBACK StackDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE: {
            HWND hEdit = GetDlgItem(hwnd, 1);
            if (hEdit) {
                RECT rc;
                GetClientRect(hwnd, &rc);
                MoveWindow(hEdit, 4, 4, rc.right - 8, rc.bottom - 8, TRUE);
            }
            return 0;
        }
        case WM_DESTROY:
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static void ShowStackDialog(HWND hwndParent) {
    if (g_ask_stack_count == 0 || !g_target.hProcess) {
        MessageBoxA(hwndParent, "No stack frames available.", "Stack Trace", MB_ICONINFORMATION);
        return;
    }

    char buf[4096];
    int pos = 0;
    for (DWORD i = 0; i < g_ask_stack_count && pos < (int)sizeof(buf) - 200; i++) {
        char resolved[256];
        ResolveModuleName(g_target.hProcess, g_ask_stack_frames[i], resolved, sizeof(resolved));
        pos += _snprintf(buf + pos, sizeof(buf) - pos, "#%u  %-28s | 0x%llX\r\n",
            i, resolved, (unsigned long long)g_ask_stack_frames[i]);
    }
    buf[pos] = 0;

    static BOOL s_registered = FALSE;
    if (!s_registered) {
        WNDCLASS wc = {0};
        wc.lpfnWndProc = StackDlgProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
        wc.lpszClassName = "RemoraStack";
        RegisterClass(&wc);
        s_registered = TRUE;
    }

    RECT prc;
    GetWindowRect(hwndParent, &prc);
    int sw = 560, sh = 300;
    int sx = prc.left + (prc.right - prc.left - sw) / 2;
    int sy = prc.top + (prc.bottom - prc.top - sh) / 2;

    HWND hwnd = CreateWindowEx(WS_EX_TOOLWINDOW, "RemoraStack", "Stack Trace",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        sx, sy, sw, sh,
        hwndParent, NULL, GetModuleHandle(NULL), NULL);

    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    HWND hEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", buf,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        4, 4, 520, 240, hwnd, (HMENU)1, GetModuleHandle(NULL), NULL);
    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hwnd, WM_SIZE, 0, 0);
}

static void OnIpcMessage(const IPC_MSG_HEADER *hdr, const void *extra, void *user) {
    (void)user;
    DWORD extra_len = (extra && hdr->extra_len > 0) ? hdr->extra_len : 0;
    DWORD need = (extra_len > 512) ? extra_len : 512;
    IpcQueueEntry *entry = (IpcQueueEntry *)malloc(sizeof(IPC_MSG_HEADER) + need);
    if (!entry) return;
    memcpy(&entry->hdr, hdr, sizeof(IPC_MSG_HEADER));
    if (extra_len > 0) {
        memcpy(entry->extra, extra, extra_len);
        entry->extra[extra_len] = 0;
    } else
        entry->extra[0] = 0;
    PostMessage(g_hWnd, WM_IPC_MSG, 0, (LPARAM)entry);
}

static void log_to_file(const char *fmt, ...) {
    if (!g_logfile) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_logfile, fmt, ap);
    va_end(ap);
    fflush(g_logfile);
}

static void AskBarRespond(JailAction action);

static void AskBarShow(DWORD hook_id, DWORD tid, const char *detail) {
    if (g_ask_pending_tid) {
        AskBarRespond(JAIL_ALLOW);
    }
    g_ask_pending_tid = tid;
    g_ask_pending_hook = hook_id;
    g_ask_stack_count = 0;

    const char *name = (hook_id < HOOK_DEF_COUNT) ? g_hook_defs[hook_id].api_name : "???";
    char label[512];
    if (detail && detail[0])
        StringCchPrintfA(label, sizeof(label), "  JAIL ASK [TID:%04X]  %s", tid, detail);
    else
        StringCchPrintfA(label, sizeof(label), "  JAIL ASK [TID:%04X]  %s(...)", tid, name);
    SetWindowTextA(g_hAskLabel, label);
    ShowWindow(g_hAskBar, SW_SHOW);
    ShowWindow(g_hAskLabel, SW_SHOW);
    ShowWindow(g_hBtnAllow, SW_SHOW);
    ShowWindow(g_hBtnBlock, SW_SHOW);
    ShowWindow(g_hBtnAllowAll, SW_SHOW);
    ShowWindow(g_hBtnStack, SW_SHOW);
    EnableWindow(g_hBtnStack, FALSE);
    SendMessage(g_hWnd, WM_SIZE, 0, 0);
    FlashWindow(g_hWnd, TRUE);
}

static void AskBarRespond(JailAction action) {
    if (!g_ask_pending_tid || !g_jail_shared) return;

    for (int i = 0; i < JAIL_ASK_MAX_PENDING; i++) {
        if (g_jail_shared->slots[i].tid == g_ask_pending_tid) {
            g_jail_shared->slots[i].action = (DWORD)action;

            char evt_name[128];
            JailEventName(evt_name, sizeof(evt_name), g_target.pid, g_ask_pending_tid);
            HANDLE hEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, evt_name);
            if (hEvent) {
                SetEvent(hEvent);
                CloseHandle(hEvent);
            }
            break;
        }
    }

    g_ask_pending_tid = 0;
    g_ask_pending_hook = 0;
    g_ask_stack_count = 0;
    ShowWindow(g_hAskBar, SW_HIDE);
    ShowWindow(g_hAskLabel, SW_HIDE);
    ShowWindow(g_hBtnAllow, SW_HIDE);
    ShowWindow(g_hBtnBlock, SW_HIDE);
    ShowWindow(g_hBtnAllowAll, SW_HIDE);
    ShowWindow(g_hBtnStack, SW_HIDE);
    SendMessage(g_hWnd, WM_SIZE, 0, 0);
}

/* ------------------------------------------------------------------ */
/* Jail Policies dialog                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    HookCategory cat;
} JailPolicyGroup;

static const JailPolicyGroup g_jp_groups[] = {
    { "File",     HOOK_CAT_FILE },
    { "Process",  HOOK_CAT_PROCESS },
    { "Memory",   HOOK_CAT_MEMORY },
    { "Registry", HOOK_CAT_REGISTRY },
    { "Network",  HOOK_CAT_NETWORK },
    { "HTTP",     HOOK_CAT_HTTP },
    { "Module",   HOOK_CAT_MODULE },
    { "Crypto",   HOOK_CAT_CRYPTO },
};
#define JP_GROUP_COUNT (sizeof(g_jp_groups) / sizeof(g_jp_groups[0]))

static HWND g_jpHwnd = NULL;
static HWND g_jpRadios[HOOK_CAT_COUNT][4];
static const char *JP_CLASS = "RemoraJailPolicies";

#define IDC_JP_RADIO_BASE 7200
#define IDC_JP_APPLY      7100
#define IDC_JP_ALLALLOW   7101
#define IDC_JP_ALLBLOCK   7102
#define IDC_JP_ALLLOG     7103
#define IDC_JP_ALLASK     7104

static int JpGetGroupSelection(int g) {
    for (int a = 0; a < 4; a++) {
        if (SendMessageA(g_jpRadios[g][a], BM_GETCHECK, 0, 0) == BST_CHECKED)
            return a;
    }
    return -1;
}

static void JpSetGroupSelection(int g, int action) {
    for (int a = 0; a < 4; a++)
        SendMessageA(g_jpRadios[g][a], BM_SETCHECK, a == action ? BST_CHECKED : BST_UNCHECKED, 0);
}

static LRESULT CALLBACK JailPoliciesWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = GetModuleHandle(NULL);
        HFONT hFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

        const char *actionNames[] = { "Allow", "Log", "Ask", "Block" };
        int colX[] = { 110, 160, 210, 260 };
        for (int a = 0; a < 4; a++) {
            HWND hLbl = CreateWindowExA(0, "STATIC", actionNames[a],
                WS_CHILD | WS_VISIBLE | SS_CENTER,
                colX[a], 4, 45, 16, hwnd, NULL, hInst, NULL);
            SendMessage(hLbl, WM_SETFONT, (WPARAM)hFont, TRUE);
        }

        for (int g = 0; g < (int)JP_GROUP_COUNT; g++) {
            int y = 24 + g * 26;
            HWND hLbl = CreateWindowExA(0, "STATIC", g_jp_groups[g].name,
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
                12, y, 95, 20, hwnd, NULL, hInst, NULL);
            SendMessage(hLbl, WM_SETFONT, (WPARAM)hFont, TRUE);

            for (int a = 0; a < 4; a++) {
                DWORD style = WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON;
                if (a == 0) style |= WS_GROUP;
                g_jpRadios[g][a] = CreateWindowExA(0, "BUTTON", "",
                    style, colX[a] + 14, y, 18, 18,
                    hwnd, (HMENU)(INT_PTR)(IDC_JP_RADIO_BASE + g * 4 + a), hInst, NULL);
            }

            HookCategory cat = g_jp_groups[g].cat;
            int counts[4] = {0};
            for (int i = 0; i < (int)HOOK_DEF_COUNT; i++) {
                if (g_hook_defs[i].category == cat) {
                    int act = (int)JailGetAction((HookId)i);
                    if (act >= 0 && act < 4) counts[act]++;
                }
            }
            int best = 0;
            for (int a = 1; a < 4; a++)
                if (counts[a] > counts[best]) best = a;
            if (counts[best] > 0)
                JpSetGroupSelection(g, best);
        }

        int btnY = 24 + (int)JP_GROUP_COUNT * 26 + 12;
        struct { int id; const char *text; int x; } btns[] = {
            { IDC_JP_ALLALLOW, "All Allow", 12 },
            { IDC_JP_ALLLOG,   "All Log",   82 },
            { IDC_JP_ALLASK,   "All Ask",   152 },
            { IDC_JP_ALLBLOCK, "All Block", 222 },
            { IDC_JP_APPLY,    "Apply",     302 },
        };
        for (int b = 0; b < 5; b++) {
            HWND hBtn = CreateWindowExA(0, "BUTTON", btns[b].text,
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
                btns[b].x, btnY, 64, 26, hwnd, (HMENU)(INT_PTR)btns[b].id, hInst, NULL);
            SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
        }
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_JP_APPLY:
            for (int g = 0; g < (int)JP_GROUP_COUNT; g++) {
                int sel = JpGetGroupSelection(g);
                if (sel < 0) continue;
                HookCategory cat = g_jp_groups[g].cat;
                for (int i = 0; i < (int)HOOK_DEF_COUNT; i++) {
                    if (g_hook_defs[i].category == cat) {
                        JailSetAction((HookId)i, (JailAction)sel);
                        if (g_jail_shared)
                            g_jail_shared->actions[i] = (DWORD)sel;
                    }
                }
            }
            LoggerAppend("[*] Jail policies applied\n", LOG_COLOR_INFO);
            DestroyWindow(hwnd);
            return 0;
        case IDC_JP_ALLALLOW:
            for (int g = 0; g < (int)JP_GROUP_COUNT; g++)
                JpSetGroupSelection(g, JAIL_ALLOW);
            return 0;
        case IDC_JP_ALLLOG:
            for (int g = 0; g < (int)JP_GROUP_COUNT; g++)
                JpSetGroupSelection(g, JAIL_LOG);
            return 0;
        case IDC_JP_ALLASK:
            for (int g = 0; g < (int)JP_GROUP_COUNT; g++)
                JpSetGroupSelection(g, JAIL_ASK);
            return 0;
        case IDC_JP_ALLBLOCK:
            for (int g = 0; g < (int)JP_GROUP_COUNT; g++)
                JpSetGroupSelection(g, JAIL_BLOCK);
            return 0;
        }
        break;
    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        g_jpHwnd = NULL;
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void ShowJailPoliciesDialog(HWND hwndParent) {
    if (g_jpHwnd) {
        SetForegroundWindow(g_jpHwnd);
        return;
    }

    static BOOL registered = FALSE;
    if (!registered) {
        WNDCLASSEXA wc = {0};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = JailPoliciesWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = JP_CLASS;
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        RegisterClassExA(&wc);
        registered = TRUE;
    }

    int h = 24 + (int)JP_GROUP_COUNT * 26 + 100;
    int w = 390;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    g_jpHwnd = CreateWindowExA(0, JP_CLASS, "Jail Policies",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        (screenW - w) / 2, (screenH - h) / 2, w, h,
        hwndParent, NULL, GetModuleHandle(NULL), NULL);

    if (g_jpHwnd) {
        ShowWindow(g_jpHwnd, SW_SHOW);
        UpdateWindow(g_jpHwnd);
    }
}

/* ------------------------------------------------------------------ */
/* Auto-dump config dialog                                              */
/* ------------------------------------------------------------------ */

#define IDC_AD_ENABLE   4001
#define IDC_AD_MINSIZE  4002
#define IDC_AD_RX       4003
#define IDC_AD_RWX      4004
#define IDC_AD_X        4005
#define IDC_AD_FOLDER   4006
#define IDC_AD_BROWSE   4007

static int CALLBACK BrowseFolderCallback(HWND hwnd, UINT msg, LPARAM lp, LPARAM data) {
    if (msg == BFFM_INITIALIZED && data)
        SendMessageA(hwnd, BFFM_SETSELECTIONA, TRUE, data);
    return 0;
}

static INT_PTR CALLBACK AutoDumpDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG: {
        AutoDumpCfg *cfg = g_jail_shared ? &g_jail_shared->autodump : NULL;
        BOOL enabled = cfg ? cfg->enabled : FALSE;
        DWORD minSize = cfg ? cfg->min_size : 0x1000;
        DWORD mask = cfg ? cfg->prot_mask : (ADUMP_PROT_RX | ADUMP_PROT_RWX);

        CheckDlgButton(hwnd, IDC_AD_ENABLE, enabled ? BST_CHECKED : BST_UNCHECKED);
        char buf[32];
        wsprintfA(buf, "%X", minSize);
        SetDlgItemTextA(hwnd, IDC_AD_MINSIZE, buf);
        CheckDlgButton(hwnd, IDC_AD_RX,  (mask & ADUMP_PROT_RX)  ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hwnd, IDC_AD_RWX, (mask & ADUMP_PROT_RWX) ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hwnd, IDC_AD_X,   (mask & ADUMP_PROT_X)   ? BST_CHECKED : BST_UNCHECKED);

        if (!g_autodump_folder[0]) {
            GetModuleFileNameA(NULL, g_autodump_folder, MAX_PATH);
            char *sl = strrchr(g_autodump_folder, '\\');
            if (sl) *(sl + 1) = '\0';
            strncat(g_autodump_folder, "dumps", MAX_PATH - strlen(g_autodump_folder) - 1);
        }
        SetDlgItemTextA(hwnd, IDC_AD_FOLDER, g_autodump_folder);
        return TRUE;
    }
    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        HWND hFolder = GetDlgItem(hwnd, IDC_AD_FOLDER);
        HWND hBrowse = GetDlgItem(hwnd, IDC_AD_BROWSE);
        if (hFolder && hBrowse) {
            RECT fr;
            GetWindowRect(hFolder, &fr);
            MapWindowPoints(NULL, hwnd, (POINT *)&fr, 2);
            int btnW = 38;
            int margin = 8;
            int browseX = rc.right - margin - btnW;
            int editW = browseX - fr.left - 4;
            if (editW < 60) editW = 60;
            MoveWindow(hFolder, fr.left, fr.top, editW, fr.bottom - fr.top, TRUE);
            MoveWindow(hBrowse, browseX, fr.top, btnW, fr.bottom - fr.top, TRUE);
        }
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_AD_BROWSE) {
            char curFolder[MAX_PATH] = {0};
            GetDlgItemTextA(hwnd, IDC_AD_FOLDER, curFolder, MAX_PATH);
            BROWSEINFOA bi = {0};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = "Select auto-dump output folder";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            bi.lParam = (LPARAM)curFolder;
            bi.lpfn = BrowseFolderCallback;
            LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
            if (pidl) {
                char path[MAX_PATH];
                if (SHGetPathFromIDListA(pidl, path))
                    SetDlgItemTextA(hwnd, IDC_AD_FOLDER, path);
                CoTaskMemFree(pidl);
            }
            return TRUE;
        }
        if (LOWORD(wp) == IDOK) {
            if (g_jail_shared) {
                g_jail_shared->autodump.enabled = IsDlgButtonChecked(hwnd, IDC_AD_ENABLE) == BST_CHECKED;
                char buf[32] = {0};
                GetDlgItemTextA(hwnd, IDC_AD_MINSIZE, buf, sizeof(buf));
                DWORD ms = 0;
                sscanf(buf, "%X", &ms);
                if (ms == 0) ms = 0x1000;
                g_jail_shared->autodump.min_size = ms;
                DWORD mask = 0;
                if (IsDlgButtonChecked(hwnd, IDC_AD_RX)  == BST_CHECKED) mask |= ADUMP_PROT_RX;
                if (IsDlgButtonChecked(hwnd, IDC_AD_RWX) == BST_CHECKED) mask |= ADUMP_PROT_RWX;
                if (IsDlgButtonChecked(hwnd, IDC_AD_X)   == BST_CHECKED) mask |= ADUMP_PROT_X;
                if (mask == 0) mask = ADUMP_PROT_RX | ADUMP_PROT_RWX;
                g_jail_shared->autodump.prot_mask = mask;
            }
            GetDlgItemTextA(hwnd, IDC_AD_FOLDER, g_autodump_folder, MAX_PATH);
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

static WORD *AdAlignDword(WORD *p) {
    ULONG_PTR a = (ULONG_PTR)p;
    a = (a + 3) & ~(ULONG_PTR)3;
    return (WORD *)a;
}

static WORD *AdAddCtrl(WORD *p, DWORD style, short x, short y, short cx, short cy,
                       WORD id, WORD cls, const char *text) {
    p = AdAlignDword(p);
    DLGITEMTEMPLATE *itm = (DLGITEMTEMPLATE *)p;
    itm->style = style;
    itm->x = x; itm->y = y; itm->cx = cx; itm->cy = cy;
    itm->id = id;
    p = (WORD *)(itm + 1);
    *p++ = 0xFFFF; *p++ = cls;
    while (*text) *p++ = (WORD)(unsigned char)*text++;
    *p++ = 0;
    *p++ = 0;
    return p;
}

static void ShowAutoDumpDialog(HWND hParent) {
    BYTE tmpl[2048];
    memset(tmpl, 0, sizeof(tmpl));
    WORD *p = (WORD *)tmpl;

    DLGTEMPLATE *hdr = (DLGTEMPLATE *)p;
    hdr->style = DS_MODALFRAME | DS_CENTER | DS_SETFONT | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME;
    hdr->cdit = 11;
    hdr->cx = 320;
    hdr->cy = 130;
    p = (WORD *)(hdr + 1);
    *p++ = 0; *p++ = 0;
    /* title */
    { const char *t = "Auto Dump"; while (*t) *p++ = (WORD)(unsigned char)*t++; *p++ = 0; }
    /* font (DS_SETFONT): size then name */
    *p++ = 9;
    { const char *f = "Segoe UI"; while (*f) *p++ = (WORD)(unsigned char)*f++; *p++ = 0; }

    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP,
        8,8,100,10, IDC_AD_ENABLE, 0x0080, "Enable auto-dump");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|SS_LEFT,
        8,24,56,10, (WORD)-1, 0x0082, "Min size (hex):");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_AUTOHSCROLL,
        66,22,40,13, IDC_AD_MINSIZE, 0x0081, "");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP,
        120,8,30,10, IDC_AD_RX, 0x0080, "RX");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP,
        155,8,35,10, IDC_AD_RWX, 0x0080, "RWX");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP,
        195,8,25,10, IDC_AD_X, 0x0080, "X");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|SS_LEFT,
        8,42,30,10, (WORD)-1, 0x0082, "Folder:");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_AUTOHSCROLL,
        40,40,230,13, IDC_AD_FOLDER, 0x0081, "");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|WS_TABSTOP,
        274,40,38,13, IDC_AD_BROWSE, 0x0080, "...");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|WS_DISABLED|SS_LEFT,
        8,60,304,10, (WORD)-1, 0x0082,
        "Saves memory to disk when VirtualProtect size >= min and protection flags match.");
    p = AdAddCtrl(p, WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON|WS_TABSTOP,
        205,110,50,14, IDOK, 0x0080, "OK");

    DialogBoxIndirectParamA(GetModuleHandleA(NULL),
        (DLGTEMPLATE *)tmpl, hParent, AutoDumpDlgProc, 0);
}

static void HandleAutoDump(IPC_MSG_HEADER *hdr, const void *extra) {
    if (!g_target.hProcess || !extra) return;
    const AutoDumpRequest *req = (const AutoDumpRequest *)extra;
    if (req->size == 0 || req->size > 256 * 1024 * 1024) return;

    if (!g_autodump_folder[0]) {
        GetModuleFileNameA(NULL, g_autodump_folder, MAX_PATH);
        char *sl = strrchr(g_autodump_folder, '\\');
        if (sl) *(sl + 1) = '\0';
        strncat(g_autodump_folder, "dumps", MAX_PATH - strlen(g_autodump_folder) - 1);
    }
    CreateDirectoryA(g_autodump_folder, NULL);

    char filename[MAX_PATH];
    snprintf(filename, MAX_PATH, "%s\\autodump_%03d_%I64X_%I64X.bin",
        g_autodump_folder, g_autodump_counter++,
        req->address, req->address + req->size);

    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LoggerAppendFmt(LOG_COLOR_BLOCK, "[ADUMP] Failed to create: %s\n", filename);
        return;
    }

    BYTE chunk[4096];
    UINT64 offset = 0;
    UINT64 written = 0;
    while (offset < req->size) {
        SIZE_T toRead = (req->size - offset > 4096) ? 4096 : (SIZE_T)(req->size - offset);
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(g_target.hProcess,
                (LPCVOID)(UINT_PTR)(req->address + offset),
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

    const char *protStr = "??";
    switch (req->new_prot & 0xFF) {
    case PAGE_EXECUTE:           protStr = "X";   break;
    case PAGE_EXECUTE_READ:      protStr = "RX";  break;
    case PAGE_EXECUTE_READWRITE: protStr = "RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: protStr = "RWX"; break;
    }
    LoggerAppendFmt(LOG_COLOR_RETURN,
        "[ADUMP] Saved 0x%I64X (%I64u bytes, prot=%s) -> %s\n",
        req->address, written, protStr, filename);
}

/* ------------------------------------------------------------------ */

static BOOL PassesCategoryFilter(DWORD hook_id) {
    if (hook_id >= HOOK_DEF_COUNT) return TRUE;
    HookCategory cat = g_hook_defs[hook_id].category;
    if (cat < HOOK_CAT_COUNT)
        return g_catFilter[cat];
    return TRUE;
}

static void ProcessIpcMessage(IpcQueueEntry *entry) {
    IPC_MSG_HEADER *hdr = &entry->hdr;
    SummaryAccumulate(&g_summary, hdr, entry->extra,
        (hdr->extra_len > 0) ? hdr->extra_len : 0);
    switch (hdr->msg_type) {
        case MSG_HOOK_CALL: {
            if (!PassesCategoryFilter(hdr->hook_id)) break;
            const char *name = "???";
            if (hdr->hook_id < HOOK_DEF_COUNT)
                name = g_hook_defs[hdr->hook_id].api_name;
            LoggerAppendFmt(LOG_COLOR_API, "[TID:%04X] 0x%016llX %s(",
                hdr->tid, hdr->ret_addr, name);
            log_to_file("[TID:%04X] 0x%016llX %s(", hdr->tid, hdr->ret_addr, name);
            for (DWORD i = 0; i < hdr->arg_count; i++) {
                if (i > 0) { LoggerAppend(", ", LOG_COLOR_API); log_to_file(", "); }
                LoggerAppendFmt(LOG_COLOR_API, "0x%llX", hdr->args[i]);
                log_to_file("0x%llX", hdr->args[i]);
            }
            LoggerAppend(")\n", LOG_COLOR_API);
            log_to_file(")\n");
            break;
        }
        case MSG_HOOK_RETURN: {
            if (!PassesCategoryFilter(hdr->hook_id)) break;
            const char *name = "???";
            if (hdr->hook_id < HOOK_DEF_COUNT)
                name = g_hook_defs[hdr->hook_id].api_name;
            LoggerAppendFmt(LOG_COLOR_RETURN, "  -> %s = 0x%llX\n", name, hdr->ret_value);
            log_to_file("  -> %s = 0x%llX\n", name, hdr->ret_value);
            break;
        }
        case MSG_LOG_TEXT: {
            if (!PassesCategoryFilter(hdr->hook_id)) break;
            const char *text = entry->extra[0] ? entry->extra : NULL;
            if (text) {
                log_to_file("[TID:%04X] 0x%016llX %s\n", hdr->tid, hdr->ret_addr, text);
                if (g_coalesce && hdr->hook_id == HOOK_OpenProcess
                    && g_target.pid && strstr(text, "QUERY_INFORMATION")) {
                    char pid_tag[32];
                    wsprintfA(pid_tag, "PID=%u", g_target.pid);
                    if (strstr(text, pid_tag))
                        break;
                }
                if (g_coalesce && hdr->hook_id == HOOK_VirtualAlloc
                    && hdr->args[1] <= 0x1000)
                    break;
                if (!CoalesceTryMerge(hdr->tid, hdr->hook_id, text)) {
                    LoggerAppendFmt(LOG_COLOR_API, "[TID:%04X] 0x%016llX %s\n",
                        hdr->tid, hdr->ret_addr, text);
                }
            }
            break;
        }
        case MSG_DLL_LOADED: {
            if (!g_catFilter[FILT_GENERAL_IDX]) break;
            const char *dll_name = entry->extra[0] ? entry->extra : NULL;
            if (dll_name) {
                if (strncmp(dll_name, "[diag]", 6) == 0) {
                    if (g_debuglog)
                        LoggerAppendFmt(RGB(180, 120, 255), "%s\n", dll_name);
                    log_to_file("%s\n", dll_name);
                } else {
                    char dll_key[512];
                    snprintf(dll_key, sizeof(dll_key), "DLL loaded: %s @ %016llX",
                        dll_name, hdr->args[0]);
                    log_to_file("[+] %s\n", dll_key);
                    if (!CoalesceTryMerge(hdr->tid, 0xFFFF, dll_key)) {
                        LoggerAppendFmt(LOG_COLOR_VERBOSE, "[+] %s\n", dll_key);
                    }
                }
            }
            break;
        }
        case MSG_JAIL_ASK: {
            const char *detail = entry->extra[0] ? entry->extra : NULL;
            if (detail)
                LoggerAppendFmt(LOG_COLOR_API, "[TID:%04X] 0x%016llX %s\n",
                    hdr->tid, hdr->ret_addr, detail);
            LoggerAppendFmt(LOG_COLOR_WARN, "[?] JAIL ASK [TID:%04X] %s -- waiting for user\n",
                hdr->tid, (hdr->hook_id < HOOK_DEF_COUNT) ? g_hook_defs[hdr->hook_id].api_name : "???");
            if (LoggerGetAutoScroll())
                LoggerScrollToBottom();
            AskBarShow(hdr->hook_id, hdr->tid, detail);
            break;
        }
        case MSG_HOOK_CALLSTACK: {
            DWORD frame_count = hdr->arg_count;
            if (frame_count > IPC_MAX_STACK_FRAMES) frame_count = IPC_MAX_STACK_FRAMES;
            if (frame_count > 0 && hdr->extra_len >= frame_count * sizeof(UINT64)) {
                memcpy(g_ask_stack_frames, entry->extra, frame_count * sizeof(UINT64));
                g_ask_stack_count = frame_count;
                if (IsWindowVisible(g_hBtnStack))
                    EnableWindow(g_hBtnStack, TRUE);
            }
            break;
        }
        case MSG_HOOK_BUFFER: {
            if (!PassesCategoryFilter(hdr->hook_id)) break;
            DWORD buf_type = (DWORD)hdr->args[0];
            DWORD total_len = (DWORD)hdr->args[1];
            DWORD cap_len = hdr->extra_len;
            const BYTE *data = (const BYTE *)entry->extra;
            const char *type_str = (buf_type == BUFFER_INPUT) ? "input" :
                                   (buf_type == BUFFER_OUTPUT) ? "output" : "key";
            const char *name = (hdr->hook_id < HOOK_DEF_COUNT)
                ? g_hook_defs[hdr->hook_id].api_name : "???";
            if (cap_len > total_len) cap_len = total_len;
            DWORD show = (cap_len > 32) ? 32 : cap_len;
            char hex[128];
            int pos = 0;
            for (DWORD i = 0; i < show; i++)
                pos += wsprintfA(hex + pos, "%02X ", data[i]);
            if (cap_len > show)
                pos += wsprintfA(hex + pos, "...");
            if (cap_len < total_len)
                LoggerAppendFmt(LOG_COLOR_VERBOSE, "  %s %s (%u/%u bytes): %s\n",
                    name, type_str, cap_len, total_len, hex);
            else
                LoggerAppendFmt(LOG_COLOR_VERBOSE, "  %s %s (%u bytes): %s\n",
                    name, type_str, cap_len, hex);
            log_to_file("  %s %s (%u/%u bytes): %s\n",
                name, type_str, cap_len, total_len, hex);
            break;
        }
        case MSG_AUTO_DUMP:
            if (hdr->extra_len >= sizeof(AutoDumpRequest))
                HandleAutoDump(hdr, entry->extra);
            break;
        case MSG_HOOK_READY:
            LoggerAppend("[+] Hook DLL initialized, all hooks active.\n", LOG_COLOR_RETURN);
            if (g_target.remote_dll_path) {
                VirtualFreeEx(g_target.hProcess, g_target.remote_dll_path, 0, MEM_RELEASE);
                g_target.remote_dll_path = NULL;
            }
            if (g_target.ep_patched) {
                LoggerAppendFmt(LOG_COLOR_INFO, "[*] Entry point @ %016llX (EB FE spin)\n",
                    g_target.ep_addr);
                SetTimer(g_hWnd, IDT_EP_SUSPEND, 10, NULL);
            } else {
                ToolbarUpdateIcon(TB_STATE_IDLE);
            }
            break;
    }
    free(entry);
}

typedef struct {
    char path[MAX_PATH];
    char args[1024];
} LaunchParams;

#define LAUNCH_OK           0
#define LAUNCH_ERR_IPC      1
#define LAUNCH_ERR_PROCESS  2
#define LAUNCH_ERR_INJECT   3

static DWORD WINAPI LaunchThreadProc(LPVOID param) {
    LaunchParams *lp = (LaunchParams *)param;

    if (!IpcServerCreate(&g_ipc, GetCurrentProcessId(), OnIpcMessage, NULL)) {
        PostMessage(g_hWnd, WM_LAUNCH_DONE, LAUNCH_ERR_IPC, 0);
        free(lp);
        return 1;
    }

    char shared_name[128];
    JailSharedName(shared_name, sizeof(shared_name), GetCurrentProcessId());
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    BOOL sd_ok = ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:(A;;GA;;;OW)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL);

    g_jail_shared_mapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE, sd_ok ? &sa : NULL, PAGE_READWRITE, 0, sizeof(JailSharedMem), shared_name);

    if (sa.lpSecurityDescriptor)
        LocalFree(sa.lpSecurityDescriptor);
    if (g_jail_shared_mapping) {
        g_jail_shared = (JailSharedMem *)MapViewOfFile(
            g_jail_shared_mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(JailSharedMem));
        if (g_jail_shared) {
            memset(g_jail_shared, 0, sizeof(JailSharedMem));
            for (int i = 0; i < HOOK_COUNT; i++)
                g_jail_shared->actions[i] = (DWORD)JailGetAction((HookId)i);
            JailSyncConditions(g_jail_shared);
            JailRulesSyncToShared(g_jail_shared);
            g_jail_shared->capture_max_bytes = CAPTURE_DEFAULT_MAX;
        }
    }

    if (!ProcessCreate(&g_target, lp->path, lp->args)) {
        IpcServerDestroy(&g_ipc);
        PostMessage(g_hWnd, WM_LAUNCH_DONE, LAUNCH_ERR_PROCESS, (LPARAM)GetLastError());
        free(lp);
        return 1;
    }

    char dll_path[MAX_PATH];
    GetModuleFileNameA(NULL, dll_path, MAX_PATH);
    char *slash = strrchr(dll_path, '\\');
    if (slash) strcpy(slash + 1, "hookdll.dll");

    if (!ProcessInjectDll(&g_target, dll_path)) {
        DWORD err = GetLastError();
        TerminateProcess(g_target.hProcess, 1);
        ProcessClose(&g_target);
        IpcServerDestroy(&g_ipc);
        PostMessage(g_hWnd, WM_LAUNCH_DONE, LAUNCH_ERR_INJECT, (LPARAM)err);
        free(lp);
        return 1;
    }

    if (g_break_at_oep) {
        BOOL patched = FALSE;
        for (int attempt = 0; attempt < 20; attempt++) {
            if (ProcessPatchEntryPoint(&g_target)) {
                patched = TRUE;
                break;
            }
            Sleep(1);
        }
        if (!patched)
            LoggerAppend("[!] OEP-patch: all retries failed -- target will run without break\n",
                LOG_COLOR_BLOCK);
    }

    ResumeThread(g_target.hThread);
    g_target.suspended = FALSE;

    PostMessage(g_hWnd, WM_LAUNCH_DONE, LAUNCH_OK, 0);
    free(lp);
    return 0;
}

static void CALLBACK OnProcessExit(PVOID context, BOOLEAN timedOut) {
    (void)context; (void)timedOut;
    PostMessage(g_hWnd, WM_TARGET_EXIT, 0, 0);
}

static void LaunchTarget(const char *path, const char *args) {
    strncpy(g_last_exe, path, MAX_PATH - 1);
    g_last_exe[MAX_PATH - 1] = 0;
    strncpy(g_last_args, args ? args : "", sizeof(g_last_args) - 1);
    g_last_args[sizeof(g_last_args) - 1] = 0;
    if (!g_target.hProcess)
        LoggerClear();
    SummaryInit(&g_summary);
    ToolbarUpdateIcon(TB_STATE_LOADING);
    EnableStartButton(FALSE);
    LoggerAppendFmt(LOG_COLOR_INFO, "[*] Starting program: %s\n", path);

    if (g_silence_boring) {
        JailApplyBoringPreset();
        LoggerAppend("[*] Boring API preset: silenced GetModuleHandle, GetProcAddress, "
            "ReadProcessMemory, VirtualAlloc, VirtualProtect, OpenProcess "
            "(Config -> Silence Boring APIs)\n", LOG_COLOR_VERBOSE);
    }

    LaunchParams *lp = (LaunchParams *)malloc(sizeof(LaunchParams));
    if (!lp) return;
    strncpy(lp->path, path, MAX_PATH - 1);
    lp->path[MAX_PATH - 1] = 0;
    strncpy(lp->args, args, sizeof(lp->args) - 1);
    lp->args[sizeof(lp->args) - 1] = 0;

    HANDLE hThread = CreateThread(NULL, 0, LaunchThreadProc, lp, 0, NULL);
    if (hThread)
        CloseHandle(hThread);
    else {
        free(lp);
        ToolbarUpdateIcon(TB_STATE_IDLE);
        EnableStartButton(TRUE);
    }
}

/* ------------------------------------------------------------------ */
/* H1: Rich Edit subclass -- double-click a 16-digit hex addr -> dasm  */
/* ------------------------------------------------------------------ */

static WNDPROC g_prevRichEditProc = NULL;

static LRESULT CALLBACK RichEditSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CONTEXTMENU) {
        DWORD selStart = 0, selEnd = 0;
        SendMessageW(hWnd, EM_GETSEL, (WPARAM)&selStart, (LPARAM)&selEnd);
        if (selStart != selEnd) {
            HMENU hPop = CreatePopupMenu();
            AppendMenuA(hPop, MF_STRING, 1, "Copy");
            int x = GET_X_LPARAM(lParam), y = GET_Y_LPARAM(lParam);
            int cmd = TrackPopupMenu(hPop, TPM_RETURNCMD | TPM_RIGHTBUTTON, x, y, 0, hWnd, NULL);
            DestroyMenu(hPop);
            if (cmd == 1)
                SendMessageW(hWnd, WM_COPY, 0, 0);
        }
        return 0;
    }
    LRESULT ret = CallWindowProcA(g_prevRichEditProc, hWnd, msg, wParam, lParam);
    if (msg == WM_LBUTTONDBLCLK && g_target.hProcess && g_dasm_dblclk) {
        /* After default proc sets word-selection, get the clicked line */
        DWORD selStart = 0;
        SendMessageW(hWnd, EM_GETSEL, (WPARAM)&selStart, 0);
        int lineIdx = (int)SendMessageW(hWnd, EM_LINEFROMCHAR, (WPARAM)selStart, 0);
        WCHAR wline[512];
        *(WORD*)wline = (WORD)(sizeof(wline)/sizeof(WCHAR) - 2);
        int lineLen = (int)SendMessageW(hWnd, EM_GETLINE, (WPARAM)lineIdx, (LPARAM)wline);
        wline[lineLen] = 0;
        char line[512];
        WideCharToMultiByte(CP_ACP, 0, wline, -1, line, sizeof(line), NULL, NULL);
        /* Scan for first run of exactly 16 hex digits */
        UINT64 addr = 0;
        for (int i = 0; line[i] && !addr; i++) {
            int j = 0;
            while (isxdigit((unsigned char)line[i + j])) j++;
            if (j == 16 && (i == 0 || !isxdigit((unsigned char)line[i - 1])))
                sscanf(line + i, "%16I64x", &addr);
        }
        if (addr) {
            DasmOpen(GetParent(hWnd), g_target.hProcess);
            DasmGotoAddress(addr);
        }
    }
    return ret;
}

static HFONT g_about_link_font;
static HCURSOR g_about_hand;
static HBITMAP g_about_logo;

static INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG: {
        g_about_hand = LoadCursor(NULL, IDC_HAND);
        HFONT base = (HFONT)SendDlgItemMessage(hDlg, IDC_ABOUT_LINK, WM_GETFONT, 0, 0);
        LOGFONT lf;
        GetObject(base, sizeof(lf), &lf);
        lf.lfUnderline = TRUE;
        g_about_link_font = CreateFontIndirect(&lf);
        SendDlgItemMessage(hDlg, IDC_ABOUT_LINK, WM_SETFONT, (WPARAM)g_about_link_font, TRUE);
        g_about_logo = LoadBitmapA(GetModuleHandle(NULL), MAKEINTRESOURCEA(IDB_LOGO));
        if (g_about_logo)
            SendDlgItemMessage(hDlg, IDC_ABOUT_LOGO, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)g_about_logo);
        char build[64];
        wsprintfA(build, "Build: %s %s", __DATE__, __TIME__);
        SetDlgItemTextA(hDlg, IDC_ABOUT_BUILD, build);
        return TRUE;
    }
    case WM_CTLCOLORSTATIC:
        if ((HWND)lParam == GetDlgItem(hDlg, IDC_ABOUT_LINK)) {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, RGB(0, 102, 204));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetStockObject(NULL_BRUSH);
        }
        break;
    case WM_SETCURSOR:
        if ((HWND)wParam == GetDlgItem(hDlg, IDC_ABOUT_LINK)) {
            SetCursor(g_about_hand);
            SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
            return TRUE;
        }
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_ABOUT_LINK && HIWORD(wParam) == STN_CLICKED) {
            ShellExecuteA(NULL, "open", "https://github.com/arkup/remora", NULL, NULL, SW_SHOWNORMAL);
            return TRUE;
        }
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            if (g_about_link_font) { DeleteObject(g_about_link_font); g_about_link_font = NULL; }
            if (g_about_logo) { DeleteObject(g_about_logo); g_about_logo = NULL; }
            EndDialog(hDlg, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = ((CREATESTRUCT *)lParam)->hInstance;
            LoadLibrary("Msftedit.dll");

            CreateMainToolbar(hWnd);

            g_hRichEdit = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_NOHIDESEL,
                0, 0, 100, 100, hWnd, (HMENU)IDC_RICHEDIT, hInst, NULL);

            g_hStatus = CreateWindow(STATUSCLASSNAME, "",
                WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                0, 0, 0, 0, hWnd, (HMENU)IDC_STATUS, hInst, NULL);

            DragAcceptFiles(hWnd, TRUE);

            // Ask bar (hidden until JAIL_ASK fires)
            g_hAskBar = CreateWindowEx(0, "STATIC", "",
                WS_CHILD | WS_BORDER | SS_LEFT,
                0, 0, 100, 30, hWnd, (HMENU)IDC_ASK_BAR, hInst, NULL);
            g_hAskLabel = CreateWindow("EDIT", "",
                WS_CHILD | ES_READONLY | ES_AUTOHSCROLL,
                2, 2, 96, 26, hWnd, (HMENU)IDC_ASK_LABEL, hInst, NULL);
            g_hBtnAllow = CreateWindow("BUTTON", "Allow",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 70, 24, hWnd, (HMENU)IDC_BTN_ALLOW, hInst, NULL);
            g_hBtnBlock = CreateWindow("BUTTON", "Block",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 70, 24, hWnd, (HMENU)IDC_BTN_BLOCK, hInst, NULL);
            g_hBtnAllowAll = CreateWindow("BUTTON", "Allow All",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 80, 24, hWnd, (HMENU)IDC_BTN_ALLOW_ALL, hInst, NULL);
            g_hBtnStack = CreateWindow("BUTTON", "Stack",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 70, 24, hWnd, (HMENU)IDC_BTN_STACK, hInst, NULL);
            ShowWindow(g_hBtnAllow, SW_HIDE);
            ShowWindow(g_hBtnBlock, SW_HIDE);
            ShowWindow(g_hBtnAllowAll, SW_HIDE);
            ShowWindow(g_hBtnStack, SW_HIDE);

            // Find bar (hidden until Ctrl+F)
            g_hFindEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_CHILD | ES_AUTOHSCROLL,
                0, 0, 200, 22, hWnd, (HMENU)IDC_FIND_EDIT, hInst, NULL);
            g_hBtnFindNext = CreateWindow("BUTTON", "Next",
                WS_CHILD | BS_PUSHBUTTON,
                0, 0, 50, 22, hWnd, (HMENU)IDC_BTN_FIND_NEXT, hInst, NULL);
            g_hBtnFindPrev = CreateWindow("BUTTON", "Prev",
                WS_CHILD | BS_PUSHBUTTON,
                0, 0, 50, 22, hWnd, (HMENU)IDC_BTN_FIND_PREV, hInst, NULL);
            g_hBtnFindClose = CreateWindow("BUTTON", "X",
                WS_CHILD | BS_PUSHBUTTON,
                0, 0, 24, 22, hWnd, (HMENU)IDC_BTN_FIND_CLOSE, hInst, NULL);

            g_hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
            g_hAskBrush = CreateSolidBrush(RGB(255, 200, 50));
            SendMessage(g_hAskLabel, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessage(g_hBtnAllow, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessage(g_hBtnBlock, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessage(g_hBtnAllowAll, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessage(g_hBtnStack, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessage(g_hFindEdit, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessage(g_hBtnFindNext, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessage(g_hBtnFindPrev, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessage(g_hBtnFindClose, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            LoggerInit(g_hRichEdit);
            SetTimer(hWnd, IDT_LOG_FLUSH, 16, NULL);
            g_prevRichEditProc = (WNDPROC)(LONG_PTR)SetWindowLongPtrA(
                g_hRichEdit, GWLP_WNDPROC, (LONG_PTR)RichEditSubclassProc);

            HMENU hMenu = GetMenu(hWnd);
            HMENU hJail = GetSubMenu(hMenu, 3);
            JailInit(hJail);
            {
                char cfg_ini[MAX_PATH];
                GetConfigIniPath(cfg_ini, MAX_PATH);
                JailLoadPolicy(cfg_ini);
                LoadConfigToggles(cfg_ini, hWnd);
            }
            JailRulesInit();
            EnableMenuItem(hMenu, IDM_FILE_TERMINATE, MF_BYCOMMAND | MF_GRAYED);
            EnableMenuItem(hMenu, IDM_EDIT_SUSPEND, MF_BYCOMMAND | MF_GRAYED);
            EnableMenuItem(hMenu, IDM_CFG_BUFCAPTURE, MF_BYCOMMAND | MF_GRAYED);
            if (g_debuglog)
                CheckMenuItem(hMenu, IDM_VIEW_DEBUGLOG, MF_CHECKED);

            if (g_debuglog) {
                g_logfile = fopen("remora_debug.log", "w");
                if (g_logfile) setvbuf(g_logfile, NULL, _IONBF, 0);
            }

            LoggerAppend("Remora idle -- looking for a shark.\n\n", LOG_COLOR_INFO);
            LoggerAppend("  Ctrl+O    Open target executable\n", LOG_COLOR_VERBOSE);
            LoggerAppend("  Ctrl+J    Jail policy editor\n", LOG_COLOR_VERBOSE);
            LoggerAppend("  Ctrl+M    Memory viewer\n", LOG_COLOR_VERBOSE);
            LoggerAppend("  Ctrl+R    Jail rules\n", LOG_COLOR_VERBOSE);
            LoggerAppend("  Ctrl+B    Sandbox report\n", LOG_COLOR_VERBOSE);
            LoggerAppend("  Ctrl+F    Find in log\n", LOG_COLOR_VERBOSE);
            LoggerAppend("  F12       Suspend / resume target\n\n", LOG_COLOR_VERBOSE);
            return 0;
        }

        case WM_SIZE: {
            RECT rc;
            GetClientRect(hWnd, &rc);
            int status_h = 22;
            int tbH = GetToolbarHeight();
            int find_bar_h = 0;
            int ask_bar_h = 0;

            SendMessage(g_hStatus, WM_SIZE, 0, 0);
            if (g_hToolbar)
                MoveWindow(g_hToolbar, 0, 0, rc.right, tbH, TRUE);

            if (g_find_visible) {
                find_bar_h = 28;
                int fy = tbH + 3;
                MoveWindow(g_hFindEdit, 4, fy, rc.right - 170, 22, TRUE);
                MoveWindow(g_hBtnFindPrev, rc.right - 160, fy, 50, 22, TRUE);
                MoveWindow(g_hBtnFindNext, rc.right - 106, fy, 50, 22, TRUE);
                MoveWindow(g_hBtnFindClose, rc.right - 52, fy, 24, 22, TRUE);
            }

            if (IsWindowVisible(g_hAskBar)) {
                ask_bar_h = 30;
                int bar_y = rc.bottom - status_h - ask_bar_h;
                int btn_x = rc.right - 314;
                if (btn_x < 200) btn_x = 200;
                MoveWindow(g_hAskBar, 0, bar_y, rc.right, ask_bar_h, TRUE);
                MoveWindow(g_hAskLabel, 2, bar_y + 2, btn_x - 4, ask_bar_h - 4, TRUE);
                MoveWindow(g_hBtnAllow, btn_x, bar_y + 3, 70, 24, TRUE);
                MoveWindow(g_hBtnBlock, btn_x + 74, bar_y + 3, 70, 24, TRUE);
                MoveWindow(g_hBtnAllowAll, btn_x + 148, bar_y + 3, 80, 24, TRUE);
                MoveWindow(g_hBtnStack, btn_x + 232, bar_y + 3, 70, 24, TRUE);
            }

            MoveWindow(g_hRichEdit, 0, tbH + find_bar_h, rc.right,
                rc.bottom - tbH - find_bar_h - ask_bar_h - status_h, TRUE);
            return 0;
        }

        case WM_COMMAND: {
            WORD id = LOWORD(wParam);
            switch (id) {
                case IDM_FILE_OPEN: {
                    OpenTargetResult otr = {0};
                    if (ShowOpenTargetDialog(hWnd, &otr)) {
                        if (g_target.hProcess) {
                            if (g_hProcessWait) {
                                UnregisterWait(g_hProcessWait);
                                g_hProcessWait = NULL;
                            }
                            ProcessTerminate(&g_target);
                            IpcServerDestroy(&g_ipc);
                            ProcessClose(&g_target);
                        }
                        LaunchTarget(otr.exe_path, otr.arguments);
                    }
                    break;
                }
                case IDM_FILE_LAUNCH:
                    SendMessage(hWnd, WM_COMMAND, IDM_TB_START, 0);
                    break;
                case IDM_FILE_SAVE_LOG: {
                    LoggerFlush();
                    OPENFILENAMEA ofn = {0};
                    char save_path[MAX_PATH] = "remora_log.txt";
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hWnd;
                    ofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
                    ofn.lpstrFile = save_path;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
                    ofn.lpstrDefExt = "txt";
                    if (GetSaveFileNameA(&ofn)) {
                        if (LoggerSaveToFile(save_path)) {
                            LoggerAppendFmt(LOG_COLOR_INFO, "[*] Log saved to %s (%u total lines)\n",
                                save_path, LoggerGetTotalLines());
                        } else {
                            LoggerAppendFmt(LOG_COLOR_WARN, "[!] Failed to save log\n");
                        }
                    }
                    break;
                }
                case IDM_FILE_SAVE_SUMMARY: {
                    OPENFILENAMEA sofn = {0};
                    char sum_path[MAX_PATH];
                    {
                        char tname[36] = "unknown";
                        if (g_last_exe[0]) {
                            char *sl = strrchr(g_last_exe, '\\');
                            char *base = sl ? sl + 1 : g_last_exe;
                            lstrcpynA(tname, base, sizeof(tname));
                            char *dot = strrchr(tname, '.');
                            if (dot) *dot = 0;
                            tname[32] = 0;
                        }
                        _snprintf(sum_path, MAX_PATH, "remora_report_%s.txt", tname);
                        sum_path[MAX_PATH - 1] = 0;
                    }
                    sofn.lStructSize = sizeof(sofn);
                    sofn.hwndOwner = hWnd;
                    sofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
                    sofn.lpstrFile = sum_path;
                    sofn.nMaxFile = MAX_PATH;
                    sofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
                    sofn.lpstrDefExt = "txt";
                    if (GetSaveFileNameA(&sofn)) {
                        FILE *sf = fopen(sum_path, "w");
                        if (sf) {
                            char *rname = NULL;
                            if (g_last_exe[0]) {
                                rname = strrchr(g_last_exe, '\\');
                                rname = rname ? rname + 1 : g_last_exe;
                            }
                            SummaryRenderText(&g_summary, rname, g_target.pid, sf);
                            fclose(sf);
                            LoggerAppendFmt(LOG_COLOR_INFO, "[*] Summary report saved to %s\n", sum_path);
                        } else {
                            LoggerAppend("[!] Failed to save summary report\n", LOG_COLOR_WARN);
                        }
                    }
                    break;
                }
                case IDM_FILE_EXIT:
                    PostQuitMessage(0);
                    break;
                case IDM_FILE_TERMINATE:
                    if (g_target.hProcess) {
                        if (g_hProcessWait) {
                            UnregisterWait(g_hProcessWait);
                            g_hProcessWait = NULL;
                        }
                        ProcessTerminate(&g_target);
                        IpcServerDestroy(&g_ipc);
                        ProcessClose(&g_target);
                        LoggerAppend("[*] Target terminated.\n", LOG_COLOR_WARN);
                        SetWindowTextA(hWnd, "Remora Hook");
                        ToolbarUpdateIcon(TB_STATE_IDLE);
                        EnableStartButton(TRUE);
                        EnableMenuItem(GetMenu(hWnd), IDM_FILE_TERMINATE, MF_BYCOMMAND | MF_GRAYED);
                        ModifyMenuA(GetMenu(hWnd), IDM_EDIT_SUSPEND, MF_BYCOMMAND | MF_STRING,
                            IDM_EDIT_SUSPEND, "&Suspend Target\tF12");
                        EnableMenuItem(GetMenu(hWnd), IDM_EDIT_SUSPEND, MF_BYCOMMAND | MF_GRAYED);
                        EnableMenuItem(GetMenu(hWnd), IDM_CFG_BUFCAPTURE, MF_BYCOMMAND | MF_GRAYED);
                        CheckMenuItem(GetMenu(hWnd), IDM_CFG_BUFCAPTURE, MF_UNCHECKED);
                    }
                    break;
                case IDM_EDIT_SUSPEND:
                    if (g_target.hProcess) {
                        if (g_target.user_suspended) {
                            if (ProcessResumeAll(&g_target)) {
                                LoggerAppend("[*] Target resumed.\n", LOG_COLOR_INFO);
                                ModifyMenuA(GetMenu(hWnd), IDM_EDIT_SUSPEND, MF_BYCOMMAND | MF_STRING,
                                    IDM_EDIT_SUSPEND, "&Suspend Target\tF12");
                            } else {
                                LoggerAppend("[!] Failed to resume target.\n", LOG_COLOR_BLOCK);
                            }
                        } else {
                            if (ProcessSuspendAll(&g_target)) {
                                LoggerAppend("[*] Target suspended.\n", LOG_COLOR_WARN);
                                ModifyMenuA(GetMenu(hWnd), IDM_EDIT_SUSPEND, MF_BYCOMMAND | MF_STRING,
                                    IDM_EDIT_SUSPEND, "&Resume Target\tF12");
                            } else {
                                LoggerAppend("[!] Failed to suspend target.\n", LOG_COLOR_BLOCK);
                            }
                        }
                    }
                    break;
                case IDM_VIEW_CLEAR:
                    g_coal_count = 0;
                    LoggerClear();
                    break;
                case IDM_VIEW_DEBUGLOG: {
                    g_debuglog = !g_debuglog;
                    HMENU hMenu = GetMenu(hWnd);
                    CheckMenuItem(hMenu, IDM_VIEW_DEBUGLOG,
                        g_debuglog ? MF_CHECKED : MF_UNCHECKED);
                    if (g_debuglog && !g_logfile) {
                        g_logfile = fopen("remora_debug.log", "w");
                        if (g_logfile) setvbuf(g_logfile, NULL, _IONBF, 0);
                    } else if (!g_debuglog && g_logfile) {
                        fclose(g_logfile);
                        g_logfile = NULL;
                    }
                    if (g_debuglog) {
                        char fullpath[MAX_PATH];
                        GetFullPathNameA("remora_debug.log", MAX_PATH, fullpath, NULL);
                        LoggerAppendFmt(LOG_COLOR_VERBOSE, "[*] Debug logging ON -- writing to %s\n", fullpath);
                    } else {
                        LoggerAppendFmt(LOG_COLOR_VERBOSE, "[*] Debug logging OFF\n");
                    }
                    break;
                }
                case IDM_HELP_ABOUT:
                    DialogBoxA(GetModuleHandle(NULL), MAKEINTRESOURCEA(IDD_ABOUT), hWnd, AboutDlgProc);
                    break;
                case IDM_CFG_FONT: {
                    CHARFORMAT2 cf = {0};
                    cf.cbSize = sizeof(cf);
                    cf.dwMask = CFM_FACE | CFM_SIZE;
                    SendMessage(g_hRichEdit, EM_GETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf);
                    LOGFONTA lf = {0};
                    HDC hdc = GetDC(hWnd);
                    lf.lfHeight = -MulDiv(cf.yHeight / 20, GetDeviceCaps(hdc, LOGPIXELSY), 72);
                    ReleaseDC(hWnd, hdc);
                    lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
                    strcpy(lf.lfFaceName, cf.szFaceName);
                    CHOOSEFONTA cfont = {0};
                    cfont.lStructSize = sizeof(cfont);
                    cfont.hwndOwner = hWnd;
                    cfont.lpLogFont = &lf;
                    cfont.Flags = CF_INITTOLOGFONTSTRUCT | CF_FIXEDPITCHONLY | CF_SCREENFONTS;
                    if (ChooseFontA(&cfont)) {
                        CHARFORMAT2 newcf = {0};
                        newcf.cbSize = sizeof(newcf);
                        newcf.dwMask = CFM_FACE | CFM_SIZE;
                        newcf.yHeight = cfont.iPointSize / 10 * 20;
                        strcpy(newcf.szFaceName, lf.lfFaceName);
                        SendMessage(g_hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&newcf);
                    }
                    break;
                }
                case IDM_CFG_AUTODUMP:
                    ShowAutoDumpDialog(hWnd);
                    break;
                case IDM_CFG_AUTOSCROLL: {
                    BOOL on = !LoggerGetAutoScroll();
                    LoggerSetAutoScroll(on);
                    CheckMenuItem(GetMenu(hWnd), IDM_CFG_AUTOSCROLL,
                        on ? MF_CHECKED : MF_UNCHECKED);
                    break;
                }
                case IDM_CFG_BUFCAPTURE: {
                    if (g_jail_shared) {
                        BOOL on = !g_jail_shared->capture_enabled;
                        g_jail_shared->capture_enabled = on;
                        CheckMenuItem(GetMenu(hWnd), IDM_CFG_BUFCAPTURE,
                            on ? MF_CHECKED : MF_UNCHECKED);
                        LoggerAppendFmt(LOG_COLOR_INFO, "[*] Buffer capture %s (max %u bytes)\n",
                            on ? "enabled" : "disabled", g_jail_shared->capture_max_bytes);
                    }
                    break;
                }
                case IDM_CFG_COALESCE: {
                    g_coalesce = !g_coalesce;
                    CheckMenuItem(GetMenu(hWnd), IDM_CFG_COALESCE,
                        g_coalesce ? MF_CHECKED : MF_UNCHECKED);
                    if (g_coalesce) {
                        SetTimer(hWnd, IDT_COALESCE_FLUSH, COALESCE_TIMEOUT_MS, NULL);
                        LoggerAppend("[*] Trim Noise enabled\n", LOG_COLOR_INFO);
                    } else {
                        KillTimer(hWnd, IDT_COALESCE_FLUSH);
                        CoalesceFlushAll();
                        LoggerAppend("[*] Trim Noise disabled\n", LOG_COLOR_INFO);
                    }
                    break;
                }
                case IDM_CFG_DASM_DBLCLK: {
                    g_dasm_dblclk = !g_dasm_dblclk;
                    HMENU hMenu = GetMenu(hWnd);
                    CheckMenuItem(hMenu, IDM_CFG_DASM_DBLCLK,
                        g_dasm_dblclk ? MF_CHECKED : MF_UNCHECKED);
                    break;
                }
                case IDM_CFG_BREAK_OEP: {
                    g_break_at_oep = !g_break_at_oep;
                    HMENU hMenu = GetMenu(hWnd);
                    CheckMenuItem(hMenu, IDM_CFG_BREAK_OEP,
                        g_break_at_oep ? MF_CHECKED : MF_UNCHECKED);
                    break;
                }
                case IDM_CFG_SILENCE_BORING: {
                    g_silence_boring = !g_silence_boring;
                    HMENU hMenu = GetMenu(hWnd);
                    CheckMenuItem(hMenu, IDM_CFG_SILENCE_BORING,
                        g_silence_boring ? MF_CHECKED : MF_UNCHECKED);
                    break;
                }
                case IDM_CFG_SAVEPOS: {
                    SaveWindowPos(hWnd);
                    char pos_ini[MAX_PATH];
                    GetConfigIniPath(pos_ini, MAX_PATH);
                    LoggerAppendFmt(LOG_COLOR_INFO, "[*] Window position saved to %s\n", pos_ini);
                    break;
                }
                case IDM_CFG_SAVESETTINGS: {
                    char cfg_ini[MAX_PATH];
                    GetConfigIniPath(cfg_ini, MAX_PATH);
                    JailSavePolicy(cfg_ini);
                    SaveConfigToggles(cfg_ini);
                    LoggerAppendFmt(LOG_COLOR_INFO, "[*] Settings saved to %s\n", cfg_ini);
                    break;
                }
                case IDM_VIEW_MEMVIEW:
                    MemViewCreate(hWnd, g_target.hProcess);
                    break;
                case IDM_VIEW_STRSCAN:
                    StrScanOpen(hWnd, g_target.hProcess);
                    break;
                case IDM_VIEW_STACK:
                    StackViewOpen(hWnd, g_target.hProcess, g_target.hThread);
                    break;
                case IDM_VIEW_MODULES:
                    ModuleMapOpen(hWnd, g_target.hProcess);
                    break;
                case IDM_VIEW_DASM:
                    DasmOpen(hWnd, g_target.hProcess);
                    if (g_target.ep_addr)
                        DasmGotoAddress(g_target.ep_addr);
                    break;
                case IDM_VIEW_SANDBOX_RPT: {
                    char *rname = NULL;
                    if (g_last_exe[0]) {
                        rname = strrchr(g_last_exe, '\\');
                        rname = rname ? rname + 1 : g_last_exe;
                    }
                    SandboxReportOpen(hWnd, &g_summary, rname, g_target.pid);
                    break;
                }
                case IDM_TB_START: {
                    if (g_target.hProcess && g_target.ep_patched) {
                        ProcessRestoreEntryPoint(&g_target);
                        ResumeThread(g_target.hThread);
                        LoggerAppend("[*] Entry point restored, target running.\n", LOG_COLOR_INFO);
                        ToolbarUpdateIcon(TB_STATE_IDLE);
                    } else if (g_target.hProcess && g_target.suspended) {
                        ProcessResume(&g_target);
                        LoggerAppend("[*] Target resumed.\n", LOG_COLOR_INFO);
                        ToolbarUpdateIcon(TB_STATE_IDLE);
                    } else if (!g_target.hProcess && g_last_exe[0]) {
                        LaunchTarget(g_last_exe, g_last_args);
                    } else if (!g_target.hProcess) {
                        OpenTargetResult otr = {0};
                        if (ShowOpenTargetDialog(hWnd, &otr))
                            LaunchTarget(otr.exe_path, otr.arguments);
                    }
                    break;
                }
                case IDC_BTN_ALLOW:
                    LoggerAppendFmt(LOG_COLOR_INFO, "[*] JAIL: Allowed (TID:%04X)\n", g_ask_pending_tid);
                    AskBarRespond(JAIL_LOG);
                    break;
                case IDC_BTN_BLOCK:
                    LoggerAppendFmt(LOG_COLOR_BLOCK, "[*] JAIL: Blocked (TID:%04X)\n", g_ask_pending_tid);
                    AskBarRespond(JAIL_BLOCK);
                    break;
                case IDC_BTN_ALLOW_ALL:
                    LoggerAppendFmt(LOG_COLOR_INFO, "[*] JAIL: Allow All for %s\n",
                        (g_ask_pending_hook < HOOK_DEF_COUNT) ? g_hook_defs[g_ask_pending_hook].api_name : "???");
                    JailSetAction((HookId)g_ask_pending_hook, JAIL_LOG);
                    if (g_jail_shared && g_ask_pending_hook < HOOK_COUNT)
                        g_jail_shared->actions[g_ask_pending_hook] = (DWORD)JAIL_LOG;
                    AskBarRespond(JAIL_LOG);
                    break;
                case IDC_BTN_STACK:
                    ShowStackDialog(hWnd);
                    break;
                case IDC_BTN_FIND_NEXT:
                    FindBarDoSearch(TRUE);
                    break;
                case IDC_BTN_FIND_PREV:
                    FindBarDoSearch(FALSE);
                    break;
                case IDC_BTN_FIND_CLOSE:
                    FindBarHide();
                    break;
                case IDM_FIND:
                    FindBarShow();
                    break;
                case IDM_FIND_NEXT:
                    if (g_find_visible) FindBarDoSearch(TRUE);
                    break;
                case IDM_FIND_PREV:
                    if (g_find_visible) FindBarDoSearch(FALSE);
                    break;
                case IDM_FIND_CLOSE:
                    if (g_find_visible) FindBarHide();
                    break;
                case IDM_JAIL_RULES:
                    JailRulesDialog(hWnd);
                    if (g_jail_shared)
                        JailRulesSyncToShared(g_jail_shared);
                    break;
                case IDM_JAIL_POLICIES:
                    ShowJailPoliciesDialog(hWnd);
                    break;
                case IDM_TB_FILT_FILE:
                case IDM_TB_FILT_PROCESS:
                case IDM_TB_FILT_MEMORY:
                case IDM_TB_FILT_REGISTRY:
                case IDM_TB_FILT_NETWORK:
                case IDM_TB_FILT_HTTP:
                case IDM_TB_FILT_MODULE:
                case IDM_TB_FILT_CRYPTO:
                case IDM_TB_FILT_GENERAL: {
                    int idx = id - IDM_TB_FILT_BASE;
                    g_catFilter[idx] = !g_catFilter[idx];
                    HMENU hMenu = GetMenu(hWnd);
                    CheckMenuItem(hMenu, IDM_FILT_FILE + idx,
                        g_catFilter[idx] ? MF_CHECKED : MF_UNCHECKED);
                    break;
                }
                case IDM_FILT_FILE:
                case IDM_FILT_PROCESS:
                case IDM_FILT_MEMORY:
                case IDM_FILT_REGISTRY:
                case IDM_FILT_NETWORK:
                case IDM_FILT_HTTP:
                case IDM_FILT_MODULE:
                case IDM_FILT_CRYPTO:
                case IDM_FILT_GENERAL: {
                    int idx = id - IDM_FILT_FILE;
                    g_catFilter[idx] = !g_catFilter[idx];
                    HMENU hMenu = GetMenu(hWnd);
                    CheckMenuItem(hMenu, id,
                        g_catFilter[idx] ? MF_CHECKED : MF_UNCHECKED);
                    SendMessage(g_hToolbar, TB_CHECKBUTTON,
                        IDM_TB_FILT_BASE + idx, g_catFilter[idx]);
                    break;
                }
                default:
                    if (JailHandleCondCommand(hWnd, id)) {
                        if (g_jail_shared)
                            JailSyncConditions(g_jail_shared);
                    } else if (id >= IDM_JAIL_BASE) {
                        JailHandleMenuCommand(id);
                        if (g_jail_shared) {
                            WORD offset = id - IDM_JAIL_BASE;
                            WORD hook_idx = offset / 4;
                            if (hook_idx < HOOK_COUNT) {
                                g_jail_shared->actions[hook_idx] = (DWORD)JailGetAction((HookId)hook_idx);
                                int partner = JailGetAWPartner((int)hook_idx);
                                if (partner >= 0 && partner < HOOK_COUNT)
                                    g_jail_shared->actions[partner] = (DWORD)JailGetAction((HookId)partner);
                            }
                        }
                    }
                    break;
            }

            if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == g_hFindEdit) {
                char needle[256];
                GetWindowTextA(g_hFindEdit, needle, sizeof(needle));
                LoggerClearHighlight();
                if (needle[0])
                    LoggerHighlightAll(needle);
            }
            return 0;
        }

        case WM_IPC_MSG: {
            IpcQueueEntry *entry = (IpcQueueEntry *)lParam;
            if (entry) ProcessIpcMessage(entry);
            return 0;
        }

        case WM_LAUNCH_DONE: {
            DWORD result = (DWORD)wParam;
            switch (result) {
                case LAUNCH_OK: {
                    LoggerAppendFmt(LOG_COLOR_INFO, "[*] Created process: PID=%u\n", g_target.pid);
                    LoggerAppend("[*] hookdll.dll injection queued, target running.\n", LOG_COLOR_RETURN);
                    if (g_target.ep_patched)
                        LoggerAppendFmt(LOG_COLOR_INFO, "[*] Image base: 0x%016llX, OEP will break at 0x%016llX\n",
                            g_target.image_base, g_target.ep_addr);
                    char title[MAX_PATH + 16];
                    char exe_name[MAX_PATH];
                    GetModuleFileNameExA(g_target.hProcess, NULL, exe_name, MAX_PATH);
                    char *bs = strrchr(exe_name, '\\');
                    wsprintfA(title, "Remora Hook - %s", bs ? bs + 1 : exe_name);
                    SetWindowTextA(hWnd, title);
                    RegisterWaitForSingleObject(&g_hProcessWait, g_target.hProcess,
                        OnProcessExit, NULL, INFINITE, WT_EXECUTEONLYONCE);
                    EnableMenuItem(GetMenu(hWnd), IDM_FILE_TERMINATE, MF_BYCOMMAND | MF_ENABLED);
                    EnableMenuItem(GetMenu(hWnd), IDM_EDIT_SUSPEND, MF_BYCOMMAND | MF_ENABLED);
                    EnableMenuItem(GetMenu(hWnd), IDM_CFG_BUFCAPTURE, MF_BYCOMMAND | MF_ENABLED);
                    break;
                }
                case LAUNCH_ERR_IPC:
                    LoggerAppend("[!] Failed to create IPC server\n", LOG_COLOR_BLOCK);
                    ToolbarUpdateIcon(TB_STATE_IDLE);
                    EnableStartButton(TRUE);
                    break;
                case LAUNCH_ERR_PROCESS:
                    LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] Failed to create process (err=%u)\n", (unsigned)lParam);
                    ToolbarUpdateIcon(TB_STATE_IDLE);
                    EnableStartButton(TRUE);
                    break;
                case LAUNCH_ERR_INJECT:
                    LoggerAppendFmt(LOG_COLOR_BLOCK, "[!] DLL injection failed (err=%u)\n", (unsigned)lParam);
                    LoggerAppend("[!] Check: hookdll.dll exists? Defender blocking?\n", LOG_COLOR_WARN);
                    ToolbarUpdateIcon(TB_STATE_IDLE);
                    EnableStartButton(TRUE);
                    break;
            }
            return 0;
        }

        case WM_TARGET_EXIT: {
            if (!g_target.hProcess) return 0;
            CoalesceFlushAll();
            if (g_hProcessWait) {
                UnregisterWait(g_hProcessWait);
                g_hProcessWait = NULL;
            }
            DWORD exitCode = 0;
            GetExitCodeProcess(g_target.hProcess, &exitCode);
            IpcServerDestroy(&g_ipc);
            ProcessClose(&g_target);
            LoggerAppendFmt(LOG_COLOR_WARN, "[*] Target exited (code=0x%08X).\n", exitCode);
            SetWindowTextA(hWnd, "Remora Hook");
            ToolbarUpdateIcon(TB_STATE_IDLE);
            EnableStartButton(TRUE);
            EnableMenuItem(GetMenu(hWnd), IDM_FILE_TERMINATE, MF_BYCOMMAND | MF_GRAYED);
            ModifyMenuA(GetMenu(hWnd), IDM_EDIT_SUSPEND, MF_BYCOMMAND | MF_STRING,
                IDM_EDIT_SUSPEND, "&Suspend Target\tF12");
            EnableMenuItem(GetMenu(hWnd), IDM_EDIT_SUSPEND, MF_BYCOMMAND | MF_GRAYED);
            EnableMenuItem(GetMenu(hWnd), IDM_CFG_BUFCAPTURE, MF_BYCOMMAND | MF_GRAYED);
            CheckMenuItem(GetMenu(hWnd), IDM_CFG_BUFCAPTURE, MF_UNCHECKED);
            return 0;
        }

        case WM_TIMER:
            if (wParam == IDT_LOG_FLUSH) {
                LoggerFlush();
                return 0;
            }
            if (wParam == IDT_COALESCE_FLUSH) {
                CoalesceFlushStale();
                return 0;
            }
            if (wParam == IDT_EP_SUSPEND) {
                if (!g_target.hProcess || !g_target.ep_patched) {
                    KillTimer(hWnd, IDT_EP_SUSPEND);
                    EnableStartButton(TRUE);
                    ToolbarUpdateIcon(TB_STATE_IDLE);
                    return 0;
                }
                SuspendThread(g_target.hThread);
                CONTEXT ctx = {0};
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(g_target.hThread, &ctx) && ctx.Rip == g_target.ep_addr) {
                    KillTimer(hWnd, IDT_EP_SUSPEND);
                    char evt_name[64];
                    sprintf(evt_name, "RemoraOEP_%u", g_target.pid);
                    HANDLE hEvt = OpenEventA(EVENT_MODIFY_STATE, FALSE, evt_name);
                    if (hEvt) {
                        SetEvent(hEvt);
                        CloseHandle(hEvt);
                    }
                    LoggerAppend("[*] Target suspended at OEP. Press ", LOG_COLOR_INFO);
                    LoggerAppend("Start", LOG_COLOR_RETURN);
                    LoggerAppend(" (green circle on toolbar) to run.\n", LOG_COLOR_INFO);
                    EnableStartButton(TRUE);
                    ToolbarUpdateIcon(TB_STATE_READY);
                } else {
                    ResumeThread(g_target.hThread);
                }
            }
            return 0;

        case WM_NOTIFY: {
            NMHDR *nmh = (NMHDR *)lParam;
            if (nmh->code == TTN_GETDISPINFOA) {
                NMTTDISPINFOA *di = (NMTTDISPINFOA *)lParam;
                if (di->hdr.idFrom == IDM_TB_START) {
                    switch (g_tb_state) {
                        case TB_STATE_LOADING: di->lpszText = "Loading..."; break;
                        case TB_STATE_READY:   di->lpszText = "Start Execution"; break;
                        default:               di->lpszText = "Open Target"; break;
                    }
                } else {
                    static const char *filt_tips[FILT_COUNT] = {
                        "File", "Process", "Memory", "Registry",
                        "Network", "HTTP", "Module", "Crypto", "General"
                    };
                    int idx = (int)(di->hdr.idFrom - IDM_TB_FILT_BASE);
                    if (idx >= 0 && idx < FILT_COUNT)
                        di->lpszText = (LPSTR)filt_tips[idx];
                }
            }
            return 0;
        }

        case WM_CTLCOLORSTATIC: {
            HDC hdc = (HDC)wParam;
            HWND hCtrl = (HWND)lParam;
            if (hCtrl == g_hAskBar || hCtrl == g_hAskLabel) {
                SetBkColor(hdc, RGB(255, 200, 50));
                SetTextColor(hdc, RGB(0, 0, 0));
                return (LRESULT)g_hAskBrush;
            }
            break;
        }

        case WM_DROPFILES: {
            if (g_target.hProcess) {
                DragFinish((HDROP)wParam);
                break;
            }
            char drop_path[MAX_PATH] = {0};
            DragQueryFileA((HDROP)wParam, 0, drop_path, MAX_PATH);
            DragFinish((HDROP)wParam);
            if (drop_path[0]) {
                const char *ext = strrchr(drop_path, '.');
                if (ext && (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".scr") == 0)) {
                    LaunchTarget(drop_path, "");
                }
            }
            return 0;
        }

        case WM_DESTROY:
            ProcessTerminate(&g_target);
            IpcServerDestroy(&g_ipc);
            ProcessClose(&g_target);
            if (g_jail_shared) {
                UnmapViewOfFile(g_jail_shared);
                g_jail_shared = NULL;
            }
            if (g_jail_shared_mapping) {
                CloseHandle(g_jail_shared_mapping);
                g_jail_shared_mapping = NULL;
            }
            if (g_hToolbarIml) { ImageList_Destroy(g_hToolbarIml); g_hToolbarIml = NULL; }
            if (g_hFont) DeleteObject(g_hFont);
            if (g_hAskBrush) DeleteObject(g_hAskBrush);
            LoggerShutdown();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hPrev;
    InitCommonControls();

    WNDCLASS wc = {0};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_APPICON));
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
    wc.lpszMenuName = MAKEINTRESOURCE(IDM_MAINMENU);
    wc.lpszClassName = "RemoraMain";
    RegisterClass(&wc);

    int ww = 1100, wh = 700;
    int sx, sy;
    if (!LoadWindowPos(&sx, &sy, &ww, &wh)) {
        sx = (GetSystemMetrics(SM_CXSCREEN) - ww) / 2;
        sy = (GetSystemMetrics(SM_CYSCREEN) - wh) / 2;
    }

    g_hWnd = CreateWindow("RemoraMain", "Remora Hook",
        WS_OVERLAPPEDWINDOW, sx, sy, ww, wh,
        NULL, NULL, hInst, NULL);

    ShowWindow(g_hWnd, nShow);
    UpdateWindow(g_hWnd);

    // If command line has a target, launch it
    if (lpCmd && lpCmd[0]) {
        char exe[MAX_PATH] = {0};
        const char *args = "";
        if (lpCmd[0] == '"') {
            char *end = strchr(lpCmd + 1, '"');
            if (end) {
                size_t len = end - lpCmd - 1;
                if (len >= MAX_PATH) len = MAX_PATH - 1;
                memcpy(exe, lpCmd + 1, len);
                args = end + 1;
                while (*args == ' ') args++;
            }
        } else {
            char *sp = strchr(lpCmd, ' ');
            if (sp) {
                size_t len = sp - lpCmd;
                if (len >= MAX_PATH) len = MAX_PATH - 1;
                memcpy(exe, lpCmd, len);
                args = sp + 1;
            } else {
                strncpy(exe, lpCmd, MAX_PATH - 1);
            }
        }
        if (exe[0])
            LaunchTarget(exe, args);
    }

    ACCEL accel_table[] = {
        { FCONTROL | FVIRTKEY, 'O', IDM_FILE_OPEN },
        { FCONTROL | FVIRTKEY, 'F', IDM_FIND },
        { FCONTROL | FVIRTKEY, 'L', IDM_VIEW_CLEAR },
        { FCONTROL | FVIRTKEY, 'S', IDM_FILE_SAVE_LOG },
        { FCONTROL | FVIRTKEY, 'R', IDM_JAIL_RULES },
        { FCONTROL | FVIRTKEY, 'J', IDM_JAIL_POLICIES },
        { FCONTROL | FVIRTKEY, 'M', IDM_VIEW_MEMVIEW },
        { FCONTROL | FVIRTKEY, 'B', IDM_VIEW_SANDBOX_RPT },
        { FVIRTKEY, VK_F5, IDM_FILE_LAUNCH },
        { FVIRTKEY, VK_F3, IDM_FIND_NEXT },
        { FSHIFT | FVIRTKEY, VK_F3, IDM_FIND_PREV },
        { FVIRTKEY, VK_ESCAPE, IDM_FIND_CLOSE },
        { FVIRTKEY, VK_F12, IDM_EDIT_SUSPEND },
        { FVIRTKEY, VK_F1, IDM_HELP_ABOUT },
    };
    HACCEL hAccel = CreateAcceleratorTable(accel_table, _countof(accel_table));

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        /* Skip accelerators when dasm view or its children have focus */
        HWND hFocus = GetFocus();
        BOOL dasmActive = hFocus && GetAncestor(hFocus, GA_ROOT) != g_hWnd;
        if (!dasmActive && TranslateAccelerator(g_hWnd, hAccel, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    DestroyAcceleratorTable(hAccel);
    return (int)msg.wParam;
}
