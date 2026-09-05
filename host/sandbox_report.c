#include <windows.h>
#include <commdlg.h>
#include <richedit.h>
#include <stdio.h>
#include <string.h>
#include "sandbox_report.h"
#include "summary.h"
#include "hook_defs.h"

static const char *SR_CLASS = "RemoraSandboxReport";
static HWND  g_srHwnd      = NULL;
static HWND  g_srRichEdit  = NULL;
static HWND  g_srAutoChk   = NULL;
static HFONT g_srFont      = NULL;
static HFONT g_srUIFont    = NULL;
static BOOL  g_srAutoRefresh = FALSE;

static WNDPROC g_srPrevRichProc = NULL;

static SummaryAccumulator *g_srAcc  = NULL;
static const char *g_srTargetName   = NULL;
static DWORD g_srTargetPid          = 0;

#define SR_COLOR_HEADING  RGB(0, 200, 255)
#define SR_COLOR_SECTION  RGB(255, 200, 0)
#define SR_COLOR_NORMAL   RGB(220, 220, 220)
#define SR_COLOR_WARN     RGB(255, 80, 80)
#define SR_COLOR_OK       RGB(0, 220, 100)
#define SR_COLOR_DIM      RGB(140, 140, 140)
#define SR_COLOR_BLOCKED  RGB(255, 80, 80)

#define IDC_SR_REFRESH    1
#define IDC_SR_SAVE       2
#define IDC_SR_COPY       3
#define IDC_SR_AUTOREFRESH 4
#define IDC_SR_RICHEDIT   5
#define IDT_SR_AUTOREFRESH 100

static void sr_append(const char *text, COLORREF color) {
    int len = GetWindowTextLength(g_srRichEdit);
    SendMessage(g_srRichEdit, EM_SETSEL, len, len);
    CHARFORMAT2 cf = {0};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessage(g_srRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessage(g_srRichEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
}

static void sr_appendf(COLORREF color, const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    sr_append(buf, color);
}

static void sr_format_bytes(UINT64 bytes, char *out, int out_size) {
    if (bytes >= 1048576)
        _snprintf(out, out_size, "%.1f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024)
        _snprintf(out, out_size, "%.1f KB", (double)bytes / 1024.0);
    else
        _snprintf(out, out_size, "%I64u bytes", bytes);
    out[out_size - 1] = 0;
}

static void sr_render(void) {
    if (!g_srRichEdit || !g_srAcc) return;

    SendMessage(g_srRichEdit, WM_SETREDRAW, FALSE, 0);
    SetWindowText(g_srRichEdit, "");

    SummaryAccumulator *acc = g_srAcc;
    SummaryDetectSuspicious(acc);

    double dur = (double)(acc->end_tick - acc->start_tick) / 1000.0;
    if (dur < 0.1) dur = 0.1;

    sr_append("=== Sandbox Report ===\n", SR_COLOR_HEADING);
    sr_appendf(SR_COLOR_NORMAL, "Target:   %s\n", g_srTargetName ? g_srTargetName : "(unknown)");
    if (g_srTargetPid)
        sr_appendf(SR_COLOR_NORMAL, "PID:      %u\n", g_srTargetPid);
    sr_appendf(SR_COLOR_NORMAL, "Duration: %.1fs\n", dur);
    sr_appendf(SR_COLOR_NORMAL, "Total API calls: %u", acc->total_calls);
    if (acc->blocked_count > 0)
        sr_appendf(SR_COLOR_BLOCKED, " (%u blocked)", acc->blocked_count);
    sr_append("\n", SR_COLOR_NORMAL);

    if (acc->suspicious_count > 0) {
        sr_append("\n--- Suspicious Indicators ---\n", SR_COLOR_WARN);
        for (int i = 0; i < acc->suspicious_count; i++)
            sr_appendf(SR_COLOR_WARN, "  [!] %s\n", acc->suspicious[i]);
    }

    if (acc->file_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_CreateFileA; i <= HOOK_CloseHandle; i++)
            cat_calls += acc->calls_per_hook[i];
        sr_appendf(SR_COLOR_SECTION, "\n--- File Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->file_count; i++) {
            SummaryFileEntry *f = &acc->files[i];
            sr_appendf(SR_COLOR_NORMAL, "  %s\n", f->path);
            if (f->create_count)
                sr_appendf(SR_COLOR_DIM, "    opened %u time(s)\n", f->create_count);
            if (f->write_count) {
                char bs[32];
                sr_format_bytes(f->write_bytes, bs, sizeof(bs));
                sr_appendf(SR_COLOR_DIM, "    written %u time(s), %s\n", f->write_count, bs);
            }
            if (f->read_count)
                sr_appendf(SR_COLOR_DIM, "    read %u time(s)\n", f->read_count);
            if (f->delete_count)
                sr_appendf(SR_COLOR_WARN, "    deleted %u time(s)\n", f->delete_count);
            if (f->was_blocked)
                sr_appendf(SR_COLOR_BLOCKED, "    [BLOCKED]\n");
        }
        if (acc->file_overflow)
            sr_appendf(SR_COLOR_DIM, "  ... and %d more unique paths\n", acc->file_overflow);
    }

    if (acc->reg_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_RegOpenKeyExA; i <= HOOK_RegDeleteValueW; i++)
            cat_calls += acc->calls_per_hook[i];
        sr_appendf(SR_COLOR_SECTION, "\n--- Registry Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->reg_count; i++) {
            SummaryRegEntry *r = &acc->regs[i];
            sr_appendf(SR_COLOR_NORMAL, "  %s\n", r->key);
            if (r->open_count)
                sr_appendf(SR_COLOR_DIM, "    opened %u\n", r->open_count);
            if (r->set_count)
                sr_appendf(SR_COLOR_DIM, "    set %u\n", r->set_count);
            if (r->create_count)
                sr_appendf(SR_COLOR_DIM, "    created %u\n", r->create_count);
            if (r->delete_count)
                sr_appendf(SR_COLOR_WARN, "    deleted %u\n", r->delete_count);
            if (r->was_blocked)
                sr_appendf(SR_COLOR_BLOCKED, "    [BLOCKED]\n");
        }
        if (acc->reg_overflow)
            sr_appendf(SR_COLOR_DIM, "  ... and %d more unique keys\n", acc->reg_overflow);
    }

    if (acc->net_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_connect; i <= HOOK_closesocket; i++)
            cat_calls += acc->calls_per_hook[i];
        sr_appendf(SR_COLOR_SECTION, "\n--- Network Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->net_count; i++) {
            SummaryNetEntry *n = &acc->nets[i];
            char line[512];
            int pos = _snprintf(line, sizeof(line), "  %s", n->addr);
            if (n->connect_count) {
                pos += _snprintf(line + pos, sizeof(line) - pos, " (connect x%u", n->connect_count);
                if (n->send_count) {
                    char bs[32];
                    sr_format_bytes(n->send_bytes, bs, sizeof(bs));
                    pos += _snprintf(line + pos, sizeof(line) - pos, ", send x%u %s", n->send_count, bs);
                }
                if (n->recv_count) {
                    char bs[32];
                    sr_format_bytes(n->recv_bytes, bs, sizeof(bs));
                    pos += _snprintf(line + pos, sizeof(line) - pos, ", recv x%u %s", n->recv_count, bs);
                }
                pos += _snprintf(line + pos, sizeof(line) - pos, ")");
            }
            line[sizeof(line) - 1] = 0;
            sr_appendf(SR_COLOR_NORMAL, "%s\n", line);
        }
        if (acc->net_overflow)
            sr_appendf(SR_COLOR_DIM, "  ... and %d more connections\n", acc->net_overflow);
    }

    if (acc->http_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_InternetOpenA; i <= HOOK_InternetReadFile; i++)
            cat_calls += acc->calls_per_hook[i];
        sr_appendf(SR_COLOR_SECTION, "\n--- HTTP Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->http_count; i++) {
            if (acc->https[i].count > 1)
                sr_appendf(SR_COLOR_NORMAL, "  %s (x%u)\n", acc->https[i].desc, acc->https[i].count);
            else
                sr_appendf(SR_COLOR_NORMAL, "  %s\n", acc->https[i].desc);
        }
        if (acc->http_overflow)
            sr_appendf(SR_COLOR_DIM, "  ... and %d more requests\n", acc->http_overflow);
    }

    if (acc->keys_generated || acc->encrypt_calls || acc->decrypt_calls) {
        int cat_calls = 0;
        for (int i = HOOK_CryptEncrypt; i <= HOOK_BCryptImportKey; i++)
            cat_calls += acc->calls_per_hook[i];
        sr_appendf(SR_COLOR_SECTION, "\n--- Crypto Activity (%d calls) ---\n", cat_calls);
        if (acc->keys_generated)
            sr_appendf(SR_COLOR_NORMAL, "  Keys generated: %d\n", acc->keys_generated);
        if (acc->encrypt_calls) {
            char bs[32];
            sr_format_bytes(acc->encrypt_bytes, bs, sizeof(bs));
            sr_appendf(SR_COLOR_NORMAL, "  Encrypt: %d calls, %s\n", acc->encrypt_calls, bs);
        }
        if (acc->decrypt_calls) {
            char bs[32];
            sr_format_bytes(acc->decrypt_bytes, bs, sizeof(bs));
            sr_appendf(SR_COLOR_NORMAL, "  Decrypt: %d calls, %s\n", acc->decrypt_calls, bs);
        }
    }

    if (acc->proc_created_count > 0 || acc->proc_opened_count > 0 ||
        acc->proc_terminated_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_CreateProcessA; i <= HOOK_QueueUserAPC; i++)
            cat_calls += acc->calls_per_hook[i];
        sr_appendf(SR_COLOR_SECTION, "\n--- Process Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->proc_created_count; i++) {
            if (acc->proc_created[i].count > 1)
                sr_appendf(SR_COLOR_NORMAL, "  Created: %s (x%u)\n", acc->proc_created[i].desc, acc->proc_created[i].count);
            else
                sr_appendf(SR_COLOR_NORMAL, "  Created: %s\n", acc->proc_created[i].desc);
        }
        for (int i = 0; i < acc->proc_opened_count; i++) {
            if (acc->proc_opened[i].count > 1)
                sr_appendf(SR_COLOR_NORMAL, "  Opened: %s (x%u)\n", acc->proc_opened[i].desc, acc->proc_opened[i].count);
            else
                sr_appendf(SR_COLOR_NORMAL, "  Opened: %s\n", acc->proc_opened[i].desc);
        }
        for (int i = 0; i < acc->proc_terminated_count; i++) {
            if (acc->proc_terminated[i].count > 1)
                sr_appendf(SR_COLOR_WARN, "  Terminated: %s (x%u)\n", acc->proc_terminated[i].desc, acc->proc_terminated[i].count);
            else
                sr_appendf(SR_COLOR_WARN, "  Terminated: %s\n", acc->proc_terminated[i].desc);
        }
    }

    if (acc->valloc_total > 0 || acc->vprot_total > 0) {
        int cat_calls = acc->calls_per_hook[HOOK_VirtualAlloc] +
                        acc->calls_per_hook[HOOK_VirtualProtect] +
                        acc->calls_per_hook[HOOK_ReadProcessMemory];
        sr_appendf(SR_COLOR_SECTION, "\n--- Memory Activity (%d calls) ---\n", cat_calls);
        if (acc->valloc_total) {
            sr_appendf(SR_COLOR_NORMAL, "  VirtualAlloc: %d total", acc->valloc_total);
            if (acc->valloc_exec_count)
                sr_appendf(SR_COLOR_WARN, ", %d with EXECUTE", acc->valloc_exec_count);
            sr_append("\n", SR_COLOR_NORMAL);
        }
        if (acc->vprot_total) {
            sr_appendf(SR_COLOR_NORMAL, "  VirtualProtect: %d total", acc->vprot_total);
            if (acc->vprot_rw_to_rx)
                sr_appendf(SR_COLOR_WARN, ", %d to RX/RWX", acc->vprot_rw_to_rx);
            sr_append("\n", SR_COLOR_NORMAL);
        }
    }

    if (acc->blocked_count > 0) {
        sr_appendf(SR_COLOR_SECTION, "\n--- Blocked Actions (%u total) ---\n", acc->blocked_count);
        for (int i = 0; i < HOOK_COUNT; i++) {
            if (acc->blocked_per_hook[i] > 0)
                sr_appendf(SR_COLOR_BLOCKED, "  %s x%u\n",
                    g_hook_defs[i].api_name, acc->blocked_per_hook[i]);
        }
    }

    sr_append("\n=== End Report ===\n", SR_COLOR_HEADING);

    SendMessage(g_srRichEdit, EM_SETSEL, 0, 0);
    SendMessage(g_srRichEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_srRichEdit, NULL, TRUE);
}

static void sr_save(HWND hwnd) {
    char path[MAX_PATH] = "sandbox_report.txt";
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = "txt";
    if (!GetSaveFileNameA(&ofn)) return;

    FILE *f = fopen(path, "w");
    if (f) {
        SummaryRenderText(g_srAcc, g_srTargetName, g_srTargetPid, f);
        fclose(f);
    } else {
        MessageBoxA(hwnd, "Failed to save report.", "Error", MB_OK | MB_ICONERROR);
    }
}

static void sr_copy_all(void) {
    if (!g_srRichEdit) return;
    int len = GetWindowTextLengthA(g_srRichEdit);
    if (len <= 0) return;

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)(len + 1));
    if (!hMem) return;
    char *buf = (char *)GlobalLock(hMem);
    if (buf) {
        GetWindowTextA(g_srRichEdit, buf, len + 1);
        GlobalUnlock(hMem);
        if (OpenClipboard(g_srHwnd)) {
            EmptyClipboard();
            SetClipboardData(CF_TEXT, hMem);
            CloseClipboard();
        } else {
            GlobalFree(hMem);
        }
    } else {
        GlobalFree(hMem);
    }
}

static LRESULT CALLBACK SrRichEditSubProc(HWND hwnd, UINT msg,
                                          WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_ESCAPE) {
        DestroyWindow(g_srHwnd);
        return 0;
    }
    return CallWindowProcA(g_srPrevRichProc, hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK SandboxReportWndProc(HWND hwnd, UINT msg,
                                              WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_srFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
        g_srUIFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");

        HINSTANCE hInst = GetModuleHandle(NULL);
        int x = 4;

        HWND hRefresh = CreateWindowExA(0, "BUTTON", "Refresh",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, 4, 70, 26, hwnd, (HMENU)IDC_SR_REFRESH, hInst, NULL);
        SendMessage(hRefresh, WM_SETFONT, (WPARAM)g_srUIFont, TRUE);
        x += 76;

        HWND hSave = CreateWindowExA(0, "BUTTON", "Save...",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, 4, 70, 26, hwnd, (HMENU)IDC_SR_SAVE, hInst, NULL);
        SendMessage(hSave, WM_SETFONT, (WPARAM)g_srUIFont, TRUE);
        x += 76;

        HWND hCopy = CreateWindowExA(0, "BUTTON", "Copy All",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, 4, 70, 26, hwnd, (HMENU)IDC_SR_COPY, hInst, NULL);
        SendMessage(hCopy, WM_SETFONT, (WPARAM)g_srUIFont, TRUE);
        x += 86;

        g_srAutoChk = CreateWindowExA(0, "BUTTON", "Auto-refresh",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            x, 8, 100, 18, hwnd, (HMENU)IDC_SR_AUTOREFRESH, hInst, NULL);
        SendMessage(g_srAutoChk, WM_SETFONT, (WPARAM)g_srUIFont, TRUE);

        g_srRichEdit = CreateWindowExW(WS_EX_CLIENTEDGE,
            MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            0, 34, 100, 100, hwnd, (HMENU)IDC_SR_RICHEDIT, hInst, NULL);

        SendMessage(g_srRichEdit, EM_SETBKGNDCOLOR, 0, RGB(0, 0, 0));
        SendMessage(g_srRichEdit, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);
        if (g_srFont)
            SendMessage(g_srRichEdit, WM_SETFONT, (WPARAM)g_srFont, TRUE);

        g_srPrevRichProc = (WNDPROC)(LONG_PTR)SetWindowLongPtrA(
            g_srRichEdit, GWLP_WNDPROC, (LONG_PTR)SrRichEditSubProc);

        sr_render();
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        if (g_srRichEdit)
            MoveWindow(g_srRichEdit, 0, 34, w, h - 34, TRUE);
        return 0;
    }

    case WM_TIMER:
        if (wParam == IDT_SR_AUTOREFRESH) {
            sr_render();
            return 0;
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_SR_REFRESH:
            sr_render();
            return 0;
        case IDC_SR_SAVE:
            sr_save(hwnd);
            return 0;
        case IDC_SR_COPY:
            sr_copy_all();
            return 0;
        case IDC_SR_AUTOREFRESH:
            g_srAutoRefresh = (SendMessage(g_srAutoChk, BM_GETCHECK, 0, 0) == BST_CHECKED);
            if (g_srAutoRefresh)
                SetTimer(hwnd, IDT_SR_AUTOREFRESH, 2000, NULL);
            else
                KillTimer(hwnd, IDT_SR_AUTOREFRESH);
            return 0;
        }
        break;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_SR_AUTOREFRESH);
        g_srAutoRefresh = FALSE;
        if (g_srFont) { DeleteObject(g_srFont); g_srFont = NULL; }
        if (g_srUIFont) { DeleteObject(g_srUIFont); g_srUIFont = NULL; }
        g_srRichEdit = NULL;
        g_srAutoChk = NULL;
        g_srHwnd = NULL;
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void SandboxReportOpen(HWND hwndParent, SummaryAccumulator *acc,
                       const char *target_name, DWORD target_pid) {
    g_srAcc = acc;
    g_srTargetName = target_name;
    g_srTargetPid = target_pid;

    if (g_srHwnd) {
        sr_render();
        SetForegroundWindow(g_srHwnd);
        return;
    }

    static BOOL registered = FALSE;
    if (!registered) {
        WNDCLASSEXA wc = {0};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = SandboxReportWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = SR_CLASS;
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        RegisterClassExA(&wc);
        registered = TRUE;
    }

    int w = 700, h = 550;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    g_srHwnd = CreateWindowExA(0, SR_CLASS, "Sandbox Report",
        WS_OVERLAPPEDWINDOW,
        (screenW - w) / 2, (screenH - h) / 2, w, h,
        hwndParent, NULL, GetModuleHandle(NULL), NULL);

    if (g_srHwnd) {
        ShowWindow(g_srHwnd, SW_SHOW);
        UpdateWindow(g_srHwnd);
    }
}

void SandboxReportRefresh(void) {
    if (g_srHwnd && g_srRichEdit)
        sr_render();
}

void SandboxReportClose(void) {
    if (g_srHwnd) {
        DestroyWindow(g_srHwnd);
        g_srHwnd = NULL;
    }
}
