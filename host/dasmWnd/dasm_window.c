#include "dasm.h"
#include "dasm_decode.h"
#include "dasm_render.h"
#include "dasm_symbols.h"
#include "dasm_labels.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define IDC_DASM_GOTO_EDIT  3010
#define IDC_DASM_GOTO_BTN   3011
#define IDC_DASM_STATUS     3012
#define IDC_DASM_BACK_BTN   3013
#define IDC_DASM_FWD_BTN    3014

/* Context menu commands */
#define IDM_DASM_COPY_ADDR  3020
#define IDM_DASM_COPY_LINE  3021
#define IDM_DASM_GOTO       3022
#define IDM_DASM_RENAME     3023
#define IDM_DASM_COMMENT    3024
#define IDM_DASM_FOLLOW     3025
#define IDM_DASM_FROMHERE   3026
#define IDM_DASM_DEREF      3027
#define IDM_DASM_HIGHLIGHT  3028

/* Gutter (Phase E) */
#define DASM_GUTTER_LANES   8
#define DASM_LANE_W         6
#define DASM_GUTTER_W       (DASM_GUTTER_LANES * DASM_LANE_W)  /* 48 px */

static const char *DASM_CLASS      = "RemoraDasm";
static const char *DASM_VIEW_CLASS = "RemoraDasmView";

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */

static HWND   g_dasmHwnd     = NULL;
static HWND   g_dasmView     = NULL;
static HWND   g_dasmGotoEdit = NULL;
static HWND   g_dasmGotoBtn  = NULL;
static HWND   g_dasmBackBtn  = NULL;
static HWND   g_dasmFwdBtn   = NULL;
static HWND   g_dasmStatus   = NULL;
static HFONT  g_dasmFont     = NULL;
static HANDLE g_dasmProcess  = NULL;

static DecodedInsn g_dasmLines[DASM_MAX_LINES];
static int    g_dasmLineCount = 0;
static int    g_dasmCursorRow = 0;
static int    g_dasmViewTop   = 0;
static UINT64 g_dasmBaseAddr  = 0;
static int    g_dasmCharW     = 8;
static int    g_dasmCharH     = 16;

/* Phase G: double-click highlight */
static char  g_hlText[64]  = {0};
static BOOL  g_hlActive    = FALSE;

/* Shift-select range: anchor is where selection started, selEnd is current extent */
static int   g_dasmSelAnchor = -1;  /* -1 = no active selection */
static int   g_dasmSelEnd    = -1;

/* Navigation history (back/forward) */
#define DASM_HIST_MAX 32
static UINT64 g_hist[DASM_HIST_MAX];
static int    g_histTop = 0;
static UINT64 g_fwd[DASM_HIST_MAX];
static int    g_fwdTop = 0;

/* Sym file path for labels persistence */
static char g_symPath[MAX_PATH] = {0};

/* Forward declarations */
static void CopyToClipboard(HWND hwnd, const char *text);
static BOOL ResolveAddress(const char *text, UINT64 *outAddr);
static void DoGoto(void);

/* Selection helpers */
static void DasmSelClear(void) {
    g_dasmSelAnchor = -1;
    g_dasmSelEnd    = -1;
}

static BOOL DasmSelActive(void) {
    return g_dasmSelAnchor >= 0 && g_dasmSelEnd >= 0 &&
           g_dasmSelAnchor != g_dasmSelEnd;
}

static void DasmSelGetRange(int *lo, int *hi) {
    if (g_dasmSelAnchor <= g_dasmSelEnd) {
        *lo = g_dasmSelAnchor;
        *hi = g_dasmSelEnd;
    } else {
        *lo = g_dasmSelEnd;
        *hi = g_dasmSelAnchor;
    }
}

/* ------------------------------------------------------------------ */
/* Input box (Phase F)                                                  */
/* ------------------------------------------------------------------ */

typedef struct { char *buf; int len; const char *prompt; } InputBoxData;

#define IDD_EDIT 100

static INT_PTR CALLBACK InputDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG: {
        InputBoxData *d = (InputBoxData *)lp;
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, (LONG_PTR)d);
        SetWindowTextA(hwnd, d->prompt);
        HWND hEdit = GetDlgItem(hwnd, IDD_EDIT);
        SetWindowTextA(hEdit, d->buf);
        SendMessageA(hEdit, EM_SETSEL, 0, -1);
        SetFocus(hEdit);
        return FALSE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            InputBoxData *d = (InputBoxData *)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
            GetDlgItemTextA(hwnd, IDD_EDIT, d->buf, d->len);
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

static WORD *AlignDword(WORD *p) {
    ULONG_PTR addr = (ULONG_PTR)p;
    addr = (addr + 3) & ~(ULONG_PTR)3;
    return (WORD *)addr;
}

static BOOL DasmInputBox(HWND hParent, const char *prompt, char *buf, int bufLen) {
    BYTE tmpl[512];
    memset(tmpl, 0, sizeof(tmpl));
    WORD *p = (WORD *)tmpl;

    /* DLGTEMPLATE header */
    DLGTEMPLATE *hdr = (DLGTEMPLATE *)p;
    hdr->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU;
    hdr->cdit  = 2; /* edit + OK button (Cancel via WM_CLOSE/Esc) */
    hdr->cx    = 220;
    hdr->cy    = 40;
    p = (WORD *)(hdr + 1);
    *p++ = 0; /* menu */
    *p++ = 0; /* class */
    *p++ = 0; /* title */

    /* Item 1: Edit control */
    p = AlignDword(p);
    DLGITEMTEMPLATE *edit = (DLGITEMTEMPLATE *)p;
    edit->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL;
    edit->x = 4; edit->y = 4; edit->cx = 172; edit->cy = 13;
    edit->id = IDD_EDIT;
    p = (WORD *)(edit + 1);
    *p++ = 0xFFFF; *p++ = 0x0081; /* Edit class */
    *p++ = 0; /* title */
    *p++ = 0; /* extra */

    /* Item 2: OK button */
    p = AlignDword(p);
    DLGITEMTEMPLATE *btn = (DLGITEMTEMPLATE *)p;
    btn->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
    btn->x = 180; btn->y = 4; btn->cx = 34; btn->cy = 13;
    btn->id = IDOK;
    p = (WORD *)(btn + 1);
    *p++ = 0xFFFF; *p++ = 0x0080; /* Button class */
    *p++ = 'O'; *p++ = 'K'; *p++ = 0; /* title "OK" */
    *p++ = 0; /* extra */

    InputBoxData d;
    d.buf = buf; d.len = bufLen; d.prompt = prompt;

    INT_PTR ret = DialogBoxIndirectParamA(GetModuleHandleA(NULL),
        (DLGTEMPLATE *)tmpl, hParent, InputDlgProc, (LPARAM)&d);
    return (ret == 1);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void BuildFont(HDC hdc) {
    if (g_dasmFont) { DeleteObject(g_dasmFont); g_dasmFont = NULL; }
    g_dasmFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_DONTCARE, "Consolas");
    if (!g_dasmFont)
        g_dasmFont = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);
    HFONT old = (HFONT)SelectObject(hdc, g_dasmFont);
    TEXTMETRICA tm;
    GetTextMetricsA(hdc, &tm);
    g_dasmCharW = tm.tmAveCharWidth;
    g_dasmCharH = tm.tmHeight + tm.tmExternalLeading;
    SelectObject(hdc, old);
}

static void UpdateStatusBar(void) {
    if (!g_dasmStatus) return;
    char buf[256];
    if (g_dasmCursorRow >= 0 && g_dasmCursorRow < g_dasmLineCount) {
        DecodedInsn *di = &g_dasmLines[g_dasmCursorRow];
        char sym[160] = {0};
        char symBuf[128];
        if ((di->is_branch || di->is_call) && di->branch_target &&
            !di->indirect_resolved &&
            DasmSymbolLookup(di->branch_target, symBuf, sizeof(symBuf)))
            snprintf(sym, sizeof(sym), "  | %s", symBuf);
        snprintf(buf, sizeof(buf), "  Address: %016I64X  |  Len: %u  |  %s%s",
            di->address, (unsigned)di->length, di->text, sym);
    } else {
        snprintf(buf, sizeof(buf), "  No data");
    }
    SetWindowTextA(g_dasmStatus, buf);
}

static void RedecodeVisible(void) {
    if (!g_dasmProcess || g_dasmBaseAddr == 0) return;
    g_dasmLineCount = DasmDecodeForward(g_dasmBaseAddr, DASM_MAX_LINES, g_dasmLines);
    if (g_dasmView) InvalidateRect(g_dasmView, NULL, FALSE);
}

static int GetVisibleRows(void) {
    if (!g_dasmView || g_dasmCharH == 0) return 25;
    RECT rc;
    GetClientRect(g_dasmView, &rc);
    return (rc.bottom - rc.top + g_dasmCharH - 1) / g_dasmCharH;
}

static void EnsureCursorVisible(void) {
    int vis = GetVisibleRows();
    if (g_dasmCursorRow < g_dasmViewTop)
        g_dasmViewTop = g_dasmCursorRow;
    if (g_dasmCursorRow >= g_dasmViewTop + vis)
        g_dasmViewTop = g_dasmCursorRow - vis + 1;
    if (g_dasmViewTop < 0) g_dasmViewTop = 0;
}

static BOOL ExtendBackward(int n) {
    DecodedInsn tmpBack[DASM_MAX_LINES];
    int got = DasmDecodeBackward(g_dasmBaseAddr, n, tmpBack);
    if (got <= 0) return FALSE;
    int drop = (g_dasmLineCount + got > DASM_MAX_LINES)
               ? (g_dasmLineCount + got - DASM_MAX_LINES) : 0;
    int keep = g_dasmLineCount - drop;
    memmove(&g_dasmLines[got], g_dasmLines, keep * sizeof(DecodedInsn));
    memcpy(g_dasmLines, tmpBack, got * sizeof(DecodedInsn));
    g_dasmLineCount  = got + keep;
    g_dasmBaseAddr   = g_dasmLines[0].address;
    g_dasmCursorRow += got;
    g_dasmViewTop   += got;
    return TRUE;
}

static void NavUp(int n) {
    for (int i = 0; i < n; i++) {
        if (g_dasmCursorRow > 0) {
            g_dasmCursorRow--;
        } else {
            if (!ExtendBackward(16)) break;
            if (g_dasmCursorRow > 0) g_dasmCursorRow--;
            else break;
        }
    }
    EnsureCursorVisible();
    UpdateStatusBar();
    if (g_dasmView) InvalidateRect(g_dasmView, NULL, FALSE);
}

static void NavDown(int n) {
    for (int i = 0; i < n; i++) {
        if (g_dasmCursorRow < g_dasmLineCount - 1) {
            g_dasmCursorRow++;
        } else if (g_dasmLineCount > 0) {
            int shift = DASM_MAX_LINES / 4;
            if (shift >= g_dasmLineCount) shift = g_dasmLineCount / 2;
            if (shift < 1) break;
            UINT64 nextAddr = g_dasmLines[g_dasmLineCount - 1].address
                            + g_dasmLines[g_dasmLineCount - 1].length;
            memmove(g_dasmLines, &g_dasmLines[shift],
                    (g_dasmLineCount - shift) * sizeof(DecodedInsn));
            g_dasmLineCount -= shift;
            g_dasmCursorRow -= shift;
            g_dasmViewTop   -= shift;
            if (g_dasmCursorRow < 0) g_dasmCursorRow = 0;
            if (g_dasmViewTop   < 0) g_dasmViewTop   = 0;
            g_dasmBaseAddr = g_dasmLines[0].address;
            int more = DasmDecodeForward(nextAddr,
                DASM_MAX_LINES - g_dasmLineCount, &g_dasmLines[g_dasmLineCount]);
            g_dasmLineCount += more;
            if (g_dasmCursorRow < g_dasmLineCount - 1)
                g_dasmCursorRow++;
        } else break;
    }
    EnsureCursorVisible();
    UpdateStatusBar();
    if (g_dasmView) InvalidateRect(g_dasmView, NULL, FALSE);
}

static void HistPush(UINT64 addr) {
    if (g_histTop < DASM_HIST_MAX) {
        g_hist[g_histTop++] = addr;
    } else {
        memmove(g_hist, g_hist + 1, (DASM_HIST_MAX - 1) * sizeof(UINT64));
        g_hist[DASM_HIST_MAX - 1] = addr;
    }
    g_fwdTop = 0;
}

static void NavBack(void) {
    if (g_histTop <= 0) return;
    UINT64 cur = g_dasmBaseAddr;
    UINT64 prev = g_hist[--g_histTop];
    if (g_fwdTop < DASM_HIST_MAX)
        g_fwd[g_fwdTop++] = cur;
    DasmGotoAddress(prev);
}

static void NavForward(void) {
    if (g_fwdTop <= 0) return;
    UINT64 cur = g_dasmBaseAddr;
    UINT64 next = g_fwd[--g_fwdTop];
    if (g_histTop < DASM_HIST_MAX)
        g_hist[g_histTop++] = cur;
    DasmGotoAddress(next);
}

/* ------------------------------------------------------------------ */
/* Gutter arrow drawing (Phase E)                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    int  srcRow;
    int  dstRow;
    int  lane;
    BOOL isBackward;
    BOOL highlighted;
} ArrowInfo;

static int arrow_dist_cmp(const void *a, const void *b) {
    const ArrowInfo *aa = (const ArrowInfo *)a;
    const ArrowInfo *ab = (const ArrowInfo *)b;
    int da = aa->srcRow > aa->dstRow ? aa->srcRow - aa->dstRow : aa->dstRow - aa->srcRow;
    int db = ab->srcRow > ab->dstRow ? ab->srcRow - ab->dstRow : ab->dstRow - ab->srcRow;
    return da - db;
}

static void DrawGutter(HDC hdc, int drawCount, int cursorScreenRow) {
    if (drawCount <= 0 || g_dasmCharH == 0) return;

    ArrowInfo arrows[DASM_MAX_LINES];
    int       arrowCount = 0;

    for (int i = 0; i < drawCount && arrowCount < DASM_MAX_LINES; i++) {
        int bufIdx = g_dasmViewTop + i;
        DecodedInsn *di = &g_dasmLines[bufIdx];
        if (!di->is_branch || di->is_call || di->branch_target == 0) continue;

        /* Find destination row in visible range (forward or backward) */
        int dstRow = -1;
        for (int j = 0; j < drawCount; j++) {
            if (g_dasmLines[g_dasmViewTop + j].address == di->branch_target) {
                dstRow = j;
                break;
            }
        }

        /* Also handle off-screen targets: clamp to edge */
        if (dstRow < 0) {
            if (di->branch_target < g_dasmLines[g_dasmViewTop].address)
                dstRow = -1; /* above visible area */
            else if (di->branch_target > g_dasmLines[g_dasmViewTop + drawCount - 1].address)
                dstRow = drawCount; /* below visible area */
            else
                continue; /* target in range but not at instruction boundary */
        }

        ArrowInfo ar;
        ar.srcRow     = i;
        ar.dstRow     = dstRow;
        ar.lane       = -1;
        ar.isBackward = (dstRow < i);
        ar.highlighted = (i == cursorScreenRow);
        arrows[arrowCount++] = ar;
    }

    if (arrowCount == 0) return;

    /* Sort by distance (short jumps get inner lanes) */
    qsort(arrows, arrowCount, sizeof(ArrowInfo), arrow_dist_cmp);

    /* Lane assignment using per-row occupancy bitmap */
    BYTE laneRowUsed[DASM_GUTTER_LANES][DASM_MAX_LINES + 2];
    memset(laneRowUsed, 0, sizeof(laneRowUsed));

    for (int a = 0; a < arrowCount; a++) {
        int lo = arrows[a].srcRow < arrows[a].dstRow ? arrows[a].srcRow : arrows[a].dstRow;
        int hi = arrows[a].srcRow > arrows[a].dstRow ? arrows[a].srcRow : arrows[a].dstRow;
        if (lo < 0) lo = 0;
        if (hi >= drawCount + 1) hi = drawCount;
        int lane = -1;
        for (int l = 0; l < DASM_GUTTER_LANES; l++) {
            BOOL free = TRUE;
            for (int r = lo; r <= hi; r++) {
                if (r < DASM_MAX_LINES + 2 && laneRowUsed[l][r]) { free = FALSE; break; }
            }
            if (free) { lane = l; break; }
        }
        if (lane < 0) continue;
        arrows[a].lane = lane;
        for (int r = lo; r <= hi; r++)
            if (r >= 0 && r < DASM_MAX_LINES + 2) laneRowUsed[lane][r] = 1;
    }

    /* Draw arrows */
    int gutterRight = DASM_GUTTER_W - 2;

    for (int a = 0; a < arrowCount; a++) {
        if (arrows[a].lane < 0) continue;

        COLORREF clr;
        if (arrows[a].highlighted)     clr = RGB(255, 255,  80);
        else if (arrows[a].isBackward) clr = RGB(255, 100, 100);
        else                           clr = RGB(100, 200, 255);

        HPEN pen = CreatePen(PS_SOLID, 1, clr);
        HPEN old = (HPEN)SelectObject(hdc, pen);

        int lane   = arrows[a].lane;
        int lineX  = DASM_GUTTER_W - (lane + 1) * DASM_LANE_W + DASM_LANE_W / 2;
        int srcMid = arrows[a].srcRow * g_dasmCharH + g_dasmCharH / 2;
        int dstMid;
        BOOL dstOffscreen = FALSE;

        if (arrows[a].dstRow < 0) {
            dstMid = 0;
            dstOffscreen = TRUE;
        } else if (arrows[a].dstRow >= drawCount) {
            dstMid = drawCount * g_dasmCharH;
            dstOffscreen = TRUE;
        } else {
            dstMid = arrows[a].dstRow * g_dasmCharH + g_dasmCharH / 2;
        }

        /* Horizontal tick from source to vertical lane */
        MoveToEx(hdc, gutterRight, srcMid, NULL);
        LineTo  (hdc, lineX, srcMid);

        /* Vertical line */
        MoveToEx(hdc, lineX, srcMid, NULL);
        LineTo  (hdc, lineX, dstMid);

        /* Horizontal tick from lane to arrow tip at destination */
        if (!dstOffscreen) {
            MoveToEx(hdc, lineX, dstMid, NULL);
            LineTo  (hdc, gutterRight, dstMid);

            /* Filled arrowhead pointing right */
            HBRUSH br = CreateSolidBrush(clr);
            HBRUSH oldBr = (HBRUSH)SelectObject(hdc, br);
            HPEN arPen = CreatePen(PS_SOLID, 1, clr);
            HPEN oldPen2 = (HPEN)SelectObject(hdc, arPen);
            POINT tip[3] = {
                { gutterRight + 4, dstMid },
                { gutterRight - 2, dstMid - 4 },
                { gutterRight - 2, dstMid + 4 }
            };
            Polygon(hdc, tip, 3);
            SelectObject(hdc, oldPen2);
            DeleteObject(arPen);
            SelectObject(hdc, oldBr);
            DeleteObject(br);
        }

        SelectObject(hdc, old);
        DeleteObject(pen);
    }
}

/* ------------------------------------------------------------------ */
/* View child window proc                                               */
/* ------------------------------------------------------------------ */

static void HighlightTokenAtPixel(HWND hWnd, int mouseX, int mouseY) {
    int screenRow = mouseY / (g_dasmCharH ? g_dasmCharH : 16);
    int bufIdx    = g_dasmViewTop + screenRow;
    if (bufIdx < 0 || bufIdx >= g_dasmLineCount) return;

    int x_mnem = DASM_GUTTER_W + 2 + 18 * g_dasmCharW + 46 * g_dasmCharW;
    int colInMnem = (mouseX - x_mnem) / (g_dasmCharW ? g_dasmCharW : 8);

    DecodedInsn *di = &g_dasmLines[bufIdx];
    DasmToken tokens[DASM_MAX_TOKENS];
    int ntok = DasmColorLine(di, tokens, DASM_MAX_TOKENS);
    for (int t = 0; t < ntok; t++) {
        if (colInMnem >= tokens[t].col &&
            colInMnem < tokens[t].col + tokens[t].len) {
            int copyLen = tokens[t].len < 63 ? tokens[t].len : 63;
            memcpy(g_hlText, di->text + tokens[t].col, copyLen);
            g_hlText[copyLen] = '\0';
            g_hlActive = (g_hlText[0] != ' ' && g_hlText[0] != '\0');
            InvalidateRect(hWnd, NULL, FALSE);
            break;
        }
    }
}

static LRESULT CALLBACK DasmViewProc(HWND hWnd, UINT msg,
                                      WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc;
        GetClientRect(hWnd, &rc);

        /* Background */
        HBRUSH bgBrush = CreateSolidBrush(RGB(20, 20, 20));
        FillRect(hdc, &rc, bgBrush);
        DeleteObject(bgBrush);

        if (!g_dasmLineCount || !g_dasmFont) { EndPaint(hWnd, &ps); return 0; }

        HFONT old = (HFONT)SelectObject(hdc, g_dasmFont);
        SetBkMode(hdc, TRANSPARENT);

        /* Column pixel offsets -- addr shifted right by gutter */
        int x_addr  = DASM_GUTTER_W + 2;
        int x_bytes = x_addr  + 18 * g_dasmCharW;
        int x_mnem  = x_bytes + 46 * g_dasmCharW;

        int visRows   = (rc.bottom - rc.top + g_dasmCharH - 1) / g_dasmCharH;
        int available = g_dasmLineCount - g_dasmViewTop;
        int drawCount = (available < visRows) ? available : visRows;
        if (drawCount < 0) drawCount = 0;

        /* Determine cursor screen row for gutter highlight */
        int cursorScreenRow = g_dasmCursorRow - g_dasmViewTop;

        for (int i = 0; i < drawCount; i++) {
            int bufIdx = g_dasmViewTop + i;
            DecodedInsn *di = &g_dasmLines[bufIdx];
            int y = i * g_dasmCharH;

            /* Selection highlight */
            if (DasmSelActive()) {
                int selLo, selHi;
                DasmSelGetRange(&selLo, &selHi);
                if (bufIdx >= selLo && bufIdx <= selHi) {
                    RECT rowRc = { 0, y, rc.right, y + g_dasmCharH };
                    HBRUSH selBr = CreateSolidBrush(RGB(40, 60, 90));
                    FillRect(hdc, &rowRc, selBr);
                    DeleteObject(selBr);
                }
            }

            /* Cursor row highlight */
            if (bufIdx == g_dasmCursorRow) {
                RECT rowRc = { 0, y, rc.right, y + g_dasmCharH };
                HBRUSH sel = CreateSolidBrush(RGB(0, 60, 120));
                FillRect(hdc, &rowRc, sel);
                DeleteObject(sel);
            }

            /* Address column: label (yellow) or hex address (green) */
            const char *lbl = DasmLabelGet(di->address);
            if (lbl) {
                char lblBuf[20];
                strncpy(lblBuf, lbl, 17);
                lblBuf[17] = ':'; lblBuf[18] = '\0';
                SetTextColor(hdc, RGB(255, 255, 80));
                TextOutA(hdc, x_addr, y, lblBuf, (int)strlen(lblBuf));
            } else {
                char addr[20];
                snprintf(addr, sizeof(addr), "%016I64X", di->address);
                SetTextColor(hdc, DASM_COL_ADDR);
                TextOutA(hdc, x_addr, y, addr, (int)strlen(addr));
            }

            /* Hex bytes */
            char hex[48] = {0};
            char *p = hex;
            for (int b = 0; b < (int)di->length && b < 15; b++) {
                snprintf(p, 4, "%02X ", di->bytes[b]);
                p += 3;
            }
            SetTextColor(hdc, DASM_COL_BYTES);
            TextOutA(hdc, x_bytes, y, hex, (int)strlen(hex));

            /* Mnemonic + operands (syntax colored with highlight) */
            {
                DasmToken tokens[DASM_MAX_TOKENS];
                int ntok = DasmColorLine(di, tokens, DASM_MAX_TOKENS);
                for (int t = 0; t < ntok; t++) {
                    /* Highlight matching token background */
                    if (g_hlActive && tokens[t].len > 0) {
                        char tok[64] = {0};
                        int copyLen = tokens[t].len < 63 ? tokens[t].len : 63;
                        memcpy(tok, di->text + tokens[t].col, copyLen);
                        if (strcmp(tok, g_hlText) == 0) {
                            RECT hlRc;
                            hlRc.left   = x_mnem + tokens[t].col * g_dasmCharW;
                            hlRc.right  = hlRc.left + tokens[t].len * g_dasmCharW;
                            hlRc.top    = y;
                            hlRc.bottom = y + g_dasmCharH;
                            HBRUSH hb = CreateSolidBrush(RGB(60, 60, 0));
                            FillRect(hdc, &hlRc, hb);
                            DeleteObject(hb);
                        }
                    }
                    SetTextColor(hdc, tokens[t].color);
                    TextOutA(hdc, x_mnem + tokens[t].col * g_dasmCharW, y,
                             di->text + tokens[t].col, tokens[t].len);
                }

                /* Phase D3: symbol annotation for branch targets (skipped for indirect
                   calls whose text was already rewritten to show the symbol inline) */
                if (di->is_branch && di->branch_target && !di->indirect_resolved) {
                    char symBuf[128];
                    const char *sym = DasmSymbolLookup(di->branch_target, symBuf, sizeof(symBuf));
                    if (!sym) {
                        /* Try label */
                        sym = DasmLabelGet(di->branch_target);
                    }
                    if (sym) {
                        int mnemLen = (int)strlen(di->text);
                        char annot[160];
                        snprintf(annot, sizeof(annot), " ; %s", sym);
                        SetTextColor(hdc, DASM_COL_KEYWORD);
                        TextOutA(hdc, x_mnem + mnemLen * g_dasmCharW, y,
                                 annot, (int)strlen(annot));
                    }
                }

                /* Phase F5: inline comment */
                {
                    const char *cmt = DasmCommentGet(di->address);
                    if (cmt) {
                        int mnemLen = (int)strlen(di->text);
                        /* Account for symbol annotation offset */
                        int extraOff = 0;
                        if (di->is_branch && di->branch_target) {
                            char symBuf2[128];
                            const char *sym2 = DasmSymbolLookup(di->branch_target, symBuf2, sizeof(symBuf2));
                            if (!sym2) sym2 = DasmLabelGet(di->branch_target);
                            if (sym2) extraOff = (int)(strlen(sym2) + 3); /* " ; " + sym */
                        }
                        char cmtBuf[160];
                        snprintf(cmtBuf, sizeof(cmtBuf), "  ; %s", cmt);
                        SetTextColor(hdc, RGB(128, 128, 128));
                        TextOutA(hdc, x_mnem + (mnemLen + extraOff) * g_dasmCharW, y,
                                 cmtBuf, (int)strlen(cmtBuf));
                    }
                }
            }
        }

        /* Phase E: draw gutter arrows */
        DrawGutter(hdc, drawCount, cursorScreenRow);

        SelectObject(hdc, old);
        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        BOOL ctrl  = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        if (ctrl) {
            HighlightTokenAtPixel(hWnd, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            SetFocus(hWnd);
            return 0;
        }
        g_hlActive = FALSE;
        int screenRow = GET_Y_LPARAM(lParam) / (g_dasmCharH ? g_dasmCharH : 16);
        int bufIdx = g_dasmViewTop + screenRow;
        if (bufIdx >= 0 && bufIdx < g_dasmLineCount) {
            BOOL shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (shift && g_dasmCursorRow >= 0) {
                if (g_dasmSelAnchor < 0)
                    g_dasmSelAnchor = g_dasmCursorRow;
                g_dasmSelEnd = bufIdx;
            } else {
                DasmSelClear();
            }
            g_dasmCursorRow = bufIdx;
            UpdateStatusBar();
            InvalidateRect(hWnd, NULL, FALSE);
        }
        SetFocus(hWnd);
        return 0;
    }

    case WM_LBUTTONDBLCLK: {
        int screenRow = GET_Y_LPARAM(lParam) / (g_dasmCharH ? g_dasmCharH : 16);
        int bufIdx    = g_dasmViewTop + screenRow;
        if (bufIdx < 0 || bufIdx >= g_dasmLineCount) return 0;

        DecodedInsn *di = &g_dasmLines[bufIdx];
        if ((di->is_branch || di->is_call) && di->branch_target) {
            HistPush(di->address);
            DasmGotoAddress(di->branch_target);
        } else {
            HighlightTokenAtPixel(hWnd, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        }
        return 0;
    }

    case WM_RBUTTONUP: {
        /* Right-click: update cursor to clicked row, show context menu */
        int screenRow = GET_Y_LPARAM(lParam) / (g_dasmCharH ? g_dasmCharH : 16);
        int bufIdx = g_dasmViewTop + screenRow;
        if (bufIdx >= 0 && bufIdx < g_dasmLineCount) {
            g_dasmCursorRow = bufIdx;
            UpdateStatusBar();
            InvalidateRect(hWnd, NULL, FALSE);
        }
        if (g_dasmCursorRow < 0 || g_dasmCursorRow >= g_dasmLineCount) return 0;
        HMENU hm = CreatePopupMenu();
        AppendMenuA(hm, MF_STRING,    IDM_DASM_COPY_ADDR, "Copy Address");
        AppendMenuA(hm, MF_STRING,    IDM_DASM_COPY_LINE,
                    DasmSelActive() ? "Copy Lines\tCtrl+C" : "Copy Line\tCtrl+C");
        AppendMenuA(hm, MF_STRING,    IDM_DASM_GOTO,      "Go to Address...\tCtrl+G");
        AppendMenuA(hm, MF_SEPARATOR, 0, NULL);
        {
            DecodedInsn *di = &g_dasmLines[g_dasmCursorRow];
            if ((di->is_branch || di->is_call) && di->branch_target) {
                char followLabel[64];
                snprintf(followLabel, sizeof(followLabel), "Follow 0x%016I64X", di->branch_target);
                AppendMenuA(hm, MF_STRING, IDM_DASM_FOLLOW, followLabel);
            }
            if (di->slot_address) {
                char derefLabel[80];
                snprintf(derefLabel, sizeof(derefLabel),
                         "Follow deref [0x%016I64X] -> 0x%016I64X",
                         di->slot_address, di->branch_target);
                AppendMenuA(hm, MF_STRING, IDM_DASM_DEREF, derefLabel);
            }
            if ((di->is_branch || di->is_call) && (di->branch_target || di->slot_address))
                AppendMenuA(hm, MF_SEPARATOR, 0, NULL);
        }
        AppendMenuA(hm, MF_STRING,    IDM_DASM_FROMHERE,  "Disasm from here");
        AppendMenuA(hm, MF_STRING,    IDM_DASM_HIGHLIGHT, "Highlight word\tCtrl+Click");
        AppendMenuA(hm, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hm, MF_STRING,    IDM_DASM_RENAME,    "Rename (n)");
        AppendMenuA(hm, MF_STRING,    IDM_DASM_COMMENT,   "Comment (;)");
        POINT pt; GetCursorPos(&pt);
        int cmd = TrackPopupMenu(hm, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, g_dasmHwnd, NULL);
        DestroyMenu(hm);
        if (!cmd) return 0;

        UINT64 curAddr = g_dasmLines[g_dasmCursorRow].address;
        switch (cmd) {
        case IDM_DASM_COPY_ADDR: {
            char ab[32];
            snprintf(ab, sizeof(ab), "%016I64X", curAddr);
            CopyToClipboard(g_dasmHwnd, ab);
            break;
        }
        case IDM_DASM_COPY_LINE: {
            if (DasmSelActive()) {
                int selLo, selHi;
                DasmSelGetRange(&selLo, &selHi);
                int count = selHi - selLo + 1;
                char *bigBuf = (char *)HeapAlloc(GetProcessHeap(), 0, count * 180);
                if (bigBuf) {
                    bigBuf[0] = '\0';
                    for (int r = selLo; r <= selHi; r++) {
                        char line[180];
                        snprintf(line, sizeof(line), "%016I64X  %s\r\n",
                                 g_dasmLines[r].address, g_dasmLines[r].text);
                        strcat(bigBuf, line);
                    }
                    CopyToClipboard(g_dasmHwnd, bigBuf);
                    HeapFree(GetProcessHeap(), 0, bigBuf);
                }
            } else {
                char ib[160];
                snprintf(ib, sizeof(ib), "%016I64X  %s", curAddr, g_dasmLines[g_dasmCursorRow].text);
                CopyToClipboard(g_dasmHwnd, ib);
            }
            break;
        }
        case IDM_DASM_FOLLOW: {
            DecodedInsn *di = &g_dasmLines[g_dasmCursorRow];
            if ((di->is_branch || di->is_call) && di->branch_target) {
                HistPush(curAddr);
                DasmGotoAddress(di->branch_target);
            }
            break;
        }
        case IDM_DASM_DEREF: {
            DecodedInsn *di = &g_dasmLines[g_dasmCursorRow];
            if (di->slot_address && di->branch_target) {
                HistPush(curAddr);
                DasmGotoAddress(di->branch_target);
            }
            break;
        }
        case IDM_DASM_GOTO: {
            char addrBuf[192] = {0};
            if (DasmInputBox(g_dasmHwnd, "Go to address / symbol:", addrBuf, sizeof(addrBuf))) {
                UINT64 addr = 0;
                if (ResolveAddress(addrBuf, &addr)) {
                    HistPush(g_dasmBaseAddr);
                    DasmGotoAddress(addr);
                }
            }
            break;
        }
        case IDM_DASM_RENAME: {
            char newLabel[64] = {0};
            const char *existing = DasmLabelGet(curAddr);
            if (existing) strncpy(newLabel, existing, 63);
            if (DasmInputBox(g_dasmHwnd, "Enter label:", newLabel, sizeof(newLabel))) {
                DasmLabelSet(curAddr, newLabel[0] ? newLabel : NULL);
                InvalidateRect(hWnd, NULL, FALSE);
            }
            break;
        }
        case IDM_DASM_COMMENT: {
            char newCmt[128] = {0};
            const char *existing = DasmCommentGet(curAddr);
            if (existing) strncpy(newCmt, existing, 127);
            if (DasmInputBox(g_dasmHwnd, "Enter comment:", newCmt, sizeof(newCmt))) {
                DasmCommentSet(curAddr, newCmt[0] ? newCmt : NULL);
                InvalidateRect(hWnd, NULL, FALSE);
            }
            break;
        }
        case IDM_DASM_FROMHERE: {
            HistPush(g_dasmBaseAddr);
            DasmGotoAddress(curAddr);
            break;
        }
        case IDM_DASM_HIGHLIGHT: {
            DecodedInsn *di = &g_dasmLines[g_dasmCursorRow];
            DasmToken tokens[DASM_MAX_TOKENS];
            int ntok = DasmColorLine(di, tokens, DASM_MAX_TOKENS);
            if (ntok > 0) {
                int copyLen = tokens[0].len < 63 ? tokens[0].len : 63;
                memcpy(g_hlText, di->text + tokens[0].col, copyLen);
                g_hlText[copyLen] = '\0';
                g_hlActive = (g_hlText[0] != ' ' && g_hlText[0] != '\0');
                InvalidateRect(g_dasmView, NULL, FALSE);
            }
            break;
        }
        }
        return 0;
    }

    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        if (delta > 0) NavUp(3);
        else           NavDown(3);
        return 0;
    }

    case WM_KEYDOWN: {
        BOOL ctrl  = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        BOOL shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
        switch (wParam) {
        case VK_UP:
        case VK_DOWN:
        case VK_PRIOR:
        case VK_NEXT: {
            if (shift) {
                if (g_dasmSelAnchor < 0)
                    g_dasmSelAnchor = g_dasmCursorRow;
            } else {
                DasmSelClear();
            }
            if (wParam == VK_UP)        NavUp(1);
            else if (wParam == VK_DOWN) NavDown(1);
            else if (wParam == VK_PRIOR) NavUp(GetVisibleRows());
            else                         NavDown(GetVisibleRows());
            if (shift)
                g_dasmSelEnd = g_dasmCursorRow;
            break;
        }
        case VK_ESCAPE:
            DasmSelClear();
            if (g_histTop > 0)
                NavBack();
            g_hlActive = FALSE;
            InvalidateRect(hWnd, NULL, FALSE);
            break;
        case VK_RETURN:
            if (g_dasmCursorRow >= 0 && g_dasmCursorRow < g_dasmLineCount) {
                DecodedInsn *di = &g_dasmLines[g_dasmCursorRow];
                if (di->is_branch && di->branch_target) {
                    HistPush(di->address);
                    DasmGotoAddress(di->branch_target);
                }
            }
            break;
        case VK_BACK:
            NavBack();
            break;
        case VK_F5:
            DasmSymbolBuild(g_dasmProcess);
            InvalidateRect(hWnd, NULL, FALSE);
            break;
        default:
            if (ctrl && wParam == 'C') {
                /* Ctrl+C: copy selection or current line */
                if (DasmSelActive()) {
                    int selLo, selHi;
                    DasmSelGetRange(&selLo, &selHi);
                    int count = selHi - selLo + 1;
                    char *bigBuf = (char *)HeapAlloc(GetProcessHeap(), 0, count * 180);
                    if (bigBuf) {
                        bigBuf[0] = '\0';
                        for (int r = selLo; r <= selHi; r++) {
                            char line[180];
                            snprintf(line, sizeof(line), "%016I64X  %s\r\n",
                                     g_dasmLines[r].address, g_dasmLines[r].text);
                            strcat(bigBuf, line);
                        }
                        CopyToClipboard(g_dasmHwnd, bigBuf);
                        HeapFree(GetProcessHeap(), 0, bigBuf);
                    }
                } else if (g_dasmCursorRow >= 0 && g_dasmCursorRow < g_dasmLineCount) {
                    char buf[180];
                    snprintf(buf, sizeof(buf), "%016I64X  %s",
                             g_dasmLines[g_dasmCursorRow].address,
                             g_dasmLines[g_dasmCursorRow].text);
                    CopyToClipboard(g_dasmHwnd, buf);
                }
            } else if (ctrl && wParam == 'G') {
                SendMessage(GetParent(hWnd), WM_COMMAND, IDM_DASM_GOTO, 0);
            } else {
                PostMessage(GetParent(hWnd), WM_KEYDOWN, wParam, lParam);
            }
        }
        return 0;
    }

    case WM_CHAR: {
        /* Phase F hotkeys */
        char ch = (char)(unsigned char)wParam;
        if (g_dasmCursorRow < 0 || g_dasmCursorRow >= g_dasmLineCount) return 0;
        UINT64 curAddr = g_dasmLines[g_dasmCursorRow].address;

        if (ch == 'n' || ch == 'N') {
            char newLabel[64] = {0};
            const char *existing = DasmLabelGet(curAddr);
            if (existing) strncpy(newLabel, existing, 63);
            if (DasmInputBox(g_dasmHwnd, "Enter label:", newLabel, sizeof(newLabel))) {
                DasmLabelSet(curAddr, newLabel[0] ? newLabel : NULL);
                InvalidateRect(hWnd, NULL, FALSE);
            }
            return 0;
        }
        if (ch == ';') {
            char newCmt[128] = {0};
            const char *existing = DasmCommentGet(curAddr);
            if (existing) strncpy(newCmt, existing, 127);
            if (DasmInputBox(g_dasmHwnd, "Enter comment:", newCmt, sizeof(newCmt))) {
                DasmCommentSet(curAddr, newCmt[0] ? newCmt : NULL);
                InvalidateRect(hWnd, NULL, FALSE);
            }
            return 0;
        }
        return 0;
    }
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Main window proc                                                     */
/* ------------------------------------------------------------------ */

static void LayoutChildren(HWND hWnd) {
    RECT rc;
    GetClientRect(hWnd, &rc);
    int tbH = 32;
    SendMessage(g_dasmStatus, WM_SIZE, 0, 0);
    RECT srect;
    GetWindowRect(g_dasmStatus, &srect);
    int statusH = srect.bottom - srect.top;
    MoveWindow(g_dasmBackBtn,  4,   5, 30, 22, TRUE);
    MoveWindow(g_dasmFwdBtn,  36,  5, 30, 22, TRUE);
    MoveWindow(g_dasmGotoEdit, 72, 5, 260, 22, TRUE);
    MoveWindow(g_dasmGotoBtn,  336, 5, 44, 22, TRUE);
    MoveWindow(g_dasmView, 0, tbH, rc.right, rc.bottom - tbH - statusH, TRUE);
}

static BOOL IsHexString(const char *s) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!*s) return FALSE;
    for (; *s; s++) {
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') ||
              (*s >= 'A' && *s <= 'F')))
            return FALSE;
    }
    return TRUE;
}

static BOOL ResolveAddress(const char *text, UINT64 *outAddr) {
    if (!text || !text[0] || !outAddr) return FALSE;
    while (*text == ' ') text++;
    if (IsHexString(text)) {
        UINT64 addr = 0;
        const char *p = text;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        if (sscanf(p, "%I64x", &addr) == 1 && addr) {
            *outAddr = addr;
            return TRUE;
        }
    }
    return DasmSymbolFind(text, outAddr);
}

static WNDPROC g_origEditProc = NULL;

static LRESULT CALLBACK GotoEditSubclassProc(HWND hWnd, UINT msg,
                                              WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        DoGoto();
        if (g_dasmView) SetFocus(g_dasmView);
        return 0;
    }
    if (msg == WM_CHAR && wParam == '\r') return 0;
    return CallWindowProcA(g_origEditProc, hWnd, msg, wParam, lParam);
}

static void DoGoto(void) {
    char buf[192] = {0};
    GetWindowTextA(g_dasmGotoEdit, buf, sizeof(buf));
    UINT64 addr = 0;
    if (ResolveAddress(buf, &addr))
        DasmGotoAddress(addr);
}

/* Copy helpers */
static void CopyToClipboard(HWND hwnd, const char *text) {
    int len = (int)strlen(text);
    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        HGLOBAL hm = GlobalAlloc(GMEM_MOVEABLE, len + 1);
        if (hm) {
            char *p = (char *)GlobalLock(hm);
            memcpy(p, text, len + 1);
            GlobalUnlock(hm);
            SetClipboardData(CF_TEXT, hm);
        }
        CloseClipboard();
    }
}

static LRESULT CALLBACK DasmWndProc(HWND hWnd, UINT msg,
                                      WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = ((CREATESTRUCTA *)lParam)->hInstance;
        g_dasmBackBtn = CreateWindowA("BUTTON", "<<",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 0, 0, hWnd, (HMENU)(UINT_PTR)IDC_DASM_BACK_BTN, hInst, NULL);
        g_dasmFwdBtn = CreateWindowA("BUTTON", ">>",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 0, 0, hWnd, (HMENU)(UINT_PTR)IDC_DASM_FWD_BTN, hInst, NULL);
        g_dasmGotoEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            0, 0, 0, 0, hWnd, (HMENU)(UINT_PTR)IDC_DASM_GOTO_EDIT, hInst, NULL);
        g_dasmGotoBtn = CreateWindowA("BUTTON", "Go",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, 0, 0, hWnd, (HMENU)(UINT_PTR)IDC_DASM_GOTO_BTN, hInst, NULL);
        g_dasmStatus = CreateWindowExA(0, STATUSCLASSNAME, "",
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hWnd, (HMENU)(UINT_PTR)IDC_DASM_STATUS, hInst, NULL);
        g_dasmView = CreateWindowA(DASM_VIEW_CLASS, "",
            WS_CHILD | WS_VISIBLE,
            0, 32, 100, 100, hWnd, NULL, hInst, NULL);
        HDC hdc = GetDC(hWnd);
        BuildFont(hdc);
        ReleaseDC(hWnd, hdc);
        SendMessage(g_dasmBackBtn,  WM_SETFONT, (WPARAM)g_dasmFont, FALSE);
        SendMessage(g_dasmFwdBtn,   WM_SETFONT, (WPARAM)g_dasmFont, FALSE);
        SendMessage(g_dasmGotoEdit, WM_SETFONT, (WPARAM)g_dasmFont, FALSE);
        g_origEditProc = (WNDPROC)SetWindowLongPtrA(g_dasmGotoEdit, GWLP_WNDPROC,
            (LONG_PTR)GotoEditSubclassProc);
        SendMessage(g_dasmGotoBtn,  WM_SETFONT, (WPARAM)g_dasmFont, FALSE);
        SendMessage(g_dasmStatus,   WM_SETFONT, (WPARAM)g_dasmFont, FALSE);
        return 0;
    }
    case WM_SIZE:
        LayoutChildren(hWnd);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_DASM_BACK_BTN:
            NavBack();
            if (g_dasmView) SetFocus(g_dasmView);
            return 0;
        case IDC_DASM_FWD_BTN:
            NavForward();
            if (g_dasmView) SetFocus(g_dasmView);
            return 0;
        case IDC_DASM_GOTO_BTN:
            DoGoto();
            return 0;
        case IDM_DASM_COPY_ADDR:
            if (g_dasmCursorRow >= 0 && g_dasmCursorRow < g_dasmLineCount) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%016I64X",
                         g_dasmLines[g_dasmCursorRow].address);
                CopyToClipboard(hWnd, buf);
            }
            return 0;
        case IDM_DASM_COPY_LINE:
            if (DasmSelActive()) {
                int selLo, selHi;
                DasmSelGetRange(&selLo, &selHi);
                int count = selHi - selLo + 1;
                char *bigBuf = (char *)HeapAlloc(GetProcessHeap(), 0, count * 180);
                if (bigBuf) {
                    bigBuf[0] = '\0';
                    for (int r = selLo; r <= selHi; r++) {
                        char line[180];
                        snprintf(line, sizeof(line), "%016I64X  %s\r\n",
                                 g_dasmLines[r].address, g_dasmLines[r].text);
                        strcat(bigBuf, line);
                    }
                    CopyToClipboard(hWnd, bigBuf);
                    HeapFree(GetProcessHeap(), 0, bigBuf);
                }
            } else if (g_dasmCursorRow >= 0 && g_dasmCursorRow < g_dasmLineCount) {
                char buf[160];
                snprintf(buf, sizeof(buf), "%016I64X  %s",
                         g_dasmLines[g_dasmCursorRow].address,
                         g_dasmLines[g_dasmCursorRow].text);
                CopyToClipboard(hWnd, buf);
            }
            return 0;
        case IDM_DASM_GOTO: {
            char addrBuf[192] = {0};
            if (DasmInputBox(hWnd, "Go to address / symbol:", addrBuf, sizeof(addrBuf))) {
                UINT64 addr = 0;
                if (ResolveAddress(addrBuf, &addr)) {
                    HistPush(g_dasmBaseAddr);
                    DasmGotoAddress(addr);
                }
            }
            return 0;
        }
        case IDM_DASM_RENAME:
            if (g_dasmView && g_dasmCursorRow >= 0 && g_dasmCursorRow < g_dasmLineCount) {
                UINT64 curAddr = g_dasmLines[g_dasmCursorRow].address;
                char newLabel[64] = {0};
                const char *existing = DasmLabelGet(curAddr);
                if (existing) strncpy(newLabel, existing, 63);
                if (DasmInputBox(hWnd, "Enter label:", newLabel, sizeof(newLabel))) {
                    DasmLabelSet(curAddr, newLabel[0] ? newLabel : NULL);
                    InvalidateRect(g_dasmView, NULL, FALSE);
                }
            }
            return 0;
        case IDM_DASM_COMMENT:
            if (g_dasmView && g_dasmCursorRow >= 0 && g_dasmCursorRow < g_dasmLineCount) {
                UINT64 curAddr = g_dasmLines[g_dasmCursorRow].address;
                char newCmt[128] = {0};
                const char *existing = DasmCommentGet(curAddr);
                if (existing) strncpy(newCmt, existing, 127);
                if (DasmInputBox(hWnd, "Enter comment:", newCmt, sizeof(newCmt))) {
                    DasmCommentSet(curAddr, newCmt[0] ? newCmt : NULL);
                    InvalidateRect(g_dasmView, NULL, FALSE);
                }
            }
            return 0;
        }
        return 0;
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) DoGoto();
        return 0;
    case WM_CLOSE:
        ShowWindow(hWnd, SW_HIDE);
        return 0;
    case WM_DESTROY:
        if (g_dasmFont) { DeleteObject(g_dasmFont); g_dasmFont = NULL; }
        g_dasmHwnd     = NULL;
        g_dasmView     = NULL;
        g_dasmStatus   = NULL;
        g_dasmGotoEdit = NULL;
        g_dasmGotoBtn  = NULL;
        g_dasmBackBtn  = NULL;
        g_dasmFwdBtn   = NULL;
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

static BOOL s_classesRegistered = FALSE;

static void RegisterDasmClasses(HINSTANCE hInst) {
    if (s_classesRegistered) return;
    s_classesRegistered = TRUE;
    WNDCLASSA wc = {0};
    wc.style         = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc   = DasmWndProc;
    wc.hInstance     = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = DASM_CLASS;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);
    wc.lpfnWndProc   = DasmViewProc;
    wc.hbrBackground = NULL;
    wc.lpszClassName = DASM_VIEW_CLASS;
    RegisterClassA(&wc);
}

void DasmOpen(HWND hParent, HANDLE hProcess) {
    g_dasmProcess = hProcess;
    DasmDecodeInit(hProcess);
    DasmSymbolBuild(hProcess);

    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrA(hParent, GWLP_HINSTANCE);
    RegisterDasmClasses(hInst);

    if (g_dasmHwnd) {
        ShowWindow(g_dasmHwnd, SW_SHOWNORMAL);
        SetForegroundWindow(g_dasmHwnd);
        return;
    }

    /* Derive sym file path: <remora_dir>\<targetbase>.sym */
    g_symPath[0] = '\0';
    if (hProcess) {
        char remoraDir[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, remoraDir, MAX_PATH);
        char *sl = strrchr(remoraDir, '\\');
        if (sl) *(sl + 1) = '\0';

        char targetPath[MAX_PATH] = {0};
        GetModuleFileNameExA(hProcess, NULL, targetPath, MAX_PATH);
        char *tsl  = strrchr(targetPath, '\\');
        const char *tbase = tsl ? tsl + 1 : targetPath;

        char symName[MAX_PATH];
        strncpy(symName, tbase, MAX_PATH - 1);
        char *dot = strrchr(symName, '.');
        if (dot && _stricmp(dot, ".exe") == 0) *dot = '\0';
        strncat(symName, ".sym", MAX_PATH - strlen(symName) - 1);

        snprintf(g_symPath, MAX_PATH, "%s%s", remoraDir, symName);
        DasmLabelsLoad(g_symPath);
    }

    g_dasmHwnd = CreateWindowExA(0, DASM_CLASS, "Disassembly",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 960, 640,
        hParent, NULL, hInst, NULL);

    if (g_dasmHwnd) {
        /* Center over parent */
        RECT pr, wr;
        GetWindowRect(hParent, &pr);
        GetWindowRect(g_dasmHwnd, &wr);
        int w  = wr.right - wr.left;
        int h  = wr.bottom - wr.top;
        int cx = pr.left + (pr.right  - pr.left - w) / 2;
        int cy = pr.top  + (pr.bottom - pr.top  - h) / 2;
        if (cx < 0) cx = 0;
        if (cy < 0) cy = 0;
        SetWindowPos(g_dasmHwnd, NULL, cx, cy, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        ShowWindow(g_dasmHwnd, SW_SHOWNORMAL);
        UpdateWindow(g_dasmHwnd);
    }
}

void DasmGotoAddress(UINT64 addr) {
    g_dasmBaseAddr  = addr;
    g_dasmCursorRow = 0;
    g_dasmViewTop   = 0;
    RedecodeVisible();
    UpdateStatusBar();

    if (g_dasmHwnd) {
        /* Phase D4/H4: title with module + symbol */
        char title[128];
        char modBuf[64], symBuf[128];
        const char *mod = DasmModuleName(addr, modBuf, sizeof(modBuf));
        const char *sym = DasmSymbolLookup(addr, symBuf, sizeof(symBuf));
        if (mod && sym)
            snprintf(title, sizeof(title), "Disassembly - %s!%s", mod, sym);
        else if (sym)
            snprintf(title, sizeof(title), "Disassembly - %s", sym);
        else if (mod)
            snprintf(title, sizeof(title), "Disassembly - %s:%I64X", mod, addr);
        else
            snprintf(title, sizeof(title), "Disassembly - %016I64X", addr);
        SetWindowTextA(g_dasmHwnd, title);
        ShowWindow(g_dasmHwnd, SW_SHOWNORMAL);
        SetForegroundWindow(g_dasmHwnd);
    }

    if (g_dasmGotoEdit) {
        char buf[20];
        snprintf(buf, sizeof(buf), "%I64X", addr);
        SetWindowTextA(g_dasmGotoEdit, buf);
    }
}

void DasmClose(void) {
    if (g_symPath[0])
        DasmLabelsSave(g_symPath);
    DasmSymbolFree();
    DasmLabelsFree();
    if (g_dasmHwnd) {
        DestroyWindow(g_dasmHwnd);
        g_dasmHwnd = NULL;
    }
}
