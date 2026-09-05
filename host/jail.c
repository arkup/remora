#include "jail.h"
#include "hook_defs.h"
#include "jail_shared.h"
#include "resource.h"
#include <string.h>

static JailAction g_actions[HOOK_COUNT];
static char g_conditions[HOOK_COUNT][JAIL_COND_MAX_LEN];
static HMENU g_hMenu;
static HMENU g_hookMenus[HOOK_COUNT];

static int get_aw_partner(int i) {
    const char *name = g_hook_defs[i].api_name;
    int len = lstrlenA(name);
    if (len < 2) return -1;
    char suffix = name[len - 1];
    if (suffix == 'A') {
        if ((i + 1) < (int)HOOK_DEF_COUNT) {
            const char *next = g_hook_defs[i + 1].api_name;
            int nlen = lstrlenA(next);
            if (nlen == len && next[nlen - 1] == 'W' &&
                memcmp(name, next, len - 1) == 0)
                return i + 1;
        }
    } else if (suffix == 'W') {
        if (i > 0) {
            const char *prev = g_hook_defs[i - 1].api_name;
            int plen = lstrlenA(prev);
            if (plen == len && prev[plen - 1] == 'A' &&
                memcmp(name, prev, len - 1) == 0)
                return i - 1;
        }
    }
    return -1;
}

static BOOL is_jail_alias(int i) {
    switch (i) {
    case HOOK_FindFirstFileExA:
    case HOOK_FindFirstFileExW:
        return TRUE;
    default:
        return FALSE;
    }
}

void JailInit(HMENU hJailMenu) {
    g_hMenu = hJailMenu;
    memcpy(g_actions, g_default_jail, sizeof(g_actions));

    int count = GetMenuItemCount(hJailMenu);
    if (count > 0)
        DeleteMenu(hJailMenu, count - 1, MF_BYPOSITION);

    const char *cat_names[] = { "File", "Process", "Memory", "Registry", "Network", "HTTP", "Module", "Crypto" };
    HMENU cat_menus[HOOK_CAT_COUNT];

    for (int c = 0; c < HOOK_CAT_COUNT; c++) {
        cat_menus[c] = CreatePopupMenu();
        AppendMenu(hJailMenu, MF_POPUP, (UINT_PTR)cat_menus[c], cat_names[c]);
    }

    memset(g_hookMenus, 0, sizeof(g_hookMenus));
    for (DWORD i = 0; i < HOOK_DEF_COUNT; i++) {
        int partner = get_aw_partner((int)i);
        if (partner >= 0 && partner < (int)i)
            continue;
        if (is_jail_alias((int)i))
            continue;

        HMENU sub = CreatePopupMenu();
        g_hookMenus[i] = sub;
        if (partner >= 0)
            g_hookMenus[partner] = sub;
        WORD base = IDM_JAIL_BASE + (WORD)(i * 4);
        AppendMenu(sub, MF_STRING, base + 0, "Allow");
        AppendMenu(sub, MF_STRING, base + 1, "Log");
        AppendMenu(sub, MF_STRING, base + 2, "Ask");
        AppendMenu(sub, MF_STRING, base + 3, "Block");
        AppendMenu(sub, MF_SEPARATOR, 0, NULL);
        AppendMenu(sub, MF_STRING, IDM_JAIL_COND_BASE + (WORD)i, "Condition...");

        CheckMenuRadioItem(sub, base, base + 3, base + g_actions[i], MF_BYCOMMAND);

        char display_name[128];
        lstrcpynA(display_name, g_hook_defs[i].api_name, sizeof(display_name));
        if (partner >= 0) {
            int len = lstrlenA(display_name);
            if (len > 0 && display_name[len - 1] == 'A')
                display_name[len - 1] = 0;
        }

        AppendMenu(cat_menus[g_hook_defs[i].category], MF_POPUP, (UINT_PTR)sub, display_name);
    }
}

void JailSetAction(HookId id, JailAction action) {
    if (id < HOOK_COUNT) {
        g_actions[id] = action;
        int partner = get_aw_partner((int)id);
        if (partner >= 0 && partner < HOOK_COUNT)
            g_actions[partner] = action;
    }
}

JailAction JailGetAction(HookId id) {
    if (id >= HOOK_COUNT) return JAIL_ALLOW;
    return g_actions[id];
}

int JailGetAWPartner(int hook_idx) {
    return get_aw_partner(hook_idx);
}

void JailHandleMenuCommand(WORD cmd_id) {
    if (cmd_id < IDM_JAIL_BASE) return;
    WORD offset = cmd_id - IDM_JAIL_BASE;
    WORD hook_idx = offset / 4;
    WORD action = offset % 4;

    if (hook_idx >= HOOK_COUNT) return;

    g_actions[hook_idx] = (JailAction)action;
    int partner = get_aw_partner((int)hook_idx);
    if (partner >= 0 && partner < HOOK_COUNT)
        g_actions[partner] = (JailAction)action;

    WORD base = IDM_JAIL_BASE + hook_idx * 4;
    HMENU sub = g_hookMenus[hook_idx];
    if (sub)
        CheckMenuRadioItem(sub, base, base + 3, cmd_id, MF_BYCOMMAND);
}

/* ------------------------------------------------------------------ */
/* Simple per-hook condition dialog                                     */
/* ------------------------------------------------------------------ */

static int g_cond_hook_idx;

static INT_PTR CALLBACK CondDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG: {
        char title[128];
        const char *name = g_hook_defs[g_cond_hook_idx].api_name;
        int nlen = lstrlenA(name);
        char display[128];
        lstrcpynA(display, name, sizeof(display));
        int partner = get_aw_partner(g_cond_hook_idx);
        if (partner >= 0 && nlen > 0 && display[nlen - 1] == 'A')
            display[nlen - 1] = 0;
        wsprintfA(title, "Condition - %s", display);
        SetWindowTextA(hDlg, title);
        SetDlgItemTextA(hDlg, IDC_COND_EDIT, g_conditions[g_cond_hook_idx]);
        HWND hEdit = GetDlgItem(hDlg, IDC_COND_EDIT);
        SetFocus(hEdit);
        SendMessage(hEdit, EM_SETSEL, 0, -1);
        return FALSE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDOK: {
            char buf[JAIL_COND_MAX_LEN];
            GetDlgItemTextA(hDlg, IDC_COND_EDIT, buf, JAIL_COND_MAX_LEN);
            lstrcpynA(g_conditions[g_cond_hook_idx], buf, JAIL_COND_MAX_LEN);
            int partner = get_aw_partner(g_cond_hook_idx);
            if (partner >= 0 && partner < HOOK_COUNT)
                lstrcpynA(g_conditions[partner], buf, JAIL_COND_MAX_LEN);
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDC_COND_CLEAR:
            g_conditions[g_cond_hook_idx][0] = 0;
            { int partner = get_aw_partner(g_cond_hook_idx);
            if (partner >= 0 && partner < HOOK_COUNT)
                g_conditions[partner][0] = 0; }
            EndDialog(hDlg, IDOK);
            return TRUE;
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

BOOL JailHandleCondCommand(HWND hParent, WORD cmd_id) {
    if (cmd_id < IDM_JAIL_COND_BASE || cmd_id >= IDM_JAIL_COND_BASE + HOOK_COUNT)
        return FALSE;
    g_cond_hook_idx = cmd_id - IDM_JAIL_COND_BASE;
    DialogBoxParamA(GetModuleHandle(NULL), MAKEINTRESOURCEA(IDD_CONDITION),
        hParent, CondDlgProc, 0);
    char label[64];
    if (g_conditions[g_cond_hook_idx][0])
        wsprintfA(label, "Condition... [*]");
    else
        wsprintfA(label, "Condition...");
    MENUITEMINFOA mii = {0};
    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_STRING;
    mii.dwTypeData = label;
    SetMenuItemInfoA(GetMenu(hParent), cmd_id, FALSE, &mii);
    return TRUE;
}

const char *JailGetCondition(int hook_idx) {
    if (hook_idx < 0 || hook_idx >= HOOK_COUNT) return "";
    return g_conditions[hook_idx];
}

static const HookId g_boring_hooks[] = {
    HOOK_GetModuleHandleA,
    HOOK_GetModuleHandleW,
    HOOK_GetProcAddress,
    HOOK_ReadProcessMemory,
    HOOK_VirtualAlloc,
    HOOK_VirtualProtect,
    HOOK_OpenProcess,
};

void JailApplyBoringPreset(void) {
    for (int i = 0; i < (int)(sizeof(g_boring_hooks) / sizeof(g_boring_hooks[0])); i++) {
        HookId id = g_boring_hooks[i];
        if (id >= HOOK_COUNT) continue;
        if (g_actions[id] != g_default_jail[id]) continue;
        g_actions[id] = JAIL_ALLOW;
        HMENU sub = g_hookMenus[id];
        if (sub) {
            WORD base = IDM_JAIL_BASE + (WORD)(id * 4);
            CheckMenuRadioItem(sub, base, base + 3, base + JAIL_ALLOW, MF_BYCOMMAND);
        }
    }
}

void JailSyncConditions(JailSharedMem *shm) {
    if (!shm) return;
    memcpy(shm->conditions, g_conditions, sizeof(g_conditions));
}

void JailSavePolicy(const char *ini_path) {
    char buf[16], key[32];
    for (DWORD i = 0; i < HOOK_DEF_COUNT; i++) {
        wsprintfA(key, "%u", i);
        wsprintfA(buf, "%d", (int)g_actions[i]);
        WritePrivateProfileStringA("JailPolicy", key, buf, ini_path);
    }
    for (DWORD i = 0; i < HOOK_DEF_COUNT; i++) {
        wsprintfA(key, "Cond%u", i);
        WritePrivateProfileStringA("JailConditions", key,
            g_conditions[i][0] ? g_conditions[i] : NULL, ini_path);
    }
}

void JailLoadPolicy(const char *ini_path) {
    char key[32];
    BOOL any = FALSE;
    for (DWORD i = 0; i < HOOK_DEF_COUNT; i++) {
        wsprintfA(key, "%u", i);
        int v = GetPrivateProfileIntA("JailPolicy", key, -1, ini_path);
        if (v < 0) continue;
        if (v > JAIL_BLOCK) v = JAIL_BLOCK;
        g_actions[i] = (JailAction)v;
        any = TRUE;
    }
    if (any) {
        for (DWORD i = 0; i < HOOK_DEF_COUNT; i++) {
            HMENU sub = g_hookMenus[i];
            if (!sub) continue;
            WORD base = IDM_JAIL_BASE + (WORD)(i * 4);
            CheckMenuRadioItem(sub, base, base + 3,
                base + g_actions[i], MF_BYCOMMAND);
        }
    }
    for (DWORD i = 0; i < HOOK_DEF_COUNT; i++) {
        wsprintfA(key, "Cond%u", i);
        GetPrivateProfileStringA("JailConditions", key, "",
            g_conditions[i], JAIL_COND_MAX_LEN, ini_path);
    }
}
