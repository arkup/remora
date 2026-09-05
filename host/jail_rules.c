#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <string.h>
#include "resource.h"
#include "jail_rules.h"
#include "jail.h"
#include "hook_defs.h"

static JailRule g_rules[JAIL_RULE_MAX];
static DWORD g_rule_count = 0;

static const char *g_str_match_names[] = { "(none)", "Glob", "Exact", "Contains" };
static const char *g_num_match_names[] = { "(none)", "==", "!=", ">", "<", ">=", "<=", "& any", "& all" };
static const char *g_action_names[] = { "Allow", "Log", "Ask", "Block" };

/* ------------------------------------------------------------------ */
/* INI persistence                                                      */
/* ------------------------------------------------------------------ */

void JailRulesLoad(const char *ini_path) {
    char section[32], buf[JAIL_RULE_PATTERN_LEN];
    g_rule_count = (DWORD)GetPrivateProfileIntA("RuleCount", "Count", 0, ini_path);
    if (g_rule_count > JAIL_RULE_MAX) g_rule_count = JAIL_RULE_MAX;
    for (DWORD i = 0; i < g_rule_count; i++) {
        wsprintfA(section, "Rule%u", i);
        g_rules[i].hook_id = (DWORD)GetPrivateProfileIntA(section, "HookId", 0, ini_path);
        g_rules[i].enabled = (DWORD)GetPrivateProfileIntA(section, "Enabled", 1, ini_path);
        g_rules[i].action = (DWORD)GetPrivateProfileIntA(section, "Action", 0, ini_path);
        g_rules[i].str_match = (DWORD)GetPrivateProfileIntA(section, "StrMatch", 0, ini_path);
        GetPrivateProfileStringA(section, "StrPattern", "", g_rules[i].str_pattern,
            JAIL_RULE_PATTERN_LEN, ini_path);
        g_rules[i].num_match = (DWORD)GetPrivateProfileIntA(section, "NumMatch", 0, ini_path);
        GetPrivateProfileStringA(section, "NumPattern", "0", buf, sizeof(buf), ini_path);
        g_rules[i].num_pattern = _strtoui64(buf, NULL, 10);
    }
}

void JailRulesSave(const char *ini_path) {
    char section[32], buf[64];
    WritePrivateProfileSectionA("RuleCount", NULL, ini_path);
    for (DWORD i = 0; i < JAIL_RULE_MAX; i++) {
        wsprintfA(section, "Rule%u", i);
        WritePrivateProfileSectionA(section, NULL, ini_path);
    }
    for (DWORD i = 0; i < g_rule_count; i++) {
        wsprintfA(section, "Rule%u", i);
        wsprintfA(buf, "%u", g_rules[i].hook_id);
        WritePrivateProfileStringA(section, "HookId", buf, ini_path);
        wsprintfA(buf, "%u", g_rules[i].enabled);
        WritePrivateProfileStringA(section, "Enabled", buf, ini_path);
        wsprintfA(buf, "%u", g_rules[i].action);
        WritePrivateProfileStringA(section, "Action", buf, ini_path);
        wsprintfA(buf, "%u", g_rules[i].str_match);
        WritePrivateProfileStringA(section, "StrMatch", buf, ini_path);
        WritePrivateProfileStringA(section, "StrPattern", g_rules[i].str_pattern, ini_path);
        wsprintfA(buf, "%u", g_rules[i].num_match);
        WritePrivateProfileStringA(section, "NumMatch", buf, ini_path);
        sprintf(buf, "%llu", (unsigned long long)g_rules[i].num_pattern);
        WritePrivateProfileStringA(section, "NumPattern", buf, ini_path);
    }
    wsprintfA(buf, "%u", g_rule_count);
    WritePrivateProfileStringA("RuleCount", "Count", buf, ini_path);
}

/* ------------------------------------------------------------------ */
/* Shared memory sync                                                   */
/* ------------------------------------------------------------------ */

void JailRulesSyncToShared(JailSharedMem *shm) {
    if (!shm) return;

    JailRulesShared *rs = &shm->rules;

    BYTE hook_first[HOOK_COUNT];
    memset(hook_first, 0xFF, sizeof(hook_first));
    for (DWORD i = 0; i < g_rule_count; i++) {
        DWORD hid = g_rules[i].hook_id;
        if (hid < HOOK_COUNT && hook_first[hid] == 0xFF)
            hook_first[hid] = (BYTE)i;
        int partner = JailGetAWPartner((int)hid);
        if (partner >= 0 && partner < HOOK_COUNT && hook_first[partner] == 0xFF)
            hook_first[partner] = (BYTE)i;
    }

    memcpy((void *)rs->rules, g_rules, g_rule_count * sizeof(JailRule));
    if (g_rule_count < JAIL_RULE_MAX)
        memset((void *)&rs->rules[g_rule_count], 0,
            (JAIL_RULE_MAX - g_rule_count) * sizeof(JailRule));
    memcpy((void *)rs->hook_first, hook_first, sizeof(hook_first));
    InterlockedExchange((volatile LONG *)&rs->rule_count, (LONG)g_rule_count);
    InterlockedIncrement((volatile LONG *)&rs->generation);
}

/* ------------------------------------------------------------------ */
/* Hook name helper (merged A/W display)                                */
/* ------------------------------------------------------------------ */

static const char *get_hook_display_name(int idx) {
    static char buf[128];
    const char *name = g_hook_defs[idx].api_name;
    int partner = JailGetAWPartner(idx);
    if (partner >= 0 && partner < idx) return NULL;
    lstrcpynA(buf, name, sizeof(buf));
    if (partner >= 0) {
        int len = lstrlenA(buf);
        if (len > 0 && buf[len - 1] == 'A')
            buf[len - 1] = 0;
    }
    return buf;
}

/* ------------------------------------------------------------------ */
/* Rule edit dialog                                                      */
/* ------------------------------------------------------------------ */

static INT_PTR CALLBACK RuleEditDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    static JailRule *s_rule;
    switch (msg) {
    case WM_INITDIALOG: {
        s_rule = (JailRule *)lp;
        HWND hHook = GetDlgItem(hDlg, IDC_RE_HOOK);
        int sel_idx = 0, combo_idx = 0;
        for (DWORD i = 0; i < HOOK_DEF_COUNT; i++) {
            int partner = JailGetAWPartner((int)i);
            if (partner >= 0 && partner < (int)i) continue;
            const char *dname = get_hook_display_name((int)i);
            if (!dname) continue;
            int ci = (int)SendMessageA(hHook, CB_ADDSTRING, 0, (LPARAM)dname);
            SendMessageA(hHook, CB_SETITEMDATA, ci, (LPARAM)i);
            if (i == s_rule->hook_id) sel_idx = combo_idx;
            combo_idx++;
        }
        SendMessageA(hHook, CB_SETCURSEL, sel_idx, 0);

        HWND hStr = GetDlgItem(hDlg, IDC_RE_STR_TYPE);
        for (int i = 0; i < 4; i++)
            SendMessageA(hStr, CB_ADDSTRING, 0, (LPARAM)g_str_match_names[i]);
        SendMessageA(hStr, CB_SETCURSEL, s_rule->str_match, 0);

        SetDlgItemTextA(hDlg, IDC_RE_STR_PAT, s_rule->str_pattern);

        HWND hNum = GetDlgItem(hDlg, IDC_RE_NUM_TYPE);
        for (int i = 0; i < 9; i++)
            SendMessageA(hNum, CB_ADDSTRING, 0, (LPARAM)g_num_match_names[i]);
        SendMessageA(hNum, CB_SETCURSEL, s_rule->num_match, 0);

        char num_buf[32];
        if (s_rule->num_pattern > 0xFFFFFFFF)
            sprintf(num_buf, "0x%llX", (unsigned long long)s_rule->num_pattern);
        else if (s_rule->num_pattern > 255)
            wsprintfA(num_buf, "0x%X", (DWORD)s_rule->num_pattern);
        else
            wsprintfA(num_buf, "%u", (DWORD)s_rule->num_pattern);
        SetDlgItemTextA(hDlg, IDC_RE_NUM_VAL, num_buf);

        HWND hAct = GetDlgItem(hDlg, IDC_RE_ACTION);
        for (int i = 0; i < 4; i++)
            SendMessageA(hAct, CB_ADDSTRING, 0, (LPARAM)g_action_names[i]);
        SendMessageA(hAct, CB_SETCURSEL, s_rule->action, 0);

        CheckDlgButton(hDlg, IDC_RE_ENABLED, s_rule->enabled ? BST_CHECKED : BST_UNCHECKED);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDOK: {
            HWND hHook = GetDlgItem(hDlg, IDC_RE_HOOK);
            int ci = (int)SendMessageA(hHook, CB_GETCURSEL, 0, 0);
            s_rule->hook_id = (DWORD)SendMessageA(hHook, CB_GETITEMDATA, ci, 0);
            s_rule->str_match = (DWORD)SendMessageA(GetDlgItem(hDlg, IDC_RE_STR_TYPE), CB_GETCURSEL, 0, 0);
            GetDlgItemTextA(hDlg, IDC_RE_STR_PAT, s_rule->str_pattern, JAIL_RULE_PATTERN_LEN);
            s_rule->num_match = (DWORD)SendMessageA(GetDlgItem(hDlg, IDC_RE_NUM_TYPE), CB_GETCURSEL, 0, 0);

            char num_buf[64];
            GetDlgItemTextA(hDlg, IDC_RE_NUM_VAL, num_buf, sizeof(num_buf));
            if (num_buf[0] == '0' && (num_buf[1] == 'x' || num_buf[1] == 'X'))
                s_rule->num_pattern = _strtoui64(num_buf + 2, NULL, 16);
            else
                s_rule->num_pattern = _strtoui64(num_buf, NULL, 10);

            s_rule->action = (DWORD)SendMessageA(GetDlgItem(hDlg, IDC_RE_ACTION), CB_GETCURSEL, 0, 0);
            s_rule->enabled = (IsDlgButtonChecked(hDlg, IDC_RE_ENABLED) == BST_CHECKED) ? 1 : 0;
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Rules list dialog                                                    */
/* ------------------------------------------------------------------ */

static void RefreshRulesList(HWND hList) {
    ListView_DeleteAllItems(hList);
    for (DWORD i = 0; i < g_rule_count; i++) {
        LVITEMA lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;

        lvi.iSubItem = 0;
        lvi.pszText = (LPSTR)(g_rules[i].enabled ? "Yes" : "No");
        SendMessageA(hList, LVM_INSERTITEMA, 0, (LPARAM)&lvi);

        const char *hname = "???";
        if (g_rules[i].hook_id < HOOK_DEF_COUNT)
            hname = g_hook_defs[g_rules[i].hook_id].api_name;
        lvi.iSubItem = 1;
        lvi.pszText = (LPSTR)hname;
        SendMessageA(hList, LVM_SETITEMA, 0, (LPARAM)&lvi);

        char str_desc[300] = "";
        if (g_rules[i].str_match > 0 && g_rules[i].str_match < 4) {
            wsprintfA(str_desc, "%s: %s",
                g_str_match_names[g_rules[i].str_match], g_rules[i].str_pattern);
        }
        lvi.iSubItem = 2;
        lvi.pszText = str_desc;
        SendMessageA(hList, LVM_SETITEMA, 0, (LPARAM)&lvi);

        char num_desc[128] = "";
        if (g_rules[i].num_match > 0 && g_rules[i].num_match < 9) {
            if (g_rules[i].num_pattern > 0xFFFFFFFF)
                sprintf(num_desc, "%s 0x%llX",
                    g_num_match_names[g_rules[i].num_match],
                    (unsigned long long)g_rules[i].num_pattern);
            else
                wsprintfA(num_desc, "%s 0x%X",
                    g_num_match_names[g_rules[i].num_match],
                    (DWORD)g_rules[i].num_pattern);
        }
        lvi.iSubItem = 3;
        lvi.pszText = num_desc;
        SendMessageA(hList, LVM_SETITEMA, 0, (LPARAM)&lvi);

        lvi.iSubItem = 4;
        lvi.pszText = (LPSTR)(g_rules[i].action < 4 ? g_action_names[g_rules[i].action] : "?");
        SendMessageA(hList, LVM_SETITEMA, 0, (LPARAM)&lvi);
    }
}

static HWND g_rules_parent;

static INT_PTR CALLBACK RulesListDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hList;
    switch (msg) {
    case WM_INITDIALOG: {
        hList = GetDlgItem(hDlg, IDC_RULES_LIST);
        ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        LVCOLUMNA col = {0};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = "On"; col.cx = 30;
        SendMessageA(hList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
        col.pszText = "Hook"; col.cx = 120;
        SendMessageA(hList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
        col.pszText = "String Condition"; col.cx = 140;
        SendMessageA(hList, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
        col.pszText = "Numeric Condition"; col.cx = 100;
        SendMessageA(hList, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);
        col.pszText = "Action"; col.cx = 50;
        SendMessageA(hList, LVM_INSERTCOLUMNA, 4, (LPARAM)&col);

        RefreshRulesList(hList);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_RULES_ADD: {
            if (g_rule_count >= JAIL_RULE_MAX) {
                MessageBoxA(hDlg, "Maximum 64 rules reached.", "Limit", MB_OK);
                break;
            }
            JailRule newrule = {0};
            newrule.enabled = 1;
            newrule.action = JAIL_LOG;
            if (DialogBoxParamA(GetModuleHandle(NULL), MAKEINTRESOURCEA(IDD_RULE_EDIT),
                    hDlg, RuleEditDlgProc, (LPARAM)&newrule) == IDOK) {
                g_rules[g_rule_count++] = newrule;
                RefreshRulesList(hList);
            }
            break;
        }
        case IDC_RULES_EDIT: {
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= (int)g_rule_count) break;
            JailRule copy = g_rules[sel];
            if (DialogBoxParamA(GetModuleHandle(NULL), MAKEINTRESOURCEA(IDD_RULE_EDIT),
                    hDlg, RuleEditDlgProc, (LPARAM)&copy) == IDOK) {
                g_rules[sel] = copy;
                RefreshRulesList(hList);
            }
            break;
        }
        case IDC_RULES_DEL: {
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= (int)g_rule_count) break;
            for (DWORD i = (DWORD)sel; i < g_rule_count - 1; i++)
                g_rules[i] = g_rules[i + 1];
            g_rule_count--;
            RefreshRulesList(hList);
            break;
        }
        case IDC_RULES_UP: {
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel <= 0 || sel >= (int)g_rule_count) break;
            JailRule tmp = g_rules[sel - 1];
            g_rules[sel - 1] = g_rules[sel];
            g_rules[sel] = tmp;
            RefreshRulesList(hList);
            ListView_SetItemState(hList, sel - 1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            break;
        }
        case IDC_RULES_DOWN: {
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= (int)g_rule_count - 1) break;
            JailRule tmp = g_rules[sel + 1];
            g_rules[sel + 1] = g_rules[sel];
            g_rules[sel] = tmp;
            RefreshRulesList(hList);
            ListView_SetItemState(hList, sel + 1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            break;
        }
        case IDOK:
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        break;
    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR *)lp;
        if (nm->idFrom == IDC_RULES_LIST && nm->code == NM_DBLCLK) {
            SendMessageA(hDlg, WM_COMMAND, IDC_RULES_EDIT, 0);
            return TRUE;
        }
        break;
    }
    case WM_CLOSE:
        EndDialog(hDlg, IDOK);
        return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void JailRulesInit(void) {
    char ini_path[MAX_PATH];
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *(slash + 1) = 0;
    wsprintfA(ini_path, "%sremora_rules.ini", exe_path);
    JailRulesLoad(ini_path);
}

void JailRulesDialog(HWND hParent) {
    g_rules_parent = hParent;
    DialogBoxParamA(GetModuleHandle(NULL), MAKEINTRESOURCEA(IDD_JAIL_RULES),
        hParent, RulesListDlgProc, 0);

    char ini_path[MAX_PATH];
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char *slash = strrchr(exe_path, '\\');
    if (slash) *(slash + 1) = 0;
    wsprintfA(ini_path, "%sremora_rules.ini", exe_path);
    JailRulesSave(ini_path);
}
