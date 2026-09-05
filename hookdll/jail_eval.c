#include <windows.h>
#include "jail_rules.h"
#include "jail_shared.h"

static BOOL glob_match(const char *str, const char *pat) {
    while (*pat) {
        if (*pat == '*') {
            pat++;
            if (!*pat) return TRUE;
            while (*str) {
                if (glob_match(str, pat)) return TRUE;
                str++;
            }
            return FALSE;
        } else if (*pat == '?') {
            if (!*str) return FALSE;
            str++; pat++;
        } else {
            char c1 = *str, c2 = *pat;
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
            if (c1 != c2) return FALSE;
            str++; pat++;
        }
    }
    return *str == 0;
}

static const char *stristr(const char *haystack, const char *needle) {
    if (!needle[0]) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n) {
            char c1 = *h, c2 = *n;
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
            if (c1 != c2) break;
            h++; n++;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

extern JailSharedMem *g_jail_shared;

JailAction RemoraEvalRules(DWORD hook_id, const char *str_field, UINT64 num_field) {
    if (!g_jail_shared) return (JailAction)-1;
    if (hook_id >= HOOK_COUNT) return (JailAction)-1;

    JailRulesShared *rs = &g_jail_shared->rules;

    BYTE first_idx = rs->hook_first[hook_id];
    if (first_idx != 0xFF) {
        DWORD count = rs->rule_count;
        if (count > JAIL_RULE_MAX) count = JAIL_RULE_MAX;

        for (DWORD i = 0; i < count; i++) {
            const JailRule *rule = &rs->rules[i];
            if (rule->hook_id != hook_id) continue;
            if (!rule->enabled) continue;

            BOOL str_ok = TRUE;
            if (rule->str_match != RULE_MATCH_NONE) {
                if (!str_field || !str_field[0]) {
                    str_ok = FALSE;
                } else {
                    switch ((RuleStrMatch)rule->str_match) {
                    case RULE_MATCH_GLOB:
                        str_ok = glob_match(str_field, rule->str_pattern);
                        break;
                    case RULE_MATCH_EXACT:
                        str_ok = (lstrcmpiA(str_field, rule->str_pattern) == 0);
                        break;
                    case RULE_MATCH_CONTAINS:
                        str_ok = (stristr(str_field, rule->str_pattern) != NULL);
                        break;
                    default:
                        str_ok = FALSE;
                        break;
                    }
                }
            }
            if (!str_ok) continue;

            BOOL num_ok = TRUE;
            if (rule->num_match != RULE_NUM_NONE) {
                UINT64 val = num_field;
                UINT64 pat = rule->num_pattern;
                switch ((RuleNumMatch)rule->num_match) {
                case RULE_NUM_EQ:       num_ok = (val == pat); break;
                case RULE_NUM_NE:       num_ok = (val != pat); break;
                case RULE_NUM_GT:       num_ok = (val > pat); break;
                case RULE_NUM_LT:       num_ok = (val < pat); break;
                case RULE_NUM_GE:       num_ok = (val >= pat); break;
                case RULE_NUM_LE:       num_ok = (val <= pat); break;
                case RULE_NUM_MASK_ANY: num_ok = ((val & pat) != 0); break;
                case RULE_NUM_MASK_ALL: num_ok = ((val & pat) == pat); break;
                default: num_ok = FALSE; break;
                }
            }
            if (!num_ok) continue;

            return (JailAction)rule->action;
        }
    }

    const char *cond = g_jail_shared->conditions[hook_id];
    if (cond[0] && str_field && str_field[0]) {
        if (!glob_match(str_field, cond))
            return JAIL_ALLOW;
    }

    return (JailAction)-1;
}
