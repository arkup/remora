#ifndef JAIL_RULES_H
#define JAIL_RULES_H

#include <windows.h>
#include "hook_defs.h"
#include "jail_defs.h"

#define JAIL_RULE_MAX         64
#define JAIL_RULE_PATTERN_LEN 256

typedef enum {
    RULE_MATCH_NONE = 0,
    RULE_MATCH_GLOB,
    RULE_MATCH_EXACT,
    RULE_MATCH_CONTAINS,
} RuleStrMatch;

typedef enum {
    RULE_NUM_NONE = 0,
    RULE_NUM_EQ,
    RULE_NUM_NE,
    RULE_NUM_GT,
    RULE_NUM_LT,
    RULE_NUM_GE,
    RULE_NUM_LE,
    RULE_NUM_MASK_ANY,
    RULE_NUM_MASK_ALL,
} RuleNumMatch;

#pragma pack(push, 1)
typedef struct {
    DWORD  hook_id;
    DWORD  enabled;
    DWORD  action;
    DWORD  str_match;
    DWORD  num_match;
    UINT64 num_pattern;
    char   str_pattern[JAIL_RULE_PATTERN_LEN];
} JailRule;
#pragma pack(pop)

typedef struct {
    volatile DWORD rule_count;
    volatile DWORD generation;
    JailRule       rules[JAIL_RULE_MAX];
    volatile BYTE  hook_first[HOOK_COUNT];
} JailRulesShared;

#endif
