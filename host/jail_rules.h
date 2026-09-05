#ifndef JAIL_RULES_H_HOST
#define JAIL_RULES_H_HOST

#include <windows.h>
#include "jail_rules.h"
#include "jail_shared.h"

void JailRulesInit(void);
void JailRulesDialog(HWND hParent);
void JailRulesSyncToShared(JailSharedMem *shm);
void JailRulesLoad(const char *ini_path);
void JailRulesSave(const char *ini_path);

#endif
