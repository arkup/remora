#ifndef JAIL_H
#define JAIL_H

#include <windows.h>
#include "jail_defs.h"
#include "jail_shared.h"

void JailInit(HMENU hJailMenu);
void JailSetAction(HookId id, JailAction action);
JailAction JailGetAction(HookId id);
int JailGetAWPartner(int hook_idx);
void JailHandleMenuCommand(WORD cmd_id);
BOOL JailHandleCondCommand(HWND hParent, WORD cmd_id);
const char *JailGetCondition(int hook_idx);
void JailSyncConditions(JailSharedMem *shm);
void JailSavePolicy(const char *ini_path);
void JailLoadPolicy(const char *ini_path);
void JailApplyBoringPreset(void);

#endif
