#ifndef DASM_LABELS_H
#define DASM_LABELS_H

#include <windows.h>

/* Per-address annotation: label and/or comment. */

void        DasmLabelSet  (UINT64 addr, const char *label);
void        DasmCommentSet(UINT64 addr, const char *comment);
const char *DasmLabelGet  (UINT64 addr);
const char *DasmCommentGet(UINT64 addr);

void DasmLabelsFree(void);
void DasmLabelsSave(const char *path);
void DasmLabelsLoad(const char *path);

#endif
