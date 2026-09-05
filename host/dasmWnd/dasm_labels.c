#include "dasm_labels.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    UINT64 addr;
    char   label  [64];
    char   comment[128];
} Annotation;

static Annotation *g_annots   = NULL;
static int         g_annotCnt = 0;
static int         g_annotCap = 0;

static int ann_cmp(const void *a, const void *b) {
    const Annotation *aa = (const Annotation *)a;
    const Annotation *ab = (const Annotation *)b;
    if (aa->addr < ab->addr) return -1;
    if (aa->addr > ab->addr) return  1;
    return 0;
}

static Annotation *find_or_create(UINT64 addr) {
    /* Binary search */
    int lo = 0, hi = g_annotCnt - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if      (g_annots[mid].addr < addr) lo = mid + 1;
        else if (g_annots[mid].addr > addr) hi = mid - 1;
        else return &g_annots[mid];
    }
    /* Insert at position lo */
    if (g_annotCnt >= g_annotCap) {
        int newCap = g_annotCap ? g_annotCap * 2 : 32;
        Annotation *p = (Annotation *)realloc(g_annots, newCap * sizeof(Annotation));
        if (!p) return NULL;
        g_annots   = p;
        g_annotCap = newCap;
    }
    memmove(&g_annots[lo + 1], &g_annots[lo],
            (g_annotCnt - lo) * sizeof(Annotation));
    memset(&g_annots[lo], 0, sizeof(Annotation));
    g_annots[lo].addr = addr;
    g_annotCnt++;
    return &g_annots[lo];
}

static const Annotation *find_ro(UINT64 addr) {
    int lo = 0, hi = g_annotCnt - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if      (g_annots[mid].addr < addr) lo = mid + 1;
        else if (g_annots[mid].addr > addr) hi = mid - 1;
        else return &g_annots[mid];
    }
    return NULL;
}

void DasmLabelSet(UINT64 addr, const char *label) {
    Annotation *a = find_or_create(addr);
    if (!a) return;
    if (label) { strncpy(a->label, label, 63); a->label[63] = '\0'; }
    else a->label[0] = '\0';
}

void DasmCommentSet(UINT64 addr, const char *comment) {
    Annotation *a = find_or_create(addr);
    if (!a) return;
    if (comment) { strncpy(a->comment, comment, 127); a->comment[127] = '\0'; }
    else a->comment[0] = '\0';
}

const char *DasmLabelGet(UINT64 addr) {
    const Annotation *a = find_ro(addr);
    if (!a || a->label[0] == '\0') return NULL;
    return a->label;
}

const char *DasmCommentGet(UINT64 addr) {
    const Annotation *a = find_ro(addr);
    if (!a || a->comment[0] == '\0') return NULL;
    return a->comment;
}

void DasmLabelsFree(void) {
    free(g_annots);
    g_annots   = NULL;
    g_annotCnt = 0;
    g_annotCap = 0;
}

void DasmLabelsSave(const char *path) {
    if (!path || g_annotCnt == 0) return;
    FILE *f = fopen(path, "w");
    if (!f) return;

    fprintf(f, "[labels]\n");
    for (int i = 0; i < g_annotCnt; i++)
        if (g_annots[i].label[0])
            fprintf(f, "0x%016llX=%s\n", (unsigned long long)g_annots[i].addr, g_annots[i].label);

    fprintf(f, "[comments]\n");
    for (int i = 0; i < g_annotCnt; i++)
        if (g_annots[i].comment[0])
            fprintf(f, "0x%016llX=%s\n", (unsigned long long)g_annots[i].addr, g_annots[i].comment);

    fclose(f);
}

void DasmLabelsLoad(const char *path) {
    if (!path) return;
    FILE *f = fopen(path, "r");
    if (!f) return;

    DasmLabelsFree();

    typedef enum { SEC_NONE, SEC_LABELS, SEC_COMMENTS } Section;
    Section sec = SEC_NONE;
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline */
        int len = (int)strlen(line);
        while (len > 0 && (line[len-1] == '\r' || line[len-1] == '\n'))
            line[--len] = '\0';

        if (line[0] == '[') {
            if (strncmp(line, "[labels]",   8) == 0)   sec = SEC_LABELS;
            else if (strncmp(line, "[comments]", 10) == 0) sec = SEC_COMMENTS;
            else sec = SEC_NONE;
            continue;
        }

        if (sec == SEC_NONE) continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *addrStr = line;
        const char *val     = eq + 1;

        UINT64 addr = 0;
        if (addrStr[0] == '0' && (addrStr[1] == 'x' || addrStr[1] == 'X'))
            sscanf(addrStr + 2, "%llX", &addr);
        else
            sscanf(addrStr, "%llX", &addr);

        if (addr == 0 || val[0] == '\0') continue;

        if      (sec == SEC_LABELS)   DasmLabelSet  (addr, val);
        else if (sec == SEC_COMMENTS) DasmCommentSet(addr, val);
    }

    fclose(f);
}
