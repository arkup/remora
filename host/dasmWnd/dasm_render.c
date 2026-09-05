#include "dasm_render.h"
#include <string.h>
#include <ctype.h>

static const char * const s_regs[] = {
    /* 64-bit GP */
    "rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp",
    "r8","r9","r10","r11","r12","r13","r14","r15","rip",
    /* 32-bit GP */
    "eax","ebx","ecx","edx","esi","edi","esp","ebp",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d","eip",
    /* 16-bit GP */
    "ax","bx","cx","dx","si","di","sp","bp",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
    /* 8-bit GP */
    "al","ah","bl","bh","cl","ch","dl","dh",
    "spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
    /* XMM */
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
    /* YMM */
    "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
    "ymm8","ymm9","ymm10","ymm11","ymm12","ymm13","ymm14","ymm15",
    /* MMX */
    "mm0","mm1","mm2","mm3","mm4","mm5","mm6","mm7",
    /* FPU stack */
    "st0","st1","st2","st3","st4","st5","st6","st7",
    /* Segment */
    "cs","ds","es","fs","gs","ss",
    NULL
};

static const char * const s_size_kw[] = {
    "byte","word","dword","qword","ptr",
    "xmmword","ymmword","zmmword","tword","oword",
    NULL
};

static COLORREF classify_token(const char *tok, int len) {
    /* Hex immediate: starts with 0x or 0X */
    if (len >= 3 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X'))
        return DASM_COL_IMM;

    /* Decimal immediate: all digits */
    {
        int allDig = 1;
        for (int i = 0; i < len; i++)
            if (!isdigit((unsigned char)tok[i])) { allDig = 0; break; }
        if (allDig && len > 0) return DASM_COL_IMM;
    }

    /* Lowercase copy for table lookup (max 31 chars -- no register or keyword is longer) */
    char lo[32] = {0};
    int n = len < 31 ? len : 31;
    for (int i = 0; i < n; i++) lo[i] = (char)tolower((unsigned char)tok[i]);

    for (int i = 0; s_size_kw[i]; i++)
        if (strcmp(lo, s_size_kw[i]) == 0) return DASM_COL_KEYWORD;

    for (int i = 0; s_regs[i]; i++)
        if (strcmp(lo, s_regs[i]) == 0) return DASM_COL_REG;

    return DASM_COL_MNEMONIC;
}

int DasmColorLine(const DecodedInsn *di, DasmToken *out, int maxOut) {
    const char *s = di->text;
    int col = 0, n = 0, first = 1;

    while (*s && n < maxOut) {
        if (isalnum((unsigned char)*s) || *s == '_') {
            const char *start = s;
            int startCol = col;
            while (isalnum((unsigned char)*s) || *s == '_') { s++; col++; }
            int len = (int)(s - start);
            COLORREF clr;
            if (first) {
                clr = di->is_branch ? DASM_COL_JUMP : DASM_COL_MNEMONIC;
                first = 0;
            } else {
                clr = classify_token(start, len);
            }
            out[n].col = startCol; out[n].len = len; out[n].color = clr;
            n++;
        } else {
            out[n].col = col; out[n].len = 1; out[n].color = DASM_COL_PUNCT;
            n++; s++; col++;
        }
    }
    return n;
}
