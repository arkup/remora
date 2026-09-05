#ifndef DASM_RENDER_H
#define DASM_RENDER_H

#include <windows.h>
#include "dasm_decode.h"

#define DASM_MAX_TOKENS 64

typedef struct {
    int      col;   /* char offset into di->text */
    int      len;   /* number of chars */
    COLORREF color;
} DasmToken;

/* Shared color constants */
#define DASM_COL_ADDR     RGB(100, 180, 100)
#define DASM_COL_BYTES    RGB(100, 100, 100)
#define DASM_COL_MNEMONIC RGB(220, 220, 220)
#define DASM_COL_JUMP     RGB(255, 180, 100)
#define DASM_COL_REG      RGB(180, 200, 255)
#define DASM_COL_IMM      RGB(180, 255, 180)
#define DASM_COL_KEYWORD  RGB(160, 160, 160)
#define DASM_COL_PUNCT    RGB(128, 128, 128)

/* Split di->text into colored token segments.
   Returns number of tokens written to out[]. */
int DasmColorLine(const DecodedInsn *di, DasmToken *out, int maxOut);

#endif
