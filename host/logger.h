#ifndef LOGGER_H
#define LOGGER_H

#include <windows.h>

#define LOG_COLOR_INFO    RGB(255, 255, 255)
#define LOG_COLOR_API     RGB(0, 200, 255)
#define LOG_COLOR_RETURN  RGB(0, 255, 100)
#define LOG_COLOR_WARN    RGB(255, 255, 0)
#define LOG_COLOR_BLOCK   RGB(255, 80, 80)
#define LOG_COLOR_VERBOSE RGB(160, 160, 160)

void LoggerInit(HWND hRichEdit);
void LoggerShutdown(void);
void LoggerAppend(const char *text, COLORREF color);
void LoggerAppendFmt(COLORREF color, const char *fmt, ...);
void LoggerFlush(void);
void LoggerClear(void);
void LoggerSetFilter(const char *filter);
DWORD LoggerGetLineCount(void);
DWORD LoggerGetTotalLines(void);
BOOL LoggerSaveToFile(const char *path);
int LoggerFindNext(const char *needle, BOOL forward);
void LoggerHighlightAll(const char *needle);
void LoggerClearHighlight(void);
void LoggerSetAutoScroll(BOOL enable);
BOOL LoggerGetAutoScroll(void);
void LoggerScrollToBottom(void);

#endif
