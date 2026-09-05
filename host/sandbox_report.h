#ifndef SANDBOX_REPORT_H
#define SANDBOX_REPORT_H

#include <windows.h>
#include "summary.h"

void SandboxReportOpen(HWND hwndParent, SummaryAccumulator *acc,
                       const char *target_name, DWORD target_pid);
void SandboxReportRefresh(void);
void SandboxReportClose(void);

#endif
