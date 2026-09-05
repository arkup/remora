#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "summary.h"
#include "hook_defs.h"
#include "jail_defs.h"

void SummaryInit(SummaryAccumulator *acc) {
    memset(acc, 0, sizeof(*acc));
    acc->start_tick = GetTickCount64();
}

static int find_file(SummaryAccumulator *acc, const char *path) {
    for (int i = 0; i < acc->file_count; i++)
        if (_stricmp(acc->files[i].path, path) == 0) return i;
    return -1;
}

static int add_file(SummaryAccumulator *acc, const char *path) {
    int idx = find_file(acc, path);
    if (idx >= 0) return idx;
    if (acc->file_count >= SUMMARY_MAX_FILES) { acc->file_overflow++; return -1; }
    idx = acc->file_count++;
    lstrcpynA(acc->files[idx].path, path, sizeof(acc->files[idx].path));
    return idx;
}

static int find_reg(SummaryAccumulator *acc, const char *key) {
    for (int i = 0; i < acc->reg_count; i++)
        if (_stricmp(acc->regs[i].key, key) == 0) return i;
    return -1;
}

static int add_reg(SummaryAccumulator *acc, const char *key) {
    int idx = find_reg(acc, key);
    if (idx >= 0) return idx;
    if (acc->reg_count >= SUMMARY_MAX_REG) { acc->reg_overflow++; return -1; }
    idx = acc->reg_count++;
    lstrcpynA(acc->regs[idx].key, key, sizeof(acc->regs[idx].key));
    return idx;
}

static int find_net(SummaryAccumulator *acc, const char *addr) {
    for (int i = 0; i < acc->net_count; i++)
        if (strcmp(acc->nets[i].addr, addr) == 0) return i;
    return -1;
}

static int add_net(SummaryAccumulator *acc, const char *addr) {
    int idx = find_net(acc, addr);
    if (idx >= 0) return idx;
    if (acc->net_count >= SUMMARY_MAX_NET) { acc->net_overflow++; return -1; }
    idx = acc->net_count++;
    lstrcpynA(acc->nets[idx].addr, addr, sizeof(acc->nets[idx].addr));
    return idx;
}

static int add_http(SummaryAccumulator *acc, const char *desc) {
    for (int i = 0; i < acc->http_count; i++) {
        if (strcmp(acc->https[i].desc, desc) == 0) {
            acc->https[i].count++;
            return i;
        }
    }
    if (acc->http_count >= SUMMARY_MAX_HTTP) { acc->http_overflow++; return -1; }
    int idx = acc->http_count++;
    lstrcpynA(acc->https[idx].desc, desc, sizeof(acc->https[idx].desc));
    acc->https[idx].count = 1;
    return idx;
}

static BOOL extract_quoted(const char *text, const char *prefix, char *out, int out_size) {
    const char *p = strstr(text, prefix);
    if (!p) return FALSE;
    p += strlen(prefix);
    if (*p != '"') return FALSE;
    p++;
    const char *end = strchr(p, '"');
    if (!end) return FALSE;
    int len = (int)(end - p);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, p, len);
    out[len] = 0;
    return TRUE;
}

static BOOL is_blocked(const char *text) {
    return strstr(text, "BLOCKED") != NULL;
}

static DWORD parse_bytes(const char *text, const char *keyword) {
    const char *p = strstr(text, keyword);
    if (!p) return 0;
    p += strlen(keyword);
    while (*p == ' ') p++;
    return (DWORD)strtoul(p, NULL, 10);
}

static void acc_createfile(SummaryAccumulator *acc, const char *text) {
    char path[260];
    if (!extract_quoted(text, "(", path, sizeof(path))) return;
    int idx = add_file(acc, path);
    if (idx < 0) return;
    acc->files[idx].create_count++;
    if (is_blocked(text)) acc->files[idx].was_blocked = TRUE;
}

static void acc_writefile(SummaryAccumulator *acc, const char *text) {
    char name[260];
    if (extract_quoted(text, "(", name, sizeof(name))) {
        int idx = add_file(acc, name);
        if (idx >= 0) {
            acc->files[idx].write_count++;
            acc->files[idx].write_bytes += parse_bytes(text, "\",");
            if (!acc->files[idx].write_bytes)
                acc->files[idx].write_bytes += parse_bytes(text, ", ");
            if (is_blocked(text)) acc->files[idx].was_blocked = TRUE;
        }
    } else {
        DWORD bytes = parse_bytes(text, "WriteFile(");
        if (bytes == 0) bytes = parse_bytes(text, ",");
        (void)bytes;
    }
}

static void acc_readfile(SummaryAccumulator *acc, const char *text) {
    char name[260];
    if (extract_quoted(text, "(", name, sizeof(name))) {
        int idx = add_file(acc, name);
        if (idx >= 0) acc->files[idx].read_count++;
    }
}

static void acc_deletefile(SummaryAccumulator *acc, const char *text) {
    char path[260];
    if (extract_quoted(text, "(", path, sizeof(path))) {
        int idx = add_file(acc, path);
        if (idx >= 0) {
            acc->files[idx].delete_count++;
            if (is_blocked(text)) acc->files[idx].was_blocked = TRUE;
        }
    }
}

static void acc_regopen(SummaryAccumulator *acc, const char *text) {
    const char *p = strchr(text, '(');
    if (!p) return;
    p++;
    const char *end = strchr(p, ',');
    if (!end) end = strchr(p, ')');
    if (!end) return;
    char key[512];
    int len = (int)(end - p);
    if (len >= (int)sizeof(key)) len = sizeof(key) - 1;
    memcpy(key, p, len);
    key[len] = 0;
    int idx = add_reg(acc, key);
    if (idx >= 0) acc->regs[idx].open_count++;
}

static void acc_regset(SummaryAccumulator *acc, const char *text) {
    char name[512];
    if (extract_quoted(text, "(", name, sizeof(name))) {
        int idx = add_reg(acc, name);
        if (idx >= 0) {
            acc->regs[idx].set_count++;
            if (is_blocked(text)) acc->regs[idx].was_blocked = TRUE;
        }
    }
}

static void acc_regcreate(SummaryAccumulator *acc, const char *text) {
    const char *p = strchr(text, '(');
    if (!p) return;
    p++;
    const char *end = strchr(p, ',');
    if (!end) end = strchr(p, ')');
    if (!end) return;
    char key[512];
    int len = (int)(end - p);
    if (len >= (int)sizeof(key)) len = sizeof(key) - 1;
    memcpy(key, p, len);
    key[len] = 0;
    int idx = add_reg(acc, key);
    if (idx >= 0) acc->regs[idx].create_count++;
}

static void acc_regdelete(SummaryAccumulator *acc, const char *text) {
    const char *p = strchr(text, '(');
    if (!p) return;
    p++;
    const char *end = strchr(p, ')');
    if (!end) return;
    char key[512];
    int len = (int)(end - p);
    if (len >= (int)sizeof(key)) len = sizeof(key) - 1;
    memcpy(key, p, len);
    key[len] = 0;
    int idx = add_reg(acc, key);
    if (idx >= 0) {
        acc->regs[idx].delete_count++;
        if (is_blocked(text)) acc->regs[idx].was_blocked = TRUE;
    }
}

static void acc_connect(SummaryAccumulator *acc, const char *text) {
    const char *p = strstr(text, "connect(");
    if (!p) p = strstr(text, "WSAConnect(");
    if (!p) return;
    const char *comma = strstr(p, ", ");
    if (!comma) return;
    comma += 2;
    const char *end = strchr(comma, ')');
    if (!end) return;
    char addr[128];
    int len = (int)(end - comma);
    if (len >= (int)sizeof(addr)) len = sizeof(addr) - 1;
    memcpy(addr, comma, len);
    addr[len] = 0;
    int idx = add_net(acc, addr);
    if (idx >= 0) acc->nets[idx].connect_count++;
}

static void acc_send(SummaryAccumulator *acc, const char *text, BOOL is_sendto) {
    DWORD bytes = 0;
    const char *arrow = strstr(text, ") -> ");
    if (arrow) {
        int ret_val = atoi(arrow + 5);
        if (ret_val > 0) bytes = (DWORD)ret_val;
    }
    if (is_sendto) {
        const char *p = strstr(text, "len=");
        if (p) {
            p += 4;
            const char *comma = strchr(p, ',');
            if (comma) {
                comma += 2;
                const char *end = strchr(comma, ',');
                if (!end) end = strchr(comma, ')');
                if (end) {
                    char addr[128];
                    int len = (int)(end - comma);
                    if (len >= (int)sizeof(addr)) len = sizeof(addr) - 1;
                    memcpy(addr, comma, len);
                    addr[len] = 0;
                    int idx = add_net(acc, addr);
                    if (idx >= 0) {
                        acc->nets[idx].send_count++;
                        acc->nets[idx].send_bytes += bytes;
                    }
                    return;
                }
            }
        }
    }
    if (acc->net_count > 0) {
        acc->nets[acc->net_count - 1].send_count++;
        acc->nets[acc->net_count - 1].send_bytes += bytes;
    }
}

static void acc_recv(SummaryAccumulator *acc, const char *text) {
    DWORD bytes = 0;
    const char *arrow = strstr(text, ") -> ");
    if (arrow) {
        int ret_val = atoi(arrow + 5);
        if (ret_val > 0) bytes = (DWORD)ret_val;
    }
    if (acc->net_count > 0) {
        acc->nets[acc->net_count - 1].recv_count++;
        acc->nets[acc->net_count - 1].recv_bytes += bytes;
    }
}

static void acc_http_connect(SummaryAccumulator *acc, const char *text) {
    char server[256];
    if (extract_quoted(text, "(", server, sizeof(server))) {
        char desc[512];
        const char *port = strchr(text, ':');
        if (port) {
            port++;
            const char *end = strchr(port, ')');
            if (end) {
                char pstr[16];
                int plen = (int)(end - port);
                if (plen >= (int)sizeof(pstr)) plen = sizeof(pstr) - 1;
                memcpy(pstr, port, plen);
                pstr[plen] = 0;
                _snprintf(desc, sizeof(desc), "Connect: %s:%s", server, pstr);
            } else {
                _snprintf(desc, sizeof(desc), "Connect: %s", server);
            }
        } else {
            _snprintf(desc, sizeof(desc), "Connect: %s", server);
        }
        desc[sizeof(desc) - 1] = 0;
        add_http(acc, desc);
    }
}

static void acc_http_request(SummaryAccumulator *acc, const char *text) {
    char verb[16] = "", obj[512] = "";
    const char *p = strchr(text, '(');
    if (!p) return;
    p++;
    if (*p == '"') {
        p++;
        const char *end = strchr(p, '"');
        if (end) {
            int len = (int)(end - p);
            if (len >= (int)sizeof(verb)) len = sizeof(verb) - 1;
            memcpy(verb, p, len);
            verb[len] = 0;
            p = end + 1;
            while (*p == ',' || *p == ' ') p++;
            if (*p == '"') {
                p++;
                end = strchr(p, '"');
                if (end) {
                    len = (int)(end - p);
                    if (len >= (int)sizeof(obj)) len = sizeof(obj) - 1;
                    memcpy(obj, p, len);
                    obj[len] = 0;
                }
            }
        }
    }
    if (verb[0] && obj[0]) {
        char desc[512];
        _snprintf(desc, sizeof(desc), "%s %s", verb, obj);
        desc[sizeof(desc) - 1] = 0;
        add_http(acc, desc);
    }
}

static void acc_http_openurl(SummaryAccumulator *acc, const char *text) {
    char url[512];
    if (extract_quoted(text, "(", url, sizeof(url))) {
        char desc[512];
        _snprintf(desc, sizeof(desc), "GET %s", url);
        desc[sizeof(desc) - 1] = 0;
        add_http(acc, desc);
    }
}

static void acc_createprocess(SummaryAccumulator *acc, const char *text) {
    char desc[512];
    const char *p = strchr(text, '(');
    if (!p) return;
    p++;
    const char *end = strrchr(text, ')');
    if (!end || end <= p) return;
    int len = (int)(end - p);
    if (len >= (int)sizeof(desc)) len = sizeof(desc) - 1;
    memcpy(desc, p, len);
    desc[len] = 0;
    for (int i = 0; i < acc->proc_created_count; i++) {
        if (strcmp(acc->proc_created[i].desc, desc) == 0) {
            acc->proc_created[i].count++;
            return;
        }
    }
    if (acc->proc_created_count >= SUMMARY_MAX_PROC) return;
    lstrcpynA(acc->proc_created[acc->proc_created_count].desc, desc, sizeof(acc->proc_created[0].desc));
    acc->proc_created[acc->proc_created_count].count = 1;
    acc->proc_created_count++;
}

static void acc_openprocess(SummaryAccumulator *acc, const char *text) {
    const char *p = strchr(text, '(');
    if (!p) return;
    p++;
    const char *end = strstr(text, ") ->");
    if (!end) end = strchr(p, ')');
    if (!end) return;
    char desc[512];
    int len = (int)(end - p);
    if (len >= (int)sizeof(desc)) len = sizeof(desc) - 1;
    memcpy(desc, p, len);
    desc[len] = 0;
    for (int i = 0; i < acc->proc_opened_count; i++) {
        if (strcmp(acc->proc_opened[i].desc, desc) == 0) {
            acc->proc_opened[i].count++;
            return;
        }
    }
    if (acc->proc_opened_count >= SUMMARY_MAX_PROC) return;
    lstrcpynA(acc->proc_opened[acc->proc_opened_count].desc, desc, sizeof(acc->proc_opened[0].desc));
    acc->proc_opened[acc->proc_opened_count].count = 1;
    acc->proc_opened_count++;
}

static void acc_terminateprocess(SummaryAccumulator *acc, const char *text) {
    const char *p = strchr(text, '(');
    if (!p) return;
    p++;
    const char *end = strstr(text, ") ->");
    if (!end) end = strchr(p, ')');
    if (!end) return;
    char desc[512];
    int len = (int)(end - p);
    if (len >= (int)sizeof(desc)) len = sizeof(desc) - 1;
    memcpy(desc, p, len);
    desc[len] = 0;
    for (int i = 0; i < acc->proc_terminated_count; i++) {
        if (strcmp(acc->proc_terminated[i].desc, desc) == 0) {
            acc->proc_terminated[i].count++;
            return;
        }
    }
    if (acc->proc_terminated_count >= SUMMARY_MAX_PROC) return;
    lstrcpynA(acc->proc_terminated[acc->proc_terminated_count].desc, desc, sizeof(acc->proc_terminated[0].desc));
    acc->proc_terminated[acc->proc_terminated_count].count = 1;
    acc->proc_terminated_count++;
}

static void acc_valloc(SummaryAccumulator *acc, const IPC_MSG_HEADER *hdr) {
    acc->valloc_total++;
    if (hdr->arg_count >= 4) {
        DWORD prot = (DWORD)hdr->args[3];
        DWORD base = prot & 0xFF;
        if (base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
            base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY)
            acc->valloc_exec_count++;
    }
}

static void acc_vprot(SummaryAccumulator *acc, const IPC_MSG_HEADER *hdr) {
    acc->vprot_total++;
    if (hdr->arg_count >= 3) {
        DWORD prot = (DWORD)hdr->args[2];
        DWORD base = prot & 0xFF;
        if (base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE)
            acc->vprot_rw_to_rx++;
    }
}

static void acc_encrypt(SummaryAccumulator *acc, const char *text) {
    acc->encrypt_calls++;
    DWORD bytes = parse_bytes(text, "out ");
    if (bytes == 0) bytes = parse_bytes(text, "bytes");
    acc->encrypt_bytes += bytes;
}

static void acc_decrypt(SummaryAccumulator *acc, const char *text) {
    acc->decrypt_calls++;
    DWORD bytes = parse_bytes(text, "out ");
    if (bytes == 0) bytes = parse_bytes(text, "bytes");
    acc->decrypt_bytes += bytes;
}

static void add_suspicious(SummaryAccumulator *acc, const char *msg) {
    if (acc->suspicious_count >= SUMMARY_MAX_SUSPICIOUS) return;
    for (int i = 0; i < acc->suspicious_count; i++)
        if (strcmp(acc->suspicious[i], msg) == 0) return;
    lstrcpynA(acc->suspicious[acc->suspicious_count++], msg, 128);
}

void SummaryAccumulate(SummaryAccumulator *acc, const IPC_MSG_HEADER *hdr,
                       const char *extra, DWORD extra_len) {
    if (!acc || !hdr) return;
    if (hdr->msg_type != MSG_LOG_TEXT && hdr->msg_type != MSG_HOOK_CALL &&
        hdr->msg_type != MSG_HOOK_RETURN)
        return;

    acc->end_tick = GetTickCount64();
    acc->total_calls++;
    if (hdr->hook_id < HOOK_COUNT)
        acc->calls_per_hook[hdr->hook_id]++;

    const char *text = (extra && extra_len > 0) ? extra : "";
    BOOL blocked = is_blocked(text);
    if (blocked) {
        acc->blocked_count++;
        if (hdr->hook_id < HOOK_COUNT)
            acc->blocked_per_hook[hdr->hook_id]++;
    }

    switch (hdr->hook_id) {
    case HOOK_CreateFileA:
    case HOOK_CreateFileW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_createfile(acc, text);
        break;
    case HOOK_WriteFile:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_writefile(acc, text);
        break;
    case HOOK_ReadFile:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_readfile(acc, text);
        break;
    case HOOK_DeleteFileA:
    case HOOK_DeleteFileW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_deletefile(acc, text);
        break;

    case HOOK_RegOpenKeyExA:
    case HOOK_RegOpenKeyExW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_regopen(acc, text);
        break;
    case HOOK_RegSetValueExA:
    case HOOK_RegSetValueExW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_regset(acc, text);
        break;
    case HOOK_RegCreateKeyExA:
    case HOOK_RegCreateKeyExW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_regcreate(acc, text);
        break;
    case HOOK_RegDeleteKeyA:
    case HOOK_RegDeleteKeyW:
    case HOOK_RegDeleteValueA:
    case HOOK_RegDeleteValueW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_regdelete(acc, text);
        break;

    case HOOK_connect:
    case HOOK_WSAConnect:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_connect(acc, text);
        break;
    case HOOK_send:
    case HOOK_WSASend:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_send(acc, text, FALSE);
        break;
    case HOOK_sendto:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_send(acc, text, TRUE);
        break;
    case HOOK_recv:
    case HOOK_recvfrom:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_recv(acc, text);
        break;

    case HOOK_InternetConnectA:
    case HOOK_InternetConnectW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_http_connect(acc, text);
        break;
    case HOOK_HttpOpenRequestA:
    case HOOK_HttpOpenRequestW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_http_request(acc, text);
        break;
    case HOOK_InternetOpenUrlA:
    case HOOK_InternetOpenUrlW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_http_openurl(acc, text);
        break;

    case HOOK_CreateProcessA:
    case HOOK_CreateProcessW:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_createprocess(acc, text);
        break;
    case HOOK_OpenProcess:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_openprocess(acc, text);
        break;
    case HOOK_TerminateProcess:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_terminateprocess(acc, text);
        break;

    case HOOK_VirtualAlloc:
        if (hdr->msg_type == MSG_HOOK_CALL || hdr->msg_type == MSG_LOG_TEXT)
            acc_valloc(acc, hdr);
        break;
    case HOOK_VirtualProtect:
        if (hdr->msg_type == MSG_HOOK_CALL || hdr->msg_type == MSG_LOG_TEXT)
            acc_vprot(acc, hdr);
        break;

    case HOOK_BCryptEncrypt:
    case HOOK_CryptEncrypt:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_encrypt(acc, text);
        break;
    case HOOK_BCryptDecrypt:
    case HOOK_CryptDecrypt:
        if (hdr->msg_type == MSG_LOG_TEXT) acc_decrypt(acc, text);
        break;

    case HOOK_BCryptGenerateSymmetricKey:
    case HOOK_BCryptGenerateKeyPair:
    case HOOK_BCryptImportKey:
        if (hdr->msg_type == MSG_LOG_TEXT) acc->keys_generated++;
        break;
    }
}

void SummaryDetectSuspicious(SummaryAccumulator *acc) {
    if (acc->valloc_exec_count > 0)
        add_suspicious(acc, "Executable memory allocation (VirtualAlloc with X)");
    if (acc->vprot_rw_to_rx > 0)
        add_suspicious(acc, "Memory protection escalation (VirtualProtect to RX/RWX)");
    for (int i = 0; i < acc->reg_count; i++) {
        if (acc->regs[i].set_count > 0) {
            const char *k = acc->regs[i].key;
            if (strstr(k, "\\Run") || strstr(k, "\\RunOnce") || strstr(k, "\\Services"))
                add_suspicious(acc, "Registry persistence (Run/RunOnce/Services key)");
        }
    }
    if (acc->proc_opened_count > 0) {
        for (int i = 0; i < acc->proc_opened_count; i++) {
            if (strstr(acc->proc_opened[i].desc, "VM_WRITE") ||
                strstr(acc->proc_opened[i].desc, "ALL_ACCESS"))
                add_suspicious(acc, "Process injection indicators (OpenProcess with write access)");
        }
    }
    if (acc->proc_created_count > 0 && acc->file_count > 0) {
        for (int i = 0; i < acc->file_count; i++) {
            if (acc->files[i].write_count > 0) {
                const char *p = acc->files[i].path;
                if (strstr(p, "Temp") || strstr(p, "temp") || strstr(p, "AppData"))
                    add_suspicious(acc, "Dropped and executed payload (WriteFile to Temp + CreateProcess)");
            }
        }
    }
    if (acc->proc_terminated_count > 0)
        add_suspicious(acc, "Process termination (TerminateProcess called)");
    if (acc->encrypt_calls > 5 && acc->net_count > 0)
        add_suspicious(acc, "Encrypt-then-exfil pattern (high crypto + network activity)");
}

static void format_bytes(UINT64 bytes, char *out, int out_size) {
    if (bytes >= 1048576)
        _snprintf(out, out_size, "%.1f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024)
        _snprintf(out, out_size, "%.1f KB", (double)bytes / 1024.0);
    else
        _snprintf(out, out_size, "%I64u bytes", bytes);
    out[out_size - 1] = 0;
}

BOOL SummaryRenderText(SummaryAccumulator *acc, const char *target_name, DWORD target_pid, FILE *out) {
    if (!acc || !out) return FALSE;

    SummaryDetectSuspicious(acc);

    double dur = (double)(acc->end_tick - acc->start_tick) / 1000.0;
    if (dur < 0.1) dur = 0.1;

    fprintf(out, "=== RemoraHook Summary Report ===\n");
    fprintf(out, "Target:   %s\n", target_name ? target_name : "(unknown)");
    if (target_pid)
        fprintf(out, "PID:      %u\n", target_pid);
    fprintf(out, "Duration: %.1fs\n", dur);
    fprintf(out, "Total API calls: %u", acc->total_calls);
    if (acc->blocked_count > 0)
        fprintf(out, " (%u logged, %u blocked)", acc->total_calls - acc->blocked_count, acc->blocked_count);
    fprintf(out, "\n");

    if (acc->file_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_CreateFileA; i <= HOOK_CloseHandle; i++)
            cat_calls += acc->calls_per_hook[i];
        fprintf(out, "\n--- File Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->file_count; i++) {
            SummaryFileEntry *f = &acc->files[i];
            fprintf(out, "  %s\n", f->path);
            if (f->create_count) fprintf(out, "    opened %u time(s)\n", f->create_count);
            if (f->write_count) {
                char bs[32];
                format_bytes(f->write_bytes, bs, sizeof(bs));
                fprintf(out, "    written %u time(s), %s\n", f->write_count, bs);
            }
            if (f->read_count) fprintf(out, "    read %u time(s)\n", f->read_count);
            if (f->delete_count) fprintf(out, "    deleted %u time(s)\n", f->delete_count);
            if (f->was_blocked) fprintf(out, "    [BLOCKED]\n");
        }
        if (acc->file_overflow)
            fprintf(out, "  ... and %d more unique paths\n", acc->file_overflow);
    }

    if (acc->reg_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_RegOpenKeyExA; i <= HOOK_RegDeleteValueW; i++)
            cat_calls += acc->calls_per_hook[i];
        fprintf(out, "\n--- Registry Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->reg_count; i++) {
            SummaryRegEntry *r = &acc->regs[i];
            fprintf(out, "  %s\n", r->key);
            if (r->open_count) fprintf(out, "    opened %u\n", r->open_count);
            if (r->set_count) fprintf(out, "    set %u\n", r->set_count);
            if (r->create_count) fprintf(out, "    created %u\n", r->create_count);
            if (r->delete_count) fprintf(out, "    deleted %u\n", r->delete_count);
            if (r->was_blocked) fprintf(out, "    [BLOCKED]\n");
        }
        if (acc->reg_overflow)
            fprintf(out, "  ... and %d more unique keys\n", acc->reg_overflow);
    }

    if (acc->net_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_connect; i <= HOOK_closesocket; i++)
            cat_calls += acc->calls_per_hook[i];
        fprintf(out, "\n--- Network Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->net_count; i++) {
            SummaryNetEntry *n = &acc->nets[i];
            fprintf(out, "  %s", n->addr);
            if (n->connect_count) fprintf(out, " (connect x%u", n->connect_count);
            if (n->send_count) {
                char bs[32];
                format_bytes(n->send_bytes, bs, sizeof(bs));
                fprintf(out, ", send x%u %s", n->send_count, bs);
            }
            if (n->recv_count) {
                char bs[32];
                format_bytes(n->recv_bytes, bs, sizeof(bs));
                fprintf(out, ", recv x%u %s", n->recv_count, bs);
            }
            if (n->connect_count) fprintf(out, ")");
            fprintf(out, "\n");
        }
        if (acc->net_overflow)
            fprintf(out, "  ... and %d more connections\n", acc->net_overflow);
    }

    if (acc->http_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_InternetOpenA; i <= HOOK_InternetReadFile; i++)
            cat_calls += acc->calls_per_hook[i];
        fprintf(out, "\n--- HTTP Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->http_count; i++) {
            if (acc->https[i].count > 1)
                fprintf(out, "  %s (x%u)\n", acc->https[i].desc, acc->https[i].count);
            else
                fprintf(out, "  %s\n", acc->https[i].desc);
        }
        if (acc->http_overflow)
            fprintf(out, "  ... and %d more requests\n", acc->http_overflow);
    }

    if (acc->keys_generated || acc->encrypt_calls || acc->decrypt_calls) {
        int cat_calls = 0;
        for (int i = HOOK_CryptEncrypt; i <= HOOK_BCryptImportKey; i++)
            cat_calls += acc->calls_per_hook[i];
        fprintf(out, "\n--- Crypto Activity (%d calls) ---\n", cat_calls);
        if (acc->keys_generated)
            fprintf(out, "  Keys generated: %d\n", acc->keys_generated);
        if (acc->encrypt_calls) {
            char bs[32];
            format_bytes(acc->encrypt_bytes, bs, sizeof(bs));
            fprintf(out, "  Encrypt: %d calls, %s\n", acc->encrypt_calls, bs);
        }
        if (acc->decrypt_calls) {
            char bs[32];
            format_bytes(acc->decrypt_bytes, bs, sizeof(bs));
            fprintf(out, "  Decrypt: %d calls, %s\n", acc->decrypt_calls, bs);
        }
    }

    if (acc->proc_created_count > 0 || acc->proc_opened_count > 0 ||
        acc->proc_terminated_count > 0) {
        int cat_calls = 0;
        for (int i = HOOK_CreateProcessA; i <= HOOK_QueueUserAPC; i++)
            cat_calls += acc->calls_per_hook[i];
        fprintf(out, "\n--- Process Activity (%d calls) ---\n", cat_calls);
        for (int i = 0; i < acc->proc_created_count; i++) {
            if (acc->proc_created[i].count > 1)
                fprintf(out, "  Created: %s (x%u)\n", acc->proc_created[i].desc, acc->proc_created[i].count);
            else
                fprintf(out, "  Created: %s\n", acc->proc_created[i].desc);
        }
        for (int i = 0; i < acc->proc_opened_count; i++) {
            if (acc->proc_opened[i].count > 1)
                fprintf(out, "  Opened: %s (x%u)\n", acc->proc_opened[i].desc, acc->proc_opened[i].count);
            else
                fprintf(out, "  Opened: %s\n", acc->proc_opened[i].desc);
        }
        for (int i = 0; i < acc->proc_terminated_count; i++) {
            if (acc->proc_terminated[i].count > 1)
                fprintf(out, "  Terminated: %s (x%u)\n", acc->proc_terminated[i].desc, acc->proc_terminated[i].count);
            else
                fprintf(out, "  Terminated: %s\n", acc->proc_terminated[i].desc);
        }
    }

    if (acc->valloc_total > 0 || acc->vprot_total > 0) {
        int cat_calls = acc->calls_per_hook[HOOK_VirtualAlloc] +
                        acc->calls_per_hook[HOOK_VirtualProtect] +
                        acc->calls_per_hook[HOOK_ReadProcessMemory];
        fprintf(out, "\n--- Memory Activity (%d calls) ---\n", cat_calls);
        if (acc->valloc_total)
            fprintf(out, "  VirtualAlloc: %d total, %d with EXECUTE\n",
                acc->valloc_total, acc->valloc_exec_count);
        if (acc->vprot_total)
            fprintf(out, "  VirtualProtect: %d total, %d to RX/RWX\n",
                acc->vprot_total, acc->vprot_rw_to_rx);
    }

    if (acc->blocked_count > 0) {
        fprintf(out, "\n--- Blocked Actions (%u total) ---\n", acc->blocked_count);
        for (int i = 0; i < HOOK_COUNT; i++) {
            if (acc->blocked_per_hook[i] > 0)
                fprintf(out, "  %s x%u\n", g_hook_defs[i].api_name, acc->blocked_per_hook[i]);
        }
    }

    if (acc->suspicious_count > 0) {
        fprintf(out, "\n--- Suspicious Indicators ---\n");
        for (int i = 0; i < acc->suspicious_count; i++)
            fprintf(out, "  [!] %s\n", acc->suspicious[i]);
    }

    fprintf(out, "\n=== End Report ===\n");
    return TRUE;
}
