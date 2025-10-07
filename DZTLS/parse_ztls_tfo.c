// parse_ztls_tfo_getdns.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <xlsxwriter.h>

#define MAX_FILES 2000
#define LINE_SIZE 2048

typedef struct {
    int    serial;
    double t_dns_start;   // "start A and AAAA DNS records query :"
    double t_dns_done;    // "complete A and AAAA DNS records query :"
    double t_send_app;    // "sending application data from client to server : ... :"
    double t_recv_app;    // "receiving application data from server : ... :"
    // derived
    double dns_time;           // dns_done - dns_start
    double pre_send_time;      // send_app - dns_done
    double app_gap;            // recv_app - send_app
    double total_from_dns_start; // recv_app - dns_start
} Row;

static double find_time(const char *line, const char *pattern)
{
    regex_t re;
    regmatch_t m[2];
    double val = -1.0;

    if (regcomp(&re, pattern, REG_EXTENDED) != 0) return -1.0;
    if (regexec(&re, line, 2, m, 0) == 0 && m[1].rm_so != -1) {
        char buf[64];
        int len = m[1].rm_eo - m[1].rm_so;
        if (len > (int)sizeof(buf)-1) len = sizeof(buf)-1;
        memcpy(buf, line + m[1].rm_so, len);
        buf[len] = '\0';
        val = atof(buf);
    }
    regfree(&re);
    return val;
}

// 여러 패턴을 순서대로 시도
static double find_time_any(const char *line, const char *const patterns[], int n)
{
    for (int i = 0; i < n; i++) {
        double v = find_time(line, patterns[i]);
        if (v > 0) return v;
    }
    return -1.0;
}

static int parse_one(const char *filename, Row *out, int serial)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    memset(out, 0, sizeof(*out));
    out->serial     = serial;
    out->t_dns_start = out->t_dns_done = out->t_send_app = out->t_recv_app = -1.0;

    // 정규식 패턴들 (공백/콜론 변형에 관대하게)
    const char *P_DNS_START = "^start[[:space:]]+A[[:space:]]+and[[:space:]]+AAAA[[:space:]]+DNS[[:space:]]+records[[:space:]]+query[[:space:]]*:[[:space:]]*([0-9]+\\.[0-9]+)";
    const char *P_DNS_DONE  = "^complete[[:space:]]+A[[:space:]]+and[[:space:]]+AAAA[[:space:]]+DNS[[:space:]]+records[[:space:]]+query[[:space:]]*:[[:space:]]*([0-9]+\\.[0-9]+)";

    // "sending application data from client to server : hello : 2022.311694"
    // 줄 끝쪽의 마지막 숫자를 잡도록, 앞의 payload(hello 등)는 .* 로 무시
    const char *P_SEND_1 = "^sending[[:space:]]+application[[:space:]]+data[[:space:]]+from[[:space:]]+client[[:space:]]+to[[:space:]]+server[[:space:]]*:[[:space:]]*.*:[[:space:]]*([0-9]+\\.[0-9]+)";
    const char *P_SEND_2 = "^sending[[:space:]]+application[[:space:]]+data[[:space:]]+from[[:space:]]+client[[:space:]]+to[[:space:]]+server[[:space:]]*:[[:space:]]*([0-9]+\\.[0-9]+)";

    // "receiving application data from server : mmlab : 2022.634971"
    const char *P_RECV_1 = "^receiving[[:space:]]+application[[:space:]]+data[[:space:]]+from[[:space:]]+server[[:space:]]*:[[:space:]]*.*:[[:space:]]*([0-9]+\\.[0-9]+)";
    const char *P_RECV_2 = "^receiving[[:space:]]+application[[:space:]]+data[[:space:]]+from[[:space:]]+server[[:space:]]*:[[:space:]]*([0-9]+\\.[0-9]+)";

    const char *SEND_PATTERNS[] = { P_SEND_1, P_SEND_2 };
    const char *RECV_PATTERNS[] = { P_RECV_1, P_RECV_2 };

    char line[LINE_SIZE];
    while (fgets(line, sizeof(line), fp)) {
        if (out->t_dns_start < 0) out->t_dns_start = find_time(line, P_DNS_START);
        if (out->t_dns_done  < 0) out->t_dns_done  = find_time(line, P_DNS_DONE);
        if (out->t_send_app  < 0) out->t_send_app  = find_time_any(line, SEND_PATTERNS, 2);
        if (out->t_recv_app  < 0) out->t_recv_app  = find_time_any(line, RECV_PATTERNS, 2);
    }
    fclose(fp);

    // 파생값 계산
    out->dns_time           = (out->t_dns_done  > 0 && out->t_dns_start > 0) ? (out->t_dns_done - out->t_dns_start) : -1;
    out->pre_send_time      = (out->t_send_app  > 0 && out->t_dns_done  > 0) ? (out->t_send_app - out->t_dns_done) : -1;
    out->app_gap            = (out->t_recv_app  > 0 && out->t_send_app  > 0) ? (out->t_recv_app - out->t_send_app) : -1;
    out->total_from_dns_start = (out->t_recv_app > 0 && out->t_dns_start > 0) ? (out->t_recv_app - out->t_dns_start) : -1;

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s output.xlsx file1.txt [file2.txt ...]\n", argv[0]);
        return 1;
    }

    const char *out_xlsx = argv[1];
    Row rows[MAX_FILES];
    int n = 0;

    for (int i = 2; i < argc && n < MAX_FILES; i++) {
        if (parse_one(argv[i], &rows[n], n+1) == 0) n++;
    }

    lxw_workbook  *wb = workbook_new(out_xlsx);
    lxw_worksheet *ws = workbook_add_worksheet(wb, NULL);

    int r = 0;
    // 헤더
    worksheet_write_string(ws, r, 0,  "serial",                NULL);
    worksheet_write_string(ws, r, 1,  "dns_time",              NULL);
    worksheet_write_string(ws, r, 2,  "pre_send_time",         NULL);
    worksheet_write_string(ws, r, 3,  "app_gap",               NULL);
    worksheet_write_string(ws, r, 4,  "total_from_dns_start",  NULL);
    worksheet_write_string(ws, r, 5,  "t_dns_start",           NULL);
    worksheet_write_string(ws, r, 6,  "t_dns_done",            NULL);
    worksheet_write_string(ws, r, 7,  "t_send_app",            NULL);
    worksheet_write_string(ws, r, 8,  "t_recv_app",            NULL);

    for (int i = 0; i < n; i++) {
        r = i + 1;
        worksheet_write_number(ws, r, 0,  rows[i].serial,              NULL);
        worksheet_write_number(ws, r, 1,  rows[i].dns_time,            NULL);
        worksheet_write_number(ws, r, 2,  rows[i].pre_send_time,       NULL);
        worksheet_write_number(ws, r, 3,  rows[i].app_gap,             NULL);
        worksheet_write_number(ws, r, 4,  rows[i].total_from_dns_start,NULL);
        worksheet_write_number(ws, r, 5,  rows[i].t_dns_start,         NULL);
        worksheet_write_number(ws, r, 6,  rows[i].t_dns_done,          NULL);
        worksheet_write_number(ws, r, 7,  rows[i].t_send_app,          NULL);
        worksheet_write_number(ws, r, 8,  rows[i].t_recv_app,          NULL);
    }

    workbook_close(wb);
    printf("✅ wrote %s (%d rows)\n", out_xlsx, n);
    return 0;
}

