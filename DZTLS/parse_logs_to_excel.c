#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <xlsxwriter.h>

#define MAX_FILES 500
#define LINE_SIZE 1024

typedef struct {
    int serial;
    double start, a_start, a_done, recv;
    double recv_minus_start;
    double a_done_minus_a_start;
} LogData;

// ---- 정규식으로 타임스탬프 추출 ----
double find_time(const char *line, const char *pattern) {
    regex_t regex;
    regmatch_t match[2];
    double val = -1.0;

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0)
        return -1.0;

    if (regexec(&regex, line, 2, match, 0) == 0 && match[1].rm_so != -1) {
        char buf[64];
        int len = match[1].rm_eo - match[1].rm_so;
        strncpy(buf, line + match[1].rm_so, len);
        buf[len] = '\0';
        val = atof(buf);
    }
    regfree(&regex);
    return val;
}

// ---- 한 파일 파싱 ----
int parse_file(const char *filename, LogData *out, int serial) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    char line[LINE_SIZE];
    double start = -1, a_start = -1, a_done = -1, recv = -1;

    while (fgets(line, sizeof(line), fp)) {
        if (start < 0)
            start = find_time(line, "^start *: *([0-9]+\\.[0-9]+)");
        if (a_start < 0)
            a_start = find_time(line, "^start A and AAAA DNS records query *: *([0-9]+\\.[0-9]+)");
        if (a_done < 0)
            a_done = find_time(line, "^complete A and AAAA DNS records query *: *([0-9]+\\.[0-9]+)");
        if (recv < 0)
            recv = find_time(line, "^receiving application data from server *: *([0-9]+\\.[0-9]+)");
        if (recv < 0)
            recv = find_time(line, "^receiving application data from server : mmlab *: *([0-9]+\\.[0-9]+)");
            
    }
    fclose(fp);

    out->serial = serial;
    out->start = start;
    out->a_start = a_start;
    out->a_done = a_done;
    out->recv = recv;

    if (recv > 0 && start > 0)
        out->recv_minus_start = recv - start;
    else
        out->recv_minus_start = -1;

    if (a_done > 0 && a_start > 0)
        out->a_done_minus_a_start = a_done - a_start;
    else
        out->a_done_minus_a_start = -1;

    return 0;
}

// ---- 메인 ----
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s output.xlsx file1.txt [file2.txt ...]\n", argv[0]);
        return 1;
    }

    const char *outfile = argv[1];
    LogData data[MAX_FILES];
    int count = 0;

    for (int i = 2; i < argc && count < MAX_FILES; i++) {
        if (parse_file(argv[i], &data[count], count + 1) == 0)
            count++;
    }

    // Excel 파일 작성
    lxw_workbook  *workbook  = workbook_new(outfile);
    lxw_worksheet *worksheet = workbook_add_worksheet(workbook, NULL);

    // 헤더 작성
    worksheet_write_string(worksheet, 0, 0, "serial", NULL);
    worksheet_write_string(worksheet, 0, 1, "recv_minus_start", NULL);
    worksheet_write_string(worksheet, 0, 2, "a_done_minus_a_start", NULL);
    worksheet_write_string(worksheet, 0, 3, "start", NULL);
    worksheet_write_string(worksheet, 0, 4, "a_start", NULL);
    worksheet_write_string(worksheet, 0, 5, "a_done", NULL);
    worksheet_write_string(worksheet, 0, 6, "recv", NULL);

    // 데이터 행
    for (int i = 0; i < count; i++) {
        worksheet_write_number(worksheet, i+1, 0, data[i].serial, NULL);
        worksheet_write_number(worksheet, i+1, 1, data[i].recv_minus_start, NULL);
        worksheet_write_number(worksheet, i+1, 2, data[i].a_done_minus_a_start, NULL);
        worksheet_write_number(worksheet, i+1, 3, data[i].start, NULL);
        worksheet_write_number(worksheet, i+1, 4, data[i].a_start, NULL);
        worksheet_write_number(worksheet, i+1, 5, data[i].a_done, NULL);
        worksheet_write_number(worksheet, i+1, 6, data[i].recv, NULL);
    }

    workbook_close(workbook);
    printf("✅ Wrote %s (%d entries)\n", outfile, count);
    return 0;
}
