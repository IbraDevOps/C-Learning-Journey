/*
 * SecLog Analyzer - A simple C program to parse HTTP access logs,
 * extract client IPs, and track request statistics. For each unique IP,
 * it counts total requests, failed requests (4xx/5xx), and suspicious
 * activity based on basic heuristic patterns (e.g., SQL injection, XSS,
 * path traversal). The results are sorted by suspicious activity,
 * failures, and total requests, then displayed in a formatted table.
 * Input can be from a file or piped via stdin.
 */


// SecLog Scan — a tiny log analyzer (arrays, pointers, memory mgmt)
// Build:  gcc -Wall -Wextra -Wpedantic -Wshadow -Wconversion -O2 \
//             -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
//             -fsanitize=address,undefined \
//             seclog_scan.c -o seclog_scan
//
// Usage:  ./seclog_scan access.log
//         cat access.log | ./seclog_scan
//
// Log format expected (loose): "IP - - [date] \"METHOD PATH ...\" STATUS ..."
// Works with common Nginx/Apache styles. If parsing fails for a line, it is skipped safely.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>

typedef struct {
    char *ip;                 // dynamically owned
    unsigned total;           // total requests from this IP
    unsigned failed;          // 4xx/5xx
    unsigned suspicious;      // matched heuristic signatures
} IPStat;

typedef struct {
    IPStat *data;
    size_t len;
    size_t cap;
} Vec;

// ---- small safe helpers ----
static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) { perror("malloc"); exit(EXIT_FAILURE); }
    return p;
}
static void *xrealloc(void *ptr, size_t n) {
    void *p = realloc(ptr, n);
    if (!p) { perror("realloc"); exit(EXIT_FAILURE); }
    return p;
}
static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)xmalloc(n);
    memcpy(p, s, n);
    return p;
}

// grow vector capacity safely (cap *= 2, with minimal overflow guard)
static void vec_reserve(Vec *v, size_t need) {
    if (need <= v->cap) return;
    size_t new_cap = v->cap ? v->cap : 8;
    while (new_cap < need) {
        if (new_cap > (SIZE_MAX / 2)) { fprintf(stderr, "capacity overflow\n"); exit(EXIT_FAILURE); }
        new_cap *= 2;
    }
    v->data = (IPStat *)xrealloc(v->data, new_cap * sizeof(IPStat));
    v->cap = new_cap;
}

static void vec_free(Vec *v) {
    if (!v) return;
    for (size_t i = 0; i < v->len; i++) free(v->data[i].ip);
    free(v->data);
    v->data = NULL; v->len = v->cap = 0;
}

// find IP in vector (linear search keeps code simple)
static ssize_t find_ip(const Vec *v, const char *ip) {
    for (size_t i = 0; i < v->len; i++) {
        if (strcmp(v->data[i].ip, ip) == 0) return (ssize_t)i;
    }
    return -1;
}

static void add_or_update(Vec *v, const char *ip, int failed, int suspicious) {
    ssize_t idx = find_ip(v, ip);
    if (idx < 0) {
        vec_reserve(v, v->len + 1);
        v->data[v->len].ip = xstrdup(ip);
        v->data[v->len].total = 1u;
        v->data[v->len].failed = failed ? 1u : 0u;
        v->data[v->len].suspicious = suspicious ? 1u : 0u;
        v->len++;
    } else {
        IPStat *s = &v->data[(size_t)idx];
        s->total++;
        if (failed) s->failed++;
        if (suspicious) s->suspicious++;
    }
}

// ---- parsing & detection ----

// extract first token (IP) from a line; returns 1 on success
static int extract_ip(const char *line, char *out, size_t outsz) {
    // skip leading spaces
    while (*line && isspace((unsigned char)*line)) line++;
    // copy until space
    size_t i = 0;
    while (line[i] && !isspace((unsigned char)line[i])) {
        if (i + 1 >= outsz) return 0; // too long
        out[i] = line[i];
        i++;
    }
    if (i == 0) return 0;
    out[i] = '\0';
    return 1;
}

// try to find `"METHOD PATH` segment to pull PATH (best-effort)
static int extract_path(const char *line, char *out, size_t outsz) {
    const char *q1 = strchr(line, '\"');
    if (!q1) return 0;
    q1++;
    // METHOD ends at space
    const char *sp = strchr(q1, ' ');
    if (!sp) return 0;
    // PATH starts after METHOD's space
    const char *path = sp + 1;
    // PATH ends at next space or quote
    size_t i = 0;
    while (path[i] && path[i] != ' ' && path[i] != '\"') {
        if (i + 1 >= outsz) return 0;
        out[i] = path[i];
        i++;
    }
    if (i == 0) return 0;
    out[i] = '\0';
    return 1;
}

static int extract_status(const char *line) {
    // Find the closing quote of the request then the status code after it
    const char *q2 = strrchr(line, '\"');
    if (!q2) return -1;
    const char *p = q2 + 1;
    while (*p && isspace((unsigned char)*p)) p++;
    // read int
    char *end = NULL;
    long val = strtol(p, &end, 10);
    if (end == p || val < 0 || val > 999) return -1;
    return (int)val;
}

// very small heuristic signatures for demo purposes
static int is_suspicious_path(const char *path) {
    // lower-case copy (bounded)
    char tmp[512];
    size_t n = 0;
    for (; path[n] && n < sizeof(tmp) - 1; n++) tmp[n] = (char)tolower((unsigned char)path[n]);
    tmp[n] = '\0';

    return strstr(tmp, "union%20select") || strstr(tmp, "union+select") ||
           strstr(tmp, "union select")   || strstr(tmp, "' or '1'='1")  ||
           strstr(tmp, "%27or%271%27%3d%271") || strstr(tmp, "<script") ||
           strstr(tmp, "%3cscript")      || strstr(tmp, "../")          ||
           strstr(tmp, "%2e%2e%2f");
}

// ---- main ----

int main(int argc, char **argv) {
    const char *fname = NULL;
    if (argc >= 2) fname = argv[1];
    FILE *fp = fname ? fopen(fname, "r") : stdin;
    if (!fp) { perror("fopen"); return EXIT_FAILURE; }

    Vec stats = {0};
    char line[2048];          // bounded read buffer
    char ip[64];
    char path[512];

    while (fgets(line, (int)sizeof line, fp)) {
        if (!extract_ip(line, ip, sizeof ip)) continue;
        int status = extract_status(line);
        (void)extract_path(line, path, sizeof path);    // best-effort; OK if it fails

        int failed = (status >= 400 && status <= 599);
        int susp   = (extract_path(line, path, sizeof path) && is_suspicious_path(path)) ? 1 : 0;

        add_or_update(&stats, ip, failed, susp);
    }

    if (fp != stdin) fclose(fp);

    // sort by suspicious desc, then failed desc (qsort + comparator)
    int cmp(const void *a, const void *b) {
        const IPStat *x = (const IPStat *)a, *y = (const IPStat *)b;
        if (y->suspicious != x->suspicious) return (int)y->suspicious - (int)x->suspicious;
        if (y->failed     != x->failed)     return (int)y->failed - (int)x->failed;
        return (int)y->total - (int)x->total;
    }
    qsort(stats.data, stats.len, sizeof(IPStat), cmp);

    // report
    printf("\n== SecLog Scan Report ==\n");
    printf("%-18s %8s %8s %11s\n", "IP", "Total", "Failed", "Suspicious");
    printf("-----------------------------------------------------\n");
    for (size_t i = 0; i < stats.len; i++) {
        printf("%-18s %8u %8u %11u\n",
               stats.data[i].ip,
               stats.data[i].total,
               stats.data[i].failed,
               stats.data[i].suspicious);
    }
    printf("Entries: %zu unique IPs\n", stats.len);

    vec_free(&stats);
    return EXIT_SUCCESS;
}

