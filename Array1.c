/*
  SecScore Analyzer — CMU/CyLab Edition (arrays-only)

  GOAL (from a security lens):
  - Practice clean, defensive C using only what you've learned: variables, loops, conditionals, arrays.
  - Show safe input parsing (no unsafe gets/scanf patterns), bounds checks, and no magic numbers.
  - Keep memory on the stack with fixed-size arrays; validate all indices and counts.
  - Make output deterministic and easy to diff in CI.

  THREAT MODEL (learning-grade):
  - Input comes from a human. Expect typos, negative numbers, and out-of-range values.
  - Avoid classic pitfalls: buffer overreads, unchecked scanf, magic numbers, integer overflows on sizes.
  - We are not using dynamic allocation yet (you'll add malloc later in the journey).

  HOW TO COMPILE (with warnings + basic hardening/UB checks):
    gcc -Wall -Wextra -Wpedantic -Wshadow -Wconversion -O2 \
        -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        -fsanitize=address,undefined \
        secscore_cmu.c -o secscore

  NOTE: AddressSanitizer/UBSan help catch memory bugs at runtime.
*/

#include <stdio.h>    // printf, fgets
#include <stdlib.h>   // strtol, strtof, EXIT_*
#include <string.h>   // strlen
#include <errno.h>    // errno
#include <limits.h>   // INT_MAX
#include <float.h>    // FLT_MAX

/* ==== Constants (no magic numbers) ==== */
#define MAX_MEMBERS 100   /* upper bound for stack arrays to prevent overflow */
#define MODULES 4         /* fixed number of CMU/CyLab-style modules */

/* Grade cutoffs — tweak to your policy. Using macros keeps policy in one place. */
#define GRADE_A 85
#define GRADE_B 75
#define GRADE_C 65
#define GRADE_D 50

/* Human-readable module names aligned to your curriculum. */
static const char *MODULE_NAMES[MODULES] = {
    "Network Security",
    "Secure Software",
    "SOC Operations",
    "Ethical Hacking"
};

/* ==== Forward declarations ==== */
/* Small parsing helpers that avoid unsafe scanf patterns. */
static int   read_int_in_range(const char *prompt, int min, int max);
static float read_float_in_range(const char *prompt, float min, float max);

static void  inputScores(float s[][MODULES], int n);
static void  memberAverages(const float s[][MODULES], int n, float avg[]);
static void  teamStats(const float avg[], int n, float *teamAvg, float *hi, float *lo);
static void  moduleAverages(const float s[][MODULES], int n, float colAvg[]);
static char  gradeFromScore(float x);
static const char* riskFromGrade(char g);
static void  printReport(const float s[][MODULES], int n,
                         const float avg[], float teamAvg, float hi, float lo,
                         const float colAvg[]);

/* ==== main: wires the steps, keeps logic minimal ==== */
int main(void) {
    /* All memory is stack-based, fixed-size arrays; no heap yet. */
    float scores[MAX_MEMBERS][MODULES];
    float avg[MAX_MEMBERS];
    float teamAvg, hi, lo, colAvg[MODULES];

    /* Defensive size read with range check to prevent out-of-bounds writes. */
    int n = read_int_in_range("Enter number of team members (1-100): ", 1, MAX_MEMBERS);

    /* Step 1: Read 2D scores array safely. */
    inputScores(scores, n);

    /* Step 2: Compute per-member averages (1D result from 2D input). */
    memberAverages(scores, n, avg);

    /* Step 3: Compute aggregate team statistics from per-member averages. */
    teamStats(avg, n, &teamAvg, &hi, &lo);

    /* Step 4: Compute per-module averages (column means). */
    moduleAverages(scores, n, colAvg);

    /* Step 5: Print a deterministic, table-style report. */
    printReport(scores, n, avg, teamAvg, hi, lo, colAvg);

    return EXIT_SUCCESS;
}

/* ==== Input helpers (secure-ish for a console app) ==== */

/* read_int_in_range:
   - Uses fgets into a small stack buffer (bounded) to avoid overflow.
   - Converts with strtol and checks for errors (ERANGE, trailing junk).
   - Enforces [min, max] range to stop size abuse.
*/
static int read_int_in_range(const char *prompt, int min, int max) {
    char buf[64]; /* small fixed buffer; big enough for typical ints + junk */
    for (;;) {
        printf("%s", prompt);
        if (!fgets(buf, (int)sizeof buf, stdin)) {
            /* EOF or error — fail closed. */
            fprintf(stderr, "Input error.\n");
            exit(EXIT_FAILURE);
        }
        /* Strip newline if present (fgets keeps it). */
        size_t len = strlen(buf);
        if (len && buf[len - 1] == '\n') buf[len - 1] = '\0';

        errno = 0;
        char *end = NULL;
        long v = strtol(buf, &end, 10); /* base-10 */

        /* Validate: conversion happened, no range error, and no trailing junk. */
        if (end == buf || errno == ERANGE || *end != '\0') {
            printf("  Invalid integer. Try again.\n");
            continue;
        }
        /* Range enforcement. */
        if (v < (long)min || v > (long)max) {
            printf("  Out of range [%d..%d]. Try again.\n", min, max);
            continue;
        }
        return (int)v;
    }
}

/* read_float_in_range:
   - Same pattern as above but for floats.
   - strtof allows us to catch junk like "12abc".
   - Range gate limits logical inputs to [min, max].
*/
static float read_float_in_range(const char *prompt, float min, float max) {
    char buf[64];
    for (;;) {
        printf("%s", prompt);
        if (!fgets(buf, (int)sizeof buf, stdin)) {
            fprintf(stderr, "Input error.\n");
            exit(EXIT_FAILURE);
        }
        size_t len = strlen(buf);
        if (len && buf[len - 1] == '\n') buf[len - 1] = '\0';

        errno = 0;
        char *end = NULL;
        float v = strtof(buf, &end);

        if (end == buf || errno == ERANGE || *end != '\0') {
            printf("  Invalid number. Use 0..100 (no letters). Try again.\n");
            continue;
        }
        if (v < min || v > max) {
            printf("  Out of range [%.0f..%.0f]. Try again.\n", (double)min, (double)max);
            continue;
        }
        return v;
    }
}

/* inputScores:
   - Fills a 2D array scores[n][MODULES] with validated floats 0..100.
   - The outer loop walks team members; inner loop walks modules.
   - Bounds: i in [0, n), m in [0, MODULES). No writes beyond arrays.
*/
static void inputScores(float s[][MODULES], int n) {
    for (int i = 0; i < n; i++) {
        printf("\n-- Member %d --\n", i + 1);
        for (int m = 0; m < MODULES; m++) {
            /* Prompt includes the actual module title for clarity. */
            char prompt[96];
            (void)snprintf(prompt, sizeof prompt, "%s score (0-100): ", MODULE_NAMES[m]);
            s[i][m] = read_float_in_range(prompt, 0.0f, 100.0f);
        }
    }
}

/* memberAverages:
   - Average of each row (member) across MODULES columns.
   - Sum uses float; MODULES is small → precision is fine for 0..100.
*/
static void memberAverages(const float s[][MODULES], int n, float avg[]) {
    for (int i = 0; i < n; i++) {
        float sum = 0.0f;
        for (int m = 0; m < MODULES; m++) sum += s[i][m];
        avg[i] = sum / (float)MODULES;
    }
}

/* teamStats:
   - Computes aggregate stats on the per-member averages.
   - Initializes from avg[0] to avoid sentinel bugs on min/max.
*/
static void teamStats(const float avg[], int n, float *teamAvg, float *hi, float *lo) {
    float sum = avg[0];
    *hi = avg[0];
    *lo = avg[0];
    for (int i = 1; i < n; i++) {
        sum += avg[i];
        if (avg[i] > *hi) *hi = avg[i];
        if (avg[i] < *lo) *lo = avg[i];
    }
    *teamAvg = sum / (float)n;
}

/* moduleAverages:
   - Column means across all members; helps spot weak curriculum areas.
*/
static void moduleAverages(const float s[][MODULES], int n, float colAvg[]) {
    for (int m = 0; m < MODULES; m++) {
        float sum = 0.0f;
        for (int i = 0; i < n; i++) sum += s[i][m];
        colAvg[m] = sum / (float)n;
    }
}

/* gradeFromScore:
   - Converts a numeric average to a policy grade (A..F).
   - Using macros keeps the policy centralized and auditable.
*/
static char gradeFromScore(float x) {
    if (x >= (float)GRADE_A) return 'A';
    else if (x >= (float)GRADE_B) return 'B';
    else if (x >= (float)GRADE_C) return 'C';
    else if (x >= (float)GRADE_D) return 'D';
    else return 'F';
}

/* riskFromGrade:
   - Maps grades to operational risk terms security folks use.
*/
static const char* riskFromGrade(char g) {
    switch (g) {
        case 'A': return "Low";
        case 'B': return "Moderate";
        case 'C': return "High";
        case 'D': return "Very High";
        default:  return "Critical";
    }
}

/* printReport:
   - Single responsibility: presentation.
   - Keeps formatting consistent and easy to diff in CI logs.
*/
static void printReport(const float s[][MODULES], int n,
                        const float avg[], float teamAvg, float hi, float lo,
                        const float colAvg[]) {
    printf("\n================ SecScore Report (CMU/CyLab) ================\n");
    printf("Modules:\n");
    for (int m = 0; m < MODULES; m++) {
        printf("  M%d: %s\n", m + 1, MODULE_NAMES[m]);
    }
    printf("\n%-9s %-9s %-9s %-9s %-9s %-9s %-10s\n",
           "Member", "M1", "M2", "M3", "M4", "Avg", "Risk");
    printf("----------------------------------------------------------------\n");

    for (int i = 0; i < n; i++) {
        char g = gradeFromScore(avg[i]);
        printf("%-9d %-9.1f %-9.1f %-9.1f %-9.1f %-9.1f %-10s\n",
               i + 1, s[i][0], s[i][1], s[i][2], s[i][3], avg[i], riskFromGrade(g));
    }

    printf("\nTeam Average: %.2f   Highest Avg: %.2f   Lowest Avg: %.2f\n",
           teamAvg, hi, lo);
    printf("Module Averages -> M1: %.2f  M2: %.2f  M3: %.2f  M4: %.2f\n",
           colAvg[0], colAvg[1], colAvg[2], colAvg[3]);
    printf("==============================================================\n");
}

