/** Mini Project: System Resource Usage Tracker
 *  - Ask user for CPU, Memory, Disk usage readings
 *  - Store in arrays
 *  - Compute Avg / High / Low
 *  - Derive status (Normal / Warning / Critical) from average
 *  Build: gcc -std=c99 "System Resource Usage Tracker.c" -o System_Tracker
 */
#include <stdio.h>

const char* status_from_avg(float x) {
    if (x < 60.0f)  return "NORMAL";
    if (x <= 80.0f) return "WARNING";
    return "CRITICAL";
}

int main(void) {
    int i;

    printf("=========================================\n");
    printf("     SYSTEM RESOURCE USAGE TRACKER\n");
    printf("=========================================\n");

    /* ---------- CPU ---------- */
    int cpu_n;
    printf("\nEnter number of readings to record\n");
    scanf("%d", &cpu_n);

    int cpu[cpu_n];
    printf("\n--- Enter CPU usage readings (%%):\n");
    for (i = 0; i < cpu_n; i++) {
        printf("Reading %d: ", i + 1);
        scanf("%d", &cpu[i]);
    }

    /* ---------- Memory ---------- */
    int mem_n;
    printf("Enter number of MEM readings to record\n");
    scanf("%d", &mem_n);

    int Mem[mem_n];
    printf("\n--- Enter Memory usage readings (%%):\n");
    for (i = 0; i < mem_n; i++) {
        printf("Reading %d: ", i + 1);
        scanf("%d", &Mem[i]);        // FIXED: was cpu[i]
    }

    /* ---------- Disk ---------- */
    int disk_n;
    printf("Enter number of Disk readings to record\n");
    scanf("%d", &disk_n);

    int Disk[disk_n];
    printf("\n--- Enter Disk  usage readings (%%):\n");
    for (i = 0; i < disk_n; i++) {
        printf("Reading %d: ", i + 1);
        scanf("%d", &Disk[i]);       // FIXED: was cpu[i]
    }

    /* ---------- Compute stats ---------- */
    // CPU
    int cpu_hi = cpu[0], cpu_lo = cpu[0]; long cpu_sum = 0;
    for (i = 0; i < cpu_n; i++) {
        if (cpu[i] > cpu_hi) cpu_hi = cpu[i];
        if (cpu[i] < cpu_lo) cpu_lo = cpu[i];
        cpu_sum += cpu[i];
    }
    float cpu_avg = (float)cpu_sum / (float)cpu_n;

    // Memory
    int mem_hi = Mem[0], mem_lo = Mem[0]; long mem_sum = 0;
    for (i = 0; i < mem_n; i++) {
        if (Mem[i] > mem_hi) mem_hi = Mem[i];
        if (Mem[i] < mem_lo) mem_lo = Mem[i];
        mem_sum += Mem[i];
    }
    float mem_avg = (float)mem_sum / (float)mem_n;

    // Disk
    int disk_hi = Disk[0], disk_lo = Disk[0]; long disk_sum = 0;
    for (i = 0; i < disk_n; i++) {
        if (Disk[i] > disk_hi) disk_hi = Disk[i];
        if (Disk[i] < disk_lo) disk_lo = Disk[i];
        disk_sum += Disk[i];
    }
    float disk_avg = (float)disk_sum / (float)disk_n;

    /* ---------- Report ---------- */
    printf("\n=========================================\n");
    printf("             USAGE SUMMARY\n");
    printf("=========================================\n");
    printf("CPU   -> Avg: %.1f%%   High: %d%%   Low: %d%%   Status: %s\n",
           cpu_avg, cpu_hi, cpu_lo, status_from_avg(cpu_avg));
    printf("RAM   -> Avg: %.1f%%   High: %d%%   Low: %d%%   Status: %s\n",
           mem_avg, mem_hi, mem_lo, status_from_avg(mem_avg));
    printf("Disk  -> Avg: %.1f%%   High: %d%%   Low: %d%%   Status: %s\n",
           disk_avg, disk_hi, disk_lo, status_from_avg(disk_avg));

    printf("\nLegend:\n");
    printf("- NORMAL:   < 60%%\n");
    printf("- WARNING:  60%% - 80%%\n");
    printf("- CRITICAL: > 80%%\n");
    printf("\n=========================================\n");
    printf("Report generated successfully!\n");

    return 0;
}

