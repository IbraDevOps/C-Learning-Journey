#include <stdio.h>
#include <string.h>

// EDUCATIONAL ONLY: shows a stack buffer overflow with overlong input.
int main(int argc, char **argv) {
    char name[32] = {0};              // 32-byte stack buffer

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }

    // ❌ NO BOUNDS CHECK: overlong argv[1] will overflow `name`
    strcpy(name, argv[1]);

    printf("Hello, %s\n", name);
    return 0;
}

