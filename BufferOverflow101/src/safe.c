#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char name[32] = {0};

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }

    // ✅ BOUNDED COPY: copies at most 31 chars + NUL
    strncpy(name, argv[1], sizeof(name) - 1);
    printf("Hello, %s\n", name);
    return 0;
}
