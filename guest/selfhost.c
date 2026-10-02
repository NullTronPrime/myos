/* A guest that uses only minic, our self-hosted C library: no host glibc and no
 * dynamic linker. Built with `-nostdlib` against lib/crt0.S and lib/minic.c. */
#include "minic.h"

int main(int argc, char **argv) {
    printf("selfhost argc=%d\n", argc);
    for (int i = 1; i < argc; i++) {
        printf("arg[%d]=%s\n", i, argv[i]);
    }

    char *buf = malloc(64);
    if (!buf) {
        puts("malloc-failed");
        return 2;
    }
    for (int i = 0; i < 63; i++) {
        buf[i] = (char)('A' + (i % 26));
    }
    buf[63] = '\0';
    puts(buf);
    printf("len=%d\n", (int)strlen(buf));

    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%d/%x/%s", 42, 255, "ok");
    printf("fmt=%s\n", tmp);

    free(buf);
    return 7;
}
