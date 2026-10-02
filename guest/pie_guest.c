/* A static-PIE guest: it has no interpreter and no host libraries, but its
 * globals hold absolute addresses that only become known once a load base is
 * chosen. The kernel-side loader must apply the resulting R_X86_64_RELATIVE
 * relocations, because neither ld.so nor crt0 does.
 *
 * The table is `volatile` and indexed at run time so the compiler cannot fold
 * the pointers away; otherwise a small program can legitimately link with no
 * relocations at all and this would prove nothing. */
#include "minic.h"

static const char *volatile names[4] = { "zero", "one", "two", "three" };
volatile long checksum;

int main(int argc, char **argv) {
    for (int i = 0; i < 4; i++) {
        const char *p = (const char *)names[i];
        checksum += p[0];
        printf("name[%d]=%s\n", i, p);
    }
    printf("argc=%d argv0=%s\n", argc, argv[0]);
    return 7;
}
