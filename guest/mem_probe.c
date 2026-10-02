/* Checks that mmap and brk are mediated: the dispatcher decides, the host
 * realises. Built on minic, our self-hosted C library. */
#include "minic.h"

static void mark(char c) { write(1, &c, 1); }

int main(void) {
    mark('1');
    long len = 8192;
    char *m = (char *)mmap(0, (size_t)len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mark('2');
    if ((long)m < 0) {
        mark('X');
        _exit(2);
    }
    m[0] = 'a';
    mark('3');
    for (long i = 0; i < len; i++) m[i] = (char)(i & 0x7f);
    mark('4');
    write(1, "mmap-ok\n", 8);

    char *base = (char *)brk((void *)0);
    mark('5');
    char *want = base + 8192;
    char *got = (char *)brk(want);
    mark('6');
    if (got != want) {
        mark('Y');
        _exit(3);
    }
    base[0] = 'b';
    mark('7');
    for (long i = 0; i < 8192; i++) base[i] = (char)(0x40 + (i & 0x3f));
    mark('8');
    write(1, "brk-ok\n", 7);
    return 0;
}
