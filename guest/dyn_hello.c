// Dynamically linked: proves the loader maps the interpreter and lets ld.so
// pull in libc, and that a guest built as PIE (ET_DYN) runs to completion.
//
// Kept separate from hello.c because that one is a -nostdlib static image used
// to exercise the mediated syscall path, whereas this one depends on the
// host's ld.so and libc being reachable.
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64];
    size_t n = strlen("dynamic-link-ok");
    snprintf(buf, sizeof buf, "dyn %s %zu\n", "ok", n);
    fputs(buf, stdout);
    return 42;
}
