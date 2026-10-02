// Child for the process-model contract test.
//
// Loaded through `myos --exec`, so its `getpid` must be the host pid and its
// exit status must propagate to the parent's `wait4`. Also reads one line from
// stdin to prove `read(0)` is wired to the host.
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("child pid=%d\n", (int)getpid());
    fflush(stdout);
    char buf[64];
    ssize_t n = read(0, buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = 0;
        printf("child read=%s", buf);
    } else {
        printf("child read=empty\n");
    }
    fflush(stdout);
    return 7;
}
