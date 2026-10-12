// Exercises poll(2) with a timeout on host-backed fds: an empty pipe must
// report nothing only AFTER the timeout elapses (an instant zero means the
// kernel snapshots instead of waiting, stranding every DNS lookup), and a
// pipe with bytes waiting must report readable at once.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;
    struct pollfd pfd = { .fd = fds[0], .events = POLLIN };

    long t0 = now_ms();
    int r = poll(&pfd, 1, 300);
    long dt = now_ms() - t0;
    printf("empty poll=%d dt=%ld\n", r, dt);
    if (r != 0) return 2;
    if (dt < 200) return 3; /* returned before the timeout: not a wait */

    if (write(fds[1], "x", 1) != 1) return 4;
    t0 = now_ms();
    r = poll(&pfd, 1, 300);
    dt = now_ms() - t0;
    printf("ready poll=%d dt=%ld revents=%d\n", r, dt, pfd.revents);
    if (r != 1 || !(pfd.revents & POLLIN)) return 5;
    if (dt > 200) return 6; /* ready data should not wait out the timeout */
    printf("POLL_TEST:PASS\n");
    return 0;
}
