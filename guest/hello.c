/* A guest built on minic, our self-hosted C library: no host libc and no
 * dynamic linker. Every syscall it makes is trapped by myos and serviced by
 * oscore. The writes to fd 1 are captured by the dispatcher and flushed to the
 * terminal by the SIGSYS handler, which proves the trap-service path end to
 * end. The open/read/close sequence exercises the in-memory VFS. */
#include "minic.h"

int main(void) {
    static const char hello[] = "guest: write trapped and serviced by myos\n";
    write(1, hello, sizeof(hello) - 1);

    /* open/read/close against the seeded /motd file in myos's VFS. */
    char buf[128];
    int fd = open("/motd", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            write(1, buf, (size_t)n);
        }
        close(fd);
    }

    /* Write a new file through the VFS, then read it back. */
    int wfd = open("/scratch", O_RDWR | O_CREAT, 0644);
    if (wfd >= 0) {
        static const char scratch[] = "guest: /scratch created through the VFS\n";
        write(wfd, scratch, sizeof(scratch) - 1);
        close(wfd);
    }
    int rfd = open("/scratch", O_RDONLY);
    if (rfd >= 0) {
        ssize_t n = read(rfd, buf, sizeof(buf));
        if (n > 0) {
            write(1, buf, (size_t)n);
        }
        close(rfd);
    }

    /* getpid is mediated too: the dispatcher returns a synthetic pid. */
    return getpid();
}
