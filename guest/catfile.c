// Reads a guest file by path and writes it to stdout. Used to prove the
// host-backed rootfs is visible through the mediated openat/read path.
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 1;
    char buf[512];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        if (write(1, buf, (size_t)n) != n) return 3;
    }
    return 0;
}
