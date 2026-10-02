// Copies stdin to stdout. Used to prove a shell `a | b` pipeline actually moves
// bytes through the host-backed pipe.
#include <unistd.h>

int main(void) {
    char buf[256];
    ssize_t n;
    while ((n = read(0, buf, sizeof buf)) > 0) {
        if (write(1, buf, (size_t)n) != n) return 1;
    }
    return 0;
}
