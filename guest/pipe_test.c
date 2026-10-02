// Exercises the host-backed descriptor path: pipe, fork, dup2, write/read,
// and wait. Prints what the parent received over the pipe.
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 1);
        close(fds[1]);
        write(1, "through-the-pipe\n", 17);
        _exit(0);
    }

    close(fds[1]);
    char buf[64];
    ssize_t n = read(fds[0], buf, sizeof buf - 1);
    int st = 0;
    wait4(pid, &st, 0, NULL);
    close(fds[0]);
    if (n <= 0) return 2;
    buf[n] = 0;
    write(1, "parent got: ", 12);
    write(1, buf, (size_t)n);
    return strncmp(buf, "through-the-pipe", 16) == 0 ? 0 : 3;
}
