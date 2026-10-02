// Parent for the process-model contract test.
//
// Forks, execs the child (argv[1]) through the myos `execve` trampoline, and
// reaps it with `wait4`, reporting the child's exit status.
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: proc_parent <child>\n");
        return 2;
    }
    printf("parent pid=%d\n", (int)getpid());
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 3;
    }
    if (pid == 0) {
        char *args[] = {argv[1], NULL};
        execve(argv[1], args, NULL);
        _exit(111);
    }

    int st = 0;
    pid_t r = wait4(pid, &st, 0, NULL);
    if (r < 0) {
        perror("wait4");
        return 4;
    }
    if (WIFEXITED(st)) {
        printf("parent reaped %d status=%d\n", (int)r, WEXITSTATUS(st));
        return 42;
    }
    printf("parent reaped %d raw=%#x\n", (int)r, st);
    return 5;
}
