/* init: the first process a myos guest runs.
 *
 * Sets up the environment, starts the shell, and reaps orphaned children.
 * This is the guest's PID 1 equivalent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

int main(void) {
    // Set up default environment
    setenv("PATH", "/bin:/usr/bin:/usr/local/bin", 1);
    setenv("HOME", "/", 1);
    setenv("TERM", "myos", 1);
    setenv("MYOS", "1", 1);

    // Open console
    int fd = open("/dev/console", O_RDWR);
    if (fd >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) close(fd);
    }

    printf("\n");
    printf("myos: init starting\n");
    printf("myos: welcome to the parasitic OS\n");
    printf("\n");

    // Start the shell
    pid_t pid = fork();
    if (pid == 0) {
        // Child: exec the shell
        char *argv[] = {"sh2", NULL};
        char *envp[] = {
            "PATH=/bin:/usr/bin:/usr/local/bin",
            "HOME=/",
            "TERM=myos",
            "MYOS=1",
            NULL
        };
        execve("/bin/sh2", argv, envp);
        // If execve fails, try sh
        char *argv2[] = {"sh", NULL};
        execve("/bin/sh", argv2, envp);
        perror("init: cannot start shell");
        _exit(1);
    }

    // Parent: reap children
    int status;
    while (1) {
        pid_t result = wait(&status);
        if (result < 0) {
            break;
        }
        if (WIFEXITED(status)) {
            printf("myos: process %d exited with status %d\n", result, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("myos: process %d killed by signal %d\n", result, WTERMSIG(status));
        }
    }

    printf("myos: init exiting\n");
    return 0;
}
