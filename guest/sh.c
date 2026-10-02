// A tiny interactive shell, run as a myos guest.
//
// Reads a command line from stdin, forks, execs the program through the myos
// `execve` trampoline, and waits for it. A line may chain commands with `|`,
// which the host-backed pipe/fork/dup2 support makes real. Reading is done one
// byte at a time so the shell never buffers input meant for a child sharing
// fd 0.
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_CMDS 8
#define MAX_ARGS 64

static ssize_t read_line(char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        ssize_t r = read(0, &c, 1);
        if (r < 0) return -1;
        if (r == 0) return n == 0 ? 0 : (ssize_t)n;
        if (c == '\n') break;
        buf[n++] = c;
    }
    buf[n] = 0;
    return (ssize_t)n;
}

// Splits `line` on '|', trimming surrounding blanks. Returns the command count.
static int split_commands(char *line, char *cmds[MAX_CMDS]) {
    int n = 0;
    char *p = line;
    while (*p && n < MAX_CMDS) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0) break;
        cmds[n++] = p;
        char *bar = strchr(p, '|');
        if (!bar) break;
        char *e = bar;
        while (e > p && (e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
        *bar = 0;
        p = bar + 1;
    }
    return n;
}

static int tokenize(char *cmd, char *argv[MAX_ARGS]) {
    int argc = 0;
    for (char *t = strtok(cmd, " \t"); t && argc < MAX_ARGS - 1; t = strtok(NULL, " \t")) {
        argv[argc++] = t;
    }
    argv[argc] = NULL;
    return argc;
}

int main(void) {
    char line[1024];
    for (;;) {
        ssize_t n = read_line(line, sizeof line);
        if (n <= 0) break;

        char *cmds[MAX_CMDS];
        int ncmds = split_commands(line, cmds);
        if (ncmds == 0) continue;

        char *argv[MAX_CMDS][MAX_ARGS];
        for (int i = 0; i < ncmds; i++) tokenize(cmds[i], argv[i]);
        if (ncmds == 1 && argv[0][0] == NULL) continue;
        if (ncmds == 1 && strcmp(argv[0][0], "exit") == 0) break;

        int pipes[MAX_CMDS][2];
        int ok = 1;
        for (int i = 0; i < ncmds - 1; i++) {
            if (pipe(pipes[i]) != 0) {
                perror("sh: pipe");
                ok = 0;
                break;
            }
        }
        if (!ok) continue;

        pid_t pids[MAX_CMDS];
        for (int i = 0; i < ncmds; i++) {
            pid_t pid = fork();
            if (pid < 0) {
                perror("sh: fork");
                pids[i] = -1;
                continue;
            }
            if (pid == 0) {
                if (i > 0) dup2(pipes[i - 1][0], 0);
                if (i < ncmds - 1) dup2(pipes[i][1], 1);
                for (int j = 0; j < ncmds - 1; j++) {
                    close(pipes[j][0]);
                    close(pipes[j][1]);
                }
                execve(argv[i][0], argv[i], NULL);
                perror("sh: exec");
                _exit(127);
            }
            pids[i] = pid;
        }
        for (int j = 0; j < ncmds - 1; j++) {
            close(pipes[j][0]);
            close(pipes[j][1]);
        }

        for (int i = 0; i < ncmds; i++) {
            int st = 0;
            if (pids[i] <= 0 || wait4(pids[i], &st, 0, NULL) < 0) continue;
            if (i == ncmds - 1) {
                if (WIFEXITED(st))
                    printf("sh: %s exited %d\n", argv[i][0], WEXITSTATUS(st));
                else if (WIFSIGNALED(st))
                    printf("sh: %s killed by signal %d\n", argv[i][0], WTERMSIG(st));
            }
        }
        fflush(stdout);
    }
    printf("sh: bye\n");
    return 0;
}
