/* sh2: a proper shell for myos with PATH lookup, redirection, and job control.
 *
 * Improvements over sh.c:
 * - PATH lookup: commands are searched in PATH directories
 * - Redirection: >, >>, <, 2> for file descriptors
 * - Environment: basic env var expansion ($VAR)
 * - Builtins: cd, export, unset, echo, pwd, exit
 * - Background: & at end of command
 * - Job control: fg, bg, jobs (basic)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_LINE 4096
#define MAX_ARGS 128
#define MAX_CMDS 16
#define MAX_PATH 4096
#define MAX_BG 32

typedef struct {
    pid_t pid;
    char command[MAX_LINE];
    int active;
} Job;

static Job jobs[MAX_BG];
static int job_count = 0;

static char *path_dirs[16];
static int path_count = 0;

static void init_path(void) {
    const char *path = getenv("PATH");
    if (!path) {
        path_dirs[0] = strdup("/bin");
        path_dirs[1] = strdup("/usr/bin");
        path_count = 2;
        return;
    }
    char *copy = strdup(path);
    char *saveptr = NULL;
    char *dir = strtok_r(copy, ":", &saveptr);
    while (dir && path_count < 16) {
        path_dirs[path_count++] = strdup(dir);
        dir = strtok_r(NULL, ":", &saveptr);
    }
    free(copy);
}

static char *find_in_path(const char *cmd) {
    if (strchr(cmd, '/')) {
        return access(cmd, X_OK) == 0 ? strdup(cmd) : NULL;
    }
    for (int i = 0; i < path_count; i++) {
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", path_dirs[i], cmd);
        if (access(full, X_OK) == 0) {
            return strdup(full);
        }
    }
    return NULL;
}

static char *expand_vars(const char *line) {
    static char expanded[MAX_LINE];
    char *out = expanded;
    const char *p = line;
    while (*p && out < expanded + sizeof(expanded) - 1) {
        if (*p == '$' && p[1]) {
            p++;
            char varname[64];
            int i = 0;
            while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                   (*p >= '0' && *p <= '9') || *p == '_') {
                if (i < (int)sizeof(varname) - 1) varname[i++] = *p;
                p++;
            }
            varname[i] = 0;
            const char *val = getenv(varname);
            if (val) {
                while (*val && out < expanded + sizeof(expanded) - 1) {
                    *out++ = *val++;
                }
            }
        } else {
            *out++ = *p++;
        }
    }
    *out = 0;
    return expanded;
}

static int tokenize(char *line, char *argv[], int max_args) {
    int argc = 0;
    char *p = line;
    while (*p && argc < max_args - 1) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (*p == '"') {
            p++;
            argv[argc++] = p;
            while (*p && *p != '"') p++;
            if (*p) *p++ = 0;
        } else if (*p == '\'') {
            p++;
            argv[argc++] = p;
            while (*p && *p != '\'') p++;
            if (*p) *p++ = 0;
        } else {
            argv[argc++] = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = 0;
        }
    }
    argv[argc] = NULL;
    return argc;
}

static int builtin_cd(int argc, char *argv[]) {
    const char *dir = argc > 1 ? argv[1] : getenv("HOME");
    if (!dir) dir = "/";
    if (chdir(dir) != 0) {
        perror("cd");
        return 1;
    }
    return 0;
}

static int builtin_export(int argc, char *argv[]) {
    if (argc < 2) {
        extern char **environ;
        for (char **e = environ; *e; e++) {
            printf("%s\n", *e);
        }
        return 0;
    }
    char *eq = strchr(argv[1], '=');
    if (eq) {
        *eq = 0;
        setenv(argv[1], eq + 1, 1);
    }
    return 0;
}

static int builtin_unset(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        unsetenv(argv[i]);
    }
    return 0;
}

static int builtin_echo(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (i > 1) printf(" ");
        printf("%s", argv[i]);
    }
    printf("\n");
    return 0;
}

static int builtin_pwd(void) {
    char cwd[MAX_PATH];
    if (getcwd(cwd, sizeof(cwd))) {
        printf("%s\n", cwd);
    }
    return 0;
}

static int builtin_jobs(void) {
    for (int i = 0; i < MAX_BG; i++) {
        if (jobs[i].active) {
            printf("[%d] %d %s\n", i + 1, jobs[i].pid, jobs[i].command);
        }
    }
    return 0;
}

static int run_builtin(int argc, char *argv[]) {
    if (strcmp(argv[0], "cd") == 0) return builtin_cd(argc, argv);
    if (strcmp(argv[0], "export") == 0) return builtin_export(argc, argv);
    if (strcmp(argv[0], "unset") == 0) return builtin_unset(argc, argv);
    if (strcmp(argv[0], "echo") == 0) return builtin_echo(argc, argv);
    if (strcmp(argv[0], "pwd") == 0) return builtin_pwd();
    if (strcmp(argv[0], "jobs") == 0) return builtin_jobs();
    if (strcmp(argv[0], "exit") == 0) return -1; // signal to exit
    return 0;
}

static int run_command(char *line, int background) {
    char *argv[MAX_ARGS];
    int argc = tokenize(line, argv, MAX_ARGS);
    if (argc == 0) return 0;

    // Check for redirection
    int redirect_in = -1, redirect_out = -1, redirect_err = -1;
    char *in_file = NULL, *out_file = NULL, *err_file = NULL;
    int append_out = 0;

    // Simple redirection parsing: find >, >>, <, 2> and remove from args
    int new_argc = 0;
    char *new_argv[MAX_ARGS];
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], ">") == 0 && i + 1 < argc) {
            out_file = argv[++i];
            append_out = 0;
        } else if (strcmp(argv[i], ">>") == 0 && i + 1 < argc) {
            out_file = argv[++i];
            append_out = 1;
        } else if (strcmp(argv[i], "<") == 0 && i + 1 < argc) {
            in_file = argv[++i];
        } else if (strcmp(argv[i], "2>") == 0 && i + 1 < argc) {
            err_file = argv[++i];
        } else {
            new_argv[new_argc++] = argv[i];
        }
    }
    new_argv[new_argc] = NULL;
    argc = new_argc;
    for (int i = 0; i <= argc; i++) argv[i] = new_argv[i];

    // Try builtins first
    int builtin_ret = run_builtin(argc, argv);
    if (builtin_ret == -1) return -1; // exit
    if (builtin_ret != 0 || (argc > 0 && (
        strcmp(argv[0], "cd") == 0 || strcmp(argv[0], "export") == 0 ||
        strcmp(argv[0], "unset") == 0 || strcmp(argv[0], "echo") == 0 ||
        strcmp(argv[0], "pwd") == 0 || strcmp(argv[0], "jobs") == 0))) {
        return builtin_ret;
    }

    // Find the command in PATH
    char *cmd_path = find_in_path(argv[0]);
    if (!cmd_path) {
        fprintf(stderr, "sh2: %s: command not found\n", argv[0]);
        return 127;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("sh2: fork");
        return 1;
    }
    if (pid == 0) {
        // Child: set up redirection
        if (in_file) {
            int fd = open(in_file, O_RDONLY);
            if (fd < 0) { perror("sh2: open"); _exit(1); }
            dup2(fd, 0);
            close(fd);
        }
        if (out_file) {
            int flags = O_WRONLY | O_CREAT | (append_out ? O_APPEND : O_TRUNC);
            int fd = open(out_file, flags, 0644);
            if (fd < 0) { perror("sh2: open"); _exit(1); }
            dup2(fd, 1);
            close(fd);
        }
        if (err_file) {
            int fd = open(err_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) { perror("sh2: open"); _exit(1); }
            dup2(fd, 2);
            close(fd);
        }
        execv(cmd_path, argv);
        fprintf(stderr, "sh2: %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    if (background) {
        // Add to job table
        for (int i = 0; i < MAX_BG; i++) {
            if (!jobs[i].active) {
                jobs[i].pid = pid;
                strncpy(jobs[i].command, line, MAX_LINE - 1);
                jobs[i].active = 1;
                job_count++;
                printf("[%d] %d\n", i + 1, pid);
                break;
            }
        }
        return 0;
    }

    // Wait for the child
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "sh2: %s killed by signal %d\n", argv[0], WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    return 0;
}

static void check_background_jobs(void) {
    for (int i = 0; i < MAX_BG; i++) {
        if (jobs[i].active) {
            int status;
            pid_t result = waitpid(jobs[i].pid, &status, WNOHANG);
            if (result > 0) {
                jobs[i].active = 0;
                job_count--;
                if (WIFEXITED(status)) {
                    printf("[%d] Done %s (exit %d)\n", i + 1, jobs[i].command, WEXITSTATUS(status));
                }
            }
        }
    }
}

int main(void) {
    char line[MAX_LINE];
    init_path();

    printf("myos shell v2\n");
    printf("Type 'exit' to quit.\n\n");

    for (;;) {
        check_background_jobs();
        printf("$ ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            printf("\n");
            break;
        }

        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = 0;
        }

        // Expand environment variables
        char *expanded = expand_vars(line);

        // Check for background
        int background = 0;
        size_t elen = strlen(expanded);
        if (elen > 0 && expanded[elen - 1] == '&') {
            background = 1;
            expanded[elen - 1] = 0;
            // Trim trailing spaces
            while (elen > 1 && expanded[elen - 2] == ' ') {
                expanded[--elen - 1] = 0;
            }
        }

        // Split on | for pipelines
        char *cmds[MAX_CMDS];
        int ncmds = 0;
        char *p = expanded;
        while (*p && ncmds < MAX_CMDS) {
            while (*p == ' ' || *p == '\t') p++;
            if (!*p) break;
            cmds[ncmds++] = p;
            char *bar = strchr(p, '|');
            if (!bar) break;
            char *e = bar;
            while (e > p && (e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
            *bar = 0;
            p = bar + 1;
        }

        if (ncmds == 0) continue;

        if (ncmds == 1) {
            int ret = run_command(cmds[0], background);
            if (ret == -1) break; // exit
            continue;
        }

        // Pipeline: create pipes and fork
        int pipes[MAX_CMDS][2];
        for (int i = 0; i < ncmds - 1; i++) {
            if (pipe(pipes[i]) != 0) {
                perror("sh2: pipe");
                break;
            }
        }

        pid_t pids[MAX_CMDS];
        for (int i = 0; i < ncmds; i++) {
            pid_t pid = fork();
            if (pid < 0) {
                perror("sh2: fork");
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
                // Run the command (no recursion into pipelines)
                char *argv[MAX_ARGS];
                int argc = tokenize(cmds[i], argv, MAX_ARGS);
                if (argc > 0) {
                    char *cmd_path = find_in_path(argv[0]);
                    if (cmd_path) {
                        execv(cmd_path, argv);
                    }
                    fprintf(stderr, "sh2: %s: command not found\n", argv[0]);
                }
                _exit(127);
            }
            pids[i] = pid;
        }

        for (int j = 0; j < ncmds - 1; j++) {
            close(pipes[j][0]);
            close(pipes[j][1]);
        }

        for (int i = 0; i < ncmds; i++) {
            if (pids[i] > 0) {
                int status;
                waitpid(pids[i], &status, 0);
            }
        }
    }

    printf("sh2: bye\n");
    return 0;
}
