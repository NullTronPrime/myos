/* Does execve preserve a SIGSYS handler? Parent installs handler + seccomp
 * filter, then execs a child that issues a trapped syscall. */
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static void handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si; (void)uc;
    const char *m = "HANDLER-SURVIVED-EXEC\n";
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(1L), "D"(2L), "S"(m), "d"(21L)
                     : "rcx", "r11", "memory");
    _exit(42);
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <child>\n", argv[0]); return 2; }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("nnp"); return 1; }

    /* Allow write, exit, exit_group, execve; trap getpid.
     * Layout: 0 LD nr; 1..4 JEQ -> 6; 5 RET TRAP; 6 RET ALLOW. */
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = 7, .filter = f };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { perror("seccomp"); return 1; }

    execv(argv[1], &argv[1]);
    perror("execv");
    return 127;
}
