/* Verifies that a SIGSYS handler can return normally under a seccomp filter:
 * does the kernel let rt_sigreturn through, or does returning from the handler
 * trap again? The handler emulates getpid() == 0 and steps over the syscall. */
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static void handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si;
    ucontext_t *u = (ucontext_t *)uc;
    u->uc_mcontext.gregs[REG_RAX] = 0;      /* getpid "returns" 0 */
    /* RIP is already past the syscall for a seccomp TRAP; do not adjust it. */
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("nnp"); return 1; }

    /* Allow write, exit, exit_group, rt_sigreturn; trap getpid.
     * 0 LD nr; 1..4 JEQ -> 6; 5 RET TRAP; 6 RET ALLOW. */
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigreturn, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = 7, .filter = f };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { perror("seccomp"); return 1; }

    fprintf(stderr, "about to call getpid\n");
    long r = syscall(SYS_getpid);
    fprintf(stderr, "getpid returned %ld (handler ran and we resumed)\n", r);
    return 0;
}
