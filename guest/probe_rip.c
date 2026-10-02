/* Determines where the kernel leaves RIP for a seccomp TRAP.
 *
 * The handler prints the raw RIP from the ucontext, and does NOT advance it.
 *  - If the program traps again and again, RIP points at the syscall and the
 *    handler must skip it.
 *  - If getpid simply returns, RIP already points past the syscall.
 */
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

static long raw_write(int fd, const char *buf, unsigned long n)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(1L), "D"((long)fd), "S"(buf), "d"(n)
                     : "rcx", "r11", "memory");
    return ret;
}

static int put_hex(char *b, int i, unsigned long v)
{
    const char *hx = "0123456789abcdef";
    int shift;
    b[i++] = '0'; b[i++] = 'x';
    for (shift = (int)(sizeof(v) * 8) - 4; shift >= 0; shift -= 4)
        b[i++] = hx[(v >> shift) & 0xf];
    b[i++] = '\n';
    return i;
}

static int traps;

static void handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si;
    ucontext_t *u = (ucontext_t *)uc;
    char b[32];
    int i = put_hex(b, 0, (unsigned long)u->uc_mcontext.gregs[REG_RIP]);
    raw_write(2, b, (unsigned long)i);
    if (++traps >= 3) _exit(7);
    /* Deliberately do not touch RIP: observe whether it re-traps. */
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

    /* Allow write, exit, exit_group, rt_sigreturn; trap getpid. */
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

    long r = syscall(SYS_getpid);
    fprintf(stderr, "returned %ld\n", r);
    return 0;
}
