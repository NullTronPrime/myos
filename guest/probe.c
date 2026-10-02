/* Reports what the kernel delivers for a trapped syscall.
 *
 * The handler must be async-signal-safe: it cannot call stdio, because stdio
 * itself issues write() syscalls, which the filter traps again. So the handler
 * formats into a stack buffer with hand-rolled integer printing and writes it
 * with one raw syscall. */
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

/* Raw write that cannot re-enter the filter's handler path via stdio. */
static long raw_write(int fd, const char *buf, unsigned long n)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(1L), "D"((long)fd), "S"(buf), "d"(n)
                     : "rcx", "r11", "memory");
    return ret;
}

/* Minimal unsigned decimal printer; avoids stdio entirely. */
static int put(char *b, int i, char c)
{
    b[i] = c;
    return i + 1;
}

static int put_num(char *b, int i, unsigned long v)
{
    char tmp[24];
    int n = 0;
    if (v == 0) return put(b, i, '0');
    while (v) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n) b[i++] = tmp[--n];
    return i;
}

static void handler(int sig, siginfo_t *si, void *uc)
{
    (void)uc;
    char b[128];
    int i = 0;
    i = put(b, i, 's'); i = put(b, i, 'i'); i = put(b, i, '_');
    i = put_num(b, i, (unsigned long)si->si_signo);
    i = put(b, i, ' ');
    i = put(b, i, 'c'); i = put(b, i, 'o'); i = put(b, i, 'd'); i = put(b, i, 'e');
    i = put(b, i, '=');
    i = put_num(b, i, (unsigned long)si->si_code);
    i = put(b, i, ' ');
    i = put(b, i, 'e'); i = put(b, i, 'r'); i = put(b, i, 'r');
    i = put(b, i, 'n'); i = put(b, i, 'o'); i = put(b, i, '=');
    i = put_num(b, i, (unsigned long)si->si_errno);
    i = put(b, i, ' ');
    i = put(b, i, 's'); i = put(b, i, 'y'); i = put(b, i, 's');
    i = put(b, i, '=');
    i = put_num(b, i, (unsigned long)si->si_syscall);
    i = put(b, i, '\n');
    raw_write(2, b, (unsigned long)i);
    _exit(42);
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

    /* Allow write(2) only, so the handler's own report can get out. Everything
     * else traps, including the getpid below. */
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = 4, .filter = f };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { perror("seccomp"); return 1; }

    fprintf(stderr, "about to call getpid\n");
    long r = syscall(SYS_getpid);
    fprintf(stderr, "returned %ld, no trap happened\n", r);
    return 0;
}
