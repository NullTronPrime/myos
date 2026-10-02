/* Validates the IP-gating idea: a seccomp filter can distinguish the guest
 * (mapped low) from the kernel (mapped high) by the high word of
 * seccomp_data.instruction_pointer.
 *
 * The low page holds a hand-written getpid stub. The filter traps every syscall
 * whose instruction pointer is below 4 GiB. So the stub must trap while every
 * libc call (high) passes through. */
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define LOW 0x400000UL

static volatile int trapped;

static void handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)uc;
    trapped++;
    /* Report what the kernel thinks the syscall address is. */
    fprintf(stderr, "trapped: syscall=%d ip=%p\n",
            si->si_syscall, si->si_call_addr);
    /* Make getpid "return" a distinctive value and resume. RIP is already
     * past the syscall for a TRAP. */
    ((ucontext_t *)uc)->uc_mcontext.gregs[REG_RAX] = 0xabc;
}

int main(void)
{
    void *p = mmap((void *)LOW, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p != (void *)LOW) { perror("mmap low"); return 1; }

    /* mov eax, 39 ; syscall ; ret */
    unsigned char stub[] = { 0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xc3 };
    memcpy(p, stub, sizeof stub);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("nnp"); return 1; }

    /* ip high != 0 -> ALLOW ; ip high == 0 -> TRAP.
     * 0 LD [12]; 1 JEQ 0 jt=1 jf=0; 2 RET ALLOW; 3 RET TRAP. */
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };
    struct sock_fprog prog = { .len = 4, .filter = f };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { perror("seccomp"); return 1; }

    long (*low_getpid)(void) = (long (*)(void))p;
    long r1 = low_getpid();
    fprintf(stderr, "low stub returned %#lx (want 0xabc)\n", r1);

    long r2 = syscall(SYS_getpid);
    fprintf(stderr, "libc getpid returned %ld (real: no trap)\n", r2);

    return (r1 == 0xabc && trapped == 1) ? 0 : 2;
}
