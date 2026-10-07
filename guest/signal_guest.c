/* Signal delivery, as the guest sees it.
 *
 * Built on minic, our self-hosted C library, so every call here is a raw
 * `syscall` from a low address and is therefore trapped and serviced by the OS
 * under test. That matters: the seccomp filter passes syscalls made from high
 * addresses straight to the host, so a libc guest's `sigaction` and `raise`
 * would install and raise *host* signals and prove nothing about the mediated
 * layer.
 *
 * What is proved:
 *
 *   1. A handler is entered with the three C-ABI arguments, and a plain
 *      `return` out of it comes back through `rt_sigreturn`, resuming the
 *      guest. That round trip is the whole design: the frame written at
 *      delivery has to be the frame read back at return.
 *   2. A blocked signal waits rather than being lost, and is delivered when it
 *      is unblocked.
 *   3. A fault becomes a guest signal, with `si_addr` naming the address that
 *      faulted.
 *
 * The fault handler exits rather than returning, because returning to a
 * faulting instruction only faults again — on a real kernel too, which is why
 * anyone catching SIGSEGV for a bad access escapes instead of continuing.
 *
 * Built against minic rather than a real libc on purpose: glibc's `raise` uses
 * `tgkill`, and the seccomp filter lets a syscall from an address outside the
 * guest's text reach the host, so a glibc guest would be signalling the host and
 * testing nothing here.
 */
#include "minic.h"

static volatile unsigned long fault_expect;
static volatile int usr2_count;

static void on_fault(int signo, mysiginfo *si, myucontext *uc) {
    if (signo != SIGSEGV)
        puts("FAIL fault handler got the wrong signal number");
    else if (si == 0 || si->si_signo != SIGSEGV)
        puts("FAIL fault handler got no siginfo");
    else if (si->si_addr != fault_expect)
        puts("FAIL si_addr does not name the faulting address");
    else if (uc == 0)
        puts("FAIL fault handler got no ucontext");
    else if (uc_rip == 0)
        puts("FAIL ucontext has no instruction pointer");
    else
        puts("ok guest fault became a guest signal with the right si_addr");

    /* Returning would re-execute the faulting store, so the run ends here.
     * Reaching this line at all is what proves delivery happened. */
    _exit(0);
}

static void on_usr1(int signo, mysiginfo *si, myucontext *uc) {
    if (signo != SIGUSR1 || si == 0 || si->si_signo != SIGUSR1 || uc == 0)
        puts("FAIL usr1 handler arguments were wrong");
    else if (uc_rip == 0)
        puts("FAIL usr1 ucontext has no instruction pointer");
    else
        puts("ok handler ran with the right arguments");
    /* Plain return: `sigaction` filled in `sa_restorer`, so this lands on the
     * trampoline that issues `rt_sigreturn`. */
}

static void on_usr2(int signo, mysiginfo *si, myucontext *uc) {
    (void)signo;
    (void)si;
    (void)uc;
    usr2_count++;
}

/* Installs with `restorer` deliberately left zero, which is the case a real
 * kernel rejects and the OS has to make work. */
static int install(int signo, mysighandler_t fn) {
    mysigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.handler = fn;
    sa.flags = SA_SIGINFO;
    return sigaction(signo, &sa, 0);
}

int main(void) {
    unsigned long bit_usr2;
    char *page;

    /* --- 1. a handler that returns is resumed --- */
    if (install(SIGUSR1, on_usr1) != 0) {
        puts("FAIL could not install a SIGUSR1 handler");
        return 1;
    }
    if (raise_(SIGUSR1) != 0) {
        puts("FAIL raise(SIGUSR1) failed");
        return 1;
    }
    /* Being here means the handler ran and the return out of it came back
     * through rt_sigreturn, because nothing else resumes this line. */
    puts("ok handler returned through rt_sigreturn");

    /* --- 2. a blocked signal waits, then is delivered --- */
    if (install(SIGUSR2, on_usr2) != 0) {
        puts("FAIL could not install a SIGUSR2 handler");
        return 1;
    }
    bit_usr2 = 1UL << (SIGUSR2 - 1);
    if (sigprocmask(SIG_BLOCK, &bit_usr2, 0) != 0) {
        puts("FAIL could not block SIGUSR2");
        return 1;
    }
    if (raise_(SIGUSR2) != 0) {
        puts("FAIL raise(SIGUSR2) failed");
        return 1;
    }
    if (usr2_count != 0) {
        puts("FAIL a blocked signal was delivered anyway");
        return 1;
    }
    puts("ok blocked signal stayed pending");
    /* Unblocking runs nothing by itself: the pending signal is picked up at the
     * next syscall boundary, which is the only safe place to interrupt. */
    if (sigprocmask(SIG_UNBLOCK, &bit_usr2, 0) != 0) {
        puts("FAIL could not unblock SIGUSR2");
        return 1;
    }
    getpid();
    if (usr2_count != 1) {
        printf("FAIL handler ran %d times after unblocking\n", usr2_count);
        return 1;
    }
    puts("ok unblocking delivered the pending signal");

    /* --- 3. a fault reaches the guest's own handler --- */
    if (install(SIGSEGV, on_fault) != 0) {
        puts("FAIL could not install a SIGSEGV handler");
        return 1;
    }
    page = mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)page <= 0) {
        puts("FAIL mmap returned a bad address");
        return 1;
    }
    if (mprotect(page, 4096, PROT_READ) != 0) {
        puts("FAIL mprotect failed");
        return 1;
    }
    fault_expect = (unsigned long)page;
    /* Volatile so the store stays after the `fault_expect` write above: an
     * ordinary store to a page the compiler believes is writable may be moved
     * across a volatile one, since trapping is undefined behaviour. */
    *(volatile char *)page = 1; /* faults: the page is read-only */
    puts("FAIL the write was allowed, so nothing faulted");
    return 1;
}
