/* Checks that rt_sigaction refuses a handler with no `sa_restorer`.
 *
 * A handler returns to whatever `sa_restorer` held, so one with none has no way
 * back to where it was interrupted and a real kernel refuses the install rather
 * than building a frame the guest could never leave. This calls the syscall
 * directly instead of going through minic's `sigaction`, because that fills the
 * restorer in on the caller's behalf and would hide the difference.
 *
 * Built against minic on purpose: a glibc guest's `sigaction` also supplies a
 * restorer, and its `raise` reaches the host rather than this kernel.
 */
#include "minic.h"

/* minic exposes `errno` but not the values; this is the Linux one. */
#define EINVAL 22

static void handler(int signo, mysiginfo *si, myucontext *uc) {
    (void)signo;
    (void)si;
    (void)uc;
}

int main(void) {
    mysigaction bare;
    mysigaction with_restorer;
    int r;

    bare.handler = handler;
    bare.flags = SA_SIGINFO;
    bare.restorer = 0;
    bare.mask = 0;

    errno = 0;
    r = syscall(SYS_rt_sigaction, SIGUSR1, (long)&bare, 0, 8);
    if (r == -1 && errno == EINVAL)
        puts("ok rt_sigaction refused a handler with no restorer");
    else
        puts("FAIL rt_sigaction accepted a handler with no restorer");

    with_restorer = bare;
    with_restorer.restorer = (unsigned long)minic_sigreturn;
    r = syscall(SYS_rt_sigaction, SIGUSR1, (long)&with_restorer, 0, 8);
    if (r == 0)
        puts("ok rt_sigaction accepted a handler with one");
    else
        puts("FAIL rt_sigaction refused a handler with a restorer");

    return 0;
}
