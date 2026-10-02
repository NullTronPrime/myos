/* Child: issues a syscall (getpid) that the parent's filter traps. */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

int main(void)
{
    long r = syscall(SYS_getpid);
    fprintf(stderr, "child getpid returned %ld\n", r);
    return 0;
}
