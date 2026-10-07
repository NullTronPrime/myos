/* minic: the myos self-hosted C library.
 *
 * Guests built with `-nostdlib` link against this instead of glibc, so they run
 * with no host libc and no dynamic linker. Only the pieces our guests actually
 * use are provided; everything bottoms out in a raw `syscall` that myos traps
 * and services. */
#ifndef MINIC_H
#define MINIC_H

#include <stddef.h>
#include <stdarg.h>

typedef long ssize_t;
typedef long off_t;
typedef int pid_t;

/* x86-64 Linux syscall numbers used here. */
#define SYS_read      0
#define SYS_write     1
#define SYS_open      2
#define SYS_close     3
#define SYS_mmap      9
#define SYS_mprotect  10
#define SYS_munmap    11
#define SYS_brk       12
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn 15
#define SYS_ioctl     16
#define SYS_writev    20
#define SYS_pipe      22
#define SYS_dup       32
#define SYS_dup2      33
#define SYS_getpid    39
#define SYS_fork      57
#define SYS_execve    59
#define SYS_exit      60
#define SYS_wait4     61
#define SYS_kill      62
#define SYS_openat    257

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2
#define O_CREAT  0100
#define O_TRUNC  01000
#define O_APPEND 02000

#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20

/* The single syscall entry point, with glibc's variadic shape so existing
 * `syscall(SYS_..., ...)` call sites just work. Returns -1 and sets `errno` on
 * failure. */
long syscall(long n, ...);

void _exit(int code) __attribute__((noreturn));
void exit(int code) __attribute__((noreturn));
void abort(void) __attribute__((noreturn));

ssize_t write(int fd, const void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count);
int close(int fd);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int mprotect(void *addr, size_t len, int prot);
void *brk(void *addr);
int open(const char *path, int flags, ...);
int getpid(void);
pid_t fork(void);
int execve(const char *path, char *const argv[], char *const envp[]);
pid_t wait4(pid_t pid, int *status, int options, void *rusage);
int pipe(int fds[2]);
int dup2(int oldfd, int newfd);

/* --- signals -----------------------------------------------------------
 *
 * The OS owns signal delivery, so these are the mediated calls rather than the
 * host's. `mysigaction` is the kernel's own `struct sigaction`; leaving
 * `restorer` zero is allowed here, because the OS synthesises one and an
 * ordinary `return` out of the handler comes back through `rt_sigreturn`. */
#define SA_SIGINFO 0x00000004

#define SIG_BLOCK   0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define SIGHUP  1
#define SIGINT  2
#define SIGQUIT 3
#define SIGILL  4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS  7
#define SIGFPE  8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15

/* The leading fields of `siginfo_t`, which is much larger. `addr` carries the
 * faulting address for SIGSEGV and the sender's pid for a raised signal. */
typedef struct mysiginfo {
    int si_signo;
    int si_errno;
    int si_code;
    int __pad;
    unsigned long si_addr;
} mysiginfo;

/* `ucontext_t` up to the register file. Only `uc_mcontext.gregs` is named here;
 * `gregs[16]` is `rip`. */
typedef struct myucontext {
    unsigned long uc_flags;
    unsigned long uc_link;
    unsigned long uc_stack[3];
    unsigned long gregs[23];
} myucontext;

#define uc_rip (uc->gregs[16])

typedef void (*mysighandler_t)(int, mysiginfo *, myucontext *);

/* The two dispositions that are not a handler address. The trailing underscore
 * keeps them from colliding with the same macros from a real `<signal.h>`. */
#define SIG_DFL_ ((mysighandler_t)0)
#define SIG_IGN_ ((mysighandler_t)1)

typedef struct mysigaction {
    mysighandler_t handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
} mysigaction;

int sigaction(int signum, const mysigaction *act, mysigaction *old);
int sigprocmask(int how, const unsigned long *set, unsigned long *old);
int kill(pid_t pid, int signo);

/* `sa_restorer` for handlers installed through `sigaction`. A handler returns
 * to this, which issues `rt_sigreturn`; a real handler cannot do without one,
 * so `sigaction` fills it in when the caller left it zero. */
void minic_sigreturn(void);

/* `raise(signo)`, spelled with a trailing underscore because glibc's
 * `<signal.h>` declares `raise` as `noreturn` and a guest that pulls in both
 * headers would otherwise disagree about the same name. */
int raise_(int signo);

size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strcat(char *dst, const char *src);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

int atoi(const char *s);
void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

int puts(const char *s);
int putchar(int c);
int printf(const char *fmt, ...);
int snprintf(char *buf, size_t cap, const char *fmt, ...);
int perror(const char *s);

extern int errno;

#endif /* MINIC_H */
