/* minic: implementations. See minic.h. */
#include "minic.h"

int errno;

long syscall(long n, ...) {
    va_list ap;
    va_start(ap, n);
    long a = va_arg(ap, long);
    long b = va_arg(ap, long);
    long c = va_arg(ap, long);
    long d = va_arg(ap, long);
    long e = va_arg(ap, long);
    long f = va_arg(ap, long);
    va_end(ap);

    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    if (ret < 0 && ret >= -4095) {
        errno = (int)-ret;
        return -1;
    }
    return ret;
}

void _exit(int code) {
    syscall(SYS_exit, code);
    for (;;) {
    }
}

void exit(int code) {
    _exit(code);
}

void abort(void) {
    _exit(134);
}

ssize_t write(int fd, const void *buf, size_t count) {
    return syscall(SYS_write, fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    return syscall(SYS_read, fd, buf, count);
}

int close(int fd) {
    return (int)syscall(SYS_close, fd);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    return (void *)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
}

int mprotect(void *addr, size_t len, int prot) {
    return (int)syscall(SYS_mprotect, addr, len, prot);
}

void *brk(void *addr) {
    return (void *)syscall(SYS_brk, addr);
}

int open(const char *path, int flags, ...) {
    int mode = 0;
    /* Only O_CREAT consumes a mode argument; reading one otherwise would pull a
     * value the caller never passed. */
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

int getpid(void) {
    return (int)syscall(SYS_getpid);
}

pid_t fork(void) {
    return (pid_t)syscall(SYS_fork);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    return (int)syscall(SYS_execve, path, argv, envp);
}

pid_t wait4(pid_t pid, int *status, int options, void *rusage) {
    return (pid_t)syscall(SYS_wait4, pid, status, options, rusage);
}

int pipe(int fds[2]) {
    return (int)syscall(SYS_pipe, fds);
}

int dup2(int oldfd, int newfd) {
    return (int)syscall(SYS_dup2, oldfd, newfd);
}

/* Signals. Each of these is serviced by the OS rather than the host, so a guest
 * built against minic gets the same delivery, blocking and frame semantics as
 * one built against a real libc -- which is what makes the two comparable. */

int sigaction(int signum, const mysigaction *act, mysigaction *old) {
    /* A handler returns to `sa_restorer`, which has to issue `rt_sigreturn`, so
     * an install without one is refused. Rather than make every guest spell it
     * out, fill in the one this library ships, the way a real libc does. The
     * caller's copy is left alone because it is const. */
    mysigaction patched;
    if (act != 0) {
        patched = *act;
        if (patched.handler != SIG_DFL_ && patched.handler != SIG_IGN_ &&
            patched.restorer == 0) {
            patched.restorer = (unsigned long)minic_sigreturn;
        }
        act = &patched;
    }
    /* The trailing argument is the size of the mask, which the kernel's
     * x86-64 ABI fixes at eight bytes. Passing it is required: the OS reads the
     * action through it to decide what to install. */
    return (int)syscall(SYS_rt_sigaction, signum, (long)act, (long)old, 8);
}

int sigprocmask(int how, const unsigned long *set, unsigned long *old) {
    return (int)syscall(SYS_rt_sigprocmask, how, (long)set, (long)old, 8);
}

int kill(pid_t pid, int signo) {
    return (int)syscall(SYS_kill, pid, signo);
}

int raise_(int signo) {
    /* One guest per process, so "me" is always the right pid. */
    return kill(getpid(), signo);
}

size_t strlen(const char *s) {
    const char *p = s;
    while (*p) {
        p++;
    }
    return (size_t)(p - s);
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
        }
        if (a[i] == 0) {
            return 0;
        }
    }
    return 0;
}

char *strcpy(char *dst, const char *src) {
    char *r = dst;
    while ((*dst++ = *src++)) {
    }
    return r;
}

char *strncpy(char *dst, const char *src, size_t n) {
    size_t i = 0;
    for (; i < n && src[i]; i++) {
        dst[i] = src[i];
    }
    for (; i < n; i++) {
        dst[i] = 0;
    }
    return dst;
}

char *strcat(char *dst, const char *src) {
    char *r = dst;
    while (*dst) {
        dst++;
    }
    while ((*dst++ = *src++)) {
    }
    return r;
}

char *strchr(const char *s, int c) {
    for (; *s; s++) {
        if (*s == (char)c) {
            return (char *)s;
        }
    }
    return c == 0 ? (char *)s : 0;
}

char *strrchr(const char *s, int c) {
    const char *last = 0;
    for (; *s; s++) {
        if (*s == (char)c) {
            last = s;
        }
    }
    if (c == 0) {
        return (char *)s;
    }
    return (char *)last;
}

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d < s) {
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else if (d > s) {
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    for (size_t i = 0; i < n; i++) {
        d[i] = (unsigned char)c;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a;
    const unsigned char *y = b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) {
            return (int)x[i] - (int)y[i];
        }
    }
    return 0;
}

int atoi(const char *s) {
    int sign = 1;
    long v = 0;
    while (*s == ' ' || *s == '\t' || *s == '\n') {
        s++;
    }
    if (*s == '-') {
        sign = -1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return (int)(sign * v);
}

/* A bump allocator over anonymous mappings. `free` is a no-op; guests here are
 * short-lived, and this keeps the implementation small and dependency-free. */
#define HEAP_CHUNK (1u << 20)
static unsigned char *heap;
static unsigned char *heap_end;

void *malloc(size_t size) {
    size = (size + 15) & ~(size_t)15;
    if (size == 0) {
        size = 16;
    }
    if (!heap || heap + size > heap_end) {
        size_t chunk = size < HEAP_CHUNK ? HEAP_CHUNK : size;
        long p = syscall(SYS_mmap, 0, chunk, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p < 0) {
            return 0;
        }
        heap = (unsigned char *)p;
        heap_end = heap + chunk;
    }
    void *r = heap;
    heap += size;
    return r;
}

void free(void *ptr) {
    (void)ptr;
}

void *calloc(size_t count, size_t size) {
    size_t total = count * size;
    void *p = malloc(total);
    if (p) {
        memset(p, 0, total);
    }
    return p;
}

void *realloc(void *ptr, size_t size) {
    void *p = malloc(size);
    if (p && ptr) {
        memcpy(p, ptr, size);
    }
    return p;
}

/* Formatting. A sink callback lets printf and snprintf share one formatter. */
typedef void (*sink_fn)(void *ctx, int ch);

/* `base` is 8, 10 or 16. Constant divisors and shifts keep this free of the
 * libgcc 64-bit division helpers, which `-nostdlib` does not link. */
static void emit_uint(sink_fn sink, void *ctx, unsigned long v, unsigned base, int upper) {
    char tmp[32];
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else if (base == 16) {
        while (v) {
            tmp[n++] = digits[v & 0xf];
            v >>= 4;
        }
    } else if (base == 8) {
        while (v) {
            tmp[n++] = digits[v & 7];
            v >>= 3;
        }
    } else {
        while (v) {
            tmp[n++] = digits[v % 10u];
            v /= 10u;
        }
    }
    while (n > 0) {
        sink(ctx, tmp[--n]);
    }
}

static void vfmt(sink_fn sink, void *ctx, const char *fmt, va_list ap) {
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            sink(ctx, *p);
            continue;
        }
        p++;
        int is_long = 0;
        while (*p == 'l' || *p == 'z') {
            is_long = 1;
            p++;
        }
        while (*p == 'h') {
            p++;
        }
        switch (*p) {
        case '%':
            sink(ctx, '%');
            break;
        case 'c':
            sink(ctx, va_arg(ap, int));
            break;
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) {
                s = "(null)";
            }
            while (*s) {
                sink(ctx, *s++);
            }
            break;
        }
        case 'd':
        case 'i': {
            long v = is_long ? va_arg(ap, long) : (long)va_arg(ap, int);
            if (v < 0) {
                sink(ctx, '-');
                emit_uint(sink, ctx, (unsigned long)(-(v + 1)) + 1, 10, 0);
            } else {
                emit_uint(sink, ctx, (unsigned long)v, 10, 0);
            }
            break;
        }
        case 'u': {
            unsigned long v = is_long ? va_arg(ap, unsigned long)
                                      : (unsigned long)va_arg(ap, unsigned);
            emit_uint(sink, ctx, v, 10, 0);
            break;
        }
        case 'x': {
            unsigned long v = is_long ? va_arg(ap, unsigned long)
                                      : (unsigned long)va_arg(ap, unsigned);
            emit_uint(sink, ctx, v, 16, 0);
            break;
        }
        case 'X': {
            unsigned long v = is_long ? va_arg(ap, unsigned long)
                                      : (unsigned long)va_arg(ap, unsigned);
            emit_uint(sink, ctx, v, 16, 1);
            break;
        }
        case 'p':
            sink(ctx, '0');
            sink(ctx, 'x');
            emit_uint(sink, ctx, (unsigned long)va_arg(ap, void *), 16, 0);
            break;
        default:
            sink(ctx, '%');
            sink(ctx, *p);
            break;
        }
    }
}

struct fd_ctx {
    int fd;
    char buf[256];
    size_t n;
};

static void fd_sink(void *ctx, int ch) {
    struct fd_ctx *o = ctx;
    if (o->n == sizeof(o->buf)) {
        write(o->fd, o->buf, o->n);
        o->n = 0;
    }
    o->buf[o->n++] = (char)ch;
}

static void fd_flush(struct fd_ctx *o) {
    if (o->n) {
        write(o->fd, o->buf, o->n);
        o->n = 0;
    }
}

int printf(const char *fmt, ...) {
    struct fd_ctx o = {1, {0}, 0};
    va_list ap;
    va_start(ap, fmt);
    vfmt(fd_sink, &o, fmt, ap);
    va_end(ap);
    fd_flush(&o);
    return 0;
}

struct buf_ctx {
    char *buf;
    size_t cap;
    size_t n;
};

static void buf_sink(void *ctx, int ch) {
    struct buf_ctx *o = ctx;
    if (o->n + 1 < o->cap) {
        o->buf[o->n] = (char)ch;
    }
    o->n++;
}

int snprintf(char *buf, size_t cap, const char *fmt, ...) {
    struct buf_ctx o = {buf, cap, 0};
    va_list ap;
    va_start(ap, fmt);
    vfmt(buf_sink, &o, fmt, ap);
    va_end(ap);
    if (cap) {
        buf[o.n < cap ? o.n : cap - 1] = 0;
    }
    return (int)o.n;
}

int puts(const char *s) {
    size_t n = strlen(s);
    write(1, s, n);
    write(1, "\n", 1);
    return 0;
}

int putchar(int c) {
    char ch = (char)c;
    write(1, &ch, 1);
    return c;
}

int perror(const char *s) {
    if (s && *s) {
        printf("%s: ", s);
    }
    printf("error %d\n", errno);
    return 0;
}
