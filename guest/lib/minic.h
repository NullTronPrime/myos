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
