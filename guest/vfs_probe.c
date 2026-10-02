static long sys_write(long fd, const char *buf, unsigned long len) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(1L), "D"(fd), "S"(buf), "d"(len) : "rcx", "r11", "memory");
    return ret;
}
static long sys_read(long fd, void *buf, unsigned long len) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(0L), "D"(fd), "S"(buf), "d"(len) : "rcx", "r11", "memory");
    return ret;
}
static long sys_openat(long dirfd, const char *path, long flags) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(257L), "D"(dirfd), "S"(path), "d"(flags) : "rcx", "r11", "memory");
    return ret;
}
static long sys_close(long fd) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(3L), "D"(fd) : "rcx", "r11", "memory");
    return ret;
}
static void sys_exit(int code) {
    __asm__ volatile("syscall" :: "a"(60L), "D"((long)code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static void putc(char c) { sys_write(1, &c, 1); }
static void putn(long v) {
    char b[24];
    int i = 0;
    if (v < 0) { putc('-'); v = -v; }
    if (v == 0) { putc('0'); return; }
    while (v) { b[i++] = (char)('0' + v % 10); v /= 10; }
    while (i) putc(b[--i]);
}

void _start(void) {
    char buf[128];
    putc('A');
    long fd = sys_openat(-100, "/motd", 0);
    putc('B'); putn(fd); putc('\n');
    if (fd >= 0) {
        long n = sys_read(fd, buf, sizeof(buf));
        putc('C'); putn(n); putc('\n');
        if (n > 0) sys_write(1, buf, (unsigned long)n);
        sys_close(fd);
    }
    sys_exit(0);
}
