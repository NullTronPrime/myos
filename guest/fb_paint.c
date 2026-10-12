// Paints a couple of overlapping windows through the parasyteos display syscalls and
// asks the host to composite them. The host writes the frame as a PPM, which is
// how the offscreen display becomes observable in tests.
//
// Scenario (argv[1]):
//   stack (default) - B is created after A, so B composites on top of A
//   raise           - A is raised first, so A composites on top of B
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SYS_DISPLAY_INFO   0x1000
#define SYS_WINDOW_CREATE  0x1001
#define SYS_WINDOW_MAP     0x1002
#define SYS_WINDOW_PRESENT 0x1003
#define SYS_WINDOW_MOVE    0x1004
#define SYS_WINDOW_DESTROY 0x1005
#define SYS_DISPLAY_PRESENT 0x1006
#define SYS_WINDOW_RAISE   0x1007
#define SYS_WINDOW_DRAW_TEXT 0x1008

#define RED   0x00ff0000u
#define GREEN 0x0000ff00u

struct display_info {
    unsigned int width, height, stride, format;
};

struct window_info {
    unsigned long base;
    unsigned int width, height, stride, format;
};

static int die(const char *what) {
    perror(what);
    return 1;
}

int main(int argc, char **argv) {
    const char *scenario = argc > 1 ? argv[1] : "stack";

    struct display_info di;
    if ((long)syscall(SYS_DISPLAY_INFO, &di, 0, 0, 0, 0, 0) < 0) return die("display_info");
    if (di.width == 0 || di.height == 0) return 1;

    if (strcmp(scenario, "text") == 0) {
        long w = (long)syscall(SYS_WINDOW_CREATE, 24, 8, 0, 0, 0, 0);
        if (w < 0) return die("window_create text");
        struct window_info wi;
        unsigned long bw = (unsigned long)syscall(SYS_WINDOW_MAP, w, &wi, 0, 0, 0, 0);
        if ((long)bw < 0) return die("window_map text");
        unsigned int *p = (unsigned int *)bw;
        for (unsigned int i = 0; i < wi.width * wi.height; i++) p[i] = 0x00000000u;
        if ((long)syscall(SYS_WINDOW_MOVE, w, 2, 3, 0, 0, 0) < 0) return die("move text");
        if ((long)syscall(SYS_WINDOW_DRAW_TEXT, w, 0, 0, 0x00ffffff, 0x00000000, "Hi") < 0)
            return die("draw_text");
        if ((long)syscall(SYS_WINDOW_PRESENT, w, 0, 0, 0, 0, 0) < 0) return die("present text");
        if ((long)syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0) < 0) return die("display_present");
        if ((long)syscall(SYS_WINDOW_DESTROY, w, 0, 0, 0, 0, 0) < 0) return die("destroy text");
        return 0;
    }

    long a = (long)syscall(SYS_WINDOW_CREATE, 40, 30, 0, 0, 0, 0);
    if (a < 0) return die("window_create a");
    long b = (long)syscall(SYS_WINDOW_CREATE, 20, 20, 0, 0, 0, 0);
    if (b < 0) return die("window_create b");

    struct window_info wa, wb;
    unsigned long ba = (unsigned long)syscall(SYS_WINDOW_MAP, a, &wa, 0, 0, 0, 0);
    if ((long)ba < 0) return die("window_map a");
    unsigned long bb = (unsigned long)syscall(SYS_WINDOW_MAP, b, &wb, 0, 0, 0, 0);
    if ((long)bb < 0) return die("window_map b");
    if (ba == 0 || bb == 0) return 1;

    unsigned int *pa = (unsigned int *)ba;
    for (unsigned int i = 0; i < wa.width * wa.height; i++) pa[i] = RED;
    unsigned int *pb = (unsigned int *)bb;
    for (unsigned int i = 0; i < wb.width * wb.height; i++) pb[i] = GREEN;

    if ((long)syscall(SYS_WINDOW_MOVE, a, 0, 0, 0, 0, 0) < 0) return die("move a");
    if ((long)syscall(SYS_WINDOW_MOVE, b, 10, 10, 0, 0, 0) < 0) return die("move b");
    if (strcmp(scenario, "raise") == 0) {
        if ((long)syscall(SYS_WINDOW_RAISE, a, 0, 0, 0, 0, 0) < 0) return die("raise a");
    }
    if ((long)syscall(SYS_WINDOW_PRESENT, a, 0, 0, 0, 0, 0) < 0) return die("present a");
    if ((long)syscall(SYS_WINDOW_PRESENT, b, 0, 0, 0, 0, 0) < 0) return die("present b");
    if ((long)syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0) < 0) return die("display_present");

    if ((long)syscall(SYS_WINDOW_DESTROY, a, 0, 0, 0, 0, 0) < 0) return die("destroy a");
    if ((long)syscall(SYS_WINDOW_DESTROY, b, 0, 0, 0, 0, 0) < 0) return die("destroy b");
    return 0;
}
