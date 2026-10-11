/* input_test: verifies mouse/keyboard events reach the guest.
 *
 * Creates a small window, then polls the input fd and prints every event
 * it receives. On a button press it draws a marker in the window so the
 * frame output also shows the interaction happened.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#define SYS_DISPLAY_INFO    0x1000
#define SYS_WINDOW_CREATE   0x1001
#define SYS_WINDOW_MAP      0x1002
#define SYS_WINDOW_PRESENT  0x1003
#define SYS_WINDOW_MOVE     0x1004
#define SYS_DISPLAY_PRESENT 0x1006
#define SYS_WINDOW_SET_TITLE 0x100e
#define SYS_INPUT_FD        0x1012

struct display_info {
    unsigned int width, height, stride, format;
};

struct window_info {
    unsigned long base;
    unsigned int width, height, stride, format;
};

struct input_event {
    unsigned int kind, window;
    int x, y;
    unsigned int button;
    unsigned char mods, text;
    unsigned int width, height;
};

static long draw_count = 0;

static void fill_window(unsigned long buf, unsigned int w, unsigned int h,
                        unsigned char r, unsigned char g, unsigned char b) {
    unsigned int *px = (unsigned int *)buf;
    for (unsigned int y = 0; y < h; y++)
        for (unsigned int x = 0; x < w; x++)
            px[y * w + x] = (r << 16) | (g << 8) | b;
}

int main(void) {
    struct display_info di;
    if ((long)syscall(SYS_DISPLAY_INFO, &di, 0, 0, 0, 0, 0) < 0) return 1;
    fprintf(stderr, "input_test: display %ux%u\n", di.width, di.height);

    int win = (int)syscall(SYS_WINDOW_CREATE, 400, 300, 100, 100, 0, 0);
    if (win < 0) { fprintf(stderr, "input_test: window_create failed\n"); return 1; }
    struct window_info wi;
    unsigned long buf = (unsigned long)syscall(SYS_WINDOW_MAP, win, &wi, 0, 0, 0, 0);
    if (buf == 0) { fprintf(stderr, "input_test: window_map failed\n"); return 1; }
    syscall(SYS_WINDOW_SET_TITLE, win, "input_test", 0, 0, 0, 0);
    syscall(SYS_WINDOW_PRESENT, win, 0, 0, 0, 0, 0);

    fill_window(buf, wi.width, wi.height, 40, 40, 60);
    syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0);
    fprintf(stderr, "input_test: window at 100,100 size 400x300\n");

    long fd = syscall(SYS_INPUT_FD, 0, 0, 0, 0, 0, 0);
    if (fd < 0) { fprintf(stderr, "input_test: input_fd failed\n"); return 1; }

    struct pollfd pfd = { .fd = (int)fd, .events = POLLIN };

    for (int i = 0; i < 200; i++) {
        int ret = poll(&pfd, 1, 50);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            struct input_event ev;
            ssize_t n = read((int)fd, &ev, sizeof(ev));
            if (n == (ssize_t)sizeof(ev)) {
                fprintf(stderr,
                    "input_test: EVENT kind=%u win=%u x=%d y=%d btn=%u mods=%u text=%u\n",
                    ev.kind, ev.window, ev.x, ev.y, ev.button, ev.mods, ev.text);
                /* kind 3 = button press: flash green, kind 4 = release: back to base */
                if (ev.kind == 3) {
                    fill_window(buf, wi.width, wi.height, 0, 200, 0);
                    syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0);
                    draw_count++;
                } else if (ev.kind == 4) {
                    fill_window(buf, wi.width, wi.height, 40, 40, 60);
                    syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0);
                }
            }
        }
    }
    fprintf(stderr, "input_test: done, %ld button presses\n", draw_count);
    return 0;
}
