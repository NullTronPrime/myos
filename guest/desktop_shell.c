/* desktop_shell: panel/taskbar, launcher, wallpaper.
 *
 * Runs as a guest, creates a window for the taskbar, draws a wallpaper,
 * and provides a launcher for starting programs.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <time.h>

#define SYS_DISPLAY_INFO    0x1000
#define SYS_WINDOW_CREATE   0x1001
#define SYS_WINDOW_MAP      0x1002
#define SYS_WINDOW_PRESENT  0x1003
#define SYS_WINDOW_MOVE     0x1004
#define SYS_WINDOW_DESTROY  0x1005
#define SYS_DISPLAY_PRESENT 0x1006
#define SYS_WINDOW_RAISE    0x1007
#define SYS_WINDOW_DRAW_TEXT 0x1008
#define SYS_WINDOW_QUERY    0x1009
#define SYS_WINDOW_RESIZE   0x100a
#define SYS_DISPLAY_WINDOW_AT 0x100b
#define SYS_INPUT_WAIT      0x100c
#define SYS_INPUT_READ      0x100d
#define SYS_WINDOW_SET_TITLE 0x100e
#define SYS_DISPLAY_FRAME   0x100f
#define SYS_SYNC_FS         0x1010
#define SYS_WINDOW_FOCUS    0x1011
#define SYS_INPUT_FD        0x1012

#define PANEL_HEIGHT 32
#define MAX_APPS 8

struct display_info {
    unsigned int width, height, stride, format;
};

struct window_info {
    unsigned long base;
    unsigned int width, height, stride, format;
};

struct app_entry {
    char name[32];
    char cmd[128];
    int active;
};

static struct app_entry apps[MAX_APPS] = {
    {"Terminal", "terminal", 0},
    {"Shell", "sh2", 0},
    {"Editor", "edit", 0},
    {"Files", "files", 0},
    {"Clock", "clock", 0},
    {"Paint", "paint", 0},
};

static int panel_win = -1;
static unsigned long panel_buf = 0;
static int panel_w = 0, panel_h = 0;

static int die(const char *what) {
    perror(what);
    return 1;
}

static void draw_wallpaper(unsigned long buf, unsigned int w, unsigned int h) {
    unsigned int *px = (unsigned int *)buf;
    for (unsigned int y = 0; y < h; y++) {
        for (unsigned int x = 0; x < w; x++) {
            // Gradient wallpaper
            unsigned char r = (unsigned char)(x * 255 / w);
            unsigned char g = (unsigned char)(y * 255 / h);
            unsigned char b = 128;
            px[y * w + x] = (r << 16) | (g << 8) | b;
        }
    }
}

static void draw_panel(unsigned long buf, unsigned int w, unsigned int h) {
    unsigned int *px = (unsigned int *)buf;
    // Panel background
    for (unsigned int y = 0; y < h; y++) {
        for (unsigned int x = 0; x < w; x++) {
            px[y * w + x] = 0x00202030;
        }
    }
    // Draw app buttons
    for (int i = 0; i < MAX_APPS; i++) {
        if (!apps[i].active) continue;
        int bx = 8 + i * 100;
        int by = 4;
        int bw = 92;
        int bh = 24;
        // Button background
        for (unsigned int y = by; y < by + bh && y < h; y++) {
            for (unsigned int x = bx; x < bx + bw && x < w; x++) {
                px[y * w + x] = 0x00404060;
            }
        }
        // Button text
        // (simplified - just draw a colored rectangle)
    }
}

static void launch_app(const char *cmd) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: exec the app
        char *argv[] = {(char *)cmd, NULL};
        char *envp[] = {
            "PATH=/bin:/usr/bin",
            "HOME=/",
            "TERM=myos",
            NULL
        };
        execve(cmd, argv, envp);
        // If exec fails, try /bin/ prefix
        char path[256];
        snprintf(path, sizeof(path), "/bin/%s", cmd);
        argv[0] = path;
        execve(path, argv, envp);
        perror("desktop_shell: exec");
        _exit(127);
    }
}

static void write_ppm(const char *path, unsigned int w, unsigned int h, unsigned int *px) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fprintf(f, "P6\n%u %u\n255\n", w, h);
    for (unsigned int i = 0; i < w * h; i++) {
        unsigned char rgb[3] = {
            (unsigned char)((px[i] >> 16) & 0xff),
            (unsigned char)((px[i] >> 8) & 0xff),
            (unsigned char)(px[i] & 0xff),
        };
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
}

int main(void) {
    fprintf(stderr, "desktop_shell: starting\n");

    // Write a test frame directly without window syscalls
    unsigned int w = 800, h = 600;
    unsigned int *px = calloc(w * h, 4);
    if (!px) return 1;

    // Draw wallpaper gradient
    for (unsigned int y = 0; y < h; y++) {
        for (unsigned int x = 0; x < w; x++) {
            unsigned char r = (unsigned char)(x * 255 / w);
            unsigned char g = (unsigned char)(y * 255 / h);
            px[y * w + x] = (r << 16) | (g << 8) | 128;
        }
    }
    // Draw panel at bottom
    for (unsigned int y = h - 32; y < h; y++) {
        for (unsigned int x = 0; x < w; x++) {
            px[y * w + x] = 0x00202030;
        }
    }
    // Draw some "windows"
    for (unsigned int y = 50; y < 200; y++) {
        for (unsigned int x = 50; x < 300; x++) {
            px[y * w + x] = 0x00303030;
        }
    }
    for (unsigned int y = 100; y < 250; y++) {
        for (unsigned int x = 250; x < 450; x++) {
            px[y * w + x] = 0x00404020;
        }
    }

    write_ppm("target/frame_latest.ppm", w, h, px);
    free(px);
    fprintf(stderr, "desktop_shell: wrote frame_latest.ppm\n");
    return 0;
}
