/* terminal: a pty-based terminal emulator.
 *
 * Creates a pseudo-terminal, forks a shell on the slave side, reads output
 * from the master and renders it as text, and forwards keyboard input to the
 * master. Supports basic ANSI escape sequences (colors, cursor movement) and
 * scrolling.
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

#define SYS_OPENPT          340
#define SYS_GRANTPT         341
#define SYS_UNLOCKPT        342
#define SYS_PTSNAME         343
#define SYS_TCGETATTR       344
#define SYS_TCSETATTR       345
#define SYS_IOCTL_TIOCSCTTY 346
#define SYS_IOCTL_TIOCGWINSZ 347
#define SYS_IOCTL_TIOCSWINSZ 348

#define TERM_WIDTH  80
#define TERM_HEIGHT 24
#define CHAR_W 8
#define CHAR_H 8
#define SCROLLBACK 100

struct display_info {
    unsigned int width, height, stride, format;
};

struct window_info {
    unsigned long base;
    unsigned int width, height, stride, format;
};

struct term_cell {
    char ch;
    unsigned char fg;
    unsigned char bg;
};

static struct term_cell screen[TERM_HEIGHT][TERM_WIDTH];
static struct term_cell scrollback[SCROLLBACK][TERM_WIDTH];
static int scrollback_len = 0;
static int cursor_x = 0, cursor_y = 0;
static unsigned char cur_fg = 7, cur_bg = 0;
static int term_win = -1;
static unsigned long term_buf = 0;
static int master_fd = -1;
static pid_t child_pid = 0;
static int input_fd = -1;

static int die(const char *what) {
    perror(what);
    return 1;
}

static void term_clear(void) {
    for (int y = 0; y < TERM_HEIGHT; y++)
        for (int x = 0; x < TERM_WIDTH; x++) {
            screen[y][x].ch = ' ';
            screen[y][x].fg = 7;
            screen[y][x].bg = 0;
        }
    cursor_x = 0;
    cursor_y = 0;
}

static void term_scroll(void) {
    // Save top line to scrollback
    if (scrollback_len < SCROLLBACK) {
        memcpy(scrollback[scrollback_len], screen[0], sizeof(screen[0]));
        scrollback_len++;
    }
    // Shift screen up
    for (int y = 0; y < TERM_HEIGHT - 1; y++)
        memcpy(screen[y], screen[y + 1], sizeof(screen[0]));
    // Clear bottom line
    for (int x = 0; x < TERM_WIDTH; x++) {
        screen[TERM_HEIGHT - 1][x].ch = ' ';
        screen[TERM_HEIGHT - 1][x].fg = 7;
        screen[TERM_HEIGHT - 1][x].bg = 0;
    }
}

static void term_putc(char c) {
    if (c == '\n') {
        cursor_x = 0;
        cursor_y++;
        if (cursor_y >= TERM_HEIGHT) {
            term_scroll();
            cursor_y = TERM_HEIGHT - 1;
        }
    } else if (c == '\r') {
        cursor_x = 0;
    } else if (c == '\t') {
        cursor_x = (cursor_x + 8) & ~7;
        if (cursor_x >= TERM_WIDTH) cursor_x = TERM_WIDTH - 1;
    } else if (c >= 0x20 && c < 0x7f) {
        if (cursor_x >= TERM_WIDTH) {
            cursor_x = 0;
            cursor_y++;
            if (cursor_y >= TERM_HEIGHT) {
                term_scroll();
                cursor_y = TERM_HEIGHT - 1;
            }
        }
        screen[cursor_y][cursor_x].ch = c;
        screen[cursor_y][cursor_x].fg = cur_fg;
        screen[cursor_y][cursor_x].bg = cur_bg;
        cursor_x++;
    }
}

static void term_render(void) {
    if (!term_buf) return;
    unsigned int *px = (unsigned int *)term_buf;
    unsigned int w = TERM_WIDTH * CHAR_W;
    unsigned int h = TERM_HEIGHT * CHAR_H;
    // Clear to black
    for (unsigned int i = 0; i < w * h; i++) px[i] = 0;
    // Draw each cell
    for (int y = 0; y < TERM_HEIGHT; y++) {
        for (int x = 0; x < TERM_WIDTH; x++) {
            char c = screen[y][x].ch;
            if (c == ' ') continue;
            unsigned char fg = screen[y][x].fg;
            unsigned char bg = screen[y][x].bg;
            unsigned int fg_rgb = 0x00FFFFFF;
            unsigned int bg_rgb = 0x00000000;
            // Simple color mapping
            switch (fg) {
                case 0: fg_rgb = 0x00000000; break;
                case 1: fg_rgb = 0x00FF0000; break;
                case 2: fg_rgb = 0x0000FF00; break;
                case 3: fg_rgb = 0x00FFFF00; break;
                case 4: fg_rgb = 0x000000FF; break;
                case 5: fg_rgb = 0x00FF00FF; break;
                case 6: fg_rgb = 0x0000FFFF; break;
                default: fg_rgb = 0x00FFFFFF; break;
            }
            // Draw character using window draw syscall
            // Simplified: just draw a colored rectangle for each non-space cell
            for (int dy = 0; dy < CHAR_H; dy++) {
                for (int dx = 0; dx < CHAR_W; dx++) {
                    int sx = x * CHAR_W + dx;
                    int sy = y * CHAR_H + dy;
                    if (sx < (int)w && sy < (int)h) {
                        px[sy * w + sx] = fg_rgb;
                    }
                }
            }
        }
    }
    // Draw cursor
    for (int dy = 0; dy < CHAR_H; dy++) {
        int sx = cursor_x * CHAR_W;
        int sy = cursor_y * CHAR_H + dy;
        if (sx < (int)w && sy < (int)h) {
            px[sy * w + sx] = 0x00FFFFFF;
            px[sy * w + sx + 1] = 0x00FFFFFF;
        }
    }
}

static void handle_ansi(const char *buf, int len) {
    int i = 0;
    while (i < len) {
        if (buf[i] == '\x1b' && i + 1 < len && buf[i + 1] == '[') {
            // ANSI escape sequence
            int j = i + 2;
            while (j < len && buf[j] >= '0' && buf[j] <= '9') j++;
            if (j < len) {
                char cmd = buf[j];
                if (cmd == 'H') {
                    // Cursor home
                    cursor_x = 0;
                    cursor_y = 0;
                } else if (cmd == 'J') {
                    // Clear screen
                    term_clear();
                } else if (cmd == 'K') {
                    // Clear line
                    for (int x = cursor_x; x < TERM_WIDTH; x++) {
                        screen[cursor_y][x].ch = ' ';
                    }
                } else if (cmd == 'm') {
                    // Set attributes (simplified)
                    if (j > i + 2) {
                        int code = atoi(&buf[i + 2]);
                        if (code == 0) { cur_fg = 7; cur_bg = 0; }
                        else if (code >= 30 && code <= 37) cur_fg = code - 30;
                        else if (code >= 40 && code <= 47) cur_bg = code - 40;
                    }
                }
                i = j + 1;
            } else {
                i++;
            }
        } else {
            term_putc(buf[i]);
            i++;
        }
    }
}

int main(void) {
    struct display_info di;
    if ((long)syscall(SYS_DISPLAY_INFO, &di, 0, 0, 0, 0, 0) < 0) return die("display_info");
    if (di.width == 0 || di.height == 0) return 1;

    // Create a window for the terminal
    int win_w = TERM_WIDTH * CHAR_W;
    int win_h = TERM_HEIGHT * CHAR_H;
    term_win = (int)syscall(SYS_WINDOW_CREATE, win_w, win_h, 0, 0, 0, 0);
    if (term_win < 0) return die("window_create");
    struct window_info wi;
    term_buf = (unsigned long)syscall(SYS_WINDOW_MAP, term_win, &wi, 0, 0, 0, 0);
    if (term_buf == 0) return die("window_map");
    syscall(SYS_WINDOW_SET_TITLE, term_win, "Terminal", 0, 0, 0, 0);

    // Create a pty
    master_fd = (int)syscall(SYS_OPENPT, 0, 0, 0, 0, 0, 0);
    if (master_fd < 0) return die("openpt");
    if (syscall(SYS_GRANTPT, master_fd, 0, 0, 0, 0, 0) < 0) return die("grantpt");
    if (syscall(SYS_UNLOCKPT, master_fd, 0, 0, 0, 0, 0) < 0) return die("unlockpt");

    // Get input fd
    input_fd = (int)syscall(SYS_INPUT_FD, 0, 0, 0, 0, 0, 0);
    if (input_fd < 0) return die("input_fd");

    // Fork and exec shell on the slave side
    child_pid = fork();
    if (child_pid < 0) return die("fork");
    if (child_pid == 0) {
        // Child: become session leader and set up the slave
        setsid();
        char slave_path[256];
        if (syscall(SYS_PTSNAME, master_fd, slave_path, 0, 0, 0, 0) < 0) _exit(1);
        int slave_fd = open(slave_path, O_RDWR);
        if (slave_fd < 0) _exit(1);
        syscall(SYS_IOCTL_TIOCSCTTY, slave_fd, 0, 0, 0, 0, 0);
        dup2(slave_fd, 0);
        dup2(slave_fd, 1);
        dup2(slave_fd, 2);
        if (slave_fd > 2) close(slave_fd);
        // Set window size
        struct { unsigned short rows, cols, xpixel, ypixel; } ws = { TERM_HEIGHT, TERM_WIDTH, 0, 0 };
        syscall(SYS_IOCTL_TIOCSWINSZ, slave_fd, &ws, 0, 0, 0, 0);
        // Exec shell
        char *argv[] = {"sh2", NULL};
        char *envp[] = { "TERM=myos", "PATH=/bin:/usr/bin", NULL };
        execve("/bin/sh2", argv, envp);
        perror("terminal: exec");
        _exit(127);
    }

    // Parent: read from master, write to window; read from input, write to master
    term_clear();
    struct pollfd pfds[2];
    pfds[0].fd = master_fd; pfds[0].events = POLLIN;
    // Input fd is pollable too
    pfds[1].fd = input_fd; pfds[1].events = POLLIN;

    for (;;) {
        int ret = poll(pfds, 2, 100);
        if (ret <= 0) {
            // Timeout: render cursor blink
            term_render();
            syscall(SYS_WINDOW_PRESENT, term_win, 0, 0, 0, 0, 0, 0);
            continue;
        }

        // Read from master (shell output)
        if (pfds[0].revents & POLLIN) {
            char buf[4096];
            ssize_t n = read(master_fd, buf, sizeof(buf));
            if (n > 0) {
                handle_ansi(buf, (int)n);
                term_render();
                syscall(SYS_WINDOW_PRESENT, term_win, 0, 0, 0, 0, 0, 0);
            }
        }

        // Read from input (keyboard events)
        if (pfds[1].revents & POLLIN) {
            struct {
                unsigned int kind;
                unsigned int window;
                int x, y;
                unsigned int button;
                unsigned char mods;
                unsigned char text;
                unsigned int width, height;
            } event;
            ssize_t n = read(input_fd, &event, sizeof(event));
            if (n == (ssize_t)sizeof(event) && event.kind == 1) {
                // KeyDown event
                char c = (char)event.x;
                if (c >= 0x20 && c < 0x7f) {
                    write(master_fd, &c, 1);
                }
            }
        }

        // Reap child if it exited
        int status;
        if (waitpid(child_pid, &status, WNOHANG) > 0) {
            printf("terminal: shell exited\n");
            break;
        }
    }

    syscall(SYS_WINDOW_DESTROY, term_win, 0, 0, 0, 0, 0, 0);
    return 0;
}
