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
#include <sys/stat.h>
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

#define MAX_TABS 4

// Modifier bits, matching oscore::input::Mods bitmask.
#define MOD_SHIFT 1
#define MOD_CTRL 2
#define MOD_ALT 4

// Keysyms the host delivers for non-text keys (see osplat::display).
#define KEY_TAB 0xff09
#define KEY_NEXT 0xff54   /* Page Down */
#define KEY_PRIOR 0xff55 /* Page Up */

struct term_tab {
    struct term_cell screen[TERM_HEIGHT][TERM_WIDTH];
    struct term_cell scrollback[SCROLLBACK][TERM_WIDTH];
    int scrollback_len;
    int cursor_x, cursor_y;
    unsigned char cur_fg, cur_bg;
    int master_fd;
    pid_t child_pid;
    int active;
};

static struct term_tab tabs[MAX_TABS];
static int ntabs = 0;
static int curtab = 0;
static int term_win = -1;
static unsigned long term_buf = 0;
static int input_fd = -1;

static int die(const char *what) {
    perror(what);
    return 1;
}

static void term_clear(struct term_tab *t) {
    for (int y = 0; y < TERM_HEIGHT; y++)
        for (int x = 0; x < TERM_WIDTH; x++) {
            t->screen[y][x].ch = ' ';
            t->screen[y][x].fg = 7;
            t->screen[y][x].bg = 0;
        }
    t->cursor_x = 0;
    t->cursor_y = 0;
}

static void term_scroll(struct term_tab *t) {
    // Save top line to scrollback
    if (t->scrollback_len < SCROLLBACK) {
        memcpy(t->scrollback[t->scrollback_len], t->screen[0], sizeof(t->screen[0]));
        t->scrollback_len++;
    }
    // Shift screen up
    for (int y = 0; y < TERM_HEIGHT - 1; y++)
        memcpy(t->screen[y], t->screen[y + 1], sizeof(t->screen[0]));
    // Clear bottom line
    for (int x = 0; x < TERM_WIDTH; x++) {
        t->screen[TERM_HEIGHT - 1][x].ch = ' ';
        t->screen[TERM_HEIGHT - 1][x].fg = 7;
        t->screen[TERM_HEIGHT - 1][x].bg = 0;
    }
}

static void term_backspace(struct term_tab *t) {
    if (t->cursor_x > 0) {
        t->cursor_x--;
    } else if (t->cursor_y > 0) {
        t->cursor_y--;
        t->cursor_x = TERM_WIDTH - 1;
    } else {
        return;
    }
    t->screen[t->cursor_y][t->cursor_x].ch = ' ';
    t->screen[t->cursor_y][t->cursor_x].fg = 7;
    t->screen[t->cursor_y][t->cursor_x].bg = 0;
}

static void term_putc(struct term_tab *t, char c) {
    if (c == '\n') {
        t->cursor_x = 0;
        t->cursor_y++;
        if (t->cursor_y >= TERM_HEIGHT) {
            term_scroll(t);
            t->cursor_y = TERM_HEIGHT - 1;
        }
    } else if (c == '\r') {
        t->cursor_x = 0;
    } else if (c == '\b' || c == 0x7f) {
        term_backspace(t);
    } else if (c == '\t') {
        t->cursor_x = (t->cursor_x + 8) & ~7;
        if (t->cursor_x >= TERM_WIDTH) t->cursor_x = TERM_WIDTH - 1;
    } else if (c >= 0x20 && c < 0x7f) {
        if (t->cursor_x >= TERM_WIDTH) {
            t->cursor_x = 0;
            t->cursor_y++;
            if (t->cursor_y >= TERM_HEIGHT) {
                term_scroll(t);
                t->cursor_y = TERM_HEIGHT - 1;
            }
        }
        t->screen[t->cursor_y][t->cursor_x].ch = c;
        t->screen[t->cursor_y][t->cursor_x].fg = t->cur_fg;
        t->screen[t->cursor_y][t->cursor_x].bg = t->cur_bg;
        t->cursor_x++;
    }
}

static unsigned int fg_to_rgb(unsigned char fg) {
    switch (fg) {
        case 0: return 0x00000000;
        case 1: return 0x00FF0000;
        case 2: return 0x0000FF00;
        case 3: return 0x00FFFF00;
        case 4: return 0x000000FF;
        case 5: return 0x00FF00FF;
        case 6: return 0x0000FFFF;
        default: return 0x00FFFFFF;
    }
}

static void term_render(struct term_tab *t) {
    if (!term_buf) return;
    unsigned int *px = (unsigned int *)term_buf;
    unsigned int w = TERM_WIDTH * CHAR_W;
    unsigned int h = TERM_HEIGHT * CHAR_H;
    // Clear to black
    for (unsigned int i = 0; i < w * h; i++) px[i] = 0;
    // Draw each row as runs of equal foreground color through the
    // kernel's 8x8 text renderer, so glyphs (not color blocks) appear.
    char run[TERM_WIDTH + 1];
    for (int y = 0; y < TERM_HEIGHT; y++) {
        int x = 0;
        while (x < TERM_WIDTH) {
            // Skip trailing blanks: nothing to draw past the last glyph.
            int last = TERM_WIDTH - 1;
            while (last >= x && t->screen[y][last].ch == ' ') last--;
            if (last < x) break;
            unsigned char fg = t->screen[y][x].fg;
            int n = 0;
            while (x + n <= last && n < TERM_WIDTH &&
                   t->screen[y][x + n].fg == fg)
                n++;
            for (int k = 0; k < n; k++) run[k] = t->screen[y][x + k].ch;
            run[n] = '\0';
            syscall(SYS_WINDOW_DRAW_TEXT, term_win, x * CHAR_W, y * CHAR_H,
                    fg_to_rgb(fg), 0x00000000, run);
            x += n;
        }
    }
    // Draw cursor
    for (int dy = 0; dy < CHAR_H; dy++) {
        int sx = t->cursor_x * CHAR_W;
        int sy = t->cursor_y * CHAR_H + dy;
        if (sx < (int)w && sy < (int)h) {
            px[sy * w + sx] = 0x00FFFFFF;
            px[sy * w + sx + 1] = 0x00FFFFFF;
        }
    }
}

// Reflects the tab count in the window title, so the taskbar and the
// decorations show which tab is live.
static void update_title(void) {
    char title[32];
    if (ntabs <= 1)
        snprintf(title, sizeof(title), "Terminal");
    else
        snprintf(title, sizeof(title), "Terminal (%d/%d)", curtab + 1, ntabs);
    syscall(SYS_WINDOW_SET_TITLE, term_win, title, 0, 0, 0, 0);
}

// Spawns a shell on a fresh pty; returns the tab index or -1.
static int spawn_tab(void) {
    if (ntabs >= MAX_TABS) return -1;
    int master = (int)syscall(SYS_OPENPT, 0, 0, 0, 0, 0, 0);
    if (master < 0) return -1;
    if (syscall(SYS_GRANTPT, master, 0, 0, 0, 0, 0) < 0) return -1;
    if (syscall(SYS_UNLOCKPT, master, 0, 0, 0, 0, 0) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        // Child: become session leader and set up the slave.
        setsid();
        char slave_path[256];
        if (syscall(SYS_PTSNAME, master, slave_path, 0, 0, 0, 0) < 0) _exit(1);
        int slave_fd = open(slave_path, O_RDWR);
        if (slave_fd < 0) _exit(1);
        syscall(SYS_IOCTL_TIOCSCTTY, slave_fd, 0, 0, 0, 0, 0);
        dup2(slave_fd, 0);
        dup2(slave_fd, 1);
        dup2(slave_fd, 2);
        if (slave_fd > 2) close(slave_fd);
        struct { unsigned short rows, cols, xpixel, ypixel; } ws = { TERM_HEIGHT, TERM_WIDTH, 0, 0 };
        syscall(SYS_IOCTL_TIOCSWINSZ, slave_fd, &ws, 0, 0, 0, 0);
        char *argv[] = {"sh2", NULL};
        char *envp[] = { "TERM=myos", "PATH=/bin:/usr/bin", NULL };
        execve("/bin/sh2", argv, envp);
        perror("terminal: exec");
        _exit(127);
    }
    int idx = ntabs++;
    struct term_tab *t = &tabs[idx];
    memset(t, 0, sizeof(*t));
    t->master_fd = master;
    t->child_pid = pid;
    t->active = 1;
    t->cur_fg = 7;
    term_clear(t);
    if (ntabs == 1) curtab = 0;
    update_title();
    return idx;
}

// Closes a tab; closing the last tab ends the terminal.
static void close_tab(int idx) {
    if (idx < 0 || idx >= ntabs) return;
    close(tabs[idx].master_fd);
    // The shell observes the hangup from the host and exits; reap below.
    for (int i = idx; i + 1 < ntabs; i++) tabs[i] = tabs[i + 1];
    ntabs--;
    memset(&tabs[ntabs], 0, sizeof(tabs[ntabs]));
    if (curtab >= ntabs) curtab = ntabs - 1;
    if (curtab < 0) curtab = 0;
    update_title();
}

static void next_tab(void) {
    if (ntabs <= 1) return;
    curtab = (curtab + 1) % ntabs;
    update_title();
}

static void prev_tab(void) {
    if (ntabs <= 1) return;
    curtab = (curtab + ntabs - 1) % ntabs;
    update_title();
}

static int clamp_cursor(struct term_tab *t) {
    if (t->cursor_x < 0) t->cursor_x = 0;
    if (t->cursor_x >= TERM_WIDTH) t->cursor_x = TERM_WIDTH - 1;
    if (t->cursor_y < 0) t->cursor_y = 0;
    if (t->cursor_y >= TERM_HEIGHT) t->cursor_y = TERM_HEIGHT - 1;
    return 0;
}

// Parses ESC [ params cmd. Returns the command char, or 0 when the
// sequence is incomplete (caller passes the trailing bytes through).
// params[] holds up to 4 integers; *nparams counts them; *has_param is
// false for a bare ESC [ cmd with no digits.
static char parse_csi(const char *buf, int len, int *i, int *params, int *nparams, int *has_param) {
    int j = *i + 2;
    *nparams = 0;
    *has_param = 0;
    int cur = 0, digits = 0;
    while (j < len && ((buf[j] >= '0' && buf[j] <= '9') || buf[j] == ';')) {
        *has_param = 1;
        if (buf[j] == ';') {
            if (*nparams < 4) params[(*nparams)++] = digits ? cur : 0;
            cur = 0;
            digits = 0;
        } else {
            cur = cur * 10 + (buf[j] - '0');
            digits = 1;
        }
        j++;
    }
    if (*has_param && *nparams < 4) params[(*nparams)++] = cur;
    if (j >= len) return 0;
    *i = j + 1;
    return buf[j];
}

static void handle_ansi(struct term_tab *t, const char *buf, int len) {
    int i = 0;
    while (i < len) {
        if (buf[i] == '\x1b' && i + 1 < len && buf[i + 1] == '[') {
            int params[4] = {0, 0, 0, 0};
            int nparams = 0, has_param = 0;
            int at = i;
            char cmd = parse_csi(buf, len, &at, params, &nparams, &has_param);
            if (!cmd) {
                term_putc(t, buf[i]);
                i++;
                continue;
            }
            i = at;
            int p0 = nparams > 0 ? params[0] : 0;
            int p1 = nparams > 1 ? params[1] : 0;
            switch (cmd) {
            case 'A': // cursor up
                t->cursor_y -= has_param && p0 ? p0 : 1;
                clamp_cursor(t);
                break;
            case 'B': // cursor down
                t->cursor_y += has_param && p0 ? p0 : 1;
                clamp_cursor(t);
                break;
            case 'C': // cursor forward
                t->cursor_x += has_param && p0 ? p0 : 1;
                clamp_cursor(t);
                break;
            case 'D': // cursor back
                t->cursor_x -= has_param && p0 ? p0 : 1;
                clamp_cursor(t);
                break;
            case 'E': // next line
                t->cursor_x = 0;
                t->cursor_y += has_param && p0 ? p0 : 1;
                clamp_cursor(t);
                break;
            case 'F': // previous line
                t->cursor_x = 0;
                t->cursor_y -= has_param && p0 ? p0 : 1;
                clamp_cursor(t);
                break;
            case 'G': // horizontal absolute
                t->cursor_x = (has_param && p0 ? p0 : 1) - 1;
                clamp_cursor(t);
                break;
            case 'd': // vertical absolute
                t->cursor_y = (has_param && p0 ? p0 : 1) - 1;
                clamp_cursor(t);
                break;
            case 'H': // cursor position (default home)
                t->cursor_y = (nparams > 0 && p0 ? p0 : 1) - 1;
                t->cursor_x = (nparams > 1 && p1 ? p1 : 1) - 1;
                clamp_cursor(t);
                break;
            case 'J': // erase in display
                if (!has_param || p0 == 0) {
                    // Cursor to end of screen.
                    for (int y = t->cursor_y; y < TERM_HEIGHT; y++) {
                        int from = (y == t->cursor_y) ? t->cursor_x : 0;
                        for (int x = from; x < TERM_WIDTH; x++)
                            t->screen[y][x].ch = ' ';
                    }
                } else {
                    term_clear(t);
                }
                break;
            case 'K': // erase in line
                if (!has_param || p0 == 0) {
                    for (int x = t->cursor_x; x < TERM_WIDTH; x++)
                        t->screen[t->cursor_y][x].ch = ' ';
                } else if (p0 == 1) {
                    for (int x = 0; x <= t->cursor_x && x < TERM_WIDTH; x++)
                        t->screen[t->cursor_y][x].ch = ' ';
                } else {
                    for (int x = 0; x < TERM_WIDTH; x++)
                        t->screen[t->cursor_y][x].ch = ' ';
                }
                break;
            case 'm': { // attributes, possibly several separated by ';'
                if (!has_param) { t->cur_fg = 7; t->cur_bg = 0; break; }
                for (int k = 0; k < nparams; k++) {
                    int code = params[k];
                    if (code == 0) { t->cur_fg = 7; t->cur_bg = 0; }
                    else if (code == 1) { /* bold: ignored */ }
                    else if (code >= 30 && code <= 37) t->cur_fg = (unsigned char)(code - 30);
                    else if (code >= 40 && code <= 47) t->cur_bg = (unsigned char)(code - 40);
                }
                break;
            }
            default:
                break; // unknown: ignore
            }
        } else {
            term_putc(t, buf[i]);
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

    // Announce ourselves to the window server via the well-known path
    // (mirrors oscore::winserv::client_path). Best effort: the terminal
    // works standalone when the server is absent.
    mkdir("/winserv", 0755);
    mkdir("/winserv/clients", 0755);
    {
        char reg[64];
        snprintf(reg, sizeof(reg), "/winserv/clients/%d", (int)getpid());
        FILE *rf = fopen(reg, "w");
        if (rf) {
            fprintf(rf, "%d terminal\n", term_win);
            fclose(rf);
        }
    }

    // Get input fd
    input_fd = (int)syscall(SYS_INPUT_FD, 0, 0, 0, 0, 0, 0);
    if (input_fd < 0) return die("input_fd");

    // First tab; without it there is nothing to show.
    if (spawn_tab() < 0) return die("spawn_tab");

    // Parent: read from masters, write to window; read from input, write
    // to the active tab's master. Tabs: Ctrl+T new, Ctrl+W close,
    // Ctrl+PageUp/PageDown switch.
    for (;;) {
        struct pollfd pfds[MAX_TABS + 1];
        for (int i = 0; i < ntabs; i++) {
            pfds[i].fd = tabs[i].master_fd;
            pfds[i].events = POLLIN;
        }
        pfds[ntabs].fd = input_fd;
        pfds[ntabs].events = POLLIN;

        int ret = poll(pfds, ntabs + 1, 100);
        if (ret <= 0) {
            // Timeout: render cursor blink
            if (ntabs > 0) term_render(&tabs[curtab]);
            syscall(SYS_WINDOW_PRESENT, term_win, 0, 0, 0, 0, 0, 0);
            continue;
        }

        // Read from each master (shell output)
        for (int i = 0; i < ntabs; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;
            char buf[4096];
            ssize_t n = read(tabs[i].master_fd, buf, sizeof(buf));
            if (n > 0) {
                handle_ansi(&tabs[i], buf, (int)n);
                if (i == curtab) {
                    term_render(&tabs[i]);
                    syscall(SYS_WINDOW_PRESENT, term_win, 0, 0, 0, 0, 0, 0);
                }
            }
        }

        // Read from input (keyboard events addressed to our window)
        if (pfds[ntabs].revents & POLLIN) {
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
            if (n != (ssize_t)sizeof(event)) continue;
            if ((int)event.window != term_win) continue; // not ours
            if (event.kind == 8) break; // Close: exit cleanly
            if (event.kind != 1) continue; // KeyDown only
            if ((event.mods & MOD_CTRL) && event.x == 't') {
                if (spawn_tab() < 0)
                    term_render(&tabs[curtab]);
                else {
                    term_render(&tabs[curtab]);
                    syscall(SYS_WINDOW_PRESENT, term_win, 0, 0, 0, 0, 0, 0);
                }
                continue;
            }
            if ((event.mods & MOD_CTRL) && event.x == 'w') {
                close_tab(curtab);
                if (ntabs == 0) break; // last tab closed
                term_render(&tabs[curtab]);
                syscall(SYS_WINDOW_PRESENT, term_win, 0, 0, 0, 0, 0, 0);
                continue;
            }
            if ((event.mods & MOD_CTRL) &&
                (event.x == KEY_NEXT || event.x == KEY_PRIOR)) {
                if (event.x == KEY_NEXT) next_tab();
                else prev_tab();
                term_render(&tabs[curtab]);
                syscall(SYS_WINDOW_PRESENT, term_win, 0, 0, 0, 0, 0, 0);
                continue;
            }
            if (ntabs == 0) continue;
            // KeyDown event for the active tab; modifiers address
            // shortcuts above and never reach the shell as text.
            if (event.mods & (MOD_CTRL | MOD_ALT)) continue;
            char c = (char)event.x;
            int mfd = tabs[curtab].master_fd;
            if (c == '\r' || c == '\n') {
                char nl = '\n';
                write(mfd, &nl, 1);
            } else if (c == 0x08 || c == 0x7f) {
                write(mfd, &c, 1);
            } else if (c >= 0x20 && c < 0x7f) {
                write(mfd, &c, 1);
            }
        }

        // Reap shells that exited; drop their tabs (but never the last
        // visible one without breaking the loop below).
        for (int i = 0; i < ntabs; i++) {
            int status;
            pid_t r = waitpid(tabs[i].child_pid, &status, WNOHANG);
            if (r > 0) {
                printf("terminal: shell exited\n");
                close_tab(i);
                i--;
            }
        }
        if (ntabs == 0) break;
        // Keep the visible tab rendered after tab bookkeeping.
        term_render(&tabs[curtab]);
    }

    syscall(SYS_WINDOW_DESTROY, term_win, 0, 0, 0, 0, 0, 0);
    return 0;
}
