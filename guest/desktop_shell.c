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
#include <dirent.h>

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
#define SYS_DISPLAY_WINDOWS 0x1013
#define SYS_WINDOW_MINIMIZE 0x1014
#define SYS_WINDOW_LOWER    0x1015
#define SYS_WINDOW_GET_TITLE 0x1016

#define PANEL_HEIGHT 32
#define MAX_APPS 8
#define MAX_WINBTN 32

// Alt+Tab switcher: KeyDown for XK_Tab with the Alt modifier bit.
#define EV_KEYDOWN 1
#define KEY_TAB 0xff09
#define MOD_ALT 4

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
    {"Terminal", "terminal", 1},
    {"Shell", "sh2", 1},
    {"Browser", "browser", 1},
    {"Files", "files", 0},
    {"Clock", "clock", 0},
    {"Paint", "paint", 0},
};

static int panel_win = -1;
static unsigned long panel_buf = 0;
static int panel_w = 0, panel_h = 0;

// Own windows for Alt+Tab, refreshed with the panel redraw. Untitled
// windows (wallpaper) and the panel itself are not browsable entries.
static unsigned int win_ids[MAX_WINBTN];
static int nwin = 0;
static int winbtn_x0 = 0;
static int focused_win = -1;

static void refresh_window_list(void) {
    unsigned int ids[MAX_WINBTN];
    long n = syscall(SYS_DISPLAY_WINDOWS, ids, MAX_WINBTN, 0, 0, 0, 0);
    focused_win = (int)syscall(SYS_WINDOW_FOCUS, 0xffffffffUL, 0, 0, 0, 0, 0);
    nwin = 0;
    if (n < 0) return;
    if (n > MAX_WINBTN) n = MAX_WINBTN;
    for (long i = 0; i < n; i++) {
        if ((int)ids[i] == panel_win) continue;
        char title[64];
        if (syscall(SYS_WINDOW_GET_TITLE, ids[i], title, sizeof(title), 0, 0, 0) <= 0)
            continue;
        win_ids[nwin++] = ids[i];
    }
}

#define MAX_CENSUS 8

// Other processes' apps, discovered through the well-known registry that
// terminal.c and browser.c announce themselves in. This is a census, not
// control: windows in other processes live in other address spaces (see
// ROADMAP §2.2), so entries are display-only.
static char cen_names[MAX_CENSUS][32];
static int ncen = 0;

static void refresh_census(void) {
    ncen = 0;
    DIR *d = opendir("/winserv/clients");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && ncen < MAX_CENSUS) {
        if (e->d_name[0] == '.') continue;
        char path[160];
        snprintf(path, sizeof(path), "/winserv/clients/%s", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[96];
        if (fgets(line, sizeof(line), f)) {
            /* "<winid> <name>"; name optional for old writers. */
            char *sp = strchr(line, ' ');
            if (sp) {
                sp[1 + strcspn(sp + 1, "\r\n")] = '\0';
                snprintf(cen_names[ncen], sizeof(cen_names[ncen]), "%s", sp + 1);
            } else {
                snprintf(cen_names[ncen], sizeof(cen_names[ncen]), "pid%s", e->d_name);
            }
            if (cen_names[ncen][0]) ncen++;
        }
        fclose(f);
    }
    closedir(d);
}

static void cycle_focus(void) {
    unsigned int ids[MAX_WINBTN];
    long n = syscall(SYS_DISPLAY_WINDOWS, ids, MAX_WINBTN, 0, 0, 0, 0);
    if (n <= 1) return;
    if (n > MAX_WINBTN) n = MAX_WINBTN;
    long cur = syscall(SYS_WINDOW_FOCUS, 0xffffffffUL, 0, 0, 0, 0, 0);
    long at = 0;
    for (long i = 0; i < n; i++) {
        if ((long)ids[i] == cur) {
            at = i;
            break;
        }
    }
    // Skip our own panel and wallpaper: focus the next foreign window.
    for (long k = 1; k <= n; k++) {
        long cand = ids[(at + k) % n];
        if ((int)cand == panel_win) continue;
        syscall(SYS_WINDOW_FOCUS, cand, 0, 0, 0, 0, 0);
        syscall(SYS_WINDOW_RAISE, cand, 0, 0, 0, 0, 0);
        break;
    }
}

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
    // Census entries (other processes' apps), right of the launcher.
    // Only active launchers occupy space; inactive slots collapse.
    winbtn_x0 = 8;
    for (int i = 0; i < MAX_APPS; i++) {
        if (apps[i].active) winbtn_x0 += 100;
    }
    for (int i = 0; i < ncen; i++) {
        int bx = winbtn_x0 + i * 100;
        if (bx + 92 > (int)w) break; // clip: no room for another entry
        int by = 4;
        int bw = 92;
        int bh = 24;
        for (unsigned int y = by; y < by + bh && y < h; y++) {
            for (unsigned int x = bx; x < bx + bw && x < w; x++) {
                px[y * w + x] = 0x00303048;
            }
        }
    }
}

static void launch_app(const char *cmd) {
    pid_t pid = fork();
    if (pid > 0) {
        fprintf(stderr, "desktop_shell: launch %s pid %d\n", cmd, (int)pid);
    }
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

int main(void) {
    struct display_info di;
    if ((long)syscall(SYS_DISPLAY_INFO, &di, 0, 0, 0, 0, 0) < 0) return die("display_info");
    if (di.width == 0 || di.height == 0) {
        fprintf(stderr, "desktop_shell: no display\n");
        return 1;
    }

    // Wallpaper window (full screen, bottom of z-order)
    long wall_win = syscall(SYS_WINDOW_CREATE, di.width, di.height, 0, 0, 0, 0);
    if (wall_win < 0) return die("window_create wallpaper");
    struct window_info wall_info;
    unsigned long wall_buf = (unsigned long)syscall(SYS_WINDOW_MAP, wall_win, &wall_info, 0, 0, 0, 0);
    if (wall_buf == 0) return die("window_map wallpaper");
    draw_wallpaper(wall_buf, wall_info.width, wall_info.height);
    syscall(SYS_WINDOW_PRESENT, wall_win, 0, 0, 0, 0, 0);

    // Panel window (bottom of the screen, on top of the wallpaper)
    panel_w = di.width;
    panel_h = PANEL_HEIGHT;
    panel_win = (int)syscall(SYS_WINDOW_CREATE, panel_w, panel_h, 0, 0, 0, 0);
    if (panel_win < 0) return die("window_create panel");
    struct window_info panel_info;
    panel_buf = (unsigned long)syscall(SYS_WINDOW_MAP, panel_win, &panel_info, 0, 0, 0, 0);
    if (panel_buf == 0) return die("window_map panel");
    syscall(SYS_WINDOW_MOVE, panel_win, 0, di.height - PANEL_HEIGHT, 0, 0, 0);
    syscall(SYS_WINDOW_SET_TITLE, panel_win, "myos panel", 0, 0, 0, 0);
    draw_panel(panel_buf, panel_info.width, panel_info.height);
    syscall(SYS_WINDOW_PRESENT, panel_win, 0, 0, 0, 0, 0);

    // Composite every visible window into one frame. The kernel writes
    // it to MYOS_FB_OUT (or pushes it to the real window) when this
    // syscall returns.
    long pr = syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0);
    fprintf(stderr, "desktop_shell: display_present returned %ld\n", pr);
    fprintf(stderr, "desktop_shell: %dx%d, first frame presented\n", di.width, di.height);

    // Input loop: the kernel pumps host events into this fd.
    long input_fd = syscall(SYS_INPUT_FD, 0, 0, 0, 0, 0, 0);
    if (input_fd < 0) return die("input_fd");

    struct pollfd pfd = { .fd = (int)input_fd, .events = POLLIN };
    int frame_counter = 0;
    for (;;) {
        int ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            struct {
                unsigned int kind, window;
                int x, y;
                unsigned int button;
                unsigned char mods, text;
                unsigned int width, height;
            } event;
            if (read((int)input_fd, &event, sizeof(event)) == (ssize_t)sizeof(event)) {
                // Alt+Tab cycles focus across open windows.
                if (event.kind == EV_KEYDOWN && event.x == KEY_TAB &&
                    (event.mods & MOD_ALT)) {
                    cycle_focus();
                }
                // kind 3 is a mouse button press
                if (event.kind == 3 && event.y >= (int)di.height - PANEL_HEIGHT) {
                    int btn = (event.x - 8) / 100;
                    if (btn >= 0 && btn < MAX_APPS && apps[btn].active) {
                        launch_app(apps[btn].cmd);
                    }
                    /* Census entries are display-only: their windows live
                     * in other processes and cannot be focused from here. */
                }
            }
        }
        if (frame_counter % 30 == 0) {
            refresh_window_list();
            refresh_census();
            draw_panel(panel_buf, panel_info.width, panel_info.height);
            // App labels through the kernel's 8x8 text renderer.
            for (int i = 0; i < MAX_APPS; i++) {
                if (!apps[i].active) continue;
                syscall(SYS_WINDOW_DRAW_TEXT, panel_win, 8 + i * 100 + 6, 12,
                        0x00FFFFFF, 0xffffffffL, apps[i].name);
            }
            // Census names next to the launcher block.
            for (int i = 0; i < ncen; i++) {
                int bx = winbtn_x0 + i * 100;
                if (bx + 92 > (int)panel_info.width) break;
                char label[14];
                snprintf(label, sizeof(label), "*%.10s", cen_names[i]);
                syscall(SYS_WINDOW_DRAW_TEXT, panel_win, bx + 6, 12,
                        0x0000FF00, 0xffffffffL, label);
            }
            // Clock at the right edge (guest gettimeofday is dispatched).
            {
                time_t now = time(NULL);
                struct tm *tm = gmtime(&now);
                char clock[16];
                if (tm)
                    snprintf(clock, sizeof(clock), "%02d:%02d:%02d",
                             tm->tm_hour, tm->tm_min, tm->tm_sec);
                else
                    snprintf(clock, sizeof(clock), "--:--:--");
                syscall(SYS_WINDOW_DRAW_TEXT, panel_win,
                        (int)panel_info.width - 80, 12,
                        0x00FFFF00, 0xffffffffL, clock);
            }
            syscall(SYS_WINDOW_PRESENT, panel_win, 0, 0, 0, 0, 0);
            syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0);
        }
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0) {}
        frame_counter++;
    }
    return 0;
}
