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
#include <sys/stat.h>

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
#define SYS_DISPLAY_XID     0x1017

#define PANEL_HEIGHT 32
#define MAX_APPS 8
#define MAX_WINBTN 32
/* Taskbar grid: launcher pill occupies x<72, app slots are 100px wide. */
#define SLOT_X0 72

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
static int wall_win = -1;
static unsigned int disp_w = 0, disp_h = 0;
static struct window_info panel_info;

/* App index occupying a visible slot (inactive apps collapse, so slot !=
 * index once anything is off). -1 when the slot is empty. */
static int app_at_slot(int slot) {
    int s = 0;
    for (int i = 0; i < MAX_APPS; i++) {
        if (!apps[i].active) continue;
        if (s == slot) return i;
        s++;
    }
    return -1;
}

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

static void draw_wallpaper(unsigned long buf, unsigned int w, unsigned int h);
static void draw_panel(unsigned long buf, unsigned int w, unsigned int h);

/* (Re)builds wallpaper + panel for a WxH desktop: used at startup and
 * when the host resizes the window (ConfigureNotify arrives as kind 9).
 * Old windows are destroyed; their mappings leak until exit, one per
 * resize, which a toy desktop accepts. Returns 0 or -1. */
static int build_desktop(unsigned int w, unsigned int h) {
    if (w < 320 || h < 200 || w > 2048 || h > 2048) return -1;
    if (wall_win >= 0) syscall(SYS_WINDOW_DESTROY, wall_win, 0, 0, 0, 0, 0);
    if (panel_win >= 0) syscall(SYS_WINDOW_DESTROY, panel_win, 0, 0, 0, 0, 0);
    disp_w = w;
    disp_h = h;
    // Wallpaper window (full screen, bottom of z-order)
    wall_win = (int)syscall(SYS_WINDOW_CREATE, w, h, 0, 0, 0, 0);
    if (wall_win < 0) return die("window_create wallpaper");
    struct window_info wall_info;
    unsigned long wall_buf = (unsigned long)syscall(SYS_WINDOW_MAP, wall_win, &wall_info, 0, 0, 0, 0);
    if (wall_buf == 0) return die("window_map wallpaper");
    draw_wallpaper(wall_buf, wall_info.width, wall_info.height);
    syscall(SYS_WINDOW_PRESENT, wall_win, 0, 0, 0, 0, 0);

    // Panel window (bottom of the screen, on top of the wallpaper)
    panel_w = (int)w;
    panel_h = PANEL_HEIGHT;
    panel_win = (int)syscall(SYS_WINDOW_CREATE, panel_w, panel_h, 0, 0, 0, 0);
    if (panel_win < 0) return die("window_create panel");
    panel_buf = (unsigned long)syscall(SYS_WINDOW_MAP, panel_win, &panel_info, 0, 0, 0, 0);
    if (panel_buf == 0) return die("window_map panel");
    syscall(SYS_WINDOW_MOVE, panel_win, 0, (int)h - PANEL_HEIGHT, 0, 0, 0);
    syscall(SYS_WINDOW_SET_TITLE, panel_win, "parasyteos panel", 0, 0, 0, 0);
    draw_panel(panel_buf, panel_info.width, panel_info.height);
    syscall(SYS_WINDOW_PRESENT, panel_win, 0, 0, 0, 0, 0);
    /* Publish the app area so embedded windows can follow resizes. */
    {
        FILE *f = fopen("/winserv/desktop/geom", "w");
        if (f) {
            unsigned int ah = h > PANEL_HEIGHT ? h - PANEL_HEIGHT : h;
            fprintf(f, "%ux%u\n", w, ah);
            fclose(f);
        }
    }
    fprintf(stderr, "desktop_shell: desktop %ux%u\n", w, h);
    return 0;
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

/* Pixel helpers: rounded tiles like a modern dock. Corners are cut by
 * skipping a radius-r square at each corner (r=0 is a plain rect). */
static void tile(unsigned int *px, unsigned int w, unsigned int h,
                 int x0, int y0, int bw, int bh, int r, unsigned int color) {
    for (int y = 0; y < bh; y++) {
        for (int x = 0; x < bw; x++) {
            int cx = x < r ? r - 1 - x : (x >= bw - r ? x - (bw - r) : -1);
            int cy = y < r ? r - 1 - y : (y >= bh - r ? y - (bh - r) : -1);
            if (cx >= 0 && cy >= 0 && cx * cx + cy * cy >= r * r) continue;
            int sx = x0 + x, sy = y0 + y;
            if (sx >= 0 && sy >= 0 && (unsigned)sx < w && (unsigned)sy < h)
                px[sy * w + sx] = color;
        }
    }
}

/* Per-app tile colors (icon-ish, Brave-dock style). */
static unsigned int app_color(const char *name) {
    if (strcmp(name, "Browser") == 0) return 0x00FB542B; /* brave orange */
    if (strcmp(name, "Terminal") == 0) return 0x004A4A4A; /* gray square */
    if (strcmp(name, "Shell") == 0) return 0x002E7D32;    /* green */
    if (strcmp(name, "Files") == 0) return 0x00C09800;    /* folder yellow */
    if (strcmp(name, "Clock") == 0) return 0x005C6BC0;    /* muted blue */
    if (strcmp(name, "Paint") == 0) return 0x008E24AA;    /* purple */
    return 0x00404060;
}

static void draw_panel(unsigned long buf, unsigned int w, unsigned int h) {
    unsigned int *px = (unsigned int *)buf;
    /* Bar background: dark dock gray. */
    for (unsigned int y = 0; y < h; y++) {
        for (unsigned int x = 0; x < w; x++) {
            px[y * w + x] = 0x00323232;
        }
    }
    /* Launcher pill with a 2x2 grid glyph. */
    tile(px, w, h, 8, 4, 56, 24, 8, 0x00444444);
    tile(px, w, h, 20, 10, 6, 6, 1, 0x00DDDDDD);
    tile(px, w, h, 28, 10, 6, 6, 1, 0x00DDDDDD);
    tile(px, w, h, 20, 18, 6, 6, 1, 0x00DDDDDD);
    tile(px, w, h, 28, 18, 6, 6, 1, 0x00DDDDDD);
    /* App tiles: icon block + running underline. Slots share the 100px
     * grid the click hit-test uses (SLOT_X0 + slot*100). */
    int nslots = 0;
    for (int slot = 0; ; slot++) {
        int i = app_at_slot(slot);
        if (i < 0) break;
        int bx = SLOT_X0 + slot * 100;
        if (bx + 92 > (int)w) break;
        nslots = slot + 1;
        tile(px, w, h, bx, 4, 40, 24, 5, app_color(apps[i].name));
        /* Running indicator: census name matches this app. */
        for (int c = 0; c < ncen; c++) {
            if (strcasecmp(cen_names[c], apps[i].name) == 0) {
                tile(px, w, h, bx + 6, 26, 28, 3, 1, 0x004C8DFF);
                break;
            }
        }
    }
    // Census entries (other processes' apps), right of the launcher.
    // Only active launchers occupy space; inactive slots collapse.
    winbtn_x0 = SLOT_X0 + nslots * 100;
    for (int i = 0; i < ncen; i++) {
        int bx = winbtn_x0 + i * 100;
        if (bx + 92 > (int)w) break; // clip: no room for another entry
        tile(px, w, h, bx, 4, 40, 24, 5, 0x00262626);
    }
}

/* Reads the published outer-window id for embedding, or -1. */
static long desktop_xid(void) {
    FILE *f = fopen("/winserv/desktop/xid", "r");
    if (!f) return -1;
    long xid = -1;
    if (fscanf(f, "%li", &xid) != 1) xid = -1;
    fclose(f);
    return xid;
}

static void launch_app(const char *cmd) {
    pid_t pid = fork();
    if (pid > 0) {
        fprintf(stderr, "desktop_shell: launch %s pid %d\n", cmd, (int)pid);
    }
    if (pid == 0) {
        // Child: exec the app
        char *argv[] = {(char *)cmd, NULL};
        char embed_parent[64];
        char *envp[8];
        int ne = 0;
        envp[ne++] = "PATH=/bin:/usr/bin";
        envp[ne++] = "HOME=/";
        envp[ne++] = "TERM=parasyteos";
        /* The browser lives INSIDE the desktop window: its outer X
         * window reparents into ours (one OS window on the host),
         * sized to the area above the panel. */
        if (strcmp(cmd, "browser") == 0) {
            long xid = desktop_xid();
            if (xid > 0) {
                snprintf(embed_parent, sizeof(embed_parent),
                         "PARASYTEOS_EMBED_PARENT=%li", xid);
                envp[ne++] = embed_parent;
                /* Guest model and host window must agree exactly: any
                 * mismatch sends every frame down the resize path. */
                envp[ne++] = "PARASYTEOS_WIDTH=640";
                envp[ne++] = "PARASYTEOS_HEIGHT=448";
                envp[ne++] = "PARASYTEOS_DISPLAY=640x448";
            }
        }
        envp[ne] = NULL;
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

    disp_w = di.width;
    disp_h = di.height;
    if (build_desktop(disp_w, disp_h) < 0) return 1;

    // Composite every visible window into one frame. The kernel writes
    // it to PARASYTEOS_FB_OUT (or pushes it to the real window) when this
    // syscall returns.
    long pr = syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0);
    fprintf(stderr, "desktop_shell: display_present returned %ld\n", pr);
    fprintf(stderr, "desktop_shell: %dx%d, first frame presented\n", di.width, di.height);

    /* Publish the outer window id so apps can embed into this window. */
    {
        long xid = syscall(SYS_DISPLAY_XID, 0, 0, 0, 0, 0, 0);
        if (xid > 0) {
            mkdir("/winserv", 0755);
            mkdir("/winserv/desktop", 0755);
            FILE *f = fopen("/winserv/desktop/xid", "w");
            if (f) {
                fprintf(f, "%li\n", xid);
                fclose(f);
            }
        }
    }

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
                // kind 9 is a host resize: rebuild for the new size.
                if (event.kind == 9 && event.width >= 320 && event.height >= 200) {
                    if (build_desktop(event.width, event.height) == 0)
                        frame_counter = 29; /* redraw on the next pass */
                }
                // kind 3 is a mouse button press
                if (event.kind == 3 && event.y >= (int)disp_h - PANEL_HEIGHT) {
                    int slot = (event.x - SLOT_X0) / 100;
                    int ai = slot >= 0 ? app_at_slot(slot) : -1;
                    if (ai >= 0) {
                        launch_app(apps[ai].cmd);
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
            // App labels through the kernel's 8x8 text renderer: a
            // glyph letter on the icon plus a short name beside it.
            for (int slot = 0; ; slot++) {
                int i = app_at_slot(slot);
                if (i < 0) break;
                int bx = SLOT_X0 + slot * 100;
                if (bx + 92 > (int)panel_info.width) break;
                char glyph[2] = {(char)(apps[i].name[0] | 0x20), '\0'};
                if (glyph[0] < 'a' || glyph[0] > 'z') glyph[0] = apps[i].name[0];
                syscall(SYS_WINDOW_DRAW_TEXT, panel_win, bx + 16, 12,
                        0x00FFFFFF, 0xffffffffL, glyph);
                char shortn[8];
                snprintf(shortn, sizeof(shortn), "%.6s", apps[i].name);
                syscall(SYS_WINDOW_DRAW_TEXT, panel_win, bx + 44, 12,
                        0x00DDDDDD, 0xffffffffL, shortn);
            }
            // Census names next to the launcher block.
            for (int i = 0; i < ncen; i++) {
                int bx = winbtn_x0 + i * 100;
                if (bx + 92 > (int)panel_info.width) break;
                char label[10];
                snprintf(label, sizeof(label), "*%.6s", cen_names[i]);
                syscall(SYS_WINDOW_DRAW_TEXT, panel_win, bx + 44, 12,
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
