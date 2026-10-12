/* window_server: the root guest that owns the display.
 *
 * Registers client processes, routes input events to the focused client,
 * manages window lifecycle (create/destroy/minimize/resize), and composites
 * the final frame.
 *
 * Clients connect by creating a file in /winserv/clients/. The server
 * polls this directory, spawns new clients, and routes events via pipes.
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

#define MAX_CLIENTS 16
#define MAX_WINDOWS 32

struct display_info {
    unsigned int width, height, stride, format;
};

struct window_info {
    unsigned long base;
    unsigned int width, height, stride, format;
};

struct client {
    pid_t pid;
    int win_id;
    int input_pipe[2];
    int event_pipe[2];
    char name[64];
    int active;
};

static struct client clients[MAX_CLIENTS];
static int client_count = 0;

// Input event kinds, matching parasyte_core::input::EventKind codes.
#define EV_EXPOSE 7
#define EV_CLOSE 8
#define EV_RESIZE 9

// Well-known rendezvous, mirroring parasyte_core::winserv paths.
#define WINSERV_DIR "/winserv"
#define WINSERV_CLIENTS "/winserv/clients"
#define WINSERV_PIDFILE "/winserv/server.pid"

static int find_client(pid_t pid);
static int register_client(pid_t pid, int win_id);

static void init_clients(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].active = 0;
        clients[i].pid = -1;
        clients[i].win_id = -1;
        clients[i].input_pipe[0] = clients[i].input_pipe[1] = -1;
        clients[i].event_pipe[0] = clients[i].event_pipe[1] = -1;
    }
}

static void close_if_open(int fd) {
    if (fd >= 0) close(fd);
}

// Clients announce themselves by writing their window id (ASCII) to
// /winserv/clients/<pid>. Scanning the directory picks up registrations
// without any fd passing, which this hosted model cannot do across the
// fork boundary anyway; live event delivery additionally uses FOCUS plus
// the shared input queue, which every guest can already read.
static void scan_registrations(void) {
    DIR *d = opendir(WINSERV_CLIENTS);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char *end = NULL;
        long pid = strtol(e->d_name, &end, 10);
        if (!end || *end != '\0' || pid <= 0) continue;
        if (find_client((pid_t)pid) >= 0) continue;
        char path[128];
        snprintf(path, sizeof(path), "%s/%s", WINSERV_CLIENTS, e->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        char buf[32];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';
        long win = strtol(buf, &end, 10);
        if (end == buf || win < 0) continue;
        if (register_client((pid_t)pid, (int)win) < 0) return; // table full
    }
    closedir(d);
}

static int die(const char *what) {
    perror(what);
    return 1;
}

static int find_client(pid_t pid) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].pid == pid) return i;
    }
    return -1;
}

static int register_client(pid_t pid, int win_id) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].pid = pid;
            clients[i].win_id = win_id;
            clients[i].active = 1;
            snprintf(clients[i].name, sizeof(clients[i].name), "client-%d", i);
            client_count++;
            return i;
        }
    }
    return -1;
}

static void unregister_client(pid_t pid) {
    int idx = find_client(pid);
    if (idx >= 0) {
        close_if_open(clients[idx].input_pipe[0]);
        close_if_open(clients[idx].input_pipe[1]);
        close_if_open(clients[idx].event_pipe[0]);
        close_if_open(clients[idx].event_pipe[1]);
        clients[idx].active = 0;
        clients[idx].pid = -1;
        clients[idx].win_id = -1;
        client_count--;
        // Remove the rendezvous file so a later scan does not resurrect it.
        char path[128];
        snprintf(path, sizeof(path), "%s/%d", WINSERV_CLIENTS, (int)pid);
        unlink(path);
    }
}

static void broadcast_event(int event_type, int x, int y, int button) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            write(clients[i].event_pipe[1], &event_type, sizeof(int));
            write(clients[i].event_pipe[1], &x, sizeof(int));
            write(clients[i].event_pipe[1], &y, sizeof(int));
            write(clients[i].event_pipe[1], &button, sizeof(int));
        }
    }
}

struct window_query {
    int x, y;
    unsigned int w, h, z, focused;
};

// Drag state for input-driven move/resize: the decorations are drawn by
// the kernel but only the server sees every event, so it owns the gesture.
static int drag_win = -1;
static int drag_mode = 0; // 1 = move, 2 = resize
static int drag_offx = 0, drag_offy = 0;
static int drag_qx = 0, drag_qy = 0;

#define EV_MOUSEDOWN 3
#define EV_MOUSEUP 4
#define EV_MOUSEMOVE 5
#define TITLE_BAR_H 20
#define CLOSE_X0 16
#define RESIZE_GRIP 10

static void route_input(int input_fd) {
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
    if (n != (ssize_t)sizeof(event)) return;

    // An in-progress drag consumes motion and release events directly.
    if (drag_win >= 0) {
        if (event.kind == EV_MOUSEMOVE) {
            if (drag_mode == 1) {
                syscall(SYS_WINDOW_MOVE, drag_win, event.x - drag_offx,
                        event.y - drag_offy, 0, 0, 0);
            } else if (drag_mode == 2) {
                int nw = event.x - drag_qx;
                int nh = event.y - drag_qy;
                if (nw < 40) nw = 40;
                if (nh < 40) nh = 40;
                struct window_info wi;
                syscall(SYS_WINDOW_RESIZE, drag_win, nw, nh, &wi, 0, 0);
            }
            return;
        }
        if (event.kind == EV_MOUSEUP) {
            drag_win = -1;
            drag_mode = 0;
            return;
        }
    }

    // Window-manager events carry their target directly; pointer events
    // need a hit-test first.
    long wid = (long)event.window;
    if (event.kind != EV_CLOSE && event.kind != EV_RESIZE) {
        wid = syscall(SYS_DISPLAY_WINDOW_AT, event.x, event.y, 0, 0, 0, 0);
        if (wid < 0) return;
    }

    // Left-press on a window starts a window-manager gesture: the close
    // box (matching gfx::draw_decorations), the title bar for moves, or
    // the bottom-right grip for resizes.
    if (event.kind == EV_MOUSEDOWN && event.button == 1) {
        struct window_query q;
        if ((long)syscall(SYS_WINDOW_QUERY, wid, &q, 0, 0, 0, 0) >= 0) {
            int lx = event.x - q.x;
            int ly = event.y - q.y;
            if (lx >= (int)q.w - CLOSE_X0 && ly >= 2 && ly < 14 && q.w >= 24) {
                syscall(SYS_WINDOW_DESTROY, wid, 0, 0, 0, 0, 0);
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].active && clients[i].win_id == (int)wid) {
                        unregister_client(clients[i].pid);
                        break;
                    }
                }
                return;
            }
            if (ly >= 0 && ly < TITLE_BAR_H) {
                drag_win = (int)wid;
                drag_mode = 1;
                drag_offx = lx;
                drag_offy = ly;
            } else if (lx >= (int)q.w - RESIZE_GRIP && ly >= (int)q.h - RESIZE_GRIP) {
                drag_win = (int)wid;
                drag_mode = 2;
                drag_qx = q.x;
                drag_qy = q.y;
            }
        }
    }

    // Focus follows the pointer so the owning client receives keyboard
    // events through the shared input queue as well.
    syscall(SYS_WINDOW_FOCUS, wid, 0, 0, 0, 0, 0);

    // Window lifecycle from client requests: close destroys, resize remaps.
    if (event.kind == EV_CLOSE) {
        syscall(SYS_WINDOW_DESTROY, wid, 0, 0, 0, 0, 0);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].win_id == (int)wid) {
                pid_t pid = clients[i].pid;
                unregister_client(pid);
                break;
            }
        }
        return;
    }
    if (event.kind == EV_RESIZE) {
        struct window_info wi;
        syscall(SYS_WINDOW_RESIZE, wid, event.width, event.height, &wi, 0, 0);
        return;
    }

    // Find the client that owns this window
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].win_id == (int)wid) {
            if (clients[i].event_pipe[1] >= 0)
                write(clients[i].event_pipe[1], &event, sizeof(event));
            break;
        }
    }
}

static void reap_children(void) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        unregister_client(pid);
    }
}

int main(void) {
    struct display_info di;
    if ((long)syscall(SYS_DISPLAY_INFO, &di, 0, 0, 0, 0, 0) < 0) return die("display_info");
    if (di.width == 0 || di.height == 0) return 1;

    init_clients();

    // Well-known rendezvous for client discovery.
    mkdir(WINSERV_DIR, 0755);
    mkdir(WINSERV_CLIENTS, 0755);
    FILE *pf = fopen(WINSERV_PIDFILE, "w");
    if (pf) {
        fprintf(pf, "%d\n", (int)getpid());
        fclose(pf);
    }

    // Get the input fd
    long input_fd = syscall(SYS_INPUT_FD, 0, 0, 0, 0, 0, 0);
    if (input_fd < 0) return die("input_fd");

    printf("window_server: %dx%d, input_fd=%ld\n", di.width, di.height, input_fd);

    // Main loop
    struct pollfd pfd = { .fd = (int)input_fd, .events = POLLIN };
    int frame_counter = 0;

    for (;;) {
        reap_children();
        if (frame_counter % 30 == 0) scan_registrations();

        // Wait for input with a timeout (for frame pacing)
        int ret = poll(&pfd, 1, 16); // ~60fps
        if (ret > 0 && (pfd.revents & POLLIN)) {
            route_input((int)input_fd);
        }

        // Composite and present
        long n = syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0);
        if (n > 0) {
            frame_counter++;
        }

        // Periodic sync
        if (frame_counter % 60 == 0) {
            syscall(SYS_SYNC_FS, 0, 0, 0, 0, 0, 0);
        }
    }

    return 0;
}
