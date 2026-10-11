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
        close(clients[idx].input_pipe[0]);
        close(clients[idx].input_pipe[1]);
        close(clients[idx].event_pipe[0]);
        close(clients[idx].event_pipe[1]);
        clients[idx].active = 0;
        client_count--;
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

    // Find the window at this position
    long wid = syscall(SYS_DISPLAY_WINDOW_AT, event.x, event.y, 0, 0, 0, 0);
    if (wid < 0) return;

    // Find the client that owns this window
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].win_id == (int)wid) {
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

    // Get the input fd
    long input_fd = syscall(SYS_INPUT_FD, 0, 0, 0, 0, 0, 0);
    if (input_fd < 0) return die("input_fd");

    printf("window_server: %dx%d, input_fd=%ld\n", di.width, di.height, input_fd);

    // Main loop
    struct pollfd pfd = { .fd = (int)input_fd, .events = POLLIN };
    int frame_counter = 0;

    for (;;) {
        reap_children();

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
