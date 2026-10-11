/* browser: a minimal graphical web browser for myos.
 *
 * One window: a URL bar on top, the page below, a status line at the
 * bottom. HTTP/1.0 over the guest socket layer, tag-stripping HTML with
 * clickable links, scrollback-free scrolling viewport, and a back history.
 *
 * Controls:
 *   type             edit the URL bar
 *   Return           fetch the URL
 *   Backspace        back in history (when the URL bar is empty)
 *   Up/Down/PgUp/PgDn  scroll
 *   click a link     follow it
 *   window Close     quit
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include "lib/resolve.h"
#include "lib/tls.h"

#define SYS_DISPLAY_INFO    0x1000
#define SYS_WINDOW_CREATE   0x1001
#define SYS_WINDOW_MAP      0x1002
#define SYS_WINDOW_PRESENT  0x1003
#define SYS_WINDOW_MOVE     0x1004
#define SYS_WINDOW_DESTROY  0x1005
#define SYS_DISPLAY_PRESENT 0x1006
#define SYS_WINDOW_DRAW_TEXT 0x1008
#define SYS_WINDOW_RESIZE   0x100a
#define SYS_INPUT_READ      0x100d
#define SYS_WINDOW_SET_TITLE 0x100e
#define SYS_WINDOW_FOCUS    0x1011
#define SYS_INPUT_FD        0x1012
#define SYS_SYNC_FS         0x1010

#define CHAR_W 8
#define CHAR_H 8
#define BAR_H 24
#define STATUS_H 16
#define URL_CAP 512
#define BODY_CAP (256 * 1024)
#define MAX_LINES 512
#define MAX_LINKS 128
#define MAX_HIST 16
#define LINE_COLS 160

#define FG_TEXT 0x00FFFFFF
#define FG_LINK 0x006090FF
#define FG_BAR  0x00FFFFFF
#define FG_DIM  0x00909090
#define BG_MAIN 0x00000000
#define BG_BAR  0x00202838

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

/* Event kinds from oscore::input. */
#define EV_KEYDOWN 1
/* Modifier bits from oscore::input::Mods. */
#define MOD_CTRL 2
#define EV_MOUSEDOWN 3
#define EV_MOUSEUP 4
#define EV_CLOSE 8
/* Keysyms. */
#define KEY_RETURN 0xff0d
#define KEY_BS 0xff08
#define KEY_PRIOR 0xff55
#define KEY_NEXT 0xff54
#define KEY_UP 0xff51 /* host aliases Up and Down to one keysym */

#define MAX_RUNS 8

/* One colored span inside a laid-out line. */
struct lirun {
    int c0, c1; /* half-open column range */
    int link;   /* index into links[], or -1 for plain text */
};

/* A laid-out line: text plus per-word color/link runs. */
struct line {
    char text[LINE_COLS + 1];
    struct lirun runs[MAX_RUNS];
    int nrun;
};

struct link {
    int row, c0, c1; /* row and half-open column range in page coords */
    char url[URL_CAP];
};

static int win = -1;
static unsigned long win_buf = 0;
static unsigned win_w = 0, win_h = 0;
static int input_fd = -1;

static char urlbar[URL_CAP];
static int url_len = 0;

static char body[BODY_CAP];
static size_t body_len = 0;

static struct line lines[MAX_LINES];
static int nlines = 0;
static struct link links[MAX_LINKS];
static int nlinks = 0;

static int scroll = 0; /* first visible page row */
static int nscripts = 0; /* <script> blocks on the page (not executed) */

static char hist[MAX_HIST][URL_CAP];
static int nhist = 0;

static char status[URL_CAP];

static char cur_host[256];
static char cur_port[16];

static int die(const char *what) {
    perror(what);
    return 1;
}

static void present(void);

/* ---------------- URL parsing ---------------- */

static int parse_url(const char *url, char *host, size_t hostcap,
                     char *port, size_t portcap, char *path, size_t pathcap,
                     int *secure) {
    const char *p = url;
    int https = 0;
    if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        https = 1;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else {
        return -1; /* scheme required */
    }
    if (secure) *secure = https;
    /* host[:port][/path] */
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t hostlen;
    if (colon && (!slash || colon < slash)) {
        hostlen = (size_t)(colon - p);
        const char *pend = slash ? slash : p + strlen(p);
        size_t portlen = (size_t)(pend - colon - 1);
        if (portlen == 0 || portlen >= portcap) return -1;
        memcpy(port, colon + 1, portlen);
        port[portlen] = '\0';
    } else {
        hostlen = slash ? (size_t)(slash - p) : strlen(p);
        snprintf(port, portcap, "%s", https ? "443" : "80");
    }
    if (hostlen == 0 || hostlen >= hostcap) return -1;
    memcpy(host, p, hostlen);
    host[hostlen] = '\0';
    if (slash) snprintf(path, pathcap, "%s", slash);
    else snprintf(path, pathcap, "/");
    return 0;
}

/* Resolve href against the current page URL. Absolute http(s) URLs pass
 * through; rooted and relative paths inherit scheme/host/port. */
static void resolve_url(const char *base, const char *href, char *out, size_t outcap) {
    if (strncmp(href, "http://", 7) == 0 || strncmp(href, "https://", 8) == 0) {
        snprintf(out, outcap, "%s", href);
        return;
    }
    /* base is always a normalized absolute URL here. */
    char tmp[URL_CAP];
    snprintf(tmp, sizeof(tmp), "%s", base);
    char *scheme = strstr(tmp, "://");
    char *rest = scheme ? scheme + 3 : tmp;
    char *slash = strchr(rest, '/');
    size_t prefix = slash ? (size_t)(slash - tmp) : strlen(tmp);
    if (href[0] == '/') {
        snprintf(out, outcap, "%.*s%s", (int)prefix, tmp, href);
    } else {
        /* relative: replace the last segment of the base path. */
        char *last = slash ? strrchr(slash, '/') : NULL;
        size_t dirlen = last ? (size_t)(last - tmp) + 1 : prefix;
        snprintf(out, outcap, "%.*s%s", (int)dirlen, tmp, href);
    }
}

/* ---------------- HTTP fetch ---------------- */

/* Fetch failures go to the status line and to stderr: headless runs
 * cannot read pixels, so the log is the only observable. */
static void fetch_fail(const char *msg) {
    snprintf(status, sizeof(status), "%s", msg);
    fprintf(stderr, "browser: fetch %s\n", msg);
}

static int fetch_page(const char *url) {
    char host[256], port[16], path[URL_CAP];
    int secure = 0;
    if (parse_url(url, host, sizeof(host), port, sizeof(port), path, sizeof(path), &secure) < 0) {
        fetch_fail("bad URL (want http(s)://host[:port]/path)");
        return -1;
    }
    snprintf(status, sizeof(status), "resolving %s...", host);

    /* Static-friendly resolution (no NSS in a static guest). */
    struct in_addr addr;
    if (resolve_host(host, &addr) < 0) {
        char msg[300];
        snprintf(msg, sizeof(msg), "resolve: %s", host);
        fetch_fail(msg);
        return -1;
    }
    int pnum = atoi(port);
    if (pnum <= 0 || pnum > 65535) {
        fetch_fail("bad port");
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr = addr;
    sa.sin_port = (unsigned short)(((pnum & 0xff) << 8) | ((pnum >> 8) & 0xff));
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char msg[300];
        snprintf(msg, sizeof(msg), "socket: %s", strerror(errno));
        fetch_fail(msg);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        char msg[300];
        snprintf(msg, sizeof(msg), "connect: %s", strerror(errno));
        fetch_fail(msg);
        close(fd);
        return -1;
    }
    struct tls_ctx tls;
    memset(&tls, 0, sizeof(tls));
    if (secure) {
        char err[128] = {0};
        if (tls_handshake(fd, host, &tls, err, sizeof(err)) < 0) {
            char msg[300];
            snprintf(msg, sizeof(msg), "tls: %s", err);
            fetch_fail(msg);
            close(fd);
            return -1;
        }
        if (err[0])
            snprintf(status, sizeof(status), "https (%s)", err);
        else
            snprintf(status, sizeof(status), "https...");
    } else {
        snprintf(status, sizeof(status), "loading %s...", path);
    }
    char req[URL_CAP + 128];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: myos-browser\r\nConnection: close\r\n\r\n",
             path, host);
    size_t left = strlen(req);
    const char *q = req;
    while (left > 0) {
        ssize_t n = secure ? tls_write(&tls, q, left)
                           : send(fd, q, left, 0);
        if (n <= 0) {
            char msg[300];
            snprintf(msg, sizeof(msg), "send: %s", secure ? "tls error" : strerror(errno));
            fetch_fail(msg);
            tls_free(&tls);
            close(fd);
            return -1;
        }
        q += n;
        left -= (size_t)n;
    }
    body_len = 0;
    char buf[8192];
    ssize_t n;
    for (;;) {
        n = secure ? tls_read(&tls, buf, sizeof(buf)) : recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        size_t room = BODY_CAP - body_len - 1;
        if (room == 0) break;
        size_t take = (size_t)n < room ? (size_t)n : room;
        memcpy(body + body_len, buf, take);
        body_len += take;
    }
    tls_free(&tls);
    close(fd);
    /* A body already delivered is renderable even if the tail errored
     * (truncated close, RST after a complete response). */
    if (n < 0 && body_len == 0) {
        char msg[300];
        snprintf(msg, sizeof(msg), "recv: %s", secure ? "tls error" : strerror(errno));
        fetch_fail(msg);
        return -1;
    }
    body[body_len] = '\0';
    snprintf(cur_host, sizeof(cur_host), "%s", host);
    snprintf(cur_port, sizeof(cur_port), "%s", port);
    return 0;
}

/* ---------------- HTML to lines ---------------- */

/* Layout: tokenise into words with link tags, then fill lines. */
struct tok {
    char word[64];
    int link;
};

static void layout_html(const char *html) {
    nlines = 0;
    nlinks = 0;
    scroll = 0;

    /* First pass: words + link spans. */
    static struct tok toks[4096];
    int ntoks = 0;
    int cur_link = -1;
    char link_url[URL_CAP] = {0};

    /* Scripts have no engine here (see ROADMAP); count them so the page
     * can say so instead of silently dropping behavior. */
    nscripts = 0;
    for (const char *s = html; (s = strcasestr(s, "<script")) != NULL; s += 7)
        nscripts++;

    const char *p = html;
    /* Skip to <body> when present. */
    const char *bs = strstr(p, "<body");
    if (bs) {
        const char *ge = strchr(bs, '>');
        if (ge) p = ge + 1;
    }
    static char wbuf[64];
    size_t wlen = 0;
    int intag = 0, inhead = 0;
    static char tag[64];
    size_t taglen = 0;
    char href[URL_CAP];

    /* Lambda-free callbacks: inline the flush. */
#define FLUSH_WORD() do { \
        if (wlen > 0 && ntoks < 4096) { \
            wbuf[wlen] = '\0'; \
            snprintf(toks[ntoks].word, sizeof(toks[ntoks].word), "%s", wbuf); \
            toks[ntoks].link = cur_link; \
            ntoks++; \
            wlen = 0; \
        } \
    } while (0)
#define NEWLINE() do { \
        if (nlines < MAX_LINES) { \
            lines[nlines].text[0] = '\0'; \
            lines[nlines].nrun = 0; \
            nlines++; \
        } \
    } while (0)

    while (*p && ntoks < 4096 && nlines < MAX_LINES) {
        if (!intag && *p == '<') {
            FLUSH_WORD();
            intag = 1;
            taglen = 0;
            href[0] = '\0';
            p++;
            continue;
        }
        if (intag) {
            if (*p == '>') {
                intag = 0;
                tag[taglen] = '\0';
                /* tag name: lowercase up to space or /. */
                char name[16] = {0};
                size_t ni = 0;
                int closing = tag[0] == '/';
                size_t si = closing ? 1 : 0;
                while (tag[si] && tag[si] != ' ' && tag[si] != '/' && ni < 15)
                    name[ni++] = (char)tolower((unsigned char)tag[si++]);
                if (!closing && strcmp(name, "head") == 0) inhead = 1;
                if (closing && strcmp(name, "head") == 0) inhead = 0;
                if (inhead) { p++; continue; }
                if (!closing && strcmp(name, "a") == 0) {
                    /* href="..." */
                    const char *h = strstr(tag, "href");
                    if (h) {
                        h += 4;
                        while (*h == ' ' || *h == '=') h++;
                        char q = (*h == '"' || *h == '\'') ? *h++ : 0;
                        size_t hi = 0;
                        while (*h && hi + 1 < sizeof(href) &&
                               (q ? *h != q : *h != ' ' && *h != '>'))
                            href[hi++] = *h++;
                        href[hi] = '\0';
                        if (nlinks < MAX_LINKS && hi > 0) {
                            /* resolve later at click time; store raw here */
                            cur_link = nlinks;
                            snprintf(links[nlinks].url, sizeof(links[nlinks].url), "%s", href);
                            links[nlinks].row = -1;
                            nlinks++;
                        }
                    }
                } else if (closing && strcmp(name, "a") == 0) {
                    cur_link = -1;
                } else if (strcmp(name, "br") == 0 || strcmp(name, "p") == 0 ||
                           strcmp(name, "div") == 0 || strcmp(name, "tr") == 0 ||
                           strcmp(name, "li") == 0 ||
                           (name[0] == 'h' && name[1] >= '1' && name[1] <= '6' && !name[2])) {
                    if (!closing || strcmp(name, "p") == 0 || strcmp(name, "div") == 0)
                        NEWLINE();
                } else if (strcmp(name, "title") == 0) {
                    /* page <title> becomes the first line when no body text yet */
                }
                p++;
                continue;
            }
            /* inside tag text: entities + href capture continue */
            if (taglen + 1 < sizeof(tag)) tag[taglen++] = *p;
            /* entities */
            if (*p == '&') {
                const char *semi = strchr(p, ';');
                if (semi && semi - p < 8) {
                    char ent[10] = {0};
                    size_t el = (size_t)(semi - p - 1);
                    memcpy(ent, p + 1, el);
                    char ec = 0;
                    if (strcmp(ent, "amp") == 0) ec = '&';
                    else if (strcmp(ent, "lt") == 0) ec = '<';
                    else if (strcmp(ent, "gt") == 0) ec = '>';
                    else if (strcmp(ent, "quot") == 0) ec = '"';
                    else if (strcmp(ent, "nbsp") == 0) ec = ' ';
                    if (ec && wlen + 1 < sizeof(wbuf)) wbuf[wlen++] = ec;
                    p = semi + 1;
                    continue;
                }
            }
            p++;
            continue;
        }
        /* text */
        if (*p == '&') {
            const char *semi = strchr(p, ';');
            if (semi && semi - p < 8) {
                char ent[10] = {0};
                size_t el = (size_t)(semi - p - 1);
                memcpy(ent, p + 1, el);
                char ec = 0;
                if (strcmp(ent, "amp") == 0) ec = '&';
                else if (strcmp(ent, "lt") == 0) ec = '<';
                else if (strcmp(ent, "gt") == 0) ec = '>';
                else if (strcmp(ent, "quot") == 0) ec = '"';
                else if (strcmp(ent, "nbsp") == 0) ec = ' ';
                if (ec) {
                    if (wlen + 1 < sizeof(wbuf)) wbuf[wlen++] = ec;
                    p = semi + 1;
                    continue;
                }
            }
        }
        unsigned char c = (unsigned char)*p;
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if (c == ' ') {
            FLUSH_WORD();
        } else if (c >= 0x20 && c < 0x7f) {
            if (wlen + 1 < sizeof(wbuf)) wbuf[wlen++] = (char)c;
        } else if (c >= 0x80) {
            if (wlen + 1 < sizeof(wbuf)) wbuf[wlen++] = '?';
        }
        p++;
    }
    FLUSH_WORD();

    /* Second pass: fill lines greedily, recording one run per word so
     * links keep their color even mid-line. */
    int cols = (win_w ? (int)win_w : 640) / CHAR_W;
    if (cols > LINE_COLS) cols = LINE_COLS;
    if (cols < 20) cols = 20;
    nlines = 0;
    char cur[LINE_COLS + 1];
    size_t clen = 0;
    struct lirun rruns[MAX_RUNS];
    int nrr = 0;
    for (int i = 0; i < ntoks && nlines < MAX_LINES; i++) {
        size_t wl = strlen(toks[i].word);
        size_t need = clen + (clen ? 1 : 0) + wl;
        if (need > (size_t)cols && clen > 0) {
            cur[clen] = '\0';
            snprintf(lines[nlines].text, sizeof(lines[nlines].text), "%s", cur);
            memcpy(lines[nlines].runs, rruns, sizeof(rruns[0]) * (size_t)nrr);
            lines[nlines].nrun = nrr;
            nlines++;
            clen = 0;
            nrr = 0;
        }
        size_t at = clen + (clen ? 1 : 0);
        if (clen) cur[clen++] = ' ';
        if (nrr < MAX_RUNS) {
            rruns[nrr].c0 = (int)at;
            rruns[nrr].c1 = (int)(at + wl);
            rruns[nrr].link = toks[i].link;
            nrr++;
        } else {
            rruns[nrr - 1].c1 = (int)(at + wl);
            if (rruns[nrr - 1].link != toks[i].link) rruns[nrr - 1].link = -1;
        }
        memcpy(cur + clen, toks[i].word, wl);
        clen += wl;
    }
    if (clen && nlines < MAX_LINES) {
        cur[clen] = '\0';
        snprintf(lines[nlines].text, sizeof(lines[nlines].text), "%s", cur);
        memcpy(lines[nlines].runs, rruns, sizeof(rruns[0]) * (size_t)nrr);
        lines[nlines].nrun = nrr;
        nlines++;
    }
    if (nlines == 0) {
        snprintf(lines[0].text, sizeof(lines[0].text), "(empty page)");
        lines[0].nrun = 0;
        nlines = 1;
    }
    (void)ntoks;
    /* Back-fill each link's row span from the runs, for click mapping. */
    for (int i = 0; i < nlinks; i++) {
        links[i].row = -1;
        links[i].c0 = 0;
        links[i].c1 = 0;
    }
    for (int r = 0; r < nlines; r++) {
        for (int k = 0; k < lines[r].nrun; k++) {
            int li = lines[r].runs[k].link;
            if (li < 0 || li >= nlinks) continue;
            if (links[li].row < 0) {
                links[li].row = r;
                links[li].c0 = lines[r].runs[k].c0;
                links[li].c1 = lines[r].runs[k].c1;
            } else if (links[li].row == r && lines[r].runs[k].c1 > links[li].c1) {
                links[li].c1 = lines[r].runs[k].c1;
            }
        }
    }
}

/* ---------------- navigation ---------------- */

static void push_hist(const char *url) {
    if (nhist >= MAX_HIST) {
        memmove(hist[0], hist[1], sizeof(hist[0]) * (MAX_HIST - 1));
        nhist = MAX_HIST - 1;
    }
    snprintf(hist[nhist++], URL_CAP, "%s", url);
}

/* Streams a URL body straight to a file: pages buffer in memory for
 * rendering, but app binaries can exceed that. Returns bytes written or
 * -1 with status set. */
static long stream_to_file(const char *url, const char *path) {
    char host[256], port[16], upath[URL_CAP];
    int secure = 0;
    if (parse_url(url, host, sizeof(host), port, sizeof(port), upath, sizeof(upath), &secure) < 0)
        return -1;
    struct in_addr addr;
    if (resolve_host(host, &addr) < 0) return -1;
    int pnum = atoi(port);
    if (pnum <= 0 || pnum > 65535) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr = addr;
    sa.sin_port = (unsigned short)(((pnum & 0xff) << 8) | ((pnum >> 8) & 0xff));
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    struct tls_ctx tls;
    memset(&tls, 0, sizeof(tls));
    if (secure) {
        char err[128] = {0};
        if (tls_handshake(fd, host, &tls, err, sizeof(err)) < 0) {
            close(fd);
            return -1;
        }
    }
    char req[URL_CAP + 128];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: myos-browser\r\nConnection: close\r\n\r\n",
             upath, host);
    size_t left = strlen(req);
    const char *q = req;
    while (left > 0) {
        ssize_t n = secure ? tls_write(&tls, q, left) : send(fd, q, left, 0);
        if (n <= 0) {
            tls_free(&tls);
            close(fd);
            return -1;
        }
        q += n;
        left -= (size_t)n;
    }
    /* Slurp headers (small) to find the body offset. */
    static char hdr[8192];
    size_t hlen = 0;
    ssize_t n = 0;
    char *sep = NULL;
    while (!sep) {
        if (hlen >= sizeof(hdr)) break;
        n = secure ? tls_read(&tls, hdr + hlen, sizeof(hdr) - hlen)
                   : recv(fd, hdr + hlen, sizeof(hdr) - hlen, 0);
        if (n <= 0) break;
        hlen += (size_t)n;
        hdr[hlen] = '\0';
        sep = strstr(hdr, "\r\n\r\n");
    }
    if (!sep) {
        tls_free(&tls);
        close(fd);
        return -1;
    }
    size_t hoff = (size_t)(sep + 4 - hdr);
    int out = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) {
        tls_free(&tls);
        close(fd);
        return -1;
    }
    long total = 0;
    /* Leftover body bytes already read past the headers. */
    if (hlen > hoff) {
        size_t extra = hlen - hoff;
        if (write(out, hdr + hoff, extra) != (ssize_t)extra) {
            close(out);
            tls_free(&tls);
            close(fd);
            return -1;
        }
        total += (long)extra;
    }
    char buf[8192];
    for (;;) {
        n = secure ? tls_read(&tls, buf, sizeof(buf)) : recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = write(out, buf + off, (size_t)n - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        if (off != (size_t)n) break;
        total += n;
    }
    close(out);
    tls_free(&tls);
    close(fd);
    return total;
}

/* Downloads a binary response to /downloads and runs it in-process (a
 * forked child execs it, so the browser keeps its window). An explicit
 * click is the consent model here, matching this toy desktop's threat
 * model: no sandboxing beyond the parasitic trap. */
static void download_and_run(const char *url) {
    const char *slash = strrchr(url, '/');
    const char *base = slash ? slash + 1 : url;
    if (!*base) base = "download.bin";
    char name[64];
    size_t ni = 0;
    for (const char *s = base; *s && ni + 1 < sizeof(name); s++) {
        if (isalnum((unsigned char)*s) || *s == '_' || *s == '-' || *s == '.')
            name[ni++] = *s;
    }
    name[ni] = '\0';
    if (ni == 0) snprintf(name, sizeof(name), "download.bin");
    mkdir("/downloads", 0755);
    char path[128];
    snprintf(path, sizeof(path), "/downloads/%s", name);
    /* Stream straight to disk: app binaries dwarf the page buffer. */
    long binlen = stream_to_file(url, path);
    if (binlen < 0) {
        snprintf(status, sizeof(status), "save: download failed");
        return;
    }
    /* Persist so the exec below resolves through the host rootfs. */
    syscall(SYS_SYNC_FS, 0, 0, 0, 0, 0, 0);
    fprintf(stderr, "browser: saved %s (%ld bytes)\n", path, binlen);
    snprintf(status, sizeof(status), "saved %s, running...", name);
    present();
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(status, sizeof(status), "run: fork failed");
        return;
    }
    if (pid == 0) {
        char *argv[] = {path, NULL};
        char *envp[] = {"PATH=/bin:/usr/bin", "HOME=/", NULL};
        execve(path, argv, envp);
        fprintf(stderr, "browser: exec %s: %s\n", path, strerror(errno));
        _exit(127);
    }
    fprintf(stderr, "browser: running %s pid %d\n", path, (int)pid);
}

static int url_is_binary(const char *url) {
    size_t n = strlen(url);
    return n > 4 && strcmp(url + n - 4, ".bin") == 0;
}

static void navigate(const char *url, int record) {
    char full[URL_CAP];
    if (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0) {
        snprintf(full, sizeof(full), "%s", url);
    } else {
        /* Relative link: resolve against the current page URL. */
        char base[URL_CAP];
        if (urlbar[0])
            snprintf(base, sizeof(base), "%s", urlbar);
        else
            snprintf(base, sizeof(base), "http://%s:%s/",
                     cur_host[0] ? cur_host : "localhost",
                     cur_port[0] ? cur_port : "80");
        resolve_url(base, url, full, sizeof(full));
    }
    if (record && urlbar[0]) push_hist(urlbar);
    fprintf(stderr, "browser: -> %s\n", full);
    snprintf(urlbar, sizeof(urlbar), "%s", full);
    url_len = (int)strlen(urlbar);
    /* Split headers from body for rendering. */
    if (fetch_page(full) == 0) {
        const char *sep = strstr(body, "\r\n\r\n");
        /* Binary payloads (octet-stream or .bin links) download and run
         * instead of rendering. */
        int is_bin = url_is_binary(full);
        if (!is_bin && sep) {
            size_t hlen = (size_t)(sep - body);
            char *hdrs = malloc(hlen + 1);
            if (hdrs) {
                memcpy(hdrs, body, hlen);
                hdrs[hlen] = '\0';
                if (strcasestr(hdrs, "application/octet-stream")) is_bin = 1;
                free(hdrs);
            }
        }
        if (is_bin) {
            download_and_run(full);
            return;
        }
        const char *html = sep ? sep + 4 : body;
        /* status line into the window title area */
        char first[128] = {0};
        size_t fl = strcspn(body, "\r\n");
        if (fl > sizeof(first) - 1) fl = sizeof(first) - 1;
        memcpy(first, body, fl);
        snprintf(status, sizeof(status), "%s", first);
        layout_html(html);
    }
}

/* ---------------- rendering ---------------- */

static void draw_bar(void) {
    unsigned int *px = (unsigned int *)win_buf;
    for (unsigned y = 0; y < BAR_H && y < win_h; y++)
        for (unsigned x = 0; x < win_w; x++)
            px[y * win_w + x] = BG_BAR;
    char prompt[URL_CAP + 8];
    snprintf(prompt, sizeof(prompt), "URL: %s", urlbar);
    prompt[win_w / CHAR_W > 5 ? win_w / CHAR_W - 5 : 0] = '\0';
    syscall(SYS_WINDOW_DRAW_TEXT, win, 4, 8, FG_BAR, BG_BAR, prompt);
    /* cursor */
    {
        int cx = 4 + (int)(strlen("URL: ") + (size_t)url_len) * CHAR_W;
        unsigned int *pp = (unsigned int *)win_buf;
        for (int dy = 0; dy < CHAR_H && 8 + dy < (int)BAR_H; dy++)
            for (int dx = 0; dx < 2; dx++) {
                int sx = cx + dx, sy = 8 + dy;
                if (sx >= 0 && sx < (int)win_w && sy >= 0 && sy < (int)win_h)
                    pp[sy * win_w + sx] = FG_BAR;
            }
    }
}

static void render(void) {
    if (!win_buf) return;
    unsigned int *px = (unsigned int *)win_buf;
    for (unsigned i = 0; i < win_w * win_h; i++) px[i] = BG_MAIN;
    /* Page rows as per-run colored text; links in link color. */
    int rows = ((int)win_h - BAR_H - STATUS_H) / CHAR_H;
    char run[LINE_COLS + 1];
    for (int r = 0; r < rows; r++) {
        int lr = scroll + r;
        if (lr < 0 || lr >= nlines) continue;
        const char *t = lines[lr].text;
        if (!t[0]) continue;
        if (lines[lr].nrun == 0) {
            syscall(SYS_WINDOW_DRAW_TEXT, win, 0, BAR_H + r * CHAR_H,
                    FG_TEXT, BG_MAIN, t);
            continue;
        }
        for (int k = 0; k < lines[lr].nrun; k++) {
            int c0 = lines[lr].runs[k].c0;
            int c1 = lines[lr].runs[k].c1;
            int li = lines[lr].runs[k].link;
            if (c0 < 0) c0 = 0;
            if (c1 > (int)strlen(t)) c1 = (int)strlen(t);
            if (c1 <= c0) continue;
            int n = c1 - c0;
            if (n > (int)sizeof(run) - 1) n = (int)sizeof(run) - 1;
            memcpy(run, t + c0, (size_t)n);
            run[n] = '\0';
            syscall(SYS_WINDOW_DRAW_TEXT, win, c0 * CHAR_W, BAR_H + r * CHAR_H,
                    li >= 0 ? FG_LINK : FG_TEXT, BG_MAIN, run);
        }
    }
    draw_bar();
    /* Status line. */
    {
        unsigned int *pp = (unsigned int *)win_buf;
        unsigned y0 = win_h > STATUS_H ? win_h - STATUS_H : 0;
        for (unsigned y = y0; y < win_h; y++)
            for (unsigned x = 0; x < win_w; x++)
                pp[y * win_w + x] = BG_BAR;
        char st[128];
        if (nscripts > 0)
            snprintf(st, sizeof(st), "%s [+%d script%s, no JS engine]", status,
                     nscripts, nscripts == 1 ? "" : "s");
        else
            snprintf(st, sizeof(st), "%s", status);
        st[win_w / CHAR_W > 1 ? win_w / CHAR_W - 1 : 0] = '\0';
        syscall(SYS_WINDOW_DRAW_TEXT, win, 4, (int)y0 + 4, FG_DIM, BG_BAR, st);
        char tab[32];
        snprintf(tab, sizeof(tab), "%d/%d lines", scroll + 1 <= nlines ? scroll + 1 : nlines, nlines);
        syscall(SYS_WINDOW_DRAW_TEXT, win, (int)win_w - 100, (int)y0 + 4, FG_DIM, BG_BAR, tab);
    }
    char title[URL_CAP + 16];
    snprintf(title, sizeof(title), "browser - %s", urlbar[0] ? urlbar : "(blank)");
    syscall(SYS_WINDOW_SET_TITLE, win, title, 0, 0, 0, 0);
}

static void present(void) {
    render();
    syscall(SYS_WINDOW_PRESENT, win, 0, 0, 0, 0, 0, 0);
    syscall(SYS_DISPLAY_PRESENT, 0, 0, 0, 0, 0, 0, 0);
}

/* Click at page coords: follow a link if one covers the cell. */
static void click_page(int px, int py) {
    int rows = ((int)win_h - BAR_H - STATUS_H) / CHAR_H;
    int r = (py - BAR_H) / CHAR_H;
    int c = px / CHAR_W;
    if (r < 0 || r >= rows) return;
    int lr = scroll + r;
    if (lr < 0 || lr >= nlines) return;
    for (int k = 0; k < nlinks; k++) {
        if (links[k].row == lr && c >= links[k].c0 && c < links[k].c1) {
            char target[URL_CAP];
            char base[URL_CAP];
            snprintf(base, sizeof(base), "%s", urlbar);
            resolve_url(base, links[k].url, target, sizeof(target));
            navigate(target, 1);
            present();
            return;
        }
    }
}

static void go_back(void) {
    if (nhist == 0) return;
    char prev[URL_CAP];
    snprintf(prev, sizeof(prev), "%s", hist[--nhist]);
    snprintf(urlbar, sizeof(urlbar), "%s", prev);
    url_len = (int)strlen(urlbar);
    if (fetch_page(prev) == 0) {
        const char *sep = strstr(body, "\r\n\r\n");
        layout_html(sep ? sep + 4 : body);
    }
    present();
}

int main(int argc, char **argv) {
    struct display_info di;
    if ((long)syscall(SYS_DISPLAY_INFO, &di, 0, 0, 0, 0, 0) < 0) return die("display_info");
    if (di.width == 0 || di.height == 0) return 1;

    win_w = di.width > 640 ? 640 : di.width;
    win_h = di.height > 480 ? 480 : di.height;
    win = (int)syscall(SYS_WINDOW_CREATE, win_w, win_h, 0, 0, 0, 0);
    if (win < 0) return die("window_create");
    struct window_info wi;
    win_buf = (unsigned long)syscall(SYS_WINDOW_MAP, win, &wi, 0, 0, 0, 0);
    if (win_buf == 0) return die("window_map");
    win_w = wi.width;
    win_h = wi.height;
    syscall(SYS_WINDOW_SET_TITLE, win, "browser", 0, 0, 0, 0);
    syscall(SYS_WINDOW_FOCUS, win, 0, 0, 0, 0, 0);

    mkdir("/winserv", 0755);
    mkdir("/winserv/clients", 0755);
    {
        char reg[64];
        snprintf(reg, sizeof(reg), "/winserv/clients/%d", (int)getpid());
        FILE *rf = fopen(reg, "w");
        if (rf) {
            fprintf(rf, "%d browser\n", win);
            fclose(rf);
        }
    }

    input_fd = (int)syscall(SYS_INPUT_FD, 0, 0, 0, 0, 0, 0);
    if (input_fd < 0) return die("input_fd");

    const char *start = argc > 1 ? argv[1] : "http://localhost:80/";
    fprintf(stderr, "browser: start %s\n", start);
    snprintf(urlbar, sizeof(urlbar), "%s", start);
    url_len = (int)strlen(urlbar);
    if (fetch_page(start) == 0) {
        const char *sep = strstr(body, "\r\n\r\n");
        layout_html(sep ? sep + 4 : body);
    } else {
        layout_html("<html><body><p>Type a URL above and press Return.</p></body></html>");
    }
    present();

    struct pollfd pfd = { .fd = input_fd, .events = POLLIN };
    for (;;) {
        /* Reap downloaded apps that ran and exited. */
        int st;
        while (waitpid(-1, &st, WNOHANG) > 0) {}
        int ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            struct input_event ev;
            ssize_t n = read(input_fd, &ev, sizeof(ev));
            if (n != (ssize_t)sizeof(ev)) continue;
            if (ev.kind == EV_CLOSE) break;
            if (ev.kind == EV_MOUSEDOWN && ev.button == 1) {
                if (ev.y < BAR_H) {
                    /* URL bar takes focus; nothing else to do. */
                } else {
                    click_page(ev.x, ev.y);
                }
                continue;
            }
            if (ev.kind != EV_KEYDOWN) continue;
            long k = ev.x;
            /* Ctrl+U clears the URL bar (readline-style), so a search can
             * start from a known state without re-launching. */
            if ((ev.mods & MOD_CTRL) && (k == 'u' || k == 'U')) {
                url_len = 0;
                urlbar[0] = '\0';
                present();
                continue;
            }
            if (k == KEY_RETURN) {
                if (url_len > 0) {
                    navigate(urlbar, 1);
                    present();
                }
            } else if (k == KEY_BS) {
                if (url_len > 0) {
                    urlbar[--url_len] = '\0';
                    present();
                } else {
                    go_back();
                }
            } else if (k == KEY_NEXT) {
                int rows = ((int)win_h - BAR_H - STATUS_H) / CHAR_H;
                scroll += rows - 1;
                int max = nlines - rows;
                if (max < 0) max = 0;
                if (scroll > max) scroll = max;
                present();
            } else if (k == KEY_PRIOR) {
                int rows = ((int)win_h - BAR_H - STATUS_H) / CHAR_H;
                scroll -= rows - 1;
                if (scroll < 0) scroll = 0;
                present();
            } else if (k == KEY_UP) {
                /* Up/Down share one keysym on this host mapping, so both
                 * arrows scroll by a line. */
                scroll += 1;
                int rows = ((int)win_h - BAR_H - STATUS_H) / CHAR_H;
                int max = nlines - rows;
                if (max < 0) max = 0;
                if (scroll > max) scroll = max;
                present();
            } else if (k >= 0x20 && k < 0x7f && !ev.mods) {
                if (url_len + 1 < (int)sizeof(urlbar)) {
                    urlbar[url_len++] = (char)k;
                    urlbar[url_len] = '\0';
                    present();
                }
            }
        }
    }

    syscall(SYS_WINDOW_DESTROY, win, 0, 0, 0, 0, 0, 0);
    return 0;
}
