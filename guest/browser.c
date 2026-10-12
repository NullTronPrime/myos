/* browser: a minimal graphical web browser for parasyteos.
 *
 * One window: a URL bar on top, the page below, a status line at the
 * bottom. HTTP/1.1 over the guest socket layer (chunked bodies decoded),
 * tag-stripping HTML with clickable links, scrollback-free scrolling
 * viewport, and a back history.
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
#include "lib/dom.h"
#include "lib/jsdom.h"

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
/* Title strip (drag handle + close), then nav row + bookmarks row. */
#define TITLE_H 18
#define NAV_H 24
#define BM_H 16
#define BAR_H (NAV_H + BM_H)
#define CHROME_H (TITLE_H + BAR_H)
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

/* Event kinds from parasyte_core::input. */
#define EV_KEYDOWN 1
/* Modifier bits from parasyte_core::input::Mods. */
#define MOD_CTRL 2
#define EV_MOUSEDOWN 3
#define EV_MOUSEUP 4
#define EV_MOUSEMOVE 5
#define EV_CLOSE 8
#define EV_RESIZE 9
/* Keysyms. */
#define KEY_RETURN 0xff0d
#define KEY_BS 0xff08
#define KEY_ESC 0xff1b
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
    struct dom_node *field; /* non-NULL for form-field clicks (no navigate) */
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
/* Last response's status line + Location header (for redirects). */
static char http_status[128];
static char http_location[URL_CAP];
static char fwd[MAX_HIST][URL_CAP];
static int nfwd = 0;
/* Starred pages, shown on the bookmarks bar (max 3, in-memory). */
static char marks[3][URL_CAP];
static int nmarks = 0;

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
/* Decodes chunked transfer encoding in place; returns the decoded length.
 * A truncated tail keeps what decoded so far (matches the truncated-close
 * tolerance in fetch_page). */
static size_t dechunk(char *b, size_t n) {
    size_t ri = 0, wi = 0;
    while (ri < n) {
        char *e = memchr(b + ri, '\n', n - ri);
        if (!e) break;
        unsigned long sz = strtoul(b + ri, NULL, 16);
        ri = (size_t)(e + 1 - b);
        if (sz == 0) break;
        if (ri + sz > n) break;
        memmove(b + wi, b + ri, sz);
        wi += sz;
        ri += sz;
        if (ri + 2 <= n && b[ri] == '\r' && b[ri + 1] == '\n') ri += 2;
        else if (ri < n && b[ri] == '\n') ri += 1;
    }
    return wi;
}

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
    int fd = tcp_connect_timeout(&addr, pnum, 10000);
    if (fd < 0) {
        char msg[300];
        snprintf(msg, sizeof(msg), "connect: %s", strerror(errno));
        fetch_fail(msg);
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
             "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: parasyteos-browser\r\nConnection: close\r\n\r\n",
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
    /* Stash the status line + Location BEFORE the headers are stripped,
     * so navigate() can follow redirects. */
    {
        http_status[0] = '\0';
        http_location[0] = '\0';
        size_t fl = strcspn(body, "\r\n");
        if (fl > sizeof(http_status) - 1) fl = sizeof(http_status) - 1;
        memcpy(http_status, body, fl);
        http_status[fl] = '\0';
        const char *hend = strstr(body, "\r\n\r\n");
        size_t hlen = hend ? (size_t)(hend - body) : body_len;
        const char *p = body;
        while (p < body + hlen) {
            const char *eol = strstr(p, "\r\n");
            if (!eol || eol > body + hlen) eol = body + hlen;
            if ((size_t)(eol - p) > 9 && strncasecmp(p, "location:", 9) == 0) {
                const char *v = p + 9;
                while (v < eol && (*v == ' ' || *v == '\t')) v++;
                size_t vlen = (size_t)(eol - v);
                while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t'))
                    vlen--;
                if (vlen > 0 && vlen < sizeof(http_location)) {
                    memcpy(http_location, v, vlen);
                    http_location[vlen] = '\0';
                }
            }
            p = (*eol == '\r') ? eol + 2 : eol;
            if (p >= body + hlen) break;
        }
    }
    /* Split off the response headers; decode chunked bodies, which HTTP/1.1
     * servers use for dynamic pages (search results). */
    char *sep = strstr(body, "\r\n\r\n");
    if (sep) {
        char save = *sep;
        *sep = '\0';
        int chunked = strcasestr(body, "transfer-encoding") &&
                      strcasestr(body, "chunked");
        *sep = save;
        size_t boff = (size_t)(sep + 4 - body);
        if (chunked) {
            body_len = dechunk(body + boff, body_len - boff);
            memmove(body, body + boff, body_len);
        } else {
            memmove(body, body + boff, body_len - boff);
            body_len -= boff;
        }
        body[body_len] = '\0';
    }
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

static struct tok toks[4096];
static int ntoks = 0;
static int walk_link = -1;
static char walk_buf[64];
static size_t walk_len = 0;
static struct dom_doc *page_doc = NULL;
static struct jsdom_page *page_js = NULL;
static void relayout(void);
static void submit_form(struct dom_node *from);
/* Focused form field (a dom node), or NULL for the URL bar. */
static struct dom_node *focused_input = NULL;

#define WFLUSH() do { \
        if (walk_len > 0 && ntoks < 4096) { \
            walk_buf[walk_len] = '\0'; \
            snprintf(toks[ntoks].word, sizeof(toks[ntoks].word), "%s", walk_buf); \
            toks[ntoks].link = walk_link; \
            ntoks++; \
            walk_len = 0; \
        } \
    } while (0)
#define WNEWLINE() do { \
        if (nlines < MAX_LINES) { \
            lines[nlines].text[0] = '\0'; \
            lines[nlines].nrun = 0; \
            nlines++; \
        } \
    } while (0)

/* One decoded text char into the word stream. */
static void walk_char(unsigned char c) {
    if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    if (c == ' ') {
        WFLUSH();
    } else if (c >= 0x20 && c < 0x7f) {
        if (walk_len + 1 < sizeof(walk_buf)) walk_buf[walk_len++] = (char)c;
    } else if (c >= 0x80) {
        if (walk_len + 1 < sizeof(walk_buf)) walk_buf[walk_len++] = '?';
    }
}

static void walk_text(const char *s) {
    while (*s) {
        if (*s == '&') {
            const char *semi = strchr(s, ';');
            if (semi && semi - s < 10) {
                size_t el = (size_t)(semi - s - 1);
                char ent[12] = {0};
                memcpy(ent, s + 1, el);
                char ec = 0;
                int numeric = 0;
                if (strcmp(ent, "amp") == 0) ec = '&';
                else if (strcmp(ent, "lt") == 0) ec = '<';
                else if (strcmp(ent, "gt") == 0) ec = '>';
                else if (strcmp(ent, "quot") == 0) ec = '"';
                else if (strcmp(ent, "nbsp") == 0) ec = ' ';
                else if (ent[0] == '#') {
                    /* Numeric reference: decimal or hex. Anything the
                     * 8x8 font cannot draw becomes '?'. */
                    unsigned long v = 0;
                    if ((ent[1] == 'x' || ent[1] == 'X') && ent[2]) {
                        v = strtoul(ent + 2, NULL, 16);
                        numeric = 1;
                    } else if (ent[1]) {
                        v = strtoul(ent + 1, NULL, 10);
                        numeric = 1;
                    }
                    if (numeric) ec = (v > 0 && v < 128) ? (char)v : '?';
                }
                if (ec || numeric) {
                    walk_char((unsigned char)(ec ? ec : '?'));
                    s = semi + 1;
                    continue;
                }
            }
        }
        walk_char((unsigned char)*s++);
    }
}

static int walk_block_tag(int tag) {
    return tag == TAG_BR || tag == TAG_P || tag == TAG_DIV ||
           tag == TAG_TR || tag == TAG_LI ||
           (tag >= TAG_H1 && tag <= TAG_H6);
}

/* First pass over the tree: words + link spans. Element boundaries
 * break words (the old streaming tokenizer flushed at every tag). */
static void walk_node(struct dom_node *n) {
    if (!n) return;
    if (n->text) {
        walk_text(n->text);
        return;
    }
    WFLUSH();
    if (n->tag == TAG_HEAD || n->tag == TAG_SCRIPT || n->tag == TAG_STYLE ||
        n->tag == TAG_NOSCRIPT) {
        return; /* head, scripts and styles never render */
    }
    if (n->tag == TAG_A) {
        const char *href = dom_attr(n, "href");
        int save = walk_link;
        if (href && href[0] && nlinks < MAX_LINKS) {
            walk_link = nlinks;
            snprintf(links[nlinks].url, sizeof(links[nlinks].url), "%s", href);
            links[nlinks].row = -1;
            links[nlinks].field = NULL;
            nlinks++;
        }
        for (int i = 0; i < n->nkids; i++) walk_node(n->kids[i]);
        WFLUSH(); /* trailing fragment keeps this link, not the next */
        walk_link = save;
        return;
    }
    if (n->tag == TAG_IMG) {
        /* Images have no pixels here; their alt text reads in place. */
        const char *alt = dom_attr(n, "alt");
        if (alt && alt[0]) walk_text(alt);
        return;
    }
    if (n->tag == TAG_INPUT) {
        const char *type = dom_attr(n, "type");
        int is_button = type && (strcasecmp(type, "submit") == 0 ||
                                 strcasecmp(type, "button") == 0);
        int is_text = !type || strcasecmp(type, "text") == 0 ||
                      strcasecmp(type, "search") == 0;
        if (!is_button && !is_text) return; /* hidden/checkbox/radio */
        int save = walk_link;
        if (nlinks < MAX_LINKS) {
            char cell[64];
            if (is_button) {
                /* Submit button: its label clicks. */
                const char *v = dom_attr(n, "value");
                snprintf(cell, sizeof(cell), "[ %s ]", v && v[0] ? v : "submit");
            } else {
                const char *v = dom_attr(n, "value");
                if (!v) v = "";
                if (n == focused_input)
                    snprintf(cell, sizeof(cell), "[ %-27.27s_]", v);
                else
                    snprintf(cell, sizeof(cell), "[ %-28.28s]", v);
            }
            walk_link = nlinks;
            links[nlinks].url[0] = '\0';
            links[nlinks].row = -1;
            links[nlinks].field = n;
            nlinks++;
            walk_text(cell);
            WFLUSH(); /* trailing fragment keeps this link, not the next */
            walk_link = save;
        }
        return;
    }
    if (walk_block_tag(n->tag)) WNEWLINE();
    for (int i = 0; i < n->nkids; i++) walk_node(n->kids[i]);
    if (n->tag == TAG_P || n->tag == TAG_DIV) WNEWLINE();
}

/* Finds the body element, if any. */
static void find_body_walk(struct dom_node *n, struct dom_node **hit) {
    if (*hit || !n) return;
    if (n->tag == TAG_BODY) {
        *hit = n;
        return;
    }
    for (int i = 0; i < n->nkids; i++) find_body_walk(n->kids[i], hit);
}

static void layout_html(const char *html) {
    nlines = 0;
    nlinks = 0;
    scroll = 0;
    ntoks = 0;
    walk_len = 0;
    walk_link = -1;
    focused_input = NULL; /* old tree is freed below; never dangle */

    /* Parse once; scripts run against this tree before layout. */
    if (page_doc) {
        dom_free(page_doc);
        page_doc = NULL;
    }
    page_doc = dom_parse(html ? html : "");
    if (!page_doc) {
        snprintf(lines[0].text, sizeof(lines[0].text), "(empty page)");
        lines[0].nrun = 0;
        nlines = 1;
        return;
    }

    /* Scripts run against the tree before layout, through QuickJS. */
    {
        const char **ss = NULL;
        nscripts = dom_scripts(page_doc, &ss);
        if (ss) {
            for (int i = 0; i < nscripts; i++) free((void *)ss[i]);
            free(ss);
        }
    }
    if (page_js) {
        jsdom_free(page_js);
        page_js = NULL;
    }
    if (nscripts > 0) {
        char jserr[128] = {0};
        page_js = jsdom_run(page_doc, urlbar, jserr, sizeof(jserr));
        if (!page_js && jserr[0])
            fprintf(stderr, "browser: js: %s\n", jserr);
        else if (page_js)
            fprintf(stderr, "browser: js ran %d script(s)\n", nscripts);
    }

    relayout();
}

/* Re-walks the live tree into lines: used after parsing, and again
 * whenever scripts mutate the page (timers, events) so the screen
 * follows the DOM instead of freezing at first paint. */
static void relayout(void) {
    if (!page_doc) return;
    nlines = 0;
    nlinks = 0;
    ntoks = 0;
    walk_len = 0;
    walk_link = -1;
    /* Layout the body when present, else the whole tree. */
    struct dom_node *start = NULL;
    find_body_walk(page_doc->root, &start);
    if (!start) start = page_doc->root;
    walk_node(start);
    WFLUSH();


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

/* Chunk-framing state for a streamed download. */
struct unchunk {
    int active;          /* transfer-encoding is chunked */
    int done;            /* terminal zero chunk seen */
    unsigned long left;  /* body bytes remaining in this chunk */
    int need_size;       /* next bytes are a chunk-size line */
    char line[32];       /* partial size line */
    size_t llen;
};

/* Writes all of b or returns -1. */
static int write_all(int fd, const char *b, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, b, n);
        if (w <= 0) return -1;
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

/* Feeds wire bytes through the chunk framing, writing de-framed body bytes
 * to `out` and counting them in *total. Returns 0 normally, 1 when the
 * terminal chunk arrived (stop reading), -1 on write error. */
static int unchunk_feed(struct unchunk *u, int out, const char *b, size_t n, long *total) {
    if (!u->active) {
        if (write_all(out, b, n) < 0) return -1;
        *total += (long)n;
        return 0;
    }
    size_t i = 0;
    while (i < n && !u->done) {
        if (u->need_size) {
            char c = b[i++];
            if (c == '\n') {
                u->line[u->llen] = '\0';
                u->left = strtoul(u->line, NULL, 16);
                u->llen = 0;
                u->need_size = 0;
                if (u->left == 0) u->done = 1;
            } else if (c != '\r' && u->llen + 1 < sizeof(u->line)) {
                u->line[u->llen++] = c;
            }
        } else if (u->left > 0) {
            size_t run = n - i;
            if (run > u->left) run = (size_t)u->left;
            if (write_all(out, b + i, run) < 0) return -1;
            *total += (long)run;
            i += run;
            u->left -= (unsigned long)run;
        } else {
            /* End of chunk data: consume one CRLF, then a size line. */
            if (b[i++] == '\n') u->need_size = 1;
        }
    }
    return u->done ? 1 : 0;
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
    int fd = tcp_connect_timeout(&addr, pnum, 10000);
    if (fd < 0) return -1;
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
             "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: parasyteos-browser\r\nConnection: close\r\n\r\n",
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
    /* Chunked bodies must be de-framed or the saved binary corrupts. */
    struct unchunk u;
    memset(&u, 0, sizeof(u));
    {
        char save = *sep;
        *sep = '\0';
        u.active = strcasestr(hdr, "transfer-encoding") && strcasestr(hdr, "chunked");
        *sep = save;
        u.need_size = u.active;
    }
    long total = 0;
    int feed = 0;
    /* Leftover body bytes already read past the headers. */
    if (hlen > hoff) {
        feed = unchunk_feed(&u, out, hdr + hoff, hlen - hoff, &total);
        if (feed < 0) {
            close(out);
            tls_free(&tls);
            close(fd);
            return -1;
        }
    }
    char buf[8192];
    while (!feed) {
        n = secure ? tls_read(&tls, buf, sizeof(buf)) : recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        feed = unchunk_feed(&u, out, buf, (size_t)n, &total);
        if (feed < 0) break;
    }
    if (feed < 0) {
        close(out);
        tls_free(&tls);
        close(fd);
        return -1;
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

/* If the last response was a redirect, returns a malloc'd absolute URL
 * for the Location target, or NULL. Only 3xx with an http(s) or relative
 * Location is followed. */
static char *redirect_location(const char *base) {
    const char *sp = strchr(http_status, ' ');
    if (!sp || sp[1] != '3' || sp[2] < '0' || sp[2] > '9') return NULL;
    if (!http_location[0]) return NULL;
    char *out = malloc(URL_CAP);
    if (!out) return NULL;
    resolve_url(base, http_location, out, URL_CAP);
    return out;
}

static void navigate(const char *url, int record) {
    char full[URL_CAP];
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        /* What users type: a bare hostname goes to https, a single
         * word becomes a web search. */
        if (!strchr(url, ' ') && !strchr(url, '/')) {
            char with[URL_CAP];
            if (strchr(url, '.'))
                snprintf(with, sizeof(with), "https://%s", url);
            else
                snprintf(with, sizeof(with), "https://wiby.me/?q=%s", url);
            navigate(with, record);
            return;
        }
    }
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
    if (record && urlbar[0]) {
        push_hist(urlbar);
        nfwd = 0; /* a new navigation forgets the forward trail */
    }
    fprintf(stderr, "browser: -> %s\n", full);
    snprintf(urlbar, sizeof(urlbar), "%s", full);
    url_len = (int)strlen(urlbar);
    /* Follow redirects (google.com -> www.google.com): re-fetch against
     * the Location URL, same-method GET, bounded hops. */
    int fetched = 0;
    for (int hops = 0; hops < 5; hops++) {
        if (fetch_page(full) != 0) return;
        fetched = 1;
        char *loc = redirect_location(full);
        if (!loc) break;
        fprintf(stderr, "browser: redirect -> %s\n", loc);
        snprintf(full, sizeof(full), "%s", loc);
        free(loc);
        snprintf(urlbar, sizeof(urlbar), "%s", full);
        url_len = (int)strlen(urlbar);
    }
    /* Split headers from body for rendering (body holds the final hop). */
    if (fetched) {
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
        /* Status line into the window title area (from the stashed
         * headers: body no longer carries them). */
        snprintf(status, sizeof(status), "%s", http_status);
        layout_html(html);
    }
}

/* ---------------- rendering ---------------- */

/* Bookmarks-row label origins, recorded while drawing so clicks map. */
static int mark_x[3];

/* Fill a rect in the window buffer, clipped. */
static void bar_rect(int x0, int y0, int bw, int bh, unsigned int color) {
    unsigned int *pp = (unsigned int *)win_buf;
    for (int y = y0; y < y0 + bh; y++) {
        if (y < 0 || y >= (int)win_h) continue;
        for (int x = x0; x < x0 + bw; x++) {
            if (x < 0 || x >= (int)win_w) continue;
            pp[y * win_w + x] = color;
        }
    }
}

/* 1px outline with cut corners (radius 3), Brave-pill style. */
static void pill_outline(int x0, int y0, int bw, int bh, unsigned int color) {
    unsigned int *pp = (unsigned int *)win_buf;
    for (int x = x0 + 3; x < x0 + bw - 3; x++) {
        if (x < 0 || x >= (int)win_w) continue;
        if (y0 >= 0 && y0 < (int)win_h) pp[y0 * win_w + x] = color;
        if (y0 + bh - 1 >= 0 && y0 + bh - 1 < (int)win_h)
            pp[(y0 + bh - 1) * win_w + x] = color;
    }
    for (int y = y0 + 3; y < y0 + bh - 3; y++) {
        if (y < 0 || y >= (int)win_h) continue;
        if (x0 >= 0 && x0 < (int)win_w) pp[y * win_w + x0] = color;
        if (x0 + bw - 1 >= 0 && x0 + bw - 1 < (int)win_w)
            pp[y * win_w + x0 + bw - 1] = color;
    }
}

/* Drag state for the title strip (window-relative grab point + tracked
 * outer position, since events arrive in window coordinates). */
static int dragging = 0;
static int grab_x = 0, grab_y = 0;
static int own_x = 0, own_y = 0;


static void draw_bar(void) {
    unsigned int *px = (unsigned int *)win_buf;
    /* Title strip: drag handle + close box. */
    for (unsigned y = 0; y < TITLE_H && y < win_h; y++)
        for (unsigned x = 0; x < win_w; x++)
            px[y * win_w + x] = 0x003A3D4D;
    {
        char title[128];
        snprintf(title, sizeof(title), "browser - %s",
                 urlbar[0] ? urlbar : "(blank)");
        title[(win_w - 60) / CHAR_W > 0 ? (win_w - 60) / CHAR_W : 0] = '\0';
        syscall(SYS_WINDOW_DRAW_TEXT, win, 8, 5, FG_BAR, 0x003A3D4D, title);
        syscall(SYS_WINDOW_DRAW_TEXT, win, (int)win_w - 20, 5, FG_BAR,
                0x003A3D4D, "X");
    }
    int top = TITLE_H;
    for (unsigned y = top; y < top + BAR_H && y < win_h; y++)
        for (unsigned x = 0; x < win_w; x++)
            px[y * win_w + x] = BG_BAR;
    /* Nav buttons: back fwd reload home. Dim when they would do nothing. */
    syscall(SYS_WINDOW_DRAW_TEXT, win, 6, top + 8, nhist ? FG_BAR : FG_DIM, BG_BAR, "<");
    syscall(SYS_WINDOW_DRAW_TEXT, win, 24, top + 8, nfwd ? FG_BAR : FG_DIM, BG_BAR, ">");
    syscall(SYS_WINDOW_DRAW_TEXT, win, 42, top + 8, FG_BAR, BG_BAR, "R");
    syscall(SYS_WINDOW_DRAW_TEXT, win, 60, top + 8, FG_BAR, BG_BAR, "H");
    /* Star at the right edge. */
    {
        char star[2] = {'*', '\0'};
        syscall(SYS_WINDOW_DRAW_TEXT, win, (int)win_w - 22, top + 8, FG_BAR, BG_BAR, star);
    }
    /* URL pill: blurple outline, dark fill, lion tile + text. */
    int pill_x = 84, pill_y = top + 3, pill_w = (int)win_w - pill_x - 30, pill_h = 18;
    if (pill_w > 40) {
        bar_rect(pill_x, pill_y, pill_w, pill_h, 0x001E2029);
        pill_outline(pill_x, pill_y, pill_w, pill_h, 0x004C54D2);
        /* Lion tile: brave-orange block with a white B. */
        bar_rect(pill_x + 4, pill_y + 2, 14, 14, 0x00FB542B);
        syscall(SYS_WINDOW_DRAW_TEXT, win, pill_x + 7, pill_y + 4,
                0x00FFFFFF, 0xffffffffL, "B");
        char shown[URL_CAP];
        snprintf(shown, sizeof(shown), "%s", urlbar);
        int maxc = (pill_w - 28) / CHAR_W;
        if (maxc < 0) maxc = 0;
        if ((int)strlen(shown) > maxc) shown[maxc] = '\0';
        syscall(SYS_WINDOW_DRAW_TEXT, win, pill_x + 24, pill_y + 5,
                FG_BAR, 0x001E2029, shown);
        /* cursor */
        {
            int cx = pill_x + 24 + url_len * CHAR_W;
            if (cx < pill_x + pill_w - 4) {
                for (int dy = 0; dy < CHAR_H; dy++)
                    for (int dx = 0; dx < 2; dx++) {
                        int sx = cx + dx, sy = pill_y + 5 + dy;
                        if (sx >= 0 && sx < (int)win_w && sy >= 0 && sy < (int)win_h)
                            px[sy * win_w + sx] = FG_BAR;
                    }
            }
        }
    }
    /* Bookmarks bar: grid glyph + placeholder or saved marks. */
    int bmy = top + NAV_H;
    bar_rect(0, bmy, (int)win_w, BM_H, 0x00282A36);
    bar_rect(6, bmy + 4, 4, 4, 0x00BBBBBB);
    bar_rect(12, bmy + 4, 4, 4, 0x00BBBBBB);
    bar_rect(6, bmy + 10, 4, 4, 0x00BBBBBB);
    bar_rect(12, bmy + 10, 4, 4, 0x00BBBBBB);
    if (nmarks == 0) {
        syscall(SYS_WINDOW_DRAW_TEXT, win, 26, bmy + 4, FG_DIM, 0x00282A36,
                "For quick access, place your bookmarks here.");
    } else {
        int mx = 90;
        for (int i = 0; i < nmarks; i++) {
            char host[64], port[16], path[URL_CAP], hshow[40];
            int sec = 0;
            mark_x[i] = mx;
            if (parse_url(marks[i], host, sizeof(host), port, sizeof(port),
                          path, sizeof(path), &sec) == 0)
                snprintf(hshow, sizeof(hshow), "%.36s", host);
            else
                snprintf(hshow, sizeof(hshow), "%.36s", marks[i]);
            syscall(SYS_WINDOW_DRAW_TEXT, win, mx, bmy + 4, FG_LINK,
                    0x00282A36, hshow);
            mx += (int)strlen(hshow) * CHAR_W + 24;
        }
    }
}

/* Renders the current page state (called after layout and on input). */
static void render(void) {
    if (!win_buf) return;
    unsigned int *px = (unsigned int *)win_buf;
    for (unsigned i = 0; i < win_w * win_h; i++) px[i] = BG_MAIN;
    /* Page rows as per-run colored text; links in link color. */
    {
        int rows = ((int)win_h - CHROME_H - STATUS_H) / CHAR_H;
        char run[LINE_COLS + 1];
        for (int r = 0; r < rows; r++) {
            int lr = scroll + r;
            if (lr < 0 || lr >= nlines) continue;
            const char *t = lines[lr].text;
            if (!t[0]) continue;
            if (lines[lr].nrun == 0) {
                syscall(SYS_WINDOW_DRAW_TEXT, win, 0, CHROME_H + r * CHAR_H,
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
                syscall(SYS_WINDOW_DRAW_TEXT, win, c0 * CHAR_W, CHROME_H + r * CHAR_H,
                        li >= 0 ? FG_LINK : FG_TEXT, BG_MAIN, run);
            }
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
            snprintf(st, sizeof(st), "%s [+%d script%s%s]", status,
                     nscripts, nscripts == 1 ? "" : "s",
                     page_js ? ", js ran" : ", no JS engine");
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
    int rows = ((int)win_h - CHROME_H - STATUS_H) / CHAR_H;
    int r = (py - CHROME_H) / CHAR_H;
    int c = px / CHAR_W;
    if (r < 0 || r >= rows) return;
    int lr = scroll + r;
    if (lr < 0 || lr >= nlines) return;
    for (int k = 0; k < nlinks; k++) {
        if (links[k].row == lr && c >= links[k].c0 && c < links[k].c1) {
            if (links[k].field) {
                /* Form field: text focuses, submit clicks through. */
                const char *type = dom_attr(links[k].field, "type");
                if (type && (strcasecmp(type, "submit") == 0 ||
                             strcasecmp(type, "button") == 0)) {
                    submit_form(links[k].field);
                } else {
                    focused_input = links[k].field;
                    relayout();
                    present();
                }
                return;
            }
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

/* Submits the form enclosing a node (GET): action + named inputs. */
static void submit_form(struct dom_node *from) {
    struct dom_node *f = from;
    while (f && f->tag != TAG_FORM) f = f->parent;
    char action[URL_CAP] = {0};
    if (f) {
        const char *a = dom_attr(f, "action");
        if (a) snprintf(action, sizeof(action), "%s", a);
    }
    if (!action[0]) snprintf(action, sizeof(action), "%s", urlbar);
    /* Collect name=value pairs under the form (or the whole page). */
    static char query[2048];
    query[0] = '\0';
    struct dom_node *scope = f ? f : (page_doc ? page_doc->root : NULL);
    if (scope) {
        struct dom_node *stack[256];
        int sp = 0;
        stack[sp++] = scope;
        while (sp > 0) {
            struct dom_node *n = stack[--sp];
            if (n->tag == TAG_INPUT) {
                const char *type = dom_attr(n, "type");
                int is_button = type && (strcasecmp(type, "submit") == 0 ||
                                         strcasecmp(type, "button") == 0);
                const char *nm = dom_attr(n, "name");
                if (!is_button && nm && nm[0]) {
                    const char *v = dom_attr(n, "value");
                    if (!v) v = "";
                    char pair[512];
                    size_t pi = 0;
                    pi += (size_t)snprintf(pair + pi, sizeof(pair) - pi, "%s%s=",
                                           query[0] ? "&" : "", nm);
                    for (const char *s = v; *s && pi + 1 < sizeof(pair); s++)
                        pair[pi++] = *s == ' ' ? '+' : *s;
                    pair[pi] = '\0';
                    if (strlen(query) + strlen(pair) < sizeof(query) - 1)
                        strcat(query, pair);
                }
            }
            for (int i = n->nkids - 1; i >= 0; i--) {
                if (sp < 256) stack[sp++] = n->kids[i];
            }
        }
    }
    char target[URL_CAP];
    {
        char base[URL_CAP];
        snprintf(base, sizeof(base), "%s", urlbar);
        char merged[URL_CAP * 2];
        snprintf(merged, sizeof(merged), "%s%s%s", action,
                 query[0] ? (strchr(action, '?') ? "&" : "?") : "", query);
        merged[sizeof(merged) - 1] = '\0';
        resolve_url(base, merged, target, sizeof(target));
    }
    focused_input = NULL;
    navigate(target, 1);
    present();
}

static void push_fwd(const char *url) {
    if (nfwd >= MAX_HIST) {
        memmove(fwd[0], fwd[1], sizeof(fwd[0]) * (MAX_HIST - 1));
        nfwd = MAX_HIST - 1;
    }
    snprintf(fwd[nfwd++], URL_CAP, "%s", url);
}

static void go_back(void) {
    if (nhist == 0) return;
    if (urlbar[0]) push_fwd(urlbar);
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

static void go_forward(void) {
    if (nfwd == 0) return;
    if (urlbar[0]) push_hist(urlbar);
    char next[URL_CAP];
    snprintf(next, sizeof(next), "%s", fwd[--nfwd]);
    snprintf(urlbar, sizeof(urlbar), "%s", next);
    url_len = (int)strlen(urlbar);
    if (fetch_page(next) == 0) {
        const char *sep = strstr(body, "\r\n\r\n");
        layout_html(sep ? sep + 4 : body);
    }
    present();
}

static void go_home(void) {
    navigate("https://www.google.com/", 1);
}

static void reload(void) {
    if (!urlbar[0]) return;
    navigate(urlbar, 0);
    present();
}

/* Star button: remember the current page on the bookmarks bar. */
static void toggle_mark(void) {
    if (!urlbar[0]) return;
    for (int i = 0; i < nmarks; i++) {
        if (strcmp(marks[i], urlbar) == 0) {
            snprintf(status, sizeof(status), "already bookmarked");
            present();
            return;
        }
    }
    if (nmarks >= 3) {
        snprintf(status, sizeof(status), "bookmarks bar is full (3)");
        present();
        return;
    }
    snprintf(marks[nmarks++], URL_CAP, "%s", urlbar);
    snprintf(status, sizeof(status), "bookmarked");
    present();
}

/* (Re)builds the window for a WxH frame: startup and host resizes. */
static int build_window(unsigned w, unsigned h) {
    if (w < 200 || h < 120 || w > 2048 || h > 2048) return -1;
    if (win >= 0) syscall(SYS_WINDOW_DESTROY, win, 0, 0, 0, 0, 0);
    win_w = w;
    win_h = h;
    win = (int)syscall(SYS_WINDOW_CREATE, win_w, win_h, 0, 0, 0, 0);
    if (win < 0) return -1;
    struct window_info wi;
    win_buf = (unsigned long)syscall(SYS_WINDOW_MAP, win, &wi, 0, 0, 0, 0);
    if (win_buf == 0) return -1;
    win_w = wi.width;
    win_h = wi.height;
    syscall(SYS_WINDOW_SET_TITLE, win, "browser", 0, 0, 0, 0);
    syscall(SYS_WINDOW_FOCUS, win, 0, 0, 0, 0, 0);
    return 0;
}

int main(int argc, char **argv) {
    struct display_info di;
    if ((long)syscall(SYS_DISPLAY_INFO, &di, 0, 0, 0, 0, 0) < 0) return die("display_info");
    if (di.width == 0 || di.height == 0) return 1;

    if (build_window(di.width, di.height) < 0) return die("window_create");

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

    const char *start = argc > 1 ? argv[1] : "https://www.google.com/";
    fprintf(stderr, "browser: start %s\n", start);
    snprintf(urlbar, sizeof(urlbar), "%s", start);
    url_len = (int)strlen(urlbar);
    /* Through navigate so redirects resolve the same way as typed URLs. */
    navigate(start, 0);
    if (nlines == 0)
        layout_html("<html><body><p>Type a URL above and press Return.</p></body></html>");
    present();

    /* Embedded mode follows the desktop's app area (see geom file). */
    int embedded = getenv("PARASYTEOS_EMBED_PARENT") != NULL;
    int geom_tick = 0;
    struct pollfd pfd = { .fd = input_fd, .events = POLLIN };
    for (;;) {
        /* Reap downloaded apps that ran and exited. */
        int st;
        while (waitpid(-1, &st, WNOHANG) > 0) {}
        /* Page timers (setTimeout/setInterval) fire here; the tree may
         * have mutated, so re-layout before repainting. */
        if (page_js && jsdom_poll(page_js)) {
            relayout();
            present();
        }
        /* Every ~3s, check whether the desktop resized under us. */
        if (embedded && ++geom_tick >= 30) {
            geom_tick = 0;
            FILE *gf = fopen("/winserv/desktop/geom", "r");
            if (gf) {
                unsigned gw = 0, gh = 0;
                if (fscanf(gf, "%ux%u", &gw, &gh) == 2 &&
                    gw >= 200 && gh >= 120 && gw <= 2048 && gh <= 2048 &&
                    (gw != win_w || gh != win_h)) {
                    syscall(SYS_WINDOW_RESIZE, win, gw, gh, 0, 0, 0, 0);
                    if (build_window(gw, gh) == 0) {
                        relayout();
                        present();
                    }
                }
                fclose(gf);
            }
        }
        int ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            struct input_event ev;
            ssize_t n = read(input_fd, &ev, sizeof(ev));
            if (n != (ssize_t)sizeof(ev)) continue;
            if (ev.kind == EV_CLOSE) break;
            if (ev.kind == EV_RESIZE) {
                /* Host resized the window: rebuild the buffer and
                 * re-render the current page into it. */
                if (build_window(ev.width, ev.height) == 0) {
                    relayout();
                    int rows = ((int)win_h - CHROME_H - STATUS_H) / CHAR_H;
                    int max = nlines - rows;
                    if (max < 0) max = 0;
                    if (scroll > max) scroll = max;
                    present();
                }
                continue;
            }
            if (ev.kind == EV_MOUSEUP && ev.button == 1 && dragging) {
                dragging = 0;
                continue;
            }
            if (ev.kind == EV_MOUSEMOVE && dragging) {
                int nx = own_x + ev.x - grab_x;
                int ny = own_y + ev.y - grab_y;
                if (syscall(SYS_WINDOW_MOVE, win, nx, ny, 0, 0, 0, 0) == 0) {
                    own_x = nx;
                    own_y = ny;
                }
                continue;
            }
            if (ev.kind == EV_MOUSEDOWN && ev.button == 1) {
                if (ev.y < TITLE_H) {
                    /* Title strip: close box or drag handle. */
                    if (ev.x >= (int)win_w - 24) {
                        break;
                    }
                    dragging = 1;
                    grab_x = ev.x;
                    grab_y = ev.y;
                } else if (ev.y < TITLE_H + NAV_H) {
                    /* Nav row: back fwd reload home ... star. */
                    if (ev.x < 21) go_back();
                    else if (ev.x < 41) go_forward();
                    else if (ev.x < 61) reload();
                    else if (ev.x < 81) go_home();
                    else if (ev.x >= (int)win_w - 28) toggle_mark();
                    /* Elsewhere on the row is the URL pill: typing
                     * already goes there, so focus needs no action. */
                } else if (ev.y < CHROME_H) {
                    /* Bookmarks row: follow a saved mark. */
                    for (int i = 0; i < nmarks; i++) {
                        char host[64], port[16], path[URL_CAP], hshow[40];
                        int sec = 0;
                        if (parse_url(marks[i], host, sizeof(host), port,
                                      sizeof(port), path, sizeof(path),
                                      &sec) == 0)
                            snprintf(hshow, sizeof(hshow), "%.36s", host);
                        else
                            snprintf(hshow, sizeof(hshow), "%.36s", marks[i]);
                        int x0 = mark_x[i];
                        int x1 = x0 + (int)strlen(hshow) * CHAR_W;
                        if (ev.x >= x0 && ev.x < x1) {
                            navigate(marks[i], 1);
                            present();
                            break;
                        }
                    }
                } else {
                    click_page(ev.x, ev.y);
                }
                continue;
            }
            if (ev.kind != EV_KEYDOWN) continue;
            long k = ev.x;
            if (focused_input) {
                /* Typing goes to the focused form field. */
                if ((ev.mods & MOD_CTRL) && (k == 'u' || k == 'U')) {
                    dom_set_attr(focused_input, "value", "");
                    relayout();
                    present();
                    continue;
                }
                if (k == KEY_RETURN) {
                    submit_form(focused_input);
                } else if (k == KEY_BS) {
                    const char *v = dom_attr(focused_input, "value");
                    if (v && v[0]) {
                        char nb[256];
                        snprintf(nb, sizeof(nb), "%s", v);
                        nb[strlen(nb) - 1] = '\0';
                        dom_set_attr(focused_input, "value", nb);
                        relayout();
                        present();
                    }
                } else if (k == KEY_ESC) {
                    focused_input = NULL;
                    relayout();
                    present();
                } else if (k >= 0x20 && k < 0x7f && !(ev.mods & ~1)) {
                    const char *v = dom_attr(focused_input, "value");
                    if (!v) v = "";
                    if (strlen(v) < 200) {
                        char nb[256];
                        snprintf(nb, sizeof(nb), "%s%c", v, (char)k);
                        dom_set_attr(focused_input, "value", nb);
                        relayout();
                        present();
                    }
                }
                continue;
            }
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
                int rows = ((int)win_h - CHROME_H - STATUS_H) / CHAR_H;
                scroll += rows - 1;
                int max = nlines - rows;
                if (max < 0) max = 0;
                if (scroll > max) scroll = max;
                present();
            } else if (k == KEY_PRIOR) {
                int rows = ((int)win_h - CHROME_H - STATUS_H) / CHAR_H;
                scroll -= rows - 1;
                if (scroll < 0) scroll = 0;
                present();
            } else if (k == KEY_UP) {
                /* Up/Down share one keysym on this host mapping, so both
                 * arrows scroll by a line. */
                scroll += 1;
                int rows = ((int)win_h - CHROME_H - STATUS_H) / CHAR_H;
                int max = nlines - rows;
                if (max < 0) max = 0;
                if (scroll > max) scroll = max;
                present();
            } else if (k >= 0x20 && k < 0x7f && !(ev.mods & ~1)) {
                /* Shift is consumed into the keysym above; ctrl/alt
                 * combos stay reserved for shortcuts. */
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
