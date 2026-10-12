/* resolve: tiny static-friendly IPv4 resolver, see resolve.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "resolve.h"

/* Reads up to cap-1 bytes of a small config file; NUL-terminates. */
static ssize_t read_small(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    ssize_t n;
    while (got + 1 < cap && (n = read(fd, buf + got, cap - 1 - got)) > 0)
        got += (size_t)n;
    close(fd);
    if (n < 0) return -1;
    buf[got] = '\0';
    return (ssize_t)got;
}

/* /etc/hosts lookup: "ip name [aliases...]". */
static int hosts_lookup(const char *name, struct in_addr *out) {
    static char file[8192];
    if (read_small("/etc/hosts", file, sizeof(file)) < 0) return -1;
    char *save = NULL;
    for (char *line = strtok_r(file, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '\0' || *line == '#') continue;
        char *s = NULL;
        char *ip = strtok_r(line, " \t", &s);
        if (!ip) continue;
        char *hit = NULL;
        for (char *h = strtok_r(NULL, " \t", &s); h; h = strtok_r(NULL, " \t", &s)) {
            if (strcasecmp(h, name) == 0) {
                hit = h;
                break;
            }
        }
        if (hit && inet_pton(AF_INET, ip, out) == 1) return 0;
    }
    return -1;
}

/* All IPv4 nameservers in /etc/resolv.conf, in order. Trying each in
 * turn matters: the first entry is often a local proxy that flaps, with a
 * working fallback (8.8.8.8) listed second. */
#define MAXNS 4
static int resolv_servers(struct in_addr *out, int cap) {
    static char file[4096];
    if (read_small("/etc/resolv.conf", file, sizeof(file)) < 0) return 0;
    int n = 0;
    char *save = NULL;
    for (char *line = strtok_r(file, "\n", &save); line && n < cap; line = strtok_r(NULL, "\n", &save)) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "nameserver", 10) != 0) continue;
        line += 10;
        while (*line == ' ' || *line == '\t') line++;
        char *end = line + strcspn(line, " \t\r\n#;");
        char saved = *end;
        *end = '\0';
        int ok = inet_pton(AF_INET, line, &out[n]) == 1;
        *end = saved;
        if (ok) n++;
    }
    return n;
}

/* Skips a (possibly compressed) DNS name; *at advances past it. */
static int skip_name(const unsigned char *msg, size_t mlen, size_t *at) {
    size_t i = *at;
    int jumps = 0;
    while (i < mlen) {
        unsigned char c = msg[i];
        if ((c & 0xc0) == 0xc0) {
            i += 2;
            jumps++;
            if (jumps > 8) return -1;
            if (jumps == 1) *at = i;
            /* Follow for bounds only; content unneeded while skipping. */
            size_t tgt = ((size_t)(c & 0x3f) << 8) | msg[i - 1];
            if (tgt >= mlen) return -1;
            continue;
        }
        if (c == 0) {
            if (jumps == 0) *at = i + 1;
            return 0;
        }
        i += 1 + c;
        if (jumps == 0) *at = i;
    }
    return -1;
}

static unsigned short rd16(const unsigned char *p) {
    return (unsigned short)((p[0] << 8) | p[1]);
}

/* Builds a DNS A query; returns its length (txid written through). */
static int dns_build(const char *name, unsigned char *q, size_t cap, unsigned short *txid) {
    size_t qlen = 0;
    *txid = (unsigned short)(getpid() ^ 0x5bd1);
    q[qlen++] = (unsigned char)(*txid >> 8);
    q[qlen++] = (unsigned char)*txid;
    q[qlen++] = 0x01; /* RD */
    q[qlen++] = 0x00;
    q[qlen++] = 0x00; q[qlen++] = 0x01; /* QDCOUNT */
    q[qlen++] = 0x00; q[qlen++] = 0x00;
    q[qlen++] = 0x00; q[qlen++] = 0x00;
    q[qlen++] = 0x00; q[qlen++] = 0x00;
    /* QNAME labels. */
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t ll = dot ? (size_t)(dot - s) : strlen(s);
        if (ll == 0 || ll > 63 || qlen + 1 + ll + 4 >= cap) return -1;
        q[qlen++] = (unsigned char)ll;
        memcpy(q + qlen, s, ll);
        qlen += ll;
        s += ll + (dot ? 1 : 0);
        if (!dot) break;
    }
    q[qlen++] = 0x00;
    q[qlen++] = 0x00; q[qlen++] = 0x01; /* A */
    q[qlen++] = 0x00; q[qlen++] = 0x01; /* IN */
    return (int)qlen;
}

/* Scans a DNS response for the first A record. */
static int dns_parse(const unsigned char *r, size_t n, unsigned short txid, struct in_addr *out) {
    if (n < 12) return -1;
    if (r[0] != (txid >> 8) || r[1] != (txid & 0xff)) return -1;
    if (r[3] & 0x0f) return -1; /* RCODE != 0 */
    unsigned qd = (rd16(r + 4));
    unsigned an = (rd16(r + 6));
    size_t at = 12;
    for (unsigned i = 0; i < qd; i++) {
        if (skip_name(r, n, &at) < 0 || at + 4 > n) return -1;
        at += 4;
    }
    for (unsigned i = 0; i < an; i++) {
        if (skip_name(r, n, &at) < 0 || at + 10 > n) return -1;
        unsigned short type = rd16(r + at);
        unsigned short class = rd16(r + at + 2);
        unsigned short rdlen = rd16(r + at + 8);
        at += 10;
        if (at + rdlen > n) return -1;
        if (type == 1 && class == 1 && rdlen == 4) {
            memcpy(&out->s_addr, r + at, 4);
            return 0;
        }
        at += rdlen;
    }
    return -1;
}

/* Reads exactly n bytes (for TCP-framed DNS) or returns -1. */
static int read_n(int fd, unsigned char *b, size_t n) {
    while (n > 0) {
        ssize_t r = recv(fd, b, n, 0);
        if (r <= 0) return -1;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

/* One DNS A query/response round trip: UDP first, then TCP fallback
 * (length-prefixed framing). UDP alone strands guests on networks that
 * pass TCP but drop datagrams. */
static int dns_query(const struct in_addr *server, const char *name, struct in_addr *out) {
    unsigned char q[512];
    unsigned short txid = 0;
    int qlen = dns_build(name, q, sizeof(q), &txid);
    if (qlen < 0) return -1;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr = *server;
    dst.sin_port = 0x3500; /* 53 in network order */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        for (int attempt = 0; attempt < 2; attempt++) {
            if (sendto(fd, q, (size_t)qlen, 0, (struct sockaddr *)&dst, sizeof(dst)) != qlen)
                continue;
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, 1500) <= 0) continue;
            unsigned char r[512];
            ssize_t n = recv(fd, r, sizeof(r), 0);
            if (n > 0 && dns_parse(r, (size_t)n, txid, out) == 0) {
                close(fd);
                return 0;
            }
        }
        close(fd);
    }

    /* TCP fallback: same query with a 2-byte length prefix. The
     * connect is bounded (a blackholed :53 would stall for minutes). */
    close(fd);
    fd = tcp_connect_timeout(&dst.sin_addr, 53, 8000);
    if (fd < 0) return -1;
    unsigned char framed[514];
    framed[0] = (unsigned char)(qlen >> 8);
    framed[1] = (unsigned char)qlen;
    memcpy(framed + 2, q, (size_t)qlen);
    size_t left = (size_t)qlen + 2;
    const unsigned char *p = framed;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += n;
        left -= (size_t)n;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ok = -1;
    if (poll(&pfd, 1, 5000) > 0) {
        unsigned char lh[2];
        if (read_n(fd, lh, 2) == 0) {
            size_t rlen = ((size_t)lh[0] << 8) | lh[1];
            if (rlen <= 4096) {
                static unsigned char r[4096];
                if (read_n(fd, r, rlen) == 0 && dns_parse(r, rlen, txid, out) == 0)
                    ok = 0;
            }
        }
    }
    close(fd);
    return ok;
}

int resolve_host(const char *name, struct in_addr *out) {
    if (!name || !*name || !out) return -1;
    if (inet_pton(AF_INET, name, out) == 1) return 0;
    if (hosts_lookup(name, out) == 0) return 0;
    struct in_addr ns[MAXNS];
    int nns = resolv_servers(ns, MAXNS);
    for (int i = 0; i < nns; i++)
        if (dns_query(&ns[i], name, out) == 0) return 0;
    return -1;
}

/* Bounds every read and write: servers that accept and then go silent
 * (tarpits, throttles) would otherwise stall the guest forever. Callers
 * already tolerate truncated responses. */
static void sock_timeout(int fd) {
    struct timeval tv;
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int tcp_connect_timeout(const struct in_addr *addr, int port, int ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    /* Non-blocking connect so the wait is bounded by poll, not by the
     * kernel's minutes-long SYN retry schedule. */
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr = *addr;
    sa.sin_port = (unsigned short)(((port & 0xff) << 8) | ((port >> 8) & 0xff));
    int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0 && errno != EINPROGRESS) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    if (r < 0) {
        /* Retry on EINTR (signals steal the wait); the deadline keeps
         * the total bounded. */
        long left = ms;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (;;) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, (int)left);
            if (pr > 0) break;
            if (pr == 0) {
                close(fd);
                errno = ETIMEDOUT;
                return -1;
            }
            if (errno != EINTR) {
                int e = errno;
                close(fd);
                errno = e;
                return -1;
            }
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long dt = (now.tv_sec - t0.tv_sec) * 1000L +
                      (now.tv_nsec - t0.tv_nsec) / 1000000L;
            left = (long)ms - dt;
            if (left <= 0) {
                close(fd);
                errno = ETIMEDOUT;
                return -1;
            }
        }
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) {
            int e = errno;
            close(fd);
            errno = e;
            return -1;
        }
        if (err != 0) {
            close(fd);
            errno = err;
            return -1;
        }
    }
    /* Back to blocking: the TLS and HTTP layers read synchronously. */
    if (fcntl(fd, F_SETFL, fl) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    sock_timeout(fd);
    return fd;
}
