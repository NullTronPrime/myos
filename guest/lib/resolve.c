/* resolve: tiny static-friendly IPv4 resolver, see resolve.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
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

/* First IPv4 nameserver in /etc/resolv.conf. */
static int resolv_server(struct in_addr *out) {
    static char file[4096];
    if (read_small("/etc/resolv.conf", file, sizeof(file)) < 0) return -1;
    char *save = NULL;
    for (char *line = strtok_r(file, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "nameserver", 10) != 0) continue;
        line += 10;
        while (*line == ' ' || *line == '\t') line++;
        char *end = line + strcspn(line, " \t\r\n#;");
        char saved = *end;
        *end = '\0';
        int ok = inet_pton(AF_INET, line, out) == 1;
        *end = saved;
        if (ok) return 0;
    }
    return -1;
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

/* One DNS A query/response round trip over UDP. */
static int dns_query(const struct in_addr *server, const char *name, struct in_addr *out) {
    unsigned char q[512];
    size_t qlen = 0;
    unsigned short txid = (unsigned short)(getpid() ^ 0x5bd1);
    q[qlen++] = (unsigned char)(txid >> 8);
    q[qlen++] = (unsigned char)txid;
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
        if (ll == 0 || ll > 63 || qlen + 1 + ll + 4 >= sizeof(q)) return -1;
        q[qlen++] = (unsigned char)ll;
        memcpy(q + qlen, s, ll);
        qlen += ll;
        s += ll + (dot ? 1 : 0);
        if (!dot) break;
    }
    q[qlen++] = 0x00;
    q[qlen++] = 0x00; q[qlen++] = 0x01; /* A */
    q[qlen++] = 0x00; q[qlen++] = 0x01; /* IN */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr = *server;
    dst.sin_port = 0x3500; /* 53 in network order */
    for (int attempt = 0; attempt < 3; attempt++) {
        if (sendto(fd, q, qlen, 0, (struct sockaddr *)&dst, sizeof(dst)) != (ssize_t)qlen)
            continue;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 2000) <= 0) continue;
        unsigned char r[512];
        ssize_t n = recv(fd, r, sizeof(r), 0);
        if (n < 12) continue;
        if (r[0] != (txid >> 8) || r[1] != (txid & 0xff)) continue;
        if (r[3] & 0x0f) continue; /* RCODE != 0 */
        unsigned qd = (rd16(r + 4));
        unsigned an = (rd16(r + 6));
        size_t at = 12;
        for (unsigned i = 0; i < qd; i++) {
            if (skip_name(r, (size_t)n, &at) < 0 || at + 4 > (size_t)n) break;
            at += 4;
        }
        for (unsigned i = 0; i < an; i++) {
            if (skip_name(r, (size_t)n, &at) < 0 || at + 10 > (size_t)n) break;
            unsigned short type = rd16(r + at);
            unsigned short class = rd16(r + at + 2);
            unsigned short rdlen = rd16(r + at + 8);
            at += 10;
            if (at + rdlen > (size_t)n) break;
            if (type == 1 && class == 1 && rdlen == 4) {
                memcpy(&out->s_addr, r + at, 4);
                close(fd);
                return 0;
            }
            at += rdlen;
        }
    }
    close(fd);
    return -1;
}

int resolve_host(const char *name, struct in_addr *out) {
    if (!name || !*name || !out) return -1;
    if (inet_pton(AF_INET, name, out) == 1) return 0;
    if (hosts_lookup(name, out) == 0) return 0;
    struct in_addr ns;
    if (resolv_server(&ns) == 0 && dns_query(&ns, name, out) == 0) return 0;
    return -1;
}
