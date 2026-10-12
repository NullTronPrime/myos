/* fetch: minimal HTTP client proving guest networking works.
 *
 * Resolves a hostname (exercises the bridged /etc/resolv.conf path),
 * connects over TCP, sends an HTTP/1.1 request and prints the response.
 * Usage: fetch <host> [port] [path] [--body]
 * An https:// URL prefix selects TLS (default :443). --body also dumps
 * the response body to stdout (headers always print).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "lib/resolve.h"
#include "lib/tls.h"

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "example.com";
    const char *port = argc > 2 ? argv[2] : "80";
    const char *path = argc > 3 ? argv[3] : "/";
    int secure = 0;

    /* Accept https:// URLs as well as bare hosts. */
    static char hostbuf[256];
    static char portbuf[16];
    static char pathbuf[512];
    /* A trailing --body flag is not a positional argument. */
    int pos = argc;
    if (pos > 1 && strcmp(argv[pos - 1], "--body") == 0) pos--;
    if (strncmp(host, "https://", 8) == 0) {
        secure = 1;
        snprintf(hostbuf, sizeof(hostbuf), "%s", host + 8);
        char *slash = strchr(hostbuf, '/');
        if (slash) {
            if (pos <= 3) {
                snprintf(pathbuf, sizeof(pathbuf), "%s", slash);
                path = pathbuf;
            }
            *slash = '\0';
        }
        /* Split an explicit host:port. */
        char *colon = strchr(hostbuf, ':');
        if (colon) {
            *colon = '\0';
            if (pos <= 2) {
                snprintf(portbuf, sizeof(portbuf), "%s", colon + 1);
                port = portbuf;
            }
        } else if (pos <= 2) {
            port = "443";
        }
        host = hostbuf;
    }

    /* Static-friendly resolution (no NSS in a static guest). */
    struct in_addr addr;
    if (resolve_host(host, &addr) < 0) {
        fprintf(stderr, "fetch: resolve %s\n", host);
        return 1;
    }
    int pnum = atoi(port);
    if (pnum <= 0 || pnum > 65535) {
        fprintf(stderr, "fetch: bad port\n");
        return 1;
    }
    int fd = tcp_connect_timeout(&addr, pnum, 10000);
    if (fd < 0) {
        perror("fetch: connect");
        return 1;
    }

    struct tls_ctx tls;
    memset(&tls, 0, sizeof(tls));
    if (secure) {
        char err[128] = {0};
        if (tls_handshake(fd, host, &tls, err, sizeof(err)) < 0) {
            fprintf(stderr, "fetch: tls: %s\n", err);
            close(fd);
            return 1;
        }
        fprintf(stderr, "fetch: https to %s%s\n", host, err[0] ? err : "");
    }

    char req[1024];
    /* HTTP/1.1: some servers (DuckDuckGo's nginx) answer 400 to 1.0. */
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) parasyteos-fetch\r\nConnection: close\r\n\r\n",
             path, host);
    size_t left = strlen(req);
    const char *p = req;
    while (left > 0) {
        ssize_t n = secure ? tls_write(&tls, p, left) : send(fd, p, left, 0);
        if (n <= 0) {
            if (secure)
                fprintf(stderr, "fetch: tls send\n");
            else
                perror("fetch: send");
            tls_free(&tls);
            close(fd);
            return 1;
        }
        p += n;
        left -= (size_t)n;
    }

    size_t total = 0;
    int lines = 0;
    /* Guests start with an empty environment by design, so debug switches
     * ride on argv, not env. */
    int dump = 0;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--body") == 0) dump = 1;
    char buf[4096];
    ssize_t n;
    for (;;) {
        n = secure ? tls_read(&tls, buf, sizeof(buf) - 1) : recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        total += (size_t)n;
        if (dump) fwrite(buf, 1, (size_t)n, stdout);
        // Print the status line and headers (up to the first blank line).
        if (lines < 12) {
            buf[n] = '\0';
            char *s = buf;
            while (*s && lines < 12) {
                char *e = strchr(s, '\n');
                if (e) *e = '\0';
                printf("%s\n", s);
                lines++;
                if (!e) break;
                s = e + 1;
                if (*s == '\r') s++;
                if (*s == '\n' || *s == '\0') {
                    lines = 12;
                    break;
                }
            }
        }
    }
    if (n < 0) {
        if (secure)
            fprintf(stderr, "fetch: tls recv\n");
        else
            perror("fetch: recv");
    }
    fprintf(stderr, "fetch: %zu bytes from %s\n", total, host);
    tls_free(&tls);
    close(fd);
    return total > 0 ? 0 : 1;
}
