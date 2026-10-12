/* tls: a minimal TLS 1.2 client for myos guests (guest/lib/tls.c).
 *
 * Offers TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 first, falling back to
 * TLS_RSA_WITH_AES_128_CBC_SHA. Static-link friendly: only
 * read/write/open/close, malloc and time from libc; entropy from
 * /dev/urandom (bridged read-only).
 *
 * Toy-grade on purpose: RSA certificates only (ECDSA chains fail), no
 * session resumption, certificate hostname/expiry checks but NO
 * chain-of-trust validation (there is nowhere to store trust anchors
 * yet). Enough to fetch real pages where the OS has connectivity; not a
 * general trust story. See the header of tls.c for the full accounting.
 */
#ifndef MYOS_TLS_H
#define MYOS_TLS_H

#include <stddef.h>
#include <sys/types.h>

struct tls_ctx {
    int fd;
    unsigned long long read_seq;
    unsigned long long write_seq;
    /* Negotiated suite: 0x002f (CBC) or 0xc02f (GCM). */
    int suite;
    unsigned char client_mac[20];
    unsigned char server_mac[20];
    unsigned char client_key[16];
    unsigned char server_key[16];
    /* GCM traffic keys + salts (suite 0xc02f only). */
    unsigned char cwkey[16];
    unsigned char swkey[16];
    unsigned char cwiv[4];
    unsigned char swiv[4];
    /* Leftover decrypted application bytes. */
    unsigned char *pending;
    size_t pending_len;
    size_t pending_off;
};

/* Handshakes on a connected TCP fd. Returns 0 on success, -1 with `err`
 * describing the failure (certificate mismatch, decrypt failure, ...). */
int tls_handshake(int fd, const char *host, struct tls_ctx *t, char *err, size_t errcap);

/* Writes all n bytes (looping records) or returns -1. */
ssize_t tls_write(struct tls_ctx *t, const void *buf, size_t n);

/* Returns decrypted application bytes (at most n), 0 on clean close, -1
 * on error. May return less than a full record; call again for more. */
ssize_t tls_read(struct tls_ctx *t, void *buf, size_t n);

/* Frees pending buffers (does not close fd). */
void tls_free(struct tls_ctx *t);

#endif /* MYOS_TLS_H */
