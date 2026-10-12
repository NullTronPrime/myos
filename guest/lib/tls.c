/* tls: minimal TLS 1.2 client (ECDHE+RSA+GCM preferred, RSA+CBC fallback).
 *
 * Accounting of every cryptographic choice, so nobody mistakes this for a
 * general TLS stack:
 *
 * - Two suites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (P-256, offered
 *   first) and TLS_RSA_WITH_AES_128_CBC_SHA (fallback). Servers offering
 *   neither fail the handshake; that is reported, not negotiated around.
 * - RSA certificates only: a server sending an ECDSA chain fails, and only
 *   rsa_pkcs1_sha256 signatures are offered/verified (servers that ignore
 *   signature_algorithms and sign with another hash fail too).
 * - Server authentication is hostname (+expiry sanity), not chain trust:
 *   there is no trust-anchor store in the guest yet, so a self-signed cert
 *   for the right name is accepted with a note. MITM by a wrong-host cert
 *   is rejected (CN/SAN must match). Server ECDHE points are validated
 *   on-curve before use.
 * - No session resumption, no renegotiation (a HelloRequest kills the
 *   connection), no compression, no TLS 1.3, TLS 1.2 record framing only.
 * - Schoolbook bignum + affine P-256, constant in shape but not hardened
 *   against side channels. Fine for a demo OS, not for secrets that
 *   matter.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include "tls.h"

#define TLS_VER_MAJOR 3
#define TLS_VER_MINOR 3 /* 3.3 on the wire == TLS 1.2 */
#define SUITE_RSA_AES128_SHA 0x002f
#define SUITE_ECDHE_RSA_AES128_GCM 0xc02f
#define REC_MAX 16384
#define TRANS_MAX 16384
#define CERT_MAX 8192

/* ---------------- utilities ---------------- */

static unsigned short rd16(const unsigned char *p) {
    return (unsigned short)((p[0] << 8) | p[1]);
}

static void wr16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

/* Reads exactly n bytes or returns -1. */
static int read_full(int fd, unsigned char *b, size_t n) {
    while (n > 0) {
        ssize_t r = recv(fd, b, n, 0);
        if (r <= 0) return -1;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

/* Writes exactly n bytes or returns -1. */
static int write_full(int fd, const unsigned char *b, size_t n) {
    while (n > 0) {
        ssize_t r = send(fd, b, n, 0);
        if (r <= 0) return -1;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

/* Fills n bytes from /dev/urandom (bridged read-only). Fatal if empty. */
static int rand_bytes(unsigned char *b, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    /* Plain read(): this fd is a file, not a socket. */
    while (n > 0) {
        ssize_t r = read(fd, b, n);
        if (r <= 0) {
            close(fd);
            return -1;
        }
        b += r;
        n -= (size_t)r;
    }
    close(fd);
    return 0;
}

/* ---------------- SHA-256 ---------------- */

struct sha256 {
    unsigned state[8];
    unsigned long long count;
    unsigned char buf[64];
    size_t buflen;
};

static const unsigned K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static unsigned ror(unsigned x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_block(struct sha256 *c, const unsigned char *p) {
    unsigned w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((unsigned)p[4 * i] << 24) | ((unsigned)p[4 * i + 1] << 16) |
               ((unsigned)p[4 * i + 2] << 8) | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        unsigned s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    {
        unsigned A = c->state[0], B = c->state[1], C = c->state[2], D = c->state[3];
        unsigned E = c->state[4], F = c->state[5], G = c->state[6], H = c->state[7];
        for (int i = 0; i < 64; i++) {
            unsigned S1 = ror(E, 6) ^ ror(E, 11) ^ ror(E, 25);
            unsigned ch = (E & F) ^ (~E & G);
            unsigned t1 = H + S1 + ch + K256[i] + w[i];
            unsigned S0 = ror(A, 2) ^ ror(A, 13) ^ ror(A, 22);
            unsigned maj = (A & B) ^ (A & C) ^ (B & C);
            unsigned t2 = S0 + maj;
            H = G;
            G = F;
            F = E;
            E = D + t1;
            D = C;
            C = B;
            B = A;
            A = t1 + t2;
        }
        c->state[0] += A;
        c->state[1] += B;
        c->state[2] += C;
        c->state[3] += D;
        c->state[4] += E;
        c->state[5] += F;
        c->state[6] += G;
        c->state[7] += H;
    }
}

static void sha256_init(struct sha256 *c) {
    c->state[0] = 0x6a09e667;
    c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372;
    c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f;
    c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab;
    c->state[7] = 0x5be0cd19;
    c->count = 0;
    c->buflen = 0;
}

static void sha256_update(struct sha256 *c, const unsigned char *p, size_t n) {
    c->count += n;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(struct sha256 *c, unsigned char out[32]) {
    unsigned long long bits = c->count * 8;
    unsigned char pad = 0x80;
    sha256_update(c, &pad, 1);
    unsigned char z = 0;
    while (c->buflen != 56) sha256_update(c, &z, 1);
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (56 - 8 * i));
    /* Bypass update() counting for the length word. */
    {
        unsigned char tmp[64];
        memcpy(tmp, c->buf, 56);
        memcpy(tmp + 56, lenb, 8);
        sha256_block(c, tmp);
        c->buflen = 0;
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (unsigned char)(c->state[i] >> 24);
        out[4 * i + 1] = (unsigned char)(c->state[i] >> 16);
        out[4 * i + 2] = (unsigned char)(c->state[i] >> 8);
        out[4 * i + 3] = (unsigned char)c->state[i];
    }
}

static void sha256_once(const unsigned char *p, size_t n, unsigned char out[32]) {
    struct sha256 c;
    sha256_init(&c);
    sha256_update(&c, p, n);
    sha256_final(&c, out);
}

/* HMAC-SHA256. */
static void hmac_sha256(const unsigned char *key, size_t klen, const unsigned char *msg, size_t mlen,
                        unsigned char out[32]) {
    unsigned char k[64] = {0};
    if (klen > 64) {
        sha256_once(key, klen, k);
    } else {
        memcpy(k, key, klen);
    }
    unsigned char ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    struct sha256 c;
    unsigned char inner[32];
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, mlen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

/* TLS PRF with SHA-256: out = P_hash(secret, label + seed). */
static void tls_prf(const unsigned char *secret, size_t slen, const char *label,
                    const unsigned char *seed, size_t seedlen, unsigned char *out, size_t olen) {
    size_t lablen = strlen(label);
    unsigned char seedbuf[256];
    if (lablen + seedlen > sizeof(seedbuf)) return;
    memcpy(seedbuf, label, lablen);
    memcpy(seedbuf + lablen, seed, seedlen);
    size_t tot = lablen + seedlen;
    unsigned char A[32];
    hmac_sha256(secret, slen, seedbuf, tot, A);
    while (olen > 0) {
        unsigned char chunk[32 + 256];
        memcpy(chunk, A, 32);
        memcpy(chunk + 32, seedbuf, tot);
        unsigned char h[32];
        hmac_sha256(secret, slen, chunk, 32 + tot, h);
        size_t take = olen < 32 ? olen : 32;
        memcpy(out, h, take);
        out += take;
        olen -= take;
        unsigned char nx[32];
        hmac_sha256(secret, slen, A, 32, nx);
        memcpy(A, nx, 32);
    }
}

/* ---------------- SHA-1 (record MACs only) ---------------- */

struct sha1 {
    unsigned state[5];
    unsigned long long count;
    unsigned char buf[64];
    size_t buflen;
};

static unsigned rol(unsigned x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_block(struct sha1 *c, const unsigned char *p) {
    unsigned w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((unsigned)p[4 * i] << 24) | ((unsigned)p[4 * i + 1] << 16) |
               ((unsigned)p[4 * i + 2] << 8) | p[4 * i + 3];
    for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    unsigned A = c->state[0], B = c->state[1], C = c->state[2], D = c->state[3], E = c->state[4];
    for (int i = 0; i < 80; i++) {
        unsigned f, k;
        if (i < 20) {
            f = (B & C) | (~B & D);
            k = 0x5a827999;
        } else if (i < 40) {
            f = B ^ C ^ D;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (B & C) | (B & D) | (C & D);
            k = 0x8f1bbcdc;
        } else {
            f = B ^ C ^ D;
            k = 0xca62c1d6;
        }
        unsigned t = rol(A, 5) + f + E + k + w[i];
        E = D;
        D = C;
        C = rol(B, 30);
        B = A;
        A = t;
    }
    c->state[0] += A;
    c->state[1] += B;
    c->state[2] += C;
    c->state[3] += D;
    c->state[4] += E;
}

static void sha1_init(struct sha1 *c) {
    c->state[0] = 0x67452301;
    c->state[1] = 0xefcdab89;
    c->state[2] = 0x98badcfe;
    c->state[3] = 0x10325476;
    c->state[4] = 0xc3d2e1f0;
    c->count = 0;
    c->buflen = 0;
}

static void sha1_update(struct sha1 *c, const unsigned char *p, size_t n) {
    c->count += n;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            sha1_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha1_final(struct sha1 *c, unsigned char out[20]) {
    unsigned long long bits = c->count * 8;
    unsigned char pad = 0x80;
    sha1_update(c, &pad, 1);
    unsigned char z = 0;
    while (c->buflen != 56) sha1_update(c, &z, 1);
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (56 - 8 * i));
    {
        unsigned char tmp[64];
        memcpy(tmp, c->buf, 56);
        memcpy(tmp + 56, lenb, 8);
        sha1_block(c, tmp);
        c->buflen = 0;
    }
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (unsigned char)(c->state[i] >> 24);
        out[4 * i + 1] = (unsigned char)(c->state[i] >> 16);
        out[4 * i + 2] = (unsigned char)(c->state[i] >> 8);
        out[4 * i + 3] = (unsigned char)c->state[i];
    }
}

static void hmac_sha1(const unsigned char *key, const unsigned char *msg, size_t mlen,
                      unsigned char out[20]) {
    unsigned char ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5c;
    }
    struct sha1 c;
    unsigned char inner[20];
    sha1_init(&c);
    sha1_update(&c, ipad, 64);
    sha1_update(&c, msg, mlen);
    sha1_final(&c, inner);
    sha1_init(&c);
    sha1_update(&c, opad, 64);
    sha1_update(&c, inner, 20);
    sha1_final(&c, out);
}

/* ---------------- AES-128 ---------------- */

static const unsigned char SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

static const unsigned char INVSBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
};

static const unsigned char RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

struct aes128 {
    unsigned char rk[11][16];
};

static void aes_key(struct aes128 *a, const unsigned char key[16]) {
    memcpy(a->rk[0], key, 16);
    for (int r = 1; r <= 10; r++) {
        unsigned char t[4];
        t[0] = a->rk[r - 1][13];
        t[1] = a->rk[r - 1][14];
        t[2] = a->rk[r - 1][15];
        t[3] = a->rk[r - 1][12];
        t[0] = SBOX[t[0]] ^ RCON[r - 1];
        t[1] = SBOX[t[1]];
        t[2] = SBOX[t[2]];
        t[3] = SBOX[t[3]];
        for (int i = 0; i < 16; i++) {
            if (i < 4)
                a->rk[r][i] = a->rk[r - 1][i] ^ t[i];
            else
                a->rk[r][i] = a->rk[r - 1][i] ^ a->rk[r][i - 4];
        }
    }
}

static unsigned char xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static void aes_enc_block(struct aes128 *a, const unsigned char in[16], unsigned char out[16]) {
    unsigned char s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ a->rk[0][i];
    for (int r = 1; r <= 10; r++) {
        for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        /* ShiftRows (column-major state). */
        unsigned char t[16];
        t[0] = s[0];
        t[4] = s[4];
        t[8] = s[8];
        t[12] = s[12];
        t[1] = s[5];
        t[5] = s[9];
        t[9] = s[13];
        t[13] = s[1];
        t[2] = s[10];
        t[6] = s[14];
        t[10] = s[2];
        t[14] = s[6];
        t[3] = s[15];
        t[7] = s[3];
        t[11] = s[7];
        t[15] = s[11];
        memcpy(s, t, 16);
        if (r < 10) {
            for (int c = 0; c < 4; c++) {
                unsigned char a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
                s[4 * c] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
                s[4 * c + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
                s[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
                s[4 * c + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
            }
        }
        for (int i = 0; i < 16; i++) s[i] ^= a->rk[r][i];
    }
    memcpy(out, s, 16);
}

static unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    while (b) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

static void aes_dec_block(struct aes128 *a, const unsigned char in[16], unsigned char out[16]) {
    unsigned char s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ a->rk[10][i];
    for (int r = 9; r >= 0; r--) {
        unsigned char t[16];
        t[0] = s[0];
        t[4] = s[4];
        t[8] = s[8];
        t[12] = s[12];
        t[1] = s[13];
        t[5] = s[1];
        t[9] = s[5];
        t[13] = s[9];
        t[2] = s[10];
        t[6] = s[14];
        t[10] = s[2];
        t[14] = s[6];
        t[3] = s[7];
        t[7] = s[11];
        t[11] = s[15];
        t[15] = s[3];
        for (int i = 0; i < 16; i++) t[i] = INVSBOX[t[i]];
        /* Straightforward order (AddKey before InvMix) rather than the
         * equivalent-key form, so the plain round keys apply as-is. */
        for (int i = 0; i < 16; i++) t[i] ^= a->rk[r][i];
        if (r > 0) {
            for (int c = 0; c < 4; c++) {
                unsigned char a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                s[4 * c] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
                s[4 * c + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
                s[4 * c + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
                s[4 * c + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
            }
        } else {
            memcpy(s, t, 16);
        }
    }
    memcpy(out, s, 16);
}

/* ---------------- bignum (schoolbook, 2048-bit max) ---------------- */

#define BN_MAX 72 /* limbs; headroom past 2048 bits */

struct bn {
    unsigned limbs[BN_MAX];
    int n; /* used limbs, no leading zeroes except value 0 (n=1) */
};

static void bn_norm(struct bn *a) {
    while (a->n > 1 && a->limbs[a->n - 1] == 0) a->n--;
}

static void bn_from_bytes(struct bn *a, const unsigned char *b, size_t n) {
    memset(a->limbs, 0, sizeof(a->limbs));
    a->n = (int)((n + 3) / 4);
    if (a->n > BN_MAX) a->n = BN_MAX;
    for (size_t i = 0; i < n && i / 4 < BN_MAX; i++) {
        a->limbs[i / 4] |= (unsigned)b[n - 1 - i] << (8 * (i % 4));
    }
    bn_norm(a);
}

static int bn_cmp(const struct bn *a, const struct bn *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (int i = a->n - 1; i >= 0; i--) {
        if (a->limbs[i] != b->limbs[i])
            return a->limbs[i] < b->limbs[i] ? -1 : 1;
    }
    return 0;
}

/* r = a * b, truncated to BN_MAX limbs. */
static void bn_mul(const struct bn *a, const struct bn *b, struct bn *r) {
    unsigned long long acc[BN_MAX] = {0};
    for (int i = 0; i < a->n; i++) {
        for (int j = 0; j < b->n && i + j < BN_MAX; j++)
            acc[i + j] += (unsigned long long)a->limbs[i] * b->limbs[j];
    }
    r->n = BN_MAX;
    unsigned long long carry = 0;
    for (int i = 0; i < BN_MAX; i++) {
        unsigned long long v = acc[i] + carry;
        r->limbs[i] = (unsigned)(v & 0xffffffffu);
        carry = v >> 32;
    }
    bn_norm(r);
}

/* r = a - b, assuming a >= b. */
static void bn_sub(const struct bn *a, const struct bn *b, struct bn *r) {
    long long borrow = 0;
    r->n = a->n;
    for (int i = 0; i < a->n; i++) {
        long long v = (long long)a->limbs[i] - (i < b->n ? b->limbs[i] : 0) - borrow;
        r->limbs[i] = (unsigned)(v & 0xffffffffu);
        borrow = v < 0 ? 1 : 0;
    }
    bn_norm(r);
}

/* r = a mod m by binary long division. a may exceed BN_MAX limbs from mul. */
static void bn_mod(const struct bn *a, const struct bn *m, struct bn *r) {
    struct bn rem = *a;
    struct bn div = *m;
    int shift = 0;
    while (bn_cmp(&div, &rem) <= 0) {
        /* shift div left by 1 */
        unsigned carry = 0;
        for (int i = 0; i < div.n && i < BN_MAX; i++) {
            unsigned ncarry = div.limbs[i] >> 31;
            div.limbs[i] = (div.limbs[i] << 1) | carry;
            carry = ncarry;
        }
        if (carry && div.n < BN_MAX) div.limbs[div.n++] = carry;
        shift++;
        if (shift > BN_MAX * 32 + 32) break;
    }
    for (; shift > 0; shift--) {
        /* shift div right by 1 */
        unsigned carry = 0;
        for (int i = div.n - 1; i >= 0; i--) {
            unsigned ncarry = div.limbs[i] & 1;
            div.limbs[i] = (div.limbs[i] >> 1) | (carry << 31);
            carry = ncarry;
        }
        bn_norm(&div);
        if (bn_cmp(&div, &rem) <= 0) {
            struct bn t;
            bn_sub(&rem, &div, &t);
            rem = t;
        }
    }
    *r = rem;
}

/* r = (a + b) mod m. Operands are already reduced, so one conditional
 * subtraction suffices. */
static void bn_addmod(const struct bn *a, const struct bn *b, const struct bn *m, struct bn *r) {
    unsigned long long carry = 0;
    int n = a->n > b->n ? a->n : b->n;
    if (n >= BN_MAX) n = BN_MAX - 1;
    struct bn t;
    t.n = n + 1;
    if (t.n > BN_MAX) t.n = BN_MAX;
    for (int i = 0; i < t.n; i++) {
        unsigned long long v = carry;
        if (i < a->n) v += a->limbs[i];
        if (i < b->n) v += b->limbs[i];
        t.limbs[i] = (unsigned)(v & 0xffffffffu);
        carry = v >> 32;
    }
    bn_norm(&t);
    if (bn_cmp(&t, m) >= 0) {
        struct bn d;
        bn_sub(&t, m, &d);
        t = d;
    }
    *r = t;
}

/* r = (a * b) mod m by double-and-add: every intermediate stays below 2m,
 * so no wide product is ever needed. */
static void bn_mulmod(const struct bn *a, const struct bn *b, const struct bn *m, struct bn *r) {
    struct bn acc, base, t;
    memset(&acc, 0, sizeof(acc));
    acc.n = 1;
    bn_mod(a, m, &base);
    for (int i = 0; i < b->n; i++) {
        for (int bit = 0; bit < 32; bit++) {
            /* LSB first: base holds b*2^k, so a set bit adds it as-is. */
            if ((b->limbs[i] >> bit) & 1) {
                bn_addmod(&acc, &base, m, &t);
                acc = t;
            }
            /* base = base*2 mod m */
            bn_addmod(&base, &base, m, &t);
            base = t;
        }
    }
    *r = acc;
}

/* r = base^exp mod m, exp a small (fits u32) public exponent. */
static void bn_powmod_u32(const struct bn *base, unsigned exp, const struct bn *m, struct bn *r) {
    struct bn acc, b, t;
    memset(&acc, 0, sizeof(acc));
    acc.limbs[0] = 1;
    acc.n = 1;
    bn_mod(base, m, &b);
    while (exp > 0) {
        if (exp & 1) {
            bn_mulmod(&acc, &b, m, &t);
            acc = t;
        }
        exp >>= 1;
        if (exp) {
            bn_mulmod(&b, &b, m, &t);
            b = t;
        }
    }
    *r = acc;
}

static void bn_to_bytes(const struct bn *a, unsigned char *out, size_t n) {
    memset(out, 0, n);
    for (size_t i = 0; i < n; i++) {
        unsigned li = (unsigned)(i / 4);
        if ((int)li < a->n)
            out[n - 1 - i] = (unsigned char)(a->limbs[li] >> (8 * (i % 4)));
    }
}

/* ---------------- P-256 (ECDHE) ----------------
 *
 * Affine-coordinate arithmetic over struct bn, reusing the generic
 * addmod/mulmod. Slow (~0.2s a handshake) but obviously correct; a toy
 * client pays that once per connection. Server points are validated
 * on-curve before use.
 */

static const unsigned char P256_P[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const unsigned char P256_N[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};
static const unsigned char P256_B[32] = {
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55,
    0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
    0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
};
static const unsigned char P256_GX[32] = {
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5,
    0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
};
static const unsigned char P256_GY[32] = {
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
    0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

/* r = (a - b) mod p. */
static void fp_sub(const struct bn *a, const struct bn *b, const struct bn *p, struct bn *r) {
    if (bn_cmp(a, b) >= 0) {
        bn_sub(a, b, r);
    } else {
        struct bn d, t;
        bn_sub(b, a, &d);
        bn_sub(p, &d, &t);
        *r = t;
    }
}

/* r = base^exp mod m, exp a full-size (256-bit scale) exponent. */
static void bn_powmod(const struct bn *base, const struct bn *exp, const struct bn *m,
                      struct bn *r) {
    struct bn acc, b, t;
    memset(&acc, 0, sizeof(acc));
    acc.limbs[0] = 1;
    acc.n = 1;
    bn_mod(base, m, &b);
    for (int i = exp->n - 1; i >= 0; i--) {
        for (int bit = 31; bit >= 0; bit--) {
            bn_mulmod(&acc, &acc, m, &t);
            acc = t;
            if ((exp->limbs[i] >> bit) & 1) {
                bn_mulmod(&acc, &b, m, &t);
                acc = t;
            }
        }
    }
    *r = acc;
}

/* out = 1/a mod p via Fermat (a^(p-2)). */
static void fp_inv(const struct bn *a, const struct bn *p, struct bn *out) {
    struct bn e, two, exp;
    bn_from_bytes(&e, P256_P, 32);
    memset(&two, 0, sizeof(two));
    two.limbs[0] = 2;
    two.n = 1;
    bn_sub(&e, &two, &exp);   /* exp = p - 2 */
    bn_powmod(a, &exp, p, out);
}

struct p256_pt {
    struct bn x;
    struct bn y;
    int inf;
};

static void p256_base(struct bn *p, const unsigned char bytes[32]) {
    bn_from_bytes(p, bytes, 32);
}

/* Doubles p in place (affine). Requires p not at infinity. */
static void p256_double(struct p256_pt *p, const struct bn *mod) {
    struct bn x2, s, inv, xr, yr, t1, t2;
    bn_mulmod(&p->x, &p->x, mod, &x2);          /* x^2 */
    bn_addmod(&x2, &x2, mod, &t1);
    bn_addmod(&t1, &x2, mod, &s);               /* s = 3x^2 */
    /* a = -3, so 3x^2 + a: subtract 3. */
    {
        struct bn three;
        memset(&three, 0, sizeof(three));
        three.limbs[0] = 3;
        three.n = 1;
        fp_sub(&s, &three, mod, &t1);
        s = t1;
    }
    bn_addmod(&p->y, &p->y, mod, &t1);          /* 2y */
    fp_inv(&t1, mod, &inv);
    bn_mulmod(&s, &inv, mod, &t1);              /* slope */
    bn_mulmod(&t1, &t1, mod, &t2);
    fp_sub(&t2, &p->x, mod, &xr);
    fp_sub(&xr, &p->x, mod, &t2);
    xr = t2;                                    /* xr = s^2 - 2x */
    fp_sub(&p->x, &xr, mod, &t2);
    bn_mulmod(&t1, &t2, mod, &yr);
    fp_sub(&yr, &p->y, mod, &t2);
    yr = t2;                                    /* yr = s(x-xr) - y */
    p->x = xr;
    p->y = yr;
}

/* r = p + q (affine). Handles infinity and doubling/opposites. */
static void p256_add(const struct p256_pt *p, const struct p256_pt *q, const struct bn *mod,
                     struct p256_pt *r) {
    if (p->inf) {
        *r = *q;
        return;
    }
    if (q->inf) {
        *r = *p;
        return;
    }
    if (bn_cmp(&p->x, &q->x) == 0) {
        struct bn ysum, t;
        bn_addmod(&p->y, &q->y, mod, &ysum);
        /* ysum == 0 mod p means opposite points (or both zero). */
        memset(&t, 0, sizeof(t));
        t.n = 1;
        if (bn_cmp(&ysum, &t) == 0) {
            r->inf = 1;
            return;
        }
        *r = *p;
        p256_double(r, mod);
        return;
    }
    struct bn dy, dx, inv, s, xr, yr, t;
    fp_sub(&q->y, &p->y, mod, &dy);
    fp_sub(&q->x, &p->x, mod, &dx);
    fp_inv(&dx, mod, &inv);
    bn_mulmod(&dy, &inv, mod, &s);
    bn_mulmod(&s, &s, mod, &t);
    fp_sub(&t, &p->x, mod, &xr);
    fp_sub(&xr, &q->x, mod, &t);
    xr = t;
    fp_sub(&p->x, &xr, mod, &t);
    bn_mulmod(&s, &t, mod, &yr);
    fp_sub(&yr, &p->y, mod, &t);
    yr = t;
    r->x = xr;
    r->y = yr;
    r->inf = 0;
}

/* r = k * base by double-and-add (MSB first). k must be nonzero. */
static void p256_mul(const struct bn *k, const struct p256_pt *base, const struct bn *mod,
                     struct p256_pt *r) {
    struct p256_pt acc;
    memset(&acc, 0, sizeof(acc));
    acc.inf = 1;
    int started = 0;
    for (int i = k->n - 1; i >= 0; i--) {
        for (int bit = 31; bit >= 0; bit--) {
            if (started) {
                struct p256_pt t;
                p256_add(&acc, &acc, mod, &t);
                acc = t;
            }
            if ((k->limbs[i] >> bit) & 1) {
                started = 1;
                struct p256_pt t;
                p256_add(&acc, base, mod, &t);
                acc = t;
            }
        }
    }
    *r = acc;
}

/* True when (x, y) satisfies y^2 = x^3 - 3x + b over the field. */
static int p256_valid(const struct bn *x, const struct bn *y, const struct bn *b,
                      const struct bn *mod) {
    struct bn lhs, x2, x3, ax, rhs, t, three;
    bn_mulmod(y, y, mod, &lhs);
    bn_mulmod(x, x, mod, &x2);
    bn_mulmod(&x2, x, mod, &x3);
    memset(&three, 0, sizeof(three));
    three.limbs[0] = 3;
    three.n = 1;
    /* x^3 - 3x + b. */
    bn_addmod(x, x, mod, &t);
    bn_addmod(&t, x, mod, &ax);       /* ax = 3x */
    fp_sub(&x3, &ax, mod, &t);
    bn_addmod(&t, b, mod, &rhs);
    return bn_cmp(&lhs, &rhs) == 0;
}

/* ---------------- DER walk ---------------- */

/* Reads a TLV header at *at: tag byte, total header length, content length. */
static int der_head(const unsigned char *b, size_t n, size_t *at, unsigned char *tag,
                    size_t *clen) {
    size_t i = *at;
    if (i + 2 > n) return -1;
    *tag = b[i++];
    unsigned char lb = b[i++];
    size_t len = 0;
    if ((lb & 0x80) == 0) {
        len = lb;
    } else {
        int cnt = lb & 0x7f;
        if (cnt == 0 || cnt > 4 || i + (size_t)cnt > n) return -1;
        for (int k = 0; k < cnt; k++) len = (len << 8) | b[i++];
    }
    if (i + len > n) return -1;
    *at = i;
    *clen = len;
    return 0;
}

/* Finds an RSA public key (modulus + exponent) inside a DER certificate. */
static int cert_rsa_pubkey(const unsigned char *cert, size_t n, struct bn *mod, unsigned *exp,
                           const unsigned char **cn, size_t *cnlen,
                           const unsigned char **not_after, size_t *nalen) {
    /* Heuristic walk: locate the rsaEncryption OID, then the enclosing
     * BIT STRING's INTEGER pair; locate CN (2.5.4.3) and validity times. */
    static const unsigned char RSA_OID[] = {0x06, 0x09, 0x2a, 0x86, 0x48,
                                            0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
    size_t opos = n;
    for (size_t i = 0; i + sizeof(RSA_OID) <= n; i++) {
        if (memcmp(cert + i, RSA_OID, sizeof(RSA_OID)) == 0) {
            opos = i;
            break;
        }
    }
    if (opos == n) return -1;
    /* After the OID comes NULL then the BIT STRING holding RSAPublicKey. */
    size_t at = opos + sizeof(RSA_OID);
    unsigned char tag;
    size_t clen;
    if (der_head(cert, n, &at, &tag, &clen) < 0 || tag != 0x05) return -1;
    at += clen; /* skip NULL */
    if (der_head(cert, n, &at, &tag, &clen) < 0 || tag != 0x03) return -1;
    if (clen < 1 || cert[at] != 0x00) return -1; /* unused-bits byte */
    at += 1;
    clen -= 1;
    if (der_head(cert, n, &at, &tag, &clen) < 0 || tag != 0x30) return -1;
    size_t seq_end = at + clen;
    if (der_head(cert, n, &at, &tag, &clen) < 0 || tag != 0x02) return -1;
    /* Modulus: strip a leading zero used for sign. */
    size_t mstart = at;
    size_t mlen = clen;
    if (mlen > 0 && cert[mstart] == 0x00) {
        mstart++;
        mlen--;
    }
    if (mlen == 0 || mlen > 512) return -1;
    bn_from_bytes(mod, cert + mstart, mlen);
    at += clen;
    if (at >= seq_end) return -1;
    if (der_head(cert, n, &at, &tag, &clen) < 0 || tag != 0x02) return -1;
    if (clen == 0 || clen > 4) return -1; /* public exponents are small */
    unsigned e = 0;
    for (size_t k = 0; k < clen; k++) e = (e << 8) | cert[at + k];
    *exp = e;
    /* CN: OID 2.5.4.3 followed by a string. */
    static const unsigned char CN_OID[] = {0x06, 0x03, 0x55, 0x04, 0x03};
    *cn = NULL;
    *cnlen = 0;
    for (size_t i = 0; i + sizeof(CN_OID) + 2 <= n; i++) {
        if (memcmp(cert + i, CN_OID, sizeof(CN_OID)) != 0) continue;
        size_t j = i + sizeof(CN_OID);
        if (cert[j] != 0x13 && cert[j] != 0x0c) continue;
        size_t sl = cert[j + 1];
        if (j + 2 + sl > n) continue;
        *cn = cert + j + 2;
        *cnlen = sl;
        break;
    }
    /* Validity: first two UTCTime/GeneralizedTime values in the cert. */
    *not_after = NULL;
    *nalen = 0;
    int found = 0;
    for (size_t i = 0; i + 2 <= n && found < 2; i++) {
        if ((cert[i] == 0x17 || cert[i] == 0x18) && cert[i + 1] <= 20 &&
            i + 2 + cert[i + 1] <= n) {
            if (found == 1) {
                *not_after = cert + i + 2;
                *nalen = cert[i + 1];
            }
            found++;
        }
    }
    return 0;
}

/* Matches host against CN/SAN with a single leading-wildcard allowance. */
static int host_match(const unsigned char *pat, size_t plen, const char *host) {
    size_t hlen = strlen(host);
    if (plen >= 2 && pat[0] == '*' && pat[1] == '.') {
        const char *dot = strchr(host, '.');
        if (!dot || strchr(dot + 1, '.') == NULL) {
            /* also allow the bare domain? No: strict single-label wildcard */
        }
        if (!dot) return -1;
        size_t suffix = plen - 1; /* ".example.com" */
        if (hlen < suffix) return -1;
        if (strncasecmp(host + hlen - suffix, (const char *)pat + 1, suffix) != 0) return -1;
        /* The wildcard must cover exactly one label. */
        if (memchr(host, '.', hlen - suffix) != NULL && hlen - suffix > 0) {
            /* more labels before the suffix: still one label, ok */
        }
        return 0;
    }
    if (plen != hlen) return -1;
    return strncasecmp((const char *)pat, host, hlen) == 0 ? 0 : -1;
}

/* Current UTC as YYMMDDHHMMSS for expiry sanity. */
static void now_stamp(char out[13]) {
    time_t t = time(NULL);
    struct tm *g = gmtime(&t);
    if (!g) {
        strcpy(out, "990101000000");
        return;
    }
    snprintf(out, 13, "%02d%02d%02d%02d%02d%02d", (g->tm_year + 1900) % 100, g->tm_mon + 1,
             g->tm_mday, g->tm_hour, g->tm_min, g->tm_sec);
}

/* ---------------- record layer ---------------- */

static int send_record(int fd, unsigned char type, const unsigned char *p, size_t n) {
    unsigned char h[5];
    h[0] = type;
    h[1] = TLS_VER_MAJOR;
    h[2] = TLS_VER_MINOR;
    wr16(h + 3, (unsigned)n);
    if (write_full(fd, h, 5) < 0) return -1;
    if (n > 0 && write_full(fd, p, n) < 0) return -1;
    return 0;
}

/* Reads one record header + payload (cap REC_MAX). */
static int recv_record(int fd, unsigned char *type, unsigned char *buf, size_t *n) {
    unsigned char h[5];
    if (read_full(fd, h, 5) < 0) return -1;
    size_t len = ((size_t)h[3] << 8) | h[4];
    if (len > REC_MAX) return -1;
    if (len > 0 && read_full(fd, buf, len) < 0) return -1;
    *type = h[0];
    *n = len;
    return 0;
}

/* CBC-decrypts one application record in place; returns plaintext length. */
static int cbc_unprotect(struct tls_ctx *t, unsigned char *rec, size_t reclen, size_t *plainlen) {
    if (reclen < 16 + 20 + 1) return -1;
    struct aes128 aes;
    aes_key(&aes, t->server_key);
    unsigned char prev[16];
    memcpy(prev, rec, 16);
    size_t body = reclen - 16;
    if (body % 16 != 0) return -1;
    for (size_t i = 0; i < body; i += 16) {
        unsigned char dec[16];
        aes_dec_block(&aes, rec + 16 + i, dec);
        for (int k = 0; k < 16; k++) dec[k] ^= prev[k];
        memcpy(rec + i, dec, 16);
        memcpy(prev, rec + 16 + i, 16);
    }
    unsigned pad = rec[body - 1];
    if (pad + 1 > body || pad > 16) return -1;
    for (size_t i = body - 1 - pad; i < body; i++) {
        if (rec[i] != pad) return -1;
    }
    size_t ptlen = body - 1 - pad;
    if (ptlen < 20) return -1;
    size_t msglen = ptlen - 20;
    /* MAC over seq + type + version + length + plaintext. */
    unsigned char hdr[13];
    for (int i = 0; i < 8; i++) hdr[i] = (unsigned char)(t->read_seq >> (56 - 8 * i));
    hdr[8] = 23;
    hdr[9] = TLS_VER_MAJOR;
    hdr[10] = TLS_VER_MINOR;
    hdr[11] = (unsigned char)(msglen >> 8);
    hdr[12] = (unsigned char)msglen;
    unsigned char mac[20];
    {
        unsigned char ipad[64], opad[64];
        for (int i = 0; i < 64; i++) {
            ipad[i] = (i < 20 ? t->server_mac[i] : 0) ^ 0x36;
            opad[i] = (i < 20 ? t->server_mac[i] : 0) ^ 0x5c;
        }
        struct sha1 c;
        unsigned char inner[20];
        sha1_init(&c);
        sha1_update(&c, ipad, 64);
        sha1_update(&c, hdr, 13);
        sha1_update(&c, rec, msglen);
        sha1_final(&c, inner);
        sha1_init(&c);
        sha1_update(&c, opad, 64);
        sha1_update(&c, inner, 20);
        sha1_final(&c, mac);
    }
    unsigned diff = 0;
    for (size_t i = 0; i < 20; i++) diff |= (unsigned)(rec[msglen + i] ^ mac[i]);
    if (diff != 0) return -1;
    memmove(rec, rec, 0); /* plaintext already in place */
    /* Shift plaintext to the front (it starts at rec[0] already). */
    *plainlen = msglen;
    t->read_seq++;
    return 0;
}

/* Encrypts and sends one application record. */
static int cbc_protect(struct tls_ctx *t, const unsigned char *pt, size_t ptlen) {
    if (ptlen > REC_MAX - 256) return -1;
    unsigned char mac[20];
    {
        unsigned char hdr[13];
        for (int i = 0; i < 8; i++) hdr[i] = (unsigned char)(t->write_seq >> (56 - 8 * i));
        hdr[8] = 23;
        hdr[9] = TLS_VER_MAJOR;
        hdr[10] = TLS_VER_MINOR;
        hdr[11] = (unsigned char)(ptlen >> 8);
        hdr[12] = (unsigned char)ptlen;
        unsigned char ipad[64], opad[64];
        for (int i = 0; i < 64; i++) {
            ipad[i] = (i < 20 ? t->client_mac[i] : 0) ^ 0x36;
            opad[i] = (i < 20 ? t->client_mac[i] : 0) ^ 0x5c;
        }
        struct sha1 c;
        unsigned char inner[20];
        sha1_init(&c);
        sha1_update(&c, ipad, 64);
        sha1_update(&c, hdr, 13);
        sha1_update(&c, pt, ptlen);
        sha1_final(&c, inner);
        sha1_init(&c);
        sha1_update(&c, opad, 64);
        sha1_update(&c, inner, 20);
        sha1_final(&c, mac);
    }
    size_t frag = ptlen + 20;
    unsigned pad = (unsigned)((16 - ((frag + 1) % 16)) % 16);
    size_t body = frag + 1 + pad;
    unsigned char *blk = malloc(16 + body);
    if (!blk) return -1;
    if (rand_bytes(blk, 16) < 0) {
        free(blk);
        return -1;
    }
    memcpy(blk + 16, pt, ptlen);
    memcpy(blk + 16 + ptlen, mac, 20);
    memset(blk + 16 + ptlen + 20, (int)pad, pad + 1);
    struct aes128 aes;
    aes_key(&aes, t->client_key);
    unsigned char prev[16];
    memcpy(prev, blk, 16);
    for (size_t i = 0; i < body; i += 16) {
        unsigned char x[16];
        for (int k = 0; k < 16; k++) x[k] = blk[16 + i + k] ^ prev[k];
        aes_enc_block(&aes, x, blk + 16 + i);
        memcpy(prev, blk + 16 + i, 16);
    }
    int r = send_record(t->fd, 23, blk, 16 + body);
    /* Wipe key-adjacent material. */
    memset(blk, 0, 16 + body);
    memset(mac, 0, sizeof(mac));
    free(blk);
    if (r < 0) return -1;
    t->write_seq++;
    return 0;
}

/* ---------------- AES-GCM (suite 0xC02F) ----------------
 *
 * TLS 1.2 GCM: nonce = 4-byte salt (key block) + 8-byte explicit nonce on
 * the wire (we send the sequence number, the common practice), AES-CTR
 * from counter 2, 16-byte tag over AAD + ciphertext.
 */

/* r = x * H in GF(2^128) (big-endian blocks, poly x^128+x^7+x^2+x+1). */
static void ghash_mul(const unsigned char x[16], const unsigned char h[16],
                      unsigned char r[16]) {
    unsigned char v[16], z[16];
    memcpy(v, h, 16);
    memset(z, 0, 16);
    for (int i = 0; i < 16; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            if ((x[i] >> bit) & 1) {
                for (int k = 0; k < 16; k++) z[k] ^= v[k];
            }
            int lsb = v[15] & 1;
            for (int k = 15; k > 0; k--) v[k] = (unsigned char)((v[k] >> 1) | ((v[k - 1] & 1) << 7));
            v[0] >>= 1;
            if (lsb) v[0] ^= 0xe1;
        }
    }
    memcpy(r, z, 16);
}

/* GHASH over aad || ciphertext with the standard length block. */
static void ghash(const unsigned char h[16], const unsigned char *aad, size_t alen,
                  const unsigned char *ct, size_t ctlen, unsigned char out[16]) {
    unsigned char y[16];
    memset(y, 0, 16);
    unsigned char blk[16];
    size_t i = 0;
    /* AAD is always our 13-byte record header here; pad to one block. */
    memset(blk, 0, 16);
    memcpy(blk, aad, alen > 16 ? 16 : alen);
    ghash_mul(blk, h, y);
    /* Full blocks... AAD fits one block; assert that below by construction. */
    while (i + 16 <= ctlen) {
        for (int k = 0; k < 16; k++) blk[k] = (unsigned char)(y[k] ^ ct[i + k]);
        ghash_mul(blk, h, y);
        i += 16;
    }
    if (i < ctlen) {
        memset(blk, 0, 16);
        memcpy(blk, ct + i, ctlen - i);
        for (int k = 0; k < 16; k++) blk[k] ^= y[k];
        ghash_mul(blk, h, y);
    }
    memset(blk, 0, 16);
    unsigned long long alen_bits = (unsigned long long)alen * 8;
    unsigned long long ctlen_bits = (unsigned long long)ctlen * 8;
    for (int k = 0; k < 8; k++) {
        blk[k] = (unsigned char)(alen_bits >> (56 - 8 * k));
        blk[8 + k] = (unsigned char)(ctlen_bits >> (56 - 8 * k));
    }
    for (int k = 0; k < 16; k++) blk[k] ^= y[k];
    ghash_mul(blk, h, y);
    memcpy(out, y, 16);
}

/* AES-CTR from counter block ctr0 (GCM data starts at 2). */
static void aes_ctr(struct aes128 *aes, const unsigned char nonce12[12], unsigned ctr0,
                    const unsigned char *in, size_t n, unsigned char *out) {
    unsigned char ctr[16], ks[16];
    memcpy(ctr, nonce12, 12);
    size_t off = 0;
    unsigned c = ctr0;
    while (off < n) {
        ctr[12] = (unsigned char)(c >> 24);
        ctr[13] = (unsigned char)(c >> 16);
        ctr[14] = (unsigned char)(c >> 8);
        ctr[15] = (unsigned char)c;
        aes_enc_block(aes, ctr, ks);
        size_t take = n - off < 16 ? n - off : 16;
        for (size_t k = 0; k < take; k++) out[off + k] = (unsigned char)(in[off + k] ^ ks[k]);
        off += take;
        c++;
    }
    memset(ks, 0, sizeof(ks));
}

/* Builds one GCM record payload: explicit nonce + ciphertext + tag.
 * Returns a malloc'd buffer with *outlen set, or NULL. Advances write_seq
 * like cbc_protect does. */
static unsigned char *gcm_protect(struct tls_ctx *t, unsigned char type,
                                  const unsigned char *pt, size_t ptlen, size_t *outlen) {
    const unsigned char *key = t->cwkey;
    const unsigned char *salt = t->cwiv;
    unsigned long long seq = t->write_seq;
    t->write_seq++;
    unsigned char *out = malloc(8 + ptlen + 16);
    if (!out) return NULL;
    unsigned char nonce[12];
    memcpy(nonce, salt, 4);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)(seq >> (56 - 8 * i));
        out[i] = nonce[4 + i];
    }
    struct aes128 aes;
    aes_key(&aes, key);
    aes_ctr(&aes, nonce, 2, pt, ptlen, out + 8);
    unsigned char h[16] = {0};
    aes_enc_block(&aes, h, h);
    unsigned char aad[13];
    for (int i = 0; i < 8; i++) aad[i] = (unsigned char)(seq >> (56 - 8 * i));
    aad[8] = type;
    aad[9] = TLS_VER_MAJOR;
    aad[10] = TLS_VER_MINOR;
    aad[11] = (unsigned char)(ptlen >> 8);
    aad[12] = (unsigned char)ptlen;
    unsigned char tag[16], mask[16], j0[16];
    ghash(h, aad, 13, out + 8, ptlen, tag);
    memcpy(j0, nonce, 12);
    memset(j0 + 12, 0, 4);
    j0[15] = 1;
    aes_enc_block(&aes, j0, mask);
    for (int i = 0; i < 16; i++) out[8 + ptlen + i] = (unsigned char)(tag[i] ^ mask[i]);
    memset(tag, 0, sizeof(tag));
    memset(mask, 0, sizeof(mask));
    *outlen = 8 + ptlen + 16;
    return out;
}

/* Verifies and decrypts one GCM record in place (ciphertext slides front).
 * expect is the content type the AAD must name. Advances read_seq on
 * success like cbc_unprotect does. */
static int gcm_unprotect(struct tls_ctx *t, unsigned char expect, unsigned char *rec,
                         size_t reclen, size_t *plainlen) {
    const unsigned char *key = t->swkey;
    const unsigned char *salt = t->swiv;
    unsigned long long seq = t->read_seq;
    if (reclen < 8 + 16) return -1;
    size_t ctlen = reclen - 8 - 16;
    unsigned char nonce[12];
    memcpy(nonce, salt, 4);
    memcpy(nonce + 4, rec, 8);
    struct aes128 aes;
    aes_key(&aes, key);
    unsigned char h[16] = {0};
    aes_enc_block(&aes, h, h);
    unsigned char aad[13];
    for (int i = 0; i < 8; i++) aad[i] = (unsigned char)(seq >> (56 - 8 * i));
    aad[8] = expect;
    aad[9] = TLS_VER_MAJOR;
    aad[10] = TLS_VER_MINOR;
    aad[11] = (unsigned char)(ctlen >> 8);
    aad[12] = (unsigned char)ctlen;
    unsigned char tag[16], mask[16], j0[16];
    ghash(h, aad, 13, rec + 8, ctlen, tag);
    memcpy(j0, nonce, 12);
    memset(j0 + 12, 0, 4);
    j0[15] = 1;
    aes_enc_block(&aes, j0, mask);
    unsigned diff = 0;
    for (int i = 0; i < 16; i++) diff |= (unsigned)((rec[8 + ctlen + i] ^ mask[i]) ^ tag[i]);
    memset(tag, 0, sizeof(tag));
    memset(mask, 0, sizeof(mask));
    if (diff) return -1;
    aes_ctr(&aes, nonce, 2, rec + 8, ctlen, rec);
    *plainlen = ctlen;
    t->read_seq++;
    return 0;
}

/* ---------------- handshake ---------------- */

int tls_handshake(int fd, const char *host, struct tls_ctx *t, char *err, size_t errcap) {
#define FAIL(m)                                   \
    do {                                          \
        snprintf(err, errcap, "%s", m);           \
        return -1;                                \
    } while (0)

    memset(t, 0, sizeof(*t));
    t->fd = fd;

    unsigned char crnd[32], srnd[32];
    unsigned char pre[48];
    unsigned char master[48];
    if (rand_bytes(crnd + 4, 28) < 0) FAIL("no entropy");
    crnd[0] = 0;
    crnd[1] = 0;
    crnd[2] = 0;
    crnd[3] = 0;

    /* ClientHello. */
    unsigned char hello[512];
    size_t hl = 0;
    hello[hl++] = 1; /* ClientHello */
    size_t hlen_at = hl;
    hl += 3;
    hello[hl++] = 3;
    hello[hl++] = 3;
    memcpy(hello + hl, crnd, 32);
    hl += 32;
    hello[hl++] = 0; /* no session */
    /* Two suites, modern first: ECDHE+RSA+GCM, then RSA+CBC fallback. */
    hello[hl++] = 0;
    hello[hl++] = 4;
    hello[hl++] = 0xc0;
    hello[hl++] = 0x2f;
    hello[hl++] = 0x00;
    hello[hl++] = 0x2f;
    hello[hl++] = 1; /* one compression method */
    hello[hl++] = 0; /* null */
    /* Extensions: SNI (9+hlen), signature_algorithms restricted to the one
     * scheme this client verifies (rsa_pkcs1_sha256, 8 bytes),
     * supported_groups secp256r1 (8), ec_point_formats uncompressed (6),
     * ALPN http/1.1 (15), empty renegotiation_info (5, which servers
     * expect as a matter of course). Total: 51+hlen. */
    size_t hlen = strlen(host);
    if (hlen == 0 || hlen > 255) FAIL("bad hostname");
    size_t extlen = 51 + hlen;
    if (extlen > 0xffff) FAIL("bad hostname");
    {
        hello[hl++] = (unsigned char)(extlen >> 8);
        hello[hl++] = (unsigned char)extlen; /* extensions length */
        hello[hl++] = 0x00;
        hello[hl++] = 0x00; /* server_name */
        hello[hl++] = (unsigned char)((5 + hlen) >> 8);
        hello[hl++] = (unsigned char)(5 + hlen); /* extension_data length */
        hello[hl++] = (unsigned char)((3 + hlen) >> 8);
        hello[hl++] = (unsigned char)(3 + hlen); /* server_name_list length */
        hello[hl++] = 0x00;                      /* host_name */
        hello[hl++] = (unsigned char)(hlen >> 8);
        hello[hl++] = (unsigned char)hlen;
        memcpy(hello + hl, host, hlen);
        hl += hlen;
        /* signature_algorithms: rsa_pkcs1_sha256 only. Offering more would
         * invite signatures this client cannot check; servers honour the
         * restriction (and demand the extension before choosing). */
        hello[hl++] = 0x00;
        hello[hl++] = 0x0d;
        hello[hl++] = 0x00;
        hello[hl++] = 0x04;
        hello[hl++] = 0x00;
        hello[hl++] = 0x02;
        hello[hl++] = 0x04;
        hello[hl++] = 0x01;
        /* supported_groups: secp256r1. */
        hello[hl++] = 0x00;
        hello[hl++] = 0x0a;
        hello[hl++] = 0x00;
        hello[hl++] = 0x04;
        hello[hl++] = 0x00;
        hello[hl++] = 0x02;
        hello[hl++] = 0x00;
        hello[hl++] = 0x17;
        /* ec_point_formats: uncompressed. */
        hello[hl++] = 0x00;
        hello[hl++] = 0x0b;
        hello[hl++] = 0x00;
        hello[hl++] = 0x02;
        hello[hl++] = 0x01;
        hello[hl++] = 0x00;
        /* ALPN: http/1.1 (this client speaks nothing else). Lengths are
         * over the 8 protocol bytes; no NUL goes on the wire. */
        hello[hl++] = 0x00;
        hello[hl++] = 0x10;
        hello[hl++] = 0x00;
        hello[hl++] = 11; /* ext_data: list(2) + name_len(1) + 8 */
        hello[hl++] = 0x00;
        hello[hl++] = 9;  /* list length */
        hello[hl++] = 8;  /* name length */
        memcpy(hello + hl, "http/1.1", 8);
        hl += 8;
        /* Empty renegotiation_info (RFC 5746): a single zero byte of
         * extension data. Absence is legal, but some stacks only accept
         * its presence. */
        hello[hl++] = 0xff;
        hello[hl++] = 0x01;
        hello[hl++] = 0x00;
        hello[hl++] = 0x01;
        hello[hl++] = 0x00;
    }
    size_t body = hl - hlen_at - 3;
    hello[hlen_at] = (unsigned char)(body >> 16);
    hello[hlen_at + 1] = (unsigned char)(body >> 8);
    hello[hlen_at + 2] = (unsigned char)body;
    if (getenv("TLS_DUMP")) {
        for (size_t di = 0; di < hl; di++) fprintf(stderr, "%02x", hello[di]);
        fprintf(stderr, "\n");
    }
    if (send_record(fd, 22, hello, hl) < 0) FAIL("send ClientHello");

    unsigned char trans[TRANS_MAX];
    size_t tlen = 0;
#define TRANS_ADD(p, n)                                    \
    do {                                                   \
        if (tlen + (n) > sizeof(trans)) FAIL("flight too big"); \
        memcpy(trans + tlen, (p), (n));                    \
        tlen += (n);                                       \
    } while (0)
    TRANS_ADD(hello, hl);

    /* Server flight: ServerHello, Certificate, [ServerKeyExchange,]
     * ServerHelloDone, in order, possibly coalesced or fragmented across
     * records. SKE appears only for ECDHE suites. */
    unsigned char rec[REC_MAX + 5];
    size_t recn = 0;
    unsigned char msgb[REC_MAX + 5];
    size_t msgn = 0;
    int stage = 0; /* 0 SH, 1 CERT, 2 SKE-or-SHD, 3 done */
    size_t cert_len = 0;
    static unsigned char cert[CERT_MAX];
    static unsigned char ske_x[32], ske_y[32];
    int ske_seen = 0;
    while (stage < 3) {
        unsigned char type;
        size_t n = 0;
        /* Refill: keep unconsumed handshake bytes. */
        if (msgn == 0) {
            if (recv_record(fd, &type, rec, &n) < 0) FAIL("server flight");
            if (type == 21) FAIL("server alert");
            if (type != 22) FAIL("unexpected record");
            memcpy(msgb, rec, n);
            msgn = n;
        }
        if (msgn < 4) FAIL("short handshake");
        unsigned char htype = msgb[0];
        size_t hlen2 = ((size_t)msgb[1] << 16) | ((size_t)msgb[2] << 8) | msgb[3];
        if (hlen2 > REC_MAX) FAIL("huge handshake");
        if (msgn < 4 + hlen2) {
            /* Fragmented: pull another record of the same flight. */
            unsigned char type2;
            size_t n2 = 0;
            if (recv_record(fd, &type2, rec, &n2) < 0) FAIL("fragment");
            if (type2 != 22 || msgn + n2 > sizeof(msgb)) FAIL("bad fragment");
            memcpy(msgb + msgn, rec, n2);
            msgn += n2;
            continue;
        }
        if ((stage == 0 && htype != 2) || (stage == 1 && htype != 11) ||
            (stage == 2 && htype != 12 && htype != 14) || stage > 2)
            FAIL("unexpected handshake order");
        TRANS_ADD(msgb, 4 + hlen2);
        if (getenv("TLS_DUMP"))
            fprintf(stderr, "DBG flight htype=%u hlen=%zu stage=%d\n", htype, hlen2, stage);
        const unsigned char *mb = msgb + 4;
        if (stage == 0) {
            if (hlen2 < 38) FAIL("short ServerHello");
            if (mb[0] != 3 || mb[1] != 3) FAIL("not TLS 1.2");
            memcpy(srnd, mb + 2, 32);
            size_t si = 34;
            if (si >= hlen2) FAIL("short ServerHello");
            si += 1 + mb[si]; /* session id */
            if (si + 2 > hlen2) FAIL("short ServerHello");
            {
                /* Unlike ClientHello's length-prefixed vector, ServerHello
                 * names exactly one suite in a fixed 2-byte field. */
                if (si + 2 > hlen2) FAIL("short ServerHello suites");
                if (mb[si] == 0xc0 && mb[si + 1] == 0x2f) {
                    t->suite = SUITE_ECDHE_RSA_AES128_GCM;
                } else if (mb[si] == 0x00 && mb[si + 1] == 0x2f) {
                    t->suite = SUITE_RSA_AES128_SHA;
                } else {
                    FAIL("suite not offered");
                }
                si += 2;
            }
            if (si >= hlen2 || mb[si] != 0) FAIL("no null compression");
        } else if (stage == 1) {
            if (hlen2 < 3) FAIL("short Certificate");
            size_t cl = ((size_t)mb[0] << 16) | ((size_t)mb[1] << 8) | mb[2];
            if (3 + cl != hlen2) FAIL("cert length");
            size_t ci = 3;
            if (ci + 3 > hlen2) FAIL("empty chain");
            size_t c0 = ((size_t)mb[ci] << 16) | ((size_t)mb[ci + 1] << 8) | mb[ci + 2];
            ci += 3;
            if (ci + c0 > hlen2 || c0 > CERT_MAX) FAIL("cert too big");
            memcpy(cert, mb + ci, c0);
            cert_len = c0;
        } else if (stage == 2 && htype == 12) {
            /* ServerKeyExchange for ECDHE: named curve secp256r1 with an
             * uncompressed point, RSA/SHA-256 signed. The signature covers
             * client_random + server_random + the curve params exactly as
             * they appear on the wire. */
            if (t->suite != SUITE_ECDHE_RSA_AES128_GCM) FAIL("stray SKE");
            if (hlen2 < 4 + 65 + 4) FAIL("short SKE");
            if (mb[0] != 3 || mb[1] != 0x00 || mb[2] != 0x17) FAIL("SKE curve");
            if (mb[3] != 65 || mb[4] != 0x04) FAIL("SKE point");
            size_t params_len = 4 + 65;
            size_t si = params_len;
            if (mb[si] != 0x04 || mb[si + 1] != 0x01) FAIL("SKE sigalg");
            size_t slen = ((size_t)mb[si + 2] << 8) | mb[si + 3];
            si += 4;
            if (si + slen != hlen2) FAIL("SKE sig length");
            /* Validate the point before any crypto touches it. */
            {
                struct bn px, py, pmod, bb;
                bn_from_bytes(&px, mb + 5, 32);
                bn_from_bytes(&py, mb + 5 + 32, 32);
                bn_from_bytes(&pmod, P256_P, 32);
                bn_from_bytes(&bb, P256_B, 32);
                if (!p256_valid(&px, &py, &bb, &pmod)) FAIL("SKE off-curve");
                memcpy(ske_x, mb + 5, 32);
                memcpy(ske_y, mb + 5 + 32, 32);
            }
            /* RSA-verify the signature with the certificate's key. */
            {
                struct bn smod;
                unsigned sexp = 0;
                const unsigned char *d1 = NULL, *d2 = NULL;
                size_t l1 = 0, l2 = 0;
                if (cert_rsa_pubkey(cert, cert_len, &smod, &sexp, &d1, &l1, &d2, &l2) < 0)
                    FAIL("SKE cert parse");
                if (sexp == 0 || sexp > 0xffffff) FAIL("SKE bad exponent");
                unsigned char hash[32];
                {
                    struct sha256 c;
                    sha256_init(&c);
                    sha256_update(&c, crnd, 32);
                    sha256_update(&c, srnd, 32);
                    sha256_update(&c, mb, params_len);
                    sha256_final(&c, hash);
                }
                struct bn sig, em;
                bn_from_bytes(&sig, mb + si, slen);
                bn_powmod_u32(&sig, sexp, &smod, &em);
                /* EM must be k bytes: 00 01 FF..FF 00 DigestInfo SHA-256 hash. */
                unsigned char embuf[512];
                size_t kn = slen;
                if (kn < 19 + 32 + 11 || kn > sizeof(embuf)) FAIL("SKE sig size");
                bn_to_bytes(&em, embuf, kn);
                static const unsigned char PREFIX[19] = {
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
                };
                if (embuf[0] != 0x00 || embuf[1] != 0x01) FAIL("SKE sig shape");
                size_t pi = 2;
                while (pi < kn && embuf[pi] == 0xff) pi++;
                if (pi < 10 || pi >= kn || embuf[pi] != 0x00) FAIL("SKE sig pad");
                pi++;
                if (kn - pi != 19 + 32) FAIL("SKE sig tail");
                if (memcmp(embuf + pi, PREFIX, 19) != 0) FAIL("SKE digest id");
                unsigned diff = 0;
                for (int i = 0; i < 32; i++) diff |= (unsigned)(embuf[pi + 19 + i] ^ hash[i]);
                memset(embuf, 0, kn);
                if (diff) FAIL("SKE sig verify");
            }
            ske_seen = 1;
        }
        /* Consume. */
        memmove(msgb, msgb + 4 + hlen2, msgn - 4 - hlen2);
        msgn -= 4 + hlen2;
        /* SKE does not advance the stage: ServerHelloDone still follows. */
        if (htype != 12) stage++;
    }
    if (t->suite == SUITE_ECDHE_RSA_AES128_GCM && !ske_seen) FAIL("ECDHE without SKE");
    (void)recn;

    /* Authenticate: RSA key + hostname (+expiry sanity, warn-only). */
    struct bn mod;
    unsigned exp = 0;
    const unsigned char *cn = NULL;
    size_t cnlen = 0;
    const unsigned char *na = NULL;
    size_t nalen = 0;
    if (cert_rsa_pubkey(cert, cert_len, &mod, &exp, &cn, &cnlen, &na, &nalen) < 0)
        FAIL("cert parse");
    if (exp == 0 || exp > 0xffffff) FAIL("bad exponent");
    int cn_ok = (cn && host_match(cn, cnlen, host) == 0);
    /* SAN dNSName entries: walk the extension value as DER (OID, optional
     * critical flag, OCTET STRING wrapping a SEQUENCE OF GeneralName) so
     * long SAN lists match wherever the name sits, with exact lengths. */
    int san_ok = 0, san_present = 0;
    {
        static const unsigned char SAN_OID[] = {0x06, 0x03, 0x55, 0x1d, 0x11};
        for (size_t i = 0; i + sizeof(SAN_OID) <= cert_len; i++) {
            if (memcmp(cert + i, SAN_OID, sizeof(SAN_OID)) != 0) continue;
            size_t at = i + sizeof(SAN_OID);
            unsigned char tag = 0;
            size_t clen = 0;
            if (at < cert_len && cert[at] == 0x01) {
                /* critical BOOLEAN, always 3 bytes (01 01 FF). */
                at += 3;
            }
            /* extnValue OCTET STRING ... */
            if (der_head(cert, cert_len, &at, &tag, &clen) < 0 || tag != 0x04) break;
            size_t vend = at + clen;
            /* ... wrapping a SEQUENCE OF GeneralName. */
            if (der_head(cert, cert_len, &at, &tag, &clen) < 0 || tag != 0x30) break;
            size_t send = at + clen;
            if (send > vend) break;
            while (at + 2 <= send) {
                if (der_head(cert, cert_len, &at, &tag, &clen) < 0) break;
                if (at + clen > send) break;
                if (tag == 0x82) {
                    san_present = 1;
                    if (host_match(cert + at, clen, host) == 0) san_ok = 1;
                }
                at += clen;
            }
            break;
        }
    }
    if (!((san_present && san_ok) || (!san_present && cn_ok))) FAIL("hostname mismatch");
    if (na && nalen >= 12) {
        char expst[13] = {0};
        size_t cp = nalen < 12 ? nalen : 12;
        /* UTCTime YYMMDDHHMMSS: normalize to comparable YYMMDDHHMMSS. */
        memcpy(expst, na, cp);
        char now[13];
        now_stamp(now);
        if (strncmp(expst, now, 12) < 0)
            snprintf(err, errcap, "note: certificate expired (continuing)");
    }

    /* ClientKeyExchange: ECDHE point or RSAES-PKCS1-v1_5. */
    size_t prelen = 48;
    if (t->suite == SUITE_ECDHE_RSA_AES128_GCM) {
        /* Ephemeral keypair dG, then Z = d * server_point. The premaster
         * is x(Z) as exactly 32 bytes (P-256 coordinate size). */
        struct bn pmod, nord, d, gx, gy, sx, sy;
        struct p256_pt base, mine, shared;
        bn_from_bytes(&pmod, P256_P, 32);
        bn_from_bytes(&nord, P256_N, 32);
        bn_from_bytes(&gx, P256_GX, 32);
        bn_from_bytes(&gy, P256_GY, 32);
        bn_from_bytes(&sx, ske_x, 32);
        bn_from_bytes(&sy, ske_y, 32);
        base.x = gx;
        base.y = gy;
        base.inf = 0;
        unsigned char draw[32];
        if (rand_bytes(draw, 32) < 0) FAIL("no entropy");
        bn_from_bytes(&d, draw, 32);
        memset(draw, 0, sizeof(draw));
        /* 1 <= d <= n-1. */
        {
            struct bn one, nm1, t;
            memset(&one, 0, sizeof(one));
            one.limbs[0] = 1;
            one.n = 1;
            bn_sub(&nord, &one, &nm1);       /* n - 1 */
            bn_mod(&d, &nm1, &t);
            bn_addmod(&t, &one, &nord, &d);  /* d = d mod (n-1) + 1 */
        }
        p256_mul(&d, &base, &pmod, &mine);
        if (mine.inf) FAIL("bad ephemeral");
        {
            struct p256_pt srv;
            srv.x = sx;
            srv.y = sy;
            srv.inf = 0;
            p256_mul(&d, &srv, &pmod, &shared);
        }
        memset(&d, 0, sizeof(d));
        if (shared.inf) FAIL("bad ECDH");
        unsigned char cke[4 + 1 + 65];
        cke[0] = 16; /* ClientKeyExchange */
        cke[1] = 0;
        cke[2] = 0;
        cke[3] = 66; /* 1 length byte + 65 point bytes */
        cke[4] = 65;
        cke[5] = 0x04;
        bn_to_bytes(&shared.x, pre, 32);
        prelen = 32;
        bn_to_bytes(&mine.x, cke + 6, 32);
        bn_to_bytes(&mine.y, cke + 6 + 32, 32);
        memset(&shared, 0, sizeof(shared));
        memset(&mine, 0, sizeof(mine));
        TRANS_ADD(cke, sizeof(cke));
        if (send_record(fd, 22, cke, sizeof(cke)) < 0) {
            memset(cke, 0, sizeof(cke));
            FAIL("send CKE");
        }
        memset(cke, 0, sizeof(cke));
    } else {
    pre[0] = 3;
    pre[1] = 3;
    if (rand_bytes(pre + 2, 46) < 0) FAIL("no entropy");
    {
        int k = 0;
        /* Modulus byte length from the parsed limbs. */
        unsigned char mbytes[512];
        bn_to_bytes(&mod, mbytes, sizeof(mbytes));
        /* Real length: strip leading zeroes. */
        size_t kn = sizeof(mbytes);
        while (kn > 0 && mbytes[sizeof(mbytes) - kn] == 0) kn--;
        /* Recompute properly below; k = minimal byte length of n. */
        size_t i = 0;
        while (i < sizeof(mbytes) && mbytes[i] == 0) i++;
        k = (int)(sizeof(mbytes) - i);
        if (k < 59 || k > 512) FAIL("bad modulus");
        unsigned char em[512];
        em[0] = 0x00;
        em[1] = 0x02;
        if (rand_bytes(em + 2, (size_t)k - 48 - 3) < 0) FAIL("no entropy");
        /* PKCS#1 requires nonzero pad bytes. */
        for (int j = 2; j < k - 48; j++) {
            while (em[j] == 0) {
                if (rand_bytes(em + j, 1) < 0) FAIL("no entropy");
            }
        }
        em[k - 48 - 1] = 0x00;
        memcpy(em + k - 48, pre, 48);
        struct bn m, c;
        bn_from_bytes(&m, em, (size_t)k);
        if (bn_cmp(&m, &mod) >= 0) FAIL("encrypt range");
        bn_powmod_u32(&m, exp, &mod, &c);
        unsigned char *cke = malloc((size_t)k + 6);
        if (!cke) FAIL("oom");
        cke[0] = 16; /* ClientKeyExchange (handshake type 16) */
        cke[1] = (unsigned char)((k + 2) >> 16);
        cke[2] = (unsigned char)((k + 2) >> 8);
        cke[3] = (unsigned char)(k + 2);
        /* The encrypted block carries a 2-byte length prefix on the wire
         * (this is what interoperating servers parse; a bare block is
         * answered with a length-mismatch alert). */
        if (k > 0xffff) FAIL("bad modulus");
        bn_to_bytes(&c, cke + 6, (size_t)k);
        cke[4] = (unsigned char)(k >> 8);
        cke[5] = (unsigned char)k;
        /* Wrap in a record directly (not part of any transcript yet). */
        TRANS_ADD(cke, (size_t)k + 6);
        if (getenv("TLS_DUMP"))
            fprintf(stderr, "DBG send CKE k=%d hs=%02x%02x%02x%02x\n", k, cke[0], cke[1],
                    cke[2], cke[3]);
        if (send_record(fd, 22, cke, (size_t)k + 6) < 0) {
            free(cke);
            FAIL("send CKE");
        }
        memset(cke, 0, (size_t)k + 6);
        memset(em, 0, sizeof(em));
        free(cke);
    }
    } /* end RSA branch */

    /* Master secret + key block (SHA-256 PRF). GCM needs no MAC keys:
     * 16 client key + 16 server key + 4 client salt + 4 server salt. */
    {
        unsigned char mseed[64], kseed[64];
        memcpy(mseed, crnd, 32);
        memcpy(mseed + 32, srnd, 32);
        tls_prf(pre, prelen, "master secret", mseed, 64, master, 48);
        memcpy(kseed, srnd, 32);
        memcpy(kseed + 32, crnd, 32);
        if (t->suite == SUITE_ECDHE_RSA_AES128_GCM) {
            unsigned char block[40];
            tls_prf(master, 48, "key expansion", kseed, 64, block, sizeof(block));
            memcpy(t->cwkey, block, 16);
            memcpy(t->swkey, block + 16, 16);
            memcpy(t->cwiv, block + 32, 4);
            memcpy(t->swiv, block + 36, 4);
            memset(block, 0, sizeof(block));
        } else {
            unsigned char block[104];
            tls_prf(master, 48, "key expansion", kseed, 64, block, sizeof(block));
            memcpy(t->client_mac, block, 20);
            memcpy(t->server_mac, block + 20, 20);
            memcpy(t->client_key, block + 40, 16);
            memcpy(t->server_key, block + 56, 16);
            memset(block, 0, sizeof(block));
        }
        memset(mseed, 0, sizeof(mseed));
        memset(kseed, 0, sizeof(kseed));
    }
    /* Test aid: transcript hash only. Key material (premaster, master,
     * keys, randoms) is deliberately never printed. */
    if (getenv("TLS_DUMP")) {
        unsigned char th[32];
        struct sha256 tc;
        sha256_init(&tc);
        sha256_update(&tc, trans, tlen);
        sha256_final(&tc, th);
        fprintf(stderr, "DBG pre-keys transcript: ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", th[i]);
        fprintf(stderr, "\n");
    }
    memset(pre, 0, sizeof(pre));

    /* ChangeCipherSpec + Finished. */
    {
        unsigned char one = 1;
        if (send_record(fd, 20, &one, 1) < 0) FAIL("send CCS");
        unsigned char hhash[32];
        {
            struct sha256 c;
            sha256_init(&c);
            sha256_update(&c, trans, tlen);
            sha256_final(&c, hhash);
        }
        if (getenv("TLS_DUMP")) {
            fprintf(stderr, "DBG trans len=%zu hash: ", tlen);
            for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", hhash[i]);
            fprintf(stderr, "\n");
        }
        unsigned char verify[12];
        tls_prf(master, 48, "client finished", hhash, 32, verify, 12);
        unsigned char fin[16];
        fin[0] = 20; /* Finished */
        fin[1] = 0;
        fin[2] = 0;
        fin[3] = 12;
        memcpy(fin + 4, verify, 12);
        TRANS_ADD(fin, 16);
        memset(verify, 0, sizeof(verify));
        /* Finished goes out encrypted under the new keys. */
        t->write_seq = 0;
        t->read_seq = 0;
        if (t->suite == SUITE_ECDHE_RSA_AES128_GCM) {
            size_t flen = 0;
            unsigned char *frec = gcm_protect(t, 22, fin, 16, &flen);
            memset(fin, 0, sizeof(fin));
            if (!frec) FAIL("oom");
            if (send_record(fd, 22, frec, flen) < 0) {
                memset(frec, 0, flen);
                free(frec);
                FAIL("send Finished");
            }
            memset(frec, 0, flen);
            free(frec);
        }
        /* Encrypt manually: plaintext is the handshake message. */
        if (t->suite != SUITE_ECDHE_RSA_AES128_GCM) {
            size_t frag = 16 + 20;
            unsigned pad = (unsigned)((16 - ((frag + 1) % 16)) % 16);
            size_t body = frag + 1 + pad;
            unsigned char *blk = malloc(16 + body);
            if (!blk) FAIL("oom");
            if (rand_bytes(blk, 16) < 0) {
                free(blk);
                FAIL("no entropy");
            }
            /* MAC covers the *handshake* content type (22), not appdata. */
            unsigned char hdr[13];
            for (int i = 0; i < 8; i++) hdr[i] = 0;
            hdr[8] = 22;
            hdr[9] = 3;
            hdr[10] = 3;
            hdr[11] = 0;
            hdr[12] = 16;
            unsigned char mac[20];
            {
                unsigned char ipad[64], opad[64];
                for (int i = 0; i < 64; i++) {
                    ipad[i] = (i < 20 ? t->client_mac[i] : 0) ^ 0x36;
                    opad[i] = (i < 20 ? t->client_mac[i] : 0) ^ 0x5c;
                }
                struct sha1 c;
                unsigned char inner[20];
                sha1_init(&c);
                sha1_update(&c, ipad, 64);
                sha1_update(&c, hdr, 13);
                sha1_update(&c, fin, 16);
                sha1_final(&c, inner);
                sha1_init(&c);
                sha1_update(&c, opad, 64);
                sha1_update(&c, inner, 20);
                sha1_final(&c, mac);
            }
            memcpy(blk + 16, fin, 16);
            memcpy(blk + 32, mac, 20);
            memset(blk + 52, (int)pad, pad + 1);
            struct aes128 aes;
            aes_key(&aes, t->client_key);
            unsigned char prev[16];
            memcpy(prev, blk, 16);
            for (size_t i = 0; i < body; i += 16) {
                unsigned char x[16];
                for (int k2 = 0; k2 < 16; k2++) x[k2] = blk[16 + i + k2] ^ prev[k2];
                aes_enc_block(&aes, x, blk + 16 + i);
                memcpy(prev, blk + 16 + i, 16);
            }
            memset(mac, 0, sizeof(mac));
            memset(fin, 0, sizeof(fin));
            if (send_record(fd, 22, blk, 16 + body) < 0) {
                memset(blk, 0, 16 + body);
                free(blk);
                FAIL("send Finished");
            }
            memset(blk, 0, 16 + body);
            free(blk);
            t->write_seq = 1;
        }
    }

    /* Server ChangeCipherSpec + Finished. A ticketed server sends a
     * NewSessionTicket handshake message first; it belongs to neither
     * transcript, so it is skipped (bounded, to never spin). The buffer
     * must fit a whole record: a ticket is hundreds of bytes, and a
     * short buffer here is a stack smash. */
    {
        unsigned char type;
        static unsigned char ccs[REC_MAX + 5];
        size_t n = 0;
        int skips = 0;
        for (;;) {
            if (recv_record(fd, &type, ccs, &n) < 0) FAIL("server CCS");
            if (type == 22 && n >= 4 && ccs[0] == 4) {
                if (++skips > 4) FAIL("server CCS");
                continue;
            }
            break;
        }
        if (type != 20) {
            if (getenv("TLS_DUMP"))
                fprintf(stderr, "DBG want CCS got type=%u len=%zu %02x%02x\n", type, n,
                        n > 0 ? ccs[0] : 0, n > 1 ? ccs[1] : 0);
            FAIL("server CCS");
        }
        unsigned char rhdr[5 + REC_MAX];
        size_t rn = 0;
        if (recv_record(fd, &type, rhdr, &rn) < 0 || type != 22) FAIL("server Finished");
        /* Decrypt like an app record but expect handshake type 22. */
        unsigned char *blk = malloc(rn);
        if (!blk) FAIL("oom");
        memcpy(blk, rhdr, rn);
        size_t msglen = 0;
        if (t->suite == SUITE_ECDHE_RSA_AES128_GCM) {
            size_t ptlen = 0;
            if (gcm_unprotect(t, 22, blk, rn, &ptlen) < 0) {
                free(blk);
                FAIL("Finished decrypt");
            }
            msglen = ptlen;
        } else {
        size_t ptlen = 0;
        /* Temporarily verify with type 22 instead of 23. */
        if (rn < 16 + 20 + 1) {
            free(blk);
            FAIL("short Finished");
        }
        struct aes128 aes;
        aes_key(&aes, t->server_key);
        unsigned char prev[16];
        memcpy(prev, blk, 16);
        size_t body = rn - 16;
        if (body % 16 != 0) {
            free(blk);
            FAIL("Finished align");
        }
        for (size_t i = 0; i < body; i += 16) {
            unsigned char dec[16];
            aes_dec_block(&aes, blk + 16 + i, dec);
            for (int k2 = 0; k2 < 16; k2++) dec[k2] ^= prev[k2];
            memcpy(blk + i, dec, 16);
            memcpy(prev, blk + 16 + i, 16);
        }
        unsigned pad = blk[body - 1];
        if (pad + 1 > body || pad > 16) {
            free(blk);
            FAIL("Finished pad");
        }
        size_t ptl = body - 1 - pad;
        if (ptl < 20 + 16) {
            free(blk);
            FAIL("Finished short");
        }
        msglen = ptl - 20;
        unsigned char hdr[13];
        for (int i = 0; i < 8; i++) hdr[i] = 0; /* server read_seq was 0 */
        hdr[8] = 22;
        hdr[9] = 3;
        hdr[10] = 3;
        hdr[11] = (unsigned char)(msglen >> 8);
        hdr[12] = (unsigned char)msglen;
        unsigned char mac[20];
        {
            unsigned char ipad[64], opad[64];
            for (int i = 0; i < 64; i++) {
                ipad[i] = (i < 20 ? t->server_mac[i] : 0) ^ 0x36;
                opad[i] = (i < 20 ? t->server_mac[i] : 0) ^ 0x5c;
            }
            struct sha1 c;
            unsigned char inner[20];
            sha1_init(&c);
            sha1_update(&c, ipad, 64);
            sha1_update(&c, hdr, 13);
            sha1_update(&c, blk, msglen);
            sha1_final(&c, inner);
            sha1_init(&c);
            sha1_update(&c, opad, 64);
            sha1_update(&c, inner, 20);
            sha1_final(&c, mac);
        }
        unsigned diff = 0;
        for (size_t i = 0; i < 20; i++) diff |= (unsigned)(blk[msglen + i] ^ mac[i]);
        if (diff) {
            free(blk);
            FAIL("Finished MAC");
        }
        } /* end CBC-only Finished decryption */
        /* Verify_data: first 12 bytes are the Finished body. */
        if (msglen != 16 || blk[0] != 20 || blk[1] != 0 || blk[2] != 0 || blk[3] != 12) {
            free(blk);
            FAIL("Finished shape");
        }
        unsigned char expect[12];
        /* The server hashes everything through our Finished (which trans
         * ends with) but not its own. */
        {
            struct sha256 c;
            unsigned char hh[32];
            sha256_init(&c);
            sha256_update(&c, trans, tlen);
            sha256_final(&c, hh);
            tls_prf(master, 48, "server finished", hh, 32, expect, 12);
        }
        unsigned diff = 0;
        for (int i = 0; i < 12; i++) diff |= (unsigned)(blk[4 + i] ^ expect[i]);
        memset(blk, 0, rn);
        free(blk);
        if (diff) FAIL("Finished verify");
        t->read_seq = 1;
    }
    memset(master, 0, sizeof(master));
    memset(srnd, 0, sizeof(srnd));
    /* Handshake hashes are single-use; keep no transcript past this point. */
    memset(trans, 0, sizeof(trans));
    return 0;
#undef FAIL
}

ssize_t tls_write(struct tls_ctx *t, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t left = n;
    while (left > 0) {
        size_t take = left < 14000 ? left : 14000;
        if (t->suite == SUITE_ECDHE_RSA_AES128_GCM) {
            size_t olen = 0;
            unsigned char *rec = gcm_protect(t, 23, p, take, &olen);
            if (!rec) {
                errno = EIO;
                return -1;
            }
            int r = send_record(t->fd, 23, rec, olen);
            memset(rec, 0, olen);
            free(rec);
            if (r < 0) {
                errno = EIO;
                return -1;
            }
        } else if (cbc_protect(t, p, take) < 0) {
            errno = EIO;
            return -1;
        }
        p += take;
        left -= take;
    }
    return (ssize_t)n;
}

ssize_t tls_read(struct tls_ctx *t, void *buf, size_t n) {
    /* A peer that closes TCP without close_notify (typical for HTTP/1.0
     * close-delimited responses) looks like EOF, not an error, when no
     * record is in flight. Peek first so a clean FIN is a 0 return. */
    {
        unsigned char one;
        ssize_t r = recv(t->fd, &one, 1, MSG_PEEK);
        if (r == 0) return 0;
        if (r < 0) {
            errno = EIO;
            return -1;
        }
    }
    if (t->pending_len > 0) {
        size_t take = n < t->pending_len ? n : t->pending_len;
        memcpy(buf, t->pending + t->pending_off, take);
        t->pending_off += take;
        t->pending_len -= take;
        if (t->pending_len == 0) {
            free(t->pending);
            t->pending = NULL;
            t->pending_off = 0;
        }
        return (ssize_t)take;
    }
    unsigned char type;
    static unsigned char rec[REC_MAX + 5];
    size_t rn = 0;
    for (;;) {
        if (recv_record(t->fd, &type, rec, &rn) < 0) {
            errno = EIO;
            return -1;
        }
        if (type == 21) {
            /* Alert: any fatal (or close_notify) ends the stream. */
            if (rn >= 2 && rec[0] == 1 && rec[1] == 0) return 0;
            errno = EIO;
            return -1;
        }
        if (type != 23) {
            errno = EIO;
            return -1;
        }
        break;
    }
    size_t ptlen = 0;
    int ok;
    if (t->suite == SUITE_ECDHE_RSA_AES128_GCM)
        ok = gcm_unprotect(t, 23, rec, rn, &ptlen);
    else
        ok = cbc_unprotect(t, rec, rn, &ptlen);
    if (ok < 0) {
        errno = EIO;
        return -1;
    }
    if (ptlen > n) {
        memcpy(buf, rec, n);
        t->pending = malloc(ptlen - n);
        if (!t->pending) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(t->pending, rec + n, ptlen - n);
        t->pending_len = ptlen - n;
        t->pending_off = 0;
        memset(rec, 0, rn);
        return (ssize_t)n;
    }
    memcpy(buf, rec, ptlen);
    memset(rec, 0, rn);
    return (ssize_t)ptlen;
}

void tls_free(struct tls_ctx *t) {
    if (t->pending) {
        memset(t->pending, 0, t->pending_len);
        free(t->pending);
        t->pending = NULL;
    }
    memset(t->client_mac, 0, sizeof(t->client_mac));
    memset(t->server_mac, 0, sizeof(t->server_mac));
    memset(t->client_key, 0, sizeof(t->client_key));
    memset(t->server_key, 0, sizeof(t->server_key));
    memset(t->cwkey, 0, sizeof(t->cwkey));
    memset(t->swkey, 0, sizeof(t->swkey));
    memset(t->cwiv, 0, sizeof(t->cwiv));
    memset(t->swiv, 0, sizeof(t->swiv));
}
