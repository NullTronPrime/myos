/* ec_test: P-256 self-checks (order, DH consistency, GCM round-trip). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "lib/tls.c"

static int fails = 0;
#define CHECK(c, m) do { \
    if (!(c)) { printf("FAIL %s\n", m); fails++; } \
    else { printf("ok %s\n", m); } \
} while (0)

int main(void) {
    struct bn pmod, nord, gx, gy, one, d, e;
    bn_from_bytes(&pmod, P256_P, 32);
    bn_from_bytes(&nord, P256_N, 32);
    bn_from_bytes(&gx, P256_GX, 32);
    bn_from_bytes(&gy, P256_GY, 32);
    memset(&one, 0, sizeof(one));
    one.limbs[0] = 1;
    one.n = 1;
    struct p256_pt G, R;
    G.x = gx;
    G.y = gy;
    G.inf = 0;

    /* 1*G == G. */
    p256_mul(&one, &G, &pmod, &R);
    CHECK(!R.inf && bn_cmp(&R.x, &gx) == 0 && bn_cmp(&R.y, &gy) == 0, "1*G==G");

    /* n*G == infinity (group order). */
    p256_mul(&nord, &G, &pmod, &R);
    CHECK(R.inf, "n*G==inf");

    /* (n-1)*G == -G. */
    {
        struct bn nm1, t;
        bn_sub(&nord, &one, &nm1);
        p256_mul(&nm1, &G, &pmod, &R);
        struct bn negy, sum;
        fp_sub(&pmod, &gy, &pmod, &negy);
        bn_addmod(&R.y, &gy, &pmod, &sum);
        memset(&t, 0, sizeof(t));
        t.n = 1;
        CHECK(!R.inf && bn_cmp(&R.x, &gx) == 0 && bn_cmp(&sum, &t) == 0, "(n-1)*G==-G");
    }

    /* DH consistency: a*(bG) == b*(aG). */
    {
        unsigned char ab[32], bb[32];
        memset(ab, 0, 32);
        memset(bb, 0, 32);
        ab[31] = 0xa5;
        bb[31] = 0x3c;
        bb[30] = 0x77;
        struct bn a, b;
        struct p256_pt aG, bG, ab2, ba2;
        bn_from_bytes(&a, ab, 32);
        bn_from_bytes(&b, bb, 32);
        p256_mul(&a, &G, &pmod, &aG);
        p256_mul(&b, &G, &pmod, &bG);
        p256_mul(&a, &bG, &pmod, &ab2);
        p256_mul(&b, &aG, &pmod, &ba2);
        CHECK(!ab2.inf && !ba2.inf && bn_cmp(&ab2.x, &ba2.x) == 0 &&
              bn_cmp(&ab2.y, &ba2.y) == 0, "DH consistent");
    }

    /* GCM round-trip with fixed keys. */
    {
        struct tls_ctx t;
        memset(&t, 0, sizeof(t));
        for (int i = 0; i < 16; i++) {
            t.cwkey[i] = (unsigned char)i;
            t.swkey[i] = (unsigned char)(0xf0 + i);
        }
        t.cwiv[0] = 1;
        t.cwiv[1] = 2;
        t.cwiv[2] = 3;
        t.cwiv[3] = 4;
        memcpy(t.swiv, t.cwiv, 4);
        const char *msg = "hello gcm world, sixteen+ bytes here!!";
        size_t mlen = strlen(msg);
        size_t olen = 0;
        unsigned char *rec = gcm_protect(&t, 23, (const unsigned char *)msg, mlen, &olen);
        CHECK(rec && olen == 8 + mlen + 16, "gcm protect shape");
        /* Decrypt with the *sender* keys: swap sender/receiver roles. */
        struct tls_ctx u;
        memset(&u, 0, sizeof(u));
        memcpy(u.swkey, t.cwkey, 16);
        memcpy(u.swiv, t.cwiv, 4);
        size_t ptlen = 0;
        int r = gcm_unprotect(&u, 23, rec, olen, &ptlen);
        CHECK(r == 0 && ptlen == mlen && memcmp(rec, msg, mlen) == 0, "gcm round-trip");
        /* Tamper: flip a ciphertext bit, must fail. */
        rec[10] ^= 0x01;
        struct tls_ctx u2;
        memset(&u2, 0, sizeof(u2));
        memcpy(u2.swkey, t.cwkey, 16);
        memcpy(u2.swiv, t.cwiv, 4);
        size_t p2 = 0;
        CHECK(gcm_unprotect(&u2, 23, rec, olen, &p2) < 0, "gcm tamper fails");
        free(rec);
    }
    printf(fails ? "EC_TEST:FAIL\n" : "EC_TEST:PASS\n");
    return fails != 0;
}
