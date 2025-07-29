#ifndef SODIUM_H
#define SODIUM_H
#include <stdint.h>
#include <stddef.h>
#include "mbedtls/sha256.h"

#define crypto_hash_sha256_BYTES 32

static inline int crypto_hash_sha256(uint8_t *out, const uint8_t *in, unsigned long long inlen) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, in, inlen);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
    return 0;
}

static inline int crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m, unsigned long long mlen, const unsigned char *pk) {
    (void)sig; (void)m; (void)mlen; (void)pk;
    return -1; // not implemented, always fail
}

static inline void sodium_memzero(void *p, size_t len) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
}
#endif // SODIUM_H
