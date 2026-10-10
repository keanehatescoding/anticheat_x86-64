/*
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * sha256.h — minimal SHA-256 (FIPS 180-4) for anticheat baselines.
 */
#ifndef _AC_SHA256_H_
#define _AC_SHA256_H_

/* size_t/uint*_t only -- plain <stddef.h>/<stdint.h> aren't part of the
 * kernel module build's include path (it builds with -nostdinc and no
 * compiler-freestanding -isystem dir), but linux/types.h typedefs the
 * same names for kernel code. See sha256.c's #include block for why this
 * can't be one unconditional include the way linux/string.h vs string.h
 * is handled there. */
#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stddef.h>
# include <stdint.h>
#endif

typedef struct {
    uint32_t h[8];
    uint64_t len;          /* total bytes processed */
    uint8_t  buf[64];
    size_t   buflen;
} ac_sha256_ctx;

void ac_sha256_init(ac_sha256_ctx *c);
void ac_sha256_update(ac_sha256_ctx *c, const void *data, size_t len);
void ac_sha256_final(ac_sha256_ctx *c, uint8_t out[32]);

/* hex-encode a raw 32-byte digest (e.g. the output of ac_sha256_final(),
 * including one produced incrementally via a streaming init/update/final
 * sequence) -- writes 64 chars + NUL into out_hex. */
void ac_sha256_hex_digest(const uint8_t digest[32], char out_hex[65]);

/* one-shot: hex digest of buf, writes 64 chars + NUL into out_hex */
void ac_sha256_hex(const void *buf, size_t len, char out_hex[65]);

#endif /* _AC_SHA256_H_ */
