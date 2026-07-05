/*
 * ESP32-FIDO2 — Dedicated field arithmetic for Ed25519 / Curve25519 over
 *               the prime field GF(2^255 - 19).
 *
 * Uses 8 × 32-bit little-endian limbs with fast reduction by 2^255 − 19.
 * Replaces generic mbedtls_mpi operations that are ~100× slower.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef FE25519_H
#define FE25519_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mbedtls/bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------- */
/*  Type                                                             */
/* ----------------------------------------------------------------- */

/* 256-bit field element: 8 × 32-bit limbs, little-endian (limb 0 = LSB) */
typedef struct {
    uint32_t v[8];
} fe25519;

/* ----------------------------------------------------------------- */
/*  Constants                                                        */
/* ----------------------------------------------------------------- */
extern const fe25519 fe25519_zero;
extern const fe25519 fe25519_one;
extern const fe25519 fe25519_two;

/* ----------------------------------------------------------------- */
/*  Conversion                                                       */
/* ----------------------------------------------------------------- */

/* Load from 32-byte little-endian buffer */
void fe25519_from_bytes(fe25519 *r, const unsigned char buf[32]);

/* Store as 32-byte little-endian buffer */
void fe25519_to_bytes(unsigned char buf[32], const fe25519 *r);

/* Convert from mbedtls_mpi (big-endian internal) */
int fe25519_from_mpi(fe25519 *r, const mbedtls_mpi *a);

/* Convert to mbedtls_mpi (big-endian internal) */
int fe25519_to_mpi(mbedtls_mpi *r, const fe25519 *a);

/* ----------------------------------------------------------------- */
/*  Arithmetic                                                        */
/* ----------------------------------------------------------------- */

/* r = -a mod p   (a = -1 curve) */
void fe25519_neg(fe25519 *r, const fe25519 *a);

/* r = a + b  (reduced) */
void fe25519_add(fe25519 *r, const fe25519 *a, const fe25519 *b);

/* r = a - b  (reduced, result may be negative; final conditional add) */
void fe25519_sub(fe25519 *r, const fe25519 *a, const fe25519 *b);

/* r = a * b  (full multiply + fast reduction by 2^255 - 19) */
void fe25519_mul(fe25519 *r, const fe25519 *a, const fe25519 *b);

/* r = a * 2  (optimised shift) */
void fe25519_mul2(fe25519 *r, const fe25519 *a);

/* r = a^2    (optimised squaring) */
void fe25519_sq(fe25519 *r, const fe25519 *a);

/* r = a^{-1} mod p  (Fermat: a^{p-2} mod p) */
void fe25519_invert(fe25519 *r, const fe25519 *a);

/* r = 0 */
void fe25519_set_zero(fe25519 *r);

/* r = 1 */
void fe25519_set_one(fe25519 *r);

/* r = small int */
void fe25519_set_int(fe25519 *r, uint32_t v);

/* r = a */
void fe25519_copy(fe25519 *r, const fe25519 *a);

/* Constant-time compare: return 0 if equal */
int fe25519_iseq(const fe25519 *a, const fe25519 *b);

/* Return 1 if bit i of the field element is set */
int fe25519_get_bit(const fe25519 *a, int i);

#ifdef __cplusplus
}
#endif

#endif /* FE25519_H */
