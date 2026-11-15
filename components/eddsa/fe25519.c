/*
 * ESP32-FIDO2 — Dedicated field arithmetic for GF(2^255 - 19).
 *
 * Uses 8 × 32-bit little-endian limbs. Reduction by the property
 * 2^255 ≡ 19 (mod 2^255 - 19), so the high 256 bits of a product
 * are multiplied by 19 and added to the low 256 bits.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "fe25519.h"

/* ----------------------------------------------------------------- */
/*  Public constants                                                  */
/* ----------------------------------------------------------------- */
const fe25519 fe25519_zero = { { 0, 0, 0, 0, 0, 0, 0, 0 } };
const fe25519 fe25519_one  = { { 1, 0, 0, 0, 0, 0, 0, 0 } };
const fe25519 fe25519_two  = { { 2, 0, 0, 0, 0, 0, 0, 0 } };

/* ----------------------------------------------------------------- */
/*  Internal helpers                                                  */
/* ----------------------------------------------------------------- */

/* Propagate carries in a 16-limb product array (used before reduction).
 * Kept as a utility even if not currently called from every path. */
__attribute__((unused)) static void carry_propagate(uint32_t r[16]) {
    uint64_t c;
    for (int i = 0; i < 15; i++) {
        c = (uint64_t)r[i];
        r[i]     = (uint32_t)(c & 0xffffffffULL);
        r[i + 1] += (uint32_t)(c >> 32);
    }
    /* limb 15 may exceed 32 bits; reduce modulo 2^255-19 below */
}

/* Constants of p = 2^255 - 19, little-endian 32-bit limbs. */
static const uint32_t fe25519_p[8] = {
    0xffffffedU, 0xffffffffU, 0xffffffffU, 0xffffffffU,
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0x7fffffffU
};

/* A product reduced by 38 can be up to about 34*p; 40 fixed
   conditional subtractions make the reduction constant-time. */
#define FE25519_REDUCE_STEPS 40

/* Fully reduce r[8] mod p with a fixed number of constant-time
   conditional subtractions. */
static void fe25519_fully_reduce(uint32_t r[8]) {
    for (int s = 0; s < FE25519_REDUCE_STEPS; s++) {
        uint32_t d[8];
        uint64_t t;
        uint32_t borrow = 0;
        for (int i = 0; i < 8; i++) {
            t = (uint64_t)r[i] - fe25519_p[i] - borrow;
            d[i] = (uint32_t)t;
            borrow = (uint32_t)((t >> 32) & 1);
        }
        /* borrow == 0 means r >= p: select d = r - p.
           borrow == 1 means r < p: keep r. */
        uint32_t mask = borrow - 1U;
        for (int i = 0; i < 8; i++) {
            r[i] = (r[i] & ~mask) | (d[i] & mask);
        }
    }
}

/* ----------------------------------------------------------------- */
/*  Conversion                                                        */
/* ----------------------------------------------------------------- */

void fe25519_from_bytes(fe25519 *r, const unsigned char buf[32]) {
    r->v[0] = (uint32_t)buf[0]        | ((uint32_t)buf[1]  << 8) | ((uint32_t)buf[2]  << 16) | ((uint32_t)buf[3]  << 24);
    r->v[1] = (uint32_t)buf[4]        | ((uint32_t)buf[5]  << 8) | ((uint32_t)buf[6]  << 16) | ((uint32_t)buf[7]  << 24);
    r->v[2] = (uint32_t)buf[8]        | ((uint32_t)buf[9]  << 8) | ((uint32_t)buf[10] << 16) | ((uint32_t)buf[11] << 24);
    r->v[3] = (uint32_t)buf[12]       | ((uint32_t)buf[13] << 8) | ((uint32_t)buf[14] << 16) | ((uint32_t)buf[15] << 24);
    r->v[4] = (uint32_t)buf[16]       | ((uint32_t)buf[17] << 8) | ((uint32_t)buf[18] << 16) | ((uint32_t)buf[19] << 24);
    r->v[5] = (uint32_t)buf[20]       | ((uint32_t)buf[21] << 8) | ((uint32_t)buf[22] << 16) | ((uint32_t)buf[23] << 24);
    r->v[6] = (uint32_t)buf[24]       | ((uint32_t)buf[25] << 8) | ((uint32_t)buf[26] << 16) | ((uint32_t)buf[27] << 24);
    r->v[7] = (uint32_t)buf[28]       | ((uint32_t)buf[29] << 8) | ((uint32_t)buf[30] << 16) | ((uint32_t)buf[31] << 24);
}

void fe25519_to_bytes(unsigned char buf[32], const fe25519 *r) {
    buf[0]  = r->v[0] & 0xff; buf[1]  = (r->v[0] >> 8) & 0xff; buf[2]  = (r->v[0] >> 16) & 0xff; buf[3]  = (r->v[0] >> 24) & 0xff;
    buf[4]  = r->v[1] & 0xff; buf[5]  = (r->v[1] >> 8) & 0xff; buf[6]  = (r->v[1] >> 16) & 0xff; buf[7]  = (r->v[1] >> 24) & 0xff;
    buf[8]  = r->v[2] & 0xff; buf[9]  = (r->v[2] >> 8) & 0xff; buf[10] = (r->v[2] >> 16) & 0xff; buf[11] = (r->v[2] >> 24) & 0xff;
    buf[12] = r->v[3] & 0xff; buf[13] = (r->v[3] >> 8) & 0xff; buf[14] = (r->v[3] >> 16) & 0xff; buf[15] = (r->v[3] >> 24) & 0xff;
    buf[16] = r->v[4] & 0xff; buf[17] = (r->v[4] >> 8) & 0xff; buf[18] = (r->v[4] >> 16) & 0xff; buf[19] = (r->v[4] >> 24) & 0xff;
    buf[20] = r->v[5] & 0xff; buf[21] = (r->v[5] >> 8) & 0xff; buf[22] = (r->v[5] >> 16) & 0xff; buf[23] = (r->v[5] >> 24) & 0xff;
    buf[24] = r->v[6] & 0xff; buf[25] = (r->v[6] >> 8) & 0xff; buf[26] = (r->v[6] >> 16) & 0xff; buf[27] = (r->v[6] >> 24) & 0xff;
    buf[28] = r->v[7] & 0xff; buf[29] = (r->v[7] >> 8) & 0xff; buf[30] = (r->v[7] >> 16) & 0xff; buf[31] = (r->v[7] >> 24) & 0xff;
}

int fe25519_from_mpi(fe25519 *r, const mbedtls_mpi *a) {
    unsigned char buf[32] = { 0 };
    int ret = mbedtls_mpi_write_binary_le(a, buf, 32);
    if (ret != 0) return ret;
    fe25519_from_bytes(r, buf);
    return 0;
}

int fe25519_to_mpi(mbedtls_mpi *r, const fe25519 *a) {
    unsigned char buf[32];
    fe25519_to_bytes(buf, a);
    return mbedtls_mpi_read_binary_le(r, buf, 32);
}

/* ----------------------------------------------------------------- */
/*  Arithmetic                                                        */
/* ----------------------------------------------------------------- */

void fe25519_set_zero(fe25519 *r) { memset(r->v, 0, 32); }
void fe25519_set_one(fe25519 *r)  { fe25519_set_zero(r); r->v[0] = 1; }
void fe25519_set_int(fe25519 *r, uint32_t v) { fe25519_set_zero(r); r->v[0] = v; }
void fe25519_copy(fe25519 *r, const fe25519 *a) { memcpy(r->v, a->v, 32); }

void fe25519_cmov(fe25519 *r, const fe25519 *a, uint32_t flag) {
    uint32_t mask = (uint32_t)0 - (flag & 1U);
    for (int i = 0; i < 8; i++) {
        r->v[i] = (r->v[i] & ~mask) | (a->v[i] & mask);
    }
}

int fe25519_iseq(const fe25519 *a, const fe25519 *b) {
    uint32_t d = 0;
    for (int i = 0; i < 8; i++) d |= a->v[i] ^ b->v[i];
    return (d == 0) ? 1 : 0;
}

int fe25519_get_bit(const fe25519 *a, int i) {
    return (a->v[i >> 5] >> (i & 31)) & 1;
}

/* r = a + b (fully reduced) */
void fe25519_add(fe25519 *r, const fe25519 *a, const fe25519 *b) {
    uint64_t t;
    uint32_t c = 0;
    uint32_t out[8];
    for (int i = 0; i < 8; i++) {
        t = (uint64_t)a->v[i] + b->v[i] + c;
        out[i] = (uint32_t)t;
        c = (uint32_t)(t >> 32);
    }
    /* Fold a possible 2^256 carry (38 mod p) without a data-dependent
       branch.  For canonical inputs this is a no-op. */
    uint32_t extra = 38U * c;
    for (int round = 0; round < 2; round++) {
        uint32_t carry = 0;
        for (int i = 0; i < 8; i++) {
            t = (uint64_t)out[i] + (i == 0 ? extra : 0U) + carry;
            out[i] = (uint32_t)t;
            carry = (uint32_t)(t >> 32);
        }
        extra = 38U * carry;
    }
    memcpy(r->v, out, 32);
    fe25519_fully_reduce(r->v);
}

/* r = a - b (fully reduced) */
void fe25519_sub(fe25519 *r, const fe25519 *a, const fe25519 *b) {
    uint64_t t;
    uint32_t borrow = 0;
    uint32_t out[8];
    t = (uint64_t)a->v[0] - (uint64_t)b->v[0] - borrow; out[0] = (uint32_t)t; borrow = (t >> 63) & 1;
    t = (uint64_t)a->v[1] - (uint64_t)b->v[1] - borrow; out[1] = (uint32_t)t; borrow = (t >> 63) & 1;
    t = (uint64_t)a->v[2] - (uint64_t)b->v[2] - borrow; out[2] = (uint32_t)t; borrow = (t >> 63) & 1;
    t = (uint64_t)a->v[3] - (uint64_t)b->v[3] - borrow; out[3] = (uint32_t)t; borrow = (t >> 63) & 1;
    t = (uint64_t)a->v[4] - (uint64_t)b->v[4] - borrow; out[4] = (uint32_t)t; borrow = (t >> 63) & 1;
    t = (uint64_t)a->v[5] - (uint64_t)b->v[5] - borrow; out[5] = (uint32_t)t; borrow = (t >> 63) & 1;
    t = (uint64_t)a->v[6] - (uint64_t)b->v[6] - borrow; out[6] = (uint32_t)t; borrow = (t >> 63) & 1;
    t = (uint64_t)a->v[7] - (uint64_t)b->v[7] - borrow; out[7] = (uint32_t)t;
    borrow = (t >> 63) & 1;
    /* Branchless: add p iff the subtraction borrowed. */
    uint32_t mask = (uint32_t)0 - (uint32_t)borrow;
    uint32_t carry = 0;
    for (int i = 0; i < 8; i++) {
        t = (uint64_t)out[i] + (fe25519_p[i] & mask) + carry;
        out[i] = (uint32_t)t;
        carry = (uint32_t)(t >> 32);
    }
    memcpy(r->v, out, 32);
}

void fe25519_neg(fe25519 *r, const fe25519 *a) {
    fe25519 zero;
    fe25519_set_zero(&zero);
    fe25519_sub(r, &zero, a);
}

void fe25519_mul2(fe25519 *r, const fe25519 *a) {
    fe25519_add(r, a, a);
}

/* ----------------------------------------------------------------- */
/*  Multiplication: full 16-limb product → reduce via 2^255 ≡ 19     */
/* ----------------------------------------------------------------- */
void fe25519_mul(fe25519 *r, const fe25519 *a, const fe25519 *b) {
    uint64_t p[16] = { 0 };
    /* Schoolbook multiplication */
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = p[i + j] + (uint64_t)a->v[i] * b->v[j] + carry;
            p[i + j] = t & 0xffffffffULL;
            carry = t >> 32;
        }
        p[i + 8] = carry;
    }
    /* Carry propagate */
    for (int i = 0; i < 15; i++) {
        uint64_t t = p[i];
        p[i]     = t & 0xffffffffULL;
        p[i + 1] += t >> 32;
    }
    /* Reduction: p[8:15] is at 2^256, and 2^256 ≡ 38 mod p
       (since 2^255 ≡ 19).  Do not use 19 here. */
    uint64_t r0[8];
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t t = p[i] + (uint64_t)p[i + 8] * 38 + carry;
        r0[i] = t & 0xffffffffULL;
        carry = t >> 32;
    }
    /* Fold the carry out of the 2^256 position unconditionally, so no
       branch depends on the product.  A few rounds are enough for the
       8-limb product bound. */
    for (int round = 0; round < 4; round++) {
        uint64_t add = carry * 38;
        carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t t = r0[i] + (i == 0 ? add : 0) + carry;
            r0[i] = t & 0xffffffffULL;
            carry = t >> 32;
        }
    }
    for (int i = 0; i < 8; i++) r->v[i] = (uint32_t)r0[i];
    fe25519_fully_reduce(r->v);
}

/* ----------------------------------------------------------------- */
/*  Squaring                                                          */
/*  Use the multiplication path for correctness; a dedicated square   */
/*  can be added later once it is covered by test vectors.            */
/* ----------------------------------------------------------------- */
void fe25519_sq(fe25519 *r, const fe25519 *a) {
    fe25519_mul(r, a, a);
}

/* ----------------------------------------------------------------- */
/*  Inversion: a^{p-2} mod p using square-and-multiply                */
/*  p - 2 = 2^255 - 21 = 0x7fffffff...ed - 1                          */
/* ----------------------------------------------------------------- */
void fe25519_invert(fe25519 *r, const fe25519 *a) {
    /* p - 2 = 2^255 - 21 = 0x7fff...ffeb (little-endian limbs).  Use a
       straightforward fixed-exponent square-and-multiply chain: it is
       slower than the ref10 chain, but the exponent is public and the
       implementation is easy to verify. */
    static const uint32_t exp[8] = {
        0xffffffebU, 0xffffffffU, 0xffffffffU, 0xffffffffU,
        0xffffffffU, 0xffffffffU, 0xffffffffU, 0x7fffffffU
    };
    fe25519 result, base;
    fe25519_set_one(&result);
    fe25519_copy(&base, a);
    for (int i = 254; i >= 0; i--) {
        fe25519_sq(&result, &result);
        if ((exp[i >> 5] >> (i & 31)) & 1U) {
            fe25519_mul(&result, &result, &base);
        }
    }
    fe25519_copy(r, &result);
}
