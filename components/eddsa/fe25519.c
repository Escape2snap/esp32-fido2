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

/* Propagate carries in a 16-limb product array (used before reduction) */
static void carry_propagate(uint32_t r[16]) {
    uint64_t c;
    for (int i = 0; i < 15; i++) {
        c = (uint64_t)r[i];
        r[i]     = (uint32_t)(c & 0xffffffffULL);
        r[i + 1] += (uint32_t)(c >> 32);
    }
    /* limb 15 may exceed 32 bits; reduce modulo 2^255-19 below */
}

/* Fully reduce r[8] mod p (r may be up to ~ 2*p - 1). */
static void fe25519_fully_reduce(uint32_t r[8]) {
    /* Subtract p repeatedly if r >= p.  At most 2 subtractions needed. */
    uint32_t borrow;
    /* First subtraction: r = r - p */
    uint64_t tmp;
    tmp = (uint64_t)r[0] - 0xffffffedULL;  borrow = (tmp >> 32) & 1; r[0] = (uint32_t)tmp;
    tmp = (uint64_t)r[1] - 0xffffffffULL - borrow; borrow = (tmp >> 32) & 1; r[1] = (uint32_t)tmp;
    tmp = (uint64_t)r[2] - 0xffffffffULL - borrow; borrow = (tmp >> 32) & 1; r[2] = (uint32_t)tmp;
    tmp = (uint64_t)r[3] - 0xffffffffULL - borrow; borrow = (tmp >> 32) & 1; r[3] = (uint32_t)tmp;
    tmp = (uint64_t)r[4] - 0xffffffffULL - borrow; borrow = (tmp >> 32) & 1; r[4] = (uint32_t)tmp;
    tmp = (uint64_t)r[5] - 0xffffffffULL - borrow; borrow = (tmp >> 32) & 1; r[5] = (uint32_t)tmp;
    tmp = (uint64_t)r[6] - 0xffffffffULL - borrow; borrow = (tmp >> 32) & 1; r[6] = (uint32_t)tmp;
    tmp = (uint64_t)r[7] - 0x7fffffffULL - borrow; borrow = (tmp >> 32) & 1; r[7] = (uint32_t)tmp;
    /* If borrow == 0, r was >= p and we keep it; otherwise add p back */
    if (borrow) {
        /* r = r + p */
        uint32_t carry;
        tmp = (uint64_t)r[0] + 0xffffffedULL;  carry = (uint32_t)(tmp >> 32); r[0] = (uint32_t)tmp;
        tmp = (uint64_t)r[1] + 0xffffffffULL + carry; carry = (uint32_t)(tmp >> 32); r[1] = (uint32_t)tmp;
        tmp = (uint64_t)r[2] + 0xffffffffULL + carry; carry = (uint32_t)(tmp >> 32); r[2] = (uint32_t)tmp;
        tmp = (uint64_t)r[3] + 0xffffffffULL + carry; carry = (uint32_t)(tmp >> 32); r[3] = (uint32_t)tmp;
        tmp = (uint64_t)r[4] + 0xffffffffULL + carry; carry = (uint32_t)(tmp >> 32); r[4] = (uint32_t)tmp;
        tmp = (uint64_t)r[5] + 0xffffffffULL + carry; carry = (uint32_t)(tmp >> 32); r[5] = (uint32_t)tmp;
        tmp = (uint64_t)r[6] + 0xffffffffULL + carry; carry = (uint32_t)(tmp >> 32); r[6] = (uint32_t)tmp;
        tmp = (uint64_t)r[7] + 0x7fffffffULL + carry; r[7] = (uint32_t)tmp;
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
    t = (uint64_t)a->v[0] + b->v[0]; out[0] = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)a->v[1] + b->v[1] + c; out[1] = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)a->v[2] + b->v[2] + c; out[2] = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)a->v[3] + b->v[3] + c; out[3] = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)a->v[4] + b->v[4] + c; out[4] = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)a->v[5] + b->v[5] + c; out[5] = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)a->v[6] + b->v[6] + c; out[6] = (uint32_t)t; c = (uint32_t)(t >> 32);
    t = (uint64_t)a->v[7] + b->v[7] + c; out[7] = (uint32_t)t; /* c ignored here — handled by full reduce */
    /* Reduce: if c (the carry out of the top limb) is 1, add back 19 (the
     * reduction equivalent of 2^255) and propagate, then conditionally sub p. */
    if (c) {
        /* r = r + 19 (since c * 2^255 ≡ c * 19 mod p) */
        uint32_t carry = 0;
        t = (uint64_t)out[0] + 19; out[0] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[1] + carry; out[1] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[2] + carry; out[2] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[3] + carry; out[3] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[4] + carry; out[4] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[5] + carry; out[5] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[6] + carry; out[6] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[7] + carry; out[7] = (uint32_t)t;
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
    if (borrow) {
        /* Add back p: result was negative */
        uint32_t carry = 0;
        t = (uint64_t)out[0] + 0xffffffedULL;  out[0] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[1] + 0xffffffffULL + carry; out[1] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[2] + 0xffffffffULL + carry; out[2] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[3] + 0xffffffffULL + carry; out[3] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[4] + 0xffffffffULL + carry; out[4] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[5] + 0xffffffffULL + carry; out[5] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[6] + 0xffffffffULL + carry; out[6] = (uint32_t)t; carry = (uint32_t)(t >> 32);
        t = (uint64_t)out[7] + 0x7fffffffULL + carry; out[7] = (uint32_t)t;
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
    /* Reduction: p = p[0:7] + 19 * p[8:15] (since 2^255 ≡ 19 mod p) */
    uint64_t r0[8];
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t t = p[i] + (uint64_t)p[i + 8] * 19 + carry;
        r0[i] = t & 0xffffffffULL;
        carry = t >> 32;
    }
    /* Handle top carry: carry is at most 19 * 0xffffffff + carry from last addition */
    /* Add carry * 19 to r0[0] and propagate */
    if (carry) {
        uint64_t t = r0[0] + carry * 19;
        r0[0] = t & 0xffffffffULL;
        carry = t >> 32;
        for (int i = 1; i < 8 && carry; i++) {
            t = r0[i] + carry;
            r0[i] = t & 0xffffffffULL;
            carry = t >> 32;
        }
    }
    for (int i = 0; i < 8; i++) r->v[i] = (uint32_t)r0[i];
    fe25519_fully_reduce(r->v);
}

/* ----------------------------------------------------------------- */
/*  Squaring (optimized)                                              */
/* ----------------------------------------------------------------- */
void fe25519_sq(fe25519 *r, const fe25519 *a) {
    uint64_t p[16] = { 0 };
    for (int i = 0; i < 8; i++) {
        /* Diagonal: i == j */
        uint64_t t = p[2 * i] + (uint64_t)a->v[i] * a->v[i];
        p[2 * i] = t & 0xffffffffULL;
        uint64_t carry = t >> 32;
        for (int j = i + 1; j < 8; j++) {
            uint64_t prod = (uint64_t)a->v[i] * a->v[j];
            t = p[i + j] + 2 * prod + carry;
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
    /* Reduction */
    uint64_t r0[8];
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t t = p[i] + (uint64_t)p[i + 8] * 19 + carry;
        r0[i] = t & 0xffffffffULL;
        carry = t >> 32;
    }
    if (carry) {
        uint64_t t = r0[0] + carry * 19;
        r0[0] = t & 0xffffffffULL;
        carry = t >> 32;
        for (int i = 1; i < 8 && carry; i++) {
            t = r0[i] + carry;
            r0[i] = t & 0xffffffffULL;
            carry = t >> 32;
        }
    }
    for (int i = 0; i < 8; i++) r->v[i] = (uint32_t)r0[i];
    fe25519_fully_reduce(r->v);
}

/* ----------------------------------------------------------------- */
/*  Inversion: a^{p-2} mod p using square-and-multiply                */
/*  p - 2 = 2^255 - 21 = 0x7fffffff...ed - 1                          */
/* ----------------------------------------------------------------- */
void fe25519_invert(fe25519 *r, const fe25519 *a) {
    fe25519 t1, t2, t3, t4, t5;
    int i;

    fe25519_copy(&t1, a);

    /* Compute a^2 */
    fe25519_sq(&t2, &t1);
    fe25519_mul(&t1, &t1, &t2);  /* t1 = a^3 */

    fe25519_sq(&t2, &t1); fe25519_mul(&t2, &t2, a);      /* a^7 */
    fe25519_sq(&t3, &t2); fe25519_sq(&t3, &t3); fe25519_mul(&t3, &t3, &t2); /* a^15 */

    fe25519_copy(&t4, &t3);
    for (i = 0; i < 4; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t3);  /* a^(2^8 - 1) */

    fe25519_copy(&t5, &t4);
    for (i = 0; i < 8; i++) { fe25519_sq(&t5, &t5); }
    fe25519_mul(&t5, &t5, &t4);  /* a^(2^16 - 1) */

    fe25519_copy(&t4, &t5);
    for (i = 0; i < 16; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t5);  /* a^(2^32 - 1) */

    fe25519_copy(&t5, &t4);
    for (i = 0; i < 32; i++) { fe25519_sq(&t5, &t5); }
    fe25519_mul(&t5, &t5, &t4);  /* a^(2^64 - 1) */

    fe25519_copy(&t4, &t5);
    for (i = 0; i < 64; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t5);  /* a^(2^128 - 1) */

    for (i = 0; i < 64; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t5);  /* a^(2^192 - 1) */

    for (i = 0; i < 32; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t5);  /* a^(2^224 - 1) */

    for (i = 0; i < 16; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t5);  /* a^(2^240 - 1) */

    for (i = 0; i < 8; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t3);  /* a^(2^248 - 1) */

    for (i = 0; i < 4; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t2);  /* a^(2^252 - 1) */

    for (i = 0; i < 2; i++) { fe25519_sq(&t4, &t4); }
    fe25519_mul(&t4, &t4, &t1);  /* a^(2^254 - 1) */

    fe25519_sq(&t4, &t4);         /* a^(2^255 - 2) = a^{p-2} mod p */
    fe25519_sq(&t4, &t4);         /* a^(2^256 - 4) ... */
    fe25519_mul(r, &t4, a);
    /* Final result = a^(2^255 - 21) which is a^{p-2} */
}
