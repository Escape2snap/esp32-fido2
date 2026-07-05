/*
 * ESP32-FIDO2 — Edwards curve ECP functions for EdDSA
 *
 * Uses dedicated 256-bit field arithmetic (fe25519) for GF(2^255-19)
 * instead of slow generic mbedtls_mpi operations.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "common.h"

#if defined(MBEDTLS_ECP_C)

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/sha512.h"
#include "eddsa_compat.h"
#include "fe25519.h"

/* ------------------------------------------------------------------ */
/*  Ed25519 constants  (big-endian bytes)                              */
/* ------------------------------------------------------------------ */
static const unsigned char BE_Bx[32] = {
    0x21, 0x69, 0x36, 0xD3, 0xCD, 0x6E, 0x53, 0xFE,
    0xC0, 0xA4, 0xE2, 0x31, 0xFD, 0xD6, 0xDC, 0x5C,
    0x69, 0x2C, 0xC7, 0x60, 0x95, 0x25, 0xA7, 0xB2,
    0xC9, 0x56, 0x2D, 0x60, 0x8F, 0x25, 0xD5, 0x1A
};
static const unsigned char BE_By[32] = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58
};
static const unsigned char BE_2d[32] = {
    0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75,
    0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00,
    0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C,
    0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52
};
static const unsigned char BE_l[32] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
};

/* ------------------------------------------------------------------ */
/*  Cached field-element constants                                     */
/* ------------------------------------------------------------------ */
static fe25519 bX, bY, bT, d2, grp_l;
static int fe_ok = 0;

static void fe_init(void) {
    if (fe_ok) return;
    fe25519_from_bytes(&bX, BE_Bx);
    fe25519_from_bytes(&bY, BE_By);
    fe25519_mul(&bT, &bX, &bY);
    fe25519_from_bytes(&d2, BE_2d);
    fe25519_from_bytes(&grp_l, BE_l);
    fe_ok = 1;
}

/* ------------------------------------------------------------------ */
/*  Edwards curve operations (a = -1, extended coordinates)            */
/* ------------------------------------------------------------------ */

/* Double: (X,Y,Z,T) = 2*(X,Y,Z,T) */
static void pt_double(fe25519 *X, fe25519 *Y, fe25519 *Z, fe25519 *T) {
    fe25519 A, B, C, D, E, F, G, H;
    fe25519_sq(&A, X); fe25519_sq(&B, Y); fe25519_sq(&C, Z);
    fe25519_add(&C, &C, &C);
    fe25519_add(&D, &A, &B); fe25519_sub(&E, &A, &B);
    fe25519_add(&F, &D, &C); fe25519_sub(&G, &D, &C);
    fe25519_mul(&H, Y, Z); fe25519_add(&H, &H, &H);
    fe25519_mul(X, &E, &F); fe25519_mul(Y, &G, &H);
    fe25519_mul(T, &E, &H); fe25519_mul(Z, &F, &G);
}

/* Add: R += B where B has Z=1 (base point) */
static void pt_add(fe25519 *X, fe25519 *Y, fe25519 *Z, fe25519 *T) {
    fe25519 A, B, E, F, G, H, tx, ty;
    fe25519_sub(&A, Y, X); fe25519_sub(&B, &bY, &bX);
    fe25519_mul(&tx, &A, &B);
    fe25519_add(&A, Y, X); fe25519_add(&B, &bY, &bX);
    fe25519_mul(&ty, &A, &B);
    fe25519_mul(&A, T, &bT); fe25519_mul(&A, &A, &d2);
    fe25519_add(&B, Z, Z);
    fe25519_sub(&E, &ty, &tx); fe25519_sub(&F, &B, &A);
    fe25519_add(&G, &B, &A); fe25519_add(&H, &ty, &tx);
    fe25519_mul(X, &E, &F); fe25519_mul(Y, &G, &H);
    fe25519_mul(T, &E, &H); fe25519_mul(Z, &F, &G);
}

/* Inverse via fe25519_invert (a^{p-2} mod p) */

/* ------------------------------------------------------------------ */
/*  Scalar multiplication: (R) = scalar * base_point                   */
/*  Left-to-right double-and-add, extended coords, 256 iterations.     */
/*  Caller must wrap with ED25519_WDT_ADD()/DEL() if this is the      */
/*  first/last scalarmult in a public API call.                       */
/* ------------------------------------------------------------------ */
static void scalarmult_base(fe25519 *X, fe25519 *Y, fe25519 *Z, fe25519 *T,
                            const fe25519 *scalar) {
    fe_init();
    fe25519_set_zero(X);
    fe25519_set_one(Y);
    fe25519_set_one(Z);
    fe25519_set_zero(T);
    for (int i = 255; i >= 0; i--) {
        if (i % 8 == 0) ED25519_WDT_RESET();
        pt_double(X, Y, Z, T);
        if (fe25519_get_bit(scalar, i))
            pt_add(X, Y, Z, T);
    }
}

/* Convert extended coords to affine: x = X/Z, y = Y/Z */
static void to_affine(fe25519 *x, fe25519 *y, fe25519 *z,
                      const fe25519 *X, const fe25519 *Y, const fe25519 *Z) {
    fe25519 zi;
    fe25519_invert(&zi, Z);
    fe25519_mul(x, X, &zi);
    fe25519_mul(y, Y, &zi);
}

/* Encode Edwards point as 32-byte little-endian Y + X sign bit */
static void ed25519_encode_point(const fe25519 *x, const fe25519 *y,
                                 unsigned char out[32]) {
    fe25519 q;
    fe25519_copy(&q, y);
    q.v[7] |= (fe25519_get_bit(x, 0) << 31);
    fe25519_to_bytes(out, &q);
}

/* ------------------------------------------------------------------ */
/*  Expand a 32-byte seed to (clamped_scalar, prefix) via SHA-512.    */
/*  Used by both key generation and signing.                          */
/* ------------------------------------------------------------------ */
static void expand_seed(const unsigned char seed[32],
                        fe25519 *scalar, unsigned char prefix[32]) {
    unsigned char hash[64];
    mbedtls_sha512(seed, 32, hash, 0);
    hash[0] &= 248; hash[31] &= 63; hash[31] |= 64;
    fe25519_from_bytes(scalar, hash);    /* little-endian read */
    if (prefix) memcpy(prefix, hash + 32, 32);
}

/* ------------------------------------------------------------------ */
/*  Public API — called from openpgp.c and cmd_keypair_gen.c          */
/* ------------------------------------------------------------------ */

int ed25519_generate_keypair(mbedtls_ecp_keypair *key,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng) {
    int ret;
    unsigned char seed[32];
    fe25519 s, X, Y, Z, T, x, y;

    fe_init();

    /* 1. Generate random seed */
    f_rng(p_rng, seed, 32);

    /* 2. Expand to clamped scalar */
    expand_seed(seed, &s, NULL);

    /* 3. Q = s * B */
    ED25519_WDT_ADD();
    scalarmult_base(&X, &Y, &Z, &T, &s);
    ED25519_WDT_DEL();

    /* 4. Convert to affine */
    to_affine(&x, &y, &Z, &X, &Y, &Z);
    fe25519_to_mpi(&key->Q.X, &x);
    fe25519_to_mpi(&key->Q.Y, &y);
    mbedtls_mpi_lset(&key->Q.Z, 1);

    /* 5. Set group parameters */
    ed25519_setup_group(&key->grp);

    /* 6. Store original seed as private key (not clamped scalar) */
    mbedtls_mpi_read_binary(&key->d, seed, 32);

    ret = 0;
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return ret;
}

int ed25519_compute_public(mbedtls_ecp_keypair *key) {
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    unsigned char seed[32];
    fe25519 s, X, Y, Z, T, x, y;

    fe_init();

    /* Read seed from key->d */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&key->d, seed, 32));

    /* Expand to scalar */
    expand_seed(seed, &s, NULL);

    /* Q = s * B */
    ED25519_WDT_ADD();
    scalarmult_base(&X, &Y, &Z, &T, &s);
    ED25519_WDT_DEL();

    /* Affine */
    to_affine(&x, &y, &Z, &X, &Y, &Z);
    fe25519_to_mpi(&key->Q.X, &x);
    fe25519_to_mpi(&key->Q.Y, &y);
    mbedtls_mpi_lset(&key->Q.Z, 1);
    ret = 0;

cleanup:
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return ret;
}

int ed25519_sign(const mbedtls_ecp_keypair *key,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t sig[64]) {
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    unsigned char seed[32], prefix[32], r_buf[64], h_buf[64];
    unsigned char r_enc[32], q_enc[32];
    fe25519 s, Xq, Yq, Zq, Tq, Xr, Yr, Zr, Tr, x, y;
    mbedtls_mpi order_l, mr, mk, ms;
    mbedtls_sha512_context sha;

    fe_init();
    mbedtls_mpi_init(&order_l); mbedtls_mpi_init(&mr);
    mbedtls_mpi_init(&mk); mbedtls_mpi_init(&ms);
    mbedtls_mpi_read_binary(&order_l, BE_l, 32);

    /* Read seed */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&key->d, seed, 32));

    /* Expand to scalar + prefix */
    expand_seed(seed, &s, prefix);

    /* Q = scalar * B */
    ED25519_WDT_ADD();
    scalarmult_base(&Xq, &Yq, &Zq, &Tq, &s);
    ED25519_WDT_RESET();
    to_affine(&x, &y, &Zq, &Xq, &Yq, &Zq);
    ed25519_encode_point(&x, &y, q_enc);

    /* r = SHA-512(prefix || msg) mod l */
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    mbedtls_sha512_update(&sha, prefix, 32);
    mbedtls_sha512_update(&sha, msg, msg_len);
    mbedtls_sha512_finish(&sha, r_buf);
    mbedtls_sha512_free(&sha);
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&mr, r_buf, 64));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&mr, &mr, &order_l));

    /* R = r * B */
    fe25519_from_mpi(&s, &mr);  /* reuse s as r (s not needed past here) */
    ED25519_WDT_RESET();
    scalarmult_base(&Xr, &Yr, &Zr, &Tr, &s);
    ED25519_WDT_DEL();
    to_affine(&x, &y, &Zr, &Xr, &Yr, &Zr);
    ed25519_encode_point(&x, &y, r_enc);

    /* k = SHA-512(R_enc || Q_enc || msg) mod l */
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    mbedtls_sha512_update(&sha, r_enc, 32);
    mbedtls_sha512_update(&sha, q_enc, 32);
    mbedtls_sha512_update(&sha, msg, msg_len);
    mbedtls_sha512_finish(&sha, h_buf);
    mbedtls_sha512_free(&sha);
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&mk, h_buf, 64));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&mk, &mk, &order_l));

    /* Restore s from seed (was overwritten above as r) */
    expand_seed(seed, &s, NULL);
    fe25519_to_mpi(&ms, &s);

    /* S = (r + k * s) mod l */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&mk, &mk, &ms));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&mr, &mr, &mk));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&mr, &mr, &order_l));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&mr, sig + 32, 32));
    memcpy(sig, r_enc, 32);

    ret = 0;
cleanup:
    mbedtls_mpi_free(&order_l); mbedtls_mpi_free(&mr);
    mbedtls_mpi_free(&mk); mbedtls_mpi_free(&ms);
    mbedtls_platform_zeroize(seed, sizeof(seed));
    mbedtls_platform_zeroize(prefix, sizeof(prefix));
    mbedtls_platform_zeroize(r_buf, sizeof(r_buf));
    mbedtls_platform_zeroize(h_buf, sizeof(h_buf));
    return ret;
}

/* ------------------------------------------------------------------ */
/*  mbedtls_ecp_point_encode — Edwards version                        */
/* ------------------------------------------------------------------ */
int mbedtls_ecp_point_encode(const mbedtls_ecp_group *grp,
                             mbedtls_mpi *q,
                             const mbedtls_ecp_point *pt) {
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    if (mbedtls_ecp_get_type(grp) != MBEDTLS_ECP_TYPE_EDWARDS)
        return ret;
    if (mbedtls_mpi_cmp_int(&pt->Z, 1) != 0)
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(q, &pt->Y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(q, grp->pbits,
                    mbedtls_mpi_get_bit(&pt->X, 0)));
    ret = 0;
cleanup:
    return ret;
}

/* ------------------------------------------------------------------ */
/*  mbedtls_ecp_expand_edwards — stub (no longer needed for Ed25519)  */
/* ------------------------------------------------------------------ */
#if defined(MBEDTLS_ECP_DP_ED448_ENABLED) && defined(MBEDTLS_SHA3_C)
/* Ed448 seed expansion — kept for compatibility, not yet used */
int mbedtls_ecp_expand_edwards(mbedtls_ecp_group *grp,
                               const mbedtls_mpi *d,
                               mbedtls_mpi *q,
                               mbedtls_mpi *prefix) {
    (void)grp; (void)d; (void)q; (void)prefix;
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
}
#else
int mbedtls_ecp_expand_edwards(mbedtls_ecp_group *grp,
                               const mbedtls_mpi *d,
                               mbedtls_mpi *q,
                               mbedtls_mpi *prefix) {
    (void)grp; (void)d; (void)q; (void)prefix;
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
}
#endif

/* ------------------------------------------------------------------ */
/*  ed25519_setup_group — set group parameters for Ed25519            */
/* ------------------------------------------------------------------ */
int ed25519_setup_group(mbedtls_ecp_group *grp) {
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    mbedtls_ecp_group_init(grp);
    grp->id = MBEDTLS_ECP_DP_ED25519;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->P, (const unsigned char *)
        "\xed\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f", 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->A, &grp->P, 1));  /* A = -1 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&grp->B, 10,
        "37095705934669439368261579733463697440081861771719747696363762035337300239372"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->G.X, BE_Bx, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->G.Y, BE_By, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    grp->pbits = 255;
    grp->nbits = 254;
    ret = 0;
cleanup:
    if (ret != 0) mbedtls_ecp_group_free(grp);
    return ret;
}

#endif /* MBEDTLS_ECP_C */
