/*
 * ESP32-FIDO2 — Edwards curve ECP functions for EdDSA
 * Extracted from polhenarejos/mbedtls (mbedtls-3.6-eddsa fork)
 */
#include "common.h"

#if defined(MBEDTLS_ECP_C)

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/error.h"
#include "eddsa_compat.h"
#ifdef ESP_PLATFORM
#include "esp_task_wdt.h"
#define ED25519_WDT_RESET() esp_task_wdt_reset()
#else
#define ED25519_WDT_RESET()
#endif

/* ------------------------------------------------------------------ */
/* mbedtls_ecp_point_encode — Edwards version (mpi output)            */
/* ------------------------------------------------------------------ */
int mbedtls_ecp_point_encode(const mbedtls_ecp_group *grp,
                             mbedtls_mpi *q,
                             const mbedtls_ecp_point *pt)
{
    int ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

    if (mbedtls_ecp_get_type(grp) != MBEDTLS_ECP_TYPE_EDWARDS)
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    if (mbedtls_mpi_cmp_int(&pt->Z, 1) != 0)
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(q, &pt->Y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(q, grp->pbits,
                    mbedtls_mpi_get_bit(&pt->X, 0)));
cleanup:
    return ret;
}

/* ------------------------------------------------------------------ */
/* Edwards scalar expansion helpers                                    */
/* ------------------------------------------------------------------ */
#if defined(MBEDTLS_ECP_DP_ED25519_ENABLED)
#include "mbedtls/sha512.h"
/* Ed25519 seed expansion: SHA-512(seed) → {scalar, prefix} */
static int mbedtls_ecp_expand_ed25519(const mbedtls_mpi *d,
                                      mbedtls_mpi *q,
                                      mbedtls_mpi *prefix)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    uint8_t seed[32], hash[64];
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, seed, 32));
    mbedtls_sha512(seed, 32, hash, 0);
    hash[0] &= 248; hash[31] &= 63; hash[31] |= 64;
    if (prefix != NULL)
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(prefix, hash + 32, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(q, hash, 32));
cleanup:
    mbedtls_platform_zeroize(seed, sizeof(seed));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return ret;
}
#endif

#if defined(MBEDTLS_ECP_DP_ED448_ENABLED) && defined(MBEDTLS_SHA3_C)
static int mbedtls_ecp_expand_ed448(const mbedtls_mpi *d,
                                     mbedtls_mpi *q,
                                     mbedtls_mpi *prefix)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    uint8_t buf[58], hash[64];
    mbedtls_sha3_context sha_ctx;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, buf + 2, 57));
    buf[0] = 0x01; buf[1] = 0x38;
    mbedtls_sha3_init(&sha_ctx);
    mbedtls_sha3_starts(&sha_ctx, MBEDTLS_SHA3_SHAKE256);
    mbedtls_sha3_update(&sha_ctx, buf, 59);
    mbedtls_sha3_finish(&sha_ctx, hash, sizeof(hash));
    mbedtls_sha3_free(&sha_ctx);
    hash[0] &= 252; hash[55] |= 128;
    if (prefix != NULL)
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(prefix, hash, 57));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(q, hash, 57));
cleanup:
    mbedtls_platform_zeroize(buf, sizeof(buf));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return ret;
}
#endif

/* ------------------------------------------------------------------ */
/* mbedtls_ecp_expand_edwards — expand private key for Edwards curves */
/* ------------------------------------------------------------------ */
int mbedtls_ecp_expand_edwards(mbedtls_ecp_group *grp,
                               const mbedtls_mpi *d,
                               mbedtls_mpi *q,
                               mbedtls_mpi *prefix)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
#if defined(MBEDTLS_ECP_DP_ED25519_ENABLED)
    if (grp->id == MBEDTLS_ECP_DP_ED25519)
        ret = mbedtls_ecp_expand_ed25519(d, q, prefix);
#endif
#if defined(MBEDTLS_ECP_DP_ED448_ENABLED) && defined(MBEDTLS_SHA3_C)
    if (grp->id == MBEDTLS_ECP_DP_ED448)
        ret = mbedtls_ecp_expand_ed448(d, q, prefix);
#endif
    return ret;
}

#endif /* MBEDTLS_ECP_C */

/* ------------------------------------------------------------------ */
/* Ed25519 key generation — self-contained Edwards point multiplication */
/* Uses curve: -x^2 + y^2 = 1 + d*x^2*y^2 over GF(2^255-19)           */
/* ------------------------------------------------------------------ */
#if defined(MBEDTLS_ECP_DP_ED25519_ENABLED)

/* Ed25519 prime p = 2^255 - 19 */
static const uint8_t ed25519_p[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

/* Ed25519 base point B_x (big-endian) — matches mbedtls fork ecp_use_ed25519 */
static const uint8_t ed25519_Bx[32] = {
    0x21, 0x69, 0x36, 0xD3, 0xCD, 0x6E, 0x53, 0xFE,
    0xC0, 0xA4, 0xE2, 0x31, 0xFD, 0xD6, 0xDC, 0x5C,
    0x69, 0x2C, 0xC7, 0x60, 0x95, 0x25, 0xA7, 0xB2,
    0xC9, 0x56, 0x2D, 0x60, 0x8F, 0x25, 0xD5, 0x1A
};
/* Ed25519 base point B_y (big-endian) */
static const uint8_t ed25519_By[32] = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58
};

static void ed25519_mont_reduce(mbedtls_mpi *r, const mbedtls_mpi *a) {
    mbedtls_mpi p;
    mbedtls_mpi_init(&p);
    mbedtls_mpi_read_binary(&p, ed25519_p, 32);
    mbedtls_mpi_mod_mpi(r, a, &p);
    mbedtls_mpi_free(&p);
}

int ed25519_generate_keypair(mbedtls_ecp_keypair *key,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int ret;
    uint8_t seed[32], hash[64];
    mbedtls_mpi p, d_inv, a, b, c, d, e, f, g, h;
    mbedtls_mpi X1, Y1, Z1, T1;
    mbedtls_mpi X2, Y2, Z2, T2;
    mbedtls_mpi tx, ty, tz, tt;
    mbedtls_mpi two, scalar, bp_x, bp_y, ed_d;

    printf("Ed25519 keygen: entering\n");
    /* Generate 32 random bytes as seed */
    f_rng(p_rng, seed, 32);

    /* h = SHA-512(seed) */
    mbedtls_sha512(seed, 32, hash, 0);

    /* Clamp: h[0] &= 248, h[31] &= 63, h[31] |= 64 */
    hash[0] &= 248;
    hash[31] &= 63;
    hash[31] |= 64;

    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&d_inv);
    mbedtls_mpi_init(&a); mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&c); mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&e); mbedtls_mpi_init(&f);
    mbedtls_mpi_init(&g); mbedtls_mpi_init(&h);
    mbedtls_mpi_init(&X1); mbedtls_mpi_init(&Y1); mbedtls_mpi_init(&Z1); mbedtls_mpi_init(&T1);
    mbedtls_mpi_init(&X2); mbedtls_mpi_init(&Y2); mbedtls_mpi_init(&Z2); mbedtls_mpi_init(&T2);
    mbedtls_mpi_init(&tx); mbedtls_mpi_init(&ty); mbedtls_mpi_init(&tz); mbedtls_mpi_init(&tt);
    mbedtls_mpi_init(&two); mbedtls_mpi_init(&scalar);
    mbedtls_mpi_init(&bp_x); mbedtls_mpi_init(&bp_y); mbedtls_mpi_init(&ed_d);

    mbedtls_mpi_read_binary(&p, ed25519_p, 32);
    mbedtls_mpi_read_binary(&bp_x, ed25519_Bx, 32);
    mbedtls_mpi_read_binary(&bp_y, ed25519_By, 32);
    mbedtls_mpi_read_binary(&scalar, hash, 32);
    ed25519_mont_reduce(&scalar, &scalar);
    mbedtls_mpi_lset(&two, 2);

    /* d = -121665/121666 mod p = 37095705934669439368261579733463697440081861771719747696363762035337300239372 */
    /* Use precomputed value */
    mbedtls_mpi_read_string(&ed_d, 10, "37095705934669439368261579733463697440081861771719747696363762035337300239372");

    /* Set base point in extended coordinates */
    mbedtls_mpi_copy(&X1, &bp_x);
    mbedtls_mpi_copy(&Y1, &bp_y);
    mbedtls_mpi_lset(&Z1, 1);
    /* T1 = X1 * Y1 * Z1^{-1}, but Z1=1 so T1 = X1 * Y1 mod p */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T1, &X1, &Y1));
    ed25519_mont_reduce(&T1, &T1);

    /* Double-and-add scalar multiplication */
    mbedtls_mpi_lset(&X2, 0); mbedtls_mpi_lset(&Y2, 1);
    mbedtls_mpi_lset(&Z2, 1); mbedtls_mpi_lset(&T2, 0);

    for (int i = 255; i >= 0; i--) {
        if (i % 8 == 0) ED25519_WDT_RESET();
        if (i % 32 == 0) printf("Ed25519 keygen: %d/256\n", 256-i);
        /* Double current point */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&a, &X2, &X2)); /* A = X^2 */
        ed25519_mont_reduce(&a, &a);
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&b, &Y2, &Y2)); /* B = Y^2 */
        ed25519_mont_reduce(&b, &b);
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&c, &two, &Z2));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&c, &c, &Z2));  /* C = 2*Z^2 */
        ed25519_mont_reduce(&c, &c);
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&d, &a, &b));    /* D = A + B */
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&e, &a, &b));    /* E = A - B */
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&f, &d, &c));    /* F = D + C */
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&g, &d, &c));    /* G = D - C */
        /* H = 2 * Y * Z (HWCD extended coordinates doubling, a = -1) */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&h, &Y2, &Z2));
        ed25519_mont_reduce(&h, &h);
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&h, &h, &two));
        ed25519_mont_reduce(&h, &h);
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&X2, &e, &f));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Y2, &g, &h));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T2, &e, &h));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z2, &f, &g));
        ed25519_mont_reduce(&X2, &X2); ed25519_mont_reduce(&Y2, &Y2);
        ed25519_mont_reduce(&T2, &T2); ed25519_mont_reduce(&Z2, &Z2);

        if (mbedtls_mpi_get_bit(&scalar, i)) {
            /* Add base point: R = R + B */
            /* Using extended coordinates addition: */
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&a, &Y1, &X1)); /* A = Y1 - X1 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&b, &Y2, &X2)); /* B = Y2 - X2 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tx, &a, &b));  /* tx = (Y1-X1)*(Y2-X2) */
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&a, &Y1, &X1)); /* A = Y1 + X1 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&b, &Y2, &X2)); /* B = Y2 + X2 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ty, &a, &b));  /* ty = (Y1+X1)*(Y2+X2) */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&a, &T2, &ed_d)); /* C = T1 * 2*d * T2 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&a, &a, &two));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&b, &a, &T1));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&c, &Z2, &two));  /* D = Z1 * 2 * Z2 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&d, &c, &Z1));
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&e, &ty, &tx));   /* E = B - A */
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&f, &d, &b));     /* F = D - C */
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&g, &d, &b));     /* G = D + C */
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&h, &ty, &tx));   /* H = B + A */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&X2, &e, &f));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Y2, &g, &h));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T2, &e, &h));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Z2, &f, &g));
            ed25519_mont_reduce(&X2, &X2); ed25519_mont_reduce(&Y2, &Y2);
            ed25519_mont_reduce(&T2, &T2); ed25519_mont_reduce(&Z2, &Z2);
        }
    }

    /* Convert to affine: x = X/Z, y = Y/Z */
    printf("Ed25519 keygen: loop done\n");
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&d_inv, &Z2, &p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&key->Q.X, &X2, &d_inv));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&key->Q.Y, &Y2, &d_inv));
    mbedtls_mpi_lset(&key->Q.Z, 1);
    ed25519_mont_reduce(&key->Q.X, &key->Q.X);
    ed25519_mont_reduce(&key->Q.Y, &key->Q.Y);

    /* Copy group modulus P for make_ecdsa_response */
    mbedtls_mpi_copy(&key->grp.P, &p);
    key->grp.pbits = 255;
    key->grp.nbits = 254;
    /* Set generator G = (Bx, By) */
    mbedtls_mpi_copy(&key->grp.G.X, &bp_x);
    mbedtls_mpi_copy(&key->grp.G.Y, &bp_y);
    mbedtls_mpi_lset(&key->grp.G.Z, 1);

    /* Set private key = seed (not clamped scalar — for eddsa signing) */
    mbedtls_mpi_read_binary(&key->d, seed, 32);

    printf("Ed25519 keygen: success\n");
    ret = 0;
cleanup:
    mbedtls_mpi_free(&p); mbedtls_mpi_free(&d_inv);
    mbedtls_mpi_free(&a); mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&c); mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&e); mbedtls_mpi_free(&f);
    mbedtls_mpi_free(&g); mbedtls_mpi_free(&h);
    mbedtls_mpi_free(&X1); mbedtls_mpi_free(&Y1); mbedtls_mpi_free(&Z1); mbedtls_mpi_free(&T1);
    mbedtls_mpi_free(&X2); mbedtls_mpi_free(&Y2); mbedtls_mpi_free(&Z2); mbedtls_mpi_free(&T2);
    mbedtls_mpi_free(&tx); mbedtls_mpi_free(&ty); mbedtls_mpi_free(&tz); mbedtls_mpi_free(&tt);
    mbedtls_mpi_free(&two); mbedtls_mpi_free(&scalar);
    mbedtls_mpi_free(&bp_x); mbedtls_mpi_free(&bp_y); mbedtls_mpi_free(&ed_d);
    return ret;
}

/* Set up Ed25519 group params (for key loading without system ecp support) */
int ed25519_setup_group(mbedtls_ecp_group *grp) {
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    mbedtls_ecp_group_init(grp);
    grp->id = MBEDTLS_ECP_DP_ED25519;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->P, ed25519_p, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->A, &grp->P, 1)); /* A = -1 mod p */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&grp->B, 10,
        "37095705934669439368261579733463697440081861771719747696363762035337300239372"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->G.X, ed25519_Bx, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->G.Y, ed25519_By, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    grp->pbits = 255;
    grp->nbits = 254;
    ret = 0;
cleanup:
    if (ret != 0) mbedtls_ecp_group_free(grp);
    return ret;
}

/* Ed25519 group order l = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t ed25519_l[32] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
};

/* Encode Edwards point as 32-byte little-endian Y + X sign bit */
static void ed25519_encode_point(mbedtls_mpi *x, mbedtls_mpi *y, uint8_t out[32]) {
    mbedtls_mpi q;
    mbedtls_mpi_init(&q);
    mbedtls_mpi_copy(&q, y);
    mbedtls_mpi_set_bit(&q, 255, mbedtls_mpi_get_bit(x, 0));
    mbedtls_mpi_write_binary_le(&q, out, 32);
    mbedtls_mpi_free(&q);
}

/* Self-contained Ed25519 signing.
 * key->d must contain the 32-byte seed. Computes Q = scalar*B internally. */
int ed25519_sign(const mbedtls_ecp_keypair *key,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t sig[64])
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    uint8_t seed[32], hash[64], r_buf[64], h_buf[64];
    uint8_t r_enc[32], q_enc[32];
    mbedtls_mpi p, l, two, ed_d;
    mbedtls_mpi scalar, prefix, r_nonce, k_chal;
    mbedtls_mpi X1, Y1, Z1, T1;        /* base point */
    mbedtls_mpi Xr, Yr, Zr, Tr;        /* R = r * B */
    mbedtls_mpi Xq, Yq, Zq, Tq;        /* Q = scalar * B */
    mbedtls_mpi a, b, c, d, e, f, g, h;
    mbedtls_mpi tx, ty;
    mbedtls_mpi bp_x, bp_y;
    mbedtls_sha512_context sha;

    mbedtls_mpi_init(&p); mbedtls_mpi_init(&l); mbedtls_mpi_init(&two);
    mbedtls_mpi_init(&ed_d); mbedtls_mpi_init(&scalar); mbedtls_mpi_init(&prefix);
    mbedtls_mpi_init(&r_nonce); mbedtls_mpi_init(&k_chal);
    mbedtls_mpi_init(&X1); mbedtls_mpi_init(&Y1); mbedtls_mpi_init(&Z1); mbedtls_mpi_init(&T1);
    mbedtls_mpi_init(&Xr); mbedtls_mpi_init(&Yr); mbedtls_mpi_init(&Zr); mbedtls_mpi_init(&Tr);
    mbedtls_mpi_init(&Xq); mbedtls_mpi_init(&Yq); mbedtls_mpi_init(&Zq); mbedtls_mpi_init(&Tq);
    mbedtls_mpi_init(&a); mbedtls_mpi_init(&b); mbedtls_mpi_init(&c);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&e); mbedtls_mpi_init(&f);
    mbedtls_mpi_init(&g); mbedtls_mpi_init(&h);
    mbedtls_mpi_init(&tx); mbedtls_mpi_init(&ty);
    mbedtls_mpi_init(&bp_x); mbedtls_mpi_init(&bp_y);

    mbedtls_mpi_read_binary(&p, ed25519_p, 32);
    mbedtls_mpi_read_binary(&l, ed25519_l, 32);
    mbedtls_mpi_read_binary(&bp_x, ed25519_Bx, 32);
    mbedtls_mpi_read_binary(&bp_y, ed25519_By, 32);
    mbedtls_mpi_lset(&two, 2);
    mbedtls_mpi_read_string(&ed_d, 10,
        "37095705934669439368261579733463697440081861771719747696363762035337300239372");

    /* Step 1: expand seed → scalar + prefix */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&key->d, seed, 32));
    mbedtls_sha512(seed, 32, hash, 0);
    hash[0] &= 248; hash[31] &= 63; hash[31] |= 64;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&scalar, hash, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&prefix, hash + 32, 32));

    /* Helper: compute point = scalar * base_point (double-and-add, extended coords) */
    #define ED25519_MUL_TO(Xv,Yv,Zv,Tv,scalar_val) do { \
        mbedtls_mpi_lset(&Xv, 0); mbedtls_mpi_lset(&Yv, 1); \
        mbedtls_mpi_lset(&Zv, 1); mbedtls_mpi_lset(&Tv, 0); \
        for (int _i = 255; _i >= 0; _i--) { \
            if (_i % 8 == 0) ED25519_WDT_RESET(); \
            /* double */ \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&a, &Xv, &Xv)); \
            mbedtls_mpi_mod_mpi(&a, &a, &p); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&b, &Yv, &Yv)); \
            mbedtls_mpi_mod_mpi(&b, &b, &p); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&c, &two, &Zv)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&c, &c, &Zv)); \
            mbedtls_mpi_mod_mpi(&c, &c, &p); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&d, &a, &b)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&e, &a, &b)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&f, &d, &c)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&g, &d, &c)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&h, &Yv, &Zv)); \
            mbedtls_mpi_mod_mpi(&h, &h, &p); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&h, &h, &two)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Xv, &e, &f)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Yv, &g, &h)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Tv, &e, &h)); \
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Zv, &f, &g)); \
            mbedtls_mpi_mod_mpi(&Xv, &Xv, &p); mbedtls_mpi_mod_mpi(&Yv, &Yv, &p); \
            mbedtls_mpi_mod_mpi(&Tv, &Tv, &p); mbedtls_mpi_mod_mpi(&Zv, &Zv, &p); \
            if (mbedtls_mpi_get_bit(scalar_val, _i)) { \
                /* add base point */ \
                MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&a, &Y1, &X1)); /* A = Y1 - X1 */ \
                MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&b, &Yv, &Xv)); /* B = Yv - Xv */ \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tx, &a, &b));  /* tx = (Y1-X1)*(Yv-Xv) */ \
                MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&a, &Y1, &X1)); /* A = Y1 + X1 */ \
                MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&b, &Yv, &Xv)); /* B = Yv + Xv */ \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ty, &a, &b));  /* ty = (Y1+X1)*(Yv+Xv) */ \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&a, &Tv, &ed_d)); \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&a, &a, &two)); \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&b, &a, &T1)); \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&c, &Zv, &two)); \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&d, &c, &Z1)); \
                mbedtls_mpi_sub_mpi(&e, &ty, &tx); \
                mbedtls_mpi_sub_mpi(&f, &d, &b); \
                mbedtls_mpi_add_mpi(&g, &d, &b); \
                mbedtls_mpi_add_mpi(&h, &ty, &tx); \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Xv, &e, &f)); \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Yv, &g, &h)); \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Tv, &e, &h)); \
                MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Zv, &f, &g)); \
                mbedtls_mpi_mod_mpi(&Xv, &Xv, &p); mbedtls_mpi_mod_mpi(&Yv, &Yv, &p); \
                mbedtls_mpi_mod_mpi(&Tv, &Tv, &p); mbedtls_mpi_mod_mpi(&Zv, &Zv, &p); \
            } \
        } \
    } while(0)

    /* Set base point extended coords */
    mbedtls_mpi_copy(&X1, &bp_x); mbedtls_mpi_copy(&Y1, &bp_y);
    mbedtls_mpi_lset(&Z1, 1);
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T1, &X1, &Y1));
    mbedtls_mpi_mod_mpi(&T1, &T1, &p);

    /* Compute Q = scalar * B */
    ED25519_MUL_TO(Xq, Yq, Zq, Tq, &scalar);

    /* Convert Q to affine */
    {
        mbedtls_mpi d_inv;
        mbedtls_mpi_init(&d_inv);
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&d_inv, &Zq, &p));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Xq, &Xq, &d_inv));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Yq, &Yq, &d_inv));
        mbedtls_mpi_mod_mpi(&Xq, &Xq, &p);
        mbedtls_mpi_mod_mpi(&Yq, &Yq, &p);
        mbedtls_mpi_free(&d_inv);
    }
    ed25519_encode_point(&Xq, &Yq, q_enc);

    /* Step 2: r = SHA-512(prefix || msg) mod l */
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    {
        uint8_t prefix_buf[32];
        mbedtls_mpi_write_binary_le(&prefix, prefix_buf, 32);
        mbedtls_sha512_update(&sha, prefix_buf, 32);
    }
    mbedtls_sha512_update(&sha, msg, msg_len);
    mbedtls_sha512_finish(&sha, r_buf);
    mbedtls_sha512_free(&sha);
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&r_nonce, r_buf, 64));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&r_nonce, &r_nonce, &l));

    /* Step 3: R = r * B */
    ED25519_MUL_TO(Xr, Yr, Zr, Tr, &r_nonce);

    /* Convert R to affine */
    {
        mbedtls_mpi d_inv;
        mbedtls_mpi_init(&d_inv);
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&d_inv, &Zr, &p));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Xr, &Xr, &d_inv));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&Yr, &Yr, &d_inv));
        mbedtls_mpi_mod_mpi(&Xr, &Xr, &p);
        mbedtls_mpi_mod_mpi(&Yr, &Yr, &p);
        mbedtls_mpi_free(&d_inv);
    }
    ed25519_encode_point(&Xr, &Yr, r_enc);

    /* Step 4: k = SHA-512(R_enc || Q_enc || msg) mod l */
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    mbedtls_sha512_update(&sha, r_enc, 32);
    mbedtls_sha512_update(&sha, q_enc, 32);
    mbedtls_sha512_update(&sha, msg, msg_len);
    mbedtls_sha512_finish(&sha, h_buf);
    mbedtls_sha512_free(&sha);
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&k_chal, h_buf, 64));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&k_chal, &k_chal, &l));

    /* Step 5: S = (r + k * scalar) mod l */
    {
        mbedtls_mpi tmp;
        mbedtls_mpi_init(&tmp);
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp, &k_chal, &scalar));
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tmp, &r_nonce, &tmp));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp, &tmp, &l));
        /* Output: sig[0:32] = R_enc, sig[32:64] = S (little-endian) */
        memcpy(sig, r_enc, 32);
        mbedtls_mpi_write_binary_le(&tmp, sig + 32, 32);
        mbedtls_mpi_free(&tmp);
    }

    ret = 0;
cleanup:
    mbedtls_mpi_free(&p); mbedtls_mpi_free(&l); mbedtls_mpi_free(&two);
    mbedtls_mpi_free(&ed_d); mbedtls_mpi_free(&scalar); mbedtls_mpi_free(&prefix);
    mbedtls_mpi_free(&r_nonce); mbedtls_mpi_free(&k_chal);
    mbedtls_mpi_free(&X1); mbedtls_mpi_free(&Y1); mbedtls_mpi_free(&Z1); mbedtls_mpi_free(&T1);
    mbedtls_mpi_free(&Xr); mbedtls_mpi_free(&Yr); mbedtls_mpi_free(&Zr); mbedtls_mpi_free(&Tr);
    mbedtls_mpi_free(&Xq); mbedtls_mpi_free(&Yq); mbedtls_mpi_free(&Zq); mbedtls_mpi_free(&Tq);
    mbedtls_mpi_free(&a); mbedtls_mpi_free(&b); mbedtls_mpi_free(&c);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&e); mbedtls_mpi_free(&f);
    mbedtls_mpi_free(&g); mbedtls_mpi_free(&h);
    mbedtls_mpi_free(&tx); mbedtls_mpi_free(&ty);
    mbedtls_mpi_free(&bp_x); mbedtls_mpi_free(&bp_y);
    mbedtls_platform_zeroize(seed, sizeof(seed));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    mbedtls_platform_zeroize(r_buf, sizeof(r_buf));
    mbedtls_platform_zeroize(h_buf, sizeof(h_buf));
    mbedtls_platform_zeroize(r_enc, sizeof(r_enc));
    mbedtls_platform_zeroize(q_enc, sizeof(q_enc));
    return ret;
}
#endif /* MBEDTLS_ECP_DP_ED25519_ENABLED */
