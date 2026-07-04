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
static int mbedtls_ecp_expand_ed25519(const mbedtls_mpi *d,
                                      mbedtls_mpi *q,
                                      mbedtls_mpi *prefix)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    uint8_t buf[34];
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, buf + 2, 32));
    buf[0] = 0x01; buf[1] = 0x20;
    buf[2] &= 248; buf[31] &= 127; buf[31] |= 64;
    if (prefix != NULL)
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(prefix, buf + 2, 32));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(q, buf, 34));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(q, 2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(q, buf, 34));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(q, buf + 2, 32));
cleanup:
    mbedtls_platform_zeroize(buf, sizeof(buf));
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
#include "mbedtls/sha512.h"

/* Ed25519 prime p = 2^255 - 19 */
static const uint8_t ed25519_p[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

/* Ed25519 base point B_y */
static const uint8_t ed25519_By[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};
/* Ed25519 base point B_x (recovered from y) */
static const uint8_t ed25519_Bx[32] = {
    0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe,
    0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
    0x69, 0x2c, 0xcc, 0x76, 0x94, 0xaa, 0x12, 0x3c,
    0x0c, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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
        /* Double current point */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&a, &X2, &X2)); /* A = X^2 */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&b, &Y2, &Y2)); /* B = Y^2 */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&c, &two, &Z2));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&c, &c, &Z2));  /* C = 2*Z^2 */
        ed25519_mont_reduce(&c, &c);
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&d, &a, &b));    /* D = A + B */
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&e, &a, &b));    /* E = A - B */
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&f, &d, &c));    /* F = D + C */
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&g, &d, &c));    /* G = D - C */
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&h, &b, &a));    /* H = B + A */
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
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&a, &Y2, &X2)); /* A = Y1 - X1 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&b, &Y1, &X1)); /* B = Y2 + X2 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tx, &a, &b));
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&a, &Y2, &X2)); /* A = Y1 + X1 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&b, &Y1, &X1)); /* B = Y2 - X2 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ty, &a, &b));
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
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&d_inv, &Z2, &p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&key->Q.X, &X2, &d_inv));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&key->Q.Y, &Y2, &d_inv));
    mbedtls_mpi_lset(&key->Q.Z, 1);
    ed25519_mont_reduce(&key->Q.X, &key->Q.X);
    ed25519_mont_reduce(&key->Q.Y, &key->Q.Y);

    /* Set private key scalar */
    mbedtls_mpi_copy(&key->d, &scalar);

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
#endif /* MBEDTLS_ECP_DP_ED25519_ENABLED */
