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
