/*
 * ESP32-IDF compatibility shims for EdDSA
 * Provides functions missing from ESP-IDF's mbedTLS build.
 */
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/sha512.h"
#include "mbedtls/sha3.h"
#include "mbedtls/platform_util.h"
#include "eddsa_compat.h"

/* Edwards key expansion — SHA-512 seed → clamped scalar */
int eddsa_expand_key(const mbedtls_mpi *d, mbedtls_mpi *q,
                     unsigned char *prefix_out)
{
    unsigned char key_buf[32], sha_buf[64];
    if (mbedtls_mpi_size(d) != 32) return MBEDTLS_ERR_ECP_INVALID_KEY;

    mbedtls_mpi_write_binary_le(d, key_buf, 32);
    mbedtls_sha512(key_buf, 32, sha_buf, 0);
    mbedtls_platform_zeroize(key_buf, sizeof(key_buf));

    sha_buf[0] &= ~0x7;
    sha_buf[31] &= ~0x80;
    sha_buf[31] |= 0x40;

    mbedtls_mpi_read_binary_le(q, sha_buf, 32);
    if (prefix_out) memcpy(prefix_out, sha_buf + 32, 32);
    mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));
    return 0;
}

/* mbedtls_ecp_point_encode — write point to MPI */
int mbedtls_ecp_point_encode(const mbedtls_ecp_group *grp,
                             mbedtls_mpi *q,
                             const mbedtls_ecp_point *pt)
{
    size_t olen;
    uint8_t buf[MBEDTLS_ECP_MAX_PT_LEN];
    int ret = mbedtls_ecp_point_write_binary(grp, pt, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &olen, buf, sizeof(buf));
    if (ret != 0) return ret;
    return mbedtls_mpi_read_binary(q, buf, olen);
}

/* mbedtls_ecp_expand_edwards — expand EdDSA private key seed */
int mbedtls_ecp_expand_edwards(mbedtls_ecp_group *grp,
                               const mbedtls_mpi *d, mbedtls_mpi *q,
                               mbedtls_mpi *prefix)
{
    (void)grp;
    unsigned char prefix_buf[32];
    int ret = eddsa_expand_key(d, q, prefix ? prefix_buf : NULL);
    if (ret == 0 && prefix) {
        mbedtls_mpi_read_binary(prefix, prefix_buf, 32);
    }
    mbedtls_platform_zeroize(prefix_buf, sizeof(prefix_buf));
    return ret;
}
