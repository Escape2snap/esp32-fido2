#ifndef MBEDTLS_EDDSA_COMPAT_H
#define MBEDTLS_EDDSA_COMPAT_H

#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/sha3.h"

/* ESP-IDF v5.4.4 mbedtls lacks MBEDTLS_ECP_DP_ED25519/448 and SHAKE256 */
#ifndef MBEDTLS_ECP_DP_ED25519
#define MBEDTLS_ECP_DP_ED25519 ((mbedtls_ecp_group_id)(MBEDTLS_ECP_DP_CURVE448 + 1))
#endif

#ifndef MBEDTLS_ECP_DP_ED448
#define MBEDTLS_ECP_DP_ED448   ((mbedtls_ecp_group_id)(MBEDTLS_ECP_DP_CURVE448 + 2))
#endif

#ifndef MBEDTLS_SHA3_SHAKE256
#define MBEDTLS_SHA3_SHAKE256  ((mbedtls_sha3_id)(MBEDTLS_SHA3_512 + 2))
#endif

/* Declarations provided by eddsa_shim.c */
int mbedtls_ecp_point_encode(const mbedtls_ecp_group *grp,
                             mbedtls_mpi *q,
                             const mbedtls_ecp_point *pt);
int mbedtls_ecp_expand_edwards(mbedtls_ecp_group *grp,
                               const mbedtls_mpi *d, mbedtls_mpi *q,
                               mbedtls_mpi *prefix);

/* Edwards key expansion — SHA-512 seed → clamped scalar */
int eddsa_expand_key(const mbedtls_mpi *d, mbedtls_mpi *q,
                     unsigned char *prefix_out);

#endif /* MBEDTLS_EDDSA_COMPAT_H */
