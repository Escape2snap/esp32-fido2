/*
 * ESP32-FIDO2 — EdDSA compatibility for ESP-IDF mbedtls
 * ESP-IDF's mbedtls lacks MBEDTLS_ECP_DP_ED25519, ED448, and SHAKE256.
 * These values match the polhenarejos/mbedtls mbedtls-3.6-eddsa fork.
 */
#ifndef EDDSA_COMPAT_H
#define EDDSA_COMPAT_H

#include "mbedtls/ecp.h"
#include "mbedtls/sha3.h"

#ifndef MBEDTLS_ECP_DP_ED25519
#define MBEDTLS_ECP_DP_ED25519 ((mbedtls_ecp_group_id)(MBEDTLS_ECP_DP_CURVE448 + 1))
#endif

#ifndef MBEDTLS_ECP_DP_ED448
#define MBEDTLS_ECP_DP_ED448   ((mbedtls_ecp_group_id)(MBEDTLS_ECP_DP_CURVE448 + 2))
#endif

#ifndef MBEDTLS_SHA3_SHAKE256
#define MBEDTLS_SHA3_SHAKE256  ((mbedtls_sha3_id)(MBEDTLS_SHA3_512 + 2))
#endif

#ifndef MBEDTLS_ECP_TYPE_EDWARDS
#define MBEDTLS_ECP_TYPE_EDWARDS ((mbedtls_ecp_curve_type)(MBEDTLS_ECP_TYPE_MONTGOMERY + 1))
#endif

#ifndef MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE
#define MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE (-0x4E80)
#endif

#endif /* EDDSA_COMPAT_H */
