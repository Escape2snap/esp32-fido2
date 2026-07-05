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

/* Task WDT management for long-running Ed25519 scalar multiplication */
/* Must yield to prevent IDLE task watchdog from starving */
#ifdef ESP_PLATFORM
#include "esp_task_wdt.h"
#define ED25519_WDT_RESET() do { esp_task_wdt_reset(); taskYIELD(); } while(0)
#define ED25519_WDT_ADD()   esp_task_wdt_add(NULL)
#define ED25519_WDT_DEL()   esp_task_wdt_delete(NULL)
#else
#define ED25519_WDT_RESET()
#define ED25519_WDT_ADD()
#define ED25519_WDT_DEL()
#endif

/* Set up Ed25519 group parameters manually (bypasses system ecp_group_load) */
int ed25519_setup_group(mbedtls_ecp_group *grp);
/* Ed25519 self-contained key generation */
#if defined(MBEDTLS_ECP_DP_ED25519_ENABLED)
#include "mbedtls/ecp.h"
int ed25519_generate_keypair(mbedtls_ecp_keypair *key,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng);
/* Self-contained Ed25519 signing. key->d must contain 32-byte seed. */
int ed25519_sign(const mbedtls_ecp_keypair *key,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t sig[64]);
/* Compute public key Q from loaded seed in key->d */
int ed25519_compute_public(mbedtls_ecp_keypair *key);
#endif

#endif /* EDDSA_COMPAT_H */
