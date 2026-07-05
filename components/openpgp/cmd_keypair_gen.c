/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include "openpgp.h"
#include "do.h"
#include "random.h"
#include "eddsa_compat.h"

int cmd_keypair_gen(void) {
    if (P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 2 && apdu.nc != 5) {
        return SW_WRONG_LENGTH();
    }
    if (!has_pw3 && P1(apdu) == 0x80) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    uint16_t fid = 0x0;
    int r = PICOKEYS_OK;
    if (apdu.data[0] == 0xB6) {
        fid = EF_PK_SIG;
    }
    else if (apdu.data[0] == 0xB8) {
        fid = EF_PK_DEC;
    }
    else if (apdu.data[0] == 0xA4) {
        fid = EF_PK_AUT;
    }
    else {
        return SW_WRONG_DATA();
    }

    file_t *algo_ef = file_search_by_fid(fid - 0x0010, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    uint16_t algo_len = algorithm_attr_rsa2k[0];
    if (fid == EF_PK_SIG || fid == EF_PK_AUT) {
        algo = algorithm_attr_p384r1 + 1;
        algo_len = algorithm_attr_p384r1[0];
    }
    else if (fid == EF_PK_DEC) {
        algo = algorithm_attr_cv25519 + 1;
        algo_len = algorithm_attr_cv25519[0];
    }
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
        algo_len = file_get_size(algo_ef);
    }
    if (P1(apdu) == 0x80) { //generate
        if (algo[0] == ALGO_RSA) {
            int exponent = 65537, nlen = (algo[1] << 8) | algo[2];
            printf("KEYPAIR RSA %d\r\n", nlen);
            //if (nlen != 2048 && nlen != 4096)
            //    return SW_FUNC_NOT_SUPPORTED();
            mbedtls_rsa_context rsa;
            mbedtls_rsa_init(&rsa);
            r = mbedtls_rsa_gen_key(&rsa, random_fill_iterator, NULL, nlen, exponent);
            if (r != 0) {
                mbedtls_rsa_free(&rsa);
                return SW_EXEC_ERROR();
            }
            r = store_keys(&rsa, ALGO_RSA, fid, true);
            make_rsa_response(&rsa);
            mbedtls_rsa_free(&rsa);
            if (r != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
        }
        else if (algo[0] == ALGO_ECDH || algo[0] == ALGO_ECDSA || algo[0] == ALGO_EDDSA) {
            printf("KEYPAIR algo0=%02x alen=%d\r\n", algo[0], algo_len);
            mbedtls_ecp_group_id gid = get_ec_group_id_from_attr(algo + 1, algo_len - 1);
            printf("KEYPAIR gid=%d\r\n", gid);
            if (gid == MBEDTLS_ECP_DP_NONE) {
                printf("KEYPAIR gid NONE\r\n");
                return SW_FUNC_NOT_SUPPORTED();
            }
#ifdef MBEDTLS_EDDSA_C
            if (gid == MBEDTLS_ECP_DP_ED25519) {
                printf("KEYPAIR Ed25519\r\n");
                mbedtls_ecp_keypair ed;
                mbedtls_ecp_keypair_init(&ed);
                mbedtls_ecp_group_init(&ed.grp);
                ed.grp.id = gid;
                r = ed25519_generate_keypair(&ed, random_fill_iterator, NULL);
                if (r != 0) {
                    mbedtls_ecp_keypair_free(&ed);
                    return SW_EXEC_ERROR();
                }
                r = store_keys(&ed, algo[0], fid, true);
                make_ecdsa_response(&ed);
                mbedtls_ecp_keypair_free(&ed);
                if (r != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                goto keygen_done;
            }
            if (gid == MBEDTLS_ECP_DP_ED448) {
                return SW_FUNC_NOT_SUPPORTED(); // Ed448 not yet supported
            }
#endif
            if (gid == MBEDTLS_ECP_DP_CURVE25519) {
                printf("KEYPAIR X25519\r\n");
                mbedtls_ecp_keypair ecdh;
                mbedtls_ecp_keypair_init(&ecdh);
                mbedtls_ecp_group_load(&ecdh.grp, gid);
                uint8_t xkey[32];
                random_fill_iterator(NULL, xkey, 32);
                r = mbedtls_mpi_read_binary(&ecdh.d, xkey, 32);
                mbedtls_platform_zeroize(xkey, sizeof(xkey));
                if (r != 0) {
                    mbedtls_ecp_keypair_free(&ecdh);
                    return SW_EXEC_ERROR();
                }
                r = mbedtls_ecp_keypair_calc_public(&ecdh, random_fill_iterator, NULL);
                if (r != 0) {
                    mbedtls_ecp_keypair_free(&ecdh);
                    return SW_EXEC_ERROR();
                }
                r = store_keys(&ecdh, algo[0], fid, true);
                make_ecdsa_response(&ecdh);
                mbedtls_ecp_keypair_free(&ecdh);
                if (r != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                goto keygen_done;
            }
            mbedtls_ecp_keypair ecdsa;
            mbedtls_ecp_keypair_init(&ecdsa);
            r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_fill_iterator, NULL);
            if (r != 0) {
                mbedtls_ecp_keypair_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            r = store_keys(&ecdsa, algo[0], fid, true);
            make_ecdsa_response(&ecdsa);
            mbedtls_ecp_keypair_free(&ecdsa);
            if (r != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
        }
        else {
            return SW_FUNC_NOT_SUPPORTED();
        }
#ifdef MBEDTLS_EDDSA_C
keygen_done:
#endif
        file_t *pbef = file_search_by_fid(fid + 3, NULL, SPECIFY_EF);
        if (!pbef) {
            return SW_REFERENCE_NOT_FOUND();
        }
        r = file_put_data(pbef, res_APDU, res_APDU_size);
        if (r != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        if (fid == EF_PK_SIG) {
            reset_sig_count();
        }
        else if (fid == EF_PK_DEC) {
            // OpenPGP does not allow generating AES keys. So, we generate a new one when gen for DEC is called.
            // It is a 256 AES key by default.
            uint8_t aes_key[32]; //maximum AES key size
            uint8_t key_size = 32;
            memcpy(aes_key, random_bytes_get(key_size), key_size);
            r = store_keys(aes_key, ALGO_AES_256, EF_AES_KEY, true);
            /* if storing the key fails, we silently continue */
            //if (r != PICOKEYS_OK)
            //    return SW_EXEC_ERROR();
        }
        // Store algorithm attribute for PSO
        const uint8_t *algo_attr = algorithm_attr_p384r1;
        if (fid == EF_PK_DEC) algo_attr = algorithm_attr_cv25519;
        if (!file_has_data(algo_ef)) {
            file_put_data(algo_ef, algo_attr, algo_attr[0] + 1);
        }
        flash_commit();
        return SW_OK();
    }
    else if (P1(apdu) == 0x81) { //read
        file_t *ef = file_search_by_fid(fid + 3, NULL, SPECIFY_EF);
        if (!file_has_data(ef)) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU_size = file_get_size(ef);
        memcpy(res_APDU, file_get_data(ef), res_APDU_size);
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}
