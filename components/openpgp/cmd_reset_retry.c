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
#include <inttypes.h>
#include "openpgp.h"
#include "otp.h"

#define DBG_TAG "[DBG_fix-openpgp-pin-retry]"
#define DBG_PRINTF(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)

int cmd_reset_retry(void) {
    DBG_PRINTF("%s cmd_reset_retry p1=0x%02x p2=0x%02x nc=%" PRIu32 "\n", DBG_TAG, P1(apdu), P2(apdu), apdu.nc);
    if (P2(apdu) != 0x81) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (P1(apdu) == 0x0 || P1(apdu) == 0x2) {
        int newpin_len = 0;
        file_t *pw = NULL;
        has_pw1 = false;
        if (!(pw = file_search_by_fid(EF_PW1, NULL, SPECIFY_EF))) {
            DBG_PRINTF("%s cmd_reset_retry: EF_PW1 not found\n", DBG_TAG);
            return SW_REFERENCE_NOT_FOUND();
        }
        if (P1(apdu) == 0x0) {
            DBG_PRINTF("%s cmd_reset_retry: using RC\n", DBG_TAG);
            file_t *rc;
            if (!(rc = file_search_by_fid(EF_RC, NULL, SPECIFY_EF))) {
                DBG_PRINTF("%s cmd_reset_retry: RC file not found\n", DBG_TAG);
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t pin_len = file_get_data(rc)[0];
            DBG_PRINTF("%s cmd_reset_retry: rc_pin_len=%d\n", DBG_TAG, pin_len);
            if (apdu.nc <= pin_len) {
                return SW_WRONG_LENGTH();
            }
            uint16_t r = check_pin(rc, apdu.data, pin_len);
            DBG_PRINTF("%s cmd_reset_retry: check_pin(rc) returned 0x%04x\n", DBG_TAG, r);
            if (r != 0x9000) {
                return r;
            }
            newpin_len = apdu.nc - pin_len;
            has_rc = true;
            pin_derive_session(apdu.data, pin_len, session_rc);
            has_pw1 = has_pw3 = false;
            isUserAuthenticated = false;
        }
        else if (P1(apdu) == 0x2) {
            DBG_PRINTF("%s cmd_reset_retry: using PW3 (has_pw3=%d)\n", DBG_TAG, has_pw3);
            if (!has_pw3) {
                DBG_PRINTF("%s cmd_reset_retry: PW3 not verified -> SW_CONDITIONS_NOT_SATISFIED\n", DBG_TAG);
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            newpin_len = apdu.nc;
        }
        int r = 0;
        if ((r = load_dek()) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        file_t *tf = file_search_by_fid(EF_DEK_PW1, NULL, SPECIFY_EF);
        if (!tf) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x03;
        pin_derive_session(apdu.data + (apdu.nc - newpin_len), newpin_len, session_pw1);
        encrypt_with_aad(session_pw1, dek, DEK_SIZE, PIN_KDF_DEFAULT_VERSION, def + 1);
        r = file_put_data(tf, def, sizeof(def));

        uint8_t dhash[34];
        dhash[0] = newpin_len;
        dhash[1] = 0x1; // Format
        pin_derive_verifier(apdu.data + (apdu.nc - newpin_len), newpin_len, dhash + 2);
        file_put_data(pw, dhash, sizeof(dhash));
        if (pin_reset_retries(pw, true) != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        flash_commit();
        if ((r = load_dek()) != PICOKEYS_OK) {
            DBG_PRINTF("%s cmd_reset_retry: load_dek failed after reset\n", DBG_TAG);
            return SW_EXEC_ERROR();
        }
        DBG_PRINTF("%s cmd_reset_retry: SUCCESS newpin_len=%d\n", DBG_TAG, newpin_len);
        return SW_OK();
    }
    DBG_PRINTF("%s cmd_reset_retry: invalid P1=0x%02x\n", DBG_TAG, P1(apdu));
    return SW_INCORRECT_P1P2();
}
