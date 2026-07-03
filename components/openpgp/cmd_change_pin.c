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

#include "openpgp.h"
#include "otp.h"

int cmd_change_pin(void) {
    if (P1(apdu) != 0x0) {
        return SW_WRONG_P1P2();
    }
    uint16_t fid = 0x1000 | P2(apdu);
    file_t *pw;
    if (!(pw = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t pin_len = file_get_data(pw)[0];
    uint16_t r = 0;
    r = check_pin(pw, apdu.data, pin_len);
    if (r != 0x9000) {
        return r;
    }
    if ((r = load_dek()) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }

    uint8_t dhash[34];
    dhash[0] = apdu.nc - pin_len;
    dhash[1] = 0x1; // Format
    pin_derive_verifier(apdu.data + pin_len, apdu.nc - pin_len, dhash + 2);
    file_put_data(pw, dhash, sizeof(dhash));

    if (P2(apdu) == 0x81) {
        file_t *tf = file_search_by_fid(EF_DEK_PW1, NULL, SPECIFY_EF);
        if (!tf) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x3;
        pin_derive_session(apdu.data + pin_len, apdu.nc - pin_len, session_pw1);
        encrypt_with_aad(session_pw1, dek, DEK_SIZE, PIN_KDF_DEFAULT_VERSION, def + 1);
        r = file_put_data(tf, def, sizeof(def));
    }
    else if (P2(apdu) == 0x83) {
        file_t *tf = file_search_by_fid(EF_DEK_PW3, NULL, SPECIFY_EF);
        if (!tf) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x3;
        pin_derive_session(apdu.data + pin_len, apdu.nc - pin_len, session_pw3);
        encrypt_with_aad(session_pw3, dek, DEK_SIZE, PIN_KDF_DEFAULT_VERSION, def + 1);
        r = file_put_data(tf, def, sizeof(def));
    }
    flash_commit();
    return SW_OK();
}
