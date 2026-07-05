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

int cmd_put_data(void) {
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    file_t *ef;
    if (fid == EF_RESET_CODE) {
        fid = EF_RC;
    }
    else if (fid == EF_ALGO_SIG || fid == EF_ALGO_DEC || fid == EF_ALGO_AUT) {
        fid |= 0x1000;
    }
    if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!file_authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if ((fid == EF_PRIV_DO_1 || fid == EF_PRIV_DO_3) && (!has_pw2 && !has_pw3)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (!(fid == EF_PRIV_DO_1 || fid == EF_PRIV_DO_3) && !has_pw3) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (fid == EF_PW_STATUS) {
        fid = EF_PW_PRIV;
        apdu.nc = 4; //we silently ommit the reset parameters
    }
    if (currentEF && currentEF->fid == fid) { // previously selected same EF
        ef = currentEF;
    }
    if (ef->type & FILE_DATA_FLASH) {
        int r = 0;
        if (apdu.nc > 0) {
            if (fid == EF_RC) {
                has_rc = false;
                if ((r = load_dek()) != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                uint8_t dhash[34];
                dhash[0] = apdu.nc;
                dhash[1] = 0x1; // Format
                pin_derive_verifier(apdu.data, apdu.nc, dhash + 2);
                file_put_data(ef, dhash, sizeof(dhash));

                file_t *tf = file_search_by_fid(EF_DEK, NULL, SPECIFY_EF);
                if (!tf) {
                    return SW_REFERENCE_NOT_FOUND();
                }

                uint8_t def[DEK_FILE_SIZE];
                def[0] = 0x3;
                pin_derive_session(apdu.data, apdu.nc, session_rc);
                encrypt_with_aad(session_rc, dek, DEK_SIZE, PIN_KDF_DEFAULT_VERSION, def + 1);
                r = file_put_data(tf, def, sizeof(def));
            }
            else {
                r = file_put_data(ef, apdu.data, apdu.nc);
            }
            if (r != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
            flash_commit();
        }
        else {
            file_delete(ef);
        }
    }
    return SW_OK();
}
