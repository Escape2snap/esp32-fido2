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

#define DBG_TAG "[DBG_fix-openpgp-pin-retry]"
#define DBG_PRINTF(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)

int cmd_verify(void) {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);

    DBG_PRINTF("%s cmd_verify p1=0x%02x p2=0x%02x nc=%" PRIu32 "\n", DBG_TAG, p1, p2, apdu.nc);

    if (p1 == 0xFF) {
        if (apdu.nc != 0) {
            return SW_WRONG_DATA();
        }
        if (p2 == 0x81) {
            has_pw1 = false;
        }
        else if (p2 == 0x82) {
            has_pw2 = false;
        }
        else if (p2 == 0x83) {
            has_pw3 = false;
        }
        return SW_OK();
    }
    else if (p1 != 0x0 || (p2 & 0x60) != 0x0) {
        return SW_WRONG_P1P2();
    }
    uint16_t fid = 0x1000 | p2;
    DBG_PRINTF("%s fid=0x%04x", DBG_TAG, fid);
    if (fid == EF_RC && apdu.nc > 0) {
        fid = EF_PW1;
        DBG_PRINTF(" -> EF_PW1 (RC with data)");
    }
    DBG_PRINTF("\n");

    file_t *pw, *pw_status;
    if (!(pw = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        DBG_PRINTF("%s pw file not found for fid=0x%04x\n", DBG_TAG, fid);
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!(pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
DBG_PRINTF("%s pw_status (EF_PW_PRIV) not found\n", DBG_TAG);
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!file_has_data(pw) || file_get_data(pw)[0] == 0) {
DBG_PRINTF("%s pw file has no data or pin_len=0\n", DBG_TAG);
        return SW_REFERENCE_NOT_FOUND();
    }
    if (apdu.nc > 0) {
DBG_PRINTF("%s calling check_pin(fid=0x%04x, data_len=%" PRIu32 ")\n", DBG_TAG, fid, apdu.nc);
        uint16_t sw = check_pin(pw, apdu.data, apdu.nc);
DBG_PRINTF("%s check_pin returned 0x%04x\n", DBG_TAG, sw);
        return sw;
    }
    uint8_t *pw_status_data = file_get_data(pw_status);
    if (!pw_status_data) {
DBG_PRINTF("%s pw_status data is NULL\n", DBG_TAG);
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t retries = *(pw_status_data + 3 + (fid & 0xf)); /* DO C4: retry counters at byte 3+ */
DBG_PRINTF("%s status query: fid=0x%04x pw_idx=%d retries=%d\n", DBG_TAG, fid, (int)(3 + (fid & 0xf)), retries);
    /* Dump all PW status bytes */
    uint16_t pwsz = file_get_size(pw_status);
    DBG_PRINTF("%s PW_STATUS_ALL: size=%u bytes=[", DBG_TAG, (unsigned)pwsz);
    for (int _i = 0; _i < pwsz && _i < 16; _i++) {
        DBG_PRINTF("%s%u", _i ? " " : "", (unsigned)pw_status_data[_i]);
    }
    DBG_PRINTF("]\n");
    if (retries == 0) {
DBG_PRINTF("%s PIN BLOCKED\n", DBG_TAG);
        return SW_PIN_BLOCKED();
    }
    if ((p2 == 0x81 && has_pw1) || (p2 == 0x82 && has_pw2) || (p2 == 0x83 && has_pw3)) {
DBG_PRINTF("%s already verified (has_pw%d)\n", DBG_TAG,
               p2 == 0x81 ? 1 : (p2 == 0x82 ? 2 : 3));
        return SW_OK();
    }
DBG_PRINTF("%s returning 0x63 0xc0|%d = 0x63%02x\n", DBG_TAG, retries, 0xc0 | retries);
    return set_res_sw(0x63, 0xc0 | retries);
}
