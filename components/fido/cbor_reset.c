/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
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

#include "picokeys.h"
#include "file.h"
#include "fido.h"
#include "ctap2_cbor.h"
#include "ctap.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#ifdef ESP_PLATFORM
#include "esp_compat.h"
#endif
#include "fs/phy.h"
#include "files.h"

/* All FIDO2 file FIDs that should be deleted on reset.
   These are the well-known files created by scan_files_fido()
   or user operations (setPIN, etc.). */
static const uint16_t fido_fids[] = {
    EF_PIN,                // 0x1080
    EF_PIN_ADMIN,          // 0x1084
    EF_KEY_DEV,            // 0xCC00
    EF_KEY_DEV_ENC,        // 0xCC01
    EF_EE_DEV,             // 0xCC02
    EF_EE_DEV_EA,          // 0xCC03
    EF_COUNTER,            // 0xCC04
    EF_AUTHTOKEN,          // 0xCC05
    EF_PAUTHTOKEN,         // 0xCC06
    EF_MINPINLEN,          // 0xCC07
    EF_PIN_COMPLEXITY_POLICY, // 0xCC08
    EF_DEV_STATE,          // 0xCC09
    EF_OPTS,               // 0xCC0A
    EF_LARGEBLOB,          // 0xCC0B
    EF_OTP_PIN,            // 0xCC0C
    EF_DEV_SALT,           // 0x1130
};

int cbor_reset(void) {
#ifndef ENABLE_EMULATION
#if defined(ENABLE_POWER_ON_RESET) && ENABLE_POWER_ON_RESET == 1
    if (!(phy_data.opts & PHY_OPT_DISABLE_POWER_RESET) && board_millis() > 10000) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
#endif
    if (wait_button_pressed() > 0) {
        return CTAP2_ERR_USER_ACTION_TIMEOUT;
    }
#endif
    /* Delete well-known FIDO2 files.  file_delete() only touches
       the page cache (flash_program_*) and never calls low_flash_task(),
       so it is safe from core 1 where this CBOR handler runs. */
    for (size_t i = 0; i < sizeof(fido_fids) / sizeof(fido_fids[0]); i++) {
        file_t *ef = file_search(fido_fids[i]);
        if (ef) {
            file_delete(ef);
        }
    }
    /* Delete credentials (EF_CRED + 0 .. 255, FIDs 0xCF00-0xCFFF). */
    for (uint16_t fid = EF_CRED; fid < EF_CRED + 256; fid++) {
        file_t *ef = file_search(fid);
        if (ef) {
            file_delete(ef);
        }
    }
    /* Delete relying-party records (EF_RP + 0 .. 255, FIDs 0xD000-0xD0FF). */
    for (uint16_t fid = EF_RP; fid < EF_RP + 256; fid++) {
        file_t *ef = file_search(fid);
        if (ef) {
            file_delete(ef);
        }
    }
    fido_initialized = false;
    init_fido();
#ifdef DEFAULT_MCUV_NOT_REQUIRED
    set_opts(get_opts() | FIDO2_OPT_MCUV_NOTRQD);
#endif
#ifdef DEFAULT_PIN_POLICY
    file_t *ef_pin_policy = file_search_by_fid(EF_PIN_COMPLEXITY_POLICY, NULL, SPECIFY_EF);
    if (ef_pin_policy) {
        uint8_t default_pin_policy[2] = { 0 };
        file_put_data(ef_pin_policy, default_pin_policy, sizeof(default_pin_policy));
        flash_commit();
    }
#endif
    return 0;
}
