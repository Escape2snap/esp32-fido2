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

int cmd_activate_file(void) {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    /* OpenPGP Card v3.4 §7.2.15: ACTIVATE FILE only re-activates a DF that
       was terminated with TERMINATE DF.  It must never erase the shared
       flash pool (FIDO credentials, PIV keys, OpenPGP keys). */
    card_terminated = false;
    return SW_OK();
}