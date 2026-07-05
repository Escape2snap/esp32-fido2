# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Flash

```bash
# Activate ESP-IDF (required before any idf.py command)
source /path/to/esp-idf-v5.4.4/export.sh

# Full build flow (first time)
rm -rf build sdkconfig
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 erase-flash
idf.py -p /dev/ttyACM0 flash

# Incremental build
idf.py build
idf.py -p /dev/ttyACM0 flash

# Monitor
idf.py -p /dev/ttyACM0 monitor    # exit: Ctrl+]

# Clean rebuild
idf.py fullclean && idf.py build
```

### Permissions

```bash
sudo chmod 666 /dev/ttyACM0              # temporary
sudo usermod -a -G dialout $USER         # permanent (log out first)
```

### Device Identity

```bash
cp main/device_config.old.h main/device_config.h
# edit USB strings, VID, PID
```

`device_config.h` is gitignored. CMake auto-copies template if missing.

---

## Architecture

### Component Flow

```
main/main.c
  └── app_main()
       ├── init chain (flash, RTC, phy, LED)
       ├── usb_init() → hid_init/ccid_init
       ├── tinyusb_driver_install()
       └── core0_loop (task loop)
            ├── usb_task()  → hid_task() + ccid_task()
            ├── flash_task / button_task
            └── led_blinking_task
```

### USB Interface Layout

| Interface | Function | Endpoints | Windows Driver |
|-----------|----------|-----------|----------------|
| 0 | CCID (Smart Card 0x0B) | Bulk EP1 IN/OUT, Int EP2 IN | usbccid.sys |
| 1 | HID (FIDO CTAP 0x03) | Int EP4 IN/OUT | hidusb.sys |

**CCID must be Interface 0** for Windows compatibility. Interface ordering is:
1. CCID registered first in `usb_init()` (`components/picokeys/src/usb/usb.c`)
2. HID registered second

### Key Bug Fix (Interface Routing)

`ITF_HID_CTAP` (HID sub-index) and `ITF_CCID` are both 0, causing `apdu.c` to call the HID finished handler for CCID APDUs. This causes a NULL-pointer crash when HID is disabled at runtime.

**Fix (apdu.c):** The condition `if (itf == ITF_HID_CTAP)` matches both HID and CCID. When adding CCID+HID coexistence, ensure APDU routing checks distinguish interfaces. The NULL guard in `driver_exec_finished_cont_hid()` (`components/picokeys/src/usb/hid/hid.c`) prevents the crash.

### Task Safety

- **DO NOT call `tud_task()` on ESP_PLATFORM** — TinyUSB creates its own FreeRTOS task. Double-calling causes USB stack corruption.
- `usb_task()` in `components/picokeys/src/usb/usb.c` guards `hid_task()` with `ITF_HID_TOTAL > 0` check.

---

## Known Issues

### Windows CCID+HID Coexistence

On Windows, composite devices with both CCID (Smart Card) and HID interfaces may need multiple connection attempts before the smartcard driver fully enumerates. This is a Windows `usbccgp.sys` limitation, not a firmware bug.

**Workaround:** A 100ms startup delay is built into `main/main.c` before `usb_init()`. For more reliable GPG on Windows, switch to CCID+WCID mode (no HID):

```c
// main/main.c
phy_data.enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_WCID;
```

On Linux both interfaces work reliably.

### FIDO2 User Presence

The **BOOT button** (GPIO0) on the ESP32-S3 board serves as the FIDO2 user presence button. Press it when the browser/system prompts for confirmation.

---

## Algorithm Configuration

### Defaults (NIST P-384)

| Slot | Algorithm | Defined in |
|------|-----------|------------|
| SIG | NIST P-384 (ECDSA) | `cmd_keypair_gen.c`, `do.c` |
| DEC | NIST P-384 (ECDH) | `cmd_keypair_gen.c`, `do.c` |
| AUT | NIST P-384 (ECDSA) | `cmd_keypair_gen.c`, `do.c` |

Each slot has its own algorithm attribute file (EF_ALGO_PRIV1/2/3).
On first key generation, the algorithm attribute is written automatically.
If GPG reports `Zero prefix in S-expression`, run `key-attr` first.

### feat/ed25519 Branch (Experimental)

The `feat/ed25519` branch adds Ed25519 (EdDSA) and X25519 (ECDH) support.
It is WIP — Ed25519 signing works but GPG key generation exceeds PC/SC timeouts.

**Key commits:**
- `cb475c2` — Fixed Edwards point addition formula (HWCD extended coordinates)
- `96e748c` — MPI intermediate reduction + WDT feeding in scalar multiplication loop
- `4f2a30a` — `esp_task_wdt_add()` subscription before long loops
- `b68bed8` — Flash-backed algorithm attribute files (FID 0x10C1-0x10C3) for PUT DATA
- `1bfef34` — DEC slot default → Curve25519 ECDH for GPG compatibility
- `ee2bdcf` — Import path, PSO guard, `ed25519_compute_public()`, MBEDTLS_MPI_CHK fixes

**Remaining issues:**
- Ed25519 scalar multiplication takes ~8s (generic mbedtls_mpi) → PC/SC timeouts
- X25519 ECDH keygen (`mbedtls_ecp_keypair_calc_public`) needs verification
- Full key generation via GPG `generate` not yet functional

**Known fix needed:** Replace double-and-add with dedicated 25519 field
arithmetic (montgomery reduction, constant-time ladder) for 100x speedup.

### Important: Algorithm Attribute Storage

After `cmd_keypair_gen.c` generates a key, the algorithm attribute must
be written to `fid - 0x0010` (EF_ALGO_PRIV1/2/3). Without this, PSO:CDS
falls back to `algorithm_attr_rsa2k` and tries RSA operations on an ECDSA
key. See the `if (!file_has_data(algo_ef))` block in `cmd_keypair_gen.c`.

### Available Curves

| Curve | SIG | DEC | AUT | Requires |
|-------|-----|-----|-----|----------|
| RSA 2048/3072/4096 | ✅ | ✅ | ✅ | — |
| secp256r1 (P-256) | ✅ | ✅ | ✅ | — |
| secp384r1 (P-384) | ✅ | ✅ | ✅ | — |
| secp521r1 (P-521) | ✅ | ✅ | ✅ | — |
| secp256k1 | ✅ | ✅ | ✅ | — |
| brainpool* | ✅ | ✅ | ✅ | ⚠️ No HW ECC support on ESP32-S3 |
| Curve25519 (X25519) | ❌ | ✅ | ❌ | — |
| Ed25519 | ✅ | ❌ | ✅ | `ENABLE_EDDSA` + mbedTLS fork |

> Brainpool curves are defined in ESP-IDF but the HW ECC accelerator
> only supports NIST curves. Key generation and signing will fail.

### Flash Commit Async Issue

`flash_commit()` is asynchronous — data is written in `low_flash_task()`
which runs every 10ms. After key generation, GPG immediately sends PSO:CDS.
If the key data hasn't been written to flash yet, the signing operation
loads stale data and fails.

**Fix:** `flash_commit_sync()` in `flash.c` busy-waits calling
`low_flash_task()` until `ready_pages == 0`.

---

## Flash Filesystem

- `file_entries[]` in `components/openpgp/files.c` — single array for both OpenPGP and FIDO entries
- FIDO EFs discovered at runtime via `scan_files_fido()` → `file_search_by_fid()`
- Partition: `part0` at 0x220000, 4MB, wear-levelled
- FIDO EF globals: `ef_keydev`, `ef_pin`, `ef_authtoken`, etc. in `components/fido/fido_ef.c`

## LED

- NeoPixel WS2812 on GPIO48, dimmed to ~20% (pixel[] RGB = 50)
- Driver: `components/picokeys/src/led/led_neopixel.c`
- Mode format in `led.h`: (brightness << shift | color << shift | on_ms << shift | off_ms << shift)

## Commit Convention

```
feat:     new feature
fix:      bug fix
docs:     documentation
chore:    maintenance, tooling
refactor: code restructuring
perf:     performance optimization
test:     testing
```
