# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Flash

```bash
# Activate ESP-IDF (required before any idf.py command)
source /path/to/esp-idf-v5.4.4/export.sh

# Full build flow (first time)
rm -rf build sdkconfig
git clone https://github.com/intel/tinycbor.git third-party/tinycbor  # see "Dependency Notes → tinycbor"
idf.py set-target esp32s3    # ⚠️ MUST set target before first build (tinyusb only supports esp32s2/s3)
idf.py build
idf.py -p /dev/ttyACM0 erase-flash
idf.py -p /dev/ttyACM0 flash

# Incremental build
idf.py build
idf.py -p /dev/ttyACM0 flash

# Clean rebuild (keeps sdkconfig — target stays esp32s3)
idf.py fullclean && idf.py build
```

> **Important:** `idf.py set-target esp32s3` is required before the **first** build.
> The `espressif/tinyusb` component only supports `esp32s2`, `esp32s3` and newer
> targets — the default `esp32` target will cause version-solving failures.
> Removing `build/` or `.sdkconfig` also requires re-running `set-target`.

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

## Dependency Notes

### esp_tinyusb / tinyusb Version Constraint

`main/idf_component.yml` constrains `espressif/esp_tinyusb` to `>=1.4,<2.0`:

```yaml
dependencies:
  espressif/esp_tinyusb: ">=1.4,<2.0"
```

- **Do NOT add `espressif/tinyusb` as an explicit dependency** — it is pulled in
  transitively by `esp_tinyusb`. Its version string format (e.g. `0.19.0~3`)
  uses `~` which is not valid PEP 440 and causes the component manager solver
  to fail.
- **Do NOT upgrade to `esp_tinyusb >=2.0`** — the v2.x API for `tinyusb_config_t`
  is incompatible with the existing USB code in `components/picokeys/src/usb/`.

### tinycbor

The `third-party/tinycbor/` directory is a clone of
[Intel/tinycbor](https://github.com/intel/tinycbor). It is listed in
`.gitignore` so must be cloned manually:

```bash
git clone https://github.com/intel/tinycbor.git third-party/tinycbor
# Generate CMake output headers (normally produced by CMake configure):
cp third-party/tinycbor/src/tinycbor-export.h.in third-party/tinycbor/src/tinycbor-export.h
```

Then create `third-party/tinycbor/src/tinycbor-version.h` with:
```c
#define TINYCBOR_VERSION_MAJOR 7
#define TINYCBOR_VERSION_MINOR 0
#define TINYCBOR_VERSION_PATCH 0
```

The tinycbor repo's own `CMakeLists.txt` must remain in place — it is
discovered by the ESP-IDF build system as an external dependency.

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
| Ed25519 | ✅ | ❌ | ✅ | Dedicated fe25519 field arithmetic |

> Ed25519 is implemented with self-contained fe25519 field arithmetic
> (components/eddsa/) — not the generic mbedTLS ECP layer.  X25519 uses
> mbedTLS's built-in Curve25519 support (MBEDTLS_ECP_DP_CURVE25519).

### Flash Commit Async Issue

`flash_commit()` is asynchronous — data is written in `low_flash_task()`
which runs every 10ms. After key generation, GPG immediately sends PSO:CDS.
If the key data hasn't been written to flash yet, the signing operation
loads stale data and fails.

**Fix:** `flash_commit_sync()` in `flash.c` busy-waits calling
`low_flash_task()` until `ready_pages == 0`.

> **Note:** `flash_commit_sync` was reverted in commit 8ea5467 because it
> could cause Guru Meditation crashes on ESP32-S3 dual-core.  The current
> code uses `flash_commit()` + `vTaskDelay(1) * 3` which gives the main
> loop 30ms to process pending pages.  For Ed25519 keygen this is normally
> sufficient because the ~8s scalar multiplication gives core 0 plenty of
> time to drain the flash queue while keygen runs on core 1.

### CCID Timeout for Ed25519

Ed25519 scalar multiplication takes ~8 s on the ESP32-S3.  The CCID timeout
was originally 1500 ms (set in `driver_init_ccid()`).  Even though the
firmware sends `CCID_CMD_STATUS_TIMEEXT` requests, GPG's CCID driver may
not handle them correctly.

**Fix (PR #4):** Increased CCID timeout from 1500 ms → 10000 ms in
`components/picokeys/src/usb/ccid/ccid.c:161`.  This covers the full
Ed25519 keygen within a single timeout window, avoiding time extensions.

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

## Debug Mode

A Kconfig-controlled debug framework is **built into the `feat/ed25519`
branch** (commit `d586d1d`).  No cherry-pick needed.

### Enabling Debug Output

```bash
idf.py menuconfig
# → Debug Mode → Enable debug mode [*]
# → Debug Mode → APDU hex dump [*]
# Save & exit
idf.py build
idf.py -p /dev/ttyACM0 flash
idf.py -p /dev/ttyACM0 monitor
```

### Available options (`idf.py menuconfig → Debug Mode`)

| Symbol | Default | Effect |
|--------|---------|--------|
| `CONFIG_DEBUG_ENABLE` | n | Master switch |
| `CONFIG_DEBUG_APDU_HEX` | y | Hex dump APDUs + Ed25519 key material |
| `CONFIG_DEBUG_PERF` | y | Timing via `PERF_START()` / `PERF_END()` |
| `CONFIG_DEBUG_STACK` | n | Stack high-water via `uxTaskGetStackHighWaterMark()` |
| `CONFIG_DEBUG_WDT_FEED` | n | WDT reset in long loops |

### Macros (defined in `components/fido/debug_mode.h`)

- `PERF_START()` / `PERF_END(msg)` — elapsed-time markers
- `APDU_TRACE(tag, data, len)` — hex dump
- `WDT_FEED()` — periodic `esp_task_wdt_reset()`

When debugging is disabled (`CONFIG_DEBUG_ENABLE=n`, the default),
all macros expand to nothing — zero overhead in production builds.

### Stack Monitoring

```c
// main/main.c: core0_loop() — logs every ~10 s
[stack] core0_loop: 1024 bytes free
[stack] core0: 2048 bytes free
```

### WDT Feeding for Ed25519

On the `feat/ed25519` branch where Ed25519 scalar multiplication
takes ~8 s, enable `CONFIG_DEBUG_WDT_FEED` to prevent Task WDT
timeouts.  The `WDT_FEED()` macro is placed inside the HKDF chain
loop in `derive_key()` and can be added to any long-running loop.

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
