# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Flash

```bash
# Activate ESP-IDF (required before any idf.py command)
source /path/to/esp-idf-v5.4.4/export.sh

# Full build flow (first time)
./tools/setup-deps.sh        # pinned tinycbor + mbedTLS fork, Ed448-off patch
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

### Local Checks

There is no GitHub Actions CI. Run before pushing:

```bash
idf.py build
./tools/check-eddsa-ct.sh
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

### mbedtls-fork (required on main)

The firmware needs an mbedtls fork with EdDSA support
(`polhenarejos/mbedtls`, `mbedtls-3.6-eddsa` branch). `third-party/` is
gitignored. `tools/setup-deps.sh` pins the exact commit and applies the
Ed448-off patch; to do it manually:

```bash
git clone --branch mbedtls-3.6-eddsa \
    https://github.com/polhenarejos/mbedtls.git \
    third-party/mbedtls-fork
cd third-party/mbedtls-fork
git submodule update --init --depth 1
```

Referenced by `components/eddsa/CMakeLists.txt` for `eddsa.c` and headers.

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

### FIDO First-Connection RX Error

On first USB enumeration after flashing (or after device power cycle),
the host may report `FIDO err rx` or the FIDO configuration manager may
show an error.  The device recovers on the second connection attempt.

**Root cause (suspected):** TinyUSB and the FIDO CBOR handler need a short
settling time after USB enumeration.  A 100ms startup delay is already
built into `main/main.c`; the issue may be a host-side timing race.

**Workaround:** Unplug and re-plug the device, or simply retry the
FIDO operation once.  Second and subsequent attempts work reliably.

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

### Ed25519 / X25519 (main)

Ed25519 (EdDSA, SIG/AUT) and X25519 (ECDH, DEC) are merged into `main`.
GPG key generation, Ed25519 signing and X25519 `PSO:DEC` are supported on
hardware. Ed25519 uses the dedicated `fe25519`/`sc25519` code and is
compiled with the `-O3` override in `components/eddsa/CMakeLists.txt`;
do not remove that override (it is required for constant-time codegen).
Use `gpg --edit-card` → `key-attr` to select EdDSA/cv25519 before
generating.

**Note:** Ed25519's software scalar multiplication is still the slowest
on-card operation; measure it with `CONFIG_DEBUG_PERF` before changing
the implementation.

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

> ESP32-S3 has **no dedicated ECC accelerator** (`SOC_ECC_SUPPORTED` is
> not defined); all ECC curves, including Brainpool, run in software via
> mbedTLS or `components/eddsa`. The RSA/MPI accelerator speeds RSA and
> some big-integer operations only, not ECC point multiplication.

### Flash Commit Async Issue

`flash_commit()` is asynchronous — data is written in `low_flash_task()`
which runs from `core0_loop` every 10ms. After key generation, GPG may
immediately send PSO:CDS; if the key data hasn't reached flash yet, signing
can load stale data.

**Current behaviour:** `flash_commit_sync()` calls `flash_commit()` and
yields (`vTaskDelay`) until core0 drains the queue. It must **not** call
`low_flash_task()` from core1: that function uses
`multicore_lockout_start_timeout_us()`, which is a `vTaskSuspend(hcore1)`
on ESP and would self-suspend the CBOR/APDU worker. `button_wait()` also
continues draining flash and feeding the Task WDT while waiting for user
presence.

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

Scope goes **after the colon with a space**, not in parentheses:
- ✅ `fix: openpgp correct PW_STATUS byte layout`
- ❌ `fix(openpgp): correct PW_STATUS byte layout`

## Branch Naming

Use slash-separated prefixes, not hyphens:
- ✅ `fix/pin-retry`, `feat/ed25519`, `docs/readme-update`
- ❌ `fix-pin-retry`, `feat-ed25519`

Worktree isolation names can use `/` as segment separators:
`worktree/fix/pin-retry`. Requires WorktreeCreate hooks in settings.json
(not currently configured — falls back to in-place checkout).

## Claude Rules

- **No force commands.** Never use `--force` or `-f` with any command (git push, git reset, git checkout, rm, etc.). Normal operations only.
- **Every commit must be signed.** Always commit with `-s` (Signed-off-by). Unsigned commits are never acceptable.
- **On timeout, stop and ask the user.** Never skip, retry, work around, or proceed silently. Wait for explicit instruction.
- **No `gh` CLI for PRs.** Use plain `git` for everything.
- **English commit messages** matching the convention above.
- **Worktree isolation** — always use `EnterWorktree` before editing files.
