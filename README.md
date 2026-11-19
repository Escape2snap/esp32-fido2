# ESP32-FIDO2

ESP32-FIDO2 turns an **ESP32-S3** into a USB security key that combines:

- **FIDO2 / CTAP 2.1 / U2F** — WebAuthn, resident credentials, PIN/UV
- **OpenPGP card v3.4** — GnuPG, SSH, S/MIME, PSO:CDS and PSO:DEC
- **PIV** — Yubico-compatible PIV applet (management-key protected)

The firmware is a standalone ESP-IDF project built on
[pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk). It does
not target the Raspberry Pi Pico.

## Status

| Area | Status |
|------|--------|
| FIDO2 / WebAuthn / U2F | Working |
| OpenPGP RSA / NIST ECC | Working |
| OpenPGP Ed25519 / X25519 | Working (hardware-tested) |
| PIV | Working (management-key protected) |
| OATH TOTP/HOTP | Not built (applet removed) |
| Yubico OTP | Not implemented |
| Windows CCID + HID | Working; one reconnect may be needed after first enumeration |

Hardware-verified on an ESP32-S3 + Windows host:

- FIDO2 WebAuthn registration and login
- OpenPGP Ed25519 key generation and signing
- cv25519/X25519 PSO:DEC decryption, including the OpenPGP `0x40` Montgomery prefix
- GnuPG `--card-status`, PIN verification and key generation

## Feature Matrix

### FIDO2 / WebAuthn / U2F

| Feature | Status |
|---------|--------|
| CTAP 2.1 / CTAP 1 / U2F | Yes |
| Discoverable credentials / resident keys | Yes |
| HMAC-Secret, CredProtect, minPinLength | Yes |
| credBlob, largeBlobKey | Yes |
| PIN and user-verification protocol | Yes |
| Credential management | Yes |
| Enterprise attestation | Yes |
| ECDSA P-256 / P-384 / P-521 / secp256k1 | Yes |
| OATH TOTP/HOTP | No (applet removed) |
| Yubico OTP | No |

### OpenPGP Smartcard

| Feature | Status |
|---------|--------|
| OpenPGP card v3.4 (ISO 7816-4) | Yes |
| Three key slots (SIG, DEC, AUT) | Yes |
| RSA 2048 / 3072 / 4096 | Yes |
| ECDSA P-256 / P-384 / P-521 / secp256k1 | Yes |
| Brainpool 256r1 / 384r1 / 512r1 | Software fallback |
| Ed25519 / EdDSA | Yes |
| X25519 / cv25519 ECDH | Yes |
| On-device key generation | Yes |
| Key import/export (PUT DATA, IMPORT DATA) | Yes |
| PW1 / PW3 PIN verification | Yes |
| Reset Code and RESET RETRY | Yes |
| PW status byte (DO C4) | Yes |
| KDF (PIN, DEK) | Yes |
| Signature counter | Yes |
| GET CHALLENGE / INTERNAL AUTHENTICATE | Yes |
| PSO:CDS and PSO:DEC | Yes |
| GnuPG / SSH / S/MIME compatible | Yes |

### Default Key Algorithms

| Slot | Default |
|------|---------|
| Signature (SIG) | NIST P-384 ECDSA |
| Decryption (DEC) | NIST P-384 ECDH |
| Authentication (AUT) | NIST P-384 ECDSA |

Ed25519 (SIG/AUT) and X25519 (DEC) can be selected with
`gpg --edit-card` → `key-attr`.

## Hardware

| Item | Detail |
|------|--------|
| MCU | ESP32-S3, dual-core Xtensa LX7, 240 MHz |
| Flash | 16 MB QIO |
| PSRAM | 8 MB+ Octal (currently unused) |
| LED | NeoPixel WS2812 on GPIO48 |
| User-presence button | BOOT button, GPIO0 |
| USB | CCID smartcard + HID FIDO2 composite device |
| Accelerators | AES, SHA, RSA/MPI (4096-bit); no dedicated ECC accelerator — ECC and EdDSA run in software |

## Quick Start

### Prerequisites

- ESP-IDF **v5.4.x** (tested with v5.4.4) and the ESP32-S3 toolchain
- Python 3 and `git`
- A board with 16 MB flash and a NeoPixel on GPIO48

### Clone and dependencies

`third-party/` is gitignored. Use the pinned setup script (recommended):

    ./tools/setup-deps.sh

It checks out the exact commits and applies the Ed448-off patch required by
the mbedTLS fork. The manual steps below are kept for reference.

```bash
git clone https://github.com/Escape2snap/esp32-fido2.git
cd esp32-fido2

# tinycbor
git clone https://github.com/intel/tinycbor.git third-party/tinycbor
cp third-party/tinycbor/src/tinycbor-export.h.in third-party/tinycbor/src/tinycbor-export.h
# create third-party/tinycbor/src/tinycbor-version.h with
# TINYCBOR_VERSION_MAJOR 7, MINOR 0, PATCH 0

# mbedTLS fork with EdDSA/X25519 support
git clone --branch mbedtls-3.6-eddsa \
  https://github.com/polhenarejos/mbedtls.git third-party/mbedtls-fork
cd third-party/mbedtls-fork
git submodule update --init --depth 1
cd ../..
```

The tinycbor version header is required:

```c
#define TINYCBOR_VERSION_MAJOR 7
#define TINYCBOR_VERSION_MINOR 0
#define TINYCBOR_VERSION_PATCH 0
```

### Build and flash

```bash
cd ~/esp-idf-v5.4.4
./install.sh esp32s3
. ./export.sh
cd ~/esp32-fido2

idf.py set-target esp32s3     # required; TinyUSB does not support the default esp32 target
idf.py build

# First flash
idf.py -p /dev/ttyACM0 erase-flash
idf.py -p /dev/ttyACM0 flash

# Subsequent builds
idf.py build
idf.py -p /dev/ttyACM0 flash
```

On Windows use the appropriate COM port, for example
`idf.py -p COM5 flash`.

### Linux permissions

```bash
sudo chmod 666 /dev/ttyACM0
# or permanently:
sudo usermod -a -G dialout "$USER"
```

## Device Identity

`main/device_config.h` is gitignored. The build auto-copies
`main/device_config.old.h` on the first build if the file is missing.
Edit it to change USB strings, VID/PID or interface names.

```bash
cp main/device_config.old.h main/device_config.h
# edit USB identity
idf.py build
```

## Usage

### OpenPGP with GnuPG

Default PINs are defined in `components/openpgp/openpgp.c`:

| Secret | Default | Purpose |
|--------|---------|---------|
| PW1 (user PIN) | `123456` | Signing, decryption, authentication |
| RC (reset code) | `12345678` | Unblock PW1 |
| PW3 (admin PIN) | `12345678` | Admin operations and key management |

Change all three after first setup:

```bash
gpg --card-status
gpg --edit-card
gpg/card> admin
gpg/card> passwd
gpg/card> generate
```

Notes:

- The default algorithm is NIST P-384.
- On Windows, GPG may report `Zero prefix in S-expression` on the first
  generation. Run `key-attr` once, then `generate`.
- For Ed25519/X25519, use `key-attr` and select EdDSA/Ed25519 for SIG and
  AUT and cv25519 for DEC before generating.
- The CCID path keeps the Windows-compatible `dwFeatures = 0x40840` value.

### FIDO2

```bash
python3 -c "from fido2.hid import CtapHidDevice; d = next(CtapHidDevice.list_devices()); print(d.get_info())"
```

Browser test: <https://webauthn.io>

Press the **BOOT button** when the browser asks for user presence.

### OATH / OTP

Not supported in this firmware. The OATH/OTP applet sources were removed;
only FIDO2/U2F, OpenPGP and PIV are built.

## Platform Notes

### Windows

- The device is a composite CCID + HID device. Windows may require a
  reconnect after the first enumeration while `usbccgp.sys` binds both
  interfaces.
- Firmware includes a 100 ms USB settle delay.
- Do not remove the CCID feature bit `0x40` from `dwFeatures = 0x40840`;
  doing so makes PC/SC negotiate parameters and fail with
  `SCARD_E_PROTO_MISMATCH`.
- GnuPG and the Windows Smart Card service may need a restart after a
  driver update.

### WSL

The device must be passed through to WSL with `usbipd` before Linux
GnuPG/PCSC can see it. Windows and WSL cannot own the USB device at the
same time.

## Architecture

### USB Interfaces

| Interface | Function | Endpoints | Host driver |
|-----------|----------|-----------|-------------|
| 0 | CCID smartcard | Bulk OUT/IN + interrupt IN | usbccid / PCSC |
| 1 | HID FIDO2/CTAP | Interrupt OUT/IN | hidusb |

CCID is interface 0 for Windows compatibility.

### Tasks

- TinyUSB task on CPU1
- `core0_loop` on CPU0: USB housekeeping, flash task, button task, LED task
- Applet APDU/CBOR workers on CPU1

### Components

| Path | Purpose |
|------|---------|
| `components/picokeys` | USB CCID/HID, flash filesystem, LED, RNG, APDU routing |
| `components/openpgp` | OpenPGP card v3.4, PSO, PIN/DEK, key management |
| `components/fido` | CTAP2.1, WebAuthn, PIN/UV |
| `components/eddsa` | Ed25519/X25519 field and scalar code |
| `components/tinycbor` | tinycbor build wrapper |
| `third-party/mbedtls-fork` | EdDSA-capable mbedTLS fork |
| `main` | ESP-IDF application, USB identity and task setup |

## Build Configuration

### Hardware Acceleration

Configured in `sdkconfig.defaults`:

| Accelerator | Setting |
|-------------|---------|
| AES | `CONFIG_MBEDTLS_HARDWARE_AES=y` |
| SHA | `CONFIG_MBEDTLS_HARDWARE_SHA=y` |
| MPI | `CONFIG_MBEDTLS_HARDWARE_MPI=y` (4096-bit) |

ESP32-S3 has **no dedicated ECC accelerator**: `SOC_ECC_SUPPORTED` is
not defined for this target, so `CONFIG_MBEDTLS_HARDWARE_ECC` is
unavailable and ECC point multiplication (P-256/P-384/P-521, Brainpool,
secp256k1) runs in software. Ed25519/X25519 use the software field and
scalar code in `components/eddsa`. The RSA/MPI accelerator only speeds
big-integer operations used by RSA and some mbedTLS bignum paths; it is
not a dedicated ECC engine.

`sdkconfig.defaults` also selects `-O2` (`CONFIG_COMPILER_OPTIMIZATION_PERF`),
an 8192-byte main task stack, and disables the USB-Serial-JTAG module/console
(UART remains available for development).

### USB Interface Mode

Edit `main/main.c`:

```c
/* Both CCID and HID: FIDO2 + OpenPGP (default) */
phy_data.enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_HID;

/* CCID + WCID only: OpenPGP, no FIDO2 */
phy_data.enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_WCID;
```

### Security / Debug Defaults

- Core dump disabled
- USB-Serial-JTAG disabled
- JTAG eFuse not burned
- `CONFIG_DEBUG_ENABLE` and `CONFIG_DEBUG_APDU_HEX` must stay disabled for
  production: debug builds can print key material.

## Partition Layout

| Partition | Offset | Size |
|-----------|--------|------|
| nvs | 0x11000 | 24 KB |
| phy_init | 0x17000 | 4 KB |
| factory | 0x20000 | 2 MB |
| part0 | 0x220000 | 4 MB |

The factory app partition is 2 MB; release builds fit comfortably below
the limit.

## Security Model

### Key Hierarchy

```
random 32-byte device salt (first boot)
  + chip serial or optional OTP key
    -> HKDF-SHA256("DEVICE/ROOT")
      -> device master key (keydev), encrypted in flash
        -> AES-GCM/ChaCha20-Poly1305
          -> encrypted private keys and credentials in flash
```

OpenPGP private keys are encrypted with the DEK, and FIDO credential
secrets are encrypted with the device key. PIV private keys are wrapped in
a `PIVKEY1` (DEK) or `PIVKEY2` (device-bound `kbase`) envelope; the
latter keeps raw keys off flash when only the PIV management key is
available, but it is **not PIN-protected** — a full flash dump can derive
`kbase`. The PIV management key itself is still stored unencrypted.
Enable Secure Boot and Flash Encryption before production, or add a
PIV-PIN-wrapped KEK. The optional OTP key adds entropy; without it,
physical flash readout plus the chip serial number is sufficient to
attempt an offline brute-force of the device root.

### PIN / DEK Flow

```
user PIN -> KDF -> DEK -> decrypt private key
```

The DEK is derived in RAM and is never exported.

### Security-Related Behavior Changes (PR #60)

- `GET BULK DATA` (0xCE) is disabled.
- PIV `SET RETRIES`/`RESET`/`PUT DATA` require the management key;
  OpenPGP `IMPORT DATA` requires PW3.
- `PIV RESET` only removes PIV objects (it no longer erases OpenPGP or
  FIDO2 data).
- Rescue PHY writes and `KEYDEV_SIGN` are compile-gated; enable them with
  `-DPICOKEYS_ENABLE_RESCUE_DEBUG=1` for provisioning builds.
- Concurrent CBOR requests are rejected with `CHANNEL_BUSY` while the
  previous one is in flight.

### Secure Boot (Optional, Irreversible)

ESP32-S3 uses **Secure Boot v2**. Do not use generic
`espefuse.py burn_key secure_boot` instructions from ESP32 Secure Boot v1.

High-level flow:

1. Generate and back up an offline signing key.
2. Enable Secure Boot v2 in `sdkconfig`.
3. Sign bootloader and application.
4. Burn the public key digest.
5. Enable Secure Boot and verify with `espefuse.py summary`.

See the [ESP-IDF Secure Boot
documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot.html).
This is irreversible; a lost signing key makes firmware updates
impossible. ESP32 silicon has had published Secure Boot bypasses; check
Espressif security advisories for your revision.

## Known Limitations

- **Windows CCID + HID**: may require one reconnect after first enumeration.
- **Brainpool**: software fallback; slower and may hit PC/SC timeouts.
- **P-384 key generation**: software path can take 10+ seconds.
- **Ed25519/X25519**: Ed25519 signing is constant-time under the pinned
  `-O3` flags in `components/eddsa/CMakeLists.txt`; do not remove that
  override. Target timing and WDT margin still need measurement.
- **OATH / Yubico OTP**: not implemented; the OATH/OTP applet sources were removed.
- **ECC acceleration**: none on ESP32-S3; all NIST/Brainpool/Edwards curves run in software (see Build Configuration).
- **Debug builds**: may print secrets if debug options are enabled.

## Development

### Local Checks

There is no GitHub Actions CI. Run before pushing:

```bash
./tools/preflight.sh
```

### Commit Convention

```
feat:     new feature
fix:      bug fix
docs:     documentation
chore:    maintenance/tooling
refactor: restructuring
perf:     performance
test:     tests
```

Scope goes after the colon and a space:

- `fix: openpgp correct PW_STATUS layout`
- not `fix(openpgp): ...`

Commits should be signed (`git commit -S -s`) and use English messages.

## Fix History

[`HISTORY.md`](HISTORY.md) contains detailed root-cause analyses for PRs
#24–#45 and #60. Recent work:

- #47: USB transport and APDU routing
- #48: FIDO2/OATH bounds and PIN handling
- #49: OpenPGP v3.4 lifecycle, DEK, PIN retry and key handling
- #50: RNG, flash mapping, OTP presence and build hardening
- #51: restore CCID `dwFeatures = 0x40840` for Windows PC/SC
- #52: README sync for current support
- #53: CCID status reset on USB reset
- #54: WCID busy-slots descriptor byte
- #55: CCID T=1 protocol reporting
- #56: Ed25519 field arithmetic and curve constants
- #57: constant-time Ed25519 signing
- #58: X25519 PSO:DEC `0x40` prefix
- #59: merge Ed25519/X25519 into main
- #60: security hardening for APDU/PIV/FIDO boundaries and Phase 0 build cleanup

Do not remove the CCID `0x40` compatibility bit.

## License

AGPL v3. Based on:

- [pico-openpgp](https://github.com/polhenarejos/pico-openpgp) (GPL v3)
- [pico-fido](https://github.com/polhenarejos/pico-fido) (GPL v3)
- [pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk) (AGPL v3)

The Ed25519 scalar arithmetic in `components/eddsa/sc25519.c` is derived
from the public-domain SUPERCOP ed25519 ref10 implementation.
