# ESP32-FIDO2

ESP32-FIDO2 transforms an **ESP32-S3** microcontroller into a combined **FIDO2 security key** and **OpenPGP smartcard** — a fully open-source YubiKey alternative.

Built on [pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk):

- **OpenPGP card v3.4** — GnuPG, SSH, S/MIME, smartcard operations
- **FIDO2 / CTAP 2.1** — WebAuthn, U2F, passwordless authentication  
- **OATH / OTP** *(in progress)* — TOTP/HOTP, Yubico OTP

> Standalone ESP-IDF project optimized for **ESP32-S3 N16R8**.
> No Raspberry Pi Pico or cross-platform logic.

---

## Features

### FIDO2 / WebAuthn / U2F

| Feature | Status |
|---------|--------|
| CTAP 2.1 / CTAP 1 / U2F | ✅ |
| WebAuthn (discoverable credentials, resident keys) | ✅ |
| HMAC-Secret, CredProtect, minPinLength | ✅ |
| credBlobs, largeBlobKey | ✅ |
| PIN & UV authentication protocol | ✅ |
| Credential management | ✅ |
| Enterprise attestation | ✅ |
| ECDSA (P-256, P-384, P-521, secp256k1) | ✅ |
| OATH TOTP/HOTP | 🚧 |
| Yubico OTP | 🚧 |

### OpenPGP Smartcard

| Feature | Status |
|---------|--------|
| OpenPGP card v3.4 | ✅ |
| 3 key slots (SIG, DEC, AUT) | ✅ |
| RSA 2048/3072/4096 | ✅ |
| ECDSA (P-256, P-384, P-521, secp256k1) | ✅ |
| Brainpool (256r1, 384r1, 512r1) | ✅ |
| Curve25519 (X25519 ECDH) | ✅ |
| On-device key generation | ✅ |
| Key import/export | ✅ |
| PIN & Admin PIN protection | ✅ |
| PW Status, Reset Code, AES KDF | ✅ |
| GnuPG / SSH / S/MIME compatible | ✅ |

### Default Algorithm

- **brainpool384r1** for Signature, Decryption, and Authentication keys

### Hardware

| Spec | Details |
|------|---------|
| Chip | ESP32-S3 (Xtensa dual-core 240MHz) |
| Flash | 16MB (Quad SPI) |
| PSRAM | 8MB (Octal PSRAM, optional) |
| LED | NeoPixel WS2812 (GPIO48) |
| USB | CCID (smartcard) + HID (CTAP) |

---

## Requirements

- **Hardware:** ESP32-S3 development board (e.g. ESP32-S3-DevKitC-1 N16R8)
- **Software:** [ESP-IDF](https://github.com/espressif/esp-idf) v5.4.4+
- **Cable:** USB-C data cable

---

## Quick Start

```bash
# Clone
git clone https://github.com/Escape2snap/esp32-fido2.git
cd esp32-fido2

# Set up ESP-IDF (install first if needed)
cd ~/esp-idf-v5.4.4
./install.sh esp32s3
. ./export.sh
cd ~/esp32-fido2

# Set target, build, flash
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 erase-flash   # first time only
idf.py -p /dev/ttyACM0 flash

# Monitor
idf.py -p /dev/ttyACM0 monitor
```

> **Tip:** Use `!` prefix in Claude Code to run commands interactively:
> ```
> ! idf.py -p /dev/ttyACM0 flash
> ```

### First Flash

On a new device, erase the entire flash before the first write to ensure clean partitions:

```bash
idf.py -p /dev/ttyACM0 erase-flash
idf.py -p /dev/ttyACM0 flash
```

### Permission Issues (Linux)

```bash
# Temporary fix (current session only)
sudo chmod 666 /dev/ttyACM0

# Permanent fix
sudo usermod -a -G dialout $USER
# Log out and back in, or restart WSL2
```

---

## Testing

### OpenPGP (GnuPG)

```bash
# List connected smartcards
gpg --card-status

# If not detected, start scdaemon manually
gpg-connect-agent --verbose /bye

# Edit card (change PIN, generate keys, etc.)
gpg --edit-card
gpg/card> admin
gpg/card> passwd
gpg/card> generate
```

### FIDO2 / WebAuthn

```bash
# Register with a WebAuthn demo
# Open https://webauthn.io in your browser

# Or use Python fido2 library to enumerate
pip install fido2
python -c "
from fido2.hid import CtapHidDevice
for dev in CtapHidDevice.list_devices():
    print(f'FIDO2 device: {dev}')
"
```

### Yubico Tools

- **[Yubico Authenticator](https://www.yubico.com/products/yubico-authenticator/)** — OATH/TOTP codes *(coming soon)*
- **[Yubico YKMAN](https://www.yubico.com/support/download/ykman/)** — FIDO2 configuration *(coming soon)*

---

## Build Configuration

### Hardware Acceleration

ESP32-S3 provides hardware acceleration for cryptographic operations, enabled by default:

| Accelerator | mbedTLS Config |
|-------------|----------------|
| AES | `CONFIG_MBEDTLS_HARDWARE_AES=y` |
| SHA | `CONFIG_MBEDTLS_HARDWARE_SHA=y` |
| ECC | `CONFIG_MBEDTLS_HARDWARE_ECC=y` |
| GCM | `CONFIG_MBEDTLS_HARDWARE_GCM=y` |

### ESP-IDF Version

Tested with **ESP-IDF v5.4.4**. Also compatible with **v6.0.2** (with same mbedTLS feature set).

To switch versions:

```bash
# Clean and reconfigure for new ESP-IDF
source /path/to/esp-idf-v6.0.2/export.sh
rm -rf build sdkconfig
idf.py set-target esp32s3
idf.py build
```

---

## Project Structure

```
esp32-fido2/
├── CMakeLists.txt              # Project configuration (ESP-IDF)
├── sdkconfig.defaults          # Default Kconfig settings
├── partitions.csv              # Flash layout (factory 2MB + part0 4MB)
├── main/
│   ├── CMakeLists.txt
│   ├── idf_component.yml       # Managed component dependencies
│   └── main.c                  # Entry point (app_main)
├── components/
│   ├── picokeys/               # Core SDK
│   │   ├── CMakeLists.txt
│   │   └── src/
│   │       ├── fs/             # Flash file system
│   │       ├── usb/            # USB CCID + HID transport
│   │       ├── led/            # NeoPixel LED driver
│   │       ├── rng/            # Random number generation
│   │       └── compat/         # ESP32 platform compatibility
│   ├── openpgp/                # OpenPGP smartcard v3.4
│   │   ├── CMakeLists.txt
│   │   └── *.c *.h             # APDU handlers, DO management, crypto
│   ├── fido/                   # FIDO2 / CTAP 2.1
│   │   ├── CMakeLists.txt
│   │   └── *.c *.h             # CBOR handlers, credential mgmt, U2F
│   └── tinycbor/               # CBOR parsing library
└── managed_components/         # ESP-IDF managed components (gitignored)
    ├── espressif__esp_tinyusb/
    ├── espressif__tinyusb/
    └── zorxx__neopixel/
```

---

## Partition Layout

| Partition | Offset | Size | Description |
|-----------|--------|------|-------------|
| nvs | 0x11000 | 24KB | NVS storage |
| phy_init | 0x17000 | 4KB | PHY calibration |
| factory | 0x20000 | 2MB | Application firmware |
| part0 | 0x220000 | 4MB | Wear-levelled data storage |

---

## Development

### Commit Convention

```
feat:     new feature
fix:      bug fix
docs:     documentation
chore:    maintenance, tooling
refactor: code restructuring
perf:     performance optimization
test:     testing
```

### Adding Features

1. **FIDO application:** Add new CBOR handlers in `components/fido/`
2. **OpenPGP:** Add DO handlers in `components/openpgp/`
3. **Hardware:** Configure pins and drivers in `components/picokeys/src/`

For EdDSA support (Ed25519/Ed448), additional mbedTLS integration is required. See `config/esp32/ext/eddsa/` in the original pico-keys-sdk for reference.

---

## Security Notes

- **Secure Boot:** ESP32-S3 supports Secure Boot and Secure Lock via OTP
- **MKEK:** Master Key Encryption Key stored in OTP — protects all private keys at rest
- **Flash Encryption:** All secret key material encrypted before writing to flash
- **⚠️ CVE-27840:** ESP32 has known Secure Boot bypass vulnerability. For high-assurance deployments, consider RP2350-based alternatives.

---

## License

This project incorporates work from multiple open-source projects:

| Project | License |
|---------|---------|
| [pico-openpgp](https://github.com/polhenarejos/pico-openpgp) | GPL v3 |
| [pico-fido](https://github.com/polhenarejos/pico-fido) | GPL v3 |
| [pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk) | AGPL v3 |
| [tinyusb](https://github.com/hathach/tinyusb) | MIT |
| [cJSON](https://github.com/DaveGamble/cJSON) | MIT |

The combined work is distributed under the **GNU General Public License v3.0**.
