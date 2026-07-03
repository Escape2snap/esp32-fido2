# ESP32-FIDO2

ESP32-FIDO2 transforms an **ESP32-S3** microcontroller into a combined **FIDO2 security key** and **OpenPGP smartcard** — a fully open-source YubiKey alternative.

Built on [pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk), it integrates:

- [pico-openpgp](https://github.com/polhenarejos/pico-openpgp) — OpenPGP card v3.4
- [pico-fido](https://github.com/polhenarejos/pico-fido) — FIDO2 / CTAP 2.1 / U2F

> This is a standalone ESP-IDF project for ESP32-S3 (no Raspberry Pi Pico or cross-platform logic).

---

## Features

### FIDO2 / WebAuthn / U2F
- CTAP 2.1 / CTAP 1 / U2F
- WebAuthn (discoverable credentials, resident keys)
- HMAC-Secret, CredProtect, minPinLength, credBlobs, largeBlobKey
- PIN & UV authentication protocol
- Credential management
- ECDSA (P-256, P-384, P-521, secp256k1)

### OpenPGP Smartcard
- OpenPGP card specification v3.4
- 3 key slots: Signature, Decryption, Authentication
- RSA (2048, 3072, 4096), ECDSA (P-256, P-384, P-521, Brainpool)
- Curve25519 (X25519 ECDH)
- On-device key generation, import/export
- PIN & Admin PIN protection
- GnuPG / SSH / S/MIME compatible

### Default Algorithm
- **brainpool384r1** for all three key slots

### Hardware
- ESP32-S3 target (N16R8: 16MB flash, 8MB PSRAM)
- NeoPixel (WS2812) RGB LED on GPIO48
- USB CCID smartcard interface
- USB HID for CTAP

---

## Requirements

- ESP32-S3 development board (e.g. ESP32-S3-DevKitC-1)
- USB-C cable for power and data
- [ESP-IDF](https://github.com/espressif/esp-idf) v5.4.4+

## Quick Start

```bash
# Clone
git clone https://github.com/Escape2snap/esp32-fido2.git
cd esp32-fido2

# Set up ESP-IDF
source /path/to/esp-idf/export.sh

# Configure target
idf.py set-target esp32s3

# Build
idf.py build

# Flash
idf.py -p /dev/ttyACM0 flash

# Monitor
idf.py -p /dev/ttyACM0 monitor
```

> **Note:** On first flash, erase the entire flash first:
> ```bash
> idf.py -p /dev/ttyACM0 erase-flash
> idf.py -p /dev/ttyACM0 flash
> ```

### Permission Issues (Linux)

```bash
# Temporary fix
sudo chmod 666 /dev/ttyACM0

# Permanent fix (add to dialout group)
sudo usermod -a -G dialout $USER
# Then log out and back in
```

---

## Testing with GnuPG

```bash
# Check smartcard status
gpg --card-status

# Generate keys on device
gpg --edit-card
gpg/card> generate
```

## Testing with FIDO2

```bash
# Register with webauthn.io or similar
# Or use Python's fido2 library:
pip install fido2
python -c "
from fido2.hid import CtapHidDevice
for dev in CtapHidDevice.list_devices():
    print(f'Found: {dev}')
"
```

---

## Project Structure

```
esp32-fido2/
├── CMakeLists.txt                 # Project configuration
├── sdkconfig.defaults             # ESP-IDF defaults
├── partitions.csv                 # Flash partition table
├── main/
│   └── main.c                     # Entry point (app_main)
├── components/
│   ├── picokeys/                  # Core SDK (USB, FS, LED, RNG, crypto...)
│   ├── openpgp/                   # OpenPGP smartcard v3.4
│   ├── fido/                      # FIDO2 / CTAP 2.1 / U2F
│   └── tinycbor/                  # CBOR library (for CTAP)
└── third-party/                   # External dependencies (gitignored)
```

---

## License

This project is based on:
- [pico-openpgp](https://github.com/polhenarejos/pico-openpgp) — **GPL v3**
- [pico-fido](https://github.com/polhenarejos/pico-fido) — **GPL v3**
- [pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk) — **AGPL v3**

The combined work is distributed under the **GNU General Public License v3.0**.

---

## Security Notes

- ESP32-S3 supports Secure Boot and Secure Lock (OTP)
- Master Key Encryption Key (MKEK) stored in OTP — inaccessible outside secure code
- **However:** ESP32 has known security vulnerabilities (CVE-27840). For high-assurance use, consider RP2350-based alternatives.
