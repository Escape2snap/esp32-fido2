# ESP32-FIDO2

ESP32-FIDO2 transforms an **ESP32-S3** microcontroller into a combined **FIDO2 security key** and **OpenPGP smartcard** — a fully open-source YubiKey alternative.

Built on [pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk):

- **FIDO2 / CTAP 2.1** — WebAuthn, U2F, passwordless authentication ✅
- **OpenPGP card v3.4** — GnuPG, SSH, S/MIME, smartcard operations ✅
- **OATH / OTP** *(in progress)* — TOTP/HOTP, Yubico OTP 🚧

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
| GnuPG / SSH / S/MIME compatible | ✅ |

### Default Algorithm

| Slot | Algorithm |
|------|----------|
| Signature (SIG) | brainpool384r1 (ECDSA) |
| Decryption (DEC) | brainpool384r1 (ECDH) |
| Authentication (AUT) | brainpool384r1 (ECDSA) |

### Hardware

| Spec | Details |
|------|---------|
| Chip | ESP32-S3 (Xtensa dual-core 240MHz) |
| Flash | 16MB (Quad SPI QIO) |
| PSRAM | 8MB (Octal PSRAM, optional) |
| LED | NeoPixel WS2812 (GPIO48, dimmed ~20%) |
| USB | CCID (smartcard) + HID (FIDO2 CTAP) |

---

## Quick Start

```bash
# Clone
git clone https://github.com/Escape2snap/esp32-fido2.git
cd esp32-fido2

# Set up ESP-IDF
cd ~/esp-idf-v5.4.4
./install.sh esp32s3
. ./export.sh
cd ~/esp32-fido2

# First time: clean flash
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 erase-flash
idf.py -p /dev/ttyACM0 flash

# Subsequent builds
idf.py build
idf.py -p /dev/ttyACM0 flash

# Monitor
idf.py -p /dev/ttyACM0 monitor
```

### Permission Issues (Linux)

```bash
# Temporary
sudo chmod 666 /dev/ttyACM0
# Permanent
sudo usermod -a -G dialout $USER
```

---

## Testing

### OpenPGP (GnuPG)

```bash
# Check card
gpg --card-status

# Initialize (set PINs, generate keys)
gpg --edit-card
gpg/card> admin
gpg/card> passwd
gpg/card> generate
```

### FIDO2 / WebAuthn

```
Open https://webauthn.io in your browser and register.
```

### Python

```bash
pip install fido2
python -c "
from fido2.hid import CtapHidDevice
for dev in CtapHidDevice.list_devices():
    print(f'FIDO2 device: {dev}')
"
```

---

## Platform Notes

| Feature | Linux | Windows |
|---------|-------|---------|
| FIDO2 | ✅ | ✅ |
| OpenPGP (CCID) | ✅ | ✅ (may need retry on first connection) |

On **Windows**, the composite CCID+HID device may need 1–3 connection attempts
before the smartcard driver fully enumerates. This is a known timing issue with
Windows `usbccgp.sys` handling of multi-interface HID+CCID devices.
A 100ms startup delay is built into the firmware to minimize this.

---

## Build Configuration

### Hardware Acceleration

| Accelerator | Config |
|-------------|--------|
| AES | `CONFIG_MBEDTLS_HARDWARE_AES=y` |
| SHA | `CONFIG_MBEDTLS_HARDWARE_SHA=y` |
| ECC | `CONFIG_MBEDTLS_HARDWARE_ECC=y` |
| GCM | `CONFIG_MBEDTLS_HARDWARE_GCM=y` |

### Interface Mode

Edit `main/main.c` to switch USB interfaces:

```c
// Both CCID + HID (default — FIDO2 + OpenPGP)
phy_data.enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_HID;

// CCID + WCID only (more stable GPG on Windows, no FIDO2)
phy_data.enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_WCID;
```

---

## Project Structure

```
esp32-fido2/
├── CMakeLists.txt
├── sdkconfig.defaults
├── partitions.csv
├── main/
│   ├── CMakeLists.txt
│   ├── idf_component.yml
│   └── main.c
├── components/
│   ├── picokeys/        # Core SDK (USB, FS, LED, RNG...)
│   ├── openpgp/         # OpenPGP smartcard v3.4
│   ├── fido/            # FIDO2 / CTAP 2.1 / U2F
│   └── tinycbor/        # CBOR library
└── managed_components/  # TinyUSB, NeoPixel
```

---

## Partition Layout

| Partition | Offset | Size |
|-----------|--------|------|
| nvs | 0x11000 | 24KB |
| phy_init | 0x17000 | 4KB |
| factory | 0x20000 | 2MB |
| part0 | 0x220000 | 4MB |

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

---

## License

AGPL v3. Based on [pico-openpgp](https://github.com/polhenarejos/pico-openpgp) (GPL v3),
[pico-fido](https://github.com/polhenarejos/pico-fido) (GPL v3), and
[pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk) (AGPL v3).
