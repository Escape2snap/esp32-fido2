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
| Signature (SIG) | NIST P-384 (ECDSA) |
| Decryption (DEC) | NIST P-384 (ECDH) |
| Authentication (AUT) | NIST P-384 (ECDSA) |

### Experimental: Ed25519 / X25519 Support (feat/ed25519 Branch)

The `feat/ed25519` branch adds Ed25519 (EdDSA) and X25519 (Curve25519 ECDH) support:

| Feature | Status | Note |
|---------|--------|------|
| Ed25519 key generation | ✅ | Self-contained implementation (no mbedtls fork dependency) |
| Ed25519 signing | ✅ | Both OpenPGP and FIDO2 paths |
| X25519 ECDH | 🚧 | Key generation works, PSO:DEC ECDH path incomplete |
| Key import/export | ✅ | Ed25519 import path added |
| WDT handling | ✅ | Task + IDLE watchdog fed during long operations |
| Performance | ⚠️ | ~8s for Ed25519 scalar multiplication on ESP32-S3 (mbedtls_mpi) |

**Status:** On hold — the 8-second keygen time causes PC/SC interface timeouts in GPG.
A dedicated 25519 field arithmetic implementation would bring this to milliseconds.

```bash
git checkout feat/ed25519
idf.py build
```

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

> **First key generation:** The default algorithm is NIST P-384.
> On Windows, GPG may report `Zero prefix in S-expression` on the first
> `generate`. Run `key-attr` once to initialize, then generate normally:
> ```
> gpg/card> key-attr
>   select ECC → NIST P-384 for all three slots
> gpg/card> generate
> ```
> This only needs to be done once per fresh card.

### FIDO2 / WebAuthn

```
Open https://webauthn.io in your browser and register.
```

**User Presence:** Press the **BOOT button** (GPIO0) on the board when
prompted. This physical button press is required by FIDO2 for registration
and authentication.

### Device Configuration

```bash
cp main/device_config.old.h main/device_config.h
# edit USB names, VID, PID, interface strings
```

`main/device_config.h` is gitignored — your custom identity stays local.
The template at `main/device_config.old.h` has the default values.

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

### Known Limitations

- **Brainpool curves:** ESP32-S3 HW ECC accelerator does not support
  brainpool curves. Key generation and signing will fail. Use NIST P-256/P-384
  or Curve 25519 instead.
- **GPG key-attr:** On first key generation with default P-384, GPG on Windows
  may report `Zero prefix in S-expression`. Run `key-attr` once before
  `generate` to initialize the algorithm attributes.
- **CCID+HID coexistence:** Windows `usbccgp.sys` handles CCID and HID
  interfaces better on reboot. If the smartcard reader doesn't appear,
  reconnect the device.
- **P-384 key generation is slow:** On ESP32-S3, P-384 ECDSA/ECDH key
  generation using software mbedtls_mpi can take 10+ seconds. The Task
  WDT will trigger but the operation completes. Stick to P-256 or Ed25519
  (feat/ed25519) for faster key generation.
- **Ed25519/Curve25519 (feat/ed25519):** Work in progress. Ed25519 signing
  works but the 8-second scalar multiplication exceeds PC/SC timeouts
  in GPG. X25519 ECDH key generation needs completion. See the
  `feat/ed25519` branch for details.

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
│   ├── main.c
│   ├── device_config.h        ← gitignored, your custom identity
│   └── device_config.old.h    ← template, tracked in git
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

## Security Model

### Key Hierarchy

```
OTP/eFuse (chip-internal, unreadable)
  └── Master Key Encryption Key (MKEK)
        └── AES/GCM/ChaCha20-Poly1305
              └── Encrypted private keys → Flash storage
```

All private key material is **encrypted at rest** using a master key stored in
the ESP32-S3's **OTP/eFuse** memory. eFuse is one-time programmable and
physically inaccessible from outside the chip — even with physical flash
readout, private keys cannot be recovered.

### Key Derivation

PIN-protected access uses a KEK (Key Encryption Key) flow:

```
User PIN ──→ KDF ──→ DEK (Data Encryption Key) ──→ Decrypt private key
```

Each decryption operation requires the correct PIN. The DEK is derived using
the card's KDF algorithm and never exposed externally.

### Secure Boot (Optional, One-Time)

> **⚠️ Not enabled by default. Irreversible once activated.**

ESP32-S3 supports Secure Boot via eFuse. When enabled, the chip verifies the
firmware signature against a whitelisted public key before every boot.
If the firmware is tampered with, the chip refuses to boot.

**Before enabling** — understand the consequences:

- **Irreversible**: eFuse is a physical one-time programmable fuse. Once blown,
  Secure Boot cannot be disabled.
- **Key management**: The signing private key must be kept safe. If lost,
  firmware updates become impossible and the device is **permanently bricked**.
- **Recovery impossible**: There is no backdoor, no recovery mode, and no
  debug override.

**Enable only if you accept the risk:**

```bash
# 1. Generate signing key (BACK THIS UP SAFELY)
espsecure.py generate_signing_key secure_boot_signing_key.pem

# 2. Sign the firmware binary
espsecure.py sign_data --keyfile secure_boot_signing_key.pem \
  --version 2 build/esp32_fido2.bin

# 3. Flash normally
idf.py -p /dev/ttyACM0 flash

# 4. Burn the signing key to eFuse and enable Secure Boot
#    ⚠️ THIS IS PERMANENT — READ ESP-IDF DOCS FIRST
espefuse.py -p /dev/ttyACM0 burn_key secure_boot \
  secure_boot_signing_key.pem

# 5. Verify
espefuse.py -p /dev/ttyACM0 summary
```

See the [ESP-IDF Secure Boot
documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot.html)
for detailed instructions.

### CVE-27840

ESP32 (all variants including ESP32-S3) has a known Secure Boot bypass
vulnerability (CVE-27840). For high-assurance deployments, consider
RP2350-based alternatives which have a more robust secure boot
implementation.

---

## License

AGPL v3. Based on [pico-openpgp](https://github.com/polhenarejos/pico-openpgp) (GPL v3),
[pico-fido](https://github.com/polhenarejos/pico-fido) (GPL v3), and
[pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk) (AGPL v3).
