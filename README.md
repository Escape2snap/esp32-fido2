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
| Ed25519 (EdDSA) | ✅ |
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

### Verifying Ed25519 Keys (Debug Mode)

When CONFIG_DEBUG_APDU_HEX is enabled, the firmware prints the raw key
material to serial during Ed25519 key generation:

```
[dbg] Ed25519 seed:          <32-byte hex — the private key seed>
[dbg] Ed25519 Q.x (LE):     <32-byte hex — public key x (little-endian)>
[dbg] Ed25519 Q.y (LE):     <32-byte hex — public key y (little-endian)>
[dbg] make_ecdsa Ed25519... <32-byte hex — RFC 8032 encoded public key>
[dbg] make_ecdsa final APDU <full 7F 49 response including SW>
```

To verify that the card computed the correct public key:

1. Extract the seed hex from the serial output (first `[dbg] Ed25519 seed:` line)
2. Compute the expected public key with Python:

```python
import hashlib

seed = bytes.fromhex("<paste seed hex here>")
# SHA-512(seed), clamp
h = hashlib.sha512(seed).digest()
scalar = bytearray(h[:32])
scalar[0] &= 248; scalar[31] &= 63; scalar[31] |= 64

# The clamped scalar is used for EC point multiplication s * B
# (requires an Ed25519 library like nacl or cryptography)
```

Or extract the GPG public key for comparison:

```bash
gpg --export --export-options export-minimal --armor <KEYID> | gpg --list-packets
```

The serial output `[dbg] Ed25519 Q.y (LE)` should match the y-coordinate
in the GPG public key packet.

---

## Debug Mode

Debug output (Ed25519 seed, public key, APDU hex dumps) is **built into
the `feat/ed25519` branch**.  Enable via `idf.py menuconfig` → **Debug
Mode**:

| Option | Default | Description |
|--------|---------|-------------|
| `DEBUG_ENABLE` | n | Master switch |
| `DEBUG_APDU_HEX` | y¹ | Hex dump APDUs + Ed25519 key material |
| `DEBUG_PERF` | y¹ | Timing markers for key derivation, signing, flash |
| `DEBUG_STACK` | n | Periodic free-stack report for core0_loop |
| `DEBUG_WDT_FEED` | n | `esp_task_wdt_reset()` inside long-running loops |
| `DEBUG_WDT_FEED_INTERVAL_MS` | 500 | WDT feed interval (100–5000 ms) |

¹ *Only visible when `DEBUG_ENABLE` is set.*

### Console Output (example)

```
[perf] derive_key: 15234 us
[perf] credential_create: 8912 us
[stack] core0: 2048 bytes free
[fido-req] 90010A4700...
[fido-resp] 00...
```

When `DEBUG_WDT_FEED` is enabled, the hardware watchdog is
automatically reset during long crypto operations (HKDF chains,
Ed25519 scalar multiplication) at the configured interval, preventing
watchdog-triggered reboots during operations that take > 10 s.

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
- **Ed25519 key generation is slow (~8 s):** The dedicated fe25519 field
  arithmetic (components/eddsa/) is ~100× faster than generic mbedTLS bignum,
  but still slower than the HW ECC accelerator (which doesn't support
  Edwards curves).  CCID timeout was increased to 10 s to accommodate this.

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
