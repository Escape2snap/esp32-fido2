# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Flash

```bash
# Activate ESP-IDF (required before any idf.py command)
source /path/to/esp-idf-v5.4.4/export.sh

# Full build flow (first time or after changing target)
rm -rf build sdkconfig
idf.py set-target esp32s3
idf.py build

# Flash (erase first for initial or partition-table changes)
idf.py -p /dev/ttyACM0 erase-flash
idf.py -p /dev/ttyACM0 flash

# Incremental build (after code changes)
idf.py build
idf.py -p /dev/ttyACM0 flash

# Monitor serial output
idf.py -p /dev/ttyACM0 monitor
# Exit monitor: Ctrl+]

# Clean and full rebuild
idf.py fullclean
idf.py build
```

### Permissions

```bash
sudo chmod 666 /dev/ttyACM0                    # temporary
sudo usermod -a -G dialout $USER               # permanent (log out first)
```

### Enabling Optional Features

```bash
# Enable EdDSA (Ed25519/Ed448) — requires mbedTLS fork integration
idf.py reconfigure -DENABLE_EDDSA=ON

# Enable PQC (ML-KEM)
idf.py reconfigure -DENABLE_PQC=ON
```

## Architecture

### Component Dependency Flow

```
main/
  └── app_main() → init chain, core0_loop()
       │
       ├── picokeys (core SDK layer)
       │   ├── fs/            — flash file system (wear-levelling, low-level flash ops)
       │   ├── usb/           — USB CCID + HID transport + descriptors
       │   ├── led/           — NeoPixel WS2812 LED (GPIO48)
       │   ├── rng/           — hardware RNG + software random
       │   └── compat/        — ESP32 platform compat headers
       │
       ├── openpgp (OpenPGP card v3.4)
       │   ├── cmd_*.c        — APDU command handlers (one per ISO 7816 instruction)
       │   ├── do.c           — Data Object parsing/formatting
       │   ├── files.c        — file_entries[] (combined OpenPGP + FIDO entries)
       │   ├── management.c   — AID lifecycle management
       │   └── piv.c          — PIV smartcard application
       │
       ├── fido (FIDO2/CTAP 2.1)
       │   ├── cbor_*.c       — CTAP 2.1 CBOR command handlers
       │   ├── cmd_*.c        — U2F legacy APDU handlers
       │   ├── credential.c   — resident key storage and RP management
       │   ├── fido.c         — init, scan_files_fido(), AID registration
       │   └── fido_ef.c      — EF pointer globals (ef_keydev, ef_pin, ...)
       │
       └── tinycbor (CBOR parser — from Intel/tinycbor v0.6.1)
```

### Key Data Flow

```
USB CCID ←→ openpgp (parse APDU → dispatch cmd_* → respond)
USB HID  ←→ fido/hid.c (CTAP HID transport → cbor_process() → respond)
                ↓
          picokeys/fs/ (wear-levelled flash storage)
                ↓
          mbedTLS (ESP-IDF built-in, with hardware acceleration)
```

### Flash File System

- Single `file_entries[]` array defined in `components/openpgp/files.c`
- Both OpenPGP and FIDO2 file entries coexist in the same array
- EF (Elementary File) pointers discovered at runtime via `scan_files_fido()`
- Wear-levelling on `part0` partition (4MB)
- Partition table at `partitions.csv` (factory 2MB + part0 4MB + NVS)

### LED Control

- NeoPixel WS2812 on GPIO48
- Driver: `components/picokeys/src/led/led_neopixel.c`
- Brightness controlled via `pixel[]` RGB values (currently 50/255 ≈ 20%)
- Mode definitions in `led.h` encode: color, brightness, on/off timing

### Algorithm Defaults

Set in two places (keep in sync):
- `components/openpgp/cmd_keypair_gen.c` — default for key generation
- `components/openpgp/do.c` — default reported in ALGO INFO

## Key Patterns

### Adding a new FIDO CBOR command

1. Add handler in `components/fido/cbor_*.c`
2. Wire the command code in the dispatch table in `fido.c`
3. Add file entries to `components/openpgp/files.c` if persistent storage needed

### Important Global Variables

| Symbol | Defined In | Purpose |
|--------|-----------|---------|
| `app_t apps[]` | `main/main.c` | Registered application table |
| `ef_*` (ef_keydev, ef_pin, etc.) | `components/fido/fido_ef.c` | FIDO EF file pointers |
| `ccid_atr` | `main/main.c` | CCID ATR (set by selected applet) |
| `file_entries[]` | `components/openpgp/files.c` | Combined flash filesystem entries |

### Default Algorithm Configuration

Default algorithm for all three key slots (SIG/DEC/AUT) is **brainpool384r1**.
- Set via `algorithm_attr_bp384r1` references in `cmd_keypair_gen.c` and `do.c`
- For X25519 decryption: use `algorithm_attr_cv25519`
- For Ed25519: use `algorithm_attr_ed25519` (requires ENABLE_EDDSA)

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
