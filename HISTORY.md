# Fix History

### PR #45 — RSA PSO:DEC Algorithm Reference Byte
`cmd_pso.c:125-147` — Skip algorithm reference byte (`apdu.data + 1`)

**Root cause:** OpenPGP Card spec v3.4 §7.2.10 defines the PSO:DEC input
for RSA as `XX || C` where XX is the algorithm reference (0x02 = PKCS#1)
and C is the raw big-endian ciphertext. The fork rewrote the upstream's
`apdu.data + 1` into a local buffer copy without skipping the first byte,
prepending the algorithm reference to the ciphertext and corrupting PKCS#1
padding. The added `apdu.nc > key_size` guard then rejected the
`key_size + 1` input outright.

**Effect:** All RSA 2048/4096 decryption failed with GPG reporting
"decryption failed: Invalid value". EC curves were unaffected.

---

### PR #44 — Core 1 RNG Bottleneck
`hwrng.c:223-224` — `sleep_ms(1)` → `hwrng_task()`

**Root cause:** `hwrng_wait_full()` on core 1 used `sleep_ms(1)` in a polling
loop, depending on core 0's `hwrng_task()` to fill the 32-byte RNG buffer at
8 bytes per 10ms (~800 B/s). RSA 2048 key generation needs hundreds of
kilobytes of random data, making keygen minutes-long.

**Effect:** RSA 2048/4096 key generation took 10+ minutes. ECC key generation
was also somewhat slower than necessary.

---

### PR #43 — FIDO Reset Linked-List Corruption & Core 1 Deadlock
`cbor_reset.c:43-87` — `file_initialize_flash()` → per-file `file_delete()`

**Root cause:** The old approach (`file_initialize_flash(true)`) wrote 8 bytes
of zeros at `end_data_pool` to break the flash linked list, leaving orphaned
credential/RP data in flash. The subsequent `flash_task()` drain called
`low_flash_task()` which does `multicore_lockout_start_timeout_us()` →
`vTaskSuspend(hcore1)` on ESP32 — self-suspending the calling CBOR handler
on core 1 permanently.

---

### PR #42 — User-Presence Button Never Commissioned
`main/main.c:178-179`, `button.c:105`, `cbor_make_credential.c:444-451`

**Root cause:** Three independent issues:
1. `up_btn_present` never set to `true` in `main.c` → `button_wait()` returned
   immediately without polling GPIO0.
2. `force_button_wait` was declared and assigned in `cbor_selection.c` but
   `button_wait()` never read it.
3. `cbor_make_credential.c` only called `check_user_presence()` when
   `pinUvAuthParam.present == true`. Without a PIN, UP was silently granted.

**Effect:** FIDO2 registration and login never required the BOOT button press.
UIF-enabled OpenPGP signing also skipped the button.

---

### PR #41 — FIDO/OpenPGP PIN Conflict & PSO Authentication Check
`cmd_pso.c:31-41`, `openpgp.c`, `main/main.c`

**Root cause — PSO auth check (critical):** `cmd_pso.c` had has_pw1/has_pw2
checks accidentally swapped from upstream:
- PSO:CDS (`0x9E, 0x9A`) requires PW1 in CDS mode (`VERIFY P2=0x81`,
  tracked by `has_pw1`), but checked `has_pw2`.
- PSO:DEC (`0x80, 0x86`) requires PW1 in other mode (`VERIFY P2=0x82`,
  tracked by `has_pw2`), but checked `has_pw1`.

After FIDO init, re-selecting OpenPGP cleared all `has_pw` flags. GPG then
sent `VERIFY P2=0x81` setting `has_pw1`, but PSO:CDS checked `has_pw2` →
`SECURITY_STATUS_NOT_SATISFIED` → GPG reported "Bad Pin".

**Root cause — kbase instability:** `derive_kbase()` returned different keys
depending on whether `EF_DEV_SALT` existed. OpenPGP PIN verifiers derived
with "NO-OTP" fallback were invalidated when FIDO later created the random
salt. Fixed by creating `EF_DEV_SALT` at boot in `app_main()`.

**Root cause — flash_commit_sync deadlock:** `inc_sig_count()` called
`flash_commit_sync(5000)` which busy-waits for `flash_available`, but
`flash_available` is only cleared by `low_flash_task()` in the same
`core0_loop` — causing a 5-second timeout on every PSO:CDS operation.
Reverted to async `flash_commit()`.

---

### PR #40 — OpenPGP Counters Reset on Reboot
`openpgp.c:215-266`, `low_flash.c:96,220-228`

**Root cause — PIV/OpenPGP size conflict (PIN retry counters):** PIV's
`scan_files_piv()` upgraded `EF_PW_PRIV` from 7 to 9 bytes (adding PIV PIN
retry fields) and `EF_PW_RETRIES` from 4 to 6 bytes. OpenPGP's
`scan_files_openpgp()` had hardcoded size checks (`!= 7` / `!= 4`) that
triggered on the PIV-extended sizes and reinitialised both files to defaults,
destroying all OpenPGP retry counters on every OpenPGP select after PIV init.

**Root cause — stale MMU mapping:** `low_flash_task()` mapped the ESP32
partition only once and never remapped, so `flash_read()` returned stale
cached data after `esp_partition_write()`. Restored upstream's
`esp_partition_munmap()` + `esp_partition_mmap()` cycle after every write.

**Root cause — `ready_pages` global pollution:** Changed from
non-static global to `static` to prevent corruption by other compilation
units (underflow recovery code was already added, confirming the problem).

---

### PR #37 — PIN Retry Counter Not Decrementing
`files.c:138-139`, `cmd_verify.c:59`, `openpgp.c:217-222,448-465,474-492`

**Root cause:** `EF_PW_PRIV` (PW_STATUS DO C4) byte layout did not match
[OpenPGP Card spec v3.4 §4.3.1](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf).
The spec defines 7 bytes as `[PW1_validity, max_PW1_len, max_RC_len, max_PW3_len,
PW1_retries, RC_retries, PW3_retries]`, but the code used
`{0x01, 3, 3, 3, 0, 0, 0}` — treating bytes 1–3 as retry counters and
leaving bytes 4–6 (actual retry counters) at 0.

**Effect:** All three passwords were blocked from the first boot.

---

### PR #33 — CBOR COSE Algorithm Encoding Fix
`cbor.c:165,232` — `-(alg+1)` → `-alg`

**Root cause:** The CBOR COSE algorithm encoding used `-(alg + 1)` instead of the
correct `-alg`. `cbor_encode_negative_int(absolute_value)` encodes CBOR major type 1
with value `absolute_value - 1`, which decodes as `-absolute_value`. For ES256 (alg=-7),
`-alg=7` produces CBOR -7 (correct), while `-(alg+1)=6` produced CBOR -6 (wrong).

**Effect:** All COSE key encodings in getInfo, makeCredential, and getAssertion
had incorrect algorithm identifiers. Browsers rejected the device.

---

### PR #32 — Auth Token Pointer Staleness After Flash Commit
`fido.c:494-505`

**Root cause:** `scan_files_fido()` captured `paut.data` and `ppaut.data` from the
flash page cache, then called `flash_commit_sync(5000)` which flushed the cache and
freed those pages. getInfo later used the stale pointers, reading freed cache memory.

---

### PR #30 — HID Transaction Timeout
`hid.c:100` — `200ms` → `1500ms`

**Root cause:** HID transaction timeout was 200ms while CCID used 1500ms. getInfo
processing (flash reads + AES encryption) could exceed 200ms, causing premature
KEEPALIVE frames.

---

### PR #28 — Protocol, Security & Stability Fixes
| Fix | File | Detail |
|-----|------|--------|
| HID INIT channel ID | `hid.c:401` | SHA-256(nonce \|\| device_secret) per CTAP 2.1 §8.2.3 |
| CCID bSeq use-after-free | `ccid.c:351` | Save seq before RX buffer consumed |
| CTAP_MAX_PACKET_SIZE | `ctap_hid.h:145` | 128→127 segments (7609→7600 bytes) |
| LOCK bypass | `hid.c:349` | Removed 100ms idle window |
| CANCEL spec violation | `hid.c:535-536` | Removed response frame |
| Mutex leak | `usb.c:296-303` | break-without-unlock fixed |
| CHANGE PIN buffer over-read | `cmd_change_pin.c:30` | Added `pin_len > apdu.nc` check |
| ACTIVATE FILE no-op | `cmd_activate_file.c:20` | Implemented per OpenPGP v3.4 §7.2.14 |
| flash_commit_sync data race | `flash.c:200-211` | Added volatile + memory barrier |

---

### PR #27 — CTAP2 / USB Transport / Security Hardening
| Fix | File | Detail |
|-----|------|--------|
| Transport array overflow | `cbor_make_credential.c:133` | Added `>= 8` bounds check |
| Transport array overflow | `cbor_get_assertion.c:136` | Added `>= 8` bounds check |
| calloc NULL deref | `credential.c:327-334` | Added `!copy_cred_id` check + free |
| memcmp buffer over-read | `cbor_get_assertion.c:339` | Added `MIN()` + file size validation |
| Sign counter silent increment | `cbor_get_assertion.c:752` | Added `if (up)` guard |
| Counter async commit | `cbor_get_assertion.c:755` | `flash_commit()` → `flash_commit_sync(5000)` |
| CBOR key order | `cbor_make_credential.c:74-77` | Removed CTAP 2.1 spec violation |
| keydev_dec/session_pin zeroize | `fido.c:99-100` | Added to `fido_unload()` |
| bootloader_random_disable | `hwrng.c:33,63-66` | Added missing disable call |
| SHA-256 error check | `serial.c:43-46` | Added `sha_ret != 0` check |
| HID bufsize validation | `hid.c:283-286` | Added `bufsize != 64` check |
| USB power descriptor | `usb_descriptors.c:53` | 4mA→100mA |
| flash use-after-free | `flash.c:134-138` | Save `old_file_data` before clear |
| meta_delete TLV corruption | `file.c:408,414` | Remove spurious `-1` offset |
| part0 NULL crash | `low_flash.c:247-250` | Added `!part0` check |
| CBOR msg size check | `hid.c:520-523` | Added `CTAP_MAX_CBOR_PAYLOAD` bound |
| cancel_button volatile | `hid.c:315` | `bool`→`volatile bool` |
| APDU routing HID/CCID clash | `apdu.c:130,159` | Added `itf != ITF_SC_CCID/WCID` |
| RSA PSO:DEC algorithm byte | `cmd_pso.c:125-147` | Restored `apdu.data + 1` per spec §7.2.10 |
| Ed25519/X25519 key format | `openpgp.c` | EdDSA seed storage, X25519 LE scalar |

---

### PR #24 — OpenPGP Card Implementation Fixes
| Fix | File | Detail |
|-----|------|--------|
| PIN retry index (3-bytes off) | `openpgp.c:447-478` | Removed spurious `3 +` offset |
| PSO:ENC/AES always failing | `cmd_pso.c:46-48` | Set `algo_fid = EF_ALGO_PRIV2` |
| RESET RETRY always failing | `openpgp.c:272` | Added `!has_rc` to `load_dek` |
| MSE SET buffer over-read | `cmd_mse.c:23-25` | Added `apdu.nc < 3` check |
| SELECT DATA buffer over-read | `cmd_select_data.c:25-27` | Added `apdu.nc < 1` check |
| ECDH kdata overflow | `cmd_pso.c:167-169` | Added `key_size > sizeof(kdata)` check |
| is_gpg not reset | `openpgp.c:411` | Set `is_gpg = true` on select |
