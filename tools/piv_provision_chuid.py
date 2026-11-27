#!/usr/bin/env python3
"""Provision a production PIV CHUID (ETSI/PIV-I style) over PC/SC.

The tool requires:
  - pyscard
  - pycryptodome (for 3DES/AES management-key authentication)

It performs A.1 external authenticate with the 9B management key, then writes
5FC102 with chained PUT DATA. The CHUID is built from issuer-provided FASC-N,
GUID, ASCII expiration and an optional CMS 3E signature. FE 00 is appended.

FASC-N is accepted as 25 raw bytes in hex. The issuer is responsible for the
FASC-N encoding and for the CMS signature; this tool does not sign.

Examples:
  py tools/piv_provision_chuid.py \
      --fascn-hex D4E739DA739CED39CE739D836858210842108421C84210C3EB \
      --expiry 20301231 \
      --signature issuer-chuid.cms \
      --admin-key 010203040506070801020304050607080102030405060708

  py tools/piv_provision_chuid.py --dry-run ...   (build only, no card)
"""

import argparse
import os
import sys
import uuid

try:
    from smartcard.System import readers
    from Crypto.Cipher import AES, DES, DES3
except ImportError:
    print("Missing packages. Install with:")
    print("  py -m pip install pyscard pycryptodome")
    sys.exit(2)

ALG_3DES = 0x03
ALG_AES128 = 0x08
ALG_AES192 = 0x0A
ALG_AES256 = 0x0C

ALG_MAP = {
    "3des": (ALG_3DES, 24),
    "aes128": (ALG_AES128, 16),
    "aes192": (ALG_AES192, 24),
    "aes256": (ALG_AES256, 32),
}

MAX_CHUID_CONTENT = 1900  # USB/CCID short-APDU and chain-buffer safety margin.


def parse_hex(text):
    text = "".join(c for c in text if c in "0123456789abcdefABCDEF")
    if len(text) % 2:
        raise ValueError("odd hex length")
    return bytes.fromhex(text)


def tlv(tag, value):
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    if n <= 0xFF:
        return bytes([tag, 0x81, n]) + value
    if n <= 0xFFFF:
        return bytes([tag, 0x82, n >> 8, n & 0xFF]) + value
    raise ValueError("TLV too large")


def parse_tlv(data, off=0):
    if off + 2 > len(data):
        raise ValueError("TLV too short")
    tag = data[off]
    length = data[off + 1]
    hdr = 2
    if length & 0x80:
        count = length & 0x7F
        if count < 1 or count > 2:
            raise ValueError("unsupported TLV length")
        length = int.from_bytes(data[off + 2:off + 2 + count], "big")
        hdr = 2 + count
    vo = off + hdr
    if vo + length > len(data):
        raise ValueError("TLV overrun")
    return tag, data[vo:vo + length]


def make_guid(value):
    if value:
        return uuid.UUID(value).bytes
    guid = bytearray(os.urandom(16))
    guid[6] = (guid[6] & 0x0F) | 0x40
    guid[8] = (guid[8] & 0x3F) | 0x80
    return bytes(guid)


def make_cipher(key, algo):
    if algo == "3des":
        if key[:8] == key[8:16] == key[16:24]:
            return DES.new(key[:8], DES.MODE_ECB)
        return DES3.new(key, DES3.MODE_ECB)
    return AES.new(key, AES.MODE_ECB)


class Card:
    def __init__(self, reader_name):
        candidates = readers()
        if not candidates:
            raise RuntimeError("no smart card reader found")
        if reader_name:
            selected = None
            for i, r in enumerate(candidates):
                if str(i) == reader_name or r.name == reader_name:
                    selected = r
                    break
            if selected is None:
                raise RuntimeError("reader not found: " + reader_name)
        else:
            selected = candidates[0]
        self.reader = selected
        self.connection = selected.createConnection()
        self.connection.connect()

    def close(self):
        try:
            self.connection.disconnect()
        except Exception:
            pass

    def transmit(self, apdu):
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        out = bytearray(data)
        while sw1 == 0x61:
            more, sw1, sw2 = self.connection.transmit(
                [0x00, 0xC0, 0x00, 0x00, sw2])
            out.extend(more)
        return bytes(out), sw1, sw2

    def send_ok(self, apdu):
        data, sw1, sw2 = self.transmit(apdu)
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError("APDU %s -> %02X%02X" %
                               (apdu.hex(), sw1, sw2))
        return data


def build_chuid(fascn, guid, expiry, signature):
    expiry_b = expiry.encode("ascii")
    if len(expiry_b) != 8 or not expiry_b.isdigit():
        raise ValueError("expiration must be 8 ASCII digits YYYYMMDD")
    if len(fascn) != 25:
        raise ValueError("FASC-N must be exactly 25 bytes")
    if len(guid) != 16:
        raise ValueError("GUID must be exactly 16 bytes")

    content = (
        tlv(0x30, fascn)
        + tlv(0x34, guid)
        + tlv(0x35, expiry_b)
        + tlv(0x3E, signature)
        + tlv(0xFE, b"")
    )
    if len(content) > MAX_CHUID_CONTENT:
        raise ValueError("CHUID content too large: %d bytes" % len(content))
    return content


def authenticate(card, key, algo):
    alg_id, key_len = ALG_MAP[algo]
    if len(key) != key_len:
        raise ValueError("%s key must be %d bytes" % (algo, key_len))

    card.send_ok(bytes.fromhex("00A4040009A0000003080000100000"))

    step1_data = bytes.fromhex("7C028100")
    step1 = bytes([0x00, 0x87, alg_id, 0x9B, len(step1_data)]) + step1_data + b"\x00"
    resp = card.send_ok(step1)

    tag, body = parse_tlv(resp)
    if tag != 0x7C:
        raise RuntimeError("auth step 1: no 7C")
    tag, challenge = parse_tlv(body)
    if tag != 0x81:
        raise RuntimeError("auth step 1: no 81 challenge")

    cipher = make_cipher(key, algo)
    encrypted = cipher.encrypt(challenge)

    step2_data = tlv(0x7C, tlv(0x82, encrypted))
    step2 = bytes([0x00, 0x87, alg_id, 0x9B, len(step2_data)]) + step2_data + b"\x00"
    card.send_ok(step2)
    print("management authentication OK (%s, %d-bit)" %
          (algo, key_len * 8))


def put_data_chained(card, content):
    command = tlv(0x5C, bytes.fromhex("5FC102")) + tlv(0x53, content)
    chunks = [command[i:i + 200] for i in range(0, len(command), 200)]
    for index, chunk in enumerate(chunks):
        last = index == len(chunks) - 1
        cla = 0x00 if last else 0x10
        apdu = bytes([cla, 0xDB, 0x3F, 0xFF, len(chunk)]) + chunk
        if last:
            apdu += b"\x00"
        card.send_ok(apdu)
    print("PUT DATA OK: %d bytes in %d chunk(s)" % (len(command), len(chunks)))


def read_back(card):
    get = bytes([0x00, 0xCB, 0x3F, 0xFF, 5]) + bytes.fromhex("5C035FC102") + b"\x00"
    resp = card.send_ok(get)
    tag, body = parse_tlv(resp)
    if tag != 0x53:
        raise RuntimeError("GET DATA: no 53 wrapper")
    return body


def main():
    parser = argparse.ArgumentParser(description="Provision a PIV CHUID")
    parser.add_argument("--fascn-hex", required=True,
                        help="25-byte FASC-N, hex (50 chars)")
    parser.add_argument("--guid", help="UUID string; omitted = random UUIDv4")
    parser.add_argument("--expiry", default="20741231",
                        help="8 ASCII digits YYYYMMDD")
    parser.add_argument("--signature", help="CMS 3E signature, DER file")
    parser.add_argument("--allow-empty-signature", action="store_true",
                        help="write 3E 00 (not PACS-conformant)")
    parser.add_argument("--admin-key", default="010203040506070801020304050607080102030405060708",
                        help="management key hex")
    parser.add_argument("--admin-key-file",
                        help="read management key hex from a file")
    parser.add_argument("--admin-algo", choices=sorted(ALG_MAP), default="3des")
    parser.add_argument("--reader", help="reader index or name")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and print the CHUID without touching the card")
    args = parser.parse_args()

    fascn = parse_hex(args.fascn_hex)
    guid = make_guid(args.guid)
    if args.admin_key_file:
        admin_key = parse_hex(open(args.admin_key_file, "r", encoding="ascii").read())
    else:
        admin_key = parse_hex(args.admin_key)

    if args.signature:
        signature = open(args.signature, "rb").read()
    elif args.allow_empty_signature:
        signature = b""
    else:
        raise SystemExit("--signature is required for a production CHUID; "
                         "use --allow-empty-signature only for testing")

    content = build_chuid(fascn, guid, args.expiry, signature)
    print("FASC-N : " + fascn.hex().upper())
    print("GUID   : " + str(uuid.UUID(bytes=guid)))
    print("Expiry : " + args.expiry)
    print("3E size: %d bytes" % len(signature))
    print("CHUID  : %d bytes" % len(content))
    print("Content: " + content.hex().upper())

    if args.dry_run:
        return 0

    card = Card(args.reader)
    try:
        print("Reader: " + card.reader.name)
        authenticate(card, admin_key, args.admin_algo)
        put_data_chained(card, content)
        got = read_back(card)
        if got != content:
            raise RuntimeError("read-back mismatch: wrote %d, read %d bytes" %
                               (len(content), len(got)))
        print("CHUID read-back verified")
    finally:
        card.close()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("FAIL: " + str(exc))
        sys.exit(1)
