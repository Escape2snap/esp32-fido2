#!/usr/bin/env python3
"""Test PIV ECDH key establishment (GENERAL AUTHENTICATE tag 85).

Prerequisites:
  - The card has a 9D EC key, e.g.:
      piv-tool -A A:9B:03 -G 9D:11 -o 9D.pub
  - Python packages: pyscard, cryptography

The script verifies the PIV PIN, reads the 9D certificate, generates an
ephemeral host key, sends its uncompressed public point with tag 85, and
compares the returned shared secret with the host's ECDH result.
"""

import argparse
import sys

try:
    from smartcard.System import readers
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    print("Missing packages. Install with:")
    print("  py -m pip install pyscard cryptography")
    sys.exit(2)


def parse_tlv(data, off=0):
    if off + 2 > len(data):
        raise ValueError("TLV too short")
    tag = data[off]
    length = data[off + 1]
    hdr = 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[off + 2:off + 2 + n], "big")
        hdr = 2 + n
    vo = off + hdr
    if vo + length > len(data):
        raise ValueError("TLV overrun")
    return tag, data[vo:vo + length]


class Card:
    def __init__(self, reader_name):
        candidates = readers()
        if not candidates:
            raise RuntimeError("no reader")
        if reader_name:
            selected = None
            for i, r in enumerate(candidates):
                if str(i) == reader_name or r.name == reader_name:
                    selected = r
                    break
            if selected is None:
                raise RuntimeError("reader not found")
        else:
            selected = candidates[0]
        self.reader = selected
        self.conn = selected.createConnection()
        self.conn.connect()

    def close(self):
        try:
            self.conn.disconnect()
        except Exception:
            pass

    def apdu(self, data):
        resp, sw1, sw2 = self.conn.transmit(list(data))
        out = bytearray(resp)
        while sw1 == 0x61:
            more, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            out.extend(more)
        return bytes(out), sw1, sw2

    def ok(self, data):
        resp, sw1, sw2 = self.apdu(data)
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError("APDU %s -> %02X%02X" %
                               (data.hex(), sw1, sw2))
        return resp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", default="123456")
    ap.add_argument("--reader")
    args = ap.parse_args()

    card = Card(args.reader)
    try:
        print("Reader: " + card.reader.name)
        card.ok(bytes.fromhex("00A4040009A0000003080000100000"))

        pin = args.pin.encode("ascii")
        verify = bytes([0x00, 0x20, 0x00, 0x80, len(pin)]) + pin
        card.ok(verify)
        print("PIN verified")

        get_cert = bytes([0x00, 0xCB, 0x3F, 0xFF, 5]) + bytes.fromhex("5C035FC10B") + b"\x00"
        resp = card.ok(get_cert)
        tag, body = parse_tlv(resp)
        if tag != 0x53:
            raise RuntimeError("9D certificate: no 53")
        tag, der = parse_tlv(body)
        if tag != 0x70:
            raise RuntimeError("9D certificate: no 70")
        cert = x509.load_der_x509_certificate(der)
        pub = cert.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise RuntimeError("9D certificate is not EC")
        curve = pub.curve
        if isinstance(curve, ec.SECP256R1):
            alg = 0x11
        elif isinstance(curve, ec.SECP384R1):
            alg = 0x14
        else:
            raise RuntimeError("unsupported curve")

        host = ec.generate_private_key(curve)
        point = host.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        inner = b"\x82\x00" + b"\x85" + bytes([len(point)]) + point
        outer = b"\x7C" + bytes([len(inner)]) + inner
        ga = bytes([0x00, 0x87, alg, 0x9D, len(outer)]) + outer + b"\x00"
        resp = card.ok(ga)

        tag, body = parse_tlv(resp)
        if tag != 0x7C:
            raise RuntimeError("GA: no 7C")
        tag, z_card = parse_tlv(body)
        if tag != 0x82:
            raise RuntimeError("GA: no 82 shared secret")
        z_host = host.exchange(ec.ECDH(), pub)

        print("card Z : " + z_card.hex().upper())
        print("host Z : " + z_host.hex().upper())
        if z_card != z_host:
            raise RuntimeError("ECDH shared secret mismatch")
        print("PASS: PIV ECDH key establishment")
    finally:
        card.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("FAIL: " + str(exc))
        sys.exit(1)
