"""Print independent public test vectors; not a runtime crypto implementation.

Requires Python cryptography (verified with 41.0.7). These public fixture keys
must never be used outside tests. Run from any directory; no files are modified.
"""

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def main():
    """Generate one first-packet vector for each custom cover and suite."""
    session = b"\x22" * 16
    lane = 0x01020304
    generation = 7
    payload = bytes([0, 1, 2, 254, 255])
    for cover in (1, 2):
        for suite in (1, 2):
            info = (
                b"l2tunnel/datagram/key/v1\0"
                + bytes([suite, cover, 1])
                + session
                + struct.pack("!II", lane, generation)
            )
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"l2tunnel/datagram/extract/v1",
                info=info,
            ).derive(b"\x11" * 32)
            prefix = b"\x48\x02\x03\x04" if cover == 1 else b"\x40" + session[:8]
            header = (
                prefix
                + b"LD"
                + bytes([1, cover, suite, 1, 0, 0])
                + session
                + struct.pack("!IIQHH", lane, generation, 0, len(payload), 0)
            )
            if suite == 1:
                packet = header + ChaCha20Poly1305(key).encrypt(b"\0" * 12, payload, header)
            else:
                authenticated = header + payload
                packet = authenticated + hmac.new(key, authenticated, hashlib.sha256).digest()
            print(f"cover={cover} suite={suite} {packet.hex()}")


if __name__ == "__main__":
    main()
