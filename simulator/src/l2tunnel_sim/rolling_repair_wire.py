"""Byte oracle for the C48 regular and tail repair union (excluding near8)."""

from .aggregate_ack import _decode_bounded_varint
from .aligned_records import _unsigned_varint


def _support(identity, end, tail, window, local, every, max_payload):
    if not (0 < identity < 2**64 - 1 and 0 < end < 2**32
            and 1 <= local <= window <= 8192 and 1 <= every < 2**16
            and 1 <= max_payload <= 4096):
        raise ValueError("invalid rolling identity, window or global interval")
    global_row = tail or (identity & 0x7fff) % every == 0
    return global_row, max(0, end - (window if global_row else local))


def encode_repair(identity, end, start, tail, rhs, *, confirmed_prefix,
                  window=8192, local=128, every=16, max_payload=1259):
    """Encode the frozen actual support. RHS includes its GF-coded u16 length."""
    global_row, nominal = _support(identity, end, tail, window, local, every, max_payload)
    if not nominal <= start < end or not 3 <= len(rhs) <= max_payload + 2:
        raise ValueError("invalid rolling repair support or coded extent")
    trimmed = start > nominal
    if trimmed and not (confirmed_prefix and global_row):
        raise ValueError("shortened repair outside negotiated global support")
    tag = (8 if tail else 7) if trimmed else (4 if tail else 2)
    header = bytes([tag]) + _unsigned_varint(identity) + _unsigned_varint(end)
    if trimmed:
        header += _unsigned_varint(start - nominal)
    return header + bytes(rhs)


def decode_repair(data, *, confirmed_prefix, window=8192, local=128, every=16, max_payload=1259):
    """Return repair identity, end, start, tail, and RHS from canonical wire bytes."""
    if not data or data[0] not in ((2, 4, 7, 8) if confirmed_prefix else (2, 4)):
        raise ValueError("unknown rolling repair tag")
    tail = data[0] in (4, 8)
    identity, pos = _decode_bounded_varint(data, 1, 2**64 - 2)
    end, pos = _decode_bounded_varint(data, pos, 2**32 - 1)
    global_row, start = _support(identity, end, tail, window, local, every, max_payload)
    if data[0] in (7, 8):
        count, pos = _decode_bounded_varint(data, pos, 2**32 - 1)
        if not global_row or not 0 < count < end - start:
            raise ValueError("invalid or redundant rolling prefix count")
        start += count
    if not 3 <= len(data) - pos <= max_payload + 2:
        raise ValueError("invalid rolling coded extent")
    return identity, end, start, tail, bytes(data[pos:])
