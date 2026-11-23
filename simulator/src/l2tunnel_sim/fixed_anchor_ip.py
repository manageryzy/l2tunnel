"""Native-IP fixed-context record bodies, for use over already authenticated channel records.

The study's forward Ethernet MACs are supplied by its local endpoint adapter.
No Ethernet bytes are embedded in an IP header context or IP raw record.
"""

from dataclasses import dataclass

from .aligned_records import TIMESTAMP_PAIRS, TIMESTAMP_PAIR_INDEX, _unsigned_varint
from .compact import _checksum


CONTEXT, DELTA, WRAPPER, RAW = 8, 9, 11, 2
MAX_DISTANCE = 8


def _u16(data, pos):
    return int.from_bytes(data[pos : pos + 2], "big")


def _options(data, start, end, tcp):
    stamp = None
    while start < end:
        kind = data[start]
        if kind == 0:
            break
        if kind == 1:
            start += 1
            continue
        if start + 1 >= end or not 2 <= data[start + 1] <= end - start:
            raise ValueError("malformed IP or TCP option")
        size = data[start + 1]
        if tcp and kind == 8:
            if size != 10 or stamp is not None:
                raise ValueError("invalid TCP timestamp option")
            stamp = start + 2
        start += size
    return stamp


@dataclass(frozen=True)
class Header:
    data: bytes
    tcp: int
    fields: tuple
    values: tuple
    payload: int
    ipv4: bool

    @classmethod
    def parse(cls, data, *, full):
        if not data:
            raise ValueError("empty IP packet")
        ipv4 = data[0] >> 4 == 4
        if ipv4:
            tcp = (data[0] & 15) * 4
            if (
                len(data) < 20
                or not 20 <= tcp <= 60
                or len(data) < tcp
                or data[9] != 6
                or _u16(data, 6) & 0x3FFF
            ):
                raise ValueError("unsupported IPv4 header")
            _options(data, 20, tcp, False)
            total = _u16(data, 2)
        elif data[0] >> 4 == 6 and len(data) >= 40 and data[6] == 6 and _u16(data, 4):
            tcp, total = 40, 40 + _u16(data, 4)
        else:
            raise ValueError("unsupported IP header")
        if len(data) < tcp + 20:
            raise ValueError("truncated TCP header")
        header = tcp + (data[tcp + 12] >> 4) * 4
        if not tcp + 20 <= header <= min(tcp + 60, len(data), total):
            raise ValueError("bad TCP header extent")
        if len(data) != (total if full else header):
            raise ValueError("inconsistent native IP length")
        ts = _options(data, tcp + 20, header, True)
        fields = (
            (4, 2) if ipv4 else None,
            (tcp + 4, 4),
            (tcp + 8, 4),
            (tcp + 13, 1),
            (tcp + 14, 2),
            (tcp + 18, 2),
            (ts, 4) if ts is not None else None,
            (ts + 4, 4) if ts is not None else None,
        )
        values = tuple(
            int.from_bytes(data[p[0] : p[0] + p[1]], "big") if p else 0 for p in fields
        )
        return cls(bytes(data[:header]), tcp, fields, values, total - header, ipv4)

    def restore(self, values, payload):
        h = bytearray(self.data)
        for value, field in zip(values, self.fields):
            if field:
                start, width = field
                h[start : start + width] = value.to_bytes(width, "big")
        tcp = self.tcp
        size = len(h) + len(payload)
        if size > 65535:
            raise ValueError("native packet exceeds study maximum")
        tlen = size - tcp
        if self.ipv4:
            h[2:4] = size.to_bytes(2, "big")
            h[10:12] = b"\0\0"
            h[10:12] = _checksum(bytes(h[:tcp]))
            pseudo = bytes(h[12:20]) + b"\0\x06" + tlen.to_bytes(2, "big")
        else:
            h[4:6] = (size - 40).to_bytes(2, "big")
            pseudo = bytes(h[8:40]) + tlen.to_bytes(4, "big") + b"\0\0\0\x06"
        h[tcp + 16 : tcp + 18] = b"\0\0"
        h[tcp + 16 : tcp + 18] = _checksum(pseudo + bytes(h[tcp:]) + payload)
        return bytes(h)


def _word(n):
    return n.to_bytes(2, "big")


def _delta_prefix(inner):
    tag = inner[0]
    if tag == DELTA:
        if len(inner) < 4:
            raise ValueError("truncated explicit delta")
        mask, pos = inner[3], 4
    elif tag == 6:
        if len(inner) < 2:
            raise ValueError("truncated length-elided delta")
        mask, pos = inner[1], 2
    elif tag & 7 == 7:
        mask, pos = tag & 0xF8, 1
    elif tag & 7 == 5:
        return 1, [0] * 8
    else:
        raise ValueError("invalid fixed-anchor inner tag")
    changed = [0] * 8
    for i in range(8):
        if mask & (1 << i):
            for shift in range(0, 35, 7):
                if pos >= len(inner):
                    raise ValueError("truncated IP delta")
                b = inner[pos]
                pos += 1
                changed[i] |= (b & 127) << shift
                if not b & 128:
                    break
            else:
                raise ValueError("overflowing IP delta")
    return pos, changed


def validate_body(data, *, padded, max_native=65532):
    """Return the exact explicit body, or an implicit body pending its named context."""
    if not data:
        raise ValueError("empty fixed-anchor body")
    tag = data[0]
    if tag in (RAW, CONTEXT):
        if len(data) < 3:
            raise ValueError("truncated native body")
        size = _u16(data, 1)
        end = 3 + size
        if not 0 < size <= max_native:
            raise ValueError("invalid native body extent")
        if tag == CONTEXT:
            anchor = Header.parse(data[3:end], full=False)
            if len(anchor.data) + anchor.payload > max_native or (
                anchor.ipv4 and _checksum(anchor.data[: anchor.tcp]) != b"\0\0"
            ):
                raise ValueError("invalid IP context size or checksum")
    elif tag == WRAPPER and len(data) >= 3 and 1 <= data[1] <= MAX_DISTANCE:
        inner = data[2:]
        pos, _ = _delta_prefix(inner)
        if inner[0] != DELTA:
            return bytes(data)
        end = 2 + pos + _u16(inner, 1)
    else:
        raise ValueError("invalid fixed-anchor outer tag or backward distance")
    if end > len(data) or (any(data[end:]) if padded else end != len(data)):
        raise ValueError("fixed-anchor trailing or truncated data")
    return bytes(data[:end])


def encode_ip(
    packet, anchor, distance, *, capacity, elide, predictive, pairs, short, maximum
):
    """Return an optional new numbered context and one body. Deltas never update an anchor."""
    if not 0 < len(packet) <= maximum:
        raise ValueError("invalid native IP length")
    raw = bytes((RAW,)) + _word(len(packet)) + packet
    if len(packet) <= short:
        return None, raw
    try:
        current = Header.parse(packet, full=True)
    except ValueError:
        return None, raw
    payload = packet[len(current.data) :]
    values = current.values
    refresh = (
        anchor is None
        or anchor.fields != current.fields
        or len(anchor.data) != len(current.data)
        or anchor.ipv4 != current.ipv4
        or anchor.restore(values, payload) != current.data
    )
    if refresh:
        if current.restore(values, payload) != current.data:
            return None, raw
        anchor = current
        distance = 1
    if not 1 <= distance <= MAX_DISTANCE:
        raise ValueError("invalid anchor distance")
    diffs = [
        (a - b) % (1 << (8 * field[1])) if field else 0
        for a, b, field in zip(values, anchor.values, anchor.fields)
    ]
    mask = sum(1 << i for i, x in enumerate(diffs) if x)
    changes = b"".join(_unsigned_varint(x) for x in diffs if x)
    base = bytes((DELTA,)) + _word(len(payload)) + bytes((mask,)) + changes + payload
    if (
        predictive
        and not refresh
        and len(payload) == anchor.payload
        and (not anchor.ipv4 or diffs[0] == 1)
        and diffs[1] == len(payload)
        and not diffs[2]
    ):
        pred = (
            bytes(((mask & 0xF8) | 7,))
            + b"".join(_unsigned_varint(x) for x in diffs[3:] if x)
            + payload
        )
        if len(pred) <= capacity - 2:
            pair = (
                TIMESTAMP_PAIR_INDEX.get(tuple(diffs[6:]))
                if pairs and anchor.fields[6] and not mask & 0x38
                else None
            )
            base = (bytes(((pair << 3) | 5,)) + payload) if pair is not None else pred
    if (
        elide
        and base[0] == DELTA
        and len(base) - 2 <= capacity - 2
        and len(payload) == anchor.payload
    ):
        base = b"\x06" + base[3:]
    return (current if refresh else None), bytes((WRAPPER, distance)) + base


def decode_ip(anchor, body, *, padded, maximum):
    inner = body[2:]
    tag = inner[0]
    explicit = tag == DELTA
    size = _u16(inner, 1) if explicit else anchor.payload
    pos, diffs = _delta_prefix(inner)
    mask = (
        inner[3]
        if explicit
        else inner[1]
        if tag == 6
        else tag & 0xF8
        if tag & 7 == 7
        else 0
    )
    if any(mask & (1 << i) and field is None for i, field in enumerate(anchor.fields)):
        raise ValueError("delta names absent IP field")
    if tag & 7 in (5, 7):
        diffs[:3] = [int(anchor.ipv4), size, 0]
        if tag & 7 == 5:
            if anchor.fields[6] is None:
                raise ValueError("timestamp prediction without timestamp")
            diffs[6:] = TIMESTAMP_PAIRS[tag >> 3]
    if (
        len(anchor.data) + size > maximum
        or pos + size > len(inner)
        or (any(inner[pos + size :]) if padded else pos + size != len(inner))
    ):
        raise ValueError("inconsistent native delta payload length")
    vals = [
        (old + diff) % (1 << (8 * field[1])) if field else 0
        for old, diff, field in zip(anchor.values, diffs, anchor.fields)
    ]
    payload = bytes(inner[pos : pos + size])
    return anchor.restore(vals, payload) + payload


def enable_forward_fixed_anchor(
    transport, interval=8, *, macs=bytes(range(12)), max_native_bytes=4096
):
    """Select this fixed-MAC native-IP study adapter before the first forward submission."""
    from .fixed_anchor_packed import select

    return select(transport, interval, macs, max_native_bytes)
