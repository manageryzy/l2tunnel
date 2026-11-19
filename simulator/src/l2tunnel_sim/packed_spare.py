"""Sender-local byte budget and compact canonical eight-source study rows."""
from dataclasses import dataclass

from .coding import PRODUCT
from .compact import coefficient

GROUP = 8
MTU = 1500
OUTER = 49
TAG = 6


@dataclass
class SpareGate:
    """100 ms IP-byte buckets against the local configured physical pacing budget."""

    bytes_per_second: int
    enabled: bool = False
    qualifying: int = 0
    credit_eighths: int = 0
    accepted: int = 0

    def __post_init__(self):
        if self.bytes_per_second <= 0:
            raise ValueError("positive sender pacer required")

    def close_bucket(self, ordinary_backlog):
        # Multiply both sides to compare exact integer bytes without roundoff.
        scaled = self.accepted * 1000
        light = 0 < scaled <= 75 * self.bytes_per_second
        if not self.accepted or scaled >= 90 * self.bytes_per_second or ordinary_backlog > 8 * MTU:
            self.enabled = False
        if light and ordinary_backlog <= 8 * MTU:
            self.qualifying = min(self.qualifying + 1, 4)
            self.enabled |= self.qualifying == 4
        else:
            self.qualifying = 0
        self.accepted = 0

    def accept(self, ip_bytes):
        self.accepted += ip_bytes

    def earn_first(self, ip_bytes):
        self.credit_eighths = min(8 * MTU, self.credit_eighths + ip_bytes)

    def reserve_row(self, ip_bytes, ordinary_backlog):
        if not self.enabled or ordinary_backlog > 8 * MTU or not 0 < ip_bytes <= MTU:
            return False
        if self.credit_eighths < 8 * ip_bytes:
            return False
        self.credit_eighths -= 8 * ip_bytes
        return True


def end_bytes(end):
    if not GROUP <= end < 2**32 or end % GROUP:
        raise ValueError("invalid exclusive near endpoint")
    result = bytearray()
    while end >= 128:
        result.append(128 | (end & 127))
        end >>= 7
    result.append(end)
    return bytes(result)


def row_seed(end):
    return 0xb1800000 ^ ((end // GROUP * 2654435761) & 0xffffffff)


def row_bytes(end, bodies):
    """Evaluate actual GF equation, including big-endian protected lengths and padding."""
    if len(bodies) != GROUP or any(not 0 < len(b) <= 65535 for b in bodies):
        raise ValueError("require eight nonempty canonical sources")
    header = bytes([TAG]) + end_bytes(end)
    extent = max(map(len, bodies))
    if OUTER + len(header) + 2 + extent > MTU:
        raise ValueError("row exceeds selected carrier MTU")
    # int XOR aligns little-endian byte vectors on the left, supplying canonical zero tails.
    value = 0
    for index, body in enumerate(bodies, end - GROUP):
        factor = coefficient(row_seed(end), index)
        canonical = len(body).to_bytes(2, "big") + body
        value ^= int.from_bytes(canonical.translate(PRODUCT[factor]), "little")
    return header + value.to_bytes(2 + extent, "little")


def parse_row(wire, floor, global_window):
    if len(wire) < 5 or wire[0] != TAG or OUTER + len(wire) > MTU:
        raise ValueError("invalid near row")
    end = 0
    for i in range(1, min(6, len(wire))):
        octet = wire[i]
        end |= (octet & 127) << (7 * (i - 1))
        if octet < 128:
            if (wire[1:i+1] != end_bytes(end) or len(wire) <= i+3 or
                    not max(1, floor - global_window) <= end <= floor + global_window):
                break
            return end, wire[i+1:i+3], wire[i+3:]
    raise ValueError("invalid near endpoint or extent")
