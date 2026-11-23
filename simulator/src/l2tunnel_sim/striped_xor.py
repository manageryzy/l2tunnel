"""Length-aware one-erasure array code, selected independently of uniform Cauchy."""
from dataclasses import dataclass

from . import striped_cauchy as uniform


@dataclass(frozen=True)
class Member:
    total: int
    original: bytes
    parity: bytes


class Geometry(uniform.Geometry):
    def own(self, member):
        return member.original

    def parity_bytes(self, member):
        return len(member.parity)


def _widths(sizes):
    """The other members' parity covers every byte and the protected length."""
    n = len(sizes)
    lengths = [size + 2 for size in sizes]
    if n < 2 or not all(0 < size <= 65535 for size in sizes):
        raise ValueError("invalid mixed originals")
    total = max(n, max(lengths) + 1, (sum(lengths) + n - 2) // (n - 1))
    # Give each helper one parity byte. Allocate the remainder within P-L_i
    # so losing helper i still leaves at least L_i parity positions.
    room = [total - length - 1 for length in lengths]
    available = sum(room)
    extra = total - n
    widths = [1 + extra * space // available if available else 1 for space in room]
    remainder = total - sum(widths)
    for i, space in enumerate(room):
        if remainder and widths[i] <= space:
            widths[i] += 1
            remainder -= 1
    if remainder or total > 65535:
        raise ValueError("mixed parity extent exceeds wire limit")
    return total, widths


def _body(original, capacity):
    if len(original) + 2 > capacity:
        raise ValueError("original exceeds available helper positions")
    return original.ljust(capacity - 2, b"\0") + len(original).to_bytes(2, "big")


def _pieces(owner, widths):
    """Put the first payload byte of each owner on its immediate successor."""
    offset = 0
    for step in range(1, len(widths)):
        helper = (owner + step) % len(widths)
        yield helper, offset, offset + widths[helper]
        offset += widths[helper]


def _header(base, count, full):
    if full.m != 1 or not 2 <= count <= full.n or base < 0 or base + count > 2**64:
        raise ValueError("invalid one-erasure group shape")
    return bytes([count - 1]) + uniform._generation_bytes(base)


def group_max_wire(base, originals, full):
    if full.m != 1:
        raise ValueError("length-aware parity requires one allowed erasure")
    if len(originals) == 1:
        return uniform.group_max_wire(base, originals, full)
    prefix = _header(base, len(originals), full)
    _, widths = _widths(list(map(len, originals)))
    return len(prefix) + 5 + max(len(raw) + width for raw, width in zip(originals, widths))


def encode_packets(base, originals, full, max_wire):
    if full.m != 1:
        raise ValueError("length-aware parity requires one allowed erasure")
    if len(originals) == 1:
        return uniform.encode_packets(base, originals, full, max_wire)
    prefix = _header(base, len(originals), full)
    total, widths = _widths(list(map(len, originals)))
    if any(len(prefix) + 5 + len(raw) + w > max_wire for raw, w in zip(originals, widths)):
        raise ValueError("one-erasure datagram exceeds wire budget")
    parity = [0] * len(originals)
    for i, raw in enumerate(originals):
        data = _body(raw, total - widths[i])
        for j, begin, end in _pieces(i, widths):
            parity[j] ^= int.from_bytes(data[begin:end], "little")
    return [prefix + bytes([i]) + len(raw).to_bytes(2, "big") + total.to_bytes(2, "big")
            + raw + parity[i].to_bytes(widths[i], "little") for i, raw in enumerate(originals)]


def inspect_packet(wire, full, max_wire):
    if not wire or len(wire) > max_wire or full.m != 1:
        raise ValueError("invalid one-erasure datagram")
    if wire[0] == 0:
        return uniform.inspect_packet(wire, full, max_wire)
    count = wire[0] + 1
    base = 0
    for pos, octet in enumerate(wire[1:11]):
        base |= (octet & 127) << (7 * pos)
        if octet < 128:
            break
    else:
        raise ValueError("truncated one-erasure generation")
    prefix = _header(base, count, full)
    start = len(prefix)
    if wire[:start] != prefix or len(wire) < start + 7:
        raise ValueError("invalid one-erasure header")
    ordinal = wire[start]
    length = int.from_bytes(wire[start+1:start+3], "big")
    total = int.from_bytes(wire[start+3:start+5], "big")
    end = start + 5 + length
    width = len(wire) - end
    if (ordinal >= count or length == 0 or not count <= total <= max(count, max_wire)
            or not 0 < width <= total - length - 2):
        raise ValueError("invalid one-erasure member dimensions")
    return base, Geometry(count - 1, 1), None, ordinal, Member(total, wire[start+5:end], wire[end:])


class Receiver:
    def __init__(self, geometry):
        self.geometry = geometry
        self.packets = {}
        self.originals = {}
        self.total = None
        self.scaled_bytes = 0

    def add(self, ordinal, member):
        n = self.geometry.n
        if (type(ordinal) is not int or not 0 <= ordinal < n or not isinstance(member, Member)
                or not member.original or not n <= member.total <= 65535
                or not 0 < len(member.parity) <= member.total - len(member.original) - 2):
            raise ValueError("invalid member identity")
        if self.total is not None and member.total != self.total:
            raise ValueError("conflicting group parity total")
        if ordinal in self.packets:
            if self.packets[ordinal] != member:
                raise ValueError("conflicting one-erasure member")
            return None
        if ordinal in self.originals and member.original != self.originals[ordinal]:
            raise ValueError("conflicting recovered original")
        received_width = len(member.parity) + sum(len(m.parity) for m in self.packets.values())
        remaining = n - len(self.packets) - 1
        if received_width + remaining > member.total or (not remaining and received_width != member.total):
            raise ValueError("inconsistent helper widths")
        if not remaining:
            ordered = [member if i == ordinal else self.packets[i] for i in range(n)]
            sizes = [len(m.original) for m in ordered]
            if _widths(sizes) != (member.total, [len(m.parity) for m in ordered]):
                raise ValueError("noncanonical helper widths")
        self.total = member.total
        self.packets[ordinal] = member
        if ordinal in self.originals:
            return None
        self.originals[ordinal] = member.original
        return member.original

    def recover_missing(self):
        if len(self.packets) != self.geometry.k or len(self.originals) == self.geometry.n:
            return {}
        missing, = set(range(self.geometry.n)) - self.packets.keys()
        widths = [len(self.packets[i].parity) if i in self.packets else 0 for i in range(self.geometry.n)]
        widths[missing] = self.total - sum(widths)
        decoded = {i: int.from_bytes(m.parity, "little") for i, m in self.packets.items()}
        work = sum(widths) - widths[missing]
        for i, member in self.packets.items():
            raw = _body(member.original, self.total - widths[i])
            for j, begin, end in _pieces(i, widths):
                if j != missing:
                    decoded[j] ^= int.from_bytes(raw[begin:end], "little")
                    work += end - begin
        body = b"".join(decoded[j].to_bytes(widths[j], "little") for j, _, _ in _pieces(missing, widths))
        size = int.from_bytes(body[-2:], "big")
        if not 0 < size <= len(body) - 2 or any(body[size:-2]):
            raise ValueError("invalid recovered one-erasure record")
        sizes = [size if i == missing else len(self.packets[i].original) for i in range(self.geometry.n)]
        if _widths(sizes) != (self.total, widths):
            raise ValueError("noncanonical recovered helper widths")
        self.scaled_bytes += work
        self.originals[missing] = body[:size]
        return {missing: body[:size]}
