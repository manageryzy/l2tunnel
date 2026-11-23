"""Six mixed datagrams for three already-due Packed sources in the short-group study."""
from dataclasses import dataclass
from struct import Struct

from .striped_cauchy import _generation_bytes


# Zero followed by a zero logical length is invalid in the ordinary split grammar.
TAG = b"\x00\x00"
HEADER = Struct("!B3H")


def _part(source, source_index, slot, width):
    # The four slots outside this source's pair cover its four disjoint shards.
    piece = slot if slot < 2*source_index else slot-2
    return int.from_bytes(source[piece*width:(piece+1)*width], "little")


def encode(base, sources, max_wire):
    """Return None if the complete cohort cannot fit at its original seal time."""
    if not 0 <= base <= 2**64-3 or len(sources) != 3:
        raise ValueError("invalid three-source cohort")
    sizes = tuple(map(len, sources))
    if not all(0 < n <= 65535 for n in sizes):
        raise ValueError("invalid split-repair source length")
    prefix = TAG + _generation_bytes(base)
    width = (max(sizes)+3)//4
    if len(prefix)+HEADER.size+max(sizes)+width > max_wire:
        return None
    wires = []
    for slot in range(6):
        own = slot//2
        check = 0
        for target, source in enumerate(sources):
            if target != own:
                check ^= _part(source,target,slot,width)
        wires.append(prefix + HEADER.pack(slot,*sizes) + sources[own] + check.to_bytes(width,"little"))
    return wires


@dataclass(frozen=True)
class Member:
    base: int
    slot: int
    sizes: tuple
    source: bytes
    parity: bytes


def inspect(wire, max_wire):
    if len(wire) > max_wire or not wire.startswith(TAG):
        raise ValueError("invalid split-repair datagram")
    base = 0
    for i, byte in enumerate(wire[len(TAG):len(TAG)+10]):
        base |= (byte & 127) << (7*i)
        if byte < 128:
            pos = len(TAG)+i+1
            break
    else:
        raise ValueError("incomplete group identity")
    if base > 2**64-3 or wire[len(TAG):pos] != _generation_bytes(base) or len(wire)-pos < HEADER.size:
        raise ValueError("invalid group identity or metadata")
    slot,*sizes = HEADER.unpack_from(wire,pos)
    pos += HEADER.size
    width = (max(sizes)+3)//4
    if slot >= 6 or min(sizes) == 0 or len(wire) != pos+sizes[slot//2]+width:
        raise ValueError("inconsistent split-repair extents")
    return Member(base,slot,tuple(sizes),wire[pos:len(wire)-width],wire[-width:])


class Receiver:
    """Accept each direct source immediately and recover a fully erased pair locally."""

    def __init__(self, first):
        self.base, self.sizes = first.base, first.sizes
        self.sources = {}
        self.parities = {}
        self.recovered = 0

    def add(self, member):
        if (member.base, member.sizes) != (self.base, self.sizes):
            raise ValueError("conflicting split-repair group")
        own = member.slot//2
        if own in self.sources and self.sources[own] != member.source:
            raise ValueError("conflicting split-repair source")
        if member.slot in self.parities and self.parities[member.slot] != member.parity:
            raise ValueError("conflicting split-repair parity")
        new = {} if own in self.sources else {own: member.source}
        self.sources[own] = member.source
        self.parities[member.slot] = member.parity
        if len(self.sources) == 2 and len(self.parities) == 4:
            missing, = set(range(3))-self.sources.keys()
            parts = []
            for slot, parity in sorted(self.parities.items()):
                other = 3 - slot//2 - missing
                part = int.from_bytes(parity,"little") ^ _part(self.sources[other], other, slot, len(parity))
                parts.append(part.to_bytes(len(parity),"little"))
            raw = b"".join(parts)
            size = self.sizes[missing]
            if any(raw[size:]):
                raise ValueError("invalid reconstructed padding")
            new[missing] = self.sources[missing] = raw[:size]
            self.recovered += 1
        return new
