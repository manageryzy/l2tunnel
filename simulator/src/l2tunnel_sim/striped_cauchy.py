"""Systematic datagrams with cyclic Cauchy parity across physical packet erasures."""
from dataclasses import dataclass
from functools import lru_cache

from .coding import INVERSE, PRODUCT, block_coefficients


@dataclass(frozen=True)
class Geometry:
    k: int
    m: int

    def __post_init__(self):
        if type(self.k) is not int or type(self.m) is not int or min(self.k, self.m) < 1 or self.n > 256:
            raise ValueError("require positive k, m with k+m <= 256")

    @property
    def n(self):
        return self.k + self.m

    def parity_bytes(self, body):
        return len(body) // self.n * self.m

    def own(self, body):
        if len(body) % self.n or not 0 < len(body) <= 65535:
            raise ValueError("invalid striped body width")
        data = body[:(len(body) // self.n) * self.k]
        size = int.from_bytes(data[:2], "big")
        if len(data) < 2 or not 0 < size <= len(data) - 2 or any(data[size+2:]):
            raise ValueError("invalid striped original length or padding")
        return bytes(data[2:size+2])


def _scaled(cell, factor):
    return int.from_bytes(cell.translate(PRODUCT[factor]), "little")


def encode_group(originals, geometry):
    """Return full n*w bodies. A partial group keeps ownership at the caller."""
    k, m, n = geometry.k, geometry.m, geometry.n
    if len(originals) != n:
        raise ValueError("incomplete striped group")
    if not all(0 < len(body) <= 65535 for body in originals):
        raise ValueError("invalid striped original")
    w = (2 + max(map(len, originals)) + k - 1) // k
    if n*w > 65535:
        raise ValueError("oversized striped body")
    rows = [bytearray((len(src).to_bytes(2, "big") + bytes(src)).ljust(n*w, b"\x00")) for src in originals]
    for stripe in range(n):
        cells = [rows[(stripe+c) % n][c*w:(c+1)*w] for c in range(k)]
        for r in range(m):
            value = 0
            for cell, factor in zip(cells, block_coefficients(k, r)):
                value ^= _scaled(cell, factor)
            start = (k+r)*w
            rows[(stripe+k+r) % n][start:start+w] = value.to_bytes(w, "little")
    return list(map(bytes, rows))


def _generation_bytes(generation):
    if type(generation) is not int or not 0 <= generation < 2**64:
        raise ValueError("invalid striped generation")
    encoded = bytearray()
    while generation >= 128:
        encoded.append(128 | (generation & 127))
        generation >>= 7
    encoded.append(generation)
    return bytes(encoded)


def encode_datagram(generation, ordinal, body, geometry, max_wire):
    """Authenticated metadata and compact original plus every parity cell; external overhead is separate."""
    if type(ordinal) is not int or not 0 <= ordinal < geometry.n:
        raise ValueError("invalid striped ordinal")
    original = geometry.own(body)
    systematic_end = len(body) // geometry.n * geometry.k
    wire = (_generation_bytes(generation) + bytes([ordinal]) + len(original).to_bytes(2, "big")
            + original + body[systematic_end:])
    if len(wire) > max_wire:
        raise ValueError("striped datagram exceeds wire budget")
    return wire


def decode_datagram(wire, geometry, max_wire):
    if not 0 < len(wire) <= max_wire:
        raise ValueError("invalid striped datagram length")
    generation = 0
    for pos, value in enumerate(wire[:10]):
        generation |= (value & 127) << (7*pos)
        if value < 128:
            pos += 1
            break
    else:
        raise ValueError("invalid striped generation")
    if _generation_bytes(generation) != wire[:pos] or len(wire) < pos + 4:
        raise ValueError("noncanonical or truncated striped header")
    ordinal = wire[pos]
    size = int.from_bytes(wire[pos+1:pos+3], "big")
    boundary = pos + 3 + size
    parity_size = len(wire) - boundary
    if ordinal >= geometry.n or not size or parity_size <= 0 or parity_size % geometry.m:
        raise ValueError("invalid striped datagram dimensions")
    w = parity_size // geometry.m
    if w * geometry.n > 65535 or size + 2 > w * geometry.k:
        raise ValueError("invalid striped data extent")
    body = wire[pos+1:boundary].ljust(w*geometry.k, b"\x00") + wire[boundary:]
    return generation, ordinal, body


def shortened(full, count):
    if not 1 <= count <= full.n:
        raise ValueError("invalid striped group size")
    if count == 1:
        return Geometry(1, 1)
    repairs = min(count - 1, (count * full.m + full.n - 1) // full.n)
    return Geometry(count - repairs, repairs)


def encode_packets(base, originals, full, max_wire):
    """Shape an actual group, including the two protected parts of a lone record."""
    g = shortened(full, len(originals))
    if len(originals) == 1:
        original = originals[0]
        if not 0 < len(original) <= 65535:
            raise ValueError("invalid single striped record")
        header = b"\x00" + _generation_bytes(len(original))
        half = (len(original)+1)//2
        pieces = [original[:half], original[half:] if len(original) > 1 else original]
    else:
        header = bytes([len(originals)-1])
        pieces = originals
    if base + len(originals) - 1 >= 2**64:
        raise ValueError("striped source identity exhausted")
    bodies = encode_group(pieces, g)
    return [header + encode_datagram(base, i, p, g, max_wire-len(header)) for i, p in enumerate(bodies)]


def group_max_wire(base, originals, full):
    """Size the most expensive actual packet before committing any group output."""
    count = len(originals)
    g = shortened(full, count)
    largest = max(map(len, originals))
    header = 1 + len(_generation_bytes(base)) + 1 + 2
    if count == 1:
        header += len(_generation_bytes(largest))
        largest = (largest+1)//2
    w = (2+largest+g.k-1)//g.k
    return header + largest + g.m*w


def inspect_packet(wire, full, max_wire):
    if not wire or len(wire) > max_wire:
        raise ValueError("invalid shaped datagram length")
    count = wire[0] + 1
    g = shortened(full, count)
    prefix = 1
    single = None
    if count == 1:
        single = 0
        for pos, octet in enumerate(wire[1:4]):
            single |= (octet & 127) << (7*pos)
            if octet < 128:
                prefix = pos+2
                break
        if not 1 <= single <= 65535 or wire[1:prefix] != _generation_bytes(single):
            raise ValueError("invalid striped single record length")
    base, ordinal, body = decode_datagram(wire[prefix:], g, max_wire-prefix)
    if base + count - 1 >= 2**64:
        raise ValueError("striped source identity exhausted")
    if single is not None:
        half = (single+1)//2
        if len(g.own(body)) != (half if ordinal == 0 or single == 1 else single-half):
            raise ValueError("invalid striped split extent")
    return base, g, single, ordinal, body


def reconstruct_split(body, ordinal, total):
    """In the 1+1 layout the parity cell is the other complete length-prefixed half."""
    if ordinal not in (0, 1) or not 0 < total <= 65535:
        raise ValueError("invalid striped split identity")
    half = (total+1)//2
    w = 2+half
    if len(body) != 2*w:
        raise ValueError("invalid striped split width")
    left, right = (body[:w], body[w:]) if ordinal == 0 else (body[w:], body[:w])
    def read(cell, size):
        if int.from_bytes(cell[:2], "big") != size or any(cell[2+size:]):
            raise ValueError("invalid striped split length or padding")
        return cell[2:2+size]
    a = read(left, half)
    b = read(right, 1 if total == 1 else total-half)
    if total == 1 and a != b:
        raise ValueError("striped one-byte copies disagree")
    return a if total == 1 else a+b


@lru_cache(maxsize=256)
def _inverse(k, missing, repairs):
    """Invert only the missing-column Cauchy minor for this stripe."""
    d = len(missing)
    rows = [[block_coefficients(k, r)[c] for c in missing] + [int(i == j) for j in range(d)]
            for i, r in enumerate(repairs)]
    for j in range(d):
        # Every leading square Cauchy minor is invertible.
        scale = PRODUCT[INVERSE[rows[j][j]]]
        rows[j] = [scale[x] for x in rows[j]]
        for i in range(d):
            if i != j:
                factors = PRODUCT[rows[i][j]]
                rows[i] = [x ^ factors[y] for x, y in zip(rows[i], rows[j])]
    return tuple(tuple(row[d:]) for row in rows)


class Receiver:
    """One bounded authenticated generation; choose when to spend work on erasures."""

    def __init__(self, geometry):
        self.geometry = geometry
        self.packets = {}
        self.originals = {}
        self.width = None
        self.elimination_stripes = 0
        self.scaled_bytes = 0

    def add(self, ordinal, body):
        if type(ordinal) is not int or not 0 <= ordinal < self.geometry.n:
            raise ValueError("invalid striped ordinal")
        original = self.geometry.own(body)
        if self.width is not None and self.width != len(body):
            raise ValueError("inconsistent striped group width")
        if ordinal in self.packets:
            if self.packets[ordinal] != body:
                raise ValueError("conflicting striped datagram")
            return None
        if ordinal in self.originals and self.originals[ordinal] != original:
            raise ValueError("conflicting striped original")
        self.width = len(body)
        self.packets[ordinal] = bytes(body)
        if ordinal in self.originals:
            return None
        self.originals[ordinal] = original
        return original

    def recover_missing(self):
        k, n = self.geometry.k, self.geometry.n
        if len(self.packets) < k or len(self.originals) == n:
            return {}
        w = self.width // n
        outputs = {p: bytearray(k*w) for p in range(n) if p not in self.packets}
        for stripe in range(n):
            missing = tuple(c for c in range(k) if (stripe+c) % n in outputs)
            if not missing:
                continue
            repairs = tuple(r for r in range(self.geometry.m) if (stripe+k+r) % n in self.packets)[:len(missing)]
            rhs = []
            for r in repairs:
                raw = self.packets[(stripe+k+r) % n]
                value = int.from_bytes(raw[(k+r)*w:(k+r+1)*w], "little")
                factors = block_coefficients(k, r)
                for c in range(k):
                    source = self.packets.get((stripe+c) % n)
                    if source is not None:
                        value ^= _scaled(source[c*w:(c+1)*w], factors[c])
                        self.scaled_bytes += w
                rhs.append(value.to_bytes(w, "little"))
            for c, inverse_row in zip(missing, _inverse(k, missing, repairs)):
                value = 0
                for cell, factor in zip(rhs, inverse_row):
                    value ^= _scaled(cell, factor)
                    self.scaled_bytes += w
                outputs[(stripe+c) % n][c*w:(c+1)*w] = value.to_bytes(w, "little")
            self.elimination_stripes += 1
        originals = {}
        for ordinal, data in outputs.items():
            size = int.from_bytes(data[:2], "big")
            if not 0 < size <= len(data) - 2 or any(data[2+size:]):
                raise ValueError("invalid reconstructed original length or padding")
            originals[ordinal] = bytes(data[2:2+size])
        self.originals.update(originals)
        return originals
