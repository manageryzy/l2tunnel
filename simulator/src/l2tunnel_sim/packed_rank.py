"""Optional PackedWire rank backend using C-level byte translation and integer XOR."""

from .coding import INVERSE, PRODUCT
from .compact_wire import GLOBAL_WINDOW


class Row:
    """A reduced row beginning at its nonzero pivot, independent of absolute sequence size."""

    __slots__ = ("pivot", "values", "bits", "nonzero")

    def __init__(self, pivot, values):
        self.pivot = pivot
        self.values = values
        self.bits = int.from_bytes(values, "little")
        self.nonzero = len(values) - values.count(0)

    def coefficient(self, symbol):
        offset = symbol - self.pivot
        return self.values[offset] if 0 <= offset < len(self.values) else 0

    def scaled(self, factor):
        if factor == 1:
            return self.bits
        return int.from_bytes(self.values.translate(PRODUCT[factor]), "little")


def to_bytes(bits):
    return bits.to_bytes((bits.bit_length() + 7) // 8, "little")


class PackedRankDecoder:
    """Same RREF and work counts as the sparse decoder. Commit only at service completion."""

    def __init__(self):
        self.known = set()
        self.rows = {}
        self._prepared = None

    def _prepare(self, coefficients):
        entries = {i: v for i, v in coefficients.items() if v and i not in self.known}
        if not entries:
            return None, (), (0, 0, 0)
        start = min(entries)
        width = max(entries) - start + 1
        if width > 2 * GLOBAL_WINDOW:
            raise ValueError("packed repair exceeds the supported receive range")
        data = bytearray(width)
        for i, value in entries.items():
            data[i - start] = value
        bits = int.from_bytes(data, "little")
        mixes = updates = 0
        # Every retained row is zero at every other retained pivot. Eliminating
        # one pivot therefore never changes the input factor at another pivot.
        for pivot, factor in entries.items():
            existing = self.rows.get(pivot)
            if existing is not None:
                bits ^= existing.scaled(factor) << (8 * (pivot - start))
                mixes += 1
                updates += existing.nonzero
        if not bits:
            return None, (), (mixes, updates, 0)
        skipped = ((bits & -bits).bit_length() - 1) // 8
        normalized = to_bytes(bits >> (skipped * 8))
        scale = INVERSE[normalized[0]]
        if scale != 1:
            normalized = normalized.translate(PRODUCT[scale])
        row = Row(start + skipped, normalized)
        backward = [(other, factor) for other in self.rows.values()
                    if (factor := other.coefficient(row.pivot))]
        changed = len(backward) + (scale != 1)
        return row, backward, (mixes + changed, updates + changed * row.nonzero, len(self.rows))

    def preview(self, coefficients):
        self._prepared = (coefficients, self._prepare(coefficients))
        return self._prepared[1][2]

    def insert(self, coefficients):
        pending, self._prepared = self._prepared, None
        if pending is None or pending[0] != coefficients:
            row, backward, _ = self._prepare(coefficients)
        else:
            row, backward, _ = pending[1]
        if row is None:
            return []
        solved = []
        products = {}
        for other, factor in backward:
            if factor not in products:
                products[factor] = row.scaled(factor)
            value = other.bits ^ (products[factor] << (8 * (row.pivot - other.pivot)))
            updated = Row(other.pivot, to_bytes(value))
            self.rows[other.pivot] = updated
            if updated.nonzero == 1:
                solved.append(other.pivot)
        self.rows[row.pivot] = row
        if row.nonzero == 1:
            solved.append(row.pivot)
        for i in solved:
            del self.rows[i]
            self.known.add(i)
        return sorted(solved)
