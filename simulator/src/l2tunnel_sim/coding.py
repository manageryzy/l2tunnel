"""GF(256) rank and recovery model. Equations carry coefficients only."""

from functools import lru_cache


def _multiply(left, right):
    product = 0
    while right:
        if right & 1:
            product ^= left
        left <<= 1
        if left & 0x100:
            left ^= 0x11D
        right >>= 1
    return product


PRODUCT = tuple(bytes(_multiply(i, j) for j in range(256)) for i in range(256))
INVERSE = (0, *(PRODUCT[i].index(1) for i in range(1, 256)))


@lru_cache(maxsize=256)
def block_coefficients(sources, repair_index):
    """Systematic Cauchy code with the MDS property for up to 256 symbols."""
    return tuple(INVERSE[column ^ (sources + repair_index)] for column in range(sources))


def _eliminate(target, row, factor):
    products = PRODUCT[factor]
    for symbol, coefficient in row.items():
        value = target.get(symbol, 0) ^ products[coefficient]
        if value:
            target[symbol] = value
        else:
            target.pop(symbol, None)


class Decoder:
    def __init__(self):
        self.known = set()
        self.rows = {}

    def insert(self, coefficients):
        """Return newly identifiable source IDs after adding one equation."""
        row = {symbol: coefficient for symbol, coefficient in coefficients.items()
               if coefficient and symbol not in self.known}
        # Existing rows have zeros in every other pivot column.
        for pivot in tuple(row):
            if pivot in self.rows:
                _eliminate(row, self.rows[pivot], row[pivot])
        if not row:
            return []
        pivot = min(row)
        scale = PRODUCT[INVERSE[row[pivot]]]
        row = {symbol: scale[coefficient] for symbol, coefficient in row.items()}
        solved = []
        for other, other_row in self.rows.items():
            if pivot in other_row:
                _eliminate(other_row, row, other_row[pivot])
                if len(other_row) == 1:
                    solved.append(other)
        self.rows[pivot] = row
        if len(row) == 1:
            solved.append(pivot)
        for symbol in solved:
            del self.rows[symbol]
            self.known.add(symbol)
        return sorted(solved)
