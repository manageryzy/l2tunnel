"""Independent polynomial arithmetic and full-payload FEC fixtures.

Run with --check to verify existing fixtures. No simulator files are modified.
The simulator is imported read-only to compare field/coefficient semantics.
"""

from pathlib import Path
import struct
import sys


def multiply(left, right):
    """Independent carryless polynomial product and high-to-low reduction."""
    product = 0
    for bit in range(8):
        if right & (1 << bit):
            product ^= left << bit
    for bit in range(14, 7, -1):
        if product & (1 << bit):
            product ^= 0x11D << (bit - 8)
    return product


def coefficient(seed, source):
    value = (seed ^ (source * 0x9E3779B9)) & 0xFFFFFFFF
    value ^= value >> 16
    value = (value * 0x85EBCA6B) & 0xFFFFFFFF
    value ^= value >> 13
    value = (value * 0xC2B2AE35) & 0xFFFFFFFF
    return (value ^ (value >> 16)) & 255


def packet(generation, symbol, coefficients, sources):
    width = max(map(len, sources)) + 2
    coded = bytearray(width)
    for value, source in zip(coefficients, sources, strict=True):
        padded = struct.pack("!H", len(source)) + source
        padded += bytes(width - len(padded))
        for index, byte in enumerate(padded):
            coded[index] ^= multiply(value, byte)
    count = len(sources)
    header = (
        b"FE"
        + bytes([1, int(symbol >= count), 1, 0])
        + struct.pack("!H", count)
        + bytes(range(16))
        + struct.pack("!QIQIHHI", 7, 9, generation, symbol, width, count, 0)
    )
    return header + bytes(coefficients) + coded


def main():
    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root / "simulator" / "src"))
    from l2tunnel_sim.coding import PRODUCT, block_coefficients
    from l2tunnel_sim.compact import coefficient as simulator_coefficient

    products = bytes(multiply(a, b) for a in range(256) for b in range(256))
    assert products == b"".join(PRODUCT)
    inverses = [0] + [next(b for b in range(1, 256) if multiply(a, b) == 1) for a in range(1, 256)]
    cauchy = bytes(inverses[column ^ 5] for column in range(3))
    assert tuple(cauchy) == block_coefficients(3, 2)
    compact = bytes(coefficient(0xDEADBEEF, source) for source in range(100, 116))
    assert compact == bytes(simulator_coefficient(0xDEADBEEF, source) for source in range(100, 116))
    sources = [bytes([0, 1, 2]), bytes([254]), bytes([5, 4, 3, 2, 1])]
    fixtures = {
        "products.bin": products,
        "coefficients.bin": cauchy + compact,
        "systematic.bin": packet(11, 1, [0, 1, 0], sources),
        "repair.bin": packet(11, 3, [7, 19, 251], sources),
    }
    destination = Path(__file__).with_name("fixtures")
    checking = sys.argv[1:] == ["--check"]
    if not checking:
        destination.mkdir(exist_ok=True)
    for name, value in fixtures.items():
        path = destination / name
        if checking:
            assert path.read_bytes() == value, name
        else:
            path.write_bytes(value)
        print(f"{name}: {len(value)} bytes verified against independent arithmetic")


if __name__ == "__main__":
    main()
