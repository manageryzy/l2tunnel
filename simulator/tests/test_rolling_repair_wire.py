from pathlib import Path

import pytest

from l2tunnel_sim.rolling_repair_wire import decode_repair, encode_repair


def test_shared_rust_python_rolling_repair_vectors():
    fixture = Path(__file__).parent / "fixtures/rolling_confirmed_prefix.txt"
    for line in fixture.read_text().splitlines():
        if line.startswith("#"):
            continue
        identity, end, start, tail, rhs, wire = line.split()
        row = (int(identity), int(end), int(start), bool(int(tail)), bytes.fromhex(rhs))
        wire = bytes.fromhex(wire)
        assert encode_repair(*row, confirmed_prefix=True) == wire
        assert decode_repair(wire, confirmed_prefix=True) == row
        if wire[0] in (7, 8):
            with pytest.raises(ValueError):
                decode_repair(wire, confirmed_prefix=False)
        else:
            assert encode_repair(*row, confirmed_prefix=False) == wire


@pytest.mark.parametrize("wire", ["091003010001a5", "071003000001a5", "071003030001a5",
                                   "071103010001a5", "07100381000001a5", "0710030180"])
def test_rejects_invalid_rolling_repair(wire):
    with pytest.raises(ValueError):
        decode_repair(bytes.fromhex(wire), confirmed_prefix=True)
