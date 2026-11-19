import pytest

from l2tunnel_sim.coding import INVERSE, PRODUCT
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.packed_spare import MTU, OUTER, SpareGate, end_bytes, parse_row, row_bytes, row_seed


def test_bucket_hysteresis_backlog_and_cold_start():
    gate = SpareGate(100_000)
    for _ in range(3):
        gate.accept(7500)
        gate.close_bucket(0)
        assert not gate.enabled
    gate.accept(7501)
    gate.close_bucket(0)
    assert not gate.enabled and gate.qualifying == 0
    for _ in range(4):
        gate.accept(7500)
        gate.close_bucket(8 * MTU)
    assert gate.enabled
    gate.accept(8999)
    gate.close_bucket(0)
    assert gate.enabled
    gate.accept(9000)
    gate.close_bucket(0)
    assert not gate.enabled
    for _ in range(4):
        gate.accept(1)
        gate.close_bucket(1)
    assert gate.enabled
    gate.accept(1)
    gate.close_bucket(8 * MTU + 1)
    assert not gate.enabled
    for _ in range(4):
        gate.accept(1)
        gate.close_bucket(0)
    gate.close_bucket(0)
    assert not gate.enabled


def test_physical_byte_credit_never_spends_on_blocked_or_unfunded_row():
    g = SpareGate(12_500_000)
    g.earn_first(8*1500+4000)
    assert g.credit_eighths == 12000
    assert not g.reserve_row(1500, 0)
    for _ in range(4):
        g.accept(100)
        g.close_bucket(0)
    assert not g.reserve_row(1500, 12001)
    assert not g.reserve_row(1501, 0)
    assert g.reserve_row(1500, 12000)
    assert not g.reserve_row(1, 0)


@pytest.mark.parametrize(('end','golden'),[
    (8,'060800417c890000'), (128,'0680010014d3240000')
])
def test_exact_canonical_golden_and_each_single_erasure(end, golden):
    sources = [bytes((i+1,0)) if i%2 else bytes((0,i+1,0,0)) for i in range(8)]
    wire = row_bytes(end, sources)
    assert wire.hex() == golden
    parsed, length, data = parse_row(wire, end, 8192)
    assert parsed == end and OUTER + len(wire) == 49+1+len(end_bytes(end))+2+4
    for missing, expected in enumerate(sources):
        remaining = bytearray(length + data)
        for i, source in enumerate(sources):
            if i == missing:
                continue
            factor = coefficient(row_seed(end), end-8+i)
            for j, b in enumerate(len(source).to_bytes(2,'big') + source):
                remaining[j] ^= PRODUCT[factor][b]
        inverse = INVERSE[coefficient(row_seed(end), end-8+missing)]
        decoded = bytes(remaining).translate(PRODUCT[inverse])
        assert int.from_bytes(decoded[:2],'big') == len(expected)
        assert decoded[2:2+len(expected)] == expected and not any(decoded[2+len(expected):])


@pytest.mark.parametrize('wire', [
    b'\x06\x88\x00\x00\x00a', b'\x06\x00\x00\x00a', b'\x06\x09\x00\x00a',
    b'\x06\x08\x00\x00', b'\x06\x80\x80\x80\x80\x10\x00\x00a',
    b'\x05\x08\x00\x00a', b'\x06\x08\x00\x00'+bytes(MTU),
])
def test_reject_noncanonical_range_and_extent(wire):
    with pytest.raises(ValueError):
        parse_row(wire, 8, 8192)
