"""Byte parity, erasure limits and canonical control boundaries."""
from itertools import combinations
from pathlib import Path

import pytest

from l2tunnel_sim import multipath_wire as wire


def test_horizontal_shards_match_the_shared_fec_vectors():
    fixture = Path(__file__).resolve().parents[2] / "crates/l2tunnel-fec/tests/data/path-shards.tsv"
    for line in fixture.read_text().splitlines():
        if line.startswith("#"):
            continue
        n, k, raw, *expected = line.split()
        native = bytes.fromhex(raw)
        n, k = int(n), int(k)
        parts = wire.shards(native, n, k)
        assert [p.hex() for p in parts] == expected
        for survivors in combinations(range(n), k):
            received = {i: parts[i] for i in reversed(survivors)}
            assert wire.recover(n, k, len(native), received) == native
            del received[survivors[0]]
            with pytest.raises(ValueError):
                wire.recover(n, k, len(native), received)


def test_codec_rejects_invalid_shard_extents_and_ids():
    native = bytes(range(250)) * 6
    parts = wire.shards(native, 6, 5)
    got = dict(enumerate(parts[:5]))
    assert wire.recover(6, 5, len(native), got) == native
    for changed in (parts[0][:-1], b"\0", b"\x81\x00" + parts[0][2:], parts[0] + b"\0"):
        with pytest.raises(ValueError):
            wire.recover(6, 5, len(native), {**got, 0: changed})
    with pytest.raises(ValueError):
        wire.recover(6, 5, len(native), {**got, 6: parts[5]})


def test_data_migration_and_piggyback_match_rust():
    entries = ((300, 2, b"abc"), (9, 1, b"Z"))
    blocks = ((0, 0, 2, ((3, 4), (5, 7))), (2, 128, 129, ()), (255, 0, 9000, ()))
    ack = wire.encode_ack(blocks)
    assert ack.hex() == "a1030000020201010102028001810100ff00a84600"
    assert wire.decode_ack(ack) == blocks
    data = wire.encode_data(2, 129, entries)
    assert data.hex() == "0102810102ac02066162630903015a"
    combined = wire.encode_data(2, 129, entries, ack)
    assert wire.decode_packet(combined) == (2, 129, entries, ack)
    for broken in (combined[:i] for i in range(len(combined))):
        with pytest.raises(ValueError):
            wire.decode_packet(broken)
    for broken in (data + ack, combined + b"\0", bytes.fromhex("0100000100030078")):
        with pytest.raises(ValueError):
            wire.decode_packet(broken)


def test_old_logical_requests_and_physical_window_bounds():
    ids = (0, 1, 55555, wire.MAX - 1)
    assert wire.decode_request(wire.encode_request(ids)) == ids
    for blocks in ([(255, 8, 8, ())], [(2, 0, 8193, ())], [(1, 8, 7, ())],
                   [(3, 0, 0, ((0, 1),))], [(2, 0, 0, ()), (2, 0, 0, ())]):
        with pytest.raises(ValueError):
            wire.encode_ack(blocks)
    for req in (b"\xa2\0", wire.encode_request(ids) + b"\0", b"\xa2\x01\x81\x00"):
        with pytest.raises(ValueError):
            wire.decode_request(req)


def test_repair_mask_survives_path_migration_and_preserves_old_identity():
    rows = ((0, (1, 5)), (8192, (0, 2)), (wire.MAX - 1, (5,)))
    packet = wire.encode_shard_request(rows, 6)
    assert wire.decode_shard_request(packet, 6) == rows
    assert wire.encode_shard_request(rows[:2], 6).hex() == "a3020022ff3f05"
    for broken in (packet + b"\0", packet[:-1], b"\xa3\x01\x00\0", b"\xa3\x01\x00\x40"):
        with pytest.raises(ValueError):
            wire.decode_shard_request(broken, 6)
