from itertools import combinations

import pytest

from l2tunnel_sim.striped_cauchy import (
    Geometry, Receiver, decode_datagram, encode_datagram, encode_group,
    encode_packets, group_max_wire, inspect_packet, reconstruct_split, shortened,
)


def test_shared_three_plus_two_vector_with_nonuniform_zero_ended_originals():
    geometry = Geometry(3, 2)
    raw = list(map(bytes.fromhex, ("0b", "0700c8", "5a51", "ff01020304", "70040810")))
    rows = encode_group(raw, geometry)
    assert [p.hex() for p in rows] == [
        "00010b0000000000008ef4b942c9c8", "00030700c80000000002075da7dd6c",
        "00025a51000000000000f7dba61754", "0005ff0102030400000090f200011c",
        "000470040810000000a201f600ddcb",
    ]
    assert [encode_datagram(128, i, p, geometry, 1451).hex() for i, p in enumerate(rows)] == [
        "80010000010b8ef4b942c9c8", "80010100030700c802075da7dd6c", "80010200025a5100f7dba61754",
        "8001030005ff010203040090f200011c", "800104000470040810a201f600ddcb",
    ]


@pytest.mark.parametrize("k,m", [(1, 1), (4, 1), (4, 2), (8, 2)])
def test_any_k_distinct_datagrams_restore_all_original_bytes(k, m):
    geometry = Geometry(k, m)
    originals = [bytes([j, 0, 0]) * (j+1) for j in range(geometry.n)]
    bodies = encode_group(originals, geometry)
    packets = [encode_datagram(127 + geometry.n, j, p, geometry, 1451) for j, p in enumerate(bodies)]
    for kept in combinations(range(geometry.n), k):
        receiver = Receiver(geometry)
        for j in reversed(kept):
            generation, slot, body = decode_datagram(packets[j], geometry, 1451)
            assert generation == 127 + geometry.n and slot == j and body == bodies[j]
            assert receiver.add(slot, body) == originals[j]
            assert receiver.add(slot, body) is None
        assert receiver.elimination_stripes == receiver.scaled_bytes == 0
        recovered = receiver.recover_missing()
        assert recovered == {j: p for j, p in enumerate(originals) if j not in kept}
        assert receiver.recover_missing() == {}
        assert receiver.originals == dict(enumerate(originals))
        for j in recovered:
            assert receiver.add(j, bodies[j]) is None


def test_no_loss_fast_path_and_incomplete_group_keep_old_hole_until_retransmission():
    geometry = Geometry(4, 1)
    originals = [bytes([j+4]) * (j*7+3) for j in range(5)]
    bodies = encode_group(originals, geometry)
    receiver = Receiver(geometry)
    for j in (0, 2, 4):
        assert receiver.add(j, bodies[j]) == originals[j]
    assert receiver.recover_missing() == {}
    assert set(receiver.originals) == {0, 2, 4}
    assert receiver.add(3, bodies[3]) == originals[3]
    assert receiver.recover_missing() == {1: originals[1]}
    clean = Receiver(geometry)
    for j, body in enumerate(bodies):
        assert clean.add(j, body) == originals[j]
    assert clean.recover_missing() == {}
    assert clean.elimination_stripes == clean.scaled_bytes == 0
    with pytest.raises(ValueError, match="incomplete"):
        encode_group(originals[:-1], geometry)


def test_compact_physical_extent_and_stable_cyclic_layout():
    geometry = Geometry(4, 1)
    originals = [bytes([j, 0]) * (j+1) for j in range(5)]
    bodies = encode_group(originals, geometry)
    width = 3
    assert {len(body) for body in bodies} == {geometry.n*width}
    for j, body in enumerate(bodies):
        packet = encode_datagram(128, j, body, geometry, 1451)
        assert len(packet) + 49 == 49 + 2 + 1 + 2 + len(originals[j]) + width
        with pytest.raises(ValueError, match="budget"):
            encode_datagram(128, j, body, geometry, len(packet)-1)
    assert bodies[0][:12] == bytes.fromhex("000200000000000000000000")
    with pytest.raises(ValueError, match="header"):
        decode_datagram(b"\x80\x00" + bytes(12), geometry, 1451)
    with pytest.raises(ValueError, match="dimensions"):
        decode_datagram(b"\x00\x05\x00\x01zz", geometry, 1451)
    receiver = Receiver(geometry)
    receiver.add(0, bodies[0])
    with pytest.raises(ValueError, match="conflicting"):
        receiver.add(0, bodies[0][:-1] + bytes([bodies[0][-1] ^ 1]))


@pytest.mark.parametrize("count", range(1, 11))
def test_compact_shortened_groups_survive_every_guaranteed_physical_erasure(count):
    full = Geometry(8, 2)
    raw = [bytes([0, i, 0]) * (i+2) for i in range(count)]
    wires = encode_packets(1024, raw, full, 1451)
    g = shortened(full, count)
    assert len(wires) == g.n and max(map(len, wires)) == group_max_wire(1024, raw, full)
    for kept in combinations(range(g.n), g.k):
        rx = Receiver(g)
        for slot in kept:
            base, actual, single, ordinal, body = inspect_packet(wires[slot], full, 1451)
            assert base == 1024 and actual == g and ordinal == slot
            assert single == (len(raw[0]) if count == 1 else None)
            got = rx.add(slot, body)
            if count > 1:
                assert got == raw[slot]
        rx.recover_missing()
        if count == 1:
            assert rx.originals[0] + rx.originals[1] == raw[0]
        else:
            assert rx.originals == dict(enumerate(raw))


def test_single_byte_is_an_explicit_single_record_and_split_halves_fit_mtu():
    full = Geometry(4, 1)
    wires = encode_packets(12, [b"\x80"], full, 1451)
    assert len(wires) == 2
    for w in wires:
        base, g, single, _, body = inspect_packet(w, full, 1451)
        assert base == 12 and g == Geometry(1, 1) and single == 1 and g.own(body) == b"\x80"
    oversized = [b"a" * 1146, b"b" * 1146]
    assert group_max_wire(12, oversized, full) > 1451
    for i, record in enumerate(oversized):
        assert all(len(w)+49 <= 1500 for w in encode_packets(12+i, [record], full, 1451))


@pytest.mark.parametrize("original", [b"x", b"ab", b"abc", b"trailing\x00"])
def test_first_split_packet_recovers_both_halves_without_elimination_in_either_order(original):
    geometry = Geometry(4, 1)
    for wire in encode_packets(42, [original], geometry, 1451):
        _, _, single, ordinal, body = inspect_packet(wire, geometry, 1451)
        assert reconstruct_split(body, ordinal, single) == original
        # The length of the opposite original is protected on this datagram.
        corrupt = bytearray(body)
        corrupt[len(body)//2] = 1
        with pytest.raises(ValueError, match="length or padding"):
            reconstruct_split(corrupt, ordinal, single)
        if single == 1:
            corrupt = bytearray(body)
            corrupt[-1] ^= 1
            with pytest.raises(ValueError, match="disagree"):
                reconstruct_split(corrupt, ordinal, single)
