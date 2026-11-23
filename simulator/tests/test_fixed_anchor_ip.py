"""Real Packed sources, named native-IP contexts and independently delivered TCP segments."""

from hashlib import sha256

import pytest

from l2tunnel_sim.compact import _checksum, tcp_profile_frame
from l2tunnel_sim.fixed_anchor_ip import (
    Header,
    decode_ip,
    encode_ip,
    enable_forward_fixed_anchor,
    validate_body,
)
from l2tunnel_sim.packed_wire import packed_units
from test_packed_wire import container, make_transport, run_until, submit


def frame(i, size=140):
    return tcp_profile_frame(
        sequence=1234 + i * size,
        identification=37 + i,
        timestamp=100 + i * 18,
        echoed_timestamp=15,
        payload_bytes=size,
    )


def options(capacity=512):
    return dict(
        capacity=capacity,
        elide=True,
        predictive=True,
        pairs=True,
        short=0,
        maximum=4096,
    )


def test_native_headers_exact_own_distance_and_predictive_forms():
    ip = frame(0)[14:]
    anchor, first = encode_ip(ip, None, 1, **options())
    assert len(anchor.data) == 52 and anchor.data == ip[:52]
    assert first == b"\x0b\x01\x06\0" + ip[52:]
    assert decode_ip(anchor, first, padded=False, maximum=4096) == ip
    for i in range(1, 8):
        data = frame(i)[14:]
        new, body = encode_ip(data, anchor, i + 1, **options())
        assert new is None and body[:2] == bytes((11, i + 1))
        if i == 1:
            assert body[2] == 5
        elif i > 1:
            assert body[2] == 6
        assert decode_ip(anchor, body, padded=False, maximum=4096) == data
    data = frame(3, 700)[14:]
    _, explicit = encode_ip(data, anchor, 4, **options(110))
    assert explicit[:3] == b"\x0b\x04\x09"
    assert decode_ip(anchor, explicit, padded=False, maximum=4096) == data
    for invalid in (b"\x0b\0\x09", b"\x0b\x09\x06", b"\x0b\x01\x08", b"\x0b\x01\x0b"):
        with pytest.raises(ValueError):
            validate_body(invalid, padded=False)


def wire(ch, r, body):
    return bytes((ch,)) + r.to_bytes(2, "big") + body


def pad(x):
    return x.ljust(1460, b"\0")


def receiver():
    _, t = make_transport(independent_delivery=True, independent_short_frame_bytes=0)
    enable_forward_fixed_anchor(t)
    return t.receiver


def test_missing_predecessor_exact_channel_late_anchor_and_once_only_rollback():
    rx = receiver()
    params = options()
    a, one = encode_ip(frame(0)[14:], None, 1, **params)
    _, two = encode_ip(frame(1)[14:], a, 2, **params)
    _, three = encode_ip(frame(2)[14:], a, 3, **params)
    context = b"\x08\0\x34" + a.data
    assert rx.receive(4, pad(wire(0, 3, three))) == []
    assert rx.receive(0, pad(wire(1, 0, context))) == [(1, 0, None)]
    assert rx.receive(7, pad(wire(0, 0, context))) == [(0, 3, frame(2)), (0, 0, None)]
    assert rx.expected[0] == 1 and rx.receive(4, pad(wire(0, 3, three))) == []
    assert rx.receive(12, pad(wire(0, 1, one))) == [(0, 1, frame(0))]
    old = (
        dict(rx.expected),
        dict(rx.retired),
        dict(rx.complete),
        dict(rx.early_delivered),
        set(rx.seen),
    )
    # Record four incorrectly points to an already retired data record.
    invalid = wire(0, 4, bytes((11, 3)) + three[2:])
    with pytest.raises(ValueError, match="non-context"):
        rx.receive(21, container([wire(0, 2, two), invalid]))
    assert old == (
        dict(rx.expected),
        dict(rx.retired),
        dict(rx.complete),
        dict(rx.early_delivered),
        set(rx.seen),
    )
    assert rx.receive(21, pad(wire(0, 2, two))) == [(0, 2, frame(1))]
    assert rx.expected[0] == 4 and not rx.early_delivered


def test_transport_fragments_opaque_bytes_and_cadence_through_wrap():
    sim, t = make_transport(independent_delivery=True, independent_short_frame_bytes=0)
    t.select_packing_geometry(122, 8)
    p = enable_forward_fixed_anchor(t)
    delivered = []
    records = []
    original = t._submit_record

    def capture(ch, r, b):
        records.append((r, b))
        return original(ch, r, b)

    t._submit_record = capture
    for i in range(11):
        submit(t, frame(i, 250), delivered)
    run_until(sim, 0.5)
    assert delivered == [frame(i, 250) for i in range(11)]
    assert [r for r, b in records if b[0] == 8] == [0, 8]
    assert all(b[1] == r % 8 for r, b in records if b[0] == 11)
    assert p.counts["wrapped"] == 11 and t.fragmented_records == 11
    with pytest.raises(ValueError):
        enable_forward_fixed_anchor(t)
    rx = receiver()
    rx.expected[0] = 65535
    anchor, data = encode_ip(frame(0)[14:], None, 1, **options())
    assert rx.receive(1, pad(wire(0, 0, data))) == []
    assert rx.receive(0, pad(wire(0, 65535, b"\x08\0\x34" + anchor.data))) == [
        (0, 65536, frame(0)),
        (0, 65535, None),
    ]
    assert rx.expected[0] == 65537


def test_empty_history_overflow_wrong_profile_and_unsupported_raw():
    rx = receiver()
    with pytest.raises(ValueError, match="underflows"):
        rx.receive(0, pad(wire(0, 0, b"\x0b\x01\x06\0")))
    with pytest.raises(ValueError):
        rx.receive(0, pad(wire(0, 0, b"\x00\0\x42" + frame(0)[:66])))
    with pytest.raises(ValueError):
        packed_units(container([wire(0, 0, b"\x08\0\x34" + frame(0)[14:66])] * 2))
    ip = bytearray(frame(0)[14:])
    ip[10] ^= 1
    _, raw = encode_ip(bytes(ip), None, 1, **options())
    assert raw[0] == 2 and raw[3:] == ip
    assert rx.receive(2, pad(wire(0, 0, raw))) == [(0, 0, frame(0)[:14] + ip)]


def oracle_frames():
    frames = []
    for i, size in enumerate(
        [
            140,
            140,
            140,
            700,
            1,
            52,
            1448,
            1448,
            140,
            140,
            52,
            1448,
            250,
            250,
            250,
            250,
            200,
            140,
            800,
            140,
        ]
        * 2
    ):
        native = bytearray(frame(i, size)[14:])
        if i % 17 == 4:
            native[10] ^= 1
        if 17 <= i <= 28:
            tcp = bytearray(native[20:])
            if i >= 22:
                # A variable TCP header including SACK and TS options.
                tcp[32:32] = bytes.fromhex("0101050a0000000200000050")
                tcp[12] = 11 << 4
            ipv6 = (
                bytes.fromhex("60000000")
                + len(tcp).to_bytes(2, "big")
                + b"\x06\x40"
                + bytes(range(32))
            )
            tcp[16:18] = b"\0\0"
            tcp[16:18] = _checksum(
                ipv6[8:] + len(tcp).to_bytes(4, "big") + b"\0\0\0\x06" + bytes(tcp)
            )
            native = ipv6 + tcp
        frames.append(
            (
                int(i % 11 >= 8),
                bytes(range(12))
                + (b"\x08\x00" if native[0] >> 4 == 4 else b"\x86\xdd")
                + native,
            )
        )
    return frames


def oracle_tape(frames):
    return b"".join(
        bytes([channel]) + len(f[14:]).to_bytes(2, "big") + f[14:]
        for channel, f in frames
    )


def canonical_units(frames):
    _, t = make_transport(independent_delivery=True, timestamp_pair_dictionary=True)
    t.select_packing_geometry(1146, 8)
    enable_forward_fixed_anchor(t)
    units = []
    t._queue_source = units.append
    for channel, packet in frames:
        submit(t, packet, [], channel)
    return units


def test_rust_canonical_unit_golden_and_reordered_ipv4_ipv6_payload_bytes():
    frames = oracle_frames()
    units = canonical_units(frames)
    stream = b"".join(len(unit).to_bytes(2, "big") + unit for unit in units)
    # Generated by fixtures/fixed_anchor_ip_oracle.rs with the same oracle_tape.
    assert (
        sha256(stream).hexdigest()
        == "6380076896d496b2296793faea5347c40cdd9838dfe5d1e3d2d1252593022666"
    )
    _, t = make_transport(independent_delivery=True, timestamp_pair_dictionary=True)
    t.select_packing_geometry(1146, 8)
    enable_forward_fixed_anchor(t)
    emitted = []
    for odd in (1, 0):
        for index in range(odd, len(units), 2):
            emitted.extend(t.receiver.receive(index, pad(units[index])))
    for ch in (0, 1):
        issued = [packet for channel, packet in frames if channel == ch]
        restored = [
            packet
            for channel, _, packet in sorted(emitted)
            if packet is not None and channel == ch
        ]
        assert restored == issued


def test_ordinary_rolling_copy_policy_parses_packed_contexts_and_delta_units():
    sim, t = make_transport(independent_delivery=True)
    t.select_packing_geometry(1146, 8)
    enable_forward_fixed_anchor(t)
    delivered = []
    for i in range(18):
        submit(t, frame(i), delivered)
    run_until(sim, 0.5)
    assert t.packed_sources and t.wire_repeated_source_packets
    assert delivered == [frame(i) for i in range(18)]
