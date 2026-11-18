"""Ordinary PackedWire channel order, independent of global source retirement."""

import pytest

from l2tunnel_sim.aligned_records import CHANNEL_HEADER, FRAGMENT_HEADER, FRAGMENT_KIND
from l2tunnel_sim.compact import tcp_profile_frame
from l2tunnel_sim.compact_wire import decode_packet
from l2tunnel_sim.packed_wire import PACKED_CHANNEL, packed_units
from test_packed_wire import make_transport, run_until, submit


@pytest.fixture(params=["historical", "targeted"])
def captured(request):
    # Leave feedback on the existing asynchronous reverse link. Collect
    # real encoded source datagrams so the test controls forward loss/order.
    sim, transport = make_transport(short_source_copies=1)
    if request.param == "targeted":
        from l2tunnel_sim.packed_targeted import TargetedPackedWireTransport

        transport = TargetedPackedWireTransport(sim, False, transport.config)
    wires = {}

    def capture(wire, kind, header_bytes):
        packet = decode_packet(wire, transport.received_prefix, transport.config.encapsulation)
        if packet.kind == "source":
            wires[packet.index] = wire
        return sim.now, .07

    transport._send_wire = capture
    return sim, transport, wires


def ordinary_frame(size, marker):
    # Unsupported EtherType retains every nonzero payload byte in a full record.
    header = bytes.fromhex("02000000000202000000000188b5")
    return header + bytes((marker + i) % 256 for i in range(size - len(header)))


def test_packed_tcp_context_reorders_within_channel_and_crosses_global_gap(captured):
    sim, t, wires = captured
    seen = []
    a = ordinary_frame(900, 17)
    submit(t, a, seen, channel=0)
    first = tcp_profile_frame(sequence=999, identification=65535, payload_bytes=512)
    second = tcp_profile_frame(sequence=1511, identification=0, payload_bytes=512)
    # Channel records wrap independently of wire source IDs, including a
    # context-only record followed by its data record in the same container.
    for mapping in (t.channel_sequences, t.channel_acknowledged, t.channel_completed, t.receiver.expected):
        mapping[1] = 65535
    submit(t, first, seen, channel=1)
    t.flush()
    submit(t, second, seen, channel=1)
    t.flush()
    assert set(wires) == {0, 1, 2}
    src = decode_packet(wires[1], 0, t.config.encapsulation).payload
    assert src[0] == PACKED_CHANNEL
    assert [CHANNEL_HEADER.unpack_from(unit) for unit in packed_units(src)] == [(1, 65535), (1, 0)]
    assert t.packed_predictive_records == 1 and t.independent_short_records == 0

    t._receive_wire(wires[2])
    assert not seen and not t.received_prefix
    t._receive_wire(wires[1])
    t._receive_wire(wires[2])
    assert seen == [first, second]
    assert t.received_prefix == t.base == 0
    assert t.channel_completed[1] == 65538 and t.channel_acknowledged[1] == 65535
    assert len(t.callbacks) == 1
    t._receive_wire(wires[0])
    t._receive_wire(wires[1])
    assert seen == [first, second, a]
    assert t.received_prefix == 3 and t.base == 0
    run_until(sim, .1)
    assert t.base == 3 and t.channel_acknowledged[1] == 65538
    assert not t.callbacks and not t.receiver.seen


def test_reordered_fragments_across_missing_source_complete_exactly_once(captured):
    sim, t, wires = captured
    seen = []
    a, b = ordinary_frame(900, 41), ordinary_frame(3100, 63)
    submit(t, a, seen, channel=0)
    submit(t, b, seen, channel=1)
    t.flush()
    assert set(wires) == {0, 1, 2, 3}
    for index in (1, 2, 3):
        data = decode_packet(wires[index], 0, t.config.encapsulation).payload
        assert CHANNEL_HEADER.unpack_from(data) == (1, 0)
        assert FRAGMENT_HEADER.unpack_from(data, CHANNEL_HEADER.size)[0] == FRAGMENT_KIND
    for index in (3, 2, 3):
        t._receive_wire(wires[index])
    assert not seen and len(t.receiver.fragments) == 1
    t._receive_wire(wires[1])
    t._receive_wire(wires[3])
    assert seen == [b] and not t.receiver.fragments
    assert not t.received_prefix and not t.base and not t.channel_acknowledged[1]
    t._receive_wire(wires[0])
    assert seen == [b, a] and t.received_prefix == 4
    run_until(sim, .1)
    assert t.base == 4 and t.channel_acknowledged[1] == 1
    assert not t.callbacks and not t.receiver.seen


def test_rank_solved_ordinary_source_releases_before_older_hole(captured):
    from l2tunnel_sim.compact import coefficient

    _, t, wires = captured
    seen = []
    a, b = ordinary_frame(900, 29), ordinary_frame(980, 73)
    submit(t, a, seen, channel=0)
    submit(t, b, seen, channel=1)
    assert set(wires) == {0, 1}
    # Select a real regular-repair serial whose equation has only B as
    # its unknown. Neither original has been submitted to the receiver.
    def only_b(serial):
        seed = (serial * 2654435761) & 0xFFFFFFFF
        return not coefficient(seed, 0) and coefficient(seed, 1)

    serial = next(serial for serial in range(1, 32768) if only_b(serial))
    t.repair_serial = serial - 1
    repair_wires = []

    def capture_repair(wire, kind, header_bytes):
        assert kind == "repair"
        repair_wires.append(wire)
        return t.sim.now, .07

    t._send_wire = capture_repair
    t._repair(False)
    [wire] = repair_wires
    t._receive_wire(wire)
    assert seen == [b] and t.received_prefix == t.base == 0
    assert 1 in t.decoder.known and 1 not in t.received_source
    t._receive_wire(wire)
    t._receive_wire(wires[1])
    t._receive_wire(wires[0])
    assert seen == [b, a] and t.received_prefix == 2
