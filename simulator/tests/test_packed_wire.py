"""Finite framing, credit, correlation and physical-service checks."""

from copy import deepcopy
from heapq import heappop
from itertools import count

import pytest

from l2tunnel_sim.aligned_records import CHANNEL_HEADER, FRAGMENT_HEADER
from l2tunnel_sim.compact import tcp_profile_frame
from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport, decode_packet
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.packed_wire import (
    PackedAlignedReceiver, PackedWireTransport, packed_units,
)


def make_transport(reverse=False, **options):
    simulation = Simulation(
        Scenario(70, 0), Traffic(duration_s=1, drain_s=2),
        (PathConfig(100, 10),), Strategy("packed source fixture", mode="tcp"), 42)
    fields = dict(repair_ratio=0, feedback_ms=1, tail_repair_delay_ms=10000,
                  elide_payload_length=True, packed_predictive_records=True,
                  independent_short_frame_bytes=128, encapsulation="raw_ipv4_crc32",
                  short_source_max_bytes=128, short_source_copies=3,
                  short_source_copy_scope="context_and_independent",
                  pack_sources_max_delay_ms=.5)
    fields.update(options)
    transport = PackedWireTransport(simulation, reverse, CompactWireConfig(**fields))
    return simulation, transport


def run_until(simulation, until):
    while simulation.events and simulation.events[0][0] <= until:
        simulation.now, _, callback, arguments = heappop(simulation.events)
        callback(*arguments)
    simulation.now = until


def submit(transport, frame, received, channel=0):
    transport.submit_channel(channel, len(frame), max(0, len(frame) - 66), received.append,
                             frame=frame, deliver_frame=True)


def unit(serial, frame, channel=0):
    return CHANNEL_HEADER.pack(channel, serial & 65535) + b"\x02" + len(frame).to_bytes(2, "big") + frame


def container(units, padded=True):
    value = bytes([255, len(units)]) + b"".join(len(item).to_bytes(2, "big") + item for item in units)
    return value + bytes(1460 - len(value)) if padded else value


@pytest.mark.parametrize("invalid", [-1, True, False, None, "0.5", float("inf"), float("nan"), 1.01])
def test_packing_delay_rejects_invalid_values(invalid):
    with pytest.raises(ValueError, match="packing delay"):
        CompactWireConfig(pack_sources_max_delay_ms=invalid)


@pytest.mark.parametrize("scope", [None, "", "probe", "all"])
def test_copy_scope_is_explicit(scope):
    with pytest.raises(ValueError, match="copy scope"):
        CompactWireConfig(short_source_copy_scope=scope)


def test_packed_transport_requires_opt_in_and_reserves_channel255():
    with pytest.raises(ValueError, match="positive packing delay"):
        make_transport(pack_sources_max_delay_ms=0)
    _, transport = make_transport()
    frame = tcp_profile_frame(payload_bytes=0)
    for channel in (255, 256, -1, True, "0"):
        with pytest.raises(ValueError, match="reserved channel 255"):
            submit(transport, frame, [], channel)
    assert not transport._pack and not transport.sources and not transport.callbacks


@pytest.mark.parametrize("scope,expected", [("all_short", [3, 3, 3, 3]),
                                             ("context_and_independent", [3, 3, 1, 1])])
def test_scope_classifies_original_encoded_unit(scope, expected):
    simulation, packed = make_transport(short_source_copy_scope=scope)
    transport = CompactWireTransport(simulation, False, packed.config)
    frame = tcp_profile_frame(payload_bytes=0)
    context = CHANNEL_HEADER.pack(0, 0) + b"\x00\x00\x42" + frame
    full = unit(1, frame)
    delta = CHANNEL_HEADER.pack(0, 2) + b"\x03\x00\x40\x00" + bytes(64)
    fragment = CHANNEL_HEADER.pack(0, 3) + FRAGMENT_HEADER.pack(4, 1500, 1452) + bytes(48)
    assert [transport._source_copy_count(item) for item in (context, full, delta, fragment)] == expected


@pytest.mark.parametrize("reverse", [False, True])
def test_bounded_hold_source_accounting_and_independent_physical_copies(reverse):
    simulation, transport = make_transport(reverse)
    frame = tcp_profile_frame(payload_bytes=0)
    received = []
    submit(transport, frame, received, 0)
    assert transport.pending_pack_bytes == transport.buffer_bytes == transport.submitted_bytes == 72
    assert len(transport.sources) == 0
    run_until(simulation, .0003)
    submit(transport, frame, received, 1)
    assert transport.pending_pack_bytes == transport.buffer_bytes == transport.submitted_bytes == 150
    run_until(simulation, .000499)
    assert len(transport.sources) == 0
    run_until(simulation, .0005)
    assert len(transport.sources) == 1 and transport.sources[0].size == 150
    assert transport.pending_pack_bytes == transport.buffer_bytes == 0
    assert transport.sent_bytes == transport.submitted_bytes == 150
    assert transport.packed_sources == 1 and transport.packed_units == 2
    assert transport.packed_header_bytes == 6
    assert transport.wire_repeated_source_packets == 2
    assert transport.last_source_at == pytest.approx(.0005 + 3 * 176 / simulation.links[reverse][0].bytes_per_s)
    run_until(simulation, .2)
    assert received == [frame, frame]
    assert simulation.datagrams[reverse]["source"] == 3
    assert simulation.wire[reverse]["source"] == 3 * 176
    assert transport.base == 1 and not transport._source_record_ends
    assert transport.channel_acknowledged == {0: 1, 1: 1}
    assert transport.packed_wait_max_ms == .5
    assert not transport.receiver.seen


def test_lost_container_correlates_all_records_but_copies_have_separate_erasures():
    simulation, transport = make_transport()
    erased = iter([True, True, False])
    simulation.links[False][0].erasures.lost = lambda: next(erased, False)
    frames = [tcp_profile_frame(payload_bytes=0, identification=i) for i in range(3)]
    received = []
    for channel, frame in enumerate(frames):
        submit(transport, frame, received, channel)
    run_until(simulation, .2)
    assert received == frames
    assert len(transport.sources) == 1
    assert simulation.erasures[False]["source"] == 2
    assert simulation.datagrams[False]["source"] == 3
    assert transport.wire_repeated_source_packets == 2
    assert transport.wire_protected_sources == 1


def test_complete_container_loss_recovers_all_units_with_one_charged_equation():
    simulation, transport = make_transport(short_source_copies=1)
    departures = count()
    simulation.links[False][0].erasures.lost = lambda: next(departures) == 0
    frames = [tcp_profile_frame(payload_bytes=0, identification=i) for i in range(2)]
    received = []
    for channel, frame in enumerate(frames):
        submit(transport, frame, received, channel)
    run_until(simulation, .1)
    assert received == [] and transport.base == 0
    transport._repair(True)
    run_until(simulation, .3)
    assert received == frames and transport.base == 1
    assert transport.recovered_symbols == 1
    assert simulation.wire[False]["repair"] > 0
    assert not transport.callbacks


def test_policy_change_seals_and_compressed_small_payload_is_single_copy():
    simulation, transport = make_transport()
    received = []
    first = tcp_profile_frame(payload_bytes=64)
    second = tcp_profile_frame(payload_bytes=64, sequence=64, identification=1, timestamp=18)
    submit(transport, first, received)
    assert transport.sources[0].size == 72
    assert transport.wire_repeated_source_packets == 2
    assert transport.pending_pack_bytes == 69
    submit(transport, second, received)
    run_until(simulation, .2)
    assert received == [first, second]
    assert len(transport.sources) == 2
    assert transport._source_copy_count(transport.source_payloads[1][:transport.sources[1].size]) == 1
    assert transport.wire_repeated_source_packets == 2
    assert simulation.datagrams[False]["source"] == 4
    assert transport.packed_flush_reasons["copy_policy"] == 1


def test_container_parser_prevalidates_every_unit_before_receiver_mutation():
    frame = tcp_profile_frame(payload_bytes=0)
    first, second = unit(0, frame, 0), unit(0, frame, 1)
    valid = bytearray(container([first, second]))
    cases = []
    bad = bytearray(valid)
    bad[1] = 1
    cases.append(bad)
    bad = bytearray(valid)
    bad[2:4] = b"\xff\xff"
    cases.append(bad)
    bad = bytearray(valid)
    bad[4 + len(first) + 2] = 255
    cases.append(bad)
    bad = bytearray(valid)
    bad[4 + len(first) + 2 + 3] = 9
    cases.append(bad)
    bad = bytearray(valid)
    bad[-1] = 1
    cases.append(bad)
    receiver = PackedAlignedReceiver(1460, 128)
    for bad in cases:
        state = deepcopy(receiver.__dict__)
        with pytest.raises(ValueError):
            receiver.receive(7, bytes(bad))
        assert receiver.__dict__ == state


def test_receiver_synthetic_ids_duplicate_suppression_retirement_and_early_release():
    receiver = PackedAlignedReceiver(1460, 128)
    frame = tcp_profile_frame(payload_bytes=0)
    value = container([unit(1, frame, 0), unit(0, frame, 1)])
    assert receiver.receive(2, value) == [(0, 1, frame), (1, 0, frame)]
    assert receiver.expected[0] == 0 and receiver.expected[1] == 1
    assert receiver.early_delivered == {(0, 1)}
    assert receiver.seen == {512, 513}
    assert receiver.receive(2, value) == []
    plain = unit(0, frame) + bytes(1460 - len(unit(0, frame)))
    assert receiver.receive(1, plain) == [(0, 0, frame)]
    assert receiver.expected[0] == 2 and not receiver.early_delivered
    receiver.discard_before(2)
    assert receiver.seen == {512, 513}
    receiver.discard_before(3)
    assert not receiver.seen


def test_later_context_dependent_error_rolls_back_earlier_unit_state():
    receiver = PackedAlignedReceiver(1460, 128)
    frame = tcp_profile_frame(payload_bytes=0)
    first = unit(0, frame, 0)
    missing_context = CHANNEL_HEADER.pack(1, 0) + b"\x06\x00"
    before = deepcopy(receiver.__dict__)
    with pytest.raises(ValueError, match="missing aligned payload-length context"):
        receiver.receive(0, container([first, missing_context]))
    assert receiver.__dict__ == before
    assert receiver.receive(0, container([first, unit(0, frame, 1)])) == [(0, 0, frame), (1, 0, frame)]


def test_large_plain_source_preserves_actual_wire_format_and_does_not_wait():
    simulation, transport = make_transport(short_source_copies=1)
    received = []
    sent = []
    send = transport._send_wire

    def capture(wire, kind, header_bytes):
        sent.append((wire, kind))
        return send(wire, kind, header_bytes)

    transport._send_wire = capture
    frame = tcp_profile_frame(payload_bytes=1448)
    submit(transport, frame, received)
    assert len(transport.sources) == 2 and transport.pending_pack_bytes == 0
    assert transport.source_payloads[1][0] == 0
    assert decode_packet(sent[1][0], 0, "raw_ipv4_crc32").payload == transport.source_payloads[1][:transport.sources[1].size]
    assert simulation.now == 0 and transport.packed_sources == 0
    run_until(simulation, .2)
    assert received == [frame]


def test_sender_channel_credit_waits_for_actual_delayed_feedback():
    simulation, transport = make_transport()
    transport.channel_sequences[0] = 32765
    transport.channel_acknowledged[0] = 0
    transport.channel_completed[0] = 32765
    transport.receiver.expected[0] = 32765
    frame = tcp_profile_frame(payload_bytes=0)
    received = []
    assert transport.can_submit_channel(0)
    submit(transport, frame, received)
    assert not transport.can_submit_channel(0)
    run_until(simulation, .05)
    assert received == [frame]
    assert transport.channel_completed[0] == 32766
    assert transport.channel_acknowledged[0] == 0 and not transport.can_submit_channel(0)
    run_until(simulation, .1)
    assert transport.channel_acknowledged[0] == 32766 and transport.can_submit_channel(0)


def test_context_and_fragment_credit_retire_at_their_real_last_source():
    simulation, transport = make_transport(short_source_copies=1)
    frame = bytes(range(256)) * 16
    received = []
    submit(transport, frame, received)
    assert len(transport.sources) == 3
    assert transport._source_record_ends == {0: {}, 1: {}, 2: {0: 1}}
    transport._receive_feedback(1, 0)
    assert transport.channel_acknowledged[0] == 0
    transport._receive_feedback(2, 0)
    assert transport.channel_acknowledged[0] == 0
    transport._receive_feedback(3, 0)
    assert transport.channel_acknowledged[0] == 1
    # Direct feedback calls above inspect sender accounting only, with no
    # receiver credit or delivery inferred from those synthetic observations.
    assert received == []


def test_packed_record_serial_wrap_preserves_absolute_feedback_credit():
    simulation, transport = make_transport()
    transport.channel_sequences[0] = 65535
    transport.channel_acknowledged[0] = 65535
    transport.channel_completed[0] = 65535
    transport.receiver.expected[0] = 65535
    frames = [tcp_profile_frame(payload_bytes=0, identification=i) for i in range(2)]
    received = []
    for frame in frames:
        submit(transport, frame, received)
    run_until(simulation, .2)
    assert received == frames
    assert transport.channel_sequences[0] == transport.channel_completed[0] == 65537
    assert transport.channel_acknowledged[0] == 65537
    assert transport.base == 1


def test_pending_container_is_in_buffer_accounting_and_explicit_flush_is_idempotent():
    simulation, transport = make_transport()
    frame = tcp_profile_frame(payload_bytes=0)
    submit(transport, frame, [])
    assert transport.buffer_bytes == transport.pending_pack_bytes == 72
    transport.flush()
    assert transport.buffer_bytes == transport.pending_pack_bytes == 0
    assert len(transport.sources) == 1
    run_until(simulation, .001)
    assert len(transport.sources) == 1
    assert transport.packed_flush_reasons == {"explicit": 1}


def test_full_container_capacity_and_count_are_charged_exactly():
    simulation, transport = make_transport(short_source_copies=1)
    frame = tcp_profile_frame(payload_bytes=0)
    received = []
    for index in range(25):
        submit(transport, frame, received, index % 16)
    transport.flush()
    assert [source.size for source in transport.sources] == [1408, 446]
    assert [len(packed_units(transport.source_payloads[i])) for i in range(2)] == [19, 6]
    assert transport.submitted_bytes == transport.sent_bytes == 25 * 72 + 2 * 2 + 25 * 2
    run_until(simulation, .2)
    assert len(received) == 25 and transport.base == 2
    assert simulation.wire[False]["source"] == 2 * 26 + transport.sent_bytes
    assert transport.channel_header_bytes == 25 * 3


def test_capacity_notification_defers_reentrant_submission_until_serial_is_committed():
    simulation, transport = make_transport(short_source_copies=1)
    frames = [tcp_profile_frame(payload_bytes=1448, sequence=i * 1448, identification=i) for i in range(2)]
    received = []
    submitted = []

    def capacity():
        if not submitted:
            submitted.append(True)
            submit(transport, frames[1], received)

    transport.capacity_callback = capacity
    submit(transport, frames[0], received)
    assert transport.channel_sequences[0] == 2 and not submitted
    run_until(simulation, .2)
    assert received == frames and transport.channel_sequences[0] == 3
