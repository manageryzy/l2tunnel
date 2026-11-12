"""Directional compact-wire service and optional ingress credit notifications."""

from heapq import heappop
from types import SimpleNamespace

import pytest

from l2tunnel_sim.compact import CompactSource, tcp_profile_frame
from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport, GLOBAL_WINDOW, SYMBOL_BYTES
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation


def make_simulation(loss=0):
    simulation = Simulation(
        Scenario(70, loss), Traffic(duration_s=.2, drain_s=3),
        (PathConfig(100, 10),), Strategy("duplex fixture", mode="tcp"), 42)
    packets = []
    send = simulation.send

    def record_send(reverse, size, kind, receive):
        finish, rtt = send(reverse, size, kind, receive)
        packets.append((simulation.now, reverse, size, kind, finish))
        return finish, rtt

    simulation.send = record_send
    return simulation, packets


def drain(simulation):
    while simulation.events:
        simulation.now, _, callback, arguments = heappop(simulation.events)
        callback(*arguments)


@pytest.mark.parametrize("encapsulation", ["udp", "raw_ipv4_crc32"])
@pytest.mark.parametrize("loss", [0, .15])
def test_both_directions_decode_frames_and_charge_sources_repairs_feedback(encapsulation, loss):
    simulation, packets = make_simulation(loss)
    config = CompactWireConfig(
        repair_ratio=.5, feedback_ms=1, tail_repair_delay_ms=15,
        encapsulation=encapsulation, elide_payload_length=True,
        short_source_max_bytes=128, short_source_copies=4)
    transports = [CompactWireTransport(simulation, reverse, config) for reverse in (False, True)]
    delivered = [[], []]
    frames = [
        tcp_profile_frame(payload_bytes=0, flags=0x02),
        tcp_profile_frame(payload_bytes=0, flags=0x12, identification=1),
        tcp_profile_frame(payload_bytes=0, flags=0x10, identification=2),
        tcp_profile_frame(payload_bytes=1448, identification=3),
        bytes(range(256)) * 8,
    ]
    for reverse, transport in enumerate(transports):
        for index, frame in enumerate(frames):
            payload_bytes = 1448 if index == 3 else 0
            transport.submit_channel(0, len(frame), payload_bytes, delivered[reverse].append,
                                     frame=frame, deliver_frame=True)
    drain(simulation)

    assert delivered == [frames, frames]
    for reverse, transport in enumerate(transports):
        assert transport.base == transport.received_prefix == len(transport.sources)
        assert not transport.callbacks and not transport.source_queue
        assert not transport.wire_invalid_packets
        assert transport.wire_protected_sources > 0
        assert transport.scheduled_repairs > 0
        copies = [4 if source.size <= 128 else 1 for source in transport.sources]
        expected_source_bytes = sum(
            copies[index] * (transport.source_header + source.size)
            for index, source in enumerate(transport.sources))
        assert simulation.wire[reverse]["source"] == expected_source_bytes
        assert simulation.datagrams[reverse]["source"] == sum(copies)
        assert transport.wire_repeated_source_packets == sum(count - 1 for count in copies)
        assert transport.wire_repeated_source_bytes == sum(
            (copies[index] - 1) * (transport.source_header + source.size)
            for index, source in enumerate(transport.sources))
        expected_repairs = (
            transport.scheduled_repairs * (transport.repair_header + SYMBOL_BYTES)
            + transport.tail_repairs * (transport.ip_header_bytes + transport.crc_bytes + 12 + SYMBOL_BYTES))
        assert simulation.wire[reverse]["repair"] == expected_repairs
        assert simulation.wire[reverse]["feedback"] > 0
        assert simulation.wire[reverse]["feedback"] == 40 * simulation.datagrams[reverse]["feedback"]
        assert set(simulation.wire[reverse]) == {"source", "repair", "feedback"}
        assert simulation.links[reverse][0].reserved_bytes == sum(simulation.wire[reverse].values())
    assert all(size <= 1500 for _, _, size, _, _ in packets)


@pytest.mark.parametrize("reverse", [False, True])
def test_sources_and_repairs_use_selected_fifo_feedback_uses_opposite_fifo(reverse):
    simulation, packets = make_simulation()
    transport = CompactWireTransport(simulation, reverse, CompactWireConfig(
        repair_ratio=.5, feedback_ms=1, short_source_max_bytes=128, short_source_copies=4))
    frame = tcp_profile_frame(payload_bytes=0, flags=0x12)
    delivered = []
    transport.submit_channel(7, len(frame), 0, delivered.append, frame=frame, deliver_frame=True)
    sources = [packet for packet in packets if packet[3] == "source"]
    assert len(sources) == 8
    assert all(packet[1] == reverse for packet in packets)
    # Copies reserve the actual chosen serializer, including its asymmetric rate.
    previous_finish = 0
    for submitted, direction, size, _, finish in packets:
        expected_finish = max(submitted, previous_finish) + size / simulation.links[direction][0].bytes_per_s
        assert finish == pytest.approx(expected_finish)
        previous_finish = finish
    drain(simulation)
    assert delivered == [frame]
    assert transport.base == len(transport.sources)
    assert all(direction == (not reverse) for _, direction, _, kind, _ in packets if kind == "feedback")
    assert all(direction == reverse for _, direction, _, kind, _ in packets if kind != "feedback")


def test_reverse_validation_reads_only_its_data_path():
    simulation, _ = make_simulation()
    simulation.links[False] = [SimpleNamespace(jitter=1), SimpleNamespace(jitter=1)]
    transport = CompactWireTransport(simulation, True, CompactWireConfig())
    assert transport.reverse is True
    simulation.links[True][0].jitter = .001
    with pytest.raises(ValueError, match="zero reverse-path jitter"):
        CompactWireTransport(simulation, True, CompactWireConfig())
    simulation.links[True].append(simulation.links[True][0])
    with pytest.raises(ValueError, match="reverse single-FIFO"):
        CompactWireTransport(simulation, True, CompactWireConfig())


@pytest.mark.parametrize("flags", [0x02, 0x10, 0x12, 0x14])
def test_reverse_short_control_protection_recovers_after_three_lost_copies(flags):
    simulation, packets = make_simulation()
    erasures = iter([True, True, True, False] * 2)
    simulation.links[True][0].erasures.lost = lambda: next(erasures, False)
    transport = CompactWireTransport(simulation, True, CompactWireConfig(
        repair_ratio=0, feedback_ms=1, short_source_max_bytes=128, short_source_copies=4))
    frame = tcp_profile_frame(payload_bytes=0, flags=flags)
    delivered = []
    transport.submit_channel(0, len(frame), 0, delivered.append, frame=frame, deliver_frame=True)
    drain(simulation)
    assert delivered == [frame]
    assert transport.base == len(transport.sources) == 2
    assert simulation.erasures[True]["source"] == 6
    assert simulation.datagrams[True]["source"] == 8
    assert transport.wire_repeated_source_packets == 6
    assert transport.tail_repairs == transport.scheduled_repairs == 0
    assert all(direction for _, direction, _, kind, _ in packets if kind == "source")
    assert all(not direction for _, direction, _, kind, _ in packets if kind == "feedback")


@pytest.mark.parametrize("reverse", [False, True])
def test_capacity_wake_follows_internal_queue_flush_and_retention_pruning(reverse):
    simulation, packets = make_simulation()
    transport = CompactWireTransport(simulation, reverse, CompactWireConfig(repair_ratio=0))
    transport.sources = [CompactSource(index, 1, index + 1) for index in range(GLOBAL_WINDOW)]
    transport.source_payloads = [b"x"] * GLOBAL_WINDOW
    frame = tcp_profile_frame(payload_bytes=64)
    transport.submit_channel(0, len(frame), 64, lambda: None, frame=frame)
    assert len(transport.source_queue) == 2
    assert not packets
    observations = []

    def capacity_available():
        observations.append((transport.base, len(transport.source_queue),
                             transport.wire_retained_start, transport.source_payloads[:2]))
        # The common ingress owner may submit immediately from this callback.
        # Existing internal records have already consumed two of three credits.
        next_frame = tcp_profile_frame(sequence=64, identification=1, payload_bytes=64)
        transport.submit_channel(0, len(next_frame), 64, lambda: None, frame=next_frame)

    transport.capacity_callback = capacity_available
    transport._receive_feedback(3, 0)
    assert observations == [(3, 0, 2, [None, None])]
    assert len(transport.sources) == GLOBAL_WINDOW + 3
    assert len(transport.sources) - transport.base == GLOBAL_WINDOW
    assert not transport.source_queue
    assert transport.wire_retained_start == 3
    assert all(direction == reverse for _, direction, _, _, _ in packets)


def test_stale_feedback_wake_does_not_restore_credit_or_overwrite_deficit():
    simulation, _ = make_simulation()
    transport = CompactWireTransport(simulation, True, CompactWireConfig())
    transport.base = 5
    transport.reported_deficit = 2
    observations = []
    transport.capacity_callback = lambda: observations.append((transport.base, transport.reported_deficit))
    transport._receive_feedback(4, 99)
    assert observations == [(5, 2)]


def test_absent_or_noop_capacity_callback_preserves_packet_and_event_trace():
    traces = []
    for callback in (None, lambda: None):
        simulation, packets = make_simulation(.15)
        transport = CompactWireTransport(simulation, False, CompactWireConfig(
            repair_ratio=.22, feedback_ms=1, tail_repair_delay_ms=15))
        assert transport.capacity_callback is None
        transport.capacity_callback = callback
        delivered = []
        for index in range(4):
            frame = tcp_profile_frame(sequence=index * 1448, identification=index, payload_bytes=1448)
            transport.submit_channel(0, len(frame), 1448, delivered.append, frame=frame, deliver_frame=True)
        events = []
        while simulation.events:
            simulation.now, serial, function, arguments = heappop(simulation.events)
            events.append((simulation.now, serial, function.__name__))
            function(*arguments)
        traces.append((packets, events, delivered, simulation.wire, transport.base))
    assert traces[0] == traces[1]
