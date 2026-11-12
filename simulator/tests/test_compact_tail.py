"""Configurable tail repair uses the real FIFO clock for every compact format."""

from heapq import heappop

import pytest

from l2tunnel_sim.aligned_records import AlignedRecordConfig, AlignedRecordTransport
from l2tunnel_sim.compact import CompactConfig, CompactTransport, tcp_profile_frame
from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.shared_records import SharedRecordConfig, SharedRecordTransport


FORMATS = [
    (CompactConfig, CompactTransport),
    (SharedRecordConfig, SharedRecordTransport),
    (AlignedRecordConfig, AlignedRecordTransport),
    (CompactWireConfig, CompactWireTransport),
]


def make_transport(config_type, transport_type, *, rtt=70, loss=1, **options):
    sim = Simulation(Scenario(rtt, loss), Traffic(duration_s=.001, drain_s=3),
                     (PathConfig(10, 2),), Strategy("tail fixture"), 42)
    packets = []
    send = sim.send

    def record_send(reverse, size, kind, receive):
        finish, measured_rtt = send(reverse, size, kind, receive)
        packets.append((sim.now, finish, reverse, size, kind))
        return finish, measured_rtt

    sim.send = record_send
    config = config_type(repair_ratio=0, **options)
    transport = transport_type(sim, False, config)
    return transport, packets


def submit(transport, sequence=0, delivered=None):
    frame = tcp_profile_frame(sequence=sequence, payload_bytes=64)

    def deliver():
        if delivered is not None:
            delivered.append(frame)

    if isinstance(transport, SharedRecordTransport):
        transport.submit_channel(0, len(frame), 64, deliver, frame=frame)
    else:
        transport.submit(len(frame), 64, deliver, frame=frame)
    transport.flush()
    return frame


def advance(sim, until):
    while sim.events and sim.events[0][0] <= until:
        sim.now, _, callback, args = heappop(sim.events)
        callback(*args)
    sim.now = until


def active_tail_times(transport):
    return sorted(when for when, _, callback, args in transport.sim.events
                  if callback == transport._tail and args == (transport.tail_generation,))


@pytest.mark.parametrize("config_type,transport_type", FORMATS)
@pytest.mark.parametrize("rtt,delay_ms,expected_delay", [
    (20, None, .05), (70, None, .14), (70, 7.5, .0075),
])
def test_initial_and_repeated_timers_use_configured_delay_and_real_source_finish(
        config_type, transport_type, rtt, delay_ms, expected_delay):
    transport, packets = make_transport(config_type, transport_type, rtt=rtt,
                                        tail_repair_delay_ms=delay_ms)
    submit(transport)
    sources = [packet for packet in packets if packet[-1] == "source"]
    assert sources
    assert transport.last_source_at == sources[-1][1] > transport.sim.now
    first = transport.last_source_at + expected_delay
    assert active_tail_times(transport) == pytest.approx([first])
    original_sources = list(transport.sources)
    original_credit = transport.credit

    advance(transport.sim, first - 1e-9)
    assert transport.tail_repairs == 0
    advance(transport.sim, first)
    assert transport.tail_repairs == 1
    second = first + expected_delay
    assert active_tail_times(transport) == pytest.approx([second])
    advance(transport.sim, second)
    assert transport.tail_repairs == 2
    assert active_tail_times(transport) == pytest.approx([second + expected_delay])
    assert transport.sources == original_sources
    assert transport.credit == original_credit
    assert transport.base == transport.scheduled_repairs == 0
    assert [packet[0] for packet in packets if packet[-1] == "repair"] == [first, second]


@pytest.mark.parametrize("config_type,transport_type", FORMATS)
@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"),
                                   -float("inf"), True, False, "5"])
def test_tail_delay_rejects_nonfinite_nonpositive_or_nonnumeric_values(
        config_type, transport_type, value):
    with pytest.raises(ValueError, match="tail_repair_delay_ms"):
        config_type(tail_repair_delay_ms=value)


@pytest.mark.parametrize("delay_ms,after", [(1e-13, 1.0), (5e-324, 0.0)])
def test_tail_delay_must_advance_the_floating_point_clock(delay_ms, after):
    transport, _ = make_transport(CompactConfig, CompactTransport, tail_repair_delay_ms=delay_ms)
    with pytest.raises(ValueError, match="advance the simulation clock"):
        transport._schedule_tail(after, 1)
    assert not transport.sim.events


@pytest.mark.parametrize("encapsulation", ["udp", "raw_ipv4_crc32"])
@pytest.mark.parametrize("delay_ms", [None, 7.5])
def test_short_source_copies_start_tail_after_the_last_actual_serialization(
        encapsulation, delay_ms):
    transport, packets = make_transport(
        CompactWireConfig, CompactWireTransport, encapsulation=encapsulation,
        short_source_max_bytes=1460, short_source_copies=3,
        tail_repair_delay_ms=delay_ms)
    submit(transport)
    sources = [packet for packet in packets if packet[-1] == "source"]
    assert len(sources) == 3 * len(transport.sources)
    assert all(first[1] < second[1] for first, second in zip(sources, sources[1:]))
    assert sources[-1][1] == transport.last_source_at
    assert transport.last_source_at == pytest.approx(sum(packet[3] for packet in sources) / 1_250_000)
    delay = .14 if delay_ms is None else delay_ms / 1000
    first = sources[-1][1] + delay
    assert active_tail_times(transport) == pytest.approx([first])
    advance(transport.sim, first)
    assert transport.tail_repairs == 1
    assert active_tail_times(transport) == pytest.approx([first + delay])
    assert transport.wire_repeated_source_packets == 2 * len(transport.sources)
    assert transport.wire_repeated_source_bytes == sum(packet[3] for packet in sources) * 2 // 3
    assert transport.sim.wire[False]["source"] == sum(packet[3] for packet in sources)


@pytest.mark.parametrize("config_type,transport_type", FORMATS)
def test_new_source_invalidates_old_repeat_and_feedback_stops_current_tail(config_type, transport_type):
    transport, packets = make_transport(config_type, transport_type, tail_repair_delay_ms=7.5)
    submit(transport)
    first = active_tail_times(transport)[0]
    advance(transport.sim, first)
    old_repeat = active_tail_times(transport)[0]
    assert transport.tail_repairs == 1
    submit(transport, sequence=64)
    new_first = active_tail_times(transport)[0]
    assert new_first > old_repeat
    advance(transport.sim, old_repeat)
    assert transport.tail_repairs == 1
    advance(transport.sim, new_first)
    assert transport.tail_repairs == 2
    transport._receive_feedback(len(transport.sources), 0)
    advance(transport.sim, new_first + .1)
    assert transport.tail_repairs == 2
    assert not active_tail_times(transport)
    assert transport.base == len(transport.sources)


@pytest.mark.parametrize("config_type,transport_type", FORMATS)
def test_lossless_delivery_and_feedback_retirement_with_short_tail(config_type, transport_type):
    transport, _ = make_transport(config_type, transport_type, loss=0, tail_repair_delay_ms=7.5)
    delivered = []
    expected = submit(transport, delivered=delivered)
    advance(transport.sim, .5)
    assert delivered == [expected]
    assert transport.base == len(transport.sources)
    assert not active_tail_times(transport)
    assert transport.tail_repairs > 0  # Repairs sent before original confirmation are charged.
