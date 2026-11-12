"""Bound first-flight acceleration under loss, reordering, and stale ACKs."""

import pytest

from l2tunnel_sim.compact import CompactConfig, CompactSimulation
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.compact_lowlatency import BoundedGapARQTransport, FirstFlightARQTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic


class LowLatencySimulation(CompactSimulation):
    transport_type = FirstFlightARQTransport

    def make_transports(self, rng):
        return (self.transport_type(self, False, self.compact_config),
                self.transport_type(self, True, self.compact_config))


def connection(transport=FirstFlightARQTransport, *, jitter=0, loss=0, drain=2):
    class SelectedSimulation(LowLatencySimulation):
        transport_type = transport
    return SelectedSimulation(
        Scenario(20, loss), Traffic(duration_s=.001, drain_s=drain, window_bytes=20 * 1448, ack_every=1),
        (PathConfig(jitter_ms=jitter),), Strategy("Low-latency compact ARQ"), 42,
        CompactConfig(repair_ratio=0, feedback_ms=5),
    )


def test_first_feedback_recovers_before_original_guard_and_only_once():
    old, accelerated = connection(CompactARQTransport), connection()
    for sim in (old, accelerated):
        sim.produce()
        sim.now = .021
        sim.forward._receive_feedback(0, 0, 4, 0b1110, 4, 0, 1)
    assert old.forward.flights[0].attempts == 1
    assert accelerated.forward.flights[0].attempts == 2
    assert accelerated.forward.first_flight_fast_retransmissions == 1
    serial = accelerated.forward.flights[0].serial
    accelerated.now += .001
    accelerated.forward._receive_feedback(0, 0, 4, 0b1110, 4, 0, 2)
    assert accelerated.forward.flights[0].serial == serial


def test_stale_feedback_and_insufficient_later_receipts_cannot_accelerate():
    sim = connection()
    sim.produce()
    sim.now = .021
    transport = sim.forward
    transport._receive_feedback(0, 0, 3, 0b110, 3, 0, 10)
    assert transport.flights[0].attempts == 1
    transport._receive_feedback(0, 0, 4, 0b1110, 4, 0, 9)
    assert transport.flights[0].attempts == 1
    transport._receive_feedback(0, 0, 4, 0b1110, 1, 0, 11)
    assert transport.flights[0].attempts == 1


def test_newer_echo_keeps_rtt_guard_for_repeat_attempts():
    sim = connection()
    sim.produce()
    transport = sim.forward
    sim.now = .021
    transport._receive_feedback(0, 0, 4, 0b1110, 4, 0, 1)
    assert transport.flights[0].attempts == 2
    sim.now = .022
    transport.submit(1514, 1448, lambda: None)
    echo = transport.transmission_serial
    assert echo > transport.flights[0].serial
    count = len(transport.sources)
    bitmap = (1 << count) - 2
    sim.now = .043
    transport._receive_feedback(0, 0, count, bitmap, echo, 0, 2)
    assert transport.flights[0].attempts == 2
    sim.now = .065
    transport._receive_feedback(0, 0, count, bitmap, echo, 0, 3)
    assert transport.flights[0].attempts == 3


@pytest.mark.parametrize("transport", [FirstFlightARQTransport, BoundedGapARQTransport])
def test_loss_and_feedback_loss_complete_without_duplicate_callbacks(transport):
    sim = connection(transport)
    erasures = iter([True] + [False] * 10000)
    reverse = iter([True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(erasures)
    sim.links[True][0].erasures.lost = lambda: next(reverse)
    sim.run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert len(sim.forward.delays) == 20
    assert not sim.forward.flights
    assert sim.forward.base == len(sim.forward.sources)
    assert sim.datagrams[False]["retry"] == 1
    assert sim.datagrams[False]["repair"] == 0


@pytest.mark.parametrize("transport", [FirstFlightARQTransport, BoundedGapARQTransport])
def test_reordering_preserves_exactly_once_ordered_frame_release(transport):
    sim = connection(transport, jitter=30).run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert len(sim.forward.delays) == 20
    assert sim.forward.base == len(sim.forward.sources)


def test_lost_reverse_feedback_cannot_create_sender_knowledge():
    sim = connection(drain=.2)
    sim.links[True][0].erasures.lost = lambda: True
    sim.run()
    assert sim.tcp_received == 20
    assert sim.tcp_acked == 0
    assert sim.forward.base == 0
    assert sim.forward.flights


def test_early_gap_feedback_is_charged_and_suppressed_for_same_hole():
    sim = connection(BoundedGapARQTransport)
    sim.produce()
    sent = []
    original_send = sim.send

    def send(reverse, size, kind, deliver):
        sent.append((reverse, size, kind))
        return original_send(reverse, size, kind, deliver)

    sim.send = send
    transport = sim.forward
    sim.now = .01
    for index in (1, 2, 3):
        transport._receive_source(transport.sources[index], index + 1)
    assert transport.early_feedback_packets == 1
    assert sent == [(True, 53, "feedback")]
    for index in (4, 5, 6):
        transport._receive_source(transport.sources[index], index + 1)
    assert transport.early_feedback_packets == 1
    assert sent == [(True, 53, "feedback")]
    transport._receive_source(transport.sources[0], 1)
    for index in (8, 9, 10):
        transport._receive_source(transport.sources[index], index + 1)
    assert transport.early_feedback_packets == 1
    sim.now += .006
    transport._receive_source(transport.sources[11], 12)
    assert transport.early_feedback_packets == 2


def test_gap_feedback_interval_requires_a_positive_finite_budget():
    sim = connection()
    for value in (0, -1, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="finite and positive"):
            BoundedGapARQTransport(sim, False, gap_feedback_min_interval_ms=value)
