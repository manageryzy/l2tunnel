"""Selective-repeat recovery over real lossy links and compact record packing."""

from l2tunnel_sim.compact import CompactConfig, CompactSimulation
from l2tunnel_sim.compact_arq import CompactARQTransport, FEEDBACK_HEADER_BYTES
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic


class ARQSimulation(CompactSimulation):
    def make_transports(self, rng):
        return (CompactARQTransport(self, False, self.compact_config),
                CompactARQTransport(self, True, self.compact_config))


def connection(*, packets=20, loss=0, drain=2, jitter=0):
    return ARQSimulation(
        Scenario(20, loss),
        Traffic(duration_s=.001, drain_s=drain, window_bytes=packets * 1448, ack_every=1),
        (PathConfig(jitter_ms=jitter),), Strategy('Compact ARQ'), 42,
        CompactConfig(repair_ratio=0, feedback_ms=2),
    )


def test_lossless_delivery_has_no_repairs_or_retries_and_charges_ack_header():
    sim = connection().run()
    assert sim.tcp_received == sim.tcp_acked == len(sim.sent_times) == 20
    assert not sim.forward.flights
    assert sim.forward.base == len(sim.forward.sources)
    assert sim.datagrams[False]['repair'] == sim.datagrams[False]['retry'] == 0
    assert sim.datagrams[True]['repair'] == sim.datagrams[True]['retry'] == 0
    assert sim.wire[True]['feedback'] >= FEEDBACK_HEADER_BYTES * sim.datagrams[True]['feedback']
    assert sim.forward.record_capacity == 1462


def test_one_source_loss_retransmits_only_that_source():
    sim = connection()
    losses = iter([True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(losses)
    sim.run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert sim.datagrams[False]['retry'] == 1
    assert sim.forward.retransmitted_source_bytes == 1462
    assert len(sim.forward.delays) == 20


def test_lost_feedback_and_three_consecutive_sources_eventually_complete():
    sim = connection()
    losses = iter([True, True, True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(losses)
    reverse_losses = iter([True] + [False] * 10000)
    sim.links[True][0].erasures.lost = lambda: next(reverse_losses)
    sim.run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert sim.datagrams[False]['retry'] == 3
    assert not sim.forward.flights
    assert len(sim.forward.delays) == 20


def test_reordering_keeps_callbacks_unique_and_repeated_feedback_is_harmless():
    sim = connection(jitter=30).run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert len(sim.forward.delays) == 20
    transport = sim.forward
    count = len(transport.sources)
    before = sim.datagrams[False]['retry']
    transport._receive_feedback(0, 0, count, (1 << count) - 1, 1, 0, 1)
    assert transport.base == count
    assert not transport.flights
    assert sim.datagrams[False]['retry'] == before


def test_cutoff_preserves_undelivered_records_and_unconfirmed_sources():
    sim = connection(packets=1, loss=1, drain=.1).run()
    assert sim.tcp_received == sim.tcp_acked == 0
    assert sim.forward.flights
    assert sim.forward.records
    assert sim.forward.base == 0
    assert sim.datagrams[False]['retry'] > 0
    assert sim.forward.pending_bytes > 0


def test_all_feedback_loss_never_fakes_sender_confirmation():
    sim = connection(packets=1, drain=.2)
    sim.links[True][0].erasures.lost = lambda: True
    sim.run()
    assert sim.tcp_received == 1
    assert sim.tcp_acked == 0
    assert sim.forward.flights
    assert sim.forward.base == 0
    assert len(sim.forward.delays) == 1
    assert sim.datagrams[False]['retry'] > 0


def test_repeated_negative_bitmap_cannot_repeat_a_retry_before_its_rtt():
    sim = connection()
    sim.produce()
    transport = sim.forward
    # Source zero is missing and three later source IDs are acknowledged.
    sim.now = .1
    transport._receive_feedback(0, 0, 4, 0b1110, 4, 80000, 1)
    first_retry_serial = transport.flights[0].serial
    assert transport.flights[0].attempts == 2
    sim.now += .001
    transport._receive_feedback(0, 0, 4, 0b1110, 4, 80000, 2)
    assert transport.flights[0].serial == first_retry_serial
    assert transport.flights[0].attempts == 2


def test_actual_delta_header_records_use_the_same_arq_delivery_path():
    sim = ARQSimulation(
        Scenario(20, .15), Traffic(duration_s=.001, drain_s=3, window_bytes=20 * 1448),
        (PathConfig(),), Strategy('Compact ARQ delta'), 42,
        CompactConfig(repair_ratio=0, header_profile='tcp_delta', feedback_ms=2),
    ).run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert sim.forward.profile_context_bytes == 69
    assert sim.forward.source_record_bytes < 20 * 1474
    assert sim.datagrams[False]['repair'] == 0
