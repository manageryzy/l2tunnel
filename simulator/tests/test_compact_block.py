"""Actual finite-field block recovery and feedback accounting regressions."""

from l2tunnel_sim.compact import CompactSimulation
from l2tunnel_sim.compact_block import CompactBlockConfig, CompactBlockTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic


class BlockSimulation(CompactSimulation):
    def make_transports(self, rng):
        return (CompactBlockTransport(self, False, self.compact_config),
                CompactBlockTransport(self, True, self.compact_config))


def simulation(*, loss=0, packets=20, drain=2, **config):
    return BlockSimulation(
        Scenario(20, loss), Traffic(duration_s=.001, drain_s=drain, window_bytes=packets * 1448),
        (PathConfig(),), Strategy('Compact block'), 42,
        CompactBlockConfig(repair_ratio=.1, generation_sources=10, feedback_ms=2, **config),
    )


def test_lossless_finite_blocks_and_idle_tail_deliver_all_records():
    sim = simulation().run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert sim.forward.code_blocks == [10, 10, 1]
    assert sim.forward.initial_repairs == 3
    assert sim.forward.additional_repairs == 0
    assert not sim.forward.sending_blocks
    assert sim.forward.decoder.rows == {}


def test_rank_repair_recovers_more_losses_than_initial_parity():
    sim = simulation()
    losses = iter([True, True, True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(losses)
    sim.run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert sim.forward.additional_repairs >= 2
    assert sim.forward.recovered_symbols >= 3
    assert len(sim.forward.delays) == 20
    assert not sim.forward.sending_blocks


def test_lost_rank_feedback_and_partial_slow_start_block_recover():
    sim = simulation(packets=1)
    losses = iter([True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(losses)
    reverse_losses = iter([True] + [False] * 10000)
    sim.links[True][0].erasures.lost = lambda: next(reverse_losses)
    sim.run()
    assert sim.tcp_received == sim.tcp_acked == 1
    assert sim.forward.code_blocks == [2]
    assert not sim.forward.sending_blocks


def test_stale_rank_report_preserves_monotone_degrees_and_inflight_credit():
    sim = simulation()
    sim.produce()
    block = sim.forward.sending_blocks[0]
    sim.forward._receive_feedback(0, [(0, 10, 8, 0)], 2)
    before = sim.forward.additional_repairs
    sim.forward._receive_feedback(0, [(0, 10, 1, 0)], 1)
    assert block.reported_degrees == 8
    assert sim.forward.additional_repairs == before


def test_all_loss_preserves_incomplete_records_and_uses_bounded_probes():
    sim = simulation(loss=1, packets=1, drain=.2).run()
    assert sim.tcp_received == sim.tcp_acked == 0
    assert sim.forward.records
    assert sim.forward.sending_blocks
    assert 0 < sim.forward.additional_repairs < 20


def test_delta_header_uses_actual_frame_codec_and_reliable_rank_repair():
    sim = simulation(loss=.15, header_profile='tcp_delta').run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert sim.forward.profile_context_bytes == 69
    assert sim.forward.source_record_bytes < 20 * 1474


def test_reordered_generations_never_inflate_an_unsealed_block_boundary():
    sim = simulation()
    sim.produce()
    sim.forward.flush()
    transport = sim.forward
    transport._receive_source(transport.sources[0], 0)
    transport._receive_source(transport.sources[20], 20)
    assert transport.receiving_blocks[0].end == 1
    assert not transport.receiving_blocks[0].sealed


def test_pending_repair_credit_prevents_duplicate_rank_refills():
    sim = simulation()
    sim.produce()
    transport = sim.forward
    sim.now = .1
    transport._receive_feedback(0, [(0, 10, 8, 0)], 1, 22)
    sent = transport.additional_repairs
    assert sent == 3
    sim.now += .001
    transport._receive_feedback(0, [(0, 10, 8, 0)], 2, 22)
    assert transport.additional_repairs == sent


def test_loss_and_bidirectional_reordering_preserve_exact_record_delivery():
    sim = simulation(loss=.15)
    for direction in sim.links:
        for link in direction:
            link.jitter = .03
    sim.run()
    assert sim.tcp_received == sim.tcp_acked == 20
    assert len(sim.forward.delays) == 20
    assert sim.forward.delivered_bytes == 20 * 1514
    assert not sim.forward.sending_blocks
