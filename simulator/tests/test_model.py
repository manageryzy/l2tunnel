from itertools import combinations
from random import Random

import pytest

from l2tunnel_sim.coding import Decoder, block_coefficients
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure
from l2tunnel_sim.model import Erasures, Simulation


def one_frame(strategy, *, drain=0.15, mtu=1500, frame_bytes=1514):
    traffic = Traffic(duration_s=0.001, drain_s=drain, frame_bytes=frame_bytes,
                      payload_bytes=frame_bytes, window_bytes=frame_bytes, ack_every=1)
    return Simulation(Scenario(20, 0, mtu=mtu), traffic, (PathConfig(),), strategy, 42)


def script_losses(sim, direction, lost_indices):
    lost_indices = set(lost_indices)
    decisions = (index in lost_indices for index in range(1000))
    sim.links[direction][0].erasures.lost = lambda: next(decisions)


def test_lossless_fragment_accounting_and_reverse_ack():
    sim = one_frame(Strategy("ARQ")).run()
    result = measure(sim)
    assert result["forward_source_datagrams"] == 2
    assert result["forward_source_bytes"] == 1514 + 2 * 88
    assert result["reverse_source_bytes"] == 66 + 88
    assert result["forward_retry_bytes"] == 0
    assert result["tcp_acked_frames"] == 1
    assert result["tcp_goodput_mbps"] == 0  # The frame arrives during drain.
    assert result["frame_p50_ms"] == pytest.approx(10 + 2 * 845 / 12500)


def test_arq_retries_a_fragment_and_reassembles_exactly_once():
    sim = one_frame(Strategy("ARQ"))
    script_losses(sim, False, [0])
    result = measure(sim.run())
    assert result["forward_retry_datagrams"] == 1
    assert result["forward_retry_bytes"] == 845
    assert result["released_frames"] == 1
    assert result["tcp_acked_frames"] == 1
    assert result["forward_unconfirmed_symbols"] == 0
    assert result["frame_p50_ms"] > 60


def test_block_repair_recovers_before_timeout():
    sim = one_frame(Strategy("2+1", mode="block", block_size=2, block_repairs=1))
    script_losses(sim, False, [0])
    result = measure(sim.run())
    assert result["forward_repair_bytes"] == 845
    assert result["forward_fec_recovered_symbols"] == 1
    assert result["forward_retry_datagrams"] == 0
    assert result["frame_p50_ms"] == pytest.approx(10 + 3 * 845 / 12500)


def test_packed_fragments_share_one_erase_and_retry_separately():
    sim = one_frame(Strategy("Packed", source_batch=2), frame_bytes=1000)
    script_losses(sim, False, [0])
    result = measure(sim.run())
    assert result["forward_source_datagrams"] == 1
    assert result["forward_source_bytes"] == 1000 + 88 + 4
    assert result["forward_source_lost"] == 1
    assert result["forward_retry_datagrams"] == 2
    assert result["released_frames"] == 1


def test_lost_reverse_ack_frame_delays_sender_progress():
    sim = one_frame(Strategy("ARQ"), drain=0.045)
    script_losses(sim, True, [0])
    result = measure(sim.run())
    assert result["tcp_delivered_frames"] == 1
    assert result["tcp_acked_frames"] == 0
    assert result["reverse_source_lost"] == 1


def test_feedback_repair_can_use_gap_before_source_timeout():
    strategy = Strategy("Sliding", mode="sliding", fragments=1, repair_every=20,
                        fec_wait_ms=1000, feedback_repair=True)
    traffic = Traffic(duration_s=0.001, drain_s=0.2, frame_bytes=100,
                      payload_bytes=100, window_bytes=300, ack_every=1)
    sim = Simulation(Scenario(20, 0), traffic, (PathConfig(),), strategy, 42)
    # The first source is still covered by a future scheduled coding flush, but no
    # proactive repair has been queued when the feedback for sources 1 and 2 arrives.
    script_losses(sim, False, [0])
    result = measure(sim.run())
    assert result["forward_repair_datagrams"] == 1
    assert result["forward_fec_recovered_symbols"] == 1
    assert result["forward_retry_datagrams"] == 0
    assert result["frame_p95_ms"] < 50


def test_reverse_tunnel_can_release_newer_ack_across_a_gap():
    strategy = Strategy("ARQ", streams=2, reverse_ordered=False)
    traffic = Traffic(duration_s=0.001, drain_s=0.035, frame_bytes=100,
                      payload_bytes=100, window_bytes=200, ack_every=1)
    sim = Simulation(Scenario(20, 0), traffic, (PathConfig(),), strategy, 42)
    script_losses(sim, True, [0])
    assert measure(sim.run())["tcp_acked_frames"] == 2

    ordered = Strategy("Ordered", streams=2, reverse_ordered=True)
    sim = Simulation(Scenario(20, 0), traffic, (PathConfig(),), ordered, 42)
    script_losses(sim, True, [0])
    assert measure(sim.run())["tcp_acked_frames"] == 0


def test_mtu_limits_aggregation_and_forces_fragmentation():
    sim = one_frame(Strategy("Packed", fragments=1, source_batch=4), mtu=1280).run()
    assert sim.datagrams[False]["source"] == 2
    assert sim.forward.delivered_bytes == 1514


def test_all_subsets_match_systematic_mds_threshold():
    equations = [
        {0: 1}, {1: 1}, {2: 1},
        *[dict(enumerate(block_coefficients(3, row))) for row in range(2)],
    ]
    for received in range(6):
        for indices in combinations(range(5), received):
            decoder = Decoder()
            for index in reversed(indices):
                decoder.insert(equations[index])
            assert (decoder.known == {0, 1, 2}) == (received >= 3)


def test_burst_loss_has_requested_stationary_rate_and_run_length():
    channel = Erasures(Scenario(20, 0.2, "burst", mean_burst=4), Random(75))
    samples = [channel.lost() for _ in range(60000)]
    burst_starts = sum(lost and not prior for prior, lost in zip([False, *samples], samples))
    assert sum(samples) / len(samples) == pytest.approx(0.2, abs=0.01)
    assert sum(samples) / burst_starts == pytest.approx(4, abs=0.25)


def test_equal_paths_serialize_two_fragments_concurrently():
    traffic = Traffic(duration_s=0.001, drain_s=0.15, window_bytes=1448)
    sim = Simulation(Scenario(20, 0), traffic, (PathConfig(), PathConfig()),
                     Strategy("Two paths"), 42).run()
    assert all(path.free_at > 0 for path in sim.links[False])
    assert measure(sim)["frame_p50_ms"] == pytest.approx(10 + 845 / 12500)


def test_cumulative_feedback_covers_a_lost_earlier_confirmation():
    rows = []
    for cumulative in (False, True):
        strategy = Strategy("ARQ", fragments=1, feedback_batch=1,
                            cumulative_feedback=cumulative)
        traffic = Traffic(duration_s=.001, drain_s=.2, frame_bytes=100,
                          payload_bytes=100, window_bytes=200, ack_every=10)
        sim = Simulation(Scenario(20, 0), traffic, (PathConfig(),), strategy, 42)
        script_losses(sim, True, [0])
        rows.append(measure(sim.run()))
    assert rows[0]["forward_retry_datagrams"] == 1
    assert rows[1]["forward_retry_datagrams"] == 0
    assert rows[1]["tcp_acked_frames"] == 2


def test_cumulative_and_selective_feedback_can_arrive_out_of_order():
    sim = one_frame(Strategy("Cumulative", cumulative_feedback=True))
    sim.produce()
    sim.forward.on_feedback((1,))
    assert list(sim.forward.pending) == [0]
    sim.forward.on_feedback((), 1)
    sim.forward.on_feedback((), 0)
    assert sim.forward.confirmed_prefix == 1
    assert not sim.forward.pending
    assert sim.forward.pending_bytes == 0


@pytest.mark.parametrize("frames,repairs", [(10, 3), (4, 2)])
def test_fractional_repair_rate_counts_full_and_timed_partial_groups(frames, repairs):
    strategy = Strategy("Thirty percent", mode="sliding", fragments=1,
                        repair_every=10, repairs_per_group=3)
    traffic = Traffic(duration_s=.001, drain_s=.1, frame_bytes=100,
                      payload_bytes=100, window_bytes=frames * 100)
    sim = Simulation(Scenario(20, 0), traffic, (PathConfig(),), strategy, 42).run()
    assert sim.datagrams[False]["repair"] == repairs
    assert sim.wire[False]["repair"] == repairs * 188


def test_interleaved_repairs_spread_fractional_redundancy_across_sources():
    strategy = Strategy("Interleaved", mode="sliding", fragments=1,
                        repair_every=5, repairs_per_group=2, interleave_repairs=True)
    traffic = Traffic(duration_s=.001, drain_s=.1, frame_bytes=100,
                      payload_bytes=100, window_bytes=500)
    sim = Simulation(Scenario(20, 0), traffic, (PathConfig(),), strategy, 42)
    sends = []
    original_send = sim.send

    def record(reverse, size, kind, receive):
        sends.append(kind)
        return original_send(reverse, size, kind, receive)

    sim.send = record
    sim.produce()
    assert sends == ["source", "source", "source", "repair", "source", "source", "repair"]
