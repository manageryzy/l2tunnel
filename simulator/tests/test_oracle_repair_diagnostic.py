"""The oracle diagnostic retains service costs, origins, HOL and censoring."""

from pathlib import Path

import pytest


@pytest.fixture
def diagnostic(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    import oracle_repair_diagnostic
    return oracle_repair_diagnostic


def task(method="oracle_fifo", **changes):
    result = dict(method=method, repair_ratio=.208, seed=42, forward_mbps=100, reverse_mbps=10,
                  rtt_ms=70, loss_rate=.15, loss_model="iid", duration_s=.1, warmup_s=.02,
                  drain_s=1, payload_bytes=1448)
    result.update(changes)
    return result


def inputs(count=20, flows=4):
    sources = [dict(source_id=index, flow_id=index % flows, record_serial=index // flows,
                    segment_id=index // flows, is_context=False, enqueue_s=index * .00015,
                    protected_bytes=1460) for index in range(count)]
    segments = [dict(flow_id=item["flow_id"], segment_id=item["segment_id"],
                     original_submission_s=item["enqueue_s"]) for item in sources]
    return sources, segments


def test_no_loss_oracle_charges_every_idle_repair_and_matches_causal_service(diagnostic):
    sources, segments = inputs()
    causal, _, _, causal_packets = diagnostic.analyze(task("causal_rlnc", loss_rate=0), sources, segments)
    oracle, _, _, oracle_packets = diagnostic.analyze(task(loss_rate=0), sources, segments)
    assert causal["analytic_packet_schedule_loss_sha256"] == oracle["analytic_packet_schedule_loss_sha256"]
    assert causal["analytic_completion_p99_ms"] == oracle["analytic_completion_p99_ms"]
    assert oracle["analytic_oracle_idle_repair_slots"] == oracle["analytic_repair_packet_count"] == 4
    assert oracle["analytic_forward_bytes"] == 20 * 1496 + 4 * 1500
    assert len(causal_packets) == len(oracle_packets) == 24
    assert oracle["analytic_unresolved_sources"] == 0


def test_oracle_retries_fifo_head_after_a_lost_repair_without_future_loss_information(diagnostic):
    sources, _ = inputs(count=6, flows=1)
    sim = diagnostic.FixedReplay(task(repair_ratio=.5), sources)
    # Sources 0 and 1 fail. The first repair fails and its target stays queued.
    losses = iter((True, True, True, False, False, False, False, False, False))
    sim.links[False][0].erasures.lost = lambda: next(losses)
    sim.run()
    repairs = [packet for packet in sim.packets if packet["kind"] == "repair"]
    assert [packet["oracle_target"] for packet in repairs] == [0, 0, 1]
    assert sim.known_at[0] == pytest.approx(repairs[1]["transmission_finish_s"] + .035)
    assert sim.known_at[1] == pytest.approx(repairs[2]["transmission_finish_s"] + .035)
    assert sim.oracle_peak_queue == 2
    assert sim.oracle_useful_repairs == 2
    assert len(sim.packets) == 9


def test_unresolved_source_and_dependent_segments_survive_drain(diagnostic):
    sources, segments = inputs(count=4, flows=1)
    sim = diagnostic.FixedReplay(task(), sources)
    losses = iter((False, True, False, False))
    sim.links[False][0].erasures.lost = lambda: next(losses)
    sim.run()
    rows = diagnostic.delivered_segments(sources, segments, sim.known_at, .035, 1.1)
    assert len(sim.packets) == 4  # Ratio-only schedule adds no tail repairs.
    assert rows[0]["analytic_completion_censored"] is False
    assert all(row["analytic_completion_censored"] for row in rows[1:])
    assert len(sim.oracle_queue) == 1
    assert len(rows) == len(segments)


def test_actual_short_context_size_is_preserved(diagnostic):
    sources, segments = inputs(count=2, flows=1)
    sources[0].update(protected_bytes=72, is_context=True)
    sources[1]["segment_id"] = 0
    row, _, _, packets = diagnostic.analyze(task(loss_rate=0, repair_ratio=.5), sources, segments[:1])
    assert [packet["bytes"] for packet in packets] == [108, 1496, 1500]
    assert row["analytic_forward_bytes"] == 3104


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_forward_packet_and_loss_schedule_remains_identical_with_causal_feedback(diagnostic, seed):
    sources, segments = inputs(count=200)
    causal, _, _, _ = diagnostic.analyze(task("causal_rlnc", seed=seed), sources, segments)
    oracle, _, _, _ = diagnostic.analyze(task(seed=seed), sources, segments)
    assert causal["analytic_packet_schedule_loss_sha256"] == oracle["analytic_packet_schedule_loss_sha256"]
    assert causal["analytic_forward_bytes"] == oracle["analytic_forward_bytes"]
    assert causal["analytic_source_losses"] == oracle["analytic_source_losses"]
    assert causal["analytic_reverse_feedback_bytes"] > 0
    assert oracle["analytic_reverse_feedback_bytes"] == 0
    assert causal["analytic_causal_sender_window_would_bind"] is False


def test_context_fragment_and_native_delivery_dependencies_keep_original_deadlines(diagnostic):
    sources = [dict(source_id=0, flow_id=0, record_serial=0, segment_id=0, is_context=True),
               dict(source_id=1, flow_id=0, record_serial=1, segment_id=0, is_context=False),
               dict(source_id=2, flow_id=0, record_serial=1, segment_id=0, is_context=False),
               dict(source_id=3, flow_id=0, record_serial=2, segment_id=1, is_context=False)]
    segments = [dict(flow_id=0, segment_id=0, original_submission_s=0),
                dict(flow_id=0, segment_id=1, original_submission_s=.01)]
    rows = diagnostic.delivered_segments(sources, segments, [.2, .05, .06, .07], .035, 1)
    assert [row["analytic_delivery_s"] for row in rows] == [.2, .2]
    assert [row["analytic_ideal_return_latency_ms"] for row in rows] == pytest.approx([235, 225])
    censored = diagnostic.delivered_segments(sources, segments, [.2, .05, .06, .07], .035, .21)
    assert all(not row["analytic_delivery_censored"] and row["analytic_completion_censored"] for row in censored)


def test_diagnostic_rows_are_excluded_from_protocol_archive(diagnostic):
    import all_experiments
    sources, segments = inputs()
    row, segment_rows, source_rows, packets = diagnostic.analyze(task(), sources, segments)
    assert not all_experiments.is_observation(row)
    assert all(not all_experiments.is_observation(item) for item in [*segment_rows, *source_rows, *packets])
    assert row["analytic_protocol_target_claim"] is False
