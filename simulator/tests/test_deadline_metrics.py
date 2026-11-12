"""Per-segment completion and deadline accounting without survivor selection."""

from functools import partial
import importlib.util
from pathlib import Path

import pytest

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.shared_compact import SharedCompactMultiFlow
from l2tunnel_sim.tcp import PlainTCP, Segment


spec = importlib.util.spec_from_file_location(
    "deadline_metrics_study", Path(__file__).resolve().parents[1] / "studies/deadline_metrics.py")
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)


class ObservedTCP(metrics.SegmentDeadlineObserver, PlainTCP):
    pass


def connection(*, duration=1, drain=1, rtt=100):
    return ObservedTCP(Scenario(rtt, 0), Traffic(duration_s=duration, drain_s=drain,
                       payload_bytes=64, frame_bytes=130, window_bytes=640),
                       (PathConfig(),), Strategy("Deadline observer", mode="tcp"), 42)


def history(*, sent, ack=(), delivery=(), duration=1, drain=1):
    sim = connection(duration=duration, drain=drain)
    sim.sent_times = list(sent)
    sim.segment_ack_completion_times = list(ack)
    sim.segment_delivery_times = list(delivery)
    sim.tcp_acked, sim.tcp_received = len(ack), len(delivery)
    return sim


def test_stretch_ack_records_every_original_submission_and_ignores_duplicate_acks():
    sim = connection(duration=.05)
    sim.sent_times = [0, .01, .02]
    sim.forward.pending = {index: Segment(last_sent_at=.075, attempts=2) for index in range(3)}
    sim.forward.pending_bytes = 3 * 64
    sim.now = .1
    sim.on_ack(3, .075)
    sim.on_ack(3, .075)
    sim.on_ack(1, .01)
    assert sim.segment_ack_completion_times == [.1] * 3
    assert sim.tcp_rtts == pytest.approx([80])
    row = metrics.deadline_metrics(sim)
    assert row["with_drain_tcp_all_segment_ack_rtt_samples"] == 3
    assert row["with_drain_tcp_all_segment_ack_rtt_p99_ms"] == pytest.approx(99.8)
    assert sim.srtt == pytest.approx(.025)


def test_out_of_order_arrival_waits_for_application_delivery_and_uses_each_delay():
    sim = connection(duration=.05)
    sim.sent_times = [0, .01, .02]
    sim.now = .04
    sim.on_data(2, .02)
    assert sim.segment_delivery_times == []
    sim.now = .06
    sim.on_data(0, 0)
    sim.now = .1
    sim.on_data(1, .01)
    sim.on_data(2, .02)
    assert sim.segment_delivery_times == [.06, .1, .1]
    assert sim.forward.delays == pytest.approx([60, 90, 80])
    row = metrics.deadline_metrics(sim)
    assert row["with_drain_tcp_application_delivery_samples"] == 3
    assert row["with_drain_tcp_application_delivery_p99_ms"] == pytest.approx(89.8)


def test_cutoffs_include_overdue_unresolved_segments_in_deadline_bounds():
    sim = history(sent=[0, .5, .9], ack=[.125], delivery=[.0625, .5625])
    row = metrics.deadline_metrics(sim)
    stem = "tcp_all_segment_ack_rtt_cohort"
    assert row[stem + "_offered_segments"] == 3
    assert row[stem + "_completed_segments"] == 1
    assert row[stem + "_censored_segments"] == 2
    assert row[stem + "_censored_exceeded_segments"] == 1
    assert row[stem + "_censored_within_budget_segments"] == 1
    assert row[stem + "_miss_fraction_lower"] == pytest.approx(1 / 3)
    assert row[stem + "_miss_fraction_upper"] == pytest.approx(2 / 3)
    assert row[stem + "_completed_p99_ms"] == 125
    assert row[stem + "_latency_lower_bound_p99_ms"] > 490
    assert row["with_drain_" + stem + "_censored_exceeded_segments"] == 2
    assert row["with_drain_" + stem + "_miss_fraction_lower"] == pytest.approx(2 / 3)
    assert row["tcp_application_delivery_cohort_censored_segments"] == 1


def test_drain_completions_do_not_leak_into_traffic_cutoff():
    sim = history(sent=[0, .9], ack=[.125, 1.125], delivery=[.0625, 1.0625])
    row = metrics.deadline_metrics(sim)
    assert row["tcp_all_segment_ack_rtt_samples"] == 1
    assert row["tcp_all_segment_ack_rtt_cohort_censored_segments"] == 1
    assert row["with_drain_tcp_all_segment_ack_rtt_samples"] == 2
    assert row["with_drain_tcp_all_segment_ack_rtt_cohort_censored_segments"] == 0
    assert row["with_drain_tcp_all_segment_ack_rtt_exceeded_budget_fraction"] == .5
    assert row["with_drain_tcp_all_segment_ack_rtt_cohort_miss_fraction_lower"] == .5
    assert row["with_drain_tcp_all_segment_ack_rtt_cohort_miss_fraction_upper"] == .5


def test_steady_event_window_and_submission_cohort_have_explicitly_different_denominators():
    sim = history(sent=[0, .5, .9], ack=[.125, .8], delivery=[.0625, .75])
    row = metrics.deadline_metrics(sim, warmup_s=.6)
    assert row["steady_tcp_all_segment_ack_rtt_samples"] == 1
    assert row["steady_tcp_all_segment_ack_rtt_p99_ms"] == pytest.approx(300)
    assert row["steady_tcp_all_segment_ack_rtt_cohort_offered_segments"] == 1
    assert row["steady_tcp_all_segment_ack_rtt_cohort_completed_segments"] == 0
    assert row["steady_tcp_all_segment_ack_rtt_cohort_censored_segments"] == 1
    assert row["steady_tcp_all_segment_ack_rtt_cohort_completed_p99_ms"] is None


def test_deadline_equality_is_not_an_observed_miss():
    sim = history(sent=[0], ack=[.125], delivery=[.0625])
    row = metrics.deadline_metrics(sim, deadline_factor=1.25)
    assert row["latency_budget_ms"] == 125
    assert row["tcp_all_segment_ack_rtt_exceeded_budget_fraction"] == 0
    assert row["tcp_all_segment_ack_rtt_cohort_miss_fraction_lower"] == 0


def test_empty_history_has_no_quantiles_or_invented_success_fraction():
    row = metrics.deadline_metrics(connection())
    assert row["tcp_all_segment_ack_rtt_samples"] == 0
    assert row["tcp_all_segment_ack_rtt_p99_ms"] is None
    assert row["tcp_all_segment_ack_rtt_cohort_censored_segments"] == 0
    assert row["tcp_all_segment_ack_rtt_cohort_miss_fraction_lower"] is None


@pytest.mark.parametrize("kwargs", [dict(warmup_s=-1), dict(warmup_s=1), dict(warmup_s=float("nan")),
                                    dict(deadline_factor=0), dict(deadline_factor=float("inf"))])
def test_invalid_metric_intervals_are_rejected(kwargs):
    with pytest.raises(ValueError):
        metrics.deadline_metrics(connection(), **kwargs)


def test_missing_observer_history_fails_loudly():
    sim = connection()
    sim.tcp_acked = 1
    with pytest.raises(ValueError, match="history"):
        metrics.deadline_metrics(sim)
    with pytest.raises(ValueError, match="complete TCP lifetime"):
        sim.on_ack(1)


def test_observer_preserves_shared_coalesced_tcp_behavior_and_existing_rtt_observer(monkeypatch):
    pytest.importorskip("aioquic")
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from latency_ack import ObservedCoalescedACKTCP

    class ObservedSharedTCP(metrics.SegmentDeadlineObserver, ObservedCoalescedACKTCP):
        pass

    config = CompactConfig(header_profile="tcp_delta", repair_ratio=.25)
    args = (Scenario(20, .1), Traffic(duration_s=.03, drain_s=2, payload_bytes=64,
            frame_bytes=130, window_bytes=1280), (PathConfig(),), Strategy("Shared deadline", mode="tcp"), 42, 2)
    sims = []
    for kind in (ObservedCoalescedACKTCP, ObservedSharedTCP):
        factory = partial(kind, compact_config=config, ack_copies=2, ack_coalesce_ms=.25)
        sim = SharedCompactMultiFlow(*args, compact_config=config, simulation_factory=factory)
        assert not sim.events
        sims.append(sim.run())
    control, observed = sims
    assert observed.measurements() == control.measurements()
    for plain, flow in zip(control.flows, observed.flows):
        assert flow.sent_times == plain.sent_times
        assert flow.cwnd == plain.cwnd
        assert flow.timestamp_rtt_observations == plain.timestamp_rtt_observations
        assert len(flow.segment_ack_completion_times) == flow.tcp_acked
        assert len(flow.segment_delivery_times) == flow.tcp_received
        assert len(flow.segment_ack_completion_times) > len(flow.ack_rtt_observations)
    row = metrics.deadline_metrics(observed, warmup_s=.01)
    assert row["with_drain_tcp_all_segment_ack_rtt_samples"] == sum(flow.tcp_acked for flow in observed.flows)
    assert row["with_drain_tcp_application_delivery_samples"] == sum(flow.tcp_received for flow in observed.flows)
