"""Passive stage attribution preserves event order, state, and wire accounting."""

from pathlib import Path

import pytest


@pytest.fixture
def stages(monkeypatch):
    pytest.importorskip("aioquic")
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    import aligned_latency_stages
    return aligned_latency_stages


def task(**changes):
    profile = dict(name="passive aligned attribution", wire_format="aligned_records",
                   compact=dict(header_profile="tcp_delta", repair_ratio=.208,
                                independent_delivery=True, repair_window_sources=128,
                                global_repair_every=16, elide_payload_length=True),
                   window_bytes=65536, flow_count=4, payload_rate_mbps=10,
                   ack_coalesce_ms=.25, ack_copies=3, rto_min_ms=1000)
    result = dict(profile=profile, payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
                  rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500,
                  duration_s=.12, warmup_s=.02, drain_s=3, seed=42)
    result.update(changes)
    return result


def without_compute(row):
    return {key: value for key, value in row.items() if key != "compute_seconds"}


@pytest.mark.parametrize("loss,model", [(0, "iid"), (.15, "iid"), (.15, "burst")])
def test_probe_and_auditor_preserve_plain_runner_results_and_exact_events(stages, loss, model):
    value = task(loss_rate=loss, loss_model=model)
    plain = stages.normal.execute(value)
    control, _, control_events = stages.observe(value, stages=False)
    observed, probe, observed_events = stages.observe(value)
    assert without_compute(plain) == without_compute(control) == without_compute(observed)
    assert control_events == observed_events
    assert control_events["scheduled_events"] == control_events["dispatched_events"]
    rows = probe.segment_rows()
    assert len(rows) == observed["offered_frames"]
    assert sum(row["end_ack_censored"] for row in rows) == 0
    for row in rows:
        assert sum(row[name] for name in stages.STAGES) == pytest.approx(row["all_segment_ack_rtt_ms"])
    summary = stages.summarize_stages(rows, observed["latency_budget_ms"], value["rtt_ms"])
    assert summary["all_segment_ack_p99_ms"] == pytest.approx(observed["with_drain_tcp_all_segment_ack_rtt_p99_ms"])
    assert len(probe.source_rows()) == observed["shared_source_count"]
    assert sum(source["protected_bytes"] for source in probe.source_rows()) == observed["shared_submitted_bytes"]


def manual_simulation(stages, *, duration=.001, elide=True):
    value = task(duration_s=duration, warmup_s=0, loss_rate=0)
    value["profile"].update(flow_count=1, payload_rate_mbps=.05792)
    value["profile"]["compact"]["elide_payload_length"] = elide
    sim = stages.normal.make_simulation(value)
    probe = stages.StageProbe(sim)
    sim.flows[0].produce()
    return sim, probe


def clock(sim, now):
    sim.now = now
    for flow in sim.flows:
        flow.now = now


def receive(sim, index, now):
    clock(sim, now)
    sim.shared_forward._receive_source(sim.shared_forward.sources[index])


def test_ready_systematic_data_waits_for_lost_context_and_retains_original_clock(stages):
    sim, probe = manual_simulation(stages)
    receive(sim, 1, .035)
    assert sim.flows[0].tcp_received == 0
    receive(sim, 0, .080)
    clock(sim, .115)
    sim.flows[0].on_ack(1, 0)
    row, = probe.segment_rows()
    assert row["original_submission_s"] == 0
    assert row["record_ready_s"] == .035
    assert row["channel_delivery_s"] == row["tcp_contiguous_delivery_s"] == .080
    assert row["ordered_channel_hol_ms"] == pytest.approx(45)
    assert row["hol_blocker_is_context"] is True
    assert row["all_sources_systematic"] is True
    assert row["all_segment_ack_rtt_ms"] == 115
    assert sum(row[name] for name in stages.STAGES) == pytest.approx(115)
    summary = stages.summarize_stages([row], 105, 70)
    assert summary["cohorts"]["over_budget"]["systematic_records_waiting_for_channel"] == 1
    assert summary["cohorts"]["over_budget"]["largest_excess_stage_counts"] == {"ordered_channel_hol_ms": 1}


def test_fragmented_record_is_ready_only_when_all_fragments_are_known(stages):
    sim, probe = manual_simulation(stages, duration=.3, elide=False)
    receive(sim, 0, .035)
    receive(sim, 1, .036)
    clock(sim, .2)
    sim.flows[0].peer_timestamp = .2
    sim.flows[0].produce()
    assert len(sim.shared_forward.sources) == 4
    receive(sim, 3, .24)
    assert "record_ready_s" not in probe.records[0, 2]
    receive(sim, 2, .31)
    row = probe.segment_rows()[1]
    assert row["source_count"] == 2
    assert row["source_ids"] == "2 3"
    assert row["record_ready_s"] == row["channel_delivery_s"] == .31
    assert row["traffic_delivery_censored"] is True
    assert row["end_delivery_censored"] is False


def test_recovery_known_time_is_distinct_from_later_systematic_receipt(stages):
    sim, probe = manual_simulation(stages)
    receive(sim, 0, .035)
    clock(sim, .09)
    shared = sim.shared_forward
    shared._new_known(shared.decoder.insert({1: 1}))
    shared._advance()
    receive(sim, 1, .12)
    row, = probe.segment_rows()
    assert row["record_ready_s"] == .09
    assert row["recovered_sources"] == 1
    assert row["all_sources_systematic"] is False
    assert probe.sources[1]["known_s"] == .09
    assert probe.sources[1]["systematic_arrival_s"] == .12
    assert len(probe.first_records) == 1


def test_censored_segments_and_queued_sources_remain_in_output(stages):
    value = task(duration_s=.05, warmup_s=0, drain_s=0, loss_rate=.99)
    row, probe, _ = stages.observe(value)
    segments = probe.segment_rows()
    assert len(segments) == row["offered_frames"] > 0
    assert all(segment["end_ack_censored"] for segment in segments)
    assert all(segment["all_segment_ack_rtt_ms"] is None for segment in segments)
    summary = stages.summarize_stages(segments, 105, 70)
    assert summary["end_censored_segments"] == row["offered_frames"]
    assert summary["all_segment_ack_p99_ms"] is None


def test_retransmission_mapping_keeps_the_first_record_and_original_submission(stages):
    sim, probe = manual_simulation(stages)
    clock(sim, .2)
    sim.flows[0].transmit_segment(0)
    receive(sim, 0, .25)
    receive(sim, 1, .25)
    for index in range(2, len(sim.shared_forward.sources)):
        receive(sim, index, .28)
    row, = probe.segment_rows()
    assert row["attempts"] == 2
    assert row["attempt"] == 1
    assert row["original_submission_s"] == 0
    assert row["record_serial"] == 1
    assert row["channel_delivery_s"] == .25


def test_probe_rejects_late_attachment(stages):
    sim = stages.normal.make_simulation(task())
    sim.flows[sim.startup_order[0]].produce()
    with pytest.raises(ValueError, match="before any submission"):
        stages.StageProbe(sim)


def test_source_identity_survives_sender_window_queue_and_later_feedback(stages):
    value = task(duration_s=.3, warmup_s=0, loss_rate=0)
    value["profile"].update(flow_count=1, payload_rate_mbps=.05792)
    value["profile"]["compact"]["block_sources"] = 2
    sim = stages.normal.make_simulation(value)
    probe = stages.StageProbe(sim)
    sim.flows[0].produce()
    clock(sim, .2)
    sim.flows[0].produce()
    assert len(probe.queue) == 1
    queued = probe.segment_rows()[1]
    assert queued["source_enqueue_s"] == .2
    assert queued["last_source_transmission_finish_s"] is None
    assert queued["record_ready_s"] is None
    receive(sim, 0, .25)
    receive(sim, 1, .25)
    clock(sim, .4)
    sim.shared_forward._receive_feedback(2, 0)
    assert not probe.queue
    assert probe.sources[2]["record"]["segment_id"] == 1
    assert probe.sources[2]["enqueue_s"] == .2
    assert probe.sources[2]["transmission_finish_s"] >= .4
