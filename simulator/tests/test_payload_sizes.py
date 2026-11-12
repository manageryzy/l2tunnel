"""Keep protocol RTT measurements and payload-size accounting distinct."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("aioquic")

spec = importlib.util.spec_from_file_location(
    "payload_size_study", Path(__file__).resolve().parents[1] / "studies/payload_sizes.py"
)
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


def task(profile, size=256):
    return dict(run_id=1, profile={**profile, "window_bytes": size * 10}, forward_mbps=100,
                reverse_mbps=10, rtt_ms=20, loss_rate=0, loss_model="iid", payload_bytes=size,
                duration_s=.15, warmup_s=.03, drain_s=.3, replication=1, seed=42)


def test_native_tcp_payload_frame_lengths_and_three_rtt_measurements():
    row = study.execute(task(study.default_profiles()[0]))
    assert row["payload_bytes_per_frame"] == 256
    assert row["forward_l2_bytes"] == row["released_frames"] * 322
    assert row["tcp_ack_rtt_samples"] > 0
    assert row["tcp_timestamp_rtt_samples"] == row["tcp_srtt_samples"]
    assert row["tcp_timestamp_rtt_p50_ms"] >= 20
    assert row["tcp_srtt_at_measurement_end_ms"] > 0
    assert row["quic_latest_rtt_p50_ms"] is None


def test_real_quic_qlog_rtt_excludes_tls_warmup_and_has_no_tcp_rtt():
    sim = study.make_simulation(task(study.default_profiles()[1]))
    assert sim.loggers[False].trace.rtt_observations == []
    sim.run()
    metrics = study.rtt_metrics(sim, .03)
    assert metrics["quic_latest_rtt_samples"] > 0
    assert 20 <= metrics["quic_latest_rtt_p50_ms"] < 25
    assert metrics["tcp_ack_rtt_p50_ms"] is None
    assert metrics["tcp_timestamp_rtt_p50_ms"] is None
    assert all(time >= 0 for time, _, _ in sim.loggers[False].trace.rtt_observations)


def test_compact_profiles_preserve_small_payload_sizes_and_relative_pacing():
    profile = {**study.default_profiles()[2], "payload_rate_capacity_pct": 80}
    sim = study.make_simulation(task(profile, 64))
    assert sim.traffic.frame_bytes == 130 and sim.traffic.payload_bytes == 64
    assert sim.traffic.frame_interval_ms == pytest.approx(64 * 8 / 80000)
    row = study.execute(task(profile, 64))
    assert row["forward_l2_bytes"] == row["released_frames"] * 130
    assert row["tcp_timestamp_rtt_p99_ms"] is not None


def test_main_and_drain_inclusive_rtt_samples_use_distinct_time_windows():
    sim = study.make_simulation(task(study.default_profiles()[0]))
    sim.ack_rtt_observations = [(.01, 20), (.10, 30), (.20, 200)]
    sim.timestamp_rtt_observations = [(.01, 21, 21), (.10, 31, 22), (.20, 201, 44)]
    metrics = study.rtt_metrics(sim, .03)
    assert metrics["tcp_ack_rtt_p50_ms"] == 25
    assert metrics["steady_tcp_ack_rtt_p50_ms"] == 30
    assert metrics["with_drain_tcp_ack_rtt_p99_ms"] > 190
    assert metrics["tcp_srtt_at_measurement_end_ms"] == 22
    assert metrics["tcp_srtt_final_ms"] == 44


def test_independent_tcp_flows_pool_actual_rtt_and_share_fixed_capacity_and_window():
    profile = {**study.default_profiles()[2], "flow_count": 4}
    settings = task(profile)
    sim = study.make_simulation(settings)
    assert all(flow.links is sim.links for flow in sim.flows)
    assert sum(flow.traffic.window_bytes for flow in sim.flows) == 2560
    sim.run()
    metrics = study.rtt_metrics(sim, settings["warmup_s"])
    expected = sum(sum(now <= settings["duration_s"] for now, _, _ in flow.timestamp_rtt_observations)
                   for flow in sim.flows)
    assert metrics["tcp_timestamp_rtt_samples"] == expected > 0
    assert len({id(flow.compact_forward) for flow in sim.flows}) == 4
    row = study.execute(settings)
    assert row["flow_count"] == 4
    assert row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
    assert row["tcp_delivered_frames"] == row["offered_frames"]
    assert row["forward_wire_bytes_during_measurement"] <= 100 * 125000 * settings["duration_s"]
