"""Prevent false target qualification from mixed intervals or source baselines."""

import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("matplotlib")

spec = importlib.util.spec_from_file_location(
    "goal_report_study", Path(__file__).resolve().parents[1] / "studies/goal_report.py"
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


def replication(**changes):
    row = dict(study="fixture", name="Candidate", compact=json.dumps({"coding": "gf256"}),
               controller="cubic", rto_min_ms="200", reliable_acks="False", seed="1",
               loss_model="iid", forward_mbps="100", rtt_ms="70", duration_s="10",
               warmup_s="2", drain_s="5", offered_frames="70000", tcp_delivered_frames="70000",
               tcp_acked_frames="70000", outer_all_confirmed="True", payload_bytes_per_frame="1448",
               tcp_payload_bytes_during_measurement="101360000", forward_datagrams="84000",
               forward_source_datagrams="80000", steady_forward_datagrams="69440",
               steady_delivered_frames="56000", frame_p99_ms="100", steady_frame_p99_ms="101",
               full_target_met="True", steady_target_met="True")
    return {**row, **changes}


def test_full_and_steady_target_use_their_own_raw_packet_counters():
    whole = report.observation(replication(), "Whole transfer")
    steady = report.observation(replication(), "Post-warmup")
    assert whole["extra_packets_pct"] == pytest.approx(20)
    assert whole["capacity_pct"] == pytest.approx(81.088)
    assert whole["target_met"]
    assert steady["extra_packets_pct"] == pytest.approx(24)
    assert not steady["target_met"]
    assert not report.observation(replication(forward_datagrams="86000"), "Whole transfer")["target_met"]


@pytest.mark.parametrize("changes", [
    {"outer_all_confirmed": ""}, {"tcp_acked_frames": "69999"},
    {"compact": json.dumps({"coding": "ideal"})},
])
def test_unconfirmed_and_ideal_points_cannot_enter_the_frontier(changes):
    summaries = report.summarize([replication(**changes)])
    assert all(not row["eligible"] and row["target_passes"] == 0 for row in summaries)
    assert not report.frontier(summaries)


def test_different_conditions_and_duplicate_seeds_preserve_sampling_boundaries():
    summaries = report.summarize([replication(), replication(seed="2", rtt_ms="150")])
    assert len(report.groups(summaries)) == 4
    with pytest.raises(ValueError, match="duplicate replication seeds"):
        report.summarize([replication(), replication()])
    with pytest.raises(ValueError, match="payload exceeds"):
        report.observation(replication(tcp_payload_bytes_during_measurement="101360001"), "Whole transfer")
