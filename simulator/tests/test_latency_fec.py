"""Verify actual FEC generation telemetry and observational equivalence."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("aioquic")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
try:
    import latency_fec
    import payload_sizes
finally:
    sys.path.pop(0)


def test_actual_block_histogram_and_repair_counts_are_transport_observations():
    forward = SimpleNamespace(code_blocks=[1, 5, 5, 4], sources=range(15),
                              initial_repairs=4, additional_repairs=2)
    reverse = SimpleNamespace(code_blocks=[], sources=[], initial_repairs=0, additional_repairs=0)
    metrics = latency_fec.block_metrics([SimpleNamespace(compact_forward=forward, compact_reverse=reverse)])
    assert json.loads(metrics["forward_block_histogram"]) == {"1": 1, "4": 1, "5": 2}
    assert metrics["forward_block_mean_sources"] == 3.75
    assert metrics["forward_block_p50_sources"] == 4.5
    assert metrics["forward_initial_repair_count"] == 4
    assert metrics["forward_additional_repairs_per_source_pct"] == pytest.approx(200 / 15)
    assert metrics["reverse_block_mean_sources"] is None


def task(idle):
    profile = dict(name="Observed block sizing", recovery="block", reliable_acks=False,
                   flow_count=2, rto_min_ms=1000, controller="cubic", window_bytes=1048576,
                   payload_rate_mbps=10, compact=dict(header_profile="tcp_delta", repair_ratio=.2,
                       generation_sources=5, idle_flush_ms=idle, maximum_block_ms=50, repair_margin=0))
    return dict(run_id=1, profile=profile, forward_mbps=100, reverse_mbps=10, rtt_ms=20,
                loss_rate=0, loss_model="iid", payload_bytes=1448, duration_s=.3,
                drain_s=.5, warmup_s=.05, replication=1, seed=42)


def test_idle_flush_can_preempt_generation_limit_and_telemetry_preserves_measurements():
    short = latency_fec.execute(task(2))
    batched = latency_fec.execute(task(4))
    reference = payload_sizes.execute(task(4))
    assert short["forward_block_mean_sources"] < 2
    assert batched["forward_block_mean_sources"] > 4
    assert batched["forward_block_max_sources"] == 5
    assert batched["forward_initial_repairs_per_source_pct"] < short["forward_initial_repairs_per_source_pct"]
    assert batched["forward_block_closed_sources"] == batched["forward_block_sources"]
    for key in ("application_goodput_mbps", "tcp_timestamp_rtt_p99_ms", "tcp_ack_rtt_p99_ms",
                "forward_datagrams", "reverse_datagrams", "forward_wire_bytes", "reverse_wire_bytes",
                "tcp_all_acknowledged", "outer_all_confirmed"):
        assert batched[key] == reference[key]
