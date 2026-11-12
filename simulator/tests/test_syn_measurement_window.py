"""Regress same-window wire service and payload accounting for TCP SYN studies."""

import importlib
from pathlib import Path

import pytest

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from test_tcp_syn_probe import case as shared_task


def test_serialization_counts_partial_packets_and_excludes_queued_bytes():
    sim = Simulation(Scenario(20, 0), Traffic(), (PathConfig(),), Strategy("ARQ"), 42)
    sim.send(False, 1500, "source", lambda: None)
    sim.send(False, 1000, "source", lambda: None)
    link = sim.links[False][0]
    assert link.reserved_bytes == 2500
    assert link.serialized_bytes(0) == pytest.approx(0)
    start, end = .0001, .00013
    assert link.serialized_bytes(start) == pytest.approx(1250)
    assert link.serialized_bytes(end) == pytest.approx(1625)
    assert link.serialized_bytes(end) - link.serialized_bytes(start) == pytest.approx(
        link.bytes_per_s * (end - start))
    assert link.serialized_bytes(.01) == pytest.approx(2500)
    sim.now = .01
    sim.send(False, 500, "source", lambda: None)
    assert link.serialized_bytes(.01002) == pytest.approx(2750)


def test_quic_warmup_leaves_runtime_serialization_counters_empty():
    pytest.importorskip("aioquic")
    from l2tunnel_sim.tcp_syn_baseline import ProbeQUIC
    from test_tcp_syn_baseline import quic
    sim = quic(ProbeQUIC)
    for direction in sim.links:
        for link in direction:
            assert link.reserved_bytes == 0
            assert link.serialized_bytes(0) == 0


@pytest.mark.parametrize("kind", ["shared", "tcp", "quic", "compact"])
def test_probe_exports_one_interval_for_payload_and_both_wire_directions(monkeypatch, kind):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    if kind == "shared":
        study = importlib.import_module("aggregate_ack_deadlines")
        task = shared_task()
    else:
        study = importlib.import_module("tcp_syn_baseline_regression")
        if kind == "quic":
            pytest.importorskip("aioquic")
        profile = next(dict(item) for item in study.profiles()
                       if item["kind"] == ("quic" if kind == "quic" else "tcp"))
        profile.update(flow_count=2, window_bytes=1448 * 40, payload_rate_mbps=1)
        profile["tcp_syn_probe"] = dict(interval_ms=100, timeout_ms=100, reverse_copies=1,
            stability_window_s=.02, stability_windows=2, throughput_tolerance_pct=100,
            queue_tolerance_ms=10)
        task = dict(profile=profile, run_id=1, payload_bytes=1448, duration_s=.3,
            warmup_s=.01, drain_s=2, forward_mbps=100, reverse_mbps=10, rtt_ms=20,
            loss_rate=0, loss_model="iid", mtu=1500, seed=42, replication=1)
        if kind == "compact":
            profile = dict(study.compact_profiles()[0])
            profile.update(flow_count=2, window_bytes=1448 * 40, payload_rate_mbps=1,
                           tcp_syn_probe=task["profile"]["tcp_syn_probe"])
            task["profile"] = profile
    row = study.execute(task)
    prefix = "tcp_syn_ping_measurement_"
    start, end = (row[prefix + "snapshots"][key] for key in ("start", "end"))
    duration = row[prefix + "duration_s"]
    payload = row[prefix + "payload_bytes"]
    goodput = row["tcp_syn_ping_background_goodput_mbps"]
    assert start["at_s"] == row["tcp_syn_probe_start_s"]
    assert end["at_s"] == task["duration_s"]
    assert duration == end["at_s"] - start["at_s"]
    assert payload == end["delivered_payload_bytes"] - start["delivered_payload_bytes"]
    assert goodput == pytest.approx(payload * 8 / (duration * 1e6))
    for direction in ("forward", "reverse"):
        wire = row[prefix + direction + "_ip_bytes"]
        assert wire == pytest.approx(
            end[direction + "_serialized_ip_bytes"] - start[direction + "_serialized_ip_bytes"])
        assert row[prefix + direction + "_mbps"] == pytest.approx(wire * 8 / (duration * 1e6))
        assert row[prefix + direction + "_mbps"] <= task[direction + "_mbps"] + 1e-6
    overhead = row[prefix + "extra_forward_ip_pct"]
    assert goodput * (1 + overhead / 100) == pytest.approx(row[prefix + "forward_mbps"])
    assert all(start["at_s"] <= probe["started_at"] <= probe["completed_at"] <= end["at_s"]
               for probe in row["tcp_syn_probe_records"])
