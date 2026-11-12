import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

pytest.importorskip("aioquic")

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.compact import CompactHeaderCodec
from l2tunnel_sim.experiment import measure
from l2tunnel_sim.quic import QUIC
from l2tunnel_sim.tcp_syn_baseline import BaselineHandshakeProbe, CompactHandshakeProbe, ProbeQUIC
from l2tunnel_sim.tcp_syn_probe import Probe, SYNProbeConfig, connection_tuple, handshake_frame


@pytest.fixture
def study(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    return importlib.import_module("tcp_syn_baseline_regression")


def task(study, kind="tcp", *, duration=.3, drain=2, loss=0):
    profile = next(item for item in study.profiles() if item["kind"] == kind)
    profile.update(flow_count=2, window_bytes=1448 * 40, payload_rate_mbps=1)
    profile["tcp_syn_probe"] = dict(interval_ms=100, timeout_ms=100, reverse_copies=1,
        stability_window_s=.02, stability_windows=2, throughput_tolerance_pct=100, queue_tolerance_ms=10)
    return dict(profile=profile, run_id=1, payload_bytes=1448, duration_s=duration, warmup_s=.01,
        drain_s=drain, forward_mbps=100, reverse_mbps=10, rtt_ms=20, loss_rate=loss,
        loss_model="iid", mtu=1500, seed=42, replication=1)


def quic(factory, *, payload=1448, loss=0):
    return factory(Scenario(20, loss), Traffic(duration_s=.001, drain_s=2,
        payload_bytes=payload, frame_bytes=payload + 66, window_bytes=payload * 5),
        (PathConfig(),), Strategy("QUIC L2", mode="quic"), 42)


@pytest.mark.parametrize("payload", [64, 1448])
@pytest.mark.parametrize("loss", [0, .15])
def test_disabled_control_preserves_original_quic_results(payload, loss):
    original = measure(quic(QUIC, payload=payload, loss=loss).run())
    adapted = measure(quic(ProbeQUIC, payload=payload, loss=loss).run())
    assert adapted == original


@pytest.mark.parametrize("kind", ["tcp", "quic"])
def test_normal_entry_stable_probe_and_bulk_counts_remain_separate(study, kind):
    row = study.execute(task(study, kind))
    assert row["tcp_syn_probe_steady_state_reached"]
    assert row["tcp_syn_probe_start_s"] >= .04
    assert row["tcp_syn_ping_offered"] > 0
    assert row["tcp_syn_ping_completed"] == row["tcp_syn_ping_offered"]
    assert row["tcp_syn_ping_failure_pct"] == 0
    assert row["tcp_syn_ping_p99_ms"] >= 20
    assert row["fully_confirmed"] and row["tcp_syn_probe_all_flushed"]
    assert row["tcp_syn_probe_dispatch"] == "received-header TCP four-tuple and flags"
    assert row["tcp_syn_probe_dispatch_rejections"] == {}
    assert row["tcp_acked_frames"] == row["tcp_delivered_frames"] == row["offered_frames"]
    assert row["forward_l2_bytes"] == row["offered_frames"] * (1448 + 66)
    assert all(probe["started_at"] < row["tcp_syn_probe_admission_end_s"] for probe in row["tcp_syn_probe_records"])
    count = row["tcp_syn_ping_offered"]
    if kind == "tcp":
        assert row["tcp_syn_probe_forward_departed_bytes"] == 3 * count * 52
        assert row["tcp_syn_probe_reverse_departed_bytes"] == count * 52
    else:
        assert row["tcp_syn_probe_forward_quic_stream_submitted_bytes"] == 3 * count * 68
        assert row["tcp_syn_probe_reverse_quic_stream_submitted_bytes"] == count * 76
        assert row["tcp_syn_probe_reverse_departed_bytes"] is None
        for direction in ("forward", "reverse"):
            assert row[f"tcp_syn_probe_{direction}_quic_stream_submitted_bytes"] == row[f"tcp_syn_probe_{direction}_quic_stream_acknowledged_bytes"]
            assert row[f"tcp_syn_probe_{direction}_quic_containing_packet_bytes"] <= row[direction + "_wire_bytes"]


@pytest.mark.parametrize("reverse", [False, True])
def test_auxiliary_stream_recovers_actual_packet_losses(study, reverse):
    case = task(study, "quic", duration=.3, drain=3)
    sim = study.make_simulation(case)
    probe = BaselineHandshakeProbe(sim, SYNProbeConfig(interval_ms=100, timeout_ms=200),
                                  start_s=.01, wait_for_stability=False)
    decisions = iter([True, True, False] + [False] * 10000)
    sim.links[reverse][0].erasures.lost = lambda: next(decisions)
    sim.run()
    assert sim.flows[0].control_confirmed
    assert probe.measurements()["tcp_syn_ping_completed"] == probe.measurements()["tcp_syn_ping_offered"]
    assert all(flow.tcp_received == flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    if reverse:
        assert sim.flows[0].control_retransmitted[True] > 0


def test_mixed_bulk_and_auxiliary_packet_retains_exact_record_boundaries():
    sim = ProbeQUIC(Scenario(20, 0), Traffic(duration_s=.001, drain_s=2, window_bytes=1448),
                   (PathConfig(),), Strategy("QUIC L2", mode="quic"), 42)
    sim.sent_times.append(0)
    sim.forward.pending[0] = True
    sim.forward.pending_bytes = 1448
    sim.connections[False].send_stream_data(0, sim.record)
    delivered = []
    body = bytes(range(66))
    sim.submit_control(False, body, delivered.append)
    assert set(sim.sent_packets) & set(sim.control_packets[False])
    sim.run()
    assert delivered == [body]
    assert sim.tcp_received == sim.tcp_acked == 1
    assert sim.stream_received_bytes == 1514
    assert sim.stream_sent_end == 1514
    assert sim.control_received[False] == sim.control_submitted[False] == 68
    assert sim.control_confirmed


def test_auxiliary_ack_ranges_cannot_grant_bulk_credit():
    sim = quic(ProbeQUIC)
    sim.control_submitted[False] = 100
    sim.control_packets[False][900] = [(50, 100)]
    packet = {"frames": [{"frame_type": "ack", "acked_ranges": [[900, 900]]}]}
    sim.observe_packet(False, packet)
    assert sim.tcp_acked == 0
    assert not sim.control_confirmed
    sim.control_packets[False][901] = [(0, 50)]
    sim.observe_packet(False, {"frames": [{"frame_type": "ack", "acked_ranges": [[901, 901]]}]})
    assert sim.control_confirmed
    assert sim.tcp_acked == 0


def test_all_reverse_loss_preserves_probe_timeout_and_unconfirmed_quic_bytes(study):
    case = task(study, "quic", duration=.15, drain=.3)
    sim = study.make_simulation(case)
    probe = BaselineHandshakeProbe(sim, SYNProbeConfig(interval_ms=100, timeout_ms=100),
                                  start_s=.01, wait_for_stability=False)
    sim.links[True][0].erasures.lost = lambda: True
    sim.run()
    row = probe.measurements()
    assert row["tcp_syn_ping_timeouts"] == row["tcp_syn_ping_offered"] == 1
    assert row["tcp_syn_ping_p99_ms"] is None
    assert row["tcp_syn_ping_failure_pct"] == 100
    assert not row["tcp_syn_probe_all_flushed"]


@pytest.mark.parametrize("kind", ["tcp", "quic"])
def test_no_steady_load_keeps_zero_probe_metrics_missing(study, kind):
    case = task(study, kind, duration=.2, drain=.1, loss=1)
    row = study.execute(case)
    assert row["tcp_syn_ping_offered"] == 0
    assert not row["tcp_syn_probe_steady_state_reached"]
    assert row["tcp_syn_ping_p99_ms"] is None
    assert not row["tcp_syn_ping_joint_target_met"]


def test_extra_native_or_quic_response_copies_are_rejected(study):
    sim = study.make_simulation(task(study))
    with pytest.raises(ValueError, match="one native TCP response"):
        BaselineHandshakeProbe(sim, SYNProbeConfig(reverse_copies=3))


def test_matrix_is_paired_and_first_seed_covers_all_twelve_cases(study):
    plan = study.tasks()
    assert len(plan) == 45
    assert len({case["seed"] for case in plan[:12]}) == 1
    assert {(case["profile"]["kind"], case["payload_bytes"]) for case in plan[:12]} == {
        (kind, payload) for kind in ("tcp", "quic") for payload in study.PAYLOADS}
    assert all([case["seed"] for case in plan if case["profile"]["kind"] == kind and case["payload_bytes"] == payload]
        == [plan[index]["seed"] for index in (0, 12, 24)] for kind in ("tcp", "quic") for payload in study.PAYLOADS)
    assert len(plan[36:]) == 9
    assert {case["profile"]["recovery"] for case in plan[36:]} == {"arq", "rlnc", "block"}
    assert all(case["payload_bytes"] == 1448 and case["profile"]["flow_count"] == 16
               and case["profile"]["window_bytes"] == 4 * 1048576 for case in plan[36:])
    assert study.tasks(include_compact=False) == plan[:36]


def test_compact_payload_matrix_and_explicit_native_averaging_keep_independent_profiles(study):
    rates = [8, 20, 40, 70, 78, 80.05]
    plan = study.tasks(include_baselines=False, compact_all_payloads=True, payload_rates=rates)
    assert len(plan) == 54
    assert {case["profile"]["kind"] for case in plan} == {"compact"}
    for case in plan:
        assert case["profile"]["payload_rate_mbps"] == rates[study.PAYLOADS.index(case["payload_bytes"])]
    native = study.tasks(1200, include_compact=False, baseline_kinds=("tcp",), stability_window=30)
    assert len(native) == 18
    assert all(case["duration_s"] == 1200 and case["profile"]["kind"] == "tcp" for case in native)
    assert all(case["profile"]["tcp_syn_probe"]["stability_window_s"] == 30 for case in native)
    assert all(case["profile"]["tcp_syn_probe"]["stability_window_s"] == 1 for case in plan)
    assert study.profiles()[0]["tcp_syn_probe"]["stability_window_s"] == 1
    block = study.tasks(include_baselines=False, compact_all_payloads=True, compact_recoveries=("block",))
    assert len(block) == 18
    assert {case["profile"]["recovery"] for case in block} == {"block"}
    assert [case["run_id"] for case in block] == list(range(1, 19))
    small = study.tasks(include_baselines=False, compact_all_payloads=True, compact_recoveries=("rlnc",),
                        payloads=(64,), payload_rates=[6, 20, 40, 70, 78, 80.05])
    assert len(small) == 3
    assert all(case["payload_bytes"] == 64 and case["profile"]["payload_rate_mbps"] == 6 for case in small)
    assert [case["seed"] for case in small] == [case["seed"] for case in block[::6]]


def compact_task(study, recovery, *, reliable=False):
    case = task(study)
    case["profile"] = next(profile for profile in study.compact_profiles() if profile["recovery"] == recovery)
    case["profile"].update(flow_count=2, window_bytes=1448 * 40, payload_rate_mbps=1,
                          reliable_acks=reliable, tcp_syn_probe=task(study)["profile"]["tcp_syn_probe"])
    return case


@pytest.mark.parametrize("recovery", ["arq", "rlnc", "block"])
@pytest.mark.parametrize("reliable", [False, True])
def test_compact_normal_entry_preserves_bulk_and_probe_confirmation(study, recovery, reliable):
    row = study.execute(compact_task(study, recovery, reliable=reliable))
    assert row["tcp_syn_ping_offered"] > 0
    assert row["tcp_syn_ping_completed"] == row["tcp_syn_ping_offered"]
    assert row["fully_confirmed"] and row["tcp_syn_probe_all_flushed"]
    assert row["tcp_acked_frames"] == row["tcp_delivered_frames"] == row["offered_frames"]
    assert row["forward_l2_bytes"] == row["offered_frames"] * 1514
    count = row["tcp_syn_ping_offered"]
    assert row["tcp_syn_probe_forward_compact_records"] == count * 3
    assert row["tcp_syn_probe_forward_compact_context_bytes"] >= count * 69
    if reliable:
        assert row["tcp_syn_probe_reverse_compact_records"] == count
        assert row["tcp_syn_probe_reverse_compact_context_bytes"] >= count * 69
        assert row["tcp_syn_probe_reverse_requested_bytes"] == 0
    else:
        assert row["tcp_syn_probe_reverse_compact_records"] == 0
        assert row["tcp_syn_probe_reverse_requested_bytes"] == row["tcp_syn_probe_reverse_departed_bytes"] == count * 102


@pytest.mark.parametrize("recovery", ["arq", "rlnc", "block"])
def test_compact_probe_bytes_roundtrip_through_bulk_context_and_lost_prefix(study, recovery):
    case = compact_task(study, recovery, reliable=True)
    sim = study.make_simulation(case)
    sim.startup_order = [0, 1]
    sim.flows[0].next_source = 0
    sim.flows[1].next_source = .01
    probe = CompactHandshakeProbe(sim, SYNProbeConfig(interval_ms=100, timeout_ms=200),
                                  start_s=.001, wait_for_stability=False)
    captured = [[], []]
    for direction, transport in enumerate((sim.flows[0].compact_forward, sim.flows[0].compact_reverse)):
        original = transport.header_codec.encode
        decoder = CompactHeaderCodec(delta=True)

        def encode(frame, original=original, decoder=decoder, direction=direction):
            encoded = original(frame)
            assert decoder.decode(encoded) == [frame]
            captured[direction].append(frame)
            return encoded

        transport.header_codec.encode = encode
    lost = iter([True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(lost)
    sim.run()
    row = probe.measurements()
    assert row["tcp_syn_ping_completed"] == row["tcp_syn_ping_offered"] == 1
    assert row["tcp_syn_probe_all_flushed"]
    assert all(flow.tcp_received == flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    assert {frame[47] for frame in captured[False] if len(frame) == 66} >= {0x02, 0x10, 0x14}
    assert any(frame[47] == 0x12 for frame in captured[True])
    assert sum(len(frame) > 66 for frame in captured[False]) > 0
    assert sim.flows[0].compact_forward.profile_context_bytes >= row["tcp_syn_probe_forward_compact_context_bytes"] + 69
    if recovery == "arq":
        # The SYN follows lost bulk bytes in the same ordered stream.
        assert row["tcp_syn_probe_records"][0]["server_started_at"] > .03


def test_native_adapter_uses_all_bulk_flows_without_unused_channel_limit(study):
    case = task(study)
    case["profile"].update(flow_count=256, window_bytes=1448 * 256)
    sim = study.make_simulation(case)
    probe = BaselineHandshakeProbe(sim, SYNProbeConfig(timeout_ms=100))
    for flow in sim.flows:
        flow.tcp_received = 1
    assert probe.bulk_received() == 256


def test_auxiliary_records_reassemble_after_loss_across_multiple_datagrams():
    sim = quic(ProbeQUIC)
    lost = iter([True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(lost)
    bodies = [bytes(range(256)) * 20, b"second record"]
    delivered = []
    for body in bodies:
        sim.submit_control(False, body, delivered.append)
    sim.run()
    assert delivered == bodies
    assert sim.control_submitted[False] == sum(len(body) + 2 for body in bodies)
    assert sim.control_confirmed
    assert sim.control_retransmitted[False] > 0
    assert sim.tcp_received == sim.tcp_acked == len(sim.sent_times)


def test_terminal_failure_is_explicit_without_invented_metrics(study, monkeypatch):
    case = task(study)
    case["profile"]["kind"] = "invalid"
    monkeypatch.setattr(study, "execution_receipts", lambda: {"fixture": "receipt"})
    row = study.terminal_execute(case)
    assert row["execution_status"] == "error"
    assert row["application_goodput_mbps"] is None
    assert not row["fully_confirmed"]
    assert row["executed_source_receipts"] == {"fixture": "receipt"}


def test_explicit_plan_retains_original_profiles_seeds_and_order(study, tmp_path):
    cases = [compact_task(study, "block"), task(study, "tcp"), task(study, "quic")]
    for index, case in enumerate(cases, 1):
        case["run_id"] = index
    cases.reverse()
    path = tmp_path / "task-plan.json"
    path.write_text(json.dumps(dict(tasks=cases, provenance="finite fixture")))
    assert study.load_task_plan(path) == cases


@pytest.mark.parametrize("change", [
    {"forward_mbps": 300}, {"reverse_mbps": 100}, {"payload_bytes": 1},
    {"duration_s": float("inf")}, {"warmup_s": 1}, {"seed": True}, {"run_id": 0},
])
def test_explicit_plan_rejects_invalid_conditions(study, tmp_path, change):
    case = task(study)
    case.update(change)
    path = tmp_path / "task-plan.json"
    path.write_text(json.dumps(dict(tasks=[case])))
    with pytest.raises(ValueError):
        study.load_task_plan(path)


def test_explicit_plan_rejects_duplicate_identity(study, tmp_path):
    case = task(study)
    path = tmp_path / "task-plan.json"
    path.write_text(json.dumps(dict(tasks=[case, case])))
    with pytest.raises(ValueError, match="unique positive"):
        study.load_task_plan(path)


def test_explicit_plan_frozen_execution_and_policy_resume(study, tmp_path):
    output = tmp_path / "explicit-cli-fixture"
    cases = [task(study, "quic", duration=.001, drain=0), compact_task(study, "block")]
    for index, case in enumerate(cases, 1):
        case.update(run_id=index, duration_s=.001, warmup_s=0, drain_s=0)
    path = tmp_path / "task-plan.json"
    path.write_text(json.dumps(dict(tasks=cases)))
    command = [sys.executable, str(Path(study.__file__).resolve()), "--out", str(output),
               "--task-plan", str(path), "--single-phase", "--workers", "2"]
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((output / "experiment.json").read_text())
    assert manifest["tasks"] == cases
    assert manifest["task_plan_sha256"] == study.digest(path)
    assert manifest["execution_policy"] == dict(single_phase=True)
    original = (output / "runs/00001.json").read_bytes()
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (output / "runs/00001.json").read_bytes() == original
    command.remove("--single-phase")
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=120)
    assert result.returncode != 0
    assert "execution policy differs" in result.stderr


@pytest.mark.parametrize("baseline_only,expected_count", [(False, 15), (True, 12)])
def test_frozen_cli_execution_resume_and_corrupt_receipt_rejection(study, tmp_path, baseline_only, expected_count):
    output = tmp_path / "finite-cli-fixture"
    command = [sys.executable, str(Path(study.__file__).resolve()), "--out", str(output),
               "--duration", ".001", "--warmup", "0", "--drain", "0", "--replications", "1", "--workers", "2"]
    if baseline_only:
        command.append("--baseline-only")
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((output / "experiment.json").read_text())
    assert len(manifest["tasks"]) == expected_count
    verification = json.loads((output / "source-verification.json").read_text())
    assert verification["executed_from_frozen_sources"]
    assert not verification["changed_during_run"]
    assert verification["verified_run_ids"] == list(range(1, expected_count + 1))
    raw_path = output / "runs/00001.json"
    original = raw_path.read_bytes()
    row = json.loads(original)
    study.validate_saved(row, manifest["tasks"][0], output, manifest)
    assert row["execution_status"] == "completed"
    assert all(Path(receipt["path"]).is_relative_to(output / "sources")
               for receipt in row["executed_source_receipts"].values())
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert raw_path.read_bytes() == original
    row["source_manifest_sha256"] = "wrong"
    raw_path.write_text(json.dumps(row))
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=120)
    assert result.returncode != 0
    assert "different source manifest" in result.stderr


@pytest.mark.parametrize("kind", ["tcp", "quic", "compact"])
def test_adapter_received_bytes_override_original_submitter_identity(study, monkeypatch, kind):
    case = compact_task(study, "arq") if kind == "compact" else task(study, kind)
    case["duration_s"] = .001
    sim = study.make_simulation(case)
    endpoint_type = CompactHandshakeProbe if kind == "compact" else BaselineHandshakeProbe
    endpoint = endpoint_type(sim, SYNProbeConfig(timeout_ms=100))
    first, second = Probe(0, 1, 0, syn_attempts=1), Probe(1, 2, 0, syn_attempts=1)
    endpoint.probes.extend((first, second))
    endpoint.probe_connections.update({connection_tuple(probe): probe for probe in (first, second)})
    module = importlib.import_module("l2tunnel_sim.tcp_syn_baseline")

    def swap_initial_syn(probe, **kwargs):
        return handshake_frame(second if probe is first and kwargs["flags"] == 0x02 else probe, **kwargs)

    monkeypatch.setattr(module, "handshake_frame", swap_initial_syn)
    endpoint.send_forward(first, 0x02)
    sim.run()
    assert first.server_started_at is None and first.completed_at is None
    assert second.server_started_at is not None and second.completed_at is not None
    assert second.server_established and second.server_closed
    assert endpoint.received_frame_counts == [3, 1]
    assert not endpoint.dispatch_rejections
    if kind == "quic":
        assert sim.flows[0].control_confirmed
        assert sim.flows[0].control_submitted == [3 * 68, 76]
    assert all(flow.tcp_received == flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
