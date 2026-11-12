"""Serialized, delayed feedback must be the gate's only receiver state."""

import importlib
from pathlib import Path
import subprocess
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
study = importlib.import_module("rtt_feedback_gate")
numeric_solutions = importlib.import_module("test_recursive_parity").numeric_solutions
from l2tunnel_sim.coding import Decoder, PRODUCT


def finite_validation():
    states = clean_equivalent = changed_unknown = erased_packets = 0
    for seed in (13, 29, 47):
        for old_lost in (False, True):
            size, old, recent = 160, 20, 150
            payload = [(index * 31 + 17) % 256 for index in range(size)]
            unknown = {recent, old} if old_lost else {recent}
            known = set(range(size)) - unknown
            sender = study.SenderGate(15)
            sender.accept(study.Snapshot(1, 16, 16, 0).encode(), 70.0368)
            start, mode = sender.choose(16, size, 80)
            assert (start, mode) == (32, "gated_local")
            local = study.packet_equation(start, size, seed)
            global_row = study.packet_equation(sender.base, size, seed)
            local_unknown = study.reduced_equation(local, known)
            global_unknown = study.reduced_equation(global_row, known)
            assert (local_unknown == global_unknown) == (not old_lost)
            clean_equivalent += not old_lost
            changed_unknown += old_lost
            for equation in (global_row, local):
                for erased in (False, True):
                    decoder = Decoder()
                    received = []
                    for source in sorted(known):
                        decoder.insert({source: 1})
                        received.append(({source: 1}, payload[source]))
                    if erased:
                        erased_packets += 1
                    else:
                        decoder.insert(equation)
                        value = 0
                        for source, weight in equation.items():
                            value ^= PRODUCT[weight][payload[source]]
                        received.append((equation, value))
                    solved = numeric_solutions(received, size)
                    assert set(solved) == decoder.known
                    assert all(value == payload[source] for source, value in solved.items())
                    if old_lost and not erased:
                        assert old not in solved
                        assert (recent in solved) == (equation == local)
                    states += 1
    return dict(independent_numeric_states=states, clean_old_equivalent_fixtures=clean_equivalent,
                unknown_old_different_fixtures=changed_unknown, erased_repair_packets=erased_packets,
                erased_value_equations_injected=0, actual_numeric_source_values_match=True,
                local_repair_retains_old_unknown_in_denominator=True)


def test_finite_numeric_decoding_and_clean_old_equivalence():
    receipt = finite_validation()
    assert receipt["independent_numeric_states"] == 24
    assert receipt["clean_old_equivalent_fixtures"] == 3
    assert receipt["unknown_old_different_fixtures"] == 3
    assert receipt["erased_repair_packets"] == 12


def test_snapshot_exact_wire_format_and_validation():
    snapshot = study.Snapshot(12, 34, 200, 15)
    encoded = snapshot.encode()
    assert len(encoded) == 18 and 28 + len(encoded) == 46
    assert study.Snapshot.decode(encoded) == snapshot
    for malformed in (encoded[:-1], encoded + b"\0",
                      study.FEEDBACK.pack(12, 34, 200, 15, 2, 0),
                      study.FEEDBACK.pack(12, 34, 200, 15, 1, 1),
                      study.FEEDBACK.pack(12, 201, 200, 15, 1, 0),
                      study.FEEDBACK.pack(12, 34, 200, 167, 1, 0)):
        with pytest.raises(ValueError):
            study.Snapshot.decode(malformed)


@pytest.mark.parametrize("freshness", (15, 30))
def test_startup_staleness_reported_debt_and_receive_time_freshness(freshness):
    sender = study.SenderGate(freshness)
    assert sender.choose(16, 700, 80) == (0, "startup_global")
    sender.accept(study.Snapshot(1, 10, 100, 5).encode(), 80)
    assert sender.choose(16, 700, 80 + freshness) == (572, "gated_local")
    assert sender.choose(16, 700, 80 + freshness + .001) == (10, "stale_global")
    sender.accept(study.Snapshot(2, 20, 400, 1).encode(), 120)
    assert sender.choose(16, 700, 120) == (20, "reported_debt_global")
    assert sender.choose(17, 700, 120) == (572, "ordinary_local")
    sender.accept(study.Snapshot(3, 20, 400, 0).encode(), 125)
    assert sender.choose(16, 700, 125) == (572, "gated_local")
    fixed = study.SenderGate(None)
    fixed.accept(study.Snapshot(1, 20, 400, 0).encode(), 125)
    assert fixed.choose(16, 700, 125) == (20, "fixed_global")


def test_lost_delayed_reordered_and_regressing_feedback():
    sender = study.SenderGate(15)
    payload = study.Snapshot(2, 10, 100, 0).encode()
    due = 70 + 46 * 8 / 10000
    # A generated or erased report has no effect before actual delivery.
    assert sender.choose(16, 600, due - .001) == (0, "startup_global")
    sender.accept(payload, due)
    assert sender.choose(16, 600, due) == (472, "gated_local")
    for old in (study.Snapshot(1, 9, 200, 1), study.Snapshot(3, 9, 200, 1)):
        sender.accept(old.encode(), due + 10)
        assert sender.latest.sequence == 2
        assert sender.received_at == due
    # Dropping the next report neither advances the prefix nor refreshes age.
    study.Snapshot(4, 100, 100, 0).encode()
    assert sender.choose(16, 600, due + 15.001) == (10, "stale_global")


def test_dense_control_matches_previous_causal_execution():
    task = dict(analytic_case_id=1, seed=23, source_count=1000, warmup_sources=100, tail_sources=100)
    old = study.reference.execute(dict(task, profile=study.reference.PROFILES[0]))
    new, _ = study.execute(dict(task, profile=study.PROFILES[0]))
    for field in ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
                  "recovered_only_created_to_known_p99_ms", "erasure_trace_sha256",
                  "forward_total_wire_bytes", "reverse_feedback_wire_bytes", "largest_repair_support",
                  "final_known_sources", "final_receiver_prefix", "final_sender_confirmed_prefix"):
        assert new[field] == old[field], field


def test_paired_schedules_budgets_rank_and_all_source_denominator():
    task = dict(analytic_case_id=1, seed=23, source_count=1000, warmup_sources=100, tail_sources=100)
    results = [study.execute(dict(task, profile=profile)) for profile in study.PROFILES]
    for field in ("repair_packets", "erasure_trace_sha256", "feedback_erasure_trace_sha256",
                  "packet_schedule_sha256", "source_arrival_trace_sha256", "forward_total_wire_bytes",
                  "reverse_feedback_wire_bytes", "measured_sources"):
        assert len({row[field] for row, _ in results}) == 1, field
    for row, diagnostics in results:
        assert row["measured_sources"] == 800
        assert row["repair_packets"] == 208
        assert row["minimum_feedback_age_ms"] >= 70
        assert sum(row["repair_mode_counts"].values()) == 208
        assert sum(row["innovative_equation_counts"].values()) == row["final_known_sources"] + row["full_horizon_residual_equation_rank"]
        assert row["full_horizon_unknown_count"] == 1000 - row["final_known_sources"]
        assert row["full_horizon_rank_deficit"] >= 0
        assert row["deadline_miss_count"] >= row["unresolved_count"]
        assert row["modified_slots"] == len(diagnostics)
        for slot in diagnostics:
            assert slot["reduced_equations_identical"] == (slot["old_unknown_nonzero_coefficients"] == 0)
            assert slot["actual_rank_gain"] == 0 if slot["erased"] else slot["actual_rank_gain"] in (0, 1)
    assert results[1][0]["modified_slots"] > 0


@pytest.mark.parametrize("loss", (0, 1))
def test_complete_loss_and_lossless_keep_all_measured_sources(loss):
    row, _ = study.execute(dict(analytic_case_id=1, profile=study.PROFILES[1], seed=23,
        source_count=600, warmup_sources=50, tail_sources=50, loss_rate=loss))
    assert row["measured_sources"] == 500
    assert row["deadline_miss_count"] == row["unresolved_count"] == 500 * loss
    assert row["full_horizon_unknown_count"] == 600 * loss
    assert row["final_known_sources"] == 600 * (1 - loss)


@pytest.mark.parametrize("as_module", (False, True))
def test_cli_help_from_repository_root(as_module):
    root = Path(__file__).resolve().parents[2]
    arguments = ["-m", "simulator.studies.rtt_feedback_gate"] if as_module else ["simulator/studies/rtt_feedback_gate.py"]
    result = subprocess.run([sys.executable, *arguments, "--help"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--workers" in result.stdout


def test_renderer_has_all_cases_fixed_colors_and_separate_frontiers(tmp_path, monkeypatch):
    rows = []
    for index, profile in enumerate(study.PROFILES):
        for replication, seed in enumerate(study.SEEDS):
            rows.append(dict(analytic_case_id=3 * index + replication + 1, policy=profile["name"], seed=seed,
                deadline_miss_fraction=.03 + index * .01, unresolved_at_horizon_fraction=.01 if index == 1 else 0,
                recovered_only_created_to_known_p99_ms=70 + index, ideal_application_service_ceiling_mbps=80.0885,
                deadline_miss_count=3 + index, unresolved_count=1 if index == 1 else 0, measured_sources=100,
                modified_slots=4 if index else 0, modified_slots_clean_old_equivalent=2,
                modified_slots_with_different_reduced_equation=2, modified_received_innovative=2,
                modified_received_slots=3, full_horizon_unknown_count=2, full_horizon_rank_deficit=1))
    captured = {}

    def html(figure, **kwargs):
        captured["figure"] = figure.to_plotly_json()
        return '<div id="feedback-gate-pareto"></div>'

    monkeypatch.setattr(study.go.Figure, "to_html", html)
    study.render(tmp_path, rows, study.summarize(rows))
    traces = captured["figure"]["data"]
    raw = [trace for trace in traces if trace["meta"]["kind"] == "raw-case"]
    assert len(raw) == 12
    for profile in study.PROFILES:
        selected = [trace for trace in raw if trace["name"] == profile["name"]]
        assert len(selected) == 4
        assert len({trace["marker"]["color"] for trace in selected}) == 1
    for axis in ("x", "x2", "x3", "x4"):
        assert {case for trace in raw if trace["xaxis"] == axis for case in trace["ids"]} == {
            str(row["analytic_case_id"]) for row in rows}
    assert len([trace for trace in traces if trace["meta"]["kind"] == "mean-frontier"]) == 2
