"""Replacement slots preserve latent recursion and the charged causal schedule."""

import importlib
from pathlib import Path
import subprocess
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
study = importlib.import_module("rtt_recursive_fallback")
numeric_solutions = importlib.import_module("test_recursive_parity").numeric_solutions
from l2tunnel_sim.coding import Decoder, PRODUCT


def finite_validation():
    states = replacements = erased_packets = reset_replacements = 0
    recursive_values_injected = fresh_values_injected = 0
    for template in study.PROFILES[2:]:
        for loss_pattern in (0, 1, 2):
            profile = dict(template, reset=7)
            count = 160
            payload = [(source * 19 + 37) % 256 for source in range(count)]
            expanded, latent = Decoder(), Decoder()
            received_equations = []
            symbolic_parity, parity_value = {}, 0
            serial = 0
            for source in range(count):
                if not loss_pattern or (source + loss_pattern) % 5:
                    expanded.insert({source: 1})
                    latent.insert({source: 1})
                    received_equations.append(({source: 1}, payload[source]))
                if 26 * (source + 1) // 125 == serial:
                    continue
                serial += 1
                restart = serial == study.recursive.epoch_start(serial, profile["reset"])
                if restart:
                    symbolic_parity, parity_value = {}, 0
                check = study.recursive.check_equation(profile, serial, source + 1)
                for symbol, weight in check.items():
                    value = symbolic_parity.get(symbol, 0) ^ weight
                    if value:
                        symbolic_parity[symbol] = value
                    else:
                        symbolic_parity.pop(symbol, None)
                    parity_value ^= PRODUCT[weight][payload[symbol]]
                direct = {symbol: study.recursive.expanded_coefficient(profile, serial, symbol)
                          for symbol in range(source + 1)}
                assert symbolic_parity == {symbol: value for symbol, value in direct.items() if value}
                constraint = dict(check)
                constraint[count + serial] = 1
                if not restart:
                    constraint[count + serial - 1] = 1
                latent.insert(constraint)
                assert expanded.known == {symbol for symbol in latent.known if symbol < count}
                mode = study.repair_mode(profile, serial)
                replacements += mode == "fallback"
                reset_replacements += mode == "fallback" and restart
                erased = loss_pattern and (serial + loss_pattern) % 4 in (0, 1)
                if erased:
                    erased_packets += 1
                else:
                    seed = serial * study.recursive.SERIAL_MULTIPLIER & 0xffffffff
                    equation = {symbol: study.repair_coefficient(profile, seed, symbol)
                                for symbol in range(source + 1)}
                    equation = {symbol: value for symbol, value in equation.items() if value}
                    expanded.insert(equation)
                    if mode == "recursive":
                        assert equation == symbolic_parity
                        latent.insert({count + serial: 1})
                        received_equations.append((equation, parity_value))
                        recursive_values_injected += 1
                    else:
                        latent.insert(equation)
                        fresh_value = 0
                        for symbol, weight in equation.items():
                            fresh_value ^= PRODUCT[weight][payload[symbol]]
                        received_equations.append((equation, fresh_value))
                        fresh_values_injected += 1
                assert expanded.known == {symbol for symbol in latent.known if symbol < count}
                solved = numeric_solutions(received_equations, count)
                assert set(solved) == expanded.known
                assert all(value == payload[symbol] for symbol, value in solved.items())
                states += 1
    return dict(independent_numeric_states=states, replacement_slots=replacements,
                erased_repair_packets=erased_packets, replacements_at_restart=reset_replacements,
                recursive_received_value_equations=recursive_values_injected,
                fresh_received_value_equations=fresh_values_injected,
                replaced_recursive_value_equations_injected=0, erased_packet_value_equations_injected=0,
                source_only_equals_latent_at_every_event=True, actual_numeric_source_values_match=True,
                recursive_state_advances_across_replacements=True)


def test_latent_expanded_numeric_equivalence_across_replacements_losses_and_resets():
    receipt = finite_validation()
    assert receipt["independent_numeric_states"] == 297
    assert receipt["replacement_slots"] == 21
    assert receipt["replacements_at_restart"] > 0
    assert receipt["fresh_received_value_equations"] > 0
    assert receipt["replaced_recursive_value_equations_injected"] == 0
    assert receipt["erased_packet_value_equations_injected"] == 0


def test_mode_and_coefficients_follow_existing_seed_and_profile():
    for profile in study.PROFILES[2:]:
        for serial in (1, 8, 16, 32, 255, 256, 257):
            seed = serial * study.recursive.SERIAL_MULTIPLIER & 0xffffffff
            fallback = serial % profile["fresh_interval"] == 0
            assert study.repair_mode(profile, serial) == ("fallback" if fallback else "recursive")
            for source in (0, 1, 11, 27):
                expected = study.recursive.coefficient(seed, source) if fallback else study.recursive.expanded_coefficient(profile, serial, source)
                assert study.repair_coefficient(profile, seed, source) == expected


@pytest.mark.parametrize("index", (0, 1))
def test_controls_match_previous_execution_exactly(index):
    task = dict(analytic_case_id=0, profile=study.PROFILES[index], seed=19,
                source_count=600, warmup_sources=100, tail_sources=100)
    old = study.recursive.execute(task)
    new = study.execute(task)
    for field in ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
                  "recovered_only_created_to_known_p99_ms", "erasure_trace_sha256",
                  "forward_total_wire_bytes", "reverse_feedback_wire_bytes", "largest_repair_support"):
        assert old[field] == new[field]


def test_replacements_charge_exactly_one_packet_and_preserve_delayed_feedback():
    task = dict(analytic_case_id=0, seed=23, source_count=500, warmup_sources=50, tail_sources=50)
    rows = [study.execute(dict(task, profile=profile)) for profile in study.PROFILES]
    for field in ("repair_packets", "erasure_trace_sha256", "forward_total_wire_bytes",
                  "reverse_feedback_wire_bytes", "measured_sources"):
        assert len({row[field] for row in rows}) == 1
    for row in rows[2:]:
        assert row["fallback_repair_packets"] == 104 // row["profile"]["fresh_interval"]
        assert row["recursive_repair_packets"] + row["fallback_repair_packets"] == 104
        assert row["minimum_feedback_age_ms"] >= 70
        assert row["deadline_miss_count"] >= row["unresolved_count"]
        assert row["full_horizon_unknown_count"] == 500 - row["final_known_sources"]
        assert row["full_horizon_rank_deficit"] == row["full_horizon_unknown_count"] - row["remaining_decoder_rows"]
        assert row["full_horizon_rank_deficit"] >= 0
    assert study.reference.support.__name__ == "support"
    assert study.reference.coefficient is study.recursive.coefficient


@pytest.mark.parametrize("as_module", (False, True))
def test_cli_help_from_repository_root(as_module):
    root = Path(__file__).resolve().parents[2]
    arguments = ["-m", "simulator.studies.rtt_recursive_fallback"] if as_module else ["simulator/studies/rtt_recursive_fallback.py"]
    result = subprocess.run([sys.executable, *arguments, "--help"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--workers" in result.stdout


def test_renderer_preserves_all_cases_colors_and_separate_mean_frontier(tmp_path, monkeypatch):
    rows = []
    for index, profile in enumerate(study.PROFILES):
        for replication, seed in enumerate(study.SEEDS):
            rows.append(dict(analytic_case_id=3 * index + replication + 1,
                policy=profile["name"], seed=seed, deadline_miss_fraction=.03 + index * .01,
                unresolved_at_horizon_fraction=.01 if index == 1 else 0,
                recovered_only_created_to_known_p99_ms=70 + index,
                ideal_application_service_ceiling_mbps=80.0885, deadline_miss_count=3 + index,
                unresolved_count=1 if index == 1 else 0, measured_sources=100,
                largest_repair_support=1400, dense_control_repair_packets=4160 if index == 0 else 0,
                recursive_repair_packets=3900 if index else 0, fallback_repair_packets=260 if index else 0,
                parity_resets=17 if index else 0))
    captured = {}

    def html(figure, **kwargs):
        captured["figure"] = figure.to_plotly_json()
        return '<div id="recursive-fallback-pareto"></div>'

    monkeypatch.setattr(study.go.Figure, "to_html", html)
    study.render(tmp_path, rows, study.summarize(rows))
    traces = captured["figure"]["data"]
    raw = [trace for trace in traces if trace["meta"]["kind"] == "raw-case"]
    assert len(raw) == 20
    for profile in study.PROFILES:
        selected = [trace for trace in raw if trace["name"] == profile["name"]]
        assert len(selected) == 4
        assert len({trace["marker"]["color"] for trace in selected}) == 1
    for axis in ("x", "x2", "x3", "x4"):
        assert {case for trace in raw if trace["xaxis"] == axis for case in trace["ids"]} == {
            str(row["analytic_case_id"]) for row in rows}
    assert len([trace for trace in traces if trace["meta"]["kind"] == "mean-frontier"]) == 2
