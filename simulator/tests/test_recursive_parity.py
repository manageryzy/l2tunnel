"""Validate recursive parity through independent graph and numeric representations."""

import importlib
from pathlib import Path
import subprocess
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("rtt_recursive_parity")
from l2tunnel_sim.coding import Decoder, INVERSE, PRODUCT


def numeric_solutions(equations, size):
    rows = [[equation.get(column, 0) for column in range(size)] + [value]
            for equation, value in equations]
    pivot_row = 0
    for column in range(size):
        candidate = next((index for index in range(pivot_row, len(rows)) if rows[index][column]), None)
        if candidate is None:
            continue
        rows[pivot_row], rows[candidate] = rows[candidate], rows[pivot_row]
        scale = PRODUCT[INVERSE[rows[pivot_row][column]]]
        rows[pivot_row] = [scale[value] for value in rows[pivot_row]]
        for index in range(len(rows)):
            if index != pivot_row and rows[index][column]:
                products = PRODUCT[rows[index][column]]
                rows[index] = [left ^ products[right] for left, right in zip(rows[index], rows[pivot_row])]
        pivot_row += 1
    solved = {}
    for row in rows:
        nonzero = [index for index, value in enumerate(row[:-1]) if value]
        if len(nonzero) == 1:
            solved[nonzero[0]] = row[-1]
        if not nonzero:
            assert row[-1] == 0
    return solved


def finite_validation():
    states = lost_parities = reset_events = 0
    for template in study.PROFILES[1:]:
        for loss_pattern in (0, 1, 2):
            profile = dict(template, reset=7)
            count = 120
            payload = [(source * 17 + 29) % 256 for source in range(count)]
            expanded, augmented = Decoder(), Decoder()
            received_equations = []
            symbolic_parity, parity_value = {}, 0
            serial = 0
            for source in range(count):
                source_lost = loss_pattern and (source + loss_pattern) % 5 == 0
                if not source_lost:
                    expanded.insert({source: 1})
                    augmented.insert({source: 1})
                    received_equations.append(({source: 1}, payload[source]))
                if 26 * (source + 1) // 125 == serial:
                    continue
                serial += 1
                restart = serial == study.epoch_start(serial, profile["reset"])
                if restart:
                    symbolic_parity, parity_value = {}, 0
                    reset_events += 1
                check = study.check_equation(profile, serial, source + 1)
                for symbol, weight in check.items():
                    value = symbolic_parity.get(symbol, 0) ^ weight
                    if value:
                        symbolic_parity[symbol] = value
                    else:
                        symbolic_parity.pop(symbol, None)
                    parity_value ^= PRODUCT[weight][payload[symbol]]
                expected = {symbol: study.expanded_coefficient(profile, serial, symbol)
                            for symbol in range(source + 1)}
                expected = {symbol: value for symbol, value in expected.items() if value}
                assert expected == symbolic_parity
                assert min(expected, default=source) >= study.source_start(profile, serial)
                constraint = dict(check)
                constraint[count + serial] = 1
                if not restart:
                    constraint[count + serial - 1] = 1
                augmented.insert(constraint)
                # A structural zero-RHS equation defines the latent parity. It
                # does not tell the receiver its actual value after erasure.
                assert expanded.known == {symbol for symbol in augmented.known if symbol < count}
                parity_lost = loss_pattern and (serial + loss_pattern) % 4 in (0, 1)
                if parity_lost:
                    lost_parities += 1
                else:
                    expanded.insert(expected)
                    augmented.insert({count + serial: 1})
                    received_equations.append((expected, parity_value))
                assert expanded.known == {symbol for symbol in augmented.known if symbol < count}
                solved = numeric_solutions(received_equations, count)
                assert set(solved) == expanded.known
                assert all(value == payload[symbol] for symbol, value in solved.items())
                states += 1
    return dict(independent_numeric_states=states, erased_parity_packets=lost_parities,
                reset_events=reset_events, source_only_equals_augmented_at_every_event=True,
                actual_numeric_source_values_match=True, erased_parity_value_equations_injected=0,
                cross_reset_taps_retained=True)


def test_numeric_rank_graph_equivalence_and_erased_parity_values():
    receipt = finite_validation()
    assert receipt["independent_numeric_states"] == 216
    assert receipt["erased_parity_packets"] > 0
    assert receipt["reset_events"] > 9
    assert receipt["erased_parity_value_equations_injected"] == 0


def test_taps_are_source_regular_nonzero_causal_and_in_distinct_age_bands():
    for profile in study.PROFILES[1:]:
        for source in range(500):
            first = 26 * source // 125 + 1
            taps = study.source_taps(source, profile["taps"], profile["width"])
            assert len(taps) == profile["taps"]
            assert len({check for check, weight in taps}) == len(taps)
            for edge, (check, weight) in enumerate(taps):
                assert first + edge * profile["width"] <= check < first + (edge + 1) * profile["width"]
                assert 1 <= weight <= 255
                assert (125 * check + 25) // 26 > source


def test_reset_keeps_future_edges_from_earlier_sources():
    profile = dict(study.PROFILES[2], reset=7)
    assert any(source < 25 for source in study.check_equation(profile, 8, 39))
    for source in range(39):
        assert study.expanded_coefficient(profile, 8, source) == study.check_equation(profile, 8, 39).get(source, 0)


def test_seed_roundtrip_and_header_span_bound():
    for profile in study.PROFILES[1:]:
        for serial in (1, 7, 255, 256, 257, 4160, 100000):
            seed = serial * study.SERIAL_MULTIPLIER & 0xffffffff
            assert seed * study.SERIAL_INVERSE & 0xffffffff == serial
            end = (125 * serial + 25) // 26
            assert 0 <= study.source_start(profile, serial) < end
            assert end - study.source_start(profile, serial) < 1500


def test_dense_control_preserves_reference_and_hooks_restore():
    task = dict(analytic_case_id=0, profile=study.PROFILES[0], seed=12,
                source_count=300, warmup_sources=50, tail_sources=50)
    original_support, original_coefficient = study.reference.support, study.reference.coefficient
    expected = study.reference.execute(task)
    actual = study.execute(task)
    assert {key: value for key, value in expected.items() if key != "record_kind"} == {
        key: actual[key] for key in expected if key != "record_kind"}
    assert study.reference.support is original_support
    assert study.reference.coefficient is original_coefficient


def test_candidate_preserves_charged_schedule_and_censored_denominator():
    task = dict(analytic_case_id=0, seed=19, source_count=500, warmup_sources=50, tail_sources=50)
    control = study.execute(dict(task, profile=study.PROFILES[0]))
    candidate = study.execute(dict(task, profile=study.PROFILES[2]))
    for field in ("repair_packets", "erasure_trace_sha256", "forward_total_wire_bytes",
                  "reverse_feedback_wire_bytes", "measured_sources"):
        assert control[field] == candidate[field]
    assert candidate["repair_packets"] == 104
    assert candidate["measured_sources"] == 400
    assert candidate["deadline_miss_count"] >= candidate["unresolved_count"]
    assert candidate["minimum_feedback_age_ms"] >= 70


@pytest.mark.parametrize("as_module", (False, True))
def test_cli_help_from_repository_root(as_module):
    root = Path(__file__).resolve().parents[2]
    arguments = ["-m", "simulator.studies.rtt_recursive_parity"] if as_module else ["simulator/studies/rtt_recursive_parity.py"]
    result = subprocess.run([sys.executable, *arguments, "--help"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--workers" in result.stdout


def test_renderer_preserves_every_case_and_policy_colors(tmp_path, monkeypatch):
    rows = []
    for index, profile in enumerate(study.PROFILES):
        for replication, seed in enumerate(study.SEEDS):
            rows.append(dict(analytic_case_id=3 * index + replication + 1,
                policy=profile["name"], seed=seed, deadline_miss_fraction=.03 + index * .01,
                unresolved_at_horizon_fraction=.01 if index else 0,
                recovered_only_created_to_known_p99_ms=70 + index,
                ideal_application_service_ceiling_mbps=80.0885, deadline_miss_count=3 + index,
                unresolved_count=1 if index else 0, measured_sources=100,
                largest_repair_support=1400, mean_emitted_check_source_degree=14,
                maximum_emitted_check_source_degree=25, parity_resets=17))
    captured = {}

    def html(figure, **kwargs):
        captured["figure"] = figure.to_plotly_json()
        return '<div id="recursive-parity-pareto"></div>'

    monkeypatch.setattr(study.go.Figure, "to_html", html)
    study.render(tmp_path, rows, study.summarize(rows))
    traces = captured["figure"]["data"]
    raw = [trace for trace in traces if trace["meta"]["kind"] == "raw-case"]
    assert len(raw) == 16
    for profile in study.PROFILES:
        selected = [trace for trace in raw if trace["name"] == profile["name"]]
        assert len(selected) == 4
        assert len({trace["marker"]["color"] for trace in selected}) == 1
    for axis in ("x", "x2", "x3", "x4"):
        assert {case for trace in raw if trace["xaxis"] == axis for case in trace["ids"]} == {
            str(row["analytic_case_id"]) for row in rows}
    frontiers = [trace for trace in traces if trace["meta"]["kind"] == "mean-frontier"]
    assert len(frontiers) == 2
    assert all(trace["text"] == [study.PROFILES[0]["name"]] for trace in frontiers)
