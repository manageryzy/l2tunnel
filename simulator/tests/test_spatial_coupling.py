"""Independent finite source-generator and parity-check validation."""

import importlib
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("rtt_spatial_coupling")
from l2tunnel_sim.coding import Decoder, INVERSE, PRODUCT


def inverse_matrix(matrix):
    size = len(matrix)
    rows = [list(row) + [int(index == column) for column in range(size)]
            for index, row in enumerate(matrix)]
    for column in range(size):
        pivot = next(index for index in range(column, size) if rows[index][column])
        rows[column], rows[pivot] = rows[pivot], rows[column]
        multiply = PRODUCT[INVERSE[rows[column][column]]]
        rows[column] = [multiply[value] for value in rows[column]]
        for index in range(size):
            factor = rows[index][column]
            if index != column and factor:
                rows[index] = [a ^ PRODUCT[factor][b] for a, b in zip(rows[index], rows[column])]
    assert [row[:size] for row in rows] == [[int(i == j) for j in range(size)] for i in range(size)]
    return [row[size:] for row in rows]


def add_scaled(target, other, factor):
    for source, value in other.items():
        combined = target.get(source, 0) ^ PRODUCT[factor][value]
        if combined:
            target[source] = combined
        else:
            target.pop(source, None)


def independent_expansion(lift, section, previous):
    """Construct the encoder directly, independently of block_entries/constraints."""
    alpha = [1]
    for _ in range(8):
        alpha.append(PRODUCT[alpha[-1]][2])
    same_parity = [[int(row == column) ^ (2 if column == (row + 1) % lift else 0)
                    for column in range(lift)] for row in range(lift)]
    inverse = inverse_matrix(same_parity)
    rhs = []
    for row in range(lift):
        value = {}
        for column in range(5):
            base = section * 5 * lift + column * lift
            value[base + (row + column) % lift] = 1
            value[base + (row + column + 3) % lift] = alpha[column + 2]
            lag = 1 if column % 2 else 2
            if section >= lag:
                earlier = (section - lag) * 5 * lift + column * lift
                shift = column * column + (2 if lag == 2 else 0)
                value[earlier + (row + shift) % lift] = alpha[column + 1]
        if section:
            add_scaled(value, previous[section - 1][(row + 25) % lift], alpha[6])
        rhs.append(value)
    result = []
    for row in inverse:
        equation = {}
        for factor, value in zip(row, rhs):
            add_scaled(equation, value, factor)
        result.append(equation)
    return result


def numeric_solutions(equations, size):
    rows = [[equation.get(column, 0) for column in range(size)] + [value]
            for equation, value in equations]
    pivot = 0
    for column in range(size):
        selected = next((index for index in range(pivot, len(rows)) if rows[index][column]), None)
        if selected is None:
            continue
        rows[pivot], rows[selected] = rows[selected], rows[pivot]
        products = PRODUCT[INVERSE[rows[pivot][column]]]
        rows[pivot] = [products[value] for value in rows[pivot]]
        for index in range(len(rows)):
            if index != pivot and rows[index][column]:
                multiply = PRODUCT[rows[index][column]]
                rows[index] = [a ^ multiply[b] for a, b in zip(rows[index], rows[pivot])]
        pivot += 1
    solved = {}
    for row in rows:
        nonzero = [index for index, value in enumerate(row[:-1]) if value]
        if len(nonzero) == 1:
            solved[nonzero[0]] = row[-1]
        if not nonzero:
            assert row[-1] == 0
    return solved


def finite_validation():
    events = erased_parities = numeric_states = structural_rows = startup_slots = 0
    for lift in (4, 8):
        for pattern in (0, 1, 2):
            count = 20 * lift + 3
            payload = [(source * 17 + 29) % 256 for source in range(count)]
            expanded, augmented, shifted = Decoder(), Decoder(), Decoder()
            encodings, received, constraints = {}, [], []
            serial = 0

            def equivalent():
                nonlocal events
                assert expanded.known == {symbol for symbol in augmented.known if symbol < count}
                assert expanded.known == {symbol for symbol in shifted.known if symbol < count}
                events += 1

            def observed(equation):
                value = 0
                for symbol, weight in equation.items():
                    value ^= PRODUCT[weight][payload[symbol]]
                received.append((equation, value))

            for source in range(count):
                if pattern == 0 or (source + pattern) % 5:
                    expanded.insert({source: 1})
                    augmented.insert({source: 1})
                    shifted.insert({source: 1})
                    observed({source: 1})
                equivalent()
                if (source + 1) % (5 * lift) == 0:
                    section = (source + 1) // (5 * lift) - 1
                    encodings[section] = independent_expansion(lift, section, encodings)
                    for equation in study.section_constraints(count, lift, section):
                        expanded_constraint = {}
                        for symbol, weight in equation.items():
                            if symbol < count:
                                add_scaled(expanded_constraint, {symbol: 1}, weight)
                            else:
                                parity_section, index = divmod(symbol - count, lift)
                                add_scaled(expanded_constraint, encodings[parity_section][index], weight)
                        assert expanded_constraint == {}
                        augmented.insert(equation)
                        shifted.insert({symbol + 100000 if symbol >= count else symbol: weight
                                        for symbol, weight in equation.items()})
                        constraints.append((equation, 0))
                        structural_rows += 1
                        equivalent()
                target = 26 * (source + 1) // 125
                if target == serial:
                    continue
                serial = target
                mode, section, index = study.repair_slot(serial, lift)
                if mode == "startup-zero":
                    startup_slots += 1
                    equation = {}
                elif mode == "global":
                    seed = serial * 2654435761 & 0xffffffff
                    equation = {symbol: study.coefficient(seed, symbol) for symbol in range(source + 1)}
                else:
                    assert (section + 1) * 5 * lift <= source + 1
                    equation = encodings[section][index]
                    assert max(equation) < (section + 1) * 5 * lift
                lost = pattern and (serial + pattern) % 4 in (0, 1)
                before = set(augmented.known)
                if lost:
                    erased_parities += 1
                    assert augmented.known == before
                else:
                    expanded.insert(equation)
                    if mode == "spatial":
                        augmented.insert({study.parity_id(count, lift, section, index): 1})
                        shifted.insert({study.parity_id(count, lift, section, index) + 100000: 1})
                    else:
                        augmented.insert(equation)
                        shifted.insert(equation)
                    observed(equation)
                equivalent()
                if serial % 8 == 0:
                    solved = numeric_solutions(received, count)
                    assert set(solved) == expanded.known
                    assert all(value == payload[symbol] for symbol, value in solved.items())
                    numeric_states += 1
            assert len(encodings) == 4
            assert count % (5 * lift) == 3
    return dict(event_comparisons=events, independent_numeric_states=numeric_states,
                erased_parity_packets=erased_parities, checked_structural_rows=structural_rows,
                charged_startup_slots_checked=startup_slots,
                same_section_inverse_checked=True, expanded_equals_augmented_at_every_event=True,
                actual_numeric_source_values_match=True, structural_equations_independent_of_receipt=True,
                shifted_parity_namespace_preserves_every_source_identification=True,
                erased_parity_value_equations_injected=0, final_partial_section_unencoded=True)


def test_independent_numeric_parity_check_and_generator_equivalence():
    receipt = finite_validation()
    assert receipt["event_comparisons"] > 800
    assert receipt["independent_numeric_states"] > 10
    assert receipt["erased_parity_packets"] > 0
    assert receipt["erased_parity_value_equations_injected"] == 0


@pytest.mark.parametrize("lift", (4, 8))
def test_interior_parity_check_degrees_and_causal_pipeline(lift):
    count = 1000
    all_equations = [equation for section in range(5) for equation in study.section_constraints(count, lift, section)]
    for equation in study.section_constraints(count, lift, 3):
        assert len(equation) == 18
    for column in range(6):
        for index in range(lift):
            symbol = 2 * 5 * lift + column * lift + index if column < 5 else study.parity_id(count, lift, 2, index)
            assert sum(symbol in equation for equation in all_equations) == 3
    startup = 0
    for serial in range(1, 4161):
        mode, section, index = study.repair_slot(serial, lift)
        transmitted_sources = (125 * serial + 25) // 26
        if mode == "spatial":
            assert (section + 1) * 5 * lift <= transmitted_sources
        if mode == "startup-zero":
            startup += 1
    assert startup == lift


def test_dense_g26_matches_reference_with_the_same_global_schedule():
    task = dict(analytic_case_id=0, profile=study.PROFILES[0], seed=20261110,
                source_count=1000, warmup_sources=100, tail_sources=100)

    def support(profile, end, base, serial, final=False):
        return (base if serial % 26 == 0 else max(base, end - 128)), end

    with patch.object(study.reference, "support", support):
        expected = study.reference.execute(dict(task, profile=dict(task["profile"], burst=False, checkpoint=0)))
    actual = study.execute(task)
    for field in ("deadline_miss_fraction", "unresolved_at_horizon_fraction", "recovered_only_created_to_known_p99_ms",
                  "forward_total_wire_bytes", "reverse_feedback_wire_bytes", "final_known_sources", "final_receiver_prefix",
                  "final_sender_confirmed_prefix", "minimum_feedback_age_ms", "sender_queue_p99_ms", "erasure_trace_sha256"):
        assert actual[field] == expected[field]


def test_fixed_wire_arrivals_feedback_startup_and_unflushed_horizon():
    task = dict(analytic_case_id=0, seed=19, source_count=1003, warmup_sources=100, tail_sources=100)
    cases = [study.execute(dict(task, profile=profile)) for profile in study.PROFILES]
    for field in ("repair_packets", "erasure_trace_sha256", "feedback_erasure_trace_sha256", "forward_total_wire_bytes",
                  "reverse_feedback_wire_bytes", "source_arrival_trace_sha256", "measured_sources", "horizon_ms"):
        assert len({row[field] for row in cases}) == 1
    for case in cases[1:]:
        assert case["charged_startup_zero_packets"] == case["profile"]["lift"]
        assert case["startup_zero_wire_bytes"] == case["profile"]["lift"] * 1500
        assert case["unassembled_partial_section_sources"] == 3
        assert case["assembled_unsent_parity_symbols"] > 0
        assert case["structural_source_identifications"] == 0
        assert case["deadline_miss_count"] >= case["unresolved_count"]
        assert case["uncharged_termination_packets"] == 0


def test_renderer_keeps_every_case_and_consistent_colors(tmp_path, monkeypatch):
    rows = []
    for profile_index, profile in enumerate(study.PROFILES):
        for replication, seed in enumerate(study.SEEDS):
            rows.append(dict(analytic_case_id=profile_index * 3 + replication + 1, profile=profile, policy=profile["name"],
                seed=seed, deadline_miss_fraction=.03 + profile_index * .01, unresolved_at_horizon_fraction=0.,
                recovered_only_created_to_known_p99_ms=70 + profile_index, ideal_application_service_ceiling_mbps=80.0885,
                deadline_miss_count=480 + profile_index * 160, unresolved_count=0, global_repair_packets=160,
                dense_repair_packets=4000 if profile_index == 0 else 0, spatial_repair_packets=4000 if profile_index else 0,
                charged_startup_zero_packets=0, assembled_unsent_parity_symbols=0))
    captured = {}

    def html(figure, **kwargs):
        captured["figure"] = figure.to_plotly_json()
        return '<div id="spatial-coupling-pareto"></div>'

    monkeypatch.setattr(study.go.Figure, "to_html", html)
    study.render(tmp_path, rows, study.summarize(rows))
    traces = [trace for trace in captured["figure"]["data"] if trace["meta"]["kind"] == "raw-case"]
    assert len(traces) == 12
    for axis in ("x", "x2", "x3", "x4"):
        assert {case for trace in traces if trace["xaxis"] == axis for case in trace["ids"]} == {str(i) for i in range(1, 10)}
    for profile in study.PROFILES:
        assert len({trace["marker"]["color"] for trace in traces if trace["name"] == profile["name"]}) == 1


@pytest.mark.parametrize("module", (False, True))
def test_cli_entrypoints(module):
    root = Path(__file__).resolve().parents[2]
    arguments = ["-m", "simulator.studies.rtt_spatial_coupling"] if module else ["simulator/studies/rtt_spatial_coupling.py"]
    result = subprocess.run([sys.executable, *arguments, "--help"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
