"""Independent arithmetic, packet-loss correlation and causal budget fixtures."""

import importlib
from itertools import product
from pathlib import Path
import sys
from unittest.mock import patch

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("partial_repair_screen")
reference = importlib.import_module("rtt_checkpoint_repairs")


def multiply(left, right):
    value = 0
    while right:
        if right & 1:
            value ^= left
        left <<= 1
        if left & 256:
            left ^= 0x11d
        right >>= 1
    return value


def numeric_identified(equations, values):
    """Independent dense elimination including actual two-byte right sides."""
    count = len(values)
    matrix = []
    for equation in equations:
        row = [equation.get(index, 0) for index in range(count)] + [0, 0]
        for index, factor in equation.items():
            for byte in range(2):
                row[count + byte] ^= multiply(factor, values[index][byte])
        matrix.append(row)
    pivot = 0
    for column in range(count):
        selected = next((index for index in range(pivot, len(matrix)) if matrix[index][column]), None)
        if selected is None:
            continue
        matrix[pivot], matrix[selected] = matrix[selected], matrix[pivot]
        inverse = next(value for value in range(1, 256) if multiply(matrix[pivot][column], value) == 1)
        matrix[pivot] = [multiply(value, inverse) for value in matrix[pivot]]
        for index, row in enumerate(matrix):
            if index != pivot and row[column]:
                factor = row[column]
                matrix[index] = [left ^ multiply(factor, right) for left, right in zip(row, matrix[pivot])]
        pivot += 1
    result = {}
    for row in matrix:
        nonzero = [index for index in range(count) if row[index]]
        if len(nonzero) == 1:
            result[nonzero[0]] = bytes(row[count:])
    return result


def test_numeric_half_decoder_and_lost_observations():
    values = [[bytes(((source * 37 + lane * 83 + byte * 19) & 255) for byte in range(2))
               for source in range(4)] for lane in range(2)]
    # Systematic 0 is absent. The first two repair observations independently
    # supply its two halves. No encoded values enter on erased observations.
    events = [({1: 1}, 0), ({2: 1}, 0), ({3: 1}, 0),
              ({0: 1, 1: 2}, 1), ({0: 1, 1: 2}, 2),
              ({0: 7, 2: 9}, 0)]
    states = 0
    for lost in product((False, True), repeat=3):
        decoder = study.HalfDecoder(4)
        equations = [[], []]
        for event, (equation, kind) in enumerate(events):
            if event < 3 or not lost[event - 3]:
                decoder.receive(equation, kind, event + .1)
                for lane in ((0, 1) if kind == 0 else (kind - 1,)):
                    equations[lane].append(equation)
            numerical = [numeric_identified(equations[lane], values[lane]) for lane in range(2)]
            for lane in range(2):
                assert set(numerical[lane]) == decoder.lanes[lane].known
                assert all(value == values[lane][source] for source, value in numerical[lane].items())
            complete = set(numerical[0]) & set(numerical[1])
            assert set(np.flatnonzero(np.isfinite(decoder.complete_at))) == complete
            states += 1
        if all(lost):
            assert not np.isfinite(decoder.complete_at[0])
    assert states == 48


def test_complete_source_waits_for_second_half_and_header_is_self_describing():
    decoder = study.HalfDecoder(2)
    decoder.receive({1: 1}, 0, .1)
    header = study.repair_header(0, 2, 13, 1)
    first, kind = study.parse_repair(header)
    assert len(header) == 12 and kind == 1
    decoder.receive(first, kind, .2)
    assert 0 in decoder.lanes[0].known and 0 not in decoder.lanes[1].known
    assert not np.isfinite(decoder.complete_at[0]) and decoder.prefix == 0
    second, kind = study.parse_repair(study.repair_header(0, 2, 13, 2))
    assert first == second and kind == 2
    decoder.receive(second, kind, .2616)
    assert decoder.complete_at[0] == .2616 and decoder.prefix == 2


def test_coupled_numeric_payloads_and_split_rows():
    count = 4
    values = [bytes(((half * 37 + byte * 73) & 255) for byte in range(2)) for half in range(2 * count)]
    full = study.parse_coupled_repair(study.repair_header(0, count, 13, 0, coupled=True))
    split = [study.parse_coupled_repair(study.repair_header(0, count, 13, kind, coupled=True))[0] for kind in (1, 2)]
    assert full == split
    assert full[0] != full[1]
    assert all(set(equation) == set(range(2 * count)) for equation in full)
    states = 0
    for losses in product((False, True), repeat=3):
        decoder = study.CoupledDecoder(count)
        equations = []
        events = [([{2: 1}, {3: 1}], False), ([{4: 1}, {5: 1}], False),
                  ([{6: 1}, {7: 1}], False), ([split[0]], losses[0]),
                  ([split[1]], losses[1]),
                  (study.parse_coupled_repair(study.repair_header(0, count, 14, 0, coupled=True)), losses[2])]
        for index, (incoming, erased) in enumerate(events):
            if not erased:
                decoder.receive(incoming, 0, index + .1)
                equations.extend(incoming)
            numerical = numeric_identified(equations, values)
            assert set(numerical) == decoder.decoder.known
            assert all(value == values[half] for half, value in numerical.items())
            whole = {source for source in range(count) if 2 * source in numerical and 2 * source + 1 in numerical}
            assert whole == set(np.flatnonzero(np.isfinite(decoder.complete_at)))
            states += 1
        if all(losses):
            assert not np.isfinite(decoder.complete_at[0])
    assert states == 48


def task(profile, count=1000):
    return dict(analytic_case_id=1, profile=profile, seed=20261110,
                source_count=count, warmup_sources=100, tail_sources=100)


def test_full_vector_reference_matches_two_lanes_at_fixed_80mbps():
    actual = study.execute(task(study.PROFILES[0]))
    control = dict(name=study.PROFILES[0]["name"], checkpoint=0, burst=False)
    with patch.object(reference, "ARRIVAL_MS", study.ARRIVAL_MS):
        expected = reference.execute(task(control))
    for metric in ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
                   "recovered_only_created_to_known_p99_ms", "sender_queue_p99_ms",
                   "maximum_source_queue_ms", "forward_total_wire_bytes", "reverse_feedback_packets",
                   "lost_feedback_packets", "delivered_feedback_reports", "final_receiver_prefix", "final_sender_confirmed_prefix"):
        assert actual[metric] == expected[metric], metric
    assert actual["common_source_and_repair_first_erasure_sha256"] == expected["erasure_trace_sha256"]
    assert actual["single_vector_control_equivalence_events"] > 1000


def test_exact_budget_paired_losses_and_queue_charges(tmp_path):
    rows = [study.execute(task(profile), tmp_path / f"{index}.csv") for index, profile in enumerate(study.PROFILES)]
    assert study.split_positions(2) == (13, 26)
    assert study.split_positions(4) == (6, 13, 19, 26)
    for row, groups, cost, extra in zip(rows, (0, 0, 16, 32), (1808, 1808, 1808.64, 1809.28), (20.8, 20.8, 22.4, 24)):
        assert row["split_repair_groups"] == groups
        assert row["ip_bytes_per_original_source"] == cost
        assert row["extra_packets_per_original_source_pct"] == extra
        assert row["forward_serialization_ms"] == row["forward_total_wire_bytes"] * 8 / 100000
        assert row["maximum_source_queue_ms"] > 0
        assert row["minimum_feedback_age_ms"] >= 70.0368 - 1e-10
        assert row["maximum_reverse_queue_ms"] == 0
        assert row["measured_sources"] == 800
        assert not row["strict_20pct_packet_cap_met"]
        assert row["ideal_application_service_ceiling_mbps"] > 80
        assert row["parity_bytes"] == 208 * 1460
    for key in ("common_source_and_repair_first_erasure_sha256", "common_candidate_second_half_erasure_sha256",
                "source_creation_times_sha256"):
        assert len({row[key] for row in rows}) == 1
    assert len({row["actual_datagram_erasure_sha256"] for row in rows}) == 3
    assert len((tmp_path / "0.csv").read_text().splitlines()) == 1001


def test_last_partial_credit_does_not_gain_flush_packets():
    row = study.execute(task(study.PROFILES[3], count=1003))
    assert row["repair_groups"] == 1003 * 26 // 125
    assert row["split_repair_groups"] == 32
    assert row["repair_packets"] == 240


def test_report_all_points_and_consistent_colors(tmp_path):
    rows = []
    for index, profile in enumerate(study.PROFILES):
        row = study.execute(task(profile))
        row.update(analytic_case_id=index + 1, source_observations_path=f"source-observations/{index + 1:03d}.csv")
        rows.append(row)
    with patch.object(study.go.Figure, "to_html", autospec=True, return_value="chart") as rendered:
        study.render(tmp_path, rows, study.summarize(rows))
    figure = rendered.call_args.args[0]
    for profile in study.PROFILES:
        traces = [trace for trace in figure.data if trace.meta["kind"] == "raw-case" and trace.name == profile["name"]]
        assert len(traces) == 2
        assert len({trace.marker.color for trace in traces}) == 1
    assert sum(len(trace.ids) for trace in figure.data if trace.meta["kind"] == "raw-case") == 8
