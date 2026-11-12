"""Source bridging must preserve byte causality and original-source accounting."""

import importlib
from pathlib import Path
import subprocess
import sys

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("source_bridge_diagnostic")
control = importlib.import_module("partial_repair_screen")


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


def numeric_known(equations, values):
    """Independent dense Gauss-Jordan with actual byte right-hand sides."""
    count = len(values)
    matrix = []
    for equation in equations:
        row = [equation.get(source, 0) for source in range(count)] + [0, 0]
        for source, factor in equation.items():
            for byte in range(2):
                row[count + byte] ^= multiply(factor, values[source][byte])
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


def test_header_round_trip_and_full1460byte_causal_inverse():
    originals = [bytes((source * 37 + byte * 19) & 255 for byte in range(1460)) for source in range(259)]
    recovered = []
    for source, value in enumerate(originals):
        header = study.source_header(source, True)
        source_id, equation = study.source_equation(header)
        assert len(header) == 8 and source_id == source
        assert max(equation) == source and min(equation) >= 0
        coded = bytearray(1460)
        for index in equation:
            for byte in range(1460):
                coded[byte] ^= originals[index][byte]
        for index in equation:
            if index < source:
                for byte in range(1460):
                    coded[byte] ^= recovered[index][byte]
        recovered.append(bytes(coded))
        assert recovered[-1] == value
    assert recovered == originals  # No termination symbols at the partial end.
    assert study.source_equation(study.source_header(128, True))[1] == {128: 1, 0: 1}
    assert study.source_equation(study.source_header(128, False))[1] == {128: 1}
    with pytest.raises(ValueError):
        study.source_equation(study.SOURCE_HEADER.pack(128, 1, 1, 64))


@pytest.mark.parametrize("bridge_packet_lost", (False, True))
def test_old_source_rescued_through_local_repair_with_independent_rhs(bridge_packet_lost):
    count = 130
    values = [bytes((source * 17 + byte * 73) & 255 for byte in range(2)) for source in range(count)]
    decoder, equations = study.Decoder(), []
    for source in range(1, count):
        _, equation = study.source_equation(study.source_header(source, True))
        if source == 128 and bridge_packet_lost:
            continue
        equations.append(equation)
        decoder.insert(equation)
    before = numeric_known(equations, values)
    assert set(before) == decoder.known
    assert 0 not in decoder.known and 128 not in decoder.known
    # Source0 has left W128. The repair contains original128 but excludes0.
    local, kind = study.parse_repair(study.repair_header(2, 130, 27, 0))
    assert kind == 0 and 0 not in local and local[128]
    equations.append(local)
    decoder.insert(local)
    after = numeric_known(equations, values)
    assert set(after) == decoder.known
    assert all(value == values[source] for source, value in after.items())
    assert 128 in decoder.known
    assert (0 in decoder.known) == (not bridge_packet_lost)
    systematic = study.Decoder()
    for source in range(1, count):
        systematic.insert({source: 1})
    systematic.insert(local)
    assert 0 not in systematic.known


def test_component_deficit_is_passive_and_includes_absent_sources():
    decoder = study.Decoder()
    decoder.insert({0: 1, 128: 1})
    before_rows = {key: value.copy() for key, value in decoder.rows.items()}
    state = study.component_state(decoder, 0, 130, 35)
    assert state["component_variables"] == 2 and state["component_rank"] == 1
    assert state["component_deficit"] == 1 and state["source_expired_from_local_window"]
    assert decoder.rows == before_rows and not decoder.known
    absent = study.component_state(decoder, 1, 130, 35)
    assert absent["component_variables"] == 1 and absent["component_rank"] == 0
    assert not absent["source_has_equation"]


def task(profile, count=1000):
    return dict(analytic_case_id=1, profile=profile, seed=20261110,
                source_count=count, warmup_sources=100, tail_sources=300)


def test_baseline_matches_saved_runner_and_physical_trace_is_paired(tmp_path):
    baseline = study.execute(task(study.PROFILES[0]))
    original = control.execute(task(control.PROFILES[0]))
    for field in ("deadline_miss_fraction", "unresolved_at_horizon_fraction", "recovered_only_created_to_known_p99_ms",
                  "sender_queue_p99_ms", "maximum_source_queue_ms", "forward_total_wire_bytes", "reverse_feedback_packets",
                  "lost_feedback_packets", "delivered_feedback_reports", "final_receiver_prefix", "final_sender_confirmed_prefix",
                  "full_source_recovery_times_sha256"):
        assert baseline[field] == original[field], field
    assert baseline["erasure_trace_sha256"] == original["actual_datagram_erasure_sha256"]
    candidate = study.execute(task(study.PROFILES[1]))
    for field in ("erasure_trace_sha256", "packet_trace_sha256", "source_arrival_trace_sha256", "forward_total_wire_bytes"):
        assert baseline[field] == candidate[field], field
    assert baseline["late_originals_with_received_source_datagram"] == 0
    assert candidate["minimum_feedback_age_ms"] >= 70.0368 - 1e-10
    assert candidate["measured_sources"] == 600
    assert candidate["sender_queue_p99_ms"] > 0


def test_last_partial_source_interval_has_no_extra_termination():
    row = study.execute(task(study.PROFILES[1], count=1003))
    assert row["forward_source_packets"] == 1003
    assert row["forward_repair_packets"] == 1003 * 26 // 125
    assert row["forward_total_wire_bytes"] == 1003 * 1496 + 208 * 1500
    assert row["measured_sources"] == 603


def test_both_cli_entrypoints():
    root = Path(__file__).resolve().parents[2]
    for arguments in (["simulator/studies/source_bridge_diagnostic.py", "--help"],
                      ["-m", "simulator.studies.source_bridge_diagnostic", "--help"]):
        result = subprocess.run([sys.executable, *arguments], cwd=root, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert "--workers" in result.stdout
