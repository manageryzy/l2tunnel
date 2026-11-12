"""Causal bitmap-coded repairs use exact charged snapshot bytes."""

import importlib
import json
from pathlib import Path
from struct import error as StructError
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("rtt_bitmap_coded_fallback")


def snapshot(serial=1, bitmap=0b1010, highest=5):
    return study.previous.Feedback(serial, 0, 0, 4, highest, 0, bitmap).encode()


def test_reconstructs_actual_saved_report_bytes_and_excludes_unobserved_endpoint():
    payload = snapshot(highest=4, bitmap=0b0010)
    sender = study.BitmapSender()
    sender.accept_payload(payload, 75)
    header = sender.bitmap_header(16)
    equation, high, serial = study.repair_equation(header, {1: payload})
    seed = 16 * study.previous.SERIAL_MULTIPLIER & 0xffffffff
    assert equation == {index: study.coefficient(seed, index) for index in (0, 2)}
    assert high == 4 and serial == 16
    assert len(header) + 28 + 1460 == 1500
    assert study.missing_ids(study.previous.Feedback.decode(payload)) == (0, 2)


def test_missing_report_and_mismatched_count_fail_explicitly():
    sender = study.BitmapSender()
    sender.accept_payload(snapshot(), 75)
    header = sender.bitmap_header(16)
    with pytest.raises(ValueError, match="missing emitted report"):
        study.repair_equation(header, {})
    serial, count, seed, kind = study.REPAIR_FIELDS.unpack(header)
    with pytest.raises(ValueError, match="identity or count"):
        study.repair_equation(study.REPAIR_FIELDS.pack(serial, count - 1, seed, kind), {1: snapshot()})


def test_latest_delivered_snapshot_survives_reordered_feedback_and_future_decoding():
    sender = study.BitmapSender()
    assert sender.bitmap_header(16) is None
    sender.accept_payload(snapshot(2, bitmap=0b1110), 80)
    header = sender.bitmap_header(16)
    sender.accept_payload(snapshot(1, bitmap=0b1011), 85)
    assert sender.latest_report == 2 and sender.latest_delivered_ms == 80
    assert sender.bitmap_header(16) == header
    assert 0 in sender.confirmed
    equation, _, _ = study.repair_equation(header, {2: snapshot(2, bitmap=0b1110)})
    assert set(equation) == {0}
    decoder = study.Decoder()
    decoder.insert({0: 1})
    assert decoder.insert(equation) == []
    assert set(equation) == {0}


def test_fresh_seeded_equations_have_actual_independent_gf256_rank():
    sender = study.BitmapSender()
    payload = snapshot()
    sender.accept_payload(payload, 75)
    decoder = study.Decoder()
    first, _, _ = study.repair_equation(sender.bitmap_header(16), {1: payload})
    second, _, _ = study.repair_equation(sender.bitmap_header(32), {1: payload})
    assert first != second and set(first) == set(second) == {0, 2}
    assert decoder.insert(first) == []
    assert len(decoder.rows) == 1
    assert decoder.insert(second) == [0, 2]


def test_empty_snapshot_retains_dense_global_and_widths_are_bounded():
    sender = study.BitmapSender()
    sender.accept_payload(snapshot(bitmap=0b1111), 75)
    assert sender.bitmap_header(16) is None
    with pytest.raises(StructError):
        study.previous.Feedback(1 << 32, 0, 0, 0, 0, 0, 0).encode()
    payload = study.previous.Feedback(1, 0, 0, 1024, 1025, 0, 0).encode()
    assert len(payload) + 28 == 180


def test_numpy_receiver_diagnostics_have_exact_json_round_trip():
    task = dict(analytic_case_id=1, profile=study.PROFILES[2], seed=20261110,
                source_count=1000, warmup_sources=100, tail_sources=300)
    row, sources, repairs, reports = study.execute(task)
    for key in ("feedback_size_histogram", "support_length_histogram"):
        row[key] = {str(size): count for size, count in row[key].items()}
    for value in (row, sources, repairs, reports):
        assert json.loads(json.dumps(value, default=study.json_scalar)) == value
    with pytest.raises(TypeError, match="unsupported JSON value"):
        json.dumps(object(), default=study.json_scalar)


@pytest.mark.parametrize("profile", study.PROFILES[:2])
def test_controls_reproduce_existing_full_source_histories(profile):
    task = dict(analytic_case_id=1, profile=profile, seed=20261110,
                source_count=1000, warmup_sources=100, tail_sources=300)
    expected, expected_sources, _ = study.previous.execute(task)
    actual, sources, repairs, _ = study.execute(task)
    common = set(expected) & set(actual) - {"record_kind", "compute_seconds"}
    assert {key: expected[key] for key in common} == {key: actual[key] for key in common}
    assert sources == expected_sources and repairs == []


def test_all_policies_preserve_forward_trace_budget_cohort_and_delayed_feedback():
    task = dict(analytic_case_id=1, seed=20261110, source_count=1000, warmup_sources=100, tail_sources=300)
    results = [study.execute(dict(task, profile=profile)) for profile in study.PROFILES]
    for key in ("packet_schedule_sha256", "erasure_trace_sha256", "source_arrival_trace_sha256", "forward_total_wire_bytes"):
        assert len({result[0][key] for result in results}) == 1
    for row, sources, repairs, reports in results:
        assert len(sources) == 1000 and row["measured_sources"] == 600
        assert row["repair_packets"] == 208 and row["forward_total_packets"] == 1208
        assert sum(report["ip_bytes"] for report in reports) == row["reverse_feedback_wire_bytes"]
        by_serial = {report["serial"]: report for report in reports}
        emitted = {report["serial"]: bytes.fromhex(report["payload_hex"]) for report in reports}
        for event in repairs:
            report = by_serial[event["report_serial"]]
            assert not report["lost"]
            assert event["selected_ms"] >= event["report_delivered_ms"] >= report["generated_ms"] + 70
            equation, _, _ = study.repair_equation(bytes.fromhex(event["header_hex"]), emitted)
            assert all(event["selected_ms"] - index * study.ARRIVAL_MS >= 70 for index in equation)
            assert event["repair_serial"] % row["profile"]["bitmap_every"] == 0
        diagnostics = row["bitmap_diagnostics"]
        assert diagnostics.get("sent", 0) == sum(diagnostics.get(key, 0) for key in ("erased", "empty", "dependent", "innovative"))


@pytest.mark.parametrize("entrypoint", [
    ["simulator/studies/rtt_bitmap_coded_fallback.py"],
    ["-m", "simulator.studies.rtt_bitmap_coded_fallback"],
])
def test_cli_standalone_and_module_help(entrypoint):
    result = subprocess.run([sys.executable, *entrypoint, "--help"],
        cwd=Path(__file__).resolve().parents[2], check=True, capture_output=True, text=True)
    assert "--out" in result.stdout and "--workers" in result.stdout
