"""Report-only fixtures preserve raw cases, cohorts, missing metrics and hashes."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest


@pytest.fixture
def report(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    import compact_ack_report
    return compact_ack_report


def fixture_study(root, name="fixture", count=3, mutate=None):
    directory = root / "tcp-latency" / name
    (directory / "runs").mkdir(parents=True)
    (directory / "sources").mkdir()
    code = b"# Independent report fixture, no simulation execution.\n"
    (directory / "sources" / "fixture.py").write_bytes(code)
    profile = dict(name="Distinct 64flows batch_delta ACKx3 trim1 r22 pace80.12",
        wire_format="compact_wire", flow_count=64, window_bytes=4194304, payload_rate_mbps=80.12,
        ack_record_encoding="batch_delta", ack_copies=3, distinct_flow_headers=True,
        compact=dict(repair_ratio=.22, repair_window_sources=128, global_repair_every=16,
                     trim_repair_padding=True))
    tasks = []
    prefix = "with_drain_tcp_all_segment_ack_rtt_cohort_"
    for index in range(count):
        task = dict(run_id=index + 1, seed=index + 100, replication=index + 1, profile=deepcopy(profile),
            payload_bytes=1448, forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15,
            loss_model="iid", mtu=1500, duration_s=10, warmup_s=2, drain_s=20)
        raw = dict(task, profile=json.dumps(task["profile"]), strategy=profile["name"],
            offered_frames=100, tcp_delivered_frames=100, tcp_acked_frames=100,
            tcp_all_acknowledged=True, outer_all_confirmed=True, fully_confirmed=True,
            tcp_controller="cubic", application_goodput_mbps=80.1 + index * .01,
            steady_application_goodput_mbps=80.2, tcp_timestamp_rtt_p99_ms=90,
            with_drain_tcp_timestamp_rtt_p99_ms=92, with_drain_tcp_all_segment_ack_rtt_p99_ms=100,
            forward_wire_bytes=180000, reverse_wire_bytes=10000, forward_datagrams=122,
            forward_measurement_mbps=99.5, reverse_measurement_mbps=6.5,
            ack_batch_requested_wire_bytes=10000, ack_batch_departed_wire_bytes=10000,
            ack_batch_full_equivalent_wire_bytes=15000, ack_batch_saved_wire_bytes=5000,
            compact_wire_trimmed_repair_bytes=200, ack_batch_encoding_datagrams={"byte_delta": 300})
        raw.update({prefix + "censored_segments": 0, prefix + "latency_lower_bound_p99_ms": 100,
                    prefix + "miss_fraction_lower": .005, prefix + "miss_fraction_upper": .005,
                    prefix + "offered_segments": 100, prefix + "completed_segments": 100})
        if mutate:
            mutate(index, task, raw)
        tasks.append(task)
        (directory / "runs" / f"{index + 1:05d}.json").write_text(json.dumps(raw))
    manifest = dict(tasks=tasks, sources={"fixture.py": sha256(code).hexdigest()})
    (directory / "experiment.json").write_text(json.dumps(manifest))
    (directory / "source-verification.json").write_text(json.dumps(dict(changed_during_run=[])))
    return directory


def test_normal_loader_uses_traffic_timestamp_and_original_cohort(report, tmp_path):
    fixture_study(tmp_path)
    rows, evidence = report.load(tmp_path, ["fixture"])
    assert len(rows) == 3 and evidence[0]["saved"] == 3
    assert all(row["tcp_rtt_p99_ms"] == 90 and row["provisional_joint_pass"] for row in rows)
    assert all(row["tcp_all_segment_ack_p99_ms"] == 100 for row in rows)
    assert rows[0]["packet_extra_pct"] == pytest.approx(22)
    assert rows[0]["byte_extra_pct"] == pytest.approx(100 * (180000 / 144800 - 1))
    assert rows[0]["ack_batch_saved_wire_bytes"] == 5000
    assert json.loads(rows[0]["original_profile"])["distinct_flow_headers"]
    means = report.summarize(rows)
    assert len(means) == 1 and means[0]["independent_n"] == 3
    assert means[0]["provisional_joint_passes"] == 3
    assert means[0]["goodput_mbps"] == pytest.approx(80.11)


def test_missing_failed_and_censored_runs_remain_visible(report, tmp_path):
    def mutate(index, task, raw):
        if index == 0:
            raw.pop("tcp_timestamp_rtt_p99_ms")
            raw.pop("application_goodput_mbps")
            raw["error"] = "Recorded failure fixture"
            raw["fully_confirmed"] = False
        if index == 1:
            raw[report.PREFIX + "censored_segments"] = 2
            raw["fully_confirmed"] = False
    fixture_study(tmp_path, mutate=mutate)
    rows, evidence = report.load(tmp_path, ["fixture"])
    assert rows[0]["status"] == "failed" and rows[0]["goodput_mbps"] is None
    assert rows[0]["provisional_joint_pass"] is None
    assert rows[1]["ack_p99_is_lower_bound"] and not rows[1]["eligible"]
    assert "fallback" in evidence[0]["loader"]
    means = report.summarize(rows)
    assert means[0]["n"] == 3 and means[0]["goodput_mbps_n"] == 2
    assert not report.archive.frontier(means, "tcp_all_segment_ack_p99_ms")
    output = tmp_path / "report"
    output.mkdir()
    _, coverage, _ = report.figures(output, rows, means)
    assert len(coverage) == 18
    assert len({(row["id"], row["metric"]) for row in coverage}) == 18
    assert sum(row["coordinate_kind"] == "unmeasured strip" for row in coverage) == 6


def test_complete_profile_payload_duration_and_source_cohorts_separate(report, tmp_path):
    def mutate(index, task, raw):
        if index == 1:
            task["profile"]["ack_copies"] = 2
            raw["profile"] = json.dumps(task["profile"])
        if index == 2:
            task["payload_bytes"] = raw["payload_bytes"] = 512
        if index == 3:
            task["duration_s"] = raw["duration_s"] = 120
    fixture_study(tmp_path, count=4, mutate=mutate)
    rows, _ = report.load(tmp_path, ["fixture"])
    means = report.summarize(rows)
    assert len(means) == 4
    assert len({row["cohort"] for row in rows}) == 3
    assert rows[0]["configuration"] != rows[1]["configuration"]
    assert rows[0]["configuration"] == rows[2]["configuration"]
    old_cohort = rows[0]["cohort"]
    source = tmp_path / "tcp-latency/fixture/sources/fixture.py"
    source.write_text("# New verified fixture version.\n")
    manifest_path = source.parent.parent / "experiment.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["sources"]["fixture.py"] = sha256(source.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    changed, _ = report.load(tmp_path, ["fixture"])
    assert changed[0]["cohort"] != old_cohort


@pytest.mark.parametrize("failure", ["missing_run", "wrong_task", "changed_source", "hash_mismatch"])
def test_unverified_or_unfinished_studies_are_rejected(report, tmp_path, failure):
    directory = fixture_study(tmp_path)
    if failure == "missing_run":
        (directory / "runs/00001.json").unlink()
    if failure == "wrong_task":
        path = directory / "runs/00001.json"
        raw = json.loads(path.read_text())
        raw["seed"] += 1
        path.write_text(json.dumps(raw))
    if failure == "changed_source":
        (directory / "source-verification.json").write_text(json.dumps(dict(changed_during_run=["fixture.py"])))
    if failure == "hash_mismatch":
        (directory / "sources/fixture.py").write_text("# Altered fixture\n")
    with pytest.raises(ValueError):
        report.load(tmp_path, ["fixture"])


def test_repeated_seed_and_missing_metrics_do_not_gain_confidence(report, tmp_path):
    def mutate(index, task, raw):
        task["seed"] = raw["seed"] = 7
        if index == 2:
            raw.pop("reverse_measurement_mbps")
    fixture_study(tmp_path, mutate=mutate)
    rows, _ = report.load(tmp_path, ["fixture"])
    mean = report.summarize(rows)[0]
    assert mean["independent_n"] == 1 and mean["goodput_mbps_low"] is None
    assert mean["reverse_measurement_mbps_n"] == 2
    assert not report.archive.frontier([mean], "reverse_measurement_mbps")


def test_normalized_export_imports_as_existing_raw_ids_without_unresolved_aliases(report, tmp_path):
    fixture_study(tmp_path, count=3)
    output = tmp_path / "report"
    receipt = report.render(tmp_path, ["fixture"], output)
    assert receipt["saved_runs"] == 3 and receipt["raw_plot_instances"] == 18
    import csv
    points = list(csv.DictReader((output / "all-runs.csv").open()))
    assert "source_file" not in points[0]
    source = tmp_path / points[0]["source"]
    assert sha256(source.read_bytes()).hexdigest() == points[0]["source_sha256"]
    assert points[0]["id"] == "tcp-latency/fixture/runs/00001.json#1"
    assert (output / "report-sources/compact_ack_report.py").exists()
    imported, inventory = report.archive.load_all(tmp_path, tmp_path / "archive")
    assert len(imported) == 3
    assert {row["id"] for row in imported} == {row["id"] for row in points}
    export = next(row for row in inventory if row["study"] == "report/all-runs.csv")
    assert export["state"] == "derived normalized observations"
    assert export["alias_rows"] == 3 and export["raw_runs"] == 0
    assert sum(row.get("unresolved_alias_rows", 0) for row in inventory) == 0
