"""Keep historical coverage complete without manufacturing Pareto eligibility."""

import importlib.util
import json
from hashlib import sha256
from pathlib import Path

import pytest

pytest.importorskip("plotly")
spec = importlib.util.spec_from_file_location(
    "all_experiments_study", Path(__file__).resolve().parents[1] / "studies/all_experiments.py"
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


def observation(**changes):
    return dict(dict(run_id=1, name="Compact candidate", seed=1, offered_frames=100,
                     tcp_delivered_frames=100, tcp_acked_frames=100, tcp_all_acknowledged=True,
                     outer_all_confirmed=True, forward_wire_bytes=170000, forward_datagrams=118,
                     tcp_goodput_mbps=80, payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
                     rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500, duration_s=10,
                     warmup_s=2, drain_s=5, tcp_timestamp_rtt_p99_ms=300, frame_p99_ms=290,
                     tcp_controller="cubic"), **changes)


def normalized(raw=None, **changes):
    return report.normalize(raw or observation(**changes), {}, {}, "compact-study", "compact-study/runs/1.json", 1)


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def save_csv(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    report.write_csv(path, values)


def test_nested_aggregate_and_string_task_identifiers_recover_metadata():
    raw = observation(run_id="2")
    for key in report.NUMERIC_CONDITIONS:
        raw.pop(key, None)
    task = dict(run_id=2, scenario=dict(rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500),
                traffic=dict(payload_bytes=512, duration_s=10, drain_s=5),
                paths=[dict(forward_mbps=100, reverse_mbps=10)])
    manifest = dict(tasks=[task])
    row = report.normalize(dict(aggregate=raw, flows=[]), report.task_for(dict(aggregate=raw), manifest),
                           manifest, "fixture", "fixture/runs/2.json", 1)
    assert row["payload_bytes"] == 512
    assert row["forward_mbps"] == 100
    assert row["warmup_s"] == 0
    assert row["duration_s"] == 10
    assert row["eligible"]
    assert json.loads(row["metadata_provenance"])["payload_bytes"] == "task.traffic.payload_bytes"


def test_initial_pilot_matches_unique_strategy_without_run_id(tmp_path):
    raw = observation(strategy="ARQ")
    for key in ("run_id", "name", "duration_s", "drain_s", "warmup_s", "payload_bytes"):
        raw.pop(key)
    save_csv(tmp_path / "pilot.csv", [raw])
    save_json(tmp_path / "pilot-config.json", [dict(strategy=dict(name="ARQ"),
              traffic=dict(duration_s=2, drain_s=3, payload_bytes=256))])
    rows, _ = report.load_all(tmp_path, tmp_path / "out")
    assert rows[0]["payload_bytes"] == 256
    assert rows[0]["duration_s"] == 2


def test_core_hash_is_independent_of_optional_source_inventory():
    sources = {name: str(index) * 64 for index, name in enumerate(report.CORE_FILES, 1)}
    base = report.source_version(dict(sources=sources), "one")
    assert base == report.source_version(dict(sources={**sources, "optional.py": "a" * 64}), "two")
    partial = dict(sources={"model.py": "1" * 64})
    assert report.source_version(partial, "one") != report.source_version(partial, "two")
    assert report.source_version(partial, "one") != base


@pytest.mark.parametrize("execution_status,expected", [("unsupported", "unsupported"),
    ("error", "tool failure"), ("failed", "tool failure"), ("bound exhausted", "bound exhausted")])
def test_execution_outcomes_remain_explicit_and_cannot_enter_frontiers(execution_status, expected):
    row = normalized(execution_status=execution_status, error="recorded outcome")
    assert row["status"] == expected
    assert row["execution_error"] == "recorded outcome"
    assert not row["eligible"]
    assert not row["tcp_syn_ping_frontier_eligible"]


def test_verified_defaults_require_a_verified_call_that_omits_the_field(tmp_path):
    config = tmp_path / "config.py"
    config.write_text('class Scenario:\n    mtu: int = 1500\n    loss_model: str = "iid"\n')
    runner = tmp_path / "studies" / "runner.py"
    runner.parent.mkdir()
    runner.write_text('scenario = Scenario(task["rtt_ms"], .15)\n')
    manifest = dict(sources={str(p): sha256(p.read_bytes()).hexdigest() for p in (config, runner)})
    metadata, evidence = report.verified_metadata(manifest, tmp_path)
    assert metadata == dict(mtu=1500, loss_rate=.15, loss_model="iid")
    assert "omitted argument" in evidence["mtu"]
    runner.write_text('scenario = Scenario(70, .15, mtu=task["mtu"])\n')
    assert report.verified_metadata(manifest, tmp_path)[0] == {}
    manifest["sources"][str(runner)] = sha256(runner.read_bytes()).hexdigest()
    assert "mtu" not in report.verified_metadata(manifest, tmp_path)[0]


@pytest.mark.parametrize("changes,status", [
    ({"tcp_all_acknowledged": False}, "incomplete"),
    ({"outer_all_confirmed": False}, "incomplete"),
    ({"tcp_acked_frames": 99}, "incomplete"),
    ({"outer_all_confirmed": None}, "confirmation unknown"),
    ({"fully_confirmed": False}, "incomplete"),
    ({"fully_confirmed": "False"}, "incomplete"),
    ({"ack_all_flushed": False}, "incomplete"),
    ({"ack_all_flushed": "false", "outer_all_confirmed": None}, "incomplete"),
])
def test_terminal_evidence_is_required_and_false_flags_win(changes, status):
    row = normalized(**changes)
    assert row["status"] == status
    assert not row["eligible"]


def test_optional_final_flags_preserve_unknowns_and_cannot_override_failure():
    assert normalized(fully_confirmed=True, ack_all_flushed=True)["eligible"]
    assert normalized(fully_confirmed=None, ack_all_flushed="")["eligible"]
    row = normalized(fully_confirmed=True, ack_all_flushed=True, tcp_all_acknowledged=False)
    assert row["status"] == "incomplete"
    evidence = json.loads(row["terminal_evidence"])
    assert evidence["completion_flags"] == dict(fully_confirmed=True, ack_all_flushed=True)
    failed = normalized(fully_confirmed="false", ack_all_flushed=True)
    assert json.loads(failed["terminal_evidence"])["completion_flags"]["fully_confirmed"] is False


def test_missing_conditions_and_historical_bugs_remain_visible_but_ineligible():
    row = normalized(mtu=None, loss_model=None)
    assert "unknown mtu" in row["exclusion_reason"]
    assert not row["eligible"]
    row = report.normalize(observation(), {}, {}, "compact-tcp/pilot", "compact-tcp/pilot/runs/1.json", 1)
    assert row["quality"] == "historical diagnostic"
    assert not row["eligible"]


def test_frame_latency_normalizes_to_through_drain():
    row = normalized(frame_p99_ms=120, with_drain_frame_p99_ms=250,
                     tcp_ack_rtt_p99_ms=140, with_drain_tcp_ack_rtt_p99_ms=270)
    assert row["frame_p99_ms"] == 250
    assert row["tcp_ack_p99_ms"] == 270
    assert row["tcp_rtt_p99_ms"] == 300
    assert normalized(with_drain_frame_p99_ms=None)["frame_p99_ms"] is None


def test_incomplete_metric_coverage_excludes_only_that_frontier():
    first = normalized()
    second = normalized(seed=2, tcp_timestamp_rtt_p99_ms=None)
    second["id"] = "compact-study/runs/2.json#1"
    means = report.summarize([first, second])
    assert means[0]["tcp_rtt_p99_ms_n"] == 1
    assert report.frontier(means, "tcp_rtt_p99_ms") == []
    assert len(report.frontier(means, "packet_extra_pct")) == 1


def test_payload_duration_and_loss_process_have_separate_frontiers():
    rows = [normalized(), normalized(payload_bytes=512), normalized(duration_s=60),
            normalized(loss_model="burst", mean_burst=4)]
    assert len({row["cohort"] for row in rows}) == 4
    assert len(report.summarize(rows)) == 4


def test_independent_json_executions_with_identical_outcomes_are_preserved(tmp_path):
    for study in ("one", "two"):
        save_json(tmp_path / study / "runs" / "1.json", observation())
    rows, _ = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 2
    assert json.loads(rows[1]["same_outcome_as"]) == [rows[0]["id"]]


def test_csv_only_studies_with_equal_counters_are_distinct_experiments(tmp_path):
    for study in ("one", "two"):
        save_json(tmp_path / study / "experiment.json", dict(config=dict(traffic=dict(duration_s=10))))
        save_csv(tmp_path / study / "replications.csv", [observation()])
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 2
    assert sum(item["alias_rows"] for item in inventory) == 0


def test_only_provenance_scoped_derived_exports_are_aliased(tmp_path):
    raw = observation()
    save_json(tmp_path / "original" / "runs" / "1.json", raw)
    save_json(tmp_path / "original" / "experiment.json", dict(tasks=[dict(run_id=1)]))
    save_csv(tmp_path / "original" / "replications.csv", [raw])
    save_csv(tmp_path / "aggregate" / "replications.csv", [raw])
    save_json(tmp_path / "aggregate" / "manifest.json", dict(
        source_manifests=[str(tmp_path / "original" / "experiment.json")]))
    save_csv(tmp_path / "unreferenced" / "audit.csv", [raw])
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 2
    assert sum(item["alias_rows"] for item in inventory) == 2
    assert {row["study"] for row in rows} == {"original", "unreferenced"}


def test_export_digest_mismatch_does_not_suppress_an_observation(tmp_path):
    path = tmp_path / "original" / "runs" / "1.json"
    save_json(path, observation())
    save_json(tmp_path / "aggregate" / "manifest.json", dict(raw_inputs={str(path): "0" * 64}))
    save_csv(tmp_path / "aggregate" / "replications.csv", [observation()])
    assert len(report.load_all(tmp_path, tmp_path / "out")[0]) == 2


def analytical_source_table(tmp_path, digest=None, **changes):
    source = tmp_path / "original" / "runs" / "1.json"
    raw = observation(fully_confirmed=True)
    save_json(source, raw)
    reference = {key: raw[key] for key in ("run_id", "seed", "offered_frames",
                                           "tcp_goodput_mbps", "fully_confirmed")}
    reference.update(changes)
    save_csv(tmp_path / "budget" / "source-observations.csv", [reference])
    save_json(tmp_path / "budget" / "analysis.json", dict(protocol_executions=0,
              analysis_kind="wire_budget_only", source_file_receipts=[
                  dict(path=str(source), sha256=digest or sha256(source.read_bytes()).hexdigest())]))
    return source


def test_verified_reduced_analytical_references_keep_original_run_identity(tmp_path):
    analytical_source_table(tmp_path)
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert [row["id"] for row in rows] == ["original/runs/1.json#1"]
    reference = next(item for item in inventory if item["state"] == "analytical source references")
    assert reference["raw_runs"] == 0
    assert reference["alias_rows"] == 1
    assert reference["unresolved_alias_rows"] == 0
    assert json.loads(reference["alias_targets"]) == [rows[0]["id"]]


@pytest.mark.parametrize("digest,changes", [
    ("0" * 64, {}),
    (None, {"tcp_goodput_mbps": 81}),
    (None, {"seed": 18446744073709551615}),
])
def test_unverified_analytical_references_remain_explicit_inventory_rows(tmp_path, digest, changes):
    analytical_source_table(tmp_path, digest, **changes)
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert [row["id"] for row in rows] == ["original/runs/1.json#1"]
    reference = next(item for item in inventory if item["state"] == "analytical source references")
    assert reference["alias_rows"] == 0
    assert reference["unresolved_alias_rows"] == 1
    retained = json.loads(reference["unresolved_references"])[0]
    assert retained["source_row"] == 1
    assert retained["recorded_fields"]["offered_frames"] == "100"
    if digest:
        assert "digest mismatch" in reference["receipt_issues"]


def test_ambiguous_analytical_references_do_not_choose_an_arbitrary_execution(tmp_path):
    first_source = analytical_source_table(tmp_path)
    second_source = tmp_path / "other" / "runs" / "1.json"
    second_source.parent.mkdir(parents=True)
    second_source.write_bytes(first_source.read_bytes())
    analysis = tmp_path / "budget" / "analysis.json"
    details = json.loads(analysis.read_text())
    details["source_file_receipts"].append(dict(path=str(second_source),
                                              sha256=sha256(second_source.read_bytes()).hexdigest()))
    save_json(analysis, details)
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 2
    reference = next(item for item in inventory if item["state"] == "analytical source references")
    assert reference["alias_rows"] == 0
    assert reference["unresolved_alias_rows"] == 1
    assert len(json.loads(reference["unresolved_references"])[0]["matching_source_ids"]) == 2


def test_invalid_analytical_receipt_structure_retains_reference_evidence(tmp_path):
    analytical_source_table(tmp_path)
    save_json(tmp_path / "budget" / "analysis.json", dict(protocol_executions=0,
                                                         source_file_receipts=None))
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 1
    reference = next(item for item in inventory if item["state"] == "analytical source references")
    assert reference["unresolved_alias_rows"] == 1
    assert "not a list" in reference["receipt_issues"]


def source_file_table(tmp_path, **changes):
    source = tmp_path / "study" / "runs" / "1.json"
    profile = dict(name="Wire candidate", wire_format="compact_wire", payload_rate_mbps=80.2,
                   compact=dict(repair_ratio=.22, encapsulation="raw_ipv4_crc32"))
    raw = observation(replication=1, profile=json.dumps(profile), strategy=profile["name"],
                      application_goodput_mbps=80, fully_confirmed=True,
                      forward_encapsulation="raw_ipv4_crc32", rtt_budget_met=False,
                      packet_cost_target_met=False)
    save_json(source, raw)
    reference = dict(run_id=1, seed=1, replication=1, profile=profile["name"],
                     application_goodput_mbps=80, original_segments=100, acknowledged_segments=100,
                     wire_format="compact_wire", encapsulation="raw_ipv4_crc32", repair_ratio=.22,
                     payload_pacing_mbps=80.2, fully_confirmed=True, throughput_latency_gate=False,
                     legacy_packet_gate=False, source_file="runs/1.json",
                     source_sha256=sha256(source.read_bytes()).hexdigest())
    reference.update(changes)
    save_csv(tmp_path / "study" / "screen-points.csv", [reference])
    return raw, reference


@pytest.mark.parametrize("profile_json", [False, True])
def test_digest_source_file_exports_preserve_raw_ids_and_profile_alternatives(tmp_path, profile_json):
    raw, reference = source_file_table(tmp_path)
    if profile_json:
        reference["profile"] = json.dumps(json.loads(raw["profile"]), sort_keys=True)
        save_csv(tmp_path / "study" / "screen-points.csv", [reference])
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert [row["id"] for row in rows] == ["study/runs/1.json#1"]
    entry = next(item for item in inventory if item["state"] == "digest-verified source-file references")
    assert entry["alias_rows"] == 1
    assert entry["unresolved_alias_rows"] == 0
    assert json.loads(entry["alias_targets"]) == [rows[0]["id"]]


@pytest.mark.parametrize("changes", [
    dict(source_sha256="0" * 64), dict(source_file="runs/missing.json"),
    dict(run_id=2), dict(seed=18446744073709551615), dict(replication=2), dict(seed=""),
    dict(application_goodput_mbps=81), dict(original_segments=101), dict(acknowledged_segments=99),
    dict(profile="Different strategy"), dict(repair_ratio=.23), dict(encapsulation="udp"),
])
def test_unverified_source_file_exports_retain_all_reference_fields(tmp_path, changes):
    source_file_table(tmp_path, **changes)
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 1
    entry = next(item for item in inventory if item["state"] == "digest-verified source-file references")
    assert entry["alias_rows"] == 0
    assert entry["unresolved_alias_rows"] == 1
    retained = json.loads(entry["unresolved_references"])[0]
    assert retained["source_row"] == 1
    assert retained["recorded_fields"]["source_file"] == changes.get("source_file", "runs/1.json")
    assert retained["reason"]


def test_screen_means_and_frontiers_do_not_create_protocol_observations(tmp_path):
    source_file_table(tmp_path)
    mean = dict(profile="Wire candidate", application_goodput_mbps_mean=80,
                with_drain_tcp_all_segment_ack_rtt_p99_ms_mean=130, n=3)
    save_csv(tmp_path / "study" / "screen-summary.csv", [mean])
    save_csv(tmp_path / "study" / "screen-frontiers.csv", [dict(axis="tcp_timestamp_rtt_p99_ms",
              run_id=1, cost=130, application_goodput_mbps=80)])
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert [row["id"] for row in rows] == ["study/runs/1.json#1"]
    derived = next(item for item in inventory if item["study"].endswith("screen-frontiers.csv"))
    assert derived["state"] == "derived summary"
    assert derived["raw_runs"] == 0


def test_generated_latency_exports_do_not_change_run_count(tmp_path):
    save_json(tmp_path / "original" / "runs" / "1.json", observation())
    rows, _ = report.load_all(tmp_path, tmp_path / "out")
    means = report.summarize(rows)
    output = tmp_path / "tcp-latency"
    for name, records in (("all-runs.csv", rows), ("latency-validation.csv", rows),
                          ("configuration-means.csv", means), ("frontiers.csv", report.frontier_rows(means)),
                          ("latency-validation-summary.csv", means),
                          ("latency-validation-paired.csv", [dict(metric="goodput", value=1)])):
        save_csv(output / name, records)
    after, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert [row["id"] for row in after] == [row["id"] for row in rows]
    assert sum(item["alias_rows"] for item in inventory) == 2
    assert not any(item.get("unresolved_alias_rows") for item in inventory)


def test_repeat_seeds_do_not_add_independent_ci_replications():
    rows = [normalized(seed=1, tcp_goodput_mbps=10), normalized(seed=1, tcp_goodput_mbps=20),
            normalized(seed=2, tcp_goodput_mbps=30)]
    for index, row in enumerate(rows):
        row["id"] = str(index)
    result = report.summarize(rows)[0]
    assert result["n"] == 3
    assert result["independent_n"] == 2
    assert result["repeated_seed_runs"] == 1
    assert result["goodput_mbps"] == pytest.approx(22.5)
    assert result["goodput_mbps_n"] == 3
    assert result["goodput_mbps_independent_n"] == 2
    rows[0]["seed"] = None
    assert report.summarize(rows)[0]["goodput_mbps_low"] is None


def test_missing_planned_tasks_and_recovered_tool_failure_are_inventoried(tmp_path):
    save_json(tmp_path / "study" / "experiment.json", dict(tasks=[dict(run_id=1), dict(run_id=2)]))
    save_json(tmp_path / "study" / "runs" / "1.json", observation())
    save_json(tmp_path / "study" / "execution-attempts.json", dict(initial_attempt=dict(status="tool_failure"),
              resume=dict(status="complete")))
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 1
    coverage = next(item for item in inventory if item["state"] == "planned task coverage")
    assert json.loads(coverage["missing_task_ids"]) == ["2"]
    assert any(item["state"] == "recorded execution attempts" and item["raw_runs"] == 0 for item in inventory)


def test_analytical_tasks_use_separate_case_coverage(tmp_path):
    save_json(tmp_path / "diagnostic" / "experiment.json",
              dict(record_kind="coding_only_manifest", tasks=[dict(run_id=1)]))
    save_json(tmp_path / "diagnostic" / "runs" / "1.json",
              dict(record_kind="analytic_repair_case", run_id=1, analytic_completion_p99_ms=78))
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert rows == []
    assert not any(item["state"] == "planned task coverage" for item in inventory)
    coverage = next(item for item in inventory if item["state"] == "analytical task manifest")
    assert coverage["planned_tasks"] == 1
    assert "missing_task_ids" not in coverage


def test_explicit_analytic_task_plans_do_not_imply_executed_cases(tmp_path):
    save_json(tmp_path / "diagnostic" / "manifest.json",
              dict(record_kind="analytic_screen_manifest", analytic_tasks=[
                  dict(analytic_case_id=1), dict(analytic_case_id=2)]))
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert rows == []
    coverage = next(item for item in inventory if item["state"] == "analytical task manifest")
    assert coverage["planned_tasks"] == 2
    assert coverage["raw_runs"] == 0
    assert "saved_observations" not in coverage
    assert "missing_task_ids" not in coverage
    assert "planned analytical tasks" in coverage["detail"]


def test_plotly_v3_titles_units_and_bounded_legend(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "get_plotlyjs", lambda: "")
    rows = [normalized()]
    report.html_report(tmp_path, rows, report.summarize(rows), [], [])
    page = (tmp_path / "report.html").read_text()
    assert "title:{text:'TCP SYN ping P99 (ms)'}" in page
    assert "title:{text:'Concurrent bulk goodput (Mbps)'}" in page
    assert "maxheight:125" in page
    assert "TCP SYN ping P99 (ms)" in page
    historical = (tmp_path / "historical-overview.html").read_text()
    assert "Extra forward packets / delivered record (%)" in historical


def test_completed_coding_reports_are_linked_from_the_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "get_plotlyjs", lambda: "")
    output = tmp_path / "all-experiments"
    output.mkdir()
    studies = ("recursive-fallback-screen", "selective-fallback-screen", "spatial-coupling-screen",
               "feedback-gate-screen", "partial-repair-screen", "bitmap-coded-fallback-screen",
               "source-bridge-screen", "busy-period-diagnostic", "predictive-wire-budget",
               "compact-wire-screen", "compact-wire-ack-screen", "compact-wire-ack-long", "tcp-syn-ping-analysis")
    for study in studies:
        path = tmp_path / "tcp-latency" / study / "report.html"
        path.parent.mkdir(parents=True)
        path.write_text("Completed coding study")
    rows = [normalized()]
    report.html_report(output, rows, report.summarize(rows), [], [])
    page = (output / "historical-overview.html").read_text()
    for study in studies:
        assert f'href="../tcp-latency/{study}/report.html"' in page


def test_independent_flow_counts_are_configuration_choices():
    rows = []
    for count in (1, 2, 4, 8, 16):
        task = dict(strategy=dict(name="Same strategy"), flow_count=count,
                    traffic=dict(window_bytes=4194304), window_policy="fixed_total")
        rows.append(report.normalize(observation(), task, {}, "flows", f"flows/{count}.json", 1))
    assert len({row["cohort"] for row in rows}) == 1
    assert len(report.summarize(rows)) == 5
    assert {json.loads(row["profile"])["flow_count"] for row in rows} == {1, 2, 4, 8, 16}
    assert report.source_version(dict(simulator_version="0.3"), "one") != report.source_version(
        dict(simulator_version="0.3"), "two")


def test_unmeasured_strip_keeps_zero_delivery_run_without_fake_coordinates(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "get_plotlyjs", lambda: "")
    row = normalized(tcp_delivered_frames=0, tcp_acked_frames=0, tcp_goodput_mbps=0,
                     tcp_timestamp_rtt_p99_ms=None, frame_p99_ms=None)
    assert row["packet_extra_pct"] is None
    report.html_report(tmp_path, [row], report.summarize([row]), [], [])
    page = (tmp_path / "historical-overview.html").read_text()
    assert "xaxis:missingX?'x2':'x'" in page
    assert "xaxis2:{domain:[.91,1]" in page
    assert "y:points.map(r=>missingVertical?yStripLabel:r.goodput_mbps)" in page
    assert '"packet_extra_pct": null' in page


def test_tied_nondominated_configurations_all_remain_on_frontier():
    rows = [normalized(tcp_goodput_mbps=80), normalized(tcp_goodput_mbps=80),
            normalized(tcp_goodput_mbps=79), normalized(tcp_goodput_mbps=80, forward_datagrams=119)]
    for index, row in enumerate(rows):
        row["id"] = str(index)
    assert [row["id"] for row in report.frontier(rows, "packet_extra_pct")] == ["0", "1"]


def test_all_segment_ack_completion_requires_its_own_recorded_metric():
    row = normalized(with_drain_tcp_all_segment_ack_rtt_p99_ms=900,
                     with_drain_tcp_ack_rtt_p99_ms=300,
                     with_drain_tcp_all_segment_ack_rtt_cohort_miss_fraction_upper=.15)
    assert row["tcp_ack_p99_ms"] == 300
    assert row["tcp_all_segment_ack_p99_ms"] == 900
    assert row["tcp_deadline_miss_pct"] == 15
    assert normalized(with_drain_tcp_ack_rtt_p99_ms=300)["tcp_all_segment_ack_p99_ms"] is None
    assert normalized()["tcp_deadline_miss_pct"] is None


def test_historical_deadline_values_remain_exported_without_a_plot_axis(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "get_plotlyjs", lambda: "")
    rows = [normalized(name="Recorded miss", with_drain_tcp_all_segment_ack_rtt_cohort_miss_fraction_upper=.004),
            normalized(name="Unmeasured")]
    for index, row in enumerate(rows):
        row["id"] = f"fixture/{index}.json#1"
    assert rows[0]["tcp_deadline_miss_pct"] == .4
    means = report.summarize(rows)
    assert next(row for row in means if row["name"] == "Recorded miss")["tcp_deadline_miss_pct"] == .4
    frontiers = report.frontier_rows(means)
    assert all(row["frontier_metric"] in report.AXES for row in frontiers)
    assert report.AXES == ("packet_extra_pct", "byte_extra_pct", "tcp_syn_ping_p99_ms")
    report.html_report(tmp_path, rows, means, frontiers, [])
    page = (tmp_path / "report.html").read_text()
    for old_axis in ("tcp_deadline_miss_pct", "tcp_rtt_p99_ms", "frame_p99_ms", "tcp_ack_p99_ms",
                     "tcp_all_segment_ack_p99_ms", "quic_rtt_p99_ms", "tcp_syn_ping_failure_pct"):
        assert f'<option value="{old_axis}">' not in page
    assert "Measured TCP SYN ping Pareto comparisons" in page
    assert 'href="historical-overview.html"' in page
    assert "Full executed source hashes" in page


def test_plot_coverage_accounts_for_every_coordinate_combination_per_payload():
    rows = [normalized(tcp_syn_ping_p99_ms=80), normalized(),
            normalized(tcp_goodput_mbps=None, tcp_syn_ping_p99_ms=80),
            normalized(tcp_goodput_mbps=None),
            normalized(payload_bytes=64, tcp_goodput_mbps=0)]
    coverage = report.plot_coverage(rows)
    assert len(coverage) == 2 * len(report.AXES)
    for item in coverage:
        assert item["recorded_runs"] == item["plotted_runs"]
    timestamp = next(item for item in coverage if item["payload_bytes"] == 1448
                     and item["metric"] == "tcp_syn_ping_p99_ms")
    assert [timestamp[key] for key in ("measured_points", "unmeasured_x_points",
                                     "unmeasured_y_points", "unmeasured_both_points")] == [1, 1, 1, 1]
    assert next(item for item in coverage if item["payload_bytes"] == 64)["zero_goodput_points"] == 1


def test_primary_view_matches_one_condition_and_secondary_archive_retains_all_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "get_plotlyjs", lambda: "")
    rows = [normalized(), normalized(tcp_goodput_mbps=0), normalized(tcp_goodput_mbps=None)]
    for index, row in enumerate(rows):
        row["id"] = f"fixture/{index}.json#1"
    report.html_report(tmp_path, rows, report.summarize(rows), [], [])
    page = (tmp_path / "report.html").read_text()
    assert "get('cohort').value='all'" not in page
    assert "ids:points.map(row=>row.id)" in page
    assert "Measured SYN plot coverage mismatch" in page
    assert "row.syn_cohort===get('cohort').value" in page
    assert "type:'linear',rangemode:'tozero'" in page
    assert "xaxis.ticktext=ticks.map" in page
    assert 'id="costplot"' not in page
    assert "yaxis2" not in page
    assert 'href="plot-coverage.csv"' in page
    embedded = page.split('<script id="data" type="application/json">', 1)[1].split('</script>', 1)[0]
    assert {row["id"] for row in json.loads(embedded)["runs"]} == {row["id"] for row in rows}
    historical = (tmp_path / "historical-overview.html").read_text()
    assert "Secondary historical experiment archive" in historical
    assert "get('cohort').value='all'; render();" in historical
    assert "get('scale').value==='log'&&r.goodput_mbps<=0" in historical
    assert "yaxis:missingVertical?'y2':'y'" in historical
    assert "Raw-run plot coverage mismatch" in historical


def test_static_figures_separate_conditions_and_keep_missing_cases_in_coverage(tmp_path, monkeypatch):
    pytest.importorskip("matplotlib")
    from matplotlib.axes import Axes
    original = Axes.scatter
    sizes = []
    axes = []

    def record_scatter(axis, x, y, *args, **kwargs):
        axes.append(axis)
        sizes.append(len(x))
        return original(axis, x, y, *args, **kwargs)

    monkeypatch.setattr(Axes, "scatter", record_scatter)
    rows = [normalized(syn_observation(tcp_syn_ping_background_goodput_mbps=80,
                                      tcp_syn_probe_steady_state_reached=True)),
            normalized(syn_observation(rtt_ms=100, tcp_syn_ping_p99_ms=130,
                                      tcp_syn_ping_background_goodput_mbps=79,
                                      tcp_syn_probe_steady_state_reached=True)),
            normalized(), normalized(payload_bytes=64, tcp_goodput_mbps=None)]
    for index, row in enumerate(rows):
        row["id"] = f"fixture/{index}.json#1"
    report.static_payloads(tmp_path, rows, report.summarize(rows))
    assert sum(sizes) == 2
    assert all(axis.get_ylim() == pytest.approx((0, 86.4)) for axis in axes)
    index = json.loads((tmp_path / "syn-ping-static-index.json").read_text())
    assert len(index) == 2
    assert {identifier for cohort in index for identifier in cohort["raw_ids"]} == {row["id"] for row in rows[:2]}
    assert all(len(cohort["raw_ids"]) == 1 and (tmp_path / cohort["png"]).is_file() for cohort in index)
    assert not (tmp_path / "payload-1448-pareto.png").exists()
    assert "No measured stable-load TCP SYN ping cohort" in (tmp_path / "syn-ping-index.html").read_text()
    import csv
    with (tmp_path / "syn-ping-coverage.csv").open() as stream:
        coverage = list(csv.DictReader(stream))
    assert {row["id"] for row in coverage} == {row["id"] for row in rows}
    assert [row["primary_display"] for row in coverage] == ["measured point"] * 2 + ["coverage table"] * 2


def syn_observation(**changes):
    values = dict(tcp_syn_ping_p99_ms=95, tcp_syn_ping_failure_pct=0,
                  tcp_syn_ping_offered=100, tcp_syn_ping_completed=100,
                  tcp_syn_ping_timeouts=0, tcp_syn_ping_censored=0,
                  tcp_syn_probe_all_flushed=True, tcp_syn_probe_config=dict(interval_ms=100, timeout_ms=3000))
    values.update(changes)
    return observation(**values)


def test_syn_ping_uses_only_explicit_raw_values_and_preserves_old_values():
    historical = normalized(with_drain_tcp_all_segment_ack_rtt_p99_ms=175)
    measured = normalized(syn_observation(with_drain_tcp_all_segment_ack_rtt_p99_ms=175))
    for key in ("id", "cohort", "profile", "packet_extra_pct", "byte_extra_pct", "goodput_mbps",
                "tcp_rtt_p99_ms", "tcp_all_segment_ack_p99_ms", "frame_p99_ms", "eligible"):
        assert measured[key] == historical[key]
    assert historical["tcp_syn_ping_p99_ms"] is None
    assert historical["tcp_syn_ping_failure_pct"] is None
    assert not historical["tcp_syn_ping_frontier_eligible"]
    assert measured["tcp_syn_ping_p99_ms"] == 95
    assert measured["tcp_syn_ping_failure_pct"] == 0
    assert measured["tcp_syn_ping_frontier_eligible"]


@pytest.mark.parametrize("changes", [
    dict(tcp_syn_ping_failure_pct=1), dict(tcp_syn_ping_failure_pct=None),
    dict(tcp_syn_ping_completed=99), dict(tcp_syn_ping_completed=None),
    dict(tcp_syn_ping_timeouts=1), dict(tcp_syn_ping_timeouts=None),
    dict(tcp_syn_ping_censored=1), dict(tcp_syn_ping_censored=None),
    dict(tcp_syn_ping_offered=0, tcp_syn_ping_completed=0),
    dict(tcp_syn_ping_p99_ms=None), dict(tcp_syn_probe_all_flushed=False),
    dict(tcp_syn_probe_steady_state_reached=False),
])
def test_probe_failures_exclude_only_the_syn_frontier(changes):
    row = normalized(syn_observation(**changes))
    assert row["eligible"]
    assert not row["tcp_syn_ping_frontier_eligible"]
    means = report.summarize([row])
    assert report.frontier(means, "tcp_syn_ping_p99_ms") == []
    assert len(report.frontier(means, "packet_extra_pct")) == 1
    assert len(report.frontier(means, "byte_extra_pct")) == 1


def test_syn_summary_requires_every_replication_and_retains_failure_counts():
    rows = [normalized(syn_observation(seed=1)), normalized(syn_observation(seed=2, tcp_syn_ping_p99_ms=85,
            tcp_syn_ping_failure_pct=1, tcp_syn_ping_completed=99, tcp_syn_ping_timeouts=1))]
    rows[1]["id"] = "compact-study/runs/2.json#1"
    summary = report.summarize(rows)[0]
    assert summary["tcp_syn_ping_p99_ms"] == 90
    assert summary["tcp_syn_ping_failure_pct"] == .5
    assert summary["tcp_syn_ping_offered"] == 200
    assert summary["tcp_syn_ping_completed"] == 199
    assert summary["tcp_syn_ping_timeouts"] == 1
    assert not summary["tcp_syn_ping_frontier_eligible"]
    assert report.frontier([summary], "tcp_syn_ping_p99_ms") == []
    assert report.frontier([summary], "packet_extra_pct") == [summary]


def test_probe_configuration_separates_syn_frontiers_without_changing_cost_cohorts():
    rows = [normalized(syn_observation(tcp_syn_probe_config=dict(interval_ms=100))),
            normalized(syn_observation(name="Other interval", tcp_syn_ping_p99_ms=110,
                                       tcp_goodput_mbps=79, tcp_syn_probe_config=dict(interval_ms=500)))]
    rows[1]["id"] = "compact-study/runs/2.json#1"
    assert rows[0]["cohort"] == rows[1]["cohort"]
    frontiers = report.frontier_rows(report.summarize(rows))
    assert len([row for row in frontiers if row["frontier_metric"] == "tcp_syn_ping_p99_ms"]) == 2
    assert len([row for row in frontiers if row["frontier_metric"] == "packet_extra_pct"]) == 1
    fallback = report.normalize(observation(), dict(profile=dict(tcp_syn_probe=dict(interval_ms=250))),
                                {}, "fixture", "fixture/1.json", 1)
    assert json.loads(fallback["tcp_syn_probe_config"]) == dict(interval_ms=250)


def test_probe_copy_strategies_compete_within_the_same_measurement_frontier(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "get_plotlyjs", lambda: "")
    configurations = [dict(interval_ms=100, timeout_ms=3000, reverse_copies=1, copy_spacing_ms=0),
                      dict(interval_ms=100, timeout_ms=3000, reverse_copies=3, copy_spacing_ms=.25)]
    rows = [normalized(syn_observation(name="One copy", tcp_syn_ping_p99_ms=150,
                                      tcp_syn_probe_config=configurations[0])),
            normalized(syn_observation(name="Three copies", tcp_syn_ping_p99_ms=90,
                                      tcp_syn_probe_config=configurations[1]))]
    rows[1]["id"] = "compact-study/runs/2.json#1"
    assert [json.loads(row["tcp_syn_probe_config"]) for row in rows] == configurations
    assert {row["tcp_syn_probe_measurement_config"] for row in rows} == {
        json.dumps(dict(interval_ms=100, timeout_ms=3000), sort_keys=True)}
    means = report.summarize(rows)
    assert len(means) == 2
    frontiers = report.frontier_rows(means)
    syn_frontier = [row for row in frontiers if row["frontier_metric"] == "tcp_syn_ping_p99_ms"]
    assert [row["name"] for row in syn_frontier] == ["Three copies"]
    report.html_report(tmp_path, rows, means, frontiers, [])
    page = (tmp_path / "historical-overview.html").read_text()
    assert "metric==='tcp_syn_ping_p99_ms'?r.tcp_syn_probe_measurement_config:null" in page


def test_primary_frontier_uses_concurrent_goodput_and_preserves_original_metrics(tmp_path):
    rows = [normalized(syn_observation(name="Higher full goodput", tcp_goodput_mbps=90,
                tcp_syn_ping_p99_ms=100, tcp_syn_ping_background_goodput_mbps=79,
                tcp_syn_probe_steady_state_reached=True)),
            normalized(syn_observation(name="Higher concurrent goodput", tcp_goodput_mbps=80,
                tcp_syn_ping_p99_ms=90, tcp_syn_ping_background_goodput_mbps=80,
                tcp_syn_probe_steady_state_reached=True))]
    rows[1]["id"] = "compact-study/runs/2.json#1"
    means = report.summarize(rows)
    before = json.dumps(dict(rows=rows, means=means), sort_keys=True)
    view = report.syn_presentation(rows, means, tmp_path)
    assert len(view["cohorts"]) == 1
    assert len(view["observations"]) == 2
    assert [row["name"] for row in view["frontiers"]] == ["Higher concurrent goodput"]
    assert view["frontiers"][0]["goodput_mbps"] == 80
    assert json.dumps(dict(rows=rows, means=means), sort_keys=True) == before
    assert len(report.frontier(means, "tcp_syn_ping_p99_ms")) == 2


def test_primary_views_match_package_helper_and_runtime_with_full_manifest_input(tmp_path):
    from test_tcp_syn_ping_report import syn_study
    syn_study(tmp_path, "first")
    second = syn_study(tmp_path, "second")
    rows, _ = report.load_all(tmp_path, tmp_path / "out")
    view = report.syn_presentation(rows, report.summarize(rows), tmp_path)
    assert len(view["cohorts"]) == 1
    manifest_path = second / "experiment.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["runtime"]["aioquic"] = "different-fixture-version"
    manifest_path.write_text(json.dumps(manifest))
    changed = report.syn_presentation(rows, report.summarize(rows), tmp_path)
    assert len(changed["cohorts"]) == 2


@pytest.mark.parametrize("profile,raw,name,family", [
    ({"mode": "tcp"}, {}, "Compact named baseline", "Plain TCP"),
    ({"kind": "quic"}, {}, "Baseline", "QUIC"),
    ({"mode": "kcp"}, {}, "Baseline", "KCP"),
    ({"mode": "arq"}, {}, "ARQ", "ARQ"),
    ({"mode": "block"}, {}, "MDS 5+1", "Block FEC"),
    ({"mode": "sliding"}, {}, "Sliding", "Sliding-window coding"),
    ({"mode": "hybrid"}, {}, "Hybrid", "Hybrid coding and ARQ"),
    ({"recovery": "block"}, {"transport": "direct_tcp"}, "Block inherited metrics", "Block FEC"),
    ({"compact": {"repair_ratio": 0}}, {}, "Candidate", "Compact ARQ"),
    ({"compact": {"repair_ratio": .2}, "recovery": "arq"}, {}, "Recorded positive FEC", "Sliding-window coding"),
    ({"wire_format": "aligned_records"}, {}, "Aligned", "Aligned shared coding"),
    ({"wire_format": "compact_wire"}, {}, "Compact", "Compact wire coding"),
    ({"mode": "tcp", "wire_format": "compact_wire"}, {}, "Tunneled TCP", "Compact wire coding"),
    ({"mode": "tcp", "wire_format": "aligned_records"}, {}, "Tunneled TCP", "Aligned shared coding"),
    ({"mode": "tcp", "recovery": "shared_record_rlnc"}, {}, "Tunneled TCP", "Shared compact coding"),
    ({"mode": "tcp", "recovery": "block"}, {}, "Tunneled TCP", "Block FEC"),
    ({"mode": "tcp", "compact": {"repair_ratio": 0}}, {}, "Tunneled TCP", "Compact ARQ"),
    ({"mode": "tcp", "compact": {"repair_ratio": .22}}, {}, "Tunneled TCP", "Sliding-window coding"),
    ({"recovery": "shared_record_rlnc"}, {}, "Shared", "Shared compact coding"),
    ({}, {"transport": "shared_compact_inner_tcp"}, "Shared", "Shared compact coding"),
    ({}, {"transport": "direct_tcp"}, "Plain", "Plain TCP"),
    ({}, {}, "Block 20+10", "Block FEC"),
    ({}, {}, "Unknown experiment", "Unclassified"),
])
def test_strategy_family_uses_recorded_protocol_fields(profile, raw, name, family):
    actual, evidence = report.strategy_family(raw, profile, name)
    assert actual == family
    assert actual in report.STRATEGY_COLORS
    assert evidence


def test_family_colors_apply_to_raw_mean_and_missing_points(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "get_plotlyjs", lambda: "")
    rows = [normalized(syn_observation(profile=dict(mode="tcp"))),
            normalized(name="Unmeasured QUIC", profile=dict(kind="quic"))]
    rows[1]["id"] = "compact-study/runs/2.json#1"
    means = report.summarize(rows)
    assert {row["strategy_type"] for row in means} == {"Plain TCP", "QUIC"}
    report.html_report(tmp_path, rows, means, report.frontier_rows(means), [])
    page = (tmp_path / "report.html").read_text()
    assert "row.strategy_type===family" in page
    assert "color:data.strategy_colors[family]" in page
    assert "legendgroup:family" in page
    historical = (tmp_path / "historical-overview.html").read_text()
    assert "const familyColors=data.strategy_colors" in historical
    assert "color:familyColors[family]" in historical
    assert "timeout and censored counts" in historical
    assert "every probe completed" in historical


def test_syn_gate_start_and_background_goodput_are_retained_in_exports_and_tooltips(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "get_plotlyjs", lambda: "")
    row = normalized(syn_observation(tcp_syn_probe_steady_state_reached=True,
                                    tcp_syn_probe_start_s=2.5, tcp_syn_ping_background_goodput_mbps=80.04))
    assert row["tcp_syn_probe_steady_state_reached"] is True
    assert row["tcp_syn_probe_start_s"] == 2.5
    assert row["tcp_syn_ping_background_goodput_mbps"] == 80.04
    means = report.summarize([row])
    assert means[0]["tcp_syn_probe_steady_state_reached"] is True
    assert means[0]["tcp_syn_probe_start_s"] == 2.5
    assert means[0]["tcp_syn_ping_background_goodput_mbps"] == 80.04
    report.html_report(tmp_path, [row], means, report.frontier_rows(means), [])
    page = (tmp_path / "report.html").read_text()
    assert "traffic cutoff minus probe timeout" in page
    assert "Steady-state gate " in page
    assert "Concurrent bulk " in page


def test_archive_loads_large_embedded_measurement_fields(tmp_path):
    previous_limit = report.csv.field_size_limit(131072)
    try:
        save_csv(tmp_path / "large-records.csv", [observation(probe_trace="x" * 200000)])
        rows, _ = report.load_all(tmp_path, tmp_path / "out")
        assert len(rows) == 1
        assert rows[0]["source"] == "large-records.csv"
        assert rows[0]["goodput_mbps"] == 80
    finally:
        report.csv.field_size_limit(previous_limit)


@pytest.mark.parametrize("status", ["unsupported", "error", "failed", "bound exhausted"])
def test_identical_failed_csv_export_aliases_json_without_numeric_measurements(tmp_path, status):
    raw = dict(run_id=19, seed=123, execution_status=status, application_goodput_mbps=None,
               error="channel limit", profile={"flow_count": 256})
    save_json(tmp_path / "study/runs/00019.json", raw)
    save_csv(tmp_path / "study/replications.csv", [dict(raw, extra_empty_field="")])
    rows, inventory = report.load_all(tmp_path, tmp_path / "out")
    assert [row["id"] for row in rows] == ["study/runs/00019.json#1"]
    export = next(item for item in inventory if item["study"] == "study/replications.csv")
    assert export["alias_rows"] == 1
    assert json.loads(export["alias_targets"]) == [rows[0]["id"]]
    save_csv(tmp_path / "study/replications.csv", [dict(raw, error="different failure")])
    rows, _ = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 2


@pytest.mark.parametrize("run_id", [None, ""])
def test_failed_export_without_run_identity_stays_an_independent_observation(tmp_path, run_id):
    raw = dict(run_id=run_id, seed=123, execution_status="unsupported",
               application_goodput_mbps=None, error="channel limit")
    save_json(tmp_path / "study/runs/unknown.json", raw)
    save_csv(tmp_path / "study/replications.csv", [raw])
    rows, _ = report.load_all(tmp_path, tmp_path / "out")
    assert len(rows) == 2
