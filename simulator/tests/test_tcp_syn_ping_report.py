"""SYN-ping report fixtures cover measurement cohorts and preserved source evidence."""

from copy import deepcopy
import csv
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path

import pytest

from l2tunnel_sim.tcp_syn_probe import SYNProbeConfig
from test_compact_ack_report import fixture_study


RUNTIME = {"python": "3.12.8", "numpy": "2.2.6", "scipy": "1.15.3", "aioquic": "1.3.0"}
ENGINE_FILES = ("src/l2tunnel_sim/model.py", "src/l2tunnel_sim/tcp.py",
                "src/l2tunnel_sim/compact.py", "src/l2tunnel_sim/tcp_syn_probe.py",
                "studies/payload_sizes.py")
VERSION_CHANGES = [("sources", "src/l2tunnel_sim/tcp_syn_probe.py"),
                   ("sources", "studies/payload_sizes.py"),
                   *[("runtime", name) for name in RUNTIME]]


@pytest.fixture
def report(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    import tcp_syn_ping_report
    return tcp_syn_ping_report


def syn_study(root, name, *, count=1, mutate=None):
    def with_probe(index, task, raw):
        config = asdict(SYNProbeConfig(interval_ms=200))
        task["profile"]["tcp_syn_probe"] = config
        raw["profile"] = json.dumps(task["profile"])
        raw.update(tcp_syn_probe_config=deepcopy(config), execution_status="completed",
            tcp_syn_probe_all_flushed=True, tcp_syn_probe_steady_state_reached=True,
            tcp_syn_probe_start_s=3, tcp_syn_probe_admission_end_s=5,
            tcp_syn_ping_background_goodput_mbps=80.2, tcp_syn_ping_budget_ms=105,
            tcp_syn_ping_offered=1, tcp_syn_ping_completed=1, tcp_syn_ping_timeouts=0,
            tcp_syn_ping_censored=0, tcp_syn_ping_failure_pct=0,
            tcp_syn_ping_deadline_miss_upper_pct=0, tcp_syn_ping_p50_ms=90,
            tcp_syn_ping_p95_ms=90, tcp_syn_ping_p99_ms=90,
            tcp_syn_probe_records=[dict(index=0, started_at=3, completed_at=3.09)],
            tcp_syn_probe_stability_history=[dict(end_s=second, goodput_mbps=80.2,
                forward_queue_mean_ms=0, reverse_queue_mean_ms=0, stable=second == 3)
                for second in (1, 2, 3)])
        if mutate:
            mutate(index, task, raw)

    directory = fixture_study(root, name, count=count, mutate=with_probe)
    path = directory / "experiment.json"
    manifest = json.loads(path.read_text())
    for source in (*ENGINE_FILES, f"studies/{name}_executor.py"):
        snapshot = directory / "sources" / source
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(f"# Frozen report fixture for {source}.\n")
        manifest["sources"][source] = sha256(snapshot.read_bytes()).hexdigest()
    manifest["runtime"] = dict(RUNTIME)
    path.write_text(json.dumps(manifest))
    return directory


@pytest.mark.parametrize("section,key", VERSION_CHANGES)
def test_comparison_version_changes_for_engine_helper_and_runtime(report, section, key):
    manifest = dict(sources={name: sha256(name.encode()).hexdigest() for name in ENGINE_FILES},
                    runtime=dict(RUNTIME))
    changed = deepcopy(manifest)
    changed[section][key] += "-changed"
    assert report.comparison_version(changed)[0] != report.comparison_version(manifest)[0]


def test_comparison_version_normalizes_runtime_layout_and_executor_inventories(report):
    sources = {name: sha256(name.encode()).hexdigest() for name in ENGINE_FILES}
    first = dict(sources=dict(sources, **{"studies/first_executor.py": "a" * 64}),
                 runtime=dict(RUNTIME, cryptography="44.0.0"))
    second = dict(sources=dict(sources, **{"studies/second_executor.py": "b" * 64}),
                  python=RUNTIME["python"], dependencies={key: value for key, value in RUNTIME.items()
                                                        if key != "python"})
    second["dependencies"]["cryptography"] = "45.0.0"
    first_version, first_runtime = report.comparison_version(first)
    second_version, second_runtime = report.comparison_version(second)
    assert first_version == second_version
    assert first_runtime["cryptography"] == "44.0.0"
    assert second_runtime["cryptography"] == "45.0.0"
    assert {key: first_runtime[key] for key in RUNTIME} == RUNTIME
    assert {key: second_runtime[key] for key in RUNTIME} == RUNTIME


@pytest.mark.parametrize("section,key", VERSION_CHANGES)
def test_loaded_cohorts_separate_changed_engine_helper_and_runtime(report, tmp_path, section, key):
    syn_study(tmp_path, "first")
    directory = syn_study(tmp_path, "second")
    path = directory / "experiment.json"
    manifest = json.loads(path.read_text())
    if section == "sources":
        snapshot = directory / "sources" / key
        snapshot.write_text(snapshot.read_text() + "# Changed implementation fixture.\n")
        manifest[section][key] = sha256(snapshot.read_bytes()).hexdigest()
    else:
        manifest[section][key] += "-changed"
    path.write_text(json.dumps(manifest))
    rows, _, _, _ = report.load(tmp_path, ["first", "second"])
    assert all(row["eligible"] for row in rows)
    assert rows[0]["version"] == rows[1]["version"]
    assert rows[0]["engine_source_version"] != rows[1]["engine_source_version"]
    assert rows[0]["cohort"] != rows[1]["cohort"]


def test_executor_inventories_share_cohort_and_retain_both_full_receipts(report, tmp_path):
    syn_study(tmp_path, "first")
    syn_study(tmp_path, "second")
    rows, evidence, _, _ = report.load(tmp_path, ["first", "second"])
    assert rows[0]["cohort"] == rows[1]["cohort"]
    assert rows[0]["engine_source_version"] == rows[1]["engine_source_version"]
    assert rows[0]["report_source_version"] != rows[1]["report_source_version"]
    assert rows[0]["cohort_label"] == rows[1]["cohort_label"]
    assert all("all-source" not in row["cohort_label"] for row in rows)
    assert {item["study"] for item in evidence} == {row["study"] for row in rows}
    output = tmp_path / "report"
    receipt = report.render(tmp_path, ["first", "second"], output)
    assert receipt["saved_runs"] == 2
    assert len(receipt["studies"]) == 2
    assert {item["study"]: item["source_hashes"] for item in receipt["studies"]} == {
        item["study"]: item["source_hashes"] for item in evidence}
    page = (output / "report.html").read_text()
    for row in rows:
        assert f'<td>{row["study"]}</td><td>{row["report_source_version"]}</td>' in page
    with (output / "all-runs.csv").open() as stream:
        exports = list(csv.DictReader(stream))
    assert {row["id"] for row in exports} == {row["id"] for row in rows}
    assert {row["report_source_version"] for row in exports} == {row["report_source_version"] for row in rows}


def test_reverse_copy_policy_competes_but_measurement_frequency_separates(report, tmp_path):
    def mutate(index, task, raw):
        config = task["profile"]["tcp_syn_probe"]
        if index == 1:
            config.update(reverse_copies=3, copy_spacing_ms=.5)
            raw["tcp_syn_ping_p99_ms"] = 85
        if index == 2:
            config["interval_ms"] = 500
        raw["tcp_syn_probe_config"] = deepcopy(config)
        raw["profile"] = json.dumps(task["profile"])

    syn_study(tmp_path, "copies", count=3, mutate=mutate)
    rows, _, _, _ = report.load(tmp_path, ["copies"])
    assert all(row["eligible"] for row in rows)
    assert rows[0]["cohort"] == rows[1]["cohort"] != rows[2]["cohort"]
    means = report.summarize(rows)
    assert len(means) == 3
    competing = [row for row in means if row["cohort"] == rows[0]["cohort"]]
    frontier = report.frontier(competing, "goodput_mbps")
    assert len(frontier) == 1
    assert json.loads(frontier[0]["raw_ids"]) == [rows[1]["id"]]


def test_unsupported_failed_and_unsteady_cases_remain_visible_and_ineligible(report, tmp_path):
    def mutate(index, task, raw):
        if index == 0:
            return
        raw.update(tcp_syn_probe_steady_state_reached=False, tcp_syn_probe_start_s=None,
            tcp_syn_ping_offered=0, tcp_syn_ping_completed=0, tcp_syn_ping_failure_pct=None,
            tcp_syn_ping_p50_ms=None, tcp_syn_ping_p95_ms=None, tcp_syn_ping_p99_ms=None,
            tcp_syn_ping_background_goodput_mbps=None, tcp_syn_probe_records=[])
        if index in (1, 2):
            raw["execution_status"] = "unsupported" if index == 1 else "error"
            raw["error"] = "Terminal report fixture"
            raw["fully_confirmed"] = False
            raw["application_goodput_mbps"] = None

    syn_study(tmp_path, "outcomes", count=4, mutate=mutate)
    rows, _, probes, windows = report.load(tmp_path, ["outcomes"])
    assert [row["status"] for row in rows] == ["complete", "unsupported", "tool failure", "ineligible"]
    assert [row["eligible"] for row in rows] == [True, False, False, False]
    assert "unsupported configuration" in rows[1]["exclusion_reason"]
    assert "tool failure" in rows[2]["exclusion_reason"]
    assert "stability gate not reached" in rows[3]["exclusion_reason"]
    assert len(probes) == 1 and len(windows) == 12
    assert not report.frontier(report.summarize(rows), "goodput_mbps")
    output = tmp_path / "report"
    receipt = report.render(tmp_path, ["outcomes"], output)
    assert receipt["saved_runs"] == 4
    assert receipt["frontier_eligible_runs"] == 1
    with (output / "all-runs.csv").open() as stream:
        exports = list(csv.DictReader(stream))
    assert {row["id"] for row in exports} == {row["id"] for row in rows}
    page = (output / "report.html").read_text()
    assert all(row["source"] in page for row in rows)
    assert all(reason in page for reason in ("unsupported configuration", "tool failure", "stability gate not reached"))


def test_static_figures_label_latency_ticks_targets_and_model_scope(report, tmp_path, monkeypatch):
    syn_study(tmp_path, "static")
    rows, _, _, _ = report.load(tmp_path, ["static"])
    output = tmp_path / "figures"
    output.mkdir()
    captured = []
    from matplotlib.figure import Figure
    original_save = Figure.savefig

    def verify_and_save(figure, filename, **kwargs):
        axis = figure.axes[0]
        labels = [label.get_text() for label in axis.get_xticklabels()]
        assert labels and all(float(label) > 0 for label in labels)
        assert "Coefficient/rank simulation" in axis.get_title()
        legends = [label.get_text() for legend in figure.legends for label in legend.get_texts()]
        assert "PING target 105 ms" in legends
        assert "Goodput target 80 Mbps" in legends
        assert axis.get_ylim()[1] > max(row["tcp_syn_ping_background_goodput_mbps"] for row in rows)
        captured.append(filename)
        return original_save(figure, filename, **kwargs)

    monkeypatch.setattr(Figure, "savefig", verify_and_save)
    report.figures(output, rows, report.summarize(rows))
    assert len(captured) == 2


RECEIVED_MODEL = {
    "tcp_syn_probe_dispatch": "received-header TCP four-tuple and flags",
    "tcp_syn_probe_cpu_model": "Packet processing consumes zero simulated CPU time",
    "tcp_syn_probe_model_detail": "Decoded TCP/IP headers select endpoint state",
}


def test_mixed_endpoint_modes_preserve_metadata_and_separate_cohorts(report, tmp_path):
    def mutate(index, task, raw):
        if index == 1:
            raw.update(RECEIVED_MODEL)
        elif index == 2:
            raw["tcp_syn_probe_dispatch"] = "callback-bound endpoint identity"

    syn_study(tmp_path, "mixed", count=3, mutate=mutate)
    rows, _, _, _ = report.load(tmp_path, ["mixed"])
    assert len({row["engine_source_version"] for row in rows}) == 1
    assert len({row["cohort"] for row in rows}) == 3
    assert [row["endpoint_dispatch"] for row in rows] == [
        "unrecorded", RECEIVED_MODEL["tcp_syn_probe_dispatch"], "callback-bound endpoint identity"]
    assert rows[1]["probe_cpu_model"] == RECEIVED_MODEL["tcp_syn_probe_cpu_model"]
    assert rows[1]["probe_model_detail"] == RECEIVED_MODEL["tcp_syn_probe_model_detail"]
    means = report.summarize(rows)
    assert len(means) == 3
    assert {row["endpoint_dispatch"] for row in means} == {row["endpoint_dispatch"] for row in rows}
    output = tmp_path / "report"
    receipt = report.render(tmp_path, ["mixed"], output)
    assert receipt["saved_runs"] == 3
    assert receipt["endpoint_dispatch_counts"] == {row["endpoint_dispatch"]: 1 for row in rows}
    assert receipt["raw_inputs"] == {row["source"]: row["source_sha256"] for row in rows}
    page = (output / "report.html").read_text()
    assert "These frozen campaigns use callback-bound" not in page
    assert "Missing dispatch metadata is labeled unrecorded" in page
    assert "1 received-header TCP four-tuple and flags" in page
    assert "1 callback-bound endpoint identity" in page
    assert "1 unrecorded" in page
    assert "<th>Probe CPU model</th>" in page
    assert 'data-syn-dispatch="syn-ping-p0"' in page
    assert {cohort["endpoint_dispatch"] for cohort in receipt["charts"][0]["cohorts"]} == {
        row["endpoint_dispatch"] for row in rows}
    for filename in ("all-runs.csv", "configuration-means.csv"):
        with (output / filename).open() as stream:
            exports = list(csv.DictReader(stream))
        assert {row["endpoint_dispatch"] for row in exports} == {row["endpoint_dispatch"] for row in rows}
        current = next(row for row in exports if row["endpoint_dispatch"] == RECEIVED_MODEL["tcp_syn_probe_dispatch"])
        assert current["probe_model_detail"] == RECEIVED_MODEL["tcp_syn_probe_model_detail"]
        assert current["probe_cpu_model"] == RECEIVED_MODEL["tcp_syn_probe_cpu_model"]


@pytest.mark.parametrize("metadata_key", ["tcp_syn_probe_cpu_model", "tcp_syn_probe_model_detail"])
def test_recorded_probe_model_changes_separate_comparison_cohorts(report, tmp_path, metadata_key):
    def mutate(index, task, raw):
        raw.update(RECEIVED_MODEL)
        if index == 1:
            raw[metadata_key] += " with a changed modeled assumption"

    syn_study(tmp_path, "models", count=2, mutate=mutate)
    rows, _, _, _ = report.load(tmp_path, ["models"])
    assert rows[0]["engine_source_version"] == rows[1]["engine_source_version"]
    assert rows[0]["original_profile"] == rows[1]["original_profile"]
    assert rows[0]["cohort"] != rows[1]["cohort"]
    assert len(report.summarize(rows)) == 2


def test_short_source_and_repair_profiles_compete_as_distinct_configurations(report, tmp_path):
    settings = [(128, 1, .221), (128, 4, .221), (64, 4, .221), (128, 4, .25)]

    def mutate(index, task, raw):
        threshold, copies, ratio = settings[index]
        task["profile"]["compact"].update(short_source_max_bytes=threshold,
            short_source_copies=copies, repair_ratio=ratio)
        raw["profile"] = json.dumps(task["profile"])
        raw.update(RECEIVED_MODEL)

    syn_study(tmp_path, "protection", count=len(settings), mutate=mutate)
    rows, _, _, _ = report.load(tmp_path, ["protection"])
    assert len({row["label"] for row in rows}) == 1
    assert len({row["cohort"] for row in rows}) == 1
    assert len({row["configuration"] for row in rows}) == len(settings)
    means = report.summarize(rows)
    assert len(means) == len(settings)
    assert all(row["n"] == 1 for row in means)
    output = tmp_path / "report"
    report.render(tmp_path, ["protection"], output)
    for filename in ("all-runs.csv", "configuration-means.csv"):
        with (output / filename).open() as stream:
            exports = list(csv.DictReader(stream))
        profiles = [json.loads(row["original_profile"])["compact"] for row in exports]
        assert {(profile["short_source_max_bytes"], profile["short_source_copies"], profile["repair_ratio"])
                for profile in profiles} == set(settings)
        assert {profile["repair_window_sources"] for profile in profiles} == {128}
        assert {profile["global_repair_every"] for profile in profiles} == {16}
        assert all(profile["trim_repair_padding"] for profile in profiles)
