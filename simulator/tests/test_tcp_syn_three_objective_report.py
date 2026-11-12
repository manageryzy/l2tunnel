"""Final-series publication preserves complete measured seed groups and 3D tradeoffs."""

from copy import deepcopy
import csv
import importlib
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys

import pytest

from test_tcp_syn_ping_report import syn_study


def add_matching_measurement(task, raw):
    prefix = "tcp_syn_ping_measurement_"
    start = dict(at_s=3, delivered_payload_bytes=0, forward_serialized_ip_bytes=0,
                 reverse_serialized_ip_bytes=0, forward_departed_ip_bytes=0, reverse_departed_ip_bytes=0)
    end = dict(at_s=task["duration_s"], delivered_payload_bytes=100 * task["payload_bytes"],
               forward_serialized_ip_bytes=180000, reverse_serialized_ip_bytes=1000,
               forward_departed_ip_bytes=180000, reverse_departed_ip_bytes=1000)
    duration = end["at_s"] - start["at_s"]
    payload = end["delivered_payload_bytes"]
    fields = dict(start_s=start["at_s"], end_s=end["at_s"], duration_s=duration, payload_bytes=payload,
                  forward_ip_bytes=180000, reverse_ip_bytes=1000, forward_departed_ip_bytes=180000,
                  reverse_departed_ip_bytes=1000, forward_mbps=180000 * 8 / duration / 1e6,
                  reverse_mbps=1000 * 8 / duration / 1e6, extra_forward_ip_pct=100 * (180000 / payload - 1),
                  snapshots=dict(start=start, end=end), byte_accounting="Fixture same-window serialized IP service")
    raw.update({prefix + key: value for key, value in fields.items()})
    raw.update(payload_bytes_per_frame=task["payload_bytes"], tcp_syn_ping_background_goodput_mbps=payload * 8 / duration / 1e6)


@pytest.fixture(scope="module")
def series():
    directory = str(Path(__file__).resolve().parents[1] / "studies")
    sys.path.insert(0, directory)
    try:
        yield importlib.import_module("tcp_syn_three_objective_report")
    finally:
        sys.path.remove(directory)


@pytest.fixture(scope="module")
def campaign(series, tmp_path_factory):
    root = tmp_path_factory.mktemp("three-objective-publication")

    def mutate(index, task, raw):
        payload = index // 24
        configuration = (index // 3) % 8
        task.update(payload_bytes=series.PAYLOADS[payload], seed=index % 3 + 100, replication=index % 3 + 1)
        task["profile"].update(name=f"Complete configuration {configuration}", choice=configuration)
        raw.update(task, profile=json.dumps(task["profile"]), strategy=task["profile"]["name"])
        add_matching_measurement(task, raw)

    syn_study(root, "current", count=144, mutate=mutate)
    rows, _, _, _ = series.report.load(root, ["current"])
    series.audit_bytes(root, rows)
    selection = dict(record_kind="explicit_complete_configuration_selection", studies=[dict(
        study="current", run_ids=[row["run_id"] for row in rows])])
    return root, rows, selection


def test_publication_requires_complete_groups_for_every_payload(series, campaign):
    _, rows, selection = campaign
    selected, receipt = series.select_rows(rows, selection, 8)
    assert selected == rows
    assert receipt["selected_rows"] == receipt["measured_rows"] == 144
    assert receipt["coverage_only_rows"] == 0
    assert receipt["configuration_counts"] == {str(payload): 8 for payload in series.PAYLOADS}
    assert len(receipt["configuration_seed_receipts"]) == 48
    assert all(group["seeds"] == ["100", "101", "102"] for group in receipt["configuration_seed_receipts"])


@pytest.mark.parametrize("metric", ("tcp_syn_ping_p99_ms", "probe_interval_goodput_mbps", "probe_interval_extra_ip_pct"))
@pytest.mark.parametrize("value", (None, float("nan"), float("inf"), float("-inf")))
def test_publication_rejects_every_missing_or_nonfinite_coordinate(series, campaign, metric, value):
    _, original, selection = campaign
    rows = deepcopy(original)
    rows[0][metric] = value
    with pytest.raises(ValueError, match="finite measured three-axis coordinates"):
        series.select_rows(rows, selection, 8)


@pytest.mark.parametrize("updates", (
    {"tcp_syn_probe_steady_state_reached": False},
    {"status": "unsupported"},
    {"status": "tool failure"},
    {"status": "bound exhausted"},
    {"tcp_syn_ping_p99_ms": 0},
    {"probe_interval_goodput_mbps": -1},
))
def test_publication_rejects_unmeasured_rows(series, campaign, updates):
    _, original, selection = campaign
    rows = deepcopy(original)
    rows[0].update(updates)
    with pytest.raises(ValueError, match="finite measured three-axis coordinates"):
        series.select_rows(rows, selection, 8)


def test_selection_cannot_remove_an_unsuccessful_seed(series, campaign):
    _, original, original_selection = campaign
    rows, selection = deepcopy(original), deepcopy(original_selection)
    rows[0]["tcp_syn_probe_steady_state_reached"] = False
    selection["studies"][0]["run_ids"].remove(rows[0]["run_id"])
    with pytest.raises(ValueError, match="omits recorded members"):
        series.select_rows(rows, selection, 8)


@pytest.mark.parametrize("seed", (None, 100))
def test_selection_requires_three_distinct_known_seeds(series, campaign, seed):
    _, original, selection = campaign
    rows = deepcopy(original)
    rows[1]["seed"] = seed
    with pytest.raises(ValueError, match="exactly three distinct recorded seeds"):
        series.select_rows(rows, selection, 8)


@pytest.mark.parametrize("extra_run_id, message", ((1, "unique explicit"), (999999, "Unknown selected")))
def test_selection_rejects_duplicate_or_unknown_identity(series, campaign, extra_run_id, message):
    _, rows, original = campaign
    selection = deepcopy(original)
    selection["studies"][0]["run_ids"].append(extra_run_id)
    with pytest.raises(ValueError, match=message):
        series.select_rows(rows, selection, 8)


def test_selection_cannot_replace_configuration_coverage_with_duplicate_cohorts(series, campaign):
    _, original, selection = campaign
    rows = deepcopy(original)
    rows[0]["original_profile"] = rows[3]["original_profile"]
    rows[1]["original_profile"] = rows[3]["original_profile"]
    rows[2]["original_profile"] = rows[3]["original_profile"]
    for row in rows[:3]:
        row["cohort"] += " alternate source cohort"
    with pytest.raises(ValueError, match="requires 8 complete configurations, observed 7"):
        series.select_rows(rows, selection, 8)


def test_measured_timeouts_remain_visible_but_frontier_ineligible(series, campaign):
    _, original, selection = campaign
    rows = deepcopy(original)
    rows[0].update(eligible=False, status="ineligible", tcp_syn_ping_timeouts=7,
                   exclusion_reason="probe failures or unresolved probes")
    selected, _ = series.select_rows(rows, selection, 8)
    means = series.summarize(selected)
    affected = next(mean for mean in means if rows[0]["id"] in json.loads(mean["raw_ids"]))
    assert affected["n"] == 3
    assert affected["complete_three_seed_coordinates"]
    assert affected["timeout_count"] == 7
    assert not affected["eligible"]
    assert affected not in series.frontier(means)


def test_frontier_uses_all_three_objectives_and_preserves_ties(series):
    def point(identifier, latency, goodput, overhead, *, eligible=True, complete=True):
        return dict(id=identifier, tcp_syn_ping_p99_ms=latency, probe_interval_goodput_mbps=goodput,
                    probe_interval_extra_ip_pct=overhead, eligible=eligible, complete_three_seed_coordinates=complete)

    points = [point("fast", 90, 75, 25), point("higher-throughput", 100, 80, 30),
              point("lower-overhead", 110, 85, 20), point("tied", 90, 75, 25),
              point("dominated", 110, 70, 40), point("ineligible", 50, 90, 10, eligible=False),
              point("incomplete", 40, 100, 5, complete=False)]
    assert {point["id"] for point in series.frontier(points)} == {
        "fast", "higher-throughput", "lower-overhead", "tied"}


def test_overhead_uses_same_window_serialization_service_and_delivered_payload(series, campaign):
    root, original, _ = campaign
    rows = deepcopy(original)
    series.audit_bytes(root, rows)
    assert all(row[series.OVERHEAD] == pytest.approx(
        100 * (row["probe_interval_forward_ip_bytes"] / row["probe_interval_payload_bytes"] - 1)) for row in rows)
    rows[0][series.OVERHEAD] += 1
    with pytest.raises(ValueError, match="capacity identity mismatch"):
        series.validate_capacity(rows[0])


def test_conditions_expose_window_duration_and_fixed_or_uncapped_load(series, campaign):
    _, rows, _ = campaign
    fixed = series.condition(rows[0])
    assert fixed["payload_rate_mbps"] == 80.12
    assert fixed["stability_gate_label"] == "3 × 1 s"
    row = deepcopy(rows[0])
    profile, probe = json.loads(row["original_profile"]), json.loads(row["tcp_syn_probe_config"])
    profile.pop("payload_rate_mbps")
    probe["stability_window_s"] = 30
    row.update(original_profile=json.dumps(profile), tcp_syn_probe_config=json.dumps(probe))
    uncapped = series.condition(row)
    assert uncapped["stability_gate_label"] == "3 × 30 s"
    assert uncapped["payload_rate_mbps"] is None
    assert "no fixed Mbps cap" in uncapped["offered_load_label"]


def test_render_rejects_missing_coordinates_before_writing_output(series, campaign, tmp_path, monkeypatch):
    root, original, selection = campaign
    rows = deepcopy(original)
    rows[0][series.LATENCY] = None
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(json.dumps(selection))
    output = tmp_path / "report"
    monkeypatch.setattr(series.report, "load", lambda *_: (rows, [], [], []))
    with pytest.raises(ValueError, match="finite measured three-axis coordinates"):
        series.render(root, selection_path, output)
    assert not output.exists()


@pytest.mark.parametrize("peak, target_visible", ((8, False), (20, False), (70, True), (80, True)))
def test_static_goodput_axes_follow_observations_with_conditional_capacity_target(
        series, campaign, tmp_path, monkeypatch, peak, target_visible):
    _, original, _ = campaign
    rows = deepcopy(original[:3])
    for row in rows:
        row["probe_interval_payload_bytes"] = peak * row["probe_interval_duration_s"] * 1e6 / 8
        row["probe_interval_forward_ip_bytes"] = row["probe_interval_payload_bytes"] * 1.25
        row[series.GOODPUT] = peak
        row[series.OVERHEAD] = 25
    means = series.summarize(rows)
    series.decorate(rows, means)
    original_close = series.plt.close
    monkeypatch.setattr(series.plt, "close", lambda *_: None)
    monkeypatch.setattr("matplotlib.figure.Figure.savefig", lambda *_args, **_kwargs: None)
    series.static_figure(tmp_path, 64, rows, means, series.frontier(means))
    figure = series.plt.gcf()
    try:
        for axis in figure.axes[:2]:
            upper = axis.get_ylim()[1]
            assert upper > peak
            assert upper < 100 if target_visible else upper < peak * 1.2
            reference_lines = [line for line in axis.lines if line.get_color() == "#15803d"]
            assert bool(reference_lines) is target_visible
        for axis in (figure.axes[0], figure.axes[2]):
            reference_lines = [line for line in axis.lines if line.get_color() == "#b91c1c"]
            assert len(reference_lines) == 1
            assert list(reference_lines[0].get_xdata()) == [105, 105]
        captions = " ".join(item.get_text() for item in figure.texts)
        assert ("80 Mbps bandwidth target lies above the displayed range" in captions) is not target_visible
        assert ("100 Mbps capacity bound lies above the displayed throughput range" in captions) is not target_visible
        assert ("Purple curves show the 100 Mbps capacity limit" in captions) is target_visible
    finally:
        original_close(figure)


def test_configuration_table_exposes_all_three_coordinates_of_overlapping_means(series, campaign):
    _, original, _ = campaign
    rows = deepcopy(original[:6])
    means = series.summarize(rows)
    series.decorate(rows, means)
    for mean in means:
        mean.update(tcp_syn_ping_p99_ms=123.456789, probe_interval_goodput_mbps=79.1234567,
                    probe_interval_extra_ip_pct=25.9876543)
    coordinates = [[mean[key] for key in series.METRICS] for mean in means]
    table = series.condition_table(means)
    assert all(header in table for header in (
        "Mean per-run SYN P99 (ms)", "Pooled probe-interval goodput (Mbps)", "Pooled extra IP bytes (%)"))
    assert all(table.count(f"<td>{value}</td>") == 2 for value in ("123.456789", "79.1234567", "25.9876543"))
    assert all(mean["series_configuration"] in table for mean in means)
    assert [[mean[key] for key in series.METRICS] for mean in means] == coordinates


@pytest.mark.parametrize("capacity, accepted", ((100, False), (300, True)))
def test_capacity_bound_rejects_80_mbps_with_100_percent_extra_on_100_mbps_link(series, capacity, accepted):
    row = dict(id="capacity-example", forward_mbps=capacity, probe_interval_payload_bytes=10_000_000,
               probe_interval_forward_ip_bytes=20_000_000, probe_interval_duration_s=1,
               probe_interval_goodput_mbps=80, probe_interval_extra_ip_pct=100)
    if accepted:
        series.validate_capacity(row)
        assert row["probe_interval_forward_ip_mbps"] == 160
    else:
        with pytest.raises(ValueError, match="Forward IP capacity exceeded"):
            series.validate_capacity(row)


def test_configuration_means_pool_bytes_and_time_instead_of_overhead_ratios(series, campaign):
    _, original, _ = campaign
    rows = deepcopy(original[:2])
    for row, payload, overhead in zip(rows, (12_500_000, 6_250_000), (0, 100)):
        row.update(probe_interval_payload_bytes=payload, probe_interval_forward_ip_bytes=12_500_000,
                   probe_interval_duration_s=1, probe_interval_goodput_mbps=payload * 8 / 1e6,
                   probe_interval_extra_ip_pct=overhead)
        series.validate_capacity(row)
    mean, = series.summarize(rows)
    assert mean[series.GOODPUT] == 75
    assert mean[series.OVERHEAD] == pytest.approx(100 / 3)
    assert mean["probe_interval_forward_ip_mbps"] == 100
    assert mean["capacity_identity_error_mbps"] < 1e-12
    assert mean["probe_interval_duration_s"] == 2


@pytest.mark.parametrize("key, value", (("forward_mbps", 300), ("reverse_mbps", 100), ("rtt_ms", 71),
                                        ("loss_rate", .2), ("loss_model", "burst"), ("mtu", 1400)))
def test_publication_enforces_fixed_physical_contract(series, campaign, key, value):
    _, original, selection = campaign
    rows = deepcopy(original)
    rows[0][key] = value
    with pytest.raises(ValueError, match="fixed physical conditions"):
        series.select_rows(rows, selection, 8)


@pytest.mark.parametrize("field", ("snapshots", "start_s", "end_s", "duration_s", "payload_bytes", "forward_ip_bytes",
                                   "reverse_ip_bytes", "forward_departed_ip_bytes", "reverse_departed_ip_bytes",
                                   "forward_mbps", "reverse_mbps", "extra_forward_ip_pct"))
def test_source_requires_all_same_window_measurement_fields(series, campaign, tmp_path, field):
    root, original, _ = campaign
    row = deepcopy(original[0])
    raw = json.loads((root / row["source"]).read_text())
    raw.pop(series.MEASUREMENT_PREFIX + field)
    path = tmp_path / "run.json"
    path.write_text(json.dumps(raw))
    row.update(source="run.json", source_sha256=sha256(path.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="same-window"):
        series.audit_bytes(tmp_path, [row])


def test_fractional_serialization_service_is_preserved_separately_from_departures(series, campaign, tmp_path):
    root, original, _ = campaign
    row = deepcopy(original[0])
    raw = json.loads((root / row["source"]).read_text())
    prefix = series.MEASUREMENT_PREFIX
    wire = raw[prefix + "forward_ip_bytes"] + .5
    raw[prefix + "snapshots"]["end"]["forward_serialized_ip_bytes"] = wire
    raw[prefix + "forward_ip_bytes"] = wire
    raw[prefix + "forward_mbps"] = wire * 8 / raw[prefix + "duration_s"] / 1e6
    raw[prefix + "extra_forward_ip_pct"] = 100 * (wire / raw[prefix + "payload_bytes"] - 1)
    path = tmp_path / "run.json"
    path.write_text(json.dumps(raw))
    row.update(source="run.json", source_sha256=sha256(path.read_bytes()).hexdigest())
    series.audit_bytes(tmp_path, [row])
    assert row["probe_interval_forward_ip_bytes"] == 180000.5
    assert row["probe_interval_forward_departed_ip_bytes"] == 180000


def test_capacity_floating_tolerance_does_not_clamp_observations(series):
    rate = 100 + 2.6e-7
    row = dict(id="floating-service", forward_mbps=100, probe_interval_payload_bytes=10_000_000,
               probe_interval_forward_ip_bytes=rate * 1e6 / 8, probe_interval_duration_s=1,
               probe_interval_goodput_mbps=80, probe_interval_extra_ip_pct=100 * (rate / 80 - 1))
    series.validate_capacity(row)
    assert row["probe_interval_forward_ip_mbps"] > 100
    assert row["probe_interval_forward_ip_mbps"] == pytest.approx(rate, abs=1e-12)


def test_summary_distinguishes_traffic_pooling_from_mean_per_run_p99(series, campaign):
    _, original, _ = campaign
    rows = deepcopy(original[:3])
    for row, latency in zip(rows, (80, 100, 180)):
        row[series.LATENCY] = latency
    mean, = series.summarize(rows)
    assert mean[series.LATENCY] == 120
    assert mean["latency_aggregation"] == "Arithmetic mean of per-run completed-probe P99 values"
    assert "sum(duration)" in mean["interval_aggregation"]
    assert "sum(IP service) / sum(payload)" in mean["interval_aggregation"]


def test_render_labels_fixed_link_weighted_summaries_and_separates_legacy_links(series, campaign, tmp_path, monkeypatch):
    root, original, selection = campaign
    rows = deepcopy(original)
    legacy = root / "all-experiments" / "report.html"
    legacy.parent.mkdir(exist_ok=True)
    legacy.write_text("Legacy fixture")
    diagnosis = root / "tcp-latency" / "tcp-syn-fixed100-baselines" / "quic-repeatability-diagnosis.json"
    diagnosis.parent.mkdir(exist_ok=True)
    diagnosis.write_text("{}")
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(json.dumps(selection))
    output = tmp_path / "report"

    def static_stub(directory, payload, *_):
        filename = f"payload-{payload}-pareto.png"
        (directory / filename).write_bytes(b"fixture-image")
        return filename

    monkeypatch.setattr(series.report, "load", lambda *_: (rows, [], [], []))
    monkeypatch.setattr(series, "static_figure", static_stub)
    monkeypatch.setattr(series, "interactive", lambda *_args, **_kwargs: "<div>Fixture 3D chart</div>")
    receipt = series.render(root, selection_path, output)
    html = (output / "report.html").read_text()
    assert "<h1>Fixed 100/10 Mbps" in html
    assert "8 sum(P) / sum(T) / 1e6 Mbps, time-weighted" in html
    assert "100 (sum(W) / sum(P) − 1)%, payload-byte-weighted" in html
    assert "Arithmetic mean of the three per-run P99 values" in html
    assert '<details><summary>Legacy records outside this fixed-link comparison</summary>' in html
    assert html.index("Legacy full experiment archive") > html.index("1448 B payload")
    assert receipt["record_kind"] == "fixed100_same_window_three_objective_payload_pareto_series"
    assert receipt["coordinate_keys"]["goodput"] == series.GOODPUT
    assert "QUIC reproducibility limitation" in html
    assert "Repeatability diagnosis" in html
    assert receipt["reproducibility"]["sha256"] == sha256(diagnosis.read_bytes()).hexdigest()


@pytest.mark.parametrize("profile, expected", (
    ({"kind": "tcp"}, "TCP"),
    ({"kind": "quic"}, "QUIC"),
    ({"recovery": "arq"}, "ARQ"),
    ({"recovery": "block", "compact": {"generation_sources": 5}}, "FEC 5+1"),
    ({"recovery": "rlnc", "compact": {"repair_ratio": .19}}, "RLNC 19%"),
    ({"recovery": "shared_record_rlnc", "compact": {"short_source_copies": 1}}, "Shared RLNC"),
    ({"recovery": "shared_record_rlnc", "compact": {"short_source_copies": 4}}, "Shared RLNC + Short×4"),
    ({"recovery": "shared_record_rlnc", "compact": {"short_source_copies": 4, "tail_repair_delay_ms": 15}}, "Shared RLNC + Short×4 + Tail15"),
))
def test_strategy_names_are_short_and_method_specific(series, campaign, profile, expected):
    _, original, _ = campaign
    row = deepcopy(original[0])
    profile.update(name="Internal execution profile", flow_count=16, payload_rate_mbps=20)
    row["original_profile"] = json.dumps(profile)
    name, overview = series.strategy_labels(row)
    assert name == expected
    assert "16 flows" in overview or "16 connections" in overview
    assert "offered 20 Mbps" in overview
    assert "Internal execution profile" not in name + overview


def test_shared_strategy_overview_distinguishes_generation_and_repair_window(series, campaign):
    _, original, _ = campaign
    row = deepcopy(original[0])
    row["original_profile"] = json.dumps(dict(name="internal", flow_count=128, recovery="shared_record_rlnc",
        compact=dict(block_sources=8192, repair_window_sources=128, repair_ratio=.221,
                     short_source_max_bytes=128, short_source_copies=4, tail_repair_delay_ms=15)))
    _, overview = series.strategy_labels(row)
    assert "8192-source generation / 128-source repair window" in overview
    assert "22.1% repair" in overview
    assert "≤128 B ×4" in overview
    assert "15 ms tail repair" in overview


def test_interactive_names_replace_opaque_configuration_callouts(series, campaign):
    _, original, _ = campaign
    rows = deepcopy(original[:3])
    means = series.summarize(rows)
    series.decorate(rows, means)
    html = series.interactive(64, rows, means, series.frontier(means), include_plotly=False)
    assert '"mode":"markers+text"' not in html
    assert means[0]["strategy_name"] in html
    assert means[0]["series_configuration"] not in html.split("</ul>")[0]
    assert f'"text":["{means[0]["series_configuration"]}"]' not in html


def test_block_overview_uses_idle_flush_configuration(series, campaign):
    _, original, _ = campaign
    row = deepcopy(original[0])
    row["original_profile"] = json.dumps(dict(name="internal", recovery="block", flow_count=16,
        compact=dict(generation_sources=5, idle_flush_ms=7.5, flush_ms=99)))
    name, overview = series.strategy_labels(row)
    assert name == "FEC 5+1"
    assert "7.5 ms idle flush" in overview
    assert "99 ms" not in overview


@pytest.fixture(scope="module")
def mux_campaign(series, tmp_path_factory):
    root = tmp_path_factory.mktemp("unified-mux-publication")

    def mutate(index, task, raw):
        task.update(payload_bytes=series.PAYLOADS[index // 3], seed=index % 3 + 100, replication=index % 3 + 1)
        task["profile"].update(name="Unified mux fixture", flow_count=16, mux=dict(channels=16),
                               recovery="shared_record_rlnc", ack_aggregation=False, ack_copies=1)
        task["profile"]["tcp_syn_probe"]["reverse_copies"] = 1
        raw.update(task, profile=json.dumps(task["profile"]), strategy=task["profile"]["name"],
            tcp_syn_probe_config=deepcopy(task["profile"]["tcp_syn_probe"]),
            transport="unified_duplex_mux_inner_tcp", flow_count=16, window_policy="fixed_total",
            total_window_bytes=task["profile"]["window_bytes"] // task["payload_bytes"] * task["payload_bytes"],
            mux_channel_count=16, mux_mapping="crc32", mux_classifier=series.CRC32_CLASSIFIER, mux_arbiter="FIFO round robin",
            tcp_syn_probe_transport="unified duplex mux and shared coded transports",
            tcp_syn_probe_channel_policy="same frame classifier and channel pool as bulk TCP",
            tcp_syn_probe_channels_used=[0], tcp_syn_probe_reverse_submitted_frames=1,
            tcp_syn_probe_forward_frames=3, tcp_retransmissions=2, ack_transmitted=50,
            mux_both_directions_confirmed=True, mux_endpoint_records_pending=0)
        for direction, count in (("forward", 105), ("reverse", 51)):
            raw["mux_" + direction] = dict(channel_ids=list(range(16)), submitted_channel_ids=list(range(16)),
                channel_count=16, submitted_frames=count, admitted_frames=count, delivered_frames=count,
                queued_frames=0, queued_bytes=0, registered_endpoints=17)
        add_matching_measurement(task, raw)

    syn_study(root, "unified", count=18, mutate=mutate)
    rows, _, _, _ = series.report.load(root, ["unified"])
    series.audit_bytes(root, rows)
    selection = dict(publication_requirements=dict(unified_mux_required=True, max_l2_channels=16),
        studies=[dict(study="unified", run_ids=[row["run_id"] for row in rows])])
    return root, rows, selection


def test_optional_unified_publication_keeps_historical_default_and_rejects_private_probe_rows(
        series, campaign, mux_campaign):
    _, historical, historical_selection = campaign
    _, receipt = series.select_rows(deepcopy(historical), historical_selection, 8)
    assert receipt["unified_mux_required"] is False
    assert receipt["unified_mux_validated_rows"] == 0
    selection = deepcopy(historical_selection)
    selection["publication_requirements"] = dict(unified_mux_required=True, max_l2_channels=16)
    with pytest.raises(ValueError, match="unified mux channel configuration"):
        series.select_rows(deepcopy(historical), selection, 8)
    _, original, selection = mux_campaign
    selected, receipt = series.select_rows(deepcopy(original), selection, 1)
    assert receipt["unified_mux_required"] is True
    assert receipt["max_l2_channels"] == 16
    assert receipt["unified_mux_validated_rows"] == len(selected) == 18
    assert all(row["unified_mux_qualified"] for row in selected)


@pytest.mark.parametrize("requirements", (
    {"unified_mux_required": "true", "max_l2_channels": 16},
    {"unified_mux_required": True},
    {"max_l2_channels": 16},
    {"unified_mux_required": True, "max_l2_channels": True},
    {"unified_mux_required": True, "max_l2_channels": 0},
    {"unified_mux_required": True, "max_l2_channels": 17.0},
))
def test_unified_publication_requirements_are_explicit(series, mux_campaign, requirements):
    _, rows, original = mux_campaign
    selection = deepcopy(original)
    selection["publication_requirements"] = requirements
    with pytest.raises(ValueError, match="unified_mux_required|Unified mux publication"):
        series.select_rows(deepcopy(rows), selection, 1)


@pytest.mark.parametrize("field,value", (
    ("mux_channel_count", 17), ("mux_channel_count", 8), ("mux_channel_count", True),
    ("flow_count", 128), ("flow_count", 15), ("flow_count", True),
    ("total_window_bytes", 4194304 * 16), ("window_policy", "fixed_per_flow"),
    ("transport", "shared_record_inner_tcp"),
))
def test_unified_gate_requires_actual_channel_flow_and_window_receipts(series, mux_campaign, field, value):
    _, original, selection = mux_campaign
    rows = deepcopy(original)
    rows[0][field] = value
    with pytest.raises(ValueError, match="mux|TCP window"):
        series.select_rows(rows, selection, 1)


@pytest.mark.parametrize("direction", ("forward", "reverse"))
@pytest.mark.parametrize("field,value", (
    ("channel_ids", [0, 16]), ("channel_ids", [0, 0]), ("channel_ids", [False]),
    ("submitted_channel_ids", [16]), ("submitted_channel_ids", []),
    ("channel_count", 15), ("channel_count", True), ("queued_frames", 1),
))
def test_unified_gate_validates_both_actual_directional_inventories(series, mux_campaign, direction, field, value):
    _, original, selection = mux_campaign
    rows = deepcopy(original)
    rows[0]["mux_" + direction][field] = value
    with pytest.raises(ValueError, match="mux"):
        series.select_rows(rows, selection, 1)


@pytest.mark.parametrize("key,value", (("ack_copies", 4), ("ack_copies", True), ("ack_aggregation", True)))
def test_unified_gate_rejects_separate_ack_protection(series, mux_campaign, key, value):
    _, original, selection = mux_campaign
    rows = deepcopy(original)
    profile = json.loads(rows[0]["original_profile"])
    profile[key] = value
    rows[0]["original_profile"] = json.dumps(profile)
    with pytest.raises(ValueError, match="common copy protection"):
        series.select_rows(rows, selection, 1)


@pytest.mark.parametrize("location", ("raw_config", "profile"))
def test_unified_gate_rejects_separate_probe_copies(series, mux_campaign, location):
    _, original, selection = mux_campaign
    rows = deepcopy(original)
    if location == "raw_config":
        probe = json.loads(rows[0]["tcp_syn_probe_config"])
        probe["reverse_copies"] = 4
        rows[0]["tcp_syn_probe_config"] = json.dumps(probe)
    else:
        profile = json.loads(rows[0]["original_profile"])
        profile["tcp_syn_probe"]["reverse_copies"] = 4
        rows[0]["original_profile"] = json.dumps(profile)
    with pytest.raises(ValueError, match="common copy protection"):
        series.select_rows(rows, selection, 1)


@pytest.mark.parametrize("field", ("offered_frames", "tcp_retransmissions", "tcp_syn_probe_forward_frames",
                                  "ack_transmitted", "tcp_syn_probe_reverse_submitted_frames"))
def test_unified_gate_rejects_bulk_or_probe_frames_bypassing_mux_counts(series, mux_campaign, field):
    _, original, selection = mux_campaign
    rows = deepcopy(original)
    rows[0][field] += 1
    with pytest.raises(ValueError, match="admission counters"):
        series.select_rows(rows, selection, 1)


def test_unified_probe_channels_must_belong_to_shared_forward_inventory(series, mux_campaign):
    _, original, selection = mux_campaign
    rows = deepcopy(original)
    inventory = rows[0]["mux_forward"]
    inventory.update(channel_ids=[1], submitted_channel_ids=[1], channel_count=1)
    with pytest.raises(ValueError, match="outside the shared forward mux inventory"):
        series.select_rows(rows, selection, 1)


@pytest.mark.parametrize("channels", (4, 8, 16))
def test_unified_short_names_and_configuration_show_actual_shared_pool(series, mux_campaign, channels):
    _, original, _ = mux_campaign
    row = deepcopy(original[0])
    profile = json.loads(row["original_profile"])
    profile["mux"]["channels"] = channels
    profile["compact"].update(repair_ratio=.221, short_source_max_bytes=128, short_source_copies=4,
                               tail_repair_delay_ms=15)
    row["original_profile"] = json.dumps(profile)
    name, overview = series.strategy_labels(row)
    expected = f"Hash{channels}" + (" TCP16" if channels != 16 else "") + " r22.1×4 Tail15"
    assert name == expected
    assert "16 bulk flows" in overview
    assert f"{row['total_window_bytes']:,} B total TCP window" in overview
    assert f"same {channels}-channel pool for bulk and probes in both directions" in overview
    assert "all sources ≤128 B ×4 in both directions" in overview
    assert "SYN-ACK ×" not in overview


def test_unified_names_distinguish_bulk_flow_count_on_same_channel_pool(series, mux_campaign):
    _, original, _ = mux_campaign
    row = deepcopy(original[0])
    default, _ = series.strategy_labels(row)
    profile = json.loads(row["original_profile"])
    profile["flow_count"] = 8
    row["original_profile"] = json.dumps(profile)
    changed, overview = series.strategy_labels(row)
    assert default != changed
    assert "Hash16 TCP8" in changed and "8 bulk flows" in overview


@pytest.mark.parametrize("threshold", (66, 128, 256))
@pytest.mark.parametrize("copies", (1, 4))
def test_independent_full_frame_names_are_distinct_from_source_copy_policy(series, mux_campaign, threshold, copies):
    _, original, _ = mux_campaign
    row = deepcopy(original[0])
    profile = json.loads(row["original_profile"])
    profile["compact"].update(independent_short_frame_bytes=threshold, short_source_max_bytes=128,
                               short_source_copies=copies)
    row["original_profile"] = json.dumps(profile)
    name, overview = series.strategy_labels(row)
    assert name.startswith("IndHash16 ")
    assert name.endswith(f" + Full{threshold}") if threshold != 128 else 'Full128' not in name
    assert ("×4" in name) is (copies == 4)
    assert f"independent full Ethernet frames ≤{threshold} B" in overview
    assert "protected source extent = frame length + 6 B" in overview
    assert ("all sources ≤128 B ×4" in overview) is (copies == 4)
    assert "TCP ACK every 2 segments, 10 ms ACK delay" in overview


def test_zero_independent_full_frame_option_preserves_default_labels(series, mux_campaign):
    _, original, _ = mux_campaign
    row = deepcopy(original[0])
    expected = series.strategy_labels(row)
    profile = json.loads(row["original_profile"])
    profile["compact"]["independent_short_frame_bytes"] = 0
    row["original_profile"] = json.dumps(profile)
    assert series.strategy_labels(row) == expected
    assert "Full" not in expected[0]
    assert "independent full Ethernet" not in expected[1]


@pytest.mark.parametrize("hold", [0, .25, 1])
def test_small_packet_labels_describe_selective_copies_and_actual_packing(series, mux_campaign, hold):
    _, source, _ = mux_campaign
    row = deepcopy(source[0])
    profile = json.loads(row['original_profile'])
    profile.update(payload_rate_mbps=64, ack_every=64, ack_coalesce_ms=2)
    profile['compact'].update(short_source_copy_scope='context_and_independent',
        pack_sources_max_delay_ms=hold, short_source_copies=3, short_source_max_bytes=128)
    row['original_profile'] = json.dumps(profile)
    name, overview = series.strategy_labels(row)
    assert name == ('Select' if hold == 0 else f'Pack{hold:g}') + ' 64M A64 C2'
    assert 'context and independent full-frame units ≤128 B ×3' in overview
    assert '2 ms advancing-ACK coalescing' in overview
    assert ('packed before coding' in overview) is bool(hold)


@pytest.mark.parametrize("kind", ['tcp', 'quic_inner', 'kcp_inner'])
def test_shared_baselines_require_explicit_admission_evidence(series, mux_campaign, kind):
    row = baseline_publication_row(mux_campaign[1][0], kind)
    series.validate_transport_baseline(row, 16)
    if kind == 'tcp':
        row['tcp_syn_probe_transport'] = 'auxiliary path'
    else:
        row['tunnel_probe_extra_connections'] = 1
    with pytest.raises(ValueError):
        series.validate_transport_baseline(row, 16)


@pytest.mark.parametrize("every,delay", ((1, 0), (2, 5), (4, 7.5)))
def test_full_frame_overview_uses_actual_tcp_ack_generation_parameters(series, mux_campaign, every, delay):
    _, original, _ = mux_campaign
    row = deepcopy(original[0])
    profile = json.loads(row["original_profile"])
    profile.update(ack_every=every, ack_delay_ms=delay)
    profile["compact"]["independent_short_frame_bytes"] = 128
    row["original_profile"] = json.dumps(profile)
    _, overview = series.strategy_labels(row)
    assert f"TCP ACK every {every} segments, {delay:g} ms ACK delay" in overview


def test_independent_full_frame_suffix_also_describes_nonmux_shared_transport(series, campaign):
    _, original, _ = campaign
    row = deepcopy(original[0])
    profile = json.loads(row["original_profile"])
    profile["recovery"] = "shared_record_rlnc"
    profile["compact"].update(independent_short_frame_bytes=128, short_source_copies=4, short_source_max_bytes=128)
    row["original_profile"] = json.dumps(profile)
    name, overview = series.strategy_labels(row)
    assert name == "Shared RLNC + Short×4 + Full128"
    assert "independent full Ethernet frames ≤128 B" in overview
    assert "TCP ACK every 2 segments, 10 ms ACK delay" in overview


def test_unified_mapping_names_and_recorded_classifier_must_agree(series, mux_campaign):
    _, original, _ = mux_campaign
    row = deepcopy(original[0])
    profile = json.loads(row["original_profile"])
    profile["mux"]["mapping"] = "connection_round_robin"
    row["original_profile"] = json.dumps(profile)
    with pytest.raises(ValueError, match="mapping differs"):
        series.validate_unified_mux(row, 16)
    row["mux_mapping"] = "connection_round_robin"
    row["mux_classifier"] = "Canonical endpoints assigned round robin to existing channels"
    series.validate_unified_mux(row, 16)
    name, overview = series.strategy_labels(row)
    assert "RR16" in name
    assert "round-robin connection assignment" in overview
    assert series.condition(row)["mux_mapping"] == "connection_round_robin"


def test_frozen_hash_mapping_requires_exact_recorded_legacy_classifier(series, mux_campaign):
    _, original, _ = mux_campaign
    row = deepcopy(original[0])
    row.pop("mux_mapping")
    series.validate_unified_mux(row, 16)
    row["mux_classifier"] = "unrecorded"
    with pytest.raises(ValueError, match="mapping differs"):
        series.validate_unified_mux(row, 16)


def test_unified_goal_uses_same_window_goodput_and_preserves_failure_exclusion(series, mux_campaign):
    _, original, selection = mux_campaign
    rows = deepcopy(original)
    rows[0]["joint_target_met"] = True
    rows[1].update(eligible=False, exclusion_reason="probe failures or unresolved probes", tcp_syn_ping_timeouts=1)
    selected, _ = series.select_rows(rows, selection, 1)
    assert selected[0][series.GOODPUT] < 80
    assert not selected[0]["joint_target_met"]
    assert not selected[1]["eligible"] and not selected[1]["joint_target_met"]
    means = series.summarize(selected)
    assert all(mean["unified_mux_qualified"] for mean in means)
    affected = next(mean for mean in means if rows[1]["id"] in json.loads(mean["raw_ids"]))
    assert affected not in series.frontier(means)


@pytest.mark.parametrize("metric", ("goodput_mbps", "tcp_syn_ping_background_goodput_mbps", "probe_interval_goodput_mbps"))
def test_unified_goal_keeps_full_run_and_stable_window_throughput_conjunctive(series, mux_campaign, metric):
    _, original, selection = mux_campaign
    rows = deepcopy(original)
    first = rows[0]
    first.update(goodput_mbps=80, tcp_syn_ping_background_goodput_mbps=80,
                 probe_interval_goodput_mbps=80, joint_target_met=True)
    first[metric] = 79.99
    first['probe_interval_payload_bytes'] = first[series.GOODPUT] * first['probe_interval_duration_s'] * 1e6 / 8
    first['probe_interval_forward_ip_bytes'] = first['probe_interval_payload_bytes'] * 1.2
    first[series.OVERHEAD] = 20
    selected, _ = series.select_rows(rows, selection, 1)
    assert not selected[0]['joint_target_met']


def test_mux_raw_metadata_survives_audit_means_and_exports(series, mux_campaign, tmp_path, monkeypatch):
    root, _, selection = mux_campaign
    rows, _, _, _ = series.report.load(root, ["unified"])
    series.audit_bytes(root, rows)
    raw = json.loads((root / rows[0]["source"]).read_text())
    for key in ("mux_forward", "mux_reverse", "mux_classifier", "mux_channel_count", "flow_count", "total_window_bytes"):
        assert rows[0][key] == raw[key]
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(json.dumps(selection))
    output = tmp_path / "report"

    def static_stub(directory, payload, *_):
        filename = f"payload-{payload}-pareto.png"
        (directory / filename).write_bytes(b"fixture-image")
        return filename

    monkeypatch.setattr(series, "static_figure", static_stub)
    monkeypatch.setattr(series, "interactive", lambda *_args, **_kwargs: "<div>Fixture 3D chart</div>")
    receipt = series.render(root, selection_path, output, minimum_configurations=1)
    assert receipt["publication_gate"]["unified_mux_validated_rows"] == 18
    html = (output / "report.html").read_text()
    assert "Unified duplex mux is required" in html
    assert "same 16-channel pool for bulk and probes" in html
    assert "Historical private-probe-channel observations are outside this goal qualification" in html
    assert "complete unfragmented Ethernet/IPv4/TCP frames" in html
    assert "connection-affinity records have no finite resource bound" in html
    assert "simultaneous opposite-direction connection initiation with conflicting affinity" in html
    assert "modeled TCP callback ledger" in html
    assert "sender ledger" in html
    assert "Comparisons reflect complete configurations, including ACK frequency/delay" in html
    with (output / "current-series-coverage.csv").open() as handle:
        coverage = list(csv.DictReader(handle))
    assert len(coverage) == 18
    assert all(row["mux_channel_count"] == "16" and row["flow_count"] == "16" for row in coverage)
    assert all(json.loads(row["unified_mux_evidence"])["mux_reverse"]["channel_count"] == 16 for row in coverage)
    with (output / "current-series-means.csv").open() as handle:
        means = list(csv.DictReader(handle))
    assert len(means) == 6
    evidence = json.loads(means[0]["mux_run_evidence"])
    assert len(evidence) == 3
    assert all(item["mux_forward"]["channel_ids"] == list(range(16)) for item in evidence)
    assert {item["raw_id"] for mean in means for item in json.loads(mean["mux_run_evidence"])} == {row["id"] for row in coverage}


@pytest.fixture(scope="module")
def supplementary_campaign(series, mux_campaign, tmp_path_factory):
    source_root, source_rows, source_selection = mux_campaign
    root = tmp_path_factory.mktemp("supplementary-publication")
    shutil.copytree(source_root, root, dirs_exist_ok=True)
    samples = [json.loads((source_root / row["source"]).read_text()) for row in source_rows[-3:]]

    def mutate(index, task, raw):
        sample = deepcopy(samples[index])
        profile = json.loads(sample["profile"])
        profile["name"] = "Supplementary incomplete seed cohort"
        task.update({key: sample[key] for key in task if key != "profile"})
        task.update(run_id=index + 1, profile=profile)
        raw.clear()
        raw.update(sample)
        raw.update(task, profile=json.dumps(profile), strategy=profile["name"])
        if index == 2:
            raw.update(tcp_syn_probe_steady_state_reached=False, tcp_syn_probe_start_s=None,
                       tcp_syn_ping_p99_ms=None, tcp_syn_ping_offered=0, tcp_syn_ping_completed=0,
                       tcp_syn_probe_channels_used=[])
            for key in list(raw):
                if key.startswith(series.MEASUREMENT_PREFIX):
                    del raw[key]

    syn_study(root, "supplementary", count=3, mutate=mutate)
    rows, _, _, _ = series.report.load(root, ["unified", "supplementary"])
    plotted = [row for row in rows if row["tcp_syn_probe_steady_state_reached"]]
    series.audit_bytes(root, plotted)
    selection = deepcopy(source_selection)
    selection.update(supplementary_studies=[dict(study="supplementary", run_ids=[1, 2])],
                     coverage_only_studies=[dict(study="supplementary", run_ids=[3])],
                     load_controlled_payloads=[64, 256, 512, 1024, 1228])
    return root, rows, selection


def test_supplementary_measured_runs_remain_visible_without_partial_means(series, supplementary_campaign):
    _, original, selection = supplementary_campaign
    selected, receipt = series.select_rows(deepcopy(original), selection, 1)
    assert len(selected) == 20
    assert receipt["primary_rows"] == 18 and receipt["supplementary_rows"] == 2
    assert receipt["coverage_only_rows"] == 1
    assert receipt["all_primary_configuration_cohorts_complete"]
    assert not receipt["all_selected_configuration_cohorts_complete"]
    assert receipt["configuration_counts"] == {str(payload): 1 for payload in series.PAYLOADS}
    assert len(receipt["partial_configuration_receipts"]) == 1
    supplemental = [row for row in selected if row["publication_role"] == "supplementary"]
    assert all(not row["configuration_complete"] and not row["frontier_eligible"] for row in supplemental)
    means = series.summarize(selected)
    assert len(means) == 6
    assert not {row["id"] for row in supplemental} & {identifier for mean in means for identifier in json.loads(mean["raw_ids"])}
    payload = [row for row in selected if row["payload_bytes"] == 1448]
    averages = [mean for mean in means if mean["payload_bytes"] == 1448]
    series.decorate(payload, averages)
    html = series.interactive(1448, payload, averages, series.frontier(averages), include_plotly=False)
    assert all(row["id"] in html.replace('\\u002f', '/') for row in payload)
    assert "configuration lacks a complete measured three-seed cohort" in html


def test_partial_supplementary_groups_cannot_satisfy_publication_minimum(series, supplementary_campaign):
    _, rows, selection = supplementary_campaign
    with pytest.raises(ValueError, match="requires 2 complete configurations, observed 1"):
        series.select_rows(deepcopy(rows), selection, 2)


def test_complete_supplementary_groups_receive_only_full_three_seed_means(series, supplementary_campaign):
    _, original, source_selection = supplementary_campaign
    rows, selection = deepcopy(original), deepcopy(source_selection)
    last = next(row for row in rows if row['study'].endswith('/supplementary') and row['run_id'] == 3)
    first = next(row for row in rows if row['study'].endswith('/supplementary') and row['run_id'] == 1)
    identity = {key: last[key] for key in ('id', 'source', 'source_sha256', 'run_id', 'seed', 'replication')}
    last.update(first, **identity)
    selection['supplementary_studies'][0]['run_ids'].append(3)
    selection['coverage_only_studies'] = []
    selected, receipt = series.select_rows(rows, selection, 1)
    assert receipt['configuration_counts']['1448'] == 2
    assert receipt['all_selected_configuration_cohorts_complete']
    assert len(series.summarize(selected)) == 7


@pytest.mark.parametrize('section', ('supplementary_studies', 'coverage_only_studies'))
def test_selection_roles_cannot_duplicate_a_primary_run(series, supplementary_campaign, section):
    _, rows, original = supplementary_campaign
    selection = deepcopy(original)
    selection[section].append(dict(study='unified', run_ids=[1]))
    with pytest.raises(ValueError, match='unique explicit'):
        series.select_rows(deepcopy(rows), selection, 1)


def test_supplementary_rows_still_require_measured_coordinates_and_mux_contract(series, supplementary_campaign):
    _, original, selection = supplementary_campaign
    for field, value, message in ((series.LATENCY, None, 'finite measured'),
                                  ('forward_mbps', 300, 'fixed physical'),
                                  ('mux_channel_count', 17, 'mux channel')):
        rows = deepcopy(original)
        supplemental = next(row for row in rows if row['study'].endswith('/supplementary') and row['run_id'] == 1)
        supplemental[field] = value
        with pytest.raises(ValueError, match=message):
            series.select_rows(rows, selection, 1)


def test_coverage_only_cannot_hide_a_finite_measured_run(series, supplementary_campaign):
    _, rows, original = supplementary_campaign
    selection = deepcopy(original)
    selection['supplementary_studies'][0]['run_ids'].remove(2)
    selection['coverage_only_studies'][0]['run_ids'].append(2)
    with pytest.raises(ValueError, match='cannot hide a measured run'):
        series.select_rows(deepcopy(rows), selection, 1)


def test_render_exports_supplementary_and_coverage_rows_without_synthetic_coordinates(
        series, supplementary_campaign, tmp_path, monkeypatch):
    root, original, selection = supplementary_campaign
    selection_path = tmp_path / 'selection.json'
    selection_path.write_text(json.dumps(selection))
    output = tmp_path / 'report'
    observed = {}

    def static_stub(directory, payload, rows, means, boundary):
        observed[payload] = (deepcopy(rows), deepcopy(means))
        filename = f'payload-{payload}-pareto.png'
        (directory / filename).write_bytes(b'fixture-image')
        return filename

    monkeypatch.setattr(series, 'static_figure', static_stub)
    monkeypatch.setattr(series, 'interactive', lambda *_args, **_kwargs: '<div>Fixture 3D chart</div>')
    receipt = series.render(root, selection_path, output, minimum_configurations=1)
    assert receipt['raw_runs'] == 20 and receipt['outside_plot_rows'] == 1
    assert len(receipt['raw_inputs']) == 21
    assert len(observed[1448][0]) == 5 and len(observed[1448][1]) == 1
    assert all(row['load_controlled_observation'] for row in observed[64][0])
    assert not any(row['load_controlled_observation'] for row in observed[1448][0])
    html = (output / 'report.html').read_text()
    assert 'load-controlled observations at the listed offered rates' in html
    assert 'Load-controlled small-payload observations.' in html
    assert 'These configured offered loads bound the observed throughput.' in html
    assert 'Supplementary measured runs from incomplete seed cohorts appear individually' in html
    assert 'Experiments outside the plotted coordinates' in html
    assert '<div class="scroll"><table>' in html
    assert '.table-scroll,.scroll{overflow-x:auto;max-width:100%;min-width:0}' in html
    assert 'stability gate not reached' in html
    with (output / 'outside-plot-coverage.csv').open() as handle:
        outside = list(csv.DictReader(handle))
    assert len(outside) == 1 and outside[0][series.LATENCY] == ''
    assert outside[0]['source_sha256']
    plotted_ids = {row['id'] for rows, _ in observed.values() for row in rows}
    assert outside[0]['id'] not in plotted_ids
    assert plotted_ids == {row['id'] for row in original if row['tcp_syn_probe_steady_state_reached']}


def test_many_mux_variants_reserve_legend_space_and_compact_shared_configuration(
        series, mux_campaign, tmp_path, monkeypatch):
    _, source, _ = mux_campaign
    rows = []
    for index in range(19):
        row = deepcopy(source[-3 + index % 3])
        profile = json.loads(row['original_profile'])
        profile.update(name=f'Variant {index}', ack_every=2 + index % 2)
        profile['mux']['mapping'] = 'crc32' if index < 6 else 'connection_round_robin'
        profile['compact'].update(repair_ratio=.19 + index / 1000, short_source_max_bytes=128,
                                  short_source_copies=3 + index % 2,
                                  independent_short_frame_bytes=128 if index >= 12 else 0)
        row.update(id=f'fixture-{index}', original_profile=json.dumps(profile), configuration_complete=False)
        rows.append(row)
    series.decorate(rows, [])
    common, variants = series.static_overview(rows)
    assert common == ''
    assert all('total TCP window' not in line for line in variants)
    assert len(variants) == 3
    assert all(len(line) < 100 for line in variants)
    assert {row['color_label'] for row in rows} == {
        'Hash ordered mux', 'Round-robin ordered mux', 'Independent-short mux'}
    assert len({row['color'] for row in rows}) == 3
    original_close = series.plt.close
    monkeypatch.setattr(series.plt, 'close', lambda *_: None)
    monkeypatch.setattr('matplotlib.figure.Figure.savefig', lambda *_args, **_kwargs: None)
    series.static_figure(tmp_path, 1448, rows, [], [])
    figure = series.plt.gcf()
    try:
        figure.canvas.draw()
        renderer = figure.canvas.get_renderer()
        legend = figure.legends[0]
        legend_bounds = legend.get_window_extent(renderer)
        assert {item.get_text() for item in legend.get_texts()} == {'Hash', 'RR', 'Ind'}
        assert legend_bounds.x0 >= 0 and legend_bounds.x1 <= figure.bbox.x1
        for axis in figure.axes:
            assert legend_bounds.y1 + 8 < axis.get_tightbbox(renderer).y0
        overview_texts = [item for item in figure.texts if 'Hash —' in item.get_text() or 'Ind —' in item.get_text()]
        assert overview_texts
        assert all(item.get_window_extent(renderer).y1 < legend_bounds.y0 for item in overview_texts)
        assert all(item.get_window_extent(renderer).x1 <= figure.bbox.x1 for item in overview_texts)
    finally:
        original_close(figure)
    figures = []
    monkeypatch.setattr(series.go.Figure, 'to_html', lambda figure, **kwargs: figures.append(figure) or '')
    series.interactive(1448, rows, [], [], include_plotly=False)
    assert {trace.name for trace in figures[0].data} == {'Hash', 'RR', 'Ind'}
    hover_text = ' '.join(text for trace in figures[0].data for text in trace.text)
    assert all(row['strategy_name'] in hover_text for row in rows)


def baseline_publication_row(source, kind):
    row = deepcopy(source)
    profile = json.loads(row['original_profile'])
    profile.pop('mux')
    profile['kind'] = kind
    row['original_profile'] = json.dumps(profile)
    if kind == 'tcp':
        row.update(transport='direct_tcp', tcp_syn_probe_transport='native IPv4 TCP')
        return row
    count = profile['flow_count']
    row.update(transport='inner_tcp_over_' + kind.removesuffix('_inner'), tunnel_protocol=kind,
        tunnel_connection_count=count, tunnel_shared_record_path=True, tunnel_inner_tcp=True,
        tunnel_probe_extra_connections=0, tunnel_probe_extra_streams=0,
        tunnel_tcp_total_window_bytes=row['total_window_bytes'], tunnel_all_confirmed=True,
        tunnel_mux={key: deepcopy(value) for key, value in row.items() if key.startswith('mux_')})
    row['tunnel_mux']['mux_mapping'] = 'connection_round_robin'
    for direction in ('forward', 'reverse'):
        metrics = row['tunnel_mux']['mux_' + direction]
        frame_bytes = 66 + (int(row['payload_bytes']) if direction == 'forward' else 0)
        metrics.update({stage + '_bytes': metrics[stage + '_frames'] * frame_bytes
                        for stage in ('submitted', 'admitted', 'delivered', 'queued')})
    records = []
    slots = profile['window_bytes'] // int(row['payload_bytes'])
    quic = kind == 'quic_inner'
    for index in range(count):
        byte_counts = []
        for direction in ('forward', 'reverse'):
            metrics = row['tunnel_mux']['mux_' + direction]
            total = metrics['admitted_bytes'] + (2 * metrics['admitted_frames'] if quic else 0)
            byte_counts.append(total // count + (index < total % count))
        if quic:
            record = dict(streams=[[0], [0]], confirmed=True,
                sender_window_bytes=(slots // count + (index < slots % count)) * (int(row['payload_bytes']) + 68),
                peak_outstanding_bytes=[0, 0], submitted_stream_bytes=byte_counts,
                received_stream_bytes=list(byte_counts), acknowledged_stream_bytes=list(byte_counts))
        else:
            record = dict(confirmed=True, sender_window_segments=128, peak_waiting_segments=[0, 0],
                submitted_frame_bytes=byte_counts, received_frame_bytes=list(byte_counts), retransmitted_segments=[0, 0])
        records.append(record)
    row['tunnel_protocol_records'] = records
    queue_model = 'physical FIFO plus shared ingress and admitted protocol bytes not yet first transmitted'
    row.update(tunnel_stability_queue_model=queue_model, tcp_syn_probe_stability_queue_model=queue_model)
    for record in records:
        record.update(pending_first_transmission_bytes=[0, 0], peak_pending_first_transmission_bytes=[0, 0])
        record['first_transmitted_stream_bytes' if quic else 'first_transmitted_frame_bytes'] = list(
            record['submitted_stream_bytes' if quic else 'submitted_frame_bytes'])
    return row


@pytest.mark.parametrize('kind', ['quic_inner', 'kcp_inner'])
@pytest.mark.parametrize('direction', ['forward', 'reverse'])
@pytest.mark.parametrize('mutation', ['duplicate_ids', 'duplicate_submitted_ids', 'channel_count',
    'missing_admitted_id', 'queued_frames', 'queued_bytes', 'negative_counter', 'fractional_counter',
    'missing_shared_frame', 'missing_shared_bytes', 'probe_channel'])
def test_shared_baseline_rejects_inconsistent_mux_receipts(series, mux_campaign, kind, direction, mutation):
    row = baseline_publication_row(mux_campaign[1][0], kind)
    metrics = row['tunnel_mux']['mux_' + direction]
    if mutation == 'duplicate_ids':
        metrics['channel_ids'] = [0] * 16
    elif mutation == 'duplicate_submitted_ids':
        metrics['submitted_channel_ids'] = [0] * 16
    elif mutation == 'channel_count':
        metrics['channel_count'] = 15
    elif mutation == 'missing_admitted_id':
        metrics['submitted_channel_ids'] = list(range(15))
    elif mutation in ('queued_frames', 'queued_bytes'):
        metrics[mutation] = 1
    elif mutation == 'negative_counter':
        metrics['delivered_frames'] = -1
    elif mutation == 'fractional_counter':
        metrics['submitted_bytes'] += .5
    elif mutation in ('missing_shared_frame', 'missing_shared_bytes'):
        unit = 'frames' if mutation == 'missing_shared_frame' else 'bytes'
        for stage in ('submitted', 'admitted', 'delivered'):
            metrics[stage + '_' + unit] -= 1
    else:
        row['tcp_syn_probe_channels_used'] = [16]
    with pytest.raises(ValueError, match='Baseline'):
        series.validate_transport_baseline(row, 16)


@pytest.mark.parametrize('kind', ['quic_inner', 'kcp_inner'])
@pytest.mark.parametrize('mutation', ['confirmation_false', 'confirmation_missing', 'transport_unconfirmed',
    'wrong_window', 'overflow_peak', 'negative_peak', 'nan_peak', 'missing_peak',
    'received_exceeds_submitted', 'confirmed_byte_gap', 'protocol_total_mismatch'])
def test_shared_baseline_rejects_invalid_protocol_receipts(series, mux_campaign, kind, mutation):
    row = baseline_publication_row(mux_campaign[1][0], kind)
    record = row['tunnel_protocol_records'][0]
    quic = kind == 'quic_inner'
    window = 'sender_window_bytes' if quic else 'sender_window_segments'
    peak = 'peak_outstanding_bytes' if quic else 'peak_waiting_segments'
    submitted = 'submitted_stream_bytes' if quic else 'submitted_frame_bytes'
    received = 'received_stream_bytes' if quic else 'received_frame_bytes'
    if mutation == 'confirmation_false':
        record['confirmed'] = False
    elif mutation == 'confirmation_missing':
        del record['confirmed']
    elif mutation == 'transport_unconfirmed':
        row['tunnel_all_confirmed'] = False
    elif mutation == 'wrong_window':
        record[window] += 1
    elif mutation == 'overflow_peak':
        record[peak][0] = record[window] + 1
    elif mutation == 'negative_peak':
        record[peak][0] = -1
    elif mutation == 'nan_peak':
        record[peak][0] = float('nan')
    elif mutation == 'missing_peak':
        del record[peak]
    elif mutation == 'received_exceeds_submitted':
        record[received][0] += 1
    elif mutation == 'confirmed_byte_gap':
        record[received][0] -= 1
    else:
        record[submitted][0] += 1
        record[received][0] += 1
        record['first_transmitted_stream_bytes' if quic else 'first_transmitted_frame_bytes'][0] += 1
        if quic:
            record['acknowledged_stream_bytes'][0] += 1
    with pytest.raises(ValueError, match='Baseline|Confirmed baseline|QUIC'):
        series.validate_transport_baseline(row, 16)


@pytest.mark.parametrize('kind', ['quic_inner', 'kcp_inner'])
def test_shared_baseline_retains_consistent_incomplete_confirmation(series, mux_campaign, kind):
    row = baseline_publication_row(mux_campaign[1][0], kind)
    row.update(fully_confirmed=False, tunnel_all_confirmed=False)
    row['tunnel_protocol_records'][0]['confirmed'] = False
    series.validate_transport_baseline(row, 16)


def test_quic_baseline_rejects_unconfirmed_stream_bytes_and_extra_stream(series, mux_campaign):
    original = baseline_publication_row(mux_campaign[1][0], 'quic_inner')
    for field, value in [('acknowledged_stream_bytes', [0, 0]), ('streams', [[0, 4], [0]])]:
        row = deepcopy(original)
        row['tunnel_protocol_records'][0][field] = value
        with pytest.raises(ValueError, match='QUIC'):
            series.validate_transport_baseline(row, 16)


@pytest.mark.parametrize('kind', ['quic_inner', 'kcp_inner'])
def test_shared_baseline_retains_explicit_zero_probe_inventory(series, mux_campaign, kind):
    row = baseline_publication_row(mux_campaign[1][0], kind)
    row.update(tcp_syn_ping_offered=0, tcp_syn_probe_channels_used=[])
    series.validate_transport_baseline(row, 16)
    row['tcp_syn_ping_offered'] = 1
    with pytest.raises(ValueError, match='probe channels'):
        series.validate_transport_baseline(row, 16)


@pytest.mark.parametrize('kind', ['quic_inner', 'kcp_inner'])
@pytest.mark.parametrize('legacy_field', ['pending_first_transmission_bytes', 'tunnel_stability_queue_model',
                                        'tcp_syn_probe_stability_queue_model'])
def test_legacy_queue_gate_remains_visible_but_cannot_qualify(series, mux_campaign, kind, legacy_field):
    row = baseline_publication_row(mux_campaign[1][0], kind)
    row.update(publication_role='supplementary', eligible=True, exclusion_reason='probe failure', status='ineligible')
    if legacy_field == 'pending_first_transmission_bytes':
        del row['tunnel_protocol_records'][0][legacy_field]
    else:
        row[legacy_field] = 'physical FIFO plus shared record ingress backlog'
    series.validate_transport_baseline(row, 16)
    assert row['baseline_internal_queue_observed'] is False
    assert row['eligible'] is row['frontier_eligible'] is row['joint_target_met'] is False
    assert row['exclusion_reason'].startswith('probe failure | ')
    assert 'legacy queue gate' in row['exclusion_reason']
    series.validate_transport_baseline(row, 16)
    assert row['exclusion_reason'].count('legacy queue gate') == 1
    row['publication_role'] = 'primary'
    with pytest.raises(ValueError, match='Primary baseline requires internal protocol queue'):
        series.validate_transport_baseline(row, 16)


@pytest.mark.parametrize('kind', ['quic_inner', 'kcp_inner'])
@pytest.mark.parametrize('mutation', ['negative', 'nan', 'missing_peak', 'inconsistent_first', 'confirmed_pending'])
def test_internal_queue_receipts_require_exact_consistent_byte_counters(series, mux_campaign, kind, mutation):
    row = baseline_publication_row(mux_campaign[1][0], kind)
    record = row['tunnel_protocol_records'][0]
    first = 'first_transmitted_stream_bytes' if kind == 'quic_inner' else 'first_transmitted_frame_bytes'
    if mutation == 'negative':
        record['pending_first_transmission_bytes'][0] = -1
    elif mutation == 'nan':
        record['peak_pending_first_transmission_bytes'][0] = float('nan')
    elif mutation == 'missing_peak':
        del record['peak_pending_first_transmission_bytes']
    elif mutation == 'inconsistent_first':
        record[first][0] -= 1
    else:
        record['pending_first_transmission_bytes'][0] = record['peak_pending_first_transmission_bytes'][0] = 1
        record[first][0] -= 1
    with pytest.raises(ValueError, match='Baseline internal protocol queue'):
        series.validate_transport_baseline(row, 16)


@pytest.mark.parametrize('kind', ['quic_inner', 'kcp_inner'])
def test_baseline_conditions_use_actual_shared_pool_evidence(series, mux_campaign, kind):
    row = baseline_publication_row(mux_campaign[1][0], kind)
    conditions = series.condition(row)
    assert conditions['mux_mapping'] == 'connection_round_robin'
    assert conditions['mux_channels'] == 16
    assert conditions['mux_forward'] == row['tunnel_mux']['mux_forward']
    assert conditions['mux_reverse'] == row['tunnel_mux']['mux_reverse']


def test_native_tcp_conditions_have_no_outer_mux(series, mux_campaign):
    row = baseline_publication_row(mux_campaign[1][0], 'tcp')
    conditions = series.condition(row)
    assert conditions['mux_mapping'] is None
    assert conditions['mux_channels'] is None


def test_interactive_failed_run_and_mean_use_crosses(series, campaign, monkeypatch):
    rows = deepcopy(campaign[1][:3])
    rows[0].update(eligible=False, exclusion_reason='probe failures')
    means = series.summarize(rows)
    series.decorate(rows, means)
    figures = []
    monkeypatch.setattr(series.go.Figure, 'to_html', lambda figure, **kwargs: figures.append(figure) or '')
    series.interactive(64, rows, means, [], include_plotly=False)
    assert len(figures[0].data) == 6
    for index in range(0, 6, 2):
        raw, mean = figures[0].data[index:index + 2]
        assert raw.type == mean.type == 'scatter'
        assert raw.meta['role'] == 'raw'
        assert raw.marker.symbol == ('x', 'circle', 'circle')
        assert mean.meta['role'] == 'mean'
        assert mean.marker.symbol == ('x',)


def test_combined_2d_view_preserves_payloads_loads_and_coordinates(series, mux_campaign, monkeypatch):
    rows = deepcopy(mux_campaign[1])
    means = series.summarize(rows)
    series.decorate(rows, means)
    boundaries = [mean for payload in series.PAYLOADS
                  for mean in series.frontier([row for row in means if row['payload_bytes'] == payload])]
    figures = []
    monkeypatch.setattr(series.go.Figure, 'to_html', lambda figure, **kwargs: figures.append(figure) or '')
    series.interactive(None, rows, means, boundaries, include_plotly=False)
    figure = figures[0]
    assert all(trace.type == 'scatter' for trace in figure.data)
    lookup = {row['id']: row for row in rows + means}
    for column, (x, y, _, _) in enumerate(series.PROJECTIONS, 1):
        raw_ids = []
        for trace in figure.data:
            if trace.meta['projection'] != column:
                continue
            for index, identity in enumerate(trace.customdata):
                row = lookup[identity]
                assert trace.x[index] == row[x] and trace.y[index] == row[y]
                assert trace.marker.symbol[index] == series.PAYLOAD_SYMBOLS[row['payload_bytes']]
                if trace.meta['role'] == 'raw':
                    raw_ids.append(identity)
        assert sorted(raw_ids) == sorted(row['id'] for row in rows)
