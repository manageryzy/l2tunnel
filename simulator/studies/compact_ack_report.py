"""Render verified compact ACK studies without dropping individual executions."""

import argparse
from collections import defaultdict
from hashlib import sha256
from html import escape
import json
from os.path import relpath
from pathlib import Path
import textwrap

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import plotly.graph_objects as go
from plotly.subplots import make_subplots

if __package__:
    from . import aligned_record_report as aligned
    from . import all_experiments as archive
else:
    import aligned_record_report as aligned
    import all_experiments as archive
from l2tunnel_sim import stats


PREFIX = "with_drain_tcp_all_segment_ack_rtt_cohort_"
PANELS = (
    ("tcp_all_segment_ack_p99_ms", "Original-segment ACK P99 through drain (ms)"),
    ("tcp_rtt_p99_ms", "Timestamp RTT P99 during traffic (ms)"),
    ("tcp_deadline_miss_pct", "Original-segment deadline misses, upper bound (%)"),
    ("reverse_measurement_mbps", "Reverse IP load during traffic (Mbps)"),
    ("packet_extra_pct", "Forward extra packets through drain (%)"),
    ("byte_extra_pct", "Forward extra IP bytes through drain (%)"),
)
RAW_FIELDS = (
    "steady_application_goodput_mbps", "forward_measurement_mbps", "reverse_measurement_mbps",
    "forward_wire_bytes", "reverse_wire_bytes", "forward_datagrams", "offered_frames",
    "tcp_delivered_frames", "tcp_acked_frames", "ack_batch_records_mean",
    "ack_batch_queue_delays_ms_p99", "ack_batch_hold_delays_ms_p99",
    "ack_batch_requested_wire_bytes", "ack_batch_departed_wire_bytes",
    "ack_batch_full_equivalent_wire_bytes", "ack_batch_saved_wire_bytes",
    "compact_wire_trimmed_repair_bytes", "shared_packed_predictive_records",
    "shared_timestamp_pair_candidates", "shared_timestamp_pair_records", "shared_timestamp_pair_saved_bytes",
    "ack_batch_submitted_records", "ack_batch_released_records", "ack_batch_unreceived_records",
)
# The shared loader predates terminal failure rows and requires these fields.
SHARED_REQUIRED = (
    PREFIX + "censored_segments", PREFIX + "latency_lower_bound_p99_ms",
    PREFIX + "miss_fraction_lower", PREFIX + "miss_fraction_upper",
    "with_drain_tcp_all_segment_ack_rtt_p99_ms", "tcp_timestamp_rtt_p99_ms",
    "with_drain_tcp_timestamp_rtt_p99_ms", "fully_confirmed",
    "steady_application_goodput_mbps", "forward_measurement_mbps", "reverse_measurement_mbps",
    "forward_wire_bytes", "reverse_wire_bytes",
)


def fallback_load(root, name, manifest, raw_runs):
    """Preserve terminal JSONs with absent metrics using the same source audit."""
    directory = root / "tcp-latency" / name
    verification_path = directory / "source-verification.json"
    verification = json.loads(verification_path.read_text())
    if verification.get("changed_during_run") != []:
        raise ValueError(f"Source verification failed or is incomplete: {name}")
    sources = manifest["sources"]
    if not sources:
        raise ValueError(f"Source inventory is empty: {name}")
    for source, expected in sources.items():
        snapshot = directory / "sources" / source
        if not snapshot.is_file() or aligned.digest(snapshot) != expected:
            raise ValueError(f"Missing or mismatched source snapshot: {snapshot}")
    rows = []
    for task, path, raw in raw_runs:
        for key, expected in task.items():
            if key in raw:
                actual = archive.object_value(raw[key]) if key == "profile" else raw[key]
                if actual != expected:
                    raise ValueError(f"Saved run does not match task field {key}: {path}")
        row = archive.normalize(raw, task, manifest, "tcp-latency/" + name,
                                path.relative_to(root).as_posix(), 1)
        rows.append(row)
    evidence = dict(study="tcp-latency/" + name, planned=len(raw_runs), saved=len(raw_runs),
                    experiment_sha256=aligned.digest(directory / "experiment.json"),
                    source_verification_sha256=aligned.digest(verification_path), source_hashes=sources,
                    loader="missing-metric fallback with task and source validation")
    return rows, [evidence]


def load(root, names):
    rows, evidence = [], []
    for name in names:
        if Path(name).name != name or name in (".", ".."):
            raise ValueError("Study names must be direct directories under tcp-latency")
        directory = root / "tcp-latency" / name
        manifest = json.loads((directory / "experiment.json").read_text())
        tasks = manifest["tasks"]
        if not tasks or len({task["run_id"] for task in tasks}) != len(tasks):
            raise ValueError(f"Empty or duplicate task plan: {name}")
        planned = {f"{task['run_id']:05d}.json" for task in tasks}
        if {path.name for path in (directory / "runs").glob("*.json")} != planned:
            raise ValueError(f"Awaiting exact planned terminal run set: {name}")
        raw_runs = [(task, directory / "runs" / f"{task['run_id']:05d}.json") for task in tasks]
        raw_runs = [(task, path, json.loads(path.read_text())) for task, path in raw_runs]
        has_schema = all(all(raw.get(key) is not None for key in SHARED_REQUIRED)
                         and "profile" in raw and "wire_format" in task["profile"]
                         for task, _, raw in raw_runs)
        normalized, audit = (aligned.load_studies(root, {name: None}) if has_schema
                             else fallback_load(root, name, manifest, raw_runs))
        source_version = sha256(json.dumps(manifest["sources"], sort_keys=True).encode()).hexdigest()[:12]
        for row, (task, path, raw) in zip(normalized, raw_runs):
            profile = task["profile"]
            source = path.relative_to(root).as_posix()
            # normalize supplies the traffic-interval estimator and stable archive ID.
            original = archive.normalize(raw, task, manifest, "tcp-latency/" + name, source, 1)
            row.update(original)
            censored = archive.numeric(raw.get(PREFIX + "censored_segments"))
            confirmed = raw.get("fully_confirmed")
            row.update(run_id=task["run_id"], source_sha256=aligned.digest(path),
                       original_profile=json.dumps(profile, sort_keys=True),
                       label=str(raw.get("strategy") or profile.get("name") or row["name"]),
                       report_source_version=source_version, fully_confirmed=confirmed,
                       censored_segments=censored, ack_p99_is_lower_bound=bool(censored),
                       tcp_all_segment_ack_p99_ms=archive.numeric(raw.get(PREFIX + "latency_lower_bound_p99_ms")),
                       deadline_ms=archive.numeric(raw.get("latency_budget_ms")),
                       recorded_rtt_budget_met=raw.get("rtt_budget_met"),
                       original_error=raw.get("error") or raw.get("exception"),
                       ack_batch_encoding_datagrams=json.dumps(raw.get("ack_batch_encoding_datagrams"), sort_keys=True))
            if row["deadline_ms"] is None and row["rtt_ms"] is not None:
                row["deadline_ms"] = 1.5 * row["rtt_ms"]
            for key in RAW_FIELDS:
                row[key] = archive.numeric(raw.get(key))
            for key in ("offered_segments", "completed_segments", "completed_exceeded_segments",
                        "censored_exceeded_segments", "censored_within_budget_segments"):
                row["cohort_" + key] = archive.numeric(raw.get(PREFIX + key))
            lower = archive.numeric(raw.get(PREFIX + "miss_fraction_lower"))
            row["tcp_deadline_miss_lower_pct"] = 100 * lower if lower is not None else None
            row["cohort"] = json.dumps([original["cohort"], source_version, row["deadline_ms"]])
            row["cohort_label"] += f" | all-source {source_version} | deadline {row['deadline_ms']} ms"
            if row["original_error"]:
                row["status"] = "failed"
            elif confirmed is not True or censored != 0:
                row["status"] = "incomplete" if confirmed is False or censored else "confirmation unknown"
            row["eligible"] = bool(original["eligible"] and confirmed is True and censored == 0
                                   and not row["original_error"])
            fields = ("goodput_mbps", "forward_mbps", "tcp_all_segment_ack_p99_ms",
                      "tcp_rtt_p99_ms", "tcp_deadline_miss_pct", "deadline_ms")
            row["throughput_pass"] = (None if any(row[key] is None for key in fields[:2]) else
                                      row["goodput_mbps"] >= .8 * row["forward_mbps"])
            row["provisional_joint_pass"] = (None if any(row[key] is None for key in fields) else
                bool(row["eligible"] and row["throughput_pass"]
                     and row["tcp_all_segment_ack_p99_ms"] <= row["deadline_ms"]
                     and row["tcp_rtt_p99_ms"] <= row["deadline_ms"] and row["tcp_deadline_miss_pct"] <= 1))
            row["latency_periods"] = "Original-segment cohort through drain; TCP timestamp samples during traffic"
            rows.append(row)
        evidence.extend(audit)
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("Duplicate study or raw execution")
    profiles = list(dict.fromkeys(row["original_profile"] for row in rows))
    for row in rows:
        index = profiles.index(row["original_profile"])
        row["configuration"] = f"C{index + 1:02d}"
        row["color"] = aligned.COLORS[index % len(aligned.COLORS)]
    return rows, evidence


def summarize(rows):
    means = archive.summarize(rows)
    groups = defaultdict(list)
    for row in rows:
        groups[(row["cohort"], row["study"], row["name"], row["profile"])].append(row)
    for mean in means:
        group = groups[(mean["cohort"], mean["study"], mean["name"], mean["profile"])]
        for key in ("label", "configuration", "color", "duration_s", "warmup_s", "drain_s",
                    "report_source_version", "deadline_ms", "forward_mbps", "reverse_mbps", "original_profile"):
            mean[key] = group[0][key]
        mean.update(raw_inputs=json.dumps([row["source"] for row in group]),
                    raw_ids=json.dumps([row["id"] for row in group]),
                    fully_confirmed_count=sum(row["fully_confirmed"] is True for row in group),
                    throughput_passes=sum(row["throughput_pass"] is True for row in group),
                    provisional_joint_passes=sum(row["provisional_joint_pass"] is True for row in group))
        for metric in (*RAW_FIELDS, "censored_segments", "tcp_deadline_miss_lower_pct"):
            units = defaultdict(list)
            observed = [row for row in group if row[metric] is not None]
            for row in observed:
                seed = str(row["seed"]) if row["seed"] not in (None, "") else "unknown-" + row["id"]
                units[seed].append(row[metric])
            estimate = stats.mean_ci([sum(values) / len(values) for values in units.values()])
            mean[metric] = estimate["mean"]
            mean[metric + "_low"] = estimate["ci_low"] if not mean["unknown_seed_runs"] else None
            mean[metric + "_high"] = estimate["ci_high"] if not mean["unknown_seed_runs"] else None
            mean[metric + "_n"] = len(observed)
    return means


def targets(rows, metric):
    key = {"tcp_all_segment_ack_p99_ms": "deadline_ms", "tcp_rtt_p99_ms": "deadline_ms",
           "reverse_measurement_mbps": "reverse_mbps"}.get(metric)
    if key:
        return sorted({row[key] for row in rows if row[key] is not None})
    return {"tcp_deadline_miss_pct": [1], "packet_extra_pct": [20]}.get(metric, [])


def figures(output, rows, means):
    fragments, coverage, boundaries = [], [], []
    payloads = sorted({row["payload_bytes"] for row in rows}, key=lambda value: (value is None, value or 0))
    for payload_index, payload in enumerate(payloads):
        selected = [row for row in rows if row["payload_bytes"] == payload]
        summaries = [row for row in means if row["payload_bytes"] == payload]
        chart = make_subplots(rows=3, cols=2, subplot_titles=[title for _, title in PANELS],
                              horizontal_spacing=.12, vertical_spacing=.11)
        figure, axes = plt.subplots(3, 2, figsize=(16, 16))
        configurations = list(dict.fromkeys(row["configuration"] for row in selected))
        for panel, ((metric, title), axis) in enumerate(zip(PANELS, axes.flat)):
            grid_row, grid_col = panel // 2 + 1, panel % 2 + 1
            thresholds = targets(selected, metric)
            observed_x = [row[metric] for row in selected if row[metric] is not None] + thresholds
            observed_y = [row["goodput_mbps"] for row in selected if row["goodput_mbps"] is not None]
            x_span = max(max(observed_x or [1]) - min(observed_x or [0]), 1)
            y_span = max(max(observed_y or [1]) - min(observed_y or [0]), .1)
            missing_x = max(observed_x or [0]) + .2 * x_span
            missing_y = min(observed_y or [0]) - .2 * y_span
            missing = any(row[metric] is None or row["goodput_mbps"] is None for row in selected)
            for configuration in configurations:
                points = [row for row in selected if row["configuration"] == configuration]
                color = points[0]["color"]
                x = [row[metric] if row[metric] is not None else missing_x for row in points]
                y = [row["goodput_mbps"] if row["goodput_mbps"] is not None else missing_y for row in points]
                text = [f"{escape(row['id'])}<br>{escape(row['label'])}<br>{escape(row['cohort_label'])}"
                        f"<br>Seed {row['seed']} · {row['status']} · confirmed {row['fully_confirmed']}"
                        f"<br>Censored originals {row['censored_segments']}"
                        + ("<br>ACK P99 is a censored lower bound" if row["ack_p99_is_lower_bound"] else "")
                        + ("<br>Missing coordinate shown in unmeasured strip"
                           if row[metric] is None or row["goodput_mbps"] is None else "") for row in points]
                chart.add_trace(go.Scatter(x=x, y=y, mode="markers", ids=[row["id"] for row in points],
                    name=configuration + " · " + points[0]["label"], legendgroup=configuration, showlegend=False,
                    meta=dict(kind="raw-run", metric=metric, configuration=configuration),
                    customdata=[[row["run_id"], str(row["seed"]), row[metric], row["goodput_mbps"]] for row in points],
                    marker=dict(color=color, size=9, opacity=.75,
                                symbol=["circle" if row["eligible"] else "x" for row in points]),
                    text=text, hovertemplate="%{text}<br>Recorded X %{customdata[2]}"
                        "<br>Full Mbps %{customdata[3]}<extra></extra>", cliponaxis=False), row=grid_row, col=grid_col)
                for row, px, py in zip(points, x, y):
                    axis.scatter(px, py, color=color, marker="o" if row["eligible"] else "x", s=26, alpha=.75)
                    coverage.append(dict(id=row["id"], run_id=row["run_id"], seed=str(row["seed"]),
                        source=row["source"], source_sha256=row["source_sha256"], payload_bytes=payload,
                        metric=metric, x=px, y=py, recorded_x=row[metric], recorded_y=row["goodput_mbps"],
                        coordinate_kind="measured" if row[metric] is not None and row["goodput_mbps"] is not None
                        else "unmeasured strip", configuration=configuration, color=color,
                        chart_id=f"compact-ack-payload-{payload_index}"))
                group = [row for row in summaries if row["configuration"] == configuration
                         and row[metric] is not None and row["goodput_mbps"] is not None]
                chart.add_trace(go.Scatter(x=[row[metric] for row in group], y=[row["goodput_mbps"] for row in group],
                    mode="markers", marker=dict(color=color, symbol="diamond-open", size=13),
                    showlegend=False, meta=dict(kind="configuration-mean", metric=metric),
                    text=[f"{configuration} · n={row['n']} · {escape(row['cohort_label'])}" for row in group],
                    hovertemplate="%{text}<br>X %{x:.5f}<br>Full Mbps %{y:.5f}<extra></extra>"), row=grid_row, col=grid_col)
                axis.scatter([row[metric] for row in group], [row["goodput_mbps"] for row in group],
                             edgecolor=color, facecolor="none", marker="D", s=55)
            for cohort in dict.fromkeys(row["cohort"] for row in summaries):
                boundary = archive.frontier([row for row in summaries if row["cohort"] == cohort], metric)
                boundaries.extend(dict(row, frontier_metric=metric) for row in boundary)
                chart.add_trace(go.Scatter(x=[row[metric] for row in boundary], y=[row["goodput_mbps"] for row in boundary],
                    mode="lines", line=dict(color="#475569", dash="dash"), showlegend=False,
                    meta=dict(kind="matched-mean-frontier", metric=metric, cohort=cohort),
                    hoverinfo="skip"), row=grid_row, col=grid_col)
                axis.plot([row[metric] for row in boundary], [row["goodput_mbps"] for row in boundary], "--", color="#475569")
            for target in thresholds:
                chart.add_vline(x=target, line_dash="dot", line_color="#b91c1c", row=grid_row, col=grid_col)
                axis.axvline(target, linestyle=":", color="#b91c1c")
            for target in sorted({.8 * row["forward_mbps"] for row in selected if row["forward_mbps"] is not None}):
                chart.add_hline(y=target, line_dash="dot", line_color="#15803d", row=grid_row, col=grid_col)
                axis.axhline(target, linestyle=":", color="#15803d")
            if missing:
                if any(row[metric] is None for row in selected):
                    chart.add_vline(x=missing_x, line_color="#cbd5e1", annotation_text="X unmeasured",
                                    row=grid_row, col=grid_col)
                    axis.axvline(missing_x, color="#cbd5e1")
                    axis.text(missing_x, .02, "X unmeasured", transform=axis.get_xaxis_transform(), rotation=90)
                if any(row["goodput_mbps"] is None for row in selected):
                    chart.add_hline(y=missing_y, line_color="#cbd5e1", annotation_text="Y unmeasured",
                                    row=grid_row, col=grid_col)
                    axis.axhline(missing_y, color="#cbd5e1")
                    axis.text(.02, missing_y, "Y unmeasured", transform=axis.get_yaxis_transform())
            chart.update_xaxes(title=dict(text=title), row=grid_row, col=grid_col)
            chart.update_yaxes(title=dict(text="Full application goodput (Mbps)"), row=grid_row, col=grid_col)
            axis.set(xlabel=title, ylabel="Full application goodput (Mbps)")
            axis.grid(alpha=.2)
            axis.margins(y=.15, x=.08)
        payload_label = f"{payload:g} B" if payload is not None else "Unknown payload"
        legend_rows = [next(row for row in selected if row["configuration"] == key) for key in configurations]
        legend = [textwrap.fill(row["configuration"] + " · " + row["label"], 135) for row in legend_rows]
        figure.suptitle(f"{payload_label} · {len(selected)} individual executions · separate matched-cohort mean frontiers")
        handles = [Line2D([], [], color=row["color"], marker="o", linestyle="none") for row in legend_rows]
        figure.legend(handles, legend, loc="lower left", bbox_to_anchor=(.04, .012), fontsize=8, frameon=False)
        legend_lines = sum(len(label.splitlines()) for label in legend)
        figure.tight_layout(rect=(0, .03 + legend_lines * .012, 1, .97))
        filename = f"pareto-payload-{payload:g}.png" if payload is not None else "pareto-payload-unknown.png"
        figure.savefig(output / filename, dpi=150)
        plt.close(figure)
        chart.update_layout(width=1250, height=1460, template="plotly_white",
            title=dict(text=f"{payload_label} · all {len(selected)} individual executions"), margin=dict(l=85, r=40, t=100, b=80))
        key = "".join(f'<li style="border-left:5px solid {row["color"]}">{escape(row["configuration"] + " · " + row["label"])}</li>'
                      for row in legend_rows)
        fragments.append(f'<section><h2>{escape(payload_label)} payload</h2><ul class="keys">{key}</ul>'
            '<div class="scroll">' + chart.to_html(full_html=False, include_plotlyjs=payload_index == 0,
                div_id=f"compact-ack-payload-{payload_index}", config=dict(responsive=False, displaylogo=False))
            + f'</div><p><a href="{filename}">Standalone PNG figure</a></p></section>')
    return "".join(fragments), coverage, boundaries


def link(output, path, label):
    return f'<a href="{escape(relpath(path, output))}">{escape(label)}</a>'


def render(root, names, output):
    rows, evidence = load(root, names)
    means = summarize(rows)
    output.mkdir(parents=True, exist_ok=True)
    panels, coverage, boundaries = figures(output, rows, means)
    expected = {(row["id"], metric) for row in rows for metric, _ in PANELS}
    if len(coverage) != len(expected) or {(row["id"], row["metric"]) for row in coverage} != expected:
        raise ValueError("Raw point coverage does not match every execution and panel")
    for filename, records in (("all-runs.csv", rows), ("configuration-means.csv", means),
                              ("plot-coverage.csv", coverage), ("frontiers.csv", boundaries)):
        archive.write_csv(output / filename, records)
    conditions = list({row["cohort"]: row for row in rows}.values())
    condition_table = aligned.table(["Matched cohort", "Deadline ms"],
        [[row["cohort_label"], row["deadline_ms"]] for row in conditions])
    summary = aligned.table(["Configuration", "Study", "n / unique seeds", "Full Mbps", "95% interval",
        "Steady Mbps", "All-segment ACK P99 ms", "Traffic timestamp P99 ms", "Miss upper %",
        "Extra packets %", "Extra bytes %", "Reverse Mbps", "Confirmed", "Throughput passes", "Provisional joint passes"],
        [[row["configuration"], row["study"], f"{row['n']} / {row['independent_n']}", row["goodput_mbps"],
          f"{row['goodput_mbps_low']} – {row['goodput_mbps_high']}", row["steady_application_goodput_mbps"],
          row["tcp_all_segment_ack_p99_ms"], row["tcp_rtt_p99_ms"], row["tcp_deadline_miss_pct"],
          row["packet_extra_pct"], row["byte_extra_pct"], row["reverse_measurement_mbps"],
          f"{row['fully_confirmed_count']}/{row['n']}", f"{row['throughput_passes']}/{row['n']}",
          f"{row['provisional_joint_passes']}/{row['n']}"] for row in means])
    configs = list({row["configuration"]: row for row in rows}.values())
    config_table = aligned.table(["ID", "Original strategy", "Flows", "ACK encoding", "Copies", "Trim",
        "Repair ratio", "Pace Mbps", "Distinct ports", "ACK delay ms", "Batch hold ms", "Forward framing"],
        [[row["configuration"], row["label"], profile.get("flow_count"), profile.get("ack_record_encoding", "full"),
          profile.get("ack_copies"), profile.get("compact", {}).get("trim_repair_padding", False),
          profile.get("compact", {}).get("repair_ratio"), profile.get("payload_rate_mbps"),
          profile.get("distinct_flow_headers", False), profile.get("ack_delay_ms", 10),
          profile.get("ack_batch_hold_ms"), profile.get("compact", {}).get("encapsulation", "udp")]
         for row in configs for profile in [json.loads(row["original_profile"])]])
    raw_table = aligned.table(["Raw ID", "Configuration", "Seed", "Status", "Full Mbps", "All-segment ACK P99 ms",
        "Traffic timestamp P99 ms", "Miss lower %", "Miss upper %", "Offered", "ACKed", "Censored", "Fully confirmed"],
        [[row["id"], row["configuration"], str(row["seed"]), row["status"], row["goodput_mbps"],
          row["tcp_all_segment_ack_p99_ms"], row["tcp_rtt_p99_ms"], row["tcp_deadline_miss_lower_pct"],
          row["tcp_deadline_miss_pct"], row["offered_frames"], row["tcp_acked_frames"], row["censored_segments"],
          row["fully_confirmed"]] for row in rows])
    costs = aligned.table(["Raw ID", "ACK formats, requested copies", "ACK requested B", "ACK departed B",
        "Full-equivalent requested B", "ACK requested savings B", "Forward repair requested trim B",
        "Timestamp pair candidates", "Timestamp pair hits", "Timestamp pair source savings B",
        "All forward departed B", "All reverse departed B", "Reverse traffic Mbps"],
        [[row["id"], row["ack_batch_encoding_datagrams"], row["ack_batch_requested_wire_bytes"],
          row["ack_batch_departed_wire_bytes"], row["ack_batch_full_equivalent_wire_bytes"],
          row["ack_batch_saved_wire_bytes"], row["compact_wire_trimmed_repair_bytes"],
          row["shared_timestamp_pair_candidates"], row["shared_timestamp_pair_records"],
          row["shared_timestamp_pair_saved_bytes"],
          row["forward_wire_bytes"], row["reverse_wire_bytes"], row["reverse_measurement_mbps"]] for row in rows])
    source_links = []
    for name in names:
        directory = root / "tcp-latency" / name
        links = [link(output, directory / filename, filename) for filename in
                 ("experiment.json", "source-verification.json", "profiles.json", "execution-attempts.json")
                 if (directory / filename).exists()]
        source_links.append(f'<li>{escape(name)} · ' + " · ".join(links) + '</li>')
    raw_links = " · ".join(link(output, root / row["source"], f"{row['study'].split('/')[-1]} run {row['run_id']}") for row in rows)
    snapshots = output / "report-sources"
    snapshots.mkdir(exist_ok=True)
    report_sources = {}
    for source in (Path(__file__), Path(aligned.__file__), Path(archive.__file__), Path(stats.__file__)):
        target = snapshots / source.name
        target.write_bytes(source.read_bytes())
        report_sources[target.relative_to(output).as_posix()] = aligned.digest(target)
    receipt = dict(record_kind="derived_compact_ack_report", studies=evidence,
        raw_inputs={row["source"]: row["source_sha256"] for row in rows},
        saved_runs=len(rows), panels_per_payload=len(PANELS), raw_plot_instances=len(coverage),
        unique_plotted_runs=len({row["id"] for row in coverage}),
        unmeasured_plot_instances=sum(row["coordinate_kind"] != "measured" for row in coverage),
        fully_confirmed_runs=sum(row["fully_confirmed"] is True for row in rows),
        provisional_joint_passes=sum(row["provisional_joint_pass"] is True for row in rows),
        report_sources=report_sources, generator_sha256=aligned.digest(Path(__file__)),
        source_validation="Every planned raw JSON and every frozen source digest checked; changed_during_run empty",
        archive_export_schema="Derived normalized observations with original source/id and source_sha256",
        metric_windows="Original-segment cohort through drain; timestamp estimator and reverse Mbps during traffic",
        frontier_grouping="Complete profile means, matched payload/scenario/duration/warmup/drain/model/all-source-version/deadline",
        browser_validation="Not performed by this renderer")
    (output / "report-validation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compact ACK experiments</title><style>body{{font:15px/1.55 system-ui,sans-serif;color:#172435;background:#f5f7fa;margin:0}}
main{{max-width:1500px;margin:auto;padding:24px;min-width:0}}section{{background:white;padding:20px;margin:20px 0;border:1px solid #dbe1e8;border-radius:8px;min-width:0}}
.scroll{{overflow-x:auto;max-width:100%}}table{{border-collapse:collapse;font-size:13px}}th,td{{padding:8px 11px;border-bottom:1px solid #dbe1e8;text-align:left;white-space:nowrap}}
th{{background:#edf2f7}}a{{color:#1664a5}}p,li{{overflow-wrap:anywhere}}.keys{{list-style:none;padding:0}}.keys li{{padding:3px 10px;margin:6px 0}}
@media(max-width:600px){{main{{padding:10px}}section{{padding:12px}}h1{{font-size:25px}}}}</style><main>
<h1>Compact ACK experiments</h1><p>{len(rows)} individual executions across {len(names)} studies.
{receipt['fully_confirmed_runs']} are fully confirmed. {receipt['provisional_joint_passes']} pass the provisional joint gate.
Each raw execution appears in all six panels for its payload, including incomplete and dominated outcomes.</p>
<section><h2>Measurement and comparison rules</h2><p>Full goodput uses application bytes delivered in the complete traffic interval.
Steady goodput excludes the warmup. Original-segment ACK latency starts at the segment's first submission and ends at a cumulative ACK
covering that segment. Its cohort retains all originals through drain. A censored segment contributes its observed waiting-time lower bound.
The timestamp estimator samples ACK-carried timestamps during traffic. Both metrics are shown independently.</p>
<p>The provisional joint gate requires full goodput at least 80% of forward capacity, all-original-segment ACK P99 and traffic timestamp P99
at most 1.5 times base RTT, deadline-miss upper fraction at most 1%, and complete confirmation with no censored originals.
For the reference 100/10 Mbps, 70 ms scenario these limits are 80 Mbps and 105 ms. The historical extra-packet cap of 20% is shown
separately, with its own pass/fail status.</p>
<p>Extra packets equal all forward datagrams through drain divided by unique delivered TCP segments, minus one.
Extra bytes equal all forward IP bytes through drain divided by delivered application payload bytes, minus one.
Reverse Mbps uses actual IP bytes that departed during traffic divided by the traffic duration. Lost transmissions are charged.
ACK compression, repair trimming and timestamp-pair counters describe requested encodings. Departed-byte counters determine measured link cost.</p>
<p>Circles are eligible confirmed runs, crosses are incomplete or diagnostic observations, and open diamonds are configuration means.
Missing coordinates occupy labeled unmeasured strips. Dashed mean frontiers match payload, link conditions, traffic duration, warmup,
drain, model, complete source-snapshot version and deadline. Means use the complete profile as a grouping key. Each frontier follows a single
cohort. Lower cost or latency and higher full goodput define dominance. Every configuration mean is descriptive.</p>
<p>95% intervals use Student-t estimates across independent seed means. Three-seed screens provide limited information about tail variability.
Repeated seeds are combined before interval estimation. Missing metric samples are counted in the CSV, and partially observed means are
excluded from the corresponding frontier. These intervals do not bound packet-level tails or model error.</p>{condition_table}</section>
<section><h2>Configurations</h2>{config_table}</section>
{panels}<section><h2>Configuration means</h2>{summary}</section>
<section><h2>Every original execution</h2>{raw_table}<p>{raw_links}</p></section>
<section><h2>Requested savings and departed wire cost</h2>{costs}</section>
<section><h2>Implementation scope</h2><p>ACK batches reconstruct complete 66-byte Ethernet/IPv4/TCP timestamp ACK frames from transmitted bytes.
The full format preserves every frame. Optional batch_delta chooses the smallest full, fresh batch-local CompactHeaderCodec, or byte-patch
envelope. Compressed records retain channel, 64-bit event identity and explicit length. Every batch carries its own initial full context.
Byte patches include a nine-byte changed-position mask and all changed bytes. TCP checksums are verified. Distinct-port profiles use source
port 443 and destination 49152 plus the channel index. These are custom formats.</p>
<p>Verified ACK frame bytes release the existing simulator callback, which retains unwrapped sequence numbers and sub-millisecond timestamp
state. Forward GF(256) recovery tracks coefficient rank and uses the existing source ledger for reconstructed content. Payload arithmetic CPU,
host scheduling, NIC costs, deployed TCP stack behavior and cryptographic processing are outside this model. Raw IPv4 CRC32 forward framing
and optional repair zero-padding removal are charged according to each recorded profile. Historical source snapshots remain the execution evidence.</p>
</section><section><h2>Sources and exports</h2><ul>{''.join(source_links)}</ul><p>
<a href="all-runs.csv">Individual-point CSV</a> · <a href="configuration-means.csv">Means and intervals</a> ·
<a href="frontiers.csv">Matched frontiers</a> · <a href="plot-coverage.csv">Exact point coverage</a> ·
<a href="report-validation.json">Source and report receipt</a> ·
<a href="report-sources/compact_ack_report.py">Frozen report generator</a></p></section></main></html>'''
    (output / "report.html").write_text(page)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--studies", nargs="+", required=True, help="Completed directory names under root/tcp-latency")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    receipt = render(args.root.resolve(), args.studies, args.out.resolve())
    print(json.dumps({key: receipt[key] for key in ("saved_runs", "raw_plot_instances", "fully_confirmed_runs", "provisional_joint_passes")}))


if __name__ == "__main__":
    main()
