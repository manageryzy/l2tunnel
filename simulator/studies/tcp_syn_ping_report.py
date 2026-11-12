"""Render every frozen TCP SYN-ping run with payload-specific Pareto figures."""

import argparse
from collections import defaultdict
from hashlib import sha256
from html import escape
import json
from os.path import relpath
from pathlib import Path
import sys

from math import log10

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import plotly.graph_objects as go

# Existing report helpers also support direct invocation from the studies folder.
if __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import all_experiments as archive
import compact_ack_report as compact
from l2tunnel_sim import stats


LATENCY = "tcp_syn_ping_p99_ms"
LATENCY_TICKS = (.1, .2, .5, 1, 2, 5, 10, 20, 50, 70, 100, 200, 500, 1000, 2000, 5000, 10000)
THROUGHPUTS = (
    ("goodput_mbps", "Full traffic-interval bulk goodput (Mbps)"),
    ("tcp_syn_ping_background_goodput_mbps", "Concurrent bulk goodput (Mbps)"),
)
SYMBOLS = ("circle", "square", "diamond", "triangle-up", "triangle-down", "pentagon",
           "hexagon", "star", "cross", "x", "triangle-left", "triangle-right")
MPL_SYMBOLS = ("o", "s", "D", "^", "v", "p", "h", "*", "P", "X", "<", ">")
NUMERIC_FIELDS = (
    "tcp_syn_ping_p50_ms", "tcp_syn_ping_p95_ms", LATENCY,
    "tcp_syn_ping_cohort_lower_bound_p99_ms", "tcp_syn_ping_failure_pct",
    "tcp_syn_ping_deadline_miss_upper_pct", "tcp_syn_ping_budget_ms",
    "tcp_syn_ping_timeouts", "tcp_syn_ping_censored", "tcp_syn_ping_offered", "tcp_syn_ping_completed",
    "tcp_syn_probe_start_s", "tcp_syn_probe_admission_end_s", "tcp_syn_ping_background_goodput_mbps",
    "tcp_syn_ping_syn_retransmissions", "tcp_syn_ping_synack_transmissions",
    "tcp_syn_probe_forward_frames", "tcp_syn_probe_forward_frame_bytes",
    "tcp_syn_probe_reverse_requested_bytes", "tcp_syn_probe_reverse_departed_bytes",
    "tcp_syn_probe_reverse_datagrams", "tcp_syn_probe_reverse_erasures", "tcp_syn_probe_copy_duplicates",
    "forward_measurement_mbps", "reverse_measurement_mbps",
)
BASE_FIELDS = (
    "id", "study", "source", "source_sha256", "run_id", "seed", "replication", "name", "label",
    "profile", "original_profile", "payload_bytes", "forward_mbps", "reverse_mbps", "rtt_ms",
    "loss_rate", "loss_model", "mean_burst", "mtu", "duration_s", "warmup_s", "drain_s", "paths",
    "model", "version", "report_source_version", "cohort_label", "quality", "goodput_mbps",
    "packet_extra_pct", "byte_extra_pct", "fully_confirmed",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


comparison_version = archive.comparison_version

def load(root, names):
    """Verify execution snapshots and retain each raw execution identity."""
    normalized, evidence = compact.load(root, names)
    engine_versions, runtimes = {}, {}
    for name in names:
        manifest = json.loads((root / "tcp-latency" / name / "experiment.json").read_text())
        engine_versions["tcp-latency/" + name], runtimes["tcp-latency/" + name] = comparison_version(manifest)
    rows, probes, windows = [], [], []
    for original in normalized:
        raw = json.loads((root / original["source"]).read_text())
        profile = archive.object_value(original["original_profile"])
        if "tcp_syn_ping_offered" not in raw and not profile.get("tcp_syn_probe"):
            raise ValueError(f"Run has no independent SYN probe configuration: {original['source']}")
        row = {key: original.get(key) for key in BASE_FIELDS}
        row["engine_source_version"] = engine_versions[row["study"]]
        row["recorded_runtime"] = canonical(runtimes[row["study"]])
        row.update({key: archive.numeric(raw.get(key)) for key in NUMERIC_FIELDS})
        config = archive.object_value(raw.get("tcp_syn_probe_config") or profile.get("tcp_syn_probe"))
        row["tcp_syn_probe_config"] = canonical(config)
        for key in ("tcp_syn_probe_all_flushed", "tcp_syn_probe_steady_state_reached", "tcp_syn_ping_joint_target_met"):
            row[key] = raw.get(key)
        row["original_error"] = raw.get("error") or raw.get("error_message") or raw.get("exception")
        row["execution_status"] = raw.get("execution_status")
        row["definition"] = raw.get("tcp_syn_ping_definition")
        row["endpoint_dispatch"] = raw.get("tcp_syn_probe_dispatch") or "unrecorded"
        row["probe_cpu_model"] = raw.get("tcp_syn_probe_cpu_model") or "unrecorded"
        row["probe_model_detail"] = raw.get("tcp_syn_probe_model_detail") or "unrecorded"
        row["strategy_type"], row["strategy_type_evidence"] = archive.strategy_family(raw, profile, row["label"])
        family = row["strategy_type"]
        row["color_group"] = family
        row["color_label"] = family
        row["color"] = archive.STRATEGY_COLORS.get(family, archive.STRATEGY_COLORS["Unclassified"])
        # Copy policy is a transport choice. Probe frequency, lifetime and stability
        # definition remain matched measurement conditions.
        measurement = {key: value for key, value in config.items()
                       if key not in ("reverse_copies", "copy_spacing_ms")}
        row["cohort"] = canonical([*[row[key] for key in archive.CONDITIONS],
                                    row["engine_source_version"], measurement, row["tcp_syn_ping_budget_ms"],
                                    row["endpoint_dispatch"], row["probe_cpu_model"], row["probe_model_detail"]])
        row["cohort_label"] = row["cohort_label"].split(" | all-source ", 1)[0]
        row["cohort_label"] += " | engine " + row["engine_source_version"] + " | SYN measurement " + canonical(measurement)
        row["cohort_label"] += " | endpoint dispatch " + row["endpoint_dispatch"]
        offered = row["tcp_syn_ping_offered"]
        reasons = []
        if row["original_error"]:
            reasons.append("unsupported configuration" if row["execution_status"] == "unsupported" else "tool failure")
        if row["fully_confirmed"] is not True:
            reasons.append("bulk or outer confirmation incomplete")
        if row["tcp_syn_probe_steady_state_reached"] is not True:
            reasons.append("stability gate not reached")
        if row["tcp_syn_probe_all_flushed"] is not True:
            reasons.append("probe wire flush incomplete")
        if offered is None or offered <= 0:
            reasons.append("no probe cohort")
        if row["tcp_syn_ping_completed"] != offered or any(
                row[key] != 0 for key in ("tcp_syn_ping_timeouts", "tcp_syn_ping_censored", "tcp_syn_ping_failure_pct")):
            reasons.append("probe failures or unresolved probes")
        if any(row[key] is None for key in (LATENCY, *[key for key, _ in THROUGHPUTS])):
            reasons.append("missing plotted metric")
        if any(row[key] is None for key in archive.CONDITIONS if key != "mean_burst"):
            reasons.append("missing physical or measurement condition")
        row["eligible"] = not reasons
        row["status"] = "complete" if row["eligible"] else "ineligible"
        if row["execution_status"] == "unsupported":
            row["status"] = "unsupported"
        elif row["execution_status"] in ("error", "failed", "tool failure"):
            row["status"] = "tool failure"
        elif row["execution_status"] == "bound exhausted":
            row["status"] = "bound exhausted"
        row["exclusion_reason"] = " | ".join(reasons)
        target = .8 * row["forward_mbps"] if row["forward_mbps"] is not None else None
        row["joint_target_met"] = bool(row["eligible"] and target is not None
            and all(row[key] >= target for key, _ in THROUGHPUTS)
            and row["tcp_syn_ping_budget_ms"] is not None and row[LATENCY] <= row["tcp_syn_ping_budget_ms"]
            and row["tcp_syn_ping_deadline_miss_upper_pct"] is not None
            and row["tcp_syn_ping_deadline_miss_upper_pct"] <= 1)
        for item in raw.get("tcp_syn_probe_records", []):
            probes.append(dict(raw_id=row["id"], raw_source=row["source"], raw_sha256=row["source_sha256"], **item))
        history = raw.get("tcp_syn_probe_stability_history", [])
        row["stability_window_count"] = len(history)
        row["probe_record_count"] = len(raw.get("tcp_syn_probe_records", []))
        for index, item in enumerate(history, 1):
            window = dict(raw_id=row["id"], window=index, raw_source=row["source"], raw_sha256=row["source_sha256"])
            window.update({"observed_" + key: value for key, value in item.items()})
            window["phase"] = ("before admission" if row["tcp_syn_probe_start_s"] is None
                               or item["end_s"] <= row["tcp_syn_probe_start_s"] else "after admission")
            windows.append(window)
        rows.append(row)
    configurations = sorted({row["original_profile"] for row in rows})
    for case, row in enumerate(rows, 1):
        index = configurations.index(row["original_profile"])
        row.update(case_number=case, configuration=f"C{index + 1:02d}",
                   symbol=SYMBOLS[index % len(SYMBOLS)], mpl_symbol=MPL_SYMBOLS[index % len(MPL_SYMBOLS)])
    return rows, evidence, probes, windows


def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[row["cohort"], row["study"], row["original_profile"]].append(row)
    output = []
    for records in groups.values():
        first = records[0]
        result = {key: first[key] for key in ("cohort", "cohort_label", "study", "configuration", "label",
                  "original_profile", "payload_bytes", "strategy_type", "color_group", "color_label", "color",
                  "symbol", "mpl_symbol", "report_source_version", "engine_source_version", "forward_mbps", "tcp_syn_ping_budget_ms",
                  "endpoint_dispatch", "probe_cpu_model", "probe_model_detail")}
        result.update(id="mean-" + sha256("|".join(row["id"] for row in records).encode()).hexdigest()[:12],
                      n=len(records), eligible=all(row["eligible"] for row in records),
                      raw_ids=canonical([row["id"] for row in records]),
                      joint_passes=sum(row["joint_target_met"] for row in records))
        for key in (LATENCY, *[key for key, _ in THROUGHPUTS]):
            units = defaultdict(list)
            for row in records:
                if row[key] is not None:
                    seed = str(row["seed"]) if row["seed"] is not None else row["id"]
                    units[seed].append(row[key])
            estimate = stats.mean_ci([sum(values) / len(values) for values in units.values()])
            result[key] = estimate["mean"]
            known_seeds = all(row["seed"] is not None for row in records)
            result[key + "_low"] = estimate["ci_low"] if known_seeds else None
            result[key + "_high"] = estimate["ci_high"] if known_seeds else None
            result[key + "_n"] = sum(row[key] is not None for row in records)
            result[key + "_independent_n"] = len(units)
        output.append(result)
    return output


def frontier(means, throughput):
    candidates = [row for row in means if row["eligible"] and row[LATENCY] is not None
                  and row[throughput] is not None and row[LATENCY + "_n"] == row["n"]
                  and row[throughput + "_n"] == row["n"]]
    result, best, previous_latency = [], float("-inf"), None
    for row in sorted(candidates, key=lambda item: (item[LATENCY], -item[throughput])):
        if row[throughput] > best or (row[throughput] == best and row[LATENCY] == previous_latency):
            result.append(row)
            best, previous_latency = row[throughput], row[LATENCY]
    return result


def display(value):
    return "—" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)


def table(headers, records):
    return '<div class="scroll"><table><thead><tr>' + ''.join(
        f'<th>{escape(header)}</th>' for header in headers) + '</tr></thead><tbody>' + ''.join(
        '<tr>' + ''.join(f'<td>{escape(display(value))}</td>' for value in record) + '</tr>'
        for record in records) + '</tbody></table></div>'


def hover(row):
    return (f"Case {row['case_number']} · {escape(row['configuration'])} · seed {row['seed']}"
        f"<br>{escape(row['label'])}<br>{escape(row['id'])}"
        f"<br>Endpoint dispatch {escape(row['endpoint_dispatch'])}"
        f"<br>Completed P99 {display(row[LATENCY])} ms"
        f"<br>Full bulk {display(row['goodput_mbps'])} Mbps"
        f"<br>Concurrent bulk {display(row['tcp_syn_ping_background_goodput_mbps'])} Mbps"
        f"<br>Completed/offered {display(row['tcp_syn_ping_completed'])}/{display(row['tcp_syn_ping_offered'])}"
        f"<br>Timeout/censored {display(row['tcp_syn_ping_timeouts'])}/{display(row['tcp_syn_ping_censored'])}"
        f"<br>Start {display(row['tcp_syn_probe_start_s'])} s · {escape(row['status'])}"
        f"<br>{escape(row['exclusion_reason'])}")


def figures(output, rows, means):
    sections, coverage, boundaries, chart_specs = [], [], [], []
    throughput = "tcp_syn_ping_background_goodput_mbps"
    payloads = sorted({row["payload_bytes"] for row in rows}, key=lambda value: (value is None, value or 0))
    for payload_index, payload in enumerate(payloads):
        selected = [row for row in rows if row["payload_bytes"] == payload]
        measured = [row for row in selected if row[LATENCY] is not None and row[LATENCY] > 0
                    and row[throughput] is not None and row["tcp_syn_probe_steady_state_reached"] is True]
        label = f"{payload:g} B" if payload is not None else "Unknown payload"
        chart_id = f"syn-ping-p{payload_index}"
        measured_ids = {row["id"] for row in measured}
        for row in selected:
            plotted = row["id"] in measured_ids
            coverage.append(dict(id=row["id"], payload_bytes=payload, chart_id=chart_id if plotted else "",
                panel=throughput, cohort=row["cohort"], recorded_latency_ms=row[LATENCY], recorded_rate=row[throughput],
                plotted_x=row[LATENCY] if plotted else None, plotted_y=row[throughput] if plotted else None,
                coordinate_kind="measured" if plotted else "coverage table", configuration=row["configuration"],
                source=row["source"], source_sha256=row["source_sha256"], color=row["color"],
                symbol="circle" if row["eligible"] else "circle-open", exclusion_reason=row["exclusion_reason"],
                endpoint_dispatch=row["endpoint_dispatch"]))
        if not measured:
            sections.append(f'<section><h2>{escape(label)}</h2><p>No stable-load TCP PING measurements are available. '
                            f'All {len(selected)} saved cases appear in the coverage table and exports.</p></section>')
            continue
        groups = defaultdict(list)
        for row in measured:
            groups[row["cohort"]].append(row)
        ordered = sorted(groups, key=lambda cohort: (-len(groups[cohort]), -groups[cohort][0]["duration_s"], cohort))
        chart = go.Figure()
        cohort_specs, static_files, download_links = [], [], []
        for cohort_index, cohort in enumerate(ordered):
            points = groups[cohort]
            first = points[0]
            cohort_means = [row for row in means if row["cohort"] == cohort
                            and row[LATENCY] is not None and row[throughput] is not None]
            condition = (f"{first['forward_mbps']:g}/{first['reverse_mbps']:g} Mbps · RTT {first['rtt_ms']:g} ms · "
                         f"loss {100 * first['loss_rate']:g}% {first['loss_model']} · {first['duration_s']:g} s")
            short_engine = first["engine_source_version"].removeprefix("engine-")
            option = (f"{condition} · {len(points)} measured runs · engine {short_engine}"
                      f" · endpoint dispatch {first['endpoint_dispatch']}")
            families = list(dict.fromkeys(row["color_group"] for row in points))
            trace_start = len(chart.data)
            figure, axis = plt.subplots(figsize=(9, 5.8))
            for family in families:
                family_points = [row for row in points if row["color_group"] == family]
                color = family_points[0]["color"]
                chart.add_trace(go.Scatter(x=[row[LATENCY] for row in family_points],
                    y=[row[throughput] for row in family_points], ids=[row["id"] for row in family_points],
                    mode="markers", name=family, legendgroup=family, showlegend=True, visible=cohort_index == 0,
                    marker=dict(color=color, symbol=["circle" if row["eligible"] else "circle-open" for row in family_points],
                                size=8, opacity=.8, line=dict(width=1.5)),
                    text=[hover(row) for row in family_points], hovertemplate="%{text}<extra></extra>",
                    meta=dict(kind="raw-run", panel=throughput, cohort=cohort)))
                for row in family_points:
                    axis.scatter(row[LATENCY], row[throughput], s=32, marker="o", edgecolors=color,
                                 facecolors=color if row["eligible"] else "none", alpha=.8)
                family_means = [row for row in cohort_means if row["color_group"] == family and row["eligible"]]
                chart.add_trace(go.Scatter(x=[row[LATENCY] for row in family_means],
                    y=[row[throughput] for row in family_means], mode="markers", name=family + " means",
                    legendgroup=family, showlegend=False, visible=cohort_index == 0,
                    marker=dict(color=color, symbol="diamond", size=12, line=dict(color="white", width=1)),
                    text=[f"{row['configuration']} · {escape(row['label'])} · {row['n']} runs" for row in family_means],
                    hovertemplate="%{text}<br>Mean run P99 %{x:.3f} ms<br>Concurrent goodput %{y:.3f} Mbps<extra></extra>",
                    meta=dict(kind="configuration-mean", cohort=cohort)))
                axis.scatter([row[LATENCY] for row in family_means], [row[throughput] for row in family_means],
                             s=65, marker="D", color=color, edgecolors="white", linewidths=.5)
            boundary = frontier(cohort_means, throughput)
            boundaries.extend(dict(row, frontier_throughput=throughput) for row in boundary)
            chart.add_trace(go.Scatter(x=[row[LATENCY] for row in boundary], y=[row[throughput] for row in boundary],
                mode="lines", name="Pareto frontier of complete configuration means", showlegend=False,
                visible=cohort_index == 0, line=dict(color="#334155", dash="dash"), hoverinfo="skip",
                meta=dict(kind="configuration-mean-frontier", panel=throughput, cohort=cohort)))
            axis.plot([row[LATENCY] for row in boundary], [row[throughput] for row in boundary], "--", color="#334155")
            deadline = first["tcp_syn_ping_budget_ms"]
            target = .8 * first["forward_mbps"]
            low = min([row[LATENCY] for row in points] + [deadline]) * .85
            high = max([row[LATENCY] for row in points] + [deadline]) * 1.2
            ymax = max(first["forward_mbps"], max(row[throughput] for row in points)) * 1.05
            shapes = [dict(type="line", xref="x", yref="paper", x0=deadline, x1=deadline, y0=0, y1=1,
                           line=dict(color="#b91c1c", dash="dot", width=1)),
                      dict(type="line", xref="paper", yref="y", x0=0, x1=1, y0=target, y1=target,
                           line=dict(color="#15803d", dash="dot", width=1))]
            x_range = [log10(low), log10(high)]
            cohort_specs.append(dict(cohort=cohort, label=option, trace_indices=list(range(trace_start, len(chart.data))),
                raw_ids=[row["id"] for row in points], shapes=shapes, x_range=x_range, y_range=[0, ymax],
                endpoint_dispatch=first["endpoint_dispatch"]))
            axis.set(xscale="log", xlim=(low, high), ylim=(0, ymax), xlabel="TCP PING P99 (ms)",
                     ylabel="Concurrent bulk goodput (Mbps)",
                     title=(f"Coefficient/rank simulation · TCP SYN PING\n{label} · {condition}"
                            f"\nEndpoint dispatch · {first['endpoint_dispatch']}"))
            visible_ticks = [value for value in LATENCY_TICKS if low <= value <= high]
            axis.set_xticks(visible_ticks, [f"{value:g}" for value in visible_ticks])
            axis.minorticks_off()
            axis.axvline(deadline, color="#b91c1c", linestyle=":", linewidth=1)
            axis.axhline(target, color="#15803d", linestyle=":", linewidth=1)
            axis.grid(alpha=.2)
            handles = [Line2D([], [], marker="o", color=archive.STRATEGY_COLORS[family], linestyle="none", label=family)
                       for family in families]
            handles.extend([Line2D([], [], marker="D", color="#334155", linestyle="none", label="Configuration mean"),
                            Line2D([], [], color="#334155", linestyle="--", label="Matched Pareto frontier"),
                            Line2D([], [], color="#b91c1c", linestyle=":", label=f"PING target {deadline:g} ms"),
                            Line2D([], [], color="#15803d", linestyle=":", label=f"Goodput target {target:g} Mbps")])
            figure.legend(handles=handles, loc="lower center", ncol=2, frameon=False, fontsize=8)
            figure.tight_layout(rect=(0, .08 + .025 * len(handles), 1, 1))
            stem = f"{chart_id}-c{cohort_index}"
            for suffix in ("png", "svg"):
                filename = f"{stem}.{suffix}"
                figure.savefig(output / filename, dpi=160)
                static_files.append(filename)
            plt.close(figure)
            download_links.append(f'<li>{escape(option)} · <a href="{stem}.png">PNG</a> · <a href="{stem}.svg">SVG</a></li>')
        default = cohort_specs[0]
        chart.update_layout(template="plotly_white", autosize=True, height=650,
            margin=dict(l=65, r=15, t=15, b=145), shapes=default["shapes"],
            legend=dict(orientation="h", x=0, y=-.22, xanchor="left", yanchor="top", font=dict(size=11)),
            xaxis=dict(title="TCP PING P99 (ms, logarithmic scale)", type="log", range=default["x_range"], automargin=True,
                       tickmode="array", tickvals=list(LATENCY_TICKS),
                       ticktext=[f"{value:g}" for value in LATENCY_TICKS]),
            yaxis=dict(title="Concurrent bulk goodput (Mbps)", range=default["y_range"], automargin=True),
            hoverlabel=dict(namelength=-1))
        options = ''.join(f'<option value="{index}">{escape(item["label"])}</option>' for index, item in enumerate(cohort_specs))
        selector = (f'<label>Matched conditions <select data-syn-select="{chart_id}">{options}</select></label>'
                    f'<p data-syn-dispatch="{chart_id}">Endpoint dispatch · {escape(default["endpoint_dispatch"])}</p>')
        plot = chart.to_html(full_html=False, include_plotlyjs=not chart_specs, div_id=chart_id,
                             config=dict(responsive=True, displaylogo=False))
        data = canonical(cohort_specs).replace("<", "\\u003c")
        script = f'''<script>(function(){{const id={json.dumps(chart_id)}, groups={data};
const select=document.querySelector('[data-syn-select="'+id+'"]');
select.addEventListener('change',function(){{const item=groups[Number(this.value)];
document.querySelector('[data-syn-dispatch="'+id+'"]').textContent='Endpoint dispatch · '+item.endpoint_dispatch;
Plotly.update(id,{{visible:document.getElementById(id).data.map((_,i)=>item.trace_indices.includes(i))}},
{{shapes:item.shapes,'xaxis.range':item.x_range,'yaxis.range':item.y_range}});}});}})();</script>'''
        sections.append(f'<section><h2>{escape(label)} · TCP PING and concurrent throughput</h2>' + selector
            + '<div class="chart">' + plot + '</div>' + script
            + f'<p>{len(measured)} measured runs. {len(selected)-len(measured)} cases with unavailable coordinates appear in the coverage table.</p>'
            + '<details><summary>Export each matched comparison</summary><ul>' + ''.join(download_links) + '</ul></details></section>')
        chart_specs.append(dict(id=chart_id, payload_bytes=payload, panel=throughput, raw_ids=[row["id"] for row in measured],
                                cohorts=cohort_specs, static_files=static_files))
    return "".join(sections), coverage, boundaries, chart_specs


def link(output, path, label):
    return f'<a href="{escape(relpath(path, output))}">{escape(label)}</a>'


def render(root, names, output):
    rows, evidence, probes, windows = load(root, names)
    means = summarize(rows)
    output.mkdir(parents=True, exist_ok=True)
    previous_receipt = output / "report-validation.json"
    previous_artifacts = json.loads(previous_receipt.read_text()).get("artifacts", {}) if previous_receipt.exists() else {}
    charts, coverage, boundaries, specifications = figures(output, rows, means)
    if len(coverage) != len(rows) or {row["id"] for row in coverage} != {row["id"] for row in rows}:
        raise ValueError("Every raw case must appear exactly once in plotted or unavailable coverage")
    exports = (("all-runs.csv", rows), ("configuration-means.csv", means), ("frontiers.csv", boundaries),
               ("plot-coverage.csv", coverage), ("probe-records.csv", probes), ("stability-windows.csv", windows))
    for filename, records in exports:
        archive.write_csv(output / filename, records)
    configurations = list({row["configuration"]: row for row in rows}.values())
    config_table = table(["Configuration", "Method", "Family", "Bulk flows", "Bulk ACK format/copies",
        "Probe reverse copies", "Probe interval ms", "Probe timeout ms", "Repair ratio", "Pacing Mbps"],
        [[row["configuration"], row["label"], row["color_label"], profile.get("flow_count"),
          f"{profile.get('ack_record_encoding', 'full')} / {profile.get('ack_copies')}", config.get("reverse_copies"),
          config.get("interval_ms"), config.get("timeout_ms"), profile.get("compact", {}).get("repair_ratio"),
          profile.get("payload_rate_mbps")]
         for row in configurations for profile in [archive.object_value(row["original_profile"])]
         for config in [archive.object_value(row["tcp_syn_probe_config"])]])
    raw_table = table(["Case", "Configuration", "Seed", "Full Mbps", "Concurrent Mbps", "PING P50 ms", "P95 ms", "P99 ms",
        "Completed / offered", "Timeout / censored", "Failure %", "Deadline miss upper %", "Probe start s", "Admission end s",
        "Steady gate", "Windows", "Bulk confirmed", "Probe flushed", "Joint pass", "Exclusion"],
        [[row["case_number"], row["configuration"], str(row["seed"]), row["goodput_mbps"],
          row["tcp_syn_ping_background_goodput_mbps"], row["tcp_syn_ping_p50_ms"], row["tcp_syn_ping_p95_ms"], row[LATENCY],
          f"{display(row['tcp_syn_ping_completed'])} / {display(row['tcp_syn_ping_offered'])}",
          f"{display(row['tcp_syn_ping_timeouts'])} / {display(row['tcp_syn_ping_censored'])}",
          row["tcp_syn_ping_failure_pct"], row["tcp_syn_ping_deadline_miss_upper_pct"], row["tcp_syn_probe_start_s"],
          row["tcp_syn_probe_admission_end_s"], row["tcp_syn_probe_steady_state_reached"], row["stability_window_count"],
          row["fully_confirmed"], row["tcp_syn_probe_all_flushed"], row["joint_target_met"], row["exclusion_reason"]] for row in rows])
    mean_table = table(["Configuration", "Study", "Runs / independent seeds", "Mean full Mbps", "Mean concurrent Mbps",
        "Mean run P99 ms", "95% seed interval for run P99", "Frontier eligible", "Joint passes"],
        [[row["configuration"], row["study"], f"{row['n']} / {row[LATENCY + '_independent_n']}", row["goodput_mbps"],
          row["tcp_syn_ping_background_goodput_mbps"], row[LATENCY],
          f"{display(row[LATENCY + '_low'])} – {display(row[LATENCY + '_high'])}", row["eligible"], row["joint_passes"]] for row in means])
    raw_links = ''.join('<li>' + link(output, root / row["source"],
        f"Case {row['case_number']} · {row['study']} · run {row['run_id']} · exact raw JSON and probe records")
        + f' <code>{row["source_sha256"]}</code></li>' for row in rows)
    source_links = ''.join('<li>' + escape(name) + ' · ' + ' · '.join(
        link(output, root / "tcp-latency" / name / filename, filename)
        for filename in ("experiment.json", "source-verification.json")) + '</li>' for name in names)
    snapshots = output / "report-sources"
    snapshots.mkdir(exist_ok=True)
    report_sources = {}
    for source in (Path(__file__), Path(compact.__file__), Path(compact.aligned.__file__), Path(archive.__file__), Path(stats.__file__)):
        target = snapshots / source.name
        target.write_bytes(source.read_bytes())
        report_sources[target.relative_to(output).as_posix()] = compact.aligned.digest(target)
    families = list({row["color_group"]: row for row in rows}.values())
    legend = ''.join(f'<li><span class="swatch" style="background:{row["color"]}"></span>{escape(row["color_label"])}</li>' for row in families)
    dispatch_counts = defaultdict(int)
    for row in rows:
        dispatch_counts[row["endpoint_dispatch"]] += 1
    dispatch_summary = ", ".join(f"{count} {escape(mode)}" for mode, count in sorted(dispatch_counts.items()))
    conditions = table(["Matched cohort", "Study", "Complete source version", "Recorded runtime",
                        "Endpoint dispatch", "Probe model details", "Probe CPU model"],
        [[row["cohort_label"], row["study"], row["report_source_version"], row["recorded_runtime"],
          row["endpoint_dispatch"], row["probe_model_detail"], row["probe_cpu_model"]]
         for row in {(row["cohort"], row["study"]): row for row in rows}.values()])
    page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Modeled TCP SYN PING under stable bulk load</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f1f5f9;color:#172033;font:15px/1.55 system-ui,sans-serif}}main{{max-width:1500px;margin:auto;padding:22px}}
section,header{{background:white;border:1px solid #dce3ec;border-radius:12px;padding:20px;margin-bottom:18px;min-width:0}}h1{{font-size:29px;line-height:1.2}}h2{{font-size:21px}}
select{{display:block;max-width:100%;width:100%;margin:8px 0;padding:8px}}p,li,code{{overflow-wrap:anywhere}}.chart{{width:100%;min-width:0;overflow:hidden}}.scroll{{max-width:100%;overflow:auto}}table{{border-collapse:collapse;min-width:850px;width:100%;font-size:12px}}th,td{{text-align:left;padding:8px;border-bottom:1px solid #e2e8f0;vertical-align:top}}th{{background:#f8fafc;white-space:nowrap}}a{{color:#1764ab}}.legend{{display:flex;flex-wrap:wrap;gap:14px;list-style:none;padding:0}}.swatch{{display:inline-block;width:13px;height:13px;margin-right:7px;border-radius:3px}}code{{font-size:11px}}@media(max-width:600px){{main{{padding:8px}}section,header{{padding:12px}}h1{{font-size:24px}}h2{{font-size:19px}}}}
</style></head><body><main><header><h1>Modeled TCP SYN PING under stable bulk load</h1>
<p>{len(rows)} saved experiment cases · {len(configurations)} configurations · {sum(row['joint_target_met'] for row in rows)} joint passes.
Each probe models a fresh TCP connection. Timing starts at first SYN submission to L2 and ends at matching SYN-ACK reception, including retries.</p>
<p>Saved-case endpoint metadata includes {dispatch_summary}. Historical campaigns used callback-bound TCP endpoint identity. Received-header campaigns resolve endpoint state from decoded TCP/IP headers. Missing dispatch metadata is labeled unrecorded, and the source table retains each cohort's recorded dispatch, model details and CPU model.</p>
<p>Shared L2 record parsing and FIFO serialization are simulated. Compact FEC recovery uses coefficient/rank equations and materializes recoverable source bytes from the sender ledger. QUIC carries serialized probe records through aioquic. Endpoint dispatch and FEC-model fidelity are part of each result's interpretation.</p><ul class="legend">{legend}</ul></header>{charts}
<details><summary>Metric definitions and matched-comparison source evidence</summary><section><h2>Metric and comparison rules</h2><p>Full bulk goodput uses the complete traffic interval. Concurrent bulk goodput uses the interval from the measured stability gate to bulk-traffic end.
The recorded profile controls probe frequency, timeout and stability tolerances. Admission ends one timeout horizon before bulk load stops. Window diagnostics continue after admission begins.</p>
<p>P50, P95 and P99 use completed probes. Timeout and censored counts retain every admitted probe. Runs with failures, absent metrics, missing stability, incomplete confirmation or unflushed probe traffic are excluded from frontiers and remain visible as open symbols. Cases with unavailable coordinates remain in the coverage table and CSV exports.
The selector displays one matching measurement cohort at a time.</p>
<p>Color identifies protocol family. Small circles show individual runs and diamonds show complete-configuration means. Full method names and complete profiles remain in exports. Dashed lines connect eligible complete-configuration means within matching payload, physical conditions, duration, warmup, drain, complete simulator-package and shared payload-builder versions, recorded Python/NumPy/SciPy/aioquic versions, probe measurement settings, and recorded endpoint-dispatch/CPU/model details. Study-specific executor inventories and all recorded runtime versions appear in the source table.
Reverse-copy count and spacing are transport choices within those comparisons. Exact tied configurations are retained.</p>
<p>Mean P99 is the mean of per-seed run P99 values. Repeated seeds are averaged first. Descriptive 95% Student-t intervals across seed means do not measure uncertainty of a pooled packet percentile.
The joint gate requires both bulk-goodput measures at least 80% of forward capacity, PING P99 at most 1.5 times nominal RTT, deadline-miss upper percentage at most 1%, and full confirmation with no failed or unresolved probes.</p>
<p>Red dotted lines show the PING deadline and green dotted lines show the bulk-goodput target. Probes use timestamp-only TCP headers and an immediate modeled listener. Native TCP sends 52 IP bytes per handshake packet. Shared coding carries 66-byte Ethernet frames in the forward transport and uses the recorded native reverse fallback, costing 102 IP bytes per SYN-ACK copy under the zero-authentication profile. Compact strategies use their configured reliable or native reverse path. QUIC carries probe records on an auxiliary stream of an existing bulk connection, sharing its congestion control, packetization and queues. Each path charges its serialized packets, retransmissions and final ACK/reset traffic. Host scheduling and deployed kernel behavior are outside this model.</p>{conditions}</section></details>
<details><summary>Complete configurations and measurement coverage</summary><section><h2>Configurations</h2>{config_table}</section>
<section><h2>Configuration means</h2>{mean_table}</section><section><h2>Every experiment case and measurement coverage</h2>{raw_table}<ul>{raw_links}</ul></section></details>
<section><h2>Probe records, stability and source audit</h2><p><a href="all-runs.csv">Normalized individual runs</a> · <a href="configuration-means.csv">Configuration means and seed intervals</a> · <a href="frontiers.csv">Matched frontiers</a> · <a href="plot-coverage.csv">Exact plotted-point coverage</a> · <a href="probe-records.csv">Every probe record</a> · <a href="stability-windows.csv">Every stability window</a> · <a href="report-validation.json">Source and coverage receipt</a> · <a href="report-sources/tcp_syn_ping_report.py">Frozen report renderer</a></p>
<p>Raw JSON links retain the exact probe list and stability history. Every executed source snapshot is checked against its manifest digest, and each study must have an unchanged-during-run verification receipt. Renderer snapshots are recorded separately.</p><ul>{source_links}</ul></section></main></body></html>'''
    (output / "report.html").write_text(page)
    artifacts = ["report.html", *[name for name, _ in exports],
                 *[filename for item in specifications for filename in item["static_files"]]]
    receipt = dict(record_kind="derived_tcp_syn_ping_report", saved_runs=len(rows), raw_plot_instances=sum(row["coordinate_kind"] == "measured" for row in coverage),
                   unavailable_coordinate_cases=sum(row["coordinate_kind"] != "measured" for row in coverage),
                   frontier_eligible_runs=sum(row["eligible"] for row in rows), joint_passes=sum(row["joint_target_met"] for row in rows),
                   studies=evidence, raw_inputs={row["source"]: row["source_sha256"] for row in rows},
                   charts=specifications, report_sources=report_sources, color_by="strategy family",
                   probe_records=len(probes), stability_windows=len(windows),
                   endpoint_dispatch_counts=dict(sorted(dispatch_counts.items())),
                   artifacts={name: compact.aligned.digest(output / name) for name in artifacts})
    removed = []
    for filename in sorted(set(previous_artifacts) - set(artifacts)):
        path = output / filename
        if path.parent == output and path.suffix in (".png", ".svg") and path.is_file():
            path.unlink()
            removed.append(filename)
    receipt["obsolete_generated_charts_removed"] = removed
    (output / "report-validation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--studies", nargs="+", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    receipt = render(args.root.resolve(), args.studies, args.out.resolve())
    print(json.dumps({key: receipt[key] for key in ("saved_runs", "raw_plot_instances", "frontier_eligible_runs", "joint_passes")}))


if __name__ == "__main__":
    main()
