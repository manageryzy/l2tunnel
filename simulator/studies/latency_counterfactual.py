"""Analyze fixed recorded TCP trajectories without executing a protocol.

Every original segment is retained. Counterfactual clocks are optimistic
arithmetic relaxations of the recorded event times. The source run's measured
goodput is a reference coordinate, and changing FEC invalidates these bounds.
"""

import argparse
from collections import defaultdict
import csv
from hashlib import sha256
from html import escape
import json
from math import isfinite
from os.path import relpath
from pathlib import Path
import platform

import numpy as np
import plotly.graph_objects as go

from l2tunnel_sim.stats import mean_ci


CASES = {
    "observed": ("Observed cumulative ACK", "1000 × (ACK completion − original submission)",
                 "The original measured cumulative ACK completion time."),
    "zero_source_queue": ("Subtract source queue and serialization", "observed − source queue and serialization",
                          "Remove the whole recorded source queue and serialization stage while keeping all other recorded delays fixed."),
    "ideal_reverse": ("Immediate ACK and ideal reverse", "1000 × (TCP delivery − submission) + RTT/2",
                      "Keep recorded contiguous TCP delivery. Generate an ACK immediately and remove reverse serialization, queueing, loss, delayed ACK and coalescing waits."),
    "tcp_prefix": ("Free context with TCP prefix and ideal reverse", "1000 × (max ready time through this TCP segment − submission) + RTT/2",
                   "Assume each recorded data body is independently usable when its bytes are ready. Remove codec context dependencies, retain the per-flow TCP receive prefix, and use the ideal reverse path."),
    "own_ready": ("Own bytes ready and ideal reverse", "1000 × (own record ready − submission) + RTT/2",
                  "Also remove all channel and TCP ordering dependencies. Every segment can be acknowledged independently when its recorded body bytes are ready."),
    "own_ready_zero_queue": ("Own bytes ready, zero queue and ideal reverse", "own bytes ready and ideal reverse − source queue and serialization",
                             "Also subtract the entire recorded source queue and serialization stage. Later coding events and every original submission time remain frozen."),
}
PROBE_RUNS = (2, 4, 6)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def counterfactual_rows(rows, rtt_ms):
    """Return every original row with six clocks, rejecting incomplete input."""
    result = []
    next_segment = defaultdict(int)
    prefix_ready = defaultdict(float)
    for original in rows:
        row = dict(original)
        flow, segment = int(row["flow_id"]), int(row["segment_id"])
        if segment != next_segment[flow]:
            raise ValueError("each flow must contain every segment exactly once in sequence")
        next_segment[flow] += 1
        required = ("original_submission_s", "record_ready_s", "tcp_contiguous_delivery_s",
                    "cumulative_ack_completion_s", "source_queue_and_serialization_ms")
        try:
            sent, ready, delivered, acknowledged, queue = (float(row[key]) for key in required)
        except (KeyError, ValueError, TypeError) as error:
            raise ValueError("every original segment needs complete recorded stage times") from error
        if not all(isfinite(value) for value in (sent, ready, delivered, acknowledged, queue)):
            raise ValueError("stage times must be finite")
        if not sent <= ready <= delivered <= acknowledged or queue < 0:
            raise ValueError("recorded stages must be causal and queue cost nonnegative")
        prefix_ready[flow] = max(prefix_ready[flow], ready)
        values = {
            "observed": (acknowledged - sent) * 1000,
            "zero_source_queue": (acknowledged - sent) * 1000 - queue,
            "ideal_reverse": (delivered - sent) * 1000 + rtt_ms / 2,
            "tcp_prefix": (prefix_ready[flow] - sent) * 1000 + rtt_ms / 2,
            "own_ready": (ready - sent) * 1000 + rtt_ms / 2,
            "own_ready_zero_queue": (ready - sent) * 1000 + rtt_ms / 2 - queue,
        }
        if any(value < -1e-7 or value > values["observed"] + 1e-7 for value in values.values()):
            raise ValueError("a relaxed clock must be nonnegative and no later than observation")
        if values["own_ready"] > values["tcp_prefix"] + 1e-7 or values["tcp_prefix"] > values["ideal_reverse"] + 1e-7:
            raise ValueError("relaxed readiness must respect the original TCP receive prefix")
        row.update({case + "_latency_ms": value for case, value in values.items()})
        result.append(row)
    if not result:
        raise ValueError("an empty trace has no analytical cohort")
    return result


def latency_summary(values, budget_ms):
    values = np.asarray(values, dtype=float)
    return dict(segment_count=int(values.size),
                **{f"latency_p{level}_ms": float(np.percentile(values, level)) for level in (50, 95, 99)},
                deadline_miss_count=int(np.count_nonzero(values > budget_ms)),
                deadline_miss_fraction=float(np.mean(values > budget_ms)))


def eligible_frontier(points):
    """Minimize latency and maximize reference goodput within one assumption."""
    result = []
    for point in points:
        if not point["analytical_eligible"]:
            continue
        peers = [other for other in points if other["analytical_eligible"]
                 and other["case_id"] == point["case_id"] and other["cohort"] == point["cohort"]]
        dominated = any(other["latency_p99_ms"] <= point["latency_p99_ms"]
                        and other["source_measured_app_mbps"] >= point["source_measured_app_mbps"]
                        and (other["latency_p99_ms"] < point["latency_p99_ms"]
                             or other["source_measured_app_mbps"] > point["source_measured_app_mbps"])
                        for other in peers)
        if not dominated:
            result.append(point)
    return result


def write_csv(path, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def validate_source(source):
    manifest = json.loads((source / "experiment.json").read_text())
    pairs = json.loads((source / "paired-equivalence.json").read_text())
    files = [source / name for name in ("experiment.json", "paired-equivalence.json", "source-verification.json")]
    if json.loads(files[-1].read_text())["changed_during_run"]:
        raise ValueError("source study reports changed runtime code")
    snapshot_checks = []
    for name, expected in manifest["sources"].items():
        path = source / "sources" / name
        if digest(path) != expected:
            raise ValueError(f"frozen source hash mismatch for {name}")
        files.append(path)
        current = Path(__file__).resolve().parents[1] / name
        snapshot_checks.append(dict(path=name, sha256=expected, snapshot_matches=True,
                                    current_checkout_matches=current.exists() and digest(current) == expected))
    verified_pairs = []
    for run_id in PROBE_RUNS:
        pair = next(pair for pair in pairs if pair["probe_run"] == run_id)
        if pair["differing_metrics"] or not pair["identical_events_and_state"]:
            raise ValueError("instrumented run is not equivalent to its paired control")
        control_path = source / "runs" / f"{pair['control_run']:05d}.json"
        probe_path = source / "runs" / f"{run_id:05d}.json"
        control, probe = (json.loads(path.read_text()) for path in (control_path, probe_path))
        ignored = {"run_id", "stage_instrumentation", "compute_seconds"}
        if ({key: value for key, value in control.items() if key not in ignored}
                != {key: value for key, value in probe.items() if key not in ignored}):
            raise ValueError("paired metrics differ")
        events = [source / "events" / f"{index:05d}.json" for index in (pair["control_run"], run_id)]
        first, second = (json.loads(path.read_text()) for path in events)
        if first != second or any(pair[key] != value for key, value in first.items()):
            raise ValueError("paired event and state hashes differ")
        task = next(task for task in manifest["tasks"] if task["run_id"] == run_id)
        expected = dict(forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15,
                        loss_model="iid", mtu=1500, payload_bytes=1448, duration_s=10,
                        drain_s=20, warmup_s=2)
        if any(task[key] != value for key, value in expected.items()):
            raise ValueError("this report describes the fixed 10-second aligned stage cohort")
        profile = task["profile"]
        if (profile["flow_count"] != 64 or profile["ack_copies"] != 3
                or profile["compact"]["repair_ratio"] != .208
                or profile["compact"]["repair_window_sources"] != 128
                or profile["compact"]["global_repair_every"] != 16
                or not profile["compact"]["elide_payload_length"]):
            raise ValueError("source transport differs from the report's fixed profile")
        if not task["stage_instrumentation"] or pair["seed"] != task["seed"] or probe["seed"] != pair["seed"]:
            raise ValueError("probe seed or task pairing differs")
        files.extend([control_path, probe_path, *events,
                      source / "stages" / f"{run_id:05d}-segments.csv",
                      source / "stages" / f"{run_id:05d}-sources.csv"])
        verified_pairs.append(pair)
    if len({pair["seed"] for pair in verified_pairs}) != len(PROBE_RUNS):
        raise ValueError("independent probe runs must use distinct seeds")
    return manifest, verified_pairs, snapshot_checks, {path: digest(path) for path in files}


def make_plots(output, points, frontier):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = ("#26364d", "#87929e", "#2166ac", "#35978f", "#d27516", "#8d4a8b")
    figure = go.Figure()
    static, axes = plt.subplots(2, 3, figsize=(14, 8), sharex=True, sharey=True)
    for index, (case, (label, _, _)) in enumerate(CASES.items()):
        group = [point for point in points if point["case_id"] == case]
        boundary = sorted((point for point in frontier if point["case_id"] == case), key=lambda row: row["latency_p99_ms"])
        hover = [[f"P{row['source_run_id']}", str(row["seed"]), row["segment_count"],
                  100 * row["deadline_miss_fraction"], row["on_analytical_frontier"]] for row in group]
        figure.add_trace(go.Scatter(x=[row["latency_p99_ms"] for row in group],
            y=[row["source_measured_app_mbps"] for row in group], mode="markers", name=label,
            legendgroup=case, marker=dict(size=11 + 2 * (index % 2), color=colors[index],
            symbol=("circle", "square", "circle-open", "x", "diamond", "triangle-up")[index]),
            customdata=hover, hovertemplate=("%{fullData.name}<br>Source %{customdata[0]}, seed %{customdata[1]}"
            "<br>P99 %{x:.3f} ms<br>Source measured goodput %{y:.5f} Mbps<br>Segments %{customdata[2]}"
            "<br>Deadline misses %{customdata[3]:.4f}%<br>Analytical frontier %{customdata[4]}<extra></extra>")))
        figure.add_trace(go.Scatter(x=[row["latency_p99_ms"] for row in boundary],
            y=[row["source_measured_app_mbps"] for row in boundary], mode="lines", name=label + " frontier",
            legendgroup=case, showlegend=False, line=dict(color=colors[index], width=1, dash="dot"), hoverinfo="skip"))
        axis = axes.flat[index]
        axis.scatter([row["latency_p99_ms"] for row in group], [row["source_measured_app_mbps"] for row in group], color=colors[index])
        axis.plot([row["latency_p99_ms"] for row in boundary], [row["source_measured_app_mbps"] for row in boundary], linestyle=":", color=colors[index])
        for row in group:
            axis.annotate(f"P{row['source_run_id']}", (row["latency_p99_ms"], row["source_measured_app_mbps"]), xytext=(5, 5), textcoords="offset points", fontsize=8)
        axis.axvline(105, color="#af3348", linestyle="--", linewidth=.8)
        axis.axhline(80, color="#af3348", linestyle="--", linewidth=.8)
        axis.set_title(label.replace(" and ", "\nand "), fontsize=10)
        axis.grid(alpha=.2)
        axis.set(xlim=(100, 163), ylim=(79.68, 80.02))
    static.supxlabel("Fixed-trajectory cumulative ACK P99 or optimistic clock (ms)")
    static.supylabel("Original source run's measured application goodput (Mbps)")
    static.suptitle("All 18 analytical points · three independent recorded seeds\nDotted frontiers compare identical assumptions. Goodput is held at its source observation.", fontsize=12)
    static.tight_layout(rect=(.02, .02, 1, .91))
    static.savefig(output / "analytical-pareto.png", dpi=160)
    plt.close(static)
    figure.add_vline(x=105, line_dash="dash", line_color="#af3348")
    figure.add_hline(y=80, line_dash="dash", line_color="#af3348")
    figure.update_layout(title=dict(text="Every recorded seed under each analytical assumption"),
        xaxis=dict(title=dict(text="Fixed-trajectory P99 latency (ms)"), range=[100, 163]),
        yaxis=dict(title=dict(text="Source measured application goodput (Mbps)"), range=[79.68, 80.02]),
        template="plotly_white", height=640, margin=dict(l=75, r=20, t=75, b=180),
        legend=dict(orientation="h", y=-.22, maxheight=.25, groupclick="togglegroup"))
    return figure.to_html(full_html=False, include_plotlyjs=True, config=dict(responsive=True, displaylogo=False))


def report(output, source, points, aggregates, provenance, plot):
    source_link = Path(relpath(source, output)).as_posix()
    assumptions = "".join(f"<tr><td>{escape(label)}</td><td><code>{escape(formula)}</code></td><td>{escape(scope)}</td></tr>"
                          for label, formula, scope in CASES.values())
    table = "".join(f"<tr><td>{escape(row['label'])}</td><td>{row['segment_count']:,}</td>"
        f"<td>{row['latency_p99_ms']:.3f}</td><td>{row['deadline_miss_count']:,}</td>"
        f"<td>{100*row['deadline_miss_fraction']:.4f}%</td><td>{row['seed_p99_mean_ms']:.3f} "
        f"[{row['seed_p99_ci_low_ms']:.3f}, {row['seed_p99_ci_high_ms']:.3f}]</td></tr>" for row in aggregates)
    rows = "".join(f"<tr><td>P{row['source_run_id']}</td><td>{escape(row['label'])}</td>"
        f"<td>{row['segment_count']:,}</td><td>{row['source_measured_app_mbps']:.5f}</td>"
        f"<td>{row['latency_p99_ms']:.3f}</td><td>{100*row['deadline_miss_fraction']:.4f}%</td>"
        f"<td>{'Yes' if row['analytical_eligible'] else 'No'}</td><td>{'Yes' if row['on_analytical_frontier'] else 'No'}</td></tr>" for row in points)
    sources = "".join(f'<li>P{run_id} · <a href="{source_link}/runs/{run_id:05d}.json">Original run</a> · '
        f'<a href="{source_link}/stages/{run_id:05d}-segments.csv">Original segments</a> · '
        f'<a href="segments/{run_id:05d}.csv">Every segment with all six analytical clocks</a></li>' for run_id in PROBE_RUNS)
    page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fixed-trajectory TCP latency limits</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f4f7fa;color:#203246;font:16px/1.55 system-ui}}main{{max-width:1200px;margin:auto;padding:30px 24px;overflow-wrap:anywhere}}h1{{font-size:clamp(1.7rem,4vw,2.4rem);line-height:1.2}}h2{{line-height:1.25}}.card{{background:white;border:1px solid #d6e0e9;border-radius:8px;padding:22px;margin:20px 0}}.scope{{border-left:5px solid #a95c18}}.scroll{{max-width:100%;overflow-x:auto}}table{{width:100%;min-width:820px;border-collapse:collapse;font-size:14px}}td,th{{padding:9px;text-align:left;border-bottom:1px solid #dce3e9}}th{{background:#eef3f7}}img{{max-width:100%;height:auto}}code{{white-space:normal;overflow-wrap:anywhere}}a{{color:#165f92}}.plot{{max-width:100%;overflow:hidden}}.small{{font-size:14px}}@media(max-width:600px){{main{{padding:16px 10px}}.card{{padding:14px}}}}
</style></head><body><main><h1>Fixed-trajectory TCP latency limits</h1>
<div class="card scope"><p><strong>Analytical postprocessing · zero protocol executions.</strong> The bounds apply to the recorded original submissions, source-byte recovery times and TCP flow membership. Changing FEC, packet scheduling or admission can change those times and invalidates direct use of this frozen-trajectory bound. Every original segment remains in every denominator.</p>
<p>The three independent 10-second pilots have a 20-second drain, 64 TCP flows, 1448-byte application payloads, 100/10 Mbps IP service rates, 70 ms RTT and 15% IID loss. Their aligned-record transport uses payload-length elision, repair ratio 20.8%, W128/G16 and three ACK copies. All {aggregates[0]['segment_count']:,} original segments are confirmed after drain. Their measured full-interval goodput is 79.713–79.794 Mbps.</p>
<p>Removing ACK-policy and reverse-link waiting leaves pooled P99 at {aggregates[2]['latency_p99_ms']:.3f} ms. Even removing every ordering dependency and the full source queue/serialization contribution leaves {aggregates[5]['deadline_miss_count']:,} segments ({100*aggregates[5]['deadline_miss_fraction']:.4f}%) above 105 ms. These arithmetic relaxations quantify the remaining delay on these saved trajectories.</p></div>
<div class="card"><h2>Every per-seed analytical point</h2><p>The vertical coordinate is the original run's measured application goodput. It is held fixed as a reference and carries no prediction of throughput under a changed policy. All 18 points are retained. Coincident coordinates can overlap in the interactive view. Toggle a legend entry to inspect its assumption separately, or use the six-panel figure below.</p>
<p>Dotted Pareto frontiers minimize P99 and maximize reference goodput only within the same assumption, scenario, duration and frozen source version. Eligibility requires a fully confirmed source run, complete finite segment clocks, verified seed pairing and matching frozen hashes. This frontier describes analytical coordinates, with zero protocol candidates added.</p><div class="plot">{plot}</div>
<a href="analytical-pareto.png"><img src="analytical-pareto.png" alt="Six panels retain all three per-seed points for each fixed-trajectory assumption"></a></div>
<div class="card"><h2>Transparent assumptions</h2><p>All clocks start at the original TCP submission. The ideal reverse path contributes exactly 35 ms, with zero ACK-generation wait, loss, packet cost, serialization or queueing. Original wire costs remain available in each source result. Those costs are unchanged reference observations, while the idealized clocks grant free removal of selected costs.</p>
<p>Record readiness is the saved readiness of the first record actually delivered for that segment. The TCP-prefix relaxation uses the maximum readiness through that segment in the same original flow. Relaxing codec context and TCP ordering grants additional receiver abilities solely for this analysis. Subtracting source queue and serialization grants a zero-time stage while leaving recorded downstream recovery fixed. This is arithmetic sensitivity under frozen downstream event times.</p>
<div class="scroll" tabindex="0" role="region" aria-label="Assumptions and equations"><table><thead><tr><th>Case</th><th>Equation in milliseconds</th><th>Assumptions</th></tr></thead><tbody>{assumptions}</tbody></table></div></div>
<div class="card"><h2>Aggregate statistics</h2><p>Pooled quantiles weight every original segment equally. The last column separately summarizes three per-seed P99 values with a 95% Student-t interval. The three seeds are the replication units. Instrumented and control runs are paired equivalents and contribute one trace per seed.</p><div class="scroll" tabindex="0" role="region" aria-label="Pooled statistics"><table><thead><tr><th>Case</th><th>Segments</th><th>Pooled P99 ms</th><th>Misses</th><th>Miss fraction</th><th>Mean seed P99 ms [95% CI]</th></tr></thead><tbody>{table}</tbody></table></div></div>
<div class="card"><h2>All 18 points and eligibility</h2><div class="scroll" tabindex="0" role="region" aria-label="Every analytical point"><table><thead><tr><th>Source</th><th>Case</th><th>Segments</th><th>Source Mbps</th><th>P99 ms</th><th>Miss fraction</th><th>Eligible</th><th>Frontier</th></tr></thead><tbody>{rows}</tbody></table></div></div>
<div class="card"><h2>Provenance and reproducibility</h2><ul>{sources}</ul>
<p><a href="analytical-points.csv">Every analytical point CSV</a> · <a href="analytical-frontier.csv">Eligible frontier CSV</a> · <a href="aggregate-statistics.csv">Aggregate CSV</a> · <a href="analysis.json">Machine-readable analysis</a> · <a href="provenance.json">Source and snapshot SHA256 receipts</a> · <a href="validation.json">Validation receipt</a> · <a href="latency_counterfactual.py">Frozen analysis script</a> · <a href="{source_link}/paired-equivalence.json">Original paired equivalence receipt</a></p>
<p class="small">Analysis script SHA256 <code>{provenance['analysis_script_sha256']}</code>. Reproduce from the repository root with <code>/tmp/l2tunnel-quic-venv/bin/python simulator/studies/latency_counterfactual.py --source work/results-20261110/tcp-latency/aligned-latency-stages --out work/results-20261110/tcp-latency/latency-counterfactual</code>.</p></div></main></body></html>'''
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.out.resolve()
    manifest, pairs, snapshots, input_hashes = validate_source(source)
    output.mkdir(parents=True, exist_ok=True)
    (output / "segments").mkdir(exist_ok=True)
    points, aggregates, retained, all_values = [], [], [], defaultdict(list)
    cohort_fields = ("forward_mbps", "reverse_mbps", "rtt_ms", "loss_rate", "loss_model", "mtu",
                     "payload_bytes", "duration_s", "drain_s", "warmup_s", "profile")
    for run_id in PROBE_RUNS:
        task = next(task for task in manifest["tasks"] if task["run_id"] == run_id)
        original = json.loads((source / "runs" / f"{run_id:05d}.json").read_text())
        if not original["fully_confirmed"]:
            raise ValueError("the fixed complete-cohort analysis requires final confirmation")
        if not isfinite(original["application_goodput_mbps"]):
            raise ValueError("the source goodput coordinate must be finite")
        with (source / "stages" / f"{run_id:05d}-segments.csv").open() as handle:
            raw = list(csv.DictReader(handle))
        rows = counterfactual_rows(raw, task["rtt_ms"])
        if len(rows) != original["offered_frames"]:
            raise ValueError("every original submission must be retained")
        if any(row["end_ack_censored"] != "False" or row["end_delivery_censored"] != "False" for row in rows):
            raise ValueError("the source cohort contains censored segments")
        if any(not 0 <= float(row["original_submission_s"]) < task["duration_s"] for row in rows):
            raise ValueError("original segment lies outside the traffic submission interval")
        with (source / "stages" / f"{run_id:05d}-sources.csv").open() as handle:
            source_rows = list(csv.DictReader(handle))
        if len(source_rows) != original["shared_source_count"] or sum(int(row["protected_bytes"]) for row in source_rows) != original["shared_submitted_bytes"]:
            raise ValueError("source-symbol counts or bytes disagree with the original run")
        cohort = sha256(json.dumps(dict(scenario={key: task[key] for key in cohort_fields},
                                        sources=manifest["sources"]), sort_keys=True).encode()).hexdigest()
        for row in rows:
            row.update(record_kind="analytic_segment_counterfactual", source_run_id=run_id, seed=task["seed"])
        write_csv(output / "segments" / f"{run_id:05d}.csv", rows)
        retained.append(dict(source_run_id=run_id, seed=task["seed"], original_segments=len(raw), retained_segments=len(rows),
                             source_symbols=len(source_rows), final_censored_segments=0))
        for case, (label, _, _) in CASES.items():
            values = [row[case + "_latency_ms"] for row in rows]
            all_values[case].extend(values)
            summary = latency_summary(values, original["latency_budget_ms"])
            if case == "observed" and not np.isclose(summary["latency_p99_ms"], original["with_drain_tcp_all_segment_ack_rtt_p99_ms"], atol=1e-8, rtol=0):
                raise ValueError("recomputed observed P99 differs from the source run")
            points.append(dict(record_kind="analytic_latency_counterfactual", source_run_id=run_id, seed=task["seed"],
                case_id=case, label=label, cohort=cohort, source_measured_app_mbps=original["application_goodput_mbps"],
                source_fully_confirmed=original["fully_confirmed"], analytical_eligible=True,
                payload_bytes=task["payload_bytes"], rtt_ms=task["rtt_ms"], duration_s=task["duration_s"],
                drain_s=task["drain_s"], latency_budget_ms=original["latency_budget_ms"], **summary))
    frontier = eligible_frontier(points)
    for point in points:
        point["on_analytical_frontier"] = point in frontier
    for case, (label, _, _) in CASES.items():
        confidence = mean_ci([point["latency_p99_ms"] for point in points if point["case_id"] == case])
        aggregates.append(dict(record_kind="analytic_latency_aggregate", case_id=case, label=label,
            **latency_summary(all_values[case], points[0]["latency_budget_ms"]), independent_seeds=confidence["n"],
            seed_p99_mean_ms=confidence["mean"], seed_p99_ci_low_ms=confidence["ci_low"], seed_p99_ci_high_ms=confidence["ci_high"]))
    script = Path(__file__).resolve()
    stats_source = Path(__file__).resolve().parents[1] / "src/l2tunnel_sim/stats.py"
    provenance = dict(record_kind="analytical_source_provenance", analysis_script_sha256=digest(script),
        stats_helper_sha256=digest(stats_source), python_version=platform.python_version(), numpy_version=np.__version__,
        source_study=str(source), pairs=pairs, frozen_snapshot_checks=snapshots,
        input_sha256={str(path.relative_to(source)): value for path, value in input_hashes.items()})
    (output / "latency_counterfactual.py").write_bytes(script.read_bytes())
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    write_csv(output / "analytical-points.csv", points)
    write_csv(output / "analytical-frontier.csv", frontier)
    write_csv(output / "aggregate-statistics.csv", aggregates)
    analysis = dict(record_kind="fixed_trajectory_analytical_study", protocol_executions_added=0,
                    source_runs=list(PROBE_RUNS), cases=CASES, points=points, aggregates=aggregates,
                    frontier_definition="Separate within-case frontiers require matching frozen conditions and confirmed complete source cohorts.")
    (output / "analysis.json").write_text(json.dumps(analysis, indent=2) + "\n")
    plot = make_plots(output, points, frontier)
    report(output, source, points, aggregates, provenance, plot)
    if any(digest(path) != expected for path, expected in input_hashes.items()):
        raise ValueError("source evidence changed during analysis")
    validation = dict(record_kind="analytical_validation_receipt", protocol_executions_added=0,
        per_seed_retention=retained, independent_seeds=len(pairs), analytical_points=len(points),
        eligible_analytical_points=sum(point["analytical_eligible"] for point in points), frontier_points=len(frontier),
        all_original_columns_retained=True, every_counterfactual_at_most_observed_per_segment=True,
        source_inputs_unchanged=True, paired_events_and_metrics_identical=True,
        frozen_source_snapshots_verified=len(snapshots), observed_p99_matches_original=True,
        analysis_script_sha256=digest(script), frozen_script_matches=digest(output / "latency_counterfactual.py") == digest(script),
        artifact_sha256={str(path.relative_to(output)): digest(path) for path in sorted(output.rglob("*")) if path.is_file() and path.name != "validation.json"})
    (output / "validation.json").write_text(json.dumps(validation, indent=2) + "\n")
    print(json.dumps({key: validation[key] for key in ("independent_seeds", "analytical_points", "frontier_points", "frozen_source_snapshots_verified", "protocol_executions_added")}, indent=2))


if __name__ == "__main__":
    main()
