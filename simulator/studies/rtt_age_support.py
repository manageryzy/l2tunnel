"""Coding-only age-support screen with fixed arrivals and delayed feedback."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
from heapq import heappop, heappush
from html import escape
import json
from pathlib import Path
import platform
from random import Random
from time import perf_counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim.coding import Decoder
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci, paired_difference
from rtt_checkpoint_repairs import ARRIVAL_MS, SOURCE_MS, REPAIR_MS, write_csv


SEEDS = (20261110, 20261111, 20261112)
METRICS = ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
           "cohort_latency_lower_bound_p99_ms", "mean_repair_support_sources")


def profiles():
    result = [dict(name="Current W128 G16", window=128, lag=0, tiers=[])]
    for window in (64, 128):
        for lag in (16, 32, 64):
            result.append(dict(name=f"Lag{lag} W{window} G16", window=window, lag=lag, tiers=[]))
    result.append(dict(name="Age tiers 0/64/0/128 W64 G16", window=64, lag=0, tiers=[0, 64, 0, 128]))
    return result


def support(profile, next_source, sender_base, repair_serial):
    if repair_serial % 16 == 0:
        return sender_base, next_source
    tiers = profile["tiers"]
    lag = tiers[(repair_serial - 1) % len(tiers)] if tiers else profile["lag"]
    end = max(1, next_source - lag)
    return max(sender_base, end - profile["window"]), end


def execute(task):
    started = perf_counter()
    profile, count = task["profile"], task["source_count"]
    forward_rng, feedback_rng = Random(task["seed"]), Random(task["seed"] ^ 0xFED123)
    decoder = Decoder()
    created_at = np.arange(count, dtype=float) * ARRIVAL_MS
    known_at = np.full(count, np.inf)
    queue_delay = np.zeros(count)
    sender_base, receiver_prefix = 0, 0
    now, last_report = 0., -5.
    pending_feedback = []
    reports, delivered_reports, lost_reports = 0, 0, 0
    credit, repair_serial = 0, 0
    supports, ages = Counter(), Counter()
    erasure_hash, feedback_erasure_hash = sha256(), sha256()
    minimum_feedback_age = np.inf

    def receive_feedback():
        nonlocal sender_base, delivered_reports, minimum_feedback_age
        while pending_feedback and pending_feedback[0][0] <= now:
            due, prefix, generated = heappop(pending_feedback)
            sender_base = max(sender_base, prefix)
            delivered_reports += 1
            minimum_feedback_age = min(minimum_feedback_age, due - generated)

    def receive_equation(equation, finish):
        nonlocal receiver_prefix, last_report, reports, lost_reports
        for symbol in decoder.insert(equation):
            known_at[symbol] = finish
        while receiver_prefix in decoder.known:
            receiver_prefix += 1
        if finish - last_report >= 5:
            last_report = finish
            reports += 1
            erased = feedback_rng.random() < .15
            feedback_erasure_hash.update(bytes([erased]))
            if erased:
                lost_reports += 1
            else:
                heappush(pending_feedback, (finish + 70 + 46 * 8 / 10000, receiver_prefix, finish))

    def erased():
        lost = forward_rng.random() < .15
        erasure_hash.update(bytes([lost]))
        return lost

    for source in range(count):
        now = max(now, created_at[source])
        receive_feedback()
        queue_delay[source] = now - created_at[source]
        now += SOURCE_MS
        if not erased():
            receive_equation({source: 1}, now)
        credit += 26
        while credit >= 125:
            credit -= 125
            receive_feedback()
            repair_serial += 1
            start, end = support(profile, source + 1, sender_base, repair_serial)
            assert 0 <= sender_base <= start < end <= source + 1
            supports[end - start] += 1
            ages[source + 1 - end] += 1
            now += REPAIR_MS
            if not erased():
                packet_seed = repair_serial * 2654435761 & 0xFFFFFFFF
                receive_equation({symbol: coefficient(packet_seed, symbol) for symbol in range(start, end)}, now)
    selected = np.arange(task["warmup_sources"], count - task["tail_sources"])
    delay = known_at[selected] - created_at[selected]
    finite = np.isfinite(delay)
    lower_bounds = np.where(finite, delay, now - created_at[selected])
    assert repair_serial == count * 26 // 125
    assert minimum_feedback_age >= 70
    assert np.all(now - created_at[selected] > 35)
    return dict(task, record_kind="analytic_age_support_case", protocol_executions=0,
                policy=profile["name"], measured_sources=len(selected), repair_packets=repair_serial,
                repair_per_source=repair_serial / count, source_ip_bytes=1496, repair_ip_bytes=1500,
                feedback_ip_bytes=46, forward_total_wire_bytes=count * 1496 + repair_serial * 1500,
                reverse_feedback_packets=reports, reverse_feedback_wire_bytes=reports * 46,
                lost_feedback_packets=lost_reports, delivered_feedback_reports=delivered_reports,
                minimum_feedback_age_ms=minimum_feedback_age, horizon_ms=now,
                ideal_application_service_ceiling_mbps=1448 * 8 / ARRIVAL_MS / 1000,
                coding_deadline_ms=35, deadline_miss_fraction=float(np.mean(delay > 35)),
                deadline_missed_sources=int(np.count_nonzero(delay > 35)),
                unresolved_at_horizon_fraction=float(np.mean(~finite)), unresolved_sources=int(np.count_nonzero(~finite)),
                cohort_latency_lower_bound_p99_ms=float(np.percentile(lower_bounds, 99)),
                cohort_p99_is_lower_bound=bool(np.any(~finite)),
                recovered_only_created_to_known_p99_ms=float(np.percentile(delay[finite], 99)) if finite.any() else None,
                sender_queue_p99_ms=float(np.percentile(queue_delay[selected], 99)),
                maximum_source_queue_ms=float(queue_delay.max()), erasure_trace_sha256=erasure_hash.hexdigest(),
                feedback_erasure_trace_sha256=feedback_erasure_hash.hexdigest(),
                source_arrival_trace_sha256=sha256(created_at.astype("<f8").tobytes()).hexdigest(),
                final_known_sources=len(decoder.known), final_receiver_prefix=receiver_prefix,
                final_sender_confirmed_prefix=sender_base, remaining_decoder_rows=len(decoder.rows),
                mean_repair_support_sources=sum(length * number for length, number in supports.items()) / repair_serial,
                largest_repair_support=max(supports), support_length_histogram=dict(supports),
                support_lag_histogram=dict(ages), compute_seconds=perf_counter() - started)


def summarize(rows):
    summary, paired = [], []
    controls = {row["seed"]: row for row in rows if row["policy"] == "Current W128 G16"}
    for profile in profiles():
        group = sorted([row for row in rows if row["policy"] == profile["name"]], key=lambda row: row["seed"])
        entry = dict(record_kind="analytic_age_support_summary", policy=profile["name"], n=len(group),
                     raw_inputs=[f"cases/{row['analytic_case_id']:03d}.json" for row in group])
        for metric in METRICS:
            stats = mean_ci([row[metric] for row in group])
            entry[metric] = stats["mean"]
            entry[metric + "_ci_low"], entry[metric + "_ci_high"] = stats["ci_low"], stats["ci_high"]
        summary.append(entry)
        if profile["name"] != "Current W128 G16":
            paired.append(dict(record_kind="analytic_age_support_paired", policy=profile["name"],
                metric="deadline_miss_fraction", raw_inputs=entry["raw_inputs"],
                **paired_difference([row["deadline_miss_fraction"] for row in group],
                                    [controls[row["seed"]]["deadline_miss_fraction"] for row in group])))
    return summary, paired


def frontier(rows, metric):
    selected, best, best_cost = [], float("inf"), None
    for row in sorted(rows, key=lambda row: (row[metric], row["deadline_miss_fraction"])):
        if row["deadline_miss_fraction"] < best or (row["deadline_miss_fraction"] == best and row[metric] == best_cost):
            selected.append(row)
            best = row["deadline_miss_fraction"]
            best_cost = row[metric]
    return selected


def render(output, rows, summary, paired):
    axes_metrics = (("mean_repair_support_sources", "Mean repair support (source symbols)"),
                    ("cohort_latency_lower_bound_p99_ms", "Full-cohort coding P99 lower bound (ms)"))
    interactive = make_subplots(rows=1, cols=2, subplot_titles=[title for _, title in axes_metrics])
    figure, axes = plt.subplots(1, 2, figsize=(14, 7))
    figure.subplots_adjust(left=.07, right=.99, bottom=.24, top=.85, wspace=.23)
    palette = ("#1764ab", "#17816a", "#ce761f", "#9159a0", "#b23a48", "#5d7190", "#7b831f", "#b14c89")
    coverage = []
    for column, ((metric, title), axis) in enumerate(zip(axes_metrics, axes), 1):
        for index, mean in enumerate(summary):
            group = [row for row in rows if row["policy"] == mean["policy"]]
            text = [f"Case {row['analytic_case_id']} · {row['policy']}<br>seed {row['seed']}"
                    f"<br>{row['measured_sources']} measured sources · {row['unresolved_sources']} unresolved"
                    f"<br>20.8% repair/source · source/repair 1496/1500 B" for row in group]
            interactive.add_trace(go.Scatter(x=[row[metric] for row in group],
                y=[100 * row["deadline_miss_fraction"] for row in group], mode="markers", name=mean["policy"],
                legendgroup=mean["policy"], showlegend=column == 1, ids=[str(row["analytic_case_id"]) for row in group],
                marker=dict(color=palette[index], size=8, symbol=["x" if row["unresolved_sources"] else "circle" for row in group]),
                text=text, hovertemplate="%{text}<br>X %{x:.3f}<br>35 ms misses %{y:.3f}%<extra></extra>"), row=1, col=column)
            interactive.add_trace(go.Scatter(x=[mean[metric]], y=[100 * mean["deadline_miss_fraction"]],
                mode="markers", showlegend=False, legendgroup=mean["policy"],
                marker=dict(color=palette[index], size=12, symbol="diamond-open"),
                hovertemplate=mean["policy"] + " mean<br>X %{x:.3f}<br>35 ms misses %{y:.3f}%<extra></extra>"), row=1, col=column)
            for row in group:
                axis.scatter(row[metric], 100 * row["deadline_miss_fraction"], color=palette[index],
                             marker="x" if row["unresolved_sources"] else "o", s=26)
                coverage.append(dict(record_kind="analytic_age_support_plot_coverage", analytic_case_id=row["analytic_case_id"],
                                     source=f"cases/{row['analytic_case_id']:03d}.json", metric=metric))
            axis.scatter(mean[metric], 100 * mean["deadline_miss_fraction"], edgecolors=palette[index],
                         facecolors="none", marker="D", s=65, label=mean["policy"])
        edge = frontier(summary, metric)
        interactive.add_trace(go.Scatter(x=[row[metric] for row in edge], y=[100 * row["deadline_miss_fraction"] for row in edge],
                                        mode="lines", showlegend=False, line=dict(color="#333", dash="dash")), row=1, col=column)
        axis.plot([row[metric] for row in edge], [100 * row["deadline_miss_fraction"] for row in edge], "--", color="#333")
        interactive.add_hline(y=1, line_dash="dot", line_color="#777", row=1, col=column)
        interactive.update_xaxes(title_text=title, row=1, col=column)
        interactive.update_yaxes(title_text="All measured sources missing 35 ms deadline (%)", row=1, col=column)
        axis.axhline(1, color="#777", linestyle=":")
        axis.set(xlabel=title, ylabel="All measured sources missing 35 ms deadline (%)")
        axis.grid(alpha=.2)
    figure.suptitle("Coding-only age-support screen · every sampled case\n20.8% repairs · identical arrivals, packet costs and paired erasure traces")
    handles, names = axes[0].get_legend_handles_labels()
    figure.legend(handles, names, loc="lower center", ncol=3, fontsize=9)
    figure.savefig(output / "coding-only-pareto.png", dpi=180)
    plt.close(figure)
    interactive.update_layout(height=620, template="plotly_white", margin=dict(t=90, b=140),
                              legend=dict(orientation="h", y=-.28))
    write_csv(output / "plot-coverage.csv", coverage)
    write_csv(output / "frontiers.csv", [dict(row, frontier_metric=metric) for metric, _ in axes_metrics for row in frontier(summary, metric)])
    table = "".join(f"<tr><td>{escape(row['policy'])}</td><td>{row['n']}</td>"
                    f"<td>{100*row['deadline_miss_fraction']:.3f}</td>"
                    f"<td>{100*row['unresolved_at_horizon_fraction']:.3f}</td>"
                    f"<td>{row['cohort_latency_lower_bound_p99_ms']:.3f}</td>"
                    f"<td>{row['mean_repair_support_sources']:.3f}</td></tr>" for row in summary)
    pairs = "".join(f"<tr><td>{escape(row['policy'])}</td><td>{100*row['mean']:+.3f}</td>"
                    f"<td>[{100*row['ci_low']:+.3f}, {100*row['ci_high']:+.3f}]</td></tr>" for row in paired)
    best = min(summary, key=lambda row: row["deadline_miss_fraction"])
    first = rows[0]
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Age-support coding screen</title>
<style>body{{font:16px/1.5 system-ui;color:#233447;max-width:1450px;margin:30px auto;padding:20px}}table{{border-collapse:collapse;width:100%;font-size:14px}}
td,th{{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}}th{{background:#edf3f8}}a{{color:#146a98}}.notice{{padding:15px;background:#fff2dc}}
.table-scroll,.plot-scroll{{max-width:100%;overflow-x:auto}}.plot-min-width{{min-width:900px}}</style>
<h1>Coding-only age-support screen</h1><p class="notice">All {len(rows)} analytical samples appear in both plots.
Protocol executions are zero. The smallest mean 35 ms miss fraction is {100*best['deadline_miss_fraction']:.3f}%
for {escape(best['policy'])}. Every measured source remains in this denominator.</p>
<p>Each policy uses {len(SEEDS)} paired seeds, {first['source_count']:,} sources, {first['warmup_sources']:,} warmup sources,
{first['measured_sources']:,} measured sources and {first['tail_sources']:,} trailing sources. Costs are fixed at
1496-byte sources and 1500-byte repairs on a 100 Mbps IP link. A 26/125 integer repair credit fixes the
20.8% repair ratio. Exogenous source arrivals are spaced by 0.14464 ms. The ideal one-1448-byte-payload-per-source
service ceiling is {first['ideal_application_service_ceiling_mbps']:.4f} Mbps.</p>
<h2>Causal schedules</h2><p>The control repairs the newest 128 sources. A lagged band ends at
max(1, next_source − lag) and covers up to W preceding sources, clipped by the last received prefix report.
The six bands use lag16/32/64 and W64/128. The age-tier policy cycles W64 bands at ages 0,64,0,128.
Every sixteenth repair in every policy covers the full sender-unconfirmed range through next_source.
The schedule uses source counters and delayed reports. All sources remain available to the algebra and
global repairs. Endpoints advance with the source counter.</p>
<p>The actual GF256 coefficient Decoder identifies individually recoverable symbols. Prefix feedback
is generated after a received forward packet when at least 5 ms has elapsed, costs 46 IP bytes, suffers
15% IID loss and arrives after 70 ms plus 0.0368 ms reverse serialization. The 10 Mbps reverse link carries
feedback alone. Forward erasures, feedback erasures and source creation times are paired across policies.</p>
<h2>Separate analytical Pareto plots</h2><p>Circles are individual seeds, open diamonds are means and
crosses mark unresolved sources at the horizon. Dashed lines show nondominated means, minimizing both
axes. Mean support is an equation-size proxy. The screen does not assign CPU time to it. P99 includes
the full measured cohort, with elapsed-age lower bounds for unresolved sources. The explicit 35 ms
miss fraction includes every unresolved source, all of which have aged past the deadline.</p>
<div class="plot-scroll"><div class="plot-min-width">{interactive.to_html(full_html=False, include_plotlyjs=True)}</div></div><p><a href="coding-only-pareto.png">PNG</a></p>
<div class="table-scroll"><table><tr><th>Policy</th><th>Seeds</th><th>35 ms misses %</th><th>Unresolved %</th><th>Cohort P99 lower bound ms</th><th>Mean support symbols</th></tr>{table}</table></div>
<h2>Paired changes against W128/G16</h2><p>Changes are percentage points in the complete-cohort miss
fraction. Intervals are 95% Student-t intervals over three paired seed differences.</p>
<div class="table-scroll"><table><tr><th>Policy</th><th>Mean change pp</th><th>95% paired interval pp</th></tr>{pairs}</table></div>
<h2>Scope and provenance</h2><p>The 35 ms coding budget grants forward recovery the entire excess over
70 ms base RTT. TCP, reverse TCP ACKs, record/channel ordering, coded payload arithmetic and CPU execution
are excluded. Measured creation-to-known delay includes source queueing and charged serialization.
The service ceiling is an analytical byte budget. Full TCP throughput and all-segment ACK latency require
separate protocol validation. Each source and repair packet stays in the fixed cost denominator.</p>
<p>Source snapshots and the complete task plan were frozen before execution. Every case has its own JSON
file and original analytical case ID. The saved validation checks verify equal arrival and erasure traces,
forward byte totals, cohort sizes and delayed-feedback causality.</p>
<p><a href="analytic-cases.csv">Every sample</a> · <a href="analytic-summary.csv">Means and intervals</a> ·
<a href="paired-differences.csv">Paired comparisons</a> · <a href="plot-coverage.csv">Plot coverage</a> ·
<a href="manifest.json">Frozen plan and hashes</a> · <a href="source-verification.json">Source verification</a> ·
<a href="validation-checks.json">Matched-input checks</a></p></html>"""
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--source-count", type=int, default=20000)
    parser.add_argument("--warmup-sources", type=int, default=2000)
    parser.add_argument("--tail-sources", type=int, default=2000)
    args = parser.parse_args()
    if min(args.warmup_sources, args.tail_sources) < 0 or args.warmup_sources + args.tail_sources >= args.source_count:
        parser.error("measurement cohort must be positive")
    if args.tail_sources * ARRIVAL_MS <= 35:
        parser.error("trailing sources must extend every measured deadline past the horizon")
    tasks = []
    for profile in profiles():
        for seed in SEEDS:
            tasks.append(dict(analytic_case_id=len(tasks) + 1, profile=profile, seed=seed,
                              source_count=args.source_count, warmup_sources=args.warmup_sources,
                              tail_sources=args.tail_sources, forward_mbps=100, reverse_mbps=10,
                              base_rtt_ms=70, loss_rate=.15, loss_model="iid", payload_bytes=1448,
                              configured_repair_ratio=.208, arrival_interval_ms=ARRIVAL_MS))
    root = Path(__file__).resolve().parents[1]
    paths = [Path(__file__).resolve(), root / "studies/rtt_checkpoint_repairs.py",
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest() for path in paths}
    manifest = dict(record_kind="analytic_age_support_manifest", protocol_executions=0, analytic_tasks=tasks,
                    source_snapshots_frozen_before_execution=True, sources=hashes, python=platform.python_version(),
                    numpy=np.__version__,
                    assumptions=["1496-byte sources and 1500-byte repairs at 100 Mbps", "26/125 fixed repair credit",
                                 "0.14464 ms fixed exogenous source arrivals", "15% IID forward and feedback loss",
                                 "70 ms delayed-prefix feedback plus 46-byte serialization at 10 Mbps",
                                 "Actual GF256 coefficient Decoder, full measured cohort, 35 ms coding deadline",
                                 "TCP, reverse TCP ACK traffic, channel record ordering and CPU are excluded"])
    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / "manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing task plan or frozen source hashes differ")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in paths:
        snapshot = args.out / "sources" / path.relative_to(root)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(path.read_bytes())
    cases = args.out / "cases"
    cases.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (cases / f"{task['analytic_case_id']:03d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            path = cases / f"{row['analytic_case_id']:03d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
            temporary.replace(path)
            print(f"Saved {row['analytic_case_id']:02d} {row['policy']} misses={100*row['deadline_miss_fraction']:.3f}% "
                  f"unresolved={row['unresolved_sources']}", flush=True)
    rows = [json.loads((cases / f"{task['analytic_case_id']:03d}.json").read_text()) for task in tasks]
    for seed in SEEDS:
        group = [row for row in rows if row["seed"] == seed]
        for key in ("source_arrival_trace_sha256", "erasure_trace_sha256", "feedback_erasure_trace_sha256",
                    "forward_total_wire_bytes", "reverse_feedback_wire_bytes", "measured_sources", "horizon_ms"):
            assert len({row[key] for row in group}) == 1, key
    summary, paired = summarize(rows)
    write_csv(args.out / "analytic-cases.csv", rows)
    write_csv(args.out / "analytic-summary.csv", summary)
    write_csv(args.out / "paired-differences.csv", paired)
    changed = [name for name, value in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != value]
    (args.out / "source-verification.json").write_text(json.dumps(dict(changed_during_run=changed), indent=2) + "\n")
    if changed:
        raise ValueError("a frozen source changed during execution")
    checks = dict(record_kind="analytic_age_support_validation", protocol_executions=0,
                  paired_arrivals_and_erasure_traces=True, equal_forward_and_feedback_byte_budgets=True,
                  equal_full_measurement_cohorts=True, feedback_delay_at_least_70ms=True,
                  unresolved_sources_retained=True, planned_cases=len(tasks), saved_cases=len(rows),
                  plotted_raw_points=2 * len(rows),
                  raw_sha256={path.relative_to(args.out).as_posix(): sha256(path.read_bytes()).hexdigest()
                              for path in sorted(cases.glob("*.json"))})
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    render(args.out, rows, summary, paired)
    print(f"Completed {len(rows)} analytical cases, zero protocol executions", flush=True)


if __name__ == "__main__":
    main()
