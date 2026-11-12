"""Screen repeated-coefficient rolling repairs under a fixed causal wire budget."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
from html import escape
import json
from pathlib import Path
from unittest.mock import patch

import plotly.graph_objects as go
from plotly.subplots import make_subplots

import rtt_checkpoint_repairs as reference
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci


SERIAL_MULTIPLIER = 2654435761
SERIAL_INVERSE = pow(SERIAL_MULTIPLIER, -1, 1 << 32)
PROFILES = [dict(name="Fresh dense W128 G16", lanes=0, window=128, checkpoint=0, burst=False),
            *[dict(name=f"Accumulator L{lanes} W{window} G16", lanes=lanes, window=window,
                   checkpoint=0, burst=False)
              for lanes, window in ((1, 128), (3, 128), (7, 128), (15, 128), (7, 256))]]


def repair_coefficient(profile, packet_seed, source):
    serial = packet_seed * SERIAL_INVERSE & 0xffffffff
    if not profile["lanes"] or serial % 16 == 0:
        return coefficient(packet_seed, source)
    lane = serial % profile["lanes"]
    return coefficient(0xA5B30000 + lane, source)


def repair_support(profile, next_source, sender_base, serial, final=False):
    if serial % 16 == 0:
        return sender_base, next_source
    return max(sender_base, next_source - profile["window"]), next_source


def execute(task):
    def repeated_coefficient(packet_seed, source):
        return repair_coefficient(task["profile"], packet_seed, source)

    with patch.object(reference, "support", repair_support), patch.object(reference, "coefficient", repeated_coefficient):
        row = reference.execute(task)
    row.update(record_kind="analytic_rolling_accumulator_case", protocol_executions=0,
               payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
               base_rtt_ms=70, loss_rate=.15, loss_model="iid")
    return row


def summarize(rows):
    summaries = []
    for profile in PROFILES:
        selected = [row for row in rows if row["policy"] == profile["name"]]
        summary = dict(policy=profile["name"], cases=len(selected))
        for metric in ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
                       "recovered_only_created_to_known_p99_ms"):
            stats = mean_ci([row[metric] for row in selected])
            summary[metric] = stats["mean"]
            summary[metric + "_ci_low"] = stats["ci_low"]
            summary[metric + "_ci_high"] = stats["ci_high"]
        summaries.append(summary)
    return summaries


def render(output, rows, summaries):
    figure = make_subplots(rows=1, cols=2, subplot_titles=("35 ms source deadline", "Conditional source P99"))
    axes = ((1, "deadline_miss_fraction", 100, "Original-source deadline misses (%)"),
            (2, "recovered_only_created_to_known_p99_ms", 1, "Recovered-only source P99 (ms)"))
    colors = ("#1764ab", "#d16b25", "#16816a", "#9751b5", "#a34255", "#557f16")
    for index, profile in enumerate(PROFILES):
        selected = [row for row in rows if row["policy"] == profile["name"]]
        for column, metric, scale, title in axes:
            figure.add_trace(go.Scatter(
                x=[row[metric] * scale for row in selected],
                y=[row["ideal_application_service_ceiling_mbps"] for row in selected],
                ids=[str(row["analytic_case_id"]) for row in selected],
                customdata=[[row["analytic_case_id"], row["seed"],
                             100 * row["unresolved_at_horizon_fraction"]] for row in selected],
                meta=dict(kind="raw-case"), mode="markers", name=profile["name"],
                marker=dict(color=colors[index], size=9), legendgroup=profile["name"], showlegend=column == 1,
                hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}<br>Cost %{x:.5g}"
                              "<br>Service ceiling %{y:.6g} Mbps<br>Unresolved %{customdata[2]:.4g}%<extra>%{fullData.name}</extra>"),
                row=1, col=column)
            figure.update_xaxes(title_text=title, row=1, col=column)
            figure.update_yaxes(title_text="Optimistic application service ceiling (Mbps)", row=1, col=column)
    complete = [row for row in summaries if row["unresolved_at_horizon_fraction"] == 0]
    for column, metric, scale, title in axes:
        if complete:
            best = min(complete, key=lambda row: row[metric])
            figure.add_trace(go.Scatter(
                x=[best[metric] * scale], y=[rows[0]["ideal_application_service_ceiling_mbps"]],
                text=[best["policy"]], mode="markers", marker=dict(symbol="star-open", color="#172b3a", size=15),
                name="Empirical mean frontier", legendgroup="frontier", showlegend=column == 1,
                hovertemplate="%{text}<br>Fully recovered cohort mean<extra></extra>"), row=1, col=column)
    figure.add_vline(x=1, line_dash="dash", line_color="#a34444", row=1, col=1)
    figure.update_layout(height=560, margin=dict(l=65, r=35, t=65, b=130),
                         legend=dict(orientation="h", y=-.25, x=0), template="plotly_white")
    table = "".join(
        f'<tr><td>{escape(row["policy"])}</td><td>{row["cases"]}</td>'
        f'<td>{100 * row["deadline_miss_fraction"]:.4f}%</td>'
        f'<td>{100 * row["unresolved_at_horizon_fraction"]:.4f}%</td>'
        f'<td>{row["recovered_only_created_to_known_p99_ms"]:.3f}</td></tr>' for row in summaries)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rolling-accumulator repair screen</title><style>
body{max-width:1250px;margin:25px auto;padding:18px;font:16px/1.5 system-ui;color:#213547}
.scroll{max-width:100%;overflow:auto}.chart{min-width:1000px}table{border-collapse:collapse;width:100%}
td,th{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}a{color:#12688d}
</style><h1>Repeated-coefficient rolling repairs</h1>
<p>Each analytical case is a finite GF256 coefficient-decoder experiment. Three paired seeds per
configuration carry 20,000 sources, including 2,000 warmup and 2,000 trailing sources. All 16,000
measured sources remain in the 35 ms deadline denominator, including unresolved symbols.</p>
<p>Sources cost 1496 IP bytes and repairs cost 1500 IP bytes on a 100 Mbps forward link. Integer
26/125 repair credit fixes the 20.8% repair/source budget. Forward and feedback erasures are 15% IID.
Prefix feedback costs 46 bytes on the 10 Mbps reverse link and arrives after at least 70 ms.</p>
<p>Every sixteenth repair uses fresh coefficients over the sender-unconfirmed prefix. Other repairs
cover the latest W transmitted sources, bounded by the delayed confirmed prefix. The control also
uses fresh coefficients in this range. Accumulator variants repeat a fixed coefficient seed in L
lanes. Coefficients depend on the lane and absolute source ID. Overlapping same-lane equations
therefore cancel their common interior under GF256 addition. The existing serial-derived packet
seed identifies the lane and global slots. This rule requires no current receiver loss knowledge.</p>
<p>The displayed rate is the optimistic 1448-byte application service ceiling before full record
framing and TCP effects. Actual TCP throughput, ACK traffic, parity-payload arithmetic and coding
CPU cost remain unmeasured. Conditional P99 excludes symbols unresolved at the horizon. All raw
points have stable analytical IDs. A star marks the lowest mean cost among configurations whose
measured cohorts recovered completely.</p>
<div class="scroll"><div class="chart">__CHART__</div></div>
<div class="scroll"><table><thead><tr><th>Policy</th><th>Cases</th><th>35 ms misses</th>
<th>Unresolved</th><th>Recovered-only P99 ms</th></tr></thead><tbody>__ROWS__</tbody></table></div>
<p><a href="analytic-cases.csv">Every raw case</a> · <a href="analytic-summary.csv">Means and intervals</a> ·
<a href="manifest.json">Pre-execution source snapshots</a> · <a href="validation-checks.json">Coverage and paired-budget checks</a></p></html>'''
    chart = figure.to_html(full_html=False, include_plotlyjs=True, div_id="analytic-pareto", config=dict(responsive=True))
    (output / "report.html").write_text(page.replace("__CHART__", chart).replace("__ROWS__", table))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    tasks = [dict(analytic_case_id=index * 3 + replication + 1, profile=profile, seed=20261110 + replication,
                  source_count=20000, warmup_sources=2000, tail_sources=2000)
             for index, profile in enumerate(PROFILES) for replication in range(3)]
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(reference.__file__).resolve(),
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_rolling_accumulator_manifest", protocol_executions=0,
                    analytic_cases=len(tasks), analytic_tasks=tasks, sources=hashes)
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "manifest.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing sources or task matrix differ")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in files:
        copy = args.out / "sources" / path.relative_to(root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    cases = args.out / "cases"
    cases.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (cases / f"{task['analytic_case_id']:03d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            target = cases / f"{row['analytic_case_id']:03d}.json"
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
            temporary.replace(target)
            print(f'Case {row["analytic_case_id"]} {row["policy"]} miss={100 * row["deadline_miss_fraction"]:.4f}% '
                  f'unresolved={100 * row["unresolved_at_horizon_fraction"]:.4f}%', flush=True)
    rows = [json.loads((cases / f"{task['analytic_case_id']:03d}.json").read_text()) for task in tasks]
    for seed in range(20261110, 20261113):
        paired = [row for row in rows if row["seed"] == seed]
        for field in ("erasure_trace_sha256", "forward_total_wire_bytes", "reverse_feedback_wire_bytes", "measured_sources"):
            assert len({row[field] for row in paired}) == 1
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not changed, changed
    summaries = summarize(rows)
    reference.write_csv(args.out / "analytic-cases.csv", rows)
    reference.write_csv(args.out / "analytic-summary.csv", summaries)
    checks = dict(cases=len(rows), plotted_case_ids=[row["analytic_case_id"] for row in rows],
                  points_per_panel=len(rows), paired_erasure_traces=True, fixed_forward_byte_budget=True,
                  paired_feedback_byte_budget=True, original_source_denominator=True, changed_during_run=changed)
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    render(args.out, rows, summaries)


if __name__ == "__main__":
    main()
