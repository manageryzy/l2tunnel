"""Screen age-dependent coefficient taps under the unchanged causal wire budget."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
from html import escape
import json
from pathlib import Path
from unittest.mock import patch

import plotly.graph_objects as go
from plotly.subplots import make_subplots

if __package__:
    from . import rtt_checkpoint_repairs as reference
else:
    import rtt_checkpoint_repairs as reference
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci, paired_difference


SERIAL_MULTIPLIER = 2654435761
SERIAL_INVERSE = pow(SERIAL_MULTIPLIER, -1, 1 << 32)
SEEDS = (20261110, 20261111, 20261112)
METRICS = ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
           "recovered_only_created_to_known_p99_ms")
PROFILES = [dict(name="Fresh dense W128 G16", lanes=0, tap_width=0, checkpoint=0, burst=False),
            *[dict(name=f"Age taps L{lanes} T{width} W128 G16", lanes=lanes, tap_width=width,
                   checkpoint=0, burst=False) for lanes in (1, 3) for width in (16, 32, 64)]]


def repair_coefficient(profile, packet_seed, source, end):
    """Derive every coefficient from the existing seed/range and agreed profile."""
    serial = packet_seed * SERIAL_INVERSE & 0xffffffff
    if not profile["lanes"] or serial % 16 == 0:
        return coefficient(packet_seed, source)
    age_band = (end - 1 - source) // profile["tap_width"]
    lane = serial % profile["lanes"]
    return coefficient(0x5A000000 + 256 * lane + age_band, source)


def execute(task):
    original_support = reference.support
    current_end = 0

    def support(profile, next_source, sender_base, serial, final=False):
        nonlocal current_end
        start, current_end = original_support(profile, next_source, sender_base, serial, final)
        return start, current_end

    def age_coefficient(packet_seed, source):
        return repair_coefficient(task["profile"], packet_seed, source, current_end)

    with patch.object(reference, "support", support), patch.object(reference, "coefficient", age_coefficient):
        row = reference.execute(task)
    row.update(record_kind="analytic_age_coefficient_case", protocol_executions=0,
               payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
               base_rtt_ms=70, loss_rate=.15, loss_model="iid")
    return row


def summarize(rows):
    control = sorted((row for row in rows if row["policy"] == PROFILES[0]["name"]), key=lambda row: row["seed"])
    summaries = []
    for profile in PROFILES:
        group = sorted((row for row in rows if row["policy"] == profile["name"]), key=lambda row: row["seed"])
        summary = dict(policy=profile["name"], cases=len(group))
        for metric in METRICS:
            summary.update({metric + "_" + key: value for key, value in mean_ci([row[metric] for row in group]).items()})
        difference = paired_difference([row[METRICS[0]] for row in group], [row[METRICS[0]] for row in control])
        summary.update({"paired_miss_difference_" + key: value for key, value in difference.items()})
        summaries.append(summary)
    return summaries


def render(output, rows, summaries):
    figure = make_subplots(rows=2, cols=2, subplot_titles=(
        "35 ms source deadline", "Conditional source P99",
        "Every case and deadline misses", "Every case and unresolved sources"))
    panels = ((1, 1, "deadline_miss_fraction", 100),
              (1, 2, "recovered_only_created_to_known_p99_ms", 1),
              (2, 1, "deadline_miss_fraction", 100),
              (2, 2, "unresolved_at_horizon_fraction", 100))
    colors = ("#1764ab", "#d16b25", "#16816a", "#9751b5", "#a34255", "#557f16", "#555c91")
    for profile, color in zip(PROFILES, colors):
        group = [row for row in rows if row["policy"] == profile["name"]]
        for grid_row, column, metric, scale in panels:
            ids = [str(row["analytic_case_id"]) for row in group]
            x = [row[metric] * scale for row in group] if grid_row == 1 else [row["analytic_case_id"] for row in group]
            y = [row["ideal_application_service_ceiling_mbps"] for row in group] if grid_row == 1 else [row[metric] * scale for row in group]
            figure.add_trace(go.Scatter(
                x=x, y=y, ids=ids, text=ids, mode="markers" if grid_row == 1 else "markers+text",
                textposition="top center", name=profile["name"], legendgroup=profile["name"],
                marker=dict(color=color, size=7),
                showlegend=grid_row == 1 and column == 1, meta=dict(kind="raw-case"),
                customdata=[[row["analytic_case_id"], row["seed"]] for row in group],
                hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}<br>x %{x:.6g}<br>y %{y:.6g}<extra>%{fullData.name}</extra>"),
                row=grid_row, col=column)
    complete = [row for row in summaries if row["unresolved_at_horizon_fraction_mean"] == 0]
    for column, metric, scale in ((1, METRICS[0], 100), (2, METRICS[2], 1)):
        if complete:
            lowest = min(row[metric + "_mean"] for row in complete)
            best = [row for row in complete if row[metric + "_mean"] == lowest]
            figure.add_trace(go.Scatter(
                x=[lowest * scale] * len(best), y=[rows[0]["ideal_application_service_ceiling_mbps"]] * len(best),
                text=[row["policy"] for row in best], mode="markers", marker=dict(symbol="diamond-open", size=16, color="#203040"),
                name="Eligible mean frontier", showlegend=column == 1, meta=dict(kind="mean-frontier"),
                hovertemplate="%{text}<br>Configuration mean<extra></extra>"), row=1, col=column)
    figure.update_xaxes(title_text="Original-source deadline misses (%)", row=1, col=1)
    figure.update_xaxes(title_text="Recovered-only source P99 (ms)", row=1, col=2)
    for column in (1, 2):
        figure.update_yaxes(title_text="Optimistic application service ceiling (Mbps)", row=1, col=column)
        figure.update_xaxes(title_text="Individual analytical case ID", row=2, col=column)
    figure.update_yaxes(title_text="Deadline misses (%)", row=2, col=1)
    figure.update_yaxes(title_text="Unresolved measured sources (%)", row=2, col=2)
    figure.add_vline(x=1, line_dash="dash", line_color="#aa4444", row=1, col=1)
    figure.update_layout(height=880, template="plotly_white", margin=dict(l=80, r=35, t=65, b=150),
                         legend=dict(orientation="h", y=-.2, x=0))
    table = "".join(
        f'<tr><td>{escape(row["policy"])}</td><td>{row["cases"]}</td>'
        f'<td>{100 * row["deadline_miss_fraction_mean"]:.4f}%</td>'
        f'<td>{100 * row["unresolved_at_horizon_fraction_mean"]:.4f}%</td>'
        f'<td>{row["recovered_only_created_to_known_p99_ms_mean"]:.3f}</td>'
        f'<td>{100 * row["paired_miss_difference_mean"]:.4f} '
        f'[{100 * row["paired_miss_difference_ci_low"]:.4f}, {100 * row["paired_miss_difference_ci_high"]:.4f}]</td></tr>'
        for row in summaries)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Age-dependent coefficient screen</title>
<style>body{max-width:1250px;margin:25px auto;padding:18px;font:16px/1.5 system-ui;color:#213547}
.scroll{max-width:100%;overflow:auto}.chart{min-width:1100px}table{border-collapse:collapse;width:100%}
td,th{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}a{color:#12688d}code{overflow-wrap:anywhere}</style>
<h1>Age-dependent coefficient taps</h1>
<p>All 21 finite GF256 coding cases appear in each panel. Each configuration uses three paired seeds,
20,000 source symbols, 2,000 warmup sources and 2,000 trailing sources. The complete measured cohort of
16,000 original sources remains in the 35 ms deadline denominator. Unresolved sources count as misses.</p>
<p>Fixed source arrivals, 1496-byte source packets, 1500-byte repairs and integer 26/125 repair credit
retain the reference forward wire budget. Forward service is 100 Mbps, reverse service is 10 Mbps,
nominal RTT is 70 ms, and forward and feedback loss are 15% IID. Prefix feedback consumes 46 bytes
and takes at least 70 ms. All paired cases have identical forward erasure traces and feedback byte costs.</p>
<p>Every sixteenth repair uses fresh coefficients over the sender-unconfirmed prefix. Other repairs
cover the latest 128 transmitted sources. The control uses fresh coefficients. Each candidate uses L
repeating lanes and changes a source's coefficient when its age crosses a T-source boundary.
With transmitted end E, source ID s and serial q, the coefficient is
<code>coefficient(0x5A000000 + 256*(q mod L) + floor((E-1-s)/T), s)</code>.
The existing packet seed recovers q modulo 2^32. Both endpoints know E and the configured L and T.</p>
<p>This heuristic lets equations cancel coefficients within unchanged age bands while exposing new
constraints at age boundaries. Selection uses transmitted source IDs and delayed confirmed prefixes.
The screen tests whether this structure improves early partial recovery under the charged schedule.</p>
<p>The rate axis is an optimistic 1448-byte application service ceiling. TCP throughput, complete-frame
delivery, ACK traffic, parity-payload arithmetic and coding CPU time remain unmeasured. Conditional P99
uses recovered measured sources. The diamond marks the best empirical mean among configurations with
fully recovered measured cohorts. The lower panels preserve every case ID when cost-rate points overlap.</p>
<div class="scroll" tabindex="0"><div class="chart">__CHART__</div></div>
<div class="scroll" tabindex="0"><table><thead><tr><th>Policy</th><th>Seeds</th><th>35 ms misses</th>
<th>Unresolved</th><th>Conditional P99 ms</th><th>Paired miss change pp [95% CI]</th></tr></thead><tbody>__ROWS__</tbody></table></div>
<p><a href="analytic-cases.csv">Every raw case</a> · <a href="analytic-summary.csv">Means and paired intervals</a> ·
<a href="manifest.json">Pre-execution source snapshots</a> · <a href="validation-checks.json">Coverage and budget checks</a></p></html>'''
    chart = figure.to_html(full_html=False, include_plotlyjs=True, div_id="age-coefficient-pareto", config=dict(responsive=True))
    (output / "report.html").write_text(page.replace("__CHART__", chart).replace("__ROWS__", table))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    tasks = [dict(analytic_case_id=index * len(SEEDS) + replication + 1, profile=profile, seed=seed,
                  source_count=20000, warmup_sources=2000, tail_sources=2000)
             for index, profile in enumerate(PROFILES) for replication, seed in enumerate(SEEDS)]
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(reference.__file__).resolve(),
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_age_coefficient_manifest", protocol_executions=0,
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
    pending = [task for task in tasks if not (cases / f'{task["analytic_case_id"]:03d}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            target = cases / f'{row["analytic_case_id"]:03d}.json'
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
            temporary.replace(target)
            print(f'Case {row["analytic_case_id"]} {row["policy"]} miss={100 * row["deadline_miss_fraction"]:.4f}% '
                  f'unresolved={100 * row["unresolved_at_horizon_fraction"]:.4f}%', flush=True)
    rows = [json.loads((cases / f'{task["analytic_case_id"]:03d}.json').read_text()) for task in tasks]
    for seed in SEEDS:
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
