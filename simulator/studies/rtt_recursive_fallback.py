"""Replace occasional recursive parity packets with charged fresh-prefix repairs."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
from html import escape
import json
from pathlib import Path
from unittest.mock import patch

import plotly.graph_objects as go
from plotly.subplots import make_subplots

if __package__:
    from . import rtt_recursive_parity as recursive
else:
    import rtt_recursive_parity as recursive
from l2tunnel_sim.stats import paired_difference


reference = recursive.reference
SEEDS = recursive.SEEDS
METRICS = recursive.METRICS
PROFILES = [dict(recursive.PROFILES[0], fresh_interval=0),
            dict(recursive.PROFILES[3], fresh_interval=0),
            *[dict(recursive.PROFILES[3], name=f"Recursive Q4 B8 + fresh G{interval}",
                   fresh_interval=interval) for interval in (8, 16, 32)]]
COLORS = ("#1764ab", "#9751b5", "#d16b25", "#16816a", "#a34255")


def repair_mode(profile, serial):
    if not profile["taps"]:
        return "dense"
    interval = profile["fresh_interval"]
    if interval and serial % interval == 0:
        return "fallback"
    return "recursive"


def repair_coefficient(profile, seed, source):
    serial = seed * recursive.SERIAL_INVERSE & 0xffffffff
    if repair_mode(profile, serial) != "recursive":
        return recursive.coefficient(seed, source)
    return recursive.expanded_coefficient(profile, serial, source)


def execute(task):
    profile = task["profile"]
    original_support = reference.support
    received_degrees = Counter()
    modes = Counter()

    def support(policy, end, base, serial, final=False):
        mode = repair_mode(policy, serial)
        modes[mode] += 1
        if mode == "dense":
            start, end = original_support(policy, end, base, serial, final)
        elif mode == "fallback":
            start = base
        else:
            start = recursive.source_start(policy, serial)
        if end - start > 65535:
            raise ValueError("repair support exceeds the charged 16-bit range field")
        return start, end

    def coefficients(seed, source):
        serial = seed * recursive.SERIAL_INVERSE & 0xffffffff
        value = repair_coefficient(profile, seed, source)
        received_degrees[serial] += bool(value)
        return value

    with patch.object(reference, "support", support), patch.object(reference, "coefficient", coefficients):
        row = reference.execute(task)
    row.update(record_kind="analytic_recursive_fallback_case", protocol_executions=0,
        payload_bytes=1448, forward_mbps=100, reverse_mbps=10, base_rtt_ms=70,
        loss_rate=.15, loss_model="iid",
        deadline_miss_count=round(row[METRICS[0]] * row["measured_sources"]),
        unresolved_count=round(row[METRICS[1]] * row["measured_sources"]),
        fallback_repair_packets=modes["fallback"], recursive_repair_packets=modes["recursive"],
        dense_control_repair_packets=modes["dense"], replacement_interval_repairs=profile["fresh_interval"] or None,
        planned_source_check_degree=profile["taps"] or None,
        mean_received_repair_degree=sum(received_degrees.values()) / len(received_degrees),
        maximum_received_repair_degree=max(received_degrees.values()),
        full_horizon_unknown_count=task["source_count"] - row["final_known_sources"],
        full_horizon_residual_equation_rank=row["remaining_decoder_rows"],
        full_horizon_rank_deficit=task["source_count"] - row["final_known_sources"] - row["remaining_decoder_rows"],
        parity_resets=(row["repair_packets"] - 1) // profile["reset"] + 1 if profile["taps"] else 0,
        reset_interval_repairs=profile["reset"] if profile["taps"] else None,
        recursive_state_advances_at_replaced_slots=True)
    assert sum(modes.values()) == row["repair_packets"]
    return row


def summarize(rows):
    with patch.object(recursive, "PROFILES", PROFILES):
        summaries = recursive.summarize(rows)
    pure = sorted((row for row in rows if row["policy"] == PROFILES[1]["name"]), key=lambda row: row["seed"])
    for summary in summaries:
        selected = sorted((row for row in rows if row["policy"] == summary["policy"]), key=lambda row: row["seed"])
        delta = paired_difference([row[METRICS[0]] for row in selected], [row[METRICS[0]] for row in pure])
        summary.update({"paired_vs_pure_miss_difference_" + key: value for key, value in delta.items()})
    return summaries


def render(output, rows, summaries):
    figure = make_subplots(rows=2, cols=2, subplot_titles=(
        "35 ms original-source deadline", "Recovered-only source P99",
        "Every case and deadline misses", "Every case and unresolved sources"))
    panels = ((1, 1, METRICS[0], 100), (1, 2, METRICS[2], 1),
              (2, 1, METRICS[0], 100), (2, 2, METRICS[1], 100))
    for policy_index, profile in enumerate(PROFILES):
        selected = [row for row in rows if row["policy"] == profile["name"]]
        for grid_row, column, metric, scale in panels:
            ids = [str(row["analytic_case_id"]) for row in selected]
            figure.add_trace(go.Scatter(
                x=[row[metric] * scale if grid_row == 1 else row["analytic_case_id"] for row in selected],
                y=[row["ideal_application_service_ceiling_mbps"] if grid_row == 1 else row[metric] * scale for row in selected],
                ids=ids, text=ids, mode="markers" if grid_row == 1 else "markers+text", textposition="top center",
                marker=dict(color=COLORS[policy_index], size=9), name=profile["name"], legendgroup=profile["name"],
                showlegend=grid_row == 1 and column == 1, meta=dict(kind="raw-case"),
                customdata=[[row["analytic_case_id"], row["seed"], row["deadline_miss_count"],
                             row["unresolved_count"], row["measured_sources"]] for row in selected],
                hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}<br>x %{x:.6g} · y %{y:.6g}"
                    "<br>Misses %{customdata[2]} / %{customdata[4]}"
                    "<br>Unresolved %{customdata[3]} / %{customdata[4]}<extra>%{fullData.name}</extra>"),
                row=grid_row, col=column)
    eligible = [row for row in summaries if row["frontier_eligible"]]
    for column, metric, scale in ((1, METRICS[0], 100), (2, METRICS[2], 1)):
        if eligible:
            lowest = min(row[metric + "_mean"] for row in eligible)
            tied = [row for row in eligible if row[metric + "_mean"] == lowest]
            figure.add_trace(go.Scatter(x=[lowest * scale] * len(tied),
                y=[rows[0]["ideal_application_service_ceiling_mbps"]] * len(tied),
                text=[row["policy"] for row in tied], mode="markers",
                marker=dict(symbol="diamond-open", size=16, color="#203040"),
                meta=dict(kind="mean-frontier"), name="Eligible mean frontier", showlegend=column == 1,
                hovertemplate="%{text}<br>Complete-cohort mean<extra></extra>"), row=1, col=column)
    figure.update_xaxes(title_text="Original-source deadline misses (%)", row=1, col=1)
    figure.update_xaxes(title_text="Recovered-only source P99 (ms)", row=1, col=2)
    for column in (1, 2):
        figure.update_yaxes(title_text="Optimistic application service ceiling (Mbps)", row=1, col=column)
        figure.update_xaxes(title_text="Individual analytical case ID", row=2, col=column)
    figure.update_yaxes(title_text="Deadline misses (%)", row=2, col=1)
    figure.update_yaxes(title_text="Unresolved measured sources (%)", row=2, col=2)
    figure.add_vline(x=1, line_dash="dash", line_color="#aa4444", row=1, col=1)
    figure.update_layout(height=900, template="plotly_white", margin=dict(l=80, r=35, t=65, b=180),
                         legend=dict(orientation="h", y=-.22, x=0))
    result_table = "".join(f'<tr><td>{escape(row["policy"])}</td>'
        f'<td>{100 * row[METRICS[0] + "_mean"]:.4f}%</td><td>{100 * row[METRICS[1] + "_mean"]:.4f}%</td>'
        f'<td>{row[METRICS[2] + "_mean"]:.3f}</td>'
        f'<td>{100 * row["paired_miss_difference_mean"]:.4f} '
        f'[{100 * row["paired_miss_difference_ci_low"]:.4f}, {100 * row["paired_miss_difference_ci_high"]:.4f}]</td>'
        f'<td>{100 * row["paired_vs_pure_miss_difference_mean"]:.4f} '
        f'[{100 * row["paired_vs_pure_miss_difference_ci_low"]:.4f}, {100 * row["paired_vs_pure_miss_difference_ci_high"]:.4f}]</td></tr>'
        for row in summaries)
    modes_table = ""
    for profile in PROFILES:
        selected = [row for row in rows if row["policy"] == profile["name"]]
        row = selected[0]
        modes_table += f'<tr><td>{escape(profile["name"])}</td><td>{row["dense_control_repair_packets"]}</td>'
        modes_table += f'<td>{row["recursive_repair_packets"]}</td><td>{row["fallback_repair_packets"]}</td>'
        modes_table += f'<td>{max(item["largest_repair_support"] for item in selected)}</td><td>{row["parity_resets"]}</td></tr>'
    passing_cases = sum(row[METRICS[0]] <= .01 for row in rows)
    interpretation = f'{passing_cases} of {len(rows)} cases have at most 1% original-source deadline misses.'
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Recursive parity with fresh repairs</title>
<style>body{max-width:1250px;margin:25px auto;padding:18px;font:16px/1.5 system-ui;color:#213547}
.scroll{max-width:100%;overflow:auto}.chart{min-width:1100px}table{border-collapse:collapse;width:100%}
td,th{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}a{color:#12688d}code{overflow-wrap:anywhere}</style>
<h1>Recursive parity with fresh-prefix replacements</h1>
<p>All 15 coding-only cases appear in every panel. Five policies use three paired seeds each,
20,000 sources, 2,000 warmup sources and 2,000 trailing sources. The 16,000 measured original
sources remain in the 35 ms deadline denominator. Unresolved sources count as misses.</p>
<p>Sources cost 1496 IP bytes and repairs cost 1500 IP bytes. Integer 26/125 credit fixes the total
repair/source ratio at 20.8%. Forward service is 100 Mbps, reverse service is 10 Mbps, nominal RTT
is 70 ms, and packet losses are 15% IID. Prefix feedback costs 46 bytes and arrives after at least
70 ms. Packet service, forward erasure traces and feedback byte costs are paired.</p>
<h2>Causal construction and wire accounting</h2>
<p>The source-regular Q4/B8 code assigns each source one nonzero GF256 edge in each of four
consecutive eight-repair age bands. At every repair serial j, U[j] combines the sources assigned
to check j, and P[j]=P[j-1]+U[j]. The recursive state restarts from zero every 256 repairs.
Source edges crossing a restart still participate in their assigned future checks.</p>
<p>For replacement interval G, serials divisible by G send a fresh GF256 combination of the
delayed-unconfirmed source prefix. Other serials send P[j]. Recursive state advances at every
serial, including replacement slots. Each replacement uses one existing scheduled repair slot.
The existing seed recovers the serial, and the agreed profile determines the mode. Its existing
first-source ID and 16-bit range describe the chosen support. Total forward bytes stay fixed.</p>
<p>The fresh repair uses the original counter-based coefficients and the sender's delayed prefix.
It requires no instantaneous receiver-loss information. The executed rank decoder expands P[j]
into source-only coefficients. Finite independent numeric fixtures compare this with latent parity
variables and zero-RHS structural constraints across replacements, erased packets and restarts.
A replaced or erased recursive packet supplies no received-value equation for P[j].</p>
<p>This packet-level GF256 heuristic draws on causal systematic spatially coupled repeat-accumulate
construction. Finite deadline performance is established only by the saved cases below.
<a href="https://arxiv.org/pdf/1110.6787">Johnson and Lechner, Spatially Coupled Repeat-Accumulate Codes</a>.</p>
<h2>All cases and empirical Pareto frontiers</h2><p>__INTERPRETATION__
The rate axis is the optimistic 1448-byte application service ceiling. Actual TCP goodput,
encoded-payload CPU cost, complete-frame timing and cumulative ACK completion require full
protocol measurements. Conditional P99 excludes unresolved sources. The complete source
deadline denominator governs this screen.</p>
<p>Diamond markers show tied nondominated configuration means among policies whose three measured
cohorts fully recovered. Dominated and incomplete raw cases remain visible. The lower panels show
every individual case ID when top-panel points coincide. Paired 95% Student-t intervals use three
seeds and describe this finite matrix.</p>
<div class="scroll" tabindex="0"><div class="chart">__CHART__</div></div>
<div class="scroll"><table><thead><tr><th>Policy</th><th>35 ms misses</th><th>Unresolved</th>
<th>Conditional P99 ms</th><th>Miss change vs dense pp [95% CI]</th><th>Miss change vs pure recursive pp [95% CI]</th>
</tr></thead><tbody>__ROWS__</tbody></table></div>
<h2>Packet modes and bounded support</h2><p>Counts cover the whole 20,000-source run. Each run has
4,160 repairs. Zero-state starts include the initial state. The CSV includes each received repair's
mean and maximum nonzero source degree, exact byte totals, source hashes and censored counts.</p>
<p>The CSV separately records full-horizon unknown-source counts, residual independent equation
rank and their difference. That full-horizon population includes warmup and trailing sources.
The 35 ms deadline and measured unresolved counts use the fixed 16,000-source cohort.</p>
<div class="scroll"><table><thead><tr><th>Policy</th><th>Dense control</th><th>Recursive</th>
<th>Fresh replacement</th><th>Maximum support span</th><th>Zero-state starts</th></tr></thead>
<tbody>__MODES__</tbody></table></div>
<p><a href="analytic-cases.csv">Every raw case</a> · <a href="analytic-summary.csv">Means and paired intervals</a> ·
<a href="manifest.json">Frozen execution sources</a> · <a href="validation-checks.json">Coverage and budget checks</a> ·
<a href="finite-validation.json">Independent finite validation</a></p></html>'''
    chart = figure.to_html(full_html=False, include_plotlyjs=True, div_id="recursive-fallback-pareto", config=dict(responsive=True))
    (output / "report.html").write_text(page.replace("__CHART__", chart).replace("__ROWS__", result_table)
        .replace("__MODES__", modes_table).replace("__INTERPRETATION__", interpretation))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    tasks = [dict(analytic_case_id=index * len(SEEDS) + replication + 1, profile=profile, seed=seed,
                  source_count=20000, warmup_sources=2000, tail_sources=2000)
             for index, profile in enumerate(PROFILES) for replication, seed in enumerate(SEEDS)]
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(recursive.__file__).resolve(), Path(reference.__file__).resolve(),
             root / "tests/test_recursive_fallback.py", root / "tests/test_recursive_parity.py",
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_recursive_fallback_manifest", protocol_executions=0,
                    analytic_cases=len(tasks), analytic_tasks=tasks, sources=hashes)
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "manifest.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing sources or task matrix differ")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in files:
        copy = args.out / "sources" / path.relative_to(root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        if copy.exists() and copy.read_bytes() != path.read_bytes():
            raise ValueError("frozen source snapshot differs")
        copy.write_bytes(path.read_bytes())
    cases = args.out / "cases"
    cases.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (cases / f'{task["analytic_case_id"]:03d}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            row["execution_source_sha256"] = hashes
            target = cases / f'{row["analytic_case_id"]:03d}.json'
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
            temporary.replace(target)
            print(f'Case {row["analytic_case_id"]} {row["policy"]} '
                  f'miss={100 * row[METRICS[0]]:.4f}% unresolved={100 * row[METRICS[1]]:.4f}%', flush=True)
    rows = [json.loads((cases / f'{task["analytic_case_id"]:03d}.json').read_text()) for task in tasks]
    for seed in SEEDS:
        selected = [row for row in rows if row["seed"] == seed]
        for field in ("erasure_trace_sha256", "forward_total_wire_bytes", "reverse_feedback_wire_bytes", "measured_sources"):
            assert len({row[field] for row in selected}) == 1
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not changed, changed
    summaries = summarize(rows)
    reference.write_csv(args.out / "analytic-cases.csv", rows)
    reference.write_csv(args.out / "analytic-summary.csv", summaries)
    checks = dict(cases=len(rows), plotted_case_ids=[row["analytic_case_id"] for row in rows],
                  points_per_panel=len(rows), panels=4, paired_erasure_traces=True,
                  fixed_forward_byte_budget=True, paired_feedback_byte_budget=True,
                  original_source_denominator=True, changed_during_run=changed,
                  raw_case_sha256={path.name: sha256(path.read_bytes()).hexdigest() for path in sorted(cases.glob("*.json"))})
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    render(args.out, rows, summaries)


if __name__ == "__main__":
    main()
