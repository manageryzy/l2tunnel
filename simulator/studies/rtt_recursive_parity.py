"""Causal source-regular recursive parity under a fixed charged packet schedule."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache
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
PROFILES = [dict(name="Fresh dense W128 G16", taps=0, width=0, reset=256,
                 checkpoint=0, burst=False),
            *[dict(name=f"Recursive Q{taps} B{width} R256", taps=taps, width=width,
                   reset=256, checkpoint=0, burst=False)
              for taps, width in ((3, 8), (3, 12), (4, 8))]]
METRICS = ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
           "recovered_only_created_to_known_p99_ms")


@lru_cache(maxsize=131072)
def source_taps(source, taps, width):
    """Place one nonzero edge in each successive future repair-age band."""
    first = (26 * source) // 125 + 1
    result = []
    for edge in range(taps):
        digest = sha256(f"recursive-parity-v1/{source}/{edge}".encode()).digest()
        offset = int.from_bytes(digest[:4], "big") % width
        weight = 1 + int.from_bytes(digest[4:8], "big") % 255
        result.append((first + edge * width + offset, weight))
    return tuple(result)


def epoch_start(serial, reset):
    return ((serial - 1) // reset) * reset + 1


def source_start(profile, serial):
    # Conservative inverse of first(s)+max_offset >= epoch_start.
    earliest = epoch_start(serial, profile["reset"]) - profile["taps"] * profile["width"]
    return max(0, (earliest - 1) * 125 // 26)


def expanded_coefficient(profile, serial, source):
    value = 0
    first = epoch_start(serial, profile["reset"])
    for check, weight in source_taps(source, profile["taps"], profile["width"]):
        if first <= check <= serial:
            value ^= weight
    return value


def check_equation(profile, serial, end):
    """Source part U[j] of the zero-RHS constraint P[j]+P[j-1]+U[j]=0."""
    result = {}
    for source in range(source_start(profile, serial), end):
        for check, weight in source_taps(source, profile["taps"], profile["width"]):
            if check == serial:
                result[source] = weight
    return result


def execute(task):
    profile = task["profile"]
    original_support = reference.support
    expanded_degrees = Counter()

    def support(policy, end, base, serial, final=False):
        if not policy["taps"]:
            return original_support(policy, end, base, serial, final)
        start = source_start(policy, serial)
        if end - start > 65535:
            raise ValueError("recursive support exceeds the charged 16-bit range field")
        return start, end

    def repair_coefficient(seed, source):
        serial = seed * SERIAL_INVERSE & 0xffffffff
        if not profile["taps"]:
            value = coefficient(seed, source)
        else:
            value = expanded_coefficient(profile, serial, source)
        expanded_degrees[serial] += bool(value)
        return value

    with patch.object(reference, "support", support), patch.object(reference, "coefficient", repair_coefficient):
        row = reference.execute(task)
    # The reference constructs equations only for received repairs. These
    # degrees describe those received rows and exclude erased packet contents.
    checks = Counter(check for source in range(task["source_count"])
                     for check, weight in source_taps(source, profile["taps"], profile["width"])
                     if check <= row["repair_packets"])
    row.update(record_kind="analytic_recursive_parity_case", protocol_executions=0,
               payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
               base_rtt_ms=70, loss_rate=.15, loss_model="iid",
               deadline_miss_count=round(row["deadline_miss_fraction"] * row["measured_sources"]),
               unresolved_count=round(row["unresolved_at_horizon_fraction"] * row["measured_sources"]),
               planned_source_check_degree=profile["taps"] or None,
               mean_emitted_check_source_degree=sum(checks.values()) / row["repair_packets"] if checks else None,
               maximum_emitted_check_source_degree=max(checks.values(), default=0) if checks else None,
               mean_received_expanded_repair_degree=sum(expanded_degrees.values()) / len(expanded_degrees),
               maximum_received_expanded_repair_degree=max(expanded_degrees.values()),
               reset_interval_repairs=profile["reset"] if profile["taps"] else None,
               parity_resets=(row["repair_packets"] - 1) // profile["reset"] + 1 if profile["taps"] else 0)
    return row


def summarize(rows):
    control = sorted((row for row in rows if row["policy"] == PROFILES[0]["name"]), key=lambda row: row["seed"])
    summaries = []
    for profile in PROFILES:
        group = sorted((row for row in rows if row["policy"] == profile["name"]), key=lambda row: row["seed"])
        summary = dict(policy=profile["name"], cases=len(group),
                       frontier_eligible=len(group) == len(SEEDS) and all(row["unresolved_count"] == 0 for row in group))
        for metric in METRICS:
            summary.update({metric + "_" + key: value for key, value in mean_ci([row[metric] for row in group]).items()})
        delta = paired_difference([row[METRICS[0]] for row in group], [row[METRICS[0]] for row in control])
        summary.update({"paired_miss_difference_" + key: value for key, value in delta.items()})
        summaries.append(summary)
    return summaries


def render(output, rows, summaries):
    figure = make_subplots(rows=2, cols=2, subplot_titles=(
        "35 ms original-source deadline", "Recovered-only source P99",
        "Every case and deadline misses", "Every case and unresolved sources"))
    panels = ((1, 1, METRICS[0], 100), (1, 2, METRICS[2], 1),
              (2, 1, METRICS[0], 100), (2, 2, METRICS[1], 100))
    colors = ("#1764ab", "#d16b25", "#16816a", "#9751b5")
    for profile_index, profile in enumerate(PROFILES):
        selected = [row for row in rows if row["policy"] == profile["name"]]
        for grid_row, column, metric, scale in panels:
            ids = [str(row["analytic_case_id"]) for row in selected]
            x = [row[metric] * scale for row in selected] if grid_row == 1 else [row["analytic_case_id"] for row in selected]
            y = [row["ideal_application_service_ceiling_mbps"] for row in selected] if grid_row == 1 else [row[metric] * scale for row in selected]
            figure.add_trace(go.Scatter(x=x, y=y, ids=ids, text=ids,
                mode="markers" if grid_row == 1 else "markers+text", textposition="top center",
                name=profile["name"], legendgroup=profile["name"], showlegend=grid_row == 1 and column == 1,
                marker=dict(color=colors[profile_index], size=9),
                meta=dict(kind="raw-case"), customdata=[[row["analytic_case_id"], row["seed"],
                    row["deadline_miss_count"], row["unresolved_count"], row["measured_sources"]] for row in selected],
                hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}<br>x %{x:.6g} · y %{y:.6g}"
                              "<br>Misses %{customdata[2]} / %{customdata[4]}"
                              "<br>Unresolved %{customdata[3]} / %{customdata[4]}<extra>%{fullData.name}</extra>"),
                row=grid_row, col=column)
    eligible = [row for row in summaries if row["frontier_eligible"]]
    for column, metric, scale in ((1, METRICS[0], 100), (2, METRICS[2], 1)):
        if eligible:
            lowest = min(row[metric + "_mean"] for row in eligible)
            best = [row for row in eligible if row[metric + "_mean"] == lowest]
            figure.add_trace(go.Scatter(x=[lowest * scale] * len(best),
                y=[rows[0]["ideal_application_service_ceiling_mbps"]] * len(best), text=[row["policy"] for row in best],
                mode="markers", marker=dict(symbol="diamond-open", size=16, color="#203040"),
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
    figure.update_layout(height=870, template="plotly_white", margin=dict(l=80, r=35, t=65, b=150),
                         legend=dict(orientation="h", y=-.2, x=0))
    table = "".join(f'<tr><td>{escape(row["policy"])}</td><td>{row["cases"]}</td>'
        f'<td>{100 * row["deadline_miss_fraction_mean"]:.4f}%</td>'
        f'<td>{100 * row["unresolved_at_horizon_fraction_mean"]:.4f}%</td>'
        f'<td>{row["recovered_only_created_to_known_p99_ms_mean"]:.3f}</td>'
        f'<td>{100 * row["paired_miss_difference_mean"]:.4f} '
        f'[{100 * row["paired_miss_difference_ci_low"]:.4f}, {100 * row["paired_miss_difference_ci_high"]:.4f}]</td></tr>'
        for row in summaries)
    degree_table = "".join(f'<tr><td>{escape(profile["name"])}</td>'
        f'<td>{max(row["largest_repair_support"] for row in rows if row["policy"] == profile["name"])}</td>'
        f'<td>{profile["taps"] or "dense"}</td>'
        f'<td>{next(row["mean_emitted_check_source_degree"] for row in rows if row["policy"] == profile["name"])}</td>'
        f'<td>{next(row["maximum_emitted_check_source_degree"] for row in rows if row["policy"] == profile["name"])}</td>'
        f'<td>{next(row["parity_resets"] for row in rows if row["policy"] == profile["name"])}</td></tr>'
        for profile in PROFILES)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Source-regular recursive parity</title>
<style>body{max-width:1250px;margin:25px auto;padding:18px;font:16px/1.5 system-ui;color:#213547}
.scroll{max-width:100%;overflow:auto}.chart{min-width:1100px}table{border-collapse:collapse;width:100%}
td,th{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}a{color:#12688d}code{overflow-wrap:anywhere}</style>
<h1>Source-regular recursive parity</h1>
<p>All 12 coding-only cases appear in every panel. Each configuration uses three paired seeds,
20,000 source symbols, 2,000 warmup sources and 2,000 trailing sources. The 16,000 measured original
sources remain in the 35 ms deadline denominator. Unresolved sources count as misses.</p>
<p>Sources cost 1496 IP bytes and repairs cost 1500 IP bytes. Integer 26/125 credit fixes the
repair/source budget at 20.8%. Forward service is 100 Mbps, reverse service is 10 Mbps, nominal RTT
is 70 ms, and forward and feedback loss are 15% IID. Prefix feedback costs 46 bytes and arrives
after at least 70 ms. Frozen source arrivals and complete packet-erasure traces are paired.</p>
<h2>Construction</h2><p>For source s, the first eligible repair is floor(26s/125)+1.
One SHA256-derived check is selected in each of Q consecutive B-repair age bands. Each edge has
a reproducible nonzero GF256 coefficient. At repair j, U[j] combines exactly the sources assigned
to that check, and P[j]=P[j-1]+U[j]. The recursive state restarts from zero every 256 repairs.
Future source edges cross restart boundaries normally. Every scheduled repair sends P[j].</p>
<p>The executed decoder receives the algebraically expanded source-only equation for P[j].
An independent augmented representation includes latent parity variables and zero-RHS
constraints. Finite fixtures compare both at every event, including erased parity packets and
restart boundaries. A received parity value is available only when its actual packet arrives.</p>
<p>The existing 32-bit repair seed recovers j through the modular inverse of 2654435761.
The first-source ID and 16-bit range delimit the expanded equation, whose maximum span is checked.
The configured type/version selects the edge and restart rules. This screen models the existing
header charge. A protocol implementation would negotiate the profile and retain the required
source/parity state. CPU costs and actual encoded payload arithmetic remain unmeasured here.</p>
<p>This is a finite GF256 heuristic inspired by systematic spatially coupled repeat-accumulate
construction. The primary paper establishes the construction and studies larger lifted binary
graphs. Its results provide no finite 35 ms guarantee for this packet-level derivative.
<a href="https://arxiv.org/pdf/1110.6787">Johnson and Lechner, Spatially Coupled Repeat-Accumulate Codes</a>.</p>
<p>Prior mixed-degree screens sample each repair row independently. Prior rolling and age-band
screens vary dense coefficients over sliding supports. Here each source has a fixed check degree
and a recursive parity state. The control retains fresh dense W128 repairs and every-sixteenth
global repair. The new policies use their entire fixed budget for recursive repairs.</p>
<h2>Results</h2><p>All three new configurations exceeded the 1% original-source deadline-miss
threshold in every seed. Each also left measured sources unresolved at the observation horizon.
Their mean deadline-miss fractions exceeded the paired dense control. These finite results
deprioritize the tested degree, age-band and restart choices. They leave other coupled graph
constructions unqualified. The degree-three cases' lower conditional P99 excludes their substantial
unresolved cohorts. The complete original-source deadline denominator governs this screen.</p>
<p>The rate axis is the optimistic 1448-byte application service ceiling.
Measured TCP throughput requires a later full protocol experiment. Conditional P99 uses recovered measured sources. Diamond markers
identify tied nondominated configuration means whose three measured cohorts fully recovered.
All raw cases remain visible, including dominated and incomplete cases. A coding-only result
must still pass actual frame delivery and all-original-segment cumulative ACK timing to qualify
the 80 Mbps / 105 ms end-to-end target.</p>
<div class="scroll" tabindex="0"><div class="chart">__CHART__</div></div>
<div class="scroll" tabindex="0"><table><thead><tr><th>Policy</th><th>Seeds</th><th>35 ms misses</th>
<th>Unresolved</th><th>Conditional P99 ms</th><th>Paired miss change pp [95% CI]</th></tr></thead>
<tbody>__ROWS__</tbody></table></div>
<h2>Finite support and degree accounting</h2>
<p>Source degree counts scheduled sparse-check edges. Check degree counts sources in U[j], before
accumulation. The raw CSV also records each received expanded repair's mean and maximum nonzero
source degree. Erased repair values are absent from those received-row statistics. Resets include
the initial zero state, occur every 256 repairs, and consume no extra packets.</p>
<div class="scroll"><table><thead><tr><th>Policy</th><th>Maximum header span</th><th>Source degree</th>
<th>Mean check degree</th><th>Maximum check degree</th><th>Zero-state starts</th></tr></thead>
<tbody>__DEGREES__</tbody></table></div>
<p><a href="analytic-cases.csv">Every raw case</a> · <a href="analytic-summary.csv">Means and paired intervals</a> ·
<a href="manifest.json">Frozen execution sources</a> · <a href="validation-checks.json">Coverage and budget checks</a> ·
<a href="finite-validation.json">Independent finite validation</a> ·
<a href="report-render-provenance.json">Rendering provenance</a></p></html>'''
    chart = figure.to_html(full_html=False, include_plotlyjs=True, div_id="recursive-parity-pareto", config=dict(responsive=True))
    (output / "report.html").write_text(page.replace("__CHART__", chart).replace("__ROWS__", table).replace("__DEGREES__", degree_table))


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
             root / "tests/test_recursive_parity.py",
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_recursive_parity_manifest", protocol_executions=0,
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
                  f'miss={100 * row["deadline_miss_fraction"]:.4f}% '
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
                  points_per_panel=len(rows), panels=4, paired_erasure_traces=True,
                  fixed_forward_byte_budget=True, paired_feedback_byte_budget=True,
                  original_source_denominator=True, changed_during_run=changed,
                  raw_case_sha256={path.name: sha256(path.read_bytes()).hexdigest() for path in sorted(cases.glob("*.json"))})
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    render(args.out, rows, summaries)


if __name__ == "__main__":
    main()
