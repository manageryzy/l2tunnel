"""Screen occasional low-degree repairs within the causal dense repair schedule."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
from html import escape
import json
from pathlib import Path
from random import Random
from unittest.mock import patch

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import rtt_checkpoint_repairs as reference
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci


def profiles():
    settings = [(0, 0), (4, 16), (8, 16), (4, 8), (8, 8), (16, 8), (8, 4)]
    return [dict(name=("Dense W128 G16" if not degree else f"Mixed degree{degree} every{every}"),
                 checkpoint=0, burst=False, degree=degree, sparse_every=every)
            for degree, every in settings]


def sparse_support(profile, start, end, serial):
    """Both peers derive this subset from the existing range and seed fields."""
    every = profile["sparse_every"]
    if not every or serial % 16 == 0 or serial % every != every - 1:
        return None
    seed = (serial * 2654435761) & 0xffffffff
    return set(Random(seed ^ 0x5A17D175).sample(range(start, end), min(profile["degree"], end - start)))


def execute(task):
    original_support = reference.support
    selected = None
    sparse_packets = 0

    def support(profile, next_source, sender_base, serial, final=False):
        nonlocal selected, sparse_packets
        start, end = original_support(profile, next_source, sender_base, serial, final)
        selected = sparse_support(profile, start, end, serial)
        sparse_packets += selected is not None
        return start, end

    def mixed_coefficient(seed, symbol):
        return coefficient(seed, symbol) if selected is None or symbol in selected else 0

    with patch.object(reference, "support", support), patch.object(reference, "coefficient", mixed_coefficient):
        row = reference.execute(task)
    row.update(record_kind="analytic_mixed_degree_case", sparse_repair_packets=sparse_packets)
    return row


def report(output, rows):
    summaries = []
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), layout="constrained")
    for profile in profiles():
        group = [row for row in rows if row["policy"] == profile["name"]]
        summary = dict(policy=profile["name"], cases=len(group))
        for metric in ("deadline_miss_fraction", "unresolved_at_horizon_fraction", "recovered_only_created_to_known_p99_ms"):
            stats = mean_ci([row[metric] for row in group])
            summary[metric] = stats["mean"]
            summary[metric + "_ci_low"] = stats["ci_low"]
            summary[metric + "_ci_high"] = stats["ci_high"]
        summaries.append(summary)
        for axis, metric, scale in ((axes[0], "deadline_miss_fraction", 100),
                                    (axes[1], "recovered_only_created_to_known_p99_ms", 1)):
            axis.scatter([row[metric] * scale for row in group],
                         [row["ideal_application_service_ceiling_mbps"] for row in group],
                         label=profile["name"], s=34)
    complete = [row for row in summaries if row["unresolved_at_horizon_fraction"] == 0]
    for axis, metric, scale in ((axes[0], "deadline_miss_fraction", 100),
                                (axes[1], "recovered_only_created_to_known_p99_ms", 1)):
        if complete:
            best = min(complete, key=lambda row: row[metric])
            axis.scatter([best[metric] * scale], [rows[0]["ideal_application_service_ceiling_mbps"]],
                         marker="*", s=160, facecolors="none", edgecolors="black",
                         label="Empirical mean frontier")
        ordered = sorted(rows, key=lambda row: (row[metric], row["analytic_case_id"]))
        for index, row in enumerate(ordered):
            axis.annotate(str(row["analytic_case_id"]),
                          (row[metric] * scale, row["ideal_application_service_ceiling_mbps"]),
                          xytext=((index + .5) / len(ordered), .24 + .09 * (index % 2)),
                          textcoords="axes fraction", ha="center", va="center", fontsize=7,
                          bbox=dict(boxstyle="round,pad=.15", facecolor="white", edgecolor="#b3becb"),
                          arrowprops=dict(arrowstyle="-", color="#7d8a98", linewidth=.6))
    axes[0].set_xlabel("Original-source 35 ms deadline misses (%)")
    axes[1].set_xlabel("Recovered-only source completion P99 (ms)")
    for axis in axes:
        axis.set_ylabel("Optimistic application service ceiling (Mbps)")
        axis.grid(alpha=.2)
    axes[0].axvline(1, color="#9b3333", linestyle="--", linewidth=1)
    axes[0].legend(fontsize=7, loc="upper left")
    fig.suptitle("Every coding-only case has a marker and ID · identical charged forward budgets")
    fig.savefig(output / "all-analytic-cases.png", dpi=170)
    plt.close(fig)
    reference.write_csv(output / "analytic-summary.csv", summaries)
    table = "".join(
        f'<tr><td>{escape(row["policy"])}</td><td>{row["cases"]}</td>'
        f'<td>{100 * row["deadline_miss_fraction"]:.4f}%</td>'
        f'<td>{100 * row["unresolved_at_horizon_fraction"]:.4f}%</td>'
        f'<td>{row["recovered_only_created_to_known_p99_ms"]:.3f}</td></tr>'
        for row in summaries)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mixed-degree causal repair screen</title><style>
body{max-width:1200px;margin:30px auto;padding:20px;font:16px/1.5 system-ui;color:#213547}
img{width:100%}.scroll{overflow:auto}table{border-collapse:collapse;width:100%}
td,th{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}a{color:#12688d}
</style><h1>Occasional sparse repairs within a dense causal schedule</h1>
<p>All cases use the actual GF256 coefficient decoder, fixed source arrivals, 1496-byte source packets,
1500-byte repair packets, 100 Mbps forward service, 15% IID erasures and the same 26/125 repair credit.
Every sixteenth repair covers the sender-unconfirmed prefix. Other repairs normally cover the most
recent 128 sources. Selected repairs use a configured low-degree subset of that same causal range.</p>
<p>The sparse positions are serial mod every = every − 1. Both peers derive their subset using a
separate PRNG seeded from the existing packet seed and the transmitted range. This schedule preserves
global repairs and uses no current receiver loss information. Delayed, lossy prefix feedback takes
70 ms plus charged reverse serialization. Forward loss traces are paired by packet position.</p>
<p>Every original measured source remains in the 35 ms denominator, including unresolved sources.
The capacity axis assumes one 1448-byte application record per source before further protocol costs.
TCP, full-frame reconstruction, ACK traffic, parity-payload arithmetic and CPU execution are outside
this screen. The P99 panel is conditional on recovery by the horizon. Complete tail state remains in
every raw case. Each point carries its analytical case ID. A star marks the lowest-cost mean among
configurations whose measured cohorts are fully recovered. All cases share one service ceiling.</p>
<img src="all-analytic-cases.png" alt="All analytical case points">
<div class="scroll"><table><thead><tr><th>Policy</th><th>Seeds</th><th>35 ms misses</th>
<th>Unresolved measured sources</th><th>Recovered-only P99 ms</th></tr></thead><tbody>__ROWS__</tbody></table></div>
<p><a href="analytic-cases.csv">Every analytical case</a> ·
<a href="analytic-summary.csv">Seed means and intervals</a> ·
<a href="manifest.json">Frozen source snapshots and task matrix</a> ·
<a href="validation-checks.json">Paired-trace and byte-budget checks</a>__RENDER_LINK__</p></html>'''
    rendering = output / "report-render-provenance.json"
    render_link = (' · <a href="report-render-provenance.json">Report-only rendering provenance</a>'
                   if rendering.is_file() else "")
    page = page.replace("__RENDER_LINK__", render_link)
    (output / "report.html").write_text(page.replace("__ROWS__", table))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    tasks = [dict(analytic_case_id=index * 3 + replication + 1, profile=profile,
                  seed=20261110 + replication, source_count=20000, warmup_sources=2000, tail_sources=2000)
             for index, profile in enumerate(profiles()) for replication in range(3)]
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(reference.__file__).resolve(),
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_mixed_degree_manifest", protocol_executions=0,
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
            print(f'{row["policy"]} seed {row["seed"]} miss {100*row["deadline_miss_fraction"]:.4f}%', flush=True)
    rows = [json.loads((cases / f"{task['analytic_case_id']:03d}.json").read_text()) for task in tasks]
    for seed in range(20261110, 20261113):
        paired = [row for row in rows if row["seed"] == seed]
        for field in ("erasure_trace_sha256", "forward_total_wire_bytes", "measured_sources"):
            assert len({row[field] for row in paired}) == 1
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not changed, changed
    checks = dict(all_analytical_cases=len(rows), paired_erasure_traces=True, fixed_forward_byte_budget=True,
                  original_source_deadlines=True, changed_during_run=changed)
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    reference.write_csv(args.out / "analytic-cases.csv", rows)
    report(args.out, rows)


if __name__ == "__main__":
    main()
