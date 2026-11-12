"""Analytic coding-only finite-window GF256 deadline screen, with causal senders."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from fractions import Fraction
from hashlib import sha256
from html import escape
import json
from pathlib import Path
import platform
from random import Random
from time import perf_counter

import numpy as np
from scipy.stats import binom

from l2tunnel_sim.coding import Decoder
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci


SEEDS = [20261110, 20261111, 20261112, 20261113, 20261114]
METRICS = ("symbol_deadline_miss_fraction", "symbol_unresolved_at_horizon_fraction",
           "conditional_coding_p99_ms", "global_order_deadline_miss_fraction",
           "oldest_protected_symbol_released_before_all_unknowns_fraction")


def policies():
    result = [dict(name="Dense", window=0, ratio=.20)]
    result.extend(dict(name=f"Band W{w}", window=w, ratio=.20) for w in (16, 32, 64, 96, 128, 192, 256))
    result.extend(dict(name=f"Aged W{w} offset{age}", window=w, age=age, ratio=.20)
                  for w, age in ((64, 32), (128, 32)))
    result.extend(dict(name=f"Mixed W{w} long{long} every4", window=w, long_window=long,
                       long_every=4, ratio=.20) for w, long in ((32, 256), (64, 256), (64, 0)))
    result.extend(dict(name=f"Causal generation K{k}", generation=k, window=0, ratio=.20)
                  for k in (40, 80, 160, 240))
    result.extend(dict(name=f"Band W{w} r19", window=w, ratio=.19) for w in (64, 128, 256))
    return result


def repair_range(profile, next_source, repair_serial):
    """Use only sender-owned counters and static policy parameters."""
    generation = profile.get("generation", 0)
    if generation:
        return ((next_source - 1) // generation) * generation, next_source
    window = profile["window"]
    if profile.get("long_every") and repair_serial % profile["long_every"] == 0:
        window = profile["long_window"]
    end = max(1, next_source - profile.get("age", 0))
    return max(0, end - window) if window else 0, end


def execute(task):
    started = perf_counter()
    profile = task["profile"]
    rng, decoder = Random(task["seed"]), Decoder()
    count = task["source_symbols"]
    revealed = np.full(count, np.inf)
    born = np.zeros(count)
    slot, repair_serial, credit = 0, 0, 0
    ratio = Fraction(str(profile["ratio"]))
    early_oldest, eligible_oldest = 0, 0
    erasure_digest = sha256()
    for source in range(count):
        born[source] = slot
        erased = rng.random() < task["loss_rate"]
        erasure_digest.update(bytes([erased]))
        if not erased:
            for symbol in decoder.insert({source: 1}):
                revealed[symbol] = slot
        slot += 1
        credit += ratio.numerator
        while credit >= ratio.denominator:
            credit -= ratio.denominator
            repair_serial += 1
            start, end = repair_range(profile, source + 1, repair_serial)
            erased = rng.random() < task["loss_rate"]
            erasure_digest.update(bytes([erased]))
            if not erased:
                unknown_before = [index for index in range(start, end) if index not in decoder.known]
                seed = (repair_serial * 2654435761) & 0xffffffff
                newly_known = decoder.insert({index: coefficient(seed, index) for index in range(start, end)})
                for symbol in newly_known:
                    revealed[symbol] = slot
                if unknown_before:
                    eligible_oldest += 1
                    if unknown_before[0] in newly_known and any(index not in decoder.known for index in unknown_before):
                        early_oldest += 1
            slot += 1
    selection = slice(task["warmup_symbols"], task["source_symbols"] - task["tail_symbols"])
    delays = (revealed - born)[selection] * task["slot_ms"]
    measurable = np.isfinite(delays)
    global_order = (np.maximum.accumulate(revealed) - born)[selection] * task["slot_ms"]
    result = dict(task, record_kind="analytic_coding_monte_carlo", policy=profile["name"],
                  measured_symbols=len(delays), scheduled_source_packets=count, scheduled_repair_packets=repair_serial,
                  repair_per_source=repair_serial / count, erasure_trace_sha256=erasure_digest.hexdigest(),
                  symbol_deadline_miss_fraction=float(np.mean(delays > task["coding_deadline_ms"])),
                  symbol_unresolved_at_horizon_fraction=float(np.mean(~measurable)),
                  conditional_coding_p99_ms=float(np.percentile(delays[measurable], 99)) if measurable.any() else None,
                  unconditional_coding_p99_ms=float(np.percentile(delays, 99)) if measurable.mean() > .99 else None,
                  global_order_deadline_miss_fraction=float(np.mean(global_order > task["coding_deadline_ms"])),
                  oldest_protected_symbol_released_before_all_unknowns_fraction=early_oldest / eligible_oldest if eligible_oldest else 0,
                  unresolved_degrees_of_freedom_at_horizon=count - len(decoder.known) - len(decoder.rows),
                  compute_seconds=perf_counter() - started)
    return result


def write_csv(path, rows):
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=keys)
        writer.writeheader()
        writer.writerows({key: json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
                          for key, value in row.items()} for row in rows)


def summarize(rows):
    result = []
    for name in dict.fromkeys(row["policy"] for row in rows):
        group = [row for row in rows if row["policy"] == name]
        entry = dict(record_kind="analytic_coding_summary", policy=name, profile=group[0]["profile"], n=len(group))
        for key in METRICS:
            stats = mean_ci([row[key] for row in group if row[key] is not None])
            entry[key] = stats["mean"]
            entry[key + "_ci_low"], entry[key + "_ci_high"] = stats["ci_low"], stats["ci_high"]
        result.append(entry)
    return sorted(result, key=lambda row: row["symbol_deadline_miss_fraction"])


def exact_references():
    rows = []
    for sources in range(5, 244):
        repairs, loss = sources // 5, .15
        rows.append(dict(record_kind="analytic_exact_mds_reference", sources=sources, repairs=repairs,
                    source_plus_repair_slots=sources + repairs, total_span_ms=(sources + repairs) * .12,
                    ideal_mds_erased_source_failure=loss * float(binom.sf(repairs - 1, sources + repairs - 1, loss))))
    return rows


def html_report(output, summary, exact, tasks):
    def cells(row):
        return (f"<td>{escape(row['policy'])}</td><td>{row['n']}</td>"
                f"<td>{100 * row['symbol_deadline_miss_fraction']:.3f}%</td>"
                f"<td>[{100 * row['symbol_deadline_miss_fraction_ci_low']:.3f}, {100 * row['symbol_deadline_miss_fraction_ci_high']:.3f}]%</td>"
                f"<td>{100 * row['symbol_unresolved_at_horizon_fraction']:.3f}%</td>"
                f"<td>{row['conditional_coding_p99_ms']:.3f}</td>")
    best = min(exact, key=lambda row: row["ideal_mds_erased_source_failure"])
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>Causal finite-window coding analysis</title>
<style>body{font:16px/1.5 system-ui;max-width:1250px;margin:30px auto;padding:20px;color:#203447}table{border-collapse:collapse;font-size:13px;width:100%}td,th{border-bottom:1px solid #ccd5df;padding:8px}th{background:#edf3f8}a{color:#126b98}code{background:#edf3f8;padding:2px}.notice{padding:15px;background:#fff3dc;border-left:5px solid #af6a19}</style>
<h1>Causal bounded-window coding under a 35 ms recovery budget</h1>
<p class="notice">Every case in this report is an analytical coding-only experiment. The actual GF256 coefficient decoder runs over a sampled IID erasure trace. TCP, reverse ACKs, congestion control, payload arithmetic, byte framing, codec CPU and sender packet queues are outside this model. The protocol experiment count is zero.</p>
<h2>Policy and sender causality</h2>
<p>The smallest implementation is a last-W source-symbol repair band. Upon each repair opportunity, the sender emits a seeded GF256 combination of source IDs <code>[max(0, next_source − W), next_source)</code>. It chooses the window using its own source sequence and a fixed configuration. A repair never contains a future source. The screen also includes delayed-age bands, deterministic short/long mixes, and causal generations that reset their range at a fixed source boundary. All policies use the same integer-credit repair scheduler. Erasures are paired by transmitted-packet position for equal repair ratios. The sender's scheduling and coefficient construction are independent of receiver state.</p>
<p>The receiver passes each received source or repair equation to the existing reduced-row GF256 Decoder. Any newly identifiable symbol receives its actual decode time, even while other symbols remain unknown. A received systematic source is immediately identifiable. __SAMPLE__ A 1500-byte packet at 100 Mbps occupies 0.12 ms. The coding deadline is 35 ms. Late and unresolved symbols remain in the deadline-miss denominator. The displayed conditional P99 covers only symbols recovered by the horizon, so the explicit miss and unresolved columns govern interpretation. Seed-mean Student intervals are left unbounded, and may extend beyond the probability domain in small samples.</p>
<p>Independent symbol delivery provides the optimistic input to per-channel record reconstruction. A packet can hold part of several records, and a delta-compressed record depends on its channel's preceding context. The eventual tunnel must therefore reconstruct complete records and preserve each channel's order. Coding-only source-symbol delay is a distinct metric from TCP timestamp RTT or application completion RTT.</p>
<h2>Analytical cases</h2>
<table><thead><tr><th>Policy</th><th>Seeds</th><th>35 ms misses</th><th>95% seed-mean CI</th><th>Unresolved at horizon</th><th>Recovered-only coding P99 ms</th></tr></thead><tbody>__ROWS__</tbody></table>
<h2>Finite-deadline limitation of independent small generations</h2>
<p>For a systematic ideal MDS generation containing k sources and r repairs, a source is erased and remains unavailable after the generation with probability <code>p × P[Binomial(k+r−1,p) ≥ r]</code>. This formula grants perfect independence of every useful parity equation. For k from 5 through 243, r=floor(k/5), repair/source at most 20%, and generation transmission span at most 35 ms, the best erased-source failure probability is __BEST__ for k=__K__, r=__R__. This already exceeds the 1% per-source target before source collection, ACK loss or record-order delays. The conclusion applies to independent generations under this stated packet/time model.</p>
<p>The 288-symbol reference grants ideal MDS behavior beyond the current 256-symbol systematic Cauchy implementation limit. It is an optimistic analytical reference and does not represent an executed GF256 block-code configuration.</p>
<p>For a bounded band, a second exact necessary failure event is an erased source together with every repair containing its coefficient erased. Its probability is <code>p^(m+1)</code> when exactly m repairs protect that source. With one repair per five sources, W=5 gives 2.25% unavoidable failures at p=.15. Larger windows reduce this event, while coupled unknowns impose additional constraints. Consequently, shrinking W can reduce some observed coding delays while increasing permanently unresolved data. The two quantities must be inspected together.</p>
<h2>Primary-source findings</h2>
<p>RFC 8681 describes window IDs, seed-derived coefficients and recovery as soon as a full-rank subsystem identifies a lost symbol. It also supports assigning recovered ADUs to application flows. These mechanisms support a bounded-window implementation and independent channel reconstruction. Its expiry-oriented media behavior needs a reliable fallback for this complete-L2 task. <a href="https://www.rfc-editor.org/rfc/rfc8681.html#section-6.2">RFC 8681 §6.2</a></p>
<p>Su and colleagues analyze random linear streaming codes with finite memory and finite deadlines under IID symbol erasures in the large-field regime. Their framework evaluates individual decodability through the receiving matrix row space and treats memory, reliability and delay jointly. It motivates an exact GF256 finite-window screen while preserving the distinction between large-field analysis and this finite-field implementation. <a href="https://engineering.purdue.edu/~chihw/pub_pdf/22J_IT_RLSC.pdf">Su et al., IEEE TIT 2022</a> · <a href="https://engineering.purdue.edu/~chihw/pub_pdf/26J_streaming-code-part2.pdf">Author-hosted follow-up analysis</a></p>
<p>Fong and colleagues give delay-constrained convolutional constructions for bounded sliding-window erasures. Their structured matrices can recover earlier symbols before the entire block is available. IID losses occasionally violate the bounded-erasure premise, so those guarantees require an explicit statistical mapping before adoption here. A subpacket convolutional implementation would additionally need exact field arithmetic and charged subpacket/framing metadata. <a href="https://arxiv.org/pdf/1801.04241">Fong et al.</a></p>
<h2>Wire budget and implementation decision</h2>
<p>The existing repair format carries a 32-bit first source ID, 16-bit window length, 32-bit seed and two-byte type/version, totaling 12 bytes after 28-byte IPv4/UDP. The coded valid-length field adds two bytes, leaving at most 1458 source-record bytes inside MTU 1500. A bounded window reuses these existing fields. Multiplexing, resynchronization, per-record headers and reversible codec bytes still consume that source budget. Reliable fallback and forward feedback increase transmitted packet count. The strict gate must use all forward datagrams divided by completed application records, with baseline source expansion counted explicitly.</p>
<p>The implementation candidate is bounded-window GF256 with immediate symbol availability and independent per-channel record delivery. The table identifies which W values merit protocol tests and which lose too many symbols. Every unresolved source remains eligible for charged, feedback-driven reliable recovery. The 35 ms coding interval is shorter than one 70 ms feedback RTT, so current-loss feedback arrives too late to choose a repair that meets the original source's 105 ms ACK-completion deadline. Prior feedback may update channel estimates or remove older acknowledged data.</p>
<p>These finite samples provide policy screening. A strategy that meets the source-symbol deadline still requires full TCP and byte-framed tunnel validation. The 80 Mbps application gate and strict 20% packet gate remain separately measured constraints. The tested random bands and mixes do not establish a universal finite-deadline converse for structured convolutional codes. At the historical 20% loss rate, even ideal capacity after only IPv4/UDP overhead is 100 × 0.8 × 1472/1500 = 78.507 Mbps, below the 80 Mbps application target. The current 15% loss case has a feasible asymptotic bandwidth envelope, while finite-delay feasibility remains unresolved.</p>
<p><a href="analytic-cases.csv">All sampled analytical cases</a> · <a href="analytic-summary.csv">Seed means and intervals</a> · <a href="exact-generation-reference.csv">Exact generation reference</a> · <a href="pilot-screen.csv">Earlier four-case pilot</a> · <a href="manifest.json">Assumptions and source hashes</a></p></html>'''
    page = page.replace("__ROWS__", "".join("<tr>" + cells(row) + "</tr>" for row in summary))
    task = tasks[0]
    measured = task["source_symbols"] - task["warmup_symbols"] - task["tail_symbols"]
    sample = (f'Each tested stream has {task["source_symbols"]:,} sources, '
              f'{task["warmup_symbols"]:,} warmup sources, {measured:,} measured sources '
              f'and {task["tail_symbols"]:,} trailing sources, with {summary[0]["n"]} independent seeds.')
    page = page.replace("__SAMPLE__", sample)
    page = page.replace("__BEST__", f"{100 * best['ideal_mds_erased_source_failure']:.3f}%")
    page = page.replace("__K__", str(best["sources"])).replace("__R__", str(best["repairs"]))
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--source-symbols", type=int, default=10000)
    parser.add_argument("--warmup-symbols", type=int, default=2000)
    parser.add_argument("--tail-symbols", type=int, default=2000)
    parser.add_argument("--policy", action="append", help="Exact policy name, repeatable")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "cases").mkdir(exist_ok=True)
    tasks = []
    selected = [profile for profile in policies() if not args.policy or profile["name"] in args.policy]
    if not selected or args.warmup_symbols + args.tail_symbols >= args.source_symbols:
        parser.error("Select existing policies and a positive measurement interval")
    for profile in selected:
        for seed in SEEDS:
            tasks.append(dict(analytic_case_id=len(tasks) + 1, profile=profile, seed=seed, loss_rate=.15,
                              source_symbols=args.source_symbols, warmup_symbols=args.warmup_symbols,
                              tail_symbols=args.tail_symbols,
                              slot_ms=.12, coding_deadline_ms=35))
    rows = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in tasks]):
            row = future.result()
            rows.append(row)
            (args.out / "cases" / f"{row['analytic_case_id']:04d}.json").write_text(json.dumps(row, indent=2, allow_nan=False))
            if len(rows) % 5 == 0:
                print(f"Saved {len(rows)}/{len(tasks)} analytical cases", flush=True)
    rows.sort(key=lambda row: row["analytic_case_id"])
    summary, exact = summarize(rows), exact_references()
    write_csv(args.out / "analytic-cases.csv", rows)
    write_csv(args.out / "analytic-summary.csv", summary)
    write_csv(args.out / "exact-generation-reference.csv", exact)
    pilot = [dict(record_kind="analytic_pilot", seed=20261110, source_symbols=4000,
                  warmup_symbols=500, measured_symbols=3000, tail_symbols=500, loss_rate=.15,
                  repair_per_source=.20, window=window, symbol_deadline_miss_fraction=late,
                  symbol_unresolved_at_horizon_fraction=unresolved)
             for window, late, unresolved in ((16, .06466666666666666, .06466666666666666),
                                              (64, .029333333333333333, .016),
                                              (256, .03233333333333333, 0), (0, .03233333333333333, 0))]
    write_csv(args.out / "pilot-screen.csv", pilot)
    simulator = Path(__file__).resolve().parents[1]
    source_paths = [Path(__file__).resolve(), simulator / "src/l2tunnel_sim/coding.py",
                    simulator / "src/l2tunnel_sim/compact.py"]
    manifest = dict(record_kind="analytical_study_manifest", protocol_executions=0, analytic_cases=len(rows),
                    analytic_pilot_cases=4, analytic_tasks=tasks, python=platform.python_version(),
                    sources={str(path): sha256(path.read_bytes()).hexdigest() for path in source_paths},
                    primary_sources=["https://www.rfc-editor.org/rfc/rfc8681.html",
                                     "https://engineering.purdue.edu/~chihw/pub_pdf/22J_IT_RLSC.pdf",
                                     "https://engineering.purdue.edu/~chihw/pub_pdf/26J_streaming-code-part2.pdf",
                                     "https://arxiv.org/pdf/1801.04241"],
                    limitations=["coding-only, no TCP or reverse path", "rank equations without coded payload arithmetic",
                                 "full 1500-byte packet slot charged, record mapping excluded", "finite sample, no universal converse"])
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    snapshot = args.out / "sources"
    snapshot.mkdir(exist_ok=True)
    for path in source_paths:
        (snapshot / path.name).write_bytes(path.read_bytes())
    html_report(args.out, summary, exact, tasks)
    print("Analytical finite-window screen complete", flush=True)


if __name__ == "__main__":
    main()
