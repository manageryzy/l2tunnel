"""Coding-only checkpoint repair screen with causal delayed-prefix feedback."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from hashlib import sha256
from heapq import heappop, heappush
from html import escape
import json
from pathlib import Path
import platform
from random import Random

import numpy as np

from l2tunnel_sim.coding import Decoder
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci


PROFILES = [dict(name="Sliding W128 G16", checkpoint=0, burst=False),
            dict(name="Checkpoint B16 W128 G16", checkpoint=16, burst=False),
            dict(name="Checkpoint B32 W128 G16", checkpoint=32, burst=False),
            dict(name="Checkpoint burst B32 W128 G16", checkpoint=32, burst=True)]
SEEDS = [20261110, 20261111, 20261112, 20261113, 20261114]
SOURCE_MS, REPAIR_MS = 1496 * 8 / 100000, 1500 * 8 / 100000
ARRIVAL_MS = SOURCE_MS + .208 * REPAIR_MS


def support(profile, next_source, sender_base, repair_serial, final=False):
    if repair_serial % 16 == 0:
        return sender_base, next_source
    checkpoint = profile["checkpoint"]
    end = (next_source // checkpoint) * checkpoint if checkpoint else next_source
    if not end or final:
        end = next_source
    return max(sender_base, end - 128), end


def execute(task):
    profile, count = task["profile"], task["source_count"]
    forward_rng, reverse_rng = Random(task["seed"]), Random(task["seed"] ^ 0xFED123)
    decoder = Decoder()
    known_at = np.full(count, np.inf)
    queue_delay = np.zeros(count)
    sender_base, receiver_prefix, receiver_high = 0, 0, 0
    now, last_report = 0., -5.
    pending_feedback, reports = [], 0
    delivered_reports, lost_reports, credit, repair_serial = 0, 0, 0, 0
    supports = Counter()
    erasure_hash = sha256()
    minimum_feedback_age = np.inf

    def receive_feedback():
        nonlocal sender_base, delivered_reports, minimum_feedback_age
        while pending_feedback and pending_feedback[0][0] <= now:
            due, prefix, generated = heappop(pending_feedback)
            sender_base = max(sender_base, prefix)
            delivered_reports += 1
            minimum_feedback_age = min(minimum_feedback_age, due - generated)

    def receive_equation(equation, finish, high):
        nonlocal receiver_prefix, receiver_high, last_report, reports, lost_reports
        receiver_high = max(receiver_high, high)
        for symbol in decoder.insert(equation):
            known_at[symbol] = finish
        while receiver_prefix in decoder.known:
            receiver_prefix += 1
        if finish - last_report >= 5:
            last_report = finish
            reports += 1
            if reverse_rng.random() < .15:
                lost_reports += 1
            else:
                # Receiver clock is shifted by the fixed 35 ms propagation.
                # Feedback reaches the sender after both 35 ms legs plus its
                # charged 46-byte serialization on the 10 Mbps reverse link.
                due = finish + 70 + 46 * 8 / 10000
                heappush(pending_feedback, (due, receiver_prefix, finish))

    def erased():
        lost = forward_rng.random() < .15
        erasure_hash.update(bytes([lost]))
        return lost

    for source in range(count):
        created = source * ARRIVAL_MS
        now = max(now, created)
        receive_feedback()
        queue_delay[source] = now - created
        now += SOURCE_MS
        if not erased():
            receive_equation({source: 1}, now, source + 1)
        credit += 26
        release_repairs = (not profile["burst"] or (source + 1) % profile["checkpoint"] == 0 or source + 1 == count)
        if release_repairs:
            while credit >= 125:
                credit -= 125
                receive_feedback()
                repair_serial += 1
                start, end = support(profile, source + 1, sender_base, repair_serial, final=source + 1 == count)
                assert 0 <= start < end <= source + 1
                supports[end - start] += 1
                now += REPAIR_MS
                if not erased():
                    packet_seed = repair_serial * 2654435761 & 0xFFFFFFFF
                    receive_equation({symbol: coefficient(packet_seed, symbol) for symbol in range(start, end)}, now, end)
    selected = np.arange(task["warmup_sources"], count - task["tail_sources"])
    delay = known_at[selected] - selected * ARRIVAL_MS
    finite = np.isfinite(delay)
    assert repair_serial == count * 26 // 125
    assert minimum_feedback_age >= 70
    return dict(task, record_kind="analytic_causal_checkpoint_case", policy=profile["name"],
                measured_sources=len(selected), repair_packets=repair_serial, repair_per_source=repair_serial / count,
                source_ip_bytes=1496, repair_ip_bytes=1500, feedback_ip_bytes=46,
                forward_total_wire_bytes=count * 1496 + repair_serial * 1500,
                reverse_feedback_packets=reports, reverse_feedback_wire_bytes=reports * 46,
                lost_feedback_packets=lost_reports, delivered_feedback_reports=delivered_reports,
                minimum_feedback_age_ms=minimum_feedback_age,
                ideal_application_service_ceiling_mbps=1448 * 8 / ARRIVAL_MS / 1000,
                coding_deadline_ms=35, deadline_miss_fraction=float(np.mean(delay > 35)),
                unresolved_at_horizon_fraction=float(np.mean(~finite)),
                recovered_only_created_to_known_p99_ms=float(np.percentile(delay[finite], 99)),
                unconditional_created_to_known_p99_ms=float(np.percentile(delay, 99)) if finite.mean() > .99 else None,
                sender_queue_p99_ms=float(np.percentile(queue_delay[selected], 99)),
                maximum_source_queue_ms=float(queue_delay.max()), erasure_trace_sha256=erasure_hash.hexdigest(),
                final_known_sources=len(decoder.known), final_receiver_prefix=receiver_prefix,
                final_sender_confirmed_prefix=sender_base, remaining_decoder_rows=len(decoder.rows),
                largest_repair_support=max(supports), support_length_histogram=dict(supports))


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key:json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
                         for key,value in row.items()} for row in rows)


def summarize(rows):
    result = []
    for profile in PROFILES:
        group = [row for row in rows if row["policy"] == profile["name"]]
        entry = dict(record_kind="analytic_checkpoint_summary", policy=profile["name"], n=len(group))
        for metric in ("deadline_miss_fraction", "unresolved_at_horizon_fraction", "recovered_only_created_to_known_p99_ms", "sender_queue_p99_ms"):
            value = mean_ci([row[metric] for row in group])
            entry[metric] = value["mean"]
            entry[metric + "_ci_low"], entry[metric + "_ci_high"] = value["ci_low"], value["ci_high"]
        result.append(entry)
    return result


def render(output, rows, summary):
    table = []
    for row in summary:
        table.append("<tr>" + "".join(f"<td>{value}</td>" for value in
            (escape(row["policy"]), row["n"], f'{100*row["deadline_miss_fraction"]:.4f}%',
             f'[{100*row["deadline_miss_fraction_ci_low"]:.4f}, {100*row["deadline_miss_fraction_ci_high"]:.4f}]%',
             f'{100*row["unresolved_at_horizon_fraction"]:.4f}%',
             f'{row["recovered_only_created_to_known_p99_ms"]:.3f}', f'{row["sender_queue_p99_ms"]:.3f}')) + "</tr>")
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>Checkpoint repair screen</title>
<style>body{max-width:1120px;margin:35px auto;padding:20px;font:16px/1.5 system-ui;color:#203748}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:9px;border-bottom:1px solid #ccd5df}th{background:#edf3f8}code{background:#edf3f8}.notice{padding:16px;background:#fff0d8;border-left:5px solid #a35e20}a{color:#12688d}</style>
<h1>Checkpoint-prefix repair scheduling at a fixed 20.8% repair budget</h1>
<p class="notice">Every point is a coding-only analytical sample using the actual GF256 coefficient Decoder. Application capacity is an optimistic service ceiling. TCP, record reconstruction, reverse TCP ACK traffic, coded payload arithmetic and CPU time are outside this probe. Protocol executions are zero.</p>
<h2>Concrete causal policy</h2>
<p>The matched control repairs the most recent 128 transmitted source symbols. The checkpoint variants instead set <code>end = floor(next_source/B)·B</code> and repair <code>[max(confirmed_prefix,end−128),end)</code>, with B=16 or B=32. The support endpoint stays fixed between checkpoint boundaries, allowing consecutive equations to resolve an older subsystem without mixing every newly arriving source into it. Startup uses the available prefix. Every sixteenth repair covers the full sender-unconfirmed prefix through next_source. The final partial checkpoint is included.</p>
<p>A 26/125 integer credit after each source fixes the total repair/source ratio at 20.8%. The regular checkpoint variants emit repair credit immediately. The burst variant holds that same credit until each 32-source checkpoint. All decisions use transmitted source IDs, static configuration, repair serials and delayed confirmed-prefix feedback. Receiver rank or loss knowledge is never read directly by the scheduler.</p>
<h2>Common arrivals, feedback and denominator</h2>
<p>Every source arrives at the same exogenous interval of <code>(1496+0.208·1500)·8/100000 = 0.14464 ms</code>. Source and repair IP sizes are charged as 1496 and 1500 bytes at 100 Mbps. The source remains in the sender queue until transmitted. Its recovery delay begins at its common creation time, so repair bursts cannot hide queueing by resetting the clock. One 1448-byte application payload per source would give an optimistic 80.0885 Mbps service ceiling before record overhead, TCP effects or additional transmissions.</p>
<p>Receiver feedback is emitted after a received packet when at least 5 ms has passed since the previous report. Each report charges 46 IP bytes on the 10 Mbps reverse path, suffers independent 15% erasure, and reaches the sender only after 70 ms plus 0.0368 ms serialization. The receiver's forward clock is translated by the common propagation delay, preserving this feedback causality. Only received prefix reports advance sender state. All original sources remain in the receiver algebra and the deadline denominator, including symbols that expire from local repair bands. Every repair packet remains in the fixed forward budget.</p>
<p>Each configuration uses five paired seeds. Every seed includes __COUNT__ source arrivals, with __WARM__ warmup sources, __MEASURED__ measured sources and __TAIL__ trailing sources. Later sources provide the same trailing service interval for each policy. Undecoded sources count as deadline misses. Conditional P99 includes only sources identified by the horizon. Complete-source recovery and the 35 ms miss fraction govern interpretation.</p>
<table><thead><tr><th>Policy</th><th>Seeds</th><th>35 ms misses</th><th>95% seed interval</th><th>Unresolved</th><th>Recovered-only creation-to-known P99 ms</th><th>Sender queue P99 ms</th></tr></thead><tbody>__ROWS__</tbody></table>
<p>The 35 ms threshold grants the entire excess over 70 ms base RTT to forward recovery. Actual all-segment ACK completion also includes reverse ACK and full-record delivery constraints. These data support choosing a protocol candidate only if the complete denominator improves under the same byte budget.</p>
<p><a href="analytic-cases.csv">Every analytical sample</a> · <a href="analytic-summary.csv">Means and intervals</a> · <a href="manifest.json">Assumptions and source snapshots</a> · <a href="validation-checks.json">Finite checks</a></p></html>'''
    first = rows[0]
    for key, value in (("ROWS", "".join(table)), ("COUNT", first["source_count"]),
                       ("WARM", first["warmup_sources"]), ("MEASURED", first["measured_sources"]), ("TAIL", first["tail_sources"])):
        page = page.replace("__" + key + "__", str(value))
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-count", type=int, default=50000)
    parser.add_argument("--warmup-sources", type=int, default=5000)
    parser.add_argument("--tail-sources", type=int, default=5000)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "cases").mkdir(exist_ok=True)
    tasks = [dict(analytic_case_id=index * len(SEEDS) + seed_index + 1, profile=profile, seed=seed,
                  source_count=args.source_count, warmup_sources=args.warmup_sources, tail_sources=args.tail_sources)
             for index, profile in enumerate(PROFILES) for seed_index, seed in enumerate(SEEDS)]
    rows = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in tasks]):
            row = future.result()
            rows.append(row)
            (args.out / "cases" / f"{row['analytic_case_id']:03d}.json").write_text(json.dumps(row, indent=2))
            print(f"Saved {row['analytic_case_id']:02d} {row['policy']} miss={100*row['deadline_miss_fraction']:.3f}%", flush=True)
    rows.sort(key=lambda row:row["analytic_case_id"])
    summary = summarize(rows)
    write_csv(args.out / "analytic-cases.csv", rows)
    write_csv(args.out / "analytic-summary.csv", summary)
    for seed in SEEDS:
        group = [row for row in rows if row["seed"] == seed]
        assert len({row["erasure_trace_sha256"] for row in group}) == 1
        assert len({row["forward_total_wire_bytes"] for row in group}) == 1
        assert len({row["measured_sources"] for row in group}) == 1
    checks = dict(paired_forward_packet_position_erasure_traces=True, exact_fixed_forward_byte_budget=True,
                  same_creation_times_and_source_cohort=True, delayed_feedback_minimum_70ms=True,
                  all_measured_unresolved_sources_retained=True)
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2))
    simulator = Path(__file__).resolve().parents[1]
    paths = [Path(__file__).resolve(), simulator / "src/l2tunnel_sim/coding.py", simulator / "src/l2tunnel_sim/compact.py"]
    snapshots = args.out / "sources"
    snapshots.mkdir(exist_ok=True)
    for path in paths:
        (snapshots / path.name).write_bytes(path.read_bytes())
    manifest = dict(record_kind="analytic_checkpoint_manifest", protocol_executions=0, analytic_cases=len(rows),
                    analytic_tasks=tasks, python=platform.python_version(),
                    sources={str(path):sha256(path.read_bytes()).hexdigest() for path in paths},
                    assumptions=["fixed 100 Mbps IP forward service", "1496-byte sources and 1500-byte repairs",
                                 "fixed source arrivals, independent of sender queue", "15% IID forward and feedback loss",
                                 "actual GF256 coefficient recovery, no byte-vector arithmetic", "no TCP or TCP ACK traffic"])
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    render(args.out, rows, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
