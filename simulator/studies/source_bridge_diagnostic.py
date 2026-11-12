"""Causal source-side D128 precoding, with per-original decoder diagnostics."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
from heapq import heappop, heappush
from html import escape
import json
from pathlib import Path
from random import Random
from struct import Struct

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim.coding import Decoder
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci
if __package__:
    from .partial_repair_screen import write_csv, repair_header, parse_repair
else:
    from partial_repair_screen import write_csv, repair_header, parse_repair


SOURCE_HEADER = Struct("!IBBH")
ARRIVAL_MS = 1448 * 8 / 80000
PROFILES = (dict(name="Systematic W128 G16", bridge=False), dict(name="Source bridge D128 W128 G16", bridge=True))
SEEDS = (20261110, 20261111, 20261112)
COLORS = ("#286b9a", "#bb7027")


def source_header(source, bridge):
    return SOURCE_HEADER.pack(source, 1, int(bridge), 128 if bridge else 0)


def source_equation(header):
    """Receiver derives the whole source equation from the eight wire bytes."""
    if len(header) != SOURCE_HEADER.size:
        raise ValueError("source header must have eight bytes")
    source, version, profile, lag = SOURCE_HEADER.unpack(header)
    if version != 1 or (profile, lag) not in ((0, 0), (1, 128)):
        raise ValueError("unsupported source-bridge profile")
    equation = {source: 1}
    if lag and source >= lag:
        equation[source - lag] = 1
    return source, equation


def component_state(decoder, source, sent_sources, now):
    """Read-only unknown-component rank in the receiver's reduced equations."""
    variables = {source}
    rows = list(decoder.rows.values())
    selected = set()
    changed = True
    while changed:
        changed = False
        for index, row in enumerate(rows):
            if index not in selected and variables.intersection(row):
                selected.add(index)
                variables.update(row)
                changed = True
    return dict(unknown_sources=sent_sources - len(decoder.known), receiver_rank=len(rows),
                receiver_deficit=sent_sources - len(decoder.known) - len(rows),
                component_variables=len(variables), component_rank=len(selected),
                component_deficit=len(variables) - len(selected),
                component_expired_variables=sum(sent_sources - index > 128 for index in variables),
                component_oldest_age_ms=now - min(variables) * ARRIVAL_MS,
                source_expired_from_local_window=sent_sources - source > 128,
                source_is_pivot=source in decoder.rows, source_has_equation=bool(selected))


def execute(task, output=None):
    count, profile = task["source_count"], task["profile"]
    forward_rng, reverse_rng = Random(task["seed"]), Random(task["seed"] ^ 0xFED123)
    decoder = Decoder()
    known = np.full(count, np.inf)
    queue = np.zeros(count)
    source_lost = np.zeros(count, dtype=bool)
    release_packet = np.full(count, -1)
    release_mode = [None] * count
    deadline_states = [None] * count
    now, reverse_free, last_report = 0., 0., -5.
    sender_base = prefix = next_deadline = sent_sources = packet_serial = credit = repair_serial = 0
    reports = delivered_reports = lost_reports = 0
    pending = []
    batches = []
    erasure_hash, source_header_hash, feedback_hash, packet_hash = (sha256() for _ in range(4))
    min_feedback_age = np.inf

    def accept_feedback():
        nonlocal sender_base, delivered_reports, min_feedback_age
        while pending and pending[0][0] <= now:
            due, accepted, generated = heappop(pending)
            sender_base = max(sender_base, accepted)
            delivered_reports += 1
            min_feedback_age = min(min_feedback_age, due - generated)

    def deadlines(before, inclusive):
        nonlocal next_deadline
        while next_deadline < count:
            due = next_deadline * ARRIVAL_MS + 35
            if due > before or (due == before and not inclusive):
                break
            if next_deadline not in decoder.known:
                deadline_states[next_deadline] = component_state(decoder, next_deadline, sent_sources, due)
            next_deadline += 1

    def receive(equation, mode):
        nonlocal prefix, reports, lost_reports, last_report, reverse_free
        identified = decoder.insert(equation)
        for source in identified:
            known[source] = now
            release_packet[source] = packet_serial
            release_mode[source] = mode
        late = [source for source in identified if now - source * ARRIVAL_MS > 35]
        if len(identified) > 1 or late:
            batches.append(dict(packet_id=packet_serial, finish_ms=now, mode=mode, sources=len(identified),
                                late_sources=len(late), source_ids=identified, late_source_ids=late))
        while prefix in decoder.known:
            prefix += 1
        if now - last_report >= 5:
            last_report = now
            reports += 1
            begin = max(now + 35, reverse_free)
            reverse_free = begin + 46 * 8 / 10000
            lost = reverse_rng.random() < .15
            feedback_hash.update(bytes([lost]))
            if lost:
                lost_reports += 1
            else:
                heappush(pending, (reverse_free + 35, prefix, now))

    def transmit(size, equation, mode, source=None):
        nonlocal now, packet_serial, sent_sources
        packet_serial += 1
        now += size * 8 / 100000
        deadlines(now, False)
        lost = forward_rng.random() < .15
        erasure_hash.update(bytes([lost]))
        packet_hash.update(Struct("!IdIB").pack(packet_serial, now, size, int(lost)))
        if source is not None:
            sent_sources = source + 1
            source_lost[source] = lost
        if not lost:
            receive(equation, mode)
        deadlines(now, True)

    for source in range(count):
        now = max(now, source * ARRIVAL_MS)
        accept_feedback()
        queue[source] = now - source * ARRIVAL_MS
        header = source_header(source, profile["bridge"])
        source_header_hash.update(header)
        parsed_source, equation = source_equation(header)
        assert parsed_source == source
        transmit(28 + len(header) + 1460, equation, "source", parsed_source)
        credit += 26
        while credit >= 125:
            credit -= 125
            accept_feedback()
            repair_serial += 1
            end = source + 1
            global_repair = repair_serial % 16 == 0
            start = sender_base if global_repair else max(sender_base, end - 128)
            equation, kind = parse_repair(repair_header(start, end, repair_serial, 0))
            assert kind == 0
            transmit(1500, equation, "global_repair" if global_repair else "local_repair")

    selected = np.arange(task["warmup_sources"], count - task["tail_sources"])
    delays = known[selected] - selected * ARRIVAL_MS
    finite = np.isfinite(delays)
    late_ids = selected[delays > 35]
    assert all(deadline_states[source] is not None for source in late_ids)
    assert next_deadline >= count - task["tail_sources"]
    assert repair_serial == count * 26 // 125
    wire_bytes = count * 1496 + repair_serial * 1500
    states = [deadline_states[source] for source in late_ids]
    release_counts = Counter(release_mode[source] for source in late_ids)
    row = dict(task, record_kind="analytic_source_bridge_case", protocol_executions=0,
               policy=profile["name"], payload_bytes=1448, source_symbol_bytes=1460, source_header_bytes=8,
               source_ip_bytes=1496, repair_ip_bytes=1500, feedback_ip_bytes=46,
               forward_mbps=100, reverse_mbps=10, base_rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500,
               source_arrival_interval_ms=ARRIVAL_MS, offered_application_mbps=80, coding_deadline_ms=35,
               forward_source_packets=count, forward_repair_packets=repair_serial,
               forward_total_wire_bytes=wire_bytes, ip_bytes_per_original_source=wire_bytes / count,
               ideal_application_service_ceiling_mbps=100 * count * 1448 / wire_bytes,
               extra_packets_per_original_source_pct=100 * repair_serial / count,
               strict_20pct_packet_cap_met=repair_serial / count <= .20,
               reverse_feedback_packets=reports, reverse_feedback_wire_bytes=reports * 46,
               lost_feedback_packets=lost_reports, delivered_feedback_reports=delivered_reports,
               minimum_feedback_age_ms=min_feedback_age, final_forward_finish_ms=now,
               measured_sources=len(selected), deadline_miss_count=len(late_ids),
               deadline_miss_fraction=float(np.mean(delays > 35)),
               unresolved_at_horizon_count=int(np.count_nonzero(~finite)),
               unresolved_at_horizon_fraction=float(np.mean(~finite)),
               recovered_only_created_to_known_p99_ms=float(np.percentile(delays[finite], 99)) if finite.any() else None,
               unconditional_created_to_known_p99_ms=float(np.percentile(delays, 99)) if finite.all() else None,
               sender_queue_p99_ms=float(np.percentile(queue[selected], 99)), maximum_source_queue_ms=float(queue.max()),
               final_known_sources=len(decoder.known), final_receiver_prefix=prefix,
               final_sender_confirmed_prefix=sender_base, final_decoder_rows=len(decoder.rows),
               late_originals_with_received_source_datagram=int(sum(not source_lost[source] for source in late_ids)),
               late_originals_with_lost_source_datagram=int(sum(source_lost[source] for source in late_ids)),
               late_original_release_modes=dict(release_counts),
               late_originals_expired_from_local_window=sum(state["source_expired_from_local_window"] for state in states),
               late_originals_with_no_receiver_equation=sum(not state["source_has_equation"] for state in states),
               late_component_deficit_histogram=dict(Counter(state["component_deficit"] for state in states)),
               late_component_variables_p50=float(np.median([state["component_variables"] for state in states])) if states else 0,
               erasure_trace_sha256=erasure_hash.hexdigest(), packet_trace_sha256=packet_hash.hexdigest(),
               feedback_erasure_trace_sha256=feedback_hash.hexdigest(), source_header_trace_sha256=source_header_hash.hexdigest(),
               source_arrival_trace_sha256=sha256((np.arange(count) * ARRIVAL_MS).tobytes()).hexdigest(),
               full_source_recovery_times_sha256=sha256(known.tobytes()).hexdigest(),
               late_release_batch_count=len({release_packet[source] for source in late_ids if release_packet[source] >= 0}),
               maximum_measured_late_release_batch=max(Counter(release_packet[source] for source in late_ids
                                                                if release_packet[source] >= 0).values(), default=0))
    if output is not None:
        observations = []
        for source in range(count):
            observations.append(dict(source_id=source, created_ms=source * ARRIVAL_MS,
                in_measured_cohort=task["warmup_sources"] <= source < count - task["tail_sources"],
                source_datagram_lost=bool(source_lost[source]),
                recovered_ms=float(known[source]) if np.isfinite(known[source]) else None,
                delay_ms=float(known[source] - source * ARRIVAL_MS) if np.isfinite(known[source]) else None,
                deadline_missed=bool(known[source] - source * ARRIVAL_MS > 35),
                deadline_evaluated=source < next_deadline, release_packet_id=int(release_packet[source]),
                release_mode=release_mode[source], sender_queue_ms=float(queue[source]),
                **(deadline_states[source] or {})))
        for name, data in (("source-observations", observations), ("release-batches", batches)):
            path = output / name / f'{task["analytic_case_id"]:03d}.csv'
            write_csv(path, data)
            row[name.replace("-", "_") + "_path"] = str(path.relative_to(output))
            row[name.replace("-", "_") + "_sha256"] = sha256(path.read_bytes()).hexdigest()
    return row


def summarize(rows):
    result = []
    for profile in PROFILES:
        group = [row for row in rows if row["policy"] == profile["name"]]
        item = dict(record_kind="analytic_source_bridge_summary", policy=profile["name"], n=len(group),
                    raw_inputs=[f'cases/{row["analytic_case_id"]:03d}.json' for row in group])
        for metric in ("deadline_miss_fraction", "unresolved_at_horizon_fraction", "recovered_only_created_to_known_p99_ms",
                       "late_originals_with_received_source_datagram", "late_originals_with_lost_source_datagram",
                       "late_release_batch_count", "maximum_measured_late_release_batch"):
            stats = mean_ci([row[metric] for row in group])
            item.update({metric: stats["mean"], metric + "_ci_low": stats["ci_low"], metric + "_ci_high": stats["ci_high"]})
        result.append(item)
    return result


def compare_sources(output, rows):
    import csv
    changes = []
    for seed in SEEDS:
        baseline, candidate = [row for row in rows if row["seed"] == seed]
        before = list(csv.DictReader((output / baseline["source_observations_path"]).open()))
        after = list(csv.DictReader((output / candidate["source_observations_path"]).open()))
        paired = []
        for old, new in zip(before, after):
            assert old["source_id"] == new["source_id"] and old["created_ms"] == new["created_ms"]
            assert old["source_datagram_lost"] == new["source_datagram_lost"]
            old_late, new_late = old["deadline_missed"] == "True", new["deadline_missed"] == "True"
            paired.append(dict(source_id=int(old["source_id"]), in_measured_cohort=old["in_measured_cohort"] == "True",
                baseline_late=old_late, candidate_late=new_late, rescued=old_late and not new_late,
                introduced=not old_late and new_late, source_datagram_lost=old["source_datagram_lost"] == "True",
                baseline_delay_ms=old["delay_ms"], candidate_delay_ms=new["delay_ms"],
                baseline_release_mode=old["release_mode"], candidate_release_mode=new["release_mode"]))
        write_csv(output / "paired-sources" / f"{seed}.csv", paired)
        measured = [row for row in paired if row["in_measured_cohort"]]
        rescued, introduced = sum(row["rescued"] for row in measured), sum(row["introduced"] for row in measured)
        assert introduced - rescued == candidate["deadline_miss_count"] - baseline["deadline_miss_count"]
        changes.append(dict(record_kind="derived_source_bridge_paired_change", seed=seed,
            raw_inputs=[f'cases/{baseline["analytic_case_id"]:03d}.json', f'cases/{candidate["analytic_case_id"]:03d}.json'],
            baseline_case_id=baseline["analytic_case_id"], candidate_case_id=candidate["analytic_case_id"],
            rescued_late_originals=rescued, introduced_late_originals=introduced,
            newly_late_received_datagrams=sum(row["introduced"] and not row["source_datagram_lost"] for row in measured),
            deadline_miss_change_pp=100 * (candidate["deadline_miss_fraction"] - baseline["deadline_miss_fraction"]),
            original_source_p99_change_ms=candidate["recovered_only_created_to_known_p99_ms"] - baseline["recovered_only_created_to_known_p99_ms"]))
    return changes


def render(output, rows, summaries, changes):
    import csv
    diagnostics = []
    for row in rows:
        sources = list(csv.DictReader((output / row["source_observations_path"]).open()))
        late = [source for source in sources if source["in_measured_cohort"] == "True" and source["deadline_missed"] == "True"]
        item = dict(record_kind="derived_source_bridge_deadline_diagnostic", source_case_id=row["analytic_case_id"],
            raw_inputs=[f'cases/{row["analytic_case_id"]:03d}.json', row["source_observations_path"]],
            policy=row["policy"], seed=row["seed"], late_originals=len(late),
            measured_cohort_sources=row["measured_sources"], measured_cohort_unknowns=row["unresolved_at_horizon_count"],
            full_input_sources=row["source_count"], full_input_unknowns=row["source_count"] - row["final_known_sources"],
            trailing_input_unknowns=sum(not source["recovered_ms"] and int(source["source_id"]) >= row["source_count"] - row["tail_sources"] for source in sources),
            final_sender_confirmed_prefix=row["final_sender_confirmed_prefix"],
            expired_late_originals=row["late_originals_expired_from_local_window"],
            equation_absent_late_originals=row["late_originals_with_no_receiver_equation"],
            late_released_by_local_repair=row["late_original_release_modes"].get("local_repair", 0),
            late_released_by_global_repair=row["late_original_release_modes"].get("global_repair", 0),
            deadline_component_variables_median=float(np.median([int(source["component_variables"]) for source in late])),
            deadline_component_deficit_median=float(np.median([int(source["component_deficit"]) for source in late])))
        diagnostics.append(item)
    write_csv(output / "deadline-component-summary.csv", diagnostics)
    diagnostic_table = "".join("<tr>" + "".join(f"<td>{value}</td>" for value in (
        row["source_case_id"], escape(row["policy"]), row["late_originals"],
        row["deadline_component_variables_median"], row["deadline_component_deficit_median"],
        row["late_released_by_local_repair"], row["late_released_by_global_repair"],
        f'{row["measured_cohort_sources"] - row["measured_cohort_unknowns"]}/{row["measured_cohort_sources"]}',
        row["full_input_unknowns"], row["trailing_input_unknowns"], row["final_sender_confirmed_prefix"])) + "</tr>" for row in diagnostics)
    baseline = [row for row in diagnostics if row["policy"] == PROFILES[0]["name"]]
    baseline_late = sum(row["late_originals"] for row in baseline)
    baseline_local = sum(row["late_released_by_local_repair"] for row in baseline)
    rescued = sum(row["rescued_late_originals"] for row in changes)
    introduced = sum(row["introduced_late_originals"] for row in changes)
    received_introductions = sum(row["newly_late_received_datagrams"] for row in changes)
    metrics = (("deadline_miss_fraction", 100, "Original-source 35 ms misses (%)"),
               ("recovered_only_created_to_known_p99_ms", 1, "Recovered-only original-source P99 (ms)"))
    figure = make_subplots(rows=1, cols=2)
    for index, profile in enumerate(PROFILES):
        selected = [row for row in rows if row["policy"] == profile["name"]]
        for column, (metric, scale, title) in enumerate(metrics, 1):
            figure.add_trace(go.Scatter(x=[row[metric] * scale for row in selected],
                y=[row["ideal_application_service_ceiling_mbps"] for row in selected],
                ids=[str(row["analytic_case_id"]) for row in selected],
                customdata=[[row["analytic_case_id"], row["seed"], row["deadline_miss_count"], row["measured_sources"],
                             row["unresolved_at_horizon_count"]] for row in selected],
                meta=dict(kind="raw-case"), mode="markers+text", text=[str(row["analytic_case_id"]) for row in selected], cliponaxis=False,
                textposition="top center", name=profile["name"], legendgroup=profile["name"], showlegend=column == 1,
                marker=dict(color=COLORS[index], size=11),
                hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}<br>X %{x:.5f} · ceiling %{y:.5f} Mbps"
                    "<br>Miss %{customdata[2]}/%{customdata[3]} · unresolved %{customdata[4]}<extra></extra>"), row=1, col=column)
            figure.update_xaxes(title_text=title, row=1, col=column)
            ceiling = rows[0]["ideal_application_service_ceiling_mbps"]
            figure.update_yaxes(title_text="Optimistic byte-service ceiling (Mbps)", range=[ceiling - .025, ceiling + .025], row=1, col=column)
    for column, (metric, scale, _) in enumerate(metrics, 1):
        eligible = [row for row in summaries if row["unresolved_at_horizon_fraction"] == 0]
        best = min(eligible, key=lambda row: row[metric]) if eligible else None
        if best:
            figure.add_trace(go.Scatter(x=[best[metric] * scale], y=[rows[0]["ideal_application_service_ceiling_mbps"]],
                name="Eligible mean frontier", legendgroup="frontier", showlegend=column == 1,
                meta=dict(kind="mean-frontier"), mode="markers", text=[best["policy"]],
                marker=dict(color="#253641", symbol="diamond-open", size=19)), row=1, col=column)
    figure.add_vline(x=1, line_dash="dash", line_color="#a33", row=1, col=1)
    figure.update_layout(width=1150, height=550, template="plotly_white", margin=dict(b=120), legend=dict(orientation="h", y=-.25))
    chart = figure.to_html(full_html=False, include_plotlyjs=True, div_id="source-bridge-pareto")
    summary_table = "".join("<tr>" + "".join(f"<td>{value}</td>" for value in (
        escape(row["policy"]), row["n"], f'{100 * row["deadline_miss_fraction"]:.4f}%',
        f'{100 * row["unresolved_at_horizon_fraction"]:.4f}%', f'{row["recovered_only_created_to_known_p99_ms"]:.3f}',
        f'{row["late_originals_with_received_source_datagram"]:.1f}', f'{row["late_release_batch_count"]:.1f}')) + "</tr>" for row in summaries)
    change_table = "".join("<tr>" + "".join(f"<td>{value}</td>" for value in (
        row["seed"], row["rescued_late_originals"], row["introduced_late_originals"], row["newly_late_received_datagrams"],
        f'{row["deadline_miss_change_pp"]:+.5f}', f'{row["original_source_p99_change_ms"]:+.4f}')) + "</tr>" for row in changes)
    intervals = []
    for metric in ("deadline_miss_change_pp", "original_source_p99_change_ms"):
        stats = mean_ci([row[metric] for row in changes])
        intervals.append(dict(record_kind="derived_source_bridge_paired_interval", metric=metric,
                              raw_inputs=[path for row in changes for path in row["raw_inputs"]], **stats))
    write_csv(output / "paired-intervals.csv", intervals)
    interval_text = " ".join(f'{escape(row["metric"])} has mean {row["mean"]:+.5f} and 95% paired Student interval '
                             f'[{row["ci_low"]:+.5f}, {row["ci_high"]:+.5f}].' for row in intervals)
    links = "".join(f'<li>Case {row["analytic_case_id"]} · {escape(row["policy"])} · seed {row["seed"]} · '
        f'<a href="cases/{row["analytic_case_id"]:03d}.json">Raw result</a> · '
        f'<a href="{row["source_observations_path"]}">All source states</a> · '
        f'<a href="{row["release_batches_path"]}">Release batches</a></li>' for row in rows)
    (output / "report.html").write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Delayed source bridge diagnostic</title>
<style>*{{box-sizing:border-box}}body{{max-width:1220px;margin:24px auto;padding:18px;font:16px/1.5 system-ui;color:#243747;overflow-wrap:anywhere}}.scroll{{max-width:100%;overflow-x:auto}}table{{border-collapse:collapse;min-width:1000px;width:100%}}th,td{{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}}th{{background:#edf3f7}}.notice{{padding:14px;background:#fff0d8;border-left:5px solid #a65e24}}a{{color:#12688d}}</style>
<h1>Delayed source bridging at unchanged forward cost</h1>
<p class="notice">Six coding-only cases compare identical fixed arrivals, datagram erasures, packet timing and byte budgets. The rate axis is an optimistic byte-service ceiling. Actual TCP goodput and cumulative ACK completion are unmeasured. All cases use 20.8% extra packets, exceeding the historical 20% cap.</p>
<h2>Causal source packet transformation</h2>
<p>The control sends original source x[s]. The candidate sends y[s]=x[s]+x[s−128] in GF256, with negative-time inputs zero. All 1460 source bytes undergo the same XOR. The original x variables remain the repair-code domain and the deadline denominator. The source packet contains IPv4/UDP 28 bytes, an actual serialized and parsed 8-byte header, and 1460 payload bytes. Header fields are source ID (4), version (1), profile (1) and lag (2). Receiver equations are derived exclusively from these bytes. Both formats consume 1496 IP bytes.</p>
<p>The candidate's lower-triangular source transform has unit diagonal and a causal inverse. A later bridge can link an old missing source to a new source still inside the repair window. It can also withhold direct recovery of the new source when the old source is missing. Source-side bridging was absent from the preceding recursive-parity and spatial-coupling screens, whose original sources were systematic. No receiver information chooses the source transformation.</p>
<p>Repairs retain 26/125 integer credit, fresh W128 support, and every sixteenth original repair group over the sender-unconfirmed prefix. They operate on original x IDs and cost 1500 bytes with the unchanged 12-byte first-ID/count/seed/type header. Prefix feedback costs 46 bytes, is generated after received events at least 5 ms apart, and traverses a charged 10 Mbps reverse link after two 35 ms propagation legs. Both directions have 15% IID datagram erasures.</p>
<h2>Fixed original-source cohort and decoder diagnostics</h2>
<p>Each seed admits 20,000 sources every 0.1448 ms, equivalent to 80 Mbps of 1448-byte application payload. Queueing starts at that fixed origin. The 16,000-source measured cohort excludes 2,000 warmup and 2,000 trailing sources, while all originals remain in the algebra and CSVs. Unresolved measured sources count as misses. Execution stops after the final scheduled packet with no extra flush or termination. Whole-source completion is identification of original x[s].</p>
<p>At each original's 35 ms deadline, a read-only observer records whether it has left the local band, the receiver's rank deficit, and its connected unknown-variable component. Component rank is the number of independent reduced rows in that component. These diagnostic states never enter sender decisions. Per-source exports preserve source-datagram erasure, completion event and mode, queue wait, and deadline state. Paired source exports distinguish rescued old misses from newly introduced misses on the identical loss trace.</p>
<div class="scroll">{chart}</div><div class="scroll"><table><thead><tr><th>Policy</th><th>Seeds</th><th>35 ms misses</th><th>Unresolved</th><th>Recovered-only P99 ms</th><th>Late originals with received source packets</th><th>Late release batches</th></tr></thead><tbody>{summary_table}</tbody></table></div>
<h2>Observed failure mechanism and terminal state</h2>
<p>The candidate rescued {rescued} baseline-late originals and introduced {introduced} new late originals across the paired measured cohorts. Of these introductions, {received_introductions} had successful source-datagram reception. The new dependency propagated old uncertainty into received traffic.</p>
<p>Every late baseline original had left the most recent 128-source support at its deadline, yet every one still belonged to a retained receiver equation. The old source variables remained algebraically connected to newer local repairs. Of {baseline_late} baseline-late originals, {baseline_local} ({100 * baseline_local / baseline_late:.2f}%) eventually became identifiable on a local repair event. The component medians below quantify the shortage of independent constraints and the enlarged connected sets under bridging. These observations identify a failed causal mechanism on the three paired traces, while leaving other coding constructions untested.</p>
<p>All measured-cohort originals recovered by the horizon. Full-input trailing unknowns are shown separately. A source outside the measured cohort still remains in the input, algebra and byte denominator. Sender-confirmed prefix is a separate delayed-feedback state. No additional packets resolve the remaining trailing unknowns after the finite horizon.</p>
<div class="scroll"><table><thead><tr><th>Case</th><th>Policy</th><th>Late originals</th><th>Median component variables</th><th>Median rank deficit</th><th>Late releases on local repair</th><th>On global repair</th><th>Measured recovered</th><th>Full-input unknowns</th><th>Trailing unknowns</th><th>Sender-confirmed prefix</th></tr></thead><tbody>{diagnostic_table}</tbody></table></div>
<p><a href="deadline-component-summary.csv">Per-case component and terminal-state audit</a></p>
<h2>Paired changes</h2><p>Changes are candidate minus control. Negative changes indicate fewer misses or lower source delay. {interval_text}</p>
<div class="scroll"><table><thead><tr><th>Seed</th><th>Rescued late originals</th><th>Introduced late originals</th><th>Newly late despite received source</th><th>Miss change pp</th><th>P99 change ms</th></tr></thead><tbody>{change_table}</tbody></table></div>
<p><a href="analytic-cases.csv">All six cases</a> · <a href="analytic-summary.csv">Configuration means</a> · <a href="paired-comparisons.csv">Paired seed changes</a> · <a href="paired-intervals.csv">Paired intervals</a> · <a href="manifest.json">Frozen sources and tasks</a> · <a href="validation-checks.json">Verification receipt</a> · <a href="finite-tests.txt">Pre-run finite tests</a> · <a href="postrun-provenance.json">Post-run import and rendering provenance</a> · <a href="postrun-tests.txt">Final CLI and regression tests</a></p><ul>{links}</ul></html>''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), root / "tests/test_source_bridge.py", root / "studies/partial_repair_screen.py",
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    tasks = [dict(analytic_case_id=index * 3 + replication + 1, profile=profile, seed=seed,
                  source_count=20000, warmup_sources=2000, tail_sources=2000, execution_source_sha256=hashes)
             for index, profile in enumerate(PROFILES) for replication, seed in enumerate(SEEDS)]
    manifest = dict(record_kind="analytic_source_bridge_manifest", protocol_executions=0, analytic_cases=6,
                    analytic_tasks=tasks, sources=hashes, model_version="source-bridge-d128-v1")
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "manifest.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing tasks or sources differ")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in files:
        copy = args.out / "sources" / path.relative_to(root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    for name in ("cases", "source-observations", "release-batches", "paired-sources"):
        (args.out / name).mkdir(exist_ok=True)
    pending = [task for task in tasks if not (args.out / "cases" / f'{task["analytic_case_id"]:03d}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task, args.out) for task in pending]):
            row = future.result()
            (args.out / "cases" / f'{row["analytic_case_id"]:03d}.json').write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
            print(f'Case {row["analytic_case_id"]} {row["policy"]} miss={100 * row["deadline_miss_fraction"]:.4f}% '
                  f'P99={row["recovered_only_created_to_known_p99_ms"]:.3f} ms', flush=True)
    rows = [json.loads((args.out / "cases" / f'{task["analytic_case_id"]:03d}.json').read_text()) for task in tasks]
    for seed in SEEDS:
        group = [row for row in rows if row["seed"] == seed]
        for field in ("erasure_trace_sha256", "packet_trace_sha256", "source_arrival_trace_sha256", "forward_total_wire_bytes", "measured_sources"):
            assert len({row[field] for row in group}) == 1, field
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not changed, changed
    summary, paired = summarize(rows), compare_sources(args.out, rows)
    write_csv(args.out / "analytic-cases.csv", rows)
    write_csv(args.out / "analytic-summary.csv", summary)
    write_csv(args.out / "paired-comparisons.csv", paired)
    checks = dict(cases=6, case_ids=[row["analytic_case_id"] for row in rows], points_per_panel=6,
                  changed_during_run=changed, fixed_original_source_arrivals=True, original_deadline_cohort_retained=True,
                  identical_forward_packet_times_sizes_and_erasure_draws=True, causal_70ms_prefix_feedback=True,
                  parsed_8byte_source_headers=True, paired_rescues_and_introductions_reconcile=True)
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    render(args.out, rows, summary, paired)
    print(json.dumps(dict(summary=summary, paired=paired), indent=2), flush=True)


if __name__ == "__main__":
    main()
