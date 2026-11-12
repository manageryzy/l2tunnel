"""Coding-only old-debt equations reconstructed from causal bitmap feedback."""

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

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim.coding import Decoder
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci, paired_difference

if __package__:
    from . import rtt_selective_fallback as previous
else:
    import rtt_selective_fallback as previous


SOURCE_MS, REPAIR_MS, ARRIVAL_MS = previous.SOURCE_MS, previous.REPAIR_MS, previous.ARRIVAL_MS
SEEDS = previous.SEEDS
PROFILES = (
    dict(name="Prefix dense W128 G16", policy="prefix", bitmap_every=0, checkpoint=0, burst=False),
    dict(name="Bitmap dense W128 G16", policy="bitmap", bitmap_every=0, checkpoint=0, burst=False),
    dict(name="Bitmap-coded old debt G16", policy="bitmap", bitmap_every=16, checkpoint=0, burst=False),
    dict(name="Alternating dense and bitmap-coded G32", policy="bitmap", bitmap_every=32, checkpoint=0, burst=False),
)
COLORS = ("#303f59", "#2578a9", "#b85e17", "#248267")
REPAIR_FIELDS = previous.REPAIR_FIELDS
BITMAP_REPAIR_KIND = 2


def json_scalar(value):
    """Preserve numeric diagnostics when the counter contains a NumPy scalar."""
    if isinstance(value, np.generic):
        return value.item()
    raise TypeError(f"unsupported JSON value {type(value).__name__}")


def missing_ids(report):
    """Explicit negatives below an observed later endpoint in one fixed report."""
    return tuple(report.start + offset for offset in range(report.count)
                 if not (report.bitmap >> offset & 1)
                 and report.start + offset + 1 < report.highest_exclusive)


class BitmapSender(previous.SelectiveSender):
    def __init__(self):
        super().__init__("bitmap")
        self.latest_payload = None
        self.latest_delivered_ms = None

    def accept_payload(self, payload, delivered_ms):
        report = previous.Feedback.decode(payload)
        newer = report.serial > self.latest_report
        self.accept(report)
        if newer:
            self.latest_payload = bytes(payload)
            self.latest_delivered_ms = delivered_ms

    def bitmap_header(self, repair_serial):
        if self.latest_payload is None:
            return None
        report = previous.Feedback.decode(self.latest_payload)
        if not missing_ids(report):
            return None
        seed = repair_serial * previous.SERIAL_MULTIPLIER & 0xffffffff
        return REPAIR_FIELDS.pack(report.serial, report.count, seed, BITMAP_REPAIR_KIND)


def repair_equation(header, emitted_reports):
    """Decode the charged header using the receiver's immutable emitted bytes."""
    report_serial, count, seed, kind = REPAIR_FIELDS.unpack(header)
    if kind != BITMAP_REPAIR_KIND:
        return previous.repair_equation(header)
    if report_serial not in emitted_reports:
        raise ValueError("bitmap-coded repair references a missing emitted report")
    report = previous.Feedback.decode(emitted_reports[report_serial])
    if report.serial != report_serial or count != report.count:
        raise ValueError("bitmap-coded repair report identity or count differs")
    support = missing_ids(report)
    if not support:
        raise ValueError("bitmap-coded repair references an empty missing set")
    serial = seed * previous.SERIAL_INVERSE & 0xffffffff
    return ({index: coefficient(seed, index) for index in support},
            report.highest_exclusive, serial)


def execute(task):
    started = perf_counter()
    profile, count = task["profile"], task["source_count"]
    prefix_only = profile["policy"] == "prefix"
    decoder, sender = Decoder(), BitmapSender()
    forward_rng, reverse_rng = Random(task["seed"]), Random(task["seed"] ^ 0xFED123)
    created_at = np.arange(count, dtype=float) * ARRIVAL_MS
    known_at, queue_delay = np.full(count, np.inf), np.zeros(count)
    now, last_report, reverse_free = 0., -5., 0.
    receiver_prefix, receiver_high, repair_echo = 0, 0, 0
    credit, repair_serial, reports, delivered_reports, lost_reports, feedback_bytes = 0, 0, 0, 0, 0, 0
    minimum_feedback_age = float("inf")
    pending_feedback, report_log, repair_log = [], [], []
    emitted_reports = {}
    supports, feedback_sizes, diagnostics = Counter(), Counter(), Counter()
    erasure_hash, packet_hash, feedback_erasure_hash = sha256(), sha256(), sha256()

    def receive_feedback():
        nonlocal delivered_reports, minimum_feedback_age
        while pending_feedback and pending_feedback[0][0] <= now:
            due, _, payload, generated = heappop(pending_feedback)
            if prefix_only:
                sender.accept_prefix(int.from_bytes(payload, "big"))
            else:
                sender.accept_payload(payload, due)
            delivered_reports += 1
            minimum_feedback_age = min(minimum_feedback_age, due - generated)

    def receive_equation(equation, finish, high, seen_repair=0):
        nonlocal receiver_prefix, receiver_high, repair_echo, last_report, reports
        nonlocal lost_reports, feedback_bytes, reverse_free
        receiver_high = max(receiver_high, high)
        repair_echo = max(repair_echo, seen_repair)
        solved = decoder.insert(equation)
        for symbol in solved:
            known_at[symbol] = finish
        while receiver_prefix in decoder.known:
            receiver_prefix += 1
        if finish - last_report < 5:
            return solved
        last_report = finish
        reports += 1
        if prefix_only:
            payload, size = receiver_prefix.to_bytes(4, "big"), 46
        else:
            count_bits = min(previous.BITMAP_BITS, receiver_high - receiver_prefix)
            bitmap = sum(1 << offset for offset in range(count_bits)
                         if receiver_prefix + offset in decoder.known)
            snapshot = previous.Feedback(reports, receiver_prefix, receiver_prefix, count_bits,
                                         receiver_high, repair_echo, bitmap)
            payload = snapshot.encode()
            emitted_reports[reports] = payload
            size = 28 + len(payload)
        assert size <= 180
        feedback_sizes[size] += 1
        feedback_bytes += size
        start = max(finish, reverse_free)
        serialization = size * 8 / 10000
        reverse_free = start + serialization
        lost = reverse_rng.random() < .15
        feedback_erasure_hash.update(bytes([lost]))
        due = start + 70 + serialization
        report_log.append(dict(serial=reports, generated_ms=finish, sender_due_ms=due,
                               lost=lost, ip_bytes=size, payload_hex=payload.hex()))
        if lost:
            lost_reports += 1
        else:
            heappush(pending_feedback, (due, reports, payload, finish))
        return solved

    def erased(size, finish):
        lost = forward_rng.random() < .15
        erasure_hash.update(bytes([lost]))
        packet_hash.update(f"{size},{finish:.12f},{int(lost)}\n".encode())
        return lost

    for source in range(count):
        now = max(now, created_at[source])
        receive_feedback()
        queue_delay[source] = now - created_at[source]
        now += SOURCE_MS
        if not erased(1496, now):
            receive_equation({source: 1}, now, source + 1)
        credit += 26
        while credit >= 125:
            credit -= 125
            receive_feedback()
            repair_serial += 1
            selected_header = None
            if profile["bitmap_every"] and repair_serial % profile["bitmap_every"] == 0:
                selected_header = sender.bitmap_header(repair_serial)
                diagnostics["eligible_slots"] += 1
                diagnostics["empty_selection_slots"] += selected_header is None
            bitmap_repair = selected_header is not None
            event = None
            if bitmap_repair:
                report = previous.Feedback.decode(sender.latest_payload)
                support = missing_ids(report)
                assert all(now - created_at[index] >= 70 for index in support)
                assert sender.latest_delivered_ms <= now
                diagnostics["sent"] += 1
                event = dict(repair_serial=repair_serial, selected_ms=now,
                             sender_highest_source=source, report_serial=report.serial,
                             report_delivered_ms=sender.latest_delivered_ms,
                             header_hex=selected_header.hex(), explicit_missing_sources=len(support))
                supports[len(support)] += 1
            else:
                start, end = previous.reference.support(profile, source + 1, sender.base, repair_serial)
                assert 0 <= start < end <= source + 1
                seed = repair_serial * previous.SERIAL_MULTIPLIER & 0xffffffff
                selected_header = REPAIR_FIELDS.pack(start, end - start, seed, 0)
                supports[end - start] += 1
            assert 28 + len(selected_header) + 1460 == 1500
            now += REPAIR_MS
            lost = erased(1500, now)
            if lost:
                if bitmap_repair:
                    diagnostics["erased"] += 1
                    event.update(status="erased", finish_ms=now)
            else:
                equation, received_end, received_serial = repair_equation(selected_header, emitted_reports)
                rank_before = len(decoder.known) + len(decoder.rows)
                active = {index for index, value in equation.items() if value and index not in decoder.known}
                solved = receive_equation(equation, now, received_end, received_serial)
                rank_delta = len(decoder.known) + len(decoder.rows) - rank_before
                assert rank_delta in (0, 1)
                if bitmap_repair:
                    status = "empty" if not active else "innovative" if rank_delta else "dependent"
                    old_solved = sum(now - created_at[index] >= 70 for index in solved)
                    reported_solved = sum(index in equation for index in solved)
                    diagnostics[status] += 1
                    diagnostics["newly_solved_sources"] += len(solved)
                    diagnostics["old_sources_solved"] += old_solved
                    diagnostics["reported_holes_solved"] += reported_solved
                    event.update(status=status, finish_ms=now, active_unknown_coefficients=len(active),
                                 rank_delta=rank_delta, newly_solved_sources=solved,
                                 old_sources_solved=old_solved, reported_holes_solved=reported_solved)
            if event is not None:
                repair_log.append(event)
    selected = np.arange(task["warmup_sources"], count - task["tail_sources"])
    delay = known_at[selected] - created_at[selected]
    finite = np.isfinite(delay)
    lower_bounds = np.where(finite, delay, now - created_at[selected])
    assert np.all(now - created_at[selected] > 35)
    assert repair_serial == count * 26 // 125
    row = dict(task, record_kind="analytic_bitmap_coded_case", protocol_executions=0,
        policy=profile["name"], measured_sources=len(selected), repair_packets=repair_serial,
        repair_per_source=repair_serial / count, source_ip_bytes=1496, repair_ip_bytes=1500,
        feedback_ip_bytes=46 if prefix_only else None,
        forward_total_wire_bytes=count * 1496 + repair_serial * 1500,
        forward_total_packets=count + repair_serial, forward_extra_packets_pct=100 * repair_serial / count,
        forward_ip_bytes_per_source=(count * 1496 + repair_serial * 1500) / count,
        reverse_feedback_packets=reports, reverse_feedback_wire_bytes=feedback_bytes,
        reverse_feedback_mbps=feedback_bytes * 8 / now / 1000,
        feedback_size_histogram=dict(feedback_sizes), lost_feedback_packets=lost_reports,
        delivered_feedback_reports=delivered_reports, pending_feedback_reports=len(pending_feedback),
        minimum_feedback_age_ms=minimum_feedback_age, horizon_ms=now,
        ideal_application_service_ceiling_mbps=1448 * 8 / ARRIVAL_MS / 1000,
        coding_deadline_ms=35, deadline_miss_fraction=float(np.mean(delay > 35)),
        deadline_missed_sources=int(np.count_nonzero(delay > 35)),
        unresolved_at_horizon_fraction=float(np.mean(~finite)), unresolved_sources=int(np.count_nonzero(~finite)),
        cohort_latency_lower_bound_p99_ms=float(np.percentile(lower_bounds, 99)),
        cohort_p99_is_lower_bound=bool(np.any(~finite)),
        recovered_only_created_to_known_p99_ms=float(np.percentile(delay[finite], 99)) if finite.any() else None,
        unconditional_created_to_known_p99_ms=float(np.percentile(delay, 99)) if finite.mean() > .99 else None,
        sender_queue_p99_ms=float(np.percentile(queue_delay[selected], 99)),
        maximum_source_queue_ms=float(queue_delay.max()), erasure_trace_sha256=erasure_hash.hexdigest(),
        feedback_erasure_trace_sha256=feedback_erasure_hash.hexdigest(), packet_schedule_sha256=packet_hash.hexdigest(),
        source_arrival_trace_sha256=sha256(created_at.astype("<f8").tobytes()).hexdigest(),
        final_known_sources=len(decoder.known), final_receiver_prefix=receiver_prefix,
        final_sender_confirmed_prefix=sender.base, final_sender_confirmed_sources=len(sender.confirmed),
        measured_sender_confirmed_sources=sum(int(index) in sender.confirmed for index in selected),
        final_unresolved_sources=count - len(decoder.known), final_unconfirmed_sources=count - len(sender.confirmed),
        remaining_decoder_rows=len(decoder.rows), largest_repair_support=max(supports),
        support_length_histogram=dict(supports), bitmap_diagnostics=dict(diagnostics),
        receiver_retained_report_bytes=sum(len(payload) for payload in emitted_reports.values()),
        compute_seconds=perf_counter() - started)
    source_rows = [dict(record_kind="analytic_source", source_id=index, created_ms=created_at[index],
        known_ms=known_at[index] if np.isfinite(known_at[index]) else None,
        delay_ms=known_at[index] - created_at[index] if np.isfinite(known_at[index]) else None,
        measured=task["warmup_sources"] <= index < count-task["tail_sources"],
        deadline_missed=not np.isfinite(known_at[index]) or known_at[index]-created_at[index] > 35,
        known_at_horizon=bool(np.isfinite(known_at[index])), sender_confirmed=index in sender.confirmed)
        for index in range(count)]
    return row, source_rows, repair_log, report_log


def summarize(rows):
    controls = {row["seed"]: row for row in rows if row["profile"]["policy"] == "prefix"}
    summary, paired = [], []
    for profile in PROFILES:
        group = sorted((row for row in rows if row["policy"] == profile["name"]), key=lambda row: row["seed"])
        result = dict(record_kind="analytic_bitmap_coded_summary", policy=profile["name"], n=len(group))
        for key in ("deadline_miss_fraction", "cohort_latency_lower_bound_p99_ms", "reverse_feedback_mbps"):
            for suffix, value in mean_ci([row[key] for row in group]).items():
                if suffix != "method":
                    result[key + "_" + suffix] = value
        result["measured_complete_cases"] = sum(row["unresolved_sources"] == 0 for row in group)
        result["input_complete_cases"] = sum(row["final_unresolved_sources"] == 0 for row in group)
        result["input_confirmed_cases"] = sum(row["final_unconfirmed_sources"] == 0 for row in group)
        summary.append(result)
        if profile["policy"] != "prefix":
            paired.append(dict(record_kind="analytic_bitmap_coded_paired", policy=profile["name"],
                **paired_difference([row["deadline_miss_fraction"] for row in group],
                                    [controls[row["seed"]]["deadline_miss_fraction"] for row in group])))
    return summary, paired


def render(output, rows, summary, paired):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    figure = make_subplots(rows=1, cols=2, subplot_titles=("Exact complete-cohort deadline misses", "Coding P99 and optimistic service ceiling"))
    static, axes = plt.subplots(4, 2, figsize=(13, 13))
    boundary = sorted(previous.frontier(rows), key=lambda row: row["reverse_feedback_mbps"])
    for index, profile in enumerate(PROFILES):
        group = [row for row in rows if row["policy"] == profile["name"]]
        for column, (xkey, ykey, scale) in enumerate((("reverse_feedback_mbps", "deadline_miss_fraction", 100),
                ("cohort_latency_lower_bound_p99_ms", "ideal_application_service_ceiling_mbps", 1))):
            x, y = [row[xkey] for row in group], [scale * row[ykey] for row in group]
            custom = [[row["analytic_case_id"], str(row["seed"]), row["unresolved_sources"],
                       row["final_unresolved_sources"], row["final_unconfirmed_sources"],
                       row["bitmap_diagnostics"].get("sent", 0)] for row in group]
            figure.add_trace(go.Scatter(x=x, y=y, mode="markers", name=profile["name"], legendgroup=str(index),
                showlegend=column == 0, marker=dict(color=COLORS[index], size=11,
                symbol=("circle", "square", "diamond", "triangle-up")[index]), customdata=custom,
                hovertemplate=("%{fullData.name}<br>Case %{customdata[0]}, seed %{customdata[1]}<br>x %{x:.6f}, y %{y:.6f}"
                "<br>Measured unresolved %{customdata[2]}<br>Total unresolved %{customdata[3]}, unconfirmed %{customdata[4]}"
                "<br>Bitmap-coded repairs %{customdata[5]}<extra></extra>")), row=1, col=column + 1)
            axis = axes[index, column]
            axis.scatter(x, y, color=COLORS[index], s=40)
            for position, (row, xx, yy) in enumerate(zip(group, x, y)):
                offset = (5, -15) if column == 0 and position == 2 else (5, 6)
                axis.annotate(f"Case {row['analytic_case_id']}", (xx, yy), xytext=offset,
                              textcoords="offset points", fontsize=8)
            axis.set_title(profile["name"], color=COLORS[index], fontsize=10, loc="left")
            axis.grid(alpha=.2)
        axes[index, 0].plot([row["reverse_feedback_mbps"] for row in boundary],
                            [100 * row["deadline_miss_fraction"] for row in boundary], ":*",
                            color="#68737b", fillstyle="none", label="Pooled analytical frontier")
        axes[index, 0].axhline(1, color="#b14451", linestyle="--", linewidth=.8)
        axes[index, 1].axvline(35, color="#b14451", linestyle="--", linewidth=.8)
        axes[index, 0].set(xlim=(min(row["reverse_feedback_mbps"] for row in rows)*.9,
                                 max(row["reverse_feedback_mbps"] for row in rows)*1.12),
                           ylim=(0, max(2, max(row["deadline_miss_fraction"] for row in rows)*115)),
                           xlabel="Reverse feedback IP service (Mbps)", ylabel="Sources exceeding 35 ms (%)")
        axes[index, 1].set(xlim=(25, max(45, max(row["cohort_latency_lower_bound_p99_ms"] for row in rows)*1.14)),
                           ylim=(79.9, 80.3), xlabel="Coding P99 / censored lower bound (ms)",
                           ylabel="Ideal application service ceiling (Mbps)")
        axes[index, 1].ticklabel_format(axis="y", useOffset=False)
    axes[0, 0].legend(loc="upper right", fontsize=8)
    static.suptitle("Coding-only bitmap-coded feedback · all 12 cases retained", fontsize=14)
    static.text(.5, .01, "Four policies × three paired seeds. Source tails remain in the raw records.\n"
                "The common 80.0885 Mbps value is an optimistic byte-service ceiling.", ha="center", fontsize=9)
    static.tight_layout(rect=(0, .055, 1, .97), h_pad=2)
    static.savefig(output / "all-cases.png", dpi=160)
    plt.close(static)
    figure.add_trace(go.Scatter(x=[row["reverse_feedback_mbps"] for row in boundary],
        y=[100 * row["deadline_miss_fraction"] for row in boundary], mode="lines+markers",
        marker=dict(symbol="star-open"), name="Pooled analytical frontier", line=dict(color="#68737b", dash="dot")), row=1, col=1)
    figure.update_xaxes(title=dict(text="Reverse feedback IP service (Mbps)"), row=1, col=1)
    figure.update_yaxes(title=dict(text="Sources exceeding 35 ms (%)"), row=1, col=1)
    figure.update_xaxes(title=dict(text="Coding P99 / censored lower bound (ms)"), row=1, col=2)
    figure.update_yaxes(title=dict(text="Ideal application service ceiling (Mbps)"), row=1, col=2)
    figure.add_hline(y=1, line_dash="dash", line_color="#b14451", row=1, col=1)
    figure.add_vline(x=35, line_dash="dash", line_color="#b14451", row=1, col=2)
    figure.update_layout(height=570, template="plotly_white", margin=dict(l=65, r=25, t=60, b=155),
                         legend=dict(orientation="h", y=-.32, maxheight=.25))
    plot = figure.to_html(full_html=False, include_plotlyjs=True, config=dict(responsive=True, displaylogo=False))
    statistics = "".join(f"<tr><td>{escape(row['policy'])}</td><td>{100*row['deadline_miss_fraction_mean']:.4f}%</td>"
        f"<td>[{100*row['deadline_miss_fraction_ci_low']:.4f}, {100*row['deadline_miss_fraction_ci_high']:.4f}]%</td>"
        f"<td>{row['cohort_latency_lower_bound_p99_ms_mean']:.3f}</td><td>{row['reverse_feedback_mbps_mean']:.6f}</td>"
        f"<td>{row['measured_complete_cases']}/3</td><td>{row['input_complete_cases']}/3</td>"
        f"<td>{row['input_confirmed_cases']}/3</td></tr>" for row in summary)
    cases = "".join(f"<tr><td><a href='cases/{row['analytic_case_id']:03d}.json'>{row['analytic_case_id']}</a></td>"
        f"<td>{escape(row['policy'])}</td><td>{row['seed']}</td><td>{100*row['deadline_miss_fraction']:.4f}%</td>"
        f"<td>{row['unresolved_sources']}</td><td>{row['final_unresolved_sources']}</td><td>{row['final_unconfirmed_sources']}</td>"
        f"<td><a href='source-rows/{row['analytic_case_id']:03d}.csv'>Sources</a> · "
        f"<a href='feedback/{row['analytic_case_id']:03d}.json'>Report bytes</a> · "
        f"<a href='repair-events/{row['analytic_case_id']:03d}.json'>Repair outcomes</a></td></tr>" for row in rows)
    diagnostics = ""
    for profile in PROFILES:
        group = [row for row in rows if row["policy"] == profile["name"]]
        counts = sum((Counter(row["bitmap_diagnostics"]) for row in group), Counter())
        diagnostics += (f"<tr><td>{escape(profile['name'])}</td><td>{min(row['reverse_feedback_mbps'] for row in group):.6f}–"
            f"{max(row['reverse_feedback_mbps'] for row in group):.6f}</td>"
            + "".join(f"<td>{counts[key]}</td>" for key in ("sent", "erased", "empty", "dependent", "innovative", "old_sources_solved")) + "</tr>")
    comparisons = "".join(f"<li>{escape(row['policy'])} minus prefix control, paired miss difference "
        f"{100*row['mean']:+.4f} percentage points, 95% interval [{100*row['ci_low']:+.4f}, {100*row['ci_high']:+.4f}].</li>" for row in paired)
    page = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bitmap-coded old-debt screen</title><style>*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:#213548;font:16px/1.55 system-ui}main{max-width:1220px;margin:auto;padding:28px 20px;overflow-wrap:anywhere}.card{background:white;border:1px solid #d7e0e8;padding:20px;margin:20px 0;border-radius:8px}.notice{border-left:5px solid #a76120}.scroll{max-width:100%;overflow-x:auto}.plot-frame{min-width:1050px}table{min-width:900px;width:100%;border-collapse:collapse;font-size:14px}th,td{padding:8px;text-align:left;border-bottom:1px solid #dae3eb}th{background:#edf3f8}img{max-width:100%;height:auto}a{color:#17638e}h1{font-size:clamp(1.7rem,4vw,2.4rem)}@media(max-width:600px){main{padding:12px}.card{padding:14px}}</style></head><body><main>
<h1>Bitmap-coded equations for old source debt</h1><div class="card notice"><strong>Coding-only analysis · zero TCP protocol executions.</strong>
<p>Four policies share 20,000 original source arrivals per seed, with 2,000 warmup, 16,000 measured and 2,000 trailing sources. Three paired seeds preserve identical forward serialization, packet sizes and 15% IID loss draws. Every measured source is older than the 35 ms deadline at the common final horizon. Unresolved sources count as misses. All original sources and incomplete tails remain in the exports.</p>
<p>The 26/125 schedule uses 20,000 source packets of 1496 IP bytes and 4,160 repair packets of 1500 IP bytes, totaling 36,160,000 forward IP bytes and 24,160 packets. Repair packets add 20.8% to the source packet baseline. The 80.088496 Mbps ideal application service ceiling grants one 1448-byte application payload per source. Actual Ethernet record packing, TCP flow control, native ACK traffic, coded payload arithmetic and CPU cost require an end-to-end experiment. This screen performs actual GF256 coefficient elimination.</p></div>
<div class="card"><h2>Causal construction and wire representation</h2><p>The prefix and bitmap controls retain dense W128 local repairs and one global repair per sixteen opportunities. Candidate G16 replaces each global opportunity with a fresh equation over all explicit missing IDs in the newest delivered bitmap. Candidate G32 alternates an original global opportunity with a bitmap-coded opportunity. If the delivered snapshot has no usable missing IDs, the original dense global support is retained.</p>
<p>A new repair type reuses the existing 12-byte start/count/seed/type header. Its first 32-bit field identifies the feedback report, the 16-bit count verifies the bitmap length, and the unchanged 32-bit seed determines GF256 coefficients. The receiver reconstructs support from the exact bytes of its previously emitted report. Only zero bits with a strictly later observed endpoint identify missing sources. Unreported IDs remain unknown. The receiver retains every emitted bitmap report for this finite screen. Missing report lookup fails explicitly. A deployment needs a bounded retention and epoch/wrap policy.</p>
<p>Both sides use the immutable report snapshot. Future decoding never changes its support. Newer delivered serials replace the sender selection snapshot, while reordered older reports can only add positive knowledge. Fresh repair seeds permit additional independent equations over the same old subsystem. Receiver elimination naturally removes already known symbols.</p>
<p>Reports occur after a received forward packet, at least 5 ms apart. Bitmap packets cost 52–180 IP bytes, comprising 28-byte IPv4/UDP, a 24-byte header and up to 1024 bitmap bits. Prefix control retains its prior 46-byte reports. Every report consumes the 10 Mbps reverse service and its own 15% loss draw. Feedback reaches the sender only after 70 ms plus charged reverse serialization and queueing. All report payload bytes and sender arrival times are exported. The reverse rates here cover coding feedback.</p></div>
<div class="card"><h2>Every analytical case and frontier</h2><p>Colors identify policies consistently. The left frontier minimizes reverse feedback service and exact 35 ms miss fraction for the full measured cohort. The right view displays coding P99 or its explicitly censored lower bound against the common optimistic byte-service ceiling. Coincident coordinates remain separate cases and appear in separate static policy facets. The interactive chart scrolls horizontally on narrow screens.</p><div class="scroll" tabindex="0"><div class="plot-frame">''' + plot + '''</div></div><a href="all-cases.png"><img src="all-cases.png" alt="All twelve coding cases separated into four policy facets"></a></div>
<div class="card"><h2>Three-seed summaries</h2><div class="scroll" tabindex="0"><table><thead><tr><th>Policy</th><th>35 ms misses</th><th>95% seed interval</th><th>Mean P99 or lower bound ms</th><th>Feedback Mbps</th><th>Measured decoded</th><th>Entire input decoded</th><th>Entire input confirmed</th></tr></thead><tbody>''' + statistics + '''</tbody></table></div><ul>''' + comparisons + '''</ul><p>Student-t intervals use three independent seeds and remain unbounded. They describe this finite screen.</p></div>
<div class="card"><h2>Receiver-only repair diagnostics</h2><p>Empty means every nonzero coefficient was already known on arrival. Dependent means unknown coefficients remained but total decoder information rank did not increase. Innovative means rank increased by one. Old-source recoveries count newly identified sources whose original creation preceded repair arrival by at least 70 ms in the translated coding clock. These observations never influence sender choices.</p><div class="scroll" tabindex="0"><table><thead><tr><th>Policy</th><th>Feedback Mbps range</th><th>Bitmap sent</th><th>Erased</th><th>Empty on arrival</th><th>Dependent</th><th>Innovative</th><th>Old sources solved</th></tr></thead><tbody>''' + diagnostics + '''</tbody></table></div></div>
<div class="card"><h2>All cases and terminal state</h2><div class="scroll" tabindex="0"><table><thead><tr><th>Case</th><th>Policy</th><th>Seed</th><th>Deadline misses</th><th>Measured unresolved</th><th>Total unresolved</th><th>Total unconfirmed</th><th>Original records</th></tr></thead><tbody>''' + cases + '''</tbody></table></div></div>
<div class="card"><h2>Reproduction and provenance</h2><p><a href="analytic-cases.csv">Every case</a> · <a href="analytic-summary.csv">Summary</a> · <a href="paired-differences.csv">Paired differences</a> · <a href="analytic-frontier.csv">Analytical frontier</a> · <a href="manifest.json">Frozen manifest</a> · <a href="validation.json">Validation receipt</a></p><p>Reproduce with <code>/tmp/l2tunnel-quic-venv/bin/python -m simulator.studies.rtt_bitmap_coded_fallback --out work/results-20261110/tcp-latency/bitmap-coded-fallback-reproduction</code>. Sources are frozen before execution. No additional tail repairs or feedback drain are granted. Each original creation time remains unchanged.</p></div></main></body></html>'''
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    output = args.out.resolve()
    tasks = [dict(analytic_case_id=index * 3 + offset + 1, profile=profile, seed=seed,
                  source_count=20000, warmup_sources=2000, tail_sources=2000)
             for index, profile in enumerate(PROFILES) for offset, seed in enumerate(SEEDS)]
    source_root = Path(__file__).resolve().parents[1]
    paths = [Path(__file__).resolve(), Path(previous.__file__).resolve(), Path(previous.reference.__file__).resolve(),
             source_root / "tests/test_bitmap_coded_fallback.py",
             *(source_root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest() for path in paths}
    manifest = dict(record_kind="analytic_bitmap_coded_manifest", protocol_executions=0, analytic_tasks=tasks,
                    source_sha256=hashes, python=platform.python_version(), numpy=np.__version__,
                    feedback_max_ip_bytes=180, repair_header_bytes=12, source_ip_bytes=1496,
                    repair_ip_bytes=1500, forward_mbps=100, reverse_mbps=10, loss_rate=.15,
                    loss_model="iid", rtt_ms=70, coding_deadline_ms=35,
                    retained_report_policy="All exact emitted bitmap bytes retained for this finite screen")
    output.mkdir(parents=True, exist_ok=True)
    if (output / "manifest.json").exists() and json.loads((output / "manifest.json").read_text()) != manifest:
        raise ValueError("existing source snapshots or tasks differ")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for path in paths:
        copy = output / "sources" / path.relative_to(source_root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    for name in ("cases", "source-rows", "repair-events", "feedback"):
        (output / name).mkdir(exist_ok=True)
    pending = [task for task in tasks if not (output / "cases" / f"{task['analytic_case_id']:03d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row, source_rows, repair_log, report_log = future.result()
            stem = f"{row['analytic_case_id']:03d}"
            previous.reference.write_csv(output / "source-rows" / (stem + ".csv"), source_rows)
            for directory, data in (("repair-events", repair_log), ("feedback", report_log), ("cases", row)):
                (output / directory / (stem + ".json")).write_text(json.dumps(data, indent=2, default=json_scalar) + "\n")
            print(f"Saved {stem} {row['policy']} miss={100 * row['deadline_miss_fraction']:.4f}% "
                  f"P99={row['cohort_latency_lower_bound_p99_ms']:.3f} ms "
                  f"diagnostics={row['bitmap_diagnostics']}", flush=True)
    rows = [json.loads((output / "cases" / f"{task['analytic_case_id']:03d}.json").read_text()) for task in tasks]
    for seed in SEEDS:
        group = [row for row in rows if row["seed"] == seed]
        for key in ("erasure_trace_sha256", "packet_schedule_sha256", "source_arrival_trace_sha256", "forward_total_wire_bytes", "measured_sources"):
            assert len({row[key] for row in group}) == 1, key
    summary, paired = summarize(rows)
    for name, data in (("analytic-cases", rows), ("analytic-summary", summary),
                       ("paired-differences", paired), ("analytic-frontier", previous.frontier(rows))):
        previous.reference.write_csv(output / (name + ".csv"), data)
    render(output, rows, summary, paired)
    assert all(sha256((source_root / name).read_bytes()).hexdigest() == value for name, value in hashes.items())
    validation = dict(record_kind="analytic_bitmap_coded_validation", protocol_executions=0,
                      analytical_cases=len(rows), original_source_rows=12 * 20000,
                      measured_sources_per_case=16000, source_snapshots_frozen_before_cases=True,
                      unchanged_source_hashes=True, forward_schedule_and_erasures_paired=True,
                      fixed_source_clocks=True, no_extra_tail_service=True,
                      minimum_feedback_age_ms=min(row["minimum_feedback_age_ms"] for row in rows))
    (output / "validation.json").write_text(json.dumps(validation, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
