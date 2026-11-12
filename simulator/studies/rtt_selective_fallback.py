"""Coding-only selective-feedback fallback on an unchanged forward schedule."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from hashlib import sha256
from heapq import heappop, heappush
from html import escape
import json
from pathlib import Path
import platform
from random import Random
from struct import Struct
from time import perf_counter

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim.coding import Decoder
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci, paired_difference
if __package__:
    from . import rtt_checkpoint_repairs as reference
else:
    import rtt_checkpoint_repairs as reference


SOURCE_MS, REPAIR_MS, ARRIVAL_MS = reference.SOURCE_MS, reference.REPAIR_MS, reference.ARRIVAL_MS
SEEDS = (20261110, 20261111, 20261112)
PROFILES = (
    dict(name="Prefix dense W128 G16", policy="prefix", checkpoint=0, burst=False),
    dict(name="Bitmap dense W128 G16", policy="bitmap", checkpoint=0, burst=False),
    dict(name="Bitmap oldest-hole fallback", policy="oldest", checkpoint=0, burst=False),
    dict(name="Bitmap least-attempted fallback", policy="least_attempted", checkpoint=0, burst=False),
)
COLORS = ("#303f59", "#2578a9", "#c26418", "#278569")
BITMAP_BITS = 1024
FEEDBACK_FIELDS = Struct("!IIIHHII")
REPAIR_FIELDS = Struct("!IHIH")
SERIAL_MULTIPLIER = 2654435761
SERIAL_INVERSE = pow(SERIAL_MULTIPLIER, -1, 1 << 32)


def repair_equation(header):
    start, count, seed, kind = REPAIR_FIELDS.unpack(header)
    if not count or kind not in (0, 1) or (kind == 1 and count != 1):
        raise ValueError("invalid repair support or type")
    serial = seed * SERIAL_INVERSE & 0xffffffff
    equation = ({start: 1} if kind == 1 else
                {index: coefficient(seed, index) for index in range(start, start + count)})
    return equation, start + count, serial


@dataclass(frozen=True)
class Feedback:
    serial: int
    prefix: int
    start: int
    count: int
    highest_exclusive: int
    repair_echo: int
    bitmap: int

    def encode(self):
        if not 0 <= self.count <= BITMAP_BITS or not 0 <= self.bitmap < 1 << self.count:
            raise ValueError("invalid feedback bitmap")
        if not self.prefix <= self.start <= self.start + self.count <= self.highest_exclusive:
            raise ValueError("feedback bitmap exceeds its received horizon")
        header = FEEDBACK_FIELDS.pack(self.serial, self.prefix, self.start, self.count, 0,
                                      self.highest_exclusive, self.repair_echo)
        return header + self.bitmap.to_bytes((self.count + 7) // 8, "little")

    @classmethod
    def decode(cls, payload):
        serial, prefix, start, count, reserved, highest, echo = FEEDBACK_FIELDS.unpack_from(payload)
        if reserved or len(payload) != FEEDBACK_FIELDS.size + (count + 7) // 8:
            raise ValueError("invalid feedback length or reserved bits")
        result = cls(serial, prefix, start, count, highest, echo,
                     int.from_bytes(payload[FEEDBACK_FIELDS.size:], "little"))
        if result.encode() != payload:
            raise ValueError("feedback round-trip differs")
        return result


class SelectiveSender:
    """Decisions consume only received bytes and local transmission history."""

    def __init__(self, policy):
        self.policy = policy
        self.base = 0
        self.confirmed = set()
        self.missing = {}
        self.latest_report = 0
        self.attempts = Counter()
        self.inflight = {}

    def accept_prefix(self, prefix):
        self.confirmed.update(range(self.base, prefix))
        self.base = max(self.base, prefix)
        for index in tuple(self.missing):
            if index < self.base:
                self.missing.pop(index)
                self.inflight.pop(index, None)

    def accept(self, report):
        self.accept_prefix(report.prefix)
        # Positive knowledge is monotone, including reordered old reports.
        for offset in range(report.count):
            index = report.start + offset
            if report.bitmap >> offset & 1:
                self.confirmed.add(index)
                self.missing.pop(index, None)
                self.inflight.pop(index, None)
        if report.serial <= self.latest_report:
            return
        self.latest_report = report.serial
        for offset in range(report.count):
            index = report.start + offset
            # The highest observed source/repair endpoint witnesses transmission
            # beyond the hole. An absent bit outside this page means unknown.
            if (index not in self.confirmed and index >= self.base
                    and index + 1 < report.highest_exclusive):
                self.missing[index] = (report.serial, report.repair_echo)

    def choose(self, now, next_source):
        eligible = []
        for index, (report_serial, repair_echo) in self.missing.items():
            if index >= next_source - 128 or now - index * ARRIVAL_MS < 70:
                continue
            previous = self.inflight.get(index)
            if previous is not None:
                finish, serial, accepted_report = previous
                # A new negative snapshot must acknowledge this repair or a
                # later repair. Its arrival alone never bypasses the RTT guard.
                if now < finish + 70 or report_serial <= accepted_report or repair_echo < serial:
                    continue
            eligible.append(index)
        if not eligible:
            return None
        if self.policy == "least_attempted":
            return min(eligible, key=lambda index: (self.attempts[index], index))
        return min(eligible)

    def target(self, index, finish, repair_serial):
        self.attempts[index] += 1
        self.inflight[index] = (finish, repair_serial, self.latest_report)


def execute(task):
    started = perf_counter()
    policy, count = task["profile"]["policy"], task["source_count"]
    forward_rng, reverse_rng = Random(task["seed"]), Random(task["seed"] ^ 0xFED123)
    decoder, sender = Decoder(), SelectiveSender(policy)
    created_at = np.arange(count, dtype=float) * ARRIVAL_MS
    known_at, queue_delay = np.full(count, np.inf), np.zeros(count)
    now, last_report, reverse_free = 0., -5., 0.
    receiver_prefix, receiver_high, repair_echo, credit, repair_serial = 0, 0, 0, 0, 0
    reports, delivered_reports, lost_reports, feedback_bytes = 0, 0, 0, 0
    pending_feedback = []
    minimum_feedback_age = float("inf")
    supports, feedback_sizes = Counter(), Counter()
    erasure_hash, feedback_erasure_hash, packet_hash = sha256(), sha256(), sha256()
    fallback_attempts, fallback_useful, fallback_known_on_arrival = 0, 0, 0
    empty_fallback_slots = 0
    targets = []

    def receive_feedback():
        nonlocal delivered_reports, minimum_feedback_age
        while pending_feedback and pending_feedback[0][0] <= now:
            due, _, payload, generated = heappop(pending_feedback)
            if policy == "prefix":
                sender.accept_prefix(int.from_bytes(payload, "big"))
            else:
                sender.accept(Feedback.decode(payload))
            delivered_reports += 1
            minimum_feedback_age = min(minimum_feedback_age, due - generated)

    def receive_equation(equation, finish, high, seen_repair=0):
        nonlocal receiver_prefix, receiver_high, repair_echo, last_report, reports
        nonlocal lost_reports, feedback_bytes, reverse_free
        receiver_high = max(receiver_high, high)
        repair_echo = max(repair_echo, seen_repair)
        for symbol in decoder.insert(equation):
            known_at[symbol] = finish
        while receiver_prefix in decoder.known:
            receiver_prefix += 1
        if finish - last_report < 5:
            return
        last_report = finish
        reports += 1
        if policy == "prefix":
            payload, size = receiver_prefix.to_bytes(4, "big"), 46
        else:
            count_bits = min(BITMAP_BITS, receiver_high - receiver_prefix)
            bitmap = sum(1 << offset for offset in range(count_bits)
                         if receiver_prefix + offset in decoder.known)
            snapshot = Feedback(reports, receiver_prefix, receiver_prefix, count_bits,
                                receiver_high, repair_echo, bitmap)
            payload = snapshot.encode()
            size = 28 + len(payload)
        assert size <= 1500
        feedback_sizes[size] += 1
        feedback_bytes += size
        start = max(finish, reverse_free)
        serialization = size * 8 / 10000
        reverse_free = start + serialization
        lost = reverse_rng.random() < .15
        feedback_erasure_hash.update(bytes([lost]))
        if lost:
            lost_reports += 1
        else:
            # The receiver's clock is translated by the 35 ms forward leg.
            # This feedback can affect the sender only after the full 70 ms.
            heappush(pending_feedback, (start + 70 + serialization, reports, payload, finish))

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
            target = None
            if repair_serial % 16 == 0 and policy in ("oldest", "least_attempted"):
                target = sender.choose(now, source + 1)
                empty_fallback_slots += target is None
            if target is None:
                start, end = reference.support(task["profile"], source + 1, sender.base, repair_serial)
            else:
                start, end = target, target + 1
                fallback_attempts += 1
                targets.append(dict(source_id=target, selected_ms=now, repair_serial=repair_serial,
                                    report_serial=sender.missing[target][0], repair_echo=sender.missing[target][1],
                                    sender_highest_source=source, attempt=sender.attempts[target] + 1))
                sender.target(target, now + REPAIR_MS, repair_serial)
            assert 0 <= start < end <= source + 1
            supports[end - start] += 1
            seed = repair_serial * SERIAL_MULTIPLIER & 0xffffffff
            header = REPAIR_FIELDS.pack(start, end - start, seed, int(target is not None))
            assert 28 + len(header) + 1460 == 1500
            now += REPAIR_MS
            if not erased(1500, now):
                if target is not None:
                    fallback_known_on_arrival += target in decoder.known
                    fallback_useful += target not in decoder.known
                equation, received_end, received_serial = repair_equation(header)
                receive_equation(equation, now, received_end, received_serial)
    selected = np.arange(task["warmup_sources"], count - task["tail_sources"])
    delay = known_at[selected] - created_at[selected]
    finite = np.isfinite(delay)
    lower_bounds = np.where(finite, delay, now - created_at[selected])
    assert np.all(now - created_at[selected] > 35)
    assert repair_serial == count * 26 // 125
    assert minimum_feedback_age >= 70
    measured_confirmed = sum(int(index) in sender.confirmed for index in selected)
    row = dict(task, record_kind="analytic_selective_fallback_case", protocol_executions=0,
        policy=task["profile"]["name"], measured_sources=len(selected), repair_packets=repair_serial,
        repair_per_source=repair_serial / count, source_ip_bytes=1496, repair_ip_bytes=1500,
        feedback_ip_bytes=46 if policy == "prefix" else None,
        forward_total_wire_bytes=count * 1496 + repair_serial * 1500,
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
        measured_sender_confirmed_sources=measured_confirmed, final_unresolved_sources=count-len(decoder.known),
        final_unconfirmed_sources=count-len(sender.confirmed), remaining_decoder_rows=len(decoder.rows),
        largest_repair_support=max(supports), support_length_histogram=dict(supports),
        fallback_attempts=fallback_attempts, fallback_useful_on_arrival=fallback_useful,
        fallback_already_known_on_arrival=fallback_known_on_arrival, empty_fallback_slots=empty_fallback_slots,
        compute_seconds=perf_counter()-started)
    source_rows = [dict(record_kind="analytic_source", source_id=index, created_ms=created_at[index],
        known_ms=known_at[index] if np.isfinite(known_at[index]) else None,
        delay_ms=known_at[index]-created_at[index] if np.isfinite(known_at[index]) else None,
        measured=task["warmup_sources"] <= index < count-task["tail_sources"],
        deadline_missed=not np.isfinite(known_at[index]) or known_at[index]-created_at[index] > 35,
        known_at_horizon=bool(np.isfinite(known_at[index])), sender_confirmed=index in sender.confirmed)
        for index in range(count)]
    return row, source_rows, targets


def summarize(rows):
    controls = {row["seed"]:row for row in rows if row["profile"]["policy"] == "prefix"}
    summaries, paired = [], []
    for profile in PROFILES:
        group = sorted((row for row in rows if row["policy"] == profile["name"]), key=lambda row:row["seed"])
        entry = dict(record_kind="analytic_selective_summary", policy=profile["name"], n=len(group))
        for key in ("deadline_miss_fraction", "cohort_latency_lower_bound_p99_ms", "unresolved_at_horizon_fraction", "reverse_feedback_mbps"):
            for suffix, value in mean_ci([row[key] for row in group]).items():
                if suffix != "method":
                    entry[key + "_" + suffix] = value
        entry["measured_complete_cases"] = sum(row["unresolved_sources"] == 0 for row in group)
        entry["whole_input_complete_cases"] = sum(row["final_unresolved_sources"] == 0 for row in group)
        entry["whole_input_confirmed_cases"] = sum(row["final_unconfirmed_sources"] == 0 for row in group)
        summaries.append(entry)
        if profile["policy"] != "prefix":
            paired.append(dict(record_kind="analytic_selective_paired", policy=profile["name"],
                **paired_difference([row["deadline_miss_fraction"] for row in group],
                                    [controls[row["seed"]]["deadline_miss_fraction"] for row in group])))
    return summaries, paired


def frontier(rows):
    # Every measured source is older than the deadline at the common horizon,
    # so its miss indicator remains exact even when it is still unresolved.
    return [row for row in rows if not any(
        other["reverse_feedback_mbps"] <= row["reverse_feedback_mbps"]
        and other["deadline_miss_fraction"] <= row["deadline_miss_fraction"]
        and (other["reverse_feedback_mbps"] < row["reverse_feedback_mbps"]
             or other["deadline_miss_fraction"] < row["deadline_miss_fraction"])
        for other in rows)]


def render(output, rows, summary, paired):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig = make_subplots(rows=1, cols=2, subplot_titles=("Feedback cost and deadline misses", "Measured-cohort latency and ideal service ceiling"))
    static, axes = plt.subplots(1, 2, figsize=(13, 5))
    boundary = sorted(frontier(rows), key=lambda row:row["reverse_feedback_mbps"])
    for index, profile in enumerate(PROFILES):
        group = [row for row in rows if row["policy"] == profile["name"]]
        for col, (xkey, ykey, scale) in enumerate((("reverse_feedback_mbps", "deadline_miss_fraction", 100),
                ("cohort_latency_lower_bound_p99_ms", "ideal_application_service_ceiling_mbps", 1)), 1):
            x, y = [row[xkey] for row in group], [scale*row[ykey] for row in group]
            hover = [[row["analytic_case_id"], str(row["seed"]), row["unresolved_sources"], row["final_unresolved_sources"],
                      row["final_unconfirmed_sources"], row["fallback_attempts"]] for row in group]
            fig.add_trace(go.Scatter(x=x, y=y, mode="markers", name=profile["name"], legendgroup=profile["policy"],
                showlegend=col==1, marker=dict(size=10, color=COLORS[index], symbol=("circle", "square", "diamond", "triangle-up")[index]),
                customdata=hover, hovertemplate=("%{fullData.name}<br>Case %{customdata[0]}, seed %{customdata[1]}"
                "<br>x %{x:.6f}, y %{y:.6f}<br>Measured unresolved %{customdata[2]}"
                "<br>Whole input unresolved %{customdata[3]}, unconfirmed %{customdata[4]}"
                "<br>Fallback slots %{customdata[5]}<extra></extra>")), row=1,col=col)
            axes[col-1].scatter(x,y,color=COLORS[index],marker=("o","s","D","^")[index],label=profile["name"])
            for row,xx,yy in zip(group,x,y):
                axes[col-1].annotate(str(row["analytic_case_id"]),(xx,yy),xytext=(4,4),textcoords="offset points",fontsize=7)
    fig.add_trace(go.Scatter(x=[row["reverse_feedback_mbps"] for row in boundary],
        y=[100*row["deadline_miss_fraction"] for row in boundary],mode="lines",name="Exact miss/cost frontier",
        line=dict(color="#56616d",dash="dot")),row=1,col=1)
    axes[0].plot([row["reverse_feedback_mbps"] for row in boundary],[100*row["deadline_miss_fraction"] for row in boundary],":",color="#56616d")
    fig.add_hline(y=1,line_dash="dash",line_color="#ae3348",row=1,col=1)
    fig.add_vline(x=35,line_dash="dash",line_color="#ae3348",row=1,col=2)
    labels=(("Reverse feedback IP service (Mbps)","Measured sources exceeding 35 ms (%)"),
            ("Cohort latency P99 / censored lower bound (ms)","Ideal application service ceiling (Mbps)"))
    for col,(xlabel,ylabel) in enumerate(labels,1):
        fig.update_xaxes(title=dict(text=xlabel),row=1,col=col)
        fig.update_yaxes(title=dict(text=ylabel),row=1,col=col)
        axes[col-1].set(xlabel=xlabel,ylabel=ylabel); axes[col-1].grid(alpha=.2)
    axes[0].axhline(1,linestyle="--",color="#ae3348",linewidth=.8)
    axes[1].axvline(35,linestyle="--",color="#ae3348",linewidth=.8)
    static.suptitle("Coding-only causal selective feedback · all 12 cases retained")
    static.legend(*axes[0].get_legend_handles_labels(),loc="lower center",ncol=2,fontsize=9)
    static.tight_layout(rect=(0,.12,1,.94)); static.savefig(output/"all-cases.png",dpi=160);plt.close(static)
    fig.update_layout(height=580,template="plotly_white",margin=dict(l=65,r=25,t=65,b=155),
        legend=dict(orientation="h",y=-.32,maxheight=.25),title=dict(text="All coding-only cases under the same forward schedule"))
    plot=fig.to_html(full_html=False,include_plotlyjs=True,config=dict(responsive=True,displaylogo=False))
    table="".join(f"<tr><td>{escape(row['policy'])}</td><td>{100*row['deadline_miss_fraction_mean']:.4f}%</td>"
        f"<td>[{100*row['deadline_miss_fraction_ci_low']:.4f}, {100*row['deadline_miss_fraction_ci_high']:.4f}]%</td>"
        f"<td>{row['cohort_latency_lower_bound_p99_ms_mean']:.3f}</td><td>{row['reverse_feedback_mbps_mean']:.5f}</td>"
        f"<td>{row['measured_complete_cases']}/3</td><td>{row['whole_input_complete_cases']}/3</td><td>{row['whole_input_confirmed_cases']}/3</td></tr>" for row in summary)
    raw="".join(f"<tr><td><a href='cases/{row['analytic_case_id']:03d}.json'>{row['analytic_case_id']}</a></td><td>{escape(row['policy'])}</td>"
        f"<td>{row['seed']}</td><td>{100*row['deadline_miss_fraction']:.4f}%</td><td>{row['unresolved_sources']}</td>"
        f"<td>{row['final_unresolved_sources']}</td><td>{row['final_unconfirmed_sources']}</td><td>{row['fallback_attempts']}</td>"
        f"<td><a href='source-rows/{row['analytic_case_id']:03d}.csv'>Every source</a></td></tr>" for row in rows)
    comparison="".join(f"<li>{escape(row['policy'])} minus prefix control, paired miss difference {100*row['mean']:+.4f} percentage points "
                       f"with 95% interval [{100*row['ci_low']:+.4f}, {100*row['ci_high']:+.4f}].</li>" for row in paired)
    page=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Causal selective fallback screen</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f5f7fa;color:#213548;font:16px/1.55 system-ui}}main{{max-width:1200px;margin:auto;padding:28px 20px;overflow-wrap:anywhere}}h1{{font-size:clamp(1.7rem,4vw,2.4rem)}}.card{{background:white;border:1px solid #d7e0e8;padding:20px;margin:20px 0;border-radius:8px}}.notice{{border-left:5px solid #a76120}}.scroll{{max-width:100%;overflow-x:auto}}table{{min-width:850px;width:100%;border-collapse:collapse;font-size:14px}}td,th{{padding:8px;text-align:left;border-bottom:1px solid #dae3eb}}th{{background:#edf3f8}}img{{max-width:100%;height:auto}}a{{color:#17638e}}code{{overflow-wrap:anywhere}}@media(max-width:600px){{main{{padding:12px}}.card{{padding:14px}}}}</style></head><body><main>
<h1>Causal selective feedback for old holes</h1><div class="card notice"><strong>Coding-only analysis · zero protocol executions.</strong><p>All four policies use 20,000 fixed original source arrivals per seed, 2,000 warmup sources, 16,000 deadline-measured sources and 2,000 trailing sources. Three paired seeds share the identical source times, forward packet sizes, serialization schedule and 15% IID packet erasures. Every measured source is older than 35 ms at the final horizon. Unresolved measured sources count as deadline misses. All 20,000 sources remain in the per-source CSVs and terminal counters.</p>
<p>The unchanged 26/125 schedule sends exactly 4,160 repair packets. Sources cost 1496 IP bytes and repairs cost 1500 IP bytes at 100 Mbps. The implied 80.088496 Mbps application service ceiling grants one 1448-byte application payload to every source. Actual Ethernet record framing, TCP source control, native TCP ACK traffic, coded payload arithmetic and CPU time require a full protocol experiment. This screen measures actual GF256 coefficient elimination.</p></div>
<div class="card"><h2>Concrete causal construction</h2><p>Fifteen of every sixteen repair slots retain W128 local coding. At each original global slot, a fallback policy may send one independently decodable old source. Its serialized start/count/seed/type header sets count to one and the type selects coefficient one. The receiver recovers the repair serial by inverting the seed's fixed odd multiplier modulo 2³². The fixed 40-byte outer repair header plus 1460-byte symbol still costs 1500 bytes. If no old reported hole is eligible, that slot uses the original dense global support. The experiment uses exactly its scheduled repair slots and stops without extra tail repairs.</p>
<p>The oldest policy chooses the smallest eligible source ID. The least-attempted policy first minimizes prior fallback attempts, breaking ties by source ID. Eligibility requires an explicit zero bit in a received feedback page, a strictly later source or repair endpoint observed by the receiver, age at least 70 ms, and an ID outside the newest 128 sources. A selected source is suppressed for at least 70 ms from repair serialization finish. Another attempt also requires a newer negative report whose repair echo has observed that repair serial or a later one. Positive confirmations remain monotone, including reordered feedback. Unreported bitmap positions stay unknown.</p>
<p>The reference uses its original 46-byte prefix feedback. The other three cases use an actual serialized 24-byte feedback header after 28-byte IPv4/UDP, plus up to 1024 bitmap bits. The header carries a 32-bit feedback serial, 32-bit prefix, 32-bit bitmap start, 16-bit count, 16 reserved bits, 32-bit highest-observed exclusive source ID and 32-bit highest received repair serial. A full bitmap report costs 180 IP bytes. Reports start at the receiver's current prefix and cover at most 1024 positions. Both received systematic and algebraically decoded sources set bits.</p>
<p>Reports are generated only after a received forward packet, at least 5 ms apart, using that instant's receiver state. Every report consumes the 10 Mbps reverse link and its own 15% IID loss draw. The translated receiver clock yields sender arrival after 70 ms plus charged reverse queueing/serialization. At most 0.288 Mbps is required by full reports at this interval. Source-specific feedback arrives after that source's 35 ms coding budget, but isolated recovery of an old hole can end an old algebraic dependency and reduce delays for later sources. This mechanism changes future recovery trajectories.</p></div>
<div class="card"><h2>Every analytical point</h2><p>The left frontier minimizes reverse feedback cost and the exact deadline miss fraction over the complete measured cohort. Its miss coordinate includes every unresolved measured source. The right panel retains censored P99 lower bounds explicitly and shows the common analytical service ceiling. Colors remain fixed by policy. All source-tail failures are visible below.</p>{plot}<a href="all-cases.png"><img src="all-cases.png" alt="All twelve coding-only cases with consistent policy colors"></a></div>
<div class="card"><h2>Three-seed summaries</h2><div class="scroll" tabindex="0"><table><thead><tr><th>Policy</th><th>35 ms misses</th><th>95% seed interval</th><th>Mean cohort P99 or lower bound ms</th><th>Reverse feedback Mbps</th><th>Measured cohort decoded</th><th>Entire input decoded</th><th>Entire input confirmed</th></tr></thead><tbody>{table}</tbody></table></div><ul>{comparison}</ul><p>Student-t intervals use the three independent seeds and remain unbounded. They describe this finite screen.</p></div>
<div class="card"><h2>All cases and incomplete tails</h2><div class="scroll" tabindex="0"><table><thead><tr><th>Case</th><th>Policy</th><th>Seed</th><th>Miss fraction</th><th>Measured unresolved</th><th>Total unresolved</th><th>Total sender-unconfirmed</th><th>Fallback attempts</th><th>Raw source rows</th></tr></thead><tbody>{raw}</tbody></table></div></div>
<div class="card"><h2>Reproduction and receipts</h2><p><a href="analytic-cases.csv">Every analytical case CSV</a> · <a href="analytic-summary.csv">Summary CSV</a> · <a href="paired-differences.csv">Paired differences</a> · <a href="analytic-frontier.csv">Analytical frontier</a> · <a href="manifest.json">Frozen pre-run manifest</a> · <a href="validation.json">Validation receipt</a></p><p>Reproduce with <code>/tmp/l2tunnel-quic-venv/bin/python simulator/studies/rtt_selective_fallback.py --out work/results-20261110/tcp-latency/selective-fallback-screen</code>. The source snapshot hashes are recorded before any case starts. The prefix control is separately checked against the unchanged prior reference scheduler. Every policy retains the original creation clock.</p></div></main></body></html>'''
    (output/"report.html").write_text(page)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--workers",type=int,default=2)
    args=parser.parse_args(); output=args.out.resolve()
    tasks=[dict(analytic_case_id=index*3+offset+1,profile=profile,seed=seed,
                source_count=20000,warmup_sources=2000,tail_sources=2000)
           for index,profile in enumerate(PROFILES) for offset,seed in enumerate(SEEDS)]
    source_root=Path(__file__).resolve().parents[1]
    paths=[Path(__file__).resolve(),Path(reference.__file__).resolve(),source_root/"tests/test_selective_fallback.py",
           *(source_root/"src/l2tunnel_sim"/name for name in ("compact.py","coding.py","stats.py"))]
    hashes={str(path.relative_to(source_root)):sha256(path.read_bytes()).hexdigest() for path in paths}
    manifest=dict(record_kind="analytic_selective_manifest",protocol_executions=0,analytic_tasks=tasks,
                  source_sha256=hashes,python=platform.python_version(),numpy=np.__version__,
                  feedback_header_format=FEEDBACK_FIELDS.format,feedback_header_bytes=52,bitmap_bits=1024)
    output.mkdir(parents=True,exist_ok=True)
    target=output/"manifest.json"
    if target.exists() and json.loads(target.read_text())!=manifest:
        raise ValueError("existing source snapshots or tasks differ")
    target.write_text(json.dumps(manifest,indent=2)+'\n')
    for path in paths:
        copy=output/"sources"/path.relative_to(source_root); copy.parent.mkdir(parents=True,exist_ok=True)
        copy.write_bytes(path.read_bytes())
    for name in ("cases","source-rows","fallback-targets"):(output/name).mkdir(exist_ok=True)
    pending=[task for task in tasks if not (output/"cases"/f"{task['analytic_case_id']:03d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute,task) for task in pending]):
            row,source_rows,targets=future.result();stem=f"{row['analytic_case_id']:03d}"
            reference.write_csv(output/"source-rows"/(stem+'.csv'),source_rows)
            (output/"fallback-targets"/(stem+'.json')).write_text(json.dumps(targets,indent=2)+'\n')
            (output/"cases"/(stem+'.json')).write_text(json.dumps(row,indent=2)+'\n')
            print(f"Saved {stem} {row['policy']} miss={100*row['deadline_miss_fraction']:.4f}% "
                  f"P99={row['cohort_latency_lower_bound_p99_ms']:.3f}ms "
                  f"unresolved={row['final_unresolved_sources']} unconfirmed={row['final_unconfirmed_sources']}",flush=True)
    rows=[json.loads((output/"cases"/f"{task['analytic_case_id']:03d}.json").read_text()) for task in tasks]
    for seed in SEEDS:
        group=[row for row in rows if row["seed"]==seed]
        for key in ("erasure_trace_sha256","packet_schedule_sha256","source_arrival_trace_sha256","forward_total_wire_bytes","measured_sources"):
            assert len({row[key] for row in group})==1,key
    reference_checks=[]
    for task in tasks[:3]:
        expected=json.loads(json.dumps(reference.execute(task)))
        actual=rows[task["analytic_case_id"]-1]
        differences=[key for key,value in expected.items() if key!="record_kind" and actual[key]!=value]
        if differences:raise ValueError(f"prefix control differs from prior reference {differences}")
        reference_checks.append(dict(seed=task["seed"],source_case=task["analytic_case_id"],identical_prior_reference_metrics=True))
    summary,paired=summarize(rows)
    for name,data in (("analytic-cases",rows),("analytic-summary",summary),("paired-differences",paired),("analytic-frontier",frontier(rows))):
        reference.write_csv(output/(name+'.csv'),data)
    render(output,rows,summary,paired)
    changed=[name for name,value in hashes.items() if sha256((source_root/name).read_bytes()).hexdigest()!=value]
    assert not changed
    validation=dict(record_kind="analytic_selective_validation",protocol_executions=0,analytical_cases=len(rows),
        full_reference_rechecks=reference_checks,reference_rechecks_are_deterministic_validation=True,
        forward_packet_schedule_and_loss_draws_paired=True,fixed_source_clocks_and_cohorts=True,
        no_additional_tail_repair=True,source_snapshots_frozen_before_cases=True,changed_sources=changed,
        every_source_row_retained=12*20000,measured_sources_per_case=16000,
        minimum_feedback_age_ms=min(row["minimum_feedback_age_ms"] for row in rows),
        frontier_metric_has_complete_deadline_denominator=True)
    (output/"validation.json").write_text(json.dumps(validation,indent=2)+'\n')
    print(json.dumps(summary,indent=2))


if __name__=="__main__":
    main()
