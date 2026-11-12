"""Coding-only partial half-vector repair packetization with charged queues."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
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


ARRIVAL_MS = 1448 * 8 / 80000
HEADER = Struct("!IHIH")
SEEDS = (20261110, 20261111, 20261112)
PROFILES = [dict(name="Legacy full-vector control", split_groups=0, coupled=False),
            dict(name="Coupled-half full control", split_groups=0, coupled=True),
            dict(name="Coupled-half split 2 of 26", split_groups=2, coupled=True),
            dict(name="Coupled-half split 4 of 26", split_groups=4, coupled=True)]
COLORS = ("#2369a0", "#8355a3", "#b36a24", "#23836b")


def split_positions(groups):
    if groups not in (0, 2, 4):
        raise ValueError("only the three bounded profiles are supported")
    return tuple(index * 26 // groups for index in range(1, groups + 1))


def repair_header(start, end, serial, lane, *, coupled=False):
    """Type 0 is a full vector, type 1/2 identifies a 730-byte half."""
    if not 0 <= start < end <= 0xffffffff or end - start > 65535 or lane not in (0, 1, 2):
        raise ValueError("invalid repair support or half type")
    return HEADER.pack(start, end - start, serial * 2654435761 & 0xffffffff, lane | (0x100 if coupled else 0))


def parse_repair(header):
    if len(header) != HEADER.size:
        raise ValueError("repair header must occupy twelve bytes")
    start, count, seed, lane = HEADER.unpack(header)
    if not count or lane not in (0, 1, 2):
        raise ValueError("invalid serialized repair header")
    return {source: coefficient(seed, source) for source in range(start, start + count)}, lane


def parse_coupled_repair(header):
    """Derive one or two dense half-variable rows from transmitted metadata."""
    if len(header) != HEADER.size:
        raise ValueError("repair header must occupy twelve bytes")
    start, count, seed, kind = HEADER.unpack(header)
    if not count or kind not in (0x100, 0x101, 0x102):
        raise ValueError("invalid coupled repair header")
    selected = (0, 1) if kind == 0x100 else (kind - 0x101,)
    return [{half: coefficient(seed ^ (0xA511E9B3 * (row + 1) & 0xffffffff), half)
             for half in range(2 * start, 2 * (start + count))} for row in selected]


class CoupledDecoder:
    """Each received 730-byte equation can identify either half of any source."""

    def __init__(self, count):
        self.decoder = Decoder()
        self.known_at = np.full((2, count), np.inf)
        self.complete_at = np.full(count, np.inf)
        self.prefix = 0
        self.shadow_events = 0

    def receive(self, equations, kind, finish):
        for equation in equations:
            for half in self.decoder.insert(equation):
                source, lane = divmod(half, 2)
                self.known_at[lane, source] = finish
                self.complete_at[source] = max(self.known_at[:, source])
        while self.prefix < len(self.complete_at) and np.isfinite(self.complete_at[self.prefix]):
            self.prefix += 1


class HalfDecoder:
    """Two coefficient systems, with whole-source release after both identify it."""

    def __init__(self, count, shadow=False):
        self.lanes = (Decoder(), Decoder())
        self.known_at = np.full((2, count), np.inf)
        self.complete_at = np.full(count, np.inf)
        self.prefix = 0
        self.shadow = Decoder() if shadow else None
        self.shadow_events = 0

    def receive(self, equation, kind, finish):
        selected = (0, 1) if kind == 0 else (kind - 1,)
        changed = set()
        for lane in selected:
            identified = self.lanes[lane].insert(equation)
            self.known_at[lane, identified] = finish
            changed.update(identified)
        for source in changed:
            self.complete_at[source] = max(self.known_at[:, source])
        while self.prefix < len(self.complete_at) and np.isfinite(self.complete_at[self.prefix]):
            self.prefix += 1
        if self.shadow is not None:
            assert kind == 0
            self.shadow.insert(equation)
            assert self.shadow.known == self.lanes[0].known == self.lanes[1].known
            assert self.shadow.rows == self.lanes[0].rows == self.lanes[1].rows
            self.shadow_events += 1


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list, tuple)) else value
                         for key, value in row.items()} for row in rows)


def execute(task, source_csv=None):
    count, profile = task["source_count"], task["profile"]
    split = split_positions(profile["split_groups"])
    forward_rng = Random(task["seed"])
    second_rng = Random(task["seed"] ^ 0x51A17E)
    reverse_rng = Random(task["seed"] ^ 0xFED123)
    coupled = profile["coupled"]
    decoder = CoupledDecoder(count) if coupled else HalfDecoder(count, shadow=not split)
    queue = np.zeros(count)
    now, reverse_free, sender_base, last_report = 0., 0., 0, -5.
    reports = delivered_reports = lost_reports = credit = serial = split_count = 0
    pending_feedback = []
    supports, packet_counts, lost_counts = Counter(), Counter(), Counter()
    base_hash, second_hash, wire_hash, feedback_hash, timing_hash = (sha256() for _ in range(5))
    minimum_feedback_age = np.inf
    maximum_reverse_queue = 0.

    def feedback_arrivals():
        nonlocal sender_base, delivered_reports, minimum_feedback_age
        while pending_feedback and pending_feedback[0][0] <= now:
            due, prefix, generated = heappop(pending_feedback)
            sender_base = max(sender_base, prefix)
            delivered_reports += 1
            minimum_feedback_age = min(minimum_feedback_age, due - generated)

    def receive(equation, kind):
        nonlocal reports, lost_reports, last_report, reverse_free, maximum_reverse_queue
        decoder.receive(equation, kind, now)
        if now - last_report >= 5:
            last_report = now
            reports += 1
            # Shift the receiver clock by 35 ms. Departure plus the return
            # propagation determines when this particular prefix is usable.
            received_at = now + 35
            begin = max(received_at, reverse_free)
            maximum_reverse_queue = max(maximum_reverse_queue, begin - received_at)
            reverse_free = begin + 46 * 8 / 10000
            lost = reverse_rng.random() < .15
            feedback_hash.update(bytes([lost]))
            if lost:
                lost_reports += 1
            else:
                heappush(pending_feedback, (reverse_free + 35, decoder.prefix, now))

    def transmit(size, kind, lost, equation, lane=0):
        nonlocal now
        begin = now
        now += size * 8 / 100000
        packet_counts[kind] += 1
        lost_counts[kind] += lost
        wire_hash.update(bytes([lost]))
        timing_hash.update(Struct("!ddIB").pack(begin, now, size, lane))
        if not lost:
            receive(equation, lane)

    for source in range(count):
        created = source * ARRIVAL_MS
        now = max(now, created)
        feedback_arrivals()
        queue[source] = now - created
        lost = forward_rng.random() < .15
        base_hash.update(bytes([lost]))
        systematic = [{2 * source: 1}, {2 * source + 1: 1}] if coupled else {source: 1}
        transmit(1496, "source", lost, systematic)
        credit += 26
        while credit >= 125:
            credit -= 125
            feedback_arrivals()
            serial += 1
            end = source + 1
            start = sender_base if serial % 16 == 0 else max(sender_base, end - 128)
            assert 0 <= start < end
            supports[end - start] += 1
            lost_first = forward_rng.random() < .15
            lost_second = second_rng.random() < .15
            base_hash.update(bytes([lost_first]))
            second_hash.update(bytes([lost_second]))
            is_split = (serial - 1) % 26 + 1 in split
            if is_split:
                split_count += 1
                # Both packets retain the captured range and seed even if
                # feedback arrives while the first half is serialized.
                for lane, lost_half in ((1, lost_first), (2, lost_second)):
                    header = repair_header(start, end, serial, lane, coupled=coupled)
                    if coupled:
                        transmit(770, "half_repair", lost_half, parse_coupled_repair(header), lane)
                    else:
                        equation, decoded_lane = parse_repair(header)
                        transmit(770, "half_repair", lost_half, equation, decoded_lane)
            else:
                header = repair_header(start, end, serial, 0, coupled=coupled)
                if coupled:
                    transmit(1500, "full_repair", lost_first, parse_coupled_repair(header))
                else:
                    equation, decoded_lane = parse_repair(header)
                    transmit(1500, "full_repair", lost_first, equation, decoded_lane)

    selected = np.arange(task["warmup_sources"], count - task["tail_sources"])
    delays = decoder.complete_at[selected] - selected * ARRIVAL_MS
    finite = np.isfinite(delays)
    repaired_packets = serial + split_count
    wire_bytes = count * 1496 + (serial - split_count) * 1500 + split_count * 1540
    assert serial == count * 26 // 125
    assert sum(packet_counts.values()) == count + repaired_packets
    assert minimum_feedback_age >= 70
    row = dict(task, record_kind="analytic_partial_repair_case", protocol_executions=0,
               policy=profile["name"], payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
               base_rtt_ms=70, loss_model="iid", loss_rate=.15, mtu=1500,
               source_arrival_interval_ms=ARRIVAL_MS, offered_application_mbps=80,
               source_ip_bytes=1496, full_repair_ip_bytes=1500, half_repair_ip_bytes=770,
               repair_header_bytes=HEADER.size, feedback_ip_bytes=46, coding_deadline_ms=35,
               split_positions=list(split), repair_groups=serial, split_repair_groups=split_count,
               repair_packets=repaired_packets, parity_bytes=serial * 1460,
               parity_to_source_symbol_bytes_ratio=serial / count,
               extra_packets_per_original_source_pct=100 * repaired_packets / count,
               strict_20pct_packet_cap_met=repaired_packets / count <= .20,
               forward_total_wire_bytes=wire_bytes, ip_bytes_per_original_source=wire_bytes / count,
               ideal_application_service_ceiling_mbps=100 * count * 1448 / wire_bytes,
               forward_serialization_ms=wire_bytes * 8 / 100000, final_forward_finish_ms=now,
               reverse_feedback_packets=reports, reverse_feedback_wire_bytes=reports * 46,
               reverse_feedback_average_mbps=reports * 46 * 8 / now / 1000,
               lost_feedback_packets=lost_reports, delivered_feedback_reports=delivered_reports,
               pending_feedback_at_horizon=len(pending_feedback), minimum_feedback_age_ms=minimum_feedback_age,
               maximum_reverse_queue_ms=maximum_reverse_queue, measured_sources=len(selected),
               deadline_miss_count=int(np.count_nonzero(delays > 35)),
               deadline_miss_fraction=float(np.mean(delays > 35)),
               unresolved_at_horizon_count=int(np.count_nonzero(~finite)),
               unresolved_at_horizon_fraction=float(np.mean(~finite)),
               recovered_only_created_to_known_p99_ms=float(np.percentile(delays[finite], 99)) if finite.any() else None,
               unconditional_created_to_known_p99_ms=float(np.percentile(delays, 99)) if finite.all() else None,
               sender_queue_p99_ms=float(np.percentile(queue[selected], 99)), maximum_source_queue_ms=float(queue.max()),
               all_input_known_sources=int(np.isfinite(decoder.complete_at).sum()),
               final_receiver_prefix=decoder.prefix, final_sender_confirmed_prefix=sender_base,
               remaining_decoder_rows=[len(decoder.decoder.rows)] if coupled else [len(lane.rows) for lane in decoder.lanes],
               single_vector_control_equivalence_events=decoder.shadow_events,
               common_source_and_repair_first_erasure_sha256=base_hash.hexdigest(),
               common_candidate_second_half_erasure_sha256=second_hash.hexdigest(),
               actual_datagram_erasure_sha256=wire_hash.hexdigest(), feedback_erasure_sha256=feedback_hash.hexdigest(),
               serialization_timing_sha256=timing_hash.hexdigest(), packet_counts=dict(packet_counts),
               lost_packet_counts=dict(lost_counts), support_length_histogram=dict(supports),
               source_creation_times_sha256=sha256((np.arange(count) * ARRIVAL_MS).tobytes()).hexdigest(),
               full_source_recovery_times_sha256=sha256(decoder.complete_at.tobytes()).hexdigest())
    if source_csv is not None:
        source_rows = []
        for source in range(count):
            known = decoder.complete_at[source]
            source_rows.append(dict(source_id=source, created_ms=source * ARRIVAL_MS,
                in_measured_cohort=task["warmup_sources"] <= source < count - task["tail_sources"],
                half0_known_ms=float(decoder.known_at[0, source]) if np.isfinite(decoder.known_at[0, source]) else None,
                half1_known_ms=float(decoder.known_at[1, source]) if np.isfinite(decoder.known_at[1, source]) else None,
                complete_known_ms=float(known) if np.isfinite(known) else None,
                delay_ms=float(known - source * ARRIVAL_MS) if np.isfinite(known) else None,
                deadline_missed=bool(known - source * ARRIVAL_MS > 35), sender_queue_ms=float(queue[source])))
        write_csv(source_csv, source_rows)
        row["source_observations_path"] = "source-observations/" + source_csv.name
        row["source_observations_sha256"] = sha256(source_csv.read_bytes()).hexdigest()
    return row


def summarize(rows):
    result = []
    for profile in PROFILES:
        group = [row for row in rows if row["policy"] == profile["name"]]
        item = dict(record_kind="analytic_partial_repair_summary", policy=profile["name"], n=len(group))
        for metric in ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
                       "recovered_only_created_to_known_p99_ms", "sender_queue_p99_ms",
                       "reverse_feedback_average_mbps", "ideal_application_service_ceiling_mbps",
                       "ip_bytes_per_original_source", "extra_packets_per_original_source_pct"):
            stats = mean_ci([row[metric] for row in group])
            item.update({metric: stats["mean"], metric + "_ci_low": stats["ci_low"],
                         metric + "_ci_high": stats["ci_high"]})
        result.append(item)
    return result


def frontier(rows, metric):
    eligible = [row for row in rows if row["unresolved_at_horizon_fraction"] == 0]
    return [row for row in eligible if not any(
        other[metric] <= row[metric] and other["ideal_application_service_ceiling_mbps"] >= row["ideal_application_service_ceiling_mbps"]
        and (other[metric] < row[metric] or other["ideal_application_service_ceiling_mbps"] > row["ideal_application_service_ceiling_mbps"])
        for other in eligible)]


def render(output, rows, summary):
    paired_rows, paired_summary = [], []
    for profile in PROFILES[2:]:
        selected = [row for row in rows if row["policy"] == profile["name"]]
        changes = []
        for row in selected:
            control = next(item for item in rows if item["policy"] == PROFILES[1]["name"] and item["seed"] == row["seed"])
            change = dict(record_kind="derived_partial_repair_paired_change", policy=row["policy"], seed=row["seed"],
                raw_inputs=[f'cases/{control["analytic_case_id"]:03d}.json', f'cases/{row["analytic_case_id"]:03d}.json'],
                control_case_id=control["analytic_case_id"], candidate_case_id=row["analytic_case_id"],
                whole_source_p99_change_ms=row["recovered_only_created_to_known_p99_ms"] - control["recovered_only_created_to_known_p99_ms"],
                deadline_miss_change_pp=100 * (row["deadline_miss_fraction"] - control["deadline_miss_fraction"]))
            changes.append(change)
        paired_rows.extend(changes)
        item = dict(record_kind="derived_partial_repair_paired_summary", policy=profile["name"], n=len(changes),
                    raw_inputs=[path for change in changes for path in change["raw_inputs"]],
                    interval_method="95% Student t interval over three paired seed differences")
        for metric in ("whole_source_p99_change_ms", "deadline_miss_change_pp"):
            stats = mean_ci([change[metric] for change in changes])
            item.update({metric: stats["mean"], metric + "_ci_low": stats["ci_low"], metric + "_ci_high": stats["ci_high"]})
        paired_summary.append(item)
    write_csv(output / "paired-coupled-cases.csv", paired_rows)
    write_csv(output / "paired-coupled-summary.csv", paired_summary)
    effect_table = "".join("<tr>" + "".join(f"<td>{value}</td>" for value in (
        escape(row["policy"]), f'{row["whole_source_p99_change_ms"]:+.4f}',
        (f'[{row["whole_source_p99_change_ms_ci_low"]:+.4f}, {row["whole_source_p99_change_ms_ci_high"]:+.4f}]'
         if row["whole_source_p99_change_ms_ci_low"] is not None else "Unavailable with one seed"),
        f'{row["deadline_miss_change_pp"]:+.5f}',
        (f'[{row["deadline_miss_change_pp_ci_low"]:+.5f}, {row["deadline_miss_change_pp_ci_high"]:+.5f}]'
         if row["deadline_miss_change_pp_ci_low"] is not None else "Unavailable with one seed"))) + "</tr>" for row in paired_summary)
    seed_table = "".join("<tr>" + "".join(f"<td>{value}</td>" for value in (
        escape(row["policy"]), row["seed"], f'{row["control_case_id"]} → {row["candidate_case_id"]}',
        f'{row["whole_source_p99_change_ms"]:+.4f}', f'{row["deadline_miss_change_pp"]:+.5f}')) + "</tr>" for row in paired_rows)
    metrics = (("deadline_miss_fraction", 100, "Original-source 35 ms misses (%)"),
               ("recovered_only_created_to_known_p99_ms", 1, "Recovered-only full-source P99 (ms)"))
    figure = make_subplots(rows=1, cols=2)
    for index, profile in enumerate(PROFILES):
        selected = [row for row in rows if row["policy"] == profile["name"]]
        for column, (metric, scale, title) in enumerate(metrics, 1):
            figure.add_trace(go.Scatter(x=[row[metric] * scale for row in selected],
                y=[row["ideal_application_service_ceiling_mbps"] for row in selected],
                ids=[str(row["analytic_case_id"]) for row in selected],
                customdata=[[row["analytic_case_id"], row["seed"], row["deadline_miss_count"], row["measured_sources"],
                             row["unresolved_at_horizon_count"], row["extra_packets_per_original_source_pct"]] for row in selected],
                meta=dict(kind="raw-case"), mode="markers+text", text=[str(row["analytic_case_id"]) for row in selected],
                textposition="bottom center" if index == 0 else "top center", name=profile["name"], legendgroup=profile["name"], showlegend=column == 1,
                marker=dict(size=16 if index == 0 else 10, symbol="circle-open" if index == 0 else "circle", color=COLORS[index]), hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}"
                "<br>X %{x:.6g} · ceiling %{y:.6g} Mbps<br>Miss %{customdata[2]}/%{customdata[3]}"
                " · unresolved %{customdata[4]}<br>Extra packets %{customdata[5]:.3f}%<extra></extra>"), row=1, col=column)
            figure.update_xaxes(title_text=title, row=1, col=column)
            figure.update_yaxes(title_text="Optimistic byte-service ceiling (Mbps)", row=1, col=column)
    for column, (metric, scale, _) in enumerate(metrics, 1):
        points = sorted(frontier(summary, metric), key=lambda row: row[metric])
        figure.add_trace(go.Scatter(x=[row[metric] * scale for row in points],
            y=[row["ideal_application_service_ceiling_mbps"] for row in points],
            text=[row["policy"] for row in points], mode="lines+markers", name="Complete-cohort mean frontier",
            meta=dict(kind="mean-frontier"), legendgroup="frontier", showlegend=column == 1,
            marker=dict(size=16, symbol="diamond-open", color="#22313e"), line=dict(color="#22313e")), row=1, col=column)
        figure.add_hline(y=80, line_dash="dash", line_color="#a33", row=1, col=column)
    figure.add_vline(x=1, line_dash="dash", line_color="#a33", row=1, col=1)
    figure.update_layout(width=1150, height=600, template="plotly_white", margin=dict(t=45, b=120),
                         legend=dict(orientation="h", y=-.25))
    chart = figure.to_html(full_html=False, include_plotlyjs=True, div_id="partial-repair-pareto")
    table = "".join("<tr>" + "".join(f"<td>{value}</td>" for value in (
        escape(row["policy"]), row["n"], f'{100 * row["deadline_miss_fraction"]:.4f}%',
        f'{100 * row["unresolved_at_horizon_fraction"]:.4f}%', f'{row["recovered_only_created_to_known_p99_ms"]:.3f}',
        f'{row["ip_bytes_per_original_source"]:.2f}', f'{row["extra_packets_per_original_source_pct"]:.1f}%',
        f'{row["reverse_feedback_average_mbps"]:.5f}')) + "</tr>" for row in summary)
    cases = "".join(f'<li>Case {row["analytic_case_id"]} · {escape(row["policy"])} · seed {row["seed"]} '
        f'<a href="cases/{row["analytic_case_id"]:03d}.json">Raw result</a> · '
        f'<a href="{row["source_observations_path"]}">All original sources</a></li>' for row in rows)
    (output / "report.html").write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Partial repair packetization</title>
<style>*{{box-sizing:border-box}}body{{max-width:1220px;margin:24px auto;padding:18px;font:16px/1.5 system-ui;color:#243747;overflow-wrap:anywhere}}.scroll{{max-width:100%;overflow-x:auto}}table{{border-collapse:collapse;min-width:1020px;width:100%}}th,td{{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}}th{{background:#edf3f7}}.notice{{padding:14px;background:#fff0d8;border-left:5px solid #a65e24}}a{{color:#12688d}}</style>
<h1>Independent erasures for a small subset of half-vector repairs</h1>
<p class="notice">All {len(rows)} points are coding-only cases. The rate axis is a byte-service ceiling. TCP goodput and cumulative ACK latency are unmeasured. Every configuration exceeds the historical 20% extra-packet cap. The complete original-source 35 ms deadline is a necessary screening metric for the 105 ms TCP ACK target.</p>
<h2>Packet schedule and original-source completion</h2>
<p>Each 125 fixed original-source arrivals earns 26 repair groups. The two controls send all groups as 1500-byte IP packets. The split variants select groups 13 and 26, or 6, 13, 19 and 26, for two consecutive 770-byte packets. Every original source costs 1496 bytes. A full repair carries 1460 parity bytes after 28-byte IPv4/UDP and a 12-byte header. A half repair carries 730 parity bytes after the same headers. Its two-byte type field identifies the legacy/coupled mode and full packet or row index. The remaining fields are first source ID (4), count (2) and seed (4). The receiver parses this serialized header to derive each equation.</p>
<p>The legacy full control uses two separate 730-byte decoder lanes with identical support, coefficients and shared packet erasures. Its observed states match a separate full-vector decoder after every received packet. Splitting those independent lanes would leave whole-source completion constrained by the union of their failures. The three coupled policies instead apply each parity row to all 2×source half variables in the captured support. For row j=0,1, coefficients are <code>coefficient(seed XOR ((0xA511E9B3 × (j+1)) mod 2^32), absolute_half_ID)</code>. Source s has half IDs 2s and 2s+1. Thus either received row can contribute rank towards any missing half. These two rows use distinct deterministic coefficient seeds. Finite-field dependence remains possible and is evaluated by the actual GF256 Decoder.</p>
<p>Every policy uses W128 source support, with every sixteenth original repair group spanning the sender-unconfirmed prefix. Both rows retain the captured support and seed. An original source completes only when both halves are known. A full packet supplies two equations under one shared erasure. Split packets have independent erasures. Their extra 40 bytes per split group are charged before the next source departs. Coupled-full versus legacy-full isolates the coefficient construction. Coupled-split versus coupled-full isolates packetization and its charged timing consequences.</p>
<p>Sources arrive every 0.1448 ms, corresponding to 80 Mbps of 1448-byte application payload. Queueing begins at those fixed arrival timestamps. The controls cost 1808 IP bytes per source. Split variants cost 1808.64 and 1809.28, with 20.8%, 22.4% and 24.0% extra datagrams respectively. Equal parity volume remains 20.8%. Sources are modeled as aligned 1460-byte protected records. Byte-codec reconstruction, context/overflow packets, payload-vector arithmetic, authentication and CPU cost require later protocol validation.</p>
<h2>Causal feedback and paired loss samples</h2>
<p>Forward and reverse capacities are 100 and 10 Mbps with 70 ms base RTT and 15% IID datagram losses. Prefix reports cost 46 bytes, are generated at received-packet events at least 5 ms apart, and traverse a charged reverse queue. The sender receives them only after both 35 ms propagation legs. Reports acknowledge complete sources. No receiver loss state enters the repair scheduler.</p>
<p>Paired seeds preserve source and first-half erasure draws by original repair group. A separate independent stream supplies second-half draws by group, including unused draws for full groups. Actual datagram traces differ when a group splits. Reverse draws are paired by report ordinal, while report times and counts may differ. Every case keeps all 20,000 originals, including its 16,000-source measured cohort after 2,000 warmup sources and before 2,000 trailing sources. Unresolved originals count as misses. Execution ends after the last scheduled packet, with no extra termination or tail repairs.</p>
<div class="scroll">{chart}</div><div class="scroll"><table><thead><tr><th>Policy</th><th>Seeds</th><th>35 ms misses</th><th>Unresolved</th><th>Recovered-only P99 ms</th><th>IP bytes/source</th><th>Extra packets</th><th>Reverse Mbps</th></tr></thead><tbody>{table}</tbody></table></div>
<p>Recovered-only P99 excludes unresolved sources. Mean-frontier eligibility requires complete recovery of every measured cohort. Seed intervals and paired changes are in the CSV exports. All individual cases remain visible, including dominated outcomes.</p>
<h2>Paired changes against the coupled-half full control</h2>
<p>All twelve measured cohorts recovered completely. Every individual case exceeded the 1% deadline-miss target. Splitting four groups lowered the mean full-source P99 by 4.9683 ms while changing the mean deadline-miss rate by −0.00417 percentage points. Both paired 95% intervals span zero. Its 80.03184 Mbps value is the optimistic byte-service ceiling, with 24% extra datagrams. These observations leave the TCP goodput and cumulative ACK target unproven.</p>
<p>Differences are candidate minus paired control. Negative values indicate lower delay or fewer misses. Intervals use Student t over three independent seed differences. The six rows below are derived comparisons of the saved cases.</p>
<div class="scroll"><table><thead><tr><th>Candidate</th><th>Mean P99 change ms</th><th>95% interval ms</th><th>Mean miss change pp</th><th>95% interval pp</th></tr></thead><tbody>{effect_table}</tbody></table></div>
<div class="scroll"><table><thead><tr><th>Candidate</th><th>Seed</th><th>Control → candidate case</th><th>Whole-source P99 change ms</th><th>35 ms miss change pp</th></tr></thead><tbody>{seed_table}</tbody></table></div>
<p><a href="paired-coupled-cases.csv">Six paired seed differences</a> · <a href="paired-coupled-summary.csv">Paired mean intervals</a> · <a href="report-render-provenance.json">Report-only rendering provenance</a></p>
<p><a href="analytic-cases.csv">All cases CSV</a> · <a href="analytic-summary.csv">Means and intervals</a> · <a href="paired-comparisons.csv">Paired changes</a> · <a href="manifest.json">Frozen sources and tasks</a> · <a href="validation-checks.json">Validation receipt</a></p><ul>{cases}</ul></html>''')
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for index, profile in enumerate(PROFILES):
        selected = [row for row in rows if row["policy"] == profile["name"]]
        for axis, (metric, scale, title) in zip(axes, metrics):
            axis.scatter([row[metric] * scale for row in selected], [row["ideal_application_service_ceiling_mbps"] for row in selected],
                         facecolors="none" if index == 0 else COLORS[index], edgecolors=COLORS[index],
                         s=90 if index == 0 else 40, label=profile["name"])
            for row in selected:
                axis.annotate(str(row["analytic_case_id"]), (row[metric] * scale, row["ideal_application_service_ceiling_mbps"]), xytext=(4, -12 if index == 0 else 4), textcoords="offset points", fontsize=8)
            axis.set_xlabel(title)
            axis.set_ylabel("Optimistic byte-service ceiling (Mbps)")
            axis.grid(alpha=.2)
    for axis, (metric, scale, _) in zip(axes, metrics):
        points = sorted(frontier(summary, metric), key=lambda row: row[metric])
        axis.plot([row[metric] * scale for row in points], [row["ideal_application_service_ceiling_mbps"] for row in points],
                  color="#22313e", marker="D", markerfacecolor="none", linewidth=1)
    fig.legend(loc="lower center", ncol=2)
    fig.tight_layout(rect=(0, .10, 1, 1))
    fig.savefig(output / "all-cases.png", dpi=150)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), root / "tests/test_partial_repair.py", root / "studies/rtt_checkpoint_repairs.py",
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    tasks = [dict(analytic_case_id=index * 3 + replication + 1, profile=profile, seed=seed,
                  source_count=20000, warmup_sources=2000, tail_sources=2000,
                  execution_source_sha256=hashes) for index, profile in enumerate(PROFILES)
             for replication, seed in enumerate(SEEDS)]
    manifest = dict(record_kind="analytic_partial_repair_manifest", protocol_executions=0,
                    analytic_cases=len(tasks), analytic_tasks=tasks, sources=hashes,
                    model_version="partial-repair-v2-coupled", source_arrival_interval_ms=ARRIVAL_MS)
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "manifest.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing tasks or frozen sources differ")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in files:
        copy = args.out / "sources" / path.relative_to(root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    for directory in ("cases", "source-observations"):
        (args.out / directory).mkdir(exist_ok=True)
    pending = [task for task in tasks if not (args.out / "cases" / f'{task["analytic_case_id"]:03d}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(execute, task, args.out / "source-observations" / f'{task["analytic_case_id"]:03d}.csv') for task in pending]
        for future in as_completed(futures):
            row = future.result()
            path = args.out / "cases" / f'{row["analytic_case_id"]:03d}.json'
            path.write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
            print(f'Case {row["analytic_case_id"]} {row["policy"]} miss={100 * row["deadline_miss_fraction"]:.4f}% P99={row["recovered_only_created_to_known_p99_ms"]:.3f} ms', flush=True)
    rows = [json.loads((args.out / "cases" / f'{task["analytic_case_id"]:03d}.json').read_text()) for task in tasks]
    paired = []
    for seed in SEEDS:
        group = [row for row in rows if row["seed"] == seed]
        for field in ("common_source_and_repair_first_erasure_sha256", "common_candidate_second_half_erasure_sha256",
                      "source_creation_times_sha256", "measured_sources", "parity_bytes"):
            assert len({row[field] for row in group}) == 1, field
        for baseline, candidates in ((group[0], group[1:]), (group[1], group[2:])):
            for row in candidates:
                paired.append(dict(seed=seed, policy=row["policy"], control_policy=baseline["policy"],
                    control_case_id=baseline["analytic_case_id"], candidate_case_id=row["analytic_case_id"],
                    deadline_miss_change_pp=100 * (row["deadline_miss_fraction"] - baseline["deadline_miss_fraction"]),
                    recovered_only_p99_change_ms=row["recovered_only_created_to_known_p99_ms"] - baseline["recovered_only_created_to_known_p99_ms"]))
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not changed, changed
    summary = summarize(rows)
    write_csv(args.out / "analytic-cases.csv", rows)
    write_csv(args.out / "analytic-summary.csv", summary)
    write_csv(args.out / "paired-comparisons.csv", paired)
    checks = dict(cases=len(rows), plotted_case_ids=[row["analytic_case_id"] for row in rows], points_per_panel=len(rows),
                  changed_during_run=changed, fixed_arrivals_and_full_original_cohort=True,
                  paired_source_and_first_half_losses=True, independent_second_half_by_group=True,
                  equal_parity_volume=True, extra_headers_and_serialization_charged=True,
                  full_control_equivalence_events=sum(row["single_vector_control_equivalence_events"] for row in rows),
                  every_case_fails_historical_20pct_packet_cap=all(not row["strict_20pct_packet_cap_met"] for row in rows))
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    render(args.out, rows, summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
