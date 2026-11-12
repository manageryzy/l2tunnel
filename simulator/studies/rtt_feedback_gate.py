"""Causal delayed-feedback gating of charged W128/G16 repair slots."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
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

if __package__:
    from . import rtt_checkpoint_repairs as reference
else:
    import rtt_checkpoint_repairs as reference
from l2tunnel_sim.coding import Decoder
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci, paired_difference


SEEDS = (20261110, 20261111, 20261112)
PROFILES = [dict(name="Fixed dense W128 G16", freshness_ms=None),
            dict(name="Feedback gate 15 ms", freshness_ms=15),
            dict(name="Feedback gate 30 ms", freshness_ms=30)]
COLORS = ("#1764ab", "#d16b25", "#16816a")
METRICS = ("deadline_miss_fraction", "unresolved_at_horizon_fraction", "recovered_only_created_to_known_p99_ms")
FEEDBACK = Struct("!IIIHHH")
SERIAL_MULTIPLIER = 2654435761
SOURCE_MS, REPAIR_MS, ARRIVAL_MS = reference.SOURCE_MS, reference.REPAIR_MS, reference.ARRIVAL_MS


@dataclass(frozen=True)
class Snapshot:
    sequence: int
    prefix: int
    highest: int
    deficit: int

    def encode(self):
        if not 0 <= self.prefix <= self.highest or not 0 <= self.deficit <= self.highest - self.prefix:
            raise ValueError("invalid feedback prefix, horizon or deficit")
        return FEEDBACK.pack(self.sequence, self.prefix, self.highest, self.deficit, 1, 0)

    @classmethod
    def decode(cls, payload):
        if len(payload) != FEEDBACK.size:
            raise ValueError("feedback must contain exactly 18 bytes")
        sequence, prefix, highest, deficit, version, reserved = FEEDBACK.unpack(payload)
        if version != 1 or reserved:
            raise ValueError("unsupported feedback version or reserved bits")
        result = cls(sequence, prefix, highest, deficit)
        if result.encode() != payload:
            raise ValueError("feedback round trip differs")
        return result


class SenderGate:
    """Only delivered serialized snapshots and local time affect decisions."""

    def __init__(self, freshness_ms):
        self.freshness_ms = freshness_ms
        self.base = 0
        self.latest = None
        self.received_at = None

    def accept(self, payload, now):
        snapshot = Snapshot.decode(payload)
        if self.latest is not None and snapshot.sequence <= self.latest.sequence:
            return
        if snapshot.prefix < self.base:
            return
        self.base = snapshot.prefix
        self.latest, self.received_at = snapshot, now

    def choose(self, serial, end, now):
        if serial % 16:
            return max(self.base, end - 128), "ordinary_local"
        if self.freshness_ms is None:
            return self.base, "fixed_global"
        if self.latest is None:
            return self.base, "startup_global"
        if now - self.received_at > self.freshness_ms:
            return self.base, "stale_global"
        if self.latest.highest - self.latest.prefix > 128 and self.latest.deficit > 0:
            return self.base, "reported_debt_global"
        return max(self.base, end - 128), "gated_local"


def packet_equation(start, end, seed):
    return {source: value for source in range(start, end) if (value := coefficient(seed, source))}


def reduced_equation(equation, known):
    return {source: value for source, value in equation.items() if source not in known}


def execute(task):
    count, profile = task["source_count"], task["profile"]
    loss = task.get("loss_rate", .15)
    forward_rng, reverse_rng = Random(task["seed"]), Random(task["seed"] ^ 0xFED123)
    decoder, sender = Decoder(), SenderGate(profile["freshness_ms"])
    created = np.arange(count, dtype=float) * ARRIVAL_MS
    known_at, queue_delay = np.full(count, np.inf), np.zeros(count)
    now, last_report, reverse_free = 0., -5., 0.
    receiver_prefix = receiver_high = credit = serial = 0
    reports = delivered_reports = lost_reports = 0
    minimum_feedback_age = float("inf")
    pending = []
    mode_counts, received_modes, innovative_modes, solved_by_mode, supports = (Counter() for _ in range(5))
    erasure_hash, feedback_hash, schedule_hash = sha256(), sha256(), sha256()
    diagnostics = []

    def receive_feedback():
        nonlocal delivered_reports, minimum_feedback_age
        while pending and pending[0][0] <= now:
            due, _, payload, generated = heappop(pending)
            sender.accept(payload, due)
            delivered_reports += 1
            minimum_feedback_age = min(minimum_feedback_age, due - generated)

    def receive(equation, finish, high, mode):
        nonlocal receiver_prefix, receiver_high, last_report, reports, lost_reports, reverse_free
        receiver_high = max(receiver_high, high)
        rank_before = len(decoder.known) + len(decoder.rows)
        solved = decoder.insert(equation)
        gain = len(decoder.known) + len(decoder.rows) - rank_before
        assert gain in (0, 1)
        received_modes[mode] += 1
        innovative_modes[mode] += gain
        solved_by_mode[mode] += len(solved)
        for source in solved:
            known_at[source] = finish
        while receiver_prefix in decoder.known:
            receiver_prefix += 1
        if finish - last_report >= 5:
            last_report = finish
            reports += 1
            missing = receiver_high - len(decoder.known)
            deficit = max(0, missing - len(decoder.rows))
            payload = Snapshot(reports, receiver_prefix, receiver_high, deficit).encode()
            assert 28 + len(payload) == 46
            start = max(finish, reverse_free)
            serialization = 46 * 8 / 10000
            reverse_free = start + serialization
            lost = reverse_rng.random() < loss
            feedback_hash.update(bytes([lost]))
            if lost:
                lost_reports += 1
            else:
                heappush(pending, (start + 70 + serialization, reports, payload, finish))
        return gain, len(solved)

    def erased(size, finish):
        lost = forward_rng.random() < loss
        erasure_hash.update(bytes([lost]))
        schedule_hash.update(f"{size}/{finish:.12f}/{int(lost)};".encode())
        return lost

    for source in range(count):
        now = max(now, created[source])
        receive_feedback()
        queue_delay[source] = now - created[source]
        now += SOURCE_MS
        if not erased(1496, now):
            receive({source: 1}, now, source + 1, "source")
        credit += 26
        while credit >= 125:
            credit -= 125
            receive_feedback()
            serial += 1
            start, mode = sender.choose(serial, source + 1, now)
            end = source + 1
            assert 0 <= start < end and end - start <= 65535
            mode_counts[mode] += 1
            supports[end - start] += 1
            seed = serial * SERIAL_MULTIPLIER & 0xffffffff
            equation = packet_equation(start, end, seed)
            diagnostic = None
            if mode == "gated_local":
                # Receiver-only classification. No diagnostic is passed to the
                # sender, feedback encoder, packet scheduler or chosen equation.
                old_unknown = [index for index in range(sender.base, start) if index not in decoder.known]
                global_equation = packet_equation(sender.base, end, seed)
                global_unknown = reduced_equation(global_equation, decoder.known)
                local_unknown = reduced_equation(equation, decoder.known)
                differing = {index for index in global_unknown if index not in local_unknown}
                assert differing == {index for index in old_unknown if coefficient(seed, index)}
                diagnostic = dict(record_kind="analytic_gate_slot_diagnostic", analytic_case_id=task["analytic_case_id"],
                    repair_serial=serial, sent_at_ms=now, source_end=end, local_start=start, global_start=sender.base,
                    received_snapshot_sequence=sender.latest.sequence,
                    received_snapshot_age_ms=now - sender.received_at,
                    old_unknown_sources=len(old_unknown), old_unknown_nonzero_coefficients=len(differing),
                    reduced_equations_identical=global_unknown == local_unknown)
            now += REPAIR_MS
            lost = erased(1500, now)
            gain = solved = 0
            if not lost:
                gain, solved = receive(equation, now, end, mode)
            if diagnostic is not None:
                diagnostic.update(erased=lost, actual_rank_gain=gain, actual_newly_identified_sources=solved)
                diagnostics.append(diagnostic)
    selected = np.arange(task["warmup_sources"], count - task["tail_sources"])
    delay = known_at[selected] - created[selected]
    finite = np.isfinite(delay)
    lower_bound = np.where(finite, delay, now - created[selected])
    assert serial == count * 26 // 125
    unknown = count - len(decoder.known)
    row = dict(task, record_kind="analytic_feedback_gate_case", protocol_executions=0, policy=profile["name"],
        payload_bytes=1448, forward_mbps=100, reverse_mbps=10, base_rtt_ms=70, loss_rate=loss, loss_model="iid",
        source_ip_bytes=1496, repair_ip_bytes=1500, feedback_ip_bytes=46, feedback_payload_bytes=18,
        measured_sources=len(selected), repair_packets=serial, repair_per_source=serial / count,
        forward_total_wire_bytes=count * 1496 + serial * 1500,
        reverse_feedback_packets=reports, reverse_feedback_wire_bytes=46 * reports,
        delivered_feedback_reports=delivered_reports, lost_feedback_packets=lost_reports,
        pending_feedback_reports=len(pending), minimum_feedback_age_ms=minimum_feedback_age if delivered_reports else None,
        erasure_trace_sha256=erasure_hash.hexdigest(), feedback_erasure_trace_sha256=feedback_hash.hexdigest(),
        packet_schedule_sha256=schedule_hash.hexdigest(), source_arrival_trace_sha256=sha256(created.astype("<f8").tobytes()).hexdigest(),
        ideal_application_service_ceiling_mbps=1448 * 8 / ARRIVAL_MS / 1000, coding_deadline_ms=35,
        deadline_miss_fraction=float(np.mean(delay > 35)), deadline_miss_count=int(np.count_nonzero(delay > 35)),
        unresolved_at_horizon_fraction=float(np.mean(~finite)), unresolved_count=int(np.count_nonzero(~finite)),
        recovered_only_created_to_known_p99_ms=float(np.percentile(delay[finite], 99)) if finite.any() else None,
        cohort_latency_lower_bound_p99_ms=float(np.percentile(lower_bound, 99)), cohort_p99_is_lower_bound=bool(np.any(~finite)),
        sender_queue_p99_ms=float(np.percentile(queue_delay[selected], 99)), maximum_source_queue_ms=float(queue_delay.max()),
        final_known_sources=len(decoder.known), final_receiver_prefix=receiver_prefix, final_sender_confirmed_prefix=sender.base,
        full_horizon_unknown_count=unknown, full_horizon_residual_equation_rank=len(decoder.rows),
        full_horizon_rank_deficit=unknown - len(decoder.rows), largest_repair_support=max(supports),
        support_length_histogram=dict(supports), repair_mode_counts=dict(mode_counts),
        received_packet_mode_counts=dict(received_modes), innovative_equation_counts=dict(innovative_modes),
        newly_identified_source_counts=dict(solved_by_mode), modified_slots=len(diagnostics),
        modified_slots_with_old_unknown=sum(item["old_unknown_sources"] > 0 for item in diagnostics),
        modified_slots_with_different_reduced_equation=sum(not item["reduced_equations_identical"] for item in diagnostics),
        modified_received_slots=sum(not item["erased"] for item in diagnostics),
        modified_received_innovative=sum(item["actual_rank_gain"] for item in diagnostics),
        modified_slots_clean_old_equivalent=sum(item["old_unknown_sources"] == 0 and item["reduced_equations_identical"] for item in diagnostics))
    assert sum(mode_counts.values()) == serial
    assert sum(innovative_modes.values()) == len(decoder.known) + len(decoder.rows)
    return row, diagnostics


def summarize(rows):
    baseline = sorted((row for row in rows if row["policy"] == PROFILES[0]["name"]), key=lambda row: row["seed"])
    summaries = []
    for profile in PROFILES:
        selected = sorted((row for row in rows if row["policy"] == profile["name"]), key=lambda row: row["seed"])
        summary = dict(policy=profile["name"], cases=len(selected),
            frontier_eligible={row["seed"] for row in selected} == set(SEEDS) and all(row["unresolved_count"] == 0 for row in selected))
        for metric in METRICS:
            summary.update({metric + "_" + key: value for key, value in mean_ci([row[metric] for row in selected]).items()})
        difference = paired_difference([row[METRICS[0]] for row in selected], [row[METRICS[0]] for row in baseline])
        summary.update({"paired_miss_difference_" + key: value for key, value in difference.items()})
        summaries.append(summary)
    return summaries


def render(output, rows, summaries):
    figure = make_subplots(rows=2, cols=2, subplot_titles=("35 ms original-source deadline", "Recovered-only source P99",
        "Every case and deadline misses", "Every case and unresolved sources"))
    panels = ((1, 1, METRICS[0], 100), (1, 2, METRICS[2], 1), (2, 1, METRICS[0], 100), (2, 2, METRICS[1], 100))
    for index, profile in enumerate(PROFILES):
        selected = [row for row in rows if row["policy"] == profile["name"]]
        for grid_row, column, metric, scale in panels:
            ids = [str(row["analytic_case_id"]) for row in selected]
            figure.add_trace(go.Scatter(x=[row[metric] * scale if grid_row == 1 else row["analytic_case_id"] for row in selected],
                y=[row["ideal_application_service_ceiling_mbps"] if grid_row == 1 else row[metric] * scale for row in selected],
                ids=ids, text=ids, mode="markers" if grid_row == 1 else "markers+text", textposition="top center", cliponaxis=False,
                marker=dict(color=COLORS[index], size=9), name=profile["name"], legendgroup=profile["name"],
                showlegend=grid_row == 1 and column == 1, meta=dict(kind="raw-case"),
                customdata=[[row["analytic_case_id"], row["seed"], row["deadline_miss_count"], row["unresolved_count"], row["measured_sources"]] for row in selected],
                hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}<br>x %{x:.6g} · y %{y:.6g}"
                    "<br>Misses %{customdata[2]} / %{customdata[4]}<br>Unresolved %{customdata[3]} / %{customdata[4]}<extra>%{fullData.name}</extra>"),
                row=grid_row, col=column)
    complete = [row for row in summaries if row["frontier_eligible"]]
    for column, metric, scale in ((1, METRICS[0], 100), (2, METRICS[2], 1)):
        if complete:
            lowest = min(row[metric + "_mean"] for row in complete)
            best = [row for row in complete if row[metric + "_mean"] == lowest]
            figure.add_trace(go.Scatter(x=[lowest * scale] * len(best), y=[rows[0]["ideal_application_service_ceiling_mbps"]] * len(best),
                text=[row["policy"] for row in best], mode="markers", marker=dict(symbol="diamond-open", size=16, color="#203040"),
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
    figure.update_layout(height=880, template="plotly_white", margin=dict(l=80, r=35, t=65, b=145),
                         legend=dict(orientation="h", y=-.2, x=0))
    summary_table = "".join(f'<tr><td>{escape(row["policy"])}</td><td>{100 * row[METRICS[0] + "_mean"]:.4f}%</td>'
        f'<td>{100 * row[METRICS[1] + "_mean"]:.4f}%</td><td>{row[METRICS[2] + "_mean"]:.3f}</td>'
        f'<td>{100 * row["paired_miss_difference_mean"]:.4f} '
        f'[{100 * row["paired_miss_difference_ci_low"]:.4f}, {100 * row["paired_miss_difference_ci_high"]:.4f}]</td></tr>'
        for row in summaries)
    diagnosis_table = "".join(f'<tr><td>{row["analytic_case_id"]}</td><td>{escape(row["policy"])}</td>'
        f'<td>{row["modified_slots"]}</td><td>{row["modified_slots_clean_old_equivalent"]}</td>'
        f'<td>{row["modified_slots_with_different_reduced_equation"]}</td>'
        f'<td>{row["modified_received_innovative"]}/{row["modified_received_slots"]}</td>'
        f'<td>{row["full_horizon_unknown_count"]}/{row["full_horizon_rank_deficit"]}</td></tr>' for row in rows)
    passing = sum(row[METRICS[0]] <= .01 for row in rows)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Delayed-feedback repair gate</title><style>body{max-width:1250px;margin:25px auto;padding:18px;font:16px/1.5 system-ui;color:#213547}
.scroll{max-width:100%;overflow:auto}.chart{min-width:1100px}table{border-collapse:collapse;width:100%}
td,th{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}a{color:#12688d}code{overflow-wrap:anywhere}</style>
<h1>Delayed-feedback gating of global repair slots</h1>
<p>Every one of nine coding-only cases appears in each panel. Three policies use three paired seeds,
20,000 sources, 2,000 warmup and 2,000 trailing sources. All 16,000 measured original sources remain
in the 35 ms deadline denominator. Unresolved sources count as misses.</p>
<h2>Same charged schedule and causal feedback</h2><p>Sources cost 1496 IP bytes, repairs 1500 IP bytes,
and feedback 46 IP bytes. Integer 26/125 credit preserves every forward packet service time and
original source arrival. Forward/reverse rates are 100/10 Mbps, nominal RTT is 70 ms, and forward
and feedback erasures are 15% IID. The feedback payload serializes three uint32 fields for sequence,
prefix and highest observed source, followed by uint16 deficit, version and reserved fields.
Its 18 bytes plus IPv4/UDP consume exactly 46 bytes. It arrives after at least 70.0368 ms.</p>
<p>The control always uses a global repair at G16 slots. Each gate uses W128 at a G16 slot only
when its latest delivered snapshot is fresh and reports no old debt. Startup, stale feedback, or
highest−prefix&gt;128 with positive deficit selects global repair. Freshness is measured since
snapshot receipt, with a 15 or 30 ms threshold. Older sequence numbers cannot change the gate.
All other repair slots use W128. Every decision uses serialized delivered feedback and sender-local
state. Unresolved old sources remain in the receiver algebra and every applicable metric.</p>
<h2>Receiver-only diagnostic</h2><p>At each changed slot, the observer compares the chosen local
equation with the same-seed global equation after removing already-known sources. Their difference
contains exactly nonzero coefficients of currently unknown old sources. If all excluded sources
are known, both equations are identical in this decoder. These diagnostic facts are never supplied
to the sender. Actual innovation is the increase in total known-source count plus residual rank
when the received packet enters the decoder. Erased packets add no equation.</p>
<p>The window spans about 18.51 ms, while feedback needs at least 70.0368 ms. Thus a fresh received
snapshot still describes an old receiver state. This screen checks the effect of the resulting
causal decisions directly. Counts and per-slot diagnostics remain available for every case.</p>
<h2>Every case and empirical frontiers</h2><p>__PASSING__ of nine cases have at most 1% deadline misses.
The rate axis is the optimistic 1448-byte application service ceiling. Full TCP goodput, complete
frame release, coding CPU cost and original-segment cumulative ACK completion require protocol
measurements. Conditional P99 excludes unresolved sources. Diamonds show tied nondominated
configuration means with all three measured cohorts completely recovered. Dominated and incomplete
raw cases remain visible, with individual IDs in the lower panels.</p>
<div class="scroll" tabindex="0"><div class="chart">__CHART__</div></div>
<div class="scroll"><table><thead><tr><th>Policy</th><th>35 ms misses</th><th>Unresolved</th><th>Conditional P99 ms</th>
<th>Paired miss change pp [95% CI]</th></tr></thead><tbody>__SUMMARY__</tbody></table></div>
<h2>Slot decisions and complete-horizon counts</h2><p>Full-horizon unknown/rank-deficit counts include
warmup and trailing sources. Deadline metrics use the separate fixed measured cohort. The raw CSV
contains all local/global decision reasons, received packet counts, actual innovative ranks and
newly identified sources by mode. Clean-old and differing-equation classifications include erased
slots, while innovation ratios use received modified packets.</p>
<div class="scroll"><table><thead><tr><th>Case</th><th>Policy</th><th>Modified G16 slots</th>
<th>Clean old sources / identical row</th><th>Different unknown row</th><th>Received innovative/received</th>
<th>Full-horizon unknown/deficit</th></tr></thead><tbody>__DIAGNOSIS__</tbody></table></div>
<p><a href="analytic-cases.csv">Every raw case</a> · <a href="analytic-summary.csv">Means and paired intervals</a> ·
<a href="slot-diagnostics.csv">Every changed-slot diagnostic</a> · <a href="manifest.json">Frozen execution sources</a> ·
<a href="validation-checks.json">Coverage and budget checks</a> · <a href="finite-validation.json">Finite decoding and causality checks</a></p></html>'''
    chart = figure.to_html(full_html=False, include_plotlyjs=True, div_id="feedback-gate-pareto", config=dict(responsive=True))
    (output / "report.html").write_text(page.replace("__CHART__", chart).replace("__SUMMARY__", summary_table)
        .replace("__DIAGNOSIS__", diagnosis_table).replace("__PASSING__", str(passing)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    tasks = [dict(analytic_case_id=index * len(SEEDS) + replication + 1, profile=profile, seed=seed,
                  source_count=20000, warmup_sources=2000, tail_sources=2000)
             for index, profile in enumerate(PROFILES) for replication, seed in enumerate(SEEDS)]
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(reference.__file__).resolve(), root / "tests/test_feedback_gate.py",
             root / "tests/test_recursive_parity.py",
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_feedback_gate_manifest", protocol_executions=0,
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
    slots = args.out / "slot-diagnostics"
    cases.mkdir(exist_ok=True)
    slots.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (cases / f'{task["analytic_case_id"]:03d}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row, diagnostics = future.result()
            row["execution_source_sha256"] = hashes
            slot_path = slots / f'{row["analytic_case_id"]:03d}.json'
            slot_path.write_text(json.dumps(diagnostics, indent=2, allow_nan=False) + "\n")
            row["slot_diagnostic_sha256"] = sha256(slot_path.read_bytes()).hexdigest()
            target = cases / f'{row["analytic_case_id"]:03d}.json'
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
            temporary.replace(target)
            print(f'Case {row["analytic_case_id"]} {row["policy"]} miss={100 * row[METRICS[0]]:.4f}% '
                  f'unresolved={100 * row[METRICS[1]]:.4f}% modified={row["modified_slots"]}', flush=True)
    rows = [json.loads((cases / f'{task["analytic_case_id"]:03d}.json').read_text()) for task in tasks]
    for seed in SEEDS:
        paired = [row for row in rows if row["seed"] == seed]
        for field in ("erasure_trace_sha256", "feedback_erasure_trace_sha256", "packet_schedule_sha256",
                      "source_arrival_trace_sha256", "forward_total_wire_bytes", "reverse_feedback_wire_bytes", "measured_sources"):
            assert len({row[field] for row in paired}) == 1
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not changed, changed
    summaries = summarize(rows)
    reference.write_csv(args.out / "analytic-cases.csv", rows)
    reference.write_csv(args.out / "analytic-summary.csv", summaries)
    diagnostics = [item for path in sorted(slots.glob("*.json")) for item in json.loads(path.read_text())]
    reference.write_csv(args.out / "slot-diagnostics.csv", diagnostics)
    checks = dict(cases=len(rows), plotted_case_ids=[row["analytic_case_id"] for row in rows],
        points_per_panel=len(rows), panels=4, paired_packet_and_arrival_traces=True,
        fixed_forward_and_feedback_byte_budgets=True, original_source_denominator=True,
        changed_during_run=changed, diagnostic_slots=len(diagnostics), diagnostic_only_receiver_information=True,
        raw_case_sha256={path.name: sha256(path.read_bytes()).hexdigest() for path in sorted(cases.glob("*.json"))})
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    render(args.out, rows, summaries)


if __name__ == "__main__":
    main()
