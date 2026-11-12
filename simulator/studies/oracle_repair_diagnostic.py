"""Fixed-arrival coding diagnostic with an unimplementable loss-information oracle.

Actual saved source sizes and arrivals are retained. Every ratio-driven repair
slot is charged, including an oracle slot with no missing source. The causal
case reuses the existing shared transport's coding and feedback methods.
The FIFO oracle learns each packet's loss immediately at serialization finish.
Both cases use a separate ideal 35 ms return-path completion proxy.

This study emits analytic_* metrics and component records. Its outputs are
excluded from the protocol-run archive and have their own all-case chart.
"""

import argparse
from collections import defaultdict, deque
import csv
from hashlib import sha256
from html import escape
import json
from pathlib import Path

import numpy as np
import plotly.graph_objects as go

from l2tunnel_sim.compact import CompactSource
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.shared_records import SharedRecordConfig, SharedRecordTransport


class FixedSourceCoding(SharedRecordTransport):
    """Reuse causal repair coefficients and feedback on frozen source arrivals."""

    def add_source(self, item):
        index = item["source_id"]
        if index != len(self.sources):
            raise ValueError("source arrivals must retain their original source-ID order")
        self.submitted_bytes += item["protected_bytes"]
        self.sent_bytes += item["protected_bytes"]
        source = CompactSource(index, item["protected_bytes"], self.sent_bytes)
        self.sources.append(source)
        # Coding coefficients operate on the same zero-extended symbol domain.
        # Record and fragment dependencies are reconstructed from the saved map.
        self.source_payloads.append(None)
        self.sim.active_source = index
        self.sim.send(False, self.source_header + source.size, "source", lambda: self._receive_source(source))
        self.sim.active_source = None
        self.credit += self.credit_numerator
        while self.credit >= self.credit_denominator:
            self.credit -= self.credit_denominator
            self._repair(False)
        self.sim.peak_unconfirmed = max(self.sim.peak_unconfirmed, len(self.sources) - self.base)

    def _new_known(self, symbols):
        for index in symbols:
            self.sim.known_at[index] = self.sim.now
        super()._new_known(symbols)

    def _deliver_symbol(self, index):
        # Full record/channel/TCP ordering is evaluated from byte membership
        # after the coding event loop, without manufacturing ACK feedback.
        pass


class FixedReplay(Simulation):
    def __init__(self, task, sources):
        self.task = task
        self.input_sources = sources
        super().__init__(Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"]),
                         Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"]),
                         (PathConfig(task["forward_mbps"], task["reverse_mbps"]),),
                         Strategy("Fixed-arrival analytical replay"), task["seed"])
        self.known_at = [float("inf")] * len(sources)
        self.oracle_queue = deque()
        self.oracle_peak_queue = 0
        self.oracle_idle_repairs = 0
        self.oracle_useful_repairs = 0
        self.packets = []
        self.active_source = None
        self.peak_unconfirmed = 0
        self.forward = FixedSourceCoding(self, False, SharedRecordConfig(
            repair_ratio=task["repair_ratio"], feedback_ms=1, feedback_packets=64,
            independent_delivery=False, repair_window_sources=128, global_repair_every=16))

    def make_transports(self, rng):
        return None, None

    def produce(self):
        for item in self.input_sources:
            self.at(item["enqueue_s"], self.forward.add_source, item)

    def send(self, reverse, size, kind, receive):
        if reverse:
            return super().send(reverse, size, kind, receive)
        link = self.links[False][0]
        finish = link.finish(self.now, size)
        source_id = self.active_source if kind == "source" else None
        packet = dict(record_kind="analytic_packet", packet_id=len(self.packets), kind=kind,
                      source_id=source_id, enqueue_s=self.now, transmission_start_s=max(self.now, link.free_at),
                      transmission_finish_s=finish, bytes=size, lost=None, oracle_target=None)
        link.free_at = finish
        self.packets.append(packet)

        def depart():
            self.wire[False][kind] += size
            self.datagrams[False][kind] += 1
            lost = link.erasures.lost()
            packet["lost"] = lost
            if lost:
                self.erasures[False][kind] += 1
            propagation = None if lost else max(0, link.rtt / 2 + link.jitter_rng.uniform(-link.jitter, link.jitter))
            if self.task["method"] == "oracle_fifo":
                self._oracle_depart(packet, propagation)
            elif not lost:
                self.at(self.now + propagation, receive)

        self.at(finish, depart)
        return finish, link.rtt

    def _oracle_depart(self, packet, propagation):
        if packet["kind"] == "source":
            if packet["lost"]:
                self.oracle_queue.append(packet["source_id"])
                self.oracle_peak_queue = max(self.oracle_peak_queue, len(self.oracle_queue))
            else:
                self.known_at[packet["source_id"]] = self.now + propagation
            return
        if not self.oracle_queue:
            self.oracle_idle_repairs += 1
            return
        packet["oracle_target"] = self.oracle_queue[0]
        if not packet["lost"]:
            self.known_at[self.oracle_queue.popleft()] = self.now + propagation
            self.oracle_useful_repairs += 1


def load_inputs(source_path, segment_path):
    with Path(source_path).open() as stream:
        sources = [dict(source_id=int(row["source_id"]), flow_id=int(row["flow_id"]),
                        record_serial=int(row["record_serial"]), segment_id=int(row["segment_id"]),
                        is_context=row["is_context"] == "True", enqueue_s=float(row["enqueue_s"]),
                        protected_bytes=int(row["protected_bytes"])) for row in csv.DictReader(stream)]
    sources.sort(key=lambda item: item["source_id"])
    if [item["source_id"] for item in sources] != list(range(len(sources))):
        raise ValueError("trace must include every original source exactly once")
    if any(right["enqueue_s"] < left["enqueue_s"] for left, right in zip(sources, sources[1:])):
        raise ValueError("source trace is not FIFO")
    with Path(segment_path).open() as stream:
        segments = [dict(flow_id=int(row["flow_id"]), segment_id=int(row["segment_id"]),
                         original_submission_s=float(row["original_submission_s"])) for row in csv.DictReader(stream)]
    return sources, segments


def delivered_segments(sources, segments, known_at, return_delay_s, cutoff):
    records = defaultdict(list)
    for source in sources:
        records[source["flow_id"], source["record_serial"]].append(source)
    channel_complete = defaultdict(float)
    first_delivery = defaultdict(lambda: float("inf"))
    for (flow, serial), members in sorted(records.items()):
        ready = max(known_at[item["source_id"]] for item in members)
        channel_complete[flow] = max(channel_complete[flow], ready)
        if not members[0]["is_context"]:
            segment = members[0]["segment_id"]
            first_delivery[flow, segment] = min(first_delivery[flow, segment], channel_complete[flow])
    contiguous = defaultdict(float)
    result = []
    for item in sorted(segments, key=lambda item: (item["flow_id"], item["segment_id"])):
        flow, index = item["flow_id"], item["segment_id"]
        contiguous[flow] = max(contiguous[flow], first_delivery[flow, index])
        delivered = contiguous[flow]
        completion = delivered + return_delay_s
        result.append(dict(record_kind="analytic_segment", **item,
            analytic_delivery_s=delivered if delivered <= cutoff else None,
            analytic_ideal_return_completion_s=completion if completion <= cutoff else None,
            analytic_delivery_ms=(delivered - item["original_submission_s"]) * 1000 if delivered <= cutoff else None,
            analytic_ideal_return_latency_ms=(completion - item["original_submission_s"]) * 1000 if completion <= cutoff else None,
            analytic_delivery_censored=delivered > cutoff, analytic_completion_censored=completion > cutoff))
    return result


def quantiles(values):
    return {f"p{level}_ms": float(np.percentile(values, level)) if values else None for level in (50, 95, 99)}


def analyze(task, sources, segments):
    sim = FixedReplay(task, sources).run()
    cutoff = task["duration_s"] + task["drain_s"]
    delivered = delivered_segments(sources, segments, sim.known_at, task["rtt_ms"] / 2000, cutoff)
    budget = 1.5 * task["rtt_ms"]
    completions = [item["analytic_ideal_return_latency_ms"] for item in delivered
                   if item["analytic_ideal_return_latency_ms"] is not None]
    misses = sum(value > budget for value in completions)
    censored = [item for item in delivered if item["analytic_completion_censored"]]
    known_censored_misses = sum((cutoff - item["original_submission_s"]) * 1000 > budget for item in censored)
    received_in_traffic = sum(item["analytic_delivery_s"] is not None
                              and item["analytic_delivery_s"] <= task["duration_s"] for item in delivered)
    received_steady = sum(item["analytic_delivery_s"] is not None
                         and task["warmup_s"] <= item["analytic_delivery_s"] <= task["duration_s"] for item in delivered)
    source_rows = [dict(record_kind="analytic_source", **item,
                       analytic_known_s=sim.known_at[item["source_id"]] if sim.known_at[item["source_id"]] <= cutoff else None,
                       analytic_source_latency_ms=(sim.known_at[item["source_id"]] - item["enqueue_s"]) * 1000
                       if sim.known_at[item["source_id"]] <= cutoff else None,
                       analytic_censored=sim.known_at[item["source_id"]] > cutoff) for item in sources]
    packet_fields = ("kind", "source_id", "enqueue_s", "transmission_start_s", "transmission_finish_s", "bytes", "lost")
    digest = sha256()
    for packet in sim.packets:
        digest.update(json.dumps([packet[key] for key in packet_fields], separators=(",", ":")).encode())
        digest.update(b"\n")
    forward_bytes = sum(sim.wire[False].values())
    transmitted = [packet for packet in sim.packets if packet["lost"] is not None]
    traffic_bytes = sum(packet["bytes"] for packet in transmitted if packet["transmission_finish_s"] <= task["duration_s"])
    row = dict(record_kind="coding_only_diagnostic", **task,
        analytic_offered_segments=len(segments), analytic_source_count=len(sources),
        analytic_forward_packet_count=len(transmitted), analytic_forward_bytes=forward_bytes,
        analytic_forward_during_traffic_bytes=traffic_bytes,
        analytic_repair_packet_count=sim.datagrams[False]["repair"],
        analytic_source_packet_count=sim.datagrams[False]["source"],
        analytic_source_losses=sim.erasures[False]["source"], analytic_repair_losses=sim.erasures[False]["repair"],
        analytic_reverse_feedback_bytes=sum(sim.wire[True].values()),
        analytic_full_delivery_mbps=received_in_traffic * task["payload_bytes"] * 8 / task["duration_s"] / 1e6,
        analytic_steady_delivery_mbps=received_steady * task["payload_bytes"] * 8 / (task["duration_s"] - task["warmup_s"]) / 1e6,
        analytic_unresolved_sources=sum(item["analytic_censored"] for item in source_rows),
        analytic_unresolved_segments=len(censored),
        analytic_completion_deadline_miss_fraction_lower=(misses + known_censored_misses) / len(segments),
        analytic_completion_deadline_miss_fraction_upper=(misses + len(censored)) / len(segments),
        analytic_completion_completed_misses=misses,
        analytic_packet_schedule_loss_sha256=digest.hexdigest(),
        analytic_oracle_peak_missing_queue=sim.oracle_peak_queue if task["method"] == "oracle_fifo" else None,
        analytic_oracle_idle_repair_slots=sim.oracle_idle_repairs if task["method"] == "oracle_fifo" else None,
        analytic_oracle_useful_repair_slots=sim.oracle_useful_repairs if task["method"] == "oracle_fifo" else None,
        analytic_causal_peak_unconfirmed_sources=sim.peak_unconfirmed if task["method"] == "causal_rlnc" else None,
        analytic_causal_sender_window_would_bind=(sim.peak_unconfirmed > sim.forward.config.block_sources)
            if task["method"] == "causal_rlnc" else None,
        analytic_completion_proxy="native contiguous delivery plus nominal lossless return propagation",
        analytic_protocol_target_claim=False)
    for prefix, values in (("analytic_completion_", completions),
                           ("analytic_application_", [item["analytic_delivery_ms"] for item in delivered if item["analytic_delivery_ms"] is not None]),
                           ("analytic_source_", [item["analytic_source_latency_ms"] for item in source_rows if item["analytic_source_latency_ms"] is not None])):
        row.update({prefix + key: value for key, value in quantiles(values).items()})
    assert traffic_bytes * 8 / task["duration_s"] <= task["forward_mbps"] * 1e6 + 1e-7
    assert forward_bytes == sum(packet["bytes"] for packet in transmitted)
    return row, delivered, source_rows, sim.packets


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def make_report(out, rows, references):
    figure = go.Figure()
    for method, label in (("causal_rlnc", "Causal RLNC, frozen arrivals, ideal return"),
                          ("oracle_fifo", "Instant-loss FIFO oracle, ideal return")):
        selected = [row for row in rows if row["method"] == method]
        figure.add_trace(go.Scatter(name=label, mode="markers+text",
            x=[100 * row["analytic_completion_deadline_miss_fraction_upper"] for row in selected],
            y=[row["analytic_full_delivery_mbps"] for row in selected],
            text=[f"{row['run_id']} / seed {row['replication']}" for row in selected], textposition="top center",
            marker=dict(size=12), customdata=[[row["analytic_completion_p99_ms"], row["analytic_unresolved_sources"]] for row in selected],
            hovertemplate="Miss upper bound %{x:.4f}%<br>Delivery %{y:.4f} Mbps<br>Completed proxy P99 %{customdata[0]:.3f} ms<br>Unresolved sources %{customdata[1]}<extra>%{fullData.name}</extra>"))
    figure.add_vline(x=1, line_dash="dot", line_color="#a54433")
    figure.update_layout(template="plotly_white", height=470, font=dict(family="system-ui", size=13),
                         title="Every fixed-arrival diagnostic point", xaxis_title="Completion-proxy deadline-miss upper bound (%)",
                         yaxis_title="Full-interval contiguous delivery (Mbps)", legend=dict(orientation="h", y=-.3),
                         margin=dict(b=145,t=65,l=70,r=30))
    chart = figure.to_html(full_html=False, include_plotlyjs=True, config=dict(responsive=True, displaylogo=False))
    table_rows = "".join(f"<tr><td><a href='runs/{row['run_id']:05d}.json'>{row['run_id']}</a></td><td>{row['replication']}</td><td>{escape(row['method'])}</td><td>{row['analytic_full_delivery_mbps']:.3f}</td><td>{row['analytic_steady_delivery_mbps']:.3f}</td><td>{row['analytic_completion_p99_ms']:.3f}</td><td>{100*row['analytic_completion_deadline_miss_fraction_upper']:.4f}%</td><td>{row['analytic_unresolved_sources']}</td><td>{row['analytic_unresolved_segments']}</td></tr>" for row in rows)
    reference_rows = "".join(f"<tr><td>{ref['replication']}</td><td>{ref['full_mbps']:.3f}</td><td>{ref['steady_mbps']:.3f}</td><td>{ref['actual_ack_p99_ms']:.3f}</td><td>{100*ref['actual_miss_fraction']:.4f}%</td><td>{ref['unresolved_segments']}</td></tr>" for ref in references)
    accounting_rows = "".join(f"<tr><td>{row['run_id']}</td><td>{row['analytic_source_packet_count']:,}</td><td>{row['analytic_repair_packet_count']:,}</td><td>{row['analytic_forward_bytes']:,}</td><td>{row['analytic_source_losses']:,}</td><td>{row['analytic_repair_losses']:,}</td><td>{row['analytic_oracle_idle_repair_slots'] if row['analytic_oracle_idle_repair_slots'] is not None else '—'}</td><td>{row['analytic_oracle_peak_missing_queue'] if row['analytic_oracle_peak_missing_queue'] is not None else '—'}</td></tr>" for row in rows)
    links = "".join(f"<li>Run {row['run_id']} <a href='components/{row['run_id']:05d}-segments.csv'>all segments</a>, <a href='components/{row['run_id']:05d}-sources.csv'>all sources</a>, <a href='components/{row['run_id']:05d}-packets.csv'>all charged packets</a></li>" for row in rows)
    html = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Oracle repair scheduling diagnostic</title><style>body{{font:16px/1.5 system-ui;background:#f5f7f9;color:#203040;margin:0}}main{{max-width:1180px;margin:auto;padding:30px 24px}}.card{{background:white;border:1px solid #dae2e9;border-radius:10px;padding:22px;margin:20px 0}}.notice{{border-left:6px solid #9b5c31}}h1,h2{{line-height:1.2}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{padding:9px;border-bottom:1px solid #e2e8ee;text-align:right}}th:first-child,td:first-child{{text-align:left}}thead{{background:#eef3f7}}.scroll{{overflow-x:auto}}a{{color:#235f96}}li{{margin:7px 0}}</style></head><body><main>
<h1>Oracle repair scheduling diagnostic</h1><div class='card notice'><h2>Instantaneous loss knowledge is an optimistic analytical assumption</h2><p>The oracle learns packet loss at serialization finish and spends each successful repair on the oldest lost source. This information is unavailable to a causal sender over the modeled 70 ms RTT. The completion proxy adds exactly 35 ms of lossless return propagation to native contiguous delivery. TCP ACK generation, reverse ACK queueing and ACK loss are excluded from that proxy.</p><p>The fixed 10-second source arrivals, original TCP segment submission times, flow/channel dependencies, contexts and fragments come from the three saved aligned stage traces. Each systematic packet uses its recorded protected length plus 36 bytes. Every ratio-0.208 repair slot costs 1500 bytes. Both cases share the same 100 Mbps packet schedule and IID 15% forward losses. The reverse feedback path is 10 Mbps.</p></div>
<div class='card'><h2>All analytical points</h2>{chart}<div class='scroll'><table><thead><tr><th>Run</th><th>Seed</th><th>Method</th><th>Full Mbps</th><th>Steady Mbps</th><th>Completed proxy P99 ms</th><th>Miss upper bound</th><th>Unresolved sources</th><th>Unresolved segments</th></tr></thead><tbody>{table_rows}</tbody></table></div><p>All offered source and segment records remain in the exported components. The miss upper bound counts every unresolved segment as a miss. Completed-sample percentiles are shown alongside those unresolved counts. The 2-second warmup and 20-second drain match the trace study.</p></div>
<div class='card'><h2>Actual causal TCP observations that supplied the arrivals</h2><div class='scroll'><table><thead><tr><th>Seed</th><th>Full Mbps</th><th>Steady Mbps</th><th>Actual cumulative ACK P99 ms</th><th>Actual miss fraction</th><th>Unresolved segments</th></tr></thead><tbody>{reference_rows}</tbody></table></div><p>These reference values retain their original actual ACK behavior, variable source framing, native TCP source generation and tail-repair recovery. The frozen-arrival analytical comparisons use ratio-driven repairs only. All remaining unknown sources are censored at the end of the drain. Existing causal coding uses its W128/G16 support rule, GF256 rank decoder and delayed lossy feedback. Record and TCP ordering are reconstructed from the saved source membership.</p></div>
<div class='card'><h2>Charged forward service</h2><div class='scroll'><table><thead><tr><th>Run</th><th>Sources</th><th>Repairs</th><th>Forward bytes</th><th>Source losses</th><th>Repair losses</th><th>Idle oracle repair slots</th><th>Peak oracle missing queue</th></tr></thead><tbody>{accounting_rows}</tbody></table></div><p>Idle oracle repair slots remain on the wire and consume their shared loss draw. The saved packet schedule hashes include exact packet sizes, enqueue and serialization times, and loss outcomes. Causal feedback bytes are separately recorded in the raw diagnostic rows. Oracle loss-information traffic and the ideal ACK return are uncharged analytical assumptions.</p></div>
<div class='card'><h2>Interpretation boundaries</h2><p>A favorable oracle result shows that this finite packet schedule can repair its realized losses quickly when repair service targets missing bytes with instantaneous information. It motivates studying causal partial recovery and repair support structure. A miss rate above 1% diagnoses this precise arrival trace, packet schedule, loss realization and FIFO oracle policy. A coding diagnostic is insufficient to establish a deployable protocol result at the 80 Mbps and 105 ms joint target.</p><p>The stored segment origin remains its original TCP submission time. Channel record prefix waits and native TCP contiguous-delivery waits remain in both cases. The existing model uses GF256 coefficient elimination and excludes payload coding and CPU costs.</p></div>
<div class='card'><h2>Data and provenance</h2><ul><li><a href='experiment.json'>Tasks, input hashes and executed source hashes</a></li><li><a href='all-cases.csv'>Every diagnostic point</a></li><li><a href='pairing-checks.json'>Identical packet-schedule and loss checks</a></li><li><a href='source-verification.json'>Execution source verification</a></li>{links}</ul></div></main></body></html>"""
    (out / "report.html").write_text(html)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    originals = [json.loads(path.read_text()) for path in sorted((args.input / "runs").glob("*.json"))]
    selected = [row for row in originals if row.get("stage_instrumentation")]
    tasks, input_files, references = [], [], []
    for original in selected:
        stem = f"{original['run_id']:05d}"
        source_path = (args.input / "stages" / (stem + "-sources.csv")).resolve()
        segment_path = (args.input / "stages" / (stem + "-segments.csv")).resolve()
        input_files.extend((source_path, segment_path, (args.input / "runs" / (stem + ".json")).resolve()))
        references.append(dict(replication=original["replication"], full_mbps=original["application_goodput_mbps"],
            steady_mbps=original["steady_application_goodput_mbps"], actual_ack_p99_ms=original["with_drain_tcp_all_segment_ack_rtt_p99_ms"],
            actual_miss_fraction=original["with_drain_tcp_all_segment_ack_rtt_cohort_miss_fraction_upper"],
            unresolved_segments=original["with_drain_tcp_all_segment_ack_rtt_cohort_censored_segments"]))
        for method in ("causal_rlnc", "oracle_fifo"):
            tasks.append(dict(run_id=len(tasks) + 1, method=method, source_trace=str(source_path),
                segment_trace=str(segment_path), repair_ratio=.208,
                **{key: original[key] for key in ("seed", "replication", "duration_s", "warmup_s", "drain_s",
                    "forward_mbps", "reverse_mbps", "rtt_ms", "loss_rate", "loss_model", "payload_bytes")}))
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), *(root / "src/l2tunnel_sim" / name for name in (
        "shared_records.py", "compact.py", "coding.py", "model.py", "config.py", "tcp.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="coding_only_manifest", tasks=tasks, sources=hashes,
        inputs={str(path): sha256(path.read_bytes()).hexdigest() for path in input_files},
        assumptions=["Source arrivals, original segment origins and byte membership are frozen from saved stage traces",
          "Systematic packet sizes use recorded protected_bytes plus 36; every scheduled repair costs 1500 bytes",
          "Ratio-only repair slots stop with the final source; no additional drain or tail repair slots are added",
          "Causal coding reuses the W128/G16 shared transport and its delayed lossy feedback",
          "Oracle loss information is instantaneous at serialization finish and costs zero bytes",
          "Oracle repairs select the oldest missing source and retain charged idle slots",
          "Record prefix and native TCP contiguous delivery dependencies remain intact",
          "Completion proxy adds 35 ms lossless return propagation without actual ACK packets",
          "All unresolved sources and segments remain explicitly censored",
          "These coding-only diagnostic points are excluded from the protocol archive"])
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "experiment.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing diagnostic tasks or source hashes differ")
    save_json(target, manifest)
    for path in files:
        copy = args.out / "sources" / path.relative_to(root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    for name in ("runs", "components"):
        (args.out / name).mkdir(exist_ok=True)
    rows = []
    for task in tasks:
        path = args.out / "runs" / f"{task['run_id']:05d}.json"
        if path.exists():
            rows.append(json.loads(path.read_text()))
            continue
        sources, segments = load_inputs(task["source_trace"], task["segment_trace"])
        row, segment_rows, source_rows, packets = analyze(task, sources, segments)
        stem = f"{task['run_id']:05d}"
        for name, records in (("segments", segment_rows), ("sources", source_rows), ("packets", packets)):
            write_csv(args.out / "components" / f"{stem}-{name}.csv", records)
        save_json(path, row)
        rows.append(row)
        print(f"run {row['run_id']} {row['method']} proxy99={row['analytic_completion_p99_ms']:.3f} "
              f"miss={row['analytic_completion_deadline_miss_fraction_upper']:.6f} "
              f"unresolved={row['analytic_unresolved_sources']}", flush=True)
    checks = [dict(record_kind="analytic_pairing", replication=left["replication"],
                   identical_schedule_and_loss=left["analytic_packet_schedule_loss_sha256"] == right["analytic_packet_schedule_loss_sha256"],
                   digest=left["analytic_packet_schedule_loss_sha256"]) for left, right in zip(rows[::2], rows[1::2])]
    save_json(args.out / "pairing-checks.json", checks)
    write_csv(args.out / "all-cases.csv", rows)
    make_report(args.out, rows, references)
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    save_json(args.out / "source-verification.json", dict(changed_during_run=changed))
    if changed or not all(item["identical_schedule_and_loss"] for item in checks):
        raise RuntimeError("diagnostic source or packet pairing verification failed")


if __name__ == "__main__":
    main()
