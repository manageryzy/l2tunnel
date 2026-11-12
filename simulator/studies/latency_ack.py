"""Compare native, reliable, and superseded cumulative ACKs on shared links."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from time import perf_counter

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_ack import CoalescedACKTCP
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.multiflow import MultiFlow
from l2tunnel_sim.stats import mean_ci

import payload_sizes


class ObservedCoalescedACKTCP(payload_sizes.TCPRTTObserver, CoalescedACKTCP):
    pass


def make_simulation(task):
    profile = task["profile"]
    if "ack_coalesce_ms" not in profile:
        return payload_sizes.make_simulation(task)
    payload = task["payload_bytes"]
    rate = profile.get("payload_rate_mbps")
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"],
                      frame_bytes=payload + 66, payload_bytes=payload,
                      window_bytes=profile.get("window_bytes", 4 * 1048576),
                      frame_interval_ms=payload * 8 / (rate * 1000) if rate else 0)
    factory = partial(ObservedCoalescedACKTCP,
                      compact_config=CompactConfig(**profile["compact"]),
                      transport_type=CompactARQTransport,
                      ack_coalesce_ms=profile["ack_coalesce_ms"],
                      ack_copies=profile.get("ack_copies", 1),
                      ack_copy_spacing_ms=profile.get("ack_copy_spacing_ms", .1),
                      acknowledged_segment_slow_start=profile.get("acknowledged_segment_slow_start", False))
    return MultiFlow(Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"]), traffic,
                     (PathConfig(task["forward_mbps"], task["reverse_mbps"]),),
                     Strategy(profile["name"], mode="tcp", tcp_rto_min_ms=profile["rto_min_ms"]),
                     task["seed"], profile["flow_count"], simulation_factory=factory)


def execute(task):
    started = perf_counter()
    sim = make_simulation(task)
    snapshots = {}

    def sample(time):
        snapshots[time] = (
            sum(flow.tcp_received for flow in sim.flows),
            sum(sum(flow.datagrams[False].values()) for flow in sim.flows),
        )

    sim.flows[0].at(task["warmup_s"], sample, task["warmup_s"])
    sim.flows[0].at(task["duration_s"], sample, task["duration_s"])
    sim.run()
    row = {key: value for key, value in task.items() if key != "profile"}
    row.update(profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
               **sim.measurements(), **payload_sizes.rtt_metrics(sim, task["warmup_s"]))
    for name in ("tcp_timeouts", "tcp_retransmissions", "tcp_fast_retransmits"):
        row[name] = sum(getattr(flow, name) for flow in sim.flows)
    start, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    steady_frames = end[0] - start[0]
    row["application_goodput_mbps"] = row["tcp_goodput_mbps"]
    row["application_capacity_pct"] = 100 * row["application_goodput_mbps"] / task["forward_mbps"]
    row["steady_application_goodput_mbps"] = 8 * steady_frames * task["payload_bytes"] / (
        (task["duration_s"] - task["warmup_s"]) * 1e6)
    row["steady_application_capacity_pct"] = 100 * row["steady_application_goodput_mbps"] / task["forward_mbps"]
    row["steady_forward_datagrams"] = end[1] - start[1]
    row["steady_delivered_frames"] = steady_frames
    row["extra_packets_per_delivered_record_pct"] = 100 * (row["forward_datagrams"] / row["tcp_delivered_frames"] - 1)
    row["steady_extra_packets_per_delivered_record_pct"] = 100 * ((end[1] - start[1]) / steady_frames - 1)
    row["forward_extra_payload_bytes_pct"] = 100 * (row["forward_wire_bytes"] / row["tcp_payload_bytes"] - 1)
    row["duplex_extra_payload_bytes_pct"] = 100 * (
        (row["forward_wire_bytes"] + row["reverse_wire_bytes"]) / row["tcp_payload_bytes"] - 1)
    row["reverse_measurement_mbps"] = row["reverse_wire_bytes_during_measurement"] * 8 / (task["duration_s"] * 1e6)
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    row["outer_all_confirmed"] = all(
        transport.base == len(transport.sources) and transport.buffer_bytes == 0 and not transport.pending
        for flow in sim.flows for transport in (flow.compact_forward, flow.compact_reverse))
    row["ack_all_flushed"] = all(getattr(flow, "pending_ack", None) is None for flow in sim.flows)
    row["transport"] = "compact_inner_tcp"
    row["measurement_payload_kind"] = "modeled TCP application data"
    for name in ("ack_generated", "ack_superseded", "ack_transmitted", "ack_duplicates_transmitted",
                 "ack_copy_duplicates"):
        row[name] = sum(getattr(flow, name, 0) for flow in sim.flows)
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_l2_bytes"] == row["released_frames"] * (task["payload_bytes"] + 66)
    assert row["forward_wire_bytes_during_measurement"] <= task["forward_mbps"] * 125000 * task["duration_s"]
    assert row["reverse_wire_bytes_during_measurement"] <= task["reverse_mbps"] * 125000 * task["duration_s"]
    return row


def profiles():
    common = dict(compact={"header_profile": "tcp_delta", "repair_ratio": 0}, recovery="arq",
                  flow_count=16, controller="cubic", rto_min_ms=1000)
    return [dict(common, name="Native ACK", reliable_acks=False),
            dict(common, name="Reliable compact ACK", reliable_acks=True),
            *(dict(common, name=f"Coalesced ACK {delay:g} ms", reliable_acks=False,
                   ack_coalesce_ms=delay) for delay in (.25, .5, 1))]


def summarize(rows):
    summaries = payload_sizes.summarize(rows)
    metrics = ("forward_extra_payload_bytes_pct", "duplex_extra_payload_bytes_pct",
               "reverse_measurement_mbps", "ack_generated", "ack_superseded",
               "ack_transmitted", "ack_duplicates_transmitted", "ack_copy_duplicates", "forward_datagrams",
               "reverse_datagrams", "forward_wire_bytes", "reverse_wire_bytes")
    for summary in summaries:
        group = [row for row in rows if row["strategy"] == summary["strategy"]
                 and row["payload_bytes"] == summary["payload_bytes"]]
        for metric in metrics:
            for key, value in mean_ci([row[metric] for row in group]).items():
                if key != "method":
                    summary[metric + "_" + key] = value
        summary["ack_flushed_replications"] = sum(row["ack_all_flushed"] for row in group)
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--replications", type=int, default=3)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--drain", type=float, default=5)
    parser.add_argument("--payloads", type=int, nargs="+", default=[64, 256, 1448])
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than duration")
    selected = json.loads(args.profiles.read_text()) if args.profiles else profiles()
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    plan = []
    for profile in selected:
        for payload in args.payloads:
            for replication, seed in enumerate(seeds, 1):
                plan.append(dict(run_id=len(plan) + 1, profile=profile, forward_mbps=100,
                                 reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model="iid",
                                 payload_bytes=payload, duration_s=args.duration, warmup_s=args.warmup,
                                 drain_s=args.drain, replication=replication, seed=seed))
    args.out.mkdir(parents=True, exist_ok=True)
    source_root = Path(__file__).resolve().parents[1]
    paths = [Path(__file__).resolve(), Path(payload_sizes.__file__).resolve(),
             *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest() for path in paths}
    manifest = dict(tasks=plan, sources=hashes,
                    ack_semantics="Only unsent advancing ACKs may be superseded. Every duplicate ACK is preserved. "
                                  "Each selected ACK is a self-contained 66-byte L2 frame with 36-byte outer header. "
                                  "There is no compression context on the coalesced ACK path. Optional loss-protection "
                                  "copies carry the same 64-bit record identifier and are deduplicated before TCP.")
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing task plan or source hashes differ")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    remaining = [task for task in plan if not (runs / f"{task['run_id']:05d}.json").exists()]
    print(f"{len(plan) - len(remaining)}/{len(plan)} complete", flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for count, future in enumerate(as_completed([pool.submit(execute, task) for task in remaining]),
                                       len(plan) - len(remaining) + 1):
            row = future.result()
            path = runs / f"{row['run_id']:05d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(path)
            print(f"{count}/{len(plan)} complete | {row['strategy']} | {row['payload_bytes']} B | "
                  f"{row['application_goodput_mbps']:.3f} Mbps | RTT P99 "
                  f"{row['tcp_timestamp_rtt_p99_ms']:.1f} ms", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in plan]
    summary = summarize(rows)
    payload_sizes.write_csv(args.out / "replications.csv", rows)
    payload_sizes.write_csv(args.out / "summary.csv", summary)
    payload_sizes.report(args.out, summary)
    path = args.out / "payload-report.html"
    page = path.read_text().replace("<h1>Payload size, throughput and protocol RTT</h1>",
        "<h1>ACK supersession across delivered frames</h1><p>Each transmitted coalesced ACK contains a full "
        "66-byte Ethernet/IPv4/TCP timestamp frame and a 36-byte outer header. Only unsent advancing "
        "cumulative ACKs are superseded over the selected timer interval. Duplicate ACKs flush any "
        "pending advance and transmit individually. No sender-side loss oracle or shared compression "
        "context is used. Optional redundant copies carry the same eight-byte tunnel record identifier "
        "and are deduplicated before TCP, preserving distinct duplicate-ACK events. ACK loss remains "
        "visible to the TCP cumulative ACK and retransmission logic.</p>"
        "<p>Profiles explicitly enabling acknowledged_segment_slow_start use the number of newly "
        "acknowledged full segments to grow the slow-start window, while retaining the inherited "
        "cwnd-limited check. This option follows the slow-start counting rule in "
        "<a href=\"https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_cong.c#L418-L434\">"
        "Linux v6.12 tcp_slow_start</a>. It changes one step in the CUBIC model. It does not execute "
        "the kernel TCP implementation. Compare coalescing against a baseline with the same option. "
        "<a href=\"https://www.rfc-editor.org/rfc/rfc3449.html#section-5.2.1\">RFC 3449</a> "
        "discusses ACK filtering, infrequent ACKs, and sender-side adaptations.</p>")
    path.write_text(page)
    changed = [str(path.relative_to(source_root)) for path in paths
               if sha256(path.read_bytes()).hexdigest() != hashes[str(path.relative_to(source_root))]]
    (args.out / "source-verification.json").write_text(json.dumps({"changed_during_run": changed}, indent=2) + "\n")
    print(f"ACK study complete at {args.out}; changed source files {changed}", flush=True)


if __name__ == "__main__":
    main()
