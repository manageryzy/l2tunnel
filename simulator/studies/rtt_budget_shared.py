"""Measure pooled forward coding against the throughput and 1.5-RTT target."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from time import perf_counter

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.shared_compact import SharedCompactMultiFlow
from latency_ack import ObservedCoalescedACKTCP
from payload_sizes import rtt_metrics, summarize, write_csv


def make_simulation(task):
    profile = task["profile"]
    config = CompactConfig(**profile["compact"])
    payload = task["payload_bytes"]
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"],
                      frame_bytes=payload + 66, payload_bytes=payload,
                      window_bytes=profile["window_bytes"],
                      frame_interval_ms=payload * 8 / (profile["payload_rate_mbps"] * 1000))
    factory = partial(ObservedCoalescedACKTCP, compact_config=config,
                      acknowledged_segment_slow_start=True,
                      ack_coalesce_ms=profile["ack_coalesce_ms"], ack_copies=profile["ack_copies"])
    return SharedCompactMultiFlow(
        Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"], mtu=task["mtu"]),
        traffic, (PathConfig(task["forward_mbps"], task["reverse_mbps"]),),
        Strategy(profile["name"], mode="tcp", tcp_rto_min_ms=profile["rto_min_ms"]),
        task["seed"], profile["flow_count"], compact_config=config, simulation_factory=factory)


def execute(task):
    started = perf_counter()
    sim = make_simulation(task)
    snapshots = {}

    def snapshot(when):
        snapshots[when] = (sum(flow.tcp_received for flow in sim.flows),
                           sum(sum(flow.datagrams[False].values()) for flow in sim.flows))

    sim.flows[0].at(task["warmup_s"], snapshot, task["warmup_s"])
    sim.flows[0].at(task["duration_s"], snapshot, task["duration_s"])
    sim.run()
    row = {key: value for key, value in task.items() if key != "profile"}
    row.update(profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
               **sim.measurements(), **rtt_metrics(sim, task["warmup_s"]))
    begin, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    delivered = end[0] - begin[0]
    row.update(application_goodput_mbps=row["tcp_goodput_mbps"],
               application_capacity_pct=100 * row["tcp_goodput_mbps"] / task["forward_mbps"],
               steady_application_goodput_mbps=delivered * task["payload_bytes"] * 8 / (
                   (task["duration_s"] - task["warmup_s"]) * 1e6),
               steady_forward_datagrams=end[1] - begin[1], steady_delivered_frames=delivered,
               transport="shared_compact_inner_tcp", measurement_payload_kind="modeled TCP application data")
    row["steady_application_capacity_pct"] = 100 * row["steady_application_goodput_mbps"] / task["forward_mbps"]
    row["extra_packets_per_delivered_record_pct"] = 100 * (
        row["forward_datagrams"] / row["tcp_delivered_frames"] - 1) if row["tcp_delivered_frames"] else None
    row["steady_extra_packets_per_delivered_record_pct"] = 100 * (
        row["steady_forward_datagrams"] / delivered - 1) if delivered else None
    for key in ("tcp_timeouts", "tcp_retransmissions", "tcp_fast_retransmits"):
        row[key] = sum(getattr(flow, key) for flow in sim.flows)
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    shared = sim.shared_forward
    row["outer_all_confirmed"] = shared.base == len(shared.sources) and not shared.buffer_bytes
    row["ack_all_flushed"] = all(flow.pending_ack is None for flow in sim.flows)
    row["fully_confirmed"] = bool(row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
                                   and row["ack_all_flushed"] and row["tcp_delivery_fraction"] == 1)
    row["shared_source_count"] = len(shared.sources)
    row["shared_record_bytes"] = shared.submitted_bytes
    row["shared_context_bytes"] = shared.profile_context_bytes
    row["shared_scheduled_repairs"] = shared.scheduled_repairs
    row["shared_tail_repairs"] = shared.tail_repairs
    row["with_drain_frame_p99_ms"] = row["frame_p99_ms"]
    for direction in ("forward", "reverse"):
        row[direction + "_measurement_mbps"] = row[direction + "_wire_bytes_during_measurement"] * 8 / (
            task["duration_s"] * 1e6)
    row["latency_budget_ms"] = task["rtt_ms"] * 1.5
    latency = [row["tcp_timestamp_rtt_p99_ms"], row["tcp_ack_rtt_p99_ms"]]
    row["rtt_budget_met"] = bool(row["fully_confirmed"] and row["application_capacity_pct"] >= 80
                                 and all(value is not None and value <= row["latency_budget_ms"] for value in latency))
    row["packet_cost_target_met"] = row["extra_packets_per_delivered_record_pct"] is not None and row[
        "extra_packets_per_delivered_record_pct"] <= 20
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_l2_bytes"] == row["released_frames"] * (task["payload_bytes"] + 66)
    for direction in ("forward", "reverse"):
        assert row[direction + "_measurement_mbps"] <= task[direction + "_mbps"] + 1e-8
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--duration", type=float, default=3)
    parser.add_argument("--drain", type=float, default=5)
    parser.add_argument("--warmup", type=float, default=.5)
    parser.add_argument("--replications", type=int, default=1)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than duration")
    profiles = json.loads(args.profiles.read_text()) if args.profiles else [
        dict(name=f"Shared RLNC{ratio:.0%} nativeACK 64flows paced81.5", shared_coding=True,
             compact=dict(header_profile="tcp_delta", repair_ratio=ratio, feedback_ms=1, feedback_packets=64),
             flow_count=64, controller="cubic", rto_min_ms=1000, window_bytes=4 * 1048576,
             payload_rate_mbps=81.5, ack_coalesce_ms=0, ack_copies=1,
             acknowledged_segment_slow_start=True, reliable_acks=False, recovery="rlnc")
        for ratio in (.19, .21, .23, .25)]
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for profile in profiles:
        for replication, seed in enumerate(seeds, 1):
            tasks.append(dict(run_id=len(tasks) + 1, profile=profile, seed=seed, replication=replication,
                              forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15,
                              loss_model="iid", mtu=1500, payload_bytes=1448, duration_s=args.duration,
                              drain_s=args.drain, warmup_s=args.warmup))
    source_root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), source_root / "studies/latency_ack.py",
             source_root / "studies/payload_sizes.py", *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(tasks=tasks, sources=hashes, assumptions=[
        "Every connection has independent CUBIC and per-channel reversible delta header state",
        "A charged six-byte channel/length envelope precedes every encoded frame",
        "One forward GF256 coding window spans all connections with global ordered record delivery",
        "The first flow owns shared outer datagrams; aggregate accounting includes each datagram once",
        "Pacing uses the known IP bottleneck capacity; authentication bytes and codec CPU cost are zero",
        "RTT target checks both timestamp estimator samples and original-segment ACK completion",
        "Frame P99 includes drain and is separately reported; every payload byte remains opaque",
    ])
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "experiment.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing tasks or source hashes differ")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in files:
        copy = args.out / "sources" / path.relative_to(source_root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (runs / f"{task['run_id']:05d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            path = runs / f"{row['run_id']:05d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(path)
            print(f"{row['strategy']} full={row['application_goodput_mbps']:.3f} "
                  f"steady={row['steady_application_goodput_mbps']:.3f} "
                  f"RTT99={row['tcp_timestamp_rtt_p99_ms']:.2f} ACK99={row['tcp_ack_rtt_p99_ms']:.2f} "
                  f"extra={row['extra_packets_per_delivered_record_pct']:.2f} confirmed={row['fully_confirmed']}", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summarize(rows))
    changed = [name for name, digest in hashes.items() if sha256((source_root / name).read_bytes()).hexdigest() != digest]
    (args.out / "source-verification.json").write_text(json.dumps(dict(changed_during_run=changed), indent=2) + "\n")


if __name__ == "__main__":
    main()
