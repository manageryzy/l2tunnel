"""Bounded flow-count probe of the 80%-throughput and 1.5-RTT latency budget."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from random import Random

from l2tunnel_sim import __version__
from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.stats import mean_ci
import latency_ack
import payload_sizes


def profiles():
    selected = []
    for count in (16, 64, 128, 256):
        common = dict(compact=asdict(CompactConfig(header_profile="tcp_delta", repair_ratio=0)),
                      recovery="arq", flow_count=count, controller="cubic", rto_min_ms=1000,
                      window_bytes=4 * 1048576, payload_rate_mbps=81.5, reliable_acks=False,
                      acknowledged_segment_slow_start=True, ack_copy_spacing_ms=.1)
        if count <= 64:
            selected.append(dict(common, name=f"{count} flows native ACK counted slow start paced81.5",
                                 ack_coalesce_ms=0, ack_copies=1))
        selected.append(dict(common, name=f"{count} flows ACK0.25ms x2 counted slow start paced81.5",
                             ack_coalesce_ms=.25, ack_copies=2))
    return selected


def execute(task):
    row = latency_ack.execute(task)
    row["forward_measurement_mbps"] = row["forward_wire_bytes_during_measurement"] * 8 / (
        task["duration_s"] * 1e6)
    row["reverse_measurement_capacity_pct"] = 100 * row["reverse_measurement_mbps"] / task["reverse_mbps"]
    row["with_drain_frame_p99_ms"] = row["frame_p99_ms"]
    row["latency_budget_ms"] = 1.5 * task["rtt_ms"]
    confirmed = row["tcp_delivery_fraction"] == 1 and row["tcp_all_acknowledged"] and row[
        "outer_all_confirmed"] and row["ack_all_flushed"]
    row["fully_confirmed"] = confirmed
    row["packet_cost_target_met"] = row["extra_packets_per_delivered_record_pct"] <= 20
    row["full_rtt_budget_met"] = bool(confirmed and row["application_capacity_pct"] >= 80
                                    and row["tcp_timestamp_rtt_p99_ms"] is not None
                                    and row["tcp_timestamp_rtt_p99_ms"] <= row["latency_budget_ms"])
    row["steady_rtt_budget_met"] = bool(confirmed and row["steady_application_capacity_pct"] >= 80
                                      and row["steady_tcp_timestamp_rtt_p99_ms"] is not None
                                      and row["steady_tcp_timestamp_rtt_p99_ms"] <= row["latency_budget_ms"])
    return row


def summarize(rows):
    summaries = latency_ack.summarize(rows)
    for summary in summaries:
        records = [row for row in rows if row["strategy"] == summary["strategy"]]
        summary["latency_budget_ms"] = records[0]["latency_budget_ms"]
        summary["full_rtt_budget_passes"] = sum(row["full_rtt_budget_met"] for row in records)
        summary["steady_rtt_budget_passes"] = sum(row["steady_rtt_budget_met"] for row in records)
        summary["packet_cost_passes"] = sum(row["packet_cost_target_met"] for row in records)
        for metric in ("forward_measurement_mbps", "reverse_measurement_capacity_pct"):
            estimate = mean_ci([row[metric] for row in records])
            for suffix in ("mean", "ci_low", "ci_high"):
                summary[f"{metric}_{suffix}"] = estimate[suffix]
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--drain", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--replications", type=int, default=1)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than the traffic interval")
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for profile in profiles():
        for replication, seed in enumerate(seeds, 1):
            tasks.append(dict(run_id=len(tasks) + 1, profile=profile, forward_mbps=100, reverse_mbps=10,
                              rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500, payload_bytes=1448,
                              duration_s=args.duration, warmup_s=args.warmup, drain_s=args.drain,
                              replication=replication, seed=seed, model_version=__version__))
    source_root = Path(__file__).resolve().parents[1]
    sources = [Path(__file__).resolve(), Path(latency_ack.__file__).resolve(), Path(payload_sizes.__file__).resolve(),
               *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest() for path in sources}
    model_hash = sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    for task in tasks:
        task["model_source_hash"] = model_hash
    manifest = dict(tasks=tasks, sources=hashes, assumptions=[
        "100/10 Mbps IP capacity, 70 ms base RTT, 15% independent erasures in both directions, MTU 1500",
        "1448-byte TCP payload, aggregate 4 MiB window, known-capacity 81.5 Mbps source pacing",
        "16/64/128/256 independent TCP and ARQ states share directional queues and loss processes",
        "All profiles use acknowledged-segment slow-start growth and 1-second TCP minimum RTO",
        "Coalescing supersedes only unsent advancing ACKs over 0.25 ms and preserves duplicate ACKs",
        "Two ACK copies cost 102 IP bytes each, use 0.1 ms spacing, and are deduplicated before TCP",
        "Native ACK comparison uses the same acknowledged-segment slow-start option, with zero coalescing and one copy",
        "Full and steady throughput and timestamp RTT use their respective traffic intervals",
        "Frame P99 includes drain; TCP ACK completion RTT is exported for traffic, steady, and drain-inclusive intervals",
        "Target requires full confirmation, application throughput at least 80% capacity, timestamp RTT P99 at most 1.5 base RTT",
        "20% packet cost is reported separately from the RTT-budget target; all feedback and retries remain charged",
        "Header compression and cross-frame packing are enabled; authentication-byte budget and CPU cost are zero",
    ])
    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing tasks or recorded sources differ")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    for source in sources:
        target = args.out / "sources" / source.relative_to(source_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    remaining = [task for task in tasks if not (runs / f"{task['run_id']:05d}.json").exists()]
    print(f"{len(tasks) - len(remaining)}/{len(tasks)} complete", flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in remaining]):
            row = future.result()
            target = runs / f"{row['run_id']:05d}.json"
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(target)
            print(f"{row['strategy']} full={row['application_goodput_mbps']:.3f} "
                  f"steady={row['steady_application_goodput_mbps']:.3f} "
                  f"RTT99={row['tcp_timestamp_rtt_p99_ms']:.2f} "
                  f"reverse={row['reverse_measurement_mbps']:.3f} confirmed={row['fully_confirmed']}", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    payload_sizes.write_csv(args.out / "replications.csv", rows)
    payload_sizes.write_csv(args.out / "summary.csv", summarize(rows))
    changed = [str(path.relative_to(source_root)) for path in sources
               if sha256(path.read_bytes()).hexdigest() != hashes[str(path.relative_to(source_root))]]
    (args.out / "source-verification.json").write_text(json.dumps(dict(changed_during_run=changed), indent=2) + "\n")
    print(f"Completed {len(rows)} runs at {args.out}; changed source files {changed}", flush=True)


if __name__ == "__main__":
    main()
