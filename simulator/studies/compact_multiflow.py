"""Inner CUBIC flow counts over compact selective-repeat ARQ on one bottleneck."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import asdict
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
from random import Random

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.compact_tcp import CompactTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure
from l2tunnel_sim.multiflow import MultiFlow
from l2tunnel_sim.stats import mean_ci


def execute(task):
    rate = task["payload_rate_mbps"]
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"],
                      window_bytes=4 * 1048576,
                      frame_interval_ms=1448 * 8 / (rate * 1000) if rate else 0)
    strategy = Strategy("Compact ARQ inner CUBIC", mode="tcp", tcp_cc="cubic",
                        tcp_rto_min_ms=task["rto_min_ms"])
    factory = partial(CompactTCP, compact_config=CompactConfig(**task["compact"]),
                      reliable_acks=False, transport_type=CompactARQTransport)
    sim = MultiFlow(Scenario(70, .15), traffic, (PathConfig(100, 10),), strategy,
                    task["seed"], task["flow_count"], simulation_factory=factory)
    snapshots = {}

    def sample(when):
        snapshots[when] = {
            "frames": sum(flow.tcp_received for flow in sim.flows),
            "packets": sum(sum(flow.datagrams[False].values()) for flow in sim.flows),
            "wire": sum(sum(flow.wire[False].values()) for flow in sim.flows),
        }

    sim.flows[0].at(task["warmup_s"], sample, task["warmup_s"])
    sim.flows[0].at(task["duration_s"], sample, task["duration_s"])
    sim.run()
    row = {**task, **sim.measurements()}
    row["transport"] = "compact_inner_tcp_multiflow"
    row["compact"] = json.dumps(task["compact"], sort_keys=True)
    row["tcp_retransmissions"] = sum(flow.tcp_retransmissions for flow in sim.flows)
    row["tcp_timeouts"] = sum(flow.tcp_timeouts for flow in sim.flows)
    row["tcp_fast_retransmits"] = sum(flow.tcp_fast_retransmits for flow in sim.flows)
    row["tcp_final_cwnd_segments"] = sum(flow.cwnd for flow in sim.flows)
    per_flow = []
    for index, flow in enumerate(sim.flows, 1):
        outer = [flow.compact_forward, flow.compact_reverse]
        entry = dict(run_id=task["run_id"], flow_id=index, flow_count=task["flow_count"],
                     payload_rate_mbps=rate, rto_min_ms=task["rto_min_ms"],
                     replication=task["replication"], seed=sim.flow_seeds[index - 1],
                     window_bytes=flow.traffic.window_bytes, **measure(flow))
        entry["transport"] = "compact_inner_tcp"
        entry["tcp_all_acknowledged"] = flow.tcp_acked == len(flow.sent_times)
        entry["outer_all_confirmed"] = all(
            transport.base == len(transport.sources) and transport.buffer_bytes == 0
            and len(transport.pending) == 0 for transport in outer)
        entry["outer_forward_unconfirmed_sources"] = len(flow.compact_forward.pending)
        entry["outer_forward_buffer_bytes"] = flow.compact_forward.buffer_bytes
        entry["outer_forward_sources"] = len(flow.compact_forward.sources)
        entry["outer_forward_confirmed_prefix"] = flow.compact_forward.base
        entry["outer_forward_fast_retransmissions"] = flow.compact_forward.fast_retransmissions
        entry["outer_forward_timeout_retransmissions"] = flow.compact_forward.timeout_retransmissions
        entry["extra_packets_per_delivered_tcp_segment_pct"] = (
            100 * (entry["forward_datagrams"] / flow.tcp_received - 1)
            if flow.tcp_received else None)
        per_flow.append(entry)
    row["tcp_all_acknowledged"] = all(item["tcp_all_acknowledged"] for item in per_flow)
    row["outer_all_confirmed"] = all(item["outer_all_confirmed"] for item in per_flow)
    row["outer_forward_unconfirmed_sources"] = sum(item["outer_forward_unconfirmed_sources"] for item in per_flow)
    row["outer_forward_buffer_bytes"] = sum(item["outer_forward_buffer_bytes"] for item in per_flow)
    row["outer_forward_fast_retransmissions"] = sum(item["outer_forward_fast_retransmissions"] for item in per_flow)
    row["outer_forward_timeout_retransmissions"] = sum(item["outer_forward_timeout_retransmissions"] for item in per_flow)
    row["extra_packets_per_delivered_tcp_segment_pct"] = (
        100 * (row["forward_datagrams"] / row["tcp_delivered_frames"] - 1)
        if row["tcp_delivered_frames"] else None)
    start, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    interval = task["duration_s"] - task["warmup_s"]
    delivered = end["frames"] - start["frames"]
    packets = end["packets"] - start["packets"]
    row["steady_tcp_mbps"] = delivered * 1448 * 8 / interval / 1e6
    row["steady_delivered_frames"] = delivered
    row["steady_forward_packets"] = packets
    row["steady_extra_packets_per_delivered_tcp_segment_pct"] = (
        100 * (packets / delivered - 1) if delivered else None)
    complete = row["tcp_delivery_fraction"] == 1 and row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
    cost = row["extra_packets_per_delivered_tcp_segment_pct"]
    steady_cost = row["steady_extra_packets_per_delivered_tcp_segment_pct"]
    row["full_target_met"] = bool(complete and cost is not None and cost <= 20 and row["tcp_goodput_mbps"] >= 80)
    row["steady_target_met"] = bool(complete and steady_cost is not None and steady_cost <= 20 and row["steady_tcp_mbps"] >= 80)
    row["per_flow"] = per_flow
    assert row["forward_datagrams"] == sum(item["forward_datagrams"] for item in per_flow)
    assert row["tcp_delivered_frames"] == sum(item["tcp_delivered_frames"] for item in per_flow)
    assert row["forward_wire_bytes_during_measurement"] <= 100 * 125000 * task["duration_s"]
    return row


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    groups = {}
    for row in rows:
        key = row["flow_count"], row["rto_min_ms"], row["payload_rate_mbps"]
        groups.setdefault(key, []).append(row)
    metrics = ("tcp_goodput_mbps", "steady_tcp_mbps", "extra_packets_per_delivered_tcp_segment_pct",
               "steady_extra_packets_per_delivered_tcp_segment_pct", "frame_p99_ms",
               "tcp_retransmissions", "tcp_timeouts", "jain_goodput_fairness",
               "forward_source_datagrams", "forward_retry_datagrams", "forward_feedback_datagrams",
               "outer_forward_fast_retransmissions", "outer_forward_timeout_retransmissions")
    result = []
    for key, group in groups.items():
        row = dict(flow_count=key[0], rto_min_ms=key[1], payload_rate_mbps=key[2], replications=len(group),
                   min_completion=min(item["tcp_delivery_fraction"] for item in group),
                   confirmed_replications=sum(item["tcp_all_acknowledged"] and item["outer_all_confirmed"] for item in group),
                   full_target_passes=sum(item["full_target_met"] for item in group),
                   steady_target_passes=sum(item["steady_target_met"] for item in group))
        for metric in metrics:
            estimate = mean_ci([item[metric] for item in group if item[metric] is not None])
            for name in ("mean", "ci_low", "ci_high"):
                row[f"{metric}_{name}"] = estimate[name]
        result.append(row)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--replications", type=int, default=3)
    parser.add_argument("--duration", type=float, default=20)
    parser.add_argument("--drain", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=5)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--pacing", choices=("unpaced", "paced", "both"), default="both")
    parser.add_argument("--flows", type=int, nargs="+", default=(1, 4, 16))
    parser.add_argument("--rto", type=int, nargs="+", default=(200, 1000))
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than duration")
    args.out.mkdir(parents=True, exist_ok=True)
    run_dir = args.out / "runs"
    run_dir.mkdir(exist_ok=True)
    config = asdict(CompactConfig(repair_ratio=0, header_profile="tcp_delta"))
    rates = (None, 81.5) if args.pacing == "both" else ((None,) if args.pacing == "unpaced" else (81.5,))
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for rate in rates:
        for rto in args.rto:
            for flows in args.flows:
                for replication, seed in enumerate(seeds, 1):
                    tasks.append(dict(run_id=len(tasks) + 1, flow_count=flows, rto_min_ms=rto,
                                      payload_rate_mbps=rate, compact=config, replication=replication,
                                      seed=seed, duration_s=args.duration, drain_s=args.drain, warmup_s=args.warmup))
    paths = [Path(__file__), *(Path(__file__).parents[1] / "src/l2tunnel_sim" / name
                              for name in ("compact.py", "compact_arq.py", "compact_tcp.py", "tcp.py", "multiflow.py", "model.py"))]
    manifest = {"tasks": tasks, "sources": {str(path): sha256(path.read_bytes()).hexdigest() for path in paths},
                "assumptions": ["shared 100 Mbps forward and 10 Mbps reverse links",
                                "independent 15% erasures in both directions and 70 ms RTT",
                                "one shared loss process per physical direction",
                                "independent CUBIC, TCP recovery, ARQ recovery, and compression context per flow",
                                "fixed aggregate 4 MiB flow-control window, rounded down to whole segments",
                                "native cumulative TCP ACKs cross the lossy reverse link without outer reliable recovery",
                                "optional 81.5 Mbps aggregate source-payload pacing split equally between flows",
                                "extra packet denominator is unique delivered native TCP segments",
                                "authentication and coding CPU cost excluded"]}
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing experiment differs, select a fresh output directory")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    pending = [task for task in tasks if not (run_dir / f'{task["run_id"]:04}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(execute, task) for task in pending]
        for future in as_completed(futures):
            result = future.result()
            path = run_dir / f'{result["run_id"]:04}.json'
            temp = path.with_suffix(".tmp")
            temp.write_text(json.dumps(result, indent=2) + "\n")
            temp.replace(path)
            print(f'Completed {result["run_id"]}/{len(tasks)}, flows {result["flow_count"]}, '
                  f'RTO {result["rto_min_ms"]} ms, pacing {result["payload_rate_mbps"]}, '
                  f'full {result["tcp_goodput_mbps"]:.3f}, post-warmup {result["steady_tcp_mbps"]:.3f} Mbps, '
                  f'extra {result["extra_packets_per_delivered_tcp_segment_pct"]:.3f}%', flush=True)
    rows = [json.loads(path.read_text()) for path in sorted(run_dir.glob("*.json"))]
    write_csv(args.out / "per_flow.csv", [item for row in rows for item in row["per_flow"]])
    records = [{key: value for key, value in row.items() if key != "per_flow"} for row in rows]
    write_csv(args.out / "replications.csv", records)
    write_csv(args.out / "summary.csv", summarize(records))
    (args.out / "methodology.txt").write_text(
        "Compact ARQ multi-flow study\n\n" + "\n".join(manifest["assumptions"]) + "\n\n"
        "Full throughput counts TCP application payload delivered during the offered-load duration.\n"
        "Post-warmup throughput excludes the configured warmup interval and can include earlier queued data.\n"
        "Full packet overhead includes all forward source, repair, retransmission, and control datagrams through drain.\n"
        "Post-warmup packet overhead uses departures and deliveries within the same post-warmup interval.\n"
        "Completion requires delivery, acknowledgement of every offered TCP segment, and confirmation of all outer source symbols.\n"
        "Per-flow records report each independent TCP state and outer confirmation state.\n"
        "Confidence intervals use independent replications as their sampling unit.\n")
    print(f"Wrote {len(rows)} aggregate runs and {sum(len(row['per_flow']) for row in rows)} flow records", flush=True)


if __name__ == "__main__":
    main()
