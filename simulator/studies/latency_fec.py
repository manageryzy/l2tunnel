"""Measure small cross-frame GF256 blocks on the established inner-TCP path."""

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from time import perf_counter

import numpy as np

from l2tunnel_sim import __version__
from l2tunnel_sim.stats import mean_ci
from payload_sizes import make_simulation, rtt_metrics, summarize, write_csv


def block_metrics(flows):
    """Read achieved generation sizes and repair counters from each transport."""
    row = {}
    for direction in ("forward", "reverse"):
        transports = [getattr(flow, f"compact_{direction}") for flow in flows]
        sizes = [size for transport in transports for size in transport.code_blocks]
        sources = sum(len(transport.sources) for transport in transports)
        prefix = f"{direction}_block_"
        row[prefix + "histogram"] = json.dumps(dict(sorted(Counter(sizes).items())), sort_keys=True)
        row[prefix + "count"] = len(sizes)
        row[prefix + "mean_sources"] = float(np.mean(sizes)) if sizes else None
        row[prefix + "p50_sources"] = float(np.percentile(sizes, 50)) if sizes else None
        row[prefix + "p95_sources"] = float(np.percentile(sizes, 95)) if sizes else None
        row[prefix + "max_sources"] = max(sizes) if sizes else None
        row[prefix + "closed_sources"] = sum(sizes)
        row[prefix + "sources"] = sources
        for phase in ("initial", "additional"):
            repairs = sum(getattr(transport, phase + "_repairs") for transport in transports)
            row[f"{direction}_{phase}_repair_count"] = repairs
            row[f"{direction}_{phase}_repairs_per_source_pct"] = 100 * repairs / sources if sources else None
    return row


def execute(task):
    """Reuse the payload study's construction, RTT observers and measurements."""
    started = perf_counter()
    sim = make_simulation(task)
    flows = sim.flows
    snapshots = {}

    def sample(when):
        snapshots[when] = (sum(flow.tcp_received for flow in flows),
                           sum(sum(flow.datagrams[False].values()) for flow in flows))

    flows[0].at(task["warmup_s"], sample, task["warmup_s"])
    flows[0].at(task["duration_s"], sample, task["duration_s"])
    sim.run()
    row = {key: value for key, value in task.items() if key != "profile"}
    row.update(profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
               **sim.measurements(), **rtt_metrics(sim, task["warmup_s"]), **block_metrics(flows))
    row["total_window_bytes"] = sum(flow.traffic.window_bytes for flow in flows)
    for metric in ("tcp_timeouts", "tcp_retransmissions", "tcp_fast_retransmits"):
        row[metric] = sum(getattr(flow, metric) for flow in flows)
    start, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    steady_frames = end[0] - start[0]
    row["application_goodput_mbps"] = row["tcp_goodput_mbps"]
    row["application_capacity_pct"] = 100 * row["application_goodput_mbps"] / task["forward_mbps"]
    row["steady_application_goodput_mbps"] = steady_frames * task["payload_bytes"] * 8 / (
        (task["duration_s"] - task["warmup_s"]) * 1e6)
    row["steady_application_capacity_pct"] = 100 * row["steady_application_goodput_mbps"] / task["forward_mbps"]
    row["steady_delivered_frames"] = steady_frames
    row["steady_forward_datagrams"] = end[1] - start[1]
    row["extra_packets_per_delivered_record_pct"] = 100 * (
        row["forward_datagrams"] / row["tcp_delivered_frames"] - 1)
    row["steady_extra_packets_per_delivered_record_pct"] = 100 * (
        row["steady_forward_datagrams"] / steady_frames - 1) if steady_frames else None
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in flows)
    row["outer_all_confirmed"] = all(transport.base == len(transport.sources) and transport.buffer_bytes == 0
                                      and not transport.pending for flow in flows
                                      for transport in (flow.compact_forward, flow.compact_reverse))
    row["flow_confirmation"] = json.dumps([
        dict(flow_id=index, offered=len(flow.sent_times), received=flow.tcp_received, acknowledged=flow.tcp_acked,
             final_srtt_ms=flow.srtt * 1000 if flow.srtt is not None else None)
        for index, flow in enumerate(flows, 1)])
    row["transport"] = "compact_inner_tcp"
    row["measurement_payload_kind"] = "modeled TCP application data"
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_l2_bytes"] == row["released_frames"] * (task["payload_bytes"] + 66)
    assert row["forward_wire_bytes_during_measurement"] <= task["forward_mbps"] * 125000 * task["duration_s"]
    return row


def summarize_blocks(rows):
    summaries = summarize(rows)
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["strategy"]].append(row)
    for summary in summaries:
        records = grouped[summary["strategy"]]
        profile = json.loads(records[0]["profile"])
        summary["configured_generation_sources"] = profile["compact"]["generation_sources"]
        summary["configured_idle_flush_ms"] = profile["compact"]["idle_flush_ms"]
        summary["configured_maximum_block_ms"] = profile["compact"]["maximum_block_ms"]
        summary["configured_initial_repair_ratio"] = profile["compact"]["repair_ratio"]
        for direction in ("forward", "reverse"):
            histogram = Counter()
            for record in records:
                histogram.update({int(size): count for size, count in json.loads(
                    record[f"{direction}_block_histogram"]).items()})
            summary[f"{direction}_achieved_block_histogram"] = json.dumps(dict(sorted(histogram.items())), sort_keys=True)
        for metric in records[0]:
            if "_block_" not in metric and "_repair_count" not in metric and "_repairs_per_source_pct" not in metric:
                continue
            values = [record[metric] for record in records if isinstance(record[metric], (int, float))]
            if values:
                estimate = mean_ci(values)
                for suffix in ("mean", "ci_low", "ci_high"):
                    summary[f"{metric}_{suffix}"] = estimate[suffix]
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--drain", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--replications", type=int, default=3)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--idle-flush-ms", type=float, default=4)
    parser.add_argument("--maximum-block-ms", type=float, default=50)
    parser.add_argument("--generations", type=int, nargs="+", default=(5, 10))
    parser.add_argument("--repair-ratios", type=float, nargs="+", default=(.2,))
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than the traffic interval")
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for sources, ratio in ((sources, ratio) for sources in args.generations for ratio in args.repair_ratios):
        rate = 94 / (1 + ratio)
        profile = dict(name=f"Cross-frame GF256 k{sources} repair{ratio:.0%} idle{args.idle_flush_ms:g}ms paced{rate:.2f}",
                       recovery="block", reliable_acks=False, flow_count=16, rto_min_ms=1000,
                       controller="cubic", window_bytes=4 * 1048576, payload_rate_mbps=rate,
                       compact=dict(header_profile="tcp_delta", repair_ratio=ratio,
                                    generation_sources=sources, repair_margin=0,
                                    idle_flush_ms=args.idle_flush_ms, maximum_block_ms=args.maximum_block_ms))
        for replication, seed in enumerate(seeds, 1):
            tasks.append(dict(run_id=len(tasks) + 1, profile=profile, forward_mbps=100,
                              reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model="iid",
                              payload_bytes=1448, duration_s=args.duration, drain_s=args.drain,
                              warmup_s=args.warmup, replication=replication, seed=seed))
    source_root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), source_root / "studies/payload_sizes.py",
             *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    manifest = dict(tasks=tasks, sources={str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest()
                                        for path in files},
                    assumptions=["IP capacity model, independent 15% erasures in both directions",
                                 "Actual GF256 rank recovery across bounded groups of packed L2 records",
                                 "16 established inner CUBIC connections, aggregate 4 MiB window",
                                 "Source pacing is 94/(1+initial repair ratio) Mbps using configured capacity",
                                 "All feedback, initial and deficit repairs are charged; authentication budget is zero"])
    model_hash = sha256(json.dumps(manifest["sources"], sort_keys=True).encode()).hexdigest()
    for task in tasks:
        task.update(model_version=__version__, model_source_hash=model_hash)
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / "experiment.json"
    if path.exists() and json.loads(path.read_text()) != manifest:
        raise ValueError("Output directory contains a different experiment")
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (runs / f"{task['run_id']:05d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            destination = runs / f"{row['run_id']:05d}.json"
            temporary = destination.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(destination)
            print(f"Completed {row['run_id']}/{len(tasks)} {row['strategy']} "
                  f"{row['application_goodput_mbps']:.3f} Mbps RTT P99 "
                  f"{row['tcp_timestamp_rtt_p99_ms']:.2f} ms achieved block mean "
                  f"{row['forward_block_mean_sources']:.3f}", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summarize_blocks(rows))


if __name__ == "__main__":
    main()
