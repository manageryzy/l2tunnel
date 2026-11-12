"""Compare guarded and first-flight recovery of compact cross-frame TCP records."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
import platform
from random import Random
from time import perf_counter

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.compact_lowlatency import BoundedGapARQTransport, FirstFlightARQTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.multiflow import MultiFlow

from payload_sizes import ObservedCompactTCP, rtt_metrics, summarize, write_csv


TRANSPORTS = {"baseline": CompactARQTransport, "first-flight": FirstFlightARQTransport,
              "gap": BoundedGapARQTransport}


def execute(task):
    started = perf_counter()
    profile = task["profile"]
    payload = task["payload_bytes"]
    rate = profile["payload_rate_mbps"]
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"], frame_bytes=payload + 66,
                      payload_bytes=payload, window_bytes=profile["window_bytes"],
                      frame_interval_ms=payload * 8 / (rate * 1000) if rate else 0)
    config = CompactConfig(**profile["compact"])
    transport = TRANSPORTS[profile["variant"]]
    if profile["variant"] == "gap":
        transport = partial(transport, gap_feedback_min_interval_ms=profile["gap_feedback_min_interval_ms"])
    factory = partial(ObservedCompactTCP, compact_config=config, reliable_acks=False, transport_type=transport)
    sim = MultiFlow(Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"]), traffic,
                    (PathConfig(task["forward_mbps"], task["reverse_mbps"]),),
                    Strategy(profile["name"], mode="tcp", tcp_cc="cubic", tcp_rto_min_ms=1000),
                    task["seed"], 16, simulation_factory=factory)
    snapshots = {}

    def sample(when):
        snapshots[when] = (sum(flow.tcp_received for flow in sim.flows),
                           sum(sum(flow.datagrams[False].values()) for flow in sim.flows))

    sim.flows[0].at(task["warmup_s"], sample, task["warmup_s"])
    sim.flows[0].at(task["duration_s"], sample, task["duration_s"])
    sim.run()
    row = {key: value for key, value in task.items() if key != "profile"}
    row.update(profile=json.dumps(profile, sort_keys=True), strategy=profile["name"],
               **sim.measurements(), **rtt_metrics(sim, task["warmup_s"]))
    row["transport"] = "compact_inner_tcp_multiflow"
    row["flow_count"] = 16
    row["requested_window_bytes"] = profile["window_bytes"]
    row["payload_rate_mbps"] = rate
    row["variant"] = profile["variant"]
    row["reliable_acks"] = False
    row["compact"] = json.dumps(profile["compact"], sort_keys=True)
    for field in ("tcp_retransmissions", "tcp_timeouts", "tcp_fast_retransmits"):
        row[field] = sum(getattr(flow, field) for flow in sim.flows)
    for field in ("first_flight_fast_retransmissions", "early_feedback_packets", "fast_retransmissions",
                  "timeout_retransmissions"):
        row["outer_" + field] = sum(getattr(flow.compact_forward, field, 0) for flow in sim.flows)
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    row["outer_all_confirmed"] = all(
        transport.base == len(transport.sources) and not transport.pending and transport.buffer_bytes == 0
        for flow in sim.flows for transport in (flow.compact_forward, flow.compact_reverse))
    row["flow_confirmation"] = json.dumps([
        dict(flow_id=index, offered=len(flow.sent_times), received=flow.tcp_received, acknowledged=flow.tcp_acked,
             source_count=len(flow.compact_forward.sources), source_confirmed=flow.compact_forward.base,
             source_unconfirmed=len(flow.compact_forward.pending), buffer_bytes=flow.compact_forward.buffer_bytes)
        for index, flow in enumerate(sim.flows, 1)])
    row["application_goodput_mbps"] = row["tcp_goodput_mbps"]
    row["application_capacity_pct"] = 100 * row["tcp_goodput_mbps"] / task["forward_mbps"]
    row["extra_packets_per_delivered_record_pct"] = 100 * (row["forward_datagrams"] / row["tcp_delivered_frames"] - 1)
    start, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    row["steady_delivered_frames"] = end[0] - start[0]
    row["steady_forward_datagrams"] = end[1] - start[1]
    row["steady_application_goodput_mbps"] = row["steady_delivered_frames"] * payload * 8 / (
        (task["duration_s"] - task["warmup_s"]) * 1e6)
    row["steady_application_capacity_pct"] = 100 * row["steady_application_goodput_mbps"] / task["forward_mbps"]
    row["steady_extra_packets_per_delivered_record_pct"] = 100 * (
        row["steady_forward_datagrams"] / row["steady_delivered_frames"] - 1)
    complete = row["tcp_delivery_fraction"] == 1 and row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
    row["full_target_met"] = bool(complete and row["application_capacity_pct"] >= 80
                                 and row["extra_packets_per_delivered_record_pct"] <= 20)
    row["steady_target_met"] = bool(complete and row["steady_application_capacity_pct"] >= 80
                                   and row["steady_extra_packets_per_delivered_record_pct"] <= 20)
    row["measurement_payload_kind"] = "modeled TCP application data"
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_l2_bytes"] == row["released_frames"] * (payload + 66)
    for direction in ("forward", "reverse"):
        assert row[direction + "_wire_bytes_during_measurement"] <= task[direction + "_mbps"] * 125000 * task["duration_s"]
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--drain", type=float, default=5)
    parser.add_argument("--replications", type=int, default=3)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--variants", nargs="+", choices=TRANSPORTS, default=list(TRANSPORTS))
    parser.add_argument("--window-mib", nargs="+", type=int, default=[1, 4])
    parser.add_argument("--pacing", nargs="+", type=float, default=[0, 81.5])
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than duration")
    config = asdict(CompactConfig(repair_ratio=0, header_profile="tcp_delta"))
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for window in args.window_mib:
        for rate in args.pacing:
            for variant in args.variants:
                profile = dict(name=f"Compact ARQ {variant} {window}MiB {rate:g}Mbps pacing",
                               variant=variant, compact=config, flow_count=16, window_bytes=window * 1048576,
                               payload_rate_mbps=rate, rto_min_ms=1000, controller="cubic", reliable_acks=False,
                               gap_feedback_min_interval_ms=5)
                for replication, seed in enumerate(seeds, 1):
                    tasks.append(dict(run_id=len(tasks) + 1, profile=profile, forward_mbps=100, reverse_mbps=10,
                                      rtt_ms=70, loss_rate=.15, loss_model="iid", payload_bytes=1448,
                                      duration_s=args.duration, warmup_s=args.warmup, drain_s=args.drain,
                                      replication=replication, seed=seed))
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(__file__).with_name("payload_sizes.py").resolve(),
             *(root / "src/l2tunnel_sim" / name for name in (
                 "compact_lowlatency.py", "compact_arq.py", "compact.py", "compact_tcp.py", "tcp.py", "model.py",
                 "multiflow.py", "config.py", "experiment.py", "quic.py", "coding.py", "stats.py"))]
    manifest = dict(tasks=tasks, runtime_python=platform.python_version(),
                    sources={str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files},
                    assumptions=["100/10 Mbps IP service rate with one shared physical queue per direction",
                                 "16 independent CUBIC/ARQ flows share the aggregate window and source pacing",
                                 "Native reverse TCP ACKs use the real lossy reverse link",
                                 "Only received bitmap and transmission serial feedback triggers early retry",
                                 "First-flight retry guard bypass retains the original guard for repeat attempts",
                                 "Gap feedback remains charged and limited to one per prefix and at least 5ms apart",
                                 "TCP RTT is the continuous-time modeled estimator sample; sub-ms TSval quantization omitted",
                                 "Authentication budget is zero and CPU cost is omitted"])
    args.out.mkdir(parents=True, exist_ok=True)
    metadata = args.out / "experiment.json"
    if metadata.exists() and json.loads(metadata.read_text()) != manifest:
        raise ValueError("existing experiment parameters or source versions differ")
    metadata.write_text(json.dumps(manifest, indent=2) + "\n")
    snapshots = args.out / "sources"
    for path in files:
        target = snapshots / path.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    remaining = [task for task in tasks if not (runs / f"{task['run_id']:05d}.json").exists()]
    print(f"{len(tasks)-len(remaining)}/{len(tasks)} runs complete", flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for count, future in enumerate(as_completed([pool.submit(execute, task) for task in remaining]),
                                       len(tasks) - len(remaining) + 1):
            row = future.result()
            target = runs / f"{row['run_id']:05d}.json"
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(target)
            print(f"{count}/{len(tasks)} runs complete", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summarize(rows))
    print(f"Cross-frame latency study complete at {args.out}", flush=True)


if __name__ == "__main__":
    main()
