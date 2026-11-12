"""Matched ordered/unordered full-L2 record feasibility experiment."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from time import perf_counter

import numpy as np

from l2tunnel_sim.compact_unordered import IndependentRecordTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.multiflow import MultiFlow
from payload_sizes import TCPRTTObserver, rtt_metrics, write_csv
from latency_window import summarize


class ObservedIndependentTCP(TCPRTTObserver, IndependentRecordTCP):
    def __init__(self, *args, **kwargs):
        self.frame_observations = []
        self.raw_record_observations = []
        self.raw_record_indices = set()
        self.all_segment_ack_observations = []
        super().__init__(*args, **kwargs)

    def on_data(self, index, timestamp):
        if index not in self.raw_record_indices:
            self.raw_record_indices.add(index)
            self.raw_record_observations.append((self.now, (self.now - self.sent_times[index]) * 1000))
        before = len(self.forward.delays)
        super().on_data(index, timestamp)
        self.frame_observations.extend((self.now, value) for value in self.forward.delays[before:])

    def on_ack(self, *args, **kwargs):
        before = self.tcp_acked
        super().on_ack(*args, **kwargs)
        self.all_segment_ack_observations.extend(
            (self.now, (self.now - self.sent_times[index]) * 1000)
            for index in range(before, self.tcp_acked))


def execute(task):
    started = perf_counter()
    payload, rate = task["payload_bytes"], task["payload_rate_mbps"]
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"],
                      frame_bytes=payload + 66, payload_bytes=payload,
                      window_bytes=round(task["window_mib"] * 1048576),
                      frame_interval_ms=payload * 8 / (rate * 1000) if rate else 0)
    sim = MultiFlow(Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"]), traffic,
                    (PathConfig(task["forward_mbps"], task["reverse_mbps"]),),
                    Strategy(task["name"], mode="tcp", tcp_rto_min_ms=1000), task["seed"],
                    task["flow_count"], simulation_factory=partial(
                        ObservedIndependentTCP, ordered_delivery=task["ordered_delivery"]))
    snapshots = {}

    def sample(when):
        snapshots[when] = (sum(flow.tcp_received for flow in sim.flows),
                           sum(sum(flow.datagrams[False].values()) for flow in sim.flows))

    for time in (task["warmup_s"], task["duration_s"]):
        sim.flows[0].at(time, sample, time)
    sim.run()
    row = dict(task, **sim.measurements(), **rtt_metrics(sim, task["warmup_s"]))
    row.update(strategy=task["name"], rto_min_ms=1000, mtu=1500, controller="cubic",
               recovery="arq", reliable_acks=False, header_profile="full_l2",
               transport="independent_full_l2_records", measurement_payload_kind="modeled TCP application data",
               profile=json.dumps({"ordered_delivery": task["ordered_delivery"], "header_profile": "full_l2",
                                   "packet_fragment_descriptor_bytes": 8}, sort_keys=True))
    for name in ("tcp_timeouts", "tcp_retransmissions", "tcp_fast_retransmits"):
        row[name] = sum(getattr(flow, name) for flow in sim.flows)
    for prefix, start, end in (("", 0, task["duration_s"]),
                               ("steady_", task["warmup_s"], task["duration_s"]),
                               ("with_drain_", 0, task["duration_s"] + task["drain_s"])):
        for metric, attribute in (("frame", "frame_observations"),
                                   ("raw_l2_record", "raw_record_observations"),
                                   ("tcp_all_segment_ack_rtt", "all_segment_ack_observations")):
            values = [value for flow in sim.flows for when, value in getattr(flow, attribute)
                      if start <= when <= end]
            for percentile in (50, 95, 99):
                row[f"{prefix}{metric}_p{percentile}_ms"] = float(np.percentile(values, percentile)) if values else None
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    row["outer_all_confirmed"] = all(transport.base == len(transport.sources) and not transport.buffer_bytes
                                      and not transport.pending for flow in sim.flows
                                      for transport in (flow.compact_forward, flow.compact_reverse))
    start, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    row["steady_delivered_frames"] = end[0] - start[0]
    row["steady_forward_datagrams"] = end[1] - start[1]
    row["application_goodput_mbps"] = row["tcp_goodput_mbps"]
    row["steady_application_goodput_mbps"] = (end[0] - start[0]) * payload * 8 / (
        (task["duration_s"] - task["warmup_s"]) * 1e6)
    row["steady_tcp_mbps"] = row["steady_application_goodput_mbps"]
    row["extra_packets_per_delivered_tcp_segment_pct"] = 100 * (
        row["forward_datagrams"] / row["tcp_delivered_frames"] - 1)
    confirmed = row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
    row["full_target_met"] = (confirmed and row["tcp_goodput_mbps"] >= .8 * task["forward_mbps"]
                               and row["tcp_all_segment_ack_rtt_p99_ms"] <= 1.5 * task["rtt_ms"])
    row["steady_target_met"] = (confirmed and row["steady_tcp_mbps"] >= .8 * task["forward_mbps"]
                                 and row["steady_tcp_all_segment_ack_rtt_p99_ms"] <= 1.5 * task["rtt_ms"])
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--replications", type=int, default=1)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--drain", type=float, default=5)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--flows", type=int, nargs="+", default=[16, 64])
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    source_root = Path(__file__).resolve().parents[1]
    paths = [Path(__file__).resolve(), source_root / "studies/payload_sizes.py",
             source_root / "studies/latency_window.py",
             *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest() for path in paths}
    source_hash = sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for flows in args.flows:
        for ordered in (True, False):
            for replication, seed in enumerate(seeds, 1):
                tasks.append(dict(run_id=len(tasks) + 1, name=f"Full L2 {'ordered' if ordered else 'unordered'} {flows} flows",
                                  ordered_delivery=ordered, flow_count=flows, window_mib=4,
                                  payload_bytes=1448, payload_rate_mbps=81.5, forward_mbps=100,
                                  reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model="iid",
                                  duration_s=args.duration, warmup_s=args.warmup, drain_s=args.drain,
                                  seed=seed, replication=replication, source_manifest_hash=source_hash))
    manifest = dict(tasks=tasks, sources=hashes,
                    packet_format="36-byte source header plus 8-byte first-record descriptor and 2-byte valid length. "
                                  "Every full L2 frame carries its existing 3-byte type/length prefix. Both delivery modes use identical bytes.",
                    semantics="Unordered L2 record callbacks still pass through the native cumulative TCP receive sequence. "
                              "All-segment ACK completion metrics include every newly cumulatively acknowledged segment.")
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing task plan or sources differ")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    remaining = [task for task in tasks if not (runs / f"{task['run_id']:05d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in remaining]):
            row = future.result()
            path = runs / f"{row['run_id']:05d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(path)
            print(f"{row['name']} | {row['tcp_goodput_mbps']:.3f} Mbps | TCP RTT P99 "
                  f"{row['tcp_timestamp_rtt_p99_ms']:.1f} ms | frame P99 {row['frame_p99_ms']:.1f} ms | "
                  f"all-segment ACK P99 {row['tcp_all_segment_ack_rtt_p99_ms']:.1f} ms", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summarize(rows))
    changed = [str(path.relative_to(source_root)) for path in paths
               if sha256(path.read_bytes()).hexdigest() != hashes[str(path.relative_to(source_root))]]
    (args.out / "source-verification.json").write_text(json.dumps({"changed_during_run": changed}, indent=2) + "\n")
    print(f"Independent-record study complete, changed source files {changed}", flush=True)


if __name__ == "__main__":
    main()
