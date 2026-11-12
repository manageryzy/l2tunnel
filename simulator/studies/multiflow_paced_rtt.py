"""Final five-seed long validation with aggregate 81.5 Mbps source pacing."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from random import Random

from l2tunnel_sim.compact import CompactConfig
from payload_sizes import execute, summarize, write_csv


def normalize(row):
    compact = asdict(CompactConfig(header_profile="tcp_delta", repair_ratio=0))
    row.update(name=row["strategy"], controller="cubic", reliable_acks=False, recovery="arq",
               payload_rate_mbps=81.5, rto_min_ms=1000, mtu=1500, compact=json.dumps(compact, sort_keys=True),
               steady_tcp_mbps=row["steady_application_goodput_mbps"],
               full_tcp_capacity_pct=row["application_capacity_pct"],
               steady_tcp_capacity_pct=row["steady_application_capacity_pct"],
               extra_packets_per_delivered_tcp_segment_pct=row["extra_packets_per_delivered_record_pct"],
               steady_extra_packets_per_delivered_tcp_segment_pct=row["steady_extra_packets_per_delivered_record_pct"],
               steady_frame_p99_ms=None)
    complete = row["tcp_delivery_fraction"] == 1 and row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
    row["full_target_met"] = bool(complete and row["application_goodput_mbps"] >= 80
                                   and row["extra_packets_per_delivered_record_pct"] <= 20)
    row["steady_target_met"] = bool(complete and row["steady_application_goodput_mbps"] >= 80
                                     and row["steady_extra_packets_per_delivered_record_pct"] <= 20)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    profile = dict(name="Compact ARQ 16 flows RTO1s 81.5 Mbps pacing / 60 s full run", kind="compact",
                   controller="cubic", rto_min_ms=1000, flow_count=16, window_bytes=4 * 1048576,
                   compact=dict(header_profile="tcp_delta", repair_ratio=0), recovery="arq",
                   reliable_acks=False, payload_rate_mbps=81.5)
    rng = Random(20261110)
    tasks = [dict(run_id=replication, profile=profile, forward_mbps=100, reverse_mbps=10,
                  rtt_ms=70, loss_rate=.15, loss_model="iid", payload_bytes=1448,
                  duration_s=60, warmup_s=5, drain_s=20, replication=replication, seed=rng.getrandbits(64))
             for replication in range(1, 6)]
    paths = [Path(__file__), Path(__file__).with_name("payload_sizes.py"),
             *sorted((Path(__file__).parents[1] / "src/l2tunnel_sim").glob("*.py"))]
    manifest = {"tasks": tasks, "sources": {str(path): sha256(path.read_bytes()).hexdigest() for path in paths},
                "observer": "TCP timestamp estimator, SRTT, cumulative ACK completion RTT, delivered-frame latency",
                "metric_aliases": "goal_report aliases added to the existing payload-study measurements"}
    args.out.mkdir(parents=True, exist_ok=True)
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing experiment differs, select a fresh output directory")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    pending = [task for task in tasks if not (runs / f'{task["run_id"]:04}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(execute, task) for task in pending]
        for future in as_completed(futures):
            row = normalize(future.result())
            path = runs / f'{row["run_id"]:04}.json'
            temp = path.with_suffix(".tmp")
            temp.write_text(json.dumps(row, indent=2) + "\n")
            temp.replace(path)
            print(f'Completed paced RTT replication {row["replication"]}, '
                  f'{row["application_goodput_mbps"]:.4f} Mbps, '
                  f'RTT P99 {row["tcp_timestamp_rtt_p99_ms"]:.2f} ms, '
                  f'extra {row["extra_packets_per_delivered_record_pct"]:.3f}%', flush=True)
    rows = [json.loads(path.read_text()) for path in sorted(runs.glob("*.json"))]
    write_csv(args.out / "replications.csv", rows)
    summaries = summarize(rows)
    summaries[0].update(full_target_passes=sum(row["full_target_met"] for row in rows),
                        steady_target_passes=sum(row["steady_target_met"] for row in rows))
    write_csv(args.out / "summary.csv", summaries)
    print(json.dumps({"completed_runs": len(rows), "full_target_passes": summaries[0]["full_target_passes"],
                      "out": str(args.out)}), flush=True)


if __name__ == "__main__":
    main()
