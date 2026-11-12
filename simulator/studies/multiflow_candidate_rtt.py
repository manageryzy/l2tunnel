"""Observe protocol RTT for the already-qualified sixteen-flow compact ARQ candidate."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
import json
from pathlib import Path
from random import Random

from payload_sizes import execute, summarize, write_csv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    profile = dict(name="Compact ARQ 16 flows RTO1s", kind="compact", controller="cubic",
                   rto_min_ms=1000, flow_count=16, window_bytes=4 * 1048576,
                   compact=dict(header_profile="tcp_delta", repair_ratio=0),
                   recovery="arq", reliable_acks=False)
    rng = Random(20261110)
    tasks = [dict(run_id=replication, profile=profile, forward_mbps=100, reverse_mbps=10,
                  rtt_ms=70, loss_rate=.15, loss_model="iid", payload_bytes=1448,
                  duration_s=60, warmup_s=5, drain_s=20, replication=replication, seed=rng.getrandbits(64))
             for replication in range(1, 6)]
    paths = [Path(__file__), Path(__file__).with_name("payload_sizes.py"),
             *sorted((Path(__file__).parents[1] / "src/l2tunnel_sim").glob("*.py"))]
    manifest = {"tasks": tasks, "reference": str(args.reference),
                "sources": {str(path): sha256(path.read_bytes()).hexdigest() for path in paths},
                "observer": "TCP timestamp update_rtt samples, smoothed RTT, and cumulative ACK completion samples"}
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
            row = future.result()
            path = runs / f'{row["run_id"]:04}.json'
            temp = path.with_suffix(".tmp")
            temp.write_text(json.dumps(row, indent=2) + "\n")
            temp.replace(path)
            print(f'Completed RTT observer replication {row["replication"]}, '
                  f'{row["application_goodput_mbps"]:.4f} Mbps, '
                  f'RTT P99 {row["tcp_timestamp_rtt_p99_ms"]:.2f} ms', flush=True)
    rows = [json.loads(path.read_text()) for path in sorted(runs.glob("*.json"))]
    references = {row["seed"]: row for path in (args.reference / "runs").glob("*.json")
                  for row in [json.loads(path.read_text())]}
    keys = ("tcp_goodput_mbps", "tcp_delivered_frames", "tcp_acked_frames", "offered_frames",
            "forward_datagrams", "forward_wire_bytes", "tcp_timeouts", "tcp_retransmissions",
            "frame_p99_ms", "tcp_all_acknowledged", "outer_all_confirmed")
    comparisons = []
    for row in rows:
        reference = references[row["seed"]]
        mismatches = [key for key in keys if row[key] != reference[key]]
        comparisons.append(dict(seed=row["seed"], identical=not mismatches, mismatched_metrics=mismatches))
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summarize(rows))
    (args.out / "observer_equivalence.json").write_text(json.dumps(comparisons, indent=2) + "\n")
    if any(not comparison["identical"] for comparison in comparisons):
        raise AssertionError("observer run differs from the qualified candidate")
    print(json.dumps({"completed_runs": len(rows), "exact_reference_matches": len(comparisons),
                      "out": str(args.out)}), flush=True)


if __name__ == "__main__":
    main()
