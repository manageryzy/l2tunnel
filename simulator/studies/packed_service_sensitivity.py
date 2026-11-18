"""Re-run a saved PackedWire workload with serial receiver service."""

import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from copy import deepcopy
from hashlib import sha256
import json
from math import isfinite
from pathlib import Path
from statistics import median
import subprocess
from tempfile import TemporaryDirectory

from aggregate_ack_deadlines import execute


ROOT = Path(__file__).resolve().parents[2]
PLAN = Path("work/results-20261110/tcp-latency/tcp-syn-small-packet-qualified/task-plan.json")
KERNEL = Path("crates/l2tunnel-fec/src/rolling/gf_batch.rs")
BENCH = Path("simulator/studies/packed_gf_calibration.rs")


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--duration", type=float, default=3.0)
    parser.add_argument("--warmup", type=float, default=1.0)
    parser.add_argument("--drain", type=float, default=3.0)
    parser.add_argument("--replications", type=int, default=2)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--plan", type=Path, default=ROOT / PLAN, help="archived C48 task-plan JSON")
    parser.add_argument("--gf-manifest", type=Path,
                        help="reuse the archived GF kernel distribution instead of compiling a local native kernel")
    parser.add_argument("--full-pair", action="store_true",
                        help="use the untouched historical timing, original first seed and dense-cost control")
    args = parser.parse_args()
    tasks = [t for t in json.loads(args.plan.read_text())["tasks"]
             if t["profile"]["name"] == "Mux16 Select3 Pack0.5 ACK2 C5 Load76"]
    if not (0 <= args.warmup < args.duration and args.drain > 0 and
            1 <= args.replications <= len(tasks) and args.workers >= 1):
        parser.error("invalid time bounds, replication or worker count")
    args.out.mkdir(parents=True, exist_ok=False)
    if args.gf_manifest:
        prior = json.loads(args.gf_manifest.read_text())
        timings = prior["gf_calibration"]
        compiler = prior["rustc"]
        calibration_source = dict(manifest=str(args.gf_manifest), sha256=digest(args.gf_manifest))
        calibration_files = ()
    else:
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / "packed-gf-calibration"
            subprocess.run(["rustc", "--edition=2024", "-O", str(ROOT / BENCH), "-o", str(binary)], check=True)
            timings = json.loads(subprocess.check_output([str(binary)]))
        compiler = subprocess.check_output(["rustc", "-Vv"], text=True)
        calibration_source = dict(kernel=str(KERNEL), benchmark=str(BENCH))
        calibration_files = (ROOT / KERNEL, ROOT / BENCH)
    for key in ("zero_ns_per_byte", "dense_ns_per_byte"):
        if not timings[key] or not all(type(n) in (int, float) and isfinite(n) and n > 0 for n in timings[key]):
            raise ValueError("invalid GF calibration samples")
    dense = median(timings["dense_ns_per_byte"])
    cases = [(label, task, rate) for task in tasks[:args.replications] for label, rate in (
        ("zero-service", 0), ("host-zero-input", median(timings["zero_ns_per_byte"])),
        ("host-dense-input", dense), ("four-times-dense", 4 * dense))]
    workload = "C48 historical profile and seed; shortened observation and drain"
    if args.full_pair:
        cases = [("original", tasks[0], None), ("host-dense-input", tasks[0], dense)]
        workload = "C48 original task, all original time bounds, paired with dense receiver service"
    meta = dict(
        workload=workload,
        original_task_plan=str(args.plan), plan_sha256=digest(args.plan), gf_calibration=timings,
        rustc=compiler, calibration_source=calibration_source,
        cost_model="One serial FIFO per direction, 256 waiting datagrams plus one active. "
                   "Use measured median ns per logical GF payload byte, fixed packet and metadata costs zero. "
                   "All service distributions here are conditional lower-dimensional estimates; field kernel timing "
                   "omits codec, crypto, coefficient storage, scheduling and sender service. "
                   "The 4x dense case is a sensitivity assumption.",
        source_hashes={str(p.relative_to(ROOT)): digest(p) for p in (
            *sorted((ROOT / "simulator/src/l2tunnel_sim").glob("*.py")),
            ROOT / "simulator/studies/aggregate_ack_deadlines.py", Path(__file__).resolve(), *calibration_files)},
        jobs=[])
    jobs = []
    for label, historical, rate in cases:
        task = deepcopy(historical)
        if not args.full_pair:
            task.update(duration_s=args.duration, warmup_s=args.warmup, drain_s=args.drain)
        if rate is not None:
            task["packed_receiver_cost"] = dict(packet_us=0, metadata_ns=0, gf_ns_per_byte=rate, waiting_slots=256)
        name = f"rep-{task['replication']}-{label}.json"
        meta["jobs"].append(dict(result=name, original_task=historical, executed_task=task))
        jobs.append(task)
    write(args.out / "manifest.json", meta)
    summary = defaultdict(list)
    with ProcessPoolExecutor(args.workers) as pool:
        for row, plan, (label, _, _) in zip(pool.map(execute, jobs), meta["jobs"], cases):
            write(args.out / plan["result"], row)
            summary[label].append({key: row.get(key) for key in (
                "seed", "fully_confirmed", "steady_application_goodput_mbps",
                "with_drain_tcp_application_delivery_p99_ms", "packed_receiver_service")})
    write(args.out / "summary.json", summary)


if __name__ == "__main__":
    main()
