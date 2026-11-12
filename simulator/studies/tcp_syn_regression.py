"""Run frozen, explicitly planned TCP SYN-ping regression cases.

Preparation only writes a task plan. Execution snapshots the complete simulator
package and the study entry-point dependencies, then imports those frozen files
in each worker. The first replication completes before later replications start.
"""

import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from copy import deepcopy
import csv
from datetime import datetime, timezone
from hashlib import sha256
import importlib
from importlib.metadata import version
import json
from multiprocessing import get_context
from pathlib import Path
import platform
from random import Random
import sys
from time import perf_counter
import traceback


PAYLOADS = (64, 256, 512, 1024, 1228, 1448)
STUDY_DEPENDENCIES = ("aggregate_ack_deadlines.py", "shared_record_deadlines.py",
                      "deadline_metrics.py", "latency_ack.py", "payload_sizes.py")
UNSUPPORTED_MESSAGES = ("fresh-connection probes require an unused L2 channel",)
SUMMARY_METRICS = ("application_goodput_mbps", "steady_application_goodput_mbps",
                   "tcp_syn_ping_background_goodput_mbps", "tcp_syn_ping_p99_ms",
                   "tcp_syn_ping_failure_pct", "tcp_syn_ping_deadline_miss_upper_pct",
                   "extra_packets_per_delivered_record_pct", "forward_measurement_mbps",
                   "reverse_measurement_mbps", "compute_seconds")
FROZEN_ROOT = None


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def json_scalar(value):
    if hasattr(value, "item"):
        return value.item()
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False, default=json_scalar) + "\n")
    temporary.replace(path)


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields or ["run_id"])
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def historical_inventory(root):
    studies = ("tcp-latency/aligned-record-payloads", "tcp-latency/aligned-record-elision-long",
               "tcp-latency/shared-record-refinement", "tcp-latency/compact-ack-delta-long",
               "tcp-latency/tcp-syn-ping-screen", "l2-pareto/payload-sizes")
    references = []
    for study in studies:
        for path in sorted((root / study / "runs").glob("*.json")):
            row = json.loads(path.read_text())
            payload = row.get("payload_bytes", row.get("payload_bytes_per_frame"))
            if payload not in PAYLOADS or row.get("rtt_ms") != 70:
                continue
            references.append(dict(source_file=str(path.resolve()), source_sha256=digest(path),
                                   source_run_id=row.get("run_id"), source_seed=row.get("seed"),
                                   source_replication=row.get("replication"), payload_bytes=payload,
                                   historical_strategy=row.get("strategy", row.get("name")),
                                   historical_profile=row.get("profile"), reference_role="historical profile and payload evidence"))
    return references


def payload_plan(root):
    main_path = root / "tcp-latency/tcp-syn-ping-screen/experiment.json"
    alternate_path = root / "tcp-latency/shared-record-refinement/experiment.json"
    main_manifest = json.loads(main_path.read_text())
    alternate_manifest = json.loads(alternate_path.read_text())
    main = next(task["profile"] for task in main_manifest["tasks"]
                if task["profile"]["tcp_syn_probe"]["reverse_copies"] == 3)
    alternate = next(task["profile"] for task in alternate_manifest["tasks"]
                     if task["profile"]["name"] == "Shared records independent W128 r20% ACKx2 paced80.4")
    profiles = []
    for original, path, family in ((main, main_path, "current_compact"),
                                    (alternate, alternate_path, "historical_shared")):
        profile = deepcopy(original)
        profile["tcp_syn_probe"] = deepcopy(main["tcp_syn_probe"])
        profile["ack_aggregation"] = profile.get("ack_aggregation", False)
        profile["wire_format"] = profile.get("wire_format", "shared_records")
        profile["name"] = original["name"] + " / six-payload SYN regression"
        profiles.append((family, profile, dict(manifest=str(path.resolve()), sha256=digest(path),
                                              original_profile=original)))
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(3)]
    tasks = []
    for replication, seed in enumerate(seeds, 1):
        for family, profile, reference in profiles:
            for payload in PAYLOADS:
                tasks.append(dict(run_id=len(tasks) + 1, profile=deepcopy(profile), seed=seed,
                                  replication=replication, forward_mbps=100, reverse_mbps=10,
                                  rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500,
                                  payload_bytes=payload, duration_s=30, warmup_s=5, drain_s=20,
                                  regression_family=family, historical_profile_reference=reference))
    return dict(record_kind="tcp_syn_regression_plan", tasks=tasks,
                historical_payload_references=historical_inventory(root),
                assumptions=[
                    "The two families preserve their recorded flow count, pacing, recovery and bulk ACK differences",
                    "Every payload uses the same three simulation seeds, with protocol-dependent packet schedules",
                    "A fresh SYN probe is admitted at 5 Hz only after the actual three-window stability gate",
                    "The minimum warmup is five seconds and admission ends five seconds before traffic stops",
                    "SYN-ACK copies use three charged reverse packets; bulk ACK policy remains profile-specific",
                    "Thirty-second runs without a steady-state gate retain unmeasured SYN latency",
                    "The first replication across all profile/payload combinations runs before later replications",
                    "Known unsupported configurations retain terminal metadata with undefined performance metrics",
                ])


def validate_tasks(plan):
    tasks = plan.get("tasks") if isinstance(plan, dict) else plan
    contract = plan.get("fixed_link_contract", {}) if isinstance(plan, dict) else {}
    channel_limit = plan.get("max_l2_channels") if isinstance(plan, dict) else None
    if channel_limit is not None and (isinstance(channel_limit, bool) or not isinstance(channel_limit, int)
                                      or not 1 <= channel_limit <= 256):
        raise ValueError("max_l2_channels must be an integer from one to 256")
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("task plan must contain a nonempty tasks list")
    required = ("run_id", "profile", "seed", "replication", "forward_mbps", "reverse_mbps", "rtt_ms",
                "loss_rate", "loss_model", "mtu", "payload_bytes", "duration_s", "warmup_s", "drain_s")
    identifiers = set()
    for task in tasks:
        missing = [key for key in required if key not in task]
        if missing:
            raise ValueError(f"task is missing fields {missing}")
        if any(task.get(key) != value for key, value in contract.items()):
            raise ValueError("task violates the fixed physical-link contract")
        identifier = task["run_id"]
        if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1 or identifier in identifiers:
            raise ValueError("run_id must be a unique positive integer")
        identifiers.add(identifier)
        if not 0 <= task["warmup_s"] < task["duration_s"] or task["drain_s"] < 0:
            raise ValueError("invalid traffic, warmup or drain interval")
        probe = task["profile"].get("tcp_syn_probe")
        if not isinstance(probe, dict):
            raise ValueError("each profile must explicitly configure tcp_syn_probe")
        if channel_limit is not None:
            channels = task["profile"].get("mux", {}).get("channels")
            if isinstance(channels, bool) or not isinstance(channels, int) or not 1 <= channels <= channel_limit:
                raise ValueError("task requires a unified mux within the total L2 channel limit")
    return tasks


def freeze_sources(output, plan):
    source_root = Path(__file__).resolve().parents[1]
    target = output / "experiment.json"
    tasks = validate_tasks(plan)
    if target.exists():
        manifest = json.loads(target.read_text())
        if manifest["tasks"] != tasks:
            raise ValueError("saved task plan differs; use a new output directory")
        for name, expected in manifest["sources"].items():
            if digest(output / "sources" / name) != expected:
                raise ValueError(f"frozen source receipt mismatch for {name}")
        runner_name = "studies/" + Path(__file__).name
        if digest(Path(__file__)) != manifest["sources"][runner_name]:
            raise ValueError("coordinator source changed; resume with the frozen runner")
        return manifest
    files = [Path(__file__).resolve(), *(source_root / "studies" / name for name in STUDY_DEPENDENCIES),
             *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {}
    for path in files:
        name = str(path.relative_to(source_root))
        hashes[name] = digest(path)
        snapshot = output / "sources" / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(path.read_bytes())
        if digest(snapshot) != hashes[name]:
            raise ValueError(f"source changed during freeze for {name}")
    metadata = plan if isinstance(plan, dict) else {}
    manifest = dict(metadata, record_kind="tcp_syn_regression_manifest", tasks=tasks, sources=hashes,
                    executor="aggregate_ack_deadlines.execute", python=platform.python_version(),
                    dependencies={name: version(name) for name in ("numpy", "scipy", "aioquic")},
                    frozen_at_utc=datetime.now(timezone.utc).isoformat(),
                    execution_source="frozen sources/src and sources/studies imported in each worker")
    save_json(target, manifest)
    return manifest


def use_frozen_sources(output):
    global FROZEN_ROOT
    frozen = Path(output) / "sources"
    FROZEN_ROOT = frozen.resolve()
    sys.path[:0] = [str(frozen / "src"), str(frozen / "studies")]


def execution_receipts():
    receipts = {}
    study_modules = {Path(name).stem for name in STUDY_DEPENDENCIES}
    for name, module in tuple(sys.modules.items()):
        if not (name == "l2tunnel_sim" or name.startswith("l2tunnel_sim.") or name in study_modules):
            continue
        path = Path(module.__file__).resolve()
        if FROZEN_ROOT is None or not path.is_relative_to(FROZEN_ROOT):
            raise ValueError(f"execution module was imported outside the frozen source tree: {name}")
        receipts[name] = dict(path=str(path), sha256=digest(path))
    return receipts


def execute_task(task):
    started = perf_counter()
    try:
        execute = importlib.import_module("aggregate_ack_deadlines").execute
        execution_receipts()
        row = execute(task)
        row["execution_status"] = "completed"
        row["observation_status"] = ("unsteady" if not row.get("tcp_syn_probe_steady_state_reached")
                                     else "complete" if row.get("tcp_syn_ping_joint_target_met") else "recorded")
    except Exception as error:
        unsupported = isinstance(error, ValueError) and str(error) in UNSUPPORTED_MESSAGES
        row = {key: value for key, value in task.items() if key != "profile"}
        row.update(profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
                   execution_status="unsupported" if unsupported else "error",
                   observation_status="unsupported" if unsupported else "execution error",
                   error_type=type(error).__name__, error=str(error), error_message=str(error), error_traceback=traceback.format_exc(),
                   application_goodput_mbps=None, tcp_goodput_mbps=None, fully_confirmed=False,
                   tcp_syn_ping_p99_ms=None, tcp_syn_ping_failure_pct=None, tcp_syn_ping_offered=None,
                   tcp_syn_ping_completed=None, tcp_syn_ping_timeouts=None, tcp_syn_ping_censored=None,
                   tcp_syn_probe_config=task["profile"]["tcp_syn_probe"], tcp_syn_ping_joint_target_met=False)
    row["executed_source_receipts"] = execution_receipts()
    row["compute_seconds"] = perf_counter() - started
    return row


def summarize(rows):
    from l2tunnel_sim.stats import mean_ci
    groups = defaultdict(list)
    for row in rows:
        key = (row["profile"], row["payload_bytes"], row["forward_mbps"], row["reverse_mbps"], row["rtt_ms"],
               row["loss_rate"], row["duration_s"], row["warmup_s"], row["drain_s"])
        groups[key].append(row)
    output = []
    for records in groups.values():
        summary = {key: records[0][key] for key in ("strategy", "profile", "payload_bytes", "forward_mbps",
                   "reverse_mbps", "rtt_ms", "loss_rate", "duration_s", "warmup_s", "drain_s")}
        summary.update(replications=len(records), completed_executions=sum(row["execution_status"] == "completed" for row in records),
                       unsupported_executions=sum(row["execution_status"] == "unsupported" for row in records),
                       error_executions=sum(row["execution_status"] == "error" for row in records),
                       steady_state_runs=sum(bool(row.get("tcp_syn_probe_steady_state_reached")) for row in records),
                       no_ping_runs=sum(not row.get("tcp_syn_ping_offered") for row in records),
                       fully_confirmed_runs=sum(bool(row.get("fully_confirmed")) for row in records),
                       joint_target_runs=sum(bool(row.get("tcp_syn_ping_joint_target_met")) for row in records))
        for metric in SUMMARY_METRICS:
            values = [row[metric] for row in records if row.get(metric) is not None]
            for key, value in mean_ci(values).items():
                if key != "method":
                    summary[metric + "_" + key] = value
        output.append(summary)
    return output


def run(output, manifest, workers, single_phase=False):
    tasks = manifest["tasks"]
    runs = output / "runs"
    runs.mkdir(exist_ok=True)
    rows = []
    for task in tasks:
        path = runs / f"{task['run_id']:05d}.json"
        if path.exists():
            row = json.loads(path.read_text())
            actual_task = {key: json.loads(row["profile"]) if key == "profile" else row.get(key) for key in task}
            if actual_task != task:
                raise ValueError(f"saved run differs from task {task['run_id']}")
            rows.append(row)
    saved = {row["run_id"] for row in rows}
    first_replication = min(task["replication"] for task in tasks)
    phases = ([task for task in tasks if task["replication"] == first_replication],
              [task for task in tasks if task["replication"] != first_replication])
    if single_phase:
        phases = (tasks,)
    attempts_path = output / "execution-attempts.json"
    attempts = json.loads(attempts_path.read_text()) if attempts_path.exists() else {"attempts": []}
    attempt = dict(started_at_utc=datetime.now(timezone.utc).isoformat(), workers=workers,
                   previously_saved=sorted(saved), completed_run_ids=[], state="running",
                   single_phase=single_phase)
    attempts["attempts"].append(attempt)
    save_json(attempts_path, attempts)
    try:
        for phase in phases:
            if any(row["execution_status"] == "error" for row in rows):
                break
            pending = [task for task in phase if task["run_id"] not in saved]
            with ProcessPoolExecutor(max_workers=workers, mp_context=get_context("spawn"),
                                     initializer=use_frozen_sources, initargs=(str(output),)) as pool:
                futures = {pool.submit(execute_task, task): task for task in pending}
                for future in as_completed(futures):
                    if future.cancelled():
                        continue
                    row = future.result()
                    row["source_manifest_sha256"] = digest(output / "experiment.json")
                    save_json(runs / f"{row['run_id']:05d}.json", row)
                    rows.append(row)
                    saved.add(row["run_id"])
                    attempt["completed_run_ids"].append(row["run_id"])
                    save_json(attempts_path, attempts)
                    save_json(output / "status.json", dict(state="running", saved=len(rows), planned=len(tasks),
                              last_run_id=row["run_id"], last_execution_status=row["execution_status"]))
                    print(json.dumps({key: row.get(key) for key in ("run_id", "strategy", "payload_bytes", "replication",
                          "execution_status", "observation_status", "compute_seconds", "application_goodput_mbps",
                          "tcp_syn_probe_steady_state_reached", "tcp_syn_ping_offered", "tcp_syn_ping_p99_ms",
                          "tcp_syn_ping_failure_pct", "tcp_syn_ping_joint_target_met")}), flush=True)
                    if row["execution_status"] == "error":
                        for pending_future in futures:
                            pending_future.cancel()
        attempt["state"] = "stopped after hard error" if any(row["execution_status"] == "error" for row in rows) else "complete"
    except BaseException as error:
        attempt.update(state="coordinator failure", error_type=type(error).__name__, error_message=str(error))
        raise
    finally:
        attempt["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
        save_json(attempts_path, attempts)
        rows.sort(key=lambda row: row["run_id"])
        use_frozen_sources(str(output))
        write_csv(output / "replications.csv", rows)
        write_csv(output / "summary.csv", summarize(rows))
        changed = [name for name, expected in manifest["sources"].items()
                   if digest(output / "sources" / name) != expected]
        save_json(output / "source-verification.json", dict(changed_during_run=changed, frozen_sources_changed=changed,
                  executed_from_frozen_sources=True, verified_run_ids=sorted(saved)))
        save_json(output / "status.json", dict(state=attempt["state"], saved=len(saved), planned=len(tasks),
                  missing_run_ids=sorted(task["run_id"] for task in tasks if task["run_id"] not in saved)))
        if changed:
            raise ValueError("frozen source files changed during execution")
    return not any(row["execution_status"] == "error" for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--task-plan", type=Path)
    parser.add_argument("--history-root", type=Path, default=Path("work/results-20261110"))
    parser.add_argument("--prepare-payload-plan", action="store_true")
    parser.add_argument("--freeze-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--single-phase", action="store_true",
                        help="Run an already qualified task matrix without a first-replication barrier")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("workers must be positive")
    if args.prepare_payload_plan and (args.run or args.freeze_only or args.task_plan):
        parser.error("payload-plan preparation is separate from freezing and execution")
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.prepare_payload_plan:
        plan = payload_plan(args.history_root.resolve())
        validate_tasks(plan)
        save_json(output / "task-plan.json", plan)
        print(f"Prepared {len(plan['tasks'])} tasks without executing a protocol simulation", flush=True)
        return
    if args.task_plan is None or not (args.run or args.freeze_only):
        parser.error("provide --task-plan and either --freeze-only or --run")
    plan = json.loads(args.task_plan.read_text())
    manifest = freeze_sources(output, plan)
    if args.run:
        if not run(output, manifest, args.workers, args.single_phase):
            raise SystemExit(1)
    else:
        print(f"Frozen {len(manifest['sources'])} source files for {len(manifest['tasks'])} tasks", flush=True)


if __name__ == "__main__":
    main()
