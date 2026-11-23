#!/usr/bin/env python3
"""Bounded perf sampling of the two receipt-owned daemon PIDs of a running native lab.

Replaces the per-campaign ``l2tunnel-kernel-perf-owned``, ``l2tunnel-profile-owned``
and ``l2tunnel-current-impaired-profile`` helpers. It never starts a native
workload: it waits for an already running lab to publish ``reference-clock.json``
and ``receipt.json``, verifies that both daemon PIDs execute the lab's owned
binary outside PID 1's network namespace, and samples only those processes
inside the measured window, shrunk by an edge margin on both sides.

Modes (``--mode``):

* ``kernel``: ``cycles:k`` per-thread process sampling with kernel frame-pointer
  address chains, stopped by SIGINT at the window end, plus before/after
  ``/proc`` host and owned-process snapshots.
* ``clean``: ``perf record ... -- sleep REMAINING`` over the owned processes
  with a hard wall-clock timeout and no extra observation.
* ``impaired``: full receipt/build/namespace/helper validation, per-TID
  sampling with context-switch records, 250 ms state/wchan samples of the most
  CPU-active owned threads, and a ``cycles`` to ``cpu-clock`` fallback when the
  hardware event is unsupported.

Without ``--apply`` the tool only prints the planned perf command (with PID/TID
placeholders) and timing contract; it reads no lab file, touches no ``/proc``
entry and never runs perf. All results are diagnostic observations with
observer overhead, never uninstrumented throughput qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time

MODES = ("kernel", "clean", "impaired")
MIB = 1024 * 1024

# Original per-mode recorder parameters; every value is overridable.
MODE_DEFAULTS = {
    "kernel": {"event": "cycles:k", "max_size": "16M", "chown": True,
               "scope": "owned tunnel processes only; kernel address callchains, no raw stack bytes; "
                        "diagnostic overhead, not uninstrumented acceptance"},
    "clean": {"event": "cycles", "max_size": "8M", "chown": True,
              "scope": "diagnostic sampling of only the two owned tunnel processes; additional observer "
                       "overhead; not an uninstrumented throughput qualification; frame-pointer address "
                       "chains only, no raw stack bytes"},
    "impaired": {"event": "cycles", "max_size": "64M", "chown": False,
                 "scope": "current source-pinned impaired QUIC-like owned-PID diagnostic; not uninstrumented "
                          "throughput qualification, no unrelated task payloads or raw stack bytes"},
}

# Original impaired workload contract (receipt plan keys and initial policy).
DEFAULT_PLAN_CONTRACT = {"cover": "quic-like", "path": "impaired", "workload": "forward16",
                         "one_way_delay_ms": 35, "loss_percent_per_direction": 15,
                         "flows": 16, "measurement_seconds": 20, "warmup_seconds": 5}
DEFAULT_POLICY_CONTRACT = {"path_mtu": 1500, "forward_kbit": 99000, "reverse_kbit": 9900,
                           "channels": 16, "window": 64, "repair_permille": 0}
UNSUPPORTED_EVENT = re.compile(
    r"not supported|No such device|No permission to enable|Access to performance monitoring", re.I)
INTERPRETATION = (
    "cycles/cpu-clock samples describe on-CPU execution; paired per-TID switch records "
    "describe off-CPU intervals with left/right censoring. Preemption flag distinguishes involuntary "
    "switch-out, not exact wakeup/runqueue delay. Validate parsed records, timestamps and zero loss separately; "
    "FP user callchains may be truncated in this unchanged optimized binary.")


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


# ---------------------------------------------------------------- bounded reads

def raw(path: Path | str, limit: int = MIB) -> bytes:
    with Path(path).open("rb") as handle:
        value = handle.read(limit + 1)
    require(len(value) <= limit, f"bounded read exceeded: {path}")
    return value


def text(path: Path | str, limit: int = MIB) -> str:
    return raw(path, limit).decode("utf-8", errors="strict")


def digest(path: Path | str, limit: int = 128 * MIB) -> str:
    return hashlib.sha256(raw(path, limit)).hexdigest()


def load(path: Path | str) -> object:
    return json.loads(text(path, 8 * MIB))


def number(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


# ---------------------------------------------------------------- pure parsers

def stat_fields(value: str) -> dict[str, object]:
    """Parse the identity and CPU fields of a ``/proc/PID[/task/TID]/stat`` line."""
    head, delimiter, tail = value.rpartition(") ")
    require(bool(delimiter) and "(" in head, "malformed owned task stat")
    fields = tail.split()
    require(len(fields) >= 22, "short owned task stat")
    pid = int(head.split(" ", 1)[0])
    return {"pid": pid, "state": fields[0], "user_ticks": int(fields[11]),
            "system_ticks": int(fields[12]), "starttime_ticks": int(fields[19])}


def task_status(value: str) -> dict[str, str]:
    """Keep only scheduling-relevant ``status`` fields of an owned task."""
    allowed = {"Name", "State", "Threads", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"}
    return {key: item.strip() for line in value.splitlines()
            if ":" in line for key, item in [line.split(":", 1)] if key in allowed}


def window(clock: dict, edge_ns: int) -> tuple[int, int]:
    """Return the monotonic recording start/stop inside the clock's measured window."""
    start = clock["start_ns"] + clock["warmup_ns"] + edge_ns
    end = clock["start_ns"] + clock["warmup_ns"] + clock["measure_ns"] - edge_ns
    return start, end


def contained(end: int, now: int, minimum_ns: int, maximum_ns: int) -> bool:
    return minimum_ns <= end - now <= maximum_ns


def choose_tasks(first: dict, second: dict, limit: int = 8) -> tuple[dict, dict]:
    """Rank owned TIDs by CPU ticks between two snapshots; keep the top ``limit``.

    A TID whose start time changed (reuse) counts as zero. The main thread is a
    candidate even when idle.
    """
    selected, all_tasks = {}, {}
    for pid, process in second["processes"].items():
        ranked = []
        all_tasks[pid] = {}
        for tid, task in process["tasks"].items():
            current = stat_fields(task["stat"])
            all_tasks[pid][tid] = current["starttime_ticks"]
            previous = first["processes"][pid]["tasks"].get(tid)
            delta = 0
            if previous is not None:
                old = stat_fields(previous["stat"])
                if old["starttime_ticks"] == current["starttime_ticks"]:
                    delta = (current["user_ticks"] + current["system_ticks"]
                             - old["user_ticks"] - old["system_ticks"])
            if delta > 0 or tid == pid:
                ranked.append((delta, int(tid)))
        ranked.sort(reverse=True)
        selected[pid] = {str(tid): all_tasks[pid][str(tid)] for _, tid in ranked[:limit]}
    return all_tasks, selected


def check_plan_contract(plan: dict, expected: dict, policy: dict | None) -> None:
    for key, value in expected.items():
        require(plan.get(key) == value, f"wrong preserved workload: {key}")
    if policy is not None:
        require(plan.get("initial_policy") == policy, "policy changed")


def should_fall_back(event: str, fallback: str | None, log: str, elapsed_ns: int) -> bool:
    """Original rule: only an immediate (<1 s) unsupported-event exit of the primary event."""
    return bool(fallback) and event != fallback and elapsed_ns < 1_000_000_000 \
        and UNSUPPORTED_EVENT.search(log) is not None


# ---------------------------------------------------------------- perf commands

def kernel_command(a: argparse.Namespace, pids: str, data: Path) -> list[str]:
    return ["perf", "record", "-e", a.event, "-F", str(a.frequency), "--call-graph", a.call_graph,
            "--per-thread", "--no-inherit", "--no-buildid", "--no-buildid-cache",
            "-m", str(a.mmap_pages), "--max-size", a.max_size, "--clockid", "mono",
            "-p", pids, "-o", str(data)]


def clean_command(a: argparse.Namespace, pids: str, data: Path, remaining: str) -> list[str]:
    return ["perf", "record", "-e", a.event, "-F", str(a.frequency), "--call-graph", a.call_graph,
            "--no-buildid-cache", "--max-size", a.max_size, "--clockid", "mono",
            "-p", pids, "-o", str(data), "--", "sleep", remaining]


def impaired_command(a: argparse.Namespace, event: str, tids: str, data: Path) -> list[str]:
    return ["perf", "record", "-e", event, "-F", str(a.frequency), "--call-graph", a.call_graph,
            "--switch-events", "-T", "--sample-cpu", "--per-thread", "--no-inherit",
            "--no-buildid", "--no-buildid-cache", "-m", str(a.mmap_pages), "--max-size", a.max_size,
            "--clockid", "mono", "-t", tids, "-o", str(data)]


def plan(a: argparse.Namespace) -> dict:
    """Dry-run description; placeholders stand for receipt PIDs and attached TIDs."""
    pids = ",".join(f"<PID_{side}>" for side in a.sides)
    if a.mode == "kernel":
        command = kernel_command(a, pids, a.output / "perf.data")
    elif a.mode == "clean":
        command = clean_command(a, pids, a.output / "perf.data", "<REMAINING_SECONDS>")
    else:
        command = impaired_command(a, a.event, "<OWNED_TIDS>", a.output / f"perf-{a.event}.data")
    result = {"mode": a.mode, "dry_run": True, "lab": str(a.lab), "output": str(a.output),
              "binary_name": a.binary_name, "sides": a.sides, "command": command,
              "setup_seconds": a.setup_seconds, "edge_margin_seconds": a.edge_margin_seconds,
              "window_seconds": [a.min_window_seconds, a.max_window_seconds],
              "chown_to_parent_owner": a.chown, "scope": MODE_DEFAULTS[a.mode]["scope"]}
    if a.mode == "clean":
        result["timeout_seconds"] = a.clean_timeout_seconds
    else:
        result.update(stop_timeout_seconds=a.stop_timeout_seconds,
                      kill_timeout_seconds=a.kill_timeout_seconds)
    if a.mode == "kernel":
        result["max_tasks"] = a.max_tasks
    if a.mode == "impaired":
        result.update(fallback_event=a.fallback_event, expected_binary_sha256=a.expected_binary_sha256,
                      plan_contract=a.expect_plan, policy_contract=a.expect_policy,
                      clock_contract={"warmup_ns": a.expect_warmup_ns, "measure_ns": a.expect_measure_ns},
                      wait_state={"tasks_per_process": a.wait_state_tasks,
                                  "interval_ms": a.wait_state_interval_ms,
                                  "max_samples": a.wait_state_max_samples},
                      max_tasks=a.max_tasks, perf_file_ceiling_bytes=a.perf_file_ceiling_bytes,
                      log_limit_bytes=a.log_limit_bytes)
    return result


# ---------------------------------------------------------------- live helpers

def namespace(path: Path | str) -> dict[str, int]:
    value = os.stat(path)
    return {"device": value.st_dev, "inode": value.st_ino}


def wait_for_clock(lab: Path, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while not (lab / "reference-clock.json").is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"original{seconds:g}s setup bound")
        time.sleep(.1)


def sleep_until(target_ns: int) -> None:
    while time.monotonic_ns() < target_ns:
        time.sleep(min(.05, max(0, (target_ns - time.monotonic_ns()) / 1e9)))


def receipt_pids(receipt: dict, sides: list[str]) -> list[int]:
    return [receipt["initial_daemon_resources"][side]["pid"] for side in sides]


def verify_simple_owned(lab: Path, binary_name: str, pids: list[int]) -> dict[int, str]:
    """kernel/clean modes: owned executable and non-host network namespace."""
    starttimes = {}
    for pid in pids:
        require(Path(f"/proc/{pid}/exe").resolve() == lab / binary_name, "daemon executable is not owned copy")
        require(Path(f"/proc/{pid}/ns/net").readlink() != Path("/proc/1/ns/net").readlink(),
                "daemon in original network namespace")
        starttimes[pid] = Path(f"/proc/{pid}/stat").read_text().rpartition(") ")[2].split()[19]
    return starttimes


def finish(child: subprocess.Popen, stop_timeout: float, kill_timeout: float) -> int:
    """SIGINT, then terminate, then kill; raise if perf did not finalize gracefully."""
    if child.poll() is None:
        child.send_signal(signal.SIGINT)
    try:
        return child.wait(timeout=stop_timeout)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            child.wait(timeout=kill_timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=kill_timeout)
        raise TimeoutError(f"perf did not finalize within original{stop_timeout:g}s graceful-stop bound")


def file_records(output: Path) -> dict:
    return {p.name: {"bytes": p.stat().st_size, "sha256": digest(p)} for p in output.iterdir() if p.is_file()}


def chown_to_parent(output: Path) -> None:
    owner = output.parent.stat()
    for path in [output, *output.iterdir()]:
        os.chown(path, owner.st_uid, owner.st_gid)


# ---------------------------------------------------------------- kernel mode

def kernel_sample(pids: list[int], expected: dict[int, str], max_tasks: int) -> dict:
    observations = {"at_monotonic_ns": time.monotonic_ns(), "host_stat": Path("/proc/stat").read_text(),
                    "pressure": {n: Path("/proc/pressure/" + n).read_text() for n in ("cpu", "io", "memory")},
                    "processes": {}}
    for pid in pids:
        base = Path("/proc") / str(pid)
        value = (base / "stat").read_text()
        require(value.rpartition(") ")[2].split()[19] == expected[pid], "owned PID identity changed")
        tasks = sorted((base / "task").iterdir(), key=lambda p: int(p.name))
        require(len(tasks) <= max_tasks, "owned task bound exceeded")
        observations["processes"][str(pid)] = {
            "stat": value, "status": (base / "status").read_text(), "io": (base / "io").read_text(),
            "schedstat": (base / "schedstat").read_text(),
            "task_stats": {p.name: (p / "stat").read_text() for p in tasks}}
    observations["completed_monotonic_ns"] = time.monotonic_ns()
    return observations


def run_kernel(a: argparse.Namespace) -> int:
    lab, out = a.lab, a.output
    out.mkdir(mode=0o700, exist_ok=False)
    result: dict = {"status": "failed", "scope": MODE_DEFAULTS["kernel"]["scope"]}
    child = None
    try:
        wait_for_clock(lab, a.setup_seconds)
        clock = json.loads((lab / "reference-clock.json").read_text())
        receipt = json.loads((lab / "receipt.json").read_text())
        pids = receipt_pids(receipt, a.sides)
        expected = verify_simple_owned(lab, a.binary_name, pids)
        start, end = window(clock, a.edge_ns)
        sleep_until(start)
        require(contained(end, time.monotonic_ns(), a.min_window_ns, a.max_window_ns),
                "no contained recording interval")
        before = kernel_sample(pids, expected, a.max_tasks)
        argv = kernel_command(a, ",".join(map(str, pids)), out / "perf.data")
        result.update(command=argv, owned_pids=pids, reference_clock=clock,
                      binary_sha256=receipt["binary_sha256"],
                      task_delayacct=Path("/proc/sys/kernel/task_delayacct").read_text().strip(),
                      sched_schedstats=Path("/proc/sys/kernel/sched_schedstats").read_text().strip(),
                      before=before)
        with (out / "record.log").open("w") as log:
            child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            while time.monotonic_ns() < end and child.poll() is None:
                time.sleep(min(.05, max(0, (end - time.monotonic_ns()) / 1e9)))
            result["stop_requested_ns"] = time.monotonic_ns()
            exit_code = finish(child, a.stop_timeout_seconds, a.kill_timeout_seconds)
        result.update(exit_code=exit_code, finalized_ns=time.monotonic_ns(),
                      after=kernel_sample(pids, expected, a.max_tasks))
        result["status"] = "passed" if exit_code == 0 else "failed"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=a.kill_timeout_seconds)
        result["files"] = file_records(out)
        (out / "profile.json").write_text(json.dumps(result, indent=2) + "\n")
        if a.chown:
            chown_to_parent(out)
        print(json.dumps({k: v for k, v in result.items() if k not in ("before", "after")}), flush=True)
    return 0 if result["status"] == "passed" else 1


# ---------------------------------------------------------------- clean mode

def run_clean(a: argparse.Namespace) -> int:
    lab, out = a.lab, a.output
    out.mkdir(mode=0o700, exist_ok=False)
    result: dict = {"status": "failed", "scope": MODE_DEFAULTS["clean"]["scope"]}
    code = 1
    try:
        wait_for_clock(lab, a.setup_seconds)
        clock = json.loads((lab / "reference-clock.json").read_text())
        receipt = json.loads((lab / "receipt.json").read_text())
        pids = receipt_pids(receipt, a.sides)
        verify_simple_owned(lab, a.binary_name, pids)
        start, end = window(clock, a.edge_ns)
        sleep_until(start)
        now = time.monotonic_ns()
        require(contained(end, now, a.min_window_ns, a.max_window_ns), "no contained recording interval")
        remaining = (end - now) / 1e9
        argv = clean_command(a, ",".join(map(str, pids)), out / "perf.data", str(remaining))
        before = time.monotonic_ns()
        with (out / "record.log").open("w") as log:
            completed = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=False,
                                       timeout=a.clean_timeout_seconds)
        after = time.monotonic_ns()
        code = completed.returncode
        result.update(status="passed" if code == 0 else "failed", command=argv, exit_code=code,
                      original_reference_clock=clock, sampled_start_ns=before, sampled_end_ns=after,
                      owned_pids=pids, binary_sha256=receipt["binary_sha256"])
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
        code = 1
    finally:
        (out / "profile.json").write_text(json.dumps(result, indent=2) + "\n")
        if a.chown:
            chown_to_parent(out)
        print(json.dumps(result), flush=True)
    return code


# ---------------------------------------------------------------- impaired mode

def limits(ceiling: int) -> None:
    """Child-side RLIMIT_FSIZE so perf data cannot exceed the bounded ceiling."""
    inherited = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
    if inherited != resource.RLIM_INFINITY:
        require(inherited >= ceiling, "inherited file ceiling cannot hold bounded perf data")
    resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling, ceiling))


def validate_case(a: argparse.Namespace) -> tuple[dict, dict, dict]:
    lab = a.lab
    receipt = load(lab / "receipt.json")
    build = load(lab / "build-receipt.json")
    require(build["status"] == "passed" and build["source_stable_during_build"], "unverified build")
    require(build["source_sha256_before"] == build["source_sha256_after"], "unstable build inputs")
    require(build["binary_sha256"] == receipt["binary_sha256"] == a.expected_binary_sha256,
            "not current source-pinned")
    require(digest(lab / a.binary_name) == a.expected_binary_sha256, "copied binary hash changed")
    require(digest(lab / "build-receipt.json") == receipt["build_receipt_sha256"], "build receipt changed")
    case_plan = receipt["plan"]
    check_plan_contract(case_plan, a.expect_plan, a.expect_policy)
    proof = receipt["namespace_proof"]
    for kind in ("user", "net", "mnt"):
        require(proof["fresh"][kind] != proof["original"][kind], f"no fresh {kind} namespace")
    sources = {}
    for name, expected in receipt["executed_helpers"].items():
        require(name.startswith("tools/") and "/" not in name[6:], "unexpected helper path")
        actual = digest(lab / name[6:])
        require(actual == expected == build["source_sha256_before"][name], "helper source changed")
        sources[name] = actual
    owned = {}
    for side in a.sides:
        info = receipt["initial_daemon_resources"][side]
        pid = info["pid"]
        require(number(pid) and pid > 1, "invalid receipt-owned PID")
        expected_ns = case_plan["namespaces"]["endpoint_" + side]
        require(bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", expected_ns)), "invalid owned namespace name")
        base = Path("/proc") / str(pid)
        current = stat_fields(text(base / "stat", 8192))
        require(current["pid"] == pid and current["starttime_ticks"] == info["starttime_ticks"], "PID reused")
        require(current["state"] not in ("Z", "X"), "owned daemon exited")
        require((base / "exe").resolve() == lab / a.binary_name, "daemon executable is not owned copy")
        net = namespace(base / "ns/net")
        require(net == namespace(base / "root/run/netns" / expected_ns), "daemon not in expected owned netns")
        require(net != proof["original"]["net"], "daemon in original network namespace")
        require(namespace(base / "ns/user") == proof["fresh"]["user"], "daemon user namespace changed")
        require(namespace(base / "ns/mnt") != proof["original"]["mnt"], "daemon in original mount namespace")
        owned[pid] = {"side": side, "starttime_ticks": current["starttime_ticks"], "network": net,
                      "user": namespace(base / "ns/user"), "mount": namespace(base / "ns/mnt")}
    require(len(owned) == len(a.sides), "same daemon PID used twice")
    return receipt, owned, sources


def verify_pid(lab: Path, binary_name: str, pid: int, expected: dict) -> tuple[Path, str]:
    base = Path("/proc") / str(pid)
    value = text(base / "stat", 8192)
    parsed = stat_fields(value)
    require(parsed["starttime_ticks"] == expected["starttime_ticks"], "owned PID identity changed")
    require(parsed["state"] not in ("Z", "X"), "owned daemon exited during diagnostic")
    require((base / "exe").resolve() == lab / binary_name, "owned executable changed")
    for kind, key in [("net", "network"), ("user", "user"), ("mnt", "mount")]:
        require(namespace(base / "ns" / kind) == expected[key], "owned namespace changed")
    return base, value


def impaired_snapshot(a: argparse.Namespace, owned: dict) -> dict:
    result = {"start_monotonic_ns": time.monotonic_ns(), "host_stat": text("/proc/stat"),
              "host_diskstats": text("/proc/diskstats"),
              "host_pressure": {name: text("/proc/pressure/" + name, 4096) for name in ("cpu", "io", "memory")},
              "processes": {}}
    for pid, expected in owned.items():
        base, value = verify_pid(a.lab, a.binary_name, pid, expected)
        tasks = sorted((base / "task").iterdir(), key=lambda path: int(path.name))
        require(len(tasks) <= a.max_tasks, "owned task bound exceeded")
        result["processes"][str(pid)] = {
            "stat": value, "io": text(base / "io", 8192), "status": text(base / "status", 65536),
            "schedstat": text(base / "schedstat", 4096),
            "tasks": {task.name: {"stat": text(task / "stat", 8192),
                                  "status": task_status(text(task / "status", 65536))} for task in tasks}}
    result["end_monotonic_ns"] = time.monotonic_ns()
    return result


def wait_states(a: argparse.Namespace, owned: dict, selected: dict) -> dict:
    result = {"start_monotonic_ns": time.monotonic_ns(), "processes": {}}
    for pid, expected in owned.items():
        base, _ = verify_pid(a.lab, a.binary_name, pid, expected)
        rows = {}
        for tid, identity in selected[str(pid)].items():
            task = base / "task" / tid
            try:
                value = stat_fields(text(task / "stat", 8192))
                require(value["starttime_ticks"] == identity, "owned TID reused")
                rows[tid] = {"stat": value, "wchan": text(task / "wchan", 512).strip(),
                             "status": task_status(text(task / "status", 65536))}
            except FileNotFoundError:
                rows[tid] = {"exited": True}
        result["processes"][str(pid)] = rows
    result["end_monotonic_ns"] = time.monotonic_ns()
    return result


def run_impaired(a: argparse.Namespace) -> int:
    lab, output = a.lab, a.output
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    result: dict = {"status": "failed", "scope": MODE_DEFAULTS["impaired"]["scope"],
                    "binary_sha256": a.expected_binary_sha256, "helper_sha256": digest(__file__),
                    "data_validated": False, "attempts": [], "wait_state_samples": []}
    child = None
    owned = None
    try:
        wait_for_clock(lab, a.setup_seconds)
        _, owned, sources = validate_case(a)
        result.update(
            owned_processes=owned, executed_helpers=sources,
            native_receipt_sha256_at_attach=digest(lab / "receipt.json"),
            build_receipt_sha256=digest(lab / "build-receipt.json"),
            user_hz=os.sysconf("SC_CLK_TCK"),
            perf_version=subprocess.run(["perf", "version"], capture_output=True, text=True,
                                        timeout=3, check=True).stdout.strip(),
            kernel_settings={name: text("/proc/sys/kernel/" + name, 128).strip()
                             for name in ("perf_event_paranoid", "kptr_restrict",
                                          "task_delayacct", "sched_schedstats")})
        clock = load(lab / "reference-clock.json")
        require(set(clock) == {"start_ns", "warmup_ns", "measure_ns"}
                and all(number(value) for value in clock.values()), "invalid finite clock")
        if a.expect_warmup_ns is not None:
            require(clock["warmup_ns"] == a.expect_warmup_ns, "clock contract changed")
        if a.expect_measure_ns is not None:
            require(clock["measure_ns"] == a.expect_measure_ns, "clock contract changed")
        start, end = window(clock, a.edge_ns)
        result.update(reference_clock=clock, planned_start_ns=start, planned_stop_ns=end)
        warmup = impaired_snapshot(a, owned)
        sleep_until(start)
        require(contained(end, time.monotonic_ns(), a.min_window_ns, a.max_window_ns),
                "no contained recording interval")
        before = impaired_snapshot(a, owned)
        result["before"] = before
        all_tasks, selected = choose_tasks(warmup, before, a.wait_state_tasks)
        result.update(
            attached_tasks=all_tasks, wait_state_sampled_tasks=selected,
            wait_state_scope=f"at most{a.wait_state_tasks} previously CPU-active owned TIDs per process, "
            f"including main when in top{a.wait_state_tasks}; attached TID snapshot excludes later-created "
            f"threads; {a.wait_state_interval_ms}ms state/wchan samples are observations, not exact "
            "blocked-duration or wakeup attribution")
        tids = ",".join(tid for tasks in all_tasks.values() for tid in tasks)
        event = a.event
        interval_ns = a.wait_state_interval_ms * 1_000_000
        next_sample = time.monotonic_ns()
        while True:
            path = output / ("perf-" + event + ".data")
            log_path = output / ("perf-" + event + ".log")
            argv = impaired_command(a, event, tids, path)
            attempt = {"event": event, "command": argv, "start_ns": time.monotonic_ns()}
            result["attempts"].append(attempt)
            with log_path.open("xb") as log:
                child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                         preexec_fn=lambda: limits(a.perf_file_ceiling_bytes))
                while time.monotonic_ns() < end and child.poll() is None:
                    now = time.monotonic_ns()
                    if now >= next_sample:
                        require(len(result["wait_state_samples"]) < a.wait_state_max_samples,
                                "wait-state sample bound")
                        result["wait_state_samples"].append(wait_states(a, owned, selected))
                        next_sample = now + interval_ns
                    require(log_path.stat().st_size <= a.log_limit_bytes, "recorder log exceeded bound")
                    time.sleep(min(.025, max(0, (end - time.monotonic_ns()) / 1e9)))
                if child.poll() is not None and time.monotonic_ns() < end:
                    attempt.update(exit_code=child.returncode, stopped_ns=time.monotonic_ns(),
                                   unexpected_early_exit=True)
                    reason = text(log_path, a.log_limit_bytes)
                    if should_fall_back(event, a.fallback_event, reason,
                                        time.monotonic_ns() - attempt["start_ns"]):
                        require(end - time.monotonic_ns() >= a.min_window_ns,
                                "fallback cannot extend original interval")
                        event = a.fallback_event
                        child = None
                        continue
                    raise RuntimeError("recorder exited before original stop; inspect retained log/cap")
                attempt["stop_requested_ns"] = time.monotonic_ns()
                attempt["exit_code"] = finish(child, a.stop_timeout_seconds, a.kill_timeout_seconds)
                attempt["finalized_ns"] = time.monotonic_ns()
                child = None
            require(attempt["exit_code"] in (0, -signal.SIGINT, 128 + signal.SIGINT), "unexpected recorder stop")
            require(path.is_file() and 128 < path.stat().st_size <= a.perf_file_ceiling_bytes,
                    "missing or oversized perf data")
            result.update(status="recorded_unvalidated", selected_event=event, perf_data=path.name,
                          after=impaired_snapshot(a, owned), intentional_sigint=True,
                          interpretation=INTERPRETATION)
            break
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if "after" not in result and owned is not None:
            try:
                result["after"] = impaired_snapshot(a, owned)
            except Exception as error:
                result["after_observation_error"] = f"{type(error).__name__}: {error}"
        if child is not None and child.poll() is None:
            try:
                result["forced_stop_exit_code"] = finish(child, a.stop_timeout_seconds, a.kill_timeout_seconds)
            except Exception as error:
                result["forced_stop_error"] = f"{type(error).__name__}: {error}"
        result["files"] = file_records(output)
        (output / "profile.json").write_text(json.dumps(result, indent=2) + "\n")
        if a.chown:
            chown_to_parent(output)
        print(json.dumps({key: value for key, value in result.items()
                          if key not in ("before", "after", "wait_state_samples", "attached_tasks")}), flush=True)
    return 0 if result["status"] == "recorded_unvalidated" else 1


# ---------------------------------------------------------------- CLI

def json_object(value: str) -> dict:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("expected a JSON object")
    return parsed


def optional_json_object(value: str) -> dict | None:
    parsed = json.loads(value)
    if parsed is not None and not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("expected a JSON object or null")
    return parsed


def optional_seconds(value: str) -> float | None:
    return None if value == "any" else float(value)


def parse(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=MODES, required=True)
    p.add_argument("--lab", type=Path, required=True,
                   help="Running lab directory holding reference-clock.json, receipt.json and the owned binary")
    p.add_argument("--output", type=Path, required=True, help="New result directory (must not exist)")
    p.add_argument("--apply", action="store_true", help="Actually run perf; default prints the plan only")
    p.add_argument("--binary-name", default="l2tunnel-native", help="Owned executable name inside --lab")
    p.add_argument("--sides", default="a,b", help="Comma-separated receipt daemon sides")
    p.add_argument("--setup-seconds", type=float, default=75.0, help="Bound for the lab clock to appear")
    p.add_argument("--edge-margin-seconds", type=float, default=2.0,
                   help="Skip this much after warmup and before the measured window end")
    p.add_argument("--min-window-seconds", type=float, default=2.0)
    p.add_argument("--max-window-seconds", type=float, default=17.0)
    p.add_argument("--event", help="perf event (default: kernel cycles:k, clean/impaired cycles)")
    p.add_argument("--fallback-event", default="cpu-clock",
                   help="impaired: event used after an immediate unsupported-event exit; '' disables")
    p.add_argument("--frequency", type=int, default=99, help="perf -F sampling frequency (Hz)")
    p.add_argument("--call-graph", default="fp")
    p.add_argument("--mmap-pages", type=int, default=8, help="perf -m (kernel/impaired)")
    p.add_argument("--max-size", help="perf --max-size (default: kernel 16M, clean 8M, impaired 64M)")
    p.add_argument("--stop-timeout-seconds", type=float, default=5.0, help="SIGINT finalize bound")
    p.add_argument("--kill-timeout-seconds", type=float, default=2.0)
    p.add_argument("--clean-timeout-seconds", type=float, default=25.0, help="clean: perf wall-clock cap")
    p.add_argument("--max-tasks", type=int, default=2048, help="Owned task count bound per process")
    p.add_argument("--chown", dest="chown", action="store_true", default=None,
                   help="chown output to its parent's owner (default for kernel/clean)")
    p.add_argument("--no-chown", dest="chown", action="store_false", help="(default for impaired)")
    p.add_argument("--expected-binary-sha256", help="impaired: required source-pinned daemon digest")
    p.add_argument("--expect-plan", type=json_object, default=DEFAULT_PLAN_CONTRACT,
                   help="impaired: receipt plan keys that must match (JSON object; {} disables)")
    p.add_argument("--expect-policy", type=optional_json_object, default=DEFAULT_POLICY_CONTRACT,
                   help="impaired: exact plan initial_policy (JSON object; null disables)")
    p.add_argument("--expect-warmup-seconds", type=optional_seconds, default=5.0,
                   help="impaired: required clock warmup ('any' disables)")
    p.add_argument("--expect-measure-seconds", type=optional_seconds, default=20.0,
                   help="impaired: required clock measurement ('any' disables)")
    p.add_argument("--wait-state-tasks", type=int, default=8)
    p.add_argument("--wait-state-interval-ms", type=int, default=250)
    p.add_argument("--wait-state-max-samples", type=int, default=80)
    p.add_argument("--perf-file-ceiling-bytes", type=int, default=128 * MIB,
                   help="impaired: RLIMIT_FSIZE for perf and maximum perf data size")
    p.add_argument("--log-limit-bytes", type=int, default=MIB, help="impaired: recorder log bound")
    a = p.parse_args(argv)
    defaults = MODE_DEFAULTS[a.mode]
    a.event = a.event or defaults["event"]
    a.max_size = a.max_size or defaults["max_size"]
    a.chown = defaults["chown"] if a.chown is None else a.chown
    a.fallback_event = a.fallback_event or None
    a.sides = [side for side in a.sides.split(",") if side]
    if not a.sides or len(set(a.sides)) != len(a.sides):
        p.error("--sides needs distinct non-empty sides")
    for name in ("setup_seconds", "edge_margin_seconds", "min_window_seconds", "stop_timeout_seconds",
                 "kill_timeout_seconds", "clean_timeout_seconds"):
        if getattr(a, name) < 0:
            p.error(f"--{name.replace('_', '-')} must not be negative")
    if a.min_window_seconds > a.max_window_seconds:
        p.error("--min-window-seconds exceeds --max-window-seconds")
    for name in ("frequency", "mmap_pages", "max_tasks", "wait_state_tasks", "wait_state_interval_ms",
                 "wait_state_max_samples", "perf_file_ceiling_bytes", "log_limit_bytes"):
        if getattr(a, name) <= 0:
            p.error(f"--{name.replace('_', '-')} must be positive")
    a.edge_ns = round(a.edge_margin_seconds * 1e9)
    a.min_window_ns = round(a.min_window_seconds * 1e9)
    a.max_window_ns = round(a.max_window_seconds * 1e9)
    a.expect_warmup_ns = None if a.expect_warmup_seconds is None else round(a.expect_warmup_seconds * 1e9)
    a.expect_measure_ns = None if a.expect_measure_seconds is None else round(a.expect_measure_seconds * 1e9)
    if a.expected_binary_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", a.expected_binary_sha256):
        p.error("--expected-binary-sha256 must be 64 lowercase hex digits")
    if a.apply and a.mode == "impaired" and a.expected_binary_sha256 is None:
        p.error("--mode impaired --apply requires --expected-binary-sha256")
    a.lab = a.lab.resolve()
    a.output = a.output.resolve()
    if a.output.exists() or a.output.is_symlink():
        p.error("--output must not exist")
    return a


def main(argv: list[str] | None = None) -> int:
    a = parse(argv)
    if not a.apply:
        print(json.dumps(plan(a), indent=2), flush=True)
        return 0
    return {"kernel": run_kernel, "clean": run_clean, "impaired": run_impaired}[a.mode](a)


if __name__ == "__main__":
    sys.exit(main())
