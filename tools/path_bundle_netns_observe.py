"""Passive underlay observers for the owned, shaper-before-loss path-bundle lab."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

if __package__:
    from . import common_native_matrix as matrix
    from . import common_native_observe as observe
else:
    import common_native_matrix as matrix
    import common_native_observe as observe


PACKETS = 750_000
SAMPLE_BYTES = 8 * 1024 * 1024
SAMPLE_NS = 25_000_000
QDISC_NS = 100_000_000
MAX_NS = 120_000_000_000
ROUTER_PORTS = ("a0", "b0")


def network_inode(pid):
    return Path(f"/proc/{pid}/ns/net").stat().st_ino


def start_captures(case, children):
    namespace = case.spec.namespaces["router"]
    inode = (Path("/run/netns") / namespace).stat().st_ino
    info = case.value["underlay_observer"] = {
        "router_namespace": namespace, "router_inode": inode, "captures": {}, "complete": False,
        "scope": "Router interface packet taps bracket forwarding and output queuing; "
                 "these taps do not timestamp individual qdisc enqueue or dequeue calls.",
    }
    for interface in ROUTER_PORTS:
        name = f"router-{interface}"
        path = case.output / (name + ".pcap")
        args = ["tcpdump", "-Z", "root", "--immediate-mode", "-p", "-nn", "-s", "96",
                "-B", "8192", "-i", interface, "-c", str(PACKETS), "-w", "-",
                "ip", "and", "udp", "and", "host", matrix.WAN["a"], "and", "host", matrix.WAN["b"]]
        child = children[name] = case.spawn("router", name, args, capture=path)
        case.wait_marker(child, "listening on", time.monotonic() + 8)
        pid = child["process"].pid
        matrix.require(network_inode(pid) == inode, "capture outside owned router")
        info["captures"][name] = dict(interface=interface, pid=pid, path=path.name,
                                      snaplen=96, packet_limit=PACKETS, ready_monotonic_ns=time.monotonic_ns())
    case.save()


def task(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    runtime, wait, slices = map(int, Path(f"/proc/{pid}/schedstat").read_text().split())
    return dict(start_ticks=int(fields[19]), cpu=int(fields[36]), state=fields[0],
                runtime_ns=runtime, runqueue_wait_ns=wait, timeslices=slices)


def start_sampler(case, children, adapters):
    info = case.value["underlay_observer"]
    args = [sys.executable, Path(__file__).resolve(), info["router_namespace"]]
    info["adapters"] = {}
    for side in "ab":
        pid = adapters[side]["process"].pid
        inode = case.value["adapter_pid_ns"][side]["expected_inode"]
        matrix.require(network_inode(pid) == inode, "sampler target outside owned endpoint")
        start = task(pid)["start_ticks"]
        info["adapters"][side] = dict(pid=pid, netns_inode=inode, start_ticks=start,
                                      affinity=sorted(os.sched_getaffinity(pid)))
        args.extend((str(pid), str(inode), str(start)))
    path = case.output / "underlay-samples.jsonl"
    child = children["router-sampler"] = case.spawn("router", "router-sampler", args, capture=path)
    case.wait_marker(child, "SAMPLER_READY", time.monotonic() + 8)
    matrix.require(network_inode(child["process"].pid) == info["router_inode"], "sampler outside owned router")
    info["sampler"] = dict(path=path.name, byte_limit=SAMPLE_BYTES, sample_us=SAMPLE_NS // 1000,
                           qdisc_us=QDISC_NS // 1000, ready_monotonic_ns=time.monotonic_ns())
    case.save()


def router_queues():
    result = subprocess.run(["tc", "-s", "-j", "qdisc", "show"], check=True,
                            capture_output=True, timeout=1)
    matrix.require(len(result.stdout) <= 32768, "owned qdisc output exceeds bound")
    queues = {}
    for row in json.loads(result.stdout):
        if row.get("dev") not in ROUTER_PORTS:
            continue
        dev = row["dev"]
        matrix.require(dev not in queues and row.get("kind") == "netem"
                       and row.get("handle") == "10:" and row.get("root") is True,
                       "unexpected owned router qdisc")
        queues[dev] = {k: row[k] for k in ("bytes", "packets", "drops", "overlimits",
                                           "requeues", "backlog", "qlen")}
        matrix.require(all(type(v) is int and v >= 0 for v in queues[dev].values()),
                       "invalid router qdisc counter")
    matrix.require(set(queues) == set(ROUTER_PORTS), "missing owned router qdisc")
    return queues


def sample(namespace, targets):
    matrix.require(network_inode("self") == (Path("/run/netns") / namespace).stat().st_ino,
                   "sampler outside selected router")
    matrix.require(set(targets) == set("ab"), "expected two adapter identities")
    running = True

    def stop(_sig, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    origin = time.monotonic_ns()
    previous = None
    next_qdisc = origin
    count = size = max_gap = 0

    def emit(row):
        nonlocal size
        data = (json.dumps(row, separators=(",", ":")) + "\n").encode()
        size += len(data)
        matrix.require(size <= SAMPLE_BYTES, "underlay sample byte limit reached")
        sys.stdout.buffer.write(data)

    while running:
        begin = time.monotonic_ns()
        matrix.require(begin - origin < MAX_NS, "underlay sampler time limit reached")
        if previous is not None:
            max_gap = max(max_gap, begin - previous)
        previous = begin
        entry = {"mono_begin_ns": begin, "wall_ns": time.time_ns(), "tasks": {}}
        for side, (pid, inode, start) in targets.items():
            current = task(pid)
            matrix.require(current["start_ticks"] == start and network_inode(pid) == inode,
                           "owned adapter identity changed")
            entry["tasks"][side] = current
        entry["sampler_task"] = task("self")
        if begin >= next_qdisc:
            entry["tc_begin_ns"] = time.monotonic_ns()
            try:
                entry["router_netem"] = router_queues()
            except subprocess.CalledProcessError:
                if running:
                    raise
                break
            entry["tc_end_ns"] = time.monotonic_ns()
            next_qdisc = begin + QDISC_NS
        entry["mono_end_ns"] = time.monotonic_ns()
        emit(entry)
        count += 1
        if count == 1:
            print("SAMPLER_READY", file=sys.stderr, flush=True)
        remaining = begin + SAMPLE_NS - time.monotonic_ns()
        if running and remaining > 0:
            time.sleep(remaining / 1_000_000_000)
    emit(dict(complete=True, samples=count, max_sample_gap_ns=max_gap,
              finished_monotonic_ns=time.monotonic_ns()))
    sys.stdout.buffer.flush()


def finish(case, children):
    info = case.value["underlay_observer"]
    errors = []
    for name, child in children.items():
        try:
            alive = child["process"].poll() is None
            rc = case.stop(child, signal.SIGINT)
            matrix.require(alive and rc == 0, f"{name} did not cover workload or stop cleanly")
            path = child["capture"]
            if name == "router-sampler":
                item = info["sampler"]
                matrix.require(0 < path.stat().st_size <= SAMPLE_BYTES, "invalid sampler output size")
                last = None
                with path.open("rb") as stream:
                    for line in stream:
                        last = line
                footer = json.loads(last or b"null")
                matrix.require(isinstance(footer, dict) and footer.get("complete") and footer["samples"] > 0,
                               "missing complete sampler footer")
                item.update(footer)
            else:
                item = info["captures"][name]
                counts = observe.capture_counters(child["log"])
                item["counters"] = counts
                matrix.require(0 < counts["captured"] < PACKETS and counts["dropped"] == 0,
                               "incomplete owned router capture")
                matrix.require(24 < path.stat().st_size <= 24 + PACKETS * (16 + 96),
                               "invalid capture size")
            item.update(bytes=path.stat().st_size, sha256=matrix.file_hash(path), complete=True)
        except (KeyError, OSError, TypeError, ValueError, RuntimeError) as error:
            errors.append(f"{name}: {error}")
    info["errors"] = errors
    info["complete"] = set(children) == {"router-a0", "router-b0", "router-sampler"} and not errors
    case.save()
    return info["complete"]


if __name__ == "__main__":
    namespace, *args = sys.argv[1:]
    matrix.require(len(args) == 6 and Path(namespace).name == namespace, "invalid sampler arguments")
    sample(namespace, {side: tuple(map(int, args[i:i + 3])) for side, i in (("a", 0), ("b", 3))})
