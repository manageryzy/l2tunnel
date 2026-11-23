#!/usr/bin/env python3
"""One established-session multipath UDP/TUN measurement. Dry-run unless --apply."""

import argparse
from collections import Counter
import contextlib
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import sys
import time
import uuid

if __package__:
    from . import common_native_matrix as matrix
    from . import common_native_observe as observe
    from . import path_bundle_netns_links as path_links
    from . import path_bundle_netns_observe as underlay_observe
else:
    import common_native_matrix as matrix
    import common_native_observe as observe
    import path_bundle_netns_links as path_links
    import path_bundle_netns_observe as underlay_observe

ROOT = Path(__file__).resolve().parents[1]
BASE_PORT = {"a": 24480, "b": 24500}
SEEDS = {"a": 31248, "b": 31248 ^ 0x9E3779B97F4A7C15}
PCAP_LIMIT = 750_000
NEIGHBOR_LIMIT = 4096
NEIGHBOR_SURFACES = (
    ("endpoint_a", "wan0"), ("router", "a0"),
    ("router", "b0"), ("endpoint_b", "wan0"),
)
HOLD_US = 500
OUTER_MTU = 1500
PLAN = dict(
    profile="pre-established authenticated P2P laboratory adapter",
    max_path_hold_us=HOLD_US,
    shares_one_wan_queue_per_direction=True,
    forward_mbps=100,
    reverse_mbps=10,
    one_way_delay_ms=35,
    loss_percent_each_direction=15,
    directional_seeds=SEEDS,
    inner_linux_tcp_connections=1,
    application_credit_bytes=4 * 1024**2,
    warmup_seconds=2,
    sample_seconds=10,
    native_mtu=1500,
    tun_txqueuelen=768,
    forward_tun_fq_maxrate_mbps=85,
    application_offer_mbps=90,
    comparison="Shared WAN and inner Linux probe match the historical single-flow arm. "
    "The selected UDP tuples carry separate shard batches; both lab endpoints start with the same fresh session key. "
    "This measures established-path interoperability between these two lab processes.",
)


def wan_capture(path, sample_ns, paths):
    """Count actual complete IPv4 lengths from a header-only capture, by direction and UDP tuple."""
    counts = {s: [Counter() for _ in range(paths)] for s in "ab"}
    addresses = {socket.inet_aton(addr): side for side, addr in matrix.WAN.items()}
    with path.open("rb") as stream:
        hdr = stream.read(24)
        fmt = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000)}
        matrix.require(hdr[:4] in fmt, "expected timestamped classic pcap")
        order, scale = fmt[hdr[:4]]
        matrix.require(
            struct.unpack_from(order + "I", hdr, 20)[0] == 1,
            "expected owned Ethernet veth",
        )
        records = 0
        while raw := stream.read(16):
            sec, usec, caplen, length = struct.unpack(order + "4I", raw)
            matrix.require(caplen <= 96 and caplen <= length, "invalid captured extent")
            frame = stream.read(caplen)
            matrix.require(
                len(frame) == caplen
                and len(frame) >= 42
                and frame[12:14] == b"\x08\x00",
                "invalid Ethernet IPv4",
            )
            ip = frame[14:]
            ihl = 4 * (ip[0] & 15)
            iplen = int.from_bytes(ip[2:4], "big")
            matrix.require(
                ip[0] >> 4 == 4
                and ip[9] == 17
                and ihl >= 20
                and ihl + 8 <= len(ip)
                and 28 <= iplen <= length - 14
                and (int.from_bytes(ip[6:8], "big") & 0x3FFF) == 0,
                "unexpected IP extent or fragment on owned WAN",
            )
            side = addresses[ip[12:16]]
            peer = "b" if side == "a" else "a"
            src, dst, udp_size = struct.unpack_from("!HHH", ip, ihl)
            slot = src - BASE_PORT[side]
            matrix.require(
                addresses[ip[16:20]] == peer
                and 0 <= slot < paths
                and dst == BASE_PORT[peer] + slot
                and udp_size == iplen - ihl,
                "unexpected physical UDP tuple or UDP size",
            )
            measures = counts[side][slot]
            measures["packets"] += 1
            measures["ip_bytes"] += iplen
            t = sec * 10**9 + usec * scale
            if sample_ns and sample_ns[0] <= t < sample_ns[1]:
                measures["steady_packets"] += 1
                measures["steady_ip_bytes"] += iplen
            records += 1
        matrix.require(records < PCAP_LIMIT, "WAN packet capture ceiling reached")
    return {
        s: [dict(slot=i, **dict(row)) for i, row in enumerate(rows)]
        for s, rows in counts.items()
    }


def neighbor_events(path, captured):
    """Validate one independent Ethernet/IPv4 ARP pcap and extract its wall-clock events."""
    matrix.require(0 <= captured < NEIGHBOR_LIMIT, "ARP observer capture ceiling reached")
    with path.open("rb") as stream:
        header = stream.read(24)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1_000), b"\xa1\xb2\xc3\xd4": (">", 1_000),
                   b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
        matrix.require(len(header) == 24 and header[:4] in formats, "invalid ARP pcap header")
        order, scale = formats[header[:4]]
        matrix.require(struct.unpack_from(order + "HH", header, 4) == (2, 4)
                       and struct.unpack_from(order + "II", header, 16) == (96, 1),
                       "expected snaplen-96 Ethernet ARP capture")
        events = []
        while record := stream.read(16):
            matrix.require(len(record) == 16 and len(events) < captured, "ARP pcap count/extent differs")
            sec, fraction, size, length = struct.unpack(order + "IIII", record)
            matrix.require(42 <= size <= 96 and size <= length and fraction * scale < 1_000_000_000,
                           "invalid ARP pcap record")
            frame = stream.read(size)
            matrix.require(len(frame) == size and frame[12:14] == b"\x08\x06"
                           and frame[14:20] == b"\x00\x01\x08\x00\x06\x04",
                           "expected full Ethernet/IPv4 ARP header")
            events.append(dict(wall_ns=sec * 1_000_000_000 + fraction * scale,
                               opcode=int.from_bytes(frame[20:22], "big"),
                               sender_ip=socket.inet_ntoa(frame[28:32]),
                               target_ip=socket.inet_ntoa(frame[38:42]),
                               sender_mac=frame[22:28].hex(":"), target_mac=frame[32:38].hex(":")))
        matrix.require(len(events) == captured, "ARP pcap and tcpdump counts differ")
        return events


def neighbor_snapshot(case, role, interface):
    begin = time.time_ns()
    entries = json.loads(case.command(role, "ip", "-j", "-4", "neigh", "show", "dev", interface))
    matrix.require(isinstance(entries, list), "expected owned IPv4 neighbor table")
    return dict(begin_wall_ns=begin, end_wall_ns=time.time_ns(), entries=entries)


def start_neighbor_captures(case, children):
    observations = case.value["neighbor_observers"] = {}
    for role, interface in NEIGHBOR_SURFACES:
        label = f"arp-{role}-{interface}"
        child = case.spawn(role, label, ["tcpdump", "-Z", "root", "--immediate-mode", "-p",
                          "-nn", "-s", "96", "-B", "256", "-i", interface, "-c",
                          str(NEIGHBOR_LIMIT), "-w", "-", "arp"], capture=case.output / (label + ".pcap"))
        children[label] = child
        case.wait_marker(child, "listening on", time.monotonic() + 8)
        pid = child["process"].pid
        namespace = case.spec.namespaces[role]
        inode = (Path("/proc") / str(pid) / "ns/net").stat().st_ino
        expected = (Path("/run/netns") / namespace).stat().st_ino
        matrix.require(inode == expected, "ARP observer outside owned namespace")
        observations[label] = dict(role=role, namespace=namespace, ns_inode=inode, interface=interface,
                                   filter="arp", snaplen=96, pid=pid, path=child["capture"].name,
                                   ready_wall_ns=time.time_ns())
        case.save()
    for info in observations.values():
        info["before_adapter"] = neighbor_snapshot(case, info["role"], info["interface"])
    case.save()


def finish_neighbor_captures(case, children):
    errors = []
    observations = case.value.get("neighbor_observers", {})
    for label, child in children.items():
        try:
            info = observations[label]
            counts = observe.capture_counters(child["log"])
            info["counters"] = counts
            info["sha256"] = matrix.file_hash(child["capture"])
            info["events"] = neighbor_events(child["capture"], counts["captured"])
            matrix.require(info.get("alive_after_workload") and child["process"].returncode == 0,
                           "ARP observer did not cover the full workload and stop cleanly")
            info["complete"] = True
        except (KeyError, OSError, ValueError, RuntimeError) as error:
            errors.append(f"{label}: {error}")
    if len(observations) != len(NEIGHBOR_SURFACES):
        errors.append("missing requested ARP observer")
    if errors:
        case.value["neighbor_capture_errors"] = errors
        if case.value["status"] in {"passed", "measured_with_outstanding_groups"}:
            case.value["status_without_neighbor_observation"] = case.value["status"]
            case.value["status"] = "incomplete"


def timestamp_counters(pid, expected_inode):
    """Read the selected endpoint namespace TCP timestamp counters without launching a probe."""
    root = Path("/proc") / str(pid)
    matrix.require(
        (root / "ns/net").stat().st_ino == expected_inode, "endpoint namespace changed"
    )
    fields = ("PAWSActive", "PAWSEstab", "PAWSOldAck", "TCPACKSkippedPAWS")
    before = time.monotonic_ns()
    lines = (root / "net/netstat").read_text().splitlines()
    for names, values in zip(lines[::2], lines[1::2]):
        labels, numbers = names.split(), values.split()
        if labels[0] == numbers[0] == "TcpExt:" and len(labels) == len(numbers):
            observed = dict(zip(labels[1:], numbers[1:]))
            return dict(
                begin_ns=before,
                end_ns=time.monotonic_ns(),
                counters={
                    name: int(observed[name]) if name in observed else None
                    for name in fields
                },
            )
    raise ValueError("missing namespace TCP extended counters")


def workload(case, adapters):
    phase = case.output / "probe"
    phase.mkdir()
    deadline = time.monotonic() + 59
    ns_deadline = time.monotonic_ns() + int((deadline - time.monotonic()) * 1e9)
    endpoints = []
    for side, action in (("b", "listen"), ("a", "connect")):
        child = case.spawn(
            "endpoint_" + side,
            "probe-" + side,
            [
                sys.executable,
                ROOT / "tools/common_native_probe.py",
                action,
                "--phase",
                "forward",
                "--address",
                matrix.NATIVE["b"],
                "--port",
                "24451",
                "--clock",
                phase / "clock.json",
                "--result",
                phase / (side + ".json"),
                "--deadline-ns",
                str(ns_deadline),
                "--single-flow-4m",
            ],
        )
        endpoints.append(child)
        case.wait_marker(
            child, "Listening" if action == "listen" else "Connected", deadline
        )
    case.wait_marker(endpoints[0], "Connected", deadline)
    before, wall, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
    offset = wall - (before + after) // 2
    start = after + 500_000_000
    clock = dict(
        start_ns=start,
        measure_start_ns=start + 2_000_000_000,
        end_ns=start + 12_000_000_000,
    )
    scope = (clock["measure_start_ns"] + offset, clock["end_ns"] + offset)
    case.value["sample_wall_ns"] = scope
    case.value["clock_anchor"] = dict(
        monotonic_before_ns=before, wall_ns=wall, monotonic_after_ns=after
    )
    case.value["cpu"] = []
    case.save()
    matrix.atomic_json(phase / "clock.json", clock)
    next_cpu = 0
    sampled = []
    if case.value["request"]["trace"]:
        case.value["tcp_timestamp_counter_edges"] = sampled
    targets = (clock["measure_start_ns"], clock["end_ns"])
    while any(p["process"].poll() is None for p in endpoints):
        case.check(deadline)
        for side, child in adapters.items():
            matrix.require(
                child["process"].poll() is None, f"adapter {side} exited during probe"
            )
        if (
            case.value["request"]["trace"]
            and len(sampled) < len(targets)
            and time.monotonic_ns() >= targets[len(sampled)]
        ):
            edge = {"target_ns": targets[len(sampled)]}
            for side, adapter in adapters.items():
                edge[side] = timestamp_counters(
                    adapter["process"].pid,
                    case.value["adapter_pid_ns"][side]["expected_inode"],
                )
            sampled.append(edge)
        if time.monotonic() >= next_cpu:
            case.value["cpu"].append(
                observe.cpu_snapshot(
                    [(p["label"], p["process"]) for p in case.children]
                )
            )
            next_cpu = time.monotonic() + 0.5
        time.sleep(0.025)
    if case.value["request"]["trace"]:
        matrix.require(len(sampled) == 2, "missing TCP timestamp counter edges")
        case.value["tcp_timestamp_counter_delta"] = {
            side: {
                key: (
                    sampled[1][side]["counters"][key] - old
                    if old is not None and sampled[1][side]["counters"][key] is not None
                    else None
                )
                for key, old in sampled[0][side]["counters"].items()
            }
            for side in "ab"
        }
    results = [
        matrix.read_json(phase / (s + ".json"), matrix.BOUNDS["log_bytes"])
        for s in "ab"
    ]
    for result, child in zip(reversed(results), endpoints):
        matrix.require(
            result.get("status") == "passed" and child["process"].returncode == 0,
            f"native probe {child['label']}: {result.get('status')} {result.get('error', '')}",
        )
    case.value["throughput"] = matrix.compare_probes(
        *results, "forward", paced=True, single_flow=True
    )
    case.value["flow_identity"] = [j["flow_identity"] for j in results]
    case.value["single_flow_credit"] = results[0]["single_flow"]
    case.save()


def wait_for_authenticated_paths(case, adapters):
    """Each local marker attests that all its own fresh path challenges were answered."""
    gate = case.value["authenticated_path_gate"] = {
        "scope": "preprovisioned session key possession and bidirectional UDP path liveness",
        "wait_started_wall_ns": time.time_ns(), "observed": {},
    }
    case.value["stage"] = "awaiting_authenticated_paths"
    case.save()
    deadline = time.monotonic() + 6
    for side in "ab":
        case.wait_marker(adapters[side], "AUTHENTICATED_PATH_READY", deadline)
        gate["observed"][side] = dict(pid=adapters[side]["process"].pid, observed_wall_ns=time.time_ns())
        case.save()
    matrix.require(all(c["process"].poll() is None for c in adapters.values()),
                   "adapter exited before both authenticated path markers")
    gate["both_observed_wall_ns"] = time.time_ns()
    case.save()


def adapter_policy_args(plan, side):
    flags = (
        "low_load_forward_round", "authenticated_path_ready", "path_arq", "fair_members",
        "physical_rank_suppression", "pace_original_frontiers", "ordered_native", "ordered_tcp_data",
        "transfer_named_path_debt",
    )
    args = ["--" + flag.replace("_", "-") for flag in flags if plan.get(flag, False)]
    if plan["paced_recovery"]:
        args.extend(("--paced-recovery", "--wire-rate-bps", str(plan["wire_rate_bps"][side])))
        if plan["pacing_burst_frames"] > 1:
            args.extend(("--pacing-burst-frames", str(plan["pacing_burst_frames"])))
    for name in ("pacing_timer_slack_ns", "trace_scheduler_groups"):
        if plan.get(name) is not None:
            args.extend(("--" + name.replace("_", "-"), str(plan[name])))
    return args


def validate_timer_slack(stats, selected):
    observed = stats.get("timer_slack")
    if observed is None and selected is None:
        return  # Historical adapters did not expose this Linux thread setting.
    matrix.require(isinstance(observed, dict) and observed.get("requested_ns") == selected,
                   "requested timer slack is not observable")
    matrix.require(all(type(observed.get(k)) is int and observed[k] > 0
                       for k in ("before_ns", "effective_ns")), "invalid timer slack readback")
    matrix.require(observed["effective_ns"] == (selected if selected is not None else observed["before_ns"]),
                   "effective timer slack differs from selection")


def validate_named_transfer(stats, selected):
    matrix.require(stats["config"].get("transfer_named_path_debt", False) is selected,
                   "requested and effective named path debt transfer differ")
    count = stats.get("path_debts_transferred_to_named", 0)
    matrix.require(type(count) is int and count >= 0 and (selected or count == 0),
                   "invalid named path debt transfer count")
    matrix.require(not selected or "path_debts_transferred_to_named" in stats,
                   "missing named path debt transfer counter")


def validate_low_load_round(stats, side, selected, paths):
    """Check actual socket payments against the bounded per-direction startup policy."""
    matrix.require(stats["config"].get("low_load_forward_round", False) is selected,
                   f"{side}: requested and effective low-load forward round differ")
    entries = 0
    for path in stats["paths"]:
        names = ("low_load_round_packets", "low_load_round_entries", "low_load_round_ip_bytes")
        if selected:
            matrix.require(all(name in path for name in names), f"{side}: missing low-load payment counters")
        packets, count, ip_bytes = (path.get(name, 0) for name in names)
        matrix.require(all(type(value) is int and value >= 0 for value in (packets, count, ip_bytes)),
                       f"{side}: invalid low-load payment counter")
        matrix.require(packets <= count and bool(packets) == bool(count) == bool(ip_bytes),
                       f"{side}: inconsistent low-load payments")
        if packets:
            matrix.require(selected and packets <= path["paid_packets"] and ip_bytes <= path["paid_ip_bytes"],
                           f"{side}: low-load payments exceed the full socket ledger")
        entries += count
    matrix.require(entries <= 128 * paths, f"{side}: extra members exceed the per-direction startup allowance")


def validate_path_ready(stats, paths):
    status = stats.get("authenticated_path_ready") or {}
    matrix.require(status.get("ready") is True and len(status.get("paths", [])) == paths,
                   "missing authenticated path proofs")
    matrix.require(stats["totals"]["authenticated_other_packets_before_path_ready"] == 0,
                   "unexpected non-readiness traffic before the controlled workload")
    for slot, (proof, wire) in enumerate(zip(status["paths"], stats["paths"])):
        requests, echoes = wire["path_ready_requests_paid"], wire["path_ready_echoes_paid"]
        packets = requests + echoes
        expected_ip = packets * (stats["config"]["outer_ipv4_bytes"] + 18)
        matrix.require(proof["slot"] == wire["slot"] == slot and proof["ready_at_us"] is not None
                       and requests == proof["requests_paid"] > 0 and echoes == proof["echoes_paid"] > 0
                       and wire["path_ready_ip_bytes"] == expected_ip
                       and wire["path_ready_ethernet_bytes"] == expected_ip + 14 * packets
                       and expected_ip <= wire["paid_ip_bytes"], "path proof or real socket cost differs")


def tun_case_row(paths, threshold):
    return {"id": f"path-bundle-{paths}-{threshold}-single",
            "required_cli": {side: ["--layer", "tun"] for side in ("a", "b")}}


def run(binary, output, study_lock, plan):
    paths = plan["physical_udp_paths"]
    threshold = plan["coding_threshold"]
    matrix.require(
        os.geteuid() == 0, "--apply requires root only for the owned network namespaces"
    )
    matrix.require(
        binary.is_file() and os.access(binary, os.X_OK),
        "built release example is required",
    )
    matrix.require(
        os.path.ismount("/proc") and Path("/dev/net/tun").exists(),
        "local TUN or proc unavailable",
    )
    matrix.require(
        shutil.disk_usage(output.parent).free
        > (1024 if plan["trace"] else 512) * 1024**2,
        "capture and diagnostic disk capacity unavailable",
    )
    optional_lock = study_lock.open("rb") if study_lock else contextlib.nullcontext()
    with optional_lock as lock, matrix.exclusive_lab():
        if lock is not None:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output.mkdir(mode=0o755)
        spec = matrix.lab.LabSpec(f"p{paths}k{threshold}-" + uuid.uuid4().hex[:10])
        case = matrix.Case(
            tun_case_row(paths, threshold),
            spec,
            output,
            native_tun_txqueuelen=PLAN["tun_txqueuelen"],
            native_forward_tun_maxrate_mbit=PLAN["forward_tun_fq_maxrate_mbps"],
        )
        case.value.update(
            request=plan,
            binary_sha256=matrix.file_hash(binary),
            binary=str(binary),
            harness_sha256=matrix.file_hash(Path(__file__)),
            probe_sha256=matrix.file_hash(ROOT / "tools/common_native_probe.py"),
            free_disk_before=shutil.disk_usage(output).free,
            lock_file=str(study_lock) if study_lock else None,
            namespace_id=spec.lab_id,
        )
        state = Path("/run") / ("l2tunnel-" + spec.lab_id)
        state.mkdir(mode=0o700)
        key = state / "key"
        captures, adapters, neighbors, underlay = {}, {}, {}, {}

        def interrupted(signum, frame):
            raise KeyboardInterrupt(f"signal {signum}")

        old_signals = {
            s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGINT)
        }
        try:
            with os.fdopen(
                os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as f:
                f.write(os.urandom(32))
            case.value["stage"] = "owned_topology"
            matrix.topology(case, state)
            path_links.configure(case, SEEDS, plan["loss_after_shaper"])
            if plan.get("observe_underlay", False):
                underlay_observe.start_captures(case, underlay)
            for side in "ab":
                role = "endpoint_" + side
                surfaces = [("wan", "wan0", "udp", matrix.WAN)]
                if plan["trace"]:
                    surfaces.append(("native", "tun0", "tcp", matrix.NATIVE))
                for kind, interface, protocol, addresses in surfaces:
                    pcap = output / f"{side}-{kind}.pcap"
                    child = case.spawn(
                        role,
                        f"{kind}-{side}",
                        [
                            "tcpdump",
                            "-Z",
                            "root",
                            "--immediate-mode",
                            "-n",
                            "-s",
                            "96",
                            "-B",
                            "8192",
                            "-i",
                            interface,
                            "-c",
                            str(PCAP_LIMIT),
                            "-w",
                            "-",
                            "ip",
                            "and",
                            protocol,
                            "and",
                            "host",
                            addresses["a"],
                            "and",
                            "host",
                            addresses["b"],
                        ],
                        capture=pcap,
                    )
                    captures[side, kind] = child
                    case.wait_marker(child, "listening on", time.monotonic() + 8)
            if plan.get("capture_neighbor_events", False):
                case.value["stage"] = "starting_neighbor_observers"
                start_neighbor_captures(case, neighbors)
            case.value["stage"] = "established_adapter_startup"
            for side in "ba":
                peer = "a" if side == "b" else "b"
                role = "endpoint_" + side
                args = [
                    binary,
                    "--role",
                    "client" if side == "a" else "server",
                    "--netns",
                    spec.namespaces[role],
                    "--tun",
                    "tun0",
                    "--local-ip",
                    matrix.WAN[side],
                    "--peer-ip",
                    matrix.WAN[peer],
                    "--local-port",
                    str(BASE_PORT[side]),
                    "--peer-port",
                    str(BASE_PORT[peer]),
                    "--key-file",
                    key,
                    "--paths",
                    str(paths),
                    "--threshold",
                    str(threshold),
                    "--a3-request-copies",
                    str(plan["a3_request_copies"]),
                    "--a3-reply-copies",
                    str(plan["a3_reply_copies"]),
                    "--mtu",
                    str(plan["outer_ipv4_mtu"]),
                    "--hold-us",
                    str(HOLD_US),
                    "--stats",
                    output / (side + "-stats.json"),
                ]
                args.extend(adapter_policy_args(plan, side))
                if plan["trace"]:
                    args += ["--trace", output / f"{side}-trace.csv"]
                child = case.spawn(role, "adapter-" + side, args)
                adapters[side] = child
                case.wait_marker(child, "READY", time.monotonic() + 10)
                case.value.setdefault("adapter_pid_ns", {})[side] = {
                    "pid": child["process"].pid,
                    "ns_inode": os.stat(f"/proc/{child['process'].pid}/ns/net").st_ino,
                    "expected_inode": os.stat(
                        Path("/run/netns") / spec.namespaces[role]
                    ).st_ino,
                }
                one = case.value["adapter_pid_ns"][side]
                matrix.require(
                    one["ns_inode"] == one["expected_inode"],
                    "adapter outside its owned endpoint",
                )
            if plan.get("authenticated_path_ready", False):
                wait_for_authenticated_paths(case, adapters)
            if plan.get("observe_underlay", False):
                underlay_observe.start_sampler(case, underlay, adapters)
            case.value["stage"] = "single_tcp_measurement"
            case.save()
            workload(case, adapters)
            # The adapter reports custody at graceful exit. Give the same four-second
            # post-EOF interval as the earlier Linux arm; this is a final snapshot,
            # not the earlier service's two-sample drain instrumentation.
            case.value["post_eof_grace_seconds"] = 4
            until = time.monotonic() + 4
            while time.monotonic() < until:
                case.check()
                matrix.require(
                    all(c["process"].poll() is None for c in adapters.values()),
                    "adapter exited before drain snapshot",
                )
                time.sleep(0.05)
            case.value["qdisc_after"] = path_links.snapshot(case, plan["loss_after_shaper"])
            if plan.get("observe_underlay", False):
                matrix.require(underlay_observe.finish(case, underlay),
                               "requested underlay observation is incomplete")
            for label, child in neighbors.items():
                info = case.value["neighbor_observers"][label]
                info["after_workload"] = neighbor_snapshot(case, info["role"], info["interface"])
                info["alive_after_workload"] = child["process"].poll() is None
            case.value["status"] = "measured"
        except BaseException as error:
            case.value.update(status="failed", error=f"{type(error).__name__}: {error}")
        finally:
            # All process groups were created in this case. Recovery can use the journal
            # if removing any particular namespace fails its identity/empty-PID checks.
            for s in old_signals:
                signal.signal(s, signal.SIG_IGN)
            deadline = time.monotonic() + 30
            errors = []
            for child in reversed(case.children):
                try:
                    case.stop(
                        child,
                        signal.SIGINT if child.get("capture") else signal.SIGTERM,
                        deadline=deadline,
                    )
                except Exception as error:
                    errors.append(f"{child['label']}: {error}")
            journal = state / (spec.lab_id + ".json")
            try:
                if journal.exists():
                    matrix.bounded.bounded_lab(
                        matrix.lab.cleanup, spec, state, deadline
                    )
                matrix.require(
                    all(
                        not (Path("/run/netns") / v).exists()
                        for v in spec.namespaces.values()
                    ),
                    "owned namespace still present",
                )
                case.value["namespace_cleanup"] = "verified_absent"
            except Exception as error:
                errors.append(
                    f"namespace cleanup: {error}; recovery journal: {journal}"
                )
            key.unlink(missing_ok=True)
            for role in ("client", "server"):
                key.with_name(key.name + "." + role + ".used").unlink(missing_ok=True)
            if not journal.exists():
                (state / (spec.lab_id + ".lock")).unlink(missing_ok=True)
                with contextlib.suppress(OSError):
                    state.rmdir()
            if errors:
                case.value.update(status="cleanup_failed", cleanup_errors=errors)
            case.value["free_disk_after"] = shutil.disk_usage(output).free
            for s, previous in old_signals.items():
                signal.signal(s, previous)
            case.save()
        try:
            for (side, kind), child in captures.items():
                if kind == "native":
                    counts = observe.capture_counters(child["log"])
                    matrix.require(
                        (counts["captured"] > 0 or case.value["stage"] == "awaiting_authenticated_paths")
                        and counts["captured"] < PCAP_LIMIT and counts["dropped"] == 0,
                        "native capture incomplete",
                    )
                    case.value.setdefault("native_capture", {})[side] = dict(
                        path=child["capture"].name,
                        sha256=matrix.file_hash(child["capture"]),
                        counters=counts,
                        snaplen=96,
                    )
                    continue
                rows = wan_capture(
                    child["capture"], case.value.get("sample_wall_ns"), paths
                )
                case.value.setdefault("wire", {})[side] = dict(
                    tuples=rows,
                    sha256=matrix.file_hash(child["capture"]),
                    capture_counters=observe.capture_counters(child["log"]),
                )
            for side in adapters:
                stats_path = output / (side + "-stats.json")
                if stats_path.is_file():
                    stats = matrix.read_json(stats_path, matrix.BOUNDS["log_bytes"])
                    case.value.setdefault("adapter_stats", {})[side] = stats
                if plan["trace"]:
                    trace = output / f"{side}-trace.csv"
                    matrix.require(
                        trace.is_file() and trace.stat().st_size > 0,
                        f"missing endpoint {side} trace",
                    )
                    case.value.setdefault("adapter_trace", {})[side] = dict(
                        path=trace.name,
                        sha256=matrix.file_hash(trace),
                        bytes=trace.stat().st_size,
                    )
            if case.value["status"] == "measured":
                for side in "ab":
                    matrix.require(
                        len(case.value["adapter_stats"][side]["paths"]) == paths,
                        "missing physical path stats",
                    )
                    effective = case.value["adapter_stats"][side]["config"]
                    validate_timer_slack(case.value["adapter_stats"][side],
                                         plan.get("pacing_timer_slack_ns"))
                    validate_named_transfer(case.value["adapter_stats"][side],
                                            plan.get("transfer_named_path_debt", False))
                    validate_low_load_round(case.value["adapter_stats"][side], side,
                                            plan.get("low_load_forward_round", False), paths)
                    selected = plan.get("authenticated_path_ready", False)
                    matrix.require(effective.get("authenticated_path_ready", False) is selected,
                                   "requested and effective authenticated path gate differ")
                    if selected:
                        validate_path_ready(case.value["adapter_stats"][side], paths)
                    matrix.require(
                        (
                            effective["paths"],
                            effective["threshold"],
                            effective["mtu"],
                            effective["hold_us"],
                            effective["a3_request_copies"],
                            effective["a3_reply_copies"],
                        )
                        == (
                            paths,
                            threshold,
                            plan["native_mtu"],
                            HOLD_US,
                            plan["a3_request_copies"],
                            plan["a3_reply_copies"],
                        ),
                        "effective adapter geometry differs",
                    )
                    matrix.require(
                        effective["path_arq"] is plan["path_arq"],
                        "effective path ARQ state differs",
                    )
                    matrix.require(
                        effective["fair_members"] is plan["fair_members"],
                        "effective member scheduling state differs",
                    )
                    matrix.require(effective.get("physical_rank_suppression", False) is plan["physical_rank_suppression"],
                                   "effective physical rank suppression differs")
                    matrix.require(effective.get("pace_original_frontiers", False) is plan["pace_original_frontiers"],
                                   "effective original frontier pacing differs")
                    matrix.require(effective["ordered_native"] is plan["ordered_native"],
                                   "effective native handoff ordering differs")
                    matrix.require(effective.get("ordered_tcp_data", False) is plan["ordered_tcp_data"],
                                   "effective TCP data ordering differs")
                    matrix.require(effective["paced_recovery"] is plan["paced_recovery"],
                                   "effective paced recovery state differs")
                    if plan["paced_recovery"]:
                        matrix.require(effective["wire_rate_bps"] == plan["wire_rate_bps"][side],
                                       "effective shared pacing rate differs")
                        matrix.require(effective["pacing_burst_ethernet_bytes"] == plan["pacing_burst_ethernet_bytes"],
                                       "effective shared pacing burst bytes differ")
                        # Prior one-frame endpoints reported only capacity. A larger
                        # selection always requires explicit effective settings.
                        if plan["pacing_burst_frames"] > 1 or "pacing_burst_frames" in effective:
                            matrix.require(
                                (effective["pacing_burst_frames"], effective["pacing_initial_ethernet_bytes"])
                                == (plan["pacing_burst_frames"], plan["pacing_initial_ethernet_bytes"]),
                                "effective shared pacing frames or initial credit differ",
                            )
                    if plan["path_arq"]:
                        matrix.require(
                            (
                                effective["path_arq_window"],
                                effective["path_arq_later_packets"],
                                effective["path_arq_rto_us"],
                            )
                            == (256, 3, 90000),
                            "effective path ARQ bounds differ",
                        )
                    cap = case.value["wire"][side]
                    matrix.require(
                        cap["capture_counters"]["dropped"] == 0,
                        "WAN capture dropped packets",
                    )
                    matrix.require(
                        cap["capture_counters"]["captured"]
                        == sum(
                            row.get("packets", 0)
                            for values in cap["tuples"].values()
                            for row in values
                        ),
                        "WAN records differ from tcpdump count",
                    )
                    for direction in "ab":
                        matrix.require(
                            all(
                                r.get("steady_packets", 0) > 0
                                for r in case.value["wire"][side]["tuples"][direction]
                            ),
                            "a negotiated UDP tuple was idle during the measured window",
                        )
                matrix.require(
                    matrix.file_hash(binary) == case.value["binary_sha256"],
                    "binary changed during measurement",
                )
                drain = {}
                for side, child in adapters.items():
                    metrics = case.value["adapter_stats"][side]
                    matrix.require(
                        child["process"].returncode == 0,
                        f"adapter {side} did not stop cleanly",
                    )
                    drain[side] = {
                        k: metrics[k]
                        for k in (
                            "oldest_unconfirmed",
                            "next_generation",
                            "confirmed_prefix",
                            "retained_sender_groups",
                            "retained_rx_groups",
                        )
                    }
                case.value["final_group_custody"] = drain
                case.value["status"] = (
                    "passed"
                    if all(
                        r["retained_sender_groups"] == r["retained_rx_groups"] == 0
                        for r in drain.values()
                    )
                    else "measured_with_outstanding_groups"
                )
        except Exception as error:
            case.value["analysis_error"] = f"{type(error).__name__}: {error}"
            if case.value["status"] == "measured":
                case.value["status"] = "incomplete"
        if plan.get("capture_neighbor_events", False):
            finish_neighbor_captures(case, neighbors)
        case.value["finished_wall_ns"] = time.time_ns()
        case.save()
        print(
            json.dumps(
                {"status": case.value["status"], "receipt": str(output / "result.json")}
            ),
            flush=True,
        )
        return int(case.value["status"] != "passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--low-load-forward-round", action="store_true",
                        help="allow one further round of original forward shards during idle startup credit")
    parser.add_argument("--transfer-named-path-debt", action="store_true",
                        help="let a live paid named repair own stale unfrozen path debt; requires path ARQ, fair members and rank suppression")
    parser.add_argument("--authenticated-path-ready", action="store_true",
                        help="require an authenticated challenge/echo on every selected UDP path at both ends before TCP")
    parser.add_argument("--capture-neighbor-events", action="store_true",
                        help="passively capture IPv4 ARP on each owned underlay link endpoint before adapter startup")
    parser.add_argument("--observe-underlay", action="store_true",
                        help="capture owned router UDP taps and bounded queue/scheduler samples; requires --loss-after-shaper")
    parser.add_argument("--pacing-timer-slack-ns", type=int,
                        help="explicit Linux adapter-thread timer slack; requires paced recovery, defaults unchanged")
    parser.add_argument("--trace-scheduler-groups",
                        help="trace up to 128 admitted groups as FIRST:END; requires trace, paced recovery and fair members")
    parser.add_argument(
        "--trace",
        action="store_true",
        help="record bounded endpoint events and native TCP packet headers",
    )
    parser.add_argument(
        "--binary", type=Path, default=ROOT / "target/release/examples/path-bundle-lab"
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--study-lock", type=Path, help="also serialize with an existing study lock"
    )
    parser.add_argument(
        "--path-arq",
        action="store_true",
        help="enable ACK-driven recovery of each physical path in the lab endpoint",
    )
    parser.add_argument("--paths", type=int, default=6)
    parser.add_argument("--pace-original-frontiers", action="store_true",
                        help="prefer overdue original groups on lagging paths within the shared DATA budget")
    parser.add_argument("--physical-rank-suppression", action="store_true",
                        help="suppress redundant repair debt after sufficient physical shard receipts; requires path ARQ and fair members")
    delivery = parser.add_mutually_exclusive_group()
    delivery.add_argument("--ordered-native", action="store_true",
                          help="Deliver complete native groups in global sequence in this single-flow lab.")
    delivery.add_argument("--ordered-tcp-data", action="store_true",
                          help="Keep native group order and allow validated pure TCP ACKs through gaps.")
    parser.add_argument("--paced-recovery", action="store_true",
                        help="share the measured direction's L2 wire budget and enable bounded feedback/RTT recovery")
    parser.add_argument("--pacing-burst-frames", type=int, choices=range(1, 9),
                        help="shared earned credit capacity in MTU-sized Ethernet frames (paced default 1)")
    parser.add_argument("--loss-after-shaper", action="store_true",
                        help="move delay/loss to the owned router after endpoint shaping; preserve historical topology otherwise")
    parser.add_argument(
        "--fair-members",
        action="store_true",
        help="share pending member custody and rotate fresh, path retry and named work",
    )
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--a3-request-copies", type=int, default=1)
    parser.add_argument("--a3-reply-copies", type=int, default=1)
    options = parser.parse_args()
    if options.pacing_timer_slack_ns is not None and not (
        options.paced_recovery and 0 < options.pacing_timer_slack_ns < 2**64
    ):
        parser.error("--pacing-timer-slack-ns requires --paced-recovery and a positive u64")
    if options.trace_scheduler_groups is not None:
        try:
            first, end = (int(x) for x in options.trace_scheduler_groups.split(":"))
        except ValueError:
            parser.error("scheduler range must be FIRST:END")
        if not (0 <= first < end < 2**64 and end - first <= 128
                and options.trace and options.paced_recovery and options.fair_members):
            parser.error("scheduler trace requires 1..128 groups, --trace, --paced-recovery and --fair-members")
    if options.transfer_named_path_debt and not (
        options.path_arq and options.fair_members and options.physical_rank_suppression
    ):
        parser.error("--transfer-named-path-debt requires --path-arq, --fair-members and --physical-rank-suppression")
    if options.observe_underlay and not options.loss_after_shaper:
        parser.error("--observe-underlay requires --loss-after-shaper")
    if options.low_load_forward_round and not (
        options.paced_recovery and options.fair_members and options.path_arq and options.physical_rank_suppression
    ):
        parser.error("--low-load-forward-round requires --paced-recovery, --fair-members, --path-arq and --physical-rank-suppression")
    if options.authenticated_path_ready and not options.paced_recovery:
        parser.error("--authenticated-path-ready requires --paced-recovery")
    if options.pace_original_frontiers and not (options.paced_recovery and options.fair_members):
        parser.error("--pace-original-frontiers requires --paced-recovery and --fair-members")
    if options.physical_rank_suppression and not (options.path_arq and options.fair_members):
        parser.error("--physical-rank-suppression requires --path-arq and --fair-members")
    if options.pacing_burst_frames is not None and not options.paced_recovery:
        parser.error("--pacing-burst-frames requires --paced-recovery")
    burst = (options.pacing_burst_frames or 1) if options.paced_recovery else None
    if not 1 <= options.threshold <= options.paths <= 255:
        parser.error("require 1 <= threshold <= paths <= 255")
    if (
        not 1 <= options.a3_request_copies <= options.paths
        or not 1 <= options.a3_reply_copies <= options.paths
    ):
        parser.error("require both A3 copy counts in 1..paths")
    plan = {
        **PLAN,
        "trace": options.trace,
        "capture_neighbor_events": options.capture_neighbor_events,
        "observe_underlay": options.observe_underlay,
        "pacing_timer_slack_ns": options.pacing_timer_slack_ns,
        "trace_scheduler_groups": options.trace_scheduler_groups,
        "authenticated_path_ready": options.authenticated_path_ready,
        "low_load_forward_round": options.low_load_forward_round,
        "transfer_named_path_debt": options.transfer_named_path_debt,
        "path_arq": options.path_arq,
        "fair_members": options.fair_members,
        "physical_rank_suppression": options.physical_rank_suppression,
        "pace_original_frontiers": options.pace_original_frontiers,
        "ordered_native": options.ordered_native,
        "ordered_tcp_data": options.ordered_tcp_data,
        "paced_recovery": options.paced_recovery,
        "outer_ipv4_mtu": OUTER_MTU,
        "pacing_burst_frames": burst,
        "pacing_initial_ethernet_bytes": OUTER_MTU + 14 if burst is not None else None,
        "pacing_burst_ethernet_bytes": burst * (OUTER_MTU + 14) if burst is not None else None,
        "loss_after_shaper": options.loss_after_shaper,
        "wire_rate_bps": {"a": 100_000_000, "b": 10_000_000},
        "a3_request_copies": options.a3_request_copies,
        "a3_reply_copies": options.a3_reply_copies,
        "physical_udp_paths": options.paths,
        "coding_threshold": options.threshold,
    }
    if not options.apply:
        print(json.dumps(plan, indent=2))
        return 0
    if options.output is None:
        parser.error("a new result directory is required with --apply")
    return run(
        options.binary.resolve(), options.output.absolute(), options.study_lock, plan
    )


if __name__ == "__main__":
    raise SystemExit(main())
