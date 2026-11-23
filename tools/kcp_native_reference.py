#!/usr/bin/env python3
"""Pinned C KCP benchmark on an owned TAP pair. Run is a dry run unless --apply is given."""

import argparse
from collections import Counter, defaultdict, namedtuple
import csv
from contextlib import suppress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import common_native_matrix as matrix
import path_bundle_netns_lab as bundle

VENDOR = TOOLS.parent / "simulator/src/l2tunnel_sim/_vendor/kcp"
SOURCE = TOOLS / "kcp_native_reference.c"
SEEDS = {"a": 31248, "b": 31248 ^ 0x9E3779B97F4A7C15}
DEBT = (
    "encoder_credit",
    "waitsnd",
    "rcv_queue",
    "rcv_buf",
    "pending_tap_frame",
    "pending_ack_segments",
)
# Present only in the "extensions" stats object of an endpoint run with any
# optional benchmark parameter: frames still in the native ingress ring and
# partial stream bodies are undelivered debt.
EXTENSION_DEBT = ("native_queue_frames", "stream_reassembly_bytes")

# Optional parameters. These defaults reproduce the original unpaced,
# message-mode endpoint and the shared single-flow probe exactly.
DEFAULTS = dict(
    window=8192,
    nocwnd=1,
    stream=False,
    pace_forward_mbit=None,
    pace_reverse_mbit=None,
    pace_burst_ms=2.0,
    pace_reserve="queued",
    native_queue_frames=0,
    flush_interval_us=0,
    max_wait_us=None,
    udp_buffer_bytes=None,
    sample_interval_ms=0,
    inner_rto_min_ms=None,
    udp_snmp_counters=False,
    loss_percent=15,
    workload="single-flow-4m",
    warmup_s=2,
    steady_s=10,
    max_bytes=None,
    workload_seconds=59,
    # secure_udp_native_probe.py tcp limits; None keeps that probe's defaults
    # (96 samples, 60 s deadline, 30 s maximum measurement).
    probe_max_samples=None,
    probe_deadline_seconds=None,
    probe_max_measure_seconds=None,
)
# Settings of the selected paced KCP/TAP benchmark previously kept as the
# campaign copy work/kcp-tap-optimized-20261121/buffered/{adapter.c,run.py}:
# framed stream, 95/9.5 Mbit/s admission pacing with a 2 ms bucket and
# queued-segment reservation, a 4096-frame native ingress ring, an explicit
# flush about every 1 ms, 100 us poll wakeups, 4 MiB UDP socket buffers,
# per-second adapter samples, UDP SNMP counters and one CUBIC flow measured by
# secure_udp_native_probe.py with 10 s warmup, 60 s measurement, 1 GiB cap and
# a 230 s case lifetime.
PRESETS = {
    "optimized-20261121": dict(
        stream=True,
        pace_forward_mbit=95.0,
        pace_reverse_mbit=9.5,
        native_queue_frames=4096,
        flush_interval_us=1000,
        max_wait_us=100,
        udp_buffer_bytes=4 * 1024 * 1024,
        sample_interval_ms=1000,
        udp_snmp_counters=True,
        workload="secure-forward16",
        warmup_s=10,
        steady_s=60,
        max_bytes=1024**3,
        workload_seconds=230,
        probe_max_samples=512,
        probe_deadline_seconds=180,
        probe_max_measure_seconds=90,
    ),
}
WORKLOADS = ("single-flow-4m", "secure-forward16")
PROBE_LIMITS = {"probe_max_samples": "--max-samples", "probe_deadline_seconds": "--deadline-seconds",
                "probe_max_measure_seconds": "--max-measure-seconds"}


def probe_limit_args(options):
    return [arg for key, flag in PROBE_LIMITS.items() if options[key] is not None
            for arg in (flag, str(options[key]))]


def resolve_options(preset=None, **overrides):
    """Merge DEFAULTS, an optional preset and explicit (non-None) overrides, then validate."""
    options = dict(DEFAULTS)
    if preset is not None:
        matrix.require(preset in PRESETS, "unknown KCP benchmark preset")
        options.update(PRESETS[preset])
    unknown = set(overrides) - set(DEFAULTS)
    matrix.require(not unknown, f"unknown KCP benchmark options: {sorted(unknown)}")
    options.update({k: v for k, v in overrides.items() if v is not None})
    o = options
    matrix.require(128 <= o["window"] <= 16384 and o["nocwnd"] in (0, 1), "KCP window/nocwnd outside 128..16384 / 0..1")
    for key in ("pace_forward_mbit", "pace_reverse_mbit"):
        matrix.require(o[key] is None or 0.001 <= o[key] <= 100000, f"{key} outside 0.001..100000")
    matrix.require(0.1 <= o["pace_burst_ms"] <= 1000 and o["pace_reserve"] in ("queued", "fixed"),
                   "pace burst/reserve invalid")
    matrix.require(0 <= o["native_queue_frames"] <= 65536, "native queue outside 0..65536 frames")
    matrix.require(o["flush_interval_us"] == 0 or 100 <= o["flush_interval_us"] <= 1000000, "flush interval invalid")
    matrix.require(o["max_wait_us"] is None or 0 <= o["max_wait_us"] <= 1000000, "max wait invalid")
    matrix.require(o["udp_buffer_bytes"] is None or 4096 <= o["udp_buffer_bytes"] <= 256 * 1024**2,
                   "UDP buffer request invalid")
    matrix.require(o["sample_interval_ms"] == 0 or 10 <= o["sample_interval_ms"] <= 60000, "sample interval invalid")
    matrix.require(o["inner_rto_min_ms"] is None or 1 <= o["inner_rto_min_ms"] <= 120000, "inner rto_min invalid")
    matrix.require(type(o["loss_percent"]) is int and 0 <= o["loss_percent"] <= 100, "loss percent outside 0..100")
    matrix.require(o["workload"] in WORKLOADS, "unknown workload")
    if o["workload"] == "single-flow-4m":
        # common_native_probe.py fixes its shared clock and 60 s deadline.
        matrix.require((o["warmup_s"], o["steady_s"], o["workload_seconds"]) == (2, 10, 59)
                       and o["max_bytes"] is None and all(o[k] is None for k in PROBE_LIMITS),
                       "single-flow-4m fixes 2 s warmup, 10 s sample, 59 s workload and its own byte cap")
    else:
        matrix.require(0 < o["warmup_s"] and 0 < o["steady_s"]
                       and o["warmup_s"] + o["steady_s"] + 2 < o["workload_seconds"]
                       <= matrix.BOUNDS["case_seconds"] - 40,
                       "secure workload windows must fit its workload lifetime inside the case bound")
        matrix.require(o["max_bytes"] is None or o["max_bytes"] > 0, "max bytes must be positive")
        matrix.require(all(o[k] is None or (type(o[k]) is int and o[k] > 0) for k in PROBE_LIMITS),
                       "probe limits must be positive integers")
        deadline = o["probe_deadline_seconds"] or 60
        measure = o["probe_max_measure_seconds"] or 30
        matrix.require(o["steady_s"] <= measure and o["warmup_s"] <= 10 and o["warmup_s"] + o["steady_s"] + 2 < deadline,
                       "secure probe limits (deadline, maximum measurement, 10 s warmup) do not admit these windows")
    return options


def adapter_args(options, side):
    """Optional C endpoint arguments; empty for the defaults."""
    o, args = options, []
    if o["window"] != DEFAULTS["window"]:
        args += ["--window", str(o["window"])]
    if o["nocwnd"] != DEFAULTS["nocwnd"]:
        args += ["--nocwnd", str(o["nocwnd"])]
    if o["stream"]:
        args.append("--stream")
    rate = o["pace_forward_mbit" if side == "a" else "pace_reverse_mbit"]
    if rate is not None:
        args += ["--pace-mbit", repr(float(rate)), "--pace-burst-ms", repr(float(o["pace_burst_ms"])),
                 "--pace-reserve", o["pace_reserve"]]
    if o["native_queue_frames"]:
        args += ["--native-queue", str(o["native_queue_frames"])]
    if o["flush_interval_us"]:
        args += ["--flush-us", str(o["flush_interval_us"])]
    if o["max_wait_us"] is not None:
        args += ["--max-wait-us", str(o["max_wait_us"])]
    if o["udp_buffer_bytes"] is not None:
        args += ["--udp-buffer-bytes", str(o["udp_buffer_bytes"])]
    if o["sample_interval_ms"]:
        args += ["--sample-ms", str(o["sample_interval_ms"])]
    return args


def build_inputs():
    upstream = json.loads((VENDOR / "provenance.json").read_text())
    hashes = {name: matrix.file_hash(VENDOR / name) for name in upstream["files"]}
    matrix.require(
        all(hashes[name] == row["sha256"] for name, row in upstream["files"].items()),
        "upstream KCP source differs from pinned provenance",
    )
    return dict(
        upstream_commit=upstream["commit"],
        upstream_sha256=hashes,
        endpoint_sha256=matrix.file_hash(SOURCE),
    )


def build(output):
    pins = build_inputs()
    output.mkdir(mode=0o700)
    binary = output / "kcp-native-reference"
    command = [
        "cc",
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-I",
        str(VENDOR),
        str(SOURCE),
        str(VENDOR / "ikcp.c"),
        "-llz4",
        "-lcrypto",
        "-o",
        str(binary),
    ]
    subprocess.run(command, check=True, timeout=60)
    versions = subprocess.check_output(
        ["pkg-config", "--modversion", "liblz4", "libcrypto"], text=True
    ).splitlines()
    matrix.atomic_json(
        output / "build.json",
        {
            **pins,
            "binary_sha256": matrix.file_hash(binary),
            "command": command,
            "compiler": subprocess.check_output(
                ["cc", "--version"], text=True
            ).splitlines()[0],
            "liblz4": versions[0],
            "libcrypto": versions[1],
        },
    )


def plan(mode, trace=False, options=None):
    o = resolve_options() if options is None else options
    paced = o["pace_forward_mbit"] is not None or o["pace_reverse_mbit"] is not None
    secure = o["workload"] == "secure-forward16"
    return dict(
        engine="unmodified upstream C KCP",
        mode=mode,
        native_layer="tap",
        ip_mtu=1500,
        kcp_mtu=1451,
        kcp_mss=1427,
        kcp_window_segments=o["window"],
        kcp_nodelay=[1, 10, 2, o["nocwnd"]],
        application_credit=4194304,
        encoded_message_send_credit=4194304,
        receive_credit=f"upstream KCP window of {o['window']} segments; one additional decoded frame can wait on TAP"
        + ("; one partial stream body" if o["stream"] else ""),
        native_formats=("tag 2 raw / tag 10 LZ4 bodies packed into one KCP byte stream (stream mode)"
                        if o["stream"] else
                        "one L2 body per ordered KCP message; tag 2 raw, tag 10 independent LZ4 when shorter"),
        outer="IPv4 20 + UDP 8 + authenticated header 5 + ChaCha20-Poly1305 tag 16; actual packet bytes",
        protection="fresh directional keys installed locally per run; no Common session handshake or management",
        local_send="nonblocking connected UDP; EAGAIN/ENOBUFS are measured local drops",
        flow=("one native CUBIC TCP through secure_udp_native_probe.py forward16 with --flows 1"
              if secure else
              "one native CUBIC TCP; 512-byte application records at 90 Mbit/s; shared 4 MiB writer"),
        network="same netns_lab HTB parent/netem child as the Rust TAP matrix; 100/10 Mbit/s, 35 ms each way, "
        f"independent {o['loss_percent']}% loss",
        netem_seeds=SEEDS,
        warmup_s=o["warmup_s"],
        steady_s=o["steady_s"],
        post_eof_max_s=4,
        trace=trace,
        native_txqueuelen=None,
        native_fq_maxrate=None,
        kcp_stream=o["stream"],
        admission_pacing=(dict(forward_mbit=o["pace_forward_mbit"], reverse_mbit=o["pace_reverse_mbit"],
                               bucket_ms=o["pace_burst_ms"], reserve=o["pace_reserve"],
                               debit="every accepted datagram's UDP payload plus 28 IPv4/UDP bytes")
                          if paced else None),
        native_queue_frames=o["native_queue_frames"],
        explicit_flush_interval_us=o["flush_interval_us"] or None,
        max_poll_wait_us=o["max_wait_us"],
        udp_buffer_bytes_requested=o["udp_buffer_bytes"],
        adapter_sample_interval_ms=o["sample_interval_ms"] or None,
        inner_tcp_rto_min_ms=o["inner_rto_min_ms"],
        udp_snmp_counters=o["udp_snmp_counters"],
        loss_percent=o["loss_percent"],
        workload=o["workload"],
        workload_seconds=o["workload_seconds"],
        max_bytes_per_flow=o["max_bytes"],
        probe_limits={k: o[k] for k in PROBE_LIMITS},
        adapter_args={side: adapter_args(o, side) for side in "ab"},
    )


def paid(stats):
    packets, payload = stats["socket_datagrams"], stats["socket_udp_payload_bytes"]
    segments = sum(
        stats[k]
        for k in (
            "fresh_push",
            "retry_push",
            "ack_segments",
            "window_probes",
            "window_reports",
        )
    )
    matrix.require(
        payload
        == stats["fresh_push_bytes"]
        + stats["retry_push_bytes"]
        + 24 * segments
        + 21 * packets,
        "accepted socket bytes differ from upstream segment and AEAD accounting",
    )
    return dict(
        ip_bytes=payload + 28 * packets,
        ethernet_bytes_without_fcs=payload + 42 * packets,
    )


TRACE_LIMIT = 262144
TRACE_FIELDS = "begin_ns end_ns outcome reason current pn cmd frg wnd ts sn una bytes ip_bytes xmit prior_deadline deadline rto".split()
Segment = namedtuple("Segment", TRACE_FIELDS)


def read_trace(path, stats):
    meta = stats["kcp_trace"]
    matrix.require(meta["enabled"] and meta["capacity"] == TRACE_LIMIT and
                   0 <= meta["rows"] <= TRACE_LIMIT and path.stat().st_size <= TRACE_LIMIT * 230 + 512,
                   "invalid bounded KCP trace")
    rows = []
    with path.open(newline="") as stream:
        reader = csv.reader(stream)
        matrix.require(next(reader, None) == TRACE_FIELDS, "unexpected KCP trace columns")
        for values in reader:
            matrix.require(len(rows) < meta["rows"] and len(values) == len(TRACE_FIELDS), "invalid KCP trace extent")
            row = Segment(*(v if i in (2, 3) else int(v) for i, v in enumerate(values)))
            matrix.require(0 <= row.begin_ns <= row.end_ns and 0 < row.pn <= 0xffffffff and
                           row.outcome in ("paid", "refused", "input") and row.cmd in (81, 82, 83, 84) and
                           73 <= row.ip_bytes <= 1500 and 0 <= row.bytes <= 1427,
                           "invalid KCP trace row")
            matrix.require(row.reason in (("fresh", "fast", "timeout", "unknown")
                           if row.outcome != "input" and row.cmd == 81 else ("none",)), "invalid KCP trace reason")
            if row.reason in ("fast", "timeout"):
                elapsed = (row.current - row.prior_deadline) & 0xffffffff
                matrix.require(row.xmit >= 2 and (elapsed < 0x80000000) == (row.reason == "timeout"),
                               "KCP branch and prior deadline disagree")
            rows.append(row)
    matrix.require(len(rows) == meta["rows"], "short KCP trace")
    return rows


def packets(rows, outcome):
    result = defaultdict(list)
    for row in rows:
        if row.outcome == outcome:
            result[row.pn].append(row)
    for segments in result.values():
        first = segments[0]
        matrix.require(all((r.begin_ns, r.end_ns, r.ip_bytes) == (first.begin_ns, first.end_ns, first.ip_bytes)
                           for r in segments) and sum(24 + r.bytes for r in segments) + 49 == first.ip_bytes,
                       "incomplete KCP physical datagram")
    return result


def first_feedback(rows, maximum_sn):
    """First explicit ACK or cumulative UNA covering each original source at this observation point."""
    found = {}
    previous_una = 0
    for row in rows:
        matrix.require(row.una <= maximum_sn + 1 and (row.cmd != 82 or row.sn <= maximum_sn),
                       "KCP ACK extent exceeds originals")
        if row.una > previous_una:
            for sn in range(previous_una, row.una):
                found.setdefault(sn, row)
            previous_una = row.una
        if row.cmd == 82:
            found.setdefault(row.sn, row)
    return found


def analyze_direction(local, peer, stats):
    accepted = packets(local, "paid")
    received = packets(peer, "input")
    refused = packets(local, "refused")
    matrix.require(len(accepted) == stats["socket_datagrams"] and len(refused) == stats["local_socket_drops"]
                   and sum(g[0].ip_bytes for g in accepted.values()) == paid(stats)["ip_bytes"],
                   "trace disagrees with actual socket payment")
    def wire(r):
        return (r.cmd, r.frg, r.wnd, r.ts, r.sn, r.una, r.bytes, r.ip_bytes)
    for pn, group in received.items():
        matrix.require(pn in accepted and list(map(wire, group)) == list(map(wire, accepted[pn])),
                       "authenticated input does not match a paid packet")
    pushes = [r for r in local if r.cmd == 81 and r.outcome != "input"]
    maximum = max((r.sn for r in pushes), default=-1)
    matrix.require(maximum < TRACE_LIMIT, "KCP trace SN exceeds prefix from run start")
    ack_tx = first_feedback((r for r in peer if r.outcome == "paid"), maximum)
    ack_rx = first_feedback((r for r in local if r.outcome == "input"), maximum)
    ack_pns_rx = {r.pn for r in local if r.outcome == "input"}
    reasons, retry_bytes, relation, paid_reasons = Counter(), Counter(), Counter(), Counter()
    first_arrival = {}
    first_witness = None
    for r in pushes:
        is_retry = r.xmit > 1
        if is_retry:
            reasons[r.reason] += 1
            if r.outcome == "paid":
                paid_reasons[r.reason] += 1
                retry_bytes[r.reason] += r.bytes
                previous = first_arrival.get(r.sn)
                tx, rx = ack_tx.get(r.sn), ack_rx.get(r.sn)
                if previous and previous.end_ns <= r.begin_ns:
                    relation["prior_peer_input_processed_before_retry_callback"] += r.bytes
                    if tx and tx.end_ns <= r.begin_ns:
                        relation["peer_covering_ack_paid_before_retry_callback"] += r.bytes
                        if tx.pn not in ack_pns_rx:
                            relation["earliest_covering_ack_datagram_never_arrived"] += r.bytes
                    if rx and rx.end_ns <= r.begin_ns:
                        relation["covering_ack_processed_before_retry_callback"] += r.bytes
                    if first_witness is None:
                        first_witness = dict(sn=r.sn, prior_paid_pn=previous.pn,
                                             prior_recv_return_ns=previous.begin_ns, prior_input_ns=previous.end_ns,
                                             retry_pn=r.pn, retry_reason=r.reason, retry_callback_ns=r.begin_ns,
                                             retry_paid_ns=r.end_ns, retry_received=r.pn in received,
                                             first_peer_covering_ack_paid_ns=tx.end_ns if tx else None,
                                             first_peer_covering_ack_pn=tx.pn if tx else None,
                                             first_covering_ack_processed_ns=rx.end_ns if rx else None,
                                             ack_processed_pn=rx.pn if rx else None)
                elif previous and previous.begin_ns <= r.begin_ns:
                    relation["prior_peer_recv_returned_but_input_in_progress_at_retry_callback"] += r.bytes
                elif previous:
                    relation["prior_peer_recv_returned_after_retry_callback"] += r.bytes
                else:
                    relation["no_prior_paid_attempt_reached_peer"] += r.bytes
        if r.outcome == "paid" and r.pn in received:
            peer_input = received[r.pn][0]
            if r.sn not in first_arrival or peer_input.end_ns < first_arrival[r.sn].end_ns:
                first_arrival[r.sn] = peer_input
    rx_push = [r for group in received.values() for r in group if r.cmd == 81]
    first_size = {}
    for r in rx_push:
        matrix.require(first_size.setdefault(r.sn, r.bytes) == r.bytes, "PUSH retry size changed")
    matrix.require(sum(reasons.values()) == stats["engine_retry_callbacks"] and
                   sum(paid_reasons.values()) == stats["retry_push"] and
                   sum(retry_bytes.values()) == stats["retry_push_bytes"] and
                   reasons["timeout"] == stats["engine_timeout_pushes"], "KCP reason counters disagree")
    return dict(engine_retry_callbacks=dict(reasons), paid_retry_segments=dict(paid_reasons),
                paid_retry_payload_bytes=dict(retry_bytes), retry_payload_byte_conditions=dict(relation),
                received_duplicate_push_payload_bytes=sum(r.bytes for r in rx_push) - sum(first_size.values()),
                first_retry_after_proven_peer_arrival=first_witness, peer_received_packets=len(received))


def analyze_trace_files(output, stats):
    sides = {}
    files = {}
    complete = True
    for side in "ab":
        path = output / (side + "-kcp.csv")
        rows = read_trace(path, stats[side])
        m = stats[side]["kcp_trace"]
        files[side] = dict(file=path.name, sha256=matrix.file_hash(path), **m)
        complete &= not (m["dropped"] or m["unknown_pushes"] or m["timeout_mismatched_updates"])
        sides[side] = rows
    result = {"status": "complete" if complete else "partial_or_unclassified", "files": files,
              "clock": "same-host CLOCK_MONOTONIC; begin/end bound callback to socket outcome, or recv return to ikcp_input return",
              "conditions": ("A successful recv return precedes authenticated KCP input completion. "
                             "Kernel arrival is unobserved. Before-callback ACK categories are nested. "
                             "Loss of the earliest covering ACK PN does not imply loss of every covering ACK.")}
    if complete:
        for side, peer in (("a", "b"), ("b", "a")):
            result[side] = analyze_direction(sides[side], sides[peer], stats[side])
            matrix.require(result[side]["peer_received_packets"] == stats[peer]["udp_accepted"],
                           "trace disagrees with peer's authenticated accepted datagrams")
    return result


def confirmed(stats):
    for side, other in (("a", "b"), ("b", "a")):
        tx, rx = stats[side], stats[other]
        if (
            any(tx[key] for key in DEBT)
            or any(tx.get("extensions", {}).get(key) for key in EXTENSION_DEBT)
            or tx["accepted_frames"] == 0
            or tx["accepted_frames"] != rx["injected_frames"]
            or tx["native_read_bytes"] != rx["native_written_bytes"]
        ):
            return False
    return True


def captures(case):
    active = {}
    for side in "ab":
        for name, device, ips in [
            ("wan", "wan0", matrix.WAN),
            ("native", "tun0", matrix.NATIVE),
        ]:
            pair = ["ip", "and", "host", ips["a"], "and", "host", ips["b"]]
            selected = ["arp", "or", "(", *pair, ")"] if name == "native" else pair
            label = side + "-" + name
            child = case.spawn(
                "endpoint_" + side,
                label,
                [
                    "tcpdump",
                    "-Z",
                    "root",
                    "--immediate-mode",
                    "-n",
                    "-s",
                    str(matrix.observe.SNAPLEN),
                    "-B",
                    "8192",
                    "-i",
                    device,
                    "-y",
                    "EN10MB",
                    "-c",
                    str(matrix.observe.CAPTURE_PACKETS),
                    "-w",
                    "-",
                    *selected,
                ],
                capture=case.output / (label + ".pcap"),
            )
            active[label] = child, [ips["a"], ips["b"]]
            case.wait_marker(child, "listening on", time.monotonic() + 8)
    return active


def udp_snmp(case):
    """Kernel UDP counters (/proc/net/snmp) of both endpoint namespaces."""
    return {side: case.command("endpoint_" + side, "cat", "/proc/net/snmp") for side in "ab"}


def set_inner_rto_min(case, milliseconds):
    """Raise the native TCP minimum RTO on each endpoint's owned tun0 route only."""
    routes = {}
    for side in "ab":
        role = "endpoint_" + side
        case.command(role, "ip", "route", "change", "198.18.0.0/24", "dev", "tun0", "proto", "kernel",
                     "scope", "link", "src", matrix.NATIVE[side], "rto_min", f"{milliseconds}ms")
        routes[side] = json.loads(case.command(role, "ip", "-j", "-d", "route", "show", "dev", "tun0"))
    case.value["inner_routes"] = routes


def secure_workload(case, adapters):
    """One CUBIC flow by secure_udp_native_probe.py forward16 with selectable windows."""
    request = case.value["request"]
    phase = case.output / "probe"
    phase.mkdir()
    deadline = time.monotonic() + request["workload_seconds"]
    clock = phase / "clock.json"
    common = ["--address", matrix.NATIVE["b"], "--flows", "1", "--clock", clock, "--workload", "forward16",
              *(["--max-bytes", str(request["max_bytes_per_flow"])] if request["max_bytes_per_flow"] else []),
              *probe_limit_args(request["probe_limits"])]
    server = case.spawn("endpoint_b", "probe-b", [sys.executable, TOOLS / "secure_udp_native_probe.py",
                                                  "tcp", "listen", *common])
    case.wait_marker(server, "Listening", deadline)
    client = case.spawn("endpoint_a", "probe-a", [sys.executable, TOOLS / "secure_udp_native_probe.py",
                                                  "tcp", "connect", *common])
    for child in (server, client):
        case.wait_marker(child, "Connected", deadline)
    before, wall, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
    offset = wall - (before + after) // 2
    start = after + 1_500_000_000
    warmup, measured = int(request["warmup_s"] * 1e9), int(request["steady_s"] * 1e9)
    case.value["sample_wall_ns"] = (start + warmup + offset, start + warmup + measured + offset)
    case.value["clock_anchor"] = dict(monotonic_before_ns=before, wall_ns=wall, monotonic_after_ns=after)
    case.value["cpu"] = []
    case.save()
    matrix.atomic_json(clock, {"start_ns": start, "warmup_ns": warmup, "measure_ns": measured})
    next_cpu = 0
    while client["process"].poll() is None or server["process"].poll() is None:
        case.check(deadline)
        for side, child in adapters.items():
            matrix.require(child["process"].poll() is None, f"adapter {side} exited during probe")
        if time.monotonic() >= next_cpu:
            case.value["cpu"].append(matrix.observe.cpu_snapshot([(c["label"], c["process"]) for c in case.children]))
            next_cpu = time.monotonic() + 0.5
        time.sleep(0.1)
    results = [json.loads(child["log"].read_text().splitlines()[-1]) for child in (client, server)]
    for result, child in zip(results, (client, server)):
        matrix.require(child["process"].returncode == 0, f"native probe {child['label']}: {result}")
    import secure_udp_native as native

    case.value["throughput"] = native.compare_probes(*results, "forward16", flows=1)


def measure(case, executable, key):
    loss = case.value["request"]["loss_percent"]
    for side, seed in SEEDS.items():
        role = "endpoint_" + side
        case.value.setdefault("configured_seeds", {})[side] = json.loads(
            case.command(
                role,
                sys.executable,
                TOOLS / "common_native_netem_seed.py",
                case.spec.namespaces[role],
                str(seed),
                *([] if loss == DEFAULTS["loss_percent"] else ["--loss-percent", str(loss)]),
            )
        )
    case.value["qdisc_before"] = matrix.qdisc(case)
    if case.value["request"]["udp_snmp_counters"]:
        case.value["udp_snmp_before"] = udp_snmp(case)
    adapters = {}
    for side in "ba":
        role = "endpoint_" + side
        child = case.spawn(
            role,
            "kcp-" + side,
            [
                executable,
                side,
                case.value["request"]["mode"],
                key,
                case.output / (side + "-stats.json"),
                *(["--trace-kcp", case.output / (side + "-kcp.csv")] if case.value["request"]["trace"] else []),
                *case.value["request"]["adapter_args"][side],
            ],
        )
        case.wait_marker(child, "Ready", time.monotonic() + 8)
        pid = child["process"].pid
        inode = Path(f"/proc/{pid}/ns/net").stat().st_ino
        matrix.require(
            inode == (Path("/run/netns") / case.spec.namespaces[role]).stat().st_ino,
            "KCP endpoint namespace identity differs",
        )
        case.value.setdefault("endpoint_pids", {})[side] = {
            "pid": pid,
            "netns_inode": inode,
        }
        case.value.setdefault("adapter_pid_ns", {})[side] = {
            "pid": pid,
            "ns_inode": inode,
            "expected_inode": inode,
        }
        adapters[side] = child
    active = captures(case)
    phase = dict(phase="forward", status="running", captures={})
    case.value["phases"].append(phase)
    try:
        if case.value["request"]["workload"] == "secure-forward16":
            secure_workload(case, adapters)
        else:
            bundle.workload(case, adapters)
        deadline = time.monotonic() + case.value["request"]["post_eof_max_s"]
        last = None
        while time.monotonic() < deadline:
            case.check()
            matrix.require(
                all(ch["process"].poll() is None for ch in adapters.values()),
                "KCP exited while draining",
            )
            sample = read_stats(case)
            case.value["last_drain_sample"] = sample
            if confirmed(sample) and last == sample:
                break
            last = sample
            time.sleep(0.25)
        else:
            raise matrix.OutcomeError(
                "bound_exhausted",
                "KCP failed to reach stable bilateral zero debt within 4 s",
            )
        phase["status"] = "passed"
    except Exception as error:
        phase.update(status=matrix.failure_status(error), error=str(error))
        raise
    finally:
        matrix.stop_captures(
            case, phase, active, case.value.get("sample_wall_ns"), time.monotonic() + 10
        )
        case.value["qdisc_after"] = matrix.qdisc(case)
        if case.value["request"]["udp_snmp_counters"]:
            case.value["udp_snmp_after"] = udp_snmp(case)
        case.save()


def read_stats(case):
    return {
        side: matrix.read_json(case.output / (side + "-stats.json"), 8192)
        for side in "ab"
    }


def preflight_executable(executable):
    # The pinned C entry rejects the empty argument list before opening keys,
    # TAP or sockets. Execute the actual private copy to catch mount policy.
    probe = subprocess.run([executable], stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
    matrix.require(probe.returncode == 2 and not probe.stdout and
                   probe.stderr.startswith(b"usage: endpoint a|b raw|lz4 KEYFILE STATS"),
                   "private C endpoint failed its no-I/O argument preflight")
    return dict(exitcode=probe.returncode, operation="verified argument guard before key and device access")


def run(build_dir, output, request):
    matrix.require(os.geteuid() == 0, "root is needed to create owned namespaces")
    matrix.require(
        shutil.disk_usage(output.parent).free > 512 * 1024**2,
        "insufficient space for bounded captures",
    )
    binary = build_dir / "kcp-native-reference"
    receipt = matrix.read_json(build_dir / "build.json", 16384)
    matrix.require(
        all(receipt[key] == value for key, value in build_inputs().items()),
        "build receipt does not match present sources",
    )
    with matrix.exclusive_lab(), tempfile.TemporaryDirectory(dir="/tmp", prefix="l2t-kcp-exec-") as private:
        output.mkdir(mode=0o755)
        # The shared qdisc readback check uses the module-level loss selection.
        matrix.LOSS_PERCENT = request["loss_percent"]
        spec = matrix.lab.LabSpec("kcp-" + uuid.uuid4().hex[:10], loss_percent=request["loss_percent"])
        row = dict(
            id="upstream-kcp-tap-" + request["mode"],
            required_cli={"a": ["--layer", "tap"], "b": ["--layer", "tap"]},
        )
        case = matrix.Case(row, spec, output)
        state = Path("/run") / ("l2tunnel-" + spec.lab_id)
        state.mkdir(mode=0o700)
        executable, key = Path(private) / "endpoint", state / "key"
        journal = state / (spec.lab_id + ".json")
        case.value.update(
            request=request,
            namespace_id=spec.lab_id,
            build=receipt,
            runner_sha256=matrix.file_hash(Path(__file__)),
            helper_sha256={
                name: matrix.file_hash(TOOLS / name)
                for name in (
                    "path_bundle_netns_lab.py",
                    "common_native_matrix.py",
                    "common_native_probe.py",
                    "common_native_single_flow.py",
                    "common_native_observe.py",
                    "common_native_netem_seed.py",
                    "netns_lab.py",
                    "secure_udp_native_probe.py",
                    "secure_udp_native.py",
                )
            },
        )

        def interrupted(signum, _frame):
            raise KeyboardInterrupt(f"interrupted by signal {signum}")

        old = {
            sig: signal.signal(sig, interrupted)
            for sig in (signal.SIGINT, signal.SIGTERM)
        }
        errors = []
        try:
            shutil.copyfile(binary, executable)
            executable.chmod(0o700)
            matrix.require(
                matrix.file_hash(executable) == receipt["binary_sha256"],
                "private binary hash mismatch",
            )
            case.value["executable_preflight"] = preflight_executable(executable)
            case.save()
            with os.fdopen(
                os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as f:
                f.write(os.urandom(64))
            case.value["stage"] = "owned_topology"
            matrix.topology(case, state)
            if request["inner_rto_min_ms"] is not None:
                set_inner_rto_min(case, request["inner_rto_min_ms"])
            case.value["stage"] = "single_tcp_measurement"
            measure(case, executable, key)
            case.value.update(status="passed", stage="cleanup")
        except (Exception, KeyboardInterrupt) as error:
            case.value.update(status=matrix.failure_status(error), error=str(error))
        finally:
            deadline = time.monotonic() + 30
            for child in reversed(case.children):
                try:
                    if child["process"].poll() is None:
                        rc = case.stop(
                            child,
                            signal.SIGINT if child.get("capture") else signal.SIGTERM,
                            deadline=deadline,
                        )
                        if child["label"].startswith("kcp-"):
                            matrix.require(
                                rc == 0, "KCP endpoint failed to stop cleanly"
                            )
                except Exception as error:
                    errors.append(str(error))
            try:
                if journal.exists():
                    matrix.bounded.bounded_lab(
                        matrix.lab.cleanup, spec, state, deadline
                    )
                matrix.require(
                    all(
                        not (Path("/run/netns") / ns).exists()
                        for ns in spec.namespaces.values()
                    ),
                    "owned namespace remains",
                )
                case.value["namespace_cleanup"] = "verified_absent"
            except Exception as error:
                errors.append(str(error))
            key.unlink(missing_ok=True)
            if not journal.exists():
                (state / (spec.lab_id + ".lock")).unlink(missing_ok=True)
                with suppress(OSError):
                    state.rmdir()
            for sig, handler in old.items():
                signal.signal(sig, handler)
            if errors:
                case.value.update(status="cleanup_failed", cleanup_errors=errors)
            case.save()
        try:
            if all((output / (s + "-stats.json")).is_file() for s in "ab"):
                stats = read_stats(case)
                case.value["endpoint_statistics"] = stats
                case.value["socket_accepted_wire"] = {
                    side: paid(v) for side, v in stats.items()
                }
                if case.value["status"] == "passed":
                    matrix.require(
                        confirmed(stats), "final bilateral debt or native byte mismatch"
                    )
            if request["trace"] and case.value["status"] == "passed":
                case.value["kcp_trace_analysis"] = analyze_trace_files(output, stats)
            matrix.analyze_captures(case)
        except Exception as error:
            case.value["analysis_error"] = str(error)
            if case.value["status"] == "passed":
                case.value["status"] = "tool_failure"
        case.save()
        return case.value["status"] == "passed"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    builder = commands.add_parser("build")
    builder.add_argument("--output", required=True, type=Path)
    lab = commands.add_parser("run")
    lab.add_argument("--mode", required=True, choices=["raw", "lz4"])
    lab.add_argument("--build-dir", required=True, type=Path)
    lab.add_argument("--output", required=True, type=Path)
    lab.add_argument("--apply", action="store_true")
    lab.add_argument("--trace-kcp", action="store_true", help="retain bounded authenticated KCP header and send-branch metadata")
    add_options(lab)
    args = parser.parse_args(argv)
    if args.action == "build":
        build(args.output.absolute())
        return 0
    try:
        options = options_from_args(args)
    except ValueError as error:
        parser.error(str(error))
    request = plan(args.mode, args.trace_kcp, options)
    if not args.apply:
        print(json.dumps(request, indent=2))
    else:
        return 0 if run(args.build_dir.absolute(), args.output.absolute(), request) else 1
    return 0


def add_options(lab):
    """Optional benchmark parameters; omitted options keep DEFAULTS or the selected preset."""
    group = lab.add_argument_group("optional KCP benchmark parameters (defaults: original endpoint)")
    group.add_argument("--preset", choices=sorted(PRESETS), help="apply a recorded parameter set first")
    group.add_argument("--window", type=int, help="KCP send/receive window segments (default 8192)")
    group.add_argument("--nocwnd", type=int, choices=(0, 1), help="ikcp_nodelay nc argument (default 1)")
    group.add_argument("--stream", action="store_const", const=True,
                       help="KCP stream mode; bodies are packed into one byte stream")
    group.add_argument("--pace-forward-mbit", type=float, help="endpoint A token-bucket admission rate (default unpaced)")
    group.add_argument("--pace-reverse-mbit", type=float, help="endpoint B token-bucket admission rate (default unpaced)")
    group.add_argument("--pace-burst-ms", type=float, help="token accumulation cap in ms of rate (default 2)")
    group.add_argument("--pace-reserve", choices=("queued", "fixed"),
                       help="reserve actual queued segment cost (default) or 1500 bytes/segment + 1600")
    group.add_argument("--native-queue-frames", type=int, help="bounded native ingress ring (default 0 = none)")
    group.add_argument("--flush-interval-us", type=int, help="explicit ikcp_flush interval (default 0 = none)")
    group.add_argument("--max-wait-us", type=int, help="cap each poll wait (default: ikcp_check only)")
    group.add_argument("--udp-buffer-bytes", type=int, help="request SO_SNDBUF/SO_RCVBUF (default: system)")
    group.add_argument("--sample-interval-ms", type=int, help="adapter stdout sample interval (default 0 = off)")
    group.add_argument("--inner-rto-min-ms", type=int, help="rto_min on each endpoint's tun0 route (default: kernel)")
    group.add_argument("--udp-snmp-counters", action="store_const", const=True,
                       help="record /proc/net/snmp before and after the workload")
    group.add_argument("--loss-percent", type=int, help="independent random loss each direction (default 15)")
    group.add_argument("--workload", choices=WORKLOADS, help="native TCP workload (default single-flow-4m)")
    group.add_argument("--warmup-s", type=float, help="secure-forward16 warmup seconds")
    group.add_argument("--steady-s", type=float, help="secure-forward16 measurement seconds")
    group.add_argument("--max-bytes", type=int, help="secure-forward16 per-flow byte cap (probe default 256 MiB)")
    group.add_argument("--workload-seconds", type=int, help="secure-forward16 workload lifetime")
    group.add_argument("--probe-max-samples", type=int, help="secure_udp_native_probe.py --max-samples")
    group.add_argument("--probe-deadline-seconds", type=int, help="secure_udp_native_probe.py --deadline-seconds")
    group.add_argument("--probe-max-measure-seconds", type=int, help="secure_udp_native_probe.py --max-measure-seconds")


def options_from_args(args):
    explicit = {key: getattr(args, key) for key in DEFAULTS if hasattr(args, key)}
    return resolve_options(args.preset, **explicit)


if __name__ == "__main__":
    raise SystemExit(main())
