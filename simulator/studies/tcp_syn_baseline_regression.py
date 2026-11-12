"""Regress native TCP, QUIC L2 and compact transports with fresh stable-load SYN probes."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
from functools import partial
from importlib.metadata import version
import json
from math import isfinite
from multiprocessing import get_context
import os
from pathlib import Path
import platform
from random import Random
import sys
from time import perf_counter
import traceback

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.multiflow import MultiFlow
from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.mux_tcp import MuxTCP
from l2tunnel_sim.tcp_syn_baseline import BaselineHandshakeProbe, CompactHandshakeProbe, compact_confirmed
from l2tunnel_sim.tcp_syn_probe import SYNProbeConfig
from payload_sizes import ObservedTCP, TCPRTTObserver, default_profiles, make_simulation as make_compact_simulation, rtt_metrics, write_csv


PAYLOADS = (64, 256, 512, 1024, 1228, 1448)


def _load_probe_quic():
    if "ObservedProbeQUIC" in globals():
        return
    from l2tunnel_sim.tcp_syn_baseline import ProbeQUIC
    from payload_sizes import RTTLogger

    class ObservedProbeQUIC(ProbeQUIC):
        def configuration(self, reverse):
            self.loggers[reverse] = RTTLogger(self)
            return super().configuration(reverse)

    ObservedProbeQUIC.__qualname__ = "ObservedProbeQUIC"
    globals()["ObservedProbeQUIC"] = ObservedProbeQUIC


def __getattr__(name):
    if name == "ObservedProbeQUIC":
        _load_probe_quic()
        return globals()[name]
    raise AttributeError(name)


class ObservedTunnelTCP(TCPRTTObserver, MuxTCP):
    pass


def profiles():
    probe = dict(interval_ms=200, timeout_ms=5000, initial_rto_ms=1000, reverse_copies=1,
                 copy_spacing_ms=.1, stability_window_s=1, stability_windows=3,
                 throughput_tolerance_pct=3, queue_tolerance_ms=1)
    return [dict(name="Plain TCP CUBIC16 RTO1s native SYN PING", kind="tcp", controller="cubic",
                 rto_min_ms=1000, flow_count=16, window_bytes=4 * 1048576, tcp_syn_probe=probe),
            dict(name="QUIC L2 CUBIC16 existing-connection auxiliary-stream SYN PING", kind="quic",
                 controller="cubic", flow_count=16, window_bytes=4 * 1048576, tcp_syn_probe=probe,
                 probe_outer_connection=0, probe_stream_id=4, probe_record_length_bytes=2)]


def inner_profiles():
    common = dict(controller='cubic', flow_count=16, window_bytes=4 * 1048576,
                  rto_min_ms=1000, ack_every=2, ack_delay_ms=10,
                  tcp_syn_probe=dict(profiles()[0]['tcp_syn_probe']))
    return [dict(common, name='TCP over QUIC16 shared stream0', kind='quic_inner',
                 record_path='one ordered stream 0 per outer connection, shared bulk and probes'),
            dict(common, name='TCP over KCP16 fast shared queue', kind='kcp_inner',
                 kcp=dict(window=128, nodelay=1, interval=10, resend=2, nocwnd=1),
                 record_path='one upstream KCP ordered message queue per conversation, shared bulk and probes')]


def compact_profiles():
    probe = profiles()[0]["tcp_syn_probe"]
    result = [dict(profile, kind="compact", flow_count=16, window_bytes=4 * 1048576,
                   tcp_syn_probe=dict(probe), probe_outer_connection=0,
                   historical_profile_source="payload_sizes.default_profiles")
              for profile in default_profiles() if "compact" in profile]
    result.append(dict(name="Derived compact GF256 5+1 native ACK RTO1s SYN PING", kind="compact",
        compact=dict(header_profile="tcp_delta", repair_ratio=.20, generation_sources=5),
        recovery="block", reliable_acks=False, controller="cubic", rto_min_ms=1000,
        flow_count=16, window_bytes=4 * 1048576, tcp_syn_probe=dict(probe), probe_outer_connection=0,
        historical_profile_source="Derived CompactBlockTransport generation-5 configuration",
        fec_definition="One initial GF256 repair per full five-source generation, plus causal feedback repair"))
    return result


def make_simulation(task):
    profile = task["profile"]
    if profile["kind"] == "compact":
        return make_compact_simulation(task)
    if profile['kind'] in ('quic_inner', 'kcp_inner'):
        from l2tunnel_sim.reliable_tunnel import ReliableTunnelMultiFlow
        payload = task['payload_bytes']
        rate = profile.get('payload_rate_mbps')
        traffic = Traffic(duration_s=task['duration_s'], drain_s=task['drain_s'], frame_bytes=payload + 66,
            payload_bytes=payload, window_bytes=profile['window_bytes'],
            ack_every=profile.get('ack_every', 2), ack_delay_ms=profile.get('ack_delay_ms', 10),
            frame_interval_ms=payload * 8 / (rate * 1000) if rate else 0)
        factory = partial(ObservedTunnelTCP, compact_config=CompactConfig(header_profile='tcp_delta'),
                          ack_coalesce_ms=0, ack_copies=1, acknowledged_segment_slow_start=True)
        return ReliableTunnelMultiFlow(Scenario(task['rtt_ms'], task['loss_rate'], task['loss_model'], mtu=task['mtu']),
            traffic, (PathConfig(task['forward_mbps'], task['reverse_mbps']),),
            Strategy(profile['name'], mode='tcp', tcp_cc=profile['controller'], tcp_rto_min_ms=profile.get('rto_min_ms', 1000)),
            task['seed'], profile['flow_count'], protocol=profile['kind'], protocol_settings=profile.get('kcp', {}),
            simulation_factory=factory)
    if profile["kind"] not in ("tcp", "quic"):
        raise ValueError("baseline regression supports native TCP and QUIC L2")
    payload = task["payload_bytes"]
    rate = profile.get("payload_rate_mbps")
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"], frame_bytes=payload + 66,
                      payload_bytes=payload, window_bytes=profile["window_bytes"],
                      frame_interval_ms=payload * 8 / (rate * 1000) if rate else 0)
    if profile["kind"] == "quic":
        _load_probe_quic()
    return MultiFlow(Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"], mtu=task["mtu"]),
        traffic, (PathConfig(task["forward_mbps"], task["reverse_mbps"]),),
        Strategy(profile["name"], mode=profile["kind"], tcp_cc=profile["controller"],
                 tcp_rto_min_ms=profile.get("rto_min_ms", 200), quic_l2=True),
        task["seed"], profile["flow_count"],
        simulation_factory=ObservedProbeQUIC if profile["kind"] == "quic" else ObservedTCP)


def execute(task):
    started = perf_counter()
    sim = make_simulation(task)
    tunnel = task["profile"]["kind"] in ("quic_inner", "kcp_inner")
    if tunnel:
        from l2tunnel_sim.reliable_tunnel import TunnelHandshakeProbe
    probe_type = (TunnelHandshakeProbe if tunnel else
                  CompactHandshakeProbe if task["profile"]["kind"] == "compact" else BaselineHandshakeProbe)
    probe = probe_type(sim, SYNProbeConfig(**task["profile"]["tcp_syn_probe"]), start_s=task["warmup_s"])
    snapshots = {}

    def snapshot(when):
        snapshots[when] = sum(flow.tcp_received for flow in sim.flows)

    for when in (task["warmup_s"], task["duration_s"]):
        sim.flows[0].at(when, snapshot, when)
    sim.run()
    row = {key: value for key, value in task.items() if key != "profile"}
    row.update(profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
               **sim.measurements(), **rtt_metrics(sim, task["warmup_s"]), **probe.measurements())
    row["application_goodput_mbps"] = row["tcp_goodput_mbps"]
    row["application_capacity_pct"] = 100 * row["application_goodput_mbps"] / task["forward_mbps"]
    row["steady_application_goodput_mbps"] = ((snapshots[task["duration_s"]] - snapshots[task["warmup_s"]])
        * task["payload_bytes"] * 8 / ((task["duration_s"] - task["warmup_s"]) * 1e6))
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    row["outer_all_confirmed"] = all(flow.control_confirmed for flow in sim.flows) if probe.quic else True
    if tunnel:
        row['outer_all_confirmed'] = sim.tunnel_confirmed
    if isinstance(probe, CompactHandshakeProbe):
        row["outer_all_confirmed"] = all(compact_confirmed(transport) for flow in sim.flows
            for transport in (flow.compact_forward, flow.compact_reverse))
    row["ack_all_flushed"] = all(flow.ack_timer is None for flow in sim.flows)
    row["fully_confirmed"] = bool(row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
        and row["ack_all_flushed"] and row["tcp_delivery_fraction"] == 1)
    for direction in ("forward", "reverse"):
        row[direction + "_measurement_mbps"] = row[direction + "_wire_bytes_during_measurement"] * 8 / (task["duration_s"] * 1e6)
        assert row[direction + "_measurement_mbps"] <= task[direction + "_mbps"] + 1e-8
    row["extra_packets_per_delivered_record_pct"] = (100 * (row["forward_datagrams"] / row["tcp_delivered_frames"] - 1)
        if row["tcp_delivered_frames"] else None)
    concurrent = row["tcp_syn_ping_background_goodput_mbps"]
    row["tcp_syn_ping_joint_target_met"] = bool(row["fully_confirmed"] and row["tcp_syn_probe_all_flushed"]
        and row["application_capacity_pct"] >= 80 and concurrent is not None and concurrent >= .8 * task["forward_mbps"]
        and row["tcp_syn_ping_completed"] > 0 and row["tcp_syn_ping_failure_pct"] == 0
        and row["tcp_syn_ping_p99_ms"] <= row["tcp_syn_ping_budget_ms"]
        and row["tcp_syn_ping_deadline_miss_upper_pct"] <= 1)
    row["measurement_payload_kind"] = "QUIC L2 record payload equivalent" if probe.quic else "modeled TCP application data"
    row["tcp_timeouts"] = sum(getattr(flow, "tcp_timeouts", 0) for flow in sim.flows) if not probe.quic else None
    row["tcp_retransmissions"] = sum(flow.tcp_retransmissions for flow in sim.flows) if not probe.quic else None
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_l2_bytes"] == row["released_frames"] * (task["payload_bytes"] + 66)
    return row


def terminal_execute(task):
    receipts = execution_receipts()
    try:
        row = execute(task)
        row["execution_status"] = "completed"
        row["observation_status"] = "recorded" if row["tcp_syn_probe_steady_state_reached"] else "unsteady"
    except Exception as error:
        row = dict(task, profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
                   application_goodput_mbps=None, fully_confirmed=False, error=repr(error),
                   traceback=traceback.format_exc(), execution_status="error", observation_status="execution error")
    row["executed_source_receipts"] = receipts
    return row


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def execution_receipts():
    frozen = Path(__file__).resolve().parents[1]
    if frozen.name != "sources":
        raise ValueError("execute regression workers from the frozen source tree")
    receipts = {}
    for name, module in tuple(sys.modules.items()):
        if not (name == "l2tunnel_sim" or name.startswith("l2tunnel_sim.") or name == "payload_sizes"):
            continue
        path = Path(module.__file__).resolve()
        if not path.is_relative_to(frozen):
            raise ValueError(f"module imported outside frozen source tree: {name}")
        receipts[name] = dict(path=str(path), sha256=digest(path))
    receipts["tcp_syn_baseline_regression"] = dict(path=str(Path(__file__).resolve()), sha256=digest(Path(__file__)))
    return receipts


def validate_saved(row, task, output, manifest):
    actual = {key: json.loads(row["profile"]) if key == "profile" else row.get(key) for key in task}
    if actual != task:
        raise ValueError(f"saved run differs from task {task['run_id']}")
    if row.get("source_manifest_sha256") != digest(output / "experiment.json"):
        raise ValueError(f"saved run has a different source manifest: {task['run_id']}")
    receipts = row.get("executed_source_receipts", {})
    required = {"tcp_syn_baseline_regression", "payload_sizes", "l2tunnel_sim.tcp_syn_baseline", "l2tunnel_sim.tcp_syn_probe"}
    if not required <= receipts.keys():
        raise ValueError(f"saved run lacks execution receipts: {task['run_id']}")
    frozen = (output / "sources").resolve()
    for receipt in receipts.values():
        path = Path(receipt["path"]).resolve()
        if not path.is_relative_to(frozen):
            raise ValueError("saved execution source lies outside frozen tree")
        name = path.relative_to(frozen).as_posix()
        if manifest["sources"].get(name) != receipt["sha256"] or digest(path) != receipt["sha256"]:
            raise ValueError(f"saved execution source receipt mismatch: {name}")
    if row.get("execution_status") not in ("completed", "error"):
        raise ValueError("saved run lacks a terminal execution status")


def tasks(duration=30, warmup=5, drain=20, replications=3, *, include_compact=True,
          include_baselines=True, compact_all_payloads=False, payload_rates=None, stability_window=1,
          baseline_kinds=("tcp", "quic"), compact_recoveries=None, payloads=PAYLOADS):
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(replications)]
    plan = []
    # The first paired seed covers all twelve family/payload combinations first.
    for replication, seed in enumerate(seeds, 1):
        for profile in profiles() + inner_profiles() if include_baselines else []:
            if profile["kind"] not in baseline_kinds:
                continue
            for payload in payloads:
                plan.append(dict(run_id=len(plan) + 1, profile=profile, payload_bytes=payload,
                    forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500,
                    duration_s=duration, warmup_s=warmup, drain_s=drain, replication=replication, seed=seed))
    for profile in compact_profiles() if include_compact else []:
        if compact_recoveries is not None and profile["recovery"] not in compact_recoveries:
            continue
        for replication, seed in enumerate(seeds, 1):
            for payload in payloads if compact_all_payloads or payloads != PAYLOADS else (1448,):
                plan.append(dict(run_id=len(plan) + 1, profile=profile, payload_bytes=payload,
                    forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500,
                    duration_s=duration, warmup_s=warmup, drain_s=drain, replication=replication, seed=seed))
    for task in plan:
        profile = dict(task["profile"])
        profile["tcp_syn_probe"] = dict(profile["tcp_syn_probe"], stability_window_s=stability_window)
        if payload_rates is not None:
            profile["payload_rate_mbps"] = payload_rates[PAYLOADS.index(task["payload_bytes"])]
        task["profile"] = profile
    return plan


def load_task_plan(path):
    """Load explicit paired cases while enforcing this study's fixed links."""
    plan = json.loads(path.read_text())["tasks"]
    if not isinstance(plan, list) or not plan:
        raise ValueError("explicit task plan must contain a nonempty task list")
    expected = set(tasks(replications=1)[0])
    identifiers = set()
    for task in plan:
        if not isinstance(task, dict) or set(task) != expected:
            raise ValueError("explicit task has unexpected or missing fields")
        identifier = task["run_id"]
        if type(identifier) is not int or identifier < 1 or identifier in identifiers:
            raise ValueError("explicit task identifiers must be unique positive integers")
        identifiers.add(identifier)
        if task["forward_mbps"] != 100 or task["reverse_mbps"] != 10:
            raise ValueError("explicit baseline tasks require fixed 100/10 Mbps links")
        if task["payload_bytes"] not in PAYLOADS:
            raise ValueError("explicit task has an unsupported payload size")
        profile = task["profile"]
        if not isinstance(profile, dict) or profile.get("kind") not in ("tcp", "quic", "compact", "quic_inner", "kcp_inner"):
            raise ValueError("explicit task has an unsupported baseline profile")
        for key in ("duration_s", "warmup_s", "drain_s"):
            value = task[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or value < 0:
                raise ValueError("explicit task durations must be finite and nonnegative")
        if not task["warmup_s"] < task["duration_s"]:
            raise ValueError("explicit task warmup must precede traffic end")
        if any(type(task[key]) is not int or task[key] < minimum
               for key, minimum in (("seed", 0), ("replication", 1))):
            raise ValueError("explicit task seed and replication must be valid integers")
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--warmup", type=float, default=5)
    parser.add_argument("--drain", type=float, default=20)
    parser.add_argument("--replications", type=int, default=3)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--baseline-only", action="store_true",
                        help="Run the native TCP and QUIC payload matrix without compact profiles")
    selection.add_argument("--compact-only", action="store_true",
                           help="Run only Compact ARQ, RLNC19 and generation-5 profiles")
    parser.add_argument("--baseline-kind", action="append", choices=("tcp", "quic", "quic_inner", "kcp_inner"),
                        help="Select a baseline family; defaults to both")
    parser.add_argument("--compact-all-payloads", action="store_true")
    parser.add_argument("--compact-recovery", action="append", choices=("arq", "rlnc", "block"),
                        help="Select compact recovery profiles; defaults to all three")
    parser.add_argument("--payload", type=int, action="append", choices=PAYLOADS,
                        help="Select payload sizes; defaults to all six")
    parser.add_argument("--payload-rates", type=float, nargs=6, metavar="MBPS",
                        help="Explicit offered Mbps for payloads 64/256/512/1024/1228/1448")
    parser.add_argument("--stability-window", type=float, default=1,
                        help="Averaging seconds per stability window; thresholds and three-window count are preserved")
    parser.add_argument("--task-plan", type=Path,
                        help="Use an explicit JSON task list with fixed 100/10 Mbps links")
    parser.add_argument("--single-phase", action="store_true",
                        help="Schedule the explicit task order in one shared worker pool")
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    args.out = args.out.resolve()
    if not 0 <= args.warmup < args.duration or args.replications < 1 or args.workers < 1:
        parser.error("invalid duration, warmup, replications or worker count")
    if not isfinite(args.stability_window) or args.stability_window < 1e-9:
        parser.error("stability window must be finite and positive")
    if args.payload_rates is not None and any(not isfinite(rate) or rate <= 0 for rate in args.payload_rates):
        parser.error("payload rates must be finite and positive")
    source_root = Path(__file__).resolve().parents[1]
    sources = [Path(__file__).resolve(), source_root / "studies/payload_sizes.py",
               source_root / "tests/test_tcp_syn_baseline.py", source_root / 'tests/test_reliable_tunnel.py',
               *sorted((source_root / "src/l2tunnel_sim").glob("*.py")),
               *sorted((source_root / 'src/l2tunnel_sim/_vendor/kcp').glob('*'))]
    hashes = {path.relative_to(source_root).as_posix(): digest(path) for path in sources}
    manifest = dict(tasks=tasks(args.duration, args.warmup, args.drain, args.replications,
                               include_compact=not args.baseline_only, include_baselines=not args.compact_only,
                               compact_all_payloads=args.compact_all_payloads,
                               payload_rates=args.payload_rates, stability_window=args.stability_window,
                               baseline_kinds=args.baseline_kind or ("tcp", "quic"),
                               compact_recoveries=args.compact_recovery,
                               payloads=tuple(dict.fromkeys(args.payload)) if args.payload else PAYLOADS), sources=hashes,
        runtime=dict(python=platform.python_version(), **{name: version(name) for name in ("aioquic", "cryptography", "numpy", "scipy")}),
        assumptions=[
            "Native TCP and QUIC L2 retain sixteen independent CUBIC controllers and a fixed aggregate 4 MiB application window",
            "All six payloads 64/256/512/1024/1228/1448 use 100/10 Mbps, 70 ms nominal RTT, 15 percent IID whole-IP-packet loss and MTU 1500",
            "Fresh TCP probes start only after minimum warmup and the recorded measured stability gate; missing steady state remains explicit",
            "Probe admission ends one full timeout horizon before bulk traffic ends; all completed, timed-out and censored probes remain recorded",
            "Native TCP SYN/SYN-ACK/final ACK/reset use 52 IPv4/TCP bytes including timestamps, with one response and a 1 second initial RTO/backoff",
            "QUIC probe frames use auxiliary bidirectional stream 4 on existing bulk connection 0",
            "QUIC bulk records use stream 0. Stream 4 records contain uint16 length and full 66-byte forward Ethernet frames or event64 plus 66-byte reverse frames",
            "Auxiliary QUIC streams share connection flow control, congestion control, packetization, FIFO service and erasures with bulk data",
            "Every actual QUIC datagram, retransmission and control packet is charged at serialized UDP length plus 28 IPv4/UDP bytes",
            "Packets containing probe records can also contain bulk data or transport ACKs; their IP-byte subtotal is overlapping attribution, not extra additive service",
            "Per-stream qlog offsets keep auxiliary stream delivery and acknowledgements separate from bulk segment counts",
            "QUIC bulk application throughput remains complete-L2-record payload equivalent without an inner bulk TCP state machine",
            "The new probe endpoint implements TCP handshake state; timestamp-only headers and an immediate modeled listener exclude kernel/application scheduling",
            "When selected, additional 1448-byte cases reuse recorded native-ACK Compact ARQ/RLNC19 profiles and one derived Compact GF256 generation-5/ratio-.20 profile",
            "Compact probes share flow 0's ordered transport and reversible header context, preserving bulk head-of-line waiting and charged context switches",
            "The derived 5+1 profile sends one initial GF256 repair per full five-source generation and permits later causal feedback repair. Random coefficients retain finite-field rank dependence",
            "CompactTransport preserves its length-and-GF256-rank payload abstraction. Probe frames enter the real reversible header encoder and callbacks wait for ordered record completion",
            "Execution uses immutable snapshots of the complete current protocol package and the optional adapters in tcp_syn_baseline.py",
            "When kind is quic_inner or kcp_inner, bulk runs the modeled inner TCP state machine and all complete Ethernet data/ACK/probe frames share the same causal RR outer connection pool",
            "The new inner-TCP QUIC baseline uses only stream 0 in each of at most sixteen established connections, and charges actual encrypted IP/UDP service",
            "The new inner-TCP KCP baseline executes pinned unmodified upstream C, with one common ordered message queue and finite segment window per conversation",
            "Inner-TCP reliable baseline stability includes physical FIFO, shared ingress backlog, and admitted protocol bytes not yet first transmitted. Sent unacknowledged bytes remain window occupancy rather than unsent backlog",
            "Historical auxiliary-stream QUIC assumptions above apply only to kind quic, never to quic_inner or kcp_inner",
        ])
    manifest["execution_policy"] = dict(single_phase=args.single_phase)
    if args.task_plan is not None:
        args.task_plan = args.task_plan.resolve()
        manifest["tasks"] = load_task_plan(args.task_plan)
        manifest["task_plan_sha256"] = digest(args.task_plan)
    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists():
        saved = json.loads(manifest_path.read_text())
        if saved["tasks"] != manifest["tasks"] or saved["runtime"] != manifest["runtime"]:
            raise ValueError("existing task plan or runtime differs")
        if (saved.get("execution_policy", dict(single_phase=False)) != manifest["execution_policy"]
                or saved.get("task_plan_sha256") != manifest.get("task_plan_sha256")):
            raise ValueError("existing task plan receipt or execution policy differs")
        if digest(Path(__file__)) != saved["sources"]["studies/tcp_syn_baseline_regression.py"]:
            raise ValueError("coordinator source changed, resume using the frozen runner")
        manifest = saved
    else:
        for source in sources:
            target = args.out / "sources" / source.relative_to(source_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    hashes = manifest["sources"]
    for name, expected in hashes.items():
        if digest(args.out / "sources" / name) != expected:
            raise ValueError(f"frozen source changed: {name}")
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    if args.plan_only:
        print(json.dumps(dict(planned=len(manifest["tasks"]), source_files=len(hashes))))
        return
    frozen_runner = args.out / "sources/studies/tcp_syn_baseline_regression.py"
    if Path(__file__).resolve() != frozen_runner:
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join(
            [str(args.out / "sources/src"), str(args.out / "sources/studies")]), PYTHONDONTWRITEBYTECODE="1")
        os.execve(sys.executable, [sys.executable, str(frozen_runner), *sys.argv[1:]], environment)
    execution_receipts()
    rows = []
    for task in manifest["tasks"]:
        path = runs / f"{task['run_id']:05d}.json"
        if path.exists():
            row = json.loads(path.read_text())
            validate_saved(row, task, args.out, manifest)
            rows.append(row)
    saved_ids = {row["run_id"] for row in rows}
    phases = ([task for task in manifest["tasks"] if task["profile"]["kind"] != "compact" and task["replication"] == 1],
              [task for task in manifest["tasks"] if task["profile"]["kind"] != "compact" and task["replication"] != 1],
              [task for task in manifest["tasks"] if task["profile"]["kind"] == "compact"])
    if args.single_phase:
        phases = (manifest["tasks"],)
    for phase in phases:
        if any(row["execution_status"] == "error" for row in rows):
            break
        pending = [task for task in phase if task["run_id"] not in saved_ids]
        with ProcessPoolExecutor(max_workers=args.workers, mp_context=get_context("spawn")) as pool:
            futures = [pool.submit(terminal_execute, task) for task in pending]
            for future in as_completed(futures):
                if future.cancelled():
                    continue
                row = future.result()
                row["source_manifest_sha256"] = digest(manifest_path)
                path = runs / f"{row['run_id']:05d}.json"
                temporary = path.with_suffix(".tmp")
                temporary.write_text(json.dumps(row, allow_nan=False) + "\n")
                temporary.replace(path)
                rows.append(row)
                print(json.dumps({key: row.get(key) for key in ("run_id", "strategy", "payload_bytes", "application_goodput_mbps",
                      "tcp_syn_probe_start_s", "tcp_syn_ping_offered", "tcp_syn_ping_p99_ms", "error")}), flush=True)
                if row["execution_status"] == "error":
                    for pending_future in futures:
                        pending_future.cancel()
    rows.sort(key=lambda row: row["run_id"])
    fields = list(dict.fromkeys(key for row in rows for key in row))
    write_csv(args.out / "replications.csv", [{key: row.get(key) for key in fields} for row in rows])
    changed = [name for name, expected in hashes.items() if digest(args.out / "sources" / name) != expected]
    (args.out / "source-verification.json").write_text(json.dumps(dict(changed_during_run=changed,
        executed_from_frozen_sources=True, verified_run_ids=[row["run_id"] for row in rows]), indent=2) + "\n")
    print(json.dumps(dict(saved=len(rows), failures=sum(bool(row.get("error")) for row in rows), changed_during_run=changed)), flush=True)
    if changed or any(row["execution_status"] == "error" for row in rows) or len(rows) != len(manifest["tasks"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
