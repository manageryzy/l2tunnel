"""Measure independently delivered shared records with all-segment deadlines."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from time import perf_counter

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.shared_records import SharedRecordConfig, SharedRecordMultiFlow
from l2tunnel_sim.aligned_records import AlignedRecordConfig, AlignedRecordTransport
from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport

from deadline_metrics import SegmentDeadlineObserver, deadline_metrics
from latency_ack import ObservedCoalescedACKTCP
from payload_sizes import rtt_metrics, summarize, write_csv


class DeadlineTCP(SegmentDeadlineObserver, ObservedCoalescedACKTCP):
    pass


def make_simulation(task):
    profile = task["profile"]
    wire_format = profile.get("wire_format", "shared_records")
    config_types = {"shared_records": SharedRecordConfig, "aligned_records": AlignedRecordConfig,
                    "compact_wire": CompactWireConfig}
    if wire_format not in config_types:
        raise ValueError("unknown shared-record wire format")
    config_type = config_types[wire_format]
    config = config_type(**profile["compact"])
    payload = task["payload_bytes"]
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"],
                      frame_bytes=payload + 66, payload_bytes=payload,
                      window_bytes=profile["window_bytes"],
                      ack_delay_ms=profile.get("ack_delay_ms", 10), ack_every=profile.get("ack_every", 2),
                      frame_interval_ms=payload * 8 / (profile["payload_rate_mbps"] * 1000))
    factory = partial(DeadlineTCP, compact_config=config, acknowledged_segment_slow_start=True,
                      ack_coalesce_ms=profile["ack_coalesce_ms"], ack_copies=profile["ack_copies"])
    transport = {}
    if wire_format == "aligned_records":
        transport["transport_type"] = AlignedRecordTransport
    elif wire_format == "compact_wire":
        transport["transport_type"] = CompactWireTransport
    return SharedRecordMultiFlow(
        Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"], mtu=task["mtu"]),
        traffic, (PathConfig(task["forward_mbps"], task["reverse_mbps"]),),
        Strategy(profile["name"], mode="tcp", tcp_rto_min_ms=profile["rto_min_ms"],
                 tcp_data_paws=profile.get("tcp_data_paws", False),
                 tcp_partial_timestamp_undo=profile.get("tcp_partial_timestamp_undo", False),
                 tcp_newreno_ack_heuristic=profile.get("tcp_newreno_ack_heuristic", False)),
        task["seed"], profile["flow_count"], compact_config=config, simulation_factory=factory, **transport)


def execute(task):
    started = perf_counter()
    sim = make_simulation(task)
    snapshots = {}

    def snapshot(time):
        snapshots[time] = (sum(flow.tcp_received for flow in sim.flows),
                           sum(sum(flow.datagrams[False].values()) for flow in sim.flows))

    for time in (task["warmup_s"], task["duration_s"]):
        sim.flows[0].at(time, snapshot, time)
    sim.run()
    row = {key: value for key, value in task.items() if key != "profile"}
    row.update(profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
               **sim.measurements(), **rtt_metrics(sim, task["warmup_s"]))
    row.update(deadline_metrics(sim, task["warmup_s"]))
    begin, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    delivered = end[0] - begin[0]
    row.update(application_goodput_mbps=row["tcp_goodput_mbps"],
               application_capacity_pct=100 * row["tcp_goodput_mbps"] / task["forward_mbps"],
               steady_application_goodput_mbps=delivered * task["payload_bytes"] * 8 / (
                   (task["duration_s"] - task["warmup_s"]) * 1e6),
               steady_forward_datagrams=end[1] - begin[1], steady_delivered_frames=delivered,
               ack_delay_ms=sim.traffic.ack_delay_ms, ack_every=sim.traffic.ack_every,
               transport="shared_record_inner_tcp", measurement_payload_kind="modeled TCP application data")
    row["steady_application_capacity_pct"] = 100 * row["steady_application_goodput_mbps"] / task["forward_mbps"]
    row["extra_packets_per_delivered_record_pct"] = 100 * (
        row["forward_datagrams"] / row["tcp_delivered_frames"] - 1) if row["tcp_delivered_frames"] else None
    row["steady_extra_packets_per_delivered_record_pct"] = 100 * (
        row["steady_forward_datagrams"] / delivered - 1) if delivered else None
    for key in ("tcp_timeouts", "tcp_retransmissions", "tcp_fast_retransmits"):
        row[key] = sum(getattr(flow, key) for flow in sim.flows)
    if sim.flows[0].data_paws is not None:
        row["tcp_data_paws"] = "linux_6_8_established_data"
        row["tcp_data_paws_rejections"] = sum(flow.data_paws.rejections for flow in sim.flows)
    if sim.flows[0].strategy.tcp_partial_timestamp_undo:
        row["tcp_partial_timestamp_undos"] = sum(flow.tcp_partial_timestamp_undos for flow in sim.flows)
    if sim.flows[0].strategy.tcp_newreno_ack_heuristic:
        row["tcp_newreno_ack_heuristic"] = True
        row["tcp_newreno_ack_heuristic_entries"] = sum(flow.tcp_newreno_ack_heuristic_entries for flow in sim.flows)
    shared = sim.shared_forward
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    row["outer_all_confirmed"] = shared.base == len(shared.sources) and not shared.buffer_bytes and not shared.callbacks
    row["ack_all_flushed"] = all(flow.pending_ack is None for flow in sim.flows)
    row["fully_confirmed"] = bool(row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
                                   and row["ack_all_flushed"] and row["tcp_delivery_fraction"] == 1)
    row["shared_source_count"] = len(shared.sources)
    for key in ("submitted_bytes", "source_record_bytes", "profile_context_bytes", "padding_bytes",
                "anchor_bytes", "scheduled_repairs", "tail_repairs", "local_repairs", "global_repairs"):
        row["shared_" + key] = getattr(shared, key)
    for key in ("aligned_records", "fragmented_records", "fragment_sources", "context_records",
                "channel_header_bytes", "implicit_padding_bytes", "elided_length_records",
                "packed_predictive_records", "timestamp_pair_candidates", "timestamp_pair_records",
                "timestamp_pair_saved_bytes"):
        row["shared_" + key] = getattr(shared, key, None)
    row["forward_encapsulation"] = getattr(shared.config, "encapsulation", "udp")
    for key in ("header_bytes", "crc_bytes", "regular_repairs", "source_wraps",
                "repair_serial_wraps", "retained_peak_symbols", "invalid_packets", "trimmed_repair_bytes",
                "protected_sources", "repeated_source_packets", "repeated_source_bytes", "peak_outstanding_sources"):
        row["compact_wire_" + key] = getattr(shared, "wire_" + key, None)
    row["with_drain_frame_p99_ms"] = row["with_drain_tcp_application_delivery_p99_ms"]
    for direction in ("forward", "reverse"):
        row[direction + "_measurement_mbps"] = row[direction + "_wire_bytes_during_measurement"] * 8 / (
            task["duration_s"] * 1e6)
    latency = [row["tcp_timestamp_rtt_p99_ms"], row["with_drain_tcp_all_segment_ack_rtt_p99_ms"]]
    miss = row["with_drain_tcp_all_segment_ack_rtt_cohort_miss_fraction_upper"]
    row["rtt_budget_met"] = bool(row["fully_confirmed"] and row["application_capacity_pct"] >= 80
                                 and miss is not None and miss <= .01
                                 and all(value is not None and value <= row["latency_budget_ms"] for value in latency))
    row["packet_cost_target_met"] = row["extra_packets_per_delivered_record_pct"] is not None and row[
        "extra_packets_per_delivered_record_pct"] <= 20
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_l2_bytes"] == row["released_frames"] * (task["payload_bytes"] + 66)
    if row["compact_wire_invalid_packets"] is not None:
        assert row["compact_wire_invalid_packets"] == 0
    for direction in ("forward", "reverse"):
        assert row[direction + "_measurement_mbps"] <= task[direction + "_mbps"] + 1e-8
    return row


def profiles():
    common = dict(flow_count=64, controller="cubic", rto_min_ms=1000, window_bytes=4 * 1048576,
                  payload_rate_mbps=81.5, ack_coalesce_ms=0, ack_copies=1,
                  acknowledged_segment_slow_start=True, reliable_acks=False, recovery="shared_record_rlnc")
    choices = [(False, 0, 4), (True, 0, 4), (True, 32, 4), (True, 64, 4),
               (True, 128, 4), (True, 64, 2)]
    return [dict(common, name=f"Shared records {'independent' if independent else 'ordered'} W{window} G{every} r20",
                 compact=dict(header_profile="tcp_delta", repair_ratio=.20, feedback_ms=1, feedback_packets=64,
                              independent_delivery=independent, repair_window_sources=window,
                              global_repair_every=every)) for independent, window, every in choices]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--duration", type=float, default=4)
    parser.add_argument("--drain", type=float, default=6)
    parser.add_argument("--warmup", type=float, default=1)
    parser.add_argument("--replications", type=int, default=1)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--payloads", type=int, nargs="+", default=[1448])
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than duration")
    selected = json.loads(args.profiles.read_text()) if args.profiles else profiles()
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for profile in selected:
        for payload in args.payloads:
            for replication, seed in enumerate(seeds, 1):
                tasks.append(dict(run_id=len(tasks) + 1, profile=profile, seed=seed, replication=replication,
                                  forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15,
                                  loss_model="iid", mtu=1500, payload_bytes=payload, duration_s=args.duration,
                                  drain_s=args.drain, warmup_s=args.warmup))
    source_root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), *(source_root / "studies" / name for name in
             ("deadline_metrics.py", "latency_ack.py", "payload_sizes.py")),
             *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(tasks=tasks, sources=hashes, assumptions=[
        "The shared_records format charges fixed symbols with a two-byte valid length, two-byte anchor and five-byte record prefix",
        "The optional aligned_records format has a three-byte channel/sequence prefix and one self-describing codec record per source",
        "Aligned context records use separate sources; oversized records have charged five-byte fragment descriptors",
        "Aligned sources transmit their actual bytes; implicit zero extension to the fixed repair-symbol size is reconstructed from the codec length",
        "Optional aligned kind six omits two payload-length bytes only when the prior ordered channel context has the same length; oversized records retain explicit lengths",
        "Optional packed predictive records exactly predict IPID, TCP sequence and unchanged ACK fields; exceptional frames retain existing reversible record kinds",
        "Optional kind-five timestamp pairs use a fixed 32-entry delta dictionary with exact frame reconstruction; unmatched pairs retain the existing predictive or explicit record formats",
        "The optional compact_wire format uses parsed typed short identifiers, fixed local/global repair ranges, charged extended tail headers and retained source bytes",
        "compact_wire encapsulation is forward-only UDP or raw IPv4 with CRC32; reverse TCP ACK and feedback paths retain their recorded service costs",
        "Optional compact-wire repair trimming removes only encoder padding beyond the maximum encoded source extent in the actual repair support; received short repair payloads are zero extended",
        "A real byte parser reassembles records and independently maintains each channel's delta context",
        "GF256 coefficient elimination identifies recoverable source bytes; repair payload arithmetic and CPU cost are excluded",
        "The same byte framing and padding apply to both globally ordered and independent-channel controls",
        "Bounded repair windows and periodic global repairs use only sender state and configured schedules",
        "Timestamp samples and every cumulatively acknowledged segment are measured separately",
        "Deadline miss bounds include unresolved submissions; only fully confirmed runs can meet the target",
        "Pacing uses configured IP capacity; authentication-byte budgets are zero",
    ])
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "experiment.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing tasks or source hashes differ")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in files:
        copy = args.out / "sources" / path.relative_to(source_root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (runs / f"{task['run_id']:05d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            path = runs / f"{row['run_id']:05d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(path)
            print(f"{row['strategy']} {row['payload_bytes']}B full={row['application_goodput_mbps']:.3f} "
                  f"steady={row['steady_application_goodput_mbps']:.3f} "
                  f"RTT99={row['tcp_timestamp_rtt_p99_ms']:.2f} "
                  f"ALLACK99={row['with_drain_tcp_all_segment_ack_rtt_p99_ms']:.2f} "
                  f"miss={row['with_drain_tcp_all_segment_ack_rtt_cohort_miss_fraction_upper']:.4f} "
                  f"extra={row['extra_packets_per_delivered_record_pct']:.2f} confirmed={row['fully_confirmed']}", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summarize(rows))
    changed = [name for name, digest in hashes.items() if sha256((source_root / name).read_bytes()).hexdigest() != digest]
    (args.out / "source-verification.json").write_text(json.dumps(dict(changed_during_run=changed), indent=2) + "\n")


if __name__ == "__main__":
    main()
