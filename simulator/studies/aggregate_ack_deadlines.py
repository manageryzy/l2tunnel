"""Measure full-frame cross-flow ACK aggregation with all-segment deadlines."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from time import perf_counter

import numpy as np

from l2tunnel_sim.aggregate_ack import ACKAggregator, AggregateACKTCP
from l2tunnel_sim.aligned_records import AlignedRecordConfig, AlignedRecordTransport
from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.shared_records import SharedRecordMultiFlow
from l2tunnel_sim.mux_tcp import MuxTCP, UnifiedMuxMultiFlow, UnifiedMuxHandshakeProbe
from l2tunnel_sim.packed_receiver_service import DecoderCurve, PackedReceiverService, ReceiverCost
from l2tunnel_sim.tcp_syn_probe import SYNProbeConfig, TCPHandshakeProbe
from deadline_metrics import SegmentDeadlineObserver, deadline_metrics
from payload_sizes import TCPRTTObserver, rtt_metrics, summarize, write_csv
import shared_record_deadlines as baseline


class ObservedAggregateTCP(SegmentDeadlineObserver, TCPRTTObserver, AggregateACKTCP):
    pass


class ObservedMuxTCP(SegmentDeadlineObserver, TCPRTTObserver, MuxTCP):
    pass


def make_simulation(task):
    profile = task["profile"]
    mux = profile.get("mux")
    targeted = task.get("packed_targeted_recovery", False)
    if type(targeted) is not bool:
        raise ValueError("packed_targeted_recovery must be a boolean")
    latency_policy = task.get("packed_latency_policy")
    if latency_policy is not None and (not targeted or not isinstance(latency_policy, str)):
        raise ValueError("packed_latency_policy requires targeted recovery and a policy name")
    if targeted and (mux is None or profile.get("wire_format") != "compact_wire"
                     or profile["compact"].get("pack_sources_max_delay_ms", 0) <= 0):
        raise ValueError("targeted recovery requires a packed duplex MUX")
    if mux is None and not profile["ack_aggregation"]:
        return baseline.make_simulation(task)
    wire_format = profile.get("wire_format", "aligned_records")
    formats = {"aligned_records": (AlignedRecordConfig, AlignedRecordTransport),
               "compact_wire": (CompactWireConfig, CompactWireTransport)}
    if wire_format not in formats:
        raise ValueError("unknown aggregate-ACK forward wire format")
    config_type, transport_type = formats[wire_format]
    config = config_type(**profile["compact"])
    payload = task["payload_bytes"]
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"],
                      frame_bytes=payload + 66, payload_bytes=payload, window_bytes=profile["window_bytes"],
                      ack_delay_ms=profile.get("ack_delay_ms", 10), ack_every=profile.get("ack_every", 2),
                      frame_interval_ms=payload * 8 / (profile["payload_rate_mbps"] * 1000))
    factory_options = dict(compact_config=config, acknowledged_segment_slow_start=True,
                           ack_coalesce_ms=profile["ack_coalesce_ms"], ack_copies=profile["ack_copies"])
    simulation_options = dict(compact_config=config)
    simulation_type = SharedRecordMultiFlow
    tcp_type = ObservedAggregateTCP
    if mux is not None:
        if wire_format != "compact_wire" or profile["ack_aggregation"]:
            raise ValueError("unified mux requires duplex compact wire without a separate ACK aggregator")
        simulation_type, tcp_type = UnifiedMuxMultiFlow, ObservedMuxTCP
        simulation_options["channel_count"] = mux["channels"]
        simulation_options["mapping"] = mux.get("mapping", "crc32")
    else:
        factory_options["distinct_flow_headers"] = profile.get("distinct_flow_headers", False)
        simulation_options["transport_type"] = transport_type
    factory = partial(tcp_type, **factory_options)
    sim = simulation_type(
        Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"], mtu=task["mtu"]),
        traffic, (PathConfig(task["forward_mbps"], task["reverse_mbps"]),),
        Strategy(profile["name"], mode="tcp", tcp_rto_min_ms=profile["rto_min_ms"],
                 tcp_cc=profile.get("controller", "cubic"),
                 tcp_data_paws=profile.get("tcp_data_paws", False),
                 tcp_partial_timestamp_undo=profile.get("tcp_partial_timestamp_undo", False),
                 tcp_newreno_ack_heuristic=profile.get("tcp_newreno_ack_heuristic", False)),
        task["seed"], profile["flow_count"], simulation_factory=factory, **simulation_options)
    if targeted:
        # Install before producers, probes or receiver service attach. The named
        # historical MUX constructor and its source fingerprint stay reproducible.
        from l2tunnel_sim.packed_targeted import TargetedPackedWireTransport, TargetedPolicy
        if latency_policy is None:
            transports = tuple(TargetedPackedWireTransport(sim.flows[0], reverse, config)
                               for reverse in (False, True))
        elif latency_policy == "queue-aware-repair-budget":
            from l2tunnel_sim.packed_backlog_policy import BacklogPackedWireTransport, oldest_mux_wait_ms
            transports = tuple(BacklogPackedWireTransport(
                sim.flows[0], reverse, config, policy=TargetedPolicy(),
                oldest_wait_ms=partial(oldest_mux_wait_ms, sim.mux, reverse)) for reverse in (False, True))
        else:
            from l2tunnel_sim.packed_latency_policy import LatencyPackedWireTransport
            transports = tuple(LatencyPackedWireTransport(
                sim.flows[0], reverse, config, policy=TargetedPolicy(), variant=latency_policy)
                for reverse in (False, True))
        for previous, current in zip(sim.mux.transports, transports):
            current.capacity_callback = previous.capacity_callback
            previous.capacity_callback = None
        sim.shared_forward, sim.shared_reverse = transports
        sim.mux.transports = transports
        for flow in sim.flows:
            flow.compact_forward.transport, flow.compact_reverse.transport = transports
    if mux is not None:
        return sim
    sim.ack_aggregate = ACKAggregator(sim.flows, hold_ms=profile["ack_batch_hold_ms"],
                                    record_encoding=profile.get("ack_record_encoding", "full"))
    return sim


def execute(task, *, observe_packed=None):
    started = perf_counter()
    sim = make_simulation(task)
    services = {}
    costs = {"packed_receiver_cost": ReceiverCost, "packed_decoder_curve": DecoderCurve}
    selected = costs.keys() & task.keys()
    if selected:
        if len(selected) != 1:
            raise ValueError("select exactly one packed receiver pricing model")
        if not hasattr(sim, "mux"):
            raise ValueError("packed receiver cost requires a duplex packed MUX")
        key = selected.pop()
        cost = costs[key](**task[key])
        services = {name: PackedReceiverService(getattr(sim, "shared_" + name), cost,
                                                task.get("packed_rank_backend", "reference"))
                    for name in ("forward", "reverse")}
    elif "packed_rank_backend" in task:
        raise ValueError("rank backend selection requires a packed receiver service")
    probe_settings = task["profile"].get("tcp_syn_probe")
    probe_type = UnifiedMuxHandshakeProbe if hasattr(sim, "mux") else TCPHandshakeProbe
    probe = (probe_type(sim, SYNProbeConfig(**probe_settings), start_s=task["warmup_s"])
             if probe_settings is not None else None)
    snapshots = {}

    def snapshot(when):
        snapshots[when] = (sum(flow.tcp_received for flow in sim.flows),
                           sum(sum(flow.datagrams[False].values()) for flow in sim.flows),
                           sum(flow.byte_offset(flow.tcp_received) for flow in sim.flows))

    for when in (task["warmup_s"], task["duration_s"]):
        sim.flows[0].at(when, snapshot, when)
    if observe_packed is not None:
        observe_packed(sim, services)
    sim.run()
    row = {key: value for key, value in task.items() if key != "profile"}
    row.update(profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
               **sim.measurements(), **rtt_metrics(sim, task["warmup_s"]),
               **deadline_metrics(sim, task["warmup_s"]))
    begin, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    delivered = end[0] - begin[0]
    row.update(application_goodput_mbps=row["tcp_goodput_mbps"],
               application_capacity_pct=100 * row["tcp_goodput_mbps"] / task["forward_mbps"],
               steady_application_goodput_mbps=(end[2] - begin[2]) * 8 / (
                   (task["duration_s"] - task["warmup_s"]) * 1e6),
               steady_forward_datagrams=end[1] - begin[1], steady_delivered_frames=delivered,
               ack_delay_ms=sim.traffic.ack_delay_ms, ack_every=sim.traffic.ack_every,
               transport="shared_record_inner_tcp", measurement_payload_kind="modeled TCP application data")
    row["steady_application_capacity_pct"] = 100 * row["steady_application_goodput_mbps"] / task["forward_mbps"]
    row["extra_packets_per_delivered_record_pct"] = 100 * (
        row["forward_datagrams"] / row["tcp_delivered_frames"] - 1) if row["tcp_delivered_frames"] else None
    row["steady_extra_packets_per_delivered_record_pct"] = 100 * (
        row["steady_forward_datagrams"] / delivered - 1) if delivered else None
    for key in ("tcp_timeouts", "tcp_retransmissions", "tcp_fast_retransmits", "ack_generated",
                "ack_superseded", "ack_transmitted", "ack_duplicates_transmitted", "ack_copy_duplicates"):
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
    if task.get("packed_targeted_recovery"):
        row["targeted_policy"] = asdict(shared.policy)
        if task.get("packed_latency_policy") is not None:
            row["packed_latency_policy"] = task["packed_latency_policy"]
            row["packed_latency_counts"] = {name: dict(transport.latency_counts)
                                            for name, transport in (("forward", shared),
                                                                    ("reverse", sim.shared_reverse))}
        row["targeted_counts"] = {name: dict(transport.targeted_counts)
                                  for name, transport in (("forward", shared),
                                                          ("reverse", sim.shared_reverse))}
    aggregate = getattr(sim, "ack_aggregate", None)
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    row["outer_all_confirmed"] = shared.base == len(shared.sources) and not shared.buffer_bytes and not shared.callbacks
    row["ack_all_flushed"] = all(flow.pending_ack is None for flow in sim.flows) and (
        aggregate is None or aggregate.flushed)
    row["fully_confirmed"] = bool(row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
                                   and row["ack_all_flushed"] and row["tcp_delivery_fraction"] == 1)
    if hasattr(sim, "mux"):
        row.update(sim.mux.measurements())
        row["transport"] = "unified_duplex_mux_inner_tcp"
        row["fully_confirmed"] = row["fully_confirmed"] and sim.mux_confirmed
        row["mux_both_directions_confirmed"] = sim.mux_confirmed
        row["mux_endpoint_records_pending"] = sum(len(endpoint.records) for flow in sim.flows
            for endpoint in (flow.compact_forward, flow.compact_reverse))
        for direction, transport in (("forward", sim.shared_forward), ("reverse", sim.shared_reverse)):
            row[f"mux_{direction}_independent_short_records"] = transport.independent_short_records
            row[f"mux_{direction}_early_short_releases"] = transport.receiver.early_release_count
            row[f"mux_{direction}_early_short_pending"] = len(transport.receiver.early_delivered)
            row[f"mux_{direction}_peak_outstanding_sources"] = transport.wire_peak_outstanding_sources
            row[f"mux_{direction}_pending_pack_bytes"] = getattr(transport, "pending_pack_bytes", 0)
            for metric in ("sources", "single_sources", "units", "header_bytes", "max_units", "wait_count",
                           "wait_sum_ms", "wait_max_ms", "peak_pending_channel_records", "flush_reasons"):
                row[f"mux_{direction}_packed_{metric}"] = getattr(transport, "packed_" + metric, None)
    row["shared_source_count"] = len(shared.sources)
    for key in ("submitted_bytes", "source_record_bytes", "profile_context_bytes", "padding_bytes",
                "anchor_bytes", "scheduled_repairs", "tail_repairs", "local_repairs", "global_repairs",
                "aligned_records", "fragmented_records", "fragment_sources", "context_records",
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
    prefix = "with_drain_tcp_all_segment_ack_rtt_cohort_"
    latency = row[prefix + "latency_lower_bound_p99_ms"]
    miss = row[prefix + "miss_fraction_upper"]
    timestamp_latency = row["tcp_timestamp_rtt_p99_ms"]
    row["rtt_budget_met"] = bool(row["fully_confirmed"] and row["application_capacity_pct"] >= 80
                                 and row[prefix + "censored_segments"] == 0 and miss is not None and miss <= .01
                                 and latency is not None and latency <= row["latency_budget_ms"]
                                 and timestamp_latency is not None and timestamp_latency <= row["latency_budget_ms"])
    row["packet_cost_target_met"] = row["extra_packets_per_delivered_record_pct"] is not None and row[
        "extra_packets_per_delivered_record_pct"] <= 20
    if aggregate is not None:
        row["ack_record_encoding"] = aggregate.record_encoding
        row["distinct_flow_headers"] = sim.flows[0].distinct_flow_headers
        row["ack_batch_encoding_datagrams"] = dict(aggregate.encoding_datagrams)
        row["ack_batch_full_equivalent_wire_bytes"] = aggregate.full_equivalent_wire_bytes
        row["ack_batch_saved_wire_bytes"] = aggregate.saved_wire_bytes
        row["ack_batch_size_histogram"] = dict(aggregate.batch_sizes)
        row["ack_batch_records_mean"] = aggregate.submitted_records / aggregate.batches if aggregate.batches else None
        for key in ("batches", "submitted_records", "verified_records", "released_records", "requested_wire_bytes"):
            row["ack_batch_" + key] = getattr(aggregate, key)
        row["ack_batch_unreceived_records"] = len(aggregate.records)
        for name in ("hold_delays_ms", "queue_delays_ms"):
            values = getattr(aggregate, name)
            for percentile in (50, 95, 99):
                row["ack_batch_" + name + "_p" + str(percentile)] = float(np.percentile(values, percentile)) if values else None
        row["ack_batch_departed_wire_bytes"] = sum(flow.wire[True]["ack_batch"] for flow in sim.flows)
        row["ack_batch_departed_datagrams"] = sum(flow.datagrams[True]["ack_batch"] for flow in sim.flows)
    row["compute_seconds"] = perf_counter() - started
    if services:
        row["packed_receiver_service"] = {name: service.measurements() for name, service in services.items()}
    if probe is not None:
        row.update(probe.measurements())
        row["tcp_syn_ping_joint_target_met"] = bool(
            row["fully_confirmed"] and row["tcp_syn_probe_all_flushed"]
            and row["application_capacity_pct"] >= 80 and row["tcp_syn_ping_completed"] > 0
            and row["tcp_syn_ping_background_goodput_mbps"] >= .8 * task["forward_mbps"]
            and row["tcp_syn_ping_failure_pct"] == 0
            and row["tcp_syn_ping_p99_ms"] <= row["tcp_syn_ping_budget_ms"]
            and row["tcp_syn_ping_deadline_miss_upper_pct"] <= 1)
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_l2_bytes"] == (sum(flow.byte_offset(flow.tcp_received) for flow in sim.flows)
                                       + row["released_frames"] * 66)
    if row["compact_wire_invalid_packets"] is not None:
        assert row["compact_wire_invalid_packets"] == 0
    for direction in ("forward", "reverse"):
        assert row[direction + "_measurement_mbps"] <= task[direction + "_mbps"] + 1e-8
    return row


def profiles():
    common = dict(controller="cubic", rto_min_ms=1000, window_bytes=4 * 1048576,
                  payload_rate_mbps=80.18, ack_coalesce_ms=.25, acknowledged_segment_slow_start=True,
                  reliable_acks=False, recovery="shared_record_rlnc", wire_format="aligned_records",
                  compact=dict(header_profile="tcp_delta", repair_ratio=.208, feedback_ms=1,
                               feedback_packets=64, flush_ms=2, independent_delivery=True,
                               repair_window_sources=128, global_repair_every=16, elide_payload_length=True))
    choices = [(64, 3, False), (64, 3, True), (64, 2, True), (128, 2, True), (256, 2, True),
               (128, 3, True)]
    return [dict(common, name=f"Aligned {flows}flows ACKx{copies} {'batch0.5ms' if aggregate else 'unbatched'} r20.8",
                 flow_count=flows, ack_copies=copies, ack_aggregation=aggregate, ack_batch_hold_ms=.5)
            for flows, copies, aggregate in choices]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--drain", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--replications", type=int, default=1)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration or args.replications < 1:
        parser.error("warmup must be shorter than duration and replications must be positive")
    selected = json.loads(args.profiles.read_text()) if args.profiles else profiles()
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for profile in selected:
        for replication, seed in enumerate(seeds, 1):
            tasks.append(dict(run_id=len(tasks) + 1, profile=profile, seed=seed, replication=replication,
                              forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model="iid",
                              mtu=1500, payload_bytes=1448, duration_s=args.duration, drain_s=args.drain,
                              warmup_s=args.warmup))
    source_root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), *(source_root / "studies" / name for name in
             ("shared_record_deadlines.py", "deadline_metrics.py", "latency_ack.py", "payload_sizes.py")),
             *sorted((source_root / "src/l2tunnel_sim").glob("*.py")),
             source_root / "tests/test_aggregate_ack_deadlines.py", source_root / "tests/test_tcp_syn_probe.py"]
    hashes = {str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(tasks=tasks, sources=hashes, assumptions=[
        "Each aggregate charges 28 IPv4/UDP bytes and a 4-byte version/kind/count header; default full records use 75 bytes each",
        "Each ACK record preserves a 1-byte channel, 8-byte event ID and checksum-valid 66-byte Ethernet/IPv4/TCP frame",
        "Optional batch_delta chooses the smallest full-frame, exact header-codec or byte-patch envelope, with explicit encoded lengths and a new charged context in each datagram",
        "Optional batch_varint additionally tests byte-patch records with batch-local signed event-ID deltas, a zero initial reference and explicit varint record lengths; every original uint64 event identity is retained",
        "Distinct-flow header profiles give each ACK channel a serialized destination port and regenerate its TCP checksum before reversible compression",
        "Batch-local compression has no inter-datagram context dependencies; compression savings and format counters measure requested copies while load gates use departed bytes",
        "Batches use each profile's ack_batch_hold_ms maximum hold or fill the MTU; every copy traverses the charged lossy reverse link",
        "Aggregated profiles pass ack_delay_ms and ack_every to Traffic, defaulting to 10 ms and two segments",
        "Profiles with ack_aggregation false delegate to the existing shared-record study entry point",
        "Only copies of the same channel/event ID are deduplicated; distinct duplicate-ACK events remain visible to TCP",
        "Byte-exact ACK reconstruction releases the existing callback with unwrapped sequence and sub-millisecond timestamps",
        "Serialized TCP timestamps retain millisecond precision; sub-millisecond callback timing is the existing simulator abstraction",
        "Unreceived obsolete ACK events do not prevent confirmation when later cumulative ACKs acknowledge every segment",
        "All-segment deadline cohorts include censored submissions and the joint target requires complete confirmation",
        "Optional independent TCP SYN probes start after minimum warmup and a measured stability gate, use distinct connection four-tuples and share the forward coding transport and both FIFO links with bulk traffic",
        "Default stability requires three consecutive one-second windows with throughput range at most three percent of their mean and each direction's mean FIFO queue delay range at most one millisecond, sampled every ten milliseconds",
        "Probe admission ends a full timeout horizon before bulk traffic stops; window diagnostics continue after probe startup and the joint target also requires probe-interval bulk throughput of eighty percent of forward capacity",
        "Probe timing starts at first SYN submission and ends at matching SYN-ACK reception; client and server start with a one-second RTO and exponential backoff unless explicitly configured otherwise",
        "Probe SYN-ACK frames use a charged native full-frame reverse fallback with explicit reverse_copies; pure established ACK batches retain their existing format",
        "Probe final ACK and reset frames traverse forward L2; successful latency quantiles, timeout counts and unresolved bounds are exported separately",
        "The probe endpoint uses the existing 66-byte timestamp-only Ethernet/IPv4/TCP profile, an immediate modeled listener and no kernel or application scheduling cost",
        "Forward framing follows the profile wire_format and compact configuration; the default remains aligned_records",
        "Optional compact_wire uses parsed typed short IDs and charged regular/extended-tail headers over forward UDP or raw IPv4 with CRC32",
        "Packed predictive aligned records preserve exact source-frame bytes; exceptional records retain explicit formats",
        "Optional kind-five timestamp pairs use a fixed 32-entry delta dictionary with exact frame reconstruction and fallback for every unmatched pair; its source-record saving counters use requested encoded bytes",
        "Compact-wire header/CRC counters count requested sends; actual departed forward/reverse bytes determine load and packet-cost metrics",
        "Optional repair trimming removes only encoder padding beyond the maximum encoded source extent in each actual repair support; requested savings are exported separately from departed wire bytes",
        "GF256 recovery uses coefficient elimination and the source-byte ledger; repair-payload arithmetic, CPU and authentication execution are excluded",
    ])
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "experiment.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing task plan or source hashes differ")
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
            print(f"{row['strategy']} full={row['application_goodput_mbps']:.3f} "
                  f"steady={row['steady_application_goodput_mbps']:.3f} "
                  f"ALLACK99={row['with_drain_tcp_all_segment_ack_rtt_cohort_latency_lower_bound_p99_ms']:.2f} "
                  f"reverse={row['reverse_measurement_mbps']:.3f} confirmed={row['fully_confirmed']}", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    fields = list(dict.fromkeys(key for row in rows for key in row))
    write_csv(args.out / "replications.csv", [{key: row.get(key) for key in fields} for row in rows])
    write_csv(args.out / "summary.csv", summarize(rows))
    changed = [name for name, value in hashes.items() if sha256((source_root / name).read_bytes()).hexdigest() != value]
    (args.out / "source-verification.json").write_text(json.dumps(dict(changed_during_run=changed), indent=2) + "\n")


if __name__ == "__main__":
    main()
