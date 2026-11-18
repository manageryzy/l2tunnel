"""Compare targeted PackedWire repairs against the archived, priced C48 workload."""

import argparse
from collections import Counter
import json
from pathlib import Path

from aggregate_ack_deadlines import execute
from packed_service_sensitivity import ROOT, digest, write


PRIOR = ROOT / "work/frame-channel-study-20261118"
DIRECTIONS = ("forward", "reverse")


def read(path):
    return json.loads(path.read_text())


def require(passed, message):
    if not passed:
        raise ValueError(message)


def archived_task(directory, replication):
    manifest = read(directory / "manifest.json")
    oracle = read(directory / "equivalence.json")
    result = read(directory / "result.json")
    require(digest(directory / "result.json") == oracle["verified_full_result_sha256"],
            "archived completed result digest differs")
    require(digest(directory / "state-5.json") == oracle["identical_full_workload_checkpoint_sha256"]["5"],
            "archived warmup checkpoint differs from the paired rank result")
    previous = ROOT / manifest["archived_manifest"]
    require(digest(previous) == manifest["archived_sha256"], "archived calibration manifest changed")
    original = read(previous)
    plan = ROOT / original["original_task_plan"]
    require(digest(plan) == original["plan_sha256"], "C48 workload plan changed")
    paid = manifest["task"]
    source_task = {k: v for k, v in paid.items() if k not in ("packed_decoder_curve", "packed_rank_backend")}
    task, = [t for t in read(plan)["tasks"] if t["profile"] == paid["profile"] and t["replication"] == replication]
    if replication == 1:
        require(task == source_task, "C48 reference and archived paid task differ")
    require(json.loads(result["profile"]) == paid["profile"] and
            all(result[k] == v for k, v in paid.items() if k != "profile"), "paid result/task mismatch")
    # The new entry point installs an opt-in transport. Verify that the old
    # PackedWire algorithms, cost model, rank kernel, MUX and link still match.
    for name in ("packed_wire", "compact_wire", "compact", "coding", "model", "mux", "mux_tcp",
                 "multiflow", "tcp", "packed_rank", "packed_receiver_service"):
        key = f"simulator/src/l2tunnel_sim/{name}.py"
        require(digest(ROOT / key) == manifest["source_sha256"][key], f"inherited source differs: {key}")
    task.update(packed_decoder_curve=paid["packed_decoder_curve"], packed_rank_backend=paid["packed_rank_backend"],
                packed_targeted_recovery=True)
    return task, result


def track_source_copies(transport):
    """Count repeated policy copies at link departure on their original source kind."""
    count = Counter()
    last = None
    send = transport._send_wire

    def observed(wire, kind, header_bytes):
        nonlocal last
        finish, rtt = send(wire, kind, header_bytes)
        if kind == "source":
            source = len(transport.sources) - 1
            if source == last:
                size = transport.ip_header_bytes + len(wire)
                transport.sim.at(finish, count.update, {"bytes": size, "packets": 1})
            last = source
        return finish, rtt

    transport._send_wire = observed
    return count


def sample(sim, services, copies):
    directions = {}
    for d, direction in enumerate(DIRECTIONS):
        t = services[direction].transport
        endpoints = [getattr(f, "compact_" + direction) for f in sim.flows]
        directions[direction] = dict(
            departed_bytes=dict(sum((f.wire[d] for f in sim.flows), Counter())),
            departed_packets=dict(sum((f.datagrams[d] for f in sim.flows), Counter())),
            source_copy_bytes=copies[direction]["bytes"], source_copy_packets=copies[direction]["packets"],
            unconfirmed_sources=len(t.sources) - t.base, receiver_prefix=t.received_prefix,
            source_count=len(t.sources), unconfirmed_tcp_endpoint_records=sum(
                len(callbacks) for e in endpoints for callbacks in e.records.values()),
            undelivered_mux_frames=sim.mux.submitted_frames[d] - sim.mux.delivered_frames[d],
            target=dict(t.targeted_counts), decoder_waiting=len(services[direction].waiting),
            decoder_active=services[direction].active, decoder_drops=services[direction].drops)
    return dict(directions=directions, forward_tcp_segments_unacked=sum(
        len(f.sent_times) - f.tcp_acked for f in sim.flows), forward_tcp_segments_undelivered=sum(
        len(f.sent_times) - f.tcp_received for f in sim.flows))


def window(before, after):
    by_kind = {k: after["departed_bytes"].get(k, 0) - before["departed_bytes"].get(k, 0)
               for k in sorted(after["departed_bytes"].keys() | before["departed_bytes"].keys())}
    total = sum(by_kind.values())
    require(all(v >= 0 for v in by_kind.values()), "nonmonotone departed bytes")
    repair = by_kind.get("repair", 0) + by_kind.get("retry", 0)
    feedback = by_kind.get("feedback", 0) + by_kind.get("gap_request", 0)
    copies = None if "source_copy_bytes" not in before else after["source_copy_bytes"] - before["source_copy_bytes"]
    if copies is not None:
        require(0 <= copies <= by_kind.get("source", 0), "policy-copy bytes exceed source bytes")
    return dict(departed_bytes=by_kind, total_bytes=total, repair_plus_retry_bytes=repair,
                repair_plus_retry_fraction=repair / total if total else None, feedback_bytes=feedback,
                feedback_fraction=feedback / total if total else None, policy_copy_bytes=copies,
                repair_retry_and_copy_bytes=None if copies is None else repair + copies,
                repair_retry_and_copy_fraction=(repair + copies) / total if copies is not None and total else None)


def row_metrics(row):
    cohort = "with_drain_tcp_application_delivery_cohort_"
    steady = "steady_tcp_application_delivery_cohort_"
    return dict(goodput_mbps=row["steady_application_goodput_mbps"], delivered_in_window=row["steady_delivered_frames"],
                confirmed=row["fully_confirmed"], tcp_all_acknowledged=row["tcp_all_acknowledged"],
                mux_confirmed=row["mux_both_directions_confirmed"],
                delivery_p99_ms=row["with_drain_tcp_application_delivery_p99_ms"],
                cohort_lower_bound_p99_ms=row[cohort + "latency_lower_bound_p99_ms"],
                offered=row[cohort + "offered_segments"], uncensored=row[cohort + "completed_segments"],
                censored=row[cohort + "censored_segments"], ack_rtt_p99_ms=row["with_drain_tcp_all_segment_ack_rtt_p99_ms"],
                postwarmup_cohort_at_offer_end=dict(p99_lower_bound_ms=row[steady + "latency_lower_bound_p99_ms"],
                    offered=row[steady + "offered_segments"], uncensored=row[steady + "completed_segments"],
                    censored=row[steady + "censored_segments"]),
                decoder=row["packed_receiver_service"])


def archived_summary(directory, result):
    start, stop = [read(directory / name) for name in ("state-5.json", "state-90.json")]
    summary = row_metrics(result)
    summary["matched_wire"] = {name: window({"departed_bytes": start["wire"][d]},
                                             {"departed_bytes": stop["wire"][d]}) for d, name in enumerate(DIRECTIONS)}
    summary["traffic_end"] = dict(
        unconfirmed_sources={d: stop[d]["sender_sources"] - stop[d]["base"] for d in DIRECTIONS},
        forward_tcp_segments_unacked=sum(sent - acked for _, acked, sent in stop["flows"]),
        forward_tcp_segments_undelivered=sum(sent - recv for recv, _, sent in stop["flows"]),
        unconfirmed_tcp_endpoint_records=None)
    summary["drain_end"] = dict(unconfirmed_sources={d: 0 for d in DIRECTIONS} if result["mux_both_directions_confirmed"] else None,
                                forward_tcp_segments_unacked=result["offered_frames"] - result["tcp_acked_frames"],
                                unconfirmed_tcp_endpoint_records={d: 0 for d in DIRECTIONS} if result["mux_both_directions_confirmed"] else None)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=PRIOR / "packed-rank-dense-full")
    parser.add_argument("--short", action="store_true", help="1 s warmup, 3 s offering, 3 s drain")
    parser.add_argument("--replication", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    task, original = archived_task(args.archive, args.replication)
    if args.short:
        task.update(warmup_s=1, duration_s=3, drain_s=3)
    args.out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve()
    files = [source, source.with_name("aggregate_ack_deadlines.py"), source.with_name("deadline_metrics.py"),
             *sorted((ROOT / "simulator/src/l2tunnel_sim").glob("*.py"))]
    write(args.out / "manifest.json", dict(task=task, archive=str(args.archive),
          definitions=dict(goodput="Receiver TCP payload delivered between warmup and traffic-end snapshots.",
            delivery_p99="Completed TCP segment delivery from first submission, up to end of drain.",
            cohort_lower_bound="All original segment submissions through traffic end. Unfinished ones contribute age at cutoff.",
            matched_wire="Differences of fully departed outer IP packet bytes at traffic end and warmup, before link loss.",
            repair_plus_retry="Regular and tail repair datagrams plus explicit retained-source retries and quiet probes.",
            feedback="Ordinary cumulative feedback and targeted gap requests on their actual physical direction.",
            policy_copy="Repeated short source bytes included in the source wire kind; separately tagged at departure.",
            tcp_endpoint_records="Submitted but not delivered TCP frame callbacks, counting each frame including repeated frames.",
            tcp_segments="The inner workload carries TCP payload only forward. Reverse TCP endpoint records are ACK frames."),
          source_sha256={str(f.relative_to(ROOT)): digest(f) for f in files},
          archived_sha256={f: digest(args.archive / f) for f in ("result.json", "manifest.json", "equivalence.json",
                                                                  "state-5.json", "state-90.json")}))
    write(args.out / "archived-full-summary.json", archived_summary(args.archive, original))
    snapshots = {}
    owners = {}

    def observe(sim, services):
        from l2tunnel_sim.packed_targeted import TargetedPackedWireTransport
        require(all(isinstance(s.transport, TargetedPackedWireTransport) for s in services.values())
                and len(services) == 2, "targeted recovery not attached to both paid receivers")
        copies = {d: track_source_copies(s.transport) for d, s in services.items()}
        owners.update(sim=sim, services=services, copies=copies)

        def snapshot(label):
            snapshots[label] = sample(**owners)
            write(args.out / f"{label}.json", snapshots[label])

        for t, label in ((task["warmup_s"], "warmup_end"), (task["duration_s"], "traffic_end")):
            sim.flows[0].at(t, snapshot, label)

    row = execute(task, observe_packed=observe)
    write(args.out / "result.json", row)
    final = sample(**owners)
    write(args.out / "drain_end.json", final)
    measured = row_metrics(row)
    measured["matched_wire"] = {d: window(snapshots["warmup_end"]["directions"][d],
                                          snapshots["traffic_end"]["directions"][d]) for d in DIRECTIONS}
    measured["traffic_end"] = snapshots["traffic_end"]
    measured["drain_end"] = final
    require(sum(d["departed_bytes"].get("gap_request", 0) for d in final["directions"].values()) > 0,
            "no targeted request departed on either physical link")
    write(args.out / "summary.json", measured)


if __name__ == "__main__":
    main()
