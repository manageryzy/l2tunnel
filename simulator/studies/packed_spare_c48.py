"""Run a frozen C48 task with authenticated UDP prices and an optional forward near8 row."""
import argparse
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "simulator/src"))

from aggregate_ack_deadlines import execute
from l2tunnel_sim.tcp import PlainTCP
from l2tunnel_sim.tcp_sack import POLICIES as SACK_POLICIES
from packed_spare_pricing import install as price_udp
from packed_spare_study import NearStudy


def run(task, policy, segments, pacer):
    adapters = []
    writer = None
    ack_codec = None
    wire_pricing = None
    striped = None
    fixed_anchor = None
    cutoff = {}
    sack_policy = task["profile"].get("c48_tcp_sack_recovery")
    if sack_policy is not None and (sack_policy not in SACK_POLICIES or
                                    "c48_tcp_mss" not in task["profile"] or not task["profile"].get("mux")):
        raise ValueError("C48 SACK requires a duplex MUX, explicit stream MSS and supported SACK policy")
    tail_transports = {}
    fair_reverse = task["profile"].get("c48_striped_fair_reverse_probes", False)
    short_prefix = task["profile"].get("c48_striped_short_prefix", False)
    split_triples = task["profile"].get("c48_striped_split_triples", False)
    if split_triples and (policy != "striped-cauchy" or not short_prefix):
        raise ValueError("short-group split repair requires mixed packets and ordinary prefix selection")
    variable_parity = task["profile"].get("c48_striped_variable_parity_forward", False)
    startup_anchor_copy = task["profile"].get("c48_striped_startup_anchor_copy", False)
    if startup_anchor_copy and (policy != "striped-cauchy" or not task["profile"].get("c48_forward_fixed_anchor")):
        raise ValueError("startup anchor copies require the mixed path and forward fixed anchors")
    forward_unit = task["profile"].get("c48_striped_forward_unit_bytes")
    forward_hold = task["profile"].get("c48_striped_forward_hold_us")
    forward_geometry = task["profile"].get("c48_striped_forward_geometry")
    reverse_unit = task["profile"].get("c48_striped_reverse_unit_bytes")
    rank_requests = task["profile"].get("c48_striped_rank_requests", False)
    timing = task["profile"].get("c48_striped_timing", "study")
    if timing not in ("study", "rust-single-flow"):
        raise ValueError("unsupported mixed timing profile")
    if timing == "rust-single-flow" and (policy != "striped-cauchy" or task["profile"]["flow_count"] != 1
            or fair_reverse or task["profile"].get("c48_striped_frontier_requests")):
        raise ValueError("Rust single-flow timing requires one mixed flow with its own feedback and quiet policy")
    if (variable_parity or forward_unit is not None or forward_hold is not None
            or forward_geometry is not None or reverse_unit is not None or rank_requests) and policy != "striped-cauchy":
        raise ValueError("forward mixed options require the striped path")
    if short_prefix and policy != "striped-cauchy":
        raise ValueError("short prefix groups require the mixed path")
    frontier_requests = task["profile"].get("c48_striped_frontier_requests", False)
    if frontier_requests and (policy != "striped-cauchy" or
                              not task["profile"].get("c48_forward_fifo_gap_observation")):
        raise ValueError("striped frontier requests require the mixed path and forward FIFO observation")
    if fair_reverse and policy != "striped-cauchy":
        raise ValueError("fair reverse quiet probes require the striped Cauchy profile")
    if "c48_tcp_mss" in task["profile"] and "c48_application_credit_bytes" not in task["profile"]:
        raise ValueError("stream packetization requires an explicit application credit limit")
    def attach(sim, services):
        nonlocal writer, ack_codec, wire_pricing, striped, fixed_anchor
        if task["profile"].get("c48_forward_fifo_gap_observation", False):
            services["forward"].observe_fifo_gaps()
        if task["profile"].get("c48_native_udp_packing", False):
            for service in services.values():
                # Original UDP Common reserves the carrier, protection and maximum identity bytes.
                service.transport.select_packing_geometry(task["mtu"] - 28 - 21 - 200, 8)
        if task["profile"].get("c48_fragment_tail_packing", False):
            if set(services) != {"forward", "reverse"}:
                raise ValueError("fragment tail packing requires both Packed receiver services")
            for direction, service in services.items():
                service.transport.enable_fragment_tail_packing()
                tail_transports[direction] = service.transport
        if policy == "spare":
            selection = task["profile"].get("c48_idle_prefix")
            adapters.append(NearStudy(sim, services, pacer, selection) if selection is not None
                            else NearStudy(sim, services, pacer))
        if task["profile"].get("c48_reverse_ack_lz4", False):
            from l2tunnel_sim.packed_ack_lz4 import ShortAckBlocks
            reverse = services["reverse"].transport
            if not reverse.reverse or reverse.c48_union:
                raise ValueError("expected the study's reverse Packed transport")
            ack_codec = ShortAckBlocks(reverse.packing_bytes, reverse.config.independent_short_frame_bytes,
                                       task["profile"]["mux"]["channels"])
            reverse.source_wire_codec = ack_codec
        _, _, wire_pricing = price_udp(sim, services)
        if policy == "striped-cauchy":
            from l2tunnel_sim.striped_cauchy import Geometry
            from packed_striped_path import StripedPath
            if set(services) != {"forward", "reverse"} or not task.get("packed_targeted_recovery"):
                raise ValueError("striped Cauchy requires duplex Packed services with old-hole custody")
            geometry = Geometry(*task["profile"].get("c48_striped_geometry", (4, 1)))
            forward = Geometry(*forward_geometry) if forward_geometry is not None else geometry
            striped = {direction: StripedPath(service, forward if direction == "forward" else geometry)
                       for direction, service in services.items()}
            if variable_parity:
                striped["forward"].select_variable_parity()
            if forward_unit is not None or forward_hold is not None:
                striped["forward"].select_forward_batch(forward_unit, forward_hold)
            if reverse_unit is not None:
                striped["reverse"].select_batch(reverse_unit, None)
            striped["reverse"].fair_reverse_probes = fair_reverse
            striped["forward"].startup_anchor_copy = startup_anchor_copy
            striped["forward"].protect_split_triples = split_triples
            for direction in striped.values():
                direction.short_prefix_groups = short_prefix
                direction.install()
            if rank_requests and (forward.k, forward.m) != (10, 2):
                raise ValueError("rank-limited requests require forward 12/10 mixed geometry")
            if timing == "rust-single-flow":
                from packed_striped_timing import PaidTimers
                for direction, path in striped.items():
                    PaidTimers(path, rank_requests and direction == "forward").install()
            elif rank_requests:
                striped["forward"].select_rank_requests()
            if frontier_requests:
                from packed_striped_prefix import install as expedite_prefix
                expedite_prefix(striped["forward"])
        if adapters:
            adapters[0].enable()
        if task["profile"].get("c48_forward_fixed_anchor", False):
            from l2tunnel_sim.fixed_anchor_ip import enable_forward_fixed_anchor
            if "forward" not in services:
                raise ValueError("fixed anchors require a forward Packed transport")
            fixed_anchor = enable_forward_fixed_anchor(services["forward"].transport, interval=8)
        if "c48_application_credit_bytes" in task["profile"]:
            from l2tunnel_sim.tcp_application import PacedSocketWriter
            if sim.flow_count != 1:
                raise ValueError("the native application writer comparison requires one forward TCP flow")
            flow, = sim.flows
            rate = task["profile"]["payload_rate_mbps"] * 1_000_000
            if rate != int(rate):
                raise ValueError("application offer must be an integer bit rate")
            writer = PacedSocketWriter(flow, task["profile"]["c48_application_credit_bytes"], int(rate), segments,
                                       tcp_mss=task["profile"].get("c48_tcp_mss"))
            if sack_policy is not None:
                flow.enable_sack(sack_policy, writer)
            def snapshot(label):
                cutoff[label] = writer.outstanding()
            for label, at in (("warm", task["warmup_s"]), ("cut", task["duration_s"])):
                flow.at(at, snapshot, label)

    ordinary = PlainTCP.produce
    def capped_issue(flow):
        # The original producer samples its issue limit once, before sending.
        # ACK and congestion-control callbacks retain their original window.
        limit = flow.window_limit
        flow.window_limit = min(segments, limit)
        try:
            return ordinary(flow)
        finally:
            flow.window_limit = limit

    try:
        with patch.object(PlainTCP, "produce", capped_issue):
            result = execute(task, observe_packed=attach)
    finally:
        observation = adapters[0].finish() if adapters else None
    report = dict(task=task, policy=policy, segments=segments, sender_ip_bytes_per_second=pacer,
                  result=result, near=observation)
    if task["profile"].get("c48_native_udp_packing", False):
        report["offered_ip_packets"] = wire_pricing
    if striped is not None:
        report["striped_cauchy"] = {name: path.report() for name, path in striped.items()}
    if fixed_anchor is not None:
        report["forward_fixed_anchor"] = dict(interval=8, counts=dict(fixed_anchor.counts))
    if tail_transports:
        report["fragment_tail_packing"] = {
            direction: dict(transport.fragment_tail_stats, source_count=len(transport.sources),
                            confirmed_source_prefix=transport.base, pending_pack_bytes=transport.pending_pack_bytes)
            for direction, transport in tail_transports.items()
        }
    if ack_codec is not None:
        report["reverse_ack_lz4"] = dict(**ack_codec.physical,
                                         source_encode_calls=dict(ack_codec.representations))
    if writer is not None:
        report["application_writer"] = dict(**writer.report(), checkpoints=cutoff)
        if sack_policy is not None:
            flow = writer.flow
            score = flow.sack_sender
            report["tcp_sack_recovery"] = dict(policy=sack_policy, sent=dict(flow.sack_frame_bytes_sent),
                received=dict(flow.sack_frame_bytes_received), scoreboard=dict(score.stats) if score else None,
                capacity_segments=score.capacity if score else None,
                remaining_selective_segments=score.sacked.bit_count() if score else None)
        report["result"]["fully_confirmed"] &= report["application_writer"]["end_unconfirmed"] == 0
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="C48 JSON manifest with a task")
    parser.add_argument("--output", required=True, type=Path, help="new receipt")
    parser.add_argument("--policy", required=True, choices=("control", "spare", "striped-cauchy"))
    parser.add_argument("--striped-geometry", nargs=2, type=int, metavar=("K", "M"),
                        help="use K original and M parity cells per forward physical datagram")
    parser.add_argument("--striped-fair-reverse-probes", action="store_true",
                        help="rotate alternate quiet probes within the oldest reverse datagram's byte budget")
    parser.add_argument("--forward-fixed-anchor", action="store_true",
                        help="encode forward IPv4 TCP records against an explicit retained channel anchor")
    parser.add_argument("--segments", required=True, type=int, choices=(125, 512, 8192))
    parser.add_argument("--forward-support", choices=("legacy", "fixed", "confirmed_prefix"),
                        help="explicit forward C48 recovery profile (default from the manifest)")
    parser.add_argument("--tcp-data-paws", action="store_true",
                        help="apply the Linux 6.8 established DATA PAWS model at the inner receiver")
    parser.add_argument("--tcp-newreno-ack-heuristic", action="store_true",
                        help="enable RFC 6582 section 4.1 cumulative-ACK fast retransmit inside recover")
    parser.add_argument("--tcp-sack-recovery", choices=SACK_POLICIES,
                        help="send reverse wire SACKs and optionally enable selective retry and proven DSACK undo")
    parser.add_argument("--striped-frontier-requests", action="store_true",
                        help="advance a paid named mask on a one-degree deficit in the oldest mixed group")
    parser.add_argument("--striped-short-prefix", action="store_true",
                        help="keep contiguous MTU-fitting groups inside a frozen, oversized short batch")
    parser.add_argument("--striped-variable-parity-forward", action="store_true",
                        help="use the length-aware one-erasure wire profile for ordinary forward groups")
    parser.add_argument("--striped-startup-anchor-copy", action="store_true",
                        help="repeat one mixed member after 1 ms for complete forward contexts in sources 0..127")
    parser.add_argument("--striped-forward-geometry", nargs=2, type=int, metavar=("K", "M"),
                        help="override the forward data and parity cells; preserve reverse geometry")
    parser.add_argument("--striped-rank-requests", action="store_true",
                        help="name only the residual rank on the forward 12/10 mixed path")
    parser.add_argument("--striped-timing", choices=("study", "rust-single-flow"),
                        help="select original study clocks or paid Rust single-flow feedback and quiet timers")
    parser.add_argument("--striped-reverse-unit-bytes", type=int,
                        help="set the reverse Packed unit limit before admission")
    parser.add_argument("--striped-forward-unit-bytes", type=int,
                        help="select the forward Packed symbol limit inside the mixed wire budget")
    parser.add_argument("--striped-split-triples", action="store_true",
                        help="add cross-source parity to three MTU-limited split sources in one due batch")
    parser.add_argument("--striped-forward-hold-us", type=int,
                        help="bound the forward group hold in microseconds from the first source")
    parser.add_argument("--tcp-partial-timestamp-undo", action="store_true",
                        help="restore the modeled window on the first partial ACK echoing an original before a fast retry")
    parser.add_argument("--application-credit-bytes", type=int,
                        help="pace single-flow application writes and cap unsent plus unacknowledged bytes")
    parser.add_argument("--tcp-mss", type=int,
                        help="segment available written bytes up to this inner MSS when the TCP window opens")
    parser.add_argument("--native-udp-packing", action="store_true",
                        help="use the native UDP 1251-byte Packed symbol and at most eight units per source")
    parser.add_argument("--fragment-tail-packing", action="store_true",
                        help="let full first fragments pass same-copy final fragments until their original deadline")
    parser.add_argument("--reverse-ack-lz4", action="store_true",
                        help="compress each eligible reverse short-ACK source independently on the wire")
    parser.add_argument("--idle-prefix", choices=("historical-control", "historical-idle",
                                                  "startup-control", "startup-idle"),
                        help="compare optional startup idle XOR rows under the selected near8 gate")
    parser.add_argument("--sender-ip-bytes-per-second", type=int, default=12_500_000)
    options = parser.parse_args()
    if options.output.exists():
        parser.error("receipt already exists")
    task = json.loads(options.manifest.read_text())["task"]
    if options.forward_fixed_anchor:
        task["profile"]["c48_forward_fixed_anchor"] = True
    if options.striped_fair_reverse_probes:
        if options.policy != "striped-cauchy":
            parser.error("--striped-fair-reverse-probes requires --policy striped-cauchy")
        task["profile"]["c48_striped_fair_reverse_probes"] = True
    if options.striped_geometry is not None:
        if options.policy != "striped-cauchy":
            parser.error("--striped-geometry requires --policy striped-cauchy")
        task["profile"]["c48_striped_geometry"] = options.striped_geometry
    if options.forward_support is not None:
        task["profile"]["compact"]["c48_forward_repair_support"] = options.forward_support
    if options.tcp_data_paws:
        task["profile"]["tcp_data_paws"] = True
    if options.tcp_partial_timestamp_undo:
        task["profile"]["tcp_partial_timestamp_undo"] = True
    if options.tcp_newreno_ack_heuristic:
        task["profile"]["tcp_newreno_ack_heuristic"] = True
    if options.tcp_sack_recovery:
        task["profile"]["c48_tcp_sack_recovery"] = options.tcp_sack_recovery
    if options.striped_frontier_requests:
        task["profile"]["c48_striped_frontier_requests"] = True
        task["profile"]["c48_forward_fifo_gap_observation"] = True
    if options.striped_short_prefix:
        task["profile"]["c48_striped_short_prefix"] = True
    if options.striped_split_triples:
        task["profile"]["c48_striped_split_triples"] = True
    if options.striped_variable_parity_forward:
        task["profile"]["c48_striped_variable_parity_forward"] = True
    if options.striped_startup_anchor_copy:
        task["profile"]["c48_striped_startup_anchor_copy"] = True
    if options.striped_forward_geometry is not None:
        task["profile"]["c48_striped_forward_geometry"] = options.striped_forward_geometry
    if options.striped_rank_requests:
        task["profile"]["c48_striped_rank_requests"] = True
    if options.striped_timing is not None:
        task["profile"]["c48_striped_timing"] = options.striped_timing
    if options.striped_reverse_unit_bytes is not None:
        task["profile"]["c48_striped_reverse_unit_bytes"] = options.striped_reverse_unit_bytes
    if options.striped_forward_unit_bytes is not None:
        task["profile"]["c48_striped_forward_unit_bytes"] = options.striped_forward_unit_bytes
    if options.striped_forward_hold_us is not None:
        task["profile"]["c48_striped_forward_hold_us"] = options.striped_forward_hold_us
    if options.application_credit_bytes is not None:
        task["profile"]["c48_application_credit_bytes"] = options.application_credit_bytes
    if options.tcp_mss is not None:
        task["profile"]["c48_tcp_mss"] = options.tcp_mss
    if options.native_udp_packing:
        task["profile"]["c48_native_udp_packing"] = True
    if options.fragment_tail_packing:
        task["profile"]["c48_fragment_tail_packing"] = True
    if options.reverse_ack_lz4:
        task["profile"]["c48_reverse_ack_lz4"] = True
    if options.idle_prefix:
        if options.policy != "spare":
            parser.error("--idle-prefix requires --policy spare")
        task["profile"]["c48_idle_prefix"] = options.idle_prefix
    result = run(task, options.policy, options.segments, options.sender_ip_bytes_per_second)
    with options.output.open("x") as f:
        json.dump(result, f, indent=2, default=lambda value: value.item())
        f.write("\n")


if __name__ == "__main__":
    main()
