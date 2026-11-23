"""Run a single paced RACK/DSACK TCP stream over horizontally coded physical paths."""
import argparse
from collections import Counter
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "simulator/src"))
from aggregate_ack_deadlines import make_simulation
from l2tunnel_sim.compact import tcp_profile_frame
from l2tunnel_sim.mux_tcp import bulk_connection_frame
from l2tunnel_sim.path_transport import PathConfig, PathNetwork
from l2tunnel_sim.tcp_application import PacedSocketWriter


def simulate(task, cfg, segments):
    profile = task["profile"]
    if profile["flow_count"] != 1 or profile["c48_tcp_sack_recovery"] != "rack-dsack":
        raise ValueError("expected one RACK/DSACK TCP stream")
    sim = make_simulation(task)
    flow, = sim.flows
    endpoints = flow.compact_forward, flow.compact_reverse
    headers = tuple(bulk_connection_frame(tcp_profile_frame(payload_bytes=0), ep.port, ep.reverse)[:14]
                    for ep in endpoints)
    def receive_ack(ip):
        endpoints[1].receive(headers[1] + ip)
        net.audit.ack_progress(flow.byte_offset(flow.tcp_acked), flow.now)

    def receive_data(ip):
        endpoints[0].receive(headers[0] + ip)
        net.audit.receiver_progress(flow.byte_offset(flow.tcp_received), flow.now)

    deliver = (receive_data, receive_ack)
    net = PathNetwork(flow, cfg, task["seed"], deliver, (task["warmup_s"],task["duration_s"]))

    def submit(reverse, frame):
        if frame[:14] != headers[reverse]:
            raise ValueError("unexpected link header at single-flow IPv4 TUN boundary")
        net.directions[reverse].submit(frame[14:])

    sim.mux.submit_frame = submit
    writer = PacedSocketWriter(flow, profile["c48_application_credit_bytes"],
                               int(profile["payload_rate_mbps"] * 1000000), segments,
                               tcp_mss=profile["c48_tcp_mss"])
    flow.enable_sack("rack-dsack", writer)
    rack_service = flow.rack.service

    def observe_rack(*args, **kwargs):
        net.audit.rack_context = True
        try:
            return rack_service(*args, **kwargs)
        finally:
            net.audit.rack_context = False

    flow.rack.service = observe_rack
    checkpoints = {}

    def checkpoint(label):
        checkpoints[label] = dict(time=flow.now, delivered_tcp_bytes=flow.byte_offset(flow.tcp_received),
                                 inner_retrans=flow.tcp_retransmissions, rtos=flow.tcp_timeouts,
                                 cwnd=flow.cwnd, writer=writer.outstanding(),
                                 paid=[dict(c) for c in net.totals],
                                 path_events=[dict(sum((lane.counts for lane in side.lanes), Counter()))
                                              for side in net.directions])
    flow.at(task["warmup_s"], checkpoint, "begin")
    flow.at(task["duration_s"], checkpoint, "end")
    sim.run()
    app = writer.report()
    beg, end = checkpoints["begin"], checkpoints["end"]
    steady_ip, directions = {}, {}
    for rev, name in ((False, "forward"), (True, "reverse")):
        before, after = beg["paid"][rev], end["paid"][rev]
        dc = Counter(after)
        dc.subtract(before)
        steady_ip[name] = dict(dc)
        t = net.directions[rev]
        events = Counter(end["path_events"][rev])
        events.subtract(beg["path_events"][rev])
        directions[name] = dict(counters=dict(t.counts), lifetime_departed=dict(net.totals[rev]),
                                socket_to_serialization=net.socket_delay_report(rev),
                                steady_physical_events={k:v for k,v in events.items()
                                    if k.startswith(("physical_loss_", "physical_retired_", "physical_late_"))},
                                path_counters=[dict(lane.counts) for lane in t.lanes],
                                data_pn_next=[lane.next_pn for lane in t.lanes],
                                control_pn_next=[lane.control_pn for lane in t.lanes],
                                admitted=t.next_group, sender_prefix=t.tx_prefix, receiver_prefix=t.rx_prefix,
                                sender_unconfirmed=len(t.tx), receiver_missing=t.next_group - t.rx_prefix - len(t.rx_complete),
                                repair_requests_pending=len(t.gap_due), unadmitted=len(t.waiting),
                                physical_active=sum(l.active for l in t.arq),
                                physical_queued=(len(t.service.owners) + sum(map(len, t.service.debt.values()))
                                    if t.service else sum(len(l.repairs)+len(l.waiting) for l in t.arq)),
                                control_pending=(len(t.service.requests)+int(t.service.standalone_due)
                                    +int(bool(getattr(t.service, "chosen", None)))) if t.service else 0,
                                unsent_entries=sum(len(lane.entries)+(len(lane.ready[0]) if lane.ready else 0)
                                                   for lane in t.lanes))
    confirmed = (app["end_unconfirmed"] == 0 and app["end_unsent"] == 0 and
                 app["fully_read"] == app["written_records"] and not any(ep.records for ep in endpoints) and
                 all(d["admitted"] == d["sender_prefix"] == d["receiver_prefix"] and
                     not (d["sender_unconfirmed"] or d["unadmitted"] or d["unsent_entries"] or
                          d["physical_active"] or d["physical_queued"] or d["control_pending"])
                     for d in directions.values()))
    return dict(seed=task["seed"], n=cfg.n, k=cfg.k, config=asdict(cfg),
                conditions={k:task[k] for k in ("forward_mbps","reverse_mbps","rtt_ms","loss_model","loss_rate",
                                                 "payload_bytes","warmup_s","duration_s","drain_s")},
                writer_offer_mbps=profile["payload_rate_mbps"], writer_credit=writer.credit,
                inner_mss=flow.smss_bytes, inner_flow_count=1, steady_departure=steady_ip,
                goodput_mbps=(end["delivered_tcp_bytes"]-beg["delivered_tcp_bytes"])*8e-6/
                             (task["duration_s"]-task["warmup_s"]),
                steady_inner_retrans=end["inner_retrans"]-beg["inner_retrans"],steady_rtos=end["rtos"]-beg["rtos"],
                readout=app,checkpoints=checkpoints,directions=directions,fully_confirmed=confirmed,
                rack=dict(flow.sack_sender.stats),rack_trigger_observations=dict(net.audit.rack),
                rack_examples=net.audit.examples,
                paid_timeline={name:net.audit.report(side) for side,name in enumerate(("forward","reverse"))},
                scope="Established synthetic single Linux-like TCP stream. Every actual IPv4 TUN input is split "
                      "before independent path batching; coding and packet parsing operate on real bytes. One "
                      "shared serialization budget per direction, separately seeded physical path erasures. "
                      "Group confirmations retain old holes; physical receipt floors do not release group custody. "
                      "Codec and path handling have zero modeled CPU cost; UDP/IP/security envelope charged 49 B. "
                      "This raw-IPv4 study does not use the prior Packed header compression or measured Linux sockets.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--n", required=True, type=int)
    parser.add_argument("--k", required=True, type=int)
    parser.add_argument("--hold-us", type=int, default=500)
    parser.add_argument("--max-entries", type=int, default=255)
    parser.add_argument("--proactive", action="store_true")
    parser.add_argument("--rank-requests", action="store_true")
    parser.add_argument("--a3-request-copies", type=int, default=1)
    parser.add_argument("--a3-reply-copies", type=int, default=1)
    parser.add_argument("--physical-recovery", action="store_true")
    parser.add_argument("--shared-pending", action="store_true")
    parser.add_argument("--link-ethernet", action="store_true", help="Charge 14 Ethernet header bytes on every packet before physical loss")
    parser.add_argument("--paced-recovery", action="store_true", help="Share one Ethernet byte pacer, measure physical RTT and repeat positive selective evidence once")
    parser.add_argument("--loss-rates", type=float, nargs=2, metavar=("FORWARD", "REVERSE"))
    parser.add_argument("--early-forward", action="store_true")
    opts = parser.parse_args()
    if opts.output.exists():
        raise FileExistsError(opts.output)
    reference = opts.reference.read_bytes()
    prior = json.loads(reference)
    task = prior["task"]
    cfg = PathConfig(opts.n, opts.k, (task["mtu"],)*opts.n, (opts.hold_us,)*opts.n,
                     (task["rtt_ms"]/2,)*opts.n, proactive=opts.proactive, rank_requests=opts.rank_requests,
                     loss_rates=tuple(opts.loss_rates) if opts.loss_rates else None, early_forward=opts.early_forward,
                     max_entries=(opts.max_entries,)*opts.n,
                     a3_request_copies=opts.a3_request_copies, a3_reply_copies=opts.a3_reply_copies,
                     physical_recovery=opts.physical_recovery, shared_pending=opts.shared_pending,
                     link_ethernet=opts.link_ethernet, paced_recovery=opts.paced_recovery)
    result = simulate(task, cfg, prior["segments"])
    result["reference_sha256"] = sha256(reference).hexdigest()
    with opts.output.open("x") as f:
        json.dump(result,f,indent=2)
        f.write("\n")
    print(opts.output.name,result["goodput_mbps"],result["readout"]["write_to_read_ms"]["p99"],
          result["steady_inner_retrans"],result["fully_confirmed"],flush=True)


if __name__ == "__main__":
    main()

