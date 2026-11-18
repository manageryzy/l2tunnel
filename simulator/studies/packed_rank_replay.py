"""Compare exact held-time state across PackedWire rank backends on the unmodified workload."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from struct import pack

from aggregate_ack_deadlines import execute
from l2tunnel_sim.packed_rank import Row
from packed_service_sensitivity import digest, write


def rank_hash(decoder):
    result = sha256()
    for i in sorted(decoder.known):
        result.update(pack("!I", i))
    result.update(pack("!II", len(decoder.known), len(decoder.rows)))
    for i, row in sorted(decoder.rows.items()):
        if isinstance(row, Row):
            data = row.values
        else:
            data = bytearray(max(row) - i + 1)
            for j, coefficient in row.items():
                data[j - i] = coefficient
        result.update(pack("!II", i, len(data)))
        result.update(data)
    return result.hexdigest()


class PrefixComplete(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--curve", type=Path, required=True)
    parser.add_argument("--rank-backend", choices=("reference", "dense"), required=True)
    parser.add_argument("--at", type=float, nargs="+", required=True)
    parser.add_argument("--prefix-only", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.manifest.read_text())["jobs"]
    task, = [j["executed_task"] for j in plan if j["result"].endswith("-original.json")]
    if not all(0 < t <= task["duration_s"] for t in args.at) or args.at != sorted(set(args.at)):
        parser.error("checkpoints must be increasing unique positive times within the traffic duration")
    args.out.mkdir(parents=True, exist_ok=False)
    task["packed_decoder_curve"] = json.loads(args.curve.read_text())["curve"]
    task["packed_rank_backend"] = args.rank_backend
    source = Path(__file__).resolve()
    root = source.parents[2]
    sources = [source, source.with_name("aggregate_ack_deadlines.py"),
               *sorted((root / "simulator/src/l2tunnel_sim").glob("*.py"))]
    write(args.out / "manifest.json", dict(task=task, checkpoints=args.at, stop_at_last=args.prefix_only,
          archived_manifest=str(args.manifest), archived_sha256=digest(args.manifest), curve_sha256=digest(args.curve),
          source_sha256={str(p.relative_to(root)): digest(p) for p in sources}))

    def observe(sim, services):
        def snapshot(t):
            state = {}
            for name, queue in services.items():
                transport = queue.transport
                state[name] = dict(
                    arrivals=queue.arrivals, dropped_full=queue.drops, completed=queue.completed,
                    active=queue.active, waiting=len(queue.waiting), peak_waiting=queue.peak_waiting,
                    rank=rank_hash(transport.decoder), prefix=transport.received_prefix, base=transport.base,
                    sender_sources=len(transport.sources), tail=transport.tail_repairs,
                    repair_serial=transport.repair_serial, wait_samples_hash=sha256(
                        queue.waits_us.tobytes()).hexdigest(), work=dict(queue.work),
                    service_demand_us=queue.total_service_us)
            state["flows"] = [[f.tcp_received, f.tcp_acked, len(f.sent_times)] for f in sim.flows]
            state["wire"] = [dict(sum((f.wire[d] for f in sim.flows), Counter())) for d in (False, True)]
            state["erasures"] = [dict(sum((f.erasures[d] for f in sim.flows), Counter())) for d in (False, True)]
            write(args.out / f"state-{t:g}.json", state)
            if args.prefix_only and t == args.at[-1]:
                raise PrefixComplete
        for t in args.at:
            sim.flows[0].at(t, snapshot, t)

    try:
        row = execute(task, observe_packed=observe)
    except PrefixComplete:
        return
    write(args.out / "result.json", row)


if __name__ == "__main__":
    main()
