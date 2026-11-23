"""Run one opt-in, single-flow C48 startup-redundancy study on a paired lossy link."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from unittest.mock import patch

import packed_spare_c48 as c48
from l2tunnel_sim.aggregate_ack import _decode_bounded_varint
from l2tunnel_sim.coding import PRODUCT
from l2tunnel_sim.compact_wire import GLOBAL_WINDOW, SYMBOL_BYTES, _unsigned_varint
from l2tunnel_sim.packed_spare import OUTER


class GroupRow(bytes):
    """Private study union. Existing C48 and near8 wire grammars retain their own discriminators."""


OPTIONS = {
    "control": (0, 0),
    "copy4": (4, 1),
    "xor4": (4, 1),
    "pair8": (8, 2),
    "xor8": (8, 1),
}
MILESTONES = (16, 32, 64, 128, 256)


def row_columns(wire, group_size, rows, floor):
    if len(wire) < 6 or wire[0] != 0xAF:
        raise ValueError("invalid startup row")
    end, pos = _decode_bounded_varint(wire, 1, 2**32 - 1)
    if (
        not 3 < len(wire) - pos <= SYMBOL_BYTES + 3
        or wire[pos] >= rows
        or end < group_size
        or not max(1, floor - GLOBAL_WINDOW) <= end <= floor + GLOBAL_WINDOW
    ):
        raise ValueError("invalid startup support or payload")
    start = end - group_size
    return end, {
        index: 1 if wire[pos] == 0 else index - start + 1 for index in range(start, end)
    }


def encode_equation(originals, ordinal):
    extent = max(len(payload) for _, payload in originals) + 2
    rhs = 0
    for position, (_, payload) in enumerate(originals):
        canonical = len(payload).to_bytes(2, "big") + payload
        factor = 1 if ordinal == 0 else position + 1
        rhs ^= int.from_bytes(canonical.translate(PRODUCT[factor]), "little")
    end = originals[-1][0] + 1
    wire = GroupRow(
        bytes([0xAF])
        + _unsigned_varint(end)
        + bytes([ordinal])
        + rhs.to_bytes(extent, "little")
    )
    encode_us = sum(len(payload) + 2 for _, payload in originals) / 100
    return wire, OUTER + len(wire), encode_us


def run(manifest, option, cap, rate, seed, short):
    task = json.loads(manifest.read_text())["task"]
    task["seed"] = seed
    profile = task["profile"]
    profile.update(
        flow_count=1, payload_rate_mbps=rate, name="Single TCP startup group study"
    )
    profile.pop("tcp_syn_probe", None)
    assert (
        task["forward_mbps"],
        task["reverse_mbps"],
        task["rtt_ms"],
        task["loss_rate"],
        task["loss_model"],
    ) == (100, 10, 70, 0.15, "iid")
    assert (
        profile["window_bytes"],
        task["payload_bytes"],
        profile["compact"]["block_sources"],
        profile["compact"]["repair_window_sources"],
    ) == (4194304, 512, 8192, 128)
    if short:
        task.update(duration_s=1.2, warmup_s=0, drain_s=3)
    counts = Counter()
    milestones = {}
    keys = {}
    snapshots = {}
    extra_finishes = set()
    group_size, rows = OPTIONS[option]
    execute = c48.execute

    def execute_arm(task, observe_packed):
        def init(sim, services):
            observe_packed(sim, services)
            (flow,) = sim.flows
            t = services["forward"].transport
            service = services["forward"]
            (link,) = sim.links[False]
            assert link.jitter == 0

            def point():
                for ki in MILESTONES:
                    if ki not in milestones and flow.tcp_received * 512 >= ki * 1024:
                        milestones[ki] = dict(
                            receiver_ms=flow.now * 1000,
                            receiver_bytes=flow.tcp_received * 512,
                            cwnd=flow.cwnd,
                            acked=flow.tcp_acked,
                        )

            on_data = flow.on_data

            def delivered(*args):
                result = on_data(*args)
                if len(milestones) < len(MILESTONES):
                    point()
                return result

            flow.on_data = delivered
            for when in (0.075, 0.15, 0.30, 0.50, 1.0, 2.0, 12.0):
                t.sim.at(
                    when,
                    lambda when=when: snapshots.update(
                        {
                            when: [
                                flow.tcp_received * 512,
                                flow.tcp_acked * 512,
                                flow.cwnd,
                                flow.tcp_retransmissions,
                            ]
                        }
                    ),
                )
            keys.update(flow=flow, services=services)
            if not group_size:
                return
            extra_rng = Random(seed ^ 0xBEB799B735)
            ordinary_loss = link.erasures.lost

            def choose_loss():
                if t.sim.now not in extra_finishes:
                    return ordinary_loss()
                extra_finishes.remove(t.sim.now)
                lost = extra_rng.random() < 0.15
                counts["erased"] += lost
                return lost

            link.erasures.lost = choose_loss
            # Preserve ordinary forward/reverse iid draws by ordinal. Additional packet losses use an
            # independent iid sequence and the stock link still schedules serialization and propagation.
            packet_decode = service.decode
            packet_cost = service._service_us

            def decode(wire):
                if not isinstance(wire, GroupRow):
                    return packet_decode(wire)
                end, co = row_columns(wire, group_size, rows, t.received_prefix)
                t._notice(end)
                solved = t.decoder.insert(co)
                counts["source_solutions_from_startup_rows"] += len(solved)
                t._new_known(solved)
                t._advance()

            def cost(wire):
                if not isinstance(wire, GroupRow):
                    return packet_cost(wire)
                _, co = row_columns(wire, group_size, rows, t.received_prefix)
                unknown = {i: v for i, v in co.items() if i not in t.decoder.known}
                mixes, updates, probes = service.preview(unknown)
                known = len(co) - len(unknown)
                gf = (known + mixes) * (SYMBOL_BYTES + 2)
                service.work.update(
                    dict(
                        support_positions=group_size,
                        pivot_probes=probes,
                        sparse_coefficient_updates=updates,
                        known_contributions=known,
                        equation_row_mixes=mixes,
                        logical_gf_payload_bytes=gf,
                        repair_jobs=1,
                    )
                )
                return service.cost.charge(gf, group_size + probes + updates)

            service.decode = decode
            service._service_us = cost
            source = t._aligned_source
            originals = []
            started = False
            issued = 0
            credit = 0
            reserved = 0
            pending = 0
            busy = 0

            def emit(selected, size, end, cap_at):
                nonlocal pending
                now = t.sim.now
                if now >= cap_at or t.base >= end:
                    counts["expired_or_already_confirmed"] += 1
                    pending -= 1
                    return
                if link.free_at > now:
                    t.sim.at(
                        min(cap_at, link.free_at + 1e-12),
                        emit,
                        selected,
                        size,
                        end,
                        cap_at,
                    )
                    return

                # One already serialized low-priority packet is the maximum disturbance to later named retries.
                def arrival():
                    counts["reached_receiver"] += 1
                    t._receive_wire(selected)

                finish, _ = t.sim.send(False, size, "startup_extra", arrival)
                extra_finishes.add(finish)
                pending -= 1
                counts["accepted_rows"] += 1
                counts["accepted_ip_bytes"] += size

            def seal(payload):
                nonlocal started, issued, credit, reserved, pending, busy
                source(payload)
                if issued >= cap:
                    return
                if not started:
                    if len(payload) <= 256:
                        return
                    started = True
                index = len(t.sources) - 1
                issued += len(payload)
                ip_size = OUTER + 1 + len(_unsigned_varint(index)) + len(payload)
                credit = min(4 * 1500 * group_size, credit + rows * ip_size)
                originals.append((index, bytes(payload)))
                if len(originals) != group_size:
                    return
                end = index + 1
                for ordinal in range(rows):
                    if option == "copy4":
                        sid, body = originals[0]
                        wire = t.source_wire(sid, body)
                        size = OUTER + 1 + len(_unsigned_varint(sid)) + len(body)
                        encode_us = 0
                    else:
                        wire, size, encode_us = encode_equation(originals, ordinal)
                    if (
                        size > 1500
                        or credit < size * group_size
                        or reserved + size > cap * rows // group_size
                        or pending >= 4
                    ):
                        counts["unfunded_or_full"] += 1
                        continue
                    credit -= size * group_size
                    reserved += size
                    pending += 1
                    counts["reserved_ip_bytes"] += size
                    busy = max(busy, t.sim.now) + encode_us / 1e6
                    t.sim.at(busy + 1e-12, emit, wire, size, end, t.sim.now + 0.005)
                originals.clear()

            t._aligned_source = seal

        return execute(task, observe_packed=init)

    with patch.object(c48, "execute", execute_arm):
        model = c48.run(task, "spare", 8192, 12500000)
    flow = keys["flow"]
    result = model["result"]
    ages = sorted(flow.forward.delays)
    assert (
        not extra_finishes
        and sum(counts[k] for k in ("erased", "reached_receiver"))
        == counts["accepted_rows"]
    )
    drains = {
        k: len(s.transport.sources) - s.transport.base
        for k, s in keys["services"].items()
    }
    return dict(
        configuration=option,
        seed=seed,
        cap_bytes=cap,
        offer_mbps=rate,
        short=short,
        milestone=milestones,
        snapshots=snapshots,
        startup=dict(counts),
        fully_confirmed=result["fully_confirmed"],
        outer_unconfirmed=drains,
        regular_rows=result["compact_wire_regular_repairs"],
        inner_retransmissions=result["tcp_retransmissions"],
        inner_timeouts=result["tcp_timeouts"],
        drained_inner=len(flow.sent_times) - flow.tcp_acked,
        steady_goodput=result["steady_application_goodput_mbps"],
        issued_to_delivered_p99_ms=ages[(len(ages) * 99 + 99) // 100 - 1],
        total_issued=len(ages),
        manifest_sha256=sha256(manifest.read_bytes()).hexdigest(),
        context="Single-connection model with established 512-byte TCP segments, aggregate C48 receiver, authenticated UDP cost and existing near8. Original ranks and named/old-gap service stay enabled. Startup rows have byte-exact data and charged service; decoder target recovery uses the existing known-source ledger. Four pending rows maximum, five ms expiry and the named active coding byte prefix cap. Extra IP costs are bounded by one group row budget share per source, with four-MTU token capacity. Extra draws use their own 15% iid loss stream to preserve ordinary draws by ordinal.",
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--policy", choices=OPTIONS, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=11891353551447149637)
    ap.add_argument("--offer", type=int, default=90)
    ap.add_argument("--prefix", type=int, choices=(65536, 131072), default=131072)
    ap.add_argument("--short", action="store_true")
    args = ap.parse_args()
    if args.output.exists():
        ap.error("receipt already exists")
    answer = run(
        args.manifest, args.policy, args.prefix, args.offer, args.seed, args.short
    )
    with args.output.open("x") as out:
        json.dump(answer, out, indent=2)
        out.write("\n")
