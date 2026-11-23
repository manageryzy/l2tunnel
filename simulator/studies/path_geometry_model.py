#!/usr/bin/env python3
"""Offline N/K erasure and wire-cost model, calibrated against a saved path-bundle Linux trace."""

import argparse
from collections import Counter, defaultdict
import csv
from functools import lru_cache
import hashlib
from itertools import combinations
import json
from math import ceil, sqrt
from pathlib import Path
from statistics import NormalDist, mean, pstdev, stdev

OUTER = 49  # IPv4/UDP + route + authenticated PN/tag in path-bundle-lab.
ROLE = {"fresh_paid", "named_paid", "quiet_paid", "named_copy_paid", "path_retry_paid"}


@lru_cache(maxsize=512)
def poisson_binomial(probabilities):
    """Mass of the number lost, with independently erased, possibly unequal paths."""
    mass = [1.0]
    for p in probabilities:
        if not 0 <= p <= 1:
            raise ValueError("loss probability outside [0,1]")
        mass = [v * (1 - p) + w * p for v, w in zip([*mass, 0], [0, *mass])]
    return mass


def risks(probabilities, k, common=0):
    """A common erasure event wipes the group; the IID residual preserves each marginal."""
    n = len(probabilities)
    if not 1 <= k <= n or not 0 <= common <= min(probabilities) or common >= 1:
        raise ValueError("invalid K or probability for the common loss event")
    mass = [
        v * (1 - common)
        for v in poisson_binomial(
            tuple((p - common) / (1 - common) for p in probabilities)
        )
    ]
    mass[n] += common
    r = n - k
    return sum(mass[r + 1 :]), sum(
        (lost - r) * mass[lost] for lost in range(r + 1, n + 1)
    )


def uint_len(n):
    return max(1, (n.bit_length() + 6) // 7)


def shard_shape(n, k, size, index):
    largest = ceil(size / n)
    parity = (n - k) * ceil((largest + 2) / k)
    direct = size * (index + 1) // n - size * index // n
    return uint_len(size) + direct + parity


def wire(n, k, size, mtu, batch, gid, pn, cross=False, lane_weights=None):
    """Fresh or repair-only DATA; no feedback tail. Return amortized group IP and packet counts."""
    fixed = OUTER + 3 + uint_len(pn)
    bytes_per_group = packets_per_group = 0.0
    # Horizontal partitions have at most two lengths, even when hundreds of paths are considered.
    direct, remainder = divmod(size, n)
    smallest_body = shard_shape(n, k, size, 0)
    if not lane_weights or min(lane_weights) == max(lane_weights):
        weight = 1 if lane_weights is None else lane_weights[0]
        groups = [(direct, (n - remainder) * weight), (direct + 1, remainder * weight)]
    else:
        groups = [
            (size * (i + 1) // n - size * i // n, w) for i, w in enumerate(lane_weights)
        ]
    for length, weight in groups:
        if not weight:
            continue
        body = smallest_body + length - direct
        if (
            body > mtu - OUTER - 27
        ):  # Public transmitter reserves its worst-case entry header.
            return None
        extent = uint_len(gid) + uint_len(body * 2 + int(cross)) + int(cross) + body
        fit = min(255, (mtu - fixed) // extent)
        if fit <= 0:
            return None
        occupancy = min(batch, fit)
        packets_per_group += weight / occupancy
        bytes_per_group += weight * (extent + fixed / occupancy)
    return bytes_per_group, packets_per_group


def wilson(failed, n, z):
    p = failed / n
    norm = 1 + z * z / n
    m = (p + z * z / (2 * n)) / norm
    d = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / norm
    return max(0, m - d), min(1, m + d)


def summarize_capture(case, direction):
    peer = "b" if direction == "a" else "a"
    report = json.loads((case / "result.json").read_text())
    n = report["request"]["physical_udp_paths"]
    k = report["request"]["coding_threshold"]

    def rows(side):
        p = case / f"{side}-trace.csv"
        with p.open("rb") as f:
            digest = hashlib.file_digest(f, "sha256").hexdigest()
        assert (
            digest == report["adapter_trace"][side]["sha256"]
            and report["adapter_stats"][side]["trace"]["dropped"] == 0
        )
        with p.open() as f:
            yield from csv.DictReader(f)

    paid = {}
    fresh = defaultdict(dict)
    observed = set()
    for r in rows(direction):
        if r["event"] not in ROLE:
            continue
        key = int(r["path"]), int(r["data_seq"])
        pn = int(r["auth_pn"])
        packet = paid.setdefault(key, [pn, 0, 0])
        assert packet[0] == pn
        is_fresh = r["event"] == "fresh_paid"
        packet[1 if is_fresh else 2] += 1
        if is_fresh:
            g = int(r["generation"])
            ordinal = int(r["ordinal"])
            assert ordinal not in fresh[g] and ordinal == key[0]
            fresh[g][ordinal] = key
    for r in rows(peer):
        if r["event"] == "shard_rx":
            key = int(r["path"]), int(r["data_seq"])
            assert paid[key][0] == int(r["auth_pn"])
            observed.add(key)
    stats = report["adapter_stats"][direction]
    s = stats["paths"]
    assert list(sorted(fresh)) == list(range(stats["next_generation"]))
    ranks = []
    lost_rows = []
    shared = Counter()
    for g in range(len(fresh)):
        assert set(fresh[g]) == set(range(n))
        lost = [int(fresh[g][i] not in observed) for i in range(n)]
        lost_rows.append(lost)
        ranks.append(n - sum(lost))
        if g:
            shared[sum(fresh[g][i] == fresh[g - 1][i] for i in range(n))] += 1
    failed = [r < k for r in ranks]
    short = sum(max(0, k - r) for r in ranks)
    # Physical DATA denominators: one socket-paid path DATA seq, irrespective of batch occupancy.
    lanes = []
    z = NormalDist().inv_cdf(1 - 0.05 / (2 * n))
    for i, st in enumerate(s):
        physical = sorted(
            (sn, key not in observed) for key in paid for slot, sn in [key] if slot == i
        )
        assert [sn for sn, _ in physical] == list(range(st["data_packets"]))
        bits = [int(v) for _, v in physical]
        drops = sum(bits)
        remaining = zip(bits, bits[1:])
        after = [q for p, q in remaining if p]
        lanes.append(
            dict(
                paid=len(bits),
                erased=drops,
                p=drops / len(bits),
                simultaneous_iid_wilson95=wilson(drops, len(bits), z),
                conditional_next_loss_after_loss=mean(after) if after else None,
            )
        )
    pairs = []
    for i, j in combinations(range(n), 2):
        a = [x[i] for x in lost_rows]
        b = [x[j] for x in lost_rows]
        corr = (
            (mean(x * y for x, y in zip(a, b)) - mean(a) * mean(b))
            / (pstdev(a) * pstdev(b))
            if pstdev(a) * pstdev(b) > 0
            else None
        )
        pairs.append([i, j, corr])
    block = {}
    for size in (32, 128):
        values = [
            mean(failed[o : o + size]) for o in range(0, len(failed) - size + 1, size)
        ]
        if len(values) > 1:
            e = 1.96 * stdev(values) / sqrt(len(values))
            block[size] = dict(
                blocks=len(values),
                approx_interval=[max(0, mean(values) - e), min(1, mean(values) + e)],
            )

    def total(key):
        return sum(path.get(key, 0) for path in s)

    whole_ip = total("paid_ip_bytes")
    whole_packets = total("paid_packets")
    with_repair = sum(p[2] > 0 for p in paid.values())
    mixed = sum(p[1] > 0 and p[2] > 0 for p in paid.values())
    assert sum(p[1] + p[2] for p in paid.values()) == sum(
        total(key)
        for key in (
            "fresh_entries",
            "named_entries",
            "quiet_entries",
            "path_arq_retry_entries",
        )
    )
    erased = sum(row["erased"] for row in lanes)
    prob = erased / len(paid)
    fresh_only = [p[1] for p in paid.values() if p[1] and not p[2]]
    repair_entries = sum(p[2] for p in paid.values())
    charged_bodies = (
        total("named_shard_bytes")
        + total("quiet_shard_bytes")
        + total("path_arq_retry_shard_bytes")
    )
    post = report["wire"][peer]["tuples"][direction]
    assert sum(v["packets"] for v in post) == sum(
        v["rx_packets"] for v in report["adapter_stats"][peer]["paths"]
    )
    return dict(
        groups=len(ranks),
        threshold=k,
        paid_data=len(paid),
        pooled_data_erasure=prob,
        paths=lanes,
        first_flight_rank=Counter(ranks),
        rank_failure=mean(failed),
        expected_deficit_per_group=short / len(ranks),
        failed_groups=sum(failed),
        approximate_group_block_intervals=block,
        adjacent_fail_given_fail=(
            mean(q for p, q in zip(failed, failed[1:]) if p)
            if any(failed[:-1])
            else None
        ),
        fresh_slots_sharing_same_datagram_with_previous_group=shared,
        fresh_lane_pair_erasure_correlations=pairs,
        fresh_only_mean_entries=mean(fresh_only),
        paid_data_mean_entries=sum(p[1] + p[2] for p in paid.values()) / len(paid),
        mtu=stats["config"]["mtu"],
        observed_udp=dict(
            paid=whole_packets,
            ip_bytes=whole_ip,
            post_loss=sum(v["packets"] for v in post),
            post_loss_ip_bytes=sum(v["ip_bytes"] for v in post),
            containing_repair=with_repair,
            mixed_fresh_repair_packets=mixed,
            repair_packet_share_all=with_repair / whole_packets,
            repair_packet_share_data=with_repair / len(paid),
            ip_bytes_with_repair=total("data_with_repair_ip_bytes"),
            repair_carrying_ip_byte_share=total("data_with_repair_ip_bytes") / whole_ip,
            paid_repair_shards=repair_entries,
            paid_repair_shard_body_bytes=charged_bodies,
            paid_repair_shard_body_share_ip=charged_bodies / whole_ip,
            standalone_ack_ip=total("standalone_ack_ip_bytes"),
            request_ip=total("request_ip_bytes"),
            piggyback_ack_body_bytes=total("piggyback_ack_bytes"),
            fresh_shard_body_bytes=total("fresh_shard_bytes"),
            native_input_ip_bytes=stats["totals"]["native_read_bytes"],
            observed_body_ratio=total("fresh_shard_bytes")
            / stats["totals"]["native_read_bytes"],
            ratio_actual_retry_entries_to_ideal_selective=(
                repair_entries / (short / (1 - prob)) if short and prob < 1 else None
            ),
        ),
    )


def candidate(n, k, forward, reverse, batch, opts):
    def direction(size, occupancy, probabilities):
        fail, missing = risks(probabilities, k)
        # Use the least reliable measured path for the cost of a later, independent attempt.
        if max(probabilities) == 1:
            return None
        issued = missing / (1 - max(probabilities))
        fresh = wire(n, k, size, opts.mtu, occupancy, opts.gid, opts.pn)
        retry = wire(
            n,
            k,
            size,
            opts.mtu,
            opts.repair_batch,
            opts.gid,
            opts.pn,
            cross=opts.reroute_repair,
        )
        if fresh is None or retry is None:
            return None
        if opts.complete_path:
            # Counterfactual exact copy of every lost physical datagram, regardless of logical retirement.
            weights = [p / (1 - p) for p in probabilities]
            paid_retry_ip, paid_retry_packets = wire(
                n, k, size, opts.mtu, occupancy, opts.gid, opts.pn, lane_weights=weights
            )
        else:
            paid_retry_ip, paid_retry_packets = (x * issued / n for x in retry)
        return dict(
            fail=fail,
            missing=missing,
            issued=issued,
            fresh_ip=fresh[0],
            retry_ip=paid_retry_ip,
            ip=fresh[0] + paid_retry_ip,
            retry_packet_share=paid_retry_packets / (fresh[1] + paid_retry_packets),
            retry_byte_share=paid_retry_ip / (fresh[0] + paid_retry_ip),
        )

    f = direction(opts.record, batch[0], forward)
    r = direction(opts.ack_record, batch[1], reverse)
    if not f or not r:
        return None
    fb = opts.target_mbps * f["ip"] / opts.tcp_payload
    rb = opts.target_mbps * r["ip"] * opts.ack_ratio / opts.tcp_payload
    return dict(
        n=n,
        k=k,
        parity=n - k,
        coding_floor=n / k,
        rank_failure=f["fail"],
        expected_deficit=f["missing"],
        ideal_selective_repair_entries=f["issued"],
        retry_packet_share=f["retry_packet_share"],
        retry_byte_share=f["retry_byte_share"],
        forward_mbps=fb,
        reverse_mbps=rb,
        forward_headroom_mbps=opts.forward_link - fb,
        reverse_headroom_mbps=opts.reverse_link - rb,
        fluid_goodput_ceiling_mbps=min(
            opts.forward_link * opts.target_mbps / fb,
            opts.reverse_link * opts.target_mbps / rb,
        )
        if rb
        else opts.forward_link * opts.target_mbps / fb,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "capture", type=Path, help="immutable Linux path-bundle 1/1 trace directory"
    )
    p.add_argument("--output", type=Path)
    p.add_argument("--max-paths", type=int, default=32)
    p.add_argument(
        "--targets", type=float, nargs="+", default=[0.01, 0.03, 0.05, 0.10, 0.25]
    )
    p.add_argument("--record", type=int, default=1500)
    p.add_argument("--tcp-payload", type=int, default=1448)
    p.add_argument("--ack-record", type=int, default=52)
    p.add_argument("--ack-ratio", type=float, default=0.5)
    p.add_argument("--target-mbps", type=float, default=70)
    p.add_argument("--forward-link", type=float, default=100)
    p.add_argument("--reverse-link", type=float, default=10)
    p.add_argument("--mtu", type=int, default=1500)
    p.add_argument(
        "--complete-path",
        action="store_true",
        help="repay every erased physical DATA at original occupancy until received, regardless of rank",
    )
    p.add_argument("--repair-batch", type=float, default=1)
    p.add_argument(
        "--reroute-repair", action=argparse.BooleanOptionalAction, default=True
    )
    p.add_argument("--gid", type=int, default=4096)
    p.add_argument("--pn", type=int, default=4096)
    p.add_argument("--common", type=float, nargs="+", default=[0.02, 0.05])
    o = p.parse_args()
    if not (
        1 <= o.max_paths <= 255
        and 1 <= o.tcp_payload <= o.record <= 65535
        and 1 <= o.ack_record <= 65535
        and 50 <= o.mtu <= 65535
        and 0 <= o.gid < 2**64 - 1
        and 0 <= o.pn < 2**64 - 1
        and 0 <= o.ack_ratio <= 1
        and o.target_mbps > 0
        and o.forward_link > 0
        and o.reverse_link > 0
        and 1 <= o.repair_batch <= 255
        and all(0 <= v < 1 for v in o.common)
        and all(0 <= v <= 1 for v in o.targets)
    ):
        p.error("invalid geometry, budget or probabilities")
    actual = {s: summarize_capture(o.capture, s) for s in "ab"}
    f = actual["a"]
    rev = actual["b"]
    measured = [x["p"] for x in f["paths"]]
    n0 = len(measured)
    pooled = f["pooled_data_erasure"]
    upper = [x["simultaneous_iid_wilson95"][1] for x in f["paths"]]
    # Distinct forward and reverse measured probabilities enter their respective wire budgets.
    pr = [x["p"] for x in rev["paths"]]
    pr_pool = rev["pooled_data_erasure"]
    batches = {
        "full": (255, 255),
        "observed_fresh": (
            f["fresh_only_mean_entries"],
            rev["fresh_only_mean_entries"],
        ),
        "singleton": (1, 1),
    }

    fixed = {}
    allocation = {}
    all_calcs = {}
    for b, batch in batches.items():
        fixed[b] = [
            x
            for k in range(1, n0 + 1)
            if (x := candidate(n0, k, measured, pr, batch, o))
        ]
        model = [
            x
            for n in range(2, o.max_paths + 1)
            for k in range(1, n + 1)
            if (x := candidate(n, k, [pooled] * n, [pr_pool] * n, batch, o))
        ]
        all_calcs[b] = len(model)
        allocation[b] = {}
        for metric in ["rank_failure", "retry_packet_share", "retry_byte_share"]:
            out = []
            for t in o.targets:
                candidates = [x for x in model if x[metric] <= t]
                possible = [
                    x
                    for x in candidates
                    if x["forward_headroom_mbps"] >= 0
                    and x["reverse_headroom_mbps"] >= 0
                ]
                best = (
                    min(
                        candidates,
                        key=lambda x: (x["forward_mbps"], x["reverse_mbps"], x["n"]),
                    )
                    if candidates
                    else None
                )
                # Feasible means fitting both modeled rates before control overhead, not measured throughput.
                by_n = {
                    n: [x["k"] for x in possible if x["n"] == n]
                    for n in sorted({x["n"] for x in possible})
                }
                winner = (
                    max(possible, key=lambda x: x["fluid_goodput_ceiling_mbps"])
                    if possible
                    else None
                )
                out.append(
                    dict(
                        target=t,
                        feasible_n_to_k=by_n,
                        least_forward_mbps=best,
                        best_duplex_ceiling=winner,
                    )
                )
            allocation[b][metric] = out
    checks = {}
    for name, rates, shock in [
        ("homogeneous_estimate", [pooled] * n0, 0),
        ("measured_heterogeneous", measured, 0),
        ("upper_simultaneous_iid", upper, 0),
    ] + [(f"common_{v}", measured, v) for v in o.common]:
        if shock > min(rates):
            checks[name] = {"unavailable": "shock exceeds a measured path marginal"}
            continue
        checks[name] = dict(
            zip(
                ["rank_failure", "expected_deficit"],
                risks(rates, f["threshold"], shock),
            )
        )
    options = vars(o).copy()
    options["capture"] = str(o.capture)
    options.pop("output")
    if not o.complete_path:
        options.pop("complete_path")
    before = json.loads((o.capture / "result.json").read_text())
    probe = json.loads((o.capture / "probe/a.json").read_text())
    output = dict(
        options=options,
        source_hashes={
            "trace": before["adapter_trace"],
            "pcap": {s: before["wire"][s]["sha256"] for s in "ab"},
            "result_sha256": hashlib.sha256(
                (o.capture / "result.json").read_bytes()
            ).hexdigest(),
        },
        actual=actual,
        verified_application_lifetime=probe["flows"][0]["sent"],
        fixed_geometry_sensitivity=checks,
        batch_assumptions=batches,
        fixed_measured_path_geometry=fixed,
        variable_iid_geometry=allocation,
        variable_loss_probabilities={"forward": pooled, "reverse": pr_pool},
        evaluated_geometries=all_calcs,
    )
    data = json.dumps(output, indent=2) + "\n"
    if o.output:
        with o.output.open("x") as fd:
            fd.write(data)
    else:
        print(data, end="")


if __name__ == "__main__":
    main()
