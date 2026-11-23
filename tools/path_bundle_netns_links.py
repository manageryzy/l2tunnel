"""Explicit owned-lab alternative: consume link capacity before applying loss."""
import json
import re
import sys
import time

try:
    from . import common_native_matrix as matrix
except ImportError:
    import common_native_matrix as matrix


def parse_qdiscs(raw, downstream):
    rows = json.loads(raw)
    expected = {("netem", "10:")} if downstream else {("htb", "1:"), ("pfifo", "10:")}
    matrix.require(isinstance(rows, list) and len(rows) == len(expected)
                   and all(isinstance(row, dict) for row in rows), "unexpected owned qdisc list")
    matrix.require({(r.get("kind"), r.get("handle")) for r in rows} == expected,
                   "unexpected owned qdisc identity")
    for row in rows:
        matrix.require(row.get("root") is True if downstream or row["kind"] == "htb"
                       else row.get("parent") == "1:10", "unexpected owned qdisc parent")
        for field in ("bytes", "packets", "drops", "overlimits", "requeues"):
            matrix.require(type(row.get(field)) is int and row[field] >= 0, "invalid owned qdisc counter")
    return rows


def configure(case, seeds, separated):
    if separated:
        for side, outgoing in (("a", "b0"), ("b", "a0")):
            case.command("endpoint_" + side, "tc", "qdisc", "del", "dev", "wan0",
                         "parent", "1:10", "handle", "10:")
            case.command("endpoint_" + side, "tc", "qdisc", "add", "dev", "wan0",
                         "parent", "1:10", "handle", "10:", "pfifo", "limit", "1000")
            case.command("router", "tc", "qdisc", "add", "dev", outgoing, "root", "handle", "10:",
                         "netem", "limit", "1000", "delay", "35ms", "loss", "random", "15%")
    for side, outgoing in (("a", "b0"), ("b", "a0")):
        role = "router" if separated else "endpoint_" + side
        args = [sys.executable, matrix.ROOT / "tools/common_native_netem_seed.py",
                case.spec.namespaces[role], str(seeds[side])]
        if separated:
            args += ["--router-interface", outgoing]
        case.value.setdefault("netem", {})[side] = json.loads(case.command(role, *args))
    if separated:
        case.value["qdisc_before"] = snapshot(case, True)
        matrix.check_forward_tun_fq(case, case.value["qdisc_before"])


def snapshot(case, separated):
    if not separated:
        return matrix.qdisc(case)
    result = {}
    for side, outgoing in (("a", "b0"), ("b", "a0")):
        role = "endpoint_" + side
        classes, fmt = matrix.parse_tc_class(case.command(role, "tc", "-s", "-j", "class", "show", "dev", "wan0"), 100 if side == "a" else 10)
        qdiscs = parse_qdiscs(case.command(role, "tc", "-s", "-d", "-j", "qdisc", "show", "dev", "wan0"), False)
        text = case.command(role, "tc", "-d", "qdisc", "show", "dev", "wan0")
        matrix.require("netem" not in text and "pfifo" in text, "endpoint shaper still contains loss")
        downstream = parse_qdiscs(case.command("router", "tc", "-s", "-d", "-j", "qdisc", "show", "dev", outgoing), True)
        downstream_text = case.command("router", "tc", "-d", "qdisc", "show", "dev", outgoing)
        matrix.require(re.search(r"\bdelay 35(?:\.0+)?ms\b", downstream_text) is not None
                       and re.search(r"\bloss 15(?:\.0+)?%", downstream_text) is not None,
                       "downstream owned loss or delay differs")
        begin = time.time_ns()
        kernel = {"scope": "owned endpoint cumulative counters, not wait durations", "begin_wall_ns": begin}
        for name, path in (("snmp", "/proc/net/snmp"), ("udp", "/proc/net/udp"), ("sockstat", "/proc/net/sockstat")):
            kernel[name] = case.command(role, "cat", path)
        kernel["end_wall_ns"] = time.time_ns()
        result[side] = dict(class_format=fmt, qdisc=qdiscs, qdisc_text=text, kernel_buffers=kernel,
                            native_tun=matrix.native_tun_snapshot(case, role),
                            loss_after_shaper=dict(namespace=case.spec.namespaces["router"], interface=outgoing,
                                                   qdisc=downstream, qdisc_text=downstream_text))
        result[side]["class"] = classes
    return result
