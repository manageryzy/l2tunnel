#!/usr/bin/env python3
"""Summarize the outer TCP headers captured by ``common_native_matrix.py --raw-rst-observation``.

The matrix writes ``<case>/outer-tcp-headers.pcap`` (router ``a0``, snaplen 96, both
directions of the raw carrier's outer IPv4/TCP tuple) and its tcpdump log
``outer-tcp-headers.log``. This reader is passive and unprivileged.

For each direction it reports packet/flag counters by interval (before bilateral
forwarding, forwarding before the sample, steady sample, after the sample) when
the case receipt and phase clock are available, and always over the whole
capture. It also follows the 32-bit sequence space: first, last and maximum
sequence (raw and relative to the first sequence), the remaining space before
the relative sequence reaches 2**32 from the first sequence, the number of raw
wraps past 2**32, backward steps, and forward gaps beyond the highest observed
segment end. Pure ACK means only the ACK flag and zero TCP payload.

Usage: ``common_native_outer_tcp.py CASE_DIR --output NEW.json`` (receipt mode) or
``common_native_outer_tcp.py --pcap FILE --output NEW.json`` (capture only).
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct

SEQ_SPACE = 1 << 32
HALF_SPACE = 1 << 31
DEFAULT_A = ("192.0.2.2", 24440)
DEFAULT_B = ("192.0.2.6", 24441)
DEFAULT_SNAPLEN = 96
DEFAULT_MAX_PACKETS = 500_000
MAX_GAP_EXAMPLES = 16
PERIODS = ("before_bilateral_forwarding", "forwarding_before_window", "steady", "after_window")
MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
         b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
# Link types: Ethernet carries a 14-byte header; raw IPv4 has none.
LINK_HEADER = {1: 14, 101: 0, 228: 0}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def endpoint(text):
    """Parse ``A.B.C.D:PORT``."""
    host, _, port = text.rpartition(":")
    value = (str(ipaddress.IPv4Address(host)), int(port))
    require(0 < value[1] < 65536, f"invalid port in {text}")
    return value


class SequenceTrack:
    """Follow one direction's 32-bit TCP sequence numbers without assuming order."""

    def __init__(self):
        self.first = self.last = self.prev = None
        self.unwrapped = 0           # relative to the first sequence
        self.max_end = 0             # highest relative segment end
        self.max_raw = None
        self.wraps = 0               # forward steps whose raw value crossed 2**32
        self.backward_steps = 0      # retransmission or reordering below the previous sequence
        self.below_highest = 0       # segments starting below the highest observed end
        self.gaps = 0
        self.gap_bytes = 0
        self.max_gap = 0
        self.examples = []
        self.rst = Counter()

    def add(self, seq, length, at, flags):
        if self.first is None:
            self.first = self.prev = seq
            self.max_raw = seq
            self.max_end = length
        else:
            step = (seq - self.prev) % SEQ_SPACE
            if step < HALF_SPACE:
                if seq < self.prev:
                    self.wraps += 1
                self.unwrapped += step
            else:
                self.backward_steps += 1
                self.unwrapped -= SEQ_SPACE - step
            self.prev = seq
            if self.unwrapped > self.max_end:
                gap = self.unwrapped - self.max_end
                self.gaps += 1
                self.gap_bytes += gap
                self.max_gap = max(self.max_gap, gap)
                if len(self.examples) < MAX_GAP_EXAMPLES:
                    self.examples.append({"wall_ns": at, "expected_relative_seq": self.max_end,
                                          "observed_relative_seq": self.unwrapped, "gap_bytes": gap})
            elif self.unwrapped < self.max_end and length:
                self.below_highest += 1
            self.max_end = max(self.max_end, self.unwrapped + length)
            self.max_raw = max(self.max_raw, seq)
        self.last = seq
        if flags & 4:
            self.rst["rst"] += 1
            self.rst["rst_with_ack"] += bool(flags & 16)
            self.rst["rst_with_payload"] += length > 0

    def report(self):
        if self.first is None:
            return {"packets_with_sequence": 0}
        return {
            "first_seq": self.first, "last_seq": self.last, "max_raw_seq": self.max_raw,
            "last_relative_seq": self.unwrapped, "max_relative_end": self.max_end,
            "remaining_relative_space_to_2_32": SEQ_SPACE - self.max_end,
            "remaining_raw_space_from_first_to_2_32": SEQ_SPACE - self.first,
            "raw_wraps": self.wraps, "relative_wraps": self.max_end // SEQ_SPACE,
            "backward_steps": self.backward_steps, "segments_below_highest_end": self.below_highest,
            "forward_gaps": self.gaps, "forward_gap_bytes": self.gap_bytes, "max_forward_gap_bytes": self.max_gap,
            "gap_examples": self.examples, "rst": {k: self.rst[k] for k in ("rst", "rst_with_ack", "rst_with_payload")},
        }


def read_pcap(path, snaplen=DEFAULT_SNAPLEN):
    """Yield ``(wall_ns, ipv4_packet, wire_length, link_header_bytes)`` from a classic pcap."""
    with path.open("rb") as stream:
        header = stream.read(24)
        require(len(header) == 24 and header[:4] in MAGIC, "not a classic pcap file")
        endian, multiplier = MAGIC[header[:4]]
        link = struct.unpack_from(endian + "I", header, 20)[0]
        require(link in LINK_HEADER, f"unsupported pcap link type {link}")
        skip = LINK_HEADER[link]
        while head := stream.read(16):
            require(len(head) == 16, "truncated pcap record header")
            seconds, fraction, cap, wire = struct.unpack(endian + "IIII", head)
            frame = stream.read(cap)
            require(len(frame) == cap and skip + 40 <= cap <= min(snaplen, wire),
                    "unexpected truncated or oversize outer header record")
            if skip:
                require(frame[12:14] == b"\x08\x00", "non-IPv4 Ethernet frame")
            yield seconds * 1_000_000_000 + fraction * multiplier, frame[skip:], wire, skip


def analyze(path, a=DEFAULT_A, b=DEFAULT_B, *, boundaries=None, snaplen=DEFAULT_SNAPLEN):
    """Count headers and follow sequences. ``boundaries`` is (ready, start, end) wall ns or None."""
    tuples = {(*a, *b): "a_to_b", (*b, *a): "b_to_a"}
    periods = PERIODS if boundaries else ()
    counts = {period: {d: Counter() for d in tuples.values()} for period in (*periods, "all")}
    tracks = {d: SequenceTrack() for d in tuples.values()}
    earliest = latest = None
    seen = 0
    for at, pkt, wire, skip in read_pcap(path, snaplen):
        ihl = (pkt[0] & 15) * 4
        require(pkt[0] >> 4 == 4 and pkt[9] == 6 and not (int.from_bytes(pkt[6:8], "big") & 0x3fff),
                "expected unfragmented IPv4 TCP")
        require(20 <= ihl <= 60 and len(pkt) >= ihl + 20, "invalid IPv4 header length")
        tcp = pkt[ihl:]
        thl = (tcp[12] >> 4) * 4
        require(20 <= thl <= 60, "invalid TCP header length")
        payload = int.from_bytes(pkt[2:4], "big") - ihl - thl
        require(0 <= payload <= wire - skip - ihl - thl, "IPv4 total length disagrees with the frame")
        sport, dport, seq = struct.unpack_from("!HHI", tcp)
        key = (str(ipaddress.IPv4Address(pkt[12:16])), sport, str(ipaddress.IPv4Address(pkt[16:20])), dport)
        require(key in tuples, f"packet outside the outer tuple: {key}")
        direction = tuples[key]
        earliest = at if earliest is None else min(at, earliest)
        latest = at if latest is None else max(at, latest)
        flags = tcp[13]
        selected = [counts["all"][direction]]
        if boundaries:
            ready, start, end = boundaries
            selected.append(counts[PERIODS[0 if at < ready else 1 if at < start else 2 if at < end else 3]][direction])
        for counter in selected:
            counter["packets"] += 1
            counter["pure_ack_no_payload"] += flags == 0x10 and payload == 0
            counter["ack_bit_with_payload"] += bool(flags & 16) and payload > 0
            counter["syn"] += bool(flags & 2)
            counter["fin"] += bool(flags & 1)
            counter["rst"] += bool(flags & 4)
            if payload:
                counter["tcp_payload_bytes"] += payload
        tracks[direction].add(seq, payload + bool(flags & 2) + bool(flags & 1), at, flags)
        seen += 1
    return {"packets": seen, "captured_first_and_last_wall_ns": [earliest, latest],
            "counts": {p: {d: dict(c) for d, c in v.items()} for p, v in counts.items()},
            "sequence": {d: t.report() for d, t in tracks.items()}}


def capture_counters(log):
    counters = {}
    for count, name in re.findall(r"^(\d+) packets (captured|received by filter|dropped by kernel)$",
                                  log.read_text(), re.M):
        require(name not in counters, f"duplicate tcpdump counter: {name}")
        counters[name] = int(count)
    return counters


def summarize(case=None, *, pcap=None, log=None, a=DEFAULT_A, b=DEFAULT_B, snaplen=DEFAULT_SNAPLEN,
              max_packets=DEFAULT_MAX_PACKETS, interface="a0"):
    """Summarize one case directory (receipt mode) or one capture file (``case`` None)."""
    pcap = pcap or case / "outer-tcp-headers.pcap"
    value = {"source": str(pcap.resolve()), "sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
             "router_interface": interface, "outer_tuple": {"a": f"{a[0]}:{a[1]}", "b": f"{b[0]}:{b[1]}"}}
    boundaries = None
    if case is not None:
        receipt = json.loads((case / "result.json").read_text())
        phase = receipt["phases"][0]
        clock = json.loads((case / "forward/clock.json").read_text())
        anchor = phase["clock_anchor"]
        offset = anchor["wall_ns"] - (anchor["monotonic_before_ns"] + anchor["monotonic_after_ns"]) // 2
        start, end = clock["measure_start_ns"] + offset, clock["end_ns"] + offset
        ready = receipt["both_forwarding_observed_wall_ns"]
        require(ready < start < end, "forwarding observation does not precede the sample window")
        boundaries = (ready, start, end)
        value.update(phase_status=phase["status"], case_status=receipt["status"],
                     both_forwarding_observed_wall_ns=ready, steady_wall_ns=[start, end],
                     clock_anchor_bracket_ns=anchor["monotonic_after_ns"] - anchor["monotonic_before_ns"])
        for side in ("before", "after"):
            key = f"rst_rule_counters_{side}_transfer"
            if key in receipt:
                value[key] = receipt[key]
    result = analyze(pcap, a, b, boundaries=boundaries, snaplen=snaplen)
    if log is not None:
        counters = capture_counters(log)
        require(counters.get("dropped by kernel") == 0 and 0 < counters.get("captured", 0) < max_packets,
                "capture dropped packets or hit its packet bound")
        require(result["packets"] == counters["captured"], "pcap record count differs from tcpdump")
        value["capture_counters"] = counters
    if boundaries:
        earliest, latest = result["captured_first_and_last_wall_ns"]
        require(earliest is not None and earliest < boundaries[0] and latest >= boundaries[2],
                "capture does not span bootstrap through the end of the sample")
    value.update(result)
    value["scope"] = ("One owned router link, both directions of the original outer IPv4/TCP tuple. "
                      "Pure ACK means only the ACK flag and zero TCP payload. Sequence lengths count payload, "
                      "SYN and FIN. Relative space is measured from each direction's first captured sequence. "
                      "The before-forwarding interval includes bootstrap and time to userspace status observation.")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("case", type=Path, nargs="?", help="case directory holding result.json and the capture")
    parser.add_argument("legacy_output", type=Path, nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help="new JSON file (default: print)")
    parser.add_argument("--pcap", type=Path, help="capture file (default CASE/outer-tcp-headers.pcap)")
    parser.add_argument("--log", type=Path, help="tcpdump log (default CASE/outer-tcp-headers.log)")
    parser.add_argument("--no-log", action="store_true", help="skip tcpdump counter validation")
    parser.add_argument("--a-endpoint", type=endpoint, default=DEFAULT_A, metavar="IP:PORT")
    parser.add_argument("--b-endpoint", type=endpoint, default=DEFAULT_B, metavar="IP:PORT")
    parser.add_argument("--snaplen", type=int, default=DEFAULT_SNAPLEN)
    parser.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS)
    parser.add_argument("--router-interface", default="a0", help="label recorded in the summary")
    args = parser.parse_args(argv)
    if args.case is None and args.pcap is None:
        parser.error("a case directory or --pcap is required")
    output = args.output or args.legacy_output
    if output and (output.exists() or output.is_symlink()):
        parser.error("--output must not exist")
    if args.no_log:
        log = None
    else:
        log = args.log or (args.case / "outer-tcp-headers.log" if args.case else None)
    result = summarize(args.case, pcap=args.pcap, log=log, a=args.a_endpoint, b=args.b_endpoint,
                       snaplen=args.snaplen, max_packets=args.max_packets, interface=args.router_interface)
    text = json.dumps(result, indent=2) + "\n"
    if output:
        with output.open("x") as stream:
            stream.write(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
