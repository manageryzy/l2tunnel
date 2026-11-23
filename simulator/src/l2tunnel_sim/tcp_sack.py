"""Timestamp ACK profile and a bounded selective retransmit subset of RFC 6675."""
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass
from math import floor
import struct

from .compact import CompactHeaderCodec, tcp_profile_frame
from .mux import frame_tuple
from .tcp_reordering import ReorderingObserver

POLICIES = ("wire", "scoreboard", "scoreboard-dsack", "scoreboard-dsack-reordering-observer", "rack-dsack")


def unwrap(value, reference):
    return reference + ((value - reference + 2**31) % 2**32) - 2**31


class Receiver:
    """Keep the four most recent out-of-order ranges and one pending DSACK."""
    def __init__(self):
        self.recent = []
        self.duplicate = None

    def note(self, index, previous, current, duplicate, accepted):
        if duplicate:
            self.duplicate = (index, index + 1)
        if accepted and index > previous:
            lo, hi = index, index + 1
            untouched = []
            for left, right in self.recent:
                if left <= hi and lo <= right:
                    lo, hi = min(lo, left), max(hi, right)
                else:
                    untouched.append((left, right))
            self.recent = ([(lo, hi)] + untouched)[:4]
        self.recent = [(lo, hi) for lo, hi in self.recent if lo > current]

    def take_blocks(self, offset):
        ranges = ([self.duplicate] if self.duplicate else []) + self.recent
        self.duplicate = None
        return tuple((offset(lo), offset(hi)) for lo, hi in ranges[:3])


@dataclass(frozen=True)
class WireAck:
    cumulative: int
    ranges: tuple
    dsack: bool
    tsval: int
    tsecr: int


def ack_frame(edge, identification, timestamp, echo, blocks):
    header = tcp_profile_frame(acknowledged=edge, identification=identification, timestamp=timestamp,
                               echoed_timestamp=echo, payload_bytes=0, flags=0x10)
    if not blocks:
        return header
    if len(blocks) > 3 or any(not 0 < hi-lo < 2**31 for lo, hi in blocks):
        raise ValueError("invalid timestamp ACK SACK blocks")
    options = bytes([1, 1, 5, 2 + 8*len(blocks)]) + b"".join(
        struct.pack("!II", lo % 2**32, hi % 2**32) for lo, hi in blocks)
    header = bytearray(header)
    header[46] = ((len(header) - 34 + len(options)) // 4) << 4
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, options)


def parse_ack(frame, reference):
    frame_tuple(frame)
    tcp_length = len(frame) - 34
    if (len(frame) < 66 or frame[14] != 0x45 or len(frame) != 14 + int.from_bytes(frame[16:18], "big")
            or frame[47] != 0x10 or frame[46] != tcp_length//4 << 4 or tcp_length % 4
            or frame[54:58] != bytes([1, 1, 8, 10])):
        raise ValueError("expected a complete established timestamp ACK")
    edge = unwrap(int.from_bytes(frame[42:46], "big"), reference)
    options = frame[66:]
    ranges = []
    if options:
        if len(options) not in (12, 20, 28) or options[:4] != bytes([1, 1, 5, len(options)-2]):
            raise ValueError("invalid timestamp ACK SACK options")
        for left, right in struct.iter_unpack("!II", options[4:]):
            lo = unwrap(left, edge)
            hi = unwrap(right, lo)
            if lo >= hi:
                raise ValueError("invalid SACK range")
            ranges.append((lo, hi))
    dsack = bool(ranges) and (ranges[0][1] <= edge or
              (len(ranges) > 1 and ranges[1][0] <= ranges[0][0] < ranges[0][1] <= ranges[1][1]))
    ordinary = ranges[int(dsack):]
    if any(lo <= edge for lo, hi in ordinary) or any(
            max(lo, x) < min(hi, y) for i, (lo, hi) in enumerate(ordinary) for x, y in ordinary[i+1:]):
        raise ValueError("overlapping or unacknowledged-edge-crossing SACK ranges")
    return WireAck(edge, tuple(ranges), dsack, *struct.unpack_from("!II", frame, 58))


class Scoreboard:
    """Conservative pipe in segment slots. Ordinary timeout still handles reneging."""
    def __init__(self, capacity, *, reordering_smss=None):
        if not 1 <= capacity <= 8192:
            raise ValueError("single-flow SACK scoreboard supports 1..8192 outstanding segments")
        self.capacity = capacity
        self.base = 0
        self.stats = Counter()
        self.reordering = ReorderingObserver(reordering_smss, self.stats) if reordering_smss is not None else None
        self.reset()

    def reset(self):
        self.sacked = self.retried = 0
        self.fresh = False
        if self.reordering is not None:
            self.reordering.episode = None

    def observe(self, ack, index, offsets):
        self.fresh = False
        if index < self.base - self.capacity:
            return
        # A reordered cumulative ACK may still selectively acknowledge live data.
        # Keep the current left edge and clip all ranges to whole outstanding segments.
        anchor = max(self.base, index)
        if len(offsets)-1-anchor > self.capacity:
            raise ValueError("outstanding flight exceeds selected scoreboard")
        bits = 0
        for lo, hi in ack.ranges[int(ack.dsack):]:
            if not ack.cumulative < lo < hi <= offsets[-1]:
                raise ValueError("SACK outside issued stream")
            first = bisect_left(offsets, lo, anchor)
            end = bisect_right(offsets, hi, first)-1
            if end > first:
                bits |= ((1 << (end-first))-1) << (first-anchor)
        shift = anchor - self.base
        prior_sacks = self.sacked
        self.base = anchor
        self.sacked >>= shift
        self.retried = (self.retried >> shift) & ~bits
        self.fresh = bool(shift or bits & ~self.sacked)
        self.sacked |= bits
        if self.reordering is not None:
            self.reordering.observe(offsets, anchor-shift, prior_sacks, anchor, self.sacked, self.retried, ack)
        self.stats["wire_acks"] += 1
        self.stats["dsacks"] += int(ack.dsack)

    def loss_prefix(self, offsets, smss):
        """Exclusive relative end of candidates satisfying either IsLost threshold."""
        bits = self.sacked
        runs = covered = 0
        while bits:
            end = bits.bit_length()
            start = (bits ^ ((1 << end)-1)).bit_length()
            rangesize = offsets[self.base+end] - offsets[self.base+start]
            if runs + 1 >= 3 or covered + rangesize > 2*smss:
                # A single contiguous SACK range has no internal unsacked hole.
                return start
            runs += 1
            covered += rangesize
            bits &= (1 << start)-1
        return 0

    def pipe(self, issued):
        return issued - self.base - self.sacked.bit_count() + self.retried.bit_count()

    def mark_retry(self, index, recovery_end=None, timestamp=None):
        if not self.base <= index < self.base + self.capacity:
            raise ValueError("retry outside live SACK scoreboard")
        bit = 1 << (index - self.base)
        if self.retried & bit:
            return False
        self.retried |= bit
        if self.reordering is not None:
            self.reordering.retry(index - self.base, recovery_end, timestamp)
        return True

    def service(self, flow):
        if not self.fresh or not flow.in_recovery:
            return
        self.fresh = False
        end = min(self.loss_prefix(flow.segment_offsets, flow.smss_bytes), flow.recover - self.base)
        if end <= 0:
            return
        pending = ((1 << end)-1) & ~(self.retried | self.sacked)
        issued = len(flow.sent_times)
        while pending and self.pipe(issued) < floor(flow.cwnd):
            bit = pending & -pending
            pending -= bit
            flow.transmit_segment(self.base + bit.bit_length()-1)
            # Echoing an earlier original only proves the first retry redundant.
            # A further selective retry invalidates the single-retry undo evidence.
            if flow.fast_recovery_checkpoint is not None:
                self.stats["single_retry_undo_invalidated"] += 1
                flow.fast_recovery_checkpoint = None
            self.stats["additional_retransmissions"] += 1
