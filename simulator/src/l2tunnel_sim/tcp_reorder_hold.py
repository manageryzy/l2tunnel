"""Bounded delivery of already decoded TCP data in an established model flow."""

from collections import Counter
from heapq import heappop, heappush
from math import isfinite


class TCPReorderHold:
    """A per-direction byte-sequence gate with an injected monotonic event clock.

    The caller supplies validated data-only segments and a witnessed next byte.
    ACKs and connection lifecycle packets are handled outside this gate. Both
    duplicate and overlapping attempts are delivered to the modeled endpoint.
    """

    def __init__(self, next_byte, *, hold_s, max_span_bytes, max_frames, schedule, deliver):
        if (not isfinite(hold_s) or hold_s <= 0 or max_span_bytes <= 0
                or max_frames <= 0 or not 0 <= next_byte < 2 ** 32):
            raise ValueError("invalid TCP reorder hold limits or initial sequence")
        self.next_byte = next_byte
        self.hold_s = hold_s
        self.max_span_bytes = max_span_bytes
        self.max_frames = max_frames
        self.schedule = schedule
        self.deliver = deliver
        self.pending = []
        self.arrivals = 0
        self.deadline = None
        self.bypass_high = None
        self.released_ranges = []
        self.tracking_disabled = False
        self.counts = Counter()

    def receive(self, now, sequence, size, frame, *, record):
        if not 0 <= sequence < 2 ** 32 or not 0 < size < 2 ** 31:
            raise ValueError("invalid TCP sequence or payload length")
        if self.tracking_disabled:
            self.counts["untracked_deliveries"] += 1
            self.deliver(frame)
            return
        # Compare 32-bit wire sequence numbers in the witnessed byte space.
        start = self.next_byte + ((sequence - self.next_byte + 2 ** 31) % 2 ** 32 - 2 ** 31)
        end = start + size
        if self.bypass_high is not None:
            self._observe(start, end)
            if self.bypass_high is not None and self.next_byte >= self.bypass_high:
                self.bypass_high = None
                self.counts["bypass_exits"] += 1
            self.counts["bypass_deliveries"] += 1
            self.deliver(frame)
        elif start <= self.next_byte:
            self._observe(start, end)
            self.deliver(frame)
            while self.pending and self.pending[0][0] <= self.next_byte:
                start, _, end, _, frame = heappop(self.pending)
                self._observe(start, end)
                self.deliver(frame)
                self.counts["released_by_prefix"] += 1
            if not self.pending:
                self.deadline = None
        else:
            self.arrivals += 1
            heappush(self.pending, (start, self.arrivals, end, record, frame))
            self.counts["held"] += 1
            if len(self.pending) >= self.max_frames or end - self.next_byte > self.max_span_bytes:
                self._bypass("pressure")
            elif self.deadline is None:
                self.deadline = now + self.hold_s
                self.schedule(self.deadline, self._expire, self.deadline)

    def _expire(self, deadline):
        if self.deadline == deadline:
            self._bypass("deadline")

    def _observe(self, start, end):
        if self.tracking_disabled or end <= self.next_byte:
            return
        if start <= self.next_byte:
            self.next_byte = end
            while self.released_ranges and self.released_ranges[0][0] <= self.next_byte:
                self.next_byte = max(self.next_byte, self.released_ranges.pop(0)[1])
            return
        merged = []
        for left, right in self.released_ranges:
            if start <= right and left <= end:
                start, end = min(start, left), max(end, right)
            else:
                merged.append((left, right))
        merged.append((start, end))
        merged.sort()
        if len(merged) > 32:
            # The witnessed prefix can no longer be tracked safely. Continue
            # immediate delivery on this established flow until its lifecycle ends.
            self.tracking_disabled = True
            self.released_ranges.clear()
            self.bypass_high = None
            self.counts["range_overflow"] += 1
        else:
            self.released_ranges = merged

    def _bypass(self, reason):
        self.counts[reason + "_episodes"] += 1
        self.deadline = None
        self.bypass_high = max(item[2] for item in self.pending)
        # The bounded receiver walks its authenticated channel records in sender
        # order on expiry/pressure. A retransmission has a new record number.
        batch = sorted(self.pending, key=lambda item: (item[3], item[1]))
        self.pending.clear()
        for start, _, end, _, frame in batch:
            self._observe(start, end)
            self.deliver(frame)
            self.counts["released_by_" + reason] += 1
