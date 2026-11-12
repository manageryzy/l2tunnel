"""Feedback-only first-flight loss recovery for compact cross-frame records.

The ordinary ARQ receiver still supplies cumulative and bitmap feedback over
the charged, lossy reverse link. Only the first transmission can bypass the
RTT retry guard after three later source packets and a newer transmission
serial have been acknowledged. Subsequent retries use the original guard.
"""

from math import isfinite

from .compact import CompactConfig
from .compact_arq import CompactARQTransport, REORDER_THRESHOLD


class FirstFlightARQTransport(CompactARQTransport):
    """Expedite an original-flight hole using only received wire feedback."""

    def __init__(self, sim, reverse, config=CompactConfig(repair_ratio=0)):
        super().__init__(sim, reverse, config)
        self.first_flight_fast_retransmissions = 0

    def _receive_feedback(self, prefix, start, count, bitmap, echo, delay_us, serial):
        fresh = serial > self.received_feedback_serial
        # Let the original implementation confirm receipts, sample RTT, and
        # apply guarded recovery. Its retransmitted flights are then skipped.
        super()._receive_feedback(prefix, start, count, bitmap, echo, delay_us, serial)
        if not fresh:
            return
        received_after = bitmap.bit_count()
        for offset in range(count):
            if bitmap >> offset & 1:
                received_after -= 1
                continue
            flight = self.flights.get(start + offset)
            if (received_after >= REORDER_THRESHOLD and flight is not None
                    and flight.attempts == 1 and echo > flight.serial):
                self.fast_retransmissions += 1
                self.first_flight_fast_retransmissions += 1
                self._transmit(start + offset, "retry")


class BoundedGapARQTransport(FirstFlightARQTransport):
    """Send one early feedback packet per advancing qualified receive hole.

    Early feedback is rate limited per direction, charged normally, and uses
    the unchanged feedback format. Sending it cancels the superseded delayed
    feedback timer through the existing feedback generation counter.
    """

    def __init__(self, sim, reverse, config=CompactConfig(repair_ratio=0),
                 *, gap_feedback_min_interval_ms=5.0):
        if not isfinite(gap_feedback_min_interval_ms) or gap_feedback_min_interval_ms <= 0:
            raise ValueError("gap feedback interval must be finite and positive")
        super().__init__(sim, reverse, config)
        self.gap_feedback_interval = gap_feedback_min_interval_ms / 1000
        self.last_feedback_at = float("-inf")
        self.notified_gap_prefix = -1
        self.early_feedback_packets = 0

    def _feedback(self, generation=None):
        if generation is not None and generation != self.feedback_generation:
            return
        self.last_feedback_at = self.sim.now
        super()._feedback(generation)

    def _receive_source(self, source, serial):
        super()._receive_source(source, serial)
        if (len(self.decoder.known) - self.received_prefix >= REORDER_THRESHOLD
                and self.received_prefix != self.notified_gap_prefix
                and self.sim.now >= self.last_feedback_at + self.gap_feedback_interval):
            self.notified_gap_prefix = self.received_prefix
            self.early_feedback_packets += 1
            self._feedback()
