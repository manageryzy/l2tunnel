"""Experimental byte sharing driven by one directional sender's real MUX backlog."""

from .packed_latency_policy import LatencyPackedWireTransport


def oldest_mux_wait_ms(mux, reverse):
    """Age of the oldest unadmitted frame over this sender's channel FIFOs."""
    return max(((mux.sim.now - queue[0][2]) * 1000 for queue in mux.queues[reverse] if queue),
               default=0.0)


class BacklogPackedWireTransport(LatencyPackedWireTransport):
    """Use full retry-byte credit during backlog, otherwise retain half credit."""

    def __init__(self, sim, reverse, config, *, policy, oldest_wait_ms):
        if not callable(oldest_wait_ms):
            raise ValueError("a local MUX backlog observer is required")
        super().__init__(sim, reverse, config, policy=policy, variant="half-shared-repair-budget")
        self.variant = "queue-aware-repair-budget"
        self.oldest_wait_ms = oldest_wait_ms

    def _resend(self, index, reason):
        if reason == "requested_retries":
            wait = self.oldest_wait_ms()
            if self._weight == 1 and wait >= 15:
                self._weight = 2
                self.latency_counts["entered_full_credit"] += 1
            elif self._weight == 2 and wait <= 5:
                self._weight = 1
                self.latency_counts["returned_to_half_credit"] += 1
            label = "full" if self._weight == 2 else "half"
            self.latency_counts[label + "_weighted_retries"] += 1
            self.latency_counts["peak_sampled_mux_wait_ms"] = max(
                self.latency_counts["peak_sampled_mux_wait_ms"], wait)
        return super()._resend(index, reason)
