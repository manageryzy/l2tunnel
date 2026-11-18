"""Opt-in byte-sharing experiments for targeted PackedWire recovery.

An actual requested original earns bounded byte credit. Enough credit can pay
for a future regular repair opportunity, in which case no equation is sent.
The underlying serial advances only on transmission, preserving the receiver's
local/global support schedule for all emitted equations.
"""

from collections import Counter, deque

from .compact_wire import GLOBAL_EVERY, GLOBAL_WINDOW, LOCAL_WINDOW, SYMBOL_BYTES
from .packed_targeted import TargetedPackedWireTransport


class LatencyPackedWireTransport(TargetedPackedWireTransport):
    """Share recovery bytes without delaying a request, source, or old probe."""

    def __init__(self, sim, reverse, config, *, policy, variant):
        super().__init__(sim, reverse, config, policy=policy)
        weights = {"shared-repair-budget": 2, "half-shared-repair-budget": 1}
        if variant not in weights:
            raise ValueError("unknown packed latency policy")
        self.variant = variant
        # Half-byte units retain the exact fractional credit of an odd-sized
        # retry in the half-sharing experiment without rounding packet lengths.
        self._weight = weights[variant]
        self._cap = 2 * policy.window * sim.scenario.mtu
        self._balance = 0
        self._extents = {LOCAL_WINDOW: deque(), GLOBAL_WINDOW: deque()}
        self.latency_counts = Counter()

    def _aligned_source(self, payload):
        if self.config.trim_repair_padding:
            index, size = len(self.sources), len(payload)
            for width, queue in self._extents.items():
                while queue and queue[0][0] <= index - width:
                    queue.popleft()
                while queue and queue[-1][1] <= size:
                    queue.pop()
                queue.append((index, size))
        super()._aligned_source(payload)

    def _resend(self, index, reason):
        finish = super()._resend(index, reason)
        if reason == "requested_retries":
            amount = self._weight * (self.source_header + self.sources[index].size)
            balance = min(self._cap, self._balance + amount)
            self.latency_counts["retry_credit_bytes"] += amount / 2
            self.latency_counts["cap_discarded_bytes"] += (self._balance + amount - balance) / 2
            self._balance = balance
            self.latency_counts["peak_credit_bytes"] = max(
                self.latency_counts["peak_credit_bytes"], balance / 2)
        return finish

    def _repair(self, tail):
        if tail or self.base >= len(self.sources):
            return super()._repair(tail)
        width = LOCAL_WINDOW if (self.repair_serial + 1) % GLOBAL_EVERY else GLOBAL_WINDOW
        extent = self._extents[width][0][1] if self.config.trim_repair_padding else SYMBOL_BYTES
        size = self.repair_header + extent
        self.latency_counts["regular_opportunities"] += 1
        self.latency_counts["regular_opportunity_ip_bytes"] += size
        if self._balance >= 2 * size:
            self._balance -= 2 * size
            self.latency_counts["displaced_regular_packets"] += 1
            self.latency_counts["displaced_regular_ip_bytes"] += size
            return
        super()._repair(False)

    def _receive_feedback(self, prefix, deficit):
        super()._receive_feedback(prefix, deficit)
        if self.base == len(self.sources) and self._balance:
            # Do not spend a previous fully confirmed flight's residual credit
            # against a future independent burst of source traffic.
            self.latency_counts["expired_on_confirmation_bytes"] += self._balance / 2
            self._balance = 0
