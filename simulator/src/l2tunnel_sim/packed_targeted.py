"""Experimental oldest-window source recovery for the causal PackedWire model.

Regular W128/G16 repairs, packing, actual per-channel release, feedback credit
and original byte retention use the existing transport. Targeted requests travel
as received bytes on the opposite lossy FIFO. A sender that hears nothing probes
its oldest unconfirmed original. Rank-recovered bytes still use the PackedWire
simulation ledger.
"""

from collections import Counter, OrderedDict
from dataclasses import dataclass
from math import isfinite
from struct import Struct
from zlib import crc32

from .compact_wire import CRC, GLOBAL_WINDOW, encode_source
from .packed_wire import PackedWireTransport


# In the existing source/repair grammar these words denote an extended repair
# with low end bits 1 but absolute end 0. No valid data packet has this prefix.
REQUEST = Struct("!HHIIIB")
MARKER = (0x8001, 0x8000, 0)


@dataclass(frozen=True)
class TargetedPolicy:
    window: int = 32
    max_ids: int = 8
    gap_ms: float = 2
    repeat_ms: float = 80
    probe_ms: float = 140

    def __post_init__(self):
        if (type(self.window) is not int or type(self.max_ids) is not int
                or not 1 <= self.max_ids <= self.window <= 255):
            raise ValueError("require 1 <= max_ids <= window <= 255")
        if any(type(v) not in (int, float) or not isfinite(v) or v <= 0
               for v in (self.gap_ms, self.repeat_ms, self.probe_ms)):
            raise ValueError("targeted deadlines must be finite and positive")


def encode_request(prefix, start, offsets, policy, encapsulation):
    if (not 0 <= prefix <= start < prefix + GLOBAL_WINDOW or not 1 <= len(offsets) <= policy.max_ids
            or any(type(i) is not int or not 0 <= i < policy.window for i in offsets)
            or list(offsets) != sorted(set(offsets))
            or start + offsets[-1] >= min(2**32, prefix + GLOBAL_WINDOW)):
        raise ValueError("invalid absolute request prefix or offsets")
    body = REQUEST.pack(*MARKER, prefix, start, len(offsets)) + bytes(offsets)
    if encapsulation == "raw_ipv4_crc32":
        return body + CRC.pack(crc32(body))
    if encapsulation != "udp":
        raise ValueError("unsupported encapsulation")
    return body


def decode_request(wire, policy, encapsulation):
    if encapsulation == "raw_ipv4_crc32":
        if len(wire) < REQUEST.size + CRC.size:
            raise ValueError("truncated protected request")
        wire, checksum = wire[:-CRC.size], wire[-CRC.size:]
        if CRC.pack(crc32(wire)) != checksum:
            raise ValueError("request CRC mismatch")
    elif encapsulation != "udp":
        raise ValueError("unsupported encapsulation")
    if len(wire) < REQUEST.size:
        raise ValueError("truncated targeted request")
    first, second, reserved, prefix, start, count = REQUEST.unpack_from(wire)
    offsets = wire[REQUEST.size:]
    if ((first, second, reserved) != MARKER or not 1 <= count <= policy.max_ids
            or len(offsets) != count or offsets[-1] >= policy.window
            or any(a >= b for a, b in zip(offsets, offsets[1:]))
            or start < prefix or start + offsets[-1] >= min(2**32, prefix + GLOBAL_WINDOW)):
        raise ValueError("invalid targeted request fields")
    return prefix, tuple(start + offset for offset in offsets)


class TargetedPackedWireTransport(PackedWireTransport):
    """Bound new recovery work while preserving every unconfirmed source."""

    def __init__(self, sim, reverse, config, policy=TargetedPolicy()):
        if not config.independent_delivery:
            raise ValueError("targeted packed recovery requires independent channel delivery")
        super().__init__(sim, reverse, config)
        self.policy = policy
        self.targeted_counts = Counter()
        self._request_armed = False
        self._probe_armed = False
        self._fresh = OrderedDict()
        self._repeat = OrderedDict()
        self._repeat_turn = False
        self._observed_end = 0

    def _new_known(self, symbols):
        for index in symbols:
            self._fresh.pop(index, None)
            self._repeat.pop(index, None)
        super()._new_known(symbols)

    def _advance(self):
        super()._advance()
        end = self.highest_received + 1
        if end > self.received_prefix + GLOBAL_WINDOW:
            raise ValueError("observed evidence exceeds source custody")
        # A received source or decoded repair header supplied this high water.
        # Each source ID is checked at most once here, even across long holes.
        start = max(self.received_prefix, self._observed_end)
        if start < end:
            due = self.sim.now + self.policy.gap_ms / 1000
            self.targeted_counts["window_positions_checked"] += end - start
            for index in range(start, end):
                if index not in self.decoder.known:
                    self._fresh[index] = due
            self._observed_end = end
            self.targeted_counts["peak_request_state"] = max(
                self.targeted_counts["peak_request_state"], len(self._fresh) + len(self._repeat))
        if (self._fresh or self._repeat) and not self._request_armed:
            self._arm_request()

    def _arm_request(self):
        self._request_armed = True
        self.sim.at(self.sim.now + self.policy.gap_ms / 1000, self._request_tick)

    def _request_tick(self):
        self._request_armed = False
        selected = []
        for _ in range(self.policy.max_ids):
            queues = (self._repeat, self._fresh) if self._repeat_turn else (self._fresh, self._repeat)
            for queue in queues:
                if queue and next(iter(queue.values())) <= self.sim.now:
                    index, _ = queue.popitem(last=False)
                    selected.append(index)
                    self._repeat[index] = self.sim.now + self.policy.repeat_ms / 1000
                    self._repeat_turn = queue is self._fresh
                    break
            else:
                break
        # The bounded work budget covers all spans combined. Charge another
        # datagram when distant targets cannot fit the current byte offsets.
        selected.sort()
        pos = 0
        while pos < len(selected):
            start = selected[pos]
            offsets = []
            while pos < len(selected) and selected[pos] - start < self.policy.window:
                offsets.append(selected[pos] - start)
                pos += 1
            wire = encode_request(self.received_prefix, start, offsets, self.policy,
                                  self.config.encapsulation)
            self.targeted_counts["request_packets_sent"] += 1
            self.targeted_counts["requested_ids"] += len(offsets)
            self.sim.send(not self.reverse, self.ip_header_bytes + len(wire), "gap_request",
                          lambda wire=wire: self._receive_request(wire))
        if self._fresh or self._repeat:
            self._arm_request()

    def _receive_request(self, wire):
        try:
            prefix, indices = decode_request(wire, self.policy, self.config.encapsulation)
        except ValueError:
            self.targeted_counts["invalid_requests"] += 1
            return
        if indices[-1] >= len(self.sources):
            self.targeted_counts["invalid_requests"] += 1
            return
        self.targeted_counts["request_packets_received"] += 1
        # A received cumulative prefix can retire older custody exactly as a
        # regular ACK would. Only the listed original IDs trigger extra sends.
        if prefix > self.base:
            self._receive_feedback(prefix, 0)
        for index in indices:
            if index < self.base:
                self.targeted_counts["stale_requested_ids"] += 1
            else:
                self._resend(index, "requested_retries")

    def _resend(self, index, reason):
        size = self.sources[index].size
        retained = self.source_payloads[index]
        if retained is None or len(retained) < size:
            raise RuntimeError("unconfirmed source outside retained custody")
        wire = encode_source(index, retained[:size], self.config.encapsulation)
        self.targeted_counts[reason] += 1
        self.targeted_counts["retry_ip_bytes"] += self.ip_header_bytes + len(wire)
        return self._send_wire(wire, "retry", 2)[0]

    def _schedule_tail(self, after, generation):
        # A busy sender updates last_source_at on every admitted original. One
        # actual timer follows that deadline without queueing a timer per send.
        if not self._probe_armed:
            self._arm_probe(after + self.policy.probe_ms / 1000)

    def _arm_probe(self, when):
        self._probe_armed = True
        self.sim.at(when, self._probe)

    def _probe(self):
        self._probe_armed = False
        if self.base >= len(self.sources):
            return
        interval = self.policy.probe_ms / 1000
        due = self.last_source_at + interval
        if self.sim.now < due:
            self._arm_probe(due)
            return
        finish = self._resend(self.base, "quiet_probes")
        self._arm_probe(finish + interval)
