"""Shared, frame-derived admission for bounded bidirectional L2 channels.

The current classifier accepts complete unfragmented Ethernet/IPv4/TCP frames.
Connection endpoints choose a deterministic channel, while every frame follows
its direction's same FIFO-per-channel, round-robin admission policy. Endpoint
callbacks are selected only after actual reconstructed frame bytes arrive.

Optional connection round-robin keeps separate local assignment tables for the
two directions. A receiver learns reply affinity only from a decoded frame's
validated channel. Conflicting simultaneous opposite-end assignments raise an
error. The modeled ordinary TCP and SYN response paths initiate in one direction.
"""

from collections import deque
from functools import partial
from zlib import crc32

from .compact import _checksum


def _parse_frame(frame):
    if not isinstance(frame, (bytes, bytearray, memoryview)):
        raise ValueError("mux frames must be bytes")
    frame = bytes(frame)
    if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
        raise ValueError("mux requires an Ethernet IPv4 TCP frame")
    ip_size = (frame[14] & 15) * 4
    ip_length = int.from_bytes(frame[16:18], "big")
    if (ip_size < 20 or ip_length < ip_size + 20 or 14 + ip_length > len(frame)
            or frame[23] != 6 or int.from_bytes(frame[20:22], "big") & 0x3FFF):
        raise ValueError("invalid or fragmented mux IPv4 TCP frame")
    ip = frame[14:14 + ip_size]
    tcp = frame[14 + ip_size:14 + ip_length]
    tcp_size = (tcp[12] >> 4) * 4
    if tcp_size < 20 or tcp_size > len(tcp):
        raise ValueError("invalid mux TCP header length")
    pseudo = frame[26:34] + b"\x00\x06" + len(tcp).to_bytes(2, "big")
    if _checksum(ip) != b"\x00\x00" or _checksum(pseudo + tcp) != b"\x00\x00":
        raise ValueError("invalid mux IP or TCP checksum")
    endpoints = ((frame[26:30], int.from_bytes(tcp[:2], "big")),
                 (frame[30:34], int.from_bytes(tcp[2:4], "big")))
    return frame, endpoints, len(tcp) - tcp_size


def frame_tuple(frame):
    """Return directional TCP endpoints after validating the complete frame."""
    return _parse_frame(frame)[1]


def _validate_tuple(endpoints):
    if not isinstance(endpoints, tuple) or len(endpoints) != 2:
        raise ValueError("endpoint identity must contain source and destination")
    for endpoint in endpoints:
        if (not isinstance(endpoint, tuple) or len(endpoint) != 2
                or not isinstance(endpoint[0], bytes) or len(endpoint[0]) != 4
                or isinstance(endpoint[1], bool) or not isinstance(endpoint[1], int)
                or not 0 <= endpoint[1] <= 65535):
            raise ValueError("endpoint identity requires IPv4 bytes and a TCP port")


class DuplexMux:
    """Arbitrate all submitted frames through the same bounded channel set."""

    def __init__(self, sim, transports, channel_count=16, mapping="crc32"):
        if (isinstance(channel_count, bool) or not isinstance(channel_count, int)
                or not 1 <= channel_count <= 256):
            raise ValueError("channel_count must be an integer from one to 256")
        if mapping not in ("crc32", "connection_round_robin"):
            raise ValueError("unknown mux connection mapping")
        if len(transports) != 2 or transports[0] is transports[1]:
            raise ValueError("mux requires distinct forward and reverse transports")
        if any(len(sim.links[reverse]) != 1 for reverse in (False, True)):
            raise ValueError("mux admission requires one physical FIFO per direction")
        if any(transport.sim is not sim or transport.reverse != reverse
               for reverse, transport in enumerate(transports)):
            raise ValueError("mux transports must share the simulator and match their direction")
        if any(getattr(transport, "capacity_callback", None) is not None for transport in transports):
            raise ValueError("transport already has a capacity observer")
        self.sim = sim
        self.transports = tuple(transports)
        self.channel_count = channel_count
        self.mapping = mapping
        self.connection_channels = [{}, {}]
        self.local_assignment_count = [0, 0]
        self.learned_binding_count = [0, 0]
        self.endpoints = [{}, {}]
        self.queues = [[deque() for _ in range(channel_count)] for _ in range(2)]
        self.channel_ids = [set(), set()]
        self.submitted_channel_ids = [set(), set()]
        self.submitted_frames = [0, 0]
        self.submitted_bytes = [0, 0]
        self.admitted_frames = [0, 0]
        self.admitted_bytes = [0, 0]
        self.delivered_frames = [0, 0]
        self.delivered_bytes = [0, 0]
        self.queued_frames = [0, 0]
        self.queued_bytes = [0, 0]
        self.peak_queued_bytes = [0, 0]
        self.channel_queued_bytes = [[0] * channel_count for _ in range(2)]
        self.channel_peak_bytes = [[0] * channel_count for _ in range(2)]
        self.channel_peak_frames = [[0] * channel_count for _ in range(2)]
        self.queue_wait_sum_ms = [0.0, 0.0]
        self.queue_wait_max_ms = [0.0, 0.0]
        self.window_stall_events = [0, 0]
        self._window_stalled = [False, False]
        self._next_channel = [0, 0]
        self._scheduled_at = [None, None]
        self._draining = [False, False]
        self._deliver_callbacks = [[partial(self._deliver, reverse, channel)
                                    for channel in range(channel_count)] for reverse in (False, True)]
        for reverse, transport in enumerate(self.transports):
            transport.capacity_callback = partial(self._wake, bool(reverse))

    @staticmethod
    def _direction(reverse):
        if not isinstance(reverse, bool):
            raise ValueError("reverse must be boolean")
        return reverse

    def _channel(self, reverse, endpoints):
        identity = tuple(sorted(endpoints))
        assigned = self.connection_channels[reverse].get(identity)
        if assigned is None:
            if self.mapping == "connection_round_robin":
                assigned = self.local_assignment_count[reverse] % self.channel_count
            else:
                ordered = [address + port.to_bytes(2, "big") for address, port in identity]
                assigned = crc32(b"\x06" + b"".join(ordered)) % self.channel_count
            self.connection_channels[reverse][identity] = assigned
            self.local_assignment_count[reverse] += 1
        return assigned

    def channel_for_frame(self, frame, *, reverse=False):
        """Classify at one sender, using an already learned reply binding if any."""
        reverse = self._direction(reverse)
        return self._channel(reverse, frame_tuple(frame))

    def register_endpoint(self, reverse, directional_tuple, callback):
        reverse = self._direction(reverse)
        _validate_tuple(directional_tuple)
        if not callable(callback):
            raise ValueError("endpoint callback must be callable")
        existing = self.endpoints[reverse].get(directional_tuple)
        if existing is not None and existing != callback:
            raise ValueError("endpoint identity already has a different receiver")
        self.endpoints[reverse][directional_tuple] = callback

    def submit_frame(self, reverse, frame):
        reverse = self._direction(reverse)
        frame, endpoints, payload_bytes = _parse_frame(frame)
        channel = self._channel(reverse, endpoints)
        queue = self.queues[reverse][channel]
        queue.append((frame, payload_bytes, self.sim.now))
        self.submitted_frames[reverse] += 1
        self.submitted_bytes[reverse] += len(frame)
        self.submitted_channel_ids[reverse].add(channel)
        self.queued_frames[reverse] += 1
        self.queued_bytes[reverse] += len(frame)
        self.peak_queued_bytes[reverse] = max(self.peak_queued_bytes[reverse], self.queued_bytes[reverse])
        self.channel_queued_bytes[reverse][channel] += len(frame)
        self.channel_peak_bytes[reverse][channel] = max(
            self.channel_peak_bytes[reverse][channel], self.channel_queued_bytes[reverse][channel])
        self.channel_peak_frames[reverse][channel] = max(self.channel_peak_frames[reverse][channel], len(queue))
        self._wake(reverse)
        return channel

    def _blocked(self, reverse):
        transport = self.transports[reverse]
        blocked = bool(transport.source_queue or len(transport.sources) - transport.base >= transport.config.block_sources
                       or self._next_ready_channel(reverse) is None)
        if blocked and not self._window_stalled[reverse]:
            self.window_stall_events[reverse] += 1
        self._window_stalled[reverse] = blocked
        return blocked

    def _next_ready_channel(self, reverse):
        can_submit = getattr(self.transports[reverse], "can_submit_channel", None)
        for offset in range(self.channel_count):
            channel = (self._next_channel[reverse] + offset) % self.channel_count
            if self.queues[reverse][channel] and (can_submit is None or can_submit(channel)):
                return channel
        return None

    def _wake(self, reverse):
        if not self.queued_frames[reverse] or self._draining[reverse] or self._scheduled_at[reverse] is not None:
            return
        if self._blocked(reverse):
            return
        when = max(self.sim.now, self.sim.links[reverse][0].free_at)
        self._scheduled_at[reverse] = when
        self.sim.at(when, self._drain, reverse)

    def _drain(self, reverse):
        self._scheduled_at[reverse] = None
        if not self.queued_frames[reverse] or self._blocked(reverse):
            return
        if self.sim.links[reverse][0].free_at > self.sim.now:
            self._wake(reverse)
            return
        channel = self._next_ready_channel(reverse)
        frame, payload_bytes, submitted_at = self.queues[reverse][channel].popleft()
        self._next_channel[reverse] = (channel + 1) % self.channel_count
        self.queued_frames[reverse] -= 1
        self.queued_bytes[reverse] -= len(frame)
        self.channel_queued_bytes[reverse][channel] -= len(frame)
        self._draining[reverse] = True
        try:
            self.transports[reverse].submit_channel(
                channel, len(frame), payload_bytes, self._deliver_callbacks[reverse][channel],
                frame=frame, deliver_frame=True)
        finally:
            self._draining[reverse] = False
        self.admitted_frames[reverse] += 1
        self.admitted_bytes[reverse] += len(frame)
        self.channel_ids[reverse].add(channel)
        wait_ms = (self.sim.now - submitted_at) * 1000
        self.queue_wait_sum_ms[reverse] += wait_ms
        self.queue_wait_max_ms[reverse] = max(self.queue_wait_max_ms[reverse], wait_ms)
        self._wake(reverse)

    def _deliver(self, reverse, channel, frame):
        frame, endpoints, _ = _parse_frame(frame)
        callback = self.endpoints[reverse].get(endpoints)
        if callback is None:
            raise ValueError("decoded mux frame has no registered endpoint")
        if self.mapping == "connection_round_robin":
            identity = tuple(sorted(endpoints))
            learned = self.connection_channels[not reverse].get(identity)
            if learned is not None and learned != channel:
                raise ValueError("received channel conflicts with a local simultaneous connection assignment")
            if learned is None:
                self.connection_channels[not reverse][identity] = channel
                self.learned_binding_count[not reverse] += 1
        self.delivered_frames[reverse] += 1
        self.delivered_bytes[reverse] += len(frame)
        callback(frame)

    def queue_delay_ms(self, reverse):
        """Estimate backlog from physical service and unsent frame/source bytes.

        Queued frames use their original Ethernet size plus one source header.
        Encoded transport sources use their actual buffered size and headers.
        Future repair, copy and context-refresh costs are excluded from this
        diagnostic estimate. Actual enqueue-to-admission waits are also recorded.
        """
        reverse = self._direction(reverse)
        transport = self.transports[reverse]
        link = self.sim.links[reverse][0]
        queued = self.queued_bytes[reverse] + transport.buffer_bytes
        queued += transport.source_header * (self.queued_frames[reverse] + len(transport.source_queue))
        if getattr(transport, "pending_pack_bytes", 0):
            queued += transport.source_header
        return (max(0, link.free_at - self.sim.now) + queued / link.bytes_per_s) * 1000

    @property
    def flushed(self):
        return not any(self.queued_frames)

    def measurements(self):
        classifier = "CRC32(protocol + sorted IPv4 TCP endpoints) modulo channel_count"
        if self.mapping == "connection_round_robin":
            classifier = "Local first-classification round-robin with reply affinity learned from decoded wire channels"
        row = {"mux_channel_count": self.channel_count,
               "mux_mapping": self.mapping,
               "mux_assigned_connection_count": len(set(self.connection_channels[0]) | set(self.connection_channels[1])),
               "mux_classifier": classifier,
               "mux_arbiter": "Per-direction per-channel FIFO with round-robin frame admission"}
        for reverse, direction in enumerate(("forward", "reverse")):
            admitted = self.admitted_frames[reverse]
            row["mux_" + direction] = {
                "submitted_frames": self.submitted_frames[reverse],
                "submitted_bytes": self.submitted_bytes[reverse],
                "admitted_frames": admitted,
                "admitted_bytes": self.admitted_bytes[reverse],
                "delivered_frames": self.delivered_frames[reverse],
                "delivered_bytes": self.delivered_bytes[reverse],
                "channel_ids": sorted(self.channel_ids[reverse]),
                "submitted_channel_ids": sorted(self.submitted_channel_ids[reverse]),
                "channel_count": len(self.channel_ids[reverse]),
                "registered_endpoints": len(self.endpoints[reverse]),
                "assigned_connection_count": len(self.connection_channels[reverse]),
                "local_assignment_count": self.local_assignment_count[reverse],
                "learned_binding_count": self.learned_binding_count[reverse],
                "queued_frames": self.queued_frames[reverse],
                "queued_bytes": self.queued_bytes[reverse],
                "peak_queued_bytes": self.peak_queued_bytes[reverse],
                "channel_peak_bytes": list(self.channel_peak_bytes[reverse]),
                "channel_peak_frames": list(self.channel_peak_frames[reverse]),
                "queue_wait_count": admitted,
                "queue_wait_mean_ms": self.queue_wait_sum_ms[reverse] / admitted if admitted else None,
                "queue_wait_max_ms": self.queue_wait_max_ms[reverse] if admitted else None,
                "window_stall_events": self.window_stall_events[reverse],
                "queue_delay_estimate_ms": self.queue_delay_ms(bool(reverse)),
            }
        return row
