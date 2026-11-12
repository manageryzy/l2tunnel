"""Multiplex independent TCP record contexts over a shared coded tunnel."""

from functools import partial
from struct import Struct

from .compact import CompactHeaderCodec, CompactTransport
from .compact_tcp import CompactTCP
from .multiflow import MultiFlow


class MultiplexedHeaderCodec:
    """Frame each existing byte codec with a channel ID and encoded length.

    The two-byte channel and four-byte body length are carried on the wire.
    Each channel has independent compression state. A receiver processes the
    complete ordered record after its constituent coding symbols are decoded.
    """

    prefix = Struct("!HI")

    def __init__(self):
        self.channels = {}

    def encode(self, channel, frame):
        if isinstance(channel, bool) or not isinstance(channel, int) or not 0 <= channel <= 65535:
            raise ValueError("channel must be a 16-bit unsigned integer")
        codec = self.channels.setdefault(channel, CompactHeaderCodec(delta=True))
        body = codec.encode(frame)
        return self.prefix.pack(channel, len(body)) + body

    def decode(self, data):
        frames, position = [], 0
        while position < len(data):
            if len(data) - position < self.prefix.size:
                raise ValueError("truncated multiplexed record header")
            channel, size = self.prefix.unpack_from(data, position)
            position += self.prefix.size
            if len(data) - position < size:
                raise ValueError("truncated multiplexed record body")
            codec = self.channels.setdefault(channel, CompactHeaderCodec(delta=True))
            frames.extend((channel, frame) for frame in codec.decode(data[position:position + size]))
            position += size
        return frames


class MultiplexedCompactTransport(CompactTransport):
    """Share coding, packetization, and confirmations across channel records."""

    def __init__(self, sim, reverse, config):
        if config.header_profile != "tcp_delta":
            raise ValueError("multiplexed compact transport requires the delta byte codec")
        super().__init__(sim, reverse, config)
        self.multiplexer = MultiplexedHeaderCodec()

    def submit_channel(self, channel, frame_bytes, payload_bytes, deliver, *, ack=False, frame=None):
        if frame is None or len(frame) != frame_bytes or not 0 <= payload_bytes <= frame_bytes:
            raise ValueError("a complete serialized frame and valid byte counts are required")
        encoded = self.multiplexer.encode(channel, frame)
        context = 69 if encoded[self.multiplexer.prefix.size] == 0 else 0
        self.context_sent = True
        self.profile_context_bytes += context
        self.source_record_bytes += len(encoded) - context
        self.buffer_bytes += len(encoded)
        self.submitted_bytes += len(encoded)
        self.frame_count += 1
        self.records.append((self.submitted_bytes, frame_bytes, self.sim.now, deliver))
        self.peak_pending_bytes = max(self.peak_pending_bytes, self.pending_bytes)
        self._flush_full()
        self._schedule_flush()


class CompactChannel:
    """Expose one submit endpoint while retaining shared confirmation state."""

    def __init__(self, transport, channel):
        self.transport = transport
        self.channel = channel

    def submit(self, *args, **kwargs):
        self.transport.submit_channel(self.channel, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.transport, name)


class SharedCompactMultiFlow(MultiFlow):
    """Independent TCP state over one forward GF(256) record transport.

    The first endpoint owns shared outer datagram accounting. All endpoints
    already share physical links, event time, and loss RNGs through MultiFlow.
    Native or coalesced TCP ACKs continue to use each endpoint's reverse path.
    """

    def __init__(self, *args, compact_config, simulation_factory=None, **kwargs):
        if simulation_factory is None:
            simulation_factory = partial(CompactTCP, compact_config=compact_config, reliable_acks=False)
        super().__init__(*args, simulation_factory=simulation_factory, **kwargs)
        if len(self.flows) > 65536:
            raise ValueError("channel identifiers support at most 65536 connections")
        if any(flow.compact_config != compact_config or flow.reliable_acks for flow in self.flows):
            raise ValueError("shared forward coding requires matching compact configurations and native ACK paths")
        self.shared_forward = MultiplexedCompactTransport(self.flows[0], False, compact_config)
        for channel, flow in enumerate(self.flows):
            flow.compact_forward = CompactChannel(self.shared_forward, channel)
