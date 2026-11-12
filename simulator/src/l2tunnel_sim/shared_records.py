"""Byte-framed shared coding with independent ordered delivery per channel."""

from collections import defaultdict, deque
from dataclasses import dataclass
from functools import partial
from struct import Struct

from .compact import CompactConfig, CompactHeaderCodec, CompactSource, CompactTransport
from .compact_tcp import CompactTCP
from .multiflow import MultiFlow
from .shared_compact import CompactChannel


RECORD_HEADER = Struct("!BHH")  # Channel, wrapping channel sequence, encoded size.
SYMBOL_HEADER = Struct("!HH")  # Valid bytes, first complete record-header offset.
NO_RECORD_HEADER = 65535


@dataclass(frozen=True)
class SharedRecordConfig(CompactConfig):
    header_profile: str = "tcp_delta"
    repair_window_sources: int = 0
    global_repair_every: int = 4
    independent_delivery: bool = True

    def __post_init__(self):
        super().__post_init__()
        if self.header_profile != "tcp_delta":
            raise ValueError("shared records require the reversible delta codec")
        for name in ("repair_window_sources", "global_repair_every"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
                raise ValueError(f"{name} must be an unsigned 16-bit integer")
        if not isinstance(self.independent_delivery, bool):
            raise ValueError("independent_delivery must be boolean")


class SharedRecordReceiver:
    """Find and reconstruct records using only received symbol bytes.

    A two-byte anchor locates the first record header after an initial body
    continuation. Headers fit wholly within one symbol. Body continuations
    follow consecutive source IDs. Padding is excluded by the valid length.
    The half-range serial rule permits at most 32767 outstanding channel
    records. Each channel decodes its original delta context in order.
    """

    def __init__(self, capacity):
        self.capacity = capacity
        self.symbols = {}
        self.seen = set()
        self.pending = {}
        self.complete = defaultdict(dict)
        self.expected = defaultdict(int)
        self.codecs = defaultdict(lambda: CompactHeaderCodec(delta=True))

    def receive(self, index, data):
        if index in self.seen:
            return []
        if len(data) != self.capacity + SYMBOL_HEADER.size:
            raise ValueError("invalid shared-record symbol length")
        valid, anchor = SYMBOL_HEADER.unpack_from(data)
        if not 0 < valid <= self.capacity:
            raise ValueError("invalid shared-record valid length")
        if anchor != NO_RECORD_HEADER and anchor + RECORD_HEADER.size > valid:
            raise ValueError("record anchor does not identify a complete header")
        content = data[SYMBOL_HEADER.size:SYMBOL_HEADER.size + valid]
        self.symbols[index] = content
        self.seen.add(index)
        position = anchor
        while position != NO_RECORD_HEADER and position < valid:
            if position + RECORD_HEADER.size > valid:
                raise ValueError("record header crosses a symbol boundary")
            channel, serial, size = RECORD_HEADER.unpack_from(content, position)
            if not size:
                raise ValueError("empty encoded record")
            distance = (serial - self.expected[channel]) & 65535
            if distance < 32768:
                key = (channel, self.expected[channel] + distance)
                self.pending.setdefault(key, (index, position + RECORD_HEADER.size, size))
            position += RECORD_HEADER.size + size
        for key, (source, offset, size) in tuple(self.pending.items()):
            pieces, remaining = [], size
            while remaining and source in self.symbols:
                part = self.symbols[source][offset:offset + remaining]
                pieces.append(part)
                remaining -= len(part)
                source, offset = source + 1, 0
            if not remaining:
                channel, serial = key
                self.complete[channel][serial] = b"".join(pieces)
                del self.pending[key]
        delivered = []
        for channel, records in self.complete.items():
            while self.expected[channel] in records:
                serial = self.expected[channel]
                frames = self.codecs[channel].decode(records.pop(serial))
                if len(frames) != 1:
                    raise ValueError("a shared record must contain exactly one frame")
                delivered.append((channel, serial, frames[0]))
                self.expected[channel] += 1
        return delivered

    def discard_before(self, prefix):
        keep = min((record[0] for record in self.pending.values()), default=prefix)
        for index in tuple(self.symbols):
            if index < min(prefix, keep):
                del self.symbols[index]


class SharedRecordTransport(CompactTransport):
    """Pool coding while preserving independent wire-visible channel order.

    Every source carries a fixed-size symbol, including padding, valid length,
    and the resynchronization anchor. Repairs protect all those bytes. The
    existing start/count/seed repair header identifies dense or bounded bands.
    Scheduled band selection uses sender sequence numbers and configuration.
    Tail repairs cover the complete unconfirmed window.
    """

    def __init__(self, sim, reverse, config):
        if not isinstance(config, SharedRecordConfig):
            raise TypeError("SharedRecordTransport requires SharedRecordConfig")
        super().__init__(sim, reverse, config)
        self.record_capacity -= 2  # Additional anchor beyond the existing valid length.
        if self.record_capacity < RECORD_HEADER.size:
            raise ValueError("MTU cannot hold a complete shared-record header")
        self.byte_buffer = bytearray()
        self.record_starts = deque()
        self.channel_sequences = defaultdict(int)
        self.channel_completed = defaultdict(int)
        self.channel_codecs = defaultdict(lambda: CompactHeaderCodec(delta=True))
        self.callbacks = {}
        self.source_payloads = []
        self.receiver = SharedRecordReceiver(self.record_capacity)
        self.padding_bytes = 0
        self.anchor_bytes = 0
        self.local_repairs = 0
        self.global_repairs = 0

    def submit_channel(self, channel, frame_bytes, payload_bytes, deliver, *, ack=False, frame=None, deliver_frame=False):
        if isinstance(channel, bool) or not isinstance(channel, int) or not 0 <= channel < 256:
            raise ValueError("shared-record channels must fit one byte")
        if frame is None or len(frame) != frame_bytes or not 0 <= payload_bytes <= frame_bytes:
            raise ValueError("complete serialized frame and valid byte counts are required")
        serial = self.channel_sequences[channel]
        if serial - self.channel_completed[channel] >= 32767:
            raise ValueError("channel record window exceeds serial-number half range")
        codec = self.channel_codecs[channel]
        old_context = codec.context
        body = codec.encode(frame)
        if len(body) > 65535:
            codec.context = old_context
            raise ValueError("encoded record exceeds the 16-bit length field")
        encoded = RECORD_HEADER.pack(channel, serial & 65535, len(body)) + body
        context = 69 if body[0] == 0 else 0
        self.record_starts.append(self.submitted_bytes)
        self.byte_buffer.extend(encoded)
        self.buffer_bytes += len(encoded)
        self.submitted_bytes += len(encoded)
        self.profile_context_bytes += context
        self.source_record_bytes += len(encoded) - context
        self.frame_count += 1
        self.channel_sequences[channel] += 1
        self.callbacks[channel, serial] = (frame, self.sim.now, deliver, deliver_frame)
        self.peak_pending_bytes = max(self.peak_pending_bytes, self.pending_bytes)
        self._flush_full()
        self._schedule_flush()

    def _source(self, size):
        end = self.sent_bytes + size
        split_header = next((start for start in self.record_starts
                             if end - RECORD_HEADER.size < start < end), None)
        if split_header is not None:
            size = split_header - self.sent_bytes
        if size <= 0:
            raise ValueError("source has no room for a complete record header")
        anchor = self.record_starts[0] - self.sent_bytes if self.record_starts else NO_RECORD_HEADER
        if anchor >= size:
            anchor = NO_RECORD_HEADER
        padding = self.record_capacity - size
        payload = SYMBOL_HEADER.pack(size, anchor) + self.byte_buffer[:size] + bytes(padding)
        del self.byte_buffer[:size]
        self.buffer_bytes -= size
        self.sent_bytes += size
        while self.record_starts and self.record_starts[0] < self.sent_bytes:
            self.record_starts.popleft()
        source = CompactSource(len(self.sources), size, self.sent_bytes)
        self.sources.append(source)
        self.source_payloads.append(bytes(payload))
        self.padding_bytes += padding
        self.anchor_bytes += 2
        finish, _ = self.sim.send(self.reverse, self.source_header + self.symbol_bytes, "source",
                                  lambda: self._receive_source(source))
        self.last_source_at = finish
        self.credit += self.credit_numerator
        while self.credit >= self.credit_denominator:
            self.credit -= self.credit_denominator
            self._repair(False)
        self.tail_generation += 1
        self._schedule_tail(finish, self.tail_generation)

    def _repair(self, tail):
        if self.base >= len(self.sources):
            return
        self.repair_serial += 1
        start, end = self.base, len(self.sources)
        window, every = self.config.repair_window_sources, self.config.global_repair_every
        local = not tail and window and (not every or self.repair_serial % every)
        if local:
            start = max(start, end - window)
        seed = (self.repair_serial * 2654435761) & 0xFFFFFFFF
        self.sim.send(self.reverse, self.repair_header + self.symbol_bytes, "repair",
                      lambda: self._receive_repair(start, end, seed))
        self.local_repairs += bool(local)
        self.global_repairs += not local
        self.tail_repairs += bool(tail)
        self.scheduled_repairs += not tail

    def _new_known(self, symbols):
        super()._new_known(symbols)
        if self.config.independent_delivery:
            for index in symbols:
                self._deliver_symbol(index)

    def _deliver_symbol(self, index):
        for channel, serial, frame in self.receiver.receive(index, self.source_payloads[index]):
            expected, created_at, callback, deliver_frame = self.callbacks.pop((channel, serial))
            if frame != expected:
                raise ValueError("reconstructed frame differs from submitted bytes")
            self.channel_completed[channel] = serial + 1
            self.delivered_bytes += len(frame)
            self.delays.append((self.sim.now - created_at) * 1000)
            if self.sim.now <= self.sim.traffic.duration_s:
                self.delivered_during_measurement_bytes += len(frame)
            if deliver_frame:
                callback(frame)
            else:
                callback()

    def _advance(self):
        before = self.received_prefix
        super()._advance()
        if not self.config.independent_delivery:
            for index in range(before, self.received_prefix):
                self._deliver_symbol(index)
        if self.received_prefix > before:
            self.receiver.discard_before(self.received_prefix)

    def _receive_feedback(self, prefix, deficit):
        previous = self.base
        super()._receive_feedback(prefix, deficit)
        for index in range(previous, self.base):
            self.source_payloads[index] = None


class SharedRecordMultiFlow(MultiFlow):
    def __init__(self, *args, compact_config, simulation_factory=None,
                 transport_type=SharedRecordTransport, **kwargs):
        factory = simulation_factory or partial(CompactTCP, compact_config=compact_config, reliable_acks=False)
        super().__init__(*args, simulation_factory=factory, **kwargs)
        if len(self.flows) > 256:
            raise ValueError("shared-record format supports up to 256 channels")
        if any(flow.compact_config != compact_config or flow.reliable_acks for flow in self.flows):
            raise ValueError("shared records require matching configurations and native ACK paths")
        self.shared_forward = transport_type(self.flows[0], False, compact_config)
        for channel, flow in enumerate(self.flows):
            flow.compact_forward = CompactChannel(self.shared_forward, channel)
