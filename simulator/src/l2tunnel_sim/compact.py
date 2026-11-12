"""Compact stream packetization with feedback-driven elastic GF(256) coding.

The model packs records across Ethernet-frame boundaries. Its bulk IPv4/TCP
profile preserves the complete frame using one reliable 66-byte context and
23 dynamic header bytes plus a three-byte record prefix. ``compact_header``
implements that profile on actual frames. Packet simulation carries lengths
and GF(256) coefficients, matching the existing simulator's payload abstraction.

CPU time, authentication, and congestion fairness are not modeled. The profile
supports Ethernet/IPv4/TCP with the conventional 12-byte timestamp option.
Other headers require a full-frame record, as used by ``compact_header``.
"""

from collections import deque
from dataclasses import dataclass
from fractions import Fraction
from math import ceil, isfinite
from struct import unpack

from .coding import Decoder
from .model import Simulation


@dataclass(frozen=True)
class CompactConfig:
    repair_ratio: float = 0.19
    block_sources: int = 8192  # Maximum elastic encoding-window length.
    flush_ms: float = 0.5
    feedback_ms: float = 5.0
    feedback_packets: int = 64
    outer_header_bytes: int = 36  # IPv4 20, UDP 8, source identifier 8.
    authentication_bytes: int = 0
    header_profile: str = "tcp_timestamp"
    coding: str = "gf256"
    tail_repair_delay_ms: float | None = None  # None retains max(2 * RTT, 50 ms).

    def __post_init__(self):
        if not 0 <= self.repair_ratio <= 1:
            raise ValueError("repair_ratio must lie between zero and one")
        if self.block_sources < 1 or self.block_sources > 65535:
            raise ValueError("block_sources must fit a 16-bit window length")
        if self.flush_ms <= 0 or self.feedback_ms <= 0 or self.feedback_packets < 1:
            raise ValueError("flush and feedback intervals must be positive")
        if self.outer_header_bytes < 36 or self.authentication_bytes < 0:
            raise ValueError("header budget is smaller than the specified format")
        if self.header_profile not in ("tcp_timestamp", "tcp_delta", "full_l2"):
            raise ValueError("unknown compact record profile")
        if self.coding != "gf256":
            raise ValueError("compact transport requires the actual GF256 rank decoder")
        delay = self.tail_repair_delay_ms
        if delay is not None and (isinstance(delay, bool) or not isinstance(delay, (int, float))
                                  or not isfinite(delay) or delay <= 0):
            raise ValueError("tail_repair_delay_ms must be finite and positive or None")

    @property
    def record_header_bytes(self):
        return 26 if self.header_profile == "tcp_timestamp" else 69


@dataclass(frozen=True)
class CompactSource:
    index: int
    size: int
    end_offset: int


def coefficient(seed, symbol):
    """Counter-based 8-bit coefficient, reproducible from a 32-bit packet seed."""
    value = (seed ^ (symbol * 0x9E3779B9)) & 0xFFFFFFFF
    value ^= value >> 16
    value = value * 0x85EBCA6B & 0xFFFFFFFF
    value ^= value >> 13
    value = value * 0xC2B2AE35 & 0xFFFFFFFF
    return (value ^ (value >> 16)) & 255


class CompactTransport:
    """Reliable ordered record stream over one direction of ``Simulation``.

    ``submit(frame_bytes, payload_bytes, deliver, ack=False)`` accepts a complete
    frame. ``deliver()`` fires once, after every byte of the reconstructed record
    is available. The context and record lengths are charged to source packets.
    The eight-byte source header includes a 32-bit source ID. The 12-byte repair
    header includes a 32-bit first source ID, 16-bit window length, 32-bit random
    seed, and two bytes for type/version. Each coding symbol also contains a
    two-byte valid length, allowing partial-symbol recovery without side data.
    """

    def __init__(self, sim, reverse, config=CompactConfig()):
        self.sim, self.reverse, self.config = sim, reverse, config
        self.source_header = config.outer_header_bytes + config.authentication_bytes
        self.repair_header = self.source_header + 4
        self.symbol_bytes = sim.scenario.mtu - self.repair_header
        self.record_capacity = self.symbol_bytes - 2
        if self.record_capacity < 1:
            raise ValueError("MTU leaves no compact coding-symbol payload")
        self.sources = []
        self.records = deque()
        self.buffer_bytes = 0
        self.submitted_bytes = 0
        self.sent_bytes = 0
        self.context_sent = False
        self.header_codec = CompactHeaderCodec(delta=config.header_profile == "tcp_delta")
        self.base = 0
        self.decoder = Decoder()
        self.received_prefix = 0
        self.highest_received = -1
        self.received_source = set()
        self.known_bytes = 0
        self.credit = 0
        ratio = Fraction(str(config.repair_ratio))
        self.credit_numerator, self.credit_denominator = ratio.numerator, ratio.denominator
        self.flush_generation = 0
        self.feedback_generation = 0
        self.feedback_pending = False
        self.feedback_events = 0
        self.last_source_at = 0.0
        self.tail_generation = 0
        self.reported_deficit = 1
        self.repair_serial = 0
        self.delivered_bytes = 0
        self.delivered_during_measurement_bytes = 0
        self.delays = []
        self.recovered_symbols = 0
        self.peak_pending_bytes = 0
        self.peak_reorder_bytes = 0
        self.frame_count = 0
        self.source_record_bytes = 0
        self.profile_context_bytes = 0
        self.scheduled_repairs = 0
        self.tail_repairs = 0

    @property
    def pending(self):
        return range(self.base, len(self.sources))

    @property
    def pending_bytes(self):
        return self.submitted_bytes - (self.sources[self.base - 1].end_offset if self.base else 0)

    def submit(self, frame_bytes, payload_bytes, deliver, ack=False, frame=None):
        if frame_bytes < payload_bytes or payload_bytes < 0:
            raise ValueError("invalid frame or payload length")
        if self.config.header_profile != "full_l2" and frame_bytes - payload_bytes != 66:
            raise ValueError("timestamp compression profile requires a 66-byte L2/IP/TCP header")
        if self.config.header_profile == "tcp_delta":
            if frame is None or len(frame) != frame_bytes:
                raise ValueError("delta compression requires the serialized complete Ethernet frame")
            encoded = self.header_codec.encode(frame)
            context = 69 if encoded[0] == 0 else 0
            size = len(encoded) - context
        else:
            context = (69 if self.config.header_profile == "tcp_timestamp"
                       and not self.context_sent else 0)
            size = (payload_bytes + 26 if self.config.header_profile == "tcp_timestamp"
                    else frame_bytes + 3)
        if not self.context_sent:
            self.context_sent = True
        self.buffer_bytes += context
        self.submitted_bytes += context
        self.profile_context_bytes += context
        self.source_record_bytes += size
        self.buffer_bytes += size
        self.submitted_bytes += size
        self.frame_count += 1
        self.records.append((self.submitted_bytes, frame_bytes, self.sim.now, deliver))
        self.peak_pending_bytes = max(self.peak_pending_bytes, self.pending_bytes)
        self._flush_full()
        self._schedule_flush()

    def _schedule_flush(self):
        if self.buffer_bytes:
            self.flush_generation += 1
            self.sim.at(self.sim.now + self.config.flush_ms / 1000,
                        self.flush, self.flush_generation)

    def _flush_full(self):
        while (self.buffer_bytes >= self.record_capacity
               and len(self.sources) - self.base < self.config.block_sources):
            self._source(self.record_capacity)

    def flush(self, generation=None):
        if generation is not None and generation != self.flush_generation:
            return
        self._flush_full()
        if self.buffer_bytes and len(self.sources) - self.base < self.config.block_sources:
            self._source(min(self.buffer_bytes, self.record_capacity))

    def _source(self, size):
        self.buffer_bytes -= size
        self.sent_bytes += size
        source = CompactSource(len(self.sources), size, self.sent_bytes)
        self.sources.append(source)
        finish, _ = self.sim.send(self.reverse, self.source_header + 2 + size, "source",
                                  lambda: self._receive_source(source))
        self.last_source_at = finish
        self.credit += self.credit_numerator
        while self.credit >= self.credit_denominator:
            self.credit -= self.credit_denominator
            self._repair(False)
        self.tail_generation += 1
        self._schedule_tail(finish, self.tail_generation)

    def _schedule_tail(self, after, generation):
        """Schedule from source serialization finish, or the previous tail attempt."""
        delay_ms = self.config.tail_repair_delay_ms
        if delay_ms is None:
            rtt = min(link.rtt for link in self.sim.links[self.reverse])
            delay = max(2 * rtt, 0.05)
        else:
            delay = delay_ms / 1000
        when = after + delay
        if when <= after:
            raise ValueError("tail repair delay must advance the simulation clock")
        self.sim.at(when, self._tail, generation)

    def _repair(self, tail):
        if self.base >= len(self.sources):
            return
        start, end = self.base, len(self.sources)
        self.repair_serial += 1
        seed = (self.repair_serial * 2654435761) & 0xFFFFFFFF
        size = max(source.size for source in self.sources[start:end]) + 2
        self.sim.send(self.reverse, self.repair_header + size, "repair",
                      lambda: self._receive_repair(start, end, seed))
        if tail:
            self.tail_repairs += 1
        else:
            self.scheduled_repairs += 1

    def _tail(self, generation):
        if generation != self.tail_generation or self.base >= len(self.sources):
            return
        # Retry the receiver's reported deficit until feedback retires the window.
        for _ in range(max(1, self.reported_deficit)):
            self._repair(True)
        self._schedule_tail(self.sim.now, generation)

    def _notice(self, end):
        self.highest_received = max(self.highest_received, end - 1)

    def _receive_source(self, source):
        self._notice(source.index + 1)
        self.received_source.add(source.index)
        self._new_known(self.decoder.insert({source.index: 1}))
        self._advance()

    def _receive_repair(self, start, end, seed):
        self._notice(end)
        coefficients = {index: coefficient(seed, index) for index in range(start, end)
                        if index not in self.decoder.known}
        self._new_known(self.decoder.insert(coefficients))
        self._advance()

    def _new_known(self, symbols):
        self.known_bytes += sum(self.sources[index].size for index in symbols)

    def _advance(self):
        while self.received_prefix in self.decoder.known:
            if self.received_prefix not in self.received_source:
                self.recovered_symbols += 1
            self.received_prefix += 1
        offset = self.sources[self.received_prefix - 1].end_offset if self.received_prefix else 0
        while self.records and self.records[0][0] <= offset:
            _, size, created_at, deliver = self.records.popleft()
            self.delivered_bytes += size
            self.delays.append((self.sim.now - created_at) * 1000)
            if self.sim.now <= self.sim.traffic.duration_s:
                self.delivered_during_measurement_bytes += size
            deliver()
        gap_bytes = self.known_bytes - offset
        self.peak_reorder_bytes = max(self.peak_reorder_bytes, gap_bytes)
        self.feedback_events += 1
        if self.feedback_events >= self.config.feedback_packets:
            self._feedback()
        elif not self.feedback_pending:
            self.feedback_pending = True
            self.feedback_generation += 1
            self.sim.at(self.sim.now + self.config.feedback_ms / 1000,
                        self._feedback, self.feedback_generation)

    def _feedback(self, generation=None):
        if generation is not None and generation != self.feedback_generation:
            return
        self.feedback_generation += 1
        self.feedback_pending = False
        self.feedback_events = 0
        prefix = self.received_prefix
        missing = self.highest_received + 1 - len(self.decoder.known)
        rank = len(self.decoder.rows)
        deficit = max(0, missing - rank)
        self.sim.send(not self.reverse, 40 + self.config.authentication_bytes, "feedback",
                      lambda: self._receive_feedback(prefix, deficit))

    def _receive_feedback(self, prefix, deficit):
        if prefix < self.base:
            return
        self.base = prefix
        self.reported_deficit = deficit
        self._flush_full()
        self._schedule_flush()


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total & 65535).to_bytes(2, "big")


class CompactHeaderCodec:
    """Executable, reversible profile for the model's 26-byte TCP record.

    A context record is type 0, two-byte body length, then the full 66-byte
    Ethernet/IPv4/TCP header. Data records use type 1, two-byte payload length,
    23 dynamic header bytes, then payload. Unsupported frames use type 2 plus
    their two-byte complete-frame length and the original bytes. Checksums and
    IPv4 total length are regenerated and checked before selecting the profile.
    The single-flow context is established in the same reliable coding stream.
    """

    dynamic = (slice(18, 20), slice(38, 46), slice(47, 50), slice(52, 54), slice(58, 66))
    delta_fields = (slice(18, 20), slice(38, 42), slice(42, 46), slice(47, 48),
                    slice(48, 50), slice(52, 54), slice(58, 62), slice(62, 66))

    def __init__(self, *, delta=False):
        self.context = None
        self.delta = delta

    @staticmethod
    def _supported(frame):
        return (66 <= len(frame) <= 65535 and frame[12:15] == b"\x08\x00\x45"
                and frame[23] == 6 and frame[46] >> 4 == 8
                and frame[54:58] == b"\x01\x01\x08\x0a"
                and int.from_bytes(frame[16:18], "big") == len(frame) - 14
                and int.from_bytes(frame[20:22], "big") & 0x3FFF == 0)

    @classmethod
    def _restore(cls, context, dynamic, payload):
        header = bytearray(context)
        offset = 0
        for area in cls.dynamic:
            size = area.stop - area.start
            header[area] = dynamic[offset:offset + size]
            offset += size
        header[16:18] = (len(payload) + 52).to_bytes(2, "big")
        header[24:26] = b"\x00\x00"
        header[50:52] = b"\x00\x00"
        header[24:26] = _checksum(bytes(header[14:34]))
        pseudo = bytes(header[26:34]) + b"\x00\x06" + (len(payload) + 32).to_bytes(2, "big")
        header[50:52] = _checksum(pseudo + bytes(header[34:]) + payload)
        return bytes(header) + payload

    def encode(self, frame):
        frame = bytes(frame)
        if not self._supported(frame):
            return b"\x02" + len(frame).to_bytes(2, "big") + frame
        dynamic = b"".join(frame[area] for area in self.dynamic)
        context = frame[:66]
        if self._restore(context, dynamic, frame[66:]) != frame:
            return b"\x02" + len(frame).to_bytes(2, "big") + frame
        prefix = b""
        if (self.context is None
                or self._restore(self.context, dynamic, frame[66:]) != frame):
            self.context = context
            prefix = b"\x00\x00\x42" + context
        if self.delta:
            mask, values = 0, bytearray()
            for bit, area in enumerate(self.delta_fields):
                current = int.from_bytes(frame[area], "big")
                previous = int.from_bytes(self.context[area], "big")
                difference = (current - previous) % (1 << (8 * (area.stop - area.start)))
                if difference:
                    mask |= 1 << bit
                    while difference >= 128:
                        values.append((difference & 127) | 128)
                        difference >>= 7
                    values.append(difference)
            self.context = context
            return (prefix + b"\x03" + (len(frame) - 66).to_bytes(2, "big")
                    + mask.to_bytes(1, "big") + values + frame[66:])
        return prefix + b"\x01" + (len(frame) - 66).to_bytes(2, "big") + dynamic + frame[66:]

    def decode(self, records):
        frames, offset = [], 0
        while offset < len(records):
            if len(records) - offset < 3:
                raise ValueError("truncated compact record header")
            kind = records[offset]
            size = int.from_bytes(records[offset + 1:offset + 3], "big")
            offset += 3
            if kind == 3:
                if self.context is None or offset >= len(records):
                    raise ValueError("missing context or truncated delta record")
                mask, offset = records[offset], offset + 1
                header = bytearray(self.context)
                for bit, area in enumerate(self.delta_fields):
                    if mask & (1 << bit):
                        difference, shift = 0, 0
                        while True:
                            if offset >= len(records) or shift > 28:
                                raise ValueError("truncated or overflowing header delta")
                            byte, offset = records[offset], offset + 1
                            difference |= (byte & 127) << shift
                            if byte < 128:
                                break
                            shift += 7
                        width = area.stop - area.start
                        value = (int.from_bytes(header[area], "big") + difference) % (1 << (8 * width))
                        header[area] = value.to_bytes(width, "big")
                if len(records) - offset < size:
                    raise ValueError("truncated delta-record payload")
                dynamic = b"".join(header[area] for area in self.dynamic)
                frame = self._restore(header, dynamic, records[offset:offset + size])
                offset += size
                self.context = frame[:66]
                frames.append(frame)
                continue
            body = size + 23 if kind == 1 else size
            if len(records) - offset < body:
                raise ValueError("truncated compact record")
            value = records[offset:offset + body]
            offset += body
            if kind == 0 and size == 66:
                self.context = value
            elif kind == 1 and self.context is not None:
                frames.append(self._restore(self.context, value[:23], value[23:]))
            elif kind == 2:
                frames.append(value)
            else:
                raise ValueError("invalid compact record or missing context")
        return frames


def tcp_profile_frame(*, sequence=0, acknowledged=0, identification=0, timestamp=0,
                      echoed_timestamp=0, payload_bytes=1448, flags=0x18, window=65535):
    """Build a valid established Ethernet/IPv4/TCP frame with timestamp options.

    Payload bytes are opaque and never compressed. Their content has no effect
    on the byte budget or erasure simulation. Addresses and ports identify one
    established model flow. The compression codec itself accepts arbitrary
    payload contents and updates its context when invariant header fields change.
    """
    header = bytearray(66)
    header[:12] = bytes(range(12))
    header[12:15] = b"\x08\x00\x45"
    header[18:20] = (identification & 65535).to_bytes(2, "big")
    header[20:24] = b"\x40\x00\x40\x06"
    header[26:34] = b"\x0a\x00\x00\x01\x0a\x00\x00\x02"
    header[34:38] = b"\x01\xbb\x13\x88"
    header[38:42] = (sequence & 0xFFFFFFFF).to_bytes(4, "big")
    header[42:46] = (acknowledged & 0xFFFFFFFF).to_bytes(4, "big")
    header[46:48] = bytes((0x80, flags))
    header[48:50] = window.to_bytes(2, "big")
    header[54:58] = b"\x01\x01\x08\x0a"
    header[58:62] = (timestamp & 0xFFFFFFFF).to_bytes(4, "big")
    header[62:66] = (echoed_timestamp & 0xFFFFFFFF).to_bytes(4, "big")
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, bytes(payload_bytes))


class CompactSimulation(Simulation):
    """Fixed-window payload ceiling using compact transport in both directions."""

    def __init__(self, scenario, traffic, paths, strategy, seed, compact_config=CompactConfig()):
        self.compact_config = compact_config
        super().__init__(scenario, traffic, paths, strategy, seed)

    def make_transports(self, rng):
        return (CompactTransport(self, False, self.compact_config),
                CompactTransport(self, True, self.compact_config))

    def produce(self):
        self.source_timer = None
        slots = self.traffic.window_bytes // self.traffic.payload_bytes
        while self.now < self.traffic.duration_s and len(self.sent_times) - self.tcp_acked < slots:
            if self.next_source > self.now:
                self.source_timer = self.next_source
                self.at(self.next_source, self.produce)
                return
            index = len(self.sent_times)
            self.sent_times.append(self.now)
            frame = (tcp_profile_frame(sequence=index * self.traffic.payload_bytes,
                                       identification=index, timestamp=int(self.now * 1000),
                                       payload_bytes=self.traffic.payload_bytes)
                     if self.compact_config.header_profile == "tcp_delta" else None)
            self.forward.submit(self.traffic.frame_bytes, self.traffic.payload_bytes,
                                lambda index=index: self.on_data(index), frame=frame)
            self.next_source = self.now + self.traffic.frame_interval_ms / 1000

    def emit_ack(self):
        self.ack_timer = None
        self.last_ack = self.tcp_received
        acknowledged = self.last_ack
        frame = (tcp_profile_frame(acknowledged=acknowledged * self.traffic.payload_bytes,
                                   identification=acknowledged, timestamp=int(self.now * 1000),
                                   payload_bytes=0, flags=0x10)
                 if self.compact_config.header_profile == "tcp_delta" else None)
        self.reverse.submit(66, 0, lambda: self.on_ack(acknowledged), ack=True, frame=frame)
