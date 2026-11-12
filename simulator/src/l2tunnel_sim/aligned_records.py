"""Self-describing channel records aligned to individual coding symbols.

The protected prefix is a one-byte channel and a two-byte channel sequence.
The existing compact codec gives the complete record length. Kind four is a
fragment with two-byte encoded length and offset fields. Zero extension to
the common repair-symbol size is implicit and carries no application data.
Kind six inherits payload length. Kinds with low three bits seven also
predict contiguous IPID/sequence and unchanged ACK, packing the remaining
five delta-presence bits into the kind byte. Optional low-three-bit kind five
uses a fixed timestamp-delta pair dictionary when other dynamic fields match
that prediction. Every exceptional record retains the existing codec path.
Optional short full-frame records use kind two and leave header context intact.
They may be delivered before earlier channel records, while the contiguous
serial watermark and coding-source feedback still retain every unresolved gap.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from struct import Struct

from .compact import CompactHeaderCodec, CompactSource
from .shared_records import SharedRecordConfig, SharedRecordTransport


CHANNEL_HEADER = Struct("!BH")
FRAGMENT_HEADER = Struct("!BHH")
FRAGMENT_KIND = 4
CONTEXT_LENGTH_KIND = 6
PACKED_PREDICTIVE_KIND = 7
TIMESTAMP_PAIR_KIND = 5
# This table is part of the wire format. The pair stores exact unsigned
# 32-bit timestamp differences, with exceptional differences encoded by kind 7.
TIMESTAMP_PAIRS = tuple(
    (timestamp, echoed)
    for timestamp in (18, 19)
    for echoed in (0, 1, 17, 18, 19, 20, 36, 37, 38, 55, 56, 74, 75, 92, 93, 111)
)
TIMESTAMP_PAIR_INDEX = {pair: index for index, pair in enumerate(TIMESTAMP_PAIRS)}


@dataclass(frozen=True)
class AlignedRecordConfig(SharedRecordConfig):
    elide_payload_length: bool = False
    packed_predictive_records: bool = False
    timestamp_pair_dictionary: bool = False
    independent_short_frame_bytes: int = 0

    def __post_init__(self):
        super().__post_init__()
        if not isinstance(self.elide_payload_length, bool):
            raise ValueError("payload length elision must be boolean")
        if not isinstance(self.packed_predictive_records, bool):
            raise ValueError("packed predictive records must be boolean")
        if not isinstance(self.timestamp_pair_dictionary, bool):
            raise ValueError("timestamp pair dictionary must be boolean")
        if self.timestamp_pair_dictionary and not self.packed_predictive_records:
            raise ValueError("timestamp pair dictionary requires packed predictive records")
        threshold = self.independent_short_frame_bytes
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not 0 <= threshold <= 65532:
            raise ValueError("independent short frame threshold must be an integer between 0 and 65532 bytes")


def _unsigned_varint(value):
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def encoded_record_length(data):
    """Parse one existing codec record without interpreting its zero extension."""
    if len(data) < 3:
        raise ValueError("truncated aligned codec record")
    kind, size = data[0], int.from_bytes(data[1:3], "big")
    position = 3
    if kind == 0:
        if size != 66:
            raise ValueError("aligned context must contain 66 header bytes")
    elif kind == 1:
        position += 23
    elif kind == 3:
        if position >= len(data):
            raise ValueError("truncated aligned delta mask")
        mask = data[position]
        position += 1
        for bit in range(8):
            if mask & (1 << bit):
                shift = 0
                while True:
                    if position >= len(data) or shift > 28:
                        raise ValueError("truncated or overflowing aligned delta")
                    byte = data[position]
                    position += 1
                    if byte < 128:
                        break
                    shift += 7
    elif kind != 2:
        raise ValueError("unknown aligned codec record kind")
    end = position + size
    if end > len(data):
        raise ValueError("truncated aligned codec record body")
    return end


class AlignedRecordReceiver:
    def __init__(self, symbol_bytes, independent_short_frame_bytes=0):
        if (isinstance(independent_short_frame_bytes, bool)
                or not isinstance(independent_short_frame_bytes, int)
                or not 0 <= independent_short_frame_bytes <= symbol_bytes - CHANNEL_HEADER.size - 3):
            raise ValueError("independent short frame threshold must fit one protected symbol")
        self.symbol_bytes = symbol_bytes
        self.independent_short_frame_bytes = independent_short_frame_bytes
        self.seen = set()
        self.expected = defaultdict(int)
        self.codecs = defaultdict(lambda: CompactHeaderCodec(delta=True))
        self.complete = defaultdict(dict)
        self.fragments = {}
        self.early_delivered = set()
        self.early_release_count = 0

    def receive(self, index, data):
        if index in self.seen:
            return []
        if len(data) != self.symbol_bytes:
            raise ValueError("invalid aligned symbol length")
        channel, serial = CHANNEL_HEADER.unpack_from(data)
        distance = (serial - self.expected[channel]) & 65535
        if distance >= 32768:
            self.seen.add(index)
            return []
        serial = self.expected[channel] + distance
        body = data[CHANNEL_HEADER.size:]
        record = None
        if body[0] == FRAGMENT_KIND:
            _, total, offset = FRAGMENT_HEADER.unpack_from(body)
            capacity = len(body) - FRAGMENT_HEADER.size
            if not 0 <= offset < total or offset % capacity:
                raise ValueError("invalid aligned fragment offset or length")
            size = min(capacity, total - offset)
            if any(body[FRAGMENT_HEADER.size + size:]):
                raise ValueError("nonzero aligned fragment padding")
            key = (channel, serial)
            expected, pieces = self.fragments.setdefault(key, (total, {}))
            if total != expected:
                raise ValueError("inconsistent aligned fragment length")
            piece = body[FRAGMENT_HEADER.size:FRAGMENT_HEADER.size + size]
            if offset in pieces and pieces[offset] != piece:
                raise ValueError("conflicting aligned fragment")
            pieces[offset] = piece
            if sum(map(len, pieces.values())) == total:
                record = b"".join(pieces[position] for position in range(0, total, capacity))
                if encoded_record_length(record) != total:
                    raise ValueError("fragmented aligned record contains trailing bytes")
                del self.fragments[key]
        elif body[0] == CONTEXT_LENGTH_KIND or body[0] & 7 in (PACKED_PREDICTIVE_KIND, TIMESTAMP_PAIR_KIND):
            # Its preceding in-order channel context determines payload size.
            # Preserve the entire symbol until that context becomes available.
            record = body
        else:
            size = encoded_record_length(body)
            if any(body[size:]):
                raise ValueError("nonzero aligned record padding")
            record = body[:size]
        records = self.complete[channel]
        if record is not None:
            previous = records.get(serial)
            if previous is not None and previous != record:
                raise ValueError("conflicting aligned record")
            records[serial] = record
        self.seen.add(index)
        delivered = []
        key = (channel, serial)
        if (record is not None and record[0] == 2 and self.independent_short_frame_bytes
                and len(record) - 3 <= self.independent_short_frame_bytes
                and key not in self.early_delivered):
            # Kind two is self-contained and never updates the channel codec.
            # Keep the record and tombstone until contiguous retirement.
            delivered.append((channel, serial, record[3:]))
            self.early_delivered.add(key)
            self.early_release_count += serial > self.expected[channel]
        while self.expected[channel] in records:
            serial = self.expected[channel]
            record = records.pop(serial)
            predictive = record[0] & 7 in (PACKED_PREDICTIVE_KIND, TIMESTAMP_PAIR_KIND)
            if record[0] == CONTEXT_LENGTH_KIND or predictive:
                context = self.codecs[channel].context
                if context is None:
                    raise ValueError("missing aligned payload-length context")
                payload_bytes = int.from_bytes(context[16:18], "big") - 52
                header_bytes = 1 if predictive else 2
                if not 0 <= payload_bytes <= self.symbol_bytes - CHANNEL_HEADER.size - header_bytes:
                    raise ValueError("invalid aligned payload-length context")
                deltas = record[1:]
                if predictive:
                    # High bits retain the existing flags/window/urgent/TS mask.
                    # IPID advances by one, sequence by the prior payload size,
                    # and ACK is unchanged. CompactHeaderCodec applies wrapping.
                    mask = (record[0] & 0xF8) | 1 | (2 if payload_bytes else 0)
                    if record[0] & 7 == TIMESTAMP_PAIR_KIND:
                        timestamp, echoed = TIMESTAMP_PAIRS[record[0] >> 3]
                        mask = 1 | (2 if payload_bytes else 0) | 64 | (128 if echoed else 0)
                        deltas = (_unsigned_varint(timestamp)
                                  + (_unsigned_varint(echoed) if echoed else b"") + deltas)
                    predicted = b"\x01" + (_unsigned_varint(payload_bytes) if payload_bytes else b"")
                    deltas = bytes([mask]) + predicted + deltas
                expanded = b"\x03" + payload_bytes.to_bytes(2, "big") + deltas
                size = encoded_record_length(expanded)
                if any(expanded[size:]):
                    raise ValueError("nonzero aligned context-length padding")
                record = expanded[:size]
            frames = self.codecs[channel].decode(record)
            if len(frames) > 1 or (not frames and record[0] != 0):
                raise ValueError("invalid aligned record decode count")
            key = (channel, serial)
            if key in self.early_delivered:
                self.early_delivered.remove(key)
            else:
                delivered.append((channel, serial, frames[0] if frames else None))
            self.expected[channel] += 1
        return delivered

    def discard_before(self, prefix):
        # Fragment bodies are owned by their channel record until complete.
        # The compact decoder suppresses duplicate known source IDs itself.
        self.seen.difference_update(index for index in tuple(self.seen) if index < prefix)


class AlignedRecordTransport(SharedRecordTransport):
    """Retain shared causal coding and align every common frame to one source."""

    def __init__(self, sim, reverse, config):
        super().__init__(sim, reverse, config)
        self.record_capacity = self.symbol_bytes - CHANNEL_HEADER.size
        if self.record_capacity <= FRAGMENT_HEADER.size:
            raise ValueError("MTU cannot hold an aligned fragment")
        self.receiver = AlignedRecordReceiver(
            self.symbol_bytes, getattr(config, "independent_short_frame_bytes", 0))
        self.source_queue = deque()
        self.aligned_records = 0
        self.fragmented_records = 0
        self.fragment_sources = 0
        self.context_records = 0
        self.channel_header_bytes = 0
        self.implicit_padding_bytes = 0
        self.elided_length_records = 0
        self.packed_predictive_records = 0
        self.timestamp_pair_candidates = 0
        self.timestamp_pair_records = 0
        self.timestamp_pair_saved_bytes = 0
        self.independent_short_records = 0

    def submit_channel(self, channel, frame_bytes, payload_bytes, deliver, *, ack=False, frame=None, deliver_frame=False):
        if isinstance(channel, bool) or not isinstance(channel, int) or not 0 <= channel < 256:
            raise ValueError("aligned-record channels must fit one byte")
        if frame is None or len(frame) != frame_bytes or not 0 <= payload_bytes <= frame_bytes:
            raise ValueError("complete serialized frame and valid byte counts are required")
        codec = self.channel_codecs[channel]
        previous_context = codec.context
        # Threshold counts complete Ethernet bytes. The protected symbol adds
        # three channel/serial bytes and three kind/length bytes before copies.
        independent_short = bool(self.receiver.independent_short_frame_bytes
                                 and len(frame) <= self.receiver.independent_short_frame_bytes)
        encoded = (b"\x02" + len(frame).to_bytes(2, "big") + bytes(frame)
                   if independent_short else codec.encode(frame))
        context = encoded[:69] if encoded[0] == 0 else None
        body = encoded[69:] if context else encoded
        serial = self.channel_sequences[channel]
        records = 2 if context else 1
        if len(body) > 65535 or serial + records - self.channel_completed[channel] > 32767:
            codec.context = previous_context
            raise ValueError("aligned record exceeds length or serial-number window")
        if context:
            self._submit_record(channel, serial, context)
            self.profile_context_bytes += len(context)
            self.context_records += 1
            serial += 1
        length_context = context[3:] if context else previous_context
        if (getattr(self.config, "packed_predictive_records", False) and context is None
                and previous_context is not None and body[0] == 3
                and len(frame) - 66 == int.from_bytes(previous_context[16:18], "big") - 52
                and int.from_bytes(frame[18:20], "big")
                    == ((int.from_bytes(previous_context[18:20], "big") + 1) & 65535)
                and int.from_bytes(frame[38:42], "big")
                    == ((int.from_bytes(previous_context[38:42], "big") + len(frame) - 66) & 0xFFFFFFFF)
                and frame[42:46] == previous_context[42:46]):
            payload_size = len(frame) - 66
            predicted_size = 1 + (len(_unsigned_varint(payload_size)) if payload_size else 0)
            packed = bytes([(body[3] & 0xF8) | PACKED_PREDICTIVE_KIND]) + body[4 + predicted_size:]
            pair_saved_bytes = 0
            if (self.config.timestamp_pair_dictionary and len(packed) <= self.record_capacity
                    and not body[3] & 0x38):
                self.timestamp_pair_candidates += 1
                timestamp = (int.from_bytes(frame[58:62], "big")
                             - int.from_bytes(previous_context[58:62], "big")) & 0xFFFFFFFF
                echoed = (int.from_bytes(frame[62:66], "big")
                          - int.from_bytes(previous_context[62:66], "big")) & 0xFFFFFFFF
                pair_index = TIMESTAMP_PAIR_INDEX.get((timestamp, echoed))
                if pair_index is not None:
                    paired = bytes([TIMESTAMP_PAIR_KIND | pair_index << 3]) + frame[66:]
                    pair_saved_bytes = len(packed) - len(paired)
                    packed = paired
            if len(packed) <= self.record_capacity:
                body = packed
                self.packed_predictive_records += 1
                if pair_saved_bytes:
                    self.timestamp_pair_records += 1
                    self.timestamp_pair_saved_bytes += pair_saved_bytes
        if (getattr(self.config, "elide_payload_length", False) and body[0] == 3
                and length_context is not None and len(body) - 2 <= self.record_capacity
                and int.from_bytes(body[1:3], "big") == int.from_bytes(length_context[16:18], "big") - 52):
            body = bytes([CONTEXT_LENGTH_KIND]) + body[3:]
            self.elided_length_records += 1
        self.callbacks[channel, serial] = (frame, self.sim.now, deliver, deliver_frame)
        self._submit_record(channel, serial, body)
        self.source_record_bytes += len(body)
        self.frame_count += 1
        self.independent_short_records += independent_short
        self.channel_sequences[channel] = serial + 1
        self.peak_pending_bytes = max(self.peak_pending_bytes, self.pending_bytes)

    def _submit_record(self, channel, serial, body):
        header = CHANNEL_HEADER.pack(channel, serial & 65535)
        if len(body) <= self.record_capacity:
            self._queue_source(header + body)
            self.aligned_records += int(body[0] != 0)
            return
        self.fragmented_records += 1
        capacity = self.record_capacity - FRAGMENT_HEADER.size
        for offset in range(0, len(body), capacity):
            self._queue_source(header + FRAGMENT_HEADER.pack(FRAGMENT_KIND, len(body), offset)
                               + body[offset:offset + capacity])
            self.fragment_sources += 1

    def _queue_source(self, payload):
        self.source_queue.append(payload)
        self.buffer_bytes += len(payload)
        self.submitted_bytes += len(payload)
        self._flush_full()

    def _flush_full(self):
        while self.source_queue and len(self.sources) - self.base < self.config.block_sources:
            self._aligned_source(self.source_queue.popleft())

    def _schedule_flush(self):
        # Complete records are ready immediately. Only received feedback can
        # unblock a full sender window, and its existing callback flushes it.
        pass

    def flush(self, generation=None):
        if generation is None or generation == self.flush_generation:
            self._flush_full()

    def _aligned_source(self, payload):
        size = len(payload)
        self.channel_header_bytes += CHANNEL_HEADER.size
        self.implicit_padding_bytes += self.symbol_bytes - size
        self.buffer_bytes -= size
        self.sent_bytes += size
        source = CompactSource(len(self.sources), size, self.sent_bytes)
        self.sources.append(source)
        self.source_payloads.append(payload + bytes(self.symbol_bytes - size))
        finish, _ = self.sim.send(self.reverse, self.source_header + size, "source",
                                  lambda: self._receive_source(source))
        self.last_source_at = finish
        self.credit += self.credit_numerator
        while self.credit >= self.credit_denominator:
            self.credit -= self.credit_denominator
            self._repair(False)
        self.tail_generation += 1
        self._schedule_tail(finish, self.tail_generation)

    def _deliver_symbol(self, index):
        for channel, serial, frame in self.receiver.receive(index, self.source_payloads[index]):
            self.channel_completed[channel] = self.receiver.expected[channel]
            if frame is None:
                continue
            expected, created_at, callback, deliver_frame = self.callbacks.pop((channel, serial))
            if frame != expected:
                raise ValueError("reconstructed aligned frame differs from submitted bytes")
            self.delivered_bytes += len(frame)
            self.delays.append((self.sim.now - created_at) * 1000)
            if self.sim.now <= self.sim.traffic.duration_s:
                self.delivered_during_measurement_bytes += len(frame)
            if deliver_frame:
                callback(frame)
            else:
                callback()
