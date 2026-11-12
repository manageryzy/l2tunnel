"""Lossy cross-flow batches of complete TCP ACK frames.

The executable parser reconstructs each 66-byte frame. As in the existing
forward record model, verified bytes release the original TCP callback. That
callback retains the model's sub-millisecond timestamps and unwrapped sequence
numbers, while the serialized TCP fields use their normal finite widths.

Version one kind one carries 75-byte full records. Optional kind two carries
channel/event/encoded-length records with a fresh delta-codec context for
each datagram. Context refreshes are transmitted in full inside that batch.
Kind three uses a full first frame followed by byte patches against the
preceding frame in the same batch. Optional compression chooses the smallest
complete envelope. Kind four adds canonical variable-length event-ID deltas
and lengths to those byte patches, resetting both references per datagram.
"""

from collections import Counter
from math import isfinite
from struct import Struct

from .aligned_records import _unsigned_varint, encoded_record_length
from .compact import CompactHeaderCodec, _checksum, tcp_profile_frame
from .compact_ack import CoalescedACKTCP


IP_UDP_BYTES = 28
BATCH_HEADER = Struct("!BBH")
RECORD_HEADER = Struct("!BQ")
DELTA_RECORD_HEADER = Struct("!BQH")
ACK_FRAME_BYTES = 66
RECORD_BYTES = RECORD_HEADER.size + ACK_FRAME_BYTES
FULL_KIND = 1
BATCH_DELTA_KIND = 2
BYTE_DELTA_KIND = 3
BYTE_VARINT_KIND = 4
BYTE_MASK_BYTES = 9
MAX_EVENT_ID = (1 << 64) - 1
MAX_EVENT_DELTA_ZIGZAG = 2 * MAX_EVENT_ID


def _decode_bounded_varint(data, offset, maximum):
    """Read a canonical unsigned value with at most ten wire bytes."""
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated aggregate ACK varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if value > maximum:
            raise ValueError("overflowing aggregate ACK varint")
        if byte < 128:
            if shift and byte == 0:
                raise ValueError("noncanonical aggregate ACK varint")
            return value, offset
    raise ValueError("overflowing aggregate ACK varint")


def _encode_byte_delta(previous, frame):
    if previous is None:
        return bytes(frame)
    mask, changed = 0, bytearray()
    for index, (before, after) in enumerate(zip(previous, frame)):
        if before != after:
            mask |= 1 << index
            changed.append(after)
    return mask.to_bytes(BYTE_MASK_BYTES, "big") + changed


def _decode_byte_delta(previous, encoded):
    if previous is None:
        return bytes(encoded)
    if len(encoded) < BYTE_MASK_BYTES:
        raise ValueError("truncated aggregate ACK byte mask")
    mask = int.from_bytes(encoded[:BYTE_MASK_BYTES], "big")
    if mask >> ACK_FRAME_BYTES or len(encoded) != BYTE_MASK_BYTES + mask.bit_count():
        raise ValueError("invalid aggregate ACK byte mask or length")
    frame, offset = bytearray(previous), BYTE_MASK_BYTES
    for index in range(ACK_FRAME_BYTES):
        if mask & (1 << index):
            frame[index] = encoded[offset]
            offset += 1
    return bytes(frame)


def _decode_codec_record(codec, encoded):
    context_bytes = 69 if encoded[0] == 0 else 0
    if context_bytes:
        if len(encoded) < 69 or encoded[1:3] != b"\x00\x42":
            raise ValueError("invalid aggregate ACK delta context")
        validate_ack_frame(encoded[3:69])
    record = encoded[context_bytes:]
    if (not record or record[0] not in (2, 3)
            or encoded_record_length(record) != len(record)):
        raise ValueError("invalid aggregate ACK delta record boundary")
    frames = codec.decode(encoded)
    if len(frames) != 1:
        raise ValueError("aggregate ACK delta record must decode one frame")
    return frames[0]


def validate_ack_frame(frame):
    """Validate the complete Ethernet/IPv4/TCP timestamp ACK profile."""
    if (len(frame) != ACK_FRAME_BYTES or frame[12:15] != b"\x08\x00\x45"
            or frame[16:18] != b"\x00\x34" or frame[23] != 6
            or frame[46:48] != b"\x80\x10" or frame[54:58] != b"\x01\x01\x08\x0a"):
        raise ValueError("unsupported aggregate ACK frame")
    pseudo = frame[26:34] + b"\x00\x06\x00\x20"
    if _checksum(frame[14:34]) != b"\x00\x00" or _checksum(pseudo + frame[34:]) != b"\x00\x00":
        raise ValueError("invalid aggregate ACK checksum")


def encode_batch(records, record_encoding="full"):
    """Encode one independent batch, using delta records only when smaller."""
    if record_encoding not in ("full", "batch_delta", "batch_varint"):
        raise ValueError("unknown aggregate ACK record encoding")
    if not 1 <= len(records) <= 65535:
        raise ValueError("aggregate ACK record count is out of range")
    body = bytearray(BATCH_HEADER.pack(1, FULL_KIND, len(records)))
    compressed = bytearray(BATCH_HEADER.pack(1, BATCH_DELTA_KIND, len(records)))
    patched = bytearray(BATCH_HEADER.pack(1, BYTE_DELTA_KIND, len(records)))
    varint = bytearray(BATCH_HEADER.pack(1, BYTE_VARINT_KIND, len(records)))
    codec = CompactHeaderCodec(delta=True) if record_encoding != "full" else None
    previous = None
    previous_event = 0
    for channel, record_id, frame in records:
        validate_ack_frame(frame)
        body.extend(RECORD_HEADER.pack(channel, record_id))
        body.extend(frame)
        if codec is not None:
            encoded = codec.encode(frame)
            compressed.extend(DELTA_RECORD_HEADER.pack(channel, record_id, len(encoded)))
            compressed.extend(encoded)
            delta = _encode_byte_delta(previous, frame)
            patched.extend(DELTA_RECORD_HEADER.pack(channel, record_id, len(delta)))
            patched.extend(delta)
            if record_encoding == "batch_varint":
                current_event = int(record_id)
                difference = current_event - previous_event
                zigzag = 2 * difference if difference >= 0 else -2 * difference - 1
                varint.append(channel)
                varint.extend(_unsigned_varint(zigzag))
                varint.extend(_unsigned_varint(len(delta)))
                varint.extend(delta)
                previous_event = current_event
            previous = frame
    candidates = (body, compressed, patched) if codec is not None else (body,)
    if record_encoding == "batch_varint":
        candidates += (varint,)
    return bytes(min(candidates, key=len))


def decode_batch(body):
    if len(body) < BATCH_HEADER.size:
        raise ValueError("truncated aggregate ACK header")
    version, kind, count = BATCH_HEADER.unpack_from(body)
    if version != 1 or kind not in (FULL_KIND, BATCH_DELTA_KIND, BYTE_DELTA_KIND, BYTE_VARINT_KIND) or count == 0:
        raise ValueError("invalid aggregate ACK envelope")
    if kind in (BATCH_DELTA_KIND, BYTE_DELTA_KIND, BYTE_VARINT_KIND):
        # Context belongs to this datagram. No earlier batch is required.
        codec = CompactHeaderCodec(delta=True)
        previous = None
        previous_event = 0
        records, offset = [], BATCH_HEADER.size
        for _ in range(count):
            if kind == BYTE_VARINT_KIND:
                if offset >= len(body):
                    raise ValueError("truncated aggregate ACK varint record header")
                channel = body[offset]
                zigzag, offset = _decode_bounded_varint(body, offset + 1, MAX_EVENT_DELTA_ZIGZAG)
                difference = zigzag // 2 if zigzag % 2 == 0 else -(zigzag // 2) - 1
                record_id = previous_event + difference
                if not 0 <= record_id <= MAX_EVENT_ID:
                    raise ValueError("aggregate ACK event ID is out of range")
                size, offset = _decode_bounded_varint(body, offset, BYTE_MASK_BYTES + ACK_FRAME_BYTES)
            else:
                if len(body) - offset < DELTA_RECORD_HEADER.size:
                    raise ValueError("truncated aggregate ACK delta record header")
                channel, record_id, size = DELTA_RECORD_HEADER.unpack_from(body, offset)
                offset += DELTA_RECORD_HEADER.size
            if not size or offset + size > len(body):
                raise ValueError("invalid aggregate ACK delta record length")
            encoded = body[offset:offset + size]
            offset += size
            frame = (_decode_codec_record(codec, encoded) if kind == BATCH_DELTA_KIND
                     else _decode_byte_delta(previous, encoded))
            validate_ack_frame(frame)
            records.append((channel, record_id, frame))
            previous = frame
            previous_event = record_id
        if offset != len(body):
            raise ValueError("trailing aggregate ACK delta bytes")
        return records
    if len(body) != BATCH_HEADER.size + count * RECORD_BYTES:
        raise ValueError("invalid aggregate ACK envelope")
    records = []
    for offset in range(BATCH_HEADER.size, len(body), RECORD_BYTES):
        channel, record_id = RECORD_HEADER.unpack_from(body, offset)
        frame = body[offset + RECORD_HEADER.size:offset + RECORD_BYTES]
        validate_ack_frame(frame)
        records.append((channel, record_id, frame))
    return records


class AggregateACKTCP(CoalescedACKTCP):
    """Retain existing ACK production and coalescing, replacing transmission."""

    def __init__(self, *args, distinct_flow_headers=False, **kwargs):
        if not isinstance(distinct_flow_headers, bool):
            raise ValueError("distinct_flow_headers must be boolean")
        self.distinct_flow_headers = distinct_flow_headers
        super().__init__(*args, **kwargs)

    def transmit_ack(self, packet):
        frame = tcp_profile_frame(
            acknowledged=packet.acknowledged * self.traffic.payload_bytes,
            identification=self.ack_packet_id, timestamp=int(packet.created_at * 1000),
            echoed_timestamp=int((packet.echoed_timestamp or 0) * 1000),
            payload_bytes=0, flags=0x10,
        )
        if self.distinct_flow_headers:
            header = bytearray(frame)
            header[36:38] = (49152 + self.ack_channel).to_bytes(2, "big")
            header[50:52] = b"\x00\x00"
            header[50:52] = _checksum(header[26:34] + b"\x00\x06\x00\x20" + header[34:])
            frame = bytes(header)
        self.ack_aggregate.submit(self.ack_channel, self.ack_packet_id, frame, packet)
        self.ack_packet_id += 1
        self.ack_transmitted += 1


class ACKAggregator:
    """Attach one bounded-latency reverse batch queue to shared-link flows."""

    def __init__(self, flows, *, hold_ms=.5, record_encoding="full"):
        if isinstance(hold_ms, bool) or not isfinite(hold_ms) or hold_ms < 0:
            raise ValueError("aggregate hold must be finite and nonnegative")
        if record_encoding not in ("full", "batch_delta", "batch_varint"):
            raise ValueError("unknown aggregate ACK record encoding")
        if not 1 <= len(flows) <= 256 or any(not isinstance(flow, AggregateACKTCP) for flow in flows):
            raise ValueError("aggregate ACKs require one to 256 compatible flows")
        self.flows = flows
        self.sim = flows[0]
        settings = {(flow.ack_copies, flow.ack_copy_spacing_ms, flow.compact_config.authentication_bytes,
                     flow.scenario.mtu) for flow in flows}
        if len(settings) != 1 or any(flow.links is not self.sim.links for flow in flows):
            raise ValueError("aggregate ACK flows must share link and packet settings")
        self.copies, self.spacing_ms, self.authentication_bytes, mtu = settings.pop()
        self.capacity = (mtu - IP_UDP_BYTES - self.authentication_bytes - BATCH_HEADER.size) // RECORD_BYTES
        if self.capacity < 1:
            raise ValueError("MTU cannot hold a complete aggregate ACK")
        self.hold_ms = hold_ms
        self.record_encoding = record_encoding
        self.queue = []
        self.records = {}
        self.generation = 0
        self.pending_copy_events = 0
        self.batch_sizes = Counter()
        self.hold_delays_ms = []
        self.queue_delays_ms = []
        self.batches = 0
        self.submitted_records = 0
        self.verified_records = 0
        self.released_records = 0
        self.requested_wire_bytes = 0
        self.encoding_datagrams = Counter()
        self.full_equivalent_wire_bytes = 0
        self.saved_wire_bytes = 0
        for channel, flow in enumerate(flows):
            flow.ack_aggregate = self
            flow.ack_channel = channel

    def submit(self, channel, record_id, frame, packet):
        key = (channel, record_id)
        if key in self.records or record_id in self.flows[channel].received_ack_ids:
            raise ValueError("aggregate ACK event identifier was reused")
        validate_ack_frame(frame)
        self.records[key] = (frame, packet)
        self.queue.append((channel, record_id, frame, self.sim.now))
        self.submitted_records += 1
        if len(self.queue) >= self.capacity or self.hold_ms == 0:
            self.flush(self.generation)
        elif len(self.queue) == 1:
            self.sim.at(self.sim.now + self.hold_ms / 1000, self.flush, self.generation)

    def flush(self, generation):
        if generation != self.generation or not self.queue:
            return
        queue, self.queue = self.queue, []
        self.generation += 1
        body = encode_batch([(channel, record_id, frame) for channel, record_id, frame, _ in queue],
                            self.record_encoding)
        self.batch_sizes[len(queue)] += 1
        self.batches += 1
        self.hold_delays_ms.extend((self.sim.now - submitted) * 1000 for _, _, _, submitted in queue)
        self.send_copy(body)
        for copy in range(1, self.copies):
            self.pending_copy_events += 1
            self.sim.at(self.sim.now + copy * self.spacing_ms / 1000, self.send_scheduled_copy, body)

    def send_scheduled_copy(self, body):
        self.pending_copy_events -= 1
        self.send_copy(body)

    def send_copy(self, body):
        size = IP_UDP_BYTES + self.authentication_bytes + len(body)
        link = min(self.sim.links[True], key=lambda link: link.finish(self.sim.now, size) + link.rtt / 2)
        self.queue_delays_ms.append(max(0, link.free_at - self.sim.now) * 1000)
        self.requested_wire_bytes += size
        _, kind, count = BATCH_HEADER.unpack_from(body)
        encoding = {FULL_KIND: "full", BATCH_DELTA_KIND: "batch_delta", BYTE_DELTA_KIND: "byte_delta",
                    BYTE_VARINT_KIND: "byte_varint"}[kind]
        self.encoding_datagrams[encoding] += 1
        full_size = IP_UDP_BYTES + self.authentication_bytes + BATCH_HEADER.size + count * RECORD_BYTES
        self.full_equivalent_wire_bytes += full_size
        self.saved_wire_bytes += full_size - size
        self.sim.send(True, size, "ack_batch", lambda: self.receive(body))

    def receive(self, body):
        for channel, record_id, frame in decode_batch(body):
            if channel >= len(self.flows):
                raise ValueError("aggregate ACK references an unknown channel")
            flow = self.flows[channel]
            self.verified_records += 1
            if record_id in flow.received_ack_ids:
                flow.ack_copy_duplicates += 1
                continue
            expected, packet = self.records.pop((channel, record_id))
            if frame != expected:
                raise ValueError("aggregate ACK reconstruction changed frame bytes")
            flow.received_ack_ids.add(record_id)
            self.released_records += 1
            flow.peer_timestamp = max(flow.peer_timestamp, packet.created_at)
            flow.reverse.delivered_bytes += len(frame)
            flow.reverse.delays.append((flow.now - packet.created_at) * 1000)
            flow.on_ack(packet.acknowledged, packet.echoed_timestamp)

    @property
    def flushed(self):
        return (not self.queue and self.pending_copy_events == 0
                and self.requested_wire_bytes == self.sim.wire[True]["ack_batch"])
