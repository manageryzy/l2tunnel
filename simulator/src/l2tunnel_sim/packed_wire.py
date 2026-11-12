"""Optional bounded aggregation of aligned units before source coding.

Channel 255 identifies a packed source and is unavailable for frame admission.
The protected payload contains that marker, a one-byte unit count, and a
two-byte length followed by each original aligned unit. A single unit retains
the original format. Every packed source is one coding symbol and one erasure
event per physical copy. Units with different copy policies use separate
sources. Channel credit advances only after received source-prefix feedback.
"""

from collections import Counter, defaultdict, deque
from copy import copy

from .aligned_records import (
    CHANNEL_HEADER, CONTEXT_LENGTH_KIND, FRAGMENT_HEADER, FRAGMENT_KIND,
    PACKED_PREDICTIVE_KIND, TIMESTAMP_PAIR_KIND, AlignedRecordReceiver,
    encoded_record_length,
)
from .compact_wire import CompactWireTransport


PACKED_CHANNEL = 255
SLOTS_PER_SOURCE = 256


def _validate_unit(unit, symbol_bytes):
    if not 4 <= len(unit) <= symbol_bytes or unit[0] == PACKED_CHANNEL:
        raise ValueError("invalid packed aligned unit length or channel")
    body = unit[CHANNEL_HEADER.size:]
    if body[0] == FRAGMENT_KIND:
        if len(body) <= FRAGMENT_HEADER.size:
            raise ValueError("truncated packed aligned fragment")
        _, total, offset = FRAGMENT_HEADER.unpack_from(body)
        capacity = symbol_bytes - CHANNEL_HEADER.size - FRAGMENT_HEADER.size
        if not 0 <= offset < total or offset % capacity:
            raise ValueError("invalid packed aligned fragment offset")
        if len(body) != FRAGMENT_HEADER.size + min(capacity, total - offset):
            raise ValueError("truncated or oversized packed aligned fragment")
    elif body[0] == CONTEXT_LENGTH_KIND:
        # Validate the explicit delta header now. Payload length depends on
        # the preceding in-order codec context and is checked by the receiver.
        encoded_record_length(b"\x03\x00\x00" + body[1:])
    elif body[0] & 7 == PACKED_PREDICTIVE_KIND:
        encoded_record_length(b"\x03\x00\x00" + bytes([body[0] & 0xF8]) + body[1:])
    elif body[0] & 7 != TIMESTAMP_PAIR_KIND:
        if encoded_record_length(body) != len(body):
            raise ValueError("packed aligned unit contains trailing bytes")


def packed_units(payload, symbol_bytes=1460):
    """Validate the complete container framing before returning its units."""
    payload = bytes(payload)
    if not 2 <= len(payload) <= symbol_bytes or payload[0] != PACKED_CHANNEL:
        raise ValueError("invalid packed source marker or length")
    count = payload[1]
    if count < 2:
        raise ValueError("packed source requires at least two units")
    units = []
    position = 2
    for _ in range(count):
        if position + 2 > len(payload):
            raise ValueError("truncated packed unit length")
        size = int.from_bytes(payload[position:position + 2], "big")
        position += 2
        if position + size > len(payload):
            raise ValueError("truncated packed unit body")
        unit = payload[position:position + size]
        _validate_unit(unit, symbol_bytes)
        units.append(unit)
        position += size
    if any(payload[position:]):
        raise ValueError("nonzero packed source padding")
    return units


class PackedAlignedReceiver(AlignedRecordReceiver):
    """Decode each validated unit with the existing per-channel receiver."""

    def receive(self, index, data):
        if len(data) != self.symbol_bytes:
            raise ValueError("invalid packed symbol length")
        if data[0] != PACKED_CHANNEL:
            return super().receive(index * SLOTS_PER_SOURCE, data)
        units = packed_units(data, self.symbol_bytes)
        channels = {unit[0] for unit in units}
        expected = {channel: self.expected[channel] for channel in channels if channel in self.expected}
        codecs = {channel: copy(self.codecs[channel]) for channel in channels if channel in self.codecs}
        complete = {channel: self.complete[channel].copy() for channel in channels if channel in self.complete}
        fragments = {key: (total, pieces.copy()) for key, (total, pieces) in self.fragments.items()
                     if key[0] in channels}
        early = {key for key in self.early_delivered if key[0] in channels}
        early_count = self.early_release_count
        added_indices = {index * SLOTS_PER_SOURCE + slot for slot in range(len(units))} - self.seen
        delivered = []
        try:
            for slot, unit in enumerate(units):
                padded = unit + bytes(self.symbol_bytes - len(unit))
                delivered.extend(super().receive(index * SLOTS_PER_SOURCE + slot, padded))
        except Exception:
            # Some payload lengths depend on earlier decoded context. Roll
            # back affected channel state if that second-stage check fails.
            # Application callbacks run only after this method returns.
            for mapping, snapshot in ((self.expected, expected), (self.codecs, codecs),
                                      (self.complete, complete)):
                for channel in channels:
                    mapping.pop(channel, None)
                mapping.update(snapshot)
            for key in tuple(self.fragments):
                if key[0] in channels:
                    del self.fragments[key]
            self.fragments.update(fragments)
            self.early_delivered.difference_update(key for key in tuple(self.early_delivered)
                                                  if key[0] in channels)
            self.early_delivered.update(early)
            self.early_release_count = early_count
            self.seen.difference_update(added_indices)
            raise
        return delivered

    def discard_before(self, prefix):
        super().discard_before(prefix * SLOTS_PER_SOURCE)


class PackedWireTransport(CompactWireTransport):
    """Pack adjacent same-policy units within one bounded source buffer."""

    def __init__(self, sim, reverse, config):
        if config.pack_sources_max_delay_ms <= 0:
            raise ValueError("packed wire transport requires a positive packing delay")
        super().__init__(sim, reverse, config)
        self.receiver = PackedAlignedReceiver(self.symbol_bytes, config.independent_short_frame_bytes)
        self._pack = []
        self._pack_unit_bytes = 0
        self._pack_copies = None
        self._pack_deadline = None
        self._pack_generation = 0
        self._queued_record_ends = deque()
        self._source_record_ends = {}
        self.channel_acknowledged = defaultdict(int)
        self.packed_sources = 0
        self.packed_single_sources = 0
        self.packed_units = 0
        self.packed_header_bytes = 0
        self.packed_max_units = 0
        self.packed_wait_count = 0
        self.packed_wait_sum_ms = 0.0
        self.packed_wait_max_ms = 0.0
        self.packed_peak_pending_channel_records = 0
        self.packed_flush_reasons = Counter()

    @property
    def pending_pack_bytes(self):
        count = len(self._pack)
        return self._pack_unit_bytes + (2 + 2 * count if count > 1 else 0)

    def can_submit_channel(self, channel):
        return self.channel_sequences[channel] - self.channel_acknowledged[channel] <= 32765

    def submit_channel(self, channel, *args, **kwargs):
        if (isinstance(channel, bool) or not isinstance(channel, int)
                or not 0 <= channel < PACKED_CHANNEL):
            raise ValueError("packed wire channels must be integers below reserved channel 255")
        if not self.can_submit_channel(channel):
            raise ValueError("packed channel awaits source-prefix feedback credit")
        super().submit_channel(channel, *args, **kwargs)
        pending = self.channel_sequences[channel] - self.channel_acknowledged[channel]
        self.packed_peak_pending_channel_records = max(self.packed_peak_pending_channel_records, pending)

    def _record_end(self, unit):
        channel, serial = CHANNEL_HEADER.unpack_from(unit)
        reference = self.channel_sequences[channel]
        distance = (serial - reference) & 65535
        if distance > 1:
            raise ValueError("queued aligned unit does not match its sender channel sequence")
        body = unit[CHANNEL_HEADER.size:]
        if body[0] == FRAGMENT_KIND:
            _, total, offset = FRAGMENT_HEADER.unpack_from(body)
            if offset + len(body) - FRAGMENT_HEADER.size != total:
                return None
        return channel, reference + distance + 1

    def _queue_source(self, payload):
        payload = bytes(payload)
        _validate_unit(payload, self.symbol_bytes)
        copies = super()._source_copy_count(payload)
        projected = 2 + 2 * (len(self._pack) + 1) + self._pack_unit_bytes + len(payload)
        if self._pack and (copies != self._pack_copies or projected > self.symbol_bytes):
            self._seal_pack("copy_policy" if copies != self._pack_copies else "capacity")
        old_size = self.pending_pack_bytes
        self._pack.append((payload, self.sim.now, self._record_end(payload)))
        self._pack_unit_bytes += len(payload)
        self._pack_copies = copies
        added = self.pending_pack_bytes - old_size
        self.buffer_bytes += added
        self.submitted_bytes += added
        # A unit that cannot share a source with another equal-sized unit
        # follows the existing immediate-send path, independent of its role.
        if len(payload) > (self.symbol_bytes - 6) // 2:
            self._seal_pack("large_unit")
        else:
            self._schedule_flush()

    def _schedule_flush(self):
        if not self._pack or self._pack_deadline is not None:
            return
        self._pack_generation += 1
        self._pack_deadline = self.sim.now + self.config.pack_sources_max_delay_ms / 1000
        if self._pack_deadline <= self.sim.now:
            raise ValueError("source packing delay must advance the simulation clock")
        self.sim.at(self._pack_deadline, self.flush, self._pack_generation)

    def flush(self, generation=None):
        if generation is not None and generation != self._pack_generation:
            return
        if self._pack:
            self._seal_pack("timer" if generation is not None else "explicit")
        self._flush_full()

    def _seal_pack(self, reason):
        if len(self._pack) == 1:
            payload = self._pack[0][0]
            self.packed_single_sources += 1
        else:
            payload = bytes([PACKED_CHANNEL, len(self._pack)]) + b"".join(
                len(unit).to_bytes(2, "big") + unit for unit, _, _ in self._pack)
            self.packed_sources += 1
            self.packed_units += len(self._pack)
            self.packed_header_bytes += 2 + 2 * len(self._pack)
        if len(payload) != self.pending_pack_bytes or len(payload) > self.symbol_bytes:
            raise ValueError("packed source accounting mismatch")
        ends = {}
        for _, queued_at, end in self._pack:
            wait = (self.sim.now - queued_at) * 1000
            self.packed_wait_count += 1
            self.packed_wait_sum_ms += wait
            self.packed_wait_max_ms = max(self.packed_wait_max_ms, wait)
            if end is not None:
                channel, record_end = end
                ends[channel] = max(ends.get(channel, 0), record_end)
        self.packed_max_units = max(self.packed_max_units, len(self._pack))
        self.packed_flush_reasons[reason] += 1
        self._pack.clear()
        self._pack_unit_bytes = 0
        self._pack_copies = None
        self._pack_deadline = None
        self._pack_generation += 1
        self.source_queue.append(payload)
        self._queued_record_ends.append(ends)
        self._flush_full()
        if self.capacity_callback is not None:
            self.sim.at(self.sim.now, self.capacity_callback)

    def _flush_full(self):
        while self.source_queue and len(self.sources) - self.base < self.config.block_sources:
            payload = self.source_queue.popleft()
            ends = self._queued_record_ends.popleft()
            self._source_record_ends[len(self.sources)] = ends
            self._aligned_source(payload)
            if payload[0] == PACKED_CHANNEL:
                self.channel_header_bytes += CHANNEL_HEADER.size * (payload[1] - 1)

    def _source_copy_count(self, payload):
        if payload[0] != PACKED_CHANNEL:
            return super()._source_copy_count(payload)
        counts = set()
        for unit in packed_units(payload, self.symbol_bytes):
            counts.add(super()._source_copy_count(unit))
        if len(counts) != 1:
            raise ValueError("packed source contains different copy policies")
        return counts.pop()

    def _receive_feedback(self, prefix, deficit):
        if prefix > len(self.sources):
            raise ValueError("feedback confirms unsent packed sources")
        for index in range(self.base, prefix):
            for channel, end in self._source_record_ends.pop(index).items():
                self.channel_acknowledged[channel] = max(self.channel_acknowledged[channel], end)
        super()._receive_feedback(prefix, deficit)
