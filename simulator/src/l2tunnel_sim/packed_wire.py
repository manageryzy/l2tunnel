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
# The exclusive end of a repair must still fit in 32 bits.
LAST_RECOVERABLE_SOURCE = 2**32 - 2


def _validate_unit(unit, symbol_bytes, fixed_anchor=False):
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
    elif fixed_anchor:
        from .fixed_anchor_ip import validate_body
        validate_body(body, padded=False)
    elif body[0] == CONTEXT_LENGTH_KIND:
        # Validate the explicit delta header now. Payload length depends on
        # the preceding in-order codec context and is checked by the receiver.
        encoded_record_length(b"\x03\x00\x00" + body[1:])
    elif body[0] & 7 == PACKED_PREDICTIVE_KIND:
        encoded_record_length(b"\x03\x00\x00" + bytes([body[0] & 0xF8]) + body[1:])
    elif body[0] & 7 != TIMESTAMP_PAIR_KIND:
        if encoded_record_length(body) != len(body):
            raise ValueError("packed aligned unit contains trailing bytes")


def packed_units(payload, symbol_bytes=1460, *, fixed_anchor=False):
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
        _validate_unit(unit, symbol_bytes, fixed_anchor)
        units.append(unit)
        position += size
    if any(payload[position:]):
        raise ValueError("nonzero packed source padding")
    return units


class PackedAlignedReceiver(AlignedRecordReceiver):
    """Decode each validated unit with the existing per-channel receiver."""

    def __init__(self, symbol_bytes, independent_short_frame_bytes=0, *, coding_bytes=None, max_units=255):
        super().__init__(symbol_bytes, independent_short_frame_bytes)
        self.coding_bytes = symbol_bytes if coding_bytes is None else coding_bytes
        self.max_units = max_units

    def receive(self, index, data):
        if len(data) != self.coding_bytes or any(data[self.symbol_bytes:]):
            raise ValueError("invalid packed symbol length")
        data = data[:self.symbol_bytes]
        if data[0] != PACKED_CHANNEL:
            return super().receive(index * SLOTS_PER_SOURCE, data)
        units = packed_units(data, self.symbol_bytes)
        if len(units) > self.max_units:
            raise ValueError("too many units in packed source")
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

    fixed_anchor_ip = None

    def __init__(self, sim, reverse, config):
        if config.pack_sources_max_delay_ms <= 0:
            raise ValueError("packed wire transport requires a positive packing delay")
        super().__init__(sim, reverse, config)
        self.packing_bytes = self.symbol_bytes
        self.unit_limit = 255
        self.receiver = PackedAlignedReceiver(self.symbol_bytes, config.independent_short_frame_bytes)
        self._pack = []
        self._pack_unit_bytes = 0
        self._pack_copies = None
        self._pack_deadline = None
        self._pack_generation = 0
        self.fragment_tail_stats = None
        self._holds_only_final_fragments = False
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
        if self.fixed_anchor_ip is None:
            super().submit_channel(channel, *args, **kwargs)
        else:
            self.fixed_anchor_ip.submit(self, channel, *args, **kwargs)
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

    def select_packing_geometry(self, unit_bytes, max_units):
        """Set the sender and receiver geometry before the first native frame."""
        if (self.fixed_anchor_ip is not None or type(unit_bytes) is not int or type(max_units) is not int or
                not CHANNEL_HEADER.size + FRAGMENT_HEADER.size < unit_bytes <= self.symbol_bytes or
                not 1 <= max_units <= 255 or self.frame_count or self._pack or self.sources):
            raise ValueError("invalid or already active Packed geometry")
        receiver = PackedAlignedReceiver(unit_bytes, self.config.independent_short_frame_bytes,
                                         coding_bytes=self.symbol_bytes, max_units=max_units)
        self.receiver = receiver
        self.packing_bytes = unit_bytes
        self.unit_limit = max_units
        self.record_capacity = unit_bytes - CHANNEL_HEADER.size

    def enable_fragment_tail_packing(self):
        """Let leading full fragments pass same-copy final fragments before their hold expires."""
        if self.frame_count or self.sources or self.source_queue or self._pack:
            raise ValueError("select fragment tail packing before the first unit")
        self.fragment_tail_stats = Counter()

    def _queue_source(self, payload):
        payload = bytes(payload)
        _validate_unit(payload, self.packing_bytes, self.fixed_anchor_ip is not None)
        copies = super()._source_copy_count(payload)
        end = self._record_end(payload)
        if self.fragment_tail_stats is not None:
            if self._pack_deadline is not None and self.sim.now >= self._pack_deadline:
                self.flush(self._pack_generation)
            offset = (FRAGMENT_HEADER.unpack_from(payload, CHANNEL_HEADER.size)[2]
                      if payload[CHANNEL_HEADER.size] == FRAGMENT_KIND else None)
            # Include sealed sources waiting for coding-window credit. Keep an
            # identity for the older batch and a representable 32-bit repair end.
            if (self._holds_only_final_fragments and self._pack_copies == copies
                    and len(payload) == self.packing_bytes and offset == 0 and end is None
                    and len(self.sources) + len(self.source_queue) < LAST_RECOVERABLE_SOURCE):
                self.buffer_bytes += len(payload)
                self.submitted_bytes += len(payload)
                self._seal_pack("leading_full_fragment", leading=payload)
                return
        projected = 2 + 2 * (len(self._pack) + 1) + self._pack_unit_bytes + len(payload)
        if self._pack and (copies != self._pack_copies or projected > self.packing_bytes):
            self._seal_pack("copy_policy" if copies != self._pack_copies else "capacity")
        if self.fragment_tail_stats is not None:
            if not self._pack and len(self.sources) + len(self.source_queue) > LAST_RECOVERABLE_SOURCE:
                raise ValueError("no recoverable Packed source identity remains")
            self._holds_only_final_fragments = ((not self._pack or self._holds_only_final_fragments)
                                                and offset not in (None, 0) and end is not None)
        old_size = self.pending_pack_bytes
        self._pack.append((payload, self.sim.now, end))
        self._pack_unit_bytes += len(payload)
        self._pack_copies = copies
        added = self.pending_pack_bytes - old_size
        self.buffer_bytes += added
        self.submitted_bytes += added
        # A unit that cannot share a source with another equal-sized unit
        # follows the existing immediate-send path, independent of its role.
        if len(self._pack) == self.unit_limit:
            self._seal_pack("unit_limit")
        elif len(payload) > (self.packing_bytes - 6) // 2:
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

    def _seal_pack(self, reason, *, leading=None):
        units = self._pack if leading is None else ((leading, self.sim.now, None),)
        expected_bytes = self.pending_pack_bytes if leading is None else len(leading)
        if len(units) == 1:
            payload = units[0][0]
            self.packed_single_sources += 1
        else:
            payload = bytes([PACKED_CHANNEL, len(units)]) + b"".join(
                len(unit).to_bytes(2, "big") + unit for unit, _, _ in units)
            self.packed_sources += 1
            self.packed_units += len(units)
            self.packed_header_bytes += 2 + 2 * len(units)
        if len(payload) != expected_bytes or len(payload) > self.packing_bytes:
            raise ValueError("packed source accounting mismatch")
        ends = {}
        for _, queued_at, end in units:
            wait = (self.sim.now - queued_at) * 1000
            self.packed_wait_count += 1
            self.packed_wait_sum_ms += wait
            self.packed_wait_max_ms = max(self.packed_wait_max_ms, wait)
            if end is not None:
                channel, record_end = end
                ends[channel] = max(ends.get(channel, 0), record_end)
        self.packed_max_units = max(self.packed_max_units, len(units))
        self.packed_flush_reasons[reason] += 1
        if leading is None:
            if self._holds_only_final_fragments:
                stats = self.fragment_tail_stats
                stats["tail_only_sources"] += 1
                stats["tail_only_units"] += len(units)
                if len(units) > 1:
                    stats["combined_tail_sources"] += 1
                    stats["combined_units"] += len(units)
                    stats["container_metadata_bytes"] += 2 + 2 * len(units)
                wait_us = (self.sim.now - units[0][1]) * 1_000_000
                stats["maximum_tail_batch_wait_us"] = max(stats["maximum_tail_batch_wait_us"], wait_us)
                self._holds_only_final_fragments = False
            self._pack.clear()
            self._pack_unit_bytes = 0
            self._pack_copies = None
            self._pack_deadline = None
            self._pack_generation += 1
        else:
            self.fragment_tail_stats["leading_heads"] += 1
            self.fragment_tail_stats["leading_body_bytes"] += len(leading)
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
        for unit in packed_units(payload, self.packing_bytes, fixed_anchor=self.fixed_anchor_ip is not None):
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
