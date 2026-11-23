"""Per-direction Packed integration of native IP contexts with exact short record distances."""

from collections import Counter, defaultdict

from .aligned_records import FRAGMENT_HEADER, FRAGMENT_KIND
from .fixed_anchor_ip import (
    CONTEXT,
    RAW,
    WRAPPER,
    MAX_DISTANCE,
    Header,
    encode_ip,
    decode_ip,
    validate_body,
)
from .packed_wire import PACKED_CHANNEL, PackedWireTransport, packed_units


def _frame(packet, macs):
    if not packet or packet[0] >> 4 not in (4, 6):
        raise ValueError("native study packet lacks IP framing")
    return macs + (b"\x08\x00" if packet[0] >> 4 == 4 else b"\x86\xdd") + packet


class Policy:
    def __init__(self, interval, macs, maximum):
        self.interval, self.macs, self.maximum = interval, macs, maximum
        self.anchors = {}
        self.counts = Counter()

    def submit(
        self,
        t,
        ch,
        frame_bytes,
        payload_bytes,
        deliver,
        *,
        ack=False,
        frame=None,
        deliver_frame=False,
    ):
        if (
            frame is None
            or len(frame) != frame_bytes
            or not 0 <= payload_bytes <= frame_bytes
        ):
            raise ValueError("invalid native study frame")
        frame = bytes(frame)
        ip = frame[14:]
        if _frame(ip, self.macs) != frame:
            raise ValueError(
                "fixed native IP study requires its configured Ethernet endpoint"
            )
        serial = t.channel_sequences[ch]
        anchor_id, anchor = self.anchors.get(ch, (-1, None))
        distance = serial - anchor_id
        if serial % self.interval == 0 or not 1 <= distance <= MAX_DISTANCE:
            anchor = None
        new, body = encode_ip(
            ip,
            anchor,
            distance,
            capacity=t.record_capacity,
            elide=t.config.elide_payload_length,
            predictive=t.config.packed_predictive_records,
            pairs=t.config.timestamp_pair_dictionary,
            short=t.receiver.independent_short_frame_bytes,
            maximum=self.maximum,
        )
        if (
            serial + 1 + int(new is not None) - t.channel_completed[ch] > 32767
            or len(body) > 65535
        ):
            raise ValueError("fixed native channel exceeds its record budget")
        if new is not None:
            header = bytes((CONTEXT,)) + len(new.data).to_bytes(2, "big") + new.data
            t._submit_record(ch, serial, header)
            self.anchors[ch] = serial, new
            t.profile_context_bytes += len(header)
            t.context_records += 1
            self.counts["contexts"] += 1
            serial += 1
        t.callbacks[ch, serial] = (frame, t.sim.now, deliver, deliver_frame)
        t._submit_record(ch, serial, body)
        if body[0] == RAW:
            self.counts["raw"] += 1
            t.independent_short_records += (
                len(ip) <= t.receiver.independent_short_frame_bytes
            )
        else:
            self.counts["wrapped"] += 1
            inner = body[2]
            self.counts[
                "delta_explicit"
                if inner == 9
                else "length_elided"
                if inner == 6
                else "predictive"
            ] += 1
            t.elided_length_records += inner == 6
            t.packed_predictive_records += (inner & 7) in (5, 7)
            t.timestamp_pair_records += (inner & 7) == 5
        t.source_record_bytes += len(body)
        t.frame_count += 1
        t.channel_sequences[ch] = serial + 1
        t.peak_pending_bytes = max(t.peak_pending_bytes, t.pending_bytes)


_ABSENT = object()


class Journal:
    """Touch only rows affected by this authenticated packet; no whole-channel snapshot."""

    def __init__(self):
        self.changes = []

    def put(self, mapping, key, value):
        self.changes.append((mapping, key, mapping.get(key, _ABSENT)))
        if value is _ABSENT:
            mapping.pop(key, None)
        else:
            mapping[key] = value

    def rollback(self):
        for mapping, key, previous in reversed(self.changes):
            if previous is _ABSENT:
                mapping.pop(key, None)
            else:
                mapping[key] = previous


class FixedReceiver:
    def __init__(self, t, policy):
        self.policy = policy
        self.symbol_bytes = t.packing_bytes
        self.coding_bytes = t.symbol_bytes
        self.max_units = t.unit_limit
        self.independent_short_frame_bytes = t.receiver.independent_short_frame_bytes
        self.expected = defaultdict(int)
        self.fragments = {}
        self.complete = {}
        self.retired = {}
        self.early_delivered = {}
        self.early_release_count = 0
        self.seen = set()
        self.source_prefix = 0

    def discard_before(self, prefix):
        for index in range(self.source_prefix, prefix):
            self.seen.discard(index)
        self.source_prefix = max(prefix, self.source_prefix)

    def _anchor(self, ch, serial):
        row = self.complete.get((ch, serial))
        if row is not None and row[2] is not None:
            return row[2]
        retired = self.retired.get((ch, serial % MAX_DISTANCE))
        return retired[1] if retired is not None and retired[0] == serial else None

    def _native(self, key, ordered):
        body, padded, anchor = self.complete[key]
        if anchor is not None:
            return None
        ch, serial = key
        if body[0] == WRAPPER:
            anchor = self._anchor(ch, serial - body[1])
            if anchor is None:
                if ordered:
                    raise ValueError(
                        "fixed delta references a retired non-context record"
                    )
                return None
            ip = decode_ip(anchor, body, padded=padded, maximum=self.policy.maximum)
        else:
            ip = body[3:]
        if not ordered and not (
            body[0] == RAW and len(ip) <= self.independent_short_frame_bytes
        ):
            # This simulated TUN hands independently reconstructed established TCP
            # payloads straight to its endpoint. Other traffic keeps ordered handoff.
            try:
                h = Header.parse(ip, full=True)
            except ValueError:
                return None
            flags = ip[h.tcp + 13]
            if not h.payload or not flags & 16 or flags & 7:
                return None
        return _frame(ip, self.policy.macs)

    def _publish(self, ch, serial, body, padded, j, out, counts):
        key = (ch, serial)
        body = validate_body(body, padded=padded, max_native=self.policy.maximum)
        if body[0] == WRAPPER and serial < body[1]:
            raise ValueError("fixed anchor distance underflows record ID")
        header = Header.parse(body[3:], full=False) if body[0] == CONTEXT else None
        if key in self.complete:
            if self.complete[key] != (body, padded, header):
                raise ValueError("conflicting fixed IP record")
            return
        j.put(self.complete, key, (body, padded, header))
        # At most eight later records can refer to a newly available context.
        stop = serial + MAX_DISTANCE if header is not None else serial
        for candidate in range(serial, stop + 1):
            k = (ch, candidate)
            if (
                candidate <= self.expected.get(ch, 0)
                or k not in self.complete
                or k in self.early_delivered
            ):
                continue
            if candidate != serial:
                target = self.complete[k][0]
                if target[0] != WRAPPER or candidate - target[1] != serial:
                    continue
            native = self._native(k, False)
            if native is not None:
                j.put(self.early_delivered, k, True)
                out.append((*k, native))
                counts["early_native"] += 1
        head = self.expected.get(ch, 0)
        while (ch, head) in self.complete:
            k = (ch, head)
            _, _, context = self.complete[k]
            if context is not None:
                j.put(self.retired, (ch, head % MAX_DISTANCE), (head, context))
                out.append((*k, None))
            elif k in self.early_delivered:
                j.put(self.early_delivered, k, _ABSENT)
            else:
                out.append((*k, self._native(k, True)))
                counts["ordered_native"] += 1
            j.put(self.complete, k, _ABSENT)
            head += 1
        if head != self.expected.get(ch, 0):
            j.put(self.expected, ch, head)

    def _unit(self, unit, padded, j, out, counts):
        if len(unit) < 4 or unit[0] == PACKED_CHANNEL:
            raise ValueError("invalid fixed-anchor unit")
        ch = unit[0]
        head = self.expected.get(ch, 0)
        delta = (int.from_bytes(unit[1:3], "big") - head) & 65535
        if delta >= 32768:
            return
        serial = head + delta
        key = (ch, serial)
        body = unit[3:]
        if body[0] == FRAGMENT_KIND:
            if len(body) <= FRAGMENT_HEADER.size:
                raise ValueError("truncated fixed fragment")
            _, total, offset = FRAGMENT_HEADER.unpack_from(body)
            capacity = self.symbol_bytes - 8
            if not (
                self.symbol_bytes - 3 < total <= min(65535, self.policy.maximum + 49)
                and offset < total
                and offset % capacity == 0
            ):
                raise ValueError("invalid fixed fragment extent")
            length = min(total - offset, capacity)
            part = body[5 : 5 + length]
            if len(part) != length or (
                any(body[5 + length :]) if padded else len(body) != 5 + length
            ):
                raise ValueError("truncated or padded fixed fragment")
            size, old = self.fragments.get(key, (total, {}))
            if size != total or (offset in old and old[offset] != part):
                raise ValueError("conflicting fixed fragment")
            new = {**old, offset: part}
            if len(new) != (total + capacity - 1) // capacity:
                j.put(self.fragments, key, (total, new))
                return
            body = b"".join(new[i] for i in range(0, total, capacity))
            padded = False
            if body[0] == WRAPPER and len(body) > 2 and body[2] != 9:
                raise ValueError("implicit fixed body cannot span symbols")
            j.put(self.fragments, key, _ABSENT)
        elif key in self.fragments:
            raise ValueError("conflicting fixed record framing")
        self._publish(ch, serial, body, padded, j, out, counts)

    def receive(self, index, data):
        if len(data) != self.coding_bytes or any(data[self.symbol_bytes :]):
            raise ValueError("invalid fixed symbol extent")
        if index < self.source_prefix or index in self.seen:
            return []
        data = data[: self.symbol_bytes]
        packed = data[0] == PACKED_CHANNEL
        units = (
            packed_units(data, self.symbol_bytes, fixed_anchor=True)
            if packed
            else (data,)
        )
        if len(units) > self.max_units:
            raise ValueError("too many fixed-anchor packed units")
        out = []
        j = Journal()
        counts = Counter()
        try:
            for unit in units:
                self._unit(unit, not packed, j, out, counts)
        except ValueError:
            j.rollback()
            raise
        self.seen.add(index)
        self.early_release_count += counts["early_native"]
        self.policy.counts.update(counts)
        return out


def select(t, interval, macs, maximum):
    if (
        not isinstance(t, PackedWireTransport)
        or t.reverse
        or t.frame_count
        or t.sources
        or t._pack
        or t.source_queue
        or t.fixed_anchor_ip is not None
    ):
        raise ValueError("select fixed IP headers on a fresh forward Packed transport")
    if (
        type(interval) is not int
        or not 1 <= interval <= MAX_DISTANCE
        or type(macs) is not bytes
        or len(macs) != 12
    ):
        raise ValueError("invalid fixed IP cadence or endpoint MACs")
    if (
        type(maximum) is not int
        or not 40 <= maximum <= 65532
        or not t.config.independent_delivery
    ):
        raise ValueError(
            "fixed IP study needs bounded native capacity and independent source delivery"
        )
    policy = Policy(interval, macs, maximum)
    t.receiver = FixedReceiver(t, policy)
    t.fixed_anchor_ip = policy
    return policy
