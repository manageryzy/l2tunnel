"""Optional typed compact wire metadata for aligned shared coding.

The data encapsulation is IPv4/UDP or raw IPv4 with CRC32 in either direction.
Feedback travels in the opposite direction using its existing format. Source and repair
identities are parsed from received bytes. Bulk repairs retain the simulator's
coefficient-only GF256 model. Their serialized payload is a zero placeholder
with optional extent-based padding removal. Decoded source bytes use the
existing model ledger. CRC and
metadata helpers also accept actual coded bytes for independent numeric tests.

The opt-in C48 forward profiles instead emit the selected Rust union with actual
GF-coded lengths and bytes. Their return path keeps the existing lossy feedback
model. The rank decoder still materializes solved application bytes from its ledger.

The supported path is one FIFO link. A 15-bit source identifier has half-range
16384, exceeding the enforced 8192-source outstanding window. Bounded reorder
within that window is decoded correctly. Larger reorder spans or cross-session
stale datagrams require an extended session format. Original unknown sources
remain within the global repair window because admission stops at its limit.
"""

from dataclasses import dataclass, replace
from math import isfinite
from struct import Struct
from zlib import crc32

from .aligned_records import AlignedRecordConfig, AlignedRecordTransport, _unsigned_varint
from .compact import CompactSource, CompactTransport, coefficient
from .aggregate_ack import _decode_bounded_varint
from .coding import PRODUCT
from . import rolling_repair_wire as c48_wire
from .packed_spare import OUTER as C48_OUTER, parse_row, row_seed


WORD = Struct("!H")
TAIL = Struct("!HHII")
CRC = Struct("!I")
ID_MODULUS = 32768
ID_MASK = ID_MODULUS - 1
HALF_RANGE = ID_MODULUS // 2
TYPE_BIT = 32768
SYMBOL_BYTES = 1460
GLOBAL_WINDOW = 8192
LOCAL_WINDOW = 128
GLOBAL_EVERY = 16
ZERO_REPAIR = bytes(SYMBOL_BYTES)


@dataclass(frozen=True)
class CompactWireConfig(AlignedRecordConfig):
    encapsulation: str = "udp"
    repair_window_sources: int = LOCAL_WINDOW
    global_repair_every: int = GLOBAL_EVERY
    trim_repair_padding: bool = False
    short_source_max_bytes: int = 0
    short_source_copies: int = 1
    short_source_copy_scope: str = "all_short"
    pack_sources_max_delay_ms: float = 0
    c48_forward_repair_support: str = "legacy"

    def __post_init__(self):
        super().__post_init__()
        if self.encapsulation not in ("udp", "raw_ipv4_crc32"):
            raise ValueError("unknown compact wire encapsulation")
        if not isinstance(self.trim_repair_padding, bool):
            raise ValueError("repair padding trimming must be boolean")
        if self.c48_forward_repair_support not in ("legacy", "fixed", "confirmed_prefix"):
            raise ValueError("unknown C48 forward repair support")
        if (isinstance(self.short_source_max_bytes, bool) or not isinstance(self.short_source_max_bytes, int)
                or not 0 <= self.short_source_max_bytes <= SYMBOL_BYTES):
            raise ValueError("short source threshold must be an integer between 0 and 1460 bytes")
        if (isinstance(self.short_source_copies, bool) or not isinstance(self.short_source_copies, int)
                or self.short_source_copies < 1):
            raise ValueError("short source copies must be a positive integer")
        if self.short_source_copy_scope not in ("all_short", "context_and_independent"):
            raise ValueError("unknown short source copy scope")
        delay = self.pack_sources_max_delay_ms
        if (isinstance(delay, bool) or not isinstance(delay, (int, float))
                or not isfinite(delay) or not 0 <= delay <= 1):
            raise ValueError("source packing delay must be finite and between zero and one millisecond")
        if (self.block_sources != GLOBAL_WINDOW or self.repair_window_sources != LOCAL_WINDOW
                or self.global_repair_every != GLOBAL_EVERY):
            raise ValueError("compact wire requires an 8192-source global window and W128/G16")
        if self.authentication_bytes or self.outer_header_bytes != 36:
            raise ValueError("compact wire requires the existing zero-authentication IPv4 baseline")


@dataclass(frozen=True)
class ReceivedPacket:
    kind: str
    index: int
    payload: bytes
    start: int = 0
    end: int = 0
    serial: int = 0
    seed: int = 0


def _encapsulation(encapsulation):
    if encapsulation not in ("udp", "raw_ipv4_crc32"):
        raise ValueError("unknown compact wire encapsulation")
    return encapsulation == "raw_ipv4_crc32"


def _protect(body, encapsulation):
    return body + CRC.pack(crc32(body)) if _encapsulation(encapsulation) else body


def _unwrap(identifier, reference):
    distance = (identifier - reference) & ID_MASK
    if distance >= HALF_RANGE:
        distance -= ID_MODULUS
    return reference + distance


def encode_source(index, payload, encapsulation="udp"):
    if not 0 <= index < 2**32 or not 0 < len(payload) <= SYMBOL_BYTES:
        raise ValueError("source ID or payload is outside the supported format")
    return _protect(WORD.pack(index & ID_MASK) + bytes(payload), encapsulation)


def encode_repair(end, serial, payload, encapsulation="udp", *, tail=False, seed=None):
    if not 0 < end < 2**32 or serial < 0 or not 0 < len(payload) <= SYMBOL_BYTES:
        raise ValueError("repair identifier or payload is outside the supported format")
    first, second = TYPE_BIT | (end & ID_MASK), serial & ID_MASK
    if tail:
        if seed is None or not 0 <= seed < 2**32:
            raise ValueError("tail repair requires an explicit 32-bit seed")
        header = TAIL.pack(first, TYPE_BIT | second, end, seed)
    else:
        if seed is not None:
            raise ValueError("regular repair seed is derived from its transmitted serial")
        header = WORD.pack(first) + WORD.pack(second)
    return _protect(header + bytes(payload), encapsulation)


def decode_packet(wire, reference, encapsulation="udp"):
    """Decode only transmitted fields and receiver-local cumulative progress."""
    wire = bytes(wire)
    if _encapsulation(encapsulation):
        if len(wire) < CRC.size + WORD.size + 1:
            raise ValueError("truncated CRC-protected packet")
        body, expected = wire[:-CRC.size], CRC.unpack(wire[-CRC.size:])[0]
        if crc32(body) != expected:
            raise ValueError("compact wire CRC mismatch")
    else:
        body = wire
    if reference < 0 or len(body) < WORD.size + 1:
        raise ValueError("invalid receiver reference or truncated packet")
    first = WORD.unpack_from(body)[0]
    index = _unwrap(first & ID_MASK, reference)
    if not first & TYPE_BIT:
        payload = body[WORD.size:]
        if not max(0, reference - GLOBAL_WINDOW) <= index < reference + GLOBAL_WINDOW:
            raise ValueError("source ID exceeds the supported receive window")
        if len(payload) > SYMBOL_BYTES:
            raise ValueError("oversized compact source")
        return ReceivedPacket("source", index, payload)
    if len(body) < 4:
        raise ValueError("truncated repair fields")
    second = WORD.unpack_from(body, 2)[0]
    serial = second & ID_MASK
    if second & TYPE_BIT:
        if not TAIL.size < len(body) <= TAIL.size + SYMBOL_BYTES:
            raise ValueError("invalid extended repair length")
        _, _, end, seed = TAIL.unpack_from(body)
        if end & ID_MASK != first & ID_MASK:
            raise ValueError("inconsistent extended repair end")
        header_size, local = TAIL.size, False
    else:
        if not 4 < len(body) <= 4 + SYMBOL_BYTES:
            raise ValueError("invalid regular repair length")
        end, seed = index, (serial * 2654435761) & 0xFFFFFFFF
        header_size, local = 4, serial % GLOBAL_EVERY != 0
    if not max(1, reference - GLOBAL_WINDOW) <= end <= reference + GLOBAL_WINDOW:
        raise ValueError("repair end exceeds the supported receive window")
    start = max(0, end - (LOCAL_WINDOW if local else GLOBAL_WINDOW))
    payload = body[header_size:]
    payload += bytes(SYMBOL_BYTES - len(payload))
    return ReceivedPacket("tail" if second & TYPE_BIT else "repair", end - 1,
                          payload, start, end, serial, seed)


class CompactWireTransport(AlignedRecordTransport):
    """Shared aligned transport with charged, byte-parsed directional metadata."""

    def __init__(self, sim, reverse, config):
        if not isinstance(config, CompactWireConfig):
            raise TypeError("compact wire transport requires CompactWireConfig")
        direction = "reverse" if reverse else "forward"
        if sim.scenario.mtu != 1500 or len(sim.links[reverse]) != 1:
            raise ValueError(f"compact wire supports the {direction} single-FIFO MTU1500 path")
        if sim.links[reverse][0].jitter != 0:
            raise ValueError(f"compact wire requires zero {direction}-path jitter")
        super().__init__(sim, reverse, config)
        if self.symbol_bytes != SYMBOL_BYTES:
            raise ValueError("compact wire requires 1460 protected bytes")
        self.ip_header_bytes = 20 if config.encapsulation == "raw_ipv4_crc32" else 28
        self.crc_bytes = 4 if config.encapsulation == "raw_ipv4_crc32" else 0
        self.source_header = self.ip_header_bytes + self.crc_bytes + 2
        self.repair_header = self.ip_header_bytes + self.crc_bytes + 4
        self.wire_header_bytes = 0
        self.wire_crc_bytes = 0
        self.wire_regular_repairs = 0
        self.wire_source_wraps = 0
        self.wire_repair_serial_wraps = 0
        self.wire_retained_peak_symbols = 0
        self.wire_invalid_packets = 0
        self.wire_trimmed_repair_bytes = 0
        self.wire_protected_sources = 0
        self.wire_repeated_source_packets = 0
        self.wire_repeated_source_bytes = 0
        self.wire_peak_outstanding_sources = 0
        self.wire_retained_start = 0
        self.wire_received_symbols = {}
        # A shared ingress queue can recheck credit after feedback processing.
        # The callback takes no arguments and may submit more complete records.
        self.capacity_callback = None
        self.c48_union = not reverse and config.c48_forward_repair_support != "legacy"
        self.confirmed_support = self.c48_union and config.c48_forward_repair_support == "confirmed_prefix"
        self.wire_confirmed_prefix_rows = 0
        self.wire_skipped_prefix_sources = 0
        if self.c48_union:
            # The C48 study charges the IPv4/UDP header and authenticated envelope.
            self.ip_header_bytes, self.crc_bytes = C48_OUTER, 0

    source_wire_codec = None

    def source_wire(self, index, payload):
        if self.source_wire_codec is not None:
            payload = self.source_wire_codec.encode(payload)
        if self.c48_union:
            return b"\x01" + _unsigned_varint(index) + payload
        return encode_source(index, payload, self.config.encapsulation)

    def source_wire_header_bytes(self, wire, canonical_size):
        if self.source_wire_codec is None:
            return len(wire) - canonical_size - self.crc_bytes
        return WORD.size  # The selected study compresses legacy-framed reverse sources.

    def source_ip_bytes(self, index, wire):
        return self.ip_header_bytes + len(wire)

    def c48_regular_charge(self, extent):
        identity = self.repair_serial + 1
        end = len(self.sources)
        header = 1 + len(_unsigned_varint(identity)) + len(_unsigned_varint(end))
        if self.confirmed_support and identity % GLOBAL_EVERY == 0:
            skipped = self.base - max(0, end - GLOBAL_WINDOW)
            if skipped > 0:
                header += len(_unsigned_varint(skipped))
        return C48_OUTER + header + 2 + extent

    def decode_data_packet(self, wire):
        if not self.c48_union:
            packet = decode_packet(wire, self.received_prefix, self.config.encapsulation)
            if self.source_wire_codec is not None and packet.kind == "source":
                packet = replace(packet, payload=self.source_wire_codec.decode(packet.payload))
            return packet
        if not wire or C48_OUTER + len(wire) > self.sim.scenario.mtu:
            raise ValueError("invalid C48 data length")
        floor = self.received_prefix
        if wire[0] == 1:
            index, pos = _decode_bounded_varint(wire, 1, 2**32 - 2)
            body = wire[pos:]
            if (not 0 < len(body) <= SYMBOL_BYTES
                    or not max(0, floor - GLOBAL_WINDOW) <= index < floor + GLOBAL_WINDOW):
                raise ValueError("invalid C48 source")
            return ReceivedPacket("source", index, body)
        if wire[0] == 6:
            end, _, body = parse_row(wire, floor, GLOBAL_WINDOW)
            return ReceivedPacket("repair", end - 1, body, end - 8, end, end // 8, row_seed(end))
        identity, end, start, tail, rhs = c48_wire.decode_repair(
            wire, confirmed_prefix=self.confirmed_support, max_payload=SYMBOL_BYTES)
        if (not max(1, floor - GLOBAL_WINDOW) <= end <= floor + GLOBAL_WINDOW
                or (wire[0] in (7, 8) and start > floor)):
            raise ValueError("C48 repair is outside receiver-confirmed custody")
        seed = ((identity if tail else identity & ID_MASK) * 2654435761) & 0xffffffff
        return ReceivedPacket("tail" if tail else "repair", end - 1, rhs, start, end, identity, seed)

    def _c48_equation(self, start, end, seed, extent):
        # Source vectors include their protected big-endian payload lengths.
        # Integer XOR aligns short vectors on the left, with implicit zero tails.
        value = 0
        for index in range(start, end):
            factor = coefficient(seed, index)
            if factor:
                size = self.sources[index].size
                body = size.to_bytes(2, "big") + self.source_payloads[index][:size]
                value ^= int.from_bytes(body.translate(PRODUCT[factor]), "little")
        return value.to_bytes(extent + 2, "little")

    def _send_wire(self, wire, kind, header_bytes):
        if self.c48_union and C48_OUTER + len(wire) > self.sim.scenario.mtu:
            raise ValueError("selected C48 packet exceeds the configured path MTU")
        self.wire_header_bytes += header_bytes
        self.wire_crc_bytes += self.crc_bytes
        return self.sim.send(self.reverse, self.ip_header_bytes + len(wire), kind,
                             lambda: self._receive_wire(wire))

    def _source_copy_count(self, payload):
        if len(payload) > self.config.short_source_max_bytes:
            return 1
        if self.config.short_source_copy_scope == "all_short":
            return self.config.short_source_copies
        if len(payload) < 6:
            return 1
        kind = payload[3]
        size = int.from_bytes(payload[4:6], "big")
        native_context = kind == 8 and getattr(self, "fixed_anchor_ip", None) is not None
        if len(payload) == 6 + size and (kind == 2 or kind == 0 and size == 66 or native_context):
            return self.config.short_source_copies
        return 1

    def _aligned_source(self, payload):
        index = len(self.sources)
        if index - self.base >= GLOBAL_WINDOW:
            raise ValueError("source admission exceeds the global repair window")
        wire = self.source_wire(index, payload)
        size = len(payload)
        self.channel_header_bytes += 3
        self.implicit_padding_bytes += SYMBOL_BYTES - size
        self.buffer_bytes -= size
        self.sent_bytes += size
        self.sources.append(CompactSource(index, size, self.sent_bytes))
        self.source_payloads.append(payload + bytes(SYMBOL_BYTES - size))
        self.wire_source_wraps += int(index > 0 and index % ID_MODULUS == 0)
        source_header = self.source_wire_header_bytes(wire, size)
        finish, _ = self._send_wire(wire, "source", source_header)
        copies = self._source_copy_count(payload)
        self.wire_protected_sources += int(copies > 1)
        for _ in range(copies - 1):
            finish, _ = self._send_wire(wire, "source", source_header)
            self.wire_repeated_source_packets += 1
            self.wire_repeated_source_bytes += self.source_ip_bytes(index, wire)
        self.wire_peak_outstanding_sources = max(self.wire_peak_outstanding_sources, index + 1 - self.base)
        self.last_source_at = finish
        self._prune_sender_payloads()
        self.credit += self.credit_numerator
        while self.credit >= self.credit_denominator:
            self.credit -= self.credit_denominator
            self._repair(False)
        self.tail_generation += 1
        self._schedule_tail(finish, self.tail_generation)

    def _prune_sender_payloads(self):
        keep = max(0, len(self.sources) - GLOBAL_WINDOW)
        if keep > self.base:
            raise ValueError("retention would expire an unconfirmed source")
        for index in range(self.wire_retained_start, keep):
            self.source_payloads[index] = None
        self.wire_retained_start = keep
        self.wire_retained_peak_symbols = max(self.wire_retained_peak_symbols, len(self.sources) - keep)

    def _repair(self, tail):
        if self.base >= len(self.sources):
            return
        self.repair_serial += 1
        self.wire_repair_serial_wraps += int(self.repair_serial % ID_MODULUS == 0)
        serial = self.repair_serial & ID_MASK
        local = not tail and serial % GLOBAL_EVERY != 0
        end = len(self.sources)
        start = max(0, end - (LOCAL_WINDOW if local else GLOBAL_WINDOW))
        nominal = start
        if self.confirmed_support and not local:
            start = max(start, self.base)
        if any(payload is None for payload in self.source_payloads[start:end]):
            raise ValueError("repair support exceeds retained source bytes")
        extent = SYMBOL_BYTES
        if self.config.trim_repair_padding:
            # Encoded extent includes every data byte, including trailing zeros.
            # Only columns zero-extended by the source encoder may be omitted.
            extent = max(source.size for source in self.sources[start:end])
        seed = (self.repair_serial * 2654435761) & 0xFFFFFFFF if tail else None
        if self.c48_union:
            factor_seed = seed if tail else (serial * 2654435761) & 0xffffffff
            rhs = self._c48_equation(start, end, factor_seed, extent)
            wire = c48_wire.encode_repair(self.repair_serial, end, start, tail, rhs,
                                          confirmed_prefix=self.confirmed_support, max_payload=SYMBOL_BYTES)
            header_bytes = len(wire) - len(rhs)
            self.wire_confirmed_prefix_rows += start > nominal
            self.wire_skipped_prefix_sources += start - nominal
        else:
            wire = encode_repair(end, serial, ZERO_REPAIR[:extent], self.config.encapsulation, tail=tail, seed=seed)
            header_bytes = TAIL.size if tail else 4
        self.wire_trimmed_repair_bytes += SYMBOL_BYTES - extent
        self._send_wire(wire, "repair", header_bytes)
        self.local_repairs += bool(local)
        self.global_repairs += not local
        self.scheduled_repairs += not tail
        self.tail_repairs += bool(tail)
        self.wire_regular_repairs += not tail

    def _receive_wire(self, wire):
        try:
            packet = self.decode_data_packet(wire)
        except ValueError:
            self.wire_invalid_packets += 1
            return
        if packet.kind == "source":
            self._notice(packet.index + 1)
            self.received_source.add(packet.index)
            if packet.index not in self.decoder.known:
                self.wire_received_symbols[packet.index] = packet.payload + bytes(SYMBOL_BYTES - len(packet.payload))
            solved = self.decoder.insert({packet.index: 1})
        else:
            self._notice(packet.end)
            coefficients = {index: coefficient(packet.seed, index) for index in range(packet.start, packet.end)
                            if index not in self.decoder.known}
            solved = self.decoder.insert(coefficients)
        self._new_known(solved)
        self._advance()

    def _deliver_symbol(self, index):
        payload = self.wire_received_symbols.pop(index, None)
        if payload is None:
            # Existing coefficient-model ledger materializes rank-recovered
            # bytes. Support selection and coefficient seeds came from wire.
            payload = self.source_payloads[index]
        for channel, serial, frame in self.receiver.receive(index, payload):
            self.channel_completed[channel] = self.receiver.expected[channel]
            if frame is None:
                continue
            expected, created_at, callback, deliver_frame = self.callbacks.pop((channel, serial))
            if frame != expected:
                raise ValueError("reconstructed compact wire frame differs from submission")
            self.delivered_bytes += len(frame)
            self.delays.append((self.sim.now - created_at) * 1000)
            if self.sim.now <= self.sim.traffic.duration_s:
                self.delivered_during_measurement_bytes += len(frame)
            if deliver_frame:
                callback(frame)
            else:
                callback()

    def _receive_feedback(self, prefix, deficit):
        # Preserve confirmed symbols still inside a future fixed support.
        CompactTransport._receive_feedback(self, prefix, deficit)
        self._prune_sender_payloads()
        if self.capacity_callback is not None:
            self.capacity_callback()
