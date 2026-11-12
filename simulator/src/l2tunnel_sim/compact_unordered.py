"""Independent full-frame record reassembly over compact selective-repeat ARQ.

Every source packet carries eight additional bytes for its first record's
32-bit ID, 16-bit fragment offset, and 16-bit total encoded length. Following
records have the existing type/length prefix and consecutive record IDs.
Full L2 records make every reconstructed frame independent of header context.
"""

from collections import deque
from dataclasses import dataclass
from functools import partial
from struct import pack, unpack

from .compact import CompactConfig
from .compact_arq import CompactARQTransport
from .compact_tcp import CompactTCP


FRAGMENT_DESCRIPTOR_BYTES = 8


def fragment_descriptor(record_id, offset, length):
    """Encode the independently parseable first-fragment packet descriptor."""
    if not 0 <= record_id < 2 ** 32 or not 0 <= offset < length <= 65535:
        raise ValueError("record ID, offset, or encoded length exceeds its wire field")
    return pack("!IHH", record_id, offset, length)


def parse_fragment_descriptor(value):
    if len(value) != FRAGMENT_DESCRIPTOR_BYTES:
        raise ValueError("truncated first-fragment descriptor")
    record_id, offset, length = unpack("!IHH", value)
    fragment_descriptor(record_id, offset, length)
    return record_id, offset, length


@dataclass
class IndependentRecord:
    index: int
    start: int
    end: int
    frame_bytes: int
    created_at: float
    deliver: object
    received_bytes: int = 0
    delivered: bool = False


class IndependentRecordARQ(CompactARQTransport):
    def __init__(self, sim, reverse, config, *, ordered_delivery=False):
        if config.header_profile != "full_l2":
            raise ValueError("independent records require the full_l2 profile")
        if type(ordered_delivery) is not bool:
            raise ValueError("ordered_delivery must be boolean")
        super().__init__(sim, reverse, config)
        self.ordered_delivery = ordered_delivery
        self.source_header += FRAGMENT_DESCRIPTOR_BYTES
        self.symbol_bytes = sim.scenario.mtu - self.source_header
        self.record_capacity = self.symbol_bytes - 2
        if self.record_capacity < 1:
            raise ValueError("MTU leaves no independent-record source payload")
        self.independent_records = []
        self.record_indices = {}
        self.packet_fragments = []
        self.packet_record_index = 0
        self.completed_records = deque()
        self.unordered_deliveries = 0

    def submit(self, frame_bytes, payload_bytes, deliver, ack=False, frame=None):
        if not 0 <= payload_bytes <= frame_bytes <= 65532:
            raise ValueError("independent full-frame records must fit a 16-bit encoded length")
        index = len(self.independent_records)
        if index >= 2 ** 32:
            raise ValueError("independent record sequence exceeds its wire field")
        record = IndependentRecord(index, self.submitted_bytes,
                                   self.submitted_bytes + frame_bytes + 3,
                                   frame_bytes, self.sim.now, deliver)
        self.independent_records.append(record)
        self.record_indices[record.end] = record.index
        super().submit(frame_bytes, payload_bytes, deliver, ack=ack, frame=frame)

    def _source(self, size):
        start, end = self.sent_bytes, self.sent_bytes + size
        fragments = []
        index = self.packet_record_index
        while index < len(self.independent_records):
            record = self.independent_records[index]
            if record.start >= end:
                break
            offset = max(start, record.start) - record.start
            length = min(end, record.end) - max(start, record.start)
            fragments.append((index, offset, length))
            if record.end > end:
                break
            index += 1
        self.packet_record_index = index
        first = self.independent_records[fragments[0][0]]
        # Validate the charged fields that identify a partial record even when
        # the preceding packet and the record's own type/length prefix are lost.
        fragment_descriptor(first.index, fragments[0][1], first.end - first.start)
        self.packet_fragments.append(tuple(fragments))
        super()._source(size)

    def _receive_source(self, source, serial):
        if source.index not in self.decoder.known:
            for index, _, length in self.packet_fragments[source.index]:
                record = self.independent_records[index]
                record.received_bytes += length
                assert record.received_bytes <= record.end - record.start
                if record.received_bytes == record.end - record.start:
                    self.completed_records.append(record)
        super()._receive_source(source, serial)

    def _advance(self):
        if self.ordered_delivery:
            self.completed_records.clear()
            super()._advance()
            return
        while self.completed_records:
            record = self.completed_records.popleft()
            if record.delivered:
                continue
            record.delivered = True
            self.delivered_bytes += record.frame_bytes
            self.delays.append((self.sim.now - record.created_at) * 1000)
            if self.sim.now <= self.sim.traffic.duration_s:
                self.delivered_during_measurement_bytes += record.frame_bytes
            self.unordered_deliveries += 1
            record.deliver()
        # The inherited ARQ feedback still reports the true contiguous source
        # prefix and receipt bitmap. Remove emitted records before its ordered
        # record loop, retaining its packet feedback and retry behavior intact.
        self.records = deque(record for record in self.records
                             if not self.independent_records[self.record_indices[record[0]]].delivered)
        super()._advance()


class IndependentRecordTCP(CompactTCP):
    """Retain native cumulative TCP delivery over an unordered L2 record path."""

    def __init__(self, *args, compact_config=None, ordered_delivery=False,
                 reliable_acks=False, **kwargs):
        config = compact_config or CompactConfig(header_profile="full_l2", repair_ratio=0)
        transport = partial(IndependentRecordARQ, ordered_delivery=ordered_delivery)
        super().__init__(*args, compact_config=config, reliable_acks=reliable_acks,
                         transport_type=transport, **kwargs)
