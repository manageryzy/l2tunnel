"""512-byte timed application records for the optional native Packed C48 probe."""

from array import array
from math import ceil
from struct import Struct


SIZE = 512
RATE = 76_000_000
HEADER = Struct("!IQ")
RECORD_NS = SIZE * 8 * 1_000_000_000


class RecordFlow:
    def __init__(self, identity, flows, clock):
        self.identity, self.flows = identity, flows
        self.start, self.end = clock["start_ns"], clock["end_ns"]
        self.outgoing = 0
        self.pending = b""
        self.incoming = 0
        self.remainder = b""
        self.delivery = array("Q")
        self.scheduled_delivery = array("Q")

    def due_ns(self, index):
        slot = self.identity + self.flows * index
        return self.start + (slot * RECORD_NS + RATE - 1) // RATE

    def offer(self, now, body):
        if not self.pending and self.due_ns(self.outgoing) <= now < self.end:
            # Embed the first attempted write time. Short writes reuse the same
            # record and time until the remainder is accepted by this TCP socket.
            offset = (self.outgoing % (len(body) // SIZE)) * SIZE
            self.pending = HEADER.pack(self.outgoing, now) + body[offset + HEADER.size:offset + SIZE]
        return self.pending

    def accepted(self, size):
        if size:
            self.pending = self.pending[size:]
            if not self.pending:
                self.outgoing += 1

    def receive(self, chunk, now):
        data = self.remainder + chunk
        end = len(data) // SIZE * SIZE
        for offset in range(0, end, SIZE):
            seq, offered = HEADER.unpack_from(data, offset)
            scheduled = self.due_ns(self.incoming)
            if seq != self.incoming or not scheduled <= offered < self.end or offered > now:
                raise ValueError("invalid sequence or timestamp in C48 application stream")
            self.delivery.append(now - offered)
            self.scheduled_delivery.append(now - scheduled)
            self.incoming += 1
        self.remainder = data[end:]


def measurements(flows, sender):
    def distribution(attribute):
        values = sorted(ns for flow in flows for ns in getattr(flow, attribute))
        return {"count": len(values), "p99_ms": values[ceil(len(values) * .99) - 1] / 1e6 if values else None,
                "max_ms": values[-1] / 1e6 if values else None}

    phase = flows[0]
    # Count schedule slots strictly before the offering cutoff.
    slots = ((phase.end - phase.start - 1) * RATE) // RECORD_NS + 1
    return {"record_bytes": SIZE, "aggregate_offered_mbit_s": RATE / 1e6,
            "scheduled_records": slots if sender else 0,
            "started_records": sum(f.outgoing + bool(f.pending) for f in flows),
            "fully_written_records": sum(f.outgoing for f in flows),
            "fully_read_records": sum(f.incoming for f in flows),
            "partial_receive_bytes": sum(len(f.remainder) for f in flows),
            "first_write_to_complete_read": distribution("delivery"),
            "scheduled_offer_to_complete_read": distribution("scheduled_delivery")}
