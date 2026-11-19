"""Optional eight-source row on the authenticated UDP C48 rank-and-service study."""
from collections import Counter, deque

from l2tunnel_sim import compact_wire as cw, packed_receiver_service as receiver
from l2tunnel_sim.packed_spare import GROUP, OUTER, SpareGate, end_bytes, parse_row, row_bytes, row_seed


class SelectedBody(bytes):
    """Typed union selection on the mixed historical-framing study adapter."""


class NearStudy:
    def __init__(self, sim, services, sender_ip_bytes_per_second):
        self.mux = sim.mux
        self.service = services["forward"]
        self.t = self.service.transport
        self.gate = SpareGate(sender_ip_bytes_per_second)
        self.counts = Counter()
        self.buckets = []
        self.snapshots = {}
        self.pending = deque()
        self.pending_bytes = 0
        self.restore = []
        # Wrap before the caller installs physical UDP pricing, to see actual IP bytes.
        for net in {id(s.transport.sim): s.transport.sim for s in services.values()}.values():
            self.observe_network(net)

    def observe_network(self, net):
        original = net.send

        def send(reverse, size, kind, receive):
            finish, rtt = original(reverse, size, kind, receive)
            if not reverse:
                self.gate.accept(size)
                if kind != "near_repair":
                    self.pending.append((finish, size))
                    self.pending_bytes += size
            return finish, rtt

        net.send = send

    def backlog(self):
        now = self.t.sim.now
        while self.pending and self.pending[0][0] <= now:
            self.pending_bytes -= self.pending.popleft()[1]
        return self.mux.queued_bytes[False] + self.t.buffer_bytes + self.pending_bytes

    def enable(self):
        t, service = self.t, self.service
        ordinary = cw.decode_packet

        def decode(wire, floor, encapsulation="udp"):
            if not isinstance(wire, SelectedBody):
                return ordinary(wire, floor, encapsulation)
            end, _, data = parse_row(wire, floor, cw.GLOBAL_WINDOW)
            if len(data) > cw.SYMBOL_BYTES:
                raise ValueError("oversized coded payload")
            return cw.ReceivedPacket("repair", end-1, data.ljust(cw.SYMBOL_BYTES, b"\x00"),
                                     end-GROUP, end, end//GROUP, row_seed(end))

        for module in (cw, receiver):
            self.restore.append((module, module.decode_packet))
            module.decode_packet = decode

        price = service._service_us
        def price_row(wire):
            if not isinstance(wire, SelectedBody):
                return price(wire)
            fields = ("support_positions", "pivot_probes", "sparse_coefficient_updates")
            gf_count = service.work["logical_gf_payload_bytes"]
            meta_count = sum(service.work[k] for k in fields)
            measured = price(wire)
            gf = service.work["logical_gf_payload_bytes"] - gf_count
            metadata = sum(service.work[k] for k in fields) - meta_count
            assert gf % cw.SYMBOL_BYTES == 0
            extra = 2 * (gf // cw.SYMBOL_BYTES)
            service.work["logical_gf_payload_bytes"] += extra
            self.counts["length_field_GF_bytes"] += extra
            return measured + service.cost.charge(gf + extra, metadata) - service.cost.charge(gf, metadata)

        service._service_us = price_row
        original_source = t._aligned_source

        def seal(payload):
            original_source(payload)
            end = len(t.sources)
            source_id_bytes = max(1, ((end - 1).bit_length() + 6) // 7)
            self.gate.earn_first(OUTER + 1 + source_id_bytes + t.sources[-1].size)
            if end % GROUP:
                return
            self.counts["opportunities"] += 1
            if not self.gate.enabled:
                self.counts["closed"] += 1
                return
            extent = max(s.size for s in t.sources[-GROUP:])
            ip_size = OUTER + 1 + len(end_bytes(end)) + 2 + extent
            queued = self.backlog()
            if t.base >= end or not self.gate.reserve_row(ip_size, queued):
                self.counts["refused_backlog" if queued > 12000 else "refused_credit_or_scope"] += 1
                return
            bodies = [p[:s.size] for p,s in zip(t.source_payloads[-GROUP:], t.sources[-GROUP:])]
            body = SelectedBody(row_bytes(end, bodies))
            assert ip_size == OUTER + len(body)
            t.sim.send(False, ip_size, "near_repair", lambda: t._receive_wire(body))
            self.counts["sent"] += 1
            self.counts["sent_ip_bytes"] += ip_size

        t._aligned_source = seal

        def bucket(index):
            backlog = self.backlog()
            accepted = self.gate.accepted
            self.gate.close_bucket(backlog)
            self.buckets.append((index, accepted, backlog, self.gate.enabled, self.counts["sent"]))
            t.sim.at((index+1)/10, bucket, index+1)

        t.sim.at(0.1, bucket, 1)
        for at, name in ((2, "warm"), (12, "cut"), (47.999, "late")):
            t.sim.at(at, self.snapshot, name)

    def snapshot(self, name):
        self.snapshots[name] = dict(counts=dict(self.counts), work=dict(self.service.work))

    def finish(self):
        for module, original in self.restore:
            module.decode_packet = original
        return dict(counts=dict(self.counts), snapshots=self.snapshots,
                    buckets=self.buckets, bucket_fields=["index", "accepted_ip_bytes",
                    "ordinary_backlog", "enabled_after_bucket", "near_emitted_total"])
