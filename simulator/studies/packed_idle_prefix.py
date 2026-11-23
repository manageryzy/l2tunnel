"""Optional sender-causal 1 ms XOR for the first 64 KiB of C48 first-source IP."""

from collections import Counter

from l2tunnel_sim.aggregate_ack import _decode_bounded_varint
from l2tunnel_sim.compact_wire import GLOBAL_WINDOW, SYMBOL_BYTES
from l2tunnel_sim.packed_spare import GROUP, MTU
from packed_startup_groups import GroupRow, encode_equation, row_columns


CAP = 64 * 1024
IDLE = .001


def decode_columns(wire, floor):
    end, _ = _decode_bounded_varint(wire, 1, 2**32 - 1)
    width = end % GROUP
    if not 2 <= width <= 7:
        raise ValueError("idle XOR must cover a contiguous two-to-seven source prefix")
    _, columns = row_columns(wire, width, 1, floor)
    return end, columns


class IdlePrefix:
    def __init__(self, owner, selection):
        if selection not in ("historical-control", "historical-idle", "startup-control", "startup-idle"):
            raise ValueError("unknown C48 idle-prefix selection")
        self.owner = owner
        self.t = owner.t
        self.selection = selection
        self.startup = selection.startswith("startup-")
        self.enabled = selection.endswith("-idle")
        self.last_accepted = -1
        self.last_departed = -1
        self.eligible_end = 0
        self.ip_accepted = 0
        self.used = set()
        self.events = []
        self.recipient = {}
        self.on_wire = {}
        self.counts = Counter()
        self.first_departures = []

    def first_source(self, size, finish):
        """Called below UDP pricing on every forward source socket acceptance."""
        index = len(self.t.sources) - 1
        if index == self.last_accepted:
            return  # Only the first of the short-source copies earns a token.
        if index != self.last_accepted + 1:
            raise ValueError("nonconsecutive first-source identity")
        self.last_accepted = index
        self.owner.gate.earn_first(size)
        if self.ip_accepted > CAP:
            return
        self.ip_accepted += size
        if self.ip_accepted <= CAP:
            self.eligible_end = index + 1
            self.counts["eligible_first_ip_bytes"] = self.ip_accepted
        # Include the first over-cap departure so it can cancel an old wake.
        self.t.sim.at(finish, self.depart, index)

    def depart(self, index):
        self.last_departed = index
        self.first_departures.append((index, self.t.sim.now))
        width = (index + 1) % GROUP
        if self.enabled and index < self.eligible_end and 2 <= width <= 7:
            self.t.sim.at(self.t.sim.now + IDLE, self.on_idle, index)

    def early_allowed(self, end):
        return self.startup and end <= self.eligible_end

    def group_used(self, start):
        return start in self.used

    def full_row(self, end, size, startup_override):
        if end > self.eligible_end:
            return
        if end-GROUP in self.used:
            raise ValueError("near8 repeated an occupied group")
        self.used.add(end-GROUP)
        self.counts["startup_full_rows"] += 1
        self.counts["startup_full_ip_bytes"] += size
        self.counts["full_gate_overrides"] += int(startup_override)

    def on_idle(self, index):
        if self.last_departed != index:
            return
        end = index + 1
        start = end - end % GROUP
        gate = self.owner.gate
        now = self.t.sim.now
        item = dict(start=start, end=end, sealed_at=now, ordinary_gate=gate.enabled)
        self.events.append(item)
        if self.group_used(start):
            item["status"] = "group_used"
            return
        if not gate.enabled and not self.early_allowed(end):
            item["status"] = "gate_closed"
            return
        # Source membership comes solely from completed first transmissions at
        # this point. There is no receiver prefix, NACK, loss draw or lookahead.
        originals = [(i, self.t.source_payloads[i][:self.t.sources[i].size])
                     for i in range(start, end)]
        wire, size, encoding_us = encode_equation(originals, 0)
        item.update(ip_bytes=size, credit_eighths=gate.credit_eighths)
        if size > MTU or size*8 > gate.credit_eighths:
            item["status"] = "unfunded"
            return
        if self.t.sim.links[False][0].free_at > now or self.owner.backlog() > 8*MTU:
            item["status"] = "ordinary_work"
            return
        # Freeze once funded even if another source is sent before encoding
        # completes. Only charge the actual packet on socket acceptance.
        self.used.add(start)
        item["status"] = "sealed"
        self.t.sim.at(now + encoding_us/1e6, self.emit, wire, item)

    def emit(self, wire, item):
        gate = self.owner.gate
        now = self.t.sim.now
        if self.t.sim.links[False][0].free_at > now or self.owner.backlog() > 8*MTU:
            item["status"] = "ordinary_work_after_seal"
            self.used.remove(item["start"])
            return
        enabled = gate.enabled
        try:
            gate.enabled = enabled or self.early_allowed(item["end"])
            accepted = gate.reserve_row(item["ip_bytes"], self.owner.backlog())
        finally:
            gate.enabled = enabled
        if not accepted:
            item["status"] = "gate_or_credit_changed"
            self.used.remove(item["start"])
            return
        self.on_wire[item["end"]] = item
        def receive():
            item["arrival"] = self.t.sim.now
            self.t._receive_wire(wire)
        finish, _ = self.t.sim.send(False, item["ip_bytes"], "near_repair", receive)
        item.update(status="sent", accepted_at=now, departed_at=finish)
        self.counts["prefix_sent"] += 1
        self.counts["prefix_ip_bytes"] += item["ip_bytes"]

    def install_receiver(self):
        service, t = self.owner.service, self.t
        original_decode, original_cost = service.decode, service._service_us

        def cost(wire):
            if not isinstance(wire, GroupRow):
                return original_cost(wire)
            _, columns = decode_columns(wire, t.received_prefix)
            unknown = {i: 1 for i in columns if i not in t.decoder.known}
            mixes, updates, probes = service.preview(unknown)
            known = len(columns) - len(unknown)
            gf = (known + mixes) * (SYMBOL_BYTES + 2)
            service.work.update(support_positions=len(columns), pivot_probes=probes,
                                sparse_coefficient_updates=updates, known_contributions=known,
                                equation_row_mixes=mixes, logical_gf_payload_bytes=gf, repair_jobs=1)
            return service.cost.charge(gf, len(columns) + probes + updates)

        def decode(wire):
            if not isinstance(wire, GroupRow):
                # Preserve actual source bytes for checking length-protected XOR
                # without borrowing the absent source from the simulation ledger.
                if len(self.recipient) < self.eligible_end:
                    packet = t.decode_data_packet(wire)
                    if packet.kind == "source" and packet.index < self.eligible_end:
                        self.recipient[packet.index] = packet.payload
                return original_decode(wire)
            end, columns = decode_columns(wire, t.received_prefix)
            item = self.on_wire[end]
            unknown = [i for i in columns if i not in t.decoder.known]
            item.update(decode_at=t.sim.now, unknown_on_arrival=unknown)
            if len(unknown) == 1 and all(i in unknown or i in self.recipient for i in columns):
                missing, = unknown
                _, pos = _decode_bounded_varint(wire, 1, 2**32-1)
                rhs = int.from_bytes(wire[pos+1:], "little")
                for i in columns:
                    if i == missing:
                        continue
                    known = self.recipient[i]
                    rhs ^= int.from_bytes(len(known).to_bytes(2, "big") + known, "little")
                decoded = rhs.to_bytes(len(wire)-pos-1, "little")
                length = int.from_bytes(decoded[:2], "big")
                if not 0 < length <= len(decoded)-2 or any(decoded[2+length:]):
                    raise ValueError("invalid recovered length or nonzero padding")
                actual = decoded[2:2+length]
                if actual != t.source_payloads[missing][:t.sources[missing].size]:
                    raise ValueError("length-protected XOR differs from original bytes")
                self.recipient[missing] = actual
                t.wire_received_symbols[missing] = actual.ljust(SYMBOL_BYTES, b"\x00")
                item.update(byte_recovered=missing, known_rank_ledger_inputs=0)
            elif len(unknown) == 1:
                # Ordinary rank-only recoveries have no independently decoded RHS.
                item["rank_only_missing_sibling_bytes"] = [
                    i for i in columns if i not in unknown and i not in self.recipient
                ]
            t._notice(end)
            solved = list(t.decoder.insert(columns))
            item["newly_known"] = solved
            self.counts["rank_solutions_triggered"] += len(solved)
            self.counts["byte_checked_direct_solutions"] += int("byte_recovered" in item)
            t._new_known(solved)
            t._advance()
        service._service_us = cost
        service.decode = decode

    def report(self):
        groups = [e["start"] for e in self.events if e["status"] == "sent"]
        if len(groups) != len(set(groups)):
            raise ValueError("multiple startup rows for one group")
        return dict(selection=self.selection, startup_cap_first_ip_bytes=CAP, idle_ms=IDLE*1000,
                    counts=dict(self.counts), decisions=self.events, first_departures=self.first_departures)
