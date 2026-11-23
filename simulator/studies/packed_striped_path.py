"""Bidirectional mixed-datagram study over the normal Packed MUX and targeted custody."""
from collections import Counter

from l2tunnel_sim.aligned_records import CHANNEL_HEADER, _unsigned_varint
from l2tunnel_sim.compact_wire import ReceivedPacket, encode_source
from l2tunnel_sim.fixed_anchor_ip import CONTEXT
from l2tunnel_sim.packed_spare import OUTER
from l2tunnel_sim.packed_wire import PACKED_CHANNEL, packed_units
from l2tunnel_sim import striped_cauchy
from l2tunnel_sim import striped_split_repair
# Saved uniform-profile diagnostics import these codec entry points from the study.
from l2tunnel_sim.striped_cauchy import Receiver, encode_packets, group_max_wire, inspect_packet, reconstruct_split


class MixedPacket(bytes):
    """Selected authenticated data union, priced with the actual compact body."""


class RecoveryTimer(bytes):
    """Local decoder work, never sent on the physical link."""


class StripedPath:
    def __init__(self, service, geometry, hold_ms=.5, deadline_ms=1):
        self.t, self.service, self.geometry = service.transport, service, geometry
        self.codec = striped_cauchy
        self.net = self.t.sim
        self.deadline = deadline_ms / 1000
        self.hold = hold_ms / 1000
        self.max_wire = self.net.scenario.mtu - OUTER
        # Reserve the largest generation ULEB and ordinal. At the maximum
        # original extent physical bytes after those fields are n*w.
        full_max = geometry.k*((self.max_wire-12)//geometry.n)-2
        split_max = 2*((self.max_wire-19)//2)
        unit_bytes = min(self.t.packing_bytes, full_max, split_max)
        self.t.select_packing_geometry(unit_bytes, self.t.unit_limit)
        self.tx = {}
        self.rx = {}
        self.pending = []
        self.pending_base = None
        self.pending_deadline = None
        self.rx_ends = {}
        self.split_proofs = {}
        self.drained_prefix = 0
        self.ready = []
        self.counts = Counter()
        self.counts["unit_bytes"] = unit_bytes
        self.counts["full_only_unit_bytes"] = geometry.k*((self.max_wire-12)//geometry.n)-2
        self.fair_reverse_probes = False
        self.paid_timers = None
        self.startup_anchor_copy = False
        self.short_prefix_groups = False
        self.protect_split_triples = False
        self.split_triples = {}
        self.probe_rotate_turn = False
        self.probe_cursor = None

    def select_variable_parity(self):
        """Use length-aware one-erasure stripes with the same bounded group deadline."""
        from l2tunnel_sim import striped_xor
        if self.geometry.m != 1 or self.pending or self.tx or self.t.frame_count:
            raise ValueError("variable parity requires an unused one-erasure direction")
        # The extra authenticated total uses two bytes in every ordinary member.
        # Check the worst full group at the longest possible generation identity.
        width = self.t.packing_bytes
        while striped_xor.group_max_wire(2**64-self.geometry.n, [bytes(width)]*self.geometry.n,
                                         self.geometry) > self.max_wire:
            width -= 1
        self.t.select_packing_geometry(width, self.t.unit_limit)
        self.codec = striped_xor
        self.counts["unit_bytes"] = width

    def select_forward_batch(self, unit_bytes, hold_us):
        if self.t.reverse:
            raise ValueError("select a forward batch on the forward mixed path")
        self.select_batch(unit_bytes, hold_us)

    def select_batch(self, unit_bytes, hold_us):
        """Set explicit Packed and FEC bounds before source admission."""
        if self.pending or self.tx or self.t.frame_count:
            raise ValueError("select the mixed batch before source admission")
        if hold_us is not None and (type(hold_us) is not int or not 0 < hold_us <= 2**32-1):
            raise ValueError("forward group hold must be a positive u32 in microseconds")
        if unit_bytes is not None:
            if type(unit_bytes) is not int or not 8 < unit_bytes <= self.t.packing_bytes:
                raise ValueError("forward Packed unit exceeds mixed geometry")
            self.t.select_packing_geometry(unit_bytes, self.t.unit_limit)
            self.counts["unit_bytes"] = unit_bytes
        if hold_us is not None:
            self.hold = hold_us / 1_000_000

    def install(self):
        t, service = self.t, self.service
        ordinary_decode = service.decode
        old_parse = t.decode_data_packet
        old_feedback = t._receive_feedback

        def parse(wire):
            if isinstance(wire, RecoveryTimer):
                raise ValueError("local decoder timer")
            if not isinstance(wire, MixedPacket):
                return old_parse(wire)
            if self.protect_split_triples and wire.startswith(striped_split_repair.TAG):
                member = striped_split_repair.inspect(wire, self.max_wire)
                return ReceivedPacket("source", member.base + member.slot//2, member.source)
            base, g, single, ordinal, body = self.codec.inspect_packet(wire, self.geometry, self.max_wire)
            if single is not None:
                return ReceivedPacket("source", base, reconstruct_split(body, ordinal, single))
            return ReceivedPacket("source", base+ordinal, g.own(body))

        def deliver(index, raw):
            # The ordinary systematic decoder sees the exact reconstructed
            # bytes. This local handoff neither sends nor prices a new packet.
            wire = (b"\x01"+_unsigned_varint(index)+raw if t.c48_union
                    else encode_source(index, raw, t.config.encapsulation))
            previous_prefix = t.received_prefix
            ordinary_decode(wire)
            if self.paid_timers is not None and t.received_prefix != previous_prefix:
                self.paid_timers.prefix_advanced()
            while self.drained_prefix < t.received_prefix:
                self.drained_prefix += 1
                if self.protect_split_triples:
                    self.split_triples.pop(self.drained_prefix-3, None)
                previous = self.rx_ends.pop(self.drained_prefix, None)
                if previous is not None:
                    self.rx.pop(previous, None)
                self.split_proofs.pop(self.drained_prefix - 1 - t.config.block_sources, None)

        def charge(wire):
            base = service.cost.charge(0, 1)
            self.ready = []
            if isinstance(wire, RecoveryTimer):
                group = int.from_bytes(wire, "big")
                receiver = self.rx.get(group)
                if receiver is None:
                    return base
                self.counts["local_recovery_jobs"] += 1
            else:
                if self.protect_split_triples and wire.startswith(striped_split_repair.TAG):
                    member = striped_split_repair.inspect(wire, self.max_wire)
                    end = member.base + 2
                    if end < t.received_prefix:
                        if self.paid_timers is not None:
                            self.paid_timers.accept(end, True)
                        return base
                    if member.base not in self.split_triples:
                        self.split_triples[member.base] = striped_split_repair.Receiver(member)
                    receiver = self.split_triples[member.base]
                    new = receiver.add(member)
                    direct = new.pop(member.slot//2, None)
                    if self.paid_timers is not None:
                        self.paid_timers.accept(end, direct is None and not new)
                    if direct is not None:
                        self.counts["direct_originals"] += 1
                        self.net.at(self.net.now + base/1e6, deliver, member.base+member.slot//2, direct)
                    self.ready = [(member.base+i, source) for i,source in new.items()]
                    self.counts["recovered_originals"] += len(new)
                    self.counts["split_triple_recovered"] += len(new)
                    return service.cost.charge(4*len(member.parity)*len(new), 1)
                group, g, single, ordinal, body = self.codec.inspect_packet(wire, self.geometry, self.max_wire)
                if single is not None:
                    raw = reconstruct_split(body, ordinal, single)
                    previous = self.split_proofs.get(group)
                    if previous is not None and raw != previous:
                        raise ValueError("conflicting striped split datagram")
                    if previous is None and group >= t.received_prefix:
                        self.split_proofs[group] = raw
                        self.net.at(self.net.now + base/1e6, deliver, group, raw)
                        self.counts["direct_originals"] += 1
                        self.counts[f"split_completed_from_ordinal_{ordinal}"] += 1
                    else:
                        self.counts["split_duplicate_datagrams"] += 1
                    if self.paid_timers is not None:
                        self.paid_timers.accept(group, previous is not None or group < t.received_prefix)
                    return base
                if group+g.n <= t.received_prefix:
                    if self.paid_timers is not None:
                        self.paid_timers.accept(group+g.n-1, True)
                    return base
                if group not in self.rx:
                    self.rx[group] = self.codec.Receiver(g)
                    self.rx_ends[group+g.n] = group
                receiver = self.rx[group]
                if receiver.geometry != g:
                    raise ValueError("conflicting striped group shape")
                original = receiver.add(ordinal, body)
                if self.paid_timers is not None:
                    self.paid_timers.accept(group+g.n-1, original is None)
                if original is not None:
                    self.net.at(self.net.now + base/1e6, deliver, group+ordinal, original)
                    self.counts["direct_originals"] += 1
                if len(receiver.packets) < g.k or len(receiver.originals) == g.n:
                    return base
                if len(receiver.packets) == g.k and original is not None:
                    self.net.at(self.net.now + self.deadline, self.on_deadline, group)
                if all(i in receiver.packets for i in range(max(receiver.packets))):
                    return base
            before = receiver.scaled_bytes
            recovered = receiver.recover_missing()
            self.ready = [(group+i, raw) for i, raw in recovered.items()]
            work = receiver.scaled_bytes - before
            self.counts["recovered_originals"] += len(recovered)
            self.counts["gf_scaled_bytes"] += work
            return service.cost.charge(work, 1)

        def commit(_wire):
            for index, raw in self.ready:
                deliver(index, raw)
            self.ready = []
            # Arrival order may differ, so retire this generation only when its
            # contiguous native source range has actually passed the frontier.
            if isinstance(_wire, RecoveryTimer):
                base = int.from_bytes(_wire, "big")
            elif self.protect_split_triples and _wire.startswith(striped_split_repair.TAG):
                return
            else:
                base, _, _, _, _ = self.codec.inspect_packet(_wire, self.geometry, self.max_wire)
            self.retire_rx(base)

        def feedback(prefix, deficit):
            old_feedback(prefix, deficit)
            while self.tx:
                oldest = next(iter(self.tx))
                if oldest >= t.base:
                    break
                self.tx.pop(oldest)

        t.decode_data_packet = parse
        service._service_us, service.decode = charge, commit
        t._send_wire, t._resend, t._receive_feedback = self.first, self.retry, feedback
        # Each direction owns its redundancy. Old-hole custody, named feedback
        # and quiet probes remain attached to that direction's normal owner.
        t._repair = lambda tail: None
        t._source_copy_count = lambda payload: 1

    def retire_rx(self, group):
        receiver = self.rx.get(group)
        if receiver is not None and group + receiver.geometry.n <= self.t.received_prefix:
            self.rx.pop(group)

    def needed_for_rank(self, index):
        """Reserve the last m absent ordinals for local recovery in a known group."""
        return self.receiver_needs(index, True)

    def receiver_needs(self, index, residual):
        if index < self.t.received_prefix or index in self.split_proofs:
            return False
        for base in range(index, max(-1, index - self.geometry.n), -1):
            if self.protect_split_triples and index - base < 3:
                triple = self.split_triples.get(base)
                if triple is not None:
                    return index - base not in triple.sources
            receiver = self.rx.get(base)
            if receiver is not None and index < base+receiver.geometry.n:
                if index-base in receiver.packets or len(receiver.packets) >= receiver.geometry.k:
                    return False
                if residual:
                    return sum(i not in receiver.packets for i in range(index-base, receiver.geometry.n)) > receiver.geometry.m
                return True
        return True

    def select_rank_requests(self):
        if self.t.reverse or (self.geometry.k, self.geometry.m) != (10, 2):
            raise ValueError("rank-limited requests require forward 12/10 mixed geometry")
        send = self.t._send_named
        def send_needed(selected):
            ids = [i for i in selected if self.needed_for_rank(i)]
            self.counts["rank_request_candidates"] += len(selected)
            self.counts["rank_request_ids"] += len(ids)
            self.counts["rank_suppressed_ids"] += len(selected) - len(ids)
            # The usual fresh/repeat scheduler still owns every unresolved
            # ID. A lost request or reply can name an eligible ID again.
            send(ids)
        self.t._send_named = send_needed

    def on_deadline(self, group):
        receiver = self.rx.get(group)
        if receiver is None or len(receiver.originals) == receiver.geometry.n:
            self.retire_rx(group)
            return
        if self.service.active and len(self.service.waiting) >= self.service.cost.waiting_slots:
            self.net.at(self.net.now + self.deadline, self.on_deadline, group)
            return
        self.service.receive(RecoveryTimer(group.to_bytes(8, "big")))

    def first(self, wire, kind, header):
        if kind != "source":
            raise ValueError("unexpected ordinary forward packet in striped profile")
        t = self.t
        index = len(t.sources)-1
        if self.pending_deadline is not None and self.net.now >= self.pending_deadline:
            self.seal(self.pending_base)
        # Preserve any selected independent source compression exactly once.
        self.pending.append(wire[header:len(wire)-t.crc_bytes])
        if self.pending_base is None:
            self.pending_base = index
            self.pending_deadline = self.net.now+self.hold
            self.net.at(self.pending_deadline, self.seal, index)
        if len(self.pending) < self.geometry.n:
            return self.net.now, self.net.links[t.reverse][0].rtt
        return self.seal(self.pending_base)

    def seal(self, base):
        if base != self.pending_base:
            return None
        n = len(self.pending)
        originals, self.pending = self.pending, []
        self.pending_deadline = None
        self.pending_base = None
        if n > 1 and self.codec.group_max_wire(base, originals, self.geometry) > self.max_wire:
            if n == self.geometry.n:
                raise ValueError("configured full striped group exceeds MTU")
            self.counts["oversized_short_groups_split"] += 1
            offset = 0
            while offset < n:
                count = 1
                if self.short_prefix_groups:
                    # A longer prefix can fit after a shorter one fails: the
                    # shortening rule changes the ratio of data to parity.
                    for width in range(n-offset, 1, -1):
                        if self.codec.group_max_wire(base+offset, originals[offset:offset+width],
                                                     self.geometry) <= self.max_wire:
                            count = width
                            self.counts["rescued_short_prefixes"] += 1
                            self.counts["rescued_short_sources"] += width
                            break
                if (self.protect_split_triples and count == 1 and n-offset == 3
                        and self.codec.group_max_wire(base+offset+1, originals[offset+1:],
                                                      self.geometry) > self.max_wire):
                    wires = striped_split_repair.encode(base+offset, originals[offset:], self.max_wire)
                    if wires is not None:
                        packets = list(map(MixedPacket, wires))
                        for i in range(3):
                            self.tx[base+offset+i] = packets[2*i:2*i+2]
                        self.counts["split_triples"] += 1
                        self.counts["short_groups"] += 1
                        self.counts["original_bytes_in_groups"] += sum(map(len, originals[offset:]))
                        for slot, packet in enumerate(packets):
                            finish = self.emit(packet, "source")
                            index = base+offset+slot//2
                            if (self.startup_anchor_copy and slot % 2 == 0 and index < 128
                                    and self.contains_complete_anchor(index)):
                                self.net.at(finish[0] + .001, self.copy_startup_anchor, index)
                        return finish
                finish = self.emit_group(base+offset, originals[offset:offset+count])
                offset += count
            return finish
        return self.emit_group(base, originals)

    def emit_group(self, base, originals):
        n = len(originals)
        packets = list(map(MixedPacket, self.codec.encode_packets(base, originals, self.geometry, self.max_wire)))
        if n == 1:
            self.tx[base] = packets
        else:
            for j, packet in enumerate(packets):
                self.tx[base+j] = (packet,)
        self.counts["groups_"+str(n)] += 1
        self.counts["full_groups" if n == self.geometry.n else "short_groups"] += 1
        self.counts["original_bytes_in_groups"] += sum(map(len, originals))
        for ordinal, packet in enumerate(packets):
            finish = self.emit(packet, "source")
            index = base + ordinal
            if (self.startup_anchor_copy and ordinal < n and index < 128
                    and self.contains_complete_anchor(index)):
                # Delay from the first member's serialization end, even if
                # other traffic was already queued at the sender.
                self.net.at(finish[0] + .001, self.copy_startup_anchor, index)
        return finish

    def contains_complete_anchor(self, index):
        # The logical payload precedes any independent source compression.
        payload = self.t.source_payloads[index][:self.t.sources[index].size]
        units = (packed_units(payload, self.t.packing_bytes, fixed_anchor=True)
                 if payload[0] == PACKED_CHANNEL else (payload,))
        return any(unit[CHANNEL_HEADER.size] == CONTEXT for unit in units)

    def copy_startup_anchor(self, index):
        if index in self.tx:
            packet = self.tx[index][0]
            self.emit(packet, "source")
            self.counts["startup_anchor_copies"] += 1
            self.counts["startup_anchor_copy_ip_bytes"] += OUTER + len(packet)

    def emit(self, packet, kind):
        size = OUTER + len(packet)
        if self.protect_split_triples and packet.startswith(striped_split_repair.TAG):
            member = striped_split_repair.inspect(packet, self.max_wire)
            index = member.base + member.slot//2
            data, parity = len(member.source), len(member.parity)
            if member.slot % 2 == 1:
                self.counts[kind+"_split_triple_copy_bytes"] += data
        else:
            base, g, split, ordinal, body = self.codec.inspect_packet(packet, self.geometry, self.max_wire)
            index = base if split is not None else base+ordinal
            data = len(g.own(body))
            parity = g.parity_bytes(body)
        self.counts[kind+"_own_bytes"] += data
        self.counts[kind+"_parity_bytes"] += parity
        self.counts[kind+"_metadata_bytes"] += len(packet)-data-parity
        self.counts[kind+"_outer_bytes"] += OUTER
        self.counts[kind + "_ip_bytes"] += size
        self.counts[kind + "_packets"] += 1
        self.counts["max_ip_bytes"] = max(self.counts["max_ip_bytes"], size)
        sent = self.net.send(self.t.reverse, size, kind, lambda: self.service.receive(packet))
        if self.paid_timers is not None and kind == "source":
            self.net.at(sent[0], self.paid_timers.fresh_paid, index)
        return sent

    def retry(self, index, reason):
        if index not in self.tx:
            self.counts["retry_waiting_for_full_group"] += 1
            return self.net.now
        slot_finish = self.net.now
        if self.fair_reverse_probes and reason == "quiet_probes":
            capacity = OUTER + len(self.tx[index][0])
            index = self.quiet_target(index)
            # A shorter alternative frees real link bytes. Keep the next probe
            # on the original cadence measured from this slot's full departure.
            link = min(self.net.links[self.t.reverse],
                       key=lambda link: link.finish(self.net.now, capacity) + link.rtt / 2)
            slot_finish = link.finish(self.net.now, capacity)
        # One surviving 1+1 half is sufficient to restore a split record.
        packet = self.tx[index][0]
        self.t.targeted_counts[reason] += 1
        self.t.targeted_counts["retry_ip_bytes"] += OUTER + len(packet)
        return max(slot_finish, self.emit(packet, "retry")[0])

    def quiet_target(self, oldest):
        """Use one existing reverse probe slot, with its original physical byte ceiling."""
        oldest_bytes = OUTER + len(self.tx[oldest][0])
        self.counts["quiet_slot_ip_budget"] += oldest_bytes
        # The first slot and at least every other slot protect the oldest debt.
        # Other slots walk the retained, contiguous sealed suffix once per cycle.
        rotate = self.probe_rotate_turn
        self.probe_rotate_turn = not rotate
        candidate = max(oldest + 1, self.probe_cursor or 0)
        if rotate and oldest + 1 in self.tx:
            if candidate not in self.tx:
                candidate = oldest + 1
            self.probe_cursor = candidate + 1
            if len(self.tx[candidate][0]) <= len(self.tx[oldest][0]):
                self.counts["rotated_quiet_probes"] += 1
                return candidate
            self.counts["rotation_exceeded_slot_bytes"] += 1
        return oldest

    def report(self):
        report = dict(k=self.geometry.k, m=self.geometry.m, counts=dict(self.counts),
                    unsealed_sources=len(self.pending), unsealed_original_bytes=sum(map(len, self.pending)),
                    retained_sent_sources=len(self.tx), receiver_live_groups=len(self.rx)+len(self.split_triples),
                    group_hold_ms=self.hold*1000,
                    recovery_deadline_ms=self.deadline*1000, source_count=len(self.t.sources),
                    confirmed_source_prefix=self.t.base)
        if self.codec is not striped_cauchy:
            report["wire_profile"] = "length-aware-one-erasure"
        return report
