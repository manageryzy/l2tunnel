"""Optional local DATA packet accountability for one physical path."""
from collections import Counter, OrderedDict
from dataclasses import dataclass
from .path_paced import PhysicalRtt


@dataclass
class Payment:
    keys: tuple
    size: int
    paid: float | None = None
    active: bool = True


class PathArq:
    def __init__(self, direction, path):
        self.d = direction
        self.path = path
        self.window = direction.cfg.physical_window
        self.rto = direction.cfg.physical_rto_us / 1e6
        self.rtt = PhysicalRtt() if direction.cfg.paced_recovery else None
        self.threshold = direction.cfg.physical_reorder_packets
        self.packets = OrderedDict()
        self.active = 0
        self.inflight = Counter()
        self.waiting = OrderedDict()
        self.repairs = OrderedDict()
        self.covered = {}
        self.paid_end = 0
        self.highest_positive = []
        self.due = None
        self.stats = direction.lanes[path].counts

    def credit(self):
        return self.active < self.window

    def submit(self, entry, role):
        if self.credit() and not self.waiting and not self.repairs:
            self.d.enqueue_now(self.path, entry, role)
        else:
            self.waiting.setdefault(entry[:2], role)
            self.drain()

    def reserve(self, pn, size, entries):
        if not self.credit():
            raise RuntimeError("physical DATA credit exceeded")
        if len(self.packets) == self.window:
            oldest_alias = next(i for i, packet in self.packets.items() if not packet.active)
            del self.packets[oldest_alias]
        keys = tuple(dict.fromkeys(e[:2] for e in entries))
        self.packets[pn] = Payment(keys, size)
        self.active += 1
        self.inflight.update(keys)
        self.stats["peak_physical_pn_records"] = max(self.stats["peak_physical_pn_records"], len(self.packets))

    def paid(self, pn, now):
        self.paid_end = max(self.paid_end, pn + 1)
        if self.rtt:
            self.rtt.sent(pn, int(now*1e6+1e-7))
        packet = self.packets.get(pn)
        if packet is not None and packet.active:
            packet.paid = now
            if all(gid not in self.d.tx for gid, _ in packet.keys):
                self.detach(packet)
                self.stats["physical_retired_by_logical_delivery"] += 1
                del self.packets[pn]
                self.drain()
            self.arm()

    def detach(self, packet):
        self.active -= 1
        packet.active = False
        for key in packet.keys:
            self.inflight[key] -= 1
            if not self.inflight[key]:
                del self.inflight[key]

    def missing(self, pn, reason):
        packet = self.packets[pn]
        self.detach(packet)
        self.stats["physical_loss_" + reason] += 1
        for gid, ordinal in packet.keys:
            key = gid, ordinal
            if (gid in self.d.tx and key not in self.inflight and
                    not self.covered.get(gid, 0) & (1 << ordinal)):
                if self.d.service:
                    self.d.service.push(self.path, key, "physical")
                else:
                    self.repairs[key] = "physical"
        if reason == "floor":
            del self.packets[pn]

    def acknowledge(self, floor, nxt, ranges):
        if max([nxt, *(hi for _, hi in ranges)]) > self.paid_end:
            raise ValueError("physical ACK exceeds the actually paid path horizon")
        if self.rtt:
            sample = self.rtt.observe(floor, nxt, ranges, int(self.d.sim.now*1e6+1e-7))
            if sample is not None:
                self.stats["physical_rtt_samples"] += 1
                self.stats["physical_rtt_sum_us"] += sample
                self.stats["physical_last_srtt_us"] = self.rtt.srtt
                self.stats["physical_last_rto_us"] = self.rtt.rto
                self.rto = self.rtt.rto/1e6
        highest = set(self.highest_positive)
        for lo, hi in ((floor, nxt), *ranges):
            highest.update(range(max(lo, hi-self.threshold), hi))
        self.highest_positive = sorted(highest, reverse=True)[:self.threshold]
        for pn, packet in list(self.packets.items()):
            if packet.paid is None:
                continue
            if pn < floor:
                if packet.active:
                    self.missing(pn, "floor")
                else:
                    del self.packets[pn]
            elif pn < nxt or any(lo <= pn < hi for lo, hi in ranges):
                if packet.active:
                    self.detach(packet)
                else:
                    self.stats["physical_late_alias_acks"] += 1
                self.stats["physically_confirmed_ip_bytes"] += packet.size
                for gid, ordinal in packet.keys:
                    if gid in self.d.tx:
                        self.covered[gid] = self.covered.get(gid, 0) | (1 << ordinal)
                    self.repairs.pop((gid, ordinal), None)
                del self.packets[pn]
            elif (packet.active and len(self.highest_positive) == self.threshold
                  and pn < self.highest_positive[-1]):
                self.missing(pn, "sack")
        self.arm()

    def arm(self):
        deadline = min((p.paid+self.rto for p in self.packets.values()
                        if p.active and p.paid is not None), default=None)
        if deadline is not None:
            deadline = max(self.d.sim.now, deadline)
        if deadline is None:
            self.due = None
        elif self.due is None or deadline < self.due:
            self.due = deadline
            self.d.sim.at(deadline, self.timeout, deadline)

    def timeout(self, scheduled):
        if self.due != scheduled:
            return
        self.due = None
        now = self.d.sim.now
        for pn, p in list(self.packets.items()):
            if p.active and p.paid is not None and p.paid + self.rto <= now:
                self.missing(pn, "timeout")
        self.drain()
        self.arm()

    def retired(self, gids):
        for gid in gids:
            self.covered.pop(gid, None)
        for pn, p in list(self.packets.items()):
            if p.paid is not None and all(gid not in self.d.tx for gid, _ in p.keys):
                if p.active:
                    self.detach(p)
                    self.stats["physical_retired_by_logical_delivery"] += 1
                del self.packets[pn]
        # All deferred references are bounded by live group and ordinal. Discard
        # retired ones even if a full or blocked path cannot drain this turn.
        for queue in (self.waiting, self.repairs):
            for key in list(queue):
                if key[0] in gids:
                    del queue[key]
        self.arm()

    def drain(self):
        if self.d.service:
            self.d.service.kick(self.path)
            return
        lane = self.d.lanes[self.path]
        if (self.credit() and lane.deadline is not None and lane.opened_at < self.d.sim.now
                and lane.deadline <= self.d.sim.now):
            self.d.flush(self.path)
        while self.credit() and (self.repairs or self.waiting):
            queue = self.repairs if self.repairs else self.waiting
            (gid, ordinal), role = queue.popitem(last=False)
            group = self.d.tx.get(gid)
            if group is None:
                continue
            if role == "physical" and self.covered.get(gid, 0) & (1 << ordinal):
                continue
            self.d.enqueue_now(self.path, (gid, ordinal, group.parts[ordinal]), role)
