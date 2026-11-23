"""Bounded single-session physical-path transport for offline IPv4 TCP experiments."""
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field, replace
from itertools import groupby
from math import ceil
from random import Random

from . import multipath_wire as wire
from .model import Erasures
from .path_arq import PathArq
from .path_paced import PacedService
from .path_service import SharedService
from .path_spare import SpareService
from .path_timeline import TimelineAudit
from .packed_spare import OUTER


@dataclass(frozen=True)
class PathConfig:
    n: int
    k: int
    mtu: tuple
    hold_us: tuple
    delay_ms: tuple
    ack_us: int = 1000
    gap_us: int = 1000
    repeat_us: int = 70000
    quiet_us: int = 140000
    group_window: int = 8192
    ack_count: int = 16
    group_ack_count: int = 16
    group_ack_us: int = 1000
    proactive: bool = False
    rank_requests: bool = False
    spare_fraction: float = .25
    spare_deadline_us: int = 12000
    spare_spacing_us: int = 750
    loss_rates: tuple | None = None
    early_forward: bool = False
    max_entries: tuple | None = None
    a3_request_copies: int = 1
    a3_reply_copies: int = 1
    physical_recovery: bool = False
    physical_window: int = 256
    physical_reorder_packets: int = 3
    physical_rto_us: int = 90000
    shared_pending: bool = False
    link_ethernet: bool = False
    paced_recovery: bool = False

    def __post_init__(self):
        if self.paced_recovery and (not self.shared_pending or not self.link_ethernet or self.physical_rto_us != 90000):
            raise ValueError("paced recovery requires shared pending, Ethernet accounting and a 90 ms initial RTO")
        if self.shared_pending and not self.physical_recovery:
            raise ValueError("shared pending service requires per-path recovery")
        if not 1 <= self.physical_reorder_packets <= self.physical_window <= 256 or self.physical_rto_us <= 0:
            raise ValueError("invalid per-path recovery limits")
        for copies in (self.a3_request_copies, self.a3_reply_copies):
            if type(copies) is not int or not 1 <= copies <= self.n or (copies > 1 and not self.rank_requests):
                raise ValueError("A3 copies require distinct negotiated physical paths and rank-specific requests")
        if (not 1 <= self.k <= self.n <= 255 or
                (self.max_entries is not None and
                 (len(self.max_entries) != self.n or any(type(v) is not int or not 1 <= v <= 255 for v in self.max_entries))) or
                any(len(v) != self.n for v in (self.mtu, self.hold_us, self.delay_ms)) or
                any(v < 256 or v > 65535 for v in self.mtu) or any(v <= 0 for v in self.hold_us) or
                any(v < 0 for v in self.delay_ms) or
                not 0 < self.spare_fraction <= 1 or (self.early_forward and not self.proactive) or
                (self.loss_rates is not None and (len(self.loss_rates) != 2 or
                                                 any(not 0 <= rate <= 1 for rate in self.loss_rates))) or
                min(self.ack_us, self.gap_us, self.repeat_us, self.quiet_us, self.group_window,
                    self.ack_count, self.group_ack_count, self.group_ack_us, self.spare_deadline_us, self.spare_spacing_us) <= 0):
            raise ValueError("invalid physical-path experiment configuration")


def intervals(values, maximum=8):
    result = []
    for _, run in groupby(enumerate(sorted(values)), key=lambda pair: pair[1] - pair[0]):
        first = last = next(run)[1]
        for _, last in run:
            pass
        result.append((first, last + 1))
        if len(result) == maximum:
            break
    return result


class ReceiptWindow:
    """Only physical receipt history may forget old packet numbers."""

    def __init__(self):
        self.floor = self.next = 0
        self.seen = set()
        self.dirty = set()
        self.cursor = 0
        self.repeat = {}

    def observe(self, pn):
        if pn < self.next:
            return
        if pn >= self.floor + 256:
            self.floor = pn - 255
            self.next = max(self.next, self.floor)
            self.seen = {old for old in self.seen if old >= self.next}
            self.dirty.intersection_update(self.seen)
            self.repeat = {old: due for old, due in self.repeat.items() if old >= self.floor}
        self.seen.add(pn)
        self.dirty.add(pn)
        while self.next in self.seen:
            self.seen.remove(self.next)
            self.dirty.discard(self.next)
            self.next += 1

    def page(self, now=None):
        # A repeatedly observed non-cumulative PN dirties its entire connected
        # run. Wrap by run end so a newly joined span crossing the cursor stays whole.
        spans = [span for span in intervals(self.seen, 256)
                 if any(pn in self.dirty or (now is not None and self.repeat.get(pn) is not None
                        and self.repeat[pn] <= now) for pn in range(*span))]
        pivot = max(self.cursor, self.next)
        ordered = [s for s in spans if s[1] > pivot] + [s for s in spans if s[1] <= pivot]
        selected = ordered[:8]
        resume = selected[-1][1] if len(ordered) > len(selected) else None
        return tuple(sorted(selected)), resume

    def reported(self, spans, resume):
        for lo, hi in spans:
            self.dirty.difference_update(range(lo, hi))
        self.cursor = self.next if resume is None else resume

    def repeat_deadline(self):
        return min((due for due in self.repeat.values() if due is not None), default=None)

    def positive_paid(self, floor, nxt, spans, now):
        for pn, due in self.repeat.items():
            if (due is not None and due <= now and (floor <= pn < nxt
                    or any(lo <= pn < hi for lo, hi in spans))):
                self.repeat[pn] = None
        for lo, hi in spans:
            for pn in range(max(lo, self.floor), hi):
                self.repeat.setdefault(pn, now+.008)


@dataclass
class Lane:
    entries: list = field(default_factory=list)
    entry_bytes: int = 0
    roles: list = field(default_factory=list)
    unreported: int = 0
    ack_due: float | None = None
    prepared_ack: tuple | None = None
    deadline: float | None = None
    opened_at: float | None = None
    ready: tuple | None = None
    closed: bool = False
    next_pn: int = 0
    control_pn: int = 0
    receipts: ReceiptWindow = field(default_factory=ReceiptWindow)
    counts: Counter = field(default_factory=Counter)
    sent_unobserved: dict = field(default_factory=dict)

    def take_open(self):
        packet = self.entries, self.roles
        self.entries, self.roles = [], []
        self.deadline = self.opened_at = None
        self.entry_bytes = 0
        self.closed = False
        return packet


@dataclass
class Custody:
    parts: tuple
    last_sent: float
    born: float
    repair_rounds: int = 0
    paid_fresh: int = 0
    recent_named: dict = field(default_factory=dict)
    last_paid: float | None = None
    last_quiet: float | None = None


class Direction:
    """Sender and receiver interact only via datagrams paid on the duplex link."""

    def __init__(self, network, reverse, deliver):
        self.net, self.reverse, self.deliver = network, reverse, deliver
        self.sim, self.cfg = network.flow, network.cfg
        self.lanes = [Lane() for _ in range(self.cfg.n)]
        self.arq = tuple(PathArq(self, i) for i in range(self.cfg.n)) if self.cfg.physical_recovery else ()
        self.service = (PacedService(self) if self.cfg.paced_recovery else
                        SharedService(self) if self.cfg.shared_pending else None)
        self.next_group = self.tx_prefix = 0
        self.tx = OrderedDict()
        self.waiting = deque()
        self.quiet_at = None
        self.rx_prefix = self.horizon = 0
        self.rx_complete = set()
        self.rx_parts = {}
        self.gap_due = {}
        self.request_rounds = {}
        self.gap_at = self.ack_at = None
        self.repeat_at = None
        self.dirty_lanes = {}
        self.group_ack_due = None
        self.group_ack_cursor = 0
        self.claimed_group_cursor = 0
        self.group_ack_rescan = False
        self.newly_completed = 0
        self.control_lane = 0
        self.spare = SpareService(self) if self.cfg.proactive else None
        self.counts = Counter()

    @property
    def peer(self):
        return self.net.directions[not self.reverse]

    def submit(self, payload):
        if self.next_group - self.tx_prefix >= self.cfg.group_window:
            if len(self.waiting) >= self.cfg.group_window:
                raise RuntimeError("multipath native admission queue overflow")
            self.waiting.append(payload)
            self.counts["queued_native"] += 1
            return
        gid = self.next_group
        self.next_group += 1
        if self.spare:
            self.spare.offer(self.sim.now, len(payload))
        if self.net.audit:
            self.net.audit.submit(self.reverse, gid, payload, self.sim.now)
        parts = wire.shards(payload, self.cfg.n, self.cfg.k)
        self.tx[gid] = Custody(parts, self.sim.now, self.sim.now)
        self.counts["admitted_native"] += 1
        self.counts["admitted_native_bytes"] += len(payload)
        self.counts["peak_custody"] = max(self.counts["peak_custody"], len(self.tx))
        for ordinal, part in enumerate(parts):
            self.enqueue(ordinal, (gid, ordinal, part), "fresh")

    def enqueue(self, path, entry, role):
        if self.service:
            return self.service.push(path, entry[:2], role)
        if self.arq:
            self.arq[path].submit(entry, role)
        else:
            self.enqueue_now(path, entry, role)
        return path

    def enqueue_now(self, path, entry, role):
        lane = self.lanes[path]
        limit = self.cfg.mtu[path] - OUTER
        # Only the DATA prefix depends on the physical packet number. Entry
        # extents are immutable even if a full head forces a new packet.
        pn = lane.next_pn + int(lane.ready is not None)
        prefix = 3 + len(wire.put_integer(pn))
        extra = len(wire.encode_data(path, pn, [entry])) - prefix
        expired_before_turn = lane.entries and self.sim.now > lane.opened_at and self.sim.now >= lane.deadline
        if lane.entries and (lane.closed or expired_before_turn or prefix + lane.entry_bytes + extra > limit):
            if self.service:
                if lane.ready is not None:
                    return False
                lane.ready = lane.take_open()
            else:
                self.flush(path)
            prefix = 3 + len(wire.put_integer(lane.next_pn + int(lane.ready is not None)))
        if prefix + extra > limit:
            raise ValueError("single shard exceeds physical path payload budget")
        due = self.sim.now + self.cfg.hold_us[path] / 1e6
        if role == "fresh" and (group := self.tx.get(entry[0])) is not None:
            due = min(due, group.born + self.cfg.hold_us[entry[1]] / 1e6)
        if not lane.entries:
            lane.opened_at = self.sim.now
        if lane.deadline is None or due < lane.deadline:
            lane.deadline = due
            self.sim.at(max(self.sim.now, due), self.flush_at, path, due)
        lane.counts["fresh_shard_bytes" if role == "fresh" else "repair_shard_bytes"] += len(entry[2])
        lane.entries.append(entry)
        lane.roles.append(role)
        lane.entry_bytes += extra
        max_entries = self.cfg.max_entries[path] if self.cfg.max_entries is not None else 255
        if len(lane.entries) == max_entries or limit - prefix - lane.entry_bytes < 3:
            if self.service:
                lane.closed = True
            else:
                self.flush(path)
        return True

    def flush_at(self, path, deadline):
        if self.lanes[path].deadline == deadline:
            if self.service:
                self.service.kick(path)
            else:
                self.flush(path)

    def flush(self, path):
        lane = self.lanes[path]
        if not lane.entries and lane.ready is None:
            return False
        if self.arq and not self.arq[path].credit():
            if lane.deadline is not None:
                lane.deadline = min(lane.deadline, self.sim.now)
            return False
        if lane.ready is None:
            entries, roles = lane.take_open()
        else:
            entries, roles = lane.ready
            lane.ready = None
        if self.service:
            kept = []
            for entry, role in zip(entries, roles):
                gid, ordinal, _ = entry
                if gid not in self.tx or (role == "physical" and self.service.covered(path, gid, ordinal)):
                    self.service.finish(self.service.token(path, (gid, ordinal), role))
                else:
                    kept.append((entry, role))
            if not kept:
                return False
            entries, roles = zip(*kept)
        elif self.arq and "physical" in roles:
            kept = [(entry, role) for entry, role in zip(entries, roles)
                    if role != "physical" or (entry[0] in self.tx and
                        not self.arq[path].covered.get(entry[0], 0) & (1 << entry[1]))]
            if not kept:
                return False
            entries, roles = zip(*kept)
        self.pay(path, entries, roles)
        return True

    def pay(self, path, entries, roles, piggyback=True):
        lane = self.lanes[path]
        payload = wire.encode_data(path, lane.next_pn, entries)
        ack, reported = self.peer.pending_ack() if piggyback else (b"", ())
        repeat_payment = None
        if ack:
            combined = wire.encode_data(path, lane.next_pn, entries, ack)
            if len(combined) + OUTER <= self.cfg.mtu[path]:
                payload = combined
                self.peer.ack_sent(reported)
                repeat_payment = reported
                self.counts["piggyback_ack_packets"] += 1
                self.counts["piggyback_ack_bytes"] += len(ack)
        kind = "spare" if roles[0] == "spare" else "with_repair" if any(r != "fresh" for r in roles) else "fresh"
        if self.cfg.paced_recovery:
            self.service.freeze(path, lane.next_pn, entries, roles)
            self.service.freeze_wire(len(payload)+OUTER, self.pay_data, path, entries, roles, kind, payload, repeat_payment)
            self.service.kick()
            return
        self.pay_data(path, entries, roles, kind, payload)

    def pay_data(self, path, entries, roles, kind, payload, repeat_payment=None):
        lane = self.lanes[path]
        if repeat_payment is not None:
            self.peer.positive_page_paid(repeat_payment)
        lane.counts["data_packets"] += 1
        lane.counts["entries"] += len(entries)
        if len(entries) > 1:
            lane.counts["aggregates"] += 1
        if self.arq:
            self.arq[path].reserve(lane.next_pn, len(payload)+OUTER, entries)
            if self.service and not self.cfg.paced_recovery:
                self.service.freeze(path, lane.next_pn, entries, roles)
        else:
            lane.sent_unobserved[lane.next_pn] = len(payload) + OUTER
        if len(lane.sent_unobserved) > self.cfg.group_window:
            oldest = next(iter(lane.sent_unobserved))
            del lane.sent_unobserved[oldest]
            lane.counts["physical_history_expirations"] += 1
        lane.next_pn += 1
        prefix_bytes = 3 + len(wire.put_integer(lane.next_pn - 1))
        meta = [(entry[0], role, len(wire.encode_data(path, lane.next_pn-1, [entry])) - prefix_bytes
                 if role in ("named_copy", "physical") else 0, entry[1]) for entry, role in zip(entries, roles)]
        paid = self.net.send(self.reverse, path, kind, payload, meta)
        for gid, _, _, _ in meta:
            group = self.tx.get(gid)
            if group:
                group.last_sent = max(group.last_sent, paid)

    def received(self, kind, physical_path, payload):
        if kind in ("shard_request", "shard_request_copy"):
            for gid, ordinals in wire.decode_shard_request(payload, self.cfg.n):
                self.peer.repair(gid, ordinals)
            return
        if kind == "request":
            for gid in wire.decode_request(payload):
                self.peer.repair(gid)
            return
        if kind == "ack":
            self.peer.acknowledged(wire.decode_ack(payload))
            return
        path, pn, entries, feedback = wire.decode_packet(payload)
        if path != physical_path:
            raise ValueError("path association mismatch")
        if feedback:
            self.peer.acknowledged(wire.decode_ack(feedback))
        lane = self.lanes[path]
        lane.receipts.observe(pn)
        lane.unreported += 1
        if lane.ack_due is None:
            lane.ack_due = self.sim.now + self.cfg.ack_us / 1e6
        self.dirty_lanes[path] = True
        for gid, ordinal, part in entries:
            self.take_shard(gid, ordinal, part, physical_path)
        urgent = lane.unreported >= self.cfg.ack_count or self.newly_completed >= self.cfg.group_ack_count
        if urgent:
            self.counts["count_triggered_ack_flushes"] += 1
            self.flush_ack(None)
        else:
            self.arm_ack()

    def take_shard(self, gid, ordinal, part, physical_path):
        if gid < self.rx_prefix or gid in self.rx_complete:
            return
        if gid >= self.rx_prefix + self.cfg.group_window:
            raise ValueError("sender exceeded negotiated group window")
        due = self.sim.now + self.cfg.gap_us / 1e6
        observed_new = gid >= self.horizon
        for new in range(self.horizon, gid + 1):
            self.gap_due[new] = due
        self.horizon = max(self.horizon, gid + 1)
        if observed_new and (self.gap_at is None or due < self.gap_at):
            self.gap_at = due
            self.sim.at(due, self.request, due)
        parts = self.rx_parts.setdefault(gid, {})
        parts.setdefault(ordinal, part)
        if len(parts) != self.cfg.k:
            return
        data = wire.recover(self.cfg.n, self.cfg.k, wire.shard_length(part), parts)
        del self.rx_parts[gid]
        del self.gap_due[gid]
        self.request_rounds.pop(gid, None)
        self.rx_complete.add(gid)
        if gid < max(self.group_ack_cursor, self.claimed_group_cursor):
            self.group_ack_rescan = True
        while self.rx_prefix in self.rx_complete:
            self.rx_complete.remove(self.rx_prefix)
            self.rx_prefix += 1
        if self.net.audit:
            self.net.audit.rows[self.reverse][gid].decoded = self.sim.now
            self.net.audit.opening(self.reverse, data, self.sim.now,
                                   self.sim.now - self.cfg.delay_ms[physical_path]/1000)
        self.newly_completed += 1
        if self.group_ack_due is None:
            self.group_ack_due = self.sim.now + self.cfg.group_ack_us / 1e6
        self.counts["groups_recovered"] += 1
        self.deliver(data)

    def pending_ack(self):
        if not self.dirty_lanes and self.group_ack_due is None:
            return b"", ()
        paths = sorted(self.dirty_lanes, key=lambda p: (self.physical_ack_due(p), p))[:4]
        blocks = []
        payments = []
        for path in sorted(paths):
            lane = self.lanes[path]
            r = lane.receipts
            if lane.prepared_ack is None:
                selected, resume = r.page(self.sim.now if self.cfg.paced_recovery else None)
                snapshot = (path, r.floor, r.next, selected, resume)
                if self.cfg.paced_recovery:
                    due = self.sim.now if lane.unreported >= self.cfg.ack_count else lane.ack_due
                    lane.prepared_ack = snapshot, due
                    self.reserve_physical_ack(path, selected, resume)
                    self.dirty_lanes[path] = True
            else:
                snapshot, _ = lane.prepared_ack
            blocks.append(snapshot[:4])
            payments.append(snapshot)
        spans = intervals((g for g in self.rx_complete if g >= self.group_ack_cursor), maximum=9)
        continuation = spans[8][0] if len(spans) > 8 else None
        blocks.append((255, 0, self.rx_prefix, spans[:8]))
        return wire.encode_ack(blocks), (payments, continuation)

    def ack_sent(self, receipt):
        payments, continuation = receipt
        if self.cfg.paced_recovery:
            self.claimed_group_cursor = continuation or 0
            self.group_ack_due = None
        else:
            for path, _, _, spans, resume in payments:
                self.reserve_physical_ack(path, spans, resume)
            self.group_ack_cursor = continuation or 0
            self.group_ack_due = (self.sim.now + self.cfg.group_ack_us / 1e6
                                  if continuation is not None or self.group_ack_rescan else None)
            if continuation is None:
                self.group_ack_rescan = False
        self.newly_completed = 0
        self.ack_at = None
        self.arm_ack()

    def reserve_physical_ack(self, path, spans, resume):
        lane = self.lanes[path]
        lane.receipts.reported(spans, resume)
        if resume is None:
            self.dirty_lanes.pop(path,None)
            lane.unreported = 0
            lane.ack_due = None
        else:
            lane.unreported = 1
            lane.ack_due = self.sim.now

    def physical_ack_due(self, path):
        lane = self.lanes[path]
        if lane.prepared_ack is None:
            return lane.ack_due
        _, due = lane.prepared_ack
        return due if lane.ack_due is None else min(due,lane.ack_due)

    def positive_page_paid(self, receipt):
        continuation = receipt[1]
        self.group_ack_cursor = continuation or 0
        self.claimed_group_cursor = 0
        if (continuation is not None or self.group_ack_rescan) and self.group_ack_due is None:
            self.group_ack_due = self.sim.now + self.cfg.group_ack_us/1e6
        if continuation is None:
            self.group_ack_rescan = False
        for path, floor, nxt, spans, _ in receipt[0]:
            lane = self.lanes[path]
            lane.receipts.positive_paid(floor, nxt, spans, self.sim.now)
            lane.prepared_ack = None
            if lane.ack_due is None:
                self.dirty_lanes.pop(path,None)
        self.ack_at = None
        self.arm_ack()
        due = min((t for lane in self.lanes if (t := lane.receipts.repeat_deadline()) is not None), default=None)
        if due is not None:
            due = max(due, self.sim.now)
            if self.repeat_at is None or due < self.repeat_at:
                self.repeat_at = due
                self.sim.at(due, self.repeat_ready, due)

    def repeat_ready(self, scheduled):
        if scheduled != self.repeat_at:
            return
        self.repeat_at = None
        future = []
        for path, lane in enumerate(self.lanes):
            due = lane.receipts.repeat_deadline()
            if due is not None and due <= self.sim.now:
                lane.ack_due = min(lane.ack_due, due) if lane.ack_due is not None else due
                self.dirty_lanes[path] = True
            elif due is not None:
                future.append(due)
        if future:
            self.repeat_at = min(future)
            self.sim.at(self.repeat_at, self.repeat_ready, self.repeat_at)
        self.arm_ack()

    def arm_ack(self):
        due = [self.physical_ack_due(p) for p in self.dirty_lanes]
        if self.group_ack_due is not None:
            due.append(self.group_ack_due)
        if due and (self.ack_at is None or min(due) < self.ack_at):
            self.ack_at = min(due)
            self.sim.at(max(self.sim.now,self.ack_at), self.flush_ack, self.ack_at)

    def ack_ready(self):
        return (self.newly_completed >= self.cfg.group_ack_count
                or (self.group_ack_due is not None and self.group_ack_due <= self.sim.now)
                or any(self.lanes[p].unreported >= self.cfg.ack_count or self.physical_ack_due(p) <= self.sim.now
                       for p in self.dirty_lanes))

    def flush_ack(self, deadline):
        if deadline is not None and self.ack_at != deadline:
            return
        if deadline is not None:
            self.counts["deadline_triggered_ack_flushes"] += 1
        if self.peer.service:
            self.peer.service.standalone_due = True
            self.peer.service.kick()
            return
        while self.dirty_lanes or self.group_ack_due is not None:
            ack, paths = self.pending_ack()
            self.peer.control("ack", ack)
            self.ack_sent(paths)
            if not self.dirty_lanes:
                break

    def control(self, kind, payload):
        if self.service:
            self.service.control(kind, payload)
            return
        self.control_now(kind, payload)

    def control_now(self, kind, payload, receipt=None, path=None):
        if path is None:
            path = self.control_lane % self.cfg.n
            self.control_lane += 1
        if self.cfg.paced_recovery:
            if receipt is not None:
                self.peer.ack_sent(receipt)
            self.service.freeze_wire(len(payload)+OUTER, self.pay_control, path, kind, payload, receipt)
            self.service.kick()
            return
        self.pay_control(path, kind, payload, receipt)

    def pay_control(self, path, kind, payload, receipt):
        if receipt is not None:
            self.peer.positive_page_paid(receipt)
        self.lanes[path].control_pn += 1
        self.net.send(self.reverse, path, kind, payload)

    def acknowledged(self, blocks):
        released = set()
        updated_paths = set()
        for path, floor, nxt, spans in blocks:
            if path != 255:
                if self.arq:
                    self.arq[path].acknowledge(floor, nxt, spans)
                    updated_paths.add(path)
                    self.counts["physical_ack_blocks"] += 1
                    continue
                lane = self.lanes[path]
                for pn in list(lane.sent_unobserved):
                    if pn < floor:
                        lane.counts["retired_unobserved_packets"] += 1
                    elif pn < nxt or any(lo <= pn < hi for lo, hi in spans):
                        lane.counts["physically_confirmed_ip_bytes"] += lane.sent_unobserved[pn]
                    else:
                        continue
                    del lane.sent_unobserved[pn]
                self.counts["physical_ack_blocks"] += 1
                continue
            if floor != 0 or nxt > self.next_group:
                raise ValueError("invalid logical confirmation")
            for gid in range(self.tx_prefix, nxt):
                if self.confirm(gid):
                    released.add(gid)
            self.tx_prefix = max(self.tx_prefix, nxt)
            for lo, hi in spans:
                if hi > self.next_group:
                    raise ValueError("confirmation beyond sender horizon")
                for gid in range(max(lo, self.tx_prefix), hi):
                    if self.confirm(gid):
                        released.add(gid)
            if self.arq and released:
                if self.service:
                    self.service.retired(released)
                for arq in self.arq:
                    arq.retired(released)
                updated_paths.update(range(self.cfg.n))
            while self.waiting and self.next_group - self.tx_prefix < self.cfg.group_window:
                self.submit(self.waiting.popleft())
            self.arm_quiet()
        for path in sorted(updated_paths):
            self.arq[path].drain()

    def confirm(self, gid):
        group = self.tx.pop(gid, None)
        if group and self.net.audit:
            self.net.audit.rows[self.reverse][gid].confirmed = self.sim.now
        return group is not None

    def request(self, deadline, building=False):
        if self.gap_at != deadline:
            return
        if self.cfg.paced_recovery and not building:
            self.peer.service.request_due = True
            self.peer.service.kick()
            return
        self.gap_at = None
        now = self.sim.now
        ids = [gid for gid, at in self.gap_due.items() if at <= now]
        if self.cfg.paced_recovery:
            ids = ids[:32]
        for start in range(0, len(ids), 32):
            batch = ids[start:start + 32]
            if self.cfg.rank_requests:
                rows = []
                for gid in batch:
                    known = self.rx_parts.get(gid, {})
                    wanted = self.cfg.k - len(known)
                    turn = self.request_rounds.get(gid, 0)
                    missing = ((turn + i) % self.cfg.n for i in range(self.cfg.n))
                    ordinals = tuple(i for i in missing if i not in known)[:wanted]
                    self.request_rounds[gid] = (turn + wanted) % self.cfg.n
                    rows.append((gid, ordinals))
                request = wire.encode_shard_request(rows, self.cfg.n)
                self.peer.control("shard_request", request)
                for _ in range(1, self.cfg.a3_request_copies):
                    self.peer.control("shard_request_copy", request)
                self.counts["named_ordinals"] += sum(len(row[1]) for row in rows)
            else:
                self.peer.control("request", wire.encode_request(batch))
            self.counts["named_ids"] += len(batch)
            for gid in batch:
                self.gap_due[gid] = now + self.cfg.repeat_us / 1e6
        if self.gap_due:
            self.gap_at = min(self.gap_due.values())
            self.sim.at(max(now, self.gap_at), self.request, self.gap_at)

    def repair(self, gid, ordinals=None, role="named"):
        group = self.tx.get(gid)
        if group is None:
            return
        start = group.repair_rounds % self.cfg.n
        copies = self.cfg.a3_reply_copies if ordinals is not None else 1
        if ordinals is None:
            ordinals = tuple((start + i) % self.cfg.n for i in range(self.cfg.k))
        else:
            # Identical masks from reordered control packets cannot reserve another
            # copy while local service is queued or inside half a retry period.
            ready = tuple(i for i in ordinals if group.recent_named.get(i, 0) <= self.sim.now)
            self.counts["suppressed_named_ordinals"] += len(ordinals) - len(ready)
            if not ready:
                return
            ordinals = ready
            for i in ordinals:
                group.recent_named[i] = max(self.sim.now, group.last_sent) + self.cfg.repeat_us / 2e6
        group.repair_rounds += 1
        group.last_sent = max(group.last_sent, self.sim.now)
        for ordinal in ordinals:
            first = (ordinal + group.repair_rounds) % self.cfg.n
            for copy in range(copies):
                path = (first + copy) % self.cfg.n
                self.counts["repair_shards"] += 1
                selected = self.enqueue(path, (gid, ordinal, group.parts[ordinal]), "named_copy" if copy else role)
                if not copy:
                    first = selected

    def quiet_deadline(self):
        group = next(iter(self.tx.values()), None)
        if group is None or group.last_paid is None:
            return None
        # A slow lane can keep a requested repair unpaid. Permit the next
        # rotation after one quiet period while keeping every actual charge.
        return max(group.last_paid, group.last_quiet or 0) + self.cfg.quiet_us / 1e6

    def arm_quiet(self):
        due = self.quiet_deadline()
        if due is None:
            self.quiet_at = None
        elif self.quiet_at is None or due < self.quiet_at:
            self.quiet_at = max(due, self.sim.now)
            self.sim.at(self.quiet_at, self.quiet, self.quiet_at)

    def quiet(self, scheduled):
        if self.quiet_at != scheduled:
            return
        self.quiet_at = None
        due = self.quiet_deadline()
        if due is not None and due <= self.sim.now:
            gid = next(iter(self.tx))
            self.tx[gid].last_quiet = self.sim.now
            self.counts["quiet_repairs"] += 1
            self.repair(gid, role="quiet")
        self.arm_quiet()


class PathNetwork:
    """Distinct physical path erasures and IDs behind one serialization budget per direction."""

    def __init__(self, flow, cfg, seed, deliver, measured=None):
        self.flow, self.cfg = flow, cfg
        self.audit = TimelineAudit(cfg, measured) if measured is not None else None
        seed_rng = Random(seed)
        rates = cfg.loss_rates or (flow.scenario.loss_rate,)*2
        self.loss = [[Erasures(replace(flow.scenario, loss_rate=rate), Random(seed_rng.getrandbits(64)))
                      for _ in range(cfg.n)] for rate in rates]
        self.directions = tuple(Direction(self, d, deliver[d]) for d in (False, True))
        self.totals = [Counter(), Counter()]
        self.measured = measured
        self.socket_delays = [Counter(), Counter()]

    def socket_delay_report(self, reverse):
        hist = self.socket_delays[reverse]
        count = sum(hist.values())
        report = {"packets": count, "scope": "UDP/IP submission to serialization end, by steady submission time"}
        cumulative = 0
        for upper_us, n in sorted(hist.items()):
            cumulative += n
            for percentile in (50, 99, 100):
                if cumulative * 100 >= percentile * count:
                    report.setdefault(f"p{percentile}_upper_us", upper_us)
        return report

    def send(self, reverse, path, kind, payload, meta=()):
        size = len(payload) + OUTER
        if size > self.cfg.mtu[path]:
            raise ValueError(f"physical UDP/IP datagram exceeds path {path} MTU: {size}")
        link = self.flow.links[reverse][0]
        wire_size = size + (14 if self.cfg.link_ethernet else 0)
        arrival = link.finish(self.flow.now, wire_size)
        link.free_at = arrival
        link.reserved_bytes += wire_size
        if self.cfg.link_ethernet:
            counts = self.totals[reverse]
            counts["socket_submitted_ip_bytes"] += size
            counts["socket_submitted_ethernet_bytes"] += wire_size
            counts["socket_submitted_packets"] += 1
            counts["socket_to_serialization_peak_us"] = max(
                counts["socket_to_serialization_peak_us"], round((arrival-self.flow.now)*1e6))
            if self.measured is None or self.measured[0] <= self.flow.now < self.measured[1]:
                wait = ceil((arrival - self.flow.now) * 1e6)
                unit = 10 if wait < 2000 else 100 if wait < 100000 else 1000
                self.socket_delays[reverse][((wait + unit - 1) // unit) * unit] += 1
        if self.cfg.paced_recovery and meta:
            if kind == "spare":
                self.directions[reverse].spare.socket_paid(wire_size)
            self.record_data_payment(reverse, path, payload, meta, self.flow.now)
        args = (self.flow.now,) if self.cfg.paced_recovery else ()
        self.flow.at(arrival, self.depart, reverse, path, kind, payload, size, meta, *args)
        return self.flow.now if self.cfg.paced_recovery else arrival

    def record_data_payment(self, reverse, path, payload, meta, now):
        direction = self.directions[reverse]
        if direction.arq:
            packet_number, _ = wire.read_integer(payload, 2, wire.MAX - 1)
            direction.arq[path].paid(packet_number, now)
            if direction.service:
                direction.service.paid(path, packet_number)
        for gid, role, _, _ in meta:
            group = direction.tx.get(gid)
            if group is not None:
                group.last_paid = now
                if role == "fresh" and direction.spare:
                    group.paid_fresh += 1
                    if group.paid_fresh == self.cfg.n:
                        direction.spare.schedule(gid, now)
        direction.arm_quiet()

    def depart(self, reverse, path, kind, payload, size, meta, submitted=None):
        self.flow.wire[reverse][kind] += size
        self.flow.datagrams[reverse][kind] += 1
        counts = self.totals[reverse]
        counts[kind + "_ip_bytes"] += size
        counts[kind + "_packets"] += 1
        lane = self.directions[reverse].lanes[path]
        lane.counts["departed_ip"] += size
        direction = self.directions[reverse]
        now = self.flow.now
        if meta:
            counts["paid_data_entries"] += len(meta)
            repaired = sum(role == "physical" for _, role, _, _ in meta)
            if repaired:
                counts["physical_repair_bearing_packets"] += 1
                counts["physical_repair_bearing_bytes"] += size
                lane.counts["physical_repair_paid_shards"] += repaired
                if repaired == len(meta):
                    counts["physical_repair_only_packet_bytes"] += size
        lost = self.loss[reverse][path].lost()
        if self.cfg.link_ethernet:
            counts["serialized_ethernet_bytes"] += size + 14
            if lost:
                counts["erased_after_serialization_ethernet_bytes"] += size + 14
                counts["erased_after_serialization_ip_bytes"] += size
        arrives = now + self.cfg.delay_ms[path]/1000
        if direction.spare:
            direction.spare.observe_paid(now, size + direction.spare.l2_bytes)
            if self.cfg.paced_recovery and kind == "spare":
                direction.spare.serialized(now)
        paid_at = submitted if self.cfg.paced_recovery else now
        if meta and not self.cfg.paced_recovery:
            self.record_data_payment(reverse, path, payload, meta, now)
        for gid, role, copy_charge, ordinal in meta:
            if role == "physical":
                counts["physical_repair_paid_entry_bytes"] += copy_charge
                counts["physical_repair_paid_shards"] += 1
            elif copy_charge:
                counts["a3_reply_copy_paid_entry_bytes"] += copy_charge
                counts["a3_reply_copy_paid_shards"] += 1
            if self.audit:
                self.audit.paid(reverse, role, gid, ordinal, paid_at, None if lost else arrives)
        if self.audit and kind in ("request", "shard_request", "shard_request_copy"):
            ids = (wire.decode_request(payload) if kind == "request" else
                   (gid for gid, _ in wire.decode_shard_request(payload, self.cfg.n)))
            for gid in ids:
                row = self.audit.rows[not reverse][gid]
                if row.first_name_paid is None:
                    row.first_name_paid = paid_at
        if lost:
            counts["erased_packets"] += 1
            lane.counts["erasures"] += 1
            return
        self.flow.at(self.flow.now + self.cfg.delay_ms[path] / 1000,
                     self.directions[reverse].received, kind, path, payload)

