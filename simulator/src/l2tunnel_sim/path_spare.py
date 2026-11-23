"""Sender-only, expiring reuse of spare link service by the multipath experiment."""
from collections import deque
from heapq import heappop, heappush

from . import multipath_wire as wire
from .packed_spare import OUTER


class SpareService:
    def __init__(self, direction):
        self.d = direction
        self.cfg = direction.cfg
        self.link = direction.sim.links[direction.reverse][0]
        self.rate = self.link.bytes_per_s * self.cfg.spare_fraction
        self.tokens = self.last = 0
        self.history = deque()
        self.offered = deque()
        self.offered_total = 0
        self.recent = 0
        self.horizon = .010
        self.future = []
        self.ready = [deque() for _ in range(self.cfg.n)]
        self.wake = None
        self.turn = 0
        self.pending = None
        self.l2_bytes = 14 if self.cfg.link_ethernet else 0

    def arm(self, at):
        at = max(self.d.sim.now, at)
        if self.pending is None and (self.wake is None or at < self.wake):
            self.wake = at
            self.d.sim.at(at, self.service, at)

    def observe_paid(self, now, size):
        self.history.append((now, size))
        self.recent += size
        self.expire(now)

    def expire(self, now):
        while self.history and self.history[0][0] <= now-self.horizon:
            self.recent -= self.history.popleft()[1]
        while self.offered and self.offered[0][0] <= now-self.horizon:
            self.offered_total -= self.offered.popleft()[1]

    def offer(self, now, native_size):
        if self.cfg.early_forward and not self.d.reverse:
            self.expire(now)
            self.offered.append((now, native_size))
            self.offered_total += native_size

    def schedule(self, gid, now):
        # Eligibility follows local fresh payment, without knowledge of peer rank or loss.
        until = now + self.cfg.spare_deadline_us / 1e6
        if self.cfg.paced_recovery:
            until = self.d.tx[gid].born + min(12_000, self.cfg.spare_deadline_us) / 1e6
            if now >= until:
                return
        low_load = (self.cfg.early_forward and not self.d.reverse and not self.d.waiting
                    and self.offered_total <= .25*self.link.bytes_per_s*self.horizon
                    and self.recent <= .50*self.link.bytes_per_s*self.horizon)
        waves = self.cfg.n * (2 if low_load else 1)
        if low_load:
            self.d.counts['low_load_forward_groups'] += 1
        for wave in range(waves):
            ordinal = (gid + wave) % self.cfg.n
            path = ((ordinal + 1 + (gid + wave//self.cfg.n) % (self.cfg.n-1)) % self.cfg.n
                    if self.cfg.n > 1 else 0)
            when = now + (wave + 1)*self.cfg.spare_spacing_us/(2e6 if low_load else 1e6)
            if when < until:
                heappush(self.future, (when, gid, path, ordinal, until, wave >= self.cfg.n))
        if self.future:
            self.arm(self.future[0][0])

    def service(self, scheduled):
        if self.wake != scheduled:
            return
        self.wake = None
        if self.pending is not None:
            return
        now = self.d.sim.now
        self.tokens = min(self.rate*self.horizon, self.tokens + self.rate*(now-self.last))
        self.last = now
        self.expire(now)
        while self.future and self.future[0][0] <= now:
            _, gid, path, ordinal, until, extra = heappop(self.future)
            self.ready[path].append((gid, ordinal, until, extra))
        for offset in range(self.cfg.n):
            path = (self.turn + offset) % self.cfg.n
            queue = self.ready[path]
            while queue and (queue[0][2] <= now or queue[0][0] not in self.d.tx or
                             (queue[0][3] and self.offered_total > .25*self.link.bytes_per_s*self.horizon)):
                queue.popleft()
                self.d.counts['spare_expired_or_confirmed_shards'] += 1
            if queue and (not self.d.arq or self.d.arq[path].credit()):
                break
        else:
            upcoming = [q[0][2] for q in self.ready if q]
            if self.future:
                upcoming.append(self.future[0][0])
            if upcoming:
                self.arm(min(upcoming))
            return
        if self.link.free_at > now:
            self.arm(self.link.free_at)
            return
        entries = []
        cost = 0
        deadline = queue[0][2]
        lane = self.d.lanes[path]
        max_entries = self.cfg.max_entries[path] if self.cfg.max_entries is not None else 255
        for gid, ordinal, until, extra in queue:
            group = self.d.tx.get(gid)
            if (len(entries) == max_entries or group is None or until <= now or
                    (extra and self.offered_total > .25*self.link.bytes_per_s*self.horizon)):
                break
            entry = (gid, ordinal, group.parts[ordinal])
            candidate = wire.encode_data(path, lane.next_pn, entries + [entry])
            ip_size = len(candidate) + OUTER
            price = ip_size + self.l2_bytes
            if (ip_size > self.cfg.mtu[path] or price > min(self.rate*self.horizon, .90*self.link.bytes_per_s*self.horizon)
                    or self.link.finish(now, price) > min(deadline, until)):
                break
            entries.append(entry)
            cost = price
            deadline = min(deadline, until)
        if not entries:
            queue.popleft()
            self.d.counts['spare_expired_or_confirmed_shards'] += 1
            self.arm(now+1e-7)
            return
        next_fresh = min((l.deadline for l in self.d.lanes if l.deadline is not None), default=float('inf'))
        if next_fresh <= now + cost/self.link.bytes_per_s:
            self.arm(max(now+1e-7, next_fresh))
            return
        # Both envelope and payload are charged. Reserve no future interval for spare work.
        if self.tokens < cost:
            self.arm(now + max(1e-7, (cost-self.tokens)/self.rate))
            return
        if self.recent + cost > .90 * self.horizon * self.link.bytes_per_s:
            self.arm(self.history[0][0]+self.horizon+1e-7)
            return
        if self.cfg.paced_recovery and not self.d.service.can_spare(cost-self.l2_bytes):
            self.arm(min(deadline, now+max(1e-6, cost/self.link.bytes_per_s)))
            return
        extras = sum(queue.popleft()[3] for _ in entries)
        payment = (cost, len(entries), extras)
        self.turn = (path+1)%self.cfg.n
        if self.cfg.paced_recovery:
            # The shared pacer freezes an eligible head and submits it in its
            # own same-time turn. Only the actual submission spends this quota.
            self.pending = payment
        else:
            self.charge(*payment)
        self.d.pay(path, entries, ['spare']*len(entries), piggyback=False)
        if not self.cfg.paced_recovery:
            self.arm(self.link.free_at)

    def charge(self, cost, count, extras):
        self.tokens -= cost
        self.d.counts["spare_shards"] += count
        self.d.counts["low_load_extra_shards"] += extras
        self.d.counts["spare_paid_wire_bytes"] += cost

    def socket_paid(self, wire_bytes):
        if self.pending is None or self.pending[0] != wire_bytes:
            raise RuntimeError("unmatched spare socket payment")
        self.charge(*self.pending)

    def serialized(self, now):
        self.pending = None
        if self.future or any(self.ready):
            self.arm(now)

