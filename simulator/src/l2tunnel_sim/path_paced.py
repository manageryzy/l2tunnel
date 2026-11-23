"""Aggregate byte pacing and positively acknowledged physical packet RTTs."""
from collections import OrderedDict

from .path_service import SharedService


class PhysicalRtt:
    def __init__(self):
        self.history = OrderedDict()
        self.srtt = None
        self.variation = 0
        self.rto = 90_000

    def sent(self, pn, paid_us):
        self.history[pn] = paid_us
        if len(self.history) > 256:
            self.history.popitem(last=False)

    def observe(self, floor, nxt, spans, now_us):
        candidate = None
        for pn, paid_us in self.history.items():
            if paid_us is not None and (floor <= pn < nxt or any(lo <= pn < hi for lo, hi in spans)):
                candidate = paid_us
                self.history[pn] = None
        if candidate is None:
            return None
        sample = max(1, now_us-candidate)
        if self.srtt is None:
            self.srtt = sample
            self.variation = (sample+1)//2
        else:
            self.variation = (3*self.variation+abs(self.srtt-sample)+2)//4
            self.srtt = (7*self.srtt+sample+4)//8
        self.rto = min(500_000, max(90_000, self.srtt+max(4*self.variation, 1_000)))
        return sample


class WirePacer:
    """Credit is held in millionths of a byte. Only a successful pay consumes it."""

    def __init__(self, rate, mtu):
        self.rate = rate
        self.cap = (mtu+14)*1_000_000
        self.credit = self.cap
        self.last = 0

    def due(self, now, ip_bytes):
        cost = (ip_bytes+14)*1_000_000
        if cost > self.cap:
            raise ValueError("physical datagram exceeds aggregate burst capacity")
        self.credit = min(self.cap, self.credit + (now-self.last)*self.rate)
        self.last = now
        deficit = max(0, cost-self.credit)
        return now + (deficit+self.rate-1)//self.rate

    def pay(self, now, ip_bytes):
        if self.due(now, ip_bytes) != now:
            raise RuntimeError("physical payment exceeds available aggregate credit")
        self.credit -= (ip_bytes+14)*1_000_000


class PacedService(SharedService):
    def __init__(self, direction):
        super().__init__(direction)
        self.pacer = WirePacer(round(direction.sim.links[direction.reverse][0].bytes_per_s), max(direction.cfg.mtu))
        self.chosen = None
        self.wake_at = None
        self.class_cursor = 0
        self.path_cursors = [0,0,0]
        self.request_due = False
        self.wait_started = None

    def clock_us(self):
        return int(self.d.sim.now*1e6 + 1e-7)

    def freeze_wire(self, size, action, *args):
        if self.chosen is not None:
            raise RuntimeError("another selected physical datagram is waiting")
        self.chosen = size, action, args

    def can_spare(self, price):
        return (self.chosen is None and not self.requests and not self.request_due and not self.standalone_due
                and not any(self.runnable(p) for p in range(self.d.cfg.n))
                and self.pacer.due(self.clock_us(), price) == self.clock_us())

    def kick(self, path=None):
        if self.running:
            return
        if self.chosen:
            when = max(self.d.sim.now, self.pacer.due(self.clock_us(), self.chosen[0])/1e6)
        elif (self.requests or self.request_due or self.standalone_due or
              (self.runnable(path) if path is not None else any(self.runnable(i) for i in range(self.d.cfg.n)))):
            when = self.d.sim.now
        else:
            return
        if self.wake_at is None or when < self.wake_at:
            self.wake_at = when
            self.d.sim.at(when, self.drive_at, when)

    def select(self):
        for offset in range(3):
            which = (self.class_cursor+offset)%3
            path = self.path_cursors[which]
            if which == 0:
                receiver = self.d.peer
                if self.standalone_due:
                    self.standalone_due = False
                    if receiver.ack_ready():
                        ack, snapshot = receiver.pending_ack()
                        self.d.control_now("ack", ack, snapshot, path)
            elif which == 1:
                if not self.requests and self.request_due:
                    self.request_due = False
                    receiver = self.d.peer
                    receiver.request(receiver.gap_at, building=True)
                if self.requests:
                    self.d.control_now(*self.requests.popleft(), path=path)
            else:
                for i in range(self.d.cfg.n):
                    path = (self.path_cursors[which]+i)%self.d.cfg.n
                    if self.runnable(path) and self.visit(path):
                        break
            if self.chosen is not None:
                self.path_cursors[which] = (path+1)%self.d.cfg.n
                self.class_cursor = (which+1)%3
                return

    def drive_at(self, when):
        if when != self.wake_at:
            return
        self.wake_at = None
        self.running = True
        for _ in range(16*self.d.cfg.n):
            if self.chosen is None:
                self.select()
            if self.chosen is None:
                break
            size, action, args = self.chosen
            now = self.clock_us()
            if self.pacer.due(now, size) > now:
                if self.wait_started is None:
                    self.wait_started = now
                    self.d.counts["pacing_credit_deferrals"] += 1
                break
            self.pacer.pay(now, size)
            if self.wait_started is not None:
                self.d.counts["pacing_credit_wait_us"] += now-self.wait_started
                self.wait_started = None
            self.chosen = None
            action(*args)
            self.d.counts["paced_datagrams"] += 1
            self.d.counts["paced_ethernet_bytes"] += size+14
            if self.d.peer.ack_ready():
                self.standalone_due = True
        self.running = False
        self.kick()

