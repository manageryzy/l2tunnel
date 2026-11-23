"""Single-flow striped feedback and sender timers, clocked by modeled datagram departures."""
from heapq import heappop, heappush

from l2tunnel_sim.aggregate_ack import _decode_bounded_varint
from l2tunnel_sim.aligned_records import _unsigned_varint
from l2tunnel_sim.packed_spare import OUTER


DELAY = .001
REPEAT = .035
QUIET = .070


def feedback_bytes(serial, prefix, ids):
    """Rust compact feedback under the fixed data-owner context. Prefix is an exclusive count."""
    fields = [serial]
    if prefix:
        fields.append(prefix - 1)
    if ids:
        fields.extend((ids[0],sum(1 << (i-ids[0]) for i in ids)))
    return bytes([0x10 | bool(prefix) | (bool(ids) << 1)]) + b"".join(_unsigned_varint(v) for v in fields)


def parse_feedback(body):
    if not body or body[0] not in (0x11,0x12,0x13):
        raise ValueError("invalid mixed feedback flags")
    limit = (1 << 64) - 1
    serial, pos = _decode_bounded_varint(body,1,limit)
    prefix, ids = 0, ()
    if body[0] & 1:
        last, pos = _decode_bounded_varint(body,pos,limit)
        prefix = last+1
    if body[0] & 2:
        first, pos = _decode_bounded_varint(body,pos,limit)
        mask, pos = _decode_bounded_varint(body,pos,limit)
        if not (mask & 1) or first < prefix or first+mask.bit_length()-1 > limit:
            raise ValueError("invalid mixed feedback bitmap")
        ids = tuple(first+i for i in range(mask.bit_length()) if mask & (1 << i))
    if not serial or pos != len(body):
        raise ValueError("invalid mixed feedback extent or serial")
    return serial,prefix,ids


class PaidTimers:
    def __init__(self, path, residual):
        self.path, self.t, self.net = path, path.t, path.net
        self.residual = residual
        self.cursor, self.sealed = 0, -1
        self.discovery = self.ack_due = self.rx_wake = None
        self.repeat_ack = False
        self.repeats, self.repeat_heap = {}, []
        self.pending_feedback = None
        self.serial = 0
        self.heard = set()
        self.highest_heard = 0
        self.paid_through = -1
        self.quiet = self.tx_wake = None
        self.pending_retry = None
        self.requests = set()
        self.last_named = -1
        self.was_quiet = False
        self.counts = path.counts

    def install(self):
        # Delivery still uses the normal decoder, native callbacks and source
        # custody. This profile takes sole ownership of outer feedback clocks.
        self.t._observe_gap_horizon = lambda end: None
        self.t._schedule_tail = lambda after, generation: None
        self.t.feedback_pending = True
        def skip_ordinary_feedback(generation=None):
            self.t.feedback_events = 0
        self.t._feedback = skip_ordinary_feedback
        self.path.paid_timers = self

    def needs(self, index):
        return self.path.receiver_needs(index, self.residual)

    def accept(self, end, duplicate):
        if duplicate:
            if self.t.received_prefix:
                self.prefix_advanced()
            return
        self.sealed = max(self.sealed, end)
        if self.cursor <= self.sealed and self.discovery is None:
            self.discovery = self.net.now + DELAY
        self.arm_rx()

    def prefix_advanced(self):
        due = self.net.now + DELAY
        self.ack_due = due if self.ack_due is None else min(due, self.ack_due)
        self.repeat_ack = True
        self.arm_rx()

    def first_repeat(self):
        while self.repeat_heap:
            due, index = self.repeat_heap[0]
            if self.repeats.get(index) == due and self.needs(index):
                return due, index
            heappop(self.repeat_heap)
            if self.repeats.get(index) == due:
                del self.repeats[index]
        return None

    def arm_rx(self):
        if self.pending_feedback is not None:
            return
        first = self.first_repeat()
        due = min((t for t in (self.discovery,self.ack_due,first[0] if first else None)
                   if t is not None), default=None)
        if due is not None:
            due = max(due,self.net.now)
            if self.rx_wake is None or due < self.rx_wake:
                self.rx_wake = due
                self.net.at(due,self.wake_rx,due)

    def scan(self):
        now = self.net.now
        first = self.first_repeat()
        if first and first[0] <= now and (self.discovery is None or first[0] <= self.discovery):
            start = first[1]
            due = [i for i in range(start,min(start+64,self.sealed+1))
                   if i in self.repeats and self.repeats[i] <= now]
            for i in due:
                del self.repeats[i]
            return [i for i in due if self.needs(i)]
        if self.discovery is None or self.discovery > now:
            return []
        start = max(self.cursor,self.t.received_prefix)
        self.cursor = min(self.sealed+1,start+64)
        ids = [i for i in range(start,self.cursor) if self.needs(i)]
        self.discovery = (now+(DELAY if ids else 0)) if self.cursor <= self.sealed else None
        return ids

    def wake_rx(self, due):
        if due != self.rx_wake:
            return
        self.rx_wake = None
        if self.pending_feedback is not None:
            return
        names = tuple(self.scan())
        prefix = self.t.received_prefix
        if not names and (not prefix or self.ack_due is None or self.ack_due > self.net.now):
            self.arm_rx()
            return
        self.serial += 1
        message = self.serial, prefix, names
        body = feedback_bytes(*message)
        kind = "mixed_gap_request" if names else "mixed_feedback"
        size = OUTER + len(body)
        finish, _ = self.net.send(not self.t.reverse,size,kind,lambda: self.hear(parse_feedback(body)))
        self.pending_feedback = message
        self.net.at(finish,self.feedback_paid,message,size)

    def feedback_paid(self, message, size):
        assert self.pending_feedback == message
        self.pending_feedback = None
        _, prefix, names = message
        repeat = self.net.now + REPEAT
        for i in names:
            if self.needs(i):
                self.repeats[i] = repeat
                heappush(self.repeat_heap,(repeat,i))
        if prefix and prefix == self.t.received_prefix:
            self.ack_due = repeat if self.repeat_ack else None
            self.repeat_ack = False
        self.counts["paid_feedback_ip_bytes"] += size
        self.counts["paid_named_ids"] += len(names)
        self.counts["paid_named_masks" if names else "paid_cumulative_acks"] += 1
        self.arm_rx()

    def hear(self, message):
        serial, prefix, names = message
        if serial in self.heard or serial+64 <= self.highest_heard:
            return
        self.highest_heard = max(serial,self.highest_heard)
        self.heard = {i for i in self.heard if i+64 > self.highest_heard}
        self.heard.add(serial)
        self.t._receive_feedback(prefix,0)
        self.requests = {i for i in self.requests if i >= self.t.base}
        self.requests.update(i for i in names if self.t.base <= i <= self.paid_through)
        if self.t.base > self.paid_through:
            self.quiet = None
        self.arm_tx()

    def fresh_paid(self, index):
        self.paid_through = max(self.paid_through,index)
        self.quiet = self.net.now + QUIET if self.t.base <= self.paid_through else None
        self.arm_tx()

    def arm_tx(self):
        if self.pending_retry is not None:
            return
        due = self.net.now if self.requests else self.quiet
        if due is not None:
            due = max(due,self.net.now)
            if self.tx_wake is None or due < self.tx_wake:
                self.tx_wake = due
                self.net.at(due,self.wake_tx,due)

    def wake_tx(self,due):
        if self.tx_wake != due:
            return
        self.tx_wake = None
        quiet = self.quiet is not None and self.quiet <= self.net.now and self.t.base <= self.paid_through
        if quiet and (not self.was_quiet or not self.requests):
            index, reason = self.t.base, "quiet_probes"
        elif self.requests:
            index = min((i for i in self.requests if i > self.last_named), default=min(self.requests))
            reason = "requested_retries"
        else:
            self.arm_tx()
            return
        self.pending_retry = index, reason
        finish = self.path.retry(index,reason)
        self.net.at(finish,self.retry_paid,index,reason)

    def retry_paid(self,index,reason):
        assert self.pending_retry == (index,reason)
        self.pending_retry = None
        self.requests.discard(index)
        self.was_quiet = reason == "quiet_probes"
        if self.was_quiet:
            self.quiet = self.net.now + QUIET if self.t.base <= self.paid_through else None
        else:
            self.last_named = index
        self.arm_tx()
