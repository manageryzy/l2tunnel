"""Passive per-group paid/received timeline; it is never consulted by the sender or receiver."""
from collections import Counter, deque
from dataclasses import dataclass, field
from math import ceil


@dataclass(slots=True)
class Timeline:
    admitted: float
    fresh_open: list = field(default_factory=list)
    fresh_member_ages: list = field(default_factory=list)
    prior_repair: int = 0
    fresh_after_repair: int = 0
    fresh_after_confirm: int = 0
    first_paid: float | None = None
    last_fresh_paid: float | None = None
    first_spare_paid: float | None = None
    first_name_paid: float | None = None
    first_repair_paid: float | None = None
    decoded: float | None = None
    confirmed: float | None = None
    tcp_decoded: float | None = None
    threshold_paid: float | None = None
    tcp_acked: float | None = None
    rx_ordered: float | None = None
    ack_issued: float | None = None
    blocked_by: int | None = None


def quantiles(xs):
    xs.sort()
    return dict(n=len(xs), p50=xs[(len(xs)-1)//2], p99=xs[ceil(len(xs)*.99)-1]) if xs else dict(n=0)


class TimelineAudit:
    def __init__(self, cfg, measured):
        self.cfg, self.measured = cfg, measured
        self.rows = [{}, {}]
        self.segment = {}
        self.tcp_outstanding = deque()
        self.rx_pending = deque()
        self.ack_pending = deque()
        self.rx_prefix_bytes = 0
        self.rack_context = False
        self.rack = Counter()
        self.examples = []

    def submit(self, reverse, gid, data, now):
        self.rows[reverse][gid] = Timeline(now)
        if len(data) < 40 or data[9] != 6:
            return
        tcp = data[4*(data[0]&15):]
        if reverse:
            self.advance(self.ack_pending, int.from_bytes(tcp[8:12], 'big'), now, 'ack_issued')
            return
        seq = int.from_bytes(tcp[4:8], 'big')
        previous = self.segment.setdefault(seq, gid)
        if previous == gid:
            size = len(tcp) - 4 * (tcp[12] >> 4)
            if size > 0:
                for pending in (self.tcp_outstanding, self.rx_pending, self.ack_pending):
                    pending.append((seq + size, gid))
        if previous==gid or not self.rack_context or not self.measured[0]<=now<self.measured[1]:
            return
        row = self.rows[False][previous]
        opened = sum(t<=now for t in row.fresh_open)
        self.rack['native_retransmissions'] += 1
        self.rack['first_round_under_k_at_trigger'] += opened<self.cfg.k
        self.rack['native_still_undecoded_at_trigger'] += row.decoded is None
        self.rack['decoded_but_no_tcp_ack_at_trigger'] += row.decoded is not None
        if len(self.examples)<8:
            self.examples.append(dict(original_group=previous,tcp_seq=seq,trigger_s=now,
                                      fresh_open_at_trigger=opened,decoded_s=row.decoded))

    def opening(self, reverse, data, now, paid_at):
        if reverse or len(data) < 40 or data[9] != 6:
            return
        start = 4*(data[0] & 15)
        seq = int.from_bytes(data[start + 4:start + 8], 'big')
        row = self.rows[0][self.segment[seq]]
        if row.tcp_decoded is None:
            row.tcp_decoded, row.threshold_paid = now, paid_at
            if seq > self.rx_prefix_bytes:
                row.blocked_by = self.segment.get(self.rx_prefix_bytes)

    def ack_progress(self, cumulative_bytes, now):
        self.advance(self.tcp_outstanding, cumulative_bytes, now, 'tcp_acked')

    def receiver_progress(self, cumulative_bytes, now):
        self.rx_prefix_bytes = cumulative_bytes
        self.advance(self.rx_pending, cumulative_bytes, now, 'rx_ordered')

    def advance(self, queue, cumulative_bytes, now, field):
        while queue and queue[0][0] <= cumulative_bytes:
            _, gid = queue.popleft()
            setattr(self.rows[0][gid], field, now)

    def paid(self, reverse, role, gid, ordinal, now, delivered_at):
        row=self.rows[reverse][gid]
        if role=='fresh':
            row.fresh_member_ages.append(1000*(now-row.admitted))
            row.fresh_after_repair += bool(row.prior_repair & (1 << ordinal))
            row.fresh_after_confirm += row.confirmed is not None
            if row.first_paid is None:
                row.first_paid=now
            row.last_fresh_paid=now
            if delivered_at is not None:
                row.fresh_open.append(delivered_at)
        elif role=='spare' and row.first_spare_paid is None:
            row.first_spare_paid=now
        elif role in ('named','named_copy') and row.first_repair_paid is None:
            row.first_repair_paid=now
        if role not in ('fresh', 'spare'):
            row.prior_repair |= 1 << ordinal

    def report(self, reverse):
        rows=[z for z in self.rows[reverse].values() if self.measured[0]<=z.admitted<self.measured[1]]
        def delays(start, end):
            return quantiles([(getattr(z,end)-getattr(z,start))*1000 for z in rows
                              if getattr(z,start) is not None and getattr(z,end) is not None])
        tail = sorted((z for z in rows if z.tcp_acked is not None and z.ack_issued is not None),
                      key=lambda z: z.tcp_acked-z.tcp_decoded, reverse=True)
        tail = tail[:ceil(len(tail)*.01)]
        sums = {name: 1000*sum(getattr(z,b)-getattr(z,a) for z in tail)
                for name,a,b in (('await_contiguous', 'tcp_decoded','rx_ordered'),
                                 ('await_ack_issue','rx_ordered','ack_issued'),
                                 ('await_ack_transport','ack_issued','tcp_acked'))}
        blockers = {z.blocked_by for z in tail if z.blocked_by is not None}
        member_ages = [age for z in rows for age in z.fresh_member_ages]
        return dict(native_groups=len(rows), first_pass_below_k=sum(len(z.fresh_open)<self.cfg.k for z in rows),
                    admission_to_each_fresh_payment_ms=quantiles(member_ages),
                    max_fresh_member_age_ms=max(member_ages, default=None),
                    fresh_paid_after_same_ordinal_repair=sum(z.fresh_after_repair for z in rows),
                    fresh_paid_after_logical_ack=sum(z.fresh_after_confirm for z in rows),
                    slowest_one_percent_open_to_sender_ack=dict(
                        segments=len(tail), opened_ahead_of_tcp_prefix=sum(z.blocked_by is not None for z in tail),
                        distinct_first_blockers=len(blockers), first_blockers_fresh_below_k=sum(
                            len(self.rows[0][gid].fresh_open)<self.cfg.k for gid in blockers),
                        summed_segment_ms=sums),
                    admission_to_first_paid_ms=delays('admitted','first_paid'),
                    first_to_last_fresh_paid_ms=delays('first_paid','last_fresh_paid'),
                    last_fresh_to_first_spare_paid_ms=delays('last_fresh_paid','first_spare_paid'),
                    admission_to_first_name_paid_ms=delays('admitted','first_name_paid'),
                    first_name_to_first_repair_paid_ms=delays('first_name_paid','first_repair_paid'),
                    admission_to_decode_ms=delays('admitted','decoded'),
                    kth_serialized_to_sender_tcp_ack_ms=delays('threshold_paid','tcp_acked'),
                    kth_open_to_sender_tcp_ack_ms=delays('tcp_decoded','tcp_acked'),
                    kth_open_to_tcp_ordered_ms=delays('tcp_decoded','rx_ordered'),
                    tcp_ordered_to_first_cumulative_ack_issue_ms=delays('rx_ordered','ack_issued'),
                    first_cumulative_ack_issue_to_sender_accept_ms=delays('ack_issued','tcp_acked'),
                    decode_to_logical_confirm_ms=delays('decoded','confirmed'))

