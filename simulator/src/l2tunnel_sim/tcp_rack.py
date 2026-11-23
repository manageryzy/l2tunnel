"""Time-based loss inference for an inner TCP endpoint, using delivered native ACKs."""
from collections import OrderedDict
from math import ceil, floor, inf

from .tcp_sack import Scoreboard


class RackScoreboard(Scoreboard):
    """Linux 6.8 RACK timing with the simulator's existing congestion controller and RTO."""

    def __init__(self, flow, capacity):
        self.flow = flow
        self.pending = OrderedDict()
        self.lost = set()
        self.min_rtt = inf
        self.steps = 1
        self.persistence = 0
        self.delivered = self.last_adjusted = 0
        self.duplicate_segments = self.retransmissions = 0
        self.pending_dsack = False
        self.growth_sacked = 0
        self.rto_recovery_end = 0
        self.armed = None
        super().__init__(capacity, reordering_smss=flow.smss_bytes)

    def reset(self):
        super().reset()
        self.latest = (-inf, -1)
        self.recent_rtt = 0
        self.advanced = False
        self.deadline = None
        self.ack_delivered = 0
        self.ack_advanced = False
        self.growth_segments = 0
        self.end_recovery()
        self.lost.clear()
        # An ordinary RTO invalidates selective delivery evidence (reneging).
        # Rebuild only retained endpoint flight, in transmission-time order.
        self.pending.clear()
        for index, segment in sorted(self.flow.forward.pending.items(), key=lambda row: (row[1].last_sent_at, row[0])):
            self.pending[index] = (segment.last_sent_at, self.delivered, segment.attempts)

    def sent(self, index):
        segment = self.flow.forward.pending[index]
        self.pending.pop(index, None)
        self.pending[index] = (segment.last_sent_at, self.delivered, segment.attempts)
        self.lost.discard(index)
        self.retransmissions += int(segment.attempts > 1)
        if self.prr_window is not None:
            self.prr_out += 1
            self.stats["prr_retries" if segment.attempts > 1 else "prr_originals"] += 1

    def pipe(self, issued):
        return len(self.pending) - len(self.lost)

    def end_recovery(self):
        self.prr_window = None
        self.prr_prior = self.prr_delivered = self.prr_out = 0

    def send_credit(self):
        # Linux sets snd_cwnd to pipe + sndcnt while applying PRR. Keep that
        # temporary send window separate from the controller's reduction target.
        limit = self.prr_window if self.prr_window is not None else floor(self.flow.cwnd)
        return max(0, limit - self.pipe(len(self.flow.sent_times)))

    def update_prr(self, delivered, newly_lost, advanced):
        if delivered <= 0:
            return
        flight = self.pipe(len(self.flow.sent_times))
        target = int(self.flow.ssthresh)
        self.prr_delivered += delivered
        room = target - flight
        if room < 0:
            total = (target * self.prr_delivered + self.prr_prior - 1) // self.prr_prior
            send = total - self.prr_out
        else:
            send = max(self.prr_delivered - self.prr_out, delivered)
            if advanced and not newly_lost:
                send += 1
            send = min(room, send)
        self.prr_window = flight + max(send, int(self.prr_out == 0))

    def observe(self, ack, index, offsets):
        old, prior = self.base, self.sacked
        delivered_before = self.delivered
        had_reordering = self.reordering_seen()
        super().observe(ack, index, offsets)
        shift = self.base - old
        new_selective = self.sacked & ~(prior >> shift)
        new_cumulative = ((1 << shift) - 1) & ~prior
        # Remember ordinary deliveries until cumulative ACK, even if a timeout
        # clears selective trust for retransmission. DSACK bytes never add credit.
        first_cumulative = ((1 << shift) - 1) & ~self.growth_sacked
        self.growth_sacked >>= shift
        first_selective = self.sacked & ~self.growth_sacked
        self.growth_sacked |= self.sacked
        self.growth_segments = 0
        flow = self.flow
        high_reorder_slow_start = self.stats["reordering_segments"] > 3 and flow.cwnd < flow.ssthresh
        if (index >= old and not flow.in_recovery
                and (shift or (high_reorder_slow_start and old >= self.rto_recovery_end))
                and flow.cwnd_limited_for_growth()):
            self.growth_segments = first_cumulative.bit_count() + first_selective.bit_count()
        sample = (-inf, -1)
        prior_delivered = 0
        for cumulative, base, changes in ((False, self.base, new_selective), (True, old, new_cumulative)):
            while changes:
                lowest = changes & -changes
                changes -= lowest
                i = base + lowest.bit_length() - 1
                record = self.pending.pop(i, None)
                if record is None:
                    continue
                at, issued_after, attempts = record
                self.lost.discard(i)
                self.delivered += 1
                if (at, i) > sample:
                    sample, prior_delivered = (at, i), issued_after
                age = self.flow.now - at
                if attempts == 1:
                    self.min_rtt = min(self.min_rtt, age)
                elif age < self.min_rtt or (cumulative and ack.tsecr and
                        0 < (int(at * 1000) - ack.tsecr) % 2**32 < 2**31):
                    # Don't advance on an ambiguous retransmission. For cumulative
                    # ACKs a pre-retry TSecr is additional evidence of the original.
                    continue
                self.latest = max(self.latest, (at, i))
                self.recent_rtt = age
                self.advanced = True
        if ack.dsack:
            lo, hi = ack.ranges[0]
            if hi - lo <= self.flow.traffic.window_bytes:
                duplicates = (hi - lo + self.flow.smss_bytes - 1) // self.flow.smss_bytes
                self.duplicate_segments += duplicates
                if self.duplicate_segments <= self.retransmissions:
                    self.delivered += duplicates
                    if had_reordering:
                        self.pending_dsack = True
        if prior_delivered:
            if prior_delivered < self.last_adjusted:
                self.pending_dsack = False
            if self.pending_dsack:
                self.steps = min(255, self.steps + 1)
                self.last_adjusted = self.delivered
                self.pending_dsack = False
                self.persistence = 16
                self.stats["rack_dsack_step_increases"] += 1
            elif not self.persistence:
                self.steps = 1
        # The old-ACK path can update SACK information but does not call Linux
        # tcp_cong_control again. Repeated service of one ACK must not mint credit.
        self.ack_delivered = self.delivered - delivered_before if index >= old else 0
        self.ack_advanced = shift > 0

    def reordering_seen(self):
        return any(self.stats[key] for key in
                   ("reordering_partial_timestamp", "reordering_cumulative", "reordering_selective"))

    def window(self):
        if not self.reordering_seen() and (self.flow.in_recovery or self.sacked.bit_count() >= self.stats["reordering_segments"]):
            return 0
        return min(self.min_rtt * self.steps / 4, self.flow.srtt or self.min_rtt)

    def service(self, flow, *, recovery_timer=False):
        newly_lost = 0
        if self.advanced:
            self.advanced = False
            newly_lost = self.detect()
        delivered, advanced = self.ack_delivered, self.ack_advanced
        growth, self.growth_segments = self.growth_segments, 0
        self.ack_delivered = 0
        self.ack_advanced = False
        entered = bool(self.lost) and not flow.in_recovery
        if entered:
            flow.tcp_fast_retransmits += 1
            flow.dsack_undo.begin(flow)
            self.prr_prior = max(1, floor(flow.cwnd))
            self.prr_window = self.prr_prior
            self.prr_delivered = self.prr_out = 0
            flow.reduce_window()
            flow.cwnd = min(flow.cwnd, flow.window_limit, flow.ssthresh)
            flow.recover = len(flow.sent_times)
            flow.in_recovery = True
            flow.partial_ack_seen = False
        if not flow.in_recovery:
            # Perform growth after loss detection so the ACK entering recovery
            # feeds PRR only. A SACK-only ACK may consume slow-start room once.
            if growth:
                if advanced:
                    flow.increase_window(growth)
                else:
                    allowance = min(growth, max(0, min(flow.window_limit, flow.ssthresh) - flow.cwnd))
                    flow.cwnd += allowance
                    self.stats["rack_sack_slow_start_segments"] += allowance
            return
        if recovery_timer:
            # tcp_rack_reo_timeout gives one synthetic delivery only when newly
            # detected losses enter recovery. In recovery it uses remaining credit.
            if entered and newly_lost:
                self.update_prr(1, newly_lost, False)
                self.stats["prr_timer_entries"] += 1
        else:
            self.update_prr(delivered, newly_lost, advanced)
        for i in sorted(self.lost)[:self.send_credit()]:
            # A later transmission can itself be lost according to its own
            # timestamp. Release only this proven-lost retry from the scoreboard.
            self.retried &= ~(1 << (i - self.base))
            if (entered and flow.strategy.tcp_partial_timestamp_undo and i == self.base
                    and flow.forward.pending[i].attempts == 1 and not self.retried):
                episode = flow.dsack_undo.episode
                if episode is not None:
                    flow.fast_recovery_checkpoint = (int(flow.now * 1000) & 0xffffffff, episode.cwnd, episode.ssthresh)
            else:
                flow.fast_recovery_checkpoint = None
            flow.transmit_segment(i)
            self.stats["rack_retransmissions"] += 1
            entered = False

    def detect(self):
        now = self.flow.now
        wait = 0
        before = len(self.lost)
        window = self.window()
        for i, (at, _, _) in self.pending.items():
            if (at, i) >= self.latest:
                break
            if i in self.lost:
                continue
            remaining = self.recent_rtt + window - (now - at)
            if remaining <= 1e-12:
                self.lost.add(i)
            else:
                wait = max(wait, remaining)
        # Ubuntu's 1000 Hz kernel rounds the maximum remaining interval plus
        # TCP_TIMEOUT_MIN_US (2 ms) up to a jiffy and bounds it by the RTO.
        self.deadline = now + min(self.flow.rto, ceil((wait + .002) * 1000) / 1000) if wait else None
        if self.deadline is not None and (self.armed is None or self.deadline < self.armed):
            self.arm(self.deadline)
        return len(self.lost) - before

    def arm(self, when):
        self.armed = when
        self.flow.at(when, self.on_timer, when)

    def on_timer(self, scheduled):
        if scheduled != self.armed:
            return
        self.armed = None
        if self.deadline is None:
            return
        if self.deadline > self.flow.now:
            self.arm(self.deadline)
            return
        self.stats["rack_timer_fires"] += 1
        self.advanced = True
        self.service(self.flow, recovery_timer=True)
