"""Direct IPv4 TCP packet model with CUBIC or Reno and NewReno recovery.

Congestion avoidance follows RFC 5681 or RFC 9438. Cumulative ACK recovery
follows RFC 6582. RTT estimation, Karn sampling and timeout backoff follow
RFC 6298 and RFC 7323 timestamp echoing, with a configurable minimum RTO. Simulation starts
with an established connection. Units for congestion windows are segments.
"""

from dataclasses import dataclass, field, replace
from math import cbrt, floor

from .model import Simulation
from .tcp_paws import LinuxDataPAWS


IP_TCP_BYTES = 52  # IPv4, TCP, and timestamp options.
ETHERNET_BYTES = 14


def partial_ack_predates_retry(previous_ack, ack, recovery_edge, retry_ts, echoed_ts):
    """Use unwrapped sequence edges and the sender's 32-bit millisecond wire timestamps."""
    if not previous_ack < ack < recovery_edge or not retry_ts or not echoed_ts:
        return False
    return 0 < (retry_ts - echoed_ts) % (1 << 32) < (1 << 31)


@dataclass
class EndpointStats:
    pending: dict = field(default_factory=dict)
    pending_bytes: int = 0
    peak_pending_bytes: int = 0
    peak_reorder_bytes: int = 0
    delivered_bytes: int = 0
    delivered_during_measurement_bytes: int = 0
    delays: list = field(default_factory=list)
    recovered_symbols: int = 0


@dataclass
class Segment:
    last_sent_at: float = 0.0
    attempts: int = 0


class PlainTCP(Simulation):
    def __init__(self, scenario, traffic, paths, strategy, seed):
        if strategy.tcp_path >= len(paths):
            raise ValueError("TCP path index out of range")
        payload = min(traffic.payload_bytes, scenario.mtu - IP_TCP_BYTES)
        traffic = replace(traffic, payload_bytes=payload)
        super().__init__(scenario, traffic, paths, strategy, seed)
        # Initialize all path RNGs before selecting a route, retaining the same
        # random stream as the corresponding route in the tunnel experiment.
        self.links = [[direction[strategy.tcp_path]] for direction in self.links]
        self.window_limit = traffic.window_bytes // payload
        self.cwnd = float(min(strategy.tcp_initial_cwnd, self.window_limit))
        self.ssthresh = float(self.window_limit)
        self.duplicate_acks = 0
        self.smss_bytes = payload
        self.sack_receiver = self.sack_sender = None
        self.rack = None
        self.dsack_undo = None
        self.last_ack_advance_bytes = 0
        self.tcp_newreno_ack_heuristic_entries = 0
        # Exclusive end of the previous loss window. No window exists yet.
        self.recover = -1
        self.in_recovery = False
        self.partial_ack_seen = False
        self.timeout_sequence = None
        self.timer_generation = 0
        self.timer_running = False
        self.rto = strategy.tcp_rto_initial_ms / 1000
        self.srtt = None
        self.rttvar = None
        self.timestamp_recent = None
        self.data_paws = LinuxDataPAWS() if strategy.tcp_data_paws else None
        self.cubic_epoch = None
        self.cubic_max = 0.0
        self.cubic_prior = self.cwnd
        self.cubic_estimate = self.cwnd
        self.cubic_k = 0.0
        self.tcp_timeouts = 0
        self.tcp_fast_retransmits = 0
        self.fast_recovery_checkpoint = None
        self.tcp_partial_timestamp_undos = 0
        self.cwnd_peak_packets = 0
        self.cwnd_usage_sequence = 0
        self.window_was_full = False
        self.segment_offsets = None
        self.reorder_bytes = 0

    def make_transports(self, rng):
        return EndpointStats(), EndpointStats()

    @property
    def tcp_retransmissions(self):
        return self.datagrams[False]["retry"]

    def produce(self):
        self.source_timer = None
        slots = min(self.window_limit, floor(self.cwnd))
        while self.now < self.traffic.duration_s and len(self.forward.pending) < slots:
            if self.next_source > self.now:
                self.source_timer = self.next_source
                self.at(self.next_source, self.produce)
                self.record_window_usage()
                return
            self.issue_original_segment()
            self.next_source = self.now + self.traffic.frame_interval_ms / 1000
        self.record_window_usage()

    def issue_original_segment(self):
        """Issue one original after the producer has checked TCP flight capacity."""
        index = len(self.sent_times)
        self.sent_times.append(self.now)
        self.forward.pending[index] = Segment()
        self.forward.pending_bytes += self.segment_bytes(index)
        self.forward.peak_pending_bytes = max(self.forward.peak_pending_bytes,
                                             self.forward.pending_bytes)
        self.transmit_segment(index)

    def byte_offset(self, index):
        """TCP stream offset at a segment boundary, including the end of issued data."""
        if self.segment_offsets is None:
            return index * self.traffic.payload_bytes
        return self.segment_offsets[index]

    def segment_bytes(self, index):
        if self.segment_offsets is None:
            return self.traffic.payload_bytes
        return self.segment_offsets[index + 1] - self.segment_offsets[index]

    def record_window_usage(self):
        """Retain paced flight utilization until its sequence window is ACKed.

        Linux tcp_cwnd_validate and tcp_is_cwnd_limited retain this evidence
        across ACK bursts. Slow start also permits growth up to twice the
        observed outstanding flight. Instantaneous occupancy loses that signal
        while the source pacing timer waits to refill newly available slots.
        """
        if not self.traffic.frame_interval_ms:
            return
        outstanding = len(self.forward.pending)
        limited = outstanding >= floor(self.cwnd)
        if (self.tcp_acked >= self.cwnd_usage_sequence or limited
                or (not self.window_was_full and outstanding > self.cwnd_peak_packets)):
            self.window_was_full = limited
            self.cwnd_peak_packets = outstanding
            self.cwnd_usage_sequence = len(self.sent_times)

    def cwnd_limited_for_growth(self):
        if self.traffic.frame_interval_ms:
            return self.window_was_full or (self.cwnd < self.ssthresh and self.cwnd < 2 * self.cwnd_peak_packets)
        return len(self.forward.pending) >= min(floor(self.cwnd), self.window_limit)

    def transmit_segment(self, index):
        segment = self.forward.pending[index]
        retry = segment.attempts > 0
        finish, _ = self.send(False, self.segment_bytes(index) + IP_TCP_BYTES,
                              "retry" if retry else "source",
                              lambda: self.on_data(index, finish))
        segment.last_sent_at = finish
        segment.attempts += 1
        if not self.timer_running:
            self.restart_timer()

    def restart_timer(self):
        self.timer_generation += 1
        self.timer_running = bool(self.forward.pending)
        if self.timer_running:
            oldest = self.forward.pending[self.tcp_acked]
            when = max(self.now, oldest.last_sent_at) + self.rto
            self.at(when, self.on_timeout, self.timer_generation)

    def on_timeout(self, generation):
        if generation != self.timer_generation or not self.forward.pending:
            return
        oldest = self.forward.pending[self.tcp_acked]
        # A partial ACK may have changed the oldest segment while this timer ran.
        if self.now + 1e-12 < oldest.last_sent_at + self.rto:
            self.restart_timer()
            return
        self.tcp_timeouts += 1
        if self.sack_sender is not None:
            self.sack_sender.reset()
        if self.rack is not None:
            self.rack.rto_recovery_end = len(self.sent_times)
        if self.dsack_undo is not None:
            self.dsack_undo.episode = None
        self.fast_recovery_checkpoint = None
        if self.timeout_sequence != self.tcp_acked:
            self.reduce_window()
            self.timeout_sequence = self.tcp_acked
        self.cwnd = 1.0
        self.cubic_max = 0.0
        self.cubic_epoch = None
        self.recover = len(self.sent_times)
        self.in_recovery = False
        self.duplicate_acks = 0
        self.rto = min(60.0, self.rto * 2)
        self.timer_running = False
        self.transmit_segment(self.tcp_acked)

    def on_data(self, index, timestamp):
        # RFC 7323 section 4.3 echoes the oldest delayed-ACK segment, then
        # switches to the transmission that fills a receive-sequence hole.
        if self.data_paws is not None:
            wire_ts = None if timestamp is None else int(timestamp * 1000) & 0xffffffff
            accepted, refresh = self.data_paws.receive(
                index, index + 1, wire_ts, self.now, self.last_ack)
            if not accepted:
                if self.sack_receiver is not None and index < self.tcp_received:
                    self.sack_receiver.note(index, self.tcp_received, self.tcp_received, True, False)
                # Established DATA elicits a current cumulative ACK on Linux;
                # tcp_oow_rate_limited exempts DATA without SYN from its limit.
                self.emit_ack()
                return
        else:
            refresh = (index <= self.last_ack and
                       (self.timestamp_recent is None or timestamp >= self.timestamp_recent))
        if refresh:
            self.timestamp_recent = timestamp
        before = self.tcp_received
        is_new = index >= before and index not in self.tcp_buffer
        had_gap = bool(self.tcp_buffer)
        if is_new:
            self.tcp_buffer.add(index)
            self.reorder_bytes += self.segment_bytes(index) + IP_TCP_BYTES + ETHERNET_BYTES
        while self.tcp_received in self.tcp_buffer:
            self.tcp_buffer.remove(self.tcp_received)
            self.forward.delays.append((self.now - self.sent_times[self.tcp_received]) * 1000)
            self.tcp_received += 1
        advanced = self.tcp_received - before
        if self.sack_receiver is not None:
            self.sack_receiver.note(index, before, self.tcp_received, not is_new, True)
        payload = self.byte_offset(self.tcp_received) - self.byte_offset(before)
        released = payload + advanced * (IP_TCP_BYTES + ETHERNET_BYTES)
        self.forward.delivered_bytes += released
        self.reorder_bytes -= released
        self.forward.peak_reorder_bytes = max(self.forward.peak_reorder_bytes,
                                              self.reorder_bytes)
        if self.now <= self.traffic.duration_s:
            self.tcp_payload_bytes += payload
            self.forward.delivered_during_measurement_bytes += released
        if index != before or had_gap:
            self.emit_ack()
        elif self.tcp_received - self.last_ack >= self.traffic.ack_every:
            self.emit_ack()
        elif self.ack_timer is None:
            self.ack_timer = self.now + self.traffic.ack_delay_ms / 1000
            self.at(self.ack_timer, self.flush_ack, self.ack_timer)

    def emit_ack(self):
        self.ack_timer = None
        self.last_ack = self.tcp_received
        acknowledged, created_at = self.tcp_received, self.now
        echoed_timestamp = self.timestamp_recent

        def receive_ack():
            self.reverse.delivered_bytes += IP_TCP_BYTES + ETHERNET_BYTES
            self.reverse.delays.append((self.now - created_at) * 1000)
            self.on_ack(acknowledged, echoed_timestamp)

        self.send(True, IP_TCP_BYTES, "source", receive_ack)

    def on_ack(self, acknowledged, echoed_timestamp=None):
        if acknowledged < self.tcp_acked or not self.forward.pending:
            return
        if acknowledged == self.tcp_acked:
            if self.rack is not None:
                # Only elapsed transmit/delivery evidence can mark RACK losses.
                if self.source_timer is None:
                    self.produce()
                return
            self.duplicate_acks += 1
            if self.in_recovery:
                self.cwnd = min(self.window_limit, self.cwnd + 1)
            elif self.duplicate_acks == 3 and (
                    self.tcp_acked > self.recover or self.allow_newreno_ack_heuristic()):
                if self.tcp_acked <= self.recover:
                    self.tcp_newreno_ack_heuristic_entries += 1
                self.tcp_fast_retransmits += 1
                if self.dsack_undo is not None:
                    self.dsack_undo.begin(self)
                if (self.strategy.tcp_partial_timestamp_undo and self.forward.pending[self.tcp_acked].attempts == 1
                        and (self.sack_sender is None or not self.sack_sender.retried)):
                    self.fast_recovery_checkpoint = (int(self.now * 1000) & 0xffffffff, self.cwnd, self.ssthresh)
                self.reduce_window()
                self.recover = len(self.sent_times)
                self.in_recovery = True
                self.partial_ack_seen = False
                self.cwnd = min(self.window_limit, self.ssthresh + 3)
                self.transmit_segment(self.tcp_acked)
                self.restart_timer()
            if self.source_timer is None:
                self.produce()
            return

        was_limited = self.cwnd_limited_for_growth()
        newly_acked = acknowledged - self.tcp_acked
        segments = [self.forward.pending.pop(index)
                    for index in range(self.tcp_acked, acknowledged)]
        self.last_ack_advance_bytes = self.byte_offset(acknowledged) - self.byte_offset(self.tcp_acked)
        self.forward.pending_bytes -= self.last_ack_advance_bytes
        self.tcp_acked = acknowledged
        self.duplicate_acks = 0
        self.tcp_rtts.append((self.now - self.sent_times[acknowledged - 1]) * 1000)
        # An echoed transmission timestamp removes retransmission ambiguity.
        # Retain Karn sampling for ACKs supplied without a timestamp.
        if echoed_timestamp is not None:
            self.update_rtt(self.now - echoed_timestamp)
        elif all(segment.attempts == 1 for segment in segments):
            self.update_rtt(self.now - segments[-1].last_sent_at)

        reset_timer = True
        # NewReno retries only the oldest segment on entry. The first advancing
        # ACK covers that retry. A strictly earlier wire tick on a partial ACK
        # permits restoring the window before another segment is retransmitted.
        checkpoint = self.fast_recovery_checkpoint
        self.fast_recovery_checkpoint = None
        if checkpoint is not None and partial_ack_predates_retry(
                acknowledged - newly_acked, acknowledged, self.recover, checkpoint[0],
                int(echoed_timestamp * 1000) & 0xffffffff if echoed_timestamp is not None else None):
            _, self.cwnd, self.ssthresh = checkpoint
            self.in_recovery = False
            if self.rack is not None:
                self.rack.end_recovery()
            self.cubic_epoch = None
            self.tcp_partial_timestamp_undos += 1
            if self.dsack_undo is not None:
                self.dsack_undo.episode = None
        elif self.in_recovery:
            if acknowledged < self.recover:
                if self.rack is None:
                    self.cwnd = max(1.0, self.cwnd - newly_acked + 1)
                    self.transmit_segment(acknowledged)
                reset_timer = not self.partial_ack_seen
                self.partial_ack_seen = True
            else:
                if self.rack is not None:
                    self.rack.persistence = max(0, self.rack.persistence - 1)
                    self.rack.end_recovery()
                    self.cwnd = min(self.window_limit, self.ssthresh)
                else:
                    self.cwnd = min(self.ssthresh, max(len(self.forward.pending), 1) + 1)
                self.in_recovery = False
                self.cubic_epoch = None
        elif was_limited:
            if self.rack is None:
                self.increase_window(newly_acked)
        else:
            # Reinitialize CUBIC after an application/receive-window-limited gap.
            self.cubic_epoch = None
        if reset_timer or not self.forward.pending:
            self.restart_timer()
        if self.source_timer is None:
            self.produce()

    def allow_newreno_ack_heuristic(self):
        """RFC 6582 section 4.1, at the third duplicate ACK below or at recover."""
        return (self.strategy.tcp_newreno_ack_heuristic and self.cwnd > 1
                and 0 < self.last_ack_advance_bytes <= 4 * self.smss_bytes)

    def update_rtt(self, sample):
        if self.srtt is None:
            self.srtt, self.rttvar = sample, sample / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
            self.srtt = 0.875 * self.srtt + 0.125 * sample
        self.rto = min(60.0, max(self.strategy.tcp_rto_min_ms / 1000,
                                 self.srtt + max(0.001, 4 * self.rttvar)))

    def reduce_window(self):
        self.cubic_prior = self.cwnd
        self.cubic_max = self.cwnd  # Single flow, fast convergence disabled.
        self.cubic_epoch = None
        if self.rack is not None:
            # Linux CUBIC and Reno compute the target from pre-loss snd_cwnd in
            # whole segments. The retained application window can include data
            # already delivered by SACK while a lower sequence is outstanding.
            packets = floor(self.cwnd)
            target = packets * 717 // 1024 if self.strategy.tcp_cc == "cubic" else packets // 2
            self.ssthresh = max(2, target)
        else:
            beta = 0.7 if self.strategy.tcp_cc == "cubic" else 0.5
            self.ssthresh = max(2.0, len(self.forward.pending) * beta)

    def increase_window(self, acknowledged):
        if self.cwnd < self.ssthresh:
            self.cwnd = min(self.window_limit, self.cwnd + 1)
            return
        if self.strategy.tcp_cc == "reno":
            self.cwnd = min(self.window_limit, self.cwnd + 1 / self.cwnd)
            return
        if self.cubic_epoch is None:
            self.cubic_epoch = self.now
            if not self.cubic_max:
                self.cubic_max = self.cwnd
            self.cubic_k = cbrt((self.cubic_max - self.cwnd) / 0.4)
            self.cubic_estimate = self.cwnd
        elapsed = self.now - self.cubic_epoch
        rtt = self.srtt or self.links[False][0].rtt
        cubic_now = 0.4 * (elapsed - self.cubic_k) ** 3 + self.cubic_max
        target = 0.4 * (elapsed + rtt - self.cubic_k) ** 3 + self.cubic_max
        target = min(1.5 * self.cwnd, max(self.cwnd, target))
        alpha = 1.0 if self.cubic_estimate >= self.cubic_prior else 3 * 0.3 / 1.7
        self.cubic_estimate += alpha * acknowledged / self.cwnd
        if cubic_now < self.cubic_estimate:
            self.cwnd = self.cubic_estimate
        else:
            self.cwnd += (target - self.cwnd) / self.cwnd
        self.cwnd = min(self.window_limit, self.cwnd)
