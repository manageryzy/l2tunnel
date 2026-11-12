"""Direct IPv4 TCP packet model with CUBIC or Reno and NewReno recovery.

Congestion avoidance follows RFC 5681 or RFC 9438. Cumulative ACK recovery
follows RFC 6582. RTT estimation, Karn sampling and timeout backoff follow
RFC 6298 and RFC 7323 timestamp echoing, with a configurable minimum RTO. Simulation starts
with an established connection. Units for congestion windows are segments.
"""

from dataclasses import dataclass, field, replace
from math import cbrt, floor

from .model import Simulation


IP_TCP_BYTES = 52  # IPv4, TCP, and timestamp options.
ETHERNET_BYTES = 14


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
        self.recover = 0
        self.in_recovery = False
        self.partial_ack_seen = False
        self.timeout_sequence = None
        self.timer_generation = 0
        self.timer_running = False
        self.rto = strategy.tcp_rto_initial_ms / 1000
        self.srtt = None
        self.rttvar = None
        self.timestamp_recent = None
        self.cubic_epoch = None
        self.cubic_max = 0.0
        self.cubic_prior = self.cwnd
        self.cubic_estimate = self.cwnd
        self.cubic_k = 0.0
        self.tcp_timeouts = 0
        self.tcp_fast_retransmits = 0
        self.cwnd_peak_packets = 0
        self.cwnd_usage_sequence = 0
        self.window_was_full = False

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
            index = len(self.sent_times)
            self.sent_times.append(self.now)
            self.forward.pending[index] = Segment()
            self.forward.pending_bytes += self.traffic.payload_bytes
            self.forward.peak_pending_bytes = max(self.forward.peak_pending_bytes,
                                                  self.forward.pending_bytes)
            self.transmit_segment(index)
            self.next_source = self.now + self.traffic.frame_interval_ms / 1000
        self.record_window_usage()

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

    def transmit_segment(self, index):
        segment = self.forward.pending[index]
        retry = segment.attempts > 0
        finish, _ = self.send(False, self.traffic.payload_bytes + IP_TCP_BYTES,
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
        if (index <= self.last_ack
                and (self.timestamp_recent is None or timestamp >= self.timestamp_recent)):
            self.timestamp_recent = timestamp
        before = self.tcp_received
        had_gap = bool(self.tcp_buffer)
        if index >= before:
            self.tcp_buffer.add(index)
        frame_size = self.traffic.payload_bytes + IP_TCP_BYTES + ETHERNET_BYTES
        while self.tcp_received in self.tcp_buffer:
            self.tcp_buffer.remove(self.tcp_received)
            self.forward.delivered_bytes += frame_size
            self.forward.delays.append((self.now - self.sent_times[self.tcp_received]) * 1000)
            self.tcp_received += 1
        advanced = self.tcp_received - before
        self.forward.peak_reorder_bytes = max(self.forward.peak_reorder_bytes,
                                              len(self.tcp_buffer) * frame_size)
        if self.now <= self.traffic.duration_s:
            self.tcp_payload_bytes += advanced * self.traffic.payload_bytes
            self.forward.delivered_during_measurement_bytes += advanced * frame_size
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
            self.duplicate_acks += 1
            if self.in_recovery:
                self.cwnd = min(self.window_limit, self.cwnd + 1)
            elif self.duplicate_acks == 3 and self.tcp_acked >= self.recover:
                self.tcp_fast_retransmits += 1
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

        was_limited = len(self.forward.pending) >= min(floor(self.cwnd), self.window_limit)
        if self.traffic.frame_interval_ms:
            was_limited = (self.window_was_full
                           or (self.cwnd < self.ssthresh and self.cwnd < 2 * self.cwnd_peak_packets))
        newly_acked = acknowledged - self.tcp_acked
        segments = [self.forward.pending.pop(index)
                    for index in range(self.tcp_acked, acknowledged)]
        self.forward.pending_bytes -= newly_acked * self.traffic.payload_bytes
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
        if self.in_recovery:
            if acknowledged < self.recover:
                self.cwnd = max(1.0, self.cwnd - newly_acked + 1)
                self.transmit_segment(acknowledged)
                reset_timer = not self.partial_ack_seen
                self.partial_ack_seen = True
            else:
                self.cwnd = min(self.ssthresh, max(len(self.forward.pending), 1) + 1)
                self.in_recovery = False
                self.cubic_epoch = None
        elif was_limited:
            self.increase_window(newly_acked)
        else:
            # Reinitialize CUBIC after an application/receive-window-limited gap.
            self.cubic_epoch = None
        if reset_timer or not self.forward.pending:
            self.restart_timer()
        if self.source_timer is None:
            self.produce()

    def update_rtt(self, sample):
        if self.srtt is None:
            self.srtt, self.rttvar = sample, sample / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
            self.srtt = 0.875 * self.srtt + 0.125 * sample
        self.rto = min(60.0, max(self.strategy.tcp_rto_min_ms / 1000,
                                 self.srtt + max(0.001, 4 * self.rttvar)))

    def reduce_window(self):
        beta = 0.7 if self.strategy.tcp_cc == "cubic" else 0.5
        self.cubic_prior = self.cwnd
        self.cubic_max = self.cwnd  # Single flow, fast convergence disabled.
        self.cubic_epoch = None
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
