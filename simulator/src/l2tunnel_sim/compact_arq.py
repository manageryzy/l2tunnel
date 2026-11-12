"""Compact ordered records with cumulative/bitmap selective-repeat recovery.

Source packets carry an eight-byte header containing a source ID and a unique
transmission serial, followed by a two-byte valid length. Feedback carries a
24-byte header after IPv4/UDP and a variable-length receipt bitmap. Its fields
are a cumulative prefix, bitmap start, bitmap bit count and reserved field,
echoed transmission serial, receiver ACK delay in microseconds, and feedback
serial. All feedback and retransmissions traverse the ordinary simulated links.
"""

from dataclasses import dataclass
from math import ceil

from .compact import CompactConfig, CompactSource, CompactTransport


FEEDBACK_HEADER_BYTES = 52
REORDER_THRESHOLD = 3


@dataclass
class ARQFlight:
    serial: int = 0
    sent_at: float = 0
    attempts: int = 0
    retry_at: float = 0


class CompactARQTransport(CompactTransport):
    """Reuse compact frame packing, replacing coding with selective repeats.

The sender uses received feedback and its own transmission history. A zero
bitmap bit can trigger fast recovery only when later source packets arrived,
the feedback echoes a newer transmission, and an RTT guard has expired.
Timeouts recover silent tails and lost feedback. Repeated or reordered ACKs
cannot trigger another retransmission in the same unacknowledged RTT interval.
"""

    def __init__(self, sim, reverse, config=CompactConfig(repair_ratio=0)):
        super().__init__(sim, reverse, config)
        # ARQ has no repair-window extension in its source packet format.
        self.symbol_bytes = sim.scenario.mtu - self.source_header
        self.record_capacity = self.symbol_bytes - 2
        self.flights = {}
        self.confirmed = set()
        self.transmission_serial = 0
        self.transmission_times = {}
        self.sampled_serial = 0
        self.last_received_serial = 0
        self.last_received_at = 0
        self.sent_feedback_serial = 0
        self.received_feedback_serial = 0
        self.bitmap_cursor = 0
        self.feedback_repeats = 0
        self.nominal_rtt = min(link.rtt for link in sim.links[reverse])
        self.srtt = None
        self.rttvar = None
        self.fast_retransmissions = 0
        self.timeout_retransmissions = 0
        self.retransmitted_source_bytes = 0

    @property
    def pending(self):
        return self.flights

    def _source(self, size):
        self.buffer_bytes -= size
        self.sent_bytes += size
        source = CompactSource(len(self.sources), size, self.sent_bytes)
        self.sources.append(source)
        self.last_source_at = self.sim.now
        self.flights[source.index] = ARQFlight()
        self._transmit(source.index, 'source')

    def _rto(self):
        feedback = self.config.feedback_ms / 1000
        if self.srtt is None:
            return max(2 * self.nominal_rtt + 2 * feedback, .02)
        return max(self.srtt + 4 * self.rttvar + 2 * feedback,
                   1.25 * self.srtt + 2 * feedback, .02)

    def _transmit(self, index, kind):
        source, flight = self.sources[index], self.flights[index]
        self.transmission_serial += 1
        serial = self.transmission_serial
        finish, _ = self.sim.send(
            self.reverse, self.source_header + 2 + source.size, kind,
            lambda: self._receive_source(source, serial),
        )
        flight.serial, flight.sent_at = serial, finish
        flight.attempts += 1
        flight.retry_at = finish + self._rto()
        self.transmission_times[serial] = finish
        self.sim.at(flight.retry_at, self._timeout, index, serial)
        if kind == 'retry':
            self.retransmitted_source_bytes += source.size

    def _timeout(self, index, serial):
        flight = self.flights.get(index)
        if flight is not None and flight.serial == serial:
            self.timeout_retransmissions += 1
            self._transmit(index, 'retry')

    def _receive_source(self, source, serial):
        self.highest_received = max(self.highest_received, source.index)
        self.last_received_serial = serial
        self.last_received_at = self.sim.now
        # Repeated receipt state makes a short flight robust to a lost ACK.
        # These are ordinary charged, lossy feedback packets.
        self.feedback_repeats = 2
        self.received_source.add(source.index)
        if source.index not in self.decoder.known:
            self.decoder.known.add(source.index)
            self.known_bytes += source.size
        self._advance()

    def _feedback(self, generation=None):
        if generation is not None and generation != self.feedback_generation:
            return
        self.feedback_generation += 1
        self.feedback_pending = False
        self.feedback_events = 0
        self.sent_feedback_serial += 1
        serial = self.sent_feedback_serial
        prefix = self.received_prefix
        header = FEEDBACK_HEADER_BYTES + self.config.authentication_bytes
        bitmap_capacity = (self.sim.scenario.mtu - header) * 8
        start = max(prefix, self.bitmap_cursor)
        if start > self.highest_received:
            start = prefix
        count = min(bitmap_capacity, max(0, self.highest_received + 1 - start))
        bitmap = 0
        for offset in range(count):
            if start + offset in self.decoder.known:
                bitmap |= 1 << offset
        self.bitmap_cursor = start + count
        if self.bitmap_cursor > self.highest_received:
            self.bitmap_cursor = prefix
        echo = self.last_received_serial
        delay_us = round((self.sim.now - self.last_received_at) * 1e6)
        self.sim.send(
            not self.reverse, header + ceil(count / 8), 'feedback',
            lambda: self._receive_feedback(prefix, start, count, bitmap, echo, delay_us, serial),
        )
        if self.feedback_repeats:
            self.feedback_repeats -= 1
            self.feedback_pending = True
            self.feedback_generation += 1
            self.sim.at(self.sim.now + self.config.feedback_ms / 1000,
                        self._feedback, self.feedback_generation)

    def _sample_rtt(self, echo, delay_us):
        sent_at = self.transmission_times.get(echo)
        if sent_at is None or echo <= self.sampled_serial:
            return
        sample = max(0, self.sim.now - sent_at - delay_us / 1e6)
        if self.srtt is None:
            self.srtt, self.rttvar = sample, sample / 2
        else:
            self.rttvar = .75 * self.rttvar + .25 * abs(self.srtt - sample)
            self.srtt = .875 * self.srtt + .125 * sample
        for serial in range(self.sampled_serial + 1, echo + 1):
            self.transmission_times.pop(serial, None)
        self.sampled_serial = echo

    def _confirm(self, index):
        self.flights.pop(index, None)
        if index >= self.base:
            self.confirmed.add(index)

    def _receive_feedback(self, prefix, start, count, bitmap, echo, delay_us, serial):
        self._sample_rtt(echo, delay_us)
        for index in range(self.base, prefix):
            self._confirm(index)
        received_after = bitmap.bit_count()
        missing = []
        for offset in range(count):
            index = start + offset
            if bitmap >> offset & 1:
                self._confirm(index)
                received_after -= 1
            elif received_after >= REORDER_THRESHOLD:
                missing.append(index)
        while self.base in self.confirmed:
            self.confirmed.remove(self.base)
            self.base += 1
        if serial > self.received_feedback_serial:
            self.received_feedback_serial = serial
            guard = max(self.nominal_rtt, self.srtt or 0) + 2 * self.config.feedback_ms / 1000
            for index in missing:
                flight = self.flights.get(index)
                if (flight is not None and echo > flight.serial
                        and self.sim.now >= flight.sent_at + guard):
                    self.fast_retransmissions += 1
                    self._transmit(index, 'retry')
        self._flush_full()
        self._schedule_flush()
