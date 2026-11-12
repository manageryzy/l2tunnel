"""Discrete-event model of framed traffic over a paced, lossy virtual link."""

from collections import Counter, deque
from dataclasses import dataclass
from heapq import heappop, heappush
from itertools import chain, count
from math import ceil
from random import Random

from .coding import Decoder, block_coefficients


# Outer IP bytes. Additional symbols in one datagram carry a small length field.
HEADER_BYTES = 88
PACKED_SYMBOL_BYTES = 4
FEEDBACK_ID_BYTES = 4
ACK_FRAME_BYTES = 66


class Erasures:
    def __init__(self, scenario, rng):
        self.rng = rng
        self.rate = scenario.loss_rate
        self.burst = scenario.loss_model == "burst" and 0 < self.rate < 1
        self.bad = rng.random() < self.rate
        if self.burst:
            self.leave = 1 / scenario.mean_burst
            self.enter = self.rate * self.leave / (1 - self.rate)

    def lost(self):
        draw = self.rng.random()
        if not self.burst:
            return draw < self.rate
        lost = self.bad
        self.bad = draw >= self.leave if self.bad else draw < self.enter
        return lost


class Link:
    def __init__(self, scenario, path, reverse, rng):
        self.rtt = scenario.rtt_ms * path.rtt_factor / 1000
        self.jitter = path.jitter_ms / 1000
        self.bytes_per_s = (path.reverse_mbps if reverse else path.forward_mbps) * 125000
        self.free_at = 0.0
        self.reserved_bytes = 0
        self.erasures = Erasures(scenario, Random(rng.getrandbits(64)))
        self.jitter_rng = Random(rng.getrandbits(64))

    def finish(self, now, size):
        return max(now, self.free_at) + size / self.bytes_per_s

    def serialized_bytes(self, now):
        """Count service through now, including the transmitted part of a packet."""
        queued_bytes = max(0.0, self.free_at - now) * self.bytes_per_s
        return self.reserved_bytes - queued_bytes


class Simulation:
    def __init__(self, scenario, traffic, paths, strategy, seed):
        self.scenario = scenario
        self.traffic = traffic
        self.strategy = strategy
        self.now = 0.0
        self.events = []
        self.sequence = count()
        self.stop_at = traffic.duration_s + traffic.drain_s
        rng = Random(seed)
        self.links = [
            [Link(scenario, path, reverse, rng) for path in paths]
            for reverse in (False, True)
        ]
        self.wire = [Counter(), Counter()]
        self.datagrams = [Counter(), Counter()]
        self.erasures = [Counter(), Counter()]
        self.forward, self.reverse = self.make_transports(rng)
        self.sent_times = []
        self.tcp_acked = 0
        self.tcp_received = 0
        self.tcp_buffer = set()
        self.tcp_payload_bytes = 0
        self.tcp_rtts = []
        self.last_ack = 0
        self.ack_timer = None
        self.next_source = 0.0
        self.source_timer = None

    def make_transports(self, rng):
        return (
            Tunnel(self, False, Random(rng.getrandbits(64)), self.on_data),
            Tunnel(self, True, Random(rng.getrandbits(64)), self.on_ack),
        )

    def at(self, when, callback, *args):
        if when <= self.stop_at:
            heappush(self.events, (when, next(self.sequence), callback, args))

    def send(self, reverse, size, kind, receive):
        """Reserve one path and account for a datagram when serialization ends."""
        assert size <= self.scenario.mtu
        link = min(self.links[reverse], key=lambda link: link.finish(self.now, size) + link.rtt / 2)
        finish = link.finish(self.now, size)
        link.free_at = finish
        link.reserved_bytes += size

        def depart():
            self.wire[reverse][kind] += size
            self.datagrams[reverse][kind] += 1
            if link.erasures.lost():
                self.erasures[reverse][kind] += 1
                return
            propagation = max(0, link.rtt / 2 + link.jitter_rng.uniform(-link.jitter, link.jitter))
            self.at(self.now + propagation, receive)

        self.at(finish, depart)
        return finish, link.rtt

    def produce(self):
        self.source_timer = None
        slots = self.traffic.window_bytes // self.traffic.payload_bytes
        while (self.now < self.traffic.duration_s
               and len(self.sent_times) - self.tcp_acked < slots):
            if self.next_source > self.now:
                self.source_timer = self.next_source
                self.at(self.next_source, self.produce)
                return
            index = len(self.sent_times)
            self.sent_times.append(self.now)
            self.forward.frame(self.traffic.frame_bytes, index)
            self.next_source = self.now + self.traffic.frame_interval_ms / 1000

    def on_data(self, index):
        self.tcp_buffer.add(index)
        before = self.tcp_received
        while self.tcp_received in self.tcp_buffer:
            self.tcp_buffer.remove(self.tcp_received)
            self.tcp_received += 1
        advanced = self.tcp_received - before
        if not advanced:
            return
        if self.now <= self.traffic.duration_s:
            self.tcp_payload_bytes += advanced * self.traffic.payload_bytes
        if self.tcp_received - self.last_ack >= self.traffic.ack_every:
            self.emit_ack()
        elif self.ack_timer is None:
            self.ack_timer = self.now + self.traffic.ack_delay_ms / 1000
            self.at(self.ack_timer, self.flush_ack, self.ack_timer)

    def flush_ack(self, when):
        if self.ack_timer == when:
            self.emit_ack()

    def emit_ack(self):
        self.ack_timer = None
        self.last_ack = self.tcp_received
        self.reverse.frame(ACK_FRAME_BYTES, self.last_ack)

    def on_ack(self, acknowledged):
        if acknowledged > self.tcp_acked:
            self.tcp_acked = acknowledged
            self.tcp_rtts.append((self.now - self.sent_times[acknowledged - 1]) * 1000)
            if self.source_timer is None:
                self.produce()

    def run(self):
        self.produce()
        while self.events:
            self.now, _, callback, args = heappop(self.events)
            callback(*args)
        return self


@dataclass
class Frame:
    sequence: int
    size: int
    value: int
    created_at: float
    missing: int


@dataclass(frozen=True)
class Symbol:
    index: int
    size: int
    frame: Frame


@dataclass(frozen=True)
class Repair:
    coefficients: dict[int, int]
    size: int
    feedback_triggered: bool


@dataclass
class Flight:
    symbol: Symbol
    sent_at: float = float("inf")
    rtt: float = 0.0
    retry_at: float = float("inf")
    repair_until: float = 0.0
    queued_repairs: int = 0
    attempts: int = 0
    early: bool = False


class Packer:
    """Combine symbols that share one MTU, serialization cost and loss draw."""

    def __init__(self, tunnel, kind, batch):
        self.tunnel = tunnel
        self.sim = tunnel.sim
        self.kind = kind
        self.batch = batch
        self.items = []
        self.size = HEADER_BYTES
        self.generation = 0

    def add(self, item):
        added = item.size + PACKED_SYMBOL_BYTES
        if self.items and self.size + added > self.sim.scenario.mtu:
            self.flush()
        if not self.items:
            self.sim.at(self.sim.now + self.tunnel.strategy.pack_wait_ms / 1000,
                        self.flush, self.generation)
            added = item.size
        self.items.append(item)
        self.size += added
        if (len(self.items) == self.batch
                or self.size + PACKED_SYMBOL_BYTES + 1 > self.sim.scenario.mtu):
            self.flush()

    def flush(self, generation=None):
        if not self.items or (generation is not None and generation != self.generation):
            return
        items, size = self.items, self.size
        self.items = []
        self.size = HEADER_BYTES
        self.generation += 1
        self.tunnel.transmit(self.kind, items, size)


class Tunnel:
    def __init__(self, sim, reverse, rng, deliver):
        self.sim = sim
        self.reverse = reverse
        self.rng = rng
        self.deliver = deliver
        self.strategy = sim.strategy
        strategy = self.strategy
        self.mode = "arq" if reverse and not strategy.reverse_fec else strategy.mode
        self.lanes = (1 if strategy.reverse_ordered else 0) if reverse else strategy.streams
        self.next_in_lane = list(range(self.lanes))
        self.reorder = {}
        self.reorder_bytes = 0
        self.peak_reorder_bytes = 0
        self.frame_count = 0
        self.symbols = []
        self.pending = {}
        self.pending_bytes = 0
        self.peak_pending_bytes = 0
        self.delivered_bytes = 0
        self.delivered_during_measurement_bytes = 0
        self.delays = []
        self.recovered_symbols = 0
        self.decoder = Decoder()
        self.decode_free_at = 0.0
        self.block = []
        self.window = deque(maxlen=strategy.long_window)
        self.fec_count = 0
        self.repair_credit = 0
        self.fec_generation = 0
        self.periodic_repairs = 0
        self.feedback = set()
        self.feedback_generation = 0
        self.highest_feedback = -1
        self.received_prefix = -1
        self.confirmed_prefix = -1
        self.source_packer = Packer(self, "source", strategy.reverse_batch if reverse else strategy.source_batch)
        self.repair_packer = Packer(self, "repair", strategy.reverse_repair_batch if reverse else strategy.repair_batch)

    def frame(self, size, value):
        maximum = self.sim.scenario.mtu - HEADER_BYTES
        minimum = 1 if self.reverse else self.strategy.fragments
        pieces = min(size, max(minimum, ceil(size / maximum)))
        base, remainder = divmod(size, pieces)
        frame = Frame(self.frame_count, size, value, self.sim.now, pieces)
        self.frame_count += 1
        for piece in range(pieces):
            symbol = Symbol(len(self.symbols), base + (piece < remainder), frame)
            self.symbols.append(symbol)
            self.pending[symbol.index] = Flight(symbol)
            self.pending_bytes += symbol.size
            self.peak_pending_bytes = max(self.peak_pending_bytes, self.pending_bytes)
            self.source_packer.add(symbol)
            if self.mode != "arq":
                self.add_to_code(symbol)

    def add_to_code(self, symbol):
        if self.mode == "block":
            self.block.append(symbol)
            target = self.strategy.block_size
        else:
            self.window.append(symbol)
            target = self.strategy.repair_every
        self.fec_count += 1
        if self.fec_count == 1:
            self.sim.at(self.sim.now + self.strategy.fec_wait_ms / 1000,
                        self.flush_code, self.fec_generation)
        ready = self.fec_count == target
        if self.mode != "block" and self.strategy.interleave_repairs:
            self.repair_credit += self.strategy.repairs_per_group
            ready = self.repair_credit >= self.strategy.repair_every
        if ready:
            self.flush_code(self.fec_generation)

    def flush_code(self, generation):
        if generation != self.fec_generation:
            return
        self.source_packer.flush()
        if self.mode == "block":
            sources, self.block = self.block, []
            n = len(sources)
            repair_count = ceil(n * self.strategy.block_repairs / self.strategy.block_size)
            for index in range(repair_count):
                self.queue_repair(sources, block_coefficients(n, index), index + 1)
        else:
            if self.strategy.interleave_repairs:
                repairs = max(1, self.repair_credit // self.strategy.repair_every)
                self.repair_credit = max(0, self.repair_credit - repairs * self.strategy.repair_every)
            else:
                repairs = ceil(self.fec_count * self.strategy.repairs_per_group / self.strategy.repair_every)
            for index in range(repairs):
                self.periodic_repairs += 1
                long = self.mode == "sliding" or self.periodic_repairs % self.strategy.long_every == 0
                width = self.strategy.long_window if long else self.strategy.short_window
                self.queue_repair(list(self.window)[-width:], spacing_index=index + 1)
        self.fec_count = 0
        self.fec_generation += 1

    def queue_repair(self, sources, coefficients=None, spacing_index=0, *, feedback_triggered=False):
        if coefficients is None:
            coefficients = [self.rng.randrange(1, 256) for _ in sources]
        size = max(source.size for source in sources)
        if feedback_triggered:
            size += FEEDBACK_ID_BYTES * len(sources)
        repair = Repair(dict(zip((source.index for source in sources), coefficients)),
                        size, feedback_triggered)
        for index in repair.coefficients:
            if index in self.pending:
                self.pending[index].queued_repairs += 1
        delay = spacing_index * self.strategy.repair_spacing_ms / 1000
        if delay:
            self.sim.at(self.sim.now + delay, self.repair_packer.add, repair)
        else:
            self.repair_packer.add(repair)

    def transmit(self, kind, items, size):
        if kind == "repair":
            finish, rtt = self.sim.send(self.reverse, size, kind, lambda: self.receive_repairs(items))
            for repair in items:
                for index in repair.coefficients:
                    flight = self.pending.get(index)
                    if flight is not None:
                        flight.queued_repairs -= 1
                        expected = finish + rtt + self.strategy.feedback_wait_ms / 1000
                        flight.repair_until = max(flight.repair_until, expected)
                        if repair.feedback_triggered and expected >= flight.retry_at:
                            self.arm_retry(flight, expected + self.strategy.rto_min_ms / 1000)
            return
        finish, rtt = self.sim.send(self.reverse, size, kind, lambda: self.receive_sources(items))
        for symbol in items:
            flight = self.pending.get(symbol.index)
            if flight is not None:
                flight.sent_at = finish
                flight.rtt = rtt
                flight.attempts += 1
                interval = max(self.strategy.rto_min_ms / 1000, rtt * self.strategy.rto_factor)
                self.arm_retry(flight, finish + interval)

    def arm_retry(self, flight, when):
        flight.retry_at = when
        self.sim.at(when, self.retry, flight.symbol.index, when)

    def retry(self, index, when):
        flight = self.pending.get(index)
        if flight is None or flight.retry_at != when:
            return
        symbol = flight.symbol
        self.transmit("retry", [symbol], HEADER_BYTES + symbol.size)

    def receive_sources(self, symbols):
        for symbol in symbols:
            if symbol.index in self.decoder.known:
                # A lost feedback datagram can cause an already known source to arrive again.
                self.mark_feedback(symbol.index)
            else:
                self.learn(self.decoder.insert({symbol.index: 1}), direct=symbol.index)

    def receive_repairs(self, repairs):
        for repair in repairs:
            cost = self.strategy.decode_us_per_symbol * len(repair.coefficients) / 1e6
            if cost:
                self.decode_free_at = max(self.sim.now, self.decode_free_at) + cost
                self.sim.at(self.decode_free_at, self.decode, repair)
            else:
                self.decode(repair)

    def decode(self, repair):
        self.learn(self.decoder.insert(repair.coefficients))

    def learn(self, indices, direct=None):
        for index in indices:
            self.mark_feedback(index)
            self.recovered_symbols += index != direct
            frame = self.symbols[index].frame
            frame.missing -= 1
            if frame.missing == 0:
                self.complete(frame)

    def complete(self, frame):
        if not self.lanes:
            self.release(frame)
            return
        lane = frame.sequence % self.lanes
        if frame.sequence != self.next_in_lane[lane]:
            self.reorder[frame.sequence] = frame
            self.reorder_bytes += frame.size
            self.peak_reorder_bytes = max(self.peak_reorder_bytes, self.reorder_bytes)
            return
        while frame is not None:
            self.release(frame)
            self.next_in_lane[lane] += self.lanes
            frame = self.reorder.pop(self.next_in_lane[lane], None)
            if frame is not None:
                self.reorder_bytes -= frame.size

    def release(self, frame):
        self.delivered_bytes += frame.size
        if self.sim.now <= self.sim.traffic.duration_s:
            self.delivered_during_measurement_bytes += frame.size
        self.delays.append((self.sim.now - frame.created_at) * 1000)
        self.deliver(frame.value)

    def mark_feedback(self, index):
        if not self.feedback:
            when = self.sim.now + self.strategy.feedback_wait_ms / 1000
            self.sim.at(when, self.flush_feedback, self.feedback_generation)
        self.feedback.add(index)
        prefix_bytes = FEEDBACK_ID_BYTES if self.strategy.cumulative_feedback else 0
        capacity = (self.sim.scenario.mtu - HEADER_BYTES - prefix_bytes) // FEEDBACK_ID_BYTES
        if len(self.feedback) >= min(capacity, self.strategy.feedback_batch):
            self.flush_feedback(self.feedback_generation)

    def flush_feedback(self, generation):
        if generation != self.feedback_generation:
            return
        ids = tuple(sorted(self.feedback))
        self.feedback.clear()
        self.feedback_generation += 1
        prefix = -1
        if self.strategy.cumulative_feedback:
            while self.received_prefix + 1 in self.decoder.known:
                self.received_prefix += 1
            prefix = self.received_prefix
            ids = tuple(index for index in ids if index > prefix)
        fields = len(ids) + int(self.strategy.cumulative_feedback)
        size = HEADER_BYTES + FEEDBACK_ID_BYTES * fields
        self.sim.send(not self.reverse, size, "feedback", lambda: self.on_feedback(ids, prefix))

    def on_feedback(self, ids, prefix=-1):
        cumulative = range(self.confirmed_prefix + 1, prefix + 1)
        self.confirmed_prefix = max(self.confirmed_prefix, prefix)
        for index in chain(cumulative, ids):
            flight = self.pending.pop(index, None)
            if flight is not None:
                self.pending_bytes -= flight.symbol.size
        self.highest_feedback = max(self.highest_feedback, prefix, ids[-1] if ids else -1)
        if not self.strategy.feedback_repair or self.mode == "arq":
            return
        candidates = []
        largest = 0
        payload_budget = self.sim.scenario.mtu - HEADER_BYTES
        for index, flight in self.pending.items():
            if index >= self.highest_feedback or len(candidates) == self.strategy.long_window:
                break
            if (flight.attempts == 1 and not flight.early and not flight.queued_repairs
                    and self.sim.now >= max(flight.sent_at + flight.rtt, flight.repair_until)):
                size = max(largest, flight.symbol.size)
                if size + FEEDBACK_ID_BYTES * (len(candidates) + 1) <= payload_budget:
                    flight.early = True
                    largest = size
                    candidates.append(flight.symbol)
        for _ in candidates:
            self.queue_repair(candidates, feedback_triggered=True)
        if candidates:
            self.repair_packer.flush()
