"""Passive forward bulk TCP original-segment paths in the single-FIFO PackedWire study.

Durations partition the lifetime of a segment along its first TCP-arriving
attempt and last available required coding source. These are observed elapsed
intervals. The interval until a solving transmission is issued may contain
loss, retransmission and antecedent equation work; these causes can overlap.
"""

from array import array
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from math import ceil

from .compact_wire import decode_packet
from .packed_wire import PACKED_CHANNEL


PHASES = ("until_winning_inner_attempt", "mux_admission", "pack_and_source_admission",
          "until_solving_transmission", "physical_fifo", "serialization", "propagation",
          "decoder_fifo", "decoder_service", "channel_order", "inner_tcp_order")


@dataclass(slots=True)
class PacketPath:
    kind: str
    index: int
    issue: float
    service_start: float = 0
    depart: float = 0
    arrival: float = 0
    decode_start: float = 0


@dataclass(slots=True, eq=False)
class Attempt:
    key: tuple
    origin: float
    issue: float
    number: int
    channel: int = -1
    admit: float | None = None
    sources: int = 0
    solved: int = 0
    last: tuple | None = None


def _set_during(observer, name, value, callback, *args, **kw):
    previous = getattr(observer, name, None)
    setattr(observer, name, value)
    try:
        return callback(*args, **kw)
    finally:
        setattr(observer, name, previous)


def _quantiles(values):
    vals = sorted(values)
    return dict(n=len(vals), mean=sum(vals) / len(vals) if vals else None,
                p99=vals[ceil(.99 * len(vals)) - 1] if vals else None,
                max=vals[-1] if vals else None)


class PackedFramePath:
    """Install after service attachment, before producers; no new simulation events."""

    def __init__(self, sim, services):
        if not sim.shared_forward.config.independent_delivery or len(sim.links[False]) != 1:
            raise ValueError("requires independent PackedWire delivery and one forward FIFO")
        self.sim = sim
        self.pending = {}
        self.winners = {}
        self.counters = Counter()
        self.by_cause = Counter()
        self.origins = array("d")
        self.total = array("d")
        self.columns = [array("d") for _ in PHASES]
        self.examples = {}
        self._sending = self._admitting = self._dispatch = None
        self._packet = self._arrival = self._active = None
        self._install_tcp()
        self._install_packing()
        self._install_wire(services.get("forward"))

    def _install_tcp(self):
        for fid, flow in enumerate(self.sim.flows):
            tx, rx = flow.transmit_segment, flow.on_data

            def transmit(index, fid=fid, flow=flow, tx=tx):
                if index < flow.tcp_received:
                    self.counters["post_delivery_inner_retries"] += 1
                    return _set_during(self, "_sending", None, tx, index)
                key = fid, index
                attempts = self.pending.setdefault(key, [])
                attempt = Attempt(key, flow.sent_times[index], flow.now, len(attempts) + 1)
                attempts.append(attempt)
                self.counters["inner_attempts"] += 1
                return _set_during(self, "_sending", attempt, tx, index)

            def receive(index, timestamp, fid=fid, flow=flow, rx=rx):
                before = flow.tcp_received
                key = fid, index
                if index >= before and key not in self.winners:
                    attempt = self._dispatch
                    if attempt is None or attempt.key != key or attempt.issue != timestamp:
                        raise ValueError("received TCP callback does not match observed MUX attempt")
                    self.winners[key] = (attempt, flow.now)
                else:
                    self.counters["duplicate_tcp_arrivals"] += 1
                result = rx(index, timestamp)
                for serial in range(before, flow.tcp_received):
                    won, arrival = self.winners.pop((fid, serial))
                    self._complete(won, arrival, flow.now)
                    del self.pending[fid, serial]
                return result

            flow.transmit_segment, flow.on_data = transmit, receive

    def _install_packing(self):
        t = self.sim.shared_forward
        queued = defaultdict(deque)
        units = deque()
        custody = {}
        mux_submit = self.sim.mux.submit_frame
        submit, unit, source, solved = t.submit_channel, t._queue_source, t._aligned_source, t._new_known

        def ingress(reverse, frame):
            channel = mux_submit(reverse, frame)
            if not reverse:
                queued[channel].append(self._sending)
            return channel

        def admission(channel, size, payload, deliver, **kw):
            attempt = queued[channel].popleft()
            if attempt is not None:
                attempt.channel = channel
                attempt.admit = t.sim.now

            def dispatch(frame):
                return _set_during(self, "_dispatch", attempt, deliver, frame)

            return _set_during(self, "_admitting", attempt, submit, channel, size, payload, dispatch, **kw)

        def queue_unit(payload):
            units.append(self._admitting)
            return unit(payload)

        def seal(payload):
            count = payload[1] if payload[0] == PACKED_CHANNEL else 1
            members = {units.popleft() for _ in range(count)} - {None}
            if members:
                custody[len(t.sources)] = (t.sim.now, members)
                for attempt in members:
                    attempt.sources += 1
            return source(payload)

        def newly_known(symbols):
            for index in symbols:
                entry = custody.pop(index, None)
                if entry is None:
                    continue
                issued, members = entry
                if self._active is None:
                    raise ValueError("decoded source has no triggering carrier observation")
                for attempt in members:
                    attempt.solved += 1
                    # Simultaneously solved dependencies share a trigger. Use the
                    # largest source ID to make the tie deterministic.
                    if (attempt.last is None or
                            (t.sim.now, index) > (attempt.last[0], attempt.last[1])):
                        attempt.last = (t.sim.now, index, issued, self._active)
            return solved(symbols)

        self.sim.mux.submit_frame = ingress
        t.submit_channel, t._queue_source, t._aligned_source, t._new_known = admission, queue_unit, seal, newly_known

    def _install_wire(self, service):
        t = self.sim.shared_forward
        net = t.sim
        reserve, send_wire, receive = net.send, t._send_wire, t._receive_wire
        accepted = deque()
        decode = service.decode if service else receive

        def send(wire, kind, header):
            packet = decode_packet(wire, t.received_prefix, t.config.encapsulation)
            cause = packet.kind if kind != "retry" else "retry"
            meta = PacketPath(cause, packet.index, net.now)
            return _set_during(self, "_packet", meta, send_wire, wire, kind, header)

        def reserve_link(reverse, size, kind, callback):
            meta = self._packet
            if reverse or meta is None:
                return reserve(reverse, size, kind, callback)

            def arrive():
                meta.arrival = net.now
                return _set_during(self, "_arrival", meta, callback)

            finish, rtt = reserve(reverse, size, kind, arrive)
            meta.depart = finish
            meta.service_start = max(meta.issue, finish - size / net.links[False][0].bytes_per_s)
            return finish, rtt

        def arrive_wire(wire):
            meta = self._arrival
            if meta is None:
                raise ValueError("unobserved forward wire arrival")
            if service is None:
                meta.decode_start = net.now
                return _set_during(self, "_active", meta, decode, wire)
            if not service.active or len(service.waiting) < service.cost.waiting_slots:
                accepted.append(meta)
            else:
                self.counters["decoder_drop"] += 1
            return receive(wire)

        t._send_wire, net.send, t._receive_wire = send, reserve_link, arrive_wire
        if service:
            price = service._service_us

            def start(wire):
                self._active = accepted.popleft()
                self._active.decode_start = net.now
                return price(wire)
            service._service_us = start

    def _complete(self, a, endpoint, app):
        if a.last is None or a.admit is None or a.solved != a.sources:
            raise ValueError("incomplete coding path at application delivery")
        solved, source, issued, packet = a.last
        landmarks = (a.origin, a.issue, a.admit, issued, packet.issue, packet.service_start,
                     packet.depart, packet.arrival, packet.decode_start, solved, endpoint, app)
        # An already in-flight equation may release a more recent source. Only
        # its suffix after that source entered custody belongs to this path.
        phases = []
        previous = landmarks[0]
        for value in landmarks[1:]:
            current = max(previous, value)
            phases.append((current - previous) * 1000)
            previous = current
        if abs(previous - app) > 1e-9 or solved > endpoint + 1e-9:
            raise ValueError("noncausal completion path")
        total = (app - a.origin) * 1000
        cause = packet.kind
        if packet.kind in ("source", "retry") and packet.index != source:
            cause = "rank_via_" + cause
        self.origins.append(a.origin)
        self.total.append(total)
        self.by_cause[cause] += 1
        for col, cost in zip(self.columns, phases):
            col.append(cost)
        bucket = int(a.origin)
        if bucket not in self.examples or self.examples[bucket]["total_ms"] < total:
            self.examples[bucket] = dict(
                flow=a.key[0], original_segment=a.key[1], attempt=a.number,
                channel=a.channel, source=source, solver=cause, trigger_index=packet.index,
                dependency_sources=a.sources, total_ms=total, phase_ms=dict(zip(PHASES, phases)),
                event_seconds=dict(zip(("original", "attempt", "mux_admitted", "source_sealed",
                    "solver_issued", "serialization_started", "departed", "arrived",
                    "decoder_started", "source_known", "tcp_arrived", "app_delivered"), landmarks)))

    def report(self, warmup_s=0):
        output = {}
        stop = self.sim.traffic.duration_s + self.sim.traffic.drain_s
        for label, start in (("all", 0), ("measurement", warmup_s)):
            indices = [i for i, t in enumerate(self.origins) if start <= t < self.sim.traffic.duration_s]
            censored = Counter()
            ages = []
            for key, attempts in self.pending.items():
                if not start <= attempts[0].origin < self.sim.traffic.duration_s:
                    continue
                # Receiver-visible progress is monotone within the set of observed attempts.
                if key in self.winners:
                    state = "arrived_waiting_for_inner_tcp_order"
                elif any(a.sources and a.solved == a.sources for a in attempts):
                    state = "known_sources_waiting_for_channel_or_unsealed_units"
                elif any(a.sources for a in attempts):
                    state = "sealed_waiting_for_all_sources_or_unsealed_units"
                elif any(a.admit is not None for a in attempts):
                    state = "admitted_waiting_for_source"
                else:
                    state = "submitted_waiting_for_mux"
                censored[state] += 1
                ages.append((stop - attempts[0].origin) * 1000)
            slow = sorted(indices, key=self.total.__getitem__, reverse=True)[:ceil(len(indices) / 100)]
            sums = {p:sum(col[i] for i in slow)/len(slow) if slow else None
                    for p,col in zip(PHASES,self.columns)}
            vals = [self.total[i] for i in indices]
            expected = sum(sum(start <= t < self.sim.traffic.duration_s for t in flow.sent_times)
                           for flow in self.sim.flows)
            if expected != len(indices) + sum(censored.values()):
                raise ValueError("original-segment conservation failed")
            examples = [e for e in self.examples.values()
                        if start <= e["event_seconds"]["original"] < self.sim.traffic.duration_s]
            output[label] = dict(submitted=expected, completed=len(indices), censored=len(ages),
                censored_by_deepest_observed_state=dict(censored), completion_ms=_quantiles(vals),
                all_latency_lower_bound_ms=_quantiles(vals+ages),
                slowest_completed_1pct=dict(samples=len(slow),
                    mean_total_ms=sum(self.total[i] for i in slow)/len(slow) if slow else None,
                    phase_mean_ms=sums), worst_examples=sorted(examples,key=lambda e:-e["total_ms"])[:3])
        return dict(phases=list(PHASES), cohorts=output, counters=dict(self.counters),
                    completed_solving_packet_types=dict(self.by_cause))
