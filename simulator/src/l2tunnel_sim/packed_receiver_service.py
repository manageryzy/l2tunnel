"""Optional serial decoder for a PackedWire sensitivity experiment.

The cost preview reads the last committed rank, computes the next incoming
pivot in scratch space, and leaves delivery and feedback unchanged until
the scheduled completion. Source bytes
for rank-recovered symbols still come from the historical simulation ledger.
"""

from array import array
from collections import Counter, deque
from dataclasses import dataclass
from math import ceil, isfinite

from .coding import _eliminate
from .compact import coefficient
from .compact_wire import SYMBOL_BYTES, decode_packet
from .packed_wire import PackedWireTransport
from .packed_rank import PackedRankDecoder


@dataclass(frozen=True)
class ReceiverCost:
    packet_us: float
    metadata_ns: float
    gf_ns_per_byte: float
    waiting_slots: int

    def __post_init__(self):
        for value in (self.packet_us, self.metadata_ns, self.gf_ns_per_byte):
            if type(value) not in (int, float) or not isfinite(value) or value < 0:
                raise ValueError("receiver service costs must be finite and nonnegative")
        if type(self.waiting_slots) is not int or not 0 <= self.waiting_slots <= 65536:
            raise ValueError("receiver waiting slots must be an integer from zero to 65536")

    def charge(self, gf_bytes, metadata_visits):
        return self.packet_us + (self.metadata_ns * metadata_visits + self.gf_ns_per_byte * gf_bytes) / 1000


@dataclass(frozen=True)
class DecoderCurve:
    """Whole-decoder microseconds fitted to systematic and two measured repair points."""

    base_us: float
    local_bytes: int
    local_us: float
    global_bytes: int
    global_us: float
    waiting_slots: int = 256

    def __post_init__(self):
        if (type(self.local_bytes) is not int or type(self.global_bytes) is not int
                or not 0 < self.local_bytes < self.global_bytes):
            raise ValueError("repair work anchors must be strictly increasing positive integers")
        if not all(type(t) in (float, int) and isfinite(t) for t in (self.base_us, self.local_us, self.global_us)):
            raise ValueError("decoder anchor times must be finite")
        if not 0 <= self.base_us <= self.local_us <= self.global_us:
            raise ValueError("decoder anchor times must be nonnegative and nondecreasing")
        if type(self.waiting_slots) is not int or not 0 <= self.waiting_slots <= 65536:
            raise ValueError("receiver waiting slots must be an integer from zero to 65536")

    def charge(self, gf_bytes, metadata_visits):
        # Whole-decoder times include the sampled metadata and copies. Adding
        # their individual prices again here would count them twice.
        if gf_bytes <= self.local_bytes:
            return self.base_us + (self.local_us - self.base_us) * gf_bytes / self.local_bytes
        return self.local_us + (self.global_us - self.local_us) * (
            (gf_bytes - self.local_bytes) / (self.global_bytes - self.local_bytes))


def equation_work(decoder, coefficients):
    """Count row mixes, sparse coefficient updates and pivot probes without committing.

    Only the incoming row must be reduced to obtain its pivot and width.
    Normalization preserves support, so backward elimination costs can then
    be read from existing row membership without changing any stored row.
    """
    row = {i: value for i, value in coefficients.items() if value and i not in decoder.known}
    mixes = updates = 0
    for pivot in tuple(row):
        if pivot in decoder.rows:
            existing = decoder.rows[pivot]
            mixes += 1
            updates += len(existing)
            _eliminate(row, existing, row[pivot])
    if not row:
        return mixes, updates, 0
    pivot = min(row)
    changed = int(row[pivot] != 1) + sum(pivot in other for other in decoder.rows.values())
    return mixes + changed, updates + changed * len(row), len(decoder.rows)


class PackedReceiverService:
    """One active job and a bounded drop-tail FIFO per directional recovery owner."""

    def __init__(self, transport, cost, rank_backend="reference"):
        if not isinstance(transport, PackedWireTransport) or transport.decoder.known or transport.decoder.rows:
            raise ValueError("attach receiver service before traffic to a fresh packed transport")
        self.transport = transport
        self.sim = transport.sim
        self.cost = cost
        self.decode = transport._receive_wire
        if rank_backend == "reference":
            self.preview = lambda values: equation_work(transport.decoder, values)
        elif rank_backend == "dense":
            transport.decoder = PackedRankDecoder()
            self.preview = transport.decoder.preview
        else:
            raise ValueError("unsupported packed rank backend")
        self.waiting = deque()
        self.active = False
        self.arrivals = self.drops = self.peak_waiting = self.completed = 0
        self.waits_us = array("d")
        self.work = Counter()
        self.total_service_us = 0.0
        # Keep the original wire parser/delivery path and its fingerprint.
        # _send_wire calls this instance hook on actual delivery by the link.
        transport._receive_wire = self.receive

    def receive(self, wire):
        self.arrivals += 1
        if not self.active:
            self._process(wire, self.sim.now)
        elif len(self.waiting) < self.cost.waiting_slots:
            self.waiting.append((wire, self.sim.now))
            self.peak_waiting = max(self.peak_waiting, len(self.waiting))
        else:
            self.drops += 1

    def _service_us(self, wire):
        try:
            packet = decode_packet(wire, self.transport.received_prefix, self.transport.config.encapsulation)
        except ValueError:
            return self.cost.charge(0, 0)
        width = 1
        known_contributions = 0
        if packet.kind == "source":
            coefficients = {packet.index: 1}
        else:
            width = packet.end - packet.start
            coefficients = {}
            for i in range(packet.start, packet.end):
                factor = coefficient(packet.seed, i)
                if i in self.transport.decoder.known:
                    known_contributions += factor != 0
                else:
                    coefficients[i] = factor
        row_mixes, coefficient_updates, pivot_probes = self.preview(coefficients)
        # A dense payload term accounts for folding known systematic symbols
        # out of repairs and scaling/eliminating actual symbol-sized rows.
        gf_bytes = (known_contributions + row_mixes) * SYMBOL_BYTES
        metadata_visits = width + pivot_probes + coefficient_updates
        self.work["support_positions"] += width
        self.work["pivot_probes"] += pivot_probes
        self.work["sparse_coefficient_updates"] += coefficient_updates
        self.work["known_contributions"] += known_contributions
        self.work["equation_row_mixes"] += row_mixes
        self.work["logical_gf_payload_bytes"] += gf_bytes
        self.work[packet.kind + "_jobs"] += 1
        return self.cost.charge(gf_bytes, metadata_visits)

    def _process(self, wire, arrival):
        self.active = True
        while True:
            self.waits_us.append((self.sim.now - arrival) * 1e6)
            duration_us = self._service_us(wire)
            self.total_service_us += duration_us
            if duration_us:
                self.sim.at(self.sim.now + duration_us / 1e6, self._finish, wire)
                return
            self.decode(wire)
            self.completed += 1
            if not self.waiting:
                self.active = False
                return
            wire, arrival = self.waiting.popleft()

    def _finish(self, wire):
        self.decode(wire)
        self.completed += 1
        if self.waiting:
            self._process(*self.waiting.popleft())
        else:
            self.active = False

    def measurements(self):
        waits = sorted(self.waits_us)
        return dict(
            arrivals=self.arrivals, dropped_full=self.drops, started=len(waits), completed=self.completed,
            active_at_stop=int(self.active), waiting_at_stop=len(self.waiting), peak_waiting=self.peak_waiting,
            terminal_waiting_ages_us=[(self.sim.stop_at - arrival) * 1e6 for _, arrival in self.waiting],
            wait_mean_us=sum(waits) / len(waits) if waits else None,
            wait_p99_us=waits[ceil(.99 * len(waits)) - 1] if waits else None,
            wait_max_us=waits[-1] if waits else None,
            wait_at_least_100ms=sum(value >= 100000 for value in waits),
            started_service_demand_us=self.total_service_us,
            work=dict(self.work))
