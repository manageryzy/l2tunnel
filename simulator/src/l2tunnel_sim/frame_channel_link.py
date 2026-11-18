"""Directional IP bottlenecks and bounded single-server receive queues for frame studies."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import blake2b
from heapq import heappop, heappush
from itertools import count
from math import ceil, isfinite

Identity = tuple[int, ...]
LossDecision = Callable[[bool, str, Identity], bool]
Work = int | Callable[[], int]


@dataclass(frozen=True)
class LinkConfig:
    forward_mbps: float = 100
    reverse_mbps: float = 10
    one_way_ms: float = 35
    loss_rate: float = 0.15
    outer_bytes: int = 28
    mtu_bytes: int = 1500
    wire_queue_bytes: int = 256 * 1500
    decoder_slots: int = 256
    service_fixed_us: float = 0
    service_record_ns_per_byte: float = 0
    service_work_ns_per_byte: float = 0

    def __post_init__(self):
        if not all(isfinite(value) and value > 0
                   for value in (self.forward_mbps, self.reverse_mbps)):
            raise ValueError("positive finite link rates required")
        if not 0 <= self.loss_rate <= 1:
            raise ValueError("loss_rate must be in [0, 1]")
        if not all(isfinite(value) and value >= 0 for value in (
            self.one_way_ms, self.service_fixed_us, self.service_record_ns_per_byte,
            self.service_work_ns_per_byte,
        )):
            raise ValueError("nonnegative finite delay and service costs required")
        if not all(type(value) is int for value in (
            self.outer_bytes, self.mtu_bytes, self.wire_queue_bytes, self.decoder_slots,
        )):
            raise ValueError("integer byte limits and decoder slots required")
        if not 0 <= self.outer_bytes < self.mtu_bytes:
            raise ValueError("invalid outer header or MTU")
        if self.wire_queue_bytes < self.mtu_bytes or self.decoder_slots < 1:
            raise ValueError("insufficient capacity for one IP packet")


@dataclass
class _Stats:
    packets: int = 0
    record_bytes: int = 0
    wire_bytes: int = 0
    erased: int = 0
    wire_queue_drops: int = 0
    decoder_queue_drops: int = 0
    serviced: int = 0


@dataclass
class _Job:
    at: float
    size: int
    work: Work
    receive: Callable[[], None]
    stats: _Stats


@dataclass
class _Direction:
    rate: float
    free_at: float = 0.0
    reserved: int = 0
    by_kind: dict[str, _Stats] = field(default_factory=dict)
    waiting: deque[_Job] = field(default_factory=deque)
    active: bool = False
    peak_slots: int = 0
    peak_wire_bytes: float = 0.0
    work_bytes: int = 0
    wire_waits: list[float] = field(default_factory=list)
    decoder_waits: list[float] = field(default_factory=list)
    services: list[float] = field(default_factory=list)


def _timings(samples: list[float]) -> dict:
    """Nearest-rank P99 with no samples represented by null."""
    n = len(samples)
    return {
        "count": n,
        "mean": sum(samples) / n if n else None,
        "p99": sorted(samples)[ceil(0.99 * n) - 1] if n else None,
        "max": max(samples, default=None),
        "at_least_100_ms": sum(sample >= 100 for sample in samples),
    }


class FrameChannelLink:
    """Each direction shares one serializer and one FIFO receive server across all channels."""

    def __init__(self, config: LinkConfig, seed: int = 1, forced_loss: LossDecision | None = None):
        self.config = config
        self.seed = seed
        self.forced_loss = forced_loss
        self.now = 0.0
        self._sequence = count()
        self._events = []
        self._dirs = [_Direction(mbps * 125000) for mbps in
                      (config.forward_mbps, config.reverse_mbps)]

    def at(self, when: float, callback: Callable, *args) -> None:
        if not isfinite(when) or when < self.now:
            raise ValueError("event must have a finite time at or after now")
        heappush(self._events, (when, next(self._sequence), callback, args))

    def run(self, until: float) -> None:
        if not isfinite(until) or until < self.now:
            raise ValueError("invalid simulation horizon")
        while self._events and self._events[0][0] <= until:
            self.now, _, callback, args = heappop(self._events)
            callback(*args)
        self.now = until

    def _erased(self, reverse: bool, kind: str, identity: Identity) -> bool:
        if self.forced_loss is not None:
            return self.forced_loss(reverse, kind, identity)
        # Semantic identities pair the same original/attempt across compositions
        # even when a different composition inserts parity or changes send order.
        if self.config.loss_rate in (0, 1):
            return bool(self.config.loss_rate)
        data = repr((self.seed, bool(reverse), kind, identity)).encode("ascii")
        sample = int.from_bytes(blake2b(data, digest_size=8).digest(), "big")
        return sample < int(self.config.loss_rate * (1 << 64))

    def send(self, reverse: bool, kind: str, identity: Identity, payload_bytes: int,
             receive: Callable[[], None], *, work_bytes: Work = 0) -> float | None:
        """Charge one record and its outer bytes. A locally dropped send returns None."""
        size = payload_bytes + self.config.outer_bytes
        if type(payload_bytes) is not int or payload_bytes < 0 or not 0 < size <= self.config.mtu_bytes:
            raise ValueError("record and outer header must fit the IP MTU")
        direction = self._dirs[reverse]
        stats = direction.by_kind.setdefault(kind, _Stats())
        wait = max(0.0, direction.free_at - self.now)
        queued = wait * direction.rate + size
        if queued > self.config.wire_queue_bytes + 1e-6:
            stats.wire_queue_drops += 1
            return None
        finish = max(self.now, direction.free_at) + size / direction.rate
        direction.free_at = finish
        direction.reserved += size
        direction.peak_wire_bytes = max(direction.peak_wire_bytes, queued)
        direction.wire_waits.append(wait * 1000)
        self.at(finish, self._depart, reverse, kind, identity, payload_bytes, receive, work_bytes)
        return finish

    def _depart(self, reverse, kind, identity, size, receive, work):
        direction = self._dirs[reverse]
        stats = direction.by_kind[kind]
        stats.packets += 1
        stats.record_bytes += size
        stats.wire_bytes += size + self.config.outer_bytes
        if self._erased(reverse, kind, identity):
            stats.erased += 1
            return
        at = self.now + self.config.one_way_ms / 1000
        self.at(at, self._arrive, direction, _Job(at, size, work, receive, stats))

    def _arrive(self, direction: _Direction, job: _Job):
        slots = len(direction.waiting) + direction.active
        if slots >= self.config.decoder_slots:
            job.stats.decoder_queue_drops += 1
            return
        direction.peak_slots = max(direction.peak_slots, slots + 1)
        if direction.active:
            direction.waiting.append(job)
        else:
            self._start(direction, job)

    def _start(self, direction: _Direction, job: _Job):
        work = job.work() if callable(job.work) else job.work
        if type(work) is not int or work < 0:
            raise ValueError("nonnegative integer byte-work count required")
        cfg = self.config
        service = (cfg.service_fixed_us * 1e-6
                   + (cfg.service_record_ns_per_byte * job.size
                      + cfg.service_work_ns_per_byte * work) * 1e-9)
        direction.active = True
        direction.work_bytes += work
        direction.decoder_waits.append((self.now - job.at) * 1000)
        direction.services.append(service * 1000)
        self.at(self.now + service, self._complete, direction, job)

    def _complete(self, direction: _Direction, job: _Job):
        job.stats.serviced += 1
        job.receive()
        direction.active = False
        if direction.waiting:
            self._start(direction, direction.waiting.popleft())

    def serialized_bytes(self, reverse: bool) -> float:
        """Inclusive wire service through now, including a partially serialized packet."""
        direction = self._dirs[reverse]
        remaining = max(0.0, direction.free_at - self.now) * direction.rate
        return max(0.0, direction.reserved - remaining)

    def report(self) -> dict:
        metrics = {}
        for label, direction in zip(("forward", "reverse"), self._dirs):
            kinds = {kind: vars(stats).copy() for kind, stats in direction.by_kind.items()}
            metrics[label] = {
                **{key: sum(row[key] for row in kinds.values()) for key in vars(_Stats())},
                "by_kind": kinds,
                "peak_wire_queue_bytes": direction.peak_wire_bytes,
                "peak_decoder_slots": direction.peak_slots,
                "decoder_in_service": int(direction.active),
                "decoder_waiting": len(direction.waiting),
                "decoder_oldest_pending_wait_ms": (
                    (self.now - direction.waiting[0].at) * 1000 if direction.waiting else None
                ),
                "decoder_work_bytes": direction.work_bytes,
                "wire_queue_wait_ms": _timings(direction.wire_waits),
                "decoder_queue_wait_ms": _timings(direction.decoder_waits),
                "decoder_service_ms": _timings(direction.services),
            }
        return metrics
