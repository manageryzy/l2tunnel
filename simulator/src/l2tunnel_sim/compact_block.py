"""Compact GF(256) generations with feedback-driven degree-of-freedom repair."""

from dataclasses import dataclass, field
from math import ceil

from .compact import CompactConfig, CompactSource, CompactTransport, coefficient


@dataclass(frozen=True)
class CompactBlockConfig(CompactConfig):
    generation_sources: int = 100
    idle_flush_ms: float = 2
    maximum_block_ms: float = 50
    assumed_loss_rate: float = .15
    repair_margin: int = 0

    def __post_init__(self):
        super().__post_init__()
        if not 1 <= self.generation_sources <= 65535:
            raise ValueError('generation_sources must fit a 16-bit count')
        if self.idle_flush_ms <= 0 or self.maximum_block_ms <= 0:
            raise ValueError('block flush intervals must be positive')
        if not 0 <= self.assumed_loss_rate < 1:
            raise ValueError('assumed_loss_rate must be in [0, 1)')
        if self.repair_margin < 0 or not isinstance(self.repair_margin, int):
            raise ValueError('repair_margin must be a nonnegative integer')
        if self.coding != 'gf256':
            raise ValueError('compact block transport uses actual GF256 equations')


@dataclass
class SendingBlock:
    start: int
    end: int
    closed: bool = False
    last_source_finish: float = 0
    last_source_serial: int = 0
    reported_degrees: int = 0
    report_received: bool = False
    latest_report_serial: int = 0
    reported_packet_serial: int = 0
    latest_repair_seen: int = 0
    inflight: dict = field(default_factory=dict)
    timer_generation: int = 0
    idle_generation: int = 0


@dataclass
class ReceivingBlock:
    start: int
    end: int
    sealed: bool = False
    latest_repair_seen: int = 0


class CompactBlockTransport(CompactTransport):
    """Reliable record delivery using bounded generations and lossy rank ACKs.

    The source header contains a source ID, generation-start ID, and packet serial. Repair
    packets use the existing 12-byte window/seed coding header. Feedback has
    44 IPv4/UDP/header bytes including an echoed packet serial, and a 12-byte entry for each generation, comprising
    its start, source count, received degrees, and latest repair serial.
    ``assumed_loss_rate`` is an explicit configured loss estimate, never a read
    of the simulator's erasure process. No native TCP timers are changed.
    """

    def __init__(self, sim, reverse, config=CompactBlockConfig()):
        if not isinstance(config, CompactBlockConfig):
            raise TypeError('CompactBlockTransport requires CompactBlockConfig')
        super().__init__(sim, reverse, config)
        self.source_header += 4
        self.sending_blocks = {}
        self.receiving_blocks = {}
        self.current_block = None
        self.feedback_serial = 0
        self.feedback_cursor = 0
        self.repair_serial = 0
        self.packet_serial = 0
        self.received_packet_serial = 0
        self.confirmed_packet_serial = 0
        self.initial_repairs = 0
        self.additional_repairs = 0
        self.code_blocks = []
        self.nominal_rtt = max(link.rtt for link in sim.links[reverse])

    def _source(self, size):
        self.buffer_bytes -= size
        self.sent_bytes += size
        source = CompactSource(len(self.sources), size, self.sent_bytes)
        self.sources.append(source)
        if self.current_block is None:
            block = SendingBlock(source.index, source.index)
            self.current_block = block
            self.sending_blocks[block.start] = block
            self.sim.at(self.sim.now + self.config.maximum_block_ms / 1000,
                        self._close_if_current, block.start)
        block = self.current_block
        block.end = source.index + 1
        self.packet_serial += 1
        serial = self.packet_serial
        finish, _ = self.sim.send(
            self.reverse, self.source_header + 2 + source.size, 'source',
            lambda: self._receive_source(source, block.start, serial),
        )
        block.last_source_finish = finish
        block.last_source_serial = serial
        block.idle_generation += 1
        self.sim.at(self.sim.now + self.config.idle_flush_ms / 1000,
                    self._close_if_current, block.start, block.idle_generation)
        if block.end - block.start == self.config.generation_sources:
            self._close_if_current(block.start)

    def _close_if_current(self, start, generation=None):
        block = self.current_block
        if block is None or block.start != start:
            return
        if generation is not None and generation != block.idle_generation:
            return
        block.closed = True
        self.current_block = None
        size = block.end - block.start
        self.code_blocks.append(size)
        count = ceil(size * self.config.repair_ratio)
        self._send_repairs(block, count, initial=True)
        self._arm_block(block)

    def _guard(self):
        return max(self.nominal_rtt + 2 * self.config.feedback_ms / 1000, .005)

    def _arm_block(self, block):
        block.timer_generation += 1
        latest = max(block.inflight.values(), default=block.last_source_finish)
        when = max(self.sim.now + self._guard(), latest + self._guard())
        self.sim.at(when, self._block_timeout, block.start, block.timer_generation)

    def _send_repairs(self, block, count, *, initial=False):
        start, end = block.start, block.end
        size = max(source.size for source in self.sources[start:end]) + 2
        for _ in range(count):
            self.repair_serial += 1
            self.packet_serial += 1
            serial = self.packet_serial
            finish, _ = self.sim.send(
                self.reverse, self.repair_header + size, 'repair',
                lambda serial=serial: self._receive_repair(start, end, serial),
            )
            block.inflight[serial] = finish
        if initial:
            self.initial_repairs += count
            self.scheduled_repairs += count
        else:
            self.additional_repairs += count
            self.tail_repairs += count

    def _recover(self, block):
        if not block.closed or block.reported_packet_serial < block.last_source_serial:
            return
        block.inflight = {
            serial: finish for serial, finish in block.inflight.items()
            if serial > block.reported_packet_serial
        }
        if not block.report_received:
            count = 0 if block.inflight else 1
        else:
            deficit = block.end - block.start - block.reported_degrees
            uncovered = max(0, deficit - len(block.inflight))
            count = (ceil(uncovered / (1 - self.config.assumed_loss_rate))
                     + self.config.repair_margin) if uncovered else 0
        if count:
            self._send_repairs(block, count)
            self._arm_block(block)

    def _block_timeout(self, start, generation):
        block = self.sending_blocks.get(start)
        if block is None or block.timer_generation != generation:
            return
        before = block.timer_generation
        self._recover(block)
        if block.timer_generation == before:
            # A probe advances the receiver's echoed serial when the last
            # repair or its feedback was lost. It bounds stale-feedback cost.
            self._send_repairs(block, 1)
            self._arm_block(block)

    def _receive_source(self, source, start, serial=0):
        self.received_packet_serial = max(self.received_packet_serial, serial)
        block = self.receiving_blocks.get(start)
        if block is None:
            block = ReceivingBlock(start, source.index + 1)
            self.receiving_blocks[start] = block
        block.end = max(block.end, source.index + 1)
        self.highest_received = max(self.highest_received, source.index)
        self.received_source.add(source.index)
        self._new_known(self.decoder.insert({source.index: 1}))
        self._advance()

    def _receive_repair(self, start, end, serial):
        self.received_packet_serial = max(self.received_packet_serial, serial)
        block = self.receiving_blocks.setdefault(start, ReceivingBlock(start, end))
        block.end, block.sealed = end, True
        block.latest_repair_seen = max(block.latest_repair_seen, serial)
        self.highest_received = max(self.highest_received, end - 1)
        coefficients = {index: coefficient(serial, index) for index in range(start, end)
                        if index not in self.decoder.known}
        self._new_known(self.decoder.insert(coefficients))
        self._advance()

    def _feedback(self, generation=None):
        if generation is not None and generation != self.feedback_generation:
            return
        self.feedback_generation += 1
        self.feedback_pending = False
        self.feedback_events = 0
        self.feedback_serial += 1
        feedback_serial = self.feedback_serial
        prefix = self.received_prefix
        self.receiving_blocks = {
            start: block for start, block in self.receiving_blocks.items()
            if block.end > prefix or (not block.sealed and block.end == prefix)
        }
        capacity = (self.sim.scenario.mtu - 44 - self.config.authentication_bytes) // 12
        starts = sorted(self.receiving_blocks)
        if self.feedback_cursor >= len(starts):
            self.feedback_cursor = 0
        selected = starts[self.feedback_cursor:self.feedback_cursor + capacity]
        self.feedback_cursor += len(selected)
        entries = []
        pivots = tuple(self.decoder.rows)
        for start in selected:
            block = self.receiving_blocks[start]
            known = sum(index in self.decoder.known for index in range(start, block.end))
            rank = sum(start <= pivot < block.end for pivot in pivots)
            entries.append((start, block.end - start, known + rank, block.latest_repair_seen))
        echo = self.received_packet_serial
        self.sim.send(
            not self.reverse, 44 + self.config.authentication_bytes + 12 * len(entries),
            'feedback', lambda: self._receive_feedback(prefix, entries, feedback_serial, echo),
        )

    def _receive_feedback(self, prefix, entries, feedback_serial, echo=0):
        self.confirmed_packet_serial = max(self.confirmed_packet_serial, echo)
        self.base = max(self.base, prefix)
        for start, block in list(self.sending_blocks.items()):
            if block.closed and block.end <= prefix:
                del self.sending_blocks[start]
        for start, _, degrees, latest_repair in entries:
            block = self.sending_blocks.get(start)
            if block is None or feedback_serial <= block.latest_report_serial:
                continue
            block.latest_report_serial = feedback_serial
            block.reported_packet_serial = echo
            block.report_received = True
            block.reported_degrees = max(block.reported_degrees, degrees)
            block.latest_repair_seen = max(block.latest_repair_seen, latest_repair)
            if block.closed and block.reported_degrees >= block.end - block.start:
                del self.sending_blocks[start]
            else:
                self._recover(block)
        self._flush_full()
        self._schedule_flush()
