"""Causal frame recovery over a caller-supplied, shared, lossy datagram link.

One channel has one ordered release frontier. Each admitted record is an opaque
byte string split into fragments. Optional parity is one zero-extended XOR of
the fragments of that record. Receiver state contains only arrived bytes.
Times in the event interface are seconds.
"""

from collections import Counter
from dataclasses import dataclass, field
from math import ceil, isfinite


@dataclass(frozen=True)
class ChannelConfig:
    channels: int = 4
    window_frames: int = 128
    fragment_bytes: int = 700
    parity: bool = True
    early_request_ms: float | None = 3.0
    rto_ms: float = 180.0
    feedback_delay_ms: float = 1.0
    tag_bytes: int = 16
    request_repeat_ms: float | None = None

    def __post_init__(self):
        for value, lower, limit in ((self.channels, 1, 256), (self.window_frames, 1, 65535),
                                    (self.fragment_bytes, 1, 65535), (self.tag_bytes, 0, 255)):
            if type(value) is not int or not lower <= value <= limit:
                raise ValueError("invalid integer channel configuration")
        if not isfinite(self.rto_ms) or self.rto_ms <= 0:
            raise ValueError("rto_ms must be finite and positive")
        if not isfinite(self.feedback_delay_ms) or self.feedback_delay_ms < 0:
            raise ValueError("feedback_delay_ms must be finite and nonnegative")
        if self.request_repeat_ms is not None and (
            not isfinite(self.request_repeat_ms) or self.request_repeat_ms <= 0
        ):
            raise ValueError("request_repeat_ms must be finite and positive or None")
        if self.early_request_ms is not None and (
            not isfinite(self.early_request_ms) or self.early_request_ms <= 0
        ):
            raise ValueError("early_request_ms must be finite and positive or None")


@dataclass(frozen=True, slots=True)
class Packet:
    kind: str
    channel: int
    sequence: int
    fragment: int
    frame_id: int
    payload: bytes
    attempt: int
    frame_bytes: int = 0
    prefix: int = 0
    tag_bytes: int = 16
    xor_bytes: int = 0

    @property
    def reverse(self):
        return self.kind in ("ack", "request")

    @property
    def wire_bytes(self):
        """Modeled record length. The link adds its own IP/UDP header.

        Data header: kind/channel (2), channel seq (4), global ID (4),
        frame length (2), fragment index (2). Feedback: kind/channel (2),
        channel seq (4), cumulative delivery frontier (4), and for a request
        the requested fragment (2). Attempts and feedback tracing IDs are
        simulation metadata. tag_bytes reserves an authenticated-record budget.
        """
        descriptor = 14
        if self.reverse:
            descriptor = 12 if self.kind == "request" else 10
        return descriptor + self.tag_bytes + len(self.payload)

    @property
    def identity(self):
        identifier = self.frame_id
        if identifier < 0:
            identifier = -1 - (self.sequence * 256 + self.channel)
        return (identifier, self.fragment, self.attempt)


@dataclass(slots=True)
class _Sent:
    frame_id: int
    size: int
    pieces: tuple
    attempts: list
    deadline: float = 0.0


@dataclass(slots=True)
class _Received:
    frame_id: int = -1
    size: int = 0
    pieces: dict = field(default_factory=dict)
    parity: bytes | None = None
    complete: bytes | None = None
    next_request: float | None = None
    requests: Counter = field(default_factory=Counter)
    requested_at: dict = field(default_factory=dict)
    observed: set = field(default_factory=set)


@dataclass(slots=True)
class _Lane:
    send_next: int = 0
    send_prefix: int = 0
    recv_prefix: int = 0
    recv_end: int = 0
    sent: dict = field(default_factory=dict)
    received: dict = field(default_factory=dict)
    ack_pending: dict = field(default_factory=dict)


def _xor(buffers, width):
    result = 0
    for buf in buffers:
        result ^= int.from_bytes(buf, "little")
    return result.to_bytes(width, "little")


class FrameChannels:
    """Finite custody and FIFO delivery in each lane over one physical link.

    transmit(packet, receive) returns the serialized departure time, or None
    for a local drop. All arrivals, including feedback, pass through transmit.
    offer returning False transfers no custody. on_credit(channel) optionally
    wakes the application when the acknowledged send window advances.
    """

    def __init__(self, config, now, at, transmit, deliver, observe=None):
        self.config = config
        self.now = now
        self.at = at
        self.transmit = transmit
        self.deliver = deliver
        self.observe = observe
        self.on_credit = None
        self.metrics = Counter()
        self.lanes = [_Lane() for _ in range(config.channels)]

    def _event(self, name, channel, sequence, piece=-1):
        self.metrics[name] += 1
        if self.observe:
            self.observe(name, channel, sequence, piece)

    @property
    def pending_frames(self):
        return sum(len(lane.sent) for lane in self.lanes)

    def can_offer(self, channel):
        if not 0 <= channel < self.config.channels:
            raise ValueError("invalid channel")
        lane = self.lanes[channel]
        return lane.send_next - lane.send_prefix < self.config.window_frames

    def offer(self, channel, frame_id, payload):
        if not isinstance(payload, bytes) or not 0 < len(payload) <= 65535:
            raise ValueError("expected 1..65535 immutable frame bytes")
        if not 0 <= frame_id < 2**32:
            raise ValueError("invalid frame ID")
        if not self.can_offer(channel):
            self.metrics["window_blocked_offers"] += 1
            return False
        lane = self.lanes[channel]
        seq = lane.send_next
        if seq >= 2**32 - 1:
            raise OverflowError("channel sequence space exhausted")
        lane.send_next += 1
        width = self.config.fragment_bytes
        pieces = tuple(payload[i:i + width] for i in range(0, len(payload), width))
        flight = _Sent(frame_id, len(payload), pieces, [0] * len(pieces))
        lane.sent[seq] = flight
        self._event("admitted", channel, seq)
        finish = max(self._send_piece(channel, seq, flight, i) for i in range(len(pieces)))
        if self.config.parity:
            parity = _xor(pieces, len(pieces[0]))
            work = sum(map(len, pieces))
            packet = Packet("parity", channel, seq, -1, frame_id, parity, 1,
                            len(payload), tag_bytes=self.config.tag_bytes, xor_bytes=work)
            self.metrics["encode_xor_bytes"] += work
            self._tx(packet)
        self._arm_rto(channel, seq, flight, finish)
        return True

    def _tx(self, packet):
        finish = self.transmit(packet, lambda: self._receive(packet))
        if finish is None:
            self.metrics["local_drop_" + packet.kind] += 1
            return self.now()
        return finish

    def _send_piece(self, channel, seq, flight, index):
        flight.attempts[index] += 1
        attempt = flight.attempts[index]
        kind = "source" if attempt == 1 else "retry"
        self._event(kind, channel, seq, index)
        return self._tx(Packet(kind, channel, seq, index, flight.frame_id, flight.pieces[index],
                               attempt, flight.size, tag_bytes=self.config.tag_bytes))

    def _arm_rto(self, channel, seq, flight, finish):
        deadline = finish + self.config.rto_ms / 1000
        flight.deadline = deadline

        self.at(deadline, lambda: self._expire(channel, seq, deadline))

    def _expire(self, channel, seq, deadline):
        flight = self.lanes[channel].sent.get(seq)
        if flight is None or flight.deadline != deadline:
            return
        self._event("rto", channel, seq)
        finish = max(self._send_piece(channel, seq, flight, i)
                     for i in range(len(flight.pieces)))
        self._arm_rto(channel, seq, flight, finish)

    def _receive(self, packet):
        if packet.reverse:
            self._feedback(packet)
            return
        lane = self.lanes[packet.channel]
        seq = packet.sequence
        if seq < lane.recv_prefix:
            self._ack(packet)
            return
        if seq >= lane.recv_prefix + self.config.window_frames:
            raise RuntimeError("packet outside causal receiver custody")
        for skipped in range(lane.recv_end, seq):
            state = _Received()
            lane.received[skipped] = state
            self._gap(packet.channel, skipped, state, 0)
            self._arm_request(packet.channel, skipped, state)
        lane.recv_end = max(lane.recv_end, seq + 1)
        state = lane.received.setdefault(seq, _Received())
        if state.complete is not None:
            self._ack(packet)
            return
        state.size = packet.frame_bytes
        state.frame_id = packet.frame_id
        if packet.kind == "parity":
            if state.parity is not None:
                return
            state.parity = packet.payload
        else:
            if packet.fragment in state.pieces:
                return
            state.pieces[packet.fragment] = packet.payload
        total = ceil(state.size / self.config.fragment_bytes)
        if state.parity is not None and len(state.pieces) == total - 1:
            missing = next(i for i in range(total) if i not in state.pieces)
            length = min(self.config.fragment_bytes, state.size - missing * self.config.fragment_bytes)
            work = len(state.parity) + sum(map(len, state.pieces.values()))
            recovered = _xor((state.parity, *state.pieces.values()), len(state.parity))
            state.pieces[missing] = recovered[:length]
            self.metrics["decode_xor_bytes"] += work
            self._event("fec_recovered", packet.channel, seq, missing)
        if len(state.pieces) == total:
            state.complete = b"".join(state.pieces[i] for i in range(total))
            state.pieces.clear()
            state.parity = None
            self._event("complete", packet.channel, seq)
            while (head := lane.received.get(lane.recv_prefix)) and head.complete is not None:
                completed_seq = lane.recv_prefix
                del lane.received[completed_seq]
                lane.recv_prefix += 1
                self._event("delivered", packet.channel, completed_seq)
                self.deliver(head.frame_id, head.complete)
            self._ack(packet)
            return
        below = total if packet.kind == "parity" else packet.fragment
        for missing in range(below):
            if missing not in state.pieces:
                self._gap(packet.channel, seq, state, missing)
        self._arm_request(packet.channel, seq, state, progress=True)

    def decode_xor_bytes(self, packet):
        """Work at service start if this arrival makes exactly one piece repairable."""
        if packet.reverse or not self.config.parity:
            return 0
        lane = self.lanes[packet.channel]
        state = lane.received.get(packet.sequence)
        if packet.sequence < lane.recv_prefix or (state and state.complete is not None):
            return 0
        pieces = state.pieces if state else {}
        parity = state.parity if state else None
        present_bytes = sum(map(len, pieces.values()))
        count = len(pieces)
        if packet.kind == "parity":
            if parity is not None:
                return 0
            parity = packet.payload
        else:
            if packet.fragment in pieces:
                return 0
            count += 1
            present_bytes += len(packet.payload)
        if parity is None or count + 1 != ceil(packet.frame_bytes / self.config.fragment_bytes):
            return 0
        return len(parity) + present_bytes

    def _gap(self, channel, seq, state, piece):
        if piece not in state.observed:
            state.observed.add(piece)
            self._event("gap_observed", channel, seq, piece)

    def _arm_request(self, channel, seq, state, progress=False):
        delay = self.config.early_request_ms
        if delay is None:
            return
        earliest = self.now() + delay / 1000
        if state.next_request is not None and not progress:
            return
        if state.next_request == earliest:
            return
        state.next_request = earliest
        self.at(earliest, lambda: self._request(channel, seq, earliest))

    def _request(self, channel, seq, deadline):
        lane = self.lanes[channel]
        state = lane.received.get(seq)
        if state is None or state.complete is not None or deadline != state.next_request:
            return
        total = ceil(state.size / self.config.fragment_bytes) if state.size else 1
        repeat_ms = self.config.request_repeat_ms
        again = (self.config.rto_ms if repeat_ms is None else repeat_ms) / 1000
        next_due = float("inf")
        for index in range(total):
            if index in state.pieces:
                continue
            if state.requested_at.get(index, float("-inf")) + again <= self.now():
                self._gap(channel, seq, state, index)
                state.requests[index] += 1
                state.requested_at[index] = self.now()
                self._event("request", channel, seq, index)
                self._tx(Packet("request", channel, seq, index, state.frame_id, b"",
                                state.requests[index], prefix=lane.recv_prefix,
                                tag_bytes=self.config.tag_bytes))
            next_due = min(next_due, state.requested_at[index] + again)
        state.next_request = next_due
        self.at(next_due, lambda: self._request(channel, seq, next_due))

    def _ack(self, packet):
        channel, seq = packet.channel, packet.sequence
        lane = self.lanes[channel]
        if seq in lane.ack_pending:
            return
        lane.ack_pending[seq] = True

        def flush():
            del lane.ack_pending[seq]
            self._event("ack", channel, seq)
            self._tx(Packet("ack", channel, seq, packet.fragment, packet.frame_id, b"",
                            packet.attempt,
                            prefix=lane.recv_prefix, tag_bytes=self.config.tag_bytes))

        self.at(self.now() + self.config.feedback_delay_ms / 1000, flush)

    def _feedback(self, packet):
        lane = self.lanes[packet.channel]
        previous = lane.send_prefix
        for seq in range(previous, packet.prefix):
            lane.sent.pop(seq, None)
        lane.send_prefix = max(previous, packet.prefix)
        if packet.kind == "ack":
            lane.sent.pop(packet.sequence, None)
        else:
            flight = lane.sent.get(packet.sequence)
            index = packet.fragment
            if flight is not None:
                finish = self._send_piece(packet.channel, packet.sequence, flight, index)
                self._arm_rto(packet.channel, packet.sequence, flight, finish)
        if lane.send_prefix > previous and self.on_credit:
            self.on_credit(packet.channel)
