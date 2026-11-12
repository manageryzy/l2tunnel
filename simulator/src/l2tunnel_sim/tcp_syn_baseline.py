"""Fresh TCP handshakes over native TCP links or an existing QUIC L2 connection."""

from collections import defaultdict, deque
from struct import Struct
from types import SimpleNamespace

from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamDataReceived
from aioquic.quic.rangeset import RangeSet

from .compact_tcp import CompactTCP
from .quic import IP_UDP_BYTES, QUIC
from .tcp import ETHERNET_BYTES, PlainTCP
from .tcp_syn_probe import EVENT_HEADER, SYNProbeConfig, TCPHandshakeProbe, handshake_frame


CONTROL_STREAM = 4  # Client-initiated bidirectional stream on the existing connection.
RECORD_LENGTH = Struct("!H")


def range_prefix(ranges):
    return ranges[0].stop if len(ranges) and ranges[0].start == 0 else 0


class ProbeQUIC(QUIC):
    """Keep bulk stream zero intact and carry framed control records on stream four.

    Both streams use the same established QUIC connection, congestion controller,
    connection flow control, packet scheduler, physical queues and erasures.
    qlog offsets are tracked separately so control records cannot become bulk data.
    """

    def __init__(self, *args, **kwargs):
        self.control_started = False
        self.stream_sent_ends = [defaultdict(int), defaultdict(int)]
        self.control_packets = [{}, {}]
        self.control_acknowledged = [RangeSet(), RangeSet()]
        self.control_submitted = [0, 0]
        self.control_received = [0, 0]
        self.control_callbacks = [deque(), deque()]
        self.control_buffers = [bytearray(), bytearray()]
        self.control_retransmitted = [0, 0]
        self.control_departed_datagrams = [0, 0]
        self.control_departed_packet_bytes = [0, 0]
        super().__init__(*args, **kwargs)
        if not self.strategy.quic_l2:
            raise ValueError("TCP handshake adapter requires QUIC L2 mode")

    def submit_control(self, reverse, body, callback):
        body = bytes(body)
        if not body or len(body) > 65535:
            raise ValueError("QUIC control record length must fit a nonzero uint16")
        self.control_started = True
        encoded = RECORD_LENGTH.pack(len(body)) + body
        self.control_callbacks[reverse].append(callback)
        self.control_submitted[reverse] += len(encoded)
        self.connections[reverse].send_stream_data(CONTROL_STREAM, encoded)
        self.flush(reverse)

    def flush(self, reverse):
        if self.warming_up:
            return super().flush(reverse)
        connection = self.connections[reverse]
        datagrams = connection.datagrams_to_send(now=self.protocol_time)
        trace = self.loggers[reverse].trace
        packets = list(trace.sent)
        trace.sent.clear()
        if len(datagrams) != len(packets):
            raise RuntimeError("unexpected QUIC packet coalescing after warmup")
        for (data, _), packet in zip(datagrams, packets):
            streams = [frame for frame in packet["frames"] if frame["frame_type"] == "stream"]
            bulk = [frame for frame in streams if frame["stream_id"] == 0]
            control = [frame for frame in streams if frame["stream_id"] == CONTROL_STREAM]
            if len(bulk) + len(control) != len(streams):
                raise ValueError("unexpected stream in QUIC handshake adapter")
            number = packet["header"]["packet_number"]
            if not reverse:
                self.sent_packets[number] = bulk
            if control:
                self.control_packets[reverse][number] = [
                    (frame["offset"], frame["offset"] + frame["length"]) for frame in control if frame["length"]]
            repeated = defaultdict(int)
            for frame in streams:
                stream = frame["stream_id"]
                repeated[stream] += min(frame["length"], max(0, self.stream_sent_ends[reverse][stream] - frame["offset"]))
                self.stream_sent_ends[reverse][stream] = max(
                    self.stream_sent_ends[reverse][stream], frame["offset"] + frame["length"])
            if not reverse:
                self.stream_sent_end = self.stream_sent_ends[False][0]
            kind = "retry" if sum(repeated.values()) else "source" if streams else "feedback"
            self.send_datagram(reverse, data, kind, repeated[0] if not reverse else 0)
            if control:
                self.at(self.links[reverse][0].free_at, self.record_control_departure,
                        reverse, len(data) + IP_UDP_BYTES, repeated[CONTROL_STREAM])
        self.quic_cwnd_bytes = self.loggers[False].trace.congestion_window
        self.timer_versions[reverse] += 1
        when = connection.get_timer()
        if when is not None:
            self.at(max(when - self.clock_offset, self.now + 1e-9),
                    self.on_timer, reverse, self.timer_versions[reverse])

    def record_control_departure(self, reverse, size, repeated):
        self.control_departed_datagrams[reverse] += 1
        self.control_departed_packet_bytes[reverse] += size
        self.control_retransmitted[reverse] += repeated

    def observe_packet(self, reverse, packet):
        # Preserve the established bulk observer, including its cumulative credit.
        bulk_packet = dict(packet, frames=[frame for frame in packet["frames"]
            if frame["frame_type"] != "stream" or frame["stream_id"] == 0])
        super().observe_packet(reverse, bulk_packet)
        for frame in packet["frames"]:
            if frame["frame_type"] != "ack":
                continue
            for number in list(self.control_packets[reverse]):
                if any(low <= number <= high for low, high in frame["acked_ranges"]):
                    for start, end in self.control_packets[reverse].pop(number):
                        self.control_acknowledged[reverse].add(start, end)

    def receive_control(self, reverse, data):
        sender = not reverse
        self.control_received[sender] += len(data)
        buffer = self.control_buffers[reverse]
        buffer.extend(data)
        while len(buffer) >= RECORD_LENGTH.size:
            size, = RECORD_LENGTH.unpack_from(buffer)
            if not size:
                raise ValueError("empty QUIC control record")
            end = RECORD_LENGTH.size + size
            if len(buffer) < end:
                break
            body = bytes(buffer[RECORD_LENGTH.size:end])
            del buffer[:end]
            if not self.control_callbacks[sender]:
                raise ValueError("unexpected QUIC control record")
            callback = self.control_callbacks[sender].popleft()
            callback(body)

    def handle_events(self, reverse):
        if not self.control_started:
            return super().handle_events(reverse)
        while (event := self.connections[reverse].next_event()) is not None:
            if isinstance(event, HandshakeCompleted):
                self.handshakes[reverse] = True
            elif isinstance(event, ConnectionTerminated):
                raise RuntimeError(f"QUIC connection terminated: {event.error_code} {event.reason_phrase}")
            elif isinstance(event, StreamDataReceived):
                if event.stream_id == CONTROL_STREAM:
                    self.receive_control(reverse, event.data)
                    continue
                if event.stream_id != 0 or not reverse:
                    raise ValueError("unexpected bulk stream event")
                self.stream_received_bytes += len(event.data)
                received = self.stream_received_bytes // self.record_bytes
                advanced = received - self.tcp_received
                for index in range(self.tcp_received, received):
                    self.forward.delays.append((self.now - self.sent_times[index]) * 1000)
                self.forward.delivered_bytes += advanced * self.traffic.frame_bytes
                if self.now <= self.traffic.duration_s:
                    self.tcp_payload_bytes += advanced * self.traffic.payload_bytes
                    self.forward.delivered_during_measurement_bytes += advanced * self.traffic.frame_bytes
                self.tcp_received = received
        if reverse and not self.warming_up:
            buffered = sum(part.stop - max(part.start, self.stream_received_bytes)
                           for part in self.received_ranges if part.stop > self.stream_received_bytes)
            self.forward.peak_reorder_bytes = max(self.forward.peak_reorder_bytes, buffered)

    @property
    def control_confirmed(self):
        return (not any(self.control_callbacks) and not any(self.control_buffers)
                and all(range_prefix(self.control_acknowledged[direction]) == self.control_submitted[direction]
                        for direction in (False, True)))


class BaselineHandshakeProbe(TCPHandshakeProbe):
    """Reuse the frozen handshake state and stability gate with baseline routing."""

    def __init__(self, simulation, config=SYNProbeConfig(), **kwargs):
        if config.reverse_copies != 1:
            raise ValueError("baseline probes use one native TCP response or one reliable QUIC record")
        self.quic = isinstance(simulation.flows[0], ProbeQUIC)
        expected = ProbeQUIC if self.quic else PlainTCP
        if any(not isinstance(flow, expected) or hasattr(flow, "compact_config") for flow in simulation.flows):
            raise ValueError("baseline probes require homogeneous native TCP or ProbeQUIC flows")
        # The parent only uses the shared endpoint for its default transmit path.
        adapter = SimpleNamespace(flows=[simulation.flows[0]], shared_forward=None)
        self.forward_requested_bytes = 0
        super().__init__(adapter, config, **kwargs)
        self.simulation = simulation

    def send_forward(self, probe, flags):
        frame = handshake_frame(probe, reverse=False, flags=flags,
                                timestamp=int(self.sim.now * 1000), identification=self.packet_id)
        self.packet_id += 1
        self.forward_frames += 1
        self.forward_frame_bytes += len(frame)
        if self.quic:
            self.sim.submit_control(False, frame, self.receive_forward_frame)
        else:
            self.forward_requested_bytes += len(frame) - ETHERNET_BYTES
            self.sim.send(False, len(frame) - ETHERNET_BYTES, "syn_probe", lambda: self.receive_forward_frame(frame))

    def send_reverse_copy(self, probe, body):
        if self.quic:
            self.sim.submit_control(True, body, self.receive_reverse_body)
        else:
            # Native TCP carries its IP/TCP frame. The legacy event envelope is
            # local bookkeeping. Received TCP headers determine the endpoint.
            size = len(body) - EVENT_HEADER.size - ETHERNET_BYTES
            self.reverse_requested_bytes += size
            self.sim.send(True, size, "syn_probe", lambda: self.receive_reverse_body(body))

    def measurements(self):
        row = super().measurements()
        row["tcp_syn_probe_transport"] = "existing QUIC connection, auxiliary reliable stream 4" if self.quic else "native IPv4 TCP"
        row["tcp_syn_probe_outer_connection_index"] = 0 if self.quic else None
        if self.quic:
            row["tcp_syn_probe_all_flushed"] = self.sim.control_confirmed
            for key in ("reverse_requested_bytes", "reverse_departed_bytes", "reverse_datagrams", "reverse_erasures"):
                row["tcp_syn_probe_" + key] = None
            for direction, label in ((False, "forward"), (True, "reverse")):
                row[f"tcp_syn_probe_{label}_quic_stream_submitted_bytes"] = self.sim.control_submitted[direction]
                row[f"tcp_syn_probe_{label}_quic_stream_received_bytes"] = self.sim.control_received[direction]
                row[f"tcp_syn_probe_{label}_quic_stream_acknowledged_bytes"] = range_prefix(self.sim.control_acknowledged[direction])
                row[f"tcp_syn_probe_{label}_quic_stream_retransmitted_bytes"] = self.sim.control_retransmitted[direction]
                row[f"tcp_syn_probe_{label}_quic_containing_datagrams"] = self.sim.control_departed_datagrams[direction]
                row[f"tcp_syn_probe_{label}_quic_containing_packet_bytes"] = self.sim.control_departed_packet_bytes[direction]
            row["tcp_syn_probe_wire_accounting"] = "All QUIC IP bytes are charged in shared-link totals; packets containing control can also contain bulk or QUIC ACK frames"
            row["tcp_syn_probe_model_detail"] = (
                "Probe Ethernet frame bytes are serialized, encrypted, reassembled and parsed through the existing QUIC connection. "
                "Received IP addresses, TCP ports and flags dispatch endpoint state. Bulk traffic retains fixed-length L2-equivalent records.")
        else:
            row["tcp_syn_probe_forward_requested_bytes"] = self.forward_requested_bytes
            row["tcp_syn_probe_forward_departed_bytes"] = self.sim.wire[False]["syn_probe"]
            row["tcp_syn_probe_all_flushed"] = bool(row["tcp_syn_probe_all_flushed"]
                and self.forward_requested_bytes == self.sim.wire[False]["syn_probe"])
            row["tcp_syn_probe_wire_accounting"] = "Each native timestamp-only IPv4/TCP SYN, SYN-ACK, final ACK and reset costs 52 IP bytes"
            row["tcp_syn_probe_model_detail"] = (
                "The simulated native link carries complete materialized frame bytes in its receive event after charged IP serialization, erasure and propagation. "
                "Received IP addresses, TCP ports and flags dispatch endpoint state.")
        return row


def compact_confirmed(transport):
    return (not transport.pending and not transport.buffer_bytes and not transport.records)


class CompactHandshakeProbe(TCPHandshakeProbe):
    """Send probe records through bulk flow zero's existing ordered transport.

    This retains CompactTransport's length-and-GF256-rank payload model. The
    complete serialized Ethernet frames enter its reversible header codec, and
    callbacks wait for all ordered record bytes. Bulk/probe context switches,
    sources, repairs and transport feedback all use the existing wire accounting.
    """

    def __init__(self, simulation, config=SYNProbeConfig(), **kwargs):
        if config.reverse_copies != 1:
            raise ValueError("compact baseline probes use one native response or one reliable record")
        if any(not isinstance(flow, CompactTCP) for flow in simulation.flows):
            raise ValueError("compact probes require homogeneous CompactTCP flows")
        self.quic = False
        self.compact_probe_records = [0, 0]
        self.compact_probe_delivered = [0, 0]
        self.compact_probe_record_bytes = [0, 0]
        self.compact_probe_context_bytes = [0, 0]
        adapter = SimpleNamespace(flows=[simulation.flows[0]], shared_forward=None)
        super().__init__(adapter, config, **kwargs)
        self.simulation = simulation

    def submit_record(self, reverse, frame, callback):
        transport = self.sim.compact_reverse if reverse else self.sim.compact_forward
        before_record = transport.source_record_bytes
        before_context = transport.profile_context_bytes
        self.compact_probe_records[reverse] += 1

        def delivered():
            self.compact_probe_delivered[reverse] += 1
            callback(frame)

        transport.submit(len(frame), 0, delivered, frame=frame)
        self.compact_probe_record_bytes[reverse] += transport.source_record_bytes - before_record
        self.compact_probe_context_bytes[reverse] += transport.profile_context_bytes - before_context

    def send_forward(self, probe, flags):
        frame = handshake_frame(probe, reverse=False, flags=flags,
                                timestamp=int(self.sim.now * 1000), identification=self.packet_id)
        self.packet_id += 1
        self.forward_frames += 1
        self.forward_frame_bytes += len(frame)
        self.submit_record(False, frame, self.receive_forward_frame)

    def send_reverse_copy(self, probe, body):
        frame = body[EVENT_HEADER.size:]
        if self.sim.reliable_acks:
            self.submit_record(True, frame, lambda received: self.receive_reverse_body(EVENT_HEADER.pack(0) + received))
        else:
            size = len(frame) + self.sim.compact_config.outer_header_bytes + self.sim.compact_config.authentication_bytes
            self.reverse_requested_bytes += size
            self.sim.send(True, size, "syn_probe", lambda: self.receive_reverse_body(body))

    def measurements(self):
        row = super().measurements()
        row["tcp_syn_probe_transport"] = "existing compact ordered record stream on bulk flow 0"
        row["tcp_syn_probe_outer_connection_index"] = 0
        row["tcp_syn_probe_reverse_policy"] = "reliable compact record" if self.sim.reliable_acks else "native full-frame tunnel"
        row["tcp_syn_probe_all_flushed"] = bool(row["tcp_syn_probe_all_flushed"]
            and self.compact_probe_delivered == self.compact_probe_records
            and compact_confirmed(self.sim.compact_forward)
            and compact_confirmed(self.sim.compact_reverse))
        for direction, label in ((False, "forward"), (True, "reverse")):
            row[f"tcp_syn_probe_{label}_compact_records"] = self.compact_probe_records[direction]
            row[f"tcp_syn_probe_{label}_compact_delivered_records"] = self.compact_probe_delivered[direction]
            row[f"tcp_syn_probe_{label}_compact_record_bytes"] = self.compact_probe_record_bytes[direction]
            row[f"tcp_syn_probe_{label}_compact_context_bytes"] = self.compact_probe_context_bytes[direction]
        row["tcp_syn_probe_wire_accounting"] = (
            "Probe and bulk records share flow 0's ordered compact stream and header context. "
            "All actual source, repair and feedback IP bytes are charged in shared-link totals. "
            "Probe record/context bytes are stream contributions, not additive IP service. "
            "The inherited transport models payload lengths and GF256 rank, with serialized reversible TCP headers.")
        row["tcp_syn_probe_model_detail"] = (
            "Historical compact transport retains its length/GF256-rank model and materializes the submitted frame after ordered completion. "
            "The materialized received frame then selects endpoint state by parsed IP addresses, TCP ports and flags.")
        return row
