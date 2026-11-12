"""Run aioquic over the simulator's duplex IP links without sockets.

An isolated lossless warmup establishes TLS and QUIC before measurement.
Only public connection APIs and qlog events are used to drive the stack.
Each application record is a complete Ethernet frame in quic_l2 mode.
"""

from collections import deque
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from heapq import heappop
import ssl

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamDataReceived
from aioquic.quic.logger import QuicLogger, QuicLoggerTrace
from aioquic.quic.packet import pull_quic_header
from aioquic.quic.rangeset import RangeSet
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .model import Simulation
from .tcp import EndpointStats


IP_UDP_BYTES = 28
CLIENT_ADDRESS = ("192.0.2.1", 12345)
SERVER_ADDRESS = ("192.0.2.2", 4433)


@lru_cache(maxsize=1)
def _certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "simulator.invalid")])
    start = datetime(2020, 1, 1, tzinfo=timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(start).not_valid_after(start + timedelta(days=36500))
                   .sign(key, hashes.SHA256()))
    return certificate, key


class PacketTrace(QuicLoggerTrace):
    """Retain only events needed for byte accounting and application credit."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.sent = deque()
        self.received = deque()
        self.congestion_window = 0

    def log_event(self, *, category, event, data):
        if category == "transport" and event == "packet_sent":
            self.sent.append(data)
        elif category == "transport" and event == "packet_received":
            # aioquic appends decoded frames to this object during receive_datagram.
            self.received.append(data)
        elif category == "recovery" and event == "metrics_updated":
            self.congestion_window = data.get("cwnd", self.congestion_window)


class PacketLogger(QuicLogger):
    def start_trace(self, is_client, odcid):
        self.trace = PacketTrace(is_client=is_client, odcid=odcid)
        return self.trace

    def end_trace(self, trace):
        pass


class QUIC(Simulation):
    def __init__(self, scenario, traffic, paths, strategy, seed):
        if scenario.mtu < 1228:
            raise ValueError("QUIC requires an IPv4 MTU of at least 1228 bytes")
        if strategy.tcp_path >= len(paths):
            raise ValueError("QUIC path index out of range")
        super().__init__(scenario, traffic, paths, strategy, seed)
        self.links = [[direction[strategy.tcp_path]] for direction in self.links]
        self.record_bytes = traffic.frame_bytes if strategy.quic_l2 else traffic.payload_bytes
        self.record = bytes(self.record_bytes)
        self.window_limit = traffic.window_bytes // traffic.payload_bytes
        self.loggers = [PacketLogger(), PacketLogger()]
        self.connections = [QuicConnection(configuration=self.configuration(False)), None]
        self.timer_versions = [0, 0]
        self.handshakes = [False, False]
        self.sent_packets = {}
        self.acknowledged_ranges = RangeSet()
        self.received_ranges = RangeSet()
        self.stream_sent_end = 0
        self.stream_received_bytes = 0
        self.quic_retransmitted_stream_bytes = 0
        self.quic_cwnd_bytes = 0
        self.warming_up = True
        self.now = -max(10.0, self.links[False][0].rtt * 100)
        self.clock_offset = 1.0 - self.now
        for direction in self.links:
            direction[0].free_at = self.now
        self.connections[False].connect(SERVER_ADDRESS, now=self.protocol_time)
        self.flush(False)
        while self.events:
            self.now, _, callback, args = heappop(self.events)
            callback(*args)
        if not all(self.handshakes):
            raise RuntimeError("QUIC warmup did not establish both endpoints")
        self.now = 0.0
        for direction in self.links:
            direction[0].free_at = 0.0
        self.warming_up = False

    @property
    def protocol_time(self):
        # aioquic initializes congestion and pacing timestamps at zero.
        # Keep its clock positive and monotonic across the isolated warmup.
        return self.now + self.clock_offset

    def configuration(self, reverse):
        stream_window = self.window_limit * self.record_bytes
        config = QuicConfiguration(
            is_client=not reverse, alpn_protocols=["l2-simulator"],
            congestion_control_algorithm=self.strategy.tcp_cc,
            max_datagram_size=self.scenario.mtu - IP_UDP_BYTES,
            max_data=stream_window,
            max_stream_data=stream_window,
            idle_timeout=max(600.0, self.stop_at * 2),
            quic_logger=self.loggers[reverse],
        )
        if reverse:
            config.certificate, config.private_key = _certificate()
        else:
            # Both endpoints are created in-process with the certificate above.
            config.verify_mode = ssl.CERT_NONE
        return config

    def make_transports(self, rng):
        return EndpointStats(), EndpointStats()

    def produce(self):
        self.source_timer = None
        while self.now < self.traffic.duration_s and len(self.forward.pending) < self.window_limit:
            if self.next_source > self.now:
                self.source_timer = self.next_source
                self.at(self.next_source, self.produce)
                break
            index = len(self.sent_times)
            self.sent_times.append(self.now)
            self.forward.pending[index] = True
            self.forward.pending_bytes += self.traffic.payload_bytes
            self.forward.peak_pending_bytes = max(self.forward.peak_pending_bytes,
                                                  self.forward.pending_bytes)
            self.connections[False].send_stream_data(0, self.record)
            self.next_source = self.now + self.traffic.frame_interval_ms / 1000
        self.flush(False)

    def flush(self, reverse):
        connection = self.connections[reverse]
        datagrams = connection.datagrams_to_send(now=self.protocol_time)
        trace = self.loggers[reverse].trace
        packets = list(trace.sent)
        trace.sent.clear()
        if self.warming_up:
            for data, _ in datagrams:
                self.send_datagram(reverse, data, "feedback", 0)
        else:
            # Established 1-RTT datagrams contain one QUIC packet each.
            if len(datagrams) != len(packets):
                raise RuntimeError("unexpected QUIC packet coalescing after warmup")
            for (data, _), packet in zip(datagrams, packets):
                streams = [frame for frame in packet["frames"]
                           if frame["frame_type"] == "stream"]
                repeated = 0
                if not reverse:
                    number = packet["header"]["packet_number"]
                    self.sent_packets[number] = streams
                    for frame in streams:
                        repeated += min(frame["length"], max(0, self.stream_sent_end - frame["offset"]))
                        self.stream_sent_end = max(self.stream_sent_end, frame["offset"] + frame["length"])
                kind = "retry" if repeated else "source" if streams else "feedback"
                self.send_datagram(reverse, data, kind, repeated)
        self.quic_cwnd_bytes = self.loggers[False].trace.congestion_window
        self.timer_versions[reverse] += 1
        when = connection.get_timer()
        if when is not None:
            when -= self.clock_offset
            self.at(max(when, self.now + 1e-9), self.on_timer, reverse, self.timer_versions[reverse])

    def send_datagram(self, reverse, data, kind, repeated):
        def receive():
            self.receive_datagram(not reverse, data)

        size = len(data) + IP_UDP_BYTES
        if self.warming_up:
            link = self.links[reverse][0]
            finish = link.finish(self.now, size)
            link.free_at = finish
            self.at(finish + link.rtt / 2, receive)
        else:
            finish, _ = self.send(reverse, size, kind, receive)
            if repeated:
                self.at(finish, self.record_retransmission, repeated)

    def record_retransmission(self, size):
        self.quic_retransmitted_stream_bytes += size

    def on_timer(self, reverse, version):
        if version == self.timer_versions[reverse]:
            self.connections[reverse].handle_timer(now=self.protocol_time)
            self.flush(reverse)
            self.handle_events(reverse)

    def receive_datagram(self, reverse, data):
        if self.connections[reverse] is None:
            header = pull_quic_header(Buffer(data=data), host_cid_length=8)
            self.connections[reverse] = QuicConnection(
                configuration=self.configuration(reverse),
                original_destination_connection_id=header.destination_cid,
            )
        address = CLIENT_ADDRESS if reverse else SERVER_ADDRESS
        self.connections[reverse].receive_datagram(data, address, now=self.protocol_time)
        trace = self.loggers[reverse].trace
        while trace.received:
            packet = trace.received.popleft()
            if not self.warming_up:
                self.observe_packet(reverse, packet)
        self.handle_events(reverse)
        self.flush(reverse)
        if not reverse and not self.warming_up and self.source_timer is None:
            self.produce()

    def observe_packet(self, reverse, packet):
        for frame in packet["frames"]:
            if reverse and frame["frame_type"] == "stream" and frame["length"]:
                self.received_ranges.add(frame["offset"], frame["offset"] + frame["length"])
            elif not reverse and frame["frame_type"] == "ack":
                for number in list(self.sent_packets):
                    if any(low <= number <= high for low, high in frame["acked_ranges"]):
                        for stream in self.sent_packets.pop(number):
                            if stream["length"]:
                                self.acknowledged_ranges.add(stream["offset"], stream["offset"] + stream["length"])
        if not reverse and len(self.acknowledged_ranges) and self.acknowledged_ranges[0].start == 0:
            acknowledged = self.acknowledged_ranges[0].stop // self.record_bytes
            for index in range(self.tcp_acked, acknowledged):
                self.forward.pending.pop(index)
                self.forward.pending_bytes -= self.traffic.payload_bytes
            self.tcp_acked = acknowledged

    def handle_events(self, reverse):
        while (event := self.connections[reverse].next_event()) is not None:
            if isinstance(event, HandshakeCompleted):
                self.handshakes[reverse] = True
            elif isinstance(event, ConnectionTerminated):
                raise RuntimeError(f"QUIC connection terminated: {event.error_code} {event.reason_phrase}")
            elif isinstance(event, StreamDataReceived):
                self.stream_received_bytes += len(event.data)
                received = self.stream_received_bytes // self.record_bytes
                frame_size = self.traffic.frame_bytes if self.strategy.quic_l2 else self.record_bytes
                advanced = received - self.tcp_received
                for index in range(self.tcp_received, received):
                    self.forward.delays.append((self.now - self.sent_times[index]) * 1000)
                self.forward.delivered_bytes += advanced * frame_size
                if self.now <= self.traffic.duration_s:
                    self.tcp_payload_bytes += advanced * self.traffic.payload_bytes
                    self.forward.delivered_during_measurement_bytes += advanced * frame_size
                self.tcp_received = received
        if reverse and not self.warming_up:
            buffered = sum(r.stop - max(r.start, self.stream_received_bytes)
                           for r in self.received_ranges if r.stop > self.stream_received_bytes)
            self.forward.peak_reorder_bytes = max(self.forward.peak_reorder_bytes, buffered)
