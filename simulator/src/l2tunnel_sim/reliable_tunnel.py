"""Modeled inner TCP over actual QUIC or upstream KCP ordered record channels.

Every Ethernet frame, including fresh SYN probes and ordinary ACKs, enters the
same causal round-robin connection pool and per-connection FIFO. QUIC has only
stream zero. KCP has one ordered message queue per conversation. There is no
probe-specific outer connection, stream, copy policy or admission priority.
"""

from functools import partial
from math import ceil
from struct import Struct
from types import SimpleNamespace

from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamDataReceived
from aioquic.quic.rangeset import RangeSet

from .kcp import KCPContext, library as kcp_library
from .multiflow import MultiFlow
from .mux import DuplexMux
from .mux_tcp import MuxTCPEndpoint, UnifiedMuxHandshakeProbe
from .quic import QUIC, IP_UDP_BYTES
from .tcp_syn_baseline import range_prefix


LENGTH = Struct('!H')
KCP_HEADER = Struct('<IBBHIIII')
STABILITY_QUEUE_MODEL = 'physical FIFO plus shared ingress and admitted protocol bytes not yet first transmitted'


class RecordQUIC(QUIC):
    """An established actual aioquic pair carrying one duplex framed stream."""

    def __init__(self, owner, window_bytes):
        self.owner = None
        self.local_now = 0.0
        self.receive_callbacks = [None, None]
        self.buffers = [bytearray(), bytearray()]
        self.submitted = [0, 0]
        self.received = [0, 0]
        self.sent_ranges = [{}, {}]
        self.confirmed_ranges = [RangeSet(), RangeSet()]
        self.sent_ends = [0, 0]
        self.stream_ids = [set(), set()]
        self.peak_outstanding = [0, 0]
        self.peak_pending = [0, 0]
        self.wake = None
        self.record_window = window_bytes
        super().__init__(owner.scenario, owner.traffic, owner.paths_for_tunnel, owner.strategy_for_tunnel, owner.seed_for_tunnel)
        self.owner = owner
        self.links = owner.links

    @property
    def now(self):
        return self.owner.now if self.owner is not None else self.local_now

    @now.setter
    def now(self, value):
        self.local_now = value

    def at(self, when, callback, *args):
        if self.owner is None:
            return super().at(when, callback, *args)
        return self.owner.at(when, callback, *args)

    def produce(self):
        # The owning inner TCP engine is the sole bulk producer.
        pass

    def configuration(self, reverse):
        config = super().configuration(reverse)
        config.max_data = config.max_stream_data = self.record_window
        return config

    def capacity(self, reverse, frame):
        return self.submitted[reverse] - range_prefix(self.confirmed_ranges[reverse]) + len(frame) + LENGTH.size <= self.record_window

    def submit(self, reverse, frame):
        if not self.capacity(reverse, frame):
            raise ValueError('QUIC record admission exceeds finite sender window')
        body = LENGTH.pack(len(frame)) + frame
        self.submitted[reverse] += len(body)
        self.peak_pending[reverse] = max(self.peak_pending[reverse], self.pending_bytes(reverse))
        outstanding = self.submitted[reverse] - range_prefix(self.confirmed_ranges[reverse])
        self.peak_outstanding[reverse] = max(self.peak_outstanding[reverse], outstanding)
        self.connections[reverse].send_stream_data(0, body)
        self.flush(reverse)

    def flush(self, reverse):
        if self.warming_up:
            return super().flush(reverse)
        connection = self.connections[reverse]
        datagrams = connection.datagrams_to_send(now=self.protocol_time)
        packets = list(self.loggers[reverse].trace.sent)
        self.loggers[reverse].trace.sent.clear()
        if len(datagrams) != len(packets):
            raise RuntimeError('unexpected QUIC coalescing after warmup')
        for (data, _), packet in zip(datagrams, packets):
            streams = [frame for frame in packet['frames'] if frame['frame_type'] == 'stream']
            if any(frame['stream_id'] != 0 for frame in streams):
                raise ValueError('record tunnel permits only shared stream zero')
            number = packet['header']['packet_number']
            if streams:
                self.sent_ranges[reverse][number] = [(frame['offset'], frame['offset'] + frame['length']) for frame in streams]
            repeated = 0
            for frame in streams:
                self.stream_ids[reverse].add(frame['stream_id'])
                repeated += min(frame['length'], max(0, self.sent_ends[reverse] - frame['offset']))
                self.sent_ends[reverse] = max(self.sent_ends[reverse], frame['offset'] + frame['length'])
            self.send_datagram(reverse, data, 'retry' if repeated else 'source' if streams else 'feedback', repeated)
        self.timer_versions[reverse] += 1
        when = connection.get_timer()
        if when is not None:
            self.at(max(when - self.clock_offset, self.now + 1e-9), self.on_timer, reverse, self.timer_versions[reverse])

    def send_datagram(self, reverse, data, kind, repeated):
        if self.warming_up:
            return super().send_datagram(reverse, data, kind, repeated)
        self.owner.send(reverse, len(data) + IP_UDP_BYTES, 'quic_' + kind,
                        partial(self.receive_datagram, not reverse, bytes(data)))

    def observe_packet(self, reverse, packet):
        sender = reverse
        for frame in packet['frames']:
            if frame['frame_type'] != 'ack':
                continue
            for number in list(self.sent_ranges[sender]):
                if any(low <= number <= high for low, high in frame['acked_ranges']):
                    for start, end in self.sent_ranges[sender].pop(number):
                        if start != end:
                            self.confirmed_ranges[sender].add(start, end)
        if self.wake is not None:
            self.wake(sender)

    def handle_events(self, reverse):
        if self.warming_up:
            return super().handle_events(reverse)
        while (event := self.connections[reverse].next_event()) is not None:
            if isinstance(event, HandshakeCompleted):
                self.handshakes[reverse] = True
            elif isinstance(event, ConnectionTerminated):
                raise RuntimeError(f'QUIC record connection terminated {event.error_code} {event.reason_phrase}')
            elif isinstance(event, StreamDataReceived):
                if event.stream_id != 0:
                    raise ValueError('unexpected QUIC record stream')
                sender = not reverse
                self.received[sender] += len(event.data)
                buffer = self.buffers[reverse]
                buffer.extend(event.data)
                while len(buffer) >= LENGTH.size:
                    length, = LENGTH.unpack_from(buffer)
                    if not length:
                        raise ValueError('empty QUIC frame record')
                    end = LENGTH.size + length
                    if len(buffer) < end:
                        break
                    frame = bytes(buffer[LENGTH.size:end])
                    del buffer[:end]
                    self.receive_callbacks[sender](frame)

    @property
    def confirmed(self):
        return (not any(self.buffers) and self.submitted == self.received
                and all(range_prefix(self.confirmed_ranges[d]) == self.submitted[d] for d in (False, True)))

    def pending_bytes(self, reverse):
        return max(0, self.submitted[reverse] - self.sent_ends[reverse])

    def measurements(self):
        return dict(protocol='aioquic', streams=[sorted(ids) for ids in self.stream_ids],
                    sender_window_bytes=self.record_window, peak_outstanding_bytes=self.peak_outstanding,
                    submitted_stream_bytes=self.submitted, received_stream_bytes=self.received,
                    first_transmitted_stream_bytes=self.sent_ends,
                    pending_first_transmission_bytes=[self.pending_bytes(d) for d in (False, True)],
                    peak_pending_first_transmission_bytes=self.peak_pending,
                    acknowledged_stream_bytes=[range_prefix(item) for item in self.confirmed_ranges], confirmed=self.confirmed)


class RecordKCP:
    """Two upstream KCP endpoints sharing the physical simulation event clock."""

    def __init__(self, owner, conversation, settings):
        self.owner = owner
        self.settings = dict(settings)
        self.peers = [KCPContext(conversation, mtu=owner.scenario.mtu - IP_UDP_BYTES, **settings) for _ in range(2)]
        self.receive_callbacks = [None, None]
        self.wake = None
        self.submitted = [0, 0]
        self.received = [0, 0]
        self.peak_waiting = [0, 0]
        self.seen_sequences = [set(), set()]
        self.unique_payload_sent = [0, 0]
        self.peak_pending = [0, 0]
        self.repeated_segments = [0, 0]
        self.timer_at = None
        self.flush_until = 0.0

    def capacity(self, reverse, frame):
        peer = self.peers[reverse]
        return peer.waiting + ceil(len(frame) / peer.mss) <= peer.window

    def submit(self, reverse, frame):
        if not self.capacity(reverse, frame):
            raise ValueError('KCP record admission exceeds finite sender window')
        self.peers[reverse].send(frame)
        self.submitted[reverse] += len(frame)
        self.peak_pending[reverse] = max(self.peak_pending[reverse], self.pending_bytes(reverse))
        self.peak_waiting[reverse] = max(self.peak_waiting[reverse], self.peers[reverse].waiting)
        self.schedule()

    def schedule(self):
        if self.timer_at is None:
            # KCP API clocks are integer milliseconds, never ahead of simulation time.
            self.timer_at = ceil((self.owner.now + 1e-9) * 1000) / 1000
            self.owner.at(self.timer_at, self.update)

    def update(self):
        self.timer_at = None
        milliseconds = int(self.owner.now * 1000 + 1e-7)
        for reverse, peer in enumerate(self.peers):
            for packet in peer.update(milliseconds):
                offset, repeats, pushes = 0, 0, 0
                while offset < len(packet):
                    _, command, _, _, _, sequence, _, length = KCP_HEADER.unpack_from(packet, offset)
                    if command == 81:
                        pushes += 1
                        repeated = sequence in self.seen_sequences[reverse]
                        repeats += repeated
                        if not repeated:
                            self.unique_payload_sent[reverse] += length
                        self.seen_sequences[reverse].add(sequence)
                    offset += KCP_HEADER.size + length
                if offset != len(packet):
                    raise ValueError('KCP output segment boundaries are inconsistent')
                self.repeated_segments[reverse] += repeats
                kind = 'kcp_retry' if repeats else 'kcp_source' if pushes else 'kcp_feedback'
                self.owner.send(bool(reverse), len(packet) + IP_UDP_BYTES, kind,
                                partial(self.input, not reverse, packet))
        if any(peer.waiting for peer in self.peers) or self.owner.now < self.flush_until:
            when = min(peer.check(milliseconds) for peer in self.peers)
            self.timer_at = max(self.owner.now + .001, when / 1000)
            self.owner.at(self.timer_at, self.update)

    def input(self, reverse, packet):
        peer = self.peers[reverse]
        peer.input(packet)
        self.flush_until = max(self.flush_until, self.owner.now + self.settings.get('interval', 10) / 1000)
        while (frame := peer.receive()) is not None:
            self.received[not reverse] += len(frame)
            self.receive_callbacks[not reverse](frame)
        if self.wake is not None:
            self.wake(reverse)
        self.schedule()

    @property
    def confirmed(self):
        return (self.submitted == self.received and not any(peer.waiting for peer in self.peers)
                and self.owner.now >= self.flush_until)

    def pending_bytes(self, reverse):
        return max(0, self.submitted[reverse] - self.unique_payload_sent[reverse])

    def measurements(self):
        return dict(protocol='upstream KCP v1', settings=self.settings, sender_window_segments=self.peers[0].window,
                    peak_waiting_segments=self.peak_waiting, submitted_frame_bytes=self.submitted,
                    received_frame_bytes=self.received, retransmitted_segments=self.repeated_segments,
                    first_transmitted_frame_bytes=self.unique_payload_sent,
                    pending_first_transmission_bytes=[self.pending_bytes(d) for d in (False, True)],
                    peak_pending_first_transmission_bytes=self.peak_pending,
                    confirmed=self.confirmed, upstream=kcp_library().receipt)


class RecordDirection:
    def __init__(self, sim, reverse, protocols):
        self.sim, self.reverse, self.protocols = sim, reverse, protocols
        self.capacity_callback = None

    def capacity(self, channel, frame):
        return self.protocols[channel].capacity(self.reverse, frame)

    def submit_channel(self, channel, frame_bytes, payload_bytes, deliver, *, frame, deliver_frame):
        if not deliver_frame or len(frame) != frame_bytes:
            raise ValueError('record adapter requires actual full-frame delivery')
        self.protocols[channel].submit(self.reverse, frame)


class ReliableMux(DuplexMux):
    """Reuse causal tuple classification and decoded dispatch with per-connection credit."""

    def _available(self, reverse, channel):
        queue = self.queues[reverse][channel]
        return bool(queue and self.transports[reverse].capacity(channel, queue[0][0]))

    def _blocked(self, reverse):
        blocked = not any(self._available(reverse, channel) for channel in range(self.channel_count))
        if blocked and not self._window_stalled[reverse]:
            self.window_stall_events[reverse] += 1
        self._window_stalled[reverse] = blocked
        return blocked

    def _drain(self, reverse):
        self._scheduled_at[reverse] = None
        if not self.queued_frames[reverse] or self._blocked(reverse):
            return
        if self.sim.links[reverse][0].free_at > self.sim.now:
            self._wake(reverse)
            return
        channel = self._next_channel[reverse]
        while not self._available(reverse, channel):
            channel = (channel + 1) % self.channel_count
        frame, payload_bytes, submitted_at = self.queues[reverse][channel].popleft()
        self._next_channel[reverse] = (channel + 1) % self.channel_count
        self.queued_frames[reverse] -= 1
        self.queued_bytes[reverse] -= len(frame)
        self.channel_queued_bytes[reverse][channel] -= len(frame)
        self._draining[reverse] = True
        try:
            self.transports[reverse].submit_channel(channel, len(frame), payload_bytes,
                self._deliver_callbacks[reverse][channel], frame=frame, deliver_frame=True)
        finally:
            self._draining[reverse] = False
        self.admitted_frames[reverse] += 1
        self.admitted_bytes[reverse] += len(frame)
        self.channel_ids[reverse].add(channel)
        wait_ms = (self.sim.now - submitted_at) * 1000
        self.queue_wait_sum_ms[reverse] += wait_ms
        self.queue_wait_max_ms[reverse] = max(self.queue_wait_max_ms[reverse], wait_ms)
        self._wake(reverse)

    def queue_delay_ms(self, reverse):
        link = self.sim.links[reverse][0]
        protocol_pending = sum(connection.pending_bytes(reverse) for connection in self.transports[reverse].protocols)
        return (max(0, link.free_at - self.sim.now)
                + (self.queued_bytes[reverse] + protocol_pending) / link.bytes_per_s) * 1000


class ReliableTunnelMultiFlow(MultiFlow):
    def __init__(self, *args, protocol, protocol_settings, simulation_factory, **kwargs):
        super().__init__(*args, simulation_factory=simulation_factory, **kwargs)
        if not 1 <= len(self.flows) <= 16:
            raise ValueError('reliable baseline supports one to sixteen outer connections')
        owner = self.flows[0]
        owner.paths_for_tunnel = args[2]
        owner.strategy_for_tunnel = args[3]
        owner.seed_for_tunnel = args[4]
        self.protocol_kind = protocol
        self.protocols = []
        for channel, flow in enumerate(self.flows):
            window = max(flow.traffic.frame_bytes + LENGTH.size,
                         flow.traffic.window_bytes // flow.traffic.payload_bytes * (flow.traffic.frame_bytes + LENGTH.size))
            connection = (RecordQUIC(owner, window) if protocol == 'quic_inner'
                          else RecordKCP(owner, channel + 1, protocol_settings))
            self.protocols.append(connection)
        directions = [RecordDirection(owner, bool(reverse), self.protocols) for reverse in range(2)]
        self.mux = ReliableMux(owner, directions, channel_count=len(self.flows), mapping='connection_round_robin')
        for channel, connection in enumerate(self.protocols):
            connection.receive_callbacks = [partial(self.mux._deliver, bool(reverse), channel) for reverse in range(2)]
            connection.wake = self.mux._wake
        for index, flow in enumerate(self.flows):
            flow.compact_forward = MuxTCPEndpoint(self.mux, False, 40000 + index)
            flow.compact_reverse = MuxTCPEndpoint(self.mux, True, 40000 + index)

    @property
    def tunnel_confirmed(self):
        return self.mux.flushed and all(connection.confirmed for connection in self.protocols) and all(
            not endpoint.records for flow in self.flows for endpoint in (flow.compact_forward, flow.compact_reverse))

    def measurements(self):
        row = super().measurements()
        row.update(transport='inner_tcp_over_' + self.protocol_kind.removesuffix('_inner'),
                   tunnel_connection_count=len(self.protocols), tunnel_protocol=self.protocol_kind,
                   tunnel_shared_record_path=True, tunnel_probe_extra_connections=0,
                   tunnel_probe_extra_streams=0, tunnel_mapping='causal connection round robin',
                   tunnel_protocol_records=[connection.measurements() for connection in self.protocols],
                   tunnel_all_confirmed=self.tunnel_confirmed,
                   tunnel_inner_tcp=True, tunnel_tcp_total_window_bytes=row['total_window_bytes'],
                   tunnel_stability_queue_model=STABILITY_QUEUE_MODEL,
                   tunnel_mux=self.mux.measurements(),
                   tcp_retransmissions=sum(flow.tcp_retransmissions for flow in self.flows),
                   ack_transmitted=sum(flow.ack_transmitted for flow in self.flows))
        return row


class TunnelHandshakeProbe(UnifiedMuxHandshakeProbe):
    quic = False  # Bulk is modeled inner TCP for both outer protocols.

    def measurements(self):
        row = super().measurements()
        row.update(tcp_syn_probe_transport='inner TCP over the existing shared ' + self.simulation.protocol_kind + ' record pool',
                   tcp_syn_probe_channel_policy='bulk and fresh probes use the same causal RR outer connection pool and ordered record FIFO',
                   tcp_syn_probe_wire_accounting='Actual QUIC or KCP UDP payload bytes plus 28 IPv4/UDP bytes, both directions, including all retransmissions and feedback',
                   tcp_syn_probe_stability_queue_model=STABILITY_QUEUE_MODEL,
                   tcp_syn_probe_model_detail='Ordinary inner TCP and fresh handshake frames are fully serialized and reconstructed through actual protocol bytes. Received headers select endpoint callbacks. No reserved probe stream or outer connection.')
        return row
