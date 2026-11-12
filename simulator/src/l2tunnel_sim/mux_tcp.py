"""TCP endpoints and fresh SYN probes entering the same duplex L2 mux."""

from collections import defaultdict, deque
from types import SimpleNamespace

from .compact import CompactHeaderCodec, tcp_profile_frame
from .compact_ack import CoalescedACKTCP
from .compact_wire import CompactWireTransport
from .packed_wire import PACKED_CHANNEL, PackedWireTransport
from .multiflow import MultiFlow
from .mux import DuplexMux, frame_tuple
from .tcp_syn_probe import EVENT_HEADER, SYNProbeConfig, TCPHandshakeProbe, handshake_frame


def bulk_connection_frame(frame, port, reverse):
    """Materialize matching endpoint identities before classification and coding."""
    header = bytearray(frame[:66])
    client, server = b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"
    source, destination = ((server, 443), (client, port)) if reverse else ((client, port), (server, 443))
    header[26:34] = source[0] + destination[0]
    header[34:38] = source[1].to_bytes(2, "big") + destination[1].to_bytes(2, "big")
    if reverse:
        header[:12] = header[6:12] + header[:6]
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, frame[66:])


class MuxTCPEndpoint:
    """Preserve modeled TCP metadata after received-byte endpoint dispatch."""

    def __init__(self, mux, reverse, port):
        self.mux, self.reverse, self.port = mux, reverse, port
        self.transport = mux.transports[reverse]
        self.records = defaultdict(deque)
        frame = bulk_connection_frame(tcp_profile_frame(payload_bytes=0), port, reverse)
        mux.register_endpoint(reverse, frame_tuple(frame), self.receive)

    def submit(self, frame_bytes, payload_bytes, deliver, *, ack=False, frame=None):
        if frame is None or len(frame) != frame_bytes or not 0 <= payload_bytes <= frame_bytes:
            raise ValueError("mux TCP endpoint requires a complete serialized frame")
        materialized = bulk_connection_frame(frame, self.port, self.reverse)
        self.mux.submit_frame(self.reverse, materialized)
        self.records[materialized].append(deliver)

    def receive(self, frame):
        callbacks = self.records.get(frame)
        if not callbacks:
            raise ValueError("decoded TCP frame has no matching endpoint record")
        deliver = callbacks.popleft()
        if not callbacks:
            del self.records[frame]
        deliver()

    def __getattr__(self, name):
        return getattr(self.transport, name)


class MuxTCP(CoalescedACKTCP):
    """Keep TCP ACK generation while applying common L2 protection to all frames."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.ack_copies != 1:
            raise ValueError("unified mux applies copies in its shared L2 transport")

    def transmit_ack(self, packet):
        frame = tcp_profile_frame(
            acknowledged=packet.acknowledged * self.traffic.payload_bytes,
            identification=self.ack_packet_id, timestamp=int(packet.created_at * 1000),
            echoed_timestamp=int((packet.echoed_timestamp or 0) * 1000),
            payload_bytes=0, flags=0x10)

        def receive_ack():
            self.peer_timestamp = max(self.peer_timestamp, packet.created_at)
            self.reverse.delivered_bytes += len(frame)
            self.reverse.delays.append((self.now - packet.created_at) * 1000)
            self.on_ack(packet.acknowledged, packet.echoed_timestamp)

        self.compact_reverse.submit(len(frame), 0, receive_ack, ack=True, frame=frame)
        self.ack_packet_id += 1
        self.ack_transmitted += 1


class UnifiedMuxMultiFlow(MultiFlow):
    """Share a fixed channel pool and coded transports across both directions."""

    def __init__(self, *args, compact_config, channel_count, simulation_factory, mapping="crc32", **kwargs):
        packed = compact_config.pack_sources_max_delay_ms > 0
        channel_limit = PACKED_CHANNEL if packed else 256
        if (isinstance(channel_count, bool) or not isinstance(channel_count, int)
                or not 1 <= channel_count <= channel_limit):
            raise ValueError(f"unified mux channel_count must be an integer from one to {channel_limit}")
        super().__init__(*args, simulation_factory=simulation_factory, **kwargs)
        if len(self.flows) > 256:
            raise ValueError("unified mux TCP fixture supports up to 256 bulk connections")
        if any(not isinstance(flow, MuxTCP) for flow in self.flows):
            raise ValueError("unified mux requires compatible TCP endpoints in every flow")
        if compact_config.header_profile != "tcp_delta":
            raise ValueError("unified mux requires serialized TCP frame headers")
        transport_type = PackedWireTransport if packed else CompactWireTransport
        self.shared_forward = transport_type(self.flows[0], False, compact_config)
        self.shared_reverse = transport_type(self.flows[0], True, compact_config)
        self.mux = DuplexMux(self.flows[0], (self.shared_forward, self.shared_reverse),
                             channel_count=channel_count, mapping=mapping)
        for index, flow in enumerate(self.flows):
            flow.compact_forward = MuxTCPEndpoint(self.mux, False, 40000 + index)
            flow.compact_reverse = MuxTCPEndpoint(self.mux, True, 40000 + index)

    @property
    def mux_confirmed(self):
        return self.mux.flushed and all(transport.base == len(transport.sources) and not transport.buffer_bytes
                   and not getattr(transport, "pending_pack_bytes", 0)
                   and not transport.callbacks for transport in (self.shared_forward, self.shared_reverse)) and all(
            not endpoint.records for flow in self.flows for endpoint in (flow.compact_forward, flow.compact_reverse))


class UnifiedMuxHandshakeProbe(TCPHandshakeProbe):
    """Fresh TCP tuples share every mux and coding rule with ordinary frames."""

    def __init__(self, simulation, config=SYNProbeConfig(), **kwargs):
        if config.reverse_copies != 1:
            raise ValueError("unified mux probes use the common L2 copy policy")
        self.mux = simulation.mux
        self.reverse_submitted_frames = 0
        adapter = SimpleNamespace(flows=[simulation.flows[0]], shared_forward=None)
        super().__init__(adapter, config, **kwargs)
        self.simulation = simulation

    def queue_delay_ms(self, reverse):
        return self.mux.queue_delay_ms(reverse)

    def send_forward(self, probe, flags):
        frame = handshake_frame(probe, reverse=False, flags=flags,
                                timestamp=int(self.sim.now * 1000), identification=self.packet_id)
        self.packet_id += 1
        self.forward_frames += 1
        self.forward_frame_bytes += len(frame)
        endpoints = frame_tuple(frame)
        self.mux.register_endpoint(False, endpoints, self.receive_forward_frame)
        self.mux.register_endpoint(True, tuple(reversed(endpoints)), self.receive_reverse_frame)
        probe.channel = self.mux.submit_frame(False, frame)

    def send_reverse_copy(self, probe, body):
        frame = bytes(body[EVENT_HEADER.size:])
        self.reverse_submitted_frames += 1
        self.mux.submit_frame(True, frame)

    def receive_reverse_frame(self, frame):
        return self.receive_reverse_body(EVENT_HEADER.pack(0) + frame)

    def measurements(self):
        row = super().measurements()
        row.update(tcp_syn_probe_transport="unified duplex mux and shared coded transports",
                   tcp_syn_probe_channel_policy="same deterministic frame classifier and channel pool as bulk TCP",
                   tcp_syn_probe_channels_used=sorted({probe.channel for probe in self.probes}),
                   tcp_syn_probe_reverse_submitted_frames=self.reverse_submitted_frames,
                   tcp_syn_probe_all_flushed=(self.forward_frames == self.received_frame_counts[False]
                       and self.reverse_submitted_frames == self.received_frame_counts[True]),
                   tcp_syn_probe_wire_accounting="Probe frames use common coded sources, repairs, feedback and the configured generic source-copy policy in both directions",
                   tcp_syn_probe_stability_queue_model="physical FIFO plus common mux ingress and coding-source backlog")
        for key in ("reverse_requested_bytes", "reverse_departed_bytes", "reverse_datagrams", "reverse_erasures"):
            row["tcp_syn_probe_" + key] = None
        return row
