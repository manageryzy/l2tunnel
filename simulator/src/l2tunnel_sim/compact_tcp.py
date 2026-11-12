"""Congestion-controlled inner TCP over the compact coded record transport.

The inherited TCP engine supplies slow start, CUBIC or Reno, NewReno recovery,
delayed cumulative ACKs, timestamp RTT samples, and retransmission timers.
Both data and ACK records traverse the coded transport and the lossy links.
"""

from .compact import CompactTransport, tcp_profile_frame
from .tcp import ETHERNET_BYTES, IP_TCP_BYTES, PlainTCP


class CompactTCP(PlainTCP):
    def __init__(self, scenario, traffic, paths, strategy, seed, compact_config,
                 *, reliable_acks=True, transport_type=CompactTransport):
        super().__init__(scenario, traffic, paths, strategy, seed)
        self.compact_forward = transport_type(self, False, compact_config)
        self.compact_reverse = transport_type(self, True, compact_config)
        self.reliable_acks = reliable_acks
        self.compact_config = compact_config
        self.inner_retransmissions = 0
        self.inner_retransmitted_payload_bytes = 0
        self.data_packet_id = 0
        self.ack_packet_id = 0
        self.peer_timestamp = 0.0

    @property
    def tcp_retransmissions(self):
        return self.inner_retransmissions

    def transmit_segment(self, index):
        segment = self.forward.pending[index]
        if segment.attempts:
            self.inner_retransmissions += 1
            self.inner_retransmitted_payload_bytes += self.traffic.payload_bytes
        sent_at = self.now
        frame_bytes = self.traffic.payload_bytes + IP_TCP_BYTES + ETHERNET_BYTES
        frame = None
        if self.compact_config.header_profile == 'tcp_delta':
            frame = tcp_profile_frame(
                sequence=index * self.traffic.payload_bytes,
                identification=self.data_packet_id, timestamp=int(sent_at * 1000),
                echoed_timestamp=int(self.peer_timestamp * 1000),
                payload_bytes=self.traffic.payload_bytes,
            )
        self.data_packet_id += 1
        self.compact_forward.submit(
            frame_bytes, self.traffic.payload_bytes,
            lambda: self.on_data(index, sent_at), frame=frame,
        )
        segment.last_sent_at = sent_at
        segment.attempts += 1
        if not self.timer_running:
            self.restart_timer()

    def emit_ack(self):
        self.ack_timer = None
        self.last_ack = self.tcp_received
        acknowledged = self.tcp_received
        created_at = self.now
        echoed_timestamp = self.timestamp_recent

        def receive_ack():
            self.peer_timestamp = max(self.peer_timestamp, created_at)
            self.reverse.delivered_bytes += IP_TCP_BYTES + ETHERNET_BYTES
            self.reverse.delays.append((self.now - created_at) * 1000)
            self.on_ack(acknowledged, echoed_timestamp)

        frame_bytes = IP_TCP_BYTES + ETHERNET_BYTES
        if self.reliable_acks:
            frame = None
            if self.compact_config.header_profile == 'tcp_delta':
                frame = tcp_profile_frame(
                    acknowledged=acknowledged * self.traffic.payload_bytes,
                    identification=self.ack_packet_id, timestamp=int(created_at * 1000),
                    echoed_timestamp=int((echoed_timestamp or 0) * 1000),
                    payload_bytes=0, flags=0x10,
                )
            self.compact_reverse.submit(frame_bytes, 0, receive_ack, ack=True, frame=frame)
        else:
            # Full Ethernet ACK records use the same lossy reverse link.
            # Later cumulative TCP ACKs can acknowledge earlier data.
            self.send(True, frame_bytes + self.compact_config.outer_header_bytes
                      + self.compact_config.authentication_bytes,
                      "source", receive_ack)
        self.ack_packet_id += 1
