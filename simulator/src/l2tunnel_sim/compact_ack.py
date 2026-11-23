"""Supersede unsent advancing TCP ACKs before the lossy reverse link.

Each transmitted ACK remains a self-contained Ethernet/IPv4/TCP frame. The
optimization acts after the receiver generates the ACK and retains the exact
timestamp echo of the selected frame. Duplicate ACKs are sent individually.
"""

from dataclasses import dataclass
from math import isfinite

from .compact_tcp import CompactTCP
from .tcp import ETHERNET_BYTES, IP_TCP_BYTES


@dataclass(frozen=True)
class PendingACK:
    acknowledged: int
    created_at: float
    echoed_timestamp: float | None
    sack_blocks: tuple = ()


class CoalescedACKTCP(CompactTCP):
    def __init__(self, *args, ack_coalesce_ms=.5, ack_copies=1,
                 ack_copy_spacing_ms=.1, acknowledged_segment_slow_start=False,
                 reliable_acks=False, **kwargs):
        if isinstance(ack_coalesce_ms, bool) or not isfinite(ack_coalesce_ms) or ack_coalesce_ms < 0:
            raise ValueError("ack_coalesce_ms must be finite and nonnegative")
        if isinstance(ack_copies, bool) or not isinstance(ack_copies, int) or not 1 <= ack_copies <= 4:
            raise ValueError("ack_copies must be an integer from one to four")
        if (isinstance(ack_copy_spacing_ms, bool) or not isfinite(ack_copy_spacing_ms)
                or ack_copy_spacing_ms < 0):
            raise ValueError("ack_copy_spacing_ms must be finite and nonnegative")
        if reliable_acks:
            raise ValueError("coalesced ACKs use self-contained lossy datagrams")
        if type(acknowledged_segment_slow_start) is not bool:
            raise ValueError("acknowledged_segment_slow_start must be boolean")
        super().__init__(*args, reliable_acks=False, **kwargs)
        if self.compact_config.outer_header_bytes < 36:
            raise ValueError("ACK packet identifiers need an eight-byte tunnel header above IPv4/UDP")
        self.ack_coalesce_ms = ack_coalesce_ms
        self.ack_copies = ack_copies
        self.ack_copy_spacing_ms = ack_copy_spacing_ms
        self.acknowledged_segment_slow_start = acknowledged_segment_slow_start
        self.pending_ack = None
        self.pending_ack_generation = 0
        self.ack_generated = 0
        self.ack_superseded = 0
        self.ack_transmitted = 0
        self.ack_duplicates_transmitted = 0
        self.received_ack_ids = set()
        self.ack_copy_duplicates = 0

    def increase_window(self, acknowledged):
        """Optionally handle stretch ACKs using Linux-style slow-start growth.

        PlainTCP.on_ack still decides whether the sender was cwnd-limited.
        Linux v6.12 tcp_slow_start consumes newly acknowledged full segments
        up to ssthresh and returns the remainder to congestion avoidance.
        This option changes only that slow-start step of the inherited model.
        """
        if self.acknowledged_segment_slow_start and self.cwnd < self.ssthresh:
            before = self.cwnd
            self.cwnd = min(self.window_limit, self.ssthresh, self.cwnd + acknowledged)
            acknowledged -= self.cwnd - before
            if acknowledged <= 0 or self.cwnd >= self.window_limit:
                return
        super().increase_window(acknowledged)

    def emit_ack(self):
        duplicate = self.tcp_received == self.last_ack
        self.ack_timer = None
        self.last_ack = self.tcp_received
        blocks = self.sack_receiver.take_blocks(self.byte_offset) if self.sack_receiver is not None else ()
        packet = PendingACK(self.tcp_received, self.now, self.timestamp_recent, blocks)
        self.ack_generated += 1
        if duplicate or blocks or self.ack_coalesce_ms == 0:
            # Preserve duplicate-ACK cardinality and send the preceding advancing
            # ACK first, so a fast-retransmit sequence cannot lose its first ACK.
            self.flush_pending_ack(self.pending_ack_generation)
            self.transmit_ack(packet)
            self.ack_duplicates_transmitted += int(duplicate)
            return
        if self.pending_ack is not None:
            self.ack_superseded += 1
            self.pending_ack = packet
            return
        self.pending_ack = packet
        self.pending_ack_generation += 1
        self.at(self.now + self.ack_coalesce_ms / 1000,
                self.flush_pending_ack, self.pending_ack_generation)

    def flush_pending_ack(self, generation):
        if generation != self.pending_ack_generation or self.pending_ack is None:
            return
        packet = self.pending_ack
        self.pending_ack = None
        self.pending_ack_generation += 1
        self.transmit_ack(packet)

    def transmit_ack(self, packet):
        frame_bytes = IP_TCP_BYTES + ETHERNET_BYTES
        packet_id = self.ack_packet_id

        def receive_ack():
            # Copies carry the same 64-bit tunnel record identifier. Distinct
            # duplicate-ACK events have distinct identifiers and remain visible
            # to TCP, while loss-protection copies never manufacture dupACKs.
            if packet_id in self.received_ack_ids:
                self.ack_copy_duplicates += 1
                return
            self.received_ack_ids.add(packet_id)
            self.peer_timestamp = max(self.peer_timestamp, packet.created_at)
            self.reverse.delivered_bytes += frame_bytes
            self.reverse.delays.append((self.now - packet.created_at) * 1000)
            self.on_ack(packet.acknowledged, packet.echoed_timestamp)

        self.send(True, frame_bytes + self.compact_config.outer_header_bytes
                  + self.compact_config.authentication_bytes, "source", receive_ack)
        for copy in range(1, self.ack_copies):
            self.at(self.now + copy * self.ack_copy_spacing_ms / 1000, self.send, True,
                    frame_bytes + self.compact_config.outer_header_bytes
                    + self.compact_config.authentication_bytes, "source", receive_ack)
        self.ack_packet_id += 1
        self.ack_transmitted += 1
