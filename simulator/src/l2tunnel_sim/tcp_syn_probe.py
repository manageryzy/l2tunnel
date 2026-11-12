"""Independent fresh-connection SYN probes sharing a loaded coded L2 path.

The measured interval starts at the first SYN submission to L2 and ends when
the client receives its matching SYN-ACK. Client and server retransmission
timers retain that original origin. Final ACK and reset frames are charged.
The endpoint handshake uses the simulator's timestamp-only TCP header profile.
"""

from dataclasses import asdict, dataclass
from collections import Counter
from math import ceil, isfinite
from struct import Struct

import numpy as np

from .compact import CompactHeaderCodec, _checksum, tcp_profile_frame


EVENT_HEADER = Struct("!Q")


@dataclass(frozen=True)
class SYNProbeConfig:
    interval_ms: float = 100
    timeout_ms: float = 5000
    initial_rto_ms: float = 1000
    reverse_copies: int = 1
    copy_spacing_ms: float = .1
    stability_window_s: float = 1
    stability_windows: int = 3
    throughput_tolerance_pct: float = 3
    queue_tolerance_ms: float = 1

    def __post_init__(self):
        for name in ("interval_ms", "timeout_ms", "initial_rto_ms", "copy_spacing_ms",
                     "stability_window_s", "throughput_tolerance_pct", "queue_tolerance_ms"):
            value = getattr(self, name)
            minimum = 0 if name == "copy_spacing_ms" else 1e-9
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or value < minimum:
                raise ValueError(f"{name} must be finite and positive, with zero copy spacing allowed")
        if (isinstance(self.reverse_copies, bool) or not isinstance(self.reverse_copies, int)
                or not 1 <= self.reverse_copies <= 4):
            raise ValueError("reverse_copies must be an integer from one to four")
        if isinstance(self.stability_windows, bool) or not isinstance(self.stability_windows, int) or self.stability_windows < 2:
            raise ValueError("stability_windows must be an integer of at least two")


@dataclass
class Probe:
    index: int
    channel: int
    started_at: float
    completed_at: float | None = None
    timed_out_at: float | None = None
    syn_attempts: int = 0
    synack_attempts: int = 0
    server_started_at: float | None = None
    server_active: bool = False
    server_closed: bool = False
    server_established: bool = False
    server_generation: int = 0
    echoed_timestamp: int = 0
    peer_timestamp: int = 0
    received_server_sequence: int | None = None
    server_client_sequence: int | None = None
    server_initial_sequence: int | None = None


@dataclass(frozen=True)
class HandshakeHeader:
    source: tuple
    destination: tuple
    flags: int
    sequence: int
    acknowledged: int
    timestamp: int
    echoed_timestamp: int


def parse_handshake_frame(frame):
    """Validate a complete timestamp-only Ethernet/IPv4/TCP control frame."""
    if (len(frame) != 66 or frame[12:15] != b"\x08\x00\x45" or frame[23] != 6
            or frame[16:18] != b"\x00\x34" or frame[46] != 0x80
            or frame[54:58] != b"\x01\x01\x08\x0a"
            or int.from_bytes(frame[20:22], "big") & 0x3FFF
            or _checksum(frame[14:34]) != b"\x00\x00"
            or _checksum(frame[26:34] + b"\x00\x06\x00\x20" + frame[34:]) != b"\x00\x00"):
        raise ValueError("invalid probe Ethernet/IPv4/TCP frame")
    return HandshakeHeader(
        source=(bytes(frame[26:30]), int.from_bytes(frame[34:36], "big")),
        destination=(bytes(frame[30:34]), int.from_bytes(frame[36:38], "big")),
        flags=frame[47], sequence=int.from_bytes(frame[38:42], "big"),
        acknowledged=int.from_bytes(frame[42:46], "big"),
        timestamp=int.from_bytes(frame[58:62], "big"),
        echoed_timestamp=int.from_bytes(frame[62:66], "big"))


def connection_tuple(probe):
    return ((b"\x0a\x00\x00\x01", 49152 + probe.index), (b"\x0a\x00\x00\x02", 443))


def handshake_frame(probe, *, reverse, flags, timestamp, identification):
    """Use a distinct four-tuple and ISNs for each connection, with checksums."""
    client_sequence = (0x10000000 + probe.index * 65537) & 0xFFFFFFFF
    server_sequence = (probe.server_initial_sequence if probe.server_initial_sequence is not None
                       else (0x70000000 + probe.index * 65539) & 0xFFFFFFFF)
    sequence = server_sequence if reverse else client_sequence + (flags != 0x02)
    acknowledged = 0
    if reverse:
        received_sequence = probe.server_client_sequence if probe.server_client_sequence is not None else client_sequence
        acknowledged = (received_sequence + 1) & 0xFFFFFFFF
    elif flags & 0x10:
        acknowledged = (probe.received_server_sequence or 0) + 1
    frame = bytearray(tcp_profile_frame(sequence=sequence, acknowledged=acknowledged,
        identification=identification, timestamp=timestamp,
        echoed_timestamp=probe.echoed_timestamp if reverse else probe.peer_timestamp,
        payload_bytes=0, flags=flags))
    client_port = 49152 + probe.index
    if reverse:
        frame[:12] = frame[6:12] + frame[:6]
        frame[26:34] = frame[30:34] + frame[26:30]
    ports = (443, client_port) if reverse else (client_port, 443)
    frame[34:38] = ports[0].to_bytes(2, "big") + ports[1].to_bytes(2, "big")
    dynamic = b"".join(frame[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(frame, dynamic, b"")


class TCPHandshakeProbe:
    """Attach probes without adding their bytes to bulk application delivery.

    Forward SYN/ACK/reset frames enter the existing shared coding transport.
    Unused channels rotate across probe connections. Reverse SYN-ACKs use the
    existing native full-frame tunnel cost, with an explicit copy count. Every
    packet uses the same FIFO links, erasure process and event heap as bulk TCP.
    """

    def __init__(self, simulation, config=SYNProbeConfig(), *, start_s=0, wait_for_stability=True):
        self.simulation = simulation
        self.sim = simulation.flows[0]
        self.shared = simulation.shared_forward
        self.config = config
        if isinstance(start_s, bool) or not isfinite(start_s) or not 0 <= start_s < self.sim.traffic.duration_s:
            raise ValueError("probe start must be within the traffic interval")
        self.first_channel = len(simulation.flows)
        if self.first_channel >= 256:
            raise ValueError("fresh-connection probes require an unused L2 channel")
        self.admission_end_s = self.sim.traffic.duration_s - config.timeout_ms / 1000
        self.count = max(0, ceil((self.admission_end_s - start_s) * 1000 / config.interval_ms))
        if self.count > 16384:
            raise ValueError("probe schedule exceeds the unique ephemeral port range")
        self.start_s = start_s
        self.minimum_start_s = start_s
        self.steady_started_at = None
        self.stability_history = []
        self.queue_samples = [[], []]
        self.last_window_received = 0
        self.window_index = 1
        self.sampling_index = 1
        self.sample_interval = config.stability_window_s / max(10, ceil(config.stability_window_s / .01))
        self.bulk_received_at_start = None
        self.bulk_received_at_end = None
        self.traffic_at_start = None
        self.traffic_at_end = None
        self.probes = []
        self.probe_connections = {}
        self.received_frame_counts = [0, 0]
        self.dispatch_rejections = Counter()
        self.received_synack_frames = set()
        self.next_event = 0
        self.packet_id = 0
        self.forward_frames = 0
        self.forward_frame_bytes = 0
        self.reverse_requested_bytes = 0
        self.reverse_copy_duplicates = 0
        self.pending_copies = 0
        self.sim.at(self.sim.traffic.duration_s, self.capture_bulk_end)
        if wait_for_stability:
            self.sim.at(self.sample_interval, self.observe_stability)
        else:
            self.sim.at(start_s, self.begin_probes)

    def bulk_received(self):
        return sum(flow.tcp_received for flow in self.simulation.flows)

    def capture_bulk_end(self):
        self.bulk_received_at_end = self.bulk_received()
        self.traffic_at_end = self.traffic_snapshot()

    def traffic_snapshot(self):
        snapshot = dict(at_s=self.sim.now,
                        delivered_payload_bytes=self.bulk_received() * self.sim.traffic.payload_bytes)
        for direction, label in ((False, "forward"), (True, "reverse")):
            snapshot[label + "_departed_ip_bytes"] = sum(
                sum(flow.wire[direction].values()) for flow in self.simulation.flows)
            snapshot[label + "_serialized_ip_bytes"] = sum(
                link.serialized_bytes(self.sim.now) for link in self.sim.links[direction])
        return snapshot

    def observe_stability(self):
        for direction in (False, True):
            delay = self.queue_delay_ms(direction)
            self.queue_samples[direction].append(delay)
        if self.sim.now + 1e-9 >= self.window_index * self.config.stability_window_s:
            received = self.bulk_received()
            goodput = ((received - self.last_window_received) * self.sim.traffic.payload_bytes * 8
                       / (self.config.stability_window_s * 1e6))
            self.last_window_received = received
            window = dict(end_s=self.sim.now, goodput_mbps=goodput,
                          forward_queue_mean_ms=sum(self.queue_samples[False]) / len(self.queue_samples[False]),
                          reverse_queue_mean_ms=sum(self.queue_samples[True]) / len(self.queue_samples[True]))
            window["phase"] = "before probes" if self.steady_started_at is None else "with probes"
            self.stability_history.append(window)
            self.queue_samples = [[], []]
            self.window_index += 1
            recent = self.stability_history[-self.config.stability_windows:]
            stable = len(recent) == self.config.stability_windows and self.sim.now >= self.minimum_start_s
            rates = [item["goodput_mbps"] for item in recent]
            mean_rate = sum(rates) / len(rates)
            stable = stable and mean_rate > 0 and max(rates) - min(rates) <= mean_rate * self.config.throughput_tolerance_pct / 100
            for direction in ("forward", "reverse"):
                values = [item[direction + "_queue_mean_ms"] for item in recent]
                stable = stable and max(values) - min(values) <= self.config.queue_tolerance_ms
            window["stable"] = bool(stable)
            if self.steady_started_at is None and stable and self.sim.now < self.admission_end_s:
                self.begin_probes()
        self.sampling_index += 1
        when = self.sampling_index * self.sample_interval
        if when < self.sim.traffic.duration_s:
            self.sim.at(when, self.observe_stability)

    def queue_delay_ms(self, reverse):
        return max(0, self.sim.links[reverse][0].free_at - self.sim.now) * 1000

    def begin_probes(self):
        self.start_s = self.sim.now
        self.steady_started_at = self.sim.now
        self.bulk_received_at_start = self.bulk_received()
        self.traffic_at_start = self.traffic_snapshot()
        self.count = max(0, ceil((self.admission_end_s - self.start_s) * 1000 / self.config.interval_ms))
        self.start_probe(0)

    def start_probe(self, index):
        if self.sim.now >= self.admission_end_s or not self.count:
            return
        channel = self.first_channel + index % (256 - self.first_channel)
        probe = Probe(index, channel, self.sim.now)
        self.probes.append(probe)
        self.probe_connections[connection_tuple(probe)] = probe
        self.send_syn(probe, self.config.initial_rto_ms / 1000)
        self.sim.at(probe.started_at + self.config.timeout_ms / 1000, self.expire_client, probe)
        when = self.start_s + (index + 1) * self.config.interval_ms / 1000
        if index + 1 < self.count and when < self.admission_end_s:
            self.sim.at(when, self.start_probe, index + 1)

    def send_forward(self, probe, flags):
        frame = handshake_frame(probe, reverse=False, flags=flags,
                                timestamp=int(self.sim.now * 1000), identification=self.packet_id)
        self.packet_id += 1
        self.forward_frames += 1
        self.forward_frame_bytes += len(frame)
        self.shared.submit_channel(probe.channel, len(frame), 0, self.receive_forward_frame,
                                   frame=frame, deliver_frame=True)

    def receive_forward_frame(self, frame):
        self.received_frame_counts[False] += 1
        try:
            header = parse_handshake_frame(frame)
        except ValueError:
            self.dispatch_rejections["malformed"] += 1
            return False
        probe = self.probe_connections.get((header.source, header.destination))
        if probe is None:
            self.dispatch_rejections["unknown_tuple"] += 1
            return False
        if header.flags == 0x02 and header.acknowledged == 0:
            if probe.server_client_sequence is not None and header.sequence != probe.server_client_sequence:
                self.dispatch_rejections["mismatched_sequence"] += 1
                return False
            self.receive_syn(probe, header.timestamp, header.sequence)
            return True
        if (header.flags not in (0x10, 0x14) or probe.server_client_sequence is None
                or probe.server_initial_sequence is None
                or header.sequence != (probe.server_client_sequence + 1) & 0xFFFFFFFF
                or header.acknowledged != (probe.server_initial_sequence + 1) & 0xFFFFFFFF):
            self.dispatch_rejections["mismatched_sequence"] += 1
            return False
        if header.flags == 0x10:
            self.establish_server(probe)
        else:
            self.close_server(probe)
        return True

    def send_syn(self, probe, rto):
        if probe.completed_at is not None or probe.timed_out_at is not None:
            return
        if self.sim.now >= probe.started_at + self.config.timeout_ms / 1000:
            return
        probe.syn_attempts += 1
        self.send_forward(probe, 0x02)
        self.sim.at(self.sim.now + rto, self.send_syn, probe, min(60, 2 * rto))

    def receive_syn(self, probe, timestamp, sequence):
        if probe.server_closed:
            return
        probe.echoed_timestamp = timestamp
        if probe.server_started_at is None:
            probe.server_client_sequence = sequence
            probe.server_initial_sequence = (0x70000000 + probe.index * 65539) & 0xFFFFFFFF
            probe.server_started_at = self.sim.now
            probe.server_active = True
            probe.server_generation += 1
            rto = self.config.initial_rto_ms / 1000
            self.sim.at(self.sim.now + rto, self.server_timeout, probe, probe.server_generation, rto)
            self.sim.at(self.sim.now + self.config.timeout_ms / 1000, self.close_server, probe)
        self.send_synack(probe)

    def send_synack(self, probe):
        if not probe.server_active:
            return
        frame = handshake_frame(probe, reverse=True, flags=0x12,
                                timestamp=int(self.sim.now * 1000), identification=self.packet_id)
        self.packet_id += 1
        event = self.next_event
        self.next_event += 1
        probe.synack_attempts += 1
        body = EVENT_HEADER.pack(event) + frame
        self.send_reverse_copy(probe, body)
        for copy in range(1, self.config.reverse_copies):
            self.pending_copies += 1
            self.sim.at(self.sim.now + copy * self.config.copy_spacing_ms / 1000,
                        self.send_scheduled_copy, probe, body)

    def send_scheduled_copy(self, probe, body):
        self.pending_copies -= 1
        self.send_reverse_copy(probe, body)

    def send_reverse_copy(self, probe, body):
        config = self.shared.config
        size = len(body) + config.outer_header_bytes - EVENT_HEADER.size + config.authentication_bytes
        self.reverse_requested_bytes += size
        self.sim.send(True, size, "syn_probe", lambda: self.receive_reverse_body(body))

    def receive_reverse_body(self, body):
        self.received_frame_counts[True] += 1
        try:
            header = parse_handshake_frame(body[EVENT_HEADER.size:])
        except ValueError:
            self.dispatch_rejections["malformed"] += 1
            return False
        probe = self.probe_connections.get((header.destination, header.source))
        if probe is None:
            self.dispatch_rejections["unknown_tuple"] += 1
            return False
        try:
            self.receive_synack(probe, body)
        except ValueError:
            self.dispatch_rejections["mismatched_sequence"] += 1
            return False
        return True

    def receive_synack(self, probe, body):
        frame = bytes(body[EVENT_HEADER.size:])
        header = parse_handshake_frame(frame)
        if (header.flags != 0x12 or (header.destination, header.source) != connection_tuple(probe)
                or header.acknowledged != (0x10000001 + probe.index * 65537) & 0xFFFFFFFF
                or (probe.received_server_sequence is not None and header.sequence != probe.received_server_sequence)):
            raise ValueError("invalid or mismatched probe SYN-ACK")
        if frame in self.received_synack_frames:
            self.reverse_copy_duplicates += 1
            return
        self.received_synack_frames.add(frame)
        probe.peer_timestamp = header.timestamp
        probe.received_server_sequence = header.sequence
        if probe.completed_at is None and probe.timed_out_at is None:
            probe.completed_at = self.sim.now
            self.send_forward(probe, 0x10)
        self.send_forward(probe, 0x14)

    def server_timeout(self, probe, generation, rto):
        if not probe.server_active or generation != probe.server_generation:
            return
        self.send_synack(probe)
        rto = min(60, 2 * rto)
        self.sim.at(self.sim.now + rto, self.server_timeout, probe, generation, rto)

    def close_server(self, probe):
        probe.server_active = False
        probe.server_closed = True
        probe.server_generation += 1

    def establish_server(self, probe):
        if not probe.server_closed:
            probe.server_established = True
            probe.server_active = False
            probe.server_generation += 1

    def expire_client(self, probe):
        if probe.completed_at is None:
            probe.timed_out_at = self.sim.now

    def measurements(self):
        cutoff = self.sim.stop_at
        completed = [probe for probe in self.probes if probe.completed_at is not None]
        timed_out = sum(probe.timed_out_at is not None for probe in self.probes)
        pending = len(self.probes) - len(completed) - timed_out
        samples = [(probe.completed_at - probe.started_at) * 1000 for probe in completed]
        bounds = [((probe.completed_at if probe.completed_at is not None else
                    probe.timed_out_at if probe.timed_out_at is not None else cutoff) - probe.started_at) * 1000
                  for probe in self.probes]
        budget = 1.5 * self.sim.scenario.rtt_ms
        background = None
        if self.bulk_received_at_start is not None and self.bulk_received_at_end is not None:
            background = ((self.bulk_received_at_end - self.bulk_received_at_start)
                          * self.sim.traffic.payload_bytes * 8 / ((self.sim.traffic.duration_s - self.start_s) * 1e6))
        row = dict(tcp_syn_probe_config=asdict(self.config), tcp_syn_probe_start_s=self.steady_started_at,
                   tcp_syn_probe_dispatch="received-header TCP four-tuple and flags",
                   tcp_syn_probe_cpu_model="Packetization, transport encoding/decoding, checksum verification and endpoint dispatch consume zero simulated CPU time",
                   tcp_syn_probe_model_detail="Decoded forward Ethernet frames and full reverse frames select endpoint state by received IP addresses and TCP ports. SYN timestamps and server ACK sequences are learned from received headers",
                   tcp_syn_probe_forward_received_frames=self.received_frame_counts[False],
                   tcp_syn_probe_reverse_received_frames=self.received_frame_counts[True],
                   tcp_syn_probe_dispatch_rejections=dict(self.dispatch_rejections),
                   tcp_syn_probe_admission_end_s=self.admission_end_s,
                   tcp_syn_probe_steady_state_reached=self.steady_started_at is not None,
                   tcp_syn_probe_stability_history=self.stability_history,
                   tcp_syn_ping_background_goodput_mbps=background,
                   tcp_syn_ping_definition="First SYN submission to L2 until matching SYN-ACK reception, including retransmission waits",
                   tcp_syn_ping_offered=len(self.probes), tcp_syn_ping_completed=len(completed),
                   tcp_syn_ping_timeouts=timed_out, tcp_syn_ping_censored=pending,
                   tcp_syn_ping_failure_pct=100 * (timed_out + pending) / len(self.probes) if self.probes else None,
                   tcp_syn_ping_deadline_miss_upper_pct=100 * (sum(value > budget for value in samples)
                       + timed_out + pending) / len(self.probes) if self.probes else None,
                   tcp_syn_ping_budget_ms=budget, tcp_syn_ping_syn_retransmissions=sum(p.syn_attempts - 1 for p in self.probes),
                   tcp_syn_ping_synack_transmissions=sum(p.synack_attempts for p in self.probes),
                   tcp_syn_probe_forward_frames=self.forward_frames, tcp_syn_probe_forward_frame_bytes=self.forward_frame_bytes,
                   tcp_syn_probe_reverse_requested_bytes=self.reverse_requested_bytes,
                   tcp_syn_probe_reverse_departed_bytes=self.sim.wire[True]["syn_probe"],
                   tcp_syn_probe_reverse_datagrams=self.sim.datagrams[True]["syn_probe"],
                   tcp_syn_probe_reverse_erasures=self.sim.erasures[True]["syn_probe"],
                   tcp_syn_probe_copy_duplicates=self.reverse_copy_duplicates,
                   tcp_syn_probe_all_flushed=self.pending_copies == 0 and self.reverse_requested_bytes == self.sim.wire[True]["syn_probe"],
                   tcp_syn_probe_records=[asdict(probe) for probe in self.probes])
        for percentile in (50, 95, 99):
            row[f"tcp_syn_ping_p{percentile}_ms"] = float(np.percentile(samples, percentile)) if samples else None
            row[f"tcp_syn_ping_cohort_lower_bound_p{percentile}_ms"] = float(np.percentile(bounds, percentile)) if bounds else None
        self.add_traffic_measurements(row)
        return row

    def add_traffic_measurements(self, row):
        """Use the same stable-load interval for payload delivery and wire service."""
        prefix = "tcp_syn_ping_measurement_"
        row[prefix + "snapshots"] = dict(start=self.traffic_at_start, end=self.traffic_at_end)
        row[prefix + "byte_accounting"] = (
            "Shared-link IP serialization during the probe interval, including partial packet service "
            "at both boundaries. Departed whole-packet counters are retained separately.")
        if self.traffic_at_start is None or self.traffic_at_end is None:
            return
        start, end = self.traffic_at_start, self.traffic_at_end
        duration = end["at_s"] - start["at_s"]
        payload = end["delivered_payload_bytes"] - start["delivered_payload_bytes"]
        row.update({prefix + "start_s": start["at_s"], prefix + "end_s": end["at_s"],
                    prefix + "duration_s": duration, prefix + "payload_bytes": payload})
        for direction in ("forward", "reverse"):
            wire = end[direction + "_serialized_ip_bytes"] - start[direction + "_serialized_ip_bytes"]
            departed = end[direction + "_departed_ip_bytes"] - start[direction + "_departed_ip_bytes"]
            row[prefix + direction + "_ip_bytes"] = wire
            row[prefix + direction + "_departed_ip_bytes"] = departed
            row[prefix + direction + "_mbps"] = wire * 8 / (duration * 1e6)
        row[prefix + "extra_forward_ip_pct"] = (
            100 * (row[prefix + "forward_ip_bytes"] / payload - 1) if payload else None)
