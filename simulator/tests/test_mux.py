"""Finite generic-mux classification, admission and byte-dispatch regressions."""

from collections import deque
from heapq import heappop, heappush
from itertools import count
from types import SimpleNamespace

import pytest

from l2tunnel_sim.compact import CompactHeaderCodec, _checksum, tcp_profile_frame
from l2tunnel_sim.mux import DuplexMux, frame_tuple


class Clock:
    def __init__(self):
        self.now = 0.0
        self.events = []
        self.sequence = count()
        self.links = [[SimpleNamespace(free_at=0.0, bytes_per_s=1_000_000)],
                      [SimpleNamespace(free_at=0.0, bytes_per_s=100_000)]]

    def at(self, when, callback, *args):
        heappush(self.events, (when, next(self.sequence), callback, args))

    def run(self, until=float("inf")):
        while self.events and self.events[0][0] <= until:
            self.now, _, callback, args = heappop(self.events)
            callback(*args)


class Transport:
    def __init__(self, sim, reverse, window=8):
        self.sim = sim
        self.reverse = reverse
        self.config = SimpleNamespace(block_sources=window)
        self.sources = []
        self.source_queue = deque()
        self.buffer_bytes = 0
        self.source_header = 26
        self.base = 0
        self.capacity_callback = None
        self.trace = []
        self.automatic_confirmation = True
        self.automatic_delivery = True

    def submit_channel(self, channel, frame_bytes, payload_bytes, deliver, *, frame, deliver_frame):
        assert deliver_frame
        assert frame_bytes == len(frame)
        assert not self.source_queue
        assert len(self.sources) - self.base < self.config.block_sources
        self.sources.append(frame)
        self.trace.append((self.sim.now, channel, frame, payload_bytes, deliver))
        link = self.sim.links[self.reverse][0]
        assert link.free_at <= self.sim.now
        link.free_at = self.sim.now + (len(frame) + self.source_header) / link.bytes_per_s
        if self.automatic_delivery:
            self.sim.at(link.free_at + .01, deliver, frame)
        if self.automatic_confirmation:
            self.sim.at(link.free_at + .02, self.confirm, len(self.sources))

    def confirm(self, prefix):
        self.base = max(self.base, prefix)
        if self.capacity_callback:
            self.capacity_callback()


def fixture(channels=16, window=8, mapping="crc32"):
    sim = Clock()
    transports = (Transport(sim, False, window), Transport(sim, True, window))
    return sim, transports, DuplexMux(sim, transports, channels, mapping=mapping)


def frame(port=40000, *, sequence=0, payload=64, reverse=False, flags=0x18):
    original = tcp_profile_frame(sequence=sequence, payload_bytes=payload, flags=flags)
    header = bytearray(original[:66])
    header[34:38] = port.to_bytes(2, "big") + (443).to_bytes(2, "big")
    if reverse:
        header[:12] = header[6:12] + header[:6]
        header[26:34] = header[30:34] + header[26:30]
        header[34:38] = header[36:38] + header[34:36]
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, original[66:])


def register(mux, reverse, frames, received):
    for data in frames:
        mux.register_endpoint(reverse, frame_tuple(data), received.append)


def test_frame_derived_classifier_is_bidirectional_and_ignores_tcp_flags():
    _, _, mux = fixture()
    data = frame()
    reply = frame(reverse=True, payload=0, flags=0x12)
    syn = frame(payload=0, flags=0x02)
    assert frame_tuple(data) == ((b"\x0a\x00\x00\x01", 40000), (b"\x0a\x00\x00\x02", 443))
    assert frame_tuple(reply) == tuple(reversed(frame_tuple(data)))
    assert mux.channel_for_frame(data) == mux.channel_for_frame(reply) == mux.channel_for_frame(syn)
    other = fixture()[2]
    assert other.channel_for_frame(data) == mux.channel_for_frame(data)


@pytest.mark.parametrize("damage", ["ip_checksum", "tcp_checksum", "truncated", "fragment", "tcp_header", "non_tcp"])
def test_invalid_frame_is_rejected_before_queue_or_counters_change(damage):
    sim, _, mux = fixture()
    data = bytearray(frame())
    if damage == "ip_checksum":
        data[24] ^= 1
    elif damage == "tcp_checksum":
        data[-1] ^= 1
    elif damage == "truncated":
        del data[-1]
    elif damage == "fragment":
        data[20:22] = b"\x20\x00"
    elif damage == "tcp_header":
        data[46] = 0x10
    else:
        data[23] = 17
    with pytest.raises(ValueError):
        mux.submit_frame(False, data)
    assert not sim.events
    assert mux.submitted_frames == mux.queued_frames == [0, 0]


def test_ethernet_padding_is_preserved_and_excluded_from_tcp_payload_count():
    sim, transports, mux = fixture()
    data = frame(payload=0) + bytes(12)
    received = []
    register(mux, False, [data], received)
    mux.submit_frame(False, data)
    sim.run()
    assert received == [data]
    assert transports[0].trace[0][3] == 0
    assert mux.delivered_bytes[0] == len(data)


@pytest.mark.parametrize("channels", [0, -1, 257, True, 1.5])
def test_channel_count_validation(channels):
    with pytest.raises(ValueError, match="channel_count"):
        fixture(channels)


def test_endpoint_registration_is_idempotent_and_rejects_conflicts():
    _, _, mux = fixture()
    received = []
    identity = frame_tuple(frame())
    mux.register_endpoint(False, identity, received.append)
    mux.register_endpoint(False, identity, received.append)
    with pytest.raises(ValueError, match="different receiver"):
        mux.register_endpoint(False, identity, lambda data: None)
    with pytest.raises(ValueError, match="IPv4 bytes"):
        mux.register_endpoint(False, ((b"short", 1), identity[1]), received.append)
    with pytest.raises(ValueError, match="boolean"):
        mux.submit_frame(1, frame())


def test_round_robin_preserves_fifo_within_colliding_connection_bucket():
    sim, transports, mux = fixture(2)
    by_channel = {}
    for port in range(40000, 40100):
        candidate = frame(port)
        by_channel.setdefault(mux.channel_for_frame(candidate), []).append(port)
    first_port, collision_port = by_channel[0][:2]
    other_port = by_channel[1][0]
    frames = [frame(first_port, sequence=1), frame(collision_port, sequence=2),
              frame(first_port, sequence=3), frame(other_port, sequence=4),
              frame(other_port, sequence=5)]
    received = []
    register(mux, False, frames, received)
    for data in frames:
        mux.submit_frame(False, data)
    assert not transports[0].trace
    sim.run()
    assert [row[1] for row in transports[0].trace] == [0, 1, 0, 1, 0]
    assert [row[2] for row in transports[0].trace if row[1] == 0] == frames[:3]
    assert received == [frames[index] for index in (0, 3, 1, 4, 2)]
    assert mux.flushed
    assert mux.channel_peak_frames[0][0] == 3


def test_identical_frames_follow_equal_policy_without_producer_parameters():
    sim, transports, mux = fixture()
    received = []
    data = frame()
    register(mux, False, [data], received)
    first = mux.submit_frame(False, data)
    second = mux.submit_frame(False, bytes(data))
    assert first == second
    sim.run()
    assert received == [data, data]
    assert [row[1:4] for row in transports[0].trace] == [(first, data, 64)] * 2
    assert mux.submitted_frames[0] == mux.admitted_frames[0] == mux.delivered_frames[0] == 2


def test_many_connections_and_both_directions_use_only_sixteen_actual_channels():
    sim, transports, mux = fixture(16, window=16)
    received = [[], []]
    expected = [[], []]
    for index in range(256):
        for reverse in (False, True):
            data = frame(40000 + index, reverse=reverse)
            register(mux, reverse, [data], received[reverse])
            assigned = mux.submit_frame(reverse, data)
            assert 0 <= assigned < 16
            expected[reverse].append(data)
    sim.run()
    for reverse in (False, True):
        assert sorted(received[reverse]) == sorted(expected[reverse])
        assert mux.channel_ids[reverse] == set(range(16))
        assert {row[1] for row in transports[reverse].trace} == set(range(16))
        assert mux.submitted_bytes[reverse] == mux.admitted_bytes[reverse] == mux.delivered_bytes[reverse]
    assert len(set.union(*mux.channel_ids)) == 16


def test_full_window_stops_ingress_until_actual_capacity_callback():
    sim, transports, mux = fixture(window=1)
    transport = transports[0]
    transport.automatic_confirmation = False
    received = []
    frames = [frame(sequence=index) for index in range(3)]
    register(mux, False, frames, received)
    for data in frames:
        mux.submit_frame(False, data)
    sim.run()
    assert len(transport.trace) == 1
    assert mux.queued_frames[0] == 2
    assert mux.window_stall_events[0] == 1
    assert not sim.events
    sim.now = .1
    transport.confirm(1)
    transport.capacity_callback()
    assert len(sim.events) == 1
    sim.run()
    assert len(transport.trace) == 2
    assert transport.trace[1][0] == .1
    transport.confirm(2)
    sim.run()
    assert len(transport.trace) == 3
    assert received == frames
    assert mux.queue_wait_max_ms[0] >= 100


def test_record_credit_blocks_only_its_channel_and_reopens_on_capacity_callback():
    sim, transports, mux = fixture(channels=2, mapping="connection_round_robin")
    transport = transports[0]
    blocked = {0}
    transport.can_submit_channel = lambda channel: channel not in blocked
    frames = [frame(40000, sequence=1), frame(40001, sequence=2), frame(40000, sequence=3)]
    received = []
    register(mux, False, frames, received)
    for data in frames:
        mux.submit_frame(False, data)
    sim.run()
    assert received == [frames[1]]
    assert mux.queued_frames[0] == 2
    blocked.clear()
    transport.capacity_callback()
    sim.run()
    assert received == [frames[1], frames[0], frames[2]]
    assert mux.flushed


def test_pending_encoded_sources_block_new_frame_even_with_window_space():
    sim, transports, mux = fixture()
    transport = transports[0]
    transport.source_queue.append(b"already encoded")
    transport.buffer_bytes = len(transport.source_queue[0])
    data = frame()
    received = []
    register(mux, False, [data], received)
    mux.submit_frame(False, data)
    sim.run()
    assert not transport.trace
    assert mux.queued_frames[0] == 1
    transport.source_queue.clear()
    transport.buffer_bytes = 0
    transport.capacity_callback()
    sim.run()
    assert received == [data]


def test_existing_and_later_fifo_reservations_delay_admission():
    sim, transports, mux = fixture()
    data = frame()
    received = []
    register(mux, False, [data], received)
    sim.links[0][0].free_at = .1
    mux.submit_frame(False, data)
    sim.at(.05, setattr, sim.links[0][0], "free_at", .2)
    sim.run()
    assert transports[0].trace[0][0] == .2
    assert mux.queue_wait_max_ms[0] == pytest.approx(200)


def test_decoded_tuple_selects_endpoint_instead_of_submission_identity():
    sim, transports, mux = fixture(1)
    transports[0].automatic_delivery = False
    first, second = frame(40000), frame(40001)
    received_a, received_b = [], []
    register(mux, False, [first], received_a)
    register(mux, False, [second], received_b)
    mux.submit_frame(False, first)
    sim.run()
    decoded_callback = transports[0].trace[0][4]
    decoded_callback(second)
    assert received_a == []
    assert received_b == [second]
    with pytest.raises(ValueError, match="no registered endpoint"):
        decoded_callback(frame(40002))


def test_endpoint_reentrant_reply_is_deferred_and_uses_reverse_policy():
    sim, transports, mux = fixture()
    request, response = frame(payload=0, flags=2), frame(reverse=True, payload=0, flags=0x12)
    received = []
    def receive_request(actual):
        assert actual == request
        mux.submit_frame(True, response)
        assert not transports[1].trace
    mux.register_endpoint(False, frame_tuple(request), receive_request)
    mux.register_endpoint(True, frame_tuple(response), received.append)
    mux.submit_frame(False, request)
    sim.run()
    assert received == [response]
    assert mux.channel_ids[0] == mux.channel_ids[1]


def test_backlog_estimate_and_metrics_keep_original_full_frame_bytes():
    sim, transports, mux = fixture()
    data = frame(payload=100)
    received = []
    register(mux, False, [data], received)
    sim.links[0][0].free_at = .1
    transport = transports[0]
    transport.source_queue.append(b"encoded")
    transport.buffer_bytes = 7
    mux.submit_frame(False, data)
    expected = 100 + (len(data) + 7 + 2 * transport.source_header) / 1000
    assert mux.queue_delay_ms(False) == pytest.approx(expected)
    report = mux.measurements()
    assert report["mux_forward"]["queued_bytes"] == len(data)
    assert report["mux_forward"]["queue_wait_count"] == 0
    transport.source_queue.clear()
    transport.buffer_bytes = 0
    transport.capacity_callback()
    sim.run()
    report = mux.measurements()["mux_forward"]
    assert report["submitted_bytes"] == report["admitted_bytes"] == report["delivered_bytes"] == len(data)
    assert report["queued_frames"] == report["queued_bytes"] == 0
    assert report["queue_wait_mean_ms"] == pytest.approx(100)
    assert report["queue_delay_estimate_ms"] == 0


def test_ipv4_and_tcp_options_are_validated_using_actual_header_lengths():
    original = frame(payload=10)
    # Add four IPv4 option bytes and update only the IPv4 header length/checksum.
    data = bytearray(original[:34] + b"\x01\x01\x00\x00" + original[34:])
    data[14] = 0x46
    data[16:18] = (len(data) - 14).to_bytes(2, "big")
    data[24:26] = b"\x00\x00"
    data[24:26] = _checksum(data[14:38])
    assert frame_tuple(data) == frame_tuple(original)


def test_blocked_forward_window_does_not_create_reverse_priority_or_block_it():
    sim, transports, mux = fixture(window=1)
    forward, reverse = frame(), frame(reverse=True)
    received = [[], []]
    register(mux, False, [forward], received[0])
    register(mux, True, [reverse], received[1])
    transports[0].sources.append(b"unconfirmed")
    mux.submit_frame(False, forward)
    mux.submit_frame(True, reverse)
    sim.run()
    assert not transports[0].trace
    assert received == [[], [reverse]]
    assert mux.queued_frames == [1, 0]
    transports[0].confirm(1)
    sim.run()
    assert received == [[forward], [reverse]]


def test_capacity_notification_during_submission_does_not_duplicate_admission():
    sim, transports, mux = fixture()
    transport = transports[0]
    original_submit = transport.submit_channel
    def submit_and_notify(*args, **kwargs):
        original_submit(*args, **kwargs)
        transport.capacity_callback()
    transport.submit_channel = submit_and_notify
    frames = [frame(sequence=index) for index in range(3)]
    received = []
    register(mux, False, frames, received)
    for data in frames:
        mux.submit_frame(False, data)
    sim.run()
    assert received == frames
    assert len(transport.trace) == 3
    assert mux.admitted_frames[0] == 3


def test_transport_direction_and_simulator_must_match_mux():
    sim = Clock()
    forward, reverse = Transport(sim, False), Transport(sim, True)
    with pytest.raises(ValueError, match="match their direction"):
        DuplexMux(sim, (reverse, forward))
    with pytest.raises(ValueError, match="share the simulator"):
        DuplexMux(sim, (forward, Transport(Clock(), True)))
    assert forward.capacity_callback is reverse.capacity_callback is None


@pytest.mark.parametrize("encapsulation", ["udp", "raw_ipv4_crc32"])
@pytest.mark.parametrize("loss", [0, .15])
@pytest.mark.parametrize("mapping", ["crc32", "connection_round_robin"])
def test_actual_bidirectional_wire_transport_preserves_colliding_frame_contexts(encapsulation, loss, mapping):
    from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport
    from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
    from l2tunnel_sim.model import Simulation

    sim = Simulation(Scenario(70, loss), Traffic(duration_s=.1, drain_s=2),
                     (PathConfig(100, 10),), Strategy("finite mux fixture", mode="arq"), 42)
    sim.produce = lambda: None
    config = CompactWireConfig(encapsulation=encapsulation, repair_ratio=.25,
                               short_source_max_bytes=128, short_source_copies=4)
    transports = tuple(CompactWireTransport(sim, reverse, config) for reverse in (False, True))
    mux = DuplexMux(sim, transports, channel_count=1, mapping=mapping)
    expected, received = [[], []], [[], []]
    for index, port in enumerate((40000, 40001, 40000, 40002)):
        for reverse in (False, True):
            data = frame(port, sequence=index * 64, reverse=reverse, payload=64 if index % 2 else 0)
            expected[reverse].append(data)
            register(mux, reverse, [data], received[reverse])
            mux.submit_frame(reverse, data)
    sim.run()
    assert received == expected
    assert mux.flushed
    for reverse, transport in enumerate(transports):
        assert mux.channel_ids[reverse] == {0}
        assert set(transport.channel_sequences) == {0}
        assert transport.base == len(transport.sources)
        assert not transport.source_queue
        assert not transport.callbacks
        assert not transport.wire_invalid_packets
        assert mux.submitted_bytes[reverse] == mux.delivered_bytes[reverse]
        assert sum(sim.wire[reverse].values()) == sim.links[reverse][0].reserved_bytes


def test_unknown_connection_mapping_is_rejected():
    with pytest.raises(ValueError, match="connection mapping"):
        fixture(mapping="probe_priority")


def test_round_robin_mapping_is_persistent_bidirectional_and_reverse_first():
    _, _, mux = fixture(mapping="connection_round_robin")
    for index in range(40):
        response = frame(41000 + index, reverse=True, payload=0, flags=0x12)
        request = frame(41000 + index, payload=0, flags=0x02)
        assert mux.channel_for_frame(response, reverse=True) == index % 16
        assert mux.channel_for_frame(request, reverse=False) == index % 16
    for index in reversed(range(40)):
        assert mux.channel_for_frame(frame(41000 + index)) == index % 16
    metrics = mux.measurements()
    assert metrics["mux_mapping"] == "connection_round_robin"
    assert metrics["mux_assigned_connection_count"] == 40
    assert set(mux.connection_channels[0].values()) == set(range(16))
    assert set(mux.connection_channels[1].values()) == set(range(16))


def test_default_crc_mapping_retains_exact_prior_assignments():
    _, _, mux = fixture()
    assignments = [mux.channel_for_frame(frame(40000 + index)) for index in range(16)]
    assert assignments == [7, 3, 14, 10, 4, 0, 13, 9, 0, 4, 9, 13, 3, 7, 10, 14]
    assert mux.measurements()["mux_mapping"] == "crc32"
    assert mux.measurements()["mux_assigned_connection_count"] == 16


def test_first_seen_mapping_uses_all_channels_for_sixteen_distinct_connections():
    sim, transports, mux = fixture(mapping="connection_round_robin", window=16)
    frames = [frame(40000 + index) for index in range(16)]
    received = []
    register(mux, False, frames, received)
    assert mux.measurements()["mux_assigned_connection_count"] == 0
    assigned = [mux.submit_frame(False, data) for data in frames]
    assert assigned == list(range(16))
    sim.run()
    assert received == frames
    assert {row[1] for row in transports[0].trace} == set(range(16))
    assert mux.channel_ids[0] == set(range(16))


def test_round_robin_mapping_has_no_tcp_flag_port_range_or_endpoint_role_policy():
    schedules = [
        [(40000, 0x18, False), (49152, 0x02, False), (443, 0x12, True), (1234, 0x10, True)],
        [(49152, 0x02, False), (40000, 0x18, False), (1234, 0x10, True), (443, 0x12, True)],
    ]
    for schedule in schedules:
        sim, _, mux = fixture(channels=2, mapping="connection_round_robin")
        received = [[], []]
        assigned = []
        for port, flags, reverse in schedule:
            data = frame(port, flags=flags, reverse=reverse, payload=0)
            register(mux, reverse, [data], received[reverse])
            assigned.append(mux.submit_frame(reverse, data))
        assert assigned == [0, 1, 0, 1]
        sim.run()
        assert sum(map(len, received)) == 4
        assert len(set.union(*mux.channel_ids)) <= 2


def test_round_robin_mapping_reuses_fifo_buckets_and_common_window_after_pool_wrap():
    sim, transports, mux = fixture(channels=2, window=1, mapping="connection_round_robin")
    transport = transports[0]
    transport.automatic_confirmation = False
    frames = [frame(40000 + index) for index in range(3)]
    received = []
    register(mux, False, frames, received)
    assert [mux.submit_frame(False, data) for data in frames] == [0, 1, 0]
    sim.run()
    assert [row[2] for row in transport.trace] == frames[:1]
    assert mux.queued_frames[0] == 2
    for prefix in (1, 2):
        transport.confirm(prefix)
        sim.run()
    assert [row[1] for row in transport.trace] == [0, 1, 0]
    assert received == frames
    assert mux.channel_ids[0] == {0, 1}
    assert mux.submitted_frames[0] == mux.admitted_frames[0] == mux.delivered_frames[0] == 3


def test_lost_initial_frame_creates_no_remote_binding_until_decoded_delivery():
    sim, transports, mux = fixture(mapping="connection_round_robin")
    transports[0].automatic_delivery = False
    data = frame()
    received = []
    register(mux, False, [data], received)
    assert mux.connection_channels == [{}, {}]
    assigned = mux.submit_frame(False, data)
    identity = tuple(sorted(frame_tuple(data)))
    assert mux.connection_channels[0][identity] == assigned
    assert mux.connection_channels[1] == {}
    sim.run()
    assert mux.connection_channels[1] == {}
    assert not received
    transports[0].trace[0][4](data)
    assert mux.connection_channels[1] == {identity: assigned}
    assert mux.learned_binding_count == [0, 1]
    assert received == [data]


def test_reordered_decoded_arrivals_teach_actual_channels_before_replies():
    sim, transports, mux = fixture(mapping="connection_round_robin")
    transports[0].automatic_delivery = False
    requests = [frame(40000 + index, payload=0, flags=2) for index in range(2)]
    replies = [frame(40000 + index, reverse=True, payload=0, flags=0x12) for index in range(2)]
    delivered = []
    for request, reply in zip(requests, replies):
        def respond(actual, response=reply):
            mux.submit_frame(True, response)
        mux.register_endpoint(False, frame_tuple(request), respond)
        mux.register_endpoint(True, frame_tuple(reply), delivered.append)
    assert [mux.submit_frame(False, request) for request in requests] == [0, 1]
    sim.run()
    assert mux.connection_channels[1] == {}
    # Connection B arrives first, although its transmitted channel is one.
    transports[0].trace[1][4](requests[1])
    transports[0].trace[0][4](requests[0])
    sim.run()
    by_frame = {row[2]: row[1] for row in transports[1].trace}
    assert by_frame == {replies[0]: 0, replies[1]: 1}
    assert sorted(delivered) == sorted(replies)
    assert mux.local_assignment_count == [2, 0]
    assert mux.learned_binding_count == [0, 2]


def test_conflicting_simultaneous_initiation_is_explicitly_rejected():
    sim, transports, mux = fixture(channels=2, mapping="connection_round_robin")
    for transport in transports:
        transport.automatic_delivery = False
    request = frame(40000, payload=0, flags=2)
    unrelated = frame(40001, reverse=True, payload=0, flags=2)
    simultaneous = frame(40000, reverse=True, payload=0, flags=2)
    received = []
    register(mux, False, [request], received)
    register(mux, True, [unrelated, simultaneous], received)
    assert mux.submit_frame(False, request) == 0
    assert mux.submit_frame(True, unrelated) == 0
    assert mux.submit_frame(True, simultaneous) == 1
    sim.run()
    with pytest.raises(ValueError, match="simultaneous connection assignment"):
        transports[0].trace[0][4](request)
    assert received == []
    assert mux.delivered_frames == [0, 0]


def test_reverse_initiated_decoded_frame_teaches_forward_reply_affinity():
    sim, transports, mux = fixture(mapping="connection_round_robin")
    request = frame(40000, reverse=True, payload=0, flags=2)
    response = frame(40000, payload=0, flags=0x12)
    received = []
    mux.register_endpoint(True, frame_tuple(request), lambda actual: mux.submit_frame(False, response))
    mux.register_endpoint(False, frame_tuple(response), received.append)
    assert mux.submit_frame(True, request) == 0
    assert mux.connection_channels[0] == {}
    sim.run()
    assert received == [response]
    assert mux.local_assignment_count == [0, 1]
    assert mux.learned_binding_count == [1, 0]
    assert mux.channel_ids == [{0}, {0}]


def test_actual_wire_context_loss_defers_reply_binding_for_only_that_connection():
    from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport
    from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
    from l2tunnel_sim.model import Simulation

    sim = Simulation(Scenario(70, 0), Traffic(duration_s=.1, drain_s=2),
                     (PathConfig(100, 10),), Strategy("causal wire fixture", mode="arq"), 42)
    sim.produce = lambda: None
    config = CompactWireConfig(repair_ratio=0, independent_delivery=True)
    transports = tuple(CompactWireTransport(sim, reverse, config) for reverse in (False, True))
    mux = DuplexMux(sim, transports, channel_count=16, mapping="connection_round_robin")
    requests = [frame(40000 + index, payload=0, flags=2) for index in range(2)]
    replies = [frame(40000 + index, reverse=True, payload=0, flags=0x12) for index in range(2)]
    received = []
    for request, reply in zip(requests, replies):
        mux.register_endpoint(False, frame_tuple(request), lambda actual, response=reply: mux.submit_frame(True, response))
        mux.register_endpoint(True, frame_tuple(reply), received.append)
    erased = iter([True])
    sim.links[0][0].erasures.lost = lambda: next(erased, False)
    assert [mux.submit_frame(False, request) for request in requests] == [0, 1]
    observations = []
    sim.at(.05, lambda: observations.append(dict(mux.connection_channels[True])))
    sim.run()
    second_identity = tuple(sorted(frame_tuple(requests[1])))
    assert observations == [{second_identity: 1}]
    assert received == [replies[1], replies[0]]
    assert mux.local_assignment_count == [2, 0]
    assert mux.learned_binding_count == [0, 2]
    assert mux.channel_ids == [{0, 1}, {0, 1}]
    assert all(transport.base == len(transport.sources) for transport in transports)
