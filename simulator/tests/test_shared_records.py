"""Wire framing, channel ordering, and recovery for shared record transport."""

from dataclasses import replace
from functools import partial
from random import Random
from types import SimpleNamespace

import pytest

from l2tunnel_sim.compact import CompactHeaderCodec, tcp_profile_frame
from l2tunnel_sim.compact_ack import CoalescedACKTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.shared_records import (
    NO_RECORD_HEADER, RECORD_HEADER, SYMBOL_HEADER,
    SharedRecordConfig, SharedRecordMultiFlow, SharedRecordReceiver, SharedRecordTransport,
)


def transport_fixture(*, config=None, mtu=1500):
    packets = []
    sim = SimpleNamespace(now=0, scenario=Scenario(20, 0, mtu=mtu),
                          traffic=Traffic(), links=[[SimpleNamespace(rtt=.02)]] * 2,
                          at=lambda *args: None)

    def send(reverse, size, kind, receive):
        packets.append((reverse, size, kind, receive))
        return sim.now, .02

    sim.send = send
    transport = SharedRecordTransport(sim, False, config or SharedRecordConfig(repair_ratio=0))
    return transport, packets


def submit(transport, channel, frame, delivered):
    serial = transport.channel_sequences[channel]
    transport.submit_channel(channel, len(frame), max(0, len(frame) - 66),
                             lambda: delivered.append((channel, serial, frame)), frame=frame)


def simulation(*, loss=0, loss_model="iid", independent=True, payload=256):
    config = SharedRecordConfig(repair_ratio=.25, feedback_ms=1, independent_delivery=independent,
                                repair_window_sources=8, global_repair_every=4)
    factory = partial(CoalescedACKTCP, compact_config=config, ack_coalesce_ms=.25,
                      ack_copies=2, acknowledged_segment_slow_start=True)
    return SharedRecordMultiFlow(
        Scenario(20, loss, loss_model),
        Traffic(duration_s=.1, drain_s=3, frame_bytes=payload + 66, payload_bytes=payload,
                window_bytes=32768, frame_interval_ms=1),
        (PathConfig(10, 10),), Strategy("shared records", mode="tcp", tcp_rto_min_ms=1000), 42, 4,
        compact_config=config, simulation_factory=factory)


@pytest.mark.parametrize("loss,loss_model", [(0, "iid"), (.15, "iid"), (.15, "burst")])
@pytest.mark.parametrize("independent", [True, False])
def test_normal_entry_point_recovers_complete_frames_and_confirms_all_records(loss, loss_model, independent):
    sim = simulation(loss=loss, loss_model=loss_model, independent=independent)
    shared = sim.shared_forward
    received_frames = []
    original_receive = shared.receiver.receive

    def receive(index, data):
        records = original_receive(index, data)
        for channel, serial, frame in records:
            assert frame == shared.callbacks[channel, serial][0]
            received_frames.append((channel, serial, frame))
        return records

    shared.receiver.receive = receive
    sim.run()
    row = sim.measurements()
    assert row["tcp_acked_frames"] == row["tcp_delivered_frames"] == row["offered_frames"]
    assert len(received_frames) == shared.frame_count
    assert shared.delivered_bytes == sum(len(frame) for _, _, frame in received_frames)
    assert shared.base == len(shared.sources)
    assert not shared.buffer_bytes and not shared.callbacks and not shared.receiver.pending
    assert all(flow.compact_forward.transport is shared for flow in sim.flows)
    assert all(sum(flow.datagrams[False].values()) == 0 for flow in sim.flows[1:])
    assert row["forward_wire_bytes"] == (row["forward_source_datagrams"] * (sim.scenario.mtu - 4)
                                         + row["forward_repair_datagrams"] * sim.scenario.mtu)
    assert shared.source_record_bytes + shared.profile_context_bytes == shared.submitted_bytes
    assert shared.submitted_bytes + shared.padding_bytes == len(shared.sources) * shared.record_capacity
    assert shared.anchor_bytes == 2 * len(shared.sources)


def test_independent_channels_release_before_a_gap_with_identical_charged_format():
    transports, packets, delivered = [], [], [[], []]
    for index, independent in enumerate((True, False)):
        transport, wire = transport_fixture(config=SharedRecordConfig(repair_ratio=0,
                                                                       independent_delivery=independent))
        for channel in range(2):
            submit(transport, channel, tcp_profile_frame(payload_bytes=64, sequence=channel), delivered[index])
            transport.flush()
        transports.append(transport)
        packets.append(wire)
    assert transports[0].source_payloads == transports[1].source_payloads
    assert [packet[:3] for packet in packets[0]] == [packet[:3] for packet in packets[1]]
    for transport in transports:
        transport._receive_source(transport.sources[1])
        assert transport.received_prefix == 0
    assert [record[0] for record in delivered[0]] == [1]
    assert delivered[1] == []
    for transport in transports:
        transport._receive_source(transport.sources[0])
        assert transport.received_prefix == 2
    assert [record[0] for record in delivered[0]] == [1, 0]
    assert [record[0] for record in delivered[1]] == [0, 1]


def test_lost_first_fragment_does_not_hide_later_channel_anchor_or_invent_context():
    transport, _ = transport_fixture(mtu=128)
    delivered = []
    first = tcp_profile_frame(payload_bytes=200)
    second = tcp_profile_frame(payload_bytes=10, sequence=17)
    submit(transport, 0, first, delivered)
    submit(transport, 1, second, delivered)
    transport.flush()
    headers = [SYMBOL_HEADER.unpack_from(data) for data in transport.source_payloads]
    assert any(anchor == NO_RECORD_HEADER for _, anchor in headers)
    assert any(0 < anchor < NO_RECORD_HEADER for _, anchor in headers)
    for source in transport.sources[1:]:
        transport._receive_source(source)
    assert delivered == [(1, 0, second)]
    assert transport.receiver.expected[0] == 0
    assert transport.receiver.codecs[0].context is None
    transport._receive_source(transport.sources[0])
    assert delivered == [(1, 0, second), (0, 0, first)]


@pytest.mark.parametrize("header_room", [1, 2, 3, 4])
def test_record_headers_never_split_and_short_symbol_padding_is_charged(header_room):
    transport, packets = transport_fixture(mtu=128)
    delivered = []
    # Fallback records have three codec bytes plus the five-byte channel header.
    first = b"x" * (transport.record_capacity - header_room - 8)
    second = b"second record"
    submit(transport, 0, first, delivered)
    submit(transport, 1, second, delivered)
    transport.flush()
    assert len(transport.sources) == 2
    assert transport.sources[0].size == transport.record_capacity - header_room
    for source, data in zip(transport.sources, transport.source_payloads):
        valid, anchor = SYMBOL_HEADER.unpack_from(data)
        assert len(data) == transport.symbol_bytes
        assert valid == source.size
        assert anchor == 0
        assert not any(data[SYMBOL_HEADER.size + valid:])
        transport._receive_source(source)
    assert delivered == [(0, 0, first), (1, 0, second)]
    assert sum(size for _, size, kind, _ in packets if kind == "source") == (
        2 * transport.source_header + transport.submitted_bytes + transport.padding_bytes
        + 2 * SYMBOL_HEADER.size)


def test_channel_serial_wrap_and_out_of_order_delta_records_preserve_full_frame_bytes():
    transport, _ = transport_fixture()
    channel = 7
    transport.channel_sequences[channel] = 65534
    transport.channel_completed[channel] = 65534
    transport.receiver.expected[channel] = 65534
    delivered = []
    frames = [tcp_profile_frame(sequence=value * 64, identification=value,
                                timestamp=value, payload_bytes=64) for value in (65534, 65535, 65536)]
    for frame in frames:
        submit(transport, channel, frame, delivered)
        transport.flush()
    headers = [RECORD_HEADER.unpack_from(data, SYMBOL_HEADER.size) for data in transport.source_payloads]
    assert [serial for _, serial, _ in headers] == [65534, 65535, 0]
    transport._receive_source(transport.sources[2])
    transport._receive_source(transport.sources[1])
    assert delivered == []
    transport._receive_source(transport.sources[0])
    assert delivered == [(channel, serial, frame) for serial, frame in zip((65534, 65535, 65536), frames)]
    assert transport.receiver.expected[channel] == 65537


def test_receiver_deduplicates_source_and_old_record_after_feedback_releases_sender_bytes():
    transport, _ = transport_fixture()
    delivered = []
    frame = tcp_profile_frame(payload_bytes=64)
    submit(transport, 0, frame, delivered)
    transport.flush()
    original = transport.source_payloads[0]
    transport._receive_source(transport.sources[0])
    transport._receive_feedback(1, 0)
    assert transport.source_payloads[0] is None
    transport._receive_source(transport.sources[0])
    assert transport.receiver.receive(0, original) == []
    assert transport.receiver.receive(1, original) == []
    assert delivered == [(0, 0, frame)]
    assert not transport.receiver.pending


def test_receiver_retains_partial_record_bytes_across_cumulative_feedback():
    transport, _ = transport_fixture(mtu=128)
    delivered = []
    frame = tcp_profile_frame(payload_bytes=200)
    submit(transport, 0, frame, delivered)
    transport.flush()
    transport._receive_source(transport.sources[0])
    transport._receive_feedback(1, 0)
    assert transport.source_payloads[0] is None
    assert 0 in transport.receiver.symbols
    assert not delivered
    for source in transport.sources[1:]:
        transport._receive_source(source)
    assert delivered == [(0, 0, frame)]
    assert not transport.receiver.symbols


def test_local_and_global_repairs_charge_complete_symbols_and_tail_covers_whole_window():
    config = SharedRecordConfig(repair_ratio=0, repair_window_sources=2, global_repair_every=3,
                                authentication_bytes=16)
    transport, packets = transport_fixture(config=config)
    for index in range(10):
        submit(transport, 0, tcp_profile_frame(sequence=index * 64, payload_bytes=64), [])
        transport.flush()
    for _ in range(4):
        transport._repair(False)
    transport._repair(True)
    bands = []
    transport._receive_repair = lambda start, end, seed: bands.append((start, end, seed))
    for _, size, kind, receive in packets:
        assert size <= transport.sim.scenario.mtu
        if kind == "repair":
            assert size == transport.repair_header + transport.symbol_bytes == 1500
            receive()
    assert [(start, end) for start, end, _ in bands] == [(8, 10), (8, 10), (0, 10), (8, 10), (0, 10)]
    assert len({seed for _, _, seed in bands}) == 5
    assert (transport.local_repairs, transport.global_repairs) == (3, 2)
    assert (transport.scheduled_repairs, transport.tail_repairs) == (4, 1)
    assert transport.symbol_bytes == 1500 - 36 - 16 - 4
    transport._feedback()
    assert packets[-1][:3] == (True, 40 + config.authentication_bytes, "feedback")


@pytest.mark.parametrize("seed", [7, 42, 125])
def test_shuffled_wire_symbols_round_trip_independent_contexts_without_sender_record_metadata(seed):
    rng = Random(seed)
    transport, _ = transport_fixture(mtu=128)
    expected = {channel: [] for channel in range(4)}
    for index in range(40):
        channel = rng.randrange(4)
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(250)))
        frame = tcp_profile_frame(sequence=index * 256, timestamp=index, payload_bytes=len(payload))
        header = bytearray(frame[:66])
        header[26] = index // 10  # Change invariant bytes and force new contexts.
        dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
        frame = CompactHeaderCodec._restore(header, dynamic, payload)
        if index % 7 == 0:
            frame = bytes([index]) * (10 + index)  # Exercise full-frame fallback.
        expected[channel].append(frame)
        submit(transport, channel, frame, [])
    transport.flush()
    receiver = SharedRecordReceiver(transport.record_capacity)
    received = {channel: [] for channel in range(4)}
    order = list(range(len(transport.source_payloads)))
    rng.shuffle(order)
    known, prefix = set(), 0
    for index in order:
        data = transport.source_payloads[index]
        for channel, serial, frame in receiver.receive(index, data):
            assert serial == len(received[channel])
            received[channel].append(frame)
        assert receiver.receive(index, data) == []
        known.add(index)
        while prefix in known:
            prefix += 1
        receiver.discard_before(prefix)
    assert received == expected
    assert not receiver.pending and not receiver.symbols


def test_dropped_first_source_and_reverse_feedback_recover_through_normal_links():
    sim = simulation(payload=1448)
    losses = iter([True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(losses)
    reverse_losses = iter([True] + [False] * 10000)
    sim.links[True][0].erasures.lost = lambda: next(reverse_losses)
    sim.run()
    assert sim.shared_forward.recovered_symbols >= 1
    assert sim.shared_forward.base == len(sim.shared_forward.sources)
    assert all(flow.tcp_received == flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)


def test_all_loss_never_delivers_or_confirms_an_unreceived_frame():
    sim = simulation(loss=1)
    sim.run()
    assert all(flow.tcp_received == flow.tcp_acked == 0 for flow in sim.flows)
    assert sim.shared_forward.base == sim.shared_forward.delivered_bytes == 0
    assert sim.shared_forward.callbacks


@pytest.mark.parametrize("valid,anchor", [(0, 0), (33, 0), (4, 0), (10, 6)])
def test_invalid_symbol_lengths_and_truncated_record_anchors_are_rejected(valid, anchor):
    receiver = SharedRecordReceiver(32)
    data = SYMBOL_HEADER.pack(valid, anchor) + bytes(32)
    with pytest.raises(ValueError):
        receiver.receive(0, data)
    with pytest.raises(ValueError, match="symbol length"):
        receiver.receive(1, data[:-1])


def test_sender_rejects_half_range_overflow_without_mutating_record_state():
    transport, _ = transport_fixture()
    transport.channel_sequences[0] = 32767
    with pytest.raises(ValueError, match="half range"):
        submit(transport, 0, tcp_profile_frame(payload_bytes=64), [])
    assert not transport.callbacks and not transport.byte_buffer
    assert transport.frame_count == 0


def test_oversized_encoded_record_does_not_commit_context_or_record_state():
    transport, _ = transport_fixture()
    with pytest.raises(ValueError, match="16-bit length"):
        submit(transport, 0, b"x" * 65535, [])
    assert transport.channel_codecs[0].context is None
    assert transport.channel_sequences[0] == 0
    assert not transport.callbacks and not transport.byte_buffer


@pytest.mark.parametrize("changes", [dict(header_profile="full_l2"), dict(independent_delivery=1),
                                     dict(repair_window_sources=-1), dict(global_repair_every=True)])
def test_invalid_shared_record_configuration_is_rejected(changes):
    with pytest.raises(ValueError):
        replace(SharedRecordConfig(), **changes)
