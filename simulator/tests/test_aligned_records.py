"""Self-describing aligned records, charged bytes, and shared TCP integration."""

import csv
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import pytest

from l2tunnel_sim.aligned_records import (
    CHANNEL_HEADER, CONTEXT_LENGTH_KIND, FRAGMENT_HEADER, FRAGMENT_KIND, PACKED_PREDICTIVE_KIND,
    TIMESTAMP_PAIR_KIND, TIMESTAMP_PAIRS,
    AlignedRecordConfig, AlignedRecordReceiver, AlignedRecordTransport, encoded_record_length,
)
from l2tunnel_sim.compact import CompactHeaderCodec, tcp_profile_frame
from l2tunnel_sim.compact_ack import CoalescedACKTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.shared_records import SharedRecordConfig, SharedRecordMultiFlow


def transport_fixture(*, config=None, mtu=1500):
    packets = []
    sim = SimpleNamespace(now=0, scenario=Scenario(20, 0, mtu=mtu), traffic=Traffic(),
                          links=[[SimpleNamespace(rtt=.02)]] * 2, at=lambda *args: None)

    def send(reverse, size, kind, receive):
        packets.append((reverse, size, kind, receive))
        return sim.now, .02

    sim.send = send
    return AlignedRecordTransport(sim, False, config or SharedRecordConfig(repair_ratio=0)), packets


def submit(transport, channel, frame, delivered):
    transport.submit_channel(channel, len(frame), max(0, len(frame) - 66),
                             lambda: delivered.append((channel, frame)), frame=frame)


@pytest.mark.parametrize("loss,loss_model", [(0, "iid"), (.15, "iid"), (.15, "burst")])
@pytest.mark.parametrize("independent", [True, False])
@pytest.mark.parametrize("elide", [False, True])
@pytest.mark.parametrize("packed", [False, True])
def test_normal_shared_entry_point_preserves_complete_frames_and_exact_wire_bytes(loss, loss_model, independent, elide, packed):
    config = AlignedRecordConfig(repair_ratio=.25, feedback_ms=1, independent_delivery=independent,
                                 elide_payload_length=elide, packed_predictive_records=packed)
    factory = partial(CoalescedACKTCP, compact_config=config, ack_copies=3, ack_coalesce_ms=.25)
    sim = SharedRecordMultiFlow(
        Scenario(20, loss, loss_model), Traffic(duration_s=.05, drain_s=3, payload_bytes=1448,
                frame_bytes=1514, window_bytes=32768, frame_interval_ms=1),
        (PathConfig(10, 10),), Strategy("aligned", mode="tcp", tcp_rto_min_ms=1000), 42, 4,
        compact_config=config, simulation_factory=factory, transport_type=AlignedRecordTransport)
    transport = sim.shared_forward
    original_receive = transport.receiver.receive
    received_frames, contexts = [], []

    def receive(index, data):
        records = original_receive(index, data)
        for channel, serial, frame in records:
            if frame is None:
                contexts.append((channel, serial))
            else:
                assert frame == transport.callbacks[channel, serial][0]
                received_frames.append(frame)
        return records

    transport.receiver.receive = receive
    sim.run()
    assert all(flow.tcp_received == flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    assert len(received_frames) == transport.frame_count
    assert len(contexts) == transport.context_records
    assert transport.delivered_bytes == sum(map(len, received_frames))
    assert transport.base == len(transport.sources)
    assert not transport.buffer_bytes and not transport.source_queue and not transport.callbacks
    assert all(transport.source_header + source.size <= 1496 for source in transport.sources)
    owner = sim.flows[0]
    assert owner.wire[False]["source"] == sum(transport.source_header + source.size for source in transport.sources)
    assert owner.wire[False]["repair"] == owner.datagrams[False]["repair"] * 1500
    assert transport.submitted_bytes == (transport.profile_context_bytes + transport.source_record_bytes
        + transport.channel_header_bytes + transport.fragment_sources * FRAGMENT_HEADER.size)
    assert bool(transport.elided_length_records) == elide
    assert bool(transport.packed_predictive_records) == packed


def test_typical_1448_payload_uses_one_source_after_separate_context_record():
    transport, packets = transport_fixture()
    delivered = []
    first = tcp_profile_frame(payload_bytes=1448)
    second = tcp_profile_frame(payload_bytes=1448, sequence=1448, identification=1,
                               timestamp=9, echoed_timestamp=9)
    submit(transport, 3, first, delivered)
    submit(transport, 3, second, delivered)
    assert len(transport.sources) == 3
    assert [source.size for source in transport.sources] == [72, 1455, 1460]
    assert [size for _, size, kind, _ in packets if kind == "source"] == [108, 1491, 1496]
    assert transport.context_records == 1
    assert transport.aligned_records == transport.frame_count == 2
    assert transport.fragmented_records == 0
    transport._receive_source(transport.sources[1])
    assert delivered == []
    transport._receive_source(transport.sources[0])
    assert delivered == [(3, first)]
    transport._receive_source(transport.sources[2])
    assert delivered == [(3, first), (3, second)]


def test_zero_extension_is_implicit_for_sources_and_charged_for_repairs():
    transport, packets = transport_fixture()
    submit(transport, 0, tcp_profile_frame(payload_bytes=64), [])
    for source, data in zip(transport.sources, transport.source_payloads):
        assert len(data) == transport.symbol_bytes == 1460
        assert not any(data[source.size:])
        assert encoded_record_length(data[CHANNEL_HEADER.size:]) == source.size - CHANNEL_HEADER.size
    source_bytes = sum(size for _, size, kind, _ in packets if kind == "source")
    assert source_bytes == transport.submitted_bytes + transport.source_header * len(transport.sources)
    assert transport.implicit_padding_bytes == len(transport.sources) * 1460 - transport.submitted_bytes
    assert transport.padding_bytes == transport.anchor_bytes == 0
    transport._repair(False)
    assert packets[-1][:3] == (False, 1500, "repair")


def test_existing_nondelta_record_kind_has_an_unambiguous_padded_length():
    frame = tcp_profile_frame(payload_bytes=64)
    encoded = CompactHeaderCodec(delta=False).encode(frame)
    context, record = encoded[:69], encoded[69:]
    receiver = AlignedRecordReceiver(1460)
    for serial, body in enumerate((context, record)):
        data = CHANNEL_HEADER.pack(0, serial) + body
        data += bytes(1460 - len(data))
        assert encoded_record_length(data[CHANNEL_HEADER.size:]) == len(body)
        expected = None if serial == 0 else frame
        assert receiver.receive(serial, data) == [(0, serial, expected)]


def test_small_mtu_and_authentication_budget_can_fragment_a_context_without_tcp_delivery():
    transport, packets = transport_fixture(mtu=128, config=SharedRecordConfig(
        repair_ratio=0, authentication_bytes=64))
    delivered = []
    frame = tcp_profile_frame(payload_bytes=12)
    submit(transport, 0, frame, delivered)
    assert transport.context_records == 1
    assert transport.fragmented_records == 1 and transport.fragment_sources == 5
    assert transport.aligned_records == 1
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame)]
    assert all(size <= 124 for _, size, kind, _ in packets if kind == "source")
    transport._repair(False)
    assert packets[-1][:3] == (False, 128, "repair")


def test_context_refresh_and_fallback_frames_round_trip_without_extra_tcp_delivery():
    transport, _ = transport_fixture()
    delivered = []
    first = tcp_profile_frame(payload_bytes=32)
    header = bytearray(first[:66])
    header[26] = 99
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    changed = CompactHeaderCodec._restore(header, dynamic, b"p" * 32)
    fallback = b"unsupported Ethernet frame"
    frames = [first, changed, fallback]
    for frame in frames:
        submit(transport, 0, frame, delivered)
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame) for frame in frames]
    assert transport.context_records == 2
    assert transport.frame_count == 3
    assert transport.channel_sequences[0] == transport.channel_completed[0] == 5


def test_large_frame_fragments_use_one_serial_and_require_every_received_chunk():
    transport, _ = transport_fixture()
    delivered = []
    frame = tcp_profile_frame(payload_bytes=4000)
    submit(transport, 5, frame, delivered)
    assert transport.context_records == 1
    assert transport.fragmented_records == 1 and transport.fragment_sources == 3
    records = transport.source_payloads[1:]
    assert [CHANNEL_HEADER.unpack_from(data) for data in records] == [(5, 1)] * 3
    assert [FRAGMENT_HEADER.unpack_from(data, CHANNEL_HEADER.size) for data in records] == [
        (FRAGMENT_KIND, 4004, 0), (FRAGMENT_KIND, 4004, 1452), (FRAGMENT_KIND, 4004, 2904)]
    transport._receive_source(transport.sources[0])
    transport._receive_source(transport.sources[3])
    transport._receive_source(transport.sources[3])
    transport._receive_source(transport.sources[1])
    assert delivered == []
    transport._receive_source(transport.sources[2])
    assert delivered == [(5, frame)]
    assert not transport.receiver.fragments


def test_independent_channel_release_and_ordered_control_share_identical_wire_bytes():
    transports, wires, delivered = [], [], [[], []]
    for index, independent in enumerate((True, False)):
        transport, packets = transport_fixture(config=SharedRecordConfig(repair_ratio=0,
                                                                         independent_delivery=independent))
        for channel in range(2):
            submit(transport, channel, tcp_profile_frame(payload_bytes=64, sequence=channel), delivered[index])
        transports.append(transport)
        wires.append(packets)
    assert transports[0].source_payloads == transports[1].source_payloads
    assert [packet[:3] for packet in wires[0]] == [packet[:3] for packet in wires[1]]
    for transport in transports:
        transport._receive_source(transport.sources[2])
        transport._receive_source(transport.sources[3])
    assert [channel for channel, _ in delivered[0]] == [1]
    assert delivered[1] == []
    for transport in transports:
        transport._receive_source(transport.sources[0])
        transport._receive_source(transport.sources[1])
    assert [channel for channel, _ in delivered[0]] == [1, 0]
    assert [channel for channel, _ in delivered[1]] == [0, 1]


def test_context_and_data_sequences_wrap_without_losing_decoder_order():
    transport, _ = transport_fixture()
    transport.channel_sequences[0] = transport.channel_completed[0] = 65534
    transport.receiver.expected[0] = 65534
    delivered = []
    frames = [tcp_profile_frame(payload_bytes=64, sequence=index * 64) for index in range(2)]
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert [CHANNEL_HEADER.unpack_from(data)[1] for data in transport.source_payloads] == [65534, 65535, 0]
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame) for frame in frames]
    assert transport.receiver.expected[0] == 65537


def test_cumulative_feedback_unblocks_queued_sources_with_a_one_symbol_window():
    transport, _ = transport_fixture(config=SharedRecordConfig(repair_ratio=0, block_sources=1))
    delivered = []
    frame = tcp_profile_frame(payload_bytes=4000)
    submit(transport, 0, frame, delivered)
    assert len(transport.sources) == 1
    assert len(transport.source_queue) == 3 and transport.buffer_bytes > 0
    for index in range(4):
        assert len(transport.sources) - transport.base == 1
        transport._receive_source(transport.sources[index])
        transport._receive_feedback(index + 1, 0)
        assert transport.source_payloads[index] is None
    assert delivered == [(0, frame)]
    assert not transport.source_queue and not transport.buffer_bytes
    assert transport.sent_bytes == transport.submitted_bytes


def test_source_dedup_after_feedback_does_not_repeat_application_delivery():
    transport, _ = transport_fixture()
    delivered = []
    frame = tcp_profile_frame(payload_bytes=64)
    submit(transport, 0, frame, delivered)
    for source in transport.sources:
        transport._receive_source(source)
    transport._receive_feedback(len(transport.sources), 0)
    for source in transport.sources:
        transport._receive_source(source)
    assert delivered == [(0, frame)]


@pytest.mark.parametrize("body", [b"", b"\x03\x00\x00", b"\x03\x00\x00\x01\x80",
                                  b"\x03\x00\x00\x01" + b"\x80" * 6,
                                  b"\x00\x00\x41" + bytes(65), b"\x05\x00\x00",
                                  b"\x02\x00\x05abc", b"\x01\x00\x00" + bytes(22)])
def test_malformed_or_truncated_self_describing_records_are_rejected(body):
    with pytest.raises(ValueError):
        encoded_record_length(body)


def test_fragment_offsets_lengths_conflicts_and_padding_are_validated():
    transport, _ = transport_fixture()
    submit(transport, 0, tcp_profile_frame(payload_bytes=4000), [])
    data = transport.source_payloads[1]
    receiver = AlignedRecordReceiver(1460)
    assert receiver.receive(1, data) == []
    assert receiver.receive(1, data) == []
    conflicting = bytearray(data)
    conflicting[CHANNEL_HEADER.size + FRAGMENT_HEADER.size + 10] ^= 1
    with pytest.raises(ValueError, match="conflicting"):
        receiver.receive(100, bytes(conflicting))
    for total, offset in ((4005, 0), (4004, 1), (4004, 4356), (0, 0)):
        changed = bytearray(data)
        FRAGMENT_HEADER.pack_into(changed, CHANNEL_HEADER.size, FRAGMENT_KIND, total, offset)
        with pytest.raises(ValueError):
            receiver.receive(101, bytes(changed))
    tail = bytearray(transport.source_payloads[-1])
    tail[-1] = 1
    with pytest.raises(ValueError, match="padding"):
        receiver.receive(102, bytes(tail))


def test_nonzero_record_padding_and_wrong_symbol_length_are_rejected():
    transport, _ = transport_fixture()
    submit(transport, 0, b"fallback", [])
    receiver = AlignedRecordReceiver(1460)
    data = bytearray(transport.source_payloads[0])
    data[-1] = 1
    with pytest.raises(ValueError, match="padding"):
        receiver.receive(0, bytes(data))
    with pytest.raises(ValueError, match="symbol length"):
        receiver.receive(1, bytes(data[:-1]))


def test_rejected_record_restores_sender_context_and_has_no_partial_submission():
    transport, _ = transport_fixture()
    transport.channel_sequences[0] = 32766
    with pytest.raises(ValueError, match="serial-number"):
        submit(transport, 0, tcp_profile_frame(payload_bytes=64), [])
    assert transport.channel_codecs[0].context is None
    assert not transport.sources and not transport.source_queue and not transport.callbacks
    transport.channel_sequences[0] = 0
    with pytest.raises(ValueError, match="length"):
        submit(transport, 0, b"x" * 65535, [])
    assert not transport.sources and not transport.callbacks


def test_deadline_study_old_and_aligned_formats_share_export_columns(monkeypatch, tmp_path):
    pytest.importorskip("aioquic")
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    import shared_record_deadlines

    rows = []
    for wire_format in ("shared_records", "aligned_records"):
        profile = dict(name="Export regression " + wire_format, wire_format=wire_format,
                       compact=dict(repair_ratio=.2), window_bytes=16384, flow_count=2,
                       payload_rate_mbps=10, ack_coalesce_ms=.25, ack_copies=2, rto_min_ms=1000)
        task = dict(profile=profile, payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
                    rtt_ms=20, loss_rate=0, loss_model="iid", mtu=1500, duration_s=.06,
                    warmup_s=.01, drain_s=.5, seed=42)
        rows.append(shared_record_deadlines.execute(task))
    assert rows[0].keys() == rows[1].keys()
    assert rows[0]["shared_aligned_records"] is None
    assert rows[1]["shared_aligned_records"] > 0
    for records in (rows, list(reversed(rows))):
        path = tmp_path / "replications.csv"
        shared_record_deadlines.write_csv(path, records)
        with path.open(newline="") as stream:
            exported = list(csv.DictReader(stream))
        assert len(exported) == 2
        assert exported[0].keys() == rows[0].keys()


def test_elided_length_keeps_long_timestamp_and_echo_deltas_in_one_full_symbol():
    frames = [tcp_profile_frame(payload_bytes=1448),
              tcp_profile_frame(payload_bytes=1448, sequence=1448, identification=1,
                                timestamp=256, echoed_timestamp=256)]
    transports, packets = [], []
    for elide in (False, True):
        transport, wire = transport_fixture(config=AlignedRecordConfig(repair_ratio=0,
                                                                        elide_payload_length=elide))
        delivered = []
        for frame in frames:
            submit(transport, 0, frame, delivered)
        for source in reversed(transport.sources):
            transport._receive_source(source)
        assert delivered == [(0, frame) for frame in frames]
        transports.append(transport)
        packets.append(wire)
    control, optimized = transports
    assert len(control.sources) == 4 and control.fragment_sources == 2
    assert len(optimized.sources) == 3 and optimized.fragment_sources == 0
    assert optimized.sources[-1].size == 1460
    assert packets[1][-1][:3] == (False, 1496, "source")
    assert optimized.elided_length_records == 2


def test_elided_records_wait_for_context_and_an_earlier_payload_length_change():
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, elide_payload_length=True))
    delivered = []
    frames = [tcp_profile_frame(payload_bytes=64),
              tcp_profile_frame(payload_bytes=256, sequence=64, identification=1),
              tcp_profile_frame(payload_bytes=256, sequence=320, identification=2)]
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert [data[CHANNEL_HEADER.size] for data in transport.source_payloads] == [0, 6, 3, 6]
    transport._receive_source(transport.sources[3])
    transport._receive_source(transport.sources[1])
    assert delivered == []
    assert transport.receiver.codecs[0].context is None
    transport._receive_source(transport.sources[0])
    assert delivered == [(0, frames[0])]
    assert transport.receiver.codecs[0].context[16:18] == (64 + 52).to_bytes(2, "big")
    transport._receive_source(transport.sources[2])
    assert delivered == [(0, frame) for frame in frames]
    assert transport.receiver.codecs[0].context[16:18] == (256 + 52).to_bytes(2, "big")


def test_arbitrary_payload_size_changes_use_explicit_lengths_then_elide_again():
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, elide_payload_length=True))
    delivered, frames = [], []
    sizes = [64, 0, 0, 511, 511, 1448, 1448, 1, 1]
    for index, size in enumerate(sizes):
        frame = tcp_profile_frame(payload_bytes=size, sequence=index * 64, identification=index)
        frames.append(frame)
        submit(transport, 0, frame, delivered)
    kinds = [data[CHANNEL_HEADER.size] for data in transport.source_payloads]
    assert kinds == [0, 6, 3, 6, 3, 6, 3, 6, 3, 6]
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame) for frame in frames]


def test_oversized_elision_candidates_keep_explicit_lengths_in_fragmented_records():
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, elide_payload_length=True))
    delivered = []
    frames = [tcp_profile_frame(payload_bytes=4000, sequence=index * 4000) for index in range(2)]
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert transport.elided_length_records == 0
    assert transport.fragmented_records == 2
    for data in transport.source_payloads[1:]:
        kind, _, offset = FRAGMENT_HEADER.unpack_from(data, CHANNEL_HEADER.size)
        assert kind == FRAGMENT_KIND
        if offset == 0:
            assert data[CHANNEL_HEADER.size + FRAGMENT_HEADER.size] == 3
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame) for frame in frames]


def test_elided_record_without_context_is_rejected():
    receiver = AlignedRecordReceiver(1460)
    data = CHANNEL_HEADER.pack(0, 0) + bytes([CONTEXT_LENGTH_KIND, 0])
    data += bytes(1460 - len(data))
    with pytest.raises(ValueError, match="context"):
        receiver.receive(0, data)


@pytest.mark.parametrize("problem", ["negative_payload", "oversized_payload", "overflowing_delta", "padding"])
def test_elided_record_context_length_and_deferred_padding_validation(problem):
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, elide_payload_length=True))
    submit(transport, 0, tcp_profile_frame(payload_bytes=64), [])
    context, data = map(bytearray, transport.source_payloads)
    if problem in ("negative_payload", "oversized_payload"):
        total = 51 if problem == "negative_payload" else 4000
        begin = CHANNEL_HEADER.size + 3 + 16
        context[begin:begin + 2] = total.to_bytes(2, "big")
    elif problem == "overflowing_delta":
        begin = CHANNEL_HEADER.size + 1
        data[begin:begin + 7] = b"\x01" + b"\x80" * 6
    else:
        data[-1] = 1
    receiver = AlignedRecordReceiver(1460)
    assert receiver.receive(1, bytes(data)) == []
    with pytest.raises(ValueError):
        receiver.receive(0, bytes(context))


@pytest.mark.parametrize("value", [1, 0, None, "true"])
def test_payload_length_elision_flag_requires_boolean(value):
    with pytest.raises(ValueError, match="boolean"):
        AlignedRecordConfig(elide_payload_length=value)


def restore_modified_frame(frame, changes):
    header = bytearray(frame[:66])
    for start, value in changes.items():
        header[start:start + len(value)] = value
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, frame[66:])


@pytest.mark.parametrize("presence", range(32))
def test_predictive_kind_packs_all_five_presence_bits_and_preserves_frame_bytes(presence):
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, packed_predictive_records=True))
    first = tcp_profile_frame(payload_bytes=64)
    second = tcp_profile_frame(payload_bytes=64, sequence=64, identification=1,
                               flags=0x19 if presence & 1 else 0x18,
                               window=0 if presence & 2 else 65535,
                               timestamp=1 if presence & 8 else 0,
                               echoed_timestamp=1 if presence & 16 else 0)
    if presence & 4:
        second = restore_modified_frame(second, {52: b"\x00\x01"})
    delivered = []
    for frame in (first, second):
        submit(transport, 0, frame, delivered)
    record = transport.source_payloads[-1][CHANNEL_HEADER.size:transport.sources[-1].size]
    assert record == bytes([(presence << 3) | PACKED_PREDICTIVE_KIND]) + b"\x01" * presence.bit_count() + second[66:]
    assert transport.packed_predictive_records == 1
    assert transport.source_payloads[1][CHANNEL_HEADER.size] == 3
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, first), (0, second)]


def test_predictive_record_saves_four_bytes_against_kind_six_for_1448_payload():
    frames = [tcp_profile_frame(), tcp_profile_frame(sequence=1448, identification=1,
                                                     timestamp=256, echoed_timestamp=256)]
    transports = []
    for packed in (False, True):
        transport, packets = transport_fixture(config=AlignedRecordConfig(
            repair_ratio=0, elide_payload_length=True, packed_predictive_records=packed))
        delivered = []
        for frame in frames:
            submit(transport, 2, frame, delivered)
        for source in reversed(transport.sources):
            transport._receive_source(source)
        assert delivered == [(2, frame) for frame in frames]
        assert [source.size + transport.source_header for source in transport.sources] == [
            size for reverse, size, kind, callback in packets if kind == "source"]
        transports.append(transport)
    control, packed = transports
    assert [source.size for source in control.sources] == [72, 1453, 1460]
    assert [source.size for source in packed.sources] == [72, 1453, 1456]
    assert control.source_payloads[1] == packed.source_payloads[1]
    assert packed.fragment_sources == 0


def test_predictive_wrap_and_unsigned_remaining_differences_are_exact():
    first = restore_modified_frame(tcp_profile_frame(sequence=0xFFFFFFF0, identification=65535,
            acknowledged=0xFFFFFFFF, timestamp=0xFFFFFFFF, echoed_timestamp=0xFFFFFFFE), {52: b"\xff\xff"})
    second = tcp_profile_frame(sequence=1432, identification=0, acknowledged=0xFFFFFFFF,
                               timestamp=256, echoed_timestamp=0, flags=0x10, window=0)
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, packed_predictive_records=True))
    delivered = []
    for frame in (first, second):
        submit(transport, 0, frame, delivered)
    record = transport.source_payloads[-1][CHANNEL_HEADER.size:transport.sources[-1].size]
    assert record == b"\xff\xf8\x01\x01\x01\x81\x02\x02" + second[66:]
    for source in transport.sources:
        transport._receive_source(source)
    assert delivered == [(0, first), (0, second)]


def test_predictive_large_unsigned_differences_preserve_full_varints():
    first = restore_modified_frame(tcp_profile_frame(payload_bytes=64, flags=1, window=1,
                                                     timestamp=1, echoed_timestamp=1), {52: b"\x00\x01"})
    second = tcp_profile_frame(payload_bytes=64, sequence=64, identification=1,
                               flags=0, window=0, timestamp=0, echoed_timestamp=0)
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, packed_predictive_records=True))
    delivered = []
    for frame in (first, second):
        submit(transport, 0, frame, delivered)
    record = transport.source_payloads[-1][CHANNEL_HEADER.size:transport.sources[-1].size]
    assert record == b"\xff\xff\x01" + b"\xff\xff\x03" * 2 + b"\xff\xff\xff\xff\x0f" * 2 + second[66:]
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, first), (0, second)]


@pytest.mark.parametrize("payload_size", [0, 1, 127, 128, 1448])
def test_predictive_sequence_delta_uses_context_payload_size(payload_size):
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, packed_predictive_records=True))
    frames = [tcp_profile_frame(payload_bytes=payload_size, sequence=index * payload_size,
                                identification=index) for index in range(2)]
    delivered = []
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert transport.source_payloads[-1][CHANNEL_HEADER.size] == PACKED_PREDICTIVE_KIND
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame) for frame in frames]


@pytest.mark.parametrize("change", [dict(payload_bytes=65), dict(identification=2),
                                    dict(sequence=0), dict(acknowledged=1)])
def test_predictive_exceptions_fall_back_then_next_contiguous_frame_recovers(change):
    fields = dict(payload_bytes=64, sequence=64, identification=1)
    fields.update(change)
    frames = [tcp_profile_frame(payload_bytes=64), tcp_profile_frame(**fields)]
    fields["sequence"] += fields["payload_bytes"]
    fields["identification"] += 1
    frames.append(tcp_profile_frame(**fields))
    transport, _ = transport_fixture(config=AlignedRecordConfig(
        repair_ratio=0, elide_payload_length=True, packed_predictive_records=True))
    delivered = []
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert [data[CHANNEL_HEADER.size] for data in transport.source_payloads] == [
        0, 6, 3 if "payload_bytes" in change else 6, PACKED_PREDICTIVE_KIND]
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame) for frame in frames]


def test_predictive_escape_and_context_refresh_preserve_independent_channel_order():
    first = tcp_profile_frame(payload_bytes=64)
    contiguous = tcp_profile_frame(payload_bytes=64, sequence=64, identification=1)
    refreshed = restore_modified_frame(tcp_profile_frame(payload_bytes=64, sequence=128, identification=2),
                                       {26: b"\x0a\x01\x02\x03"})
    next_frame = restore_modified_frame(tcp_profile_frame(payload_bytes=64, sequence=192, identification=3),
                                        {26: b"\x0a\x01\x02\x03"})
    frames = [first, b"unsupported Ethernet frame", contiguous, refreshed, next_frame]
    transport, _ = transport_fixture(config=AlignedRecordConfig(
        repair_ratio=0, elide_payload_length=True, packed_predictive_records=True))
    delivered = []
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert [data[CHANNEL_HEADER.size] for data in transport.source_payloads] == [0, 6, 2, 7, 0, 6, 7]
    independent = tcp_profile_frame(payload_bytes=64)
    submit(transport, 1, independent, delivered)
    for source in reversed(transport.sources[1:]):
        transport._receive_source(source)
        transport._receive_source(source)
    assert delivered == [(1, independent)]
    transport._receive_source(transport.sources[0])
    assert delivered == [(1, independent)] + [(0, frame) for frame in frames]


def test_predictive_oversized_records_keep_explicit_fragment_format():
    transport, _ = transport_fixture(config=AlignedRecordConfig(
        repair_ratio=0, elide_payload_length=True, packed_predictive_records=True))
    frames = [tcp_profile_frame(payload_bytes=4000, sequence=index * 4000, identification=index)
              for index in range(2)]
    delivered = []
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert transport.packed_predictive_records == transport.elided_length_records == 0
    assert transport.fragmented_records == 2
    for data in transport.source_payloads[1:]:
        kind, total, offset = FRAGMENT_HEADER.unpack_from(data, CHANNEL_HEADER.size)
        assert kind == FRAGMENT_KIND
        if offset == 0:
            assert data[CHANNEL_HEADER.size + FRAGMENT_HEADER.size] == 3
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame) for frame in frames]


def test_predictive_record_without_context_is_rejected():
    receiver = AlignedRecordReceiver(1460)
    data = CHANNEL_HEADER.pack(0, 0) + bytes([PACKED_PREDICTIVE_KIND]) + bytes(1456)
    with pytest.raises(ValueError, match="context"):
        receiver.receive(0, data)


def test_predictive_complete_symbol_with_truncated_payload_is_rejected():
    receiver = AlignedRecordReceiver(72)
    frame = tcp_profile_frame(payload_bytes=64)
    context = CHANNEL_HEADER.pack(0, 0) + b"\x00\x00\x42" + frame[:66]
    assert receiver.receive(0, context) == [(0, 0, None)]
    # A five-byte TSval delta leaves only 63 of the context's 64 payload bytes.
    data = CHANNEL_HEADER.pack(0, 1) + b"\x47\xff\xff\xff\xff\x0f" + bytes(63)
    assert len(data) == 72
    with pytest.raises(ValueError, match="truncated"):
        receiver.receive(1, data)


@pytest.mark.parametrize("problem", ["negative_payload", "oversized_payload", "overflowing_delta", "padding", "short_symbol"])
def test_predictive_malformed_context_record_and_padding_are_rejected(problem):
    transport, _ = transport_fixture(config=AlignedRecordConfig(repair_ratio=0, packed_predictive_records=True))
    submit(transport, 0, tcp_profile_frame(payload_bytes=64), [])
    submit(transport, 0, tcp_profile_frame(payload_bytes=64, sequence=64, identification=1), [])
    data = bytearray(transport.source_payloads[-1])
    receiver = AlignedRecordReceiver(1460)
    for index in (0, 1):
        receiver.receive(index, transport.source_payloads[index])
    if problem in ("negative_payload", "oversized_payload"):
        context = bytearray(receiver.codecs[0].context)
        context[16:18] = (51 if problem == "negative_payload" else 4000).to_bytes(2, "big")
        receiver.codecs[0].context = bytes(context)
    elif problem == "overflowing_delta":
        begin = CHANNEL_HEADER.size
        data[begin:begin + 7] = b"\x0f" + b"\x80" * 6
    elif problem == "padding":
        data[-1] = 1
    else:
        data.pop()
    with pytest.raises(ValueError):
        receiver.receive(2, bytes(data))


@pytest.mark.parametrize("value", [1, 0, None, "true"])
def test_packed_predictive_flag_requires_boolean(value):
    with pytest.raises(ValueError, match="boolean"):
        AlignedRecordConfig(packed_predictive_records=value)


def test_packed_predictive_flag_is_opt_in():
    assert AlignedRecordConfig().packed_predictive_records is False


@pytest.mark.parametrize("pair_index", range(32))
@pytest.mark.parametrize("payload_size", [0, 1, 64, 1448, 1454])
def test_timestamp_pair_dictionary_preserves_every_codeword_and_opaque_payload(pair_index, payload_size):
    timestamp, echoed = TIMESTAMP_PAIRS[pair_index]
    first = tcp_profile_frame(payload_bytes=payload_size)
    second = tcp_profile_frame(payload_bytes=payload_size, sequence=payload_size,
                               identification=1, timestamp=timestamp, echoed_timestamp=echoed)
    payload = bytes((index * 31 + 7) % 256 for index in range(payload_size))
    dynamic = b"".join(second[area] for area in CompactHeaderCodec.dynamic)
    second = CompactHeaderCodec._restore(second[:66], dynamic, payload)
    transport, _ = transport_fixture(config=AlignedRecordConfig(
        repair_ratio=0, packed_predictive_records=True, timestamp_pair_dictionary=True))
    delivered = []
    for frame in (first, second):
        submit(transport, 0, frame, delivered)
    record = transport.source_payloads[-1][CHANNEL_HEADER.size:transport.sources[-1].size]
    assert record == bytes([TIMESTAMP_PAIR_KIND | pair_index << 3]) + payload
    assert transport.sources[-1].size == payload_size + 4
    assert transport.timestamp_pair_candidates == transport.timestamp_pair_records == 1
    assert transport.timestamp_pair_saved_bytes == 1 + bool(echoed)
    assert transport.packed_predictive_records == 1
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, first), (0, second)]


def test_timestamp_pair_wrap_and_record_serial_wrap_preserve_exact_context():
    first = tcp_profile_frame(sequence=0xFFFFFFF0, identification=65535,
                              acknowledged=0xFFFFFFFF, timestamp=0xFFFFFFF6,
                              echoed_timestamp=0xFFFFFFFB)
    second = tcp_profile_frame(sequence=1432, identification=0, acknowledged=0xFFFFFFFF,
                               timestamp=8, echoed_timestamp=12)
    transport, _ = transport_fixture(config=AlignedRecordConfig(
        repair_ratio=0, packed_predictive_records=True, timestamp_pair_dictionary=True))
    transport.channel_sequences[0] = transport.channel_completed[0] = 65534
    transport.receiver.expected[0] = 65534
    delivered = []
    for frame in (first, second):
        submit(transport, 0, frame, delivered)
    assert CHANNEL_HEADER.unpack_from(transport.source_payloads[-1]) == (0, 0)
    assert transport.source_payloads[-1][CHANNEL_HEADER.size] & 7 == TIMESTAMP_PAIR_KIND
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, first), (0, second)]
    assert transport.receiver.codecs[0].context == second[:66]
    assert transport.channel_completed[0] == 65537


@pytest.mark.parametrize("change,kind", [
    ({"timestamp": 20}, 7), ({"echoed_timestamp": 16}, 7),
    ({"flags": 0x19}, 7), ({"window": 0}, 7), ({"urgent": 1}, 7),
    ({"sequence": 0}, 6), ({"identification": 2}, 6), ({"acknowledged": 1}, 6),
    ({"payload_bytes": 65}, 3),
])
def test_timestamp_pair_exceptions_fall_back_and_subsequent_match_resumes(change, kind):
    fields = dict(payload_bytes=64, sequence=64, identification=1, timestamp=18, echoed_timestamp=18)
    fields.update({key: value for key, value in change.items() if key != "urgent"})
    frames = [tcp_profile_frame(payload_bytes=64), tcp_profile_frame(**fields)]
    fields["sequence"] += fields["payload_bytes"]
    fields["identification"] += 1
    fields["timestamp"] += 18
    fields["echoed_timestamp"] += 18
    frames.append(tcp_profile_frame(**fields))
    if "urgent" in change:
        frames[1:] = [restore_modified_frame(frame, {52: b"\x00\x01"}) for frame in frames[1:]]
    transport, _ = transport_fixture(config=AlignedRecordConfig(
        repair_ratio=0, elide_payload_length=True, packed_predictive_records=True,
        timestamp_pair_dictionary=True))
    delivered = []
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert transport.source_payloads[-2][CHANNEL_HEADER.size] & 7 == kind
    assert transport.source_payloads[-1][CHANNEL_HEADER.size] & 7 == TIMESTAMP_PAIR_KIND
    assert transport.timestamp_pair_records == 1
    for source in reversed(transport.sources):
        transport._receive_source(source)
    assert delivered == [(0, frame) for frame in frames]


def test_timestamp_pair_context_loss_refresh_and_fallback_keep_channel_order():
    first = tcp_profile_frame(payload_bytes=64)
    second = tcp_profile_frame(payload_bytes=64, sequence=64, identification=1,
                               timestamp=18, echoed_timestamp=18)
    refreshed = restore_modified_frame(tcp_profile_frame(payload_bytes=64, sequence=128,
        identification=2, timestamp=36, echoed_timestamp=36), {26: b"\x0a\x01\x02\x03"})
    following = restore_modified_frame(tcp_profile_frame(payload_bytes=64, sequence=192,
        identification=3, timestamp=54, echoed_timestamp=54), {26: b"\x0a\x01\x02\x03"})
    frames = [first, b"unsupported Ethernet frame", second, refreshed, following]
    transport, _ = transport_fixture(config=AlignedRecordConfig(
        repair_ratio=0, elide_payload_length=True, packed_predictive_records=True,
        timestamp_pair_dictionary=True))
    delivered = []
    for frame in frames:
        submit(transport, 0, frame, delivered)
    assert [data[CHANNEL_HEADER.size] & 7 for data in transport.source_payloads] == [0, 6, 2, 5, 0, 6, 5]
    independent = tcp_profile_frame(payload_bytes=64)
    submit(transport, 1, independent, delivered)
    for source in reversed(transport.sources[1:]):
        transport._receive_source(source)
        transport._receive_source(source)
    assert delivered == [(1, independent)]
    transport._receive_source(transport.sources[0])
    assert delivered == [(1, independent)] + [(0, frame) for frame in frames]
    assert transport.timestamp_pair_records == 2


@pytest.mark.parametrize("payload_size", [1456, 1457, 4000])
def test_timestamp_pair_oversized_candidates_keep_original_fragment_policy(payload_size):
    frames = [tcp_profile_frame(payload_bytes=payload_size),
              tcp_profile_frame(payload_bytes=payload_size, sequence=payload_size,
                                identification=1, timestamp=18, echoed_timestamp=18)]
    transports = []
    for enabled in (False, True):
        transport, _ = transport_fixture(config=AlignedRecordConfig(
            repair_ratio=0, elide_payload_length=True, packed_predictive_records=True,
            timestamp_pair_dictionary=enabled))
        delivered = []
        for frame in frames:
            submit(transport, 0, frame, delivered)
        for source in reversed(transport.sources):
            transport._receive_source(source)
        assert delivered == [(0, frame) for frame in frames]
        assert transport.timestamp_pair_records == transport.timestamp_pair_saved_bytes == 0
        transports.append(transport)
    assert transports[0].source_payloads == transports[1].source_payloads
    assert transports[0].sources == transports[1].sources
    assert transports[1].fragment_sources > 0


@pytest.mark.parametrize("problem", ["missing_context", "negative_payload", "oversized_payload", "padding", "short_symbol"])
def test_timestamp_pair_context_and_padding_validation(problem):
    transport, _ = transport_fixture(config=AlignedRecordConfig(
        repair_ratio=0, packed_predictive_records=True, timestamp_pair_dictionary=True))
    submit(transport, 0, tcp_profile_frame(payload_bytes=64), [])
    submit(transport, 0, tcp_profile_frame(payload_bytes=64, sequence=64, identification=1,
                                          timestamp=18, echoed_timestamp=18), [])
    data = bytearray(transport.source_payloads[-1])
    receiver = AlignedRecordReceiver(1460)
    if problem == "missing_context":
        CHANNEL_HEADER.pack_into(data, 0, 0, 0)
    else:
        for index in (0, 1):
            receiver.receive(index, transport.source_payloads[index])
        if problem in ("negative_payload", "oversized_payload"):
            context = bytearray(receiver.codecs[0].context)
            context[16:18] = (51 if problem == "negative_payload" else 4000).to_bytes(2, "big")
            receiver.codecs[0].context = bytes(context)
        elif problem == "padding":
            data[-1] = 1
        else:
            data.pop()
    with pytest.raises(ValueError):
        receiver.receive(2, bytes(data))


@pytest.mark.parametrize("value", [1, 0, None, "true"])
def test_timestamp_pair_option_requires_boolean(value):
    with pytest.raises(ValueError, match="boolean"):
        AlignedRecordConfig(packed_predictive_records=True, timestamp_pair_dictionary=value)


def test_timestamp_pair_option_is_opt_in_and_requires_predictive_records():
    assert AlignedRecordConfig().timestamp_pair_dictionary is False
    assert len(TIMESTAMP_PAIRS) == len(set(TIMESTAMP_PAIRS)) == 32
    with pytest.raises(ValueError, match="requires packed"):
        AlignedRecordConfig(timestamp_pair_dictionary=True)


def test_timestamp_pair_disabled_wire_bytes_and_requested_savings_are_exact():
    frames = [tcp_profile_frame(), tcp_profile_frame(sequence=1448, identification=1,
                                                      timestamp=18, echoed_timestamp=18)]
    outputs = []
    for enabled in (False, True):
        transport, packets = transport_fixture(config=AlignedRecordConfig(
            repair_ratio=0, packed_predictive_records=True, timestamp_pair_dictionary=enabled))
        for frame in frames:
            submit(transport, 0, frame, [])
        outputs.append((transport, packets))
    control, packed = (item[0] for item in outputs)
    record = control.source_payloads[-1][CHANNEL_HEADER.size:control.sources[-1].size]
    assert record == b"\xc7\x12\x12" + frames[-1][66:]
    assert control.timestamp_pair_records == control.timestamp_pair_saved_bytes == 0
    assert control.source_payloads[:-1] == packed.source_payloads[:-1]
    assert control.sources[-1].size - packed.sources[-1].size == packed.timestamp_pair_saved_bytes == 2
    assert sum(packet[1] for packet in outputs[0][1]) - sum(packet[1] for packet in outputs[1][1]) == 2
