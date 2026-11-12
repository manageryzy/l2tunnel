"""Byte fidelity, distinct duplicate events, batching and charged loss copies."""

from functools import partial
from heapq import heappop

import pytest

from l2tunnel_sim.aggregate_ack import (
    ACKAggregator, AggregateACKTCP, BATCH_HEADER, BATCH_DELTA_KIND, BYTE_DELTA_KIND, BYTE_VARINT_KIND, DELTA_RECORD_HEADER,
    RECORD_HEADER, decode_batch, encode_batch, validate_ack_frame,
)
from l2tunnel_sim.aligned_records import _unsigned_varint
from l2tunnel_sim.compact import CompactConfig, CompactHeaderCodec, tcp_profile_frame
from l2tunnel_sim.compact_ack import PendingACK
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.multiflow import MultiFlow


def simulation(*, flows=2, copies=3, hold_ms=.5, duration=.02, drain=2, mtu=1500,
               record_encoding="full", distinct_flow_headers=False):
    config = CompactConfig(repair_ratio=0, header_profile="tcp_delta")
    factory = partial(AggregateACKTCP, compact_config=config, transport_type=CompactARQTransport,
                      ack_coalesce_ms=.25, ack_copies=copies, acknowledged_segment_slow_start=True,
                      distinct_flow_headers=distinct_flow_headers)
    sim = MultiFlow(Scenario(20, 0, mtu=mtu),
                    Traffic(duration_s=duration, drain_s=drain, frame_bytes=1514, payload_bytes=1448,
                            frame_interval_ms=.2, window_bytes=flows * 20 * 1448),
                    (PathConfig(),), Strategy("aggregate", mode="tcp", tcp_rto_min_ms=1000),
                    42, flows, simulation_factory=factory)
    sim.ack_aggregate = ACKAggregator(sim.flows, hold_ms=hold_ms, record_encoding=record_encoding)
    return sim


def drain_events(sim):
    while sim.events:
        when, _, callback, args = heappop(sim.events)
        sim.now = when
        for flow in sim.flows:
            flow.now = when
        callback(*args)


def test_batch_roundtrip_preserves_all_frame_bytes_and_metadata():
    frame = tcp_profile_frame(acknowledged=0xFFFFFFFA, timestamp=1234,
                              echoed_timestamp=987, payload_bytes=0, flags=0x10)
    records = [(0, 2**63 + 7, frame), (255, 11, frame)]
    encoded = encode_batch(records)
    assert len(encoded) == 4 + 75 * 2
    assert decode_batch(encoded) == records


@pytest.mark.parametrize("damage", ["truncate", "trailing", "version", "checksum"])
def test_batch_parser_rejects_malformed_envelopes_and_frames(damage):
    data = bytearray(encode_batch([(1, 7, tcp_profile_frame(payload_bytes=0, flags=0x10))]))
    if damage == "truncate":
        data.pop()
    elif damage == "trailing":
        data.append(0)
    elif damage == "version":
        data[0] = 2
    else:
        data[-1] ^= 1
    with pytest.raises(ValueError):
        decode_batch(data)


def test_full_mtu_batches_preserve_distinct_duplicate_ack_events_and_exact_timing():
    sim = simulation()
    received = []
    for channel, flow in enumerate(sim.flows):
        flow.on_ack = lambda ack, echo, channel=channel: received.append((channel, ack, echo))
    packet = PendingACK(2**32 + 1, .00012345, .00006789)
    for _ in range(20):
        for flow in sim.flows:
            flow.transmit_ack(packet)
    drain_events(sim)
    aggregate = sim.ack_aggregate
    assert aggregate.batch_sizes == {19: 2, 2: 1}
    assert len(received) == 40
    assert received.count((0, packet.acknowledged, packet.echoed_timestamp)) == 20
    assert received.count((1, packet.acknowledged, packet.echoed_timestamp)) == 20
    assert sum(flow.ack_copy_duplicates for flow in sim.flows) == 80
    assert aggregate.verified_records == 120
    assert sim.flows[0].wire[True]["ack_batch"] == 3 * (3 * 32 + 40 * 75)
    assert sim.flows[0].datagrams[True]["ack_batch"] == 9
    assert max(aggregate.hold_delays_ms) <= .5
    assert not aggregate.records and aggregate.flushed


@pytest.mark.parametrize("record_encoding", ["full", "batch_delta", "batch_varint"])
@pytest.mark.parametrize("distinct_flow_headers", [False, True])
@pytest.mark.parametrize("copies", [3, 4])
def test_ordinary_multiflow_entrypoint_completes_and_charges_every_copy_once(record_encoding, distinct_flow_headers, copies):
    sim = simulation(record_encoding=record_encoding, distinct_flow_headers=distinct_flow_headers, copies=copies).run()
    aggregate = sim.ack_aggregate
    assert all(flow.tcp_acked == flow.tcp_received == len(flow.sent_times) for flow in sim.flows)
    assert sum(flow.ack_copy_duplicates for flow in sim.flows) == (copies - 1) * aggregate.submitted_records
    assert aggregate.requested_wire_bytes == sum(flow.wire[True]["ack_batch"] for flow in sim.flows)
    assert aggregate.flushed and not aggregate.records
    assert max(aggregate.hold_delays_ms) <= .5 + 1e-10
    assert sum(aggregate.encoding_datagrams.values()) == sim.flows[0].datagrams[True]["ack_batch"]
    assert aggregate.saved_wire_bytes == aggregate.full_equivalent_wire_bytes - aggregate.requested_wire_bytes
    assert bool(aggregate.saved_wire_bytes) == (record_encoding != "full")


@pytest.mark.parametrize("record_encoding", ["full", "batch_delta", "batch_varint"])
@pytest.mark.parametrize("lost_copies", [1, 3])
def test_lost_batch_copy_recovers_without_manufacturing_duplicate_acks(record_encoding, lost_copies):
    sim = simulation(record_encoding=record_encoding, copies=lost_copies + 1)
    first = sim.flows[0]
    send = first.send
    dropped = 0

    def drop_one(reverse, size, kind, receive):
        nonlocal dropped
        if kind == "ack_batch" and dropped < lost_copies:
            dropped += 1
            receive = lambda: None
        return send(reverse, size, kind, receive)

    first.send = drop_one
    sim.run()
    assert dropped == lost_copies
    assert all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    assert sum(flow.tcp_fast_retransmits + flow.tcp_timeouts for flow in sim.flows) == 0
    assert sim.ack_aggregate.requested_wire_bytes == first.wire[True]["ack_batch"]


def test_short_drain_exposes_unflushed_queue():
    sim = simulation(duration=.001, drain=0, hold_ms=2)
    sim.flows[0].transmit_ack(PendingACK(1, 0, None))
    drain_events(sim)
    assert not sim.ack_aggregate.flushed
    assert sim.ack_aggregate.batches == 0


def test_datagram_reserved_past_cutoff_remains_unflushed():
    sim = simulation(duration=.001, drain=0, hold_ms=0, copies=1)
    for flow in sim.flows:
        flow.now = .00099
    sim.flows[0].transmit_ack(PendingACK(1, .00099, None))
    drain_events(sim)
    assert sim.ack_aggregate.requested_wire_bytes == 107
    assert sim.flows[0].wire[True]["ack_batch"] == 0
    assert sim.ack_aggregate.queue == []
    assert sim.ack_aggregate.pending_copy_events == 0
    assert not sim.ack_aggregate.flushed


@pytest.mark.parametrize("hold", [-1, True, float("nan"), float("inf")])
def test_invalid_hold_is_rejected(hold):
    with pytest.raises(ValueError):
        simulation(hold_ms=hold)


def modified_ack(frame, fields):
    header = bytearray(frame)
    for start, value in fields.items():
        header[start:start + len(value)] = value
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, b"")


def delta_parts(body):
    version, kind, count = BATCH_HEADER.unpack_from(body)
    assert version == 1 and kind in (BATCH_DELTA_KIND, BYTE_DELTA_KIND)
    parts, offset = [], BATCH_HEADER.size
    for _ in range(count):
        channel, record_id, size = DELTA_RECORD_HEADER.unpack_from(body, offset)
        offset += DELTA_RECORD_HEADER.size
        parts.append((channel, record_id, body[offset:offset + size]))
        offset += size
    assert offset == len(body)
    return parts


def pack_delta_parts(parts, kind=BATCH_DELTA_KIND):
    return BATCH_HEADER.pack(1, kind, len(parts)) + b"".join(
        DELTA_RECORD_HEADER.pack(channel, record_id, len(encoded)) + encoded
        for channel, record_id, encoded in parts)


def codec_batch(records):
    codec = CompactHeaderCodec(delta=True)
    return pack_delta_parts([(channel, record_id, codec.encode(frame)) for channel, record_id, frame in records])


def test_default_envelope_is_byte_identical_and_single_delta_record_falls_back():
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    records = [(1, 2**64 - 1, frame), (255, 0, frame)]
    expected = BATCH_HEADER.pack(1, 1, 2) + b"".join(
        RECORD_HEADER.pack(channel, record_id) + value for channel, record_id, value in records)
    assert encode_batch(records) == encode_batch(records, "full") == expected
    assert encode_batch(records[:1], "batch_delta") == encode_batch(records[:1])
    assert simulation().ack_aggregate.record_encoding == "full"


def test_batch_delta_preserves_mixed_channels_static_headers_and_all_context_charges():
    records = []
    for group in range(3):
        for offset in range(4):
            frame = tcp_profile_frame(payload_bytes=0, flags=0x10, acknowledged=offset * 1448,
                                       identification=offset, timestamp=100 + offset, echoed_timestamp=offset)
            frame = modified_ack(frame, {0: bytes([group]) * 6,
                26: bytes([10, 0, group, 1]), 30: bytes([10, 1, group, 2]),
                34: (443 + group).to_bytes(2, "big"), 36: (5000 + group).to_bytes(2, "big")})
            records.append((group * 100, 2**63 + offset, frame))
    body = codec_batch(records)
    parts = delta_parts(body)
    assert [index for index, (_, _, encoded) in enumerate(parts) if encoded[0] == 0] == [0, 4, 8]
    for index in (0, 4, 8):
        assert parts[index][2][:69] == b"\x00\x00\x42" + records[index][2]
    assert len(body) == BATCH_HEADER.size + sum(DELTA_RECORD_HEADER.size + len(part[2]) for part in parts)
    assert len(body) < len(encode_batch(records))
    assert decode_batch(body) == records
    selected = encode_batch(records, "batch_delta")
    assert BATCH_HEADER.unpack_from(selected)[1] == BYTE_DELTA_KIND
    assert len(selected) < len(body)
    assert decode_batch(selected) == records


def test_static_context_change_for_every_record_uses_charged_byte_patches():
    records = [(index, index, modified_ack(tcp_profile_frame(payload_bytes=0, flags=0x10),
                                          {26: bytes([10, 0, 0, index + 1])})) for index in range(4)]
    body = encode_batch(records, "batch_delta")
    assert BATCH_HEADER.unpack_from(body)[1] == BYTE_DELTA_KIND
    assert len(body) < len(encode_batch(records))
    assert decode_batch(body) == records


def test_existing_codec_escape_retains_complete_ack_bytes_inside_delta_batch():
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    escaped = modified_ack(frame, {20: b"\x20\x00"})
    records = [(0, 0, escaped)] + [(1, index, frame) for index in range(4)]
    body = codec_batch(records)
    parts = delta_parts(body)
    assert parts[0][2] == b"\x02\x00\x42" + escaped
    assert parts[1][2][:69] == b"\x00\x00\x42" + frame
    assert decode_batch(body) == records


def test_delta_ack_fields_and_event_ids_wrap_without_losing_bytes():
    frames = [tcp_profile_frame(payload_bytes=0, flags=0x10, sequence=0xFFFFFFFE,
                               acknowledged=0xFFFFFFFF, identification=65535,
                               timestamp=0xFFFFFFFF, echoed_timestamp=0xFFFFFFFE, window=65535),
              tcp_profile_frame(payload_bytes=0, flags=0x10, sequence=1, acknowledged=0,
                               identification=0, timestamp=0, echoed_timestamp=1, window=0),
              tcp_profile_frame(payload_bytes=0, flags=0x10, sequence=0, acknowledged=0xFFFFFFFF,
                               identification=65535, timestamp=0xFFFFFFFF, echoed_timestamp=0, window=65535)]
    frames[1] = modified_ack(frames[1], {52: b"\xff\xff"})
    records = [(0, 2**64 - 1, frames[0]), (255, 0, frames[1]), (0, 0, frames[2])]
    body = encode_batch(records, "batch_delta")
    assert BATCH_HEADER.unpack_from(body)[1] in (BATCH_DELTA_KIND, BYTE_DELTA_KIND)
    assert decode_batch(body) == records


@pytest.mark.parametrize("distinct_ports", [False, True])
def test_every_delta_batch_decodes_independently_after_loss_and_reordering(distinct_ports):
    batches = []
    for batch in range(3):
        records = [(channel, batch * 10 + channel,
                    modified_ack(tcp_profile_frame(payload_bytes=0, flags=0x10,
                        acknowledged=batch * 1000 + channel, timestamp=batch * 100),
                        {26: bytes([10, batch, 0, 1]),
                         36: (49152 + channel if distinct_ports else 5000).to_bytes(2, "big")}))
                   for channel in range(4)]
        batches.append((records, encode_batch(records, "batch_delta")))
    expected_kind = BYTE_DELTA_KIND if distinct_ports else BATCH_DELTA_KIND
    assert all(BATCH_HEADER.unpack_from(body)[1] == expected_kind for _, body in batches)
    # The first datagram is absent, and the third arrives before the second.
    for index in (2, 1, 2):
        records, body = batches[index]
        first = delta_parts(body)[0][2]
        if BATCH_HEADER.unpack_from(body)[1] == BATCH_DELTA_KIND:
            assert first[:69] == b"\x00\x00\x42" + records[0][2]
        else:
            assert first == records[0][2]
        assert decode_batch(body) == records


@pytest.mark.parametrize("damage", ["zero_length", "large_length", "context_size", "context_checksum",
    "context_only", "missing_context", "extra_record", "truncated_delta", "escaped_checksum", "trailing"])
def test_delta_batch_parser_rejects_malformed_lengths_contexts_and_frames(damage):
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    body = codec_batch([(0, 0, frame), (1, 0, frame), (0, 1, frame)])
    parts = delta_parts(body)
    channel, record_id, original = parts[0]
    encoded = bytearray(original)
    if damage == "zero_length":
        encoded.clear()
    elif damage == "large_length":
        body = bytearray(body)
        body[BATCH_HEADER.size + RECORD_HEADER.size:BATCH_HEADER.size + DELTA_RECORD_HEADER.size] = b"\xff\xff"
    elif damage == "context_size":
        encoded[1:3] = b"\x00\x43"
    elif damage == "context_checksum":
        encoded[3 + 24] ^= 1
    elif damage == "context_only":
        del encoded[69:]
    elif damage == "missing_context":
        del encoded[:69]
    elif damage == "extra_record":
        encoded.extend(b"\x03\x00\x00\x00")
    elif damage == "truncated_delta":
        encoded = bytearray(original[:69] + b"\x03\x00\x00\x01\x80")
    elif damage == "escaped_checksum":
        encoded = bytearray(b"\x02\x00\x42" + frame)
        encoded[-1] ^= 1
    else:
        body += b"\x00"
    if damage not in ("large_length", "trailing"):
        parts[0] = channel, record_id, bytes(encoded)
        body = pack_delta_parts(parts)
    with pytest.raises(ValueError):
        decode_batch(body)


@pytest.mark.parametrize("kind", [BATCH_DELTA_KIND, BYTE_DELTA_KIND])
def test_delta_parser_rejects_every_physical_truncation(kind):
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    body = encode_batch([(0, 0, frame), (1, 0, frame)], "batch_delta")
    if kind == BATCH_DELTA_KIND:
        body = codec_batch([(0, 0, frame), (1, 0, frame)])
    assert BATCH_HEADER.unpack_from(body)[1] == kind
    for length in range(len(body)):
        with pytest.raises(ValueError):
            decode_batch(body[:length])


def test_delta_batches_preserve_duplicate_events_and_charge_all_copies():
    sim = simulation(record_encoding="batch_delta")
    aggregate = sim.ack_aggregate
    assert aggregate.capacity == 19
    received = []
    for channel, flow in enumerate(sim.flows):
        flow.on_ack = lambda ack, echo, channel=channel: received.append((channel, ack, echo))
    packet = PendingACK(2**32 + 1, .00012345, .00006789)
    for _ in range(20):
        for flow in sim.flows:
            flow.transmit_ack(packet)
    drain_events(sim)
    assert aggregate.batch_sizes == {19: 2, 2: 1}
    assert aggregate.encoding_datagrams == {"batch_delta": 6, "byte_delta": 3}
    assert aggregate.full_equivalent_wire_bytes == 3 * (3 * 32 + 40 * 75)
    assert aggregate.saved_wire_bytes > 0
    assert aggregate.requested_wire_bytes + aggregate.saved_wire_bytes == aggregate.full_equivalent_wire_bytes
    assert aggregate.requested_wire_bytes == sim.flows[0].wire[True]["ack_batch"]
    assert sim.flows[0].datagrams[True]["ack_batch"] == 9
    assert len(received) == 40
    assert received.count((0, packet.acknowledged, packet.echoed_timestamp)) == 20
    assert received.count((1, packet.acknowledged, packet.echoed_timestamp)) == 20
    assert sum(flow.ack_copy_duplicates for flow in sim.flows) == 80
    assert aggregate.verified_records == 120
    assert not aggregate.records and aggregate.flushed


def test_full_fallback_counters_include_every_requested_copy():
    sim = simulation(record_encoding="batch_delta", hold_ms=0)
    sim.flows[0].on_ack = lambda *args: None
    sim.flows[0].transmit_ack(PendingACK(1, 0, None))
    drain_events(sim)
    aggregate = sim.ack_aggregate
    assert aggregate.encoding_datagrams == {"full": 3}
    assert aggregate.requested_wire_bytes == aggregate.full_equivalent_wire_bytes == 321
    assert aggregate.saved_wire_bytes == 0


@pytest.mark.parametrize("value", [None, True, 1, "delta", "unknown"])
def test_unknown_batch_record_encoding_is_rejected(value):
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    with pytest.raises(ValueError, match="encoding"):
        encode_batch([(0, 0, frame)], value)
    with pytest.raises(ValueError, match="encoding"):
        simulation(record_encoding=value)


def test_byte_patch_mask_and_values_cover_exact_changed_positions():
    first = tcp_profile_frame(payload_bytes=0, flags=0x10)
    second = modified_ack(first, {0: b"\xaa", 36: b"\xc0\x00", 65: b"\xfe"})
    records = [(0, 2**64 - 1, first), (255, 0, second)]
    body = encode_batch(records, "batch_delta")
    assert BATCH_HEADER.unpack_from(body)[1] == BYTE_DELTA_KIND
    parts = delta_parts(body)
    assert parts[0][2] == first
    positions = [index for index in range(66) if first[index] != second[index]]
    mask = sum(1 << index for index in positions)
    assert mask & 1 and mask & (1 << 65)
    assert parts[1][2] == mask.to_bytes(9, "big") + bytes(second[index] for index in positions)
    assert decode_batch(body) == records


@pytest.mark.parametrize("damage", ["unused_bits", "missing_value", "extra_value", "short_mask",
                                     "first_short", "first_long", "first_checksum", "patch_checksum", "missing_first"])
def test_byte_delta_rejects_invalid_mask_lengths_first_context_and_checksums(damage):
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    parts = [(0, 0, frame), (1, 0, bytes(9))]
    if damage == "unused_bits":
        parts[1] = 1, 0, (1 << 66).to_bytes(9, "big") + b"\x00"
    elif damage == "missing_value":
        parts[1] = 1, 0, (1 << 65).to_bytes(9, "big")
    elif damage == "extra_value":
        parts[1] = 1, 0, bytes(10)
    elif damage == "short_mask":
        parts[1] = 1, 0, bytes(8)
    elif damage == "first_short":
        parts[0] = 0, 0, frame[:-1]
    elif damage == "first_long":
        parts[0] = 0, 0, frame + b"\x00"
    elif damage == "first_checksum":
        broken = bytearray(frame)
        broken[50] ^= 1
        parts[0] = 0, 0, bytes(broken)
    elif damage == "patch_checksum":
        parts[1] = 1, 0, (1 << 50).to_bytes(9, "big") + bytes([frame[50] ^ 1])
    else:
        parts = parts[1:]
    with pytest.raises(ValueError):
        decode_batch(pack_delta_parts(parts, BYTE_DELTA_KIND))


@pytest.mark.parametrize("distinct", [False, True])
def test_generated_ack_ports_are_explicit_and_checksum_valid(distinct):
    sim = simulation(flows=4, record_encoding="batch_delta", distinct_flow_headers=distinct)
    frames = []
    original_submit = sim.ack_aggregate.submit

    def capture(channel, record_id, frame, packet):
        frames.append((channel, frame))
        return original_submit(channel, record_id, frame, packet)

    sim.ack_aggregate.submit = capture
    for flow in sim.flows:
        flow.on_ack = lambda *args: None
        flow.transmit_ack(PendingACK(2**32 + 1, .00012345, .00006789))
    drain_events(sim)
    for channel, frame in frames:
        validate_ack_frame(frame)
        assert int.from_bytes(frame[34:36], "big") == 443
        assert int.from_bytes(frame[36:38], "big") == (49152 + channel if distinct else 5000)
    if distinct:
        assert sim.ack_aggregate.encoding_datagrams == {"byte_delta": 3}
    assert sim.ack_aggregate.requested_wire_bytes == sim.flows[0].wire[True]["ack_batch"]
    assert sim.ack_aggregate.saved_wire_bytes > 0
    assert sim.ack_aggregate.released_records == 4


def test_distinct_header_last_channel_has_a_valid_16_bit_destination_port():
    sim = simulation(flows=256, copies=1, distinct_flow_headers=True)
    flow = sim.flows[-1]
    flow.on_ack = lambda *args: None
    flow.transmit_ack(PendingACK(1, 0, None))
    frame = sim.ack_aggregate.records[255, 0][0]
    assert frame[36:38] == (49152 + 255).to_bytes(2, "big")
    validate_ack_frame(frame)
    drain_events(sim)
    assert sim.ack_aggregate.released_records == 1


@pytest.mark.parametrize("value", [None, 0, 1, "true"])
def test_distinct_flow_header_flag_requires_boolean(value):
    with pytest.raises(ValueError, match="boolean"):
        simulation(distinct_flow_headers=value)


def varint_record(channel, difference, encoded):
    zigzag = difference * 2 if difference >= 0 else -difference * 2 - 1
    return (bytes([channel]) + _unsigned_varint(zigzag)
            + _unsigned_varint(len(encoded)) + encoded)


def test_varint_envelope_has_exact_canonical_metadata_and_frame_bytes():
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    records = [(0, 2, frame), (255, 0, frame)]
    expected = (BATCH_HEADER.pack(1, BYTE_VARINT_KIND, 2)
                + b"\x00\x04\x42" + frame + b"\xff\x03\x09" + bytes(9))
    assert encode_batch(records, "batch_varint") == expected
    assert decode_batch(expected) == records
    assert len(expected) == 85
    assert len(expected) < len(encode_batch(records, "batch_delta"))


@pytest.mark.parametrize("first,second", [
    (0, 0), (0, 1), (1, 0), (0, 63), (0, 64), (63, 64), (64, 63),
    (127, 128), (128, 127), (0, 2**63), (2**63, 0),
    (0, 2**64 - 1), (2**64 - 1, 0), (2**64 - 1, 2**64 - 1),
])
def test_varint_full_uint64_event_ids_and_negative_channel_differences(first, second):
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    body = (BATCH_HEADER.pack(1, BYTE_VARINT_KIND, 2)
            + varint_record(0, first, frame) + varint_record(255, second - first, bytes(9)))
    records = [(0, first, frame), (255, second, frame)]
    assert decode_batch(body) == records
    selected = encode_batch(records, "batch_varint")
    assert decode_batch(selected) == records
    assert len(selected) <= len(encode_batch(records, "batch_delta"))


def test_varint_large_event_selects_unchanged_full_envelope_when_smaller():
    records = [(255, 2**64 - 1, tcp_profile_frame(payload_bytes=0, flags=0x10))]
    assert encode_batch(records, "batch_varint") == encode_batch(records, "full")


def test_varint_preserves_unsigned_integer_inputs_supported_by_struct():
    from numpy import uint64

    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    records = [(0, uint64(2**64 - 1), frame), (255, uint64(0), frame)]
    encoded = encode_batch(records, "batch_varint")
    assert decode_batch(encoded) == records
    assert len(encoded) <= len(encode_batch(records, "batch_delta"))


@pytest.mark.parametrize("event,length", [
    (b"\x80", b""), (b"\x80" * 10, b""),
    (_unsigned_varint(2**65), b"\x42"), (_unsigned_varint(2**65 - 1), b"\x42"),
    (b"\x80\x00", b"\x42"), (b"\x82\x00", b"\x42"),
    (b"\x01", b"\x42"), (b"\x00", b"\x00"),
    (b"\x00", b"\x4c"), (b"\x00", b"\xc2\x00"), (b"\x00", b"\x80" * 10),
])
def test_varint_rejects_overflow_negative_ids_and_noncanonical_metadata(event, length):
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    body = BATCH_HEADER.pack(1, BYTE_VARINT_KIND, 1) + b"\x00" + event + length + frame
    with pytest.raises(ValueError):
        decode_batch(body)


def test_varint_reconstructed_event_id_cannot_overflow_uint64():
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    body = (BATCH_HEADER.pack(1, BYTE_VARINT_KIND, 2)
            + varint_record(0, 2**64 - 1, frame) + varint_record(1, 1, bytes(9)))
    with pytest.raises(ValueError, match="event ID"):
        decode_batch(body)


@pytest.mark.parametrize("damage", ["first_short", "first_long", "first_checksum", "patch_checksum",
                                    "short_mask", "unused_mask_bits", "trailing"])
def test_varint_rejects_invalid_frame_lengths_masks_and_checksums(damage):
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    first, second = frame, bytes(9)
    if damage == "first_short":
        first = frame[:-1]
    elif damage == "first_long":
        first = frame + b"\x00"
    elif damage == "first_checksum":
        first = frame[:50] + bytes([frame[50] ^ 1]) + frame[51:]
    elif damage == "patch_checksum":
        second = (1 << 50).to_bytes(9, "big") + bytes([frame[50] ^ 1])
    elif damage == "short_mask":
        second = bytes(8)
    elif damage == "unused_mask_bits":
        second = (1 << 66).to_bytes(9, "big") + b"\x00"
    body = (BATCH_HEADER.pack(1, BYTE_VARINT_KIND, 2)
            + varint_record(0, 0, first) + varint_record(1, 0, second))
    if damage == "trailing":
        body += b"\x00"
    with pytest.raises(ValueError):
        decode_batch(body)


def test_varint_rejects_every_physical_truncation():
    frame = tcp_profile_frame(payload_bytes=0, flags=0x10)
    body = (BATCH_HEADER.pack(1, BYTE_VARINT_KIND, 2)
            + varint_record(0, 2**64 - 1, frame) + varint_record(255, -(2**64 - 1), bytes(9)))
    for length in range(len(body)):
        with pytest.raises(ValueError):
            decode_batch(body[:length])


def test_varint_batches_decode_independently_after_loss_and_reordering():
    batches = []
    for index in range(3):
        records = [(channel, 1000 * index + channel,
                    modified_ack(tcp_profile_frame(payload_bytes=0, flags=0x10,
                        acknowledged=10000 * index + channel, timestamp=1000 * index),
                        {36: (49152 + channel).to_bytes(2, "big")})) for channel in range(4)]
        body = encode_batch(records, "batch_varint")
        assert BATCH_HEADER.unpack_from(body)[1] == BYTE_VARINT_KIND
        batches.append((records, body))
    for index in (2, 1, 2):
        records, body = batches[index]
        assert decode_batch(body) == records


def test_varint_duplicate_ack_events_and_all_copy_wire_costs(monkeypatch):
    bodies = []

    def capture(records, record_encoding):
        body = encode_batch(records, record_encoding)
        bodies.append(body)
        return body

    monkeypatch.setattr("l2tunnel_sim.aggregate_ack.encode_batch", capture)
    sim = simulation(record_encoding="batch_varint", distinct_flow_headers=True, copies=4)
    received = []
    for channel, flow in enumerate(sim.flows):
        flow.on_ack = lambda ack, echo, channel=channel: received.append((channel, ack, echo))
    packet = PendingACK(2**32 + 1, .00012345, .00006789)
    for _ in range(20):
        for flow in sim.flows:
            flow.transmit_ack(packet)
    drain_events(sim)
    aggregate = sim.ack_aggregate
    assert aggregate.capacity == 19 and aggregate.batch_sizes == {19: 2, 2: 1}
    assert aggregate.encoding_datagrams == {"byte_varint": 12}
    assert aggregate.requested_wire_bytes == 4 * sum(28 + len(body) for body in bodies)
    assert aggregate.requested_wire_bytes == sim.flows[0].wire[True]["ack_batch"]
    assert aggregate.requested_wire_bytes + aggregate.saved_wire_bytes == aggregate.full_equivalent_wire_bytes
    assert len(received) == 40
    assert received.count((0, packet.acknowledged, packet.echoed_timestamp)) == 20
    assert received.count((1, packet.acknowledged, packet.echoed_timestamp)) == 20
    assert sum(flow.ack_copy_duplicates for flow in sim.flows) == 120
    assert aggregate.flushed and not aggregate.records


def test_varint_malformed_final_record_releases_no_earlier_callback():
    sim = simulation(record_encoding="batch_varint", copies=1)
    for flow in sim.flows:
        flow.transmit_ack(PendingACK(1, 0, None))
    first = sim.ack_aggregate.records[0, 0][0]
    body = (BATCH_HEADER.pack(1, BYTE_VARINT_KIND, 2)
            + varint_record(0, 0, first) + varint_record(1, 0, bytes(8)))
    with pytest.raises(ValueError):
        sim.ack_aggregate.receive(body)
    assert sim.ack_aggregate.released_records == 0
    assert len(sim.ack_aggregate.records) == 2
    assert all(flow.tcp_acked == 0 for flow in sim.flows)
