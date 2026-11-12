from dataclasses import replace

import pytest

from l2tunnel_sim.compact import CompactConfig, CompactHeaderCodec, CompactSimulation, tcp_profile_frame
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic


def tcp_frame(sequence, *, source_address=b"\x0a\x00\x00\x01", payload=b"p" * 1448):
    header = bytearray(66)
    header[:12] = bytes(range(12))
    header[12:15] = b"\x08\x00\x45"
    header[18:20] = (sequence % 65536).to_bytes(2, "big")
    header[20:22] = b"\x40\x00"
    header[22:24] = b"\x40\x06"
    header[26:30] = source_address
    header[30:34] = b"\x0a\x00\x00\x02"
    header[34:38] = b"\x01\xbb\x13\x88"
    header[38:42] = sequence.to_bytes(4, "big")
    header[42:46] = (200).to_bytes(4, "big")
    header[46:50] = b"\x80\x18\xff\xff"
    header[54:58] = b"\x01\x01\x08\x0a"
    header[58:62] = (1000 + sequence).to_bytes(4, "big")
    header[62:66] = (500).to_bytes(4, "big")
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, payload)


def test_header_profile_round_trips_complete_frames_and_charges_context():
    frames = [tcp_frame(1000), tcp_frame(2448), tcp_frame(3896, payload=b"")]
    encoder, decoder = CompactHeaderCodec(), CompactHeaderCodec()
    encoded = [encoder.encode(frame) for frame in frames]
    assert list(map(len, encoded)) == [69 + 1448 + 26, 1448 + 26, 26]
    assert decoder.decode(b"".join(encoded)) == frames


def test_changed_invariant_sends_new_context_and_invalid_checksum_falls_back():
    encoder, decoder = CompactHeaderCodec(), CompactHeaderCodec()
    first = tcp_frame(1000)
    changed = tcp_frame(2448, source_address=b"\x0a\x00\x00\x03")
    corrupt = first[:-1] + b"x"
    encoded = [encoder.encode(frame) for frame in (first, changed, corrupt)]
    assert len(encoded[1]) == 69 + 1448 + 26
    assert encoded[2][0] == 2
    assert decoder.decode(b"".join(encoded)) == [first, changed, corrupt]


def test_missing_context_and_truncated_record_are_rejected():
    with pytest.raises(ValueError, match="missing context"):
        CompactHeaderCodec().decode(b"\x01\x00\x00" + bytes(23))
    with pytest.raises(ValueError, match="truncated"):
        CompactHeaderCodec().decode(b"\x02\x00\x04x")


def simulation(config=CompactConfig(), *, loss=0, duration=0.001, window=1448, drain=1):
    traffic = Traffic(duration_s=duration, drain_s=drain, window_bytes=window,
                      ack_every=1, frame_interval_ms=0.15)
    return CompactSimulation(Scenario(20, loss), traffic, (PathConfig(),), Strategy("Compact"),
                             42, config)


def test_compact_lossless_packetization_preserves_one_complete_l2_frame():
    sim = simulation(CompactConfig(repair_ratio=0)).run()
    assert sim.tcp_received == sim.tcp_acked == 1
    assert sim.forward.delivered_bytes == 1514
    assert sim.forward.source_record_bytes == 1474
    assert sim.forward.profile_context_bytes == 69
    assert sim.wire[False]["source"] == 1474 + 69 + 2 * (36 + 2)
    assert sim.datagrams[False]["source"] == 2
    assert sim.forward.records == sim.reverse.records == sim.forward.records.__class__()


def test_lost_first_symbol_and_feedback_recover_without_duplicate_records():
    sim = simulation(CompactConfig(repair_ratio=0.2), duration=0.01,
                     window=1448 * 20)
    losses = iter([True, False, False, False] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(losses)
    reverse_losses = iter([True] + [False] * 10000)
    sim.links[True][0].erasures.lost = lambda: next(reverse_losses)
    sim.run()
    assert sim.tcp_received == len(sim.sent_times) == sim.tcp_acked
    assert sim.forward.recovered_symbols >= 1
    assert sim.forward.base == len(sim.forward.sources)
    assert sim.forward.delivered_bytes == len(sim.sent_times) * 1514


def test_only_actual_gf256_rank_decoding_is_supported():
    with pytest.raises(ValueError, match="actual GF256"):
        CompactConfig(coding="ideal")


def test_authentication_bytes_reduce_capacity_and_all_loss_stays_undelivered():
    config = replace(CompactConfig(), authentication_bytes=16)
    sim = simulation(config, loss=1).run()
    assert sim.forward.record_capacity == 1442
    assert sim.tcp_received == 0
    assert sim.forward.tail_repairs > 0


def test_full_l2_profile_keeps_uncompressed_header_cost():
    sim = simulation(CompactConfig(header_profile="full_l2", repair_ratio=0)).run()
    assert sim.tcp_received == 1
    assert sim.forward.source_record_bytes == 1517
    assert sim.forward.profile_context_bytes == 0


def test_delta_profile_counts_actual_fields_and_round_trips_retries_and_wraps():
    frames = [tcp_profile_frame(sequence=1000, identification=65535, timestamp=1000),
              tcp_profile_frame(sequence=2448, identification=0, timestamp=1001),
              tcp_profile_frame(sequence=1000, identification=1, timestamp=1002),
              tcp_profile_frame(sequence=3896, identification=2, timestamp=1003,
                                acknowledged=12345, window=20000)]
    encoder, decoder = CompactHeaderCodec(delta=True), CompactHeaderCodec(delta=True)
    records = [encoder.encode(frame) for frame in frames]
    assert len(records[0]) == 69 + 4 + 1448
    assert len(records[1]) == 8 + 1448
    assert len(records[2]) == 11 + 1448
    assert decoder.decode(b"".join(records)) == frames


def test_delta_packet_model_computes_wire_cost_from_serialized_frames():
    sim = simulation(CompactConfig(header_profile="tcp_delta", repair_ratio=0)).run()
    assert sim.forward.source_record_bytes == 1452
    assert sim.forward.profile_context_bytes == 69
    assert sim.tcp_acked == 1


def test_tail_repair_timer_starts_after_final_source_departure():
    traffic = Traffic(duration_s=0.001, drain_s=0.052, window_bytes=1448 * 100,
                      frame_interval_ms=0)
    sim = CompactSimulation(Scenario(20, 1), traffic, (PathConfig(),), Strategy("Compact"),
                             42, CompactConfig(repair_ratio=0)).run()
    assert len(sim.sent_times) == 100
    assert sim.forward.last_source_at > 0.01
    assert sim.forward.tail_repairs == 0
