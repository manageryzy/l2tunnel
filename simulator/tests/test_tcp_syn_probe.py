import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from l2tunnel_sim.compact import CompactHeaderCodec, _checksum
from l2tunnel_sim.tcp_syn_probe import (EVENT_HEADER, Probe, SYNProbeConfig, TCPHandshakeProbe,
                                      connection_tuple, handshake_frame, parse_handshake_frame)


@pytest.fixture
def study(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    return importlib.import_module("aggregate_ack_deadlines")


def case(*, loss=0, duration=.3, drain=6, copies=1):
    profile = dict(name="SYN probe regression", flow_count=4, window_bytes=32768,
        payload_rate_mbps=10, rto_min_ms=1000, ack_coalesce_ms=.25, ack_copies=3,
        ack_aggregation=True, ack_batch_hold_ms=.5, ack_record_encoding="batch_delta",
        wire_format="compact_wire", ack_delay_ms=1,
        compact=dict(header_profile="tcp_delta", repair_ratio=.221, feedback_ms=1,
            feedback_packets=64, flush_ms=2, independent_delivery=True,
            repair_window_sources=128, global_repair_every=16, elide_payload_length=True,
            packed_predictive_records=True, encapsulation="raw_ipv4_crc32", trim_repair_padding=True),
        tcp_syn_probe=dict(interval_ms=100, timeout_ms=100, reverse_copies=copies,
                           stability_window_s=.02, throughput_tolerance_pct=100, queue_tolerance_ms=10))
    return dict(profile=profile, payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
                rtt_ms=20, loss_rate=loss, loss_model="iid", mtu=1500, duration_s=duration,
                warmup_s=.01, drain_s=drain, seed=42)


@pytest.mark.parametrize("reverse,flags", [(False, 2), (True, 18), (False, 16), (False, 20)])
def test_complete_handshake_frames_round_trip_existing_codec(reverse, flags):
    probe = Probe(12, 255, 0)
    frame = handshake_frame(probe, reverse=reverse, flags=flags, timestamp=100, identification=7)
    assert len(frame) == 66
    assert frame[47] == flags
    assert _checksum(frame[14:34]) == b"\0\0"
    assert _checksum(frame[26:34] + b"\0\x06\0\x20" + frame[34:]) == b"\0\0"
    encoder, decoder = CompactHeaderCodec(delta=True), CompactHeaderCodec(delta=True)
    assert decoder.decode(encoder.encode(frame)) == [frame]


@pytest.mark.parametrize("copies", [1, 3, 4])
@pytest.mark.parametrize("encoding", ["full", "batch_delta", "batch_varint"])
def test_normal_entry_retains_bulk_accounting_and_separate_probe_samples(study, copies, encoding):
    task = case(copies=copies)
    task["profile"]["ack_record_encoding"] = encoding
    row = study.execute(task)
    assert row["fully_confirmed"] and row["tcp_syn_probe_all_flushed"]
    count = row["tcp_syn_ping_offered"]
    assert count == row["tcp_syn_ping_completed"] and count > 0
    assert row["tcp_syn_probe_steady_state_reached"]
    assert row["tcp_syn_probe_start_s"] >= .06
    assert len(row["tcp_syn_probe_stability_history"]) >= 3
    assert all(record["started_at"] >= row["tcp_syn_probe_start_s"] for record in row["tcp_syn_probe_records"])
    assert row["tcp_syn_ping_timeouts"] == row["tcp_syn_ping_censored"] == 0
    assert 20 <= row["tcp_syn_ping_p99_ms"] < 25
    assert row["tcp_syn_ping_failure_pct"] == 0
    assert row["tcp_syn_probe_forward_frames"] == 3 * count
    assert row["tcp_syn_probe_reverse_datagrams"] == count * copies
    assert row["tcp_syn_probe_reverse_departed_bytes"] == count * copies * 102
    assert row["tcp_syn_probe_reverse_requested_bytes"] == row["tcp_syn_probe_reverse_departed_bytes"]
    assert row["forward_l2_bytes"] == row["tcp_delivered_frames"] * (1448 + 66)
    records = row["tcp_syn_probe_records"]
    assert [record["channel"] for record in records] == list(range(4, 4 + count))
    assert all(record["server_closed"] for record in records)


def test_first_syn_origin_includes_lost_synack_and_retry_wait(study):
    task = case(duration=1.2)
    sim = study.make_simulation(task)
    probe = TCPHandshakeProbe(sim, SYNProbeConfig(interval_ms=2000, timeout_ms=1100),
                              start_s=task["warmup_s"], wait_for_stability=False)
    flow = sim.flows[0]
    original_send = flow.send
    dropped = []

    def drop_first_synack(reverse, size, kind, receive):
        if kind == "syn_probe" and not dropped:
            dropped.append(True)
            receive = lambda: None
        return original_send(reverse, size, kind, receive)

    flow.send = drop_first_synack
    sim.run()
    row = probe.measurements()
    assert row["tcp_syn_ping_completed"] == 1
    assert 1020 <= row["tcp_syn_ping_p99_ms"] < 1100
    assert row["tcp_syn_ping_syn_retransmissions"] == 1
    assert row["tcp_syn_ping_deadline_miss_upper_pct"] == 100


@pytest.mark.parametrize("drain,expected_timeouts,expected_censored", [(6, 1, 0), (.1, 0, 1)])
def test_timeouts_and_unresolved_probes_remain_in_denominator(study, drain, expected_timeouts, expected_censored):
    task = case(duration=1.2, drain=drain)
    sim = study.make_simulation(task)
    if expected_censored:
        for flow in sim.flows:
            flow.stop_at = .18
    probe = TCPHandshakeProbe(sim, SYNProbeConfig(interval_ms=2000, timeout_ms=1100),
                              start_s=task["warmup_s"], wait_for_stability=False)
    sim.links[True][0].erasures.lost = lambda: True
    sim.run()
    row = probe.measurements()
    assert row["tcp_syn_ping_offered"] == 1
    assert row["tcp_syn_ping_completed"] == 0
    assert row["tcp_syn_ping_timeouts"] == expected_timeouts
    assert row["tcp_syn_ping_censored"] == expected_censored
    assert row["tcp_syn_ping_failure_pct"] == 100
    assert row["tcp_syn_ping_p99_ms"] is None
    assert row["tcp_syn_ping_cohort_lower_bound_p99_ms"] >= 100


def test_existing_queue_backlog_is_visible_to_probe(study):
    task = case(duration=1.2)
    sim = study.make_simulation(task)
    probe = TCPHandshakeProbe(sim, SYNProbeConfig(interval_ms=2000, timeout_ms=1000),
                              start_s=task["warmup_s"], wait_for_stability=False)
    sim.links[False][0].free_at = .2
    sim.run()
    assert probe.measurements()["tcp_syn_ping_p99_ms"] >= 210


@pytest.mark.parametrize("field,value", [("interval_ms", 0), ("timeout_ms", float("nan")),
    ("initial_rto_ms", True), ("reverse_copies", 0), ("reverse_copies", 5),
    ("reverse_copies", 1.5), ("copy_spacing_ms", -1)])
def test_invalid_configuration_rejected(field, value):
    with pytest.raises(ValueError):
        SYNProbeConfig(**{field: value})


def test_full_channel_allocation_is_explicitly_rejected(study):
    task = case()
    task["profile"].update(flow_count=256, window_bytes=4 * 1048576)
    sim = study.make_simulation(task)
    with pytest.raises(ValueError, match="unused L2 channel"):
        TCPHandshakeProbe(sim)


def test_unstable_zero_delivery_never_starts_probes(study):
    task = case(duration=.3, drain=0)
    sim = study.make_simulation(task)
    probe = TCPHandshakeProbe(sim, SYNProbeConfig(stability_window_s=.02), start_s=.01)
    sim.links[False][0].erasures.lost = lambda: True
    sim.run()
    row = probe.measurements()
    assert not row["tcp_syn_probe_steady_state_reached"]
    assert row["tcp_syn_probe_start_s"] is None
    assert row["tcp_syn_ping_offered"] == 0
    assert row["tcp_syn_ping_p99_ms"] is None
    assert row["tcp_syn_ping_background_goodput_mbps"] is None


@pytest.mark.parametrize("window_s,samples_per_window", [(1, 100), (.105, 11)])
def test_constant_load_reaches_stability_at_exact_window_boundaries(monkeypatch, window_s, samples_per_window):
    flow = SimpleNamespace(now=0, tcp_received=0,
        traffic=SimpleNamespace(payload_bytes=1000, duration_s=6 * window_s + 2),
        links=[[SimpleNamespace(free_at=0)], [SimpleNamespace(free_at=0)]],
        at=lambda *args: None)
    simulation = SimpleNamespace(flows=[flow], shared_forward=None)
    probe = TCPHandshakeProbe(simulation,
        SYNProbeConfig(timeout_ms=1000, stability_window_s=window_s))

    def record_admission():
        probe.steady_started_at = flow.now

    monkeypatch.setattr(probe, "begin_probes", record_admission)
    assert probe.sample_interval == window_s / samples_per_window
    if window_s == 1:
        assert probe.sample_interval == .01
    for index in range(1, 6 * samples_per_window + 1):
        flow.now = index * probe.sample_interval
        flow.tcp_received = round(flow.now * 10000)
        probe.observe_stability()

    assert probe.steady_started_at == pytest.approx(3 * window_s)
    assert len(probe.stability_history) == 6
    assert [window["end_s"] for window in probe.stability_history] == pytest.approx(
        [index * window_s for index in range(1, 7)])
    assert [window["goodput_mbps"] for window in probe.stability_history] == pytest.approx([80] * 6)
    assert [window["stable"] for window in probe.stability_history] == [False, False, True, True, True, True]


@pytest.fixture
def endpoint_pair(study, monkeypatch):
    sim = study.make_simulation(case())
    endpoint = TCPHandshakeProbe(sim, SYNProbeConfig(timeout_ms=100))
    first, second = Probe(0, 4, 0, syn_attempts=1), Probe(1, 5, 0, syn_attempts=1)
    endpoint.probes.extend((first, second))
    endpoint.probe_connections.update({connection_tuple(probe): probe for probe in (first, second)})
    sent_reverse = []
    monkeypatch.setattr(endpoint, "send_reverse_copy", lambda probe, body: sent_reverse.append(body))
    return endpoint, first, second, sent_reverse


def rewrite_frame(frame, changes):
    value = bytearray(frame)
    for start, replacement in changes:
        value[start:start + len(replacement)] = replacement
    dynamic = b"".join(value[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(value, dynamic, b"")


def test_shared_callback_dispatches_decoded_tuple_instead_of_submitted_probe(endpoint_pair, monkeypatch):
    endpoint, first, second, responses = endpoint_pair
    submitted = []

    def capture(channel, size, payload, callback, *, frame, deliver_frame=False):
        submitted.append((channel, frame, callback, deliver_frame))

    monkeypatch.setattr(endpoint.shared, "submit_channel", capture)
    endpoint.send_forward(first, 0x02)
    assert submitted[0][0] == first.channel
    assert submitted[0][3]
    received = handshake_frame(second, reverse=False, flags=0x02, timestamp=9123, identification=40)
    assert submitted[0][2](received)
    assert first.server_started_at is None
    assert second.server_started_at == endpoint.sim.now
    assert second.echoed_timestamp == 9123
    header = parse_handshake_frame(responses[0][EVENT_HEADER.size:])
    assert header.destination == connection_tuple(second)[0]
    assert header.echoed_timestamp == 9123


def test_syn_response_uses_received_sequence_and_timestamp(endpoint_pair):
    endpoint, first, _, responses = endpoint_pair
    frame = handshake_frame(first, reverse=False, flags=0x02, timestamp=9876, identification=1)
    frame = rewrite_frame(frame, [(38, (0xDEADBEEF).to_bytes(4, "big"))])
    assert endpoint.receive_forward_frame(frame)
    response = parse_handshake_frame(responses[0][EVENT_HEADER.size:])
    assert response.acknowledged == 0xDEADBEF0
    assert response.echoed_timestamp == 9876
    assert not endpoint.receive_reverse_body(responses[0])
    assert first.completed_at is None


def test_received_reverse_tuple_selects_connection_independent_of_event_identifier(endpoint_pair, monkeypatch):
    endpoint, first, second, _ = endpoint_pair
    sent = []
    monkeypatch.setattr(endpoint, "send_forward", lambda probe, flags: sent.append((probe.index, flags)))
    for probe in (second, first):
        frame = handshake_frame(probe, reverse=True, flags=0x12, timestamp=123, identification=2)
        assert endpoint.receive_reverse_body(EVENT_HEADER.pack(999) + frame)
        assert probe.completed_at == endpoint.sim.now
    assert sent == [(1, 0x10), (1, 0x14), (0, 0x10), (0, 0x14)]
    assert endpoint.reverse_copy_duplicates == 0
    # Copy identity comes from the received TCP frame, including its IP ID.
    assert endpoint.receive_reverse_body(EVENT_HEADER.pack(1000) + frame)
    assert endpoint.reverse_copy_duplicates == 1
    assert len(sent) == 4


def test_wrong_connection_ack_cannot_complete_another_tuple(endpoint_pair):
    endpoint, first, second, _ = endpoint_pair
    frame = handshake_frame(first, reverse=True, flags=0x12, timestamp=123, identification=2)
    frame = rewrite_frame(frame, [(36, (49152 + second.index).to_bytes(2, "big"))])
    assert not endpoint.receive_reverse_body(EVENT_HEADER.pack(0) + frame)
    assert first.completed_at is second.completed_at is None
    assert endpoint.dispatch_rejections["mismatched_sequence"] == 1


def test_client_acknowledges_received_server_isn(endpoint_pair, monkeypatch):
    endpoint, _, second, _ = endpoint_pair
    sent_frames = []
    monkeypatch.setattr(endpoint.shared, "submit_channel", lambda *args, **kwargs: sent_frames.append(kwargs["frame"]))
    response = handshake_frame(second, reverse=True, flags=0x12, timestamp=456, identification=2)
    response = rewrite_frame(response, [(38, (0xFEDCBA98).to_bytes(4, "big"))])
    assert endpoint.receive_reverse_body(EVENT_HEADER.pack(0) + response)
    assert second.received_server_sequence == 0xFEDCBA98
    assert second.peer_timestamp == 456
    assert [parse_handshake_frame(frame).acknowledged for frame in sent_frames] == [0xFEDCBA99, 0xFEDCBA99]
    assert [parse_handshake_frame(frame).echoed_timestamp for frame in sent_frames] == [456, 456]


def test_later_synack_cannot_replace_learned_server_sequence(endpoint_pair, monkeypatch):
    endpoint, first, _, _ = endpoint_pair
    sent = []
    monkeypatch.setattr(endpoint, "send_forward", lambda probe, flags: sent.append((probe.index, flags)))
    frame = handshake_frame(first, reverse=True, flags=0x12, timestamp=456, identification=2)
    assert endpoint.receive_reverse_body(EVENT_HEADER.pack(0) + frame)
    learned = first.received_server_sequence
    completed_at = first.completed_at
    assert sent == [(0, 0x10), (0, 0x14)]
    altered = rewrite_frame(frame, [(38, (learned + 1).to_bytes(4, "big")),
                                    (58, (999).to_bytes(4, "big"))])
    assert not endpoint.receive_reverse_body(EVENT_HEADER.pack(1) + altered)
    assert first.received_server_sequence == learned
    assert first.peer_timestamp == 456
    assert first.completed_at == completed_at
    assert sent == [(0, 0x10), (0, 0x14)]
    assert endpoint.dispatch_rejections["mismatched_sequence"] == 1


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("field", ["address", "port"])
def test_unknown_received_tuple_is_discarded(endpoint_pair, reverse, field):
    endpoint, first, second, _ = endpoint_pair
    frame = handshake_frame(first, reverse=reverse, flags=0x12 if reverse else 0x02,
                            timestamp=123, identification=2)
    offset, value = ((30 if reverse else 26), b"\x0a\x00\x00\x09") if field == "address" else (
        36 if reverse else 34, (48000).to_bytes(2, "big"))
    frame = rewrite_frame(frame, [(offset, value)])
    accepted = endpoint.receive_reverse_body(EVENT_HEADER.pack(0) + frame) if reverse else endpoint.receive_forward_frame(frame)
    assert not accepted
    assert endpoint.dispatch_rejections["unknown_tuple"] == 1
    assert first.completed_at is second.completed_at is None
    assert first.server_started_at is second.server_started_at is None


def test_final_ack_and_reset_dispatch_by_received_tuple_and_validate_sequences(endpoint_pair, monkeypatch):
    endpoint, first, second, _ = endpoint_pair
    monkeypatch.setattr(endpoint, "send_forward", lambda *args: None)
    for probe in (first, second):
        assert endpoint.receive_forward_frame(handshake_frame(probe, reverse=False, flags=0x02,
                                                             timestamp=1, identification=1))
        assert endpoint.receive_reverse_body(EVENT_HEADER.pack(0) + handshake_frame(
            probe, reverse=True, flags=0x12, timestamp=2, identification=2))
    ack = handshake_frame(second, reverse=False, flags=0x10, timestamp=3, identification=3)
    wrong_ack = rewrite_frame(ack, [(42, b"\x00\x00\x00\x01")])
    assert not endpoint.receive_forward_frame(wrong_ack)
    assert not first.server_established and not second.server_established
    assert endpoint.receive_forward_frame(ack)
    assert second.server_established and not first.server_established
    assert endpoint.receive_forward_frame(handshake_frame(second, reverse=False, flags=0x14,
                                                         timestamp=3, identification=4))
    assert second.server_closed and not first.server_closed


@pytest.mark.parametrize("reverse", [False, True])
def test_corrupted_received_frame_cannot_change_endpoint_state(endpoint_pair, reverse):
    endpoint, first, second, _ = endpoint_pair
    frame = bytearray(handshake_frame(first, reverse=reverse, flags=0x12 if reverse else 0x02,
                                     timestamp=1, identification=1))
    frame[38] ^= 1
    accepted = endpoint.receive_reverse_body(EVENT_HEADER.pack(0) + frame) if reverse else endpoint.receive_forward_frame(frame)
    assert not accepted
    assert endpoint.dispatch_rejections["malformed"] == 1
    assert first.completed_at is second.completed_at is None
