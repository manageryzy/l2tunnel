"""Regressions for cumulative ACK supersession over the real lossy link."""

from heapq import heappop

import pytest

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_ack import CoalescedACKTCP
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic


def connection(*, loss=0, loss_model="iid", payload=64, duration=.001,
               drain=4, ack_coalesce_ms=.5, ack_copies=1,
               acknowledged_segment_slow_start=False, window_packets=10):
    return CoalescedACKTCP(
        Scenario(20, loss, loss_model),
        Traffic(duration_s=duration, drain_s=drain, frame_bytes=payload + 66,
                payload_bytes=payload, window_bytes=window_packets * payload, ack_every=1),
        (PathConfig(),), Strategy("ACK coalescing", mode="tcp", tcp_rto_min_ms=1000), 42,
        CompactConfig(repair_ratio=0, header_profile="tcp_delta"),
        transport_type=CompactARQTransport, ack_coalesce_ms=ack_coalesce_ms,
        ack_copies=ack_copies,
        acknowledged_segment_slow_start=acknowledged_segment_slow_start,
    )


def drain_events(sim):
    while sim.events:
        sim.now, _, callback, args = heappop(sim.events)
        callback(*args)


def test_advancing_ack_supersession_keeps_latest_packet_and_timestamp():
    sim = connection()
    packets = []
    sim.transmit_ack = packets.append
    sim.tcp_received, sim.timestamp_recent = 2, .001
    sim.emit_ack()
    sim.now = .0002
    sim.tcp_received, sim.timestamp_recent = 4, .002
    sim.emit_ack()
    drain_events(sim)
    assert len(packets) == 1
    assert packets[0].acknowledged == 4
    assert packets[0].created_at == .0002
    assert packets[0].echoed_timestamp == .002
    assert sim.ack_generated == 2
    assert sim.ack_superseded == 1
    assert sim.now == .0005


def test_duplicate_ack_events_flush_advance_and_preserve_cardinality():
    sim = connection()
    packets = []
    sim.transmit_ack = packets.append
    sim.tcp_received = 2
    sim.emit_ack()
    for _ in range(3):
        sim.emit_ack()
    sim.tcp_received = 4
    sim.emit_ack()
    drain_events(sim)
    assert [packet.acknowledged for packet in packets] == [2, 2, 2, 2, 4]
    assert sim.ack_duplicates_transmitted == 3
    assert sim.pending_ack is None


def test_stale_flush_cannot_send_new_batch_early():
    sim = connection()
    packets = []
    sim.transmit_ack = lambda packet: packets.append((sim.now, packet.acknowledged))
    sim.tcp_received = 1
    sim.emit_ack()
    sim.emit_ack()  # Flush advance and its duplicate immediately.
    sim.now = .0004
    sim.tcp_received = 2
    sim.emit_ack()
    drain_events(sim)
    assert packets == [(0, 1), (0, 1), (.0009, 2)]


def test_single_tail_ack_is_flushed_and_charged_full_self_contained_frame():
    sim = connection().run()
    assert sim.tcp_received == sim.tcp_acked == len(sim.sent_times) == 10
    assert sim.ack_superseded >= 8
    assert sim.wire[True]["source"] == sim.datagrams[True]["source"] * 102
    assert sim.ack_generated == sim.ack_superseded + sim.ack_transmitted
    assert sim.pending_ack is None
    assert sim.compact_reverse.sources == []


def test_lost_tail_ack_recovers_via_tcp_without_invented_delivery_feedback():
    sim = connection()
    original_send = sim.send
    dropped = False

    def send(reverse, size, kind, receive):
        nonlocal dropped
        if reverse and kind == "source" and not dropped:
            dropped = True
            return original_send(reverse, size, kind, lambda: None)
        return original_send(reverse, size, kind, receive)

    sim.send = send
    sim.run()
    assert dropped
    assert sim.tcp_timeouts == 1
    assert sim.tcp_received == sim.tcp_acked == 10
    assert sim.ack_duplicates_transmitted >= 1


@pytest.mark.parametrize("copies", [3, 4])
def test_loss_protection_copies_are_charged_and_deduplicated_before_tcp(copies):
    sim = connection(ack_copies=copies).run()
    assert sim.tcp_timeouts == sim.tcp_fast_retransmits == 0
    assert sim.tcp_received == sim.tcp_acked == 10
    assert sim.datagrams[True]["source"] == sim.ack_transmitted * copies
    assert sim.ack_copy_duplicates == sim.ack_transmitted * (copies - 1)
    assert sim.wire[True]["source"] == sim.ack_transmitted * copies * 102


def test_duplicate_ack_events_remain_distinct_after_copy_deduplication():
    sim = connection(ack_copies=3)
    observed = []
    sim.on_ack = lambda acknowledged, timestamp: observed.append((acknowledged, timestamp))
    sim.tcp_received, sim.timestamp_recent = 2, .001
    sim.emit_ack()
    for _ in range(3):
        sim.emit_ack()
    drain_events(sim)
    assert observed == [(2, .001)] * 4
    assert sim.ack_copy_duplicates == 8


@pytest.mark.parametrize("lost_copies", [1, 3])
def test_copy_recovers_lost_single_ack_without_tcp_timeout(lost_copies):
    sim = connection(ack_copies=lost_copies + 1)
    original_send = sim.send
    dropped = 0

    def send(reverse, size, kind, receive):
        nonlocal dropped
        if reverse and kind == "source" and dropped < lost_copies:
            dropped += 1
            return original_send(reverse, size, kind, lambda: None)
        return original_send(reverse, size, kind, receive)

    sim.send = send
    sim.run()
    assert dropped == lost_copies
    assert sim.tcp_timeouts == 0
    assert sim.tcp_received == sim.tcp_acked == 10


@pytest.mark.parametrize("counted, expected", [(False, 11), (True, 20)])
def test_stretch_ack_slow_start_is_explicit_and_counts_confirmed_segments(counted, expected):
    sim = connection(window_packets=100, acknowledged_segment_slow_start=counted)
    sim.produce()
    assert len(sim.forward.pending) == sim.cwnd == 10
    sim.now = .1
    sim.on_ack(10, 0)
    assert sim.cwnd == expected
    assert sim.tcp_acked == 10


def test_segment_counted_slow_start_retains_cwnd_limited_check():
    sim = connection(window_packets=100, acknowledged_segment_slow_start=True)
    sim.produce()
    sim.cwnd = 40
    sim.now = .1
    sim.on_ack(10, 0)
    assert sim.cwnd == 40
    assert sim.tcp_acked == 10


@pytest.mark.parametrize("loss_model", ["iid", "burst"])
def test_lossy_reverse_and_forward_keep_cumulative_completion(loss_model):
    sim = connection(loss=.15, loss_model=loss_model, duration=.1, drain=8).run()
    assert sim.tcp_received == sim.tcp_acked == len(sim.sent_times)
    assert sim.compact_forward.base == len(sim.compact_forward.sources)
    assert sim.ack_generated == sim.ack_superseded + sim.ack_transmitted
    assert sim.pending_ack is None


@pytest.mark.parametrize("delay", [-1, float("nan"), float("inf"), True])
def test_invalid_coalescing_delay_is_rejected(delay):
    with pytest.raises(ValueError):
        connection(ack_coalesce_ms=delay)


@pytest.mark.parametrize("copies", [0, 5, -1, 1.5, True, None])
def test_invalid_ack_copy_count_is_rejected(copies):
    with pytest.raises(ValueError, match="one to four"):
        connection(ack_copies=copies)
