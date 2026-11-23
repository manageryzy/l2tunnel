"""Cumulative NewReno loss indication with real segment byte boundaries."""
import pytest

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.tcp import PlainTCP
from l2tunnel_sim.tcp_application import PacedSocketWriter


def endpoint(sizes, enabled=True):
    flow = PlainTCP(Scenario(70, 0), Traffic(duration_s=.05, payload_bytes=512),
                    (PathConfig(),), Strategy("endpoint", mode="tcp", tcp_newreno_ack_heuristic=enabled), 1)
    PacedSocketWriter(flow, 65536, 1000000, 32, tcp_mss=1448)
    flow.now = .08
    for size in sizes:
        flow.segment_offsets.append(flow.segment_offsets[-1] + size)
        flow.issue_original_segment()
    flow.recover = len(sizes)
    flow.now = .16
    return flow


@pytest.mark.parametrize("sizes,enters", [
    ([1448] * 4, True), ([1448] * 4 + [1], False), ([17, 9, 512, 800, 1448, 1448], True),
])
def test_third_duplicate_uses_last_advancing_byte_delta_and_packetizer_smss(sizes, enters):
    flow = endpoint(sizes + [100, 500])
    edge = len(sizes)
    flow.on_ack(edge)
    for index in [edge, edge - 1, edge]:
        flow.on_ack(index)
    assert flow.last_ack_advance_bytes == sum(sizes) and flow.smss_bytes == 1448
    assert not flow.in_recovery
    for _ in range(3):
        flow.on_ack(edge)
    assert flow.in_recovery is enters
    assert flow.forward.pending[edge].attempts == 1 + enters
    assert flow.tcp_newreno_ack_heuristic_entries == flow.tcp_fast_retransmits == int(enters)


def test_timeout_with_one_segment_window_and_no_unacknowledged_data():
    flow = endpoint([500] * 8)
    flow.on_ack(1)
    flow.now = 3
    flow.on_timeout(flow.timer_generation)
    assert flow.tcp_timeouts == 1 and flow.cwnd == 1 and flow.forward.pending[1].attempts == 2
    for _ in range(5):
        flow.on_ack(1)
    assert flow.forward.pending[1].attempts == 2 and not flow.in_recovery
    flow.on_ack(8)
    for _ in range(3):
        flow.on_ack(8)
    assert not flow.forward.pending and not flow.tcp_fast_retransmits


def test_no_advance_or_disabled_option_preserves_previous_recovery_gate():
    for enabled in (False, True):
        flow = endpoint([128] * 8, enabled)
        for _ in range(3):
            flow.on_ack(0)
        assert not flow.in_recovery
        flow.on_ack(1)
        for _ in range(3):
            flow.on_ack(1)
        assert flow.in_recovery is enabled
    assert not Strategy("normal", mode="tcp").tcp_newreno_ack_heuristic
    with pytest.raises(ValueError, match="tcp_newreno_ack_heuristic"):
        Strategy("non-TCP", tcp_newreno_ack_heuristic=True)
