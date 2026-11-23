"""First advancing ACK after a modeled fast retransmission."""
import pytest

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.tcp import PlainTCP, partial_ack_predates_retry


def loss_episode(enabled=True):
    sim = PlainTCP(Scenario(70, 0), Traffic(duration_s=.05),
                   (PathConfig(),), Strategy("endpoint", mode="tcp", tcp_partial_timestamp_undo=enabled), 1)
    sim.now = .08
    sim.cwnd, sim.ssthresh = 8, 64
    for _ in range(8):
        sim.issue_original_segment()
    sim.now = .16
    for _ in range(3):
        sim.on_ack(0)
    assert sim.in_recovery and sim.forward.pending[0].attempts == 2
    return sim


def test_partial_ack_with_original_timestamp_restores_window_and_preserves_later_holes():
    sim = loss_episode()
    sim.now = .19
    sim.on_ack(0, .08)
    assert sim.in_recovery and sim.tcp_partial_timestamp_undos == 0
    sim.on_ack(1, .08)
    assert (sim.cwnd, sim.ssthresh, sim.tcp_partial_timestamp_undos) == (8, 64, 1)
    assert not sim.in_recovery and sim.forward.pending[1].attempts == 1
    assert sim.tcp_acked == 1 and set(sim.forward.pending) == set(range(1, 8))
    sim.now = 3
    sim.on_timeout(sim.timer_generation)
    assert sim.forward.pending[1].attempts == 2 and sim.cwnd == 1


@pytest.mark.parametrize("enabled,echo", [(False, .08), (True, None), (True, 0), (True, .160), (True, .17)])
def test_unproven_first_partial_ack_uses_ordinary_recovery(enabled, echo):
    sim = loss_episode(enabled)
    sim.now = .19
    sim.on_ack(1, echo)
    sim.on_ack(2, .08)
    assert sim.in_recovery and sim.forward.pending[2].attempts == 2
    assert sim.tcp_partial_timestamp_undos == 0 and sim.ssthresh < 64


def test_full_ack_and_later_timeout_cannot_restore_old_checkpoint():
    sim = loss_episode()
    sim.now = .19
    sim.on_ack(8, .08)
    assert sim.tcp_partial_timestamp_undos == 0 and not sim.in_recovery
    sim = loss_episode()
    sim.now = 3
    sim.on_timeout(sim.timer_generation)
    sim.on_ack(1, .08)
    assert sim.tcp_partial_timestamp_undos == 0 and sim.ssthresh < 64


def test_wire_tick_wrap_ambiguity_and_strategy_scope():
    assert partial_ack_predates_retry(1, 2, 3, 1, 0xffffffff)
    assert not partial_ack_predates_retry(1, 2, 3, 0xffffffff, 1)
    assert not partial_ack_predates_retry(1, 2, 3, 1, 0x80000001)
    with pytest.raises(ValueError, match="tcp_partial_timestamp_undo"):
        Strategy("not TCP", tcp_partial_timestamp_undo=True)
