"""Established DATA PAWS and the boundary between endpoint ACKs and outer copies."""
import pytest

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_ack import CoalescedACKTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.tcp import PlainTCP
from l2tunnel_sim.tcp_paws import LinuxDataPAWS


def test_one_tick_tolerance_wrap_and_expiry_match_established_data():
    paws = LinuxDataPAWS()
    assert paws.receive(0, 1, 0xfffffffe, 0, 0) == (True, True)
    assert paws.receive(1, 2, 1, 1, 1) == (True, True)
    assert paws.receive(2, 3, 0, 2, 2) == (True, False)
    assert paws.receive(2, 3, 0xffffffff, 3, 2) == (False, False)
    assert paws.receive(2, 3, 0xfffffffe, 2147.99, 2) == (False, False)
    assert paws.receive(2, 3, 0xfffffffe, 2148, 2) == (True, True)
    assert paws.rejections == 2
    fresh = LinuxDataPAWS()
    assert fresh.receive(0, 1, 0, 0, 0) == (True, True)
    assert fresh.receive(1, 2, 0xfffffff0, 1, 1) == (True, True)
    assert fresh.receive(2, 3, None, 2, 2) == (True, False)


@pytest.mark.parametrize("enabled", (False, True))
def test_gap_retransmission_releases_buffer_once_without_rechecking_queued_timestamp(enabled):
    sim = PlainTCP(Scenario(70, 0), Traffic(duration_s=1, ack_every=1),
                   (PathConfig(),), Strategy("model", mode="tcp", tcp_data_paws=enabled), 1)
    sim.sent_times = [0] * 5
    sim.now = .2
    sim.on_data(0, .100)
    sim.on_data(2, .105)  # Buffered above the latest cumulative ACK, no TS.Recent change.
    assert sim.tcp_buffer == {2} and sim.timestamp_recent == .100
    sim.on_data(1, .095)
    if enabled:
        assert sim.tcp_received == 1 and sim.tcp_buffer == {2}
        assert sim.data_paws.rejections == 1 and sim.last_ack == 1
    else:
        assert sim.tcp_received == 3
    sim.on_data(1, .150)
    assert sim.tcp_received == 3 and not sim.tcp_buffer
    assert len(sim.forward.delays) == 3
    if enabled:
        sim.on_data(0, .180)  # Ends strictly before rcv_wup. Cannot poison TS.Recent.
        assert sim.timestamp_recent == .150
        sim.on_data(3, .151)
        assert sim.tcp_received == 4


def test_pending_outer_coalescer_does_not_delay_or_rewind_the_inner_ack_edge():
    sim = CoalescedACKTCP(
        Scenario(70, 0), Traffic(duration_s=1, ack_every=2),
        (PathConfig(),), Strategy("model", mode="tcp", tcp_data_paws=True), 1,
        CompactConfig(header_profile="tcp_delta"), ack_coalesce_ms=5)
    sim.sent_times = [0]*4
    sim.now = .2
    sim.on_data(0, .100)
    assert sim.last_ack == 0 and sim.pending_ack is None
    sim.on_data(1, .110)
    assert sim.last_ack == 2 and sim.pending_ack.acknowledged == 2
    assert sim.pending_ack.echoed_timestamp == .100 and sim.ack_transmitted == 0
    sim.on_data(2, .120)
    assert sim.timestamp_recent == .120 and sim.last_ack == 2
    sim.on_data(3, .115)
    assert sim.tcp_received == 3 and sim.data_paws.rejections == 1
    assert sim.pending_ack.acknowledged == 3 and sim.pending_ack.echoed_timestamp == .120


def test_non_tcp_and_nonnumeric_switch_do_not_silently_bypass_paws():
    with pytest.raises(ValueError, match="tcp_data_paws"):
        Strategy("non-TCP", tcp_data_paws=True)
    with pytest.raises(ValueError, match="tcp_data_paws"):
        Strategy("TCP", mode="tcp", tcp_data_paws=1)


def test_frame_path_attributes_old_gap_to_first_tcp_accepted_copy():
    from collections import Counter
    from types import SimpleNamespace
    from l2tunnel_sim.packed_frame_path import Attempt, PackedFramePath

    flow = PlainTCP(Scenario(70, 0), Traffic(ack_every=1), (PathConfig(),),
                    Strategy("model", mode="tcp", tcp_data_paws=True), 1)
    flow.sent_times = [0, 0]
    flow.now = .2
    flow.on_data(0, .100)
    path = PackedFramePath.__new__(PackedFramePath)
    path.sim = SimpleNamespace(flows=[flow])
    path.counters, path.winners = Counter(), {}
    key = (0, 1)
    rejected = Attempt(key, 0, .095, 1)
    retry = Attempt(key, 0, .150, 2)
    path.pending = {key: [rejected, retry]}
    winners = []
    path._complete = lambda attempt, arrival, app: winners.append(attempt)
    path._install_tcp()
    path._dispatch = rejected
    flow.on_data(1, rejected.issue)
    assert key not in path.winners
    path._dispatch = retry
    flow.on_data(1, retry.issue)
    assert winners == [retry] and path.counters["data_paws_rejections"] == 1
