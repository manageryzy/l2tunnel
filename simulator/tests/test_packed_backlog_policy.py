from collections import deque
from types import SimpleNamespace

import pytest

from l2tunnel_sim.compact_wire import CompactWireConfig
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.packed_backlog_policy import BacklogPackedWireTransport, oldest_mux_wait_ms
from l2tunnel_sim.packed_targeted import TargetedPolicy


def test_oldest_age_observes_only_local_unadmitted_frames_in_one_direction():
    mux = SimpleNamespace(sim=SimpleNamespace(now=1.), queues=[
        [deque([(b"a",1,.984),(b"b",1,.996)]), deque([(b"c",1,.990)])],
        [deque([(b"r",1,.998)])],
    ])
    assert oldest_mux_wait_ms(mux, False) == pytest.approx(16)
    assert oldest_mux_wait_ms(mux, True) == pytest.approx(2)
    mux.queues[0][0].popleft()
    assert oldest_mux_wait_ms(mux, False) == pytest.approx(10)
    mux.queues[0][0].clear()
    mux.queues[0][1].clear()
    assert oldest_mux_wait_ms(mux, False) == 0


def test_hysteresis_changes_only_actual_requested_byte_credit_without_new_wakes():
    sim = Simulation(Scenario(70, 0), Traffic(duration_s=1, drain_s=1), (PathConfig(100,10),),
                     Strategy("backlog hysteresis", mode="tcp"), 92)
    cfg = CompactWireConfig(repair_ratio=.205, feedback_ms=1, encapsulation="raw_ipv4_crc32",
                            trim_repair_padding=True, pack_sources_max_delay_ms=.5)
    ages = iter([14,15,14,6,5,6])
    tx = BacklogPackedWireTransport(sim, False, cfg, policy=TargetedPolicy(),
                                    oldest_wait_ms=lambda: next(ages))
    frame = bytes.fromhex("02000000000202000000000188b5") + bytes(900)
    tx.submit_channel(0, len(frame), 900, lambda: None, frame=frame)
    size = tx.sources[0].size + tx.source_header
    for expected in (.5,1,1,1,.5,.5):
        credit = tx.latency_counts["retry_credit_bytes"]
        jobs = len(sim.events)
        tx._resend(0,"requested_retries")
        # Same single link departure as an ordinary targeted retransmission.
        assert len(sim.events) == jobs + 1
        assert tx.latency_counts["retry_credit_bytes"] - credit == expected * size
    # No MUX sample or credit for an expired oldest-original fallback.
    tx._resend(0,"quiet_probes")
    assert tx.targeted_counts["quiet_probes"] == 1
    assert tx.latency_counts["entered_full_credit"] == tx.latency_counts["returned_to_half_credit"] == 1
    assert tx.latency_counts["full_weighted_retries"] == tx.latency_counts["half_weighted_retries"] == 3
