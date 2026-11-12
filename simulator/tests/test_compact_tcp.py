"""Regressions for congestion-controlled TCP carried by compact coding."""

from dataclasses import replace

import pytest

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_tcp import CompactTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure


def connection(*, packets=10, loss=0, reliable_acks=True, drain=2):
    return CompactTCP(
        Scenario(20, loss),
        Traffic(duration_s=.001, drain_s=drain, window_bytes=packets * 1448,
                ack_every=1),
        (PathConfig(),), Strategy('Compact CUBIC', mode='tcp'), 42,
        CompactConfig(repair_ratio=.19), reliable_acks=reliable_acks,
    )


@pytest.mark.parametrize('reliable_acks', [True, False])
def test_inner_tcp_delivers_full_frames_and_advances_cumulative_acks(reliable_acks):
    sim = connection(reliable_acks=reliable_acks).run()
    row = measure(sim)
    assert row['tcp_delivered_frames'] == row['tcp_acked_frames'] == 10
    assert row['forward_l2_bytes'] == 10 * 1514
    assert row['tcp_retransmissions'] == row['tcp_timeouts'] == 0
    assert sim.cwnd > 1
    assert sim.srtt is not None
    assert sim.forward.pending_bytes == 0


def test_forward_source_loss_is_hidden_from_tcp_by_coding():
    sim = connection(reliable_acks=False)
    decisions = iter([True] + [False] * 10000)
    sim.links[False][0].erasures.lost = lambda: next(decisions)
    row = measure(sim.run())
    assert row['tcp_delivered_frames'] == row['tcp_acked_frames'] == 10
    assert sim.compact_forward.recovered_symbols >= 1
    assert row['tcp_retransmissions'] == row['tcp_timeouts'] == 0


def test_native_ack_route_really_experiences_reverse_packet_loss():
    sim = connection(reliable_acks=False)
    decisions = iter([True] + [False] * 10000)
    sim.links[True][0].erasures.lost = lambda: next(decisions)
    row = measure(sim.run())
    assert row['reverse_lost_datagrams'] == 1
    assert row['tcp_acked_frames'] == 10
    assert row['reverse_feedback_datagrams'] > 0
    assert sim.compact_reverse.frame_count == 0


def test_complete_loss_preserves_incomplete_state_and_inner_tcp_timeout():
    row = measure(connection(packets=1, loss=1, drain=3.1).run())
    assert row['tcp_delivered_frames'] == 0
    assert row['tcp_delivery_fraction'] == 0
    assert row['tcp_timeouts'] == row['tcp_retransmissions'] == 2
    assert row['forward_unconfirmed_bytes'] == 1448


def test_delta_data_echoes_received_ack_timestamp(monkeypatch):
    from l2tunnel_sim import compact_tcp

    encoded_fields = []
    original = compact_tcp.tcp_profile_frame

    def record_frame(**fields):
        encoded_fields.append(fields)
        return original(**fields)

    monkeypatch.setattr(compact_tcp, 'tcp_profile_frame', record_frame)
    sim = connection(reliable_acks=False)
    sim.traffic = replace(sim.traffic, duration_s=.2)
    config = replace(sim.compact_config, header_profile='tcp_delta')
    sim.compact_config = config
    sim.compact_forward = compact_tcp.CompactTransport(sim, False, config)
    sim.run()
    assert sim.peer_timestamp > 0
    assert any(fields['echoed_timestamp'] > 0 for fields in encoded_fields)
