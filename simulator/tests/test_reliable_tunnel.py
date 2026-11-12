"""Real-protocol shared-stream baselines preserve inner TCP, HOL and accounting."""

from copy import deepcopy
import importlib
import json
from pathlib import Path
from math import floor

import pytest

pytest.importorskip('aioquic')

from l2tunnel_sim.compact import tcp_profile_frame
from l2tunnel_sim.kcp import KCPContext, library
from l2tunnel_sim.mux import frame_tuple
from l2tunnel_sim.mux_tcp import bulk_connection_frame
from l2tunnel_sim.reliable_tunnel import TunnelHandshakeProbe
from l2tunnel_sim.tcp_syn_probe import Probe, SYNProbeConfig, handshake_frame


@pytest.fixture
def study(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'studies'))
    return importlib.import_module('tcp_syn_baseline_regression')


def case(study, kind, *, flows=2, duration=.4, drain=3, payload=1448, loss=0):
    profile = deepcopy(next(item for item in study.inner_profiles() if item['kind'] == kind))
    profile.update(flow_count=flows, payload_rate_mbps=1, window_bytes=payload * flows * 20)
    profile['tcp_syn_probe'].update(interval_ms=100, timeout_ms=100, stability_window_s=.02,
        stability_windows=2, throughput_tolerance_pct=100, queue_tolerance_ms=10)
    return dict(profile=profile, run_id=1, payload_bytes=payload, duration_s=duration, warmup_s=.01,
        drain_s=drain, forward_mbps=100, reverse_mbps=10, rtt_ms=20, loss_rate=loss,
        loss_model='iid', mtu=1500, seed=42, replication=1)


@pytest.mark.parametrize('kind', ('quic_inner', 'kcp_inner'))
@pytest.mark.parametrize('payload', (64, 1448))
def test_normal_entry_has_real_inner_tcp_and_no_extra_probe_stream_or_connection(study, kind, payload):
    task = case(study, kind, payload=payload, duration=1)
    task['profile']['tcp_syn_probe']['stability_window_s'] = .1
    row = study.execute(task)
    assert row['tunnel_inner_tcp'] and row['fully_confirmed'] and row['tunnel_all_confirmed']
    assert row['tunnel_connection_count'] == row['flow_count'] == 2
    assert row['tunnel_probe_extra_streams'] == row['tunnel_probe_extra_connections'] == 0
    assert row['tcp_syn_ping_completed'] == row['tcp_syn_ping_offered'] > 0
    assert row['tcp_syn_probe_start_s'] >= .04
    assert row['tcp_syn_ping_p99_ms'] >= 20
    assert row['tcp_syn_probe_all_flushed']
    assert set(row['tcp_syn_probe_channels_used']) <= {0, 1}
    assert row['tcp_acked_frames'] == row['tcp_delivered_frames'] == row['offered_frames']
    assert row['forward_l2_bytes'] == row['offered_frames'] * (payload + 66)
    mux = row['tunnel_mux']
    assert mux['mux_forward']['submitted_frames'] == row['offered_frames'] + row['tcp_retransmissions'] + row['tcp_syn_probe_forward_frames']
    assert mux['mux_reverse']['submitted_frames'] == row['ack_transmitted'] + row['tcp_syn_probe_reverse_submitted_frames']
    assert all(part['confirmed'] for part in row['tunnel_protocol_records'])
    for part in row['tunnel_protocol_records']:
        assert part['pending_first_transmission_bytes'] == [0, 0]
        assert all(value > 0 for value in part['peak_pending_first_transmission_bytes'])
        if kind == 'quic_inner':
            assert part['streams'] == [[0], [0]]
            assert part['submitted_stream_bytes'] == part['received_stream_bytes'] == part['acknowledged_stream_bytes']
            assert max(part['peak_outstanding_bytes']) <= part['sender_window_bytes']
        else:
            assert max(part['peak_waiting_segments']) <= part['sender_window_segments']
            assert part['submitted_frame_bytes'] == part['received_frame_bytes']
    prefix = 'tcp_syn_ping_measurement_'
    p, wire, seconds = [row[prefix + item] for item in ('payload_bytes', 'forward_ip_bytes', 'duration_s')]
    assert row['tcp_syn_ping_background_goodput_mbps'] == pytest.approx(8 * p / seconds / 1e6)
    assert row[prefix + 'extra_forward_ip_pct'] == pytest.approx(100 * (wire / p - 1))
    assert wire * 8 / seconds / 1e6 <= 100 + 1e-6


@pytest.mark.parametrize('kind', ('quic_inner', 'kcp_inner'))
@pytest.mark.parametrize('reverse', (False, True))
@pytest.mark.parametrize('probe_first', (False, True))
def test_bulk_and_probe_share_actual_protocol_hol_under_held_loss(study, kind, reverse, probe_first):
    sim = study.make_simulation(case(study, kind, flows=1, duration=.5, drain=3))
    sim.flows[0].produce = lambda: None
    bulk = bulk_connection_frame(tcp_profile_frame(payload_bytes=1448, flags=0x10 if reverse else 0x18), 41000, reverse)
    probe = handshake_frame(Probe(0, 0, 0), reverse=reverse, flags=0x12 if reverse else 0x02,
                            timestamp=0, identification=1)
    frames = [probe, bulk] if probe_first else [bulk, probe]
    received = []
    if reverse:
        opening = bulk_connection_frame(tcp_profile_frame(payload_bytes=0), 42000, False)
        sim.mux.register_endpoint(False, frame_tuple(opening), lambda _frame: None)
        sim.mux.submit_frame(False, opening)
    for frame in frames:
        sim.mux.register_endpoint(reverse, frame_tuple(frame), received.append)
        sim.flows[0].at(.03 if reverse else 0, sim.mux.submit_frame, reverse, frame)
    hold = [True]
    sim.links[reverse][0].erasures.lost = lambda: hold[0]
    sim.flows[0].at(.19, lambda: received.append('still held') if not received else received.append('overtook loss'))
    sim.flows[0].at(.2, hold.__setitem__, 0, False)
    sim.run()
    assert received == ['still held', *frames]
    assert sim.tunnel_confirmed
    metadata = sim.mux.measurements()['mux_' + ('reverse' if reverse else 'forward')]
    assert metadata['submitted_frames'] == metadata['admitted_frames'] == metadata['delivered_frames'] == 2
    assert metadata['delivered_bytes'] == sum(map(len, frames))
    assert sum(sim.flows[0].wire[reverse].values()) > sum(map(len, frames))


@pytest.mark.parametrize('kind', ('quic_inner', 'kcp_inner'))
def test_sender_window_blocks_bulk_and_probe_in_the_same_fifo(study, kind):
    task = case(study, kind, flows=1, duration=.2, drain=.2)
    task['profile']['window_bytes'] = 1448
    if kind == 'kcp_inner':
        task['profile']['kcp']['window'] = 2
    sim = study.make_simulation(task)
    sim.flows[0].produce = lambda: None
    bulk = bulk_connection_frame(tcp_profile_frame(payload_bytes=1448), 41000, False)
    probe = handshake_frame(Probe(0, 0, 0), reverse=False, flags=0x02, timestamp=0, identification=1)
    received = []
    sim.mux.register_endpoint(False, frame_tuple(bulk), received.append)
    sim.mux.register_endpoint(False, frame_tuple(probe), received.append)
    sim.mux.submit_frame(False, bulk)
    sim.mux.submit_frame(False, probe)
    sim.mux.submit_frame(False, bulk)
    sim.links[True][0].erasures.lost = lambda: True
    sim.run()
    metadata = sim.mux.measurements()['mux_forward']
    assert received == [bulk]
    assert metadata['submitted_frames'] == 3 and metadata['admitted_frames'] == 1
    assert metadata['queued_frames'] == 2 and metadata['window_stall_events'] > 0
    assert not sim.tunnel_confirmed


@pytest.mark.parametrize('kind', ('quic_inner', 'kcp_inner'))
def test_entire_reverse_loss_preserves_missing_probe_and_unconfirmed_outer_bytes(study, kind):
    sim = study.make_simulation(case(study, kind, duration=.2, drain=.3))
    probe = TunnelHandshakeProbe(sim, SYNProbeConfig(interval_ms=100, timeout_ms=100),
                                start_s=.01, wait_for_stability=False)
    sim.links[True][0].erasures.lost = lambda: True
    sim.run()
    row = probe.measurements()
    assert row['tcp_syn_ping_offered'] == row['tcp_syn_ping_timeouts'] == 1
    assert row['tcp_syn_ping_p99_ms'] is None
    assert not sim.tunnel_confirmed and not row['tcp_syn_probe_all_flushed']


def test_upstream_kcp_message_fragmentation_loss_recovery_and_source_receipt():
    left, right = KCPContext(19), KCPContext(19)
    messages = [bytes(range(256)) * 8, b'fresh SYN bytes', b'ordinary ACK bytes']
    for message in messages:
        left.send(message)
    received, dropped = [], False
    for now in range(0, 3000, 10):
        for packet in left.update(now):
            if not dropped:
                dropped = True
                continue
            right.input(packet)
        while (message := right.receive()) is not None:
            received.append(message)
        for packet in right.update(now):
            left.input(packet)
    assert received == messages and not left.waiting
    receipt = library().receipt
    assert receipt['upstream_commit'] == '8004f7eba5d1bf33f0691eef5f887f2cd3140cb5'
    assert set(receipt['source_files']) == {'ikcp.c', 'ikcp.h', 'LICENSE'}
    assert len(receipt['library_sha256']) == 64
    left.close()
    right.close()


def test_baseline_matrix_selects_new_profiles_without_changing_historical_default(study):
    assert len(study.tasks()) == 45
    tasks = study.tasks(replications=1, include_compact=False, baseline_kinds=('tcp', 'quic_inner', 'kcp_inner'))
    assert len(tasks) == 18
    assert {task['profile']['kind'] for task in tasks} == {'tcp', 'quic_inner', 'kcp_inner'}
    assert len({task['seed'] for task in tasks}) == 1
    assert all(task['profile']['flow_count'] == 16 and task['forward_mbps'] == 100 and task['reverse_mbps'] == 10 for task in tasks)


def test_quic_ack_credit_uses_current_endpoint_sender_with_asymmetric_directions(study):
    sim = study.make_simulation(case(study, 'quic_inner', flows=1))
    connection = sim.protocols[0]
    connection.submitted = [100, 40]
    connection.sent_ranges[False][900] = [(0, 100)]
    connection.sent_ranges[True][901] = [(0, 40)]
    connection.observe_packet(False, {'frames': [{'frame_type': 'ack', 'acked_ranges': [[900, 900]]}]})
    assert connection.measurements()['acknowledged_stream_bytes'] == [100, 0]
    assert 901 in connection.sent_ranges[True]
    connection.observe_packet(True, {'frames': [{'frame_type': 'ack', 'acked_ranges': [[901, 901]]}]})
    assert connection.measurements()['acknowledged_stream_bytes'] == [100, 40]


@pytest.mark.parametrize('kind', ('quic_inner', 'kcp_inner'))
def test_growing_admitted_unsent_protocol_queue_blocks_original_stability_gate(study, kind):
    task = case(study, kind, flows=1, duration=3.5, drain=0)
    task['profile']['window_bytes'] = 1048576
    sim = study.make_simulation(task)
    sim.flows[0].produce = lambda: None
    connection = sim.protocols[0]
    if kind == 'quic_inner':
        connection.flush = lambda reverse: None
    else:
        connection.schedule = lambda: None
    bulk = bulk_connection_frame(tcp_profile_frame(payload_bytes=1448), 41000, False)
    sim.mux.register_endpoint(False, frame_tuple(bulk), lambda frame: None)
    for index in range(60):
        sim.flows[0].at(index * .05, sim.mux.submit_frame, False, bulk)
    probe = TunnelHandshakeProbe(sim, SYNProbeConfig(timeout_ms=100), start_s=.1)
    # Hold throughput exactly constant so only the protocol queue can reject the gate.
    probe.bulk_received = lambda: floor(sim.flows[0].now + 1e-8) * 1000
    sim.run()
    assert sim.mux.queued_frames == [0, 0]
    assert all(link.free_at == 0 for direction in sim.links for link in direction)
    assert connection.pending_bytes(False) >= 60 * len(bulk)
    assert connection.measurements()['pending_first_transmission_bytes'][False] > 0
    assert probe.steady_started_at is None and not probe.probes
    windows = probe.stability_history
    assert len(windows) >= 3
    assert len({window['goodput_mbps'] for window in windows}) == 1
    assert windows[2]['forward_queue_mean_ms'] - windows[0]['forward_queue_mean_ms'] > 1


@pytest.mark.parametrize('kind', ('quic_inner', 'kcp_inner'))
@pytest.mark.parametrize('reverse', (False, True))
def test_protocol_queue_excludes_first_sent_unacknowledged_bytes(study, kind, reverse):
    sim = study.make_simulation(case(study, kind, flows=1))
    connection = sim.protocols[0]
    connection.submitted[reverse] = 1000
    sent = connection.sent_ends if kind == 'quic_inner' else connection.unique_payload_sent
    sent[reverse] = 600
    link = sim.links[reverse][0]
    link.free_at = sim.flows[0].now + .002
    sim.mux.queued_bytes[reverse] = 100
    assert connection.pending_bytes(reverse) == 400
    assert sim.mux.queue_delay_ms(reverse) == pytest.approx(2 + 500 / link.bytes_per_s * 1000)
    sent[reverse] = 1000
    assert connection.pending_bytes(reverse) == 0
    assert sim.mux.queue_delay_ms(reverse) == pytest.approx(2 + 100 / link.bytes_per_s * 1000)


def test_kcp_first_transmission_counter_does_not_count_retransmissions(study):
    sim = study.make_simulation(case(study, 'kcp_inner', flows=1, duration=.2, drain=1))
    sim.flows[0].produce = lambda: None
    bulk = bulk_connection_frame(tcp_profile_frame(payload_bytes=1448), 41000, False)
    sim.mux.register_endpoint(False, frame_tuple(bulk), lambda frame: None)
    sim.links[True][0].erasures.lost = lambda: True
    sim.mux.submit_frame(False, bulk)
    sim.run()
    part = sim.protocols[0].measurements()
    assert part['retransmitted_segments'][False] > 0
    assert part['first_transmitted_frame_bytes'][False] == len(bulk)
    assert part['pending_first_transmission_bytes'] == [0, 0]
    assert not part['confirmed']
