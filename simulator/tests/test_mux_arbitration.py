"""Finite FIFO contention and independent-channel receive-order regressions."""

import importlib
from pathlib import Path

import pytest

from l2tunnel_sim.compact import tcp_profile_frame
from l2tunnel_sim.compact_wire import decode_packet
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.multiflow import MultiFlow
from l2tunnel_sim.tcp_syn_probe import Probe, handshake_frame


def native_fifo_trace(queued_packets):
    simulation = MultiFlow(Scenario(70, 0), Traffic(duration_s=.1, drain_s=.2),
                           (PathConfig(100, 10),), Strategy('FIFO fixture', mode='tcp'), 42, 2)
    for flow in simulation.flows:
        flow.produce = lambda: None
    first, second = simulation.flows
    trace = []

    def transmit(flow, owner, reverse, size, received):
        link = flow.links[reverse][0]
        row = dict(owner=owner, reverse=reverse, bytes=size, submitted_s=flow.now,
                   serializer_start_s=max(flow.now, link.free_at))
        def arrive():
            row['received_s'] = flow.now
            received()
        finish, _ = flow.send(reverse, size, owner, arrive)
        row['serializer_end_s'] = finish
        trace.append(row)

    for _ in range(queued_packets):
        transmit(first, 'A bulk', False, 1500, lambda: None)
    transmit(second, 'B SYN', False, 52,
             lambda: transmit(second, 'B SYN-ACK', True, 52, lambda: None))
    simulation.run()
    return trace


@pytest.mark.parametrize('queued_packets', [0, 1, 10, 100])
def test_second_tcp_waits_for_already_reserved_fifo_service(queued_packets):
    trace = native_fifo_trace(queued_packets)
    syn = next(row for row in trace if row['owner'] == 'B SYN')
    response = next(row for row in trace if row['owner'] == 'B SYN-ACK')
    queued_seconds = queued_packets * 1500 * 8 / 100e6
    assert syn['serializer_start_s'] == pytest.approx(queued_seconds)
    assert response['received_s'] * 1000 == pytest.approx(70.04576 + queued_seconds * 1000)
    assert all(row['serializer_end_s'] <= syn['serializer_start_s'] + 1e-12
               for row in trace if row['owner'] == 'A bulk')


def compact_channel_trace(study, drop_first_source=False):
    from test_tcp_syn_probe import case
    task = case(duration=.3, drain=1)
    task['profile']['flow_count'] = 2
    task['profile']['compact']['repair_ratio'] = 0
    simulation = study.make_simulation(task)
    for flow in simulation.flows:
        flow.produce = lambda: None
    shared = simulation.shared_forward
    trace, delivered = [], []
    original_send = shared._send_wire

    def send(wire, kind, header_bytes):
        packet = decode_packet(wire, 0, shared.config.encapsulation)
        channel = packet.payload[0] if packet.kind == 'source' else None
        start = max(simulation.flows[0].now, simulation.links[False][0].free_at)
        finish, rtt = original_send(wire, kind, header_bytes)
        trace.append(dict(kind=kind, channel=channel, submitted_s=simulation.flows[0].now,
                          serializer_start_s=start, serializer_end_s=finish, bytes=len(wire)+20))
        return finish, rtt

    shared._send_wire = send
    if drop_first_source:
        outcomes = iter([True])
        simulation.links[False][0].erasures.lost = lambda: next(outcomes, False)
    first = tcp_profile_frame(sequence=0, identification=0, payload_bytes=1448)
    second = handshake_frame(Probe(0, 1, 0), reverse=False, flags=2, timestamp=0, identification=1)
    for channel, frame in ((0, first), (1, second)):
        shared.submit_channel(channel, len(frame), len(frame)-66,
            lambda received: delivered.append(dict(time_s=simulation.flows[0].now, frame=received)),
            frame=frame, deliver_frame=True)
    simulation.run()
    return trace, delivered, first, second


@pytest.fixture
def study(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'studies'))
    return importlib.import_module('aggregate_ack_deadlines')


def test_compact_mux_keeps_fifo_service_and_delivers_decoded_frame_bytes(study):
    trace, delivered, first, second = compact_channel_trace(study)
    source = [row for row in trace if row['kind'] == 'source']
    channel_a = [row for row in source if row['channel'] == 0]
    channel_b = [row for row in source if row['channel'] == 1]
    assert channel_a and channel_b
    assert max(row['serializer_end_s'] for row in channel_a) <= min(row['serializer_start_s'] for row in channel_b)
    assert [row['frame'] for row in delivered] == [first, second]
    assert delivered[1]['time_s'] >= max(row['serializer_end_s'] for row in channel_b) + .01 - 1e-12


def test_missing_channel_a_context_does_not_block_channel_b_decode(study):
    trace, delivered, first, second = compact_channel_trace(study, drop_first_source=True)
    assert [row['frame'] for row in delivered] == [second, first]
    assert delivered[0]['time_s'] < delivered[1]['time_s']
    assert trace[0]['channel'] == 0 and trace[0]['bytes'] > 0


@pytest.mark.parametrize("module_name,factory_name", [
    ("test_shared_records", "transport_fixture"),
    ("test_aligned_records", "transport_fixture"),
    ("test_compact_wire", "fixture"),
])
def test_all_shared_wire_formats_pass_decoded_bytes_to_frame_receiver(module_name, factory_name):
    module = importlib.import_module(module_name)
    transport, packets = getattr(module, factory_name)()
    frame = handshake_frame(Probe(4, 7, 0), reverse=False, flags=2, timestamp=11, identification=9)
    received = []
    transport.submit_channel(7, len(frame), 0, received.append, frame=frame, deliver_frame=True)
    transport.flush()
    for _, _, kind, receive in list(packets):
        if kind == "source":
            receive()
    assert received == [frame]
    assert not transport.callbacks


def l2_window_trace(study, drop_first_source, tail_delay_ms=None):
    from test_tcp_syn_probe import case
    task = case(duration=.3, drain=1)
    task['profile']['flow_count'] = 2
    task['profile']['compact']['repair_ratio'] = 0
    task['profile']['compact']['tail_repair_delay_ms'] = tail_delay_ms
    sim = study.make_simulation(task)
    for flow in sim.flows:
        flow.produce = lambda: None
    transport = sim.shared_forward
    events, deliveries = [], []
    b_sources = []
    original_send = transport._send_wire
    original_feedback = transport._receive_feedback

    def record(stage):
        events.append(dict(stage=stage, time_s=sim.flows[0].now,
            sent_sources=len(transport.sources), confirmed_prefix=transport.base,
            outstanding_sources=len(transport.sources)-transport.base,
            queued_sources=len(transport.source_queue), b_sources=len(b_sources),
            physical_queue_ms=max(0, sim.links[False][0].free_at-sim.flows[0].now)*1000))

    def send(wire, kind, header_bytes):
        packet = decode_packet(wire, transport.received_prefix, transport.config.encapsulation)
        if packet.kind == 'source' and packet.payload[0] == 1:
            b_sources.append(sim.flows[0].now)
            record('B source admitted')
        elif kind == 'repair':
            record('L2 repair submitted')
        return original_send(wire, kind, header_bytes)

    def feedback(prefix, deficit):
        was_full = len(transport.sources)-transport.base == transport.config.block_sources
        previous = transport.base
        original_feedback(prefix, deficit)
        if was_full and prefix > previous:
            record('feedback advanced full window')

    transport._send_wire = send
    transport._receive_feedback = feedback
    if drop_first_source:
        outcomes = iter([True])
        sim.links[False][0].erasures.lost = lambda: next(outcomes, False)
    for index in range(transport.config.block_sources-1):
        frame = tcp_profile_frame(sequence=index*64, identification=index, payload_bytes=64)
        transport.submit_channel(0, len(frame), 64, lambda: None, frame=frame)
    assert len(transport.sources) == transport.config.block_sources
    last_finish = sim.links[False][0].free_at

    def submit_b():
        record('before B submit')
        frame = handshake_frame(Probe(0,1,sim.flows[0].now),reverse=False,flags=2,timestamp=0,identification=0)
        transport.submit_channel(1,len(frame),0,lambda received: deliveries.append(sim.flows[0].now),frame=frame,deliver_frame=True)
        record('after B submit')
    sim.flows[0].at(last_finish+.011,submit_b)
    sim.run()
    record('complete')
    return dict(first_source_erased=drop_first_source, window_sources=transport.config.block_sources,
        last_A_serialized_s=last_finish, events=events, B_frame_delivered_s=deliveries)


@pytest.mark.parametrize('drop_first_source', [False, True])
def test_shared_l2_window_and_repair_feedback_control_other_flow_admission(study, drop_first_source):
    trace = l2_window_trace(study, drop_first_source)
    before = next(row for row in trace['events'] if row['stage'] == 'before B submit')
    after = next(row for row in trace['events'] if row['stage'] == 'after B submit')
    admitted = next(row for row in trace['events'] if row['stage'] == 'B source admitted')
    assert before['physical_queue_ms'] == 0
    assert len(trace['B_frame_delivered_s']) == 1
    if drop_first_source:
        assert before['outstanding_sources'] == trace['window_sources'] == 8192
        assert after['queued_sources'] == 2 and after['b_sources'] == 0
        repair = next(row for row in trace['events'] if row['stage'] == 'L2 repair submitted')
        released = next(row for row in trace['events'] if row['stage'] == 'feedback advanced full window')
        assert repair['outstanding_sources'] == trace['window_sources']
        assert repair['time_s'] - trace['last_A_serialized_s'] == pytest.approx(.05)
        assert admitted['time_s'] == released['time_s']
        assert admitted['time_s'] - before['time_s'] == pytest.approx(.06004064)
    else:
        assert before['outstanding_sources'] < trace['window_sources']
        assert after['queued_sources'] == 0 and after['b_sources'] == 2
        assert admitted['time_s'] == before['time_s']
    assert trace['events'][-1]['outstanding_sources'] == 0


def test_short_tail_repair_releases_shared_window_earlier(study):
    waits = []
    for delay_ms in (None, 7.5):
        trace = l2_window_trace(study, True, tail_delay_ms=delay_ms)
        before = next(row for row in trace['events'] if row['stage'] == 'before B submit')
        admitted = next(row for row in trace['events'] if row['stage'] == 'B source admitted')
        assert before['physical_queue_ms'] == 0
        assert before['outstanding_sources'] == trace['window_sources']
        assert trace['events'][-1]['outstanding_sources'] == 0
        assert len(trace['B_frame_delivered_s']) == 1
        waits.append(admitted['time_s'] - before['time_s'])
    assert waits[0] == pytest.approx(.06004064)
    assert 0 < waits[1] < .025
