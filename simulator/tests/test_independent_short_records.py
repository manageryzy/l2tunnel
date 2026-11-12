"""Self-contained short frames retain channel and coding gap accounting."""

from heapq import heappop
from itertools import count
from functools import partial

import pytest

from l2tunnel_sim.aligned_records import (
    CHANNEL_HEADER, AlignedRecordConfig, AlignedRecordReceiver, AlignedRecordTransport,
)
from l2tunnel_sim.compact import CompactHeaderCodec, tcp_profile_frame
from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport, decode_packet
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.mux_tcp import MuxTCP, UnifiedMuxHandshakeProbe, UnifiedMuxMultiFlow
from l2tunnel_sim.tcp_syn_probe import SYNProbeConfig


def make_transport(kind, reverse=False, threshold=128, *, mtu=1500, **options):
    simulation = Simulation(
        Scenario(70, 0, mtu=mtu), Traffic(duration_s=1, drain_s=1),
        (PathConfig(100, 10),), Strategy("independent short fixture", mode="tcp"), 42)
    config_type, transport_type = ((CompactWireConfig, CompactWireTransport) if kind == "wire"
                                  else (AlignedRecordConfig, AlignedRecordTransport))
    fields = dict(repair_ratio=0, feedback_ms=1, tail_repair_delay_ms=10000,
                  elide_payload_length=True, packed_predictive_records=True,
                  independent_short_frame_bytes=threshold)
    if kind == "wire":
        fields["encapsulation"] = "raw_ipv4_crc32"
    fields.update(options)
    transport = transport_type(simulation, reverse, config_type(**fields))
    return simulation, transport


def run_until(simulation, until):
    while simulation.events and simulation.events[0][0] <= until:
        simulation.now, _, callback, arguments = heappop(simulation.events)
        callback(*arguments)
    simulation.now = until


def submit(transport, frame, received, channel=0):
    transport.submit_channel(channel, len(frame), max(0, len(frame) - 66), received.append,
                             frame=frame, deliver_frame=True)


def short_frame(payload=0, flags=0x12):
    original = tcp_profile_frame(payload_bytes=payload, flags=flags, identification=9)
    header = bytearray(original[:66])
    header[34:38] = b"\xc0\x01\x01\xbb"
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, original[66:])


def symbol(serial, frame, channel=0, symbol_bytes=1460):
    body = CHANNEL_HEADER.pack(channel, serial & 65535) + b"\x02" + len(frame).to_bytes(2, "big") + frame
    return body + bytes(symbol_bytes - len(body))


@pytest.mark.parametrize("kind", ["aligned", "wire"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("hole", [0, 1], ids=["earlier-context", "earlier-data"])
def test_short_frame_crosses_channel_hole_without_advancing_contiguous_credit(kind, reverse, hole):
    simulation, transport = make_transport(kind, reverse)
    departures = count()
    simulation.links[reverse][0].erasures.lost = lambda: next(departures) == hole
    first = tcp_profile_frame(payload_bytes=1448)
    short = short_frame()
    last = tcp_profile_frame(payload_bytes=1448, sequence=1448, identification=1)
    received = []
    submit(transport, first, received)
    previous = transport.channel_codecs[0].context
    submit(transport, short, received)
    assert transport.channel_codecs[0].context == previous
    submit(transport, last, received)
    assert transport.context_records == 1
    assert transport.independent_short_records == 1
    assert len(transport.sources) == 4
    assert transport.source_payloads[2] == symbol(2, short)
    run_until(simulation, .2)

    assert received == [short]
    assert transport.receiver.expected[0] == transport.channel_completed[0] == hole
    assert transport.receiver.early_delivered == {(0, 2)}
    assert transport.receiver.early_release_count == 1
    assert transport.base == transport.received_prefix == hole
    assert hole not in transport.decoder.known
    assert len(transport.pending) == 4 - hole
    assert set(transport.callbacks) == {(0, 1), (0, 3)}
    assert transport.receiver.codecs[0].context == (None if hole == 0 else first[:66])

    transport._repair(True)
    run_until(simulation, .4)
    assert received == [short, first, last]
    assert transport.base == transport.received_prefix == len(transport.sources) == 4
    assert transport.channel_completed[0] == transport.receiver.expected[0] == 4
    assert transport.receiver.codecs[0].context == last[:66]
    assert not transport.receiver.early_delivered and not transport.callbacks
    assert transport.receiver.early_release_count == 1
    assert transport.recovered_symbols == 1
    assert simulation.wire[reverse]["source"] == sum(
        transport.source_header + source.size for source in transport.sources)
    assert simulation.wire[reverse]["repair"] > 0
    assert simulation.wire[not reverse]["feedback"] > 0
    assert simulation.erasures[reverse]["source"] == 1
    assert transport.delivered_bytes == len(first) + len(short) + len(last)


@pytest.mark.parametrize("kind", ["aligned", "wire"])
@pytest.mark.parametrize("independent", [False, True])
def test_receive_reordering_keeps_context_and_respects_global_ordered_control(kind, independent):
    simulation, transport = make_transport(kind, independent_delivery=independent)
    send = simulation.send
    source_number = count()

    def reorder(reverse, size, packet_kind, receive):
        if packet_kind == "source" and next(source_number) == 0:
            original_receive = receive
            receive = lambda: simulation.at(simulation.now + .12, original_receive)
        return send(reverse, size, packet_kind, receive)

    simulation.send = reorder
    first = tcp_profile_frame(payload_bytes=1448)
    short = short_frame()
    last = tcp_profile_frame(payload_bytes=1448, sequence=1448, identification=1)
    received = []
    for frame in (first, short, last):
        submit(transport, frame, received)
    run_until(simulation, .1)
    assert received == ([short] if independent else [])
    assert transport.receiver.early_release_count == int(independent)
    assert transport.channel_completed[0] == 0
    run_until(simulation, .3)
    assert received == ([short, first, last] if independent else [first, short, last])
    assert transport.channel_completed[0] == 4
    assert transport.receiver.codecs[0].context == last[:66]
    assert not transport.receiver.early_delivered
    assert not transport.callbacks


@pytest.mark.parametrize("kind", ["aligned", "wire"])
@pytest.mark.parametrize("threshold", [0, 128])
def test_existing_full_record_fallback_remains_ordered_when_option_is_disabled(kind, threshold):
    simulation, transport = make_transport(kind, threshold=threshold)
    departures = count()
    simulation.links[False][0].erasures.lost = lambda: next(departures) == 0
    first = tcp_profile_frame(payload_bytes=1448)
    opaque = bytes(range(80))
    received = []
    submit(transport, first, received)
    submit(transport, opaque, received)
    run_until(simulation, .2)
    assert received == ([opaque] if threshold else [])
    assert transport.source_payloads[2] == symbol(2, opaque)
    assert transport.channel_completed[0] == 0
    transport._repair(True)
    run_until(simulation, .4)
    assert received == ([opaque, first] if threshold else [first, opaque])
    assert not transport.callbacks


@pytest.mark.parametrize("flags,payload", [(0x02, 0), (0x10, 0), (0x12, 0), (0x14, 0), (0x18, 64)])
@pytest.mark.parametrize("erase_three", [False, True])
def test_generic_short_frame_copies_deliver_identical_distinct_records_once(flags, payload, erase_three):
    simulation, transport = make_transport(
        "wire", reverse=True, threshold=130, short_source_max_bytes=136, short_source_copies=4)
    erasures = iter([erase_three, erase_three, erase_three, False] * 2)
    simulation.links[True][0].erasures.lost = lambda: next(erasures, False)
    received = []
    frame = short_frame(payload, flags)
    submit(transport, frame, received)
    submit(transport, frame, received)
    run_until(simulation, .2)
    assert received == [frame, frame]
    assert transport.independent_short_records == len(transport.sources) == 2
    assert transport.context_records == 0
    assert transport.channel_codecs[0].context is None
    assert transport.receiver.codecs[0].context is None
    assert transport.wire_repeated_source_packets == 6
    assert transport.base == transport.channel_completed[0] == 2
    assert transport.receiver.early_release_count == 0
    assert not transport.callbacks and not transport.receiver.early_delivered
    assert simulation.datagrams[True]["source"] == 8
    assert simulation.wire[True]["source"] == 8 * (26 + 6 + len(frame))
    assert simulation.erasures[True]["source"] == (6 if erase_three else 0)


def test_short_kind2_actual_wire_parses_without_context_and_retains_framing_cost():
    simulation, transport = make_transport("wire")
    sent = []
    send = transport._send_wire

    def capture(wire, packet_kind, header_bytes):
        sent.append((wire, packet_kind, header_bytes))
        return send(wire, packet_kind, header_bytes)

    transport._send_wire = capture
    frame = short_frame()
    received = []
    submit(transport, frame, received)
    assert len(sent) == 1
    wire, packet_kind, header_bytes = sent[0]
    packet = decode_packet(wire, 0, "raw_ipv4_crc32")
    assert packet.kind == packet_kind == "source" and packet.index == 0
    assert packet.payload == symbol(0, frame)[:72]
    assert header_bytes == 2 and len(wire) + 20 == 98
    assert transport.submitted_bytes == transport.sent_bytes == 72
    assert transport.source_record_bytes == 69 and transport.profile_context_bytes == 0
    run_until(simulation, .2)
    assert received == [frame]
    assert simulation.wire[False]["source"] == 98
    assert simulation.wire[True]["feedback"] == 40


def test_receiver_tombstones_reject_conflicts_and_duplicate_new_source_ids():
    receiver = AlignedRecordReceiver(1460, 128)
    frame = short_frame()
    assert receiver.receive(1, symbol(1, frame)) == [(0, 1, frame)]
    assert receiver.expected[0] == 0
    assert receiver.receive(1, symbol(1, frame)) == []
    assert receiver.receive(2, symbol(1, frame)) == []
    assert receiver.early_release_count == 1
    with pytest.raises(ValueError, match="conflicting aligned record"):
        receiver.receive(3, symbol(1, short_frame(flags=0x10)))
    assert receiver.complete[0][1] == b"\x02\x00\x42" + frame
    assert receiver.receive(4, symbol(0, frame)) == [(0, 0, frame)]
    assert receiver.expected[0] == 2 and not receiver.early_delivered
    assert receiver.early_release_count == 1
    assert receiver.receive(5, symbol(1, frame)) == []


def test_receiver_wrap_stale_and_half_window_do_not_advance_holes():
    receiver = AlignedRecordReceiver(1460, 128)
    receiver.expected[3] = 65534
    frame = short_frame()
    assert receiver.receive(0, symbol(65535, frame, 3)) == [(3, 65535, frame)]
    assert receiver.receive(1, symbol(65536, frame, 3)) == [(3, 65536, frame)]
    assert receiver.expected[3] == 65534
    assert receiver.receive(2, symbol(65533, frame, 3)) == []
    assert receiver.receive(3, symbol(65534 + 32768, frame, 3)) == []
    assert receiver.receive(4, symbol(65534, frame, 3)) == [(3, 65534, frame)]
    assert receiver.expected[3] == 65537 and not receiver.early_delivered
    assert receiver.early_release_count == 2


@pytest.mark.parametrize("kind", ["aligned", "wire"])
def test_early_release_does_not_open_channel_half_window(kind):
    simulation, transport = make_transport(kind)
    transport.channel_sequences[0] = 32766
    frame = short_frame()
    received = []
    submit(transport, frame, received)
    run_until(simulation, .1)
    assert received == [frame]
    assert transport.channel_completed[0] == transport.receiver.expected[0] == 0
    before = len(transport.sources)
    with pytest.raises(ValueError, match="serial-number window"):
        submit(transport, frame, received)
    assert len(transport.sources) == before
    assert transport.channel_sequences[0] == 32767


@pytest.mark.parametrize("invalid", [-1, True, False, None, 1.5, "128", 65533])
@pytest.mark.parametrize("config_type", [AlignedRecordConfig, CompactWireConfig])
def test_independent_short_threshold_is_a_validated_integer(invalid, config_type):
    with pytest.raises(ValueError, match="independent short frame threshold"):
        config_type(independent_short_frame_bytes=invalid)


@pytest.mark.parametrize("kind", ["aligned", "wire"])
def test_threshold_must_fit_one_symbol_and_oversized_frames_keep_fallback(kind):
    with pytest.raises(ValueError, match="fit one protected symbol"):
        make_transport(kind, threshold=1455)
    simulation, transport = make_transport(kind, threshold=1454)
    received = []
    for length in (1454, 1455):
        submit(transport, b"x" * length, received)
    assert transport.independent_short_records == 1
    assert transport.sources[0].size == 1460
    assert transport.fragmented_records == 1
    run_until(simulation, .2)
    assert received == [b"x" * 1454, b"x" * 1455]
    with pytest.raises(ValueError, match="fit one protected symbol"):
        make_transport("aligned", mtu=576, threshold=531)


@pytest.mark.parametrize("damage", ["length", "padding"])
def test_invalid_full_record_never_releases_or_sets_tombstone(damage):
    receiver = AlignedRecordReceiver(1460, 128)
    data = bytearray(symbol(1, short_frame()))
    if damage == "length":
        data[4:6] = b"\xff\xff"
    else:
        data[-1] = 1
    with pytest.raises(ValueError):
        receiver.receive(1, bytes(data))
    assert receiver.expected[0] == 0
    assert not receiver.early_delivered and not receiver.complete[0]


@pytest.mark.parametrize("loss", [0, .15])
def test_normal_mux_tcp_and_fresh_probe_share_independent_short_policy(loss):
    config = CompactWireConfig(
        repair_ratio=.25, feedback_ms=1, tail_repair_delay_ms=15,
        encapsulation="raw_ipv4_crc32", independent_short_frame_bytes=130,
        short_source_max_bytes=136, short_source_copies=3, trim_repair_padding=True)
    factory = partial(MuxTCP, compact_config=config, ack_copies=1,
                      ack_coalesce_ms=.25, acknowledged_segment_slow_start=True)
    simulation = UnifiedMuxMultiFlow(
        Scenario(20, loss), Traffic(duration_s=.8, drain_s=3, payload_bytes=64,
            frame_bytes=130, window_bytes=32768, frame_interval_ms=1,
            ack_delay_ms=1, ack_every=2),
        (PathConfig(100, 10),), Strategy("short mux fixture", mode="tcp", tcp_rto_min_ms=1000),
        42, 2, compact_config=config, channel_count=1, simulation_factory=factory)
    probe = UnifiedMuxHandshakeProbe(
        simulation, SYNProbeConfig(interval_ms=50, timeout_ms=500, initial_rto_ms=100),
        start_s=.05, wait_for_stability=False)
    simulation.run()
    assert probe.probes and all(item.completed_at is not None for item in probe.probes)
    assert simulation.mux_confirmed
    assert all(flow.tcp_acked == flow.tcp_received == len(flow.sent_times) for flow in simulation.flows)
    for reverse, transport in enumerate((simulation.shared_forward, simulation.shared_reverse)):
        assert transport.context_records == 0
        assert transport.independent_short_records == transport.frame_count == len(transport.sources)
        assert simulation.mux.channel_ids[reverse] == {0}
        assert transport.wire_repeated_source_packets == 2 * len(transport.sources)
        assert transport.base == len(transport.sources)
        assert not transport.callbacks and not transport.receiver.early_delivered
        assert simulation.mux.submitted_frames[reverse] == simulation.mux.delivered_frames[reverse]
