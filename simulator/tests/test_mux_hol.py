"""Real coded-channel HOL and global credit apply equally to TCP and SYN frames."""

from heapq import heappop
from itertools import count

import pytest

from l2tunnel_sim.compact import CompactHeaderCodec, tcp_profile_frame
from l2tunnel_sim.compact_wire import CompactWireConfig, CompactWireTransport, GLOBAL_WINDOW
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.mux import DuplexMux, frame_tuple


def make_frame(port, *, probe=False, reverse=False, sequence=0):
    flags = (0x12 if reverse else 0x02) if probe else (0x10 if reverse else 0x18)
    payload = 0 if probe or reverse else 64
    original = tcp_profile_frame(payload_bytes=payload, flags=flags, sequence=sequence)
    header = bytearray(original[:66])
    header[34:38] = port.to_bytes(2, "big") + (443).to_bytes(2, "big")
    if reverse:
        header[:12] = header[6:12] + header[:6]
        header[26:34] = header[30:34] + header[26:30]
        header[34:38] = header[36:38] + header[34:36]
    dynamic = b"".join(header[area] for area in CompactHeaderCodec.dynamic)
    return CompactHeaderCodec._restore(header, dynamic, original[66:])


def make_mux():
    sim = Simulation(Scenario(70, 0), Traffic(duration_s=1, drain_s=1),
                     (PathConfig(100, 10),), Strategy("mux HOL fixture", mode="tcp"), 42)
    # No scheduled parity or tail can fill the deliberate gap before release.
    config = CompactWireConfig(repair_ratio=0, feedback_ms=1, tail_repair_delay_ms=10000)
    transports = tuple(CompactWireTransport(sim, reverse, config) for reverse in (False, True))
    return sim, transports, DuplexMux(sim, transports, channel_count=16)


def run_until(sim, until):
    while sim.events and sim.events[0][0] <= until:
        sim.now, _, callback, arguments = heappop(sim.events)
        callback(*arguments)
    sim.now = until


def matching_port(mux, first, *, same_channel):
    channel = mux.channel_for_frame(first)
    return next(port for port in range(40001, 41000)
                if (mux.channel_for_frame(make_frame(port)) == channel) == same_channel)


def assert_wire_accounting(sim, transport, reverse):
    assert sim.wire[reverse]["source"] == sum(
        transport.source_header + source.size for source in transport.sources)
    assert sim.datagrams[reverse]["source"] == len(transport.sources)
    assert sim.erasures[reverse]["source"] == 1
    assert sim.wire[not reverse]["feedback"] > 0
    assert transport.wire_invalid_packets == 0


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("lost_source", [0, 1], ids=["context-loss", "body-loss"])
@pytest.mark.parametrize("probe_first", [False, True], ids=["ordinary-before-probe", "probe-before-ordinary"])
@pytest.mark.parametrize("same_channel", [True, False], ids=["same-channel", "different-channel"])
def test_source_gap_blocks_same_channel_in_both_roles_and_directions(
        reverse, lost_source, probe_first, same_channel):
    sim, transports, mux = make_mux()
    transport = transports[reverse]
    departures = count()
    sim.links[reverse][0].erasures.lost = lambda: next(departures) == lost_source
    first = make_frame(40000, probe=probe_first, reverse=reverse)
    port = matching_port(mux, first, same_channel=same_channel)
    second = make_frame(port, probe=not probe_first, reverse=reverse)
    received = []
    for frame in (first, second):
        mux.register_endpoint(reverse, frame_tuple(frame), received.append)

    first_channel = mux.submit_frame(reverse, first)
    run_until(sim, .01)
    assert len(transport.sources) == 2
    second_channel = mux.submit_frame(reverse, second)
    assert (first_channel == second_channel) == same_channel
    run_until(sim, .2)

    assert len(transport.sources) == 4
    assert lost_source not in transport.decoder.known
    assert set(range(4)) - {lost_source} <= transport.decoder.known
    assert received == ([] if same_channel else [second])
    assert transport.context_records == 2
    assert transport.scheduled_repairs == transport.tail_repairs == 0
    assert mux.admitted_frames[reverse] == 2
    assert mux.delivered_frames[reverse] == (0 if same_channel else 1)
    assert mux.delivered_bytes[reverse] == sum(map(len, received))

    # An explicit, physically serialized parity packet repairs the one gap.
    transport._repair(True)
    assert received == ([] if same_channel else [second])
    run_until(sim, .4)
    assert received == ([first, second] if same_channel else [second, first])
    assert transport.base == transport.received_prefix == len(transport.sources)
    assert transport.recovered_symbols == 1
    assert transport.tail_repairs == 1
    assert mux.submitted_frames[reverse] == mux.admitted_frames[reverse] == mux.delivered_frames[reverse] == 2
    assert mux.submitted_bytes[reverse] == mux.delivered_bytes[reverse] == len(first) + len(second)
    assert not transport.callbacks and mux.flushed
    assert mux.channel_ids[reverse] == {first_channel, second_channel}
    assert_wire_accounting(sim, transport, reverse)


@pytest.mark.parametrize("reverse", [False, True])
def test_real_global_window_blocks_bulk_and_probe_retries_until_feedback(reverse):
    sim, transports, mux = make_mux()
    transport = transports[reverse]
    departures = count()
    sim.links[reverse][0].erasures.lost = lambda: next(departures) == 0
    frames = [make_frame(40000, reverse=reverse, sequence=index * 64)
              for index in range(GLOBAL_WINDOW - 1)]
    received = []
    mux.register_endpoint(reverse, frame_tuple(frames[0]), received.append)
    for frame in frames:
        mux.submit_frame(reverse, frame)
    run_until(sim, .8)

    assert len(transport.sources) == GLOBAL_WINDOW
    assert transport.base == 0
    assert transport.wire_peak_outstanding_sources == GLOBAL_WINDOW
    assert transport.decoder.known == set(range(1, GLOBAL_WINDOW))
    assert not transport.source_queue and mux.flushed
    assert received == []

    port = matching_port(mux, frames[0], same_channel=True)
    probe = make_frame(port, probe=True, reverse=reverse)
    mux.register_endpoint(reverse, frame_tuple(probe), received.append)
    # Simultaneous ordinary and probe retries enter the same FIFO. Duplicate
    # credit wakeups must neither admit either frame nor reorder their arrival.
    retries = [frames[0], probe, probe]
    for frame in retries:
        mux.submit_frame(reverse, frame)
    transport.capacity_callback()
    transport.capacity_callback()
    run_until(sim, .9)
    assert len(transport.sources) == GLOBAL_WINDOW
    assert mux.queued_frames[reverse] == len(retries)
    assert mux.admitted_frames[reverse] == len(frames)
    assert mux.window_stall_events[reverse] == 1
    assert received == []

    transport._repair(True)
    run_until(sim, 1.4)
    assert received == frames + retries
    assert mux.submitted_frames[reverse] == mux.admitted_frames[reverse] == mux.delivered_frames[reverse]
    assert mux.submitted_bytes[reverse] == mux.delivered_bytes[reverse] == sum(map(len, received))
    assert mux.queued_frames[reverse] == mux.queued_bytes[reverse] == 0
    assert mux.queue_wait_max_ms[reverse] >= 170
    assert transport.wire_peak_outstanding_sources == GLOBAL_WINDOW
    assert transport.base == transport.received_prefix == len(transport.sources)
    assert not transport.callbacks and not transport.source_queue
    assert mux.channel_ids[reverse] == {mux.channel_for_frame(frames[0])}
    assert transport.recovered_symbols == transport.tail_repairs == 1
    assert_wire_accounting(sim, transport, reverse)
