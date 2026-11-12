"""Independent-record reassembly and its interaction with cumulative TCP."""

from heapq import heappop

import pytest

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_unordered import (
    IndependentRecordARQ, IndependentRecordTCP,
    fragment_descriptor, parse_fragment_descriptor,
)
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic


def connection(*, ordered=False, loss=0, payload=1448, packets=10):
    return IndependentRecordTCP(
        Scenario(20, loss),
        Traffic(duration_s=.001, drain_s=4, payload_bytes=payload,
                frame_bytes=payload + 66, window_bytes=packets * payload),
        (PathConfig(),), Strategy("Independent records", mode="tcp", tcp_rto_min_ms=1000),
        42, ordered_delivery=ordered,
    )


def events_until(sim, until):
    while sim.events and sim.events[0][0] <= until:
        sim.now, _, callback, args = heappop(sim.events)
        callback(*args)


@pytest.mark.parametrize("ordered", [False, True])
def test_lossless_path_delivers_and_confirms_every_complete_frame(ordered):
    sim = connection(ordered=ordered).run()
    assert sim.tcp_received == sim.tcp_acked == len(sim.sent_times) == 10
    assert sim.forward.delivered_bytes == 10 * 1514
    assert sim.compact_forward.delivered_bytes == 10 * 1514
    assert sim.compact_forward.base == len(sim.compact_forward.sources)
    assert not sim.compact_forward.records


def test_later_record_can_reassemble_before_a_lost_earlier_record():
    sim = connection(payload=64)
    transport = sim.compact_forward
    seen = []
    transport.submit(130, 64, lambda: seen.append(0))
    transport.flush()
    transport.submit(130, 64, lambda: seen.append(1))
    transport.flush()
    later = transport.sources[1]
    transport._receive_source(later, transport.flights[1].serial)
    assert seen == [1]
    assert transport.received_prefix == 0
    assert transport.base == 0
    transport._receive_source(later, transport.flights[1].serial)
    assert seen == [1]
    transport._receive_source(transport.sources[0], transport.flights[0].serial)
    assert seen == [1, 0]


def test_split_frame_waits_for_every_fragment_after_out_of_order_arrival():
    sim = connection()
    transport = sim.compact_forward
    seen = []
    transport.submit(1514, 1448, lambda: seen.append(0))
    transport.flush()
    assert len(transport.sources) == 2
    transport._receive_source(transport.sources[1], transport.flights[1].serial)
    assert seen == []
    transport._receive_source(transport.sources[0], transport.flights[0].serial)
    assert seen == [0]
    assert transport.source_header == 44
    assert sum(source.size for source in transport.sources) == 1517


def test_ordered_control_uses_same_packet_bytes_and_withholds_later_record():
    sims = [connection(ordered=ordered, payload=64) for ordered in (False, True)]
    seen = [[], []]
    for index, sim in enumerate(sims):
        transport = sim.compact_forward
        for value in range(2):
            transport.submit(130, 64, lambda value=value, index=index: seen[index].append(value))
            transport.flush()
        transport._receive_source(transport.sources[1], transport.flights[1].serial)
    assert seen == [[1], []]
    assert [source.size for source in sims[0].compact_forward.sources] == [
        source.size for source in sims[1].compact_forward.sources]
    assert sims[0].compact_forward.source_header == sims[1].compact_forward.source_header == 44


def test_outer_out_of_order_records_still_wait_for_tcp_sequence_hole():
    sim = connection()
    sim.produce()
    transport = sim.compact_forward
    # Deliver later source packets directly while withholding source zero.
    for source in transport.sources[1:]:
        transport._receive_source(source, transport.flights[source.index].serial)
    assert transport.unordered_deliveries > 0
    assert sim.tcp_received == 0
    assert sim.tcp_buffer
    assert sim.datagrams[True]["source"] == 0  # ACKs are still in serialization.
    events_until(sim, .001)
    assert sim.datagrams[True]["source"] > 0


def test_invalid_context_dependent_profile_is_rejected():
    sim = connection()
    with pytest.raises(ValueError, match="full_l2"):
        IndependentRecordARQ(sim, False, CompactConfig(header_profile="tcp_delta"))


def test_fragment_descriptor_roundtrip_and_bounds():
    assert parse_fragment_descriptor(fragment_descriptor(42, 1454, 1517)) == (42, 1454, 1517)
    for args in ((2 ** 32, 0, 10), (1, 10, 10), (1, 0, 65536)):
        with pytest.raises(ValueError):
            fragment_descriptor(*args)
    with pytest.raises(ValueError):
        parse_fragment_descriptor(b"\x00")
