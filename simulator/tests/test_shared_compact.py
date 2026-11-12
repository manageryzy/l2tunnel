from functools import partial

import pytest

from l2tunnel_sim.compact import CompactConfig, tcp_profile_frame
from l2tunnel_sim.compact_ack import CoalescedACKTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.shared_compact import MultiplexedHeaderCodec, SharedCompactMultiFlow


def test_multiplexed_byte_codec_round_trips_independent_delta_contexts():
    original = [(i % 2, tcp_profile_frame(sequence=i * 1448, timestamp=i * 3,
                                         identification=i, payload_bytes=64 + i)) for i in range(12)]
    encoder, decoder = MultiplexedHeaderCodec(), MultiplexedHeaderCodec()
    encoded = b"".join(encoder.encode(channel, frame) for channel, frame in original)
    assert decoder.decode(encoded) == original
    assert len(encoder.channels) == 2


@pytest.mark.parametrize("channel", [-1, 65536, True, 1.5])
def test_multiplexed_byte_codec_rejects_invalid_channel(channel):
    with pytest.raises(ValueError, match="channel"):
        MultiplexedHeaderCodec().encode(channel, tcp_profile_frame())


def test_multiplexed_byte_codec_rejects_truncated_header_and_body():
    encoded = MultiplexedHeaderCodec().encode(0, tcp_profile_frame())
    for truncated in (encoded[:3], encoded[:-1]):
        with pytest.raises(ValueError, match="truncated"):
            MultiplexedHeaderCodec().decode(truncated)


@pytest.mark.parametrize("loss", [0, .15])
def test_shared_coding_normal_entry_point_charges_and_confirms_each_record(loss):
    config = CompactConfig(header_profile="tcp_delta", repair_ratio=.25, feedback_ms=1)
    factory = partial(CoalescedACKTCP, compact_config=config, ack_coalesce_ms=.25,
                      ack_copies=2, acknowledged_segment_slow_start=True)
    sim = SharedCompactMultiFlow(
        Scenario(20, loss, "iid"), Traffic(duration_s=.3, drain_s=3, frame_bytes=322,
                                           payload_bytes=256, window_bytes=32768, frame_interval_ms=1),
        (PathConfig(10, 10),), Strategy("shared", mode="tcp", tcp_rto_min_ms=1000), 42, 4,
        compact_config=config, simulation_factory=factory).run()
    row = sim.measurements()
    shared = sim.shared_forward
    assert row["tcp_acked_frames"] == row["tcp_delivered_frames"] == row["offered_frames"]
    assert shared.base == len(shared.sources) and shared.buffer_bytes == 0
    assert shared.source_record_bytes + shared.profile_context_bytes == shared.submitted_bytes
    assert shared.submitted_bytes > row["tcp_payload_bytes"] + shared.frame_count * 6
    assert all(flow.compact_forward.transport is shared for flow in sim.flows)
    assert all(sum(flow.datagrams[False].values()) == 0 for flow in sim.flows[1:])
    assert row["forward_datagrams"] == sum(sim.flows[0].datagrams[False].values())
    assert row["forward_wire_bytes"] >= shared.submitted_bytes
