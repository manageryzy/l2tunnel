"""Normal aggregate-study entry points, configurable ACK timers and framing."""

from pathlib import Path

import pytest

from l2tunnel_sim.aligned_records import AlignedRecordTransport
from l2tunnel_sim.compact_wire import CompactWireTransport


@pytest.fixture
def study(monkeypatch):
    pytest.importorskip("aioquic")
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    import aggregate_ack_deadlines
    return aggregate_ack_deadlines


def task(wire_format=None, loss=0):
    compact = dict(repair_ratio=.22, feedback_ms=1, feedback_packets=64, flush_ms=2,
                   repair_window_sources=128, global_repair_every=16, elide_payload_length=True)
    profile = dict(name="Aggregate study regression", ack_aggregation=True, compact=compact,
                   window_bytes=32768, payload_rate_mbps=10, ack_copies=2, ack_coalesce_ms=.25,
                   ack_batch_hold_ms=.5, rto_min_ms=1000, flow_count=4)
    if wire_format:
        profile["wire_format"] = wire_format
    if wire_format == "compact_wire":
        compact.update(encapsulation="raw_ipv4_crc32", packed_predictive_records=True)
        profile["ack_delay_ms"] = 1
    return dict(profile=profile, payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
                rtt_ms=20, loss_rate=loss, loss_model="iid", mtu=1500, duration_s=.08,
                warmup_s=.01, drain_s=3, seed=42)


@pytest.mark.parametrize("wire_format", [None, "aligned_records", "compact_wire"])
@pytest.mark.parametrize("loss", [0, .15])
def test_normal_aggregate_study_confirms_frames_and_exports_wire_metrics(study, wire_format, loss):
    case = task(wire_format, loss)
    sim = study.make_simulation(case)
    expected_transport = CompactWireTransport if wire_format == "compact_wire" else AlignedRecordTransport
    assert type(sim.shared_forward) is expected_transport
    assert all(flow.traffic.ack_delay_ms == (1 if wire_format == "compact_wire" else 10)
               and flow.traffic.ack_every == 2 for flow in sim.flows)
    row = study.execute(case)
    assert row["fully_confirmed"]
    assert row["tcp_acked_frames"] == row["tcp_delivered_frames"] == row["offered_frames"]
    assert row["ack_batch_requested_wire_bytes"] == row["ack_batch_departed_wire_bytes"]
    assert row["ack_batch_submitted_records"] > 0
    assert row["ack_delay_ms"] == (1 if wire_format == "compact_wire" else 10)
    assert row["ack_every"] == 2
    if wire_format == "compact_wire":
        assert row["forward_encapsulation"] == "raw_ipv4_crc32"
        assert row["shared_packed_predictive_records"] > 0
        assert row["compact_wire_invalid_packets"] == 0
        assert row["compact_wire_crc_bytes"] > 0
    else:
        assert row["forward_encapsulation"] == "udp"
        assert row["shared_packed_predictive_records"] == 0
        assert row["compact_wire_invalid_packets"] is None


def test_explicit_ack_every_and_hold_reach_existing_implementations(study):
    case = task("compact_wire")
    case["profile"].update(ack_every=3, ack_batch_hold_ms=.75)
    sim = study.make_simulation(case)
    assert all(flow.traffic.ack_every == 3 for flow in sim.flows)
    assert sim.ack_aggregate.hold_ms == .75


def test_unaggregated_profile_preserves_baseline_delegation(study, monkeypatch):
    case = task("compact_wire")
    case["profile"]["ack_aggregation"] = False
    calls = []
    sentinel = object()
    monkeypatch.setattr(study.baseline, "make_simulation", lambda value: calls.append(value) or sentinel)
    assert study.make_simulation(case) is sentinel
    assert calls == [case]


def test_unknown_aggregate_wire_format_is_rejected(study):
    with pytest.raises(ValueError, match="wire format"):
        study.make_simulation(task("unknown"))


@pytest.mark.parametrize("trim", [False, True])
@pytest.mark.parametrize("copies", [3, 4])
@pytest.mark.parametrize("encoding", ["batch_delta", "batch_varint"])
def test_batch_local_delta_encoding_reaches_complete_tcp_study(study, trim, copies, encoding):
    case = task("compact_wire", .15)
    case["profile"].update(ack_record_encoding=encoding, ack_copies=copies, distinct_flow_headers=True)
    case["profile"]["compact"]["trim_repair_padding"] = trim
    row = study.execute(case)
    assert row["fully_confirmed"]
    assert row["ack_record_encoding"] == encoding
    assert row["distinct_flow_headers"]
    assert sum(row["ack_batch_encoding_datagrams"].values()) == row["ack_batch_departed_datagrams"]
    assert row["ack_batch_full_equivalent_wire_bytes"] - row["ack_batch_requested_wire_bytes"] == row["ack_batch_saved_wire_bytes"]
    assert row["ack_batch_saved_wire_bytes"] > 0
    assert (row["compact_wire_trimmed_repair_bytes"] > 0) == trim


@pytest.mark.parametrize("dictionary", [False, True])
def test_timestamp_pair_dictionary_reaches_original_tcp_cohort(study, dictionary):
    case = task("compact_wire", .15)
    case.update(duration_s=.3, warmup_s=.02)
    case["profile"].update(flow_count=128, window_bytes=4 * 1048576, payload_rate_mbps=80.05,
                           ack_copies=4, ack_record_encoding="batch_varint", distinct_flow_headers=True)
    case["profile"]["compact"].update(trim_repair_padding=True, timestamp_pair_dictionary=dictionary)
    row = study.execute(case)
    assert row["fully_confirmed"]
    assert row["tcp_acked_frames"] == row["offered_frames"]
    assert (row["shared_timestamp_pair_records"] > 0) == dictionary
    assert (row["shared_timestamp_pair_saved_bytes"] > 0) == dictionary
    assert row["shared_timestamp_pair_candidates"] >= row["shared_timestamp_pair_records"]
