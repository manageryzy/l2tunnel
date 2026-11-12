"""Exercise optional compact wire framing through the normal TCP study entry."""

import importlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("shared_record_deadlines")


def task(wire_format, encapsulation=None):
    compact = dict(header_profile="tcp_delta", repair_ratio=.22, feedback_ms=1,
                   repair_window_sources=128, global_repair_every=16,
                   elide_payload_length=True, packed_predictive_records=True)
    if encapsulation is not None:
        compact["encapsulation"] = encapsulation
    profile = dict(name="Compact wire normal-entry fixture", wire_format=wire_format,
                   compact=compact, flow_count=4, window_bytes=4 * 1048576,
                   payload_rate_mbps=80.2, ack_coalesce_ms=.25, ack_copies=3,
                   rto_min_ms=1000)
    return dict(run_id=1, profile=profile, seed=20261110, replication=1,
                forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=0,
                loss_model="iid", mtu=1500, payload_bytes=1448,
                duration_s=.3, warmup_s=.05, drain_s=1)


@pytest.mark.parametrize("encapsulation", ("udp", "raw_ipv4_crc32"))
@pytest.mark.parametrize("trim", (False, True))
def test_optional_wire_format_uses_complete_original_tcp_cohort(encapsulation, trim):
    case = task("compact_wire", encapsulation)
    case["profile"]["compact"]["trim_repair_padding"] = trim
    row = study.execute(case)
    assert row["fully_confirmed"]
    assert row["tcp_delivered_frames"] == row["offered_frames"]
    assert row["tcp_acked_frames"] == row["offered_frames"]
    assert row["shared_packed_predictive_records"] > 0
    assert row["forward_encapsulation"] == encapsulation
    assert row["compact_wire_header_bytes"] > 0
    assert row["compact_wire_regular_repairs"] > 0
    assert (row["compact_wire_crc_bytes"] > 0) == (encapsulation == "raw_ipv4_crc32")
    assert row["compact_wire_retained_peak_symbols"] <= 8192
    assert row["compact_wire_invalid_packets"] == 0
    assert (row["compact_wire_trimmed_repair_bytes"] > 0) == trim
    assert row["forward_measurement_mbps"] <= 100
    assert row["reverse_measurement_mbps"] <= 10
    assert row["with_drain_tcp_all_segment_ack_rtt_p99_ms"] >= 70


def test_existing_aligned_entry_and_unknown_format_validation():
    row = study.execute(task("aligned_records"))
    assert row["fully_confirmed"]
    assert row["compact_wire_header_bytes"] is None
    invalid = task("missing-format")
    with pytest.raises(ValueError, match="unknown shared-record wire format"):
        study.make_simulation(invalid)


def test_explicit_ack_timers_reach_unaggregated_entry():
    case = task("compact_wire", "raw_ipv4_crc32")
    case["profile"].update(ack_delay_ms=1, ack_every=3)
    sim = study.make_simulation(case)
    assert all(flow.traffic.ack_delay_ms == 1 and flow.traffic.ack_every == 3 for flow in sim.flows)
    row = study.execute(case)
    assert row["fully_confirmed"]
    assert row["ack_delay_ms"] == 1 and row["ack_every"] == 3


@pytest.mark.parametrize("aggregate", [False, True])
@pytest.mark.parametrize("encapsulation", ["udp", "raw_ipv4_crc32"])
def test_short_source_protection_has_charged_copies_through_normal_tcp_entry(aggregate, encapsulation):
    from test_tcp_syn_probe import case
    from aggregate_ack_deadlines import execute
    fixture = case(loss=.15, duration=.6, copies=4)
    fixture["profile"]["ack_aggregation"] = aggregate
    fixture["profile"]["compact"].update(encapsulation=encapsulation,
        short_source_max_bytes=128, short_source_copies=4)
    row = execute(fixture)
    assert row["fully_confirmed"] and row["tcp_syn_probe_all_flushed"]
    assert row["tcp_syn_ping_offered"] == row["tcp_syn_ping_completed"] > 0
    assert row["compact_wire_protected_sources"] > 0
    assert row["compact_wire_repeated_source_packets"] == 3 * row["compact_wire_protected_sources"]
    assert row["compact_wire_repeated_source_bytes"] > 0
    assert row["forward_source_datagrams"] == (row["shared_source_count"]
                                              + row["compact_wire_repeated_source_packets"])
    assert row["compact_wire_peak_outstanding_sources"] <= 8192
    assert row["compact_wire_invalid_packets"] == 0
    assert row["forward_measurement_mbps"] <= fixture["forward_mbps"]
    assert row["reverse_measurement_mbps"] <= fixture["reverse_mbps"]
