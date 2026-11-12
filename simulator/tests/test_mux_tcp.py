"""Exercise ordinary TCP data and fresh probes through the common duplex mux."""

import importlib
from pathlib import Path

import pytest

from l2tunnel_sim.compact import tcp_profile_frame
from l2tunnel_sim.mux import frame_tuple
from l2tunnel_sim.mux_tcp import bulk_connection_frame
from test_tcp_syn_probe import case


@pytest.fixture
def study(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    return importlib.import_module("aggregate_ack_deadlines")


def mux_case(channels=16, *, loss=0):
    task = case(duration=1.2, loss=loss)
    task["profile"].update(flow_count=16, window_bytes=1048576, ack_aggregation=False,
                           ack_copies=1, mux=dict(channels=channels))
    task["profile"]["compact"].update(short_source_max_bytes=128, short_source_copies=4)
    task["profile"]["tcp_syn_probe"].update(interval_ms=10, timeout_ms=200, reverse_copies=1)
    return task


def test_bulk_frames_have_distinct_correct_bidirectional_tuples():
    frame = tcp_profile_frame(payload_bytes=1448)
    tuples = []
    for port in range(40000, 40016):
        forward = frame_tuple(bulk_connection_frame(frame, port, False))
        reverse = frame_tuple(bulk_connection_frame(frame, port, True))
        assert forward == tuple(reversed(reverse))
        assert forward[0][1] == port and forward[1][1] == 443
        tuples.append(forward)
    assert len(set(tuples)) == 16


@pytest.mark.parametrize("channels", [1, 4, 16])
@pytest.mark.parametrize("loss", [0, .15])
def test_normal_entry_shares_both_directions_and_channel_pool(study, channels, loss):
    row = study.execute(mux_case(channels, loss=loss))
    assert row["transport"] == "unified_duplex_mux_inner_tcp"
    assert row["mux_channel_count"] == channels
    assert row["tcp_syn_probe_steady_state_reached"]
    assert row["tcp_syn_ping_completed"] > 16
    assert row["fully_confirmed"] and row["mux_both_directions_confirmed"]
    assert row["mux_endpoint_records_pending"] == 0
    assert row["tcp_syn_probe_all_flushed"]
    assert not row["tcp_syn_probe_dispatch_rejections"]
    assert set(row["tcp_syn_probe_channels_used"]) <= set(range(channels))
    for direction in ("forward", "reverse"):
        metrics = row["mux_" + direction]
        assert set(metrics["channel_ids"]) <= set(range(channels))
        assert metrics["submitted_frames"] == metrics["admitted_frames"] == metrics["delivered_frames"]
        assert metrics["queued_frames"] == metrics["queued_bytes"] == 0
    assert row["mux_forward"]["submitted_frames"] == (row["offered_frames"]
        + row["tcp_retransmissions"] + row["tcp_syn_probe_forward_frames"])
    assert row["mux_reverse"]["submitted_frames"] == (row["ack_transmitted"]
        + row["tcp_syn_probe_reverse_submitted_frames"])
    prefix = "tcp_syn_ping_measurement_"
    assert row[prefix + "forward_mbps"] <= 100 + 1e-6
    assert row[prefix + "reverse_mbps"] <= 10 + 1e-6


@pytest.mark.parametrize("policy", ["probe_copies", "ack_copies", "separate_aggregator"])
def test_unified_mode_rejects_separate_control_protection(study, policy):
    task = mux_case()
    if policy == "probe_copies":
        task["profile"]["tcp_syn_probe"]["reverse_copies"] = 4
    elif policy == "ack_copies":
        task["profile"]["ack_copies"] = 4
    else:
        task["profile"]["ack_aggregation"] = True
    with pytest.raises(ValueError):
        study.execute(task)


def test_plan_requires_actual_unified_mux_within_channel_limit(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    runner = importlib.import_module("tcp_syn_regression")
    task = mux_case()
    task.update(run_id=1, replication=1)
    plan = dict(max_l2_channels=16, tasks=[task])
    assert runner.validate_tasks(plan) == [task]
    task["profile"]["mux"]["channels"] = 17
    with pytest.raises(ValueError, match="unified mux"):
        runner.validate_tasks(plan)
    del task["profile"]["mux"]
    with pytest.raises(ValueError, match="unified mux"):
        runner.validate_tasks(plan)


@pytest.mark.parametrize("mapping", ["crc32", "connection_round_robin"])
def test_packed_mux_rejects_reserved_channel_at_construction(study, mapping, monkeypatch):
    task = mux_case(256)
    task["profile"]["mux"]["mapping"] = mapping
    task["profile"]["compact"]["pack_sources_max_delay_ms"] = .5

    def unexpected_flow_creation(*args, **kwargs):
        pytest.fail("invalid packed channel count reached flow construction")

    monkeypatch.setattr(study.ObservedMuxTCP, "__init__", unexpected_flow_creation)
    with pytest.raises(ValueError, match="unified mux channel_count.*255"):
        study.execute(task)


@pytest.mark.parametrize("packed,channels", [(True, 255), (False, 256)])
def test_mux_channel_limit_preserves_valid_end_to_end_delivery(study, packed, channels):
    task = mux_case(channels)
    task["profile"]["compact"]["pack_sources_max_delay_ms"] = .5 if packed else 0
    row = study.execute(task)
    assert row["mux_channel_count"] == channels
    assert row["fully_confirmed"] and row["mux_both_directions_confirmed"]
    assert row["tcp_syn_probe_all_flushed"]
    assert row["tcp_syn_ping_completed"] > 16
    assert row["mux_endpoint_records_pending"] == 0


def test_normal_entry_supports_generic_connection_rotation(study):
    task = mux_case(16, loss=.15)
    task['profile']['mux']['mapping'] = 'connection_round_robin'
    row = study.execute(task)
    assert row['mux_mapping'] == 'connection_round_robin'
    assert row['mux_assigned_connection_count'] > 16
    assert row['mux_forward']['channel_ids'] == list(range(16))
    assert row['mux_reverse']['channel_ids'] == list(range(16))
    assert row['mux_both_directions_confirmed']
    assert row['tcp_syn_probe_all_flushed']
    assert row['tcp_syn_ping_completed'] > 16
    assert row['mux_forward']['submitted_frames'] == (
        row['offered_frames'] + row['tcp_retransmissions'] + row['tcp_syn_probe_forward_frames'])
    assert row['mux_reverse']['submitted_frames'] == (
        row['ack_transmitted'] + row['tcp_syn_probe_reverse_submitted_frames'])


@pytest.mark.parametrize("copies,ack_every", [(4, 3), (3, 2)])
def test_generic_independent_short_frames_share_the_normal_mux(study, copies, ack_every):
    task = mux_case(16, loss=.15)
    profile = task["profile"]
    profile["mux"]["mapping"] = "connection_round_robin"
    profile["compact"].update(independent_short_frame_bytes=128, short_source_copies=copies)
    profile.update(ack_delay_ms=10, ack_every=ack_every)
    row = study.execute(task)
    assert row["mux_both_directions_confirmed"]
    assert row["tcp_syn_probe_all_flushed"]
    assert row["tcp_syn_ping_completed"] > 16
    assert row["mux_forward_independent_short_records"] == row["tcp_syn_probe_forward_frames"]
    assert row["mux_reverse_independent_short_records"] == row["mux_reverse"]["submitted_frames"]
    for direction in ("forward", "reverse"):
        assert row[f"mux_{direction}_early_short_pending"] == 0
        assert row[f"mux_{direction}_early_short_releases"] <= row[f"mux_{direction}_independent_short_records"]
        assert row[f"mux_{direction}_peak_outstanding_sources"] <= 8192
    assert row["mux_reverse"]["local_assignment_count"] == 0
    assert row["mux_reverse"]["learned_binding_count"] == row["mux_assigned_connection_count"]


@pytest.mark.parametrize("payload", [64, 256, 512, 1448])
def test_packed_sources_preserve_shared_mux_delivery_and_capacity(study, payload):
    task = mux_case(16, loss=.15)
    task["payload_bytes"] = payload
    profile = task["profile"]
    profile["mux"]["mapping"] = "connection_round_robin"
    profile["compact"].update(independent_short_frame_bytes=128,
        short_source_copy_scope="context_and_independent", pack_sources_max_delay_ms=.5)
    profile.update(ack_every=max(2, 4096 // payload), ack_coalesce_ms=2)
    row = study.execute(task)
    assert row["fully_confirmed"] and row["tcp_syn_probe_all_flushed"]
    assert row["tcp_syn_ping_completed"] > 16
    assert row["mux_channel_count"] == 16
    assert row["compact_wire_invalid_packets"] == 0
    for direction in ("forward", "reverse"):
        metrics = row["mux_" + direction]
        assert metrics["submitted_frames"] == metrics["admitted_frames"] == metrics["delivered_frames"]
        assert row[f"mux_{direction}_pending_pack_bytes"] == 0
        assert row[f"mux_{direction}_early_short_pending"] == 0
        assert row[f"mux_{direction}_peak_outstanding_sources"] <= 8192
        assert row[f"tcp_syn_ping_measurement_{direction}_mbps"] <= task[f"{direction}_mbps"] + 1e-6
    assert row["compact_wire_protected_sources"] <= row["mux_forward_independent_short_records"] + row["shared_context_records"]
    prefix = "tcp_syn_ping_measurement_"
    assert row["tcp_syn_ping_background_goodput_mbps"] * (1 + row[prefix + "extra_forward_ip_pct"] / 100) == pytest.approx(
        row[prefix + "forward_mbps"])
