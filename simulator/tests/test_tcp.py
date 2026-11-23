"""Packet-level reference cases for direct TCP and congestion recovery."""

import csv
from dataclasses import replace

import pytest

from l2tunnel_sim.config import Experiment, PathConfig, Scenario, Strategy, Traffic, load_experiment
from l2tunnel_sim.experiment import measure, run_experiment
from l2tunnel_sim.tcp import PlainTCP


def connection(*, packets=1, drain=0.1, loss=0, cc="cubic", mtu=1500, **options):
    traffic = Traffic(duration_s=0.001, drain_s=drain, frame_bytes=166,
                      payload_bytes=100, window_bytes=packets * 100, ack_every=1)
    strategy = Strategy("Direct", mode="tcp", tcp_cc=cc, **options)
    return PlainTCP(Scenario(20, loss, mtu=mtu), traffic, (PathConfig(),), strategy, 42)


def drop(sim, reverse, indices):
    decisions = (index in indices for index in range(1000))
    sim.links[reverse][0].erasures.lost = lambda: next(decisions)


def test_direct_packet_and_ack_have_only_ip_tcp_overhead():
    sim = connection().run()
    result = measure(sim)
    assert result["forward_source_datagrams"] == 1
    assert result["forward_source_bytes"] == 152
    assert result["reverse_source_bytes"] == 52
    assert result["forward_feedback_bytes"] == 0
    assert result["forward_repair_bytes"] == 0
    assert result["tcp_acked_frames"] == 1
    assert result["frame_p50_ms"] == pytest.approx(10 + 152 / 12500)
    assert result["tcp_payload_efficiency"] == pytest.approx(100 / 152)


def test_first_data_loss_is_recovered_by_tcp_timeout_after_source_cutoff():
    sim = connection(drain=1.1)
    drop(sim, False, {0})
    result = measure(sim.run())
    assert result["tcp_timeouts"] == 1
    assert result["tcp_retransmissions"] == 1
    assert result["tcp_fast_retransmits"] == 0
    assert result["tcp_acked_frames"] == 1
    assert result["tcp_goodput_mbps"] == 0
    assert sim.srtt == pytest.approx(0.0200416)  # Echo identifies the retransmission.


def test_lost_ack_is_recovered_without_duplicate_application_delivery():
    sim = connection(drain=1.1)
    drop(sim, True, {0})
    result = measure(sim.run())
    assert result["tcp_timeouts"] == 1
    assert result["forward_retry_datagrams"] == 1
    assert result["reverse_source_datagrams"] == 2
    assert result["released_frames"] == result["tcp_acked_frames"] == 1


@pytest.mark.parametrize("missing", [{1}, {1, 3}])
@pytest.mark.parametrize("cc", ["reno", "cubic"])
def test_duplicate_and_partial_acks_recover_losses_before_timeout(missing, cc):
    sim = connection(packets=10, drain=0.15, cc=cc)
    drop(sim, False, missing)
    result = measure(sim.run())
    assert result["tcp_fast_retransmits"] == 1
    assert result["tcp_timeouts"] == 0
    assert result["tcp_retransmissions"] == len(missing)
    assert result["tcp_acked_frames"] == 10
    assert not sim.in_recovery
    assert sim.forward.pending_bytes == 0


def test_repeated_timeouts_exponentially_back_off():
    sim = connection(drain=7.1, loss=1).run()
    result = measure(sim)
    assert result["forward_source_datagrams"] == 1
    assert result["tcp_timeouts"] == result["forward_retry_datagrams"] == 3
    assert result["tcp_delivered_frames"] == 0
    assert result["forward_unconfirmed_bytes"] == 100
    assert sim.rto == 8
    assert sim.cwnd == 1


def test_fast_recovery_requires_progress_beyond_the_previous_exclusive_end():
    sim = connection(packets=40)
    sim.produce()
    for _ in range(3):
        sim.on_ack(0)
    assert sim.tcp_fast_retransmits == 1
    previous_end = sim.recover
    sim.on_ack(previous_end)
    assert sim.forward.pending and not sim.in_recovery
    for _ in range(3):
        sim.on_ack(previous_end)
    assert sim.tcp_fast_retransmits == 1
    sim.on_ack(previous_end + 1)
    for _ in range(3):
        sim.on_ack(previous_end + 1)
    assert sim.tcp_fast_retransmits == 2


def test_rtt_estimator_matches_rfc6298_updates():
    sim = connection()
    sim.update_rtt(0.1)
    assert sim.srtt == pytest.approx(0.1)
    assert sim.rttvar == pytest.approx(0.05)
    assert sim.rto == pytest.approx(0.3)
    sim.update_rtt(0.14)
    assert sim.srtt == pytest.approx(0.105)
    assert sim.rttvar == pytest.approx(0.0475)
    assert sim.rto == pytest.approx(0.295)


def test_cubic_estimate_and_target_bound_match_rfc9438():
    sim = connection(packets=100)
    sim.cwnd, sim.ssthresh, sim.cubic_max = 10.0, 5.0, 20.0
    sim.cubic_prior = 20
    sim.srtt = 0.1
    sim.increase_window(2)
    assert sim.cwnd == pytest.approx(10 + (3 * 0.3 / 1.7) * 2 / 10)
    sim.cwnd, sim.cubic_epoch, sim.cubic_max = 10, 0, 10
    sim.cubic_k, sim.cubic_estimate, sim.cubic_prior = 0, 10, 100
    sim.now = 100
    sim.increase_window(1)
    assert sim.cwnd == pytest.approx(10.5)


def test_direct_tcp_adapts_segment_size_to_pmtu():
    traffic = Traffic(duration_s=0.001, drain_s=0.1, window_bytes=1448, ack_every=1)
    sim = PlainTCP(Scenario(20, 0, mtu=1280), traffic, (PathConfig(),),
                   Strategy("TCP", mode="tcp"), 42).run()
    assert sim.traffic.payload_bytes == 1228
    assert sim.wire[False]["source"] == 1280
    assert len(sim.sent_times) == sim.tcp_acked == 1


def test_direct_tcp_uses_only_the_selected_path():
    paths = (PathConfig(), PathConfig(forward_mbps=40, rtt_factor=1.4))
    sim = PlainTCP(Scenario(70, 0), Traffic(duration_s=0.001, drain_s=0.2), paths,
                   Strategy("Path 2", mode="tcp", tcp_path=1), 42).run()
    assert len(sim.links[False]) == 1
    assert sim.links[False][0].rtt == pytest.approx(0.098)
    assert sim.links[False][0].bytes_per_s == 5000000


def test_paced_slow_start_remembers_cwnd_use_across_ack_bursts():
    traffic = Traffic(duration_s=3, drain_s=.2, window_bytes=4 * 1048576,
                      frame_interval_ms=1448 * 8 / 80000)
    sim = PlainTCP(Scenario(70, 0), traffic, (PathConfig(),),
                   Strategy('Paced TCP', mode='tcp'), 42)
    samples = {}
    sim.at(2, lambda: samples.update(payload=sim.tcp_payload_bytes))
    sim.run()
    last_second_mbps = (sim.tcp_payload_bytes - samples['payload']) * 8 / 1e6
    assert last_second_mbps == pytest.approx(80, abs=.05)
    assert sim.cwnd > 500


def test_rate_limited_source_does_not_grow_an_unbounded_window():
    traffic = Traffic(duration_s=3, drain_s=.2, window_bytes=4 * 1048576,
                      frame_interval_ms=1448 * 8 / 1000)
    sim = PlainTCP(Scenario(70, 0), traffic, (PathConfig(),),
                   Strategy('Low-rate TCP', mode='tcp'), 42).run()
    assert sim.cwnd <= 20


def test_default_and_legacy_toml_and_export_support_direct_tcp(tmp_path):
    old = tmp_path / "old.toml"
    old.write_text('[[strategies]]\nname="Legacy ARQ"\n')
    assert load_experiment(old).strategies == (Strategy("Legacy ARQ"),)
    native = (Strategy("TCP", mode="tcp"), Strategy("ARQ"))
    experiment = replace(Experiment(), rtt_ms=(20,), loss_rates=(0,), replications=1,
                         traffic=Traffic(duration_s=0.001, drain_s=0.05, window_bytes=1448),
                         strategies=native)
    out = tmp_path / "result"
    run_experiment(experiment, out)
    with (out / "replications.csv").open() as stream:
        rows = list(csv.DictReader(stream))
    assert [row["transport"] for row in rows] == ["direct_tcp", "tunnel"]
    assert [row["tcp_controller"] for row in rows] == ["cubic", "fixed_window"]
    assert rows[0]["seed"] == rows[1]["seed"]
    assert "direct TCP and tunnel comparison" in (out / "report.html").read_text()
    with pytest.raises(ValueError, match="path index"):
        replace(experiment, strategies=(Strategy("Bad", mode="tcp", tcp_path=1),))


@pytest.mark.parametrize("options", [
    {"tcp_cc": "unknown"}, {"tcp_initial_cwnd": 0}, {"tcp_path": -1},
    {"tcp_rto_min_ms": 0}, {"tcp_rto_initial_ms": 100},
])
def test_invalid_tcp_configuration_is_rejected(options):
    with pytest.raises(ValueError):
        Strategy("Bad", mode="tcp", **options)


def test_karn_sampling_remains_available_without_an_echoed_timestamp():
    sim = connection()
    sim.produce()
    sim.forward.pending[0].attempts = 2
    sim.now = 0.1
    sim.on_ack(1)
    assert sim.srtt is None


def test_maximum_ip_mtu_preserves_full_l2_accounting():
    traffic = Traffic(duration_s=0.001, drain_s=0.1, frame_bytes=65535,
                      payload_bytes=65535, window_bytes=65535, ack_every=1)
    sim = PlainTCP(Scenario(20, 0, mtu=65535), traffic, (PathConfig(),),
                   Strategy("TCP", mode="tcp"), 42).run()
    assert sim.wire[False]["source"] == 65535
    assert sim.forward.delivered_bytes == 65535 + 14


def test_retransmission_queued_beyond_cutoff_has_no_completed_wire_count():
    traffic = Traffic(duration_s=0.001, drain_s=2.3, frame_bytes=166,
                      payload_bytes=100, window_bytes=100, ack_every=1)
    sim = PlainTCP(Scenario(20, 1), traffic, (PathConfig(forward_mbps=0.001),),
                   Strategy("TCP", mode="tcp"), 42).run()
    result = measure(sim)
    assert result["tcp_timeouts"] == 1
    assert result["tcp_retransmissions"] == result["forward_retry_datagrams"] == 0
