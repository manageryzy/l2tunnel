"""Real QUIC connection tests with deterministic simulated link erasures."""

import csv
from dataclasses import replace

import pytest

pytest.importorskip("aioquic")

from l2tunnel_sim.config import Experiment, PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure, run_experiment
from l2tunnel_sim.quic import QUIC


def connection(*, loss=0, cc="cubic", mtu=1500, frames=1):
    return QUIC(Scenario(20, loss, mtu=mtu),
                Traffic(duration_s=.001, drain_s=2, window_bytes=1448 * frames),
                (PathConfig(),), Strategy("QUIC L2", mode="quic", tcp_cc=cc), 42)


@pytest.mark.parametrize("cc", ["reno", "cubic"])
def test_quic_delivers_full_ethernet_frame_over_actual_encrypted_packets(cc):
    sim = connection(cc=cc).run()
    row = measure(sim)
    assert all(sim.handshakes)
    assert row["transport"] == "quic_l2"
    assert row["tcp_delivered_frames"] == row["tcp_acked_frames"] == 1
    assert row["forward_l2_bytes"] == 1514
    assert row["forward_wire_bytes"] > 1514
    assert row["forward_retry_bytes"] == 0
    assert row["quic_retransmitted_stream_bytes"] == 0
    assert row["quic_cwnd_bytes"] > 0
    assert row["frame_p50_ms"] < 11  # One complete L2 record fits the receive credit.
    assert not sim.forward.pending


@pytest.mark.parametrize("reverse", [False, True])
def test_quic_recovers_data_or_ack_loss_without_duplicate_delivery(reverse):
    sim = connection(frames=10)
    decisions = iter([True, True, False] + [False] * 1000)
    sim.links[reverse][0].erasures.lost = lambda: next(decisions)
    row = measure(sim.run())
    assert row["tcp_delivered_frames"] == row["tcp_acked_frames"] == 10
    assert row["forward_l2_bytes"] == 10 * 1514
    if not reverse:
        assert row["quic_retransmitted_stream_bytes"] > 0
        assert row["forward_retry_bytes"] > 0


def test_total_quic_loss_leaves_visible_unfinished_records():
    row = measure(connection(loss=1).run())
    assert row["tcp_delivered_frames"] == 0
    assert row["forward_unconfirmed_bytes"] == 1448
    assert row["forward_wire_bytes"] > 0


def test_quic_pmtu_and_byte_accounting_are_reproducible():
    first = measure(connection(mtu=1280, loss=.2, frames=10).run())
    second = measure(connection(mtu=1280, loss=.2, frames=10).run())
    assert first == second
    for direction in ("forward", "reverse"):
        assert first[direction + "_wire_bytes"] == sum(
            first[f"{direction}_{kind}_bytes"] for kind in ("source", "repair", "retry", "feedback")
        )


def test_quic_runs_through_toml_experiment_export(tmp_path):
    experiment = replace(Experiment(), replications=1, rtt_ms=(20,), loss_rates=(0,),
                         traffic=Traffic(duration_s=.001, drain_s=.2, window_bytes=1448),
                         strategies=(Strategy("QUIC", mode="quic"),))
    run_experiment(experiment, tmp_path / "result")
    rows = list(csv.DictReader((tmp_path / "result/replications.csv").open()))
    assert rows[0]["tcp_recovery"] == "aioquic"
    assert '"aioquic": "1.3.0"' in (tmp_path / "result/experiment.json").read_text()
    with pytest.raises(ValueError, match="MTU"):
        replace(experiment, mtus=(1200,))
