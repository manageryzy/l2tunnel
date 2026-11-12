"""Regressions against accidental per-flow bandwidth and shared recovery state."""

from dataclasses import replace
from functools import partial

import pytest

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure, simulation_type
from l2tunnel_sim.multiflow import MultiFlow


def inputs():
    return (Scenario(20, .15), Traffic(duration_s=.04, drain_s=.6, window_bytes=1448 * 32),
            (PathConfig(forward_mbps=10, reverse_mbps=1),),
            Strategy("ARQ", cumulative_feedback=True), 42)


@pytest.mark.parametrize("mode", ["arq", "quic"])
def test_one_flow_matches_existing_transport(mode):
    if mode == "quic":
        pytest.importorskip("aioquic")
    scenario, traffic, paths, strategy, seed = inputs()
    strategy = replace(strategy, mode=mode)
    reference = measure(simulation_type(mode)(scenario, traffic, paths, strategy, seed).run())
    aggregate = MultiFlow(scenario, traffic, paths, strategy, seed, 1).run().measurements()
    assert {key: aggregate[key] for key in reference} == reference


@pytest.mark.parametrize("mode", ["arq", "quic"])
def test_flows_share_capacity_and_loss_but_own_transport_state(mode):
    if mode == "quic":
        pytest.importorskip("aioquic")
    scenario, traffic, paths, strategy, seed = inputs()
    sim = MultiFlow(scenario, traffic, paths, replace(strategy, mode=mode), seed, 4)
    assert len({id(flow.forward.pending) for flow in sim.flows}) == 4
    assert len({id(flow.tcp_buffer) for flow in sim.flows}) == 4
    assert len({id(flow.sequence) for flow in sim.flows}) == 1
    for reverse in (False, True):
        assert len({id(flow.links[reverse][0]) for flow in sim.flows}) == 1
        assert len({id(flow.links[reverse][0].erasures) for flow in sim.flows}) == 1
        decisions = iter([True, False] * 10000)
        sim.links[reverse][0].erasures.lost = lambda decisions=decisions: next(decisions)
    row = sim.run().measurements()
    assert row["total_window_bytes"] == traffic.window_bytes
    for reverse, name in ((False, "forward"), (True, "reverse")):
        assert row[name + "_lost_datagrams"] == (
            row[name + "_datagrams"] + 1) // 2
        capacity = sim.links[reverse][0].bytes_per_s
        assert row[name + "_wire_bytes"] <= capacity * (traffic.duration_s + traffic.drain_s)
        assert row[name + "_wire_bytes_during_measurement"] <= capacity * traffic.duration_s


def test_fixed_total_window_rounding_and_independent_delayed_ack():
    scenario, traffic, paths, strategy, seed = inputs()
    traffic = replace(traffic, window_bytes=1448 * 19 + 17)
    sim = MultiFlow(scenario, traffic, paths, strategy, seed, 4)
    assert [flow.traffic.window_bytes // 1448 for flow in sim.flows] == [5, 5, 5, 4]
    assert sum(flow.traffic.window_bytes for flow in sim.flows) == 1448 * 19
    sim.flows[0].on_data(0)
    assert sim.flows[0].tcp_received == 1
    assert sim.flows[0].ack_timer is not None
    assert all(flow.tcp_received == 0 and flow.ack_timer is None for flow in sim.flows[1:])


def test_aggregate_pacing_preserves_requested_rate():
    scenario, traffic, paths, strategy, seed = inputs()
    traffic = replace(traffic, frame_interval_ms=2, duration_s=.011)
    sim = MultiFlow(scenario, traffic, paths, strategy, seed, 4).run()
    assert sorted(time for flow in sim.flows for time in flow.sent_times) == pytest.approx(
        [0, .002, .004, .006, .008, .010])
    assert len(sim.flow_measurements()) == 4


def test_fixed_per_flow_window_is_explicit_and_larger():
    sim = MultiFlow(*inputs(), 4, window_policy="fixed_per_flow").run()
    assert sim.measurements()["total_window_bytes"] == 4 * inputs()[1].window_bytes
    with pytest.raises(ValueError, match="at least one segment"):
        MultiFlow(*inputs(), 33)


def test_custom_compact_factory_one_flow_exactly_matches_standalone_tcp():
    from l2tunnel_sim.compact import CompactConfig
    from l2tunnel_sim.compact_arq import CompactARQTransport
    from l2tunnel_sim.compact_tcp import CompactTCP

    scenario, traffic, paths, strategy, seed = inputs()
    strategy = replace(strategy, mode="tcp", tcp_rto_min_ms=1000)
    factory = partial(CompactTCP, compact_config=CompactConfig(
        repair_ratio=0, header_profile="tcp_delta"), reliable_acks=False,
        transport_type=CompactARQTransport)
    reference = factory(scenario, traffic, paths, strategy, seed).run()
    shared = MultiFlow(scenario, traffic, paths, strategy, seed, 1,
                       simulation_factory=factory).run()
    actual = shared.flows[0]
    assert measure(actual) == measure(reference)
    assert actual.compact_forward.base == reference.compact_forward.base
    assert actual.compact_forward.flights == reference.compact_forward.flights
    assert actual.compact_forward.source_record_bytes == reference.compact_forward.source_record_bytes
    assert actual.sent_times == reference.sent_times
