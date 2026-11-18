from heapq import heappop

import pytest

from l2tunnel_sim.compact_wire import CompactWireConfig, decode_packet
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.packed_latency_policy import LatencyPackedWireTransport
from l2tunnel_sim.packed_targeted import TargetedPolicy


@pytest.mark.parametrize("variant,weight", [
    ("shared-repair-budget", 1), ("half-shared-repair-budget", .5),
])
def test_byte_budget_keeps_old_debt_and_charges_exact_regular_extent(variant, weight):
    sim = Simulation(Scenario(70, 0), Traffic(duration_s=1, drain_s=1), (PathConfig(100,10),),
                     Strategy("budget custody", mode="tcp"), 31)
    config = CompactWireConfig(repair_ratio=.25, feedback_ms=1, encapsulation="raw_ipv4_crc32",
                               trim_repair_padding=True, pack_sources_max_delay_ms=.5)
    policy = TargetedPolicy(probe_ms=80, window=8, max_ids=4)
    tx = LatencyPackedWireTransport(sim, False, config, policy=policy, variant=variant)
    send = tx._send_wire
    regular_serials = []
    recovered = []

    def send_with_erasures(wire, kind, header):
        packet = decode_packet(wire, tx.base, tx.config.encapsulation)
        if kind == "repair":
            regular_serials.append(packet.serial)
        # Keep the oldest source blocked even across global repair emissions.
        # Suppress a burst of later originals to create actual targeted debt.
        drop = (kind == "repair" or
                kind == "source" and (packet.index == 0 or 129 <= packet.index <= 142) or
                kind == "retry" and packet.index == 0 and sim.now < .34)
        if drop:
            return sim.send(False, tx.ip_header_bytes + len(wire), kind, lambda: None)
        return send(wire, kind, header)

    tx._send_wire = send_with_erasures
    expected = []

    def offer(index):
        body = bytes.fromhex("02000000000202000000000188b5") + index.to_bytes(2,"big")
        body += bytes(1300 if index == 3 else 800 + index % 73)
        expected.append(body)
        tx.submit_channel(int(index != 0), len(body), len(body) - 66,
                          recovered.append, frame=body, deliver_frame=True)

    for i in range(400):
        sim.at(i * .0005, offer, i)
    while sim.events:
        sim.now, _, fn, args = heappop(sim.events)
        fn(*args)
    costs = tx.latency_counts
    assert tx.base == len(tx.sources) == 400
    assert recovered == [*expected[1:], expected[0]]
    assert tx.targeted_counts["quiet_probes"] > 0 and tx.tail_repairs == 0
    assert tx.global_repairs > 0 and regular_serials == list(range(1,len(regular_serials)+1))
    assert costs["displaced_regular_packets"] > 0
    assert costs["regular_opportunity_ip_bytes"] == sim.wire[False]["repair"] + costs["displaced_regular_ip_bytes"]
    assert costs["peak_credit_bytes"] <= policy.window * sim.scenario.mtu
    assert costs["retry_credit_bytes"] == (costs["displaced_regular_ip_bytes"]
        + costs["expired_on_confirmation_bytes"] + costs["cap_discarded_bytes"])
    assert 0 < costs["retry_credit_bytes"] <= tx.targeted_counts["retry_ip_bytes"] * weight
