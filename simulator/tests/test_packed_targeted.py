"""Loss, old custody, wire bounds and quiet-tail tests for targeted PackedWire."""

from collections import Counter
from heapq import heappop

import pytest

from l2tunnel_sim.compact_wire import CompactWireConfig, decode_packet
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.packed_targeted import (
    TargetedPackedWireTransport, TargetedPolicy, decode_request, encode_request,
)


def fixture(erased, *, ratio=0, policy=None):
    sim = Simulation(Scenario(70, 0), Traffic(duration_s=1, drain_s=2), (PathConfig(100,10),),
                     Strategy("targeted packed loss", mode="tcp"), 42)
    cfg = CompactWireConfig(repair_ratio=ratio, feedback_ms=1, encapsulation="raw_ipv4_crc32",
                            pack_sources_max_delay_ms=.5)
    tx = TargetedPackedWireTransport(sim, False, cfg, policy or TargetedPolicy())
    send = sim.send
    attempts = Counter()
    log = []

    def lossy(reverse, size, kind, receive):
        attempts[kind] += 1
        lost = (kind, attempts[kind]) in erased
        log.append((sim.now, reverse, size, kind, lost))
        return send(reverse, size, kind, (lambda: None) if lost else receive)

    sim.send = lossy
    return sim, tx, log


def step(sim, until):
    while sim.events and sim.events[0][0] <= until:
        sim.now, _, callback, args = heappop(sim.events)
        callback(*args)
    sim.now = until


def submit(tx, value, out, lane=0):
    frame = bytes.fromhex("02000000000202000000000188b5") + value.to_bytes(2,"big") + bytes(900)
    tx.submit_channel(lane, len(frame), len(frame) - 66, out.append, frame=frame, deliver_frame=True)
    return frame


def test_gap_after_old_loss_is_retained_outside_small_window_and_recovers_exact_frame():
    sim, tx, log = fixture({("source", 1), ("gap_request", 1), ("retry", 1)},
                           policy=TargetedPolicy(gap_ms=2, repeat_ms=80, probe_ms=500))
    out = []
    first = submit(tx, 0, out)
    newer = [submit(tx, i, out, 1) for i in range(1,201)]
    step(sim, .08)
    assert tx.received_prefix == 0 and tx.highest_received >= 200
    assert out == newer and tx.source_payloads[0] is not None
    step(sim, .45)
    assert out == [*newer, first] and tx.base == len(tx.sources)
    assert tx.targeted_counts["requested_retries"] >= 2
    assert tx.targeted_counts["peak_request_state"] == 1
    assert tx.targeted_counts["quiet_probes"] == tx.tail_repairs == 0
    for _, rev, size, kind, _ in log:
        if kind == "gap_request":
            assert rev and size == 20 + 4 + 17 + 1
        if kind == "retry":
            assert not rev and size == tx.sources[0].size + tx.source_header


def test_no_received_source_means_no_oracle_request_and_sender_retries_silent_tail():
    sim, tx, log = fixture({("source",1), ("retry",1), ("feedback",1)})
    out = []
    original = submit(tx, 808, out)
    step(sim, .13)
    assert tx.highest_received == -1 and not out
    assert not any(kind == "gap_request" for _,_,_,kind,_ in log)
    step(sim, 1)
    assert out == [original] and tx.base == 1
    assert tx.targeted_counts["quiet_probes"] == 3
    assert tx.tail_repairs == tx.targeted_counts["request_packets_sent"] == 0


def test_regular_global_and_local_schedule_and_cumulative_confirmation_survive():
    sim, tx, _ = fixture(set(), ratio=.25)
    out = []
    originals = [submit(tx, i, out) for i in range(80)]
    step(sim,.5)
    assert out == originals and tx.base == 80
    assert (tx.local_repairs, tx.global_repairs, tx.tail_repairs) == (19,1,0)


def test_requests_with_small_budget_rotate_and_never_reach_beyond_observation():
    policy = TargetedPolicy(window=4, max_ids=1, gap_ms=2, repeat_ms=1, probe_ms=500)
    sim, tx, _ = fixture({("source",n) for n in range(1,5)}, policy=policy)
    seen = []
    original = tx._receive_request

    def receive(wire):
        _, ids = decode_request(wire, policy, tx.config.encapsulation)
        seen.extend(ids)
        original(wire)

    tx._receive_request = receive
    data = []
    expected = [submit(tx, i, data) for i in range(5)]
    step(sim, .5)
    assert seen[:7:2] == [0,1,2,3] and set(seen) == {0,1,2,3}
    assert data == expected and tx.targeted_counts["peak_request_state"] == 4


def test_wrap_stale_unsent_and_malformed_requests():
    policy = TargetedPolicy()
    prefix = 32767
    wire = encode_request(prefix, prefix, [0, 2], policy, "raw_ipv4_crc32")
    assert decode_request(wire, policy, "raw_ipv4_crc32") == (prefix, (32767, 32769))
    with pytest.raises(ValueError):
        decode_packet(wire, prefix, "raw_ipv4_crc32")
    for bad in (wire[:-1], wire[:-1]+bytes([wire[-1]^1])):
        with pytest.raises(ValueError):
            decode_request(bad, policy, "raw_ipv4_crc32")
    for offsets in ([0,0], [2,1], [policy.window], []):
        with pytest.raises(ValueError):
            encode_request(prefix, prefix, offsets, policy, "udp")
    with pytest.raises(ValueError):
        encode_request(2**32-1, 2**32-1, [1], policy, "udp")
    sim, tx, _ = fixture(set())
    submit(tx, 1, [])
    step(sim, .3)
    tx._receive_request(encode_request(0, 0, [0], policy, tx.config.encapsulation))
    tx._receive_request(encode_request(0, 0, [1], policy, tx.config.encapsulation))
    assert tx.targeted_counts["invalid_requests"] == tx.targeted_counts["stale_requested_ids"] == 1
    assert tx.targeted_counts["requested_retries"] == 0


def test_old_missing_head_and_newer_missing_id_use_independent_nack_span_and_ack_prefix():
    sim, tx, _ = fixture({("source",1), ("source",151)}, policy=TargetedPolicy(probe_ms=140))
    # Hold all transmissions of the first original until the newer channel
    # has independently received its missing source via a targeted retry.
    send_wire = tx._send_wire
    requests = []
    receive = tx._receive_request

    def send(wire, kind, header):
        packet = decode_packet(wire, tx.base, tx.config.encapsulation)
        if packet.kind == "source" and packet.index == 0 and kind == "retry" and sim.now < .25:
            return sim.send(False, tx.ip_header_bytes + len(wire), kind, lambda: None)
        return send_wire(wire, kind, header)

    def receive_logged(wire):
        requests.append(decode_request(wire, tx.policy, tx.config.encapsulation))
        receive(wire)

    tx._send_wire = send
    tx._receive_request = receive_logged
    out = []
    first = submit(tx, 0, out, 0)
    rest = [submit(tx,i,out,1) for i in range(1,201)]
    step(sim, .2)
    assert (0,(150,)) in requests and (0,(0,)) in requests
    assert tx.base == tx.received_prefix == 0 and out == rest
    assert tx.targeted_counts["quiet_probes"] > 0
    step(sim, .7)
    assert tx.base == 201 and out == [*rest, first]
