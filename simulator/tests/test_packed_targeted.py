"""Loss, old custody, wire bounds and quiet-tail tests for targeted PackedWire."""

from collections import Counter
from heapq import heappop

import pytest

from l2tunnel_sim.compact_wire import CompactWireConfig, decode_packet, encode_repair
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.model import Simulation
from l2tunnel_sim.packed_receiver_service import PackedReceiverService, ReceiverCost
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


@pytest.mark.parametrize("fifo_evidence", [False, True])
def test_gap_after_old_loss_is_retained_outside_small_window_and_recovers_exact_frame(fifo_evidence):
    sim, tx, log = fixture({("source", 1), ("gap_request", 1), ("retry", 1)},
                           policy=TargetedPolicy(gap_ms=2, repeat_ms=80, probe_ms=500))
    if fifo_evidence:
        PackedReceiverService(tx, ReceiverCost(0, 0, 0, 4)).observe_fifo_gaps()
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


@pytest.mark.parametrize("fifo_evidence", [False, True])
def test_fifo_gap_observation_while_repair_and_systematic_copies_are_retained(fifo_evidence, monkeypatch):
    from l2tunnel_sim import packed_targeted

    sim, tx, log = fixture({("source", i) for i in range(1, 9)})
    service = PackedReceiverService(tx, ReceiverCost(10_000, 0, 0, 3))
    if fifo_evidence:
        service.observe_fifo_gaps()
    requests = []
    encode = packed_targeted.encode_request

    def record(*args):
        wire = encode(*args)
        requests.append((sim.now, decode_request(wire, tx.policy, tx.config.encapsulation)[1], len(wire)))
        return wire

    monkeypatch.setattr(packed_targeted, "encode_request", record)
    delivered = []
    originals = [submit(tx, i, delivered) for i in range(8)]
    step(sim, .001)

    def source(index):
        return tx.source_wire(index, tx.source_payloads[index][:tx.sources[index].size])

    service.receive(encode_repair(1, 1, b"x", tx.config.encapsulation))
    # Reusing the caller's buffer must not corrupt either admitted copy of S1.
    buffer = bytearray(source(1))
    service.receive(buffer)
    service.receive(memoryview(buffer))
    buffer[-1] ^= 1

    class TaggedWire(bytes):
        pass

    tagged = TaggedWire(source(3))
    service.receive(tagged)
    assert service.waiting[-1][0] is tagged
    service.receive(source(7))
    assert service.drops == 1
    step(sim, .0029)
    assert not requests and not delivered
    step(sim, .0031)
    assert tx.received_prefix == 0 and not tx.decoder.known
    if fifo_evidence:
        at, ids, length = requests[0]
        assert at == pytest.approx(.003)
        assert ids == (0, 2) and len(requests) == 1
        assert [(rev, size) for _, rev, size, kind, _ in log if kind == "gap_request"] == [(True, 20 + length)]
    else:
        assert not requests
    step(sim, .0111)
    assert delivered == [originals[0]] and tx.received_prefix == 1
    # One copy of S1 is active, a second is waiting. S7 becomes evidence
    # only after a slot is free. The committed prefix still comes from FEC.
    service.receive(source(7))
    step(sim, .0151)
    if fifo_evidence:
        assert requests[-1][1] == (4, 5, 6)
    else:
        assert not requests
    step(sim, .032)
    assert delivered == originals[:2] and tx.received_prefix == 2 and tx.wire_invalid_packets == 0
    assert all(1 not in ids and 3 not in ids and 7 not in ids for _, ids, _ in requests)


def test_fifo_horizon_shares_the_existing_eight_id_cadence_and_repeat_floor(monkeypatch):
    from l2tunnel_sim import packed_targeted

    erased = {("source", i) for i in range(1, 42)} | {("gap_request", i) for i in range(1, 50)}
    sim, tx, _ = fixture(erased)
    service = PackedReceiverService(tx, ReceiverCost(200_000, 0, 0, 2))
    service.observe_fifo_gaps()
    sent = []
    encode = packed_targeted.encode_request

    def record(prefix, start, offsets, policy, encapsulation):
        wire = encode(prefix, start, offsets, policy, encapsulation)
        sent.append((sim.now, decode_request(wire, policy, encapsulation)[1]))
        return wire

    monkeypatch.setattr(packed_targeted, "encode_request", record)
    for index in range(41):
        submit(tx, index, [])
    step(sim, .001)
    for index in (0, 40, 2):
        service.receive(tx.source_wire(index, tx.source_payloads[index][:tx.sources[index].size]))
    step(sim, .0829)
    originals = set(range(1, 40)) - {2}
    assert {index for _, ids in sent for index in ids} == originals
    assert sum(len(ids) for _, ids in sent) == len(originals)
    ids_per_tick = Counter()
    for at, ids in sent:
        ids_per_tick[at] += len(ids)
    assert max(ids_per_tick.values()) == 8
    ticks = list(ids_per_tick)
    assert all(b - a >= .002 - 1e-12 for a, b in zip(ticks, ticks[1:]))
    step(sim, .084)
    assert set(sent[-1][1]) <= originals and len(sent[-1][1]) == 8
    assert sent[-1][0] >= sent[0][0] + .080
    assert tx.received_prefix == 0 and not tx.decoder.known


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


def test_early_frontier_mask_combines_two_ticks_and_keeps_repeat_custody():
    sim, tx, log = fixture({("gap_request", 1)})
    tx.received_prefix = 1
    tx._fifo_sources[2] += 1
    tx._observe_gap_horizon(3)
    step(sim, .0002)
    tx._fifo_sources[4] += 1
    tx._observe_gap_horizon(5)
    assert not tx.request_fresh_frontier(2, 5, 2)
    assert not tx.request_fresh_frontier(0, 5, 1)
    assert tx.request_fresh_frontier(0, 5, 2)
    assert tx.targeted_counts["requested_ids"] == 2
    assert list(tx._repeat) == [1, 3] and not tx._fresh
    assert not tx.request_fresh_frontier(0, 5, 2)
    step(sim, .006)
    assert [entry[3] for entry in log] == ["gap_request"]
    step(sim, .083)
    assert [entry[3] for entry in log] == ["gap_request", "gap_request"]
    assert list(tx._repeat) == [1, 3]


def test_same_tick_and_outstanding_older_repeat_keep_normal_feedback_slot():
    sim, tx, log = fixture(set())
    tx.received_prefix = 1
    tx._fifo_sources[2] += 1
    tx._fifo_sources[4] += 1
    tx._observe_gap_horizon(5)
    assert not tx.request_fresh_frontier(0, 5, 2)
    assert not log and list(tx._fresh) == [1, 3]
    tx._fresh[3] += .001
    tx._repeat[14] = sim.now
    assert not tx.request_fresh_frontier(0, 5, 2)
    assert not log and list(tx._fresh) == [1, 3]


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
