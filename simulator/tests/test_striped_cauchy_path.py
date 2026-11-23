"""Check the opt-in mixed physical data path on the ordinary two-way TCP study."""
from pathlib import Path
from types import SimpleNamespace


def test_short_bursts_drain_over_real_mixed_packets_on_both_directions(monkeypatch):
    from test_aggregate_ack_deadlines import task

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_spare_c48 import run

    case = task("compact_wire", .15)
    case["profile"].update(flow_count=1, ack_aggregation=False, ack_copies=1, mux={"channels": 2},
                           payload_rate_mbps=10, c48_native_udp_packing=True)
    case["profile"]["compact"].update(pack_sources_max_delay_ms=.5, trim_repair_padding=True)
    case.update(packed_targeted_recovery=True, duration_s=.1,
                packed_receiver_cost=dict(packet_us=0, metadata_ns=0, gf_ns_per_byte=0, waiting_slots=8))
    result = run(case, "striped-cauchy", 125, 12_500_000)
    assert result["result"]["fully_confirmed"]
    for direction, path in result["striped_cauchy"].items():
        counts = path["counts"]
        assert path["unsealed_sources"] == path["retained_sent_sources"] == path["receiver_live_groups"] == 0
        assert path["confirmed_source_prefix"] == path["source_count"]
        assert counts["max_ip_bytes"] <= case["mtu"]
        assert counts["split_completed_from_ordinal_0"]
        assert counts["split_duplicate_datagrams"]
        for kind in ("source","retry"):
            price = sum(counts.get(kind+field, 0) for field in
                        ("_own_bytes","_parity_bytes","_metadata_bytes","_outer_bytes"))
            assert price == counts.get(kind+"_ip_bytes", 0)
            assert price == result["offered_ip_packets"][direction]["ip_bytes"][kind]
    assert result["striped_cauchy"]["forward"]["counts"]["oversized_short_groups_split"] >= 1
    assert any(path["counts"].get("split_completed_from_ordinal_1", 0)
               for path in result["striped_cauchy"].values())


def test_input_on_expired_group_deadline_cannot_join_the_old_shape(monkeypatch):
    from l2tunnel_sim.striped_cauchy import Geometry
    from test_packed_wire import make_transport

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_path import StripedPath
    sim, transport = make_transport()
    path = StripedPath(SimpleNamespace(transport=transport), Geometry(4, 1))
    transport.sources.append(None)
    path.first(b"ABCD"+b"crc!", "source", 0)
    old_deadline = path.pending_deadline
    sim.now = old_deadline
    transport.sources.append(None)
    path.first(b"EFGH"+b"crc!", "source", 0)
    assert path.counts["groups_1"] == 1 and path.pending_base == 1
    assert path.pending_deadline == old_deadline+path.hold
    path.seal(0)
    assert path.pending == [b"EFGH"] and path.counts["source_packets"] == 2


def test_startup_anchor_repeat_uses_the_same_member_once_after_departure(monkeypatch):
    from l2tunnel_sim.aligned_records import CHANNEL_HEADER
    from l2tunnel_sim.fixed_anchor_ip import CONTEXT
    from l2tunnel_sim.packed_spare import OUTER
    from l2tunnel_sim.striped_cauchy import Geometry
    from test_fixed_anchor_ip import frame
    from test_packed_wire import container, make_transport, run_until, unit

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_path import StripedPath

    sim, transport = make_transport()
    path = StripedPath(SimpleNamespace(transport=transport, receive=lambda _: None), Geometry(4, 1))
    path.startup_anchor_copy = True
    ip_header = frame(0)[14:66]
    context = CHANNEL_HEADER.pack(0, 2) + bytes([CONTEXT]) + len(ip_header).to_bytes(2, "big") + ip_header
    raw = unit(3, bytes([CONTEXT]))
    packed = container([context, context], padded=False)
    payloads = [raw] * 124 + [raw, context, raw, packed, context]
    transport.sources.extend(SimpleNamespace(size=len(p)) for p in payloads)
    transport.source_payloads.extend(payloads)
    # A busy link must still separate the two reservations by a real millisecond.
    sim.links[False][0].free_at = .007
    sent = []
    emit = path.emit

    def observe(packet, kind):
        finish = emit(packet, kind)
        sent.append((sim.now, finish[0], packet))
        return finish

    path.emit = observe
    path.emit_group(124, payloads[124:])
    path.emit_group(1, [raw])
    transport.source_payloads[2], transport.sources[2] = context, SimpleNamespace(size=len(context))
    path.emit_group(2, [context])
    del path.tx[125]  # Already confirmed when its copy would become eligible.
    old = list(sent)
    run_until(sim, .015)
    assert [(start, packet) for start, _, packet in sent[len(old):]] == [
        (old[i][1] + .001, old[i][2]) for i in (3, 7)]
    assert path.counts["startup_anchor_copies"] == 2
    assert path.counts["startup_anchor_copy_ip_bytes"] == sum(OUTER + len(old[i][2]) for i in (3, 7))
    assert sim.wire[False]["source"] == path.counts["source_ip_bytes"]


def test_over_mtu_batch_preserves_prefix_or_suffix_and_original_deadline(monkeypatch):
    from l2tunnel_sim.striped_cauchy import Geometry, inspect_packet
    from test_packed_wire import make_transport

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_path import StripedPath

    cases = [
        ((500, 400, 1075), [(0, 2), (2, 1)]),
        ((1075, 500, 400), [(0, 1), (1, 2)]),
        # The first two exceed the MTU together, while the first three fit.
        ((900, 200, 940, 1140), [(0, 3), (3, 1)]),
    ]
    for sizes, expected in cases:
        sim, transport = make_transport()
        path = StripedPath(SimpleNamespace(transport=transport), Geometry(4, 1))
        path.short_prefix_groups = True
        for size in sizes:
            transport.sources.append(None)
            path.first(bytes(size) + b"crc!", "source", 0)
        frozen = path.pending_deadline
        sim.now = frozen
        observed = []

        def emit(packet, kind):
            base, geometry, split, ordinal, _ = inspect_packet(packet, path.geometry, path.max_wire)
            assert sim.now == frozen and len(packet) <= path.max_wire
            if not ordinal:
                observed.append((base, 1 if split is not None else geometry.n))
            return sim.now, .070

        path.emit = emit
        # The first submit at the old deadline drains the frozen suffix before
        # it starts a new, independently timed batch.
        transport.sources.append(None)
        path.first(b"new!crc!", "source", 0)
        assert observed == expected
        assert path.pending == [b"new!"] and path.pending_base == len(sizes)
        assert path.pending_deadline == frozen + path.hold


def test_reverse_quiet_rotation_preserves_oldest_slots_cost_and_deadline(monkeypatch):
    from collections import Counter
    from l2tunnel_sim.striped_cauchy import Geometry
    from test_packed_wire import make_transport

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_path import StripedPath
    from l2tunnel_sim.packed_spare import OUTER
    sim, t = make_transport()
    t.reverse = True
    t.targeted_counts = Counter()
    path = StripedPath(SimpleNamespace(transport=t), Geometry(4, 1))
    path.fair_reverse_probes = True
    for idx, length in enumerate((100, 80, 101, 100), 204):
        path.emit_group(idx, [bytes(length)])
    sent = []
    def emit(packet, kind):
        from l2tunnel_sim.striped_cauchy import inspect_packet
        index, *_ = inspect_packet(packet, path.geometry, path.max_wire)
        sent.append(index)
        return sim.send(True, OUTER + len(packet), kind, lambda: None)
    path.emit = emit
    oldest_ip = OUTER + len(path.tx[204][0])
    link, = sim.links[True]
    for _ in range(8):
        expected_finish = link.finish(sim.now, oldest_ip)
        assert path.retry(204, "quiet_probes") == expected_finish
        sim.now = expected_finish + .140
    assert sent == [204, 205, 204, 204, 204, 207, 204, 205]
    assert path.counts["quiet_slot_ip_budget"] == 8 * oldest_ip
    assert path.counts["rotation_exceeded_slot_bytes"] == 1
    assert t.targeted_counts["retry_ip_bytes"] <= 8 * oldest_ip
    # A named request bypasses the rotation and may still recover an older
    # large source. Removing a confirmed prefix cannot resurface a retired ID.
    path.retry(206, "requested_retries")
    assert sent[-1] == 206
    del path.tx[204], path.tx[205]
    path.retry(206, "quiet_probes")
    path.retry(206, "quiet_probes")
    assert sent[-2:] == [206, 207]


def test_residual_rank_repeats_oldest_after_lost_request_and_reply(monkeypatch):
    from l2tunnel_sim.packed_receiver_service import PackedReceiverService, ReceiverCost
    from l2tunnel_sim.packed_targeted import TargetedPolicy
    from l2tunnel_sim.striped_cauchy import Geometry
    from test_packed_targeted import fixture, step, submit

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_path import StripedPath

    erasures = {("source", 1), ("source", 2), ("source", 3), ("gap_request", 1), ("retry", 1)}
    sim, tx, log = fixture(erasures, policy=TargetedPolicy(probe_ms=1000))
    service = PackedReceiverService(tx, ReceiverCost(0, 0, 0, 128))
    service.observe_fifo_gaps()
    path = StripedPath(service, Geometry(10, 2))
    path.install()
    transmitted = []
    send = tx._send_named
    def record(ids):
        if ids:
            transmitted.append(tuple(ids))
        send(ids)
    tx._send_named = record
    path.select_rank_requests()
    assert path.needed_for_rank(180)
    received = []
    originals = [submit(tx, i, received, int(i >= 12)) for i in range(192)]
    step(sim, .075)
    assert tx.highest_received >= 128 and tx.received_prefix == 0
    assert path.needed_for_rank(0) and not path.needed_for_rank(1) and not path.needed_for_rank(2)
    assert transmitted == [(0,)] and 0 in path.tx
    step(sim, .45)
    assert transmitted[:3] == [(0,), (0,), (0,)]
    assert tx.base == tx.received_prefix == len(tx.sources)
    assert not path.tx and sorted(received) == sorted(originals)
    assert path.counts["rank_suppressed_ids"] > 0
    assert sum(size for _, _, size, kind, _ in log if kind == "retry") == path.counts["retry_ip_bytes"]
    assert all(size > 0 for _, _, size, kind, lost in log if lost and kind in ("gap_request", "retry"))


def test_residual_rank_selects_the_same_ids_across_feedback_mask_boundaries(monkeypatch):
    from itertools import combinations
    from l2tunnel_sim.striped_cauchy import Geometry, shortened
    from test_packed_wire import make_transport

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_path import StripedPath
    _, t = make_transport()
    path = StripedPath(SimpleNamespace(transport=t), Geometry(10, 2))
    base = 61
    for count in range(2, 13):
        g = shortened(path.geometry, count)
        for accepted in range(1, count+1):
            for ordinals in combinations(range(count), accepted):
                path.rx[base] = SimpleNamespace(geometry=g, packets=set(ordinals))
                missing = [base+i for i in range(count) if i not in ordinals]
                expected = missing[:max(g.k-accepted, 0)]
                assert [i for i in reversed(missing) if path.needed_for_rank(i)] == expected[::-1]
                assert path.needed_for_rank(base-1) and path.needed_for_rank(base+count)
