"""Decoder work preview, service completion, overflow and historical path equivalence."""

from copy import deepcopy
from heapq import heappop
from random import Random

import pytest

from l2tunnel_sim import coding
from l2tunnel_sim.compact_wire import CompactWireConfig
from l2tunnel_sim.packed_receiver_service import DecoderCurve, PackedReceiverService, ReceiverCost, equation_work
from l2tunnel_sim.packed_rank import PackedRankDecoder
from l2tunnel_sim.packed_wire import PackedWireTransport
from test_compact_wire_duplex import make_simulation
from test_mux_tcp import mux_case


def test_work_preview_matches_elimination_and_never_commits(monkeypatch):
    original = coding._eliminate
    measured = []

    def trace(target, row, factor):
        measured.append(len(row))
        return original(target, row, factor)

    monkeypatch.setattr(coding, "_eliminate", trace)
    decoder = coding.Decoder()
    reference = coding.Decoder()
    rng = Random(8152)
    inputs = [{0: 1, 1: 1}, {1: 1, 2: 1}, {0: 1, 2: 1}, {1: 1}, {0: 1}, {0: 1}, {}]
    inputs.extend({i: 1 for i in rng.sample(range(3, 60), 4)} for _ in range(80))
    for item in inputs:
        state = deepcopy((decoder.known, decoder.rows))
        mixes, updates, probes = equation_work(decoder, item)
        assert (decoder.known, decoder.rows) == state
        measured.clear()
        got = decoder.insert(item)
        # All coefficients are zero/one even after elimination. These inputs
        # never need a non-identity pivot normalization.
        assert (mixes, updates) == (len(measured), sum(measured))
        assert probes in (0, len(state[1]))
        assert reference.insert(item) == got
        assert (decoder.rows, decoder.known) == (reference.rows, reference.known)
    assert equation_work(coding.Decoder(), {2: 3, 4: 6}) == (1, 2, 0)


def test_arrivals_remain_invisible_until_completion_and_overflow_is_charged():
    sim, _ = make_simulation()
    transport = PackedWireTransport(sim, False, CompactWireConfig(pack_sources_max_delay_ms=.5))
    commits = []
    transport._receive_wire = lambda wire: commits.append((sim.now, wire))
    service = PackedReceiverService(transport, ReceiverCost(20, 0, 0, 1))
    for payload in (b"x", b"y", b"z"):
        service.receive(payload)
    assert not commits and not transport.decoder.known
    initial = service.measurements()
    assert (initial["active_at_stop"], initial["waiting_at_stop"], initial["dropped_full"]) == (1, 1, 1)
    while sim.events:
        sim.now, _, callback, args = heappop(sim.events)
        callback(*args)
    assert [entry[1] for entry in commits] == [b"x", b"y"]
    assert [entry[0] for entry in commits] == pytest.approx([20e-6, 40e-6])
    result = service.measurements()
    assert result["wait_mean_us"] == pytest.approx(10)
    assert result["wait_p99_us"] == pytest.approx(20)
    assert result["arrivals"] == result["completed"] + result["dropped_full"]


def test_zero_service_reproduces_all_historical_measurements(monkeypatch):
    from pathlib import Path
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from aggregate_ack_deadlines import execute

    case = mux_case(loss=.15)
    case["profile"]["compact"]["pack_sources_max_delay_ms"] = .5
    case.update(duration_s=.4, warmup_s=.04, drain_s=2)
    original = execute(case)
    timed = execute(dict(case, packed_receiver_cost=dict(packet_us=0, metadata_ns=0, gf_ns_per_byte=0,
                                                         waiting_slots=0)))
    assert timed.pop("packed_receiver_cost")
    for values in timed.pop("packed_receiver_service").values():
        assert values["wait_max_us"] == values["dropped_full"] == 0
        assert values["completed"] == values["arrivals"] > 0
    del original["compute_seconds"], timed["compute_seconds"]
    assert original == timed


def test_curve_prices_calibrated_total_once_and_source_visibility_waits_for_commit():
    from l2tunnel_sim.compact import tcp_profile_frame
    curve = DecoderCurve(4_000, 100, 5_000, 1000, 10_000)
    assert [curve.charge(n, 2**20) for n in (0, 100, 1000)] == [4_000, 5_000, 10_000]
    assert curve.charge(550, 0) == 7_500
    with pytest.raises(ValueError):
        DecoderCurve(1, 20, 10, 20, 30)
    sim, _ = make_simulation()
    t = PackedWireTransport(sim, False, CompactWireConfig(pack_sources_max_delay_ms=.5))
    service = PackedReceiverService(t, curve)
    frame = tcp_profile_frame(payload_bytes=768)
    got = []
    t.submit_channel(0, len(frame), 768, got.append, frame=frame, deliver_frame=True)
    while not service.active:
        sim.now, _, callback, args = heappop(sim.events)
        callback(*args)
    assert not t.decoder.known and not t.received_source and t.received_prefix == 0
    first_arrival = sim.now
    while not service.completed:
        sim.now, _, callback, args = heappop(sim.events)
        callback(*args)
    assert sim.now - first_arrival >= .004 - 1e-12
    assert t.decoder.known == {0} and t.received_prefix == 1
    while sim.events:
        sim.now, _, callback, args = heappop(sim.events)
        callback(*args)
    assert got == [frame]


def test_dense_backend_matches_every_sparse_row_and_charge_across_insertions():
    ref = coding.Decoder()
    dense = PackedRankDecoder()
    rng = Random(27621)
    # Absolute IDs cross a wrapped on-wire ID. Random coefficients, zero
    # factors, known duplicates, reverse insertion order and mixed support
    # produce partial pivots, fill-in and old holes.
    first = 2**24 - 20
    traces = []
    for batch in range(4):
        support = list(range(first + 20 * batch, first + 20 * batch + 43))
        for _ in range(25):
            values = {i: rng.randrange(256) for i in rng.sample(support, rng.randint(1, 20))}
            traces.extend((values, dict(reversed(values.items()))))
    traces.extend({i: 1} for i in range(first, first + 103))
    for item in traces:
        assert dense.preview(item) == equation_work(ref, item)
        assert dense.known == ref.known
        assert dense.insert(item) == ref.insert(item)
        assert dense.known == ref.known
        assert {i: {i + j: val for j, val in enumerate(row.values) if val}
                for i, row in dense.rows.items()} == ref.rows
