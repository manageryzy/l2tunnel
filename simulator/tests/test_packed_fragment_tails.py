"""Fragment ordering, coding-window ownership and loss under opt-in tail packing."""

import json
from pathlib import Path
import sys
from unittest.mock import MagicMock

import pytest

from l2tunnel_sim.aligned_records import CHANNEL_HEADER, FRAGMENT_HEADER
from l2tunnel_sim.packed_wire import LAST_RECOVERABLE_SOURCE, packed_units
from test_packed_channel_release import ordinary_frame
from test_packed_targeted import fixture, step
from test_packed_wire import make_transport, run_until, submit


def emitted(tx, index):
    return tx.source_payloads[index][:tx.sources[index].size]


def fragment_offset(unit):
    return FRAGMENT_HEADER.unpack_from(unit, CHANNEL_HEADER.size)[2]


@pytest.mark.parametrize("same_channel", [False, True])
def test_leading_fragment_keeps_old_hole_recoverable_and_original_tail_deadline(same_channel):
    sim, tx, wire = fixture({("source", 1), ("retry", 1)})
    tx.select_packing_geometry(1251, 8)
    tx.enable_fragment_tail_packing()
    frames = [ordinary_frame(1450, 11), ordinary_frame(1460, 21)]
    delivered = []
    submit(tx, frames[0], delivered)
    original_deadline = tx._pack_deadline
    step(sim, .0002)
    channel = 0 if same_channel else 1
    submit(tx, frames[1], delivered, channel)
    assert len(tx.sources) == 2 and tx._pack_deadline == original_deadline == .0005
    heads = [emitted(tx, i) for i in (0, 1)]
    identities = [(0, 0), (channel, int(same_channel))]
    assert [CHANNEL_HEADER.unpack_from(head) for head in heads] == identities
    assert [fragment_offset(head) for head in heads] == [0, 0]
    step(sim, original_deadline)
    combined = emitted(tx, 2)
    tails = packed_units(combined, 1251)
    assert [CHANNEL_HEADER.unpack_from(tail) for tail in tails] == identities
    assert [fragment_offset(tail) for tail in tails] == [1243, 1243]
    assert len(combined) == 6 + sum(map(len, tails))
    assert tx.buffer_bytes == 0 and tx.submitted_bytes == tx.sent_bytes == sum(s.size for s in tx.sources)
    assert tx.fragment_tail_stats["leading_heads"] == tx.fragment_tail_stats["combined_tail_sources"] == 1
    assert tx.fragment_tail_stats["maximum_tail_batch_wait_us"] == 500
    step(sim, .08)
    assert delivered == ([] if same_channel else frames[1:])
    assert tx.base == tx.received_prefix == 0
    step(sim, .8)
    assert delivered == (frames if same_channel else frames[::-1])
    assert tx.base == tx.received_prefix == 3 and not tx.callbacks
    assert tx.targeted_counts["requested_retries"] >= 2
    assert any(reverse and kind == "gap_request" for _, reverse, _, kind, _ in wire)
    assert any(not reverse and kind == "retry" and lost for _, reverse, _, kind, lost in wire)


def test_expired_tail_is_sealed_before_same_tick_head():
    sim, tx, _ = fixture(set())
    tx.select_packing_geometry(1251, 8)
    tx.enable_fragment_tail_packing()
    submit(tx, ordinary_frame(1450, 19), [])
    # Submit before the scheduled callback at the identical logical time.
    sim.now = tx._pack_deadline
    submit(tx, ordinary_frame(1460, 29), [], 1)
    assert [fragment_offset(emitted(tx, i)) for i in range(3)] == [0, 1243, 0]
    assert tx._pack_deadline == .001 and not tx.fragment_tail_stats["leading_heads"]


def test_leading_fragment_never_crosses_a_different_physical_copy_policy():
    sim, tx = make_transport(short_source_copy_scope="all_short")
    tx.select_packing_geometry(1251, 8)
    tx.enable_fragment_tail_packing()
    frames = [ordinary_frame(1300, n) for n in (23, 33)]
    delivered = []
    submit(tx, frames[0], delivered)
    assert tx._pack_copies == 3
    submit(tx, frames[1], delivered, 1)
    assert [fragment_offset(emitted(tx, i)) for i in range(3)] == [0, 1243, 0]
    assert [tx._source_copy_count(emitted(tx, i)) for i in (0, 1)] == [1, 3]
    run_until(sim, .25)
    assert delivered == frames and not tx.fragment_tail_stats["leading_heads"]
    assert sim.datagrams[False]["source"] == 8


@pytest.mark.parametrize("last_identity", [False, True])
def test_full_coding_window_and_last_reserved_identity(last_identity):
    sim, tx, _ = fixture(set())
    tx.select_packing_geometry(1251, 8)
    tx.enable_fragment_tail_packing()
    # A zero-byte virtual retired prefix and full window avoid allocating
    # billions of past sources. All new queue entries are real.
    count = LAST_RECOVERABLE_SOURCE - 1 if last_identity else tx.config.block_sources
    tx.sources = MagicMock()
    tx.sources.__len__.return_value = count
    tx.sources.__getitem__.return_value.end_offset = 0
    tx.base = count - tx.config.block_sources
    submit(tx, ordinary_frame(1450, 11), [])
    assert len(tx.source_queue) == 1
    if last_identity:
        with pytest.raises(ValueError, match="source identity"):
            submit(tx, ordinary_frame(1460, 21), [], 1)
        assert [fragment_offset(unit) for unit in tx.source_queue] == [0, 1243]
        assert tx._queued_record_ends[-1] == {0: 1}
        assert not tx.fragment_tail_stats["leading_heads"]
    else:
        submit(tx, ordinary_frame(1460, 21), [], 1)
        assert [fragment_offset(unit) for unit in tx.source_queue] == [0, 0]
        step(sim, .0005)
        assert [fragment_offset(unit) for unit in packed_units(tx.source_queue[-1], 1251)] == [1243, 1243]
        assert list(tx._queued_record_ends) == [{}, {}, {0: 1, 1: 1}]
    assert sim.datagrams[False]["source"] == 0


def test_normal_c48_command_selects_fragment_tail_packing_only_on_request(tmp_path, monkeypatch):
    from test_aggregate_ack_deadlines import task

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_spare_c48 import main

    case = task("compact_wire")
    case["profile"].update(flow_count=1, ack_aggregation=False, ack_copies=1,
                           mux={"channels": 2}, payload_rate_mbps=50)
    case["profile"]["compact"].update(pack_sources_max_delay_ms=.5, trim_repair_padding=True)
    case.update(packed_targeted_recovery=True,
                packed_receiver_cost=dict(packet_us=0, metadata_ns=0, gf_ns_per_byte=0, waiting_slots=8))
    manifest = tmp_path / "task.json"
    manifest.write_text(json.dumps({"task": case}))
    for selected in (False, True):
        receipt = tmp_path / f"{selected}.json"
        argv = ["packed_spare_c48", "--policy", "control", "--segments", "125", "--native-udp-packing",
                "--manifest", str(manifest), "--output", str(receipt)]
        if selected:
            argv.append("--fragment-tail-packing")
        monkeypatch.setattr(sys, "argv", argv)
        main()
        report = json.loads(receipt.read_text())
        assert report["result"]["fully_confirmed"]
        assert ("c48_fragment_tail_packing" in report["task"]["profile"]) == selected
        assert ("fragment_tail_packing" in report) == selected
        if selected:
            forward = report["fragment_tail_packing"]["forward"]
            assert forward["leading_heads"] > 0 and forward["combined_tail_sources"] > 0
            for arm in report["fragment_tail_packing"].values():
                assert arm["confirmed_source_prefix"] == arm["source_count"] and arm["pending_pack_bytes"] == 0
