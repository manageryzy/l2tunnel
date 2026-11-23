"""Focused native-body and C KCP reference behavior for the L2 study."""

from pathlib import Path
from random import Random
import struct
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
from kcp_like_l2_baseline import (
    CORPUS_SEED,
    KCP_HEADER,
    NativeCredit,
    body,
    corpus,
    decode,
    ethernet_frame,
    run,
)
from l2tunnel_sim.kcp import KCPContext


def test_existing_rust_lz4_block_decodes_to_complete_python_ethernet_frame():
    pytest.importorskip("lz4.block")
    frame = ethernet_frame(0, Random(CORPUS_SEED))
    # Captured from lz4_flex 0.14.0 block::compress on this exact 1514-byte frame.
    rust = bytes.fromhex(
        "610200000000020600f00e010800450005dc000040004011a8e9c6120001"
        "c61200027d007d0105c82700df0000666978747572652e4c322e0b00ffff"
        "ffffff9d602e6669787475"
    )
    assert decode(b"\x0a" + struct.pack("!HH", len(rust), 1514) + rust) == frame
    assert decode(body(frame, True)) == decode(body(frame, False)) == frame
    opaque = ethernet_frame(1, Random(1))
    assert body(opaque, True) == body(opaque, False)


def test_pinned_c_with_no_ack_has_200ms_then_300ms_timeout_interval():
    peer = KCPContext(99)
    try:
        peer.send(b"one")
        payments = [
            (ms, packet) for ms in range(0, 501, 10) for packet in peer.update(ms)
        ]
        assert [ms for ms, _ in payments] == [0, 200, 500]
        assert all(
            KCP_HEADER.unpack_from(packet)[1] == 81
            and KCP_HEADER.unpack_from(packet)[5] == 0
            for _, packet in payments
        )
    finally:
        peer.close()


def test_two_acks_inside_one_input_do_not_count_as_two_fastack_events_in_c():
    tx = KCPContext(98, mtu=300, resend=2)
    rx = KCPContext(98, mtu=300, resend=2)
    try:
        for i in range(4):
            tx.send(bytes([i]) * tx.mss)
        packets = tx.update(0)
        assert len(packets) == 4
        for p in packets[1:3]:
            rx.input(p)
        (first,) = rx.update(0)
        assert [KCP_HEADER.unpack_from(first, o)[5] for o in (0, 24)] == [1, 2]
        tx.input(first)
        assert not tx.update(10)
        rx.input(packets[3])
        (second,) = rx.update(10)
        tx.input(second)
        (retry,) = tx.update(20)
        assert (
            KCP_HEADER.unpack_from(retry)[1] == 81
            and KCP_HEADER.unpack_from(retry)[5] == 0
        )
    finally:
        tx.close()
        rx.close()


def test_native_credit_requires_each_fragment_and_ignores_duplicate_ack():
    credit = NativeCredit(150, 100)
    credit.admit(150, 155)
    assert not credit.fits(1)
    for sn, frg, size in ((0, 1, 100), (1, 0, 55)):
        credit.check_pushes(
            KCP_HEADER.pack(7, 81, frg, 128, 0, sn, 0, size) + bytes(size)
        )
    selective = KCP_HEADER.pack(7, 82, 0, 128, 25, 1, 0, 0)
    credit.input_delivered_to_sender(selective)
    credit.input_delivered_to_sender(selective)
    assert credit.bytes == 150 and len(credit.segments) == 1
    credit.input_delivered_to_sender(KCP_HEADER.pack(7, 82, 0, 128, 30, 0, 2, 0))
    assert credit.bytes == 0 and not credit.segments and credit.fits(150)


@pytest.mark.parametrize("mode", ["raw", "lz4"])
def test_impaired_link_drains_and_reconciles_every_paid_byte(mode):
    if mode == "lz4":
        pytest.importorskip("lz4.block")
    frames = corpus(100, 6)
    if mode == "raw":
        short = run(frames, 42, mode, offer_ms=100, drain_ms=4000)
        assert short["delivered_frames"] == short["native_accepted_frames"]
        assert not short["fully_confirmed"] and short["pending_KCP_segments"] == [1, 0]
    r = run(
        frames, 42, mode, offer_ms=100, drain_ms=8000, warmup_ms=20, native_cap=10_000
    )
    assert 0 < r["native_sender_credit"]["peak"] <= 10_000
    assert r["admission_ticks_and_delivery_bytes"]["blocked_native_credit_ticks"] > 0
    assert r["native_sender_credit"]["remaining"] == 0
    assert r["fully_confirmed"] and r["accepted_digest"] == r["received_digest"]
    assert r["pending_KCP_segments"] == [0, 0] and r["native_accepted_frames"] > 0
    assert r["directions"][0]["wire"]["repeat_push_segments"] > 0
    for d in r["directions"]:
        c = d["wire"]
        assert c["kcp_payload_bytes"] == sum(
            v
            for k, v in c.items()
            if k.endswith(
                (
                    "push_body_bytes",
                    "push_header_bytes",
                    "ack_header_bytes",
                    "probe_header_bytes",
                    "report_header_bytes",
                )
            )
        )
        assert (
            c["ip_bytes"]
            == c["kcp_payload_bytes"]
            + c["outer_ip_udp_bytes"]
            + c["route_and_pn_bytes"]
            + c["tag_bytes"]
        )
        assert c["l2_bytes"] == c["ip_bytes"] + 14 * c["datagrams"]
