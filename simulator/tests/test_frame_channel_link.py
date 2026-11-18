from dataclasses import replace

import pytest

from l2tunnel_sim.frame_channel_link import FrameChannelLink, LinkConfig


CLEAN = LinkConfig(forward_mbps=1, reverse_mbps=0.5, one_way_ms=10, loss_rate=0)


def test_shared_wire_budget_and_independent_lossy_feedback():
    link = FrameChannelLink(CLEAN, forced_loss=lambda rev, kind, identity: rev or identity == (0,))
    delivered = []
    a = link.send(False, "source", (0,), 972, lambda: delivered.append("a"))
    b = link.send(False, "source", (1,), 972, lambda: delivered.append("b"))
    ack = link.send(True, "ack", (1,), 72, lambda: delivered.append("ack"))
    assert (a, b, ack) == pytest.approx((0.008, 0.016, 0.0016))
    link.run(0.004)
    assert link.serialized_bytes(False) == pytest.approx(500)
    assert link.serialized_bytes(True) == pytest.approx(100)
    link.run(0.025)
    assert not delivered
    link.run(0.027)
    assert delivered == ["b"]
    report = link.report()
    assert report["forward"]["wire_bytes"] == 2000
    assert report["forward"]["record_bytes"] == 1944
    assert report["forward"]["erased"] == report["reverse"]["erased"] == 1
    assert report["reverse"]["by_kind"]["ack"]["wire_bytes"] == 100


def test_loss_is_paired_by_identity_despite_changes_in_packet_order_and_extras():
    def received(order, extra):
        net = FrameChannelLink(replace(CLEAN, loss_rate=0.3), seed=923)
        ids = set()
        for index in order:
            if extra:
                net.send(False, "parity", (index,), 32, lambda: None)
            net.send(False, "source", (index, 0), 32, lambda i=index: ids.add(i))
        net.run(1)
        return ids
    ids = received(range(80), False)
    assert 1 < len(ids) < 79
    assert received(reversed(range(80)), True) == ids


def test_decoder_starts_after_predecessor_commits_and_reports_censored_queue():
    cfg = replace(CLEAN, one_way_ms=0, decoder_slots=2, service_fixed_us=200000,
                  service_record_ns_per_byte=5, service_work_ns_per_byte=100)
    net = FrameChannelLink(cfg)
    committed = []
    for i in range(3):
        net.send(False, "source", (i,), 100, lambda i=i: committed.append(i),
                 work_bytes=lambda: 10 * len(committed))
    net.run(0.15)
    report = net.report()["forward"]
    assert report["decoder_queue_drops"] == 1
    assert report["peak_decoder_slots"] == 2
    assert report["decoder_in_service"] == report["decoder_waiting"] == 1
    assert 147 < report["decoder_oldest_pending_wait_ms"] < 149
    assert not committed
    net.run(0.5)
    report = net.report()["forward"]
    assert committed == [0, 1]
    assert report["decoder_work_bytes"] == 10
    assert report["decoder_service_ms"]["max"] == pytest.approx(200.0015)
    assert report["decoder_queue_wait_ms"]["at_least_100_ms"] == 1
    assert report["decoder_queue_wait_ms"]["count"] == 2
    assert report["decoder_oldest_pending_wait_ms"] is None


def test_wire_queue_bound_rejects_before_admission_and_recovers():
    cfg = replace(CLEAN, mtu_bytes=100, wire_queue_bytes=100)
    net = FrameChannelLink(cfg)
    assert net.send(False, "source", (0,), 72, lambda: None) == pytest.approx(.0008)
    assert net.send(False, "source", (1,), 1, lambda: None) is None
    net.run(.0004)
    assert net.send(False, "retry", (1, 1), 22, lambda: None) == pytest.approx(.0012)
    net.run(.1)
    report = net.report()["forward"]
    assert report["wire_queue_drops"] == 1
    assert report["decoder_queue_drops"] == report["erased"] == 0
    assert report["wire_bytes"] == 150
    assert report["peak_wire_queue_bytes"] == pytest.approx(100)
    with pytest.raises(ValueError, match="MTU"):
        net.send(False, "oversize", (1,), 73, lambda: None)
