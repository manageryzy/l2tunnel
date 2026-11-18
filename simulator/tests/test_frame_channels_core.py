"""Causal and resource boundaries for the independent-channel frame experiment."""

from dataclasses import replace

import pytest

from l2tunnel_sim.frame_channel_link import FrameChannelLink, LinkConfig
from l2tunnel_sim.frame_channels import ChannelConfig, FrameChannels


CONFIG = ChannelConfig(channels=2, window_frames=2, fragment_bytes=5,
                       rto_ms=100, early_request_ms=2, feedback_delay_ms=1, parity=False)


def start(config=CONFIG, erase=None):
    net = FrameChannelLink(LinkConfig(loss_rate=0, one_way_ms=10), forced_loss=erase)
    packets, deliveries, events = [], [], []

    def transmit(packet, receive):
        packets.append((net.now, packet))
        return net.send(packet.reverse, packet.kind, packet.identity, packet.wire_bytes,
                        receive, work_bytes=lambda: core.decode_xor_bytes(packet))

    core = FrameChannels(config, lambda: net.now, net.at, transmit,
                         lambda i, data: deliveries.append((net.now, i, data)),
                         lambda *args: events.append((net.now, *args)))
    return net, core, packets, deliveries, events


@pytest.mark.parametrize("same_lane,ordered", [(False, [1, 0]), (True, [0, 1])])
def test_blocked_fragment_allows_progress_only_in_other_lanes(same_lane, ordered):
    def lose(reverse, kind, ident):
        return kind == "source" and ident == (0, 0, 1)

    net, core, packets, delivered, events = start(erase=lose)
    core.offer(0, 0, b"unseenFIRST")
    core.offer(0 if same_lane else 1, 1, b"other")
    net.run(.2)
    assert [entry[1] for entry in delivered] == ordered
    assert [p.identity for _, p in packets if p.kind == "retry"] == [(0, 0, 2)]
    observed = next(t for t, name, ch, seq, piece in events
                    if (name, ch, seq, piece) == ("gap_observed", 0, 0, 0))
    request = next(t for t, p in packets if p.kind == "request")
    assert 0.002 <= request - observed < .0021
    assert core.pending_frames == core.metrics["rto"] == 0


@pytest.mark.parametrize("missing", [0, 1, 2])
def test_parity_restores_full_or_short_fragment_with_exact_received_bytes(missing):
    def lose(reverse, kind, ident):
        return kind == "source" and ident == (17, missing, 1)

    net, core, _, delivered, _ = start(replace(CONFIG, parity=True), lose)
    data = bytes.fromhex("ff17299127ab2d0022e5f1")
    core.offer(0, 17, data)
    net.run(.2)
    assert [entry[2] for entry in delivered] == [data]
    assert core.metrics["fec_recovered"] == 1
    assert core.metrics["retry"] == 0
    assert net.report()["forward"]["decoder_work_bytes"] == core.metrics["decode_xor_bytes"] > 0


def test_fully_erased_frame_is_requested_without_oracle_and_tail_has_deadline():
    def lose(reverse, kind, ident):
        return kind == "source" and ident[0] == 99

    net, core, packets, delivered, _ = start(erase=lose)
    core.offer(0, 99, b"abcdefgh")
    core.offer(0, 81, b"next")
    net.run(.3)
    requests = [p for _, p in packets if p.kind == "request"]
    assert [(p.frame_id, p.fragment) for p in requests] == [(-1, 0), (99, 1)]
    assert core.metrics["rto"] == 0
    assert [d[2] for d in delivered] == [b"abcdefgh", b"next"]

    net, core, _, delivered, _ = start(erase=lose)
    core.offer(0, 99, b"abcdefgh")
    net.run(.09)
    assert not delivered and not core.metrics["request"]
    net.run(.2)
    assert core.metrics["rto"] == 1 and delivered[0][2] == b"abcdefgh"


def test_lost_request_and_ack_recover_without_duplicate_release():
    def lose(reverse, kind, ident):
        return (kind, ident) in {("source", (9, 0, 1)), ("request", (9, 0, 1)),
                                 ("ack", (9, 0, 2))}

    net, core, _, delivered, _ = start(erase=lose)
    core.offer(0, 9, b"123456")
    net.run(.4)
    assert core.metrics["rto"] >= 2
    assert net.report()["reverse"]["erased"] >= 2
    assert core.pending_frames == 0 and [d[2] for d in delivered] == [b"123456"]


def test_selective_confirmation_cannot_open_unbounded_reorder_queue():
    net, core, _, delivered, _ = start(erase=lambda r, k, i: k == "source" and i[0] == 0)
    core.offer(0, 0, b"0")
    core.offer(0, 1, b"1")
    net.run(.0215)
    assert not delivered and core.pending_frames == 1
    assert not core.can_offer(0) and not core.offer(0, 2, b"2")
    assert core.can_offer(1)
    net.run(.2)
    assert core.can_offer(0) and core.offer(0, 2, b"2")


def test_early_disabled_uses_sender_rto_only():
    net, core, _, delivered, _ = start(replace(CONFIG, early_request_ms=None),
                                       lambda r, k, i: k == "source" and i == (0, 1, 1))
    core.offer(0, 0, b"123456")
    net.run(.3)
    assert delivered and core.metrics["rto"] == 1 and not core.metrics["request"]


def test_repeated_early_request_can_recover_before_sender_rto():
    def lose(reverse, kind, ident):
        return (kind, ident) in {("source", (3, 0, 1)), ("request", (3, 0, 1))}

    config = replace(CONFIG, rto_ms=180, request_repeat_ms=80)
    net, core, packets, delivered, _ = start(config, lose)
    core.offer(0, 3, b"abcdef")
    net.run(.3)
    requests = [(t, p.identity) for t, p in packets if p.kind == "request"]
    assert [identity for _, identity in requests] == [(3, 0, 1), (3, 0, 2)]
    assert requests[1][0] - requests[0][0] == pytest.approx(.08)
    assert delivered[0][0] < .18 and core.metrics["rto"] == 0


def test_duplicate_target_requests_use_wire_fields_and_deliver_only_once():
    from l2tunnel_sim.frame_channels import Packet

    net, core, packets, delivered, _ = start(erase=lambda r,k,i: k == "source")
    core.offer(0, 91, b"abcd")
    # The network duplicates one request. Tracing attempts and frame IDs are
    # absent from the feedback descriptor and cannot suppress a targeted resend.
    request = Packet("request", 0, 0, 0, -1, b"", 1)
    for when in (.001, .002):
        net.at(when, net.send, True, request.kind, request.identity, request.wire_bytes,
               lambda: core._receive(request))
    net.run(.2)
    assert [p.identity for _, p in packets if p.kind == "retry"] == [(91, 0, 2), (91, 0, 3)]
    assert [d[2] for d in delivered] == [b"abcd"]
    assert not core.pending_frames
