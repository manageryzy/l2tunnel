from types import SimpleNamespace
import pytest

from l2tunnel_sim.tcp_sack import Receiver, Scoreboard, WireAck, ack_frame, parse_ack


def ack(edge, *ranges, dsack=False):
    return WireAck(edge, ranges, dsack, 1, 0)


def test_wire_timestamp_three_blocks_wrap_and_checksums():
    edge = 2**32-12
    ranges = [(edge-4,edge), (edge+2,edge+7), (edge+14,edge+25)]
    frame = ack_frame(edge, 9, 500, 400, ranges)
    assert len(frame) == 94
    assert parse_ack(frame, edge+12) == WireAck(edge,tuple(ranges),True,500,400)
    broken = bytearray(frame)
    broken[-1] ^= 3
    with pytest.raises(ValueError, match="checksum"):
        parse_ack(broken,edge)
    with pytest.raises(ValueError):
        ack_frame(0,0,0,0,ranges+ranges[:1])


def test_receive_mru_ordinary_and_dsack_are_separate():
    r = Receiver()
    for index in (8, 4, 2, 12, 5, 6):
        r.note(index,0,0,False,True)
    assert r.take_blocks(int) == ((4,7),(12,13),(2,3))
    r.note(4,0,0,True,True)
    assert r.take_blocks(int) == ((4,5),(4,7),(12,13))
    r.note(1,1,7,False,True)
    assert r.take_blocks(int) == ((12,13),(8,9))


def test_threshold_bytes_or_disjoint_ranges_and_partial_segment_boundaries():
    offsets = list(range(0, 201, 10))
    b = Scoreboard(20)
    b.observe(ack(0,(53,100)),0,offsets)
    assert b.sacked.bit_count() == 4
    assert b.loss_prefix(offsets,20) == 0  # Exactly twice SMSS; four adjacent short segments.
    b.observe(ack(0,(50,100)),0,offsets)
    assert b.loss_prefix(offsets,20) == 5
    b.reset()
    b.observe(ack(0,(10,20),(40,50),(80,90)),0,offsets)
    assert b.loss_prefix(offsets,1000) == 1
    before = (b.base,b.sacked,b.retried)
    with pytest.raises(ValueError):
        b.observe(ack(30,(50,60),(190,201)),3,offsets)
    assert (b.base,b.sacked,b.retried) == before
    b.observe(ack(30,(10,20),dsack=True),3,offsets)
    before = (b.base,b.sacked,b.retried)
    b.observe(ack(0,(10,20)),0,offsets)
    assert not b.fresh and (b.base,b.sacked,b.retried) == before


def test_reordered_ack_merges_only_live_whole_segments_without_rewinding_una():
    offsets = list(range(0, 101, 10))
    board = Scoreboard(5)
    board.observe(ack(60, (90, 100)), 6, offsets)
    assert board.mark_retry(7)
    # The DSACK is exempt. The ordinary block spanning UNA fully covers 6 and 7.
    reordered = ack(40, (20, 30), (50, 85), dsack=True)
    board.observe(reordered, 4, offsets)
    assert (board.base, board.sacked, board.retried, board.fresh) == (6, 0b1011, 0, True)
    board.observe(reordered, 4, offsets)
    assert not board.fresh
    board.observe(ack(0, (80, 90)), 0, offsets)
    assert not board.fresh and board.sacked == 0b1011


def test_selective_retransmit_uses_new_evidence_pipe_and_timeout_escape():
    b = Scoreboard(8)
    offsets = list(range(0, 900, 100))
    f = SimpleNamespace(in_recovery=True, recover=8, cwnd=6, segment_offsets=offsets,smss_bytes=100,
                        sent_times=[0]*8,fast_recovery_checkpoint=(12, 8, 64))
    sent = []
    def tx(i):
        assert b.mark_retry(i)
        sent.append(i)
    f.transmit_segment = tx
    packet = ack(0,(500,800))
    b.observe(packet,0,offsets)
    b.service(f)
    assert sent == [0] and b.pipe(8) == 6
    assert f.fast_recovery_checkpoint is None and b.stats["single_retry_undo_invalidated"] == 1
    b.observe(packet,0,offsets)
    f.cwnd = 8
    b.service(f)
    assert sent == [0] and not b.mark_retry(0)
    b.reset()
    assert b.mark_retry(0) and not b.sacked


def test_reordering_observer_separates_original_sack_cumulative_and_timestamp_evidence():
    offsets = list(range(0, 1201, 100))
    board = Scoreboard(12, reordering_smss=100)
    board.observe(ack(0, (700, 900)), 0, offsets)
    assert board.stats["reordering_segments"] == 3
    board.observe(ack(0, (500, 600)), 0, offsets)
    assert board.stats["reordering_segments"] == 4
    assert board.stats["reordering_selective"] == 1
    assert board.mark_retry(0, 9, 10)
    assert board.mark_retry(2, 9, 20)
    board.observe(WireAck(100, (), False, 30, 0xfffffff0), 1, offsets)
    assert board.stats["reordering_segments"] == 9
    assert board.stats["reordering_partial_timestamp"] == 1
    assert not board.stats["reordering_cumulative"]
    board.observe(WireAck(200, (), False, 30, 10), 2, offsets)
    assert board.stats["reordering_cumulative"] == 1
    assert board.stats["reordering_partial_timestamp"] == 1
    board.reset()
    assert board.stats["reordering_segments"] == 9 and board.reordering.episode is None
    assert board.reordering.ever_retried == 1
