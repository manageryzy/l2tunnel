from collections import Counter
from types import SimpleNamespace

from l2tunnel_sim.tcp_dsack import DuplicateUndo
from l2tunnel_sim.tcp_sack import WireAck


def setup():
    flow = SimpleNamespace(tcp_acked=3, sent_times=[0] * 9, cwnd=14, ssthresh=24,
                           cubic_prior=12, cubic_max=10, in_recovery=True, window_limit=32)
    undo = DuplicateUndo(8, Counter())
    undo.begin(flow)
    flow.cwnd, flow.ssthresh = 7, 9
    return flow, undo


def observe(undo, first, end, *, scoreboard=1, una=3):
    ack = WireAck(10, ((first, end),), True, 321, 123)
    undo.observe(ack, list(range(12)), SimpleNamespace(sacked=scoreboard), una)


def test_every_distinct_retry_requires_duplicate_and_full_cumulative_coverage():
    flow, undo = setup()
    undo.retry(3, 1)
    undo.retry(5, 1)
    observe(undo, 3, 4)
    observe(undo, 3, 4)
    flow.tcp_acked = 9
    flow.in_recovery = False
    assert not undo.finish(flow) and flow.cwnd == 7
    observe(undo, 5, 6)
    flow.tcp_acked = 8
    assert not undo.finish(flow)
    flow.tcp_acked = 9
    flow.in_recovery = True
    assert not undo.finish(flow)
    flow.in_recovery = False
    assert undo.finish(flow)
    assert (flow.cwnd, flow.ssthresh, flow.cubic_prior, flow.cubic_max) == (14, 24, 12, 10)
    assert not undo.finish(flow)


def test_second_retransmission_and_old_unacknowledged_retry_disarm_episode():
    flow, undo = setup()
    undo.retry(5, 1)
    undo.retry(5, 2)
    assert undo.episode is None
    flow.tcp_acked = 4
    undo.begin(flow)
    assert undo.episode is None
    flow.tcp_acked = 6
    undo.begin(flow)
    assert undo.episode is not None
    observe(undo, 5, 6)
    assert undo.episode is None


def test_known_delayed_reports_unrecognized_duplicates_and_empty_scoreboard():
    flow, undo = setup()
    undo.retry(3, 1)
    flow.tcp_acked = 4
    undo.begin(flow)
    undo.retry(4, 1)
    observe(undo, 3, 4)
    assert undo.episode.unproven == {4}
    observe(undo, 4, 5, scoreboard=0, una=4)
    assert undo.episode is None and not undo.disabled
    observe(undo, 8, 9)
    assert undo.disabled
    flow.tcp_acked = 7
    undo.begin(flow)
    assert undo.episode is None


def test_history_bound_and_evicted_ambiguous_duplicate():
    flow, undo = setup()
    for i in range(15):
        undo.retry(i, 1)
    assert len(undo.history) == 8
    observe(undo, 1, 2)
    assert undo.disabled
