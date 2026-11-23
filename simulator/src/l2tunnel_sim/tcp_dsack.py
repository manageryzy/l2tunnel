"""Use received TCP duplicate SACKs to prove one entire fast recovery redundant."""
from bisect import bisect_left
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass
class Episode:
    first: int
    end: int
    cwnd: float
    ssthresh: float
    cubic_prior: float
    cubic_max: float
    unproven: set = field(default_factory=set)
    sent: bool = False


class DuplicateUndo:
    """Conservative single-episode comparison based on RFC 3708 section 3.

    Only one retransmission per segment can be proved. An unrecognized
    duplicate disables future undo, including one outside bounded history.
    The sender uses its own segment offsets and delivered wire ACKs.
    """
    def __init__(self, capacity, stats):
        self.capacity = capacity
        self.stats = stats
        self.history = OrderedDict()
        self.highest_retry = -1
        self.episode = None
        self.disabled = False

    def begin(self, flow):
        self.episode = None
        if self.disabled:
            return
        first, end = flow.tcp_acked, len(flow.sent_times)
        if not 0 < end - first <= self.capacity:
            return
        # A higher segment retransmitted during a preceding recovery has
        # ambiguous delivery evidence if it is still outstanding at entry.
        if self.highest_retry >= first:
            self.stats["dsack_overlapping_flight"] += 1
            return
        self.episode = Episode(first, end, flow.cwnd, flow.ssthresh,
                               flow.cubic_prior, flow.cubic_max)

    def retry(self, index, prior_attempts):
        if self.disabled:
            return
        self.highest_retry = max(self.highest_retry, index)
        self.history[index] = prior_attempts
        self.history.move_to_end(index)
        if len(self.history) > self.capacity:
            self.history.popitem(last=False)
        e = self.episode
        if e is None:
            return
        if prior_attempts != 1 or not e.first <= index < e.end:
            self.stats["dsack_ambiguous_retry"] += 1
            self.episode = None
            return
        e.sent = True
        e.unproven.add(index)

    def observe(self, ack, offsets, scoreboard, una):
        if not ack.dsack or self.disabled:
            return
        lo, hi = ack.ranges[0]
        first, end = bisect_left(offsets, lo), bisect_left(offsets, hi)
        if (end >= len(offsets) or end <= first or end - first > self.capacity
                or offsets[first] != lo or offsets[end] != hi):
            self.episode = None
            return
        for index in range(first, end):
            attempts = self.history.get(index)
            if attempts is None:
                self.disabled = True
                self.episode = None
                self.stats["dsack_unrecognized_duplicate"] += 1
                return
            if attempts > 1 or (not scoreboard.sacked and offsets[una] == lo):
                self.episode = None
        if self.episode is not None:
            self.episode.unproven.difference_update(range(first, end))

    def finish(self, flow):
        e = self.episode
        if (e is None or not e.sent or e.unproven or flow.in_recovery
                or flow.tcp_acked < e.end):
            return False
        self.episode = None
        flow.cwnd = min(flow.window_limit, max(e.cwnd, flow.cwnd))
        flow.ssthresh = max(e.ssthresh, flow.ssthresh)
        flow.cubic_prior, flow.cubic_max = e.cubic_prior, e.cubic_max
        flow.cubic_epoch = None
        self.stats["dsack_proven_recoveries"] += 1
        return True
