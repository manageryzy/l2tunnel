"""Observe SACK and timestamp reordering evidence. Loss detection is a separate policy."""


class ReorderingObserver:
    """Measure byte displacement in SMSS units, as in Linux tcp_check_sack_reordering."""

    def __init__(self, smss, stats, maximum=300):
        if smss <= 0 or maximum < 3:
            raise ValueError("invalid reordering observer geometry")
        self.smss = smss
        self.maximum = maximum
        self.stats = stats
        self.stats["reordering_segments"] = 3
        self.ever_retried = 0
        self.episode = None

    def retry(self, relative, recovery_end, timestamp):
        self.ever_retried |= 1 << relative
        if self.episode is None and recovery_end is not None and timestamp is not None:
            self.episode = recovery_end, timestamp

    def note(self, low, high, evidence):
        if low >= high:
            return
        distance = (high - low + self.smss - 1) // self.smss
        self.stats["reordering_segments"] = max(self.stats["reordering_segments"], min(self.maximum, distance))
        self.stats[evidence] += 1

    def observe(self, offsets, old_base, prior_sacks, base, sacked, live_retries, ack):
        advance = base - old_base
        width = prior_sacks.bit_length()
        # Linux checks newly SACKed originals and newly cumulative originals
        # separately. In both cases the low segment was below the prior FACK.
        remaining = max(0, width - advance)
        selective = (sacked & ((1 << remaining) - 1)) << advance
        cumulative = (1 << min(advance, width)) - 1
        high = offsets[base + sacked.bit_length()]
        for candidates, source in ((selective, "reordering_selective"), (cumulative, "reordering_cumulative")):
            holes = candidates & ~(prior_sacks | self.ever_retried)
            if holes:
                first = old_base + (holes & -holes).bit_length() - 1
                self.note(offsets[first], high, source)
        self.ever_retried >>= advance
        if self.episode is None:
            return
        recovery_end, first_retry_tick = self.episode
        if base >= recovery_end:
            self.episode = None
        elif advance and ack.tsecr and 0 < (first_retry_tick - ack.tsecr) % 2**32 < 2**31:
            # A partial ACK echoing a pre-retry timestamp is evidence of a
            # delayed original, even if that cumulative range was retransmitted.
            self.note(offsets[old_base], high, "reordering_partial_timestamp")
            if not live_retries:
                self.episode = None
