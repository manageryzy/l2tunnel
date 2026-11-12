"""Passive per-segment TCP completion measurements with explicit censoring.

Place SegmentDeadlineObserver before an existing TCP class in its MRO, including
ObservedCoalescedACKTCP. All overrides must call super(). Construction schedules
no events, so MultiFlow and SharedCompactMultiFlow can still attach shared links.
Call deadline_metrics after the simulation has exhausted its configured drain.
"""

from math import isfinite

import numpy as np


PERCENTILES = (50, 95, 99)


class SegmentDeadlineObserver:
    """Retain completion timestamps indexed by the original TCP segment number.

    sent_times remains the sender's append-only original submission history.
    Retransmissions retain that origin. Delivery advances only with tcp_received,
    after TCP reassembly, and ACK completion advances only with tcp_acked.
    """

    def __init__(self, *args, **kwargs):
        self.segment_ack_completion_times = []
        self.segment_delivery_times = []
        super().__init__(*args, **kwargs)

    def on_ack(self, *args, **kwargs):
        before = self.tcp_acked
        if len(self.segment_ack_completion_times) != before:
            raise ValueError("ACK observer must cover the complete TCP lifetime")
        super().on_ack(*args, **kwargs)
        self.segment_ack_completion_times.extend([self.now] * (self.tcp_acked - before))

    def on_data(self, *args, **kwargs):
        before = self.tcp_received
        delay_count = len(self.forward.delays)
        if len(self.segment_delivery_times) != before:
            raise ValueError("delivery observer must cover the complete TCP lifetime")
        super().on_data(*args, **kwargs)
        advanced = self.tcp_received - before
        if len(self.forward.delays) - delay_count != advanced:
            raise ValueError("TCP delivery counter and per-segment delays disagree")
        self.segment_delivery_times.extend([self.now] * advanced)


def _quantiles(values, stem):
    quantiles = np.percentile(values, PERCENTILES) if len(values) else [None] * len(PERCENTILES)
    return {f"{stem}_p{percentile}_ms": None if value is None else float(value)
            for percentile, value in zip(PERCENTILES, quantiles)}


def _period_metrics(sent, completed, start, cutoff, submission_end, budget_ms, stem):
    latency = (completed - sent) * 1000
    observed = (completed >= start) & (completed <= cutoff)
    values = latency[observed]
    row = {stem + "_samples": int(observed.sum()),
           stem + "_exceeded_budget_fraction": float(np.mean(values > budget_ms)) if len(values) else None}
    row.update(_quantiles(values, stem))

    # The offered cohort includes every submission in its interval, even if the
    # segment has no delivery or ACK observation at the selected cutoff.
    cohort = (sent >= start) & (sent < submission_end)
    arrived = cohort & (completed <= cutoff)
    censored = cohort & ~arrived
    ages = (cutoff - sent) * 1000
    completed_late = int(np.count_nonzero(arrived & (latency > budget_ms)))
    censored_late = int(np.count_nonzero(censored & (ages > budget_ms)))
    offered_count, censored_count = int(cohort.sum()), int(censored.sum())
    unknown = censored_count - censored_late
    known_late = completed_late + censored_late
    prefix = stem + "_cohort"
    row.update({prefix + "_offered_segments": offered_count,
                prefix + "_completed_segments": int(arrived.sum()),
                prefix + "_censored_segments": censored_count,
                prefix + "_completed_exceeded_segments": completed_late,
                prefix + "_censored_exceeded_segments": censored_late,
                prefix + "_censored_within_budget_segments": unknown,
                prefix + "_miss_fraction_lower": known_late / offered_count if offered_count else None,
                prefix + "_miss_fraction_upper": (known_late + unknown) / offered_count if offered_count else None})
    row.update(_quantiles(latency[arrived], prefix + "_completed"))
    # An unresolved segment's age is a lower bound on its eventual latency.
    # These bounds include the censored tail without inventing completion times.
    lower_bounds = np.where(arrived[cohort], latency[cohort], ages[cohort])
    row.update(_quantiles(lower_bounds, prefix + "_latency_lower_bound"))
    return row


def deadline_metrics(sim, warmup_s=0.0, *, deadline_factor=1.5):
    """Pool segment observations across flows, retaining all offered segments.

    Unprefixed and steady quantiles select completion events in [0, duration]
    and [warmup, duration], matching payload_sizes.rtt_metrics. with_drain uses
    [0, duration + drain]. Their exceeded-budget fractions use completed samples.

    Cohort metrics instead select submissions in [0, duration) or, for steady,
    [warmup, duration). Both full and with_drain use the same offered cohort.
    Censoring is evaluated at the corresponding traffic or drain cutoff. Miss
    bounds divide by every offered segment, including unresolved segments. A
    pending segment older than the budget is already a known miss. Pending
    segments within the budget are unknown and contribute to the upper bound.
    Cohort completed quantiles are conditional on completion, while cohort
    latency_lower_bound quantiles also include unresolved segment ages.
    """
    duration = sim.traffic.duration_s
    if isinstance(warmup_s, bool) or not isfinite(warmup_s) or not 0 <= warmup_s < duration:
        raise ValueError("warmup_s must be finite and within the traffic interval")
    if isinstance(deadline_factor, bool) or not isfinite(deadline_factor) or deadline_factor <= 0:
        raise ValueError("deadline_factor must be finite and positive")
    flows = getattr(sim, "flows", [sim])
    if not flows or any(not isinstance(flow, SegmentDeadlineObserver) for flow in flows):
        raise ValueError("every TCP flow must use SegmentDeadlineObserver")
    if any(flow.traffic.duration_s != duration or flow.traffic.drain_s != sim.traffic.drain_s
           or flow.scenario.rtt_ms != sim.scenario.rtt_ms for flow in flows):
        raise ValueError("pooled flows must share traffic cutoffs and nominal RTT")
    sent = np.concatenate([np.asarray(flow.sent_times, dtype=float) for flow in flows])
    budget_ms = deadline_factor * sim.scenario.rtt_ms
    row = dict(latency_budget_ms=budget_ms, deadline_factor=deadline_factor,
               deadline_latency_origin="Original per-segment submission in sent_times, including retransmission waiting",
               deadline_window_definition="Quantiles use completion-event windows; cohort fields use submission windows",
               deadline_censoring_definition="Unresolved at each cutoff; lower miss bound includes overdue unresolved segments, upper bound includes all unresolved segments",
               deadline_flow_aggregation="Individual TCP segments pooled across flows with equal segment weight",
               deadline_delivery_definition="Contiguous TCP application delivery from tcp_received and forward.delays")
    for stem, attribute, counter in (("tcp_all_segment_ack_rtt", "segment_ack_completion_times", "tcp_acked"),
                                     ("tcp_application_delivery", "segment_delivery_times", "tcp_received")):
        records = []
        for flow in flows:
            times = getattr(flow, attribute)
            if len(times) != getattr(flow, counter) or len(times) > len(flow.sent_times):
                raise ValueError("per-segment completion history and TCP counters disagree")
            values = np.full(len(flow.sent_times), np.nan)
            values[:len(times)] = times
            if np.any(values[:len(times)] < np.asarray(flow.sent_times[:len(times)])):
                raise ValueError("a segment cannot complete before its original submission")
            records.append(values)
        completed = np.concatenate(records)
        for prefix, start, cutoff in (("", 0, duration), ("steady_", warmup_s, duration),
                                       ("with_drain_", 0, duration + sim.traffic.drain_s)):
            row.update(_period_metrics(sent, completed, start, cutoff, duration, budget_ms, prefix + stem))
    return row
