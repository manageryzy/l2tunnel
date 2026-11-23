"""Independent transport connections sharing one duplex physical bottleneck.

Each flow owns its sequence space, acknowledgements, recovery, coding and
congestion state. All flows reference the same Link objects and event heap.
This differs from Strategy.streams, which only partitions delivery ordering.
"""

from collections import Counter
from dataclasses import replace
from heapq import heappop
from random import Random
from types import SimpleNamespace

from .experiment import measure, simulation_type


class MultiFlow:
    def __init__(self, scenario, traffic, paths, strategy, seed, flow_count,
                 *, window_policy="fixed_total", simulation_factory=None):
        if isinstance(flow_count, bool) or not isinstance(flow_count, int) or flow_count < 1:
            raise ValueError("flow_count must be a positive integer")
        if window_policy not in ("fixed_total", "fixed_per_flow"):
            raise ValueError("unknown window policy")
        total_slots = traffic.window_bytes // traffic.payload_bytes
        if window_policy == "fixed_total" and total_slots < flow_count:
            raise ValueError("fixed total window must hold at least one segment per flow")
        self.scenario = scenario
        self.traffic = traffic
        self.strategy = strategy
        self.flow_count = flow_count
        self.window_policy = window_policy
        self.seed = seed
        self.now = 0.0
        self.wire_at_measurement_end = None
        rng = Random(seed)
        self.flow_seeds = [seed] + [rng.getrandbits(64) for _ in range(flow_count - 1)]
        simulation = simulation_factory or simulation_type(strategy.mode)
        self.flows = []
        for index, flow_seed in enumerate(self.flow_seeds):
            slots = total_slots
            if window_policy == "fixed_total":
                slots = total_slots // flow_count + (index < total_slots % flow_count)
            flow_traffic = replace(traffic, window_bytes=slots * traffic.payload_bytes,
                                   frame_interval_ms=traffic.frame_interval_ms * flow_count)
            self.flows.append(simulation(scenario, flow_traffic, paths, strategy, flow_seed))
        first = self.flows[0]
        self.links = first.links
        self.events = first.events
        if any(flow.events for flow in self.flows):
            raise ValueError("transport initialization must finish before shared scheduling")
        for flow in self.flows:
            flow.links = self.links
            flow.events = self.events
            flow.sequence = first.sequence
        self.startup_order = list(range(flow_count))
        rng.shuffle(self.startup_order)
        for phase, index in enumerate(self.startup_order):
            self.flows[index].next_source = phase * traffic.frame_interval_ms / 1000

    def run(self):
        for index in self.startup_order:
            self.flows[index].produce()
        while self.events:
            when, _, callback, args = heappop(self.events)
            if self.wire_at_measurement_end is None and when > self.traffic.duration_s:
                self.wire_at_measurement_end = self._wire_totals()
            self.now = when
            for flow in self.flows:
                flow.now = when
            callback(*args)
        if self.wire_at_measurement_end is None:
            self.wire_at_measurement_end = self._wire_totals()
        return self

    def _wire_totals(self):
        return [sum(sum(flow.wire[direction].values()) for flow in self.flows)
                for direction in (False, True)]

    def measurements(self):
        """Measure aggregate bytes and delivery percentiles from all connections."""
        endpoints = []
        for attribute in ("forward", "reverse"):
            parts = [getattr(flow, attribute) for flow in self.flows]
            endpoints.append(SimpleNamespace(
                pending=range(sum(len(part.pending) for part in parts)),
                delays=[delay for part in parts for delay in part.delays],
                **{name: sum(getattr(part, name) for part in parts) for name in (
                    "pending_bytes", "peak_pending_bytes", "peak_reorder_bytes",
                    "delivered_bytes", "delivered_during_measurement_bytes", "recovered_symbols",
                )},
            ))
        totals = {name: sum(getattr(flow, name) for flow in self.flows)
                  for name in ("tcp_acked", "tcp_received", "tcp_payload_bytes")}
        aggregate = SimpleNamespace(
            scenario=self.scenario, traffic=self.flows[0].traffic, strategy=self.strategy,
            sent_times=range(sum(len(flow.sent_times) for flow in self.flows)),
            tcp_rtts=[rtt for flow in self.flows for rtt in flow.tcp_rtts],
            forward=endpoints[0], reverse=endpoints[1], **totals,
        )
        for name in ("wire", "datagrams", "erasures"):
            setattr(aggregate, name, [sum((getattr(flow, name)[direction] for flow in self.flows),
                                          Counter()) for direction in (False, True)])
        if self.strategy.mode == "quic":
            for name in ("quic_retransmitted_stream_bytes", "quic_cwnd_bytes"):
                setattr(aggregate, name, sum(getattr(flow, name) for flow in self.flows))
        segmented_payload = None
        if any(getattr(flow, "segment_offsets", None) is not None for flow in self.flows):
            segmented_payload = sum(flow.byte_offset(flow.tcp_received) for flow in self.flows)
        row = measure(aggregate, segmented_payload=segmented_payload)
        goodputs = [flow.tcp_payload_bytes for flow in self.flows]
        squares = sum(value * value for value in goodputs)
        row.update(
            flow_count=self.flow_count, window_policy=self.window_policy,
            total_window_bytes=sum(flow.traffic.window_bytes for flow in self.flows),
            jain_goodput_fairness=sum(goodputs) ** 2 / (self.flow_count * squares) if squares else None,
            forward_wire_bytes_during_measurement=self.wire_at_measurement_end[0],
            reverse_wire_bytes_during_measurement=self.wire_at_measurement_end[1],
        )
        return row

    def flow_measurements(self):
        return [dict(flow_id=index, seed=flow_seed, window_bytes=flow.traffic.window_bytes,
                     **measure(flow))
                for index, (flow_seed, flow) in enumerate(zip(self.flow_seeds, self.flows), 1)]
