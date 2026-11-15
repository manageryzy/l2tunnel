#!/usr/bin/env python3
"""Finite behavioral oracle from maintained simulator methods, not copied ARQ.

This deliberately does not call Simulation.run/produce or run a sweep/test suite.
Actual Simulation.send reserves every scripted serialization finish. Its genuine
protocol callbacks are delivered at explicit times, and actual scheduled feedback
timers (including cancelled generations) are invoked. Network departure callbacks
and unrelated TCP production are not run. Requested modeled IP costs are recorded
separately from the new Rust v2 byte codec and are never called byte parity.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
from heapq import heapify
import json
from pathlib import Path
import sys

ROOT = next(parent for parent in Path(__file__).resolve().parents
            if (parent / "simulator/src/l2tunnel_sim/compact_arq.py").is_file())
DATA = ROOT / "crates/l2tunnel-recovery/tests/data/compact-arq"
RUST_OUTPUT = ROOT / "crates/l2tunnel-recovery/src/arq/compact/python_events.rs"
SOURCES = [
    "simulator/src/l2tunnel_sim/compact.py",
    "simulator/src/l2tunnel_sim/compact_arq.py",
    "simulator/src/l2tunnel_sim/compact_lowlatency.py",
    "simulator/src/l2tunnel_sim/model.py",
    "simulator/src/l2tunnel_sim/config.py",
    "simulator/src/l2tunnel_sim/coding.py",
]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "simulator/src"))
from l2tunnel_sim.compact import CompactConfig, CompactSimulation
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.compact_lowlatency import FirstFlightARQTransport, BoundedGapARQTransport
from l2tunnel_sim.config import Scenario, Traffic, PathConfig, Strategy


def ns(seconds):
    """Output quantization only; no timing/estimator formula is implemented here."""
    return round(seconds * 1_000_000_000)


def seconds(nanos):
    return nanos / 1_000_000_000


def closure(callback):
    return dict(zip(callback.__code__.co_freevars,
                    (cell.cell_contents for cell in callback.__closure__ or ())))


class Oracle(CompactSimulation):
    def __init__(self, name, transport_type, feedback_ms=5):
        self.transport_type = transport_type
        self.name = name
        self.outputs = []
        self.data = []
        self.feedback = []
        self.finishes = deque()
        self.active_finish = None
        # Small but valid model geometry deliberately leaves one bitmap byte:
        # MTU128 - (model fixed52 + explicitly modeled authentication75) =1.
        # These are modeled costs, not a selected Rust crypto/tag declaration.
        super().__init__(Scenario(70, 0, mtu=128),
                         Traffic(duration_s=1, drain_s=1, frame_bytes=1, payload_bytes=1),
                         (PathConfig(),), Strategy("finite Compact oracle"), 71,
                         CompactConfig(repair_ratio=0, block_sources=16,
                                       feedback_ms=feedback_ms, feedback_packets=64,
                                       authentication_bytes=75, header_profile="full_l2"))
        for direction in self.links:
            for link in direction:
                link.finish = lambda _now, _size: self.active_finish
        self.events_out = []

    def make_transports(self, _rng):
        return (self.transport_type(self, False, self.compact_config),
                self.transport_type(self, True, self.compact_config))

    def send(self, reverse, size, kind, receive):
        if not self.finishes:
            raise ValueError(f"unscripted actual output: {self.name} {self.now} {kind}")
        self.active_finish = seconds(self.finishes.popleft())
        if self.active_finish < self.now:
            raise ValueError("physical finish precedes the actual send operation")
        finish, rtt = super().send(reverse, size, kind, receive)
        captured = closure(receive)
        entry = {"kind": kind, "accepted_ns": ns(finish), "modeled_ip_bytes": size}
        if kind in ("source", "retry"):
            entry.update(source=captured["source"].index, serial=captured["serial"],
                         payload_bytes=captured["source"].size)
            self.data.append((entry, receive))
        elif kind == "feedback":
            entry.update({key: captured[key] for key in
                          ("prefix", "start", "count", "bitmap", "echo", "delay_us", "serial")})
            self.feedback.append((entry, receive))
        else:
            raise ValueError(f"unexpected actual output kind {kind}")
        self.outputs.append(entry)
        return finish, rtt

    def snapshot(self):
        t = self.forward
        current_timers = [when for when, _, callback, args in self.events
                          if getattr(callback, "__self__", None) is t
                          and callback.__name__ == "_feedback"
                          and args == (t.feedback_generation,)]
        return {
            "base": t.base,
            "flights": [{"source": source, "serial": flight.serial,
                         "attempts": flight.attempts, "accepted_ns": ns(flight.sent_at),
                         "retry_ns": ns(flight.retry_at)}
                        for source, flight in sorted(t.flights.items())],
            "history": [(serial, ns(at)) for serial, at in sorted(t.transmission_times.items())],
            "sampled": t.sampled_serial, "srtt": t.srtt,
            "rttvar": t.rttvar if t.rttvar is not None else 0.0,
            "rto_ns": ns(t._rto()),
            "prefix": t.received_prefix, "feedback_cursor": t.bitmap_cursor,
            "feedback_serial": t.sent_feedback_serial,
            "received_feedback_serial": t.received_feedback_serial,
            "feedback_events": t.feedback_events, "feedback_repeats": t.feedback_repeats,
            "feedback_due_ns": ns(min(current_timers)) if t.feedback_pending else None,
            "data_outputs": len(self.data), "feedback_outputs": len(self.feedback),
        }

    def event(self, at_ns, operation, argument=0, finishes=()):
        self.now = seconds(at_ns)
        self.finishes = deque(finishes)
        before = len(self.outputs)
        t = self.forward
        if operation == "source":
            # This invokes actual full-L2 record admission/flush and _source.
            t.submit(1, 1, lambda: None)
            t.flush()
        elif operation == "source_receipt":
            self.data[argument][1]()
        elif operation == "feedback_receipt":
            self.feedback[argument][1]()
        elif operation == "timeout":
            t._timeout(argument, t.flights[argument].serial)
        elif operation == "feedback_timer":
            timers = [entry for entry in self.events
                      if abs(entry[0] - self.now) < 1e-12
                      and getattr(entry[2], "__self__", None) is t
                      and entry[2].__name__ == "_feedback"]
            if not timers:
                raise ValueError(f"no actual feedback timer at {at_ns}: {self.name}")
            for entry in sorted(timers):
                self.events.remove(entry)
                entry[2](*entry[3])
            heapify(self.events)
        else:
            raise ValueError(operation)
        if self.finishes:
            raise ValueError(f"unused scripted physical outputs: {self.name} {operation}")
        self.events_out.append({"at_ns": at_ns, "operation": operation, "argument": argument,
                                "outputs": self.outputs[before:], "expected": self.snapshot()})

    def trace(self):
        return {"name": self.name, "mode": self.transport_type.__name__,
                "nominal_ns": ns(self.forward.nominal_rtt),
                "feedback_ns": ns(self.compact_config.feedback_ms / 1000),
                "feedback_packets": self.compact_config.feedback_packets,
                "bitmap_bytes": self.scenario.mtu - 52 - self.compact_config.authentication_bytes,
                "events": self.events_out}


def originals(sim, count):
    for source in range(count):
        at = source * 2_000_000
        sim.event(at, "source", finishes=[at + 1_000_000])


def rtt_trace():
    s = Oracle("rtt_stale_feedback_newer_echo_and_retransmission", CompactARQTransport)
    originals(s, 2)
    s.event(40_000_000, "source_receipt", 1)
    s.event(45_000_000, "feedback_timer", finishes=[46_000_000])
    s.event(50_000_000, "source_receipt", 0)
    s.event(50_000_000, "feedback_timer", finishes=[51_000_000])
    s.event(55_000_000, "feedback_timer", finishes=[56_000_000])
    s.event(60_000_000, "feedback_timer", finishes=[61_000_000])
    s.event(80_000_000, "feedback_receipt", 1)
    s.event(90_000_000, "feedback_receipt", 0)
    s.event(100_000_000, "source", finishes=[101_000_000])
    due = ns(s.forward.flights[2].retry_at)
    s.event(due, "timeout", 2, finishes=[due + 1_000_000])
    s.event(due + 35_000_000, "source_receipt", 3)
    s.event(due + 40_000_000, "feedback_timer", finishes=[due + 41_000_000])
    s.event(due + 75_000_000, "feedback_receipt", 4)
    return s.trace()


def fast_trace(transport):
    s = Oracle("guarded" if transport is CompactARQTransport else "first_flight_then_original_guard", transport)
    originals(s, 4)
    for index in (1, 2, 3):
        s.event(30_000_000, "source_receipt", index)
    accelerated = transport is FirstFlightARQTransport
    s.event(35_000_000, "feedback_timer", finishes=[36_000_000])
    s.event(40_000_000, "feedback_receipt", 0,
            finishes=[41_000_000] if accelerated else [])
    s.event(40_000_000, "feedback_timer", finishes=[41_000_000])
    s.event(42_000_000, "source", finishes=[43_000_000])
    last_source = len(s.data) - 1
    s.event(45_000_000, "feedback_timer", finishes=[46_000_000])
    s.event(65_000_000, "source_receipt", last_source)
    s.event(70_000_000, "feedback_timer", finishes=[71_000_000])
    s.event(75_000_000, "feedback_receipt", 3)
    s.event(75_000_000, "feedback_timer", finishes=[76_000_000])
    s.event(80_000_000, "feedback_timer", finishes=[81_000_000])
    s.event(90_000_000, "feedback_receipt", 4,
            finishes=[] if accelerated else [91_000_000])
    s.event(122_000_000, "feedback_receipt", 5,
            finishes=[123_000_000] if accelerated else [])
    return s.trace()


def duplicate_trace():
    s = Oracle("duplicate_three_reports_rotating_bitmap", CompactARQTransport)
    originals(s, 12)
    s.event(40_000_000, "source_receipt", 9)
    for at in (45, 50, 55):
        s.event(at * 1_000_000, "feedback_timer", finishes=[(at + 1) * 1_000_000])
    s.event(60_000_000, "source_receipt", 9)
    for at in (65, 70, 75):
        s.event(at * 1_000_000, "feedback_timer", finishes=[(at + 1) * 1_000_000])
    return s.trace()


def gap_trace():
    s = Oracle("bounded_gap_uses_any_last_feedback_and_cancels_old_timer", BoundedGapARQTransport, 10)
    originals(s, 12)
    for source in (1, 3):
        s.event(30_000_000, "source_receipt", source)
    s.event(30_000_000, "source_receipt", 4, finishes=[31_000_000])
    s.event(31_000_000, "source_receipt", 5)
    s.event(32_000_000, "source_receipt", 0)
    s.event(35_000_000, "source_receipt", 6, finishes=[36_000_000])
    s.event(40_000_000, "feedback_timer")
    s.event(41_000_000, "source_receipt", 6)
    s.event(45_000_000, "feedback_timer", finishes=[46_000_000])
    s.event(46_000_000, "source_receipt", 2)
    for source in (8, 9, 10):
        s.event(47_000_000, "source_receipt", source)
    s.event(50_000_000, "source_receipt", 11, finishes=[51_000_000])
    return s.trace()


def rust_float(value):
    return "None" if value is None else f"Some({value!r})"


def rust_literals(traces):
    text = ["// Generated from actual Python methods by generate.py; do not hand edit.\n",
            "use super::{Event, Expected, Flight, Operation, Output, Trace};\n",
            "#[rustfmt::skip]\n",
            "pub(super) const TRACES: &[Trace] = &[\n"]
    modes = {"CompactARQTransport": 1, "FirstFlightARQTransport": 2, "BoundedGapARQTransport": 3}
    ops = {"source": "Source", "source_receipt": "SourceReceipt", "feedback_receipt": "FeedbackReceipt",
           "timeout": "Timeout", "feedback_timer": "FeedbackTimer"}
    for trace in traces:
        text.append(f'    Trace {{ name: "{trace["name"]}", mode: {modes[trace["mode"]]}, feedback_ns: {trace["feedback_ns"]}, events: &[\n')
        for event in trace["events"]:
            text.append(f'        Event {{ at: {event["at_ns"]}, op: Operation::{ops[event["operation"]]}, argument: {event["argument"]}, outputs: &[\n')
            for output in event["outputs"]:
                if output["kind"] == "feedback":
                    text.append("            Output::Feedback { " + ", ".join(
                        f"{field}: {output[key]}" for field, key in [("prefix", "prefix"), ("start", "start"),
                        ("count", "count"), ("bitmap", "bitmap"), ("echo", "echo"), ("delay_us", "delay_us"),
                        ("serial", "serial")]) + " },\n")
                else:
                    text.append(f'            Output::Source {{ source: {output["source"]}, serial: {output["serial"]}, accepted: {output["accepted_ns"]} }},\n')
            e = event["expected"]
            text.append("        ], expected: Expected { " + ", ".join(f"{key}: {e[key]}" for key in
                ("base", "sampled", "rto_ns", "prefix", "feedback_cursor", "feedback_serial", "received_feedback_serial",
                 "feedback_events", "feedback_repeats", "data_outputs", "feedback_outputs")) +
                f', srtt: {rust_float(e["srtt"])}, rttvar: {e["rttvar"]!r}, feedback_due: ' +
                ("None" if e["feedback_due_ns"] is None else f'Some({e["feedback_due_ns"]})') + ", flights: &[\n")
            for flight in e["flights"]:
                text.append("            Flight { " + ", ".join(f"{key}: {value}" for key, value in flight.items()) + " },\n")
            text.append("        ], history: &[" + ", ".join(f"({serial}, {at})" for serial, at in e["history"]) + "] } },\n")
        text.append("    ] },\n")
    text.append("];\n")
    return "".join(text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify current source pins and exact generated files")
    parser.add_argument("--data-dir", type=Path, default=DATA)
    parser.add_argument("--rust-output", type=Path, default=RUST_OUTPUT)
    args = parser.parse_args()
    provenance = {source: hashlib.sha256((ROOT / source).read_bytes()).hexdigest() for source in SOURCES}
    pin_file = args.data_dir / "source-pins.json"
    if not pin_file.exists() or json.loads(pin_file.read_text()) != provenance:
        raise ValueError("actual simulator sources differ from the frozen differential source pins")
    traces = [rtt_trace(), fast_trace(CompactARQTransport), fast_trace(FirstFlightARQTransport),
              duplicate_trace(), gap_trace()]
    payload = {"status": "generated_finite_python_behavior_not_rust_execution", "source_sha256": provenance,
               "harness": "actual classes, actual Simulation.send, injected Link.finish, explicit genuine callbacks/timers",
               "scope": "five small event traces; no simulation sweep, kernel performance or Rust v2 byte parity",
               "traces": traces}
    output_json = json.dumps(payload, indent=2, allow_nan=False) + "\n"
    output_rust = rust_literals(traces)
    json_path = args.data_dir / "python-events.json"
    if args.check:
        if not json_path.exists() or json_path.read_text() != output_json:
            raise SystemExit("Compact behavioral JSON differs from actual pinned Python methods")
        if not args.rust_output.exists() or args.rust_output.read_text() != output_rust:
            raise SystemExit("Compact Rust event literals differ from actual pinned Python methods")
    else:
        args.data_dir.mkdir(parents=True, exist_ok=True)
        args.rust_output.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(output_json)
        args.rust_output.write_text(output_rust)
    print(json.dumps({"mode": "check" if args.check else "generate", "traces": len(traces),
                      "events": sum(len(trace["events"]) for trace in traces),
                      "outputs": sum(len(event["outputs"]) for trace in traces for event in trace["events"])}, sort_keys=True))


if __name__ == "__main__":
    main()
