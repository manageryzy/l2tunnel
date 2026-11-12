"""Passively attribute aligned-record latency without changing protocol events.

Every segment retains its original TCP submission time, including retransmits.
The additive chain uses the first record actually delivered for that segment.
Record readiness means all its source bytes are known, even if an earlier
channel record prevents decoding. The existing all-segment deadline metrics
remain the authoritative latency and censoring measurements.
"""

import argparse
from collections import defaultdict, deque
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from functools import wraps
from hashlib import sha256
import json
from pathlib import Path
from unittest.mock import patch

import numpy as np

from l2tunnel_sim.aligned_records import AlignedRecordTransport

import shared_record_deadlines as normal


def _stable(value):
    if callable(value):
        return value.__qualname__
    if isinstance(value, (tuple, list)):
        return [_stable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _stable(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported event argument {type(value)}")


def _update_digest(digest, value):
    digest.update(json.dumps(_stable(value), separators=(",", ":"), sort_keys=True).encode())
    digest.update(b"\n")


class EventAudit:
    """Hash admitted and dispatched events without adding any scheduled event."""

    def __init__(self, sim):
        self.scheduled = sha256()
        self.dispatched = sha256()
        self.schedule_count = 0
        self.dispatch_count = 0
        for channel, flow in enumerate(sim.flows):
            self._attach(flow, channel)

    def _attach(self, flow, channel):
        original = flow.at

        @wraps(original)
        def at(when, callback, *args):
            if when > flow.stop_at:
                return original(when, callback, *args)
            event = (channel, when, callback.__qualname__, args)
            _update_digest(self.scheduled, event)
            self.schedule_count += 1

            @wraps(callback)
            def dispatch(*values):
                _update_digest(self.dispatched, (channel, flow.now, callback.__qualname__, values))
                self.dispatch_count += 1
                return callback(*values)

            return original(when, dispatch, *args)

        flow.at = at

    def result(self, sim):
        state = sha256()
        for channel, flow in enumerate(sim.flows):
            _update_digest(state, (channel, flow.sent_times, flow.segment_delivery_times,
                                  flow.segment_ack_completion_times, flow.tcp_received,
                                  flow.tcp_acked, flow.cwnd, flow.wire, flow.datagrams))
        for direction in sim.links:
            for link in direction:
                _update_digest(state, (link.free_at, link.erasures.rng.getstate(),
                                      link.erasures.bad, link.jitter_rng.getstate()))
        return dict(scheduled_sha256=self.scheduled.hexdigest(),
                    dispatched_sha256=self.dispatched.hexdigest(),
                    scheduled_events=self.schedule_count, dispatched_events=self.dispatch_count,
                    final_flow_state_sha256=state.hexdigest())


class StageProbe:
    """Observe normal synchronous record submission and asynchronous delivery.

    The probe neither calls send/at nor changes a clock, RNG or protocol field.
    Sender-side bookkeeping labels submitted records for later analysis only.
    It is never consulted by a scheduling, decoding or TCP decision.
    """

    def __init__(self, sim):
        self.sim = sim
        self.transport = sim.shared_forward
        if not isinstance(self.transport, AlignedRecordTransport):
            raise ValueError("stage probe requires the aligned-record transport")
        if self.transport.sources or self.transport.callbacks:
            raise ValueError("attach the stage probe before any submission")
        self.records = {}
        self.sources = {}
        self.queue = deque()
        self.active_segment = None
        self.active_record = None
        self.attempts = defaultdict(int)
        self.first_records = {}
        self.original_records = {}
        for channel, flow in enumerate(sim.flows):
            self._attach_flow(flow, channel)
        for name in ("_submit_record", "_queue_source", "_aligned_source", "_new_known", "_receive_source"):
            original = getattr(self.transport, name)
            observer = getattr(self, name)

            @wraps(original)
            def wrapped(*args, _original=original, _observer=observer, **kwargs):
                return _observer(_original, *args, **kwargs)

            setattr(self.transport, name, wrapped)
        original_receive = self.transport.receiver.receive

        @wraps(original_receive)
        def receive(index, data):
            delivered = original_receive(index, data)
            for channel, serial, frame in delivered:
                record = self.records[channel, serial]
                record["channel_delivery_s"] = self.sim.now
                record["release_source_id"] = index
                if frame is not None:
                    self.first_records.setdefault((channel, record["segment_id"]), record)
            return delivered

        self.transport.receiver.receive = receive

    def _attach_flow(self, flow, channel):
        original = flow.transmit_segment

        @wraps(original)
        def transmit(index):
            previous = self.active_segment
            self.attempts[channel, index] += 1
            self.active_segment = (channel, index, self.attempts[channel, index])
            try:
                return original(index)
            finally:
                self.active_segment = previous

        flow.transmit_segment = transmit

    def _submit_record(self, original, channel, serial, body):
        if self.active_segment is None or self.active_segment[0] != channel:
            raise ValueError("record submission must originate from a labeled TCP segment")
        _, segment, attempt = self.active_segment
        record = dict(flow_id=channel, record_serial=serial, segment_id=segment,
                      attempt=attempt, is_context=body[0] == 0, codec_kind=body[0],
                      record_bytes=len(body), record_enqueue_s=self.sim.now, sources=[])
        self.records[channel, serial] = record
        if not record["is_context"]:
            self.original_records.setdefault((channel, segment), record)
        previous = self.active_record
        self.active_record = record
        try:
            return original(channel, serial, body)
        finally:
            self.active_record = previous

    def _queue_source(self, original, payload):
        if self.active_record is None:
            raise ValueError("source queued outside a record submission")
        source = dict(record=self.active_record, enqueue_s=self.sim.now,
                      source_id=None, protected_bytes=len(payload))
        self.active_record["sources"].append(source)
        self.queue.append(source)
        return original(payload)

    def _aligned_source(self, original, payload):
        source = self.queue.popleft()
        source_id = len(self.transport.sources)
        source["source_id"] = source_id
        self.sources[source_id] = source
        result = original(payload)
        source["transmission_finish_s"] = self.transport.last_source_at
        return result

    def _receive_source(self, original, source):
        self.sources[source.index].setdefault("systematic_arrival_s", self.sim.now)
        return original(source)

    def _new_known(self, original, symbols):
        # Record all newly solved bytes before normal delivery can run callbacks.
        touched = set()
        for index in symbols:
            source = self.sources[index]
            source["known_s"] = self.sim.now
            source["recovered"] = index not in self.transport.received_source
            record = source["record"]
            touched.add((record["flow_id"], record["record_serial"]))
        for key in touched:
            record = self.records[key]
            if "record_ready_s" not in record and all("known_s" in source for source in record["sources"]):
                record["record_ready_s"] = self.sim.now
                record["hol_blocker_serial"] = self.transport.receiver.expected[record["flow_id"]]
        return original(symbols)

    def segment_rows(self):
        rows = []
        duration = self.sim.traffic.duration_s
        cutoff = duration + self.sim.traffic.drain_s
        for channel, flow in enumerate(self.sim.flows):
            for segment, sent_at in enumerate(flow.sent_times):
                row = dict(flow_id=channel, segment_id=segment, original_submission_s=sent_at,
                           attempts=self.attempts[channel, segment])
                record = self.first_records.get((channel, segment))
                # Unreleased originals remain visible, including partially queued fragments.
                if record is None:
                    record = self.original_records.get((channel, segment))
                row.update(self._record_stages(record))
                row["tcp_contiguous_delivery_s"] = (flow.segment_delivery_times[segment]
                    if segment < len(flow.segment_delivery_times) else None)
                row["cumulative_ack_completion_s"] = (flow.segment_ack_completion_times[segment]
                    if segment < len(flow.segment_ack_completion_times) else None)
                row["submission_to_source_enqueue_ms"] = _difference(row.get("source_enqueue_s"), sent_at)
                row["source_queue_and_serialization_ms"] = _difference(
                    row.get("last_source_transmission_finish_s"), row.get("source_enqueue_s"))
                row["propagation_and_recovery_ms"] = _difference(
                    row.get("record_ready_s"), row.get("last_source_transmission_finish_s"))
                row["ordered_channel_hol_ms"] = _difference(
                    row.get("channel_delivery_s"), row.get("record_ready_s"))
                row["tcp_reassembly_hol_ms"] = _difference(
                    row["tcp_contiguous_delivery_s"], row.get("channel_delivery_s"))
                row["application_to_ack_ms"] = _difference(
                    row["cumulative_ack_completion_s"], row["tcp_contiguous_delivery_s"])
                row["all_segment_ack_rtt_ms"] = _difference(row["cumulative_ack_completion_s"], sent_at)
                for name, boundary in (("traffic", duration), ("end", cutoff)):
                    row[name + "_delivery_censored"] = (row["tcp_contiguous_delivery_s"] is None
                                                       or row["tcp_contiguous_delivery_s"] > boundary)
                    row[name + "_ack_censored"] = (row["cumulative_ack_completion_s"] is None
                                                  or row["cumulative_ack_completion_s"] > boundary)
                rows.append(row)
        return rows

    def _record_stages(self, record):
        if record is None:
            return {}
        sources = record["sources"]
        finishes = [source.get("transmission_finish_s") for source in sources]
        recovered = sum(source.get("recovered", False) for source in sources)
        result = {key: record.get(key) for key in ("record_serial", "attempt", "record_ready_s",
                  "channel_delivery_s", "hol_blocker_serial", "release_source_id")}
        result.update(source_count=len(sources), recovered_sources=recovered,
                      source_ids=" ".join(str(source["source_id"]) for source in sources),
                      source_enqueue_s=min(source["enqueue_s"] for source in sources),
                      last_source_transmission_finish_s=(max(finishes) if all(value is not None for value in finishes)
                                                         else None),
                      all_sources_known=all("known_s" in source for source in sources),
                      all_sources_systematic=all("known_s" in source and not source["recovered"] for source in sources))
        blocker = self.records.get((record["flow_id"], record.get("hol_blocker_serial")))
        result["hol_blocker_is_context"] = blocker["is_context"] if blocker else None
        result["hol_blocker_segment_id"] = blocker["segment_id"] if blocker else None
        result["hol_blocker_ready_s"] = blocker.get("record_ready_s") if blocker else None
        return result

    def source_rows(self):
        return [dict(flow_id=source["record"]["flow_id"], record_serial=source["record"]["record_serial"],
                     segment_id=source["record"]["segment_id"], is_context=source["record"]["is_context"],
                     **{key: value for key, value in source.items() if key != "record"})
                for record in self.records.values() for source in record["sources"]]


def _difference(end, start):
    return None if end is None or start is None else (end - start) * 1000


STAGES = ("submission_to_source_enqueue_ms", "source_queue_and_serialization_ms",
          "propagation_and_recovery_ms", "ordered_channel_hol_ms", "tcp_reassembly_hol_ms",
          "application_to_ack_ms")


def summarize_stages(rows, budget_ms, rtt_ms):
    completed = [row for row in rows if row["all_segment_ack_rtt_ms"] is not None]
    latency = [row["all_segment_ack_rtt_ms"] for row in completed]
    p99 = float(np.percentile(latency, 99)) if latency else None
    cohorts = {"all_completed": completed,
               "over_budget": [row for row in completed if row["all_segment_ack_rtt_ms"] > budget_ms],
               "p99_tail": [row for row in completed if row["all_segment_ack_rtt_ms"] >= p99] if p99 else []}
    result = dict(offered_segments=len(rows), completed_segments=len(completed),
                  end_censored_segments=len(rows) - len(completed), all_segment_ack_p99_ms=p99,
                  budget_ms=budget_ms, cohorts={})
    for name, cohort in cohorts.items():
        entry = dict(segments=len(cohort), stages={})
        for stage in (*STAGES, "all_segment_ack_rtt_ms"):
            values = [row[stage] for row in cohort if row[stage] is not None]
            entry["stages"][stage] = dict(mean=float(np.mean(values)) if values else None,
                **{f"p{percentile}": float(np.percentile(values, percentile)) if values else None
                   for percentile in (50, 95, 99)})
        hol = [row for row in cohort if (row["ordered_channel_hol_ms"] or 0) > 1e-8]
        entry["ready_records_waiting_for_channel"] = len(hol)
        entry["systematic_records_waiting_for_channel"] = sum(row.get("all_sources_systematic", False) for row in hol)
        entry["own_record_recovered_segments"] = sum(row.get("recovered_sources", 0) > 0 for row in cohort)
        dominant = defaultdict(int)
        for row in cohort:
            excess = {stage: row[stage] or 0 for stage in STAGES}
            excess["propagation_and_recovery_ms"] = max(0, excess["propagation_and_recovery_ms"] - rtt_ms / 2)
            excess["application_to_ack_ms"] = max(0, excess["application_to_ack_ms"] - rtt_ms / 2)
            dominant[max(excess, key=excess.get)] += 1
        entry["largest_excess_stage_counts"] = dict(dominant)
        result["cohorts"][name] = entry
    return result


def observe(task, *, stages=True, audit=True):
    """Call the unchanged normal execute entry point with a scoped factory hook."""
    original_factory = normal.make_simulation
    captured = {}

    def make_simulation(value):
        sim = original_factory(value)
        captured["sim"] = sim
        if audit:
            captured["audit"] = EventAudit(sim)
        if stages:
            captured["probe"] = StageProbe(sim)
        return sim

    with patch.object(normal, "make_simulation", make_simulation):
        row = normal.execute(task)
    events = captured["audit"].result(captured["sim"]) if audit else None
    return row, captured.get("probe"), events


def write_csv(path, rows):
    if not rows:
        return
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _save_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def execute_saved(task, output):
    output = Path(output)
    row, probe, events = observe(task, stages=task["stage_instrumentation"])
    stem = f"{task['run_id']:05d}"
    if probe is not None:
        segments = probe.segment_rows()
        write_csv(output / "stages" / f"{stem}-segments.csv", segments)
        write_csv(output / "stages" / f"{stem}-sources.csv", probe.source_rows())
        _save_json(output / "stages" / f"{stem}-attribution.json",
                   summarize_stages(segments, row["latency_budget_ms"], task["rtt_ms"]))
    _save_json(output / "events" / f"{stem}.json", events)
    _save_json(output / "runs" / f"{stem}.json", row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--drain", type=float, default=20)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration or args.drain < 0:
        parser.error("require 0 <= warmup < duration and a nonnegative drain")
    selected = [task for task in json.loads(args.source_manifest.read_text())["tasks"]
                if task["profile"]["compact"]["repair_ratio"] == .208]
    if len(selected) != 3:
        raise ValueError("expected the three matched r20.8 seed tasks")
    tasks = []
    for source in selected:
        for enabled in (False, True):
            tasks.append(dict(source, run_id=len(tasks) + 1, duration_s=args.duration,
                              warmup_s=args.warmup, drain_s=args.drain, stage_instrumentation=enabled,
                              pilot=True, event_audit=True))
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), *(root / "studies" / name for name in (
        "shared_record_deadlines.py", "deadline_metrics.py", "latency_ack.py", "payload_sizes.py")),
        *sorted((root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(tasks=tasks, sources=hashes, source_manifest=str(args.source_manifest.resolve()),
        assumptions=["Each seed has an audited normal control and a passive stage-probe run",
                     "All protocol events and normal wire accounting retain the unchanged normal runner",
                     "Source and record labels are measurement-only and never enter protocol decisions",
                     "Readiness is all record bytes known; ordered delivery may wait on earlier channel records",
                     "Original TCP submission times and all censored segments are retained",
                     "GF256 coefficient elimination models recovery; repair payload arithmetic and CPU cost are excluded"])
    args.out.mkdir(parents=True, exist_ok=True)
    existing = args.out / "experiment.json"
    if existing.exists() and json.loads(existing.read_text()) != manifest:
        raise ValueError("existing tasks or source hashes differ")
    _save_json(existing, manifest)
    for directory in ("runs", "events", "stages"):
        (args.out / directory).mkdir(exist_ok=True)
    for path in files:
        copy = args.out / "sources" / path.relative_to(root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    pending = [task for task in tasks if not (args.out / "runs" / f"{task['run_id']:05d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute_saved, task, str(args.out)) for task in pending]):
            row = future.result()
            print(f"run {row['run_id']} goodput={row['application_goodput_mbps']:.3f} "
                  f"ACK99={row['with_drain_tcp_all_segment_ack_rtt_p99_ms']:.3f} "
                  f"confirmed={row['fully_confirmed']}", flush=True)
    rows = [json.loads((args.out / "runs" / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    write_csv(args.out / "replications.csv", rows)
    excluded = {"run_id", "stage_instrumentation", "compute_seconds"}
    comparisons = []
    for control, observed in zip(rows[::2], rows[1::2]):
        differences = [key for key in set(control) | set(observed)
                       if key not in excluded and control.get(key) != observed.get(key)]
        traces = [json.loads((args.out / "events" / f"{row['run_id']:05d}.json").read_text())
                  for row in (control, observed)]
        comparisons.append(dict(seed=control["seed"], control_run=control["run_id"],
                                probe_run=observed["run_id"], differing_metrics=differences,
                                identical_events_and_state=traces[0] == traces[1], **traces[0]))
    _save_json(args.out / "paired-equivalence.json", comparisons)
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    _save_json(args.out / "source-verification.json", dict(changed_during_run=changed))
    if changed or any(item["differing_metrics"] or not item["identical_events_and_state"] for item in comparisons):
        raise RuntimeError("source verification or passive-probe equivalence failed")


if __name__ == "__main__":
    main()
