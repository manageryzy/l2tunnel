"""Export each original in the slowest completed 1% of a frozen C48 TCP workload."""

import argparse
from collections import Counter
from copy import deepcopy
from gzip import GzipFile
from heapq import heappush, heapreplace
from io import TextIOWrapper
import json
from math import ceil
from pathlib import Path
import sys

from aggregate_ack_deadlines import execute
from l2tunnel_sim import packed_frame_path as paths
from packed_latency_study import bind, canonical
from packed_service_sensitivity import ROOT, digest, write


class FullTail(paths.PackedFramePath):
    """Retain exact earliest-completion tie order and only the largest K paths."""

    def __init__(self, sim, services, capacity):
        super().__init__(sim, services)
        if capacity < 1:
            raise ValueError("positive tail capacity required")
        self.capacity = capacity
        self.heap = []
        self.n_completed = self.n_eligible = 0
        self.release = {}
        self.gap_since = {}
        self.job_checks = 0
        self.request_sent_at = None
        self.retry = None
        self.source_release = None
        self.all_solver = Counter()
        self._observe_targeted(sim.shared_forward)
        self._observe_release(sim, services["forward"])

    def _observe_targeted(self, owner):
        if not hasattr(owner, "_resend"):
            return
        advance, known, resend, send = owner._advance, owner._new_known, owner._resend, owner.sim.send
        probe = self

        # Each transport datagram's note follows that exact send through link
        # loss, FIFO admission and rank recovery. No packet bytes are copied.
        class ProvenancedPacket(paths.PacketPath):
            __slots__ = ("retry",)

            def __init__(self, kind, index, issue):
                super().__init__(kind, index, issue)
                self.retry = probe.retry if kind == "retry" else None

        self.original_packet_type = paths.PacketPath
        paths.PacketPath = ProvenancedPacket

        def advanced():
            start = owner._observed_end
            result = advance()
            for index in range(start, owner._observed_end):
                if index in owner._fresh:
                    self.gap_since[index] = owner.sim.now
            return result

        def newly_known(symbols):
            result = known(symbols)
            for index in symbols:
                self.gap_since.pop(index, None)
            return result

        def retried(index, reason):
            info = (reason, self.gap_since.get(index), self.request_sent_at)
            return paths._set_during(self, "retry", info, resend, index, reason)

        def reserve(reverse, size, kind, callback):
            if not reverse or kind != "gap_request":
                return send(reverse, size, kind, callback)
            issued = owner.sim.now

            def arrival():
                return paths._set_during(self, "request_sent_at", issued, callback)

            return send(reverse, size, kind, arrival)

        owner._advance, owner._new_known = advanced, newly_known
        owner._resend, owner.sim.send = retried, reserve

    def _observe_release(self, sim, service):
        owner = sim.shared_forward
        deliver = owner._deliver_symbol

        def delivered(index):
            before = dict(owner.receiver.expected)
            return paths._set_during(self, "source_release", (index, before), deliver, index)

        owner._deliver_symbol = delivered
        for fid, flow in enumerate(sim.flows):
            received = flow.on_data

            def endpoint(index, ts, received=received, flow=flow, fid=fid):
                key = fid, index
                if index >= flow.tcp_received and key not in self.winners:
                    source, before = self.source_release
                    channel = self._dispatch.channel
                    self.release[key] = (source, before.get(channel, 0), owner.receiver.expected[channel])
                return received(index, ts)

            flow.on_data = endpoint

        start, finish = service._service_us, service.decode
        active = None

        def begin(wire):
            nonlocal active
            if active is not None:
                raise RuntimeError("overlapping forward service")
            result = start(wire)
            active = id(wire), self._active
            return result

        def end(wire):
            nonlocal active
            ident, meta = active
            if ident != id(wire) or meta is not self._active:
                raise RuntimeError("observer lost active decoder job identity")
            self.job_checks += 1
            try:
                return finish(wire)
            finally:
                active = None

        service._service_us, service.decode = begin, end

    def _complete(self, attempt, endpoint, app):
        seq = self.n_completed
        self.n_completed += 1
        release, before, after = self.release.pop(attempt.key)
        if not 0 <= attempt.origin < self.sim.traffic.duration_s:
            return
        self.n_eligible += 1
        total = (app - attempt.origin) * 1000
        solved, source, issue, trigger = attempt.last
        cause = trigger.kind
        if cause in ("source", "retry") and source != trigger.index:
            cause = "rank_via_" + cause
        self.all_solver[cause] += 1
        if len(self.heap) == self.capacity and (total, -seq) <= self.heap[0][:2]:
            return
        # Use the same additive partition as the aggregate observer. Keep
        # its column values only for this candidate, not for all submissions.
        super()._complete(attempt, endpoint, app)
        self.origins.pop()
        self.total.pop()
        phases = {name: col.pop() for name, col in zip(paths.PHASES, self.columns)}
        if abs(sum(phases.values()) - total) > 1e-7:
            raise RuntimeError("elapsed phase sum differs from original-to-application latency")
        retry = getattr(trigger, "retry", None)
        predecessor = None
        if app > endpoint:
            fid, serial = self._dispatch.key
            if fid != attempt.key[0] or serial >= attempt.key[1]:
                raise RuntimeError("TCP release failed its previous-segment ordering invariant")
            predecessor = serial
        info = dict(
            flow=attempt.key[0], original_segment=attempt.key[1], completion_order=seq,
            channel=attempt.channel, winning_inner_attempt=attempt.number,
            required_sources=attempt.sources, last_required_source=source, solver=cause,
            trigger_index=trigger.index, total_ms=total, phase_ms=phases,
            event_seconds=dict(original=attempt.origin, winning_attempt=attempt.issue,
                mux_admitted=attempt.admit, source_sealed=issue, solving_send=trigger.issue,
                serialization_start=trigger.service_start, departed=trigger.depart,
                wire_arrival=trigger.arrival, decoder_start=trigger.decode_start,
                source_known=solved, tcp_arrival=endpoint, application_delivery=app),
            channel_release_source=release, channel_next_serial_before_release=before,
            channel_next_serial_after_release=after, tcp_gap_filled_by_original_segment=predecessor,
            retry_reason=retry[0] if retry else None,
            trigger_source_first_gap_s=retry[1] if retry else None,
            actual_trigger_request_sent_s=retry[2] if retry else None)
        entry = (total, -seq, info)
        if len(self.heap) < self.capacity:
            heappush(self.heap, entry)
        else:
            heapreplace(self.heap, entry)

    def detach_packet_type(self):
        if hasattr(self, "original_packet_type"):
            paths.PacketPath = self.original_packet_type


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    bound, control = bind(args.archive)
    task = deepcopy(bound["task"])
    total_count = control["with_drain_tcp_application_delivery_cohort_completed_segments"]
    limit = ceil(total_count / 100)
    args.out.mkdir(parents=True, exist_ok=False)
    sources = {Path(__file__).resolve(),
               ROOT / "simulator/studies/aggregate_ack_deadlines.py",
               ROOT / "simulator/studies/packed_latency_study.py",
               ROOT / "simulator/studies/packed_targeted_study.py",
               ROOT / "simulator/studies/deadline_metrics.py",
               *(ROOT / "simulator/src/l2tunnel_sim").glob("*.py")}
    write(args.out / "manifest.json", dict(
        task=task, archive=str(args.archive), archive_result_sha256=digest(args.archive / "result.json"),
        archive_manifest_sha256=digest(args.archive / "manifest.json"),
        source_sha256={str(p.relative_to(ROOT)):digest(p) for p in sorted(sources)},
        command=[sys.executable,*sys.argv], cohort="All original forward bulk TCP segments offered "
        "in [0,duration), delivered through drain. Sort by application latency descending, "
        "then simulation completion order ascending.", expected_tail=limit,
        phase_definitions=list(paths.PHASES), time_units="event_seconds are absolute simulated seconds. "
        "Durations are milliseconds. The identified solving packet is the last dependency's trigger. "
        "Intervals before that transmission may combine waiting for evidence, prior service and earlier losses. "
        "Channel next serial before release identifies an actual missing predecessor only when channel_order > 0. "
        "Repair/tail trigger_index is inclusive support end minus one. Flow and original segment IDs are zero-based."))
    observers = []

    def attach(sim, services):
        observers.append(FullTail(sim, services, limit))

    try:
        row = canonical(execute(task, observe_packed=attach))
    finally:
        if observers:
            observers[0].detach_packet_type()
    changed = [k for k in row.keys() | control.keys() if k != "compute_seconds" and row.get(k) != control.get(k)]
    obs = observers[0]
    if (changed or row.keys()!=control.keys() or obs.n_eligible != total_count or len(obs.heap)!=limit
            or obs.job_checks!=row["packed_receiver_service"]["forward"]["completed"]):
        raise RuntimeError(f"receipt does not match original: {changed}")
    ranked = sorted(obs.heap, key=lambda entry:(-entry[0],-entry[1]))
    filename = args.out / "slowest-originals.jsonl.gz"
    causes = Counter()
    retries = Counter()
    sums = Counter()
    total = 0.0
    with filename.open("xb") as f, GzipFile(filename="", mode="wb",fileobj=f,mtime=0) as gz, TextIOWrapper(gz) as text:
        for rank, (_, _, info) in enumerate(ranked, 1):
            causes[info["solver"]] += 1
            if info["retry_reason"]:
                retries[info["retry_reason"]] += 1
            sums.update(info["phase_ms"])
            total += info["total_ms"]
            text.write(json.dumps(dict(rank=rank,**info),allow_nan=False,separators=(",",":"))+"\n")
    write(args.out / "summary.json", dict(rows=limit, original_completed=obs.n_eligible,
          original_censored=control["with_drain_tcp_application_delivery_cohort_censored_segments"],
          replay_non_wall_fields_matched=len(row)-1, checked_forward_decoder_jobs=obs.job_checks,
          threshold_ms=ranked[-1][0], max_ms=ranked[0][0], mean_total_ms=total/limit,
          mean_phase_ms={k:n/limit for k,n in sums.items()}, solver_counts_in_tail=dict(causes),
          retry_reasons_in_tail=dict(retries), all_completed_solver_counts=dict(obs.all_solver),
          artifact_sha256=digest(filename), artifact_bytes=filename.stat().st_size))


if __name__ == "__main__":
    main()
