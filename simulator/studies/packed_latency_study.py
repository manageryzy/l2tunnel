"""Trace the slowest completed C48 TCP segments against a frozen untraced workload."""

import argparse
import json
from pathlib import Path
from time import perf_counter

from aggregate_ack_deadlines import execute
from packed_service_sensitivity import ROOT, digest, write
from packed_targeted_study import DIRECTIONS, read, require, row_metrics, sample, track_source_copies, window


ARCHIVE = ROOT / "work/packed-targeted-20261118"


def canonical(value):
    return json.loads(json.dumps(value, allow_nan=False))


def bind(directory):
    index = read(directory.parent / "verification.json")[directory.name]["sha256"]
    for name, expected in index.items():
        require(digest(directory / name) == expected, f"archived {name} differs")
    manifest = read(directory / "manifest.json")
    original = read(directory / "result.json")
    require(json.loads(original["profile"]) == manifest["task"]["profile"] and
            all(original[k] == v for k, v in manifest["task"].items() if k != "profile"), "result/workload mismatch")
    return manifest, original


def run(archive, destination, options):
    from l2tunnel_sim.packed_frame_path import PackedFramePath

    audited, original = bind(archive)
    task = dict(audited["task"])
    # A candidate may select new policy knobs. The archived link, decoder
    # price, traffic, mode, seed and time horizons are shared by both arms.
    require(not options or set(options) == {"packed_latency_policy"},
            "only packed_latency_policy may differ from the bound workload")
    task.update(options)
    destination.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve()
    files = sorted({source, source.with_name("aggregate_ack_deadlines.py"), source.with_name("deadline_metrics.py"),
                    source.with_name("packed_targeted_study.py"), source.with_name("packed_service_sensitivity.py"),
                    *sorted((ROOT / "simulator/src/l2tunnel_sim").glob("*.py"))})
    write(destination / "manifest.json", dict(task=task, options=options, archive=str(archive),
          archive_verification_sha256=digest(archive.parent / "verification.json"),
          archived_manifest_sha256=digest(archive / "manifest.json"), original_result_sha256=digest(archive / "result.json"),
          source_sha256={str(f.relative_to(ROOT)): digest(f) for f in files}))
    owners = {}
    snapshots = {}
    trace = []

    def observe(sim, services):
        copies = {name: track_source_copies(s.transport) for name, s in services.items()}
        owners.update(sim=sim, services=services, copies=copies)

        def snapshot(label):
            snapshots[label] = sample(**owners)
            write(destination / f"{label}.json", snapshots[label])

        for t, label in ((task["warmup_s"], "warmup_end"), (task["duration_s"], "traffic_end")):
            sim.flows[0].at(t, snapshot, label)
        trace.append(PackedFramePath(sim, services))

    start = perf_counter()
    result = canonical(execute(task, observe_packed=observe))
    write(destination / "result.json", result)
    final = sample(**owners)
    write(destination / "drain_end.json", final)
    if not options:
        changed = sorted(k for k in result.keys() | original.keys()
                         if k != "compute_seconds" and result.get(k) != original.get(k))
        different_snapshots = [name for name, data in {**snapshots, "drain_end": final}.items()
                               if canonical(data) != read(archive / f"{name}.json")]
        write(destination / "parity.json", dict(matched_result_fields=len(result) - len(changed) - 1,
              changed_result_fields=changed, different_snapshots=different_snapshots,
              cutoff_snapshots=list(snapshots) + ["drain_end"]))
        require(result.keys() == original.keys() and not changed and not different_snapshots,
                "passive frame tracing changed the original simulation")
    report = trace[0].report(warmup_s=task["warmup_s"])
    write(destination / "frame-path.json", report)
    measured = row_metrics(result)
    measured["matched_wire"] = {
        d: window(snapshots["warmup_end"]["directions"][d], snapshots["traffic_end"]["directions"][d])
        for d in DIRECTIONS}
    measured["traffic_end"] = snapshots["traffic_end"]
    measured["drain_end"] = final
    measured["wall_seconds_including_tracing_and_report"] = perf_counter() - start
    write(destination / "summary.json", measured)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ARCHIVE / "fresh-full-r1")
    parser.add_argument("--options", type=Path, help="JSON object containing the experimental packed_latency_policy")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    options = read(args.options) if args.options else {}
    require(isinstance(options, dict), "candidate options must be a JSON object")
    run(args.archive, args.out, options)


if __name__ == "__main__":
    main()
