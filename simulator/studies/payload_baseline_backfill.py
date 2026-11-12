"""Fill the 1228-byte payload gap in the saved TCP and QUIC baseline matrix."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
import json
from pathlib import Path

import payload_sizes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    profiles = payload_sizes.default_profiles()[:2]
    # Keep the exact original seed, RTT, duration, and drain matrix. Replace
    # just one payload group so existing observations are not run again.
    tasks = [dict(task, payload_bytes=1228) for task in payload_sizes.tasks(
        profiles, duration=10, warmup=2, drain=5, replications=3)
        if task["payload_bytes"] == 1448]
    for index, task in enumerate(tasks, 1):
        task["run_id"] = index
    source_root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(payload_sizes.__file__).resolve(),
             *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest()
              for path in files}
    manifest = dict(tasks=tasks, sources=hashes, assumptions=[
        "The existing payload baseline matrix omitted 1228-byte application records",
        "This backfill uses the normal payload_sizes runner and its established TCP and aioquic entry points",
        "TCP and QUIC use their separately defined protocol RTT observations",
        "Every result is retained regardless of delivery or terminal confirmation",
    ])
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "experiment.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("existing task matrix or source hashes differ")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in files:
        copy = args.out / "sources" / path.relative_to(source_root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (runs / f"{task['run_id']:05d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(payload_sizes.execute, task) for task in pending]):
            row = future.result()
            path = runs / f"{row['run_id']:05d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(path)
            print(f"{row['strategy']} RTT {row['rtt_ms']} ms seed {row['seed']} "
                  f"goodput {row['application_goodput_mbps']:.4f} Mbps", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    payload_sizes.write_csv(args.out / "replications.csv", rows)
    payload_sizes.write_csv(args.out / "summary.csv", payload_sizes.summarize(rows))
    changed = [name for name, digest in hashes.items()
               if sha256((source_root / name).read_bytes()).hexdigest() != digest]
    (args.out / "source-verification.json").write_text(
        json.dumps(dict(changed_during_run=changed), indent=2) + "\n")
    print(f"Saved all {len(rows)} baseline observations", flush=True)


if __name__ == "__main__":
    main()
