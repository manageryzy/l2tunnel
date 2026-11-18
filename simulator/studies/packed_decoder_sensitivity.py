"""Apply two measured single-hole Rust decoder anchors to the C48 receiver FIFO."""

import argparse
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path

from aggregate_ack_deadlines import execute
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.compact_wire import SYMBOL_BYTES
from l2tunnel_sim.packed_receiver_service import DecoderCurve
from packed_service_sensitivity import digest, write


def one_hole_work(width):
    # First regular/tail repair in the maintained Python format uses serial 1.
    seed = 2654435761
    missing = coefficient(seed, 0)
    assert missing
    mixed = sum(bool(coefficient(seed, i)) for i in range(1, width)) + (missing != 1)
    return mixed * SYMBOL_BYTES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchors", required=True, type=Path)
    parser.add_argument("--paired-manifest", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--rank-backend", choices=("reference", "dense"), default="reference")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    anchors = json.loads(args.anchors.read_text())["arms_by_source_support"]
    local, global_ = anchors["128"], anchors["8192"]
    curve = DecoderCurve(local["systematic_batch_average_us_per_source"]["median"],
                        one_hole_work(128), local["repair_ms"]["median"] * 1000,
                        one_hole_work(8192), global_["repair_ms"]["median"] * 1000)
    jobs = [deepcopy(j["executed_task"]) for j in json.loads(args.paired_manifest.read_text())["jobs"]
            if j["result"].endswith(("-zero-service.json", "-original.json"))]
    if not jobs:
        raise ValueError("paired manifest has no original or zero-service controls")
    write(args.out / "manifest.json", dict(
        anchors=str(args.anchors), anchor_sha256=digest(args.anchors), paired_manifest=str(args.paired_manifest),
        paired_manifest_sha256=digest(args.paired_manifest), driver_sha256=digest(Path(__file__)),
        receiver_sha256=digest(Path(__file__).resolve().parents[1] / "src/l2tunnel_sim/packed_receiver_service.py"),
        rank_backend=args.rank_backend,
        rank_sha256=digest(Path(__file__).resolve().parents[1] / "src/l2tunnel_sim/packed_rank.py"),
        service="Piecewise linear whole-decoder microseconds versus logical GF payload bytes. "
                "Fits local/global single-hole dense repair medians and uses the local systematic "
                "batch mean as the price for zero GF work. No separate kernel, metadata, or source charge.",
        curve=asdict(curve), predictions_us=[curve.charge(size, 0) for size in (0, one_hole_work(128), one_hole_work(8192))],
        systematic_global_observed_us=global_["systematic_batch_average_us_per_source"]["median"]))
    for task in jobs:
        task.pop("packed_receiver_cost", None)
        task["packed_decoder_curve"] = asdict(curve)
        task["packed_rank_backend"] = args.rank_backend
        write(args.out / f"rep-{task['replication']}.json", execute(task))


if __name__ == "__main__":
    main()
