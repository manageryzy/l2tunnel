"""Run a frozen C48 task with authenticated UDP prices and an optional forward near8 row."""
import argparse
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "simulator/src"))

from aggregate_ack_deadlines import execute
from l2tunnel_sim.tcp import PlainTCP
from packed_spare_pricing import install as price_udp
from packed_spare_study import NearStudy


def run(task, policy, segments, pacer):
    adapters = []
    def attach(sim, services):
        if policy == "spare":
            adapters.append(NearStudy(sim, services, pacer))
        price_udp(sim, services)
        if adapters:
            adapters[0].enable()

    ordinary = PlainTCP.produce
    def capped_issue(flow):
        # The original producer samples its issue limit once, before sending.
        # ACK and congestion-control callbacks retain their original window.
        limit = flow.window_limit
        flow.window_limit = min(segments, limit)
        try:
            return ordinary(flow)
        finally:
            flow.window_limit = limit

    try:
        with patch.object(PlainTCP, "produce", capped_issue):
            result = execute(task, observe_packed=attach)
    finally:
        observation = adapters[0].finish() if adapters else None
    return dict(task=task, policy=policy, segments=segments, sender_ip_bytes_per_second=pacer,
                result=result, near=observation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="C48 JSON manifest with a task")
    parser.add_argument("--output", required=True, type=Path, help="new receipt")
    parser.add_argument("--policy", required=True, choices=("control", "spare"))
    parser.add_argument("--segments", required=True, type=int, choices=(125, 512))
    parser.add_argument("--sender-ip-bytes-per-second", type=int, default=12_500_000)
    options = parser.parse_args()
    if options.output.exists():
        parser.error("receipt already exists")
    task = json.loads(options.manifest.read_text())["task"]
    result = run(task, options.policy, options.segments, options.sender_ip_bytes_per_second)
    with options.output.open("x") as f:
        json.dump(result, f, indent=2, default=lambda value: value.item())
        f.write("\n")


if __name__ == "__main__":
    main()
