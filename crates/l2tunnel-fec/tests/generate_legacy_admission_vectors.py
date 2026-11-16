#!/usr/bin/env python3
"""Finite actual-Python congested admission/packer oracle; no simulator edits.

The link has a 250-us preexisting reservation, 100-us packet serialization and
1000-us RTT. The trace ends at20us, before any physical completion. Packing
readiness and coding snapshots are compared; Python's precomputed future send
facts are not relabeled as actual local physical receipt observations.
"""
import argparse
import importlib.util
from hashlib import sha256
from heapq import heappop, heappush
from itertools import count
from pathlib import Path
from random import Random
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
MODEL = ROOT / "simulator/src/l2tunnel_sim/model.py"
TARGET = Path(__file__).parent / "fixtures/legacy-admission-packing.txt"

def generate():
    spec = importlib.util.spec_from_file_location("legacy_oracle", Path(__file__).parent / "generate_legacy_sliding_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.actual_definitions()
    rows = ["# Actual unchanged Python Tunnel/Packer; microsecond input.",
            "# Header88/packed-item4 are analytical, not L2LB wire charges.",
            "# q time periodic support coefficients; t time kind supports analytical_bytes planned_finish",
            f"# sha256 simulator/src/l2tunnel_sim/model.py {sha256(MODEL.read_bytes()).hexdigest()}"]
    values = dict(mode="sliding", reverse_fec=False, reverse_ordered=False, streams=0,
                  source_batch=2, repair_batch=2, reverse_batch=1, reverse_repair_batch=1,
                  fragments=1, pack_wait_ms=.005, block_size=20, block_repairs=10,
                  repair_every=5, repairs_per_group=2, interleave_repairs=True,
                  short_window=2, long_window=5, long_every=3, fec_wait_ms=.010,
                  repair_spacing_ms=.001, feedback_repair=True, cumulative_feedback=False,
                  feedback_batch=16, feedback_wait_ms=.002, rto_factor=2.5,
                  rto_min_ms=.100, decode_us_per_symbol=0.)
    class Sim:
        def __init__(self):
            self.strategy = SimpleNamespace(**values)
            self.scenario = SimpleNamespace(mtu=600)
            self.traffic = SimpleNamespace(duration_s=1)
            self.now = 0.; self.events = []; self.sequence = count(); self.link_free = .000250
        def at(self, when, callback, *args):
            heappush(self.events, (when, next(self.sequence), callback, args))
        def send(self, reverse, size, kind, receive):
            self.link_free = max(self.link_free, self.now) + .000100
            return self.link_free, .001
        def until(self, at):
            end = at / 1_000_000
            while self.events and self.events[0][0] <= end:
                self.now, _, callback, args = heappop(self.events); callback(*args)
            self.now = end
    sim = Sim(); tunnel = actual.Tunnel(sim, False, Random(7349), lambda _: None)
    original_transmit = tunnel.transmit; original_queue = tunnel.queue_repair
    def transmit(kind, items, size):
        support = (";".join(",".join(map(str, repair.coefficients)) for repair in items)
                   if kind == "repair" else ",".join(str(symbol.index) for symbol in items))
        finish = round((max(sim.link_free, sim.now) + .000100) * 1_000_000)
        rows.append(f"t {round(sim.now * 1_000_000)} {kind} {support} {size} {finish}")
        return original_transmit(kind, items, size)
    def queue(sources, coefficients=None, spacing_index=0, *, feedback_triggered=False):
        state = tunnel.rng.getstate()
        captured = coefficients if coefficients is not None else [tunnel.rng.randrange(1, 256) for _ in sources]
        tunnel.rng.setstate(state)
        support = ",".join(str(source.index) for source in sources)
        rows.append(f"q {round(sim.now * 1_000_000)} {tunnel.periodic_repairs} {support} {bytes(captured).hex()}")
        original_queue(sources, coefficients, spacing_index, feedback_triggered=feedback_triggered)
    tunnel.transmit = transmit; tunnel.queue_repair = queue
    def snapshot():
        rows.append(f"z {round(sim.now * 1_000_000)} {tunnel.fec_count} {tunnel.repair_credit} {tunnel.fec_generation} {tunnel.periodic_repairs}")
    for at in range(5):
        sim.until(at); rows.append(f"a {at} {len(tunnel.symbols)}")
        tunnel.frame(2, at); snapshot()
    sim.until(20); snapshot()
    return "\n".join(rows) + "\n"

def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--check", action="store_true"); args = parser.parse_args()
    result = generate()
    if args.check:
        if TARGET.read_text() != result: raise SystemExit("Legacy admission/packing oracle differs")
    else: TARGET.write_text(result)
    print(f"Verified {len(result.splitlines())} legacy admission/packing rows")

if __name__ == "__main__":
    main()
