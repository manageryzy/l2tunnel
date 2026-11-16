#!/usr/bin/env python3
"""Small actual-Python legacy scheduling, feedback, ARQ and payload oracle.

Execute selected definitions from the unchanged model through an injected event
clock. No experiment runner, plotting dependency or historical receipt is used.
The trace uses microseconds and fixed 100-us serialization / 2000-us path RTT;
these are fixture inputs, not measured network behavior. Full coded bytes extend
Python's coefficient-only equations with its actual GF multiplication function.
"""

import argparse
import ast
from collections import deque
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from heapq import heappop, heappush
from itertools import chain, count
from math import ceil
from pathlib import Path
from random import Random
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
MODEL = ROOT / "simulator/src/l2tunnel_sim/model.py"
CODING = ROOT / "simulator/src/l2tunnel_sim/coding.py"
TARGET = Path(__file__).parent / "fixtures/legacy-sliding-policy.txt"


def actual_definitions():
    namespace = dict(dataclass=dataclass, deque=deque, ceil=ceil, chain=chain, lru_cache=lru_cache)
    coding = ast.parse(CODING.read_text(), filename=str(CODING))
    definitions = [node for node in coding.body if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Assign))]
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(CODING), "exec"), namespace)
    model = ast.parse(MODEL.read_text(), filename=str(MODEL))
    names = {"Frame", "Symbol", "Repair", "Flight", "Packer", "Tunnel"}
    definitions = [node for node in model.body if isinstance(node, ast.ClassDef) and node.name in names]
    namespace.update(HEADER_BYTES=88, PACKED_SYMBOL_BYTES=4, FEEDBACK_ID_BYTES=4)
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(MODEL), "exec"), namespace)
    return SimpleNamespace(**namespace)


def payload(source):
    result = bytearray((source * 37 + offset * 53) & 255 for offset in range(1 + source % 11))
    if source % 3 == 0:
        result[-1] = 0
    return bytes(result)


def micros(seconds):
    return round(seconds * 1_000_000)


def generate():
    actual = actual_definitions()
    rows = ["# Actual Python Tunnel methods; input time unit microseconds.",
            "# Injected serialization_us=100 path_rtt_us=2000 coded_width=13 rng=Random(7349).",
            "# p: name mode every repairs interleave short long long_every fec_wait_us spacing_us rto_min_us feedback_wait_us",
            "# a: case time source payload_hex; q: case time periodic_serial feedback ids coeff_hex coded_hex",
            "# t: case time kind ids; z: case label time fec_count credit generation periodic_serial",
            "# f: case label source attempts queued early sent_us rtt_us retry_us repair_until_us",
            "# k: case time selective_ids inclusive_prefix; Rust prefix is exclusive when present.",
            f"# sha256 {MODEL.relative_to(ROOT)} {sha256(MODEL.read_bytes()).hexdigest()}",
            f"# sha256 {CODING.relative_to(ROOT)} {sha256(CODING.read_bytes()).hexdigest()}"]

    class Sim:
        def __init__(self, strategy):
            self.strategy = strategy
            self.scenario = SimpleNamespace(mtu=1500)
            self.traffic = SimpleNamespace(duration_s=1)
            self.now = 0.
            self.events = []
            self.sequence = count()

        def at(self, when, callback, *args):
            heappush(self.events, (when, next(self.sequence), callback, args))

        def send(self, reverse, size, kind, receive):
            if kind == "feedback":
                receive()  # Capture feedback content; this fixture does not model its return network.
            return self.now + .0001, .002

        def until(self, time_us):
            until = time_us / 1_000_000
            while self.events and self.events[0][0] <= until:
                self.now, _, callback, args = heappop(self.events)
                callback(*args)
            self.now = until

    def setup(name, **changes):
        values = dict(mode="sliding", reverse_fec=False, reverse_ordered=False, streams=0,
                      source_batch=1, repair_batch=1, reverse_batch=1, reverse_repair_batch=1,
                      fragments=1, pack_wait_ms=0., block_size=20, block_repairs=10,
                      repair_every=3, repairs_per_group=2, interleave_repairs=False,
                      short_window=2, long_window=5, long_every=3, fec_wait_ms=5.,
                      repair_spacing_ms=0., feedback_repair=False, cumulative_feedback=False,
                      feedback_batch=16, feedback_wait_ms=.2, rto_factor=2.5,
                      rto_min_ms=1000., decode_us_per_symbol=0.)
        values.update(changes)
        strategy = SimpleNamespace(**values)
        sim = Sim(strategy)
        tunnel = actual.Tunnel(sim, False, Random(7349), lambda value: None)
        original_transmit = tunnel.transmit
        original_queue = tunnel.queue_repair
        rows.append(f"p {name} {strategy.mode} {strategy.repair_every} {strategy.repairs_per_group} "
                    f"{int(strategy.interleave_repairs)} {strategy.short_window} {strategy.long_window} "
                    f"{strategy.long_every} {round(strategy.fec_wait_ms * 1000)} "
                    f"{round(strategy.repair_spacing_ms * 1000)} {round(strategy.rto_min_ms * 1000)} "
                    f"{round(strategy.feedback_wait_ms * 1000)}")

        def queue(sources, coefficients=None, spacing_index=0, *, feedback_triggered=False):
            # Let the actual queue consume Random exactly once, then capture the actual Repair.
            before = tunnel.rng.getstate()
            actual_coefficients = coefficients
            if actual_coefficients is None:
                actual_coefficients = [tunnel.rng.randrange(1, 256) for _ in sources]
            tunnel.rng.setstate(before)
            coded = bytearray(13)
            for source, value in zip(sources, actual_coefficients, strict=True):
                body = payload(source.index)
                vector = len(body).to_bytes(2, "big") + body + bytes(11 - len(body))
                for offset, byte in enumerate(vector):
                    coded[offset] ^= actual._multiply(value, byte)
            ids = ",".join(str(source.index) for source in sources)
            rows.append(f"q {name} {micros(sim.now)} {tunnel.periodic_repairs} "
                        f"{int(feedback_triggered)} {ids} {bytes(actual_coefficients).hex()} {coded.hex()}")
            original_queue(sources, coefficients, spacing_index, feedback_triggered=feedback_triggered)

        def transmit(kind, items, size):
            if kind == "repair":
                ids = ";".join(",".join(map(str, repair.coefficients)) for repair in items)
            else:
                ids = ",".join(str(symbol.index) for symbol in items)
            rows.append(f"t {name} {micros(sim.now)} {kind} {ids}")
            return original_transmit(kind, items, size)

        tunnel.queue_repair = queue
        tunnel.transmit = transmit
        return sim, tunnel

    def admit(name, sim, tunnel, time_us):
        sim.until(time_us)
        source = len(tunnel.symbols)
        body = payload(source)
        rows.append(f"a {name} {time_us} {source} {body.hex()}")
        tunnel.frame(len(body), source)

    def snapshot(name, label, sim, tunnel):
        rows.append(f"z {name} {label} {micros(sim.now)} {tunnel.fec_count} {tunnel.repair_credit} "
                    f"{tunnel.fec_generation} {tunnel.periodic_repairs}")
        for source, flight in tunnel.pending.items():
            rows.append(f"f {name} {label} {source} {flight.attempts} {flight.queued_repairs} "
                        f"{int(flight.early)} {micros(flight.sent_at)} {micros(flight.rtt)} "
                        f"{micros(flight.retry_at)} {micros(flight.repair_until)}")

    for name, changes, times, finish in (
        ("ceil", {}, (0, 1000, 2000, 3000), 8000),
        ("hybrid", dict(mode="hybrid", repair_every=2), (0, 1000, 2000, 3000, 4000), 9001),
        ("interleave", dict(repair_every=5, interleave_repairs=True, fec_wait_ms=3.),
         (0, 4000, 4500, 5000, 5500), 8500),
    ):
        sim, tunnel = setup(name, **changes)
        for time in times:
            admit(name, sim, tunnel, time)
        sim.until(finish)
        snapshot(name, "final", sim, tunnel)
        if name == "ceil":
            tunnel.on_feedback((0, 1, 2, 3))
            for time in (9000, 10000, 11000):
                admit(name, sim, tunnel, time)
            snapshot(name, "acked_history", sim, tunnel)

    sim, tunnel = setup("feedback", repair_every=20, repairs_per_group=1,
                        fec_wait_ms=1000., repair_spacing_ms=5., feedback_repair=True,
                        rto_min_ms=1.)
    for time in (0, 100, 200, 300, 400):
        admit("feedback", sim, tunnel, time)
    sim.until(1000)
    tunnel.queue_repair([tunnel.symbols[0]], spacing_index=1)
    snapshot("feedback", "queued", sim, tunnel)
    sim.until(4000)
    tunnel.on_feedback((2, 4))
    snapshot("feedback", "receipt", sim, tunnel)
    sim.until(5000)
    tunnel.on_feedback((2, 4))
    snapshot("feedback", "duplicate", sim, tunnel)
    sim.until(6100)
    snapshot("feedback", "periodic_sent", sim, tunnel)
    sim.until(7500)
    snapshot("feedback", "retry", sim, tunnel)

    sim, tunnel = setup("receipts", cumulative_feedback=True, feedback_batch=2)
    tunnel.on_feedback = lambda ids, prefix=-1: rows.append(
        f"k receipts {micros(sim.now)} {','.join(map(str, ids)) or '-'} {prefix}")
    symbols = []
    for source in range(3):
        frame = actual.Frame(source, len(payload(source)), source, 0., 1)
        symbols.append(actual.Symbol(source, frame.size, frame))
    tunnel.symbols.extend(symbols)
    tunnel.receive_sources([symbols[0], symbols[2]])
    sim.until(100)
    tunnel.receive_sources([symbols[1]])
    sim.until(400)
    tunnel.receive_sources([symbols[2]])
    sim.until(601)
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate()
    if args.check:
        if TARGET.read_text() != result:
            raise SystemExit("Legacy sliding oracle differs")
    else:
        TARGET.write_text(result)
    print(f"Verified {len(result.splitlines())} legacy sliding oracle rows")


if __name__ == "__main__":
    main()
