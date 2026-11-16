#!/usr/bin/env python3
"""Extract the actual Python research policies and freeze small Rust oracle rows.

Only selected AST function definitions execute. The simulator, plotly/numpy,
experiment runners and historical receipts are neither imported nor changed.
Use --check to verify committed vectors without writing them.
"""

import argparse
import ast
from collections import Counter
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
STUDIES = ROOT / "simulator" / "studies"
TARGET = Path(__file__).parent / "fixtures" / "research-policy.txt"


def extract(path, names, namespace, parent=None):
    tree = ast.parse(path.read_text(), filename=str(path))
    scope = tree.body
    if parent:
        scope = next(node.body for node in scope if isinstance(node, ast.FunctionDef) and node.name == parent)
    definitions = [node for node in scope if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in definitions} != set(names):
        raise ValueError(f"Missing oracle function in {path}: {names}")
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), "exec"), namespace)
    return SimpleNamespace(**namespace)


def generate():
    compact_path = ROOT / "simulator" / "src" / "l2tunnel_sim" / "compact.py"
    recursive_path = STUDIES / "rtt_recursive_parity.py"
    fallback_path = STUDIES / "rtt_recursive_fallback.py"
    accumulator_path = STUDIES / "rtt_rolling_accumulator.py"
    checkpoint_path = STUDIES / "rtt_checkpoint_repairs.py"
    coding_path = ROOT / "simulator" / "src" / "l2tunnel_sim" / "coding.py"
    coding = extract(coding_path, {"_multiply"}, {})
    compact = extract(compact_path, {"coefficient"}, {})
    checkpoint = extract(checkpoint_path, {"support"}, {})
    shared = dict(coefficient=compact.coefficient, SERIAL_INVERSE=pow(2654435761, -1, 1 << 32),
                  sha256=sha256, lru_cache=lru_cache)
    recursive = extract(recursive_path, {"source_taps", "epoch_start", "source_start",
                                        "expanded_coefficient", "check_equation"}, shared)
    recursive_support = extract(recursive_path, {"support"}, dict(vars(recursive), original_support=checkpoint.support), "execute")
    fallback = extract(fallback_path, {"repair_mode", "repair_coefficient"}, dict(recursive=recursive))
    fallback_support = extract(fallback_path, {"support"}, dict(vars(fallback), modes=Counter(),
                               original_support=checkpoint.support), "execute")
    accumulator = extract(accumulator_path, {"repair_coefficient", "repair_support"}, dict(shared))
    profiles = [dict(taps=0, width=0, reset=256, fresh_interval=0),
                *[dict(taps=taps, width=width, reset=256, fresh_interval=0)
                  for taps, width in ((3, 8), (3, 12), (4, 8))],
                *[dict(taps=4, width=8, reset=256, fresh_interval=fresh) for fresh in (8, 16, 32)],
                *[dict(lanes=lanes, window=window) for lanes, window in
                  ((0, 128), (1, 128), (3, 128), (7, 128), (15, 128), (7, 256))]]
    serials = (1, 7, 8, 15, 16, 17, 31, 32, 255, 256, 257, 272, 512, 513, 32768, 32769, 1000003)
    rows = ["# Extracted actual Python functions; no analytical runner or rank ledger."]
    for path in (recursive_path, fallback_path, accumulator_path, checkpoint_path, compact_path, coding_path):
        rows.append(f"# sha256 {path.relative_to(ROOT)} {sha256(path.read_bytes()).hexdigest()}")
    for index, profile in enumerate(profiles):
        profile = dict(profile, checkpoint=0, burst=False)
        fields = tuple(profile.get(key, 0) for key in ("taps", "width", "reset", "fresh_interval", "lanes", "window"))
        rows.append(f"p {index} {'r' if 'taps' in profile else 'a'} " + " ".join(map(str, fields)))
        for serial in serials:
            end = (serial * 125 + 25) // 26
            for confirmed in dict.fromkeys((max(0, end - 8193), max(0, end - 73))):
                if "taps" in profile:
                    if profile["fresh_interval"]:
                        start, stop = fallback_support.support(profile, end, confirmed, serial)
                    else:
                        start, stop = recursive_support.support(profile, end, confirmed, serial)
                    mode = fallback.repair_mode(profile, serial)
                    mode = dict(dense="d", recursive="r", fallback="f")[mode]
                    fn = lambda source: fallback.repair_coefficient(profile, serial * 2654435761 & 0xffffffff, source)
                else:
                    start, stop = accumulator.repair_support(profile, end, confirmed, serial)
                    mode = "a" if profile["lanes"] and serial % 16 else "d"
                    fn = lambda source: accumulator.repair_coefficient(profile, serial * 2654435761 & 0xffffffff, source)
                # Rust explicitly refuses supports beyond its retained hard ceiling.
                rows.append(f"s {index} {serial} {end} {confirmed} {start} {stop} {mode}")
                sources = sorted({0, start, max(0, start - 1), stop - 1, stop,
                                  *range(max(start, stop - 32), stop)})
                rows.extend(f"c {index} {serial} {source} {fn(source)}" for source in sources)
                if serial in (1, 8, 16, 17, 255, 256, 257) and confirmed == max(0, end - 73):
                    coded = bytearray(21)
                    for source in range(start, stop):
                        payload = bytearray((source * 29 + offset * 71 + (offset >> 1)) & 255
                                            for offset in range(1 + source % 19))
                        if source % 5 == 0:
                            payload[-1] = 0
                        vector = len(payload).to_bytes(2, "big") + bytes(payload)
                        vector += bytes(21 - len(vector))
                        value = fn(source)
                        for offset, byte in enumerate(vector):
                            coded[offset] ^= coding._multiply(value, byte)
                    rows.append(f"e {index} {serial} {end} {confirmed} {start} {coded.hex()}")
    for source in (0, 1, 17, 1234, 4294967294):
        for taps, width in ((3, 8), (3, 12), (4, 8), (16, 1)):
            for edge, (check, weight) in enumerate(recursive.source_taps(source, taps, width)):
                rows.append(f"t {source} {width} {edge} {check} {weight}")
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate()
    if args.check:
        if TARGET.read_text() != result:
            raise SystemExit("Research policy oracle differs")
    else:
        TARGET.write_text(result)
    print(f"Verified {len(result.splitlines())} research policy oracle rows")


if __name__ == "__main__":
    main()
