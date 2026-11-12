#!/usr/bin/env python3
"""Capture actual Python aligned sender symbols, without reimplementing encoding."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "crates/l2tunnel-codec/tests/data/aligned-sender-goldens.tsv"
sys.path.insert(0, str(ROOT / "simulator/src"))
from l2tunnel_sim.aligned_records import AlignedRecordConfig, AlignedRecordTransport  # noqa: E402
from l2tunnel_sim.config import Scenario, Traffic  # noqa: E402
from generate_aligned_body_goldens import native  # noqa: E402


def cases():
    for symbol in (9, 20, 72, 73, 128, 1460):
        threshold = 0 if symbol < 128 else 100
        yield f"symbol{symbol}", symbol, threshold, 0, [
            (0, native()), (0, native(sequence=64, identification=1, timestamp=18)),
            (1, native(0)), (0, native(0)), (1, b"opaque"), (0, b""),
            (1, native(500, identification=1)),
            (0, native(1457, sequence=128, identification=2)),
        ]
    yield "wrap", 1460, 0, 65534, [
        (0, native()), (0, native(sequence=64, identification=1)),
        (1, native(0)), (0, b"raw"),
    ]


def generate():
    rows = ["# aligned-sender-goldens-v1; actual Python sender, unchanged inner symbol bytes"]
    for name in ("compact.py", "aligned_records.py", "shared_records.py"):
        source = ROOT / "simulator/src/l2tunnel_sim" / name
        rows.append(f"# python_source={source.relative_to(ROOT)}; sha256={hashlib.sha256(source.read_bytes()).hexdigest()}")
    rows.append("# case\tstep\tsymbol\tshort\tfirst\tchannel\tframe_hex\tsource:record:symbol_hex")
    count = 0
    for name, symbol, short, first, frames in cases():
        sim = SimpleNamespace(now=0, scenario=Scenario(20, 0, mtu=max(128, symbol + 40)),
            traffic=Traffic(), links=[[SimpleNamespace(rtt=.02)]] * 2,
            at=lambda *args: None, send=lambda *args: (0, .02))
        config = AlignedRecordConfig(repair_ratio=0, block_sources=8192,
            header_profile="tcp_delta", authentication_bytes=max(0, 128 - symbol - 40),
            elide_payload_length=True, packed_predictive_records=True,
            timestamp_pair_dictionary=True, independent_short_frame_bytes=short)
        transport = AlignedRecordTransport(sim, False, config)
        for channel in (0, 1):
            transport.channel_sequences[channel] = transport.channel_completed[channel] = first
        records = []
        original = transport._submit_record
        def capture(channel, serial, body):
            before = len(transport.sources)
            original(channel, serial, body)
            records.extend([serial] * (len(transport.sources) - before))
        transport._submit_record = capture
        for step, (channel, frame) in enumerate(frames):
            before = len(transport.sources)
            transport.submit_channel(channel, len(frame), max(0, len(frame) - 66), lambda: None, frame=frame)
            if transport.source_queue:
                raise ValueError("fixture exceeded actual sender source window")
            symbols = []
            for source in range(before, len(transport.sources)):
                payload = transport.source_payloads[source]
                if payload[0] != channel or int.from_bytes(payload[1:3], "big") != records[source] & 65535:
                    raise ValueError("actual Python identity capture mismatch")
                symbols.append(f"{source}:{records[source]}:{payload.hex()}")
                count += 1
            rows.append("\t".join((name, str(step), str(symbol), str(short), str(first), str(channel), frame.hex(), ";".join(symbols))))
    return "\n".join(rows) + "\n", count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    text, count = generate()
    if args.check:
        if args.output.read_text(encoding="utf-8") != text:
            raise SystemExit("Aligned sender symbols differ from actual Python")
        print(f"Verified {count} actual Python aligned source symbols.")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {count} actual Python aligned source symbols to {args.output}")


if __name__ == "__main__":
    main()
