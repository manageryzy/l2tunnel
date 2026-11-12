#!/usr/bin/env python3
"""Record actual preserved Python packing and parser outcomes, not a second encoder."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'crates/l2tunnel-codec/tests/data/packed-goldens.tsv'
sys.path.insert(0, str(ROOT / 'simulator/src'))
from l2tunnel_sim.aligned_records import CHANNEL_HEADER, FRAGMENT_HEADER  # noqa: E402
from l2tunnel_sim.compact_wire import CompactWireConfig  # noqa: E402
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic  # noqa: E402
from l2tunnel_sim.model import Simulation  # noqa: E402
from l2tunnel_sim.packed_wire import PackedWireTransport, packed_units  # noqa: E402


def unit(channel, serial, payload):
    return CHANNEL_HEADER.pack(channel, serial) + b'\x02' + len(payload).to_bytes(2, 'big') + payload


def make():
    sim = Simulation(Scenario(70, 0), Traffic(duration_s=1, drain_s=2),
                     (PathConfig(100, 10),), Strategy('packed golden', mode='tcp'), 42)
    config = CompactWireConfig(repair_ratio=0, pack_sources_max_delay_ms=.5,
        short_source_max_bytes=128, short_source_copies=3,
        short_source_copy_scope='context_and_independent', encapsulation='raw_ipv4_crc32')
    transport = PackedWireTransport(sim, False, config)
    emitted = []
    original = transport._seal_pack
    def seal(reason):
        before = len(transport.sources)
        copies = transport._pack_copies
        original(reason)
        for index, source in enumerate(transport.sources[before:], start=before):
            data = transport.source_payloads[index][:source.size]
            emitted.append((reason, copies, data))
    transport._seal_pack = seal
    return sim, transport, emitted


def generate():
    rows = ['# packed-goldens-v1; actual Python methods; times in integer microseconds']
    for name in ('packed_wire.py', 'compact_wire.py', 'aligned_records.py', 'compact.py'):
        path = ROOT / 'simulator/src/l2tunnel_sim' / name
        rows.append(f'# python_source={path.relative_to(ROOT)}; sha256={hashlib.sha256(path.read_bytes()).hexdigest()}')
    small = unit(0, 0, b'a' * 66)
    medium = unit(1, 0, b'b' * 123)
    large = unit(2, 0, b'c' * 900)
    units = [small, medium, large, CHANNEL_HEADER.pack(3, 0) + b'\x03\x00\x40\x00' + bytes(64),
             CHANNEL_HEADER.pack(4, 0) + b'\x06\x00' + bytes(64),
             CHANNEL_HEADER.pack(5, 0) + b'\x07' + bytes(64),
             CHANNEL_HEADER.pack(6, 0) + b'\x05' + bytes(64),
             CHANNEL_HEADER.pack(7, 0) + FRAGMENT_HEADER.pack(4, 1500, 1452) + bytes(48)]
    traces = {
        'deadline': [(0, small), (300, unit(1, 0, b'z' * 66)), (499, None), (500, None)],
        # 100us + 500us is not exact as a Python binary float: observe just
        # after that boundary; Rust separately tests exact integer deadlines.
        'copy_policy': [(0, small), (100, medium), (200, units[3]), (500, None), (601, None)],
        'large': [(0, large), (100, small), (601, None)],
        'explicit': [(0, small), (100, unit(1, 0, b'z' * 66))],
        'single_explicit': [(0, small)],
        'capacity': [(i * 10, unit(i, 0, bytes([i]) * 400)) for i in range(5)] + [(1000, None)],
        'kinds': [(i * 10, value) for i, value in enumerate(units[3:])] + [(500, None), (1000, None)],
    }
    events = 0
    for name, trace in traces.items():
        sim, transport, emitted = make()
        for step, (now, value) in enumerate(trace):
            sim.now = now / 1_000_000
            if value is None:
                if transport._pack_deadline is not None and sim.now >= transport._pack_deadline:
                    transport.flush(transport._pack_generation)
                copies = 0
            else:
                copies = transport._source_copy_count(value)
                transport._queue_source(value)
            out = ';'.join(f'{reason}:{copy}:{data.hex()}' for reason, copy, data in emitted)
            rows.append('\t'.join(('S', name, str(step), str(now), str(copies), '-' if value is None else value.hex(), out or '-')))
            emitted.clear()
            events += 1
        transport.flush()
        out = ';'.join(f'{reason}:{copy}:{data.hex()}' for reason, copy, data in emitted)
        rows.append('\t'.join(('F', name, str(len(trace)), str(trace[-1][0]), '0', '-', out or '-')))
    def container(values):
        return bytes([255, len(values)]) + b''.join(len(v).to_bytes(2, 'big') + v for v in values)
    valid = container([small, units[3]])
    candidates = [valid, valid + bytes(1460 - len(valid)), valid + b'\x01']
    candidates += [container([small, value]) for value in units]
    candidates += [valid[:i] for i in range(len(valid))]
    malformed = [b'', bytes([255, 1]), bytes([0, 2]), bytes([255, 2, 0, 4, 255, 0, 0, 5]),
        CHANNEL_HEADER.pack(1, 0) + b'\x06\x01\x80',
        CHANNEL_HEADER.pack(1, 0) + b'\x0f\x80',
        CHANNEL_HEADER.pack(1, 0) + b'\x03\x00\x00\x01' + b'\x80' * 6,
        CHANNEL_HEADER.pack(1, 0) + FRAGMENT_HEADER.pack(4, 1500, 1451) + bytes(49),
        CHANNEL_HEADER.pack(1, 0) + b'\x00\x00\x41' + bytes(65)]
    candidates += [container([small, value]) for value in malformed]
    for index, payload in enumerate(candidates):
        try:
            values = packed_units(payload, 1460)
            expected = ';'.join(value.hex() for value in values)
        except ValueError:
            expected = 'ERR'
        rows.append('\t'.join(('P', str(index), payload.hex(), expected)))
    return '\n'.join(rows) + '\n', events, len(candidates)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    text, events, parses = generate()
    if args.check:
        if args.output.read_text() != text:
            raise SystemExit('Packed golden vectors differ from actual Python')
        print(f'Verified {events} Python packing events and {parses} parser outcomes.')
    else:
        args.output.write_text(text)
        print(f'Wrote {events} Python packing events and {parses} parser outcomes.')


if __name__ == '__main__':
    main()
