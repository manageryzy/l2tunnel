#!/usr/bin/env python3
"""Bounded native UDP observation helper; no carrier or management access."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import time

COUNT = 64
SIZE = 64
OBSERVATION_NS = 10_000_000_000
REAP_NS = 1_000_000_000
JSON_LIMIT = 8192


def strict_json(raw: bytes | str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('non-finite JSON value')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def endpoint(value: str) -> tuple[str, int]:
    host, port = value.rsplit(':', 1)
    address = ipaddress.IPv4Address(host)
    number = int(port)
    if not 1 <= number <= 65535:
        raise ValueError('port outside 1..65535')
    return str(address), number


def payload(direction: int, sequence: int) -> bytes:
    if direction not in (0, 1) or not 0 <= sequence < COUNT:
        raise ValueError('burst direction/sequence outside fixed bounds')
    prefix = b'L2B1' + bytes((direction, sequence))
    return prefix + (hashlib.sha256(prefix).digest() * 2)[:SIZE - len(prefix)]


def expected_hash(direction: int) -> str:
    return hashlib.sha256(b''.join(payload(direction, sequence) for sequence in range(COUNT))).hexdigest()


def start_record(raw: bytes | str) -> dict:
    if len(raw) > JSON_LIMIT:
        raise ValueError('start record byte bound')
    value = strict_json(raw)
    if not isinstance(value, dict) or set(value) != {'version', 'started_ns', 'observation_end_ns'}:
        raise ValueError('start record fields')
    if type(value['version']) is not int or value['version'] != 1:
        raise ValueError('start record version')
    for key in ('started_ns', 'observation_end_ns'):
        if type(value[key]) is not int or not 0 <= value[key] < 2**63:
            raise ValueError('start record timestamp')
    if value['observation_end_ns'] - value['started_ns'] != OBSERVATION_NS:
        raise ValueError('observation must be exactly ten seconds')
    return value


def remaining_ns(deadline: int, now=time.monotonic_ns) -> float:
    value = deadline - now()
    if value <= 0:
        raise TimeoutError('original helper deadline exhausted')
    return value / 1_000_000_000


class Multiset:
    """One fixed bitmap: duplicate/excess/malformed records never grow storage."""
    def __init__(self, direction: int):
        self.direction = direction
        self.seen = 0
        self.count = 0

    def accept(self, data: bytes) -> None:
        if len(data) != SIZE or data[:5] != b'L2B1' + bytes((self.direction,)):
            raise ValueError('unexpected burst payload')
        sequence = data[5]
        if sequence >= COUNT or data != payload(self.direction, sequence):
            raise ValueError('unexpected burst sequence/content')
        if self.seen & (1 << sequence):
            raise ValueError('duplicate/excess burst datagram')
        self.seen |= 1 << sequence
        self.count += 1

    def finish(self) -> str:
        if self.seen != (1 << COUNT) - 1 or self.count != COUNT:
            raise ValueError(f'missing burst datagrams: received {self.count}/{COUNT}')
        return expected_hash(self.direction)


def observe(sock, peer: tuple[str, int], direction: int, record: dict, now=time.monotonic_ns) -> dict:
    """Count only reads completed before the immutable cutoff, never kernel arrivals."""
    record = start_record(json.dumps(record))
    if now() < record['started_ns']:
        raise ValueError('observation start lies in the future')
    end = record['observation_end_ns']
    state = Multiset(direction)
    last = None
    while True:
        allowance = end - now()
        if allowance <= 0:
            break
        sock.settimeout(allowance / 1_000_000_000)
        try:
            data, origin = sock.recvfrom(SIZE + 1)
        except socket.timeout:
            continue
        stamp = now()
        if stamp >= end:
            break
        if origin != peer:
            raise ValueError('unexpected native UDP peer')
        state.accept(data)
        last = stamp
    digest = state.finish()
    return {'version': 1, 'status': 'passed', 'kind': 'receive', 'direction': direction,
            'count': state.count, 'bytes': state.count * SIZE, 'sha256': digest,
            **{key: record[key] for key in ('started_ns', 'observation_end_ns')},
            'last_packet_ns': last, 'observed_until_ns': now()}


def send(sock, peer: tuple[str, int], direction: int, record: dict, now=time.monotonic_ns) -> dict:
    record = start_record(json.dumps(record))
    if now() < record['started_ns']:
        raise ValueError('producer start lies in the future')
    end = record['observation_end_ns']
    for sequence in range(COUNT):
        sock.settimeout(remaining_ns(end, now))
        if sock.sendto(payload(direction, sequence), peer) != SIZE:
            raise ValueError('short native UDP send')
        remaining_ns(end, now)
    return {'version': 1, 'status': 'passed', 'kind': 'send', 'direction': direction,
            'count': COUNT, 'bytes': COUNT * SIZE, 'sha256': expected_hash(direction),
            **{key: record[key] for key in ('started_ns', 'observation_end_ns')},
            'completed_ns': now()}


def wait_start(path: Path, deadline: int) -> dict:
    while True:
        remaining_ns(deadline)
        try:
            with path.open('rb') as stream:
                record = start_record(stream.read(JSON_LIMIT + 1))
        except FileNotFoundError:
            time.sleep(min(.001, remaining_ns(deadline)))
            continue
        remaining_ns(deadline)
        return record


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['receive', 'send'])
    parser.add_argument('--bind', required=True, type=endpoint)
    parser.add_argument('--peer', required=True, type=endpoint)
    parser.add_argument('--direction', required=True, type=int, choices=[0, 1])
    parser.add_argument('--start', required=True, type=Path)
    parser.add_argument('--setup-deadline-ns', required=True, type=int)
    parser.add_argument('--ready', type=Path)
    args = parser.parse_args(argv)
    try:
        if (args.operation == 'receive') != (args.ready is not None):
            raise ValueError('readiness path is required only for a receiver')
        remaining_ns(args.setup_deadline_ns)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(args.bind)
            remaining_ns(args.setup_deadline_ns)
            if args.ready is not None:
                temporary = args.ready.with_suffix('.tmp')
                with temporary.open('x') as stream:
                    json.dump({'version': 1, 'bind': list(sock.getsockname()),
                               'peer': list(args.peer), 'direction': args.direction}, stream)
                try:
                    os.link(temporary, args.ready)
                finally:
                    temporary.unlink()
            record = wait_start(args.start, args.setup_deadline_ns)
            result = (observe if args.operation == 'receive' else send)(sock, args.peer, args.direction, record)
        # Socket closure precedes result publication; reaping permits no more IO.
        print(json.dumps(result, separators=(',', ':')), flush=True)
        return 0
    except Exception as error:
        print(json.dumps({'version': 1, 'status': 'failed', 'error': str(error)[:512]}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
