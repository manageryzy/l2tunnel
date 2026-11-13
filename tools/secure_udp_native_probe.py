#!/usr/bin/env python3
"""Finite native TCP/UDP probe; shared timing, exact hashes and explicit send role."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import resource
import selectors
import socket
import time

try:
    from . import throughput_probe as reference
except ImportError:
    import throughput_probe as reference

MAX_FLOWS = 16
MAX_SAMPLES = 96
ORIGINAL_SECONDS = 60


def validate(flows: int, maximum: int, workload: str) -> None:
    if type(flows) is not int or not 1 <= flows <= MAX_FLOWS:
        raise ValueError('flows must be integer1..16')
    if type(maximum) is not int or not 65536 <= maximum <= reference.MAX_BYTES:
        raise ValueError('per-flow byte ceiling must be65536..1073741824')
    if workload not in ('forward16', 'reverse-stress'):
        raise ValueError('explicit forward-only or reverse-stress workload required')


def clock_file(path: Path, deadline: int) -> tuple[int, int, int]:
    while not path.exists():
        if time.monotonic_ns() >= deadline:
            raise TimeoutError('original probe deadline waiting for clock')
        time.sleep(.01)
    if path.stat().st_size > 256:
        raise ValueError('clock exceeds fixed bound')
    value = json.loads(path.read_text())
    if set(value) != {'start_ns', 'warmup_ns', 'measure_ns'} or any(type(x) is not int for x in value.values()):
        raise ValueError('invalid common measurement clock')
    start, warmup, measure = (value[k] for k in ('start_ns', 'warmup_ns', 'measure_ns'))
    if not (0 < warmup <= 10_000_000_000 and 0 < measure <= 30_000_000_000
            and time.monotonic_ns() < start < start + warmup + measure < deadline):
        raise ValueError('late or infeasible common measurement clock')
    return start, start + warmup, start + warmup + measure


def transfer(streams: list[socket.socket], start: int, measured: int, end: int,
             deadline: int, maximum: int, send_enabled: bool) -> dict:
    if not start < measured < end < deadline:
        raise ValueError('invalid original transfer window')
    state = []
    for stream in streams:
        if not send_enabled:
            stream.shutdown(socket.SHUT_WR)
        state.append({'sent': 0, 'received': 0, 'warmup': 0, 'measured': 0,
            'postwindow': 0, 'send_hash': hashlib.sha256(), 'receive_hash': hashlib.sha256(),
            'write_closed': not send_enabled, 'eof': False, 'bound_exhausted': False,
            'local': list(stream.getsockname()), 'peer': list(stream.getpeername())})
    samples, next_sample = [], start
    with selectors.DefaultSelector() as poll:
        for index, stream in enumerate(streams):
            stream.setblocking(False)
            poll.register(stream, selectors.EVENT_READ | (selectors.EVENT_WRITE if send_enabled else 0), index)
        while not all(row['eof'] and row['write_closed'] for row in state):
            now = time.monotonic_ns()
            if now >= deadline:
                raise TimeoutError('original TCP probe transfer deadline exhausted')
            if now < start:
                time.sleep(min((start - now) / 1e9, .01))
                continue
            if now >= next_sample and len(samples) < MAX_SAMPLES:
                usage = resource.getrusage(resource.RUSAGE_SELF)
                samples.append({'at_ns': now, 'flows': [{**reference.tcp_info(stream),
                    'application_counters': {key: row[key] for key in ('sent', 'received', 'warmup', 'measured', 'postwindow')}}
                    for stream, row in zip(streams, state)],
                    'process_user_seconds': usage.ru_utime, 'process_system_seconds': usage.ru_stime,
                    'process_maxrss_kib': usage.ru_maxrss})
                next_sample = now + 500_000_000
            for index, (stream, row) in enumerate(zip(streams, state)):
                if not row['write_closed'] and (now >= end or row['sent'] == maximum):
                    row['bound_exhausted'] = row['sent'] == maximum and now < end
                    stream.shutdown(socket.SHUT_WR)
                    row['write_closed'] = True
                    if row['eof']:
                        poll.unregister(stream)
                    else:
                        poll.modify(stream, selectors.EVENT_READ, index)
            for key, mask in poll.select(min(.02, (deadline - now) / 1e9)):
                stream, row = key.fileobj, state[key.data]
                if mask & selectors.EVENT_READ and not row['eof']:
                    try:
                        chunk = stream.recv(65536)
                    except BlockingIOError:
                        chunk = None
                    at = time.monotonic_ns()
                    if chunk == b'':
                        row['eof'] = True
                        if row['write_closed']:
                            poll.unregister(stream)
                        else:
                            poll.modify(stream, selectors.EVENT_WRITE, key.data)
                    elif chunk:
                        row['received'] += len(chunk)
                        if row['received'] > maximum:
                            raise ValueError('peer exceeds configured TCP byte ceiling')
                        row['receive_hash'].update(chunk)
                        row['warmup' if at < measured else 'measured' if at < end else 'postwindow'] += len(chunk)
                if mask & selectors.EVENT_WRITE and not row['write_closed'] and time.monotonic_ns() < end:
                    count = min(len(reference.BLOCK), maximum - row['sent'])
                    offset = row['sent'] % len(reference.BLOCK)
                    chunk = (reference.BLOCK[offset:] + reference.BLOCK[:offset])[:count]
                    try:
                        sent = stream.send(chunk)
                    except BlockingIOError:
                        sent = 0
                    row['send_hash'].update(chunk[:sent])
                    row['sent'] += sent
    if time.monotonic_ns() >= deadline:
        raise TimeoutError('original TCP deadline reached during final I/O')
    rows = [{**{key: value for key, value in row.items() if not key.endswith('_hash')},
        'sent_sha256': row['send_hash'].hexdigest(), 'received_sha256': row['receive_hash'].hexdigest()} for row in state]
    return {'clock': {'start_ns': start, 'measure_start_ns': measured, 'end_ns': end},
        'completed_ns': time.monotonic_ns(), 'send_enabled': send_enabled, 'flows': rows,
        'tcp_info': samples, 'measurement': 'unique application bytes returned by recv during shared monotonic window'}


def tcp(role: str, address: str, port: int, flows: int, maximum: int, clock: Path, workload: str) -> dict:
    validate(flows, maximum, workload)
    deadline = time.monotonic_ns() + ORIGINAL_SECONDS * 1_000_000_000
    streams, listener = [], None
    try:
        if role == 'listen':
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, port))
            listener.listen(flows)
            print('Listening', flush=True)
        for _ in range(flows):
            remaining = (deadline - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                raise TimeoutError('original TCP connection bound exhausted')
            if listener:
                listener.settimeout(remaining)
                stream, _ = listener.accept()
            else:
                stream = socket.socket()
                stream.settimeout(remaining)
                streams.append(stream)
                stream.connect((address, port))
            if listener:
                streams.append(stream)
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b'cubic')
        print('Connected', flush=True)
        start, measured, end = clock_file(clock, deadline)
        result = transfer(streams, start, measured, end, deadline, maximum,
                          role == 'connect' or workload == 'reverse-stress')
        return {'role': role, 'workload': workload, 'max_bytes_per_direction_flow': maximum,
                'original_deadline_ns': deadline, **result}
    finally:
        for stream in streams:
            stream.close()
        if listener:
            listener.close()


def udp_echo(address: str, port: int, ready: Path, seconds: float = 40) -> dict:
    count, end = 0, time.monotonic() + seconds
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.bind((address, port))
        ready.write_text('ready\n')
        while time.monotonic() < end:
            stream.settimeout(min(.2, max(.001, end - time.monotonic())))
            try:
                data, peer = stream.recvfrom(65535)
            except socket.timeout:
                continue
            stream.sendto(data, peer)
            count += 1
    return {'echoed': count}


def udp_probe(address: str, port: int) -> dict:
    rows, streams, end = [], [], time.monotonic() + 15
    try:
        for length in (0, 1, 18, 64, 512, 1200, 1472):
            for kind in ('zero', 'tail'):
                # Retain at most14 distinct native source sockets so a delayed
                # echo from an application retry cannot masquerade as corruption
                # of the next all-zero payload. No tunnel socket is added.
                stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                streams.append(stream)
                stream.setsockopt(socket.IPPROTO_IP, 10, 2)  # Linux IP_MTU_DISCOVER=DO.
                stream.connect((address, port))
                data = bytes(length) if kind == 'zero' else hashlib.shake_256(f'udp/{length}'.encode()).digest(length)
                if kind == 'tail' and length >= 4:
                    data = data[:-4] + bytes(4)
                answered = False
                for attempt in range(1, 9):
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('original exact UDP probe bound exhausted')
                    stream.settimeout(min(.75, remaining))
                    stream.send(data)
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('original exact UDP deadline reached during send')
                    stream.settimeout(min(.75, remaining))
                    try:
                        answer = stream.recv(65535)
                    except socket.timeout:
                        continue
                    if time.monotonic() >= end:
                        raise TimeoutError('original exact UDP deadline reached during receive')
                    if answer != data:
                        raise ValueError('exact UDP payload or trailing-zero mismatch')
                    answered = True
                    break
                rows.append({'bytes': length, 'pattern': kind, 'sha256': hashlib.sha256(data).hexdigest(),
                             'attempts': attempt, 'answered': answered})
                if not answered:
                    raise TimeoutError('exact UDP application retry ceiling exhausted')
    finally:
        for stream in streams:
            stream.close()
    if time.monotonic() >= end:
        raise TimeoutError('original exact UDP deadline reached before final result')
    return {'status': 'passed', 'rows': rows}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    bulk = sub.add_parser('tcp')
    bulk.add_argument('role', choices=('listen', 'connect'))
    bulk.add_argument('--address', required=True)
    bulk.add_argument('--port', type=int, default=24451)
    bulk.add_argument('--flows', type=int, default=16)
    bulk.add_argument('--max-bytes', type=int, default=256 * 1024 * 1024)
    bulk.add_argument('--clock', type=Path, required=True)
    bulk.add_argument('--workload', choices=('forward16', 'reverse-stress'), required=True)
    for command in ('udp-echo', 'udp-probe'):
        child = sub.add_parser(command)
        child.add_argument('--address', required=True)
        child.add_argument('--port', type=int, default=24461)
        if command == 'udp-echo':
            child.add_argument('--ready', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not 1024 <= args.port <= 65535:
            raise ValueError('probe port outside1024..65535')
        if args.command == 'tcp':
            value = tcp(args.role, args.address, args.port, args.flows, args.max_bytes, args.clock, args.workload)
        elif args.command == 'udp-echo':
            value = udp_echo(args.address, args.port, args.ready)
        else:
            value = udp_probe(args.address, args.port)
        print(json.dumps(value), flush=True)
        return 0
    except Exception as error:
        print(json.dumps({'status': 'bound_exhausted' if isinstance(error, (TimeoutError, socket.timeout)) else 'failed',
                          'error': f'{type(error).__name__}: {error}'}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
