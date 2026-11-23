#!/usr/bin/env python3
"""Finite kernel TCP throughput endpoint; all sockets share one selector/clock."""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import selectors
import resource
import socket
import struct
import time
from pathlib import Path

BLOCK = bytes(range(256)) * 256
MAX_BYTES = 1024 * 1024 * 1024
MAX_SAMPLES = 256
TRANSFER_SECONDS = 30


def validate(flows: int, maximum: int) -> None:
    if type(flows) is not int or flows not in (1, 2, 4):
        raise ValueError('flows must be 1, 2 or 4')
    if type(maximum) is not int or not 65536 <= maximum <= MAX_BYTES:
        raise ValueError('maximum bytes per direction/flow must be 65536..1073741824')


def decode_tcp_info(raw: bytes) -> dict:
    """Linux UAPI offsets; nullable suffix fields preserve older kernel support."""
    value = {'raw_hex': raw.hex(), 'length': len(raw), 'domain': 'application endpoint kernel TCP'}
    for name, offset in [('snd_mss', 16), ('unacked', 24), ('rcv_ssthresh_bytes', 64), ('rtt_us', 68),
                         ('rtt_variance_us', 72), ('snd_ssthresh_segments', 76), ('snd_cwnd_segments', 80),
                         ('advmss_bytes', 84), ('rcv_space_bytes', 96), ('total_retransmitted_segments', 100)]:
        value[name] = struct.unpack_from('=I', raw, offset)[0] if len(raw) >= offset + 4 else None
    value['snd_cwnd_bytes'] = (value['snd_cwnd_segments'] * value['snd_mss']
                               if value['snd_cwnd_segments'] is not None and value['snd_mss'] is not None else None)
    value['peer_advertised_rwnd_bytes'] = struct.unpack_from('=I', raw, 228)[0] if len(raw) >= 232 else None
    value['local_advertised_rwnd_bytes'] = struct.unpack_from('=I', raw, 232)[0] if len(raw) >= 236 else None
    for name, offset in [('bytes_acked', 120), ('bytes_sent', 200), ('bytes_retransmitted', 208)]:
        value[name] = struct.unpack_from('=Q', raw, offset)[0] if len(raw) >= offset + 8 else None
    value['advertised_rwnd_observation'] = 'sampled kernel-maintained scaled peer advertised window; not every wire packet; local rcv_space is separate'
    return value


def tcp_info(stream: socket.socket) -> dict:
    began = time.monotonic_ns()
    value = decode_tcp_info(stream.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256))
    value['read_begin_ns'], value['read_end_ns'] = began, time.monotonic_ns()
    value['send_buffer_bytes'] = stream.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    value['receive_buffer_bytes'] = stream.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    value['congestion_control'] = stream.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 32).split(b'\0')[0].decode('ascii')
    return value


def clock_file(path: Path, deadline_ns: int) -> tuple[int, int, int]:
    while not path.exists():
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('original probe deadline waiting for common clock')
        time.sleep(0.01)
    if path.stat().st_size > 256:
        raise ValueError('clock exceeds bound')
    value = json.loads(path.read_text())
    if set(value) != {'start_ns', 'warmup_ns', 'measure_ns'} or any(type(x) is not int for x in value.values()):
        raise ValueError('invalid common clock')
    start, warmup, measure = (value[k] for k in ('start_ns', 'warmup_ns', 'measure_ns'))
    if not (0 < warmup <= 2_000_000_000 and 0 < measure <= 10_000_000_000
            and time.monotonic_ns() < start < deadline_ns
            and start + warmup + measure < deadline_ns):
        raise ValueError('late or infeasible common measurement clock')
    return start, start + warmup, start + warmup + measure


def transfer(streams: list[socket.socket], start: int, measure_start: int, end: int,
             deadline: int, maximum: int) -> dict:
    if not start < measure_start < end < deadline:
        raise ValueError('invalid original transfer window')
    state = [{'sent': 0, 'received': 0, 'warmup': 0, 'measured': 0, 'postwindow': 0,
              'send_hash': hashlib.sha256(), 'receive_hash': hashlib.sha256(),
              'write_closed': False, 'eof': False, 'bound_exhausted': False} for _ in streams]
    samples, next_sample = [], start
    with selectors.DefaultSelector() as poll:
        for n, stream in enumerate(streams):
            stream.setblocking(False)
            poll.register(stream, selectors.EVENT_READ | selectors.EVENT_WRITE, n)
        while not all(s['eof'] and s['write_closed'] for s in state):
            now = time.monotonic_ns()
            if now >= deadline:
                raise TimeoutError('original probe transfer deadline exhausted')
            if now < start:
                time.sleep(min((start - now) / 1e9, 0.01))
                continue
            if now >= next_sample and len(samples) < MAX_SAMPLES:
                usage = resource.getrusage(resource.RUSAGE_SELF)
                flow_samples = []
                for stream, counters in zip(streams, state):
                    flow_samples.append({**tcp_info(stream), 'application_counters': {
                        key: counters[key] for key in ('sent', 'received', 'warmup', 'measured', 'postwindow')}})
                samples.append({'at_ns': now, 'flows': flow_samples,
                                'process_user_seconds': usage.ru_utime, 'process_system_seconds': usage.ru_stime,
                                'process_maxrss_kib': usage.ru_maxrss})
                next_sample = now + 500_000_000
            for stream, s in zip(streams, state):
                if not s['write_closed'] and (now >= end or s['sent'] == maximum):
                    s['bound_exhausted'] = s['sent'] == maximum and now < end
                    stream.shutdown(socket.SHUT_WR)
                    s['write_closed'] = True
                    if s['eof']:
                        poll.unregister(stream)
                    else:
                        poll.modify(stream, selectors.EVENT_READ, streams.index(stream))
            for key, mask in poll.select(min(0.02, (deadline - now) / 1e9)):
                stream, s = key.fileobj, state[key.data]
                if mask & selectors.EVENT_READ and not s['eof']:
                    try:
                        chunk = stream.recv(65536)
                    except BlockingIOError:
                        chunk = None
                    at = time.monotonic_ns()
                    if chunk == b'':
                        s['eof'] = True
                        if s['write_closed']:
                            poll.unregister(stream)
                        else:
                            poll.modify(stream, selectors.EVENT_WRITE, key.data)
                    elif chunk:
                        s['received'] += len(chunk)
                        if s['received'] > maximum:
                            raise ValueError('peer exceeds configured byte ceiling')
                        s['receive_hash'].update(chunk)
                        bucket = 'warmup' if at < measure_start else 'measured' if at < end else 'postwindow'
                        s[bucket] += len(chunk)
                if mask & selectors.EVENT_WRITE and not s['write_closed'] and time.monotonic_ns() < end:
                    count = min(len(BLOCK), maximum - s['sent'])
                    offset = s['sent'] % len(BLOCK)
                    chunk = (BLOCK[offset:] + BLOCK[:offset])[:count]
                    try:
                        sent = stream.send(chunk)
                    except BlockingIOError:
                        sent = 0
                    s['send_hash'].update(chunk[:sent])
                    s['sent'] += sent
    rows = []
    for s in state:
        rows.append({**{k: v for k, v in s.items() if not k.endswith('_hash')},
                     'sent_sha256': s['send_hash'].hexdigest(),
                     'received_sha256': s['receive_hash'].hexdigest()})
    return {'clock': {'start_ns': start, 'measure_start_ns': measure_start, 'end_ns': end},
            'completed_ns': time.monotonic_ns(), 'flows': rows, 'tcp_info': samples,
            'measurement': 'unique application bytes returned by recv during shared monotonic window'}


def run(role: str, address: str, port: int, flows: int, maximum: int, clock: Path) -> dict:
    validate(flows, maximum)
    ip = ipaddress.ip_address(address)
    if not 1024 <= port <= 65535:
        raise ValueError('port must be 1024..65535')
    deadline = time.monotonic_ns() + TRANSFER_SECONDS * 1_000_000_000
    streams, listener = [], None
    try:
        if role == 'listen':
            listener = socket.socket(socket.AF_INET if ip.version == 4 else socket.AF_INET6, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, port))
            listener.listen(flows)
            print('Listening', flush=True)
        for _ in range(flows):
            remaining = (deadline - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                raise TimeoutError('original connection deadline exhausted')
            if listener:
                listener.settimeout(remaining)
                stream, _ = listener.accept()
            else:
                stream = socket.socket(socket.AF_INET if ip.version == 4 else socket.AF_INET6, socket.SOCK_STREAM)
                streams.append(stream)
                stream.settimeout(remaining)
                stream.connect((address, port))
            if listener:
                streams.append(stream)
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print('Connected', flush=True)
        begin, measured, end = clock_file(clock, deadline)
        return {'role': role, 'max_bytes_per_direction_flow': maximum, 'original_deadline_ns': deadline,
                **transfer(streams, begin, measured, end, deadline, maximum)}
    finally:
        for stream in streams:
            stream.close()
        if listener:
            listener.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('role', choices=['listen', 'connect'])
    p.add_argument('--address', required=True)
    p.add_argument('--port', type=int, default=24451)
    p.add_argument('--flows', type=int, choices=[1, 2, 4], required=True)
    p.add_argument('--max-bytes', type=int, default=256 * 1024 * 1024)
    p.add_argument('--clock', type=Path, required=True)
    a = p.parse_args(argv)
    print(json.dumps(run(a.role, a.address, a.port, a.flows, a.max_bytes, a.clock)), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
