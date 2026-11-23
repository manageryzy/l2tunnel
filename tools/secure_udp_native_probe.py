#!/usr/bin/env python3
"""Finite native TCP/UDP/ICMP probes with original deadlines and exact bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import socket
import struct
import time

try:
    from . import throughput_probe as reference
except ImportError:
    import throughput_probe as reference

MAX_FLOWS = 16
# Defaults for the bounded TCP probe. Long-run studies select larger values with
# `tcp --max-samples/--deadline-seconds/--max-measure-seconds` (e.g. 512/180/90).
MAX_SAMPLES = 96
ORIGINAL_SECONDS = 60
MAX_MEASURE_NS = 30_000_000_000
# Hard ceilings for those options.
LIMIT_SAMPLES = 4096
LIMIT_SECONDS = 3600
ICMP_SECONDS = 12
ICMP_COUNT = 3
ICMP_INTERVAL_NS = 200_000_000
ICMP_PAYLOAD_BYTES = 1472
ICMP_RECEIVE_LIMIT = 256
ICMP_DIAGNOSTIC_LIMIT = 16


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def icmp_request(source: str, address: str, identifier: int, sequence: int, payload: bytes) -> bytes:
    body = bytearray(struct.pack('!BBHHH', 8, 0, 0, identifier, sequence) + payload)
    body[2:4] = internet_checksum(body).to_bytes(2, 'big')
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), sequence,
        0x4000, 64, socket.IPPROTO_ICMP, 0, socket.inet_aton(source), socket.inet_aton(address)))
    header[10:12] = internet_checksum(header).to_bytes(2, 'big')
    return bytes(header + body)


def icmp_reply(packet: bytes, peer: str, source: str, address: str, identifier: int,
               payloads: dict[int, bytes]) -> tuple[str, int | None]:
    """Classify bounded raw IPv4 input; only a complete exact echo can qualify."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return 'invalid_ipv4', None
    if peer != address or packet[12:16] != socket.inet_aton(address) or packet[16:20] != socket.inet_aton(source):
        return 'unrelated_peer', None
    header = (packet[0] & 15) * 4
    if (header < 20 or header > len(packet) or packet[9] != socket.IPPROTO_ICMP
            or internet_checksum(packet[:header]) or int.from_bytes(packet[6:8], 'big') & 0x3fff):
        return 'invalid_ipv4', None
    if len(packet) < header + 8:
        return 'invalid_icmp', None
    body = packet[header:]
    if body[0] != 0:
        return 'unrelated_type', None
    if int.from_bytes(body[4:6], 'big') != identifier:
        return 'unrelated_identifier', None
    sequence = int.from_bytes(body[6:8], 'big')
    if (len(packet) != 1500 or int.from_bytes(packet[2:4], 'big') != len(packet)
            or body[1] != 0 or internet_checksum(body) or sequence not in payloads
            or body[8:] != payloads[sequence]):
        return 'invalid_echo', sequence
    return 'exact', sequence


def icmp_probe(source: str, address: str, deadline_ns: int | None = None, *,
               clock=None, socket_factory=None, random_bytes=None, progress=None) -> dict:
    """Send exactly three DF requests; accept unique exact replies before one bound."""
    clock, socket_factory = clock or time.monotonic_ns, socket_factory or socket.socket
    random_bytes = random_bytes or os.urandom
    source, address = socket.inet_ntoa(socket.inet_aton(source)), socket.inet_ntoa(socket.inet_aton(address))
    if source == address or source == '0.0.0.0' or address == '0.0.0.0':
        raise ValueError('distinct explicit IPv4 source and peer required')
    start = clock()
    if deadline_ns is not None and (type(deadline_ns) is not int or deadline_ns <= 0):
        raise ValueError('positive absolute monotonic deadline required')
    end = min(start + ICMP_SECONDS * 1_000_000_000, deadline_ns) if deadline_ns is not None else start + ICMP_SECONDS * 1_000_000_000
    entropy = random_bytes(18)
    if not isinstance(entropy, bytes) or len(entropy) != 18:
        raise ValueError('exact18-byte fresh ICMP identity required')
    identifier = int.from_bytes(entropy[:2], 'big') or 1
    payloads = {sequence: hashlib.shake_256(entropy[2:] + bytes([sequence])).digest(ICMP_PAYLOAD_BYTES)
                for sequence in range(1, ICMP_COUNT + 1)}
    rows = [{'sequence': sequence, 'sent_ns': None, 'received_ns': None,
             'payload_prefix': payloads[sequence][:16].hex(),
             'payload_sha256': hashlib.sha256(payloads[sequence]).hexdigest()} for sequence in payloads]
    result = {'status': 'running', 'source': source, 'address': address, 'identifier': identifier,
        'request_count': ICMP_COUNT, 'payload_bytes': ICMP_PAYLOAD_BYTES, 'ip_bytes': 1500, 'df': True,
        'started_ns': start, 'original_deadline_ns': end, 'sent': 0, 'received_unique': 0,
        'duplicates': 0, 'reordered': 0, 'late': 0, 'unrelated': 0, 'invalid': 0,
        'ingress_packets': 0, 'diagnostics': [], 'rows': rows}
    def emit(event, **fields):
        if progress:
            progress({'event': event, 'status': 'running', 'sent': result['sent'],
                      'received_unique': result['received_unique'], **fields})
    def diagnostic(kind, at, sequence=None):
        if len(result['diagnostics']) < ICMP_DIAGNOSTIC_LIMIT:
            row = {'kind': kind, 'at_ns': at, 'sequence': sequence}
            result['diagnostics'].append(row)
            emit('icmp_observation', **row)
    stream = None
    try:
        if clock() >= end:
            raise TimeoutError('original ICMP deadline exhausted before socket setup')
        stream = socket_factory(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        remaining = end - clock()
        if remaining <= 0:
            raise TimeoutError('original ICMP deadline exhausted during socket setup')
        stream.settimeout(remaining / 1e9)
        stream.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        stream.setsockopt(socket.IPPROTO_IP, 10, 2)  # Linux IP_MTU_DISCOVER=DO.
        stream.bind((source, 0))
        stream.connect((address, 0))
        while True:
            now = clock()
            if now >= end:
                raise TimeoutError('original ICMP reply deadline exhausted')
            if result['sent'] < ICMP_COUNT and now >= start + result['sent'] * ICMP_INTERVAL_NS:
                sequence = result['sent'] + 1
                packet = icmp_request(source, address, identifier, sequence, payloads[sequence])
                now = clock()
                if now >= end:
                    raise TimeoutError('original ICMP deadline exhausted before request send')
                stream.settimeout((end - now) / 1e9)
                count = stream.send(packet)
                at = clock()
                # A successful irreversible send remains counted even when its
                # completion reaches the original deadline.
                if count == len(packet):
                    result['sent'] += 1
                    rows[sequence - 1]['sent_ns'] = at
                    emit('icmp_sent', sequence=sequence, at_ns=at)
                else:
                    raise ValueError('raw ICMP request was not accepted in full')
                if at >= end:
                    raise TimeoutError('original ICMP deadline reached during send')
                continue
            if result['sent'] == ICMP_COUNT and result['received_unique'] == ICMP_COUNT:
                result['status'] = 'failed' if result['invalid'] else 'passed'
                break
            wake = min(end, start + result['sent'] * ICMP_INTERVAL_NS) if result['sent'] < ICMP_COUNT else end
            stream.settimeout((wake - now) / 1e9)
            try:
                packet, peer = stream.recvfrom(1501)
            except socket.timeout:
                continue
            at = clock()
            result['ingress_packets'] += 1
            if at >= end:
                result['late'] += 1
                diagnostic('late', at)
                raise TimeoutError('original ICMP deadline reached during receive')
            if result['ingress_packets'] > ICMP_RECEIVE_LIMIT:
                raise TimeoutError('ICMP ingress packet ceiling exhausted')
            kind, sequence = icmp_reply(packet, peer[0], source, address, identifier, payloads)
            if kind != 'exact':
                result['unrelated' if kind.startswith('unrelated_') else 'invalid'] += 1
                diagnostic(kind, at, sequence)
                continue
            row = rows[sequence - 1]
            if row['sent_ns'] is None:
                result['invalid'] += 1
                diagnostic('reply_before_request', at, sequence)
            elif row['received_ns'] is not None:
                result['duplicates'] += 1
                diagnostic('duplicate', at, sequence)
            else:
                if any(value['received_ns'] is not None and value['sequence'] > sequence for value in rows):
                    result['reordered'] += 1
                row['received_ns'] = at
                row['rtt_ns'] = at - row['sent_ns']
                result['received_unique'] += 1
                emit('icmp_reply', sequence=sequence, at_ns=at, rtt_ns=row['rtt_ns'])
        if clock() >= end:
            raise TimeoutError('original ICMP deadline reached before final result')
    except Exception as error:
        result.update(status='bound_exhausted' if isinstance(error, (TimeoutError, socket.timeout)) else
                      'tool_failure' if isinstance(error, OSError) else 'failed',
                      error=f'{type(error).__name__}: {error}'[:4096])
    finally:
        if stream:
            try:
                stream.close()
            except OSError as error:
                result.update(status='tool_failure', cleanup_error=f'{type(error).__name__}: {error}'[:4096])
    result['completed_ns'] = clock()
    if result['status'] == 'passed' and result['completed_ns'] >= end:
        result.update(status='bound_exhausted', error='original ICMP deadline reached during finalization')
    return result


def validate(flows: int, maximum: int, workload: str) -> None:
    if type(flows) is not int or not 1 <= flows <= MAX_FLOWS:
        raise ValueError('flows must be integer1..16')
    if type(maximum) is not int or not 65536 <= maximum <= reference.MAX_BYTES:
        raise ValueError('per-flow byte ceiling must be65536..1073741824')
    if workload not in ('forward16', 'reverse-stress'):
        raise ValueError('explicit forward-only or reverse-stress workload required')


def clock_file(path: Path, deadline: int, max_measure_ns: int = MAX_MEASURE_NS) -> tuple[int, int, int]:
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
    if not (0 < warmup <= 10_000_000_000 and 0 < measure <= max_measure_ns
            and time.monotonic_ns() < start < start + warmup + measure < deadline):
        raise ValueError('late or infeasible common measurement clock')
    return start, start + warmup, start + warmup + measure


def transfer(streams: list[socket.socket], start: int, measured: int, end: int,
             deadline: int, maximum: int, send_enabled: bool, max_samples: int = MAX_SAMPLES) -> dict:
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
            if now >= next_sample and len(samples) < max_samples:
                usage = resource.getrusage(resource.RUSAGE_SELF)
                samples.append({'at_ns': now, 'flows': [{**reference.tcp_info(stream),
                    'application_counters': {key: row[key] for key in ('sent', 'received', 'warmup', 'measured', 'postwindow')}}
                    for stream, row in zip(streams, state)],
                    'process_user_seconds': usage.ru_utime, 'process_system_seconds': usage.ru_stime,
                    'process_maxrss_kib': usage.ru_maxrss})
                next_sample = now + 500_000_000
            for index, (stream, row) in enumerate(zip(streams, state)):
                if not row['write_closed'] and (now >= end or row['sent'] == maximum):
                    row['bound_exhausted'] = row['bound_exhausted'] or row['sent'] == maximum and now < end
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
                    if row['sent'] == maximum:
                        # Preserve the exhaustion event even if the next turn
                        # observes shutdown after the measurement boundary.
                        row['bound_exhausted'] = True
    if time.monotonic_ns() >= deadline:
        raise TimeoutError('original TCP deadline reached during final I/O')
    rows = [{**{key: value for key, value in row.items() if not key.endswith('_hash')},
        'sent_sha256': row['send_hash'].hexdigest(), 'received_sha256': row['receive_hash'].hexdigest()} for row in state]
    return {'clock': {'start_ns': start, 'measure_start_ns': measured, 'end_ns': end},
        'completed_ns': time.monotonic_ns(), 'send_enabled': send_enabled, 'flows': rows,
        'tcp_info': samples, 'measurement': 'unique application bytes returned by recv during shared monotonic window'}


def validate_limits(max_samples: int, deadline_seconds: int, max_measure_seconds: int) -> None:
    if type(max_samples) is not int or not 1 <= max_samples <= LIMIT_SAMPLES:
        raise ValueError(f'TCP_INFO sample bound must be 1..{LIMIT_SAMPLES}')
    if type(deadline_seconds) is not int or not 1 <= deadline_seconds <= LIMIT_SECONDS:
        raise ValueError(f'probe deadline must be 1..{LIMIT_SECONDS} seconds')
    if type(max_measure_seconds) is not int or not 1 <= max_measure_seconds < deadline_seconds:
        raise ValueError('measurement bound must be at least 1 second and below the probe deadline')


def tcp(role: str, address: str, port: int, flows: int, maximum: int, clock: Path, workload: str, *,
        max_samples: int = MAX_SAMPLES, deadline_seconds: int = ORIGINAL_SECONDS,
        max_measure_seconds: int = MAX_MEASURE_NS // 1_000_000_000) -> dict:
    validate(flows, maximum, workload)
    validate_limits(max_samples, deadline_seconds, max_measure_seconds)
    deadline = time.monotonic_ns() + deadline_seconds * 1_000_000_000
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
        start, measured, end = clock_file(clock, deadline, max_measure_seconds * 1_000_000_000)
        result = transfer(streams, start, measured, end, deadline, maximum,
                          role == 'connect' or workload == 'reverse-stress', max_samples)
        return {'role': role, 'workload': workload, 'max_bytes_per_direction_flow': maximum,
                'original_deadline_ns': deadline, 'probe_limits': {
                    'max_tcp_info_samples': max_samples, 'deadline_seconds': deadline_seconds,
                    'max_measure_seconds': max_measure_seconds}, **result}
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
    bulk.add_argument('--max-samples', type=int, default=MAX_SAMPLES,
                      help=f'TCP_INFO samples retained at 500 ms spacing (default {MAX_SAMPLES})')
    bulk.add_argument('--deadline-seconds', type=int, default=ORIGINAL_SECONDS,
                      help=f'Whole probe deadline including connect and drain (default {ORIGINAL_SECONDS})')
    bulk.add_argument('--max-measure-seconds', type=int, default=MAX_MEASURE_NS // 1_000_000_000,
                      help=f'Largest accepted shared measurement window (default {MAX_MEASURE_NS // 1_000_000_000})')
    for command in ('udp-echo', 'udp-probe'):
        child = sub.add_parser(command)
        child.add_argument('--address', required=True)
        child.add_argument('--port', type=int, default=24461)
        if command == 'udp-echo':
            child.add_argument('--ready', type=Path, required=True)
    echo = sub.add_parser('icmp-probe')
    echo.add_argument('--source', required=True)
    echo.add_argument('--address', required=True)
    echo.add_argument('--deadline-ns', type=int)
    args = parser.parse_args(argv)
    try:
        if args.command != 'icmp-probe' and not 1024 <= args.port <= 65535:
            raise ValueError('probe port outside1024..65535')
        if args.command == 'icmp-probe':
            value = icmp_probe(args.source, args.address, args.deadline_ns,
                               progress=lambda row: print(json.dumps(row), flush=True))
        elif args.command == 'tcp':
            value = tcp(args.role, args.address, args.port, args.flows, args.max_bytes, args.clock, args.workload,
                        max_samples=args.max_samples, deadline_seconds=args.deadline_seconds,
                        max_measure_seconds=args.max_measure_seconds)
        elif args.command == 'udp-echo':
            value = udp_echo(args.address, args.port, args.ready)
        else:
            value = udp_probe(args.address, args.port)
        print(json.dumps(value), flush=True)
        return 0 if args.command != 'icmp-probe' or value['status'] == 'passed' else 1
    except Exception as error:
        print(json.dumps({'status': 'bound_exhausted' if isinstance(error, (TimeoutError, socket.timeout)) else 'failed',
                          'error': f'{type(error).__name__}: {error}'}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
