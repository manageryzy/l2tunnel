#!/usr/bin/env python3
"""Bounded native kernel TCP workload for the current Common carrier matrix.

Both endpoints use the same monotonic window and 16 ordinary kernel TCP sockets.
No tunnel codec or recovery policy is implemented here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import resource
import selectors
import signal
import socket
import time

try:
    from . import common_native_c48 as c48, common_native_single_flow as single
    from .throughput_probe import tcp_info
except ImportError:
    import common_native_c48 as c48
    import common_native_single_flow as single
    from throughput_probe import tcp_info

FLOWS = 16
MAX_BYTES = 32 * 1024 * 1024
BLOCK = random.Random(0x12AA2026).randbytes(65536)


class ProbeStopped(Exception):
    """A requested stop must propagate through selectors that catch InterruptedError."""


def write_json(path, value):
    temporary = path.with_suffix('.pending')
    temporary.write_text(json.dumps(value, sort_keys=True) + '\n')
    temporary.replace(path)


def public_flows(states):
    return [{**{key: value for key, value in state.items() if not key.endswith('_hash')},
             'sent_sha256': state['send_hash'].hexdigest(),
             'received_sha256': state['receive_hash'].hexdigest()} for state in states]


def exact_identity(stream, deadline_ns):
    """Read the four-byte setup identity without renewing the original cap."""
    result = bytearray()
    while len(result) < 4:
        remaining = (deadline_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError('original flow identity deadline exhausted')
        stream.settimeout(remaining)
        chunk = stream.recv(4 - len(result))
        if not chunk:
            raise ValueError('truncated flow identity')
        result.extend(chunk)
    return int.from_bytes(result, 'big')


def identify_stream(stream, expected, seen, deadline_ns, flow_count=None):
    """Exchange an explicit bounded flow ID before measurement can begin."""
    limit = FLOWS if flow_count is None else flow_count
    if expected is not None:
        if not 0 <= expected < limit:
            raise ValueError('local flow identity outside bound')
        remaining = (deadline_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError('original flow identity deadline exhausted')
        stream.settimeout(remaining)
        stream.sendall(expected.to_bytes(4, 'big'))
        observed = exact_identity(stream, deadline_ns)
        if observed != expected:
            raise ValueError('flow identity acknowledgment mismatch')
    else:
        observed = exact_identity(stream, deadline_ns)
    if not 0 <= observed < limit or observed in seen:
        raise ValueError('duplicate or out-of-range flow identity')
    if expected is None:
        remaining = (deadline_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError('original flow identity deadline exhausted')
        stream.settimeout(remaining)
        stream.sendall(observed.to_bytes(4, 'big'))
    seen.add(observed)
    return observed


def transfer(streams, sending, clock, deadline_ns, result, *, paced=False, single_flow=False, flow_count=None, record_trace=None,
             credit=single.CREDIT):
    states = [dict(flow_id=index, sent=0, received=0, warmup=0, measured=0, postwindow=0,
                   write_closed=False, eof=False, write_closed_ns=None, peer_eof_ns=None, bound_exhausted=False,
                   send_hash=hashlib.sha256(), receive_hash=hashlib.sha256()) for index, _ in enumerate(streams)]
    result['clock'], result['samples'] = clock, []
    fixed_credit = single_flow or flow_count is not None
    if fixed_credit:
        result['tcp_memory_scope'] = single.tcp_memory_scope()
    start, measured, end = (clock[key] for key in ('start_ns', 'measure_start_ns', 'end_ns'))
    maximum = single.TRANSFER_CAP if fixed_credit else MAX_BYTES
    windows = [single.Window(stream, clock, credit // len(streams)) for stream in streams] if fixed_credit else []
    records = [c48.RecordFlow(i, len(streams), clock, single.RATE if fixed_credit else None)
               for i in range(len(streams))] if paced else []
    next_sample = start
    with selectors.DefaultSelector() as poll:
        for index, stream in enumerate(streams):
            stream.setblocking(False)
            poll.register(stream, selectors.EVENT_READ | (selectors.EVENT_WRITE if sending else 0), index)
        try:
            while not all(state['eof'] and state['write_closed'] for state in states):
                now = time.monotonic_ns()
                for window in windows:
                    window.sample_boundary(now)
                if now >= deadline_ns:
                    raise TimeoutError('original TCP workload deadline exhausted')
                if now < start:
                    time.sleep(min((start - now) / 1e9, .01))
                    continue
                if now >= next_sample and len(result['samples']) < 120:
                    usage = resource.getrusage(resource.RUSAGE_SELF)
                    sample = {'at_ns': now, 'user_seconds': usage.ru_utime,
                        'system_seconds': usage.ru_stime, 'maxrss_kib': usage.ru_maxrss,
                        'flows': [tcp_info(stream) for stream in streams]}
                    if fixed_credit:
                        sample['tcp_ext'] = single.tcp_memory_counters()
                    result['samples'].append(sample)
                    next_sample = now + 500_000_000
                for index, (stream, state) in enumerate(zip(streams, states)):
                    unfinished = paced and records[index].pending
                    # The offer cutoff belongs to the producer. A receive-only socket
                    # sends its FIN after consuming the peer's ordered data and EOF.
                    done_sending = state['eof']
                    if sending:
                        done_sending = (now >= end and not unfinished) or state['sent'] == maximum
                    if not state['write_closed'] and done_sending:
                        state['bound_exhausted'] = state['sent'] == maximum and now < end
                        stream.shutdown(socket.SHUT_WR)
                        state['write_closed'] = True
                        state['write_closed_ns'] = time.monotonic_ns()
                        if state['eof']:
                            if stream.fileno() in poll.get_map():
                                poll.unregister(stream)
                        else:
                            poll.modify(stream, selectors.EVENT_READ, index)
                # In the one-way paced workload the forward sender has no
                # application payload to read while waiting for its next slot.
                if paced and sending and now < end:
                    next_due = min(flow.due_ns(flow.outgoing) for flow in records)
                    if now < next_due:
                        time.sleep((min(next_due, end) - now) / 1e9)
                timeout = min(.01, (deadline_ns - now) / 1e9)
                for idx, window in enumerate(windows):
                    if window.blocked_until is None or states[idx]['write_closed']:
                        continue
                    now = time.monotonic_ns()
                    if now >= window.blocked_until and window.allows(window.needed):
                        poll.modify(streams[idx], selectors.EVENT_READ | selectors.EVENT_WRITE, idx)
                    elif window.blocked_until is not None:
                        timeout = min(timeout, max(0, window.blocked_until - now) / 1e9)
                for key, events in poll.select(timeout):
                    stream, state = key.fileobj, states[key.data]
                    if events & selectors.EVENT_READ and not state['eof']:
                        try:
                            chunk = stream.recv(65536)
                        except BlockingIOError:
                            chunk = None
                        at = time.monotonic_ns()
                        if chunk == b'':
                            state['eof'] = True
                            state['peer_eof_ns'] = at
                            if state['write_closed']:
                                poll.unregister(stream)
                            elif sending:
                                poll.modify(stream, selectors.EVENT_WRITE, key.data)
                            else:
                                poll.unregister(stream)
                        elif chunk:
                            state['received'] += len(chunk)
                            if state['received'] > maximum:
                                raise ValueError('peer exceeded original per-flow byte cap')
                            state['receive_hash'].update(chunk)
                            if paced:
                                records[key.data].receive(chunk, at)
                            bucket = 'warmup' if at < measured else 'measured' if at < end else 'postwindow'
                            state[bucket] += len(chunk)
                    if sending and events & selectors.EVENT_WRITE and not state['write_closed']:
                        at = time.monotonic_ns()
                        window = windows[key.data] if windows else None
                        if paced:
                            record = records[key.data]
                            if window is not None and (record.pending or record.due_ns(record.outgoing) <= at < end):
                                needed = len(record.pending) if record.pending else c48.SIZE
                                if not window.allows(needed):
                                    poll.modify(stream, selectors.EVENT_READ, key.data)
                                    continue
                            chunk = record.offer(at, BLOCK)
                            if not chunk:
                                continue
                        else:
                            if at >= end:
                                continue
                            offset = state['sent'] % len(BLOCK)
                            chunk = BLOCK[offset:offset + min(len(BLOCK) - offset, maximum - state['sent'])]
                        try:
                            count = stream.send(chunk)
                        except BlockingIOError:
                            count = 0
                        state['send_hash'].update(chunk[:count])
                        state['sent'] += count
                        if window is not None:
                            window.accepted(count)
                        if paced:
                            records[key.data].accepted(count)
        finally:
            result['flows'] = public_flows(states)
            result['completed_ns'] = time.monotonic_ns()
            if paced:
                result['paced_records'] = c48.measurements(records, sending)
                result['paced_records']['per_flow'] = [c48.per_flow_measurement(
                    flow, clock, record_trace / f'flow-{flow.identity:02}-record-times.bin'
                    if record_trace is not None and not sending else None) for flow in records]
            for window in windows:
                window.sample_boundary(time.monotonic_ns())
            if windows:
                result['flow_credit'] = [window.report() for window in windows]
            if single_flow:
                result['single_flow'] = windows[0].report()


def run(args):
    deadline = args.deadline_ns
    streams, listener = [], None
    single_flow = getattr(args, 'single_flow_4m', False)
    flow_count = getattr(args, 'flow_count', None)
    fixed_credit = single_flow or flow_count is not None
    flows = flow_count or (1 if single_flow else FLOWS)
    paced = fixed_credit or args.packed_c48_workload
    result = {'status': 'running', 'role': args.role, 'phase': args.phase,
              'original_deadline_ns': deadline, 'max_bytes_per_flow_direction': single.TRANSFER_CAP if fixed_credit else MAX_BYTES}
    credit = getattr(args, 'outstanding_credit_bytes', single.CREDIT)
    if fixed_credit:
        result['outstanding_application_credit_bytes'] = credit
    try:
        if args.role == 'listen':
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if fixed_credit:
                result['socket_before_syn'] = single.before_syn(listener)
            listener.bind((args.address, args.port))
            listener.listen(flows)
            print('Listening', flush=True)
        ordered, seen = [None] * flows, set()
        result['flow_identity'] = {'format': 'u32be-id-echo-v1', 'bytes_each_direction_per_flow': 4,
            'accounting': 'setup bytes excluded from application payload totals and timed sample', 'connections': []}
        for index in range(flows):
            remaining = (deadline - time.monotonic_ns()) / 1e9
            if remaining <= 0:
                raise TimeoutError('original TCP connect deadline exhausted')
            if listener:
                listener.settimeout(remaining)
                stream, _ = listener.accept()
                streams.append(stream)
            else:
                stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                streams.append(stream)
                stream.settimeout(remaining)
                if fixed_credit:
                    result['socket_before_syn'] = single.before_syn(stream)
                stream.connect((args.address, args.port))
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if paced:
                stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b'cubic')
                # Linux doubles SO_SNDBUF/SO_RCVBUF for its bookkeeping. Report
                # the actual values; these socket limits do not set kernel cwnd.
                for key in (socket.SO_SNDBUF, socket.SO_RCVBUF):
                    if not fixed_credit:
                        stream.setsockopt(socket.SOL_SOCKET, key, 128 * 1024)
                    elif stream.getsockopt(socket.SOL_SOCKET, key) != 2 * single.SOCKET_BUFFER:
                        raise ValueError('socket buffer differs from its pre-SYN setting')
            identity = identify_stream(stream, None if listener else index, seen, deadline, flows)
            ordered[identity] = stream
            connection = {'flow_id': identity, 'local': stream.getsockname(), 'peer': stream.getpeername()}
            if paced:
                connection.update(send_buffer_bytes=stream.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                                  receive_buffer_bytes=stream.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                                  tcp_congestion=stream.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16)
                                                       .rstrip(b'\x00').decode('ascii'))
            result['flow_identity']['connections'].append(connection)
        if any(stream is None for stream in ordered):
            raise ValueError('incomplete flow identity set')
        streams = ordered
        result['flow_identity']['connections'].sort(key=lambda item: item['flow_id'])
        print('Connected', flush=True)
        while not args.clock.exists():
            if time.monotonic_ns() >= deadline:
                raise TimeoutError('original common-clock deadline exhausted')
            time.sleep(.01)
        if args.clock.stat().st_size > 1024:
            raise ValueError('common clock exceeds bound')
        clock = json.loads(args.clock.read_text())
        if set(clock) != {'start_ns', 'measure_start_ns', 'end_ns'} or any(type(value) is not int for value in clock.values()):
            raise ValueError('invalid shared clock')
        start, measured, end = (clock[key] for key in ('start_ns', 'measure_start_ns', 'end_ns'))
        if not time.monotonic_ns() < start < measured < end < deadline or measured - start != 2_000_000_000 or end - measured != 10_000_000_000:
            raise ValueError('late or changed 2s warmup/10s sample clock')
        sending = args.phase == 'simultaneous' or (args.phase == 'forward') == (args.role == 'connect')
        transfer(streams, sending, clock, deadline, result, paced=paced, single_flow=single_flow,
                 flow_count=flow_count, record_trace=args.result.parent if args.trace_records else None,
                 credit=credit)
        result['status'] = 'bound_exhausted' if any(row['bound_exhausted'] for row in result['flows']) else 'passed'
    except Exception as error:
        result.update(status='bound_exhausted' if isinstance(error, TimeoutError) else 'failed',
                      error_type='InterruptedError' if isinstance(error, ProbeStopped) else type(error).__name__,
                      error=str(error))
    finally:
        for stream in streams:
            stream.close()
        if listener:
            listener.close()
        write_json(args.result, result)
    print(json.dumps({key: value for key, value in result.items() if key != 'samples'}), flush=True)
    return 0 if result['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['listen', 'connect'])
    parser.add_argument('--phase', choices=['forward', 'reverse', 'simultaneous'], required=True)
    parser.add_argument('--address', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--deadline-ns', type=int, required=True)
    parser.add_argument('--clock', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    workload = parser.add_mutually_exclusive_group()
    workload.add_argument('--packed-c48-workload', action='store_true')
    workload.add_argument('--single-flow-4m', action='store_true')
    workload.add_argument('--flow-count', type=int, choices=(1, 4, 16))
    parser.add_argument('--trace-records', action='store_true')
    parser.add_argument('--outstanding-credit-bytes', type=int, default=single.CREDIT,
                        help='Total unconfirmed application payload credit, divided equally over the '
                             'single-flow/flow-count sockets (default 4 MiB)')
    args = parser.parse_args()
    problem = single.credit_error(args.outstanding_credit_bytes, args.flow_count or 1)
    if problem:
        parser.error(problem)
    if (args.packed_c48_workload or args.single_flow_4m or args.flow_count) and args.phase != 'forward':
        parser.error('C48 workload requires the one-way forward phase')
    if not 1024 <= args.port <= 65535 or not time.monotonic_ns() < args.deadline_ns <= time.monotonic_ns() + 60_000_000_000:
        parser.error('port or original maximum60s workload deadline outside bound')
    if args.result.exists() or args.result.is_symlink():
        parser.error('result already exists')
    def interrupted(signum, _frame):
        # Preserve the existing deadline and publish partial counters from the
        # transfer/run finally blocks before the parent's bounded cleanup ends.
        raise ProbeStopped(f'probe interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
