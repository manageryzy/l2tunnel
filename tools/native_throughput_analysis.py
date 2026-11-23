#!/usr/bin/env python3
"""Read-only, bounded audit and plots of native_throughput.py case artifacts.

``analyze`` audits finalized case directories written by ``native_throughput.py``
(standard library only) and writes CSV/Markdown/HTML tables to a fresh output
directory. ``plot`` renders bounded PNG/SVG figures from an ``analyze`` output
directory; it imports matplotlib only after its inputs pass their bounds.
Neither command opens sockets, launches processes or changes network state.
"""
from __future__ import annotations
import argparse
import csv
from dataclasses import dataclass
import hashlib
import html
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import struct

MAX_CASES = 128
MAX_FILE = 4 * 1024 * 1024
MAX_BINARY = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_BYTES = 1024 * 1024 * 1024
MAX_SAMPLES = 256
HEX = re.compile(r'[0-9a-f]{64}')
# Executed helpers that native_throughput.py copies into each case directory.
HELPERS = ('native_throughput.py', 'throughput_probe.py', 'proxy_native_smoke.py',
           'proxy_measured_native_smoke.py', 'netns_lab.py')
FIELDS = ('snd_cwnd_bytes', 'peer_advertised_rwnd_bytes', 'local_advertised_rwnd_bytes',
          'rcv_space_bytes', 'rtt_us', 'rtt_variance_us', 'bytes_sent', 'bytes_acked',
          'bytes_retransmitted', 'total_retransmitted_segments')
OFFSETS32 = {'snd_mss': 16, 'rtt_us': 68, 'rtt_variance_us': 72, 'snd_cwnd_segments': 80,
             'rcv_space_bytes': 96, 'total_retransmitted_segments': 100,
             'peer_advertised_rwnd_bytes': 228, 'local_advertised_rwnd_bytes': 232}
OFFSETS64 = {'bytes_acked': 120, 'bytes_sent': 200, 'bytes_retransmitted': 208}
CSV_TABLES = ('cases', 'windows', 'tcp_timeseries', 'wan_intervals', 'wan_coverage', 'tc_deltas',
              'outer_tcp_timeseries', 'internal_relay_targets')
PLOT_MAX_FILE = 128 * 1024 * 1024
PLOT_MAX_ROWS = 300000


@dataclass(frozen=True)
class Config:
    """Plan constants of the audited lab; defaults match native_throughput.py."""
    forward_target_mbps: float = 80
    forward_capacity_mbps: float = 100
    reverse_capacity_mbps: float = 10
    max_measurement_seconds: float = 10
    outer_endpoints: tuple[str, str] = ('192.0.2.2', '192.0.2.6')
    outer_port: int = 18443
    flow_counts: tuple[int, ...] = (1, 2, 4)


DEFAULT_CONFIG = Config()


def compact(value):
    """Keep integral rates as integers so CSV/text match the original output."""
    return int(value) if isinstance(value, float) and value.is_integer() else value


def add_config_arguments(parser):
    """Shared plan options; native_throughput_profiles.py reuses them."""
    d = DEFAULT_CONFIG
    parser.add_argument('--forward-target-mbps', type=float, default=d.forward_target_mbps,
                        help='forward A->B application goodput target (default: %(default)s)')
    parser.add_argument('--forward-capacity-mbps', type=float, default=d.forward_capacity_mbps,
                        help='configured A->B link capacity (default: %(default)s)')
    parser.add_argument('--reverse-capacity-mbps', type=float, default=d.reverse_capacity_mbps,
                        help='configured B->A link capacity (default: %(default)s)')
    parser.add_argument('--max-measurement-seconds', type=float, default=d.max_measurement_seconds,
                        help='upper bound of the shared measurement window (default: %(default)s)')
    parser.add_argument('--outer-endpoints', nargs=2, metavar=('ADDRESS_A', 'ADDRESS_B'),
                        default=list(d.outer_endpoints),
                        help='outer carrier IP pair parsed from ss text (default: %(default)s)')
    parser.add_argument('--outer-port', type=int, default=d.outer_port,
                        help='outer carrier TCP port parsed from ss text (default: %(default)s)')
    parser.add_argument('--flow-counts', type=int, nargs='+', default=list(d.flow_counts),
                        help='accepted per-case flow counts (default: %(default)s)')


def config_from_args(args):
    for address in args.outer_endpoints:
        ipaddress.ip_address(address)
    require(0 < args.outer_port < 65536, 'invalid outer port')
    require(args.max_measurement_seconds > 0 and all(n > 0 for n in args.flow_counts), 'invalid plan bounds')
    return Config(forward_target_mbps=compact(args.forward_target_mbps),
                  forward_capacity_mbps=compact(args.forward_capacity_mbps),
                  reverse_capacity_mbps=compact(args.reverse_capacity_mbps),
                  max_measurement_seconds=compact(args.max_measurement_seconds),
                  outer_endpoints=tuple(str(ipaddress.ip_address(a)) for a in args.outer_endpoints),
                  outer_port=args.outer_port, flow_counts=tuple(args.flow_counts))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name, maximum=(1 << 63) - 1):
    require(type(value) is int and 0 <= value <= maximum, 'invalid integer: ' + name)
    return value


def number(value, name):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0, 'invalid number: ' + name)
    return value


def same_number(left, right, name):
    require(math.isclose(number(left, name), number(right, name), rel_tol=1e-9, abs_tol=1e-9),
            'reported/recomputed mismatch: ' + name)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate JSON key: ' + key)
            value[key] = item
        return value

    def invalid(token):
        raise ValueError('non-finite JSON constant: ' + token)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


class Inputs:
    def __init__(self):
        self.total = 0
        self.manifest = {}

    def read(self, path, limit=MAX_FILE, binary=False):
        path = path.resolve()
        info = path.stat()
        require(stat.S_ISREG(info.st_mode), 'nonregular input: ' + str(path))
        require(info.st_size <= limit, 'input file bound exceeded: ' + str(path))
        self.total += info.st_size
        require(self.total <= MAX_TOTAL, 'aggregate input bound exceeded')
        raw = path.read_bytes()
        require(len(raw) == info.st_size and len(raw) <= limit, 'input changed size while reading: ' + str(path))
        self.manifest[str(path)] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        return raw if binary else raw.decode('utf-8')

    def json(self, path):
        return strict_json(self.read(path))

    def hash_binary(self, path):
        path = path.resolve()
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_BINARY, 'binary file bound exceeded')
        self.total += info.st_size
        require(self.total <= MAX_TOTAL, 'aggregate input bound exceeded')
        digest, count = hashlib.sha256(), 0
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(65536), b''):
                count += len(block)
                require(count <= MAX_BINARY, 'binary grew past bound')
                digest.update(block)
        require(count == info.st_size, 'binary changed size while reading')
        value = digest.hexdigest()
        self.manifest[str(path)] = {'bytes': count, 'sha256': value}
        return value

    def probe(self, path):
        lines = self.read(path).splitlines()
        require(lines and len(lines) <= 512, 'empty or excessive probe log lines')
        result = strict_json(next(line for line in reversed(lines) if line.strip()))
        require(isinstance(result, dict), 'probe result must be object')
        return result


def payload_audit(a, b, flows, config=DEFAULT_CONFIG):
    require(type(flows) is int and flows in config.flow_counts, 'unsupported flow count')
    clock = a['clock']
    require(clock == b['clock'] and set(clock) == {'start_ns', 'measure_start_ns', 'end_ns'},
            'shared monotonic clock mismatch')
    for name in clock:
        integer(clock[name], name)
    require(clock['start_ns'] < clock['measure_start_ns'] < clock['end_ns'], 'invalid measurement ordering')
    duration = (clock['end_ns'] - clock['measure_start_ns']) / 1e9
    require(0 < duration <= config.max_measurement_seconds, 'measurement duration exceeds protocol bound')
    exhausted = False
    for side, result, role in [('a', a, 'connect'), ('b', b, 'listen')]:
        require(result['role'] == role, 'probe role mismatch: ' + side)
        require(len(result['flows']) == flows, 'probe flow count mismatch')
        maximum = integer(result['max_bytes_per_direction_flow'], 'maximum', MAX_BYTES)
        require(maximum >= 65536, 'invalid configured byte ceiling')
        require(clock['end_ns'] < integer(result['original_deadline_ns'], 'deadline'),
                'measurement exceeds original deadline')
        require(clock['end_ns'] <= integer(result['completed_ns'], 'completion') <= result['original_deadline_ns'],
                'incomplete or expired probe completion')
        for row in result['flows']:
            for field in ('sent', 'received', 'warmup', 'measured', 'postwindow'):
                integer(row[field], field, maximum)
            require(row['received'] == row['warmup'] + row['measured'] + row['postwindow'], 'receive bucket sum mismatch')
            require(row['eof'] is True and row['write_closed'] is True, 'incomplete EOF/SHUT_WR')
            require(type(row['bound_exhausted']) is bool, 'invalid ceiling flag')
            exhausted |= row['bound_exhausted']
            for field in ('sent_sha256', 'received_sha256'):
                require(isinstance(row[field], str) and HEX.fullmatch(row[field]), 'invalid SHA256')
    directions = {}
    for name, sender, receiver in [('a_to_b', a, b), ('b_to_a', b, a)]:
        for sent, received in zip(sender['flows'], receiver['flows']):
            require(sent['sent'] == received['received'] and sent['sent_sha256'] == received['received_sha256'],
                    'cross-endpoint exact byte/hash mismatch')
        unique = sum(row['measured'] for row in receiver['flows'])
        directions[name] = {'receiver_unique_bytes': unique, 'seconds': duration,
                            'goodput_mbps': unique * 8 / duration / 1e6,
                            'postwindow_drain_bytes': sum(row['postwindow'] for row in receiver['flows']),
                            'total_exact_bytes': sum(row['received'] for row in receiver['flows'])}
    return clock, exhausted, directions


def provenance(inputs, directory, receipt):
    path = directory / 'build-receipt.json'
    build = inputs.json(path)
    digest = inputs.manifest[str(path.resolve())]['sha256']
    require(digest == receipt['build_receipt_sha256'], 'copied build receipt digest mismatch')
    require(build['status'] == 'passed' and build['exit_code'] == 0 and build['source_stable_during_build'] is True
            and build['changed_during_build'] == [], 'build not source-stable/passed')
    sources = build['source_sha256_after']
    require(isinstance(sources, dict) and 0 < len(sources) <= 10000 and sources == build['source_sha256_before'],
            'build source map mismatch')
    for name, digest in sources.items():
        require(isinstance(name, str) and not Path(name).is_absolute() and '..' not in Path(name).parts
                and isinstance(digest, str) and HEX.fullmatch(digest), 'invalid source map item')
    require(receipt['executed_helpers_unchanged'] is True, 'executed helpers not confirmed unchanged')
    for name in HELPERS:
        text = inputs.read(directory / name)
        actual = hashlib.sha256(text.encode('utf-8')).hexdigest()
        require(sources.get('tools/' + name) == actual == receipt['executed_helpers'].get('tools/' + name),
                'copied helper source mismatch: ' + name)
    binary_hash = inputs.hash_binary(directory / 'l2tunnel-native')
    require(binary_hash == build['binary_sha256'] == receipt['binary_sha256'], 'binary hash mismatch')
    return {'build_receipt_sha256': receipt['build_receipt_sha256'], 'binary_sha256': binary_hash,
            'source_manifest_sha256': hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'probe_source_sha256': sources['tools/throughput_probe.py'],
            'harness_source_sha256': sources['tools/native_throughput.py']}


def tcp_rows(result, side, case):
    samples = result['tcp_info']
    require(isinstance(samples, list) and len(samples) <= MAX_SAMPLES, 'TCP_INFO sample count exceeded')
    clock, flows = result['clock'], len(result['flows'])
    rows, last, last_app = [], {}, {}
    for sample_index, sample in enumerate(samples):
        require(len(sample['flows']) == flows, 'TCP_INFO flow count mismatch')
        integer(sample['at_ns'], 'sample clock')
        for index, info in enumerate(sample['flows']):
            begin = integer(info['read_begin_ns'], 'TCP_INFO begin')
            end = integer(info['read_end_ns'], 'TCP_INFO end')
            require(begin <= end and begin >= last.get(index, 0), 'nonmonotonic TCP_INFO sample')
            last[index] = end
            raw_hex = info['raw_hex']
            require(isinstance(raw_hex, str) and len(raw_hex) <= 1024 and len(raw_hex) % 2 == 0, 'raw TCP_INFO bound')
            raw = bytes.fromhex(raw_hex)
            require(len(raw) == info['length'], 'raw TCP_INFO length mismatch')
            decoded = {name: struct.unpack_from('=I', raw, offset)[0] if len(raw) >= offset + 4 else None
                       for name, offset in OFFSETS32.items()}
            decoded.update({name: struct.unpack_from('=Q', raw, offset)[0] if len(raw) >= offset + 8 else None
                            for name, offset in OFFSETS64.items()})
            decoded['snd_cwnd_bytes'] = (decoded['snd_mss'] * decoded['snd_cwnd_segments']
                                         if decoded['snd_mss'] is not None and decoded['snd_cwnd_segments'] is not None
                                         else None)
            for field, expected in decoded.items():
                require(info.get(field) == expected, 'TCP_INFO decoded field mismatch: ' + field)
            inside = begin >= clock['measure_start_ns'] and end < clock['end_ns']
            row = {'case': case, 'endpoint': side, 'flow': index, 'sample_index': sample_index,
                   'sample_batch_at_ns': sample['at_ns'], 'read_begin_ns': begin, 'read_end_ns': end,
                   'seconds_from_measure_start': ((begin + end) / 2 - clock['measure_start_ns']) / 1e9,
                   'inside_measurement': inside, 'congestion_control': info.get('congestion_control', ''),
                   **{field: decoded[field] for field in FIELDS}}
            app = info['application_counters']
            for field in ('sent', 'received', 'warmup', 'measured', 'postwindow'):
                value = integer(app[field], 'sample ' + field, MAX_BYTES)
                require(value <= result['flows'][index][field], 'sample counter exceeds final value')
                require(value >= last_app.get((index, field), 0), 'application sample counter regressed')
                last_app[index, field] = value
                row['application_' + field] = value
            require(app['received'] == app['warmup'] + app['measured'] + app['postwindow'],
                    'sample receive bucket mismatch')
            rows.append(row)
    return rows


def window_summaries(rows, case):
    result = []
    for side, flow in sorted({(row['endpoint'], row['flow']) for row in rows}):
        selected = [row for row in rows if row['endpoint'] == side and row['flow'] == flow and row['inside_measurement']]
        row = {'case': case, 'endpoint': side, 'flow': flow, 'contained_samples': len(selected),
               'domain': 'native application endpoint kernel TCB; proxy peer may be maintained proxy stack'}
        if selected:
            row.update(first_sample_seconds=selected[0]['seconds_from_measure_start'],
                       last_sample_seconds=selected[-1]['seconds_from_measure_start'],
                       observed_span_seconds=selected[-1]['seconds_from_measure_start'] - selected[0]['seconds_from_measure_start'])
            for field in FIELDS:
                values = [item[field] for item in selected if item[field] is not None]
                row.update({field + '_first': values[0] if values else None, field + '_last': values[-1] if values else None,
                            field + '_min': min(values) if values else None, field + '_max': max(values) if values else None})
                if field in ('bytes_sent', 'bytes_acked', 'bytes_retransmitted', 'total_retransmitted_segments'):
                    if values:
                        require(all(a <= b for a, b in zip(values, values[1:])), 'TCP cumulative counter regressed: ' + field)
                    row[field + '_delta'] = values[-1] - values[0] if len(values) >= 2 else None
        result.append(row)
    return result


def wan_audit(receipt, clock, case):
    samples = receipt['samples']
    require(isinstance(samples, list) and len(samples) <= 96, 'WAN sample count bound exceeded')
    intervals, summaries = [], []
    for side in ('a', 'b'):
        rows = [sample['wan'][side] for sample in samples]
        covered = []
        for first, last in zip(rows, rows[1:]):
            for point in (first, last):
                for field in ('read_begin_ns', 'read_end_ns', 'tx_bytes', 'rx_bytes'):
                    integer(point[field], 'WAN ' + field)
                require(point['read_begin_ns'] <= point['read_end_ns'], 'reversed WAN read bracket')
            require(last['read_begin_ns'] >= first['read_end_ns'], 'overlapping/regressing WAN observations')
            duration = ((last['read_begin_ns'] + last['read_end_ns']) - (first['read_begin_ns'] + first['read_end_ns'])) / 2e9
            require(duration > 0, 'nonpositive WAN interval')
            row = {'case': case, 'endpoint': side, 'begin_read_ns': first['read_begin_ns'], 'begin_end_ns': first['read_end_ns'],
                   'end_read_ns': last['read_begin_ns'], 'end_end_ns': last['read_end_ns'], 'seconds': duration,
                   'inside_measurement': first['read_begin_ns'] >= clock['measure_start_ns'] and last['read_end_ns'] <= clock['end_ns']}
            for direction in ('tx', 'rx'):
                delta = last[direction + '_bytes'] - first[direction + '_bytes']
                require(delta >= 0, 'WAN counter reset')
                row[direction + '_bytes'], row[direction + '_mbps'] = delta, delta * 8 / duration / 1e6
            intervals.append(row)
            if row['inside_measurement']:
                covered.append(row)
        summary = {'case': case, 'endpoint': side, 'status': 'observed' if covered else 'unobserved',
                   'covered_seconds': sum(row['seconds'] for row in covered),
                   'requested_seconds': (clock['end_ns'] - clock['measure_start_ns']) / 1e9}
        if covered:
            summary['boundary_uncertainty_seconds'] = ((covered[0]['begin_end_ns'] - covered[0]['begin_read_ns']) +
                                                       (covered[-1]['end_end_ns'] - covered[-1]['end_read_ns'])) / 2e9
            for direction in ('tx', 'rx'):
                total = sum(row[direction + '_bytes'] for row in covered)
                summary[direction + '_bytes'], summary[direction + '_mbps'] = total, total * 8 / summary['covered_seconds'] / 1e6
        reported = receipt['result']['wire_intervals']['measurement_coverage'][side]
        require(summary['status'] == reported['status'], 'WAN coverage status mismatch')
        for field in ('covered_seconds', 'requested_seconds'):
            same_number(summary[field], reported[field], field)
        if covered:
            same_number(summary['boundary_uncertainty_seconds'], reported['clock_uncertainty_seconds'], 'WAN uncertainty')
            for direction in ('tx', 'rx'):
                require(summary[direction + '_bytes'] == reported[direction + '_bytes'], 'WAN reported byte mismatch')
                same_number(summary[direction + '_mbps'], reported[direction + '_mbps'], 'WAN Mbps')
        summaries.append(summary)
    return intervals, summaries


def tc_audit(receipt, case):
    result = []

    def identity(value):
        return value.get('kind'), value.get('handle'), value.get('parent')
    for side in ('a', 'b'):
        for category in ('class', 'qdisc'):
            before, after = receipt['tc_initial'][side][category], receipt['tc_final'][side][category]
            require(len(before) <= 64 and len(after) <= 64, 'TC object count bound exceeded')
            old = {identity(item): item for item in before}
            require(len(old) == len(before) and len(after) == len(old) and {identity(item) for item in after} == set(old),
                    'TC object changed')
            for item in after:
                key = identity(item)
                row = {'case': case, 'endpoint': side, 'category': category, 'kind': key[0], 'handle': key[1], 'parent': key[2],
                       'scope': 'whole transfer including warmup and drain; not measurement-only'}
                for field in ('bytes', 'packets', 'drops', 'overlimits', 'requeues'):
                    if field in item and field in old[key]:
                        first, last = integer(old[key][field], field), integer(item[field], field)
                        require(last >= first, 'TC counter reset')
                        row[field + '_delta'] = last - first
                result.append(row)
    return result


SS_STATES = {'ESTAB', 'SYN-SENT', 'SYN-RECV', 'FIN-WAIT-1', 'FIN-WAIT-2', 'TIME-WAIT', 'CLOSE-WAIT', 'LAST-ACK',
             'CLOSING', 'CLOSED'}


def outer_ss_rows(receipt, case, config=DEFAULT_CONFIG):
    """Optional known-field parse, retaining raw ss; batch time is not read time."""
    rows, raw_sections, raw_count = [], [], 0
    endpoints = set(config.outer_endpoints)

    def endpoint(text):
        address, port = text.rsplit(':', 1)
        return str(ipaddress.ip_address(address.strip('[]').split('%')[0])), int(port)
    for sample in receipt.get('samples', [])[:96]:
        at = integer(sample['at_ns'], 'ss nominal batch time')
        for namespace, raw in sample.get('outer_and_proxy_socket_ss', {}).items():
            require(isinstance(raw, str) and len(raw) <= 512 * 1024, 'ss text bound')
            if raw_count + len(raw) <= 256 * 1024:
                raw_sections.append(f'CASE {case} NAMESPACE {namespace} NOMINAL_BATCH_NS {at}\n{raw}\n')
                raw_count += len(raw)
            current, records = None, []
            for line in raw.splitlines():
                fields = line.split()
                if fields and fields[0] in SS_STATES:
                    require(len(fields) >= 5, 'unsupported ss socket line')
                    current = {'state': fields[0], 'local': fields[3], 'peer': fields[4], 'text': ''}
                    records.append(current)
                elif current is not None:
                    current['text'] += ' ' + line.strip()
            require(len(records) <= 128, 'ss socket count bound')
            for record in records:
                try:
                    local, peer = endpoint(record['local']), endpoint(record['peer'])
                except ValueError:
                    continue
                if {local[0], peer[0]} != endpoints or config.outer_port not in (local[1], peer[1]):
                    continue
                row = {'case': case, 'namespace': namespace, 'nominal_batch_ns': at,
                       'time_basis': 'batch start before serial commands; individual ss read unbracketed; not exact measurement-window evidence',
                       'domain': 'outer kernel TCP/TLS carrier', 'state': record['state'],
                       'local': record['local'], 'peer': record['peer']}
                tokens = dict(re.findall(r'(?:^|\s)(cwnd|mss|rtt|bytes_sent|bytes_acked|bytes_retrans|snd_wnd|rcv_space):([^\s]+)',
                                         record['text']))
                for key in ('cwnd', 'mss', 'bytes_sent', 'bytes_acked', 'bytes_retrans', 'snd_wnd', 'rcv_space'):
                    row[key] = int(tokens[key]) if key in tokens and tokens[key].isdigit() else None
                row['cwnd_bytes'] = row['cwnd'] * row['mss'] if row['cwnd'] is not None and row['mss'] is not None else None
                for key, value in zip(('rtt_ms', 'rtt_variance_ms'), tokens.get('rtt', '').split('/')):
                    if re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value):
                        row[key] = float(value)
                rows.append(row)
    return rows, '\n'.join(raw_sections)


def relay_rows(receipt, case):
    """Optional copied measured-target DTOs; never treated as TCP windows."""
    rows = []
    for sample in receipt.get('samples', [])[:96]:
        at = integer(sample['at_ns'], 'relay nominal sample time')
        for side, status in sample.get('status', {}).items():
            aggregate = status.get('state', {}).get('proxy', {}).get('measured', {}).get('aggregate')
            if not isinstance(aggregate, dict):
                continue
            row = {'case': case, 'endpoint': side, 'nominal_batch_ns': at,
                   'time_basis': 'batch start; status RPC unbracketed; actor microseconds have separate origin',
                   'domain': 'internal measured relay targets, never endpoint or outer TCP cwnd/rwnd'}
            for field in ('at_micros', 'authoritative_at_micros', 'active_flows', 'demanding_flows', 'unknown_flows',
                          'in_flight_bytes', 'in_flight_records', 'queue_delay_micros'):
                row[field] = integer(aggregate[field], 'relay ' + field)
            for field in ('receiver_pressure', 'carrier_pressure'):
                if field in aggregate:
                    require(type(aggregate[field]) is bool, 'invalid relay pressure boolean')
                    row[field] = aggregate[field]
            applied = aggregate.get('applied')
            if applied is not None:
                row['phase'] = applied['phase']
                for field in ('candidate_bytes', 'candidate_records', 'reserved_bytes', 'reserved_records'):
                    row[field] = integer(applied[field], 'relay target ' + field)
            rows.append(row)
    return rows


def audit_case(inputs, directory, synthetic=False, config=DEFAULT_CONFIG):
    case = directory.name
    errors, receipt, probes = [], {}, {}
    base = {'case': case, 'directory': str(directory.resolve()), 'accepted': False}
    directions, tcp, windows, wan, coverage, tc, outer, outer_raw, relay = {}, [], [], [], [], [], [], '', []
    try:
        receipt = inputs.json(directory / 'receipt.json')
        require(isinstance(receipt, dict), 'receipt must be object')
        synthetic = synthetic or receipt.get('synthetic_fixture') is True
        plan = receipt['plan']
        for field in ('profile', 'path', 'duplex', 'flows', 'family', 'one_way_delay_ms', 'loss_percent_per_direction'):
            base[field] = plan.get(field)
        base.update(receipt_status=receipt.get('status', 'missing'), cleanup=receipt.get('cleanup', 'missing'),
                    netem_seed='not supplied; unseeded random loss', observation='one observation, not statistical evidence',
                    receipt_sha256=inputs.manifest[str((directory / 'receipt.json').resolve())]['sha256'],
                    receipt_error=str(receipt.get('error', ''))[:4096], cleanup_error=str(receipt.get('cleanup_error', ''))[:4096])
    except Exception as error:
        errors.append('receipt: ' + str(error))
    base['data_class'] = 'synthetic_fixture' if synthetic else 'native_case'
    try:
        outer, outer_raw = outer_ss_rows(receipt, case, config)
    except Exception as error:
        base['outer_ss_warning'] = str(error)[:1024]
    try:
        relay = relay_rows(receipt, case)
    except Exception as error:
        base['relay_status_warning'] = str(error)[:1024]
    if (directory / 'policy.json').exists():
        try:
            path = directory / 'policy.json'
            policy = strict_json(inputs.read(path, 65536))
            base['policy_sha256'] = inputs.manifest[str(path.resolve())]['sha256']
            target = policy.get('allocation', {}).get('target', {})
            for field in ('initial', 'session_cap', 'per_flow_cap'):
                if field in target:
                    base['configured_internal_' + field + '_bytes'] = integer(target[field]['bytes'], 'policy ' + field)
        except Exception as error:
            base['policy_warning'] = str(error)[:1024]
    for side in ('a', 'b'):
        try:
            probes[side] = inputs.probe(directory / (side + '-probe.log'))
        except Exception as error:
            errors.append(side + ' probe: ' + str(error))
    payload_verified = False
    if len(probes) == 2:
        try:
            clock, exhausted, directions = payload_audit(probes['a'], probes['b'], base.get('flows'), config)
            base.update(measurement_start_ns=clock['measure_start_ns'], measurement_end_ns=clock['end_ns'],
                        bound_exhausted=exhausted, measurement_seconds=(clock['end_ns'] - clock['measure_start_ns']) / 1e9)
            payload_verified = True
            for side in ('a', 'b'):
                tcp.extend(tcp_rows(probes[side], side, case))
            windows = window_summaries(tcp, case)
        except Exception as error:
            errors.append('payload/windows: ' + str(error))
    base['payload_verified'] = payload_verified
    try:
        base.update(provenance(inputs, directory, receipt))
        base['provenance_verified'] = True
    except Exception as error:
        base['provenance_verified'] = False
        errors.append('provenance: ' + str(error))
    if payload_verified:
        try:
            for direction, values in directions.items():
                reported = receipt['result']['directions'][direction]
                for field, expected in values.items():
                    same_number(reported[field], expected, direction + ' ' + field)
            require(receipt['result']['hashes_and_eof'] == 'passed', 'receipt byte/EOF audit failed')
            wan, coverage = wan_audit(receipt, probes['a']['clock'], case)
            tc = tc_audit(receipt, case)
        except Exception as error:
            errors.append('receipt accounting: ' + str(error))
    eligible = bool(not errors and payload_verified and base.get('provenance_verified')
                    and base.get('receipt_status') == 'passed' and receipt.get('result', {}).get('status') == 'passed'
                    and base.get('cleanup') == 'passed' and base.get('bound_exhausted') is False
                    and len(coverage) == 2 and all(row['status'] == 'observed' for row in coverage))
    base['eligible_accounting'] = eligible
    base['accepted'] = eligible and not synthetic
    base['analysis_errors'] = ' | '.join(errors)[:8192]
    base['classification'] = 'accepted' if base['accepted'] else 'synthetic-only' if synthetic and eligible else 'diagnostic'
    direction_rows = []
    for direction in ('a_to_b', 'b_to_a'):
        row = {**base, 'direction': direction}
        values = directions.get(direction)
        if values is not None:
            row.update(receiver_unique_bytes_verified=values['receiver_unique_bytes'],
                       postwindow_drain_bytes=values['postwindow_drain_bytes'],
                       total_exact_bytes=values['total_exact_bytes'],
                       accepted_goodput_mbps=values['goodput_mbps'] if base['accepted'] else None,
                       diagnostic_goodput_mbps=values['goodput_mbps'] if not base['accepted'] else None)
        reported = receipt.get('result', {}).get('directions', {}).get(direction, {})
        row['receipt_reported_goodput_mbps'] = reported.get('goodput_mbps')
        forward = direction == 'a_to_b'
        row['configured_direction_capacity_mbps'] = config.forward_capacity_mbps if forward else config.reverse_capacity_mbps
        row['performance_target_mbps'] = config.forward_target_mbps if forward else None
        if forward and base['accepted']:
            row['performance_status'] = ('performance_pass' if values['goodput_mbps'] >= config.forward_target_mbps
                                         else 'performance_fail')
        else:
            row['performance_status'] = ('unqualified' if forward
                                         else f'separate_reverse_{config.reverse_capacity_mbps}mbps_direction')
        direction_rows.append(row)
    for collection in (tcp, windows, wan, coverage, tc, outer, relay):
        for row in collection:
            row.update(accepted=base['accepted'], classification=base['classification'], data_class=base['data_class'])
    return {'base': base, 'cases': direction_rows, 'tcp_timeseries': tcp, 'windows': windows,
            'wan_intervals': wan, 'wan_coverage': coverage, 'tc_deltas': tc, 'outer_tcp_timeseries': outer,
            'outer_ss_raw': outer_raw, 'internal_relay_targets': relay}


def write_csv(path, rows):
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with path.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=keys or ['case'])
        writer.writeheader()
        writer.writerows(rows)


def format_value(value):
    return 'unobserved' if value is None else f'{value:.3f}' if type(value) is float else str(value)


def report(results, config=DEFAULT_CONFIG):
    target, forward, reverse = config.forward_target_mbps, config.forward_capacity_mbps, config.reverse_capacity_mbps
    accepted = [item for item in results if item['base']['accepted']]
    lines = ['# Native throughput and TCP window observations', '',
             f'{len(accepted)} integrity-accepted native cases; {len(results) - len(accepted)} diagnostic or synthetic cases. '
             'Each netem case is one unseeded observation, not a statistical estimate.', '',
             'Goodput counts unique application bytes returned by `recv` during the identical shared monotonic '
             'measurement window. Warmup and post-window drain are excluded. SHA256, total byte counts, both EOFs, '
             'original deadlines, cleanup, copied binary/helpers and source-stable build receipt are audited independently.', '',
             'TCP_INFO values describe the application endpoint kernel TCB. cwnd is segments × current send MSS; '
             'peer/local advertised receive windows are sampled scaled kernel fields when supported. `rcv_space` '
             'is separate. In proxy profiles the endpoint peer can be the maintained proxy stack; internal relay '
             'targets do not become endpoint cwnd. First/last mean first/last fully contained sample, not interpolated '
             'values at exact measurement boundaries. Counter deltas cover only that observed sample span.', '',
             'Outer kernel TCP/TLS sockets are a separate domain. Their `ss` text has only a nominal batch-start '
             'timestamp, so optional outer min/max values cover the whole recorded trace and do not claim the exact '
             'measurement window. Inner cwnd can remain high while outer cwnd shrinks under loss hidden by the '
             'reliable carrier. Internal relay/active targets are a third domain, not either TCP cwnd.', '',
             'WAN Mbps uses only fully contained interface-counter intervals, with actual coverage and read-clock '
             'uncertainty reported separately from the requested application window. Veth counters include outer '
             'TCP/TLS, ACKs and retransmissions; they are not physical Ethernet line rate. TC drops cover the whole '
             'probe including warmup and drain; parent/child qdisc counters must not be added together.', '',
             f'Performance is assessed separately from integrity: the user-required forward application target is {target} Mbps '
             f'on the {forward} Mbps A→B link. A lower verified result is `performance_fail`, even when payload integrity and '
             f'cleanup pass. The {reverse} Mbps B→A direction has a separate capacity and is not evaluated against the '
             f'{target} Mbps target. Unqualified cases cannot pass performance.', '',
             '| Case | Profile/path/duplex/flows | Integrity classification | A→B Mbps | B→A Mbps | Forward performance | Cleanup |',
             '|---|---|---|---:|---:|---|---|']
    for item in results:
        base = item['base']
        rates = [row.get('accepted_goodput_mbps') for row in item['cases']]
        if base['classification'] == 'synthetic-only':
            rates = [None, None]
        lines.append('| ' + ' | '.join(str(value).replace('|', '\\|').replace('\n', ' ') for value in
                     [base['case'], '/'.join(str(base.get(key, '?')) for key in ('profile', 'path', 'duplex', 'flows')),
                      base['classification'], format_value(rates[0]), format_value(rates[1]),
                      item['cases'][0]['performance_status'], base.get('cleanup', 'missing')]) + ' |')
    for item in results:
        base = item['base']
        lines += ['', '## ' + base['case'], '',
                  f"Receipt status: `{base.get('receipt_status', 'missing')}`; classification: `{base['classification']}`; "
                  f"cleanup: `{base.get('cleanup', 'missing')}`."]
        if base['analysis_errors']:
            lines += ['', 'Audit diagnostics: ' + base['analysis_errors'].replace('\n', ' ')[:8192]]
        if base.get('receipt_error'):
            lines += ['', 'Case diagnostic: ' + base['receipt_error'].replace('\n', ' ')]
        lines += ['', f"Source manifest SHA256: `{base.get('source_manifest_sha256', 'unverified')}`. "
                  f"Binary SHA256: `{base.get('binary_sha256', 'unverified')}`."]
        if not base['accepted']:
            lines += ['', 'No metrics from this case are included as accepted native performance. '
                      'Available values remain in diagnostic CSV rows.']
            continue
        lines += ['', '| Endpoint/flow | cwnd bytes min/max | Peer rwnd bytes min/max | Local rwnd bytes min/max | '
                  'RTT us min/max | Retransmitted bytes delta | Observed span s |',
                  '|---|---:|---:|---:|---:|---:|---:|']
        for row in item['windows']:
            def cell(field):
                return '/'.join(format_value(row.get(field + '_' + suffix)) for suffix in ('min', 'max'))
            lines.append('| ' + ' | '.join([f"{row['endpoint']}/{row['flow']}", cell('snd_cwnd_bytes'),
                                            cell('peer_advertised_rwnd_bytes'), cell('local_advertised_rwnd_bytes'),
                                            cell('rtt_us'), format_value(row.get('bytes_retransmitted_delta')),
                                            format_value(row.get('observed_span_seconds'))]) + ' |')
        for row in item['wan_coverage']:
            lines += ['', f"WAN {row['endpoint']}: {format_value(row.get('tx_mbps'))} TX / {format_value(row.get('rx_mbps'))} RX Mbps over "
                      f"{format_value(row['covered_seconds'])} of {format_value(row['requested_seconds'])} requested seconds; boundary uncertainty "
                      f"{format_value(row.get('boundary_uncertainty_seconds'))} seconds."]
        drops = [row for row in item['tc_deltas'] if row['category'] == 'qdisc' and row['kind'] == 'netem']
        for row in drops:
            lines += ['', f"Whole-probe netem drops {row['endpoint']}/{row.get('handle')}: {format_value(row.get('drops_delta'))}; "
                      'not a measurement-window-only loss count.']
        grouped = {}
        for row in item['outer_tcp_timeseries']:
            grouped.setdefault((row['namespace'], row['local'], row['peer']), []).append(row)
        if grouped:
            lines += ['', 'Outer TCP/TLS, whole recorded trace (nominal batch times):', '',
                      '| Namespace/local → peer | cwnd bytes min/max | RTT ms min/max |', '|---|---:|---:|']
            for identity, points in grouped.items():
                def extent(field):
                    values = [point[field] for point in points if point.get(field) is not None]
                    return '/'.join(format_value(value) for value in (min(values), max(values))) if values else 'unobserved'
                lines.append('| ' + ' | '.join([' / '.join(identity), extent('cwnd_bytes'), extent('rtt_ms')]) + ' |')
        for side in sorted({row['endpoint'] for row in item['internal_relay_targets']}):
            values = [row['candidate_bytes'] for row in item['internal_relay_targets']
                      if row['endpoint'] == side and 'candidate_bytes' in row]
            if values:
                lines += ['', f'Internal measured relay candidate target {side}, whole recorded trace: {min(values)}..{max(values)} '
                          'bytes. This is neither native nor outer TCP cwnd/rwnd.']
    lines += ['', 'CSV files retain all per-flow samples and first/last/min/max values, observed counter deltas, WAN intervals, '
              'TC identities and failed-case diagnostics. `input_manifest.json` pins every artifact read and this analyzer. '
              'Synthetic fixture rows are never accepted as native measurements.', '']
    return '\n'.join(lines)


def analyze(case_paths, output, synthetic=False, config=DEFAULT_CONFIG):
    require(0 < len(case_paths) <= MAX_CASES, 'case count bound exceeded')
    directories = [path.resolve() for path in case_paths]
    require(len(set(directories)) == len(directories), 'duplicate input directory')
    require(all(path.is_dir() for path in directories),
            'each input must be a case directory; exclude runner logs/files from shell globs')
    require(len({path.name for path in directories}) == len(directories), 'case directory basenames must be unique for CSV joins')
    require(output.resolve() not in directories, 'report output must not replace an input case')
    inputs = Inputs()
    results = [audit_case(inputs, directory, synthetic, config) for directory in directories]
    output.mkdir(parents=True, exist_ok=False)
    for key in CSV_TABLES:
        write_csv(output / (key + '.csv'), [row for item in results for row in item[key]])
    text = report(results, config)
    (output / 'report.md').write_text(text, encoding='utf-8')
    (output / 'outer_ss_raw.txt').write_text('\n'.join(item['outer_ss_raw'] for item in results), encoding='utf-8')
    # An offline HTML view carries the same report; no scripts, fonts or external dependencies.
    (output / 'report.html').write_text(
        '<!doctype html><meta charset="utf-8"><title>Throughput observations</title>'
        '<style>body{font:15px system-ui;margin:2rem;max-width:100rem}pre{white-space:pre-wrap;line-height:1.5}</style><pre>'
        + html.escape(text) + '</pre>', encoding='utf-8')
    manifest = {'analyzer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'inputs': inputs.manifest,
                'accepted_native_cases': sum(item['base']['accepted'] for item in results), 'cases': len(results),
                'config': {**config.__dict__, 'outer_endpoints': list(config.outer_endpoints),
                           'flow_counts': list(config.flow_counts)},
                'bounds': {'cases': MAX_CASES, 'json_or_log_bytes': MAX_FILE, 'binary_bytes': MAX_BINARY,
                           'total_input_bytes': MAX_TOTAL}}
    (output / 'input_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return {'output': str(output.resolve()), 'accepted_native_cases': manifest['accepted_native_cases'], 'cases': len(results)}


# ---------------------------------------------------------------------------
# Plotting of an analyze output directory.


def read_csv(path, max_file=PLOT_MAX_FILE, max_rows=PLOT_MAX_ROWS):
    if not path.is_file() or path.stat().st_size > max_file:
        raise ValueError('missing or oversized CSV: ' + str(path))
    with path.open(newline='') as stream:
        rows = []
        for row in csv.DictReader(stream):
            if len(rows) == max_rows:
                raise ValueError('CSV row bound exceeded')
            rows.append(row)
    return rows


def csv_number(row, field):
    value = row.get(field, '')
    if value in ('', None):
        return None
    value = float(value)
    if not math.isfinite(value):
        raise ValueError('nonfinite field: ' + field)
    return value


def truth(value):
    return value in ('True', 'true', '1')


def receive_intervals(rows, side, flows, start_ns):
    """Adjacent complete batches only. Gaps/boundary batches are not bridged."""
    batches = {}
    for row in rows:
        if row['endpoint'] == side and row.get('sample_index', '') != '':
            batches.setdefault(int(row['sample_index']), []).append(row)
    points = {}
    for index, group in batches.items():
        if len(group) != flows or {int(r['flow']) for r in group} != set(range(flows)):
            continue
        if not all(truth(r['inside_measurement']) for r in group):
            continue
        begin = min(int(r['read_begin_ns']) for r in group)
        end = max(int(r['read_end_ns']) for r in group)
        points[index] = (((begin + end) / 2 - start_ns) / 1e9,
                         sum(int(r['application_measured']) for r in group),
                         (end - begin) / 1e9)
    result = []
    for index in sorted(points):
        if index - 1 not in points:
            continue
        t0, n0, uncertainty0 = points[index - 1]
        t1, n1, uncertainty1 = points[index]
        if t1 <= t0 or n1 < n0:
            raise ValueError('nonmonotonic receive accounting')
        result.append({'endpoint': side, 'sample_start': index - 1, 'sample_end': index,
                       'start_seconds': t0, 'end_seconds': t1,
                       'unique_bytes_delta': n1 - n0, 'mbps': (n1 - n0) * 8 / (t1 - t0) / 1e6,
                       'start_batch_bracket_seconds': uncertainty0,
                       'end_batch_bracket_seconds': uncertainty1})
    return result


def plan_rates(base):
    """Target/capacity text values from the audited rows, or the defaults for old reports."""
    forward = next((r for r in base if r.get('direction') == 'a_to_b'), {})
    reverse = next((r for r in base if r.get('direction') == 'b_to_a'), {})
    d = DEFAULT_CONFIG
    return (forward.get('performance_target_mbps') or str(d.forward_target_mbps),
            forward.get('configured_direction_capacity_mbps') or str(d.forward_capacity_mbps),
            reverse.get('configured_direction_capacity_mbps') or str(d.reverse_capacity_mbps))


def plot(report_dir, output):
    report_dir = report_dir.resolve()
    tables = {name: read_csv(report_dir / (name + '.csv')) for name in
              ('cases', 'tcp_timeseries', 'outer_tcp_timeseries')}
    cases = sorted({row['case'] for row in tables['cases']})
    if not 0 < len(cases) <= MAX_CASES:
        raise ValueError('case bound exceeded')
    # Load the plotting backend only after the input bounds have been checked.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size': 9, 'svg.fonttype': 'none'})
    output.mkdir(parents=True, exist_ok=False)
    links = []
    for name in CSV_TABLES:
        links.append('<a href="' + html.escape(os.path.relpath(report_dir / (name + '.csv'), output), quote=True)
                     + '">' + name + '.csv</a>')
    parts = ['<!doctype html><html lang="en"><meta charset="utf-8"><title>Native throughput observations</title>',
             '<style>body{font:15px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem;line-height:1.5}'
             'img{width:100%;height:auto}table{border-collapse:collapse}td,th{padding:.4rem;border:1px solid #aaa}'
             '.note{color:#444}</style><h1>Native throughput and TCP windows</h1>',
             '<p>Each native case is one observation, not a statistical estimate. Failed, exhausted or synthetic '
             'cases never contribute accepted performance. All plots retain the case classification.</p>',
             '<p>Receive-rate segments use differences of unique measured application-byte counters between '
             'adjacent complete TCP_INFO batches fully inside the shared measurement window. Their timestamps '
             'are batch-bracket midpoints. Unsampled boundary gaps are left empty. The exact whole-window '
             'mean comes from final byte accounting, not these sampled rates.</p>',
             '<p>Inner cwnd and advertised rwnd describe the application kernel TCB. Outer TCP/TLS sockets '
             'are a separate domain. Missing values stay unobserved; lines only connect recorded samples. '
             'Outer ss has nominal serial-command batch timestamps and cannot support exact-window means.</p>',
             '<p>' + ' · '.join(links) + '</p>']
    interval_rows = []
    output_hashes = {}

    def save(fig, stem):
        fig.tight_layout(rect=(0, .025, 1, .94))
        for suffix in ('.png', '.svg'):
            target = output / (stem + suffix)
            fig.savefig(target, dpi=120, metadata={'Creator': 'native_throughput_analysis.py plot'})
            output_hashes[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
        plt.close(fig)
        parts.append('<p><a href="' + stem + '.svg"><img alt="' + html.escape(stem) + '" src="' + stem + '.png"></a>'
                     '<a href="' + stem + '.svg">SVG</a> · <a href="' + stem + '.png">PNG</a></p>')

    for case_index, case in enumerate(cases):
        base = [r for r in tables['cases'] if r['case'] == case]
        config = base[0]
        selected = [r for r in tables['tcp_timeseries'] if r['case'] == case]
        accepted = all(truth(r['accepted']) for r in base)
        classification = config['classification']
        forward = next((r for r in base if r['direction'] == 'a_to_b'), config)
        performance = forward.get('performance_status', 'performance_unassessed')
        target, forward_capacity, reverse_capacity = plan_rates(base)
        label = case + ' [' + classification.upper() + '; ' + performance.upper() + ']'
        parts.append('<h2>' + html.escape(label) + '</h2><p>' + html.escape(' / '.join(config.get(k, '') for k in
                     ('profile', 'path', 'duplex', 'flows'))) + '</p>')
        parts.append('<p>Forward application target: ' + html.escape(target) + ' Mbps on the '
                     + html.escape(forward_capacity) + ' Mbps A→B link; status: <strong>'
                     + html.escape(performance) + '</strong>. Reverse B→A is a separate '
                     + html.escape(reverse_capacity) + ' Mbps direction.</p>')
        parts.append('<table><tr><th>Direction</th><th>Integrity-accepted whole-window Mbps</th>'
                     '<th>Diagnostic verified Mbps</th></tr>')
        for row in base:
            parts.append('<tr>' + ''.join('<td>' + html.escape(row.get(k, '') or 'unobserved') + '</td>' for k in
                         ('direction', 'accepted_goodput_mbps', 'diagnostic_goodput_mbps')) + '</tr>')
        parts.append('</table>')
        if not selected or not config.get('measurement_start_ns'):
            parts.append('<p>Application samples unobserved; no inferred plot.</p>')
            continue
        start = int(config['measurement_start_ns'])
        seconds = float(config['measurement_seconds'])
        flows = int(config['flows'])
        stem = 'case-' + str(case_index + 1).zfill(3)
        fig, axes = plt.subplots(2, 1, figsize=(11, 5.8), sharex=True)
        for ax, (side, direction) in zip(axes, [('b', 'A→B'), ('a', 'B→A')]):
            intervals = receive_intervals(selected, side, flows, start)
            for item in intervals:
                interval_rows.append({'case': case, 'classification': classification, **item})
                ax.hlines(item['mbps'], item['start_seconds'], item['end_seconds'], color='#1764ab', linewidth=2)
                ax.plot((item['start_seconds'] + item['end_seconds']) / 2, item['mbps'], '.', color='#1764ab')
            match = next((r for r in base if r['direction'] == direction), None)
            # Direction field may use ASCII; endpoint mapping remains explicit.
            if match is None:
                match = next((r for r in base if r['direction'].lower().replace(' ', '') ==
                              ('a_to_b' if side == 'b' else 'b_to_a')), None)
            if match is not None and accepted and match.get('accepted_goodput_mbps'):
                ax.axhline(float(match['accepted_goodput_mbps']), linestyle='--', color='#a33',
                           label='Exact whole-window mean')
                ax.legend(loc='upper right')
            if not intervals:
                ax.text(.5, .5, 'Unobserved: no adjacent complete contained batches', transform=ax.transAxes, ha='center')
            ax.set(ylabel=direction + ' received Mbps', xlim=(0, seconds))
            ax.grid(alpha=.25)
        axes[-1].set_xlabel('Seconds from shared measurement start; warmup/drain excluded')
        fig.suptitle(label + ' — unique application receive rates')
        save(fig, stem + '-goodput')
        fig, axes = plt.subplots(2, 3, figsize=(13, 6), sharex=True)
        fields = [('snd_cwnd_bytes', 'Send cwnd (KiB)'), ('peer_advertised_rwnd_bytes', 'Peer advertised rwnd (KiB)'),
                  ('local_advertised_rwnd_bytes', 'Local advertised rwnd (KiB)')]
        for index, side in enumerate(('a', 'b')):
            for ax, (field, title) in zip(axes[index], fields):
                observed = False
                for flow in range(flows):
                    group = sorted([r for r in selected if r['endpoint'] == side and int(r['flow']) == flow
                                    and truth(r['inside_measurement'])], key=lambda r: int(r['sample_index']))
                    x, y, prior = [], [], None
                    for row in group:
                        sample_index = int(row['sample_index'])
                        if prior is not None and sample_index != prior + 1:
                            x.append(math.nan)
                            y.append(math.nan)
                        x.append(float(row['seconds_from_measure_start']))
                        value = csv_number(row, field)
                        y.append(value / 1024 if value is not None else math.nan)
                        prior = sample_index
                    if any(math.isfinite(v) for v in y):
                        observed = True
                        ax.plot(x, y, '.-', markersize=3, linewidth=.8, label='flow ' + str(flow))
                if not observed:
                    ax.text(.5, .5, 'Unobserved', transform=ax.transAxes, ha='center')
                ax.set(title='Endpoint ' + side.upper() + ': ' + title, xlim=(0, seconds))
                ax.grid(alpha=.25)
                if observed and flows > 1:
                    ax.legend(fontsize=7)
        for ax in axes[-1]:
            ax.set_xlabel('Seconds from shared measurement start')
        fig.suptitle(label + ' — inner application kernel TCP; contained read brackets only')
        save(fig, stem + '-inner-windows')
        outer = [r for r in tables['outer_tcp_timeseries'] if r['case'] == case]
        if outer:
            fig, axes = plt.subplots(2, 1, figsize=(11, 6), sharex=True)
            identities = sorted({(r['namespace'], r['local'], r['peer']) for r in outer})
            for ident in identities:
                group = sorted([r for r in outer if (r['namespace'], r['local'], r['peer']) == ident],
                               key=lambda r: int(r['nominal_batch_ns']))
                x = [(int(r['nominal_batch_ns']) - start) / 1e9 for r in group]
                for ax, field, scale in [(axes[0], 'cwnd_bytes', 1024), (axes[1], 'rtt_ms', 1)]:
                    y = [csv_number(r, field) / scale if csv_number(r, field) is not None else math.nan for r in group]
                    if any(math.isfinite(v) for v in y):
                        ax.plot(x, y, '.', markersize=4, label=' / '.join(ident))
            for ax in axes:
                ax.axvline(0, linestyle='--', color='gray')
                ax.axvline(seconds, linestyle='--', color='gray')
                ax.grid(alpha=.25)
            axes[0].set_ylabel('Outer send cwnd (KiB)')
            axes[1].set_ylabel('Outer RTT (ms)')
            axes[0].legend(fontsize=6, loc='upper left')
            axes[1].set_xlabel('Nominal ss batch seconds from measurement start; individual reads unbracketed')
            fig.suptitle(label + ' — outer TCP/TLS, whole trace; no exact-window mean')
            save(fig, stem + '-outer-tcp')
    if interval_rows:
        with (output / 'sampled_receive_intervals.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(interval_rows[0]))
            writer.writeheader()
            writer.writerows(interval_rows)
    parts.append('<p>Input numerical report: <a href="' + html.escape(os.path.relpath(report_dir / 'report.md', output), quote=True)
                 + '">report.md</a>. CSVs remain authoritative; plots do not add qualification.</p></html>')
    (output / 'index.html').write_text('\n'.join(parts))
    manifest = {'plotter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'report': str(report_dir),
                'inputs': {name + '.csv': hashlib.sha256((report_dir / (name + '.csv')).read_bytes()).hexdigest()
                           for name in tables},
                'outputs': output_hashes, 'cases': len(cases),
                'limits': {'csv_bytes': PLOT_MAX_FILE, 'rows_per_csv': PLOT_MAX_ROWS, 'cases': MAX_CASES}}
    (output / 'plot_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return {'output': str(output.resolve()), 'cases': len(cases)}


def parse(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    audit = commands.add_parser('analyze', help='audit case directories into fresh CSV/Markdown/HTML tables')
    audit.add_argument('cases', nargs='+', type=Path, help='finalized native_throughput.py case directories')
    audit.add_argument('--output', required=True, type=Path, help='fresh report directory; never overwrites an earlier report')
    audit.add_argument('--synthetic', action='store_true', help='force fixture-only classification; never accepted native metrics')
    add_config_arguments(audit)
    figures = commands.add_parser('plot', help='render PNG/SVG figures from an analyze output directory (needs matplotlib)')
    figures.add_argument('--report', required=True, type=Path, help='an analyze output directory')
    figures.add_argument('--output', required=True, type=Path, help='fresh figure directory')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse(argv)
    if args.command == 'analyze':
        result = analyze(args.cases, args.output, args.synthetic, config_from_args(args))
    else:
        result = plot(args.report, args.output)
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
