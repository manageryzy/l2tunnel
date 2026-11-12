#!/usr/bin/env python3
"""One finite owned TCP/TLS throughput case; dry-run unless --apply is explicit."""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
from pathlib import Path
import shutil
import sys
import tempfile
import time
try:
    from . import netns_lab as lab, proxy_native_smoke as fixed, proxy_measured_native_smoke as measured
    from . import throughput_probe as probe
except ImportError:
    import netns_lab as lab
    import proxy_native_smoke as fixed
    import proxy_measured_native_smoke as measured
    import throughput_probe as probe

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ('native_throughput.py', 'throughput_probe.py', 'proxy_native_smoke.py',
           'proxy_measured_native_smoke.py', 'netns_lab.py')
PROFILES = ('tap-system', 'tun-system', 'tun-active', 'tun-measured-proxy')
CASE_SECONDS = 300
MAX_SAMPLES = 96


class ToolObservationError(RuntimeError):
    """An observation tool/format cannot establish the requested measurement."""


def wan_measured_policy() -> dict:
    """One explicit benchmark policy for every configured 2/70ms WAN condition."""
    value = measured.policy()
    # The baseline helper is historical clean-pressure policy; never mutate it.
    base_rtt = 70_000
    report = 100_000
    recovery = 1_000_000 + 200_000 + 400_000 + base_rtt
    probe_timeout = ((recovery + 499_999) // 500_000) * 500_000
    value['allocation']['target']['bootstrap_rtt_micros'] = base_rtt
    value['ownership'].update(pending_ttl_micros=report * 10,
        probe_interval_micros=250_000, probe_timeout_micros=probe_timeout,
        handoff_timeout_micros=probe_timeout, emission_interval_micros=report,
        max_records_per_interval=32)
    value['observation'].update(report_interval_micros=report,
        sample_ttl_micros=probe_timeout * 2, demand_idle_micros=report * 10,
        rate_interval_micros=250_000, rate_bins=8)
    validate_wan_policy(value)
    return value


def validate_wan_policy(value: dict) -> None:
    """Check the selected policy's duration ceilings and actual service geometry."""
    o, b, s = value['observation'], value['ownership'], value['service']
    duration_fields = [(o, key) for key in ('report_interval_micros', 'sample_ttl_micros',
        'demand_idle_micros', 'rate_interval_micros')] + [(b, key) for key in
        ('pending_ttl_micros', 'probe_interval_micros', 'probe_timeout_micros',
         'handoff_timeout_micros', 'emission_interval_micros')] + [(s, key) for key in
        ('plan_interval_micros', 'status_interval_micros')]
    if any(type(row[key]) is not int or not 1000 <= row[key] <= 120_000_000 for row, key in duration_fields):
        raise ValueError('WAN policy duration outside checked 1ms..120s')
    if (type(o['rate_bins']) is not int or not 1 <= o['rate_bins'] <= 16
            or type(b['max_records_per_interval']) is not int or not 1 <= b['max_records_per_interval'] <= 256
            or o['sample_ttl_micros'] < max(o['report_interval_micros'], b['probe_timeout_micros'], 2 * o['rate_interval_micros'])
            or o['demand_idle_micros'] < o['report_interval_micros']
            or 2 * o['rate_interval_micros'] * o['rate_bins'] > 120_000_000):
        raise ValueError('incoherent WAN observation/ownership policy')
    for key in ('report_work_per_turn', 'admission_work_per_turn', 'callback_work_per_turn'):
        if type(s[key]) is not int or not 1 <= s[key] <= 64:
            raise ValueError('WAN policy service work outside1..64')
    # The shared CLI runtime is poll1ms and fixed max16owners/33token slots.
    if ((16 + s['report_work_per_turn'] - 1) // s['report_work_per_turn'] * 1000 > o['report_interval_micros']
            or (33 + s['callback_work_per_turn'] - 1) // s['callback_work_per_turn'] * 1000 >= b['handoff_timeout_micros']):
        raise ValueError('WAN policy cannot service actual bounded owner geometry')
    bootstrap = value['allocation']['target']['bootstrap_rtt_micros']
    if type(bootstrap) is not int or not 70_000 <= bootstrap <= 120_000_000 or b['probe_timeout_micros'] <= bootstrap:
        raise ValueError('WAN probe lifetime cannot cover configured base RTT')


def failure_status(error: Exception) -> str:
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return 'bound_exhausted'
    return 'tool_failure' if isinstance(error, (OSError, ToolObservationError)) else 'failed'


def plan(lab_id: str, profile: str, duplex: str, path: str, flows: int,
         family: int = 4, maximum: int = 256 * 1024 * 1024, profile_ms: int = 0,
         delivery_window: str = 'legacy') -> dict:
    probe.validate(flows, maximum)
    if profile not in PROFILES or duplex not in ('full', 'half') or path not in ('clean', 'delay', 'loss1', 'impaired') or family not in (4, 6):
        raise ValueError('explicit supported profile/duplex/path/family required')
    if (type(profile_ms) is not int or (profile_ms != 0 and not 100 <= profile_ms <= 60000)
            or (profile_ms and profile not in ('tap-system', 'tun-system'))):
        raise ValueError('profiling requires system TCP/TLS and interval0|100..60000ms')
    if delivery_window not in ('legacy', 'bdp') or (delivery_window == 'bdp' and profile not in ('tap-system', 'tun-system')):
        raise ValueError('explicit BDP delivery window requires system TCP/TLS')
    spec = lab.LabSpec(lab_id)
    tap = profile == 'tap-system'
    value = {'lab_id': lab_id, 'namespaces': spec.namespaces, 'profile': profile,
            'duplex': duplex, 'path': path, 'flows': flows, 'family': family,
            'layer': 'tap' if tap else 'tun', 'interface': 'tap0' if tap else 'tun0',
            'application_roles': ['host_a', 'host_b'] if tap else ['endpoint_a', 'endpoint_b'],
            'addresses': (['198.18.0.1', '198.18.0.2'] if tap else ['198.19.0.1', '198.19.0.2']) if family == 4 else
                         (['fd42:12:18::1', 'fd42:12:18::2'] if tap else ['fd42:12:19::1', 'fd42:12:19::2']),
            'one_way_delay_ms': 1 if path == 'clean' else 35,
            'loss_percent_per_direction': {'clean': 0, 'delay': 0, 'loss1': 1, 'impaired': 15}[path],
            'shared_htb_mbps': {'a_to_b': 100, 'b_to_a': 10},
            'forward_acceptance_mbps': 80, 'runtime_profile_interval_ms': profile_ms,
            'delivery_window': delivery_window,
            'warmup_seconds': 2, 'measurement_seconds': 10, 'probe_original_seconds': 30,
            'max_bytes_per_direction_flow': maximum, 'max_probe_processes': 2,
            'max_daemons': 2, 'max_status_samples': MAX_SAMPLES, 'capture': 'disabled',
            'initial_topology_commands': lab.plan_document(spec)['commands']}
    if profile == 'tun-measured-proxy':
        value['measured_policy'] = wan_measured_policy()
    if delivery_window == 'bdp':
        value['delivery_policy'] = {'forward_mbps': 100, 'reverse_mbps': 10,
            'bootstrap_rtt_ms': 70, 'headroom_percent': 125,
            'max_inflight_bytes': 4 * 1024 * 1024, 'max_records': 8192}
    return value


def publish_clock(path: Path, value: dict) -> None:
    """Publish a complete closed file without replacing an existing run clock."""
    temporary = path.with_name('.clock-pending')
    try:
        with temporary.open('x') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def compare(a: dict, b: dict, flows: int) -> dict:
    if a['clock'] != b['clock'] or len(a['flows']) != flows or len(b['flows']) != flows:
        raise ValueError('probe count/common clock mismatch')
    duration = (a['clock']['end_ns'] - a['clock']['measure_start_ns']) / 1e9
    if duration <= 0:
        raise ValueError('non-positive measurement duration')
    exhausted = any(s['bound_exhausted'] for p in (a, b) for s in p['flows'])
    directions = {}
    for name, sender, receiver in [('a_to_b', a, b), ('b_to_a', b, a)]:
        for sent, received in zip(sender['flows'], receiver['flows']):
            if (not sent['write_closed'] or not received['eof']
                    or sent['sent'] != received['received']
                    or sent['sent_sha256'] != received['received_sha256']
                    or received['received'] != sum(received[k] for k in ('warmup', 'measured', 'postwindow'))):
                raise ValueError('exact stream byte/hash/EOF accounting mismatch')
        unique = sum(s['measured'] for s in receiver['flows'])
        if unique <= 0 and not exhausted:
            raise ValueError('no actual received application measurement bytes')
        directions[name] = {'receiver_unique_bytes': unique, 'seconds': duration,
                            'goodput_mbps': unique * 8 / duration / 1e6,
                            'postwindow_drain_bytes': sum(s['postwindow'] for s in receiver['flows']),
                            'total_exact_bytes': sum(s['received'] for s in receiver['flows'])}
    return {'status': 'bound_exhausted' if exhausted else 'passed',
            'directions': directions, 'hashes_and_eof': 'passed',
            'performance_acceptance': {'direction': 'a_to_b', 'minimum_goodput_mbps': 80,
                'status': 'unqualified' if exhausted else
                    ('passed' if directions['a_to_b']['goodput_mbps'] >= 80 else 'failed'),
                'scope': 'finite observed application goodput; reverse has a separate10Mbps ceiling'},
            'window_domain': 'native endpoint sampled TCP_INFO cwnd and scaled peer advertised rwnd (nullable on old kernels); local rcv_space and internal credit are separate'}


def verify_helpers(build: dict, output: Path, loaded=False) -> dict:
    result = {}
    modules = {'native_throughput.py': __file__, 'throughput_probe.py': probe.__file__,
               'proxy_native_smoke.py': fixed.__file__, 'proxy_measured_native_smoke.py': measured.__file__,
               'netns_lab.py': lab.__file__}
    for name in HELPERS:
        target = output / name
        expected = build['source_sha256_after'].get('tools/' + name)
        if expected != fixed.file_hash(target) or (loaded and Path(modules[name]).resolve() != target):
            raise ValueError('executed helper differs from exact build source: ' + name)
        result['tools/' + name] = expected
    return result


def link_counters(raw: str) -> dict:
    value = fixed.strict_json(raw)
    if not isinstance(value, list) or len(value) != 1 or value[0].get('ifname') != 'wan0':
        raise ValueError('exact owned WAN interface required')
    stats = value[0].get('stats64', value[0].get('stats'))
    result = {direction + '_bytes': stats[direction]['bytes'] for direction in ('tx', 'rx')}
    if any(type(n) is not int or n < 0 for n in result.values()):
        raise ValueError('invalid WAN byte counters')
    return result


def wire_intervals(samples: list, clock: dict) -> dict:
    result, summaries = {}, {}
    for side in ('a', 'b'):
        rows = [s['wan'][side] for s in samples]
        intervals = []
        for before, after in zip(rows, rows[1:]):
            elapsed = ((after['read_begin_ns'] + after['read_end_ns']) -
                       (before['read_begin_ns'] + before['read_end_ns'])) / 2e9
            if elapsed <= 0:
                raise ValueError('non-increasing wire sample clock')
            row = {'begin_bracket_ns': [before['read_begin_ns'], before['read_end_ns']],
                   'end_bracket_ns': [after['read_begin_ns'], after['read_end_ns']], 'seconds': elapsed}
            for direction in ('tx', 'rx'):
                delta = after[direction + '_bytes'] - before[direction + '_bytes']
                if delta < 0:
                    raise ValueError('owned WAN interface counter reset')
                row[direction + '_bytes'] = delta
                row[direction + '_mbps'] = delta * 8 / elapsed / 1e6
            row['inside_measurement_window'] = (before['read_begin_ns'] >= clock['measure_start_ns']
                                                 and after['read_end_ns'] <= clock['end_ns'])
            intervals.append(row)
        result[side] = intervals
        covered = [row for row in intervals if row['inside_measurement_window']]
        summary = {'status': 'observed' if covered else 'unobserved',
                   'requested_seconds': (clock['end_ns'] - clock['measure_start_ns']) / 1e9,
                   'covered_seconds': sum(row['seconds'] for row in covered)}
        if covered:
            first, last = covered[0]['begin_bracket_ns'], covered[-1]['end_bracket_ns']
            summary['clock_uncertainty_seconds'] = ((first[1] - first[0]) + (last[1] - last[0])) / 2e9
            for direction in ('tx', 'rx'):
                total = sum(row[direction + '_bytes'] for row in covered)
                summary[direction + '_bytes'] = total
                summary[direction + '_mbps'] = total * 8 / summary['covered_seconds'] / 1e6
        summaries[side] = summary
    return {'interfaces': result, 'measurement_coverage': summaries, 'accounting': 'owned veth WAN interface byte counters; includes outer TLS/TCP, ACKs and retransmissions; virtual-interface accounting is not physical Ethernet line rate; tc drops and overhead are separate cumulative observations'}


def _counter(value, field: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        raise ToolObservationError('invalid tc counter: ' + field)
    return value


def _rate_bits(value) -> int:
    if type(value) is int:
        # iproute2 JSON numeric rates use bytes/s; text uses explicit bit units.
        return _counter(value, 'rate') * 8
    match = re.fullmatch(r'([0-9]+)(bit|Kbit|Mbit|Gbit)', value) if isinstance(value, str) else None
    if match is None:
        raise ToolObservationError('unsupported explicit HTB rate representation')
    return _counter(int(match[1]), 'rate') * {'bit': 1, 'Kbit': 1000, 'Mbit': 10**6, 'Gbit': 10**9}[match[2]]


def parse_tc_class(raw: str, expected_mbps: int) -> tuple[list, str]:
    """Strict single-owned-root HTB class, including iproute2-6.1 text output."""
    if not raw or len(raw.encode()) > 8192:
        raise ToolObservationError('missing or excessive tc class observation')
    if raw.lstrip().startswith('['):
        try:
            rows = fixed.strict_json(raw)
        except (ValueError, TypeError) as error:
            raise ToolObservationError('invalid tc class JSON') from error
        observed_format = 'json'
    else:
        # No generic text scraping: require the complete known HTB statistics
        # grammar. Another/duplicate class or absent counters cannot disappear.
        grammar = (r'class htb (?P<handle>1:10) (?P<scope>root|parent 1:) leaf 10: prio 0 '
            r'rate (?P<rate>[0-9]+(?:bit|Kbit|Mbit|Gbit)) ceil (?P<ceil>[0-9]+(?:bit|Kbit|Mbit|Gbit)) '
            r'burst [0-9]+[A-Za-z]+ cburst [0-9]+[A-Za-z]+[ \t]*\n'
            r'[ \t]*Sent (?P<bytes>[0-9]+) bytes (?P<packets>[0-9]+) pkt '
            r'\(dropped (?P<drops>[0-9]+), overlimits (?P<overlimits>[0-9]+) requeues (?P<requeues>[0-9]+)\)[ \t]*\n'
            r'[ \t]*backlog [0-9]+[A-Za-z]+ [0-9]+p requeues (?P<backlog_requeues>[0-9]+)[ \t]*\n'
            r'[ \t]*lended: [0-9]+ borrowed: [0-9]+ giants: [0-9]+[ \t]*\n'
            r'[ \t]*tokens: -?[0-9]+ ctokens: -?[0-9]+\s*')
        match = re.fullmatch(grammar, raw)
        if match is None:
            raise ToolObservationError('unsupported or ambiguous HTB class text')
        row = {key: _counter(int(match[key]), key) for key in
               ('bytes', 'packets', 'drops', 'overlimits', 'requeues')}
        if row['requeues'] != int(match['backlog_requeues']):
            raise ToolObservationError('inconsistent HTB requeue counters')
        row.update(kind='htb', handle=match['handle'], root=match['scope'] == 'root',
                   options={'rate': match['rate'], 'ceil': match['ceil']})
        if not row['root']:
            row['parent'] = '1:'
        rows, observed_format = [row], 'htb-text-iproute2'
    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or rows[0].get('kind') != 'htb' or rows[0].get('handle') != '1:10'
            or not (rows[0].get('root') is True or rows[0].get('parent') == '1:')
            or (rows[0].get('root') is True and rows[0].get('parent') not in (None, '1:'))):
        raise ToolObservationError('expected exactly owned HTB root class1:10')
    row = rows[0]
    for field in ('bytes', 'packets', 'drops', 'overlimits', 'requeues'):
        _counter(row.get(field), field)
    options = row.get('options')
    if (not isinstance(options, dict) or _rate_bits(options.get('rate')) != expected_mbps * 10**6
            or _rate_bits(options.get('ceil')) != expected_mbps * 10**6):
        raise ToolObservationError('observed HTB rate/ceil differs from owned directional policy')
    return rows, observed_format


def parse_tc_qdisc(raw: str) -> list:
    """Qdisc remains strict JSON; class text compatibility never covers it."""
    try:
        rows = fixed.strict_json(raw)
    except (ValueError, TypeError) as error:
        raise ToolObservationError('invalid tc qdisc JSON') from error
    if not isinstance(rows, list) or len(rows) != 2 or any(not isinstance(row, dict) for row in rows):
        raise ToolObservationError('expected exactly owned HTB/netem qdiscs')
    indexed = {(row.get('kind'), row.get('handle')): row for row in rows}
    if (set(indexed) != {('htb', '1:'), ('netem', '10:')}
            or indexed['htb', '1:'].get('root') is not True
            or indexed['netem', '10:'].get('parent') != '1:10'):
        raise ToolObservationError('owned qdisc identity/parent mismatch')
    for row in rows:
        for field in ('bytes', 'packets', 'drops', 'overlimits', 'requeues'):
            _counter(row.get(field), field)
    return rows


def tc_deltas(before: dict, after: dict) -> list:
    rows = []
    for side in ('a', 'b'):
        for category in ('class', 'qdisc'):
            old = {(v.get('kind'), v.get('handle'), v.get('parent')): v for v in before[side][category]}
            for value in after[side][category]:
                key = (value.get('kind'), value.get('handle'), value.get('parent'))
                if key not in old:
                    raise ValueError('owned tc object changed during measurement')
                counters = {}
                for field in ('bytes', 'packets', 'drops', 'overlimits', 'requeues'):
                    if field in value and field in old[key]:
                        delta = value[field] - old[key][field]
                        if delta < 0:
                            raise ValueError('owned tc counter reset')
                        counters[field] = delta
                rows.append({'side': side, 'category': category, 'identity': list(key), 'counter_deltas': counters})
    return rows


def child_resources(processes: list) -> list:
    values = []
    for child in processes:
        if child.poll() is not None:
            continue
        try:
            # These are unreaped direct children, so their PIDs cannot be reused.
            stat = Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()
            values.append({'pid': child.pid, 'utime_ticks': int(stat[11]), 'stime_ticks': int(stat[12]),
                           'starttime_ticks': int(stat[19]), 'rss_pages': int(stat[21])})
        except FileNotFoundError:
            pass
    return values


def run_case(p: dict, output: Path, state_dir: Path, build: dict) -> dict:
    spec, ns = lab.LabSpec(p['lab_id']), p['namespaces']
    binary, deadline = output / 'l2tunnel-native', time.monotonic() + CASE_SECONDS
    receipt = fixed.Receipt(output / 'receipt.json', {'status': 'running', 'plan': p, 'cleanup': 'pending',
        'build_receipt_sha256': fixed.file_hash(output / 'build-receipt.json'),
        'binary_sha256': fixed.file_hash(binary), 'executed_helpers': verify_helpers(build, output, True)})
    processes, created, samples, failure, sockets = [], False, [], None, {}
    def command(role, *args):
        return fixed.command(['ip', 'netns', 'exec', ns[role], *args], deadline)
    def launch(role, args, name):
        path = output / (name + '.log')
        proc = fixed.launch(['ip', 'netns', 'exec', ns[role], *args], path)
        processes.append(proc)
        return proc, path
    def tc_json():
        raw = {}
        for side in ('a', 'b'):
            raw[side] = {}
            for kind in ('class', 'qdisc'):
                argv = ['ip', 'netns', 'exec', ns['endpoint_' + side], 'tc', '-j', '-s', kind, 'show', 'dev', 'wan0']
                result = subprocess.run(argv, capture_output=True, text=True,
                    timeout=fixed.remaining(deadline, fixed.BOUNDS['command']), check=False)
                entry = {'argv': argv, 'exit_code': result.returncode,
                         'stdout': result.stdout[:8192], 'stderr': result.stderr[:4096],
                         'stdout_characters': len(result.stdout), 'stderr_characters': len(result.stderr)}
                raw[side][kind] = entry
                # Publish raw observation before any parser/format assumption.
                receipt.update(last_tc_observation_raw=raw)
                if result.returncode or len(result.stdout) > 8192 or len(result.stderr) > 4096:
                    raise ToolObservationError('tc observation command failed or exceeded bounded output')
        normalized = {}
        for side, rate in [('a', 100), ('b', 10)]:
            class_raw, qdisc_raw = raw[side]['class']['stdout'], raw[side]['qdisc']['stdout']
            classes, observed_format = parse_tc_class(class_raw, rate)
            normalized[side] = {'class': classes, 'qdisc': parse_tc_qdisc(qdisc_raw),
                'observed_formats': {'class': observed_format, 'qdisc': 'json'},
                'raw_stdout': {'class': class_raw, 'qdisc': qdisc_raw},
                'raw_stderr': {kind: raw[side][kind]['stderr'] for kind in ('class', 'qdisc')}}
        return normalized
    def traffic():
        rows = {}
        for side in ('a', 'b'):
            began = time.monotonic_ns()
            counters = link_counters(command('endpoint_' + side, 'ip', '-j', '-s', 'link', 'show', 'dev', 'wan0'))
            rows[side] = {'read_begin_ns': began, 'read_end_ns': time.monotonic_ns(), **counters}
        return rows
    def qdiscs():
        return {side: {kind: command('endpoint_' + side, 'tc', '-s', kind, 'show', 'dev', 'wan0')
                       for kind in ('class', 'qdisc')} for side in ('a', 'b')}
    try:
        fixed.bounded_lab(lab.apply, spec, state_dir, deadline)
        created = True
        features = {}
        fixed.disable_underlay_ipv6(ns, deadline)
        for side in ('a', 'b'):
            role = 'endpoint_' + side
            command(role, 'tc', 'qdisc', 'change', 'dev', 'wan0', 'parent', '1:10', 'handle', '10:',
                    'netem', 'limit', '1000', 'delay', str(p['one_way_delay_ms']) + 'ms',
                    'loss', 'random', str(p['loss_percent_per_direction']) + '%')
            n = 1 if side == 'a' else 2
            if p['layer'] == 'tun':
                fixed.command(['ip', '-n', ns[role], 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun'], deadline)
                fixed.command(['ip', '-n', ns[role], 'link', 'set', 'tun0', 'mtu', '1500', 'up'], deadline)
                for family, address in [(4, f'198.19.0.{n}/24'), (6, f'fd42:12:19::{n}/64')]:
                    fixed.command(['ip', '-n', ns[role], *(['-6'] if family == 6 else []), 'address', 'add',
                                   address, 'dev', 'tun0', *(['nodad'] if family == 6 else [])], deadline)
            else:
                fixed.command(['ip', '-n', ns['host_' + side], '-6', 'address', 'add',
                               f'fd42:12:18::{n}/64', 'dev', 'eth0', 'nodad'], deadline)
            for interface in ('wan0', p['interface']):
                features[f'{side}-{interface}'] = fixed.offloads(ns[role], interface, deadline)
            if p['layer'] == 'tap':
                features[f'{side}-eth0'] = fixed.offloads(ns['host_' + side], 'eth0', deadline)
                features[f'{side}-lan0'] = fixed.offloads(ns[role], 'lan0', deadline)
            if p['profile'] == 'tun-measured-proxy':
                command(role, 'sysctl', '-q', '-w', 'net.ipv4.tcp_ecn=0')
        for interface in ('a0', 'b0'):
            features['router-' + interface] = fixed.offloads(ns['router'], interface, deadline)
        receipt.update(offloads=features, tc_before=qdiscs(), kernel= fixed.command(['uname', '-a'], deadline),
                       clock_ticks=os.sysconf('SC_CLK_TCK'), page_bytes=os.sysconf('SC_PAGE_SIZE'),
                       tcp_defaults={role: command(role, 'sysctl', 'net.ipv4.tcp_congestion_control', 'net.ipv4.tcp_rmem', 'net.ipv4.tcp_wmem', 'net.ipv4.tcp_ecn')
                                     for role in sorted(set(p['application_roles']) | {'endpoint_a', 'endpoint_b'})})
        with tempfile.TemporaryDirectory(prefix='l2t-throughput-secrets-') as temporary:
            secrets = Path(temporary)
            fixed.command([str(binary), 'keygen', '--private', str(secrets / 'member.der'), '--public', str(secrets / 'member.pub')], deadline)
            fixed.command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', str(secrets / 'server.pem'), '-out', str(secrets / 'cert.pem'), '-days', '1', '-subj', '/CN=lab.invalid',
                '-addext', 'subjectAltName=DNS:lab.invalid', '-addext', 'basicConstraints=critical,CA:FALSE'], deadline)
            fixed.command(['openssl', 'x509', '-in', str(secrets / 'cert.pem'), '-outform', 'DER', '-out', str(secrets / 'cert.der')], deadline)
            fixed.command(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(secrets / 'server.pem'), '-outform', 'DER', '-out', str(secrets / 'server.der')], deadline)
            common = ['--carrier', 'tcp', '--layer', p['layer'], '--device', p['interface'], '--duplex', p['duplex'],
                      '--record-profile', 'frame', '--compression', 'off', '--max-packet', '1600']
            if p['runtime_profile_interval_ms']:
                common += ['--profile-ms', str(p['runtime_profile_interval_ms'])]
            if p['delivery_window'] == 'bdp':
                selected = p['delivery_policy']
                common += ['--delivery-window', 'bdp', '--forward-mbps', str(selected['forward_mbps']),
                    '--reverse-mbps', str(selected['reverse_mbps']), '--bootstrap-rtt-ms', str(selected['bootstrap_rtt_ms']),
                    '--bdp-headroom-percent', str(selected['headroom_percent']),
                    '--inflight-max-bytes', str(selected['max_inflight_bytes']), '--inflight-max-records', str(selected['max_records'])]
            if p['profile'] == 'tun-active':
                common += ['--traffic', 'active', '--adaptive', 'on', '--active-stats-ms', '500']
            elif p['profile'] == 'tun-measured-proxy':
                policy = output / 'policy.json'
                policy.write_text(json.dumps(p['measured_policy']) + '\n')
                receipt.update(selected_measured_policy=p['measured_policy'], policy_sha256=fixed.file_hash(policy))
                common += ['--traffic', 'proxy-measured', '--proxy-policy', str(policy)]
            else:
                common += ['--traffic', 'system']
            daemons = []
            for side, operation, identity in [('b', 'serve', ['--listen', '192.0.2.6:18443', '--cert', str(secrets / 'cert.der'),
                    '--key', str(secrets / 'server.der'), '--allow-key', str(secrets / 'member.pub')]),
                    ('a', 'connect', ['--remote', '192.0.2.6:18443', '--ca', str(secrets / 'cert.der'),
                    '--server-name', 'lab.invalid', '--identity', str(secrets / 'member.der')])]:
                options = list(common)
                if p['profile'] == 'tun-measured-proxy':
                    private = secrets / side
                    private.mkdir(mode=0o700)
                    sockets[side] = private / 'control.sock'
                    options += ['--control-socket', str(sockets[side])]
                proc, log = launch('endpoint_' + side, [str(binary), operation, *identity, *options], side + '-daemon')
                daemons.append((proc, log))
                if side == 'b':
                    end = min(deadline, time.monotonic() + 5)
                    while ':18443' not in command('endpoint_b', 'ss', '-Hltn'):
                        if proc.poll() is not None:
                            raise RuntimeError('server exited before listen')
                        time.sleep(min(0.05, fixed.remaining(end, 0.05)))
            ready = min(deadline, time.monotonic() + fixed.BOUNDS['startup'])
            marker = 'Authenticated TUN' if p['profile'] == 'tun-measured-proxy' else 'Carrier:'
            for proc, log in daemons:
                fixed.wait_log(proc, log, marker, ready)
            if sockets:
                while True:
                    try:
                        initial = {side: fixed.rpc(path, 'status', ready) for side, path in sockets.items()}
                        if all((measured.validate_proxy_snapshot(v, allow_starting=True)['runtime'] or {}).get('phase') == 'Forwarding' for v in initial.values()):
                            break
                    except (FileNotFoundError, ConnectionRefusedError):
                        pass
                    time.sleep(min(0.05, fixed.remaining(ready, 0.05)))
                receipt.update(startup_status=initial)
            receipt.update(authentication={'evidence': 'post-authentication CLI readiness marker on both peers',
                'daemon_logs': [log.name for _, log in daemons], 'requested_profile': p['profile'],
                'effective_cli_markers': [next(line for line in fixed.read_log(log).splitlines() if marker in line) for _, log in daemons],
                'shared_api_status': 'sampled' if sockets else 'not available for this frontend'},
                effective_cli=common)
            probe_args = [sys.executable, str(output / 'throughput_probe.py'), '--address', p['addresses'][1],
                '--flows', str(p['flows']), '--max-bytes', str(p['max_bytes_per_direction_flow']), '--clock', str(output / 'clock.json')]
            probe_deadline = min(deadline, time.monotonic() + probe.TRANSFER_SECONDS)
            server, server_log = launch(p['application_roles'][1], [*probe_args[:2], 'listen', *probe_args[2:]], 'b-probe')
            fixed.wait_log(server, server_log, 'Listening', probe_deadline)
            client, client_log = launch(p['application_roles'][0], [*probe_args[:2], 'connect', *probe_args[2:]], 'a-probe')
            for proc, log in [(server, server_log), (client, client_log)]:
                fixed.wait_log(proc, log, 'Connected', probe_deadline)
            tc_initial = tc_json()
            clock = {'start_ns': time.monotonic_ns() + 1_000_000_000, 'warmup_ns': 2_000_000_000, 'measure_ns': 10_000_000_000}
            publish_clock(output / 'clock.json', clock)
            while client.poll() is None or server.poll() is None:
                if len(samples) >= MAX_SAMPLES:
                    raise TimeoutError('sample allocation exhausted')
                rows = {'at_ns': time.monotonic_ns(), 'load_average': list(os.getloadavg()),
                        'processes': child_resources(processes), 'wan': traffic(), 'tc_cumulative': tc_json(),
                        'application_ss': {role: command(role, 'ss', '-tinm') for role in p['application_roles']},
                        'outer_and_proxy_socket_ss': {role: command(role, 'ss', '-tinm') for role in ('endpoint_a', 'endpoint_b')}}
                if sockets:
                    rows['status'] = {side: fixed.rpc(path, 'status', deadline) for side, path in sockets.items()}
                samples.append(rows)
                receipt.update(samples=samples)
                if any(proc.poll() is not None for proc, _ in daemons):
                    raise RuntimeError('authenticated tunnel failed during throughput')
                fixed.remaining(deadline, 0.5)
                time.sleep(0.5)
            if client.returncode or server.returncode:
                raise RuntimeError('probe failed; inspect bounded endpoint logs')
            results = [fixed.strict_json(fixed.read_log(log).splitlines()[-1]) for log in (client_log, server_log)]
            result = compare(*results, p['flows'])
            result['wire_intervals'] = wire_intervals(samples, results[0]['clock'])
            tc_final = tc_json()
            result['tc_deltas'] = tc_deltas(tc_initial, tc_final)
            result['tc_counter_scope'] = 'whole probe transfer: pre-window/warmup/measurement/post-window drain; not shared 10s application window'
            if result['status'] == 'passed' and any(row['status'] != 'observed' for row in result['wire_intervals']['measurement_coverage'].values()):
                result['status'] = 'unsupported'
            receipt.update(result=result, probe_logs=[client_log.name, server_log.name], tc_after=qdiscs(),
                           tc_initial=tc_initial, tc_final=tc_final, status=result['status'], daemon_shutdown='owned process termination after exact application EOF; not graceful tunnel-drain qualification')
    except Exception as error:
        failure = error
        receipt.update(status=failure_status(error), error=str(error)[:4096])
    finally:
        errors = []
        for process in reversed(processes):
            try:
                fixed.stop(process)
            except Exception as error:
                errors.append(str(error)[:256])
        try:
            if created:
                fixed.bounded_lab(lab.cleanup, spec, state_dir, time.monotonic() + fixed.BOUNDS['namespace_cleanup'])
            if errors or any((lab.NETNS_DIRECTORY / name).exists() for name in ns.values()):
                raise RuntimeError('owned children or namespaces remain: ' + repr(errors))
            verify_helpers(build, output, True)
            fixed.verified_build_receipt(output / 'build-receipt.json', binary)
            receipt.update(cleanup='passed', executed_helpers_unchanged=True)
        except Exception as error:
            failure = error
            receipt.update(cleanup='failed', status='failed', cleanup_error=str(error)[:4096])
    if failure:
        raise RuntimeError('throughput case failed; inspect ' + str(receipt.path)) from failure
    return receipt.value


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab-id', default='throughput')
    p.add_argument('--profile', choices=PROFILES, required=True)
    p.add_argument('--duplex', choices=['full', 'half'], required=True)
    p.add_argument('--path', choices=['clean', 'delay', 'loss1', 'impaired'], required=True)
    p.add_argument('--flows', type=int, choices=[1, 2, 4], required=True)
    p.add_argument('--family', type=int, choices=[4, 6], default=4)
    p.add_argument('--max-bytes', type=int, default=256 * 1024 * 1024)
    p.add_argument('--profile-ms', type=int, default=0)
    p.add_argument('--delivery-window', choices=['legacy', 'bdp'], default='legacy')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--build-receipt', type=Path)
    p.add_argument('--state-dir', type=Path, default=Path('/run/l2tunnel-labs'))
    p.add_argument('--apply', action='store_true')
    p.add_argument('--frozen-worker', help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    case = plan(a.lab_id, a.profile, a.duplex, a.path, a.flows, a.family, a.max_bytes, a.profile_ms, a.delivery_window)
    if not a.apply:
        print(json.dumps({'status': 'dry_run', 'case': case, 'mutations': 'none'}, indent=2))
        return 0
    lab.require_root()
    if sys.platform != 'linux' or a.build_receipt is None:
        raise ValueError('Linux and exact build receipt required')
    for tool in ('ip', 'tc', 'ss', 'sysctl', 'ethtool', 'openssl'):
        if shutil.which(tool) is None:
            raise FileNotFoundError(tool)
    build = fixed.verified_build_receipt(a.build_receipt, a.binary)
    if not a.frozen_worker:
        a.output.mkdir(mode=0o755)
    output = a.output.resolve()
    if not a.frozen_worker:
        for name in HELPERS:
            shutil.copyfile(Path(__file__).parent / name, output / name)
        shutil.copyfile(a.binary, output / 'l2tunnel-native')
        (output / 'l2tunnel-native').chmod(0o755)
        shutil.copyfile(a.build_receipt, output / 'build-receipt.json')
        verify_helpers(build, output)
        st = output.stat()
        args = [sys.executable, str(output / 'native_throughput.py'), '--lab-id', a.lab_id,
            '--profile', a.profile, '--duplex', a.duplex, '--path', a.path, '--flows', str(a.flows),
            '--family', str(a.family), '--max-bytes', str(a.max_bytes), '--output', str(output),
            '--profile-ms', str(a.profile_ms),
            '--delivery-window', a.delivery_window,
            '--binary', str(output / 'l2tunnel-native'), '--build-receipt', str(output / 'build-receipt.json'),
            '--state-dir', str(a.state_dir.resolve()), '--frozen-worker', f'{st.st_dev}:{st.st_ino}', '--apply']
        os.execve(sys.executable, args, {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        raise RuntimeError('immutable worker exec returned')
    st = output.stat()
    if (a.output.is_symlink() or st.st_uid != os.geteuid() or st.st_mode & 0o022
            or a.frozen_worker != f'{st.st_dev}:{st.st_ino}'
            or a.binary.resolve() != output / 'l2tunnel-native'
            or a.build_receipt.resolve() != output / 'build-receipt.json'
            or {f.name for f in output.iterdir()} != set(HELPERS) | {'l2tunnel-native', 'build-receipt.json'}):
        raise ValueError('fresh exclusive copied worker identity/layout required')
    verify_helpers(build, output, True)
    result = run_case(case, output, a.state_dir, build)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
