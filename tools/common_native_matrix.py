#!/usr/bin/env python3
"""Current Common daemon/native kernel TCP matrix; dry-run unless --apply.

Only journal-owned namespaces are modified. Each algorithm/carrier case and its
three workload phases run serially per lane. Failed cases are retained without retries.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

try:
    from . import netns_lab as lab, proxy_native_smoke as bounded
    from . import secure_udp_native as credentials_helper
    from . import common_native_observe as observe
    from .native_throughput import parse_tc_class, parse_tc_qdisc
except ImportError:
    import netns_lab as lab
    import proxy_native_smoke as bounded
    import secure_udp_native as credentials_helper
    import common_native_observe as observe
    from native_throughput import parse_tc_class, parse_tc_qdisc

ROOT = Path(__file__).resolve().parents[1]
WAN = {'a': '192.0.2.2', 'b': '192.0.2.6'}
NATIVE = {'a': '198.18.0.1', 'b': '198.18.0.2'}
PORTS = {'a': 24440, 'b': 24441}
PHASES = ('forward', 'reverse', 'simultaneous')
BOUNDS = {'case_seconds': 300, 'startup_seconds': 40, 'command_seconds': 10,
          'phase_seconds': 60, 'cleanup_seconds': 30, 'log_bytes': 16 * 1024 * 1024}
MANIFEST_BYTES = 4 * 1024 * 1024
FIXED_CLI = {'--carrier', '--record-profile', '--duplex', '--compression', '--layer',
             '--max-packet', '--max-path-mtu', '--noise-profile', '--udp-bind', '--udp-peer',
             '--udp-cover', '--raw-mark'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def atomic_json(path, value):
    temporary = path.with_suffix('.pending')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def file_hash(path):
    return bounded.file_hash(path)


def read_json(path, maximum):
    require(path.is_file() and not path.is_symlink(), 'regular non-symlink input required: ' + str(path))
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(0 < len(raw) <= maximum, 'JSON input outside bound')
    return bounded.strict_json(raw)


def input_path(base, relative):
    require(type(relative) is str and relative and not Path(relative).is_absolute()
            and '..' not in Path(relative).parts, 'manifest paths must remain below its directory')
    path = base / relative
    require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(base.resolve()),
            'manifest input escaped root or is not a regular file')
    return path


def manifest_rows(path, selected):
    document = read_json(path, MANIFEST_BYTES)
    require(document.get('version') == 1 and isinstance(document.get('rows'), list)
            and 0 < len(document['rows']) <= 256, 'bounded v1 matrix rows required')
    rows, seen = [], set()
    for row in document['rows']:
        require(isinstance(row, dict) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,95}', row.get('id', '')),
                'invalid unique matrix row ID')
        require(row['id'] not in seen, 'duplicate row')
        seen.add(row['id'])
        require(row.get('status') in ('ready', 'plan_refused'), 'row status must be ready or plan_refused')
        if selected and row['id'] not in selected:
            continue
        if row['status'] == 'ready':
            require(row.get('carrier') in ('udp', 'raw', 'tls', 'quic'), 'unknown carrier')
            plan = input_path(path.parent, row['common_plan'])
            plan_value = read_json(plan, 256 * 1024)
            require(plan_value.get('backend') == 'common_records_v2' and plan_value.get('version') == 1,
                    'current complete Common plan required')
            require(row.get('expected_descriptor_hex') in plan_value.get('catalog', []), 'expected descriptor absent from supplied catalog')
            for side in ('a', 'b'):
                args = row['required_cli'][side]
                require(isinstance(args, list) and len(args) % 2 == 0 and 0 < len(args) <= 32
                        and all(type(item) is str and '\0' not in item for item in args), 'bounded option pairs required')
                keys = args[::2]
                require(len(keys) == len(set(keys)) and set(keys) <= FIXED_CLI, 'unknown or repeated exporter CLI option')
                options = dict(zip(keys, args[1::2]))
                expected = {'--record-profile': 'common', '--duplex': 'full', '--layer': 'tun', '--noise-profile': 'ik'}
                require(all(options.get(key) == value for key, value in expected.items()), 'row differs from current Full TUN Common selection')
                require(options.get('--carrier') == {'udp': 'quic-like', 'raw': 'raw-packet', 'tls': 'tcp', 'quic': 'quic'}[row['carrier']], 'carrier selector mismatch')
            policy = row.get('carrier_policy')
            if row['carrier'] == 'udp':
                require(policy is None, 'original UDP must not carry an unrelated policy')
            else:
                require(row.get('policy_flag') == ('--raw-policy' if row['carrier'] == 'raw' else '--maintained-policy'), 'wrong policy flag')
                for side, other in [('a', 'b'), ('b', 'a')]:
                    requested = read_json(input_path(path.parent, policy[side]), 64 * 1024)
                    if row['carrier'] == 'raw':
                        require(requested.get('profile') == 'raw-common-carrier-v1'
                            and requested.get('forward') == {'local': WAN[side] + ':' + str(PORTS[side]), 'peer': WAN[other] + ':' + str(PORTS[other])}
                            and requested.get('reverse') is None, 'raw policy must match the exact owned Full tuple')
                        local_options = dict(zip(row['required_cli'][side][::2], row['required_cli'][side][1::2]))
                        require(re.fullmatch('[0-9]+', local_options.get('--raw-mark', '')), 'raw mark must match decimal-only current CLI grammar')
                        mark = int(local_options['--raw-mark'])
                        require(0 < mark <= 0xffffffff, 'raw CLI requires explicit nonzero mark')
                    else:
                        require(requested.get('first') == {'client': WAN['a'] + ':' + str(PORTS['a']), 'server': WAN['b'] + ':' + str(PORTS['b'])}
                            and requested.get('second') is None, 'maintained policy must match exact owned Full tuple')
                if row['carrier'] == 'raw':
                    marks = [dict(zip(row['required_cli'][side][::2], row['required_cli'][side][1::2]))['--raw-mark'] for side in ('a', 'b')]
                    require(int(marks[0], 0) == int(marks[1], 0), 'raw endpoint socket marks must match isolation policy')
        else:
            require(type(row.get('reason')) is str and row['reason'], 'refused plan requires explicit reason')
        rows.append(row)
    require(not selected or selected <= seen, 'unknown requested row IDs')
    require(rows, 'no selected rows')
    return document, rows


def daemon_command(row, side, binary, secrets, inputs, inspection=False):
    other, action = ('b', 'connect') if side == 'a' else ('a', 'serve')
    selected = row['required_cli'][side]
    if inspection:
        selected = [item for at in range(0, len(selected), 2) if selected[at] != '--raw-mark' for item in selected[at:at + 2]]
    args = [str(binary), *(['inspect-common-transaction-plan', '--role', action] if inspection else [action]),
            *selected, '--common-transaction-plan', str(inputs / row['common_plan']),
            '--noise-private-key-file', str(secrets / f'noise-{side}.key'),
            '--noise-peer-key-file', str(secrets / f'noise-{other}.pub')]
    if row.get('carrier_policy'):
        args += [row['policy_flag'], str(inputs / row['carrier_policy'][side])]
    if side == 'a':
        args += ['--identity', str(secrets / 'member.der')]
        if row['carrier'] != 'udp':
            args += ['--ca', str(secrets / 'cert.der'), '--server-name', 'lab.invalid']
    else:
        args += ['--allow-key', str(secrets / 'member.pub')]
        if row['carrier'] != 'udp':
            args += ['--cert', str(secrets / 'cert.der'), '--key', str(secrets / 'server.der')]
    if not inspection:
        if row['carrier'] != 'udp':
            args += ['--remote' if side == 'a' else '--listen', WAN['b'] + ':' + str(PORTS['b'])]
        args += ['--device', 'tun0', '--control-socket', str(secrets / f'control-{side}.sock'),
                 '--session-admission-key-file', str(secrets / 'admission.key')]
        if side == 'b':
            args += ['--session-cookie-key-file', str(secrets / 'cookie.key')]
    return args


@contextmanager
def exclusive_lab(lane=None):
    # Explicit lanes use disjoint owned namespaces and fixed CPU sets. The default
    # remains serial; lane runs are labeled concurrent and retain host counters.
    suffix = '' if lane is None else '-' + lane
    path = Path('/run/l2tunnel-common-native-matrix' + suffix + '.lock')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                'matrix lock must be a private root-owned regular file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


class Case:
    def __init__(self, row, spec, output):
        self.row, self.spec, self.output = row, spec, output
        self.deadline = time.monotonic() + BOUNDS['case_seconds']
        self.children, self.commands = [], []
        self.command_index = 0
        self.value = {'version': 1, 'id': row['id'], 'row': row, 'status': 'running', 'stage': 'preflight',
                      'bounds': BOUNDS, 'phases': [], 'started_wall_ns': time.time_ns(), 'commands': self.commands}
        self.save()

    def save(self):
        atomic_json(self.output / 'result.json', self.value)

    def check(self, deadline=None):
        if time.monotonic() >= min(self.deadline, deadline or self.deadline):
            raise TimeoutError('original case/stage deadline exhausted')
        for child in self.children:
            if child['log'].stat().st_size >= BOUNDS['log_bytes']:
                raise ValueError('owned child log bound exhausted')
            if child.get('capture') and child['capture'].exists() and child['capture'].stat().st_size >= observe.CAPTURE_BYTES:
                raise ValueError('capture byte ceiling exhausted')

    def prefix(self, role, args):
        return ['ip', 'netns', 'exec', self.spec.namespaces[role], *map(str, args)] if role else list(map(str, args))

    def command(self, role, *args, deadline=None, allow_failure=False):
        self.check(deadline)
        argv = self.prefix(role, args)
        self.command_index += 1
        name = f'command-{self.command_index:04}.log'
        self.commands.append({'argv': argv, 'log': name})
        until = min(self.deadline, deadline or self.deadline)
        with (self.output / name).open('xb') as stream:
            process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=min(BOUNDS['command_seconds'], max(.001, until - time.monotonic())))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
                raise
        raw = (self.output / name).read_bytes()
        require(len(raw) < BOUNDS['log_bytes'], 'command log bound exhausted')
        self.commands[-1]['returncode'] = code
        self.save()
        if code and not allow_failure:
            raise RuntimeError(f'command exit {code}: see {name}')
        return raw.decode('utf-8', errors='replace')

    def spawn(self, role, label, args, capture=None, metrics=None):
        self.check()
        log = self.output / (label + '.log')
        stream = log.open('xb')
        packets = capture.open('xb') if capture is not None else None
        argv = self.prefix(role, args)
        try:
            process = subprocess.Popen(argv, stdout=packets if packets is not None else stream,
                stderr=stream if packets is not None else subprocess.STDOUT, start_new_session=True,
                env=None if metrics is None else {**os.environ, 'L2TUNNEL_WIRE_METRICS': str(metrics)})
        finally:
            stream.close()
            if packets is not None:
                packets.close()
        child = {'label': label, 'process': process, 'log': log, 'argv': argv, 'capture': capture}
        self.children.append(child)
        self.commands.append({'argv': argv, 'log': log.name, 'pid': process.pid})
        self.save()
        return child

    def wait_marker(self, child, marker, deadline):
        while marker not in child['log'].read_text(errors='replace'):
            self.check(deadline)
            if child['process'].poll() is not None:
                raise RuntimeError(f"{child['label']} exited before {marker}")
            time.sleep(.02)

    def stop(self, child, requested=signal.SIGTERM, deadline=None):
        process = child['process']
        until = deadline if deadline is not None else min(self.deadline, time.monotonic() + 5)
        if process.poll() is None:
            remaining = until - time.monotonic()
            os.killpg(process.pid, requested if remaining > 0 else signal.SIGKILL)
            try:
                process.wait(timeout=max(0, min(3, remaining)))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=max(0, min(2, until - time.monotonic())))
        return process.returncode


def topology(case, state_dir):
    bounded.bounded_lab(lab.apply, case.spec, state_dir, case.deadline)
    case.value['namespace_journal'] = read_json(state_dir / (case.spec.lab_id + '.json'), MANIFEST_BYTES)
    offloads = {}
    for role in case.spec.namespaces:
        case.command(role, 'sysctl', '-q', '-w', 'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1')
    for side in ('a', 'b'):
        role = 'endpoint_' + side
        for interface in ('tap0', 'lan0', 'br-lan'):
            case.command(role, 'ip', 'link', 'set', interface, 'down')
        case.command('host_' + side, 'ip', 'address', 'flush', 'dev', 'eth0')
        case.command('host_' + side, 'ip', 'link', 'set', 'eth0', 'down')
        case.command(role, 'ip', 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun')
        case.command(role, 'ip', 'address', 'add', NATIVE[side] + '/24', 'dev', 'tun0')
        case.command(role, 'ip', 'link', 'set', 'tun0', 'mtu', '1500', 'up')
    for role, interface in [('endpoint_a', 'wan0'), ('endpoint_b', 'wan0'), ('router', 'a0'), ('router', 'b0'), ('endpoint_a', 'tun0'), ('endpoint_b', 'tun0')]:
        offloads[role + '/' + interface] = bounded.offloads(case.spec.namespaces[role], interface, case.deadline)
    case.value['offloads'] = offloads
    case.value['qdisc_before'] = qdisc(case)
    case.save()


def qdisc(case):
    result = {}
    for side in ('a', 'b'):
        role = 'endpoint_' + side
        classes, class_format = parse_tc_class(case.command(role, 'tc', '-s', '-j', 'class', 'show', 'dev', 'wan0'), 100 if side == 'a' else 10)
        qdiscs = parse_tc_qdisc(case.command(role, 'tc', '-s', '-d', '-j', 'qdisc', 'show', 'dev', 'wan0'))
        text = case.command(role, 'tc', '-d', 'qdisc', 'show', 'dev', 'wan0')
        require(re.search(r'\bdelay 35(?:\.0+)?ms\b', text) is not None
                and re.search(r'\bloss 15(?:\.0+)?%', text) is not None,
                'effective owned netem delay/loss differs from35ms/15percent')
        result[side] = {'class': classes, 'class_format': class_format, 'qdisc': qdiscs, 'qdisc_text': text}
    return result


def raw_rules(case):
    result = {}
    for side, other in [('a', 'b'), ('b', 'a')]:
        role = 'endpoint_' + side
        before = case.command(role, 'iptables', '-S', 'OUTPUT')
        require(before.strip() == '-P OUTPUT ACCEPT', 'fresh namespace OUTPUT policy was not empty')
        options = dict(zip(case.row['required_cli'][side][::2], case.row['required_cli'][side][1::2]))
        mark = int(options['--raw-mark'], 0)
        require(0 < mark <= 0xffffffff, 'nonzero bounded raw socket mark required')
        rule = ['-p', 'tcp', '-s', WAN[side], '--sport', str(PORTS[side]), '-d', WAN[other], '--dport', str(PORTS[other]),
                '--tcp-flags', 'RST', 'RST', '-m', 'mark', '!', '--mark', hex(mark), '-j', 'DROP']
        case.command(role, 'iptables', '-I', 'OUTPUT', '1', *rule)
        case.command(role, 'iptables', '-C', 'OUTPUT', *rule)
        result[side] = case.command(role, 'iptables', '-S', 'OUTPUT')
    case.value['raw_reset_rules'] = result
    case.save()


def tls_credentials(case, secrets):
    case.command(None, 'openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                 '-keyout', secrets / 'server.pem', '-out', secrets / 'cert.pem', '-days', '1', '-subj', '/CN=lab.invalid',
                 '-addext', 'subjectAltName=DNS:lab.invalid', '-addext', 'basicConstraints=critical,CA:FALSE')
    case.command(None, 'openssl', 'x509', '-in', secrets / 'cert.pem', '-outform', 'DER', '-out', secrets / 'cert.der')
    case.command(None, 'openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', secrets / 'server.pem', '-outform', 'DER', '-out', secrets / 'server.der')
    for path in secrets.iterdir():
        path.chmod(0o600)
    return {'server_name': 'lab.invalid', 'own_certificate_sha256': file_hash(secrets / 'cert.der')}


def status(case, binary, secrets, side, deadline):
    raw = case.command('endpoint_' + side, binary, 'status', '--control-socket', secrets / f'control-{side}.sock',
                       '--api-version', '4', deadline=deadline, allow_failure=True)
    values = [bounded.strict_json(line) for line in raw.splitlines() if line.startswith('{')]
    return values[-1] if values else None


def require_ready(value, row):
    require(isinstance(value, dict) and value.get('version') == 4 and value.get('ok') is True, 'actual API4 status required')
    state = value.get('state') or {}
    common = state.get('common') or {}
    require(state.get('phase') == 'forwarding' and common.get('running') is True
            and common.get('terminal') is None and common.get('service_terminal') is None, 'Common daemon is not actually forwarding')
    canonical = common.get('current')
    require(type(canonical) is str and re.fullmatch('[0-9a-f]+', canonical) and len(canonical) > 96,
            'actual canonical current configuration absent')
    descriptor = canonical[:32] + canonical[96:]
    require(descriptor == row['expected_descriptor_hex'], 'actual descriptor differs from manifest request')


def readiness(case, binary, secrets, daemons):
    deadline = min(case.deadline, time.monotonic() + BOUNDS['startup_seconds'])
    observed = {}
    while True:
        case.check(deadline)
        for side in ('a', 'b'):
            if daemons[side]['process'].poll() is not None:
                raise RuntimeError('Common daemon exited during setup: ' + side)
            observed[side] = status(case, binary, secrets, side, deadline)
        case.value['startup_status'] = observed
        case.save()
        try:
            for value in observed.values():
                require_ready(value, case.row)
            return
        except ValueError:
            # Querying setup state is observation, not a handshake retry.
            for value in observed.values():
                state = (value or {}).get('state') or {}
                if state.get('phase') in ('failed', 'disconnected'):
                    raise RuntimeError('service failed before actual forwarding')
        time.sleep(.1)


def compare_probes(a, b, phase):
    require(a.get('status') == b.get('status') == 'passed', 'TCP probe did not complete within original bounds')
    require(a['clock'] == b['clock'] and len(a['flows']) == len(b['flows']) == 16, 'shared clock or flow count differs')
    for endpoint in (a, b):
        require([flow.get('flow_id') for flow in endpoint['flows']] == list(range(16)), 'explicit complete flow IDs missing or out of order')
        identity = endpoint.get('flow_identity') or {}
        require(identity.get('format') == 'u32be-id-echo-v1'
                and [item.get('flow_id') for item in identity.get('connections', [])] == list(range(16)),
                'actual premeasurement flow identity exchange missing')
    result = {}
    for direction, sender, receiver in [('a_to_b', a, b), ('b_to_a', b, a)]:
        for sent, received in zip(sender['flows'], receiver['flows']):
            require(sent['flow_id'] == received['flow_id'], 'TCP flow identity differs')
            require(sent['sent'] == received['received'] and sent['sent_sha256'] == received['received_sha256']
                    and sent['write_closed'] and received['eof'], 'TCP stream bytes/hash/EOF mismatch')
        count = sum(flow['measured'] for flow in receiver['flows'])
        active = phase == 'simultaneous' or (phase == 'forward') == (direction == 'a_to_b')
        require(count > 0 if active else count == 0, 'phase sent no measured bytes or inactive direction sent data')
        result[direction] = {'receiver_unique_sample_bytes': count, 'sample_seconds': 10, 'goodput_mbit_s': count * 8 / 10_000_000}
    return result


def phase(case, name, binary, secrets, daemons):
    output = case.output / name
    output.mkdir()
    result = {'phase': name, 'status': 'running', 'cpu': [], 'status_samples': [], 'captures': {}}
    case.value['phases'].append(result)
    deadline = min(case.deadline, time.monotonic() + BOUNDS['phase_seconds'])
    captures, probes = {}, []
    sample_wall = None
    try:
        result['qdisc_before'] = qdisc(case)
        for side in ('a', 'b'):
            for kind, interface, addresses in [('wan', 'wan0', list(WAN.values())), ('native', 'tun0', list(NATIVE.values()))]:
                label = name + '-' + side + '-' + kind
                path = output / (side + '-' + kind + '.pcap')
                args = ['tcpdump', '-Z', 'root', '--immediate-mode', '-n', '-U', '-s', str(observe.SNAPLEN), '-B', '8192', '-i', interface,
                        '-c', str(observe.CAPTURE_PACKETS), '-w', '-', 'ip', 'and', 'host', addresses[0], 'and', 'host', addresses[1]]
                child = case.spawn('endpoint_' + side, label, args, capture=path)
                captures[side + '_' + kind] = (child, addresses)
                case.wait_marker(child, 'listening on', deadline)
        probe = ROOT / 'tools/common_native_probe.py'
        clock = output / 'clock.json'
        deadline_ns = time.monotonic_ns() + int((deadline - time.monotonic()) * 1e9)
        for side, role, address in [('b', 'listen', NATIVE['b']), ('a', 'connect', NATIVE['b'])]:
            child = case.spawn('endpoint_' + side, name + '-probe-' + side,
                [sys.executable, str(probe), role, '--phase', name, '--address', address, '--port', '24451',
                 '--deadline-ns', str(deadline_ns), '--clock', str(clock), '--result', str(output / (side + '.json'))])
            probes.append(child)
            if role == 'listen':
                case.wait_marker(child, 'Listening', deadline)
        for child in probes:
            case.wait_marker(child, 'Connected', deadline)
        mono_before, wall, mono_after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
        start = mono_after + 500_000_000
        window = {'start_ns': start, 'measure_start_ns': start + 2_000_000_000, 'end_ns': start + 12_000_000_000}
        result['clock_anchor'] = {'monotonic_before_ns': mono_before, 'wall_ns': wall, 'monotonic_after_ns': mono_after}
        offset = wall - (mono_before + mono_after) // 2
        sample_wall = (window['measure_start_ns'] + offset, window['end_ns'] + offset)
        atomic_json(clock, window)
        next_cpu, next_status = 0, time.monotonic() + 2
        while any(child['process'].poll() is None for child in probes):
            case.check(deadline)
            now = time.monotonic()
            for child in daemons.values():
                require(child['process'].poll() is None, 'Common daemon exited during native workload')
            if now >= next_cpu:
                result['cpu'].append(observe.cpu_snapshot([(child['label'], child['process']) for child in case.children]))
                next_cpu = now + .5
                case.save()
            if now >= next_status:
                values = {side: status(case, binary, secrets, side, deadline) for side in ('a', 'b')}
                result['status_samples'].append({'at_ns': time.monotonic_ns(), 'endpoints': values})
                for value in values.values():
                    require_ready(value, case.row)
                next_status = now + 2
            time.sleep(.02)
        probe_results = {side: read_json(output / (side + '.json'), BOUNDS['log_bytes']) for side in ('a', 'b')}
        for side, probe_result in probe_results.items():
            if probe_result.get('status') != 'passed':
                raise OutcomeError(probe_result.get('status', 'tool_failure'), 'native TCP probe ' + side + ': ' + probe_result.get('error', 'incomplete'))
        for child in probes:
            require(child['process'].returncode == 0, 'native TCP probe exit disagrees with passing result')
        result['throughput'] = compare_probes(probe_results['a'], probe_results['b'], name)
        result['status'] = 'passed'
    except Exception as error:
        result.update(status=failure_status(error), error_type=type(error).__name__, error=str(error))
    finally:
        cleanup_deadline = min(case.deadline, time.monotonic() + BOUNDS['cleanup_seconds'])
        for child in probes:
            try:
                case.stop(child, deadline=cleanup_deadline)
            except Exception as error:
                result.setdefault('cleanup_errors', []).append(str(error))
        result['probe_results'] = {}
        for side in ('a', 'b'):
            path = output / (side + '.json')
            if path.is_file():
                try:
                    observed = read_json(path, BOUNDS['log_bytes'])
                    clock = observed.get('clock')
                    result['probe_results'][side] = {'receipt': str(path.relative_to(case.output)),
                        'status': observed.get('status'), 'error': observed.get('error'), 'clock': clock,
                        'receiver_unique_sample_bytes': sum(flow.get('measured', 0) for flow in observed.get('flows', [])),
                        'sample_window_completed': clock is not None and observed.get('completed_ns', 0) >= clock['end_ns']}
                    sample = result['probe_results'][side]
                    complete = sample['sample_window_completed']
                    result.setdefault('throughput_observed', {})['b_to_a' if side == 'a' else 'a_to_b'] = {
                        'receiver_unique_sample_bytes': sample['receiver_unique_sample_bytes'], 'configured_sample_seconds': 10,
                        'sample_window_completed': complete,
                        'observed_goodput_mbit_s': sample['receiver_unique_sample_bytes'] * 8 / 10_000_000 if complete else None,
                        'qualification': 'valid' if result['status'] == 'passed' else 'invalid_or_incomplete',
                        'reason': None if result['status'] == 'passed' else result.get('error', result['status'])}

                except Exception as error:
                    result['probe_results'][side] = {'status': 'tool_failure', 'error': str(error)}
        for surface, (child, addresses) in captures.items():
            entry = {'pcap': str(child['capture'].relative_to(case.output)), 'log': child['log'].name}
            result['captures'][surface] = entry
            try:
                entry['returncode'] = case.stop(child, signal.SIGINT, deadline=cleanup_deadline)
                require(entry['returncode'] == 0, 'tcpdump did not exit cleanly')
                entry['counters'] = observe.capture_counters(child['log'])
                entry['summary'] = observe.capture_summary(child['capture'], addresses, sample_wall)
                require(entry['counters']['captured'] == entry['summary']['captured_packets'], 'pcap packet count differs from tcpdump')
                entry['sha256'] = file_hash(child['capture'])
            except Exception as error:
                entry.update(status='tool_failure', error=str(error))
                if result['status'] == 'passed':
                    result.update(status='tool_failure', error='capture observation incomplete')
        try:
            result['qdisc_after'] = qdisc(case)
        except Exception as error:
            result['qdisc_error'] = str(error)
            if result['status'] == 'passed':
                result.update(status='tool_failure', error='qdisc observation incomplete')
        for observed in result.get('throughput_observed', {}).values():
            observed['qualification'] = 'valid' if result['status'] == 'passed' else 'invalid_or_incomplete'
            observed['reason'] = None if result['status'] == 'passed' else result.get('error', result['status'])
        case.save()
    return result['status'] == 'passed'


class OutcomeError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status if status in ('bound_exhausted', 'tool_failure', 'unsupported', 'failed') else 'tool_failure'


def failure_status(error):
    if isinstance(error, OutcomeError):
        return error.status
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return 'bound_exhausted'
    if isinstance(error, bounded.Unsupported):
        return 'unsupported'
    if isinstance(error, OSError):
        return 'tool_failure'
    return 'failed'


def run_case(row, ordinal, args, binary, inputs, secrets, state_dir):
    spec = lab.LabSpec(args.lab_id + '-' + str(ordinal))
    output = args.output / row['id']
    output.mkdir()
    case = Case(row, spec, output)
    case.value['selected_phases'] = args.phases
    created = False
    try:
        case.value['stage'] = 'offline_preflight'
        for side in ('a', 'b'):
            case.command(None, *daemon_command(row, side, binary, secrets, inputs, inspection=True))
        case.value['stage'] = 'topology'
        topology(case, state_dir)
        created = True
        if row['carrier'] == 'raw':
            raw_rules(case)
        case.value['stage'] = 'authenticated_startup'
        metrics = output / 'metrics'
        metrics.mkdir()
        daemons = {}
        for side in ('b', 'a'):
            daemons[side] = case.spawn('endpoint_' + side, 'daemon-' + side,
                daemon_command(row, side, binary, secrets, inputs), metrics=metrics / "wire")
        readiness(case, binary, secrets, daemons)
        case.value['stage'] = 'native_workload'
        for name in args.phases:
            if not phase(case, name, binary, secrets, daemons):
                # A failed connection is not restarted to manufacture later phases.
                break
        present = {value['phase'] for value in case.value['phases']}
        for name in args.phases:
            if name not in present:
                case.value['phases'].append({'phase': name, 'status': 'not_run', 'reason': 'prior phase failed; no automatic reconnect/retry'})
        case.value['status'] = next((value['status'] for value in case.value['phases'] if value['status'] != 'passed'), 'passed')
    except BaseException as error:
        case.value.update(status='interrupted' if isinstance(error, KeyboardInterrupt) else failure_status(error), error_type=type(error).__name__, error=str(error))
        if isinstance(error, KeyboardInterrupt):
            raise
    finally:
        case.value['cleanup'] = {'children': [], 'disconnect': {}}
        # Disconnect drops the actual Runtime; dropping the CLI supervisor alone
        # cannot establish graceful report publication or peer drain.
        cleanup_deadline = time.monotonic() + BOUNDS['cleanup_seconds']
        for side in ('a', 'b'):
            if (secrets / f'control-{side}.sock').exists():
                try:
                    raw = bounded.command(case.prefix('endpoint_' + side, [binary, 'disconnect',
                        '--control-socket', secrets / f'control-{side}.sock', '--api-version', '4']), cleanup_deadline, 3)
                    values = [bounded.strict_json(line) for line in raw.splitlines() if line.startswith('{')]
                    case.value['cleanup']['disconnect'][side] = values[-1] if values else {'error': 'no JSON disconnect reply'}
                except Exception as error:
                    case.value['cleanup']['disconnect'][side] = {'error': str(error)}
        if (output / 'metrics').is_dir():
            publication_deadline = min(cleanup_deadline, time.monotonic() + 2)
            while len(list((output / 'metrics').glob('wire.*.json'))) < 2 and time.monotonic() < publication_deadline:
                time.sleep(.02)
        for child in reversed(case.children):
            try:
                code = case.stop(child, signal.SIGINT if child.get('capture') else signal.SIGTERM, deadline=cleanup_deadline)
                case.value['cleanup']['children'].append({'label': child['label'], 'returncode': code})
            except Exception as error:
                case.value['cleanup']['children'].append({'label': child['label'], 'error': str(error)})
        if (output / 'metrics').is_dir():
            reports = sorted((output / 'metrics').glob('wire.*.json'))
            case.value['wire_metrics'] = {'files': [str(path.relative_to(output)) for path in reports],
                'sha256': {path.name: file_hash(path) for path in reports},
                'expected_runtime_owners': 2, 'report_count': len(reports),
                'scope': 'per-runtime accepted records across all completed phases; observer allocation is opt-in and reported separately'}
            try:
                require(len(reports) == 2, 'missing or extra actual runtime wire-metrics reports')
                actual_pids = {child['process'].pid for child in case.children if child['label'].startswith('daemon-')}
                observed_pids = {int(path.name.split('.')[1]) for path in reports}
                require(observed_pids == actual_pids and len(actual_pids) == 2, 'wire reports do not identify both actual daemon owners')
                case.value['wire_metrics']['validated'] = {path.name: observe.validate_wire_metrics(
                    read_json(path, BOUNDS['log_bytes']), row['carrier']) for path in reports}
            except Exception as error:
                case.value['wire_metrics'].update(status='tool_failure', error=str(error))
                if case.value['status'] == 'passed':
                    case.value.update(status='tool_failure', error='invalid or missing actual runtime wire metrics')
        journal = state_dir / (spec.lab_id + '.json')
        if created or journal.exists():
            try:
                bounded.bounded_lab(lab.cleanup, spec, state_dir, cleanup_deadline)
                case.value['cleanup']['namespaces'] = 'removed_after_identity_and_empty_pid_verification'
            except Exception as error:
                case.value['cleanup']['namespaces'] = 'failed'
                case.value['cleanup']['error'] = str(error)
                case.value['status'] = 'cleanup_failed'
        for side in ('a', 'b'):
            (secrets / f'control-{side}.sock').unlink(missing_ok=True)
        present = {value['phase'] for value in case.value['phases']}
        for name in args.phases:
            if name not in present:
                case.value['phases'].append({'phase': name, 'status': 'not_run', 'reason': 'setup or prior phase failed; no retry'})
        case.value['completed_wall_ns'] = time.time_ns()
        case.save()
    return case.value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append', default=[])
    parser.add_argument('--phase', action='append', choices=PHASES, help='Run only these independent phases; default all three')
    parser.add_argument('--lab-id', default='cmatrix')
    parser.add_argument('--parallel-lane', choices=('udp', 'raw', 'tls', 'quic'),
                        help='Explicit concurrent carrier lane; fixed eight-CPU affinity and distinct owned lab prefix required')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    args.phases = list(dict.fromkeys(args.phase or PHASES))
    require(re.fullmatch('[a-z][a-z0-9-]{0,14}', args.lab_id), 'lab prefix must fit owned namespace names')
    args.manifest, args.binary, args.output = (path.absolute() for path in (args.manifest, args.binary, args.output))
    document, rows = manifest_rows(args.manifest, set(args.case))
    affinity = sorted(os.sched_getaffinity(0))
    if args.parallel_lane is not None:
        require(all(row.get('carrier') == args.parallel_lane for row in rows), 'parallel lane must contain only its carrier')
        require(args.lab_id == 'cm-' + args.parallel_lane, 'parallel lane requires its distinct cm-CARRIER namespace prefix')
        start = ('udp', 'raw', 'tls', 'quic').index(args.parallel_lane) * 8
        # CPU numbers are absolute so runners started under different inherited
        # affinities cannot silently choose overlapping lane CPU sets.
        chosen = set(range(start, start + 8))
        require(chosen.issubset(affinity), 'fixed parallel lane CPU set unavailable')
        affinity = sorted(chosen)
        if args.apply:
            os.sched_setaffinity(0, chosen)
    plan = {'version': 1, 'status': 'planned', 'manifest': str(args.manifest), 'manifest_sha256': file_hash(args.manifest),
            'binary': str(args.binary), 'rows': rows, 'bounds': BOUNDS, 'phases': args.phases,
            'flows_per_phase': 16, 'warmup_seconds': 2, 'sample_seconds': 10,
            'network': {'forward_mbit_s': 100, 'reverse_mbit_s': 10, 'one_way_delay_ms': 35, 'loss_percent_each_direction': 15},
            'captures': 'each endpoint WAN and native, both directions, full packets; each surface remains separate',
            'measurement': 'application recv goodput; captured IPv4 byte totals and packet-size distributions; no p99-overhead inference',
            'parallel_lane': args.parallel_lane, 'cpu_affinity': affinity,
            'execution': 'one expensive case per explicit carrier lane; lanes share host memory, I/O and kernel; no automatic retries or cap relaxation; dry run creates no namespace'}
    if not args.apply:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0
    lab.require_root()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('matrix interrupted; cleaning owned resources')
    signal.signal(signal.SIGTERM, interrupted)
    for name in ('ip', 'tc', 'sysctl', 'ethtool', 'tcpdump', 'openssl'):
        require(shutil.which(name) is not None, 'missing required tool: ' + name)
    if any(row['carrier'] == 'raw' for row in rows if row['status'] == 'ready'):
        require(shutil.which('iptables') is not None, 'raw carrier requires namespace-local iptables')
    require(args.binary.is_file() and not args.binary.is_symlink() and os.access(args.binary, os.X_OK), 'executable current binary required')
    require(not args.output.exists() and not args.output.is_symlink(), 'output already exists; failed receipts are never overwritten')
    args.output.mkdir(parents=True, mode=0o700)
    result = {**plan, 'status': 'running', 'results': [], 'kernel': os.uname()._asdict() if hasattr(os.uname(), '_asdict') else list(os.uname())}
    atomic_json(args.output / 'results.json', result)
    try:
        with exclusive_lab(args.parallel_lane), tempfile.TemporaryDirectory(prefix='l2t-common-matrix-') as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            binary, inputs, secrets = root / 'l2tunnel', root / 'inputs', root / 'secrets'
            inputs.mkdir(mode=0o700)
            secrets.mkdir(mode=0o700)
            shutil.copyfile(args.binary, binary)
            binary.chmod(0o700)
            result['binary_sha256'] = file_hash(binary)
            result['runner_source_sha256'] = {str(path.relative_to(ROOT)): file_hash(path) for path in
                [Path(__file__).resolve(), ROOT / 'tools/common_native_probe.py', ROOT / 'tools/common_native_observe.py',
                 ROOT / 'tools/netns_lab.py', ROOT / 'tools/throughput_probe.py',
                 ROOT / 'tools/proxy_native_smoke.py', ROOT / 'tools/secure_udp_native.py', ROOT / 'tools/native_throughput.py']}
            result['binary_source_binding'] = 'binary hash observed; use the separate parent build receipt for its source revision'
            result['input_sha256'] = {}
            for row in rows:
                if row['status'] != 'ready':
                    continue
                for relative in [row['common_plan'], *(row.get('carrier_policy') or {}).values()]:
                    source = input_path(args.manifest.parent, relative)
                    destination = inputs / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
                    result['input_sha256'][relative] = file_hash(destination)
            # Reuse maintained crypto APIs only; no retired CLI or wire code runs.
            result['credentials'] = credentials_helper.credentials(binary, secrets, time.monotonic() + 30)
            credential_case = Case({'id': 'credentials'}, lab.LabSpec(args.lab_id), args.output)
            result['tls_credentials'] = tls_credentials(credential_case, secrets)
            state_dir = Path('/run/l2tunnel-common-native-matrix-state')
            for ordinal, row in enumerate(rows):
                if row['status'] == 'plan_refused':
                    result['results'].append({'id': row['id'], 'status': 'plan_refused', 'reason': row['reason']})
                else:
                    value = run_case(row, ordinal, args, binary, inputs, secrets, state_dir)
                    result['results'].append({'id': row['id'], 'status': value['status'], 'receipt': row['id'] + '/result.json'})
                    if value['status'] == 'cleanup_failed':
                        result['status'] = 'cleanup_failed'
                        break
                atomic_json(args.output / 'results.json', result)
            result['status'] = 'passed' if len(result['results']) == len(rows) and all(row['status'] == 'passed' for row in result['results']) else 'incomplete'
            result['original_binary_still_matches'] = file_hash(args.binary) == result['binary_sha256']
            result['completed_wall_ns'] = time.time_ns()
            atomic_json(args.output / 'results.json', result)
    except BaseException as error:
        result.update(status='interrupted' if isinstance(error, KeyboardInterrupt) else failure_status(error),
                      error_type=type(error).__name__, error=str(error), completed_wall_ns=time.time_ns())
        atomic_json(args.output / 'results.json', result)
    print(json.dumps({'status': result['status'], 'receipt': str(args.output / 'results.json')}))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
