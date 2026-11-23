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
import struct
# Selected once by main() from --netem-seed / --loss-percent; defaults are the standard path.
NETEM_SEED = 31248
LOSS_PERCENT = 15
import subprocess
import sys
import tempfile
from threading import Thread
import time

try:
    from . import netns_lab as lab, proxy_native_smoke as bounded
    from . import secure_udp_native as credentials_helper
    from . import common_native_observe as observe
    from . import common_native_single_flow as single
    from . import common_python_reference as reference
    from . import common_native_switch as switch_hook
    from .native_throughput import parse_tc_class, parse_tc_qdisc
except ImportError:
    import netns_lab as lab
    import proxy_native_smoke as bounded
    import secure_udp_native as credentials_helper
    import common_native_observe as observe
    import common_native_single_flow as single
    import common_python_reference as reference
    import common_native_switch as switch_hook
    from native_throughput import parse_tc_class, parse_tc_qdisc

ROOT = Path(__file__).resolve().parents[1]
WAN = {'a': '192.0.2.2', 'b': '192.0.2.6'}
NATIVE = {'a': '198.18.0.1', 'b': '198.18.0.2'}
PORTS = {'a': 24440, 'b': 24441}
PHASES = ('forward', 'reverse', 'simultaneous')
BOUNDS = {'case_seconds': 300, 'startup_seconds': 40, 'command_seconds': 10,
          'phase_seconds': 60, 'cleanup_seconds': 30, 'log_bytes': 16 * 1024 * 1024}
MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TUN_TXQUEUELEN = 8192
MAX_FORWARD_TUN_MBIT = 100
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


def native_layer(row):
    cli = row['required_cli']['a']
    return cli[cli.index('--layer') + 1]


def manifest_rows(path, selected, *, require_python_comparable=False):
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
            reference.validate_row(row, require_comparable=require_python_comparable)
            for side in ('a', 'b'):
                args = row['required_cli'][side]
                require(isinstance(args, list) and len(args) % 2 == 0 and 0 < len(args) <= 32
                        and all(type(item) is str and '\0' not in item for item in args), 'bounded option pairs required')
                keys = args[::2]
                require(len(keys) == len(set(keys)) and set(keys) <= FIXED_CLI, 'unknown or repeated exporter CLI option')
                options = dict(zip(keys, args[1::2]))
                layer = options.get('--layer')
                require(layer in ('tun', 'tap'), 'unknown native CLI layer')
                require(layer == row.get('layer', layer) and layer == native_layer(row),
                        'native layer differs between manifest and endpoints')
                expected = {'--record-profile': 'common', '--duplex': 'full', '--noise-profile': 'ik',
                            '--max-packet': '1514' if layer == 'tap' else '1500', '--max-path-mtu': '1500'}
                require(all(options.get(key) == value for key, value in expected.items()),
                        'row differs from Full Common selection or native packet/MTU geometry')
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
            require(not require_python_comparable, 'refused plan cannot establish Python comparability')
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
    def __init__(self, row, spec, output, *, native_tun_txqueuelen=None, native_forward_tun_maxrate_mbit=None):
        # Credential setup has no endpoint, interface or traffic manifest.
        layer = None if row is None else native_layer(row)
        self.row = {'id': 'credentials'} if row is None else row
        self.spec, self.output = spec, output
        self.deadline = time.monotonic() + BOUNDS['case_seconds']
        self.children, self.commands = [], []
        self.command_index = 0
        self.value = {'version': 1, 'id': self.row['id'], 'row': self.row, 'native_layer': layer,
                      'status': 'running', 'stage': 'preflight',
                      'bounds': BOUNDS, 'phases': [], 'started_wall_ns': time.time_ns(), 'commands': self.commands,
                      'requested_native_tun_txqueuelen': native_tun_txqueuelen,
                      'requested_native_forward_tun_maxrate_mbit': native_forward_tun_maxrate_mbit}
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
        receipt = {'argv': argv, 'log': name, 'started_wall_ns': time.time_ns()}
        self.commands.append(receipt)
        until = min(self.deadline, deadline or self.deadline)
        started = time.monotonic()
        with (self.output / name).open('xb') as stream:
            process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            receipt['pid'] = process.pid
            try:
                code = process.wait(timeout=min(BOUNDS['command_seconds'], max(.001, until - time.monotonic())))
            except subprocess.TimeoutExpired:
                receipt.update(timed_out=True, requested_signal='SIGKILL')
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
                raise
            finally:
                receipt.update(returncode=process.returncode, elapsed_seconds=time.monotonic() - started,
                               finished_wall_ns=time.time_ns())
                self.save()
        raw = (self.output / name).read_bytes()
        require(len(raw) < BOUNDS['log_bytes'], 'command log bound exhausted')
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
        started = time.monotonic()
        receipt = {'started_wall_ns': time.time_ns(), 'signals': []}
        child.setdefault('stops', []).append(receipt)
        self.value.setdefault('child_stops', []).append({'label': child['label'], 'pid': process.pid,
                                                       'observation': receipt})

        def send(sig):
            item = {'signal': signal.Signals(sig).name, 'elapsed_seconds': time.monotonic() - started}
            receipt['signals'].append(item)
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                item['already_exited'] = True

        try:
            if process.poll() is None:
                # TERM gets the remainder of the original three-second graceful
                # allowance if an INT-handling capture process has not exited.
                graceful_until = min(until, started + 3)
                send(requested if graceful_until > time.monotonic() else signal.SIGKILL)
                try:
                    first_until = min(graceful_until, started + 1.5) if requested == signal.SIGINT else graceful_until
                    process.wait(timeout=max(0, first_until - time.monotonic()))
                except subprocess.TimeoutExpired:
                    if requested == signal.SIGINT and time.monotonic() < graceful_until:
                        send(signal.SIGTERM)
                        try:
                            process.wait(timeout=max(0, graceful_until - time.monotonic()))
                        except subprocess.TimeoutExpired:
                            pass
                    if process.poll() is None:
                        send(signal.SIGKILL)
                        process.wait(timeout=max(0, min(2, until - time.monotonic())))
        finally:
            receipt.update(returncode=process.returncode, elapsed_seconds=time.monotonic() - started,
                           finished_wall_ns=time.time_ns())
            self.save()
        return process.returncode


def topology(case, state_dir):
    bounded.bounded_lab(lab.apply, case.spec, state_dir, case.deadline)
    case.value['namespace_journal'] = read_json(state_dir / (case.spec.lab_id + '.json'), MANIFEST_BYTES)
    offloads = {}
    requested = case.value['requested_native_tun_txqueuelen']
    options = [] if requested is None else ['txqueuelen', str(requested)]
    for role in case.spec.namespaces:
        case.command(role, 'sysctl', '-q', '-w', 'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1')
    for side in ('a', 'b'):
        role = 'endpoint_' + side
        for interface in ('tap0', 'lan0', 'br-lan'):
            case.command(role, 'ip', 'link', 'set', interface, 'down')
        case.command('host_' + side, 'ip', 'address', 'flush', 'dev', 'eth0')
        case.command('host_' + side, 'ip', 'link', 'set', 'eth0', 'down')
        case.command(role, 'ip', 'tuntap', 'add', 'dev', 'tun0', 'mode', case.value['native_layer'])
        case.command(role, 'ip', 'address', 'add', NATIVE[side] + '/24', 'dev', 'tun0')
        case.command(role, 'ip', 'link', 'set', 'tun0', 'mtu', '1500', *options, 'up')
    maxrate = case.value.get('requested_native_forward_tun_maxrate_mbit')
    if maxrate is not None:
        case.command('endpoint_a', 'tc', 'qdisc', 'replace', 'dev', 'tun0', 'root', 'fq', 'limit', '10240',
                     'flow_limit', '1024', 'maxrate', f'{maxrate}mbit')
    for role, interface in [('endpoint_a', 'wan0'), ('endpoint_b', 'wan0'), ('router', 'a0'), ('router', 'b0'), ('endpoint_a', 'tun0'), ('endpoint_b', 'tun0')]:
        offloads[role + '/' + interface] = bounded.offloads(case.spec.namespaces[role], interface, case.deadline)
    case.value['offloads'] = offloads
    case.value['qdisc_before'] = qdisc(case)
    case.save()
    check_forward_tun_fq(case, case.value['qdisc_before'])
    if requested is not None:
        require(all(side['native_tun']['effective_txqueuelen'] == requested
                    for side in case.value['qdisc_before'].values()),
                'effective owned tun0 txqueuelen differs from request')


def check_forward_tun_fq(case, sides):
    requested = case.value.get('requested_native_forward_tun_maxrate_mbit')
    if requested is not None:
        fq = sides['a']['native_tun']['effective_root_fq']
        require(fq is not None and fq.get('maxrate_bits_per_second') == requested * 1_000_000
                and fq.get('limit') == 10240 and fq.get('flow_limit') == 1024,
                'effective endpoint_a tun0 root fq limits or maxrate differ from request')


def qdisc_fields(pairs, fields):
    require(isinstance(pairs, tuple), 'invalid native tun0 qdisc object')
    selected = {}
    for key, value in pairs:
        if key in fields:
            require(key not in selected, 'duplicate native tun0 qdisc field: ' + key)
            selected[key] = value
    return selected


def native_tun_snapshot(case, role):
    begin = time.time_ns()
    links = bounded.strict_json(case.command(role, 'ip', '-j', '-s', 'link', 'show', 'dev', 'tun0'))
    require(isinstance(links, list) and len(links) == 1 and links[0].get('ifname') == 'tun0',
            'expected the owned tun0 link')
    link = links[0]
    tx = link.get('stats64', link.get('stats', {})).get('tx', {})
    require(type(link.get('txqlen')) is int and link['txqlen'] >= 0
            and all(type(tx.get(k)) is int and tx[k] >= 0 for k in ('packets', 'bytes', 'dropped', 'errors')),
            'missing native tun0 queue length or TX counters')
    raw_qdisc = case.command(role, 'tc', '-s', '-d', '-j', 'qdisc', 'show', 'dev', 'tun0')
    # Some iproute2 FQ versions emit two distinct statistics as "throttled".
    # Select the fields used for queue counters and FQ configuration. The raw output stays in the command log.
    rows = json.loads(raw_qdisc, object_pairs_hook=tuple)
    require(isinstance(rows, list), 'invalid native tun0 qdisc list')
    qdiscs = []
    root_fq = None
    fields = {'kind', 'handle', 'parent', 'root', 'options', 'drops', 'packets', 'bytes',
              'overlimits', 'requeues', 'backlog', 'qlen'}
    for pairs in rows:
        row = qdisc_fields(pairs, fields)
        options = row.pop('options', ())
        if row.get('root') is True and row.get('kind') == 'fq':
            require(root_fq is None, 'multiple root fq qdiscs on native tun0')
            root_fq = qdisc_fields(options, {'limit', 'flow_limit', 'maxrate'})
            require(all(type(v) is int and v >= 0 for v in root_fq.values()), 'invalid native tun0 fq option')
            if 'maxrate' in root_fq:
                # iproute2 emits its numeric JSON rate in bytes per second.
                root_fq['maxrate_bytes_per_second'] = root_fq.pop('maxrate')
                root_fq['maxrate_bits_per_second'] = root_fq['maxrate_bytes_per_second'] * 8
        qdiscs.append(row)
    require(isinstance(qdiscs, list) and qdiscs and all(isinstance(q, dict) and q.get('kind')
            and type(q.get('drops')) is int and q['drops'] >= 0 for q in qdiscs), 'missing native tun0 qdisc counters')
    if case.value['native_layer'] == 'tap':
        require(link.get('link_type') == 'ether', 'owned TAP must report Ethernet link type')
    return {'interface': 'tun0', 'native_layer': case.value['native_layer'], 'kernel_link_type': link.get('link_type'),
            'requested_txqueuelen': case.value['requested_native_tun_txqueuelen'],
            'effective_txqueuelen': link['txqlen'], 'tx': tx, 'qdisc': qdiscs,
            'requested_fq_maxrate_mbit': case.value.get('requested_native_forward_tun_maxrate_mbit') if role == 'endpoint_a' else None,
            'effective_root_fq': root_fq,
            'begin_wall_ns': begin, 'end_wall_ns': time.time_ns()}


def qdisc(case):
    result = {}
    for side in ('a', 'b'):
        role = 'endpoint_' + side
        classes, class_format = parse_tc_class(case.command(role, 'tc', '-s', '-j', 'class', 'show', 'dev', 'wan0'), 100 if side == 'a' else 10)
        qdiscs = parse_tc_qdisc(case.command(role, 'tc', '-s', '-d', '-j', 'qdisc', 'show', 'dev', 'wan0'))
        text = case.command(role, 'tc', '-d', 'qdisc', 'show', 'dev', 'wan0')
        loss = re.search(r'\bloss (\d+(?:\.\d+)?)%', text)
        require(re.search(r'\bdelay 35(?:\.0+)?ms\b', text) is not None
                and (float(loss.group(1)) if loss else 0.0) == LOSS_PERCENT,
                f'effective owned netem delay/loss differs from35ms/{LOSS_PERCENT}percent')
        # These counters belong only to the owned endpoint namespace. Record
        # before/after the workload; never infer a blocked interval from occupancy.
        observed_at = time.time_ns()
        kernel_buffers = {
            'scope': 'owned endpoint namespace; cumulative counters and instantaneous tables, not wait durations',
            'begin_wall_ns': observed_at,
            'snmp': case.command(role, 'cat', '/proc/net/snmp'),
            'udp': case.command(role, 'cat', '/proc/net/udp'),
            'sockstat': case.command(role, 'cat', '/proc/net/sockstat'),
            'end_wall_ns': time.time_ns(),
        }
        result[side] = {'class': classes, 'class_format': class_format, 'qdisc': qdiscs,
                        'qdisc_text': text, 'kernel_buffers': kernel_buffers, 'native_tun': native_tun_snapshot(case, role)}
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


def compare_probes(a, b, phase, *, paced=False, single_flow=False, flow_count=None, credit=single.CREDIT):
    require(a.get('status') == b.get('status') == 'passed', 'TCP probe did not complete within original bounds')
    flows = flow_count or (1 if single_flow else 16)
    require(a['clock'] == b['clock'] and len(a['flows']) == len(b['flows']) == flows, 'shared clock or flow count differs')
    for endpoint in (a, b):
        require([flow.get('flow_id') for flow in endpoint['flows']] == list(range(flows)), 'explicit complete flow IDs missing or out of order')
        identity = endpoint.get('flow_identity') or {}
        require(identity.get('format') == 'u32be-id-echo-v1'
                and [item.get('flow_id') for item in identity.get('connections', [])] == list(range(flows)),
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
        if paced and active:
            submitted, delivered = sender['paced_records'], receiver['paced_records']
            expected = submitted['fully_written_records']
            require(0 < expected == submitted['started_records'] <= submitted['scheduled_records']
                    and delivered['fully_read_records'] == expected
                    and expected * 512 == sum(row['received'] for row in receiver['flows'])
                    and delivered['partial_receive_bytes'] == 0, 'paced application records incomplete')
            result[direction]['paced_records'] = {
                'scheduled': submitted['scheduled_records'], 'fully_written_and_read': expected,
                'unsubmitted_at_offer_cutoff': submitted['scheduled_records'] - expected,
                'first_write_to_complete_read': delivered['first_write_to_complete_read'],
                'scheduled_offer_to_complete_read': delivered['scheduled_offer_to_complete_read']}
            if flow_count:
                rows = []
                for i in range(flows):
                    server = receiver['flow_identity']['connections'][i]
                    client = sender['flow_identity']['connections'][i]
                    require(client['local'] == server['peer'] and client['peer'] == server['local'],
                            'endpoint TCP socket tuple mismatch')
                    share = credit // flows
                    for endpoint, connection in ((sender, client), (receiver, server)):
                        policy = endpoint['flow_credit'][i]
                        require(connection['tcp_congestion'] == 'cubic'
                                and connection['send_buffer_bytes'] == connection['receive_buffer_bytes'] == 2 * single.SOCKET_BUFFER
                                and endpoint['paced_records']['aggregate_offered_mbit_s'] == single.RATE / 1e6
                                and policy['outstanding_payload_cap'] == share
                                and policy['max_outstanding_upper_bound'] <= share,
                                'per-flow socket, pacing or credit policy mismatch')
                    timing = delivered['per_flow'][i]
                    source = submitted['per_flow'][i]
                    received = receiver['flows'][i]
                    require(timing['flow_id'] == i == source['flow_id']
                            and timing['fully_read_records'] == source['fully_written_records']
                            and timing['fully_read_records'] * 512 == received['received']
                            and timing['partial_record_bytes'] == 0, 'per-flow delivery validation failed')
                    edges = sender['flow_credit'][i]['steady_tcp_info_edges']
                    targets = [sender['clock'][key] for key in ('measure_start_ns', 'end_ns')]
                    require(len(edges) == 2 and [edge['target_ns'] for edge in edges] == targets
                            and all(e['target_ns'] <= e['before_ns'] <= e['after_ns'] for e in edges)
                            and edges[0]['after_ns'] < edges[1]['target_ns']
                            and edges[0]['total_retrans'] <= edges[1]['total_retrans'],
                            'per-flow TCP_INFO sample edges invalid')
                    rows.append({**timing, 'four_tuple': {'sender': client['local'], 'receiver': client['peer']},
                                 'measured_bytes': received['measured'], 'goodput_mbit_s': received['measured'] * 8 / 10_000_000,
                                 'full_hash_verified': True,
                                 'steady_retransmitted_segments': edges[1]['total_retrans'] - edges[0]['total_retrans'],
                                 'retrans_read_lag_ms': [(e['after_ns'] - e['target_ns']) / 1e6 for e in edges]})
                require(len({tuple(row['four_tuple']['sender']) for row in rows}) == flows, 'duplicate TCP tuple')
                result[direction]['per_flow'] = rows
            if single_flow:
                for endpoint in (sender, receiver):
                    connection, = endpoint['flow_identity']['connections']
                    require(connection['tcp_congestion'] == 'cubic' and
                            connection['send_buffer_bytes'] == connection['receive_buffer_bytes'] == 2 * single.SOCKET_BUFFER,
                            'single-flow socket parameters differ')
                    policy = endpoint['single_flow']
                    require(policy['outstanding_payload_cap'] == credit and
                            0 <= policy['max_outstanding_upper_bound'] <= credit and
                            endpoint['max_bytes_per_flow_direction'] == single.TRANSFER_CAP and
                            endpoint['paced_records']['aggregate_offered_mbit_s'] == single.RATE / 1e6,
                            'single-flow workload or application credit differs')
                edges = sender['single_flow']['steady_tcp_info_edges']
                targets = [sender['clock'][key] for key in ('measure_start_ns', 'end_ns')]
                require(len(edges) == 2 and [edge['target_ns'] for edge in edges] == targets
                        and all(e['target_ns'] <= e['before_ns'] <= e['after_ns'] for e in edges)
                        and edges[0]['after_ns'] < edges[1]['target_ns']
                        and edges[0]['total_retrans'] <= edges[1]['total_retrans'],
                        'single-flow steady counter edges invalid')
                result[direction]['steady_tcp_retrans'] = {
                    'segments': edges[1]['total_retrans'] - edges[0]['total_retrans'],
                    'reads': edges, 'read_lag_ms': [(e['after_ns'] - e['target_ns']) / 1e6 for e in edges]}
    return result


def validate_switch_flow_delivery(case, flow_rows, output, window):
    switch = case.value.get('mode_switch', {})
    require(switch.get('status') == 'passed', 'switch did not settle and replay on both peers')
    requested, settled = switch['requested_ns'], switch['settled_ns']
    require(window['measure_start_ns'] <= requested <= settled < window['end_ns'],
            'switch did not settle within the original measurement window')
    pair = struct.Struct('!QQ')
    for row in flow_rows:
        path = output / f"flow-{row['flow_id']:02}-record-times.bin"
        require(path.stat().st_size == row['fully_read_records'] * pair.size, 'receiver record trace count differs')
        before, spanning, after, after_drain = 0, 0, 0, 0
        for sent, completed in pair.iter_unpack(path.read_bytes()):
            before += window['measure_start_ns'] <= completed < requested
            spanning += sent < requested <= completed
            after += settled <= sent <= completed < window['end_ns']
            after_drain += settled <= sent and completed >= window['end_ns']
        row['switch_delivery'] = {
            'completed_before_request_in_steady': before, 'attempted_before_request_completed_during_or_after': spanning,
            'attempted_and_completed_after_settlement_in_steady': after, 'attempted_after_settlement_completed_in_drain': after_drain,
            'record_trace': path.name, 'record_trace_sha256': file_hash(path),
        }
        require(before > 0 and after > 0, 'flow lacks steady deliveries on both sides of committed switch')


def qualify_phase(result):
    pending = result.get('capture_analysis') == 'pending'
    for observed in result.get('throughput_observed', {}).values():
        observed['qualification'] = ('pending_capture_validation' if pending and result['status'] == 'passed'
                                     else 'valid' if result['status'] == 'passed' else 'invalid_or_incomplete')
        observed['reason'] = ('capture files have not been analyzed' if pending and result['status'] == 'passed'
                              else None if result['status'] == 'passed' else result.get('error', result['status']))


def stop_captures(case, result, captures, sample_wall, deadline):
    # Release all live capture owners before parsing even their short exit logs.
    # Full pcap analysis and hashes wait until the session has been disconnected.
    for surface, (child, addresses) in captures.items():
        entry = {'pcap': str(child['capture'].relative_to(case.output)), 'log': child['log'].name,
                 'addresses': addresses, 'sample_wall_ns': sample_wall, 'analysis': 'pending'}
        result['captures'][surface] = entry
        try:
            entry['returncode'] = case.stop(child, signal.SIGINT, deadline=deadline)
            entry['stop'] = child['stops'][-1]
            require(entry['returncode'] == 0, 'tcpdump did not exit cleanly')
        except Exception as error:
            entry.update(status='tool_failure', error=str(error))
    for surface, (child, _) in captures.items():
        entry = result['captures'][surface]
        try:
            # A known capture drop still stops later live phases immediately.
            entry['counters'] = observe.capture_counters(child['log'])
        except Exception as error:
            entry.setdefault('status', 'tool_failure')
            entry.setdefault('error', str(error))
        if entry.get('status') == 'tool_failure' and result['status'] == 'passed':
            result.update(status='tool_failure', error='capture observation incomplete')
    result['capture_analysis'] = 'pending' if captures else 'not_started'


def analyze_captures(case):
    """Validate stopped files after live cleanup, retaining each phase's window."""
    for result in case.value['phases']:
        if result.get('capture_analysis') != 'pending':
            continue
        for entry in result['captures'].values():
            try:
                case.check()
                path = input_path(case.output, entry['pcap'])
                # Preserve hashes for malformed captures too; no packet data is logged.
                entry['sha256'] = file_hash(path)
                entry['summary'] = observe.capture_summary(path, entry['addresses'], entry['sample_wall_ns'])
                require('counters' in entry, 'validated capture terminal counters absent')
                require(entry['counters']['captured'] == entry['summary']['captured_packets'],
                        'pcap packet count differs from tcpdump')
                if entry.get('status') != 'tool_failure':
                    entry['analysis'] = 'passed'
            except Exception as error:
                entry.setdefault('status', 'tool_failure')
                entry.setdefault('error', str(error))
                entry['analysis_error'] = str(error)
            if entry.get('status') == 'tool_failure':
                entry['analysis'] = 'failed'
                if result['status'] == 'passed':
                    result.update(status='tool_failure', error='capture observation incomplete')
        result['capture_analysis'] = ('failed' if any(entry['analysis'] != 'passed'
                                                     for entry in result['captures'].values()) else 'passed')
        qualify_phase(result)
    case.value['data_status'] = next((result['status'] for result in case.value['phases']
                                    if result['status'] != 'passed'), 'passed')
    if case.value['status'] == 'passed' and case.value['data_status'] != 'passed':
        case.value.update(status=case.value['data_status'], error='capture observation incomplete')


def observe_mixed_drain(case, binary, secrets, cleanup_deadline):
    """Two independent, unchanged source-ledger observations after application EOF."""
    report = case.value['post_eof_mixed_sources'] = {
        'scope': 'after application EOF and capture stop, before the local disconnect requests',
        'interval_ms': 100, 'requested_cap_ms': 4000, 'outcome': 'observation_bound_exhausted', 'samples': []}
    end = min(time.monotonic() + 4, cleanup_deadline - 2, case.deadline)
    previous = None
    try:
        while time.monotonic() < end:
            pair = {}
            for side in ('a', 'b'):
                endpoint = status(case, binary, secrets, side, end)
                require_ready(endpoint, case.row)
                common = endpoint['state']['common']
                sources = common.get('striped_sources')
                if sources is None:
                    report['outcome'] = 'unavailable'
                    return
                pair[side] = {'at_ns': time.monotonic_ns(), 'epoch': common['epoch'], **sources}
            report['samples'].append(pair)
            a, b = pair['a'], pair['b']
            complete = a['epoch'] == b['epoch'] and all(
                tx['send_direction'] == rx['receive_direction'] and tx['send_stream'] == rx['receive_stream']
                and tx['send_outstanding'] == tx['send_retained'] == rx['receive_uncommitted_in_groups']
                == rx['receive_uncommitted_through_sealed'] == 0
                and tx['send_confirmed'] == rx['receive_confirmed'] == rx['receive_sealed']
                for tx, rx in ((a, b), (b, a)))
            signature = (a['epoch'], a['send_confirmed'], b['send_confirmed']) if complete else None
            if signature is not None and signature == previous:
                report['outcome'] = 'two_stable_zero_samples'
                return
            previous = signature
            time.sleep(min(.1, max(0, end - time.monotonic())))
    except Exception as error:
        report.update(outcome='observation_failed', error=str(error))


def disconnect_sessions(case, binary, secrets, deadline):
    """Keep requested local release separate from data and peer-drain qualification."""
    shutdown = {'status': 'running', 'started_wall_ns': time.time_ns(), 'endpoints': {},
                'definition': 'API4 requested local disconnect response; not a bilateral protocol drain proof',
                'submission': 'concurrent local requests; peer-close races remain failures'}
    case.value['shutdown'] = shutdown
    started = {child['label'] for child in case.children if child['label'].startswith('daemon-')}
    requests = {}
    for side in ('a', 'b'):
        endpoint = shutdown['endpoints'][side] = {'status': 'not_started'}
        if not (secrets / f'control-{side}.sock').exists():
            if 'daemon-' + side in started:
                endpoint.update(status='failed', error='started daemon control socket unavailable')
            continue
        requests[side] = case.prefix('endpoint_' + side, [binary, 'disconnect',
            '--control-socket', secrets / f'control-{side}.sock', '--api-version', '4'])

    def request(argv):
        endpoint = {'started_wall_ns': time.time_ns()}
        try:
            raw = bounded.command(argv, deadline, 3)
            values = [bounded.strict_json(line) for line in raw.splitlines() if line.startswith('{')]
            reply = values[-1] if values else {'error': 'no JSON disconnect reply'}
            state = reply.get('state') or {}
            common = state.get('common') or {}
            endpoint.update(status='passed' if reply.get('version') == 4 and reply.get('ok') is True
                            and state.get('phase') == 'disconnected' else 'failed',
                            code=reply.get('code'), phase=state.get('phase'),
                            terminal=common.get('terminal'), service_terminal=common.get('service_terminal'))
        except Exception as error:
            # Keep the actual refusal/DTO, including an already-failed peer.
            reply = {'error': str(error)}
            endpoint.update(status='failed', error_type=type(error).__name__)
        endpoint['finished_wall_ns'] = time.time_ns()
        return endpoint, reply

    if requests:
        # Submit both local requests before awaiting either completion. This
        # removes serial cleanup bias; it is not a simultaneous-acceptance or
        # bilateral-drain guarantee. Original per-command/shared caps still apply.
        results, workers = {}, []

        def collect(side, argv):
            # Each worker writes its own result only. The case receipt remains
            # coordinator-owned and is updated after all bounded workers join.
            results[side] = request(argv)

        for side, argv in requests.items():
            try:
                worker = Thread(target=collect, args=(side, argv))
                worker.start()
                workers.append(worker)
            except Exception as error:
                at = time.time_ns()
                results[side] = ({'status': 'failed', 'error_type': type(error).__name__,
                                  'started_wall_ns': at, 'finished_wall_ns': at},
                                 {'error': str(error)})
        for worker in workers:
            worker.join()
        for side, (endpoint, reply) in results.items():
            shutdown['endpoints'][side] = endpoint
            case.value['cleanup']['disconnect'][side] = reply
    outcomes = [value['status'] for value in shutdown['endpoints'].values()]
    shutdown['status'] = ('passed' if all(value == 'passed' for value in outcomes)
                          else 'not_started' if all(value == 'not_started' for value in outcomes) else 'failed')
    shutdown['finished_wall_ns'] = time.time_ns()
    if shutdown['status'] != 'passed' and case.value['status'] == 'passed':
        case.value.update(status='failed', error='requested local disconnect did not succeed for both endpoints')


def phase(case, name, binary, secrets, daemons):
    paced = getattr(case, 'paced_c48', False)
    single_flow = getattr(case, 'single_flow_4m', False)
    flow_count = getattr(case, 'flow_count', None)
    credit = getattr(case, 'outstanding_credit_bytes', single.CREDIT)
    output = case.output / name
    output.mkdir()
    result = {'phase': name, 'status': 'running', 'cpu': [], 'status_samples': [], 'captures': {}}
    case.value['phases'].append(result)
    deadline = min(case.deadline, time.monotonic() + BOUNDS['phase_seconds'])
    captures, probes = {}, []
    sample_wall = None
    try:
        if single_flow or flow_count:
            result['netem_seeds'] = {}
            for side, seed in (('a', NETEM_SEED), ('b', NETEM_SEED ^ 0x9e3779b97f4a7c15)):
                role = 'endpoint_' + side
                result['netem_seeds'][side] = json.loads(case.command(
                    role, sys.executable, ROOT / 'tools/common_native_netem_seed.py', case.spec.namespaces[role], str(seed),
                    '--loss-percent', str(LOSS_PERCENT)))
        result['qdisc_before'] = qdisc(case)
        check_forward_tun_fq(case, result['qdisc_before'])
        for side in (() if getattr(case, 'no_capture', False) else ('a', 'b')):
            for kind, interface, addresses in [('wan', 'wan0', list(WAN.values())), ('native', 'tun0', list(NATIVE.values()))]:
                label = name + '-' + side + '-' + kind
                path = output / (side + '-' + kind + '.pcap')
                ip_pair = ['ip', 'and', 'host', addresses[0], 'and', 'host', addresses[1]]
                tap = kind == 'native' and case.value['native_layer'] == 'tap'
                datalink = ['-y', 'EN10MB'] if tap else []
                capture_filter = ['arp', 'or', '(', *ip_pair, ')'] if tap else ip_pair
                args = ['tcpdump', '-Z', 'root', '--immediate-mode', '-n', '-s', str(observe.SNAPLEN), '-B', '8192', '-i', interface,
                        *datalink, '-c', str(observe.CAPTURE_PACKETS), '-w', '-', *capture_filter]
                child = case.spawn('endpoint_' + side, label, args, capture=path)
                captures[side + '_' + kind] = (child, addresses)
                case.wait_marker(child, 'listening on', deadline)
        probe = ROOT / 'tools/common_native_probe.py'
        clock = output / 'clock.json'
        deadline_ns = time.monotonic_ns() + int((deadline - time.monotonic()) * 1e9)
        for side, role, address in [('b', 'listen', NATIVE['b']), ('a', 'connect', NATIVE['b'])]:
            child = case.spawn('endpoint_' + side, name + '-probe-' + side,
                [sys.executable, str(probe), role, '--phase', name, '--address', address, '--port', '24451',
                 '--deadline-ns', str(deadline_ns), '--clock', str(clock), '--result', str(output / (side + '.json')),
                 *(['--flow-count', str(flow_count)] if flow_count else ['--single-flow-4m'] if single_flow else ['--packed-c48-workload'] if paced else []),
                 *(['--outstanding-credit-bytes', str(credit)] if single_flow or flow_count else []),
                 *(['--trace-records'] if getattr(case, 'switch_during_phase', False) else [])])
            probes.append(child)
            if role == 'listen':
                case.wait_marker(child, 'Listening', deadline)
        for child in probes:
            case.wait_marker(child, 'Connected', deadline)
        if flow_count:
            result['outer_kernel_sockets_before_workload'] = {}
            for side in ('a', 'b'):
                raw = case.command('endpoint_' + side, 'ss', '-Hnatu', deadline=deadline)
                result['outer_kernel_sockets_before_workload'][side] = [
                    line for line in raw.splitlines() if WAN[side] + ':' in line or WAN['b' if side == 'a' else 'a'] + ':' in line]
        mono_before, wall, mono_after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
        start = mono_after + 500_000_000
        window = {'start_ns': start, 'measure_start_ns': start + 2_000_000_000, 'end_ns': start + 12_000_000_000}
        result['clock_anchor'] = {'monotonic_before_ns': mono_before, 'wall_ns': wall, 'monotonic_after_ns': mono_after}
        offset = wall - (mono_before + mono_after) // 2
        sample_wall = (window['measure_start_ns'] + offset, window['end_ns'] + offset)
        atomic_json(clock, window)
        next_cpu, next_status = 0, time.monotonic() + 2
        switch_requested = getattr(case, 'switch_during_phase', False)
        while any(child['process'].poll() is None for child in probes):
            case.check(deadline)
            now = time.monotonic()
            for child in daemons.values():
                require(child['process'].poll() is None, 'Common daemon exited during native workload')
            if switch_requested and time.monotonic_ns() >= window['measure_start_ns'] + 3_000_000_000:
                switch_requested = False
                switch_hook.switch_during_phase(case, binary, secrets, deadline)
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
        result['throughput'] = compare_probes(probe_results['a'], probe_results['b'], name, paced=paced, single_flow=single_flow,
                                              flow_count=flow_count, credit=credit)
        if getattr(case, 'switch_during_phase', False):
            validate_switch_flow_delivery(case, result['throughput']['a_to_b']['per_flow'], output, window)
        if paced:
            result['after_application_eof'] = {}
            for side in ('a', 'b'):
                endpoint = status(case, binary, secrets, side, deadline)
                result['after_application_eof'][side] = {'at_ns': time.monotonic_ns(), 'endpoint': endpoint}
                require_ready(endpoint, case.row)
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
                    if paced:
                        sample['paced_records'] = observed.get('paced_records')
                    complete = sample['sample_window_completed']
                    result.setdefault('throughput_observed', {})['b_to_a' if side == 'a' else 'a_to_b'] = {
                        'receiver_unique_sample_bytes': sample['receiver_unique_sample_bytes'], 'configured_sample_seconds': 10,
                        'sample_window_completed': complete,
                        'observed_goodput_mbit_s': sample['receiver_unique_sample_bytes'] * 8 / 10_000_000 if complete else None,
                        'qualification': 'valid' if result['status'] == 'passed' else 'invalid_or_incomplete',
                        'reason': None if result['status'] == 'passed' else result.get('error', result['status'])}

                except Exception as error:
                    result['probe_results'][side] = {'status': 'tool_failure', 'error': str(error)}
        stop_captures(case, result, captures, sample_wall, cleanup_deadline)
        try:
            result['qdisc_after'] = qdisc(case)
            check_forward_tun_fq(case, result['qdisc_after'])
        except Exception as error:
            result['qdisc_error'] = str(error)
            if result['status'] == 'passed':
                result.update(status='tool_failure', error='qdisc observation incomplete')
        qualify_phase(result)
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
    spec = lab.LabSpec(args.lab_id + '-' + str(ordinal), loss_percent=LOSS_PERCENT)
    output = args.output / row['id']
    output.mkdir()
    case = Case(row, spec, output, native_tun_txqueuelen=getattr(args, 'native_tun_txqueuelen', None),
                native_forward_tun_maxrate_mbit=getattr(args, 'native_forward_tun_maxrate_mbit', None))
    case.single_flow_4m = getattr(args, 'single_flow_4m', False)
    case.flow_count = getattr(args, 'flow_count', None)
    case.outstanding_credit_bytes = getattr(args, 'outstanding_credit_bytes', single.CREDIT)
    case.no_capture = getattr(args, 'no_capture', False)
    case.switch_during_phase = getattr(args, 'switch_during_phase', False)
    case.paced_c48 = getattr(args, 'packed_c48_workload', False) or case.single_flow_4m or bool(case.flow_count)
    case.value['selected_phases'] = args.phases
    created = False
    try:
        case.value['stage'] = 'offline_preflight'
        binding = reference.validate_row(row)
        case.value['python_reference'] = binding
        for side in ('a', 'b'):
            inspection = case.command(None, *daemon_command(row, side, binary, secrets, inputs, inspection=True))
            if row.get('python_reference') is not None:
                binding['inspection'][side] = reference.validate_inspection(row, side, inspection)
        if row.get('python_reference') is not None:
            binding['status'] = 'validated_algorithm_configuration_only'
        case.save()
        case.value['stage'] = 'topology'
        topology(case, state_dir)
        created = True
        if row['carrier'] == 'raw':
            raw_rules(case)
        observe_rst = getattr(args, 'raw_rst_observation', False) and row['carrier'] == 'raw'
        if observe_rst:
            case.value['rst_rule_counters_before_transfer'] = {
                side: case.command('endpoint_' + side, 'iptables', '-w', '1', '-nvxL', 'OUTPUT', '--line-numbers')
                for side in ('a', 'b')}
            tcp_tuple = ('tcp and ((src host 192.0.2.2 and src port 24440 and dst host 192.0.2.6 '
                         'and dst port 24441) or (src host 192.0.2.6 and src port 24441 and dst host '
                         '192.0.2.2 and dst port 24440))')
            capture = case.spawn('router', 'outer-tcp-headers',
                ['tcpdump', '-Z', 'root', '--immediate-mode', '-n', '-s', '96', '-B', '16384', '-i', 'a0',
                 '-c', '500000', '-w', '-', tcp_tuple], capture=output / 'outer-tcp-headers.pcap')
            case.wait_marker(capture, 'listening on', case.deadline)
        case.value['stage'] = 'authenticated_startup'
        metrics = output / 'metrics'
        metrics.mkdir()
        daemons = {}
        for side in ('b', 'a'):
            daemons[side] = case.spawn('endpoint_' + side, 'daemon-' + side,
                daemon_command(row, side, binary, secrets, inputs), metrics=metrics / "wire")
        readiness(case, binary, secrets, daemons)
        case.value['both_forwarding_observed_wall_ns'] = time.time_ns()
        if row['carrier'] in ('raw', 'udp'):
            case.value['post_auth_socket_evidence'] = {}
            for side in ('a', 'b'):
                role = 'endpoint_' + side
                case.value['post_auth_socket_evidence'][side] = {
                    'raw_sockets': case.command(role, 'ss', '-Hawnp').splitlines(),
                    'kernel_tcp_sockets': case.command(role, 'ss', '-Hantp').splitlines(),
                    'raw_socket_table': case.command(role, 'cat', '/proc/net/raw').splitlines(),
                    'udp_sockets': case.command(role, 'ss', '-Haunp').splitlines(),
                }
            case.save()
        case.value['stage'] = 'native_workload'
        for name in args.phases:
            if not phase(case, name, binary, secrets, daemons):
                # A failed connection is not restarted to manufacture later phases.
                break
        if observe_rst:
            case.value['rst_rule_counters_after_transfer'] = {
                side: case.command('endpoint_' + side, 'iptables', '-w', '1', '-nvxL', 'OUTPUT', '--line-numbers')
                for side in ('a', 'b')}
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
        if case.single_flow_4m and case.row.get('algorithm') == 'striped' and case.value['status'] == 'passed':
            observe_mixed_drain(case, binary, secrets, cleanup_deadline)
        disconnect_sessions(case, binary, secrets, cleanup_deadline)
        if (output / 'metrics').is_dir():
            publication_deadline = min(cleanup_deadline, time.monotonic() + 2)
            while len(list((output / 'metrics').glob('wire.*.json'))) < 2 and time.monotonic() < publication_deadline:
                time.sleep(.02)
        for child in reversed(case.children):
            try:
                code = case.stop(child, signal.SIGINT if child.get('capture') else signal.SIGTERM, deadline=cleanup_deadline)
                case.value['cleanup']['children'].append({'label': child['label'], 'returncode': code,
                                                        'stops': child.get('stops', [])})
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
        # No owned process or namespace is held for offline packet parsing/hash I/O.
        # A malformed file discovered here may invalidate an earlier phase, but
        # never restarts it or suppresses independently completed later evidence.
        analyze_captures(case)
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
    parser.add_argument('--native-tun-txqueuelen', type=int, metavar='PACKETS',
                        help=f'Set transmit queue length on both owned tun0 interfaces (1..{MAX_TUN_TXQUEUELEN} packets); default uses the system setting')
    parser.add_argument('--native-forward-tun-maxrate-mbit', type=int, metavar='MBIT',
                        help=f'Set root fq per-flow maxrate on owned endpoint_a/tun0 (1..{MAX_FORWARD_TUN_MBIT} Mbit/s)')
    parser.add_argument('--parallel-lane', choices=('udp', 'raw', 'tls', 'quic'),
                        help='Explicit concurrent carrier lane; fixed eight-CPU affinity and distinct owned lab prefix required')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--no-capture', action='store_true', help='Retain daemon, endpoint TCP and qdisc counters without tcpdump')
    parser.add_argument('--switch-during-phase', action='store_true', help='Request authenticated API4 switch three seconds into the sample')
    parser.add_argument('--netem-seed', type=int, default=31248,
                        help='Endpoint A netem seed for paced/flow-count phases; B uses seed XOR 0x9e3779b97f4a7c15')
    parser.add_argument('--loss-percent', type=int, default=15, help='Independent random loss per direction (0..100)')
    parser.add_argument('--raw-rst-observation', action='store_true',
                        help='Raw rows: record RST-rule counters around the transfer and capture outer TCP headers at the router')
    workload = parser.add_mutually_exclusive_group()
    workload.add_argument('--packed-c48-workload', action='store_true',
                        help='Offer 512-byte timestamped application records at aggregate 76 Mbit/s on 16 CUBIC flows')
    workload.add_argument('--single-flow-4m', action='store_true',
                          help='Offer 90 Mbit/s on one CUBIC socket with 4 MiB (or --outstanding-credit-bytes) outstanding application payload and fixed directional netem seeds')
    workload.add_argument('--flow-count', type=int, choices=(1, 4, 16),
                          help='Split 90 Mbit/s offer and 4 MiB (or --outstanding-credit-bytes) unconfirmed application credit equally across these CUBIC sockets')
    parser.add_argument('--outstanding-credit-bytes', type=int, default=single.CREDIT,
                        help='Total unconfirmed application payload credit for --single-flow-4m/--flow-count (default 4 MiB)')
    parser.add_argument('--require-python-comparable', action='store_true',
                        help='Reject unbound or non-equivalent Python comparisons before network I/O; current named diagnostic profiles retain explicit differences')
    args = parser.parse_args(argv)
    global NETEM_SEED, LOSS_PERCENT
    if not 0 < args.netem_seed < 2**64:
        parser.error('--netem-seed must be within 1..2**64-1')
    if not 0 <= args.loss_percent <= 100:
        parser.error('--loss-percent must be within 0..100')
    NETEM_SEED, LOSS_PERCENT = args.netem_seed, args.loss_percent
    if args.native_tun_txqueuelen is not None and not 1 <= args.native_tun_txqueuelen <= MAX_TUN_TXQUEUELEN:
        parser.error(f'--native-tun-txqueuelen must be within 1..{MAX_TUN_TXQUEUELEN} packets')
    if args.native_forward_tun_maxrate_mbit is not None and not 1 <= args.native_forward_tun_maxrate_mbit <= MAX_FORWARD_TUN_MBIT:
        parser.error(f'--native-forward-tun-maxrate-mbit must be within 1..{MAX_FORWARD_TUN_MBIT} Mbit/s')
    args.phases = list(dict.fromkeys(args.phase or PHASES))
    require(not (args.packed_c48_workload or args.single_flow_4m or args.flow_count) or args.phases == ['forward'], 'paced TCP probe requires --phase forward')
    require(not args.switch_during_phase or args.flow_count, 'switch study requires explicit --flow-count')
    credit_problem = single.credit_error(args.outstanding_credit_bytes, args.flow_count or 1)
    if credit_problem:
        parser.error(credit_problem)
    require(re.fullmatch('[a-z][a-z0-9-]{0,14}', args.lab_id), 'lab prefix must fit owned namespace names')
    args.manifest, args.binary, args.output = (path.absolute() for path in (args.manifest, args.binary, args.output))
    document, rows = manifest_rows(args.manifest, set(args.case),
                                   require_python_comparable=args.require_python_comparable)
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
            'requested_native_tun_txqueuelen': args.native_tun_txqueuelen,
            'requested_native_forward_tun_maxrate_mbit': args.native_forward_tun_maxrate_mbit,
            'binary': str(args.binary), 'rows': rows, 'bounds': BOUNDS, 'phases': args.phases,
            'native_layers': {row['id']: native_layer(row) for row in rows if row['status'] == 'ready'},
            'flows_per_phase': 16, 'warmup_seconds': 2, 'sample_seconds': 10,
            'workload': 'paced 512-byte TCP application records, 76 Mbit/s aggregate' if args.packed_c48_workload else 'saturating native TCP',
            'network': {'forward_mbit_s': 100, 'reverse_mbit_s': 10, 'one_way_delay_ms': 35, 'loss_percent_each_direction': LOSS_PERCENT},
            'raw_rst_observation': args.raw_rst_observation,
            'captures': 'each endpoint WAN and native, both directions, full packets; native TAP also captures ARP separately from IPv4 byte totals',
            'measurement': 'application recv goodput; captured IPv4 byte totals and packet-size distributions; no p99-overhead inference',
            'parallel_lane': args.parallel_lane, 'cpu_affinity': affinity,
            'require_python_comparable': args.require_python_comparable,
            'comparison_scope': 'Native component measurements; named algorithm bindings retain explicit differences and do not imply exact Python/native equivalence',
            'execution': 'one expensive case per explicit carrier lane; lanes share host memory, I/O and kernel; no automatic retries or cap relaxation; dry run creates no namespace'}
    if args.single_flow_4m:
        plan.update(flows_per_phase=1, workload='one CUBIC socket, 512-byte timestamped records at 90 Mbit/s',
                    outstanding_application_credit_bytes=args.outstanding_credit_bytes, transfer_cap_bytes=single.TRANSFER_CAP,
                    socket_buffer_before_syn_bytes=single.SOCKET_BUFFER,
                    netem_seeds={'a': NETEM_SEED, 'b': NETEM_SEED ^ 0x9e3779b97f4a7c15})
    if args.flow_count:
        plan.update(flows_per_phase=args.flow_count, workload='512-byte timestamped records, 90 Mbit/s aggregate, equally divided over CUBIC connections',
                    outstanding_application_credit_bytes=args.outstanding_credit_bytes,
                    per_flow_credit_bytes=args.outstanding_credit_bytes // args.flow_count,
                    switch_during_phase=args.switch_during_phase, transfer_cap_bytes_per_flow=single.TRANSFER_CAP,
                    socket_buffer_before_syn_bytes=single.SOCKET_BUFFER,
                    netem_seeds={'a': NETEM_SEED, 'b': NETEM_SEED ^ 0x9e3779b97f4a7c15})
    if args.no_capture:
        plan['captures'] = 'disabled; application and endpoint TCP/daemon counters retained, no packet capture'
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
                [Path(__file__).resolve(), ROOT / 'tools/common_native_probe.py', ROOT / 'tools/common_native_c48.py', ROOT / 'tools/common_native_observe.py',
                 ROOT / 'tools/common_native_single_flow.py', ROOT / 'tools/common_native_netem_seed.py',
                 ROOT / 'tools/common_python_reference.py', ROOT / 'tools/common_python_references.json',
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
            credential_case = Case(None, lab.LabSpec(args.lab_id), args.output)
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
