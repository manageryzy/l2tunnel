#!/usr/bin/env python3
"""Source-pinned same-socket secure UDP TAP lab; dry-run unless --apply is explicit."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

try:
    from . import netns_lab as lab, proxy_native_smoke as bounded
    from . import native_throughput as accounting, secure_udp_native_probe as probe
except ImportError:
    import netns_lab as lab
    import proxy_native_smoke as bounded
    import native_throughput as accounting
    import secure_udp_native_probe as probe

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ('secure_udp_native.py', 'secure_udp_native_probe.py', 'netns_lab.py',
    'proxy_native_smoke.py', 'native_throughput.py', 'proxy_measured_native_smoke.py', 'throughput_probe.py')
PATHS = {'clean': (1, 0), 'delay': (35, 0), 'loss1': (35, 1), 'impaired': (35, 15)}
WAN = {'a': '192.0.2.2', 'b': '192.0.2.6'}
HOST = {'a': '198.18.0.1', 'b': '198.18.0.2'}
BOUNDS = {'case': 240, 'cleanup': 30, 'launcher': 300, 'startup': 35,
    'command': 15, 'capture_packets': 1_000_000, 'capture_bytes': 256 * 1024 * 1024,
    'capture_snaplen': 160, 'status_samples': 96, 'log_bytes': 4 * 1024 * 1024}
INITIAL = {'path_mtu': 1500, 'forward_kbit': 99_000, 'reverse_kbit': 9_900,
           'channels': 16, 'window': 64, 'repair_permille': 0}
RUNTIME_MODELS = ('multi-thread', 'current-thread')
RUNTIME_THREAD_LIMIT = 2048
POLICY_FIELDS = set(INITIAL)
STATUS_FIELDS = set(('generation carrier algorithm protection requested effective maximum_path_mtu running '
    'session transcript configuration outer member initiator_noise responder_noise local peer policy_epoch '
    'pending_epoch elapsed_micros wire_packets wire_bytes socket_accepted_packets socket_accepted_ip_bytes '
    'socket_drops socket_receive_errors received_packets rejected_packets replay_rejections native_read '
    'native_written native_oversize native_backpressure_drops native_pending_packets native_pending_bytes '
    'swift_unconfirmed user_number control_number user_generation control_generation terminal policy_change '
    'control_send_records control_send_bytes control_receive_records control_receive_bytes '
    'ping ping_deadline_micros last_verified_micros last_pong_micros '
    'reconnect retained_state_recovery cross_profile_switching fresh_rekey').split())
LOADED_HELPERS = {'secure_udp_native.py': Path(__file__), 'secure_udp_native_probe.py': Path(probe.__file__),
    'netns_lab.py': Path(lab.__file__), 'proxy_native_smoke.py': Path(bounded.__file__),
    'native_throughput.py': Path(accounting.__file__), 'proxy_measured_native_smoke.py': Path(accounting.measured.__file__),
    'throughput_probe.py': Path(probe.reference.__file__)}


class ObservationError(RuntimeError):
    """A tool/format cannot establish the requested observation."""


class BoundExhausted(TimeoutError):
    """An explicit resource or time bound was exhausted."""


def failure_status(error: Exception) -> str:
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return 'bound_exhausted'
    if isinstance(error, (OSError, ObservationError, accounting.ToolObservationError)):
        return 'tool_failure'
    return 'failed'


def _runtime_environment(runtime_model: str | None) -> dict | None:
    if runtime_model is None:
        return None
    if type(runtime_model) is not str or runtime_model not in RUNTIME_MODELS:
        raise ValueError('explicit supported host runtime model required')
    if os.environ.get('TOKIO_WORKER_THREADS') is not None:
        raise ValueError('explicit runtime experiment refuses inherited TOKIO_WORKER_THREADS')
    return {'TOKIO_WORKER_THREADS': None}


def _runtime_experiment(case: dict) -> bool:
    environment = _runtime_environment(case.get('runtime_model'))
    if environment is not None and case.get('runtime_environment') != environment:
        raise ValueError('explicit runtime experiment environment provenance differs')
    return environment is not None


def plan(lab_id: str, cover: str, path: str, workload: str, runtime_model: str | None = None) -> dict:
    environment = _runtime_environment(runtime_model)
    spec = lab.LabSpec(lab_id)
    if cover not in ('quic-like', 'media-like') or path not in PATHS or workload not in ('forward16', 'reverse-stress'):
        raise ValueError('explicit supported cover/path/workload required')
    delay, loss = PATHS[path]
    result = {'lab_id': lab_id, 'cover': cover, 'path': path, 'workload': workload,
        'namespaces': spec.namespaces, 'layer': 'tap', 'algorithm': 'swift', 'protection': 'chacha20-poly1305',
        'noise_profile': 'ik', 'udp_pair': [WAN['a'] + ':24440', WAN['b'] + ':24440'],
        'path_mtu': 1500, 'maximum_path_mtu': 9000, 'max_native': 1600,
        'initial_policy': dict(INITIAL), 'flows': 16, 'shared_htb_mbps': {'a_to_b': 100, 'b_to_a': 10},
        'one_way_delay_ms': delay, 'loss_percent_per_direction': loss,
        'inner_tcp': 'CUBIC', 'inner_rto_min_ms': 1000, 'warmup_seconds': 5, 'measurement_seconds': 20,
        'max_bytes_per_direction_flow': 256 * 1024 * 1024, 'probe_original_seconds': probe.ORIGINAL_SECONDS,
        'forward_lab_target_mbps': 80, 'target_provenance': 'existing FIX-04 native forward target; not a new owner decision',
        'reverse_bulk': workload == 'reverse-stress', 'bounds': dict(BOUNDS),
        'fresh_outer_namespaces': ['user', 'net', 'mnt'], 'capture': 'all IP and ARP, bounded header snapshots',
        'initial_topology_commands': lab.plan_document(spec)['commands'],
        'not_qualified': ['ISP/QoS classification', 'protocol interoperability/identification resistance',
            'Windows/Android', 'automatic retained-state recovery', 'full SW-11', 'OpenVPN/raw HTTPS']}
    if environment is not None:
        result.update(runtime_model=runtime_model, runtime_environment=environment)
    return result


def verify_helpers(build: dict, directory: Path, loaded: bool = False) -> dict:
    result = {}
    for name in HELPERS:
        path = directory / name
        expected = build.get('source_sha256_after', {}).get('tools/' + name)
        if (path.is_symlink() or not path.is_file() or not isinstance(expected, str)
                or bounded.file_hash(path) != expected
                or loaded and LOADED_HELPERS[name].resolve() != path.resolve()):
            raise ValueError('copied/executed helper differs from exact build: ' + name)
        result['tools/' + name] = expected
    return result


def namespace_ids() -> dict:
    return {name: {'device': os.stat('/proc/self/ns/' + name).st_dev,
                   'inode': os.stat('/proc/self/ns/' + name).st_ino} for name in ('user', 'net', 'mnt')}


def verify_fresh_namespace(descriptors: dict[str, int], original: dict, current: dict) -> None:
    if set(descriptors) != {'user', 'net', 'mnt'} or set(current) != set(descriptors):
        raise ValueError('three anchored namespace identities required')
    for name, descriptor in descriptors.items():
        info = os.fstat(descriptor)
        expected = {'device': info.st_dev, 'inode': info.st_ino}
        if (original.get(name) != expected or current[name] == expected
                or not re.fullmatch(name + r':\[\d+\]', os.readlink(f'/proc/self/fd/{descriptor}'))):
            raise ValueError('fresh isolated namespace proof failed: ' + name)


def daemon_command(case: dict, side: str, binary: Path, secrets: Path) -> list[str]:
    explicit_runtime = _runtime_experiment(case)
    if side not in ('a', 'b'):
        raise ValueError('explicit endpoint side required')
    other = 'b' if side == 'a' else 'a'
    argv = [str(binary), 'connect' if side == 'a' else 'serve', '--carrier', case['cover'],
        '--record-profile', 'swift', '--duplex', 'full', '--compression', 'off', '--layer', 'tap',
        '--device', 'tap0', '--max-packet', str(case['max_native']), '--path-mtu', '1500', '--max-path-mtu', '9000',
        '--udp-bind', WAN[side] + ':24440', '--udp-peer', WAN[other] + ':24440', '--noise-profile', 'ik',
        '--noise-private-key-file', str(secrets / f'noise-{side}.key'),
        '--noise-peer-key-file', str(secrets / f'noise-{other}.pub'),
        '--session-admission-key-file', str(secrets / 'admission.key'), '--swift-forward-kbit', '99000',
        '--swift-reverse-kbit', '9900', '--swift-channels', '16', '--swift-window', '64',
        '--swift-repair-permille', '0', '--swift-report-ms', '1000',
        '--control-socket', str(secrets / f'control-{side}.sock')]
    argv += (['--identity', str(secrets / 'member.der')] if side == 'a' else
             ['--allow-key', str(secrets / 'member.pub'), '--session-cookie-key-file', str(secrets / 'cookie.key')])
    if explicit_runtime:
        argv += ['--runtime-model', case['runtime_model']]
    return argv


def credentials(binary: Path, directory: Path, deadline: float) -> dict:
    # Crypto remains in the maintained public API; these are fresh lab inputs.
    import cryptography
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    if (not re.fullmatch(r'\d+(\.\d+){1,3}', cryptography.__version__)
            or not callable(X25519PrivateKey.generate) or Encoding.Raw is None or PrivateFormat.Raw is None or PublicFormat.Raw is None):
        raise ObservationError('reviewed cryptography X25519 Raw API version preflight failed')
    public = {}
    for side in ('a', 'b'):
        key = X25519PrivateKey.generate()
        private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pin = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        for suffix, content in [('key', private), ('pub', pin)]:
            descriptor = os.open(directory / f'noise-{side}.{suffix}', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(content)
        public[side] = list(pin)
    for name in ('admission.key', 'cookie.key'):
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(os.urandom(32))
    bounded.command([str(binary), 'keygen', '--private', str(directory / 'member.der'),
                     '--public', str(directory / 'member.pub')], deadline)
    for path in directory.iterdir():
        path.chmod(0o600)
    member = (directory / 'member.pub').read_bytes()
    if len(member) != 32:
        raise ObservationError('existing binary member keygen did not produce raw32 public key')
    return {'x25519_library': 'cryptography', 'cryptography_version': cryptography.__version__,
        'x25519_api': 'X25519PrivateKey.generate/public Raw serialization',
        'python': sys.executable, 'python_version': sys.version,
        'member_api': 'immutable binary keygen; ring PKCS8', 'noise_public': public, 'member_public': list(member),
        'private_material': 'fresh temporary owner-only files; bytes excluded from receipt'}


def last_json(path: Path) -> dict:
    text = bounded.read_log(path)
    for line in reversed(text.splitlines()):
        if line.startswith('{'):
            value = bounded.strict_json(line)
            if isinstance(value, dict):
                return value
    raise ObservationError('no bounded JSON result: ' + str(path))


def ready_event(path: Path) -> dict:
    for line in bounded.read_log(path).splitlines():
        if line.startswith('{'):
            value = bounded.strict_json(line)
            if isinstance(value, dict) and value.get('event') == 'secure_udp_ready':
                return value
    raise ObservationError('no bounded secure UDP ready event: ' + str(path))


def host_runtime_event(path: Path, requested: str) -> dict:
    if type(requested) is not str or requested not in RUNTIME_MODELS:
        raise ValueError('explicit supported host runtime model required')
    found = None
    fields = {'event', 'schema', 'requested', 'effective', 'worker_threads'}
    for line in bounded.read_log(path).splitlines():
        if not line.startswith('{'):
            continue
        value = bounded.strict_json(line)
        if not isinstance(value, dict) or value.get('event') != 'host_runtime':
            continue
        if found is not None:
            raise ObservationError('duplicate bounded host runtime startup event')
        if (set(value) != fields or type(value['schema']) is not int or value['schema'] != 1
                or value['requested'] != requested or value['effective'] != requested
                or type(value['worker_threads']) is not int
                or not 1 <= value['worker_threads'] <= RUNTIME_THREAD_LIMIT
                or requested == 'current-thread' and value['worker_threads'] != 1):
            raise ObservationError('host runtime startup event model/schema/worker count mismatch')
        found = value
    if found is None:
        raise ObservationError('no bounded host runtime startup event: ' + str(path))
    return found


def record_functional(receipt, field, operation, observe_status, deadline):
    """Retain live-owner diagnostics without replacing the original probe error."""
    try:
        receipt.update(**{field: operation()})
    except Exception:
        observations = {}
        for side in ('a', 'b'):
            row = {'at_monotonic_ns': time.monotonic_ns()}
            try:
                if time.monotonic() >= deadline:
                    raise BoundExhausted('original case deadline exhausted before failure status')
                response = observe_status(side)
                if len(json.dumps(response).encode()) > 64 * 1024:
                    raise ObservationError('failure status response exceeds64KiB bound')
                row.update(status='observed', response=response)
            except Exception as error:
                row.update(status=failure_status(error), error=f'{type(error).__name__}: {error}'[:4096])
            observations[side] = row
        try:
            receipt.update(functional_failure={'phase': field, 'peers': observations})
        except Exception as error:
            print(('functional failure evidence publication failed: ' + f'{type(error).__name__}: {error}')[:4096],
                  file=sys.stderr)
        raise


def functional(label, output, deadline, launch, command, receipt):
    result = {}
    for side, other in [('a', 'b'), ('b', 'a')]:
        ready = output / f'{label}-udp-{other}.ready'
        child, log = launch('host_' + other, [sys.executable, output / 'secure_udp_native_probe.py',
            'udp-echo', '--address', HOST[other], '--port', '24461', '--ready', ready], f'{label}-echo-{other}')
        try:
            until = min(deadline, time.monotonic() + 5)
            while not ready.exists():
                if child.poll() is not None or time.monotonic() >= until:
                    raise BoundExhausted('native UDP echo readiness bound')
                time.sleep(.02)
            # Keep one original12s ICMP bound including subprocess startup.
            # The echo owner still covers readiness<=5s + ICMP<=12s + UDP<=17s.
            ping_end = min(int(deadline * 1e9), time.monotonic_ns() + 12_000_000_000)
            ping_child, ping_log = launch('host_' + side,
                [sys.executable, output / 'secure_udp_native_probe.py', 'icmp-probe', '--source', HOST[side],
                 '--address', HOST[other], '--deadline-ns', str(ping_end)], f'{label}-icmp-{side}', cap=64 * 1024)
            wait_error, stop_error = None, None
            try:
                ping_child.wait(timeout=bounded.remaining(ping_end / 1e9, 12))
            except Exception as error:
                wait_error = error
                try:
                    bounded.stop(ping_child)
                except Exception as cleanup_error:
                    stop_error = f'{type(cleanup_error).__name__}: {cleanup_error}'[:4096]
            ping = bounded.read_log(ping_log)
            if len(ping.encode()) > 64 * 1024:
                raise ObservationError('native ping output exceeds64KiB bound')
            result[side] = {'full_mtu_df_ping': ping}
            if stop_error:
                result[side]['icmp_cleanup_error'] = stop_error
            receipt.update(**{label + '_functional_progress': result})
            if wait_error:
                raise wait_error
            icmp = last_json(ping_log)
            result[side]['icmp'] = icmp
            receipt.update(**{label + '_functional_progress': result})
            if icmp.get('status') == 'bound_exhausted':
                raise BoundExhausted('exact full-MTU ICMP probe exhausted its original bound')
            if icmp.get('status') == 'tool_failure':
                raise ObservationError('exact full-MTU ICMP tool failure: ' + str(icmp.get('error', 'unknown'))[:4096])
            if (ping_child.returncode or icmp.get('status') != 'passed' or icmp.get('sent') != 3
                    or icmp.get('received_unique') != 3 or icmp.get('request_count') != 3
                    or icmp.get('payload_bytes') != 1472 or icmp.get('ip_bytes') != 1500 or icmp.get('df') is not True
                    or icmp.get('source') != HOST[side] or icmp.get('address') != HOST[other]
                    or icmp.get('original_deadline_ns') != ping_end
                    or [row.get('sequence') for row in icmp.get('rows', [])] != [1, 2, 3]
                    or any(type(row.get('sent_ns')) is not int or type(row.get('received_ns')) is not int
                        or not row['sent_ns'] <= row['received_ns'] < ping_end for row in icmp['rows'])):
                raise ValueError('full-MTU DF native ping did not return exactly')
            raw = command('host_' + side, sys.executable, str(output / 'secure_udp_native_probe.py'),
                'udp-probe', '--address', HOST[other], '--port', '24461', cap=17)
            udp = bounded.strict_json(raw.strip().splitlines()[-1])
            result[side]['udp'] = udp
            receipt.update(**{label + '_functional_progress': result})
            if udp.get('status') != 'passed' or len(udp.get('rows', [])) != 14 or not all(row['answered'] for row in udp['rows']):
                raise ValueError('exact native UDP zero/trailing-zero probe failed')
        finally:
            bounded.stop(child)
    return result


def validate_status(response: dict, case: dict, side: str, public: dict, expected_policy: dict | None = None) -> dict:
    if (set(response) != {'version', 'ok', 'code', 'state'} or type(response['version']) is not int
            or response['version'] != 2 or response['ok'] is not True or response['code'] != 'ok'):
        raise ValueError('successful explicit API-version2 response required')
    status = (response.get('state') or {}).get('secure_udp')
    if not isinstance(status, dict) or set(status) != STATUS_FIELDS:
        raise ObservationError('source-pinned secure UDP status schema changed')
    expected = {'carrier': case['cover'], 'algorithm': 'swift', 'protection': 'chacha20-poly1305',
        'running': True, 'local': WAN[side] + ':24440', 'peer': WAN['b' if side == 'a' else 'a'] + ':24440',
        'member': public['member_public'], 'initiator_noise': public['noise_public']['a'],
        'responder_noise': public['noise_public']['b'], 'policy_change': True, 'reconnect': True,
        'retained_state_recovery': False, 'cross_profile_switching': False, 'fresh_rekey': False, 'terminal': None,
        'requested': case['initial_policy'], 'maximum_path_mtu': case['maximum_path_mtu']}
    for name, value in expected.items():
        if type(status[name]) is not type(value) or status[name] != value:
            raise ValueError('actual secure UDP status mismatch: ' + name)
    for field, length in [('session', 16), ('transcript', 32), ('configuration', 32), ('outer', 32)]:
        values = status[field]
        if not isinstance(values, list) or len(values) != length or any(type(v) is not int or not 0 <= v <= 255 for v in values) or not any(values):
            raise ValueError('invalid actual authenticated binding: ' + field)
    for name in ('requested', 'effective'):
        values = status[name]
        if not isinstance(values, dict) or set(values) != POLICY_FIELDS or any(type(v) is not int or v < 0 for v in values.values()):
            raise ValueError('invalid observable complete policy')
    if expected_policy is not None and status['effective'] != expected_policy:
        raise ValueError('effective policy did not reach committed requested values')
    for name in ('generation', 'policy_epoch', 'elapsed_micros', 'wire_packets', 'wire_bytes', 'native_read', 'native_written'):
        if type(status[name]) is not int or status[name] < 0:
            raise ValueError('invalid actual runtime counter: ' + name)
    if status['generation'] == 0:
        raise ValueError('actual generation must be nonzero')
    return status


def compare_probes(client: dict, server: dict, workload: str, flows: int = 16) -> dict:
    if client.get('clock') != server.get('clock') or len(client.get('flows', [])) != flows or len(server.get('flows', [])) != flows:
        raise ValueError('actual probe flow count/common clock mismatch')
    if client.get('send_enabled') is not True or server.get('send_enabled') is not (workload == 'reverse-stress'):
        raise ValueError('matched ACK-return workload silently changed')
    seconds = (client['clock']['end_ns'] - client['clock']['measure_start_ns']) / 1e9
    if seconds <= 0:
        raise ValueError('nonpositive actual measurement interval')
    exhausted = any(row['bound_exhausted'] for value in (client, server) for row in value['flows'])
    directions = {}
    for label, sender, receiver in [('a_to_b', client, server), ('b_to_a', server, client)]:
        peers = {(tuple(row['peer']), tuple(row['local'])): row for row in receiver['flows']}
        sent_keys = {(tuple(row['local']), tuple(row['peer'])) for row in sender['flows']}
        if len(peers) != flows or len(sent_keys) != flows:
            raise ValueError('duplicate socket flow identities')
        for row in sender['flows']:
            delivered = peers.get((tuple(row['local']), tuple(row['peer'])))
            if (delivered is None or not row['write_closed'] or not delivered['eof']
                    or row['sent'] != delivered['received'] or row['sent_sha256'] != delivered['received_sha256']
                    or delivered['received'] != sum(delivered[name] for name in ('warmup', 'measured', 'postwindow'))):
                raise ValueError('exact native socket count/hash/EOF mismatch')
        unique = sum(row['measured'] for row in receiver['flows'])
        if label == 'a_to_b' and unique <= 0 and not exhausted:
            raise ValueError('no real forward measurement bytes')
        if label == 'b_to_a' and workload == 'forward16' and any(row['sent'] for row in sender['flows']):
            raise ValueError('reverse bulk appeared in ACK-return-only reference')
        directions[label] = {'receiver_unique_bytes': unique, 'goodput_mbps': unique * 8 / seconds / 1e6,
            'postwindow_drain_bytes': sum(row['postwindow'] for row in receiver['flows']),
            'total_exact_bytes': sum(row['received'] for row in receiver['flows'])}
    return {'status': 'bound_exhausted' if exhausted else 'passed', 'hashes_and_eof': 'passed',
        'measurement_seconds': seconds, 'directions': directions,
        'performance_acceptance': {'minimum_forward_mbps': 80, 'provenance': 'existing FIX-04 lab target',
            'status': 'not_applicable_reverse_stress' if workload == 'reverse-stress' else
                'unqualified' if exhausted else 'passed' if directions['a_to_b']['goodput_mbps'] >= 80 else 'failed'}}


def clock_anchor() -> dict:
    before = time.monotonic_ns()
    real = time.time_ns()
    after = time.monotonic_ns()
    return {'monotonic_low_ns': before, 'realtime_ns': real, 'monotonic_high_ns': after,
            'offset_ns': real - (before + after) // 2, 'uncertainty_ns': (after - before + 1) // 2}


PROC_BYTES = 16_384


def bounded_proc_text(path: Path) -> str:
    with path.open('rb') as stream:
        value = stream.read(PROC_BYTES + 1)
    if len(value) > PROC_BYTES:
        raise ObservationError('owned process observation exceeds fixed byte limit')
    return value.decode('utf-8', errors='strict')


def daemon_stat(raw: str, pid: int) -> dict:
    # comm may contain spaces and closing parentheses. Linux's remaining stat
    # fields are whitespace-separated; the final ") " terminates that name.
    if len(raw.encode('utf-8')) > PROC_BYTES or type(pid) is not int or pid <= 0:
        raise ObservationError('invalid owned process stat extent/identity')
    prefix, separator, remainder = raw.rpartition(') ')
    fields = remainder.split()
    if not separator or not prefix.startswith(str(pid) + ' (') or len(fields) < 22:
        raise ObservationError('malformed or different owned process stat')
    if fields[0] not in ('R', 'S', 'D', 'T', 't', 'I', 'P'):
        raise ObservationError('owned daemon no longer has a live process state')
    try:
        values = [int(fields[index]) for index in (11, 12, 19, 20, 21)]
    except ValueError as error:
        raise ObservationError('nonnumeric owned process CPU/memory fields') from error
    if any(value < 0 or value > (1 << 64) - 1 for value in values) or values[2] == 0:
        raise ObservationError('invalid owned process CPU/memory counters')
    return dict(zip(('user_ticks', 'system_ticks', 'starttime_ticks', 'virtual_bytes', 'resident_pages'), values))


def daemon_memory(raw: str, pid: int, *, include_threads: bool = False) -> dict:
    if len(raw.encode('utf-8')) > PROC_BYTES:
        raise ObservationError('owned process status exceeds fixed byte limit')
    fields = {}
    for name, expression in [('Pid', r'Pid:\s+(\d+)'), ('Tgid', r'Tgid:\s+(\d+)'),
            ('rss_kib', r'VmRSS:\s+(\d+) kB'), ('high_water_kib', r'VmHWM:\s+(\d+) kB')]:
        values = re.findall('^' + expression + '$', raw, re.MULTILINE)
        if len(values) != 1 or int(values[0]) > (1 << 64) - 1:
            raise ObservationError('missing/duplicate/invalid owned process memory field: ' + name)
        fields[name] = int(values[0])
    if fields.pop('Pid') != pid or fields.pop('Tgid') != pid or fields['high_water_kib'] < fields['rss_kib']:
        raise ObservationError('owned process status identity/memory mismatch')
    if include_threads:
        values = re.findall(r'^Threads:\s+(\d+)$', raw, re.MULTILINE)
        if len(values) != 1 or len(values[0]) > 4 or not 1 <= int(values[0]) <= RUNTIME_THREAD_LIMIT:
            raise ObservationError('missing/duplicate/invalid owned process Threads field')
        fields['threads'] = int(values[0])
    return fields


def daemon_resources(child: subprocess.Popen, starttime: int | None = None, *, include_threads: bool = False) -> dict:
    if child.poll() is not None:
        raise ObservationError('launched daemon exited before resource observation')
    base = Path('/proc') / str(child.pid)
    before = daemon_stat(bounded_proc_text(base / 'stat'), child.pid)
    memory = daemon_memory(bounded_proc_text(base / 'status'), child.pid, include_threads=include_threads)
    after = daemon_stat(bounded_proc_text(base / 'stat'), child.pid)
    if (child.poll() is not None or before['starttime_ticks'] != after['starttime_ticks']
            or starttime is not None and after['starttime_ticks'] != starttime
            or any(after[field] < before[field] for field in ('user_ticks', 'system_ticks'))):
        raise ObservationError('launched daemon exited/reused identity during resource observation')
    return {'pid': child.pid, 'sample_monotonic_ns': time.monotonic_ns(), **after, **memory}


def resource_context() -> dict:
    ticks, page_bytes = os.sysconf('SC_CLK_TCK'), os.sysconf('SC_PAGE_SIZE')
    if type(ticks) is not int or not 1 <= ticks <= 1_000_000 or type(page_bytes) is not int or page_bytes <= 0:
        raise ObservationError('unsupported process CPU tick/page units')
    return {'daemon_cpu_clock_ticks_per_second': ticks, 'resident_page_bytes': page_bytes,
        'memory_units': 'VmRSS/VmHWM KiB from owned process status; stat virtual_bytes and resident_pages retained',
        'daemon_cpu_measurement': 'delta(user_ticks+system_ticks)/clock_ticks per endpoint process; exclude probe usage',
        'probe_cpu_measurement': 'separate per-probe getrusage samples; not tunnel daemon CPU',
        'host': {'logical_cpus': os.cpu_count(), 'allowed_cpu_count': len(os.sched_getaffinity(0)),
            'machine': os.uname().machine, 'kernel_release': os.uname().release, 'loadavg': list(os.getloadavg()),
            'scope': 'shared host CPUs; namespaces do not isolate or reserve CPU'}}


def covered_payload(body: bytes, complete_bytes: int, appearance: str) -> tuple[str, bytes, int]:
    """Parse only captured cover headers against the complete original UDP length."""
    if appearance == 'quic-like':
        if body[:1] == b'\xc3':
            if len(body) < 30 or body[1:6] != b'\0\0\0\1\x08' or body[14] != 8 or body[23] != 0:
                raise ValueError('QUIC-like handshake header mismatch')
            width = 1 << (body[24] >> 6)
            if width not in (1, 2):
                raise ValueError('unsupported QUIC-like Initial length width')
            declared = int.from_bytes(body[24:24 + width], 'big') & ((1 << (width * 8 - 2)) - 1)
            if (declared < 5 or width == 2 and declared < 64 or declared != complete_bytes - 24 - width):
                raise ValueError('QUIC-like Initial declared/noncanonical length mismatch')
            header, phase = 28 + width, 'handshake'
        elif body[:1] == b'\x43' and len(body) >= 14:
            header, phase = 13, 'established'
        else:
            raise ValueError('unexpected QUIC-like outer layout')
    elif appearance == 'media-like':
        if len(body) < 15 or body[0] != 0x80 or body[1] & 0x7f != 96:
            raise ValueError('RTP-like media header mismatch')
        header, phase = 14, 'handshake' if body[1] & 0x80 else 'established'
        if int.from_bytes(body[12:14], 'big') != complete_bytes - header:
            raise ValueError('media protected-body declared length mismatch')
    else:
        raise ValueError('unsupported selected appearance')
    if complete_bytes <= header:
        raise ValueError('missing protected cover body')
    return phase, body[header:], complete_bytes - header


def protected_shape(payload: bytes, complete_bytes: int, phase: str, direction: str) -> None:
    """Source-pinned public grammar only; this does not verify a MAC/AEAD tag."""
    if not payload:
        raise ValueError('missing protected route')
    role = 0 if direction == 'a' else 1
    tag = payload[0]
    if phase == 'established':
        if tag in (1, 2):
            if complete_bytes < 35 or len(payload) < 11 or payload[9:11] != b'\x01\x01':
                raise ValueError('short or wrong-version/suite common record')
            if tag == 2 and int.from_bytes(payload[1:9], 'big') != 1:
                raise ValueError('fixed Control epoch changed')
        elif tag == 3:
            if complete_bytes != (125 if direction == 'a' else 61) or payload[1:3] != b'\x01\x01':
                raise ValueError('Joining role/extent/security prefix mismatch')
        else:
            raise ValueError('unknown established routing tag')
    elif phase == 'handshake' and tag == 128:
        if (complete_bytes != 145 or len(payload) < 25 or payload[2] != 1 or payload[4] != 0
                or payload[3] not in ((1, 3) if direction == 'a' else (2,))
                or payload[1] != (56 if direction == 'a' else 64) or not any(payload[9:25])):
            raise ValueError('admission role/opcode/extent mismatch')
    elif phase == 'handshake' and tag == 129:
        if (complete_bytes < 109 or len(payload) < 77 or payload[1] not in (32, 40)
                or payload[2:5] != bytes([1, role, 0]) or payload[31:33] != bytes(2)
                or int.from_bytes(payload[29:31], 'big') + 65 != complete_bytes
                or payload[33:39] != b'L2AR\x01\x01' or payload[40] != role
                or payload[41:57] != payload[5:21] or int.from_bytes(payload[57:65], 'big') != 1):
            raise ValueError('bootstrap ARQ public envelope mismatch')
        if payload[1] == 40:
            if complete_bytes != 113 or payload[39] != 2:
                raise ValueError('bootstrap ACK extent/kind mismatch')
        elif payload[39] != 1 or int.from_bytes(payload[73:77], 'big') + 109 != complete_bytes:
            raise ValueError('bootstrap source extent/kind mismatch')
    else:
        raise ValueError('cover phase/routing mismatch')


def _pcap_header(header: bytes) -> tuple[str, int, int]:
    magic = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\xa1\xb2\xc3\xd4': ('>', 1000),
             b'\x4d\x3c\xb2\xa1': ('<', 1), b'\xa1\xb2\x3c\x4d': ('>', 1)}
    if len(header) != 24 or header[:4] not in magic:
        raise ObservationError('unsupported/truncated pcap header')
    endian, precision = magic[header[:4]]
    major, minor, zone, accuracy, snaplen, link = struct.unpack(endian + 'HHIIII', header[4:])
    if (major, minor, zone, accuracy, snaplen, link) != (2, 4, 0, 0, BOUNDS['capture_snaplen'], 1):
        raise ObservationError('unexpected pcap link/snapshot/version')
    return endian, precision, snaplen


def _pcap_record(header: bytes, endian: str, precision: int, snaplen: int) -> tuple[int, int, int, int]:
    if len(header) != 16:
        raise ValueError('truncated pcap record header')
    seconds, fraction, captured, original = struct.unpack(endian + 'IIII', header)
    if (fraction >= 1_000_000_000 // precision or not 14 <= captured <= snaplen
            or captured != min(original, snaplen) or original > 65_535 + 14):
        raise ValueError('invalid declared capture snapshot/extent')
    return seconds, fraction, captured, original


def _captured_ipv4(frame: bytes, original: int) -> tuple[bytes, int]:
    ip = frame[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise ValueError('unsupported IPv4 version/truncated header')
    header_bytes = (ip[0] & 15) * 4
    if not 20 <= header_bytes <= 60 or len(ip) < header_bytes:
        raise ValueError('invalid captured IPv4 header length')
    total = int.from_bytes(ip[2:4], 'big')
    if (total < header_bytes or original not in (max(14 + total, 60), 14 + total)
            or bounded.checksum(ip[:header_bytes])):
        raise ValueError('invalid captured original IP extent/checksum')
    offset = 20
    while offset < header_bytes:
        kind = ip[offset]
        if kind == 0:
            if any(ip[offset + 1:header_bytes]):
                raise ValueError('nonzero IPv4 option padding')
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 1 >= header_bytes:
            raise ValueError('truncated IPv4 option length')
        length = ip[offset + 1]
        if length < 2 or offset + length > header_bytes:
            raise ValueError('invalid IPv4 option length/extent')
        # This capture validator supports Router Alert, not other option semantics.
        if kind != 0x94 or length != 4 or ip[offset + 2:offset + length] != bytes(2):
            raise ValueError('unsupported IPv4 option semantics')
        offset += length
    return ip, total


def _native_icmp_sample(ip: bytes, total: int) -> dict | None:
    if ip[9] != 1:
        return None
    if ip[0] != 0x45:
        raise ValueError('unsupported native ICMP IPv4 options')
    source, destination = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    fragment = int.from_bytes(ip[6:8], 'big')
    if (total != 1500 or len(ip) < 44 or {source, destination} != set(HOST.values())
            or fragment & 0x3fff or ip[20] not in (0, 8) or ip[21] != 0
            or ip[20] == 8 and not fragment & 0x4000 or not 1 <= int.from_bytes(ip[26:28], 'big') <= 3):
        raise ValueError('native ICMP full-MTU/DF/type/sequence mismatch')
    return {'source': source, 'address': destination, 'type': ip[20],
        'identifier': int.from_bytes(ip[24:26], 'big'), 'sequence': int.from_bytes(ip[26:28], 'big'),
        'ip_bytes': total, 'df': bool(fragment & 0x4000), 'payload_prefix': ip[28:44].hex()}


def _native_icmp_error(ip: bytes, total: int) -> dict:
    """Classify the owned lab's classic UDP quote, not socket membership or cause."""
    if (len(ip) < 56 or ip[0] != 0x45 or total < 56 or total > 1500
            or int.from_bytes(ip[2:4], 'big') != total
            or int.from_bytes(ip[6:8], 'big') & 0xbfff
            or ip[20:22] != bytes([3, 3]) or ip[24:28] != bytes(4)):
        raise ValueError('unsupported native ICMP port-unreachable header/extent')
    if (ip[28] != 0x45 or ip[37] != 17 or int.from_bytes(ip[34:36], 'big') & 0xbfff
            or bounded.checksum(ip[28:48])):
        raise ValueError('unsupported native ICMP quoted IPv4 header')
    source, destination = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    quoted_source, quoted_destination = socket.inet_ntoa(ip[40:44]), socket.inet_ntoa(ip[44:48])
    quoted_total = int.from_bytes(ip[30:32], 'big')
    source_port, destination_port, udp_bytes = struct.unpack('!HHH', ip[48:54])
    if ({source, destination} != set(HOST.values())
            or quoted_source != destination or quoted_destination != source
            or udp_bytes not in (8, 9, 26, 72, 520, 1208, 1480)
            or quoted_total != 20 + udp_bytes or total > 28 + quoted_total
            or (source_port == 24461) == (destination_port == 24461)
            or source_port == 0 or destination_port == 0):
        raise ValueError('unsupported native ICMP port-unreachable quote')
    complete = total <= len(ip)
    if complete and bounded.checksum(ip[20:total]):
        raise ValueError('invalid complete native ICMP checksum')
    return {'source': source, 'address': destination, 'type': 3, 'code': 3, 'ip_bytes': total,
        'quoted_source': quoted_source, 'quoted_address': quoted_destination,
        'quoted_source_port': source_port, 'quoted_destination_port': destination_port,
        'quoted_protocol': 17, 'quoted_ip_bytes': quoted_total, 'quoted_udp_bytes': udp_bytes,
        'checksum_status': 'verified' if complete else 'not_observed_truncated_snapshot'}


def _native_icmp_observation(ip: bytes, total: int) -> tuple[dict | None, dict | None]:
    """Keep echo fingerprints and structural native error observations separate."""
    if len(ip) < 20:
        raise ValueError('truncated native IPv4 header')
    if ip[9] != 1:
        return None, None
    if ip[0] != 0x45 or len(ip) < 28:
        raise ValueError('unsupported native ICMP IPv4 options/truncated header')
    if ip[20:22] == bytes([3, 3]):
        return None, _native_icmp_error(ip, total)
    return _native_icmp_sample(ip, total), None


def _record_native_icmp(echo: dict, errors: dict, sample: dict | None, error: dict | None) -> None:
    if sample is None and error is None:
        return
    if len(echo['samples']) + errors['count'] >= 128:
        raise BoundExhausted('native ICMP observation ceiling exhausted')
    if sample is not None:
        echo['requests' if sample['type'] == 8 else 'replies'] += 1
        echo['samples'].append(sample)
    else:
        errors['count'] += 1
        if len(errors['samples']) < 16:
            errors['samples'].append(error)
        else:
            errors['omitted'] += 1


class _NativeCaptureCursor:
    """Observe one owned growing pcap without rescanning accepted records."""
    def __init__(self, path: Path):
        self._path, self._stream, self._identity = Path(path), None, None
        self._offset = self._packets = self._bytes_read = self._size = 0
        self._format, self._closed = None, False
        self._icmp = {'requests': 0, 'replies': 0, 'samples': []}
        self._icmp_errors = {'count': 0, 'samples': [], 'omitted': 0}

    @property
    def offset(self):
        return self._offset

    @property
    def packets(self):
        return self._packets

    @property
    def bytes_read(self):
        return self._bytes_read

    @property
    def native_icmp(self):
        return {**self._icmp, 'samples': [dict(sample) for sample in self._icmp['samples']]}

    @property
    def native_icmp_errors(self):
        return {**self._icmp_errors, 'samples': [dict(sample) for sample in self._icmp_errors['samples']]}

    def close(self):
        self._closed = True
        if self._stream is not None:
            stream, self._stream = self._stream, None
            stream.close()

    def _check_file(self, terminal):
        try:
            visible = self._path.lstat()
        except FileNotFoundError:
            if self._stream is not None or terminal:
                raise ObservationError('native capture file disappeared or was never created') from None
            return False
        if not stat.S_ISREG(visible.st_mode):
            raise ObservationError('native capture must be a regular non-symlink file')
        identity = (visible.st_dev, visible.st_ino)
        if self._stream is None:
            self._stream = self._path.open('rb', buffering=0)
            self._identity = identity
        opened = os.fstat(self._stream.fileno())
        current = self._path.lstat()
        if (not stat.S_ISREG(current.st_mode) or identity != self._identity
                or (opened.st_dev, opened.st_ino) != self._identity
                or (current.st_dev, current.st_ino) != self._identity):
            raise ObservationError('native capture path/file identity changed')
        if (opened.st_size < self._size or current.st_size < self._size or opened.st_size < self._offset
                or opened.st_size < visible.st_size or current.st_size < opened.st_size):
            raise ObservationError('native capture file shrank')
        self._size = max(opened.st_size, current.st_size)
        if self._size >= BOUNDS['capture_bytes']:
            raise BoundExhausted('capture byte ceiling exhausted')
        return True

    def _read(self, length):
        value = self._stream.read(length)
        self._bytes_read += len(value)
        return value

    def poll(self, terminal=False, max_records=4096):
        if self._closed:
            raise ValueError('native capture cursor is closed')
        if type(max_records) is not int or not 1 <= max_records <= 4096:
            raise ValueError('native capture scan work must be1..4096 records')
        result = {'records_read': 0, 'at_end': False, 'incomplete': False}
        if not self._check_file(terminal):
            return {**result, 'at_end': True, 'incomplete': True}
        self._stream.seek(self._offset)
        if self._format is None:
            header = self._read(24)
            if len(header) != 24:
                if terminal:
                    raise ObservationError('unsupported/truncated pcap header')
                return {**result, 'at_end': True, 'incomplete': True}
            self._format = _pcap_header(header)
            self._offset = 24
        endian, precision, snaplen = self._format
        for _ in range(max_records):
            header = self._read(16)
            if not header:
                result['at_end'] = True
                break
            if len(header) != 16:
                if terminal:
                    raise ValueError('truncated pcap record header')
                result.update(at_end=True, incomplete=True)
                break
            _, _, captured, original = _pcap_record(header, endian, precision, snaplen)
            frame = self._read(captured)
            if len(frame) != captured:
                if terminal:
                    raise ValueError('truncated pcap record body')
                result.update(at_end=True, incomplete=True)
                break
            if self._packets + 1 >= BOUNDS['capture_packets']:
                raise BoundExhausted('capture packet ceiling exhausted')
            if frame[12:14] != b'\x08\x06':
                if frame[12:14] != b'\x08\x00':
                    raise ValueError('unexpected IP family/underlay Ethernet type')
                ip, total = _captured_ipv4(frame, original)
                sample, error = _native_icmp_observation(ip, total)
                _record_native_icmp(self._icmp, self._icmp_errors, sample, error)
            # An incomplete or malformed record cannot adopt a cursor or key.
            self._offset += 16 + captured
            self._packets += 1
            result['records_read'] += 1
        self._check_file(terminal)
        if not result['incomplete'] and self._size > self._offset:
            result['at_end'] = False
        return result


def _native_icmp_key(sample: dict) -> tuple:
    return tuple(sample[name] for name in ('source', 'address', 'type', 'identifier',
        'sequence', 'payload_prefix', 'ip_bytes')) + (sample['df'] if sample['type'] == 8 else None,)


def _expected_native_icmp(phases: dict) -> list[dict]:
    expected, distinct = [], set()
    if not isinstance(phases, dict):
        raise ObservationError('native capture drain requires completed probe outcomes')
    for phase in ('functional', 'after_reconnect'):
        outcome = phases.get(phase)
        if not isinstance(outcome, dict) or set(outcome) != {'a', 'b'}:
            raise ObservationError('native capture drain requires all four completed ICMP probes')
        for side in ('a', 'b'):
            if not isinstance(outcome[side], dict) or not isinstance(outcome[side].get('icmp'), dict):
                raise ObservationError('native capture drain requires all four completed ICMP probes')
            result = outcome[side]['icmp']
            other = 'b' if side == 'a' else 'a'
            rows = result.get('rows', [])
            if (result.get('status') != 'passed' or result.get('sent') != 3
                    or result.get('received_unique') != 3 or result.get('request_count') != 3
                    or result.get('payload_bytes') != 1472 or result.get('ip_bytes') != 1500
                    or result.get('df') is not True or result.get('source') != HOST[side]
                    or result.get('address') != HOST[other]
                    or type(result.get('identifier')) is not int or not 1 <= result['identifier'] <= 65535
                    or type(result.get('original_deadline_ns')) is not int
                    or not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
                    or [row.get('sequence') for row in rows] != [1, 2, 3]):
                raise ObservationError('native capture drain requires exact validated three-request outcomes')
            for row in rows:
                prefix = row.get('payload_prefix')
                if (not isinstance(prefix, str) or re.fullmatch('[0-9a-f]{32}', prefix) is None
                        or type(row.get('sent_ns')) is not int or type(row.get('received_ns')) is not int
                        or not row['sent_ns'] <= row['received_ns'] < result['original_deadline_ns']):
                    raise ObservationError('native capture drain probe identity/timing is incomplete')
                for kind, source, address in [(8, HOST[side], HOST[other]), (0, HOST[other], HOST[side])]:
                    sample = {'phase': phase, 'side': side, 'source': source, 'address': address,
                        'type': kind, 'identifier': result['identifier'], 'sequence': row['sequence'],
                        'payload_prefix': prefix, 'ip_bytes': 1500, 'df': kind == 8}
                    key = _native_icmp_key(sample)
                    if key in distinct:
                        raise ObservationError('native capture drain probe fingerprints are not distinct')
                    distinct.add(key)
                    expected.append(sample)
    return expected


def drain_native_capture(process, path, phases, deadline, *, clock=time.monotonic, sleeper=time.sleep) -> dict:
    """Witness all persisted probe keys before interrupting the owned capture."""
    report = {'status': 'pending', 'deadline': deadline, 'original_deadline': deadline,
        'clock_unit': 'monotonic_seconds', 'started_monotonic_seconds': clock(),
        'finished_monotonic_seconds': None, 'expected_keys': 24,
        'matched_keys': 0, 'missing': [], 'offset': 0, 'packets': 0, 'bytes_read': 0,
        'process_returncode': None, 'scope': 'persisted exact ICMP keys; final capture audit still required'}
    cursor, failure, expected = None, None, None
    try:
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError('finite original capture drain deadline required')
        expected = _expected_native_icmp(phases)
        report['missing'] = expected
        cursor = _NativeCaptureCursor(path)
        while True:
            if clock() >= deadline:
                raise BoundExhausted('original case deadline exhausted before capture drain')
            code = process.poll()
            report['process_returncode'] = code
            polled = cursor.poll(terminal=code is not None)
            seen = {_native_icmp_key(sample) for sample in cursor.native_icmp['samples']}
            missing = [sample for sample in expected if _native_icmp_key(sample) not in seen]
            report.update(matched_keys=24 - len(missing), missing=missing, offset=cursor.offset,
                packets=cursor.packets, bytes_read=cursor.bytes_read, process_returncode=code,
                native_icmp_errors=cursor.native_icmp_errors)
            now = clock()
            if now >= deadline:
                raise BoundExhausted('original case deadline exhausted during capture drain')
            if not missing and polled['at_end'] and not polled['incomplete']:
                report['status'] = 'passed'
                return report
            if not polled['at_end']:
                continue
            if code is not None:
                raise ObservationError('native capture producer exited before all exact ICMP keys were saved')
            sleeper(min(.02, deadline - now))
    except Exception as error:
        failure = error
        if cursor is not None:
            report.update(offset=cursor.offset, packets=cursor.packets, bytes_read=cursor.bytes_read,
                native_icmp_errors=cursor.native_icmp_errors)
            if expected is not None:
                seen = {_native_icmp_key(sample) for sample in cursor.native_icmp['samples']}
                missing = [sample for sample in expected if _native_icmp_key(sample) not in seen]
                report.update(matched_keys=24 - len(missing), missing=missing)
        report.update(status=failure_status(error), error=f'{type(error).__name__}: {error}'[:4096])
        error.capture_drain = report
        raise
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception as error:
                if failure is not None:
                    report['close_error'] = f'{type(error).__name__}: {error}'[:4096]
                else:
                    report.update(status=failure_status(error), error=f'{type(error).__name__}: {error}'[:4096])
                    report['finished_monotonic_seconds'] = clock()
                    error.capture_drain = report
                    raise
        report['finished_monotonic_seconds'] = clock()
        if failure is None and report['status'] == 'passed' and report['finished_monotonic_seconds'] >= deadline:
            error = BoundExhausted('original case deadline exhausted before capture drain completion')
            report.update(status='bound_exhausted', error=f'{type(error).__name__}: {error}')
            error.capture_drain = report
            raise error


def audit_capture(path: Path, case: dict, local_side: str | None, anchors: list[dict], clock: dict | None = None) -> dict:
    if path.stat().st_size >= BOUNDS['capture_bytes']:
        raise BoundExhausted('capture byte ceiling exhausted')
    offsets = [a['offset_ns'] for a in anchors]
    if not offsets or max(offsets) - min(offsets) > 5_000_000:
        raise ObservationError('capture realtime/monotonic clock offset unstable')
    result = {'packets': 0, 'arp': 0, 'udp': 0, 'tcp': 0, 'handshake': 0, 'established': 0, 'icmp_path_errors': 0,
        'native_icmp': {'requests': 0, 'replies': 0, 'samples': []},
        'native_icmp_errors': {'count': 0, 'samples': [], 'omitted': 0},
        'directions': {side: {'packets': 0, 'ip_bytes': 0, 'measurement_min_ip_bytes': 0, 'measurement_max_ip_bytes': 0} for side in ('a', 'b')},
        'user_epochs': {}, 'snapshot_bytes': BOUNDS['capture_snaplen'], 'payload_integrity': 'endpoint exact probes, not truncated capture'}
    def account_ip(direction, total, seconds, fraction, precision):
        row = result['directions'][direction]
        row['packets'] += 1
        row['ip_bytes'] += total
        if clock and direction == local_side:
            at = seconds * 1_000_000_000 + fraction * precision
            uncertainty = precision + max(a['uncertainty_ns'] for a in anchors)
            low, high = at - max(offsets) - uncertainty, at - min(offsets) + uncertainty
            begin, end = clock['measure_start_ns'], clock['end_ns']
            if low >= begin and high < end:
                row['measurement_min_ip_bytes'] += total
            if high >= begin and low < end:
                row['measurement_max_ip_bytes'] += total

    with path.open('rb') as stream:
        header = stream.read(24)
        endian, precision, snaplen = _pcap_header(header)
        while record_header := stream.read(16):
            seconds, fraction, captured, original = _pcap_record(record_header, endian, precision, snaplen)
            frame = stream.read(captured)
            if len(frame) != captured:
                raise ValueError('truncated pcap record body')
            result['packets'] += 1
            if result['packets'] >= BOUNDS['capture_packets']:
                raise BoundExhausted('capture packet ceiling exhausted')
            ether = frame[12:14]
            if ether == b'\x08\x06':
                result['arp'] += 1
                continue
            if ether != b'\x08\x00':
                raise ValueError('unexpected IP family/underlay Ethernet type')
            ip, total = _captured_ipv4(frame, original)
            if local_side is None:
                sample, error = _native_icmp_observation(ip, total)
                _record_native_icmp(result['native_icmp'], result['native_icmp_errors'], sample, error)
                continue
            if ip[0] != 0x45:
                raise ValueError('unsupported protected WAN IPv4 options')
            if total > case['path_mtu'] or int.from_bytes(ip[6:8], 'big') & 0x3fff:
                raise ValueError('outer MTU breach or fragmentation')
            source, destination = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
            if ip[9] == 1:
                # Connected UDP may surface a genuine startup/path error. It is
                # evidence, not a tunnel side transport; validate its quoted
                # original tuple and retain a separate count.
                if (source not in (*WAN.values(), '192.0.2.1', '192.0.2.5')
                        or destination not in WAN.values() or len(ip) < 56
                        or ip[20] != 3 or ip[21] not in (0, 1, 2, 3, 4, 9, 10, 13)
                        or ip[28] != 0x45 or ip[37] != 17
                        or int.from_bytes(ip[30:32], 'big') < 28
                        or int.from_bytes(ip[52:54], 'big') != int.from_bytes(ip[30:32], 'big') - 20
                        or int.from_bytes(ip[34:36], 'big') & 0x3fff
                        or {socket.inet_ntoa(ip[40:44]), socket.inet_ntoa(ip[44:48])} != set(WAN.values())
                        or socket.inet_ntoa(ip[40:44]) != destination
                        or ip[48:52] != struct.pack('!HH', 24440, 24440)
                        or bounded.checksum(ip[28:48])):
                    raise ValueError('unexpected ICMP path-error quote')
                if total <= len(ip) and bounded.checksum(ip[20:total]):
                    raise ValueError('invalid complete ICMP checksum')
                result['icmp_path_errors'] += 1
                if source in WAN.values():
                    account_ip('a' if source == WAN['a'] else 'b', total, seconds, fraction, precision)
                continue
            if {source, destination} != set(WAN.values()):
                raise ValueError('unexpected outer IP endpoints')
            direction = 'a' if source == WAN['a'] else 'b'
            account_ip(direction, total, seconds, fraction, precision)
            if ip[9] == 6:
                result['tcp'] += 1
                raise ValueError('TCP bootstrap/side flow observed on secure UDP WAN')
            if ip[9] != 17 or len(ip) < 28:
                raise ValueError('unexpected underlay transport')
            sport, dport, length = struct.unpack('!HHH', ip[20:26])
            if sport != 24440 or dport != 24440 or length != total - 20:
                raise ValueError('original UDP tuple/extent changed')
            body = ip[28:]
            phase, payload, protected_bytes = covered_payload(body, length - 8, case['cover'])
            protected_shape(payload, protected_bytes, phase, direction)
            if phase == 'established' and payload[0] == 1:
                if len(payload) < 9:
                    raise ValueError('truncated established User scope')
                epoch = int.from_bytes(payload[1:9], 'big')
                mtu = {1: 1500, 2: 1400, 3: 1500}.get(epoch)
                if mtu is None or total > mtu:
                    raise ValueError('unknown User epoch or negotiated policy MTU breach')
                result['user_epochs'][str(epoch)] = result['user_epochs'].get(str(epoch), 0) + 1
            result[phase] += 1
            result['udp'] += 1
            if 'public_noise' in case:
                keys = case['public_noise']
                suffix = b'initiator' if direction == 'a' else b'responder'
                other = b'responder' if direction == 'a' else b'initiator'
                joined = bytes(keys['a']) + bytes(keys['b'])
                if case['cover'] == 'quic-like':
                    peer_id = hashlib.sha256(b'l2tunnel/service/CID/' + other + b'/v1\0' + joined).digest()[:8]
                    if (phase == 'handshake' and (body[6:14] != peer_id or body[15:23] != hashlib.sha256(
                            b'l2tunnel/service/CID/' + suffix + b'/v1\0' + joined).digest()[:8])
                            or phase == 'established' and body[1:9] != peer_id):
                        raise ValueError('captured public global connection IDs changed')
                elif body[8:12] != hashlib.sha256(b'l2tunnel/service/SSRC/' + suffix + b'/v1\0' + joined).digest()[:4]:
                    raise ValueError('captured public media source identity changed')
    if not result['packets'] or local_side is not None and not (result['handshake'] and result['established']):
        raise ValueError('capture did not observe real handshake and established traffic')
    if local_side is not None and case.get('require_policy_epochs') and not {'1', '2', '3'} <= set(result['user_epochs']):
        raise ValueError('capture lacks actual User traffic in each loaded policy epoch')
    return result


def icmp_capture_complete(audit: dict, phases: dict) -> dict:
    """Bind truncated native headers to independently validated endpoint payloads."""
    observed, checked = audit['native_icmp']['samples'], []
    for phase in ('functional', 'after_reconnect'):
        for side, value in phases.get(phase, {}).items():
            result = value.get('icmp', {})
            if (result.get('status') != 'passed' or result.get('sent') != 3 or result.get('received_unique') != 3
                    or [row.get('sequence') for row in result.get('rows', [])] != [1, 2, 3]):
                raise ValueError('native ICMP result lacks exact validated three-request scope')
            other = 'b' if side == 'a' else 'a'
            for row in result['rows']:
                for kind, source, address in [(8, HOST[side], HOST[other]), (0, HOST[other], HOST[side])]:
                    if not any(sample['type'] == kind and sample['source'] == source and sample['address'] == address
                            and sample['identifier'] == result['identifier'] and sample['sequence'] == row['sequence']
                            and sample['payload_prefix'] == row['payload_prefix'] and sample['ip_bytes'] == 1500
                            and (kind != 8 or sample['df']) for sample in observed):
                        raise ValueError('native capture missing exact full-MTU ICMP request/reply')
            checked.append({'phase': phase, 'side': side, 'identifier': result['identifier'], 'requests': 3, 'replies': 3})
    return {'probes': checked, 'scope': 'captured complete IP extent, DF requests and fresh payload prefix; complete ICMP checksum/payload validated by endpoint'}


def _capture_counter_observation(values: dict, returncode: int | None) -> dict:
    reasons = []
    if values['captured'] >= BOUNDS['capture_packets']:
        reasons.append('packet_cap')
    if values['kernel_dropped']:
        reasons.append('kernel_dropped')
    if type(returncode) is not int or returncode not in (0, -signal.SIGINT):
        reasons.append('process_exit')
    return {'schema': 1, 'counters': dict(values), 'returncode': returncode,
        'parse_status': 'complete', 'qualification': 'rejected' if reasons else 'passed',
        'qualification_reasons': reasons}


def capture_counts(log: Path, process: subprocess.Popen) -> dict:
    bounded.stop(process, interrupt=True)
    text = bounded.read_log(log)
    values = {}
    for field, suffix in [('captured', ' packets captured'), ('received', ' packets received by filter'),
                          ('kernel_dropped', ' packets dropped by kernel')]:
        lines = [line for line in text.splitlines() if suffix in line]
        if len(lines) != 1:
            raise ObservationError('tcpdump final counters missing/ambiguous')
        match = re.fullmatch(r'([0-9]{1,20})' + re.escape(suffix), lines[0])
        if match is None or int(match[1]) > (1 << 64) - 1:
            raise ObservationError('tcpdump final counter outside bounded unsigned grammar')
        values[field] = int(match[1])
    observation = _capture_counter_observation(values, process.returncode)
    reasons = observation['qualification_reasons']
    if reasons:
        if 'packet_cap' in reasons:
            error = BoundExhausted('tcpdump packet ceiling exhausted')
        elif 'kernel_dropped' in reasons:
            error = ObservationError('capture lost packets in kernel')
        else:
            error = ObservationError('tcpdump failed: ' + str(process.returncode))
        error.capture_counter_observation = observation
        raise error
    return values


def aligned_peers(peers: dict, require_epoch: bool = True) -> dict:
    for field in ('session', 'transcript', 'configuration', 'outer') + (('policy_epoch',) if require_epoch else ()):
        if peers['a'][field] != peers['b'][field]:
            raise ValueError('actual peer bindings/epoch disagree: ' + field)
    return peers


def capture_complete(audit: dict, counters: dict, *, require_lossless: bool = False) -> None:
    """Check record equality; only explicit strict calls qualify lossless capture."""
    if type(require_lossless) is not bool:
        raise ValueError('explicit capture qualification flag required')
    if 'kernel_dropped' in counters:
        dropped = counters['kernel_dropped']
        if type(dropped) is not int or not 0 <= dropped < 1 << 64 or dropped != 0:
            raise ObservationError('capture lost packets or has invalid kernel drop count')
    if require_lossless:
        if (set(counters) != {'captured', 'received', 'kernel_dropped'}
                or any(type(value) is not int or not 0 <= value < 1 << 64 for value in counters.values())):
            raise ObservationError('complete bounded capture counters required')
        if counters['captured'] >= BOUNDS['capture_packets']:
            raise BoundExhausted('tcpdump packet ceiling exhausted')
    if type(audit.get('packets')) is not int or not 0 <= audit['packets'] < 1 << 64:
        raise ValueError('bounded parsed capture record count required')
    if type(counters.get('captured')) is not int or not 0 <= counters['captured'] < 1 << 64:
        raise ObservationError('bounded captured counter required')
    if audit['packets'] != counters['captured']:
        raise ValueError('parsed capture records differ from tcpdump captured count')


def owned_wan_qdiscs(raw: str) -> list[dict]:
    value = bounded.strict_json(raw)
    if not isinstance(value, list) or len(value) != 2 or any(not isinstance(row, dict) for row in value):
        raise ValueError('expected only owned wan0 HTB/netem qdiscs')
    root = [row for row in value if row.get('root') is True]
    leaf = [row for row in value if row.get('parent') == '1:10']
    if (len(root) != 1 or root[0].get('kind') != 'htb' or root[0].get('handle') != '1:'
            or len(leaf) != 1 or leaf[0].get('kind') != 'netem' or leaf[0].get('handle') != '10:'):
        raise ValueError('owned wan0 qdisc identity changed')
    return value


def recreate_owned_wan(case: dict, spec: lab.LabSpec, state_dir: Path, side: str, command) -> dict:
    if side not in ('a', 'b') or case['namespaces'] != spec.namespaces or case['lab_id'] != spec.lab_id:
        raise ValueError('exact owned endpoint specification required')
    role = 'endpoint_' + side
    namespace = spec.namespaces[role]
    rate = 100 if side == 'a' else 10
    with lab.locked_state(state_dir, spec) as journal:
        manifest = lab.load_manifest(journal, spec)
        if set(manifest['owned_namespaces']) != set(spec.namespaces.values()):
            raise ValueError('complete created topology ownership required before shaping')
        for name, identity in manifest['owned_namespaces'].items():
            if lab.namespace_identity(name) != identity:
                raise ValueError('refusing shaping in replaced namespace: ' + name)
        if command(None, 'ip', 'netns', 'pids', namespace).strip():
            raise ValueError('refusing shaping while owned endpoint processes exist')
        before = owned_wan_qdiscs(command(role, 'tc', '-j', 'qdisc', 'show', 'dev', 'wan0'))
        identity = manifest['owned_namespaces'][namespace]
        if lab.namespace_identity(namespace) != identity:
            raise ValueError('namespace ownership changed before qdisc deletion')
        # The topology's existing HTB cannot acquire a different size table via
        # change/replace. Recreate only this verified root, before all daemons.
        command(role, 'tc', 'qdisc', 'del', 'dev', 'wan0', 'root', 'handle', '1:')
        command(role, 'tc', 'qdisc', 'add', 'dev', 'wan0', 'root', 'handle', '1:', 'stab',
            'overhead', '-14', 'linklayer', 'ethernet', 'htb', 'default', '10')
        command(role, 'tc', 'class', 'add', 'dev', 'wan0', 'parent', '1:', 'classid', '1:10',
            'htb', 'rate', f'{rate}mbit', 'ceil', f'{rate}mbit')
        command(role, 'tc', 'qdisc', 'add', 'dev', 'wan0', 'parent', '1:10', 'handle', '10:',
            'netem', 'limit', '1000', 'delay', str(case['one_way_delay_ms']) + 'ms',
            'loss', 'random', str(case['loss_percent_per_direction']) + '%')
        after = owned_wan_qdiscs(command(role, 'tc', '-j', 'qdisc', 'show', 'dev', 'wan0'))
        if lab.namespace_identity(namespace) != identity:
            raise ValueError('namespace ownership changed during qdisc recreation')
        return {'namespace': namespace, 'identity': identity, 'before': before, 'after': after,
            'accounting': 'explicit fresh HTB STAB overhead-14; no change/replace fallback'}


def owned_tc_snapshot(spec: lab.LabSpec, state_dir: Path, command, label: str) -> dict:
    started = time.monotonic_ns()
    observations = {}
    with lab.locked_state(state_dir, spec) as journal:
        manifest = lab.load_manifest(journal, spec)
        if set(manifest['owned_namespaces']) != set(spec.namespaces.values()):
            raise ObservationError('complete owned topology required for tc observation')
        for side in ('a', 'b'):
            role, namespace = 'endpoint_' + side, spec.namespaces['endpoint_' + side]
            identity = manifest['owned_namespaces'][namespace]
            if lab.namespace_identity(namespace) != identity:
                raise ObservationError('replaced endpoint refused for tc observation')
            raw = {kind: command(role, 'tc', '-s', kind, 'show', 'dev', 'wan0') for kind in ('class', 'qdisc')}
            if not all(value.strip() for value in raw.values()) or lab.namespace_identity(namespace) != identity:
                raise ObservationError('missing/replaced owned tc observation')
            observations[side] = {'namespace': namespace, 'identity': identity, 'raw': raw}
    return {'phase': label, 'started_monotonic_ns': started, 'finished_monotonic_ns': time.monotonic_ns(),
        'endpoints': observations, 'scope': 'cumulative kernel counters; observation bounds are not the exact throughput window'}


def record_tc_snapshot(receipt, spec: lab.LabSpec, state_dir: Path, command, label: str) -> None:
    snapshot = owned_tc_snapshot(spec, state_dir, command, label)
    receipt.update(**{label: snapshot})


def wire_window_evidence(reference: dict, audits: dict) -> dict:
    result = {}
    for side, direction in [('a', 'a_to_b'), ('b', 'b_to_a')]:
        values = audits['wan-' + side]['directions'][side]
        low, high = values['measurement_min_ip_bytes'], values['measurement_max_ip_bytes']
        if type(low) is not int or type(high) is not int or not 0 < low <= high:
            raise ObservationError('no positive conservative same-window WAN denominator: ' + direction)
        result[direction] = {'receiver_unique_bytes': reference['directions'][direction]['receiver_unique_bytes'],
            'minimum_ip_bytes': low, 'maximum_ip_bytes': high,
            'scope': 'same time window; endpoint WAN emitted IP bytes after egress qdisc, excluding qdisc drops; delivered bytes may be a different propagation cohort'}
    return result


def capture_command(name: str, destination: Path) -> list[str]:
    if name not in ('wan-a', 'wan-b', 'native-a'):
        raise ValueError('explicit owned capture surface required')
    return ['tcpdump', '-n', '-U', '-B', '8192', '-s', str(BOUNDS['capture_snaplen']),
        '-c', str(BOUNDS['capture_packets']), '-Z', 'root', '-i', 'tap0' if name == 'native-a' else 'wan0',
        '-w', str(destination), 'ip or arp' if name == 'native-a' else 'ip or ip6 or arp']


def run_case(case: dict, output: Path, build: dict, namespace_proof: dict) -> dict:
    explicit_runtime = _runtime_experiment(case)
    spec = lab.LabSpec(case['lab_id'])
    spaces, deadline = spec.namespaces, time.monotonic() + BOUNDS['case']
    binary, state_dir = output / 'l2tunnel-native', Path('/run/l2tunnel-secure-native')
    receipt = bounded.Receipt(output / 'receipt.json', {'status': 'running', 'plan': case,
        'namespace_proof': namespace_proof, 'binary_sha256': bounded.file_hash(binary),
        'build_receipt_sha256': bounded.file_hash(output / 'build-receipt.json'),
        'executed_helpers': verify_helpers(build, output, True), 'cleanup': 'pending'})
    processes, captures, commands, samples, errors = [], {}, [], [], []
    capture_counters, capture_counter_observations = {}, {}
    anchors, reference_result = [clock_anchor()], None
    public, daemon_starttimes, runtime_events = None, {}, None

    def command(role, *argv, cap=BOUNDS['command']):
        vector = (['ip', 'netns', 'exec', spaces[role]] if role else []) + list(argv)
        commands.append(vector)
        if len(commands) > 2048:
            raise BoundExhausted('command ledger ceiling exhausted')
        return bounded.command(vector, deadline, cap)

    def launch(role, argv, name, cap=BOUNDS['log_bytes']):
        vector = ['ip', 'netns', 'exec', spaces[role], *map(str, argv)]
        commands.append(vector)
        path = output / (name + '.log')
        child = bounded.launch(vector, path, cap=cap)
        processes.append(child)
        return child, path

    def rpc(side, action, *flags, cap=BOUNDS['command']):
        raw = command('endpoint_' + side, str(binary), action, '--control-socket',
                      str(secrets / f'control-{side}.sock'), '--api-version', '2', *flags, cap=cap)
        if len(raw) > BOUNDS['log_bytes']:
            raise ObservationError('local response exceeds bound')
        try:
            value = bounded.strict_json(raw.strip().splitlines()[-1])
        except (ValueError, IndexError) as error:
            raise ObservationError('local CLI did not return JSON') from error
        if not isinstance(value, dict) or value.get('version') != 2 or value.get('ok') is not True:
            raise ValueError('real API-v2 operation failed: ' + repr(value))
        return value

    def statuses(expected=None, require_epoch=True):
        result = {side: validate_status(rpc(side, 'status'), case, side, public, expected) for side in ('a', 'b')}
        return aligned_peers(result, require_epoch)

    def await_policy(expected, epoch):
        until = min(deadline, time.monotonic() + 15)
        while time.monotonic() < until:
            current = statuses(require_epoch=False)
            if (current['a']['policy_epoch'] == current['b']['policy_epoch']
                    and all(row['effective'] == expected and row['policy_epoch'] >= epoch
                            and row['pending_epoch'] is None for row in current.values())):
                return current
            time.sleep(.1)
        raise BoundExhausted('committed peer status did not reach exact policy')

    def socket_observation():
        rows = {}
        for side in ('a', 'b'):
            udp = command('endpoint_' + side, 'ss', '-H', '-u', '-n', '-p')
            tcp = command('endpoint_' + side, 'ss', '-H', '-t', '-n', '-p')
            matches = [line for line in udp.splitlines() if ':24440' in line]
            if len(matches) != 1 or WAN[side] + ':24440' not in matches[0] or WAN['b' if side == 'a' else 'a'] + ':24440' not in matches[0] or tcp.strip():
                raise ValueError('native sockets do not show the original sole UDP pair/no TCP')
            rows[side] = {'udp': udp, 'tcp': tcp}
        return rows

    def sample(label):
        if len(samples) >= BOUNDS['status_samples']:
            raise BoundExhausted('status sample ceiling exhausted')
        samples.append({'at_ns': time.monotonic_ns(), 'phase': label, 'peers': statuses(require_epoch=False),
            'daemon_resources': {side: daemon_resources(daemons[side][0], daemon_starttimes[side],
                **({'include_threads': True} if explicit_runtime else {})) for side in ('a', 'b')},
            'host_loadavg': list(os.getloadavg()),
            'wan': {side: json.loads(command('endpoint_' + side, 'ip', '-j', '-s', 'link', 'show', 'dev', 'wan0')) for side in ('a', 'b')}})

    def bulk(label, workload, warmup, seconds, policy_action=False):
        path = output / (label + '-clock.json')
        args = [sys.executable, output / 'secure_udp_native_probe.py', 'tcp', 'listen', '--address', HOST['b'],
                '--port', '24451', '--flows', '16', '--max-bytes', str(case['max_bytes_per_direction_flow']),
                '--clock', path, '--workload', workload]
        server, server_log = launch('host_b', args, label + '-server')
        bounded.wait_log(server, server_log, 'Listening', min(deadline, time.monotonic() + 10))
        args[3] = 'connect'
        client, client_log = launch('host_a', args, label + '-client')
        for child, log in [(server, server_log), (client, client_log)]:
            bounded.wait_log(child, log, 'Connected', min(deadline, time.monotonic() + 20))
        value = {'start_ns': time.monotonic_ns() + 1_500_000_000,
                 'warmup_ns': int(warmup * 1e9), 'measure_ns': int(seconds * 1e9)}
        accounting.publish_clock(path, value)
        end = value['start_ns'] + value['warmup_ns'] + value['measure_ns']
        next_sample, switched, policy_results = time.monotonic(), False, []
        while client.poll() is None or server.poll() is None:
            if time.monotonic() >= deadline:
                raise BoundExhausted('original case bound exhausted during native TCP')
            if time.monotonic() >= next_sample:
                sample(label)
                next_sample = time.monotonic() + 1
            if policy_action and not switched and time.monotonic_ns() >= value['start_ns'] + value['warmup_ns']:
                changed = {**INITIAL, 'path_mtu': 1400, 'channels': 8, 'window': 32,
                           'forward_kbit': 80_000, 'reverse_kbit': 8_000}
                previous = statuses()
                initial_session = previous['a']['session']
                for target, epoch in [(changed, 1), (INITIAL, 2)]:
                    flags = []
                    for key, flag in [('path_mtu', '--path-mtu'), ('channels', '--swift-channels'), ('window', '--swift-window'),
                                      ('repair_permille', '--swift-repair-permille'), ('forward_kbit', '--swift-forward-kbit'), ('reverse_kbit', '--swift-reverse-kbit')]:
                        flags.extend([flag, str(target[key])])
                    began = time.monotonic_ns()
                    reply = rpc('a', 'set-swift', *flags)
                    peers = await_policy(target, epoch)
                    completed = time.monotonic_ns()
                    if completed >= end or any(row['session'] != initial_session for row in peers.values()):
                        raise BoundExhausted('policy did not complete on the live session during load')
                    for side in ('a', 'b'):
                        for counter in ('user_number', 'control_number', 'wire_bytes', 'native_written'):
                            before, after = previous[side][counter], peers[side][counter]
                            if before is not None and (after is None or after < before):
                                raise ValueError('policy reset a live record/counter domain')
                    policy_results.append({'began_ns': began, 'completed_ns': completed, 'reply': reply, 'peers': peers})
                    previous = peers
                    time.sleep(.2)
                switched = True
            time.sleep(.05)
        if client.returncode or server.returncode:
            detail = {'client': last_json(client_log), 'server': last_json(server_log)}
            receipt.update(last_probe_failure=detail)
            if any(row.get('status') == 'bound_exhausted' for row in detail.values()):
                raise BoundExhausted('native TCP probe exhausted its original bound')
            raise ValueError('native TCP probe failed')
        client_result, server_result = last_json(client_log), last_json(server_log)
        (output / (label + '-client.json')).write_text(json.dumps(client_result, indent=2) + '\n')
        (output / (label + '-server.json')).write_text(json.dumps(server_result, indent=2) + '\n')
        result = compare_probes(client_result, server_result, workload)
        result.update(clock=client_result['clock'], policy_changes=policy_results,
            client_result=label + '-client.json', server_result=label + '-server.json')
        if result['status'] != 'passed':
            receipt.update(last_probe_result=result)
            raise BoundExhausted('finite native TCP byte ceiling exhausted')
        if policy_action and not switched:
            raise ValueError('real policy action was not performed')
        return result

    try:
        for tool in ('ip', 'tc', 'ss', 'ethtool', 'sysctl', 'tcpdump'):
            if shutil.which(tool) is None:
                raise FileNotFoundError(tool)
        receipt.update(kernel=command(None, 'uname', '-a'), resources=resource_context(),
            tools={name: command(None, *argv) for name, argv in [('ip', ('ip', '-Version')),
                ('tc', ('tc', '-Version')), ('tcpdump', ('tcpdump', '--version'))]})
        bounded.bounded_lab(lab.apply, spec, state_dir, deadline)
        journal = state_dir / (spec.lab_id + '.json')
        receipt.update(namespace_journal=json.loads(journal.read_text()))
        bounded.disable_underlay_ipv6(spaces, deadline)
        offloads, shaping = {}, {}
        for side in ('a', 'b'):
            role = 'endpoint_' + side
            shaping[side] = recreate_owned_wan(case, spec, state_dir, side, command)
            receipt.update(shaping_recreation=shaping)
            command('host_' + side, 'ip', 'route', 'replace', '198.18.0.0/24', 'dev', 'eth0', 'rto_min', '1000ms')
            command('host_' + side, 'sysctl', '-q', '-w', 'net.ipv4.tcp_congestion_control=cubic')
            for owner, interface in [(role, 'wan0'), (role, 'tap0'), (role, 'lan0'), ('host_' + side, 'eth0')]:
                offloads[owner + '/' + interface] = bounded.offloads(spaces[owner], interface, deadline)
        for interface in ('a0', 'b0'):
            offloads['router/' + interface] = bounded.offloads(spaces['router'], interface, deadline)
        receipt.update(offloads=offloads,
            tcp_defaults={side: command('host_' + side, 'sysctl', 'net.ipv4.tcp_congestion_control',
                'net.ipv4.tcp_rmem', 'net.ipv4.tcp_wmem', 'net.ipv4.tcp_ecn') for side in ('a', 'b')})
        record_tc_snapshot(receipt, spec, state_dir, command, 'tc_before')
        for name, role in [('wan-a', 'endpoint_a'), ('wan-b', 'endpoint_b'), ('native-a', 'endpoint_a')]:
            capture = output / (name + '.pcap')
            child, log = launch(role, capture_command(name, capture), name + '-capture', BOUNDS['capture_bytes'])
            captures[name] = (child, log, capture)
            bounded.wait_log(child, log, 'listening on', min(deadline, time.monotonic() + 5))
        with tempfile.TemporaryDirectory(prefix='l2t-secure-native-') as directory:
            secrets = Path(directory)
            secrets.chmod(0o700)
            public = credentials(binary, secrets, deadline)
            receipt.update(credentials=public)
            daemons = {}
            for side in ('b', 'a'):
                child, log = launch('endpoint_' + side, daemon_command(case, side, binary, secrets), 'daemon-' + side)
                daemons[side] = (child, log)
            for child, log in daemons.values():
                bounded.wait_log(child, log, '"event":"secure_udp_ready"', min(deadline, time.monotonic() + BOUNDS['startup']))
            receipt.update(initial_ready={side: ready_event(value[1]) for side, value in daemons.items()})
            if explicit_runtime:
                runtime_events = {side: host_runtime_event(value[1], case['runtime_model'])
                    for side, value in daemons.items()}
                receipt.update(host_runtime=runtime_events)
            initial_resources = {side: daemon_resources(value[0], **({'include_threads': True} if explicit_runtime else {}))
                for side, value in daemons.items()}
            daemon_starttimes = {side: value['starttime_ticks'] for side, value in initial_resources.items()}
            initial = statuses(INITIAL)
            receipt.update(initial_status=initial, initial_daemon_resources=initial_resources)
            receipt.update(initial_sockets=socket_observation())
            record_functional(receipt, 'functional',
                lambda: functional('initial', output, deadline, launch, command, receipt),
                lambda side: rpc(side, 'status', cap=2), deadline)
            reference_result = bulk('reference', case['workload'], 5, 20)
            receipt.update(reference=reference_result)
            record_tc_snapshot(receipt, spec, state_dir, command, 'tc_post_reference')
            policy_result = bulk('policy-load', 'forward16', 1, 12, policy_action=True)
            receipt.update(policy_under_load=policy_result)
            before = statuses(INITIAL)
            disconnect = {side: rpc(side, 'disconnect') for side in ('a', 'b')}
            for side, response in disconnect.items():
                value = (response.get('state') or {}).get('secure_udp')
                if value is not None and value.get('running') is not False:
                    raise ValueError('disconnect reported completion before native stop')
                if ':24440' in command('endpoint_' + side, 'ss', '-H', '-u', '-n', '-p'):
                    raise ValueError('disconnect retained original UDP owner')
            reconnects = {}
            for side in ('b', 'a'):
                reconnects[side] = launch('endpoint_' + side, [binary, 'reconnect', '--api-version', '2',
                    '--control-socket', secrets / f'control-{side}.sock'], 'reconnect-' + side)
            replies = {}
            for side, (child, log) in reconnects.items():
                child.wait(timeout=bounded.remaining(deadline, BOUNDS['startup']))
                replies[side] = last_json(log)
                if child.returncode or replies[side].get('ok') is not True or replies[side].get('version') != 2:
                    raise ValueError('real fresh reconnect failed')
            after = statuses(INITIAL)
            for side in ('a', 'b'):
                if after[side]['session'] == before[side]['session'] or after[side]['generation'] <= before[side]['generation']:
                    raise ValueError('reconnect did not establish fresh session and generation')
            receipt.update(lifecycle={'disconnect': disconnect, 'reconnect': replies, 'before': before, 'after': after,
                'scope': 'manual fresh authentication; no retained-state or graceful-drain claim'})
            receipt.update(final_sockets=socket_observation())
            record_functional(receipt, 'after_reconnect',
                lambda: functional('reconnected', output, deadline, launch, command, receipt),
                lambda side: rpc(side, 'status', cap=2), deadline)
            sample('after-reconnect')
            if explicit_runtime and runtime_events != {
                    side: host_runtime_event(value[1], case['runtime_model']) for side, value in daemons.items()}:
                raise ObservationError('original daemon host runtime observation changed after reconnect')
    except Exception as error:
        errors.append({'status': failure_status(error), 'error': f'{type(error).__name__}: {error}'})
    finally:
        for child in reversed(processes):
            if any(child is value[0] for value in captures.values()):
                continue
            try:
                bounded.stop(child)
            except Exception as error:
                errors.append({'status': 'failed', 'cleanup': f'{type(error).__name__}: {error}'})
        # Persist every exact probe fingerprint before any capture is
        # interrupted. This witness never replaces the final stopped audit.
        try:
            native = captures.get('native-a')
            if native is not None:
                try:
                    observation = drain_native_capture(native[0], native[2], receipt.value, deadline)
                except Exception as error:
                    observation = getattr(error, 'capture_drain', {
                        'status': failure_status(error), 'original_deadline': deadline,
                        'error': f'{type(error).__name__}: {error}'[:4096]})
                    errors.append({'status': failure_status(error), 'capture': 'native-a',
                        'phase': 'capture_drain', 'error': f'{type(error).__name__}: {error}'[:4096]})
                try:
                    receipt.update(native_capture_drain=observation)
                except Exception as error:
                    errors.append({'status': failure_status(error), 'capture': 'native-a',
                        'phase': 'capture_drain_receipt', 'error': f'{type(error).__name__}: {error}'[:4096]})
        finally:
            # Drain or publication failure must not bypass any owned stop.
            for name, (child, log, capture) in captures.items():
                observation = None
                try:
                    counts = capture_counts(log, child)
                    capture_counters[name] = counts
                    observation = _capture_counter_observation(counts, child.returncode)
                    receipt.update(**{name + '_capture_counters': counts})
                except Exception as error:
                    observation = getattr(error, 'capture_counter_observation', observation)
                    errors.append({'status': failure_status(error), 'capture': name, 'error': f'{type(error).__name__}: {error}'})
                    try:
                        bounded.stop(child)
                    except Exception:
                        pass
                if observation is not None:
                    try:
                        capture_counter_observations[name] = observation
                        receipt.update(capture_counter_observations=dict(capture_counter_observations))
                    except Exception as error:
                        errors.append({'status': failure_status(error), 'capture': name,
                            'phase': 'capture_counter_observation_receipt',
                            'error': f'{type(error).__name__}: {error}'[:4096]})
        anchors.append(clock_anchor())
        if captures and public:
            try:
                clock = reference_result['clock'] if reference_result else None
                actual_case = {**case, 'public_noise': public['noise_public'], 'require_policy_epochs': True}
                audits = {name: audit_capture(value[2], actual_case, name[-1] if name.startswith('wan-') else None, anchors, clock)
                    for name, value in captures.items()}
                for name, audit in audits.items():
                    if name not in capture_counters:
                        raise ObservationError('capture has no trustworthy final tcpdump counters: ' + name)
                    capture_complete(audit, capture_counters[name], require_lossless=True)
                if not audits['native-a']['arp']:
                    raise ValueError('no actual native ARP witnessed')
                receipt.update(capture_audits=audits)
                receipt.update(native_icmp_capture=icmp_capture_complete(audits['native-a'], receipt.value))
                if reference_result:
                    receipt.update(reference_wire_window=wire_window_evidence(reference_result, audits))
            except Exception as error:
                errors.append({'status': failure_status(error), 'error': f'{type(error).__name__}: {error}'})
        try:
            if (state_dir / (spec.lab_id + '.json')).exists():
                record_tc_snapshot(receipt, spec, state_dir, command, 'tc_final')
        except Exception as error:
            errors.append({'status': failure_status(error), 'tc_final': f'{type(error).__name__}: {error}'})
        try:
            journal = state_dir / (spec.lab_id + '.json')
            if journal.exists():
                bounded.bounded_lab(lab.cleanup, spec, state_dir, time.monotonic() + BOUNDS['cleanup'])
            if any((lab.NETNS_DIRECTORY / name).exists() for name in spaces.values()):
                raise ValueError('owned namespaces remain after cleanup')
        except Exception as error:
            errors.append({'status': 'failed', 'cleanup': f'{type(error).__name__}: {error}'})
        if reference_result and reference_result['performance_acceptance']['status'] == 'failed':
            errors.append({'status': 'failed', 'error': 'measured forward goodput below existing80Mbit/s lab target'})
        status = errors[0]['status'] if errors else 'passed'
        receipt.update(status=status, errors=errors, commands=commands, status_samples=samples, clock_anchors=anchors,
            cleanup='failed' if any('cleanup' in row for row in errors) else 'passed',
            finished_monotonic_ns=time.monotonic_ns())
    return receipt.value


def worker(case: dict, output: Path, build: dict, descriptors: dict[str, int], token: str) -> int:
    _runtime_experiment(case)
    info = output.stat()
    if (output.is_symlink() or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
            or token != f'{info.st_dev}:{info.st_ino}' or Path(__file__).resolve() != output / 'secure_udp_native.py'):
        raise ValueError('fresh exclusive copied-worker directory identity required')
    verify_helpers(build, output, True)
    launch = bounded.strict_json((output / 'launch-receipt.json').read_bytes())
    original, current = launch['original_namespaces'], namespace_ids()
    verify_fresh_namespace(descriptors, original, current)
    for descriptor in descriptors.values():
        os.close(descriptor)
    if os.geteuid() != 0:
        raise ObservationError('new user namespace did not map the current user to root')
    preflight_end = time.monotonic() + 15
    links = bounded.strict_json(bounded.command(['ip', '-j', 'link', 'show'], preflight_end))
    routes = bounded.strict_json(bounded.command(['ip', '-j', 'route', 'show', 'table', 'all'], preflight_end))
    if len(links) != 1 or links[0].get('ifname') != 'lo' or routes:
        raise ValueError('new outer network namespace is not pristine loopback-only')
    # This sequence is deliberately after all three anchored namespace checks.
    bounded.command(['mount', '--make-rprivate', '/'], preflight_end)
    bounded.command(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], preflight_end)
    Path('/run/netns').mkdir(mode=0o755)
    proof = {'original': original, 'fresh': current, 'initial_links': links, 'initial_routes': routes,
             'uid_map': Path('/proc/self/uid_map').read_text(), 'euid': os.geteuid(),
             'run_mount': 'fresh tmpfs after mount --make-rprivate /'}
    result = run_case(case, output, build, proof)
    return 0 if result['status'] == 'passed' else 1


def terminate_owned_group(child: subprocess.Popen) -> None:
    """Stop the launcher's own session even if its unshare leader already exited."""
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # Descendants inherit this unique group; leader exit is not proof that they
    # have exited. No host PID discovered by name or namespace is ever adopted.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=5)


def finalize_launch_failure(output: Path, status: str, error: str) -> None:
    path = output / 'receipt.json'
    if path.exists():
        if path.is_symlink() or path.stat().st_size > bounded.RECEIPT_LIMIT:
            raise ObservationError('unsafe/oversize interrupted worker receipt')
        value = bounded.strict_json(path.read_bytes())
        if not isinstance(value, dict):
            raise ObservationError('invalid interrupted worker receipt')
        # Only reattach after the owned child group has been terminated; this is
        # the existing bounded atomic writer, preserving every worker field.
        receipt = bounded.Receipt.__new__(bounded.Receipt)
        receipt.path, receipt.value = path, value
        receipt.update(status=status, launcher_failure=error,
            worker_status_before_interruption=value.get('status'), cleanup='unverified_after_launcher_failure')
    else:
        bounded.Receipt(path, {'status': status, 'launcher_failure': error,
            'scope': 'launcher before completed native case', 'cleanup': 'not_started_or_unverified'})


def worker_file_limits():
    """Bound the worker log while permitting explicitly capped capture children."""
    soft, hard = BOUNDS['log_bytes'], BOUNDS['capture_bytes']
    if type(soft) is not int or type(hard) is not int or not 0 < soft <= hard:
        raise ObservationError('invalid worker/capture file-size bounds')
    inherited = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
    if inherited != resource.RLIM_INFINITY and inherited < hard:
        raise ObservationError('inherited RLIMIT_FSIZE hard limit cannot permit explicit capture cap')
    def apply():
        inherited = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
        if inherited != resource.RLIM_INFINITY and inherited < hard:
            raise ValueError('inherited worker file-size ceiling changed before exec')
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
    return apply


def launch_isolated(case: dict, output: Path, binary: Path, receipt_path: Path) -> int:
    explicit_runtime = _runtime_experiment(case)
    # Never adopt an existing output. Once this exclusive directory exists,
    # preflight/copy/namespace/worker failures all receive a terminal receipt.
    output.mkdir(mode=0o700)
    output = output.resolve()
    launch = bounded.Receipt(output / 'launch-receipt.json', {'status': 'starting', 'plan': case,
        'interpreter': sys.executable, 'python_version': sys.version})
    descriptors, child, original = {}, None, None
    try:
        build = bounded.verified_build_receipt(receipt_path, binary)
        for name in HELPERS:
            shutil.copyfile(Path(__file__).parent / name, output / name)
            (output / name).chmod(0o400)
        shutil.copyfile(binary, output / 'l2tunnel-native')
        (output / 'l2tunnel-native').chmod(0o500)
        shutil.copyfile(receipt_path, output / 'build-receipt.json')
        (output / 'build-receipt.json').chmod(0o400)
        helpers = verify_helpers(build, output)
        original = namespace_ids()
        launch.update(original_namespaces=original, binary_sha256=bounded.file_hash(output / 'l2tunnel-native'),
            executed_helpers=helpers)
        executable = shutil.which('unshare')
        if executable is None:
            raise FileNotFoundError('unshare')
        for name in ('user', 'net', 'mnt'):
            descriptors[name] = os.open('/proc/self/ns/' + name, os.O_RDONLY)
        identity = output.stat()
        argv = [executable, '--user', '--map-root-user', '--net', '--mount', '--fork', sys.executable,
            str(output / 'secure_udp_native.py'), '--cover', case['cover'], '--path', case['path'],
            '--workload', case['workload'], '--lab-id', case['lab_id'], '--output', str(output),
            '--binary', str(output / 'l2tunnel-native'), '--build-receipt', str(output / 'build-receipt.json'),
            '--frozen-worker', f'{identity.st_dev}:{identity.st_ino}', '--namespace-fds',
            ','.join(f'{name}:{value}' for name, value in descriptors.items()), '--apply']
        if explicit_runtime:
            argv += ['--runtime-model', case['runtime_model']]
        environment = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME')}
        environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        limits = worker_file_limits()
        launch.update(worker_file_size_limits={'unit': 'bytes', 'soft': BOUNDS['log_bytes'],
            'hard': BOUNDS['capture_bytes'], 'inherited': list(resource.getrlimit(resource.RLIMIT_FSIZE))})
        with (output / 'worker.log').open('xb') as log:
            child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, pass_fds=tuple(descriptors.values()),
                env=environment, start_new_session=True, preexec_fn=limits)
            launch.update(status='running', worker_argv=argv, worker_pid=child.pid)
            code = child.wait(timeout=BOUNDS['launcher'])
        terminate_owned_group(child)
        child = None
        result_path = output / 'receipt.json'
        result = bounded.strict_json(result_path.read_bytes()) if result_path.is_file() else None
        if result is None or result.get('status') == 'running' or code != 0 and result.get('status') == 'passed':
            finalize_launch_failure(output, 'tool_failure', 'isolated worker exited without a coherent terminal case receipt')
            result = bounded.strict_json(result_path.read_bytes())
        after = namespace_ids()
        if after != original:
            raise ValueError('launcher namespace identities changed during isolated work')
        launch.update(status=result['status'], worker_exit=code, launcher_namespaces_after=after)
        return 0 if code == 0 and result['status'] == 'passed' else 1
    except Exception as error:
        cleanup_error = None
        if child is not None:
            try:
                terminate_owned_group(child)
            except Exception as failure:
                cleanup_error = f'{type(failure).__name__}: {failure}'
        status, detail = failure_status(error), f'{type(error).__name__}: {error}'
        launch.update(status=status, error=detail, group_cleanup_error=cleanup_error,
            launcher_namespaces_after=namespace_ids())
        finalize_launch_failure(output, status, detail)
        return 1
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cover', choices=('quic-like', 'media-like'), required=True)
    parser.add_argument('--path', choices=tuple(PATHS), required=True)
    parser.add_argument('--workload', choices=('forward16', 'reverse-stress'), default='forward16')
    parser.add_argument('--runtime-model', choices=RUNTIME_MODELS)
    parser.add_argument('--lab-id', default='secureudp')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--build-receipt', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--frozen-worker', help=argparse.SUPPRESS)
    parser.add_argument('--namespace-fds', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    case = plan(args.lab_id, args.cover, args.path, args.workload,
        **({'runtime_model': args.runtime_model} if args.runtime_model is not None else {}))
    if not args.apply:
        print(json.dumps({'status': 'dry_run', 'case': case, 'mutations': 'none'}, indent=2))
        return 0
    if sys.platform != 'linux' or args.build_receipt is None:
        raise ValueError('Linux and exact source-stable build receipt required for apply')
    if args.frozen_worker:
        if args.namespace_fds is None:
            raise ValueError('original namespace descriptors required for copied worker')
        pairs = [value.split(':') for value in args.namespace_fds.split(',')]
        if len(pairs) != 3 or any(len(pair) != 2 or not pair[1].isdigit() for pair in pairs):
            raise ValueError('invalid original namespace descriptors')
        descriptors = {key: int(value) for key, value in pairs}
        build = bounded.verified_build_receipt(args.build_receipt, args.binary)
        if args.binary.resolve() != args.output.resolve() / 'l2tunnel-native' or args.build_receipt.resolve() != args.output.resolve() / 'build-receipt.json':
            raise ValueError('worker binary/receipt must be the verified private copies')
        return worker(case, args.output.resolve(), build, descriptors, args.frozen_worker)
    if args.namespace_fds:
        raise ValueError('namespace descriptors are only valid in the verified copied worker')
    return launch_isolated(case, args.output, args.binary, args.build_receipt)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as failure:
        print(json.dumps({'status': failure_status(failure), 'error': f'{type(failure).__name__}: {failure}'}), file=sys.stderr)
        raise SystemExit(1)
