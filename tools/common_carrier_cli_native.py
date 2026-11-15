#!/usr/bin/env python3
"""Explicit production Common/APIv4 OpenVPN original-carrier native functional lab."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

try:
    from . import generic_cli_native as g, common_carrier_cli_validation as v
except ImportError:
    import generic_cli_native as g
    import common_carrier_cli_validation as v

bounded, native, lab = g.bounded, g.native, g.lab
require, BOUNDS = g.require, g.BOUNDS
HELPERS = ('common_carrier_cli_native.py', 'common_carrier_cli_validation.py', *g.HELPERS)
LOADED = {'common_carrier_cli_native.py': Path(__file__),
    'common_carrier_cli_validation.py': Path(v.__file__), **g.LOADED}
PLAN_LIMIT = 256 * 1024
LIVENESS_OBSERVATION_SECONDS = 5


def public_summary(status):
    """Compact duplicate receipt projections; full original RPC logs remain."""
    def public(value):
        if isinstance(value, dict):
            return {name: public(item) for name, item in value.items()}
        if isinstance(value, list):
            if len(value) in (16, 32) and all(type(item) is int and 0 <= item <= 255 for item in value):
                return bytes(value).hex()
            return [public(item) for item in value]
        return value
    def configuration(value):
        if value is None:
            return None
        raw = bytes.fromhex(v.canonical(value))
        return {'data_digest': bytes(v.digest(value)).hex(), 'family': v.family(value),
            'envelope': raw[16:48].hex(), 'path_mtu': int.from_bytes(raw[8:16], 'big')}
    result = public({name: value for name, value in status.items()
        if name not in ('initial', 'current', 'requested', 'result', 'catalog_page')})
    for name in ('initial', 'current', 'requested'):
        if name in status:
            result[name] = configuration(status[name])
    if status.get('result') is not None:
        result['result'] = public(status['result'])
        result['result']['configuration'] = configuration(status['result']['configuration'])
    if status.get('catalog_page') is not None:
        result['catalog_page'] = public(status['catalog_page'])
        result['catalog_page']['configurations'] = [configuration(value)
            for value in status['catalog_page']['configurations']]
    return result


def response_summary(response):
    value = {name: item for name, item in response.items() if name != 'state'}
    state = response.get('state')
    value['state'] = None if state is None else {name: item for name, item in state.items() if name != 'common'}
    if state is not None and 'common' in state:
        value['state']['common'] = public_summary(state['common'])
    return value


class Owner(g.Owner):
    """Keep full CLI logs, but avoid duplicating full C in every receipt sample."""
    def sample(self, label, value):
        super().sample(label, {side: public_summary(row) for side, row in value.items()})


def read_plan(path):
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            'absolute regular Rust-canonical public Common plan required')
    with path.open('rb') as stream:
        raw = stream.read(PLAN_LIMIT + 1)
    require(0 < len(raw) <= PLAN_LIMIT, 'Common plan file exceeds bound')
    value = bounded.strict_json(raw)
    fields = {'version', 'backend', 'initial_index', 'catalog', 'transaction', 'runtime',
        'rolling_work', 'outer_carrier'}
    require(isinstance(value, dict) and set(value) == fields and type(value['version']) is int and value['version'] == 1
        and value['backend'] == 'common_records_v2', 'explicit complete Common plan required')
    catalog = value['catalog']
    require(isinstance(catalog, list) and 1 <= len(catalog) <= 64
        and all(type(item) is str and re.fullmatch('[0-9a-f]{2544}', item) for item in catalog)
        and len(set(catalog)) == len(catalog), 'complete bounded descriptor catalog required')
    require(type(value['initial_index']) is int and 0 <= value['initial_index'] < len(catalog),
            'initial outside supplied catalog')
    require(isinstance(value['outer_carrier'], dict) and value['outer_carrier'].get('version') == 1
        and value['outer_carrier'].get('backend') == 'openvpn_wire_common', 'explicit raw original carrier policy required')
    cadence = value['runtime'].get('report_interval_micros') if isinstance(value['runtime'], dict) else None
    require(type(cadence) is int and 0 < cadence < LIVENESS_OBSERVATION_SECONDS * 1_000_000,
            'explicit positive lab report cadence within original liveness observation cap required')
    # No descriptor encoder or replacement policy lives here. The real frontend
    # validates every field, inactive byte, geometry and role before startup.
    return raw, value


def plan(lab_id, cover, layer, document, source_hash):
    case = g.plan(lab_id, cover, layer)
    case.update(backend='common_records_v2', carrier='openvpn-like', api_version=4,
        transaction_plan=document, common_plan_sha256=source_hash,
        scope='production Common original-carrier CLI Linux native functional only',
        active_catalog_scope='all provided members inspected/paged; one active representative per family',
        reconnect_scope='fresh TLS/Noise session only; no retained-state recovery')
    return case


def verify_helpers(build, directory, loaded=False):
    result = {}
    for name in HELPERS:
        path = directory / name
        expected = build.get('source_sha256_after', {}).get('tools/' + name)
        require(path.is_file() and not path.is_symlink() and type(expected) is str
            and bounded.file_hash(path) == expected, 'snapshot helper differs from build: ' + name)
        if loaded:
            require(LOADED[name].resolve() == path.resolve(), 'loaded helper not immutable copy: ' + name)
        result['tools/' + name] = expected
    return result


def daemon_command(case, side, binary, secrets, plan_file, inspection=False):
    require(side in ('a', 'b') and type(inspection) is bool, 'explicit endpoint role required')
    other, action = ('b', 'connect') if side == 'a' else ('a', 'serve')
    argv = [str(binary), *(['inspect-common-transaction-plan', '--role', action] if inspection else [action]),
        '--carrier', 'openvpn-like', '--record-profile', 'common', '--udp-cover', case['cover'],
        '--common-transaction-plan', str(plan_file), '--duplex', 'full', '--compression', 'off',
        '--layer', case['layer'], '--max-packet', str(case['max_native']), '--max-path-mtu', '9000',
        '--udp-bind', g.WAN[side] + ':24440', '--udp-peer', g.WAN[other] + ':24440', '--noise-profile', 'ik',
        '--noise-private-key-file', str(secrets / f'noise-{side}.key'),
        '--noise-peer-key-file', str(secrets / f'noise-{other}.pub')]
    if side == 'a':
        argv += ['--identity', str(secrets / 'member.der'), '--ca', str(secrets / 'cert.der'),
            '--server-name', 'lab.invalid']
    else:
        argv += ['--allow-key', str(secrets / 'member.pub'), '--cert', str(secrets / 'cert.der'),
            '--key', str(secrets / 'server.der')]
    if not inspection:
        argv += ['--device', case['device'], '--session-admission-key-file', str(secrets / 'admission.key'),
            '--control-socket', str(secrets / f'control-{side}.sock')]
        if side == 'b':
            argv += ['--session-cookie-key-file', str(secrets / 'cookie.key')]
    return argv


def owner_identity(observation, expected_pid, expected_device):
    """Stable finite descriptor observations; raw fdinfo is retained separately."""
    require(isinstance(observation, dict) and type(expected_pid) is int and expected_pid > 0,
            'actual daemon identity required')
    socket_inode = g.uint(observation.get('socket_inode'), 'socket inode')
    require(socket_inode > 0 and type(observation.get('udp')) is str, 'actual socket observation absent')
    socket_owners = re.findall(r'\bpid=(\d+),fd=(\d+)\b', observation['udp'])
    require(len(socket_owners) == 1 and int(socket_owners[0][0]) == expected_pid,
            'original socket does not belong to actual daemon')
    device = observation.get('device')
    require(isinstance(device, dict) and type(device.get('fd')) is int and device['fd'] >= 0
        and device.get('target') == '/dev/net/tun' and type(device.get('info')) is str
        and len(device['info'].encode('ascii')) <= 4096, 'actual native FD observation absent')
    fields = {}
    for line in device['info'].splitlines():
        key, separator, value = line.partition(':')
        require(separator == ':' and key and key not in fields and value.strip(),
                'invalid or duplicate native FD metadata')
        fields[key] = value.strip()
    require({'pos', 'flags', 'mnt_id', 'ino', 'iff'} <= fields.keys()
        and all(re.fullmatch(r'[0-9]+', fields[name]) for name in ('pos', 'mnt_id', 'ino'))
        and re.fullmatch(r'[0-7]+', fields['flags']) is not None
        and fields['iff'] == expected_device and int(fields['mnt_id']) > 0 and int(fields['ino']) > 0,
        'missing or invalid native descriptor identity')
    # Position and flags describe descriptor state, not its identity. Keeping
    # their full original text makes any observed change available for diagnosis.
    return {'socket_inode': socket_inode, 'socket_pid': expected_pid,
        'socket_fd': int(socket_owners[0][1]), 'device_fd': device['fd'], 'target': device['target'],
        'mount_id': int(fields['mnt_id']), 'device_inode': int(fields['ino']), 'interface': fields['iff']}


def observe_owners(owner, daemons, label, observations, identities, deadline=None):
    value = g.socket_observation(owner, daemons, deadline=deadline)
    observations[label] = value
    owner.receipt.update(sockets=observations)
    identity = {side: owner_identity(value[side], daemons[side][0].pid, owner.case['device'])
        for side in ('a', 'b')}
    identities[label] = identity
    owner.receipt.update(socket_identities=identities)
    owner.check(deadline)
    return identity


def tls_credentials(owner, secrets):
    until = owner.phase(BOUNDS['command'])
    owner.command(None, 'openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-keyout', secrets / 'server.pem', '-out', secrets / 'cert.pem', '-days', '1',
        '-subj', '/CN=lab.invalid', '-addext', 'subjectAltName=DNS:lab.invalid',
        '-addext', 'basicConstraints=critical,CA:FALSE', deadline=until)
    owner.command(None, 'openssl', 'x509', '-in', secrets / 'cert.pem', '-outform', 'DER',
        '-out', secrets / 'cert.der', deadline=until)
    owner.command(None, 'openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', secrets / 'server.pem',
        '-outform', 'DER', '-out', secrets / 'server.der', deadline=until)
    for path in secrets.iterdir():
        path.chmod(0o600)
    owner.check(until)
    return {'server_name': 'lab.invalid', 'certificate_sha256': bounded.file_hash(secrets / 'cert.der'),
        'trust': 'explicit fresh DER certificate; actual TLS verifier',
        'private_material': 'owned isolated /run tmpfs only; excluded from receipt'}


def disable_native_ipv6(owner):
    """Only observed interfaces in the four freshly owned native namespaces."""
    observations = {}
    for role in ('endpoint_a', 'endpoint_b', 'host_a', 'host_b'):
        links = bounded.strict_json(owner.command(role, 'ip', '-j', 'link', 'show'))
        require(isinstance(links, list) and 1 <= len(links) <= 16, 'bounded owned native link inventory required')
        names = [item.get('ifname') if isinstance(item, dict) else None for item in links]
        require(all(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,15}', name) for name in names)
            and len(set(names)) == len(names), 'invalid observed native interface')
        require((owner.case['device'] if role.startswith('endpoint_') else 'eth0') in names,
                'selected actual native interface missing')
        keys = ['net.ipv6.conf.' + name + '.disable_ipv6' for name in ('all', 'default', *sorted(names))]
        require(len(set(keys)) == len(keys), 'observed interface collides with sysctl keys')
        row = {'interfaces': sorted(names)}
        observations[role] = row
        row['before'] = g.sysctl_values(owner.command(role, 'sysctl', *keys), keys)
        write_keys = ['net.ipv6.conf.' + name + '.disable_ipv6' for name in ('all', 'default')]
        row['write'] = g.sysctl_values(owner.command(role, 'sysctl', '-w',
            *(key + '=1' for key in write_keys)), write_keys)
        require(all(value == 1 for value in row['write'].values()), 'owned IPv6 write refused')
        row['after'] = g.sysctl_values(owner.command(role, 'sysctl', *keys), keys)
        owner.receipt.update(native_ipv6=observations)
        require(all(value == 1 for value in row['after'].values()), 'owned native IPv6 remains active')
    return observations


def topology(owner, spec, state_dir):
    case = owner.case
    bounded.bounded_lab(lab.apply, spec, state_dir, owner.deadline)
    owner.receipt.update(namespace_journal=bounded.strict_json((state_dir / (spec.lab_id + '.json')).read_bytes()),
        underlay_ipv6=bounded.disable_underlay_ipv6(case['namespaces'], owner.deadline))
    shaping, links, offloads = {}, {}, {}
    for side in ('a', 'b'):
        role = 'endpoint_' + side
        shaping[side] = native.recreate_owned_wan(case, spec, state_dir, side, owner.command)
        if case['layer'] == 'tun':
            for device in ('tap0', 'lan0', 'br-lan'):
                owner.command(role, 'ip', 'link', 'set', device, 'down')
            owner.command('host_' + side, 'ip', 'address', 'flush', 'dev', 'eth0')
            owner.command('host_' + side, 'ip', 'link', 'set', 'eth0', 'down')
            owner.command(role, 'ip', 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun')
            owner.command(role, 'ip', 'address', 'add', case['applications'][side]['address'] + '/24', 'dev', 'tun0')
            owner.command(role, 'ip', 'link', 'set', 'tun0', 'mtu', '1500', 'up')
        links[side] = bounded.strict_json(owner.command(role, 'ip', '-d', '-j', 'link', 'show', 'dev', case['device']))
        require(len(links[side]) == 1 and links[side][0].get('ifname') == case['device']
            and links[side][0].get('linkinfo', {}).get('info_kind') == 'tun'
            and links[side][0].get('linkinfo', {}).get('info_data', {}).get('type') == case['layer'],
            'actual named TAP/TUN required')
        interfaces = [(role, 'wan0'), (role, case['device'])]
        if case['layer'] == 'tap':
            interfaces += [(role, 'lan0'), ('host_' + side, 'eth0')]
        for namespace_role, interface in interfaces:
            offloads[namespace_role + '/' + interface] = bounded.offloads(
                case['namespaces'][namespace_role], interface, owner.deadline)
    for interface in ('a0', 'b0'):
        offloads['router/' + interface] = bounded.offloads(case['namespaces']['router'], interface, owner.deadline)
    owner.receipt.update(shaping=shaping, native_links=links, offloads=offloads)
    disable_native_ipv6(owner)


def run_case(case, output, build, proof):
    binary, state_dir = output / 'l2tunnel-native', Path('/run/l2tunnel-common-cli')
    receipt = bounded.Receipt(output / 'receipt.json', {'status': 'running', 'plan': case,
        'namespace_proof': proof, 'binary_sha256': bounded.file_hash(binary),
        'build_receipt_sha256': bounded.file_hash(output / 'build-receipt.json'),
        'executed_helpers': verify_helpers(build, output, True), 'cleanup': 'pending',
        'performance_qualified': False, 'retained_recovery_qualified': False})
    owner = Owner(case, output, receipt, time.monotonic() + BOUNDS['case'])
    spec, captures, phases, errors = lab.LabSpec(case['lab_id']), {}, {}, []
    sockets, identities, daemons, epochs, required_phases = {}, {}, {}, {}, set()
    try:
        for tool in ('ip', 'tc', 'ss', 'tcpdump', 'mount', 'sysctl', 'ethtool', 'openssl'):
            if shutil.which(tool) is None:
                raise FileNotFoundError(tool)
        g.credential_preflight()
        if not Path('/dev/net/tun').exists():
            raise g.Unsupported('/dev/net/tun unavailable; actual native attachment required')
        receipt.update(kernel=owner.command(None, 'uname', '-a'),
            tools={name: owner.command(None, *argv) for name, argv in
                [('ip', ('ip', '-Version')), ('tcpdump', ('tcpdump', '--version')),
                 ('openssl', ('openssl', 'version'))]})
        topology(owner, spec, state_dir)
        for surface in ('wan-a', 'wan-b', 'native-a', 'native-b'):
            path = output / (surface + '.pcap')
            child, log = owner.launch('endpoint_' + surface[-1], g.capture_command(case, surface, path),
                surface + '-capture', BOUNDS['capture_bytes'])
            captures[surface] = (child, log, path)
            owner.wait_log(child, log, 'listening on', owner.phase(5))
        with g.private_directory() as directory:
            secrets = Path(directory)
            secrets.chmod(0o700)
            require(all(len(os.fsencode(str(secrets / f'control-{side}.sock'))) < 108 for side in ('a', 'b')),
                    'private Unix control socket exceeds SUN_LEN')
            public = native.credentials(binary, secrets, owner.deadline)
            receipt.update(credentials=public, tls=tls_credentials(owner, secrets))
            plan_file = output / 'common-plan.json'
            inspected = {side: v.inspection(owner.command('endpoint_' + side,
                *daemon_command(case, side, binary, secrets, plan_file, True)), case, side) for side in ('a', 'b')}
            for key in ('requested_configuration', 'requested_envelope', 'requested_initial', 'catalog', 'configurations'):
                require(inspected['a'][key] == inspected['b'][key], 'offline role inspection differs: ' + key)
            receipt.update(inspection={side: {name: value for name, value in header.items()
                if name != 'configurations'} for side, header in inspected.items()},
                requested_catalog_configuration_sha256=[hashlib.sha256(bytes.fromhex(value)).hexdigest()
                    for value in inspected['a']['configurations']])

            def rpc(side, action, *flags, expected=0, deadline=None, version=4):
                return owner.rpc(binary, secrets, side, action, *flags, version=version,
                    expected=expected, deadline=deadline)

            def statuses(expected, epoch, label, running=True, deadline=None):
                until = owner.phase(BOUNDS['command'], deadline)
                raw = {side: rpc(side, 'status', deadline=until) for side in ('a', 'b')}
                values = {side: v.status(raw[side], case, side, public, inspected[side],
                    expected, epoch, running) for side in ('a', 'b')}
                for key in ('session', 'transcript', 'outer', 'configuration', 'catalog', 'current', 'epoch',
                            'physical_scope', 'original_carrier'):
                    require(values['a'][key] == values['b'][key], 'actual peer binding differs: ' + key)
                owner.sample(label, values)
                owner.check(until)
                return values

            def settled(expected, epoch, label):
                until = owner.phase(BOUNDS['command'])
                def ready(raw):
                    require(all(row.get('ok') is True for row in raw.values()), 'status failed during settle')
                    return all((row.get('state') or {}).get('common', {}).get('current') == expected
                        and row['state']['common'].get('epoch') == epoch
                        and row['state']['common'].get('phase') == 'idle'
                        and row['state']['common'].get('operation') is None for row in raw.values())
                owner.await_value(until, lambda end: {side: rpc(side, 'status', deadline=end)
                    for side in ('a', 'b')}, ready, .1)
                return statuses(expected, epoch, label, deadline=until)

            def liveness(expected, epoch, label):
                until = owner.phase(LIVENESS_OBSERVATION_SECONDS)
                return owner.await_value(until, lambda end: statuses(expected, epoch, label, deadline=end),
                    lambda values: all(type(row['liveness'].get('last_pong_micros')) is int
                        and row['liveness']['last_pong_micros'] > 0 for row in values.values()))

            startup = owner.phase(BOUNDS['startup'])
            for side in ('b', 'a'):
                daemons[side] = owner.launch('endpoint_' + side,
                    daemon_command(case, side, binary, secrets, plan_file), 'daemon-' + side, deadline=startup)
                if side == 'b':
                    def bound_socket(end):
                        require(daemons['b'][0].poll() is None, 'server exited before bind')
                        return owner.command('endpoint_b', 'ss', '-H', '-u', '-n', '-a', deadline=end)
                    owner.await_value(startup, bound_socket, lambda raw: ':24440' in raw, .05)
            ready_events = {}
            for side, (child, log) in daemons.items():
                owner.wait_log(child, log, '"event":"secure_udp_common_ready"', startup)
                events = [value for value in g.json_results(log) if value.get('event') == 'secure_udp_common_ready']
                require(len(events) == 1, 'one real Common readiness event required')
                ready_events[side] = events[0]
            before = statuses(None, 1, 'initial', deadline=startup)
            initial = before['a']['initial']
            require(before['a']['current'] == initial, 'initial Bank differs from actual initial')
            for side in ('a', 'b'):
                ready_status = ready_events[side].get('status') or {}
                require(all(ready_status.get(key) == before[side][key]
                    for key in ('generation', 'session', 'current', 'configuration')),
                    'ready event differs from actual IPC generation')
            receipt.update(ready={side: {**event, 'status': public_summary(event['status'])}
                for side, event in ready_events.items()})
            total = before['a']['catalog_members']
            effective = []
            next_key = before['a']['next_request_key']
            until = owner.phase(BOUNDS['command'])
            for offset in range(0, total, 4):
                reply = rpc('a', 'common-catalog', '--generation', str(before['a']['generation']),
                    '--catalog', bytes(before['a']['catalog']).hex(), '--offset', str(offset), '--limit', '4', deadline=until)
                effective.extend(v.catalog_page(reply, before['a']['generation'], before['a']['catalog'], offset, total))
                require(reply['state']['common']['next_request_key'] == next_key, 'catalog consumed request key')
            require(len(effective) == total and len(set(effective)) == total and initial in effective,
                    'effective full catalog missing/duplicated')
            require(set(map(v.family, effective)) == set(v.FAMILIES.values()), 'effective four-family catalog incomplete')
            require({name: sum(v.family(value) == name for value in effective) for name in v.FAMILIES.values()}
                == {name: sum(v.family(value) == name for value in inspected['a']['configurations'])
                    for name in v.FAMILIES.values()}, 'effective catalog changed requested family counts')
            for selected in effective:
                require(list(bytes.fromhex(selected)[16:48]) == before['a']['original_carrier']['effective_envelope'],
                        'effective catalog contains another envelope')
            receipt.update(effective_catalog=effective)
            observe_owners(owner, daemons, 'initial', sockets, identities)
            wrong = rpc('a', 'switch-common-configuration', '--configuration', inspected['a']['requested_initial'],
                '--request-key', str(next_key), expected=1)
            require(wrong.get('version') == 4 and wrong.get('ok') is False
                and wrong.get('code') == 'invalid_configuration', 'requested E0 accepted as effective C')
            unchanged = statuses(initial, 1, 'after-E0-refusal')
            require(unchanged['a']['next_request_key'] == next_key, 'E0 refusal consumed key')
            for version in (1, 2, 3):
                wrong_version = rpc('a', 'disconnect', version=version, expected=1)
                require(wrong_version == {'version': version, 'ok': False, 'code': 'requires_version_4', 'state': None},
                        'wrong API version downgraded or retried')
            representatives = [next(value for value in effective if v.family(value) == name)
                for name in v.FAMILIES.values() if name != v.family(initial)] + [initial]
            required_phases = {'initial', 'fresh-reconnected', *(f'switch-{index}' for index in range(1, len(representatives) + 1))}
            epochs[1] = int.from_bytes(bytes.fromhex(initial)[8:16], 'big')
            phases['initial'] = g.functional_phase(owner, 'initial')
            liveness(initial, 1, 'initial-pong')
            current, epoch = initial, 1
            for index, target in enumerate(representatives, 1):
                key = statuses(current, epoch, 'before-switch')['a']['next_request_key']
                flags = ('--configuration', target, '--request-key', str(key))
                until = owner.phase(BOUNDS['command'])
                result = rpc('a', 'switch-common-configuration', *flags, deadline=until)
                result_status = v.status(result, case, 'a', public, inspected['a'], target, epoch + 1)
                completed = result_status.get('result') or {}
                require(completed.get('configuration') == target and completed.get('epoch') == epoch + 1
                    and completed.get('request_key') == key and completed.get('outcome') == 'ok'
                    and type(completed.get('operation')) is int, 'actual keyed completion differs')
                replay = rpc('a', 'switch-common-configuration', *flags, deadline=until)
                require((replay.get('state') or {}).get('common', {}).get('result') == completed,
                        'idempotent replay changed retained result')
                current, epoch = target, epoch + 1
                after = settled(current, epoch, 'switched-' + str(index))
                for side in ('a', 'b'):
                    require(all(after[side][field] == before[side][field]
                        for field in ('generation', 'session', 'transcript', 'outer', 'configuration', 'catalog')),
                        'switch replaced authenticated original session')
                label = 'switch-' + str(index)
                selected_identity = observe_owners(owner, daemons, label, sockets, identities)
                require(selected_identity == identities['initial'],
                    'switch replaced socket/native owner')
                epochs[epoch] = int.from_bytes(bytes.fromhex(current)[8:16], 'big')
                phases[label] = g.functional_phase(owner, label)
                liveness(current, epoch, label + '-pong')

            def disconnect(selected, selected_epoch, label):
                until = owner.phase(BOUNDS['command'])
                replies = {'a': rpc('a', 'disconnect', deadline=until)}
                final = {'a': v.status(replies['a'], case, 'a', public, inspected['a'],
                    selected, selected_epoch, False)}
                expected_failures = {
                    ('Io(BrokenPipe)', 'Failed(Failure { kind: BrokenPipe })', 'failed'),
                    ('PeerTimeout', 'Failed(Failure { kind: TimedOut })', 'failed')}
                def actual_failure(response):
                    state = response.get('state') or {}
                    actual = state.get('common') or {}
                    require(response.get('version') == 4 and response.get('ok') is True
                        and response.get('code') == 'ok', 'peer failure status unavailable through retained API')
                    if actual.get('running') is True:
                        return False
                    require((actual.get('terminal'), actual.get('service_terminal'), state.get('phase'))
                        in expected_failures, 'unexpected controlled peer-close failure')
                    return True
                failed = owner.await_value(until, lambda end: rpc('b', 'status', deadline=end), actual_failure, .1)
                failed_status = failed['state']['common']
                stopped = (failed_status['terminal'], failed_status['service_terminal'], failed['state']['phase'])
                final['b'] = v.status(failed, case, 'b', public, inspected['b'],
                    selected, selected_epoch, False, stopped=stopped)
                owner.sample(label + '-observed-peer-failure', final)
                # An already failed backend has no active owner to abort. The
                # existing service rejects Disconnect and retains its real
                # failure; it must not be rewritten as a successful Aborted.
                replies['b'] = rpc('b', 'disconnect', expected=1, deadline=until)
                retained = v.status(replies['b'], case, 'b', public, inspected['b'],
                    selected, selected_epoch, False, stopped=stopped, reply_outcome=(False, 'state'))
                require(all(retained.get(name) == failed_status.get(name) for name in
                    ('generation', 'session', 'transcript', 'configuration', 'catalog', 'current', 'epoch',
                     'physical_scope', 'terminal', 'service_terminal', 'next_request_key')),
                    'idempotent disconnect refusal changed actual failed generation')
                owner.check(until)
                # Outer actor drop is asynchronous. Wait within this same original
                # phase cap for real socket/device release, never fabricate it.
                def released(end):
                    try:
                        return g.socket_observation(owner, daemons, False, end)
                    except ValueError as error:
                        if str(error) != 'disconnect retained original socket/native owner':
                            raise
                        return None
                released_value = owner.await_value(until, released, lambda value: value is not None, .02)
                for side, (_, log) in daemons.items():
                    owner.await_value(until, lambda end: g.json_results(log), lambda rows: any(
                        row.get('event') == 'secure_udp_common_terminal'
                        and (row.get('status') or {}).get('generation') == final[side]['generation']
                        and row['status'].get('terminal') == final[side]['terminal']
                        and row['status'].get('service_terminal') == final[side]['service_terminal'] for row in rows), .02)
                return {'replies': {side: response_summary(value) for side, value in replies.items()},
                    'status': {side: public_summary(value) for side, value in final.items()},
                    'released': released_value}

            receipt.update(disconnect=disconnect(current, epoch, 'disconnected'))
            reconnect_end = owner.phase(BOUNDS['startup'])
            reconnects = {side: owner.launch('endpoint_' + side, [binary, 'reconnect', '--control-socket',
                secrets / f'control-{side}.sock', '--api-version', '4'], 'fresh-reconnect-' + side,
                deadline=reconnect_end) for side in ('b', 'a')}
            replies = {}
            for side, (child, log) in reconnects.items():
                require(owner.wait(child, BOUNDS['startup'], reconnect_end) == 0, 'fresh reconnect command failed')
                replies[side] = native.last_json(log)
                v.status(replies[side], case, side, public, inspected[side], epoch=1)
            fresh = statuses(None, 1, 'fresh-reconnected', deadline=reconnect_end)
            fresh_initial = fresh['a']['initial']
            for side in ('a', 'b'):
                require(fresh[side]['current'] == fresh_initial and fresh[side]['generation'] > before[side]['generation']
                    and fresh[side]['session'] != before[side]['session']
                    and fresh[side]['transcript'] != before[side]['transcript']
                    and fresh[side]['original_carrier']['session'] != before[side]['original_carrier']['session']
                    and fresh[side]['original_carrier']['effective_envelope'] != before[side]['original_carrier']['effective_envelope'],
                    'fresh reconnect reused old outer/inner state')
            require(int.from_bytes(bytes.fromhex(fresh_initial)[8:16], 'big') == epochs[1], 'fresh requested MTU changed')
            observe_owners(owner, daemons, 'fresh-reconnected', sockets, identities, reconnect_end)
            phases['fresh-reconnected'] = g.functional_phase(owner, 'fresh-reconnected')
            liveness(fresh_initial, 1, 'fresh-pong')
            receipt.update(reconnect={'scope': 'fresh session',
                'replies': {side: response_summary(value) for side, value in replies.items()},
                'status': {side: public_summary(value) for side, value in fresh.items()}},
                sockets=sockets, final_disconnect=disconnect(fresh_initial, 1, 'final-disconnected'))
    except Exception as error:
        errors.append({'status': failure_status(error), 'error': f'{type(error).__name__}: {error}'[:4096]})
    finally:
        cleanup_end = owner.begin_cleanup()
        if required_phases and set(phases) == required_phases:
            try:
                receipt.update(native_capture_drain=g.drain_native_captures(captures, case, phases,
                    min(owner.deadline, cleanup_end)))
            except Exception as error:
                errors.append({'status': failure_status(error), 'capture_drain': str(error)[:4096]})
        capture_children = {child for child, _, _ in captures.values()}
        for child in reversed(owner.processes):
            if child not in capture_children:
                try:
                    g.stop_child(child, cleanup_end)
                except Exception as error:
                    errors.append({'status': failure_status(error), 'cleanup': str(error)[:4096]})
        audits, counts = {}, {}
        for surface, (child, log, path) in captures.items():
            try:
                counts[surface] = g.stopped_capture(child, log, path, cleanup_end)
                audits[surface] = (v.audit_wan(path, case, epochs) if surface.startswith('wan-')
                    else g.audit_capture(path, case, surface, epochs))
                require(audits[surface]['packets'] == counts[surface]['captured'], 'capture counter differs')
                bounded.remaining(cleanup_end, BOUNDS['cleanup'])
            except Exception as error:
                errors.append({'status': failure_status(error), 'capture': surface, 'error': str(error)[:4096]})
                try:
                    g.stop_child(child, cleanup_end)
                except Exception:
                    pass
        try:
            require(required_phases and set(phases) == required_phases, 'functional family/reconnect matrix incomplete')
            require(set(audits) == {'wan-a', 'wan-b', 'native-a', 'native-b'}, 'capture matrix incomplete')
            receipt.update(native_fingerprints=g.verify_native_fingerprints(audits, phases))
        except Exception as error:
            errors.append({'status': failure_status(error), 'error': str(error)[:4096]})
        try:
            g.cleanup_topology(spec, state_dir, cleanup_end)
        except Exception as error:
            errors.append({'status': failure_status(error), 'cleanup': str(error)[:4096]})
        receipt.update(status=errors[0]['status'] if errors else 'passed', errors=errors,
            commands=owner.commands, status_samples=owner.samples,
            phases={label: {'status': 'passed', 'functional_receipt': label + '_functional'} for label in phases},
            capture_audits=audits, capture_counters=counts,
            cleanup='failed' if any('cleanup' in row for row in errors) else 'passed',
            finished_monotonic_ns=time.monotonic_ns())
    return receipt.value


def failure_status(error):
    if isinstance(error, OSError) and error.errno == errno.EFBIG:
        return 'bound_exhausted'
    return g.failure_status(error)


def incomplete_worker_status(raw, code):
    if ('unshare: unshare failed: Operation not permitted' in raw
            or 'unshare: write failed /proc/self/uid_map: Operation not permitted' in raw):
        return 'unsupported'
    if code != 0:
        for line in reversed(raw.splitlines()):
            if not line.startswith('{'):
                continue
            try:
                value = bounded.strict_json(line)
            except (ValueError, TypeError):
                continue
            if (isinstance(value, dict) and set(value) == {'status', 'error'}
                    and value['status'] == 'bound_exhausted' and type(value['error']) is str
                    and 0 < len(value['error']) <= 4096):
                return 'bound_exhausted'
    return 'tool_failure'


def worker(case, output, build, descriptors, token):
    info = output.stat()
    require(not output.is_symlink() and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
        and token == f'{info.st_dev}:{info.st_ino}' and Path(__file__).resolve() == output / 'common_carrier_cli_native.py',
        'fresh exclusive copied worker identity required')
    verify_helpers(build, output, True)
    launch = bounded.strict_json((output / 'launch-receipt.json').read_bytes())
    current = native.namespace_ids()
    native.verify_fresh_namespace(descriptors, launch['original_namespaces'], current)
    for descriptor in descriptors.values():
        os.close(descriptor)
    if os.geteuid() != 0:
        raise g.Unsupported('fresh user namespace did not map caller to root')
    end = time.monotonic() + BOUNDS['command']
    links = bounded.strict_json(bounded.command(['ip', '-j', 'link', 'show'], end))
    routes = bounded.strict_json(bounded.command(['ip', '-j', 'route', 'show', 'table', 'all'], end))
    require(len(links) == 1 and links[0].get('ifname') == 'lo' and routes == [],
            'fresh network namespace is not pristine')
    bounded.command(['mount', '--make-rprivate', '/'], end)
    bounded.command(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], end)
    Path('/run/netns').mkdir(mode=0o755)
    proof = {'original': launch['original_namespaces'], 'fresh': current, 'initial_links': links,
        'initial_routes': routes, 'uid_map': Path('/proc/self/uid_map').read_text(),
        'euid': os.geteuid(), 'run_mount': 'fresh tmpfs after mount --make-rprivate /'}
    return 0 if run_case(case, output, build, proof)['status'] == 'passed' else 1


def observe_worker_log(path, launch):
    """Enforce the diagnostic acceptance bound separately from the process cap."""
    size = path.stat().st_size
    launch.update(worker_log_bytes=size, worker_log_limit_bytes=BOUNDS['log_bytes'])
    if size > BOUNDS['log_bytes']:
        raise native.BoundExhausted('worker diagnostic log ceiling exhausted')
    return size


def launch_isolated(case, output, binary, build_receipt, plan_bytes):
    output.mkdir(mode=0o700)
    output = output.resolve()
    launch = bounded.Receipt(output / 'launch-receipt.json', {'status': 'starting', 'plan': case,
        'interpreter': sys.executable, 'python_version': sys.version})
    descriptors, child = {}, None
    try:
        require(binary.is_absolute() and binary.is_file() and not binary.is_symlink(), 'absolute regular immutable binary required')
        build = bounded.verified_build_receipt(build_receipt, binary)
        for name in HELPERS:
            shutil.copyfile(Path(__file__).parent / name, output / name)
            (output / name).chmod(0o400)
        shutil.copyfile(binary, output / 'l2tunnel-native')
        (output / 'l2tunnel-native').chmod(0o500)
        shutil.copyfile(build_receipt, output / 'build-receipt.json')
        (output / 'build-receipt.json').chmod(0o400)
        with (output / 'common-plan.json').open('xb') as stream:
            stream.write(plan_bytes)
        (output / 'common-plan.json').chmod(0o400)
        hashes = verify_helpers(build, output)
        original = native.namespace_ids()
        launch.update(original_namespaces=original, executed_helpers=hashes,
            binary_sha256=bounded.file_hash(output / 'l2tunnel-native'),
            common_plan_sha256=bounded.file_hash(output / 'common-plan.json'))
        executable = shutil.which('unshare')
        if executable is None:
            raise FileNotFoundError('unshare')
        for name in ('user', 'net', 'mnt'):
            descriptors[name] = os.open('/proc/self/ns/' + name, os.O_RDONLY)
        identity = output.stat()
        argv = [executable, '--user', '--map-root-user', '--net', '--mount', '--fork', sys.executable,
            str(output / 'common_carrier_cli_native.py'), '--backend', 'common-openvpn',
            '--cover', case['cover'], '--layer', case['layer'], '--lab-id', case['lab_id'],
            '--common-plan', str(output / 'common-plan.json'), '--output', str(output),
            '--binary', str(output / 'l2tunnel-native'), '--build-receipt', str(output / 'build-receipt.json'),
            '--frozen-worker', f'{identity.st_dev}:{identity.st_ino}', '--namespace-fds',
            ','.join(f'{name}:{value}' for name, value in descriptors.items()), '--apply']
        environment = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME')}
        environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        limits = g.worker_limits(file_bytes=bounded.RECEIPT_LIMIT)
        with (output / 'worker.log').open('xb') as log:
            child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, pass_fds=tuple(descriptors.values()),
                env=environment, start_new_session=True, preexec_fn=limits)
            launch.update(status='running', worker_pid=child.pid, worker_argv=argv,
                worker_file_limits={'soft': bounded.RECEIPT_LIMIT, 'hard': BOUNDS['capture_bytes']},
                worker_log_limit_bytes=BOUNDS['log_bytes'])
            code = child.wait(timeout=BOUNDS['launcher'])
        native.terminate_owned_group(child)
        child = None
        observe_worker_log(output / 'worker.log', launch)
        path = output / 'receipt.json'
        result = None
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= bounded.RECEIPT_LIMIT:
            result = bounded.strict_json(path.read_bytes())
        if result is None or result.get('status') == 'running' or code != 0 and result.get('status') == 'passed':
            raw = bounded.read_log(output / 'worker.log')
            native.finalize_launch_failure(output, incomplete_worker_status(raw, code),
                'isolated Common worker did not publish a coherent terminal receipt')
            result = bounded.strict_json(path.read_bytes())
        after = native.namespace_ids()
        require(after == original, 'launcher namespace identity changed')
        launch.update(status=result['status'], worker_exit=code, launcher_namespaces_after=after)
        return 0 if code == 0 and result['status'] == 'passed' else 1
    except Exception as error:
        cleanup_error = None
        if child is not None:
            try:
                native.terminate_owned_group(child)
            except Exception as cleanup:
                cleanup_error = str(cleanup)[:4096]
        status = failure_status(error)
        detail = f'{type(error).__name__}: {error}'[:4096]
        launch.update(status=status, error=detail, group_cleanup_error=cleanup_error,
            launcher_namespaces_after=native.namespace_ids())
        native.finalize_launch_failure(output, status, detail)
        return 1
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=('common-openvpn',), required=True)
    parser.add_argument('--cover', choices=('quic-like', 'media-like'), required=True)
    parser.add_argument('--layer', choices=('tap', 'tun'), required=True)
    parser.add_argument('--common-plan', type=Path, required=True)
    parser.add_argument('--lab-id', default='commoncli')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--build-receipt', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--frozen-worker', help=argparse.SUPPRESS)
    parser.add_argument('--namespace-fds', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    raw, document = read_plan(args.common_plan)
    case = plan(args.lab_id, args.cover, args.layer, document, hashlib.sha256(raw).hexdigest())
    if not args.apply:
        print(json.dumps({'status': 'dry_run', 'mutations': 'none', 'case': case}, indent=2))
        return 0
    if sys.platform != 'linux' or args.build_receipt is None:
        raise g.Unsupported('Linux and exact source-stable build receipt required')
    if args.frozen_worker:
        require(type(args.namespace_fds) is str, 'original namespace descriptors required')
        pairs = [item.split(':') for item in args.namespace_fds.split(',')]
        require(len(pairs) == 3 and all(len(pair) == 2 and pair[1].isdigit() for pair in pairs),
                'invalid original namespace descriptor vector')
        descriptors = {name: int(value) for name, value in pairs}
        require(set(descriptors) == {'user', 'net', 'mnt'} and len(set(descriptors.values())) == 3,
                'three distinct original namespace descriptors required')
        output = args.output.resolve()
        require(args.binary.resolve() == output / 'l2tunnel-native'
            and args.build_receipt.resolve() == output / 'build-receipt.json'
            and args.common_plan.resolve() == output / 'common-plan.json', 'exact private snapshots required')
        build = bounded.verified_build_receipt(args.build_receipt, args.binary)
        return worker(case, output, build, descriptors, args.frozen_worker)
    require(args.namespace_fds is None, 'namespace descriptors belong only to verified worker')
    return launch_isolated(case, args.output, args.binary, args.build_receipt, raw)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': failure_status(error), 'error': f'{type(error).__name__}: {error}'[:4096]}), file=sys.stderr)
        raise SystemExit(1)
