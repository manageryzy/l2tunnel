#!/usr/bin/env python3
"""Owned standalone native-drain qualification. Dry-run by default; no loss test."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import random
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

try:
    from . import native_smoke as native, netns_lab, proxy_native_smoke as shared
except ImportError:
    import native_smoke as native
    import netns_lab
    import proxy_native_smoke as shared

ROOT = Path(__file__).resolve().parents[1]
BOUNDS = {'command': 60, 'authentication': 65, 'bind': 5, 'rpc': 2,
          'native_drain': 5, 'local_grace': 5, 'observation': 12, 'cleanup': 30}
RESPONSE_LIMIT = 8192
PACKET_LIMIT = 4096
FENCE_FIELDS = {'packets', 'native_bytes', 'sources', 'source_bytes'}
CARRIER_FIELDS = {'admitted_sources', 'consumed_sources', 'admitted_datagrams',
                  'admitted_ip_bytes', 'transmitted_datagrams', 'tls_messages'}
PROGRESS_FIELDS = {'accepted', 'sources_received', 'source_bytes_received', 'native_completed',
                   'native_bytes_completed', 'native_confirmed', 'native_bytes_confirmed',
                   'outbound_fragments', 'outbound_bytes', 'admission_in_flight',
                   'reassembly_messages', 'reassembly_bytes', 'pending_native_packets',
                   'pending_native_bytes'}


def strict_json(raw):
    def reject(value):
        raise ValueError('non-finite JSON number: ' + value)
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate JSON field: ' + key)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError('missing or unknown structured fields')


def unsigned(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('counter outside u64')


def counters(value, expected):
    fields(value, expected)
    for item in value.values():
        unsigned(item)


def octets(value, count):
    if not isinstance(value, list) or len(value) != count or any(type(n) is not int or not 0 <= n <= 255 for n in value):
        raise ValueError('invalid identity byte array')


def validate_binding(value, duplex):
    if duplex == 'full':
        fields(value, {'kind', 'session', 'config'})
        if value['kind'] != 'full': raise ValueError('expected full identity')
        octets(value['session'], 16)
        octets(value['config'], 32)
    elif duplex == 'half':
        fields(value, {'kind', 'pair', 'configs'})
        if value['kind'] != 'paired' or not isinstance(value['configs'], list) or len(value['configs']) != 2:
            raise ValueError('expected actual paired identity')
        octets(value['pair'], 32)
        for config in value['configs']: octets(config, 32)
    else:
        raise ValueError('unknown duplex')


def validate_snapshot(response, duplex, binding=None):
    fields(response, {'version', 'ok', 'code', 'state'})
    if type(response['version']) is not int or response['version'] != 1 or type(response['ok']) is not bool or response['code'] not in ('ok', 'accepted', 'already_accepted', 'closed'):
        raise ValueError('invalid response envelope')
    if response['ok'] != (response['code'] != 'closed'):
        raise ValueError('inconsistent response result')
    state = response['state']
    fields(state, {'epoch', 'phase', 'compression', 'openvpn_drain'})
    if type(state['epoch']) is not int or state['epoch'] != 1 or state['compression'] != 'off':
        raise ValueError('invalid native profile wrapper')
    value = state['openvpn_drain']
    fields(value, {'binding', 'drain_accepted', 'terminal'})
    validate_binding(value['binding'], duplex)
    if binding is not None and value['binding'] != binding:
        raise ValueError('actual authenticated binding changed')
    if type(value['drain_accepted']) is not bool:
        raise ValueError('invalid acceptance')
    terminal = value['terminal']
    phase = 'terminal' if terminal is not None else ('drain_accepted' if value['drain_accepted'] else 'running')
    if state['phase'] != phase: raise ValueError('phase does not match actual outcome')
    if terminal is None:
        if response['code'] == 'closed': raise ValueError('closed without terminal')
        return value
    if not isinstance(terminal, dict): raise ValueError('invalid terminal')
    if terminal.get('kind') == 'closed':
        fields(terminal, {'kind', 'report'})
        report = terminal['report']
        fields(report, {'local', 'peer', 'carrier'})
        counters(report['local'], FENCE_FIELDS)
        counters(report['peer'], FENCE_FIELDS)
        carrier = report['carrier']
        fields(carrier, {'kind', 'lanes'})
        if carrier['kind'] != ('full' if duplex == 'full' else 'paired'):
            raise ValueError('carrier cardinality mismatch')
        lanes = [carrier['lanes']] if duplex == 'full' else carrier['lanes']
        if not isinstance(lanes, list) or len(lanes) != (1 if duplex == 'full' else 2):
            raise ValueError('carrier lane count mismatch')
        for lane in lanes: counters(lane, CARRIER_FIELDS)
    elif terminal.get('kind') == 'failed':
        fields(terminal, {'kind', 'error', 'progress'})
        error = terminal['error']
        fields(error, {'kind', 'raw_os_error', 'diagnostic'})
        if error['kind'] not in ('timed_out', 'broken_pipe', 'unexpected_eof', 'invalid_data', 'invalid_input', 'permission_denied', 'connection_reset', 'other'):
            raise ValueError('unknown failure class')
        if error['raw_os_error'] is not None and (type(error['raw_os_error']) is not int or not -(2**31) <= error['raw_os_error'] < 2**31):
            raise ValueError('invalid errno')
        if not isinstance(error['diagnostic'], str) or len(error['diagnostic'].encode()) > 512:
            raise ValueError('diagnostic bound')
        progress = terminal['progress']
        fields(progress, PROGRESS_FIELDS)
        counters(progress['accepted'], FENCE_FIELDS)
        if type(progress['admission_in_flight']) is not bool: raise ValueError('invalid pending flag')
        for key in PROGRESS_FIELDS - {'accepted', 'admission_in_flight'}: unsigned(progress[key])
    elif terminal.get('kind') == 'cancelled':
        fields(terminal, {'kind'})
    else:
        raise ValueError('unknown terminal')
    return value


def verify_closures(responses, duplex):
    fields(responses, {'a', 'b'})
    a = validate_snapshot(responses['a'], duplex)
    b = validate_snapshot(responses['b'], duplex, a['binding'])
    if not a['drain_accepted'] or b['drain_accepted']:
        raise ValueError('one-sided local acceptance required')
    reports = {}
    for side, value in [('a', a), ('b', b)]:
        if value['terminal'] is None or value['terminal']['kind'] != 'closed':
            raise ValueError('acceptance or non-clean terminal is not native closure')
        report = value['terminal']['report']
        lanes = [report['carrier']['lanes']] if duplex == 'full' else report['carrier']['lanes']
        if sum(l['admitted_sources'] for l in lanes) != report['local']['sources'] or sum(l['consumed_sources'] for l in lanes) != report['peer']['sources']:
            raise ValueError('carrier source fences disagree')
        if any(not l['tls_messages'] or not l['transmitted_datagrams'] or not l['admitted_datagrams'] or l['admitted_ip_bytes'] < l['admitted_datagrams'] for l in lanes):
            raise ValueError('missing physical/control progress')
        if duplex == 'half':
            outgoing = 0 if side == 'a' else 1
            if lanes[1 - outgoing]['admitted_sources'] or lanes[outgoing]['consumed_sources']:
                raise ValueError('paired bulk direction mismatch')
        if any(not count for fence in (report['local'], report['peer']) for count in fence.values()):
            raise ValueError('positive bidirectional traffic required')
        reports[side] = report
    if reports['a']['local'] != reports['b']['peer'] or reports['b']['local'] != reports['a']['peer']:
        raise ValueError('cross-peer native/source fences disagree')
    return reports


def remaining(deadline, cap, clock=time.monotonic):
    value = min(deadline - clock(), cap)
    if value <= 0: raise TimeoutError('original observation deadline exhausted')
    return value


def proof_deadline(global_deadline, last_nonterminal_start):
    return min(global_deadline, last_nonterminal_start + BOUNDS['local_grace'])


def command(argv, deadline, cap=60):
    # Main-thread setup children have file-size limits. Observer threads spawn only
    # our bounded proof helper; avoid unsafe preexec callbacks in a threaded parent.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run(argv, stdout=out, stderr=err, check=False,
                                timeout=remaining(deadline, cap),
                                preexec_fn=(shared.limited_child(shared.LOG_LIMIT)
                                            if threading.current_thread() is threading.main_thread() else None))
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(shared.LOG_LIMIT + 1), err.read(shared.LOG_LIMIT + 1)
    remaining(deadline, cap)
    if len(stdout) > shared.LOG_LIMIT or len(stderr) > shared.LOG_LIMIT:
        raise ValueError('bounded command log exhausted')
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {argv!r}\n{stdout.decode(errors="replace")}{stderr.decode(errors="replace")}')
    return stdout.decode()


def socket_identity(path):
    info = Path(path).lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('private Unix socket identity/mode mismatch')
    return {'dev': info.st_dev, 'ino': info.st_ino, 'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}


def rpc(path, action, deadline, identity=None):
    end = min(deadline, time.monotonic() + BOUNDS['rpc'])
    if identity is not None and socket_identity(path) != identity:
        raise ValueError('original local socket replaced')
    payload = json.dumps({'version': 1, 'action': {'command': action}}, separators=(',', ':')).encode()
    if len(payload) > 4096: raise ValueError('request limit')
    def read(stream, length):
        output = bytearray()
        while len(output) < length:
            stream.settimeout(remaining(end, BOUNDS['rpc']))
            chunk = stream.recv(length - len(output))
            if not chunk: raise ValueError('truncated local response')
            output.extend(chunk)
        return bytes(output)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(remaining(end, BOUNDS['rpc']))
        stream.connect(str(path))
        stream.sendall(struct.pack('!I', len(payload)) + payload)
        count, = struct.unpack('!I', read(stream, 4))
        if not 0 < count <= RESPONSE_LIMIT: raise ValueError('response limit')
        value = strict_json(read(stream, count))
    remaining(end, BOUNDS['rpc'])
    if identity is not None and socket_identity(path) != identity:
        raise ValueError('original local socket replaced during RPC')
    return value


def process_identity(pid):
    with Path(f'/proc/{pid}/stat').open() as stream:
        text = stream.read(65537)
    if len(text) > 65536 or ')' not in text: raise ValueError('invalid process stat')
    tail = text[text.rfind(')') + 2:].split()
    if len(tail) < 20 or tail[0] == 'Z': raise ValueError('missing/live process identity')
    return {'pid': pid, 'start_ticks': int(tail[19]), 'netns_inode': Path(f'/proc/{pid}/ns/net').stat().st_ino}


def parse_udp_table(text):
    if len(text) > 1024 * 1024: raise ValueError('UDP table bound')
    rows = []
    for line in text.splitlines()[1:]:
        columns = line.split()
        if len(columns) < 10: raise ValueError('malformed UDP table')
        address, port = columns[1].split(':')
        if len(address) != 8: raise ValueError('expected IPv4 table')
        rows.append((str(ipaddress.IPv4Address(bytes.fromhex(address)[::-1])), int(port, 16), int(columns[9])))
    return rows


def udp_owned(identity, tuples):
    if process_identity(identity['pid']) != identity: raise ValueError('original process replaced')
    sockets = set()
    import itertools
    descriptors = list(itertools.islice(Path(f'/proc/{identity["pid"]}/fd').iterdir(), 4097))
    if len(descriptors) > 4096: raise ValueError('descriptor observation bound')
    for descriptor in descriptors:
        try: value = os.readlink(descriptor)
        except FileNotFoundError: continue
        match = re.fullmatch(r'socket:\[(\d+)\]', value)
        if match: sockets.add(int(match[1]))
    with Path(f'/proc/{identity["pid"]}/net/udp').open() as stream:
        rows = parse_udp_table(stream.read(1024 * 1024 + 1))
    return [{'address': a, 'port': p, 'inode': inode} for a, p, inode in rows
            if inode in sockets and (a, p) in {tuple(v) for v in tuples}]


def prove_released(identity, tuples, path, local_identity, expected, duplex, deadline):
    if Path('/proc/self/ns/net').stat().st_ino != identity['netns_inode']:
        raise ValueError('proof must run in original owned network namespace')
    original = udp_owned(identity, tuples)
    if original: raise ValueError('original UDP sockets remain owned')
    with contextlib.ExitStack() as stack:
        bound = []
        for address, port in tuples:
            remaining(deadline, BOUNDS['rpc'])
            probe = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            # Intentionally never set REUSEADDR/REUSEPORT; all lane sockets overlap in lifetime.
            probe.bind((address, port))
            bound.append(list(probe.getsockname()))
        final = rpc(path, 'status', deadline, local_identity)
        value = validate_snapshot(final, duplex, expected['binding'])
        if final['code'] != 'ok': raise ValueError('status command result mismatch')
        if value != expected or value['terminal'] is None or value['terminal']['kind'] != 'closed':
            raise ValueError('terminal changed during original-socket proof')
        if process_identity(identity['pid']) != identity: raise ValueError('daemon exited during local-only proof')
        remaining(deadline, BOUNDS['rpc'])
        return {'identity': identity, 'original_udp_owned': original, 'simultaneous_binds': bound,
                'local_socket': local_identity, 'final_response': final, 'completed_at': time.monotonic()}


def namespace_observation(spec):
    """Read expected-name identities only; this never adopts namespace ownership."""
    result = {}
    for name in spec.namespaces.values():
        try:
            info = (netns_lab.NETNS_DIRECTORY / name).lstat()
        except FileNotFoundError:
            result[name] = None
        else:
            result[name] = {'device': info.st_dev, 'inode': info.st_ino,
                            'mode': stat.S_IFMT(info.st_mode)}
    return result


def namespace_changes(before, after):
    """New/replaced/residual names are evidence failures, never deletion targets."""
    if before is None or set(before) != set(after):
        raise ValueError('incomplete original expected-namespace observation')
    return {name: {'before': before[name], 'after': after[name]}
            for name in before if before[name] != after[name]}


def cleanup_all(actions):
    errors = []
    for name, action in actions:
        try: action()
        except Exception as error: errors.append({'step': name, 'error': str(error)[:4096]})
    return errors


def case_plan(lab_id, layer, duplex):
    if layer not in ('tap', 'tun') or duplex not in ('full', 'half'):
        raise ValueError('only explicit TAP/TUN full/half native drain')
    spec = netns_lab.LabSpec(lab_id)
    return {'case': f'{layer}-{duplex}-clean-native-drain', 'lab_id': lab_id,
            'namespaces': spec.namespaces, 'layer': layer, 'duplex': duplex,
            'bounds_seconds': BOUNDS, 'path_mtu': 1200,
            'initial_topology_commands': netns_lab.plan_document(spec)['commands'],
            'udp_tuples': {side: [[address, p] for p in ([24440] if duplex == 'full' else [24440, 24441])]
                           for side, address in [('a', '192.0.2.2'), ('b', '192.0.2.6')]},
            'scope': 'clean native/source fences and retained original UDP closure; no outage qualification',
            'mutations_require': 'explicit apply plus reviewed immutable build and fresh owned namespace journal'}


def daemon_commands(plan, binary, secrets):
    common = ['--layer', plan['layer'], '--duplex', plan['duplex'], '--compression', 'off',
              '--device', 'tun0' if plan['layer'] == 'tun' else 'tap0', '--carrier', 'openvpn-like',
              '--udp-protection', 'aead', '--path-mtu', '1200', '--openvpn-close-profile', 'native-drain',
              '--openvpn-drain-timeout-ms', '5000', '--openvpn-stats-ms', '250',
              '--admission-key-file', str(secrets / 'admission.raw')]
    result = {}
    for side in ('a', 'b'):
        opposite = 'b' if side == 'a' else 'a'
        tuples, peers = plan['udp_tuples'][side], plan['udp_tuples'][opposite]
        argv = ['ip', 'netns', 'exec', plan['namespaces'][f'endpoint_{side}'], str(binary),
                'connect' if side == 'a' else 'serve', *common,
                '--control-socket', str(secrets / (side + '.sock'))]
        for index, (local, peer) in enumerate(zip(tuples, peers, strict=True)):
            prefix = '--udp-' if index == 0 else '--udp-reverse-'
            argv += [prefix + 'bind', f'{local[0]}:{local[1]}', prefix + 'peer', f'{peer[0]}:{peer[1]}']
        argv += (['--ca', str(secrets / 'cert.der'), '--server-name', 'lab.invalid', '--identity', str(secrets / 'member.der')]
                 if side == 'a' else ['--cert', str(secrets / 'cert.der'), '--key', str(secrets / 'server.der'),
                                      '--allow-key', str(secrets / 'member.pub'), '--cookie-key-file', str(secrets / 'cookie.raw')])
        result[side] = argv
    return result


def observe_endpoint(side, process, path, local_identity, identity, plan, harness,
                     output, armed, start, cancel, shared_deadline, events):
    """One bounded observer never waits for its sibling's terminal or proof."""
    try:
        at = time.monotonic()
        initial = rpc(path, 'status', at + BOUNDS['rpc'], local_identity)
        initial_value = validate_snapshot(initial, plan['duplex'])
        if initial['code'] != 'ok': raise ValueError('status command result mismatch')
        if initial_value['terminal'] is not None or initial_value['drain_accepted']:
            raise ValueError('observer must prearm before drain')
        last_live = at
        armed.put((side, initial))
        if not start.wait(BOUNDS['rpc']) or cancel.is_set():
            raise TimeoutError('observer activation failed')
        deadline = shared_deadline['end']
        while not cancel.is_set():
            if process.poll() is not None: raise RuntimeError('daemon exited before terminal proof')
            query_start = time.monotonic()
            response = rpc(path, 'status', deadline, local_identity)
            value = validate_snapshot(response, plan['duplex'], initial_value['binding'])
            if response['code'] != 'ok': raise ValueError('status command result mismatch')
            if side == 'b' and value['drain_accepted']: raise ValueError('peer accepted a local request')
            if value['terminal'] is not None:
                events.put(('terminal', side, {'response': response, 'observed_at': time.monotonic(),
                                               'last_nonterminal_query_start': last_live}))
                if value['terminal']['kind'] != 'closed': raise ValueError('actual non-clean native terminal')
                end = proof_deadline(deadline, last_live)
                remaining(end, BOUNDS['rpc'])
                request = {'identity': identity, 'tuples': plan['udp_tuples'][side], 'path': str(path),
                           'local_identity': local_identity, 'expected': value,
                           'duplex': plan['duplex'], 'deadline': end}
                proof = strict_json(command(['ip', 'netns', 'exec', plan['namespaces'][f'endpoint_{side}'],
                                      'python3', str(harness), 'proof', json.dumps(request, separators=(',', ':'))],
                                      end, BOUNDS['rpc']))
                events.put(('proof', side, proof))
                return
            last_live = query_start
            if cancel.wait(min(0.02, remaining(deadline, 0.02))): return
        raise RuntimeError('observer cancelled')
    except Exception as error:
        events.put(('error', side, {'error': str(error)[:4096]}))
    finally:
        events.put(('done', side, {}))


def drain_observation(plan, binary, harness, output, secrets, processes, identities, evidence):
    armed, events = queue.Queue(maxsize=4), queue.Queue(maxsize=16)
    start, cancel = threading.Event(), threading.Event()
    deadline = {}
    paths = {side: secrets / (side + '.sock') for side in ('a', 'b')}
    local = {side: socket_identity(path) for side, path in paths.items()}
    threads = [threading.Thread(target=observe_endpoint, name='native-drain-' + side,
               args=(side, processes[side], paths[side], local[side], identities[side], plan,
                     harness, output, armed, start, cancel, deadline, events)) for side in ('a', 'b')]
    initial, terminals, proofs, errors = {}, {}, {}, []
    first_error = None
    try:
        prearm = time.monotonic() + BOUNDS['rpc']
        for thread in threads: thread.start()
        for _ in threads:
            side, value = armed.get(timeout=remaining(prearm, BOUNDS['rpc']))
            initial[side] = value
        if initial['a']['state']['openvpn_drain']['binding'] != initial['b']['state']['openvpn_drain']['binding']:
            raise ValueError('prearmed actual peer bindings disagree')
        evidence.record('prearmed_observers', {'responses': initial, 'local_sockets': local})
        deadline['start'] = time.monotonic()
        deadline['end'] = deadline['start'] + BOUNDS['observation']
        start.set()
        first = rpc(paths['a'], 'drain_open_vpn', deadline['end'], local['a'])
        state = validate_snapshot(first, plan['duplex'], initial['a']['state']['openvpn_drain']['binding'])
        evidence.record('first_action', {'response': first, 'started_at': deadline['start'], 'deadline': deadline['end'], 'completed_at': time.monotonic()})
        if not first['ok'] or first['code'] != 'accepted' or not state['drain_accepted']:
            raise ValueError('first local request was not accepted exactly once')
        if state['terminal'] is None:
            repeat = rpc(paths['a'], 'drain_open_vpn', deadline['end'], local['a'])
            repeated = validate_snapshot(repeat, plan['duplex'], state['binding'])
            if repeat['code'] not in ('already_accepted', 'closed') or not repeated['drain_accepted']:
                raise ValueError('retry did not preserve one-shot acceptance')
            evidence.record('repeat_action', repeat)
        done = set()
        while len(done) < 2:
            kind, side, value = events.get(timeout=remaining(deadline['end'], BOUNDS['observation']))
            if kind == 'terminal':
                terminals[side] = value
                evidence.record('terminals', terminals)
            elif kind == 'proof':
                proofs[side] = value
                evidence.record('socket_proofs', proofs)
            elif kind == 'error':
                errors.append({'side': side, **value})
                evidence.record('observer_errors', errors)
            elif kind == 'done': done.add(side)
        if errors: raise RuntimeError('endpoint observation failed: ' + json.dumps(errors))
        if set(proofs) != {'a', 'b'}: raise ValueError('both independent socket proofs required')
        reports = verify_closures({side: v['response'] for side, v in terminals.items()}, plan['duplex'])
        exits = {}
        # Waiting sequentially is safe only now: local grace proof is already independent.
        for side in ('a', 'b'):
            exits[side] = processes[side].wait(timeout=remaining(deadline['end'], BOUNDS['observation']))
            evidence.record('daemon_exit_codes', exits)
            if exits[side] != 0: raise RuntimeError('daemon did not exit zero without a signal')
        remaining(deadline['end'], BOUNDS['observation'])
        evidence.record('drain_complete', {'reports': reports, 'completed_at': time.monotonic(), 'deadline': deadline['end']})
    except Exception as error:
        first_error = error
    finally:
        cancel.set(); start.set()
        # Helpers/RPCs own at most 2 s; cleanup waits are never protocol success evidence.
        join_end = time.monotonic() + BOUNDS['rpc'] + 0.1
        for thread in threads:
            if thread.ident is not None: thread.join(max(0, join_end - time.monotonic()))
        alive = [thread.name for thread in threads if thread.is_alive()]
        if alive and first_error is None: first_error = RuntimeError('bounded observers did not stop: ' + repr(alive))
        retained_events = []
        while not events.empty(): retained_events.append(events.get_nowait())
        if retained_events: evidence.record('observer_cleanup_events', retained_events)
        evidence.record('observer_join', {'alive': alive, 'protocol_deadline': deadline.get('end')})
    if first_error is not None: raise first_error


def wait_bound(process, identity, tuples, deadline):
    end = min(deadline, time.monotonic() + BOUNDS['bind'])
    while True:
        if process.poll() is not None: raise RuntimeError('daemon exited before fixed UDP binds')
        value = udp_owned(identity, tuples)
        if {(v['address'], v['port']) for v in value} == {tuple(v) for v in tuples}: return value
        time.sleep(min(0.02, remaining(end, 0.02)))


def setup_native(plan, evidence):
    ns = plan['namespaces']
    observations = {}
    for role, interface in [('endpoint_a', 'wan0'), ('endpoint_b', 'wan0'), ('router', 'a0'), ('router', 'b0')]:
        end = time.monotonic() + BOUNDS['command']
        command(['ip', '-n', ns[role], 'link', 'set', interface, 'mtu', '1200'], end)
        link = strict_json(command(['ip', '-n', ns[role], '-j', 'link', 'show', interface], end))
        if len(link) != 1 or link[0]['mtu'] != 1200: raise ValueError('effective path MTU mismatch')
        observations[role + '/' + interface] = {'link': link, 'offloads': shared.offloads(ns[role], interface, end)}
        evidence.record('effective_underlay', observations)
    for side, number in [('a', '1'), ('b', '2')]:
        end = time.monotonic() + BOUNDS['command']
        prefix = ['ip', '-n', ns[f'endpoint_{side}']]
        command(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], 'tc', 'qdisc', 'change', 'dev', 'wan0',
                 'parent', '1:10', 'handle', '10:', 'netem', 'limit', '1000', 'delay', '1ms', 'loss', 'random', '0%'], end)
        if plan['layer'] == 'tun':
            command([*prefix, 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun'], end)
            command([*prefix, 'link', 'set', 'tun0', 'mtu', '1500', 'up'], end)
            command([*prefix, 'address', 'add', f'198.19.0.{number}/24', 'dev', 'tun0'], end)
            command([*prefix, '-6', 'address', 'add', f'fd42:12:19::{number}/64', 'dev', 'tun0', 'nodad'], end)
        else:
            command(['ip', '-n', ns[f'host_{side}'], '-6', 'address', 'add', f'fd42:12:18::{number}/64', 'dev', 'eth0', 'nodad'], end)


def positive_probes(plan, output, processes, evidence):
    ns = plan['namespaces']
    layer = plan['layer']
    network, network6 = ('198.19.0.', 'fd42:12:19::') if layer == 'tun' else ('198.18.0.', 'fd42:12:18::')
    origin = {side: ns[('endpoint_' if layer == 'tun' else 'host_') + side] for side in ('a', 'b')}
    values = []
    for family in (4, 6):
        for side, number in [('a', '2'), ('b', '1')]:
            for size in ((56, 1200) if family == 4 else (1200,)):
                for attempt in range(3):
                    address = (network if family == 4 else network6) + number
                    argv = ['ip', 'netns', 'exec', origin[side], 'ping', *(['-6'] if family == 6 else []),
                            '-n', '-c', '1', '-W', '30', '-s', str(size), address]
                    result = command(argv, time.monotonic() + 35, 35)
                    native.verify_ping(result, expected=1)
                    values.append({'family': family, 'side': side, 'payload_bytes': size, 'attempt': attempt, 'stdout': result})
                    evidence.record('positive_pings', values)
    address = network + '2'
    log = output / 'tcp-server.log'
    server = shared.launch(['ip', 'netns', 'exec', origin['b'], 'python3', str(output / 'tcp_probe.py'), 'listen', address], log)
    processes.append(server)
    shared.wait_log(server, log, 'Listening', time.monotonic() + 5)
    result = command(['ip', 'netns', 'exec', origin['a'], 'python3', str(output / 'tcp_probe.py'), 'send', address], time.monotonic() + 50, 50)
    evidence.record('tcp_sender_stdout', result)
    value = strict_json(result)
    expected = hashlib.sha256(random.Random(0x12AA).randbytes(65536)).hexdigest()
    if value.get('status') != 'passed' or value.get('bytes') != 65536 or value.get('sha256') != expected:
        raise ValueError('native TCP exact payload hash mismatch')
    if server.wait(timeout=5) != 0: raise RuntimeError('TCP producer failed')
    evidence.record('tcp_payload', value)


def provision(binary, secrets):
    commands = [
        [str(binary), 'keygen', '--private', str(secrets / 'member.der'), '--public', str(secrets / 'member.pub')],
        [str(binary), 'openvpn-keygen', '--admission', str(secrets / 'admission.raw'), '--cookie', str(secrets / 'cookie.raw')],
        ['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(secrets / 'server.pem'), '-out', str(secrets / 'cert.pem'), '-days', '1', '-subj', '/CN=lab.invalid', '-addext', 'subjectAltName=DNS:lab.invalid', '-addext', 'basicConstraints=critical,CA:FALSE'],
        ['openssl', 'x509', '-in', str(secrets / 'cert.pem'), '-outform', 'DER', '-out', str(secrets / 'cert.der')],
        ['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(secrets / 'server.pem'), '-outform', 'DER', '-out', str(secrets / 'server.der')],
    ]
    for argv in commands: command(argv, time.monotonic() + BOUNDS['command'])


def run_case(plan, binary, harness, output, secrets, state_dir, evidence):
    spec = netns_lab.LabSpec(plan['lab_id'])
    ns = spec.namespaces
    processes, filters, captures = [], [], []
    success, failure = False, None
    stages = {name: 'unrun' for name in ('namespace_setup', 'underlay', 'authentication', 'positive_probes', 'native_drain', 'capture_audit')}
    def stage(name):
        for previous in stages:
            if stages[previous] == 'running': stages[previous] = 'passed'
        stages[name] = 'running'
        evidence.record('stages', stages)
    applied = False
    names_before = None
    journal = state_dir / (spec.lab_id + '.json')
    journal_preexisted = journal.exists() or journal.is_symlink()
    try:
        stage('namespace_setup')
        names_before = namespace_observation(spec)
        evidence.record('expected_namespaces_before', names_before)
        # apply owns its rollback journal even on a partial setup failure.
        shared.bounded_lab(netns_lab.apply, spec, state_dir, time.monotonic() + BOUNDS['command'])
        applied = True
        evidence.record('namespace_journal', strict_json((state_dir / (spec.lab_id + '.json')).read_bytes()))
        stage('underlay')
        setup_native(plan, evidence)
        tcp_block = {}
        for side, peer in [('a', '192.0.2.6'), ('b', '192.0.2.2')]:
            prefix = ['ip', 'netns', 'exec', ns['endpoint_' + side]]
            end = time.monotonic() + BOUNDS['command']
            command([*prefix, 'tc', 'qdisc', 'add', 'dev', 'wan0', 'clsact'], end)
            filters.append(prefix)
            command([*prefix, 'tc', 'filter', 'add', 'dev', 'wan0', 'egress', 'protocol', 'ip', 'pref', '1', 'u32', 'match', 'ip', 'protocol', '6', '0xff', 'action', 'drop'], end)
            probe = command([*prefix, 'python3', '-c', 'import socket,sys\ns=socket.socket();s.settimeout(.3)\ntry:s.connect((sys.argv[1],24440))\nexcept TimeoutError:print("TCP blocked by timeout")\nelse:raise RuntimeError("TCP reachable")\nfinally:s.close()', peer], end)
            rule = command([*prefix, 'tc', '-s', 'filter', 'show', 'dev', 'wan0', 'egress', 'pref', '1'], end)
            if not any(int(n) for n in re.findall(r'dropped\s+(\d+)', rule)): raise ValueError('owned SYN drop not observed')
            tcp_block[side] = {'probe': probe, 'rule': rule}
            evidence.record('tcp_block', tcp_block)
            pcap, diagnostic = output / (side + '.pcap'), output / (side + '-capture.log')
            capture = shared.start_capture([*prefix, 'tcpdump', '-U', '-n', '-i', 'wan0', '-s', '0', '-c', str(PACKET_LIMIT), '-w', str(pcap), 'udp and (port 24440 or port 24441)'], diagnostic, end)
            captures.append((side, capture, pcap, diagnostic))
            evidence.record('capture_ready', [side for side, *_ in captures])
        stage('authentication')
        argv = daemon_commands(plan, binary, secrets)
        daemons, identities, binds = {}, {}, {}
        authenticated_end = time.monotonic() + BOUNDS['authentication']
        for side in ('b', 'a'):
            log = output / (side + '-daemon.log')
            process = shared.launch(argv[side], log)
            daemons[side] = process; processes.append(process)
            # ip netns exec has not necessarily completed its namespace transition yet.
            end = min(authenticated_end, time.monotonic() + BOUNDS['bind'])
            wanted = Path('/run/netns/' + ns['endpoint_' + side]).stat().st_ino
            while True:
                identity = process_identity(process.pid)
                if identity['netns_inode'] == wanted: break
                time.sleep(min(.01, remaining(end, .01)))
            identities[side] = identity
            binds[side] = wait_bound(process, identity, plan['udp_tuples'][side], end)
            evidence.record('original_processes_and_binds', {'identities': identities, 'binds': binds})
        for side in ('a', 'b'):
            shared.wait_log(daemons[side], output / (side + '-daemon.log'), 'Authenticated', authenticated_end)
            response = rpc(secrets / (side + '.sock'), 'status', authenticated_end)
            state = validate_snapshot(response, plan['duplex'])
            if state['terminal'] is not None or state['drain_accepted']: raise ValueError('non-running authenticated endpoint')
            evidence.record('authenticated_' + side, response)
            established = command(['ip', 'netns', 'exec', ns['endpoint_' + side], 'ss', '-Htn', 'state', 'established'], authenticated_end, 2)
            if established.strip(): raise ValueError('outer established TCP connection')
        stage('positive_probes')
        positive_probes(plan, output, processes, evidence)
        stage('native_drain')
        drain_observation(plan, binary, harness, output, secrets, daemons, identities, evidence)
        stage('capture_audit')
        audits = {}
        for side, capture, pcap, diagnostic in captures:
            counts = shared.finish_capture(capture, diagnostic)
            if counts['captured'] >= PACKET_LIMIT: raise ValueError('capture packet limit exhausted')
            if pcap.stat().st_size > shared.CAPTURE_LIMIT: raise ValueError('capture byte limit')
            audits[side] = {'counts': counts, 'sha256': shared.file_hash(pcap),
                            'audit': native.audit_openvpn_capture(pcap.read_bytes(), 1200, plan['duplex'])}
            if audits[side]['audit']['packets'] != counts['captured']: raise ValueError('capture count mismatch')
            evidence.record('capture_audits', audits)
        stages['capture_audit'] = 'passed'
        evidence.record('stages', stages)
        success = True
    except Exception as error:
        failure = str(error)[:4096]
        for name in stages:
            if stages[name] == 'running': stages[name] = 'failed'
        evidence.record('stages', stages)
        evidence.update(status='failed', error=failure)
    finally:
        actions = [(f'process-{p.pid}', lambda p=p: shared.stop(p)) for p in reversed(processes)]
        actions += [(f'capture-{side}', lambda p=p: shared.stop(p, interrupt=True)) for side, p, *_ in captures]
        actions += [(f'filter-{i}', lambda prefix=prefix: command([*prefix, 'tc', 'qdisc', 'del', 'dev', 'wan0', 'clsact'], time.monotonic() + BOUNDS['cleanup'], BOUNDS['cleanup'])) for i, prefix in enumerate(reversed(filters))]
        if applied:
            actions.append(('namespace-journal', lambda: shared.bounded_lab(netns_lab.cleanup, spec, state_dir, time.monotonic() + BOUNDS['cleanup'])))
        cleanup_errors = cleanup_all(actions)
        if not applied and not journal_preexisted and journal.exists():
            cleanup_errors.append({'step': 'partial-setup-journal', 'error': 'authoritative setup rollback retained ownership journal; inspect without claiming cleanup'})
        try:
            names_after = namespace_observation(spec)
            evidence.record('expected_namespaces_after', names_after)
            residual = namespace_changes(names_before, names_after)
            evidence.record('unaccounted_namespace_changes', residual)
            if residual:
                cleanup_errors.append({'step': 'unaccounted-namespace-residual',
                                       'error': 'expected namespace names changed after the attempt; read-only observation does not authorize adoption or deletion',
                                       'changes': residual})
        except Exception as error:
            cleanup_errors.append({'step': 'namespace-residual-observation', 'error': str(error)[:4096]})
        partial = {}
        for side, _, pcap, diagnostic in captures:
            try:
                if pcap.is_file():
                    length = pcap.stat().st_size
                    partial[side] = {'bytes': length, 'complete_bounded_read': length <= shared.CAPTURE_LIMIT,
                                     'sha256': shared.file_hash(pcap) if length <= shared.CAPTURE_LIMIT else None}
            except Exception as error:
                cleanup_errors.append({'step': 'capture-retention-' + side, 'error': str(error)[:4096]})
        evidence.record('retained_capture_files', partial)
        evidence.update(status='passed' if success and not cleanup_errors else 'failed',
                        cleanup='passed' if not cleanup_errors else 'failed', cleanup_errors=cleanup_errors,
                        error=failure, failure_evidence='historical wave10 paired IncompleteClose remains unattributed')
    return evidence.value


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'proof':
        if len(argv) != 2 or len(argv[1].encode()) > 16384: raise ValueError('bounded proof request required')
        value = strict_json(argv[1])
        fields(value, {'identity', 'tuples', 'path', 'local_identity', 'expected', 'duplex', 'deadline'})
        print(json.dumps(prove_released(**value), separators=(',', ':')))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layer', choices=['tap', 'tun'], required=True)
    parser.add_argument('--duplex', choices=['full', 'half'], required=True)
    parser.add_argument('--lab-id', default='ovpn-drain')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/l2tunnel-linux')
    parser.add_argument('--build-receipt', type=Path)
    parser.add_argument('--state-dir', type=Path, default=Path('/run/l2tunnel-labs'))
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    plan = case_plan(args.lab_id, args.layer, args.duplex)
    plan['daemon_commands'] = daemon_commands(plan, args.output / 'l2tunnel-native', Path('/PRIVATE_CASE_CREDENTIALS'))
    if not args.apply:
        print(json.dumps({'status': 'dry_run', 'plan': plan, 'output': str(args.output), 'mutations': 'none'}, indent=2))
        return 0
    netns_lab.require_root()
    for name in ('ip', 'tc', 'ethtool', 'tcpdump', 'ss', 'ping', 'openssl', 'python3'):
        if shutil.which(name) is None: raise FileNotFoundError(name)
    if args.build_receipt is None: raise ValueError('reviewed source-stable build receipt required')
    build = shared.verified_build_receipt(args.build_receipt, args.binary)
    args.output.mkdir(mode=0o755)
    output = args.output.resolve()
    binary = output / 'l2tunnel-native'
    shutil.copyfile(args.binary, binary); binary.chmod(0o755)
    helpers = ('openvpn_drain_native_smoke.py', 'native_smoke.py', 'proxy_native_smoke.py', 'netns_lab.py', 'tcp_probe.py')
    before = {name: shared.file_hash(ROOT / 'tools' / name) for name in helpers}
    for name in helpers: shutil.copyfile(ROOT / 'tools' / name, output / name)
    if before != {name: shared.file_hash(ROOT / 'tools' / name) for name in helpers} or before != {name: shared.file_hash(output / name) for name in helpers}:
        raise ValueError('helper source changed during immutable snapshot')
    shutil.copyfile(args.build_receipt, output / 'build-receipt.json')
    if shared.verified_build_receipt(output / 'build-receipt.json', binary) != build:
        raise ValueError('immutable build copy changed')
    evidence = native.CaseEvidence(output / 'receipt.json', plan['case'])
    evidence.update(plan=plan, cleanup='pending', binary_sha256=shared.file_hash(binary),
                    helper_sha256={p.name: shared.file_hash(p) for p in output.glob('*.py')},
                    build_receipt_sha256=shared.file_hash(output / 'build-receipt.json'),
                    binary_build_sources=build['source_sha256_after'],
                    unresolved_evidence=['work/implementation-wave10/validation.json', 'work/openvpn-drain-client/original-broad-timeout.txt'])
    with tempfile.TemporaryDirectory(prefix='l2t-drain-') as directory:
        secrets = Path(directory)
        try:
            provision(binary, secrets)
            result = run_case(plan, binary, output / 'openvpn_drain_native_smoke.py', output, secrets, args.state_dir, evidence)
        except Exception as error:
            evidence.update(status='failed', error=str(error)[:4096])
            raise
    print(json.dumps({'status': result['status'], 'receipt': str(output / 'receipt.json')}))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
