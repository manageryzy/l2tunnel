"""Finite tooling regressions; fake namespaces/captures and ordinary loopback only."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from . import secure_udp_native as h, secure_udp_native_probe as p


def case(cover='quic-like', path='impaired', workload='forward16'):
    return h.plan('unit', cover, path, workload)


def public():
    return {'member_public': [7] * 32, 'noise_public': {'a': [8] * 32, 'b': [9] * 32}}


def status(side='a'):
    value = {name: 0 for name in h.STATUS_FIELDS}
    value.update(carrier='quic-like', algorithm='swift', protection='chacha20-poly1305', running=True,
        local=h.WAN[side] + ':24440', peer=h.WAN['b' if side == 'a' else 'a'] + ':24440',
        requested=dict(h.INITIAL), effective=dict(h.INITIAL), maximum_path_mtu=9000,
        member=public()['member_public'], initiator_noise=public()['noise_public']['a'],
        responder_noise=public()['noise_public']['b'], session=[1] * 16, transcript=[2] * 32,
        configuration=[3] * 32, outer=[4] * 32, generation=1, pending_epoch=None, terminal=None,
        policy_change=True, reconnect=True, retained_state_recovery=False, cross_profile_switching=False,
        fresh_rekey=False, user_number=None, control_number=None)
    return {'version': 2, 'ok': True, 'code': 'ok', 'state': {'secure_udp': value}}


def cover_body(cover, phase='established', epoch=1, protected=None, direction='a'):
    keys = public()['noise_public']
    joined = bytes(keys['a']) + bytes(keys['b'])
    own, other = (b'initiator', b'responder') if direction == 'a' else (b'responder', b'initiator')
    protected = (145 if phase == 'handshake' else 100) if protected is None else protected
    if phase == 'handshake':
        payload = bytearray(protected)
        payload[:5] = bytes([128, 56 if direction == 'a' else 64, 1, 1 if direction == 'a' else 2, 0])
        payload[9:min(25, protected)] = bytes([1]) * max(0, min(25, protected) - 9)
        payload = bytes(payload)
    else:
        payload = b'\x01' + epoch.to_bytes(8, 'big') + b'\x01\x01' + bytes(protected - 11)
    if cover == 'quic-like':
        peer = hashlib.sha256(b'l2tunnel/service/CID/' + other + b'/v1\0' + joined).digest()[:8]
        if phase == 'established':
            return b'\x43' + peer + bytes(4) + payload
        local = hashlib.sha256(b'l2tunnel/service/CID/' + own + b'/v1\0' + joined).digest()[:8]
        length = len(payload) + 4
        encoded = bytes([length]) if length < 64 else (length | 0x4000).to_bytes(2, 'big')
        return b'\xc3\0\0\0\1\x08' + peer + b'\x08' + local + b'\0' + encoded + bytes(4) + payload
    ssrc = hashlib.sha256(b'l2tunnel/service/SSRC/' + own + b'/v1\0' + joined).digest()[:4]
    return bytes([0x80, 0xe0 if phase == 'handshake' else 96]) + bytes(6) + ssrc + len(payload).to_bytes(2, 'big') + payload


def frame(body, direction='a', protocol=17, fragment=0, source=None, destination=None):
    source = source or h.WAN[direction]
    destination = destination or h.WAN['b' if direction == 'a' else 'a']
    transport = struct.pack('!HHHH', 24440, 24440, len(body) + 8, 0) + body if protocol == 17 else body
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), 1, fragment,
        64, protocol, 0, socket.inet_aton(source), socket.inet_aton(destination)))
    ip[10:12] = h.bounded.checksum(ip).to_bytes(2, 'big')
    return bytes(12) + b'\x08\x00' + ip + transport


def pcap(frames, timestamps=None):
    result = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 160, 1))
    for index, raw in enumerate(frames):
        ns = timestamps[index] if timestamps else 1_500_000_000
        captured = min(len(raw), 160)
        result += struct.pack('<IIII', ns // 1_000_000_000, ns % 1_000_000_000 // 1000, captured, len(raw))
        result += raw[:captured]
    return bytes(result)


def probes(flows=16, reverse=False):
    clock = {'start_ns': 1, 'measure_start_ns': 2, 'end_ns': 1_000_000_002}
    client, server = [], []
    empty = hashlib.sha256(b'').hexdigest()
    for index in range(flows):
        first, second = ['198.18.0.1', 30000 + index], ['198.18.0.2', 24451]
        # A real listener has identical locals but different accepted peers.
        digest = hashlib.sha256(bytes([index])).hexdigest()
        a = dict(local=first, peer=second, sent=10, received=5 if reverse else 0,
            warmup=0, measured=5 if reverse else 0, postwindow=0, write_closed=True, eof=True,
            bound_exhausted=False, sent_sha256=digest, received_sha256=digest if reverse else empty)
        b = dict(local=second, peer=first, sent=5 if reverse else 0, received=10,
            warmup=0, measured=10, postwindow=0, write_closed=True, eof=True,
            bound_exhausted=False, sent_sha256=digest if reverse else empty, received_sha256=digest)
        client.append(a); server.append(b)
    return ({'clock': clock, 'send_enabled': True, 'flows': client},
            {'clock': clock, 'send_enabled': reverse, 'flows': list(reversed(server))})


def process_stat(pid=123, start=500, user=100, system=30, state='S'):
    fields = [state] + ['0'] * 21
    for index, value in [(11, user), (12, system), (19, start), (20, 1_048_576), (21, 256)]: fields[index] = str(value)
    return str(pid) + ' (daemon ) with spaces) ' + ' '.join(fields) + '\n'


def process_status(pid=123):
    return f'Name:\tdaemon\nTgid:\t{pid}\nPid:\t{pid}\nVmHWM:\t2048 kB\nVmRSS:\t1024 kB\n'


class HarnessContracts(unittest.TestCase):
    def test_dry_run_reads_no_inputs_and_never_starts_a_process(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'new'
            with contextlib.redirect_stdout(io.StringIO()) as text, patch.object(h.subprocess, 'Popen') as spawn, \
                    patch.object(h.bounded, 'verified_build_receipt') as verify, patch.object(h, 'namespace_ids') as ns:
                self.assertEqual(h.main(['--cover', 'quic-like', '--path', 'loss1', '--output', str(output),
                    '--binary', '/does/not/exist']), 0)
            self.assertFalse(output.exists()); spawn.assert_not_called(); verify.assert_not_called(); ns.assert_not_called()
            value = json.loads(text.getvalue())
            self.assertEqual(value['status'], 'dry_run')
            self.assertEqual(value['case']['loss_percent_per_direction'], 1)
        self.assertEqual(case(path='impaired')['loss_percent_per_direction'], 15)
        self.assertFalse(case()['reverse_bulk'])
        self.assertTrue(case(workload='reverse-stress')['reverse_bulk'])
        self.assertIn('existing FIX-04', case()['target_provenance'])
        for values in [('unknown', 'clean', 'forward16'), ('quic-like', 'fake', 'forward16'), ('quic-like', 'clean', 'duplex')]:
            with self.assertRaises(ValueError): h.plan('unit', *values)
        with self.assertRaises(ValueError): h.plan('../host', 'quic-like', 'clean', 'forward16')

    def test_explicit_daemon_roles_do_not_substitute_tls_or_a_second_transport(self):
        for appearance in ('quic-like', 'media-like'):
            for side in ('a', 'b'):
                argv = h.daemon_command(case(appearance), side, Path('/binary'), Path('/keys'))
                self.assertEqual(argv[1], 'connect' if side == 'a' else 'serve')
                self.assertEqual(argv[argv.index('--carrier') + 1], appearance)
                self.assertEqual(argv[argv.index('--record-profile') + 1], 'swift')
                self.assertEqual(argv[argv.index('--udp-bind') + 1], h.WAN[side] + ':24440')
                self.assertIn('--identity' if side == 'a' else '--session-cookie-key-file', argv)
                for flag in ('--tls', '--remote', '--listen', '--cert', '--insecure'): self.assertNotIn(flag, argv)

    def test_status_validates_real_identity_bindings_and_capabilities(self):
        self.assertEqual(h.validate_status(status(), case(), 'a', public(), h.INITIAL)['generation'], 1)
        for mutation in ('api', 'pin', 'capability', 'unknown', 'counter', 'binding', 'effective'):
            value = status(); row = value['state']['secure_udp']
            if mutation == 'api': value['version'] = 1
            if mutation == 'pin': row['responder_noise'] = [0] * 32
            if mutation == 'capability': row['fresh_rekey'] = True
            if mutation == 'unknown': row['invented'] = 0
            if mutation == 'counter': row['wire_bytes'] = True
            if mutation == 'binding': row['session'] = [0] * 16
            if mutation == 'effective': row['effective']['window'] = 8
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, h.ObservationError)):
                h.validate_status(value, case(), 'a', public(), h.INITIAL)

    def test_policy_observation_allows_only_transient_epoch_skew(self):
        peers = {side: status(side)['state']['secure_udp'] for side in ('a', 'b')}
        peers['b']['policy_epoch'] = 1
        self.assertIs(h.aligned_peers(peers, False), peers)
        with self.assertRaises(ValueError): h.aligned_peers(peers)
        peers['b']['session'][0] = 9
        with self.assertRaises(ValueError): h.aligned_peers(peers, False)

    def test_ready_event_is_retained_even_after_later_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'daemon.log'
            ready = {'event': 'secure_udp_ready', 'status': status()['state']['secure_udp']}
            path.write_text('startup\n' + json.dumps(ready) + '\n' + json.dumps({'event': 'secure_udp_terminal'}) + '\n')
            self.assertEqual(h.ready_event(path), ready)

    def test_functional_failure_keeps_prior_evidence_raw_ping_and_live_status(self):
        for label, field, prior in [('initial', 'functional', {
                'initial_ready': {'a': 'ready', 'b': 'ready'}, 'initial_status': {'generation': 1},
                'initial_daemon_resources': {'cpu_ticks': 7}, 'initial_sockets': {'sole_udp': True}}),
                ('reconnected', 'after_reconnect', {'lifecycle': {'generation': 2}, 'final_sockets': {'sole_udp': True}})]:
            with self.subTest(phase=label), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                receipt = h.bounded.Receipt(output / 'receipt.json', {'status': 'running', **prior})
                failed_ping = json.dumps({'status': 'failed', 'sent': 3, 'received_unique': 2,
                    'request_count': 3, 'payload_bytes': 1472, 'ip_bytes': 1500, 'df': True}) + '\n'
                launched, stopped, observed = [], [], []
                def launch(role, argv, name, cap=None):
                    child = Mock(); child.poll.return_value = None; child.returncode = 0
                    log = output / (name + '.log')
                    if '--ready' in argv:
                        Path(argv[argv.index('--ready') + 1]).write_text('ready')
                        launched.append(child)
                    else:
                        self.assertEqual(cap, 64 * 1024)
                        self.assertEqual(argv[2], 'icmp-probe')
                        side = role[-1]
                        self.assertEqual(argv[argv.index('--source') + 1], h.HOST[side])
                        self.assertEqual(argv[argv.index('--address') + 1], h.HOST['b' if side == 'a' else 'a'])
                        end = int(argv[argv.index('--deadline-ns') + 1])
                        self.assertLessEqual(end, int(deadline * 1e9))
                        log.write_text(json.dumps({'status': 'passed', 'sent': 3, 'received_unique': 3,
                            'request_count': 3, 'payload_bytes': 1472, 'ip_bytes': 1500, 'df': True,
                            'source': h.HOST[side], 'address': h.HOST['b' if side == 'a' else 'a'],
                            'original_deadline_ns': end,
                            'rows': [{'sequence': n, 'sent_ns': end - 2, 'received_ns': end - 1} for n in (1, 2, 3)]}) + '\n'
                            if role == 'host_a' else failed_ping)
                    return child, log
                def command(role, *argv, cap):
                    self.assertEqual(cap, 17)
                    return json.dumps({'status': 'passed', 'rows': [{'answered': True}] * 14})
                def observe(side):
                    saved = json.loads(receipt.path.read_text())
                    self.assertEqual(saved[label + '_functional_progress']['b']['full_mtu_df_ping'], failed_ping)
                    self.assertEqual(stopped, launched)
                    for key, value in prior.items(): self.assertEqual(saved[key], value)
                    observed.append(side)
                    reply = status(side)
                    reply['state']['secure_udp']['running'] = side == 'a'
                    return reply
                deadline = time.monotonic() + 20
                with patch.object(h.bounded, 'stop', side_effect=stopped.append):
                    with self.assertRaisesRegex(ValueError, 'full-MTU DF native ping did not return exactly'):
                        h.record_functional(receipt, field,
                            lambda: h.functional(label, output, deadline, launch, command, receipt), observe, deadline)
                saved = json.loads(receipt.path.read_text())
                self.assertEqual(observed, ['a', 'b'])
                self.assertNotIn(field, saved)
                self.assertEqual(len(saved[label + '_functional_progress']['a']['udp']['rows']), 14)
                self.assertFalse(saved['functional_failure']['peers']['b']['response']['state']['secure_udp']['running'])
                self.assertEqual(saved['functional_failure']['phase'], field)

    def test_failure_status_errors_and_original_deadline_preserve_primary_error(self):
        for clock, expected_calls in [([1, 1], ['a', 'b']), ([1, 5], ['a'])]:
            with self.subTest(clock=clock), tempfile.TemporaryDirectory() as directory:
                receipt = h.bounded.Receipt(Path(directory) / 'receipt.json', {'status': 'running'})
                primary = ValueError('original full-MTU failure')
                def fail(): raise primary
                def observe(side):
                    if side == 'a': raise OSError('control socket unavailable')
                    return status(side)
                with patch.object(h.time, 'monotonic', side_effect=clock), patch('builtins.print') as output:
                    observer = Mock(side_effect=observe)
                    with self.assertRaises(ValueError) as caught:
                        h.record_functional(receipt, 'functional', fail, observer, 5)
                self.assertIs(caught.exception, primary)
                self.assertEqual([call.args[0] for call in observer.call_args_list], expected_calls)
                output.assert_not_called()
                peers = json.loads(receipt.path.read_text())['functional_failure']['peers']
                self.assertEqual(peers['a']['status'], 'tool_failure')
                self.assertIn('control socket unavailable', peers['a']['error'])
                self.assertEqual(peers['b']['status'], 'observed' if len(expected_calls) == 2 else 'bound_exhausted')

    def test_icmp_process_bound_retains_partial_log_before_live_failure_status(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            receipt = h.bounded.Receipt(output / 'receipt.json', {'status': 'running', 'initial_sockets': {'sole_udp': True}})
            primary = subprocess.TimeoutExpired('icmp-probe', 12)
            progress = json.dumps({'event': 'icmp_reply', 'status': 'running', 'sent': 3, 'received_unique': 2}) + '\n'
            def launch(role, argv, name, cap=None):
                child, log = Mock(), output / (name + '.log')
                if '--ready' in argv:
                    Path(argv[argv.index('--ready') + 1]).write_text('ready')
                else:
                    log.write_text(progress)
                    child.wait.side_effect = primary
                return child, log
            def observe(side):
                saved = json.loads(receipt.path.read_text())
                self.assertEqual(saved['initial_functional_progress']['a']['full_mtu_df_ping'], progress)
                self.assertTrue(saved['initial_sockets']['sole_udp'])
                return status(side)
            deadline = time.monotonic() + 20
            with patch.object(h.bounded, 'stop') as stop, self.assertRaises(subprocess.TimeoutExpired) as caught:
                h.record_functional(receipt, 'functional',
                    lambda: h.functional('initial', output, deadline, launch, Mock(), receipt), observe, deadline)
            self.assertIs(caught.exception, primary); self.assertEqual(stop.call_count, 2)
            peers = json.loads(receipt.path.read_text())['functional_failure']['peers']
            self.assertTrue(all(row['status'] == 'observed' for row in peers.values()))

    def test_failure_diagnostic_bounds_and_publication_cannot_replace_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = h.bounded.Receipt(Path(directory) / 'receipt.json', {'status': 'running'})
            primary = ValueError('original full-MTU failure')
            def fail(): raise primary
            with self.assertRaises(ValueError) as caught:
                h.record_functional(receipt, 'functional', fail, lambda side: {'oversized': 'x' * (64 * 1024)},
                                    time.monotonic() + 20)
            self.assertIs(caught.exception, primary)
            peers = json.loads(receipt.path.read_text())['functional_failure']['peers']
            self.assertTrue(all(row['status'] == 'tool_failure' and '64KiB' in row['error'] for row in peers.values()))
            with patch.object(receipt, 'update', side_effect=OSError('receipt publication unavailable')), \
                    patch('builtins.print') as output, self.assertRaises(ValueError) as caught:
                h.record_functional(receipt, 'functional', fail, lambda side: status(side), time.monotonic() + 20)
            self.assertIs(caught.exception, primary)
            self.assertIn('receipt publication unavailable', output.call_args.args[0])

    def test_probe_accounting_matches_socket_identity_not_accept_order(self):
        client, server = probes()
        result = h.compare_probes(client, server, 'forward16')
        self.assertEqual(result['directions']['a_to_b']['receiver_unique_bytes'], 160)
        self.assertEqual(result['directions']['b_to_a']['receiver_unique_bytes'], 0)
        self.assertEqual(result['performance_acceptance']['status'], 'failed')
        client['flows'][0]['bound_exhausted'] = True
        self.assertEqual(h.compare_probes(client, server, 'forward16')['status'], 'bound_exhausted')
        client, server = probes(reverse=True)
        self.assertEqual(h.compare_probes(client, server, 'reverse-stress')['performance_acceptance']['status'], 'not_applicable_reverse_stress')
        with self.assertRaises(ValueError): h.compare_probes(client, server, 'forward16')
        for mutation in ('hash', 'eof', 'bucket', 'clock', 'duplicate'):
            client, server = probes()
            if mutation == 'hash': client['flows'][0]['sent_sha256'] = '00' * 32
            if mutation == 'eof': server['flows'][0]['eof'] = False
            if mutation == 'bucket': server['flows'][0]['postwindow'] = 1
            if mutation == 'clock': server['clock'] = {**server['clock'], 'end_ns': 1}
            if mutation == 'duplicate': server['flows'][0]['peer'] = server['flows'][1]['peer']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): h.compare_probes(client, server, 'forward16')

    def test_each_original_namespace_is_anchored_and_must_change_before_mutation(self):
        descriptors = {'user': 11, 'net': 12, 'mnt': 13}
        original = {name: {'device': 1, 'inode': value} for name, value in descriptors.items()}
        current = {name: {'device': 1, 'inode': value + 100} for name, value in descriptors.items()}
        names = {value: name for name, value in descriptors.items()}
        with patch.object(h.os, 'fstat', side_effect=lambda fd: SimpleNamespace(st_dev=1, st_ino=fd)), \
                patch.object(h.os, 'readlink', side_effect=lambda path: names[int(path.rsplit('/', 1)[1])] + ':[1]'):
            h.verify_fresh_namespace(descriptors, original, current)
            for name in descriptors:
                changed = copy.deepcopy(current); changed[name] = original[name]
                with self.subTest(name=name), self.assertRaises(ValueError): h.verify_fresh_namespace(descriptors, original, changed)
            with self.assertRaises(ValueError): h.verify_fresh_namespace({'net': 12}, original, current)

    def test_worker_rejects_unproven_namespace_before_any_mount_or_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory); output.chmod(0o700)
            info = output.stat()
            (output / 'launch-receipt.json').write_text(json.dumps({'original_namespaces': {}}))
            with patch.object(h, '__file__', str(output / 'secure_udp_native.py')), patch.object(h, 'verify_helpers'), \
                    patch.object(h, 'namespace_ids', return_value={}), patch.object(h.bounded, 'command') as command, \
                    patch.object(h, 'run_case') as run:
                with self.assertRaises(ValueError): h.worker(case(), output, {}, {}, f'{info.st_dev}:{info.st_ino}')
            command.assert_not_called(); run.assert_not_called()

    def test_source_helper_hash_and_executed_path_are_both_required(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            hashes = {}
            for name in h.HELPERS:
                (output / name).write_text(name)
                hashes['tools/' + name] = h.bounded.file_hash(output / name)
            build = {'source_sha256_after': hashes}
            self.assertEqual(h.verify_helpers(build, output), hashes)
            with self.assertRaises(ValueError): h.verify_helpers(build, output, True)
            (output / h.HELPERS[0]).write_text('changed')
            with self.assertRaises(ValueError): h.verify_helpers(build, output)

    def test_launcher_preflight_failure_is_terminal_and_existing_output_is_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'fresh'
            with patch.object(h.bounded, 'verified_build_receipt', side_effect=ValueError('bad build')), \
                    patch.object(h.subprocess, 'Popen') as spawn:
                self.assertEqual(h.launch_isolated(case(), output, Path('binary'), Path('receipt')), 1)
            spawn.assert_not_called()
            primary = json.loads((output / 'receipt.json').read_text())
            self.assertEqual(primary['status'], 'failed'); self.assertIn('bad build', primary['launcher_failure'])
            saved = (output / 'receipt.json').read_bytes()
            with self.assertRaises(FileExistsError): h.launch_isolated(case(), output, Path('binary'), Path('receipt'))
            self.assertEqual((output / 'receipt.json').read_bytes(), saved)

    def test_launcher_timeout_finalizes_running_receipt_without_erasing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'fresh'; binary = root / 'binary'; binary.write_bytes(b'binary')
            build = {'status': 'passed', 'exit_code': 0, 'source_stable_during_build': True, 'changed_during_build': [],
                'binary_sha256': h.bounded.file_hash(binary), 'source_sha256_before': {}, 'source_sha256_after': {}}
            for name in h.HELPERS:
                build['source_sha256_after']['tools/' + name] = h.bounded.file_hash(Path(h.__file__).parent / name)
            build['source_sha256_before'] = dict(build['source_sha256_after'])
            receipt = root / 'build.json'; receipt.write_text(json.dumps(build))
            child = Mock(pid=123456)
            child.wait.side_effect = [subprocess.TimeoutExpired('fake-worker', 300), 0, 0]
            def spawn(argv, **kwargs):
                self.assertEqual(argv[1:7], ['--user', '--map-root-user', '--net', '--mount', '--fork', h.sys.executable])
                self.assertTrue(kwargs['start_new_session']); self.assertEqual(len(kwargs['pass_fds']), 3)
                self.assertNotIn('PYTHONPATH', kwargs['env'])
                h.bounded.Receipt(output / 'receipt.json', {'status': 'running', 'captured_evidence': {'count': 7}, 'cleanup': 'pending'})
                return child
            with patch.object(h.shutil, 'which', return_value='/usr/bin/unshare'), \
                    patch.object(h.subprocess, 'Popen', side_effect=spawn), patch.object(h.os, 'killpg') as kill:
                self.assertEqual(h.launch_isolated(case(), output, binary, receipt), 1)
            value = json.loads((output / 'receipt.json').read_text())
            self.assertEqual(value['status'], 'bound_exhausted')
            self.assertEqual(value['captured_evidence'], {'count': 7})
            self.assertEqual(value['cleanup'], 'unverified_after_launcher_failure')
            self.assertEqual(value['worker_status_before_interruption'], 'running')
            self.assertEqual(kill.call_args_list[0].args, (123456, signal.SIGTERM))
            self.assertEqual(kill.call_args_list[-1].args, (123456, signal.SIGKILL))

    def test_exited_namespace_leader_does_not_leave_owned_descendants(self):
        child = Mock(pid=123456); child.poll.return_value = 0
        with patch.object(h.os, 'killpg') as kill:
            h.terminate_owned_group(child)
        self.assertEqual([call.args[1] for call in kill.call_args_list], [signal.SIGTERM, signal.SIGKILL])

    def test_daemon_resources_preserve_units_identity_and_memory_separate_from_probe(self):
        child = Mock(pid=123); child.poll.return_value = None
        with patch.object(h, 'bounded_proc_text', side_effect=[process_stat(), process_status(), process_stat(user=107)]) as read:
            value = h.daemon_resources(child, 500)
        self.assertEqual(value['pid'], 123); self.assertEqual(value['starttime_ticks'], 500)
        self.assertEqual(value['user_ticks'], 107); self.assertEqual(value['system_ticks'], 30)
        self.assertEqual(value['rss_kib'], 1024); self.assertEqual(value['high_water_kib'], 2048)
        self.assertEqual([call.args[0] for call in read.call_args_list],
            [Path('/proc/123/stat'), Path('/proc/123/status'), Path('/proc/123/stat')])
        context = h.resource_context()
        self.assertGreater(context['daemon_cpu_clock_ticks_per_second'], 0)
        self.assertGreater(context['resident_page_bytes'], 0)
        self.assertIn('not tunnel daemon CPU', context['probe_cpu_measurement'])
        self.assertEqual(len(context['host']['loadavg']), 3)

    def test_resource_reads_reject_reused_pid_exited_child_and_regressing_cpu(self):
        for before, after, anchor in [(process_stat(pid=124), process_stat(), 500),
                (process_stat(), process_stat(start=501), 500),
                (process_stat(), process_stat(user=99), 500),
                (process_stat(), process_stat(), 499),
                (process_stat(state='Z'), process_stat(), 500)]:
            child = Mock(pid=123); child.poll.return_value = None
            with patch.object(h, 'bounded_proc_text', side_effect=[before, process_status(), after]), self.assertRaises(h.ObservationError):
                h.daemon_resources(child, anchor)
        child = Mock(pid=123); child.poll.side_effect = [None, 0]
        with patch.object(h, 'bounded_proc_text', side_effect=[process_stat(), process_status(), process_stat()]), self.assertRaises(h.ObservationError):
            h.daemon_resources(child, 500)
        child = Mock(pid=123); child.poll.return_value = 0
        with patch.object(h, 'bounded_proc_text') as read, self.assertRaises(h.ObservationError): h.daemon_resources(child)
        read.assert_not_called()

    def test_resource_parser_caps_and_exact_memory_fields_are_required(self):
        for raw in [process_stat(user=-1), process_stat(user=1 << 64), '123 (short) S 1',
                '123 (' + 'x' * h.PROC_BYTES + ') S 1']:
            with self.subTest(raw=raw[:32]), self.assertRaises(h.ObservationError): h.daemon_stat(raw, 123)
        for raw in [process_status(124), process_status() + 'VmRSS:\t1 kB\n',
                process_status().replace('2048 kB', '512 kB'), process_status().replace('1024 kB', '1024 bytes'),
                process_status().replace('VmRSS:', 'Missing:'), 'x' * (h.PROC_BYTES + 1)]:
            with self.subTest(raw=raw[:32]), self.assertRaises(h.ObservationError): h.daemon_memory(raw, 123)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'proc-fixture'; path.write_bytes(bytes(h.PROC_BYTES + 1))
            with self.assertRaises(h.ObservationError): h.bounded_proc_text(path)
            path.write_text(process_status()); self.assertEqual(h.bounded_proc_text(path), process_status())
        with patch.object(h.os, 'sysconf', side_effect=[0, 4096]), self.assertRaises(h.ObservationError): h.resource_context()

    def test_real_worker_and_nested_capture_select_explicit_limits_without_raising_hard_ceiling(self):
        parent = h.resource.getrlimit(h.resource.RLIMIT_FSIZE)
        script = '''import json,resource,subprocess,sys
from tools import secure_udp_native as h
before=list(resource.getrlimit(resource.RLIMIT_FSIZE))
code="import json,resource; print(json.dumps(list(resource.getrlimit(resource.RLIMIT_FSIZE))))"
result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,check=True,timeout=5,
    preexec_fn=h.bounded.limited_child(h.BOUNDS['capture_bytes']))
print(json.dumps({'worker':before,'capture':json.loads(result.stdout),
    'worker_after':list(resource.getrlimit(resource.RLIMIT_FSIZE))}))
'''
        result = subprocess.run([h.sys.executable, '-B', '-c', script], cwd=h.ROOT, capture_output=True,
            text=True, check=True, timeout=10, preexec_fn=h.worker_file_limits())
        value = json.loads(result.stdout)
        self.assertEqual(value['worker'], [h.BOUNDS['log_bytes'], h.BOUNDS['capture_bytes']])
        self.assertEqual(value['worker_after'], value['worker'])
        self.assertEqual(value['capture'], [h.BOUNDS['capture_bytes']] * 2)
        self.assertEqual(h.resource.getrlimit(h.resource.RLIMIT_FSIZE), parent)

    def test_real_insufficient_inherited_hard_limit_refuses_before_worker_spawn(self):
        parent = h.resource.getrlimit(h.resource.RLIMIT_FSIZE)
        script = '''import json,resource
from tools import secure_udp_native as h
cap=h.BOUNDS['log_bytes']; resource.setrlimit(resource.RLIMIT_FSIZE,(cap,cap))
try:
    h.worker_file_limits()
except h.ObservationError as error:
    print(json.dumps({'refused':True,'error':str(error),
        'limits':list(resource.getrlimit(resource.RLIMIT_FSIZE))}))
else:
    raise SystemExit('insufficient inherited hard limit was accepted')
'''
        result = subprocess.run([h.sys.executable, '-B', '-c', script], cwd=h.ROOT,
            capture_output=True, text=True, check=True, timeout=5)
        value = json.loads(result.stdout)
        self.assertTrue(value['refused']); self.assertIn('inherited RLIMIT_FSIZE', value['error'])
        self.assertEqual(value['limits'], [h.BOUNDS['log_bytes']] * 2)
        self.assertEqual(h.resource.getrlimit(h.resource.RLIMIT_FSIZE), parent)
        with patch.object(h.resource, 'getrlimit', side_effect=[(0, h.resource.RLIM_INFINITY), (0, 1)]), \
                patch.object(h.resource, 'setrlimit') as apply:
            configure = h.worker_file_limits()
            with self.assertRaises(ValueError): configure()
        apply.assert_not_called()

    def test_capture_stays_in_mapped_root_and_preserves_explicit_bounds(self):
        for name in ('wan-a', 'wan-b', 'native-a'):
            argv = h.capture_command(name, Path('/owned/capture.pcap'))
            self.assertEqual(argv[argv.index('-Z') + 1], 'root')
            self.assertEqual(int(argv[argv.index('-c') + 1]), h.BOUNDS['capture_packets'])
            self.assertEqual(int(argv[argv.index('-s') + 1]), h.BOUNDS['capture_snaplen'])
            self.assertEqual(argv[argv.index('-w') + 1], '/owned/capture.pcap')
            self.assertEqual(argv[argv.index('-i') + 1], 'tap0' if name == 'native-a' else 'wan0')
        with self.assertRaises(ValueError): h.capture_command('host-interface', Path('/owned/capture.pcap'))


class CaptureContracts(unittest.TestCase):
    anchors = [{'offset_ns': 0, 'uncertainty_ns': 0}, {'offset_ns': 0, 'uncertainty_ns': 0}]

    def audit(self, frames, appearance='quic-like', **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            path.write_bytes(pcap(frames, kwargs.pop('timestamps', None)))
            value = {**case(appearance), 'public_noise': public()['noise_public'], **kwargs.pop('case_extra', {})}
            return h.audit_capture(path, value, 'a', self.anchors, **kwargs)

    def test_both_cover_phases_variable_quic_lengths_and_loaded_user_epochs(self):
        for appearance in ('quic-like', 'media-like'):
            for size in (20, 200):
                body = cover_body(appearance, 'handshake', protected=size)
                phase, payload, complete = h.covered_payload(body, len(body), appearance)
                self.assertEqual((phase, len(payload), complete), ('handshake', size, size))
            frames = [frame(cover_body(appearance, 'handshake'))]
            frames += [frame(cover_body(appearance, epoch=epoch)) for epoch in (1, 2, 3)]
            result = self.audit(frames, appearance, case_extra={'require_policy_epochs': True})
            self.assertEqual(result['handshake'], 1); self.assertEqual(result['established'], 3)
            self.assertEqual(result['user_epochs'], {'1': 1, '2': 1, '3': 1})

    def test_capture_common_window_accounts_original_not_snapshot_bytes(self):
        frames = [frame(cover_body('quic-like', 'handshake')),
            frame(cover_body('quic-like', protected=1000)), frame(cover_body('quic-like', protected=1000))]
        clock = {'measure_start_ns': 1_000_000_000, 'end_ns': 2_000_000_000}
        result = self.audit(frames, clock=clock, timestamps=[500_000_000, 1_500_000_000, 2_000_000_000])
        row = result['directions']['a']; full = len(frames[1]) - 14
        self.assertEqual(row['measurement_min_ip_bytes'], full)
        self.assertEqual(row['measurement_max_ip_bytes'], full * 2)
        self.assertGreater(full, result['snapshot_bytes'])
        self.assertEqual(row['ip_bytes'], sum(len(raw) - 14 for raw in frames))

    def test_breach_unknown_epoch_missing_phase_wrong_tuple_and_tcp_fail(self):
        handshake = frame(cover_body('quic-like', 'handshake'))
        good = frame(cover_body('quic-like'))
        for bad in [frame(cover_body('quic-like', epoch=2, protected=1360)),
                frame(cover_body('quic-like', epoch=4)), frame(cover_body('quic-like'), fragment=0x2000),
                frame(cover_body('quic-like'), source='192.0.2.99'), frame(bytes(20), protocol=6),
                frame(cover_body('quic-like', protected=1500))]:
            with self.subTest(raw=bad[:42]), self.assertRaises(ValueError): self.audit([handshake, good, bad])
        with self.assertRaises(ValueError): self.audit([good])
        with self.assertRaises(ValueError): self.audit([handshake, good], case_extra={'require_policy_epochs': True})

    def test_malformed_length_identity_checksum_and_truncated_capture_fail(self):
        handshake = frame(cover_body('quic-like', 'handshake'))
        good = frame(cover_body('quic-like'))
        body = bytearray(cover_body('quic-like', 'handshake', protected=20)); body[24] = 0x40
        cases = [frame(body)]
        body = bytearray(cover_body('quic-like')); body[1] ^= 1; cases.append(frame(body))
        body = bytearray(cover_body('media-like')); body[13] ^= 1
        with self.assertRaises(ValueError): self.audit([frame(cover_body('media-like', 'handshake')), frame(body)], 'media-like')
        raw = bytearray(good); raw[24] ^= 1; cases.append(bytes(raw))
        for raw in cases:
            with self.assertRaises(ValueError): self.audit([handshake, good, raw])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'short.pcap'; path.write_bytes(pcap([handshake, good])[:-1])
            with self.assertRaises(ValueError): h.audit_capture(path, case(), 'a', self.anchors)

    def test_valid_icmp_port_unreachable_is_separate_and_bad_quote_fails(self):
        quoted = frame(cover_body('quic-like'))[14:42]
        body = bytearray(bytes([3, 3]) + bytes(6) + quoted)
        body[2:4] = h.bounded.checksum(body).to_bytes(2, 'big')
        error = frame(body, direction='b', protocol=1)
        frames = [frame(cover_body('quic-like', 'handshake')), frame(cover_body('quic-like')), error]
        self.assertEqual(self.audit(frames)['icmp_path_errors'], 1)
        body[-8:-6] = bytes(2)
        with self.assertRaises(ValueError): self.audit(frames[:-1] + [frame(body, direction='b', protocol=1)])

    def test_capture_counters_must_be_complete_lossless_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.log'
            child = Mock(returncode=0)
            with patch.object(h.bounded, 'stop'):
                for raw, error in [('2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n', None),
                        ('2 packets captured\n2 packets received by filter\n1 packets dropped by kernel\n', h.ObservationError),
                        ('2 packets captured\n', h.ObservationError)]:
                    path.write_text(raw)
                    if error:
                        with self.assertRaises(error): h.capture_counts(path, child)
                    else:
                        values = h.capture_counts(path, child)
                        h.capture_complete({'packets': 2}, values)
                        with self.assertRaises(ValueError): h.capture_complete({'packets': 1}, values)
                path.write_text('2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n')
                child.returncode = 1
                with self.assertRaises(h.ObservationError): h.capture_counts(path, child)
        self.assertEqual(h.failure_status(TimeoutError()), 'bound_exhausted')
        self.assertEqual(h.failure_status(h.ObservationError()), 'tool_failure')
        self.assertEqual(h.failure_status(ValueError()), 'failed')

    def test_public_protected_record_grammar_never_substitutes_for_tag_verification(self):
        user = b'\x01' + (1).to_bytes(8, 'big') + b'\x01\x01' + bytes(24)
        control = b'\x02' + user[1:]
        for value in (user, control): h.protected_shape(value, len(value), 'established', 'a')
        for direction, length in [('a', 125), ('b', 61)]:
            joining = b'\x03\x01\x01' + bytes(length - 3)
            h.protected_shape(joining[:88], length, 'established', direction)
            with self.assertRaises(ValueError): h.protected_shape(joining[:88], length, 'established', 'b' if direction == 'a' else 'a')
        for value in (user[:9], user[:9] + b'\x01\x02' + user[11:],
                control[:1] + (2).to_bytes(8, 'big') + control[9:], b'\x03\x01\x01' + bytes(59)):
            with self.assertRaises(ValueError): h.protected_shape(value, len(value), 'established', 'a')
        for direction, role in [('a', 0), ('b', 1)]:
            # Headers are visible and checked, while zero fixture tags are never
            # presented as authenticated evidence by this capture-only parser.
            ack = bytearray(113); ack[:5] = bytes([129, 40, 1, role, 0])
            ack[5:21] = bytes([3]) * 16; ack[29:31] = (48).to_bytes(2, 'big')
            ack[33:41] = b'L2AR\x01\x01' + bytes([2, role])
            ack[41:57] = ack[5:21]; ack[57:65] = (1).to_bytes(8, 'big')
            h.protected_shape(ack[:88], len(ack), 'handshake', direction)
            source = bytearray(209); source[:77] = ack[:77]
            source[1] = 32; source[29:31] = (144).to_bytes(2, 'big'); source[39] = 1
            source[73:77] = (100).to_bytes(4, 'big')
            h.protected_shape(source[:88], len(source), 'handshake', direction)
            for offset in (2, 3, 31, 33, 38, 39, 40, 57, 76):
                bad = bytearray(source); bad[offset] ^= 1
                with self.subTest(direction=direction, offset=offset), self.assertRaises(ValueError):
                    h.protected_shape(bad[:88], len(bad), 'handshake', direction)
            with self.assertRaises(ValueError): h.protected_shape(ack[:88], len(ack) - 1, 'handshake', direction)
        self.assertEqual(self.audit([frame(cover_body('quic-like', 'handshake')),
            frame(cover_body('quic-like'))])['udp'], 2)

    def test_native_arp_is_witnessed_and_capture_resource_bounds_are_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap([bytes(12) + b'\x08\x06' + bytes(46)]))
            result = h.audit_capture(path, case(), None, self.anchors)
            self.assertEqual(result['arp'], 1)
            with patch.dict(h.BOUNDS, capture_bytes=path.stat().st_size):
                with self.assertRaises(h.BoundExhausted): h.audit_capture(path, case(), None, self.anchors)
            with patch.dict(h.BOUNDS, capture_packets=1):
                with self.assertRaises(h.BoundExhausted): h.audit_capture(path, case(), None, self.anchors)

    def test_positive_measured_payload_cannot_use_outside_window_or_boundary_only_wire_cost(self):
        frames = [frame(cover_body('quic-like', 'handshake'))]
        frames += [frame(cover_body('quic-like', epoch=epoch)) for epoch in (1, 2, 3)]
        outside = self.audit(frames, timestamps=[500_000_000] * len(frames),
            clock={'measure_start_ns': 1_000_000_000, 'end_ns': 2_000_000_000},
            case_extra={'require_policy_epochs': True})
        self.assertEqual(outside['directions']['a']['measurement_max_ip_bytes'], 0)
        reference = h.compare_probes(*probes(), 'forward16')
        audits = {'wan-a': copy.deepcopy(outside), 'wan-b': copy.deepcopy(outside)}
        with self.assertRaises(h.ObservationError): h.wire_window_evidence(reference, audits)
        audits['wan-a']['directions']['a'].update(measurement_min_ip_bytes=100, measurement_max_ip_bytes=200)
        # Reverse application bytes are zero, but actual ACK-return wire cost
        # must still have an observed conservative positive denominator.
        with self.assertRaises(h.ObservationError): h.wire_window_evidence(reference, audits)
        audits['wan-b']['directions']['b'].update(measurement_min_ip_bytes=0, measurement_max_ip_bytes=1)
        with self.assertRaises(h.ObservationError): h.wire_window_evidence(reference, audits)
        audits['wan-b']['directions']['b'].update(measurement_min_ip_bytes=50, measurement_max_ip_bytes=100)
        value = h.wire_window_evidence(reference, audits)
        self.assertEqual(value['a_to_b']['receiver_unique_bytes'], 160)
        self.assertEqual(value['b_to_a']['receiver_unique_bytes'], 0)


class OwnedShapingContracts(unittest.TestCase):
    def fixture(self):
        spec = h.lab.LabSpec('unit')
        owned = {name: {'device': 1, 'inode': index + 10} for index, name in enumerate(spec.namespaces.values())}
        manifest = {'version': h.lab.STATE_VERSION, 'lab_id': 'unit', 'uid': 0, 'owned_namespaces': owned}
        qdiscs = [{'kind': 'htb', 'handle': '1:', 'root': True},
                  {'kind': 'netem', 'handle': '10:', 'parent': '1:10'}]
        return spec, manifest, qdiscs

    def test_recreation_verifies_ownership_then_deletes_and_adds_exact_requested_geometry(self):
        for side in ('a', 'b'):
            for path in h.PATHS:
                spec, manifest, qdiscs = self.fixture()
                calls = []
                def command(role, *argv):
                    calls.append((role, *argv))
                    return json.dumps(qdiscs) if '-j' in argv else ''
                with patch.object(h.lab, 'locked_state', return_value=contextlib.nullcontext(Path('journal'))), \
                        patch.object(h.lab, 'load_manifest', return_value=manifest) as load, \
                        patch.object(h.lab, 'namespace_identity', side_effect=manifest['owned_namespaces'].__getitem__):
                    result = h.recreate_owned_wan(case(path=path), spec, Path('/owned'), side, command)
                load.assert_called_once_with(Path('journal'), spec)
                self.assertEqual(calls[0], (None, 'ip', 'netns', 'pids', spec.namespaces['endpoint_' + side]))
                self.assertEqual(calls[1][1:], ('tc', '-j', 'qdisc', 'show', 'dev', 'wan0'))
                self.assertEqual(calls[2][1:], ('tc', 'qdisc', 'del', 'dev', 'wan0', 'root', 'handle', '1:'))
                self.assertEqual(calls[3][1:], ('tc', 'qdisc', 'add', 'dev', 'wan0', 'root', 'handle', '1:',
                    'stab', 'overhead', '-14', 'linklayer', 'ethernet', 'htb', 'default', '10'))
                rate = '100mbit' if side == 'a' else '10mbit'
                self.assertEqual(calls[4][-4:], ('rate', rate, 'ceil', rate))
                self.assertEqual(calls[5][-5:], ('delay', str(h.PATHS[path][0]) + 'ms', 'loss', 'random', str(h.PATHS[path][1]) + '%'))
                self.assertTrue(all(row[0] == 'endpoint_' + side for row in calls[1:]))
                self.assertFalse(any('replace' in row or 'change' in row for row in calls))
                self.assertEqual(result['before'], qdiscs); self.assertEqual(result['after'], qdiscs)

    def test_unexpected_qdisc_replaced_namespace_or_active_process_refuses_before_mutation(self):
        for failure in ('root', 'leaf', 'extra', 'missing_namespace', 'replaced_namespace', 'active', 'race'):
            spec, manifest, qdiscs = self.fixture(); calls, target_checks = [], [0]
            if failure == 'root': qdiscs[0]['handle'] = '2:'
            if failure == 'leaf': qdiscs[1]['parent'] = '2:10'
            if failure == 'extra': qdiscs.append({'kind': 'clsact', 'handle': 'ffff:'})
            if failure == 'missing_namespace': manifest['owned_namespaces'].pop(spec.namespaces['router'])
            def identity(name):
                if failure == 'replaced_namespace': return {'device': 9, 'inode': 9}
                if name == spec.namespaces['endpoint_a']:
                    target_checks[0] += 1
                    if failure == 'race' and target_checks[0] == 2: return {'device': 9, 'inode': 9}
                return manifest['owned_namespaces'][name]
            def command(role, *argv):
                calls.append((role, *argv))
                return json.dumps(qdiscs) if '-j' in argv else '999\n' if failure == 'active' else ''
            with patch.object(h.lab, 'locked_state', return_value=contextlib.nullcontext(Path('journal'))), \
                    patch.object(h.lab, 'load_manifest', return_value=manifest), \
                    patch.object(h.lab, 'namespace_identity', side_effect=identity), \
                    self.subTest(failure=failure), self.assertRaises(ValueError):
                h.recreate_owned_wan(case(), spec, Path('/owned'), 'a', command)
            self.assertFalse(any('del' in row or 'add' in row or 'replace' in row for row in calls))

    def test_tool_rejection_after_owned_delete_is_preserved_without_accounting_fallback(self):
        spec, manifest, qdiscs = self.fixture(); calls = []
        def command(role, *argv):
            calls.append((role, *argv))
            if 'add' in argv: raise RuntimeError('real tool rejection')
            return json.dumps(qdiscs) if '-j' in argv else ''
        with patch.object(h.lab, 'locked_state', return_value=contextlib.nullcontext(Path('journal'))), \
                patch.object(h.lab, 'load_manifest', return_value=manifest), \
                patch.object(h.lab, 'namespace_identity', side_effect=manifest['owned_namespaces'].__getitem__), \
                self.assertRaisesRegex(RuntimeError, 'real tool rejection'):
            h.recreate_owned_wan(case(), spec, Path('/owned'), 'a', command)
        self.assertEqual([row[3] for row in calls if len(row) > 3 and row[2] == 'qdisc'], ['del', 'add'])
        self.assertFalse(any('replace' in row or 'change' in row for row in calls))

    def test_tc_observations_use_only_verified_endpoint_namespaces_and_bounded_timestamps(self):
        spec, manifest, _ = self.fixture(); calls = []
        def command(role, *argv):
            calls.append((role, *argv)); return 'actual raw tc statistics\n'
        with patch.object(h.lab, 'locked_state', return_value=contextlib.nullcontext(Path('journal'))), \
                patch.object(h.lab, 'load_manifest', return_value=manifest), \
                patch.object(h.lab, 'namespace_identity', side_effect=manifest['owned_namespaces'].__getitem__), \
                patch.object(h.time, 'monotonic_ns', side_effect=[100, 200]):
            value = h.owned_tc_snapshot(spec, Path('/owned'), command, 'tc_post_reference')
        self.assertEqual(value['started_monotonic_ns'], 100); self.assertEqual(value['finished_monotonic_ns'], 200)
        self.assertEqual([row[0] for row in calls], ['endpoint_a', 'endpoint_a', 'endpoint_b', 'endpoint_b'])
        self.assertTrue(all(row[1:3] == ('tc', '-s') and row[-3:] == ('show', 'dev', 'wan0') for row in calls))
        self.assertIn('not the exact throughput window', value['scope'])
        with patch.object(h.lab, 'locked_state', return_value=contextlib.nullcontext(Path('journal'))), \
                patch.object(h.lab, 'load_manifest', return_value=manifest), \
                patch.object(h.lab, 'namespace_identity', return_value={'device': 99, 'inode': 99}), \
                self.assertRaises(h.ObservationError):
            h.owned_tc_snapshot(spec, Path('/owned'), Mock(side_effect=AssertionError('must not run tc')), 'tc_final')

    def test_tc_partial_phase_failure_keeps_prior_reference_and_allows_final_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            receipt = h.bounded.Receipt(path, {'status': 'running', 'reference': {'exact_bytes': 123}})
            spec = h.lab.LabSpec('unit')
            with patch.object(h, 'owned_tc_snapshot', side_effect=[{'phase': 'before'},
                    RuntimeError('actual tc observation failed'), {'phase': 'final'}]):
                h.record_tc_snapshot(receipt, spec, Path('/owned'), Mock(), 'tc_before')
                with self.assertRaisesRegex(RuntimeError, 'actual tc observation failed'):
                    h.record_tc_snapshot(receipt, spec, Path('/owned'), Mock(), 'tc_post_reference')
                h.record_tc_snapshot(receipt, spec, Path('/owned'), Mock(), 'tc_final')
            value = json.loads(path.read_text())
            self.assertEqual(value['reference'], {'exact_bytes': 123})
            self.assertEqual(value['tc_before']['phase'], 'before'); self.assertEqual(value['tc_final']['phase'], 'final')
            self.assertNotIn('tc_post_reference', value)


def icmp_echo_reply(request):
    packet = bytearray(request)
    packet[12:16], packet[16:20] = request[16:20], request[12:16]
    packet[20] = 0
    packet[22:24] = bytes(2)
    packet[22:24] = h.bounded.checksum(packet[20:]).to_bytes(2, 'big')
    packet[10:12] = bytes(2)
    packet[10:12] = h.bounded.checksum(packet[:20]).to_bytes(2, 'big')
    return bytes(packet)


class IcmpSocket:
    """Deterministic raw socket boundary; no privileges or real ICMP traffic."""
    def __init__(self, clock, on_send):
        self.clock, self.on_send = clock, on_send
        self.sent, self.events, self.options, self.send_advance = [], [], [], {}
        self.closed, self.close_at = False, None
    def setsockopt(self, *option): self.options.append(option)
    def bind(self, address): self.local = address
    def connect(self, address): self.peer = address
    def settimeout(self, timeout):
        if timeout <= 0: raise AssertionError('nonpositive socket bound')
        self.timeout = timeout
    def send(self, packet):
        sequence = int.from_bytes(packet[26:28], 'big')
        self.sent.append((self.clock[0], packet))
        self.on_send(self, sequence, packet)
        self.clock[0] += self.send_advance.get(sequence, 0)
        return len(packet)
    def enqueue(self, at, packet, peer='198.18.0.2'):
        self.events.append((at, packet, (peer, 0)))
        self.events.sort(key=lambda row: row[0])
    def recvfrom(self, maximum):
        if maximum != 1501: raise AssertionError('unbounded ICMP receive')
        until = self.clock[0] + round(self.timeout * 1e9)
        if self.events and self.events[0][0] <= until:
            at, packet, peer = self.events.pop(0)
            self.clock[0] = max(at, self.clock[0])
            return packet[:maximum], peer
        self.clock[0] = until
        raise socket.timeout()
    def close(self):
        self.closed = True
        if self.close_at is not None: self.clock[0] = self.close_at


class IcmpContracts(unittest.TestCase):
    def probe(self, on_send, *, deadline=None, setup=None):
        clock = [1_000_000_000]
        stream = IcmpSocket(clock, on_send)
        if setup: setup(stream)
        factory, events = Mock(return_value=stream), []
        value = p.icmp_probe('198.18.0.1', '198.18.0.2', deadline,
            clock=lambda: clock[0], socket_factory=factory, random_bytes=lambda count: b'\x12\x34' + b'n' * 16,
            progress=events.append)
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.assertTrue(stream.closed)
        self.assertLess(len(json.dumps(value)) + sum(len(json.dumps(row)) for row in events), 64 * 1024)
        return value, stream, events

    def test_exact_three_full_mtu_df_requests_wait_for_delayed_third_reply(self):
        def sent(stream, sequence, packet):
            stream.enqueue(stream.clock[0] + (2_000_000_000 if sequence == 3 else 10_000_000), icmp_echo_reply(packet))
        result, stream, events = self.probe(sent)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual((result['sent'], result['received_unique']), (3, 3))
        self.assertEqual([at for at, packet in stream.sent], [1_000_000_000, 1_200_000_000, 1_400_000_000])
        self.assertGreater(result['completed_ns'], 3_000_000_000)
        self.assertEqual(stream.local, ('198.18.0.1', 0)); self.assertEqual(stream.peer, ('198.18.0.2', 0))
        self.assertIn((socket.IPPROTO_IP, socket.IP_HDRINCL, 1), stream.options)
        self.assertIn((socket.IPPROTO_IP, 10, 2), stream.options)
        for sequence, (_, packet) in enumerate(stream.sent, 1):
            self.assertEqual(len(packet), 1500); self.assertEqual(int.from_bytes(packet[2:4], 'big'), 1500)
            self.assertEqual(int.from_bytes(packet[6:8], 'big'), 0x4000)
            self.assertEqual(h.bounded.checksum(packet[:20]), 0); self.assertEqual(h.bounded.checksum(packet[20:]), 0)
            self.assertEqual(packet[20:22], b'\x08\0'); self.assertEqual(packet[24:26], b'\x12\x34')
            self.assertEqual(int.from_bytes(packet[26:28], 'big'), sequence)
            self.assertEqual(len(packet[28:]), 1472)
        self.assertEqual(len([row for row in events if row['event'] == 'icmp_sent']), 3)

    def test_unique_exact_replies_tolerate_duplicates_and_reordering(self):
        def sent(stream, sequence, packet):
            at = {1: 1_500_000_000, 2: 1_300_000_000, 3: 1_800_000_000}[sequence]
            stream.enqueue(at, icmp_echo_reply(packet))
            if sequence == 2: stream.enqueue(at + 10_000_000, icmp_echo_reply(packet))
        result, stream, _ = self.probe(sent)
        self.assertEqual(result['status'], 'passed'); self.assertEqual(len(stream.sent), 3)
        self.assertEqual(result['received_unique'], 3)
        self.assertEqual(result['duplicates'], 1); self.assertEqual(result['reordered'], 1)

    def test_loss_and_at_or_after_original_deadline_cannot_pass_or_retransmit(self):
        for third_at in (None, 13_000_000_000, 13_000_000_001):
            def sent(stream, sequence, packet):
                if sequence < 3: stream.enqueue(stream.clock[0] + 10_000_000, icmp_echo_reply(packet))
                elif third_at is not None: stream.enqueue(third_at, icmp_echo_reply(packet))
            with self.subTest(third_at=third_at):
                result, stream, _ = self.probe(sent)
                self.assertEqual(result['status'], 'bound_exhausted')
                self.assertEqual((result['sent'], result['received_unique']), (3, 2))
                self.assertEqual(len(stream.sent), 3); self.assertEqual(result['original_deadline_ns'], 13_000_000_000)
                self.assertEqual(result['late'], int(third_at == 13_000_000_000))

    def test_successful_send_and_finalization_crossing_expiry_keep_honest_counts(self):
        def sent(stream, sequence, packet): stream.enqueue(stream.clock[0] + 10_000_000, icmp_echo_reply(packet))
        result, stream, _ = self.probe(sent, setup=lambda stream: stream.send_advance.update({3: 11_600_000_000}))
        self.assertEqual(result['status'], 'bound_exhausted')
        self.assertEqual((result['sent'], result['received_unique']), (3, 2))
        self.assertEqual(len(stream.sent), 3); self.assertEqual(result['rows'][2]['sent_ns'], 13_000_000_000)
        result, _, _ = self.probe(sent, setup=lambda stream: setattr(stream, 'close_at', 13_000_000_000))
        self.assertEqual(result['status'], 'bound_exhausted'); self.assertEqual(result['received_unique'], 3)
        result, stream, _ = self.probe(sent, deadline=1_300_000_000)
        self.assertEqual(result['original_deadline_ns'], 1_300_000_000)
        self.assertEqual(result['status'], 'bound_exhausted'); self.assertEqual(len(stream.sent), 2)

    def test_checksums_identity_sequence_extent_and_payload_are_required(self):
        request = p.icmp_request('198.18.0.1', '198.18.0.2', 0x1234, 1, b'x' * 1472)
        exact = icmp_echo_reply(request)
        payloads = {1: b'x' * 1472}
        self.assertEqual(p.icmp_reply(exact, '198.18.0.2', '198.18.0.1', '198.18.0.2', 0x1234, payloads), ('exact', 1))
        for mutation in ('ip_checksum', 'icmp_checksum', 'identifier', 'sequence', 'extent', 'payload', 'fragment', 'peer', 'code'):
            packet, peer = bytearray(exact), '198.18.0.2'
            if mutation == 'ip_checksum': packet[10] ^= 1
            if mutation == 'icmp_checksum': packet[22] ^= 1
            if mutation == 'identifier': packet[25] ^= 1
            if mutation == 'sequence': packet[27] = 4
            if mutation == 'extent': packet.pop()
            if mutation == 'payload': packet[-1] ^= 1
            if mutation == 'fragment': packet[6:8] = b'\x20\0'
            if mutation == 'peer': peer = '198.18.0.9'
            if mutation == 'code': packet[21] = 1
            if mutation in ('sequence', 'payload', 'code'):
                packet[22:24] = bytes(2); packet[22:24] = h.bounded.checksum(packet[20:]).to_bytes(2, 'big')
            if mutation == 'fragment':
                packet[10:12] = bytes(2); packet[10:12] = h.bounded.checksum(packet[:20]).to_bytes(2, 'big')
            with self.subTest(mutation=mutation):
                self.assertNotEqual(p.icmp_reply(bytes(packet), peer, '198.18.0.1', '198.18.0.2', 0x1234, payloads)[0], 'exact')
        def sent(stream, sequence, packet):
            if sequence == 1:
                bad = bytearray(icmp_echo_reply(packet)); bad[-1] ^= 1
                stream.enqueue(stream.clock[0] + 1, bytes(bad))
            stream.enqueue(stream.clock[0] + 10_000_000, icmp_echo_reply(packet))
        result, _, _ = self.probe(sent)
        self.assertEqual(result['status'], 'failed'); self.assertEqual(result['invalid'], 1)
        self.assertEqual(result['received_unique'], 3)

    def test_ingress_and_diagnostic_bounds_preserve_partial_result(self):
        def sent(stream, sequence, packet):
            wrong = bytearray(icmp_echo_reply(packet)); wrong[25] ^= 1
            for offset in range(257): stream.enqueue(stream.clock[0] + offset + 1, bytes(wrong))
        result, stream, events = self.probe(sent)
        self.assertEqual(result['status'], 'bound_exhausted')
        self.assertEqual(result['ingress_packets'], 257); self.assertEqual(len(result['diagnostics']), 16)
        self.assertEqual(result['unrelated'], 256); self.assertEqual(result['received_unique'], 0)
        self.assertEqual(len(stream.sent), 1)

    def test_subcommand_failure_keeps_structured_result_and_original_deadline(self):
        failure = {'status': 'bound_exhausted', 'sent': 3, 'received_unique': 2, 'rows': [{'sequence': 3}]}
        with patch.object(p, 'icmp_probe', return_value=failure) as invoke, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(p.main(['icmp-probe', '--source', '198.18.0.1', '--address', '198.18.0.2',
                                     '--deadline-ns', '1234']), 1)
        self.assertEqual(invoke.call_args.args, ('198.18.0.1', '198.18.0.2', 1234))
        self.assertEqual(json.loads(output.getvalue()), failure)

    def test_expired_original_bound_and_socket_privilege_failure_remain_explicit(self):
        factory = Mock(side_effect=PermissionError('raw ICMP capability unavailable'))
        result = p.icmp_probe('198.18.0.1', '198.18.0.2', 1, clock=lambda: 2, socket_factory=factory)
        factory.assert_not_called()
        self.assertEqual(result['status'], 'bound_exhausted'); self.assertEqual(result['sent'], 0)
        result = p.icmp_probe('198.18.0.1', '198.18.0.2', clock=lambda: 2, socket_factory=factory)
        self.assertEqual(result['status'], 'tool_failure'); self.assertEqual(result['sent'], 0)
        self.assertIn('capability unavailable', result['error'])

    def test_native_capture_binds_full_mtu_df_request_and_reply_to_fresh_probe(self):
        def sent(stream, sequence, packet): stream.enqueue(stream.clock[0] + 10_000_000, icmp_echo_reply(packet))
        result, stream, _ = self.probe(sent)
        frames = [bytes(12) + b'\x08\0' + packet for _, request in stream.sent for packet in (request, icmp_echo_reply(request))]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'; path.write_bytes(pcap(frames))
            audit = h.audit_capture(path, case(), None, [{'offset_ns': 0, 'uncertainty_ns': 0}])
            matched = h.icmp_capture_complete(audit, {'functional': {'a': {'icmp': result}}})
            self.assertEqual((audit['native_icmp']['requests'], audit['native_icmp']['replies']), (3, 3))
            self.assertEqual(len(matched['probes']), 1)
            for mutation in ('missing', 'wrong_prefix', 'no_df'):
                changed = copy.deepcopy(audit)
                if mutation == 'missing': changed['native_icmp']['samples'].pop()
                if mutation == 'wrong_prefix': changed['native_icmp']['samples'][0]['payload_prefix'] = '00' * 16
                if mutation == 'no_df': changed['native_icmp']['samples'][0]['df'] = False
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    h.icmp_capture_complete(changed, {'functional': {'a': {'icmp': result}}})
            changed = bytearray(frames[0]); changed[20:22] = bytes(2)
            changed[24:26] = bytes(2); changed[24:26] = h.bounded.checksum(changed[14:34]).to_bytes(2, 'big')
            path.write_bytes(pcap([bytes(changed)]))
            with self.assertRaisesRegex(ValueError, 'DF'):
                h.audit_capture(path, case(), None, [{'offset_ns': 0, 'uncertainty_ns': 0}])


class ProbeContracts(unittest.TestCase):
    def test_explicit_flow_window_and_original_clock_limits(self):
        for flows in (1, 16): p.validate(flows, 65536, 'forward16')
        for flows, maximum, workload in [(0, 65536, 'forward16'), (17, 65536, 'forward16'),
                (True, 65536, 'forward16'), (16, 65535, 'forward16'), (16, 65536, 'unknown')]:
            with self.assertRaises(ValueError): p.validate(flows, maximum, workload)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'clock'
            with self.assertRaises(TimeoutError): p.clock_file(path, time.monotonic_ns() - 1)
            now = time.monotonic_ns()
            path.write_text(json.dumps({'start_ns': now + 1_000_000_000, 'warmup_ns': 100_000_000, 'measure_ns': 100_000_000}))
            self.assertEqual(len(p.clock_file(path, now + 5_000_000_000)), 3)
            path.write_text(json.dumps({'start_ns': now - 1, 'warmup_ns': 1, 'measure_ns': 1}))
            with self.assertRaises(ValueError): p.clock_file(path, now + 5_000_000_000)

    def test_real_loopback_forward_ack_return_and_reverse_bulk_exact_eof_hash(self):
        for reverse in (False, True):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0)); listener.listen(16)
                first, second = [], []
                for _ in range(16):
                    client = socket.create_connection(listener.getsockname()); server, _ = listener.accept()
                    first.append(client); second.append(server)
                now = time.monotonic_ns()
                start, measured, end, deadline = now + 30_000_000, now + 80_000_000, now + 200_000_000, now + 5_000_000_000
                values, failures = {}, []
                def transfer(label, streams, enabled):
                    try: values[label] = p.transfer(streams, start, measured, end, deadline, 256 * 1024 * 1024, enabled)
                    except Exception as error: failures.append(error)
                threads = [threading.Thread(target=transfer, args=('a', first, True)),
                           threading.Thread(target=transfer, args=('b', second, reverse))]
                try:
                    for thread in threads: thread.start()
                    for thread in threads: thread.join(6)
                    self.assertFalse(any(thread.is_alive() for thread in threads)); self.assertEqual(failures, [])
                    result = h.compare_probes(values['a'], values['b'], 'reverse-stress' if reverse else 'forward16')
                    self.assertEqual(result['status'], 'passed')
                    self.assertGreater(result['directions']['a_to_b']['receiver_unique_bytes'], 0)
                    reverse_bytes = result['directions']['b_to_a']['receiver_unique_bytes']
                    self.assertGreater(reverse_bytes, 0) if reverse else self.assertEqual(reverse_bytes, 0)
                    self.assertTrue(values['a']['tcp_info']); self.assertLessEqual(len(values['a']['tcp_info']), p.MAX_SAMPLES)
                finally:
                    for stream in first + second: stream.close()
                    for thread in threads: thread.join(1)

    def test_exact_udp_zeros_trailing_zeros_and_delayed_prior_retry_use_distinct_ports(self):
        # Ordinary native sockets only. Echo every packet twice so duplicate
        # prior replies remain queued while the next pattern is transmitted.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
            echo.bind(('127.0.0.1', 0)); echo.settimeout(.1)
            stop, peers, failures = threading.Event(), set(), []
            def reflect():
                while not stop.is_set():
                    try:
                        data, peer = echo.recvfrom(65535); peers.add(peer)
                        echo.sendto(data, peer); echo.sendto(data, peer)
                    except socket.timeout: continue
                    except OSError as error:
                        if not stop.is_set(): failures.append(error)
                        return
            thread = threading.Thread(target=reflect); thread.start()
            try:
                result = p.udp_probe(*echo.getsockname())
                self.assertEqual(result['status'], 'passed'); self.assertEqual(len(result['rows']), 14)
                self.assertEqual(len(peers), 14); self.assertEqual(failures, [])
                self.assertEqual([row['bytes'] for row in result['rows'][:2]], [0, 0])
                self.assertTrue(all(row['answered'] for row in result['rows']))
            finally:
                stop.set(); thread.join(1)

    def test_successful_last_blocking_io_cannot_cross_original_deadline(self):
        monotonic = [0.0]
        class Datagram:
            def __init__(self, *args): pass
            def setsockopt(self, *args): pass
            def connect(self, *args): pass
            def settimeout(self, timeout): self.timeout = timeout
            def send(self, data):
                self.data = data
                monotonic[0] += 14.9
                return len(data)
            def recv(self, maximum):
                monotonic[0] += .2
                return self.data
            def close(self): pass
        with patch.object(p.time, 'monotonic', side_effect=lambda: monotonic[0]), \
                patch.object(p.socket, 'socket', side_effect=Datagram):
            with self.assertRaisesRegex(TimeoutError, 'during receive'): p.udp_probe('127.0.0.1', 24461)
        # An already-ended final transfer may not become a successful empty
        # result merely because there was no remaining stream in the loop.
        with patch.object(p.time, 'monotonic_ns', return_value=5):
            with self.assertRaisesRegex(TimeoutError, 'final I/O'): p.transfer([], 1, 2, 3, 4, 65536, False)

    def test_byte_ceiling_reached_before_end_stays_exhausted_after_next_turn_crosses_end(self):
        stream = Mock()
        stream.getsockname.return_value = ('198.18.0.1', 30000)
        stream.getpeername.return_value = ('198.18.0.2', 24451)
        stream.recv.return_value = b''; stream.send.side_effect = len
        poll = Mock(); poll.__enter__ = Mock(return_value=poll); poll.__exit__ = Mock(return_value=False)
        key = SimpleNamespace(fileobj=stream, data=0)
        poll.select.side_effect = [[(key, p.selectors.EVENT_READ | p.selectors.EVENT_WRITE)], []]
        maximum = len(p.reference.BLOCK)
        with patch.object(p.selectors, 'DefaultSelector', return_value=poll), \
                patch.object(p.reference, 'tcp_info', return_value={}), \
                patch.object(p.time, 'monotonic_ns', side_effect=[20, 90, 99, 101, 102, 103]):
            result = p.transfer([stream], 1, 2, 100, 1000, maximum, True)
        row = result['flows'][0]
        self.assertEqual(row['sent'], maximum); self.assertTrue(row['write_closed']); self.assertTrue(row['bound_exhausted'])
        server = {'clock': result['clock'], 'send_enabled': False, 'flows': [{
            'local': row['peer'], 'peer': row['local'], 'sent': 0, 'received': maximum,
            'warmup': 0, 'measured': maximum, 'postwindow': 0, 'write_closed': True, 'eof': True,
            'bound_exhausted': False, 'sent_sha256': hashlib.sha256(b'').hexdigest(),
            'received_sha256': row['sent_sha256']}]}
        self.assertEqual(h.compare_probes(result, server, 'forward16', 1)['status'], 'bound_exhausted')


class TailCapture:
    """A producer observation, deliberately incapable of launching anything."""

    def __init__(self, returncode=None):
        self.returncode = returncode
        self.polls = 0

    def poll(self):
        self.polls += 1
        return self.returncode

    def send_signal(self, *args):
        raise AssertionError('drain must not stop or signal the producer')

    terminate = kill = send_signal

    def wait(self, *args, **kwargs):
        raise AssertionError('drain must not wait for producer termination')


class TailClock:
    """A deterministic monotonic clock with explicitly scheduled file appends."""

    def __init__(self, now=10.0):
        self.now = now
        self.events = []
        self.sleeps = []

    def __call__(self):
        return self.now

    def at(self, when, action):
        self.events.append((when, action))
        self.events.sort(key=lambda row: row[0])

    def sleep(self, delay):
        if not 0 < delay <= .020000001:
            raise AssertionError('sleep must be positive and at most 20ms')
        self.sleeps.append((self.now, delay))
        end = self.now + delay
        while self.events and self.events[0][0] <= end:
            when, action = self.events.pop(0)
            self.now = max(self.now, when)
            action()
        self.now = end


def capture_tail_fixture():
    """Four passed probe-shaped fixtures, with 24 exact request/reply records.

    Endpoint result dictionaries are trusted fixture inputs, not new endpoint
    integration evidence. Full ICMP/IP bytes are generated by the existing pure
    packet builder; pcap stores the established 160-byte snapshot.
    """
    phases, frames = {}, []
    for phase_index, phase in enumerate(('functional', 'after_reconnect')):
        phases[phase] = {}
        for side_index, side in enumerate(('a', 'b')):
            other = 'b' if side == 'a' else 'a'
            identifier = 700 + phase_index * 2 + side_index
            rows = []
            for sequence in (1, 2, 3):
                seed = bytes((phase_index + 1, side_index + 1, sequence, 0xA5))
                payload = (seed * 368)[:1472]
                request = p.icmp_request(h.HOST[side], h.HOST[other], identifier, sequence, payload)
                sent = (1 + phase_index * 2 + side_index) * 1_000_000_000 + sequence * 200_000_000
                rows.append({'sequence': sequence, 'payload_prefix': payload[:16].hex(),
                             'sent_ns': sent, 'received_ns': sent + 10_000_000})
                frames.extend(bytes(12) + b'\x08\x00' + packet
                              for packet in (request, icmp_echo_reply(request)))
            result = {'status': 'passed', 'sent': 3, 'received_unique': 3,
                      'identifier': identifier, 'rows': rows, 'request_count': 3,
                      'payload_bytes': 1472, 'ip_bytes': 1500, 'df': True,
                      'source': h.HOST[side], 'address': h.HOST[other],
                      'original_deadline_ns': 9_000_000_000}
            phases[phase][side] = {'icmp': result}
    return phases, frames, pcap(frames)


def append_capture_bytes(path, data):
    with path.open('ab') as stream:
        stream.write(data)


def final_native_capture_audit(path, phases):
    """The existing terminal authority remains separate from drain readiness."""
    audit = h.audit_capture(path, case(), None, [{'offset_ns': 0, 'uncertainty_ns': 0}])
    matched = h.icmp_capture_complete(audit, phases)
    h.capture_complete(audit, {'captured': audit['packets'], 'received': audit['packets'], 'kernel_dropped': 0})
    return audit, matched


class CaptureTailContracts(unittest.TestCase):
    def drain(self, process, path, phases, clock, deadline):
        return h.drain_native_capture(process, path, phases, deadline,
                                      clock=clock, sleeper=clock.sleep)

    def test_twenty_records_wait_for_four_exact_delayed_partial_tail_records(self):
        phases, _, complete = capture_tail_fixture()
        # 24-byte global header, then 176-byte full-MTU snapshot records.
        first_twenty = 24 + 20 * 176
        self.assertEqual(len(complete), 24 + 24 * 176)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete[:first_twenty])
            clock, process = TailClock(), TailCapture()
            # Last records are reconnect/b seq2 and3 request/reply. The first
            # append is only 7/16 bytes of a record header, then a partial body.
            for at, start, end in ((10.02, first_twenty, first_twenty + 7),
                                   (10.04, first_twenty + 7, first_twenty + 31),
                                   (10.06, first_twenty + 31, len(complete))):
                clock.at(at, lambda start=start, end=end: append_capture_bytes(path, complete[start:end]))
            with patch.object(h, 'audit_capture', side_effect=AssertionError('no history re-audit while live')):
                result = self.drain(process, path, phases, clock, 10.25)
            self.assertIsInstance(result, dict)
            self.assertGreaterEqual(clock.now, 10.06)
            self.assertLess(clock.now, 10.25)
            self.assertIsNone(process.returncode)
            audit, matched = final_native_capture_audit(path, phases)
            self.assertEqual(audit['packets'], 24)
            self.assertEqual(len(audit['native_icmp']['samples']), 24)
            self.assertEqual(len(matched['probes']), 4)
            # Final exact-counter authority is not weakened by successful drain.
            with self.assertRaises(ValueError):
                h.capture_complete(audit, {'captured': 25})

    def test_complete_witness_waits_for_trailing_partial_record_boundary(self):
        phases, _, complete = capture_tail_fixture()
        trailing = complete[24:24 + 176]
        for prefix in (7, 96):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(complete + trailing[:prefix])
                clock, process = TailClock(), TailCapture()
                clock.at(10.04, lambda: append_capture_bytes(path, trailing[prefix:]))
                result = self.drain(process, path, phases, clock, 10.25)
                self.assertEqual(result['status'], 'passed')
                self.assertEqual(result['matched_keys'], 24)
                self.assertEqual(result['packets'], 25)
                self.assertGreaterEqual(clock.now, 10.04)
                self.assertLess(clock.now, 10.25)
                audit, matched = final_native_capture_audit(path, phases)
                self.assertEqual(audit['packets'], 25)
                self.assertEqual(len(matched['probes']), 4)

    def test_observed_growth_after_eof_read_cannot_complete_witness(self):
        phases, _, complete = capture_tail_fixture()
        trailing = complete[24:24 + 176]
        read = h._NativeCaptureCursor._read
        appended = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete)
            clock, process = TailClock(), TailCapture()
            def growing_read(cursor, length):
                value = read(cursor, length)
                if not value and not appended:
                    append_capture_bytes(path, trailing[:7])
                    appended.append(True)
                return value
            clock.at(10.04, lambda: append_capture_bytes(path, trailing[7:]))
            with patch.object(h._NativeCaptureCursor, '_read', growing_read):
                result = self.drain(process, path, phases, clock, 10.25)
            self.assertEqual(appended, [True])
            self.assertEqual(result['status'], 'passed')
            self.assertEqual(result['packets'], 25)
            self.assertEqual(result['matched_keys'], 24)
            self.assertGreaterEqual(clock.now, 10.04)
            self.assertLess(clock.now, 10.25)
            audit, matched = final_native_capture_audit(path, phases)
            self.assertEqual(audit['packets'], 25)
            self.assertEqual(len(matched['probes']), 4)

    def test_live_partial_global_header_then_record_header_then_body_are_not_malformed(self):
        _, _, complete = capture_tail_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete[:9])
            cursor = h._NativeCaptureCursor(path)
            try:
                first = cursor.poll()
                self.assertTrue(first['incomplete'])
                self.assertEqual(cursor.packets, 0)
                self.assertEqual(cursor.offset, 0)
                append_capture_bytes(path, complete[9:24 + 5])
                header = cursor.poll()
                self.assertTrue(header['incomplete'])
                self.assertEqual(cursor.offset, 24)
                self.assertEqual(cursor.packets, 0)
                append_capture_bytes(path, complete[24 + 5:24 + 16 + 80])
                body = cursor.poll()
                self.assertTrue(body['incomplete'])
                self.assertEqual(cursor.offset, 24)
                self.assertEqual(cursor.packets, 0)
                append_capture_bytes(path, complete[24 + 16 + 80:24 + 176])
                done = cursor.poll()
                self.assertFalse(done['incomplete'])
                self.assertEqual(cursor.offset, 24 + 176)
                self.assertEqual(cursor.packets, 1)
            finally:
                cursor.close()

    def test_same_partial_inputs_fail_when_terminal(self):
        _, _, complete = capture_tail_fixture()
        for length in (9, 24 + 5, 24 + 16 + 80):
            with self.subTest(length=length), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(complete[:length])
                cursor = h._NativeCaptureCursor(path)
                try:
                    with self.assertRaises((ValueError, h.ObservationError)):
                        cursor.poll(terminal=True)
                    self.assertEqual(cursor.packets, 0)
                finally:
                    cursor.close()

    def test_complete_invalid_headers_fail_immediately_while_producer_live(self):
        _, _, complete = capture_tail_fixture()
        bad_magic = b'BAD!' + complete[4:24]
        bad_extent = complete[:24] + struct.pack('<IIII', 1, 0, 161, 1514) + bytes(161)
        for raw in (bad_magic, bad_extent):
            with self.subTest(raw=raw[:8]), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(raw)
                cursor = h._NativeCaptureCursor(path)
                try:
                    with self.assertRaises((ValueError, h.ObservationError)):
                        cursor.poll()
                    self.assertEqual(cursor.packets, 0)
                finally:
                    cursor.close()

    def test_equal_record_count_with_duplicate_instead_of_exact_key_does_not_qualify(self):
        phases, frames, _ = capture_tail_fixture()
        frames[-1] = frames[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap(frames))
            clock = TailClock()
            with self.assertRaises(h.BoundExhausted):
                self.drain(TailCapture(), path, phases, clock, 10.055)
            self.assertLessEqual(clock.now, 10.055000001)
            self.assertTrue(all(start + delay <= 10.055000001 for start, delay in clock.sleeps))
            with self.assertRaisesRegex(ValueError, 'missing exact'):
                final_native_capture_audit(path, phases)

    def test_wrong_fresh_prefix_or_identifier_is_not_a_tail_match(self):
        phases, frames, _ = capture_tail_fixture()
        for mutation in ('prefix', 'identifier'):
            changed = copy.deepcopy(frames)
            identifier = phases['after_reconnect']['b']['icmp']['identifier']
            payload = bytes.fromhex(phases['after_reconnect']['b']['icmp']['rows'][2]['payload_prefix']) * 92
            if mutation == 'prefix':
                payload = bytes([payload[0] ^ 1]) + payload[1:]
            else:
                identifier += 50
            wrong = p.icmp_request(h.HOST['b'], h.HOST['a'], identifier, 3, payload)
            changed[-1] = bytes(12) + b'\x08\x00' + icmp_echo_reply(wrong)
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(pcap(changed))
                clock = TailClock()
                with self.assertRaises(h.BoundExhausted):
                    self.drain(TailCapture(), path, phases, clock, 10.04)

    def test_new_drain_requires_four_passed_probes_and_twenty_four_distinct_keys(self):
        phases, _, complete = capture_tail_fixture()
        for mutation in ('phase', 'side', 'failed', 'count', 'sequences', 'duplicate_keys'):
            changed = copy.deepcopy(phases)
            if mutation == 'phase':
                del changed['after_reconnect']
            elif mutation == 'side':
                del changed['after_reconnect']['b']
            elif mutation == 'failed':
                changed['after_reconnect']['b']['icmp']['status'] = 'failed'
            elif mutation == 'count':
                changed['after_reconnect']['b']['icmp']['received_unique'] = 2
            elif mutation == 'sequences':
                changed['after_reconnect']['b']['icmp']['rows'][2]['sequence'] = 2
            else:
                changed['after_reconnect'] = copy.deepcopy(changed['functional'])
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(complete)
                clock = TailClock()
                with self.assertRaises((ValueError, h.ObservationError)):
                    self.drain(TailCapture(), path, changed, clock, 10.04)
                self.assertEqual(clock.sleeps, [])
        # The old checker retains its intentionally partial-scope contract.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete)
            audit = h.audit_capture(path, case(), None, [{'offset_ns': 0, 'uncertainty_ns': 0}])
            checked = h.icmp_capture_complete(audit, {'functional': {'a': phases['functional']['a']}})
            self.assertEqual(len(checked['probes']), 1)

    def test_expired_original_deadline_rejects_even_already_complete_saved_capture(self):
        phases, _, complete = capture_tail_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete)
            clock = TailClock(10.0)
            with self.assertRaises(h.BoundExhausted):
                self.drain(TailCapture(), path, phases, clock, 10.0)
            self.assertEqual(clock.sleeps, [])

    def test_exact_deadline_tail_append_cannot_renew_or_satisfy_original_bound(self):
        phases, _, complete = capture_tail_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete[:24 + 20 * 176])
            clock = TailClock()
            clock.at(10.04, lambda: append_capture_bytes(path, complete[24 + 20 * 176:]))
            with self.assertRaises(h.BoundExhausted):
                self.drain(TailCapture(), path, phases, clock, 10.04)
            self.assertLessEqual(clock.now, 10.040000001)

    def test_deadline_is_rechecked_after_bounded_read_before_accepting_saved_keys(self):
        phases, _, complete = capture_tail_fixture()
        original = h._NativeCaptureCursor.poll
        clock = TailClock()

        def read_at_deadline(cursor, *args, **kwargs):
            result = original(cursor, *args, **kwargs)
            clock.now = 10.04
            return result

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete)
            with patch.object(h._NativeCaptureCursor, 'poll', read_at_deadline):
                with self.assertRaises(h.BoundExhausted):
                    self.drain(TailCapture(), path, phases, clock, 10.04)

    def test_deadline_is_rechecked_after_owned_cursor_close_before_success(self):
        phases, _, complete = capture_tail_fixture()
        original = h._NativeCaptureCursor.close
        clock = TailClock()

        def close_at_deadline(cursor):
            original(cursor)
            clock.now = 10.04

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete)
            with patch.object(h._NativeCaptureCursor, 'close', close_at_deadline):
                with self.assertRaises(h.BoundExhausted):
                    self.drain(TailCapture(), path, phases, clock, 10.04)

    def test_exited_producer_with_complete_saved_tail_is_allowed_before_final_checks(self):
        phases, _, complete = capture_tail_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete)
            clock = TailClock()
            result = self.drain(TailCapture(returncode=0), path, phases, clock, 10.1)
            self.assertIsInstance(result, dict)
            self.assertEqual(clock.sleeps, [])
            final_native_capture_audit(path, phases)

    def test_exited_producer_is_scanned_past_first_work_chunk_before_missing_rejection(self):
        phases, frames, _ = capture_tail_fixture()
        arp = bytes(12) + b'\x08\x06' + bytes(28)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap([arp] * 5000 + frames))
            clock = TailClock()
            result = self.drain(TailCapture(returncode=0), path, phases, clock, 10.1)
            self.assertIsInstance(result, dict)
            self.assertEqual(clock.sleeps, [])
            audit, _ = final_native_capture_audit(path, phases)
            self.assertEqual(audit['packets'], 5024)

    def test_exited_producer_missing_keys_or_terminal_partial_fails_without_sleep(self):
        phases, _, complete = capture_tail_fixture()
        for length in (24 + 20 * 176, len(complete) - 1):
            with self.subTest(length=length), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(complete[:length])
                clock = TailClock()
                with self.assertRaises((ValueError, h.ObservationError)):
                    self.drain(TailCapture(returncode=0), path, phases, clock, 10.1)
                self.assertEqual(clock.sleeps, [])

    def test_cursor_work_chunks_commit_each_complete_record_once_and_do_not_rescan_eof(self):
        _, _, complete = capture_tail_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(complete)
            cursor = h._NativeCaptureCursor(path)
            try:
                for index in range(24):
                    step = cursor.poll(max_records=1)
                    self.assertEqual(step['records_read'], 1)
                    self.assertEqual(cursor.packets, index + 1)
                    self.assertEqual(cursor.offset, 24 + (index + 1) * 176)
                read = cursor.bytes_read
                self.assertEqual(read, len(complete))
                for _ in range(20):
                    end = cursor.poll(max_records=1)
                    self.assertTrue(end['at_end'])
                    self.assertEqual(end['records_read'], 0)
                    self.assertEqual(cursor.bytes_read, read)
                    self.assertEqual(cursor.packets, 24)
            finally:
                cursor.close()

    def test_cursor_accepts_all_four_existing_pcap_byte_order_and_precision_formats(self):
        phases, frames, _ = capture_tail_fixture()
        for endian in ('<', '>'):
            for nanoseconds in (False, True):
                magic = 0xa1b23c4d if nanoseconds else 0xa1b2c3d4
                raw = bytearray(struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, 160, 1))
                for frame_bytes in frames:
                    raw += struct.pack(endian + 'IIII', 1, 500_000_000 if nanoseconds else 500_000,
                                       160, len(frame_bytes))
                    raw += frame_bytes[:160]
                with self.subTest(endian=endian, nanoseconds=nanoseconds), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'native.pcap'
                    path.write_bytes(raw)
                    cursor = h._NativeCaptureCursor(path)
                    try:
                        cursor.poll(terminal=True)
                        self.assertEqual(cursor.packets, 24)
                        self.assertEqual(cursor.offset, len(raw))
                    finally:
                        cursor.close()
                    final_native_capture_audit(path, phases)

    def test_cursor_byte_packet_and_raw_icmp_sample_caps_remain_terminal(self):
        _, frames, complete = capture_tail_fixture()
        for bound, value, raw in (
                ('capture_bytes', len(complete), complete),
                ('capture_packets', 24, complete),
                # Raw duplicate observations count toward the existing128 cap,
                # even when all exact matching keys appeared earlier.
                (None, None, pcap(frames + [frames[0]] * 105))):
            with self.subTest(bound=bound), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(raw)
                bounds = dict(h.BOUNDS)
                if bound is not None:
                    bounds[bound] = value
                with patch.dict(h.BOUNDS, bounds, clear=True):
                    cursor = h._NativeCaptureCursor(path)
                    try:
                        with self.assertRaises(h.BoundExhausted):
                            cursor.poll()
                    finally:
                        cursor.close()

    def test_cursor_replacement_or_observed_shrink_cannot_splice_saved_evidence(self):
        _, _, complete = capture_tail_fixture()
        for mutation in ('replace', 'shrink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(complete)
                cursor = h._NativeCaptureCursor(path)
                try:
                    cursor.poll(max_records=1)
                    if mutation == 'replace':
                        path.rename(path.with_suffix('.old'))
                        path.write_bytes(complete)
                    else:
                        path.write_bytes(complete[:24 + 176])
                    with self.assertRaises((ValueError, h.ObservationError)):
                        cursor.poll()
                    self.assertEqual(cursor.packets, 1)
                finally:
                    cursor.close()

    def test_cursor_refuses_symlink_instead_of_adopting_capture_path(self):
        _, _, complete = capture_tail_fixture()
        with tempfile.TemporaryDirectory() as directory:
            target, link = Path(directory) / 'target.pcap', Path(directory) / 'native.pcap'
            target.write_bytes(complete)
            link.symlink_to(target)
            cursor = h._NativeCaptureCursor(link)
            try:
                with self.assertRaises((ValueError, h.ObservationError, OSError)):
                    cursor.poll()
                self.assertEqual(cursor.packets, 0)
            finally:
                cursor.close()

    def test_run_case_drain_failure_preserves_original_error_stops_and_audits_captures(self):
        self.run_case_drain_failure(False)

    def test_run_case_drain_evidence_publication_failure_still_stops_and_audits_captures(self):
        self.run_case_drain_failure(True)

    def run_case_drain_failure(self, publication_failure):
        # Exercise the actual finally orchestration. Every external operation is
        # fake; no namespace, child or host network state is created. Completed
        # probe-shaped fixtures only seed retained receipt inputs for this path.
        phases, _, _ = capture_tail_fixture()
        original_receipt = h.bounded.Receipt
        original_exists, original_read = Path.exists, Path.read_text
        events, children = [], []
        spec = h.lab.LabSpec('unit')
        journal = Path('/run/l2tunnel-secure-native/unit.json')
        namespaces = {h.lab.NETNS_DIRECTORY / name for name in spec.namespaces.values()}
        observation = {'status': 'bound_exhausted', 'expected_keys': 24, 'matched_keys': 20,
                       'missing': [{'phase': 'after_reconnect', 'side': 'b', 'sequence': 3}]}

        def receipt(path, initial):
            actual = original_receipt(path, {**initial, **phases, 'retained_sentinel': 'earlier evidence'})
            update = actual.update

            def retain(**fields):
                if publication_failure and 'native_capture_drain' in fields:
                    raise OSError('fixture capture evidence publication failure')
                update(**fields)

            actual.update = retain
            return actual

        def exists(path):
            if path == journal:
                return True
            if path in namespaces:
                return False
            return original_exists(path)

        def read(path, *args, **kwargs):
            return '{}' if path == journal else original_read(path, *args, **kwargs)

        def launch(argv, log, **kwargs):
            if len(children) == 4:
                raise ValueError('original daemon startup failure')
            child = TailCapture()
            child.name = Path(log).stem
            children.append(child)
            Path(log).write_text('24 packets captured\n24 packets received by filter\n0 packets dropped by kernel\n')
            return child

        def stop(child, **kwargs):
            events.append(('stop', child.name))
            child.returncode = 0

        def drain(process, path, supplied_phases, deadline, **kwargs):
            self.assertIs(process, children[2])
            self.assertEqual(deadline, 340.0)
            self.assertEqual(supplied_phases['functional'], phases['functional'])
            self.assertIn(('stop', 'daemon-b'), events)
            self.assertFalse(any(name.endswith('-capture') for event, name in events if event == 'stop'))
            events.append(('drain', 'native-a'))
            error = h.BoundExhausted('fixture missing native capture tail')
            error.capture_drain = copy.deepcopy(observation)
            raise error

        def audit(path, *args, **kwargs):
            events.append(('audit', path.stem))
            self.assertTrue(all(child.returncode == 0 for child in children))
            return {'packets': 24, 'arp': 1, 'native_icmp': {'samples': []}}

        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            output = Path(directory)
            (output / 'l2tunnel-native').write_bytes(b'fixture binary')
            (output / 'build-receipt.json').write_text('{}')
            patches = [
                patch.object(Path, 'exists', exists), patch.object(Path, 'read_text', read),
                patch.object(h.time, 'monotonic', return_value=100.0),
                patch.object(h.bounded, 'Receipt', side_effect=receipt),
                patch.object(h, 'verify_helpers', return_value={}),
                patch.object(h.shutil, 'which', return_value='/fixture/tool'),
                patch.object(h.bounded, 'command', return_value='fixture command output'),
                patch.object(h, 'resource_context', return_value={}),
                patch.object(h.bounded, 'bounded_lab'),
                patch.object(h.bounded, 'disable_underlay_ipv6'),
                patch.object(h.bounded, 'offloads', return_value={}),
                patch.object(h, 'recreate_owned_wan', return_value={}),
                patch.object(h, 'record_tc_snapshot'),
                patch.object(h.bounded, 'launch', side_effect=launch),
                patch.object(h.bounded, 'wait_log'),
                patch.object(h, 'credentials', return_value=public()),
                patch.object(h.bounded, 'stop', side_effect=stop),
                patch.object(h, 'drain_native_capture', side_effect=drain),
                patch.object(h, 'audit_capture', side_effect=audit),
                patch.object(h, 'icmp_capture_complete', return_value={'probes': []}),
            ]
            for operation in patches:
                stack.enter_context(operation)
            result = h.run_case(case(), output, {}, {'fixture': True})
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['cleanup'], 'passed')
            self.assertEqual(result['retained_sentinel'], 'earlier evidence')
            messages = [row.get('error', '') for row in result['errors']]
            self.assertTrue(any('original daemon startup failure' in value for value in messages))
            self.assertTrue(any('fixture missing native capture tail' in value for value in messages))
            self.assertTrue(any(row['status'] == 'bound_exhausted' for row in result['errors']))
            if publication_failure:
                self.assertTrue(any('fixture capture evidence publication failure' in value for value in messages))
            else:
                self.assertEqual(result['native_capture_drain'], observation)
            self.assertEqual(set(result['capture_audits']), {'wan-a', 'wan-b', 'native-a'})
            self.assertEqual([event for event, _ in events].count('drain'), 1)
            self.assertEqual([event for event, _ in events].count('audit'), 3)
            self.assertEqual({name for event, name in events if event == 'stop'},
                             {'daemon-b', 'wan-a-capture', 'wan-b-capture', 'native-a-capture'})
            self.assertTrue(all(name + '_capture_counters' in result for name in ('wan-a', 'wan-b', 'native-a')))

    def test_drain_closes_its_owned_cursor_on_success_deadline_and_malformed_failure(self):
        phases, _, complete = capture_tail_fixture()
        original = h._NativeCaptureCursor.close
        for mode in ('success', 'deadline', 'malformed'):
            closed = []

            def close(cursor):
                closed.append(id(cursor))
                return original(cursor)

            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                raw = complete if mode == 'success' else complete[:24 + 20 * 176]
                if mode == 'malformed':
                    raw = b'BAD!' + complete[4:24]
                path.write_bytes(raw)
                with patch.object(h._NativeCaptureCursor, 'close', close):
                    if mode == 'success':
                        self.drain(TailCapture(), path, phases, TailClock(), 10.04)
                    else:
                        with self.assertRaises((ValueError, h.ObservationError, h.BoundExhausted)):
                            self.drain(TailCapture(), path, phases, TailClock(), 10.04)
                self.assertEqual(len(set(closed)), 1)



if __name__ == '__main__':
    unittest.main()
