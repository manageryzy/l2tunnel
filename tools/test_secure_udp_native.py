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
                failed_ping = '3 packets transmitted, 2 received, 33.3333% packet loss\n'
                launched, stopped, observed = [], [], []
                def launch(role, argv, name):
                    Path(argv[argv.index('--ready') + 1]).write_text('ready')
                    child = Mock(); child.poll.return_value = None
                    launched.append(child)
                    return child, output / (name + '.log')
                def command(role, *argv, cap):
                    if argv[0] == 'ping':
                        self.assertEqual(cap, 12)
                        self.assertEqual(argv[1:-1], ('-n', '-c', '3', '-i', '.2', '-W', '3', '-M', 'do', '-s', '1472'))
                        return '3 packets transmitted, 3 received, 0% packet loss\n' if role == 'host_a' else failed_ping
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


if __name__ == '__main__':
    unittest.main()
