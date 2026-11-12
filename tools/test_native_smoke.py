"""Regression checks for finite native-smoke acceptance evidence."""
import unittest
import subprocess
import sys
import copy
import json
import io
import struct
import tempfile
import hashlib
import select
import socket
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path
from .native_smoke import verify_ping, verify_state, verify_blocked_ping, active_policy, verify_active_state, verify_active_peers, remaining, observation_snapshot, audit_openvpn_capture, CaseEvidence, outage_timing, terminal_observation, standalone_outage, case_name
from .tcp_probe import progress_record, save_progress, MAXIMUM, PROGRESS_BYTES

class AcceptanceTests(unittest.TestCase):
    def test_full_netem_is_explicit_and_default_matrix_unchanged(self):
        tool = Path(__file__).with_name('native_smoke.py')
        base = [sys.executable, str(tool), '--include-netem']
        default = subprocess.run(base, capture_output=True, text=True, timeout=10)
        self.assertEqual(default.returncode, 0, default.stderr)
        value = json.loads(default.stdout)
        self.assertEqual(value['cases'], [[layer, mode, loss] for layer in ('tap', 'tun')
                         for mode, loss in (('half', False), ('full', False))]
                         + [[layer, 'half', True] for layer in ('tap', 'tun')])
        self.assertEqual((value['netem_duplex'], value['tcp_family']), ('half', 4))
        both = subprocess.run([*base, '--netem-duplex', 'both'], capture_output=True, text=True, timeout=10)
        self.assertEqual(both.returncode, 0, both.stderr)
        self.assertEqual(json.loads(both.stdout)['cases'], value['cases'][:4]
                         + [[layer, mode, True] for layer in ('tap', 'tun') for mode in ('half', 'full')])
        for layer in ('tap', 'tun'):
            result = subprocess.run([*base, '--layers', layer, '--netem-duplex', 'full',
                                     '--only-case', f'{layer}-full-netem', '--tcp-family', '6'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            selected = json.loads(result.stdout)
            self.assertEqual(selected['cases'], [[layer, 'full', True]])
            self.assertEqual((selected['tcp_family'], selected['netem_duplex']), (6, 'full'))

    def test_invalid_full_netem_or_tcp_family_cannot_reach_mutation(self):
        from . import native_smoke as native
        for options in (['--netem-duplex', 'full'], ['--only-case', 'tap-full-netem'],
                        ['--include-netem', '--only-case', 'tap-full-netem'], ['--tcp-family', '5']):
            with self.subTest(options=options), patch.object(sys, 'argv', ['native_smoke.py', '--apply', *options]), \
                    patch.object(native.netns_lab, 'require_root') as root, \
                    patch.object(native.netns_lab, 'apply') as apply, patch('sys.stderr', new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error:
                    native.main()
                self.assertEqual(error.exception.code, 2)
                root.assert_not_called()
                apply.assert_not_called()

    @staticmethod
    def receive_exact(stream, count):
        received = bytearray()
        while len(received) < count:
            data = stream.recv(count - len(received))
            if not data:
                raise EOFError('independent TCP fixture received incomplete bytes')
            received.extend(data)
        return bytes(received)

    def test_real_ipv4_ipv6_probe_listener_checks_independent_bytes(self):
        tool = Path(__file__).with_name('tcp_probe.py')
        payload = bytes(range(256)) * 256
        for version, family, host in ((4, socket.AF_INET, '127.0.0.1'), (6, socket.AF_INET6, '::1')):
            with self.subTest(version=version), subprocess.Popen(
                    [sys.executable, str(tool), 'listen', host, '--family', str(version), '--port', '0'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as server:
                try:
                    self.assertTrue(select.select([server.stdout], [], [], 5)[0], 'probe listener readiness timed out')
                    line = server.stdout.readline(256)
                    self.assertTrue(line.startswith('Listening '), line)
                    ready = json.loads(line.partition(' ')[2])
                    self.assertEqual(ready['ip_version'], version)
                    with socket.socket(family, socket.SOCK_STREAM) as client:
                        client.settimeout(5)
                        client.connect((host, ready['port']))
                        self.assertEqual(client.family, family)
                        client.sendall(len(payload).to_bytes(4, 'big') + payload)
                        self.assertEqual(self.receive_exact(client, 32), hashlib.sha256(payload).digest())
                    stdout, stderr = server.communicate(timeout=5)
                    self.assertEqual(server.returncode, 0, stdout + stderr)
                finally:
                    if server.poll() is None:
                        server.kill()
                        server.communicate(timeout=5)

    def test_real_ipv4_ipv6_probe_sender_matches_historical_exact_digest(self):
        self.check_real_probe_sender(4, socket.AF_INET, '127.0.0.1')
        self.check_real_probe_sender(6, socket.AF_INET6, '::1')

    def test_ipv6_probe_cannot_fall_back_to_mapped_ipv4(self):
        tool = Path(__file__).with_name('tcp_probe.py')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            result = subprocess.run([sys.executable, str(tool), 'send', '::ffff:127.0.0.1',
                                     '--family', '6', '--port', str(server.getsockname()[1])],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            server.settimeout(.1)
            with self.assertRaises(TimeoutError):
                server.accept()

    def test_real_ipv6_probe_rejects_corrupted_return_checksum(self):
        self.check_real_probe_sender(6, socket.AF_INET6, '::1', corrupt=True)

    def check_real_probe_sender(self, version, family, host, corrupt=False):
        from .native_smoke import verify_tcp_payload
        # The unchanged fixed-seed 64KiB digest is preserved in native-wave4's receipt.
        expected = 'a863d4360888ecceb6f59e575cd4eaa590b127c5a096a43e92d1274b5dccb5c9'
        tool = Path(__file__).with_name('tcp_probe.py')
        with self.subTest(version=version, corrupt=corrupt), socket.socket(family, socket.SOCK_STREAM) as server:
            server.settimeout(5)
            server.bind((host, 0))
            server.listen(1)
            with subprocess.Popen([sys.executable, str(tool), 'send', host, '--family', str(version),
                                   '--port', str(server.getsockname()[1])],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as client:
                try:
                    connection, _peer = server.accept()
                    with connection:
                        connection.settimeout(5)
                        count = int.from_bytes(self.receive_exact(connection, 4), 'big')
                        self.assertEqual(count, 65536)
                        payload = self.receive_exact(connection, count)
                        self.assertEqual(hashlib.sha256(payload).hexdigest(), expected)
                        connection.sendall(bytes(32) if corrupt else bytes.fromhex(expected))
                    stdout, stderr = client.communicate(timeout=5)
                    if corrupt:
                        self.assertNotEqual(client.returncode, 0)
                        self.assertIn('checksum mismatch', stderr)
                    else:
                        self.assertEqual(client.returncode, 0, stderr)
                        result = json.loads(stdout)
                        verify_tcp_payload(result, version, 65536)
                        self.assertEqual(result['sha256'], expected)
                finally:
                    if client.poll() is None:
                        client.kill()
                        client.communicate(timeout=5)

    def test_tcp_family_witness_mismatch_is_rejected(self):
        from .native_smoke import verify_tcp_payload
        valid = {'status': 'passed', 'ip_version': 6, 'bytes': 65536, 'sha256': 'a' * 64}
        verify_tcp_payload(valid, 6, 65536)
        for key, value in (('status', 'failed'), ('ip_version', 4), ('ip_version', True),
                           ('bytes', 65535), ('sha256', 'a' * 63)):
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                verify_tcp_payload({**valid, key: value}, 6, 65536)

    def test_separate_outage_timing_and_terminal_predicates_are_strict(self):
        short = {'a': {'install_started': 0., 'installed': .01, 'remove_started': .26, 'removed': .3}}
        self.assertEqual(outage_timing(short, 'short-recovery')['joint_blocked_seconds_lower_bound'], .25)
        for field, value in [('removed', .50001), ('remove_started', .25999), ('installed', float('nan')), ('install_started', -1)]:
            changed = copy.deepcopy(short)
            changed['a'][field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, RuntimeError)):
                outage_timing(changed, 'short-recovery')
        idle = {'a': {'install_started': 0., 'installed': .01, 'remove_started': 4.125, 'removed': 4.25},
                'b': {'install_started': .01, 'installed': .125, 'remove_started': 4.125, 'removed': 4.25}}
        self.assertAlmostEqual(outage_timing(idle, 'idle-loss')['joint_blocked_seconds_lower_bound'], 4.)
        for changed in ({'a': idle['a']}, {**idle, 'b': {**idle['b'], 'removed': 5.12501}}):
            with self.assertRaises((ValueError, RuntimeError)):
                outage_timing(changed, 'idle-loss')
        line = 'l2tunnel: carrier Timeout; deadline cause not distinguished'
        self.assertEqual(terminal_observation(1, line, 4, 5)['class'], 'Timeout')
        owner = 'l2tunnel: carrier ended before distributed native drain; incomplete; lane 0 terminal=None closing=false; lane 1 terminal=Some(IncompleteClose) closing=true; '
        self.assertEqual(terminal_observation(1, owner, 4, 5)['class'], 'IncompleteClose')
        for code, text, at in [(0, line, 4), (None, line, 4), (-15, line, 4), (1, line, 5.00001), (1, line, -1), (-15, 'l2tunnel: native source stream ended', 4),
                               (1, 'l2tunnel: carrier Closed; native drain incomplete', 4), (1, owner.replace('IncompleteClose', 'Failed'), 4),
                               (1, owner.replace('Some(IncompleteClose)', 'None'), 4)]:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                terminal_observation(code, text, at, 5)

    def test_separate_outage_fake_clock_removes_filters_and_keeps_absolute_deadline(self):
        blocked = '1 packets transmitted, 0 received, 100% packet loss'
        for profile, bad_ping, terminal, removal_failure in [('short-recovery', False, False, False), ('short-recovery', True, False, False),
                                           ('idle-loss', False, True, False), ('idle-loss', False, False, False), ('idle-loss', False, True, True)]:
            with self.subTest(profile=profile, bad_ping=bad_ping, terminal=terminal, removal_failure=removal_failure), tempfile.TemporaryDirectory() as directory:
                clock = [0.]
                calls = []
                def advance(seconds):
                    clock[0] += seconds
                def run_command(argv, **_):
                    calls.append(argv)
                    advance(.01)
                    if removal_failure and 'del' in argv and 'eb' in argv:
                        raise OSError('injected first filter removal failure')
                    return 'dropped 1' if 'show' in argv else ''
                def run_ping(argv, **_):
                    self.assertEqual(argv[argv.index('-W') + 1], '0.2')
                    advance(.2)
                    return SimpleNamespace(returncode=0 if bad_ping else 1, stdout=blocked, stderr='')
                log = Path(directory) / 'endpoint.log'
                log.write_text('l2tunnel: carrier Timeout; deadline cause not distinguished\n')
                process = SimpleNamespace(returncode=1, poll=lambda: 1 if terminal and clock[0] >= 3.0 else None)
                journal = CaseEvidence(Path(directory) / 'case.json', profile)
                with patch('tools.native_smoke.time.monotonic', side_effect=lambda: clock[0]), patch('tools.native_smoke.time.sleep', side_effect=advance), patch('tools.native_smoke.command', side_effect=run_command), patch('tools.native_smoke.subprocess.run', side_effect=run_ping):
                    args = (profile, {'endpoint_a': 'ea', 'endpoint_b': 'eb'}, 'ea', '198.19.0.2', {'a': (process, log), 'b': (process, log)}, journal, 0.)
                    if removal_failure:
                        with self.assertRaisesRegex(OSError, 'injected first filter removal failure'):
                            standalone_outage(*args)
                    elif bad_ping:
                        with self.assertRaises(RuntimeError):
                            standalone_outage(*args)
                    elif profile == 'idle-loss' and not terminal:
                        with self.assertRaises(TimeoutError):
                            standalone_outage(*args)
                        self.assertAlmostEqual(clock[0], 5.02)
                    else:
                        result = standalone_outage(*args)
                        self.assertEqual(result['profile'], profile)
                        if terminal:
                            self.assertEqual(set(result['terminal']), {'a', 'b'})
                            self.assertEqual(result['terminal_deadline_seconds'], 5.02)
                self.assertEqual(len([call for call in calls if 'del' in call]), 1 if profile == 'short-recovery' else 2)
                saved = json.loads(journal.path.read_text())['completed']['udp_path_check']
                if removal_failure:
                    self.assertIn('remove_error', saved['events']['b'])
                    self.assertNotIn('removed', saved['events']['b'])
                    self.assertIn('removed', saved['events']['a'])
                else:
                    self.assertTrue(all('removed' in event for event in saved['events'].values()))

    def test_separate_outage_cli_names_are_explicit_and_scope_is_narrow(self):
        tool = Path(__file__).with_name('native_smoke.py')
        for profile in ('short-recovery', 'idle-loss'):
            base = [sys.executable, str(tool), '--carrier', 'openvpn-like', '--layers', 'tun', '--only-case', 'tun-half-clean', '--openvpn-path-probe', profile]
            result = subprocess.run(base, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['openvpn_path_probe'], profile)
            self.assertEqual(case_name('tun', 'half', False, profile), f'tun-half-clean-{profile}')
            for extra in (['--carrier', 'quic'], ['--only-case', 'tun-full-clean'], ['--layers', 'tap'], ['--include-netem'], ['--compression', 'lz4'], ['--udp-protection', 'integrity']):
                result = subprocess.run([*base, *extra], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(case_name('tun', 'half', False), 'tun-half-clean')

    def test_incremental_evidence_retains_completed_hash_and_refuses_history_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'new-case-partial.json'
            journal = CaseEvidence(path, 'new-case')
            stdout = '{"bytes": 131072, "sha256": "' + 'a' * 64 + '"}\n'
            journal.record('tcp_sender_stdout', stdout)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            payload = json.loads(stdout)
            journal.record('tcp_payload', payload)
            payload['bytes'] = 0
            journal.update(status='failed', stage='udp_restoration_probe', error='one sent, zero received')
            saved = json.loads(path.read_text())
            self.assertEqual(saved['status'], 'failed')
            self.assertEqual(saved['completed']['tcp_sender_stdout'], stdout)
            self.assertEqual(saved['completed']['tcp_payload']['bytes'], 131072)
            with self.assertRaises(FileExistsError):
                CaseEvidence(path, 'replacement')
            self.assertEqual(json.loads(path.read_text()), saved)
            self.assertEqual(list(Path(directory).glob('*.tmp')), [])

    def test_incremental_evidence_replacement_and_size_failure_leave_prior_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'new-case-partial.json'
            journal = CaseEvidence(path, 'new-case')
            journal.record('probe', {'stdout': '1 packets transmitted, 1 received, 0% packet loss'})
            previous = path.read_bytes()
            with patch('tools.native_smoke.os.replace', side_effect=OSError('injected replacement failure')):
                with self.assertRaises(OSError):
                    journal.update(status='failed')
            self.assertEqual(path.read_bytes(), previous)
            self.assertEqual(journal.value, json.loads(previous))
            with patch.object(CaseEvidence, 'MAXIMUM_BYTES', 32):
                with self.assertRaises(ValueError):
                    journal.record('oversize', 'x' * 33)
            self.assertEqual(path.read_bytes(), previous)
            self.assertEqual(list(Path(directory).glob('*.tmp')), [])

    def test_standalone_dry_run_is_explicit_and_rejects_mixed_profiles(self):
        tool = Path(__file__).with_name('native_smoke.py')
        base = [sys.executable, str(tool), '--carrier', 'openvpn-like', '--layers', 'tun', '--only-case', 'tun-half-clean']
        result = subprocess.run(base, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['cases'], [['tun', 'half', False]])
        self.assertEqual(receipt['carrier'], 'openvpn-like')
        for extra in (['--udp-cover', 'openvpn-like'], ['--fec', 'cauchy'], ['--hot-switch'], ['--traffic', 'active'], ['--record-profile', 'aligned']):
            result = subprocess.run([*base, *extra], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stdout)

    @staticmethod
    def standalone_pcap(duplex='half'):
        data = bytearray(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 262144, 1))
        for port in ([24440, 24441] if duplex == 'half' else [24440]):
            for opcode, kind in [(56, 1), (64, 2), (56, 3), (32, 0), (40, 0), (72, 0)]:
                payload = bytearray(144 if kind else 64)
                payload[:4] = bytes([opcode, 1, kind, 0])
                ip = bytearray(20)
                ip[0] = 0x45
                ip[2:4] = struct.pack('!H', 28 + len(payload))
                ip[9] = 17
                ip[12:20] = b'\xc0\x00\x02\x02\xc0\x00\x02\x06'
                frame = bytes(12) + b'\x08\x00' + ip + struct.pack('!HHHH', port, port, 8 + len(payload), 0) + payload
                data.extend(struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame)
        return bytes(data)

    def test_standalone_capture_requires_exact_lane_geometry_and_complete_gate(self):
        data = self.standalone_pcap()
        result = audit_openvpn_capture(data, 1200, 'half')
        self.assertEqual(result['packets'], 12)
        self.assertEqual(result['maximum_ip_bytes'], 172)
        self.assertEqual(set(result['lanes']), {'24440', '24441'})
        self.assertEqual(audit_openvpn_capture(self.standalone_pcap('full'), 1200, 'full')['packets'], 6)
        for offset, value in [(20, 101), (24 + 8, 1), (24 + 16 + 12, 0),
                              (24 + 16 + 16, 0xff), (24 + 16 + 20, 0x20),
                              (24 + 16 + 23, 6), (24 + 16 + 26, 1),
                              (24 + 16 + 34, 0), (24 + 16 + 38, 0xff),
                              (24 + 16 + 42, 99), (24 + 16 + 43, 2)]:
            changed = bytearray(data)
            changed[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                audit_openvpn_capture(bytes(changed), 1200, 'half')
        with self.assertRaises(ValueError):
            audit_openvpn_capture(self.standalone_pcap('full'), 1200, 'half')
        for size in (0, 23, 24, 35, len(data) - 1):
            with self.assertRaises(ValueError):
                audit_openvpn_capture(data[:size], 1200, 'half')
    def test_unimplemented_profile_mixtures_fail_before_namespace_work(self):
        tool = Path(__file__).with_name('native_smoke.py')
        for args in (['--traffic', 'active'],
                     ['--traffic', 'active', '--layers', 'tun', '--carrier', 'udp'],
                     ['--traffic', 'active', '--layers', 'tun', '--hot-switch'],
                     ['--record-profile', 'aligned'], ['--aligned-channels', '4'],
                     ['--record-profile', 'aligned', '--carrier', 'quic'],
                     ['--record-profile', 'aligned', '--carrier', 'quic', '--fec', 'cauchy', '--compression', 'lz4'],
                     ['--record-profile', 'aligned', '--carrier', 'quic', '--fec', 'cauchy', '--aligned-channels', '0'],
                     ['--record-profile', 'aligned', '--carrier', 'quic', '--fec', 'cauchy', '--aligned-channels', '257'],
                     ['--only-case', 'vxlan-full-clean'], ['--only-case', 'tap-half-netem'],
                     ['--fec', 'cauchy'], ['--fec-sources', '4'], ['--flow-churn'], ['--adaptive'],
                     ['--carrier', 'udp', '--fec', 'cauchy', '--fec-repairs', '0'],
                     ['--carrier', 'quic', '--path-mtu', '1200'],
                     ['--carrier', 'quic', '--udp-cover', 'quic-like'],
                     ['--carrier', 'quic', '--udp-protection', 'integrity'],
                     ['--carrier', 'quic', '--hot-switch'],
                     ['--active-policy-switch'],
                     ['--active-transfer-timeout', '180'],
                     ['--active-switch-timing', 'slow-netem'],
                     ['--active-progress'],
                     ['--active-policy-switch', '--traffic', 'active', '--layers', 'tun', '--active-progress'],
                     ['--active-policy-switch', '--traffic', 'active', '--layers', 'tun', '--active-switch-timing', 'slow-netem'],
                     ['--active-policy-switch', '--traffic', 'active', '--layers', 'tun', '--active-transfer-timeout', '181'],
                     ['--active-policy-switch', '--traffic', 'active', '--layers', 'tap'],
                     ['--active-policy-switch', '--traffic', 'active', '--layers', 'tun', '--carrier', 'udp'],
                     ['--active-policy-switch', '--traffic', 'active', '--layers', 'tun', '--hot-switch'],
                     ['--active-policy-switch', '--traffic', 'active', '--layers', 'tun', '--flow-churn'],
                     ['--carrier', 'udp', '--fec', 'cauchy', '--fec-flush-ms', '200']):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, str(tool), *args], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('error:', result.stderr)

    def test_base_datagram_profiles_select_delivery_without_changing_tcp_or_openvpn(self):
        from .native_smoke import DELIVERY_POLICY
        tool = Path(__file__).with_name('native_smoke.py')
        for carrier in ('udp', 'quic', 'tcp', 'openvpn-like'):
            with self.subTest(carrier=carrier):
                result = subprocess.run([sys.executable, str(tool), '--carrier', carrier,
                                         '--layers', 'tap', '--only-case', 'tap-full-clean'],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                value = json.loads(result.stdout)
                self.assertEqual(value['record_profile'], 'frame')
                self.assertEqual(value['cases'], [['tap', 'full', False]])
                self.assertEqual(value['delivery'],
                                 DELIVERY_POLICY if carrier in ('udp', 'quic') else None)

    def test_aligned_dry_run_selects_exact_case_and_complete_matrix(self):
        tool = Path(__file__).with_name('native_smoke.py')
        base = [sys.executable, str(tool), '--record-profile', 'aligned', '--carrier', 'quic', '--fec', 'cauchy']
        result = subprocess.run([*base, '--layers', 'tap', '--only-case', 'tap-full-clean'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['cases'], [['tap', 'full', False]])
        self.assertEqual(receipt['record_profile'], 'aligned')
        self.assertEqual(receipt['aligned_channels'], 4)
        self.assertEqual(receipt['fec'], [4, 2, 5])
        result = subprocess.run([*base, '--layers', 'tap', 'tun', 'vxlan', '--include-netem', '--aligned-channels', '256'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(len(receipt['cases']), 9)
        self.assertEqual(receipt['aligned_channels'], 256)

    def test_active_switch_dry_run_accepts_exact_native_profile(self):
        tool = Path(__file__).with_name('native_smoke.py')
        result = subprocess.run([sys.executable, str(tool), '--active-policy-switch', '--traffic', 'active', '--layers', 'tun', '--include-netem', '--adaptive'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['status'], 'dry_run')
        self.assertTrue(receipt['active_policy_switch'])
        self.assertEqual(len(receipt['cases']), 3)
        self.assertEqual(receipt['active_transfer_timeout'], 60)
        result = subprocess.run([sys.executable, str(tool), '--active-policy-switch', '--traffic', 'active', '--layers', 'tun', '--active-switch-timing', 'slow-netem', '--active-transfer-timeout', '180'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['active_transfer_timeout'], 180)
        self.assertEqual(receipt['active_transaction'], {'retry_ms': 250, 'phase_timeout_ms': 30000, 'reconcile_timeout_ms': 60000})

    def test_completion_deadline_is_absolute_and_never_automatically_extended(self):
        with patch('tools.native_smoke.time.monotonic', return_value=100):
            self.assertEqual(remaining(180, 70), 70)
            self.assertEqual(remaining(125, 70), 25)
            for deadline in (100, 99):
                with self.assertRaises(TimeoutError):
                    remaining(deadline, 70)

    def test_live_observation_snapshot_ignores_only_unfinished_trailing_record(self):
        self.assertEqual(observation_snapshot('Authenticated\n{"epoch":2}\n{"adaptive":'), [{'epoch': 2}])
        self.assertEqual(observation_snapshot('{"epoch":3}'), [])
        with self.assertRaises(json.JSONDecodeError):
            observation_snapshot('{"epoch":}\n')

    def test_progress_protocol_requires_bounded_advances_and_exact_final_digest(self):
        class Stream:
            def __init__(self, data):
                self.data = io.BytesIO(data)
            def settimeout(self, timeout):
                self.timeout = timeout
            def recv(self, count):
                return self.data.read(min(count, 2))
        self.assertEqual(MAXIMUM // PROGRESS_BYTES, 32)
        digest = bytes(range(32))
        total = PROGRESS_BYTES + 3
        with patch('tools.tcp_probe.time.monotonic', return_value=100):
            journal = io.StringIO()
            records = []
            save_progress(records, PROGRESS_BYTES, 99, journal)
            self.assertEqual(json.loads(journal.getvalue()), {'received_bytes': PROGRESS_BYTES, 'at_seconds': 1})
            self.assertEqual(records, [json.loads(journal.getvalue())])
            stream = Stream(b'P' + PROGRESS_BYTES.to_bytes(4, 'big') + b'P' + total.to_bytes(4, 'big') + b'F' + digest)
            first, done = progress_record(stream, total, 0, digest, 101)
            self.assertEqual((first, done), (PROGRESS_BYTES, False))
            second, done = progress_record(stream, total, first, digest, 101)
            self.assertEqual((second, done), (total, False))
            self.assertEqual(progress_record(stream, total, second, digest, 101), (total, True))
            for packet, previous in [(b'P' + PROGRESS_BYTES.to_bytes(4, 'big'), PROGRESS_BYTES),
                                     (b'P' + (total + 1).to_bytes(4, 'big'), PROGRESS_BYTES),
                                     (b'P' + (total - 1).to_bytes(4, 'big'), PROGRESS_BYTES),
                                     (b'F' + digest, 0), (b'F' + bytes(32), total), (b'X', 0)]:
                with self.subTest(packet=packet), self.assertRaises(ValueError):
                    progress_record(Stream(packet), total, previous, digest, 101)
            with self.assertRaises(TimeoutError):
                progress_record(Stream(b'P'), total, 0, digest, 100)
            with self.assertRaises(EOFError):
                progress_record(Stream(b'P\x00'), total, 0, digest, 101)

    def test_active_acceptance_requires_full_policy_live_gates_and_peer_digest(self):
        policy = active_policy(2, True)
        good = {'version': 1, 'ok': True, 'state': {'epoch': 2, 'phase': 'Idle', 'compression': 'off', 'active': {
            'policy': policy, 'running': True, 'admitting': True, 'digest': 'ab' * 32}}}
        self.assertTrue(verify_active_peers([good, good], 2, 'off', policy))
        for field, value in [('running', False), ('admitting', False), ('digest', 'g' * 64), ('digest', 'ab' * 31), ('policy', active_policy(2)), ('policy', active_policy(4))]:
            bad = copy.deepcopy(good)
            bad['state']['active'][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(verify_active_state(bad, 2, 'off', policy))
        for weights in ([1] * 63, [1] * 65, [True] * 64):
            bad = copy.deepcopy(good)
            bad['state']['active']['policy']['dscp_weights'] = weights
            self.assertFalse(verify_active_state(bad, 2, 'off', policy))
        bad = copy.deepcopy(good)
        bad['state']['active']['digest'] = 'cd' * 32
        self.assertFalse(verify_active_peers([good, bad], 2, 'off', policy))
        self.assertFalse(verify_active_peers([good], 2, 'off', policy))
        self.assertFalse(verify_active_peers([good, good], 3, 'off', policy))
        self.assertFalse(verify_active_peers([good, good], 2, 'lz4', policy))

    def test_negative_path_requires_exact_sent_and_received_counts(self):
        verify_blocked_ping('1 packets transmitted, 0 received, 100% packet loss')
        for text in ('1 packets transmitted, 1 received, 0% packet loss',
                     '2 packets transmitted, 0 received, 100% packet loss',
                     'ping: command not found'):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                verify_blocked_ping(text)

    def test_only_matching_committed_idle_state_is_accepted(self):
        good = {'ok': True, 'state': {'epoch': 2, 'compression': 'lz4', 'phase': 'Idle'}}
        self.assertTrue(verify_state(good, 2, 'lz4'))
        for bad in ({}, {'ok': True}, {'ok': True, 'state': None},
                    {'ok': False, 'state': good['state']},
                    {'ok': True, 'state': {**good['state'], 'epoch': 1}},
                    {'ok': True, 'state': {**good['state'], 'compression': 'off'}},
                    {'ok': True, 'state': {**good['state'], 'phase': 'Uncertain'}}):
            with self.subTest(response=bad):
                self.assertFalse(verify_state(bad, 2, 'lz4'))

    def test_exact_counts_and_zero_loss(self):
        verify_ping('3 packets transmitted, 3 received, 0% packet loss, time 400ms')

    def test_partial_loss_is_never_a_zero_percent_substring(self):
        for text in ('5 packets transmitted, 3 received, 40% packet loss',
                     '6 packets transmitted, 3 received, 50% packet loss',
                     '3 packets transmitted, 0 received, 100% packet loss',
                     '4 packets transmitted, 4 received, 0% packet loss',
                     '3 packets transmitted, 2 received, 0% packet loss',
                     '3 received, 0% packet loss'):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                verify_ping(text)


class PackedAcceptanceTests(unittest.TestCase):
    def dry(self, *extra):
        tool = Path(__file__).with_name('native_smoke.py')
        return subprocess.run([sys.executable, str(tool), *extra], capture_output=True, text=True)

    def test_packed_selection_is_explicit_and_legacy_defaults_stay_absent(self):
        base = ['--record-profile', 'packed', '--carrier', 'udp', '--fec', 'cauchy', '--udp-protection', 'integrity', '--path-mtu', '1200', '--layers', 'tun', '--only-case', 'tun-half-clean']
        result = self.dry(*base)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['packed'], {'channels': 4, 'hold_micros': 1000, 'max_units': 4, 'work_limit': 16})
        self.assertEqual(value['cases'], [['tun', 'half', False]])
        for extra in (['--packed-channels', '0'], ['--packed-channels', '256'], ['--packed-hold-micros', '1001'],
                      ['--packed-max-units', '0'], ['--packed-work-limit', '256'], ['--aligned-channels', '4'],
                      ['--carrier', 'tcp'], ['--carrier', 'openvpn-like'], ['--fec', 'none'], ['--compression', 'lz4'],
                      ['--traffic', 'active'], ['--hot-switch'], ['--apply']):
            with self.subTest(extra=extra): self.assertNotEqual(self.dry(*base, *extra).returncode, 0)
        for extra in (['--packed-channels', '4'], ['--packed-auditor', '/unused'], ['--build-receipt', '/unused']):
            self.assertNotEqual(self.dry(*extra).returncode, 0)
        for legacy in ([], ['--record-profile', 'aligned', '--carrier', 'udp', '--fec', 'cauchy']):
            old = self.dry(*legacy)
            self.assertEqual(old.returncode, 0, old.stderr)
            self.assertNotIn('packed', json.loads(old.stdout))

    def test_packed_peer_arguments_and_auditor_config_are_exact(self):
        from . import native_smoke as native
        settings = native.PACKED_DEFAULTS
        self.assertEqual(native.packed_options(settings), ['--record-profile', 'packed', '--packed-channels', '4', '--packed-hold-micros', '1000', '--packed-max-units', '4', '--packed-work-limit', '16'])
        value = native.packed_config('vxlan', 'half', 'udp', 1200, 'quic-like', 'integrity', (4, 2, 5), settings)
        self.assertEqual(value, {'version': 2, 'delivery': native.DELIVERY_POLICY, 'layer': 'tap', 'duplex': 'half', 'carrier': 'udp', 'path_mtu': 1200, 'max_packet': 1600, **settings, 'fec_sources': 4, 'fec_repairs': 2, 'fec_flush_ms': 5, 'cover': 'quic-like', 'protection': 'integrity'})
        quic = native.packed_config('tun', 'full', 'quic', 1228, 'unused', 'unused', (4, 2, 5), settings)
        self.assertIsNone(quic['cover']); self.assertIsNone(quic['protection'])

    @staticmethod
    def capture(payload=b'not magic: L2PK', ports=(24440, 24441), carrier='udp', duplex='half'):
        packets = []
        for port in ports:
            directions = (0 if port == 24440 else 1,) if carrier == 'udp' and duplex == 'half' else (0, 1)
            for direction in directions:
                source = bytes([192, 0, 2, 2 if direction == 0 else 6]); target = bytes([192, 0, 2, 6 if direction == 0 else 2])
                udp = struct.pack('!HHHH', port, port, 8 + len(payload), 0) + payload
                ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0) + source + target
                frame = b'\0' * 12 + b'\x08\x00' + ip + udp
                packets.append(struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame)
        return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b''.join(packets)

    def test_exact_capture_parser_preserves_whole_payload_without_magic_search(self):
        from .native_smoke import packed_capture_records
        payload = b'prefix L2PK inside user data'
        records, summary = packed_capture_records(self.capture(payload), 1200, 'half')
        expected = b''.join(struct.pack('!HBB', len(payload), direction, 0) + payload for direction in (0, 1))
        self.assertEqual(records, expected)
        self.assertEqual(summary['packets'], 2)
        self.assertEqual(summary['maximum_ip_bytes'], len(payload) + 28)
        for size in (0, 1, 23, 24, 39, len(self.capture()) - 1):
            with self.subTest(size=size), self.assertRaises(ValueError): packed_capture_records(self.capture()[:size], 1200, 'half')

    def test_capture_rejects_fragments_lengths_tuples_cap_and_missing_lanes(self):
        from . import native_smoke as native
        value = self.capture()
        # First frame starts at 40; IP at 54; UDP at 74.
        for offset, replacement in [(52, b'\x86\xdd'), (60, b'\x20\x00'), (56, b'\x04\xb1'),
                                    (63, b'\x06'), (66, b'\x7f\0\0\1'), (74, b'\0\1'), (78, b'\0\x08')]:
            changed = bytearray(value); changed[offset:offset + len(replacement)] = replacement
            with self.subTest(offset=offset), self.assertRaises(ValueError): native.packed_capture_records(bytes(changed), 1200, 'half')
        with self.assertRaises(ValueError): native.packed_capture_records(self.capture(ports=(24440,)), 1200, 'half')
        with patch.object(native, 'PACKED_CAPTURE_PACKETS', 2), self.assertRaisesRegex(ValueError, 'cap'):
            native.packed_capture_records(value, 1200, 'half')
        with patch.object(native, 'PACKED_CAPTURE_BYTES', 30), self.assertRaises(ValueError): native.packed_capture_records(value, 1200, 'half')

    def test_packed_snapshot_requires_source_and_auditor_hashes_before_any_namespace(self):
        from . import native_smoke as native
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'tools').mkdir(); output = root / 'out'; output.mkdir()
            for name in native.PACKED_HELPERS: (root / 'tools' / name).write_text(name)
            daemon, auditor = root / 'daemon', root / 'auditor'; daemon.write_bytes(b'daemon'); auditor.write_bytes(b'auditor')
            h = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            sources = {'tools/' + name: h(root / 'tools' / name) for name in native.PACKED_HELPERS}
            build = {'status': 'passed', 'exit_code': 0, 'source_stable_during_build': True, 'changed_during_build': [], 'source_sha256_before': sources, 'source_sha256_after': sources, 'binary_sha256': h(daemon), 'packed_auditor_sha256': h(auditor)}
            path = root / 'receipt.json'; path.write_text(json.dumps(build))
            with patch.object(native, 'ROOT', root):
                result = native.packed_snapshot(daemon, auditor, path, output)
                self.assertEqual(result['helper_sha256'], {name: sources['tools/' + name] for name in native.PACKED_HELPERS})
                auditor.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'auditor'): native.packed_snapshot(daemon, auditor, path, root / 'unused')
                auditor.write_bytes(b'auditor'); (root / 'tools/udp_burst_probe.py').write_text('changed')
                with self.assertRaisesRegex(ValueError, 'helper'): native.packed_snapshot(daemon, auditor, path, root / 'unused')

    def test_failed_apply_without_journal_reports_residual_and_never_adopts(self):
        from . import native_smoke as native
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); names = root / 'names'; names.mkdir(); state = root / 'state'; state.mkdir()
            out = root / 'out'; binary = root / 'binary'; binary.write_bytes(b'daemon')
            def snapshot(_binary, _auditor, _receipt, output):
                (output / 'l2tunneld-tested').write_bytes(b'daemon')
                return {}
            def apply(spec, _):
                (names / spec.namespaces['endpoint_a']).write_text('unaccounted namespace')
                raise TimeoutError('created name before failed ownership journal update')
            argv = ['native_smoke.py', '--apply', '--record-profile', 'packed', '--carrier', 'udp', '--fec', 'cauchy', '--layers', 'tun', '--only-case', 'tun-half-clean', '--lab-id', 'packed-residual', '--output', str(out), '--binary', str(binary), '--packed-auditor', str(root / 'auditor'), '--build-receipt', str(root / 'build'), '--state-dir', str(state)]
            with patch.object(sys, 'argv', argv), patch.object(native, 'validate_packed_entry'), patch.object(native.netns_lab, 'NETNS_DIRECTORY', names), patch.object(native.netns_lab, 'require_root'), patch.object(native, 'packed_snapshot', side_effect=snapshot), patch.object(native, 'invoke_packed_auditor', return_value={'status': 'passed'}), patch.object(native, 'command', return_value=''), patch.object(native.netns_lab, 'apply', side_effect=apply) as mutation, patch.object(native.netns_lab, 'cleanup') as cleanup, patch.object(native.packed_shared, 'bounded_lab', side_effect=lambda operation, spec, state, end: operation(spec, state)), patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(native.main(), 1)
            receipt = json.loads((out / 'receipt.json').read_text())
            self.assertEqual(receipt['cleanup'], 'failed')
            self.assertTrue(receipt['unaccounted_namespace_changes'])
            self.assertEqual(mutation.call_count, 1); cleanup.assert_not_called()
            self.assertEqual(len(list(names.iterdir())), 1)
            self.assertFalse(list(state.glob('*.json')))

    def test_burst_result_reap_is_shared_and_never_extends_packet_acceptance(self):
        from . import native_smoke as native
        from . import udp_burst_probe as burst
        start, end = 100, 100 + burst.OBSERVATION_NS
        record = {'version': 1, 'started_ns': start, 'observation_end_ns': end}; reap = end + burst.REAP_NS
        results = {}
        for direction in (0, 1):
            for kind in ('send', 'receive'):
                row = {'version': 1, 'status': 'passed', 'kind': kind, 'direction': direction, 'count': 64, 'bytes': 4096, 'sha256': burst.expected_hash(direction), 'started_ns': start, 'observation_end_ns': end}
                row.update({'completed_ns': start + 50} if kind == 'send' else {'last_packet_ns': start + 60, 'observed_until_ns': end + 1})
                results[f'{kind}-{direction}'] = row
        native.validate_burst_results(results, record, reap)
        for key, field, value in [('send-0', 'completed_ns', end), ('receive-0', 'observed_until_ns', end - 1), ('receive-1', 'observed_until_ns', reap), ('send-1', 'observation_end_ns', end + 1), ('receive-0', 'count', 65)]:
            changed = copy.deepcopy(results); changed[key][field] = value
            with self.subTest(key=key, field=field), self.assertRaises(ValueError): native.validate_burst_results(changed, record, reap)
        with self.assertRaises(ValueError): native.validate_burst_results(results, record, reap + 1)

    def test_auditor_subprocess_enforces_frozen_json_schemas(self):
        from . import native_smoke as native
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); auditor = root / 'auditor'; config = root / 'config.json'; config.write_text('{}')
            geometry = {key: 1 for key in ['underlay_ip_version', 'outer_overhead_bytes', 'udp_payload_ceiling', 'recovery_packet_ceiling', 'recovery_source_bytes', 'fec_source_bytes', 'fec_packet_ceiling', 'packed_header_bytes', 'record_id_bytes', 'symbol_bytes', 'channels', 'max_units', 'max_fragments_per_record', 'native_queue_packets', 'native_queue_bytes']}
            geometry['underlay_ip_version'] = 4
            valid = {'version': 1, 'status': 'passed', 'scope': 'configuration-only', 'geometry': geometry}
            rows = [{'direction': d, 'sources': 1, 'multi_unit_sources': 1, 'complete_packet_aggregation_sources': 1, 'max_units': 2, 'direct_copies': 1, 'systematic_copies': 0, 'repair_packets': 0, 'duplicate_sources': 0} for d in (0, 1)]
            audit = {'version': 1, 'status': 'passed', 'scope': 'structural-only', 'directions': rows}
            cases = [('validate', valid, True), ('audit', audit, True), ('audit', {**audit, 'scope': 'authenticated'}, False), ('validate', {**valid, 'extra': 1}, False), ('validate', {**valid, 'version': True}, False)]
            changed = copy.deepcopy(audit); changed['directions'][1]['complete_packet_aggregation_sources'] = 0; cases.append(('audit', changed, False))
            changed = copy.deepcopy(audit); changed['directions'].reverse(); cases.append(('audit', changed, False))
            for index, (operation, value, accepted) in enumerate(cases):
                auditor.write_text('#!' + sys.executable + '\nprint(' + repr(json.dumps(value)) + ')\n'); auditor.chmod(0o755)
                with self.subTest(index=index):
                    if accepted:
                        self.assertEqual(native.invoke_packed_auditor(auditor, operation, config, root / f'result-{index}'), value)
                    else:
                        with self.assertRaises(ValueError): native.invoke_packed_auditor(auditor, operation, config, root / f'result-{index}')

    def test_legacy_snapshot_does_not_import_new_packed_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('native_smoke.py', 'netns_lab.py'):
                (root / name).write_bytes(Path(__file__).with_name(name).read_bytes())
            for extra in ([], ['--record-profile', 'aligned', '--carrier', 'udp', '--fec', 'cauchy']):
                result = subprocess.run([sys.executable, str(root / 'native_smoke.py'), *extra], cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('packed', json.loads(result.stdout))
            self.assertFalse((root / 'udp_burst_probe.py').exists())

    def test_udp_half_is_unidirectional_per_lane_and_quic_half_is_bidirectional(self):
        from . import native_smoke as native
        udp, metadata = native.packed_capture_records(self.capture(), 1200, 'half', 'udp')
        self.assertTrue(udp)
        self.assertEqual(metadata['expected_lane_directions'], [[24440, 0], [24441, 1]])
        quic, metadata = native.packed_capture_records(self.capture(carrier='quic'), 1200, 'half', 'quic')
        self.assertEqual(metadata['expected_lane_directions'], [[24440, 0], [24440, 1], [24441, 0], [24441, 1]])
        self.assertEqual(len(quic), len(udp) * 2)
        with self.assertRaises(ValueError): native.packed_capture_records(self.capture(carrier='quic'), 1200, 'half', 'udp')
        with self.assertRaises(ValueError): native.packed_capture_records(self.capture(), 1200, 'half', 'quic')
        _, metadata = native.packed_capture_records(self.capture(ports=(24440,), duplex='full'), 1200, 'full', 'udp')
        self.assertEqual(metadata['expected_lane_directions'], [[24440, 0], [24440, 1]])

    def test_packed_apply_requires_actual_immutable_entry_tree(self):
        from . import native_smoke as native
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); (base / 'tools').mkdir()
            for name in native.PACKED_HELPERS: (base / 'tools' / name).write_text(name)
            binary, auditor, receipt = base / 'daemon', base / 'auditor', base / 'receipt.json'
            for path in (binary, auditor, receipt): path.write_text('fixture')
            with self.assertRaises(ValueError): native.validate_packed_entry(binary, auditor, receipt)
            with patch.object(native, 'ROOT', base), patch.object(native, '__file__', str(base / 'tools/native_smoke.py')):
                native.validate_packed_entry(binary, auditor, receipt)
                helper = base / 'tools/udp_burst_probe.py'; helper.unlink(); helper.symlink_to(binary)
                with self.assertRaisesRegex(ValueError, 'non-symlink'): native.validate_packed_entry(binary, auditor, receipt)

    def test_hash_rejection_after_output_creation_retains_bounded_failed_receipt(self):
        from . import native_smoke as native
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'output'
            argv = ['native_smoke.py', '--apply', '--record-profile', 'packed', '--carrier', 'udp', '--fec', 'cauchy', '--output', str(out), '--packed-auditor', '/fixture/auditor', '--build-receipt', '/fixture/receipt']
            with patch.object(sys, 'argv', argv), patch.object(native, 'validate_packed_entry'), patch.object(native.netns_lab, 'require_root'), patch.object(native, 'packed_snapshot', side_effect=ValueError('reviewed hash mismatch')), patch.object(native.netns_lab, 'apply') as apply, patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(native.main(), 1)
            value = json.loads((out / 'receipt.json').read_text())
            self.assertEqual((value['status'], value['preflight'], value['cleanup']), ('failed', 'failed', 'not_needed'))
            self.assertFalse(value['namespace_mutations_started']); apply.assert_not_called()


if __name__ == '__main__':
    unittest.main()
