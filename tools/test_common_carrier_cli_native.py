"""Pure/mocked Common native-runner boundaries; no real namespace or daemon."""
import contextlib
import copy
import errno
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from . import common_carrier_cli_native as h, common_carrier_cli_validation as v


def descriptor(tag):
    # Public-shape fixture only, deliberately not a Rust-valid record policy.
    # Actual functional input is supplied by the Rust canonical fixture exporter.
    return (b'L2RC\x02' + bytes([tag, 2, 0]) + (1500).to_bytes(8, 'big') + bytes(1256)).hex()


def anchored(tag, envelope=7):
    raw = bytes.fromhex(descriptor(tag))
    return (raw[:16] + bytes([envelope]) * 32 + raw[16:]).hex()


def document():
    return {'version': 1, 'backend': 'common_records_v2', 'initial_index': 0,
        'catalog': [descriptor(tag) for tag in range(1, 5)],
        'transaction': {'retained_bytes': 1_000_000}, 'runtime': {'report_interval_micros': 100_000},
        'rolling_work': {'field': 128, 'copies': 1024, 'metadata': 32},
        'outer_carrier': {'version': 1, 'backend': 'openvpn_wire_common', 'max_record_bytes': 1471}}


def case(layer='tun', cover='quic-like'):
    return h.plan('mock', cover, layer, document(), 'a' * 64)


def inspected():
    return {'requested_configuration': [1] * 32, 'requested_envelope': [2] * 32,
        'catalog': [3] * 32, 'configurations': [anchored(tag, 2) for tag in range(1, 5)],
        'outer_policy': {'path_mtu': 1500, 'max_record_bytes': 1471, 'digest': [4] * 32}}


def public():
    return {'member_public': [5] * 32, 'noise_public': {'a': [6] * 32, 'b': [8] * 32}}


def response(running=True):
    selected = anchored(1)
    status = {'carrier': 'openvpn-like', 'backend': 'common_records_v2', 'algorithm': 'common-records',
        'protection': 'chacha20-poly1305', 'running': running, 'coordinator': True,
        'configuration_change': True, 'cross_profile_switching': True, 'reconnect': True,
        'retained_state_recovery': False, 'fresh_rekey': False, 'resource_preallocation_complete': False,
        'member': public()['member_public'], 'initiator_noise': public()['noise_public']['a'],
        'responder_noise': public()['noise_public']['b'], 'local': h.g.WAN['a'] + ':24440',
        'peer': h.g.WAN['b'] + ':24440', 'catalog_members': 4, 'terminal': None,
        'service_terminal': None if running else 'Aborted', 'generation': 11, 'session': [9] * 16,
        'transcript': [10] * 32, 'outer': [11] * 32, 'configuration': [12] * 32, 'catalog': [13] * 32,
        'current': selected, 'initial': selected, 'epoch': 1, 'phase': 'idle', 'operation': None,
        'physical_scope': {'epoch': 1, 'configuration': v.digest(selected)},
        'rolling_work': document()['rolling_work'], 'native_storage_capacity_bytes': 1024,
        'workspace_capacity_bytes': 4096, 'loop_input_capacity_bytes': 4096,
        'wire': {}, 'native': {}, 'control': {}, 'security': {}, 'liveness': {},
        'storage': {'limit_bytes': 1_000_000, 'fixed_bytes': 1, 'external_bytes': 2,
            'engine_bytes': 3, 'building_bytes': 0, 'peak_bytes': 6}}
    status['original_carrier'] = {'requested': 'openvpn-like', 'effective': 'openvpn-like',
        'udp_cover': 'quic-like', 'requested_configuration': [1] * 32, 'requested_envelope': [2] * 32,
        'requested_catalog': [3] * 32, 'effective_configuration': status['configuration'],
        'effective_catalog': status['catalog'], 'effective_envelope': [7] * 32,
        'path_mtu': 1500, 'max_record_bytes': 1471, 'configuration': [4] * 32,
        'session': [14] * 16, 'binding': [15] * 32}
    return {'version': 4, 'ok': True, 'code': 'ok', 'state': {'epoch': 1,
        'phase': 'forwarding' if running else 'disconnected', 'compression': 'off', 'common': status}}


class SelectionAndPlan(unittest.TestCase):
    def test_explicit_early_dispatch_and_legacy_default_are_separate(self):
        with patch.object(h, 'main', return_value=71) as selected:
            argv = ['--backend', 'common-openvpn', '--common-plan', '/public/plan.json']
            self.assertEqual(h.g.main(argv), 71)
            selected.assert_called_once_with(argv)
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                patch.object(h.subprocess, 'Popen') as spawn, patch.object(h, 'main') as selected:
            self.assertEqual(h.g.main(['--cover', 'quic-like', '--layer', 'tun',
                '--binary', '/missing/binary', '--output', '/missing/fresh-output']), 0)
            self.assertEqual(json.loads(output.getvalue())['case']['backend'], 'generic_swift_v1')
            selected.assert_not_called()
            spawn.assert_not_called()

    def test_dry_run_snapshots_full64_input_without_output_or_binary_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public.json'
            value = document()
            # Keep64 distinct public-shape descriptors; no validity claim is made.
            value['catalog'] = [(bytes.fromhex(descriptor(1 + index % 4))[:-1]
                + bytes([index])).hex() for index in range(64)]
            raw = (json.dumps(value) + '\n').encode()
            path.write_bytes(raw)
            destination = Path(directory) / 'fresh'
            with contextlib.redirect_stdout(io.StringIO()) as output, \
                    patch.object(h.subprocess, 'Popen') as spawn, \
                    patch.object(h.bounded, 'verified_build_receipt') as build:
                self.assertEqual(h.main(['--backend', 'common-openvpn', '--cover', 'media-like',
                    '--layer', 'tap', '--common-plan', str(path), '--binary', '/missing/binary',
                    '--output', str(destination)]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result['case']['transaction_plan'], value)
            self.assertEqual(result['case']['common_plan_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertFalse(destination.exists())
            spawn.assert_not_called()
            build.assert_not_called()

    def test_plan_bounds_and_duplicate_catalog_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'plan.json'
            path.write_bytes(b'x' * (h.PLAN_LIMIT + 1))
            with self.assertRaisesRegex(ValueError, 'exceeds bound'):
                h.read_plan(path)
            value = document()
            value['catalog'].append(value['catalog'][0])
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'catalog'):
                h.read_plan(path)

    def test_disabled_or_inadequate_reporting_is_refused_before_lab_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'plan.json'
            value = document()
            for cadence in (None, 0, -1, True, '100000',
                            h.LIVENESS_OBSERVATION_SECONDS * 1_000_000,
                            h.LIVENESS_OBSERVATION_SECONDS * 1_000_000 + 1):
                value['runtime']['report_interval_micros'] = cadence
                path.write_text(json.dumps(value))
                with self.subTest(cadence=cadence), \
                        patch.object(h, 'launch_isolated') as launch, \
                        self.assertRaisesRegex(ValueError, 'report cadence'):
                    h.main(['--backend', 'common-openvpn', '--cover', 'quic-like', '--layer', 'tun',
                        '--common-plan', str(path), '--binary', '/missing/binary',
                        '--output', str(Path(directory) / 'fresh'), '--apply'])
                launch.assert_not_called()
            value['runtime']['report_interval_micros'] = 100_000
            path.write_text(json.dumps(value))
            self.assertEqual(h.read_plan(path)[1], value)

    def test_four_case_commands_select_actual_tls_noise_common_without_raw64_gate(self):
        for cover in ('quic-like', 'media-like'):
            for layer in ('tap', 'tun'):
                for side in ('a', 'b'):
                    for inspect in (False, True):
                        command = h.daemon_command(case(layer, cover), side, Path('/binary'),
                            Path('/run/private'), Path('/public-plan'), inspect)
                        self.assertIn('--common-transaction-plan', command)
                        self.assertEqual(command[command.index('--carrier') + 1], 'openvpn-like')
                        self.assertEqual(command[command.index('--udp-cover') + 1], cover)
                        self.assertEqual(command[command.index('--max-packet') + 1], '1600' if layer == 'tap' else '1500')
                        self.assertNotIn('--admission-key-file', command)
                        self.assertNotIn('--cookie-key-file', command)
                        self.assertEqual('--device' in command, not inspect)
                        self.assertEqual('--session-admission-key-file' in command, not inspect)
                        self.assertEqual('--ca' in command, side == 'a')
                        self.assertEqual('--cert' in command, side == 'b')


class ActualObservationBounds(unittest.TestCase):
    def test_receipt_above_log_bound_retains_full_bytes_and_worker_log_is_independently_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            value = {'status': 'passed', 'retained_status': 'x' * (h.BOUNDS['log_bytes'] + 1)}
            receipt = h.bounded.Receipt(path, value)
            self.assertGreater(path.stat().st_size, h.BOUNDS['log_bytes'])
            self.assertLess(path.stat().st_size, h.bounded.RECEIPT_LIMIT)
            self.assertEqual(json.loads(path.read_text()), value)
            self.assertEqual(receipt.value, value)
            log = Path(directory) / 'worker.log'
            log.write_bytes(b'x' * h.BOUNDS['log_bytes'])
            launch = Mock()
            self.assertEqual(h.observe_worker_log(log, launch), h.BOUNDS['log_bytes'])
            launch.update.assert_called_once_with(worker_log_bytes=h.BOUNDS['log_bytes'],
                worker_log_limit_bytes=h.BOUNDS['log_bytes'])
            with log.open('ab') as stream:
                stream.write(b'x')
            with self.assertRaises(h.native.BoundExhausted) as exhausted:
                h.observe_worker_log(log, launch)
            self.assertEqual(h.failure_status(exhausted.exception), 'bound_exhausted')
            self.assertEqual(launch.update.call_args.kwargs['worker_log_bytes'], h.BOUNDS['log_bytes'] + 1)
            self.assertEqual(h.BOUNDS['observations'], 256)

    def test_full64_six_phase_receipt_keeps_artifacts_within_original_file_cap(self):
        # Serialization geometry only: these public-shape values do not claim
        # authenticated protocol validity or substitute for Rust fixture exports.
        configurations = []
        for index in range(64):
            raw = bytes.fromhex(anchored(1 + index // 16))
            configurations.append((raw[:-1] + bytes([index])).hex())
        plan = document()
        plan['catalog'] = [(bytes.fromhex(value)[:16] + bytes.fromhex(value)[48:]).hex()
            for value in configurations]
        plan['runtime'] = h.g.transaction_plan('tap')['runtime']
        plan['transaction'] = h.g.transaction_plan('tap')['transaction']
        live = response()['state']['common']
        live.update(current=configurations[0], initial=configurations[0], catalog_members=64,
            elapsed_micros=1_000_000, send_rate=1_250_001, receive_rate=625_013,
            send_channels=2, receive_channels=2, rolling_scheduler_steps=128, rolling_work_used=[64, 1024, 32])
        for name in ('wire', 'native', 'control', 'security', 'liveness'):
            live[name] = {key: 1 for key in h.g.SUMMARIES[name]}
        stopped = copy.deepcopy(live)
        stopped.update(running=False, terminal='Io(BrokenPipe)',
            service_terminal='Failed(Failure { kind: BrokenPipe })')
        phases = ['initial', *(f'switch-{index}' for index in range(1, 5)), 'fresh-reconnected']
        udp = [{'bytes': size, 'pattern': kind, 'sha256': 'a' * 64, 'attempts': 1, 'answered': True}
            for size in (0, 1, 18, 64, 512, 1200, 1472) for kind in ('zero', 'tail')]
        icmp = [{'sequence': index, 'sent_ns': 1_000_000, 'received_ns': 2_000_000,
            'payload_prefix': 'b' * 32, 'payload_sha256': 'c' * 64, 'rtt_ns': 1_000_000} for index in (1, 2, 3)]
        probes = {side: {'icmp': {'status': 'passed', 'source': '198.18.0.1', 'address': '198.18.0.2',
            'identifier': 123, 'request_count': 3, 'payload_bytes': 1472, 'ip_bytes': 1500,
            'df': True, 'original_deadline_ns': 10_000_000, 'sent': 3, 'received_unique': 3, 'rows': icmp},
            'udp': {'status': 'passed', 'rows': udp}} for side in ('a', 'b')}
        captured_udp = [{'source': '198.18.0.1', 'address': '198.18.0.2', 'bytes': 1472,
            'sha256': 'd' * 64} for _ in range(len(phases) * 2 * len(udp) * 2)]
        captured_icmp = [{'source': '198.18.0.1', 'address': '198.18.0.2', 'type': 8,
            'identifier': 123, 'sequence': 1, 'payload_sha256': 'c' * 64} for _ in range(len(phases) * 2 * 3 * 2)]
        artifacts = {'plan': plan, 'effective_catalog': configurations,
            'capture_audits': {side: {'native_udp': captured_udp, 'native_icmp': captured_icmp}
                for side in ('native-a', 'native-b')},
            'phases': {name: {'status': 'passed', 'functional_receipt': name + '_functional'} for name in phases},
            'commands': [['ip', 'netns', 'exec', 'l2t-owned-endpoint', '/tmp/immutable-snapshot/l2tunnel-native',
                'switch-common-configuration' if index < 8 else 'status', '--control-socket',
                '/run/l2t-owned/control.sock', '--api-version', '4',
                *(('--configuration', configurations[index]) if index < 8 else ())] for index in range(256)]}
        artifacts.update({name + '_functional': probes for name in phases})
        raw = {**artifacts, 'ready': {side: {'status': live} for side in ('a', 'b')},
            'status_samples': [{'phase': str(index), 'peers': {'a': live, 'b': live}} for index in range(24)],
            'disconnect': {'replies': {'a': live, 'b': stopped}, 'status': {'a': live, 'b': stopped}},
            'final_disconnect': {'replies': {'a': live, 'b': stopped}, 'status': {'a': live, 'b': stopped}},
            'reconnect': {'replies': {'a': live, 'b': live}, 'status': {'a': live, 'b': live}}}
        compact = {**raw, 'ready': {side: {'status': h.public_summary(live)} for side in ('a', 'b')},
            'status_samples': [{'phase': str(index), 'peers': {side: h.public_summary(live)
                for side in ('a', 'b')}} for index in range(24)]}
        for name in ('disconnect', 'final_disconnect', 'reconnect'):
            compact[name] = {key: {side: h.public_summary(value) for side, value in entries.items()}
                for key, entries in raw[name].items()}
        self.assertGreater(len((json.dumps(raw, indent=2, sort_keys=True) + '\n').encode()), h.BOUNDS['log_bytes'])
        self.assertLess(len((json.dumps(compact, indent=2, sort_keys=True) + '\n').encode()), h.BOUNDS['log_bytes'])
        self.assertEqual(compact['plan']['catalog'], plan['catalog'])
        self.assertEqual(compact['effective_catalog'], configurations)
        self.assertEqual(compact['capture_audits'], artifacts['capture_audits'])
        self.assertEqual(compact['commands'], artifacts['commands'])
        self.assertTrue(all(compact[name + '_functional'] == probes for name in phases))
        summary = h.public_summary(stopped)
        self.assertEqual(summary['terminal'], 'Io(BrokenPipe)')
        self.assertEqual(summary['service_terminal'], 'Failed(Failure { kind: BrokenPipe })')
        self.assertEqual(summary['current']['data_digest'], bytes(v.digest(configurations[0])).hex())
        self.assertEqual(h.failure_status(OSError(errno.EFBIG, 'File too large')), 'bound_exhausted')
        self.assertEqual(h.failure_status(OSError(errno.ENOENT, 'Missing tool')), 'tool_failure')
        exhausted = json.dumps({'status': 'bound_exhausted', 'error': 'OSError: [Errno 27] File too large'})
        self.assertEqual(h.incomplete_worker_status(exhausted, 1), 'bound_exhausted')
        self.assertEqual(h.incomplete_worker_status(exhausted, 0), 'tool_failure')
        self.assertEqual(h.incomplete_worker_status('{"status":"passed","error":"bad"}', 1), 'tool_failure')

    def test_owner_identity_excludes_state_but_refuses_descriptor_or_device_replacement(self):
        observed = {'socket_inode': 201, 'udp': 'ESTAB users:(("daemon",pid=99,fd=7)) ino:201',
            'device': {'fd': 11, 'target': '/dev/net/tun',
                'info': 'pos:\t0\nflags:\t02004002\nmnt_id:\t41\nino:\t501\niff:\ttun0\n'}}
        identity = h.owner_identity(observed, 99, 'tun0')
        state_change = copy.deepcopy(observed)
        state_change['device']['info'] = state_change['device']['info'].replace('pos:\t0', 'pos:\t1600')
        self.assertEqual(h.owner_identity(state_change, 99, 'tun0'), identity)
        mutations = [lambda value: value.update(socket_inode=202),
            lambda value: value.update(udp=value['udp'].replace('fd=7', 'fd=8')),
            lambda value: value['device'].update(fd=12),
            lambda value: value['device'].update(info=value['device']['info'].replace('mnt_id:\t41', 'mnt_id:\t42')),
            lambda value: value['device'].update(info=value['device']['info'].replace('ino:\t501', 'ino:\t502'))]
        for mutate in mutations:
            changed = copy.deepcopy(observed)
            mutate(changed)
            self.assertNotEqual(h.owner_identity(changed, 99, 'tun0'), identity)
        malformed = [lambda value: value['device'].update(target='/dev/null'),
            lambda value: value.update(udp=value['udp'].replace('pid=99', 'pid=98')),
            lambda value: value['device'].update(info=value['device']['info'] + 'ino:\t501\n'),
            lambda value: value['device'].update(info=value['device']['info'].replace('iff:\ttun0', 'iff:\ttun00')),
            lambda value: value['device'].update(info=value['device']['info'].replace('ino:\t501\n', ''))]
        for mutate in malformed:
            changed = copy.deepcopy(observed)
            mutate(changed)
            with self.assertRaises(ValueError):
                h.owner_identity(changed, 99, 'tun0')
        owner = Mock()
        owner.case = case()
        daemons = {side: (Mock(pid=99), Path('/log')) for side in ('a', 'b')}
        observations, identities = {}, {}
        invalid = copy.deepcopy(observed)
        invalid['device']['info'] += 'ino:\t501\n'
        raw = {'a': invalid, 'b': observed}
        with patch.object(h.g, 'socket_observation', return_value=raw), self.assertRaises(ValueError):
            h.observe_owners(owner, daemons, 'failed-switch', observations, identities)
        self.assertEqual(observations['failed-switch'], raw)
        owner.receipt.update.assert_called_once_with(sockets=observations)
        self.assertEqual(identities, {})

    def test_status_requires_exact_phase_physical_digest_and_requested_effective_binding(self):
        valid = response()
        self.assertEqual(v.status(valid, case(), 'a', public(), inspected(), anchored(1), 1)['epoch'], 1)
        terminal = response(False)
        v.status(terminal, case(), 'a', public(), inspected(), anchored(1), 1, False)
        mutations = [lambda value: value.update(version=3),
            lambda value: value['state'].update(phase='connected'),
            lambda value: value['state']['common']['physical_scope'].update(configuration=[99] * 32),
            lambda value: value['state']['common']['original_carrier'].update(requested_catalog=[99] * 32),
            lambda value: value['state']['common']['original_carrier'].update(effective_envelope=[2] * 32)]
        for mutate in mutations:
            damaged = copy.deepcopy(valid)
            mutate(damaged)
            with self.assertRaises(ValueError):
                v.status(damaged, case(), 'a', public(), inspected(), anchored(1), 1)
        terminal['state']['phase'] = 'forwarding'
        with self.assertRaises(ValueError):
            v.status(terminal, case(), 'a', public(), inspected(), anchored(1), 1, False)
        failed = response(False)
        failed['state']['phase'] = 'failed'
        failed['state']['common'].update(terminal='Io(BrokenPipe)',
            service_terminal='Failed(Failure { kind: BrokenPipe })')
        exact = ('Io(BrokenPipe)', 'Failed(Failure { kind: BrokenPipe })', 'failed')
        with self.assertRaises(ValueError):
            v.status(failed, case(), 'a', public(), inspected(), anchored(1), 1, False)
        v.status(failed, case(), 'a', public(), inspected(), anchored(1), 1, False, stopped=exact)
        failed.update(ok=False, code='state')
        with self.assertRaises(ValueError):
            v.status(failed, case(), 'a', public(), inspected(), anchored(1), 1, False, stopped=exact)
        v.status(failed, case(), 'a', public(), inspected(), anchored(1), 1, False,
            stopped=exact, reply_outcome=(False, 'state'))

    def test_catalog_generation_identity_continuation_and_full_count(self):
        reply = response()
        status = reply['state']['common']
        status['catalog_page'] = {'offset': 0, 'total': 4, 'next': None,
            'configurations': [anchored(tag) for tag in range(1, 5)]}
        self.assertEqual(len(v.catalog_page(reply, 11, status['catalog'], 0, 4)), 4)
        for damaged in (lambda row: row.update(generation=12),
                        lambda row: row['catalog_page'].update(next=4),
                        lambda row: row['catalog_page']['configurations'].pop()):
            value = copy.deepcopy(reply)
            damaged(value['state']['common'])
            with self.assertRaises(ValueError):
                v.catalog_page(value, 11, status['catalog'], 0, 4)

    def test_literal_openvpn_control_and_opaque_layouts_and_refusals(self):
        self.assertEqual(v.outer_packet(b'\x30\x43payload'), ('data', b'\x43payload'))
        self.assertEqual(v.outer_packet(b'\x38abcdefgh\0\0\0\0\0')[0], 'reset_client')
        self.assertEqual(v.outer_packet(b'\x40abcdefgh\0\0\0\0\0')[0], 'reset_server')
        self.assertEqual(v.outer_packet(b'\x20abcdefgh\0\0\0\0\1\x16\x03\x03')[0], 'tls')
        self.assertEqual(v.outer_packet(b'\x28abcdefgh\1\0\0\0\1ijklmnop')[0], 'ack')
        for raw in (b'', b'\x30', b'\x31payload', b'\x48peerpayload',
                    b'\x28abcdefgh\0', b'\x38abcdefgh\1\0', b'\x20abcdefgh\0\0\0\0\1'):
            with self.assertRaises(ValueError):
                v.outer_packet(raw)

    def test_ipv6_suppression_observes_exact_owned_roles_and_rejects_unapplied_values(self):
        owner = Mock()
        owner.case = case()
        calls = []
        def command(role, *args):
            calls.append((role, args))
            if args[:2] == ('ip', '-j'):
                return json.dumps([{'ifname': 'lo'}, {'ifname': 'tun0' if role.startswith('endpoint_') else 'eth0'}])
            keys = args[2:] if args[1] == '-w' else args[1:]
            return '\n'.join(key.split('=')[0] + ' = 1' for key in keys)
        owner.command.side_effect = command
        rows = h.disable_native_ipv6(owner)
        self.assertEqual(set(rows), {'endpoint_a', 'endpoint_b', 'host_a', 'host_b'})
        self.assertEqual(len(calls), 16)
        self.assertTrue(all(role in rows for role, _ in calls))
        self.assertTrue(all(row == 1 for observed in rows.values() for row in observed['after'].values()))
        self.assertEqual(h.g.capture_command(case(), 'wan-a', Path('/capture'))[-1], 'ip or ip6 or arp')
        def refused(role, *args):
            raw = command(role, *args)
            return raw.replace(' = 1', ' = 0') if args[:2] == ('sysctl', '-w') else raw
        owner.command.side_effect = refused
        with self.assertRaisesRegex(ValueError, 'write refused'):
            h.disable_native_ipv6(owner)

    def test_original_phase_deadline_and_single_cleanup_cap_are_retained(self):
        receipt = Mock()
        owner = h.Owner(case(), Path('/output'), receipt, 100)
        with patch.object(h.g.time, 'monotonic', return_value=10):
            self.assertEqual(owner.phase(35, 20), 20)
            cleanup = owner.begin_cleanup()
        with patch.object(h.g.time, 'monotonic', return_value=25):
            self.assertEqual(owner.begin_cleanup(), cleanup)
            with self.assertRaises(TimeoutError):
                owner.check(20)


if __name__ == '__main__':
    unittest.main()
