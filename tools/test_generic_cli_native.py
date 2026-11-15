"""Pure/mocked native-harness boundaries; these tests never create a real lab."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import signal
import socket
import struct
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from . import generic_cli_native as h


def public():
    return {'member_public': [7] * 32, 'noise_public': {'a': [8] * 32, 'b': [9] * 32}}


def inspection(case, side='a'):
    # Logical output fixtures only; no fabricated protocol/authentication evidence.
    values = ['4c32544301010100' + byte * 296 for byte in ('01', '02')]
    return {'event': 'secure_udp_transaction_plan', 'schema': 1, 'backend': case['backend'],
        'carrier': case['cover'], 'algorithm': 'swift', 'protection': 'chacha20-poly1305',
        'role': 'initiator' if side == 'a' else 'responder', 'requested': True, 'validated': True,
        'authenticated': False, 'resource_preallocation_complete': False,
        'configuration': [3] * 32, 'envelope': [4] * 32, 'catalog': [5] * 32,
        'data_digest': h.configuration_digest(values[0]),
        'initial': values[0], 'catalog_members': 2, 'configurations': values,
        'parameters': copy.deepcopy(case['transaction_plan']['transaction']),
        'report_interval': {'seconds': 0, 'nanoseconds': 100_000_000},
        'member': public()['member_public'], 'initiator_noise': public()['noise_public']['a'],
        'responder_noise': public()['noise_public']['b'], 'local': h.WAN[side] + ':24440',
        'peer': h.WAN['b' if side == 'a' else 'a'] + ':24440'}


def status(case, side='a', target=False, running=True):
    inspected = inspection(case)
    value = {name: None for name in h.STATUS_FIELDS}
    descriptor = case['transaction_plan']['catalog'][int(target)]
    selected = inspected['configurations'][int(target)]
    epoch = 2 if target else 1
    value.update(generation=1, carrier=case['cover'], algorithm='swift', protection='chacha20-poly1305',
        backend=case['backend'], running=running, elapsed_micros=12345, session=[1] * 16,
        transcript=[2] * 32, outer=[4] * 32, member=public()['member_public'],
        initiator_noise=public()['noise_public']['a'], responder_noise=public()['noise_public']['b'],
        local=h.WAN[side] + ':24440', peer=h.WAN['b' if side == 'a' else 'a'] + ':24440',
        configuration=inspected['configuration'], catalog=inspected['catalog'], catalog_members=2,
        initial=inspected['initial'], current=selected, epoch=epoch, phase='idle',
        physical_scope={'epoch': epoch, 'configuration': h.configuration_digest(selected)},
        send=copy.deepcopy(descriptor['forward' if side == 'a' else 'reverse']),
        receive=copy.deepcopy(descriptor['reverse' if side == 'a' else 'forward']),
        storage={'limit_bytes': 64 * 1024 * 1024}, resource_preallocation_complete=False,
        native_storage_capacity_bytes=96000, workspace_capacity_bytes=70000, loop_input_capacity_bytes=8000,
        configuration_change=True, coordinator=side == 'a', reconnect=True, cross_profile_switching=False,
        retained_state_recovery=False, fresh_rekey=False, service_terminal=None if running else 'Aborted')
    for name, keys in h.SUMMARIES.items():
        value[name] = {key: None if name in ('security', 'liveness') else 0 for key in keys}
    value['storage']['limit_bytes'] = 64 * 1024 * 1024
    value['swift_unconfirmed'] = 0
    return {'version': 3, 'ok': True, 'code': 'ok', 'state': {'epoch': epoch,
        'phase': 'forwarding' if running else 'disconnected', 'compression': 'off', 'transaction': value}}


def ip_packet(source, destination, protocol, body, fragment=0):
    raw = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1, fragment,
        64, protocol, 0, socket.inet_aton(source), socket.inet_aton(destination)))
    raw[10:12] = h.bounded.checksum(raw).to_bytes(2, 'big')
    return bytes(raw) + body


def udp_packet(source, destination, data, source_port=24440, destination_port=24440):
    return ip_packet(source, destination, 17,
        struct.pack('!HHHH', source_port, destination_port, len(data) + 8, 0) + data)


def link_frame(ip, link):
    return {1: bytes(12) + b'\x08\x00', 101: b'', 113: bytes(14) + b'\x08\x00',
            276: b'\x08\x00' + bytes(18)}[link] + ip


def pcap(frames, link=1, snaplen=2048, fraction=0):
    result = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, link))
    for raw in frames:
        result += struct.pack('<IIII', 1, fraction, len(raw), len(raw)) + raw
    return bytes(result)


def cover_body(cover, epoch=1, handshake=False):
    if handshake:
        payload = bytearray(145)
        payload[:5] = bytes([128, 56, 1, 1, 0])
        payload[9:25] = bytes([1]) * 16
        payload = bytes(payload)
    else:
        payload = b'\x01' + epoch.to_bytes(8, 'big') + b'\x01\x01' + bytes(24)
    if cover == 'quic-like':
        if handshake:
            length = (len(payload) + 4 | 0x4000).to_bytes(2, 'big')
            return b'\xc3\0\0\0\1\x08' + b'p' * 8 + b'\x08' + b'l' * 8 + b'\0' + length + bytes(4) + payload
        return b'\x43' + b'p' * 8 + bytes(4) + payload
    return bytes([0x80, 0xe0 if handshake else 96]) + bytes(10) + len(payload).to_bytes(2, 'big') + payload


class PlansAndStatus(unittest.TestCase):
    def test_dry_run_never_reads_binary_receipt_or_spawns_and_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'uncreated'
            with contextlib.redirect_stdout(io.StringIO()) as stream, \
                    patch.object(h.subprocess, 'Popen') as spawn, \
                    patch.object(h.bounded, 'verified_build_receipt') as verify:
                result = h.main(['--cover', 'quic-like', '--layer', 'tap', '--binary', '/absent/binary',
                    '--build-receipt', '/absent/receipt', '--output', str(output)])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(stream.getvalue())['status'], 'dry_run')
            self.assertFalse(output.exists())
            spawn.assert_not_called()
            verify.assert_not_called()

    def test_four_explicit_cases_keep_exact_catalog_and_exclude_legacy_authorities(self):
        for cover in ('quic-like', 'media-like'):
            for layer in ('tap', 'tun'):
                case = h.plan('unit', cover, layer)
                document = case['transaction_plan']
                self.assertEqual(document['initial_index'], 0)
                self.assertEqual([v['path_mtu'] for v in document['catalog']], [1500, 1400])
                self.assertEqual([(v['forward']['channels'], v['reverse']['channels'])
                    for v in document['catalog']], [(2, 3), (4, 1)])
                self.assertEqual(document['catalog'][0]['forward']['bytes_per_second'], 1250001)
                self.assertEqual(document['catalog'][0]['reverse']['repair_denominator'], 7)
                self.assertEqual(document['runtime']['lifetime']['lease_micros'], 300000000)
                self.assertLess(len(json.dumps(document).encode()), 256 * 1024)
                for side in ('a', 'b'):
                    argv = h.daemon_command(case, side, Path('/binary'), Path('/private'), Path('/plan'))
                    self.assertEqual(argv[1], 'connect' if side == 'a' else 'serve')
                    self.assertIn('--swift-transaction-plan', argv)
                    self.assertIn('--session-admission-key-file', argv)
                    self.assertEqual(argv[argv.index('--device') + 1], case['device'])
                    for flag in ('--path-mtu', '--swift-forward-kbit', '--swift-reverse-kbit', '--swift-channels',
                                 '--swift-window', '--swift-repair-permille', '--swift-report-ms'):
                        self.assertNotIn(flag, argv)
                    inspected = h.daemon_command(case, side, Path('/binary'), Path('/private'), Path('/plan'), True)
                    self.assertEqual(inspected[1], 'inspect-swift-transaction-plan')
                    for flag in ('--device', '--control-socket', '--session-admission-key-file', '--session-cookie-key-file'):
                        self.assertNotIn(flag, inspected)
                if layer == 'tun':
                    self.assertEqual(case['applications']['a']['role'], 'endpoint_a')
                    self.assertEqual(case['applications']['a']['address'], '198.19.0.1')
                self.assertFalse(case['performance_qualified'])

    def test_ambiguous_modes_and_mutated_cases_fail_before_launch(self):
        for cover, layer in [('quic', 'tap'), ('quic-like', 'other'), ('swift', 'tun')]:
            with self.assertRaises(ValueError):
                h.plan('unit', cover, layer)
        case = h.plan('unit', 'quic-like', 'tap')
        case['transaction_plan']['catalog'].pop()
        with self.assertRaises(ValueError):
            h.daemon_command(case, 'a', Path('/binary'), Path('/private'), Path('/plan'))

    def test_full_inspection_and_actual_complete_status_are_strict_on_both_roles_layers(self):
        for cover in ('quic-like', 'media-like'):
            for layer in ('tap', 'tun'):
                case = h.plan('unit', cover, layer)
                for side in ('a', 'b'):
                    h.validate_inspection(inspection(case, side), case, side, public())
                    for target in (False, True):
                        for running in (False, True):
                            reply = status(case, side, target, running)
                            selected = inspection(case)['configurations'][int(target)]
                            h.validate_status(reply, case, side, public(), inspection(case), selected,
                                2 if target else 1, running)

    def test_inspection_cannot_claim_authentication_prune_or_rename_identity(self):
        case = h.plan('unit', 'quic-like', 'tap')
        for key, value in [('authenticated', True), ('validated', 1), ('configuration', [0] * 32),
                           ('catalog_members', 1), ('configurations', inspection(case)['configurations'][:1]),
                           ('role', 'responder'), ('unknown', True)]:
            changed = inspection(case)
            changed[key] = value
            with self.assertRaises(ValueError, msg=key):
                h.validate_inspection(changed, case, 'a', public())

    def test_status_rejects_legacy_approximation_stale_scope_capability_and_terminal_claims(self):
        case = h.plan('unit', 'media-like', 'tun')
        selected = inspection(case)['configurations'][1]
        for key, value in [('generation', True), ('running', False), ('coordinator', False),
            ('cross_profile_switching', True), ('resource_preallocation_complete', True),
            ('current', inspection(case)['initial']), ('epoch', 1), ('terminal', 'PolicyTimeout'),
            ('physical_scope', {'epoch': 2, 'configuration': inspection(case)['data_digest']}),
            ('send', {**case['transaction_plan']['catalog'][1]['forward'], 'bytes_per_second': 1375000})]:
            changed = status(case, target=True)
            changed['state']['transaction'][key] = value
            with self.assertRaises(ValueError, msg=key):
                h.validate_status(changed, case, 'a', public(), inspection(case), selected, 2)
        changed = status(case)
        changed['state']['secure_udp'] = {}
        with self.assertRaises(ValueError):
            h.validate_status(changed, case, 'a', public(), inspection(case), inspection(case)['initial'], 1)

    def test_physical_digest_matches_existing_literal_rust_vector_and_exact_target(self):
        # swift_configuration/tests.rs::independent_complete_wire_and_digest_vectors_are_exact.
        raw = b'L2TC\x01\x01\x01\x00' + bytes([0xa5]) * 32
        for number in (1500, 3, 1, 1500, 2000001, 1424, 7, 1, 3, 9, 65537, 1501, 123,
                5001, 10001, 20001, 900001, 2, 1, 1500, 1000002, 1200, 5, 2, 7, 11,
                32769, 1501, 17, 3007, 11003, 30001, 700003):
            raw += number.to_bytes(8, 'big')
        self.assertEqual(h.CONFIGURATION_DIGEST_DOMAIN, b'l2tunnel/swift-transaction-config/v1\0')
        self.assertEqual(bytes(h.configuration_digest(raw.hex())).hex(),
            'd650a7171ac7e34589355f4138c4e33423bb87623660357be0649eb663767e1b')
        case = h.plan('unit', 'quic-like', 'tun')
        changed = status(case, target=True)
        changed['state']['transaction']['physical_scope']['configuration'] = [10] * 32
        with self.assertRaises(ValueError):
            h.validate_status(changed, case, 'a', public(), inspection(case), inspection(case)['configurations'][1], 2)
        changed = inspection(case)
        changed['data_digest'] = [6] * 32
        with self.assertRaises(ValueError):
            h.validate_inspection(changed, case, 'a', public())

    def test_outer_service_phase_must_match_actual_running_and_aborted_lifecycle(self):
        case = h.plan('unit', 'media-like', 'tap')
        for running in (False, True):
            for phase in ('idle', 'connecting', 'forwarding' if not running else 'disconnected',
                          None, 0, True, [], {}):
                changed = status(case, running=running)
                changed['state']['phase'] = phase
                with self.assertRaises(ValueError, msg=repr((running, phase))):
                    h.validate_status(changed, case, 'a', public(), inspection(case), inspection(case)['initial'], 1, running)

    def test_udp_receipt_requires_all_exact_zero_nonzero_and_trailing_zero_patterns(self):
        rows = []
        for length in (0, 1, 18, 64, 512, 1200, 1472):
            for kind in ('zero', 'tail'):
                data = bytes(length) if kind == 'zero' else hashlib.shake_256(f'udp/{length}'.encode()).digest(length)
                if kind == 'tail' and length >= 4:
                    data = data[:-4] + bytes(4)
                rows.append({'bytes': length, 'pattern': kind, 'sha256': hashlib.sha256(data).hexdigest(),
                    'attempts': 1, 'answered': True})
        value = {'status': 'passed', 'rows': rows}
        self.assertEqual(h.validate_udp_probe(value), value)
        for mutate in (lambda row: row.update(sha256='00' * 32), lambda row: row.update(attempts=9),
                       lambda row: row.update(answered=1), lambda row: row.update(pattern='tail-less')):
            changed = copy.deepcopy(value)
            mutate(changed['rows'][-1])
            with self.assertRaises(ValueError):
                h.validate_udp_probe(changed)
        with self.assertRaises(ValueError):
            h.validate_udp_probe({'status': 'passed', 'rows': rows[:-1]})


class CapturesAndOwnership(unittest.TestCase):
    def write_capture(self, directory, frames, **kwargs):
        path = Path(directory) / 'capture.pcap'
        path.write_bytes(pcap(frames, **kwargs))
        return path

    def test_complete_native_udp_and_icmp_support_checked_link_layouts(self):
        case = h.plan('unit', 'quic-like', 'tun')
        first, second = (case['applications'][side]['address'] for side in ('a', 'b'))
        payload = bytes(range(256)) * 5 + bytes(192)
        packets = [udp_packet(first, second, b'\x00abc\x00\x00', 30001, 24461),
            h.probe.icmp_request(first, second, 123, 1, payload)]
        for link in (1, 101, 113, 276):
            with tempfile.TemporaryDirectory() as directory:
                path = self.write_capture(directory, [link_frame(value, link) for value in packets], link=link)
                audit = h.audit_capture(path, case, 'native-a', {1: 1500, 2: 1400, 3: 1500})
                self.assertEqual(audit['packets'], 2)
                self.assertEqual(audit['native_udp'][0]['bytes'], 6)
                self.assertEqual(audit['native_udp'][0]['sha256'], hashlib.sha256(b'\x00abc\x00\x00').hexdigest())
                self.assertEqual(audit['native_icmp'][0]['payload_sha256'], hashlib.sha256(payload).hexdigest())

    def test_outer_shape_and_all_negotiated_epochs_are_observed_for_both_covers(self):
        for cover in ('quic-like', 'media-like'):
            case = h.plan('unit', cover, 'tap')
            frames = [link_frame(udp_packet(h.WAN['a'], h.WAN['b'], cover_body(cover, handshake=True)), 1)]
            frames += [link_frame(udp_packet(h.WAN['a'], h.WAN['b'], cover_body(cover, epoch)), 1) for epoch in (1, 2, 3)]
            with tempfile.TemporaryDirectory() as directory:
                path = self.write_capture(directory, frames)
                audit = h.audit_capture(path, case, 'wan-a', {1: 1500, 2: 1400, 3: 1500})
                self.assertEqual(audit['handshake'], 1)
                self.assertEqual(audit['user_epochs'], {'1': 1, '2': 1, '3': 1})
                with self.assertRaises(ValueError):
                    h.audit_capture(path, case, 'wan-a', {1: 1500, 2: 40, 3: 1500})

    def test_capture_truncation_format_fraction_and_packet_bound_are_not_passes(self):
        packet = link_frame(udp_packet('198.19.0.1', '198.19.0.2', b'x', 30001, 24461), 1)
        for kwargs in ({'snaplen': 160}, {'link': 999}, {'fraction': 1000000}):
            with tempfile.TemporaryDirectory() as directory:
                path = self.write_capture(directory, [packet], **kwargs)
                with self.assertRaises(ValueError):
                    list(h.pcap_frames(path))
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_capture(directory, [packet])
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(ValueError):
                list(h.pcap_frames(path))
            path.write_bytes(pcap([packet, packet]))
            with patch.dict(h.BOUNDS, capture_packets=2), self.assertRaises(h.native.BoundExhausted):
                list(h.pcap_frames(path))

    def test_wan_other_tuple_tcp_and_native_checksum_errors_fail(self):
        case = h.plan('unit', 'quic-like', 'tun')
        wrong = [udp_packet(h.WAN['a'], h.WAN['b'], b'x', destination_port=24441),
                 ip_packet(h.WAN['a'], h.WAN['b'], 6, bytes(20))]
        for packet in wrong:
            with tempfile.TemporaryDirectory() as directory:
                path = self.write_capture(directory, [link_frame(packet, 1)])
                with self.assertRaises(ValueError):
                    h.audit_capture(path, case, 'wan-a', {1: 1500})
        with tempfile.TemporaryDirectory() as directory:
            broken = bytearray(udp_packet('198.19.0.1', '198.19.0.2', b'x', 30001, 24461))
            broken[10] ^= 1
            path = self.write_capture(directory, [link_frame(bytes(broken), 101)], link=101)
            with self.assertRaises(ValueError):
                h.audit_capture(path, case, 'native-a', {1: 1500})

    def test_native_ipv6_control_uses_exact_owned_roles_and_observed_interfaces(self):
        for layer in ('tap', 'tun'):
            case = h.plan('unit', 'media-like', layer)
            owner = Mock(case=case)
            written = set()
            def command(role, *argv):
                if argv == ('ip', '-j', 'link', 'show'):
                    names = ['lo', 'eth0'] if role.startswith('host_') else ['lo', 'wan0', 'br-lan', 'lan0', case['device']]
                    return json.dumps([{'ifname': name} for name in names])
                self.assertEqual(argv[0], 'sysctl')
                if argv[1] == '-w':
                    written.add(role)
                    return '\n'.join(item.replace('=', ' = ') for item in argv[2:]) + '\n'
                return '\n'.join(key + ' = ' + ('1' if role in written else '0') for key in argv[1:]) + '\n'
            owner.command.side_effect = command
            observed = h.disable_native_ipv6(owner)
            roles = ('endpoint_a', 'endpoint_b', 'host_a', 'host_b')
            self.assertEqual(list(observed), list(roles))
            self.assertEqual(owner.command.call_count, 16)
            for index, role in enumerate(roles):
                calls = owner.command.call_args_list[index * 4:(index + 1) * 4]
                self.assertTrue(all(call.args[0] == role for call in calls))
                self.assertEqual(calls[1].args, calls[3].args)
                self.assertEqual(calls[2].args, (role, 'sysctl', '-w',
                    'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1'))
                self.assertEqual(set(observed[role]['before'].values()), {0})
                self.assertEqual(set(observed[role]['after'].values()), {1})
                for name in observed[role]['interfaces']:
                    self.assertIn('net.ipv6.conf.' + name + '.disable_ipv6', observed[role]['after'])
            self.assertIn(case['device'], observed['endpoint_a']['interfaces'])

    def test_native_ipv6_malformed_or_unapplied_values_cannot_pass(self):
        key = 'net.ipv6.conf.lo.disable_ipv6'
        for raw in ('', key + ' = 2', key + ' = true', key + ' = 1\n' + key + ' = 1',
                    key + ' = 1\nnet.ipv6.conf.unknown.disable_ipv6 = 1'):
            with self.assertRaises(ValueError):
                h.sysctl_values(raw, [key])
        case = h.plan('unit', 'quic-like', 'tun')
        owner = Mock(case=case)
        def command(role, *argv):
            if argv[0] == 'ip':
                return '[{"ifname":"lo"},{"ifname":"tun0"}]'
            keys = [item.split('=')[0] for item in argv[2:]] if argv[1] == '-w' else argv[1:]
            return '\n'.join(item + ' = ' + ('1' if argv[1] == '-w' else '0') for item in keys)
        owner.command.side_effect = command
        with self.assertRaisesRegex(ValueError, 'remains active'):
            h.disable_native_ipv6(owner)
        self.assertEqual(owner.command.call_count, 4)
        owner.reset_mock()
        owner.case = copy.deepcopy(case)
        owner.case['namespaces']['endpoint_a'] = 'unowned'
        with self.assertRaises(ValueError):
            h.disable_native_ipv6(owner)
        owner.command.assert_not_called()

    def test_ipv6_capture_filter_is_retained_and_unexpected_ipv6_fails(self):
        case = h.plan('unit', 'quic-like', 'tap')
        for surface in ('wan-a', 'wan-b', 'native-a', 'native-b'):
            self.assertEqual(h.capture_command(case, surface, Path('/unused/capture'))[-1], 'ip or ip6 or arp')
            with tempfile.TemporaryDirectory() as directory:
                path = self.write_capture(directory, [bytes(12) + b'\x86\xdd' + bytes(40)])
                with self.assertRaises(ValueError):
                    h.audit_capture(path, case, surface, {1: 1500})

    def test_private_credentials_directory_uses_private_run_mount(self):
        with patch.object(h.tempfile, 'TemporaryDirectory') as temporary:
            self.assertIs(h.private_directory(), temporary.return_value)
        temporary.assert_called_once_with(prefix='l2t-gcn-', dir='/run')

    def test_owner_refuses_unowned_namespaces_and_observation_overflow_before_spawn(self):
        case = h.plan('unit', 'quic-like', 'tap')
        owner = h.Owner(case, Path('/unused'), Mock(), time.monotonic() + 10)
        with patch.object(h.bounded, 'launch') as launch:
            with self.assertRaises(ValueError):
                owner.launch('host', ['ip', 'link', 'delete', 'eth0'], 'bad')
            owner.commands = [[]] * h.BOUNDS['observations']
            with self.assertRaises(h.native.BoundExhausted):
                owner.launch('endpoint_a', ['true'], 'over')
            launch.assert_not_called()

    def test_worker_identity_failure_occurs_before_mount_or_namespace_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(h.bounded, 'command') as command, patch.object(h.lab, 'apply') as apply:
                with self.assertRaises(ValueError):
                    h.worker(h.plan('unit', 'quic-like', 'tap'), Path(directory), {}, {}, 'wrong-token')
                command.assert_not_called()
                apply.assert_not_called()

    def test_helper_snapshot_mismatch_is_refused_before_worker_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hashes = {}
            for name in h.HELPERS:
                (root / name).write_bytes(b'immutable helper')
                hashes['tools/' + name] = h.bounded.file_hash(root / name)
            build = {'source_sha256_after': hashes}
            self.assertEqual(h.verify_helpers(build, root), hashes)
            (root / 'generic_cli_native.py').write_bytes(b'changed after snapshot')
            with self.assertRaises(ValueError):
                h.verify_helpers(build, root)

    def test_cleanup_uses_journal_owner_and_rejects_retained_or_broken_handles(self):
        spec = h.lab.LabSpec('unit')
        with tempfile.TemporaryDirectory() as directory:
            state, handles = Path(directory) / 'state', Path(directory) / 'netns'
            state.mkdir()
            handles.mkdir()
            journal = state / 'unit.json'
            journal.write_text('{}')
            until = time.monotonic() + 1
            def cleaned(operation, actual_spec, actual_state, actual_deadline):
                self.assertIs(operation, h.lab.cleanup)
                self.assertEqual((actual_spec, actual_state, actual_deadline), (spec, state, until))
                journal.unlink()
            with patch.object(h.lab, 'NETNS_DIRECTORY', handles), \
                    patch.object(h.bounded, 'bounded_lab', side_effect=cleaned) as clean:
                h.cleanup_topology(spec, state, until)
                clean.assert_called_once()
                retained = handles / spec.namespaces['endpoint_a']
                retained.symlink_to(handles / 'absent')
                with self.assertRaises(ValueError):
                    h.cleanup_topology(spec, state, until)

    def test_stop_kills_only_the_recorded_child_after_original_wait_expires(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [h.subprocess.TimeoutExpired(['owned'], .1), 0]
        h.stop_child(child, time.monotonic() + 1, interrupt=True)
        child.send_signal.assert_called_once_with(signal.SIGINT)
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_count, 2)

    def test_capture_drain_failure_never_synthesizes_known_fingerprints(self):
        child = Mock()
        child.poll.return_value = 1
        captures = {name: (child, Path('/unused/log'), Path('/unused/capture'))
                    for name in ('native-a', 'native-b')}
        with patch.object(h, 'audit_capture', side_effect=ValueError('partial capture')), \
                patch.object(h.time, 'sleep') as sleep, self.assertRaises(ValueError):
            h.drain_native_captures(captures, h.plan('unit', 'quic-like', 'tun'), {}, time.monotonic() + 1)
        sleep.assert_not_called()

    def test_bad_build_preserves_failure_receipts_without_launch_and_never_adopts_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'fresh'
            with patch.object(h.subprocess, 'Popen') as spawn:
                result = h.launch_isolated(h.plan('unit', 'quic-like', 'tap'), output,
                    Path('/absent/binary'), Path('/absent/build'))
            self.assertEqual(result, 1)
            self.assertEqual(json.loads((output / 'receipt.json').read_text())['status'], 'failed')
            self.assertEqual(json.loads((output / 'launch-receipt.json').read_text())['status'], 'failed')
            spawn.assert_not_called()
            with self.assertRaises(FileExistsError):
                h.launch_isolated(h.plan('unit', 'quic-like', 'tap'), output,
                    Path('/absent/binary'), Path('/absent/build'))

    def test_failure_categories_remain_distinct(self):
        self.assertEqual(h.failure_status(h.Unsupported('device')), 'unsupported')
        self.assertEqual(h.failure_status(h.bounded.Unsupported('offload capability')), 'unsupported')
        self.assertEqual(h.failure_status(TimeoutError('original deadline')), 'bound_exhausted')
        self.assertEqual(h.failure_status(h.bounded.CaptureBound('packet cap')), 'bound_exhausted')
        self.assertEqual(h.failure_status(FileNotFoundError('tcpdump')), 'tool_failure')
        self.assertEqual(h.failure_status(ImportError('cryptography')), 'tool_failure')
        self.assertEqual(h.failure_status(ModuleNotFoundError('cryptography')), 'tool_failure')
        self.assertEqual(h.failure_status(ValueError('wrong C')), 'failed')
        owner = h.Owner(h.plan('unit', 'quic-like', 'tap'), Path('/unused'), Mock(), time.monotonic() + 1)
        child = Mock()
        child.wait.return_value = -signal.SIGXFSZ
        with self.assertRaises(h.native.BoundExhausted), patch.object(h, 'stop_child'):
            owner.wait(child, 1)

    def test_missing_ethtool_or_crypto_fails_before_topology_mutation(self):
        case = h.plan('unit', 'media-like', 'tun')
        for missing in ('ethtool', 'cryptography'):
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(h.bounded, 'file_hash', return_value='00'), \
                    patch.object(h, 'verify_helpers', return_value={}), \
                    patch.object(h.shutil, 'which', side_effect=lambda name: None if name == missing else '/tool'), \
                    patch.object(h, 'credential_preflight', side_effect=ImportError('cryptography')
                        if missing == 'cryptography' else None) as crypto, \
                    patch.object(h.bounded, 'bounded_lab') as apply, \
                    patch.object(h, 'cleanup_topology'):
                result = h.run_case(case, Path(directory), {}, {})
                self.assertEqual(result['status'], 'tool_failure')
                apply.assert_not_called()
                if missing == 'ethtool':
                    crypto.assert_not_called()


class WorkerFileLimits(unittest.TestCase):
    def test_default_and_explicit_receipt_cap_preserve_capture_ceiling(self):
        for selected, expected in ((None, h.BOUNDS['log_bytes']), (4 * 1024 * 1024, 4 * 1024 * 1024)):
            with patch.object(h.resource, 'getrlimit', return_value=(h.resource.RLIM_INFINITY, h.resource.RLIM_INFINITY)), \
                    patch.object(h.resource, 'setrlimit') as apply:
                limits = h.worker_limits() if selected is None else h.worker_limits(file_bytes=selected)
                apply.assert_not_called()
                limits()
                apply.assert_called_once_with(h.resource.RLIMIT_FSIZE, (expected, h.BOUNDS['capture_bytes']))
        self.assertEqual(h.BOUNDS['log_bytes'], 1024 * 1024)
        self.assertEqual(h.BOUNDS['capture_bytes'], 8 * 1024 * 1024)

    def test_invalid_or_insufficient_inherited_caps_refuse_without_limit_mutation(self):
        for invalid in (False, True, 0, -1, '4194304', h.BOUNDS['capture_bytes'] + 1):
            with patch.object(h.resource, 'getrlimit') as read, patch.object(h.resource, 'setrlimit') as apply:
                with self.assertRaises(ValueError):
                    h.worker_limits(file_bytes=invalid)
                read.assert_not_called()
                apply.assert_not_called()
        maximum = h.BOUNDS['capture_bytes']
        with patch.object(h.resource, 'getrlimit', return_value=(maximum - 1, maximum - 1)), \
                patch.object(h.resource, 'setrlimit') as apply:
            with self.assertRaises(h.native.ObservationError):
                h.worker_limits(file_bytes=4 * 1024 * 1024)
            apply.assert_not_called()
        with patch.object(h.resource, 'getrlimit', side_effect=[(maximum, maximum), (maximum - 1, maximum - 1)]), \
                patch.object(h.resource, 'setrlimit') as apply:
            limits = h.worker_limits(file_bytes=4 * 1024 * 1024)
            with self.assertRaises(ValueError):
                limits()
            apply.assert_not_called()


class OriginalDeadlines(unittest.TestCase):
    def owner(self):
        return h.Owner(h.plan('unit', 'quic-like', 'tap'), Path('/unused'), Mock(), 240)

    def test_rpc_uses_original_phase_wait_and_rejects_late_success(self):
        now = [1.0]
        owner, child = self.owner(), Mock()
        def waited(timeout):
            self.assertEqual(timeout, 4)
            now[0] = 6.0
            return 0
        child.wait.side_effect = waited
        with patch.object(h.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(h.bounded, 'launch', return_value=child), \
                patch.object(h.bounded, 'read_log', return_value='{"ok":true}') as read, \
                patch.object(h, 'stop_child') as stop, self.assertRaises(TimeoutError):
            owner.rpc(Path('/binary'), Path('/run/private'), 'a', 'status', deadline=5)
        read.assert_not_called()
        stop.assert_called_once_with(child, 36.0)
        self.assertEqual(owner.cleanup_deadline, 36.0)
        with patch.object(h.time, 'monotonic', return_value=20.0):
            self.assertEqual(owner.begin_cleanup(), 36.0)

    def test_expired_phase_refuses_spawn_and_poll_cannot_return_late_success(self):
        owner = self.owner()
        now = [6.0]
        with patch.object(h.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(h.bounded, 'launch') as spawn:
            with self.assertRaises(TimeoutError):
                owner.command('endpoint_a', 'ss', '-u', deadline=5)
            spawn.assert_not_called()
            now[0] = 1.0
            def read(deadline):
                self.assertEqual(deadline, 5)
                now[0] = 6.0
                return True
            with self.assertRaises(TimeoutError):
                owner.await_value(5, read, bool)
        self.assertIsNone(owner.cleanup_deadline)

    def test_ready_log_success_after_original_startup_cap_is_refused(self):
        owner, now = self.owner(), [1.0]
        def late(*args):
            self.assertEqual(args[-1], 35)
            now[0] = 36.0
        with patch.object(h.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(h.bounded, 'wait_log', side_effect=late), self.assertRaises(TimeoutError):
            owner.wait_log(Mock(), Path('/unused/log'), 'ready', 35)

    def test_normal_phase_stops_use_phase_cap_and_failure_cleanup_deadline_is_reused(self):
        owner, active, exited = self.owner(), Mock(), Mock()
        active.poll.return_value = None
        exited.poll.return_value = 0
        with patch.object(h.time, 'monotonic', return_value=10.0), patch.object(h, 'stop_child') as stop:
            owner.finish_phase([active, exited], 35, False)
            stop.assert_called_once_with(active, 35)
            self.assertIsNone(owner.cleanup_deadline)
            stop.reset_mock()
            owner.finish_phase([exited], 35, False)
            stop.assert_not_called()
            self.assertIsNone(owner.cleanup_deadline)
            owner.finish_phase([active], 35, True)
            stop.assert_called_once_with(active, 40.0)
        with patch.object(h.time, 'monotonic', return_value=29.0), patch.object(h, 'stop_child') as stop:
            owner.finish_phase([active], 35, True)
            stop.assert_called_once_with(active, 40.0)
            self.assertEqual(owner.begin_cleanup(), 40.0)


if __name__ == '__main__':
    unittest.main()
