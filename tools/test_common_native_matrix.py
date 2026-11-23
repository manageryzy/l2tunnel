#!/usr/bin/env python3
"""Unprivileged contract checks for the Common native matrix harness."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
from contextlib import ExitStack
import io
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    from . import common_native_matrix as matrix, common_native_observe as observe, common_native_probe as probe
except ImportError:
    import common_native_matrix as matrix
    import common_native_observe as observe
    import common_native_probe as probe


def row():
    base = ['--carrier', 'quic-like', '--record-profile', 'common', '--duplex', 'full', '--compression', 'off',
            '--layer', 'tun', '--max-packet', '1500', '--max-path-mtu', '1500', '--noise-profile', 'ik']
    return {'id': 'aligned-udp', 'status': 'ready', 'carrier': 'udp', 'common_plan': 'plan.json',
            'expected_descriptor_hex': 'aa' * 1272, 'carrier_policy': None,
            'required_cli': {side: [*base, '--udp-bind', matrix.WAN[side] + ':' + str(matrix.PORTS[side]),
                '--udp-peer', matrix.WAN[other] + ':' + str(matrix.PORTS[other])] for side, other in [('a', 'b'), ('b', 'a')]}}


def ipv4(source, destination, count):
    packet = bytearray(count)
    packet[0], packet[9] = 0x45, 6
    packet[2:4] = count.to_bytes(2, 'big')
    packet[12:16], packet[16:20] = socket.inet_aton(source), socket.inet_aton(destination)
    return bytes(packet)


def pcap(packets, link=101):
    value = bytearray(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 2048, link))
    for second, packet in packets:
        value += struct.pack('<IIII', second, 0, len(packet), len(packet)) + packet
    return bytes(value)


class MatrixTests(unittest.TestCase):
    def test_credentials_preflight_has_no_native_layer_but_traffic_requires_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            case = matrix.Case(None, matrix.lab.LabSpec('cred-test'), output)
            saved = json.loads((output / 'result.json').read_text())
            self.assertEqual(saved['id'], 'credentials')
            self.assertIsNone(saved['native_layer'])
            secrets = output / 'secrets'
            secrets.mkdir()
            (secrets / 'cert.der').write_bytes(b'fixture')
            with patch.object(case, 'command') as command:
                receipt = matrix.tls_credentials(case, secrets)
            self.assertEqual(receipt['own_certificate_sha256'], matrix.file_hash(secrets / 'cert.der'))
            self.assertTrue(all(call.args[:2] == (None, 'openssl') for call in command.call_args_list))
            self.assertEqual(command.call_count, 3)
            with self.assertRaises(KeyError):
                matrix.Case({'id': 'incomplete-traffic'}, None, output)

    def test_post_eof_mixed_observation_requires_matching_peer_commits_and_stability(self):
        case = SimpleNamespace(value={}, row={}, deadline=time.monotonic()+2)
        pairs = []
        for reverse_confirmation in (6, 7, 7):
            for send, receive, tx, rx in [('forward','reverse',5,reverse_confirmation), ('reverse','forward',7,5)]:
                sources = dict(send_direction=send, receive_direction=receive, send_stream=1, receive_stream=1,
                               send_outstanding=0, send_retained=0, receive_uncommitted_in_groups=0,
                               receive_uncommitted_through_sealed=0, send_confirmed=tx, receive_confirmed=rx,
                               receive_sealed=rx)
                pairs.append({'state': {'common': {'epoch': 2, 'striped_sources': sources}}})
        with patch.object(matrix, 'status', side_effect=pairs), patch.object(matrix, 'require_ready'), patch.object(matrix.time, 'sleep'):
            matrix.observe_mixed_drain(case, None, None, case.deadline + 2)
        report = case.value['post_eof_mixed_sources']
        self.assertEqual(report['outcome'], 'two_stable_zero_samples')
        self.assertEqual(len(report['samples']), 3)

    def test_single_flow_memory_observations_distinguish_missing_from_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'proc-entry'
            self.assertIsNone(probe.single.tcp_memory_scope(path)['tcp_mem_pages'])
            self.assertTrue(all(v is None for v in probe.single.tcp_memory_counters(path).values()))
            path.write_text('2 4 8\n')
            self.assertEqual(probe.single.tcp_memory_scope(path)['tcp_mem_pages'],
                             {'low': 2, 'pressure': 4, 'high': 8})
            path.write_text('TcpExt: RcvPruned Other TCPMemoryPressures\nTcpExt: 0 62 3\n')
            counters = probe.single.tcp_memory_counters(path)
            self.assertEqual(counters['RcvPruned'], 0)
            self.assertEqual(counters['TCPMemoryPressures'], 3)
            self.assertIsNone(counters['TCPMemoryPressuresChrono'])
            self.assertIsNone(counters['TCPHystartDelayDetect'])
            path.write_text('TcpExt: TCPHystartDelayCwnd TCPHystartTrainDetect TCPHystartTrainCwnd TCPHystartDelayDetect\n'
                            'TcpExt: 0 1 40 0\n')
            counters = probe.single.tcp_memory_counters(path)
            self.assertEqual([counters['TCPHystart' + field] for field in
                              ('TrainDetect', 'TrainCwnd', 'DelayDetect', 'DelayCwnd')], [1, 40, 0, 0])
            path.write_text('TcpExt: TCPMemoryPressures\nIpExt: 7\n')
            self.assertIsNone(probe.single.tcp_memory_counters(path)['TCPMemoryPressures'])
            self.assertIsNone(probe.single.tcp_memory_scope(path)['tcp_mem_pages'])

    def test_single_flow_credit_counts_accepted_bytes_and_preserves_partial_record(self):
        module = probe.single
        clock = {'measure_start_ns': 1, 'end_ns': 2}
        with patch.object(module, 'outstanding', side_effect=[0, module.CREDIT - 256, module.CREDIT - 512]):
            window = module.Window(None, clock)
            window.accepted(module.CREDIT)
            self.assertFalse(window.allows(512))
            self.assertEqual(window.needed, 512)
            self.assertTrue(window.allows(window.needed))
            window.accepted(384)
            self.assertTrue(window.allows(128))
            window.accepted(128)
        self.assertEqual(window.report()['max_outstanding_upper_bound'], module.CREDIT)
        self.assertEqual(window.report()['credit_denials'], 1)
        self.assertGreater(module.TRANSFER_CAP, module.RATE * 12 // 8)

    def test_fq_duplicate_auxiliary_statistics_preserve_kernel_drop_evidence(self):
        link = '[{"ifname":"tun0","txqlen":768,"stats64":{"tx":{"packets":17,"bytes":1024,"dropped":2,"errors":0}}}]'
        raw = '[{"kind":"fq","drops":3,"throttled":4,"throttled":18}]'
        case = SimpleNamespace(value={'native_layer': 'tun', 'requested_native_tun_txqueuelen': 768},
                               command=lambda _, tool, *args: link if tool == 'ip' else raw)
        actual = matrix.native_tun_snapshot(case, 'endpoint_a')
        self.assertEqual(actual['qdisc'], [{'kind': 'fq', 'drops': 3}])
        raw = '[{"kind":"fq","drops":3,"drops":4}]'
        with self.assertRaisesRegex(ValueError, 'duplicate native tun0 qdisc field'):
            matrix.native_tun_snapshot(case, 'endpoint_a')

    def test_owned_tun_txqueuelen_and_distinct_device_qdisc_drops(self):
        tx = {'bytes': 42000, 'packets': 31, 'errors': 0, 'dropped': 27}
        native_qdisc = [{'kind': 'fq', 'handle': '1:', 'root': True, 'drops': 0}]
        for layer, requested, effective in (('tun', None, 500), ('tun', 640, 640), ('tap', 640, 640), ('tun', 640, 500)):
            with self.subTest(layer=layer, requested=requested, effective=effective), ExitStack() as stack:
                commands = []
                maxrate = 82 if requested is not None else None

                def command(role, *argv):
                    commands.append((role, argv))
                    if argv == ('ip', '-j', '-s', 'link', 'show', 'dev', 'tun0'):
                        return json.dumps([{'ifname': 'tun0', 'link_type': 'ether' if layer == 'tap' else 'none',
                                            'txqlen': effective, 'stats64': {'tx': tx}}])
                    if argv == ('tc', '-s', '-d', '-j', 'qdisc', 'show', 'dev', 'tun0'):
                        if maxrate is not None and role == 'endpoint_a':
                            return json.dumps([dict(native_qdisc[0], options={'maxrate': 10250000, 'limit': 10240, 'flow_limit': 1024})])
                        return json.dumps(native_qdisc)
                    if argv == ('tc', '-d', 'qdisc', 'show', 'dev', 'wan0'):
                        return 'delay 35ms loss 15%'
                    return ''

                case = SimpleNamespace(spec=matrix.lab.LabSpec('tun-test'), deadline=0, command=command,
                                       value={'native_layer': layer, 'requested_native_tun_txqueuelen': requested,
                                              'requested_native_forward_tun_maxrate_mbit': maxrate}, save=lambda: None)
                for target, name, value in ((matrix.bounded, 'bounded_lab', None), (matrix.bounded, 'offloads', {}),
                                             (matrix, 'read_json', {}), (matrix, 'parse_tc_class', ([], 'test')),
                                             (matrix, 'parse_tc_qdisc', [])):
                    stack.enter_context(patch.object(target, name, return_value=value))
                if requested and effective != requested:
                    with self.assertRaisesRegex(ValueError, 'differs from request'):
                        matrix.topology(case, Path('/unused'))
                else:
                    matrix.topology(case, Path('/unused'))
                changes = [role for role, argv in commands if 'txqueuelen' in argv]
                self.assertEqual(changes, [] if requested is None else ['endpoint_a', 'endpoint_b'])
                replacements = [(role, cmd) for role, cmd in commands if cmd[:3] == ('tc', 'qdisc', 'replace')]
                self.assertEqual(replacements, [] if maxrate is None else [('endpoint_a', ('tc', 'qdisc', 'replace',
                    'dev', 'tun0', 'root', 'fq', 'limit', '10240', 'flow_limit', '1024', 'maxrate', '82mbit'))])
                for side, report in case.value['qdisc_before'].items():
                    snap = report['native_tun']
                    self.assertEqual(snap['native_layer'], layer)
                    self.assertEqual(snap['kernel_link_type'], 'ether' if layer == 'tap' else 'none')
                    self.assertEqual((snap['requested_txqueuelen'], snap['effective_txqueuelen']), (requested, effective))
                    self.assertEqual((snap['tx'], snap['qdisc']), (tx, native_qdisc))
                    shaped = side == 'a' and maxrate is not None
                    self.assertEqual(snap['requested_fq_maxrate_mbit'], 82 if shaped else None)
                    self.assertEqual(snap['effective_root_fq'], {'limit': 10240, 'flow_limit': 1024,
                                     'maxrate_bytes_per_second': 10250000, 'maxrate_bits_per_second': 82000000} if shaped else {})
                if maxrate is not None:
                    fq = case.value['qdisc_before']['a']['native_tun']['effective_root_fq']
                    for key in ('maxrate_bits_per_second', 'flow_limit', 'limit'):
                        with patch.dict(fq, {key: fq[key] - 1}), self.assertRaisesRegex(ValueError, 'differ from request'):
                            matrix.check_forward_tun_fq(case, case.value['qdisc_before'])
                for side in ('a', 'b'):
                    self.assertIn(('endpoint_' + side, ('ip', 'tuntap', 'add', 'dev', 'tun0', 'mode', layer)), commands)
                    self.assertIn(('endpoint_' + side, ('ip', 'link', 'set', 'br-lan', 'down')), commands)
                    self.assertIn(('endpoint_' + side, ('ip', 'address', 'add', matrix.NATIVE[side] + '/24',
                                                        'dev', 'tun0')), commands)
                    if requested is not None:
                        self.assertIn(('endpoint_' + side, ('ip', 'link', 'set', 'tun0', 'mtu', '1500',
                                                            'txqueuelen', str(requested), 'up')), commands)
        for invalid in ('0', str(matrix.MAX_TUN_TXQUEUELEN + 1)):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                matrix.main(['--manifest', '/unused', '--binary', '/unused', '--output', '/unused',
                             '--native-tun-txqueuelen', invalid])

        for invalid in ('0', '101'):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                matrix.main(['--manifest', '/unused', '--binary', '/unused', '--output', '/unused',
                             '--native-forward-tun-maxrate-mbit', invalid])

    def deferred_case(self, root, failure=None):
        """Exercise the actual case coordinator with owned-I/O test doubles."""
        output, secrets, state = root / 'output', root / 'secrets', root / 'state'
        for directory in (output, secrets, state):
            directory.mkdir()
        for side in ('a', 'b'):
            (secrets / f'control-{side}.sock').touch()
        events = []
        value = row()
        args = SimpleNamespace(lab_id='test-matrix', output=output, phases=list(matrix.PHASES))

        def spawn(case, role, label, argv, capture=None, metrics=None):
            pid = 101 if label == 'daemon-a' else 102
            log = case.output / (label + '.log')
            log.write_text('')
            child = {'label': label, 'process': SimpleNamespace(pid=pid), 'log': log, 'capture': capture}
            case.children.append(child)
            (metrics.parent / f'wire.{pid}.json').write_text('{}')
            return child

        def stop(case, child, requested=signal.SIGTERM, deadline=None):
            events.append(('stop', child['label']))
            self.assertIsNotNone(deadline)
            child.setdefault('stops', []).append({'returncode': 0})
            return 0

        def live_phase(case, name, *_):
            events.append(('phase', name))
            directory = case.output / name
            directory.mkdir()
            result = {'phase': name, 'status': 'passed', 'captures': {},
                      'throughput_observed': {'a_to_b': {'observed_goodput_mbit_s': 1.0}}}
            if failure == 'probe' and name == 'reverse':
                result.update(status='bound_exhausted', error='original TCP workload deadline exhausted')
            case.value['phases'].append(result)
            captures = {}
            second = 2 + 3 * matrix.PHASES.index(name)
            for side in ('a', 'b'):
                for kind, addresses in [('wan', list(matrix.WAN.values())), ('native', list(matrix.NATIVE.values()))]:
                    label = name + '-' + side + '-' + kind
                    path = directory / (side + '-' + kind + '.pcap')
                    raw = pcap([(second, ipv4(*addresses, 40))])
                    if failure == 'truncated' and name == 'forward' and side == 'a' and kind == 'wan':
                        raw = raw[:-1]
                    path.write_bytes(raw)
                    log = case.output / (label + '.log')
                    dropped = int(failure == 'drop' and name == 'forward' and side == 'a' and kind == 'wan')
                    log.write_text(f'1 packets captured\n1 packets received by filter\n{dropped} packets dropped by kernel\n')
                    child = {'label': label, 'capture': path, 'log': log}
                    captures[side + '_' + kind] = (child, addresses)
            matrix.stop_captures(case, result, captures,
                                 ((second - 1) * 1_000_000_000, (second + 1) * 1_000_000_000), case.deadline)
            matrix.qualify_phase(result)
            if result['status'] == 'passed':
                self.assertEqual(result['throughput_observed']['a_to_b']['qualification'], 'pending_capture_validation')
                self.assertTrue(all('summary' not in entry and 'sha256' not in entry for entry in result['captures'].values()))
            return result['status'] == 'passed'

        def disconnect(argv, deadline, maximum):
            side = 'a' if any('control-a.sock' in str(value) for value in argv) else 'b'
            events.append(('disconnect', side))
            self.assertEqual(maximum, 3)
            if failure == 'disconnect' and side == 'b':
                raise RuntimeError('original owner LeaseExpired')
            return json.dumps({'version': 4, 'ok': True, 'code': 'ok', 'state': {'phase': 'disconnected'}})

        original_summary = observe.capture_summary

        def summarize(*values):
            self.assertIn(('disconnect', 'a'), events)
            self.assertIn(('disconnect', 'b'), events)
            self.assertIn(('cleanup', 'namespaces'), events)
            events.append(('analyze', values[0].parent.name))
            return original_summary(*values)

        with ExitStack() as stack:
            for target, name, replacement in [
                (matrix, 'topology', lambda *_: None),
                (matrix, 'readiness', lambda *_: None),
                (matrix, 'phase', live_phase),
                (matrix.Case, 'command', lambda *_a, **_k: ''),
                (matrix.Case, 'spawn', spawn),
                (matrix.Case, 'stop', stop),
                (matrix.bounded, 'command', disconnect),
                (matrix.bounded, 'bounded_lab', lambda *_: events.append(('cleanup', 'namespaces'))),
                (matrix.observe, 'validate_wire_metrics', lambda *_: {}),
                (matrix.observe, 'capture_summary', summarize),
            ]:
                stack.enter_context(patch.object(target, name, replacement))
            result = matrix.run_case(value, 0, args, Path('/unused-binary'), root, secrets, state)
        return result, events

    def test_all_live_phases_and_requested_disconnect_precede_offline_capture_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            result, events = self.deferred_case(Path(directory))
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['data_status'], 'passed')
        self.assertEqual(result['shutdown']['status'], 'passed')
        self.assertEqual([value for kind, value in events if kind == 'phase'], list(matrix.PHASES))
        self.assertLess(events.index(('phase', 'simultaneous')), events.index(('disconnect', 'a')))
        self.assertLess(events.index(('disconnect', 'b')), events.index(('analyze', 'forward')))
        for result in result['phases']:
            self.assertEqual(result['capture_analysis'], 'passed')
            self.assertEqual(result['throughput_observed']['a_to_b']['qualification'], 'valid')
            for entry in result['captures'].values():
                self.assertEqual(entry['summary']['captured_packets'], 1)
                self.assertEqual(entry['summary']['sample_window']['a_to_b']['packets'], 1)
                self.assertEqual(len(entry['sha256']), 64)

    def test_failed_probe_still_disconnects_and_preserves_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            result, events = self.deferred_case(Path(directory), 'probe')
        self.assertEqual(result['status'], 'bound_exhausted')
        self.assertEqual(result['shutdown']['status'], 'passed')
        self.assertEqual([value for kind, value in events if kind == 'phase'], ['forward', 'reverse'])
        self.assertEqual(result['phases'][1]['error'], 'original TCP workload deadline exhausted')
        self.assertEqual(result['phases'][1]['throughput_observed']['a_to_b']['qualification'], 'invalid_or_incomplete')
        self.assertEqual(result['phases'][2]['status'], 'not_run')

    def test_known_capture_drop_stops_later_phases_and_is_never_qualified(self):
        with tempfile.TemporaryDirectory() as directory:
            result, events = self.deferred_case(Path(directory), 'drop')
        self.assertEqual([value for kind, value in events if kind == 'phase'], ['forward'])
        self.assertEqual(result['status'], 'tool_failure')
        entry = result['phases'][0]['captures']['a_wan']
        self.assertIn('drops', entry['error'])
        self.assertEqual(entry['analysis'], 'failed')
        self.assertEqual(result['shutdown']['status'], 'passed')

    def test_offline_malformed_capture_invalidates_only_its_completed_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            result, events = self.deferred_case(Path(directory), 'truncated')
        self.assertEqual([value for kind, value in events if kind == 'phase'], list(matrix.PHASES))
        self.assertEqual(result['status'], 'tool_failure')
        self.assertEqual(result['phases'][0]['capture_analysis'], 'failed')
        self.assertIn('truncated', result['phases'][0]['captures']['a_wan']['error'])
        self.assertEqual([phase['status'] for phase in result['phases'][1:]], ['passed', 'passed'])

    def test_failed_requested_disconnect_does_not_hide_valid_data_or_skip_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            result, events = self.deferred_case(Path(directory), 'disconnect')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['data_status'], 'passed')
        self.assertEqual(result['shutdown']['status'], 'failed')
        self.assertEqual(result['shutdown']['endpoints']['a']['status'], 'passed')
        self.assertEqual(result['shutdown']['endpoints']['b']['status'], 'failed')
        self.assertIn('LeaseExpired', result['cleanup']['disconnect']['b']['error'])
        self.assertIn(('cleanup', 'namespaces'), events)
        self.assertTrue(all(value['capture_analysis'] == 'passed' for value in result['phases']))

    def test_disconnect_submits_both_local_requests_before_waiting_for_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            secrets = Path(directory)
            for side in ('a', 'b'):
                (secrets / f'control-{side}.sock').touch()
            case = SimpleNamespace(children=[{'label': 'daemon-a'}, {'label': 'daemon-b'}],
                value={'status': 'passed', 'data_status': 'passed', 'cleanup': {'disconnect': {}}},
                prefix=lambda _role, argv: argv)
            deadline = time.monotonic() + 30
            entered = threading.Barrier(2)
            calls = []

            def request(argv, actual_deadline, cap):
                side = 'a' if 'control-a.sock' in str(argv) else 'b'
                calls.append((side, actual_deadline, cap))
                # Neither command can finish until the other actually started.
                # The timeout bounds a broken test, not a runtime policy change.
                entered.wait(timeout=2)
                return json.dumps({'version': 4, 'ok': True, 'code': 'ok',
                    'state': {'phase': 'disconnected', 'common': {'service_terminal': 'Aborted'}}})

            with patch.object(matrix.bounded, 'command', request):
                matrix.disconnect_sessions(case, Path('/unused'), secrets, deadline)
        self.assertEqual(sorted(calls), [('a', deadline, 3), ('b', deadline, 3)])
        self.assertEqual(case.value['shutdown']['status'], 'passed')
        self.assertEqual(case.value['status'], 'passed')
        self.assertEqual(case.value['data_status'], 'passed')
        self.assertEqual(set(case.value['cleanup']['disconnect']), {'a', 'b'})

    def test_concurrent_disconnect_keeps_peer_failure_and_success_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            secrets = Path(directory)
            for side in ('a', 'b'):
                (secrets / f'control-{side}.sock').touch()
            case = SimpleNamespace(children=[{'label': 'daemon-a'}, {'label': 'daemon-b'}],
                value={'status': 'passed', 'data_status': 'passed', 'cleanup': {'disconnect': {}}},
                prefix=lambda _role, argv: argv)
            deadline = time.monotonic() + 30
            entered = threading.Barrier(2)
            calls = []
            failure = {'version': 4, 'ok': False, 'code': 'state',
                'state': {'phase': 'failed', 'common': {'terminal': 'Io(Other)',
                    'service_terminal': 'Failed(Failure { kind: Other })'}}}

            def request(argv, actual_deadline, cap):
                side = 'a' if 'control-a.sock' in str(argv) else 'b'
                calls.append((side, actual_deadline, cap))
                entered.wait(timeout=2)
                if side == 'b':
                    raise RuntimeError('command failed (1): ' + json.dumps(failure))
                return json.dumps({'version': 4, 'ok': True, 'code': 'ok',
                                   'state': {'phase': 'disconnected'}})

            with patch.object(matrix.bounded, 'command', request):
                matrix.disconnect_sessions(case, Path('/unused'), secrets, deadline)
        self.assertEqual(sorted(calls), [('a', deadline, 3), ('b', deadline, 3)])
        self.assertEqual(case.value['shutdown']['endpoints']['a']['status'], 'passed')
        self.assertEqual(case.value['shutdown']['endpoints']['b']['status'], 'failed')
        self.assertEqual(case.value['shutdown']['status'], 'failed')
        self.assertEqual(case.value['status'], 'failed')
        self.assertEqual(case.value['data_status'], 'passed')
        self.assertIn(json.dumps(failure), case.value['cleanup']['disconnect']['b']['error'])
        self.assertTrue(case.value['cleanup']['disconnect']['a']['ok'])

    def test_command_timeout_preserves_actual_child_exit_and_original_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            case = matrix.Case(row(), None, Path(directory))
            with patch.dict(matrix.BOUNDS, command_seconds=.1):
                with self.assertRaises(subprocess.TimeoutExpired):
                    case.command(None, sys.executable, '-c', 'import time; time.sleep(10)')
            receipt = json.loads((Path(directory) / 'result.json').read_text())['commands'][0]
            self.assertTrue(receipt['timed_out'])
            self.assertEqual(receipt['requested_signal'], 'SIGKILL')
            self.assertEqual(receipt['returncode'], -signal.SIGKILL)
            self.assertGreater(receipt['pid'], 0)
            self.assertGreaterEqual(receipt['finished_wall_ns'], receipt['started_wall_ns'])

    def test_capture_int_then_term_uses_existing_graceful_budget_and_records_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            case = matrix.Case(row(), None, Path(directory))
            script = ('import signal,time\n'
                      'signal.signal(signal.SIGINT, lambda *_: print("INT", flush=True))\n'
                      'signal.signal(signal.SIGTERM, lambda *_: exit(0))\n'
                      'print("READY", flush=True)\n'
                      'while True: time.sleep(.01)\n')
            child = case.spawn(None, 'capture-signal-fixture', [sys.executable, '-c', script])
            try:
                case.wait_marker(child, 'READY', time.monotonic() + 2)
                self.assertEqual(case.stop(child, signal.SIGINT, time.monotonic() + 5), 0)
                receipt = json.loads((Path(directory) / 'result.json').read_text())['child_stops'][0]['observation']
                self.assertEqual([entry['signal'] for entry in receipt['signals']], ['SIGINT', 'SIGTERM'])
                self.assertLess(receipt['elapsed_seconds'], 3)
                self.assertEqual(receipt['returncode'], 0)
            finally:
                if child['process'].poll() is None:
                    child['process'].kill()
                    child['process'].wait(timeout=2)

    def test_manifest_keeps_plan_refused_and_rejects_escape_or_retired_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = row()
            (root / 'plan.json').write_text(json.dumps({'version': 1, 'backend': 'common_records_v2', 'catalog': [value['expected_descriptor_hex']]}))
            manifest = root / 'manifest.json'
            items = [value, {'id': 'refused', 'status': 'plan_refused', 'reason': 'generated constructor refused'}]
            manifest.write_text(json.dumps({'version': 1, 'rows': items}))
            self.assertEqual(len(matrix.manifest_rows(manifest, set())[1]), 2)
            value['required_cli']['a'] += ['--swift-forward-kbit', '100000']
            manifest.write_text(json.dumps({'version': 1, 'rows': items}))
            with self.assertRaisesRegex(ValueError, 'unknown or repeated'):
                matrix.manifest_rows(manifest, set())
            with self.assertRaises(ValueError):
                matrix.input_path(root, '../other.json')

    def test_tap_manifest_binds_both_ends_layer_and_ethernet_extent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = row()
            value['layer'] = 'tap'
            for options in value['required_cli'].values():
                options[options.index('--layer') + 1] = 'tap'
                options[options.index('--max-packet') + 1] = '1514'
            (root / 'plan.json').write_text(json.dumps({'version': 1, 'backend': 'common_records_v2',
                                                        'catalog': [value['expected_descriptor_hex']]}))
            manifest = root / 'manifest.json'
            def load():
                manifest.write_text(json.dumps({'version': 1, 'rows': [value]}))
                return matrix.manifest_rows(manifest, set())[1][0]
            self.assertEqual(matrix.native_layer(load()), 'tap')
            with patch.dict(value, layer='tun'), self.assertRaisesRegex(ValueError, 'native layer'):
                load()
            for flag, bad in (('--layer', 'tun'), ('--layer', 'raw'), ('--max-packet', '1500'), ('--max-path-mtu', '1514')):
                options = value['required_cli']['b']
                at = options.index(flag) + 1
                old, options[at] = options[at], bad
                with self.subTest(flag=flag, bad=bad), self.assertRaises(ValueError):
                    load()
                options[at] = old

    def test_tap_pcap_counts_ipv4_extent_and_keeps_arp_outside_ip_totals(self):
        addresses = list(matrix.NATIVE.values())
        mac = bytes.fromhex('020000000002020000000001')
        arp = mac + b'\x08\x06' + bytes(46)
        frame = mac + b'\x08\x00' + ipv4(*addresses, 1500)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'tap.pcap'
            path.write_bytes(pcap([(1, arp), (2, frame)], link=1))
            result = observe.capture_summary(path, addresses)
        self.assertEqual((result['captured_packets'], result['non_ipv4_packets']), (2, 1))
        self.assertEqual(result['whole_capture']['a_to_b']['ip_bytes'], 1500)

    def test_dry_run_records_selected_seed_loss_and_raw_rst_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = row()
            (root / 'plan.json').write_text(json.dumps({'version': 1, 'backend': 'common_records_v2', 'catalog': [value['expected_descriptor_hex']]}))
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'version': 1, 'rows': [value]}))
            base = ['--manifest', str(manifest), '--binary', '/unused-binary', '--output', str(root / 'output'),
                    '--phase', 'forward', '--flow-count', '4']
            try:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(matrix.main([*base, '--netem-seed', '48761', '--loss-percent', '0',
                                                  '--raw-rst-observation']), 0)
                plan = json.loads(output.getvalue())
                self.assertEqual(plan['network']['loss_percent_each_direction'], 0)
                self.assertEqual(plan['netem_seeds'], {'a': 48761, 'b': 48761 ^ 0x9e3779b97f4a7c15})
                self.assertTrue(plan['raw_rst_observation'])
                self.assertFalse((root / 'output').exists())
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(matrix.main(base), 0)
                plan = json.loads(output.getvalue())
                self.assertEqual(plan['network']['loss_percent_each_direction'], 15)
                self.assertEqual(plan['netem_seeds']['a'], 31248)
                self.assertFalse(plan['raw_rst_observation'])
                for invalid in (['--loss-percent', '101'], ['--loss-percent', '-1'], ['--netem-seed', '0']):
                    with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        matrix.main([*base, *invalid])
            finally:
                matrix.NETEM_SEED, matrix.LOSS_PERCENT = 31248, 15

    def test_dry_run_records_selected_outstanding_credit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = row()
            (root / 'plan.json').write_text(json.dumps({'version': 1, 'backend': 'common_records_v2', 'catalog': [value['expected_descriptor_hex']]}))
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'version': 1, 'rows': [value]}))
            base = ['--manifest', str(manifest), '--binary', '/unused-binary', '--output', str(root / 'output'),
                    '--phase', 'forward']
            try:
                for extra, total, share in ((['--flow-count', '4'], 4 * 1024 * 1024, 1024 * 1024),
                                            (['--flow-count', '1', '--outstanding-credit-bytes', '524288'], 524288, 524288),
                                            (['--flow-count', '4', '--outstanding-credit-bytes', '524288'], 524288, 131072)):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(matrix.main([*base, *extra]), 0)
                    plan = json.loads(output.getvalue())
                    self.assertEqual((plan['outstanding_application_credit_bytes'], plan['per_flow_credit_bytes']), (total, share))
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(matrix.main([*base, '--single-flow-4m', '--outstanding-credit-bytes', '524288']), 0)
                self.assertEqual(json.loads(output.getvalue())['outstanding_application_credit_bytes'], 524288)
                for invalid in (['--flow-count', '16', '--outstanding-credit-bytes', '4096'],
                                ['--flow-count', '1', '--outstanding-credit-bytes', '0'],
                                ['--flow-count', '1', '--outstanding-credit-bytes', str(2**32)]):
                    with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        matrix.main([*base, *invalid])
            finally:
                matrix.NETEM_SEED, matrix.LOSS_PERCENT = 31248, 15

    def test_compare_probes_checks_the_selected_per_flow_credit(self):
        clock = {'start_ns': 0, 'measure_start_ns': 10, 'end_ns': 20}

        def endpoint(cap, sending):
            connection = {'flow_id': 0, 'local': ['198.18.0.1', 4000] if sending else ['198.18.0.2', 24451],
                          'peer': ['198.18.0.2', 24451] if sending else ['198.18.0.1', 4000],
                          'tcp_congestion': 'cubic', 'send_buffer_bytes': 2 * probe.single.SOCKET_BUFFER,
                          'receive_buffer_bytes': 2 * probe.single.SOCKET_BUFFER}
            edges = [{'target_ns': 10, 'before_ns': 10, 'after_ns': 11, 'total_retrans': 0},
                     {'target_ns': 20, 'before_ns': 20, 'after_ns': 21, 'total_retrans': 2}]
            flow = {'flow_id': 0, 'sent': 512 if sending else 0, 'received': 0 if sending else 512,
                    'sent_sha256': 'x', 'received_sha256': 'x', 'write_closed': True, 'eof': True,
                    'measured': 0 if sending else 512}
            timing = {'flow_id': 0, 'fully_read_records': 1, 'fully_written_records': 1, 'partial_record_bytes': 0}
            return {'status': 'passed', 'clock': clock, 'flows': [flow],
                    'flow_identity': {'format': 'u32be-id-echo-v1', 'connections': [connection]},
                    'flow_credit': [{'outstanding_payload_cap': cap, 'max_outstanding_upper_bound': cap // 2,
                                     'steady_tcp_info_edges': edges}],
                    'paced_records': {'aggregate_offered_mbit_s': 90.0, 'fully_written_records': 1, 'started_records': 1,
                                      'scheduled_records': 1, 'fully_read_records': 1, 'partial_receive_bytes': 0,
                                      'first_write_to_complete_read': {}, 'scheduled_offer_to_complete_read': {},
                                      'per_flow': [timing]}}

        a, b = endpoint(524288, True), endpoint(524288, False)
        result = matrix.compare_probes(a, b, 'forward', paced=True, flow_count=1, credit=524288)
        self.assertEqual(result['a_to_b']['per_flow'][0]['steady_retransmitted_segments'], 2)
        with self.assertRaisesRegex(Exception, 'credit policy mismatch'):
            matrix.compare_probes(a, b, 'forward', paced=True, flow_count=1)

    def test_parallel_dry_run_requires_exact_carrier_prefix_and_disjoint_cpu_lane(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = row()
            (root / 'plan.json').write_text(json.dumps({'version': 1, 'backend': 'common_records_v2', 'catalog': [value['expected_descriptor_hex']]}))
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'version': 1, 'rows': [value]}))
            base = ['--manifest', str(manifest), '--binary', '/unused-binary', '--output', str(root / 'output')]
            with patch.object(matrix.os, 'sched_getaffinity', return_value=set(range(32))), patch.object(matrix.os, 'sched_setaffinity') as changed:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(matrix.main([*base, '--parallel-lane', 'udp', '--lab-id', 'cm-udp',
                                                  '--native-tun-txqueuelen', '640', '--native-forward-tun-maxrate-mbit', '82']), 0)
                plan = json.loads(output.getvalue())
                self.assertEqual(plan['cpu_affinity'], list(range(8)))
                self.assertEqual(plan['requested_native_tun_txqueuelen'], 640)
                self.assertEqual(plan['requested_native_forward_tun_maxrate_mbit'], 82)
                changed.assert_not_called()
                self.assertFalse((root / 'output').exists())
                with self.assertRaisesRegex(ValueError, 'only its carrier'):
                    matrix.main([*base, '--parallel-lane', 'quic', '--lab-id', 'cm-quic'])
                with self.assertRaisesRegex(ValueError, 'distinct'):
                    matrix.main([*base, '--parallel-lane', 'udp', '--lab-id', 'cm-raw'])
            with patch.object(matrix.os, 'sched_getaffinity', return_value={0, 1}):
                with self.assertRaisesRegex(ValueError, 'CPU set unavailable'):
                    matrix.main([*base, '--parallel-lane', 'udp', '--lab-id', 'cm-udp'])

    def test_current_cli_roles_and_offline_inspection_have_no_device_side_effect(self):
        value = row()
        for side in ('a', 'b'):
            actual = matrix.daemon_command(value, side, Path('/binary'), Path('/secrets'), Path('/inputs'))
            self.assertIn('--common-transaction-plan', actual)
            self.assertIn('--session-admission-key-file', actual)
            self.assertNotIn('--swift-transaction-plan', actual)
            offline = matrix.daemon_command(value, side, Path('/binary'), Path('/secrets'), Path('/inputs'), inspection=True)
            self.assertEqual(offline[1], 'inspect-common-transaction-plan')
            value['required_cli'][side] += ['--raw-mark', '305790977']
            filtered = matrix.daemon_command(value, side, Path('/binary'), Path('/secrets'), Path('/inputs'), inspection=True)
            self.assertNotIn('--raw-mark', filtered)
            for flag in ('--device', '--control-socket', '--session-admission-key-file'):
                self.assertNotIn(flag, offline)

    def test_capture_distribution_keeps_surface_direction_window_and_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            addresses = list(matrix.WAN.values())
            content = pcap([(1, ipv4(*addresses, 40)), (2, ipv4(*addresses, 100)), (3, ipv4(*reversed(addresses), 70))])
            path.write_bytes(content)
            value = observe.capture_summary(path, addresses, (2_000_000_000, 3_000_000_000))
            self.assertEqual(value['whole_capture']['a_to_b']['ip_bytes'], 140)
            self.assertEqual(value['whole_capture']['b_to_a']['ip_bytes'], 70)
            self.assertEqual(value['sample_window']['a_to_b']['ip_bytes'], 100)
            self.assertEqual(value['sample_window']['b_to_a']['packets'], 0)
            self.assertEqual(value['whole_capture']['a_to_b']['p99_ip_packet_bytes'], 100)
            self.assertIn('not encapsulation-overhead', value['definition'])
            path.write_bytes(content[:-1])
            with self.assertRaisesRegex(ValueError, 'truncated pcap bytes'):
                observe.capture_summary(path, addresses)

    def test_sampled_tcp_sack_matches_direction_extent_and_wrapped_sequence(self):
        addresses = list(matrix.NATIVE.values())
        packet = bytearray(ipv4(*reversed(addresses), 60))
        packet[32:34] = bytes((10 << 4, 0x10))
        packet[40:] = bytes((1, 1, 5, 18)) + struct.pack('!IIII', 0xfffffff8, 8, 100, 180)
        invalid = bytearray(packet)
        invalid[43] = 19
        fragment = bytearray(packet)
        fragment[6] = 0x20
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'acks.pcap'
            path.write_bytes(pcap([(1, packet), (2, packet), (2, invalid), (2, fragment)]))
            sample = observe.capture_summary(path, addresses, (2_000_000_000, 3_000_000_000))['sample_window']
        self.assertEqual(sample['observed_ipv4_tcp_ack_options']['a_to_b'], {})
        self.assertEqual(sample['observed_ipv4_tcp_ack_options']['b_to_a'], {
            'ack_packets': 2, 'acks_with_sack': 1, 'first_block_1_to_64_bytes': 1,
            'first_block_16_bytes': 1, 'malformed_options': 1, 'unparsed_fragments': 1})

    def test_capture_missing_or_dropped_counts_never_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.log'
            path.write_text('1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n')
            self.assertEqual(observe.capture_counters(path), {'captured': 1, 'filtered': 1, 'dropped': 0})
            path.write_text('3 packets captured\n3 packets received by filter\n1 packets dropped by kernel\n')
            with self.assertRaisesRegex(ValueError, 'drops'):
                observe.capture_counters(path)
            path.write_text('3 packets captured\n')
            with self.assertRaisesRegex(ValueError, 'missing'):
                observe.capture_counters(path)

    def test_wire_metrics_invalid_overflow_totals_and_boundary_refuse(self):
        def metric(size):
            return {'histogram': [[size, 3]], 'samples': 3, 'total_bytes': size * 3, 'p50': size, 'p95': size, 'p99': size}
        value = {'schema': 1, 'invalid_samples': 0, 'counter_overflow': 0, 'fragmented_records': 0, 'diagnostic_heap_bytes': 48000,
                 'accepted_classes': dict(swift_source=0, direct_arq_source=2, systematic_fec_source=0, repair=0, recovery_feedback=1, unreliable_native=0),
                 'accepted_boundaries': dict(socket_accepted=0, tls_stream_flushed=3, quic_datagram_accepted=0),
                 'algorithm_bytes': metric(100), 'final_record_bytes': metric(121), 'record_overhead_bytes': metric(21)}
        self.assertEqual(observe.validate_wire_metrics(value, 'tls')['accepted_records'], 3)
        for field in ('invalid_samples', 'counter_overflow'):
            malformed = {**value, field: 1}
            with self.assertRaises(ValueError):
                observe.validate_wire_metrics(malformed, 'tls')
        with self.assertRaisesRegex(ValueError, 'boundary'):
            observe.validate_wire_metrics(value, 'quic')
        value['final_record_bytes']['total_bytes'] += 1
        with self.assertRaisesRegex(ValueError, 'totals'):
            observe.validate_wire_metrics(value, 'tls')

    def test_probe_failure_classification_is_preserved(self):
        self.assertEqual(matrix.failure_status(matrix.OutcomeError('bound_exhausted', 'original deadline')), 'bound_exhausted')
        self.assertEqual(matrix.failure_status(matrix.OutcomeError('tool_failure', 'missing capture')), 'tool_failure')

    def test_explicit_flow_identity_survives_shuffled_accept_order_and_rejects_duplicates(self):
        pairs = [socket.socketpair() for _ in range(probe.FLOWS)]
        try:
            for identity, (client, _) in enumerate(pairs):
                client.sendall(identity.to_bytes(4, 'big'))
            accepted_order = [7, 1, 15, 0, 5, 2, 4, 3, 12, 6, 11, 8, 10, 9, 14, 13]
            seen, ordered, metadata = set(), [None] * probe.FLOWS, []
            for accepted in accepted_order:
                identity = probe.identify_stream(pairs[accepted][1], None, seen, time.monotonic_ns() + 1_000_000_000)
                ordered[identity] = pairs[accepted][1]
                metadata.append(identity)
            self.assertEqual(metadata, accepted_order)
            self.assertEqual(ordered, [pair[1] for pair in pairs])
            for identity, (client, _) in enumerate(pairs):
                self.assertEqual(probe.exact_identity(client, time.monotonic_ns() + 1_000_000_000), identity)
            for identity in (7, probe.FLOWS):
                client, server = socket.socketpair()
                try:
                    client.sendall(identity.to_bytes(4, 'big'))
                    with self.assertRaisesRegex(ValueError, 'duplicate or out-of-range'):
                        probe.identify_stream(server, None, seen, time.monotonic_ns() + 1_000_000_000)
                finally:
                    client.close()
                    server.close()
        finally:
            for pair in pairs:
                for stream in pair:
                    stream.close()

    def test_probe_sigterm_preserves_original_deadline_and_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as port_owner:
            port_owner.bind(('127.0.0.1', 0))
            port = port_owner.getsockname()[1]
            port_owner.close()
            root = Path(directory)
            deadline = time.monotonic_ns() + 3_000_000_000
            process = subprocess.Popen([sys.executable, str(Path(probe.__file__)), 'listen', '--phase', 'forward',
                '--address', '127.0.0.1', '--port', str(port), '--deadline-ns', str(deadline),
                '--clock', str(root / 'clock.json'), '--result', str(root / 'result.json')],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(), 'Listening')
                process.terminate()
                stdout, stderr = process.communicate(timeout=2)
                self.assertEqual(process.returncode, 1, stderr)
                value = json.loads((root / 'result.json').read_text())
                self.assertEqual(value['original_deadline_ns'], deadline)
                self.assertEqual(value['status'], 'failed')
                self.assertEqual(value['error_type'], 'InterruptedError')
                self.assertIn('signal', value['error'])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                process.stdout.close()
                process.stderr.close()

    def test_actual_selector_transfer_preserves_one_way_and_simultaneous_hash_eof(self):
        for phase, paced in [*((name, False) for name in matrix.PHASES), ('forward', True)]:
            pairs = [socket.socketpair() for _ in range(2)]
            a, b = [pair[0] for pair in pairs], [pair[1] for pair in pairs]
            started = time.monotonic_ns() + 20_000_000
            clock = {'start_ns': started, 'measure_start_ns': started + 10_000_000, 'end_ns': started + 30_000_000}
            results, errors = [{}, {}], []
            def worker(index, streams, sending):
                try:
                    probe.transfer(streams, sending, clock, started + 2_000_000_000, results[index], paced=paced)
                except Exception as error:
                    errors.append(error)
            try:
                with patch.object(probe, 'tcp_info', return_value={}):
                    workers = [threading.Thread(target=worker, args=(0, a, phase != 'reverse')),
                               threading.Thread(target=worker, args=(1, b, phase != 'forward'))]
                    for worker_thread in workers:
                        worker_thread.start()
                    for worker_thread in workers:
                        worker_thread.join(3)
                        self.assertFalse(worker_thread.is_alive())
                self.assertEqual(errors, [])
                for sender, receiver in [(results[0], results[1]), (results[1], results[0])]:
                    for sent, received in zip(sender['flows'], receiver['flows']):
                        self.assertEqual(sent['sent'], received['received'])
                        self.assertEqual(sent['sent_sha256'], received['received_sha256'])
                        self.assertTrue(sent['write_closed'] and received['eof'])
                inactive = results[1] if phase == 'forward' else results[0]
                if phase != 'simultaneous':
                    self.assertEqual(sum(flow['sent'] for flow in inactive['flows']), 0)
                    for flow in inactive['flows']:
                        self.assertLessEqual(flow['peer_eof_ns'], flow['write_closed_ns'])
                if paced:
                    written = results[0]['paced_records']['fully_written_records']
                    received = results[1]['paced_records']
                    self.assertGreater(written, 0)
                    self.assertEqual(received['fully_read_records'], written)
                    self.assertEqual(received['first_write_to_complete_read']['count'], written)
                    self.assertLessEqual(received['first_write_to_complete_read']['p99_ms'],
                                         received['scheduled_offer_to_complete_read']['p99_ms'])
                    self.assertEqual(received['partial_receive_bytes'], 0)
            finally:
                for stream in a + b:
                    stream.close()

    def test_passive_probe_keeps_write_half_open_through_postwindow_data(self):
        now = time.monotonic_ns()
        clock = dict(start_ns=now - 3, measure_start_ns=now - 2, end_ns=now - 1)
        result = {}
        peer, receiver = socket.socketpair()
        with peer, receiver:
            peer.sendall(b'bytes still draining')
            peer.shutdown(socket.SHUT_WR)
            with patch.object(probe, 'tcp_info', return_value={}):
                probe.transfer([receiver], False, clock, now + 2_000_000_000, result)
            flow, = result['flows']
            self.assertEqual(flow['postwindow'], len(b'bytes still draining'))
            self.assertLessEqual(flow['peer_eof_ns'], flow['write_closed_ns'])
            self.assertEqual(peer.recv(1), b'')

    def test_c48_slots_timestamps_and_partial_io(self):
        clock = dict(start_ns=1000, end_ns=100_001_000)
        writer = probe.c48.RecordFlow(7, 16, clock)
        reader = probe.c48.RecordFlow(7, 16, clock)
        due = writer.due_ns(0)
        self.assertFalse(writer.offer(due - 1, probe.BLOCK))
        record = writer.offer(due + 10, probe.BLOCK)
        writer.accepted(7)
        self.assertEqual(writer.offer(due + 40, probe.BLOCK), record[7:])
        writer.accepted(505)
        reader.receive(record[:30], due + 40)
        reader.receive(record[30:], due + 55)
        self.assertEqual(list(reader.delivery), [45])
        self.assertEqual(list(reader.scheduled_delivery), [55])
        self.assertFalse(writer.offer(clock['end_ns'], probe.BLOCK))
        with self.assertRaises(ValueError):
            reader.receive(record, due + 90)


if __name__ == '__main__':
    unittest.main()
