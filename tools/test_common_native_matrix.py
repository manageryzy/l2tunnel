#!/usr/bin/env python3
"""Unprivileged contract checks for the Common native matrix harness."""
import argparse
from contextlib import redirect_stdout
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


def pcap(packets):
    value = bytearray(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 2048, 101))
    for second, packet in packets:
        value += struct.pack('<IIII', second, 0, len(packet), len(packet)) + packet
    return bytes(value)


class MatrixTests(unittest.TestCase):
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
                    self.assertEqual(matrix.main([*base, '--parallel-lane', 'udp', '--lab-id', 'cm-udp']), 0)
                self.assertEqual(json.loads(output.getvalue())['cpu_affinity'], list(range(8)))
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

    def test_capture_missing_or_dropped_counts_never_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.log'
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
        for phase in matrix.PHASES:
            pairs = [socket.socketpair() for _ in range(2)]
            a, b = [pair[0] for pair in pairs], [pair[1] for pair in pairs]
            started = time.monotonic_ns() + 20_000_000
            clock = {'start_ns': started, 'measure_start_ns': started + 10_000_000, 'end_ns': started + 30_000_000}
            results, errors = [{}, {}], []
            def worker(index, streams, sending):
                try:
                    probe.transfer(streams, sending, clock, started + 2_000_000_000, results[index])
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
            finally:
                for stream in a + b:
                    stream.close()


if __name__ == '__main__':
    unittest.main()
