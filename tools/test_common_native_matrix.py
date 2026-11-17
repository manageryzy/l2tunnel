#!/usr/bin/env python3
"""Unprivileged contract checks for the Common native matrix harness."""
import argparse
from contextlib import redirect_stdout
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
