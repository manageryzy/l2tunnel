"""Strict native-drain acceptance and loopback-only proofs; no namespaces or root."""
import contextlib
import copy
import errno
import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from . import openvpn_drain_native_smoke as h


def response(duplex='half', side='a', closed=False):
    binding = ({'kind': 'full', 'session': [1] * 16, 'config': [2] * 32} if duplex == 'full'
               else {'kind': 'paired', 'pair': [3] * 32, 'configs': [[4] * 32, [5] * 32]})
    def fence(n): return {'packets': n, 'native_bytes': n * 100, 'sources': n * 2, 'source_bytes': n * 120}
    local, peer = (fence(3), fence(4)) if side == 'a' else (fence(4), fence(3))
    def lane(sent, received):
        return {'admitted_sources': sent, 'consumed_sources': received, 'admitted_datagrams': 30,
                'admitted_ip_bytes': 1000, 'transmitted_datagrams': 30, 'tls_messages': 9}
    lanes = (lane(local['sources'], peer['sources']) if duplex == 'full' else
             ([lane(local['sources'], 0), lane(0, peer['sources'])] if side == 'a'
              else [lane(0, peer['sources']), lane(local['sources'], 0)]))
    terminal = {'kind': 'closed', 'report': {'local': local, 'peer': peer,
               'carrier': {'kind': 'full' if duplex == 'full' else 'paired', 'lanes': lanes}}} if closed else None
    accepted = closed and side == 'a'
    return {'version': 1, 'ok': True, 'code': 'ok', 'state': {'epoch': 1,
            'phase': 'terminal' if closed else 'running', 'compression': 'off', 'openvpn_drain': {
                'binding': binding, 'drain_accepted': accepted, 'terminal': terminal}}}


@contextlib.contextmanager
def local_server(raw, count=1, inspect=None):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'api.sock'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path)); path.chmod(0o600); server.listen(4); server.settimeout(3)
        failures, requests = [], []
        def run():
            try:
                for _ in range(count):
                    stream, _ = server.accept()
                    with stream:
                        stream.settimeout(2)
                        prefix = stream.recv(4)
                        length, = struct.unpack('!I', prefix)
                        data = bytearray()
                        while len(data) < length: data.extend(stream.recv(length - len(data)))
                        requests.append(h.strict_json(data))
                        if inspect: inspect()
                        stream.sendall(raw)
            except Exception as error: failures.append(error)
            finally: server.close()
        thread = threading.Thread(target=run)
        thread.start()
        try: yield path, requests
        finally:
            thread.join(4)
            if thread.is_alive(): raise AssertionError('loopback API worker did not exit')
            if failures: raise failures[0]


def framed(value):
    raw = json.dumps(value).encode()
    return struct.pack('!I', len(raw)) + raw


class ParserTests(unittest.TestCase):
    def test_full_and_paired_exact_cross_peer_proofs(self):
        for duplex in ('half', 'full'):
            values = {side: response(duplex, side, True) for side in ('a', 'b')}
            self.assertEqual(set(h.verify_closures(values, duplex)), {'a', 'b'})

    def test_acceptance_not_terminal_and_peer_local_request_not_allowed(self):
        values = {s: response(side=s, closed=True) for s in ('a', 'b')}
        values['a'] = response()
        with self.assertRaises(ValueError): h.verify_closures(values, 'half')
        values['a'] = response(closed=True)
        values['b']['state']['openvpn_drain']['drain_accepted'] = True
        with self.assertRaises(ValueError): h.verify_closures(values, 'half')

    def test_rejects_mismatched_binding_prefix_cardinality_and_direction(self):
        for mutate in (
            lambda x: x['b']['state']['openvpn_drain']['binding']['pair'].__setitem__(0, 9),
            lambda x: x['b']['state']['openvpn_drain']['terminal']['report']['peer'].__setitem__('native_bytes', 9),
            lambda x: x['a']['state']['openvpn_drain']['terminal']['report']['carrier']['lanes'].pop(),
            lambda x: x['a']['state']['openvpn_drain']['terminal']['report']['carrier']['lanes'].reverse(),
        ):
            values = {s: response(side=s, closed=True) for s in ('a', 'b')}
            mutate(values)
            with self.assertRaises(ValueError): h.verify_closures(values, 'half')

    def test_unknown_duplicate_boolean_integer_and_nonfinite_fields_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError): h.strict_json(raw)
        for mutate in (
            lambda v: v.__setitem__('extra', 1),
            lambda v: v.__setitem__('version', True),
            lambda v: v['state'].__setitem__('active', None),
            lambda v: v['state']['openvpn_drain']['binding']['pair'].__setitem__(0, True),
            lambda v: v['state']['openvpn_drain'].__setitem__('extra', 1),
            lambda v: v['state']['openvpn_drain']['terminal']['report']['local'].__setitem__('packets', 2**64),
        ):
            value = response(closed=True); mutate(value)
            with self.assertRaises(ValueError): h.validate_snapshot(value, 'half')

    def test_failed_diagnostic_bytes_and_cancelled_are_strict(self):
        value = response(closed=True)
        snap = value['state']['openvpn_drain']
        snap['terminal'] = {'kind': 'cancelled'}
        self.assertEqual(h.validate_snapshot(value, 'half')['terminal']['kind'], 'cancelled')
        snap['terminal']['extra'] = 1
        with self.assertRaises(ValueError): h.validate_snapshot(value, 'half')
        progress = {key: 0 for key in h.PROGRESS_FIELDS}
        progress.update(accepted={k: 0 for k in h.FENCE_FIELDS}, admission_in_flight=False)
        snap['terminal'] = {'kind': 'failed', 'error': {'kind': 'timed_out', 'raw_os_error': 110,
                            'diagnostic': 'é' * 256}, 'progress': progress}
        h.validate_snapshot(value, 'half')
        snap['terminal']['error']['diagnostic'] += 'x'
        with self.assertRaises(ValueError): h.validate_snapshot(value, 'half')

    def test_phase_and_retry_terminal_race_exact_schema(self):
        value = response()
        snap = value['state']['openvpn_drain']; snap['drain_accepted'] = True
        value['state']['phase'] = 'drain_accepted'
        for code in ('accepted', 'already_accepted'):
            value['code'] = code; h.validate_snapshot(value, 'half')
        value = response(closed=True); value.update(ok=False, code='closed')
        h.validate_snapshot(value, 'half')
        value['state']['phase'] = 'running'
        with self.assertRaises(ValueError): h.validate_snapshot(value, 'half')

    def test_actual_tuple_parser_avoids_pid_or_port_substring_matches(self):
        table = 'header\n 0: 0100007F:5F78 00000000:0000 07 0:0 00:0 0 1000 0 77 2\n'
        self.assertEqual(h.parse_udp_table(table), [('127.0.0.1', 24440, 77)])
        self.assertNotEqual(h.parse_udp_table(table)[0][:2], ('127.0.0.1', 2444))
        with self.assertRaises(ValueError): h.parse_udp_table('h\ninvalid')
        with self.assertRaises(ValueError): h.parse_udp_table('x' * (1024 * 1024 + 1))


class BoundTests(unittest.TestCase):
    def test_global_cap_and_conservative_per_endpoint_grace_never_reset(self):
        self.assertEqual(h.proof_deadline(112, 101), 106)
        self.assertEqual(h.proof_deadline(112, 110), 112)
        self.assertEqual(h.remaining(112, 2, clock=lambda: 111.5), .5)
        with self.assertRaises(TimeoutError): h.remaining(112, 2, clock=lambda: 112)
        # First terminal at 105.9 still leaves only 0.1 s, not a renewed five seconds.
        self.assertAlmostEqual(h.remaining(h.proof_deadline(112, 101), 2, clock=lambda: 105.9), .1)

    def test_cleanup_attempts_every_owner_after_error(self):
        seen = []
        def failed(): seen.append('first'); raise RuntimeError('first removal failed')
        errors = h.cleanup_all([('first', failed), ('second', lambda: seen.append('second')),
                                ('journal', lambda: seen.append('journal'))])
        self.assertEqual(seen, ['first', 'second', 'journal'])
        self.assertEqual(errors, [{'step': 'first', 'error': 'first removal failed'}])

    def test_dry_run_no_files_or_mutations_and_exact_native_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'never-created'
            with patch.object(h.netns_lab, 'apply', side_effect=AssertionError('mutation')), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(h.main(['--layer', 'tun', '--duplex', 'half', '--output', str(output)]), 0)
            self.assertFalse(output.exists())
            value = json.loads(out.getvalue())
            self.assertEqual(value['status'], 'dry_run')
            self.assertEqual(value['plan']['bounds_seconds']['observation'], 12)
            for argv in value['plan']['daemon_commands'].values():
                self.assertEqual(argv[argv.index('--openvpn-close-profile') + 1], 'native-drain')
                self.assertEqual(argv[argv.index('--openvpn-drain-timeout-ms') + 1], '5000')
                self.assertIn('--udp-reverse-bind', argv)
                self.assertNotIn('--remote', argv); self.assertNotIn('--listen', argv)
            with self.assertRaises(ValueError): h.case_plan('unit', 'vxlan', 'half')

    def test_partial_setup_rollback_receipt_never_claims_cleanup_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = h.case_plan('unit', 'tun', 'half')
            receipt = h.native.CaseEvidence(root / 'receipt.json', plan['case'])
            def incomplete_setup(*args):
                (root / 'unit.json').write_text('{"retained":"owned rollback"}')
                raise RuntimeError('setup and its authoritative rollback failed')
            with patch.object(h.shared, 'bounded_lab', side_effect=incomplete_setup):
                value = h.run_case(plan, root / 'binary', root / 'helper', root, root, root, receipt)
            self.assertEqual(value['status'], 'failed')
            self.assertEqual(value['cleanup'], 'failed')
            self.assertEqual(value['completed']['stages']['namespace_setup'], 'failed')
            self.assertEqual(value['completed']['stages']['native_drain'], 'unrun')
            self.assertTrue((root / 'unit.json').exists())
            self.assertEqual(value['cleanup_errors'][0]['step'], 'partial-setup-journal')

    def test_unjournaled_namespace_after_failed_add_is_retained_and_fails_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            netns = root / 'netns'; netns.mkdir()
            plan = h.case_plan('unit', 'tun', 'half')
            receipt = h.native.CaseEvidence(root / 'receipt.json', plan['case'])
            residual = netns / plan['namespaces']['endpoint_a']
            def failed_after_creation(*args):
                # Simulate successful kernel/name creation, then command timeout,
                # before authoritative netns_lab records identity in its journal.
                residual.write_text('unaccounted namespace name')
                raise TimeoutError('ip netns add timed out after side effect')
            with patch.object(h.netns_lab, 'NETNS_DIRECTORY', netns), patch.object(h.shared, 'bounded_lab', side_effect=failed_after_creation) as apply:
                value = h.run_case(plan, root / 'binary', root / 'helper', root, root, root, receipt)
            self.assertEqual(apply.call_count, 1)  # Never attempt cleanup/adoption by this name.
            self.assertFalse((root / 'unit.json').exists())
            self.assertTrue(residual.exists())
            self.assertEqual(value['status'], 'failed')
            self.assertEqual(value['cleanup'], 'failed')
            self.assertEqual(value['cleanup_errors'][0]['step'], 'unaccounted-namespace-residual')
            changes = value['completed']['unaccounted_namespace_changes']
            self.assertEqual(set(changes), {residual.name})
            self.assertIsNone(changes[residual.name]['before'])
            self.assertIsNotNone(changes[residual.name]['after'])

    def test_namespace_observation_does_not_follow_or_adopt_existing_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = h.netns_lab.LabSpec('unit')
            path = root / spec.namespaces['router']
            path.symlink_to('/missing-untrusted-target')
            with patch.object(h.netns_lab, 'NETNS_DIRECTORY', root):
                before = h.namespace_observation(spec)
                self.assertIsNotNone(before[path.name])
                self.assertEqual(h.namespace_changes(before, h.namespace_observation(spec)), {})
                path.unlink(); path.write_text('different object')
                changes = h.namespace_changes(before, h.namespace_observation(spec))
            self.assertEqual(set(changes), {path.name})
            self.assertTrue(path.exists())

    def test_exclusive_atomic_receipt_keeps_previous_version_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            receipt = h.native.CaseEvidence(path, 'test')
            receipt.record('complete', {'ok': True})
            before = path.read_bytes()
            with patch.object(h.native.os, 'replace', side_effect=OSError('disk failure')):
                with self.assertRaises(OSError): receipt.record('uncommitted', {})
            self.assertEqual(path.read_bytes(), before)
            self.assertNotIn('uncommitted', receipt.value['completed'])
            with self.assertRaises(FileExistsError): h.native.CaseEvidence(path, 'overwrite')


class SocketProofTests(unittest.TestCase):
    def test_real_private_rpc_uses_wire_action_and_strict_size(self):
        value = response(closed=True)
        with local_server(framed(value)) as (path, requests):
            actual = h.rpc(path, 'drain_open_vpn', time.monotonic() + 2, h.socket_identity(path))
        self.assertEqual(actual, value)
        self.assertEqual(requests, [{'version': 1, 'action': {'command': 'drain_open_vpn'}}])
        for raw in (struct.pack('!I', 8193), struct.pack('!I', 2) + b'{', struct.pack('!I', 13) + b'{"x":1,"x":2}'):
            with local_server(raw) as (path, _):
                with self.assertRaises(ValueError): h.rpc(path, 'status', time.monotonic() + 2)

    def test_private_socket_replacement_and_modes_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'socket'
            path.write_text('not a socket')
            with self.assertRaises(ValueError): h.socket_identity(path)
            path.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.bind(str(path)); path.chmod(0o600)
                identity = h.socket_identity(path)
                path.chmod(0o666)
                with self.assertRaises(ValueError): h.socket_identity(path)
                path.chmod(0o600)
                identity['ino'] += 1
                with self.assertRaises(ValueError): h.rpc(path, 'status', time.monotonic() + 1, identity)

    def test_original_udp_owner_is_rejected_before_any_rebind(self):
        identity = h.process_identity(os.getpid())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1', 0)); tuples = [list(udp.getsockname())]
            self.assertEqual(len(h.udp_owned(identity, tuples)), 1)
            with self.assertRaisesRegex(ValueError, 'remain owned'):
                h.prove_released(identity, tuples, '/unused', {}, {}, 'full', time.monotonic() + 2)

    def test_both_plain_udp_probes_retained_through_final_immutable_status(self):
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        for stream in sockets: stream.bind(('127.0.0.1', 0))
        tuples = [list(stream.getsockname()) for stream in sockets]
        for stream in sockets: stream.close()
        checked = []
        def inspect():
            for address, port in tuples:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    with self.assertRaises(OSError) as error: probe.bind((address, port))
                    self.assertEqual(error.exception.errno, errno.EADDRINUSE)
                    checked.append(port)
        value = response(closed=True)
        with local_server(framed(value), inspect=inspect) as (path, _):
            proof = h.prove_released(h.process_identity(os.getpid()), tuples, path, h.socket_identity(path),
                                    value['state']['openvpn_drain'], 'half', time.monotonic() + 2)
        self.assertEqual(proof['simultaneous_binds'], tuples)
        self.assertEqual(checked, [item[1] for item in tuples])
        for address, port in tuples:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe: probe.bind((address, port))

    def test_rebind_failure_closes_previously_created_probe(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
            first.bind(('127.0.0.1', 0)); second.bind(('127.0.0.1', 0))
            tuples = [list(first.getsockname()), list(second.getsockname())]
            first.close()
            # Simulate other-owner occupancy: exact bind remains authoritative after PID inspection.
            with patch.object(h, 'udp_owned', return_value=[]):
                with self.assertRaises(OSError): h.prove_released(h.process_identity(os.getpid()), tuples, '/unused', {}, {}, 'half', time.monotonic() + 2)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe: probe.bind(tuple(tuples[0]))


class ObserverTests(unittest.TestCase):
    def exercise(self, proof_fails=False, exit_code=0):
        requested, peer_proved = threading.Event(), threading.Event()
        order, proof_ends, waits = [], [], []
        guard = threading.Lock()
        class Process:
            def poll(self): return None
            def wait(self, timeout):
                waits.append(timeout)
                return exit_code
        def rpc(path, action, deadline, identity=None):
            side = Path(path).stem
            if action == 'drain_open_vpn':
                already = requested.is_set()
                requested.set()
                value = response(side='a')
                value['code'] = 'already_accepted' if already else 'accepted'
                value['state']['phase'] = 'drain_accepted'
                value['state']['openvpn_drain']['drain_accepted'] = True
                return value
            closed = requested.is_set() and (side == 'b' or peer_proved.is_set())
            value = response(side=side, closed=closed)
            if side == 'a' and requested.is_set() and not closed:
                value['state']['phase'] = 'drain_accepted'
                value['state']['openvpn_drain']['drain_accepted'] = True
            return value
        def command(argv, deadline, cap):
            value = h.strict_json(argv[-1])
            side = Path(value['path']).stem
            with guard:
                order.append(side)
                proof_ends.append(deadline)
            if side == 'b': peer_proved.set()
            if proof_fails: raise TimeoutError('original grace exhausted')
            return json.dumps({'side': side, 'deadline': deadline})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = h.native.CaseEvidence(root / 'receipt.json', 'unit')
            with patch.object(h, 'rpc', side_effect=rpc), patch.object(h, 'command', side_effect=command), patch.object(h, 'socket_identity', return_value={'ino': 1}):
                operation = lambda: h.drain_observation(h.case_plan('unit', 'tun', 'half'), Path('/binary'), Path('/helper'), root, root,
                                                      {'a': Process(), 'b': Process()}, {'a': {}, 'b': {}}, receipt)
                if proof_fails or exit_code:
                    with self.assertRaises(RuntimeError): operation()
                else:
                    operation()
            value = copy.deepcopy(receipt.value)
        return order, proof_ends, waits, value

    def test_peer_proof_does_not_wait_for_other_endpoint_terminal(self):
        order, ends, waits, value = self.exercise()
        self.assertEqual(order, ['b', 'a'])
        self.assertEqual(len(waits), 2)
        global_end = value['completed']['first_action']['deadline']
        self.assertTrue(all(end <= global_end for end in ends))
        for side, observed in value['completed']['terminals'].items():
            proof = value['completed']['socket_proofs'][side]
            self.assertLessEqual(proof['deadline'], observed['last_nonterminal_query_start'] + 5)
        self.assertEqual(value['completed']['observer_join']['alive'], [])

    def test_proof_timeout_remains_failure_and_keeps_partial_terminal(self):
        _, _, waits, value = self.exercise(proof_fails=True)
        self.assertEqual(waits, [])
        self.assertIn('terminals', value['completed'])
        self.assertIn('observer_errors', value['completed'])
        self.assertNotIn('drain_complete', value['completed'])
        self.assertEqual(value['completed']['observer_join']['alive'], [])

    def test_signal_exit_is_never_a_clean_case(self):
        _, _, _, value = self.exercise(exit_code=-15)
        self.assertNotIn('drain_complete', value['completed'])
        self.assertEqual(value['completed']['daemon_exit_codes']['a'], -15)


if __name__ == '__main__': unittest.main()
