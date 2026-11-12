"""Measured native acceptance validators and kernel loopback probes; no root/labs."""
import contextlib
import copy
import hashlib
import io
import json
import os
import selectors
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from . import proxy_measured_native_smoke as h
from . import test_proxy_native_smoke as fixtures


def wait_ready_line(child, deadline):
    """Read one bounded readiness line within an original monotonic deadline."""
    output = bytearray()
    with selectors.DefaultSelector() as ready:
        ready.register(child.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not ready.select(remaining):
                raise TimeoutError('pressure helper readiness deadline expired')
            byte = os.read(child.stdout.fileno(), 1)
            if not byte:
                raise RuntimeError('pressure helper exited before readiness')
            output.extend(byte)
            if len(output) > 128:
                raise ValueError('pressure helper readiness line exceeds bound')
            if byte == b'\n':
                return output.decode('utf-8').strip()


def stop_child(child):
    """Kill and reap even a silent helper after readiness or assertion failure."""
    if child.poll() is None:
        child.kill()
    child.communicate(timeout=2)
    child.stdout.close()
    child.stderr.close()


def snapshot(side='a', phase='Forwarding', terminal=False, lanes=1):
    value = fixtures.snapshot(phase, terminal, lanes)
    value['state']['proxy']['measured'] = {
        'capabilities': {'requested': 'measured-relay-v1', 'effective': 'measured-relay-v1',
            'lanes': 'full' if lanes == 1 else 'half', 'requested_carrier': 'tcp_tls',
            'effective_carrier': 'tcp_tls', 'requested_udp_cover': 'not_applicable',
            'effective_udp_cover': 'not_applicable', 'measured_relay_targets': True,
            'exact_tcp_rwnd_control': False, 'native_tcp_rtt': False, 'native_tcp_cwnd': False,
            'native_window_qualified': False, 'hot_reload': False, 'flow_paging': False},
        'aggregate': {**{key: 0 for key in h.AGGREGATE_FIELDS - h.AGGREGATE_BOOLS},
            **{key: False for key in h.AGGREGATE_BOOLS},
            'at_micros': 100000, 'authoritative_at_micros': 100000, 'revision': 4,
            'active_flows': 2, 'demanding_flows': 2,
            'ack_rate': {'bytes': 65536, 'elapsed_micros': 10000, 'bytes_per_second': 6553600,
                         'bins': 2, 'latest_at_micros': 90000},
            'service_latency': {'smoothed_micros': 1000, 'admitted_at_micros': 80000,
                                'reply_at_micros': 81000, 'fresh': True},
            'applied': {'revision': 3, 'phase': 'probing', 'candidate_bytes': 65536,
                        'candidate_records': 64, 'reserved_bytes': 262144, 'reserved_records': 256},
            'admitted_by_kind': [4, 2, 2], 'receiver_pressure': True}}
    return value


def window_packet(source, destination, sport, dport, flags, window, ack=0, scale=None):
    raw = bytearray(fixtures.ip_packet(source, destination, sport, dport, flags=flags))
    offset = 20 if ':' not in source else 40
    options = b'' if scale is None else bytes([3, 3, scale, 0])
    tcp = bytearray(raw[offset:] + options)
    tcp[8:12] = ack.to_bytes(4, 'big')
    tcp[12] = (len(tcp) // 4) << 4
    tcp[14:16] = window.to_bytes(2, 'big')
    tcp[16:18] = b'\0\0'
    src, dst = fixtures.ipaddress.ip_address(source), fixtures.ipaddress.ip_address(destination)
    pseudo = (src.packed + dst.packed + bytes([0, 6]) + struct.pack('!H', len(tcp))
              if src.version == 4 else src.packed + dst.packed + struct.pack('!I', len(tcp)) + bytes([0, 0, 0, 6]))
    tcp[16:18] = fixtures.checksum(pseudo + tcp).to_bytes(2, 'big')
    header = raw[:offset]
    if src.version == 4:
        header[2:4] = (offset + len(tcp)).to_bytes(2, 'big')
        header[10:12] = b'\0\0'
        header[10:12] = fixtures.checksum(header).to_bytes(2, 'big')
    else:
        header[4:6] = len(tcp).to_bytes(2, 'big')
    return h.fixed.decode_ip(bytes(header + tcp))


def pressure_result(flow, role, start=1000):
    def anchor(mono):
        return {'before_mono_ns': mono - 200, 'realtime_ns': mono + 1_000_000_000_000 - 150,
                'after_mono_ns': mono - 100}
    ns = int(start * 1_000_000_000)
    return {'role': role, 'source': [flow['source'], flow['source_port']],
        'destination': [flow['destination'], flow['destination_port']],
        'sent_bytes': h.PRESSURE_BYTES, 'received_bytes': h.PRESSURE_BYTES,
        'sent_sha256': hashlib.sha256(h.payload(h.PRESSURE_BYTES, 11 if role == 'connect' else 29)).hexdigest(),
        'received_sha256': hashlib.sha256(h.payload(h.PRESSURE_BYTES, 29 if role == 'connect' else 11)).hexdigest(),
        'eof': True, 'effective_receive_buffer': 16384, 'effective_send_buffer': 16384,
        'clock': {'start': anchor(ns), 'release': anchor(ns + 2_000_000_000),
                  'end': anchor(ns + 4_000_001_000), 'began_mono_ns': ns,
                  'read_begin_mono_ns': ns + 2_000_000_000},
        'timing': {'began': start, 'send_begin': start + .01, 'read_begin': start + 2,
                   'send_complete': start + 3, 'ended': start + 4}}


class MeasuredNativeHarnessTests(unittest.TestCase):
    def test_dry_run_is_immutable_and_explicit_for_both_duplex_modes(self):
        for profile in ('clean', 'pressure'):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'new'
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream), patch.object(h.subprocess, 'run') as run:
                    self.assertEqual(h.main(['--output', str(output), '--profile', profile]), 0)
                self.assertFalse(output.exists())
                run.assert_not_called()
                value = json.loads(stream.getvalue())
                self.assertEqual(value['mutations'], 'none')
                self.assertEqual([c['lanes'] for c in value['cases']], [1, 2])
                for plan in value['cases']:
                    self.assertEqual(plan['profile'][1], 'proxy-measured')
                    self.assertEqual(plan['policy']['profile'], 'measured-relay-v1')
                    self.assertEqual(plan['policy']['fixed'], h.fixed.policy())
                    self.assertEqual(plan['policy']['fixed']['time_wait_reset'], 'maintained')
                    self.assertEqual(plan['clean_override']['loss_percent'], 0)
                    self.assertEqual(plan['bounds_seconds']['runtime_drain'], 120)
                    self.assertEqual(plan['pressure_probe']['dscp_weights'], [1, 1])
                self.assertEqual(h.fixed.case_plan('fixed', 'full')['profile'][1], 'proxy')

    def test_capture_allocation_is_explicit_pressure_wan_only(self):
        baseline = {'a_native': 8192, 'b_native': 8192, 'a_wan': 8192, 'b_wan': 8192}
        for mode in ('full', 'half'):
            clean = h.case_plan('unit', mode, 'clean')
            pressure = h.case_plan('unit', mode, 'pressure')
            self.assertEqual(clean['capture_packet_limits'], baseline)
            self.assertEqual(pressure['capture_packet_limits'],
                {**baseline, 'a_wan': 32768, 'b_wan': 32768})
            self.assertEqual(clean['bounds_seconds'], pressure['bounds_seconds'])
            self.assertEqual(h.fixed.validated_capture_limits(), baseline)
        with self.assertRaises(ValueError): h.capture_packet_limits('unknown')
        # Calling either plan never changes the fixed helper or measured native default.
        self.assertEqual(h.PACKET_LIMIT, 8192)
        self.assertEqual(h.fixed.PACKET_LIMIT, 8192)

    def test_timestamp_and_window_audits_use_selected_native_capture_limits(self):
        raw = fixtures.ip_packet('198.19.0.1', '198.19.0.2')
        limits = h.capture_packet_limits('pressure')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            path.write_bytes(fixtures.pcap([raw] * 3))
            with self.assertRaises(h.fixed.CaptureBound): h.timed_capture(path, 3)
            packets, timestamps, tick = h.timed_capture(path, 4)
            self.assertEqual((len(packets), len(timestamps), tick), (3, 3, 1000))
            paths = {name: path for name in limits}
            with patch.object(h, 'timed_capture', wraps=h.timed_capture) as read:
                self.assertEqual(h.audit_windows(paths, [], False, packet_limits=limits), [])
            self.assertEqual([call.args[1] for call in read.call_args_list], [8192, 8192])
            with patch.object(h, 'timed_capture') as read:
                with self.assertRaises(ValueError):
                    h.audit_windows(paths, [], False, packet_limits={'a_native': 32768})
                read.assert_not_called()

    def test_strict_plan_rejects_unsafe_names_and_conflicting_case_selection(self):
        for lab, mode, profile in [('../host', 'full', 'clean'), ('x' * 19, 'half', 'clean'),
                                    ('safe', 'bad', 'clean'), ('safe', 'full', 'unknown')]:
            with self.assertRaises(ValueError): h.case_plan(lab, mode, profile)
        with self.assertRaises(ValueError):
            h.main(['--output', '/tmp/no-create-measured', '--profile', 'clean', '--only-case', 'tun-half-pressure'])

    def test_apply_requires_original_build_before_creating_output_or_lab(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created'
            with patch.object(h.netns_lab, 'require_root'), patch.object(h.shutil, 'which', return_value='/tool'), \
                    patch.object(h.netns_lab, 'apply') as apply:
                with self.assertRaisesRegex(ValueError, 'build-receipt'):
                    h.main(['--output', str(output), '--apply'])
                apply.assert_not_called()
            self.assertFalse(output.exists())

    def test_policy_has_every_strict_version_one_field_and_bounded_geometry(self):
        policy = h.policy()
        self.assertLess(len(json.dumps(policy).encode()), 65536)
        self.assertEqual(set(policy), {'version', 'profile', 'fixed', 'allocation', 'ownership', 'observation', 'service'})
        self.assertEqual(len(policy['allocation']['target']), 12)
        self.assertEqual(len(policy['ownership']), 6)
        self.assertEqual(len(policy['observation']), 5)
        self.assertEqual(len(policy['service']), 5)
        self.assertEqual(policy['allocation']['target']['max_flows'], 16)
        self.assertLessEqual(4 * 1000, policy['observation']['report_interval_micros'])

    def test_copied_helpers_must_match_exact_build_and_actual_loaded_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            names = {'tools/proxy_measured_native_smoke.py': Path(h.__file__),
                     'tools/proxy_native_smoke.py': Path(h.fixed.__file__),
                     'tools/netns_lab.py': Path(h.netns_lab.__file__)}
            hashes = {}
            for name, path in names.items():
                copied = output / path.name; copied.write_bytes(path.read_bytes())
                hashes[name] = h.file_hash(copied)
            build = {'source_sha256_after': hashes}
            self.assertEqual(h.verify_copied_helpers(build, output), hashes)
            with self.assertRaises(ValueError): h.verify_copied_helpers(build, output, loaded=True)
            with patch.object(h, '__file__', str(output / 'proxy_measured_native_smoke.py')), \
                    patch.object(h.fixed, '__file__', str(output / 'proxy_native_smoke.py')), \
                    patch.object(h.netns_lab, '__file__', str(output / 'netns_lab.py')):
                h.verify_copied_helpers(build, output, loaded=True)
                (output / 'netns_lab.py').write_text('later helper substitution')
                with self.assertRaises(ValueError): h.verify_copied_helpers(build, output, loaded=True)
            with self.assertRaises(ValueError): h.verify_copied_helpers({'source_sha256_after': {}}, output)

    def test_launcher_execs_verified_copies_before_any_namespace_mutation(self):
        class ExecObserved(Exception):
            pass
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'new'
            binary = root / 'original'; binary.write_bytes(b'qualified test binary')
            names = {'tools/proxy_measured_native_smoke.py': Path(h.__file__),
                     'tools/proxy_native_smoke.py': Path(h.fixed.__file__),
                     'tools/netns_lab.py': Path(h.netns_lab.__file__)}
            hashes = {name: h.file_hash(path) for name, path in names.items()}
            build = {'status': 'passed', 'exit_code': 0, 'source_stable_during_build': True,
                'changed_during_build': [], 'source_sha256_before': hashes, 'source_sha256_after': hashes,
                'binary_sha256': h.file_hash(binary)}
            receipt = root / 'build.json'; receipt.write_text(json.dumps(build))
            with patch.object(h.netns_lab, 'require_root'), patch.object(h.shutil, 'which', return_value='/tool'), \
                    patch.object(h, 'source_hashes', return_value=hashes), \
                    patch.object(h.os, 'execve', side_effect=ExecObserved) as execute, \
                    patch.object(h.netns_lab, 'apply') as apply:
                with self.assertRaises(ExecObserved):
                    h.main(['--output', str(output), '--binary', str(binary),
                            '--build-receipt', str(receipt), '--apply'])
                apply.assert_not_called()
            args, env = execute.call_args.args[1:]
            self.assertEqual(args[1], str(output / 'proxy_measured_native_smoke.py'))
            self.assertIn('--frozen-worker', args)
            self.assertEqual(env['PYTHONDONTWRITEBYTECODE'], '1')
            self.assertFalse((output / 'receipt.json').exists())
            self.assertFalse((output / 'policy.json').exists())
            self.assertEqual(h.verify_copied_helpers(build, output), hashes)

    def test_existing_output_is_never_adopted_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'existing'; output.mkdir()
            sentinel = output / 'keep'; sentinel.write_text('owned elsewhere')
            with patch.object(h.netns_lab, 'require_root'), patch.object(h.shutil, 'which', return_value='/tool'), \
                    patch.object(h, 'verified_build_receipt', return_value={}), patch.object(h, 'run_case') as run:
                with self.assertRaises(FileExistsError):
                    h.main(['--output', str(output), '--apply', '--build-receipt', '/nonexistent/receipt'])
                run.assert_not_called()
            self.assertEqual(sentinel.read_text(), 'owned elsewhere')

    def test_capture_commands_and_failed_case_cleanup_share_profile_allocation(self):
        for profile in ('clean', 'pressure'):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                secrets = root / 'secrets'; secrets.mkdir(mode=0o700)
                plan = h.case_plan('unitlimits', 'half', profile)
                def child(*_):
                    process = unittest.mock.Mock(stderr=io.BytesIO())
                    process.poll.return_value = 0
                    return process
                with patch.object(h, 'bounded_lab'), patch.object(h, 'command', return_value=''), \
                        patch.object(h, 'offloads', return_value={}), \
                        patch.object(h, 'disable_underlay_ipv6', return_value={}), \
                        patch.object(h, 'start_capture', side_effect=child) as start, \
                        patch.object(h, 'finish_capture', return_value={}) as finish, \
                        patch.object(h, 'stop'), \
                        patch.object(h, 'launch', side_effect=h.fixed.CaptureBound('finite capture bound')), \
                        patch.object(h.netns_lab, 'NETNS_DIRECTORY', root / 'empty-netns'):
                    with self.assertRaises(RuntimeError):
                        h.run_case(plan, root / 'binary', root / 'harness', root, secrets, root / 'state')
                self.assertEqual(len(start.call_args_list), 4)
                limits = plan['capture_packet_limits']
                for call in start.call_args_list:
                    argv, log, _ = call.args
                    key = log.name.removesuffix('-capture.log')
                    self.assertEqual(int(argv[argv.index('-c') + 1]), limits[key])
                self.assertEqual({call.args[1].name.removesuffix('-capture.log'): call.args[2]
                                  for call in finish.call_args_list}, limits)
                receipt = json.loads((root / plan['case'] / 'receipt.json').read_text())
                self.assertEqual(receipt['status'], 'bound_exhausted')
                self.assertEqual(receipt['cleanup'], 'passed')
                self.assertEqual(receipt['plan']['capture_packet_limits'], limits)
        plan['capture_packet_limits']['a_native'] = 32768
        with patch.object(h, 'bounded_lab') as lab, self.assertRaisesRegex(ValueError, 'allocation differs'):
            h.run_case(plan, root / 'binary', root / 'harness', root, secrets, root / 'state')
        lab.assert_not_called()

    def test_partial_case_failure_cleans_only_the_same_owned_spec_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = h.case_plan('unitcleanup', 'half')
            operations = []
            def owned(operation, spec, state, deadline):
                operations.append((operation, spec.lab_id, state, deadline))
            with patch.object(h, 'bounded_lab', side_effect=owned), \
                    patch.object(h, 'disable_underlay_ipv6', side_effect=OSError('setup failed')), \
                    patch.object(h.netns_lab, 'NETNS_DIRECTORY', root / 'empty-netns'):
                with self.assertRaises(RuntimeError):
                    h.run_case(plan, root / 'binary', root / 'harness', root, root / 'secrets', root / 'state')
            self.assertEqual([item[0] for item in operations], [h.netns_lab.apply, h.netns_lab.cleanup])
            self.assertTrue(all(item[1] == plan['lab_id'] and item[2] == root / 'state' for item in operations))
            receipt = json.loads((root / plan['case'] / 'receipt.json').read_text())
            self.assertEqual(receipt['status'], 'tool_failure')
            self.assertEqual(receipt['cleanup'], 'passed')
            self.assertIn('setup failed', receipt['error'])

    def test_failed_case_socket_cleanup_requires_dead_children_and_exact_private_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / 'private'; private.mkdir(mode=0o700)
            path = private / 'proxy.sock'
            identity = private.stat()
            owners = {path: (identity.st_dev, identity.st_ino)}
            process = unittest.mock.Mock()
            with socket.socket(socket.AF_UNIX) as endpoint:
                endpoint.bind(str(path))
                process.poll.return_value = None
                with self.assertRaisesRegex(RuntimeError, 'remains live'):
                    h.cleanup_owned_sockets(owners, [process])
                self.assertTrue(path.exists())
                process.poll.return_value = -15
            self.assertEqual(h.cleanup_owned_sockets(owners, [process]), [str(path)])
            self.assertFalse(path.exists())
            self.assertEqual(h.cleanup_owned_sockets(owners, [process]), [])
            # A path replacement is not a socket we are authorized to unlink.
            path.write_text('preserve')
            with self.assertRaisesRegex(RuntimeError, 'non-socket'):
                h.cleanup_owned_sockets(owners, [process])
            self.assertEqual(path.read_text(), 'preserve')
            path.unlink()
            path.symlink_to(private / 'unrelated')
            with self.assertRaisesRegex(RuntimeError, 'non-socket'):
                h.cleanup_owned_sockets(owners, [process])
            self.assertTrue(path.is_symlink())

    def test_socket_cleanup_rejects_substituted_private_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / 'private'; private.mkdir(mode=0o700)
            path = private / 'proxy.sock'
            identity = private.stat()
            owners = {path: (identity.st_dev, identity.st_ino)}
            private.rename(root / 'old')
            private.mkdir(mode=0o700)
            with socket.socket(socket.AF_UNIX) as endpoint:
                endpoint.bind(str(path))
                with self.assertRaisesRegex(RuntimeError, 'identity'):
                    h.cleanup_owned_sockets(owners, [])
                self.assertTrue(path.exists())
            path.unlink()
            private.rmdir()
            private.symlink_to(root / 'old', target_is_directory=True)
            with self.assertRaises(OSError): h.cleanup_owned_sockets(owners, [])

    def test_status_strictness_capabilities_and_actual_observation_are_required(self):
        value = snapshot()
        h.validate_proxy_snapshot(value)
        for key, replacement in [('requested', 'fixed'), ('effective', None), ('native_tcp_rtt', True),
                                  ('native_tcp_cwnd', True), ('native_window_qualified', True), ('flow_paging', True)]:
            changed = copy.deepcopy(value)
            changed['state']['proxy']['measured']['capabilities'][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError): h.validate_proxy_snapshot(changed)
        for target in ['aggregate', 'capabilities']:
            changed = copy.deepcopy(value)
            changed['state']['proxy']['measured'][target]['unknown'] = 0
            with self.assertRaises(ValueError): h.validate_proxy_snapshot(changed)
        changed = copy.deepcopy(value); changed['state']['proxy']['measured']['aggregate']['revision'] = True
        with self.assertRaises(ValueError): h.validate_proxy_snapshot(changed)
        changed = copy.deepcopy(value); changed['state']['proxy']['measured']['aggregate']['ack_rate']['bytes'] = 2**128
        with self.assertRaises(ValueError): h.validate_proxy_snapshot(changed)
        changed = copy.deepcopy(value); changed['state']['proxy']['terminal'] = {'outcome': 'failed', 'error': 'x' * 9000}
        with self.assertRaises(ValueError): h.validate_proxy_snapshot(changed)
        for bad in [None, {}, {'state': None}]:
            with self.assertRaises(ValueError): h.validate_proxy_snapshot(bad)
        with self.assertRaises(ValueError): h.strict_json('{"x":{"a":1,"a":2}}')

    def test_starting_does_not_invent_effective_carrier_or_samples(self):
        value = snapshot(phase='Starting')
        proxy = value['state']['proxy']; proxy['runtime'] = None
        measured = proxy['measured']; measured['aggregate'] = None
        for field in ['effective', 'effective_carrier', 'effective_udp_cover']:
            measured['capabilities'][field] = None
        h.validate_proxy_snapshot(value, allow_starting=True)
        measured['capabilities']['effective_carrier'] = 'tcp_tls'
        with self.assertRaises(ValueError): h.validate_proxy_snapshot(value, allow_starting=True)

    def test_actual_feedback_growth_pressure_and_two_demand_are_separate(self):
        def sample(at, counter):
            peers = {side: snapshot(side) for side in ('a', 'b')}
            for value in peers.values():
                value['state']['proxy']['measured']['aggregate']['authoritative_at_micros'] = counter
            return {'peers': peers, 'poll_begin_monotonic_ns': at, 'poll_end_monotonic_ns': at + 1000}
        samples = [sample(1_000_500_000_000, 90000), sample(1_001_000_000_000, 100000)]
        flows = [f for f in h.case_plan('unit', 'full')['flows'] if f['split']]
        probes = [pressure_result(flow, role) for flow in flows for role in ('connect', 'listen')]
        self.assertEqual(h.measurement_evidence(samples, True, probes)['a']['growth_samples'], 2)
        for field, replacement in [('ack_rate', None), ('service_latency', None),
                                   ('demanding_flows', 1), ('receiver_pressure', False), ('admitted_by_kind', [1, 1, 0])]:
            changed = copy.deepcopy(samples)
            for sample_value in changed:
                sample_value['peers']['a']['state']['proxy']['measured']['aggregate'][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): h.measurement_evidence(changed, True, probes)
        changed = copy.deepcopy(samples)
        for sample_value in changed:
            sample_value['peers']['a']['state']['proxy']['measured']['aggregate']['applied']['candidate_bytes'] = 32768
        with self.assertRaises(ValueError): h.measurement_evidence(changed, True, probes)
        h.measurement_evidence(changed, False)
        changed = copy.deepcopy(samples)
        for sample_value in changed: sample_value['poll_end_monotonic_ns'] += 5_000_000_000
        with self.assertRaises(ValueError): h.measurement_evidence(changed, True, probes)

    def test_pressure_probe_requires_exact_bytes_eof_blocked_send_and_deadline(self):
        flow = h.case_plan('unit', 'full')['flows'][0]
        value = pressure_result(flow, 'connect')
        h.verify_probe(value, flow, 'connect', True)
        for field, replacement in [('eof', False), ('received_bytes', h.PRESSURE_BYTES - 1), ('sent_sha256', '0' * 64)]:
            with self.assertRaises(ValueError): h.verify_probe({**value, field: replacement}, flow, 'connect', True)
        for field, replacement in [('read_begin', 1001), ('send_complete', 1001), ('ended', 1040)]:
            changed = copy.deepcopy(value); changed['timing'][field] = replacement
            with self.assertRaises(ValueError): h.verify_probe(changed, flow, 'connect', True)

    def test_two_flow_progress_is_concurrent_without_claiming_weighted_fairness(self):
        flows = [f for f in h.case_plan('unit', 'half')['flows'] if f['split']]
        results = [pressure_result(flow, role) for flow in flows for role in ('connect', 'listen')]
        proof = h.verify_concurrent_probes(results, flows)
        self.assertEqual(proof['weights'], [1, 1])
        self.assertNotIn('fairness_ratio', proof)
        for result in results[2:]:
            for field in result['timing']: result['timing'][field] += 10
        with self.assertRaises(ValueError): h.verify_concurrent_probes(results, flows)

    def test_window_scale_zero_reopen_and_new_ack_required_each_leg_family(self):
        for flow in [f for f in h.case_plan('unit', 'full')['flows'] if f['split']]:
            for side in ('a', 'b'):
                first = (flow['source'], flow['source_port']); second = (flow['destination'], flow['destination_port'])
                own, peer = (second, first) if side == 'a' else (first, second)
                def packet(reverse=False, flags=0x10, window=500, ack=10, scale=None):
                    a, b = (peer, own) if reverse else (own, peer)
                    return window_packet(a[0], b[0], a[1], b[1], flags, window, ack, scale)
                packets = [packet(flags=2, window=65535, scale=2), packet(True, flags=0x12, scale=4),
                           packet(window=500), packet(window=0), packet(window=300), packet(window=400, ack=20)]
                times = [2_000_100_000_000, 2_000_200_000_000, 2_000_500_000_000,
                         2_001_000_000_000, 2_002_100_000_000, 2_002_200_000_000]
                release = h.release_clock(pressure_result(flow, 'listen' if side == 'a' else 'connect'))
                proof = h.window_sequence(packets, flow, side, True, times, release)
                self.assertEqual(proof['initial_syn_window_unscaled'], 65535)
                self.assertEqual(proof['negotiated_scale'], 2)
                self.assertEqual(proof['pressure_reopen_ack_proof']['reopen_scaled_bytes'], 1200)
                for changed in [packets[:3] + packets[4:], packets[:4], packets[:-1], packets[1:]]:
                    with self.assertRaises(ValueError): h.window_sequence(changed, flow, side, True, times[:len(changed)], release)
                # An actual reopen before release followed by a later positive ACK is insufficient.
                early = list(times); early[4] = 2_001_900_000_000
                with self.assertRaises(ValueError): h.window_sequence(packets, flow, side, True, early, release)
                late_zero = list(times); late_zero[3] = 2_002_050_000_000
                with self.assertRaises(ValueError): h.window_sequence(packets, flow, side, True, late_zero, release)
                h.window_sequence(packets[:3], flow, side, False)

    def test_clock_mapping_and_capture_timestamp_precision_are_bounded(self):
        flow = h.case_plan('unit', 'full')['flows'][0]
        probe = pressure_result(flow, 'connect')
        self.assertLessEqual(h.release_clock(probe)['mapping_uncertainty_ns'], h.CLOCK_DRIFT_NS)
        changed = copy.deepcopy(probe); changed['clock']['end']['realtime_ns'] += h.CLOCK_DRIFT_NS + 1000
        with self.assertRaises(ValueError): h.release_clock(changed)
        changed = copy.deepcopy(probe); changed['clock']['start']['before_mono_ns'] -= h.CLOCK_BRACKET_NS + 1000
        with self.assertRaises(ValueError): h.release_clock(changed)
        raw = fixtures.ip_packet('198.19.0.1', '198.19.0.2')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'timed.pcap'
            captured = bytearray(fixtures.pcap([raw]))
            captured[24:32] = struct.pack('<II', 2000, 123456)
            path.write_bytes(captured)
            packets, times, tick = h.timed_capture(path)
            self.assertEqual((len(packets), times, tick), (1, [2_000_123_456_000], 1000))
            captured[:4] = b'\x4d\x3c\xb2\xa1'
            path.write_bytes(captured)
            self.assertEqual(h.timed_capture(path)[1:], ([2_000_000_123_456], 1))
            captured[28:32] = struct.pack('<I', 1_000_000_000)
            path.write_bytes(captured)
            with self.assertRaises(ValueError): h.timed_capture(path)

    def test_original_close_fences_remain_required_and_measured_lanes_match(self):
        peers = {side: snapshot(side, 'Closed', True, 2) for side in ('a', 'b')}
        self.assertEqual(h.verify_peer_closures(peers, 2)['a']['tls_lanes_closed'], 2)
        peers['b']['state']['proxy']['terminal']['report']['peer_user_records'] += 1
        with self.assertRaises(ValueError): h.verify_peer_closures(peers, 2)

    def test_silent_pressure_helper_readiness_expires_and_is_reaped(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        started = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                wait_ready_line(child, started + 0.1)
        finally:
            stop_child(child)
        self.assertIsNotNone(child.returncode)
        self.assertLess(time.monotonic() - started, 2)

    def test_real_pressure_kernel_loopback_both_families(self):
        harness = Path(h.__file__).resolve()
        for family, address in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
            with socket.socket(family, socket.SOCK_STREAM) as reserve:
                try: reserve.bind((address, 0))
                except OSError:
                    if family == socket.AF_INET6: continue
                    raise
                port = reserve.getsockname()[1]
            with socket.socket(family, socket.SOCK_STREAM) as reserve:
                reserve.bind((address, 0)); source_port = reserve.getsockname()[1]
            args = [address, address, str(source_port), str(port)]
            server = subprocess.Popen([sys.executable, str(harness), 'pressure-probe', 'listen', *args],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(wait_ready_line(server, time.monotonic() + 5), 'Listening')
                client = subprocess.run([sys.executable, str(harness), 'pressure-probe', 'connect', *args],
                                        capture_output=True, text=True, timeout=35, check=True)
                stdout, stderr = server.communicate(timeout=35)
                self.assertEqual(server.returncode, 0, stderr)
                flow = {'source': address, 'destination': address, 'source_port': source_port, 'destination_port': port}
                h.verify_probe(json.loads(client.stdout.splitlines()[-1]), flow, 'connect', True)
                h.verify_probe(json.loads(stdout.splitlines()[-1]), flow, 'listen', True)
            finally:
                stop_child(server)


if __name__ == '__main__':
    unittest.main()
