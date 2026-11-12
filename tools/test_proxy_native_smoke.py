"""Pure acceptance regressions and ordinary loopback probes; no namespaces/root."""
import contextlib
import copy
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from . import proxy_native_smoke as h


def snapshot(phase='Forwarding', terminal=False, lanes=1):
    status = {key: 0 for key in h.STATUS_FIELDS}
    status.update(phase=phase, flows=2 if terminal else 0, retired=2 if terminal else 0)
    report = {key: 0 for key in h.CLOSE_FIELDS}
    report.update(clean_flows=2, tls_lanes_closed=lanes,
                  local_user_records=17, peer_user_records=17,
                  local_transparent_packets=9, native_confirmed_packets=9)
    return {'version': 1, 'ok': True, 'code': 'ok', 'state': {
        'epoch': 1, 'phase': phase, 'compression': 'off', 'proxy': {
            'digest': 'ab' * 32, 'drain_accepted': terminal, 'runtime': status,
            'terminal': {'outcome': 'closed', 'report': report} if terminal else None}}}


def checksum(raw):
    padded = raw + b'\0' * (len(raw) % 2)
    total = sum(int.from_bytes(padded[i:i + 2], 'big') for i in range(0, len(padded), 2))
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def ip_packet(source, destination, sport=32004, dport=24451, sequence=100, flags=2, protocol=6):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if protocol == 6:
        body = bytearray(struct.pack('!HHIIBBHHH', sport, dport, sequence, 0, 0x50, flags, 1024, 0, 0))
        check_offset = 16
    else:
        body = bytearray(bytes([8 if protocol == 1 else 128, 0]) + bytes(6))
        check_offset = 2
    pseudo = (src.packed + dst.packed + bytes([0, protocol]) + struct.pack('!H', len(body))
              if src.version == 4 else src.packed + dst.packed + struct.pack('!I', len(body)) + bytes([0, 0, 0, protocol]))
    body[check_offset:check_offset + 2] = checksum((b'' if protocol == 1 else pseudo) + body).to_bytes(2, 'big')
    if src.version == 4:
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 7, 0x4000,
                                       64, protocol, 0, src.packed, dst.packed))
        header[10:12] = checksum(header).to_bytes(2, 'big')
    else:
        header = struct.pack('!IHBB16s16s', 6 << 28, len(body), protocol, 64, src.packed, dst.packed)
    return bytes(header + body)


def pcap(packets, link=101):
    result = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
    for raw in packets:
        ether = 0x800 if raw[0] >> 4 == 4 else 0x86dd
        if link == 1:
            raw = bytes(12) + struct.pack('!H', ether) + raw
        elif link == 113:
            raw = bytes(14) + struct.pack('!H', ether) + raw
        elif link == 276:
            raw = struct.pack('!H', ether) + bytes(18) + raw
        result.extend(struct.pack('<IIII', 1, 0, len(raw), len(raw)) + raw)
    return bytes(result)


def fixture_captures(directory, lanes=1):
    flows = h.case_plan('unit', 'full' if lanes == 1 else 'half')['flows']
    paths, packets = {}, {'a_native': [], 'b_native': []}
    for flow in flows:
        for side in ('a', 'b'):
            initial = 1000 + (100 if side == 'b' and flow['split'] else 0)
            for reverse, flags in [(False, 2), (True, 0x12), (False, 0x11), (True, 0x11)]:
                first = (flow['source'], flow['source_port'])
                second = (flow['destination'], flow['destination_port'])
                if reverse:
                    first, second = second, first
                packets[f'{side}_native'].append(ip_packet(first[0], second[0], first[1], second[1], initial, flags))
    for side in ('a', 'b'):
        packets[f'{side}_wan'] = [ip_packet('192.0.2.2', '192.0.2.6', 40000 + i, 18443) for i in range(lanes)]
    for name, values in packets.items():
        paths[name] = Path(directory) / (name + '.pcap')
        paths[name].write_bytes(pcap(values))
    return paths, packets, flows


class ProxyHarnessTests(unittest.TestCase):
    def test_dry_run_has_no_files_and_explicit_clean_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist'
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream), patch.object(h.subprocess, 'run') as run:
                self.assertEqual(h.main(['--lab-id', 'unit', '--output', str(output)]), 0)
            self.assertFalse(output.exists())
            run.assert_not_called()
            result = json.loads(stream.getvalue())
            self.assertEqual(result['status'], 'dry_run')
            self.assertEqual([c['lanes'] for c in result['cases']], [1, 2])
            for case in result['cases']:
                self.assertEqual(case['policy']['time_wait_reset'], 'maintained')
                self.assertEqual(case['clean_override']['loss_percent'], 0)
                self.assertEqual(len(case['flows']), 6)
                self.assertEqual(len({f['source_port'] for f in case['flows']}), 6)
                self.assertTrue(case['initial_topology_commands'])
            for lab, duplex in [('a' * 19, 'full'), ('../bad', 'half'), ('unit', 'invalid')]:
                with self.assertRaises(ValueError):
                    h.case_plan(lab, duplex)

    def test_strict_status_rejects_unknown_duplicate_or_unbounded_fields(self):
        self.assertIsNone(h.validate_proxy_snapshot(snapshot())['terminal'])
        for raw in ['{"a":1,"a":2}', '{"a":{"b":1,"b":2}}']:
            with self.assertRaises(ValueError): h.strict_json(raw)
        cases = []
        value = snapshot(); value['state']['active'] = {}; cases.append(value)
        value = snapshot(); value['state']['proxy']['runtime']['flows'] = True; cases.append(value)
        value = snapshot(); value['state']['proxy']['runtime']['flows'] = 2**64; cases.append(value)
        value = snapshot(); value['state']['proxy']['digest'] = 'a' * 63; cases.append(value)
        value = snapshot(); value['state']['proxy']['terminal'] = {'outcome': 'failed', 'error': 'x' * 257}; cases.append(value)
        value = snapshot(); value['state']['phase'] = 'Closed'; cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                h.validate_proxy_snapshot(value)
        value = snapshot('Starting'); value['state']['proxy']['runtime'] = None
        self.assertIsNone(h.validate_proxy_snapshot(value, allow_starting=True)['runtime'])
        with self.assertRaises(ValueError): h.validate_proxy_snapshot(value)
        with self.assertRaises(ValueError): h.validate_proxy_snapshot(snapshot(), 'ff' * 32)

    def test_actual_closure_is_distinct_from_acceptance_and_cross_fences_match(self):
        for lanes in (1, 2):
            peers = {side: snapshot('Closed', True, lanes) for side in ('a', 'b')}
            self.assertEqual(h.verify_peer_closures(peers, lanes)['a']['clean_flows'], 2)
            for key, replacement in [('peer_user_records', 18), ('native_confirmed_packets', 10),
                                      ('clean_flows', 1), ('stopped_flows', 1), ('tls_lanes_closed', 3 - lanes)]:
                changed = copy.deepcopy(peers)
                changed['b']['state']['proxy']['terminal']['report'][key] = replacement
                with self.subTest(key=key), self.assertRaises(ValueError): h.verify_peer_closures(changed, lanes)
            changed = copy.deepcopy(peers)
            changed['b']['state']['proxy']['terminal'] = None
            changed['b']['state']['proxy']['drain_accepted'] = True
            with self.assertRaises(ValueError): h.verify_peer_closures(changed, lanes)

    def test_exact_probe_bytes_tuple_and_eof_are_all_required(self):
        flow = h.case_plan('unit', 'full')['flows'][0]
        first, second = h.payload(65537, 11), h.payload(32771, 29)
        value = {'role': 'connect', 'source': [flow['source'], flow['source_port']],
                 'destination': [flow['destination'], flow['destination_port']], 'sent_bytes': len(first),
                 'received_bytes': len(second), 'sent_sha256': hashlib.sha256(first).hexdigest(),
                 'received_sha256': hashlib.sha256(second).hexdigest(), 'eof': True}
        h.verify_probe(value, flow, 'connect')
        for key, replacement in [('eof', False), ('received_bytes', 32770), ('received_sha256', '0' * 64),
                                  ('source', [flow['source'], 1]), ('sent_bytes', True), ('role', 'listen')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                h.verify_probe({**value, key: replacement}, flow, 'connect')

    def test_ip_parser_checks_checksums_lengths_and_extensions(self):
        for src, dst in [('198.19.0.1', '198.19.0.2'), ('fd42:12:19::1', 'fd42:12:19::2')]:
            raw = ip_packet(src, dst)
            self.assertEqual(h.decode_ip(raw).source, src)
            broken = raw[:-1] + bytes([raw[-1] ^ 1])
            with self.assertRaises(ValueError): h.decode_ip(broken)
            for length in range(len(raw)):
                with self.assertRaises((ValueError, h.Unsupported)): h.decode_ip(raw[:length])
            icmp = ip_packet(src, dst, protocol=1 if ':' not in src else 58)
            self.assertEqual(h.decode_ip(icmp).protocol, 1 if ':' not in src else 58)
        fragment = bytearray(ip_packet('198.19.0.1', '198.19.0.2')); fragment[6] = 0x20
        with self.assertRaises(h.Unsupported): h.decode_ip(bytes(fragment))
        extension = bytearray(ip_packet('fd42:12:19::1', 'fd42:12:19::2')); extension[6] = 0
        with self.assertRaises(h.Unsupported): h.decode_ip(bytes(extension))

    def test_pcap_link_formats_truncation_and_caps(self):
        raw = ip_packet('198.19.0.1', '198.19.0.2')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            for link in (1, 101, 113, 276):
                data = pcap([raw], link); path.write_bytes(data)
                self.assertEqual(h.read_pcap(path)[0].raw, raw)
                path.write_bytes(data[:-1])
                with self.assertRaises(ValueError): h.read_pcap(path)
            path.write_bytes(pcap([raw]))
            with patch.object(h, 'CAPTURE_LIMIT', 24), self.assertRaises(ValueError): h.read_pcap(path)
            with patch.object(h, 'PACKET_LIMIT', 1), self.assertRaises(ValueError): h.read_pcap(path)
            path.write_bytes(pcap([]))
            with self.assertRaises(ValueError): h.read_pcap(path)
            data = bytearray(pcap([raw])); data[36:40] = struct.pack('<I', len(raw) + 1); path.write_bytes(data)
            with self.assertRaises(ValueError): h.read_pcap(path)
            path.write_bytes(pcap([raw + bytes(1500)]))
            with self.assertRaisesRegex(ValueError, 'beyond declared'): h.read_pcap(path)
            path.write_bytes(pcap([raw + bytes(6)], 1))
            self.assertEqual(h.read_pcap(path)[0].raw, raw)

    def test_capture_audit_requires_real_split_and_exact_bypass_both_fin_and_lanes(self):
        for lanes in (1, 2):
            with tempfile.TemporaryDirectory() as directory:
                paths, packets, flows = fixture_captures(directory, lanes)
                proof = h.audit_native_captures(paths, flows, lanes)
                self.assertEqual(len(proof['flows']), 6)
                # Successful native bytes do not substitute for distinct SYN sequence spaces.
                paths['b_native'].write_bytes(pcap(packets['a_native']))
                with self.assertRaisesRegex(ValueError, 'independent proxy'): h.audit_native_captures(paths, flows, lanes)
                paths['b_native'].write_bytes(pcap(packets['b_native'][:-1]))
                with self.assertRaisesRegex(ValueError, 'FIN'): h.audit_native_captures(paths, flows, lanes)
                paths['b_native'].write_bytes(pcap(packets['b_native']))
                paths['a_wan'].write_bytes(pcap(packets['a_wan'] + [packets['a_native'][0]]))
                with self.assertRaisesRegex(ValueError, 'escaped'): h.audit_native_captures(paths, flows, lanes)
                paths['a_wan'].write_bytes(pcap(packets['a_wan']))
                with self.assertRaisesRegex(ValueError, 'original authenticated lanes'):
                    h.audit_native_captures(paths, flows, 3 - lanes)
                # Replacing a denied SYN with another valid native SYN cannot prove transparency.
                altered = packets['b_native'].copy()
                flow = flows[2]
                altered[8] = ip_packet(flow['source'], flow['destination'], flow['source_port'], flow['destination_port'], 999)
                paths['b_native'].write_bytes(pcap(altered))
                with self.assertRaisesRegex(ValueError, 'original SYN'): h.audit_native_captures(paths, flows, lanes)
                flow = flows[0]
                rst = ip_packet(flow['source'], flow['destination'], flow['source_port'], flow['destination_port'], flags=4)
                paths['b_native'].write_bytes(pcap(packets['b_native'] + [rst]))
                with self.assertRaisesRegex(ValueError, 'reset'): h.audit_native_captures(paths, flows, lanes)

    def test_capture_counters_do_not_confuse_ten_drops_with_zero(self):
        text = '7 packets captured\n9 packets received by filter\n0 packets dropped by kernel\n'
        self.assertEqual(h.capture_counts(text)['captured'], 7)
        for changed in [text.replace('0 packets', '10 packets'), text + text,
                        text.replace('7 packets', '0 packets'), text.replace('7 packets', '8192 packets'), text[:-10]]:
            with self.assertRaises(ValueError): h.capture_counts(changed)

    def test_receipt_is_exclusive_atomic_and_failed_oversize_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            receipt = h.Receipt(path, {'status': 'running', 'events': []})
            receipt.update(status='failed', error='injected')
            prior = path.read_bytes()
            with self.assertRaises(FileExistsError): h.Receipt(path, {'status': 'passed'})
            with patch.object(h, 'RECEIPT_LIMIT', 32), self.assertRaises(ValueError): receipt.update(error='x' * 100)
            self.assertEqual(path.read_bytes(), prior)
            self.assertEqual(list(Path(directory).glob('.receipt-*')), [])
            nested = {'items': []}; receipt.update(extra=nested); nested['items'].append(1)
            self.assertEqual(receipt.value['extra'], {'items': []})

    def test_source_provenance_includes_manifests_vendor_patch_and_compile_assets(self):
        names = ['Cargo.toml', 'Cargo.lock', 'tools/proxy_native_smoke.py', 'tools/test_proxy_native_smoke.py',
                 'tools/netns_lab.py', 'crates/example/Cargo.toml', 'crates/example/src/lib.rs',
                 'crates/example/fixtures/body.bin', 'apps/example/Cargo.toml', 'third_party/source/src/lib.rs',
                 'third_party/source/LICENSE', 'third_party/source/Cargo.toml', 'third_party/source.patch',
                 'third_party/provenance.json', '.cargo/config.toml',
                 'crates/example/src/target/tests.rs', 'third_party/source/target/build-cache']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in [*names, 'target/build-cache']:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(name)
            before = h.source_hashes(root)
            self.assertEqual(set(before), set(names))
            (root / 'third_party/provenance.json').write_text('changed provenance')
            self.assertNotEqual(before, h.source_hashes(root))

    def test_build_provenance_requires_equal_original_sources_and_exact_copied_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, path = Path(directory) / 'binary', Path(directory) / 'build.json'
            binary.write_bytes(b'immutable original binary')
            sources = {'Cargo.toml': 'ab' * 32, 'third_party/source.rs': 'cd' * 32}
            good = {'status': 'passed', 'exit_code': 0, 'source_stable_during_build': True,
                    'changed_during_build': [], 'source_sha256_before': sources,
                    'source_sha256_after': sources, 'binary_sha256': h.file_hash(binary)}
            path.write_text(json.dumps(good))
            self.assertEqual(h.verified_build_receipt(path, binary), good)
            for key, value in [('status', 'failed'), ('exit_code', 1), ('source_stable_during_build', False),
                               ('changed_during_build', ['Cargo.toml']), ('source_sha256_after', {}),
                               ('binary_sha256', 'ff' * 32)]:
                path.write_text(json.dumps({**good, key: value}))
                with self.subTest(key=key), self.assertRaises(ValueError): h.verified_build_receipt(path, binary)
            path.write_text(json.dumps(good)); binary.write_bytes(b'different binary')
            with self.assertRaises(ValueError): h.verified_build_receipt(path, binary)

    def test_ipv6_is_disabled_only_on_exact_four_owned_ipv4_underlay_interfaces(self):
        namespaces = h.netns_lab.LabSpec('unit').namespaces
        with patch.object(h, 'command', side_effect=['0\n', '', '1\n'] * 4) as command:
            evidence = h.disable_underlay_ipv6(namespaces, 123)
        self.assertEqual(set(evidence), {'endpoint_a/wan0', 'endpoint_b/wan0', 'router/a0', 'router/b0'})
        for call in command.call_args_list:
            self.assertEqual(call.args[1], 123)
            self.assertEqual(call.args[0][:3], ['ip', 'netns', 'exec'])
            self.assertNotIn('tun0', ' '.join(call.args[0]))
        for replies in [['unexpected'], ['0', '', '0']]:
            with patch.object(h, 'command', side_effect=replies), self.assertRaises(h.Unsupported):
                h.disable_underlay_ipv6(namespaces, 123)

    def test_original_deadline_and_journal_runner_restored_on_failure(self):
        original = h.netns_lab.run
        with patch.object(h.time, 'monotonic', return_value=100):
            self.assertEqual(h.remaining(101, 15), 1)
            with self.assertRaises(TimeoutError): h.remaining(100, 15)
            def operation(spec, directory):
                h.netns_lab.run(['owned', 'command'])
                raise ValueError('injected journal failure')
            with patch.object(h.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
                with self.assertRaisesRegex(ValueError, 'injected'): h.bounded_lab(operation, None, None, 101)
                self.assertEqual(run.call_args.kwargs['timeout'], 1)
        self.assertIs(h.netns_lab.run, original)

    def test_owned_child_stop_never_uses_names_or_extends_each_wait(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('owned-child', 5), 0]
        h.stop(process)
        process.send_signal.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual([c.kwargs for c in process.wait.call_args_list], [{'timeout': 5}, {'timeout': 5}])
        process = Mock(); process.poll.return_value = 0
        h.stop(process); process.send_signal.assert_not_called()

    def test_case_failure_still_attempts_every_child_and_owned_namespace_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, secrets, namespaces = root / 'output', root / 'secrets', root / 'namespaces'
            for path in (output, secrets, namespaces): path.mkdir()
            children = [Mock(stderr=None), Mock(stderr=None)]
            calls = []
            def lab(operation, spec, state, deadline):
                calls.append(operation)
            def stop(process, interrupt=False):
                if process is children[1]: raise OSError('first retained child failure')
            with patch.object(h, 'bounded_lab', side_effect=lab), patch.object(h, 'command', return_value=''), \
                 patch.object(h, 'disable_underlay_ipv6', return_value={}), \
                 patch.object(h, 'offloads', return_value={'after': 'off'}), \
                 patch.object(h, 'start_capture', side_effect=[*children, OSError('capture startup injected')]), \
                 patch.object(h, 'stop', side_effect=stop) as stopped, \
                 patch.object(h.netns_lab, 'NETNS_DIRECTORY', namespaces):
                with self.assertRaises(RuntimeError):
                    h.run_case(h.case_plan('unit', 'full'), root / 'unused-binary', root / 'unused-script',
                               output, secrets, root / 'state')
            self.assertEqual(calls, [h.netns_lab.apply, h.netns_lab.cleanup])
            self.assertEqual([call.args[0] for call in stopped.call_args_list], list(reversed(children)))
            receipt = json.loads((output / 'tun-full-clean/receipt.json').read_text())
            self.assertEqual(receipt['status'], 'failed')
            self.assertEqual(receipt['cleanup'], 'failed')
            self.assertIn('capture startup injected', receipt['error'])
            self.assertIn('first retained child failure', receipt['cleanup_error'])
            self.assertEqual(receipt['events'][0]['stage'], 'capture_start')

    def test_private_rpc_is_length_bounded_and_rejects_duplicate_json(self):
        for wire in [struct.pack('!I', 8193), struct.pack('!I', 13) + b'{"a":1,"a":2}', struct.pack('!I', 4) + b'{}']:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'control.sock'
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                server.bind(str(path)); server.listen(1); server.settimeout(2)
                errors = []
                def peer():
                    try:
                        with server.accept()[0] as connection:
                            connection.settimeout(2)
                            connection.recv(4096)
                            connection.sendall(wire)
                    except Exception as error: errors.append(error)
                worker = threading.Thread(target=peer); worker.start()
                try:
                    with self.assertRaises(ValueError): h.rpc(path, 'status', time.monotonic() + 2)
                finally:
                    worker.join(3); server.close()
                self.assertFalse(worker.is_alive()); self.assertEqual(errors, [])

    def test_real_kernel_loopback_probe_exact_duplex_payload_and_eof(self):
        # Ordinary loopback only: this qualifies the helper, never native TUN proxying.
        for address, family in [('127.0.0.1', socket.AF_INET), ('::1', socket.AF_INET6)]:
            holders = [socket.socket(family, socket.SOCK_STREAM) for _ in range(2)]
            try:
                for holder in holders: holder.bind((address, 0))
                source, destination = [holder.getsockname()[1] for holder in holders]
            finally:
                for holder in holders: holder.close()
            flow = {'source': address, 'destination': address, 'source_port': source, 'destination_port': destination}
            args = [sys.executable, str(Path(h.__file__).resolve()), 'probe']
            fields = [address, address, str(source), str(destination)]
            with tempfile.TemporaryDirectory() as directory:
                log = Path(directory) / 'server.log'
                server = h.launch([*args, 'listen', *fields], log)
                try:
                    end = time.monotonic() + 10
                    h.wait_log(server, log, 'Listening', end)
                    client = subprocess.run([*args, 'connect', *fields], capture_output=True, text=True,
                                            timeout=h.remaining(end, 10), check=False)
                    self.assertEqual(client.returncode, 0, client.stderr)
                    self.assertEqual(server.wait(timeout=h.remaining(end, 10)), 0, log.read_text())
                    h.verify_probe(json.loads(client.stdout.splitlines()[-1]), flow, 'connect')
                    h.verify_probe(json.loads(log.read_text().splitlines()[-1]), flow, 'listen')
                finally:
                    h.stop(server)


if __name__ == '__main__':
    unittest.main()
