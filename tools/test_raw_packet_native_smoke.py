"""Unprivileged evidence/lifecycle checks; these fixtures do not qualify native raw I/O."""
from contextlib import ExitStack, redirect_stdout
import copy
import io
import json
import math
from pathlib import Path
import socket
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import raw_packet_native_smoke as smoke
from tools import test_raw_native_smoke as tls_fixture


def status(phase='Active', duplex='full', side='a'):
    value = {'requested': dict(smoke.SELECTION), 'effective': dict(smoke.SELECTION),
             'capabilities': dict(smoke.CAPABILITIES), 'digest': 'ab' * 32,
             'phase': phase, 'fault': 'TimedOut' if phase == 'Stopped' else None}
    for name in smoke.COUNTERS:
        value[name] = [1, 0] if duplex == 'full' else [1, 1]
    if duplex == 'half':
        for name in ('admitted', 'sources', 'peer_delivered'):
            value[name] = [1, 0] if side == 'a' else [0, 1]
        for name in ('received', 'delivered'):
            value[name] = [0, 1] if side == 'a' else [1, 0]
    return value


def response(value=None):
    value = status() if value is None else value
    return {'version': 1, 'ok': True, 'code': 'ok',
            'state': {'epoch': 1, 'phase': value['phase'], 'compression': 'off', 'raw_packet': value}}


def phase(lane, direction, number, kind, offset=0, retired=0, body=None):
    if body is None:
        body = bytes({1: 280, 2: 104, 3: 104, 6: 8, 7: 8, 8: 0}.get(kind, 0))
        if kind in (4, 5): body = b'L2RP\x01' + bytes([1 if kind == 4 else 3, 0, 0]) + b'fixture source'
    plain = struct.pack('!BBH16sQQQHH', 1, kind, 0, bytes([33]) * 16, offset, retired, retired + 32768, len(body), 0) + body
    header = struct.pack('!2s6B16sIIQH2s', b'LD', 1, 1, 2, direction, 0, 0,
                         bytes([lane + 1]) * 16, lane, 1, number, len(plain), bytes(2))
    return bytes([0x48, 0, 0, lane]) + header + plain + bytes(32)


def ip_packet(source, destination, sport, dport, sequence, flags, data=b'', acknowledgment=0):
    source_ip, destination_ip = smoke.ipaddress.ip_address(source), smoke.ipaddress.ip_address(destination)
    family = source_ip.version
    tcp = bytearray(struct.pack('!HHIIBBHHH', sport, dport, sequence & 0xffffffff,
                                acknowledgment & 0xffffffff, 0x50, flags, 32768, 0, 0) + data)
    pseudo = source_ip.packed + destination_ip.packed
    pseudo += (bytes([0, 6]) + len(tcp).to_bytes(2, 'big') if family == 4
               else len(tcp).to_bytes(4, 'big') + bytes([0, 0, 0, 6]))
    tcp[16:18] = smoke.bounded.checksum(pseudo + tcp).to_bytes(2, 'big')
    if family == 4:
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, source_ip.packed, destination_ip.packed))
        ip[10:12] = smoke.bounded.checksum(ip).to_bytes(2, 'big')
    else:
        ip = struct.pack('!IHBB16s16s', 6 << 28, len(tcp), 6, 64, source_ip.packed, destination_ip.packed)
    return bytes(12) + (b'\x08\x00' if family == 4 else b'\x86\xdd') + ip + tcp


def outer(lane, direction, sequence, flags, data=b'', acknowledgment=0):
    a, b = smoke.retained.PORTS[lane]
    return ip_packet('192.0.2.2' if direction == 1 else '192.0.2.6',
                     '192.0.2.6' if direction == 1 else '192.0.2.2',
                     a if direction == 1 else b, b if direction == 1 else a,
                     sequence, flags, data, acknowledgment)


def underlay(lanes=1):
    packets = []
    client, server = tls_fixture.streams()
    for lane in range(lanes):
        a, b = 100 + lane * 10000, 1000 + lane * 10000
        ba, bb = a + 1 + len(client), b + 1 + len(server)
        packets += [outer(lane, 1, a, 2), outer(lane, 2, b, 18, acknowledgment=a + 1),
                    outer(lane, 1, a + 1, 24, client, b + 1), outer(lane, 2, b + 1, 24, server, a + 1)]
        for direction, base, peer in ((1, ba, bb), (2, bb, ba)):
            offset = 0
            bulk = lanes == 1 or direction == (1 if lane == 0 else 2)
            for number, kind in enumerate((1, 2 if direction == 1 else 3, 4 if bulk else 5)):
                data = phase(lane, direction, number, kind, offset)
                packets.append(outer(lane, direction, base + offset, 24, data, peer))
                offset += len(data)
    return packets


def native_packets(flows):
    packets = []
    for flow in flows:
        version = flow['family']
        a, b = flow['source'], flow['destination']
        for reverse in (False, True):
            source, destination = (b, a) if reverse else (a, b)
            sport, dport = ((flow['destination_port'], flow['source_port']) if reverse
                            else (flow['source_port'], flow['destination_port']))
            isn = 5000 if reverse else 100
            packets.append(ip_packet(source, destination, sport, dport, isn, 18 if reverse else 2))
            body = smoke.bounded.payload(smoke.bounded.PAYLOAD_LENGTHS[1 if reverse else 0], 29 if reverse else 11)
            for offset in range(0, len(body), 1400):
                packets.append(ip_packet(source, destination, sport, dport, isn + 1 + offset, 24, body[offset:offset + 1400]))
            packets.append(ip_packet(source, destination, sport, dport, isn + 1 + len(body), 17))
        source_ip, destination_ip = smoke.ipaddress.ip_address(a), smoke.ipaddress.ip_address(b)
        protocol, kind = (1, 8) if version == 4 else (58, 128)
        body = bytearray(bytes([kind, 0, 0, 0, 0, 1, 0, 1]) + b'icmp fixture')
        pseudo = b'' if version == 4 else source_ip.packed + destination_ip.packed + len(body).to_bytes(4, 'big') + bytes([0, 0, 0, 58])
        body[2:4] = smoke.bounded.checksum(pseudo + body).to_bytes(2, 'big')
        if version == 4:
            ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1, 0x4000, 64, protocol, 0, source_ip.packed, destination_ip.packed))
            ip[10:12] = smoke.bounded.checksum(ip).to_bytes(2, 'big')
        else:
            ip = struct.pack('!IHBB16s16s', 6 << 28, len(body), protocol, 64, source_ip.packed, destination_ip.packed)
        packets.append(bytes(12) + (b'\x08\x00' if version == 4 else b'\x86\xdd') + ip + body)
    return packets


class RawPacketEvidenceTests(unittest.TestCase):
    def inspect(self, packets, lanes=1):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            path.write_bytes(tls_fixture.pcap(packets))
            return smoke.audit_underlay(path, lanes)

    def test_four_plans_are_explicit_and_dry_run_never_executes_or_writes(self):
        stdout = io.StringIO()
        with (patch.object(smoke.netns_lab, 'require_root', side_effect=AssertionError('no privilege')),
              patch.object(smoke.bounded, 'command', side_effect=AssertionError('no process')),
              patch.object(Path, 'mkdir', side_effect=AssertionError('no write')), redirect_stdout(stdout)):
            self.assertEqual(smoke.main([]), 0)
        value = json.loads(stdout.getvalue())
        self.assertEqual(value['mutations'], 'none')
        self.assertFalse(value['graceful_close'])
        self.assertEqual([p['case'] for p in value['cases']], ['tap-full-clean', 'tap-half-clean', 'tun-full-clean', 'tun-half-clean'])
        namespaces = [set(p['namespaces'].values()) for p in value['cases']]
        self.assertEqual(len(set.union(*namespaces)), 20)
        for plan in value['cases']:
            self.assertIn('--carrier', plan['profile'])
            self.assertEqual(plan['profile'][plan['profile'].index('--carrier') + 1], 'raw-packet')
            a, b = plan['policies']['a'], plan['policies']['b']
            self.assertEqual(a['forward'], dict(local=b['forward']['peer'], peer=b['forward']['local']))
            self.assertEqual(a['packet']['protection'], 'integrity')
            self.assertEqual(a['reverse'] is None, plan['duplex'] == 'full')
        for layer, mode in [('vxlan', 'full'), ('tun', 'netem')]:
            with self.assertRaises(ValueError): smoke.case_plan('test', layer, mode)

    def test_apply_requires_build_receipt_before_tools_or_namespace_mutation(self):
        with (patch.object(smoke.netns_lab, 'require_root'),
              patch.object(smoke.shutil, 'which', side_effect=AssertionError('no tool lookup')),
              patch.object(smoke.netns_lab, 'apply', side_effect=AssertionError('no native operation')),
              patch.object(Path, 'mkdir', side_effect=AssertionError('no write'))):
            with self.assertRaisesRegex(ValueError, 'build-receipt'):
                smoke.main(['--apply'])

    def test_status_enforces_real_effective_runtime_no_capability_promotion_and_exact_credit(self):
        smoke.validate_status(response(), 'ab' * 32)
        for mutate in [lambda v: v.update(effective=None), lambda v: v['capabilities'].update(clean_drain=True),
                       lambda v: v.update(admitted=[True, 0]), lambda v: v.update(delivered=[2, 0]),
                       lambda v: v.update(peer_delivered=[2, 0]), lambda v: v.update(digest='AB' * 32),
                       lambda v: v.update(phase='Closed'), lambda v: v.update(fault='TimedOut'),
                       lambda v: v.update(admitted=[0]), lambda v: v.update(extra=1)]:
            value = status(); mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError): smoke.validate_status(response(value))
        value = response(); value['state']['proxy'] = None
        with self.assertRaises(ValueError): smoke.validate_status(value)
        for mode, lanes in [('full', 1), ('half', 2)]:
            peers = {side: status(duplex=mode, side=side) for side in ('a', 'b')}
            self.assertTrue(smoke.confirmed(peers, lanes))
            peers['a']['peer_delivered'][0] = 0
            self.assertFalse(smoke.confirmed(peers, lanes))

    def test_natural_terminal_rejects_acceptance_signal_success_wrong_fault_late_and_nonfinite(self):
        value = {'event': 'raw_packet_terminal', 'state': status('Stopped'), 'error_kind': 'TimedOut'}
        text = json.dumps(value)
        smoke.verify_terminal(text, 1, 16, 18, 'ab' * 32)
        for code, observed, deadline in [(0, 16, 18), (-15, 16, 18), (None, 16, 18), (1, 19, 18),
                                         (1, math.nan, 18), (1, 16, math.inf)]:
            with self.subTest(code=code, observed=observed), self.assertRaises(ValueError):
                smoke.verify_terminal(text, code, observed, deadline, 'ab' * 32)
        for changed in [text + '\n' + text, text.replace('TimedOut', 'BrokenPipe'), text.replace('Stopped', 'Active')]:
            with self.assertRaises(ValueError): smoke.verify_terminal(changed, 1, 16, 18, 'ab' * 32)
        with self.assertRaises(ValueError): smoke.event('{"event":"x","event":"raw_packet_terminal"}', 'raw_packet_terminal')

    def test_original_full_half_bootstrap_phase_and_data_geometry(self):
        for lanes in (1, 2):
            value = self.inspect(underlay(lanes), lanes)
            self.assertEqual(len(value['streams']), lanes * 2)
            self.assertEqual(value['outer_fin_rst'], 0)
            self.inspect(underlay(lanes)[::-1] + underlay(lanes), lanes)
        # A ciphertext TCP segment can start 0x48 without being a phase frame.
        self.assertIsNone(smoke.phase_payload(b'\x48ciphertext', 0, 1))

    def test_acknowledged_old_prefix_keepalive_is_not_new_tls_bytes(self):
        packets = underlay()
        hello = smoke.bounded.decode_ip(packets[4][14:])
        self.inspect(packets + [outer(0, 1, hello.sequence - 1, 16, b'\x00')])
        with self.assertRaises(ValueError):
            self.inspect(packets + [outer(0, 1, hello.sequence - 2, 16, b'\x00')])

    def test_phase_rejects_wrong_context_kind_reserved_and_runtime_record(self):
        valid = phase(0, 1, 0, 4)
        smoke.phase_payload(valid, 0, 1)
        for index in (1, 6, 8, 9, 10, 46, 48, 49, 50, 94, 100):
            changed = bytearray(valid); changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError): smoke.phase_payload(bytes(changed), 0, 1)
        for changed in (valid[:-1], phase(0, 1, 0, 4, body=b'L2RP\x01\x03\0\0credit'), phase(0, 1, 0, 1, body=b'short')):
            with self.assertRaises(ValueError): smoke.phase_payload(changed, 0, 1)

    def test_capture_rejects_new_tuple_missing_data_fin_rst_nonce_overlap_gap_and_ack_change(self):
        baseline = underlay()
        tcp_data = smoke.bounded.decode_ip(baseline[4][14:])
        _, payload = smoke.tcp_parts(tcp_data)
        mutations = [baseline[:-1], baseline + [outer(0, 1, 9999, 4)],
                     baseline + [outer(0, 1, 9999, 1)],
                     baseline + [outer(1, 1, 9999, 2)],
                     baseline + [outer(0, 1, tcp_data.sequence, 24, phase(0, 1, 3, 1), int.from_bytes(tcp_data.raw[28:32], 'big'))],
                     baseline + [outer(0, 1, tcp_data.sequence, 24, payload[:-1] + b'x', 999)],
                     baseline[:2] + baseline[3:]]
        # Valid TCP checksum, invalid mirrored phase ACK.
        changed = baseline.copy(); p = smoke.bounded.decode_ip(changed[4][14:])
        changed[4] = outer(0, 1, p.sequence, p.flags, smoke.tcp_parts(p)[1], 999)
        mutations.append(changed)
        for index, packets in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError): self.inspect(packets)

    def test_cross_capture_requires_common_actual_data_and_original_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {side: Path(directory) / side for side in ('a', 'b')}
            for path in paths.values(): path.write_bytes(tls_fixture.pcap(underlay(2)))
            value = smoke.audit_captured_peers(paths, 2)
            self.assertEqual(value['common_protected_data_packets'], 2)
            changed = underlay(2)
            # Nonce-preserving body corruption in only one capture remains valid
            # untrusted structure but cannot count as the same captured Data.
            item = smoke.bounded.decode_ip(changed[6][14:])
            body = bytearray(smoke.tcp_parts(item)[1]); body[-1] ^= 1
            changed[6] = outer(0, 1, item.sequence, item.flags, body, int.from_bytes(item.raw[28:32], 'big'))
            paths['b'].write_bytes(tls_fixture.pcap(changed))
            with self.assertRaises(ValueError): smoke.audit_captured_peers(paths, 2)

    def test_native_capture_requires_exact_ipv4_ipv6_packets_payloads_and_fin(self):
        flows = smoke.case_plan('test', 'tun', 'full')['flows']
        packets = native_packets(flows)
        with tempfile.TemporaryDirectory() as directory:
            paths = {side: Path(directory) / side for side in ('a', 'b')}
            for path in paths.values(): path.write_bytes(tls_fixture.pcap(packets))
            value = smoke.audit_native(paths, flows)
            self.assertEqual(len(value['streams']), 4)
            self.assertTrue(value['exact_native_packet_multiset'])
            paths['b'].write_bytes(tls_fixture.pcap(packets[:-1]))
            with self.assertRaises(ValueError): smoke.audit_native(paths, flows)
            # Both captures agreeing on corrupted application bytes is also failure.
            changed = packets.copy(); p = smoke.bounded.decode_ip(changed[1][14:])
            body = b'wrong' + smoke.tcp_parts(p)[1][5:]
            changed[1] = ip_packet(p.source, p.destination, p.source_port, p.destination_port, p.sequence, p.flags, body)
            for path in paths.values(): path.write_bytes(tls_fixture.pcap(changed))
            with self.assertRaises(ValueError): smoke.audit_native(paths, flows)

    def test_helper_provenance_rejects_missing_stale_symlink_and_wrong_loaded_path(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory); mapping = {}
            for name in smoke.HELPERS:
                path = output / Path(name).name; path.write_text(name)
                mapping[name] = smoke.bounded.file_hash(path)
            build = {'source_sha256_after': mapping}
            self.assertEqual(smoke.verify_helpers(build, output), mapping)
            with self.assertRaises(ValueError): smoke.verify_helpers(build, output, True)
            with self.assertRaises(ValueError): smoke.verify_helpers({'source_sha256_after': {}}, output)
            path = output / 'netns_lab.py'; path.write_text('stale')
            with self.assertRaises(ValueError): smoke.verify_helpers(build, output)
            path.unlink(); path.symlink_to(output / 'raw_packet_native_smoke.py')
            with self.assertRaises(ValueError): smoke.verify_helpers(build, output)

    def test_original_raw_fd_and_port_denial_parsers_fail_closed(self):
        smoke.no_kernel_stream('ESTAB 0 0 198.19.0.1:32004 198.19.0.2:24451', 2)
        for endpoint in ('192.0.2.2:24440', '0.0.0.0:24440', '*:24440', '[::]:24440'):
            with self.assertRaises(ValueError): smoke.no_kernel_stream('LISTEN 0 1 ' + endpoint + ' *:*', 1)
        table = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 020200C0:0006 00000000:0000 07 0 0 0 0 0 123\n'
        self.assertEqual(smoke.raw_inodes(table), {'123'})
        for text in ('', 'incomplete header', table + 'truncated', 'x' * 65537):
            with self.assertRaises(ValueError): smoke.raw_inodes(text)
        smoke.no_kernel_stream('UNCONN 0 0 192.0.2.2:24440 0.0.0.0:*', 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); proc = root / '123'; (proc / 'fd').mkdir(parents=True); (proc / 'net').mkdir()
            (proc / 'stat').write_text('123 (owned test) ' + ' '.join(['S'] + ['0'] * 18 + ['42']))
            (proc / 'net/raw').write_text(table)
            (proc / 'fd/5').symlink_to('socket:[123]')
            owner = smoke.observe_owner(123, 1, proc=root)
            self.assertEqual(owner['raw_fds'], {'5': '123'})
            smoke.observe_owner(123, 1, owner, root)
            (proc / 'fd/5').unlink()
            with self.assertRaises(ValueError): smoke.observe_owner(123, 1, owner, root)
        self.assertEqual(smoke.classify(TimeoutError()), 'bound_exhausted')
        self.assertEqual(smoke.classify(smoke.bounded.Unsupported()), 'unsupported')
        self.assertEqual(smoke.classify(OSError()), 'tool_failure')
        self.assertEqual(smoke.classify(ValueError()), 'failed')

    def test_private_socket_cleanup_preserves_replaced_paths_and_live_children(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory); parent.chmod(0o700)
            identity = parent.stat(); path = parent / 'api.sock'
            owners = {path: (identity.st_dev, identity.st_ino)}
            child = SimpleNamespace(poll=lambda: None)
            with self.assertRaises(ValueError): smoke.cleanup_sockets(owners, [child])
            path.write_text('foreign replacement')
            with self.assertRaises(ValueError): smoke.cleanup_sockets(owners, [])
            self.assertEqual(path.read_text(), 'foreign replacement')
            path.unlink()
            with socket.socket(socket.AF_UNIX) as stream:
                stream.bind(str(path))
                self.assertEqual(smoke.cleanup_sockets(owners, []), [str(path)])
            self.assertFalse(path.exists())
            with self.assertRaises(ValueError): smoke.cleanup_sockets({path: (0, 0)}, [])


class OwnedLifecycleTests(unittest.TestCase):
    """Fake clocks/processes test the supervisor, never assert native qualification."""
    def exercise(self, layer='tun', duplex='half', natural=True, cleanup_error=False):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
            output = Path(directory)
            plan = smoke.case_plan('fixture', layer, duplex)
            clock, state, events = [0.], {'loss': None}, []
            sequence = [100]
            def advance(value): clock[0] += value
            class Process:
                def __init__(self, kind, log=None, side=None):
                    sequence[0] += 1
                    self.pid, self.kind, self.log, self.side = sequence[0], kind, log, side
                    self.returncode = 0 if kind == 'probe' else None
                    self.stderr = io.BytesIO() if kind == 'capture' else None
                def poll(self):
                    if (self.kind == 'daemon' and natural and self.returncode is None
                            and state['loss'] is not None and clock[0] >= state['loss'] + 15):
                        self.returncode = 1
                        value = {'event': 'raw_packet_terminal', 'state': status('Stopped', duplex, self.side), 'error_kind': 'TimedOut'}
                        with self.log.open('a') as stream: stream.write(json.dumps(value) + '\n')
                        events.append(('natural_exit', self.side))
                    return self.returncode
                def wait(self, timeout=None):
                    return self.poll()
            def command(argv, deadline, cap=15):
                advance(.002)
                if '100%' in argv and state['loss'] is None: state['loss'] = clock[0]
                if 'qdisc' in argv and 'show' in argv: return 'qdisc netem 10: parent 1:10 loss 100%'
                if '-j' in argv: return '[{"address":"02:00:00:00:00:01"}]'
                if '/proc/net/raw' in argv: return 'sl local_address inode\n'
                if 'ping' in argv: return '1 packets transmitted, 1 received, 0% packet loss'
                if 'reservation' in argv:
                    events.append(('reservation', 'released' if 'released' in argv else 'held'))
                return ''
            def capture(argv, log, deadline):
                Path(argv[argv.index('-w') + 1]).write_bytes(b'finite fake capture')
                log.write_text('ready\n')
                return Process('capture')
            def launch(argv, log):
                if 'probe' in argv:
                    i = argv.index('probe'); role = argv[i + 1]
                    source, destination, sport, dport = argv[i + 2:i + 6]
                    first, second = smoke.bounded.payload(65537, 11), smoke.bounded.payload(32771, 29)
                    sent, received = (first, second) if role == 'connect' else (second, first)
                    value = {'role': role, 'source': [source, int(sport)], 'destination': [destination, int(dport)],
                             'sent_bytes': len(sent), 'received_bytes': len(received), 'eof': True,
                             'sent_sha256': smoke.hashlib.sha256(sent).hexdigest(),
                             'received_sha256': smoke.hashlib.sha256(received).hexdigest()}
                    log.write_text('Listening\n' + json.dumps(value) + '\n')
                    return Process('probe')
                side = 'a' if 'connect' in argv else 'b'
                log.write_text(json.dumps({'event': 'raw_packet_authenticated', 'state': status('Setup', duplex, side)}) + '\n')
                return Process('daemon', log, side)
            def stop(process):
                if process.poll() is None:
                    process.returncode = -15
                    events.append(('forced', process.kind))
            def finish(process, log):
                process.returncode = 0; process.stderr.close()
                return {'captured': 1}
            def lab(operation, *_):
                if operation is smoke.netns_lab.cleanup:
                    events.append(('namespace_cleanup', clock[0]))
                    if cleanup_error: raise OSError('injected namespace cleanup failure')
            def observe(pid, lanes, previous=None):
                return {'pid': pid, 'start': '42', 'raw_fds': {str(i): str(1000 + i) for i in range(lanes)}}
            def install(target, name, **kwargs): patches.enter_context(patch.object(target, name, **kwargs))
            install(smoke.time, 'monotonic', side_effect=lambda: clock[0])
            install(smoke.time, 'sleep', side_effect=advance)
            install(smoke.bounded, 'bounded_lab', side_effect=lab)
            install(smoke.retained, 'owned', return_value={'fixture': {'inode': 42, 'device': 1}})
            install(smoke.retained, 'rules', return_value={'fixture_exact_marked_rules': True})
            install(smoke.bounded, 'command', side_effect=command)
            install(smoke.bounded, 'offloads', return_value={'fixture_disabled': True})
            install(smoke.bounded, 'disable_underlay_ipv6', return_value={})
            install(smoke.bounded, 'start_capture', side_effect=capture)
            install(smoke.bounded, 'finish_capture', side_effect=finish)
            install(smoke.bounded, 'launch', side_effect=launch)
            install(smoke.bounded, 'wait_log', return_value=None)
            install(smoke.bounded, 'rpc', side_effect=lambda path, *_: response(status(duplex=duplex, side=path.stem)))
            install(smoke.bounded, 'stop', side_effect=stop)
            install(smoke, 'observe_owner', side_effect=observe)
            install(smoke.bounded, 'read_pcap', return_value=[SimpleNamespace()])
            # Capture parsers have independent exact byte fixtures above. Here
            # only process/deadline/journal sequencing is under test.
            install(smoke, 'audit_captured_peers', return_value={'fixture_parser_tested_separately': True})
            install(smoke, 'audit_native', return_value={'fixture_parser_tested_separately': True})
            install(smoke.netns_lab, 'NETNS_DIRECTORY', new=output / 'absent-netns')
            if natural and not cleanup_error:
                value = smoke.run_case(plan, output / 'binary', output / 'harness', output, output / 'secrets', output / 'state')
                self.assertEqual(value['status'], 'passed')
                self.assertEqual(value['cleanup'], 'passed')
                self.assertFalse(value['graceful_close'])
                self.assertEqual(len(value['natural_terminal']), 2)
                self.assertEqual(len([e for e in events if e[0] == 'natural_exit']), 2)
                self.assertFalse(any(e == ('forced', 'daemon') for e in events))
                releases = [i for i, e in enumerate(events) if e == ('reservation', 'released')]
                cleanup = next(i for i, e in enumerate(events) if e[0] == 'namespace_cleanup')
                self.assertEqual(len(releases), 2)
                self.assertTrue(all(i < cleanup for i in releases))
            else:
                with self.assertRaises(RuntimeError):
                    smoke.run_case(plan, output / 'binary', output / 'harness', output, output / 'secrets', output / 'state')
                value = json.loads((output / plan['case'] / 'receipt.json').read_text())
                self.assertEqual(value['status'], 'failed' if cleanup_error else 'bound_exhausted')
                self.assertEqual(value['cleanup'], 'failed' if cleanup_error else 'passed')
                if not natural:
                    self.assertEqual(len([e for e in events if e == ('forced', 'daemon')]), 2)
                    self.assertNotIn('natural_terminal', value)
                    self.assertAlmostEqual(clock[0], value['original_loss_deadline_monotonic'])
                if cleanup_error:
                    self.assertIn('injected namespace cleanup failure', value['cleanup_error'])

    def test_all_four_clean_supervisors_require_natural_failure_then_release_before_namespace_delete(self):
        for layer in ('tap', 'tun'):
            for duplex in ('full', 'half'):
                with self.subTest(layer=layer, duplex=duplex): self.exercise(layer, duplex)

    def test_silent_peers_hit_original_loss_deadline_and_forced_cleanup_cannot_pass(self):
        self.exercise(natural=False)

    def test_namespace_cleanup_failure_preserves_failed_receipt(self):
        self.exercise(duplex='full', cleanup_error=True)


if __name__ == '__main__':
    unittest.main()
