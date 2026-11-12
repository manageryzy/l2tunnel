"""Unprivileged regression tests for raw native qualification evidence."""
from contextlib import redirect_stdout
import io
import copy
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from tools import raw_native_smoke as smoke


def record(kind: int, body: bytes) -> bytes:
    return struct.pack('!BBBH', kind, 3, 3, len(body)) + body


def hello(extensions: bytes = b'\x00\x2b\x00\x03\x02\x03\x04') -> bytes:
    body = b'\x03\x03' + bytes(32) + b'\x00\x00\x02\x13\x01\x01\x00'
    body += len(extensions).to_bytes(2, 'big') + extensions
    return b'\x01' + len(body).to_bytes(3, 'big') + body


def packet(reverse: bool, sequence: int, flags: int, data: bytes = b'',
           port_delta: int = 0, acknowledgment: int = 0) -> bytes:
    source, destination = ('192.0.2.6', '192.0.2.2') if reverse else ('192.0.2.2', '192.0.2.6')
    sport, dport = (24441, 24440) if reverse else (24440, 24441)
    tcp = struct.pack('!HHIIBBHHH', sport + port_delta, dport, sequence & 0xffffffff,
                      acknowledgment & 0xffffffff, 0x50, flags, 65535, 0, 0) + data
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(source), socket.inet_aton(destination))
    return bytes(12) + b'\x08\x00' + ip + tcp


def pcap(packets: list[bytes]) -> bytes:
    output = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, item in enumerate(packets):
        output += struct.pack('<IIII', index, 0, len(item), len(item)) + item
    return bytes(output)


def streams() -> tuple[bytes, bytes]:
    return (record(22, hello()) + record(23, b'client authenticated ciphertext'),
            record(22, b'\x02server hello') + record(23, b'server authenticated ciphertext'))


def baseline() -> list[bytes]:
    client, server = streams()
    # Sequence wraps while payload is reordered and duplicated in the capture.
    return [packet(False, 0xfffffff0, 2), packet(True, 99, 0x12),
            packet(False, 0xfffffff0, 2), packet(False, 0xfffffff1 + 40, 0x18, client[40:]),
            packet(True, 100, 0x18, server), packet(False, 0xfffffff1, 0x18, client[:40]),
            packet(False, 0xfffffff1 + 20, 0x18, client[20:60])]


def drain_proof(local: int = 3, remote: int = 5, lanes: int = 1) -> dict:
    return {'kind': 'raw_native_drained', 'status': 'passed', 'raw_drivers_clean': lanes,
            'native': {'local_admitted': local, 'local_handed': local, 'local_flushed': local,
                       'peer_barrier': remote, 'native_confirmed': remote, 'local_barrier': local,
                       'local_ack': remote, 'peer_ack': local, 'tls_lanes_closed': lanes},
            'drivers': [{'received_packets': 10, 'sent_packets': 10, 'discarded_packets': 0,
                         'sent_bytes': 1024, 'received_bytes': 1024} for _ in range(lanes)],
            'bounds': {'native_tls_seconds': 30, 'additional_driver_seconds': 45, 'request_seconds': 5}}


class RawNativeEvidenceTests(unittest.TestCase):
    def inspect(self, contents: bytes, lanes: int = 1) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bounded.pcap'
            path.write_bytes(contents)
            return smoke.inspect_capture(path, lanes)

    def test_marked_selection_is_explicit_bounded_and_dry_run(self) -> None:
        for text, expected in [('1', 1), ('0x12aa0001', 0x12aa0001), ('4294967295', 0xffffffff)]:
            self.assertEqual(smoke.mark_value(text), expected)
        for text in ('0', '0x0', '', '-1', '+1', ' 1', '1 ', '0X12', '0x', '0x100000000', '4294967296', 'é'):
            with self.subTest(text=text), self.assertRaises(smoke.argparse.ArgumentTypeError):
                smoke.mark_value(text)
        output=io.StringIO()
        with (patch('sys.argv',['raw_native_smoke.py','--raw-mark','0x12aa0001']),
              patch.object(smoke,'command',side_effect=AssertionError('must not execute')),
              patch.object(Path,'mkdir',side_effect=AssertionError('must not write')),
              redirect_stdout(output)):
            self.assertEqual(smoke.main(),0)
        result=json.loads(output.getvalue())
        self.assertEqual(result['socket_mark'],0x12aa0001)
        self.assertEqual(result['reset_policy'],'marked-v1')

    def test_marked_rules_require_exact_complete_canonical_chain(self) -> None:
        spec=smoke.netns_lab.LabSpec('mark-test')
        def chain(argv, changed=''):
            if '-S' not in argv:
                return ''
            first=argv[3]==spec.namespaces['endpoint_a']
            local,peer,sport,dport=('192.0.2.2','192.0.2.6',24440,24441) if first else ('192.0.2.6','192.0.2.2',24441,24440)
            value=f'-P OUTPUT ACCEPT\n-A OUTPUT -s {local}/32 -d {peer}/32 -p tcp -m tcp --sport {sport} --dport {dport} --tcp-flags RST RST -m mark ! --mark 0x12aa0001 -j DROP\n'
            if changed=='mark':return value.replace('0x12aa0001','0x12aa0002')
            if changed=='mask':return value.replace('0x12aa0001','0x12aa0001/0xff')
            if changed=='extra':return value+'-A OUTPUT -j ACCEPT\n'
            if changed=='broad':return value.replace('/32','/24')
            return value
        with patch.object(smoke,'command',side_effect=chain) as command:
            self.assertEqual(set(smoke.rules(spec,1,False,0x12aa0001)),{'a','b'})
            checks=[call.args[0] for call in command.call_args_list if '-C' in call.args[0]]
            self.assertEqual(len(checks),2)
            self.assertTrue(all('!' in call and '--mark' in call for call in checks))
        for changed in ('mark','mask','extra','broad'):
            with self.subTest(changed=changed), patch.object(smoke,'command',side_effect=lambda argv:chain(argv,changed)), self.assertRaises(RuntimeError):
                smoke.rules(spec,1,False,0x12aa0001)
        with patch.object(smoke,'command',side_effect=AssertionError('invalid mark before I/O')):
            for mark in (0,True,2**32,-1):
                with self.assertRaises(ValueError):smoke.rules(spec,1,False,mark)
        legacy=smoke.rule_args('192.0.2.2','192.0.2.6',24440,24441,None)
        self.assertNotIn('--mark',legacy)
        self.assertEqual(legacy[-5:],['--tcp-flags','RST','RST','-j','DROP'])

    def test_exact_native_and_raw_fences_require_both_clean_helpers(self) -> None:
        for lanes in (1, 2):
            peers = {'a': drain_proof(lanes=lanes), 'b': drain_proof(5, 3, lanes)}
            smoke.verify_peer_drains(peers, lanes)
            mutations = [
                lambda value: value['a']['native'].__setitem__('local_flushed', 2),
                lambda value: value['a']['native'].__setitem__('native_confirmed', 4),
                lambda value: value['a']['native'].__setitem__('peer_ack', True),
                lambda value: value['a'].__setitem__('raw_drivers_clean', 0),
                lambda value: value['a']['drivers'][0].__setitem__('received_bytes', 1023),
                lambda value: value['a']['drivers'].pop(),
                lambda value: value['a']['native'].__setitem__('tls_lanes_closed', 0),
                lambda value: value.pop('b'),
                lambda value: value['a']['bounds'].__setitem__('native_tls_seconds', 300),
            ]
            for mutate in mutations:
                changed = copy.deepcopy(peers)
                mutate(changed)
                with self.assertRaises(ValueError):
                    smoke.verify_peer_drains(changed, lanes)
            # Each endpoint is individually consistent but disagrees with its peer.
            peers['b'] = drain_proof(5, 4, lanes)
            with self.assertRaises(ValueError):
                smoke.verify_peer_drains(peers, lanes)

    def test_both_private_requests_precede_reply_wait_and_replies_are_bounded(self) -> None:
        for bad in (False, True):
            with tempfile.TemporaryDirectory(prefix='l2t-drain-test-') as directory:
                paths = {side: Path(directory) / side for side in ('a', 'b')}
                listeners = {}
                for side, path in paths.items():
                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    listener.bind(str(path)); listener.listen(1); listener.settimeout(2)
                    listeners[side] = listener
                errors = []
                def serve() -> None:
                    clients = {}
                    try:
                        for side, listener in listeners.items():
                            clients[side], _ = listener.accept()
                            clients[side].settimeout(2)
                        # Neither response is sent until both requests and write EOF
                        # arrived: a wait-after-first-request implementation deadlocks.
                        for connection in clients.values():
                            request = bytearray()
                            while chunk := connection.recv(16):
                                request.extend(chunk)
                            if request != b'DRAIN1\n':
                                raise AssertionError(request)
                        for side, connection in clients.items():
                            proof = drain_proof() if side == 'a' else drain_proof(5, 3)
                            raw = b'X' * 8193 if bad and side == 'a' else json.dumps(proof).encode() + b'\n'
                            connection.sendall(raw); connection.shutdown(socket.SHUT_WR)
                    except Exception as error:
                        errors.append(error)
                    finally:
                        for connection in clients.values(): connection.close()
                worker = threading.Thread(target=serve)
                worker.start()
                receipt = {}
                try:
                    if bad:
                        with self.assertRaises(ValueError):
                            smoke.drain_helpers(paths, receipt, 1, time.monotonic() + 2)
                    else:
                        smoke.drain_helpers(paths, receipt, 1, time.monotonic() + 2)
                        smoke.verify_peer_drains(receipt['peers'], 1)
                finally:
                    worker.join(timeout=3)
                    for listener in listeners.values(): listener.close()
                self.assertFalse(worker.is_alive())
                self.assertFalse(errors)

    def test_dry_run_never_executes_or_writes(self) -> None:
        output = io.StringIO()
        with (patch('sys.argv', ['raw_native_smoke.py', '--layers', 'tun', '--duplex', 'full']),
              patch.object(smoke, 'command', side_effect=AssertionError('must not execute')),
              patch.object(smoke.netns_lab, 'apply', side_effect=AssertionError('must not mutate')),
              patch.object(Path, 'mkdir', side_effect=AssertionError('must not write')),
              redirect_stdout(output)):
            self.assertEqual(smoke.main(), 0)
        self.assertEqual(json.loads(output.getvalue())['cases'], [['tun', 'full', False]])

    def test_single_diagnostic_case_selection_does_not_repeat_clean_cases(self) -> None:
        output = io.StringIO()
        with (patch('sys.argv', ['raw_native_smoke.py', '--layers', 'tap', '--include-netem', '--only-case', 'tap-half-netem']),
              patch.object(smoke, 'command', side_effect=AssertionError('must not execute')),
              patch.object(Path, 'mkdir', side_effect=AssertionError('must not write')),
              redirect_stdout(output)):
            self.assertEqual(smoke.main(), 0)
        self.assertEqual(json.loads(output.getvalue())['cases'], [['tap', 'half', True]])

    def test_exact_capture_counts_reject_drops_substrings_and_exhaustion(self) -> None:
        valid = 'tcpdump: listening on wan0\n12 packets captured\n14 packets received by filter\n0 packets dropped by kernel\n'
        self.assertEqual(smoke.capture_counts(valid)['captured'], 12)
        for bad in (valid.replace('0 packets dropped', '10 packets dropped'),
                    valid.replace('0 packets dropped', '100 packets dropped'),
                    valid.replace('12 packets captured', '0 packets captured'),
                    valid.replace('12 packets captured', '4096 packets captured'),
                    valid + '0 packets dropped by kernel\n',
                    valid.replace('14 packets received by filter\n', '')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                smoke.capture_counts(bad)

    def test_tls_records_require_complete_hello_and_encrypted_continuation(self) -> None:
        client, _ = streams()
        self.assertEqual(len(smoke.tls_records(client)), 2)
        for bad in (b'', client[:-1], client[:3], record(22, hello()),
                    record(23, b'ciphertext'), b'\x16\x03\x03\x48\x01'):
            with self.subTest(bad=bad[:8]), self.assertRaises(ValueError):
                smoke.tls_records(bad)

    def test_no_sni_parser_rejects_sni_and_malformed_lengths(self) -> None:
        smoke.client_hello_without_sni(hello())
        for bad in (hello(b'\x00\x00\x00\x00'), hello()[:-1],
                    hello(b'\x00\x2b\x00\x05\x01'), hello(b'\x00'), b'\x02' + hello()[1:]):
            with self.subTest(bad=bad[-8:]), self.assertRaises(ValueError):
                smoke.client_hello_without_sni(bad)

    def test_retained_tuple_handles_wrap_reorder_and_exact_retransmission(self) -> None:
        evidence = self.inspect(pcap(baseline()))
        self.assertEqual(evidence['packets'], 7)
        self.assertEqual(len(evidence['streams']), 2)
        self.assertEqual([row['stream_bytes'] for row in evidence['streams']],
                         [len(item) for item in streams()])
        self.assertTrue(all(row['sequence_overlap_exact'] for row in evidence['streams']))

    def test_conflicting_retransmission_and_sequence_gap_fail(self) -> None:
        client, _ = streams()
        conflicting = baseline() + [packet(False, 0xfffffff1 + 20, 0x18, b'X' + client[21:30])]
        gap = baseline()
        gap[3] = packet(False, 0xfffffff1 + len(client) + 1, 0x18, b'gap')
        for packets in (conflicting, gap):
            with self.assertRaises(ValueError):
                self.inspect(pcap(packets))

    def test_acknowledged_garbage_keepalive_is_not_tls_stream_data(self) -> None:
        client, server = streams()
        end = (0xfffffff1 + len(client)) & 0xffffffff
        probe = packet(False, end - 1, 16, b'\x00')
        acknowledged = baseline() + [packet(True, 100 + len(server), 16, acknowledgment=end), probe]
        result = self.inspect(pcap(acknowledged))
        self.assertEqual(result['streams'][0]['acknowledged_keepalive_probes'], 1)
        self.assertEqual(result['streams'][0]['stream_bytes'], len(client))
        with self.assertRaises(ValueError):
            self.inspect(pcap(baseline() + [probe]))
        # PSH or an unacknowledged sequence remains ordinary data and must agree.
        with self.assertRaises(ValueError):
            self.inspect(pcap(acknowledged[:-1] + [packet(False, end - 1, 0x18, b'\x00')]))

    def test_second_syn_reset_missing_or_foreign_tuple_fail(self) -> None:
        for packets in (baseline() + [packet(False, 999, 2)],
                        baseline() + [packet(False, 0, 4)],
                        baseline() + [packet(False, 0, 2, port_delta=1)],
                        [row for row in baseline() if row[26:30] != socket.inet_aton('192.0.2.6')]):
            with self.assertRaises(ValueError):
                self.inspect(pcap(packets))

    def test_capture_truncation_header_and_work_bounds_fail(self) -> None:
        valid = pcap(baseline())
        bad_length = bytearray(valid)
        struct.pack_into('<I', bad_length, 24 + 8, 65536)
        bad_ethernet = bytearray(valid)
        struct.pack_into('<I', bad_ethernet, 20, 101)
        for bad in (valid[:8], valid[:-1], bytes(bad_length), bytes(bad_ethernet),
                    pcap([packet(False, 1, 2)] * 4097)):
            with self.assertRaises(ValueError):
                self.inspect(bad)
        for lanes in (0, 3):
            with self.assertRaises(ValueError):
                self.inspect(valid, lanes)

    def test_ping_counts_do_not_accept_ten_received_as_one(self) -> None:
        smoke.ping_counts('1 packets transmitted, 1 received, 0% packet loss')
        for bad in ('10 packets transmitted, 10 received, 0% packet loss',
                    '1 packets transmitted, 0 received, 100% packet loss'):
            with self.assertRaises(ValueError):
                smoke.ping_counts(bad)


if __name__ == '__main__':
    unittest.main()
