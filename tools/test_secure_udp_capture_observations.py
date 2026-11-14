"""Finite capture observations; no live process or namespace is used.

Existing echo fingerprints and strict qualification remain separate from bounded
header observations, negative final counters and synthetic orchestration facts.
"""
import contextlib
import hashlib
import json
from pathlib import Path
import signal
import socket
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import secure_udp_native as h
from .test_secure_udp_native import (
    TailCapture, TailClock, append_capture_bytes, capture_tail_fixture, case, pcap, public,
)


def counter_log(captured=24, received=29, dropped=0):
    return (f'{captured} packets captured\n{received} packets received by filter\n'
            f'{dropped} packets dropped by kernel\n')


def ipv4_header(source, address, total, protocol=17, fragment=0x4000):
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, fragment,
        64, protocol, 0, socket.inet_aton(source), socket.inet_aton(address)))
    header[10:12] = h.bounded.checksum(header).to_bytes(2, 'big')
    return bytes(header)


def unreachable(*, udp_bytes=1480, ip_bytes=576, ports=(24461, 52659)):
    """Real type3/code3 grammar; a complete pcap may intentionally snap160 it."""
    quote = ipv4_header(h.HOST['b'], h.HOST['a'], 20 + udp_bytes)
    quote += struct.pack('!HHHH', *ports, udp_bytes, 0)
    quote += bytes(ip_bytes - 56)
    icmp = bytearray(b'\x03\x03\0\0' + bytes(4) + quote)
    icmp[2:4] = h.bounded.checksum(icmp).to_bytes(2, 'big')
    ip = ipv4_header(h.HOST['a'], h.HOST['b'], ip_bytes, protocol=1, fragment=0)
    return bytes(12) + b'\x08\x00' + ip + icmp


def repair_header(raw, start):
    length = (raw[start] & 15) * 4
    raw[start + 10:start + 12] = bytes(2)
    raw[start + 10:start + 12] = h.bounded.checksum(raw[start:start + length]).to_bytes(2, 'big')


def audit(path, side=None):
    return h.audit_capture(path, case(), side, [{'offset_ns': 0, 'uncertainty_ns': 0}])


class CounterObservationContracts(unittest.TestCase):
    def capture(self, text, code=0):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.log'
            path.write_text(text)
            child = SimpleNamespace(returncode=code)
            with patch.object(h.bounded, 'stop') as stop:
                try:
                    result = h.capture_counts(path, child)
                finally:
                    stop.assert_called_once_with(child, interrupt=True)
            return result

    def observation(self, error, counters, code, reasons):
        self.assertEqual(getattr(error, 'capture_counter_observation', None), {
            'schema': 1, 'counters': counters, 'returncode': code,
            'parse_status': 'complete', 'qualification': 'rejected',
            'qualification_reasons': reasons,
        })

    def test_success_shape_and_received_filter_tail_remain_unchanged(self):
        for code in (0, -signal.SIGINT):
            self.assertEqual(self.capture(counter_log(24, 31), code),
                {'captured': 24, 'received': 31, 'kernel_dropped': 0})

    def test_three_historical_kernel_drop_triples_remain_strict_failures(self):
        for captured, received, dropped in ((431654, 456633, 24979),
                                            (433865, 456635, 22768),
                                            (461072, 473089, 12017)):
            with self.subTest(captured=captured), self.assertRaisesRegex(h.ObservationError, 'lost packets in kernel') as caught:
                self.capture(counter_log(captured, received, dropped))
            self.observation(caught.exception, {'captured': captured, 'received': received,
                'kernel_dropped': dropped}, 0, ['kernel_dropped'])

    def test_packet_cap_and_exit_reasons_survive_the_original_first_failure(self):
        limit = h.BOUNDS['capture_packets']
        with self.assertRaisesRegex(h.BoundExhausted, 'packet ceiling') as caught:
            self.capture(counter_log(limit, limit + 1, 1), 7)
        self.observation(caught.exception, {'captured': limit, 'received': limit + 1,
            'kernel_dropped': 1}, 7, ['packet_cap', 'kernel_dropped', 'process_exit'])
        with self.assertRaisesRegex(h.ObservationError, 'tcpdump failed') as caught:
            self.capture(counter_log(24, 24), 7)
        self.observation(caught.exception, {'captured': 24, 'received': 24,
            'kernel_dropped': 0}, 7, ['process_exit'])

    def test_missing_duplicate_and_malformed_logs_never_mint_counter_observations(self):
        valid = counter_log()
        invalid = [valid.replace('24 packets captured\n', ''),
            valid + '24 packets captured\n', valid.replace('24 packets captured', '-24 packets captured'),
            valid.replace('24 packets captured', '+24 packets captured'),
            valid.replace('24 packets captured', '２４ packets captured'),
            valid.replace('24 packets captured', '2.4 packets captured'),
            valid.replace('24 packets captured', 'x24 packets captured'),
            valid.replace('24 packets captured', '24 packets captured suffix'),
            valid.replace('29 packets received', 'nan packets received')]
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(h.ObservationError) as caught:
                self.capture(text)
            self.assertFalse(hasattr(caught.exception, 'capture_counter_observation'))

    def test_unsigned_decimal_bounds_are_checked_before_unbounded_integer_work(self):
        maximum = (1 << 64) - 1
        self.assertEqual(self.capture(counter_log(0, maximum))['received'], maximum)
        for value in (str(maximum + 1), '0' * 21, '9' * 5000):
            text = counter_log().replace('29 packets received', value + ' packets received')
            with self.subTest(length=len(value)), self.assertRaises(h.ObservationError) as caught:
                self.capture(text)
            self.assertFalse(hasattr(caught.exception, 'capture_counter_observation'))

    def test_stop_or_log_read_failure_cannot_invent_a_complete_observation(self):
        child = SimpleNamespace(returncode=None)
        for action in ('stop', 'read_log'):
            with self.subTest(action=action), patch.object(h.bounded, 'stop') as stop, \
                    patch.object(h.bounded, 'read_log', return_value=counter_log()) as read:
                (stop if action == 'stop' else read).side_effect = OSError('fixture ' + action)
                with self.assertRaises(OSError) as caught:
                    h.capture_counts(Path('/fixture/capture.log'), child)
                self.assertFalse(hasattr(caught.exception, 'capture_counter_observation'))
                if action == 'stop': read.assert_not_called()

    def test_final_counter_equality_cannot_qualify_missing_or_negative_loss_evidence(self):
        h.capture_complete({'packets': 24}, {'captured': 24})
        for counters in ({'captured': 24, 'received': 30, 'kernel_dropped': 1},
                         {'captured': 24, 'kernel_dropped': -1},
                         {'captured': 24, 'kernel_dropped': False},
                         {'captured': 24, 'kernel_dropped': '0'}):
            with self.subTest(counters=counters), self.assertRaises((ValueError, h.ObservationError)):
                h.capture_complete({'packets': 24}, counters)
        for counters in ({'captured': 24}, {'captured': 24, 'received': 24},
                         {'captured': 24, 'kernel_dropped': 0},
                         {'captured': 24, 'received': True, 'kernel_dropped': 0},
                         {'captured': 24, 'received': 1 << 64, 'kernel_dropped': 0},
                         {'captured': h.BOUNDS['capture_packets'], 'received': 1 << 32,
                          'kernel_dropped': 0}):
            with self.subTest(counters=counters), self.assertRaises((ValueError, h.ObservationError, h.BoundExhausted)):
                h.capture_complete({'packets': counters['captured']}, counters, require_lossless=True)
        h.capture_complete({'packets': 24}, {'captured': 24, 'received': 29,
            'kernel_dropped': 0}, require_lossless=True)


class NativeErrorObservationContracts(unittest.TestCase):
    def test_saved_native_udp_port_unreachable_is_a_structural_observation_not_echo(self):
        root = Path(__file__).resolve().parent / 'fixtures/native_capture'
        manifest_path = root / 'port-unreachable-20261114.json'
        fixture_path = root / 'port-unreachable-20261114.pcap'
        self.assertLess(manifest_path.stat().st_size, 4096)
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest['fixture'], fixture_path.name)
        self.assertEqual(manifest['fixture_bytes'], 200)
        self.assertEqual(fixture_path.stat().st_size, 200)
        saved = fixture_path.read_bytes()
        self.assertEqual(hashlib.sha256(saved).hexdigest(),
            'ccb7f1c935ee5688b975b96a5df3be5d2692d7b5f7a3623e3d7376f28d34eca6')
        self.assertEqual(manifest['fixture_sha256'], hashlib.sha256(saved).hexdigest())
        self.assertEqual(manifest['source_record_offset'], 4920)
        self.assertEqual(manifest['source_record_bytes'], 176)
        self.assertEqual(manifest['archive_manifest_sha256'],
            '7d83d003df360d9d999199862dd5345507a2eae347211642ece8d4889f6bda81')
        self.assertEqual(manifest['source_capture_sha256'],
            '488faaa05518b765852fc3865e762ede85cb0d2fa0d94827f70d364d6fee00e4')
        self.assertEqual(manifest['source_record_sha256'], hashlib.sha256(saved[24:]).hexdigest())
        _, _, captured, original = struct.unpack('<IIII', saved[24:40])
        self.assertEqual((captured, original), (160, 590))
        self.assertEqual((manifest['captured_bytes'], manifest['original_frame_bytes']), (160, 590))
        cursor = h._NativeCaptureCursor(fixture_path)
        try:
            try:
                result = cursor.poll(terminal=True)
            except (ValueError, h.ObservationError) as error:
                self.fail('the saved valid UDP quote must be classified separately: ' + str(error))
            self.assertEqual(result, {'records_read': 1, 'at_end': True, 'incomplete': False})
            self.assertEqual((cursor.offset, cursor.packets), (200, 1))
            self.assertEqual(cursor.native_icmp, {'requests': 0, 'replies': 0, 'samples': []})
            observed = cursor.native_icmp_errors
            self.assertEqual(observed['count'], 1)
            self.assertEqual(observed['omitted'], 0)
            self.assertEqual(observed['samples'], [{
                'source': h.HOST['a'], 'address': h.HOST['b'], 'type': 3, 'code': 3,
                'ip_bytes': 576, 'quoted_source': h.HOST['b'], 'quoted_address': h.HOST['a'],
                'quoted_source_port': 24461, 'quoted_destination_port': 52659,
                'quoted_protocol': 17, 'quoted_ip_bytes': 1500, 'quoted_udp_bytes': 1480,
                'checksum_status': 'not_observed_truncated_snapshot',
            }])
        finally:
            cursor.close()
        stopped = audit(fixture_path)
        self.assertEqual(stopped['packets'], 1)
        self.assertEqual(stopped['native_icmp_errors'], observed)
        self.assertEqual(stopped['native_icmp'], {'requests': 0, 'replies': 0, 'samples': []})
        h.capture_complete(stopped, {'captured': 1, 'received': 1, 'kernel_dropped': 0}, require_lossless=True)

    def inspect(self, frames):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap(frames))
            cursor = h._NativeCaptureCursor(path)
            try:
                result = cursor.poll(terminal=True)
                self.assertTrue(result['at_end'])
                self.assertFalse(result['incomplete'])
                self.assertEqual(cursor.packets, len(frames))
                errors = cursor.native_icmp_errors
                echoes = cursor.native_icmp
                if errors['samples']:
                    changed = cursor.native_icmp_errors
                    changed['samples'][0]['source'] = 'not a packet address'
                    self.assertEqual(cursor.native_icmp_errors, errors)
            finally:
                cursor.close()
            stopped = audit(path)
            self.assertEqual(stopped['packets'], len(frames))
            self.assertEqual(stopped['native_icmp_errors'], errors)
            self.assertEqual(stopped['native_icmp'], echoes)
            h.capture_complete(stopped, {'captured': len(frames), 'received': len(frames) + 2,
                'kernel_dropped': 0})
            return errors, echoes

    def malformed(self, raw):
        prefix = bytes(12) + b'\x08\x06' + bytes(46)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap([prefix, raw]))
            cursor = h._NativeCaptureCursor(path)
            try:
                cursor.poll(max_records=1)
                before = (cursor.offset, cursor.packets, cursor.native_icmp, cursor.native_icmp_errors)
                with self.assertRaises((ValueError, h.ObservationError)):
                    cursor.poll(terminal=True)
                self.assertEqual((cursor.offset, cursor.packets, cursor.native_icmp,
                    cursor.native_icmp_errors), before)
            finally:
                cursor.close()
            with self.assertRaises((ValueError, h.ObservationError)):
                audit(path)

    def test_truncated_snapshot_error_has_only_structural_checksum_scope(self):
        errors, echoes = self.inspect([unreachable()])
        self.assertEqual(echoes, {'requests': 0, 'replies': 0, 'samples': []})
        self.assertEqual(errors, {'count': 1, 'samples': [{
            'source': h.HOST['a'], 'address': h.HOST['b'], 'type': 3, 'code': 3,
            'ip_bytes': 576, 'quoted_source': h.HOST['b'], 'quoted_address': h.HOST['a'],
            'quoted_source_port': 24461, 'quoted_destination_port': 52659,
            'quoted_protocol': 17, 'quoted_ip_bytes': 1500, 'quoted_udp_bytes': 1480,
            'checksum_status': 'not_observed_truncated_snapshot',
        }], 'omitted': 0})
        # This exported projection is copied, not writable cursor custody.
        self.assertNotIn('payload', errors['samples'][0])

    def test_complete_error_requires_its_full_icmp_checksum(self):
        raw = unreachable(ip_bytes=56)
        errors, _ = self.inspect([raw])
        self.assertEqual(errors['samples'][0]['checksum_status'], 'verified')
        bad = bytearray(raw)
        bad[36] ^= 1
        self.malformed(bytes(bad))

    def test_all_exact_supported_probe_lengths_and_both_udp_port_directions(self):
        frames = [unreachable(udp_bytes=length, ip_bytes=56, ports=ports)
            for length in (8, 9, 26, 72, 520, 1208, 1480)
            for ports in ((24461, 52659), (52659, 24461))]
        errors, echoes = self.inspect(frames)
        self.assertEqual(errors['count'], 14)
        self.assertEqual(len(errors['samples']), 14)
        self.assertEqual(errors['omitted'], 0)
        self.assertEqual(echoes['samples'], [])

    def test_error_summaries_are_bounded_and_cannot_exceed_shared_icmp_limit(self):
        errors, echoes = self.inspect([unreachable()] * 128)
        self.assertEqual(errors['count'], 128)
        self.assertEqual(len(errors['samples']), 16)
        self.assertEqual(errors['omitted'], 112)
        self.assertEqual(echoes['samples'], [])
        phases, frames, _ = capture_tail_fixture()
        self.assertEqual(len(frames), 24)
        errors, echoes = self.inspect(frames + [unreachable()] * 104)
        self.assertEqual((errors['count'], errors['omitted']), (104, 88))
        self.assertEqual(len(echoes['samples']), 24)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap(frames + [unreachable()] * 105))
            cursor = h._NativeCaptureCursor(path)
            try:
                with self.assertRaises(h.BoundExhausted): cursor.poll(terminal=True)
                self.assertEqual(cursor.packets, 128)
                self.assertEqual(cursor.native_icmp_errors['count'], 104)
                self.assertEqual(len(cursor.native_icmp['samples']), 24)
            finally:
                cursor.close()
            with self.assertRaises(h.BoundExhausted): audit(path)

    def test_malformed_or_unsupported_error_fields_fail_without_cursor_commit(self):
        original = unreachable()
        mutations = {
            'outer_version': (14, 0x65), 'outer_fragment': (20, 0x20),
            'outer_reserved_flag': (20, 0x80),
            'outer_wrong_source': (29, 3), 'type': (34, 11), 'code': (35, 1),
            'unused': (38, 1), 'quoted_version': (42, 0x65), 'quoted_ihl': (42, 0x46),
            'quoted_fragment': (48, 0x20), 'quoted_protocol': (51, 6),
            'quoted_reserved_flag': (48, 0x80),
            'quoted_source': (57, 9), 'quoted_destination': (61, 9),
            'quoted_ip_extent': (45, 0xDB), 'quoted_udp_extent': (67, 0xC7),
        }
        for name, (at, value) in mutations.items():
            raw = bytearray(original)
            raw[at] = value
            if name.startswith('quoted_') and name not in ('quoted_version', 'quoted_ihl'):
                repair_header(raw, 42)
            if name.startswith('outer_') and name != 'outer_version':
                repair_header(raw, 14)
            with self.subTest(mutation=name): self.malformed(bytes(raw))
        for length in (7, 10, 1479, 1481):
            raw = unreachable(udp_bytes=length, ip_bytes=56)
            with self.subTest(length=length): self.malformed(raw)
        for ports in ((0, 24461), (24461, 0), (24461, 24461), (24440, 52659)):
            with self.subTest(ports=ports): self.malformed(unreachable(ports=ports))

    def test_supported_outer_options_still_cannot_enter_fixed_error_layout(self):
        raw = bytearray(unreachable())
        raw[34:34] = b'\x94\x04\0\0'
        raw[14] = 0x46
        raw[16:18] = (580).to_bytes(2, 'big')
        repair_header(raw, 14)
        self.malformed(bytes(raw))
        # More quoted bytes than the original entire UDP packet would require
        # extension semantics, which this narrow historical grammar refuses.
        self.malformed(unreachable(udp_bytes=8, ip_bytes=64))

    def test_outer_or_quoted_header_checksum_and_truncated_quote_are_not_context(self):
        for name, at in (('outer', 24), ('quoted', 52)):
            raw = bytearray(unreachable())
            raw[at] ^= 1
            with self.subTest(checksum=name): self.malformed(bytes(raw))
        raw = bytearray(unreachable(ip_bytes=56))
        # A complete short IP message with only seven quoted UDP bytes has no
        # snap truncation excuse: the declared pcap/IP extents are consistent.
        del raw[-1:]
        raw[16:18] = (55).to_bytes(2, 'big')
        repair_header(raw, 14)
        self.malformed(bytes(raw))

    def test_error_cannot_substitute_for_or_relax_any_exact_echo_key(self):
        phases, frames, _ = capture_tail_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap(frames[:-1] + [frames[0], unreachable()]))
            stopped = audit(path)
            self.assertEqual(stopped['native_icmp_errors']['count'], 1)
            self.assertEqual(len(stopped['native_icmp']['samples']), 24)
            with self.assertRaisesRegex(ValueError, 'missing exact'):
                h.icmp_capture_complete(stopped, phases)
        # A probe with its type changed is not a valid quoted UDP error.
        corrupt = bytearray(frames[0])
        corrupt[34:36] = b'\x03\x03'
        self.malformed(bytes(corrupt))

    def test_native_error_cannot_enter_protected_wan_error_grammar(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap([unreachable()]))
            with self.assertRaises(ValueError): audit(path, 'a')


class ErrorTailContracts(unittest.TestCase):
    def drain(self, process, path, phases, clock, deadline):
        return h.drain_native_capture(process, path, phases, deadline,
            clock=clock, sleeper=clock.sleep)

    def test_errors_before_between_and_after_echoes_preserve_all_twenty_four_keys(self):
        phases, echoes, _ = capture_tail_fixture()
        frames = [unreachable()] + echoes[:12] + [unreachable(ip_bytes=56)] + echoes[12:] + [unreachable()]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap(frames))
            clock = TailClock()
            drained = self.drain(TailCapture(), path, phases, clock, 10.25)
            self.assertEqual((drained['status'], drained['matched_keys'], drained['packets']), ('passed', 24, 27))
            self.assertEqual(clock.sleeps, [])
            self.assertEqual(drained['native_icmp_errors']['count'], 3)
            stopped = audit(path)
            self.assertEqual(stopped['native_icmp_errors']['count'], 3)
            self.assertEqual(len(stopped['native_icmp']['samples']), 24)
            self.assertEqual(len(h.icmp_capture_complete(stopped, phases)['probes']), 4)
            h.capture_complete(stopped, {'captured': 27, 'received': 30, 'kernel_dropped': 0})
            with self.assertRaises(ValueError): h.capture_complete(stopped, {'captured': 26})

    def test_all_echo_keys_wait_for_an_incomplete_following_error_record(self):
        phases, echoes, _ = capture_tail_fixture()
        prefix = pcap(echoes)
        record = pcap([unreachable()])[24:]
        for cut in (7, 31, len(record) - 1):
            with self.subTest(cut=cut), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(prefix + record[:cut])
                clock = TailClock()
                clock.at(10.02, lambda: append_capture_bytes(path, record[cut:]))
                result = self.drain(TailCapture(), path, phases, clock, 10.25)
                self.assertEqual((result['matched_keys'], result['packets']), (24, 25))
                self.assertGreaterEqual(clock.now, 10.02)
                stopped = audit(path)
                self.assertEqual(stopped['native_icmp_errors']['count'], 1)
                self.assertEqual(len(h.icmp_capture_complete(stopped, phases)['probes']), 4)

    def test_incomplete_error_record_remains_live_then_fails_terminal_without_adoption(self):
        phases, echoes, _ = capture_tail_fixture()
        prefix = pcap(echoes)
        record = pcap([unreachable()])[24:]
        for cut in (7, 31, len(record) - 1):
            with self.subTest(cut=cut), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(prefix + record[:cut])
                cursor = h._NativeCaptureCursor(path)
                try:
                    result = cursor.poll()
                    self.assertTrue(result['incomplete'])
                    self.assertEqual((cursor.offset, cursor.packets), (len(prefix), 24))
                    self.assertEqual(cursor.native_icmp_errors, {'count': 0, 'samples': [], 'omitted': 0})
                    with self.assertRaises(ValueError): cursor.poll(terminal=True)
                    self.assertEqual((cursor.offset, cursor.packets), (len(prefix), 24))
                finally:
                    cursor.close()
                with self.assertRaises(ValueError): audit(path)

    def test_error_only_and_duplicate_echoes_cannot_obtain_drain_success(self):
        phases, frames, _ = capture_tail_fixture()
        for raw, expected in ((pcap([unreachable()]), 0),
                              (pcap(frames[:-1] + [frames[0], unreachable()]), 23)):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(raw)
                clock = TailClock()
                with self.assertRaises(h.BoundExhausted) as caught:
                    self.drain(TailCapture(), path, phases, clock, 10.04)
                self.assertEqual(caught.exception.capture_drain['matched_keys'], expected)
                self.assertEqual(caught.exception.capture_drain['original_deadline'], 10.04)
                self.assertGreaterEqual(clock.now, 10.04)

    def test_exact_deadline_tail_and_stopped_producer_cannot_renew_or_fake_success(self):
        phases, echoes, _ = capture_tail_fixture()
        prefix = pcap(echoes)
        record = pcap([unreachable()])[24:]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(prefix + record[:7])
            clock = TailClock()
            clock.at(10.04, lambda: append_capture_bytes(path, record[7:]))
            with self.assertRaises(h.BoundExhausted) as caught:
                self.drain(TailCapture(), path, phases, clock, 10.04)
            self.assertEqual(caught.exception.capture_drain['matched_keys'], 24)
            self.assertEqual(caught.exception.capture_drain['original_deadline'], 10.04)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(pcap([unreachable()]))
            clock = TailClock()
            with self.assertRaises(h.ObservationError):
                self.drain(TailCapture(0), path, phases, clock, 10.25)
            self.assertEqual(clock.sleeps, [])

    def test_shared_resource_failure_closes_cursor_and_preserves_twenty_four_keys(self):
        phases, frames, _ = capture_tail_fixture()
        raw = pcap(frames + [unreachable()] * 105)
        closed = []
        original_close = h._NativeCaptureCursor.close

        def close(cursor):
            closed.append(cursor.offset)
            original_close(cursor)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.pcap'
            path.write_bytes(raw)
            clock = TailClock()
            with patch.object(h._NativeCaptureCursor, 'close', close), self.assertRaises(h.BoundExhausted) as caught:
                self.drain(TailCapture(), path, phases, clock, 10.25)
            self.assertEqual(caught.exception.capture_drain['matched_keys'], 24)
            self.assertEqual(caught.exception.capture_drain['packets'], 128)
            self.assertEqual(caught.exception.capture_drain['native_icmp_errors']['count'], 104)
            self.assertEqual(len(closed), 1)
            self.assertEqual(clock.sleeps, [])

    def test_committed_error_custody_does_not_survive_path_replacement_or_shrink(self):
        raw = pcap([unreachable()])
        for mutation in ('replace', 'shrink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.pcap'
                path.write_bytes(raw)
                cursor = h._NativeCaptureCursor(path)
                try:
                    cursor.poll()
                    before = (cursor.offset, cursor.packets, cursor.native_icmp_errors)
                    if mutation == 'replace':
                        replacement = path.with_suffix('.new')
                        replacement.write_bytes(raw)
                        replacement.replace(path)
                    else:
                        path.write_bytes(raw[:30])
                    with self.assertRaises(h.ObservationError): cursor.poll()
                    self.assertEqual((cursor.offset, cursor.packets, cursor.native_icmp_errors), before)
                finally:
                    cursor.close()


class CaptureFinalizationContracts(unittest.TestCase):
    def orchestration(self, *, drops=False, publication_failure=False):
        # Exercise actual run_case finally handling with only fake external
        # operations. Trusted phase-shaped fixtures do not claim live probe work.
        phases, _, _ = capture_tail_fixture()
        original_receipt = h.bounded.Receipt
        original_exists, original_read = Path.exists, Path.read_text
        events, children = [], []
        spec = h.lab.LabSpec('unit')
        journal = Path('/run/l2tunnel-secure-native/unit.json')
        namespaces = {h.lab.NETNS_DIRECTORY / name for name in spec.namespaces.values()}
        triples = {'wan-a': (431654, 456633, 24979), 'wan-b': (433865, 456635, 22768),
                   'native-a': (461072, 473089, 12017)}

        def receipt(path, initial):
            actual = original_receipt(path, {**initial, **phases, 'retained_sentinel': 'earlier evidence'})
            update = actual.update

            def retain(**fields):
                if publication_failure and 'capture_counter_observations' in fields:
                    raise OSError('fixture counter observation publication failure')
                update(**fields)

            actual.update = retain
            return actual

        def exists(path):
            if path == journal: return True
            if path in namespaces: return False
            return original_exists(path)

        def read(path, *args, **kwargs):
            return '{}' if path == journal else original_read(path, *args, **kwargs)

        def launch(argv, log, **kwargs):
            if len(children) == 4: raise ValueError('original daemon startup failure')
            child = TailCapture()
            child.name = Path(log).stem
            children.append(child)
            name = child.name.removesuffix('-capture')
            triple = triples[name] if drops and name in triples else (24, 31, 0)
            Path(log).write_text(counter_log(*triple))
            return child

        def stop(child, **kwargs):
            events.append(('stop', child.name))
            child.returncode = 0

        def drain(process, path, supplied_phases, deadline, **kwargs):
            self.assertIs(process, children[2])
            self.assertEqual(deadline, 340.0)
            self.assertIn(('stop', 'daemon-b'), events)
            self.assertFalse(any(name.endswith('-capture') for event, name in events if event == 'stop'))
            events.append(('drain', 'native-a'))
            return {'status': 'passed', 'matched_keys': 24, 'expected_keys': 24, 'packets': 24,
                'native_icmp_errors': {'count': 0, 'samples': [], 'omitted': 0}}

        def stopped_audit(path, *args, **kwargs):
            events.append(('audit', path.stem))
            self.assertTrue(all(child.returncode == 0 for child in children))
            return {'packets': triples[path.stem][0] if drops else 24, 'arp': 1,
                'native_icmp': {'samples': []}, 'native_icmp_errors': {'count': 0, 'samples': [], 'omitted': 0}}

        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            output = Path(directory)
            (output / 'l2tunnel-native').write_bytes(b'fixture binary')
            (output / 'build-receipt.json').write_text('{}')
            replacements = [patch.object(Path, 'exists', exists), patch.object(Path, 'read_text', read),
                patch.object(h.time, 'monotonic', return_value=100.0),
                patch.object(h.bounded, 'Receipt', side_effect=receipt),
                patch.object(h, 'verify_helpers', return_value={}),
                patch.object(h.shutil, 'which', return_value='/fixture/tool'),
                patch.object(h.bounded, 'command', return_value='fixture command output'),
                patch.object(h, 'resource_context', return_value={}), patch.object(h.bounded, 'bounded_lab'),
                patch.object(h.bounded, 'disable_underlay_ipv6'), patch.object(h.bounded, 'offloads', return_value={}),
                patch.object(h, 'recreate_owned_wan', return_value={}), patch.object(h, 'record_tc_snapshot'),
                patch.object(h.bounded, 'launch', side_effect=launch), patch.object(h.bounded, 'wait_log'),
                patch.object(h, 'credentials', return_value=public()), patch.object(h.bounded, 'stop', side_effect=stop),
                patch.object(h, 'drain_native_capture', side_effect=drain),
                patch.object(h, 'audit_capture', side_effect=stopped_audit),
                patch.object(h, 'icmp_capture_complete', return_value={'probes': []})]
            for replacement in replacements: stack.enter_context(replacement)
            result = h.run_case(case(), output, {}, {'fixture': True})
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['cleanup'], 'passed')
        self.assertEqual(result['retained_sentinel'], 'earlier evidence')
        self.assertEqual(result['native_capture_drain']['status'], 'passed')
        messages = [entry.get('error', '') for entry in result['errors']]
        self.assertTrue(any('original daemon startup failure' in value for value in messages))
        self.assertEqual([event for event, _ in events].count('audit'), 3)
        if not drops:
            self.assertEqual(set(result['capture_audits']), {'wan-a', 'wan-b', 'native-a'})
        self.assertTrue(all(child.returncode == 0 for child in children))
        if publication_failure:
            self.assertTrue(any('fixture counter observation publication failure' in value for value in messages))
        else:
            observations = result['capture_counter_observations']
            self.assertEqual(set(observations), {'wan-a', 'wan-b', 'native-a'})
            for name in observations:
                captured, received, dropped = triples[name] if drops else (24, 31, 0)
                self.assertEqual(observations[name], {'schema': 1,
                    'counters': {'captured': captured, 'received': received, 'kernel_dropped': dropped},
                    'returncode': 0, 'parse_status': 'complete',
                    'qualification': 'rejected' if drops else 'passed',
                    'qualification_reasons': ['kernel_dropped'] if drops else []})
        if drops:
            self.assertEqual(sum('capture lost packets in kernel' in value for value in messages), 3)
            self.assertTrue(all(name + '_capture_counters' not in result for name in triples))
        else:
            self.assertTrue(all(name + '_capture_counters' in result for name in triples))

    def test_passed_echo_drain_cannot_hide_three_real_negative_counter_observations(self):
        self.orchestration(drops=True)

    def test_successful_counter_returns_also_have_separate_complete_observations(self):
        self.orchestration()

    def test_observation_publication_failure_keeps_original_errors_and_cleanup(self):
        self.orchestration(drops=True, publication_failure=True)


if __name__ == '__main__':
    unittest.main()
