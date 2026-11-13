"""Strict receipt tests use safe fixtures, never CPU measurements."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from tools import secure_record_perf as perf


def result(iterations=3, duration=1000):
    cases = []
    for appearance, cover in perf.APPEARANCES.items():
        for protection, tag in perf.PROTECTIONS.items():
            for body in perf.BODIES:
                elapsed, payload = iterations * duration, iterations * body
                packet = body + 9 + 10 + tag + cover
                cases.append({'appearance': appearance, 'protection': protection,
                              'body_bytes': body, 'iterations': iterations,
                              'elapsed_ns': elapsed, 'payload_bytes': payload,
                              'packet_bytes': packet,
                              'modeled_ipv4_wire_bytes': iterations * (packet + 28),
                              'ns_per_round_trip': round(elapsed / iterations, 3),
                              'payload_round_trip_gbit_per_second': round(payload * 8 / elapsed, 6)})
    return {'scope': perf.SCOPE, 'cases': cases}


class ValidationTests(unittest.TestCase):
    def validate(self, data):
        return perf.validate_result(json.dumps(data).encode(), 3)

    def test_exact_cases_and_rounded_metrics(self):
        data = result()
        self.assertEqual(self.validate(data), data)
        case = data['cases'][0]
        case['elapsed_ns'] = 3100
        case['ns_per_round_trip'] = round(3100 / 3, 3)
        case['payload_round_trip_gbit_per_second'] = round(case['payload_bytes'] * 8 / 3100, 6)
        self.assertEqual(self.validate(data), data)
        data = result(duration=10 ** 15)
        self.assertEqual(self.validate(data), data)

    def test_missing_duplicate_unknown_and_extra_cases_or_fields(self):
        for mutation in range(6):
            data = result()
            if mutation == 0:
                data['cases'].pop()
            elif mutation == 1:
                data['cases'][1] = data['cases'][0]
            elif mutation == 2:
                data['cases'][0]['appearance'] = 'unknown'
            elif mutation == 3:
                data['cases'][0]['extra'] = 1
            elif mutation == 4:
                data['extra'] = 1
            else:
                data['scope'] = 'network throughput'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.validate(data)

    def test_integer_fields_reject_booleans_and_wrong_counts(self):
        for field in ('body_bytes', 'iterations', 'elapsed_ns', 'payload_bytes',
                      'packet_bytes', 'modeled_ipv4_wire_bytes'):
            for value in (True, False, 0, -1, 1.5):
                data = result()
                data['cases'][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.validate(data)
        for field in ('iterations', 'payload_bytes', 'packet_bytes', 'modeled_ipv4_wire_bytes'):
            data = result()
            data['cases'][0][field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(data)

    def test_nonfinite_negative_boolean_and_inconsistent_metrics(self):
        for field in ('ns_per_round_trip', 'payload_round_trip_gbit_per_second'):
            for value in (True, False, float('nan'), float('inf'), -float('inf'), -1, '1000', 99999):
                data = result()
                data['cases'][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.validate(data)
        data = result()
        data['cases'][0]['elapsed_ns'] = 10 ** 400
        with self.assertRaises(ValueError):
            self.validate(data)

    def test_previous_route_wrong_tag_cover_and_wire_cost_fail(self):
        for appearance in perf.APPEARANCES:
            for protection in perf.PROTECTIONS:
                for delta in (1, 16, 32):
                    data = result()
                    case = next(case for case in data['cases']
                                if case['appearance'] == appearance and case['protection'] == protection)
                    case['packet_bytes'] += delta
                    case['modeled_ipv4_wire_bytes'] += 3 * delta
                    with self.subTest(delta=delta), self.assertRaises(ValueError):
                        self.validate(data)

    def test_duplicate_keys_nonfinite_exponent_and_invalid_encoding(self):
        encoded = json.dumps(result())
        invalid = (encoded.replace('"iterations": 3', '"iterations": 3, "iterations": 3', 1).encode(),
                   encoded.replace('1000.0', '1e999', 1).encode(), b'\xff', b'[]', b'{}')
        for raw in invalid:
            with self.subTest(raw=raw[:80]), self.assertRaises((ValueError, UnicodeError)):
                perf.validate_result(raw, 3)


@unittest.skipUnless(os.name == 'posix', 'safe executable fixtures require POSIX shebang support')
class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'tools' / 'fixture.txt'
        self.source.parent.mkdir()
        self.source.write_text('original source')
        self.binary = self.root / 'fake-bench'
        self.output = self.root / 'receipt'
        identity = patch.object(perf.record_check, 'ROOT', self.root)
        identity.start()
        self.addCleanup(identity.stop)

    def executable(self, behavior='print(json.dumps(data))'):
        self.binary.write_text('#!' + sys.executable + '\n'
                               'import json, os, subprocess, sys, time\nfrom pathlib import Path\n'
                               'data = json.loads(' + repr(json.dumps(result())) + ')\n'
                               + behavior + '\n')
        self.binary.chmod(0o700)

    def record(self, repetitions=3, timeout=5):
        return perf.record(self.binary, self.output, 3, repetitions, timeout)

    def test_success_preserves_raw_attempts_summary_and_identity(self):
        self.executable("""counter = Path('counter')
number = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(number))
for case in data['cases']:
    case['elapsed_ns'] *= number
    case['ns_per_round_trip'] *= number
    case['payload_round_trip_gbit_per_second'] = round(case['payload_bytes'] * 8 / case['elapsed_ns'], 6)
print(json.dumps(data))
print('fixture stderr ' + str(number), file=sys.stderr)""")
        receipt = self.record()
        self.assertEqual(receipt['status'], 'passed')
        self.assertEqual((self.output / 'counter').read_text(), '3')
        self.assertEqual(len(receipt['attempts']), 3)
        self.assertEqual(len(receipt['summary']), 12)
        self.assertEqual(receipt['summary'][0]['metrics']['ns_per_round_trip'],
                         {'min': 1000, 'median': 2000, 'max': 3000})
        self.assertTrue(all(case['complete'] and case['samples'] == 3 for case in receipt['summary']))
        self.assertTrue(receipt['binary_stable_during_recording'])
        self.assertTrue(receipt['source_stable_during_recording'])
        self.assertEqual(receipt['identity_before']['source_hashes']['tools/fixture.txt'],
                         hashlib.sha256(b'original source').hexdigest())
        for number, attempt in enumerate(receipt['attempts'], 1):
            self.assertEqual(attempt['command'], [str(self.binary), '3'])
            self.assertEqual(json.loads((self.output / f'repetition-{number:02d}.stdout').read_text()),
                             attempt['result'])
            self.assertEqual((self.output / f'repetition-{number:02d}.stderr').read_text(),
                             f'fixture stderr {number}\n')
            self.assertEqual(json.loads((self.output / f'repetition-{number:02d}.json').read_text()), attempt)
        self.assertEqual(json.loads((self.output / 'performance.json').read_text()), receipt)

    def test_failed_attempt_remains_failed_after_later_success(self):
        self.executable("""counter = Path('counter')
number = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(number))
print(json.dumps(data))
print('retained failure ' + str(number), file=sys.stderr)
sys.exit(7 if number == 1 else 0)""")
        receipt = self.record()
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual([attempt['returncode'] for attempt in receipt['attempts']], [7, 0, 0])
        self.assertEqual((self.output / 'counter').read_text(), '3')
        self.assertIn('retained failure 1', (self.output / 'repetition-01.stderr').read_text())
        self.assertTrue((self.output / 'repetition-01.stdout').stat().st_size)
        self.assertTrue(all(case['samples'] == 2 and not case['complete'] for case in receipt['summary']))

    def test_malformed_and_deeply_nested_json_preserve_all_attempts(self):
        for payload in ('{malformed', '[' * 2000 + '0' + ']' * 2000):
            self.executable(f"print({payload!r}); print('diagnostic', file=sys.stderr)")
            self.output = self.root / ('malformed' if payload[0] == '{' else 'nested')
            receipt = self.record(2)
            self.assertEqual(receipt['status'], 'failed')
            self.assertEqual(len(receipt['attempts']), 2)
            for attempt in receipt['attempts']:
                self.assertEqual(attempt['returncode'], 0)
                self.assertIsNone(attempt['result'])
                self.assertIn('invalid benchmark result', attempt['errors'][0])
            self.assertEqual((self.output / 'repetition-02.stdout').read_text(), payload + '\n')
            self.assertTrue(all(case['samples'] == 0 and case['metrics']['elapsed_ns'] is None
                                for case in receipt['summary']))

    def test_invocation_failure_still_records_all_attempts(self):
        receipt = self.record(2)
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(len(receipt['attempts']), 2)
        for attempt in receipt['attempts']:
            self.assertIsNone(attempt['returncode'])
            self.assertIn('invocation failed', attempt['errors'][0])
            self.assertTrue((self.output / attempt['stdout']['path']).is_file())
            self.assertTrue((self.output / attempt['stderr']['path']).is_file())

    def test_timeout_preserves_output_and_continues_exact_attempts(self):
        self.executable("print('before timeout', flush=True); print('stderr before timeout', file=sys.stderr, flush=True); time.sleep(10)")
        receipt = self.record(2, timeout=0.2)
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(len(receipt['attempts']), 2)
        self.assertTrue(all(attempt['timed_out'] for attempt in receipt['attempts']))
        self.assertEqual((self.output / 'repetition-02.stdout').read_text(), 'before timeout\n')
        self.assertEqual((self.output / 'repetition-01.stderr').read_text(), 'stderr before timeout\n')

    def test_inherited_pipe_cannot_outlive_repetition_deadline(self):
        self.executable("subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)']); print('direct child exited', flush=True)")
        started = time.monotonic()
        receipt = self.record(2, timeout=0.2)
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(receipt['status'], 'failed')
        self.assertTrue(all(attempt['timed_out'] for attempt in receipt['attempts']))
        self.assertTrue(all(attempt['returncode'] == 0 for attempt in receipt['attempts']))
        self.assertEqual((self.output / 'repetition-02.stdout').read_text(), 'direct child exited\n')

    def test_capture_overflow_is_bounded_hashed_and_failed(self):
        self.executable(f"os.write(1, b'x' * {perf.CAPTURE_BYTES + 17}); os.write(2, b'y' * {perf.CAPTURE_BYTES + 23})")
        receipt = self.record(1)
        self.assertEqual(receipt['status'], 'failed')
        attempt = receipt['attempts'][0]
        for stream, byte, extra in [('stdout', b'x', 17), ('stderr', b'y', 23)]:
            metadata = attempt[stream]
            self.assertTrue(metadata['truncated'])
            self.assertEqual(metadata['total_bytes'], perf.CAPTURE_BYTES + extra)
            self.assertEqual((self.output / metadata['path']).stat().st_size, perf.CAPTURE_BYTES)
            self.assertEqual(metadata['sha256'], hashlib.sha256(byte * (perf.CAPTURE_BYTES + extra)).hexdigest())

    def test_source_drift_fails_even_when_every_case_passes(self):
        self.executable(f"Path({str(self.source)!r}).write_text('changed source'); print(json.dumps(data))")
        receipt = self.record(2)
        self.assertEqual(receipt['status'], 'failed')
        self.assertTrue(all(attempt['status'] == 'passed' for attempt in receipt['attempts']))
        self.assertFalse(receipt['source_stable_during_recording'])
        self.assertEqual(receipt['changed_during_recording'], ['tools/fixture.txt'])

    def test_binary_drift_fails_without_replacing_attempts(self):
        self.executable("with Path(__file__).open('a') as executable: executable.write('# drift\\n')\nprint(json.dumps(data))")
        receipt = self.record(2)
        self.assertEqual(receipt['status'], 'failed')
        self.assertTrue(all(attempt['status'] == 'passed' for attempt in receipt['attempts']))
        self.assertFalse(receipt['binary_stable_during_recording'])

    def test_source_identity_error_and_nonregular_binary_do_not_hang(self):
        self.executable()
        with patch.object(perf.record_check, 'hashes', side_effect=OSError('fixture unreadable')):
            receipt = self.record(2)
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(len(receipt['attempts']), 2)
        self.assertIsNone(receipt['changed_during_recording'])
        fifo = self.root / 'nonregular-binary'
        os.mkfifo(fifo)
        identity, errors = perf._identity(fifo)
        self.assertIsNone(identity['binary_sha256'])
        self.assertTrue(errors)

    def test_existing_output_and_invalid_parameters_never_overwrite(self):
        self.output.mkdir()
        marker = self.output / 'original'
        marker.write_text('preserve')
        with self.assertRaises(FileExistsError):
            self.record(1)
        self.assertEqual(marker.read_text(), 'preserve')
        for iterations, repetitions, timeout in [(0, 1, 1), (1_000_001, 1, 1),
                                                 (True, 1, 1), (3, 0, 1), (3, 21, 1),
                                                 (3, 1, float('nan')), (3, 1, 0), (3, 1, 3601)]:
            fresh = self.root / 'must-not-exist'
            with self.subTest(iterations=iterations, repetitions=repetitions, timeout=timeout), self.assertRaises(ValueError):
                perf.record(self.binary, fresh, iterations, repetitions, timeout)
            self.assertFalse(fresh.exists())


if __name__ == '__main__':
    unittest.main()
