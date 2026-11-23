"""Synthetic profiling-accounting tests; no sockets, processes or runtime proof."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from . import native_throughput_profiles as p
from .test_native_throughput_analysis import HAS_MATPLOTLIB, fixture


def snapshot(at=1_000_000_000):
    value = {'event': 'runtime_profile', 'schema': 1, 'runtime': 'managed-tcp', 'elapsed_nanos': at, 'terminal': False,
             'counters': {k: 0 for k in p.COUNTERS}, 'high_water': {k: 0 for k in p.HIGH},
             'timings': {k: {'count': 0, 'total_nanos': 0, 'max_nanos': 0} for k in p.STAGES}}
    value['high_water'].update(configured_local_queue_packets=256, configured_delivery_credit_packets=256,
                               unconfirmed_native_packets=256, outgoing_queue_records=8)
    value['counters'].update(records_flushed=10, data_records_flushed=7, control_records_flushed=1, feedback_records_flushed=2)
    value['timings']['credit_blocked_elapsed'] = {'count': 2, 'total_nanos': 500_000_000, 'max_nanos': 300_000_000}
    value['timings']['transport_flush'] = {'count': 10, 'total_nanos': 2_000_000, 'max_nanos': 500_000}
    return value


def bdp_case():
    config = {'forward_mbps': 100, 'reverse_mbps': 10, 'bootstrap_rtt_ms': 70, 'headroom_percent': 125,
              'max_inflight_bytes': 4194304, 'max_records': 8192}
    cli = ['--delivery-window', 'bdp', '--forward-mbps', '100', '--reverse-mbps', '10', '--bootstrap-rtt-ms', '70',
           '--bdp-headroom-percent', '125', '--inflight-max-bytes', '4194304', '--inflight-max-records', '8192']
    receipt = {'plan': {'delivery_window': 'bdp', 'delivery_policy': config}, 'effective_cli': cli}
    s = snapshot()
    s['schema'] = 2
    s['values'] = {k: 0 for k in p.VALUES}
    s['values'].update(delivery_enabled=1, delivery_target_bytes=875000, delivery_outstanding_bytes=900000)
    s['high_water'].update(configured_local_queue_packets=64, configured_delivery_credit_packets=8192)
    return receipt, s


class Profiles(unittest.TestCase):
    def test_cumulative_and_delta_means_not_interval_max_or_cpu(self):
        a = snapshot()
        b = copy.deepcopy(a)
        b['elapsed_nanos'] = 2_000_000_000
        b['timings']['credit_blocked_elapsed'].update(count=3, total_nanos=800_000_000, max_nanos=300_000_000)
        b['timings']['transport_flush'].update(count=12, total_nanos=2_400_000, max_nanos=500_000)
        stream = p.parse_profiles(b'Authenticated\n' + json.dumps(a).encode() + b'\n' + json.dumps(b).encode() + b'\n')
        summary, rows, stages, highs = p.analyze_stream(stream, 'SYNTHETIC', 'a')
        self.assertEqual(summary['credit_blocked_elapsed_ratio'], .4)
        self.assertEqual(rows[-1]['credit_blocked_elapsed_ratio_interval'], .3)
        self.assertEqual(summary['data_flushed_fraction'], .7)
        f = [v for v in stages if v['stage'] == 'transport_flush'][-1]
        self.assertEqual(f['mean_completed_attempt_us_interval'], 200)
        self.assertEqual(f['max_attempt_us_cumulative'], 500)
        self.assertIsNone(f['max_attempt_us_interval'])
        self.assertIn('not stage CPU', p.process_cpu({'clock_ticks': 100, 'samples': [
            {'at_ns': 1_000_000_000, 'processes': [{'pid': 1, 'starttime_ticks': 5, 'utime_ticks': 1, 'stime_ticks': 2}]},
            {'at_ns': 2_000_000_000, 'processes': [{'pid': 1, 'starttime_ticks': 5, 'utime_ticks': 11, 'stime_ticks': 12}]}]},
            'SYNTHETIC')[0]['scope'])
        h = [v for v in highs if v['name'] == 'unconfirmed_native_packets'][-1]
        self.assertEqual(h['maximum_to_limit_ratio'], 1)

    def test_duplicates_and_completed_long_wait_do_not_get_clamped(self):
        a = snapshot()
        b = copy.deepcopy(a)
        b['elapsed_nanos'] += 100_000_000
        b['timings']['credit_blocked_elapsed'].update(count=3, total_nanos=1_000_000_000, max_nanos=500_000_000)
        stream = [{'line': 1, 'snapshot': a}, {'line': 2, 'snapshot': a}, {'line': 3, 'snapshot': b}]
        summary, rows, _, _ = p.analyze_stream(stream, 'SYNTHETIC', 'b')
        self.assertEqual(summary['exact_duplicates_ignored'], 1)
        self.assertEqual(rows[-1]['credit_blocked_elapsed_ratio_interval'], 5)

    def test_regression_and_saturation_delta_are_unobserved(self):
        a = snapshot()
        b = copy.deepcopy(a)
        b['elapsed_nanos'] *= 2
        b['counters']['records_flushed'] = 9
        b['counters']['data_admission_queue_full'] = p.U64
        summary, rows, _, _ = p.analyze_stream([{'line': 1, 'snapshot': a}, {'line': 2, 'snapshot': b}], 'SYNTHETIC', 'a')
        self.assertIsNone(rows[-1]['records_flushed_delta'])
        self.assertIsNone(rows[-1]['data_admission_queue_full_delta'])
        self.assertIn('saturated', summary['warnings'])
        self.assertIn('regression', summary['warnings'])

    def test_schema2_values_are_current_gauges_not_monotonic_counters(self):
        a = snapshot()
        a['schema'] = 2
        a['values'] = {k: 0 for k in p.VALUES}
        a['values'].update(delivery_enabled=1, delivery_target_bytes=875000, delivery_outstanding_bytes=900000,
                           delivery_service_rtt_micros=70000, delivery_service_rtt_fresh=1)
        b = copy.deepcopy(a)
        b['elapsed_nanos'] *= 2
        b['values'].update(delivery_target_bytes=400000, delivery_service_rtt_fresh=0)
        values = p.parse_profiles(json.dumps(a).encode() + b'\n' + json.dumps(b).encode())
        self.assertEqual(values[-1]['snapshot']['values']['delivery_target_bytes'], 400000)
        self.assertGreater(values[-1]['snapshot']['values']['delivery_outstanding_bytes'], 400000)
        bad = copy.deepcopy(b)
        bad['values']['delivery_enabled'] = 2
        with self.assertRaises(ValueError):
            p.parse_profiles(json.dumps(bad).encode())

    def test_bdp_selection_requires_actual_bounded_gauges_and_matching_flags(self):
        receipt, s = bdp_case()
        self.assertFalse(p.delivery_witness(receipt, {})['actual_bdp_observed'])
        streams = {side: [{'snapshot': s}] for side in ['a', 'b']}
        self.assertTrue(p.delivery_witness(receipt, streams)['actual_bdp_observed'])
        wrong = copy.deepcopy(receipt)
        wrong['effective_cli'][wrong['effective_cli'].index('--forward-mbps') + 1] = '10'
        self.assertFalse(p.delivery_witness(wrong, streams)['actual_bdp_observed'])
        s['values']['delivery_outstanding_bytes'] = 4194305
        self.assertFalse(p.delivery_witness(receipt, streams)['actual_bdp_observed'])

    def test_witness_bounds_are_options_with_original_defaults(self):
        receipt, s = bdp_case()
        s['values']['delivery_staged_native_bytes'] = 1601
        streams = {side: [{'snapshot': s}] for side in ['a', 'b']}
        self.assertIn('staged source above', p.delivery_witness(receipt, streams)['errors'])
        self.assertTrue(p.delivery_witness(receipt, streams, staged_native_max_bytes=2048)['actual_bdp_observed'])
        s['values']['delivery_staged_native_bytes'] = 0
        s['high_water']['configured_local_queue_packets'] = 128
        self.assertIn('matched 64-packet baseline', p.delivery_witness(receipt, streams)['errors'])
        self.assertTrue(p.delivery_witness(receipt, streams, baseline_local_queue_packets=128)['actual_bdp_observed'])
        args = p.parse(['analyze', 'case', '--output', 'out'])
        self.assertEqual((args.staged_native_max_bytes, args.baseline_local_queue_packets), (1600, 64))

    def test_malformed_schema_and_size_are_rejected(self):
        for mutate in [lambda v: v.update(schema=2), lambda v: v['counters'].update(unbounded=1),
                       lambda v: v.update(elapsed_nanos=True), lambda v: v['timings']['device_read'].update(count=-1),
                       lambda v: v.update(runtime='udp')]:
            v = snapshot()
            mutate(v)
            with self.assertRaises(ValueError):
                p.parse_profiles(json.dumps(v).encode())
        with self.assertRaises(ValueError):
            p.parse_profiles(b'"runtime_profile"' + b'x' * p.MAX_LINE)
        raw = json.dumps(snapshot()).replace('"schema": 1', '"schema": 1, "schema": 1')
        with self.assertRaises(ValueError):
            p.parse_profiles(raw.encode())
        self.assertEqual(p.parse_profiles(b'Authenticated\n'), [])


def profiled_case(root, name):
    directory = fixture(Path(root) / name)
    a = snapshot()
    b = copy.deepcopy(a)
    b['elapsed_nanos'] = 2_000_000_000
    b['terminal'] = True
    for side in ('a', 'b'):
        (directory / (side + '-daemon.log')).write_text('Authenticated\n' + json.dumps(a) + '\n' + json.dumps(b) + '\n')
    return directory


class EndToEnd(unittest.TestCase):
    def test_analyze_writes_fresh_tables_and_joins_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            directory = profiled_case(root, 'SYNTHETIC-case')
            baseline = Path(root) / 'baseline'
            output = Path(root) / 'profiles'
            with contextlib.redirect_stdout(io.StringIO()):
                p.accounting.main(['analyze', str(directory), '--output', str(baseline)])
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(p.main(['analyze', str(directory), '--output', str(output),
                                         '--baseline-report', str(baseline)]), 0)
            self.assertEqual(json.loads(stdout.getvalue())['observed_streams'], 2)
            for name in p.OUTPUT_TABLES:
                self.assertTrue((output / (name + '.csv')).is_file(), name)
            self.assertIn('**80 Mbps** on the 100 Mbps', (output / 'report.md').read_text())
            comparison = (output / 'baseline_comparison.csv').read_text()
            self.assertIn('SYNTHETIC-case', comparison.splitlines()[1])
            manifest = json.loads((output / 'input_manifest.json').read_text())
            self.assertEqual(manifest['policy_bounds'], {'staged_native_max_bytes': 1600, 'baseline_local_queue_packets': 64})
            with self.assertRaises(FileExistsError), contextlib.redirect_stdout(io.StringIO()):
                p.main(['analyze', str(directory), '--output', str(output)])

    @unittest.skipUnless(HAS_MATPLOTLIB, 'matplotlib (simulator plots extra) is not installed')
    def test_plot_renders_profile_figures(self):
        with tempfile.TemporaryDirectory() as root:
            directory = profiled_case(root, 'SYNTHETIC-case')
            output = Path(root) / 'profiles'
            figures = Path(root) / 'figures'
            with contextlib.redirect_stdout(io.StringIO()):
                p.main(['analyze', str(directory), '--output', str(output)])
                p.main(['plot', '--report', str(output), '--output', str(figures)])
            self.assertTrue((figures / 'case-001-wait.png').is_file())
            self.assertTrue((figures / 'case-001-wait.svg').is_file())
            self.assertIn('BDP byte gauges unobserved', (figures / 'index.html').read_text())


if __name__ == '__main__':
    unittest.main()
