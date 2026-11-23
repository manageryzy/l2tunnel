"""Synthetic accounting fixture tests only; no sockets, namespaces or native workload."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from . import native_throughput_analysis as a

HAS_MATPLOTLIB = importlib.util.find_spec('matplotlib') is not None


def probe_result(side, clock, status):
    sent, received = (2000, 1000) if side == 'a' else (1000, 2000)
    sent_hash = hashlib.sha256(b'a' * sent if side == 'a' else b'b' * sent).hexdigest()
    received_hash = hashlib.sha256(b'b' * received if side == 'a' else b'a' * received).hexdigest()
    final = {'sent': sent, 'received': received, 'warmup': received // 10, 'measured': received * 8 // 10,
             'postwindow': received // 10, 'sent_sha256': sent_hash, 'received_sha256': received_hash, 'eof': True,
             'write_closed': True, 'bound_exhausted': status == 'bound_exhausted'}
    samples = []
    for n, offset in enumerate([-1, .25, 5, 9.5, 10.5]):
        raw = bytearray(236)
        for field, at in a.OFFSETS32.items():
            value = {'snd_mss': 1000, 'snd_cwnd_segments': [999, 10, 20, 12, 999][n], 'rtt_us': 1000 + n * 10,
                     'rtt_variance_us': 100, 'rcv_space_bytes': 80000, 'total_retransmitted_segments': n,
                     'peer_advertised_rwnd_bytes': 50000 - n * 1000, 'local_advertised_rwnd_bytes': 40000 + n * 1000}[field]
            struct.pack_into('=I', raw, at, value)
        for field, at in a.OFFSETS64.items():
            struct.pack_into('=Q', raw, at, {'bytes_sent': n * 100, 'bytes_acked': n * 90, 'bytes_retransmitted': n * 25}[field])
        info = {field: struct.unpack_from('=I', raw, at)[0] for field, at in a.OFFSETS32.items()}
        info.update({field: struct.unpack_from('=Q', raw, at)[0] for field, at in a.OFFSETS64.items()})
        begin = clock['measure_start_ns'] + int(offset * 1e9)
        info.update(raw_hex=raw.hex(), length=len(raw), snd_cwnd_bytes=info['snd_mss'] * info['snd_cwnd_segments'],
                    read_begin_ns=begin, read_end_ns=begin + 20, congestion_control='synthetic')
        got = [received // 10, received // 10, received // 2, received * 9 // 10, received][n]
        warm = min(got, received // 10)
        measured = min(max(0, got - warm), received * 8 // 10)
        info['application_counters'] = {'sent': sent * n // 4, 'received': got, 'warmup': warm, 'measured': measured,
                                        'postwindow': got - warm - measured}
        samples.append({'at_ns': info['read_begin_ns'], 'flows': [info]})
    return {'role': 'connect' if side == 'a' else 'listen', 'clock': clock, 'original_deadline_ns': 30_000_000_000,
            'completed_ns': 14_000_000_000, 'max_bytes_per_direction_flow': 65536, 'flows': [final], 'tcp_info': samples}


def fixture(directory, status='passed', outer_ss=None):
    """Write one synthetic native_throughput.py case directory (never a runnable binary)."""
    directory.mkdir(parents=True)
    sources = {}
    for name in a.HELPERS:
        raw = ('SYNTHETIC accounting helper ' + name + '\n').encode()
        (directory / name).write_bytes(raw)
        sources['tools/' + name] = hashlib.sha256(raw).hexdigest()
    binary = b'SYNTHETIC fixture bytes, not a runnable binary\n'
    (directory / 'l2tunnel-native').write_bytes(binary)
    binary_sha = hashlib.sha256(binary).hexdigest()
    build = {'status': 'passed', 'exit_code': 0, 'source_stable_during_build': True, 'changed_during_build': [],
             'source_sha256_before': sources, 'source_sha256_after': sources, 'binary_sha256': binary_sha}
    (directory / 'build-receipt.json').write_text(json.dumps(build))
    clock = {'start_ns': 1_000_000_000, 'measure_start_ns': 3_000_000_000, 'end_ns': 13_000_000_000}
    ar, br = probe_result('a', clock, status), probe_result('b', clock, status)
    for side, result in [('a', ar), ('b', br)]:
        (directory / (side + '-probe.log')).write_text('Connected\n' + json.dumps(result) + '\n')
    samples = []
    for offset, tx in [(-1, 1000), (.5, 2000), (5, 6000), (9, 10000), (11, 12000)]:
        rows = {}
        for side in ('a', 'b'):
            begin = clock['measure_start_ns'] + int(offset * 1e9)
            rows[side] = {'read_begin_ns': begin, 'read_end_ns': begin + 20, 'tx_bytes': tx if side == 'a' else tx // 2,
                          'rx_bytes': tx // 2 if side == 'a' else tx}
        sample = {'wan': rows, 'at_ns': rows['a']['read_begin_ns']}
        if outer_ss is not None:
            sample['outer_and_proxy_socket_ss'] = {'endpoint_a': outer_ss}
        samples.append(sample)
    tc_before = {side: {'class': [{'kind': 'htb', 'handle': '1:10', 'parent': '1:', 'bytes': 100, 'packets': 1, 'drops': 0}],
                        'qdisc': [{'kind': 'netem', 'handle': '10:', 'parent': '1:10', 'bytes': 100, 'packets': 1, 'drops': 2}]}
                 for side in ('a', 'b')}
    tc_after = copy.deepcopy(tc_before)
    for side in ('a', 'b'):
        tc_after[side]['class'][0].update(bytes=1000, packets=10)
        tc_after[side]['qdisc'][0].update(bytes=1000, packets=10, drops=5)
    _, _, directions = a.payload_audit(ar, br, 1)
    coverage = {}
    for side in ('a', 'b'):
        tx = 8000 if side == 'a' else 4000
        rx = 4000 if side == 'a' else 8000
        coverage[side] = {'status': 'observed', 'covered_seconds': 8.5, 'requested_seconds': 10., 'clock_uncertainty_seconds': 20 / 1e9,
                          'tx_bytes': tx, 'rx_bytes': rx, 'tx_mbps': tx * 8 / 8.5 / 1e6, 'rx_mbps': rx * 8 / 8.5 / 1e6}
    receipt = {'synthetic_fixture': True, 'status': status, 'cleanup': 'passed', 'executed_helpers_unchanged': True,
               'executed_helpers': sources,
               'build_receipt_sha256': hashlib.sha256((directory / 'build-receipt.json').read_bytes()).hexdigest(),
               'binary_sha256': binary_sha,
               'plan': {'profile': 'tun-system', 'path': 'clean', 'duplex': 'full', 'flows': 1, 'family': 4,
                        'one_way_delay_ms': 1, 'loss_percent_per_direction': 0},
               'result': {'status': status, 'directions': directions, 'hashes_and_eof': 'passed',
                          'wire_intervals': {'measurement_coverage': coverage}},
               'samples': samples, 'tc_initial': tc_before, 'tc_final': tc_after}
    (directory / 'receipt.json').write_text(json.dumps(receipt))
    return directory


def rewrite_json(path, mutate, last_line=False):
    text = path.read_text()
    value = json.loads(text.splitlines()[-1] if last_line else text)
    mutate(value)
    path.write_text(json.dumps(value))


SS_TEXT = ('State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'
           'ESTAB 0 0 192.0.2.2:40123 192.0.2.6:18443\n'
           ' cubic rtt:70.25/1.5 mss:1448 cwnd:12 bytes_sent:5000 bytes_retrans:100 snd_wnd:32768\n'
           'ESTAB 0 0 198.19.0.1:30000 198.19.0.2:24451\n'
           ' cubic rtt:1.0/0.5 mss:1460 cwnd:99\n')


class Accounting(unittest.TestCase):
    def test_synthetic_never_becomes_native_and_windows_exclude_outside_samples(self):
        with tempfile.TemporaryDirectory() as root:
            value = a.audit_case(a.Inputs(), fixture(Path(root) / 'synthetic-passed'))
            self.assertEqual(value['base']['analysis_errors'], '')
            self.assertTrue(value['base']['eligible_accounting'])
            self.assertFalse(value['base']['accepted'])
            self.assertEqual(value['base']['classification'], 'synthetic-only')
            self.assertAlmostEqual(value['cases'][0]['diagnostic_goodput_mbps'], .00128)
            self.assertEqual(value['windows'][0]['contained_samples'], 3)
            self.assertEqual(value['windows'][0]['snd_cwnd_bytes_min'], 10000)
            self.assertEqual(value['windows'][0]['snd_cwnd_bytes_max'], 20000)
            self.assertEqual(value['windows'][0]['bytes_retransmitted_delta'], 50)
            self.assertAlmostEqual(value['wan_coverage'][0]['covered_seconds'], 8.5)
            self.assertEqual(value['tc_deltas'][1]['drops_delta'], 3)
            # Defaults retain the original 80/100/10 Mbps plan vocabulary.
            self.assertEqual(value['cases'][0]['performance_target_mbps'], 80)
            self.assertEqual(value['cases'][0]['configured_direction_capacity_mbps'], 100)
            self.assertEqual(value['cases'][1]['configured_direction_capacity_mbps'], 10)
            self.assertEqual(value['cases'][1]['performance_status'], 'separate_reverse_10mbps_direction')

    def test_failed_or_exhausted_or_cleanup_failed_never_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            for status in ('failed', 'bound_exhausted'):
                value = a.audit_case(a.Inputs(), fixture(Path(root) / status, status))
                self.assertFalse(value['base']['eligible_accounting'])
                self.assertFalse(value['base']['accepted'])
                self.assertIsNone(value['cases'][0]['accepted_goodput_mbps'])
            directory = fixture(Path(root) / 'cleanup')
            rewrite_json(directory / 'receipt.json', lambda r: r.update(cleanup='failed'))
            self.assertFalse(a.audit_case(a.Inputs(), directory)['base']['eligible_accounting'])

    def test_hash_and_window_raw_field_tamper_remain_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            directory = fixture(Path(root) / 'bad-hash')
            rewrite_json(directory / 'b-probe.log', lambda r: r['flows'][0].update(received_sha256='0' * 64), True)
            value = a.audit_case(a.Inputs(), directory)
            self.assertFalse(value['base']['payload_verified'])
            self.assertIn('hash mismatch', value['base']['analysis_errors'])
            directory = fixture(Path(root) / 'bad-window')
            rewrite_json(directory / 'a-probe.log', lambda r: r['tcp_info'][1]['flows'][0].update(snd_cwnd_bytes=123), True)
            value = a.audit_case(a.Inputs(), directory)
            self.assertFalse(value['base']['eligible_accounting'])
            self.assertIn('decoded field mismatch', value['base']['analysis_errors'])

    def test_outer_socket_domain_and_nominal_time_are_separate(self):
        rows, raw = a.outer_ss_rows({'samples': [{'at_ns': 123, 'outer_and_proxy_socket_ss': {'endpoint_a': SS_TEXT}}]}, 'fixture')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['cwnd_bytes'], 12 * 1448)
        self.assertEqual(rows[0]['rtt_ms'], 70.25)
        self.assertIn('unbracketed', rows[0]['time_basis'])
        self.assertIn('198.19.0.1', raw)

    def test_outer_endpoints_and_port_are_configurable(self):
        receipt = {'samples': [{'at_ns': 1, 'outer_and_proxy_socket_ss': {'endpoint_a': SS_TEXT}}]}
        config = a.Config(outer_endpoints=('198.19.0.1', '198.19.0.2'), outer_port=24451)
        rows, _ = a.outer_ss_rows(receipt, 'fixture', config)
        self.assertEqual([(r['local'], r['cwnd_bytes']) for r in rows], [('198.19.0.1:30000', 99 * 1460)])

    def test_parser_bounds_and_duplicate_keys(self):
        with self.assertRaises(ValueError):
            a.strict_json('{"x":1,"x":2}')
        with self.assertRaises(ValueError):
            a.strict_json('{"x":NaN}')
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'large'
            path.write_bytes(b'0' * 32)
            with self.assertRaises(ValueError):
                a.Inputs().read(path, 16)

    def test_plan_options_change_bounds_and_targets(self):
        with tempfile.TemporaryDirectory() as root:
            directory = fixture(Path(root) / 'synthetic-passed')
            short = a.audit_case(a.Inputs(), directory, config=a.Config(max_measurement_seconds=5))
            self.assertIn('measurement duration exceeds', short['base']['analysis_errors'])
            no_single = a.audit_case(a.Inputs(), directory, config=a.Config(flow_counts=(2, 4)))
            self.assertIn('unsupported flow count', no_single['base']['analysis_errors'])
            args = a.parse(['analyze', str(directory), '--output', str(Path(root) / 'out'), '--forward-target-mbps', '0.001',
                            '--forward-capacity-mbps', '50', '--reverse-capacity-mbps', '5'])
            config = a.config_from_args(args)
            self.assertEqual((config.forward_target_mbps, config.forward_capacity_mbps, config.reverse_capacity_mbps),
                             (0.001, 50, 5))
            value = a.audit_case(a.Inputs(), directory, config=config)
            self.assertEqual(value['cases'][0]['configured_direction_capacity_mbps'], 50)
            self.assertEqual(value['cases'][1]['performance_status'], 'separate_reverse_5mbps_direction')
            self.assertIn('5 Mbps B→A direction', a.report([value], config))

    def test_analyze_writes_fresh_report_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as root:
            directory = fixture(Path(root) / 'synthetic-passed', outer_ss=SS_TEXT)
            output = Path(root) / 'report'
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(a.main(['analyze', str(directory), '--output', str(output)]), 0)
            self.assertEqual(json.loads(stdout.getvalue())['accepted_native_cases'], 0)
            for name in a.CSV_TABLES:
                self.assertTrue((output / (name + '.csv')).is_file(), name)
            manifest = json.loads((output / 'input_manifest.json').read_text())
            self.assertEqual(manifest['config']['outer_port'], 18443)
            self.assertIn('80 Mbps on the 100 Mbps A→B link', (output / 'report.md').read_text())
            self.assertIn('192.0.2.2:40123', (output / 'outer_tcp_timeseries.csv').read_text())
            with self.assertRaises(FileExistsError), contextlib.redirect_stdout(io.StringIO()):
                a.main(['analyze', str(directory), '--output', str(output)])
            with self.assertRaises(ValueError):
                a.analyze([directory], directory)


def row(sample, flow, n, inside=True):
    return {'endpoint': 'b', 'sample_index': str(sample), 'flow': str(flow),
            'inside_measurement': str(inside), 'read_begin_ns': str(1000000000 + sample * 1000000000),
            'read_end_ns': str(1000000020 + sample * 1000000000), 'application_measured': str(n)}


class PlotAccounting(unittest.TestCase):
    def test_complete_multiflow_adjacent_batches_only(self):
        rows = [row(0, 0, 0, False), row(0, 1, 0, False), row(1, 0, 100), row(1, 1, 200),
                row(2, 0, 300), row(2, 1, 400), row(4, 0, 800), row(4, 1, 900)]
        values = a.receive_intervals(rows, 'b', 2, 1000000000)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]['unique_bytes_delta'], 400)
        self.assertAlmostEqual(values[0]['mbps'], .0032)
        self.assertEqual(values[0]['sample_start'], 1)
        self.assertEqual(values[0]['sample_end'], 2)

    def test_incomplete_batch_cannot_bridge_gap(self):
        rows = [row(1, 0, 10), row(1, 1, 20), row(2, 0, 30), row(3, 0, 50), row(3, 1, 60)]
        self.assertEqual(a.receive_intervals(rows, 'b', 2, 0), [])
        self.assertEqual(a.receive_intervals(rows, 'a', 2, 0), [])

    def test_bad_counter_and_legacy_identity(self):
        with self.assertRaises(ValueError):
            a.receive_intervals([row(1, 0, 100), row(2, 0, 90)], 'b', 1, 0)
        legacy = row(1, 0, 100)
        del legacy['sample_index']
        self.assertEqual(a.receive_intervals([legacy], 'b', 1, 0), [])

    def test_plan_rates_come_from_rows_with_original_defaults(self):
        self.assertEqual(a.plan_rates([]), ('80', '100', '10'))
        rows = [{'direction': 'a_to_b', 'performance_target_mbps': '40', 'configured_direction_capacity_mbps': '50'},
                {'direction': 'b_to_a', 'performance_target_mbps': '', 'configured_direction_capacity_mbps': '5'}]
        self.assertEqual(a.plan_rates(rows), ('40', '50', '5'))

    def test_csv_bounds(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'x.csv'
            path.write_text('a\n1\n2\n')
            with self.assertRaises(ValueError):
                a.read_csv(path, max_rows=1)
            with self.assertRaises(ValueError):
                a.read_csv(Path(root) / 'missing.csv')

    @unittest.skipUnless(HAS_MATPLOTLIB, 'matplotlib (simulator plots extra) is not installed')
    def test_plot_renders_from_fresh_report(self):
        with tempfile.TemporaryDirectory() as root:
            directory = fixture(Path(root) / 'synthetic-passed', outer_ss=SS_TEXT)
            report = Path(root) / 'report'
            figures = Path(root) / 'figures'
            with contextlib.redirect_stdout(io.StringIO()):
                a.main(['analyze', str(directory), '--output', str(report)])
                a.main(['plot', '--report', str(report), '--output', str(figures)])
            names = {path.name for path in figures.iterdir()}
            for stem in ('case-001-goodput', 'case-001-inner-windows', 'case-001-outer-tcp'):
                self.assertTrue({stem + '.png', stem + '.svg'} <= names, stem)
            self.assertIn('80 Mbps on the 100 Mbps', (figures / 'index.html').read_text())
            self.assertEqual(json.loads((figures / 'plot_manifest.json').read_text())['cases'], 1)


if __name__ == '__main__':
    unittest.main()
