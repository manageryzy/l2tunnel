#!/usr/bin/env python3
"""Offline evidence and provenance checks; no workload or network access."""
import hashlib
import json
import copy
from pathlib import Path
import tempfile
import unittest

try:
    from . import common_matrix_report as report, common_native_observe as observe
except ImportError:
    import common_matrix_report as report
    import common_native_observe as observe


def histogram(pairs):
    samples = sum(count for _, count in pairs)
    def quantile(percentile):
        rank, seen = (samples * percentile + 99) // 100, 0
        for size, count in pairs:
            seen += count
            if seen >= rank:
                return size
        return None
    return {'histogram': pairs, 'samples': samples,
            'total_bytes': sum(size * count for size, count in pairs),
            **{'p' + str(p): quantile(p) for p in (50, 95, 99)}}


def wire_fixture(schema):
    value = {'schema': schema, 'invalid_samples': 0, 'counter_overflow': 0,
             'fragmented_records': 1, 'diagnostic_heap_bytes': 880,
             'accepted_classes': dict(swift_source=1, direct_arq_source=1, systematic_fec_source=1,
                                      repair=1, recovery_feedback=1, unreliable_native=1),
             'accepted_boundaries': dict(socket_accepted=6, tls_stream_flushed=0, quic_datagram_accepted=0),
             'algorithm_bytes': histogram([[100, 6]]), 'final_record_bytes': histogram([[121, 6]]),
             'record_overhead_bytes': histogram([[21, 6]])}
    if schema >= 2:
        value.update(extent_errors=0, codec_coverage=dict.fromkeys(observe.CODEC_COVERAGE, 1),
                     diagnostic_histogram_heap_bytes=800, diagnostic_path_heap_bytes=80,
                     route_header_bytes=histogram([[0, 5], [10, 1]]),
                     fragment_header_bytes=histogram([[0, 5], [40, 1]]),
                     recovery_header_bytes=histogram([[3, 4]]),
                     systematic_coded_fill_bytes=histogram([[0, 3], [7, 1]]),
                     codec_envelope_bytes=histogram([[2, 2]]),
                     codec_container_bytes=histogram([[0, 2]]),
                     codec_unit_header_bytes=histogram([[3, 1], [6, 1]]),
                     codec_body_bytes=histogram([[70, 1], [80, 1]]))
    if schema == 3:
        value.update(socket_ip_bytes=histogram([[149, 6]]),
                     socket_ip_over_record_bytes=histogram([[28, 6]]),
                     record_outside_codec_body_bytes=histogram([[41, 1], [51, 1]]),
                     socket_ip_outside_codec_body_bytes=histogram([[69, 1], [79, 1]]))
        empty = dict(inputs=0, original_bytes=0, context_bytes=0, encoded_body_bytes=0,
                     framing_bytes=0, codec_net_gain_bytes=0, net_gain_bytes=0)
        value['native_encoding'] = {'counter_overflow': 0,
            **{label: {name: dict(empty) for name in observe.NATIVE_ENCODING_KINDS}
               for label in ('native_packet', 'proxy_record')}}
    return value


def saved_metrics(directory, values):
    case = {'commands': [], 'wire_metrics': {'files': [], 'sha256': {}}}
    for pid, (side, value) in enumerate(zip(('a', 'b'), values), 1):
        name = 'wire.' + str(pid) + '.1.json'
        raw = json.dumps(value, sort_keys=True).encode()
        (directory / name).write_bytes(raw)
        case['commands'].append({'log': 'daemon-' + side + '.log', 'pid': pid})
        case['wire_metrics']['files'].append(name)
        case['wire_metrics']['sha256'][name] = hashlib.sha256(raw).hexdigest()
    return case


class WireMetricsTests(unittest.TestCase):
    def test_schema1_keeps_original_validation_and_base_statistics(self):
        value = wire_fixture(1)
        self.assertEqual(observe.validate_wire_metrics(value, 'udp'), {
            'status': 'validated', 'accepted_records': 6, 'boundary': 'socket_accepted',
            'diagnostic_heap_bytes': 880,
            'totals': {'algorithm_bytes': 600, 'final_record_bytes': 726, 'record_overhead_bytes': 126}})

    def test_schema2_validates_independent_populations_and_observed_zero_extent(self):
        value = wire_fixture(2)
        validated = observe.validate_wire_metrics(value, 'udp')
        self.assertEqual(validated['extent_samples'], dict(zip(observe.EXTENT_METRICS, (6, 6, 4, 4, 2, 2, 2, 2))))
        self.assertEqual(validated['extent_totals']['systematic_coded_fill_bytes'], 7)
        self.assertEqual(report.extent_summary(value['codec_container_bytes']), {
            'samples': 2, 'total_bytes': 0, 'mean_bytes_per_sample': 0,
            'p50_bytes': 0, 'p95_bytes': 0, 'p99_bytes': 0})
        # No attributable codec samples is distinct from observed zero-byte framing.
        value['codec_coverage'] = dict.fromkeys(observe.CODEC_COVERAGE, 0)
        value['codec_coverage']['swift_stream'] = 6
        value['accepted_classes'] = dict.fromkeys(value['accepted_classes'], 0)
        value['accepted_classes']['swift_source'] = 6
        value['fragmented_records'] = 0
        value['fragment_header_bytes'] = histogram([[0, 6]])
        value['recovery_header_bytes'] = histogram([[3, 6]])
        value['systematic_coded_fill_bytes'] = histogram([[0, 6]])
        for key in observe.EXTENT_METRICS[4:]:
            value[key] = histogram([])
        self.assertEqual(observe.validate_wire_metrics(value, 'udp')['extent_samples']['codec_body_bytes'], 0)
        self.assertIsNone(report.extent_summary(value['codec_body_bytes'])['mean_bytes_per_sample'])
        del value['codec_body_bytes']['p99']
        with self.assertRaisesRegex(observe.ExtentMetricsError, 'quantile'):
            observe.validate_wire_metrics(value, 'udp')

    def test_schema2_refuses_errors_and_inconsistent_populations_without_losing_base(self):
        variants = []
        value = wire_fixture(2)
        value['extent_errors'] = 1
        variants.append(value)
        value = wire_fixture(2)
        value['codec_coverage']['swift_stream'] += 1
        variants.append(value)
        value = wire_fixture(2)
        value['codec_body_bytes'] = histogram([[0, 6]])
        variants.append(value)
        value = wire_fixture(2)
        value['fragmented_records'] = 0
        variants.append(value)
        value = wire_fixture(2)
        value['diagnostic_path_heap_bytes'] += 1
        variants.append(value)
        value = wire_fixture(2)
        del value['route_header_bytes']
        variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(observe.ExtentMetricsError) as raised:
                observe.validate_wire_metrics(value, 'udp')
            self.assertEqual(raised.exception.base_validation['totals']['algorithm_bytes'], 600)
        for schema in (True, 0, 4):
            value = {**wire_fixture(1), 'schema': schema}
            with self.assertRaisesRegex(ValueError, 'unknown schema'):
                observe.validate_wire_metrics(value, 'udp')

    def test_schema3_joined_metrics_preserve_population_and_actual_ip_boundary(self):
        value = wire_fixture(3)
        for carrier in ('raw', 'raw-tls-like'):
            result = observe.validate_wire_metrics(value, carrier)
            self.assertEqual(result['joined_samples'], dict(zip(observe.JOINED_METRICS, (6, 6, 2, 2))))
            self.assertEqual(result['joined_totals']['record_outside_codec_body_bytes'], 92)
        value['accepted_boundaries'] = dict(socket_accepted=0, tls_stream_flushed=6, quic_datagram_accepted=0)
        for name in ('socket_ip_bytes', 'socket_ip_over_record_bytes', 'socket_ip_outside_codec_body_bytes'):
            value[name] = histogram([])
        result = observe.validate_wire_metrics(value, 'tls')
        self.assertEqual(result['joined_samples'], dict(zip(observe.JOINED_METRICS, (0, 0, 2, 0))))
        # A budget allowance must not masquerade as a physical TLS measurement.
        value['socket_ip_bytes'] = histogram([[191, 6]])
        with self.assertRaisesRegex(observe.ExtentMetricsError, 'population'):
            observe.validate_wire_metrics(value, 'tls')

    def test_schema3_report_keeps_same_sample_join_separate_from_full_overhead(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = saved_metrics(root, [wire_fixture(2), wire_fixture(3)])
            value = report.wire_metrics(case, root, 'udp', {})
            old, new = (value['directions'][key] for key in ('a_to_b', 'b_to_a'))
            self.assertIsNone(old['layer_extents']['joined_metrics'])
            joined = new['layer_extents']['joined_metrics']['record_outside_codec_body_bytes']
            self.assertEqual((joined['samples'], joined['mean_bytes_per_sample'], joined['p99_bytes']), (2, 46, 51))
            self.assertIsNone(value['total_encapsulation_overhead_p99_bytes'])

    def test_native_admission_gain_retains_expansion_and_separates_proxy(self):
        value = wire_fixture(3)
        literal = value['native_encoding']['native_packet']['swift_literal']
        literal.update(inputs=1, original_bytes=100, encoded_body_bytes=101, framing_bytes=2,
                       codec_net_gain_bytes=-1, net_gain_bytes=-3)
        result = observe.validate_wire_metrics(value, 'udp')['native_encoding']
        self.assertEqual(result['native_packet']['swift_literal']['mean_net_gain_bytes'], -3)
        self.assertIsNone(result['proxy_record']['swift_literal']['mean_net_gain_bytes'])
        literal['net_gain_bytes'] = 0
        with self.assertRaisesRegex(observe.ExtentMetricsError, 'signed gains'):
            observe.validate_wire_metrics(value, 'udp')

    def test_native_admission_evidence_survives_no_successful_emissions(self):
        value = wire_fixture(3)
        value['accepted_classes'] = dict.fromkeys(value['accepted_classes'], 0)
        value['accepted_boundaries'] = dict.fromkeys(value['accepted_boundaries'], 0)
        value['native_encoding']['native_packet']['unencoded'].update(
            inputs=1, original_bytes=100, encoded_body_bytes=100)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = saved_metrics(root, [value])
            observed = report.wire_metrics(case, root, 'udp', {})['directions']['a_to_b']
            self.assertEqual(observed['status'], 'invalid_observation')
            self.assertEqual(observed['native_encoding_status'], 'validated')
            self.assertEqual(observed['native_encoding']['native_packet']['unencoded']['inputs'], 1)
            self.assertNotIn('record_overhead_bytes', observed)

    def test_report_retains_mixed_schema_provenance_without_filling_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = saved_metrics(root, [wire_fixture(1), wire_fixture(2)])
            provenance = {}
            value = report.wire_metrics(case, root, 'udp', provenance)
            old, new = (value['directions'][key] for key in ('a_to_b', 'b_to_a'))
            self.assertEqual(old['algorithm_bytes'], new['algorithm_bytes'])
            self.assertIsNone(old['layer_extents'])
            self.assertEqual(new['layer_extents']['metrics']['codec_body_bytes']['samples'], 2)
            self.assertEqual(new['layer_extents']['metrics']['codec_body_bytes']['mean_bytes_per_sample'], 75)
            self.assertEqual(new['layer_extents']['codec_coverage'], wire_fixture(2)['codec_coverage'])
            self.assertIsNone(value['total_encapsulation_overhead_p99_bytes'])
            self.assertEqual(len(provenance), 2)
            self.assertEqual(old['receipt_sha256'], case['wire_metrics']['sha256']['wire.1.1.json'])

    def test_report_keeps_base_but_marks_failed_layer_attribution_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = wire_fixture(2)
            value['extent_errors'] = 1
            case = saved_metrics(root, [value])
            observed = report.wire_metrics(case, root, 'udp', {})['directions']['a_to_b']
            self.assertEqual(observed['status'], 'validated')
            self.assertEqual(observed['record_overhead_bytes']['p99_bytes'], 21)
            self.assertEqual(observed['layer_extents']['status'], 'invalid_observation')
            self.assertEqual(observed['layer_extents']['extent_errors'], 1)
            self.assertIsNone(observed['layer_extents']['metrics'])
            corrupt = copy.deepcopy(value)
            corrupt['final_record_bytes']['total_bytes'] += 1
            case = saved_metrics(root, [corrupt])
            observed = report.wire_metrics(case, root, 'udp', {})['directions']['a_to_b']
            self.assertEqual(observed['status'], 'invalid_observation')
            self.assertNotIn('record_overhead_bytes', observed)

    def test_saved_case_renders_layer_samples_without_claiming_total_overhead(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'run'
            case_dir = run / 'fixture-udp'
            case_dir.mkdir(parents=True)
            case = saved_metrics(case_dir, [wire_fixture(1), wire_fixture(2)])
            row = {'id': 'fixture-udp', 'carrier': 'udp', 'expected_descriptor_hex': 'ab', 'status': 'ready'}
            case.update(id=row['id'], row=row, status='failed', selected_phases=['forward'],
                        phases=[{'phase': 'forward', 'status': 'failed', 'error': 'original cap'}],
                        started_wall_ns=1, completed_wall_ns=2)
            (case_dir / 'result.json').write_text(json.dumps(case))
            (run / 'results.json').write_text('{}')
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'rows': [row]}))
            value = report.build_report(manifest, [run])
            text = report.markdown(value)
            self.assertIn('schema1 has no layer attribution', text)
            self.assertIn('codec_body_bytes | 2 | 75.000 / 80.000', text)
            self.assertIn('neither native-packet overheads nor additive percentile components', text)
            metrics = value['combinations'][0]['attempts'][0]['common_record_metrics']
            self.assertIsNone(metrics['total_encapsulation_overhead_p99_bytes'])


def terminal(side, outcome='Protocol'):
    return {side: {'state': {'phase': 'failed', 'common': {
        'terminal': outcome, 'service_terminal': 'Failed(Failure { kind: InvalidData })',
        'current': 'large configuration must not enter report'}}}}


class TerminalEvidenceTests(unittest.TestCase):
    def test_exact_diagnostic_and_phase_dto_fallback_preserve_side_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = ('unrelated output\nCommon runtime failure: role=Client kind=InvalidData '
                    'cause=Custom { kind: InvalidData, error: "whole-message control error: Expired" }\n')
            path = root / 'daemon-a.log'
            path.write_text(text)
            sample = {'at_ns': 10, 'endpoints': {**terminal('a'), **terminal('b')}}
            case = {'phases': [{'phase': 'forward', 'status_samples': [sample, {**sample, 'at_ns': 20}]}]}
            provenance = {}
            value = report.terminal_evidence(case, root, 'tls', provenance)
            item, = value['runtime_failures']
            self.assertEqual((item['side'], item['line'], item['phase']), ('a', 2, None))
            self.assertEqual(item['category'], 'control_expired')
            self.assertEqual(item['log_sha256'], hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(provenance[str(path.resolve())], item['log_sha256'])
            fallback, = value['fallback_terminal_observations']
            self.assertEqual((fallback['side'], fallback['phase'], fallback['observations']), ('b', 'forward', 2))
            self.assertEqual((fallback['first_observed_at_ns'], fallback['last_observed_at_ns']), (10, 20))
            self.assertNotIn('large configuration', json.dumps(value))
            self.assertIsNone(value['root_cause_inference'])

    def test_categories_do_not_infer_unprinted_deadline_or_causal_direction(self):
        cases = [
            ('Custom { kind: TimedOut, error: Expired }', 'raw', 'raw_expired_unqualified'),
            ('Custom { kind: TimedOut, error: Expired }', 'udp', 'expired_unqualified'),
            ('retained TLS original record cap expired', 'tls', 'tls_record_cap_expired'),
            ('common record Bank: Engine(Rolling(Expired))', 'raw', 'algorithm_expired'),
            ('common record Bank: RetryExhausted { source: SourceId(4) }', 'quic', 'algorithm_retry_exhausted'),
            ('authenticated liveness challenge expired', 'quic', 'liveness_expired')]
        for cause, carrier, expected in cases:
            self.assertEqual(report.cause_category(cause, carrier), expected)

    def test_selected_case_counts_are_not_multiplied_by_phases_or_repeated_lines(self):
        evidence = {'runtime_failures': [{'side': 'a', 'category': 'control_expired'}] * 2,
                    'fallback_terminal_observations': []}
        fallback = {'runtime_failures': [], 'fallback_terminal_observations': [
            {'side': 'b', 'terminal': 'Protocol', 'service_terminal': None, 'state_phase': 'failed'}] * 2}
        row = {'attempts': [{'status': 'failed', 'terminal_evidence': evidence},
                            {'status': 'failed', 'terminal_evidence': fallback}],
               'phase_selection': {'forward': 0, 'reverse': 0, 'simultaneous': 0}}
        value = report.failure_summary([row])
        self.assertEqual(value['selected_case_sessions']['observed_runtime_categories'], {'control_expired': 1})
        self.assertEqual(value['selected_case_sessions']['case_sessions'], 1)
        self.assertEqual(value['all_attempts']['case_sessions'], 2)
        self.assertEqual(value['all_attempts']['fallback_dto_categories'], {'Protocol': 1})


if __name__ == '__main__':
    unittest.main()
