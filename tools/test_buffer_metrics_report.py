#!/usr/bin/env python3
"""Finite offline report checks; no native workload, sockets or compiler runs."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    from . import buffer_metrics_report as report
except ImportError:
    import buffer_metrics_report as report


def duration(completed=0, censored=0, opened=None):
    return {'episodes': int(completed > 0) + int(censored > 0) + int(opened is not None),
            'completed_episodes': int(completed > 0), 'censored_episodes': int(censored > 0),
            'completed_us': completed, 'censored_us': censored, 'open_us': opened,
            'maximum_us': max(completed, censored, opened or 0)}


def gauge(used=None, capacity=None):
    return {'samples': int(used is not None), 'used': used, 'capacity': capacity,
            'high_water': used, 'minimum_known_capacity': capacity,
            'maximum_known_capacity': capacity}


def reason(name, blocked=None, untimed=0):
    return {'reason': name, 'refusals': 7 if blocked else untimed,
            'untimed_refusals': untimed, 'progress': 1,
            'blocked': blocked or duration()}


def fixture():
    return {'schema': 1, 'owner': 'common', 'definition': 'finite fixture',
            'coverage': 'partial: unhooked queues unavailable',
            'first_observed_us': 1_000, 'last_observed_us': 1_100,
            'observed_span_us': 100, 'finished_at_us': 1_100,
            'diagnostic_heap_bytes': 4096,
            'invalid': dict.fromkeys(report.INVALID_FLAGS, False),
            'blocked_union': duration(40, 20), 'raw': None,
            'sites': [{'site': 'CarrierSubmission', 'lane': 'First', 'class': 'User',
                       'first_observed_us': 1_000, 'last_observed_us': 1_100,
                       'bytes': gauge(200, 400), 'items': gauge(1, 2),
                       'reasons': [reason('IoPending', duration(40, 20)),
                                   reason('PeerCredit', duration(35, 15)),
                                   reason('QueueFull', untimed=9)]}]}


def protocol_fixture():
    return {'identity_errors': 0, 'clock_regressions': 0, 'counter_overflow': False,
            'retired_epochs_omitted': 0, 'retired_owner_generations_omitted': 0,
            'unsupported_codec_samples': 0, 'staged_terminal_unavailable': 0,
            'epochs': [{'epoch': 7, 'configuration_digest_hex': 'ab' * 32,
                        'live_at_last_sample': True, 'owner_capacity': 1,
                        'owners': [{'scope': 'endpoint-shared', 'owner': None, 'incarnation': None,
                                    'invalid_occupancy': False, 'counter_overflow': False,
                                    'gauges': [{'name': 'arq_transmission_history_entries', 'samples': 1,
                                                'used': None, 'high_water': None, 'capacity': 1024}],
                                    'staged_admission': None}]}]}


def save(directory, name, value):
    path = Path(directory) / name
    path.write_text(json.dumps(value), encoding='utf-8')
    return path


class BufferMetricsReportTests(unittest.TestCase):
    def test_union_uses_actual_span_and_never_sums_overlapping_rows_or_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            first = save(directory, 'first.bmetrics', fixture())
            second_value = fixture()
            second_value['blocked_union'] = duration(10, 10)
            second_value['sites'] = []
            second = save(directory, 'second.bmetrics', second_value)
            value = report.build_report([first, second])
        self.assertEqual(len(value['owners']), 2)
        self.assertNotIn('blocked_union', value)
        a, b = value['owners']
        self.assertEqual(a['owner_union_percent_of_observed_span'], 60)
        self.assertEqual(b['owner_union_percent_of_observed_span'], 20)
        self.assertEqual([row['blocked']['observed_us'] for row in a['wait_ranking']], [60, 50])
        self.assertEqual(a['count_only_refusals'][0]['untimed_refusals'], 9)
        self.assertIsNone(a['count_only_refusals'][0]['duration_us'])
        self.assertEqual(a['occupancy'][0]['bytes']['high_water'], 200)
        self.assertEqual(a['status'], 'parsed_partial_coverage')

    def test_open_censored_and_completed_remain_distinct(self):
        value = fixture()
        value['finished_at_us'] = None
        value['blocked_union'] = duration(30, 20, 10)
        value['sites'][0]['reasons'] = [reason('IoPending', duration(30, 20, 10))]
        owner = report.normalize(value, 'live.bmetrics', 'digest')
        self.assertEqual(owner['owner_union_percent_of_observed_span'], 60)
        wait = owner['wait_ranking'][0]['blocked']
        self.assertEqual((wait['completed_us'], wait['censored_us'], wait['open_us']), (30, 20, 10))
        self.assertEqual(wait['episodes'], 3)
        value['finished_at_us'] = 1_100
        invalid = report.normalize(value, 'terminal.bmetrics', 'digest')
        self.assertIsNone(invalid['owner_union_percent_of_observed_span'])
        self.assertTrue(any('uncensored' in issue for issue in invalid['issues']))

    def test_partial_timing_and_unknown_gauges_do_not_become_zero_capacity(self):
        value = fixture()
        value['sites'][0]['reasons'][0]['untimed_refusals'] = 3
        value['sites'][0]['bytes'] = gauge(200)
        value['sites'][0]['items'] = gauge()
        owner = report.normalize(value, 'partial.bmetrics', 'digest')
        self.assertEqual(owner['wait_ranking'][0]['timing_coverage'], 'partial_timed')
        self.assertEqual(len(owner['count_only_refusals']), 2)
        self.assertIsNone(owner['occupancy'][0]['bytes']['capacity'])
        self.assertEqual(owner['occupancy'][0]['bytes']['coverage'], 'capacity_unknown')
        self.assertEqual(owner['occupancy'][0]['items']['coverage'], 'unobserved')

    def test_producer_invalidity_and_impossible_values_suppress_percentage(self):
        for flag in report.INVALID_FLAGS:
            with self.subTest(flag=flag):
                value = fixture()
                value['invalid'][flag] = True
                owner = report.normalize(value, 'invalid.bmetrics', 'digest')
                self.assertEqual(owner['status'], 'invalid_observations')
                self.assertIsNone(owner['owner_union_percent_of_observed_span'])
                self.assertEqual(owner['blocked_union']['observed_us'], 60)
        for change in ('span', 'capacity', 'counts'):
            with self.subTest(change=change):
                value = fixture()
                if change == 'span':
                    value['observed_span_us'] = 10
                elif change == 'capacity':
                    value['sites'][0]['bytes']['capacity'] = 1
                else:
                    value['blocked_union']['episodes'] = 9
                self.assertTrue(report.normalize(value, 'invalid.bmetrics', 'digest')['issues'])

    def test_no_hooks_and_zero_span_have_unknown_percentage(self):
        for boundary in (None, 1_100):
            value = fixture()
            value.update(first_observed_us=boundary, last_observed_us=boundary,
                         observed_span_us=None if boundary is None else 0,
                         blocked_union=duration(), sites=[])
            owner = report.normalize(value, 'empty.bmetrics', 'digest')
            self.assertFalse(owner['issues'])
            self.assertIsNone(owner['owner_union_percent_of_observed_span'])

    def test_provider_metadata_is_preserved_without_inventing_occupancy(self):
        value = fixture()
        raw = {'lanes': [None, {'send_io': {'would_block_observations': 4, 'duration_us': None}}],
               'unavailable_lanes': 1, 'timing': 'untimed'}
        quic = {'definition': 'private metadata included',
                'lanes': [{'available_payload_bytes': 200, 'configured_limit': 1000,
                           'receive_queue_bytes': None}]}
        value.update(raw=raw, quic_provider=quic)
        original = copy.deepcopy(value)
        owner = report.normalize(value, 'providers.bmetrics', 'digest')
        self.assertEqual(owner['provider_metadata'], {'raw': raw, 'quic_provider': quic})
        self.assertEqual(value, original)
        self.assertNotIn('used', owner['provider_metadata']['quic_provider']['lanes'][0])

    def test_protocol_provider_unknown_is_unavailable_and_capacity_is_not_usage(self):
        value = fixture()
        value['protocol_buffers'] = protocol_fixture()
        owner = report.normalize(value, 'protocol.bmetrics', 'digest')
        validation = owner['protocol_provider_validation']
        self.assertEqual(validation['status'], 'validated_known_fields_partial')
        self.assertTrue(any('timing unavailable' in gap for gap in validation['coverage_gaps']))
        self.assertIsNone(owner['provider_metadata']['protocol_buffers']['epochs'][0]
                          ['owners'][0]['gauges'][0]['used'])
        self.assertEqual(owner['owner_union_percent_of_observed_span'], 60)
        for missing in (None,):
            value['protocol_buffers'] = missing
            validation = report.normalize(value, 'unknown.bmetrics', 'digest')['protocol_provider_validation']
            self.assertEqual(validation['status'], 'unavailable')
        value['protocol_buffers'] = {'future_layout': []}
        owner = report.normalize(value, 'unknown.bmetrics', 'digest')
        self.assertEqual(owner['protocol_provider_validation']['status'], 'invalid_or_unrecognized_shape')
        self.assertIsNone(owner['owner_union_percent_of_observed_span'])

    def test_protocol_nested_invalidity_and_impossible_occupancy_are_visible(self):
        for case in ('identity', 'overflow', 'row', 'capacity', 'duplicate', 'bound'):
            with self.subTest(case=case):
                value = fixture()
                provider = protocol_fixture()
                value['protocol_buffers'] = provider
                row = provider['epochs'][0]['owners'][0]
                if case == 'identity':
                    provider['identity_errors'] = 1
                elif case == 'overflow':
                    provider['counter_overflow'] = True
                elif case == 'row':
                    row['invalid_occupancy'] = True
                elif case == 'capacity':
                    row['gauges'][0].update(used=2048, high_water=2048)
                elif case == 'duplicate':
                    row['gauges'].append(copy.deepcopy(row['gauges'][0]))
                else:
                    provider['epochs'][0]['owner_capacity'] = 257
                owner = report.normalize(value, 'invalid-provider.bmetrics', 'digest')
                self.assertEqual(owner['status'], 'invalid_observations')
                self.assertIsNone(owner['owner_union_percent_of_observed_span'])
                self.assertEqual(owner['provider_metadata']['protocol_buffers'], provider)
                self.assertTrue(owner['protocol_provider_validation']['issues'])

    def test_protocol_staged_invalid_flags_do_not_hide_behind_generic_zero(self):
        totals = {'completed_episodes': 0, 'completed_us': 0, 'maximum_completed_us': 0,
                  'censored_episodes': 0, 'censored_us': 0, 'maximum_censored_us': 0}
        wait = {'observed_at_us': 1100, 'terminal_at_us': 1100, 'open_us': None,
                'pending': None, 'clock_regression': False, 'identity_mismatch': False,
                'counter_overflow': False, 'union': totals,
                'reasons': [{'reason': key, 'refused_attempts': 0, 'totals': totals}
                            for key in ('send_capacity', 'sequence_window')]}
        for flag in ('clock_regression', 'identity_mismatch', 'counter_overflow'):
            with self.subTest(flag=flag):
                value = fixture()
                value.update(blocked_union=duration(), sites=[], protocol_buffers=protocol_fixture())
                observed = copy.deepcopy(wait)
                observed[flag] = True
                value['protocol_buffers']['epochs'][0]['owners'][0]['staged_admission'] = observed
                owner = report.normalize(value, 'staged-invalid.bmetrics', 'digest')
                self.assertEqual(owner['blocked_union']['observed_us'], 0)
                self.assertIsNone(owner['owner_union_percent_of_observed_span'])
                self.assertTrue(any(flag in issue for issue in owner['issues']))

    def test_protocol_gaps_do_not_create_waits_or_union_additions(self):
        value = fixture()
        value['protocol_buffers'] = protocol_fixture()
        value['protocol_buffers']['retired_epochs_omitted'] = 2
        value['protocol_buffers']['staged_terminal_unavailable'] = 1
        owner = report.normalize(value, 'partial-provider.bmetrics', 'digest')
        self.assertEqual(owner['blocked_union']['observed_us'], 60)
        self.assertEqual(len(owner['wait_ranking']), 2)
        self.assertTrue(any('retired_epochs_omitted=2' == gap for gap in
                            owner['protocol_provider_validation']['coverage_gaps']))
        text = report.markdown({'status': owner['status'], 'owners': [owner], 'rejected_inputs': []})
        self.assertIn('exclude separate protocol-owner waits', text)
        self.assertIn('staged_terminal_unavailable=1', text)

    def test_invalid_input_schema_duplicates_types_and_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = [dict(fixture(), schema=True), dict(fixture(), schema=2),
                   dict(fixture(), observed_span_us=True)]
            for index, value in enumerate(bad):
                path = save(directory, str(index) + '.bmetrics', value)
                result = report.build_report([path])
                self.assertEqual(result['owners'], [])
                self.assertEqual(len(result['rejected_inputs']), 1)
            for raw in ('{"schema":1,"schema":1}', '{"schema":NaN}', '{broken'):
                path = Path(directory) / 'bad.bmetrics'
                path.write_text(raw, encoding='utf-8')
                self.assertEqual(report.build_report([path])['owners'], [])
        value = fixture()
        value['sites'].append(copy.deepcopy(value['sites'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate site'):
            report.normalize(value, 'duplicate.bmetrics', 'digest')
        value = fixture()
        del value['blocked_union']['open_us']
        with self.assertRaisesRegex(ValueError, 'missing open_us'):
            report.normalize(value, 'missing.bmetrics', 'digest')

    def test_bounded_reads_file_count_and_new_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = save(root, 'source.bmetrics', fixture())
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            output = root / 'report'
            result = report.write_report([source], output)
            self.assertEqual(result['owners'][0]['sha256'], digest)
            self.assertEqual({path.name for path in output.iterdir()}, {'report.md', 'report.json'})
            self.assertEqual(json.loads((output / 'report.json').read_text()), result)
            self.assertIn('60.000000%', (output / 'report.md').read_text())
            with self.assertRaisesRegex(ValueError, 'must be new'):
                report.write_report([source], output)
            with self.assertRaisesRegex(ValueError, 'duplicate input'):
                report.build_report([source, source])
            with self.assertRaisesRegex(ValueError, '1 and 64'):
                report.build_report([root / (str(i) + '.bmetrics') for i in range(65)])
            with patch.object(report, 'MAX_BYTES', 16):
                rejected = report.build_report([source])['rejected_inputs']
                self.assertIn('4 MiB bound', rejected[0]['error'])
            alias = root / 'alias.bmetrics'
            alias.symlink_to(source)
            self.assertIn('non-symlink', report.build_report([alias])['rejected_inputs'][0]['error'])
            missing = root / 'missing.bmetrics'
            result = report.write_report([source, missing], root / 'partial')
            self.assertEqual(len(result['owners']), 1)
            self.assertEqual(len(result['rejected_inputs']), 1)
            self.assertIsNone(result['rejected_inputs'][0]['measurements'])

    def test_markdown_escapes_source_labels_and_preserves_unknown(self):
        value = fixture()
        value['owner'] = '<script>|owner\nnext'
        value['sites'][0]['bytes'] = gauge(1)
        owner = report.normalize(value, '/tmp/a|b.bmetrics', 'digest')
        text = report.markdown({'status': 'parsed_partial_coverage', 'owners': [owner],
                                'rejected_inputs': []})
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;&#124;owner next', text)
        self.assertIn('capacity_unknown', text)
        self.assertIn('unmeasured', text)



def management_fixture(version=1):
    """Scalar mirror of frozen draft13 output; this is not a Rust export receipt."""
    names = ('outbound_messages', 'outbound_payload_bytes', 'outbound_fragment_bytes',
             'outbound_combined_bytes', 'confirmed_retry_metadata', 'awaiting_semantic_accepted',
             'source_confirmation_custody', 'unsubmitted_fragments', 'incomplete_messages',
             'reassembly_reserved_bytes', 'held_complete_bytes', 'recovery_send_records',
             'recovery_send_payload_bytes', 'recovery_receive_records', 'recovery_receive_payload_bytes',
             'wrapper_outgoing', 'wrapper_confirmed', 'wrapper_held', 'wrapper_dispatched', 'wrapper_leased')
    identity = {'submission': 2, 'origin_epoch': 7, 'origin_digest_hex': 'cd' * 32,
                'bytes': 224, 'original_deadline_us': 2_000}
    streams = ('Transaction', 'Liveness', 'DataFeedback') + (('Lifecycle',) if version == 2 else ())
    rows = [{'stream': stream, 'stream_control_epoch': len(streams) + index + 1, 'samples': 2,
             'last_successful_owner_us': 1_050, 'owner_failed': False,
             'held_message': None, 'held_original_deadline_us': None,
             'source_scratch_capacity_bytes': 256, 'ordinary_submit_refusals': 2,
             'ordinary_submit_duration_us': None,
             'gauges': [{'name': name, 'unit': 'bytes' if name.endswith('_bytes') else 'items',
                         'used': 0, 'high_water': 0, 'capacity': None if name in (
                             'outbound_payload_bytes', 'outbound_fragment_bytes',
                             'source_confirmation_custody') else 8} for name in names]}
            for index, stream in enumerate(streams)]
    return {'definition': 'sampled management storage', 'coverage': 'partial',
            'version': version, 'sample_interval_us': 100_000, 'samples': 2,
            'retired_owners_omitted': 0, 'unavailable_samples': 0,
            'counter_overflow': False, 'clock_regression': False, 'invalid_occupancy': False,
            'first_sample_us': 1_000, 'last_sample_us': 1_100,
            'binding': {'session_hex': '61' * 16, 'lane': 0, 'role': 'Client', 'control_epoch': 1},
            'shared_quota': {'packets_left': 1, 'bytes_left': 512, 'packets_per_interval': 2,
                             'bytes_per_interval': 2048, 'refill_at_us': 1_200},
            'reservation': copy.deepcopy(identity), 'streams': rows,
            'frozen_submission_wait': {
                'stream': 'Transaction', 'wrapper_entry_refusals': 4, 'message_capacity_refusals': 1,
                'completed_episodes': 1, 'completed_us': 40, 'censored_episodes': 1, 'censored_us': 20,
                'maximum_us': 40, 'clock_regression': False, 'identity_mismatch': False,
                'counter_overflow': False, 'observed_at_us': 1_100, 'open_us': None,
                'terminal_at_us': 1_100, 'terminal_kind': 'MetricStop', 'pending': None,
                'first_refusal_us': None, 'last_refusal_us': None,
                'last_resolved': {'identity': identity, 'first_refusal_us': 1_080,
                                  'resolved_at_us': 1_100, 'outcome': 'MetricStop', 'wire_message': None}}}


class ManagementProviderTests(unittest.TestCase):
    def normalize_management(self, provider, **changes):
        value = fixture()
        value.update(management_streams=provider, **changes)
        return report.normalize(value, 'management.bmetrics', 'digest')

    def test_management_three_four_streams_do_not_add_or_rank_overlapping_waits(self):
        for version in (1, 2):
            with self.subTest(version=version):
                provider = management_fixture(version)
                original = copy.deepcopy(provider)
                owner = self.normalize_management(provider)
                validation = owner['management_provider_validation']
                self.assertEqual(validation['status'], 'validated_known_fields_partial')
                self.assertEqual(provider, original)
                self.assertEqual(owner['provider_metadata']['management_streams'], original)
                self.assertEqual(owner['blocked_union']['observed_us'], 60)
                self.assertEqual(owner['owner_union_percent_of_observed_span'], 60)
                self.assertEqual(len(owner['wait_ranking']), 2)
                self.assertEqual(len(owner['count_only_refusals']), 1)
                self.assertEqual(len(owner['occupancy']), 1)
                text = report.markdown({'status': owner['status'], 'owners': [owner], 'rejected_inputs': []})
                self.assertIn('Management provider: validated_known_fields_partial', text)
                self.assertIn('stay separate from generic/carrier', text)
                self.assertIn('retired tails remain untimed', text)

    def test_management_unavailable_unknown_and_failed_owner_are_not_zero_waits(self):
        owner = self.normalize_management(None)
        self.assertEqual(owner['management_provider_validation']['status'], 'unavailable')
        provider = management_fixture()
        provider['frozen_submission_wait'] = None
        provider['streams'][0]['ordinary_submit_refusals'] = None
        provider['streams'][0]['owner_failed'] = True
        provider['streams'][0]['gauges'][0].update(used=None, high_water=None)
        provider['retired_owners_omitted'] = 2
        owner = self.normalize_management(provider)
        self.assertEqual(owner['management_provider_validation']['status'], 'validated_known_fields_partial')
        self.assertEqual(owner['owner_union_percent_of_observed_span'], 60)
        self.assertTrue(any('unavailable' in gap for gap in owner['management_provider_validation']['coverage_gaps']))
        self.assertIsNone(owner['provider_metadata']['management_streams']['streams'][0]['gauges'][0]['used'])
        self.assertIsNone(owner['provider_metadata']['management_streams']['frozen_submission_wait'])
        empty = management_fixture()
        empty.update(version=0, samples=0, streams=[], binding=None, first_sample_us=None,
                     last_sample_us=1100, shared_quota=None, reservation=None,
                     frozen_submission_wait=None, unavailable_samples=3)
        owner = self.normalize_management(empty)
        self.assertFalse(owner['issues'])
        self.assertTrue(any('no storage sample' in gap for gap in owner['management_provider_validation']['coverage_gaps']))
        owner = self.normalize_management({'future_layout': []})
        self.assertEqual(owner['management_provider_validation']['status'], 'invalid_or_unrecognized_shape')
        self.assertIsNone(owner['owner_union_percent_of_observed_span'])

    def test_management_nested_flags_do_not_hide_behind_generic_zero(self):
        for level, flags in [('provider', ('counter_overflow', 'clock_regression', 'invalid_occupancy')),
                             ('wait', ('counter_overflow', 'clock_regression', 'identity_mismatch'))]:
            for flag in flags:
                with self.subTest(level=level, flag=flag):
                    provider = management_fixture()
                    target = provider if level == 'provider' else provider['frozen_submission_wait']
                    target[flag] = True
                    owner = self.normalize_management(provider, blocked_union=duration(), sites=[])
                    self.assertEqual(owner['blocked_union']['observed_us'], 0)
                    self.assertIsNone(owner['owner_union_percent_of_observed_span'])
                    self.assertTrue(any(flag in issue for issue in owner['issues']))

    def test_management_bounded_identity_and_gauge_failures_are_retained(self):
        cases = ('bad_session', 'role', 'duplicate_stream', 'stream_bound', 'duplicate_epoch',
                 'gauge_bound', 'duplicate_gauge', 'unit', 'capacity', 'high_water',
                 'wrong_type', 'ordinary_time', 'quota', 'version', 'schema', 'mapping', 'sample_after_finish')
        for case in cases:
            with self.subTest(case=case):
                provider = management_fixture()
                row = provider['streams'][0]
                if case == 'bad_session': provider['binding']['session_hex'] = '00'
                elif case == 'role': provider['binding']['role'] = 'Other'
                elif case == 'duplicate_stream': provider['streams'][1]['stream'] = row['stream']
                elif case == 'stream_bound': provider['streams'] *= 2
                elif case == 'duplicate_epoch': provider['streams'][1]['stream_control_epoch'] = row['stream_control_epoch']
                elif case == 'gauge_bound': row['gauges'].append(copy.deepcopy(row['gauges'][0]))
                elif case == 'duplicate_gauge': row['gauges'][1] = copy.deepcopy(row['gauges'][0])
                elif case == 'unit': row['gauges'][0]['unit'] = 'bytes'
                elif case == 'capacity': row['gauges'][0].update(used=9, high_water=9)
                elif case == 'high_water': row['gauges'][0]['high_water'] = 9
                elif case == 'wrong_type': row['samples'] = True
                elif case == 'ordinary_time': row['ordinary_submit_duration_us'] = 0
                elif case == 'quota': provider['shared_quota']['packets_left'] = 3
                elif case == 'version': provider['version'] = 3
                elif case == 'schema': provider['schema'] = True
                elif case == 'mapping': row['stream_control_epoch'] += 100
                else: provider['last_sample_us'] = 1_101
                owner = self.normalize_management(provider)
                self.assertTrue(owner['management_provider_validation']['issues'])
                self.assertIsNone(owner['owner_union_percent_of_observed_span'])
                self.assertEqual(owner['provider_metadata']['management_streams'], provider)

    def test_management_live_frozen_identity_and_original_deadline_are_validated(self):
        provider = management_fixture()
        wait = provider['frozen_submission_wait']
        wait.update(terminal_at_us=None, terminal_kind=None, open_us=10,
                    pending=copy.deepcopy(provider['reservation']), first_refusal_us=1090, last_refusal_us=1095)
        wait['last_resolved'].update(first_refusal_us=1050, resolved_at_us=1070, outcome='Cancelled')
        owner = self.normalize_management(provider, finished_at_us=None)
        self.assertFalse(owner['issues'])
        self.assertEqual(owner['owner_union_percent_of_observed_span'], 60)
        self.assertEqual(owner['provider_metadata']['management_streams']['frozen_submission_wait']['open_us'], 10)
        for case in ('identity', 'deadline', 'open_duration', 'terminal', 'reason_total', 'missing_start',
                     'future_resolution', 'wrong_outcome_message', 'missing_resolution', 'maximum'):
            with self.subTest(case=case):
                invalid = copy.deepcopy(provider)
                observed = invalid['frozen_submission_wait']
                if case == 'identity': observed['pending']['submission'] += 1
                elif case == 'deadline': observed['pending']['original_deadline_us'] = 1095
                elif case == 'open_duration': observed['open_us'] = 11
                elif case == 'terminal': observed['terminal_at_us'] = 1100
                elif case == 'reason_total': observed.update(wrapper_entry_refusals=0, message_capacity_refusals=0)
                elif case == 'missing_start': observed['first_refusal_us'] = None
                elif case == 'future_resolution': observed['last_resolved']['resolved_at_us'] = 1099
                elif case == 'wrong_outcome_message': observed['last_resolved']['wire_message'] = 1
                elif case == 'missing_resolution': observed['last_resolved'] = None
                else: observed['maximum_us'] = 71
                owner = self.normalize_management(invalid, finished_at_us=None)
                self.assertTrue(owner['management_provider_validation']['issues'])
                self.assertIsNone(owner['owner_union_percent_of_observed_span'])
        # A root terminal export must censor an enabled open management wait.
        self.assertTrue(self.normalize_management(provider)['management_provider_validation']['issues'])

    def test_management_real_error_censor_may_pass_deadline_but_admission_may_not(self):
        provider = management_fixture()
        wait = provider['frozen_submission_wait']
        wait['last_resolved']['identity']['original_deadline_us'] = 1090
        wait['last_resolved']['outcome'] = 'OwnerFailure'
        wait['terminal_kind'] = 'OwnerFailure'
        owner = self.normalize_management(provider)
        self.assertFalse(owner['issues'])
        wait['last_resolved'].update(outcome='Admitted', wire_message=4)
        wait.update(completed_episodes=2, completed_us=60, censored_episodes=0, censored_us=0)
        owner = self.normalize_management(provider)
        self.assertTrue(owner['management_provider_validation']['issues'])


if __name__ == '__main__':
    unittest.main()
