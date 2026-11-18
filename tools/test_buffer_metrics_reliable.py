"""Offline tests of separate bounded Block FEC observations, without native traffic."""
import copy
import unittest
try:
    from . import buffer_metrics_report as report
    from . import buffer_metrics_reliable as reliable
    from .test_buffer_metrics_report import protocol_fixture, fixture as owner_fixture
except ImportError:
    import buffer_metrics_report as report
    import buffer_metrics_reliable as reliable
    from test_buffer_metrics_report import protocol_fixture, fixture as owner_fixture


def fixture():
    zero = {'completed_episodes': 0, 'completed_us': 0, 'maximum_completed_us': 0,
            'censored_episodes': 0, 'censored_us': 0, 'maximum_censored_us': 0}
    return {'scope': 'endpoint-shared', 'epoch': 7, 'send_direction': 0,
            'sealed_output_present': True, 'observed_at_us': 100, 'terminal_at_us': None, 'clock_regression': False,
            'identity_mismatch': False, 'counter_overflow': False, 'union': dict(zero),
            'reasons': [{'reason': name, 'refusals': 2, 'totals': dict(zero),
                         'pending_since_us': 90} for name in reliable.REASONS],
            'pending': {'operation': {'generation': 4, 'symbol': 3, 'bytes': 127},
                        'since_us': 90, 'last_refusal_us': 95, 'open_us': 10},
            'last_resolved': None,
            'capacity_refusals': [{'reason': name, 'refusals': 0}
                                 for name in reliable.CAPACITY_REASONS]}


class ReliableProviderTests(unittest.TestCase):
    def provider(self, value):
        result = protocol_fixture()
        result['epochs'][0]['reliable_output'] = value
        return result

    def check(self, value):
        return report.protocol_provider(self.provider(value))

    def test_head_identity_and_overlapping_reasons_remain_separate(self):
        value = fixture()
        self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
        for totals in [value['union'], *(v['totals'] for v in value['reasons'])]:
            totals.update(completed_episodes=1, completed_us=10, maximum_completed_us=10)
        value.update(pending=None, last_resolved={'operation': {'generation': 4, 'symbol': 3, 'bytes': 127},
                                                 'since_us': 90, 'at_us': 100, 'censored': False})
        for row in value['reasons']:
            row['pending_since_us'] = None
        value['capacity_refusals'][1]['refusals'] = 3
        self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
        lines = []
        reliable.render(lines, {'protocol_buffers': self.provider(value)}, report.table, report.cell)
        text = '\n'.join(lines)
        self.assertIn('fec_generation_slots', text)
        self.assertIn('10 (1)', text)
        self.assertIn('not physical acceptance', text)
        self.assertIn('Reasons overlap', text)
        self.assertEqual(value['union']['completed_us'], 10)  # Not the reason sum of 20.

    def test_invalid_identity_and_unknown_or_terminal_intervals_are_not_valid_zero(self):
        mutations = [lambda v: v.update(epoch=8), lambda v: v.update(scope='independent-connection'),
                     lambda v: v.update(counter_overflow=True),
                     lambda v: v['pending'].update(open_us=9),
                     lambda v: v['pending']['operation'].update(symbol=1 << 32),
                     lambda v: v['pending']['operation'].update(bytes=65536),
                     lambda v: v.update(terminal_at_us=100),
                     lambda v: v['reasons'][0].update(reason='wire_byte_budget'),
                     lambda v: v['capacity_refusals'].append(copy.deepcopy(v['capacity_refusals'][0]))]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = fixture()
                mutate(value)
                self.assertTrue(self.check(value)['status'].startswith('invalid'))

    def test_fresh_censor_and_absent_compact_fec_keep_explicit_coverage(self):
        value = fixture()
        value.update(terminal_at_us=100, pending=None,
                     last_resolved={'operation': {'generation': 4, 'symbol': 3, 'bytes': 127},
                                    'since_us': 90, 'at_us': 100, 'censored': True})
        for totals in [value['union'], *(v['totals'] for v in value['reasons'])]:
            totals.update(censored_episodes=1, censored_us=10, maximum_censored_us=10)
        for row in value['reasons']:
            row['pending_since_us'] = None
        self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
        result = self.check(None)
        self.assertEqual(result['status'], 'validated_known_fields_partial')
        self.assertTrue(any('absence is not zero' in text for text in result['coverage_gaps']))
        self.assertIsNone(self.provider(None)['epochs'][0]['reliable_output'])
        wrong_role = self.provider(fixture())
        wrong_role['local_role'] = 'Server'
        self.assertTrue(report.protocol_provider(wrong_role)['status'].startswith('invalid'))


    def test_invalid_parent_shape_is_retained_but_never_rendered_as_measurement(self):
        for mutate in (lambda p: p.update(epochs=None), lambda p: p.update(epochs=3),
                       lambda p: p.update(schema=99)):
            with self.subTest(mutate=mutate):
                provider = self.provider(fixture())
                mutate(provider)
                value = owner_fixture()
                value['protocol_buffers'] = provider
                owner = report.normalize(value, 'invalid.bmetrics', 'source-hash')
                self.assertTrue(owner['protocol_provider_validation']['status'].startswith('invalid'))
                text = report.markdown({'status': owner['status'], 'owners': [owner], 'rejected_inputs': []})
                self.assertNotIn('### Block FEC retained output:', text)
                self.assertEqual(owner['provider_metadata']['protocol_buffers'], provider)

    def test_sparse_sequence_gate_keeps_maximum_source_and_original_flow_identity(self):
        value = fixture()
        value['staged_source'] = staged_fixture()
        self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
        lines = []
        reliable.render(lines, {'protocol_buffers': self.provider(value)}, report.table, report.cell)
        rendered = '\n'.join(lines)
        self.assertIn('earlier held sources', rendered)
        self.assertIn('sequence_full', rendered)
        self.assertIn('1/2', rendered)
        self.assertEqual(value['staged_source']['maximum_completed']['pending']['native']['flow'], 100)

    def test_validated_ack_and_held_retry_remain_distinct_from_physical_retirement(self):
        value = fixture(); value['staged_source'] = ack_staged_fixture()
        self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
        lines = []
        reliable.render(lines, {'protocol_buffers': self.provider(value)}, report.table, report.cell)
        text = '\n'.join(lines)
        self.assertIn('acknowledged held physical retry', text)
        self.assertIn('Physical held after', text)
        event = value['staged_source']['last_ack']
        self.assertTrue(event['covers_before'])
        self.assertFalse(event['retired_before'])
        self.assertEqual(event['released_records'], 0)
        old = fixture(); old['staged_source'] = staged_fixture()
        self.assertTrue(any('schema 1' in gap for gap in self.check(old)['coverage_gaps']))
        unsupported = value['staged_source']
        unsupported.update(ack_coverage='unavailable', last_ack=None)
        for key in ('maximum_completed', 'last_resolved'):
            unsupported[key]['latest_ack'] = None
        result = self.check(value)
        self.assertEqual(result['status'], 'validated_known_fields_partial')
        self.assertTrue(any('ACK boundary unavailable' in gap for gap in result['coverage_gaps']))

    def test_ack_false_coverage_identity_and_time_are_rejected(self):
        mutations = (
            lambda v: v.update(ack_coverage='unknown'),
            lambda v: v.update(last_ack=None),
            lambda v: v['last_ack'].update(serial=0),
            lambda v: v['last_ack'].update(covers_before=False),
            lambda v: v['last_ack'].update(retired_before=True),
            lambda v: v['last_ack'].update(released_bytes=4),
            lambda v: v['last_ack']['after'].update(physical_pending=False),
            lambda v: v['last_ack'].update(before=None),
            lambda v: v['last_ack'].update(bitmap=1),
            lambda v: v['last_ack'].update(received_us=100),
            lambda v: v['maximum_completed']['latest_ack'].update(observed_us=31),
            lambda v: v['maximum_completed']['pending'].update(ack_before=1),
            lambda v: v.update(schema=3),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = fixture(); value['staged_source'] = ack_staged_fixture()
                mutate(value['staged_source'])
                self.assertTrue(self.check(value)['status'].startswith('invalid'))

    def test_ack_start_serial_cannot_exceed_owner_history(self):
        for population in ('pending', 'last_resolved', 'maximum_completed', 'maximum_censored'):
            for history in ('observed', 'not_yet_observed', 'unavailable'):
                with self.subTest(population=population, history=history):
                    value = fixture()
                    staged = value['staged_source'] = ack_staged_fixture()
                    for name in ('last_resolved', 'maximum_completed'):
                        staged[name]['latest_ack'] = None
                    if history != 'observed':
                        staged['last_ack'] = None
                    if history == 'unavailable':
                        staged['ack_coverage'] = 'unavailable'
                    if population == 'pending':
                        staged['pending'] = copy.deepcopy(staged['last_resolved']['pending'])
                        pending = staged['pending']
                    elif population == 'maximum_censored':
                        value.update(terminal_at_us=100, pending=None,
                                     last_resolved={'operation': {'generation': 4, 'symbol': 3, 'bytes': 127},
                                                    'since_us': 90, 'at_us': 100, 'censored': True})
                        for totals in [value['union'], *(v['totals'] for v in value['reasons'])]:
                            totals.update(censored_episodes=1, censored_us=10, maximum_censored_us=10)
                        for row in value['reasons']:
                            row['pending_since_us'] = None
                        staged['terminal_at_us'] = 100
                        staged[population] = copy.deepcopy(staged['maximum_completed'])
                        staged[population].update(at_us=100, censored=True)
                        pending = staged[population]['pending']
                    else:
                        pending = staged[population]['pending']
                    # Each population/availability shape is valid before the one
                    # impossible producer-history mutation, including null history.
                    self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
                    pending['ack_before'] = 2 if history == 'observed' else 1
                    self.assertTrue(self.check(value)['status'].startswith('invalid'))

    def test_staged_unknown_identity_and_false_predicates_are_not_valid_zero(self):
        mutations = (
            lambda v: v.update(schema=2),
            lambda v: v.update(invalid=True),
            lambda v: v['maximum_completed']['pending'].update(unit=None),
            lambda v: v['maximum_completed']['pending']['last_gate'].update(records_full=True),
            lambda v: v['maximum_completed']['pending']['last_gate'].update(sequence_full=False),
            lambda v: v['maximum_completed']['pending']['last_gate'].update(next_source=3),
            lambda v: v['maximum_completed']['pending']['unit'].update(native_record=14),
            lambda v: v.update(terminal_at_us=100),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = fixture(); value['staged_source'] = staged_fixture()
                mutate(value['staged_source'])
                self.assertTrue(self.check(value)['status'].startswith('invalid'))
        value = fixture(); value['staged_source'] = staged_fixture()
        for key in ('last_resolved', 'maximum_completed'):
            value['staged_source'][key]['pending'].update(unit=None, native=None)
        self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')


def staged_fixture():
    gate = {'next_source': 2, 'span_base': 0, 'records': 1, 'records_capacity': 2,
            'bytes': 4, 'bytes_capacity': 512, 'proposed_bytes': 3, 'resulting_bytes': 7,
            'records_full': False, 'bytes_full': False, 'sequence_full': True,
            'oldest': {'source': 0, 'attempts': 1, 'transmission': 1,
                       'acknowledged': False, 'retry_at_us': 1000}}
    pending = {'source': 2, 'bytes': 3, 'since_us': 10, 'last_refusal_us': 11,
               'retirement_before': 0,
               'unit': {'channel': 7, 'record': 12, 'native_record': 13, 'offset': 16, 'context': True},
               'native': {'flow': 100, 'received_us': 0, 'queued_us': 1, 'deadline_us': 500},
               'first_gate': copy.deepcopy(gate), 'last_gate': copy.deepcopy(gate)}
    resolved = {'pending': pending, 'at_us': 30, 'censored': False,
                'latest_retirement': {'serial': 1, 'observed_us': 29, 'accepted_us': None,
                                      'kind': 'input', 'records': 1, 'bytes': 4, 'operation_succeeded': True}}
    return {'schema': 1, 'invalid': False, 'terminal_at_us': None, 'pending': None,
            'last_resolved': copy.deepcopy(resolved), 'maximum_completed': copy.deepcopy(resolved),
            'maximum_censored': None, 'last_retirement': copy.deepcopy(resolved['latest_retirement'])}


def ack_staged_fixture():
    value = staged_fixture()
    before = {'source': 0, 'attempts': 2, 'transmission': 7, 'acknowledged': False,
              'physical_pending': True, 'retry_at_us': None}
    event = {'serial': 1, 'received_us': 20, 'observed_us': 29, 'prefix': 1, 'bitmap': 0,
             'before': before, 'after': dict(before, acknowledged=True),
             'covers_before': True, 'retired_before': False,
             'released_records': 0, 'released_bytes': 0}
    value.update(schema=2, ack_coverage='selected_selective', last_ack=copy.deepcopy(event))
    for key in ('last_resolved', 'maximum_completed'):
        row = value[key]
        row['pending']['ack_before'] = 0
        row['latest_ack'] = copy.deepcopy(event)
        row['latest_retirement'].update(kind='physical', accepted_us=29, observed_us=30)
    value['last_retirement'] = copy.deepcopy(value['last_resolved']['latest_retirement'])
    return value


if __name__ == '__main__':
    unittest.main()
