"""Offline shape and attribution tests for the one actual receiver handoff slot."""
import copy
import unittest
from . import buffer_metrics_report as report
from . import buffer_metrics_handoff as handoff
from .test_buffer_metrics_report import protocol_fixture, fixture as owner_fixture


def fixture():
    return {'schema': 1, 'scope': 'endpoint-shared-receive', 'epoch': 7,
            'receive_direction': 1, 'packed': False, 'cells': 1,
            'inner_unit_identity': None, 'missing_context_wait': None, 'native_consumer_wait': None,
            'observed_at_us': 100, 'terminal_at_us': None, 'terminal': None,
            'terminal_unavailable': False, 'clock_regression': False,
            'identity_mismatch': False, 'counter_overflow': False,
            'refusals': [{'reason': 'capacity', 'count': 2}, {'reason': 'record_window', 'count': 1}],
            'totals': {'completed_episodes': 0, 'completed_us': 0, 'maximum_completed_us': 0,
                       'censored_episodes': 0, 'censored_us': 0, 'maximum_censored_us': 0},
            'pending': {'source': 791, 'bytes': 83, 'original_deadline_us': 200,
                        'since_us': 90, 'last_refusal_us': 95,
                        'first_reason': 'capacity', 'last_reason': 'record_window'},
            'last_resolved': None, 'maximum_completed': None, 'maximum_censored': None}


def provider(value):
    result = protocol_fixture()
    result['local_role'] = 'Client'
    result['epochs'][0].update(last_sample_us=100, receiver_handoff=value)
    return result


def resolve(value, release):
    pending = value['pending']
    value['pending'] = None
    record = {'pending': pending, 'at_us': 100, 'release': release}
    name = 'censored' if release is None else 'completed'
    value['totals'].update({name + '_episodes': 1, name + '_us': 10, 'maximum_' + name + '_us': 10})
    value['last_resolved'] = record
    value['maximum_' + name] = copy.deepcopy(record)
    if release is None:
        value.update(terminal_at_us=100, terminal='metric_stop')


class ReceiverHandoffTests(unittest.TestCase):
    def check(self, value):
        return report.protocol_provider(provider(value))

    def test_exact_source_original_cap_and_separate_release_populations(self):
        for release in ('admitted', 'already_observed', 'packed_batch', None):
            with self.subTest(release=release):
                value = fixture()
                value['packed'] = release == 'packed_batch'
                resolve(value, release)
                self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
                lines = []
                handoff.render(lines, {'protocol_buffers': provider(value)}, report.table, report.cell)
                text = '\n'.join(lines)
                self.assertIn('791', text)
                self.assertIn('Original cap us', text)
                self.assertIn('not continuous fullness or native delivery', text)
        self.assertEqual(self.check(fixture())['status'], 'validated_known_fields_partial')

    def test_bad_identity_caps_time_release_and_populations_are_rejected(self):
        mutations = [lambda v: v.update(schema=True), lambda v: v.update(epoch=8),
                     lambda v: v.update(receive_direction=0), lambda v: v.update(cells=2),
                     lambda v: v.update(packed=True), lambda v: v.update(inner_unit_identity=0),
                     lambda v: v['last_resolved']['pending'].update(original_deadline_us=99),
                     lambda v: v['last_resolved']['pending'].update(last_refusal_us=101),
                     lambda v: v['totals'].update(maximum_completed_us=9),
                     lambda v: v['refusals'][0].update(count=0),
                     lambda v: v.update(counter_overflow=True),
                     lambda v: v.update(terminal_at_us=100)]
        for mutate in mutations:
            value = fixture()
            resolve(value, 'admitted')
            mutate(value)
            with self.subTest(mutate=mutate):
                self.assertTrue(self.check(value)['status'].startswith('invalid'))

    def test_present_handoff_requires_known_endpoint_role_but_absence_stays_compatible(self):
        for role in (None, 'Unknown'):
            with self.subTest(role=role):
                value = provider(fixture())
                if role is None:
                    del value['local_role']
                else:
                    value['local_role'] = role
                self.assertEqual(report.protocol_provider(value)['status'],
                                 'invalid_or_unrecognized_shape')
                value['epochs'][0]['receiver_handoff'] = None
                self.assertEqual(report.protocol_provider(value)['status'],
                                 'validated_known_fields_partial')

    def test_stale_terminal_is_unavailable_not_extended_and_null_is_not_zero(self):
        absent = self.check(None)
        self.assertEqual(absent['status'], 'validated_known_fields_partial')
        self.assertTrue(any('absence is not zero' in gap for gap in absent['coverage_gaps']))
        value = fixture()
        value['terminal_unavailable'] = True
        result = self.check(value)
        self.assertEqual(result['status'], 'invalid_observations')
        self.assertIsNone(value['terminal_at_us'])
        self.assertEqual(value['totals']['censored_episodes'], 0)

    def test_invalid_parent_is_not_rendered_and_submicrosecond_rounding_is_valid(self):
        value = fixture()
        resolve(value, 'admitted')
        # Two durations of 10.5us sum to 21us but each maximum floors to 10us.
        value['totals'].update(completed_episodes=2, completed_us=21, maximum_completed_us=10)
        self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
        for replacement in (None, 3):
            p = provider(fixture())
            p['epochs'] = replacement
            lines = []
            handoff.render(lines, {'protocol_buffers': p}, report.table, report.cell)
            self.assertEqual(lines, [])
        p = provider(fixture())
        p['schema'] = 99
        owner = owner_fixture()
        owner['protocol_buffers'] = p
        normalized = report.normalize(owner, 'invalid.bmetrics', 'hash')
        self.assertEqual(normalized['protocol_provider_validation']['status'], 'invalid_or_unrecognized_shape')
        lines = []
        handoff.render(lines, {'protocol_buffers': p}, report.table, report.cell)
        self.assertEqual(lines, [])


if __name__ == '__main__':
    unittest.main()
