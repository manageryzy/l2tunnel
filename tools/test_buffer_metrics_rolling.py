"""Bounded offline Rolling provider validation; no protocol/native workload."""
import copy
import unittest
try:
    from . import buffer_metrics_report as report
    from .test_buffer_metrics_report import protocol_fixture
except ImportError:
    import buffer_metrics_report as report
    from test_buffer_metrics_report import protocol_fixture


def fixture():
    zero = {'completed_episodes': 0, 'completed_us': 0, 'maximum_completed_us': 0,
            'censored_episodes': 0, 'censored_us': 0, 'maximum_censored_us': 0}
    reasons = ['recovery_busy', 'recovery_capacity', 'record_busy', 'record_capacity',
               'record_window', 'packet_budget', 'wire_byte_budget']
    value = {'instance': 1, 'session_hex': '01' * 16, 'epoch': 7, 'stream': 17,
             'send_direction': 0, 'observed_at_us': 100, 'terminal_at_us': None,
             'terminal_stage': None, 'clock_regression': False, 'identity_mismatch': False,
             'counter_overflow': False, 'sites': []}
    for i, name in enumerate(('source_admission', 'decoded_handoff', 'feedback_budget')):
        value['sites'].append({'site': name, 'direction': 0 if i == 0 else 1,
                              'deadline_owner': ('codec_stage', 'decoder_handoff_cohort',
                                                 'immutable_feedback_output')[i],
                              'union': dict(zero), 'pending': None, 'last_resolved': None,
                              'reasons': [{'reason': reason, 'refusals': 0, 'totals': dict(zero),
                                           'pending_since_us': None} for reason in reasons]})
    row = value['sites'][2]
    row['pending'] = {'operation': {'id': 1, 'bytes': 20, 'original_deadline_us': 1000,
                                   'packets': 1, 'wire_bytes': 69, 'copies': 0},
                      'since_us': 90, 'last_refusal_us': 95, 'open_us': 10}
    for reason in row['reasons'][5:]:
        reason['refusals'] = 2
        reason['pending_since_us'] = 90
    return value


class RollingProviderTests(unittest.TestCase):
    def check(self, value):
        provider = protocol_fixture()
        provider['epochs'][0]['rolling_waits'] = value
        return report.protocol_provider(provider)

    def test_actual_open_identity_is_separate_and_unknown_cap_preserved(self):
        value = fixture()
        self.assertEqual(self.check(value)['status'], 'validated_known_fields_partial')
        value['sites'][2]['pending']['operation']['original_deadline_us'] = None
        result = self.check(value)
        self.assertEqual(result['status'], 'validated_known_fields_partial')
        self.assertTrue(any('deadline unavailable' in gap for gap in result['coverage_gaps']))
        self.assertIsNone(value['sites'][2]['pending']['operation']['original_deadline_us'])

    def test_invalid_identity_geometry_and_terminal_are_not_valid_zero(self):
        mutations = [lambda v: v.update(epoch=8),
                     lambda v: v.update(counter_overflow=True),
                     lambda v: v['sites'].append(copy.deepcopy(v['sites'][0])),
                     lambda v: v['sites'][2]['pending'].update(open_us=9),
                     lambda v: v['sites'][2]['pending']['operation'].update(wire_bytes=1),
                     lambda v: v.update(terminal_at_us=100, terminal_stage='driver_drop'),
                     lambda v: v['sites'][0]['reasons'][5].update(refusals=1)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = fixture()
                mutate(value)
                self.assertTrue(self.check(value)['status'].startswith('invalid'))

    def test_unknown_shape_and_absence_have_explicit_coverage(self):
        self.assertTrue(self.check({'future_schema': 2})['status'].startswith('invalid'))
        result = self.check(None)
        self.assertEqual(result['status'], 'validated_known_fields_partial')
        self.assertTrue(any('Rolling/Research wait timing unavailable' in gap
                            for gap in result['coverage_gaps']))


if __name__ == '__main__':
    unittest.main()
