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


if __name__ == '__main__':
    unittest.main()
