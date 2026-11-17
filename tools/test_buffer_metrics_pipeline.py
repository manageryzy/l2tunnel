"""Finite offline provider checks, without compiler or native workloads."""
import copy
import unittest

try:
    from . import buffer_metrics_pipeline as provider
except ImportError:
    import buffer_metrics_pipeline as provider


def totals(completed=0, censored=0):
    return {'episodes': int(completed != 0) + int(censored != 0),
            'completed_episodes': int(completed != 0), 'completed_us': completed,
            'censored_episodes': int(censored != 0), 'censored_us': censored,
            'maximum_us': max(completed, censored), 'open_us': None}


def fixture():
    row = {'epoch': 1, 'configuration_digest_hex': 'ab' * 32, 'flow_id': 1, 'channel': 0,
           'first_refusal_us': 10, 'last_event_us': 50, 'retired_at_us': None,
           'blocked_heads': totals(30),
           'reasons': [{'reason': name, 'refusals': int(name == 'codec_stage'),
                        'blocked': totals(30 if name == 'codec_stage' else 0)}
                       for name in provider.REASONS]}
    other = copy.deepcopy(row)
    other['epoch'], other['channel'] = 2, 1
    return {'flow_limit': 2, 'retained_flows': 2, 'omitted_refusals': 0,
            'unavailable_terminal': 0, 'identity_errors': 0, 'clock_regressions': 0,
            'after_terminal': 0, 'counter_overflow': False, 'terminal_at_us': 50,
            'flows': [row, other]}


class PipelineProviderTests(unittest.TestCase):
    def test_identity_and_independent_populations_are_preserved(self):
        observed = provider.validate(fixture())
        self.assertEqual(observed['status'], 'parsed_partial_coverage')
        self.assertEqual(len(observed['flows']), 2)
        self.assertEqual([row['epoch'] for row in observed['flows']], [1, 2])
        self.assertNotIn('union_percent', observed)
        self.assertNotIn('total_us', observed)

    def test_saturation_and_missing_terminal_remain_explicit_coverage_gaps(self):
        source = fixture()
        source['omitted_refusals'], source['unavailable_terminal'] = 7, 1
        observed = provider.validate(source)
        self.assertEqual(observed['status'], 'parsed_partial_coverage')
        self.assertIn('omitted_refusals=7', observed['coverage_gaps'])
        self.assertIn('unavailable_terminal=1', observed['coverage_gaps'])
        self.assertEqual(provider.validate(None)['status'], 'unavailable')

    def test_duplicate_identity_or_terminal_open_wait_is_rejected(self):
        source = fixture()
        source['flows'][1] = copy.deepcopy(source['flows'][0])
        self.assertEqual(provider.validate(source)['status'], 'invalid_observations')
        source = fixture()
        source['flows'][0]['blocked_heads']['open_us'] = 3
        self.assertEqual(provider.validate(source)['status'], 'invalid_observations')

    def test_first_refusal_segments_partition_only_their_own_flow_head(self):
        source = fixture()
        source['flows'][0]['reasons'][2]['blocked'] = totals(1000)
        observed = provider.validate(source)
        self.assertEqual(observed['status'], 'invalid_observations')
        self.assertTrue(any('partition' in issue for issue in observed['issues']))
        source = fixture()
        row = source['flows'][0]
        row['blocked_heads'] = totals(censored=30)
        row['reasons'][0]['refusals'] = 1
        row['reasons'][0]['blocked'] = totals(completed=10)
        row['reasons'][2]['blocked'] = totals(censored=20)
        observed = provider.validate(source)
        self.assertEqual(observed['status'], 'parsed_partial_coverage')
        rendered, tables = [], []
        provider.render(rendered, observed, lambda lines, headers, rows: tables.append(rows), str)
        self.assertEqual(len(tables), 2)
        self.assertTrue(any('native_delivery_window' in row for row in tables[1]))
        self.assertTrue(any('codec_stage' in row for row in tables[1]))


if __name__ == '__main__':
    unittest.main()
