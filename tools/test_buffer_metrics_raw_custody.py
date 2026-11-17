"""Offline raw-token latency report contract, independent of native workload."""
import copy
import unittest

try:
    from .buffer_metrics_report import normalize, markdown
except ImportError:
    from buffer_metrics_report import normalize, markdown


def source():
    rows = []
    for lane in (0, 1):
        for cls in ('User', 'Control'):
            rows.append(dict(lane=lane, **{'class': cls}, committed=0, physical_observed=0,
                             upper_taken=0, late_physical=0,
                             **{key: {'samples': 0, 'sum_us': 0, 'max_us': 0} for key in
                                ('commit_to_physical', 'physical_to_observe', 'observe_to_take',
                                 'censored_before_physical_observation', 'censored_after_physical_observation')}))
    row = rows[0]
    row.update(committed=3, physical_observed=2, upper_taken=1, late_physical=1)
    for name, samples, total, maximum in (
        ('commit_to_physical', 2, 20, 15), ('physical_to_observe', 2, 5, 3),
        ('observe_to_take', 1, 6, 6), ('censored_before_physical_observation', 1, 35, 35),
        ('censored_after_physical_observation', 1, 10, 10)):
        row[name] = dict(samples=samples, sum_us=total, max_us=maximum)
    return {'schema': 1, 'owner': 'raw_custody', 'pid': 42, 'diagnostic_heap_bytes': 1024,
            'inline_bytes': 24, 'definition': 'Exact latency; not blocked time.',
            'coverage': 'Final records only.', 'blocked_union': None, 'sites': [],
            'raw_custody': {'schema': 1, 'finished': True, 'observed_us': 100,
                            'invalid_clock': False, 'counter_overflow': False,
                            'identity_mismatches': 0, 'duplicate_observations': 1, 'rows': rows}}


class RawCustodyTests(unittest.TestCase):
    def test_success_and_censor_populations_remain_separate_and_union_unknown(self):
        value = normalize(source(), 'owner.bmetrics', 'a' * 64)
        self.assertEqual(value['status'], 'parsed_partial_coverage')
        self.assertIsNone(value['blocked_union'])
        self.assertIsNone(value['owner_union_percent_of_observed_span'])
        row = value['raw_custody_validation']['rows'][0]
        self.assertEqual(row['physical_observed'], 2)
        self.assertEqual(row['censored_before_physical_observation']['samples'], 1)
        report = {'owners': [value], 'rejected_inputs': [], 'status': 'parsed_partial_coverage'}
        text = markdown(report)
        self.assertIn('commit_to_physical', text)
        self.assertIn('censored_after_physical_observation', text)
        self.assertIn('Generic blocked time and percentage are unmeasured', text)

    def test_claimed_blocked_union_and_duplicate_owner_rows_are_rejected(self):
        value = source()
        value['blocked_union'] = {'completed_us': 0}
        with self.assertRaises(ValueError):
            normalize(value, 'owner.bmetrics', 'a' * 64)
        value = source()
        value['raw_custody']['rows'][1] = copy.deepcopy(value['raw_custody']['rows'][0])
        with self.assertRaises(ValueError):
            normalize(value, 'owner.bmetrics', 'a' * 64)

    def test_identity_clock_and_boundary_count_defects_are_visible(self):
        value = source()
        value['raw_custody']['identity_mismatches'] = 1
        value['raw_custody']['invalid_clock'] = True
        value['raw_custody']['rows'][0]['physical_to_observe']['samples'] = 1
        observed = normalize(value, 'owner.bmetrics', 'a' * 64)
        self.assertEqual(observed['status'], 'invalid_observations')
        self.assertGreaterEqual(len(observed['issues']), 3)


if __name__ == '__main__':
    unittest.main()
