"""Offline exact data-head provider fixtures; no protocol or native workload."""
import copy
import unittest
try:
    from . import buffer_metrics_rolling_ingress as ingress
    from . import buffer_metrics_rolling as rolling
    from .test_buffer_metrics_rolling import fixture as rolling_fixture
except ImportError:
    import buffer_metrics_rolling_ingress as ingress
    import buffer_metrics_rolling as rolling
    from test_buffer_metrics_rolling import fixture as rolling_fixture


def fixture():
    job = {'identity': {'kind': 'source', 'first': 0, 'end': 1},
           'received_us': 1, 'admitted_us': 10, 'original_deadline_us': 1000}
    return {'schema': 1, 'receive_direction': 1, 'next_head': 2, 'refusals': 2,
            'omitted_refusals': 0, 'blocker_unavailable': 0, 'terminal_unavailable': False,
            'terminal_at_us': None,
            'populations': [{'outcome': name, 'episodes': 0, 'sum_us': 0, 'maximum_us': 0,
                             'completions': (1 if i == 0 else 0) if i < 3 else None,
                             'without_refusal': (1 if i == 0 else 0) if i < 3 else None}
                            for i, name in enumerate(ingress.OUTCOMES)],
            'pending': {'serial': 2,
                        'input': {'records_number': 72, 'received_us': 2,
                                  'original_deadline_us': 900, 'bytes': 64, 'kind': 'source'},
                        'since_us': 11, 'last_refusal_us': 12,
                        'first_blocker': copy.deepcopy(job), 'latest_blocker': copy.deepcopy(job)},
            'open_us': 89, 'last_resolved': None}


def resolved(name):
    value = fixture()
    pending = value['pending']
    at = 100 if name == 'censored' else 20
    new = {'identity': {'kind': 'source', 'first': 1, 'end': 2},
           'received_us': 2, 'admitted_us': 20, 'original_deadline_us': 900}
    value.update(pending=None, open_us=None,
                 last_resolved={'pending': pending, 'at_us': at, 'outcome': name,
                                'admitted_job': new if name == 'staged' else None})
    row = value['populations'][ingress.OUTCOMES.index(name)]
    row.update(episodes=1, sum_us=at - 11, maximum_us=at - 11)
    if name == 'censored':
        value['terminal_at_us'] = at
    else:
        row['completions'] += 1
        value['next_head'] += 1
    return value


class RollingIngressTests(unittest.TestCase):
    def check(self, value, terminal=None):
        issues, gaps = [], []
        ingress.validate(value, 100, terminal, 0, 'ingress', issues, gaps)
        return issues, gaps

    def test_open_and_each_result_keep_distinct_actual_populations(self):
        self.assertEqual(self.check(fixture())[0], [])
        for name in ingress.OUTCOMES:
            with self.subTest(outcome=name):
                self.assertEqual(self.check(resolved(name), 100 if name == 'censored' else None)[0], [])

    def test_historical_absence_and_unknown_identity_remain_unavailable(self):
        old = rolling_fixture()
        issues, gaps = [], []
        rolling.validate(old, 7, 'rolling', issues, gaps)
        self.assertEqual(issues, [])
        self.assertTrue(any('data-head Busy timing unavailable' in g for g in gaps))
        value = fixture()
        value['pending']['input']['records_number'] = None
        value['pending']['first_blocker'] = None
        value['blocker_unavailable'] = 1
        self.assertTrue(any('Records identity unavailable' in g for g in self.check(value)[1]))
        stale = fixture()
        stale['terminal_unavailable'] = True
        stale['open_us'] = None
        self.assertTrue(self.check(stale, 100)[0])

    def test_identity_deadline_outcome_and_population_mutations_are_rejected(self):
        mutations = [lambda v: v.update(schema=True),
                     lambda v: v.update(receive_direction=0),
                     lambda v: v.update(next_head=3),
                     lambda v: v.update(open_us=88),
                     lambda v: v['pending'].update(serial=1),
                     lambda v: v['pending']['input'].update(original_deadline_us=12),
                     lambda v: v['pending']['first_blocker'].update(admitted_us=12),
                     lambda v: v['pending'].update(first_blocker=None),
                     lambda v: v.update(terminal_unavailable=True),
                     lambda v: v['populations'][0].update(without_refusal=0),
                     lambda v: v.update(terminal_at_us=100)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = fixture()
                mutate(value)
                with self.assertRaises(ValueError):
                    self.check(value)
        value = resolved('staged')
        value['last_resolved']['admitted_job'] = copy.deepcopy(value['last_resolved']['pending']['first_blocker'])
        with self.assertRaisesRegex(ValueError, 'new job'):
            self.check(value)
        value = resolved('duplicate')
        value['last_resolved']['admitted_job'] = fixture()['pending']['first_blocker']
        with self.assertRaisesRegex(ValueError, 'fabricated new job'):
            self.check(value)
        value = resolved('stale')
        value['populations'][2]['maximum_us'] = 1
        with self.assertRaisesRegex(ValueError, 'duration population'):
            self.check(value)

    def test_render_exposes_outcomes_and_blocker_roles_without_union_percentage(self):
        value = rolling_fixture()
        value['ingress_admission'] = resolved('staged')
        issues, gaps = [], []
        rolling.validate(value, 7, 'rolling', issues, gaps)
        self.assertEqual(issues, [])
        lines = []
        def table(lines, headers, rows):
            lines.append(' | '.join(headers))
            lines.extend(' | '.join(map(str, row)) for row in rows)
        ingress.render(lines, {'protocol_buffers': {'epochs': [
            {'epoch': 7, 'rolling_waits': value}]}}, table, str)
        text = '\n'.join(lines)
        for token in ('staged', 'duplicate', 'stale', 'censored', 'first blocker', 'newly admitted', '72'):
            self.assertIn(token, text)
        self.assertNotIn('%', text)


if __name__ == '__main__':
    unittest.main()
