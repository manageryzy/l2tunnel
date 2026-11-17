#!/usr/bin/env python3
"""Offline evidence and provenance checks; no workload or network access."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

try:
    from . import common_matrix_report as report
except ImportError:
    import common_matrix_report as report


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
