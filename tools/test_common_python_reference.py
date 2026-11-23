"""Unprivileged named-reference contract and actual pre-I/O gate regressions."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

try:
    from . import common_native_matrix as matrix, common_python_reference as reference
    from .test_common_native_matrix import row as component_row
except ImportError:
    import common_native_matrix as matrix
    import common_python_reference as reference
    from test_common_native_matrix import row as component_row


def named_row(carrier='udp'):
    value = component_row()
    entry = reference.registry()['references'][reference.SUPPORTED]
    value.update(id='python-compact-arq-' + carrier, carrier=carrier,
                 algorithm='per_connection_compact', python_reference={
                     'schema': 1, 'id': reference.SUPPORTED, 'reference_sha256': entry['sha256'],
                     'claim': 'algorithm_configuration_only', 'actual': dict(entry['required_actual']),
                     'remaining_differences': sorted(reference.DIFFERENCES)})
    return value


def inspection(value, side='a'):
    return {'event': ('secure_udp_common_requested_carrier_plan' if value['carrier'] == 'raw'
                      else 'secure_udp_common_plan'),
            'schema': 1, 'validated': True, 'requested': True, 'authenticated': False,
            'role': 'initiator' if side == 'a' else 'responder',
            'python_reference_descriptor_hex': value['expected_descriptor_hex'],
            'python_reference_actual': dict(value['python_reference']['actual'])}


class PythonReferenceTests(unittest.TestCase):
    def test_full_registry_entries_bind_distinct_saved_named_configurations(self):
        values = reference.registry()
        for name, entry in values['references'].items():
            with self.subTest(reference=name):
                self.assertEqual(entry['id'], name)
                self.assertEqual(entry['sha256'], reference.digest(
                    {key: value for key, value in entry.items() if key != 'sha256'}))
                self.assertTrue(entry['configuration'])
                self.assertTrue(entry['source_sha256'])
        self.assertEqual(len({entry['sha256'] for entry in values['references'].values()}), 4)

    def test_named_selection_is_only_a_bounded_algorithm_claim(self):
        result = reference.validate_row(named_row())
        self.assertFalse(result['exact_native_equivalence'])
        self.assertEqual(set(result['remaining_differences']), reference.DIFFERENCES)
        self.assertEqual(result['actual']['source_window_per_owner'], 8192)
        self.assertEqual(result['reference_layout']['native_tcp_flows'], 16)
        with self.assertRaisesRegex(ValueError, 'exact native comparison is unavailable'):
            reference.validate_row(named_row(), require_comparable=True)
        self.assertEqual(reference.validate_row(component_row())['status'], 'unbound_native_component')

    def test_configuration_digest_owner_and_difference_mutations_fail_closed(self):
        mutations = [
            ('window', lambda row: row['python_reference']['actual'].update(source_window_per_owner=512)),
            ('feedback', lambda row: row['python_reference']['actual'].update(feedback_packets=16)),
            ('recovery', lambda row: row['python_reference']['actual'].update(recovery='selective_repeat')),
            ('bool', lambda row: row['python_reference']['actual'].update(owners_per_direction=True)),
            ('schema', lambda row: row['python_reference'].update(schema=True)),
            ('claim', lambda row: row['python_reference'].update(claim='exact_native_equivalence')),
            ('digest', lambda row: row['python_reference'].update(reference_sha256='0' * 64)),
            ('unknown', lambda row: row['python_reference'].update(id='unknown')),
            ('missing_difference', lambda row: row['python_reference']['remaining_differences'].pop()),
            ('duplicate_difference', lambda row: row['python_reference']['remaining_differences'].append('kernel_tcp')),
            ('family', lambda row: row.update(algorithm='aligned')),
            ('missing_binding', lambda row: row.pop('python_reference')),
        ]
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                value = named_row()
                mutate(value)
                with self.assertRaises(ValueError):
                    reference.validate_row(value)

    def test_shared_packed_cannot_be_relabelled_as_independent_compact(self):
        values = reference.registry()
        for ident in ('packed-c46', 'packed-c47', 'packed-c48'):
            with self.subTest(reference=ident):
                value = named_row()
                value['python_reference'].update(id=ident, reference_sha256=values['references'][ident]['sha256'])
                with self.assertRaisesRegex(ValueError, 'shared Packed composition'):
                    reference.validate_row(value)

    def test_rehashed_manifest_cannot_hide_changed_bound_simulator_source(self):
        values = deepcopy(reference.registry())
        entry = values['references'][reference.SUPPORTED]
        name = next(iter(entry['source_sha256']))
        entry['source_sha256'][name] = '0' * 64
        entry['sha256'] = reference.digest({key: item for key, item in entry.items() if key != 'sha256'})
        value = named_row()
        value['python_reference']['reference_sha256'] = entry['sha256']
        with self.assertRaisesRegex(ValueError, 'simulator source changed'):
            reference.validate_row(value, values=values)

    def test_reviewed_projection_reports_checkout_hashes_and_rejects_further_edits(self):
        values = reference.registry()
        review = values['source_review']
        result = reference.validate_row(named_row())
        checked = result['source_verification']
        self.assertEqual(result['reference_sha256'], review['reference_sha256'])
        self.assertEqual(checked['historical_source_revision'], review['historical_source_revision'])
        expected_changes = {}
        for name, accepted in review['reviewed_projection_sha256'].items():
            actual = hashlib.sha256((reference.ROOT / name).read_bytes()).hexdigest()
            if actual != result['source_sha256'][name]:
                self.assertEqual(actual, accepted)
                expected_changes[name] = actual
        self.assertEqual(checked['checkout_matches_historical_sources'], not expected_changes)
        self.assertEqual(checked['reviewed_checkout_differences_sha256'], expected_changes)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in result['source_sha256']:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(reference.ROOT / name, destination)
            with (root / 'simulator/src/l2tunnel_sim/tcp.py').open('ab') as stream:
                stream.write(b'\n# unreviewed source change\n')
            with self.assertRaisesRegex(ValueError, 'simulator source changed'):
                reference.validate_row(named_row(), source_root=root)
            # A modified registry alone must not authorize the edited file for
            # a historical manifest that has no live projection digest.
            name = 'simulator/src/l2tunnel_sim/tcp.py'
            review['reviewed_projection_sha256'][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'projection source review digest differs'):
                reference.validate_row(named_row(), source_root=root, values=values)

    def test_both_decoder_roles_and_raw_requested_event_are_required(self):
        for carrier in ('udp', 'raw', 'tls', 'quic'):
            value = named_row(carrier)
            for side in ('a', 'b'):
                with self.subTest(carrier=carrier, side=side):
                    result = reference.validate_inspection(value, side, json.dumps(inspection(value, side)))
                    self.assertEqual(result['status'], 'validated_decoder_derived_selection')
                    self.assertEqual(len(result['descriptor_sha256']), 64)
            wrong = inspection(value, 'b')
            with self.assertRaises(ValueError):
                reference.validate_inspection(value, 'a', json.dumps(wrong))
        value = named_row('raw')
        wrong = inspection(value)
        wrong['event'] = 'secure_udp_common_plan'
        with self.assertRaises(ValueError):
            reference.validate_inspection(value, 'a', json.dumps(wrong))

    def test_actual_descriptor_projection_and_inspection_shape_fail_closed(self):
        value = named_row()
        for key, changed in [('python_reference_actual', None),
                             ('python_reference_descriptor_hex', 'bb'), ('authenticated', True),
                             ('validated', False), ('schema', True)]:
            event = inspection(value)
            event[key] = changed
            with self.subTest(field=key), self.assertRaises(ValueError):
                reference.validate_inspection(value, 'a', json.dumps(event))
        event = inspection(value)
        event['python_reference_actual']['source_window_per_owner'] = 64
        with self.assertRaisesRegex(ValueError, 'source_window_per_owner'):
            reference.validate_inspection(value, 'a', json.dumps(event))
        raw = json.dumps(inspection(value))
        for invalid in (raw + '\n' + raw, '{}', 'not JSON', '{"event":1,"event":2}'):
            with self.subTest(output=invalid[:32]), self.assertRaises(ValueError):
                reference.validate_inspection(value, 'a', invalid)

    def test_strict_request_fails_before_root_affinity_output_or_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for selected in (component_row(), named_row()):
                (root / 'plan.json').write_text(json.dumps({'backend': 'common_records_v2', 'version': 1,
                                                         'catalog': [selected['expected_descriptor_hex']]}))
                manifest = root / 'manifest.json'
                manifest.write_text(json.dumps({'version': 1, 'rows': [selected]}))
                with patch.object(matrix.lab, 'require_root') as privilege, \
                        patch.object(matrix.os, 'sched_getaffinity') as affinity, \
                        patch.object(matrix, 'topology') as topology:
                    with self.assertRaises(ValueError):
                        matrix.main(['--manifest', str(manifest), '--binary', str(root / 'absent'),
                                     '--output', str(root / 'output'), '--apply', '--require-python-comparable'])
                privilege.assert_not_called()
                affinity.assert_not_called()
                topology.assert_not_called()
                self.assertFalse((root / 'output').exists())

    def test_failed_actual_offline_selection_never_starts_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, secrets, state = (root / name for name in ('output', 'secrets', 'state'))
            for path in (output, secrets, state):
                path.mkdir()
            value = named_row()
            event = inspection(value)
            event['python_reference_actual']['source_window_per_owner'] = 64
            args = SimpleNamespace(lab_id='reference-test', output=output, phases=['forward'])
            with patch.object(matrix.Case, 'command', return_value=json.dumps(event)), \
                    patch.object(matrix, 'topology') as topology, \
                    patch.object(matrix.Case, 'spawn') as spawn:
                result = matrix.run_case(value, 0, args, root / 'binary', root, secrets, state)
            topology.assert_not_called()
            spawn.assert_not_called()
            self.assertEqual(result['stage'], 'offline_preflight')
            self.assertEqual(result['status'], 'failed')
            self.assertIn('source_window_per_owner', result['error'])
            self.assertEqual(result['phases'][0]['status'], 'not_run')


if __name__ == '__main__':
    unittest.main()
