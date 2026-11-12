"""The full simulator gate rejects omitted coverage using real pytest reports."""
from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tools import check_simulator as check


class FullSimulatorGateTests(unittest.TestCase):
    def run_pytest(self, files: dict[str, str], *, guarded: bool, extra_env=None):
        with tempfile.TemporaryDirectory(prefix='l2t-full-gate-') as directory:
            root = Path(directory)
            for name, text in files.items():
                (root / name).write_text(text, encoding='utf-8')
            report = root / 'result.xml'
            environment = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1',
                           'PYTEST_ADDOPTS': '', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1',
                           'PYTHONPATH': str(check.ROOT), **(extra_env or {})}
            command = [sys.executable, '-m', 'pytest', '-q', '--junitxml', str(report)]
            if guarded:
                command += ['-p', 'tools.check_simulator']
            result = subprocess.run(command, cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=20, check=False)
            self.assertTrue(report.is_file(), result.stdout + result.stderr)
            tests = ET.parse(report).findall('.//testcase')
            return result, tests

    def test_real_runtime_skip_only_fails_explicit_full_gate(self):
        fixture = {'test_cases.py': 'import pytest\ndef test_pass(): assert 2+2==4\ndef test_optional(): pytest.skip("optional user feature")\n'}
        ordinary, ordinary_reports = self.run_pytest(fixture, guarded=False)
        guarded, guarded_reports = self.run_pytest(fixture, guarded=True)
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertEqual(guarded.returncode, 1, guarded.stdout + guarded.stderr)
        self.assertEqual(sum(t.find('skipped') is not None for t in ordinary_reports), 1)
        self.assertEqual(sum(t.find('skipped') is not None for t in guarded_reports), 1)

    def test_actual_collection_import_skip_is_not_success(self):
        fixture = {'test_pass.py': 'def test_pass(): assert True\n',
                   'test_unavailable.py': 'import pytest\npytest.importorskip("l2t_audit_absent_optional_package")\n'}
        result, reports = self.run_pytest(fixture, guarded=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(any(t.find('skipped') is not None for t in reports))
        self.assertTrue(any(t.attrib.get('name') == 'test_pass' for t in reports))

    def test_passing_stdout_cannot_forge_a_skip_report(self):
        result, reports = self.run_pytest({'test_pass.py':
            'def test_pass():\n print("SKIPPED 100 tests; all missing")\n assert b"bytes" == bytes([98,121,116,101,115])\n'}, guarded=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(reports), 1)
        self.assertIsNone(reports[0].find('skipped'))

    def test_existing_failures_remain_failure(self):
        result, reports = self.run_pytest({'test_fail.py': 'def test_fail(): assert False\n'}, guarded=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIsNotNone(reports[0].find('failure'))

    def test_installed_metadata_does_not_hide_broken_import(self):
        def importing(name):
            if name == 'aioquic':
                raise ModuleNotFoundError('broken installed adapter', name=name)
            return object()
        with patch.object(check.importlib.metadata, 'version', return_value='installed'), \
                patch.object(check.importlib, 'import_module', side_effect=importing):
            with self.assertRaisesRegex(RuntimeError, 'importable aioquic'):
                check.verify_dependencies()

    def test_missing_plot_dependency_fails_full_gate(self):
        def version(name):
            if name == 'matplotlib':
                raise importlib.metadata.PackageNotFoundError(name)
            return 'installed'
        with patch.object(check.importlib.metadata, 'version', side_effect=version), \
                patch.object(check.importlib, 'import_module', return_value=object()):
            with self.assertRaisesRegex(RuntimeError, 'importable matplotlib'):
                check.verify_dependencies()

    def test_main_ignores_ambient_test_selection_and_cannot_skip_failure(self):
        with tempfile.TemporaryDirectory(prefix='l2t-full-main-') as directory:
            root = Path(directory)
            (root / 'simulator/tests').mkdir(parents=True)
            (root / 'simulator/pyproject.toml').write_text('[tool.pytest.ini_options]\n')
            (root / 'simulator/tests/test_cases.py').write_text(
                'import pytest\ndef test_selected(): assert True\ndef test_omitted(): pytest.skip("must be observed")\n')
            with patch.object(check, 'ROOT', root), patch.object(check, 'verify_dependencies'), \
                    patch.dict(os.environ, {'PYTHONPATH': str(Path(__file__).resolve().parents[1]),
                                           'PYTEST_ADDOPTS': '-k test_selected'}):
                self.assertEqual(check.main(), 1)


if __name__ == '__main__':
    unittest.main()
