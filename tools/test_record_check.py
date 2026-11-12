"""Source identity includes Rust modules named target, excluding build outputs."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import record_check


class SourceIdentityTests(unittest.TestCase):
    def test_simulator_test_fixture_study_and_manifest_are_source_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = ('simulator/tests/test_example.py', 'simulator/tests/fixtures/example.json',
                     'simulator/studies/example.py', 'simulator/pyproject.toml')
            for relative in files:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'checked input')
            with patch.object(record_check, 'ROOT', root):
                self.assertEqual(set(record_check.hashes()), set(files))

    def test_source_target_module_is_hashed_and_mutations_change_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = 'crates/example/src/target/tests.rs'
            source = root / relative
            source.parent.mkdir(parents=True)
            source.write_bytes(b'original test source')
            with patch.object(record_check, 'ROOT', root):
                before = record_check.hashes()
                self.assertEqual(before[relative], hashlib.sha256(source.read_bytes()).hexdigest())
                source.write_bytes(b'changed test source')
                self.assertNotEqual(before[relative], record_check.hashes()[relative])

    def test_root_build_outputs_and_python_cache_are_not_source_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ('target/debug/example', 'tools/__pycache__/check.pyc'):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'generated')
            (root / 'Cargo.toml').write_bytes(b'[workspace]\n')
            (root / '.editorconfig').write_bytes(b'root = true\n')
            with patch.object(record_check, 'ROOT', root):
                self.assertEqual(set(record_check.hashes()), {'Cargo.toml', '.editorconfig'})


if __name__ == '__main__':
    unittest.main()
