"""`l2tunnelctl service start` (owner decisions 2026-11-24: elevated start
through an installer) against a FAKE `pkexec` placed first on PATH. Checks the
prompt contract (what is run as root), the dismissed/failed mappings and that
the root-only installer refuses to run unprivileged. Nothing is installed,
started or run as root."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools import local_real_pair

ROOT = Path(__file__).resolve().parents[1]
FAKE_PKEXEC = """#!/bin/sh
printf '%s\\n' "$@" > "$FAKE_PKEXEC_ARGS"
case "$FAKE_PKEXEC_MODE" in
  dismiss) exit 126 ;;
  refuse) exit 127 ;;
  fail) echo "installer: boom" >&2; exit 1 ;;
  *) exit 0 ;;
esac
"""


def binaries() -> Path:
    target = local_real_pair.target()
    if not all((target / name).is_file() for name in ('l2tunnel-linux', 'l2tunnelctl')):
        subprocess.run(['cargo', 'build', '--quiet', '--locked', '-p', 'l2tunnel-linux', '-p', 'l2tunnelctl'],
                       cwd=ROOT, check=True)
    return target


class ServiceStartTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = binaries()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='l2tstart-')
        bin_dir = Path(self.directory.name) / 'bin'
        bin_dir.mkdir()
        fake = bin_dir / 'pkexec'
        fake.write_text(FAKE_PKEXEC)
        fake.chmod(0o755)
        self.args = Path(self.directory.name) / 'args'
        self.env = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}', FAKE_PKEXEC_ARGS=str(self.args))

    def tearDown(self):
        self.directory.cleanup()

    def start(self, mode: str, *extra: str):
        program = self.target / 'l2tunnel-linux'
        return subprocess.run([str(self.target / 'l2tunnelctl'), 'service', 'start', '--program', str(program),
                               '--wait', '1', *extra], capture_output=True, text=True, timeout=60,
                              env=dict(self.env, FAKE_PKEXEC_MODE=mode))

    def test_prompt_contract_and_failures(self):
        uid = os.getuid()
        if Path(f'/run/l2tunnel-{uid}/api.sock').exists():
            self.skipTest('a real elevated service is running for this user')
        installed = Path(f'/etc/systemd/system/l2tunnel-{uid}.service').exists()
        # Approved, but no service appears in time: exit 4 (still running).
        result = self.start('ok')
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('no service answered in time', result.stderr)
        expected = ([str(self.target / 'l2tunnel-linux'), 'system-service', 'install'] if not installed
                    else ['/usr/local/libexec/l2tunnel/l2tunnel-linux', 'system-service', 'start'])
        self.assertEqual(self.args.read_text().split('\n')[:-1], [*expected, '--uid', str(uid)])
        # --install always runs the installer from --program.
        self.assertEqual(self.start('ok', '--install').returncode, 4)
        self.assertEqual(self.args.read_text().split('\n')[:3],
                         [str(self.target / 'l2tunnel-linux'), 'system-service', 'install'])
        result = self.start('dismiss')
        self.assertEqual(result.returncode, 1)
        self.assertIn('administrator prompt was dismissed', result.stderr)
        result = self.start('refuse')
        self.assertEqual(result.returncode, 1)
        self.assertIn('authorization was refused', result.stderr)
        # The CLI prompts on its terminal, so installer output is shown directly.
        result = self.start('fail')
        self.assertEqual(result.returncode, 1)
        self.assertIn('installer: boom', result.stderr)
        self.assertIn('exit code 1', result.stderr)
        # Windows host options are refused on Linux, before any prompt.
        self.args.unlink()
        result = self.start('ok', '--install', '--address', '10.0.0.2/24')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.args.exists())

    def test_json_reply_shape_on_timeout_is_absent(self):
        if Path(f'/run/l2tunnel-{os.getuid()}/api.sock').exists():
            self.skipTest('a real elevated service is running for this user')
        # Failures print no JSON line; only a started service prints one.
        result = self.start('ok', '--json')
        self.assertEqual((result.returncode, result.stdout), (4, ''))

    def test_installer_refuses_to_run_unprivileged(self):
        if os.geteuid() == 0:
            self.skipTest('runs as root')
        linux = str(self.target / 'l2tunnel-linux')
        for args, code, text in ((['install', '--uid', '1000'], 1, 'must run as root'),
                                 (['start', '--uid', '0'], 1, 'never runs as root'),
                                 (['install', '--uid', 'me'], 1, 'numeric UID'),
                                 (['install'], 2, 'usage'),
                                 (['bogus', '--uid', '1000'], 2, 'usage')):
            result = subprocess.run([linux, 'system-service', *args], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, code, (args, result.stderr))
            self.assertIn(text, result.stderr, args)
        result = subprocess.run([linux, '--help'], capture_output=True, text=True, timeout=30)
        self.assertIn('system-service install|start|uninstall --uid UID', result.stdout)


if __name__ == '__main__':
    unittest.main()
