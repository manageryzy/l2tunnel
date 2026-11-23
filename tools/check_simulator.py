#!/usr/bin/env python3
"""Run the complete simulator suite; optional user skips cannot qualify this gate.

The pytest hooks below are loaded explicitly only by this command. Direct pytest
users retain the simulator's optional-dependency skip behavior.
"""
from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = ('numpy', 'scipy', 'plotly', 'pytest', 'aioquic', 'matplotlib', 'lz4')
# aioquic's package root does not load its native crypto or connection adapters.
# Import the actual modules used by the simulator before starting the full gate.
DEPENDENCY_IMPORTS = {
    'aioquic': ('aioquic', 'aioquic.quic.configuration', 'aioquic.quic.connection'),
    'lz4': ('lz4.block',),
}
_SKIP_COUNT = 0
_SKIP_EXAMPLES: list[str] = []


def verify_dependencies() -> None:
    """Require both distribution metadata and usable imports for the full suite."""
    for name in DEPENDENCIES:
        module = name
        try:
            version = importlib.metadata.version(name)
            for module in DEPENDENCY_IMPORTS.get(name, (name,)):
                importlib.import_module(module)
        except (importlib.metadata.PackageNotFoundError, ImportError) as error:
            raise RuntimeError(
                f'Full simulator checks require an importable {name} ({module}); install an '
                'environment with python3 -m pip install -e "./simulator[dev,quic,plots]"'
            ) from error
        print(f'Simulator check dependency: {name}=={version}', flush=True)


def pytest_sessionstart(session) -> None:
    """Reset the explicit full-gate plugin for one actual pytest session."""
    global _SKIP_COUNT
    _SKIP_COUNT = 0
    _SKIP_EXAMPLES.clear()


def _observe_report(report) -> None:
    global _SKIP_COUNT
    if report.skipped:
        _SKIP_COUNT += 1
        if len(_SKIP_EXAMPLES) < 8:
            _SKIP_EXAMPLES.append(report.nodeid)


def pytest_collectreport(report) -> None:
    """Module-level import skips count as omitted coverage too."""
    _observe_report(report)


def pytest_runtest_logreport(report) -> None:
    """Read real pytest reports, never human-readable stdout or test counts."""
    _observe_report(report)


def pytest_sessionfinish(session, exitstatus) -> None:
    """A partial suite cannot pass the full gate, even if every run test passed."""
    if not _SKIP_COUNT:
        return
    terminal = session.config.pluginmanager.get_plugin('terminalreporter')
    if terminal is not None:
        terminal.write_sep('=', f'Full simulator gate rejected {_SKIP_COUNT} skipped reports')
        for nodeid in _SKIP_EXAMPLES:
            terminal.write_line(nodeid)
    if exitstatus == 0:
        session.exitstatus = 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-dependencies', action='store_true',
                        help='validate full-suite imports without starting pytest')
    arguments = parser.parse_args(argv)
    verify_dependencies()
    if arguments.check_dependencies:
        return 0
    environment = {
        **os.environ,
        'PYTHONDONTWRITEBYTECODE': '1',
        # An ambient developer selection must not silently narrow the full gate.
        'PYTEST_ADDOPTS': '',
        'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1',
        'PYTHONPATH': os.pathsep.join(filter(None, [str(ROOT / 'simulator/src'),
            str(ROOT), os.environ.get('PYTHONPATH')])),
    }
    return subprocess.run([
        sys.executable, '-m', 'pytest', '-p', 'tools.check_simulator',
        '-o', 'addopts=', '-c', str(ROOT / 'simulator/pyproject.toml'),
        str(ROOT / 'simulator/tests'), '-q', '-ra',
    ], cwd=ROOT, env=environment, check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
