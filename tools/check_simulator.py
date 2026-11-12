#!/usr/bin/env python3
"""Run the complete simulator tests with explicit full-suite prerequisites."""
from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    # QUIC is optional for simulator users, but mandatory for this full CI gate.
    for name in ('numpy', 'scipy', 'plotly', 'pytest', 'aioquic'):
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as error:
            raise RuntimeError(
                'Full simulator checks require an environment installed with '
                'python3 -m pip install -e "./simulator[dev,quic]"'
            ) from error
        print(f'Simulator check dependency: {name}=={version}', flush=True)
    environment = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1',
        'PYTHONPATH': os.pathsep.join(filter(None, [str(ROOT / 'simulator/src'),
            os.environ.get('PYTHONPATH')]))}
    return subprocess.run([sys.executable, '-m', 'pytest', '-c',
        str(ROOT / 'simulator/pyproject.toml'), str(ROOT / 'simulator/tests'),
        '-q', '-ra'], cwd=ROOT, env=environment, check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
