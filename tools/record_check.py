#!/usr/bin/env python3
"""Run ordinary workspace checks and preserve source identity, output and scope."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def hashes() -> dict[str, str]:
    paths = set()
    for directory in ('crates', 'apps', 'tools', 'config', 'docs', '.github',
                      '.cargo', 'third_party', 'simulator/src', 'simulator/tests', 'simulator/studies'):
        paths.update(path for path in (ROOT / directory).rglob('*')
                     if path.is_file() and '__pycache__' not in path.relative_to(ROOT).parts)
    paths.update(path for path in ROOT.iterdir()
                 if path.is_file() and path.suffix in ('.toml', '.lock', '.md'))
    editor = ROOT / '.editorconfig'
    if editor.is_file():
        paths.add(editor)
    paths.update(path for path in (ROOT / 'simulator').glob('*')
                 if path.is_file() and path.suffix in ('.toml', '.md'))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = hashes()
    started = datetime.now(timezone.utc).isoformat()
    with (output / 'local-check.log').open('w') as log:
        checked = subprocess.run([sys.executable, str(ROOT / 'tools/check.py')], cwd=ROOT,
                                 stdout=log, stderr=subprocess.STDOUT, check=False)
    after = hashes()
    changed = sorted(path for path in before.keys() | after.keys()
                     if before.get(path) != after.get(path))
    text = (output / 'local-check.log').read_text()
    receipt = {
        'status': 'passed' if checked.returncode == 0 else 'failed',
        'exit_code': checked.returncode,
        'started_utc': started,
        'finished_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'local workspace check.py only; native labs and remote CI are separate receipts',
        'source_stable_during_check': not changed,
        'changed_during_check': changed,
        'rust_passed_cases_including_doctests': sum(map(int, re.findall(r'^test result: ok\. (\d+) passed;', text, re.M))),
        'python_reported_cases': sum(map(int, re.findall(r'^Ran (\d+) tests? in ', text, re.M))),
        'simulator_passed_cases': sum(map(int, re.findall(r'^(\d+) passed(?:,| in )', text, re.M))),
        'log_sha256': hashlib.sha256((output / 'local-check.log').read_bytes()).hexdigest(),
        'source_hashes_before': before,
        'source_hashes_after': after,
    }
    (output / 'validation.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({key: value for key, value in receipt.items()
                      if not key.startswith('source_hashes_')}, indent=2))
    return checked.returncode


if __name__ == '__main__':
    raise SystemExit(main())
