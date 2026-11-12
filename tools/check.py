#!/usr/bin/env python3
"""Run local, unprivileged implementation checks; never configure network interfaces."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, env: dict[str, str] | None = None) -> None:
    print('+ ' + ' '.join(args), flush=True)
    subprocess.run(args, cwd=ROOT, env=env, check=True)


def main() -> None:
    catalog = tomllib.loads((ROOT / 'config/mode-catalog.toml').read_text())
    modes = catalog['mode']
    ids = [mode['id'] for mode in modes]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate mode IDs')
    parity = (ROOT / 'docs/mode-parity.md').read_text()
    for mode in modes:
        if mode['status'] not in {'planned', 'implemented', 'integration-tested'}:
            raise ValueError(f"unknown status: {mode['id']}")
        if f"`{mode['id']}`" not in parity:
            raise ValueError(f"missing parity entry: {mode['id']}")
    for path in (ROOT / 'tools').glob('*.py'):
        ast.parse(path.read_text(), filename=str(path))
    print(f'Validated {len(modes)} mode entries and Python tool syntax.', flush=True)
    run(sys.executable, 'tools/check_checklists.py')
    run(sys.executable, '-m', 'unittest', 'tools.test_record_check', '-v')
    run(sys.executable, 'tools/check_smoltcp_source.py')
    run(sys.executable, 'tools/generate_tcp_header_goldens.py', '--check', env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    run(sys.executable, 'tools/generate_aligned_body_goldens.py', '--check', env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    run(sys.executable, 'tools/generate_aligned_receiver_goldens.py', '--check', env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    run(sys.executable, 'tools/generate_aligned_sender_goldens.py', '--check', env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    run(sys.executable, 'tools/generate_packed_goldens.py', '--check', env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    run('cargo', 'fmt', '--all', '--check')
    run('cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings')
    run('cargo', 'test', '--workspace', '--all-features', '--locked')
    run('cargo', 'doc', '--workspace', '--no-deps', '--locked', env={**os.environ, 'RUSTDOCFLAGS': '-D warnings'})
    run('cargo', 'run', '--quiet', '--locked', '-p', 'l2tunnelctl', '--', 'plan')
    result = subprocess.run(['cargo', 'run', '--quiet', '--locked', '-p', 'l2tunneld', '--', 'run'], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 2 or 'Unknown command' not in result.stderr:
        raise RuntimeError('CLI must reject unspecified network execution')
    if sys.platform == 'linux':
        run(sys.executable, '-m', 'unittest', 'tools.test_netns_lab', 'tools.test_native_smoke', 'tools.test_udp_burst_probe', 'tools.test_raw_native_smoke', 'tools.test_proxy_native_smoke', 'tools.test_proxy_measured_native_smoke', 'tools.test_openvpn_drain_native_smoke', '-v')
    else:
        print('Linux namespace harness tests skipped on this host.', flush=True)
    print('Local workspace checks passed. This command runs no privileged tests or remote CI.', flush=True)


if __name__ == '__main__':
    main()
