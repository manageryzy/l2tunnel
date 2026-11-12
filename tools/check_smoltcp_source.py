#!/usr/bin/env python3
"""Verify the reviewed offline TCP snapshot source, license and dependency selection."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PEER_WINDOW_PATCH = 'smoltcp-0.14.0-peer-window-observation.patch'
PEER_WINDOW_PATCH_SHA256 = '83cb38885005a7b294c367facdfc4445262a032fa96b3e2d694a1117aded786b'
QUIESCENT_TCP_SHA256 = '0bb6cc1ee4f82be71bec947953c4cc5fd51a33508f76fb696366b7d7b0ea190c'
PEER_WINDOW_TCP_SHA256 = 'ba2b4b1f1cf9adca3b7e01dbf699058aa01ecbfaa666369c7396605f2887189d'


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    third_party = ROOT / 'third_party'
    provenance = json.loads((third_party / 'smoltcp-provenance.json').read_text())
    manifest_path = third_party / 'smoltcp-file-manifest.json'
    if digest(manifest_path) != provenance['file_manifest_sha256']:
        raise ValueError('reviewed source manifest changed')
    manifest = json.loads(manifest_path.read_text())
    expected = manifest['patched_files_sha256']
    original = manifest['upstream_files_sha256']
    source = third_party / 'smoltcp'
    paths = [path for path in source.rglob('*')
             if not {'target', '__pycache__'}.intersection(path.relative_to(source).parts)]
    if any(path.is_symlink() for path in paths):
        raise ValueError('source package contains a symlink')
    actual = {str(path.relative_to(source)): digest(path) for path in paths if path.is_file()}
    if actual != expected or set(expected) != set(original) or len(actual) != 134:
        raise ValueError('source tree differs from the reviewed 134-file package')
    changed = sorted(name for name in expected if expected[name] != original[name])
    if changed != ['src/socket/tcp.rs'] or changed != provenance['changed_upstream_files']:
        raise ValueError('unexpected upstream source modification')
    for field, relative in [('license', 'smoltcp/LICENSE-0BSD.txt'),
                            ('patch', 'smoltcp-0.14.0-quiescent-snapshot.patch')]:
        if digest(third_party / relative) != provenance[field + '_sha256']:
            raise ValueError(f'reviewed {field} changed')
    if (provenance['archive_sha256'] != 'b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f'
            or provenance['patch_sha256'] != '0cbe61961c3b2f1e19028e55fbf9daff3f2f3536f8444f32b15a3efc93d0bcdd'):
        raise ValueError('reviewed archive/patch identity changed')
    observation = provenance['peer_window_observation_patch']
    if (observation['file'] != PEER_WINDOW_PATCH
            or observation['sha256'] != PEER_WINDOW_PATCH_SHA256
            or digest(third_party / PEER_WINDOW_PATCH) != PEER_WINDOW_PATCH_SHA256
            or observation['base_tcp_sha256'] != QUIESCENT_TCP_SHA256
            or observation['result_tcp_sha256'] != PEER_WINDOW_TCP_SHA256
            or expected['src/socket/tcp.rs'] != PEER_WINDOW_TCP_SHA256):
        raise ValueError('reviewed incremental peer-window observation identity changed')
    workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())
    if workspace['patch']['crates-io']['smoltcp'] != {'path': 'third_party/smoltcp'}:
        raise ValueError('workspace does not select the reviewed source')
    packages = [item for item in tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
                if item['name'] == 'smoltcp']
    if (len(packages) != 1 or packages[0]['version'] != '0.14.0'
            or 'source' in packages[0] or 'checksum' in packages[0]):
        raise ValueError('lockfile does not select exactly the local reviewed dependency')
    print('Verified smoltcp 0.14.0: 134 source files, preserved quiescent patch plus incremental peer-window observation, unchanged 0BSD and local lock selection.')


if __name__ == '__main__':
    main()
