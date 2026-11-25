#!/usr/bin/env python3
"""Run a REAL l2tunneld server/client pair on loopback for GUI/CLI work.

Both daemons are the actual binaries with an authenticated Common session
over 127.0.0.1 UDP, using a plan exported from current Rust code
(`common_benchmark_plan`) and fresh demo credentials. Each daemon needs a
persistent TUN device owned by this user; creating one needs root once:

    sudo ip tuntap add dev l2tdemo-a mode tun user $USER
    sudo ip tuntap add dev l2tdemo-b mode tun user $USER

The devices stay down and get no address or route, so no host traffic is
redirected; the pair exercises the control plane, not forwarding.
Remove them with `sudo ip link delete l2tdemo-a` (and `-b`).

    local_real_pair.py prepare            # once: plans + credentials
    local_real_pair.py run --side b       # server (start first)
    local_real_pair.py run --side a       # client; GUI socket: DIR/control-a.sock

Forwarding layout (traffic really crosses the tunnel on one computer): two
addresses on one host are both local, so packets between them would never
enter the tunnel. `prepare --forwarding` puts the server's carrier on a veth
pair to the owned namespace `l2tdemo`, which also holds l2tdemo-b; the TUN
ends get 10.231.255.1/30 (client) and 10.231.255.2/30 (server).
`local_real_pair.py network` prints the root commands that build (and tear
down) that layout; this tool never runs them itself. Then start the server
inside the namespace as yourself (`run --side b` prints the command) and
`ping 10.231.255.2` crosses the tunnel.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket as unix
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = Path('/tmp/l2tunnel-real')
DEFAULT_ROW = 'swift-arq-udp'
DEVICES = {'a': 'l2tdemo-a', 'b': 'l2tdemo-b'}
PORTS = {'a': 24440, 'b': 24441}
# Lab addresses in exported rows, replaced by loopback.
LAB_ADDRESSES = {'192.0.2.2': '127.0.0.1', '192.0.2.6': '127.0.0.1'}
# Benchmark plans set a 120 s logical-session lease (a hard limit nothing
# renews); interactive GUI/CLI sessions get one hour, as in
# docs/modules/secure-udp-service.md.
INTERACTIVE_LEASE_MICROS = 3_600_000_000
# Forwarding layout: owned namespace, veth carrier link and TUN addresses.
NAMESPACE = 'l2tdemo'
VETH = {'a': 'l2tdemo-h', 'b': 'l2tdemo-n'}
TRANSPORT = {'a': '10.231.254.1', 'b': '10.231.254.2'}
TUNNEL = {'a': '10.231.255.1/30', 'b': '10.231.255.2/30'}


def side_arguments(required: list[str], side: str, forwarding: bool) -> list[str]:
    """The row's CLI for `side` with lab addresses replaced: loopback, or the
    veth addresses of the forwarding layout (bind is this side, peer the other)."""
    other = 'b' if side == 'a' else 'a'
    selected = []
    for previous, value in zip([''] + required, required):
        if previous in {'--udp-bind', '--udp-peer'}:
            host, port = value.rsplit(':', 1)
            if forwarding:
                host = TRANSPORT[side if previous == '--udp-bind' else other]
            else:
                host = LAB_ADDRESSES.get(host, host)
            value = f'{host}:{port}'
        selected.append(value)
    return selected


def network_commands(user: str) -> tuple[list[str], list[str]]:
    """Root commands that build and remove the forwarding layout. They only
    create owned objects (a namespace, a veth pair, addresses on the demo
    TUNs) and never touch existing routes, bridges or qdiscs."""
    ns = f'ip -n {NAMESPACE}'
    setup = [
        f'ip tuntap add dev {DEVICES["a"]} mode tun user {user}  # skip if it exists',
        f'ip tuntap add dev {DEVICES["b"]} mode tun user {user}  # skip if it exists',
        f'ip netns add {NAMESPACE}',
        f'ip link add {VETH["a"]} type veth peer name {VETH["b"]}',
        f'ip link set {VETH["b"]} netns {NAMESPACE}',
        f'ip addr add {TRANSPORT["a"]}/30 dev {VETH["a"]}',
        f'ip link set {VETH["a"]} up',
        f'{ns} link set lo up',
        f'{ns} addr add {TRANSPORT["b"]}/30 dev {VETH["b"]}',
        f'{ns} link set {VETH["b"]} up',
        f'ip link set {DEVICES["b"]} netns {NAMESPACE}',
        f'{ns} addr add {TUNNEL["b"]} dev {DEVICES["b"]}',
        f'{ns} link set {DEVICES["b"]} up',
        f'ip addr add {TUNNEL["a"]} dev {DEVICES["a"]}',
        f'ip link set {DEVICES["a"]} up',
    ]
    teardown = [f'ip netns delete {NAMESPACE}  # removes the veth pair and l2tdemo-b',
                f'ip addr flush dev {DEVICES["a"]}', f'ip link set {DEVICES["a"]} down']
    return setup, teardown


def in_namespace() -> bool:
    """Whether this process runs in the forwarding namespace."""
    try:
        return os.stat('/proc/self/ns/net').st_ino == os.stat(f'/run/netns/{NAMESPACE}').st_ino
    except OSError:
        return False


def target() -> Path:
    return Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')).resolve() / 'debug'


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise SystemExit(f'{path} must be a private directory owned by this user')


def raw_x25519(private: Path, public: Path) -> None:
    """Fresh raw X25519 pair through openssl (PKCS#8/SPKI DER end in the raw key)."""
    der = subprocess.run(['openssl', 'genpkey', '-algorithm', 'X25519', '-outform', 'DER'],
                         check=True, capture_output=True).stdout
    pub = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
                         input=der, check=True, capture_output=True).stdout
    for path, content in ((private, der[-32:]), (public, pub[-32:])):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)


def prepare(directory: Path, row_id: str, forwarding: bool = False) -> None:
    private_directory(directory)
    pair = directory / 'pair.json'
    if pair.exists():
        print(f'Already prepared: {pair} (delete {directory} to regenerate)')
        return
    plans = directory / 'plans'
    if not plans.exists():
        subprocess.run(['cargo', 'run', '--quiet', '--locked', '-p', 'l2tunnel-client-core', '--example',
                        'common_benchmark_plan', '--', '--output-dir', str(plans)], cwd=ROOT, check=True)
    manifest = json.loads((plans / 'manifest.json').read_text())
    rows = {row['id']: row for row in manifest['rows']}
    row = rows.get(row_id)
    if row is None:
        raise SystemExit(f'unknown row {row_id}')
    if row.get('carrier') != 'udp' or row.get('status') != 'ready':
        udp = sorted(key for key, value in rows.items() if value.get('carrier') == 'udp')
        raise SystemExit(f'row must be a ready UDP row: {", ".join(udp)}')
    secrets = directory / 'secrets'
    private_directory(secrets)
    for side in ('a', 'b'):
        raw_x25519(secrets / f'noise-{side}.key', secrets / f'noise-{side}.pub')
    for name in ('admission.key', 'cookie.key'):
        descriptor = os.open(secrets / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(os.urandom(32))
    subprocess.run([str(target() / 'l2tunneld'), 'keygen', '--private', str(secrets / 'member.der'),
                    '--public', str(secrets / 'member.pub')], check=True)
    plan_path = plans / row['common_plan']
    plan = json.loads(plan_path.read_text())
    plan['runtime']['lifetime']['lease_micros'] = INTERACTIVE_LEASE_MICROS
    plan_path.write_text(json.dumps(plan, indent=1))
    sides = {}
    for side, other in (('a', 'b'), ('b', 'a')):
        selected = side_arguments(row['required_cli'][side], side, forwarding)
        args = ['connect' if side == 'a' else 'serve', *selected,
                '--common-transaction-plan', str(plans / row['common_plan']),
                '--noise-private-key-file', str(secrets / f'noise-{side}.key'),
                '--noise-peer-key-file', str(secrets / f'noise-{other}.pub'),
                '--device', DEVICES[side], '--control-socket', str(directory / f'control-{side}.sock'),
                '--session-admission-key-file', str(secrets / 'admission.key')]
        args += (['--identity', str(secrets / 'member.der')] if side == 'a'
                 else ['--allow-key', str(secrets / 'member.pub'), '--session-cookie-key-file', str(secrets / 'cookie.key')])
        sides[side] = args
    pair.write_text(json.dumps({'row': row_id, 'forwarding': forwarding, 'sides': sides}, indent=1))
    print(f'Prepared {row_id} in {directory}. Client control socket: {directory / "control-a.sock"}')


def device_ready(name: str) -> str | None:
    net = Path('/sys/class/net') / name
    if not net.exists():
        return 'missing'
    owner = (net / 'owner').read_text().strip() if (net / 'owner').exists() else '-1'
    if owner != str(os.geteuid()):
        return f'owned by uid {owner}, not {os.geteuid()}'
    return None


def run(directory: Path, side: str) -> None:
    pair_file = directory / 'pair.json'
    if not pair_file.exists():
        prepare(directory, DEFAULT_ROW)
    pair = json.loads(pair_file.read_text())
    if pair.get('forwarding') and side == 'b' and not in_namespace():
        raise SystemExit(f'The forwarding layout runs the server inside the namespace {NAMESPACE}:\n'
                         f'  sudo ip netns exec {NAMESPACE} setpriv --reuid={os.geteuid()} --regid={os.getegid()} '
                         f'--init-groups env HOME="$HOME" PATH="$PATH" python3 {Path(__file__).resolve()} '
                         f'run --dir {directory} --side b\n'
                         f'(build the layout first: {Path(__file__).name} network)')
    problem = device_ready(DEVICES[side])
    if problem:
        user = os.environ.get('USER', str(os.geteuid()))
        raise SystemExit(f'TUN device {DEVICES[side]} is {problem}. Create both once (needs root):\n'
                         f'  sudo ip tuntap add dev {DEVICES["a"]} mode tun user {user}\n'
                         f'  sudo ip tuntap add dev {DEVICES["b"]} mode tun user {user}')
    socket = directory / f'control-{side}.sock'
    if socket.is_socket():
        probe = unix.socket(unix.AF_UNIX)
        try:
            probe.connect(str(socket))
        except OSError:
            socket.unlink()  # stale socket left by an earlier run of this side
        else:
            raise SystemExit(f'side {side} is already running ({socket} answers)')
        finally:
            probe.close()
    binary = str(target() / 'l2tunneld')
    print(f'REAL l2tunneld {pair["row"]} side {side} ({"client" if side == "a" else "server"}); '
          f'control socket {socket}', flush=True)
    os.execv(binary, [binary, *pair['sides'][side]])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    first = commands.add_parser('prepare')
    first.add_argument('--dir', type=Path, default=DEFAULT_DIR)
    first.add_argument('--row', default=DEFAULT_ROW)
    first.add_argument('--forwarding', action='store_true',
                       help='carrier over a veth pair to the namespace l2tdemo, so traffic crosses the tunnel')
    second = commands.add_parser('run')
    second.add_argument('--dir', type=Path, default=DEFAULT_DIR)
    second.add_argument('--side', choices=('a', 'b'), required=True)
    commands.add_parser('network', help='print the root commands of the forwarding layout')
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.dir, args.row, args.forwarding)
    elif args.command == 'network':
        setup, teardown = network_commands(os.environ.get('USER', str(os.geteuid())))
        print('# Forwarding layout (run as root, e.g. prefix each with sudo):')
        print('\n'.join(setup))
        print('# Remove it again:')
        print('\n'.join(teardown))
    else:
        run(args.dir, args.side)


if __name__ == '__main__':
    sys.exit(main())
