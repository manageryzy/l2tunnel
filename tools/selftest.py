#!/usr/bin/env python3
"""Linux TAP self-test of the l2tunnel CLI under tc HTB/netem.

Builds five private network namespaces (two traffic hosts, two tunnel endpoints
and an underlay router), shapes each endpoint's WAN egress with HTB and netem,
starts a real `serve` and `connect` endpoint on TAP devices bridged to the
hosts, then runs verified TCP bulk flows between the hosts through the tunnel.

It reports application goodput, the IPv4 bytes the tunnel put on the shaped
WAN link, and payload efficiency. On the `impaired` path (100/10 Mbit/s, 70 ms
RTT, 15% loss per direction, 16 CUBIC flows) it compares forward goodput with
the Python simulator's compact multi-flow candidate run at the tunnel's real
per-datagram overhead; see SIMULATOR_REFERENCE.

When not started as root it re-executes itself inside an unprivileged user,
network and mount namespace, so it needs no sudo and cannot touch the host's
interfaces, routes or qdiscs. Everything it creates disappears with that
namespace. Results are finite observations of one run, not guarantees.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
NAMESPACES = ('ha', 'ea', 'rt', 'eb', 'hb')
HOST_A, HOST_B = '198.18.0.1', '198.18.0.2'
WAN_A, WAN_B = '192.0.2.2', '192.0.2.6'
PATHS = {
    'clean': (1, 0),
    'delay': (35, 0),
    'loss1': (35, 1),
    'impaired': (35, 15),
}
# Post-warm-up TCP goodput in Mbit/s of `simulator/studies/compact_multiflow.py`'s
# task (16 flows, compact selective-repeat ARQ, `tcp_delta` header profile,
# 100/10 Mbit/s) with `authentication_bytes=21`, which brings the simulator's
# 36-byte outer header to this tunnel's 57 bytes (IPv4, UDP, packet number,
# AEAD tag, source header). Mean of three replications of 30 s with 10 s
# warm-up, keyed by path and inner TCP minimum RTO in milliseconds. Receipts:
# work/swift-simulator-reference38/ (impaired) and -reference40/ (the rest).
SIMULATOR_REFERENCE = {
    ('impaired', 1000): 80.72, ('impaired', 200): 79.04,
    ('loss1', 1000): 94.55, ('delay', 1000): 94.61, ('clean', 1000): 94.58,
}
BLOCK = hashlib.shake_256(b'l2tunnel selftest payload').digest(1 << 16)


def sh(*args: str, check: bool = True) -> str:
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def ns(name: str, *args: str, check: bool = True) -> str:
    return sh('ip', 'netns', 'exec', name, *args, check=check)


def build_topology(path: str, forward_mbit: int, reverse_mbit: int, host_mtu: int,
                   rto_min_ms: int) -> None:
    delay_ms, loss_percent = PATHS[path]
    for name in NAMESPACES:
        sh('ip', 'netns', 'add', name)
        ns(name, 'ip', 'link', 'set', 'lo', 'up')
    for host, endpoint, address in (('ha', 'ea', HOST_A), ('hb', 'eb', HOST_B)):
        sh('ip', 'link', 'add', 'eth0', 'netns', host, 'type', 'veth',
           'peer', 'name', 'lan0', 'netns', endpoint)
        ns(endpoint, 'ip', 'link', 'add', 'br-lan', 'type', 'bridge')
        ns(endpoint, 'ip', 'tuntap', 'add', 'dev', 'tap0', 'mode', 'tap')
        for device in ('lan0', 'tap0'):
            ns(endpoint, 'ip', 'link', 'set', device, 'master', 'br-lan')
        for device in ('br-lan', 'lan0', 'tap0'):
            ns(endpoint, 'ip', 'link', 'set', device, 'up')
        ns(host, 'ip', 'addr', 'add', f'{address}/24', 'dev', 'eth0')
        ns(host, 'ip', 'link', 'set', 'eth0', 'mtu', str(host_mtu), 'up')
        if rto_min_ms:
            ns(host, 'ip', 'route', 'replace', '198.18.0.0/24', 'dev', 'eth0',
               'rto_min', f'{rto_min_ms}ms')
        # The tunnel carries individual Ethernet frames; keep segmentation and
        # checksum completion on the hosts instead of handing the TAP super-frames.
        for space, device in ((host, 'eth0'), (endpoint, 'lan0'), (endpoint, 'tap0')):
            ns(space, 'ethtool', '-K', device, 'tso', 'off', 'gso', 'off', 'gro', 'off',
               'tx', 'off', 'rx', 'off', check=False)
    for endpoint, router_dev, local, gateway, peer_net, rate in (
            ('ea', 'a0', WAN_A, '192.0.2.1', '192.0.2.4/30', forward_mbit),
            ('eb', 'b0', WAN_B, '192.0.2.5', '192.0.2.0/30', reverse_mbit)):
        sh('ip', 'link', 'add', 'wan0', 'netns', endpoint, 'type', 'veth',
           'peer', 'name', router_dev, 'netns', 'rt')
        ns(endpoint, 'ip', 'addr', 'add', f'{local}/30', 'dev', 'wan0')
        ns(endpoint, 'ip', 'link', 'set', 'wan0', 'up')
        ns('rt', 'ip', 'addr', 'add', f'{gateway}/30', 'dev', router_dev)
        ns('rt', 'ip', 'link', 'set', router_dev, 'up')
        ns(endpoint, 'ip', 'route', 'add', peer_net, 'via', gateway)
        # The budget is in IP bytes, as in the simulator: discount the Ethernet
        # header the kernel would otherwise charge to the shaper.
        ns(endpoint, 'tc', 'qdisc', 'add', 'dev', 'wan0', 'root', 'handle', '1:',
           'stab', 'overhead', '-14', 'linklayer', 'ethernet', 'htb', 'default', '10')
        ns(endpoint, 'tc', 'class', 'add', 'dev', 'wan0', 'parent', '1:', 'classid', '1:10',
           'htb', 'rate', f'{rate}mbit', 'ceil', f'{rate}mbit')
        ns(endpoint, 'tc', 'qdisc', 'add', 'dev', 'wan0', 'parent', '1:10', 'handle', '10:',
           'netem', 'limit', '1000', 'delay', f'{delay_ms}ms', 'loss', 'random',
           f'{loss_percent}%')
    ns('rt', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')


def credentials(binary: str, work: Path) -> None:
    sh(binary, 'keygen', '--private', str(work / 'member.der'), '--public', str(work / 'member.pub'))
    sh('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
       '-nodes', '-keyout', str(work / 'server.pem'), '-out', str(work / 'cert.pem'),
       '-days', '1', '-subj', '/CN=lab.invalid', '-addext', 'subjectAltName=DNS:lab.invalid',
       '-addext', 'basicConstraints=critical,CA:FALSE')
    sh('openssl', 'x509', '-in', str(work / 'cert.pem'), '-outform', 'DER',
       '-out', str(work / 'cert.der'))
    sh('openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(work / 'server.pem'),
       '-outform', 'DER', '-out', str(work / 'server.der'))


def rolling_policy(args: argparse.Namespace) -> dict:
    return {
        'version': 2, 'profile': 'rolling-frame-v2', 'channels': args.channels,
        'stream': 1, 'epoch': 1,
        'recovery': {
            'window': args.window, 'local_window': min(args.local_window, args.window),
            'global_every': 16, 'max_payload': args.max_payload, 'max_rows': args.window,
            'repair_history': 2 * args.window, 'handoff_sources': min(args.window, 128),
            'job_millis': 5000, 'debt_millis': 20000, 'handoff_millis': 5000,
            'memory_bytes': 33554432},
        'scheduling': {
            'repair_numerator': args.repair_numerator,
            'repair_denominator': args.repair_denominator, 'tail_millis': 20,
            'feedback_millis': args.feedback_ms, 'feedback_packets': 64,
            'memory_bytes': 33554432, 'source_wire': 'exact'},
        'service': {'field_work': 65536, 'copy_work': 65536, 'metadata_work': 65536,
                    'passes_per_turn': 64},
        'delivery': {
            'forward_bandwidth_bps': args.forward_mbit * 1_000_000,
            'reverse_bandwidth_bps': args.reverse_mbit * 1_000_000,
            'bootstrap_rtt_micros': 70000, 'min_rtt_micros': 1000,
            'max_rtt_micros': 2000000, 'headroom_percent': 125, 'minimum_bytes': 3200,
            'max_inflight_bytes': 4194304, 'max_records': 8192,
            'metadata_limit_bytes': 2097152, 'sample_ttl_micros': 4000000,
            'flush_timeout_micros': 10000000}}


def endpoint_command(args: argparse.Namespace, side: str, work: Path) -> list[str]:
    local, peer = (WAN_A, WAN_B) if side == 'a' else (WAN_B, WAN_A)
    listen = f'{WAN_B}:18443'
    command = [args.binary]
    if side == 'a':
        command += ['connect', '--remote', listen, '--ca', str(work / 'cert.der'),
                    '--server-name', 'lab.invalid', '--identity', str(work / 'member.der')]
    else:
        command += ['serve', '--listen', listen, '--cert', str(work / 'cert.der'),
                    '--key', str(work / 'server.der'), '--allow-key', str(work / 'member.pub')]
    command += ['--layer', 'tap', '--device', 'tap0', '--duplex', args.duplex,
                '--compression', 'off', '--max-packet', '1600']
    if args.profile == 'tcp':
        return command
    if args.profile == 'swift':
        return command + [
            '--carrier', 'udp', '--record-profile', 'swift', '--path-mtu', '1500',
            '--udp-bind', f'{local}:24440', '--udp-peer', f'{peer}:24440',
            # Two free-running clocks cannot share exactly one rate: leave the
            # shaper a small margin so its queue does not grow without bound.
            '--swift-forward-kbit', str(round(args.forward_mbit * 1000 * args.swift_utilization)),
            '--swift-reverse-kbit', str(round(args.reverse_mbit * 1000 * args.swift_utilization)),
            '--swift-channels', str(args.swift_channels),
            '--swift-window', str(args.swift_window),
            '--swift-repair-permille', str(args.swift_repair_permille),
            '--swift-report-ms', '1000',
            # The acceptor listens again after its peer leaves, so the
            # initiator's local reconnect command has something to reach.
            '--swift-restart', 'on' if side == 'b' else 'off',
            '--control-socket', str(work / f'control-{side}.sock')] + args.extra
    command += ['--carrier', 'udp', '--path-mtu', '1500', '--udp-cover', 'quic-like',
                '--udp-protection', args.protection,
                '--udp-bind', f'{local}:24440', '--udp-peer', f'{peer}:24440']
    if args.duplex == 'half':
        command += ['--udp-reverse-bind', f'{local}:24441', '--udp-reverse-peer', f'{peer}:24441']
    if args.profile == 'rolling':
        command += ['--record-profile', 'rolling', '--rolling-policy', str(work / 'rolling.json'),
                    '--traffic', 'system']
    else:
        command += ['--delivery-window', 'bdp', '--forward-mbps', str(args.forward_mbit),
                    '--reverse-mbps', str(args.reverse_mbit), '--bootstrap-rtt-ms', '70',
                    '--bdp-headroom-percent', '125', '--inflight-max-bytes', '4194304',
                    '--inflight-max-records', '8192']
        if args.profile == 'udp-fec':
            command += ['--fec', 'cauchy']
    return command + args.extra


def wait_for(path: Path, marker: str, process: subprocess.Popen, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if marker.lower() in path.read_text(errors='replace').lower():
            return
        if process.poll() is not None:
            break
        time.sleep(0.05)
    raise RuntimeError(f'{path.name}: no {marker!r}:\n' + path.read_text(errors='replace')[-2000:])


def wan_bytes(endpoint: str) -> dict:
    link = json.loads(ns(endpoint, 'ip', '-j', '-s', 'link', 'show', 'dev', 'wan0'))[0]
    stats = link['stats64']
    return {'tx_bytes': stats['tx']['bytes'], 'tx_packets': stats['tx']['packets'],
            'rx_bytes': stats['rx']['bytes'], 'rx_packets': stats['rx']['packets']}


# --- traffic workers, executed inside the host namespaces -------------------

def receive(port: int, flows: int, seconds: float, report: str) -> None:
    """Accept `flows` connections, verify every byte and count arrivals over time."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', port))
    listener.listen(flows)
    lock = threading.Lock()
    state = {'bytes': 0, 'corrupt': 0, 'eof': 0, 'samples': []}

    def serve(connection: socket.socket) -> None:
        offset = 0
        view = memoryview(BLOCK)
        while True:
            data = connection.recv(1 << 16)
            if not data:
                break
            position = offset % len(BLOCK)
            head = min(len(data), len(BLOCK) - position)
            good = data[:head] == view[position:position + head] and \
                data[head:] == view[:len(data) - head]
            offset += len(data)
            with lock:
                state['bytes'] += len(data)
                state['corrupt'] += 0 if good else 1
        with lock:
            state['eof'] += 1
        connection.close()

    def accept() -> None:
        for _ in range(flows):
            connection, _ = listener.accept()
            threading.Thread(target=serve, args=(connection,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    Path(report + '.ready').write_text('ready')
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        time.sleep(0.25)
        with lock:
            state['samples'].append((round(time.monotonic() - started, 3), state['bytes']))
    with lock:
        Path(report).write_text(json.dumps(state))


def send(address: str, port: int, flows: int, seconds: float) -> None:
    """Send the deterministic stream on `flows` connections until the deadline."""
    deadline = time.monotonic() + seconds

    def run() -> None:
        connection = socket.create_connection((address, port), timeout=30)
        connection.settimeout(None)
        while time.monotonic() < deadline:
            connection.sendall(BLOCK)
        connection.close()

    threads = [threading.Thread(target=run, daemon=True) for _ in range(flows)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(seconds + 60)


def reference(goodput_mbit: float, path: str, inner_rto_min_ms: int, tolerance: float,
              override: float | None = None) -> dict:
    """Compare measured forward goodput with the simulator at equal overhead.

    The kernel's own minimum RTO (selected with 0) is 200 ms.
    """
    key = inner_rto_min_ms or 200
    expected = override if override is not None else SIMULATOR_REFERENCE.get((path, key))
    if expected is None:
        return {'available': False,
                'reason': f'no simulator run for path {path} with a {key} ms minimum RTO'}
    floor = expected * (1 - tolerance)
    return {'available': True, 'simulator_goodput_mbit': expected,
            'simulator_inner_rto_min_ms': key, 'tolerance': tolerance,
            'required_goodput_mbit': round(floor, 3), 'observed_goodput_mbit': goodput_mbit,
            'observed_over_simulator': round(goodput_mbit / expected, 4),
            'meets_reference': goodput_mbit >= floor}


def udp_echo(port: int, seconds: float) -> None:
    """Answer every datagram with its SHA-256 until the deadline."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            data, peer = sock.recvfrom(65535)
        except socket.timeout:
            break
        sock.sendto(hashlib.sha256(data).digest(), peer)


def udp_probe(address: str, port: int) -> None:
    """Send datagrams from tiny to the largest unfragmented size; print how
    many came back with the right digest."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    good, sizes = 0, (1, 18, 64, 512, 1200, 1472)
    for size in sizes:
        data = BLOCK[:size]
        for _ in range(8):   # the application retries; the tunnel itself is reliable
            sock.sendto(data, (address, port))
            try:
                if sock.recvfrom(64)[0] == hashlib.sha256(data).digest():
                    good += 1
                    break
            except socket.timeout:
                continue
    print(json.dumps({'sizes': len(sizes), 'answered': good}))


def control(work: Path, binary: str, side: str, command: str, *options: str) -> dict:
    """Run one local control command against a live endpoint."""
    space = 'ea' if side == 'a' else 'eb'
    out = ns(space, binary, command, '--control-socket',
             str(work / f'control-{side}.sock'), *options, check=False)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {'ok': False, 'raw': out[-200:]}


def reachable() -> bool:
    out = ns('ha', 'ping', '-c', '3', '-i', '0.2', '-W', '2', HOST_B, check=False)
    return ' 0% packet loss' in out or ' 33% packet loss' in out


def lifecycle(work: Path, binary: str) -> dict:
    """Disconnect and reconnect through the shared service's local commands:
    the tunnel must actually stop carrying traffic and actually resume."""
    phase = lambda reply: (reply.get('state') or {}).get('phase')
    checks = {}
    # A negotiated policy change on the live session: fewer channels and a
    # proportion of coded repairs, without reconnecting.
    before = (control(work, binary, 'a', 'status').get('state') or {}).get('epoch') or 0
    changed = control(work, binary, 'a', 'set-swift', '--swift-channels', '8',
                      '--swift-repair-permille', '100')
    state = changed.get('state') or {}
    swift = state.get('swift') or {}
    checks['policy_change_committed'] = (bool(changed.get('ok')) and state.get('epoch') == before + 1
                                         and swift.get('channels') == 8
                                         and swift.get('repair_permille') == 100
                                         and swift.get('generation') == 1)
    checks['traffic_after_policy_change'] = reachable()
    refused = control(work, binary, 'b', 'set-swift', '--swift-channels', '4')
    checks['only_initiator_proposes'] = (not refused.get('ok')
                                         and refused.get('code') == 'not_coordinator')
    reply = control(work, binary, 'a', 'disconnect')
    checks['disconnect_reported'] = bool(reply.get('ok')) and phase(reply) == 'disconnected'
    checks['traffic_stopped'] = not reachable()
    resumed = {}
    for _ in range(20):   # the acceptor needs a moment to listen again
        resumed = control(work, binary, 'a', 'reconnect')
        if resumed.get('ok'):
            break
        time.sleep(0.5)
    checks['reconnect_reported'] = bool(resumed.get('ok')) and phase(resumed) == 'forwarding'
    swift = (resumed.get('state') or {}).get('swift') or {}
    checks['new_generation'] = (swift.get('generation') or 0) > 1
    checks['traffic_resumed'] = reachable()
    checks['acceptor_forwarding'] = phase(control(work, binary, 'b', 'status')) == 'forwarding'
    return checks


def functional(script: str) -> dict:
    """Layer-2 behaviour visible to the hosts, in both directions."""
    checks = {}
    for name, source, target in (('a_to_b', 'ha', HOST_B), ('b_to_a', 'hb', HOST_A)):
        # 1472 bytes of ICMP payload with DF set is exactly one 1514-byte frame.
        out = ns(source, 'ping', '-c', '5', '-i', '0.2', '-W', '3', '-M', 'do', '-s', '1472',
                 target, check=False)
        received = [line for line in out.splitlines() if 'packets transmitted' in line]
        checks[f'full_mtu_ping_{name}'] = ' 0% packet loss' in (received[0] if received else '')
        neighbours = json.loads(ns(source, 'ip', '-j', 'neigh', 'show', target) or '[]')
        checks[f'arp_resolved_{name}'] = any(entry.get('lladdr') for entry in neighbours)
    for name, source, sink, address in (('a_to_b', 'ha', 'hb', HOST_B), ('b_to_a', 'hb', 'ha', HOST_A)):
        echo = subprocess.Popen(['ip', 'netns', 'exec', sink, sys.executable, script,
                                 '--worker', 'udp-echo', '24600', '20'])
        time.sleep(0.3)
        out = ns(source, sys.executable, script, '--worker', 'udp-probe', address, '24600',
                 check=False)
        echo.terminate()
        echo.wait(5)
        try:
            state = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            state = {'sizes': 6, 'answered': 0}
        checks[f'udp_all_sizes_{name}'] = state['answered'] == state['sizes']
    return checks


def rate_mbit(samples: list, start: float, end: float) -> float:
    inside = [(t, b) for t, b in samples if start <= t <= end]
    if len(inside) < 2:
        return 0.0
    (t0, b0), (t1, b1) = inside[0], inside[-1]
    return (b1 - b0) * 8 / (t1 - t0) / 1e6


def run(args: argparse.Namespace) -> int:
    work = Path(tempfile.mkdtemp(prefix='l2tunnel-selftest-'))
    processes: list[subprocess.Popen] = []
    try:
        build_topology(args.path, args.forward_mbit, args.reverse_mbit, args.host_mtu,
                       args.inner_rto_min_ms)
        credentials(args.binary, work)
        (work / 'rolling.json').write_text(json.dumps(rolling_policy(args)))
        logs = {}
        for side, space in (('b', 'eb'), ('a', 'ea')):
            logs[side] = work / f'endpoint-{side}.log'
            handle = open(logs[side], 'w')
            processes.append(subprocess.Popen(
                ['ip', 'netns', 'exec', space, *endpoint_command(args, side, work)],
                stdout=handle, stderr=subprocess.STDOUT))
            if side == 'b':
                time.sleep(0.5)
        for side, process in zip(('b', 'a'), processes):
            wait_for(logs[side], 'Authenticated', process, 20)
        ping = ns('ha', 'ping', '-c', '10', '-i', '0.2', '-W', '3', HOST_B, check=False)
        ping_summary = [line for line in ping.splitlines() if 'packet loss' in line or 'rtt' in line]

        script = str(Path(__file__).resolve())
        checks = functional(script)
        idle_counters = {}
        if args.profile == 'swift':
            # Counters right after the idle-path checks, so a failed check
            # can be attributed to a drop or to delay.
            for side in ('a', 'b'):
                state = control(work, args.binary, side, 'status').get('state') or {}
                idle_counters[side] = state.get('swift')
        result = {'profile': args.profile, 'path': args.path, 'duplex': args.duplex,
                  'flows': args.flows, 'host_mtu': args.host_mtu,
                  'inner_rto_min_ms': args.inner_rto_min_ms, 'ping': ping_summary,
                  'functional': checks, 'functional_counters': idle_counters}
        directions = [('forward', 'ha', 'hb', HOST_B, 'ea')]
        if args.reverse:
            directions.append(('reverse', 'hb', 'ha', HOST_A, 'eb'))
        total = args.warmup + args.duration
        workers = []
        for index, (name, source, sink, address, _) in enumerate(directions):
            report = str(work / f'{name}.json')
            port = 24500 + index
            workers.append(subprocess.Popen(
                ['ip', 'netns', 'exec', sink, sys.executable, script, '--worker', 'receive',
                 str(port), str(args.flows), str(total + args.drain), report]))
            while not Path(report + '.ready').exists():
                time.sleep(0.02)
            workers.append(subprocess.Popen(
                ['ip', 'netns', 'exec', source, sys.executable, script, '--worker', 'send',
                 address, str(port), str(args.flows), str(total)]))
        switched = None
        if args.switch_at is not None:
            # Change the policy under load; the verified payload and clean
            # close of every flow then cover the barrier itself.
            time.sleep(args.switch_at)
            switched = control(work, args.binary, 'a', 'set-swift', '--swift-channels', '8',
                               '--swift-repair-permille', '50')
            time.sleep(max(0.0, args.warmup - args.switch_at))
        else:
            time.sleep(args.warmup)
        before = {space: wan_bytes(space) for space in ('ea', 'eb')}
        time.sleep(args.duration)
        after = {space: wan_bytes(space) for space in ('ea', 'eb')}
        for worker in workers:
            worker.wait(total + args.drain + 90)
        for side, process in zip(('b', 'a'), processes):
            if process.poll() is not None:
                raise RuntimeError(f'endpoint {side} exited:\n' + logs[side].read_text()[-2000:])

        passed = all(checks.values())
        if args.profile == 'swift':
            # The same status command a user would run against a live endpoint.
            result['status'] = {}
            for side, space in (('a', 'ea'), ('b', 'eb')):
                out = ns(space, args.binary, 'status', '--control-socket',
                         str(work / f'control-{side}.sock'), check=False)
                try:
                    reply = json.loads(out.strip().splitlines()[-1])
                except (ValueError, IndexError):
                    reply = {'ok': False, 'raw': out[-200:]}
                swift = (reply.get('state') or {}).get('swift') or {}
                result['status'][side] = {'ok': bool(reply.get('ok')),
                                          'phase': (reply.get('state') or {}).get('phase'),
                                          'native_written': swift.get('native_written')}
                if not reply.get('ok') or not swift.get('native_written'):
                    passed = False
            if switched is not None:
                result['switch_under_load'] = {
                    'ok': bool(switched.get('ok')),
                    'epoch': (switched.get('state') or {}).get('epoch')}
                if not switched.get('ok'):
                    passed = False
            result['lifecycle'] = lifecycle(work, args.binary)
            if not all(result['lifecycle'].values()):
                passed = False
        for name, _, _, _, endpoint in directions:
            state = json.loads((work / f'{name}.json').read_text())
            goodput = rate_mbit(state['samples'], args.warmup, total)
            packets = after[endpoint]['tx_packets'] - before[endpoint]['tx_packets']
            # Interface counters include the 14-byte Ethernet header.
            wire = ((after[endpoint]['tx_bytes'] - before[endpoint]['tx_bytes'] - 14 * packets)
                    * 8 / args.duration / 1e6)
            budget = args.forward_mbit if name == 'forward' else args.reverse_mbit
            result[name] = {
                'goodput_mbit': round(goodput, 3), 'budget_mbit': budget,
                'goodput_over_budget': round(goodput / budget, 4),
                'wan_tx_mbit_ip': round(wire, 3), 'wan_tx_packets': packets,
                'payload_over_wan_bytes': round(goodput / wire, 4) if wire else 0,
                'bytes': state['bytes'], 'corrupt_reads': state['corrupt'],
                'flows_closed_cleanly': state['eof']}
            if state['corrupt'] or state['eof'] != args.flows or state['bytes'] == 0:
                passed = False
        if args.profile == 'swift':
            result['swift'] = {}
            for side in ('a', 'b'):
                reports = [json.loads(line) for line in logs[side].read_text().splitlines()
                           if line.startswith('{') and '"swift_report"' in line]
                if reports:
                    result['swift'][side] = reports[-1]
        result['tc'] = {space: ns(space, 'tc', '-s', 'qdisc', 'show', 'dev', 'wan0').strip()
                        for space in ('ea', 'eb')}
        comparable = (args.profile == 'swift' and args.flows == 16
                      and (args.forward_mbit, args.reverse_mbit) == (100, 10) and not args.reverse)
        if comparable or args.reference_mbit is not None:
            result['reference'] = reference(result['forward']['goodput_mbit'], args.path,
                                            args.inner_rto_min_ms, args.tolerance,
                                            args.reference_mbit)
        else:
            result['reference'] = {'available': False,
                                   'reason': 'not the simulator reference scenario'}
        result['integrity_passed'] = passed
        if args.require_reference and not result['reference'].get('meets_reference'):
            passed = False
        result['passed'] = passed
        print(json.dumps(result, indent=2))
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
        if not passed or args.keep_logs:
            for side in ('a', 'b'):
                print(f'--- endpoint {side}\n' + logs[side].read_text(errors='replace')[-args.log_tail:])
        return 0 if passed else 1
    finally:
        for process in processes:
            process.send_signal(signal.SIGTERM)
        for process in processes:
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == '--worker':
        if sys.argv[2] == 'udp-echo':
            udp_echo(int(sys.argv[3]), float(sys.argv[4]))
        elif sys.argv[2] == 'udp-probe':
            udp_probe(sys.argv[3], int(sys.argv[4]))
        elif sys.argv[2] == 'receive':
            receive(int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]), sys.argv[6])
        else:
            send(sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), float(sys.argv[6]))
        return 0
    parser = argparse.ArgumentParser(description='Linux TAP self-test of the l2tunnel CLI under tc HTB/netem.')
    parser.add_argument('--binary', default=str(ROOT / 'target/release/l2tunneld'))
    parser.add_argument('--profile', choices=('swift', 'tcp', 'udp', 'udp-fec', 'rolling'), default='swift')
    parser.add_argument('--path', choices=tuple(PATHS), default='impaired')
    parser.add_argument('--duplex', choices=('full', 'half'), default='full')
    parser.add_argument('--flows', type=int, default=16)
    parser.add_argument('--reverse', action='store_true', help='also run bulk flows B to A')
    parser.add_argument('--warmup', type=float, default=5)
    parser.add_argument('--duration', type=float, default=20)
    parser.add_argument('--drain', type=float, default=10)
    parser.add_argument('--forward-mbit', type=int, default=100)
    parser.add_argument('--reverse-mbit', type=int, default=10)
    parser.add_argument('--host-mtu', type=int, default=1500)
    parser.add_argument('--protection', choices=('aead', 'integrity'), default='aead')
    parser.add_argument('--channels', type=int, default=16)
    parser.add_argument('--window', type=int, default=128)
    parser.add_argument('--local-window', type=int, default=128)
    parser.add_argument('--max-payload', type=int, default=1342)
    parser.add_argument('--repair-numerator', type=int, default=41)
    parser.add_argument('--repair-denominator', type=int, default=200)
    parser.add_argument('--feedback-ms', type=int, default=1)
    parser.add_argument('--swift-window', type=int, default=64)
    parser.add_argument('--swift-utilization', type=float, default=0.99,
                        help='tunnel budget as a fraction of the shaped rate')
    parser.add_argument('--swift-repair-permille', type=int, default=0)
    parser.add_argument('--swift-channels', type=int, default=16)
    parser.add_argument('--inner-rto-min-ms', type=int, default=1000,
                        help='minimum retransmission timeout of the test TCP flows, as in the '
                             'simulator reference; 0 keeps the kernel default')
    parser.add_argument('--reference-mbit', type=float,
                        help='forward goodput to compare against instead of the recorded '
                             'simulator result')
    parser.add_argument('--tolerance', type=float, default=0.025,
                        help='accepted shortfall against the reference, as a fraction')
    parser.add_argument('--require-reference', action='store_true',
                        help='fail unless forward goodput is within the tolerance of the '
                             'reference')
    parser.add_argument('--output')
    parser.add_argument('--switch-at', type=float,
                        help='negotiate a swift policy change this many seconds into the '
                             'warm-up, under load (must not exceed --warmup)')
    parser.add_argument('--keep-logs', action='store_true')
    parser.add_argument('--log-tail', type=int, default=3000)
    parser.add_argument('extra', nargs='*', help='extra endpoint options after --')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if args.output:
        args.output = str(Path(args.output).resolve())
    if os.geteuid() != 0:
        # Private user, network and mount namespaces: no privilege, no host changes.
        os.execvp('unshare', ['unshare', '-Urnm', sys.executable, str(Path(__file__).resolve()),
                              *sys.argv[1:]])
    sh('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    os.makedirs('/run/netns', exist_ok=True)
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
