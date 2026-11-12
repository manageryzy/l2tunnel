#!/usr/bin/env python3
"""Explicit isolated authenticated TCP/UDP native smoke; default is a dry run."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import importlib
import json
import math
import os
import re
import shutil
import struct
import stat
import sys
from pathlib import Path
import subprocess
import tempfile
import time

try:
    from . import netns_lab
except ImportError:
    import netns_lab

ROOT = Path(__file__).resolve().parents[1]


class _PackedModule:
    """Load optional helpers only for packed paths; old helper snapshots still run."""
    def __init__(self, name):
        self.name = name

    def __getattr__(self, name):
        module = importlib.import_module(('.' + self.name) if __package__ else self.name, __package__)
        return getattr(module, name)


packed_shared = _PackedModule('proxy_native_smoke')
burst = _PackedModule('udp_burst_probe')


class CaseEvidence:
    """One owned bounded JSON receipt; failed replacement preserves the last version."""
    MAXIMUM_BYTES = 4 * 1024 * 1024

    def __init__(self, path: Path, case: str):
        self.path = path
        self.value = {}
        self.update(create=True, case=case, status='running', completed={})

    def update(self, *, create: bool = False, **changes) -> None:
        candidate = {**self.value, **changes}
        data = (json.dumps(candidate, indent=2) + '\n').encode()
        if len(data) > self.MAXIMUM_BYTES:
            raise ValueError('case evidence exceeds its 4 MiB bound')
        # Own a detached JSON value so later caller mutations cannot alter the
        # last committed in-memory version before the next atomic replacement.
        candidate = json.loads(data)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.path.parent, prefix=self.path.name + '.',
                                             suffix='.tmp', delete=False) as output:
                temporary = Path(output.name)
                output.write(data)
                output.flush()
                # Receipts contain only explicitly selected non-secret evidence;
                # privileged lab runs must leave them readable for their owner.
                os.fchmod(output.fileno(), 0o644)
                os.fsync(output.fileno())
            if create:
                os.link(temporary, self.path)  # Exclusive publication; never rewrite history.
            else:
                os.replace(temporary, self.path)
            self.value = candidate
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def record(self, name: str, value) -> None:
        self.update(completed={**self.value['completed'], name: value})


def command(argv: list[str], *, timeout: float = 60) -> str:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if completed.returncode:
        raise RuntimeError(f"command failed ({completed.returncode}): {argv!r}\n{completed.stdout}{completed.stderr}")
    return completed.stdout


def verify_ping(result: str, expected: int = 3) -> None:
    """Require exact transmitted/received counts, never substring-match percentages."""
    counts = re.search(r'(\d+) packets transmitted, (\d+) received,.*?([0-9.]+)% packet loss', result)
    if counts is None or (int(counts.group(1)), int(counts.group(2)), float(counts.group(3))) != (expected, expected, 0.0):
        raise RuntimeError(f'packet count/loss mismatch in native smoke: {result}')


def verify_blocked_ping(result: str) -> None:
    """Negative path evidence must be exactly one sent packet and no response."""
    counts = re.search(r'(\d+) packets transmitted, (\d+) received,.*?([0-9.]+)% packet loss', result)
    if counts is None or (int(counts.group(1)), int(counts.group(2)), float(counts.group(3))) != (1, 0, 100.0):
        raise RuntimeError(f'UDP-blocked probe did not establish the expected path failure: {result}')


def outage_timing(events: dict, profile: str) -> dict:
    """Bound userspace-observed transitions without inventing kernel timestamps."""
    expected = {'a'} if profile == 'short-recovery' else {'a', 'b'} if profile == 'idle-loss' else set()
    if not expected or set(events) != expected:
        raise ValueError('outage profile/endpoint mismatch')
    for event in events.values():
        values = [event[key] for key in ('install_started', 'installed', 'remove_started', 'removed')]
        if any(not math.isfinite(value) or value < 0 for value in values) or values != sorted(values):
            raise ValueError('invalid outage transition timestamps')
    installed = max(event['installed'] for event in events.values())
    joint = min(event['remove_started'] for event in events.values()) - installed
    operation = max(event['removed'] for event in events.values()) - min(event['install_started'] for event in events.values())
    if profile == 'short-recovery' and (joint < 0.250 or operation > 0.500):
        raise RuntimeError('short recovery outage outside 250 ms hold / 500 ms operation bound')
    if profile == 'idle-loss' and (joint < 4.0 or max(event['removed'] for event in events.values()) > installed + 5.0):
        raise RuntimeError('idle-loss outage/removal exceeded its fixed four/five-second contract')
    return {'joint_blocked_seconds_lower_bound': joint,
            'whole_operation_seconds_upper_bound': operation,
            'joint_installed_at_seconds': installed}


def terminal_observation(returncode: int | None, line: str, observed_at: float, deadline: float) -> dict:
    """Only an actual reported terminal class satisfies expected-terminal coverage."""
    if returncode is None or returncode <= 0 or not math.isfinite(observed_at) or not math.isfinite(deadline) or observed_at < 0 or deadline < 0 or observed_at > deadline:
        raise RuntimeError('missing, successful or late terminal process outcome')
    simple = {'l2tunnel: carrier Timeout; deadline cause not distinguished': 'Timeout',
              'l2tunnel: carrier IncompleteClose; native drain incomplete': 'IncompleteClose'}
    kind = simple.get(line.strip())
    if kind is None:
        prefix = 'l2tunnel: carrier ended before distributed native drain; incomplete; '
        body = line.strip().removeprefix(prefix)
        if not line.startswith(prefix) or re.fullmatch(r'(lane [01] terminal=(None|Some\((Timeout|IncompleteClose)\)) closing=(true|false); ?){1,2}', body) is None:
            raise RuntimeError('terminal outcome is not an explicit Timeout/IncompleteClose')
        kind = 'Timeout' if 'Some(Timeout)' in body else 'IncompleteClose' if 'Some(IncompleteClose)' in body else None
    if kind is None:
        raise RuntimeError('closing without an actual terminal is not terminal evidence')
    return {'returncode': returncode, 'class': kind, 'observed_at_seconds': observed_at, 'line': line}


def standalone_outage(profile: str, namespaces: dict, source: str, address: str,
                      endpoints: dict, evidence: CaseEvidence, started: float) -> dict:
    """Separately reviewed clean TUN/half outage profiles; no policy relaxation."""
    if profile not in ('short-recovery', 'idle-loss') or set(endpoints) != {'a', 'b'}:
        raise ValueError('standalone outage requires its exact profile and both endpoint owners')
    if any(process.poll() is not None for process, _ in endpoints.values()):
        raise RuntimeError('endpoint already exited before the declared outage')
    events, installed, outcomes = {}, [], {}
    result = {'profile': profile, 'events': events, 'terminal': outcomes}
    sides = ('a',) if profile == 'short-recovery' else ('a', 'b')
    joint = None
    def now():
        return time.monotonic() - started
    def save():
        evidence.record('udp_path_check', result)
    def observe(deadline):
        for side, (process, log) in endpoints.items():
            if side not in outcomes and process.poll() is not None:
                lines = log.read_text().splitlines()
                outcomes[side] = terminal_observation(process.returncode, lines[-1] if lines else '', now(), deadline)
                save()
    try:
        for side in sides:
            endpoint = ['ip', 'netns', 'exec', namespaces[f'endpoint_{side}']]
            events[side] = {'install_started': now()}
            command([*endpoint, 'tc', 'filter', 'add', 'dev', 'wan0', 'egress', 'protocol', 'ip', 'pref', '2', 'u32', 'match', 'ip', 'protocol', '17', '0xff', 'action', 'drop'], timeout=1)
            installed.append((side, endpoint))
            events[side]['installed'] = now()
            save()
        joint = max(event['installed'] for event in events.values())
        result['joint_installed_at_seconds'] = joint
        if profile == 'idle-loss':
            result['terminal_deadline_seconds'] = joint + 5.0
        save()
        if profile == 'short-recovery':
            blocked = subprocess.run(['ip', 'netns', 'exec', source, 'ping', '-n', '-c', '1', '-W', '0.2', address], capture_output=True, text=True, timeout=0.5)
            if blocked.returncode != 1:
                raise RuntimeError(f'short blocked ping had unexpected outcome: {blocked.stdout}{blocked.stderr}')
            verify_blocked_ping(blocked.stdout)
            result['blocked_probe'] = blocked.stdout
            if any(process.poll() is not None for process, _ in endpoints.values()):
                raise RuntimeError('endpoint exited during short recovery interruption')
            time.sleep(max(0, joint + 0.250 - now()))
        else:
            while now() < joint + 4.0:
                observe(joint + 5.0)
                time.sleep(min(0.01, max(0, joint + 4.0 - now())))
        for side, endpoint in installed:
            stats = command([*endpoint, 'tc', '-s', 'filter', 'show', 'dev', 'wan0', 'egress', 'pref', '2'], timeout=0.5)
            if not any(int(count) > 0 for count in re.findall(r'dropped\s+(\d+)', stats)):
                raise RuntimeError('owned outage filter recorded no dropped packets')
            result.setdefault('drop_filter', {})[side] = stats
        save()
    finally:
        removal_error = None
        for side, endpoint in reversed(installed):
            events[side]['remove_started'] = now()
            try:
                command([*endpoint, 'tc', 'filter', 'del', 'dev', 'wan0', 'egress', 'pref', '2'], timeout=0.5)
            except Exception as error:
                events[side]['remove_error'] = str(error)
                if removal_error is None:
                    removal_error = error
            else:
                events[side]['removed'] = now()
            finally:
                try:
                    save()
                except Exception as error:
                    if removal_error is None:
                        removal_error = error
        if removal_error is not None:
            raise removal_error
    result['timing'] = outage_timing(events, profile)
    if profile == 'idle-loss':
        deadline = joint + 5.0
        while len(outcomes) != len(endpoints):
            observe(deadline)
            if now() >= deadline and len(outcomes) != len(endpoints):
                raise TimeoutError('idle-loss original five-second terminal deadline exhausted')
            if len(outcomes) != len(endpoints):
                time.sleep(min(0.01, max(0, deadline - now())))
        result['terminal_deadline_seconds'] = deadline
    elif any(process.poll() is not None for process, _ in endpoints.values()):
        raise RuntimeError('endpoint exited before short recovery restoration')
    result['tcp_control'] = command(['ip', 'netns', 'exec', namespaces['endpoint_a'], 'ss', '-Htn', 'state', 'established'])
    if any('192.0.2.' in line for line in result['tcp_control'].splitlines()):
        raise RuntimeError('standalone carrier unexpectedly has an established underlay TCP socket')
    save()
    return result


def wait_log(process: subprocess.Popen, path: Path, text: str, timeout: float = 65) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if text in path.read_text():
            return
        if process.poll() is not None:
            raise RuntimeError(f"endpoint exited: {path.read_text()}")
        time.sleep(0.05)
    raise TimeoutError(f"endpoint did not become ready: {path.read_text()}")


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_udp_bound(process: subprocess.Popen, log: Path, namespace: str,
                   address: str, ports: list[int]) -> str:
    """Observe every actual fixed UDP socket owned by the launched process."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f'standalone endpoint exited before binding: {log.read_text()}')
        sockets = command(['ip', 'netns', 'exec', namespace, 'ss', '-Huanp'], timeout=2)
        if all(any(f'{address}:{port}' in line and f'pid={process.pid},' in line
                   for line in sockets.splitlines()) for port in ports):
            return sockets
        time.sleep(0.05)
    raise TimeoutError('standalone fixed UDP sockets did not bind before deadline')


def audit_openvpn_capture(data: bytes, path_mtu: int, duplex: str) -> dict:
    """Strict finite Ethernet/IPv4 UDP sample audit; this does not verify MACs."""
    if len(data) > 64 * 1024 * 1024 or len(data) < 24:
        raise ValueError('PCAP byte bound/header')
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}.get(data[:4])
    if endian is None or not 576 <= path_mtu <= 65535 or duplex not in ('half', 'full'):
        raise ValueError('PCAP format or policy')
    major, minor, _, _, snap, link = struct.unpack_from(endian + 'HHIIII', data, 4)
    if (major, minor, link) != (2, 4, 1) or not 64 <= snap <= 262144:
        raise ValueError('PCAP requires complete Ethernet capture')
    ports = [24440, 24441] if duplex == 'half' else [24440]
    counts = {str(port): {kind: 0 for kind in ('hello', 'retry', 'echo', 'control', 'control_ack', 'protected')} for port in ports}
    offset, packets, maximum = 24, 0, 0
    while offset < len(data):
        if len(data) - offset < 16 or packets >= 4096:
            raise ValueError('PCAP record/count bound')
        _, _, size, original = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        if size != original or size > snap or size < 42 or size > len(data) - offset:
            raise ValueError('PCAP truncated or excessive packet')
        frame = data[offset:offset + size]
        offset += size
        if frame[12:14] != b'\x08\x00' or frame[14] >> 4 != 4:
            raise ValueError('unexpected underlay network protocol')
        ihl = (frame[14] & 15) * 4
        total = int.from_bytes(frame[16:18], 'big')
        fragment = int.from_bytes(frame[20:22], 'big')
        if not 20 <= ihl <= 60 or total < ihl + 8 or total > path_mtu or 14 + total > len(frame) or fragment & 0x3fff or frame[23] != 17:
            raise ValueError('underlay IP length/fragment/protocol bound')
        src, dst = frame[26:30], frame[30:34]
        a, b = b'\xc0\x00\x02\x02', b'\xc0\x00\x02\x06'
        if (src, dst) not in ((a, b), (b, a)):
            raise ValueError('unexpected fixed underlay addresses')
        start = 14 + ihl
        source, destination, length = struct.unpack_from('!HHH', frame, start)
        if source != destination or source not in ports or length != total - ihl:
            raise ValueError('unexpected UDP tuple/length')
        body = frame[start + 8:14 + total]
        if not body:
            raise ValueError('missing standalone envelope')
        kind = {32: 'control', 40: 'control_ack', 72: 'protected'}.get(body[0])
        if body[0] in (56, 64):
            if len(body) != 144 or body[1] != 1 or body[3] != 0 or (body[0], body[2]) not in ((56, 1), (64, 2), (56, 3)):
                raise ValueError('invalid gate sample')
            kind = {1: 'hello', 2: 'retry', 3: 'echo'}[body[2]]
        elif kind is None or len(body) < 64:
            raise ValueError('unknown or truncated standalone envelope')
        counts[str(source)][kind] += 1
        packets += 1
        maximum = max(maximum, total)
    if not packets or any(any(value == 0 for value in lane.values()) for lane in counts.values()):
        raise ValueError('capture lacks required gate/control/protected lane evidence')
    return {'packets': packets, 'maximum_ip_bytes': maximum, 'path_mtu': path_mtu,
            'lanes': counts, 'scope': 'finite framing/MTU sample; no cryptographic verification'}
def observation_snapshot(text: str) -> list[dict]:
    """A live file may end inside println; parse only complete records."""
    return [json.loads(line) for line in text.splitlines(keepends=True)
            if line.startswith('{"') and line.endswith('\n')]


def control(binary: Path, path: Path, action: str, compression: str | None = None, *, timeout: float = 70) -> dict:
    argv = [str(binary), action, '--control-socket', str(path)]
    if compression is not None:
        argv.extend(['--compression', compression])
    return json.loads(command(argv, timeout=timeout))


def verify_state(response: dict, epoch: int, compression: str) -> bool:
    """A successful request is not proof of both peers' committed state."""
    state = response.get('state') or {}
    return response.get('ok') is True and state.get('epoch') == epoch and state.get('compression') == compression and state.get('phase') == 'Idle'


def wait_states(binary: Path, paths: list[Path], epoch: int, compression: str) -> list[dict]:
    deadline = time.monotonic() + 30
    states = []
    while time.monotonic() < deadline:
        states = [control(binary, path, 'status') for path in paths]
        if all(verify_state(state, epoch, compression) for state in states):
            return states
        time.sleep(0.05)
    raise TimeoutError(f'peers did not reach committed idle epoch {epoch}: {states!r}')



def transaction_timing(profile: str) -> dict:
    if profile == 'slow-netem':
        return {'retry_ms': 250, 'phase_timeout_ms': 30000, 'reconcile_timeout_ms': 60000}
    return {'retry_ms': 100, 'phase_timeout_ms': 5000, 'reconcile_timeout_ms': 15000}


def active_policy(channels: int, weighted: bool = False) -> dict:
    weights = [1] * 64
    if weighted:
        weights[46] = 4
    return {'channels': channels, 'dscp_weights': weights}


def verify_active_state(response: dict, epoch: int, compression: str, policy: dict) -> bool:
    """Require the actual complete committed policy and live admission gates."""
    if not verify_state(response, epoch, compression):
        return False
    active = response['state'].get('active') or {}
    actual = active.get('policy') or {}
    weights = actual.get('dscp_weights')
    return (response.get('version') == 1 and active.get('admitting') is True
            and active.get('running') is True and type(actual.get('channels')) is int
            and isinstance(weights, list) and len(weights) == 64
            and all(type(weight) is int for weight in weights) and actual == policy
            and isinstance(active.get('digest'), str)
            and re.fullmatch(r'[0-9a-f]{64}', active['digest']) is not None)


def wait_active_states(binary: Path, paths: list[Path], epoch: int, compression: str, policy: dict, *, overall_deadline: float | None = None) -> list[dict]:
    deadline = min(time.monotonic() + 30, overall_deadline or float("inf"))
    states = []
    while time.monotonic() < deadline:
        states = [control(binary, path, 'status', timeout=remaining(deadline, 30)) for path in paths]
        if verify_active_peers(states, epoch, compression, policy):
            return states
        time.sleep(0.05)
    raise TimeoutError(f'active peers did not agree on idle policy at epoch {epoch}: {states!r}')


def verify_active_peers(states: list[dict], epoch: int, compression: str, policy: dict) -> bool:
    return (len(states) == 2 and all(verify_active_state(state, epoch, compression, policy) for state in states)
            and len({state['state']['active']['digest'] for state in states}) == 1)


def remaining(deadline: float, limit: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("declared overall TCP transfer deadline exhausted")
    return min(limit, seconds)


def switch_active(binary: Path, path: Path, policy: dict, *, rejected: bool = False, timeout: float = 70) -> dict:
    argv = [str(binary), 'set-active-policy', '--control-socket', str(path),
            '--mux-channels', str(policy['channels'])]
    changes = ','.join(f'{index}:{weight}' for index, weight in enumerate(policy['dscp_weights']) if weight != 1)
    if changes:
        argv.extend(['--qos-dscp', changes])
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f'active policy command returned no response ({result.returncode}): {result.stdout} {result.stderr}') from error
    if rejected:
        if result.returncode == 0 or response.get('ok') is not False or response.get('code') != 'not_coordinator':
            raise RuntimeError(f'follower policy request was not rejected: {response!r} {result.stderr}')
    elif result.returncode != 0 or response.get('ok') is not True:
        raise RuntimeError(f'active policy switch failed: {response!r} {result.stderr}')
    return response


def verify_tcp_payload(value: dict, family: int, count: int) -> None:
    """Require the selected real socket family and complete checksum result."""
    if (not isinstance(value, dict) or value.get('status') != 'passed'
            or type(value.get('ip_version')) is not int or value['ip_version'] != family
            or type(value.get('bytes')) is not int or value['bytes'] != count
            or not isinstance(value.get('sha256'), str)
            or re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is None):
        raise RuntimeError('TCP probe family/status/byte/checksum witness mismatch')


def case_name(layer: str, duplex: str, impaired: bool, path_probe: str = 'original-2s') -> str:
    base = f"{layer}-{duplex}-{'netem' if impaired else 'clean'}"
    return base if path_probe == 'original-2s' else f'{base}-{path_probe}'


PACKED_DEFAULTS = {'channels': 4, 'hold_micros': 1000, 'max_units': 4, 'work_limit': 16}
PACKED_HELPERS = ('native_smoke.py', 'netns_lab.py', 'proxy_native_smoke.py',
                  'tcp_probe.py', 'flow_churn_probe.py', 'udp_burst_probe.py')
PACKED_CAPTURE_BYTES = 32 * 1024 * 1024
PACKED_CAPTURE_PACKETS = 4096


def namespace_observation(spec):
    """Observe exact expected names; observations never confer deletion authority."""
    result = {}
    for name in spec.namespaces.values():
        try:
            info = (netns_lab.NETNS_DIRECTORY / name).lstat()
        except FileNotFoundError:
            result[name] = None
        else:
            result[name] = {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IFMT(info.st_mode)}
    return result


def namespace_changes(before, after):
    if before is None or set(before) != set(after):
        raise ValueError('incomplete expected-namespace baseline')
    return {name: {'before': before[name], 'after': after[name]}
            for name in before if before[name] != after[name]}


# Canonical directions match the lab's100/10Mbit/s shapers, including clean controls.
DELIVERY_POLICY = {
    'forward_bandwidth_bps': 100_000_000, 'reverse_bandwidth_bps': 10_000_000,
    'bootstrap_rtt_micros': 70_000, 'min_rtt_micros': 1000, 'max_rtt_micros': 2_000_000,
    'headroom_percent': 125, 'minimum_bytes': 3200, 'max_inflight_bytes': 4 * 1024 * 1024,
    'max_records': 8192, 'metadata_limit_bytes': 2 * 1024 * 1024,
    'sample_ttl_micros': 4_000_000, 'flush_timeout_micros': 10_000_000,
}


def delivery_options():
    return ['--delivery-window', 'bdp',
            '--forward-mbps', str(DELIVERY_POLICY['forward_bandwidth_bps'] // 1_000_000),
            '--reverse-mbps', str(DELIVERY_POLICY['reverse_bandwidth_bps'] // 1_000_000),
            '--bootstrap-rtt-ms', str(DELIVERY_POLICY['bootstrap_rtt_micros'] // 1000),
            '--bdp-headroom-percent', str(DELIVERY_POLICY['headroom_percent']),
            '--inflight-max-bytes', str(DELIVERY_POLICY['max_inflight_bytes']),
            '--inflight-max-records', str(DELIVERY_POLICY['max_records'])]


def packed_config(layer, duplex, carrier, mtu, cover, protection, fec, settings):
    return {'version': 2, 'delivery': dict(DELIVERY_POLICY), 'layer': 'tun' if layer == 'tun' else 'tap', 'duplex': duplex,
            'carrier': carrier, 'path_mtu': mtu, 'max_packet': 1600, **settings,
            'fec_sources': fec[0], 'fec_repairs': fec[1], 'fec_flush_ms': fec[2],
            'cover': cover if carrier == 'udp' else None,
            'protection': protection if carrier == 'udp' else None}


def packed_options(settings):
    return ['--record-profile', 'packed', '--packed-channels', str(settings['channels']),
            '--packed-hold-micros', str(settings['hold_micros']),
            '--packed-max-units', str(settings['max_units']), '--packed-work-limit', str(settings['work_limit'])]


def validate_packed_entry(binary, auditor, build_path):
    """Packed apply executes only the reviewed immutable BUILD/tools tree."""
    base = build_path.resolve().parent
    script = Path(__file__)
    if ROOT.resolve() != base or script.resolve() != base / 'tools/native_smoke.py':
        raise ValueError('packed apply must execute the immutable BUILD/tools/native_smoke.py entry')
    if (base / 'tools').is_symlink() or not (base / 'tools').is_dir():
        raise ValueError('immutable helper directory must be a real directory')
    files = [script, build_path, binary, auditor] + [base / 'tools' / name for name in PACKED_HELPERS]
    if any(path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode) for path in files):
        raise ValueError('immutable build inputs must be regular non-symlink files')
    if any(path.resolve().parent != base for path in (binary, auditor)):
        raise ValueError('daemon and auditor must belong to the same immutable build')


def packed_snapshot(binary, auditor, build_path, output):
    # Materialize optional Python modules before checking their source hashes;
    # later calls use the already loaded code rather than a fresh lazy import.
    burst.strict_json('{}')
    build = packed_shared.verified_build_receipt(build_path, binary)
    if build.get('packed_auditor_sha256') != packed_shared.file_hash(auditor):
        raise ValueError('packed auditor build hash mismatch')
    before = {name: packed_shared.file_hash(ROOT / 'tools' / name) for name in PACKED_HELPERS}
    if any(build['source_sha256_after'].get('tools/' + name) != digest for name, digest in before.items()):
        raise ValueError('packed helper does not match reviewed build source map')
    for source, target in ((binary, output / 'l2tunneld-tested'), (auditor, output / 'packed_capture_audit'),
                           (build_path, output / 'build-receipt.json')):
        if target.exists(): raise FileExistsError(target)
        shutil.copyfile(source, target)
    for name in PACKED_HELPERS:
        shutil.copyfile(ROOT / 'tools' / name, output / name)
    for name in ('l2tunneld-tested', 'packed_capture_audit'):
        (output / name).chmod(0o755)
    if (before != {name: packed_shared.file_hash(ROOT / 'tools' / name) for name in PACKED_HELPERS}
            or before != {name: packed_shared.file_hash(output / name) for name in PACKED_HELPERS}
            or packed_shared.verified_build_receipt(output / 'build-receipt.json', output / 'l2tunneld-tested') != build
            or packed_shared.file_hash(output / 'packed_capture_audit') != build['packed_auditor_sha256']):
        raise ValueError('packed immutable snapshot changed')
    return {'build_receipt_sha256': packed_shared.file_hash(output / 'build-receipt.json'),
            'packed_auditor_sha256': build['packed_auditor_sha256'], 'helper_sha256': before,
            'source_sha256': build['source_sha256_after']}


def invoke_packed_auditor(auditor, operation, config, result_path, input_path=None):
    """The reviewed helper is still bounded by bytes and one original local deadline."""
    argv = [str(auditor), operation, '--config', str(config)]
    if input_path is not None: argv += ['--input', str(input_path)]
    end = time.monotonic() + 15
    with result_path.open('xb') as stream:
        process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                                   preexec_fn=packed_shared.limited_child(8192))
        try:
            code = process.wait(timeout=packed_shared.remaining(end, 15))
            packed_shared.remaining(end, 15)
        finally:
            if process.poll() is None: packed_shared.stop(process)
    with result_path.open('rb') as stream: raw = stream.read(8193)
    if len(raw) > 8192 or code != 0:
        raise ValueError('packed auditor failed or exceeded bounded output: ' + raw[:1024].decode(errors='replace'))
    value = burst.strict_json(raw)
    if not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1 or value.get('status') != 'passed':
        raise ValueError('packed auditor result envelope')
    if operation == 'audit':
        keys = {'sources', 'multi_unit_sources', 'complete_packet_aggregation_sources', 'max_units',
                'direct_copies', 'systematic_copies', 'repair_packets', 'duplicate_sources', 'direction'}
        if set(value) != {'version', 'status', 'scope', 'directions'} or value['scope'] != 'structural-only' or not isinstance(value['directions'], list) or len(value['directions']) != 2:
            raise ValueError('packed audit must be explicitly structural-only and bidirectional')
        for direction, row in enumerate(value['directions']):
            if not isinstance(row, dict) or set(row) != keys or any(type(n) is not int or not 0 <= n < 2**64 for n in row.values()):
                raise ValueError('packed audit direction counters')
            if row['direction'] != direction: raise ValueError('packed audit direction order')
            if not 0 < row['complete_packet_aggregation_sources'] <= row['multi_unit_sources'] <= row['sources'] or not 2 <= row['max_units'] <= 255:
                raise ValueError('both directions require distinct complete native packet aggregation')
    else:
        geometry_keys = {'underlay_ip_version', 'outer_overhead_bytes', 'udp_payload_ceiling',
                         'recovery_packet_ceiling', 'recovery_source_bytes', 'fec_source_bytes',
                         'fec_packet_ceiling', 'packed_header_bytes', 'record_id_bytes', 'symbol_bytes',
                         'channels', 'max_units', 'max_fragments_per_record', 'native_queue_packets', 'native_queue_bytes'}
        if (set(value) != {'version', 'status', 'scope', 'geometry'} or value['scope'] != 'configuration-only'
                or not isinstance(value['geometry'], dict) or set(value['geometry']) != geometry_keys
                or any(type(n) is not int or not 0 < n < 2**64 for n in value['geometry'].values())
                or value['geometry']['underlay_ip_version'] != 4):
            raise ValueError('packed validation-only geometry schema')
    return value


def packed_capture_records(data: bytes, mtu: int, duplex: str, carrier: str = 'udp'):
    """Exact Ethernet/IPv4/UDP parsing; no payload magic or authentication claim."""
    if len(data) >= PACKED_CAPTURE_BYTES or len(data) < 24:
        raise ValueError('pcap byte bound/header')
    magic = {b'\xd4\xc3\xb2\xa1': ('<', 1_000_000), b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
             b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000), b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000)}
    if data[:4] not in magic: raise ValueError('unsupported pcap format')
    endian, fraction_limit = magic[data[:4]]
    major, minor, zone, accuracy, snaplen, network = struct.unpack_from(endian + 'HHiiii', data, 4)
    if (major, minor, zone, accuracy, network) != (2, 4, 0, 0, 1) or not 1 <= snaplen <= 262144:
        raise ValueError('unsupported pcap geometry')
    if duplex not in ('half', 'full'): raise ValueError('duplex')
    ports = {24440, 24441} if duplex == 'half' else {24440}
    if carrier not in ('udp', 'quic'): raise ValueError('unsupported packed carrier')
    expected_lanes = ({(24440, 0), (24441, 1)} if carrier == 'udp' and duplex == 'half'
                      else {(port, direction) for port in ports for direction in (0, 1)})
    ips = {ipaddress.IPv4Address('192.0.2.2').packed: 0, ipaddress.IPv4Address('192.0.2.6').packed: 1}
    offset, count, maximum = 24, 0, 0
    result = bytearray()
    lanes = set()
    while offset < len(data):
        if len(data) - offset < 16: raise ValueError('truncated pcap record')
        _, fraction, included, original = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        if fraction >= fraction_limit or included != original or included > snaplen or included < 42 or included > len(data) - offset:
            raise ValueError('truncated or invalid pcap frame')
        packet = data[offset:offset + included]; offset += included
        count += 1
        if count >= PACKED_CAPTURE_PACKETS: raise ValueError('capture packet cap reached')
        if packet[12:14] != b'\x08\x00': raise ValueError('expected untagged IPv4 underlay')
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], 'big')
        if ip[0] >> 4 != 4 or ihl < 20 or total != len(ip) or total < ihl + 8 or total > mtu or ip[9] != 17 or int.from_bytes(ip[6:8], 'big') & 0xbfff:
            raise ValueError('invalid IP length, protocol, MTU or fragmentation')
        origin, destination = ip[12:16], ip[16:20]
        if origin not in ips or destination not in ips or origin == destination:
            raise ValueError('unexpected outer IP tuple')
        udp = ip[ihl:]
        source, target, length, _ = struct.unpack_from('!HHHH', udp)
        if source != target or (source, ips[origin]) not in expected_lanes or length != len(udp) or length <= 8:
            raise ValueError('unexpected lane or UDP length')
        payload = udp[8:]
        if len(payload) > 65535: raise ValueError('UDP payload length')
        result.extend(struct.pack('!HBB', len(payload), ips[origin], 0)); result.extend(payload)
        if len(result) > 8 * 1024 * 1024: raise ValueError('auditor input byte bound')
        lanes.add((source, ips[origin])); maximum = max(maximum, total)
    if lanes != expected_lanes:
        raise ValueError('capture lacks a complete bidirectional lane sample')
    return bytes(result), {'packets': count, 'maximum_ip_bytes': maximum,
                           'carrier': carrier, 'duplex': duplex,
                           'expected_lane_directions': sorted([list(pair) for pair in expected_lanes]),
                           'scope': 'exact outer framing only; no cryptographic verification'}


def packed_underlay(spec, mtu):
    end = time.monotonic() + 60
    evidence = {}
    for role, interface in [('endpoint_a', 'wan0'), ('endpoint_b', 'wan0'), ('router', 'a0'), ('router', 'b0')]:
        namespace = spec.namespaces[role]
        packed_shared.command(['ip', '-n', namespace, 'link', 'set', interface, 'mtu', str(mtu)], end)
        features = packed_shared.offloads(namespace, interface, end)
        link = burst.strict_json(packed_shared.command(['ip', '-n', namespace, '-j', 'link', 'show', interface], end))
        if not isinstance(link, list) or len(link) != 1 or link[0].get('mtu') != mtu:
            raise ValueError('effective physical MTU mismatch')
        evidence[role + '/' + interface] = {'link': link, 'offloads': features}
    return evidence


def validate_burst_results(results, record, reap_end):
    """Both directions share one cutoff and one result-only reaping allowance."""
    if set(results) != {'send-0', 'send-1', 'receive-0', 'receive-1'} or reap_end != record['observation_end_ns'] + burst.REAP_NS:
        raise ValueError('burst result set/fence mismatch')
    for key, row in results.items():
        kind, direction = key.split('-'); direction = int(direction)
        fields = {'version', 'status', 'kind', 'direction', 'count', 'bytes', 'sha256', 'started_ns', 'observation_end_ns'}
        fields |= {'completed_ns'} if kind == 'send' else {'last_packet_ns', 'observed_until_ns'}
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError('burst result schema')
        integers = fields - {'status', 'kind', 'sha256'}
        if any(type(row[name]) is not int or not 0 <= row[name] < 2**63 for name in integers):
            raise ValueError('burst result integer bound')
        if (row['version'], row['status'], row['kind'], row['direction'], row['count'], row['bytes'], row['sha256']) != (1, 'passed', kind, direction, 64, 4096, burst.expected_hash(direction)):
            raise ValueError('burst count/content/direction mismatch')
        if any(row[name] != record[name] for name in ('started_ns', 'observation_end_ns')):
            raise ValueError('burst original deadline changed')
        packet_end = row['completed_ns'] if kind == 'send' else row['last_packet_ns']
        if not record['started_ns'] <= packet_end < record['observation_end_ns']:
            raise ValueError('packet IO completed outside observation')
        if kind == 'receive' and not record['observation_end_ns'] <= row['observed_until_ns'] < reap_end:
            raise ValueError('receiver exited early or exceeded result-only reaping')


def run_packed_burst(spec, layer, output, secrets, name, evidence):
    subnet = {'tap': '198.18.0.', 'tun': '198.19.0.', 'vxlan': '198.20.0.'}[layer]
    origins = {side: spec.namespaces[('endpoint_' if layer == 'tun' else 'host_') + side] for side in ('a', 'b')}
    start_path = secrets / (name + '-burst-start.json')
    setup_end = time.monotonic_ns() + 5_000_000_000
    processes, streams, paths, readiness = {}, [], {}, {}
    results, record, reap_end = {}, None, None
    cleanup_errors = []
    def launch(kind, direction, setup):
        sender = 'a' if direction == 0 else 'b'; receiver = 'b' if direction == 0 else 'a'
        side = sender if kind == 'send' else receiver
        source = subnet + ('1' if sender == 'a' else '2') + ':' + str(25000 + direction)
        destination = subnet + ('1' if receiver == 'a' else '2') + ':' + str(25010 + direction)
        key = f'{kind}-{direction}'
        ready = secrets / (name + '-' + key + '.ready')
        argv = ['ip', 'netns', 'exec', origins[side], sys.executable, str(output / 'udp_burst_probe.py'), kind,
                '--bind', source if kind == 'send' else destination, '--peer', destination if kind == 'send' else source,
                '--direction', str(direction), '--start', str(start_path), '--setup-deadline-ns', str(setup)]
        if kind == 'receive': argv += ['--ready', str(ready)]
        path = output / (name + '-' + key + '.json'); paths[key] = path
        stream = path.open('xb'); streams.append(stream)
        process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                                   preexec_fn=packed_shared.limited_child(8192))
        processes[key] = process
        if kind == 'receive':
            readiness[key] = (ready, {'version': 1, 'bind': list(burst.endpoint(destination)),
                                    'peer': list(burst.endpoint(source)), 'direction': direction})
    try:
        for direction in (0, 1): launch('receive', direction, setup_end)
        pending = dict(readiness)
        while pending:
            burst.remaining_ns(setup_end)
            for key, (path, expected) in list(pending.items()):
                if processes[key].poll() is not None: raise RuntimeError('burst receiver exited before readiness')
                if path.exists():
                    with path.open('rb') as stream: raw = stream.read(8193)
                    if len(raw) > 8192 or burst.strict_json(raw) != expected: raise ValueError('burst actual bind readiness mismatch')
                    del pending[key]
            if pending: time.sleep(min(.001, burst.remaining_ns(setup_end)))
        burst.remaining_ns(setup_end)
        t0 = time.monotonic_ns(); record = {'version': 1, 'started_ns': t0, 'observation_end_ns': t0 + burst.OBSERVATION_NS}
        reap_end = record['observation_end_ns'] + burst.REAP_NS
        temporary = start_path.with_suffix('.tmp')
        with temporary.open('x') as stream: json.dump(record, stream)
        os.replace(temporary, start_path)
        evidence.record('packed_burst', {'status': 'running', 'readiness_end_ns': setup_end, **record, 'reap_end_ns': reap_end})
        for direction in (0, 1): launch('send', direction, record['observation_end_ns'])
        # Poll all helpers together; no slow peer grants another peer more time.
        while any(process.poll() is None for process in processes.values()):
            burst.remaining_ns(reap_end)
            for process in processes.values():
                if process.poll() not in (None, 0): raise RuntimeError('burst helper reported failure')
            time.sleep(min(.001, burst.remaining_ns(reap_end)))
        burst.remaining_ns(reap_end)
        for key, process in processes.items():
            if process.returncode != 0: raise RuntimeError('burst helper nonzero exit')
            with paths[key].open('rb') as stream: raw = stream.read(8193)
            if len(raw) > 8192: raise ValueError('burst result byte bound')
            results[key] = burst.strict_json(raw)
        validate_burst_results(results, record, reap_end)
        burst.remaining_ns(reap_end)
        value = {'status': 'passed', 'readiness_end_ns': setup_end, **record, 'reap_end_ns': reap_end,
                 'reaped_at_ns': time.monotonic_ns(), 'results': results}
        evidence.record('packed_burst', value)
        return value
    finally:
        for key, process in processes.items():
            try: packed_shared.stop(process)
            except Exception as error: cleanup_errors.append({'helper': key, 'error': str(error)[:512]})
        for stream in streams: stream.close()
        evidence.record('packed_burst_cleanup', {'errors': cleanup_errors, 'exit_codes': {key: process.poll() for key, process in processes.items()}})
        if cleanup_errors: raise RuntimeError('burst helper cleanup incomplete')


def run_case(spec: netns_lab.LabSpec, binary: Path, secrets: Path, output: Path,
             layer: str, duplex: str, impaired: bool, compression: str, hot_switch: bool,
             carrier: str = 'tcp', udp_cover: str = 'quic-like', udp_protection: str = 'aead', path_mtu: int = 1500,
             traffic: str = 'system', fec: tuple[int, int, int] | None = None,
             flow_churn: bool = False, adaptive: bool = False, active_policy_switch: bool = False, active_transfer_timeout: int = 60, active_switch_timing: str = 'default', active_progress: bool = False, record_profile: str = 'frame', aligned_channels: int | None = None, path_probe: str = 'original-2s', packed: dict | None = None, packed_auditor: Path | None = None, tcp_family: int = 4) -> dict:
    if tcp_family not in (4, 6):
        raise ValueError('TCP probe family must be 4 or 6')
    ns = spec.namespaces
    name = case_name(layer, duplex, impaired, path_probe)
    for side in ('a', 'b'):
        command(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], 'tc', 'qdisc', 'change',
                 'dev', 'wan0', 'parent', '1:10', 'handle', '10:', 'netem', 'limit', '1000',
                 'delay', '35ms' if impaired else '1ms', 'loss', 'random', '15%' if impaired else '0%'])
    server_log = output / f'{name}-server.log'
    client_log = output / f'{name}-client.log'
    device = 'tap0' if layer == 'tap' else 'tun0'
    common = ['--layer', 'tap' if layer == 'vxlan' else layer, '--duplex', duplex, '--compression', compression]
    if record_profile == 'packed':
        if packed is None or packed_auditor is None: raise ValueError('packed runtime preflight missing')
        common.extend(packed_options(packed))
    if record_profile == 'aligned':
        common.extend(['--record-profile', 'aligned', '--aligned-channels', str(aligned_channels)])
    if record_profile in ('aligned', 'packed'):
        common.extend(delivery_options())
    if traffic == 'active':
        common.extend(['--traffic', 'active', '--active-stats-ms', '250'])
    if active_policy_switch:
        common.extend(['--mux-channels', '4', '--active-policies', str(secrets / 'active-policies.json')])
    if adaptive:
        common.extend(['--adaptive', 'on'])
    if flow_churn:
        common.extend(['--max-flows', '2', '--flow-idle-ms', '100'])
    if carrier == 'udp':
        common.extend(['--carrier', 'udp', '--udp-cover', udp_cover, '--udp-protection', udp_protection, '--path-mtu', str(path_mtu)])
    if carrier == 'quic':
        # Ephemeral lab-owned identifier; no fixed tunnel ALPN default in clients.
        common.extend(['--carrier', 'quic', '--quic-application-id', (secrets / 'application-id').read_text().strip(), '--path-mtu', str(path_mtu)])
    if carrier == 'openvpn-like':
        common.extend(['--carrier', 'openvpn-like', '--udp-protection', udp_protection,
                       '--path-mtu', str(path_mtu), '--openvpn-stats-ms', '250',
                       '--admission-key-file', str(secrets / 'admission.raw')])
    if carrier in ('udp', 'quic', 'openvpn-like'):
        if fec is not None:
            common.extend(['--fec', 'cauchy', '--fec-sources', str(fec[0]), '--fec-repairs', str(fec[1]), '--fec-flush-ms', str(fec[2])])
    if layer == 'vxlan':
        server_device = ['--vxlan-bind', '198.18.0.20:4789', '--vxlan-peer', '198.18.0.2:4789', '--vni', '42']
        client_device = ['--vxlan-bind', '198.18.0.10:4789', '--vxlan-peer', '198.18.0.1:4789', '--vni', '42']
    else:
        server_device = client_device = ['--device', device]
    subnet = {'tap': '198.18.0.', 'tun': '198.19.0.', 'vxlan': '198.20.0.'}[layer]
    subnet6 = {'tap': 'fd42:12:18::', 'tun': 'fd42:12:19::', 'vxlan': 'fd42:12:20::'}[layer]
    listener_address = '192.0.2.6:24440' if carrier == 'quic' else '192.0.2.6:18443'
    server_argv = ['ip', 'netns', 'exec', ns['endpoint_b'], str(binary), 'serve',
                   '--listen', listener_address, '--cert', str(secrets / 'cert.der'),
                   '--key', str(secrets / 'server.der'), '--allow-key', str(secrets / 'member.pub'), *common, *server_device]
    client_argv = ['ip', 'netns', 'exec', ns['endpoint_a'], str(binary), 'connect',
                   '--remote', listener_address, '--ca', str(secrets / 'cert.der'),
                   '--server-name', 'lab.invalid', '--identity', str(secrets / 'member.der'), *common, *client_device]
    if carrier == 'openvpn-like':
        for argv, option in ((server_argv, '--listen'), (client_argv, '--remote')):
            index = argv.index(option)
            del argv[index:index + 2]
        server_argv.extend(['--cookie-key-file', str(secrets / 'cookie.raw')])
    if carrier in ('udp', 'quic', 'openvpn-like'):
        for argv, local, peer in [(client_argv, '192.0.2.2', '192.0.2.6'),
                                  (server_argv, '192.0.2.6', '192.0.2.2')]:
            argv.extend(['--udp-bind', local + ':24440', '--udp-peer', peer + ':24440'])
            if duplex == 'half':
                argv.extend(['--udp-reverse-bind', local + ':24441', '--udp-reverse-peer', peer + ':24441'])
    sockets = [secrets / f'{name}-client.sock', secrets / f'{name}-server.sock']
    if hot_switch or active_policy_switch:
        client_argv.extend(['--control-socket', str(sockets[0])])
        server_argv.extend(['--control-socket', str(sockets[1])])
    started = time.monotonic()
    evidence = CaseEvidence(output / f'{name}-partial.json', name)
    def stage(value: str) -> None:
        evidence.update(stage=value, elapsed_seconds=time.monotonic() - started)
        (output / f'{name}-stage.json').write_text(json.dumps({'case': name, 'stage': value, 'elapsed_seconds': time.monotonic() - started}) + '\n')
    stage('underlay_setup')
    processes = []
    udp_captures = []
    owned_clsact = []
    tcp_disabled = {}
    udp_binding = {}
    packed_capture_logs = {}
    completed_packed_captures = set()
    burst_result = None
    def start_packed_capture(side):
        endpoint = ['ip', 'netns', 'exec', ns[f'endpoint_{side}']]
        path = output / f'{name}-underlay-{side}.pcap'
        diagnostic = output / f'{name}-capture-{side}.log'
        capture = packed_shared.start_capture([*endpoint, 'tcpdump', '-U', '-n', '-i', 'wan0', '-s', '0', '-c', str(PACKED_CAPTURE_PACKETS), '-w', str(path), 'udp and (port 24440 or port 24441)'], diagnostic, time.monotonic() + 5)
        processes.append(capture); udp_captures.append((side, capture, path)); packed_capture_logs[side] = diagnostic
        evidence.record('packed_capture_ready', {key: value.name for key, value in packed_capture_logs.items()})
    try:
        if carrier in ('quic', 'openvpn-like'):
            for side, peer in [('a', '192.0.2.6'), ('b', '192.0.2.2')]:
                endpoint = ['ip', 'netns', 'exec', ns[f'endpoint_{side}']]
                command([*endpoint, 'tc', 'qdisc', 'add', 'dev', 'wan0', 'clsact'])
                owned_clsact.append(endpoint)
                command([*endpoint, 'tc', 'filter', 'add', 'dev', 'wan0', 'egress', 'protocol', 'ip', 'pref', '1', 'u32', 'match', 'ip', 'protocol', '6', '0xff', 'action', 'drop'])
                proof = command([*endpoint, 'python3', '-c', 'import socket,sys\ns=socket.socket(); s.settimeout(0.3)\ntry: s.connect((sys.argv[1],24440))\nexcept TimeoutError: print("TCP blocked by timeout")\nelse: raise RuntimeError("TCP unexpectedly reachable")\nfinally: s.close()', peer])
                tcp_disabled[side] = {'probe': proof, 'filter': command([*endpoint, 'tc', '-s', 'filter', 'show', 'dev', 'wan0', 'egress', 'pref', '1'])}
                tcp_disabled[side]['offloads'] = command([*endpoint, 'ethtool', '-k', 'wan0'])
                tcp_disabled[side]['link'] = command(['ip', '-n', ns[f'endpoint_{side}'], '-j', 'link', 'show', 'wan0'])
                if not any(int(count) > 0 for count in re.findall(r'dropped\s+(\d+)', tcp_disabled[side]['filter'])):
                    raise RuntimeError('TCP-block filter has no observed dropped SYN')
                evidence.record('tcp_disabled', tcp_disabled)
                if record_profile == 'packed':
                    start_packed_capture(side)
                else:
                    capture_path = output / f'{name}-underlay-{side}.pcap'
                    capture = subprocess.Popen([*endpoint, 'tcpdump', '-U', '-n', '-i', 'wan0', '-s', '0', '-c', '4096', '-w', str(capture_path), 'udp and (port 24440 or port 24441)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    processes.append(capture)
                    udp_captures.append((side, capture, capture_path))
                    evidence.record('capture_started', {which: path.name for which, _, path in udp_captures})
            if record_profile != 'packed': time.sleep(0.2)
        if record_profile == 'packed' and carrier == 'udp':
            for side in ('a', 'b'): start_packed_capture(side)
        with server_log.open('w') as server_out, client_log.open('w') as client_out:
            stage('authenticate_fixed_endpoints')
            server = subprocess.Popen(server_argv, stdout=server_out, stderr=subprocess.STDOUT)
            processes.append(server)
            if carrier == 'openvpn-like':
                udp_binding['server'] = wait_udp_bound(server, server_log, ns['endpoint_b'],
                                                       '192.0.2.6', [24440, 24441] if duplex == 'half' else [24440])
                evidence.record('udp_binding', udp_binding)
            else:
                wait_log(server, server_log, 'Listening', 5)
            client = subprocess.Popen(client_argv, stdout=client_out, stderr=subprocess.STDOUT)
            processes.append(client)
            wait_log(client, client_log, 'Authenticated')
            wait_log(server, server_log, 'Authenticated')
            evidence.record('authentication', {side: next(line for line in path.read_text().splitlines() if 'Authenticated' in line)
                                               for side, path in [('client', client_log), ('server', server_log)]})
            if traffic == 'active':
                for process, log in ((client, client_log), (server, server_log)):
                    wait_log(process, log, 'managed active TUN policy catalog' if active_policy_switch else 'transparent TUN active credits')
            if fec is not None:
                for process, log in ((client, client_log), (server, server_log)):
                    wait_log(process, log, 'recovery Cauchy')
            if record_profile == 'packed':
                marker = f"record-profile packed; channels {packed['channels']}; hold {packed['hold_micros']} us; maximum units {packed['max_units']}; work limit {packed['work_limit']}"
                for process, log in ((client, client_log), (server, server_log)):
                    wait_log(process, log, marker)
                evidence.record('packed_selection', {'settings': packed, 'startup_marker': marker})
            if record_profile == 'aligned':
                for process, log in ((client, client_log), (server, server_log)):
                    wait_log(process, log, f'record-profile aligned; CRC MUX channels {aligned_channels}; recovery Cauchy')
            switches = []
            follower_rejection = None
            if hot_switch:
                wait_states(binary, sockets, 1, compression)
            if active_policy_switch:
                wait_active_states(binary, sockets, 1, compression, active_policy(4))
                follower_rejection = switch_active(binary, sockets[1], active_policy(2, True), rejected=True)
                wait_active_states(binary, sockets, 1, compression, active_policy(4))
            if carrier == 'udp' and record_profile != 'packed':
                for side in ('a', 'b'):
                    capture_path = output / f'{name}-underlay-{side}.pcap'
                    capture = subprocess.Popen(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], 'tcpdump', '-U', '-n', '-i', 'wan0', '-s', '0', '-c', '4096', '-w', str(capture_path), 'udp and (port 24440 or port 24441)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    processes.append(capture)
                    udp_captures.append((side, capture, capture_path))
                    evidence.record('capture_started', {which: path.name for which, _, path in udp_captures})
                time.sleep(0.2)
            if layer == 'vxlan':
                for side in ('a', 'b'):
                    capture = subprocess.Popen(['ip', 'netns', 'exec', ns[f'host_{side}'], 'tcpdump', '-U', '-n', '-i', 'vx0', '-s', '0', '-c', '4096', '-w', str(output / f'{name}-{side}.pcap')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    processes.append(capture)
                time.sleep(0.2)
            ping_results = []
            stage('native_ipv4_probes')
            for side, address in [('a', subnet + '2'),
                                  ('b', subnet + '1')]:
                origin = ns[f'host_{side}' if layer != 'tun' else f'endpoint_{side}']
                for size in (56, 1200):
                    for attempt in range(3):
                        # iputils may exit a multi-probe run after two measured RTTs,
                        # even with -W. Single probes have no earlier RTT sample and
                        # wait the complete explicit timeout for their one reply.
                        argv = ['ip', 'netns', 'exec', origin, 'ping', '-n', '-c', '1', '-W', '30', '-s', str(size), address]
                        result = command(argv, timeout=35)
                        verify_ping(result, expected=1)
                        ping_results.append({'origin': origin, 'destination': address, 'payload_bytes': size, 'attempt': attempt, 'stdout': result})
                        evidence.record('ipv4_probes', ping_results)
            # A finite native TCP flow exercises endpoint TCP through the tunnel.
            stage('native_tcp_payload')
            source = ns['host_a' if layer != 'tun' else 'endpoint_a']
            destination = ns['host_b' if layer != 'tun' else 'endpoint_b']
            address = (subnet if tcp_family == 4 else subnet6) + '2'
            tcp_options = ['--family', str(tcp_family)]
            tcp_log = output / f'{name}-tcp.log'
            with tcp_log.open('w') as tcp_output:
                tcp_server = subprocess.Popen(['ip', 'netns', 'exec', destination, 'python3', str(output / 'tcp_probe.py'), 'listen', address, *tcp_options] + (['--progress'] if active_progress else []), stdout=tcp_output, stderr=subprocess.STDOUT)
                processes.append(tcp_server)
                wait_log(tcp_server, tcp_log, 'Listening', 5)
                sender = ['ip', 'netns', 'exec', source, 'python3', str(output / 'tcp_probe.py'), 'send', address, *tcp_options] + (['--progress', '--progress-file', str(output / f'{name}-tcp-progress.jsonl')] if active_progress else [])
                if hot_switch or active_policy_switch:
                    marker = output / f'{name}-tcp-started'
                    tcp_client_log = output / f'{name}-tcp-client.log'
                    with tcp_client_log.open('w') as tcp_client_output:
                        transfer_deadline = time.monotonic() + active_transfer_timeout
                        tcp_client = subprocess.Popen([*sender, '--bytes', '524288', '--chunk-delay', '0.05', '--started-file', str(marker)], stdout=tcp_client_output, stderr=subprocess.STDOUT)
                        processes.append(tcp_client)
                        deadline = min(time.monotonic() + 30, transfer_deadline)
                        while not marker.exists():
                            if tcp_client.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError(f'TCP transfer did not start: {tcp_client_log.read_text()}')
                            time.sleep(0.02)
                        targets = [(2, active_policy(2, True)), (3, active_policy(4))] if active_policy_switch else [(2, 'lz4' if compression == 'off' else 'off'), (3, compression)]
                        for epoch, target in targets:
                            if tcp_client.poll() is not None:
                                raise RuntimeError('TCP transfer ended before hot-switch request')
                            if active_policy_switch:
                                response = switch_active(binary, sockets[0], target, timeout=remaining(transfer_deadline, 70))
                                states = wait_active_states(binary, sockets, epoch, compression, target, overall_deadline=transfer_deadline)
                                switches.append({'epoch': epoch, 'policy': target, 'request': response, 'peers': states})
                            else:
                                response = control(binary, sockets[0], 'set-compression', target)
                                states = wait_states(binary, sockets, epoch, target)
                                switches.append({'epoch': epoch, 'compression': target, 'request': response, 'peers': states})
                        if tcp_client.wait(timeout=remaining(transfer_deadline, active_transfer_timeout) if active_policy_switch else 60) != 0:
                            raise RuntimeError(f'concurrent TCP transfer failed: {tcp_client_log.read_text()}')
                    tcp_result = tcp_client_log.read_text()
                else:
                    tcp_result = command(sender, timeout=50)
                evidence.record('tcp_sender_stdout', tcp_result)
                if tcp_server.wait(timeout=5) != 0:
                    raise RuntimeError(f'TCP probe server failed: {tcp_log.read_text()}')
                tcp_payload = json.loads(tcp_result)
                verify_tcp_payload(tcp_payload, tcp_family, 524288 if hot_switch or active_policy_switch else 65536)
                evidence.record('tcp_payload', tcp_payload)
            ipv6_results = []
            stage('native_ipv6_probes')
            for side, address in [('a', subnet6 + '2'), ('b', subnet6 + '1')]:
                origin = ns[f'host_{side}' if layer != 'tun' else f'endpoint_{side}']
                for attempt in range(3):
                    result = command(['ip', 'netns', 'exec', origin, 'ping', '-6', '-n', '-c', '1', '-W', '30', '-s', '1200', address], timeout=35)
                    verify_ping(result, expected=1)
                    ipv6_results.append({'origin': origin, 'destination': address, 'attempt': attempt, 'stdout': result})
                    evidence.record('ipv6_probes', ipv6_results)
            if record_profile == 'packed':
                stage('native_packed_burst')
                burst_result = run_packed_burst(spec, layer, output, secrets, name, evidence)
            udp_path_check = None
            churn_result = None
            if flow_churn:
                churn_log = output / f'{name}-churn.log'
                # Cases reuse the same namespaces; unique source-port ranges
                # avoid reusing an earlier case's TIME_WAIT tuple.
                churn_port = 31200 if impaired else (31100 if duplex == 'full' else 31000)
                with churn_log.open('w') as churn_output:
                    churn_server = subprocess.Popen(['ip', 'netns', 'exec', destination,
                        'python3', str(output / 'flow_churn_probe.py'), 'listen', subnet + '2',
                        '--source-port', str(churn_port)],
                        stdout=churn_output, stderr=subprocess.STDOUT)
                    processes.append(churn_server)
                    wait_log(churn_server, churn_log, 'Listening', 5)
                    churn_result = json.loads(command(['ip', 'netns', 'exec', source,
                        'python3', str(output / 'flow_churn_probe.py'), 'send', subnet + '2',
                        '--source-address', subnet + '1', '--source-port', str(churn_port)], timeout=180))
                    if churn_server.wait(timeout=10) != 0:
                        raise RuntimeError(f'flow churn receiver failed: {churn_log.read_text()}')
                    if churn_result['status'] != 'passed' or len(churn_result['flows']) != 12:
                        raise RuntimeError('flow churn did not complete all twelve distinct flows')
            if carrier == 'openvpn-like' and path_probe != 'original-2s':
                stage(f'udp_{path_probe}')
                udp_path_check = standalone_outage(path_probe, ns, source, subnet + '2',
                    {'a': (client, client_log), 'b': (server, server_log)}, evidence, started)
                if path_probe == 'short-recovery':
                    stage('udp_restoration_probe')
                    restored = command(['ip', 'netns', 'exec', source, 'ping', '-n', '-c', '1', '-W', '30', subnet + '2'], timeout=35)
                    verify_ping(restored, expected=1)
                    if server.poll() is not None or client.poll() is not None:
                        raise RuntimeError('endpoint exited during short recovery restoration')
                    udp_path_check['restored_probe'] = restored
                    evidence.record('udp_path_check', udp_path_check)
            elif carrier in ('udp', 'quic', 'openvpn-like'):
                stage('udp_negative_path_probe')
                # Prove that native packets depend on UDP while authenticated TCP
                # control remains established. The filter exists only in our lab.
                endpoint = ['ip', 'netns', 'exec', ns['endpoint_a']]
                if carrier == 'udp':
                    command([*endpoint, 'tc', 'qdisc', 'add', 'dev', 'wan0', 'clsact'])
                try:
                    command([*endpoint, 'tc', 'filter', 'add', 'dev', 'wan0', 'egress', 'protocol', 'ip', 'pref', '2', 'u32', 'match', 'ip', 'protocol', '17', '0xff', 'action', 'drop'])
                    blocked = subprocess.run(['ip', 'netns', 'exec', source, 'ping', '-n', '-c', '1', '-W', '2', subnet + '2'], capture_output=True, text=True, timeout=5)
                    if blocked.returncode != 1:
                        raise RuntimeError(f'UDP-blocked ping had an unexpected outcome: {blocked.stdout}{blocked.stderr}')
                    verify_blocked_ping(blocked.stdout)
                    if server.poll() is not None or client.poll() is not None:
                        raise RuntimeError('endpoint exited during isolated UDP path interruption')
                    control_sockets = command([*endpoint, 'ss', '-Htn', 'state', 'established'])
                    if carrier == 'udp' and len([line for line in control_sockets.splitlines() if ':18443' in line]) != (2 if duplex == 'half' else 1):
                        raise RuntimeError('retained TCP control sockets were not established during UDP interruption')
                    if carrier in ('quic', 'openvpn-like') and any('192.0.2.' in line for line in control_sockets.splitlines()):
                        raise RuntimeError('genuine QUIC unexpectedly has an established underlay TCP socket')
                    filter_stats = command([*endpoint, 'tc', '-s', 'filter', 'show', 'dev', 'wan0', 'egress', 'pref', '2'])
                    if not any(int(count) > 0 for count in re.findall(r'dropped\s+(\d+)', filter_stats)):
                        raise RuntimeError('owned UDP drop filter recorded no dropped packets')
                    udp_path_check = {'blocked_probe': blocked.stdout, 'tcp_control': control_sockets, 'drop_filter': filter_stats}
                    evidence.record('udp_path_check', udp_path_check)
                finally:
                    if carrier == 'udp':
                        command([*endpoint, 'tc', 'qdisc', 'del', 'dev', 'wan0', 'clsact'])
                    else:
                        command([*endpoint, 'tc', 'filter', 'del', 'dev', 'wan0', 'egress', 'pref', '2'])
                stage('udp_restoration_probe')
                restored = command(['ip', 'netns', 'exec', source, 'ping', '-n', '-c', '1', '-W', '30', subnet + '2'], timeout=35)
                verify_ping(restored, expected=1)
                udp_path_check['restored_probe'] = restored
                evidence.record('udp_path_check', udp_path_check)
            stats = {side: command(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], 'tc', '-s', 'qdisc', 'show', 'dev', 'wan0']) for side in ('a', 'b')}
            udp_evidence = {}
            stage('capture_and_runtime_evidence')
            for side, capture, capture_path in udp_captures:
                if record_profile == 'packed':
                    counts = packed_shared.finish_capture(capture, packed_capture_logs[side])
                    completed_packed_captures.add(side)
                    if counts['captured'] >= PACKED_CAPTURE_PACKETS: raise ValueError('packed capture count cap reached')
                    with capture_path.open('rb') as stream: data = stream.read(PACKED_CAPTURE_BYTES + 1)
                    records, framing = packed_capture_records(data, path_mtu, duplex, carrier)
                    if framing['packets'] != counts['captured']: raise ValueError('packed capture count mismatch')
                    sample = {'pcap': capture_path.name, 'pcap_sha256': hashlib.sha256(data).hexdigest(), 'counts': counts, 'framing': framing}
                    if carrier == 'udp' and udp_protection == 'integrity':
                        input_path = output / f'{name}-{side}-packed-records.bin'
                        with input_path.open('xb') as stream: stream.write(records)
                        sample['structural_audit'] = invoke_packed_auditor(packed_auditor, 'audit', output / f'{name}-packed-config.json', output / f'{name}-{side}-packed-audit.json', input_path)
                        sample['audit_input_sha256'] = hashlib.sha256(records).hexdigest()
                    else:
                        sample['structural_audit'] = {'status': 'unsupported', 'reason': 'AEAD/QUIC captures do not expose packed content'}
                    udp_evidence[side] = sample
                    evidence.record('udp_evidence', udp_evidence)
                    continue
                stop(capture)
                decoded = command(['tcpdump', '-n', '-r', str(capture_path)], timeout=10)
                packets = [line for line in decoded.splitlines() if 'UDP, length' in line]
                if not packets:
                    raise RuntimeError('no protected UDP data observed on configured underlay')
                udp_evidence[side] = {'pcap': capture_path.name, 'observed_udp_packets': len(packets),
                                      'pcap_sha256': hashlib.sha256(capture_path.read_bytes()).hexdigest()}
                if carrier == 'openvpn-like':
                    with capture_path.open('rb') as recorded:
                        udp_evidence[side]['audit'] = audit_openvpn_capture(recorded.read(64 * 1024 * 1024 + 1), path_mtu, duplex)
                evidence.record('udp_evidence', udp_evidence)
            offloads = {side: command(['ip', 'netns', 'exec', ns[f'host_{side}'], 'ethtool', '-k', 'vx0']) for side in ('a', 'b')} if layer == 'vxlan' else {}
            active_stats = {}
            standalone_stats = {}
            if carrier == 'openvpn-like':
                for side, path in [('a', client_log), ('b', server_log)]:
                    samples = [sample for sample in observation_snapshot(path.read_text()) if sample.get('kind') == 'openvpn_native_stats']
                    if not samples or max(sample['native_delivered'] for sample in samples) == 0 or max(sample['tls_messages'] for sample in samples) == 0:
                        raise RuntimeError('missing actual standalone native/TLS progress observations')
                    standalone_stats[side] = samples
            if traffic == 'active':
                for side, path in [('a', client_log), ('b', server_log)]:
                    samples = observation_snapshot(path.read_text())
                    active_stats[side] = [sample for sample in samples if sample.get('kind') == ('managed_active_stats' if active_policy_switch else 'active_stats')]
                    if not active_stats[side] or any(sample['adaptive'] != adaptive for sample in active_stats[side]):
                        raise RuntimeError('missing or mismatched active runtime observations')
                    if flow_churn and max(sample['retired_flows'] for sample in active_stats[side]) < 10:
                        raise RuntimeError('native churn lacks matching authenticated retirement observations')
            stage('passed')
            evidence.update(status='passed')
            return {'case': name, 'status': 'passed', 'layer': layer, 'duplex': duplex,
                    'compression': compression, 'netem_loss_percent': 15 if impaired else 0, 'base_rtt_ms': 70 if impaired else 2,
                    'elapsed_seconds': time.monotonic() - started, 'ping': ping_results, 'ipv6_ping': ipv6_results, 'tcp_payload': tcp_payload, 'tcp_family': tcp_family, 'qdisc': stats, 'vxlan_offloads': offloads,
                    'hot_switch': switches if hot_switch else [],
                    'active_policy_switch': switches if active_policy_switch else [],
                    'active_transaction': transaction_timing(active_switch_timing) if active_policy_switch else None,
                    'tcp_overall_completion_timeout_seconds': active_transfer_timeout if active_policy_switch else None,
                    'tcp_io_inactivity_timeout_seconds': 45,
                    'tcp_probe_protocol': 'progress32k-v1' if active_progress else 'final-checksum-v1',
                    'follower_rejection': follower_rejection,
                    'carrier': carrier, 'traffic': traffic, 'record_profile': record_profile,
                    'delivery': DELIVERY_POLICY if record_profile in ('aligned', 'packed') else None,
                    'aligned_channels': aligned_channels,
                    **({'packed': packed, 'packed_burst': burst_result} if record_profile == 'packed' else {}),
                    'flow_churn': churn_result,
                    'active_slots': 2 if flow_churn else None,
                    'flow_idle_ms': 100 if flow_churn else None,
                    'adaptive': adaptive, 'active_stats': active_stats,
                    'active_target_observations': {side: {'first': samples[0], 'last': samples[-1], 'min_target_bytes': min(sample['target_bytes'] for sample in samples), 'max_target_bytes': max(sample['target_bytes'] for sample in samples)} for side, samples in active_stats.items()},
                    'tcp_disabled': tcp_disabled,
                    'standalone_stats': standalone_stats, 'udp_binding': udp_binding,
                    'fec': None if fec is None else {'kind': 'cauchy', 'sources': fec[0], 'repairs': fec[1], 'flush_ms': fec[2]},
                    'udp_cover': udp_cover if carrier == 'udp' else None,
                    'udp_protection': udp_protection if carrier in ('udp', 'openvpn-like') else None,
                    'path_mtu': path_mtu if carrier in ('udp', 'quic', 'openvpn-like') else None, 'udp_evidence': udp_evidence,
                    'udp_path_check': udp_path_check,
                    'openvpn_path_probe': path_probe if carrier == 'openvpn-like' else None,
                    'logs': [server_log.name, client_log.name]}
    except Exception as error:
        evidence.update(status='failed', error=str(error), elapsed_seconds=time.monotonic() - started)
        raise
    finally:
        packed_cleanup_errors = []
        for side, capture, _ in udp_captures:
            if record_profile == 'packed' and side not in completed_packed_captures:
                try:
                    packed_shared.finish_capture(capture, packed_capture_logs[side])
                except Exception as error:
                    packed_cleanup_errors.append({'step': 'capture-' + side, 'error': str(error)[:512]})
        for process in reversed(processes):
            if record_profile == 'packed':
                try: packed_shared.stop(process)
                except Exception as error: packed_cleanup_errors.append({'step': 'process', 'error': str(error)[:512]})
            else: stop(process)
        final_captures = {}
        for side, _, path in udp_captures:
            try:
                if path.is_file():
                    with path.open('rb') as capture:
                        data = capture.read(64 * 1024 * 1024 + 1)
                    sample = {'pcap': path.name, 'read_bytes': len(data), 'complete_read': len(data) <= 64 * 1024 * 1024}
                    if sample['complete_read']:
                        sample['sha256'] = hashlib.sha256(data).hexdigest()
                        if carrier == 'openvpn-like':
                            try:
                                sample['audit'] = audit_openvpn_capture(data, path_mtu, duplex)
                            except ValueError as error:
                                sample['audit_error'] = str(error)
                    final_captures[side] = sample
                    evidence.record('final_capture_diagnostic', final_captures)
            except Exception as error:
                if record_profile != 'packed': raise
                packed_cleanup_errors.append({'step': 'capture-retention-' + side, 'error': str(error)[:512]})
        for endpoint in reversed(owned_clsact):
            if record_profile == 'packed':
                try: command([*endpoint, 'tc', 'qdisc', 'del', 'dev', 'wan0', 'clsact'])
                except Exception as error: packed_cleanup_errors.append({'step': 'filter', 'error': str(error)[:512]})
            else: command([*endpoint, 'tc', 'qdisc', 'del', 'dev', 'wan0', 'clsact'])
        if record_profile == 'packed':
            evidence.record('packed_cleanup_errors', packed_cleanup_errors)
            if packed_cleanup_errors:
                evidence.update(status='failed')
                raise RuntimeError('packed per-case cleanup incomplete')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--lab-id', default='native-smoke')
    parser.add_argument('--state-dir', type=Path, default=Path('/run/l2tunnel-labs'))
    parser.add_argument('--output', type=Path, default=ROOT / 'work/native-smoke')
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/l2tunneld')
    parser.add_argument('--include-netem', action='store_true')
    parser.add_argument('--netem-duplex', choices=['half', 'full', 'both'])
    parser.add_argument('--tcp-family', type=int, choices=[4, 6], default=4)
    parser.add_argument('--only-case', choices=[f'{layer}-{duplex}-{kind}' for layer in ('tap', 'tun', 'vxlan') for duplex, kind in (('full', 'clean'), ('half', 'clean'), ('half', 'netem'), ('full', 'netem'))])
    parser.add_argument('--record-profile', choices=['frame', 'aligned', 'packed'], default='frame')
    parser.add_argument('--aligned-channels', type=int)
    for key in PACKED_DEFAULTS:
        parser.add_argument('--packed-' + key.replace('_', '-'), type=int)
    parser.add_argument('--packed-auditor', type=Path)
    parser.add_argument('--build-receipt', type=Path)
    parser.add_argument('--hot-switch', action='store_true')
    parser.add_argument('--active-policy-switch', action='store_true')
    parser.add_argument('--active-transfer-timeout', type=int, choices=[60, 180])
    parser.add_argument('--active-switch-timing', choices=['default', 'slow-netem'])
    parser.add_argument('--active-progress', action='store_true')
    parser.add_argument('--carrier', choices=['tcp', 'udp', 'quic', 'openvpn-like'], default='tcp')
    parser.add_argument('--openvpn-path-probe', choices=['original-2s', 'short-recovery', 'idle-loss'])
    parser.add_argument('--traffic', choices=['system', 'active'], default='system')
    parser.add_argument('--flow-churn', action='store_true')
    parser.add_argument('--adaptive', action='store_true')
    parser.add_argument('--fec', choices=['none', 'cauchy'], default='none')
    parser.add_argument('--fec-sources', type=int)
    parser.add_argument('--fec-repairs', type=int)
    parser.add_argument('--fec-flush-ms', type=int)
    parser.add_argument('--udp-cover', choices=['openvpn-like', 'quic-like'])
    parser.add_argument('--udp-protection', choices=['aead', 'integrity'])
    parser.add_argument('--path-mtu', type=int, default=1500)
    parser.add_argument('--compression', choices=['off', 'lz4'], default='off')
    parser.add_argument('--layers', nargs='+', choices=['tap', 'tun', 'vxlan'], default=['tap', 'tun'])
    args = parser.parse_args()
    if args.netem_duplex is not None and not args.include_netem:
        parser.error('--netem-duplex requires --include-netem')
    args.netem_duplex = args.netem_duplex or 'half'
    packed = None
    packed_values = {key: getattr(args, 'packed_' + key) for key in PACKED_DEFAULTS}
    if args.record_profile == 'packed':
        if (args.carrier not in ('udp', 'quic') or args.fec != 'cauchy' or args.compression != 'off'
                or args.traffic != 'system' or args.hot_switch or args.active_policy_switch or args.aligned_channels is not None):
            parser.error('packed requires explicit UDP/QUIC, Cauchy, compression off, system traffic and no aligned/reload options')
        packed = {key: value if value is not None else PACKED_DEFAULTS[key] for key, value in packed_values.items()}
        if any(not 1 <= value <= (1000 if key == 'hold_micros' else 255) for key, value in packed.items()):
            parser.error('packed values outside their declared bounds')
        if args.apply and (args.packed_auditor is None or args.build_receipt is None):
            parser.error('packed apply requires reviewed --packed-auditor and --build-receipt')
    elif any(value is not None for value in packed_values.values()) or args.packed_auditor is not None or args.build_receipt is not None:
        parser.error('packed flags/build receipt require --record-profile packed')
    if args.openvpn_path_probe is not None and args.carrier != 'openvpn-like':
        parser.error('standalone path probe requires --carrier openvpn-like')
    if args.openvpn_path_probe in ('short-recovery', 'idle-loss') and (args.only_case != 'tun-half-clean' or args.layers != ['tun'] or args.include_netem or args.compression != 'off' or args.udp_protection not in (None, 'aead')):
        parser.error('separate outage profiles currently require explicit clean TUN/half, compression off and AEAD')
    args.openvpn_path_probe = args.openvpn_path_probe or 'original-2s'
    if args.record_profile == 'aligned':
        if args.carrier not in ('udp', 'quic') or args.fec != 'cauchy' or args.compression != 'off' or args.traffic != 'system' or args.hot_switch or args.active_policy_switch:
            parser.error('aligned requires explicit UDP/QUIC, Cauchy, compression off and system traffic without reload')
        args.aligned_channels = 4 if args.aligned_channels is None else args.aligned_channels
        if not 1 <= args.aligned_channels <= 256:
            parser.error('aligned channels must be 1..256')
    elif args.aligned_channels is not None:
        parser.error('aligned channels require --record-profile aligned')
    if args.carrier == 'quic' and (args.udp_cover is not None or args.udp_protection is not None):
        parser.error('genuine QUIC has no custom cover or optional protection')
    if args.carrier == 'openvpn-like' and args.udp_cover is not None:
        parser.error('standalone OpenVPN-like cover is fixed; do not select a TCP-bootstrapped cover')
    args.udp_cover = args.udp_cover or 'quic-like'
    args.udp_protection = args.udp_protection or 'aead'
    if args.carrier in ('udp', 'quic', 'openvpn-like') and args.hot_switch:
        parser.error('UDP compression hot switching is not implemented')
    if args.traffic == 'active' and (args.carrier != 'tcp' or set(args.layers) != {'tun'} or args.hot_switch):
        parser.error('active native profile requires TUN over TCP without hot switching')
    if args.active_policy_switch and (args.traffic != 'active' or args.carrier != 'tcp' or set(args.layers) != {'tun'} or args.hot_switch or args.flow_churn):
        parser.error('active policy switching requires active TUN/TCP without compression switching or flow churn')
    if args.active_transfer_timeout is not None and not args.active_policy_switch:
        parser.error('active transfer deadline requires --active-policy-switch')
    if args.active_switch_timing is not None and not args.active_policy_switch:
        parser.error('active timing profile requires --active-policy-switch')
    if args.active_switch_timing == 'slow-netem' and args.active_transfer_timeout != 180:
        parser.error('slow-netem explicitly requires --active-transfer-timeout 180')
    if args.active_progress and (not args.active_policy_switch or args.active_switch_timing != 'slow-netem' or args.active_transfer_timeout != 180):
        parser.error('incremental progress requires active slow-netem with an explicit 180 s deadline')
    args.active_switch_timing = args.active_switch_timing or 'default'
    args.active_transfer_timeout = args.active_transfer_timeout or 60
    if args.flow_churn and args.traffic != 'active':
        parser.error('flow churn requires the active TUN profile')
    if args.adaptive and args.traffic != 'active':
        parser.error('measured adaptation requires the active TUN profile')
    fec_values = (args.fec_sources, args.fec_repairs, args.fec_flush_ms)
    if args.fec == 'none' and any(value is not None for value in fec_values):
        parser.error('FEC tuning requires --fec cauchy')
    fec = None
    if args.fec == 'cauchy':
        if args.carrier not in ('udp', 'quic'):
            parser.error('Cauchy native profile requires UDP')
        fec = tuple(value if value is not None else default for value, default in zip(fec_values, (4, 2, 5), strict=True))
        if not (1 <= fec[0] <= 16 and 1 <= fec[1] <= 16 and 1 <= fec[2] < 200):
            parser.error('Cauchy bounds: 1..16 sources/repairs, 1..199 ms flush')
    if not 576 <= args.path_mtu <= 65535:
        parser.error('path MTU outside native IPv4 test bounds')
    if args.carrier == 'quic' and args.path_mtu < 1228:
        parser.error('genuine QUIC requires a complete IPv4 MTU of at least 1228')
    spec = netns_lab.LabSpec(args.lab_id)
    cases = [(layer, duplex, False) for layer in args.layers for duplex in ('half', 'full')]
    if args.include_netem:
        impaired_duplex = ('half', 'full') if args.netem_duplex == 'both' else (args.netem_duplex,)
        cases.extend((layer, duplex, True) for layer in args.layers for duplex in impaired_duplex)
    if args.only_case:
        cases = [case for case in cases if f'{case[0]}-{case[1]}-{"netem" if case[2] else "clean"}' == args.only_case]
        if not cases:
            parser.error('--only-case must be included by layer/netem selection')
    if not args.apply:
        print(json.dumps({'status': 'dry_run', 'namespaces': spec.namespaces, 'cases': cases,
                          'binary': str(args.binary), 'carrier': args.carrier, 'record_profile': args.record_profile,
                          'netem_duplex': args.netem_duplex, 'tcp_family': args.tcp_family,
                          'openvpn_path_probe': args.openvpn_path_probe if args.carrier == 'openvpn-like' else None,
                          'aligned_channels': args.aligned_channels,
                          'delivery': DELIVERY_POLICY if args.record_profile in ('aligned', 'packed') else None,
                          **({'packed': packed, 'packed_preflight': 'reviewed immutable daemon/auditor/build/helpers plus validation-only geometry required before namespace work'} if packed is not None else {}),
                          'traffic': args.traffic, 'fec': fec, 'flow_churn': args.flow_churn, 'adaptive': args.adaptive,
                          'active_policy_switch': args.active_policy_switch,
                          'active_progress': args.active_progress,
                          'active_transaction': transaction_timing(args.active_switch_timing) if args.active_policy_switch else None,
                          'active_transfer_timeout': args.active_transfer_timeout if args.active_policy_switch else None,
                          'note': 'No network changes; use --apply explicitly.'}, indent=2))
        return 0
    if packed is not None:
        validate_packed_entry(args.binary, args.packed_auditor, args.build_receipt)
        if args.output.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError('packed output must be outside the immutable build tree')
    netns_lab.require_root()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    packed_build = None
    packed_publication = CaseEvidence(output / 'receipt.json', 'packed-native') if packed is not None else None
    if packed is not None:
        packed_publication.update(preflight='running', cleanup='not_needed', namespace_mutations_started=False)
        try:
            packed_build = packed_snapshot(args.binary.resolve(), args.packed_auditor.resolve(), args.build_receipt.resolve(), output)
        except Exception as error:
            packed_publication.update(status='failed', preflight='failed', error=str(error)[:4096])
            print(json.dumps({'status': 'failed', 'stage': 'immutable_preflight', 'receipt': str(output / 'receipt.json')}))
            return 1
        packed_publication.update(preflight='passed')
    else:
        (output / 'native_smoke.py').write_bytes(Path(__file__).read_bytes())
        (output / 'tcp_probe.py').write_bytes((ROOT / 'tools/tcp_probe.py').read_bytes())
        (output / 'flow_churn_probe.py').write_bytes((ROOT / 'tools/flow_churn_probe.py').read_bytes())
    # Every endpoint and keygen invocation uses this immutable test-run copy.
    binary = output / 'l2tunneld-tested'
    if packed is None: shutil.copy2(args.binary.resolve(), binary)
    receipt = {'status': 'running', 'cases': [], 'netem_duplex': args.netem_duplex, 'tcp_family': args.tcp_family, 'planned_cases': [case_name(layer, duplex, impaired, args.openvpn_path_probe) for layer, duplex, impaired in cases],
               'openvpn_path_probe': args.openvpn_path_probe if args.carrier == 'openvpn-like' else None,
               'record_profile': args.record_profile, 'aligned_channels': args.aligned_channels,
               'delivery': DELIVERY_POLICY if args.record_profile in ('aligned', 'packed') else None, 'scope': f'native Linux {args.carrier} device forwarding with retained authenticated ' + ('QUIC control and TCP explicitly blocked' if args.carrier == 'quic' else 'standalone TLS over UDP control and TCP explicitly blocked' if args.carrier == 'openvpn-like' else 'TCP/TLS control'),
               'active_transaction': transaction_timing(args.active_switch_timing) if args.active_policy_switch else None,
               'active_transfer_timeout_seconds': args.active_transfer_timeout if args.active_policy_switch else None,
               'tcp_io_inactivity_timeout_seconds': 45,
               'tcp_probe_protocol': 'progress32k-v1' if args.active_progress else 'final-checksum-v1',
               'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'acceptance': 'three sequential single-probe invocations per size/direction; each exactly 1 sent/received within 30s; TCP SHA-256; optional two peer-confirmed epoch changes during paced 512KiB TCP',
               'binary_source': str(args.binary.resolve()), 'binary_snapshot': binary.name,
               'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'cleanup': 'pending'}
    if packed_publication is not None: packed_publication.update(**receipt)
    created = False
    packed_names_before = None
    journal = args.state_dir / f'{spec.lab_id}.json'
    journal_preexisted = journal.exists() or journal.is_symlink()
    try:
        if packed is not None:
            receipt['packed'] = packed
            receipt['packed_build'] = packed_build
            receipt['packed_geometry'] = {}
            for layer, duplex, impaired in cases:
                name = case_name(layer, duplex, impaired, args.openvpn_path_probe)
                config_path = output / f'{name}-packed-config.json'
                with config_path.open('x') as stream:
                    json.dump(packed_config(layer, duplex, args.carrier, args.path_mtu, args.udp_cover, args.udp_protection, fec, packed), stream)
                receipt['packed_geometry'][name] = invoke_packed_auditor(output / 'packed_capture_audit', 'validate', config_path, output / f'{name}-packed-geometry.json')
            packed_names_before = namespace_observation(spec)
            receipt['expected_namespaces_before'] = packed_names_before
            packed_publication.update(**receipt)
            if journal_preexisted or any(value is not None for value in packed_names_before.values()):
                raise ValueError('packed lab requires fresh namespaces and absent journal')
        with tempfile.TemporaryDirectory(prefix='l2tunnel-smoke-') as directory:
            secrets = Path(directory)
            (secrets / 'application-id').write_text(os.urandom(16).hex())
            if args.active_policy_switch:
                catalog = {'version': 1, 'policies': [active_policy(4), active_policy(2, True)]}
                if args.active_switch_timing == 'slow-netem':
                    catalog['transaction'] = transaction_timing(args.active_switch_timing)
                (secrets / 'active-policies.json').write_text(json.dumps(catalog))
                (output / 'active-policies.json').write_text(json.dumps(catalog, indent=2) + '\n')
            command([str(binary), 'keygen', '--private', str(secrets / 'member.der'), '--public', str(secrets / 'member.pub')])
            if args.carrier == 'openvpn-like':
                command([str(binary), 'openvpn-keygen', '--admission', str(secrets / 'admission.raw'), '--cookie', str(secrets / 'cookie.raw')])
            command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                     '-keyout', str(secrets / 'server.pem'), '-out', str(secrets / 'cert.pem'), '-days', '1',
                     '-subj', '/CN=lab.invalid', '-addext', 'subjectAltName=DNS:lab.invalid', '-addext', 'basicConstraints=critical,CA:FALSE'])
            command(['openssl', 'x509', '-in', str(secrets / 'cert.pem'), '-outform', 'DER', '-out', str(secrets / 'cert.der')])
            command(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(secrets / 'server.pem'), '-outform', 'DER', '-out', str(secrets / 'server.der')])
            if packed is not None:
                packed_publication.update(namespace_mutations_started=True)
                packed_shared.bounded_lab(netns_lab.apply, spec, args.state_dir, time.monotonic() + 60)
            else: netns_lab.apply(spec, args.state_dir)
            created = True
            if packed is not None:
                receipt['packed_underlay'] = packed_underlay(spec, args.path_mtu)
                packed_publication.update(**receipt)
            if args.carrier in ('quic', 'openvpn-like') and packed is None:
                # Packet captures and netem must observe physical-sized UDP
                # datagrams rather than veth GSO/GRO aggregate skbs.
                for role, interface in [('endpoint_a', 'wan0'), ('endpoint_b', 'wan0'), ('router', 'a0'), ('router', 'b0')]:
                    namespace = spec.namespaces[role]
                    command(['ip', '-n', namespace, 'link', 'set', interface, 'mtu', str(args.path_mtu)])
                    command(['ip', 'netns', 'exec', namespace, 'ethtool', '-K', interface, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off'])
            for side, address in [('a', '198.19.0.1/24'), ('b', '198.19.0.2/24')]:
                namespace = spec.namespaces[f'endpoint_{side}']
                command(['ip', '-n', namespace, 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun'])
                command(['ip', '-n', namespace, 'link', 'set', 'tun0', 'mtu', '1500', 'up'])
                command(['ip', '-n', namespace, 'address', 'add', address, 'dev', 'tun0'])
                number = '1' if side == 'a' else '2'
                command(['ip', '-n', namespace, '-6', 'address', 'add', f'fd42:12:19::{number}/64', 'dev', 'tun0', 'nodad'])
                command(['ip', '-n', spec.namespaces[f'host_{side}'], '-6', 'address', 'add', f'fd42:12:18::{number}/64', 'dev', 'eth0', 'nodad'])
                if 'vxlan' in args.layers:
                    host = spec.namespaces[f'host_{side}']
                    local = f'198.18.0.{number}'
                    remote = f'198.18.0.{"10" if side == "a" else "20"}'
                    command(['ip', '-n', namespace, 'address', 'add', remote + '/24', 'dev', 'br-lan'])
                    command(['ip', '-n', host, 'link', 'add', 'vx0', 'type', 'vxlan', 'id', '42', 'local', local, 'remote', remote, 'dstport', '4789', 'dev', 'eth0'])
                    command(['ip', '-n', host, 'link', 'set', 'vx0', 'mtu', '1400', 'up'])
                    # Byte-only userspace UDP VTEPs do not receive kernel skb
                    # checksum/GSO metadata; complete checksums before this boundary.
                    for interface in ('vx0', 'eth0'):
                        command(['ip', 'netns', 'exec', host, 'ethtool', '-K', interface, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off'])
                    command(['ip', '-n', host, 'address', 'add', f'198.20.0.{number}/24', 'dev', 'vx0'])
                    command(['ip', '-n', host, '-6', 'address', 'add', f'fd42:12:20::{number}/64', 'dev', 'vx0', 'nodad'])
            for layer, duplex, impaired in cases:
                receipt['current_case'] = case_name(layer, duplex, impaired, args.openvpn_path_probe)
                receipt['cases'].append(run_case(spec, binary, secrets, output, layer, duplex, impaired, args.compression, args.hot_switch,
                                                args.carrier, args.udp_cover, args.udp_protection, args.path_mtu, args.traffic, fec, args.flow_churn, args.adaptive, args.active_policy_switch, args.active_transfer_timeout, args.active_switch_timing, args.active_progress, args.record_profile, args.aligned_channels, args.openvpn_path_probe, packed, output / 'packed_capture_audit' if packed is not None else None, args.tcp_family))
                if packed_publication is not None: packed_publication.update(**receipt)
                print(f"Passed {receipt['cases'][-1]['case']}", flush=True)
            receipt.pop('current_case', None)
            receipt['status'] = 'passed'
    except Exception as error:
        receipt['status'] = 'failed'
        receipt['error'] = str(error)
        receipt['failed_case'] = receipt.pop('current_case', None)
    finally:
        try:
            if created:
                if packed is not None: packed_shared.bounded_lab(netns_lab.cleanup, spec, args.state_dir, time.monotonic() + 30)
                else: netns_lab.cleanup(spec, args.state_dir)
            elif packed is not None and not journal_preexisted and journal.exists():
                raise RuntimeError('partial setup retained authoritative journal; cleanup is not proven')
            receipt['cleanup'] = 'passed'
        except Exception as error:
            receipt['cleanup'] = 'failed'
            receipt['cleanup_error'] = str(error)
            receipt['status'] = 'failed'
        if packed is not None:
            try:
                after = namespace_observation(spec)
                receipt['expected_namespaces_after'] = after
                changes = namespace_changes(packed_names_before, after)
                receipt['unaccounted_namespace_changes'] = changes
                if changes: raise RuntimeError('unaccounted namespace residual/replacement; no adoption or deletion authorized')
            except Exception as error:
                receipt['cleanup'] = 'failed'
                receipt['status'] = 'failed'
                receipt['namespace_observation_error'] = str(error)[:4096]
        finished = {case['case'] for case in receipt['cases']} | {receipt.get('failed_case')}
        receipt['unrun_cases'] = [case for case in receipt['planned_cases'] if case not in finished]
        receipt['partial_progress_journals'] = {path.name: observation_snapshot(path.read_text()) for path in sorted(output.glob('*-tcp-progress.jsonl'))}
        receipt['case_stage_journals'] = {path.name: json.loads(path.read_text()) for path in sorted(output.glob('*-stage.json'))}
        receipt['case_evidence_journals'] = {path.name: json.loads(path.read_text()) for path in sorted(output.glob('*-partial.json'))}
        if packed_publication is not None: packed_publication.update(**receipt)
        else: (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'cleanup': receipt['cleanup'], 'receipt': str(output / 'receipt.json')}, indent=2))
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
