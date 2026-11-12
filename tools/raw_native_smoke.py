#!/usr/bin/env python3
"""Explicit journal-owned raw TCP/TLS native qualification; dry run by default."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

try:
    from . import netns_lab
except ImportError:
    import netns_lab

ROOT = Path(__file__).resolve().parents[1]
PORTS = ((24440, 24441), (24442, 24443))


def command(argv: list[str], timeout: float = 60) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {argv!r}\n{result.stdout}{result.stderr}')
    return result.stdout


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_log(process: subprocess.Popen, path: Path, marker: str, timeout: float = 65) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in path.read_text():
            return
        if process.poll() is not None:
            raise RuntimeError(f'helper exited before {marker}: {path.read_text()}')
        time.sleep(0.05)
    raise TimeoutError(f'helper did not reach {marker}: {path.read_text()}')


def verify_drain(proof: dict, lanes: int) -> None:
    """Accept only finite exact native/TLS/raw ownership completion, never partial close."""
    if (type(lanes) is not int or lanes not in (1, 2) or not isinstance(proof, dict) or set(proof) != {'kind', 'status', 'raw_drivers_clean', 'native', 'drivers', 'bounds'}
            or proof['kind'] != 'raw_native_drained' or proof['status'] != 'passed'
            or type(proof['raw_drivers_clean']) is not int or proof['raw_drivers_clean'] != lanes
            or proof['bounds'] != {'native_tls_seconds': 30, 'additional_driver_seconds': 45, 'request_seconds': 5}):
        raise ValueError('invalid bounded raw helper completion')
    native = proof['native']
    fields = {'local_admitted', 'local_handed', 'local_flushed', 'peer_barrier', 'native_confirmed',
              'local_barrier', 'local_ack', 'peer_ack', 'tls_lanes_closed'}
    if (not isinstance(native, dict) or set(native) != fields
            or any(type(value) is not int or not 0 <= value < 2**64 for value in native.values())
            or native['tls_lanes_closed'] != lanes
            or any(native[field] != native['local_admitted'] for field in ('local_handed', 'local_flushed', 'local_barrier', 'peer_ack'))
            or any(native[field] != native['peer_barrier'] for field in ('native_confirmed', 'local_ack'))):
        raise ValueError('incomplete or mismatched native drain fence')
    counters = proof['drivers']
    fields = {'received_packets', 'sent_packets', 'discarded_packets', 'sent_bytes', 'received_bytes'}
    if (not isinstance(counters, list) or len(counters) != lanes
            or any(not isinstance(row, dict) or set(row) != fields
                   or any(type(value) is not int or not 0 <= value < 2**64 for value in row.values())
                   or any(row[field] == 0 for field in fields - {'discarded_packets'}) for row in counters)):
        raise ValueError('missing clean driver counter evidence')


def verify_peer_drains(peers: dict, lanes: int) -> None:
    if set(peers) != {'a', 'b'}:
        raise ValueError('both raw helper completions required')
    for proof in peers.values():
        verify_drain(proof, lanes)
    a, b = peers['a'], peers['b']
    for first, second in ((a, b), (b, a)):
        if (first['native']['local_admitted'] != second['native']['native_confirmed']
                or sum(row['sent_bytes'] for row in first['drivers']) != sum(row['received_bytes'] for row in second['drivers'])):
            raise ValueError('peer native/raw byte fences disagree')


def drain_helpers(paths: dict[str, Path], receipt: dict, lanes: int, deadline: float) -> None:
    """Submit both requests before waiting; one absolute deadline and 8 KiB replies."""
    if set(paths) != {'a', 'b'}:
        raise ValueError('exactly two private helper paths required')
    sockets = {}
    receipt['peers'] = {}
    try:
        for side, path in paths.items():
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sockets[side] = connection
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('both-helper drain deadline')
            connection.settimeout(remaining)
            connection.connect(str(path))
        for connection in sockets.values():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('both-helper drain deadline')
            connection.settimeout(remaining)
            connection.sendall(b'DRAIN1\n')
            connection.shutdown(socket.SHUT_WR)
        for side, connection in sockets.items():
            raw = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('both-helper drain deadline')
                connection.settimeout(remaining)
                chunk = connection.recv(8193 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > 8192:
                    raise ValueError('raw helper reply exceeds bound')
            if not raw.endswith(b'\n') or raw.count(b'\n') != 1:
                raise ValueError('one complete raw helper reply required')
            proof = json.loads(raw)
            verify_drain(proof, lanes)
            receipt['peers'][side] = proof
        verify_peer_drains(receipt['peers'], lanes)
    finally:
        for connection in sockets.values():
            connection.close()


def ping_counts(output: str) -> None:
    match = re.search(r'(\d+) packets transmitted, (\d+) received,.*?([0-9.]+)% packet loss', output)
    if not match or (int(match[1]), int(match[2]), float(match[3])) != (1, 1, 0.0):
        raise ValueError('native ping did not deliver exactly one original packet')


def capture_counts(output: str) -> dict[str, int]:
    """Require complete tcpdump counters; substrings such as 10 drops are not zero."""
    fields = ('captured', 'received by filter', 'dropped by kernel')
    counts = {}
    for field in fields:
        matches = re.findall(rf'^(\d+) packets {field}$', output, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError(f'missing/duplicate capture counter: {field}')
        counts[field] = int(matches[0])
    if not 0 < counts['captured'] < 4096 or counts['dropped by kernel'] != 0:
        raise ValueError('empty, exhausted or lossy packet capture')
    return counts


def tls_records(stream: bytes) -> list[tuple[int, bytes]]:
    records = []
    offset = 0
    while offset < len(stream):
        if len(stream) - offset < 5:
            raise ValueError('truncated captured TLS record header')
        kind, major, minor, size = struct.unpack_from('!BBBH', stream, offset)
        if kind not in (20, 21, 22, 23) or major != 3 or minor not in (1, 3) or not 1 <= size <= 18432:
            raise ValueError('invalid captured TLS record')
        offset += 5
        if offset + size > len(stream):
            raise ValueError('truncated captured TLS record body')
        records.append((kind, stream[offset:offset + size]))
        offset += size
    if not records or records[0][0] != 22 or not any(kind == 23 for kind, _ in records):
        raise ValueError('missing TLS hello/encrypted continuation')
    return records


def client_hello_without_sni(body: bytes) -> None:
    if len(body) < 39 or body[0] != 1:
        raise ValueError('missing captured ClientHello')
    length = int.from_bytes(body[1:4], 'big')
    if length + 4 != len(body):
        raise ValueError('unsupported fragmented/coalesced ClientHello')
    offset = 38
    session = body[offset]
    offset += 1 + session
    if offset + 2 > len(body):
        raise ValueError('truncated ClientHello session')
    ciphers = int.from_bytes(body[offset:offset + 2], 'big')
    offset += 2 + ciphers
    if offset >= len(body):
        raise ValueError('truncated ClientHello ciphers')
    offset += 1 + body[offset]
    if offset + 2 > len(body):
        raise ValueError('truncated ClientHello compression')
    extent = offset + 2 + int.from_bytes(body[offset:offset + 2], 'big')
    offset += 2
    if extent != len(body):
        raise ValueError('ClientHello extension length mismatch')
    while offset < extent:
        if offset + 4 > extent:
            raise ValueError('short ClientHello extension')
        kind, size = struct.unpack_from('!HH', body, offset)
        offset += 4
        if kind == 0:
            raise ValueError('unexpected SNI extension')
        if offset + size > extent:
            raise ValueError('oversized ClientHello extension')
        offset += size


def inspect_capture(path: Path, lanes: int) -> dict:
    """Bounded classic Ethernet pcap parsing and sequence-exact TLS reconstruction."""
    if lanes not in (1, 2):
        raise ValueError('invalid raw lane count')
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('capture exceeds finite qualification bound')
    raw = path.read_bytes()
    if len(raw) < 24 or raw[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        raise ValueError('unsupported/truncated pcap header')
    endian = '<' if raw[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    if struct.unpack_from(endian + 'I', raw, 20)[0] != 1:
        raise ValueError('qualification expects Ethernet capture')
    offset = 24
    flows: dict[tuple[str, int, str, int], dict] = {}
    acknowledged: dict[tuple[str, int, str, int], set[int]] = {}
    packets = 0
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise ValueError('truncated pcap packet header')
        _, _, size, original = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        if size != original or size > 65535 or offset + size > len(raw):
            raise ValueError('truncated/oversized captured packet')
        packet = raw[offset:offset + size]
        offset += size
        packets += 1
        if packets > 4096 or len(packet) < 54 or packet[12:14] != b'\x08\x00':
            raise ValueError('unexpected non-IPv4 or excess captured traffic')
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], 'big')
        if ip[0] >> 4 != 4 or ip[9] != 6 or not 20 <= ihl <= total <= len(ip) or int.from_bytes(ip[6:8], 'big') & 0x3fff:
            raise ValueError('invalid/fragmented captured IPv4 TCP')
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            raise ValueError('short captured TCP')
        sport, dport, sequence, acknowledgment = struct.unpack_from('!HHII', tcp)
        head = (tcp[12] >> 4) * 4
        if not 20 <= head <= len(tcp):
            raise ValueError('invalid TCP header length')
        flags = tcp[13]
        if flags & 4:
            raise ValueError('RST escaped the exact-tuple policy')
        key = (socket.inet_ntoa(ip[12:16]), sport, socket.inet_ntoa(ip[16:20]), dport)
        state = flows.setdefault(key, {'syn': set(), 'segments': [], 'packets': 0, 'keepalive_probes': 0})
        state['packets'] += 1
        if flags & 16:
            reverse = (key[2], key[3], key[0], key[1])
            acknowledged.setdefault(reverse, set()).add(acknowledgment)
        if flags & 2:
            state['syn'].add(sequence)
        if len(tcp) > head:
            if (flags == 16 and len(tcp) == head + 1
                    and ((sequence + 1) & 0xffffffff) in acknowledged.get(key, set())):
                # RFC 9293 keepalive may carry a garbage octet at SND.NXT-1.
                # Require captured peer acknowledgment of that octet's sequence;
                # it is outside the receive window and does not reenter the stream.
                state['keepalive_probes'] += 1
            else:
                state['segments'].append((sequence, tcp[head:]))
    expected = set()
    for a, b in PORTS[:lanes]:
        expected.add(('192.0.2.2', a, '192.0.2.6', b))
        expected.add(('192.0.2.6', b, '192.0.2.2', a))
    if set(flows) != expected:
        raise ValueError('unexpected/missing raw TCP four-tuples')
    details = []
    marker = random.Random(0x12AA).randbytes(64)
    for key, state in sorted(flows.items()):
        if len(state['syn']) != 1:
            raise ValueError('missing SYN or second initial sequence number on retained lane')
        base = (next(iter(state['syn'])) + 1) & 0xffffffff
        segments = sorted((((seq - base) & 0xffffffff), data) for seq, data in state['segments'])
        stream = bytearray()
        for position, data in segments:
            if position > len(stream) or position + len(data) > 4 * 1024 * 1024:
                raise ValueError('capture sequence gap or unbounded stream offset')
            overlap = min(len(data), len(stream) - position)
            if stream[position:position + overlap] != data[:overlap]:
                raise ValueError('TCP retransmission changed already observed bytes')
            stream.extend(data[overlap:])
        records = tls_records(bytes(stream))
        if key[0] == '192.0.2.2':
            client_hello_without_sni(records[0][1])
        elif not records[0][1] or records[0][1][0] != 2:
            raise ValueError('missing captured ServerHello')
        if marker in stream:
            raise ValueError('plaintext native probe payload found on underlay')
        details.append({'tuple': list(key), 'unique_syn_sequence': next(iter(state['syn'])),
                        'packets': state['packets'], 'stream_bytes': len(stream),
                        'acknowledged_keepalive_probes': state['keepalive_probes'],
                        'tls_records': len(records), 'encrypted_records': sum(kind == 23 for kind, _ in records),
                        'no_sni': key[0] == '192.0.2.2', 'sequence_overlap_exact': True})
    return {'pcap': path.name, 'sha256': hashlib.sha256(raw).hexdigest(), 'packets': packets,
            'streams': details, 'plaintext_probe_absent': True, 'rst_packets': 0}


def owned(spec: netns_lab.LabSpec, directory: Path) -> dict:
    with netns_lab.locked_state(directory, spec) as path:
        manifest = netns_lab.load_manifest(path, spec)
        for name, identity in manifest['owned_namespaces'].items():
            if netns_lab.namespace_identity(name) != identity:
                raise RuntimeError('owned namespace identity changed')
        if set(manifest['owned_namespaces']) != set(spec.namespaces.values()):
            raise RuntimeError('incomplete owned topology')
        return manifest['owned_namespaces']


def mark_value(text: str) -> int:
    """Canonical finite local mark; no signed/whitespace or zero values."""
    if re.fullmatch(r'(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})', text) is None:
        raise argparse.ArgumentTypeError('raw mark requires nonzero decimal or 0x hexadecimal u32')
    value = int(text, 16 if text.startswith('0x') else 10)
    if not 0 < value <= 0xffffffff:
        raise argparse.ArgumentTypeError('raw mark outside nonzero u32 bounds')
    return value


def rule_args(local: str, peer: str, sport: int, dport: int, raw_mark: int | None) -> list[str]:
    """One exact tuple; local mark never changes TCP flags or the DROP verdict."""
    base = ['-p', 'tcp', '-s', local, '--sport', str(sport), '-d', peer,
            '--dport', str(dport), '--tcp-flags', 'RST', 'RST']
    if raw_mark is not None:
        if type(raw_mark) is not int or not 0 < raw_mark <= 0xffffffff:
            raise ValueError('invalid local mark')
        base.extend(['-m', 'mark', '!', '--mark', hex(raw_mark)])
    return base + ['-j', 'DROP']


def rules(spec: netns_lab.LabSpec, lanes: int, install: bool, raw_mark: int | None = None) -> dict:
    if type(lanes) is not int or lanes not in (1, 2):
        raise ValueError('invalid raw lane count')
    if raw_mark is not None and (type(raw_mark) is not int or not 0 < raw_mark <= 0xffffffff):
        raise ValueError('invalid local mark')
    result = {}
    for side, local, peer in [('a', '192.0.2.2', '192.0.2.6'), ('b', '192.0.2.6', '192.0.2.2')]:
        prefix = ['ip', 'netns', 'exec', spec.namespaces[f'endpoint_{side}'], '/usr/sbin/iptables']
        tuples = [(a, b) if side == 'a' else (b, a) for a, b in PORTS[:lanes]]
        expected = set()
        for sport, dport in tuples:
            mark_clause = '' if raw_mark is None else f' -m mark ! --mark {hex(raw_mark)}'
            expected.add(f'-A OUTPUT -s {local}/32 -d {peer}/32 -p tcp -m tcp --sport {sport} --dport {dport} --tcp-flags RST RST{mark_clause} -j DROP')
        if install:
            before = command(prefix + ['-S', 'OUTPUT'])
            if before.strip() != '-P OUTPUT ACCEPT':
                raise RuntimeError('new owned OUTPUT chain is unexpectedly populated')
            for sport, dport in tuples:
                command(prefix + ['-I', 'OUTPUT', '1', *rule_args(local, peer, sport, dport, raw_mark)])
        chain = command(prefix + ['-S', 'OUTPUT'])
        lines = chain.splitlines()
        if not lines or lines[0] != '-P OUTPUT ACCEPT' or len(lines) != lanes + 1 or set(lines[1:]) != expected:
            raise RuntimeError('effective OUTPUT policy is not the exact owned RST chain')
        for sport, dport in tuples:
            command(prefix + ['-C', 'OUTPUT', *rule_args(local, peer, sport, dport, raw_mark)])
        result[side] = {'chain': chain, 'counters': command(prefix + ['-L', 'OUTPUT', '-n', '-v', '-x'])}
    return result


def run_case(spec: netns_lab.LabSpec, state_dir: Path, binary: Path, secrets: Path, output: Path,
             layer: str, duplex: str, impaired: bool, raw_mark: int | None = None) -> dict:
    ns = spec.namespaces
    identities = owned(spec, state_dir)
    name = f'{layer}-{duplex}-{"netem" if impaired else "clean"}'
    lanes = 2 if duplex == 'half' else 1
    # Rules for both possible lanes remain exact and owned throughout the topology.
    before = rules(spec, 2, False, raw_mark)
    case = {'case': name, 'status': 'running', 'stage': 'owned_rules_verified',
            'layer': layer, 'duplex': duplex, 'lanes': lanes,
            'reset_policy': 'marked-v1' if raw_mark is not None else 'legacy', 'socket_mark': raw_mark,
            'base_rtt_ms': 70 if impaired else 2, 'netem_loss_percent': 15 if impaired else 0,
            'namespace_identities': identities, 'rules_before': before}
    case_path = output / f'{name}.json'
    def save_case() -> None:
        case_path.write_text(json.dumps(case, indent=2) + '\n')
    save_case()
    for side in ('a', 'b'):
        command(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], 'tc', 'qdisc', 'change', 'dev', 'wan0',
                 'parent', '1:10', 'handle', '10:', 'netem', 'limit', '1000', 'delay', '35ms' if impaired else '1ms',
                 'loss', 'random', '15%' if impaired else '0%'])
    processes = []
    handles = []
    captures = []
    native_captures = []
    control_directory = tempfile.TemporaryDirectory(prefix='l2t-raw-drain-')
    control_paths = {side: Path(control_directory.name) / f'{side}.sock' for side in ('a', 'b')}
    try:
        for side in ('a', 'b'):
            capture = output / f'{name}-{side}.pcap'
            log = output / f'{name}-{side}-capture.log'
            handle = log.open('w'); handles.append(handle)
            process = subprocess.Popen(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], 'tcpdump', '--immediate-mode', '-U', '-n', '-B', '4096', '-i', 'wan0', '-s', '2048', '-c', '4096', '-w', str(capture), 'tcp portrange 24440-24443'], stdout=subprocess.DEVNULL, stderr=handle)
            processes.append(process); captures.append((process, capture, log))
            wait_log(process, log, 'listening on', 5)
            capture = output / f'{name}-{side}-native.pcap'
            log = output / f'{name}-{side}-native-capture.log'
            handle = log.open('w'); handles.append(handle)
            native_ns = ns[f'host_{side}' if layer == 'tap' else f'endpoint_{side}']
            native_if = 'eth0' if layer == 'tap' else 'tun0'
            process = subprocess.Popen(['ip', 'netns', 'exec', native_ns, 'tcpdump', '--immediate-mode', '-U', '-n', '-B', '4096', '-i', native_if, '-s', '2048', '-c', '4096', '-w', str(capture), 'arp or ip or ip6'], stdout=subprocess.DEVNULL, stderr=handle)
            processes.append(process); native_captures.append((process, capture, log))
            wait_log(process, log, 'listening on', 5)
        endpoint_processes = {}
        for side, role, local, peer in [('b', 'server', '192.0.2.6:24441', '192.0.2.2:24440'), ('a', 'client', '192.0.2.2:24440', '192.0.2.6:24441')]:
            log = output / f'{name}-{side}.log'
            handle = log.open('w'); handles.append(handle)
            process = subprocess.Popen(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], str(binary), role, layer, duplex, local, peer, 'tap0' if layer == 'tap' else 'tun0', str(secrets), str(control_paths[side]), *([] if raw_mark is None else ['--raw-mark', hex(raw_mark)])], stdout=handle, stderr=subprocess.STDOUT)
            processes.append(process); endpoint_processes[side] = (process, log)
            if role == 'server': time.sleep(0.15)
        for process, log in endpoint_processes.values():
            wait_log(process, log, 'raw_native_ready')
            if raw_mark is not None:
                ready = [json.loads(line) for line in log.read_text().splitlines() if line.startswith('{')]
                ready = [item for item in ready if item.get('kind') == 'raw_native_ready']
                if len(ready) != 1 or ready[0].get('reset_policy') != 'marked-v1' or type(ready[0].get('socket_mark')) is not int or ready[0]['socket_mark'] != raw_mark or ready[0].get('authenticated_lanes') != lanes:
                    raise ValueError('marked helper did not authenticate the selected policy')
        case['stage'] = 'authenticated_native_ready'
        save_case()
        kernel = {}
        for side in ('a', 'b'):
            table = command(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], 'ss', '-H', '-n', '-t', 'state', 'established'])
            if any(f':{port}' in table for pair in PORTS for port in pair):
                raise RuntimeError('kernel ESTABLISHED owner found on raw tuple')
            kernel[side] = table
        case['kernel_established'] = kernel
        pings = []
        case['pings'] = pings
        for side, number in [('a', '2'), ('b', '1')]:
            source = ns[f'host_{side}' if layer == 'tap' else f'endpoint_{side}']
            for ipv6 in (False, True):
                target = (f'fd42:12:{18 if layer == "tap" else 19}::{number}' if ipv6 else f'198.{18 if layer == "tap" else 19}.0.{number}')
                for size in (56, 1200):
                    response = command(['ip', 'netns', 'exec', source, 'ping', '-n', '-c', '1', '-W', '30', '-s', str(size), target], 35)
                    ping_counts(response)
                    pings.append({'source': source, 'destination': target, 'payload_bytes': size, 'output': response})
                    save_case()
        address = f'198.{18 if layer == "tap" else 19}.0.2'
        source = ns['host_a' if layer == 'tap' else 'endpoint_a']
        destination = ns['host_b' if layer == 'tap' else 'endpoint_b']
        tcp_log = output / f'{name}-tcp.log'; handle = tcp_log.open('w'); handles.append(handle)
        tcp = subprocess.Popen(['ip', 'netns', 'exec', destination, 'python3', str(output / 'tcp_probe.py'), 'listen', address], stdout=handle, stderr=subprocess.STDOUT)
        processes.append(tcp); wait_log(tcp, tcp_log, 'Listening', 5)
        payload = json.loads(command(['ip', 'netns', 'exec', source, 'python3', str(output / 'tcp_probe.py'), 'send', address], 60))
        tcp.wait(timeout=5)
        if tcp.returncode or payload['status'] != 'passed' or payload['bytes'] != 65536:
            raise ValueError('bounded native payload verification failed')
        case['tcp_payload'] = payload
        case['stage'] = 'native_payload_verified'
        save_case()
        for process, log in endpoint_processes.values():
            if process.poll() is not None:
                raise RuntimeError(f'helper exited during forwarding: {log.read_text()}')
        # Capture remains live until both authenticated native fences and all raw
        # drivers have completed. Forced termination is failure cleanup only.
        drain_started = time.monotonic()
        drain_deadline = drain_started + 80
        case['stage'] = 'drain_requested'
        case['drain'] = {'bounds': {'native_tls_seconds': 30, 'additional_driver_seconds': 45,
                                   'both_helpers_seconds': 80}, 'status': 'running'}
        save_case()
        try:
            drain_helpers(control_paths, case['drain'], lanes, drain_deadline)
            exits = {}
            for side, (process, log) in endpoint_processes.items():
                remaining = drain_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('both-helper process completion deadline')
                exits[side] = process.wait(timeout=remaining)
                if exits[side] != 0:
                    raise RuntimeError(f'helper failed after drain: {log.read_text()}')
            case['drain'].update(status='passed', helper_exit_codes=exits)
        finally:
            case['drain']['elapsed_seconds'] = time.monotonic() - drain_started
            save_case()
        case['stage'] = 'native_tls_and_raw_drivers_drained'
        save_case()
        evidence = {}
        for side, (process, capture, log) in zip(('a', 'b'), captures, strict=True):
            stop(process)
            counters = capture_counts(log.read_text())
            evidence[side] = inspect_capture(capture, lanes)
            if evidence[side]['packets'] != counters['captured']:
                raise ValueError('capture counter/file packet mismatch')
            evidence[side]['counters'] = counters
        native_evidence = {}
        for side, (process, capture, log) in zip(('a', 'b'), native_captures, strict=True):
            stop(process)
            native_evidence[side] = {'pcap': capture.name,
                                     'sha256': hashlib.sha256(capture.read_bytes()).hexdigest(),
                                     'counters': capture_counts(log.read_text())}
        case.update(status='passed', stage='capture_verified', rules_after=rules(spec, 2, False, raw_mark),
                    captures=evidence, native_captures=native_evidence,
                    scope='retained userspace reliable raw TCP, real TLS/member auth, negotiated finite native drain runtime; all raw drivers clean before capture stop; no custom packet phase')
        save_case()
        return case
    except Exception as error:
        case.update(status='failed', error=str(error))
        if case.get('drain', {}).get('status') == 'running':
            case['drain']['status'] = 'failed'
        diagnostics = {}
        try:
            case['failure_namespace_identities'] = owned(spec, state_dir)
            case['failure_rules'] = rules(spec, 2, False, raw_mark)
            case['failure_qdisc'] = {side: json.loads(command(['ip', 'netns', 'exec', ns[f'endpoint_{side}'],
                'tc', '-s', '-j', 'qdisc', 'show', 'dev', 'wan0'], 5)) for side in ('a', 'b')}
        except Exception as network_error:
            case['failure_network_snapshot_error'] = str(network_error)
        for side in ('a', 'b'):
            try:
                native_ns = ns[f'host_{side}' if layer == 'tap' else f'endpoint_{side}']
                diagnostics[side] = {'ipv6_neighbors': command(['ip', '-n', native_ns, '-6', 'neigh', 'show']),
                                     'bridge_multicast': command(['ip', 'netns', 'exec', ns[f'endpoint_{side}'], 'bridge', 'mdb', 'show'])}
            except Exception as diagnostic_error:
                diagnostics[side] = {'error': str(diagnostic_error)}
        case['native_diagnostics'] = diagnostics
        save_case()
        raise
    finally:
        for process in reversed(processes): stop(process)
        for handle in handles: handle.close()
        control_directory.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--lab-id', default='raw-native')
    parser.add_argument('--state-dir', type=Path, default=Path('/run/l2tunnel-labs'))
    parser.add_argument('--output', type=Path, default=ROOT / 'work/raw-native')
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/examples/raw-native')
    parser.add_argument('--include-netem', action='store_true')
    parser.add_argument('--raw-mark', type=mark_value)
    parser.add_argument('--only-case', choices=[f'{layer}-{mode}-{kind}' for layer in ('tap', 'tun')
        for mode, kind in (('full', 'clean'), ('half', 'clean'), ('half', 'netem'))])
    parser.add_argument('--layers', nargs='+', choices=['tap', 'tun'], default=['tap', 'tun'])
    parser.add_argument('--duplex', nargs='+', choices=['half', 'full'], default=['half', 'full'])
    args = parser.parse_args()
    spec = netns_lab.LabSpec(args.lab_id)
    cases = [(layer, duplex, False) for layer in args.layers for duplex in args.duplex]
    if args.include_netem:
        cases.extend((layer, 'half', True) for layer in args.layers)
    if args.only_case:
        cases = [case for case in cases if f'{case[0]}-{case[1]}-{"netem" if case[2] else "clean"}' == args.only_case]
        if not cases:
            parser.error('--only-case must be included by the layer/duplex/netem selection')
    if not args.apply:
        print(json.dumps({'status': 'dry_run', 'namespaces': spec.namespaces, 'cases': cases,
                          'binary': str(args.binary), 'reset_policy': 'marked-v1' if args.raw_mark is not None else 'legacy', 'socket_mark': args.raw_mark, 'note': 'No network changes; --apply creates only journal-owned namespaces.'}, indent=2))
        return 0
    netns_lab.require_root()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    binary = output / 'raw-native-tested'; shutil.copy2(args.binary.resolve(), binary)
    for name in ('raw_native_smoke.py', 'netns_lab.py', 'tcp_probe.py'):
        shutil.copy2(ROOT / 'tools' / name, output / name)
    receipt = {'status': 'running', 'cases': [], 'cleanup': 'pending', 'binary_source': str(args.binary.resolve()),
               'binary_snapshot': binary.name, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'reset_policy': 'marked-v1' if args.raw_mark is not None else 'legacy', 'socket_mark': args.raw_mark}
    created = False
    try:
        with tempfile.TemporaryDirectory(prefix='l2t-raw-credentials-') as directory:
            secrets = Path(directory)
            command([str(binary), 'keygen', str(secrets / 'member.der'), str(secrets / 'member.pub')])
            command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(secrets / 'server.pem'), '-out', str(secrets / 'cert.pem'), '-days', '1', '-subj', '/CN=lab.invalid', '-addext', 'subjectAltName=DNS:lab.invalid', '-addext', 'basicConstraints=critical,CA:FALSE'])
            command(['openssl', 'x509', '-in', str(secrets / 'cert.pem'), '-outform', 'DER', '-out', str(secrets / 'cert.der')])
            command(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(secrets / 'server.pem'), '-outform', 'DER', '-out', str(secrets / 'server.der')])
            netns_lab.apply(spec, args.state_dir); created = True
            owned(spec, args.state_dir)
            rules(spec, 2, True, args.raw_mark)
            for side, number in [('a', '1'), ('b', '2')]:
                namespace = spec.namespaces[f'endpoint_{side}']
                command(['ip', '-n', namespace, 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun'])
                command(['ip', '-n', namespace, 'link', 'set', 'tun0', 'mtu', '1500', 'up'])
                command(['ip', '-n', namespace, 'address', 'add', f'198.19.0.{number}/24', 'dev', 'tun0'])
                command(['ip', '-n', namespace, '-6', 'address', 'add', f'fd42:12:19::{number}/64', 'dev', 'tun0', 'nodad'])
                command(['ip', '-n', spec.namespaces[f'host_{side}'], '-6', 'address', 'add', f'fd42:12:18::{number}/64', 'dev', 'eth0', 'nodad'])
            for layer, duplex, impaired in cases:
                receipt['cases'].append(run_case(spec, args.state_dir, binary, secrets, output, layer, duplex, impaired, args.raw_mark))
                (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
                print(f"Passed {receipt['cases'][-1]['case']}", flush=True)
            receipt['status'] = 'passed'
    except Exception as error:
        receipt['status'] = 'failed'; receipt['error'] = str(error)
    finally:
        try:
            if created: netns_lab.cleanup(spec, args.state_dir)
            receipt['cleanup'] = 'passed'
        except Exception as error:
            receipt['status'] = 'failed'; receipt['cleanup'] = 'failed'; receipt['cleanup_error'] = str(error)
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'cleanup': receipt['cleanup'], 'receipt': str(output / 'receipt.json')}, indent=2))
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
