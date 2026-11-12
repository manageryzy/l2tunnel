#!/usr/bin/env python3
"""Dedicated fixed-credit TUN proxy qualification; dry run unless --apply is explicit."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

try:
    from . import netns_lab
except ImportError:
    import netns_lab

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_LIMIT = 32 * 1024 * 1024
LOG_LIMIT = RECEIPT_LIMIT = 4 * 1024 * 1024
PACKET_LIMIT = 8192
REPLY_LIMIT = 8192
PAYLOAD_LENGTHS = (65537, 32771)
BOUNDS = {'case': 300, 'command': 15, 'startup': 40, 'transfer': 30, 'ping': 5,
          'rpc': 2, 'drain_observation': 127, 'runtime_drain': 120, 'local_grace': 5,
          'probe_inactivity': 5, 'namespace_cleanup': 30}


class Unsupported(RuntimeError):
    """An observation cannot establish the frozen supported profile."""


def strict_json(raw: bytes | str):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError(f'duplicate JSON field: {key}')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def remaining(deadline: float, cap: float) -> float:
    value = min(deadline - time.monotonic(), cap)
    if value <= 0:
        raise TimeoutError('original stage/case deadline exhausted')
    return value


def command(argv: list[str], deadline: float, cap: float = 15) -> str:
    result = subprocess.run(argv, capture_output=True, text=True,
                            timeout=remaining(deadline, cap), check=False)
    if len(result.stdout) + len(result.stderr) > LOG_LIMIT:
        raise RuntimeError('command output exceeds fixed log bound')
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {argv!r}\n{result.stdout}{result.stderr}')
    return result.stdout


def bounded_lab(operation, spec, directory, deadline):
    """Preserve the authoritative journal while bounding its command runner locally."""
    original = netns_lab.run
    def bounded(argv):
        result = subprocess.run(argv, check=True, capture_output=True, text=True,
                                timeout=remaining(deadline, BOUNDS['command']))
        if len(result.stdout) + len(result.stderr) > LOG_LIMIT:
            raise RuntimeError('namespace command output exceeds fixed bound')
        return result
    netns_lab.run = bounded
    try:
        operation(spec, directory)
    finally:
        netns_lab.run = original


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def source_hashes(root: Path = ROOT) -> dict[str, str]:
    """Hash build inputs and vendor provenance, excluding generated caches/targets."""
    sources = {root / 'Cargo.toml', root / 'Cargo.lock', root / 'tools/proxy_native_smoke.py',
               root / 'tools/test_proxy_native_smoke.py', root / 'tools/netns_lab.py'}
    for name in ('.cargo/config.toml', 'rust-toolchain.toml'):
        path = root / name
        if path.is_file(): sources.add(path)
    for name in ('crates', 'apps', 'third_party'):
        sources.update(path for path in (root / name).rglob('*') if path.is_file()
                       and not {'target', '__pycache__', '.git'}.intersection(path.relative_to(root).parts))
    return {str(path.relative_to(root)): file_hash(path) for path in sorted(sources)}


def verified_build_receipt(path: Path, binary: Path) -> dict:
    """Verify recorded build consistency, without attributing later cwd edits to it."""
    if path.stat().st_size > RECEIPT_LIMIT:
        raise ValueError('build receipt exceeds fixed bound')
    value = strict_json(path.read_bytes())
    if (not isinstance(value, dict) or value.get('status') != 'passed'
            or value.get('exit_code') != 0 or value.get('source_stable_during_build') is not True
            or value.get('changed_during_build') != []):
        raise ValueError('successful source-stable build receipt required')
    before, after = value.get('source_sha256_before'), value.get('source_sha256_after')
    if (not isinstance(before, dict) or not before or before != after
            or any(not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts
                   or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
                   for name, digest in before.items())
            or value.get('binary_sha256') != file_hash(binary)):
        raise ValueError('build source maps or immutable binary hash mismatch')
    return value


class Receipt:
    """Exclusive initial publication and bounded atomic updates, including failures."""
    def __init__(self, path: Path, value: dict):
        if path.exists() or path.is_symlink():
            raise FileExistsError(path)
        self.path, self.value = path, {}
        self.update(**value)

    def update(self, **fields):
        value = {**self.value, **fields}
        encoded = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
        if len(encoded) > RECEIPT_LIMIT:
            raise ValueError('receipt exceeds fixed bound')
        with tempfile.NamedTemporaryFile(dir=self.path.parent, prefix='.receipt-', delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(encoded)
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
                if self.value:
                    os.replace(temporary, self.path)
                else:
                    os.link(temporary, self.path)
            finally:
                temporary.unlink(missing_ok=True)
        self.value = strict_json(encoded)


def policy() -> dict:
    return {'version': 1, 'channels': 16, 'time_wait_reset': 'maintained', 'routes': [
        {'source': source, 'destination': destination, 'ports': {'first': 24451, 'last': 24451}}
        for source, destination in [('198.19.0.1/32', '198.19.0.2/32'),
                                    ('fd42:12:19::1/128', 'fd42:12:19::2/128')]]}


def case_plan(lab_id: str, duplex: str) -> dict:
    if duplex not in ('full', 'half'):
        raise ValueError('explicit full or half duplex required')
    spec = netns_lab.LabSpec(lab_id + ('-f' if duplex == 'full' else '-h'))
    flows = []
    for stage, port, reverse, offset in [('owned', 24451, False, 0),
                                         ('denied', 24452, False, 10),
                                         ('reverse', 24451, True, 20)]:
        for family in (4, 6):
            a, b = (('198.19.0.1', '198.19.0.2') if family == 4
                    else ('fd42:12:19::1', 'fd42:12:19::2'))
            flows.append({'stage': stage, 'family': family, 'client_side': 'b' if reverse else 'a',
                          'server_side': 'a' if reverse else 'b', 'source': b if reverse else a,
                          'destination': a if reverse else b, 'source_port': 32000 + offset + family,
                          'destination_port': port, 'split': stage == 'owned'})
    return {'case': f'tun-{duplex}-clean', 'lab_id': spec.lab_id, 'namespaces': spec.namespaces,
            'duplex': duplex, 'lanes': 1 if duplex == 'full' else 2, 'bounds_seconds': BOUNDS,
            'initial_topology_commands': netns_lab.plan_document(spec)['commands'],
            'clean_override': {'one_way_delay_ms': 0, 'loss_percent': 0, 'mtu': 1500},
            'policy': policy(), 'flows': flows,
            'profile': ['--traffic', 'proxy', '--carrier', 'tcp', '--layer', 'tun', '--device', 'tun0',
                        '--record-profile', 'frame', '--compression', 'off', '--max-packet', '1600',
                        '--duplex', duplex],
            'acceptance': 'exact split IPv4/IPv6 TCP, transparent ICMP/denial/reverse, native FIN, peer closure, cleanup'}


STATUS_FIELDS = {'phase', 'flows', 'active', 'stopped', 'retired', 'queued_bytes', 'queued_records',
                 'transparent_admitted_bytes', 'transparent_admitted_packets', 'native_confirmed_packets'}
CLOSE_FIELDS = {'local_user_records', 'peer_user_records', 'local_transparent_packets',
                'native_confirmed_packets', 'clean_flows', 'stopped_flows', 'tls_lanes_closed'}


def integers(value: dict, fields: set[str]):
    if any(type(value.get(key)) is not int or not 0 <= value[key] < 2**64 for key in fields):
        raise ValueError('missing or invalid bounded integer counter')


def validate_proxy_snapshot(response: dict, digest: str | None = None, phase: str | None = None,
                            allow_starting: bool = False) -> dict:
    if (not isinstance(response, dict) or set(response) != {'version', 'ok', 'code', 'state'}
            or response['version'] != 1 or type(response['version']) is not int
            or type(response['ok']) is not bool or not isinstance(response['code'], str)
            or len(response['code']) > 64):
        raise ValueError('invalid local response envelope')
    state = response['state']
    if (not isinstance(state, dict) or set(state) != {'epoch', 'phase', 'compression', 'proxy'}
            or type(state['epoch']) is not int or state['epoch'] != 1 or state['compression'] != 'off'):
        raise ValueError('response is not the exact immutable proxy profile')
    proxy = state['proxy']
    if (not isinstance(proxy, dict) or set(proxy) != {'digest', 'drain_accepted', 'runtime', 'terminal'}
            or type(proxy['drain_accepted']) is not bool
            or not isinstance(proxy['digest'], str) or not re.fullmatch('[0-9a-f]{64}', proxy['digest'])
            or digest is not None and proxy['digest'] != digest):
        raise ValueError('proxy profile digest or fields mismatch')
    runtime = proxy['runtime']
    if runtime is None and allow_starting and state['phase'] == 'Starting' and proxy['terminal'] is None:
        return proxy
    if not isinstance(runtime, dict) or set(runtime) != STATUS_FIELDS:
        raise ValueError('actual runtime snapshot required')
    integers(runtime, STATUS_FIELDS - {'phase'})
    if runtime['phase'] not in ('Starting', 'Forwarding', 'Quiescing', 'Closing', 'Closed', 'Failed'):
        raise ValueError('unknown runtime phase')
    if state['phase'] != runtime['phase'] or phase is not None and runtime['phase'] != phase:
        raise ValueError('runtime phase mismatch')
    terminal = proxy['terminal']
    if terminal is not None:
        if not isinstance(terminal, dict):
            raise ValueError('invalid terminal result')
        if terminal.get('outcome') == 'closed' and set(terminal) == {'outcome', 'report'}:
            if not isinstance(terminal['report'], dict) or set(terminal['report']) != CLOSE_FIELDS:
                raise ValueError('invalid final report')
            integers(terminal['report'], CLOSE_FIELDS)
        elif (terminal.get('outcome') == 'failed' and set(terminal) == {'outcome', 'error'}
              and isinstance(terminal['error'], str) and len(terminal['error']) <= 256):
            pass
        else:
            raise ValueError('unknown or oversized terminal outcome')
    return proxy


def verify_peer_closures(peers: dict[str, dict], lanes: int, expected_owners: int = 2) -> dict:
    if set(peers) != {'a', 'b'} or lanes not in (1, 2):
        raise ValueError('two exact peer completions required')
    reports = {}
    digest = None
    for side, response in peers.items():
        observed = validate_proxy_snapshot(response, digest, 'Closed')
        digest = observed['digest']
        if observed['terminal'] is None or observed['terminal']['outcome'] != 'closed':
            raise ValueError('acceptance/status is not terminal closure')
        report = observed['terminal']['report']
        if (report['tls_lanes_closed'] != lanes or report['clean_flows'] != expected_owners
                or report['stopped_flows'] != 0 or observed['runtime']['flows'] != expected_owners
                or observed['runtime']['active'] != 0 or observed['runtime']['stopped'] != 0
                or observed['runtime']['queued_records'] != 0 or observed['runtime']['queued_bytes'] != 0):
            raise ValueError('proxy owners or original TLS lanes did not drain cleanly')
        reports[side] = report
    for a, b in ((reports['a'], reports['b']), (reports['b'], reports['a'])):
        if (a['local_user_records'] != b['peer_user_records']
                or a['local_transparent_packets'] != b['native_confirmed_packets']):
            raise ValueError('cross-peer exact native/user fences disagree')
    return reports


def rpc(path: Path, action: str, deadline: float) -> dict:
    end = min(deadline, time.monotonic() + BOUNDS['rpc'])
    payload = json.dumps({'version': 1, 'action': {'command': action}}, separators=(',', ':')).encode()
    def receive(stream, length):
        result = bytearray()
        while len(result) < length:
            stream.settimeout(remaining(end, BOUNDS['rpc']))
            chunk = stream.recv(length - len(result))
            if not chunk:
                raise ValueError('truncated local response')
            result.extend(chunk)
        return bytes(result)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(remaining(end, BOUNDS['rpc']))
        stream.connect(str(path))
        stream.sendall(struct.pack('!I', len(payload)) + payload)
        length, = struct.unpack('!I', receive(stream, 4))
        if not 0 < length <= REPLY_LIMIT:
            raise ValueError('local reply exceeds fixed bound')
        return strict_json(receive(stream, length))


def payload(length: int, seed: int) -> bytes:
    return bytes((i * 73 + seed) & 255 for i in range(length))


def probe_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description='Internal finite kernel TCP probe')
    parser.add_argument('role', choices=['listen', 'connect'])
    parser.add_argument('source', type=ipaddress.ip_address)
    parser.add_argument('destination', type=ipaddress.ip_address)
    parser.add_argument('source_port', type=int)
    parser.add_argument('destination_port', type=int)
    args = parser.parse_args(argv)
    if args.source.version != args.destination.version or not all(0 < p <= 65535 for p in (args.source_port, args.destination_port)):
        raise ValueError('invalid probe tuple')
    family = socket.AF_INET if args.source.version == 4 else socket.AF_INET6
    end = time.monotonic() + BOUNDS['transfer']
    source, destination = (str(args.source), args.source_port), (str(args.destination), args.destination_port)
    listener = None
    if args.role == 'listen':
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(destination)
        listener.listen(1)
        listener.settimeout(remaining(end, BOUNDS['transfer']))
        print('Listening', flush=True)
        stream, _ = listener.accept()
        outgoing, expected = payload(PAYLOAD_LENGTHS[1], 29), payload(PAYLOAD_LENGTHS[0], 11)
    else:
        stream = socket.socket(family, socket.SOCK_STREAM)
        stream.bind(source)
        stream.settimeout(remaining(end, BOUNDS['transfer']))
        stream.connect(destination)
        outgoing, expected = payload(PAYLOAD_LENGTHS[0], 11), payload(PAYLOAD_LENGTHS[1], 29)
    errors = []
    def send():
        try:
            for offset in range(0, len(outgoing), 4096):
                stream.settimeout(remaining(end, BOUNDS['probe_inactivity']))
                stream.sendall(outgoing[offset:offset + 4096])
            stream.shutdown(socket.SHUT_WR)
        except Exception as error:
            errors.append(error)
    worker = threading.Thread(target=send, daemon=True)
    worker.start()
    received = bytearray()
    try:
        while True:
            stream.settimeout(remaining(end, BOUNDS['probe_inactivity']))
            chunk = stream.recv(min(4096, len(expected) + 1 - len(received)))
            if not chunk:
                break
            received.extend(chunk)
            if len(received) > len(expected):
                raise ValueError('native probe received excess bytes')
        worker.join(remaining(end, BOUNDS['probe_inactivity']))
        if worker.is_alive() or errors or received != expected:
            raise RuntimeError(f'native probe send/read/EOF failed: {errors!r}')
        print(json.dumps({'role': args.role, 'source': list(source), 'destination': list(destination),
                          'sent_bytes': len(outgoing), 'received_bytes': len(received),
                          'sent_sha256': hashlib.sha256(outgoing).hexdigest(),
                          'received_sha256': hashlib.sha256(received).hexdigest(), 'eof': True}), flush=True)
    finally:
        stream.close()
        if listener is not None:
            listener.close()
    return 0


def verify_probe(result: dict, flow: dict, role: str) -> None:
    if (set(result) != {'role', 'source', 'destination', 'sent_bytes', 'received_bytes',
                       'sent_sha256', 'received_sha256', 'eof'} or result['role'] != role
            or result['source'] != [flow['source'], flow['source_port']]
            or result['destination'] != [flow['destination'], flow['destination_port']]
            or result['eof'] is not True):
        raise ValueError('native probe identity/EOF mismatch')
    integers(result, {'sent_bytes', 'received_bytes'})
    first, second = payload(PAYLOAD_LENGTHS[0], 11), payload(PAYLOAD_LENGTHS[1], 29)
    sent, received = (first, second) if role == 'connect' else (second, first)
    if (result['sent_bytes'] != len(sent) or result['received_bytes'] != len(received)
            or result['sent_sha256'] != hashlib.sha256(sent).hexdigest()
            or result['received_sha256'] != hashlib.sha256(received).hexdigest()):
        raise ValueError('native probe byte/hash mismatch')


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


@dataclass(frozen=True)
class Packet:
    source: str
    destination: str
    protocol: int
    source_port: int
    destination_port: int
    sequence: int
    flags: int
    raw: bytes


def decode_ip(raw: bytes) -> Packet:
    if not raw:
        raise ValueError('empty IP packet')
    version = raw[0] >> 4
    if version == 4:
        if len(raw) < 20:
            raise ValueError('truncated IPv4')
        size, fragment = struct.unpack('!HH', raw[2:4] + raw[6:8])
        header = (raw[0] & 15) * 4
        if header != 20 or fragment & 0x3fff:
            raise Unsupported('IP options/fragment capture not supported by clean gate')
        if size < header or size > len(raw) or checksum(raw[:header]):
            raise ValueError('IPv4 size/header checksum')
        source, destination = raw[12:16], raw[16:20]
        protocol, body = raw[9], raw[header:size]
        pseudo = source + destination + bytes([0, protocol]) + struct.pack('!H', len(body))
    elif version == 6:
        if len(raw) < 40:
            raise ValueError('truncated IPv6')
        size = 40 + struct.unpack('!H', raw[4:6])[0]
        if size <= 40 or size > len(raw):
            raise ValueError('IPv6 size')
        source, destination, protocol = raw[8:24], raw[24:40], raw[6]
        body = raw[40:size]
        pseudo = source + destination + struct.pack('!I', len(body)) + bytes([0, 0, 0, protocol])
    else:
        raise Unsupported('unknown IP version')
    if size > 1500:
        raise ValueError('whole IP packet exceeds frozen MTU')
    sport = dport = seq = flags = 0
    if protocol == 6:
        if len(body) < 20 or not 20 <= (body[12] >> 4) * 4 <= len(body) or checksum(pseudo + body):
            raise ValueError('TCP length/checksum')
        sport, dport, seq = struct.unpack('!HHI', body[:8])
        flags = body[13]
    elif protocol in (1, 58):
        if len(body) < 8 or checksum(body if protocol == 1 else pseudo + body):
            raise ValueError('ICMP length/checksum')
    else:
        raise Unsupported('unexpected native IP protocol/extension')
    return Packet(str(ipaddress.ip_address(source)), str(ipaddress.ip_address(destination)),
                  protocol, sport, dport, seq, flags, raw[:size])


def read_pcap(path: Path) -> list[Packet]:
    if path.stat().st_size > CAPTURE_LIMIT:
        raise ValueError('capture file exceeds fixed bound')
    data = path.read_bytes()
    magic = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
             b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    if len(data) < 24 or data[:4] not in magic:
        raise Unsupported('unsupported/truncated capture format')
    endian = magic[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + 'HHIIII', data[4:24])
    if (major, minor) != (2, 4) or snaplen < 1500 or linktype not in (1, 101, 113, 276):
        raise Unsupported('unsupported capture link/version/snapshot')
    packets, cursor, count = [], 24, 0
    while cursor < len(data):
        if len(data) - cursor < 16:
            raise ValueError('truncated capture record header')
        _, _, captured, original = struct.unpack(endian + 'IIII', data[cursor:cursor + 16])
        cursor += 16
        if captured != original or captured > 65535 + 20 or captured > len(data) - cursor:
            raise ValueError('truncated/oversized capture record')
        frame = data[cursor:cursor + captured]
        cursor += captured
        count += 1
        if count >= PACKET_LIMIT:
            raise ValueError('capture packet cap exhausted')
        offset, ether = 0, None
        if linktype == 1:
            offset = 14
            if len(frame) < offset: raise ValueError('truncated Ethernet')
            ether = int.from_bytes(frame[12:14], 'big')
        elif linktype == 113:
            offset = 16
            if len(frame) < offset: raise ValueError('truncated SLL')
            ether = int.from_bytes(frame[14:16], 'big')
        elif linktype == 276:
            offset = 20
            if len(frame) < offset: raise ValueError('truncated SLL2')
            ether = int.from_bytes(frame[:2], 'big')
        if ether == 0x806:
            continue
        if ether not in (None, 0x800, 0x86dd):
            raise Unsupported('unknown captured link protocol')
        packet = decode_ip(frame[offset:])
        # Only Ethernet minimum-frame padding may follow the declared IP bytes.
        # Raw TUN captures must be exact; extra capture bytes cannot hide an MTU breach.
        trailing = len(frame) - offset - len(packet.raw)
        if trailing and (linktype == 101 or len(frame) - offset > 46):
            raise ValueError('unexpected bytes beyond declared IP packet')
        packets.append(packet)
    if not packets:
        raise ValueError('empty IP capture')
    return packets


def audit_native_captures(paths: dict[str, Path], flows: list[dict], lanes: int) -> dict:
    if set(paths) != {'a_native', 'b_native', 'a_wan', 'b_wan'}:
        raise ValueError('four complete capture surfaces required')
    captures = {name: read_pcap(path) for name, path in paths.items()}
    evidence = []
    for flow in flows:
        def selected(p, reverse=False):
            first = (flow['source'], flow['source_port'])
            second = (flow['destination'], flow['destination_port'])
            if reverse: first, second = second, first
            return p.protocol == 6 and (p.source, p.source_port) == first and (p.destination, p.destination_port) == second
        initial, initial_ack = {}, {}
        for side in ('a', 'b'):
            packets = captures[f'{side}_native']
            initial[side] = [p for p in packets if selected(p) and p.flags & 0x12 == 2]
            initial_ack[side] = [p for p in packets if selected(p, True) and p.flags & 0x12 == 0x12]
            if (not initial[side] or not initial_ack[side]
                    or any(not any(selected(p, reverse) and p.flags & 1 for p in packets) for reverse in (False, True))):
                raise ValueError('missing complete native handshake/bidirectional FIN')
            if any((selected(p) or selected(p, True)) and p.flags & 4 for p in packets):
                raise ValueError('reset observed in clean native TCP gate')
        seqs = {side: sorted({p.sequence for p in initial[side]}) for side in ('a', 'b')}
        acknowledgers = {side: sorted({p.sequence for p in initial_ack[side]}) for side in ('a', 'b')}
        if flow['split']:
            if seqs['a'] == seqs['b'] and acknowledgers['a'] == acknowledgers['b']:
                raise ValueError('transparent handshake cannot prove independent proxy legs')
        elif not {p.raw for p in initial['a']}.intersection(p.raw for p in initial['b']):
            raise ValueError('bypass did not preserve an exact original SYN')
        evidence.append({'flow': flow, 'syn_sequences': seqs, 'synack_sequences': acknowledgers,
                         'both_fin': True, 'reset': False})
    carriers = {}
    for side in ('a', 'b'):
        packets = captures[f'{side}_wan']
        if any(p.source.startswith(('198.19.', 'fd42:12:19:')) or p.destination.startswith(('198.19.', 'fd42:12:19:')) for p in packets):
            raise ValueError('native tuple escaped directly to wan0')
        pairs = {(p.source, p.source_port, p.destination, p.destination_port) for p in packets
                 if p.protocol == 6 and p.flags & 0x12 == 2}
        if len(pairs) != lanes or any(a != '192.0.2.2' or b != '192.0.2.6' or port != 18443 for a, _, b, port in pairs):
            raise ValueError('underlay does not contain exactly the original authenticated lanes')
        carriers[side] = sorted(pairs)
    if carriers['a'] != carriers['b']:
        raise ValueError('underlay carrier tuples disagree across captures')
    return {'flows': evidence, 'carriers': carriers,
            'packet_counts': {name: len(value) for name, value in captures.items()},
            'maximum_whole_ip_bytes': {name: max(map(lambda p: len(p.raw), value)) for name, value in captures.items()}}


def capture_counts(text: str) -> dict:
    result = {}
    for field in ('captured', 'received by filter', 'dropped by kernel'):
        matches = re.findall(rf'^(\d+) packets {field}$', text, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError('missing/duplicate complete capture counters')
        result[field] = int(matches[0])
    if not 0 < result['captured'] < PACKET_LIMIT or result['dropped by kernel']:
        raise ValueError('empty/exhausted/lossy capture')
    return result


def limited_child(maximum: int):
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    return limit


def stop(process: subprocess.Popen, interrupt=False):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT if interrupt else signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def launch(argv: list[str], log: Path, cap=LOG_LIMIT) -> subprocess.Popen:
    with log.open('xb') as stream:
        return subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                                preexec_fn=limited_child(cap))


def wait_log(process: subprocess.Popen, path: Path, marker: str, deadline: float):
    while marker not in read_log(path):
        if process.poll() is not None:
            raise RuntimeError(f'child exited before {marker}: {path.read_text()}')
        time.sleep(min(0.05, remaining(deadline, 0.05)))


def read_log(path: Path) -> str:
    if path.stat().st_size > LOG_LIMIT:
        raise ValueError('log exceeds fixed bound')
    return path.read_text()


def start_capture(argv: list[str], path: Path, deadline: float):
    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               preexec_fn=limited_child(CAPTURE_LIMIT))
    initial = bytearray()
    try:
        while b'listening on' not in initial:
            if process.stderr is None or process.poll() is not None:
                raise RuntimeError('capture exited before readiness')
            ready, _, _ = select.select([process.stderr], [], [], remaining(deadline, 5))
            if not ready:
                raise TimeoutError('capture readiness deadline')
            part = os.read(process.stderr.fileno(), 4096)
            if not part:
                raise RuntimeError('capture stderr closed before readiness')
            initial.extend(part)
            if len(initial) > LOG_LIMIT:
                raise ValueError('capture diagnostics bound')
        path.write_bytes(initial)
        return process
    except Exception:
        stop(process)
        path.write_bytes(initial[:LOG_LIMIT])
        raise


def finish_capture(process: subprocess.Popen, path: Path) -> dict:
    stop(process, interrupt=True)
    if process.stderr is None:
        raise RuntimeError('capture diagnostics pipe missing')
    tail = process.stderr.read(LOG_LIMIT + 1)
    process.stderr.close()
    prior = path.read_bytes()
    if len(prior) + len(tail) > LOG_LIMIT:
        raise ValueError('capture diagnostic bound')
    path.write_bytes(prior + tail)
    return capture_counts(read_log(path))


def offloads(namespace: str, interface: str, deadline: float) -> dict:
    prefix = ['ip', 'netns', 'exec', namespace, 'ethtool']
    names = {'tx-checksumming': 'tx', 'tcp-segmentation-offload': 'tso',
             'generic-segmentation-offload': 'gso', 'generic-receive-offload': 'gro'}
    before = command([*prefix, '-k', interface], deadline)
    changes = []
    for feature, option in names.items():
        found = re.search(rf'^{feature}: (on|off)(.*)$', before, re.MULTILINE)
        if found is None:
            raise Unsupported(f'offload evidence missing: {interface}/{feature}')
        if found[1] == 'on':
            if '[fixed]' in found[2]:
                raise Unsupported(f'cannot disable observed offload: {interface}/{feature}')
            changes += [option, 'off']
    if changes:
        command([*prefix, '-K', interface, *changes], deadline)
    after = command([*prefix, '-k', interface], deadline)
    if any(not re.search(rf'^{feature}: off(?: |$)', after, re.MULTILINE) for feature in names):
        raise Unsupported('owned path offloads remain enabled')
    return {'before': before, 'after': after}


def disable_underlay_ipv6(namespaces: dict, deadline: float) -> dict:
    """Suppress unrelated MLD only on the four owned IPv4 underlay interfaces."""
    evidence = {}
    for role, interface in [('endpoint_a', 'wan0'), ('endpoint_b', 'wan0'), ('router', 'a0'), ('router', 'b0')]:
        prefix = ['ip', 'netns', 'exec', namespaces[role], 'sysctl']
        key = f'net.ipv6.conf.{interface}.disable_ipv6'
        before = command([*prefix, '-n', key], deadline).strip()
        if before not in ('0', '1'):
            raise Unsupported('missing original underlay IPv6 state')
        command([*prefix, '-q', '-w', key + '=1'], deadline)
        after = command([*prefix, '-n', key], deadline).strip()
        if after != '1':
            raise Unsupported('owned IPv4 underlay IPv6 remains active')
        evidence[f'{role}/{interface}'] = {'before': int(before), 'after': int(after)}
    return evidence


def run_case(plan: dict, binary: Path, harness: Path, output: Path, secrets: Path, state_dir: Path) -> dict:
    start = time.monotonic()
    end = start + BOUNDS['case']
    spec = netns_lab.LabSpec(plan['lab_id'])
    ns = spec.namespaces
    case_dir = output / plan['case']
    case_dir.mkdir()
    receipt = Receipt(case_dir / 'receipt.json', {'status': 'running', 'plan': plan, 'stage': 'setup', 'cleanup': 'pending'})
    processes, captures, capture_paths, sockets, samples, events = [], {}, {}, {}, [], []
    created = False
    def nsrun(side, *argv): return ['ip', 'netns', 'exec', ns[f'endpoint_{side}'], *argv]
    def stage(name, **fields):
        if len(events) >= 32:
            raise RuntimeError('stage evidence bound exhausted')
        events.append({'stage': name, 'elapsed_seconds': time.monotonic() - start,
                       'details': strict_json(json.dumps(fields))})
        receipt.update(stage=name, elapsed_seconds=time.monotonic() - start,
                       events=events, status_samples=samples)
    def snapshots(deadline):
        if len(samples) >= 2048:
            raise RuntimeError('status sample bound exhausted')
        result = {side: rpc(path, 'status', deadline) for side, path in sockets.items()}
        samples.append({'elapsed_seconds': time.monotonic() - start, 'peers': result})
        return result
    failure = None
    try:
        bounded_lab(netns_lab.apply, spec, state_dir, end)
        created = True
        underlay_ipv6 = disable_underlay_ipv6(ns, end)
        features, ecn = {}, {}
        for side in ('a', 'b'):
            endpoint = ns[f'endpoint_{side}']
            command(nsrun(side, 'tc', 'qdisc', 'change', 'dev', 'wan0', 'parent', '1:10', 'handle', '10:',
                          'netem', 'limit', '1000', 'delay', '0ms', 'loss', '0%'), end)
            command(['ip', '-n', endpoint, 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun'], end)
            command(['ip', '-n', endpoint, 'link', 'set', 'tun0', 'mtu', '1500', 'up'], end)
            number = 1 if side == 'a' else 2
            command(['ip', '-n', endpoint, 'address', 'add', f'198.19.0.{number}/24', 'dev', 'tun0'], end)
            command(['ip', '-n', endpoint, '-6', 'address', 'add', f'fd42:12:19::{number}/64', 'dev', 'tun0', 'nodad'], end)
            ecn[side] = command(nsrun(side, 'sysctl', 'net.ipv4.tcp_ecn'), end)
            command(nsrun(side, 'sysctl', '-q', '-w', 'net.ipv4.tcp_ecn=0'), end)
            for interface in ('wan0', 'tun0'):
                features[f'{side}-{interface}'] = offloads(endpoint, interface, end)
            private = secrets / f'{plan["duplex"]}-{side}'
            private.mkdir(mode=0o700)
            sockets[side] = private / 'proxy.sock'
        for interface in ('a0', 'b0'):
            features[f'router-{interface}'] = offloads(ns['router'], interface, end)
        stage('capture_start', offloads=features, original_owned_ecn=ecn, underlay_ipv6=underlay_ipv6,
              qdiscs={side: command(nsrun(side, 'tc', '-s', 'qdisc', 'show', 'dev', 'wan0'), end) for side in ('a', 'b')})
        for side in ('a', 'b'):
            for label, interface in [('native', 'tun0'), ('wan', 'wan0')]:
                key = f'{side}_{label}'
                path, log = case_dir / f'{key}.pcap', case_dir / f'{key}-capture.log'
                process = start_capture(nsrun(side, 'tcpdump', '-U', '-n', '-i', interface, '-s', '0', '-c', str(PACKET_LIMIT), '-w', str(path)), log, min(end, time.monotonic() + 5))
                captures[key], capture_paths[key] = (process, log), path
                processes.append(process)
        stage('authenticate')
        common = [*plan['profile'], '--proxy-policy', str(output / 'policy.json')]
        daemons = {}
        for side, command_name, identity in [
            ('b', 'serve', ['--listen', '192.0.2.6:18443', '--cert', str(secrets / 'cert.der'), '--key', str(secrets / 'server.der'), '--allow-key', str(secrets / 'member.pub')]),
            ('a', 'connect', ['--remote', '192.0.2.6:18443', '--ca', str(secrets / 'cert.der'), '--server-name', 'lab.invalid', '--identity', str(secrets / 'member.der')])]:
            log = case_dir / f'{side}-daemon.log'
            process = launch(nsrun(side, str(binary), command_name, *identity, *common, '--control-socket', str(sockets[side])), log)
            processes.append(process)
            daemons[side] = (process, log)
            if side == 'b':
                listen_end = min(end, time.monotonic() + 5)
                while ':18443' not in command(nsrun(side, 'ss', '-Hltn'), listen_end):
                    if process.poll() is not None: raise RuntimeError(log.read_text())
                    time.sleep(min(0.05, remaining(listen_end, 0.05)))
        ready_end, digest = min(end, time.monotonic() + BOUNDS['startup']), None
        while True:
            if any(p.poll() is not None for p, _ in daemons.values()):
                raise RuntimeError('daemon exited during authentication/startup')
            try:
                values = snapshots(ready_end)
                current = {side: validate_proxy_snapshot(value, allow_starting=True) for side, value in values.items()}
                if all(value['runtime'] is not None and value['runtime']['phase'] == 'Forwarding' for value in current.values()):
                    digest = current['a']['digest']
                    for value in values.values():
                        state = validate_proxy_snapshot(value, digest, 'Forwarding')
                        if state['runtime']['flows'] != 0 or state['terminal'] is not None: raise ValueError('startup already owns traffic')
                    break
            except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
                pass
            time.sleep(min(0.1, remaining(ready_end, 0.1)))
        stage('transparent_icmp', digest=digest, startup_status=values,
              established={side: command(nsrun(side, 'ss', '-Htn', 'state', 'established'), end) for side in ('a', 'b')})
        pings = []
        for side, peer in [('a', '2'), ('b', '1')]:
            for family, address in [(4, f'198.19.0.{peer}'), (6, f'fd42:12:19::{peer}')]:
                for _ in range(3):
                    result = command(nsrun(side, 'ping', f'-{family}', '-c', '1', '-W', '2', '-s', '64', address), end, BOUNDS['ping'])
                    match = re.search(r'(\d+) packets transmitted, (\d+) received,.*?([0-9.]+)% packet loss', result)
                    if match is None or (int(match[1]), int(match[2]), float(match[3])) != (1, 1, 0.0): raise ValueError('inexact ICMP outcome')
                    pings.append({'side': side, 'family': family, 'stdout': result})
        baseline = snapshots(end)
        for value in baseline.values():
            state = validate_proxy_snapshot(value, digest, 'Forwarding')['runtime']
            if state['flows'] != 0 or state['transparent_admitted_packets'] < 6 or state['native_confirmed_packets'] < 6: raise ValueError('ICMP bypass accounting')
        stage('tcp_owned', icmp=pings, icmp_status=baseline)
        transfers = []
        for purpose in ('owned', 'denied', 'reverse'):
            stage('tcp_' + purpose)
            before = {side: validate_proxy_snapshot(value, digest)['runtime'] for side, value in snapshots(end).items()}
            batch = []
            transfer_end = min(end, time.monotonic() + BOUNDS['transfer'])
            for flow in [f for f in plan['flows'] if f['stage'] == purpose]:
                args = [flow['source'], flow['destination'], str(flow['source_port']), str(flow['destination_port'])]
                log = case_dir / f'{purpose}-{flow["family"]}-listen.log'
                server = launch(nsrun(flow['server_side'], sys.executable, str(harness), 'probe', 'listen', *args), log)
                processes.append(server)
                wait_log(server, log, 'Listening', transfer_end)
                client_log = case_dir / f'{purpose}-{flow["family"]}-connect.log'
                client = launch(nsrun(flow['client_side'], sys.executable, str(harness), 'probe', 'connect', *args), client_log)
                processes.append(client)
                batch.extend([(server, log, flow, 'listen'), (client, client_log, flow, 'connect')])
            for process, log, flow, role in batch:
                if process.wait(timeout=remaining(transfer_end, BOUNDS['transfer'])):
                    raise RuntimeError(f'kernel TCP probe failed: {log.read_text()}')
                result = strict_json(read_log(log).splitlines()[-1])
                verify_probe(result, flow, role)
                transfers.append(result)
            after = snapshots(end)
            for side, value in after.items():
                state = validate_proxy_snapshot(value, digest, 'Forwarding')['runtime']
                if state['flows'] != 2 or state['stopped'] != 0: raise ValueError('split owners missing or failed')
                if purpose != 'owned' and state['transparent_admitted_packets'] <= before[side]['transparent_admitted_packets']:
                    raise ValueError('bypass did not advance ordinary transparent counters')
            stage(purpose + '_complete', transfers=transfers, latest_status=after)
        drain_end = min(end, time.monotonic() + BOUNDS['drain_observation'])
        stage('drain', drain_original_monotonic=time.monotonic())
        accepted = {side: rpc(path, 'drain_proxy', drain_end) for side, path in sockets.items()}
        for value in accepted.values():
            validate_proxy_snapshot(value, digest)
            if not value['ok'] or value['code'] not in ('accepted', 'already_accepted'): raise ValueError('drain submission refused')
        stage('drain', drain_acceptance=accepted)
        terminal = {}
        while len(terminal) < 2:
            if len(samples) >= 2048:
                raise RuntimeError('status sample bound exhausted')
            observed = {}
            for side, path in sockets.items():
                if side in terminal: continue
                value = rpc(path, 'status', drain_end)
                observed[side] = value
                state = validate_proxy_snapshot(value, digest)
                if state['terminal'] is not None: terminal[side] = value
            samples.append({'elapsed_seconds': time.monotonic() - start, 'peers': observed})
            time.sleep(min(0.1, remaining(drain_end, 0.1)))
        reports = verify_peer_closures(terminal, plan['lanes'])
        for process, log in daemons.values():
            if process.wait(timeout=remaining(drain_end, BOUNDS['drain_observation'])):
                raise RuntimeError(f'daemon failed after terminal observation: {log.read_text()}')
        stage('capture_audit', terminal=terminal, close_reports=reports)
        counts = {}
        for key, (process, log) in captures.items():
            counts[key] = finish_capture(process, log)
        audit = audit_native_captures(capture_paths, plan['flows'], plan['lanes'])
        stage('completed', capture_counts=counts, capture_audit=audit,
              capture_sha256={name: file_hash(path) for name, path in capture_paths.items()})
    except Exception as error:
        failure = error
        status = ('bound_exhausted' if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else
                  'unsupported' if isinstance(error, Unsupported) else 'tool_failure' if isinstance(error, OSError) else 'failed')
        receipt.update(status=status, error=str(error)[:4096])
    finally:
        child_errors = []
        for process in reversed(processes):
            try:
                stop(process)
            except Exception as error:
                child_errors.append(str(error)[:256])
        for process, log in captures.values():
            if process.stderr is not None and not process.stderr.closed:
                try:
                    finish_capture(process, log)
                except Exception:
                    pass  # Failed evidence remains in its log; the case cannot pass.
        try:
            if created:
                bounded_lab(netns_lab.cleanup, spec, state_dir, time.monotonic() + BOUNDS['namespace_cleanup'])
            if child_errors:
                raise RuntimeError(f'owned child cleanup failed: {child_errors}')
            if any((netns_lab.NETNS_DIRECTORY / name).exists() for name in ns.values()):
                raise RuntimeError('owned namespaces remain after cleanup')
            for path in sockets.values():
                if path.exists():
                    raise RuntimeError('private socket remains after daemon cleanup')
            receipt.update(cleanup='passed', status='passed' if failure is None else receipt.value['status'], elapsed_seconds=time.monotonic() - start)
        except Exception as error:
            failure = error
            receipt.update(cleanup='failed', status='failed', cleanup_error=str(error)[:4096])
    if failure is not None:
        raise RuntimeError(f'{plan["case"]} failed; inspect {receipt.path}') from failure
    return receipt.value


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'probe':
        return probe_main(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-id', default='proxy')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/l2tunnel-linux')
    parser.add_argument('--build-receipt', type=Path, help='required for apply: original source-stable binary build receipt')
    parser.add_argument('--state-dir', type=Path, default=Path('/run/l2tunnel-labs'))
    parser.add_argument('--only-case', choices=['tun-full-clean', 'tun-half-clean'])
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    plans = [case_plan(args.lab_id, mode) for mode in ('full', 'half')
             if args.only_case is None or args.only_case == f'tun-{mode}-clean']
    if not args.apply:
        print(json.dumps({'status': 'dry_run', 'cases': plans, 'output': str(args.output),
                          'binary': str(args.binary), 'build_receipt': str(args.build_receipt) if args.build_receipt else None,
                          'mutations': 'none'}, indent=2))
        return 0
    if sys.platform != 'linux': raise Unsupported('native harness requires Linux')
    netns_lab.require_root()
    for tool in ('ip', 'tc', 'sysctl', 'ethtool', 'tcpdump', 'ss', 'ping', 'openssl'):
        if shutil.which(tool) is None: raise FileNotFoundError(f'required tool missing: {tool}')
    if args.build_receipt is None:
        raise ValueError('--build-receipt is required for apply')
    build = verified_build_receipt(args.build_receipt, args.binary)
    args.output.mkdir(mode=0o755)
    output = args.output.resolve()
    binary, harness = output / 'l2tunnel-native', output / 'proxy_native_smoke.py'
    shutil.copyfile(args.binary, binary)
    binary.chmod(0o755)
    shutil.copyfile(Path(__file__), harness)
    shutil.copyfile(Path(netns_lab.__file__), output / 'netns_lab.py')
    shutil.copyfile(args.build_receipt, output / 'build-receipt.json')
    if verified_build_receipt(output / 'build-receipt.json', binary) != build:
        raise ValueError('build receipt changed during immutable copy')
    (output / 'policy.json').write_text(json.dumps(policy(), indent=2) + '\n')
    receipt = Receipt(output / 'receipt.json', {'status': 'running', 'scope': 'clean native fixed-credit TUN proxy only',
        'binary_sha256': file_hash(binary), 'harness_sha256': file_hash(harness),
        'policy_sha256': file_hash(output / 'policy.json'),
        'build_receipt_sha256': file_hash(output / 'build-receipt.json'),
        'binary_build_source_sha256': build['source_sha256_after'],
        'source_observed_at_launch_sha256': source_hashes(),
        'cases': [], 'cleanup': 'pending'})
    cases = []
    try:
        with tempfile.TemporaryDirectory(prefix='l2t-proxy-secrets-') as directory:
            secrets = Path(directory)
            deadline = time.monotonic() + 30
            command([str(binary), 'keygen', '--private', str(secrets / 'member.der'), '--public', str(secrets / 'member.pub')], deadline)
            command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                     '-keyout', str(secrets / 'server.pem'), '-out', str(secrets / 'cert.pem'), '-days', '1',
                     '-subj', '/CN=lab.invalid', '-addext', 'subjectAltName=DNS:lab.invalid', '-addext', 'basicConstraints=critical,CA:FALSE'], deadline)
            command(['openssl', 'x509', '-in', str(secrets / 'cert.pem'), '-outform', 'DER', '-out', str(secrets / 'cert.der')], deadline)
            command(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(secrets / 'server.pem'), '-outform', 'DER', '-out', str(secrets / 'server.der')], deadline)
            for plan in plans:
                case = run_case(plan, binary, harness, output, secrets, args.state_dir)
                cases.append({'case': plan['case'], 'status': case['status'], 'cleanup': case['cleanup']})
                receipt.update(cases=cases)
        receipt.update(status='passed', cleanup='passed')
    except Exception as error:
        receipt.update(status='failed', error=str(error)[:4096], cleanup='inspect_case_receipt')
        raise
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
