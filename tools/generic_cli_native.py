#!/usr/bin/env python3
"""Production generic CLI TAP/TUN functional lab; dry-run unless --apply is explicit."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

try:
    from . import netns_lab as lab, proxy_native_smoke as bounded
    from . import secure_udp_native as native, secure_udp_native_probe as probe
except ImportError:
    import netns_lab as lab
    import proxy_native_smoke as bounded
    import secure_udp_native as native
    import secure_udp_native_probe as probe

HELPERS = ('generic_cli_native.py', *native.HELPERS)
LOADED = {'generic_cli_native.py': Path(__file__), **native.LOADED_HELPERS}
WAN = dict(native.WAN)
CONFIGURATION_DIGEST_DOMAIN = b'l2tunnel/swift-transaction-config/v1\0'
BOUNDS = {'case': 240, 'startup': 35, 'command': 15, 'cleanup': 30, 'launcher': 300,
          'log_bytes': 1024 * 1024, 'capture_bytes': 8 * 1024 * 1024,
          'capture_packets': 4096, 'snaplen': 2048, 'observations': 256}
STATUS_FIELDS = set(('generation carrier algorithm protection backend running elapsed_micros terminal '
    'service_terminal session transcript outer member initiator_noise responder_noise local peer '
    'configuration catalog catalog_members initial current requested epoch phase operation physical_scope '
    'send receive storage resource_preallocation_complete native_storage_capacity_bytes workspace_capacity_bytes '
    'loop_input_capacity_bytes wire native control security liveness swift_unconfirmed configuration_change '
    'coordinator reconnect cross_profile_switching retained_state_recovery fresh_rekey').split())
SUMMARIES = {'storage': set(('limit_bytes fixed_bytes external_bytes engine_bytes building_bytes peak_bytes').split()),
    'wire': set(('packets ip_bytes socket_accepted_packets socket_accepted_ip_bytes socket_drops '
                 'socket_receive_errors received_packets rejected_packets replay_rejections').split()),
    'native': set(('read written oversize backpressure_drops pending_packets pending_bytes').split()),
    'control': set(('send_records send_bytes receive_records receive_bytes').split()),
    'security': set(('user_number control_number user_generation control_generation').split()),
    'liveness': set(('ping deadline_micros last_verified_micros last_pong_micros').split())}
PLAN_FIELDS = set(('event schema backend carrier algorithm protection role requested validated authenticated '
    'resource_preallocation_complete configuration envelope catalog data_digest initial catalog_members '
    'configurations parameters report_interval member initiator_noise responder_noise local peer').split())


class Unsupported(RuntimeError):
    """A required native capability is absent; this is never a passing skip."""


def failure_status(error: Exception) -> str:
    if isinstance(error, (Unsupported, bounded.Unsupported)):
        return 'unsupported'
    if isinstance(error, bounded.CaptureBound):
        return 'bound_exhausted'
    if isinstance(error, ImportError):
        return 'tool_failure'
    return native.failure_status(error)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def uint(value, name: str, maximum: int = (1 << 64) - 1) -> int:
    require(type(value) is int and 0 <= value <= maximum, 'invalid unsigned ' + name)
    return value


def public_bytes(value, count: int, name: str) -> list[int]:
    require(isinstance(value, list) and len(value) == count, 'incorrect public ' + name)
    for byte in value:
        uint(byte, name, 255)
    require(any(value), 'empty public ' + name)
    return value


def checked_canonical(value) -> str:
    require(type(value) is str and re.fullmatch('[0-9a-f]{608}', value) is not None,
            'exact canonical608 lowercase characters required')
    # The actual CLI decoder remains authoritative; this is not a C encoder.
    return value


def configuration_digest(canonical: str) -> list[int]:
    """Match transaction::configuration_digest over the actual inspected C bytes."""
    return list(hashlib.sha256(CONFIGURATION_DIGEST_DOMAIN + bytes.fromhex(checked_canonical(canonical))).digest())


def credential_preflight():
    """Require the existing helper's maintained API before mutating topology."""
    import cryptography
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    if (not re.fullmatch(r'\d+(\.\d+){1,3}', cryptography.__version__)
            or not callable(X25519PrivateKey.generate) or Encoding.Raw is None
            or PrivateFormat.Raw is None or PublicFormat.Raw is None or not callable(NoEncryption)):
        raise native.ObservationError('reviewed cryptography X25519 Raw API version preflight failed')


def private_directory():
    """Called only after the copied worker has mounted its verified private /run."""
    return tempfile.TemporaryDirectory(prefix='l2t-gcn-', dir='/run')


def transaction_plan(layer: str) -> dict:
    require(layer in ('tap', 'tun'), 'explicit supported layer required')
    maximum = 1600 if layer == 'tap' else 1500
    def direction(forward):
        return {'channels': 2 if forward else 3, 'layer': 'ethernet' if layer == 'tap' else 'ip',
            'max_native': maximum, 'bytes_per_second': 1_250_001 if forward else 625_013,
            'datagram_bytes': 1200 if forward else 1024, 'window': 7 if forward else 11,
            'repair_numerator': 1 if forward else 2, 'repair_denominator': 3 if forward else 7,
            'flow_sources': 64, 'queue_bytes': 8192, 'max_packet': maximum + 1,
            'flush_micros': 1000, 'feedback_micros': 5000, 'tail_micros': 10000,
            'min_rto_micros': 20000, 'max_rto_micros': 1_000_000}
    initial = {'path_mtu': 1500, 'forward': direction(True), 'reverse': direction(False)}
    target = copy.deepcopy(initial)
    target['path_mtu'] = 1400
    target['forward'].update(channels=4, bytes_per_second=1_375_007, datagram_bytes=1280)
    target['reverse'].update(channels=1, bytes_per_second=575_011, datagram_bytes=1100)
    message = {'max_message_bytes': 4096, 'max_outbound_messages': 4, 'max_outbound_bytes': 131072,
        'max_fragments': 32, 'max_reassembly_bytes': 16384, 'max_incomplete_messages': 2,
        'message_lifetime_micros': 5_000_000, 'work_per_call': 8}
    return {'version': 1, 'backend': 'generic_swift_v1', 'initial_index': 0, 'catalog': [initial, target],
        'transaction': {'retry_ms': 10, 'phase_timeout_ms': 500, 'reconcile_timeout_ms': 1000,
            'max_operation_ms': 1500, 'retained_bytes': 64 * 1024 * 1024},
        'runtime': {'control_epoch': 1, 'data_epoch': 1,
            'legacy_policy': {'transaction_micros': 10_000_000, 'max_outbound': 32},
            'security': {'packets_per_key': 1 << 28, 'max_body_bytes_per_key': 1 << 40},
            'control': {'recovery': {'max_source_bytes': 256, 'send_bytes': 8192, 'receive_bytes': 8192,
                'send_records': 32, 'receive_records': 32, 'initial_rto_micros': 10000,
                'maximum_rto_micros': 100000, 'ack_delay_micros': 1000, 'max_retries': 32},
                'interval_micros': 10000, 'packets_per_interval': 4, 'bytes_per_interval': 4096},
            'streams': {name: dict(message) for name in ('transaction', 'liveness', 'data_feedback')},
            'wire': {'initiator_burst_bytes': 8192, 'responder_burst_bytes': 6144},
            'work': {'receive_interval_micros': 1000, 'receive_packets': 256, 'send_batch': 64,
                'native_read_batch': 64, 'native_write_batch': 64},
            'native': {'pending_packets': 64, 'pending_bytes': maximum * 64,
                'stall_timeout_micros': 10_000_000},
            'lifetime': {'lease_micros': 300_000_000, 'ping_interval_micros': 100_000,
                'pong_timeout_micros': 5_000_000},
            'credit': {'floor_datagrams': 64, 'ceiling_datagrams': 8192, 'floor_bytes': 102400,
                'ceiling_bytes': 16777216, 'period_micros': 10000, 'idle_period_micros': 250000},
            'report_interval_micros': 100_000}}


def plan(lab_id: str, cover: str, layer: str) -> dict:
    require(cover in ('quic-like', 'media-like') and layer in ('tap', 'tun'),
            'explicit supported cover/layer required')
    spec = lab.LabSpec(lab_id)
    return {'lab_id': lab_id, 'cover': cover, 'layer': layer, 'namespaces': spec.namespaces,
        'device': 'tap0' if layer == 'tap' else 'tun0', 'max_native': 1600 if layer == 'tap' else 1500,
        'applications': {side: {'role': ('host_' if layer == 'tap' else 'endpoint_') + side,
            'address': ('198.18.0.' if layer == 'tap' else '198.19.0.') + str(index)}
            for index, side in enumerate(('a', 'b'), 1)},
        'backend': 'generic_swift_v1', 'one_way_delay_ms': 0, 'loss_percent_per_direction': 0,
        'udp_pair': [WAN[side] + ':24440' for side in ('a', 'b')],
        'scope': 'production generic CLI Linux native functional only',
        'tun_topology': 'endpoint-originated; unused TAP/bridge links down' if layer == 'tun' else None,
        'shared_htb_mbps': {'a_to_b': 100, 'b_to_a': 10}, 'bounds': dict(BOUNDS),
        'transaction_plan': transaction_plan(layer), 'performance_qualified': False,
        'not_qualified': ['80Mbit/s performance', 'impaired/native/full64 resource matrix',
            'all native hash channels', 'full GCS06/GCS07/GCS09', 'SW-11 and mode parity',
            'automatic retained recovery', 'fresh-DH rekey', 'Windows/Android/GUI',
            'protocol interoperability/identification resistance/ISP QoS']}


def daemon_command(case: dict, side: str, binary: Path, secrets: Path,
                   plan_file: Path, inspection: bool = False) -> list[str]:
    require(side in ('a', 'b') and type(inspection) is bool, 'explicit endpoint role required')
    require(case == plan(case['lab_id'], case['cover'], case['layer']), 'case differs from frozen plan')
    other = 'b' if side == 'a' else 'a'
    role = 'connect' if side == 'a' else 'serve'
    argv = [str(binary), *(['inspect-swift-transaction-plan', '--role', role] if inspection else [role]),
        '--carrier', case['cover'], '--record-profile', 'swift', '--duplex', 'full', '--compression', 'off',
        '--layer', case['layer'], '--max-packet', str(case['max_native']), '--max-path-mtu', '9000',
        '--udp-bind', WAN[side] + ':24440', '--udp-peer', WAN[other] + ':24440', '--noise-profile', 'ik',
        '--noise-private-key-file', str(secrets / f'noise-{side}.key'),
        '--noise-peer-key-file', str(secrets / f'noise-{other}.pub'),
        '--swift-transaction-plan', str(plan_file)]
    argv += ['--identity' if side == 'a' else '--allow-key',
             str(secrets / ('member.der' if side == 'a' else 'member.pub'))]
    if not inspection:
        argv += ['--device', case['device'], '--session-admission-key-file', str(secrets / 'admission.key'),
                 '--control-socket', str(secrets / f'control-{side}.sock')]
        if side == 'b':
            argv += ['--session-cookie-key-file', str(secrets / 'cookie.key')]
    return argv


def validate_inspection(value: dict, case: dict, side: str, public: dict) -> dict:
    require(side in ('a', 'b') and isinstance(value, dict) and set(value) == PLAN_FIELDS,
            'unexpected complete inspection schema')
    expected = {'event': 'secure_udp_transaction_plan', 'schema': 1, 'backend': case['backend'],
        'carrier': case['cover'], 'algorithm': 'swift', 'protection': 'chacha20-poly1305',
        'role': 'initiator' if side == 'a' else 'responder', 'requested': True, 'validated': True,
        'authenticated': False, 'resource_preallocation_complete': False, 'catalog_members': 2,
        'parameters': case['transaction_plan']['transaction'],
        'report_interval': {'seconds': 0, 'nanoseconds': 100_000_000},
        'member': public['member_public'], 'initiator_noise': public['noise_public']['a'],
        'responder_noise': public['noise_public']['b'], 'local': WAN[side] + ':24440',
        'peer': WAN['b' if side == 'a' else 'a'] + ':24440'}
    for key, expected_value in expected.items():
        require(type(value[key]) is type(expected_value) and value[key] == expected_value,
                'inspection differs: ' + key)
    for key in ('configuration', 'envelope', 'catalog', 'data_digest', 'member', 'initiator_noise', 'responder_noise'):
        public_bytes(value[key], 32, key)
    require(isinstance(value['configurations'], list) and len(value['configurations']) == 2,
            'full finite catalog missing')
    values = [checked_canonical(item) for item in value['configurations']]
    require(values == sorted(set(values)) and checked_canonical(value['initial']) in values,
            'inspection catalog not complete canonical sorted values')
    require(value['data_digest'] == configuration_digest(value['initial']), 'inspection initial physical digest differs')
    require(len(json.dumps(value).encode()) < 128 * 1024, 'inspection output exceeds bounded line')
    return value


def validate_status(response: dict, case: dict, side: str, public: dict,
                    inspected: dict, canonical: str, epoch: int, running: bool = True) -> dict:
    require(side in ('a', 'b') and type(running) is bool and type(epoch) is int and epoch > 0,
            'explicit actual role/epoch/running state required')
    require(isinstance(response, dict) and set(response) == {'version', 'ok', 'code', 'state'}
        and type(response['version']) is int and response['version'] == 3
        and response['ok'] is True and response['code'] == 'ok', 'successful explicit APIv3 reply required')
    state = response['state']
    require(isinstance(state, dict) and set(state) == {'epoch', 'phase', 'compression', 'transaction'}
        and type(state['epoch']) is int and state['epoch'] == epoch and state['compression'] == 'off'
        and type(state['phase']) is str and state['phase'] == ('forwarding' if running else 'disconnected'),
        'generic reply projected a legacy backend or wrong Bank epoch')
    status = state.get('transaction')
    require(isinstance(status, dict) and set(status) == STATUS_FIELDS, 'unexpected v3 status schema')
    initial = checked_canonical(inspected['initial'])
    canonical_value = checked_canonical(canonical)
    values = inspected['configurations']
    require(canonical_value in values, 'expected C not in actual inspected catalog')
    descriptor = case['transaction_plan']['catalog'][0 if canonical_value == initial else 1]
    expected = {'carrier': case['cover'], 'algorithm': 'swift', 'protection': 'chacha20-poly1305',
        'backend': case['backend'], 'running': running, 'configuration': inspected['configuration'],
        'catalog': inspected['catalog'], 'catalog_members': 2, 'initial': initial, 'current': canonical_value,
        'epoch': epoch, 'phase': 'idle', 'operation': None, 'resource_preallocation_complete': False,
        'member': public['member_public'], 'initiator_noise': public['noise_public']['a'],
        'responder_noise': public['noise_public']['b'], 'local': WAN[side] + ':24440',
        'peer': WAN['b' if side == 'a' else 'a'] + ':24440', 'configuration_change': True,
        'coordinator': side == 'a', 'reconnect': True, 'cross_profile_switching': False,
        'retained_state_recovery': False, 'fresh_rekey': False,
        'send': descriptor['forward' if side == 'a' else 'reverse'],
        'receive': descriptor['reverse' if side == 'a' else 'forward']}
    for key, expected_value in expected.items():
        require(type(status[key]) is type(expected_value) and status[key] == expected_value,
                'actual generic status differs: ' + key)
    for direction in ('send', 'receive'):
        for key, value in status[direction].items():
            if key != 'layer':
                uint(value, direction + '/' + key)
    for key, count in [('session', 16), ('transcript', 32), ('outer', 32), ('configuration', 32), ('catalog', 32)]:
        public_bytes(status[key], count, key)
    require(uint(status['generation'], 'generation') > 0 and uint(status['elapsed_micros'], 'elapsed') >= 0,
            'missing actual runtime observation')
    scope = status['physical_scope']
    require(isinstance(scope, dict) and set(scope) == {'epoch', 'configuration'}
        and type(scope['epoch']) is int and scope['epoch'] == epoch,
            'physical epoch differs from actual Bank')
    public_bytes(scope['configuration'], 32, 'physical configuration')
    require(scope['configuration'] == configuration_digest(canonical_value), 'exact actual physical D(C) differs')
    require(status['requested'] is None or status['requested'] == canonical_value, 'pending request not settled')
    require(status['terminal'] is None, 'actual runtime ended')
    require(status['service_terminal'] is None if running else status['service_terminal'] == 'Aborted',
            'incorrect actual service terminal overlay')
    for field in ('native_storage_capacity_bytes', 'workspace_capacity_bytes', 'loop_input_capacity_bytes'):
        require(uint(status[field], field) > 0, 'actual capacity observation missing')
    for name, keys in SUMMARIES.items():
        value = status[name]
        require(isinstance(value, dict) and set(value) == keys, 'actual bounded summary missing: ' + name)
        for key, count in value.items():
            if count is None and name in ('security', 'liveness'):
                continue
            uint(count, name + '/' + key)
    uint(status['swift_unconfirmed'], 'swift_unconfirmed')
    require(status['storage']['limit_bytes'] == 64 * 1024 * 1024, 'retained budget changed')
    usage = status['storage']
    total = sum(usage[key] for key in ('fixed_bytes', 'external_bytes', 'engine_bytes', 'building_bytes'))
    require(total <= usage['peak_bytes'] <= usage['limit_bytes'], 'actual retained charge exceeds bound')
    return status


def pcap_frames(path: Path):
    require(path.is_file() and not path.is_symlink(), 'regular capture required')
    if path.stat().st_size >= BOUNDS['capture_bytes']:
        raise native.BoundExhausted('capture byte ceiling exhausted')
    with path.open('rb') as stream:
        header = stream.read(24)
        magic = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                 b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
        require(len(header) == 24 and header[:4] in magic, 'unsupported pcap header')
        endian = magic[header[:4]]
        major, minor, zone, accuracy, snaplen, link = struct.unpack(endian + 'HHIIII', header[4:])
        require((major, minor, zone, accuracy, snaplen) == (2, 4, 0, 0, BOUNDS['snaplen'])
                and link in (1, 101, 113, 276), 'unsupported pcap link/version/snapshot')
        count = 0
        while record := stream.read(16):
            require(len(record) == 16, 'truncated pcap record')
            _, fraction, captured, original = struct.unpack(endian + 'IIII', record)
            nanos = header[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
            require(fraction < (1_000_000_000 if nanos else 1_000_000), 'invalid pcap timestamp fraction')
            require(0 < captured == original <= snaplen, 'truncated/oversized pcap packet')
            frame = stream.read(captured)
            require(len(frame) == captured, 'truncated pcap packet bytes')
            count += 1
            if count >= BOUNDS['capture_packets']:
                raise native.BoundExhausted('capture packet ceiling exhausted')
            offset, ether = {1: (14, 12), 101: (0, None), 113: (16, 14), 276: (20, 0)}[link]
            require(len(frame) >= offset, 'short captured link header')
            protocol = 0x800 if ether is None else int.from_bytes(frame[ether:ether + 2], 'big')
            yield count, link, protocol, frame[offset:]


def ipv4(raw: bytes, link: int) -> tuple[bytes, int]:
    require(len(raw) >= 20 and raw[0] == 0x45, 'unsupported/truncated captured IPv4')
    total = int.from_bytes(raw[2:4], 'big')
    require(20 <= total <= len(raw) and total <= 1500 and not int.from_bytes(raw[6:8], 'big') & 0x3fff
        and bounded.checksum(raw[:20]) == 0, 'captured IPv4 extent/checksum/fragment/MTU')
    require(total == len(raw) or link == 1 and len(raw) <= 46, 'unexpected bytes after captured IP')
    return raw[:total], total


def audit_capture(path: Path, case: dict, surface: str, epoch_mtus: dict[int, int]) -> dict:
    require(surface in ('wan-a', 'wan-b', 'native-a', 'native-b'), 'explicit capture surface required')
    result = {'packets': 0, 'arp': 0, 'udp': 0, 'icmp': 0, 'handshake': 0, 'established': 0,
        'user_epochs': {}, 'native_udp': [], 'native_icmp': [], 'scope': 'complete finite packet/header samples'}
    app = {row['address'] for row in case['applications'].values()}
    for count, link, ether, raw in pcap_frames(path):
        result['packets'] = count
        if ether == 0x806:
            require(link != 101 and len(raw) >= 28, 'invalid captured ARP')
            result['arp'] += 1
            continue
        require(ether == 0x800, 'unexpected captured link protocol')
        ip, total = ipv4(raw, link)
        source, destination = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        body = ip[20:]
        if surface.startswith('wan-'):
            if ip[9] == 1:
                # A final peer close can race an already-submitted Ping. Keep
                # validated original-tuple ICMP refusal separate from tunnel data.
                require(source in (*WAN.values(), '192.0.2.1', '192.0.2.5') and destination in WAN.values()
                    and len(body) >= 36 and body[:2] == bytes([3, 3]) and bounded.checksum(body) == 0,
                    'unexpected WAN ICMP path error')
                quote = body[8:]
                require(quote[0] == 0x45 and quote[9] == 17 and bounded.checksum(quote[:20]) == 0
                    and not int.from_bytes(quote[6:8], 'big') & 0x3fff
                    and socket.inet_ntoa(quote[12:16]) == destination
                    and {socket.inet_ntoa(quote[12:16]), socket.inet_ntoa(quote[16:20])} == set(WAN.values())
                    and quote[20:24] == struct.pack('!HH', 24440, 24440), 'invalid WAN ICMP original-tuple quote')
                result['icmp'] += 1
                continue
            require({source, destination} == set(WAN.values()), 'unexpected WAN endpoint/side flow')
            require(ip[9] == 17 and len(body) >= 8, 'WAN TCP/bootstrap/non-UDP side flow')
            sport, dport, length, _ = struct.unpack('!HHHH', body[:8])
            require(sport == dport == 24440 and length == len(body), 'original UDP tuple/extent changed')
            direction = 'a' if source == WAN['a'] else 'b'
            phase, payload, protected = native.covered_payload(body[8:], len(body) - 8, case['cover'])
            native.protected_shape(payload, protected, phase, direction)
            result[phase] += 1
            if phase == 'established' and payload[0] == 1:
                epoch = int.from_bytes(payload[1:9], 'big')
                require(epoch in epoch_mtus and total <= epoch_mtus[epoch], 'unknown User epoch/MTU breach')
                result['user_epochs'][str(epoch)] = result['user_epochs'].get(str(epoch), 0) + 1
            result['udp'] += 1
        else:
            require({source, destination} == app, 'unexpected native endpoints')
            if ip[9] == 17:
                require(len(body) >= 8 and int.from_bytes(body[4:6], 'big') == len(body), 'native UDP extent')
                pseudo = ip[12:20] + bytes([0, 17]) + len(body).to_bytes(2, 'big')
                require(body[6:8] == bytes(2) or bounded.checksum(pseudo + body) == 0, 'native UDP checksum')
                require(24461 in struct.unpack('!HH', body[:4]), 'unexpected native UDP port')
                result['native_udp'].append({'source': source, 'address': destination,
                    'bytes': len(body) - 8, 'sha256': hashlib.sha256(body[8:]).hexdigest()})
                result['udp'] += 1
            elif ip[9] == 1:
                require(len(body) == 1480 and bounded.checksum(body) == 0 and body[0] in (0, 8)
                        and body[1] == 0, 'native full-MTU ICMP mismatch')
                if body[0] == 8:
                    require(bool(int.from_bytes(ip[6:8], 'big') & 0x4000), 'native request lost DF')
                result['native_icmp'].append({'source': source, 'address': destination, 'type': body[0],
                    'identifier': int.from_bytes(body[4:6], 'big'), 'sequence': int.from_bytes(body[6:8], 'big'),
                    'payload_sha256': hashlib.sha256(body[8:]).hexdigest()})
                result['icmp'] += 1
            else:
                raise ValueError('unexpected native IP protocol')
    require(result['packets'] > 0, 'empty capture')
    if surface.startswith('wan-'):
        require(result['handshake'] > 0 and result['established'] > 0
                and set(result['user_epochs']) == set(map(str, epoch_mtus)), 'missing actual WAN phases/epochs')
    else:
        require(result['udp'] > 0 and result['icmp'] > 0, 'missing native functional traffic')
        if case['layer'] == 'tap':
            require(result['arp'] > 0, 'missing native TAP ARP')
    return result


def verify_helpers(build: dict, directory: Path, loaded: bool = False) -> dict:
    result = {}
    for name in HELPERS:
        path = directory / name
        expected = build.get('source_sha256_after', {}).get('tools/' + name)
        require(path.is_file() and not path.is_symlink() and type(expected) is str
                and bounded.file_hash(path) == expected, 'snapshot helper differs from build: ' + name)
        if loaded:
            require(LOADED[name].resolve() == path.resolve(), 'loaded helper not immutable copy: ' + name)
        result['tools/' + name] = expected
    return result


def json_results(path: Path) -> list[dict]:
    text = bounded.read_log(path)
    return [bounded.strict_json(line) for line in text.splitlines() if line.startswith('{')]


class Owner:
    """One finite case owns every child, log, command and observation."""
    def __init__(self, case, output, receipt, deadline):
        self.case, self.output, self.receipt, self.deadline = case, output, receipt, deadline
        self.processes, self.commands, self.samples = [], [], []
        self.ordinal = 0
        self.cleanup_deadline = None

    def check(self, deadline=None):
        bounded.remaining(min(self.deadline, deadline if deadline is not None else self.deadline), BOUNDS['case'])

    def phase(self, cap, deadline=None):
        until = min(self.deadline, time.monotonic() + cap,
            deadline if deadline is not None else self.deadline)
        self.check(until)
        return until

    def begin_cleanup(self):
        if self.cleanup_deadline is None:
            self.cleanup_deadline = time.monotonic() + BOUNDS['cleanup']
            self.receipt.update(cleanup_deadline_monotonic=self.cleanup_deadline)
        return self.cleanup_deadline

    def await_value(self, deadline, read, ready, interval=.1):
        while True:
            self.check(deadline)
            value = read(deadline)
            accepted = ready(value)
            self.check(deadline)
            if accepted:
                return value
            time.sleep(bounded.remaining(deadline, interval))

    def wait_log(self, child, path, marker, deadline):
        self.check(deadline)
        bounded.wait_log(child, path, marker, min(self.deadline, deadline))
        self.check(deadline)

    def finish_phase(self, children, deadline, failed):
        remaining = [child for child in children if child.poll() is None]
        if remaining:
            until = self.begin_cleanup() if failed else min(self.deadline, deadline)
            for child in remaining:
                stop_child(child, until)
        if not failed:
            self.check(deadline)

    def launch(self, role, argv, label, cap=None, deadline=None):
        require(role is None or role in self.case['namespaces'], 'unowned command namespace')
        if len(self.commands) >= BOUNDS['observations']:
            raise native.BoundExhausted('command observation ceiling exhausted')
        self.check(deadline)
        vector = (['ip', 'netns', 'exec', self.case['namespaces'][role]] if role else []) + list(map(str, argv))
        self.commands.append(vector)
        self.ordinal += 1
        path = self.output / f'{self.ordinal:03}-{label}.log'
        child = bounded.launch(vector, path, cap=cap or BOUNDS['log_bytes'])
        self.processes.append(child)
        self.check(deadline)
        return child, path

    def wait(self, child, cap, deadline=None):
        try:
            until = self.phase(cap, deadline)
            code = child.wait(timeout=bounded.remaining(until, cap))
            if code == -signal.SIGXFSZ:
                raise native.BoundExhausted('child file-size ceiling exhausted')
            self.check(until)
            return code
        except Exception:
            try:
                stop_child(child, self.begin_cleanup())
            except Exception as error:
                self.receipt.update(wait_cleanup_error=f'{type(error).__name__}: {error}'[:4096])
            raise

    def command(self, role, *argv, cap=BOUNDS['command'], expected=0, deadline=None):
        until = self.phase(cap, deadline)
        child, path = self.launch(role, argv, 'command', deadline=until)
        code = self.wait(child, cap, until)
        text = bounded.read_log(path)
        require(len(text.encode()) <= BOUNDS['log_bytes'], 'command log ceiling exhausted')
        require(code == expected, 'unexpected command exit: ' + str(path))
        self.check(until)
        return text

    def rpc(self, binary, secrets, side, action, *flags, version=3, expected=0, deadline=None):
        until = self.phase(BOUNDS['command'], deadline)
        raw = self.command('endpoint_' + side, binary, action, '--control-socket',
            secrets / f'control-{side}.sock', '--api-version', str(version), *flags, expected=expected, deadline=until)
        values = [bounded.strict_json(line) for line in raw.splitlines() if line.startswith('{')]
        require(len(values) == 1 and isinstance(values[0], dict), 'one bounded actual CLI JSON reply required')
        self.check(until)
        return values[0]

    def sample(self, label, value):
        if len(self.samples) >= BOUNDS['observations']:
            raise native.BoundExhausted('status observation ceiling exhausted')
        self.samples.append({'phase': label, 'at_monotonic_ns': time.monotonic_ns(), 'peers': value})
        self.receipt.update(status_samples=self.samples)


def native_device_fds(child: subprocess.Popen) -> list[dict]:
    require(child.poll() is None, 'production daemon exited before FD observation')
    directory = Path('/proc') / str(child.pid) / 'fd'
    entries = list(directory.iterdir())
    require(len(entries) <= 256, 'daemon FD observation ceiling exhausted')
    result = []
    for path in entries:
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        if target == '/dev/net/tun':
            detail = Path('/proc') / str(child.pid) / 'fdinfo' / path.name
            with detail.open('rb') as stream:
                body = stream.read(4097)
            require(len(body) <= 4096, 'device FD metadata ceiling exhausted')
            result.append({'fd': int(path.name), 'target': target, 'info': body.decode('ascii')})
    return result


def socket_observation(owner: Owner, daemons: dict, connected: bool = True, deadline=None) -> dict:
    until = owner.phase(BOUNDS['command'], deadline)
    result = {}
    for side in ('a', 'b'):
        role = 'endpoint_' + side
        udp = owner.command(role, 'ss', '-H', '-u', '-n', '-a', '-p', '-e', deadline=until)
        tcp = owner.command(role, 'ss', '-H', '-t', '-n', '-a', '-p', deadline=until)
        matches = [line for line in udp.splitlines() if ':24440' in line]
        require(not tcp.strip(), 'unexpected TCP bootstrap/side transport')
        devices = native_device_fds(daemons[side][0])
        if connected:
            require(len(matches) == 1 and WAN[side] + ':24440' in matches[0]
                and WAN['b' if side == 'a' else 'a'] + ':24440' in matches[0], 'original sole UDP pair missing')
            inode = re.findall(r'\bino:(\d+)\b', matches[0])
            require(len(inode) == 1 and len(devices) == 1, 'socket/native owner identity missing')
            require('iff:\t' + owner.case['device'] in devices[0]['info'], 'actual TunTap FD selects wrong device')
            result[side] = {'udp': matches[0], 'socket_inode': int(inode[0]), 'device': devices[0]}
        else:
            require(not matches and not devices, 'disconnect retained original socket/native owner')
            result[side] = {'udp': [], 'devices': []}
    owner.check(until)
    return result


def sysctl_values(raw, keys):
    values = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'([A-Za-z0-9_.-]+) = ([01])', line)
        require(match is not None and match[1] in keys and match[1] not in values,
                'invalid or duplicate owned IPv6 sysctl observation')
        values[match[1]] = int(match[2])
    require(set(values) == set(keys), 'incomplete owned IPv6 sysctl observation')
    return values


def disable_native_ipv6(owner):
    """Suppress IPv6 only in the four freshly owned IPv4 native namespaces."""
    case = owner.case
    require(case == plan(case['lab_id'], case['cover'], case['layer']), 'case differs from frozen plan')
    observations = {}
    for role in ('endpoint_a', 'endpoint_b', 'host_a', 'host_b'):
        links = bounded.strict_json(owner.command(role, 'ip', '-j', 'link', 'show'))
        require(isinstance(links, list) and 1 <= len(links) <= 16, 'bounded owned native link inventory required')
        names = [item.get('ifname') if isinstance(item, dict) else None for item in links]
        require(all(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,15}', name) for name in names)
            and len(set(names)) == len(names), 'invalid or duplicate observed native interface')
        require((case['device'] if role.startswith('endpoint_') else 'eth0') in names,
                'selected actual native interface missing')
        keys = ['net.ipv6.conf.' + name + '.disable_ipv6' for name in ('all', 'default', *sorted(names))]
        require(len(set(keys)) == len(keys), 'native interface collides with IPv6 sysctl defaults')
        observation = {'interfaces': sorted(names)}
        observations[role] = observation
        owner.receipt.update(native_ipv6=observations)
        observation['before'] = sysctl_values(owner.command(role, 'sysctl', *keys), keys)
        owner.receipt.update(native_ipv6=observations)
        written = ['net.ipv6.conf.' + name + '.disable_ipv6' for name in ('all', 'default')]
        observation['write'] = sysctl_values(owner.command(role, 'sysctl', '-w',
            *(key + '=1' for key in written)), written)
        require(all(value == 1 for value in observation['write'].values()), 'owned native IPv6 write was not applied')
        owner.receipt.update(native_ipv6=observations)
        observation['after'] = sysctl_values(owner.command(role, 'sysctl', *keys), keys)
        owner.receipt.update(native_ipv6=observations)
        require(all(value == 1 for value in observation['after'].values()), 'owned native IPv6 remains active')
    return observations


def validate_udp_probe(value):
    require(isinstance(value, dict) and value.get('status') == 'passed'
        and isinstance(value.get('rows'), list) and len(value['rows']) == 14, 'exact native UDP evidence incomplete')
    expected = [(length, kind) for length in (0, 1, 18, 64, 512, 1200, 1472) for kind in ('zero', 'tail')]
    for row, (length, kind) in zip(value['rows'], expected):
        require(isinstance(row, dict) and set(row) == {'bytes', 'pattern', 'sha256', 'attempts', 'answered'}
            and type(row['bytes']) is int and row['bytes'] == length and row['pattern'] == kind
            and row['answered'] is True and type(row['attempts']) is int and 1 <= row['attempts'] <= 8,
            'native UDP shape/attempt/pattern evidence differs')
        data = bytes(length) if kind == 'zero' else hashlib.shake_256(f'udp/{length}'.encode()).digest(length)
        if kind == 'tail' and length >= 4:
            data = data[:-4] + bytes(4)
        require(row['sha256'] == hashlib.sha256(data).hexdigest(), 'native UDP exact payload digest differs')
    return value


def functional_phase(owner: Owner, label: str) -> dict:
    """Two simultaneous directions; no TCP/bulk/performance generator."""
    phase_end = owner.phase(BOUNDS['startup'])
    echoes, children, result, failed = [], [], {}, True
    try:
        until = owner.phase(5, phase_end)
        for side in ('a', 'b'):
            application = owner.case['applications'][side]
            ready = owner.output / f'{label}-echo-{side}.ready'
            child, log = owner.launch(application['role'], [sys.executable, owner.output / 'secure_udp_native_probe.py',
                'udp-echo', '--address', application['address'], '--port', '24461', '--ready', ready],
                label + '-echo-' + side, deadline=until)
            echoes.append((child, log, ready))
            children.append(child)
        def echoes_ready(deadline):
            require(all(child.poll() is None for child, _, _ in echoes), 'native echo exited before readiness')
            return all(ready.is_file() for _, _, ready in echoes)
        owner.await_value(until, echoes_ready, bool, .02)
        probes = {}
        ping_end = int(owner.phase(12, phase_end) * 1e9)
        for side, other in (('a', 'b'), ('b', 'a')):
            application, peer = owner.case['applications'][side], owner.case['applications'][other]
            probes[side] = owner.launch(application['role'], [sys.executable, owner.output / 'secure_udp_native_probe.py',
                'icmp-probe', '--source', application['address'], '--address', peer['address'],
                '--deadline-ns', str(ping_end)], label + '-icmp-' + side, deadline=ping_end / 1e9)
            children.append(probes[side][0])
        for side, (child, log) in probes.items():
            code = owner.wait(child, 12, ping_end / 1e9)
            value = native.last_json(log)
            if value.get('status') == 'bound_exhausted':
                raise native.BoundExhausted('native ICMP original bound exhausted')
            if value.get('status') == 'tool_failure':
                raise native.ObservationError('native ICMP tool observation failed')
            require(code == 0, 'native ICMP probe failed')
            require(value.get('status') == 'passed' and value.get('sent') == value.get('received_unique') == 3
                and value.get('request_count') == 3 and value.get('payload_bytes') == 1472
                and value.get('ip_bytes') == 1500 and value.get('df') is True
                and value.get('source') == owner.case['applications'][side]['address']
                and value.get('address') == owner.case['applications']['b' if side == 'a' else 'a']['address']
                and value.get('original_deadline_ns') == ping_end
                and [row.get('sequence') for row in value.get('rows', [])] == [1, 2, 3],
                'full-MTU exact ICMP evidence incomplete')
            for row in value['rows']:
                require(type(row.get('sent_ns')) is int and type(row.get('received_ns')) is int
                    and row['sent_ns'] <= row['received_ns'] < ping_end, 'ICMP original deadline/receipt mismatch')
            result[side] = {'icmp': value}
        probes = {}
        owner.check(ping_end / 1e9)
        udp_end = owner.phase(17, phase_end)
        for side, other in (('a', 'b'), ('b', 'a')):
            probes[side] = owner.launch(owner.case['applications'][side]['role'],
                [sys.executable, owner.output / 'secure_udp_native_probe.py', 'udp-probe', '--address',
                 owner.case['applications'][other]['address'], '--port', '24461'],
                 label + '-udp-' + side, deadline=udp_end)
            children.append(probes[side][0])
        for side, (child, log) in probes.items():
            code = owner.wait(child, 17, udp_end)
            value = native.last_json(log)
            if value.get('status') == 'bound_exhausted':
                raise native.BoundExhausted('native UDP original bound exhausted')
            require(code == 0, 'native arbitrary-byte UDP probe failed')
            result[side]['udp'] = validate_udp_probe(value)
        owner.check(udp_end)
        owner.check(phase_end)
        owner.receipt.update(**{label + '_functional': result})
        failed = False
        return result
    finally:
        owner.finish_phase(children, phase_end, failed)


def verify_native_fingerprints(audits: dict, phases: dict) -> dict:
    result = {}
    for surface in ('native-a', 'native-b'):
        actual = audits[surface]
        udp = {(row['source'], row['address'], row['bytes'], row['sha256']) for row in actual['native_udp']}
        icmp = {(row['source'], row['address'], row['type'], row['identifier'], row['sequence'], row['payload_sha256'])
                for row in actual['native_icmp']}
        count = 0
        for peers in phases.values():
            for side, other in (('a', 'b'), ('b', 'a')):
                ping = peers[side]['icmp']
                source, destination = ping['source'], ping['address']
                for row in ping['rows']:
                    for kind, first, second in ((8, source, destination), (0, destination, source)):
                        require((first, second, kind, ping['identifier'], row['sequence'], row['payload_sha256']) in icmp,
                                'actual complete native ICMP fingerprint missing: ' + surface)
                        count += 1
                for row in peers[side]['udp']['rows']:
                    require((source, destination, row['bytes'], row['sha256']) in udp
                        and (destination, source, row['bytes'], row['sha256']) in udp,
                        'actual complete native UDP fingerprint missing: ' + surface)
        result[surface] = {'complete_icmp_fingerprints': count, 'udp_pattern_pairs': len(udp),
            'scope': 'fresh phase ICMP identities; UDP hashes plus independent per-phase endpoint exact bytes'}
    return result


def capture_command(case, surface, destination):
    require(surface in ('wan-a', 'wan-b', 'native-a', 'native-b'), 'explicit owned capture surface required')
    return ['tcpdump', '-n', '-U', '-B', '4096', '-s', str(BOUNDS['snaplen']),
        '-c', str(BOUNDS['capture_packets']), '-Z', 'root', '-i',
        'wan0' if surface.startswith('wan-') else case['device'], '-w', str(destination), 'ip or ip6 or arp']


def stop_child(child, deadline, interrupt=False):
    if child.poll() is not None:
        return
    child.send_signal(signal.SIGINT if interrupt else signal.SIGTERM)
    try:
        child.wait(timeout=bounded.remaining(deadline, 2))
    except (subprocess.TimeoutExpired, TimeoutError):
        child.kill()
        child.wait(timeout=bounded.remaining(deadline, 2))


def stopped_capture(child, log, path, deadline):
    stop_child(child, deadline, interrupt=True)
    if child.returncode == -signal.SIGXFSZ or path.is_file() and path.stat().st_size >= BOUNDS['capture_bytes']:
        raise native.BoundExhausted('capture file-size ceiling exhausted')
    require(child.returncode in (0, -signal.SIGINT), 'capture process did not stop successfully')
    values = bounded.capture_counts(bounded.read_log(log), BOUNDS['capture_packets'])
    require(path.is_file() and path.stat().st_size < BOUNDS['capture_bytes'], 'capture extent ceiling exhausted')
    return {'captured': values['captured'], 'received': values['received by filter'],
            'kernel_dropped': values['dropped by kernel'], 'returncode': child.returncode}


def drain_native_captures(captures, case, phases, deadline):
    """Wait for complete known fingerprints before interrupting packet writers."""
    until = min(deadline, time.monotonic() + 5)
    while True:
        try:
            audits = {surface: audit_capture(captures[surface][2], case, surface, {1: 1500, 2: 1400, 3: 1500})
                for surface in ('native-a', 'native-b')}
            result = verify_native_fingerprints(audits, phases)
            bounded.remaining(until, 5)
            return result
        except (ValueError, OSError):
            require(all(captures[surface][0].poll() is None for surface in ('native-a', 'native-b')),
                    'native capture writer exited before complete fingerprints')
            time.sleep(bounded.remaining(until, .02))


def cleanup_topology(spec, state_dir, deadline):
    bounded.remaining(deadline, BOUNDS['cleanup'])
    journal = state_dir / (spec.lab_id + '.json')
    if journal.exists():
        bounded.bounded_lab(lab.cleanup, spec, state_dir, deadline)
    require(not journal.exists() and not journal.is_symlink(), 'owned journal remains after cleanup')
    require(not any((lab.NETNS_DIRECTORY / name).exists() or (lab.NETNS_DIRECTORY / name).is_symlink()
        for name in spec.namespaces.values()), 'owned namespace handle remains after cleanup')
    bounded.remaining(deadline, BOUNDS['cleanup'])


def run_case(case: dict, output: Path, build: dict, proof: dict) -> dict:
    require(case == plan(case['lab_id'], case['cover'], case['layer']), 'case differs from frozen plan')
    binary, state_dir = output / 'l2tunnel-native', Path('/run/l2tunnel-generic-cli')
    receipt = bounded.Receipt(output / 'receipt.json', {'status': 'running', 'plan': case,
        'namespace_proof': proof, 'binary_sha256': bounded.file_hash(binary),
        'build_receipt_sha256': bounded.file_hash(output / 'build-receipt.json'),
        'executed_helpers': verify_helpers(build, output, True), 'cleanup': 'pending'})
    owner = Owner(case, output, receipt, time.monotonic() + BOUNDS['case'])
    spec, captures, phases, errors = lab.LabSpec(case['lab_id']), {}, {}, []
    sockets, daemons, public, inspected = {}, {}, None, None
    try:
        for tool in ('ip', 'tc', 'ss', 'tcpdump', 'mount', 'sysctl', 'ethtool'):
            if shutil.which(tool) is None:
                raise FileNotFoundError(tool)
        credential_preflight()
        if not Path('/dev/net/tun').exists():
            raise Unsupported('/dev/net/tun is unavailable; real native device required')
        receipt.update(kernel=owner.command(None, 'uname', '-a'),
            tools={name: owner.command(None, *argv) for name, argv in
                   [('ip', ('ip', '-Version')), ('tc', ('tc', '-Version')), ('tcpdump', ('tcpdump', '--version'))]})
        bounded.bounded_lab(lab.apply, spec, state_dir, owner.deadline)
        receipt.update(namespace_journal=bounded.strict_json((state_dir / (spec.lab_id + '.json')).read_bytes()))
        receipt.update(underlay_ipv6=bounded.disable_underlay_ipv6(case['namespaces'], owner.deadline))
        shaping, links, offloads = {}, {}, {}
        for side in ('a', 'b'):
            role = 'endpoint_' + side
            shaping[side] = native.recreate_owned_wan(case, spec, state_dir, side, owner.command)
            if case['layer'] == 'tun':
                for device in ('tap0', 'lan0', 'br-lan'):
                    owner.command(role, 'ip', 'link', 'set', device, 'down')
                owner.command('host_' + side, 'ip', 'address', 'flush', 'dev', 'eth0')
                owner.command('host_' + side, 'ip', 'link', 'set', 'eth0', 'down')
                owner.command(role, 'ip', 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun')
                owner.command(role, 'ip', 'address', 'add', case['applications'][side]['address'] + '/24', 'dev', 'tun0')
                owner.command(role, 'ip', 'link', 'set', 'tun0', 'mtu', '1500', 'up')
            links[side] = bounded.strict_json(owner.command(role, 'ip', '-d', '-j', 'link', 'show', 'dev', case['device']))
            require(len(links[side]) == 1 and links[side][0].get('ifname') == case['device']
                and links[side][0].get('linkinfo', {}).get('info_kind') == 'tun'
                and links[side][0].get('linkinfo', {}).get('info_data', {}).get('type') == case['layer'],
                'actual named device does not match selected TAP/TUN')
            interfaces = [(role, 'wan0'), (role, case['device'])]
            if case['layer'] == 'tap':
                interfaces += [(role, 'lan0'), ('host_' + side, 'eth0')]
            for namespace_role, interface in interfaces:
                offloads[namespace_role + '/' + interface] = bounded.offloads(case['namespaces'][namespace_role], interface, owner.deadline)
        for interface in ('a0', 'b0'):
            offloads['router/' + interface] = bounded.offloads(case['namespaces']['router'], interface, owner.deadline)
        receipt.update(shaping=shaping, native_links=links, offloads=offloads)
        disable_native_ipv6(owner)
        for surface in ('wan-a', 'wan-b', 'native-a', 'native-b'):
            path = output / (surface + '.pcap')
            child, log = owner.launch('endpoint_' + surface[-1], capture_command(case, surface, path),
                surface + '-capture', BOUNDS['capture_bytes'])
            captures[surface] = (child, log, path)
            owner.wait_log(child, log, 'listening on', owner.phase(5))
        with private_directory() as directory:
            secrets = Path(directory)
            secrets.chmod(0o700)
            require(all(len(os.fsencode(str(secrets / f'control-{side}.sock'))) < 108 for side in ('a', 'b')),
                    'private Unix socket path exceeds native bound')
            public = native.credentials(binary, secrets, owner.deadline)
            receipt.update(credentials=public)
            plan_file = output / 'transaction-plan.json'
            with plan_file.open('xb') as stream:
                stream.write((json.dumps(case['transaction_plan'], sort_keys=True) + '\n').encode())
            require(plan_file.stat().st_size <= 256 * 1024, 'native plan exceeds frontend cap')
            inspection = {side: validate_inspection(bounded.strict_json(owner.command('endpoint_' + side,
                *daemon_command(case, side, binary, secrets, plan_file, True)).strip()), case, side, public)
                for side in ('a', 'b')}
            for field in ('configuration', 'envelope', 'catalog', 'data_digest', 'initial', 'configurations'):
                require(inspection['a'][field] == inspection['b'][field], 'role inspection identity differs: ' + field)
            inspected = inspection['a']
            initial = inspected['initial']
            target = next(value for value in inspected['configurations'] if value != initial)
            receipt.update(inspection=inspection)

            def validate_pair(raw, expected, epoch, label, running, deadline):
                values = {side: validate_status(raw[side], case, side,
                    public, inspected, expected, epoch, running) for side in ('a', 'b')}
                for key in ('session', 'transcript', 'outer', 'configuration', 'catalog', 'current', 'epoch', 'physical_scope'):
                    require(values['a'][key] == values['b'][key], 'actual peers differ: ' + key)
                owner.check(deadline)
                owner.sample(label, values)
                owner.check(deadline)
                return values

            def statuses(expected, epoch, label, running=True, deadline=None):
                until = owner.phase(BOUNDS['command'], deadline)
                raw = {side: owner.rpc(binary, secrets, side, 'status', deadline=until) for side in ('a', 'b')}
                return validate_pair(raw, expected, epoch, label, running, until)

            def await_configuration(expected, epoch, label):
                until = owner.phase(BOUNDS['command'])
                def committed(raw):
                    require(all(value.get('ok') is True for value in raw.values()),
                            'status failed while awaiting actual commit')
                    return all((value.get('state') or {}).get('transaction', {}).get('current') == expected
                        and value['state']['transaction'].get('epoch') == epoch
                        and value['state']['transaction'].get('phase') == 'idle'
                        and value['state']['transaction'].get('operation') is None for value in raw.values())
                raw = owner.await_value(until,
                    lambda end: {side: owner.rpc(binary, secrets, side, 'status', deadline=end) for side in ('a', 'b')},
                    committed)
                return validate_pair(raw, expected, epoch, label, True, until)

            def await_liveness(expected, epoch, label):
                until = owner.phase(5)
                return owner.await_value(until, lambda end: statuses(expected, epoch, label, deadline=end),
                    lambda values: all(isinstance(value['liveness'], dict)
                        and type(value['liveness'].get('last_pong_micros')) is int
                        and value['liveness']['last_pong_micros'] > 0 for value in values.values()))

            startup_end = owner.phase(BOUNDS['startup'])
            for side in ('b', 'a'):
                daemons[side] = owner.launch('endpoint_' + side,
                    daemon_command(case, side, binary, secrets, plan_file), 'daemon-' + side, deadline=startup_end)
                if side == 'b':
                    def bound_socket(deadline):
                        require(daemons[side][0].poll() is None, 'server exited before original socket bind')
                        return owner.command('endpoint_b', 'ss', '-H', '-u', '-n', '-a', deadline=deadline)
                    owner.await_value(startup_end, bound_socket, lambda raw: ':24440' in raw, .05)
            ready = {}
            for side, (child, log) in daemons.items():
                owner.wait_log(child, log, '"event":"secure_udp_transaction_ready"', startup_end)
                events = [value for value in json_results(log) if value.get('event') == 'secure_udp_transaction_ready']
                require(len(events) == 1 and events[0].get('schema') == 1, 'one actual initial generic ready event required')
                ready[side] = events[0]
            before = statuses(initial, 1, 'initial', deadline=startup_end)
            require(all(ready[side]['status']['generation'] == before[side]['generation']
                and ready[side]['status']['configuration'] == inspected['configuration']
                and ready[side]['status']['current'] == initial and ready[side]['status']['running'] is True
                for side in ('a', 'b')), 'actual ready/IPC generation differs')
            receipt.update(ready=ready)
            owner.check(startup_end)
            sockets['initial'] = socket_observation(owner, daemons)
            for side in ('a', 'b'):
                for version in (1, 2):
                    refusal = owner.rpc(binary, secrets, side, 'disconnect', version=version, expected=1)
                    require(refusal == {'version': version, 'ok': False, 'code': 'requires_version_3', 'state': None},
                            'wrong-version request was not exactly refused')
            refused_status = statuses(initial, 1, 'after-version-refusal')
            for side in ('a', 'b'):
                require(all(refused_status[side][key] == before[side][key] for key in
                    ('generation', 'session', 'transcript', 'current', 'epoch', 'physical_scope')),
                    'wrong-version request changed live owner/configuration')
            sockets['after_version_refusal'] = socket_observation(owner, daemons)
            require(all(sockets['after_version_refusal'][side]['socket_inode'] == sockets['initial'][side]['socket_inode']
                and sockets['after_version_refusal'][side]['device'] == sockets['initial'][side]['device']
                for side in ('a', 'b')), 'wrong-version request replaced native/socket owner')
            phases['initial'] = functional_phase(owner, 'initial')
            for name, selected, epoch in [('target', target, 2), ('returned', initial, 3)]:
                result = owner.rpc(binary, secrets, 'a', 'switch-swift-configuration', '--configuration', selected)
                validate_status(result, case, 'a', public, inspected, selected, epoch)
                current = await_configuration(selected, epoch, name)
                require(current['a']['session'] == before['a']['session']
                    and current['a']['transcript'] == before['a']['transcript'], 'switch replaced authenticated session')
                sockets[name] = socket_observation(owner, daemons)
                require(all(sockets[name][side]['socket_inode'] == sockets['initial'][side]['socket_inode']
                    and sockets[name][side]['device'] == sockets['initial'][side]['device'] for side in ('a', 'b')),
                    'switch replaced original socket/native device')
                phases[name] = functional_phase(owner, name)
            await_liveness(initial, 3, 'before-disconnect')

            def disconnect(expected, epoch, label):
                until = owner.phase(BOUNDS['command'])
                results = {side: owner.rpc(binary, secrets, side, 'disconnect', deadline=until) for side in ('a', 'b')}
                for side, value in results.items():
                    validate_status(value, case, side, public, inspected, expected, epoch, False)
                final = statuses(expected, epoch, label, False, deadline=until)
                for side, (_, log) in daemons.items():
                    terminal_end = owner.phase(2, until)
                    owner.await_value(terminal_end, lambda end: json_results(log), lambda events: any(
                        value.get('event') == 'secure_udp_transaction_terminal'
                        and (value.get('status') or {}).get('generation') == final[side]['generation']
                        and value['status'].get('service_terminal') == 'Aborted' for value in events), .02)
                released = socket_observation(owner, daemons, False, deadline=until)
                owner.check(until)
                return {'replies': results, 'status': final, 'released': released}

            stopped = disconnect(initial, 3, 'disconnected')
            receipt.update(disconnect=stopped)
            reconnect_end = owner.phase(BOUNDS['startup'])
            reconnects = {side: owner.launch('endpoint_' + side, [binary, 'reconnect', '--control-socket',
                secrets / f'control-{side}.sock', '--api-version', '3'],
                'reconnect-' + side, deadline=reconnect_end) for side in ('b', 'a')}
            replies = {}
            for side, (child, log) in reconnects.items():
                require(owner.wait(child, BOUNDS['startup'], reconnect_end) == 0, 'real fresh reconnect failed')
                replies[side] = native.last_json(log)
                validate_status(replies[side], case, side, public, inspected, initial, 1)
            after = statuses(initial, 1, 'fresh-reconnected', deadline=reconnect_end)
            for side in ('a', 'b'):
                require(after[side]['generation'] > before[side]['generation']
                    and after[side]['session'] != before[side]['session']
                    and after[side]['transcript'] != before[side]['transcript'], 'reconnect reused old authenticated state')
            owner.check(reconnect_end)
            sockets['reconnected'] = socket_observation(owner, daemons)
            phases['reconnected'] = functional_phase(owner, 'reconnected')
            await_liveness(initial, 1, 'fresh-reconnect-pong')
            receipt.update(reconnect={'replies': replies, 'status': after}, sockets=sockets,
                final_disconnect=disconnect(initial, 1, 'final-disconnected'))
    except Exception as error:
        errors.append({'status': failure_status(error), 'error': f'{type(error).__name__}: {error}'[:4096]})
    finally:
        cleanup_end = owner.begin_cleanup()
        if not errors and set(phases) == {'initial', 'target', 'returned', 'reconnected'}:
            try:
                receipt.update(native_capture_drain=drain_native_captures(captures, case, phases,
                    min(owner.deadline, cleanup_end)))
            except Exception as error:
                errors.append({'status': failure_status(error), 'capture_drain': f'{type(error).__name__}: {error}'[:4096]})
        capture_children = {child for child, _, _ in captures.values()}
        for child in reversed(owner.processes):
            if child not in capture_children:
                try:
                    stop_child(child, cleanup_end)
                except Exception as error:
                    errors.append({'status': failure_status(error), 'cleanup': f'{type(error).__name__}: {error}'[:4096]})
        audits, counts = {}, {}
        for surface, (child, log, path) in captures.items():
            try:
                counts[surface] = stopped_capture(child, log, path, cleanup_end)
                audits[surface] = audit_capture(path, case, surface, {1: 1500, 2: 1400, 3: 1500})
                require(audits[surface]['packets'] == counts[surface]['captured'], 'capture record/counter mismatch')
                bounded.remaining(cleanup_end, BOUNDS['cleanup'])
            except Exception as error:
                errors.append({'status': failure_status(error), 'capture': surface,
                    'error': f'{type(error).__name__}: {error}'[:4096]})
                try:
                    stop_child(child, cleanup_end)
                except Exception:
                    pass
        try:
            require(set(phases) == {'initial', 'target', 'returned', 'reconnected'}, 'functional phase matrix incomplete')
            require(set(audits) == {'wan-a', 'wan-b', 'native-a', 'native-b'}, 'capture surface matrix incomplete')
            receipt.update(native_fingerprints=verify_native_fingerprints(audits, phases))
        except Exception as error:
            errors.append({'status': failure_status(error), 'error': f'{type(error).__name__}: {error}'[:4096]})
        try:
            cleanup_topology(spec, state_dir, cleanup_end)
        except Exception as error:
            errors.append({'status': failure_status(error), 'cleanup': f'{type(error).__name__}: {error}'[:4096]})
        receipt.update(status=errors[0]['status'] if errors else 'passed', errors=errors, commands=owner.commands,
            status_samples=owner.samples, phases=phases, capture_audits=audits, capture_counters=counts,
            cleanup='failed' if any('cleanup' in row for row in errors) else 'passed',
            performance_qualified=False, finished_monotonic_ns=time.monotonic_ns())
    return receipt.value


def worker_limits(*, file_bytes=None):
    maximum = BOUNDS['capture_bytes']
    soft = BOUNDS['log_bytes'] if file_bytes is None else file_bytes
    require(type(soft) is int and 0 < soft <= maximum, 'worker file cap must fit explicit capture ceiling')
    inherited = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
    if inherited != resource.RLIM_INFINITY and inherited < maximum:
        raise native.ObservationError('inherited file limit cannot permit explicit capture bound')
    def apply():
        hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
        if hard != resource.RLIM_INFINITY and hard < maximum:
            raise ValueError('worker inherited file ceiling changed before exec')
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, maximum))
    return apply


def worker(case, output, build, descriptors, token):
    info = output.stat()
    require(not output.is_symlink() and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
        and token == f'{info.st_dev}:{info.st_ino}' and Path(__file__).resolve() == output / 'generic_cli_native.py',
        'fresh exclusive copied-worker directory identity required')
    verify_helpers(build, output, True)
    launch = bounded.strict_json((output / 'launch-receipt.json').read_bytes())
    current = native.namespace_ids()
    native.verify_fresh_namespace(descriptors, launch['original_namespaces'], current)
    for descriptor in descriptors.values():
        os.close(descriptor)
    if os.geteuid() != 0:
        raise Unsupported('new user namespace did not map the caller to root')
    end = time.monotonic() + 15
    links = bounded.strict_json(bounded.command(['ip', '-j', 'link', 'show'], end))
    routes = bounded.strict_json(bounded.command(['ip', '-j', 'route', 'show', 'table', 'all'], end))
    require(len(links) == 1 and links[0].get('ifname') == 'lo' and routes == [],
            'fresh outer network namespace must be pristine loopback-only')
    bounded.command(['mount', '--make-rprivate', '/'], end)
    bounded.command(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], end)
    Path('/run/netns').mkdir(mode=0o755)
    proof = {'original': launch['original_namespaces'], 'fresh': current,
        'initial_links': links, 'initial_routes': routes, 'uid_map': Path('/proc/self/uid_map').read_text(),
        'euid': os.geteuid(), 'run_mount': 'fresh tmpfs after mount --make-rprivate /'}
    result = run_case(case, output, build, proof)
    return 0 if result['status'] == 'passed' else 1


def launch_isolated(case: dict, output: Path, binary: Path, build_receipt: Path) -> int:
    # Exclusive output is owned before preflight; every later failure gets a receipt.
    output.mkdir(mode=0o700)
    output = output.resolve()
    launch = bounded.Receipt(output / 'launch-receipt.json', {'status': 'starting', 'plan': case,
        'interpreter': sys.executable, 'python_version': sys.version})
    descriptors, child, original = {}, None, None
    try:
        require(binary.is_absolute() and binary.is_file() and not binary.is_symlink(),
                'existing absolute regular immutable binary required')
        build = bounded.verified_build_receipt(build_receipt, binary)
        for name in HELPERS:
            shutil.copyfile(Path(__file__).parent / name, output / name)
            (output / name).chmod(0o400)
        shutil.copyfile(binary, output / 'l2tunnel-native')
        (output / 'l2tunnel-native').chmod(0o500)
        shutil.copyfile(build_receipt, output / 'build-receipt.json')
        (output / 'build-receipt.json').chmod(0o400)
        hashes = verify_helpers(build, output)
        original = native.namespace_ids()
        launch.update(original_namespaces=original, executed_helpers=hashes,
            binary_sha256=bounded.file_hash(output / 'l2tunnel-native'))
        executable = shutil.which('unshare')
        if executable is None:
            raise FileNotFoundError('unshare')
        for name in ('user', 'net', 'mnt'):
            descriptors[name] = os.open('/proc/self/ns/' + name, os.O_RDONLY)
        identity = output.stat()
        argv = [executable, '--user', '--map-root-user', '--net', '--mount', '--fork', sys.executable,
            str(output / 'generic_cli_native.py'), '--cover', case['cover'], '--layer', case['layer'],
            '--lab-id', case['lab_id'], '--output', str(output), '--binary', str(output / 'l2tunnel-native'),
            '--build-receipt', str(output / 'build-receipt.json'), '--frozen-worker',
            f'{identity.st_dev}:{identity.st_ino}', '--namespace-fds',
            ','.join(f'{key}:{value}' for key, value in descriptors.items()), '--apply']
        environment = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME')}
        environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        limits = worker_limits()
        launch.update(worker_file_limits={'soft': BOUNDS['log_bytes'], 'hard': BOUNDS['capture_bytes']})
        with (output / 'worker.log').open('xb') as log:
            child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, pass_fds=tuple(descriptors.values()),
                env=environment, start_new_session=True, preexec_fn=limits)
            launch.update(status='running', worker_pid=child.pid, worker_argv=argv)
            code = child.wait(timeout=BOUNDS['launcher'])
        native.terminate_owned_group(child)
        child = None
        result_path = output / 'receipt.json'
        result = None
        if result_path.is_file() and not result_path.is_symlink() and result_path.stat().st_size <= bounded.RECEIPT_LIMIT:
            result = bounded.strict_json(result_path.read_bytes())
        if result is None or result.get('status') == 'running' or code != 0 and result.get('status') == 'passed':
            raw = bounded.read_log(output / 'worker.log')
            status = 'unsupported' if 'unshare: unshare failed: Operation not permitted' in raw else 'tool_failure'
            native.finalize_launch_failure(output, status, 'isolated worker did not publish a coherent terminal receipt')
            result = bounded.strict_json(result_path.read_bytes())
        after = native.namespace_ids()
        require(after == original, 'launcher namespace identities changed during isolated run')
        launch.update(status=result['status'], worker_exit=code, launcher_namespaces_after=after)
        return 0 if code == 0 and result['status'] == 'passed' else 1
    except Exception as error:
        cleanup_error = None
        if child is not None:
            try:
                native.terminate_owned_group(child)
            except Exception as cleanup:
                cleanup_error = f'{type(cleanup).__name__}: {cleanup}'[:4096]
        status = failure_status(error)
        detail = f'{type(error).__name__}: {error}'[:4096]
        launch.update(status=status, error=detail, group_cleanup_error=cleanup_error,
            launcher_namespaces_after=native.namespace_ids())
        native.finalize_launch_failure(output, status, detail)
        return 1
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)


def main(argv=None) -> int:
    selection = argparse.ArgumentParser(add_help=False)
    selection.add_argument('--backend', choices=('swift', 'common-openvpn'), default='swift')
    backend, _ = selection.parse_known_args(argv)
    if backend.backend == 'common-openvpn':
        try:
            from . import common_carrier_cli_native
        except ImportError:
            import common_carrier_cli_native
        return common_carrier_cli_native.main(argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=('swift',), default='swift')
    parser.add_argument('--cover', choices=('quic-like', 'media-like'), required=True)
    parser.add_argument('--layer', choices=('tap', 'tun'), required=True)
    parser.add_argument('--lab-id', default='genericcli')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--build-receipt', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--frozen-worker', help=argparse.SUPPRESS)
    parser.add_argument('--namespace-fds', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    case = plan(args.lab_id, args.cover, args.layer)
    if not args.apply:
        print(json.dumps({'status': 'dry_run', 'mutations': 'none', 'case': case}, indent=2))
        return 0
    if sys.platform != 'linux' or args.build_receipt is None:
        raise Unsupported('Linux and exact source-stable build receipt required for apply')
    if args.frozen_worker:
        require(type(args.namespace_fds) is str, 'original namespace descriptors required')
        pairs = [item.split(':') for item in args.namespace_fds.split(',')]
        require(len(pairs) == 3 and all(len(pair) == 2 and pair[1].isdigit() for pair in pairs),
                'invalid original namespace descriptors')
        descriptors = {key: int(value) for key, value in pairs}
        require(set(descriptors) == {'user', 'net', 'mnt'}, 'all original namespace descriptors required')
        output = args.output.resolve()
        require(args.binary.resolve() == output / 'l2tunnel-native'
            and args.build_receipt.resolve() == output / 'build-receipt.json', 'verified private binary/receipt copies required')
        build = bounded.verified_build_receipt(args.build_receipt, args.binary)
        return worker(case, output, build, descriptors, args.frozen_worker)
    require(args.namespace_fds is None, 'namespace descriptors belong only to verified copied worker')
    return launch_isolated(case, args.output, args.binary, args.build_receipt)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as failure:
        print(json.dumps({'status': failure_status(failure), 'error': f'{type(failure).__name__}: {failure}'[:4096]}),
              file=sys.stderr)
        raise SystemExit(1)
