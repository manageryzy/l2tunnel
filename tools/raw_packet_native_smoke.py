#!/usr/bin/env python3
"""Original raw-packet native acceptance; immutable owned labs only, dry run by default."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import sys
import tempfile
import time
import subprocess

try:
    from . import proxy_native_smoke as bounded
    from . import raw_native_smoke as retained
except ImportError:
    import proxy_native_smoke as bounded
    import raw_native_smoke as retained

netns_lab = retained.netns_lab
ROOT = Path(__file__).resolve().parents[1]
BOUNDS = {'case': 150, 'startup': 35, 'command': 10, 'transfer': 30,
          'confirmed': 10, 'carrier_loss': 18, 'cleanup': 30}
MARK = 0x12aa0001
MAX_SAMPLES = 512
# Native byte admission is independent of the finite connectivity lab's raw
# wire budget below; these settings do not qualify an 80 Mbit/s workload.
DELIVERY_POLICY = {
    'forward_bandwidth_bps': 100_000_000, 'reverse_bandwidth_bps': 10_000_000,
    'bootstrap_rtt_micros': 70_000, 'min_rtt_micros': 1000, 'max_rtt_micros': 2_000_000,
    'headroom_percent': 125, 'minimum_bytes': 3200, 'max_inflight_bytes': 4 * 1024 * 1024,
    'max_records': 8192, 'metadata_limit_bytes': 2 * 1024 * 1024,
    'sample_ttl_micros': 4_000_000, 'flush_timeout_micros': 10_000_000,
}
SELECTION = {'carrier': 'raw_packet_v1', 'udp_cover': 'none', 'traffic': 'system'}
CAPABILITIES = {'runtime_implemented': True, 'native_qualified': False,
                'congestion_control': False, 'clean_drain': False, 'hot_reload': False}
COUNTERS = {'admitted', 'sources', 'received', 'delivered', 'peer_delivered', 'staged'}
FLIGHT_COUNTERS = {f'{domain}_{unit}' for domain in
                   ('admitted', 'delivered', 'flushed', 'flushed_total', 'outstanding')
                   for unit in ('bytes', 'records')}
SAMPLE_FIELDS = {'raw_rtt_micros', 'smoothed_rtt_micros', 'sample_at_micros'}
RECOVERY_COUNTERS = {f'{direction}_{unit}' for direction in ('send', 'receive')
                     for unit in ('bytes', 'records')}
WINDOW_FIELDS = {'runtime_profile', 'delivery', 'recovery', 'native_pending_bytes',
                 'native_pending_records', 'local_queue_packets_limit', 'local_queue_bytes_limit',
                 'local_queue_packets', 'local_queue_bytes', 'wire_bytes_per_second',
                 'wire_packets_per_second'}
HELPERS = {'tools/raw_packet_native_smoke.py': Path(__file__),
           'tools/proxy_native_smoke.py': Path(bounded.__file__),
           'tools/raw_native_smoke.py': Path(retained.__file__),
           'tools/netns_lab.py': Path(netns_lab.__file__)}


def policy(duplex: str, side: str, suite: str = 'integrity') -> dict:
    if duplex not in ('full', 'half') or side not in ('a', 'b') or suite not in ('integrity', 'aead'):
        raise ValueError('explicit duplex, endpoint and supported protection suite required')
    def endpoints(ports):
        a, b = f'192.0.2.2:{ports[0]}', f'192.0.2.6:{ports[1]}'
        return {'local': a if side == 'a' else b, 'peer': b if side == 'a' else a}
    return {'version': 2, 'profile': 'raw-packet-runtime-v2',
            'delivery': dict(DELIVERY_POLICY),
            'forward': endpoints(retained.PORTS[0]),
            'reverse': endpoints(retained.PORTS[1]) if duplex == 'half' else None,
            'channels': 4, 'packet': {'mtu': 1200, 'protection': suite,
                'queue_packets': 8, 'horizon_bytes': 32768, 'minimum_transfer_bytes': 65536,
                'bytes_per_second': 1048576, 'packets_per_second': 2048,
                'burst_bytes': 16384, 'burst_packets': 32,
                'max_key_packets': 1048576, 'max_key_bytes': 1073741824},
            'recovery': {'mode': 'selective_repeat'}}


def case_plan(lab_id: str, layer: str, duplex: str, suite: str = 'integrity') -> dict:
    if layer not in ('tap', 'tun') or duplex not in ('full', 'half'):
        raise ValueError('only clean TAP/TUN full/half is supported')
    if suite not in ('integrity', 'aead'):
        raise ValueError('unsupported protection suite')
    spec = netns_lab.LabSpec(f'{lab_id}-{layer[1]}{duplex[0]}' + ('e' if suite == 'aead' else ''))
    network = 18 if layer == 'tap' else 19
    flows = [{'family': family, 'source': f'198.{network}.0.1' if family == 4 else f'fd42:12:{network}::1',
              'destination': f'198.{network}.0.2' if family == 4 else f'fd42:12:{network}::2',
              'source_port': 32000 + family, 'destination_port': 24451}
             for family in (4, 6)]
    return {'case': f'{layer}-{duplex}-clean', 'lab_id': spec.lab_id, 'layer': layer,
            'duplex': duplex, 'lanes': 1 if duplex == 'full' else 2,
            'namespaces': spec.namespaces, 'bounds_seconds': BOUNDS,
            'policies': {side: policy(duplex, side, suite) for side in ('a', 'b')},
            'socket_mark': MARK, 'flows': flows,
            'profile': ['--carrier', 'raw-packet', '--raw-mark', str(MARK),
                        '--layer', layer, '--device', f'{layer}0', '--duplex', duplex,
                        '--max-packet', '1600', '--compression', 'off'],
            'initial_topology_commands': netns_lab.plan_document(spec)['commands'],
            'acceptance': 'same original tuple/SYN/TLS/phase sequences; native exact IPv4/IPv6 and TCP bytes; natural bounded carrier-loss failure; owned cleanup',
            'graceful_close': False, 'suite': suite,
            'not_qualified': ['offline cryptographic verification', 'protected clean close', 'impairment recovery',
                              'congestion', 'PMTU/NAT/middleboxes', 'hot switching', 'other platforms']}


def unsigned(value, maximum=2**64 - 1) -> bool:
    return type(value) is int and 0 <= value <= maximum


def validate_windows(value: dict) -> None:
    """Keep local storage, retained recovery and original native flight distinct."""
    if value['runtime_profile'] != 'raw-packet-runtime-v2':
        raise ValueError('wrong raw native delivery profile')
    for name in ('delivery', 'recovery', 'native_pending_bytes', 'native_pending_records'):
        if not isinstance(value[name], list) or len(value[name]) != 2:
            raise ValueError('invalid raw lane window array')
    for unit in ('packets', 'bytes'):
        used, limit = value[f'local_queue_{unit}'], value[f'local_queue_{unit}_limit']
        if not unsigned(used) or not unsigned(limit) or limit == 0 or used > limit:
            raise ValueError('local raw queue exceeds its own bound')
    for name in ('wire_bytes_per_second', 'wire_packets_per_second'):
        if not unsigned(value[name]) or value[name] == 0:
            raise ValueError('missing configured raw wire budget')
    for index in (0, 1):
        if (not unsigned(value['native_pending_bytes'][index], DELIVERY_POLICY['max_inflight_bytes'])
                or not unsigned(value['native_pending_records'][index], DELIVERY_POLICY['max_records'])):
            raise ValueError('native receive bank exceeds negotiated bound')
        if value['native_pending_records'][index] != value['received'][index] - value['delivered'][index]:
            raise ValueError('native receive bank differs from device delivery debt')
        flight = value['delivery'][index]
        if flight is not None:
            if (not isinstance(flight, dict) or set(flight) !=
                    FLIGHT_COUNTERS | SAMPLE_FIELDS | {'target_bytes', 'sample_fresh', 'retained_records'}
                    or any(not unsigned(flight[name]) for name in FLIGHT_COUNTERS)
                    or not unsigned(flight['target_bytes'], DELIVERY_POLICY['max_inflight_bytes'])
                    or flight['target_bytes'] == 0
                    or not unsigned(flight['retained_records'], DELIVERY_POLICY['max_records'])
                    or type(flight['sample_fresh']) is not bool):
                raise ValueError('invalid bounded native flight accounting')
            for unit in ('bytes', 'records'):
                admitted, delivered = flight[f'admitted_{unit}'], flight[f'delivered_{unit}']
                if (delivered > admitted or flight[f'outstanding_{unit}'] != admitted - delivered
                        or not 0 <= flight[f'flushed_{unit}'] <= flight[f'flushed_total_{unit}'] <= admitted):
                    raise ValueError('inconsistent native byte/record flight')
            if (flight['admitted_records'] != value['admitted'][index]
                    or flight['delivered_records'] != value['peer_delivered'][index]
                    or flight['outstanding_bytes'] > DELIVERY_POLICY['max_inflight_bytes']
                    or not flight['outstanding_records'] <= flight['retained_records'] <= flight['admitted_records']):
                raise ValueError('native flight does not match runtime ownership')
            samples = [flight[name] for name in SAMPLE_FIELDS]
            if (any(sample is None for sample in samples) and not all(sample is None for sample in samples)
                    or any(sample is not None and not unsigned(sample) for sample in samples)
                    or flight['sample_fresh'] and all(sample is None for sample in samples)):
                raise ValueError('incomplete or fabricated native RTT sample')
            if all(sample is not None for sample in samples) and (
                    not 0 < flight['raw_rtt_micros'] <= flight['sample_at_micros']
                    or not DELIVERY_POLICY['min_rtt_micros'] <= flight['smoothed_rtt_micros'] <= DELIVERY_POLICY['max_rtt_micros']):
                raise ValueError('native RTT sample violates causal clock or policy bounds')
        elif value['admitted'][index] or value['peer_delivered'][index]:
            raise ValueError('native flight missing despite admitted ownership')
        recovery = value['recovery'][index]
        if recovery is not None:
            if (not isinstance(recovery, dict) or set(recovery) !=
                    RECOVERY_COUNTERS | {name + '_limit' for name in RECOVERY_COUNTERS}
                    or any(not unsigned(n) for n in recovery.values())):
                raise ValueError('invalid retained recovery accounting')
            for name in RECOVERY_COUNTERS:
                limit = recovery[name + '_limit']
                if limit == 0 or recovery[name] > limit or name.endswith('records') and limit > 64:
                    raise ValueError('recovery exceeds independent source bound')
        elif flight is not None or value['native_pending_records'][index] or value['native_pending_bytes'][index]:
            raise ValueError('recovery accounting missing for an initialized lane')


def validate_snapshot(value: dict, digest: str | None = None, phase: str | None = None) -> dict:
    if (not isinstance(value, dict) or set(value) != {'requested', 'effective', 'capabilities', 'digest',
            'phase', 'fault', *COUNTERS, *WINDOW_FIELDS} or value['requested'] != SELECTION or value['effective'] != SELECTION
            or value['capabilities'] != CAPABILITIES
            or any(type(value['capabilities'].get(k)) is not bool for k in CAPABILITIES)
            or not isinstance(value['digest'], str) or not re.fullmatch('[0-9a-f]{64}', value['digest'])
            or digest is not None and value['digest'] != digest
            or value['phase'] not in ('Setup', 'Active', 'Stopped')
            or phase is not None and value['phase'] != phase
            or value['fault'] is not None and (not isinstance(value['fault'], str) or len(value['fault']) > 64)):
        raise ValueError('invalid actual raw runtime snapshot')
    for name in COUNTERS:
        if (not isinstance(value[name], list) or len(value[name]) != 2
                or any(type(n) is not int or not 0 <= n < 2**64 for n in value[name])):
            raise ValueError('invalid bounded raw counter')
    for index in (0, 1):
        if value['delivered'][index] > value['received'][index] or value['peer_delivered'][index] > value['admitted'][index]:
            raise ValueError('impossible native delivery credit')
    if value['phase'] != 'Stopped' and value['fault'] is not None:
        raise ValueError('nonterminal snapshot has a fault')
    validate_windows(value)
    return value


def validate_status(response: dict, digest: str | None = None, phase: str | None = 'Active') -> dict:
    if (not isinstance(response, dict) or set(response) != {'version', 'ok', 'code', 'state'}
            or type(response['version']) is not int or response['version'] != 1
            or response['ok'] is not True or response['code'] != 'ok'):
        raise ValueError('invalid local status envelope')
    state = response['state']
    if (not isinstance(state, dict) or set(state) != {'epoch', 'phase', 'compression', 'raw_packet'}
            or type(state['epoch']) is not int or state['epoch'] != 1 or state['compression'] != 'off'):
        raise ValueError('status is not the immutable raw profile')
    raw = validate_snapshot(state['raw_packet'], digest, phase)
    if state['phase'] != raw['phase']:
        raise ValueError('outer/runtime status phase mismatch')
    return raw


def event(text: str, name: str) -> dict:
    values = []
    for line in text.splitlines():
        if line.startswith('{'):
            value = bounded.strict_json(line)
            if isinstance(value, dict) and value.get('event') == name:
                values.append(value)
    if len(values) != 1:
        raise ValueError('one exact runtime event required: ' + name)
    return values[0]


def verify_terminal(text: str, code: int | None, observed: float, deadline: float, digest: str) -> dict:
    if (type(code) is not int or code <= 0 or not math.isfinite(observed)
            or not math.isfinite(deadline) or not 0 <= observed <= deadline):
        raise ValueError('missing, successful, signalled or late natural terminal outcome')
    value = event(text, 'raw_packet_terminal')
    if set(value) != {'event', 'state', 'error_kind'} or value['error_kind'] != 'TimedOut':
        raise ValueError('carrier loss did not report exact TimedOut')
    state = validate_snapshot(value['state'], digest, 'Stopped')
    if state['fault'] != 'TimedOut':
        raise ValueError('terminal process fault disagrees with carrier error')
    return {'exit_code': code, 'observed_at_monotonic': observed, 'event': value}


def confirmed(peers: dict, lanes: int) -> bool:
    if set(peers) != {'a', 'b'} or type(lanes) is not int or lanes not in (1, 2):
        raise ValueError('both actual lane owners required')
    for side in ('a', 'b'):
        other = 'b' if side == 'a' else 'a'
        a, b = peers[side], peers[other]
        for i in range(lanes):
            if a['admitted'][i] != a['peer_delivered'][i] or a['admitted'][i] != b['delivered'][i] or b['received'][i] != b['delivered'][i]:
                return False
        if lanes == 1 and any(a[name][1] for name in COUNTERS):
            raise ValueError('full runtime claims a second lane')
        if lanes == 2 and any(a[name][1 if side == 'a' else 0] for name in ('admitted', 'sources', 'peer_delivered')):
            raise ValueError('half runtime used the wrong bulk lane')
        active = range(lanes) if lanes == 1 else (0 if side == 'a' else 1,)
        if not all(a['admitted'][i] > 0 and a['sources'][i] > 0 and a['staged'][i] > 0 for i in active):
            return False
        for i in active:
            flight, recovery = a['delivery'][i], a['recovery'][i]
            if (flight is None or recovery is None or flight['outstanding_bytes']
                    or flight['outstanding_records'] or flight['retained_records']
                    or recovery['send_records'] or recovery['send_bytes']
                    or any(flight[f'{name}_{unit}'] != flight[f'admitted_{unit}']
                           for name in ('delivered', 'flushed', 'flushed_total')
                           for unit in ('bytes', 'records'))):
                return False
    return True


def phase_payload(data: bytes, lane: int, direction: int) -> dict | None:
    """Untrusted structural audit only; no HMAC key is exported or checked here."""
    if not (data[:1] == b'\x48' and data[4:6] == b'LD'):
        return None
    if len(data) < 128 or data[:4] != bytes([0x48, 0, 0, lane]):
        raise ValueError('invalid protected lane prefix')
    h = data[4:48]
    length = int.from_bytes(h[40:42], 'big')
    if (h[:6] != bytes([0x4c, 0x44, 1, 1, 2, direction]) or h[6:8] != bytes(2)
            or h[42:44] != bytes(2) or int.from_bytes(h[24:28], 'big') != lane
            or int.from_bytes(h[28:32], 'big') != 1 or len(data) != 48 + length + 32):
        raise ValueError('invalid fixed integrity datagram context/length')
    plain = data[48:-32]
    kind = plain[1] if len(plain) >= 48 else 0
    body = plain[48:]
    if (len(plain) < 48 or plain[0] != 1 or plain[2:4] != bytes(2) or plain[46:48] != bytes(2)
            or int.from_bytes(plain[44:46], 'big') != len(body) or kind not in range(1, 9)
            or kind == 1 and len(body) != 280 or kind in (2, 3) and len(body) != 104
            or kind in (4, 5) and not body or kind in (6, 7) and len(body) != 8
            or kind == 8 and body):
        raise ValueError('invalid protected phase header/body shape')
    if kind in (4, 5) and (len(body) < 8 or body[:4] != b'L2RP' or body[4] != 1
                           or body[6:8] != bytes(2) or body[5] not in ((1,) if kind == 4 else (2, 3))):
        raise ValueError('phase data/control does not carry runtime records')
    result = {'session': h[8:24].hex(), 'number': int.from_bytes(h[32:40], 'big'), 'kind': kind,
            'transaction': plain[4:20].hex(), 'offset': int.from_bytes(plain[20:28], 'big'),
            'retired': int.from_bytes(plain[28:36], 'big'), 'right_edge': int.from_bytes(plain[36:44], 'big')}
    if kind == 1: result['hello'] = hello_proofs(body)
    return result


def opaque_phase_payload(data: bytes, lane: int, direction: int) -> dict | None:
    """Read only clear AEAD framing; ciphertext and tag remain unverified opaque bytes."""
    if not (data[:1] == b'\x48' and data[4:6] == b'LD'):
        return None
    if (type(lane) is not int or lane not in (0, 1) or direction not in (1, 2)
            or not 112 <= len(data) <= 1160 or data[:4] != bytes([0x48, 0, 0, lane])):
        raise ValueError('invalid opaque protected lane prefix/length')
    h = data[4:48]
    length = int.from_bytes(h[40:42], 'big')
    if (h[:6] != bytes([0x4c, 0x44, 1, 1, 1, direction]) or h[6:8] != bytes(2)
            or h[42:44] != bytes(2) or int.from_bytes(h[24:28], 'big') != lane
            or int.from_bytes(h[28:32], 'big') != 1 or len(data) != 48 + length + 16):
        raise ValueError('invalid fixed AEAD datagram context/length')
    return {'session': h[8:24].hex(), 'number': int.from_bytes(h[32:40], 'big'),
            'encrypted_payload_bytes': length}


def hello_proofs(body: bytes) -> dict:
    """Observe complete fixed Hello fences; authentication remains the runtime's job."""
    if (len(body) != 280 or body[0] != 1 or body[1] != body[2]
            or body[2] not in (1, 2) or body[3:8] != bytes(5)):
        raise ValueError('invalid captured Hello header')
    count, proofs = body[2], []
    for lane in range(count):
        p = body[72 + lane * 104:176 + lane * 104]
        if (p[0] != lane or p[1] != (0 if count == 1 else lane + 1) or p[2] not in (1, 2)
                or p[3] & ~1 or p[62:64] != bytes(2) or p[68:72] != bytes(4)
                or p[54] > 14 or p[55] not in (*range(15), 255)):
            raise ValueError('invalid captured Hello lane shape')
        proof = {'lane': p[0], 'bulk': p[1], 'role': p[2], 'options': p[3], 'session': p[4:20].hex(),
                 'written': int.from_bytes(p[20:28], 'big'), 'read': int.from_bytes(p[28:36], 'big'),
                 'una': int.from_bytes(p[36:40], 'big'), 'next': int.from_bytes(p[40:44], 'big'),
                 'receive': int.from_bytes(p[44:48], 'big'), 'ack': int.from_bytes(p[48:52], 'big'),
                 'window': int.from_bytes(p[52:54], 'big'), 'scale': p[54], 'peer_scale': p[55],
                 'peer_window': int.from_bytes(p[56:60], 'big'), 'mss': int.from_bytes(p[60:62], 'big'),
                 'available': int.from_bytes(p[64:68], 'big')}
        if (not 0 < proof['written'] < 2**31 or not 0 < proof['read'] < 2**31
                or proof['una'] != proof['next'] or proof['ack'] != proof['receive']
                or proof['mss'] == 0 or proof['available'] != 0xffffffff - proof['next']):
            raise ValueError('invalid captured Hello lane fence')
        proofs.append(proof)
    if count == 1 and body[176:] != bytes(104):
        raise ValueError('unexpected unused Hello lane')
    return {'count': count, 'pair': body[8:40].hex(), 'armed': body[40:72].hex(),
            'lanes': proofs, 'sha256': hashlib.sha256(body).hexdigest()}


def syn_profile(tcp: bytes) -> tuple[int | None, int, bool]:
    options, cursor, found = tcp[20:(tcp[12] >> 4) * 4], 0, {}
    while cursor < len(options):
        kind = options[cursor]
        if kind == 0:
            if any(options[cursor:]): raise ValueError('invalid TCP SYN option padding')
            break
        if kind == 1:
            cursor += 1
            continue
        if cursor + 2 > len(options): raise ValueError('short TCP SYN option')
        size = options[cursor + 1]
        if (kind not in (2, 3, 4) or size != {2: 4, 3: 3, 4: 2}[kind]
                or cursor + size > len(options) or kind in found):
            raise ValueError('unsupported/duplicate TCP SYN option')
        found[kind] = options[cursor + 2:cursor + size]
        cursor += size
    shift = found[3][0] if 3 in found else None
    if shift is not None and shift > 14: raise ValueError('excessive TCP SYN window scale')
    # These are the pinned maintained TCP defaults/clamp, not an inferred window.
    mss = max(int.from_bytes(found[2], 'big'), 48) if 2 in found else 536
    return shift, mss, 4 in found


def tcp_parts(packet):
    ihl = 40 if packet.raw[0] >> 4 == 6 else (packet.raw[0] & 15) * 4
    tcp = packet.raw[ihl:]
    head = (tcp[12] >> 4) * 4
    return tcp, tcp[head:]


def audit_underlay(path: Path, lanes: int) -> dict:
    if type(lanes) is not int or lanes not in (1, 2):
        raise ValueError('invalid physical lane count')
    packets = bounded.read_pcap(path)
    flows = {}
    for packet in packets:
        if packet.protocol != 6 or packet.raw[0] >> 4 != 4 or len(packet.raw) > 1200 or packet.flags & 5:
            raise ValueError('foreign protocol or outer FIN/RST')
        key = (packet.source, packet.source_port, packet.destination, packet.destination_port)
        direction = 1 if packet.source == '192.0.2.2' else 2
        wanted = [(('192.0.2.2', a, '192.0.2.6', b), ('192.0.2.6', b, '192.0.2.2', a))
                  for a, b in retained.PORTS[:lanes]]
        lane = next((i for i, pair in enumerate(wanted) if key in pair), None)
        if lane is None:
            raise ValueError('capture has a new/foreign raw tuple')
        tcp, data = tcp_parts(packet)
        state = flows.setdefault(key, {'lane': lane, 'direction': direction, 'syn': set(), 'syn_profiles': set(), 'old_wire': set(), 'tls': [], 'phase': [], 'acks': set()})
        if packet.flags & 2:
            if data or packet.flags != (2 if direction == 1 else 18):
                raise ValueError('invalid original handshake flags')
            state['syn'].add(packet.sequence)
            state['syn_profiles'].add(syn_profile(tcp))
        if packet.flags & 16:
            state['acks'].add(int.from_bytes(tcp[8:12], 'big'))
        protected = phase_payload(data, lane, direction) if data else None
        if protected is None and packet.flags & 16 and not packet.flags & 2:
            state['old_wire'].add(((packet.sequence + len(data)) & 0xffffffff,
                                   int.from_bytes(tcp[8:12], 'big'), int.from_bytes(tcp[14:16], 'big')))
        if data:
            if protected is None:
                state['tls'].append((packet.sequence, data, packet.flags))
            else:
                if len(packet.raw) > 1200 or packet.flags != 24 or len(tcp) - len(data) != 20:
                    raise ValueError('phase is not the fixed header/MTU profile')
                state['phase'].append((packet.sequence, int.from_bytes(tcp[8:12], 'big'), data, protected, int.from_bytes(tcp[14:16], 'big')))
    if len(flows) != 2 * lanes:
        raise ValueError('missing original lane direction')
    details, sessions, transactions = [], {}, set()
    for key, state in flows.items():
        if len(state['syn']) != 1 or len(state['syn_profiles']) != 1 or not state['phase']:
            raise ValueError('missing/changed original SYN or phase continuation')
        isn = next(iter(state['syn']))
        base = (isn + 1) & 0xffffffff
        stream = bytearray()
        peer_acks = flows[(key[2], key[3], key[0], key[1])]['acks']
        for sequence, data, flags in sorted(state['tls'], key=lambda row: (row[0] - base) & 0xffffffff):
            offset = (sequence - base) & 0xffffffff
            # Maintained keepalive can carry one arbitrary ACK-only byte at the
            # already acknowledged old prefix. It is not new TLS stream data.
            if (flags == 16 and len(data) == 1 and offset < len(stream)
                    and ((sequence + 1) & 0xffffffff) in peer_acks):
                continue
            if offset > len(stream):
                raise ValueError('TLS bootstrap sequence gap')
            overlap = min(len(data), len(stream) - offset)
            if stream[offset:offset + overlap] != data[:overlap]:
                raise ValueError('conflicting TLS retransmission')
            stream.extend(data[overlap:])
        records = retained.tls_records(bytes(stream))
        if state['direction'] == 1:
            retained.client_hello_without_sni(records[0][1])
        elif records[0][1][:1] != b'\x02':
            raise ValueError('missing original ServerHello')
        state['base'] = (base + len(stream)) & 0xffffffff
        hellos = [item['hello'] for _, _, _, item, _ in state['phase'] if item['kind'] == 1]
        if (not hellos or len({h['sha256'] for h in hellos}) != 1
                or hellos[0]['count'] != lanes or len(state['syn_profiles']) != 1):
            raise ValueError('missing/conflicting Hello or SYN option proof')
        hello = hellos[0]
        proof = hello['lanes'][state['lane']]
        peer_profiles = flows[(key[2], key[3], key[0], key[1])]['syn_profiles']
        if len(peer_profiles) != 1: raise ValueError('missing/conflicting peer SYN options')
        peer_syn = next(iter(peer_profiles))
        own_syn = next(iter(state['syn_profiles']))
        scale = own_syn[0] if own_syn[0] is not None and peer_syn[0] is not None else 0
        if (proof['role'] != state['direction'] or proof['next'] != state['base']
                or proof['written'] != len(stream) or proof['scale'] != scale
                or proof['peer_scale'] != (peer_syn[0] if peer_syn[0] is not None else 255)
                or proof['mss'] != peer_syn[1] or proof['options'] != int(peer_syn[2])
                or (proof['next'], proof['receive'], proof['window']) not in state['old_wire']):
            raise ValueError('Hello fence is not witnessed by original TLS/SYN/window bytes')
        effective = (min(32768, proof['window'] << scale) >> scale) << scale
        if effective < 9 * (1200 - 40) or effective >> scale > 65535:
            raise ValueError('captured effective horizon outside production bounds')
        state['proof'], state['hello'], state['tls_bytes'] = proof, hello, len(stream)
        seen, intervals, kinds = {}, [], Counter()
        for sequence, ack, data, phase, window in state['phase']:
            number, offset = phase['number'], phase['offset']
            if number in seen:
                if seen[number] != (sequence, ack, data, window):
                    raise ValueError('packet nonce reused with different wire bytes')
                continue
            seen[number] = (sequence, ack, data, window)
            end = offset + len(data)
            if (sequence != state['base'] + offset or sequence + len(data) > 0xffffffff
                    or phase['retired'] > phase['right_edge'] or phase['right_edge'] - phase['retired'] != effective
                    or window != effective >> scale or phase['session'] != proof['session']
                    or any(offset < b and a < end for a, b in intervals)):
                raise ValueError('phase byte range reused or sequence/window mismatch')
            intervals.append((offset, end))
            kinds[phase['kind']] += 1
            sessions.setdefault(state['lane'], set()).add(phase['session'])
            transactions.add(phase['transaction'])
        if sorted(seen) != list(range(len(seen))) or min(a for a, _ in intervals) != 0 or kinds[1] == 0:
            raise ValueError('missing protected counter prefix or original Hello')
        if state['direction'] == 1 and kinds[2] == 0 or state['direction'] == 2 and kinds[3] == 0:
            raise ValueError('missing per-lane Commit/CommitAck')
        bulk = lanes == 1 or state['direction'] == (1 if state['lane'] == 0 else 2)
        if (bulk and kinds[4] == 0) or (not bulk and kinds[4] != 0):
            raise ValueError('protected Data missing or on wrong half lane')
        details.append({'tuple': list(key), 'isn': isn, 'tls_bytes': len(stream),
                        'tls_records': len(records), 'phase_base': state['base'], 'frozen_window': proof['window'],
                        'negotiated_scale': scale, 'effective_horizon': effective,
                        'phase_kinds': dict(kinds), 'unique_phase_packets': len(seen)})
    if any(len(ids) != 1 for ids in sessions.values()) or len(transactions) != 1:
        raise ValueError('changed phase transaction/session identity')
    for direction in (1, 2):
        owners = [state for state in flows.values() if state['direction'] == direction]
        if len({state['hello']['sha256'] for state in owners}) != 1:
            raise ValueError('Hello does not carry one all-lane fence')
        for state in owners:
            if any(state['hello']['lanes'][other['lane']] != other['proof'] for other in owners):
                raise ValueError('Hello all-lane proof disagrees with original lane')
    for key, state in flows.items():
        peer = flows[(key[2], key[3], key[0], key[1])]
        if (next(iter(state['syn'])) + 1) & 0xffffffff not in peer['acks']:
            raise ValueError('original SYN not acknowledged')
        proof, other = state['proof'], peer['proof']
        if (proof['read'] != peer['tls_bytes'] or proof['receive'] != peer['base']
                or proof['session'] != other['session'] or proof['peer_window'] != other['window'] << other['scale']
                or other['peer_window'] != proof['window'] << proof['scale']
                or state['hello']['pair'] != peer['hello']['pair'] or state['hello']['armed'] != peer['hello']['armed']):
            raise ValueError('captured peer Hello fences are not complementary')
        for _, ack, _, phase, _ in state['phase']:
            if ack != peer['base'] + phase['retired']:
                raise ValueError('phase ACK not mirrored from original peer sequence')
    return {'pcap': path.name, 'sha256': bounded.file_hash(path), 'ip_packets': len(packets),
            'streams': sorted(details, key=lambda row: row['tuple']), 'outer_fin_rst': 0,
            'audit': 'untrusted_integrity_structure_plus_actual_authenticated_runtime_outcome'}


def audit_aead_underlay(path: Path, lanes: int) -> dict:
    """Qualify visible continuity only; encrypted transition proofs are runtime-owned."""
    if type(lanes) is not int or lanes not in (1, 2):
        raise ValueError('invalid physical lane count')
    packets, flows = bounded.read_pcap(path), {}
    wanted = [(('192.0.2.2', a, '192.0.2.6', b), ('192.0.2.6', b, '192.0.2.2', a))
              for a, b in retained.PORTS[:lanes]]
    for packet in packets:
        if packet.protocol != 6 or packet.raw[0] >> 4 != 4 or len(packet.raw) > 1200 or packet.flags & 5:
            raise ValueError('foreign protocol or outer FIN/RST')
        key = (packet.source, packet.source_port, packet.destination, packet.destination_port)
        lane = next((i for i, pair in enumerate(wanted) if key in pair), None)
        if lane is None:
            raise ValueError('capture has a new/foreign raw tuple')
        direction = 1 if key == wanted[lane][0] else 2
        tcp, data = tcp_parts(packet)
        ack, window = int.from_bytes(tcp[8:12], 'big'), int.from_bytes(tcp[14:16], 'big')
        state = flows.setdefault(key, {'lane': lane, 'direction': direction, 'syn': set(),
            'syn_profiles': set(), 'old_wire': set(), 'tls': [], 'phase': [], 'acks': set()})
        if packet.flags & 2:
            if data or packet.flags != (2 if direction == 1 else 18):
                raise ValueError('invalid original handshake flags')
            state['syn'].add(packet.sequence)
            state['syn_profiles'].add(syn_profile(tcp))
        if packet.flags & 16:
            state['acks'].add(ack)
        protected = opaque_phase_payload(data, lane, direction) if data else None
        if protected is None and packet.flags & 16 and not packet.flags & 2:
            state['old_wire'].add(((packet.sequence + len(data)) & 0xffffffff, ack, window))
        if data:
            if protected is None:
                state['tls'].append((packet.sequence, data, packet.flags))
            else:
                if packet.flags != 24 or len(tcp) - len(data) != 20:
                    raise ValueError('phase is not the fixed header/MTU profile')
                state['phase'].append((packet.sequence, ack, data, protected, window))
    if len(flows) != 2 * lanes:
        raise ValueError('missing original lane direction')
    # Finish all TLS streams before relating opaque sequence/ACK ranges to peers.
    for key, state in flows.items():
        if len(state['syn']) != 1 or len(state['syn_profiles']) != 1 or not state['phase']:
            raise ValueError('missing/changed original SYN or phase continuation')
        base, stream = (next(iter(state['syn'])) + 1) & 0xffffffff, bytearray()
        peer = flows[(key[2], key[3], key[0], key[1])]
        if base not in peer['acks']:
            raise ValueError('original SYN not acknowledged')
        for sequence, data, flags in sorted(state['tls'], key=lambda row: (row[0] - base) & 0xffffffff):
            offset = (sequence - base) & 0xffffffff
            if (flags == 16 and len(data) == 1 and offset < len(stream)
                    and ((sequence + 1) & 0xffffffff) in peer['acks']):
                continue
            if offset > len(stream):
                raise ValueError('TLS bootstrap sequence gap')
            overlap = min(len(data), len(stream) - offset)
            if stream[offset:offset + overlap] != data[:overlap]:
                raise ValueError('conflicting TLS retransmission')
            stream.extend(data[overlap:])
        records = retained.tls_records(bytes(stream))
        if state['direction'] == 1:
            retained.client_hello_without_sni(records[0][1])
        elif records[0][1][:1] != b'\x02':
            raise ValueError('missing original ServerHello')
        state.update(base=(base + len(stream)) & 0xffffffff, tls_bytes=len(stream),
                     tls_records=len(records), tls_sha256=hashlib.sha256(stream).hexdigest())
    details, sessions = [], {}
    for key, state in flows.items():
        peer = flows[(key[2], key[3], key[0], key[1])]
        own_syn, peer_syn = next(iter(state['syn_profiles'])), next(iter(peer['syn_profiles']))
        scale = own_syn[0] if own_syn[0] is not None and peer_syn[0] is not None else 0
        windows = sorted({window for sequence, ack, window in state['old_wire']
                          if sequence == state['base'] and ack == peer['base']})
        horizons = {(min(32768, window << scale) >> scale) << scale for window in windows}
        if len(horizons) != 1:
            raise ValueError('missing or ambiguous original TCP window witness')
        effective = next(iter(horizons))
        if effective < 9 * (1200 - 40) or effective >> scale > 65535:
            raise ValueError('captured effective horizon outside production bounds')
        seen, identities = {}, set()
        for sequence, ack, data, phase, window in state['phase']:
            number = phase['number']
            wire = (sequence, ack, data, window)
            if number in seen:
                if seen[number] != wire:
                    raise ValueError('packet nonce reused with different wire bytes')
                continue
            seen[number] = wire
            if sequence < state['base'] or sequence + len(data) >= 0xffffffff or window != effective >> scale:
                raise ValueError('opaque phase sequence/window mismatch or wrap')
            identities.add(phase['session'])
        if len(identities) != 1 or sorted(seen) != list(range(len(seen))):
            raise ValueError('changed opaque session or missing protected counter prefix')
        cursor = state['base']
        for number in range(len(seen)):
            sequence, _, data, _ = seen[number]
            if sequence != cursor:
                raise ValueError('opaque phase byte range reused or sequence gap')
            cursor += len(data)
        state['ends'] = {state['base']} | {seq + len(data) for seq, _, data, _ in seen.values()}
        state['identity'] = next(iter(identities))
        sessions.setdefault(state['lane'], set()).add(state['identity'])
        details.append({'tuple': list(key), 'isn': next(iter(state['syn'])),
                        'tls_bytes': state['tls_bytes'], 'tls_records': state['tls_records'],
                        'tls_sha256': state['tls_sha256'], 'phase_base': state['base'],
                        'original_window_candidates': windows, 'negotiated_scale': scale,
                        'effective_horizon': effective, 'session': state['identity'],
                        'unique_opaque_phase_packets': len(seen)})
    if any(len(ids) != 1 for ids in sessions.values()):
        raise ValueError('peer opaque session identity mismatch')
    for key, state in flows.items():
        peer = flows[(key[2], key[3], key[0], key[1])]
        if any(ack not in peer['ends'] for _, ack, _, _, _ in state['phase']):
            raise ValueError('opaque phase ACK is not an observed peer boundary')
    return {'pcap': path.name, 'sha256': bounded.file_hash(path), 'ip_packets': len(packets),
            'streams': sorted(details, key=lambda row: row['tuple']), 'outer_fin_rst': 0,
            'audit': 'opaque_AEAD_structure_plus_actual_authenticated_runtime_outcome',
            'decrypts_or_verifies_tags': False, 'inspects_transition_or_data_kinds': False}


def audit_aead_captured_peers(paths: dict[str, Path], lanes: int) -> dict:
    result = {side: audit_aead_underlay(path, lanes) for side, path in paths.items()}
    def bootstrap(value):
        return [{k: v for k, v in row.items() if k != 'unique_opaque_phase_packets'}
                for row in value['streams']]
    if set(result) != {'a', 'b'} or bootstrap(result['a']) != bootstrap(result['b']):
        raise ValueError('captured peers disagree on original bootstrap/opaque session boundaries')
    seen = {}
    for side, path in paths.items():
        records = {}
        for packet in bounded.read_pcap(path):
            tcp, data = tcp_parts(packet)
            lane = next(i for i, ports in enumerate(retained.PORTS[:lanes]) if packet.source_port in ports)
            direction = 1 if packet.source == '192.0.2.2' else 2
            item = opaque_phase_payload(data, lane, direction) if data else None
            if item is not None:
                records[(lane, direction, item['number'])] = (
                    packet.sequence, tcp[8:12], tcp[14:16], hashlib.sha256(data).hexdigest())
        seen[side] = records
    common = seen['a'].keys() & seen['b'].keys()
    if any(seen['a'][key] != seen['b'][key] for key in common):
        raise ValueError('same opaque counter differs across captures')
    if any(not any(key[:2] == (lane, direction) for key in common)
           for lane in range(lanes) for direction in (1, 2)):
        raise ValueError('no identical opaque packets at both original lane owners')
    return {'peers': result, 'common_opaque_phase_packets': len(common),
            'scope': 'opaque framing only; authenticated native delivery is checked separately; final loss may change counter tails'}


def audit_native(paths: dict[str, Path], flows: list[dict]) -> dict:
    packets = {side: bounded.read_pcap(path) for side, path in paths.items()}
    if set(packets) != {'a', 'b'} or not packets['a']:
        raise ValueError('both nonempty native captures required')
    if Counter(p.raw for p in packets['a']) != Counter(p.raw for p in packets['b']):
        raise ValueError('native IP/TCP packet bytes/counts changed across the carrier')
    required = {(4, 1), (6, 58), (4, 6), (6, 6)}
    if not required.issubset({(p.raw[0] >> 4, p.protocol) for p in packets['a']}):
        raise ValueError('missing native IPv4/IPv6 ICMP/TCP coverage')
    streams = []
    for flow in flows:
        for reverse in (False, True):
            key = ((flow['destination'], flow['destination_port'], flow['source'], flow['source_port'])
                   if reverse else (flow['source'], flow['source_port'], flow['destination'], flow['destination_port']))
            selected = [p for p in packets['a'] if p.protocol == 6
                        and (p.source, p.source_port, p.destination, p.destination_port) == key]
            syn = {p.sequence for p in selected if p.flags & 2}
            if len(syn) != 1 or not any(p.flags & 1 for p in selected) or any(p.flags & 4 for p in selected):
                raise ValueError('native TCP SYN/FIN/RST mismatch')
            base, stream = (next(iter(syn)) + 1) & 0xffffffff, bytearray()
            segments = [(p.sequence, tcp_parts(p)[1]) for p in selected if tcp_parts(p)[1]]
            for seq, data in sorted(segments, key=lambda row: (row[0] - base) & 0xffffffff):
                offset = (seq - base) & 0xffffffff
                if offset > len(stream):
                    raise ValueError('native TCP payload gap')
                overlap = min(len(data), len(stream) - offset)
                if stream[offset:offset + overlap] != data[:overlap]:
                    raise ValueError('native TCP payload conflicting retransmission')
                stream.extend(data[overlap:])
            expected = bounded.payload(bounded.PAYLOAD_LENGTHS[1 if reverse else 0], 29 if reverse else 11)
            if stream != expected:
                raise ValueError('native captured TCP differs from exact probe bytes')
            streams.append({'tuple': list(key), 'bytes': len(stream), 'sha256': hashlib.sha256(stream).hexdigest()})
    return {'exact_native_packet_multiset': True, 'ip_packets_each_side': len(packets['a']), 'streams': streams}


def audit_captured_peers(paths: dict[str, Path], lanes: int, suite: str = 'integrity') -> dict:
    if suite == 'aead':
        return audit_aead_captured_peers(paths, lanes)
    if suite != 'integrity':
        raise ValueError('unsupported protection suite')
    result = {side: audit_underlay(path, lanes) for side, path in paths.items()}
    if set(result) != {'a', 'b'} or result['a']['streams'] != result['b']['streams']:
        # Counter tails legitimately differ after intentional loss. Compare the
        # original SYN/TLS boundaries here, then require common actual Data below.
        def bootstrap(value):
            return [{k: row[k] for k in ('tuple', 'isn', 'tls_bytes', 'tls_records', 'phase_base', 'frozen_window', 'negotiated_scale', 'effective_horizon')}
                    for row in value['streams']]
        if set(result) != {'a', 'b'} or bootstrap(result['a']) != bootstrap(result['b']):
            raise ValueError('captured peers disagree on original bootstrap/phase boundaries')
    seen = {}
    for side, path in paths.items():
        data = set()
        for p in bounded.read_pcap(path):
            tcp, body = tcp_parts(p)
            lane = next((i for i, ports in enumerate(retained.PORTS[:lanes]) if p.source_port in ports), 0)
            item = phase_payload(body, lane, 1 if p.source == '192.0.2.2' else 2) if body else None
            if item is not None and item['kind'] == 4:
                data.add((p.source, p.source_port, item['number'], hashlib.sha256(body).hexdigest()))
        seen[side] = data
    common = seen['a'] & seen['b']
    for lane, ports in enumerate(retained.PORTS[:lanes]):
        for direction in ((1, 2) if lanes == 1 else ((1,) if lane == 0 else (2,))):
            source, port = ('192.0.2.2', ports[0]) if direction == 1 else ('192.0.2.6', ports[1])
            if not any(row[:2] == (source, port) for row in common):
                raise ValueError('no same protected Data captured at both original tuple owners')
    return {'peers': result, 'common_protected_data_packets': len(common),
            'scope': 'counter tails may differ only because final carrier loss is intentional'}


def source_hashes(root: Path = ROOT) -> dict[str, str]:
    result = bounded.source_hashes(root)
    for name in (*HELPERS, 'tools/test_raw_packet_native_smoke.py'):
        result[name] = bounded.file_hash(root / name)
    return result


def verify_helpers(build: dict, output: Path, loaded: bool = False) -> dict:
    result = {}
    for name, module in HELPERS.items():
        path, digest = output / Path(name).name, build.get('source_sha256_after', {}).get(name)
        if (path.is_symlink() or not path.is_file() or not isinstance(digest, str)
                or bounded.file_hash(path) != digest or loaded and module.resolve() != path.resolve()):
            raise ValueError('copied/executed helper differs from original binary build: ' + name)
        result[name] = digest
    return result


def raw_inodes(table: str) -> set[str]:
    if (len(table) > 65536 or not table.splitlines()
            or 'local_address' not in table.splitlines()[0] or 'inode' not in table.splitlines()[0]):
        raise ValueError('raw descriptor table header/bound invalid')
    values = set()
    for line in table.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10 or re.fullmatch('[0-9]+', parts[9]) is None:
            raise ValueError('invalid Linux raw descriptor table')
        if parts[1].endswith(':0006'):
            values.add(parts[9])
    return values


def observe_owner(pid: int, lanes: int, previous: dict | None = None, proc: Path = Path('/proc')) -> dict:
    directory = proc / str(pid)
    state = (directory / 'stat').read_text()
    start = state[state.rfind(')') + 2:].split()[19]
    inodes = raw_inodes((directory / 'net/raw').read_text())
    descriptors = {}
    paths = list((directory / 'fd').iterdir())
    if len(paths) > 64:
        raise ValueError('owned process descriptor bound exceeded')
    for path in paths:
        try:
            link = os.readlink(path)
        except FileNotFoundError:
            continue  # A non-raw transient fd can close between listing/readlink.
        match = re.fullmatch(r'socket:\[([0-9]+)\]', link)
        if match and match[1] in inodes:
            descriptors[path.name] = match[1]
    if len(descriptors) > lanes or previous and (previous['start'] != start
            or any(descriptors.get(fd) != inode for fd, inode in previous['raw_fds'].items())):
        raise ValueError('original raw descriptor disappeared or was replaced')
    return {'pid': pid, 'start': start, 'raw_fds': descriptors}


def reservation_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description='Internal exact-tuple reservation inspection')
    parser.add_argument('local', type=ipaddress.IPv4Address)
    parser.add_argument('mode', choices=('held', 'released'))
    parser.add_argument('ports', nargs='+', type=int)
    args = parser.parse_args(argv)
    if not 1 <= len(args.ports) <= 2 or len(set(args.ports)) != len(args.ports) or not all(0 < p < 65536 for p in args.ports):
        raise ValueError('invalid reservation probe ports')
    for port in args.ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            try:
                stream.bind((str(args.local), port))
                held = False
            except OSError as error:
                if error.errno != 98:
                    raise
                held = True
            if held != (args.mode == 'held'):
                raise ValueError('original tuple reservation state differs')
    print(json.dumps({'local': str(args.local), 'ports': args.ports, 'state': args.mode}))
    return 0


def no_kernel_stream(text: str, lanes: int) -> None:
    if type(lanes) is not int or lanes not in (1, 2):
        raise ValueError('invalid kernel stream lane count')
    for line in text.splitlines():
        if any(re.search(rf'(?:^|\s)\S+:{port}(?:\s|$)', line)
               for pair in retained.PORTS[:lanes] for port in pair):
            fields = line.split()
            # Some ss versions include the required bound-but-unconnected port
            # reservation. It is not a connected/listening kernel stream.
            if (len(fields) >= 5 and fields[0] in ('CLOSE', 'UNCONN')
                    and fields[4] in ('0.0.0.0:*', '0.0.0.0:0', '*:*')):
                continue
            raise ValueError('kernel TCP owns an original raw lane tuple')


def cleanup_sockets(paths: dict[Path, tuple[int, int]], processes: list) -> list[str]:
    if any(p.poll() is None for p in processes):
        raise ValueError('cannot remove local sockets while a child remains live')
    removed = []
    for path, identity in paths.items():
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parent = os.fstat(fd)
            if (parent.st_dev, parent.st_ino) != identity or stat.S_IMODE(parent.st_mode) != 0o700:
                raise ValueError('private socket directory identity changed')
            try:
                value = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISSOCK(value.st_mode):
                raise ValueError('private socket path replaced with a non-socket')
            os.unlink(path.name, dir_fd=fd)
            removed.append(str(path))
        finally:
            os.close(fd)
    return removed


def classify(error: Exception) -> str:
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return 'bound_exhausted'
    if isinstance(error, bounded.Unsupported):
        return 'unsupported'
    return 'tool_failure' if isinstance(error, OSError) else 'failed'


def run_case(plan: dict, binary: Path, harness: Path, output: Path, secrets: Path, state_dir: Path) -> dict:
    start, spec = time.monotonic(), netns_lab.LabSpec(plan['lab_id'])
    end, ns, lanes = start + BOUNDS['case'], spec.namespaces, plan['lanes']
    case_dir = output / plan['case']; case_dir.mkdir()
    control = case_dir / 'control'; control.mkdir(mode=0o700)
    parent = control.stat()
    sockets = {side: control / f'{side}.sock' for side in ('a', 'b')}
    socket_owners = {path: (parent.st_dev, parent.st_ino) for path in sockets.values()}
    receipt = bounded.Receipt(case_dir / 'receipt.json', {'status': 'running', 'plan': plan,
                              'stage': 'create_owned_topology', 'cleanup': 'pending', 'graceful_close': False})
    processes, captures, paths, daemons, owners = [], {}, {}, {}, {}
    created, failure, samples = False, None, []
    def run(argv, cap=10):
        return bounded.command(argv, end, cap)
    def nsrun(side, *args, native=False):
        role = f'host_{side}' if native and plan['layer'] == 'tap' else f'endpoint_{side}'
        return ['ip', 'netns', 'exec', ns[role], *args]
    def identities():
        return retained.owned(spec, state_dir)
    def exact_rules(install):
        original = retained.command
        retained.command = lambda argv, timeout=60: bounded.command(argv, end, min(timeout, BOUNDS['command']))
        try:
            return retained.rules(spec, lanes, install, MARK)
        finally:
            retained.command = original
    def stage(name, **fields):
        receipt.update(stage=name, **fields)
    def snapshots(deadline, expected_phase='Active'):
        if len(samples) >= MAX_SAMPLES:
            raise TimeoutError('status sample budget exhausted')
        values = {side: bounded.rpc(path, 'status', deadline) for side, path in sockets.items()}
        observed = {side: validate_status(value, phase=expected_phase) for side, value in values.items()}
        digest = observed['a']['digest']
        for value in values.values(): validate_status(value, digest, expected_phase)
        samples.append({'at_monotonic': time.monotonic(), 'peers': observed})
        return observed
    def inspect_live():
        for side, (process, _) in daemons.items():
            if process.poll() is not None:
                raise RuntimeError('original raw process exited before the carrier-loss stage')
            owners[side] = observe_owner(process.pid, lanes, owners.get(side))
        identities()
    try:
        bounded.bounded_lab(netns_lab.apply, spec, state_dir, end); created = True
        identities()
        exact_rules(True)
        network = 18 if plan['layer'] == 'tap' else 19
        features = {}
        for side, number in (('a', '1'), ('b', '2')):
            endpoint = ns[f'endpoint_{side}']
            run(['ip', 'netns', 'exec', endpoint, 'tc', 'qdisc', 'change', 'dev', 'wan0', 'parent', '1:10',
                 'handle', '10:', 'netem', 'limit', '1000', 'delay', '1ms', 'loss', 'random', '0%'])
            if plan['layer'] == 'tun':
                run(['ip', '-n', endpoint, 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun'])
                run(['ip', '-n', endpoint, 'link', 'set', 'tun0', 'mtu', '1500', 'up'])
                run(['ip', '-n', endpoint, 'address', 'add', f'198.19.0.{number}/24', 'dev', 'tun0'])
            native_ns = ns[f'host_{side}' if plan['layer'] == 'tap' else f'endpoint_{side}']
            interface = 'eth0' if plan['layer'] == 'tap' else 'tun0'
            run(['ip', '-n', native_ns, '-6', 'address', 'add', f'fd42:12:{network}::{number}/64', 'dev', interface, 'nodad'])
            for label, namespace, device in [('wan', endpoint, 'wan0'), ('native', native_ns, interface)]:
                features[f'{side}_{label}'] = bounded.offloads(namespace, device, end)
        for interface in ('a0', 'b0'):
            features['router_' + interface] = bounded.offloads(ns['router'], interface, end)
        underlay_ipv6 = bounded.disable_underlay_ipv6(ns, end)
        if plan['layer'] == 'tap':
            mac = {side: json.loads(run(['ip', '-j', '-n', ns[f'host_{side}'], 'link', 'show', 'dev', 'eth0']))[0]['address'] for side in ('a', 'b')}
            for side, peer in (('a', 'b'), ('b', 'a')):
                number = '2' if peer == 'b' else '1'
                for address in (f'198.18.0.{number}', f'fd42:12:18::{number}'):
                    run(['ip', '-n', ns[f'host_{side}'], 'neigh', 'replace', address, 'lladdr', mac[peer], 'nud', 'permanent', 'dev', 'eth0'])
        stage('prearm_capture', identities=identities(), offloads=features, underlay_ipv6=underlay_ipv6)
        for side in ('a', 'b'):
            for label, interface, native in [('wan', 'wan0', False), ('native', 'eth0' if plan['layer'] == 'tap' else 'tun0', True)]:
                key = side + '_' + label
                path, log = case_dir / f'{key}.pcap', case_dir / f'{key}-capture.log'
                filter_args = ['tcp', 'portrange', '24440-24443'] if label == 'wan' else [
                    '(', 'ip', 'and', 'net', f'198.{network}.0.0/24', ')', 'or', '(', 'ip6', 'and', 'net', f'fd42:12:{network}::/64', ')']
                process = bounded.start_capture(nsrun(side, 'tcpdump', '-U', '-n', '-i', interface, '-s', '0', '-c',
                    str(bounded.PACKET_LIMIT), '-w', str(path), *filter_args, native=native), log, min(end, time.monotonic() + 5))
                captures[key], paths[key] = (process, log), path
                processes.append(process)
        stage('original_authentication')
        for side, operation in (('b', 'serve'), ('a', 'connect')):
            document = plan['policies'][side]
            policy_path = case_dir / f'{side}-policy.json'
            policy_path.write_text(json.dumps(document, indent=2) + '\n')
            flags = (['--listen', document['forward']['local'], '--cert', str(secrets / 'cert.der'), '--key', str(secrets / 'server.der'), '--allow-key', str(secrets / 'member.pub')]
                     if side == 'b' else ['--remote', document['forward']['peer'], '--ca', str(secrets / 'cert.der'), '--server-name', 'lab.invalid', '--identity', str(secrets / 'member.der')])
            log = case_dir / f'{side}-daemon.log'
            process = bounded.launch(nsrun(side, str(binary), operation, *flags, *plan['profile'],
                 '--raw-policy', str(policy_path), '--control-socket', str(sockets[side])), log)
            daemons[side] = (process, log); processes.append(process)
        ready = min(end, time.monotonic() + BOUNDS['startup'])
        while True:
            inspect_live()
            try:
                peers = snapshots(ready, None)
                if all(value['phase'] == 'Active' for value in peers.values()):
                    break
            except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
                pass
            time.sleep(min(.05, bounded.remaining(ready, .05)))
        # A status RPC can advance from setup to Active after the prior procfs
        # sample. Resample the same original owners at the actual Active boundary.
        inspect_live()
        digest = peers['a']['digest']
        for side, (process, log) in daemons.items():
            proof = event(bounded.read_log(log), 'raw_packet_authenticated')
            if set(proof) != {'event', 'state'}:
                raise ValueError('invalid authenticated startup event')
            validate_snapshot(proof['state'], digest)
            if len(owners[side]['raw_fds']) != lanes:
                raise ValueError('missing original native descriptor ownership')
            text = run(nsrun(side, 'ss', '-Htan'))
            no_kernel_stream(text, lanes)
            ports = [str(pair[0 if side == 'a' else 1]) for pair in retained.PORTS[:lanes]]
            run(nsrun(side, sys.executable, str(harness), 'reservation', f'192.0.2.{2 if side == "a" else 6}', 'held', *ports))
        stage('native_ipv4_ipv6', digest=digest, startup=peers, original_raw_owners=owners)
        pings = []
        for side, peer in (('a', '2'), ('b', '1')):
            for family, address in ((4, f'198.{network}.0.{peer}'), (6, f'fd42:12:{network}::{peer}')):
                text = run(nsrun(side, 'ping', f'-{family}', '-n', '-c', '1', '-W', '3', '-s', '117', address, native=True), 5)
                retained.ping_counts(text)
                pings.append({'side': side, 'family': family, 'stdout': text})
        transfers, batch = [], []
        transfer_end = min(end, time.monotonic() + BOUNDS['transfer'])
        for flow in plan['flows']:
            args = [flow['source'], flow['destination'], str(flow['source_port']), str(flow['destination_port'])]
            for side, role in (('b', 'listen'), ('a', 'connect')):
                log = case_dir / f'tcp{flow["family"]}-{role}.log'
                process = bounded.launch(nsrun(side, sys.executable, str(harness), 'probe', role, *args, native=True), log)
                processes.append(process); batch.append((process, log, flow, role))
                if role == 'listen': bounded.wait_log(process, log, 'Listening', transfer_end)
        for process, log, flow, role in batch:
            if process.wait(timeout=bounded.remaining(transfer_end, BOUNDS['transfer'])) != 0:
                raise RuntimeError('native TCP probe failed: ' + bounded.read_log(log))
            result = bounded.strict_json(bounded.read_log(log).splitlines()[-1])
            bounded.verify_probe(result, flow, role)
            transfers.append(result)
        confirmation_end = min(end, time.monotonic() + BOUNDS['confirmed'])
        while True:
            inspect_live()
            peers = snapshots(confirmation_end)
            if confirmed(peers, lanes): break
            time.sleep(min(.05, bounded.remaining(confirmation_end, .05)))
        stage('native_confirmed', pings=pings, transfers=transfers, native_confirmed=peers, status_samples=samples,
              owners_before_loss=owners, rules_before_loss=exact_rules(False))
        # No graceful drain is requested. Natural carrier timeout is the intended
        # terminal result, and forced finally-cleanup can never satisfy it.
        loss = {}
        for side in ('a', 'b'):
            identities()
            loss[side] = {'install_started': time.monotonic()}
            run(nsrun(side, 'tc', 'qdisc', 'change', 'dev', 'wan0', 'parent', '1:10', 'handle', '10:',
                      'netem', 'limit', '1000', 'delay', '1ms', 'loss', 'random', '100%'), 2)
            loss[side]['installed'] = time.monotonic()
            text = run(nsrun(side, 'tc', '-s', 'qdisc', 'show', 'dev', 'wan0'), 2)
            if re.search(r'\bloss 100(?:\.0+)?%', text) is None:
                raise ValueError('owned carrier loss was not actually installed')
            loss[side]['effective_qdisc'] = text
        loss_deadline = min(end, max(row['installed'] for row in loss.values()) + BOUNDS['carrier_loss'])
        stage('deliberate_carrier_loss', loss=loss, original_loss_deadline_monotonic=loss_deadline)
        terminal = {}
        while len(terminal) < 2:
            for side, (process, log) in daemons.items():
                if side not in terminal and process.poll() is not None:
                    terminal[side] = verify_terminal(bounded.read_log(log), process.returncode, time.monotonic(), loss_deadline, digest)
            if len(terminal) < 2:
                time.sleep(min(.05, bounded.remaining(loss_deadline, .05)))
        for side, (process, _) in daemons.items():
            process.wait(timeout=bounded.remaining(end, 1))
            no_kernel_stream(run(nsrun(side, 'ss', '-Htan')), lanes)
            if raw_inodes(run(nsrun(side, 'cat', '/proc/net/raw'))):
                raise ValueError('original raw descriptors remain after natural peer exit')
            ports = [str(pair[0 if side == 'a' else 1]) for pair in retained.PORTS[:lanes]]
            run(nsrun(side, sys.executable, str(harness), 'reservation', f'192.0.2.{2 if side == "a" else 6}', 'released', *ports))
        stage('audit_capture', natural_terminal=terminal, descriptor_and_reservation_release=True)
        counts = {key: bounded.finish_capture(process, log) for key, (process, log) in captures.items()}
        for key, value in counts.items():
            if len(bounded.read_pcap(paths[key])) != value['captured']:
                raise ValueError('capture file/counter mismatch')
        audit = audit_captured_peers({side: paths[side + '_wan'] for side in ('a', 'b')}, lanes, plan['suite'])
        native = audit_native({side: paths[side + '_native'] for side in ('a', 'b')}, plan['flows'])
        stage('completed', capture_counts=counts, underlay_audit=audit, native_audit=native,
              capture_sha256={key: bounded.file_hash(path) for key, path in paths.items()},
              rules_after=exact_rules(False), identities_after=identities())
    except Exception as error:
        failure = error
        receipt.update(status=classify(error), error=str(error)[:4096])
    finally:
        errors = []
        for process in reversed(processes):
            try: bounded.stop(process)
            except Exception as error: errors.append(str(error)[:256])
        for process, log in captures.values():
            if process.stderr is not None and not process.stderr.closed:
                try: bounded.finish_capture(process, log)
                except Exception: pass
        try:
            if errors or any(p.poll() is None for p in processes):
                raise RuntimeError('owned children not reaped: ' + repr(errors))
            removed = cleanup_sockets(socket_owners, processes)
            if created:
                bounded.bounded_lab(netns_lab.cleanup, spec, state_dir, time.monotonic() + BOUNDS['cleanup'])
            if any((netns_lab.NETNS_DIRECTORY / name).exists() for name in ns.values()):
                raise RuntimeError('owned namespaces remain after cleanup')
            receipt.update(cleanup='passed', removed_owned_sockets=removed,
                status='passed' if failure is None else receipt.value['status'],
                elapsed_seconds=time.monotonic() - start, original_children_reaped=True)
        except Exception as error:
            failure = error
            receipt.update(cleanup='failed', status='failed', cleanup_error=str(error)[:4096])
    if failure is not None:
        raise RuntimeError(f'{plan["case"]} failed; inspect {receipt.path}') from failure
    return receipt.value


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'probe':
        return bounded.probe_main(argv[1:])
    if argv and argv[0] == 'reservation':
        return reservation_main(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--lab-id', default='rawpkt')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--suite', choices=('integrity', 'aead'), default='integrity')
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/l2tunnel-linux')
    parser.add_argument('--build-receipt', type=Path)
    parser.add_argument('--state-dir', type=Path, default=Path('/run/l2tunnel-labs'))
    parser.add_argument('--only-case', choices=[f'{layer}-{mode}-clean' for layer in ('tap', 'tun') for mode in ('full', 'half')])
    parser.add_argument('--frozen-worker', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    args.output = args.output or ROOT / ('work/raw-packet-native' + ('-aead' if args.suite == 'aead' else ''))
    plans = [case_plan(args.lab_id, layer, duplex, args.suite) for layer in ('tap', 'tun') for duplex in ('full', 'half')
             if args.only_case is None or args.only_case == f'{layer}-{duplex}-clean']
    if not args.apply:
        print(json.dumps({'status': 'dry_run', 'cases': plans, 'output': str(args.output),
                          'binary': str(args.binary), 'mutations': 'none', 'graceful_close': False}, indent=2))
        return 0
    if sys.platform != 'linux':
        raise bounded.Unsupported('native harness requires Linux')
    netns_lab.require_root()
    if args.build_receipt is None:
        raise ValueError('--build-receipt is required for apply')
    for tool in ('ip', 'tc', 'sysctl', 'ethtool', 'tcpdump', 'ss', 'ping', 'openssl'):
        if shutil.which(tool) is None:
            raise FileNotFoundError('required executable missing: ' + tool)
    if not Path('/usr/sbin/iptables').is_file():
        raise FileNotFoundError('canonical /usr/sbin/iptables is required')
    build = bounded.verified_build_receipt(args.build_receipt, args.binary)
    if not args.frozen_worker:
        args.output.mkdir(mode=0o755)
    output = args.output.resolve()
    binary, harness = output / 'l2tunnel-native', output / 'raw_packet_native_smoke.py'
    if not args.frozen_worker:
        shutil.copyfile(args.binary, binary); binary.chmod(0o755)
        for name, source in HELPERS.items():
            shutil.copyfile(source, output / Path(name).name)
        shutil.copyfile(args.build_receipt, output / 'build-receipt.json')
        verify_helpers(build, output)
        (output / 'launch-sources.json').write_text(json.dumps(source_hashes(), sort_keys=True) + '\n')
        identity = output.stat()
        arguments = [sys.executable, str(harness), '--apply', '--lab-id', args.lab_id, '--output', str(output),
                     '--suite', args.suite,
                     '--binary', str(binary), '--build-receipt', str(output / 'build-receipt.json'),
                     '--state-dir', str(args.state_dir.resolve()), '--frozen-worker', f'{identity.st_dev}:{identity.st_ino}']
        if args.only_case: arguments.extend(['--only-case', args.only_case])
        os.execve(sys.executable, arguments, {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        raise RuntimeError('copied worker exec unexpectedly returned')
    identity = output.stat()
    expected = {Path(name).name for name in HELPERS} | {'l2tunnel-native', 'build-receipt.json', 'launch-sources.json'}
    if (args.frozen_worker != f'{identity.st_dev}:{identity.st_ino}' or args.output.is_symlink()
            or identity.st_uid != os.geteuid() or identity.st_mode & 0o022
            or args.binary.resolve() != binary or args.build_receipt.resolve() != output / 'build-receipt.json'
            or {p.name for p in output.iterdir()} != expected):
        raise ValueError('fresh exclusive copied-worker identity/layout required')
    hashes = verify_helpers(build, output, loaded=True)
    if bounded.verified_build_receipt(output / 'build-receipt.json', binary) != build:
        raise ValueError('build receipt changed while copying worker')
    source_path = output / 'launch-sources.json'
    if source_path.stat().st_size > bounded.RECEIPT_LIMIT:
        raise ValueError('launch source observation exceeds receipt bound')
    launch_sources = bounded.strict_json(source_path.read_bytes())
    if not isinstance(launch_sources, dict) or any(launch_sources.get(k) != v for k, v in hashes.items()):
        raise ValueError('launch helper hashes differ from exact build')
    receipt = bounded.Receipt(output / 'receipt.json', {'status': 'running', 'cleanup': 'pending',
        'scope': f'clean {args.suite} TAP/TUN full/half raw packet cases with expected carrier-loss failure',
        'suite': args.suite,
        'graceful_close': False, 'cases': [], 'execution': 'copied_helpers_exact_build_sources',
        'binary_sha256': bounded.file_hash(binary), 'build_receipt_sha256': bounded.file_hash(output / 'build-receipt.json'),
        'executed_helper_sha256': hashes, 'binary_build_source_sha256': build['source_sha256_after'],
        'source_observed_at_launch_sha256': launch_sources})
    cases = []
    try:
        with tempfile.TemporaryDirectory(prefix='l2t-rawpkt-secrets-') as directory:
            secrets, end = Path(directory), time.monotonic() + 30
            def run(*argv): return bounded.command(list(argv), end)
            run(str(binary), 'keygen', '--private', str(secrets / 'member.der'), '--public', str(secrets / 'member.pub'))
            run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', str(secrets / 'server.pem'), '-out', str(secrets / 'cert.pem'), '-days', '1', '-subj', '/CN=lab.invalid',
                '-addext', 'subjectAltName=DNS:lab.invalid', '-addext', 'basicConstraints=critical,CA:FALSE')
            run('openssl', 'x509', '-in', str(secrets / 'cert.pem'), '-outform', 'DER', '-out', str(secrets / 'cert.der'))
            run('openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(secrets / 'server.pem'), '-outform', 'DER', '-out', str(secrets / 'server.der'))
            for plan in plans:
                verify_helpers(build, output, loaded=True)
                case = run_case(plan, binary, harness, output, secrets, args.state_dir)
                verify_helpers(build, output, loaded=True)
                cases.append({'case': plan['case'], 'status': case['status'], 'cleanup': case['cleanup']})
                receipt.update(cases=cases)
        bounded.verified_build_receipt(output / 'build-receipt.json', binary)
        receipt.update(status='passed', cleanup='passed', executed_helpers_unchanged=True)
    except Exception as error:
        receipt.update(status=classify(error), error=str(error)[:4096], cleanup='inspect_case_receipt')
        raise
    print(json.dumps({'status': 'passed', 'receipt': str(receipt.path), 'graceful_close': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
