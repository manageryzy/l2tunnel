"""Bounded public observations for the actual Common original-carrier CLI lab."""
from __future__ import annotations

import hashlib
import re
import socket
import struct
from pathlib import Path

try:
    from . import generic_cli_native as g
except ImportError:
    import generic_cli_native as g

require, uint, public_bytes = g.require, g.uint, g.public_bytes
CONFIG_DOMAIN = b'l2tunnel/record-transaction-config/v5\0'
FAMILIES = {1: 'swift', 2: 'aligned', 3: 'packed', 4: 'rolling'}


def canonical(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{2608}', value) is not None,
            'exact complete canonical Common configuration required')
    raw = bytes.fromhex(value)
    require(raw[:5] == b'L2RC\x02' and raw[5] in FAMILIES and raw[6:8] == b'\x02\0',
            'unexpected complete Common header/profile/duplex')
    require(576 <= int.from_bytes(raw[8:16], 'big') <= 9000, 'invalid canonical path MTU')
    return value


def family(value):
    return FAMILIES[bytes.fromhex(canonical(value))[5]]


def digest(value):
    return list(hashlib.sha256(CONFIG_DOMAIN + bytes.fromhex(canonical(value))).digest())


def inspection(raw, case, side):
    values = [g.bounded.strict_json(line) for line in raw.splitlines() if line.startswith('{')]
    require(2 <= len(values) <= 17, 'bounded header plus complete requested catalog pages required')
    header, pages = values[0], values[1:]
    expected = {'event': 'secure_udp_common_requested_carrier_plan', 'schema': 1, 'api_version': 4,
        'backend': 'common_records_v2', 'carrier': 'openvpn-like', 'udp_cover': case['cover'],
        'role': 'initiator' if side == 'a' else 'responder', 'requested': True, 'validated': True,
        'authenticated': False, 'configuration_scope': 'requested_base_E0',
        'authenticated_outer_binding_required': True, 'outer_tls_trust_validated': False,
        'effective_configuration': None, 'effective_envelope': None, 'effective_catalog': None}
    for name, wanted in expected.items():
        require(type(header.get(name)) is type(wanted) and header[name] == wanted,
                'requested inspection differs: ' + name)
    for name in ('requested_configuration', 'requested_envelope', 'catalog'):
        public_bytes(header.get(name), 32, name)
    total = uint(header.get('catalog_members'), 'requested catalog count', 64)
    require(total == len(case['transaction_plan']['catalog']) and total > 0,
            'requested inspection pruned supplied catalog')
    configurations = []
    for index, page in enumerate(pages):
        require(page.get('event') == 'secure_udp_common_plan_catalog' and page.get('schema') == 1
            and page.get('catalog') == header['catalog'] and page.get('offset') == index * 4
            and page.get('total') == total and page.get('configuration_scope') == 'requested_base_E0'
            and page.get('authenticated_outer_binding_required') is True,
            'requested catalog page identity differs')
        chunk = page.get('configurations')
        require(isinstance(chunk, list) and len(chunk) == min(4, total - index * 4),
                'requested catalog page extent differs')
        configurations.extend(canonical(value) for value in chunk)
    require(len(configurations) == total and len(set(configurations)) == total
        and canonical(header.get('requested_initial')) in configurations,
        'requested catalog incomplete or duplicated')
    descriptors = [(bytes.fromhex(item)[:16] + bytes.fromhex(item)[48:]).hex() for item in configurations]
    require(set(descriptors) == set(case['transaction_plan']['catalog'])
        and (bytes.fromhex(header['requested_initial'])[:16]
             + bytes.fromhex(header['requested_initial'])[48:]).hex()
        == case['transaction_plan']['catalog'][case['transaction_plan']['initial_index']],
        'requested canonical inspection changed supplied descriptor bytes')
    require(set(map(family, configurations)) == set(FAMILIES.values()),
            'supplied fixture must retain all four families')
    header['configurations'] = configurations
    return header


def status(response, case, side, public, inspected, expected=None, epoch=None, running=True, *,
           stopped=None, reply_outcome=(True, 'ok')):
    require(stopped is None or not running, 'terminal expectation on live status')
    terminal, service_terminal, state_phase = ((None, None, 'forwarding') if running else
        ((None, 'Aborted', 'disconnected') if stopped is None else stopped))
    require(isinstance(response, dict) and set(response) == {'version', 'ok', 'code', 'state'}
        and type(response['version']) is int and response['version'] == 4
        and type(response['ok']) is bool and response['ok'] == reply_outcome[0]
        and response['code'] == reply_outcome[1], 'exact explicit APIv4 reply outcome required')
    state = response['state']
    require(isinstance(state, dict) and set(state) == {'epoch', 'phase', 'compression', 'common'}
        and state['compression'] == 'off'
        and state['phase'] == state_phase,
        'Common state phase/backend differs')
    value = state['common']
    require(isinstance(value, dict), 'actual Common status absent')
    for key, wanted in {'carrier': 'openvpn-like', 'backend': 'common_records_v2',
        'algorithm': 'common-records', 'protection': 'chacha20-poly1305', 'running': running,
        'coordinator': side == 'a', 'configuration_change': True, 'cross_profile_switching': True,
        'reconnect': True, 'retained_state_recovery': False, 'fresh_rekey': False,
        'resource_preallocation_complete': False, 'member': public['member_public'],
        'initiator_noise': public['noise_public']['a'], 'responder_noise': public['noise_public']['b'],
        'local': g.WAN[side] + ':24440', 'peer': g.WAN['b' if side == 'a' else 'a'] + ':24440',
        'catalog_members': len(inspected['configurations']), 'terminal': terminal,
        'service_terminal': service_terminal}.items():
        require(type(value.get(key)) is type(wanted) and value[key] == wanted, 'actual status differs: ' + key)
    require(uint(value.get('generation'), 'generation') > 0, 'missing actual generation')
    for key in ('transcript', 'outer', 'configuration', 'catalog'):
        public_bytes(value.get(key), 32, key)
    public_bytes(value.get('session'), 16, 'session')
    current = canonical(value.get('current'))
    canonical(value.get('initial'))
    actual_epoch = uint(value.get('epoch'), 'epoch')
    require(actual_epoch > 0 and state['epoch'] == actual_epoch, 'service/Bank epoch differs')
    if expected is not None:
        require(current == canonical(expected), 'actual current differs from requested complete target')
    if epoch is not None:
        require(actual_epoch == epoch, 'actual Bank epoch differs')
    require(value.get('phase') == 'idle' and value.get('operation') is None,
            'actual operation has not settled')
    require(value.get('physical_scope') == {'epoch': actual_epoch, 'configuration': digest(current)},
            'actual physical epoch/D(C) differs')
    outer = value.get('original_carrier')
    require(isinstance(outer, dict), 'genuine actual outer observation absent')
    wanted = {'requested': 'openvpn-like', 'effective': 'openvpn-like', 'udp_cover': case['cover'],
        'requested_configuration': inspected['requested_configuration'],
        'requested_envelope': inspected['requested_envelope'], 'requested_catalog': inspected['catalog'],
        'effective_configuration': value['configuration'], 'effective_catalog': value['catalog'],
        'effective_envelope': list(bytes.fromhex(current)[16:48]),
        'path_mtu': inspected['outer_policy']['path_mtu'],
        'max_record_bytes': inspected['outer_policy']['max_record_bytes'],
        'configuration': inspected['outer_policy']['digest']}
    for name, expected_value in wanted.items():
        require(outer.get(name) == expected_value, 'actual requested/effective carrier differs: ' + name)
    public_bytes(outer.get('session'), 16, 'outer session')
    public_bytes(outer.get('binding'), 32, 'outer binding')
    require(outer['effective_envelope'] != outer['requested_envelope']
        and outer['effective_configuration'] != outer['requested_configuration'], 'actual E0/E1 proof binding absent')
    require(value.get('rolling_work') == case['transaction_plan'].get('rolling_work'), 'actual rolling work differs')
    for key in ('native_storage_capacity_bytes', 'workspace_capacity_bytes', 'loop_input_capacity_bytes'):
        require(uint(value.get(key), key) > 0, 'actual resource observation missing')
    for key in ('wire', 'native', 'control', 'security', 'liveness', 'storage'):
        require(isinstance(value.get(key), dict), 'actual summary absent: ' + key)
    storage = value['storage']
    for name in g.SUMMARIES['storage']:
        uint(storage.get(name), 'storage/' + name)
    require(sum(storage[name] for name in ('fixed_bytes', 'external_bytes', 'engine_bytes', 'building_bytes'))
        <= storage['peak_bytes'] <= storage['limit_bytes']
        == case['transaction_plan']['transaction']['retained_bytes'], 'actual storage accounting differs')
    return value


def catalog_page(response, generation, root, offset, total):
    require(response.get('version') == 4 and response.get('ok') is True and response.get('code') == 'ok',
            'actual APIv4 catalog reply failed')
    value = (response.get('state') or {}).get('common') or {}
    require(value.get('generation') == generation and value.get('catalog') == root
        and value.get('catalog_members') == total, 'catalog generation/root changed')
    page = value.get('catalog_page')
    count = min(4, total - offset)
    require(isinstance(page, dict) and set(page) == {'offset', 'total', 'next', 'configurations'}
        and page['offset'] == offset and page['total'] == total
        and page['next'] == (offset + count if offset + count < total else None)
        and isinstance(page['configurations'], list) and len(page['configurations']) == count,
        'actual full catalog page missing or pruned')
    return [canonical(value) for value in page['configurations']]


def outer_packet(body):
    """Finite no-tls-auth OpenVPN grammar, never authentication authority."""
    require(0 < len(body) <= 65507 and body[0] & 7 == 0, 'unexpected outer key/extent')
    opcode = body[0] >> 3
    if opcode == 6:
        require(len(body) > 1, 'empty opaque P_DATA_V1')
        return 'data', body[1:]
    require(opcode in (4, 5, 7, 8) and len(body) >= 10 and any(body[1:9]),
            'unexpected outer control opcode/session')
    count = body[9]
    at = 10 + 4 * count + (8 if count else 0) + (0 if opcode == 5 else 4)
    require(at <= len(body), 'truncated control ACK/session/packet ID')
    if opcode == 4:
        require(len(body) > at, 'empty TLS control fragment')
    else:
        require(len(body) == at and (opcode != 5 or count > 0), 'invalid ACK/reset layout')
    return {4: 'tls', 5: 'ack', 7: 'reset_client', 8: 'reset_server'}[opcode], body[at:]


def audit_wan(path: Path, case, epoch_mtus):
    result = {'packets': 0, 'arp': 0, 'icmp': 0, 'udp': 0, 'data': 0, 'tls': 0,
        'ack': 0, 'reset_client': 0, 'reset_server': 0, 'handshake': 0, 'established': 0,
        'user_epochs': {}, 'scope': 'bounded outer grammar/public inner shape; no captured tag verification'}
    for count, link, ether, raw in g.pcap_frames(path):
        result['packets'] = count
        if ether == 0x806:
            require(link != 101 and len(raw) >= 28, 'invalid WAN ARP')
            result['arp'] += 1
            continue
        require(ether == 0x800, 'unexpected WAN IPv6/link protocol')
        ip, total = g.ipv4(raw, link)
        source, destination = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        body = ip[20:]
        if ip[9] == 1:
            require(source in (*g.WAN.values(), '192.0.2.1', '192.0.2.5') and destination in g.WAN.values()
                and len(body) >= 36 and body[:2] == b'\x03\x03' and g.bounded.checksum(body) == 0,
                'unexpected original-carrier WAN ICMP')
            quote = body[8:]
            require(quote[0] == 0x45 and quote[9] == 17 and g.bounded.checksum(quote[:20]) == 0
                and not int.from_bytes(quote[6:8], 'big') & 0x3fff
                and socket.inet_ntoa(quote[12:16]) == destination
                and {socket.inet_ntoa(quote[12:16]), socket.inet_ntoa(quote[16:20])} == set(g.WAN.values())
                and quote[20:24] == struct.pack('!HH', 24440, 24440), 'invalid original tuple ICMP quote')
            result['icmp'] += 1
            continue
        require({source, destination} == set(g.WAN.values()) and ip[9] == 17 and len(body) >= 8,
                'unexpected WAN endpoint/TCP/bootstrap side flow')
        sport, dport, size, checksum = struct.unpack('!HHHH', body[:8])
        require(sport == dport == 24440 and size == len(body), 'original carrier tuple/extent differs')
        require(checksum == 0 or g.bounded.checksum(ip[12:20] + b'\0\x11' + size.to_bytes(2, 'big') + body) == 0,
                'outer UDP checksum differs')
        kind, payload = outer_packet(body[8:])
        result[kind] += 1
        result['udp'] += 1
        if kind == 'data':
            phase, protected, length = g.native.covered_payload(payload, len(payload), case['cover'])
            g.native.protected_shape(protected, length, phase, 'a' if source == g.WAN['a'] else 'b')
            result[phase] += 1
            if phase == 'established' and protected[0] == 1:
                epoch = int.from_bytes(protected[1:9], 'big')
                require(epoch in epoch_mtus and total <= epoch_mtus[epoch], 'actual User epoch/IP MTU differs')
                result['user_epochs'][str(epoch)] = result['user_epochs'].get(str(epoch), 0) + 1
    require(all(result[name] > 0 for name in ('tls', 'ack', 'reset_client', 'reset_server', 'handshake', 'established')),
            'actual outer/inner handshake or established samples absent')
    require(set(map(int, result['user_epochs'])) == set(epoch_mtus), 'actual active epoch capture matrix incomplete')
    return result
