#!/usr/bin/env python3
"""Finite measured TUN proxy acceptance; dry run unless --apply is explicit."""
from __future__ import annotations
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

try:
    from . import proxy_native_smoke as fixed
except ImportError:
    import proxy_native_smoke as fixed

# Reuse the existing identity-checked journal, finite command/capture/process
# helpers and exact split/bypass audit. Historical fixed defaults are untouched.
netns_lab = fixed.netns_lab
ROOT = Path(__file__).resolve().parents[1]
BOUNDS = dict(fixed.BOUNDS)
BOUNDS['pressure_pause'] = 2
PRESSURE_BYTES = 786433
POLL_SECONDS = 0.02
MAX_SAMPLES = 512
CLOCK_DRIFT_NS = 5_000_000
CLOCK_BRACKET_NS = 1_000_000
for _name in ('Unsupported', 'strict_json', 'remaining', 'command', 'bounded_lab',
              'file_hash', 'verified_build_receipt', 'Receipt', 'rpc', 'payload',
              'integers', 'launch', 'wait_log', 'read_log', 'start_capture',
              'finish_capture', 'offloads', 'disable_underlay_ipv6', 'stop',
              'audit_native_captures', 'PACKET_LIMIT', 'REPLY_LIMIT'):
    globals()[_name] = getattr(fixed, _name)


def policy() -> dict:
    """Complete required measured schema, with no hidden measured defaults."""
    return {
        'version': 1, 'profile': 'measured-relay-v1', 'fixed': fixed.policy(),
        'allocation': {'target': {
            'initial': {'bytes': 32768, 'records': 32},
            'minimum': {'bytes': 2048, 'records': 1},
            'session_cap': {'bytes': 1048576, 'records': 1024},
            'per_flow_cap': {'bytes': 65536, 'records': 64},
            'policy_cap': {'bytes': 1048576, 'records': 1024},
            'queue_allowance_bytes': 65536, 'queue_delay_target_micros': 5000,
            'many_flow_step': {'bytes': 2048, 'records': 1},
            'few_flow_threshold': 4, 'max_flows': 16,
            'bootstrap_rtt_micros': 1000, 'recovery_rtts': 2,
        }, 'minimum_per_flow': {'bytes': 2048, 'records': 1}},
        'ownership': {'pending_ttl_micros': 20000, 'probe_interval_micros': 10000,
            'probe_timeout_micros': 30000, 'handoff_timeout_micros': 50000,
            'emission_interval_micros': 10000, 'max_records_per_interval': 8},
        'observation': {'report_interval_micros': 10000, 'sample_ttl_micros': 40000,
            'demand_idle_micros': 20000, 'rate_interval_micros': 10000, 'rate_bins': 4},
        'service': {'report_work_per_turn': 4, 'admission_work_per_turn': 4,
            'callback_work_per_turn': 4, 'plan_interval_micros': 10000,
            'status_interval_micros': 10000},
    }


def case_plan(lab_id: str, duplex: str, profile: str = 'clean') -> dict:
    if profile not in ('clean', 'pressure'):
        raise ValueError('explicit clean or pressure acceptance profile required')
    plan = fixed.case_plan(lab_id, duplex)
    plan['case'] = f'tun-{duplex}-{profile}'
    plan['qualification'] = profile
    plan['policy'] = policy()
    plan['profile'][1] = 'proxy-measured'
    plan['bounds_seconds'] = dict(BOUNDS)
    plan['pressure_probe'] = {'bytes_each_direction': PRESSURE_BYTES,
                              'read_pause_seconds': BOUNDS['pressure_pause'],
                              'application_receive_buffer': 8192,
                              'application_send_buffer': 8192,
                              'concurrent_flows': 2, 'dscp_weights': [1, 1]}
    plan['acceptance'] = ('exact IPv4/IPv6 split and transparent traffic, FIN/EOF, measured ACK/service feedback, '
                          'original TLS drain and owned cleanup')
    if profile == 'pressure':
        plan['acceptance'] += ('; actual zero-window then reopening and ACK progress on both maintained '
                               'native legs per family; few-flow target growth; two equal-policy concurrent flows')
    plan['not_qualified'] = ['native cwnd/RTT', 'weighted fairness', 'throughput superiority',
                             'many-flow or impaired operation', 'other carriers or platforms']
    return plan


CAPABILITY_FIELDS = {'requested', 'effective', 'lanes', 'requested_carrier', 'effective_carrier',
    'requested_udp_cover', 'effective_udp_cover', 'measured_relay_targets', 'exact_tcp_rwnd_control',
    'native_tcp_rtt', 'native_tcp_cwnd', 'native_window_qualified', 'hot_reload', 'flow_paging'}
AGGREGATE_FIELDS = {'at_micros', 'authoritative_at_micros', 'revision', 'active_flows',
    'demanding_flows', 'unknown_flows', 'grant_exhausted', 'in_flight_bytes', 'in_flight_records',
    'ack_rate', 'service_latency', 'applied', 'pending', 'admitted', 'queued', 'awaiting_callback',
    'admitted_by_kind', 'admitted_framed_bytes', 'queue_delay_micros', 'receiver_pressure',
    'carrier_pressure', 'quiescing', 'failed'}
AGGREGATE_BOOLS = {'grant_exhausted', 'receiver_pressure', 'carrier_pressure', 'quiescing', 'failed'}


def validate_proxy_snapshot(response: dict, digest: str | None = None, phase: str | None = None,
                            allow_starting: bool = False) -> dict:
    """Validate the exact measured DTO, then reuse the unchanged fixed base validator."""
    if len(json.dumps(response, separators=(',', ':')).encode()) > REPLY_LIMIT:
        raise ValueError('measured reply exceeds unchanged local cap')
    if not isinstance(response, dict) or not isinstance(response.get('state'), dict):
        raise ValueError('measured response envelope/state required')
    value = copy.deepcopy(response)
    proxy = value['state'].get('proxy')
    if not isinstance(proxy, dict): raise ValueError('measured proxy object required')
    measured = proxy.pop('measured', None)
    observed = fixed.validate_proxy_snapshot(value, digest, phase, allow_starting)
    if not isinstance(measured, dict) or set(measured) != {'capabilities', 'aggregate'}:
        raise ValueError('explicit measured capabilities and aggregate required')
    caps, aggregate = measured['capabilities'], measured['aggregate']
    if not isinstance(caps, dict) or set(caps) != CAPABILITY_FIELDS:
        raise ValueError('invalid measured capability fields')
    effective = observed['runtime'] is not None
    expected = {'requested': 'measured-relay-v1', 'effective': 'measured-relay-v1' if effective else None,
        'lanes': caps.get('lanes'), 'requested_carrier': 'tcp_tls',
        'effective_carrier': 'tcp_tls' if effective else None,
        'requested_udp_cover': 'not_applicable', 'effective_udp_cover': 'not_applicable' if effective else None,
        'measured_relay_targets': True, 'exact_tcp_rwnd_control': False, 'native_tcp_rtt': False,
        'native_tcp_cwnd': False, 'native_window_qualified': False, 'hot_reload': False, 'flow_paging': False}
    if (caps != expected or caps['lanes'] not in ('full', 'half')
            or any(type(caps[k]) is not bool for k in expected if type(expected[k]) is bool)):
        raise ValueError('unexpected effective measured profile or unsupported capability claim')
    if aggregate is None:
        if effective: raise ValueError('actual runtime is missing its actual measured aggregate')
    else:
        if not effective or not isinstance(aggregate, dict) or set(aggregate) != AGGREGATE_FIELDS:
            raise ValueError('invalid measured aggregate')
        integers(aggregate, AGGREGATE_FIELDS - AGGREGATE_BOOLS - {'ack_rate', 'service_latency', 'applied', 'admitted_by_kind'})
        if any(type(aggregate[k]) is not bool for k in AGGREGATE_BOOLS):
            raise ValueError('invalid measured aggregate boolean')
        if (not isinstance(aggregate['admitted_by_kind'], list) or len(aggregate['admitted_by_kind']) != 3
                or any(type(n) is not int or not 0 <= n < 2**64 for n in aggregate['admitted_by_kind'])):
            raise ValueError('invalid measurement kind counters')
        rate = aggregate['ack_rate']
        if rate is not None:
            fields = {'bytes', 'elapsed_micros', 'bytes_per_second', 'bins', 'latest_at_micros'}
            if not isinstance(rate, dict) or set(rate) != fields:
                raise ValueError('invalid ACK-rate fields')
            integers(rate, fields - {'bytes'})
            if type(rate['bytes']) is not int or not 0 <= rate['bytes'] < 2**128 or rate['bins'] > 255:
                raise ValueError('invalid original-byte ACK rate')
        latency = aggregate['service_latency']
        if latency is not None:
            fields = {'smoothed_micros', 'admitted_at_micros', 'reply_at_micros', 'fresh'}
            if not isinstance(latency, dict) or set(latency) != fields or type(latency['fresh']) is not bool:
                raise ValueError('invalid service latency')
            integers(latency, fields - {'fresh'})
        applied = aggregate['applied']
        if applied is not None:
            fields = {'revision', 'phase', 'candidate_bytes', 'candidate_records', 'reserved_bytes', 'reserved_records'}
            if not isinstance(applied, dict) or set(applied) != fields or applied['phase'] not in (
                    'idle', 'bootstrap', 'probing', 'steady', 'backpressure', 'recovering'):
                raise ValueError('invalid applied relay targets')
            integers(applied, fields - {'phase'})
    observed['measured'] = measured
    return observed


def verify_peer_closures(peers: dict, lanes: int, expected_owners: int = 2) -> dict:
    base = copy.deepcopy(peers)
    for side, value in peers.items():
        measured = validate_proxy_snapshot(value)['measured']
        if measured['capabilities']['lanes'] != ('full' if lanes == 1 else 'half'):
            raise ValueError('measured lane policy mismatch')
        base[side]['state']['proxy'].pop('measured')
    return fixed.verify_peer_closures(base, lanes, expected_owners)


def source_hashes(root: Path = ROOT) -> dict[str, str]:
    result = fixed.source_hashes(root)
    for name in ('tools/proxy_measured_native_smoke.py', 'tools/test_proxy_measured_native_smoke.py'):
        result[name] = file_hash(root / name)
    return result


def verify_copied_helpers(build: dict, output: Path, loaded: bool = False) -> dict[str, str]:
    """Require copied helpers from the exact binary build, before namespace setup."""
    names = {'tools/proxy_measured_native_smoke.py': Path(__file__),
             'tools/proxy_native_smoke.py': Path(fixed.__file__),
             'tools/netns_lab.py': Path(netns_lab.__file__)}
    result = {}
    for name, module_path in names.items():
        copied = output / Path(name).name
        expected = build.get('source_sha256_after', {}).get(name)
        if (copied.is_symlink() or not copied.is_file() or not isinstance(expected, str)
                or file_hash(copied) != expected
                or loaded and module_path.resolve() != copied.resolve()):
            raise ValueError('executed copied helper differs from exact build source: ' + name)
        result[name] = expected
    return result


def clock_anchor() -> dict:
    """Bracket the realtime clock read in the same host monotonic clock domain."""
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return {'before_mono_ns': before, 'realtime_ns': realtime, 'after_mono_ns': after}


def release_clock(probe: dict) -> dict:
    """Bound capture-realtime mapping; unstable clocks cannot qualify causality."""
    value = probe.get('clock')
    if not isinstance(value, dict) or set(value) != {'start', 'release', 'end', 'began_mono_ns', 'read_begin_mono_ns'}:
        raise ValueError('bounded probe capture-clock anchors required')
    offsets = []
    for name in ('start', 'release', 'end'):
        anchor = value[name]
        if not isinstance(anchor, dict) or set(anchor) != {'before_mono_ns', 'realtime_ns', 'after_mono_ns'}:
            raise ValueError('invalid clock anchor')
        integers(anchor, set(anchor))
        if not 0 <= anchor['after_mono_ns'] - anchor['before_mono_ns'] <= CLOCK_BRACKET_NS:
            raise ValueError('probe clock anchor uncertainty exceeds bound')
        offsets.append((anchor['realtime_ns'] - anchor['after_mono_ns'],
                        anchor['realtime_ns'] - anchor['before_mono_ns']))
    low, high = min(a for a, _ in offsets), max(b for _, b in offsets)
    if high - low > CLOCK_DRIFT_NS:
        raise ValueError('realtime/monotonic clock drift exceeds causal-proof bound')
    integers(value, {'began_mono_ns', 'read_begin_mono_ns'})
    if (not value['start']['after_mono_ns'] <= value['began_mono_ns']
            <= value['release']['before_mono_ns'] <= value['release']['after_mono_ns']
            <= value['read_begin_mono_ns'] <= value['end']['before_mono_ns']
            or value['read_begin_mono_ns'] - value['began_mono_ns'] < BOUNDS['pressure_pause'] * 1_000_000_000):
        raise ValueError('original reader pause or clock ordering invalid')
    return {'pause_begin_realtime_latest_ns': value['began_mono_ns'] + high,
            'release_realtime_earliest_ns': value['read_begin_mono_ns'] + low,
            'release_realtime_latest_ns': value['read_begin_mono_ns'] + high,
            'mapping_uncertainty_ns': high - low, 'clock_drift_bound_ns': CLOCK_DRIFT_NS}


def pressure_probe_main(argv: list[str]) -> int:
    """Finite ordinary kernel endpoint with deliberately bounded application pressure."""
    parser = argparse.ArgumentParser(description='Internal measured native pressure probe')
    parser.add_argument('role', choices=['listen', 'connect'])
    parser.add_argument('source', type=ipaddress.ip_address)
    parser.add_argument('destination', type=ipaddress.ip_address)
    parser.add_argument('source_port', type=int)
    parser.add_argument('destination_port', type=int)
    args = parser.parse_args(argv)
    if args.source.version != args.destination.version or not all(0 < p <= 65535 for p in (args.source_port, args.destination_port)):
        raise ValueError('invalid pressure probe tuple')
    end = time.monotonic() + BOUNDS['transfer']
    family = socket.AF_INET if args.source.version == 4 else socket.AF_INET6
    source, destination = (str(args.source), args.source_port), (str(args.destination), args.destination_port)
    listener = None
    stream = socket.socket(family, socket.SOCK_STREAM)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
    stream.settimeout(remaining(end, BOUNDS['transfer']))
    if args.role == 'listen':
        listener = stream
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(destination)
        listener.listen(1)
        print('Listening', flush=True)
        stream, _ = listener.accept()
    else:
        stream.bind(source)
        stream.connect(destination)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
    stream.settimeout(remaining(end, BOUNDS['probe_inactivity']))
    outgoing = payload(PRESSURE_BYTES, 29 if args.role == 'listen' else 11)
    expected = payload(PRESSURE_BYTES, 11 if args.role == 'listen' else 29)
    start_clock = clock_anchor()
    began_ns = time.monotonic_ns()
    began, timing, errors = began_ns / 1_000_000_000, {}, []
    def send():
        try:
            timing['send_begin'] = time.monotonic()
            for offset in range(0, len(outgoing), 4096):
                remaining(end, BOUNDS['probe_inactivity'])
                stream.sendall(outgoing[offset:offset + 4096])
            stream.shutdown(socket.SHUT_WR)
            timing['send_complete'] = time.monotonic()
        except Exception as error:
            errors.append(str(error))
    worker = threading.Thread(target=send, daemon=True)
    worker.start()
    received = bytearray()
    try:
        time.sleep(min(BOUNDS['pressure_pause'], remaining(end, BOUNDS['pressure_pause'])))
        release_anchor = clock_anchor()
        read_begin_ns = time.monotonic_ns()
        timing['read_begin'] = read_begin_ns / 1_000_000_000
        while True:
            stream.settimeout(remaining(end, BOUNDS['probe_inactivity']))
            chunk = stream.recv(min(4096, len(expected) + 1 - len(received)))
            if not chunk: break
            received.extend(chunk)
            if len(received) > len(expected): raise ValueError('pressure probe received excess bytes')
            # Keep actual demand observable after release without altering kernel TCP policy.
            time.sleep(min(0.002, remaining(end, 0.002)))
        worker.join(remaining(end, BOUNDS['probe_inactivity']))
        if worker.is_alive() or errors or received != expected:
            raise RuntimeError(f'pressure send/read/EOF failed: {errors!r}')
        print(json.dumps({'role': args.role, 'source': list(source), 'destination': list(destination),
            'sent_bytes': len(outgoing), 'received_bytes': len(received),
            'sent_sha256': hashlib.sha256(outgoing).hexdigest(),
            'received_sha256': hashlib.sha256(received).hexdigest(), 'eof': True,
            'timing': {'began': began, **timing, 'ended': time.monotonic()},
            'clock': {'start': start_clock, 'release': release_anchor, 'end': clock_anchor(),
                      'began_mono_ns': began_ns, 'read_begin_mono_ns': read_begin_ns},
            'effective_receive_buffer': stream.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
            'effective_send_buffer': stream.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)}), flush=True)
    finally:
        stream.close()
        worker.join(1)
        if listener is not None: listener.close()
    return 0


def verify_probe(result: dict, flow: dict, role: str, pressure: bool = False) -> None:
    if not pressure:
        fixed.verify_probe(result, flow, role)
        return
    fields = {'role', 'source', 'destination', 'sent_bytes', 'received_bytes', 'sent_sha256',
              'received_sha256', 'eof', 'timing', 'clock', 'effective_receive_buffer', 'effective_send_buffer'}
    if (not isinstance(result, dict) or set(result) != fields or result['role'] != role
            or result['source'] != [flow['source'], flow['source_port']]
            or result['destination'] != [flow['destination'], flow['destination_port']]
            or result['eof'] is not True):
        raise ValueError('pressure probe identity or EOF mismatch')
    integers(result, {'sent_bytes', 'received_bytes', 'effective_receive_buffer', 'effective_send_buffer'})
    sent = payload(PRESSURE_BYTES, 11 if role == 'connect' else 29)
    received = payload(PRESSURE_BYTES, 29 if role == 'connect' else 11)
    if (result['sent_bytes'] != PRESSURE_BYTES or result['received_bytes'] != PRESSURE_BYTES
            or result['sent_sha256'] != hashlib.sha256(sent).hexdigest()
            or result['received_sha256'] != hashlib.sha256(received).hexdigest()):
        raise ValueError('pressure payload length/hash mismatch')
    timing = result['timing']
    if (not isinstance(timing, dict) or set(timing) != {'began', 'send_begin', 'send_complete', 'read_begin', 'ended'}
            or any(type(t) not in (int, float) or not 0 < t < 1e15 for t in timing.values())
            or not timing['began'] <= timing['send_begin'] <= timing['send_complete'] <= timing['ended']
            or not timing['began'] + BOUNDS['pressure_pause'] <= timing['read_begin'] <= timing['ended']
            or timing['send_complete'] < timing['read_begin']
            or timing['ended'] - timing['began'] > BOUNDS['transfer']):
        raise ValueError('pressure pause, blocked send or original deadline not established')
    release_clock(result)


def verify_concurrent_probes(transfers: list[dict], flows: list[dict]) -> dict:
    intervals = []
    for flow in [f for f in flows if f['split']]:
        roles = []
        for role in ('connect', 'listen'):
            candidates = [r for r in transfers if r.get('role') == role
                and r.get('source') == [flow['source'], flow['source_port']]
                and r.get('destination') == [flow['destination'], flow['destination_port']]]
            if len(candidates) != 1: raise ValueError('one exact result per pressure flow/role required')
            result = candidates[0]
            verify_probe(result, flow, role, True)
            roles.append(result['timing'])
        intervals.append((max(t['send_begin'] for t in roles), min(t['send_complete'] for t in roles)))
    overlap = min(b for _, b in intervals) - max(a for a, _ in intervals)
    if len(intervals) < 2 or overlap <= 0:
        raise ValueError('two concurrent equal-policy demanding native flows not established')
    return {'concurrent_flows': len(intervals), 'overlap_seconds': overlap,
            'bytes_each_direction_each_flow': PRESSURE_BYTES, 'weights': [1] * len(intervals),
            'scope': 'finite equal-policy concurrent progress and exact completion; no fairness ratio'}


def measurement_evidence(samples: list[dict], pressure: bool = False,
                         transfers: list[dict] | None = None) -> dict:
    result = {}
    initial = policy()['allocation']['target']['initial']['bytes']
    interval = None
    if pressure:
        probes = [r for r in transfers or [] if 'clock' in r]
        if len(probes) != 4: raise ValueError('two pressure flows and both readers required')
        for probe in probes: release_clock(probe)
        interval = (max(r['clock']['began_mono_ns'] for r in probes),
                    min(r['clock']['read_begin_mono_ns'] for r in probes))
        if interval[1] <= interval[0]: raise ValueError('pressure reader pauses do not overlap')
    for side in ('a', 'b'):
        rows = [validate_proxy_snapshot(sample['peers'][side])['measured']['aggregate']
                for sample in samples if side in sample['peers']]
        rows = [row for row in rows if row is not None]
        qualified = [r for r in rows if r['ack_rate'] is not None and r['ack_rate']['bytes'] > 0
                     and r['ack_rate']['bins'] > 0 and r['service_latency'] is not None
                     and r['service_latency']['fresh'] and r['service_latency']['smoothed_micros'] > 0]
        if not qualified or not all(max(r['admitted_by_kind'][i] for r in rows) > 0 for i in range(3)):
            raise ValueError('actual ACK bins, authenticated echo and all common-path measurement kinds required')
        growth = [r for r in qualified if r['demanding_flows'] > 0 and r['applied'] is not None
                  and r['applied']['candidate_bytes'] > initial]
        paused = [validate_proxy_snapshot(s['peers'][side])['measured']['aggregate'] for s in samples
                  if pressure and side in s['peers']
                  and interval[0] < s.get('poll_begin_monotonic_ns', 0)
                  <= s.get('poll_end_monotonic_ns', 0) < interval[1]]
        paused = [r for r in paused if r is not None]
        context = paused if pressure else rows
        two = [r for r in context if r['demanding_flows'] >= 2]
        # A later authoritative observation than the first in-pause sample
        # excludes a frozen status value carried over from startup.
        observed_pressure = [r for r in context if (r['receiver_pressure'] or r['carrier_pressure'])
                             and (not pressure or r['authoritative_at_micros'] > paused[0]['authoritative_at_micros'])]
        if pressure and (not growth or not two or not observed_pressure):
            raise ValueError('few-flow growth, two-flow demand or actual local pressure not observed')
        result[side] = {'qualified_samples': len(qualified), 'growth_samples': len(growth),
            'two_demand_samples': len(two), 'pressure_samples': len(observed_pressure),
            'maximum_candidate_bytes': max((r['applied']['candidate_bytes'] for r in rows if r['applied']), default=0),
            'maximum_original_ack_bytes': max(r['ack_rate']['bytes'] for r in qualified),
            'maximum_admitted_by_kind': [max(r['admitted_by_kind'][i] for r in rows) for i in range(3)],
            'pressure_context': {'overlapping_reader_pause_monotonic_ns': interval,
                                 'actual_in_pause_samples': len(paused)},
            'native_tcp_rtt_cwnd': 'unavailable; echo measures tunnel service latency'}
    return result


def tcp_window(packet) -> dict:
    """Decode advertised receive window and the exact SYN scaling offer, never cwnd."""
    raw = packet.raw
    offset = (raw[0] & 15) * 4 if raw[0] >> 4 == 4 else 40
    if packet.protocol != 6 or len(raw) < offset + 20:
        raise ValueError('TCP window needs a validated complete TCP packet')
    tcp = raw[offset:]
    header = (tcp[12] >> 4) * 4
    if not 20 <= header <= len(tcp): raise ValueError('TCP option header length')
    cursor, scale, options = 20, None, []
    while cursor < header:
        kind = tcp[cursor]
        if kind == 0: break
        if kind == 1:
            cursor += 1
            continue
        if cursor + 2 > header or not 2 <= tcp[cursor + 1] <= header - cursor:
            raise ValueError('malformed TCP option length')
        size = tcp[cursor + 1]
        options.append({'kind': kind, 'hex': tcp[cursor:cursor + size].hex()})
        if kind == 3:
            if size != 3 or scale is not None or tcp[cursor + 2] > 14:
                raise ValueError('invalid or duplicate TCP window-scale option')
            scale = tcp[cursor + 2]
        cursor += size
    return {'raw_window': int.from_bytes(tcp[14:16], 'big'),
            'ack': int.from_bytes(tcp[8:12], 'big'), 'scale_offer': scale, 'options': options}


def timed_capture(path: Path) -> tuple[list, list[int], int]:
    """Retain classic-PCAP realtime timestamps after the unchanged full audit parser."""
    packets = fixed.read_pcap(path)
    raw = path.read_bytes()
    magic = raw[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    tick = 1 if magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1000
    linktype = struct.unpack(endian + 'I', raw[20:24])[0]
    timestamps, cursor = [], 24
    while cursor < len(raw):
        seconds, fraction, length, _ = struct.unpack(endian + 'IIII', raw[cursor:cursor + 16])
        cursor += 16
        frame = raw[cursor:cursor + length]
        cursor += length
        if fraction >= 1_000_000_000 // tick:
            raise ValueError('capture timestamp fraction exceeds precision')
        ether = None
        if linktype == 1: ether = int.from_bytes(frame[12:14], 'big')
        elif linktype == 113: ether = int.from_bytes(frame[14:16], 'big')
        elif linktype == 276: ether = int.from_bytes(frame[:2], 'big')
        if ether != 0x806:
            timestamps.append(seconds * 1_000_000_000 + fraction * tick)
    if len(timestamps) != len(packets):
        raise ValueError('timestamp/validated IP record count mismatch')
    return packets, timestamps, tick


def window_sequence(packets: list, flow: dict, side: str, pressure: bool,
                    capture_times: list[int] | None = None, release: dict | None = None,
                    capture_tick_ns: int = 1000) -> dict:
    """Require actual zero/reopen/ACK progress in the maintained leg's direction."""
    first = (flow['source'], flow['source_port'])
    second = (flow['destination'], flow['destination_port'])
    own_source, own_destination = (second, first) if side == 'a' else (first, second)
    def selected(p, own=True):
        a, b = (own_source, own_destination) if own else (own_destination, own_source)
        return p.protocol == 6 and (p.source, p.source_port) == a and (p.destination, p.destination_port) == b
    owned = [(index, p, tcp_window(p)) for index, p in enumerate(packets) if selected(p)]
    syn = [v for _, p, v in owned if p.flags & 2]
    peer_syn = [tcp_window(p) for p in packets if selected(p, False) and p.flags & 2]
    if not syn or not peer_syn: raise ValueError('both native SYN option sets required')
    if len({v['scale_offer'] for v in syn}) != 1 or len({v['scale_offer'] for v in peer_syn}) != 1:
        raise ValueError('conflicting retransmitted native scale offers')
    scale = syn[0]['scale_offer'] if syn[0]['scale_offer'] is not None and peer_syn[0]['scale_offer'] is not None else 0
    first_fin = min((i for i, p in enumerate(packets) if (selected(p) or selected(p, False)) and p.flags & 1), default=len(packets))
    established = [(i, v['raw_window'] << scale, v['ack']) for i, p, v in owned
                   if i < first_fin and p.flags & 0x10 and not p.flags & 7]
    if pressure and (capture_times is None or len(capture_times) != len(packets) or release is None):
        raise ValueError('pressure capture timestamps and actual downstream release required')
    proof = None
    for at, (index, window, ack) in enumerate(established):
        if window != 0 or not any(w > 0 for _, w, _ in established[:at]): continue
        if pressure and not (release['pause_begin_realtime_latest_ns'] < capture_times[index] - capture_tick_ns
                and capture_times[index] + capture_tick_ns < release['release_realtime_earliest_ns']):
            continue
        reopened = [(i, w, a) for i, w, a in established[at + 1:] if w > 0]
        if pressure and (not reopened or capture_times[reopened[0][0]] - capture_tick_ns
                         <= release['release_realtime_latest_ns']):
            continue
        progress = [(i, w, a) for i, w, a in reopened if 0 < ((a - ack) & 0xffffffff) < 2**31]
        if pressure:
            progress = [(i, w, a) for i, w, a in progress
                        if capture_times[i] - capture_tick_ns > release['release_realtime_latest_ns']]
        if reopened and progress:
            proof = {'zero_packet': index, 'zero_ack': ack, 'reopen_packet': reopened[0][0],
                     'reopen_scaled_bytes': reopened[0][1], 'progress_packet': progress[0][0],
                     'progress_ack': progress[0][2]}
            if pressure:
                proof.update(zero_realtime_ns=capture_times[index],
                             reopen_realtime_ns=capture_times[reopened[0][0]],
                             progress_realtime_ns=capture_times[progress[0][0]],
                             capture_tick_ns=capture_tick_ns, downstream_release=release)
            break
    if pressure and proof is None:
        raise ValueError('captured native zero-window/reopen/new original-byte ACK progress missing')
    return {'side': side, 'family': flow['family'], 'source_port': flow['source_port'],
        'native_leg_advertiser': list(own_source), 'initial_syn_window_unscaled': syn[0]['raw_window'],
        'own_syn_options': syn[0]['options'], 'peer_syn_options': peer_syn[0]['options'],
        'negotiated_scale': scale, 'established_window_samples': len(established),
        'maximum_scaled_window_bytes': max((w for _, w, _ in established), default=0),
        'pressure_reopen_ack_proof': proof, 'domain': 'maintained native advertised receive window; not cwnd or relay target'}


def audit_windows(paths: dict[str, Path], flows: list[dict], pressure: bool,
                  transfers: list[dict] | None = None) -> list[dict]:
    result = []
    for side in ('a', 'b'):
        packets, timestamps, tick = timed_capture(paths[f'{side}_native'])
        for flow in flows:
            release = None
            if pressure:
                role = 'listen' if side == 'a' else 'connect'
                candidates = [r for r in transfers or [] if r.get('role') == role
                    and r.get('source') == [flow['source'], flow['source_port']]
                    and r.get('destination') == [flow['destination'], flow['destination_port']]]
                if len(candidates) != 1: raise ValueError('exact downstream pressure reader required')
                verify_probe(candidates[0], flow, role, True)
                release = {**release_clock(candidates[0]), 'reader_role': role}
            result.append(window_sequence(packets, flow, side, pressure, timestamps, release, tick))
    return result


def cleanup_owned_sockets(owners: dict[Path, tuple[int, int]], processes: list) -> list[str]:
    """Remove only sockets inside unchanged private directories after all children exit."""
    if any(process.poll() is None for process in processes):
        raise RuntimeError('cannot remove private sockets while an owned child remains live')
    removed = []
    for path, identity in owners.items():
        # Open the exact retained parent without following a substituted symlink.
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parent = os.fstat(descriptor)
            if (parent.st_dev, parent.st_ino) != identity or stat.S_IMODE(parent.st_mode) != 0o700:
                raise RuntimeError('private socket directory identity changed')
            try:
                value = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISSOCK(value.st_mode):
                raise RuntimeError('owned socket path was replaced with a non-socket')
            os.unlink(path.name, dir_fd=descriptor)
            removed.append(str(path))
        finally:
            os.close(descriptor)
    return removed


def run_case(plan: dict, binary: Path, harness: Path, output: Path, secrets: Path, state_dir: Path) -> dict:
    start = time.monotonic()
    end = start + BOUNDS['case']
    spec = netns_lab.LabSpec(plan['lab_id'])
    ns = spec.namespaces
    case_dir = output / plan['case']
    case_dir.mkdir()
    receipt = Receipt(case_dir / 'receipt.json', {'status': 'running', 'plan': plan, 'stage': 'setup', 'cleanup': 'pending'})
    processes, captures, capture_paths, sockets, samples, events = [], {}, {}, {}, [], []
    socket_owners = {}
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
        if len(samples) >= MAX_SAMPLES:
            raise TimeoutError('fixed status sample budget exhausted')
        before = time.monotonic_ns()
        result = {side: rpc(path, 'status', deadline) for side, path in sockets.items()}
        samples.append({'elapsed_seconds': time.monotonic() - start, 'peers': result,
                        'poll_begin_monotonic_ns': before, 'poll_end_monotonic_ns': time.monotonic_ns()})
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
            owner = private.stat()
            socket_owners[sockets[side]] = (owner.st_dev, owner.st_ino)
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
                        if (state['runtime']['flows'] != 0 or state['terminal'] is not None
                                or state['measured']['capabilities']['lanes'] != plan['duplex']):
                            raise ValueError('startup owns traffic or has wrong physical lane policy')
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
                server = launch(nsrun(flow['server_side'], sys.executable, str(harness), 'pressure-probe' if plan['qualification'] == 'pressure' and purpose == 'owned' else 'probe', 'listen', *args), log)
                processes.append(server)
                wait_log(server, log, 'Listening', transfer_end)
                client_log = case_dir / f'{purpose}-{flow["family"]}-connect.log'
                client = launch(nsrun(flow['client_side'], sys.executable, str(harness), 'pressure-probe' if plan['qualification'] == 'pressure' and purpose == 'owned' else 'probe', 'connect', *args), client_log)
                processes.append(client)
                batch.extend([(server, log, flow, 'listen'), (client, client_log, flow, 'connect')])
            # Poll while workloads are live; a post-transfer snapshot cannot prove demand.
            while any(process.poll() is None for process, *_ in batch):
                values = snapshots(transfer_end)
                for value in values.values(): validate_proxy_snapshot(value, digest, 'Forwarding')
                time.sleep(min(POLL_SECONDS, remaining(transfer_end, POLL_SECONDS)))
            for process, log, flow, role in batch:
                if process.wait(timeout=remaining(transfer_end, BOUNDS['transfer'])):
                    raise RuntimeError(f'kernel TCP probe failed: {log.read_text()}')
                result = strict_json(read_log(log).splitlines()[-1])
                verify_probe(result, flow, role, plan['qualification'] == 'pressure' and purpose == 'owned')
                transfers.append(result)
            after = snapshots(end)
            for side, value in after.items():
                state = validate_proxy_snapshot(value, digest, 'Forwarding')['runtime']
                if state['flows'] != 2 or state['stopped'] != 0: raise ValueError('split owners missing or failed')
                if purpose != 'owned' and state['transparent_admitted_packets'] <= before[side]['transparent_admitted_packets']:
                    raise ValueError('bypass did not advance ordinary transparent counters')
            stage(purpose + '_complete', transfers=transfers, latest_status=after)
        feedback = measurement_evidence(samples, plan['qualification'] == 'pressure', transfers)
        if plan['qualification'] == 'pressure':
            concurrency = verify_concurrent_probes(transfers, plan['flows'])
        else:
            concurrency = {'scope': 'clean exact-byte completion only'}
        stage('measured_feedback', measurement_evidence=feedback, concurrent_equal_policy=concurrency)
        drain_end = min(end, time.monotonic() + BOUNDS['drain_observation'])
        stage('drain', drain_original_monotonic=time.monotonic())
        accepted = {side: rpc(path, 'drain_proxy', drain_end) for side, path in sockets.items()}
        for value in accepted.values():
            validate_proxy_snapshot(value, digest)
            if not value['ok'] or value['code'] not in ('accepted', 'already_accepted'): raise ValueError('drain submission refused')
        stage('drain', drain_acceptance=accepted)
        terminal = {}
        while len(terminal) < 2:
            if len(samples) >= MAX_SAMPLES:
                raise TimeoutError('fixed status sample budget exhausted')
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
        windows = audit_windows(capture_paths, [f for f in plan['flows'] if f['split']], plan['qualification'] == 'pressure', transfers)
        stage('completed', capture_counts=counts, capture_audit=audit, native_windows=windows,
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
            removed_sockets = cleanup_owned_sockets(socket_owners, processes)
            receipt.update(cleanup='passed', removed_owned_sockets=removed_sockets,
                           status='passed' if failure is None else receipt.value['status'],
                           elapsed_seconds=time.monotonic() - start)
        except Exception as error:
            failure = error
            receipt.update(cleanup='failed', status='failed', cleanup_error=str(error)[:4096])
    if failure is not None:
        raise RuntimeError(f'{plan["case"]} failed; inspect {receipt.path}') from failure
    return receipt.value


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'probe':
        return fixed.probe_main(argv[1:])
    if argv and argv[0] == 'pressure-probe':
        return pressure_probe_main(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-id', default='pmproxy')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/debug/l2tunnel-linux')
    parser.add_argument('--build-receipt', type=Path, help='required for apply: original source-stable binary build receipt')
    parser.add_argument('--state-dir', type=Path, default=Path('/run/l2tunnel-labs'))
    parser.add_argument('--only-case', choices=['tun-full-clean', 'tun-half-clean', 'tun-full-pressure', 'tun-half-pressure'])
    parser.add_argument('--profile', choices=['clean', 'pressure'], default='clean')
    parser.add_argument('--frozen-worker', help=argparse.SUPPRESS)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    plans = [case_plan(args.lab_id, mode, args.profile) for mode in ('full', 'half')
             if args.only_case is None or args.only_case == f'tun-{mode}-{args.profile}']
    if not plans: raise ValueError('--only-case must agree with --profile')
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
    if not args.frozen_worker:
        args.output.mkdir(mode=0o755)
    output = args.output.resolve()
    binary, harness = output / 'l2tunnel-native', output / 'proxy_measured_native_smoke.py'
    if not args.frozen_worker:
        shutil.copyfile(args.binary, binary)
        binary.chmod(0o755)
        shutil.copyfile(Path(__file__), harness)
        shutil.copyfile(Path(fixed.__file__), output / 'proxy_native_smoke.py')
        shutil.copyfile(Path(netns_lab.__file__), output / 'netns_lab.py')
        shutil.copyfile(args.build_receipt, output / 'build-receipt.json')
        verify_copied_helpers(build, output)
        (output / 'launch-sources.json').write_text(json.dumps(source_hashes(), sort_keys=True) + '\n')
        identity = output.stat()
        arguments = [sys.executable, str(harness), '--lab-id', args.lab_id, '--output', str(output),
            '--binary', str(binary), '--build-receipt', str(output / 'build-receipt.json'),
            '--state-dir', str(args.state_dir.resolve()), '--profile', args.profile,
            '--frozen-worker', f'{identity.st_dev}:{identity.st_ino}', '--apply']
        if args.only_case: arguments.extend(['--only-case', args.only_case])
        # Replace this process before any namespace mutation. All actual lab,
        # probe and cleanup code then executes from these exact copied helpers.
        os.execve(sys.executable, arguments, {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        raise RuntimeError('immutable worker exec unexpectedly returned')
    identity = output.stat()
    expected_files = {'l2tunnel-native', 'proxy_measured_native_smoke.py', 'proxy_native_smoke.py',
                      'netns_lab.py', 'build-receipt.json', 'launch-sources.json'}
    if (args.frozen_worker != f'{identity.st_dev}:{identity.st_ino}' or args.output.is_symlink()
            or identity.st_uid != os.geteuid() or identity.st_mode & 0o022
            or args.binary.resolve() != binary or args.build_receipt.resolve() != output / 'build-receipt.json'
            or {p.name for p in output.iterdir()} != expected_files):
        raise ValueError('fresh exclusive copied-worker directory identity/layout required')
    helper_hashes = verify_copied_helpers(build, output, loaded=True)
    if verified_build_receipt(output / 'build-receipt.json', binary) != build:
        raise ValueError('build receipt changed during immutable copy')
    if (output / 'launch-sources.json').stat().st_size > fixed.RECEIPT_LIMIT:
        raise ValueError('launch source map exceeds receipt bound')
    launch_sources = strict_json((output / 'launch-sources.json').read_bytes())
    if not isinstance(launch_sources, dict) or any(launch_sources.get(k) != v for k, v in helper_hashes.items()):
        raise ValueError('launch helper source map differs from exact build')
    (output / 'policy.json').write_text(json.dumps(policy(), indent=2) + '\n')
    receipt = Receipt(output / 'receipt.json', {'status': 'running', 'scope': f'native measured TUN proxy {args.profile} finite acceptance',
        'binary_sha256': file_hash(binary), 'harness_sha256': file_hash(harness), 'helper_sha256': file_hash(output / 'proxy_native_smoke.py'),
        'ownership_helper_sha256': file_hash(output / 'netns_lab.py'),
        'execution': 'copied_helpers_exact_build_sources', 'executed_helper_sha256': helper_hashes,
        'policy_sha256': file_hash(output / 'policy.json'),
        'build_receipt_sha256': file_hash(output / 'build-receipt.json'),
        'binary_build_source_sha256': build['source_sha256_after'],
        'source_observed_at_launch_sha256': launch_sources,
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
                verify_copied_helpers(build, output, loaded=True)
                case = run_case(plan, binary, harness, output, secrets, args.state_dir)
                verify_copied_helpers(build, output, loaded=True)
                cases.append({'case': plan['case'], 'status': case['status'], 'cleanup': case['cleanup']})
                receipt.update(cases=cases)
        verified_build_receipt(output / 'build-receipt.json', binary)
        receipt.update(status='passed', cleanup='passed', executed_helpers_unchanged=True)
    except Exception as error:
        receipt.update(status='failed', error=str(error)[:4096], cleanup='inspect_case_receipt')
        raise
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
