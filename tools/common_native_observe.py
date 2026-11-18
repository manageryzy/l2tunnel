#!/usr/bin/env python3
"""Read-only bounded capture and CPU observations for the Common native matrix."""
from __future__ import annotations

from collections import Counter
import math
import os
from pathlib import Path
import re
import socket
import struct
import time

CAPTURE_BYTES = 512 * 1024 * 1024
CAPTURE_PACKETS = 2_000_000
SNAPLEN = 2048
RECORD_METRICS = ('algorithm_bytes', 'final_record_bytes', 'record_overhead_bytes')
EXTENT_METRICS = ('route_header_bytes', 'fragment_header_bytes', 'recovery_header_bytes',
                  'systematic_coded_fill_bytes', 'codec_envelope_bytes', 'codec_container_bytes',
                  'codec_unit_header_bytes', 'codec_body_bytes')
JOINED_METRICS = ('socket_ip_bytes', 'socket_ip_over_record_bytes',
                  'record_outside_codec_body_bytes', 'socket_ip_outside_codec_body_bytes')
CODEC_COVERAGE = ('envelope_only', 'fragmented_units', 'swift_stream', 'fragmented_record',
                  'not_applicable', 'unencoded_native')
NATIVE_ENCODING_KINDS = ('aligned_timestamp', 'aligned_raw', 'aligned_lz4', 'aligned_delta',
                         'aligned_elided', 'aligned_predictive', 'aligned_timestamp_pair',
                         'swift_literal', 'swift_literal_context', 'swift_delta', 'unencoded')


def validate_native_encoding(value):
    """Validate once-per-admission totals separately from emitted-record counts."""
    if (not isinstance(value, dict) or type(value.get('counter_overflow')) is not int
            or value['counter_overflow'] != 0):
        raise ValueError('native encoding counters absent or overflowed')
    unsigned_keys = ('inputs', 'original_bytes', 'context_bytes', 'encoded_body_bytes', 'framing_bytes')
    result = {}
    for label in ('native_packet', 'proxy_record'):
        forms = value.get(label)
        if not isinstance(forms, dict) or set(forms) != set(NATIVE_ENCODING_KINDS):
            raise ValueError('native encoding forms incomplete')
        result[label] = {}
        for name, item in forms.items():
            if (not isinstance(item, dict) or set(item) != set(unsigned_keys)
                    | {'codec_net_gain_bytes', 'net_gain_bytes'}
                    or any(type(item[key]) is not int or item[key] < 0 for key in unsigned_keys)
                    or any(type(item[key]) is not int for key in ('codec_net_gain_bytes', 'net_gain_bytes'))):
                raise ValueError('native encoding totals invalid')
            codec_gain = item['original_bytes'] - item['context_bytes'] - item['encoded_body_bytes']
            if (codec_gain != item['codec_net_gain_bytes']
                    or codec_gain - item['framing_bytes'] != item['net_gain_bytes']
                    or (item['inputs'] == 0 and any(item[key] for key in unsigned_keys))):
                raise ValueError('native encoding signed gains or empty population differ')
            result[label][name] = {**item,
                'mean_codec_net_gain_bytes': codec_gain / item['inputs'] if item['inputs'] else None,
                'mean_net_gain_bytes': item['net_gain_bytes'] / item['inputs'] if item['inputs'] else None}
    return result


class ExtentMetricsError(ValueError):
    """Invalid layer attribution with separately validated base record statistics."""
    def __init__(self, message, base_validation):
        super().__init__(message)
        self.base_validation = base_validation


def distribution(histogram):
    count = sum(histogram.values())
    def percentile(fraction):
        if not count:
            return None
        rank, seen = math.ceil(count * fraction), 0
        for size, amount in sorted(histogram.items()):
            seen += amount
            if seen >= rank:
                return size
        raise ValueError('invalid histogram')
    return {'packets': count, 'ip_bytes': sum(size * amount for size, amount in histogram.items()),
            'mean_ip_packet_bytes': sum(size * amount for size, amount in histogram.items()) / count if count else None,
            'p50_ip_packet_bytes': percentile(.5), 'p99_ip_packet_bytes': percentile(.99),
            'maximum_ip_packet_bytes': max(histogram, default=None),
            'histogram_ip_packet_bytes': {str(size): amount for size, amount in sorted(histogram.items())}}


def observe_tcp_sack(packet, ihl, counts):
    """Count visible ACK options on this surface; each ACK contributes at most once."""
    if int.from_bytes(packet[6:8], 'big') & 0x3fff:
        counts['unparsed_fragments'] += 1
        return
    tcp = packet[ihl:]
    header = (tcp[12] >> 4) * 4 if len(tcp) >= 20 else 0
    if not 20 <= header <= len(tcp):
        counts['malformed_headers'] += 1
        return
    if not tcp[13] & 0x10:
        return
    counts['ack_packets'] += 1
    offset, first = 20, None
    while offset < header:
        kind = tcp[offset]
        if kind == 0:
            break
        if kind == 1:
            offset += 1
            continue
        size = tcp[offset + 1] if offset + 1 < header else 0
        if size < 2 or offset + size > header:
            counts['malformed_options'] += 1
            return
        if kind == 5:
            if first is not None or size < 10 or (size - 2) % 8:
                counts['malformed_options'] += 1
                return
            first = struct.unpack_from('!II', tcp, offset + 2)
        offset += size
    if first is not None:
        counts['acks_with_sack'] += 1
        extent = (first[1] - first[0]) & 0xffffffff
        if 1 <= extent <= 64:
            counts['first_block_1_to_64_bytes'] += 1
        if extent == 16:
            counts['first_block_16_bytes'] += 1


def capture_summary(path, addresses, sample_wall_ns=None):
    """Count observed IP lengths, never infer plaintext or per-packet encapsulation.

The owned veth/HTB/netem lab observes post-qdisc survivors at both endpoint WAN
surfaces, verified against paired packet identities and qdisc counters. Capture
placement is lab-specific; it is not a pre-loss admission counter. Each surface
is separate; summing the two would double-count delivery.
"""
    if path.is_symlink() or not path.is_file() or path.stat().st_size >= CAPTURE_BYTES:
        raise ValueError('capture absent, non-regular, or byte ceiling exhausted')
    magic = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\xa1\xb2\xc3\xd4': ('>', 1000),
             b'\x4d\x3c\xb2\xa1': ('<', 1), b'\xa1\xb2\x3c\x4d': ('>', 1)}
    total = {'a_to_b': Counter(), 'b_to_a': Counter()}
    sample = {'a_to_b': Counter(), 'b_to_a': Counter()}
    tcp_sample = {'a_to_b': Counter(), 'b_to_a': Counter()}
    protocols, first, last, count, non_ip = Counter(), None, None, 0, 0
    with path.open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in magic:
            raise ValueError('unsupported/truncated classic pcap header')
        endian, scale = magic[header[:4]]
        major, minor, zone, accuracy, snaplen, link = struct.unpack(endian + 'HHIIII', header[4:])
        if (major, minor, zone, accuracy) != (2, 4, 0, 0) or snaplen != SNAPLEN or link not in (1, 101, 113, 276):
            raise ValueError('unsupported pcap geometry/link')
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError('truncated pcap packet header')
            seconds, fraction, captured, original = struct.unpack(endian + 'IIII', record)
            if fraction * scale >= 1_000_000_000 or not 0 < captured == original <= snaplen:
                raise ValueError('truncated/oversized capture or invalid timestamp')
            frame = stream.read(captured)
            if len(frame) != captured:
                raise ValueError('truncated pcap bytes')
            count += 1
            if count >= CAPTURE_PACKETS:
                raise ValueError('capture packet ceiling exhausted')
            stamp = seconds * 1_000_000_000 + fraction * scale
            first = stamp if first is None else min(first, stamp)
            last = stamp if last is None else max(last, stamp)
            offset, protocol_at = {1: (14, 12), 101: (0, None), 113: (16, 14), 276: (20, 0)}[link]
            if len(frame) < offset:
                raise ValueError('truncated link header')
            protocol = 0x800 if protocol_at is None else int.from_bytes(frame[protocol_at:protocol_at + 2], 'big')
            if protocol != 0x800:
                non_ip += 1
                continue
            packet = frame[offset:]
            if len(packet) < 20 or packet[0] >> 4 != 4:
                raise ValueError('malformed IPv4 header')
            ihl, length = (packet[0] & 15) * 4, int.from_bytes(packet[2:4], 'big')
            if not 20 <= ihl <= length <= len(packet):
                raise ValueError('invalid IPv4 captured extent')
            source, destination = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
            if (source, destination) == tuple(addresses):
                direction = 'a_to_b'
            elif (destination, source) == tuple(addresses):
                direction = 'b_to_a'
            else:
                raise ValueError(f'unexpected captured IPv4 tuple: {source}->{destination}')
            protocols[str(packet[9])] += 1
            total[direction][length] += 1
            if sample_wall_ns is not None and sample_wall_ns[0] <= stamp < sample_wall_ns[1]:
                sample[direction][length] += 1
                if packet[9] == socket.IPPROTO_TCP:
                    observe_tcp_sack(packet[:length], ihl, tcp_sample[direction])
    return {'status': 'parsed', 'captured_packets': count, 'non_ipv4_packets': non_ip,
            'first_wall_ns': first, 'last_wall_ns': last, 'ip_protocol_counts': dict(protocols),
            'whole_capture': {key: distribution(value) for key, value in total.items()},
            'sample_window': None if sample_wall_ns is None else {
                'wall_ns': list(sample_wall_ns), 'observed_ipv4_tcp_ack_options': tcp_sample,
                **{key: distribution(value) for key, value in sample.items()}},
            'definition': 'IPv4 total_length at this capture surface; packet-size quantiles are not encapsulation-overhead quantiles'}


def capture_counters(log):
    text = log.read_text()
    result = {}
    for key, suffix in [('captured', 'packets captured'), ('filtered', 'packets received by filter'), ('dropped', 'packets dropped by kernel')]:
        values = re.findall(r'^([0-9]+) ' + suffix + r'\s*$', text, re.MULTILINE)
        if len(values) != 1:
            raise ValueError('missing/ambiguous tcpdump counter: ' + key)
        result[key] = int(values[0])
    if result['dropped']:
        raise ValueError('tcpdump kernel capture drops prevent complete accounting')
    return result


def cpu_snapshot(children):
    """Host-wide counters include other jobs; child kernel time is separate."""
    begin = time.monotonic_ns()
    host = Path('/proc/stat').read_text()
    processes = []
    for label, process in children:
        if process.poll() is not None:
            continue
        try:
            fields = Path(f'/proc/{process.pid}/stat').read_text().rsplit(')', 1)[1].split()
            processes.append({'label': label, 'pid': process.pid, 'user_ticks': int(fields[11]),
                'kernel_ticks': int(fields[12]), 'start_ticks': int(fields[19]), 'rss_pages': int(fields[21])})
        except FileNotFoundError:
            continue
    return {'begin_ns': begin, 'end_ns': time.monotonic_ns(), 'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
            'page_bytes': os.sysconf('SC_PAGE_SIZE'), 'host_proc_stat': host, 'processes': processes,
            'loadavg': Path('/proc/loadavg').read_text(),
            'scope': 'host CPU includes unrelated jobs; process kernel_ticks identify each unreaped owned child'}


def validate_wire_metrics(value, carrier):
    """Validate the actual opt-in report; invalid samples never qualify overhead."""
    def unsigned(number):
        return type(number) is int and number >= 0
    if (type(value.get('schema')) is not int or value['schema'] not in (1, 2, 3)
            or type(value.get('invalid_samples')) is not int or value['invalid_samples'] != 0
            or type(value.get('counter_overflow')) is not int or value['counter_overflow'] != 0):
        raise ValueError('wire observer invalid samples, counter overflow, or unknown schema')
    classes, boundaries = value.get('accepted_classes'), value.get('accepted_boundaries')
    if not isinstance(classes, dict) or set(classes) != {'swift_source', 'direct_arq_source', 'systematic_fec_source', 'repair', 'recovery_feedback', 'unreliable_native'}:
        raise ValueError('incomplete accepted record classes')
    if not isinstance(boundaries, dict) or set(boundaries) != {'socket_accepted', 'tls_stream_flushed', 'quic_datagram_accepted'}:
        raise ValueError('incomplete actual acceptance boundaries')
    if not all(unsigned(number) for number in [*classes.values(), *boundaries.values()]):
        raise ValueError('invalid accepted record count')
    expected = {'udp': 'socket_accepted', 'raw': 'socket_accepted', 'tls': 'tls_stream_flushed', 'quic': 'quic_datagram_accepted'}[carrier]
    samples = sum(classes.values())
    if samples == 0 or sum(boundaries.values()) != samples or boundaries[expected] != samples:
        raise ValueError('actual record count or carrier boundary mismatch')
    def histogram(name, expected_samples):
        metric = value.get(name)
        if not isinstance(metric, dict) or not isinstance(metric.get('histogram'), list) or len(metric['histogram']) > 65536:
            raise ValueError('missing bounded wire histogram')
        previous, count, total = -1, 0, 0
        for pair in metric['histogram']:
            if not isinstance(pair, list) or len(pair) != 2 or not all(unsigned(number) for number in pair):
                raise ValueError('invalid wire histogram bin')
            size, amount = pair
            if not previous < size <= 65535 or amount == 0:
                raise ValueError('duplicate, unordered, oversized or empty histogram bin')
            previous, count, total = size, count + amount, total + size * amount
        if (count != expected_samples or not unsigned(metric.get('samples'))
                or not unsigned(metric.get('total_bytes'))
                or metric['samples'] != count or metric['total_bytes'] != total):
            raise ValueError('wire histogram totals differ from expected sample population: ' + name)
        for percentile in (50, 95, 99):
            rank, accumulated, answer = (count * percentile + 99) // 100, 0, None
            for size, amount in metric['histogram']:
                accumulated += amount
                if accumulated >= rank:
                    answer = size
                    break
            key = 'p' + str(percentile)
            observed = metric.get(key)
            if key not in metric or observed != answer or (observed is not None and not unsigned(observed)):
                raise ValueError('wire histogram quantile mismatch')
        return total
    totals = {name: histogram(name, samples) for name in RECORD_METRICS}
    if totals['algorithm_bytes'] + totals['record_overhead_bytes'] != totals['final_record_bytes']:
        raise ValueError('record overhead totals do not equal final minus algorithm bytes')
    if not unsigned(value.get('fragmented_records')) or value['fragmented_records'] > samples:
        raise ValueError('invalid fragmented record count')
    if not unsigned(value.get('diagnostic_heap_bytes')) or value['diagnostic_heap_bytes'] == 0:
        raise ValueError('observer allocation absent')
    result = {'status': 'validated', 'accepted_records': samples, 'boundary': expected,
              'diagnostic_heap_bytes': value['diagnostic_heap_bytes'], 'totals': totals}
    if value['schema'] == 1:
        return result
    try:
        if not unsigned(value.get('extent_errors')) or value['extent_errors'] != 0:
            raise ValueError('wire observer extent errors prevent layer attribution')
        coverage = value.get('codec_coverage')
        if (not isinstance(coverage, dict) or set(coverage) != set(CODEC_COVERAGE)
                or not all(unsigned(count) for count in coverage.values())
                or sum(coverage.values()) != samples):
            raise ValueError('codec coverage differs from accepted record population')
        if coverage['fragmented_record'] != value['fragmented_records']:
            raise ValueError('outer fragment coverage differs from fragmented records')
        recovery = samples - coverage['fragmented_record'] - coverage['unencoded_native']
        codec = coverage['envelope_only'] + coverage['fragmented_units']
        populations = dict(zip(EXTENT_METRICS, (samples, samples, recovery, recovery, codec, codec, codec, codec)))
        extent_totals = {name: histogram(name, count) for name, count in populations.items()}
        if any(total > totals['algorithm_bytes'] for total in extent_totals.values()):
            raise ValueError('layer extent bytes exceed containing algorithm bytes')
        allocations = [value.get(key) for key in ('diagnostic_histogram_heap_bytes', 'diagnostic_path_heap_bytes')]
        if not all(unsigned(count) for count in allocations) or sum(allocations) != value['diagnostic_heap_bytes']:
            raise ValueError('schema2 observer allocation totals differ')
        result = {**result, 'extent_samples': populations, 'extent_totals': extent_totals,
                  'codec_coverage': coverage, 'extent_errors': 0}
        if value['schema'] == 3:
            ip_samples = samples if carrier in ('udp', 'raw') else 0
            joined_samples = dict(zip(JOINED_METRICS, (ip_samples, ip_samples, codec,
                                                       codec if ip_samples else 0)))
            joined_totals = {name: histogram(name, count) for name, count in joined_samples.items()}
            if ip_samples and (joined_totals['socket_ip_bytes'] != totals['final_record_bytes']
                               + joined_totals['socket_ip_over_record_bytes']):
                raise ValueError('actual IP bytes differ from Records plus actual outer bytes')
            # The codec population is a subset. Its joined histogram cannot be
            # reconstructed by subtracting independent whole-owner histograms.
            if joined_totals['record_outside_codec_body_bytes'] > totals['final_record_bytes']:
                raise ValueError('joined codec framing exceeds all accepted Records bytes')
            if (ip_samples and joined_totals['socket_ip_outside_codec_body_bytes']
                    < joined_totals['record_outside_codec_body_bytes']):
                raise ValueError('joined IP codec framing is shorter than Records framing')
            result.update(joined_samples=joined_samples, joined_totals=joined_totals)
            result['native_encoding'] = validate_native_encoding(value.get('native_encoding'))
    except ValueError as error:
        # Runtime validation still refuses the complete observation. An offline
        # reader may retain the independently valid three base histograms.
        raise ExtentMetricsError(str(error), result) from error
    return result
