#!/usr/bin/env python3
"""Bounded offline runtime_profile (schema 1/2) analysis and plots; never runs native traffic.

``analyze`` re-audits native_throughput.py case directories with
``native_throughput_analysis.py`` and parses the ``runtime_profile`` lines of the
copied ``a-daemon.log``/``b-daemon.log`` into CSV/Markdown/HTML tables in a fresh
output directory. ``plot`` renders profile-domain figures from an ``analyze``
output directory and imports matplotlib only after its inputs pass their bounds.
"""
import argparse
import csv
import hashlib
import html
import json
import math
import os
from pathlib import Path

try:
    from . import native_throughput_analysis as accounting
except ImportError:
    import native_throughput_analysis as accounting

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 16 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_SNAPSHOTS = 2048
MAX_CASES = 32
MAX_TOTAL_PROFILES = 8192
MAX_TOTAL_INPUT = 1024 * 1024 * 1024
U64 = 2**64 - 1
RUNTIME = 'managed-tcp'
COUNTERS = '''driver_iterations wake_incoming wake_local wake_data_flush wake_feedback_flush wake_timer
 device_read_calls device_read_none device_read_frames device_read_bytes device_write_calls device_write_would_block
 device_write_frames device_write_bytes codec_encode_frames codec_encode_bytes codec_decode_frames codec_decode_bytes
 records_read plaintext_record_bytes_read records_flushed plaintext_record_bytes_flushed data_records_flushed
 feedback_records_flushed control_records_flushed writer_wake_data writer_wake_feedback writer_wake_control
 data_admission_credit_blocked data_admission_queue_full data_admission_protocol_paused data_admitted_frames feedback_updates'''.split()
HIGH = '''native_pending_records incoming_queue_records outgoing_queue_records control_queue_records unconfirmed_native_packets
 unflushed_data_records plaintext_record_bytes native_frame_bytes configured_local_queue_packets configured_delivery_credit_packets'''.split()
VALUES = '''delivery_enabled delivery_target_bytes delivery_outstanding_bytes delivery_outstanding_records
 delivery_retained_records delivery_service_rtt_micros delivery_service_rtt_fresh delivery_native_pending_bytes delivery_staged_native_bytes'''.split()
STAGES = '''driver_select_wait writer_select_wait device_read device_write codec_encode codec_decode outer_encode outer_decode
 transport_record_read incoming_queue_send_wait transport_prefix_write transport_body_write transport_flush credit_blocked_elapsed'''.split()
# Source files whose build-time digests identify the emitted profile schema.
SCHEMA_SOURCES = ('crates/l2tunnel-runtime/src/managed/profiling.rs', 'crates/l2tunnel-client-core/src/profiling_cli.rs')
DEFAULT_STAGED_NATIVE_MAX_BYTES = 1600
DEFAULT_BASELINE_LOCAL_QUEUE_PACKETS = 64
OUTPUT_TABLES = ('cases', 'profiles', 'profile_intervals', 'stage_timings', 'high_water', 'process_cpu',
                 'baseline_comparison', 'delivery_values', 'mode_audit')
PLOT_TABLES = ('profiles', 'profile_intervals', 'high_water', 'stage_timings', 'delivery_values', 'cases')
PLOT_MAX_FILE = 128 * 1024 * 1024
PLOT_MAX_ROWS = 150000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name):
    require(type(value) is int and 0 <= value <= U64, 'invalid u64: ' + name)
    return value


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('nonfinite JSON: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def read(path, manifest):
    require(path.is_file() and path.stat().st_size <= MAX_FILE, 'missing or oversized: ' + str(path))
    raw = path.read_bytes()
    require(sum(item['bytes'] for item in manifest.values()) + len(raw) <= MAX_TOTAL_INPUT, 'total profile input bound')
    manifest[str(path.resolve())] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    return raw


def parse_profiles(raw):
    require(len(raw) <= MAX_FILE, 'log size bound')
    result = []
    for index, line in enumerate(raw.splitlines()):
        require(len(line) <= MAX_LINE, 'daemon log line size bound')
        if b'"runtime_profile"' not in line:
            continue
        value = strict_json(line)
        schema = value.get('schema')
        fields = {'event', 'schema', 'runtime', 'elapsed_nanos', 'terminal', 'counters', 'high_water', 'timings'}
        if schema == 2:
            fields.add('values')
        require(set(value) == fields, 'unsupported profile fields')
        require(value['event'] == 'runtime_profile' and type(value['schema']) is int and value['schema'] in (1, 2)
                and value['runtime'] == RUNTIME and type(value['terminal']) is bool, 'unsupported profile schema')
        integer(value['elapsed_nanos'], 'elapsed_nanos')
        for name, labels in [('counters', COUNTERS), ('high_water', HIGH)]:
            require(set(value[name]) == set(labels), 'unsupported ' + name + ' labels')
            for key, item in value[name].items():
                integer(item, key)
        if schema == 2:
            require(set(value['values']) == set(VALUES), 'unsupported values labels')
            for key, item in value['values'].items():
                integer(item, key)
            require(value['values']['delivery_enabled'] in (0, 1) and value['values']['delivery_service_rtt_fresh'] in (0, 1),
                    'invalid delivery flags')
        require(set(value['timings']) == set(STAGES), 'unsupported timing labels')
        for key, item in value['timings'].items():
            require(set(item) == {'count', 'total_nanos', 'max_nanos'}, 'unsupported timing fields')
            for field, n in item.items():
                integer(n, key + '.' + field)
        require(len(result) < MAX_SNAPSHOTS, 'profile sample bound')
        result.append({'line': index + 1, 'snapshot': value})
    return result


def delta(current, previous, name, warnings):
    if current == U64 or previous == U64:
        warnings.add('saturated counters: deltas censored')
        return None
    if current < previous:
        warnings.add('cumulative regression: non-atomic/coalesced observation or reset; affected delta omitted: ' + name)
        return None
    return current - previous


def ratio(a, b):
    return a / b if a is not None and b else None


def analyze_stream(samples, case, side):
    rows, stages, highs, warnings = [], [], [], set()
    previous, duplicate_count = None, 0
    for sample_index, entry in enumerate(samples):
        value = entry['snapshot']
        if previous is not None and value == previous:
            duplicate_count += 1
            continue
        elapsed = value['elapsed_nanos']
        elapsed_delta = elapsed - previous['elapsed_nanos'] if previous else elapsed
        if elapsed_delta <= 0:
            warnings.add('nonadvancing profile time: interval rates omitted')
        context = {'case': case, 'endpoint': side, 'sample_index': sample_index, 'log_line': entry['line'],
                   'seconds_since_profile_start': elapsed / 1e9, 'terminal': value['terminal'], 'schema': value['schema'],
                   'interval_seconds': elapsed_delta / 1e9 if elapsed_delta > 0 else None,
                   'clock_domain': 'runtime profiling elapsed; parent monotonic alignment unobserved'}
        row = dict(context)
        for key, n in value['counters'].items():
            prior = previous['counters'][key] if previous else 0
            row[key + '_cumulative'] = n
            row[key + '_delta'] = delta(n, prior, key, warnings)
        for kind in ['data', 'control', 'feedback']:
            numerator = kind + '_records_flushed'
            row[kind + '_flushed_fraction_cumulative'] = ratio(value['counters'][numerator], value['counters']['records_flushed'])
            row[kind + '_flushed_fraction_interval'] = ratio(row[numerator + '_delta'], row['records_flushed_delta'])
        row['credit_blocked_elapsed_ratio_cumulative'] = ratio(value['timings']['credit_blocked_elapsed']['total_nanos'], elapsed)
        for key, item in value['timings'].items():
            prior = previous['timings'][key] if previous else {'count': 0, 'total_nanos': 0, 'max_nanos': 0}
            count_delta = delta(item['count'], prior['count'], key + '.count', warnings)
            total_delta = delta(item['total_nanos'], prior['total_nanos'], key + '.total', warnings)
            stage = {**context, 'stage': key, 'count_cumulative': item['count'], 'count_delta': count_delta,
                     'total_elapsed_seconds_cumulative': item['total_nanos'] / 1e9,
                     'total_elapsed_seconds_delta': total_delta / 1e9 if total_delta is not None else None,
                     'mean_attempt_us_cumulative': ratio(item['total_nanos'], item['count']) / 1000 if item['count'] else None,
                     'mean_completed_attempt_us_interval': (ratio(total_delta, count_delta) / 1000
                                                            if count_delta and total_delta is not None else None),
                     'max_attempt_us_cumulative': item['max_nanos'] / 1000,
                     'max_attempt_us_interval': None,
                     'cpu_time': 'unobserved; elapsed includes suspension/preemption and overlaps other stages'}
            if item['max_nanos'] == U64:
                warnings.add('saturated timing maximum')
            if key == 'credit_blocked_elapsed':
                row['credit_blocked_elapsed_ratio_interval'] = ratio(total_delta, elapsed_delta) if elapsed_delta > 0 else None
            stages.append(stage)
        for key, n in value['high_water'].items():
            if key == 'unconfirmed_native_packets':
                limit = value['high_water']['configured_delivery_credit_packets']
            elif key in {'outgoing_queue_records', 'native_pending_records'}:
                limit = value['high_water']['configured_local_queue_packets']
            else:
                limit = None
            highs.append({**context, 'name': key, 'maximum_since_profile_start': n, 'configured_comparable_limit_packets': limit,
                          'maximum_to_limit_ratio': ratio(n, limit),
                          'note': 'cumulative high water, not current occupancy; unflushed includes writer/coalesced progress, '
                                  'incoming/control have distinct bounds'})
        rows.append(row)
        previous = value
    if not rows:
        return {'case': case, 'endpoint': side, 'observed': False, 'warnings': ''}, rows, stages, highs
    last = rows[-1]
    final = samples[-1]['snapshot']
    blocked = final['timings']['credit_blocked_elapsed']
    summary = {'case': case, 'endpoint': side, 'observed': True, 'snapshots': len(samples),
               'exact_duplicates_ignored': duplicate_count,
               'terminal_observed': any(e['snapshot']['terminal'] for e in samples),
               'profile_observed_seconds': last['seconds_since_profile_start'],
               'credit_blocked_elapsed_ratio': last['credit_blocked_elapsed_ratio_cumulative'],
               'credit_blocked_elapsed_seconds': blocked['total_nanos'] / 1e9,
               'credit_blocked_episode_count': blocked['count'],
               'credit_blocked_episode_mean_us': ratio(blocked['total_nanos'], blocked['count']) / 1000 if blocked['count'] else None,
               'credit_blocked_episode_max_us': blocked['max_nanos'] / 1000,
               'queue_full_count': final['counters']['data_admission_queue_full'],
               'credit_blocked_attempt_count': final['counters']['data_admission_credit_blocked'],
               'configured_local_queue_packets': final['high_water']['configured_local_queue_packets'],
               'configured_delivery_credit_packets': final['high_water']['configured_delivery_credit_packets'],
               'unconfirmed_native_packets_high_water': final['high_water']['unconfirmed_native_packets'],
               'outgoing_queue_records_high_water': final['high_water']['outgoing_queue_records'],
               'unflushed_data_records_high_water': final['high_water']['unflushed_data_records'],
               'warnings': ' | '.join(sorted(warnings))}
    for key in ['data_records_flushed', 'control_records_flushed', 'feedback_records_flushed', 'records_flushed',
                'plaintext_record_bytes_flushed', 'device_read_bytes', 'device_write_bytes', 'device_read_frames', 'device_write_frames']:
        summary[key] = final['counters'][key]
    for kind in ['data', 'control', 'feedback']:
        summary[kind + '_flushed_fraction'] = last[kind + '_flushed_fraction_cumulative']
    return summary, rows, stages, highs


def delivery_witness(receipt, streams, staged_native_max_bytes=DEFAULT_STAGED_NATIVE_MAX_BYTES,
                     baseline_local_queue_packets=DEFAULT_BASELINE_LOCAL_QUEUE_PACKETS):
    """Report actual selected-policy evidence without changing integrity receipts."""
    plan = receipt.get('plan', {})
    selected = plan.get('delivery_window', 'legacy')
    result = {'requested_delivery_window': selected, 'actual_bdp_observed': False, 'policy_witness': 'legacy_policy', 'errors': ''}
    if selected != 'bdp':
        return result
    errors = []
    config = plan.get('delivery_policy', {})
    flags = {'--delivery-window': 'bdp', '--forward-mbps': config.get('forward_mbps'),
             '--reverse-mbps': config.get('reverse_mbps'), '--bootstrap-rtt-ms': config.get('bootstrap_rtt_ms'),
             '--bdp-headroom-percent': config.get('headroom_percent'), '--inflight-max-bytes': config.get('max_inflight_bytes'),
             '--inflight-max-records': config.get('max_records')}
    cli = receipt.get('effective_cli', [])
    for flag, value in flags.items():
        indices = [i for i, v in enumerate(cli) if v == flag]
        if value is None or len(indices) != 1 or indices[0] + 1 >= len(cli) or cli[indices[0] + 1] != str(value):
            errors.append('CLI policy mismatch: ' + flag)
    cap_bytes, cap_records = config.get('max_inflight_bytes'), config.get('max_records')
    if type(cap_bytes) is not int or type(cap_records) is not int:
        errors.append('missing declared policy bounds')
    else:
        for side in ['a', 'b']:
            active = [e['snapshot'] for e in streams.get(side, []) if e['snapshot'].get('values', {}).get('delivery_enabled') == 1]
            if not active:
                errors.append(side + ': no actual enabled schema2 observations')
                continue
            for v in active:
                g = v['values']
                if not 0 < g['delivery_target_bytes'] <= cap_bytes:
                    errors.append(side + ': byte target outside declared bound')
                if any(g[k] > cap_bytes for k in ['delivery_outstanding_bytes', 'delivery_native_pending_bytes']):
                    errors.append(side + ': byte ownership above declared bound')
                if any(g[k] > cap_records for k in ['delivery_outstanding_records', 'delivery_retained_records']):
                    errors.append(side + ': metadata ownership above declared bound')
                if g['delivery_staged_native_bytes'] > staged_native_max_bytes:
                    errors.append(side + ': staged source above selected maximum')
                if v['high_water']['configured_delivery_credit_packets'] != cap_records:
                    errors.append(side + ': declared receive-record budget mismatch')
                if v['high_water']['configured_local_queue_packets'] != baseline_local_queue_packets:
                    errors.append(side + f': local queue changed from matched {baseline_local_queue_packets}-packet baseline')
    result.update(actual_bdp_observed=not errors, policy_witness='observed_bounded_bdp' if not errors else 'unqualified_policy_witness',
                  errors=' | '.join(sorted(set(errors))))
    return result


def write_csv(path, rows):
    names = list(dict.fromkeys(key for row in rows for key in row))
    with path.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=names)
        writer.writeheader()
        writer.writerows(rows)


def process_cpu(receipt, case):
    # Each PID/starttime identity is retained; no unstated daemon/probe mapping.
    previous, rows = {}, []
    hz = receipt.get('clock_ticks')
    if type(hz) is not int or hz <= 0:
        return rows
    for sample in receipt.get('samples', [])[:96]:
        at = sample['at_ns']
        for p in sample.get('processes', [])[:4]:
            key = p['pid'], p['starttime_ticks']
            ticks = p['utime_ticks'] + p['stime_ticks']
            old = previous.get(key)
            if old and at > old[0] and ticks >= old[1]:
                seconds = (at - old[0]) / 1e9
                rows.append({'case': case, 'pid': key[0], 'process_starttime_ticks': key[1],
                             'nominal_batch_begin_ns': old[0], 'nominal_batch_end_ns': at,
                             'user_system_cpu_seconds_delta': (ticks - old[1]) / hz,
                             'nominal_elapsed_seconds': seconds, 'cpu_to_elapsed_ratio': (ticks - old[1]) / hz / seconds,
                             'scope': 'whole process CPU, not stage CPU; serial /proc reads unbracketed; process role not inferred'})
            previous[key] = at, ticks
    return rows


def report_text(summaries, timings, mode_rows, config):
    target, forward, reverse = config.forward_target_mbps, config.forward_capacity_mbps, config.reverse_capacity_mbps
    window = config.max_measurement_seconds
    lines = ['# Managed TCP/TLS runtime profiling observations', '',
             f'Application forward performance target: **{target} Mbps** on the {forward} Mbps A→B direction. '
             f'Integrity and performance remain separate. Reverse {reverse} Mbps is assessed separately.', '',
             'Runtime elapsed_nanos starts when profiling is enabled. There is no clock anchor to the parent/probe monotonic '
             f'clock, so no profile interval is asserted to match the exact {window}s application window. Profile stages include '
             'warmup and drain unless separately anchored in a future schema.', '',
             'All stage timing is elapsed attempt time, including async suspension, preemption and cancelled attempts. '
             'In-progress waits enter totals only when completed/cancelled. Concurrent stages overlap and MUST NOT be added '
             'into CPU utilization. Codec timings are not process CPU. Available whole-process CPU samples are separate and '
             'nominally timed.', '',
             'Mean/count/cumulative maximum are available; quantiles and interval maxima are unobserved. Delta means are '
             'attributed to completion/cancellation intervals, so one long wait can make an interval elapsed ratio exceed 1. '
             'Fixed atomic fields are coalesced/non-atomic across tasks.', '',
             '| Case/endpoint | Profile span s | Credit-blocked elapsed ratio | Credit-full attempts | Queue-full count | '
             'Unconfirmed high/configured credit | Forward gate |',
             '|---|---:|---:|---:|---:|---:|---|']
    for r in summaries:
        if not r.get('observed'):
            lines += ['| ' + r['case'] + '/' + r['endpoint'] + ' | unobserved | | | | | |']
            continue
        lines += ['| ' + ' | '.join(str(v) for v in [
            r['case'] + '/' + r['endpoint'], r['profile_observed_seconds'], r['credit_blocked_elapsed_ratio'],
            r['credit_blocked_attempt_count'], r['queue_full_count'],
            str(r['unconfirmed_native_packets_high_water']) + '/' + str(r['configured_delivery_credit_packets']),
            r['forward_performance']]) + ' |']
        if r['warnings']:
            lines += ['', r['case'] + '/' + r['endpoint'] + ' warnings: ' + r['warnings']]
    lines += ['', '## Completed attempt elapsed timings', '',
              '| Case/endpoint | Stage | Attempts | Total elapsed s | Mean us | Cumulative max us |',
              '|---|---|---:|---:|---:|---:|']
    latest_stages = {}
    for row in timings:
        latest_stages[row['case'], row['endpoint'], row['stage']] = row
    for (_, _, stage), row in sorted(latest_stages.items()):
        if stage in {'transport_prefix_write', 'transport_body_write', 'transport_flush', 'incoming_queue_send_wait',
                     'codec_encode', 'codec_decode', 'device_read', 'device_write'}:
            lines += ['| ' + ' | '.join(str(v) for v in [
                row['case'] + '/' + row['endpoint'], stage, row['count_cumulative'], row['total_elapsed_seconds_cumulative'],
                row['mean_attempt_us_cumulative'], row['max_attempt_us_cumulative']]) + ' |']
    lines += ['', '## Flushed record mix', '',
              '| Case/endpoint | Data records | Feedback records | Control records | Data fraction | Plaintext record bytes | '
              'Native read/write frames |',
              '|---|---:|---:|---:|---:|---:|---:|']
    for row in summaries:
        if row.get('observed'):
            lines += ['| ' + ' | '.join(str(v) for v in [
                row['case'] + '/' + row['endpoint'], row['data_records_flushed'], row['feedback_records_flushed'],
                row['control_records_flushed'], row['data_flushed_fraction'], row['plaintext_record_bytes_flushed'],
                str(row['device_read_frames']) + '/' + str(row['device_write_frames'])]) + ' |']
    lines += ['', '## Actual selected-policy witness', '']
    for row in mode_rows:
        lines += [row['case'] + ': ' + row['policy_witness'] + (('; ' + row['errors']) if row['errors'] else '')]
    lines += ['', 'Schema2 delivery_values.csv contains current byte targets/debt, retained metadata, pending/staged native '
              'bytes and service RTT/freshness. These are gauges, not cumulative counters. Disabled means legacy policy; '
              'missing schema1 gauges remain unobserved. A shrinking target may be below existing non-revoked debt. None is '
              'endpoint cwnd or advertised rwnd.', '']
    lines += ['', 'Evidence interpretation: high sustained completed credit-blocked time plus unconfirmed high water at the '
              'configured delivery bound supports a credit-window bottleneck hypothesis. A transient maximum alone does not '
              'establish time at the bound. Queue-full counts distinguish local admission events but are not durations. '
              'Transport prefix/body/flush means and cumulative maxima identify observed suspension, not its underlying '
              'kernel/network cause. A causal verdict requires matched interventions; these observations do not themselves '
              f'prove that a larger bound attains {target} Mbps.', '',
              'Baseline comparisons retain original source/binary identity and each integrity classification. Even matching '
              'plan fields do not make independent unseeded loss draws or profile-enabled binary changes a controlled '
              'profiling-overhead experiment.', '']
    return '\n'.join(lines)


def analyze(case_paths, output, baseline_report=None, config=accounting.DEFAULT_CONFIG,
            staged_native_max_bytes=DEFAULT_STAGED_NATIVE_MAX_BYTES,
            baseline_local_queue_packets=DEFAULT_BASELINE_LOCAL_QUEUE_PACKETS):
    require(0 < len(case_paths) <= MAX_CASES and all(d.is_dir() for d in case_paths), 'invalid case directories')
    require(len({d.name for d in case_paths}) == len(case_paths), 'duplicate case basename')
    require(output.resolve() not in {d.resolve() for d in case_paths}, 'report output must not replace an input case')
    inputs, manifest = accounting.Inputs(), {}
    results = [accounting.audit_case(inputs, d.resolve(), config=config) for d in case_paths]
    metrics = [r for v in results for r in v['cases']]
    baseline = []
    baseline_profile_intervals = {}
    if baseline_report:
        raw = read(baseline_report / 'cases.csv', manifest)
        baseline = list(csv.DictReader(raw.decode().splitlines()))
        require(len(baseline) <= 256, 'baseline row bound')
        profile_path = baseline_report / 'profiles.csv'
        if profile_path.exists():
            previous_profiles = list(csv.DictReader(read(profile_path, manifest).decode().splitlines()))
            require(len(previous_profiles) <= 64, 'baseline profile row bound')
            for r in previous_profiles:
                baseline_profile_intervals.setdefault(r['case'], set()).add(r.get('requested_profile_interval_ms', 'unobserved'))
    summaries, intervals, timings, highs, cpu, comparisons, values_rows, mode_rows = [], [], [], [], [], [], [], []
    executed_schema_sources = {}
    total_profiles = 0
    for directory, audited in zip(case_paths, results):
        case = directory.name
        receipt = strict_json(read(directory / 'receipt.json', manifest))
        build = strict_json(read(directory / 'build-receipt.json', manifest))
        executed_schema_sources[case] = {k: v for k, v in build.get('source_sha256_before', {}).items() if k in SCHEMA_SOURCES}
        cpu.extend(process_cpu(receipt, case))
        parsed_streams = {}
        for side in ['a', 'b']:
            try:
                samples = parse_profiles(read(directory / (side + '-daemon.log'), manifest))
                parsed_streams[side] = samples
                total_profiles += len(samples)
                require(total_profiles <= MAX_TOTAL_PROFILES, 'total profile count bound')
                summary, rows, stages, water = analyze_stream(samples, case, side)
                for entry in samples:
                    event = entry['snapshot']
                    if event['schema'] == 2:
                        values_rows.append({'case': case, 'endpoint': side, 'log_line': entry['line'],
                                            'seconds_since_profile_start': event['elapsed_nanos'] / 1e9, **event['values'],
                                            'meaning': 'current non-atomic gauges; enabled0 is legacy, no inferred historical '
                                                       'gauges; target shrink does not revoke debt'})
                summary.update(requested_profile_interval_ms=receipt.get('plan', {}).get('runtime_profile_interval_ms', 0),
                               effective_cli_json=json.dumps(receipt.get('effective_cli', [])),
                               integrity_classification=audited['base']['classification'],
                               forward_performance=audited['cases'][0]['performance_status'])
                summaries.append(summary)
                intervals.extend(rows)
                timings.extend(stages)
                highs.extend(water)
            except Exception as error:
                summaries.append({'case': case, 'endpoint': side, 'observed': False, 'error': str(error)})
        witness = {'case': case, **delivery_witness(receipt, parsed_streams, staged_native_max_bytes,
                                                    baseline_local_queue_packets)}
        mode_rows.append(witness)
        for row in audited['cases']:
            row.update(requested_delivery_window=witness['requested_delivery_window'], policy_witness=witness['policy_witness'],
                       requested_profile_interval_ms=receipt.get('plan', {}).get('runtime_profile_interval_ms', 0))
            keys = ['profile', 'path', 'duplex', 'flows', 'family', 'one_way_delay_ms', 'loss_percent_per_direction', 'direction']
            matches = [r for r in baseline if all(str(r.get(k, '')) == str(row.get(k, '')) for k in keys)]
            comparison = {'case': case, 'direction': row['direction'], 'profile_enabled_integrity': row['classification'],
                          'profile_enabled_goodput_mbps': row.get('accepted_goodput_mbps'),
                          'performance_status': row['performance_status'], 'matched_baseline_count': len(matches),
                          'note': 'separate unseeded observations; binary/config/workload differences and profiling overhead '
                                  'are confounded; not causal overhead estimate'}
            if len(matches) == 1:
                prior = matches[0]
                baseline_intervals = sorted(baseline_profile_intervals.get(prior['case'], {'unobserved'}))
                comparison.update(baseline_profile_interval_ms=','.join(baseline_intervals),
                                  current_profile_interval_ms=row['requested_profile_interval_ms'],
                                  same_observed_profile_interval=baseline_intervals == [str(row['requested_profile_interval_ms'])],
                                  baseline_case=prior['case'], baseline_integrity=prior['classification'],
                                  baseline_goodput_mbps=prior.get('accepted_goodput_mbps'),
                                  same_binary_sha256=prior.get('binary_sha256') == row.get('binary_sha256'),
                                  baseline_binary_sha256=prior.get('binary_sha256'), profile_binary_sha256=row.get('binary_sha256'))
                if prior.get('accepted_goodput_mbps') and row.get('accepted_goodput_mbps') is not None:
                    comparison['goodput_difference_mbps'] = row['accepted_goodput_mbps'] - float(prior['accepted_goodput_mbps'])
            comparisons.append(comparison)
    output.mkdir(parents=True, exist_ok=False)
    tables = {'cases': metrics, 'profiles': summaries, 'profile_intervals': intervals, 'stage_timings': timings,
              'high_water': highs, 'process_cpu': cpu, 'baseline_comparison': comparisons, 'delivery_values': values_rows,
              'mode_audit': mode_rows}
    for name in OUTPUT_TABLES:
        write_csv(output / (name + '.csv'), tables[name])
    text = report_text(summaries, timings, mode_rows, config)
    (output / 'report.md').write_text(text)
    (output / 'report.html').write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Runtime profile observations</title>'
        '<style>body{font:15px system-ui;margin:2rem}pre{white-space:pre-wrap;line-height:1.5}</style>'
        '<p>CSV exports: ' + ' · '.join('<a href="' + name + '.csv">' + name + '</a>' for name in OUTPUT_TABLES)
        + '</p><pre>' + html.escape(text) + '</pre></html>')
    out = {'analyzer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           'accounting_sha256': hashlib.sha256(Path(accounting.__file__).read_bytes()).hexdigest(),
           'inputs': {**inputs.manifest, **manifest},
           'executed_schema_build_sources': executed_schema_sources,
           'current_live_reference_only_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                                  for name in SCHEMA_SOURCES if (ROOT / name).exists()},
           'case_count': len(case_paths), 'observed_streams': sum(bool(r.get('observed')) for r in summaries),
           'policy_bounds': {'staged_native_max_bytes': staged_native_max_bytes,
                             'baseline_local_queue_packets': baseline_local_queue_packets},
           'bounds': {'file_bytes': MAX_FILE, 'log_line_bytes': MAX_LINE, 'profiles_per_stream': MAX_SNAPSHOTS,
                      'total_profiles': MAX_TOTAL_PROFILES, 'cases': MAX_CASES, 'total_input_bytes': MAX_TOTAL_INPUT}}
    (output / 'input_manifest.json').write_text(json.dumps(out, indent=2) + '\n')
    return {'output': str(output.resolve()), 'observed_streams': out['observed_streams']}


# ---------------------------------------------------------------------------
# Plotting of an analyze output directory.


def plot(report_dir, output):
    tables = {name: accounting.read_csv(report_dir / (name + '.csv'), PLOT_MAX_FILE, PLOT_MAX_ROWS) for name in PLOT_TABLES}
    cases = sorted({r['case'] for r in tables['cases']})
    require(0 < len(cases) <= MAX_CASES, 'case bound')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size': 9, 'svg.fonttype': 'none'})
    output.mkdir(parents=True, exist_ok=False)
    sections = ['<!doctype html><html lang="en"><meta charset="utf-8"><title>Runtime profiling</title>',
                '<style>body{font:15px system-ui;max-width:1150px;margin:2rem auto;padding:1rem}img{width:100%}</style>',
                '<h1>Runtime profile time series</h1><p>Each point uses elapsed time since runtime profiling was enabled. '
                'There is no probe clock anchor; these figures include warmup/drain and are not exact-window metrics. '
                'Timing is elapsed, including suspension/preemption, and is not CPU. Concurrent stages must not be added. '
                'Missing observations are not filled. Byte budget targets/debt are not native TCP cwnd or advertised rwnd.</p>']
    for name in tables:
        sections.append('<a href="' + html.escape(os.path.relpath(report_dir / (name + '.csv'), output), quote=True) + '">'
                        + name + '.csv</a> · ')
    output_hashes = {}

    def save(fig, stem):
        fig.tight_layout(rect=(0, .025, 1, .93))
        for suffix in ['.png', '.svg']:
            path = output / (stem + suffix)
            fig.savefig(path, dpi=120, metadata={'Creator': 'native_throughput_profiles.py plot'})
            output_hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        plt.close(fig)
        sections.append('<p><a href="' + stem + '.svg"><img src="' + stem + '.png" alt="' + stem + '"></a></p>')

    for i, case in enumerate(cases):
        forward = next(r for r in tables['cases'] if r['case'] == case and r['direction'] == 'a_to_b')
        label = case + ' [' + forward['classification'].upper() + '; ' + forward['performance_status'].upper() + ']'
        sections.append('<h2>' + html.escape(label) + '</h2>')
        fig, axes = plt.subplots(2, 1, figsize=(11, 6), sharex=True)
        observed = False
        for side, color in [('a', '#1464ad'), ('b', '#b64222')]:
            rows = [r for r in tables['profile_intervals'] if r['case'] == case and r['endpoint'] == side]
            if rows:
                observed = True
                x = [float(r['seconds_since_profile_start']) for r in rows]
                axes[0].plot(x, [float(r['credit_blocked_elapsed_ratio_cumulative'])
                                 if r.get('credit_blocked_elapsed_ratio_cumulative') else math.nan for r in rows],
                             '.', markersize=3, color=color, label='Endpoint ' + side.upper())
                # Cumulative maxima explicitly do not represent current occupancy.
                for name, marker in [('unconfirmed_native_packets', '.'), ('outgoing_queue_records', 'x')]:
                    h = [r for r in tables['high_water'] if r['case'] == case and r['endpoint'] == side and r['name'] == name]
                    axes[1].plot([float(r['seconds_since_profile_start']) for r in h],
                                 [float(r['maximum_since_profile_start']) for r in h], marker, markersize=3, color=color,
                                 label=side.upper() + ' ' + name + ' high water')
        if observed:
            axes[0].set_ylabel('Credit-blocked / profile elapsed\n(cumulative; not CPU)')
            axes[1].set_ylabel('Lifetime high water (records)\n(not current occupancy)')
            axes[1].set_xlabel('Seconds since profiling start; parent clock alignment unobserved')
            for ax in axes:
                ax.legend(fontsize=7)
                ax.grid(alpha=.25)
            fig.suptitle(label + ' — retained-credit wait and separate local queue maxima')
            save(fig, 'case-' + str(i + 1).zfill(3) + '-wait')
        else:
            plt.close(fig)
            sections.append('<p>Runtime profile unobserved.</p>')
        values = [r for r in tables['delivery_values'] if r['case'] == case and r.get('delivery_enabled') == '1']
        if values:
            fig, axes = plt.subplots(2, 1, figsize=(11, 6), sharex=True)
            for ax, side in zip(axes, ['a', 'b']):
                rows = [r for r in values if r['endpoint'] == side]
                for field, color in [('delivery_target_bytes', '#20802a'), ('delivery_outstanding_bytes', '#1464ad'),
                                     ('delivery_native_pending_bytes', '#a45c18'), ('delivery_staged_native_bytes', '#8c3794')]:
                    ax.plot([float(r['seconds_since_profile_start']) for r in rows], [float(r[field]) / 1024 for r in rows],
                            '.', markersize=3, color=color, label=field)
                ax.set_ylabel('Endpoint ' + side.upper() + ' delivery bytes (KiB)')
                ax.grid(alpha=.25)
                ax.legend(fontsize=7)
            axes[-1].set_xlabel('Original runtime profile elapsed seconds; sampled gauges, no TCP-window claim')
            fig.suptitle(label + ' — BDP delivery budget/debt and pending ownership; local queue independent')
            save(fig, 'case-' + str(i + 1).zfill(3) + '-delivery-bytes')
            fig, axes = plt.subplots(2, 1, figsize=(11, 6), sharex=True)
            for ax, side in zip(axes, ['a', 'b']):
                rows = [r for r in values if r['endpoint'] == side]
                for fresh, color in [('1', '#1464ad'), ('0', '#b64222')]:
                    g = [r for r in rows if r['delivery_service_rtt_fresh'] == fresh and int(r['delivery_service_rtt_micros']) > 0]
                    ax.plot([float(r['seconds_since_profile_start']) for r in g],
                            [float(r['delivery_service_rtt_micros']) / 1000 for r in g], '.', markersize=3, color=color,
                            label='fresh' if fresh == '1' else 'stale retained sample')
                ax.set_ylabel('Endpoint ' + side.upper() + ' service RTT EWMA ms')
                ax.grid(alpha=.25)
                if ax.lines:
                    ax.legend(fontsize=7)
            axes[-1].set_xlabel('Seconds since profiling start; actual flush→feedback service, not endpoint TCP RTT')
            fig.suptitle(label + ' — delivery service observations; zero/missing sample omitted')
            save(fig, 'case-' + str(i + 1).zfill(3) + '-delivery-service')
        else:
            sections.append('<p>Selected BDP byte gauges unobserved or disabled; no values inferred from record count or MTU.</p>')
    (output / 'index.html').write_text('\n'.join(sections) + '</html>')
    (output / 'plot_manifest.json').write_text(json.dumps({
        'plotter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'input_sha256': {name: hashlib.sha256((report_dir / (name + '.csv')).read_bytes()).hexdigest() for name in tables},
        'output_sha256': output_hashes}, indent=2) + '\n')
    return {'output': str(output.resolve()), 'cases': len(cases)}


def parse(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    audit = commands.add_parser('analyze', help='parse runtime profiles of case directories into fresh tables')
    audit.add_argument('cases', nargs='+', type=Path, help='finalized native_throughput.py case directories with daemon logs')
    audit.add_argument('--output', required=True, type=Path, help='fresh report directory')
    audit.add_argument('--baseline-report', type=Path,
                       help='optional earlier native_throughput_analysis.py/profile analyze directory for matched-plan rows')
    audit.add_argument('--staged-native-max-bytes', type=int, default=DEFAULT_STAGED_NATIVE_MAX_BYTES,
                       help='BDP witness: maximum staged native source bytes (default: %(default)s)')
    audit.add_argument('--baseline-local-queue-packets', type=int, default=DEFAULT_BASELINE_LOCAL_QUEUE_PACKETS,
                       help='BDP witness: required unchanged local queue packets (default: %(default)s)')
    accounting.add_config_arguments(audit)
    figures = commands.add_parser('plot', help='render PNG/SVG figures from an analyze output directory (needs matplotlib)')
    figures.add_argument('--report', required=True, type=Path, help='an analyze output directory')
    figures.add_argument('--output', required=True, type=Path, help='fresh figure directory')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse(argv)
    if args.command == 'analyze':
        require(args.staged_native_max_bytes >= 0 and args.baseline_local_queue_packets > 0, 'invalid witness bounds')
        result = analyze(args.cases, args.output, args.baseline_report, accounting.config_from_args(args),
                         args.staged_native_max_bytes, args.baseline_local_queue_packets)
    else:
        result = plot(args.report.resolve(), args.output)
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
