#!/usr/bin/env python3
"""Summarize saved Common native matrix receipts without running any workload.

Repeated --results directories retain every attempt. Each phase displays its
newest explicitly selected attempt, never its fastest or most successful one.
Independent sessions remain explicit; cumulative metrics never merge them.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import time

try:
    from .common_native_observe import validate_wire_metrics
except ImportError:
    from common_native_observe import validate_wire_metrics

CARRIERS = ('udp', 'raw', 'tls', 'quic')
PHASES = ('forward', 'reverse', 'simultaneous')
DIRECTIONS = {'a_to_b': ('a', 'b'), 'b_to_a': ('b', 'a')}
MAX_JSON = 32 * 1024 * 1024
MAX_LOG = 32 * 1024 * 1024
MAX_DIAGNOSTICS = 64
FAILURE_PREFIX = 'Common runtime failure: '


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path, provenance):
    require(path.is_file() and not path.is_symlink(), 'regular input required: ' + str(path))
    with path.open('rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON, 'JSON input exceeds report bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    provenance[str(path.resolve())] = hashlib.sha256(raw).hexdigest()
    return value


def child_path(directory, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(), 'relative receipt path required')
    path = directory / relative
    require('..' not in Path(relative).parts and path.resolve().is_relative_to(directory.resolve()), 'receipt escaped case directory')
    return path


def active(phase, direction):
    return phase == 'simultaneous' or (phase == 'forward') == (direction == 'a_to_b')


def unsigned(value):
    return type(value) is int and value >= 0


def cause_category(text, carrier):
    """Classify printed observations, never infer an initiating peer or root cause."""
    if 'RetryExhausted' in text:
        return 'algorithm_retry_exhausted'
    if 'whole-message control error: Expired' in text:
        return 'control_expired'
    if 'authenticated liveness challenge expired' in text:
        return 'liveness_expired'
    if 'retained TLS original record cap expired' in text:
        return 'tls_record_cap_expired'
    if 'original generic transaction custody deadline' in text:
        return 'transaction_custody_expired'
    if 'common record Bank:' in text and 'Expired' in text:
        return 'algorithm_expired'
    if re.fullmatch(r'Custom \{ kind: TimedOut, error: Expired \}', text):
        return 'raw_expired_unqualified' if carrier == 'raw' else 'expired_unqualified'
    if 'ConnectionReset' in text:
        return 'connection_reset'
    if 'UnexpectedEof' in text:
        return 'unexpected_eof'
    if 'error: Transport' in text:
        return 'transport_error'
    return 'other_runtime_failure'


def terminal_evidence(case, directory, carrier, provenance):
    result = {'scope': 'case runtime; daemon lines have no phase timestamp or cross-peer causal ordering',
              'root_cause_inference': None, 'daemon_logs': [], 'runtime_failures': [],
              'periodic_terminal_observations': [], 'fallback_terminal_observations': []}
    for side in ('a', 'b'):
        path = directory / ('daemon-' + side + '.log')
        saved = {'side': side, 'path': str(path.resolve()), 'status': 'unavailable'}
        result['daemon_logs'].append(saved)
        if not path.is_file():
            continue
        try:
            require(not path.is_symlink(), 'regular daemon log required')
            with path.open('rb') as stream:
                raw = stream.read(MAX_LOG + 1)
            require(len(raw) <= MAX_LOG, 'daemon log exceeds bounded report scan')
            digest = hashlib.sha256(raw).hexdigest()
            provenance[str(path.resolve())] = digest
            saved.update(status='read', sha256=digest, bytes=len(raw), diagnostic_lines=0)
            for number, line in enumerate(raw.splitlines(), 1):
                if FAILURE_PREFIX.encode() not in line:
                    continue
                saved['diagnostic_lines'] += 1
                if saved['diagnostic_lines'] > MAX_DIAGNOSTICS:
                    continue
                text = line.decode('utf-8', errors='replace').split(FAILURE_PREFIX, 1)[1]
                match = re.fullmatch(r'role=(\w+) kind=(\w+) cause=(.*)', text)
                # Keep exact small diagnostics, not arbitrary large debug payloads.
                retained = text[:4096]
                cause = match[3] if match else retained
                result['runtime_failures'].append({
                    'side': side, 'log': str(path.resolve()), 'log_sha256': digest,
                    'line': number, 'scope': 'case', 'phase': None,
                    'role': match[1] if match else None, 'io_kind': match[2] if match else None,
                    'cause': cause[:4096], 'diagnostic': retained,
                    'truncated': len(text) > 4096,
                    'category': cause_category(cause, carrier), 'evidence': 'observed_runtime_diagnostic'})
            saved['omitted_diagnostic_lines'] = max(0, saved['diagnostic_lines'] - MAX_DIAGNOSTICS)
        except (ValueError, OSError) as error:
            saved.update(status='unavailable', reason=str(error))
    # Collapse repeated polls of the same terminal state; retain its first actual
    # phase/sample/time and repetition count, without importing the config DTO.
    observed = {}
    for phase in case.get('phases', []):
        for index, sample in enumerate(phase.get('status_samples', [])):
            for side in ('a', 'b'):
                response = sample.get('endpoints', {}).get(side, {})
                state = response.get('state') or {}
                common = state.get('common') or {}
                terminal, outcome = common.get('terminal'), common.get('service_terminal')
                if terminal is None and outcome is None and state.get('phase') != 'failed':
                    continue
                terminal = terminal if isinstance(terminal, str) else None
                outcome = outcome if isinstance(outcome, str) else None
                key = (phase.get('phase'), side, state.get('phase'), terminal, outcome)
                if key not in observed:
                    observed[key] = {'phase': phase.get('phase'), 'side': side,
                                     'sample_index': index, 'first_observed_at_ns': sample.get('at_ns'),
                                     'state_phase': state.get('phase'), 'terminal': terminal,
                                     'service_terminal': outcome, 'observations': 0,
                                     'evidence': 'observed_periodic_terminal_dto',
                                     'category': 'terminal_dto_unqualified'}
                observed[key]['observations'] += 1
                observed[key]['last_observed_at_ns'] = sample.get('at_ns')
    result['periodic_terminal_observations'] = list(observed.values())
    diagnostic_sides = {item['side'] for item in result['runtime_failures']}
    result['fallback_terminal_observations'] = [item for item in observed.values()
                                               if item['side'] not in diagnostic_sides]
    return result


def failure_summary(rows):
    """Count case/side observations once, never multiply them by selected phases."""
    scopes = {}
    for name in ('selected_case_sessions', 'all_attempts'):
        counts, fallback, missing = Counter(), Counter(), 0
        sessions = 0
        for row in rows:
            indices = range(len(row['attempts'])) if name == 'all_attempts' else sorted({
                index for index in row['phase_selection'].values() if index is not None})
            for index in indices:
                value = row['attempts'][index]
                sessions += 1
                evidence = value['terminal_evidence']
                categories = {(item['side'], item['category']) for item in evidence['runtime_failures']}
                counts.update(category for _, category in categories)
                fallback.update({(item['side'], item['terminal'] or item['service_terminal'] or item['state_phase'])
                                 for item in evidence['fallback_terminal_observations']})
                if value['status'] != 'passed' and not categories and not evidence['fallback_terminal_observations']:
                    missing += 1
        scopes[name] = {'case_sessions': sessions, 'observed_runtime_categories': dict(sorted(counts.items())),
                        'fallback_dto_categories': {},
                        'failed_sessions_without_terminal_observation': missing}
        dto_counts = Counter()
        for (_, outcome), count in fallback.items():
            dto_counts[outcome] += count
        scopes[name]['fallback_dto_categories'] = dict(sorted(dto_counts.items()))
    return {'count_unit': 'distinct case session / side / observed category; categories are not mutually exclusive and do not establish root cause',
            'root_cause_inferences': [], **scopes}


def metric_summary(value):
    return {'accepted_records': value['samples'], 'total_bytes': value['total_bytes'],
            'mean_bytes_per_accepted_record': value['total_bytes'] / value['samples'] if value['samples'] else None,
            'p50_bytes': value['p50'], 'p99_bytes': value['p99']}


def wire_metrics(case, directory, carrier, provenance):
    result = {'scope': 'cumulative per-runtime, all executed phases including warmup and drain; not a phase-window metric',
              'excludes': ['bootstrap', 'management', 'raw carrier control', 'outer TLS/QUIC/IP headers'],
              'codec_unattributed_bytes': None, 'total_encapsulation_overhead_p99_bytes': None,
              'tls_quic_outer_overhead_p99_bytes': None, 'directions': {}}
    pids = {}
    for command in case.get('commands', []):
        for side in ('a', 'b'):
            if command.get('log') == 'daemon-' + side + '.log' and unsigned(command.get('pid')):
                require(side not in pids, 'ambiguous actual daemon PID')
                pids[side] = command['pid']
    files = case.get('wire_metrics', {}).get('files', [])
    for direction, (sender, _) in DIRECTIONS.items():
        observed = {'status': 'unavailable', 'reason': 'no unique actual daemon report'}
        result['directions'][direction] = observed
        matches = [name for name in files if re.fullmatch(r'wire\.' + str(pids.get(sender)) + r'\.[0-9]+\.json', Path(name).name)]
        if len(matches) != 1:
            continue
        try:
            path = child_path(directory, matches[0])
            value = read_json(path, provenance)
            expected = case.get('wire_metrics', {}).get('sha256', {}).get(path.name)
            require(expected == provenance[str(path.resolve())], 'wire report differs from saved case hash')
            validation = validate_wire_metrics(value, carrier)
            observed.update(status='validated', reason=None, pid=pids[sender], receipt=str(path.resolve()),
                            receipt_sha256=expected, boundary=validation['boundary'],
                            accepted_classes=value['accepted_classes'], diagnostic_heap_bytes=value['diagnostic_heap_bytes'])
            for key in ('algorithm_bytes', 'final_record_bytes', 'record_overhead_bytes'):
                observed[key] = metric_summary(value[key])
        except (ValueError, OSError, KeyError, TypeError) as error:
            observed.update(status='invalid_observation', reason=str(error))
    return result


def capture_value(phase, surface, direction):
    entry = phase.get('captures', {}).get(surface, {})
    summary, counters = entry.get('summary', {}), entry.get('counters', {})
    sample = summary.get('sample_window')
    if (entry.get('status') == 'tool_failure' or entry.get('returncode') != 0
            or summary.get('status') != 'parsed' or counters.get('dropped') != 0
            or counters.get('captured') != summary.get('captured_packets')
            or not sample or not entry.get('sha256')):
        return {'status': 'unavailable', 'bytes': None, 'reason': entry.get('error', 'capture accounting not qualified')}
    value = sample.get(direction, {})
    histogram = value.get('histogram_ip_packet_bytes', {})
    try:
        require(all(re.fullmatch(r'[0-9]+', size) and unsigned(count) for size, count in histogram.items()), 'invalid IP histogram')
        require(sum(histogram.values()) == value['packets']
                and sum(int(size) * count for size, count in histogram.items()) == value['ip_bytes'], 'IP histogram totals differ')
        require(len(sample['wall_ns']) == 2 and sample['wall_ns'][1] - sample['wall_ns'][0] == 10_000_000_000, 'capture is not the exact ten-second sample')
    except (ValueError, KeyError, TypeError) as error:
        return {'status': 'invalid_observation', 'bytes': None, 'reason': str(error)}
    return {'status': 'validated_saved_capture', 'bytes': value['ip_bytes'], 'packets': value['packets'],
            'wall_ns': sample['wall_ns'], 'receipt_pcap': entry.get('pcap'), 'saved_pcap_sha256': entry['sha256'],
            'hash_scope': 'pcap hash preserved from runner receipt; report does not reread the large pcap',
            'packet_size_p99_bytes': value.get('p99_ip_packet_bytes')}


def phase_result(case, directory, name, provenance):
    matches = [phase for phase in case.get('phases', []) if phase.get('phase') == name]
    require(len(matches) <= 1, 'duplicate phase receipt')
    phase = matches[0] if matches else {'status': 'not_run', 'reason': case.get('error') or 'phase absent from saved attempt'}
    finalized = unsigned(case.get('completed_wall_ns'))
    result = {'phase': name, 'status': phase.get('status', 'unknown'),
              'reason': phase.get('error') or phase.get('reason'), 'directions': {}}
    probes = {}
    for side in ('a', 'b'):
        path = directory / name / (side + '.json')
        if path.is_file():
            try:
                probes[side] = read_json(path, provenance)
            except (ValueError, OSError) as error:
                probes[side] = {'status': 'tool_failure', 'error': str(error)}
    for direction, (sender, receiver) in DIRECTIONS.items():
        running = active(name, direction)
        observed = phase.get('throughput_observed', {}).get(direction, {})
        declared = phase.get('throughput', {}).get(direction, {})
        probe = probes.get(receiver, {})
        clock = probe.get('clock') or {}
        measured = observed.get('receiver_unique_sample_bytes')
        if measured is None and isinstance(probe.get('flows'), list):
            counts = [flow.get('measured') for flow in probe['flows']]
            measured = sum(counts) if all(unsigned(count) for count in counts) else None
        if measured is None:
            measured = declared.get('receiver_unique_sample_bytes')
        complete = observed.get('sample_window_completed') is True or (
            unsigned(clock.get('end_ns')) and unsigned(probe.get('completed_ns')) and probe['completed_ns'] >= clock['end_ns'])
        valid = (finalized and phase.get('status') == 'passed' and unsigned(declared.get('receiver_unique_sample_bytes'))
                 and declared.get('sample_seconds') == 10 and declared['receiver_unique_sample_bytes'] == measured
                 and (measured > 0 if running else measured == 0))
        rate = measured * 8 / 10_000_000 if unsigned(measured) and (valid or complete) else None
        data = {'active_application_direction': running, 'sample_seconds': 10,
                'valid_goodput_mbit_s': rate if valid else None,
                'invalid_partial_observation': None if valid else {
                    'receiver_unique_sample_bytes': measured, 'full_sample_window_completed': complete,
                    'observed_goodput_mbit_s': rate, 'reason': result['reason'] or probe.get('error') or 'sample not qualified'},
                'receiver_unique_sample_bytes': measured if valid else None,
                'wan_sender_ip': capture_value(phase, sender + '_wan', direction),
                'native_sender_ip': capture_value(phase, sender + '_native', direction),
                'native_receiver_ip': capture_value(phase, receiver + '_native', direction),
                'wan_sent_ip_bytes_per_unique_application_byte': None,
                'wan_sent_ip_bytes_per_delivered_native_ip_byte': None}
        wan, native = data['wan_sender_ip'], data['native_receiver_ip']
        if valid and running and measured and wan['bytes'] is not None:
            data['wan_sent_ip_bytes_per_unique_application_byte'] = wan['bytes'] / measured
            if native['bytes'] and wan['wall_ns'] == native['wall_ns']:
                data['wan_sent_ip_bytes_per_delivered_native_ip_byte'] = wan['bytes'] / native['bytes']
        result['directions'][direction] = data
    return result


def attempt(row, path, run, provenance):
    case = read_json(path, provenance)
    require(case.get('id') == row['id'] and case.get('row', {}).get('expected_descriptor_hex') == row.get('expected_descriptor_hex'), 'case identity/configuration differs from manifest')
    result = {'receipt': str(path.resolve()), 'receipt_sha256': provenance[str(path.resolve())],
              'run_directory': str(path.parent.parent.resolve()), 'status': case.get('status', 'unknown'),
              'stage': case.get('stage'), 'reason': case.get('error'),
              'started_wall_ns': case.get('started_wall_ns', 0), 'completed_wall_ns': case.get('completed_wall_ns'),
              'binary_sha256': run.get('binary_sha256'), 'manifest_sha256': run.get('manifest_sha256'),
              'runner_source_sha256': run.get('runner_source_sha256'), 'input_sha256': run.get('input_sha256'),
              'network': run.get('network'), 'cleanup': case.get('cleanup'),
              'selected_phases': case.get('selected_phases', [phase['phase'] for phase in case.get('phases', [])]),
              'phases': [phase_result(case, path.parent, phase, provenance) for phase in PHASES],
              'common_record_metrics': wire_metrics(case, path.parent, row['carrier'], provenance),
              'terminal_evidence': terminal_evidence(case, path.parent, row['carrier'], provenance)}
    if result['reason'] is None:
        result['reason'] = next((phase['reason'] for phase in result['phases'] if phase['status'] not in ('passed', 'not_run')), None)
    return result


def build_report(manifest_path, directories):
    provenance = {}
    manifest = read_json(manifest_path, provenance)
    rows = manifest.get('rows', [])
    require(0 < len(rows) <= 256 and len({row['id'] for row in rows}) == len(rows), 'bounded unique manifest rows required')
    runs = []
    for directory in directories:
        path = directory / 'results.json'
        runs.append((directory, read_json(path, provenance)))
    combinations = []
    for row in rows:
        carrier = row['carrier']
        require(carrier in CARRIERS and row['id'].endswith('-' + carrier), 'unknown matrix carrier/ID')
        attempts = [attempt(row, directory / row['id'] / 'result.json', run, provenance)
                    for directory, run in runs if (directory / row['id'] / 'result.json').is_file()]
        attempts.sort(key=lambda value: (value['started_wall_ns'], value['receipt']))
        phase_selection, outcomes = {}, []
        for name in PHASES:
            candidates = [index for index, value in enumerate(attempts) if name in value['selected_phases']]
            index = candidates[-1] if candidates else None
            phase_selection[name] = index
            if index is None:
                outcomes.append({'phase': name, 'status': 'unsupported' if row.get('status') == 'unsupported' else 'not_run',
                                 'reason': row.get('reason', 'no saved attempt explicitly requested this phase'), 'attempt_index': None})
            else:
                value = attempts[index]
                phase = next(phase for phase in value['phases'] if phase['phase'] == name)
                outcomes.append({'phase': name, 'status': phase['status'], 'reason': phase['reason'],
                                 'attempt_index': index, 'case_receipt': value['receipt'],
                                 'binary_sha256': value['binary_sha256']})
        status = next((value['status'] for value in outcomes if value['status'] not in ('passed', 'not_run')), None)
        if status is None:
            selected_indices = {index for index in phase_selection.values() if index is not None}
            status = next((attempts[index]['status'] for index in sorted(selected_indices, reverse=True)
                           if attempts[index]['status'] != 'passed'), None)
        if status is None:
            status = 'passed' if all(value['status'] == 'passed' for value in outcomes) else 'incomplete' if any(value['status'] == 'passed' for value in outcomes) else 'not_run'
        combinations.append({'id': row['id'], 'algorithm_variant': row['id'][:-(len(carrier) + 1)],
                             'algorithm': row.get('algorithm'), 'variant': row.get('variant'), 'carrier': carrier,
                             'planned_status': row.get('status'), 'planned_reason': row.get('reason'),
                             'descriptor_digest_hex': row.get('descriptor_digest_hex'),
                             'parameters': row.get('parameters'), 'attempts': attempts,
                             'phase_outcomes': outcomes,
                             'phase_selection': phase_selection,
                             'independent_phase_sessions': len({index for index in phase_selection.values() if index is not None}) > 1,
                             'selected_attempt': len(attempts) - 1 if attempts else None,
                             'latest_case_status': attempts[-1]['status'] if attempts else None,
                             'status': status})
    return {'schema': 1, 'generated_wall_ns': time.time_ns(), 'manifest': str(manifest_path.resolve()),
            'input_sha256': provenance, 'combination_count': len(combinations),
            'algorithm_variant_count': len({row['algorithm_variant'] for row in combinations}),
            'status_counts': dict(Counter(row['status'] for row in combinations)),
            'failure_summary': failure_summary(combinations),
            'selection': 'latest started saved attempt independently per explicitly requested phase; all attempts retained, never fastest/best; independent sessions keep separate case/binary/receipt provenance and cumulative metrics',
            'definitions': {
                'goodput': 'unique kernel TCP recv application bytes during the shared ten-second monotonic window; a valid rate requires a finalized passing phase with matched streams/hash/EOF in the runner',
                'partial': 'failed/incomplete sample bytes are retained separately; an observed rate is shown only when the full configured window elapsed, and never qualifies as valid throughput',
                'records': 'per-direction cumulative accepted Common algorithm/final record lengths and their exact difference; includes warmup, all executed phases, source retransmissions/copies, repairs and recovery feedback; excludes management/bootstrap/raw control and outer transport',
                'capture': 'sender WAN egress before qdisc, sender native TUN and peer native TUN ingress, each separate; IPv4 total_length includes TCP/IP headers, ACKs and retransmissions; no duplicate summation across surfaces',
                'ratios': 'same-window aggregate sender WAN IP bytes / unique received application bytes or peer native delivered IP bytes; active valid direction only; includes reverse-flow ACK/control sharing that direction and packets in flight across window boundaries, not packet-matched encapsulation overhead',
                'unavailable': 'codec attribution, total encapsulation overhead p99 and TLS/QUIC outer overhead p99 remain null; IP packet size p99 and constant Records tag overhead are not substitutes',
                'terminal_causes': 'daemon diagnostics retain the observed error, side, line and log hash; they are case-wide, without phase timestamps or causal ordering between peers. Periodic terminal DTOs retain their actual phase/sample/time as less specific fallback. Category names classify observations, not root causes; raw Expired remains unqualified and TLS record cap does not prove a send-side failure. No config DTOs are copied',
                'provenance': 'JSON, daemon log and metrics input hashes recomputed; saved pcap hashes preserved without re-reading large captures; running attempts are snapshots and cannot qualify throughput'},
            'combinations': combinations}


def escape(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def number(value):
    return '—' if value is None else f'{value:.3f}'


def selected(row):
    return row['attempts'][row['selected_attempt']] if row['selected_attempt'] is not None else None


def selected_phases(row):
    for name in PHASES:
        index = row['phase_selection'][name]
        if index is not None:
            value = row['attempts'][index]
            yield value, next(phase for phase in value['phases'] if phase['phase'] == name)


def cause_label(evidence):
    observations = evidence['runtime_failures']
    if observations:
        return 'case diagnostics: ' + '; '.join(dict.fromkeys(
            item['side'] + ' ' + item['category'] for item in observations))
    fallback = evidence['fallback_terminal_observations']
    if fallback:
        return 'terminal DTO: ' + '; '.join(dict.fromkeys(
            item['side'] + ' ' + (item['terminal'] or item['service_terminal'] or item['state_phase'])
            for item in fallback))
    return None


def summary_cell(row):
    value = selected(row)
    if value is None:
        return escape(row['status'] + (': ' + row['planned_reason'] if row.get('planned_reason') else ''))
    phases = {phase['phase']: phase for _, phase in selected_phases(row)}
    def rate(phase, direction):
        return number(phases[phase]['directions'][direction]['valid_goodput_mbit_s']) if phase in phases else '—'
    text = f"F {rate('forward', 'a_to_b')}; R {rate('reverse', 'b_to_a')}; S {rate('simultaneous', 'a_to_b')}/{rate('simultaneous', 'b_to_a')}"
    failures = [phase['phase'] + ': ' + (phase['reason'] or phase['status']) for phase in row['phase_outcomes'] if phase['status'] != 'passed']
    text += '; ' + row['status']
    if row['independent_phase_sessions']:
        text += '; independent sessions'
    if failures or value['reason']:
        text += '; ' + (failures[0] if failures else value['reason'])[:160]
    causes = [cause_label(row['attempts'][index]['terminal_evidence']) for index in sorted({
        index for index in row['phase_selection'].values() if index is not None})]
    if any(causes):
        text += '; ' + ' / '.join(dict.fromkeys(cause for cause in causes if cause))
    return escape(text)


def markdown(report):
    rows = report['combinations']
    lines = ['# Common native matrix observations', '',
             f"Saved snapshot: {report['combination_count']} combinations, {report['algorithm_variant_count']} algorithm variants. Status counts: `{json.dumps(report['status_counts'], sort_keys=True)}`.", '',
             'F = forward, R = reverse, S = simultaneous forward/reverse. Rates are valid Mbit/s only; — means no qualified rate. Each phase uses its latest started explicitly requested attempt, without selecting successful retries. All attempts remain in report.json. Phases from independent sessions are labeled; they do not establish one continuous three-phase run.', '',
             '| Algorithm variant | UDP | Raw TCP-shaped | Maintained TLS | Native QUIC |',
             '|---|---|---|---|---|']
    variants = dict.fromkeys(row['algorithm_variant'] for row in rows)
    for variant in variants:
        group = {row['carrier']: row for row in rows if row['algorithm_variant'] == variant}
        lines.append('| ' + escape(variant) + ' | ' + ' | '.join(summary_cell(group[carrier]) if carrier in group else 'not in manifest' for carrier in CARRIERS) + ' |')
    lines += ['', '## Observed terminal failures', '',
              'Counts use distinct case session / side / category across the cases selected by phase. They do not count the same case again for forward/reverse/simultaneous. Multiple categories and both peers can describe one failed case; no initiating cause or cross-peer causal ordering is inferred. All-attempt counts and prior diagnostics remain in report.json.', '',
              '| Evidence | Observed category | Case-side count |', '|---|---|---:|']
    summary = report['failure_summary']['selected_case_sessions']
    for label, key in [('Runtime diagnostic', 'observed_runtime_categories'), ('Terminal DTO fallback', 'fallback_dto_categories')]:
        for category, count in summary[key].items():
            lines.append('| ' + label + ' | ' + escape(category) + ' | ' + str(count) + ' |')
    lines += ['', f"Failed/nonpassing case sessions without a saved terminal observation: {summary['failed_sessions_without_terminal_observation']}.", '',
              'The following are observed error strings, not established root causes. A daemon log covers its complete case runtime and has no phase timestamp; DTO rows are explicitly attributed to their sampled phase. Raw `Expired` alone does not identify its internal deadline. TLS record-cap expiry alone does not identify send versus receive.', '',
              '| Combination / case | Side / evidence | Observed terminal cause | Source / SHA256 |', '|---|---|---|---|']
    for row in rows:
        for index in sorted({index for index in row['phase_selection'].values() if index is not None}):
            value = row['attempts'][index]
            evidence = value['terminal_evidence']
            case_label = row['id'] + ' / ' + Path(value['run_directory']).name
            for item in evidence['runtime_failures']:
                lines.append('| ' + escape(case_label) + ' | ' + item['side'] + ' / runtime, case-wide | '
                             + escape(item['cause']) + (' [truncated]' if item['truncated'] else '')
                             + ' | [line ' + str(item['line']) + '](' + item['log'] + ') / `' + item['log_sha256'] + '` |')
            for item in evidence['fallback_terminal_observations']:
                detail = (item['terminal'] or 'unknown') + '; ' + (item['service_terminal'] or 'unknown')
                lines.append('| ' + escape(case_label) + ' | ' + item['side'] + ' / DTO ' + escape(item['phase'])
                             + ', sample ' + str(item['sample_index']) + ' | ' + escape(detail)
                             + ' | [case receipt](' + value['receipt'] + ') / `' + value['receipt_sha256'] + '` |')
    lines += ['', '## Measurement definitions', '']
    lines += ['- **' + key + ':** ' + text for key, text in report['definitions'].items()]
    lines += ['', '## Per-phase observations', '',
              'IP byte columns are separate capture surfaces. Partial rates never appear in the valid-rate column. Wire/application and wire/native ratios are aggregate same-window cost ratios, not overhead percentages.', '',
              '| Combination / phase / direction | Case session | Outcome | Valid Mbit/s | Invalid observed Mbit/s / bytes | WAN sent IP bytes | Native sent / delivered IP bytes | Wire/application | Wire/delivered native |',
              '|---|---|---|---:|---:|---:|---:|---:|---:|']
    for row in rows:
        for value, phase in selected_phases(row):
            for direction, data in phase['directions'].items():
                if not data['active_application_direction']:
                    continue
                partial = data['invalid_partial_observation'] or {}
                lines.append('| ' + escape(row['id'] + ' / ' + phase['phase'] + ' / ' + direction) + ' | ' + escape(Path(value['run_directory']).name) + ' | ' + escape(phase['status'])
                             + ' | ' + number(data['valid_goodput_mbit_s']) + ' | ' + number(partial.get('observed_goodput_mbit_s'))
                             + ' / ' + str(partial.get('receiver_unique_sample_bytes', '—')) + ' | ' + str(data['wan_sender_ip']['bytes'])
                             + ' | ' + str(data['native_sender_ip']['bytes']) + ' / ' + str(data['native_receiver_ip']['bytes'])
                             + ' | ' + number(data['wan_sent_ip_bytes_per_unique_application_byte'])
                             + ' | ' + number(data['wan_sent_ip_bytes_per_delivered_native_ip_byte']) + ' |')
    lines += ['', '## Cumulative inner Records measurements', '',
              'Each row covers one selected case runtime, not individual phase windows. Independent sessions are never merged. These measure the inner Records layer only. Codec/padding attribution, total encapsulation p99 and TLS/QUIC outer p99 remain unavailable.', '',
              '| Combination / sending direction | Case session | Actual boundary | Accepted records | Algorithm bytes mean / p99 | Final Records bytes mean / p99 | Records overhead bytes mean / p99 |',
              '|---|---|---|---:|---:|---:|---:|']
    for row in rows:
        for index in sorted({index for index in row['phase_selection'].values() if index is not None}):
            value = row['attempts'][index]
            session = escape(Path(value['run_directory']).name)
            for direction, metric in value['common_record_metrics']['directions'].items():
                if metric['status'] != 'validated':
                    lines.append('| ' + row['id'] + ' / ' + direction + ' | ' + session + ' | ' + escape(metric['status'] + ': ' + str(metric.get('reason'))) + ' | — | — | — | — |')
                    continue
                pieces = [row['id'] + ' / ' + direction, session, metric['boundary'], str(metric['final_record_bytes']['accepted_records'])]
                for name in ('algorithm_bytes', 'final_record_bytes', 'record_overhead_bytes'):
                    pieces.append(number(metric[name]['mean_bytes_per_accepted_record']) + ' / ' + str(metric[name]['p99_bytes']))
                lines.append('| ' + ' | '.join(pieces) + ' |')
    lines += ['', '## Attempt provenance', '']
    for row in rows:
        for value in row['attempts']:
            lines.append('- ' + escape(row['id']) + ': ' + escape(value['status']) + '; [' + escape(Path(value['run_directory']).name) + ']('
                         + value['receipt'] + '), receipt SHA256 `' + value['receipt_sha256'] + '`, binary `' + str(value['binary_sha256']) + '`.')
    lines += ['', 'All input hashes, complete phase reasons, partial observations, capture references, source/build hashes and prior attempts are retained in [report.json](report.json).', '']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--results', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    require(not args.output.exists() and not args.output.is_symlink(), 'output must be a new directory; prior reports are never overwritten')
    require(len(args.results) <= 32, 'at most32 explicit result directories')
    report = build_report(args.manifest, args.results)
    report['reporter_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output.mkdir(parents=True, mode=0o755)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    (args.output / 'report.md').write_text(markdown(report))
    print(json.dumps({'output': str(args.output.resolve()), 'combinations': report['combination_count'], 'status_counts': report['status_counts']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
