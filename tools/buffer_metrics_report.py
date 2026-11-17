#!/usr/bin/env python3
"""Report saved buffer observations without running workloads or merging owners.

Usage: python3 tools/buffer_metrics_report.py --output NEW_DIRECTORY FILE.bmetrics ...
The output directory must not exist. Input limits are 64 files and 4 MiB per file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

MAX_FILES = 64
MAX_BYTES = 4 * 1024 * 1024
MAX_SITES = 512
MAX_REASONS = 64
U64_MAX = (1 << 64) - 1
DURATION_COUNTS = ('episodes', 'completed_episodes', 'censored_episodes')
DURATION_TIMES = ('completed_us', 'censored_us', 'maximum_us')
GAUGE_VALUES = ('used', 'capacity', 'high_water', 'minimum_known_capacity',
                'maximum_known_capacity')
INVALID_FLAGS = ('clock_regression', 'occupancy_exceeds_capacity',
                 'update_after_finish', 'counter_overflow')
CORE_FIELDS = {'schema', 'owner', 'definition', 'coverage', 'first_observed_us',
               'last_observed_us', 'observed_span_us', 'finished_at_us',
               'diagnostic_heap_bytes', 'invalid', 'blocked_union', 'sites'}
DEFINITION = (
    'Durations cover observed refusal-to-progress intervals, including scheduling delay. '
    'Completed, terminal-censored and currently open intervals are distinct. '
    'Only the exported union for one owner is divided by that owner\'s observed_span_us. '
    'Overlapping sites/reasons and different owners are never summed. '
    'Count-only refusals have unmeasured duration; occupancy does not imply blockage. '
    'Coverage is partial even when every selected input parses successfully.'
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, name, nullable=False):
    require((nullable and value is None) or
            (type(value) is int and 0 <= value <= U64_MAX),
            name + ': expected unsigned 64-bit integer' + (' or null' if nullable else ''))
    return value


def label(value, name):
    require(isinstance(value, str) and 0 < len(value) <= 256, name + ': invalid label')
    return value


def object_value(value, name):
    require(isinstance(value, dict), name + ': expected object')
    return value


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('non-finite JSON number: ' + value)


def duration(value, name, issues):
    value = object_value(value, name)
    require('open_us' in value, name + ': missing open_us')
    result = {key: uint(value.get(key), name + '.' + key)
              for key in DURATION_COUNTS + DURATION_TIMES}
    result['open_us'] = uint(value.get('open_us'), name + '.open_us', True)
    total = result['completed_us'] + result['censored_us'] + (result['open_us'] or 0)
    result['observed_us'] = total
    expected = (result['completed_episodes'] + result['censored_episodes'] +
                int(result['open_us'] is not None))
    if result['episodes'] != expected:
        issues.append(name + ': episode counts do not match completed/censored/open state')
    if total > U64_MAX or result['maximum_us'] > total:
        issues.append(name + ': duration totals inconsistent or saturated')
    for kind in ('completed', 'censored'):
        if result[kind + '_episodes'] == 0 and result[kind + '_us'] != 0:
            issues.append(name + ': duration without ' + kind + ' episode')
    return result


def gauge(value, name, issues):
    value = object_value(value, name)
    require(all(key in value for key in GAUGE_VALUES), name + ': missing gauge fields')
    result = {'samples': uint(value.get('samples'), name + '.samples')}
    result.update({key: uint(value.get(key), name + '.' + key, True)
                   for key in GAUGE_VALUES})
    if result['samples'] == 0 and any(result[key] is not None for key in GAUGE_VALUES):
        issues.append(name + ': values without a gauge sample')
    if result['samples'] and (result['used'] is None or result['high_water'] is None):
        issues.append(name + ': sampled occupancy is missing')
    if result['used'] is not None:
        if result['capacity'] is not None and result['used'] > result['capacity']:
            issues.append(name + ': occupancy exceeds known capacity')
        if result['high_water'] is not None and result['used'] > result['high_water']:
            issues.append(name + ': latest occupancy exceeds high water')
    result['coverage'] = ('unobserved' if not result['samples'] else
                          'capacity_unknown' if result['capacity'] is None else 'sampled')
    return result


def normalize(value, source, digest):
    value = object_value(value, 'input')
    require(type(value.get('schema')) is int and value['schema'] == 1,
            'unsupported buffer metrics schema')
    issues = []
    invalid = object_value(value.get('invalid'), 'invalid')
    require(all(type(invalid.get(key)) is bool for key in INVALID_FLAGS),
            'invalid flags must be booleans')
    for key, flag in invalid.items():
        require(type(flag) is bool, 'invalid flags must be booleans')
        if flag:
            issues.append('producer invalid flag: ' + key)
    require(all(key in value for key in ('first_observed_us', 'last_observed_us',
                                        'observed_span_us', 'finished_at_us')),
            'missing owner observation boundaries')
    times = {key: uint(value.get(key), key, True) for key in (
        'first_observed_us', 'last_observed_us', 'observed_span_us', 'finished_at_us')}
    first, last, span, finished = (times[key] for key in times)
    if (first is None) != (last is None) or (first is None) != (span is None):
        issues.append('inconsistent observed time availability')
    if first is not None and last is not None:
        if last < first:
            issues.append('last observation precedes first observation')
        if finished is not None and (finished < last or span != finished - first):
            issues.append('terminal observed span does not match actual hook boundary')
        if finished is None and span is not None and span < last - first:
            issues.append('observed span ends before last hook')
    union = duration(value.get('blocked_union'), 'blocked_union', issues)
    if span is not None and union['observed_us'] > span:
        issues.append('owner union exceeds actual observed span')
    if finished is not None and union['open_us'] is not None:
        issues.append('finished owner retains an uncensored open union')
    sites = value.get('sites')
    require(isinstance(sites, list) and len(sites) <= MAX_SITES, 'invalid sites array bound')
    occupancy, waits, counts = [], [], []
    seen = set()
    for index, site in enumerate(sites):
        site = object_value(site, 'site')
        key = {name: label(site.get(name), name) for name in ('site', 'lane', 'class')}
        identity = tuple(key.values())
        require(identity not in seen, 'duplicate site/lane/class')
        seen.add(identity)
        prefix = 'sites[' + str(index) + ']'
        sampled = {**key, 'bytes': gauge(site.get('bytes'), prefix + '.bytes', issues),
                   'items': gauge(site.get('items'), prefix + '.items', issues),
                   **{name: uint(site.get(name), prefix + '.' + name, True)
                      for name in ('first_observed_us', 'last_observed_us')}}
        occupancy.append(sampled)
        reasons = site.get('reasons')
        require(isinstance(reasons, list) and len(reasons) <= MAX_REASONS,
                prefix + ': invalid reasons array bound')
        reason_names = set()
        for reason in reasons:
            reason = object_value(reason, prefix + '.reason')
            name = label(reason.get('reason'), 'reason')
            require(name not in reason_names, prefix + ': duplicate reason')
            reason_names.add(name)
            counters = {name: uint(reason.get(name), prefix + '.' + name)
                        for name in ('refusals', 'untimed_refusals', 'progress')}
            blocked = duration(reason.get('blocked'), prefix + '.' + name, issues)
            if finished is not None and blocked['open_us'] is not None:
                issues.append(prefix + ': finished reason retains an open wait')
            if span is not None and blocked['observed_us'] > span:
                issues.append(prefix + ': reason duration exceeds owner span')
            row = {**key, 'reason': name, **counters, 'blocked': blocked,
                   'timing_coverage': ('partial_timed' if counters['untimed_refusals'] else 'timed')
                   if blocked['episodes'] else 'no_timed_episode_observed'}
            if blocked['episodes']:
                waits.append(row)
            if counters['untimed_refusals'] or (not blocked['episodes'] and counters['refusals']):
                counts.append({**key, 'reason': name, **counters, 'duration_us': None,
                               'definition': 'Unmeasured refusal duration; excluded from owner union.'})
    waits.sort(key=lambda row: (-row['blocked']['observed_us'], row['site'], row['lane'],
                               row['class'], row['reason']))
    counts.sort(key=lambda row: (-row['untimed_refusals'], row['site'], row['lane'],
                                row['class'], row['reason']))
    ratio = None
    if not issues and span is not None and span > 0:
        ratio = 100.0 * union['observed_us'] / span
    return {
        'source': source, 'sha256': digest, 'owner': label(value.get('owner'), 'owner'),
        'source_schema': 1, 'status': 'invalid_observations' if issues else 'parsed_partial_coverage',
        'issues': issues, 'invalid': invalid, **times,
        'source_definition': value.get('definition'), 'source_coverage': value.get('coverage'),
        'diagnostic_heap_bytes': uint(value.get('diagnostic_heap_bytes'), 'diagnostic_heap_bytes'),
        'blocked_union': union, 'owner_union_percent_of_observed_span': ratio,
        'percentage_unavailable_reason': None if ratio is not None else
        ('invalid_observations' if issues else 'unknown_or_zero_observed_span'),
        'wait_ranking': waits, 'count_only_refusals': counts, 'occupancy': occupancy,
        'provider_metadata': {key: item for key, item in value.items() if key not in CORE_FIELDS},
        'provider_metadata_definition': 'Preserved source fields; no queue usage derived from provider space or limits.',
    }


def read_input(path):
    require(path.suffix == '.bmetrics', 'expected a .bmetrics input')
    require(not path.is_symlink() and path.is_file(), 'regular non-symlink input required')
    with path.open('rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'regular input required')
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, 'input exceeds 4 MiB bound')
    digest = hashlib.sha256(raw).hexdigest()
    value = json.loads(raw, object_pairs_hook=unique_keys, parse_constant=reject_constant)
    return normalize(value, str(path.resolve()), digest)


def build_report(paths):
    require(0 < len(paths) <= MAX_FILES, 'select between 1 and 64 input files')
    selected = [Path(path) for path in paths]
    canonical = [str(path.resolve()) for path in selected]
    require(len(set(canonical)) == len(canonical), 'duplicate input path')
    owners, rejected = [], []
    for path in selected:
        try:
            owners.append(read_input(path))
        except (OSError, ValueError, RecursionError) as error:
            rejected.append({'source': str(path.resolve()), 'status': 'rejected_input',
                             'error': str(error), 'measurements': None})
    return {'schema': 1, 'definition': DEFINITION, 'coverage': 'partial',
            'input_limits': {'files': MAX_FILES, 'bytes_per_file': MAX_BYTES},
            'owners': owners, 'rejected_inputs': rejected,
            'status': 'input_or_observation_errors' if rejected or
            any(owner['issues'] for owner in owners) else 'parsed_partial_coverage'}


def cell(value):
    if value is None:
        return 'unknown'
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace(
        '|', '&#124;').replace('\r', ' ').replace('\n', ' ').replace('`', '&#96;')


def table(lines, columns, rows):
    lines.extend(['', '| ' + ' | '.join(columns) + ' |',
                  '| ' + ' | '.join('---' for _ in columns) + ' |'])
    for row in rows:
        lines.append('| ' + ' | '.join(cell(item) for item in row) + ' |')


def markdown(report):
    lines = ['# Observed buffer pressure', '', DEFINITION, '',
             'Status: ' + report['status'] + '. Raw and QUIC provider fields are retained in JSON; '
             'provider-private queue usage is not inferred. No end-to-end blocked percentage is calculated.']
    for index, owner in enumerate(report['owners'], 1):
        union = owner['blocked_union']
        percentage = owner['owner_union_percent_of_observed_span']
        lines.extend(['', '## Owner ' + str(index) + ': ' + cell(owner['owner']), '',
                      'Source: ' + cell(owner['source']), '', 'SHA256: ' + owner['sha256'], '',
                      'Status: ' + owner['status'] + '. Coverage: ' + cell(owner['source_coverage'])])
        table(lines, ['Observed span us', 'Union completed us', 'Union censored us',
                      'Union open us', 'Union / observed span'],
              [[owner['observed_span_us'], union['completed_us'], union['censored_us'],
                union['open_us'] if union['open_us'] is not None else 'none open',
                f'{percentage:.6f}%' if percentage is not None else
                'unavailable: ' + owner['percentage_unavailable_reason']]])
        if owner['issues']:
            lines.extend(['', 'Diagnostic invalidity (values retained, percentage suppressed):'])
            lines.extend('- ' + cell(issue) for issue in owner['issues'])
        lines.extend(['', '### Ranked observed waits', '',
                      'Ranked within this owner by completed + censored + open duration for each '
                      'individual reason. Rows overlap and must not be summed.'])
        if owner['wait_ranking']:
            table(lines, ['Site / lane / class', 'Reason', 'Completed us (episodes)',
                          'Censored us (episodes)', 'Open us', 'Maximum us', 'Refusals', 'Coverage'],
                  [[' / '.join(row[key] for key in ('site', 'lane', 'class')), row['reason'],
                    f"{row['blocked']['completed_us']} ({row['blocked']['completed_episodes']})",
                    f"{row['blocked']['censored_us']} ({row['blocked']['censored_episodes']})",
                    row['blocked']['open_us'] if row['blocked']['open_us'] is not None else 'none open',
                    row['blocked']['maximum_us'], row['refusals'], row['timing_coverage']]
                   for row in owner['wait_ranking']])
        else:
            lines.extend(['', 'No timed episode was observed; unhooked waits remain unmeasured.'])
        lines.extend(['', '### Count-only refusals', '',
                      'These counts do not establish wait duration and are excluded from the timed union.'])
        if owner['count_only_refusals']:
            table(lines, ['Site / lane / class', 'Reason', 'Untimed refusals', 'All refusals', 'Duration'],
                  [[' / '.join(row[key] for key in ('site', 'lane', 'class')), row['reason'],
                    row['untimed_refusals'], row['refusals'], 'unmeasured']
                   for row in owner['count_only_refusals']])
        else:
            lines.extend(['', 'No count-only refusal is present in the selected source.'])
        lines.extend(['', '### Sampled occupancy', '',
                      'High water and capacity extrema are sampled values. Unknown capacity stays unknown.'])
        table(lines, ['Site / lane / class', 'Unit', 'Samples', 'Used', 'Capacity', 'High water',
                      'Capacity min / max', 'Coverage'],
              [[' / '.join(row[key] for key in ('site', 'lane', 'class')), unit,
                row[unit]['samples'], row[unit]['used'], row[unit]['capacity'], row[unit]['high_water'],
                cell(row[unit]['minimum_known_capacity']) + ' / ' + cell(row[unit]['maximum_known_capacity']),
                row[unit]['coverage']] for row in owner['occupancy'] for unit in ('bytes', 'items')])
        providers = owner['provider_metadata']
        if providers:
            lines.extend(['', 'Provider metadata keys preserved in JSON: ' + ', '.join(
                cell(key) for key in providers) + '. No subtraction of available space from a cap '
                'is treated as payload or heap usage. Raw candidate age is residence, not a wait.'])
    if report['rejected_inputs']:
        lines.extend(['', '## Rejected inputs', '', 'No measurements were inferred for these inputs.'])
        table(lines, ['Source', 'Error'], [[row['source'], row['error']]
                                          for row in report['rejected_inputs']])
    return '\n'.join(lines) + '\n'


def write_report(paths, output):
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'output directory must be new')
    report = build_report(paths)
    # Validate and render before creating any output. Existing receipts are never overwritten.
    encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
    text = markdown(report)
    output.mkdir()
    with (output / 'report.json').open('x', encoding='utf-8') as stream:
        stream.write(encoded)
    with (output / 'report.md').open('x', encoding='utf-8') as stream:
        stream.write(text)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new output directory')
    parser.add_argument('inputs', type=Path, nargs='+', help='explicit .bmetrics files; owners stay separate')
    args = parser.parse_args(argv)
    try:
        report = write_report(args.inputs, args.output)
    except (OSError, ValueError) as error:
        parser.exit(2, 'buffer metrics report: ' + str(error) + '\n')
    print(str(args.output / 'report.md'))
    return 0 if report['status'] == 'parsed_partial_coverage' else 2


if __name__ == '__main__':
    raise SystemExit(main())
