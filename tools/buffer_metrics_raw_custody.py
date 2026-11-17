"""Validate and render exact raw-token latency; never infer a blocked union."""
U64_MAX = (1 << 64) - 1
STAGES = ('commit_to_physical', 'physical_to_observe', 'observe_to_take',
          'censored_before_physical_observation', 'censored_after_physical_observation')

def require(condition, message):
    if not condition:
        raise ValueError('raw custody: ' + message)

def number(value, key):
    result = value.get(key)
    require(type(result) is int and 0 <= result <= U64_MAX, 'invalid ' + key)
    return result

def normalize(value, source, digest):
    require(value.get('owner') == 'raw_custody' and value.get('schema') == 1,
            'unknown owner/schema')
    require(value.get('blocked_union') is None and value.get('sites') == [],
            'latency cannot claim a generic blocked union')
    provider = value.get('raw_custody')
    require(isinstance(provider, dict) and provider.get('schema') == 1, 'provider schema')
    require(type(provider.get('finished')) is bool, 'finished flag')
    require(type(provider.get('invalid_clock')) is bool, 'clock flag')
    require(type(provider.get('counter_overflow')) is bool, 'overflow flag')
    observed = number(provider, 'observed_us')
    mismatches = number(provider, 'identity_mismatches')
    duplicates = number(provider, 'duplicate_observations')
    issues = []
    if provider['invalid_clock']:
        issues.append('producer reported invalid clock')
    if provider['counter_overflow']:
        issues.append('producer reported counter overflow')
    if mismatches:
        issues.append('producer reported identity mismatch')
    rows = provider.get('rows')
    require(isinstance(rows, list) and len(rows) == 4, 'exact four lane/class rows required')
    seen = set()
    for row in rows:
        require(isinstance(row, dict), 'row object')
        lane, cls = number(row, 'lane'), row.get('class')
        require(lane in (0, 1) and cls in ('User', 'Control'), 'lane/class')
        require((lane, cls) not in seen, 'duplicate row')
        seen.add((lane, cls))
        counts = {name: number(row, name) for name in
                  ('committed', 'physical_observed', 'upper_taken', 'late_physical')}
        c, p, t, late = (counts[k] for k in counts)
        if not t <= p <= c or late > p:
            issues.append(f'lane {lane} {cls}: custody count order')
        expected = (p, p, t, c-p, p-t)
        for index, stage in enumerate(STAGES):
            total = row.get(stage)
            require(isinstance(total, dict), 'missing stage ' + stage)
            samples, duration, maximum = (number(total, key) for key in ('samples', 'sum_us', 'max_us'))
            if (samples == 0 and (duration or maximum)) or maximum > duration:
                issues.append(f'lane {lane} {cls} {stage}: inconsistent totals')
            if duration > samples * maximum or maximum > observed:
                issues.append(f'lane {lane} {cls} {stage}: duration outside population bounds')
            if (index < 3 or provider['finished']) and samples != expected[index]:
                issues.append(f'lane {lane} {cls} {stage}: count differs from actual boundary')
    heap = number(value, 'diagnostic_heap_bytes')
    number(value, 'inline_bytes')
    pid = number(value, 'pid')
    return {
        'source': source, 'sha256': digest, 'owner': 'raw_custody', 'pid': pid,
        'source_schema': 1, 'status': 'invalid_observations' if issues else 'parsed_partial_coverage',
        'issues': issues, 'source_definition': value.get('definition'),
        'source_coverage': value.get('coverage'), 'diagnostic_heap_bytes': heap,
        'observed_span_us': observed, 'blocked_union': None,
        'owner_union_percent_of_observed_span': None,
        'percentage_unavailable_reason': 'latency_is_not_a_blocked_interval',
        'raw_custody_validation': {'status': 'invalid_observations' if issues else 'validated_latency',
                                   'definition': value.get('definition'), 'rows': rows,
                                   'finished': provider['finished'], 'identity_mismatches': mismatches,
                                   'duplicate_observations': duplicates},
        'provider_metadata': {'raw_custody': provider},
        'wait_ranking': [], 'count_only_refusals': [], 'occupancy': [],
    }

def render(lines, owner, table, cell):
    checked = owner['raw_custody_validation']
    lines.extend(['', 'Exact raw-token custody latency. Generic blocked time and percentage are unmeasured.',
                  'Completed stage and terminal-censored populations are separate; overlapping totals are never added.',
                  'Duplicate physical observations suppressed: ' + str(checked['duplicate_observations']) + '.',
                  'Identity mismatches: ' + str(checked['identity_mismatches']) + '.'])
    table(lines, ['Lane', 'Class', 'Committed', 'Physical observed', 'Upper taken', 'Late physical'],
          [[r['lane'], r['class'], r['committed'], r['physical_observed'], r['upper_taken'], r['late_physical']]
           for r in checked['rows']])
    table(lines, ['Lane', 'Class', 'Latency population', 'Samples', 'Total us', 'Mean us', 'Maximum us'],
          [[r['lane'], r['class'], stage, r[stage]['samples'], r[stage]['sum_us'],
            r[stage]['sum_us'] / r[stage]['samples'] if r[stage]['samples'] else 'unmeasured',
            r[stage]['max_us'] if r[stage]['samples'] else 'unmeasured']
           for r in checked['rows'] for stage in STAGES])
    lines.extend('- ' + cell(issue) for issue in owner['issues'])
