"""Validate actual retained receive-source refusal, never infer wait from occupancy."""
REASONS = ('arq_capacity', 'arq_sequence_window')
U64_MAX = (1 << 64) - 1


def validate(value, observed, terminal, send_direction, path, issues, gaps):
    def need(ok, message):
        if not ok:
            raise ValueError(path + ': ' + message)

    def obj(item):
        need(isinstance(item, dict), 'expected object')
        return item

    def num(item, key, nullable=False):
        need(key in item, 'missing ' + key)
        result = item[key]
        if result is None and nullable:
            return None
        need(type(result) is int and 0 <= result <= U64_MAX, 'invalid ' + key)
        return result

    def boolean(item, key):
        need(type(item.get(key)) is bool, 'invalid ' + key)
        return item[key]

    def totals(item):
        item = obj(item)
        result = []
        for kind in ('completed', 'censored'):
            count = num(item, kind + '_episodes')
            elapsed = num(item, kind + '_us')
            maximum = num(item, 'maximum_' + kind + '_us')
            # Durations are aggregated before floor-to-microsecond serialization.
            rounding = max(0, count - 1)
            need(maximum <= elapsed <= count * maximum + rounding and
                 elapsed <= count * tick + rounding and (count > 0 or elapsed == maximum == 0),
                 'inconsistent source population')
            result.append((count, elapsed, maximum))
        return result

    def opened(item):
        item = obj(item)
        count, elapsed, maximum = (num(item, key) for key in ('episodes', 'sum_us', 'maximum_us'))
        rounding = max(0, count - 1)
        need(count <= cells and maximum <= elapsed <= count * maximum + rounding and
             elapsed <= count * tick + rounding and (count > 0 or elapsed == maximum == 0), 'inconsistent open population')
        return count, elapsed, maximum

    def pending(item, end):
        item = obj(item)
        need(num(item, 'source') < U64_MAX, 'invalid full source ID')
        need(0 < num(item, 'bytes') <= capacity, 'invalid retained recovery extent')
        boolean(item, 'recovered')
        since, last = num(item, 'since_us'), num(item, 'last_refusal_us')
        need(since <= last <= end <= tick, 'invalid source interval')
        reasons = item.get('reasons_since_us')
        need(isinstance(reasons, list) and len(reasons) == 2, 'invalid reason extent')
        need(any(v is not None for v in reasons), 'source without actual refusal')
        for value in reasons:
            need(value is None or type(value) is int and since <= value <= last,
                 'reason outside source episode')
        need(min(v for v in reasons if v is not None) == since, 'source start lacks first refusal')
        return end - since

    if value is None:
        gaps.append(path + ': restored-source ARQ-admission timing unavailable; absence is not zero')
        return
    value = obj(value)
    need(type(value.get('schema')) is int and value['schema'] == 1 and
         value.get('scope') == 'endpoint-shared-receive', 'unknown schema/scope')
    need(num(value, 'receive_direction') == 1 - send_direction, 'receive direction mismatch')
    cells, capacity = num(value, 'cells'), num(value, 'restored_bytes_capacity')
    need(cells > 0 and capacity > 0, 'invalid configured restored bounds')
    tick, stop = num(value, 'observed_at_us'), num(value, 'terminal_at_us', True)
    unavailable = boolean(value, 'terminal_unavailable')
    for flag in ('identity_mismatch', 'clock_regression', 'counter_overflow', 'terminal_unavailable'):
        if boolean(value, flag):
            issues.append(path + ': producer invalid/availability flag ' + flag)
    need(tick <= observed and (unavailable or tick == observed), 'snapshot/owner clock mismatch')
    need(stop is None or stop == tick == terminal, 'terminal boundary mismatch')
    need(terminal is None or unavailable or stop == terminal, 'missing fresh terminal')
    omitted = num(value, 'omitted_refusals')
    if omitted:
        gaps.append(path + ': ' + str(omitted) + ' actual refusals omitted from source intervals')
    population = totals(value.get('sources'))
    live = opened(value.get('open'))
    need(stop is None or live == (0, 0, 0), 'terminal source remains open')
    reasons = value.get('reasons')
    need(isinstance(reasons, list) and len(reasons) == 2, 'invalid reason bound')
    refused = 0
    live_reasons = []
    reason_populations = []
    for name, row in zip(REASONS, reasons):
        row = obj(row)
        need(row.get('reason') == name, 'unknown/duplicate reason')
        count = num(row, 'refusals')
        refused += count
        values, current = totals(row.get('totals')), opened(row.get('open'))
        live_reasons.append(current)
        reason_populations.append(values)
        need(sum(v[0] for v in values) + current[0] <= count, 'reason episodes exceed refusals')
        need(all(all(a <= b for a, b in zip(v, p)) for v, p in zip(values, population)),
             'reason population exceeds source population')
        need(all(a <= b for a, b in zip(current, live)), 'open reason exceeds source population')
    need(omitted <= refused, 'omitted observations exceed actual refusals')
    need(sum(v[0] for v in population) + live[0] <= refused, 'source episodes exceed refusals')
    need(live[0] <= sum(v[0] for v in live_reasons), 'open source lacks reason')
    for index, source in enumerate(population):
        need(source[0] <= sum(v[index][0] for v in reason_populations),
             'resolved source population lacks actual refusal reason')
    need('maximum_open' in value, 'missing open identity availability')
    if value['maximum_open'] is None:
        need(live[0] == 0, 'open source lacks maximum identity')
    else:
        duration = pending(value['maximum_open'], tick)
        need(live[0] > 0 and live[2] <= duration <= live[2] + 1, 'wrong maximum open identity')
    for name, kind, maximum in [('last_completed', 0, False), ('maximum_completed', 0, True),
                                ('maximum_censored', 1, True)]:
        need(name in value, 'missing resolved identity availability')
        record = value[name]
        if record is None:
            need(population[kind][0] == 0, 'population lacks resolved identity')
            continue
        record = obj(record)
        need(boolean(record, 'censored') == bool(kind), 'resolved population mismatch')
        at = num(record, 'at_us')
        duration = pending(record.get('pending'), at)
        need(population[kind][0] > 0 and duration <= population[kind][2] + 1, 'resolved exceeds population')
        need(not maximum or population[kind][2] <= duration <= population[kind][2] + 1,
             'maximum identity duration mismatch')
        need(not kind or at == stop, 'censored identity lacks fresh terminal')
    gaps.append(path + ': source and reason durations overlap; no owner blocked-time union; only latest/'
                'maximum identities retained; missing receive-prefix/source dependency, eligible feedback '
                'delay/budget, FEC missing equations and native delivery timing remain unavailable')


def render(lines, value, table, cell):
    if not isinstance(value, dict):
        return
    # Caller renders only after validating this section with its actual owner identity.
    lines.extend(['', 'Restored-source ARQ admission (receiving direction ' +
                  cell(value['receive_direction']) + '). Actual refusal to successful admission of '
                  'that same source. Sources and reasons overlap: these sums are not owner blocked '
                  'time, feedback delay, or native delivery latency.'])
    source, current = value['sources'], value['open']
    table(lines, ['Population', 'Episodes', 'Source-duration sum us', 'Maximum source us'], [
        ['completed', source['completed_episodes'], source['completed_us'], source['maximum_completed_us']],
        ['censored', source['censored_episodes'], source['censored_us'], source['maximum_censored_us']],
        ['open', current['episodes'], current['sum_us'], current['maximum_us']]])
    table(lines, ['Actual refusal', 'Count', 'Completed source us', 'Censored source us', 'Open source us'],
          [[v['reason'], v['refusals'], v['totals']['completed_us'], v['totals']['censored_us'],
            v['open']['sum_us']] for v in value['reasons'] if v['refusals']])
    rows = []
    for key in ('maximum_open', 'last_completed', 'maximum_completed', 'maximum_censored'):
        v = value[key]
        if v is None:
            continue
        pending = v if key == 'maximum_open' else v['pending']
        end = value['observed_at_us'] if key == 'maximum_open' else v['at_us']
        rows.append([key, pending['source'], pending['bytes'], pending['recovered'],
                     pending['since_us'], end, end - pending['since_us']])
    table(lines, ['Context', 'Source ID', 'Recovery body B', 'Recovered', 'Start us', 'End us', 'Duration us'], rows)
    if value['omitted_refusals']:
        lines.append('Actual refused observations omitted: ' + cell(value['omitted_refusals']) + '.')
