"""Actual receiving data-head Busy intervals; no occupancy or work-Pending inference."""
OUTCOMES = ('staged', 'duplicate', 'stale', 'censored')
MAX = (1 << 64) - 1


def validate(value, observed, terminal, send_direction, path, issues, gaps):
    def need(ok, message):
        if not ok:
            raise ValueError(path + ': ' + message)

    def obj(value):
        need(isinstance(value, dict), 'expected object')
        return value

    def num(value, key, nullable=False):
        need(key in value, 'missing ' + key)
        result = value[key]
        if result is None and nullable:
            return None
        need(type(result) is int and 0 <= result <= MAX, 'invalid ' + key)
        return result

    def flag(value, key):
        need(type(value.get(key)) is bool, 'invalid ' + key)
        return value[key]

    def job(value, at):
        if value is None:
            return None
        value = obj(value)
        identity = obj(value.get('identity'))
        kind = identity.get('kind')
        need(kind in ('source', 'repair', 'near8'), 'invalid actual decoder identity')
        if kind == 'source':
            need(num(identity, 'first') + 1 == num(identity, 'end') <= (1 << 32) - 1,
                 'invalid systematic job identity')
        elif kind == 'near8':
            need(0 < num(identity, 'group') <= ((1 << 32) - 1) // 8,
                 'invalid eight-source repair group')
        else:
            need(num(identity, 'id') < MAX, 'invalid repair identity')
            support = identity.get('support')
            need(support is None or isinstance(support, list) and len(support) == 2 and
                 all(type(v) is int for v in support) and
                 0 <= support[0] < support[1] <= (1 << 32) - 1, 'invalid repair support')
        received, admitted, cap = (num(value, k) for k in
                                   ('received_us', 'admitted_us', 'original_deadline_us'))
        need(received <= admitted <= at < cap, 'invalid decoder job times')
        return 'repair' if kind == 'near8' else kind

    def pending(value, end):
        value = obj(value)
        serial = num(value, 'serial')
        need(0 < serial < MAX, 'invalid data-head serial')
        source = obj(value.get('input'))
        number = num(source, 'records_number', True)
        if number is None:
            gaps.append(path + ': exact Records identity unavailable for this data head')
        arrived, cap = num(source, 'received_us'), num(source, 'original_deadline_us')
        need(num(source, 'bytes') > 0 and source.get('kind') in ('source', 'repair'),
             'invalid original input geometry')
        since, last = num(value, 'since_us'), num(value, 'last_refusal_us')
        need(arrived <= since <= last <= end <= observed and last < cap,
             'invalid original input/refusal times')
        need('first_blocker' in value and 'latest_blocker' in value, 'missing blocker availability')
        need(unknown > 0 or value['first_blocker'] is not None and value['latest_blocker'] is not None,
             'unavailable blocker lacks its actual refusal count')
        job(value['first_blocker'], since)
        job(value['latest_blocker'], last)
        return serial, source, end - since

    if value is None:
        gaps.append(path + ': actual receive data-head Busy timing unavailable; absence is not zero')
        return
    value = obj(value)
    need(type(value.get('schema')) is int and value['schema'] == 1, 'unknown schema')
    need(num(value, 'receive_direction') == (send_direction ^ 1), 'receive direction mismatch')
    next_head, refusals = num(value, 'next_head'), num(value, 'refusals')
    need(next_head > 0, 'invalid next data-head serial')
    omitted, unknown = num(value, 'omitted_refusals'), num(value, 'blocker_unavailable')
    need(omitted <= refusals and unknown <= refusals, 'omitted/unknown exceeds refusals')
    if omitted:
        gaps.append(path + ': actual refusals omitted=' + str(omitted))
    if unknown:
        gaps.append(path + ': actual Busy blocker context unavailable=' + str(unknown))
    unavailable = flag(value, 'terminal_unavailable')
    if unavailable:
        need(terminal is not None, 'unavailable terminal without terminal boundary')
        issues.append(path + ': fresh terminal source sample unavailable')
    stopped = num(value, 'terminal_at_us', True)
    need(stopped is None or stopped == observed == terminal, 'terminal boundary mismatch')
    need(terminal is None or unavailable or stopped == terminal, 'missing fresh terminal')
    rows = value.get('populations')
    need(isinstance(rows, list) and len(rows) == 4, 'invalid population bound')
    episodes, duration, completions = 0, 0, 0
    for i, (name, row) in enumerate(zip(OUTCOMES, rows)):
        row = obj(row)
        need(row.get('outcome') == name, 'unknown/duplicate outcome')
        count, elapsed, maximum = (num(row, k) for k in ('episodes', 'sum_us', 'maximum_us'))
        need(maximum <= elapsed <= count * maximum and elapsed <= count * observed,
             'inconsistent duration population')
        complete, direct = num(row, 'completions', True), num(row, 'without_refusal', True)
        if i < 3:
            need(complete is not None and direct is not None and complete == direct + count,
                 'successful removal/outcome count mismatch')
            completions += complete
        else:
            need(complete is None and direct is None and count <= 1 and
                 (count == 0 or stopped is not None), 'censor is not successful removal')
        episodes += count
        duration += elapsed
    need(next_head == min(MAX, completions + 1), 'data-head serial/completion mismatch')
    residence = value.get('queue_residence')
    if residence is None:
        gaps.append(path + ': all-data queue residence unavailable; absence is not zero')
    else:
        residence = obj(residence)
        need(type(residence.get('schema')) is int and residence['schema'] == 1,
             'unknown residence schema')

        def distribution(row):
            row = obj(row)
            count, total, maximum, slow = (num(row, k) for k in
                                           ('count', 'sum_us', 'maximum_us', 'at_least_100ms'))
            bins = row.get('buckets')
            need(isinstance(bins, list) and len(bins) == 32 and
                 all(type(n) is int and 0 <= n <= MAX for n in bins) and sum(bins) == count,
                 'invalid residence histogram')
            need(maximum <= total <= count * maximum and slow <= count and
                 total >= slow * 100_000 and (maximum >= 100_000 or slow == 0),
                 'inconsistent residence totals')
            ceiling = None
            if count:
                cumulative, rank = 0, count - count // 100
                minimum_sum, maximum_sum, minimum_slow, maximum_slow = 0, 0, 0, 0
                for index, number in enumerate(bins):
                    upper = (1 << index) - 1 if index < 31 else MAX
                    lower = 0 if index == 0 else 1 << (index - 1)
                    need(not number or lower <= maximum, 'residence bucket exceeds maximum')
                    minimum_sum += lower * number
                    maximum_sum += min(upper, maximum) * number
                    if lower >= 100_000:
                        minimum_slow += number
                    if upper >= 100_000:
                        maximum_slow += number
                    cumulative += number
                    if ceiling is None and cumulative >= rank:
                        ceiling = upper
                need(minimum_sum <= total <= maximum_sum, 'residence histogram sum mismatch')
                need(minimum_slow <= slow <= maximum_slow and (maximum < 100_000 or slow > 0),
                     'residence threshold population mismatch')
                highest = max(index for index, number in enumerate(bins) if number)
                need(maximum <= ((1 << highest) - 1 if highest < 31 else MAX),
                     'maximum outside residence histogram')
                need(maximum <= observed, 'residence exceeds observation age')
                mean = row.get('mean_us')
                need(type(mean) in (int, float) and abs(mean - total / count) <= max(1, total / count) * 1e-12,
                     'incorrect residence mean')
            else:
                need(row.get('mean_us') is None and maximum == total == slow == 0,
                     'empty residence population is not a zero mean')
            need(row.get('p99_upper_us') == ceiling and
                 (ceiling is None or type(row['p99_upper_us']) is int), 'incorrect p99 upper bound')
            return row

        all_data, direct, queued = (distribution(residence.get(key)) for key in ('all', 'immediate', 'queued'))
        for key in ('count', 'sum_us', 'at_least_100ms'):
            need(all_data[key] == direct[key] + queued[key], 'all-data residence population mismatch')
        need(all_data['maximum_us'] == max(direct['maximum_us'], queued['maximum_us']) and
             all_data['buckets'] == [a + b for a, b in zip(direct['buckets'], queued['buckets'])],
             'all-data histogram mismatch')
        for key, population in [('immediate_outcomes', direct), ('queued_outcomes', queued)]:
            counts = residence.get(key)
            need(isinstance(counts, list) and len(counts) == 3 and
                 all(type(n) is int and 0 <= n <= MAX for n in counts) and sum(counts) == population['count'],
                 'invalid residence outcome counts')
        need(residence['queued_outcomes'] == [row['completions'] for row in rows[:3]],
             'queued residence does not cover successful removals')
        at = num(residence, 'retained_at_us', True)
        ages = residence.get('retained_ages')
        mode = residence.get('retained_population')
        need(mode == ('unavailable' if unavailable else 'censored' if stopped is not None else 'open_age_snapshot'),
             'incorrect retained age boundary')
        if unavailable:
            need(ages is None and (at is None or at <= observed), 'stale retained age extrapolation')
        elif ages is None:
            need(at is None, 'retained age timestamp without population')
            gaps.append(path + ': current retained input ages unavailable')
        else:
            ages = distribution(ages)
            need(at == observed and ages['maximum_us'] <= observed,
                 'retained ages lack exact current/frozen observation')
    need('pending' in value and 'last_resolved' in value, 'missing head availability')
    current, opened = value['pending'], num(value, 'open_us', True)
    if current is not None:
        serial, _, elapsed = pending(current, observed)
        need(serial == next_head and stopped is None, 'wrong current head or terminal duration')
        if unavailable:
            need(opened is None, 'stale terminal sample extrapolated open duration')
        else:
            need(opened == elapsed, 'wrong current head or open duration')
            duration += elapsed
    else:
        need(opened is None, 'open duration without refused head')
    need(episodes + int(current is not None) <= refusals, 'episodes exceed actual Busy')
    need(duration <= observed, 'same-head intervals overlap or exceed observation span')
    resolved = value['last_resolved']
    if resolved is None:
        need(episodes == 0, 'resolved population lacks identity')
    else:
        resolved = obj(resolved)
        name, at = resolved.get('outcome'), num(resolved, 'at_us')
        need(name in OUTCOMES, 'invalid resolved outcome')
        row = rows[OUTCOMES.index(name)]
        serial, source, elapsed = pending(resolved.get('pending'), at)
        need(row['episodes'] > 0 and elapsed <= row['maximum_us'], 'resolved identity lacks population')
        need('admitted_job' in resolved, 'missing newly admitted job availability')
        new = resolved['admitted_job']
        if name == 'staged':
            need(new is not None, 'staged outcome lacks actual new job')
            need(job(new, at) == source['kind'] and new['received_us'] == source['received_us'] and
                 new['admitted_us'] == at and new['original_deadline_us'] == source['original_deadline_us'],
                 'new job does not match staged input times/kind')
        else:
            need(new is None, 'duplicate/stale/censor fabricated new job')
        if name == 'censored':
            need(at == stopped and serial == next_head, 'censor lost exact unresolved head')
        else:
            need(serial < next_head and at < source['original_deadline_us'],
                 'successful removal crossed original cap or reused current head')
    gaps.append(path + ': data-head Busy intervals include scheduling; queue residence is separately attributed when present; work Pending, '
                'CPU cost, ingress-capacity refusal and feedback ordering dependencies remain separate/unavailable; '
                'only last resolved and current head identities retained')


def render(lines, metadata, table, cell):
    provider = metadata.get('protocol_buffers')
    if not isinstance(provider, dict):
        return
    for epoch in provider.get('epochs', []):
        waits = epoch.get('rolling_waits')
        if not isinstance(waits, dict):
            continue
        value = waits.get('ingress_admission')
        if not isinstance(value, dict):
            continue
        lines.extend(['', 'Rolling/Research receive data-head admission, epoch ' + cell(epoch['epoch']) +
                      ', direction ' + cell(value['receive_direction']) +
                      '. Actual Busy-to-same-head removal; separate from earlier residence, work service and CPU time.'])
        table(lines, ['Outcome', 'Refused heads resolved', 'Interval sum us', 'Maximum us',
                      'All successful removals', 'Without Busy'],
              [[v['outcome'], v['episodes'], v['sum_us'], v['maximum_us'],
                v['completions'], v['without_refusal']] for v in value['populations']])
        residence = value.get('queue_residence')
        if isinstance(residence, dict):
            lines.extend(['', 'Data input receive-to-removal residence uses original authenticated arrival. Direct inputs bypass FIFO but retain actual receive-to-admission age. '
                          'Staged, Duplicate and Stale are successful removals; retained ages are not completed admission. '
                          'p99 is a histogram upper bound; overlapping residence and Busy durations are not added.'])
            samples = [(name, residence[name]) for name in ('all', 'immediate', 'queued')]
            if residence.get('retained_ages') is not None:
                samples.append((residence['retained_population'], residence['retained_ages']))
            table(lines, ['Population', 'Inputs', 'Mean us', 'p99 upper us', 'Maximum us', 'At least 100 ms'],
                  [[name, row['count'], row['mean_us'], row['p99_upper_us'], row['maximum_us'], row['at_least_100ms']]
                   for name, row in samples])
        contexts = []
        if value['pending'] is not None:
            contexts.append(('open', value['pending'],
                             None if value['terminal_unavailable'] else waits['observed_at_us'], None))
        if value['last_resolved'] is not None:
            v = value['last_resolved']
            contexts.append((v['outcome'], v['pending'], v['at_us'], v['admitted_job']))
        table(lines, ['Context', 'Head serial', 'Records number', 'Input kind', 'Original arrival us',
                      'First Busy us', 'End us', 'Original cap us'],
              [[name, p['serial'], p['input']['records_number'], p['input']['kind'],
                p['input']['received_us'], p['since_us'], end, p['input']['original_deadline_us']]
               for name, p, end, _ in contexts])
        jobs = []
        for name, p, _, admitted in contexts:
            for label, job_value in [('first blocker', p['first_blocker']),
                                     ('latest blocker', p['latest_blocker']), ('newly admitted', admitted)]:
                if job_value is not None:
                    ident = job_value['identity']
                    key = {'repair': 'id', 'near8': 'group', 'source': 'first'}[ident['kind']]
                    identity = str(ident[key])
                    jobs.append([name, label, ident['kind'], identity, job_value['received_us'],
                                 job_value['admitted_us'], job_value['original_deadline_us']])
        table(lines, ['Context', 'Job role', 'Kind', 'ID', 'Job arrival us', 'Job admission us', 'Job cap us'], jobs)
