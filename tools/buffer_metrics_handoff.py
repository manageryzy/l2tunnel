"""Exact whole-source receiver handoff observations, separate from native delivery."""
REASONS = ('capacity', 'record_window')
U64_MAX = (1 << 64) - 1


def validate(value, epoch, role, last_sample, path, issues, gaps):
    def need(condition, message):
        if not condition:
            raise ValueError(path + ': ' + message)

    def obj(item):
        need(isinstance(item, dict), 'expected object')
        return item

    def num(item, key, nullable=False):
        need(key in item, 'missing ' + key)
        result = item[key]
        if nullable and result is None:
            return None
        need(type(result) is int and 0 <= result <= U64_MAX, 'invalid ' + key)
        return result

    def boolean(item, key):
        need(type(item.get(key)) is bool, 'invalid ' + key)
        return item[key]

    if value is None:
        gaps.append(path + ': ordered receiver handoff unavailable; absence is not zero')
        return
    value = obj(value)
    need(type(value.get('schema')) is int and value['schema'] == 1 and
         value.get('scope') == 'endpoint-shared-receive', 'unknown schema/scope')
    need(num(value, 'epoch') == epoch and num(value, 'cells') == 1, 'wrong endpoint identity/bound')
    direction = num(value, 'receive_direction')
    need(direction in (0, 1), 'invalid direction')
    need(role in ('Client', 'Server'), 'missing or unknown endpoint role')
    need(direction == {'Client': 1, 'Server': 0}[role], 'receive direction mismatch')
    packed = boolean(value, 'packed')
    for key in ('inner_unit_identity', 'missing_context_wait', 'native_consumer_wait'):
        need(key in value and value[key] is None, 'unsupported attribution is not null: ' + key)
    tick = num(value, 'observed_at_us')
    stop = num(value, 'terminal_at_us', True)
    need(tick <= last_sample and (stop is None or stop == tick), 'invalid observation boundary')
    need(value.get('terminal') in (None, 'owner_failure', 'metric_stop') and
         (stop is None) == (value['terminal'] is None), 'terminal kind/time mismatch')
    for key in ('clock_regression', 'identity_mismatch', 'counter_overflow', 'terminal_unavailable'):
        if boolean(value, key):
            issues.append(path + ': producer invalid/availability flag ' + key)
    counts = value.get('refusals')
    need(isinstance(counts, list) and len(counts) == 2, 'invalid reason bound')
    refusals = {}
    for name, row in zip(REASONS, counts):
        row = obj(row)
        need(row.get('reason') == name, 'wrong/duplicate reason')
        refusals[name] = num(row, 'count')
    totals = obj(value.get('totals'))
    populations = []
    for name in ('completed', 'censored'):
        count = num(totals, name + '_episodes')
        elapsed = num(totals, name + '_us')
        maximum = num(totals, 'maximum_' + name + '_us')
        # Aggregate Durations are floored only at serialization, hence count - 1.
        need(maximum <= elapsed <= count * maximum + max(0, count - 1) and
             elapsed <= tick and (count > 0 or elapsed == maximum == 0),
             'inconsistent ' + name + ' population')
        populations.append((count, elapsed, maximum))
    need(populations[1][0] <= 1 and (populations[1][0] == 0 or stop is not None),
         'censor without unique terminal')

    def pending(item, end):
        item = obj(item)
        num(item, 'source')
        need(num(item, 'bytes') > 0, 'empty source')
        deadline = num(item, 'original_deadline_us')
        since, last = num(item, 'since_us'), num(item, 'last_refusal_us')
        need(since <= last <= end <= tick and last <= deadline, 'invalid held source interval/cap')
        for key in ('first_reason', 'last_reason'):
            reason = item.get(key)
            need(reason in REASONS and refusals[reason] > 0, 'source lacks actual refusal')
        return end - since, deadline

    need('pending' in value, 'missing source availability')
    current = value['pending']
    open_us = 0
    if current is not None:
        need(stop is None, 'terminal source remains open')
        open_us, _ = pending(current, tick)
    need(sum(p[0] for p in populations) + int(current is not None) <= sum(refusals.values()),
         'episodes exceed actual refused attempts')
    # A timestamp difference may be one microsecond above its duration floor.
    need(sum(p[1] for p in populations) + open_us <= tick + 1,
         'single-cell intervals overlap or exceed owner time')

    def resolved(item):
        item = obj(item)
        at = num(item, 'at_us')
        elapsed, deadline = pending(item.get('pending'), at)
        release = item.get('release')
        allowed = ('packed_batch',) if packed else ('admitted', 'already_observed')
        need('release' in item and (release is None or release in allowed), 'invalid release boundary')
        index = int(release is None)
        count, _, maximum = populations[index]
        need(count > 0 and elapsed <= maximum + 1, 'resolved source exceeds population')
        need((at == stop) if release is None else at <= deadline, 'release/censor violates original boundary')
        return index, elapsed

    for key, expected in (('maximum_completed', 0), ('maximum_censored', 1)):
        need(key in value, 'missing maximum availability')
        entry = value[key]
        need((entry is None) == (populations[expected][0] == 0), 'maximum identity missing/unearned')
        if entry is not None:
            index, elapsed = resolved(entry)
            need(index == expected and populations[index][2] <= elapsed <= populations[index][2] + 1,
                 'maximum context mismatch')
    need('last_resolved' in value, 'missing latest identity availability')
    last = value['last_resolved']
    need((last is None) == (sum(p[0] for p in populations) == 0), 'latest identity missing/unearned')
    if last is not None:
        index, _ = resolved(last)
        if populations[1][0]:
            need(index == 1, 'terminal censor is not latest resolution')
    gaps.append(path + ': whole ordered recovery source only; Capacity is undifferentiated; '
                'Packed inner failing unit, preview, missing context/source dependency and native '
                'consumer waits unavailable; do not add this interval to other owners')


def render(lines, metadata, table, cell):
    provider = metadata.get('protocol_buffers') if isinstance(metadata, dict) else None
    if not isinstance(provider, dict) or ('schema' in provider and
            (type(provider['schema']) is not int or provider['schema'] != 1)):
        return
    epochs = provider.get('epochs')
    if not isinstance(epochs, list) or len(epochs) > 2:
        return
    # Called only for validated provider metadata; remain safe on direct unknown input.
    for epoch in epochs:
        value = epoch.get('receiver_handoff') if isinstance(epoch, dict) else None
        if not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1:
            continue
        lines.extend(['', 'Ordered receiver handoff — epoch ' + cell(value['epoch']) +
                      ', receiving direction ' + cell(value['receive_direction']) + '.', '',
                      'Actual Capacity/RecordWindow refusal through release of the same whole source. '
                      'Includes scheduling; not continuous fullness or native delivery. '
                      'Packed inner unit identity and preview/dependency/consumer waits remain unavailable.'])
        totals = value['totals']
        table(lines, ['Population', 'Episodes', 'Duration us', 'Maximum us'], [
            [name, totals[name + '_episodes'], totals[name + '_us'], totals['maximum_' + name + '_us']]
            for name in ('completed', 'censored')])
        table(lines, ['Returned refusal', 'Attempts'],
              [[row['reason'], row['count']] for row in value['refusals']])
        rows = []
        for name in ('pending', 'last_resolved', 'maximum_completed', 'maximum_censored'):
            entry = value[name]
            if entry is None:
                continue
            held = entry if name == 'pending' else entry['pending']
            end = value['observed_at_us'] if name == 'pending' else entry['at_us']
            release = 'open' if name == 'pending' else entry['release'] or 'censored'
            rows.append([name, held['source'], held['bytes'], held['original_deadline_us'],
                         held['since_us'], end, release])
        table(lines, ['Context', 'Recovery source', 'Body B', 'Original cap us', 'First refusal us',
                      'End us', 'Boundary'], rows)
