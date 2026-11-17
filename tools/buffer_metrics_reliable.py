"""Validate exact Block FEC head observations without deriving carrier waits."""
REASONS = ('packet_budget', 'wire_byte_budget')
CAPACITY_REASONS = ('fec_symbol_slots', 'fec_generation_slots', 'fec_logical_reservation',
                    'restored_packet_slots', 'restored_byte_budget')
U64_MAX = (1 << 64) - 1


def validate(value, epoch, path, issues, gaps, expected_direction=None):
    """Known fields remain separate from occupancy, other owners and the runtime union."""
    def need(ok, message):
        if not ok:
            raise ValueError(path + ': ' + message)

    def obj(item):
        need(isinstance(item, dict), 'expected object')
        return item

    def number(item, key, nullable=False):
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
            count = number(item, kind + '_episodes')
            elapsed = number(item, kind + '_us')
            maximum = number(item, 'maximum_' + kind + '_us')
            need(maximum <= elapsed and (count > 0 or elapsed == maximum == 0),
                 'inconsistent ' + kind + ' totals')
            result.append((count, elapsed))
        return result

    def operation(item):
        item = obj(item)
        number(item, 'generation')
        need(number(item, 'symbol') < (1 << 32), 'invalid symbol identity')
        need(0 < number(item, 'bytes') <= 65535, 'invalid output extent')

    if value is None:
        gaps.append(path + ': Block FEC outgoing timing unavailable; absence is not zero')
        return
    value = obj(value)
    need(value.get('scope') == 'endpoint-shared', 'unknown owner scope')
    need(number(value, 'epoch') == epoch, 'epoch identity mismatch')
    direction = number(value, 'send_direction')
    need(direction in (0, 1), 'invalid direction')
    need(expected_direction is None or direction == expected_direction, 'local role/direction mismatch')
    for key in ('clock_regression', 'identity_mismatch', 'counter_overflow'):
        if boolean(value, key):
            issues.append(path + ': producer invalid flag ' + key)
    sealed = boolean(value, 'sealed_output_present')
    observed = number(value, 'observed_at_us')
    terminal = number(value, 'terminal_at_us', True)
    need(terminal is None or terminal == observed, 'inconsistent terminal boundary')
    union = totals(value.get('union'))
    need('pending' in value and 'last_resolved' in value, 'missing operation availability')
    pending = value['pending']
    first, opened = None, 0
    if pending is not None:
        pending = obj(pending)
        operation(pending.get('operation'))
        first = number(pending, 'since_us')
        last = number(pending, 'last_refusal_us')
        opened = number(pending, 'open_us', True)
        need(terminal is None and first <= last <= observed and opened == observed - first,
             'invalid open interval')
    reasons = value.get('reasons')
    need(isinstance(reasons, list) and len(reasons) == 2, 'invalid reason bound')
    refusals, open_reasons = 0, 0
    for name, row in zip(REASONS, reasons):
        row = obj(row)
        need(row.get('reason') == name, 'unknown/duplicate/out-of-order reason')
        count = number(row, 'refusals')
        refusals += count
        populations = totals(row.get('totals'))
        since = number(row, 'pending_since_us', True)
        if since is not None:
            need(first is not None and first <= since <= observed, 'reason without same open head')
            open_reasons += 1
        need(sum(v[0] for v in populations) + int(since is not None) <= count,
             'reason episodes exceed actual refusals')
        need(all(p[1] <= u[1] for p, u in zip(populations, union)),
             'reason duration exceeds head union')
    need((pending is None) == (open_reasons == 0), 'pending head lacks an actual refusal')
    need(sum(v[0] for v in union) + int(pending is not None) <= refusals,
         'head episodes exceed actual refusals')
    need(sum(v[1] for v in union) + opened <= observed, 'head durations exceed observation time')
    resolved = value['last_resolved']
    if resolved is not None:
        resolved = obj(resolved)
        operation(resolved.get('operation'))
        began, ended = number(resolved, 'since_us'), number(resolved, 'at_us')
        censored = boolean(resolved, 'censored')
        need(began <= ended <= observed, 'invalid resolved time')
        need(union[int(censored)][0] > 0, 'resolved head lacks matching population')
    if not sealed:
        need(pending is None and resolved is None and refusals == 0 and
             union == [(0, 0), (0, 0)], 'absent sealed output has invented wait')
        gaps.append(path + ': sender has no sealed FEC output queue; Direct ARQ output wait unavailable')
    counts = value.get('capacity_refusals')
    need(isinstance(counts, list) and len(counts) == 5, 'invalid capacity reason bound')
    for name, row in zip(CAPACITY_REASONS, counts):
        row = obj(row)
        need(row.get('reason') == name, 'unknown/duplicate/out-of-order capacity reason')
        number(row, 'refusals')
    gaps.append(path + ': head interval includes scheduling until emission; reason intervals overlap; '
                'capacity gates are count-only; restored-source/builder/dependency/physical waits unavailable')


def render(lines, metadata, table, cell):
    """Render nonempty facts without merging head timing into any other owner union."""
    provider = metadata.get('protocol_buffers') if isinstance(metadata, dict) else None
    if not isinstance(provider, dict) or provider.get('schema', 1) != 1:
        return
    epochs = provider.get('epochs')
    if not isinstance(epochs, list) or len(epochs) > 2:
        return
    for epoch in epochs:
        value = epoch.get('reliable_output') if isinstance(epoch, dict) else None
        if not isinstance(value, dict):
            continue
        # Malformed producers are retained in JSON with validation issues, not reinterpreted.
        issues, gaps = [], []
        try:
            validate(value, epoch.get('epoch'), 'reliable_output', issues, gaps)
        except ValueError:
            continue
        if issues:
            continue
        lines.extend(['', '### Block FEC retained output: epoch ' + cell(epoch['epoch']), '',
                      'Endpoint-shared, direction ' + cell(value['send_direction']) + '. '
                      'Actual head refusal to emission, including scheduling delay; emission is not '
                      'physical acceptance. Reasons overlap and are not added. Capacity counts do '
                      'not establish wait duration. Full configuration identity is retained in JSON.'])
        if not value['sealed_output_present']:
            lines.append('No sealed FEC output queue is present; output wait duration is unavailable.')
            table(lines, ['Capacity gate', 'Actual count-only refusals'],
                  [[row['reason'], row['refusals']] for row in value['capacity_refusals'] if row['refusals']])
            continue
        union = value['union']
        pending = value['pending']
        table(lines, ['Head completed us (episodes)', 'Head censored us (episodes)', 'Head open us'],
              [[str(union['completed_us']) + ' (' + str(union['completed_episodes']) + ')',
                str(union['censored_us']) + ' (' + str(union['censored_episodes']) + ')',
                pending['open_us'] if pending is not None else 'none open']])
        table(lines, ['Reason', 'Actual refusals', 'Completed us', 'Censored us', 'Open us'],
              [[row['reason'], row['refusals'], row['totals']['completed_us'],
                row['totals']['censored_us'], value['observed_at_us'] - row['pending_since_us']
                if row['pending_since_us'] is not None else 'none open']
               for row in value['reasons'] if row['refusals']])
        table(lines, ['Capacity gate', 'Actual count-only refusals'],
              [[row['reason'], row['refusals']] for row in value['capacity_refusals'] if row['refusals']])
        lines.append('Restored-source waits, deliberate builder hold, missing equations and physical '
                     'receipt latency are unavailable in this provider.')
