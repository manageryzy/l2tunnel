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
    if 'staged_source' in value:
        validate_staged(value['staged_source'], observed, terminal, path + '.staged_source', issues, gaps)
    else:
        gaps.append(path + ': exact staged source maximum/native identity unavailable in this receipt')
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
        render_staged(lines, value.get('staged_source'), table, cell)
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


def validate_staged(value, observed, terminal, path, issues, gaps):
    """Validate bounded identity attachments without treating them as another wait union."""
    def need(ok, text):
        if not ok:
            raise ValueError(path + ': ' + text)

    def obj(value):
        need(isinstance(value, dict), 'expected object')
        return value

    def num(value, key, nullable=False):
        need(key in value, 'missing ' + key)
        v = value[key]
        need((v is None and nullable) or (type(v) is int and 0 <= v <= U64_MAX), 'invalid ' + key)
        return v

    def flag(value, key):
        need(type(value.get(key)) is bool, 'invalid ' + key)
        return value[key]

    def retirement(value):
        if value is None:
            return
        value = obj(value)
        need(num(value, 'serial') > 0 and num(value, 'observed_us') <= observed, 'invalid retirement')
        accepted = num(value, 'accepted_us', True)
        need(value.get('kind') in ('input', 'physical'), 'unknown retirement kind')
        need((accepted is None) == (value['kind'] == 'input'), 'wrong acceptance boundary')
        if flag(value, 'operation_succeeded') and accepted is not None:
            need(accepted <= value['observed_us'], 'invalid successful physical time')
        need(num(value, 'records') > 0, 'no actual source retention released')
        num(value, 'bytes')

    def ack(value):
        if value is None:
            return
        value = obj(value)
        need(num(value, 'serial') > 0, 'invalid ACK serial')
        arrived, applied = num(value, 'received_us'), num(value, 'observed_us')
        need(arrived <= applied <= observed, 'invalid ACK input/application time')
        prefix, bitmap = num(value, 'prefix'), num(value, 'bitmap')
        need(bitmap & 1 == 0 and (not bitmap or prefix + bitmap.bit_length() - 1 <= U64_MAX),
             'noncanonical ACK coverage')
        released = num(value, 'released_records'); byte_count = num(value, 'released_bytes')
        need(released > 0 or byte_count == 0, 'ACK byte release without actual source retirement')
        need('before' in value and 'after' in value, 'missing ACK oldest availability')
        before, after = value['before'], value['after']
        for oldest in (before, after):
            if oldest is None:
                continue
            oldest = obj(oldest)
            need(num(oldest, 'source') < U64_MAX and num(oldest, 'attempts') < (1 << 32),
                 'invalid ACK oldest identity')
            transmission = num(oldest, 'transmission'); retry = num(oldest, 'retry_at_us', True)
            held = flag(oldest, 'physical_pending'); acknowledged = flag(oldest, 'acknowledged')
            need(held == (transmission != 0), 'ACK physical witness/serial mismatch')
            need(not held or retry is None, 'held physical attempt has a retry timer')
            need(not acknowledged or held, 'ACKed source retained without physical custody')
        need('covers_before' in value and 'retired_before' in value, 'missing ACK outcome availability')
        if before is None:
            need(after is None and value['covers_before'] is None and value['retired_before'] is None
                 and released == byte_count == 0, 'ACK invented oldest or release')
        else:
            offset = before['source'] - prefix
            covered = before['source'] < prefix or (0 <= offset < 64 and bool(bitmap & (1 << offset)))
            retired = after is None or after['source'] != before['source']
            need(flag(value, 'covers_before') == covered, 'wrong ACK coverage predicate')
            need(flag(value, 'retired_before') == retired, 'wrong actual oldest retirement')
            need(not retired or (covered and released > 0), 'oldest retirement without ACK/release')
            need(after is None or after['source'] >= before['source'], 'ACK moved oldest backwards')
            if covered and not retired:
                need(after['acknowledged'] and after['physical_pending'],
                     'covered oldest neither retired nor physically held')

    def gate(value, source, length):
        value = obj(value)
        need(num(value, 'next_source') == source and num(value, 'proposed_bytes') == length,
             'gate belongs to another source')
        records, record_cap = num(value, 'records'), num(value, 'records_capacity')
        used, cap = num(value, 'bytes'), num(value, 'bytes_capacity')
        need(record_cap > 0 and cap > 0 and records <= record_cap and used <= cap, 'invalid capacity')
        resulting = num(value, 'resulting_bytes')
        need(resulting == used + length, 'wrong proposed byte total')
        base = num(value, 'span_base', True)
        need(base is None or base <= source, 'invalid source span')
        need(flag(value, 'records_full') == (records >= record_cap), 'wrong count predicate')
        need(flag(value, 'bytes_full') == (resulting > cap), 'wrong byte predicate')
        need(flag(value, 'sequence_full') == (base is not None and source - base >= record_cap),
             'wrong sequence predicate')
        need(any(value[k] for k in ('records_full', 'bytes_full', 'sequence_full')), 'no actual gate refusal')
        need('oldest' in value, 'missing oldest availability')
        oldest = value['oldest']
        need((oldest is None) == (records == 0), 'wrong oldest availability')
        if oldest is not None:
            oldest = obj(oldest)
            need(num(oldest, 'source') == base, 'oldest/span mismatch')
            num(oldest, 'attempts'); num(oldest, 'transmission'); num(oldest, 'retry_at_us', True)
            flag(oldest, 'acknowledged')

    def pending(value):
        value = obj(value)
        source, length = num(value, 'source'), num(value, 'bytes')
        need(length <= 65535, 'invalid source length')
        start, last = num(value, 'since_us'), num(value, 'last_refusal_us')
        need(start <= last <= observed, 'invalid refusal clock')
        num(value, 'retirement_before')
        if schema == 2:
            need(num(value, 'ack_before') <= last_ack_serial,
                 'wait ACK start serial exceeds owner history')
        for name in ('first_gate', 'last_gate'):
            gate(value.get(name), source, length)
        need('unit' in value and 'native' in value, 'missing identity availability')
        unit, native = value['unit'], value['native']
        if unit is not None:
            unit = obj(unit)
            need(num(unit, 'channel') < 256, 'invalid Aligned channel')
            record, native_record = num(unit, 'record'), num(unit, 'native_record')
            need(native_record == record + int(flag(unit, 'context')), 'wrong context/native identity')
            num(unit, 'offset')
        if native is not None:
            native = obj(native)
            need(unit is not None, 'native provenance without actual unit')
            num(native, 'flow'); num(native, 'deadline_us', True)
            need(num(native, 'received_us') <= num(native, 'queued_us') <= start,
                 'native provenance predates/does not match original staging')
        return start, last

    value = obj(value)
    schema = value.get('schema')
    need(type(schema) is int and schema in (1, 2), 'unknown schema')
    if schema == 2:
        coverage = value.get('ack_coverage')
        need(coverage in ('selected_selective', 'unavailable'), 'unknown ACK coverage')
        need('last_ack' in value, 'missing ACK observation availability')
        ack(value['last_ack'])
        last_ack_serial = value['last_ack']['serial'] if value['last_ack'] is not None else 0
        need(coverage != 'unavailable' or value['last_ack'] is None,
             'ACK observation for unsupported owner')
        if coverage == 'unavailable':
            gaps.append(path + ': selected shared SelectiveRepeat ACK boundary unavailable')
    else:
        gaps.append(path + ': exact validated ACK/oldest attribution unavailable in schema 1')
    if flag(value, 'invalid'):
        issues.append(path + ': producer invalid identity/time/counter flag')
    need(num(value, 'terminal_at_us', True) == terminal, 'terminal boundary mismatch')
    for key in ('pending', 'last_resolved', 'maximum_completed', 'maximum_censored', 'last_retirement'):
        need(key in value, 'missing ' + key)
    if value['pending'] is not None:
        need(terminal is None, 'open source after terminal')
        pending(value['pending'])
    retirement(value['last_retirement'])
    durations = {}
    for key in ('last_resolved', 'maximum_completed', 'maximum_censored'):
        resolved = value[key]
        if resolved is None:
            continue
        resolved = obj(resolved)
        start, last = pending(resolved.get('pending'))
        at, censored = num(resolved, 'at_us'), flag(resolved, 'censored')
        need(last <= at <= observed, 'invalid resolution time')
        need(not censored or (terminal == at), 'censor without exact terminal')
        need(key != 'maximum_completed' or not censored, 'wrong completed population')
        need(key != 'maximum_censored' or censored, 'wrong censored population')
        need('latest_retirement' in resolved, 'missing retirement availability')
        event = resolved['latest_retirement']
        retirement(event)
        if event is not None:
            need(event['serial'] > resolved['pending']['retirement_before'] and event['observed_us'] <= at,
                 'retirement outside same wait')
        if schema == 2:
            need('latest_ack' in resolved, 'missing same-episode ACK availability')
            event = resolved['latest_ack']
            ack(event)
            if event is not None:
                need(coverage == 'selected_selective' and value['last_ack'] is not None,
                     'episode ACK without supported observed owner')
                need(event['serial'] > resolved['pending']['ack_before']
                     and event['serial'] <= value['last_ack']['serial']
                     and start <= event['observed_us'] <= at,
                     'ACK outside same wait/owner observation')
        durations[key] = (at - start, censored)
    if 'last_resolved' in durations:
        elapsed, censored = durations['last_resolved']
        winner = 'maximum_censored' if censored else 'maximum_completed'
        need(winner in durations and durations[winner][0] >= elapsed, 'maximum lost its identity')
    gaps.append(path + ': maxima attach to existing staged wait timing; no second union; native identity is '
                'earlier admitted original, not the later refused FIFO head; latest retirement/ACK is not sole-cause proof')


def render_staged(lines, value, table, cell):
    if not isinstance(value, dict):
        return
    lines.extend(['', 'Exact staged-source identities (same existing staged wait episodes). '
                  'These are earlier held sources; later refused FIFO heads remain separate. '
                  'An actual retention release does not alone prove it enabled this source.'])
    rows = []
    for key in ('maximum_completed', 'maximum_censored', 'last_resolved'):
        row = value.get(key)
        if row is None:
            continue
        item = row['pending']; unit = item['unit']; native = item['native']; gate = item['last_gate']
        rows.append([key, item['source'], row['at_us'] - item['since_us'],
                     unit['channel'] if unit is not None else 'unavailable',
                     unit['native_record'] if unit is not None else 'unavailable',
                     native['flow'] if native is not None else 'unavailable',
                     str(gate['records']) + '/' + str(gate['records_capacity']), gate['span_base'],
                     ', '.join(k for k in ('records_full', 'bytes_full', 'sequence_full') if gate[k])])
    table(lines, ['Population', 'Source', 'Episode us', 'Channel', 'Native record', 'Original flow',
                  'Records/cap', 'Span base', 'Actual latest predicates'], rows)
    render_staged_ack(lines, value, table, cell)


def render_staged_ack(lines, value, table, cell):
    if value.get('schema') != 2:
        lines.append('Exact validated ACK/oldest attribution: unavailable in this receipt schema.')
        return
    coverage = value['ack_coverage']
    lines.append('Validated ACK boundary: ' + cell(coverage) + '. ACK coverage, acknowledged held '
                 'physical retry, and actual source retirement are distinct. Latest ACK is context, '
                 'not proof that it alone released a staged source. No ACK event history is retained.')
    rows = []
    for name, event in [('last_ack', value['last_ack']),
                        *((name, value[name]['latest_ack']) for name in
                          ('maximum_completed', 'maximum_censored', 'last_resolved') if value[name] is not None)]:
        if event is None:
            continue
        before, after = event['before'], event['after']
        rows.append([name, event['serial'], event['prefix'], event['bitmap'],
                     event['received_us'], event['observed_us'],
                     before['source'] if before else 'none', event['covers_before'],
                     after['source'] if after else 'none',
                     after['acknowledged'] if after else 'unavailable',
                     after['physical_pending'] if after else 'unavailable',
                     event['retired_before'], event['released_records']])
    table(lines, ['Context', 'ACK serial', 'Prefix', 'Bitmap', 'Received us', 'Applied us',
                  'Oldest before', 'Covered', 'Oldest after', 'ACKed after', 'Physical held after',
                  'Oldest retired', 'Sources released'], rows)
