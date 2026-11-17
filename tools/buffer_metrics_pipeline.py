"""Validate isolated Pipeline FIFO-head waits without computing a combined union."""
from __future__ import annotations

REASONS = ('native_delivery_window', 'swift_packing_queue', 'codec_stage',
           'connection_retirement', 'connection_unreliable_slot')
U64_MAX = (1 << 64) - 1


def validate(value):
    result = {'status': 'unavailable', 'issues': [], 'coverage_gaps': [], 'flows': [],
              'definition': 'Observed same-flow FIFO-head refusal through actual admission. '
                            'Includes scheduling delay. Per-reason durations belong to their flow head; '
                            'different flow rows and generic waits overlap and are not summed '
                            'or assigned a combined percentage.'}
    if value is None:
        return result
    issues, gaps = result['issues'], result['coverage_gaps']

    def require(ok, text):
        if not ok:
            raise ValueError('pipeline_admission: ' + text)

    def number(obj, key, nullable=False):
        require(key in obj, 'missing ' + key)
        number = obj[key]
        require((nullable and number is None) or
                (type(number) is int and 0 <= number <= U64_MAX), 'invalid ' + key)
        return number

    def totals(obj, name, terminal):
        require(isinstance(obj, dict), name + ' must be an object')
        parsed = {key: number(obj, key) for key in (
            'episodes', 'completed_episodes', 'completed_us', 'censored_episodes',
            'censored_us', 'maximum_us')}
        parsed['open_us'] = number(obj, 'open_us', True)
        expected = (parsed['completed_episodes'] + parsed['censored_episodes'] +
                    int(parsed['open_us'] is not None))
        if parsed['episodes'] != expected:
            issues.append(name + ': inconsistent episode counts')
        observed = parsed['completed_us'] + parsed['censored_us'] + (parsed['open_us'] or 0)
        if observed > U64_MAX or parsed['maximum_us'] > observed:
            issues.append(name + ': inconsistent duration totals')
        for kind in ('completed', 'censored'):
            if not parsed[kind + '_episodes'] and parsed[kind + '_us']:
                issues.append(name + ': duration without corresponding episode')
        if terminal is not None and parsed['open_us'] is not None:
            issues.append(name + ': terminal provider retains an open interval')
        return parsed

    try:
        require(isinstance(value, dict), 'provider must be an object')
        limit = number(value, 'flow_limit')
        require(1 <= limit <= 256, 'flow limit exceeds the diagnostic bound')
        retained = number(value, 'retained_flows')
        terminal = number(value, 'terminal_at_us', True)
        for key in ('identity_errors', 'clock_regressions', 'after_terminal'):
            if number(value, key):
                issues.append('pipeline_admission: nonzero ' + key)
        require(type(value.get('counter_overflow')) is bool, 'invalid overflow flag')
        if value['counter_overflow']:
            issues.append('pipeline_admission: counter overflow')
        for key in ('omitted_refusals', 'unavailable_terminal'):
            if number(value, key):
                gaps.append(key + '=' + str(value[key]))
        rows = value.get('flows')
        require(isinstance(rows, list) and len(rows) == retained and retained <= limit,
                'flow rows differ from retained count or limit')
        keys = set()
        for row in rows:
            require(isinstance(row, dict), 'flow row must be an object')
            epoch = number(row, 'epoch')
            flow = number(row, 'flow_id')
            channel = number(row, 'channel')
            require(channel <= 255, 'channel is outside the common bound')
            digest = row.get('configuration_digest_hex')
            require(isinstance(digest, str) and len(digest) == 64 and
                    all(c in '0123456789abcdef' for c in digest), 'invalid digest')
            key = (epoch, digest, flow, channel)
            require(key not in keys, 'duplicate full flow identity')
            keys.add(key)
            first, last = number(row, 'first_refusal_us'), number(row, 'last_event_us')
            retired = number(row, 'retired_at_us', True)
            if last < first or (terminal is not None and last > terminal):
                issues.append('pipeline_admission: flow timestamps exceed source boundary')
            if retired is not None and retired != last:
                issues.append('pipeline_admission: retired row was subsequently updated')
            head = totals(row.get('blocked_heads'), 'pipeline FIFO head', terminal)
            reasons = row.get('reasons')
            require(isinstance(reasons, list) and len(reasons) == len(REASONS),
                    'reason set incomplete')
            seen, parsed_reasons = set(), []
            for cause in reasons:
                require(isinstance(cause, dict), 'reason must be an object')
                name = cause.get('reason')
                require(name in REASONS and name not in seen, 'unknown or duplicate reason')
                seen.add(name)
                refusals = number(cause, 'refusals')
                blocked = totals(cause.get('blocked'), 'pipeline ' + name, terminal)
                if blocked['episodes'] > refusals:
                    issues.append('pipeline_admission: more reason episodes than refusals')
                parsed_reasons.append({'reason': name, 'refusals': refusals, 'blocked': blocked})
            # A row records one observed first-refusal cause at a time. Cause
            # changes partition only this FIFO-head time, not other flows or
            # the generic collector union. Category subtotals need not match:
            # an earlier cause can complete while the whole head is censored.
            def observed_time(totals):
                return totals['completed_us'] + totals['censored_us'] + (totals['open_us'] or 0)

            if sum(observed_time(cause['blocked']) for cause in parsed_reasons) != observed_time(head):
                issues.append('pipeline_admission: first-refusal reason time does not partition its flow-head time')
            result['flows'].append({'epoch': epoch, 'configuration_digest_hex': digest,
                                    'flow_id': flow, 'channel': channel,
                                    'first_refusal_us': first, 'last_event_us': last,
                                    'retired_at_us': retired, 'blocked_heads': head,
                                    'reasons': parsed_reasons})
        gaps.append('Ingress/flow-table capacity, per-flow occupancy, MUX internals and '
                    'intentional DRR/packing holds are not timed by this provider.')
        result['status'] = 'invalid_observations' if issues else 'parsed_partial_coverage'
    except ValueError as error:
        issues.append(str(error))
        result['status'] = 'invalid_observations'
    return result


def render(lines, provider, table, cell):
    lines.extend(['', 'Pipeline admission provider: ' + cell(provider['status']) + '. ' +
                  provider['definition']])
    lines.extend('- ' + cell(gap) for gap in provider['coverage_gaps'])
    if provider['flows']:
        table(lines, ['Epoch / digest / flow / channel', 'Completed us (heads)',
                      'Censored us (heads)', 'Open us', 'Maximum us'],
              [[' / '.join((str(row['epoch']), row['configuration_digest_hex'],
                            str(row['flow_id']), str(row['channel']))),
                f"{row['blocked_heads']['completed_us']} ({row['blocked_heads']['completed_episodes']})",
                f"{row['blocked_heads']['censored_us']} ({row['blocked_heads']['censored_episodes']})",
                row['blocked_heads']['open_us'], row['blocked_heads']['maximum_us']]
               for row in provider['flows']])
        reasons = [(row, cause) for row in provider['flows'] for cause in row['reasons']
                   if cause['refusals'] or cause['blocked']['episodes']]
        if reasons:
            lines.extend(['', 'Observed first-refusal causes within each flow head; these '
                          'segments partition that head only. No cross-flow or generic '
                          'wait total is calculated.'])
            table(lines, ['Epoch / digest / flow / channel', 'Reason', 'Refusals',
                          'Completed us (segments)', 'Censored us (segments)',
                          'Open us', 'Maximum us'],
                  [[' / '.join((str(row['epoch']), row['configuration_digest_hex'],
                                str(row['flow_id']), str(row['channel']))),
                    cause['reason'], cause['refusals'],
                    f"{cause['blocked']['completed_us']} ({cause['blocked']['completed_episodes']})",
                    f"{cause['blocked']['censored_us']} ({cause['blocked']['censored_episodes']})",
                    cause['blocked']['open_us'], cause['blocked']['maximum_us']]
                   for row, cause in reasons])
