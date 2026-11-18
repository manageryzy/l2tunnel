"""Validate bounded Rolling sidecar facts without merging unrelated owner durations."""
SITES = ('source_admission', 'decoded_handoff', 'feedback_budget')
REASONS = ('recovery_busy', 'recovery_capacity', 'record_busy', 'record_capacity',
           'record_window', 'packet_budget', 'wire_byte_budget')
U64_MAX = (1 << 64) - 1


def validate(value, epoch, path, issues, gaps):
    """Validate known nested fields, preserve nulls, and report incomplete coverage."""
    def need(ok, message):
        if not ok:
            raise ValueError(path + ': ' + message)

    def obj(value):
        need(isinstance(value, dict), 'expected object')
        return value

    def number(value, key, nullable=False):
        need(key in value, 'missing ' + key)
        result = value[key]
        if result is None and nullable:
            return result
        need(type(result) is int and 0 <= result <= U64_MAX, 'invalid ' + key)
        return result

    def boolean(value, key):
        need(type(value.get(key)) is bool, 'invalid ' + key)
        return value[key]

    def totals(value):
        value = obj(value)
        result = []
        for kind in ('completed', 'censored'):
            count = number(value, kind + '_episodes')
            elapsed = number(value, kind + '_us')
            maximum = number(value, 'maximum_' + kind + '_us')
            need(maximum <= elapsed and (count > 0 or elapsed == maximum == 0),
                 'inconsistent ' + kind + ' totals')
            result.append((count, elapsed))
        return result

    def operation(value, site):
        value = obj(value)
        identity = number(value, 'id')
        need(identity < (1 << 32) if site < 2 else identity > 0, 'invalid operation id')
        need(number(value, 'bytes') > 0, 'empty retained operation')
        deadline = number(value, 'original_deadline_us', True)
        if deadline is None:
            gaps.append(path + ': original operation deadline unavailable')
        packets, wire = number(value, 'packets'), number(value, 'wire_bytes')
        copies = number(value, 'copies')
        if site == 2:
            need(packets > 0 and wire >= value['bytes'] and copies == 0, 'invalid feedback debit')
        else:
            need(packets == wire == 0 and (1 <= copies <= 4 if site == 0 else copies == 0),
                 'invalid source operation geometry')
        return deadline

    if value is None:
        gaps.append(path + ': Rolling/Research wait timing unavailable')
        return
    value = obj(value)
    need(number(value, 'epoch') == epoch, 'epoch identity mismatch')
    need(number(value, 'instance') > 0 and number(value, 'stream') <= (1 << 32) - 1,
         'invalid local identity')
    direction = number(value, 'send_direction')
    need(direction in (0, 1), 'invalid direction')
    session = value.get('session_hex')
    need(isinstance(session, str) and len(session) == 32 and
         all(c in '0123456789abcdef' for c in session), 'invalid full session identity')
    for key in ('clock_regression', 'identity_mismatch', 'counter_overflow'):
        if boolean(value, key):
            issues.append(path + ': producer invalid flag ' + key)
    observed = number(value, 'observed_at_us')
    terminal = number(value, 'terminal_at_us', True)
    boundary = value.get('terminal_stage')
    need((terminal is None and boundary is None) or
         (terminal == observed and boundary in
          ('owner_failure', 'pre_settlement_metric_stop', 'driver_drop')),
         'inconsistent terminal boundary')
    sites = value.get('sites')
    need(isinstance(sites, list) and len(sites) == 3, 'invalid site bound')
    for index, (name, row) in enumerate(zip(SITES, sites)):
        row = obj(row)
        need(row.get('site') == name, 'unknown/duplicate/out-of-order site')
        need(number(row, 'direction') == (direction if index == 0 else direction ^ 1),
             'site direction mismatch')
        need(row.get('deadline_owner') ==
             ('codec_stage', 'decoder_handoff_cohort', 'immutable_feedback_output')[index],
             'wrong deadline owner')
        union = totals(row.get('union'))
        need('pending' in row and 'last_resolved' in row, 'missing operation availability')
        pending = row['pending']
        opened = 0
        first = None
        if pending is not None:
            pending = obj(pending)
            cap = operation(pending.get('operation'), index)
            first = number(pending, 'since_us')
            last = number(pending, 'last_refusal_us')
            opened = number(pending, 'open_us', True)
            need(terminal is None and first <= last <= observed and
                 opened == observed - first and (cap is None or last < cap),
                 'invalid open operation interval')
        reasons = row.get('reasons')
        need(isinstance(reasons, list) and len(reasons) == 7, 'invalid reason bound')
        refusals = 0
        for ri, (name, reason) in enumerate(zip(REASONS, reasons)):
            reason = obj(reason)
            need(reason.get('reason') == name, 'unknown/duplicate/out-of-order reason')
            count = number(reason, 'refusals')
            refusals += count
            populations = totals(reason.get('totals'))
            since = number(reason, 'pending_since_us', True)
            allowed = ri in ((0, 1) if index == 0 else range(5) if index == 1 else (5, 6))
            need(allowed or (count == 0 and populations == [(0, 0), (0, 0)] and since is None),
                 'reason belongs to a different site')
            if since is not None:
                need(first is not None and first <= since <= observed, 'reason without same open operation')
            need(sum(v[0] for v in populations) + int(since is not None) <= count,
                 'reason episodes exceed actual refusals')
            need(all(p[1] <= u[1] for p, u in zip(populations, union)),
                 'reason duration exceeds same-site union')
        need(sum(v[0] for v in union) + int(pending is not None) <= refusals <= U64_MAX,
             'union episodes exceed actual refusals')
        need(sum(v[1] for v in union) + opened <= observed, 'site durations exceed observation time')
        resolved = row['last_resolved']
        if resolved is not None:
            resolved = obj(resolved)
            cap = operation(resolved.get('operation'), index)
            began, ended = number(resolved, 'since_us'), number(resolved, 'at_us')
            censored = boolean(resolved, 'censored')
            need(began <= ended <= observed and (cap is None or began < cap),
                 'invalid resolved operation time')
            need(union[int(censored)][0] > 0, 'resolved operation lacks matching population')
        if terminal is not None:
            need(pending is None, 'terminal owner still has an open operation')
    try:
        from .buffer_metrics_rolling_ingress import validate as validate_ingress
    except ImportError:
        from buffer_metrics_rolling_ingress import validate as validate_ingress
    validate_ingress(value.get('ingress_admission'), observed, terminal, direction,
                     path + '.ingress_admission', issues, gaps)
    gaps.append(path + ': work slices, feedback construction and other ingress dependencies remain unavailable; '
                'site/reason durations are not merged into generic runtime union')
