"""Validate exact maintained QUIC ticket latencies, independently of blocked union."""
from __future__ import annotations

STAGES = ('creation_to_first_poll', 'first_poll_to_returned_queue_acceptance',
          'queue_acceptance_to_result_latch', 'result_latch_to_upper_observation',
          'upper_observation_to_take')
TIMES = ('created_us', 'first_poll_us', 'accepted_us', 'result_us',
         'observed_us', 'taken_us', 'stopped_us')


def validate(quic, owner):
    try:
        from .buffer_metrics_report import require, uint, object_value
    except ImportError:
        from buffer_metrics_report import require, uint, object_value
    result = {'status': 'unavailable', 'issues': [], 'rows': [],
              'definition': 'Exact local ticket custody phases include scheduling. Returned queue '
                            'acceptance is not physical IP send. These latencies do not join or '
                            'extend the generic blocked union; Direct and Common consumers differ.'}
    if not isinstance(quic, dict) or 'tickets' not in quic:
        return result
    issues = result['issues']

    def identity(value):
        value = object_value(value, 'quic ticket identity')
        owner_id = uint(value.get('owner'), 'ticket owner')
        require(owner_id > 0, 'quic ticket owner must be nonzero')
        serial = uint(value.get('serial'), 'ticket serial')
        require(value.get('class') in ('User', 'Control'), 'quic ticket unknown class')
        return owner_id, serial, value['class']

    def record(value, terminal, stopped):
        value = object_value(value, 'quic ticket record')
        key = identity(value.get('identity'))
        lane = uint(value.get('lane'), 'ticket lane')
        require(lane < 2, 'quic ticket lane bound')
        consumer = value.get('consumer')
        require(consumer in ('Direct', 'Common'), 'quic ticket consumer')
        require(type(value.get('failed')) is bool, 'quic ticket failed flag')
        byte_count = uint(value.get('bytes'), 'ticket bytes')
        deadline = uint(value.get('deadline_us'), 'ticket deadline')
        times = {}
        for name in TIMES:
            require(name in value, 'quic ticket missing timestamp: ' + name)
            times[name] = uint(value[name], 'ticket ' + name, name != 'created_us')
        previous = times['created_us']
        for name in TIMES[1:]:
            current = times[name]
            if current is not None:
                require(current >= previous, 'quic ticket timestamp order')
                previous = current
        for later, earlier in (('accepted_us', 'first_poll_us'), ('result_us', 'first_poll_us'),
                               ('observed_us', 'result_us'), ('taken_us', 'observed_us')):
            require(times[later] is None or times[earlier] is not None,
                    'quic ticket missing preceding boundary')
        require(times['result_us'] is None or times['accepted_us'] is not None or value['failed'],
                'quic ticket success has no acceptance')
        require((times['stopped_us'] is not None) == terminal,
                'quic ticket terminal/live metadata mismatch')
        require(stopped is None or previous <= stopped, 'quic ticket after provider cutoff')
        user = value.get('user')
        if consumer == 'Common' and key[2] == 'User':
            user = object_value(user, 'quic Common User identity')
            uint(user.get('epoch'), 'user epoch'); uint(user.get('packet_number'), 'user number')
            config = user.get('configuration')
            require(isinstance(config, str) and len(config) == 64 and
                    all(c in '0123456789abcdef' for c in config), 'quic user configuration digest')
            require(uint(user.get('bytes'), 'user bytes') == byte_count, 'quic user byte identity')
            require(uint(user.get('deadline_us'), 'user deadline') >= deadline,
                    'quic effective deadline exceeds original user deadline')
        else:
            require(user is None, 'quic unexpected User identity')
        if schema == 2:
            pending_parser.validate_record(value, stopped, require, uint, object_value)
        return key, (lane, key[2], consumer)

    try:
        value = object_value(quic['tickets'], 'quic tickets')
        require(owner == 'maintained_quic', 'quic tickets: wrong outer owner')
        require(type(value.get('schema')) is int and value['schema'] in (1, 2),
                'quic tickets: unknown schema')
        schema = value['schema']
        try:
            from . import buffer_metrics_quic_pending as pending_parser
        except ImportError:
            import buffer_metrics_quic_pending as pending_parser
        result['pending_context'] = ('sampled_public_context' if schema == 2
                                     else 'unavailable_historical_schema')
        require(value.get('cutoff') == 'carrier_drop', 'quic tickets: unknown cutoff')
        require(type(value.get('invalid')) is bool, 'quic tickets: missing invalid flag')
        if value['invalid']:
            issues.append('quic tickets: producer invalid flag')
        require(value.get('live_capacity') == 2, 'quic tickets: wrong live capacity')
        first = uint(value.get('first_us'), 'quic tickets first', True)
        stopped = uint(value.get('stopped_us'), 'quic tickets stop', True)
        require(first is None or stopped is None or first <= stopped, 'quic tickets span order')
        pending = value.get('pending'); rows = value.get('rows')
        require(isinstance(pending, list) and len(pending) <= 2, 'quic tickets pending bound')
        require(isinstance(rows, list) and len(rows) <= 8, 'quic tickets row bound')
        require(stopped is None or not pending, 'quic tickets stopped with live cells')
        pending_keys = set(); pending_rows = {}; owners = set()
        for entry in pending:
            key, row_key = record(entry, False, stopped)
            require(key[2] not in pending_keys, 'quic tickets duplicate live class')
            pending_keys.add(key[2]); owners.add(key[0])
            pending_rows[row_key] = pending_rows.get(row_key, 0) + 1
        seen = set()
        for row in rows:
            row = object_value(row, 'quic ticket row')
            lane = uint(row.get('lane'), 'quic ticket row lane')
            key = lane, row.get('class'), row.get('consumer')
            require(lane < 2 and key[1] in ('User', 'Control') and key[2] in ('Common', 'Direct')
                    and key not in seen, 'quic tickets duplicate/invalid row')
            seen.add(key)
            counts = {n: uint(row.get(n), 'quic ticket ' + n)
                      for n in ('created', 'completed', 'failed', 'censored')}
            require(counts['created'] > 0 and counts['created'] == counts['completed'] +
                    counts['failed'] + counts['censored'] + pending_rows.get(key, 0),
                    'quic tickets outcome accounting')
            last = row.get('last')
            if counts['completed'] + counts['failed'] + counts['censored']:
                last_id, last_key = record(last, True, stopped)
                require(last_key == key, 'quic tickets last row identity')
                owners.add(last_id[0])
            else:
                require(last is None, 'quic tickets unexpected last record')
            stages = row.get('stages')
            require(isinstance(stages, list) and len(stages) == len(STAGES),
                    'quic tickets incomplete stages')
            stage_names = set()
            for span in stages:
                span = object_value(span, 'quic ticket stage')
                name = span.get('stage')
                require(name in STAGES and name not in stage_names, 'quic tickets unknown/duplicate stage')
                stage_names.add(name)
                values = {n: uint(span.get(n), 'quic ticket stage ' + n) for n in
                          ('completed', 'failed', 'censored', 'completed_us', 'failed_us', 'censored_us')}
                count = values['completed'] + values['failed'] + values['censored']
                total = values['completed_us'] + values['failed_us'] + values['censored_us']
                maximum = uint(span.get('maximum_us'), 'quic ticket maximum', True)
                require(count <= counts['created'], 'quic tickets stage count exceeds tickets')
                for outcome in ('completed', 'failed', 'censored'):
                    require(values[outcome] != 0 or values[outcome + '_us'] == 0,
                            'quic tickets duration without samples')
                if count:
                    require(maximum is not None and maximum <= total <= count * maximum,
                            'quic tickets maximum/sum mismatch')
                    max_id = identity(span.get('maximum_identity'))
                    require(max_id[2] == key[1], 'quic tickets maximum class mismatch')
                    owners.add(max_id[0])
                else:
                    require(maximum is None and span.get('maximum_identity') is None,
                            'quic tickets absent phase fabricated as zero')
            if schema == 2:
                require('maximum_pending' in row, 'quic missing Pending maximum')
                maximum = row['maximum_pending']
                if maximum is not None:
                    max_id, max_key = record(maximum, True, stopped)
                    require(max_key == key, 'quic Pending maximum row identity')
                    owners.add(max_id[0])
                    elapsed = pending_parser.validate_record(
                        maximum, stopped, require, uint, object_value)
                    require(elapsed is not None, 'quic Pending maximum has no observed interval')
                    total_max = next(s['maximum_us'] for s in stages if s['stage'] == STAGES[1])
                    require(total_max is not None and elapsed <= total_max,
                            'quic Pending maximum exceeds full acceptance stage')
                    if last is not None:
                        last_elapsed = pending_parser.validate_record(
                            last, stopped, require, uint, object_value)
                        require(last_elapsed is None or last_elapsed <= elapsed,
                                'quic Pending maximum smaller than last interval')
                elif last is not None:
                    require(last['pending_observation']['polls'] == 0,
                            'quic missing observed Pending maximum')
            result['rows'].append(row)
        require(set(pending_rows) <= seen, 'quic tickets live cell without summary')
        require(len(owners) <= 1, 'quic tickets mixed actual owners')
        require((first is not None) == bool(rows), 'quic tickets first observation availability')
        result.update(status='invalid' if issues else
                      ('validated_ticket_latencies' if rows else 'no_tickets_observed'),
                      cutoff=value['cutoff'], first_us=first, stopped_us=stopped)
    except (ValueError, TypeError, KeyError) as error:
        issues.append('quic tickets: ' + str(error)); result['status'] = 'invalid'
    return result


def render(lines, observation, table, cell):
    lines.extend(['', 'QUIC ticket provider: ' + cell(observation['status']) + '. ' +
                  observation['definition']])
    if observation['status'] != 'validated_ticket_latencies':
        return
    table(lines, ['Lane', 'Class', 'Consumer', 'Stage', 'Completed', 'Completed us',
                  'Failed', 'Failed us', 'Censored', 'Censored us', 'Maximum us'],
          [[row['lane'], row['class'], row['consumer'], stage['stage'],
            stage['completed'], stage['completed_us'], stage['failed'], stage['failed_us'],
            stage['censored'], stage['censored_us'], stage['maximum_us']]
           for row in observation['rows'] for stage in row['stages']
           if stage['completed'] + stage['failed'] + stage['censored']])

    if observation.get('pending_context') == 'sampled_public_context':
        try:
            from . import buffer_metrics_quic_pending as pending_parser
        except ImportError:
            import buffer_metrics_quic_pending as pending_parser
        pending_parser.render(lines, observation['rows'], table)
    else:
        lines.extend(['', 'QUIC Pending context: unavailable in historical ticket schema 1.'])
