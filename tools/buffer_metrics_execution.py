"""Validate bounded execution observations without treating wall time as blockage."""
from __future__ import annotations

STAGES = (
    'CommonTurnSpacing', 'CommonReceiptProgress', 'CommonAdmission',
    'CommonProtocolProgress', 'CommonManagement', 'CommonSend', 'CommonReceive',
    'CommonCarrierReceive', 'CommonDeadlineService', 'CommonSnapshot',
    'CommonNativeWrite', 'CommonNativeRead', 'CommonBufferSampling',
    'CliProjection', 'CliEncoding', 'CliFlush', 'CliFileWrite',
)
STAGES_V2 = STAGES[:13] + ('CommonWakePlanning', 'CommonSelectPoll', 'CommonSelectPending') + STAGES[13:]
WINNERS = ('Shutdown', 'Request', 'Carrier', 'Native', 'Timer', 'IoError')
BOUNDARIES = {'loop_stop_before_settlement': 'loop_stop',
              'driver_future_drop': 'driver_future_drop'}


def validate(value, owner):
    try:
        from .buffer_metrics_report import require, uint, object_value
    except ImportError:
        from buffer_metrics_report import require, uint, object_value
    result = {'status': 'unavailable', 'issues': [], 'stages': [],
              'selection': {'status': 'unavailable'},
              'definition': 'Owner-local execution wall spans include scheduling; '
                            'overlapping stages are not CPU time or buffer-blocked intervals.'}
    if value is None:
        return result
    issues = result['issues']
    try:
        value = object_value(value, 'common_execution')
        require(owner == 'common', 'common_execution: wrong actual owner')
        if value.get('availability') == 'unavailable':
            require(value.get('reason') in ('diagnostic_initialization_failed', 'disabled',
                                           'loop_stop_not_observed'),
                    'common_execution: unknown unavailable reason')
            require(value.get('timing') is None and value.get('boundary') is None,
                    'common_execution: unavailable observation retains timing')
            result['reason'] = value['reason']
            return result
        require(value.get('availability') == 'observed', 'common_execution: unknown availability')
        boundary = value.get('boundary')
        require(isinstance(boundary, str) and boundary in BOUNDARIES,
                'common_execution: unknown boundary')
        timing = object_value(value.get('timing'), 'common_execution.timing')
        require(type(timing.get('schema')) is int and timing['schema'] in (1, 2) and
                timing.get('event') == 'execution_timing' and timing.get('owner') == 'CommonExecution',
                'common_execution: unknown timing schema/owner/event')
        require(timing.get('checkpoint') == BOUNDARIES[boundary],
                'common_execution: boundary/checkpoint mismatch')
        elapsed = uint(timing.get('elapsed_us'), 'common_execution.elapsed_us')
        require(type(timing.get('invalid')) is bool, 'common_execution: missing invalid flag')
        if timing['invalid']:
            issues.append('common_execution: producer invalid flag')
        for name in ('id', 'pid', 'inline_bytes', 'diagnostic_heap_bytes'):
            uint(timing.get(name), 'common_execution.' + name)
        expected = STAGES if timing['schema'] == 1 else STAGES_V2
        stages = timing.get('stages')
        require(isinstance(stages, list) and len(stages) == len(expected),
                'common_execution: incomplete or oversized stage array')
        seen = set()
        for row in stages:
            row = object_value(row, 'common_execution.stage')
            name = row.get('stage')
            require(isinstance(name, str) and name in expected and name not in seen,
                    'common_execution: duplicate or unknown stage')
            seen.add(name)
            counts = {key: uint(row.get(key), 'common_execution.' + key)
                      for key in ('samples', 'sum_us', 'max_us', 'failed', 'censored')}
            start = uint(row.get('maximum_start_us'), 'common_execution.maximum_start_us', True)
            end = uint(row.get('maximum_end_us'), 'common_execution.maximum_end_us', True)
            require('maximum_start_us' in row and 'maximum_end_us' in row,
                    'common_execution: missing maximum timestamps')
            if counts['failed'] + counts['censored'] > counts['samples']:
                issues.append(name + ': outcome count exceeds samples')
            if (counts['max_us'] > counts['sum_us'] or counts['max_us'] > elapsed
                    or counts['sum_us'] > counts['samples'] * counts['max_us']):
                issues.append(name + ': impossible maximum')
            if not counts['samples'] and any(counts[key] for key in ('sum_us', 'max_us', 'failed', 'censored')):
                issues.append(name + ': values without samples')
            if (start is None) != (end is None):
                issues.append(name + ': incomplete maximum timestamps')
            elif start is not None:
                # Individually truncated endpoint microseconds can differ by one
                # from the separately truncated duration of the same interval.
                if end < start or end > elapsed or end - start not in (counts['max_us'], counts['max_us'] + 1):
                    issues.append(name + ': inconsistent maximum interval')
                if not counts['samples']:
                    issues.append(name + ': maximum timestamps without samples')
            elif counts['samples']:
                issues.append(name + ': missing observed maximum interval')
            result['stages'].append({'stage': name, **counts,
                                     'maximum_start_us': start, 'maximum_end_us': end})
        if timing['schema'] == 1:
            require('selection' not in timing, 'common_execution: schema1 has unknown selection')
            result['selection'] = {'status': 'unavailable_historical_schema'}
        else:
            result['selection'] = validate_selection(timing.get('selection'), elapsed, boundary,
                                                     require, uint, object_value)
        result.update(boundary=boundary, elapsed_us=elapsed,
                      status='invalid_observations' if issues else 'validated_wall_spans')
    except ValueError as error:
        issues.append(str(error))
        result['status'] = 'invalid_or_unrecognized_shape'
    return result


def validate_selection(value, elapsed, boundary, require, uint, object_value):
    value = object_value(value, 'common_execution.selection')
    completed = uint(value.get('completed'), 'selection.completed')
    rows = value.get('winners')
    require(isinstance(rows, list) and len(rows) == len(WINNERS),
            'selection: incomplete or oversized winner array')
    winners = {}
    for row in rows:
        row = object_value(row, 'selection.winner')
        name = row.get('winner')
        require(isinstance(name, str) and name in WINNERS and name not in winners,
                'selection: duplicate or unknown winner')
        winners[name] = uint(row.get('count'), 'selection.count')
    require(sum(winners.values()) == completed, 'selection: winner count mismatch')
    require('maximum_lateness' in value and 'interrupted' in value and
            'pending_planned_wake_us' in value, 'selection: missing observation field')
    require(value['pending_planned_wake_us'] is None,
            'selection: frozen timing retains pending selection')
    maximum = value['maximum_lateness']
    require((maximum is None) == (completed == 0),
            'selection: maximum availability differs from completed count')
    if maximum is not None:
        maximum = object_value(maximum, 'selection.maximum_lateness')
        planned = uint(maximum.get('planned_wake_us'), 'selection.planned_wake_us')
        entered = uint(maximum.get('poll_entered_at_us'), 'selection.poll_entered_at_us')
        observed = uint(maximum.get('observed_at_us'), 'selection.observed_at_us')
        lateness = uint(maximum.get('lateness_us'), 'selection.lateness_us')
        winner = maximum.get('winner')
        require(isinstance(winner, str) and winner in winners and winners[winner] > 0,
                'selection: maximum winner never completed')
        require(entered <= observed <= elapsed and lateness <= entered and
                max(0, entered - planned) in (lateness, lateness + 1),
                'selection: impossible resume lateness')
        maximum = dict(planned_wake_us=planned, poll_entered_at_us=entered, observed_at_us=observed,
                       lateness_us=lateness, winner=winner)
    interrupted = value['interrupted']
    if interrupted is not None:
        interrupted = object_value(interrupted, 'selection.interrupted')
        planned = uint(interrupted.get('planned_wake_us'), 'selection.interrupted.planned_wake_us')
        observed = uint(interrupted.get('observed_at_us'), 'selection.interrupted.observed_at_us')
        require(boundary == 'driver_future_drop' and observed == elapsed,
                'selection: interruption is not actual cancellation cutoff')
        interrupted = dict(planned_wake_us=planned, observed_at_us=observed)
    return {'status': 'validated_observed_selection', 'completed': completed,
            'winners': winners, 'maximum_lateness': maximum, 'interrupted': interrupted,
            'definition': 'Selected Pending spans include intentional suspension and scheduling; '
                          'poll spans are actual calls, including preemption; resume lateness is winning '
                          'poll entry minus original planned wake, excluding poll work, and '
                          'does not establish timer, kernel or CPU cause.'}
