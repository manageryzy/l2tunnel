"""Validate bounded execution observations without treating wall time as blockage."""
from __future__ import annotations

STAGES = (
    'CommonTurnSpacing', 'CommonReceiptProgress', 'CommonAdmission',
    'CommonProtocolProgress', 'CommonManagement', 'CommonSend', 'CommonReceive',
    'CommonCarrierReceive', 'CommonDeadlineService', 'CommonSnapshot',
    'CommonNativeWrite', 'CommonNativeRead', 'CommonBufferSampling',
    'CliProjection', 'CliEncoding', 'CliFlush', 'CliFileWrite',
)
BOUNDARIES = {'loop_stop_before_settlement': 'loop_stop',
              'driver_future_drop': 'driver_future_drop'}


def validate(value, owner):
    try:
        from .buffer_metrics_report import require, uint, object_value
    except ImportError:
        from buffer_metrics_report import require, uint, object_value
    result = {'status': 'unavailable', 'issues': [], 'stages': [],
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
        require(type(timing.get('schema')) is int and timing['schema'] == 1 and
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
        stages = timing.get('stages')
        require(isinstance(stages, list) and len(stages) == len(STAGES),
                'common_execution: incomplete or oversized stage array')
        seen = set()
        for row in stages:
            row = object_value(row, 'common_execution.stage')
            name = row.get('stage')
            require(isinstance(name, str) and name in STAGES and name not in seen,
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
        result.update(boundary=boundary, elapsed_us=elapsed,
                      status='invalid_observations' if issues else 'validated_wall_spans')
    except ValueError as error:
        issues.append(str(error))
        result['status'] = 'invalid_or_unrecognized_shape'
    return result
