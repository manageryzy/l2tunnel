#!/usr/bin/env python3
"""Report saved buffer observations without running workloads or merging owners.

Usage: python3 tools/buffer_metrics_report.py --output NEW_DIRECTORY FILE.bmetrics ...
The output directory must not exist. Input limits are 64 files and 4 MiB per file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

MAX_FILES = 64
MAX_BYTES = 4 * 1024 * 1024
MAX_SITES = 512
MAX_REASONS = 64
U64_MAX = (1 << 64) - 1
DURATION_COUNTS = ('episodes', 'completed_episodes', 'censored_episodes')
DURATION_TIMES = ('completed_us', 'censored_us', 'maximum_us')
GAUGE_VALUES = ('used', 'capacity', 'high_water', 'minimum_known_capacity',
                'maximum_known_capacity')
INVALID_FLAGS = ('clock_regression', 'occupancy_exceeds_capacity',
                 'update_after_finish', 'counter_overflow')
CORE_FIELDS = {'schema', 'owner', 'definition', 'coverage', 'first_observed_us',
               'last_observed_us', 'observed_span_us', 'finished_at_us',
               'diagnostic_heap_bytes', 'invalid', 'blocked_union', 'sites'}
DEFINITION = (
    'Durations cover observed refusal-to-progress intervals, including scheduling delay. '
    'Completed, terminal-censored and currently open intervals are distinct. '
    'Only the exported union for one owner is divided by that owner\'s observed_span_us. '
    'Overlapping sites/reasons and different owners are never summed. '
    'Count-only refusals have unmeasured duration; occupancy does not imply blockage. '
    'Coverage is partial even when every selected input parses successfully.'
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, name, nullable=False):
    require((nullable and value is None) or
            (type(value) is int and 0 <= value <= U64_MAX),
            name + ': expected unsigned 64-bit integer' + (' or null' if nullable else ''))
    return value


def label(value, name):
    require(isinstance(value, str) and 0 < len(value) <= 256, name + ': invalid label')
    return value


def object_value(value, name):
    require(isinstance(value, dict), name + ': expected object')
    return value


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('non-finite JSON number: ' + value)


def duration(value, name, issues):
    value = object_value(value, name)
    require('open_us' in value, name + ': missing open_us')
    result = {key: uint(value.get(key), name + '.' + key)
              for key in DURATION_COUNTS + DURATION_TIMES}
    result['open_us'] = uint(value.get('open_us'), name + '.open_us', True)
    total = result['completed_us'] + result['censored_us'] + (result['open_us'] or 0)
    result['observed_us'] = total
    expected = (result['completed_episodes'] + result['censored_episodes'] +
                int(result['open_us'] is not None))
    if result['episodes'] != expected:
        issues.append(name + ': episode counts do not match completed/censored/open state')
    if total > U64_MAX or result['maximum_us'] > total:
        issues.append(name + ': duration totals inconsistent or saturated')
    for kind in ('completed', 'censored'):
        if result[kind + '_episodes'] == 0 and result[kind + '_us'] != 0:
            issues.append(name + ': duration without ' + kind + ' episode')
    return result


def gauge(value, name, issues):
    value = object_value(value, name)
    require(all(key in value for key in GAUGE_VALUES), name + ': missing gauge fields')
    result = {'samples': uint(value.get('samples'), name + '.samples')}
    result.update({key: uint(value.get(key), name + '.' + key, True)
                   for key in GAUGE_VALUES})
    if result['samples'] == 0 and any(result[key] is not None for key in GAUGE_VALUES):
        issues.append(name + ': values without a gauge sample')
    if result['samples'] and (result['used'] is None or result['high_water'] is None):
        issues.append(name + ': sampled occupancy is missing')
    if result['used'] is not None:
        if result['capacity'] is not None and result['used'] > result['capacity']:
            issues.append(name + ': occupancy exceeds known capacity')
        if result['high_water'] is not None and result['used'] > result['high_water']:
            issues.append(name + ': latest occupancy exceeds high water')
    result['coverage'] = ('unobserved' if not result['samples'] else
                          'capacity_unknown' if result['capacity'] is None else 'sampled')
    return result



def protocol_provider(value):
    """Validate known provider metadata without deriving a union or filling nulls."""
    result = {'status': 'unavailable', 'issues': [], 'coverage_gaps': [],
              'definition': 'Separate protocol-owner observations; not included in generic '
                            'collector rankings or its union percentage; unknown remains unknown.'}
    if value is None:
        return result
    issues, gaps = result['issues'], result['coverage_gaps']

    def boolean(obj, key, path, invalid=False):
        require(type(obj.get(key)) is bool, path + '.' + key + ': expected boolean')
        if invalid and obj[key]:
            issues.append(path + ': producer invalid flag ' + key)

    def number(obj, key, path, nullable=False):
        require(key in obj, path + ': missing ' + key)
        return uint(obj[key], path + '.' + key, nullable)

    def totals(obj, path):
        obj = object_value(obj, path)
        for kind in ('completed', 'censored'):
            count = number(obj, kind + '_episodes', path)
            elapsed = number(obj, kind + '_us', path)
            maximum = number(obj, 'maximum_' + kind + '_us', path)
            if maximum > elapsed or (count == 0 and (elapsed or maximum)):
                issues.append(path + ': inconsistent ' + kind + ' totals')

    try:
        value = object_value(value, 'protocol_buffers')
        require('schema' not in value or (type(value['schema']) is int and value['schema'] == 1),
                'protocol_buffers: unsupported provider schema')
        for key in ('identity_errors', 'clock_regressions'):
            if number(value, key, 'protocol_buffers'):
                issues.append('protocol_buffers: nonzero ' + key)
        boolean(value, 'counter_overflow', 'protocol_buffers', True)
        for key in ('retired_epochs_omitted', 'retired_owner_generations_omitted',
                    'unsupported_codec_samples', 'staged_terminal_unavailable'):
            # Occupancy-only producers predate the optional staged wait fields.
            if key == 'staged_terminal_unavailable' and key not in value:
                gaps.append('staged admission terminal coverage unavailable')
            elif number(value, key, 'protocol_buffers'):
                gaps.append(key + '=' + str(value[key]))
        epochs = value.get('epochs')
        require(isinstance(epochs, list) and len(epochs) <= 2,
                'protocol_buffers: invalid epoch array bound')
        identities = set()
        for ei, epoch in enumerate(epochs):
            path = 'protocol_buffers.epochs[' + str(ei) + ']'
            epoch = object_value(epoch, path)
            digest = epoch.get('configuration_digest_hex')
            require(isinstance(digest, str) and len(digest) == 64 and
                    all(c in '0123456789abcdef' for c in digest), path + ': invalid digest')
            identity = (number(epoch, 'epoch', path), digest)
            require(identity not in identities, path + ': duplicate epoch identity')
            identities.add(identity)
            boolean(epoch, 'live_at_last_sample', path)
            width = number(epoch, 'owner_capacity', path)
            require(1 <= width <= 256, path + ': invalid owner capacity')
            owners = epoch.get('owners')
            require(isinstance(owners, list) and len(owners) <= width,
                    path + ': invalid owner array bound')
            if 'rolling_waits' in epoch:
                try:
                    from .buffer_metrics_rolling import validate as validate_rolling
                except ImportError:
                    from buffer_metrics_rolling import validate as validate_rolling
                validate_rolling(epoch['rolling_waits'], epoch['epoch'],
                                 path + '.rolling_waits', issues, gaps)
            if 'reliable_output' in epoch:
                try:
                    from .buffer_metrics_reliable import validate as validate_reliable
                except ImportError:
                    from buffer_metrics_reliable import validate as validate_reliable
                validate_reliable(epoch['reliable_output'], epoch['epoch'],
                                  path + '.reliable_output', issues, gaps,
                                  {'Client': 0, 'Server': 1}.get(value.get('local_role')))
            seen = set()
            for oi, owner in enumerate(owners):
                prefix = path + '.owners[' + str(oi) + ']'
                owner = object_value(owner, prefix)
                scope = owner.get('scope')
                if scope in ('endpoint-shared', 'swift-shared-packing'):
                    require(owner.get('owner') is None and owner.get('incarnation') is None,
                            prefix + ': shared owner has independent identity')
                    if scope == 'swift-shared-packing':
                        require(owner.get('channel') is None,
                                prefix + ': shared Swift packing has channel identity')
                    identity = (scope, None, None)
                elif scope == 'swift-channel':
                    require(owner.get('owner') is None and owner.get('incarnation') is None,
                            prefix + ': Swift channel has independent connection identity')
                    channel = number(owner, 'channel', prefix)
                    require(channel < 64 and channel + 1 < width,
                            prefix + ': invalid Swift channel identity')
                    boolean(owner, 'send_present', prefix)
                    boolean(owner, 'receive_present', prefix)
                    send, receive = owner['send_present'], owner['receive_present']
                    require(send or receive, prefix + ': absent Swift channel')
                    identity = (scope, channel, None)
                else:
                    require(scope == 'independent-connection', prefix + ': unknown owner scope')
                    index = number(owner, 'owner', prefix)
                    incarnation = number(owner, 'incarnation', prefix)
                    require(index < width and incarnation > 0, prefix + ': invalid owner identity')
                    identity = (scope, index, incarnation)
                require(identity not in seen, prefix + ': duplicate owner identity')
                seen.add(identity)
                for key in ('invalid_occupancy', 'counter_overflow'):
                    boolean(owner, key, prefix, True)
                gauges = owner.get('gauges')
                require(isinstance(gauges, list) and len(gauges) <= 128,
                        prefix + ': invalid gauge array bound')
                names = set()
                for item in gauges:
                    item = object_value(item, prefix + '.gauge')
                    name = label(item.get('name'), prefix + '.gauge.name')
                    require(name not in names, prefix + ': duplicate gauge name')
                    names.add(name)
                    if scope == 'swift-channel':
                        require(name in {
                            'swift_sender_packing_bytes', 'swift_sender_source_records',
                            'swift_sender_source_payload_bytes', 'swift_sender_retry_entries',
                            'swift_sender_repairs_due', 'swift_receiver_source_positions',
                            'swift_receiver_known_sources', 'swift_receiver_source_payload_bytes',
                            'swift_receiver_equation_rows', 'swift_receiver_equation_payload_bytes',
                            'swift_receiver_stream_bytes'}, prefix + ': unknown Swift gauge')
                        if name.startswith('swift_sender_'):
                            require(send, prefix + ': absent Swift sender has gauges')
                        if name.startswith('swift_receiver_'):
                            require(receive, prefix + ': absent Swift receiver has gauges')
                        if name == 'swift_sender_repairs_due':
                            require(item.get('capacity') is None,
                                    prefix + ': repair work debt has payload capacity')
                    if scope == 'swift-shared-packing':
                        require(name == 'swift_shared_packing_bytes',
                                prefix + ': shared Swift packing has unrelated gauge')
                    number(item, 'samples', prefix + '.' + name)
                    used, cap, high = (number(item, key, prefix + '.' + name, True)
                                       for key in ('used', 'capacity', 'high_water'))
                    if (used is None) != (high is None):
                        issues.append(prefix + '.' + name + ': inconsistent use availability')
                    if used is not None and ((cap is not None and used > cap) or
                                             (high is not None and used > high)):
                        issues.append(prefix + '.' + name + ': impossible occupancy')
                wait = owner.get('staged_admission')
                if wait is None:
                    gaps.append(prefix + ': staged admission timing unavailable')
                    continue
                wait = object_value(wait, prefix + '.staged_admission')
                for key in ('clock_regression', 'identity_mismatch', 'counter_overflow'):
                    boolean(wait, key, prefix + '.staged_admission', True)
                observed = number(wait, 'observed_at_us', prefix)
                terminal = number(wait, 'terminal_at_us', prefix, True)
                opened = number(wait, 'open_us', prefix, True)
                totals(wait.get('union'), prefix + '.staged_admission.union')
                if terminal is not None and (terminal != observed or opened is not None):
                    issues.append(prefix + ': invalid staged terminal boundary')
                if (opened is None) != (wait.get('pending') is None):
                    issues.append(prefix + ': inconsistent staged source/open availability')
                reasons = wait.get('reasons')
                require(isinstance(reasons, list) and len(reasons) == 2,
                        prefix + ': invalid staged reason array')
                require([r.get('reason') if isinstance(r, dict) else None for r in reasons] ==
                        ['send_capacity', 'sequence_window'], prefix + ': unknown staged reasons')
                for reason in reasons:
                    number(reason, 'refused_attempts', prefix)
                    totals(reason.get('totals'), prefix + '.' + reason['reason'])
        result['status'] = 'invalid_observations' if issues else 'validated_known_fields_partial'
    except ValueError as error:
        issues.append(str(error))
        result['status'] = 'invalid_or_unrecognized_shape'
    return result


def management_provider(value, finished=None):
    """Validate the bounded management sidecar; never infer or merge wait time."""
    result = {'status': 'unavailable', 'issues': [], 'coverage_gaps': [],
              'definition': 'Management-stream observations stay separate from generic/carrier '
                            'wait rankings and union percentages. Sampled occupancy is not blockage; '
                            'ordinary reused-ID submissions have count-only refusals.'}
    if value is None:
        return result
    issues, gaps = result['issues'], result['coverage_gaps']
    path = 'management_streams'

    def number(obj, key, prefix, nullable=False):
        require(key in obj, prefix + ': missing ' + key)
        return uint(obj[key], prefix + '.' + key, nullable)

    def boolean(obj, key, prefix, invalid=False):
        require(type(obj.get(key)) is bool, prefix + '.' + key + ': expected boolean')
        if invalid and obj[key]:
            issues.append(prefix + ': producer invalid flag ' + key)

    def hex_string(value, length, prefix):
        require(isinstance(value, str) and len(value) == length and
                all(c in '0123456789abcdef' for c in value), prefix + ': invalid hex identity')

    def identity(value, prefix):
        value = object_value(value, prefix)
        require(number(value, 'submission', prefix) > 0 and
                number(value, 'origin_epoch', prefix) > 0, prefix + ': invalid submission identity')
        require(0 < number(value, 'bytes', prefix) <= 65_536, prefix + ': invalid message extent')
        hex_string(value.get('origin_digest_hex'), 64, prefix)
        require(number(value, 'original_deadline_us', prefix) > 0, prefix + ': invalid original deadline')
        return value

    gauge_names = {
        'outbound_messages', 'outbound_payload_bytes', 'outbound_fragment_bytes',
        'outbound_combined_bytes', 'confirmed_retry_metadata', 'awaiting_semantic_accepted',
        'source_confirmation_custody', 'unsubmitted_fragments', 'incomplete_messages',
        'reassembly_reserved_bytes', 'held_complete_bytes', 'recovery_send_records',
        'recovery_send_payload_bytes', 'recovery_receive_records', 'recovery_receive_payload_bytes',
        'wrapper_outgoing', 'wrapper_confirmed', 'wrapper_held', 'wrapper_dispatched', 'wrapper_leased'}
    try:
        value = object_value(value, path)
        require('schema' not in value or (type(value['schema']) is int and value['schema'] == 1),
                path + ': unsupported provider schema')
        version = number(value, 'version', path)
        require(version in (0, 1, 2), path + ': unsupported stream grammar version')
        require(number(value, 'sample_interval_us', path) > 0, path + ': invalid sampling interval')
        samples = number(value, 'samples', path)
        for key in ('counter_overflow', 'clock_regression', 'invalid_occupancy'):
            boolean(value, key, path, True)
        for key in ('retired_owners_omitted', 'unavailable_samples'):
            if number(value, key, path):
                gaps.append(key + '=' + str(value[key]))
        first = number(value, 'first_sample_us', path, True)
        last = number(value, 'last_sample_us', path, True)
        if last is not None and finished is not None and last > finished:
            issues.append(path + ': storage sample follows owner finish')
        rows = value.get('streams')
        require(isinstance(rows, list) and len(rows) <= 4, path + ': invalid stream array bound')
        for key in ('binding', 'shared_quota', 'reservation', 'frozen_submission_wait'):
            require(key in value, path + ': missing ' + key)
        binding = value['binding']
        control_epoch = None
        if samples == 0:
            if (first is not None or rows or binding is not None or version != 0 or
                    any(value[key] is not None for key in
                        ('shared_quota', 'reservation', 'frozen_submission_wait'))):
                issues.append(path + ': observed owner values without a sample')
            gaps.append('management owners have no storage sample; unavailable is not zero')
        else:
            require(first is not None and last is not None and version != 0,
                    path + ': sampled owner is missing observation boundaries')
            if first > last:
                issues.append(path + ': last sample precedes first')
            binding = object_value(binding, path + '.binding')
            hex_string(binding.get('session_hex'), 32, path + '.binding.session_hex')
            require(number(binding, 'lane', path) <= 0xffff_ffff, path + ': invalid lane')
            require(binding.get('role') in ('Client', 'Server'), path + ': unknown role')
            control_epoch = number(binding, 'control_epoch', path)
            require(control_epoch > 0, path + ': invalid control epoch')
        quota = value['shared_quota']
        if quota is not None:
            quota = object_value(quota, path + '.shared_quota')
            for used, cap in (('packets_left', 'packets_per_interval'),
                              ('bytes_left', 'bytes_per_interval')):
                if number(quota, used, path) > number(quota, cap, path):
                    issues.append(path + ': shared allowance exceeds its configured cap')
            number(quota, 'refill_at_us', path)
        elif samples:
            gaps.append('shared management policy allowance unavailable')
        reservation = value['reservation']
        if reservation is not None:
            reservation = identity(reservation, path + '.reservation')
        allowed = ('Transaction', 'Liveness', 'DataFeedback') + (('Lifecycle',) if version == 2 else ())
        seen, epochs = set(), set()
        for index, row in enumerate(rows):
            prefix = path + '.streams[' + str(index) + ']'
            row = object_value(row, prefix)
            stream = row.get('stream')
            require(stream in allowed and stream not in seen, prefix + ': unknown/duplicate stream')
            seen.add(stream)
            epoch = number(row, 'stream_control_epoch', prefix)
            require(epoch > 0 and epoch not in epochs, prefix + ': invalid/duplicate stream epoch')
            epochs.add(epoch)
            if control_epoch is not None:
                # Checked v1/v2 namespace map from control_streams::delivery_binding.
                expected = control_epoch * len(allowed) + allowed.index(stream) + 1
                if expected > U64_MAX or epoch != expected:
                    issues.append(prefix + ': stream epoch differs from selected binding grammar')
            require(0 < number(row, 'samples', prefix) <= samples, prefix + ': invalid sample count')
            successful = number(row, 'last_successful_owner_us', prefix)
            if last is not None and successful > last:
                issues.append(prefix + ': owner observation follows sample time')
            boolean(row, 'owner_failed', prefix)
            if row['owner_failed']:
                gaps.append(stream + ': sampled owner failed; this is not diagnostic invalidity')
            message = number(row, 'held_message', prefix, True)
            deadline = number(row, 'held_original_deadline_us', prefix, True)
            if (message is None) != (deadline is None) or message == 0:
                issues.append(prefix + ': inconsistent held-message identity/deadline')
            number(row, 'source_scratch_capacity_bytes', prefix)
            if number(row, 'ordinary_submit_refusals', prefix, True) is None:
                gaps.append(stream + ': ordinary submission refusal count unavailable')
            require('ordinary_submit_duration_us' in row and row['ordinary_submit_duration_us'] is None,
                    prefix + ': ordinary reused-ID refusal duration must remain unknown')
            gauges = row.get('gauges')
            require(isinstance(gauges, list) and len(gauges) <= 20, prefix + ': invalid gauge array bound')
            names, unknown = set(), 0
            for item in gauges:
                item = object_value(item, prefix + '.gauge')
                name = item.get('name')
                require(isinstance(name, str) and name in gauge_names and name not in names,
                        prefix + ': unknown/duplicate gauge')
                names.add(name)
                require(item.get('unit') == ('bytes' if name.endswith('_bytes') else 'items'),
                        prefix + '.' + name + ': wrong gauge unit')
                used, cap, high = (number(item, key, prefix + '.' + name, True)
                                  for key in ('used', 'capacity', 'high_water'))
                if (used is None) != (high is None):
                    issues.append(prefix + '.' + name + ': inconsistent occupancy availability')
                if used is None:
                    unknown += 1
                elif ((cap is not None and (used > cap or (high is not None and high > cap))) or
                      (high is not None and used > high)):
                    issues.append(prefix + '.' + name + ': impossible occupancy')
            if names != gauge_names:
                gaps.append(stream + ': missing sampled gauges: ' + ', '.join(sorted(gauge_names - names)))
            if unknown:
                gaps.append(stream + ': unknown occupancy gauges=' + str(unknown))
        if samples and seen != set(allowed):
            gaps.append('selected management stream samples missing: ' + ', '.join(sorted(set(allowed) - seen)))
        wait = value['frozen_submission_wait']
        if wait is None:
            gaps.append('immutable frozen submission timing unavailable')
        else:
            prefix = path + '.frozen_submission_wait'
            wait = object_value(wait, prefix)
            require(wait.get('stream') == 'Transaction', prefix + ': unknown timed stream')
            for key in ('clock_regression', 'identity_mismatch', 'counter_overflow'):
                boolean(wait, key, prefix, True)
            counts = [number(wait, key, prefix) for key in ('wrapper_entry_refusals', 'message_capacity_refusals')]
            elapsed, episodes = 0, 0
            for kind in ('completed', 'censored'):
                count = number(wait, kind + '_episodes', prefix)
                duration_us = number(wait, kind + '_us', prefix)
                elapsed += duration_us
                episodes += count
                if count == 0 and duration_us:
                    issues.append(prefix + ': duration without ' + kind + ' episode')
            observed = number(wait, 'observed_at_us', prefix, True)
            terminal = number(wait, 'terminal_at_us', prefix, True)
            opened = number(wait, 'open_us', prefix, True)
            maximum = number(wait, 'maximum_us', prefix)
            start = number(wait, 'first_refusal_us', prefix, True)
            latest = number(wait, 'last_refusal_us', prefix, True)
            for key in ('pending', 'terminal_kind', 'last_resolved'):
                require(key in wait, prefix + ': missing ' + key)
            pending = wait['pending']
            if pending is not None:
                pending = identity(pending, prefix + '.pending')
                if (opened is None or start is None or latest is None or observed is None or
                        not start <= latest <= observed or opened != observed - start or
                        latest >= pending['original_deadline_us']):
                    issues.append(prefix + ': inconsistent open reservation interval')
                if reservation != pending:
                    issues.append(prefix + ': open reservation differs from actual retained reservation')
            elif opened is not None or start is not None or latest is not None:
                issues.append(prefix + ': open interval without an exact pending reservation')
            elapsed += opened or 0
            episodes += int(opened is not None)
            if (elapsed > U64_MAX or maximum > elapsed or maximum < (opened or 0) or
                    episodes > sum(counts) or sum(counts) > U64_MAX or
                    (observed is not None and elapsed > observed)):
                issues.append(prefix + ': inconsistent duration/refusal totals')
            if samples and observed is None:
                gaps.append('frozen timing observation boundary unavailable')
            if observed is not None and last is not None and observed > last:
                issues.append(prefix + ': frozen observation follows storage sample')
            if terminal is None:
                if finished is not None:
                    issues.append(prefix + ': finished owner lacks management timing stop')
                if wait['terminal_kind'] is not None or (observed is not None and observed != last):
                    issues.append(prefix + ': inconsistent live observation boundary')
            elif (terminal != observed or pending is not None or
                  wait['terminal_kind'] not in ('OwnerFailure', 'MetricStop')):
                issues.append(prefix + ': inconsistent terminal censor boundary')
            resolved = wait['last_resolved']
            if resolved is not None:
                resolved = object_value(resolved, prefix + '.last_resolved')
                exact = identity(resolved.get('identity'), prefix + '.last_resolved.identity')
                began = number(resolved, 'first_refusal_us', prefix)
                ended = number(resolved, 'resolved_at_us', prefix)
                message = number(resolved, 'wire_message', prefix, True)
                outcome = resolved.get('outcome')
                require(outcome in ('Admitted', 'Cancelled', 'OwnerFailure', 'MetricStop'),
                        prefix + ': unknown resolution outcome')
                kind = 'completed' if outcome == 'Admitted' else 'censored'
                if (ended < began or began >= exact['original_deadline_us'] or
                        (observed is not None and ended > observed) or
                        (start is not None and ended > start) or wait[kind + '_episodes'] == 0 or
                        ended - began > wait[kind + '_us'] or ended - began > maximum or
                        (outcome in ('Admitted', 'Cancelled') and ended >= exact['original_deadline_us']) or
                        ((message is not None) != (outcome == 'Admitted')) or message == 0):
                    issues.append(prefix + ': inconsistent latest exact resolution')
            elif wait['completed_episodes'] or wait['censored_episodes']:
                issues.append(prefix + ': completed/censored episodes lack latest resolution')
        gaps.append('partial: fragment admission, receipt acceptance, dispatch/dependency and retired tails remain untimed')
        result['status'] = 'invalid_observations' if issues else 'validated_known_fields_partial'
    except ValueError as error:
        issues.append(str(error))
        result['status'] = 'invalid_or_unrecognized_shape'
    return result


def normalize(value, source, digest):
    value = object_value(value, 'input')
    require(type(value.get('schema')) is int and value['schema'] == 1,
            'unsupported buffer metrics schema')
    if value.get('owner') == 'raw_custody':
        try:
            from .buffer_metrics_raw_custody import normalize as normalize_raw_custody
        except ImportError:
            from buffer_metrics_raw_custody import normalize as normalize_raw_custody
        return normalize_raw_custody(value, source, digest)
    issues = []
    invalid = object_value(value.get('invalid'), 'invalid')
    require(all(type(invalid.get(key)) is bool for key in INVALID_FLAGS),
            'invalid flags must be booleans')
    for key, flag in invalid.items():
        require(type(flag) is bool, 'invalid flags must be booleans')
        if flag:
            issues.append('producer invalid flag: ' + key)
    require(all(key in value for key in ('first_observed_us', 'last_observed_us',
                                        'observed_span_us', 'finished_at_us')),
            'missing owner observation boundaries')
    times = {key: uint(value.get(key), key, True) for key in (
        'first_observed_us', 'last_observed_us', 'observed_span_us', 'finished_at_us')}
    first, last, span, finished = (times[key] for key in times)
    if (first is None) != (last is None) or (first is None) != (span is None):
        issues.append('inconsistent observed time availability')
    if first is not None and last is not None:
        if last < first:
            issues.append('last observation precedes first observation')
        if finished is not None and (finished < last or span != finished - first):
            issues.append('terminal observed span does not match actual hook boundary')
        if finished is None and span is not None and span < last - first:
            issues.append('observed span ends before last hook')
    union = duration(value.get('blocked_union'), 'blocked_union', issues)
    if span is not None and union['observed_us'] > span:
        issues.append('owner union exceeds actual observed span')
    if finished is not None and union['open_us'] is not None:
        issues.append('finished owner retains an uncensored open union')
    sites = value.get('sites')
    require(isinstance(sites, list) and len(sites) <= MAX_SITES, 'invalid sites array bound')
    occupancy, waits, counts = [], [], []
    seen = set()
    for index, site in enumerate(sites):
        site = object_value(site, 'site')
        key = {name: label(site.get(name), name) for name in ('site', 'lane', 'class')}
        identity = tuple(key.values())
        require(identity not in seen, 'duplicate site/lane/class')
        seen.add(identity)
        prefix = 'sites[' + str(index) + ']'
        sampled = {**key, 'bytes': gauge(site.get('bytes'), prefix + '.bytes', issues),
                   'items': gauge(site.get('items'), prefix + '.items', issues),
                   **{name: uint(site.get(name), prefix + '.' + name, True)
                      for name in ('first_observed_us', 'last_observed_us')}}
        occupancy.append(sampled)
        reasons = site.get('reasons')
        require(isinstance(reasons, list) and len(reasons) <= MAX_REASONS,
                prefix + ': invalid reasons array bound')
        reason_names = set()
        for reason in reasons:
            reason = object_value(reason, prefix + '.reason')
            name = label(reason.get('reason'), 'reason')
            require(name not in reason_names, prefix + ': duplicate reason')
            reason_names.add(name)
            counters = {name: uint(reason.get(name), prefix + '.' + name)
                        for name in ('refusals', 'untimed_refusals', 'progress')}
            blocked = duration(reason.get('blocked'), prefix + '.' + name, issues)
            if finished is not None and blocked['open_us'] is not None:
                issues.append(prefix + ': finished reason retains an open wait')
            if span is not None and blocked['observed_us'] > span:
                issues.append(prefix + ': reason duration exceeds owner span')
            row = {**key, 'reason': name, **counters, 'blocked': blocked,
                   'timing_coverage': ('partial_timed' if counters['untimed_refusals'] else 'timed')
                   if blocked['episodes'] else 'no_timed_episode_observed'}
            if blocked['episodes']:
                waits.append(row)
            if counters['untimed_refusals'] or (not blocked['episodes'] and counters['refusals']):
                counts.append({**key, 'reason': name, **counters, 'duration_us': None,
                               'definition': 'Unmeasured refusal duration; excluded from owner union.'})
    waits.sort(key=lambda row: (-row['blocked']['observed_us'], row['site'], row['lane'],
                               row['class'], row['reason']))
    counts.sort(key=lambda row: (-row['untimed_refusals'], row['site'], row['lane'],
                                row['class'], row['reason']))
    protocol = protocol_provider(value.get('protocol_buffers'))
    issues.extend(protocol['issues'])
    try:
        from .buffer_metrics_pipeline import validate as validate_pipeline
    except ImportError:
        from buffer_metrics_pipeline import validate as validate_pipeline
    pipeline = validate_pipeline(value.get('pipeline_admission'))
    issues.extend(pipeline['issues'])
    try:
        from .buffer_metrics_execution import validate as validate_execution
    except ImportError:
        from buffer_metrics_execution import validate as validate_execution
    execution = validate_execution(value.get('common_execution'), value.get('owner'))
    issues.extend(execution['issues'])
    management = management_provider(value.get('management_streams'), finished)
    issues.extend(management['issues'])
    ratio = None
    if not issues and span is not None and span > 0:
        ratio = 100.0 * union['observed_us'] / span
    return {
        'source': source, 'sha256': digest, 'owner': label(value.get('owner'), 'owner'),
        'source_schema': 1, 'status': 'invalid_observations' if issues else 'parsed_partial_coverage',
        'issues': issues, 'invalid': invalid, **times,
        'source_definition': value.get('definition'), 'source_coverage': value.get('coverage'),
        'diagnostic_heap_bytes': uint(value.get('diagnostic_heap_bytes'), 'diagnostic_heap_bytes'),
        'blocked_union': union, 'owner_union_percent_of_observed_span': ratio,
        'percentage_unavailable_reason': None if ratio is not None else
        ('invalid_observations' if issues else 'unknown_or_zero_observed_span'),
        'wait_ranking': waits, 'count_only_refusals': counts, 'occupancy': occupancy,
        'protocol_provider_validation': protocol,
        'pipeline_provider_validation': pipeline,
        'management_provider_validation': management,
        'execution_provider_validation': execution,
        'provider_metadata': {key: item for key, item in value.items() if key not in CORE_FIELDS},
        'provider_metadata_definition': 'Preserved source fields; no queue usage derived from provider space or limits.',
    }


def read_input(path):
    require(path.suffix == '.bmetrics', 'expected a .bmetrics input')
    require(not path.is_symlink() and path.is_file(), 'regular non-symlink input required')
    with path.open('rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'regular input required')
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, 'input exceeds 4 MiB bound')
    digest = hashlib.sha256(raw).hexdigest()
    value = json.loads(raw, object_pairs_hook=unique_keys, parse_constant=reject_constant)
    return normalize(value, str(path.resolve()), digest)


def build_report(paths):
    require(0 < len(paths) <= MAX_FILES, 'select between 1 and 64 input files')
    selected = [Path(path) for path in paths]
    canonical = [str(path.resolve()) for path in selected]
    require(len(set(canonical)) == len(canonical), 'duplicate input path')
    owners, rejected = [], []
    for path in selected:
        try:
            owners.append(read_input(path))
        except (OSError, ValueError, RecursionError) as error:
            rejected.append({'source': str(path.resolve()), 'status': 'rejected_input',
                             'error': str(error), 'measurements': None})
    return {'schema': 1, 'definition': DEFINITION, 'coverage': 'partial',
            'input_limits': {'files': MAX_FILES, 'bytes_per_file': MAX_BYTES},
            'owners': owners, 'rejected_inputs': rejected,
            'status': 'input_or_observation_errors' if rejected or
            any(owner['issues'] for owner in owners) else 'parsed_partial_coverage'}


def cell(value):
    if value is None:
        return 'unknown'
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace(
        '|', '&#124;').replace('\r', ' ').replace('\n', ' ').replace('`', '&#96;')


def table(lines, columns, rows):
    lines.extend(['', '| ' + ' | '.join(columns) + ' |',
                  '| ' + ' | '.join('---' for _ in columns) + ' |'])
    for row in rows:
        lines.append('| ' + ' | '.join(cell(item) for item in row) + ' |')


def markdown(report):
    lines = ['# Observed buffer pressure', '', DEFINITION, '',
             'Status: ' + report['status'] + '. Raw and QUIC provider fields are retained in JSON; '
             'provider-private queue usage is not inferred. Generic collector percentages exclude separate '
             'protocol-owner waits. No end-to-end blocked percentage is calculated.']
    for index, owner in enumerate(report['owners'], 1):
        union = owner['blocked_union']
        percentage = owner['owner_union_percent_of_observed_span']
        lines.extend(['', '## Owner ' + str(index) + ': ' + cell(owner['owner']), '',
                      'Source: ' + cell(owner['source']), '', 'SHA256: ' + owner['sha256'], '',
                      'Status: ' + owner['status'] + '. Coverage: ' + cell(owner['source_coverage'])])
        if 'raw_custody_validation' in owner:
            try:
                from .buffer_metrics_raw_custody import render as render_raw_custody
            except ImportError:
                from buffer_metrics_raw_custody import render as render_raw_custody
            render_raw_custody(lines, owner, table, cell)
            continue
        table(lines, ['Observed span us', 'Union completed us', 'Union censored us',
                      'Union open us', 'Union / observed span'],
              [[owner['observed_span_us'], union['completed_us'], union['censored_us'],
                union['open_us'] if union['open_us'] is not None else 'none open',
                f'{percentage:.6f}%' if percentage is not None else
                'unavailable: ' + owner['percentage_unavailable_reason']]])
        execution = owner['execution_provider_validation']
        lines.extend(['', 'Execution provider: ' + cell(execution['status']) + '. ' +
                      execution['definition']])
        if execution['status'] == 'validated_wall_spans':
            lines.append('Boundary: ' + cell(execution['boundary']) + '.')
            table(lines, ['Stage', 'Samples', 'Wall sum us', 'Wall maximum us', 'Failed', 'Censored'],
                  [[row['stage'], row['samples'], row['sum_us'], row['max_us'], row['failed'], row['censored']]
                   for row in execution['stages'] if row['samples']])
        protocol = owner['protocol_provider_validation']
        lines.extend(['', 'Protocol provider: ' + cell(protocol['status']) + '. ' +
                      protocol['definition']])
        lines.extend('- ' + cell(gap) for gap in protocol['coverage_gaps'])
        try:
            from .buffer_metrics_pipeline import render as render_pipeline
        except ImportError:
            from buffer_metrics_pipeline import render as render_pipeline
        render_pipeline(lines, owner['pipeline_provider_validation'], table, cell)
        try:
            from .buffer_metrics_reliable import render as render_reliable
        except ImportError:
            from buffer_metrics_reliable import render as render_reliable
        if protocol['status'] == 'validated_known_fields_partial':
            render_reliable(lines, owner['provider_metadata'], table, cell)
        management = owner['management_provider_validation']
        lines.extend(['', 'Management provider: ' + cell(management['status']) + '. ' +
                      management['definition']])
        lines.extend('- ' + cell(gap) for gap in management['coverage_gaps'])
        if owner['issues']:
            lines.extend(['', 'Diagnostic invalidity (values retained, percentage suppressed):'])
            lines.extend('- ' + cell(issue) for issue in owner['issues'])
        lines.extend(['', '### Ranked observed waits', '',
                      'Ranked within this owner by completed + censored + open duration for each '
                      'individual reason. Rows overlap and must not be summed.'])
        if owner['wait_ranking']:
            table(lines, ['Site / lane / class', 'Reason', 'Completed us (episodes)',
                          'Censored us (episodes)', 'Open us', 'Maximum us', 'Refusals', 'Coverage'],
                  [[' / '.join(row[key] for key in ('site', 'lane', 'class')), row['reason'],
                    f"{row['blocked']['completed_us']} ({row['blocked']['completed_episodes']})",
                    f"{row['blocked']['censored_us']} ({row['blocked']['censored_episodes']})",
                    row['blocked']['open_us'] if row['blocked']['open_us'] is not None else 'none open',
                    row['blocked']['maximum_us'], row['refusals'], row['timing_coverage']]
                   for row in owner['wait_ranking']])
        else:
            lines.extend(['', 'No generic collector timed episode was observed; protocol-owner and unhooked waits are not zero.'])
        lines.extend(['', '### Count-only refusals', '',
                      'These counts do not establish wait duration and are excluded from the timed union.'])
        if owner['count_only_refusals']:
            table(lines, ['Site / lane / class', 'Reason', 'Untimed refusals', 'All refusals', 'Duration'],
                  [[' / '.join(row[key] for key in ('site', 'lane', 'class')), row['reason'],
                    row['untimed_refusals'], row['refusals'], 'unmeasured']
                   for row in owner['count_only_refusals']])
        else:
            lines.extend(['', 'No count-only refusal is present in the selected source.'])
        lines.extend(['', '### Sampled occupancy', '',
                      'High water and capacity extrema are sampled values. Unknown capacity stays unknown.'])
        table(lines, ['Site / lane / class', 'Unit', 'Samples', 'Used', 'Capacity', 'High water',
                      'Capacity min / max', 'Coverage'],
              [[' / '.join(row[key] for key in ('site', 'lane', 'class')), unit,
                row[unit]['samples'], row[unit]['used'], row[unit]['capacity'], row[unit]['high_water'],
                cell(row[unit]['minimum_known_capacity']) + ' / ' + cell(row[unit]['maximum_known_capacity']),
                row[unit]['coverage']] for row in owner['occupancy'] for unit in ('bytes', 'items')])
        providers = owner['provider_metadata']
        if providers:
            lines.extend(['', 'Provider metadata keys preserved in JSON: ' + ', '.join(
                cell(key) for key in providers) + '. No subtraction of available space from a cap '
                'is treated as payload or heap usage. Raw candidate age is residence, not a wait.'])
    if report['rejected_inputs']:
        lines.extend(['', '## Rejected inputs', '', 'No measurements were inferred for these inputs.'])
        table(lines, ['Source', 'Error'], [[row['source'], row['error']]
                                          for row in report['rejected_inputs']])
    return '\n'.join(lines) + '\n'


def write_report(paths, output):
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'output directory must be new')
    report = build_report(paths)
    # Validate and render before creating any output. Existing receipts are never overwritten.
    encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
    text = markdown(report)
    output.mkdir()
    with (output / 'report.json').open('x', encoding='utf-8') as stream:
        stream.write(encoded)
    with (output / 'report.md').open('x', encoding='utf-8') as stream:
        stream.write(text)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new output directory')
    parser.add_argument('inputs', type=Path, nargs='+', help='explicit .bmetrics files; owners stay separate')
    args = parser.parse_args(argv)
    try:
        report = write_report(args.inputs, args.output)
    except (OSError, ValueError) as error:
        parser.exit(2, 'buffer metrics report: ' + str(error) + '\n')
    print(str(args.output / 'report.md'))
    return 0 if report['status'] == 'parsed_partial_coverage' else 2


if __name__ == '__main__':
    raise SystemExit(main())
