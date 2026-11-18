"""Validate bounded Pending context without inferring an exclusive wait cause."""
from __future__ import annotations

COUNTERS = ('congestion_events', 'lost_quic_packets', 'lost_quic_bytes',
            'sent_quic_packets', 'udp_tx_datagrams', 'udp_tx_payload_bytes', 'datagram_frames_tx')


def validate_record(record, stopped, require, uint, object_value):
    polls = uint(record.get('poll_count'), 'quic poll count')
    latest_poll = uint(record.get('latest_poll_us'), 'quic latest poll', True)
    gap = uint(record.get('maximum_poll_gap_us'), 'quic maximum poll gap', True)
    first_poll = record['first_poll_us']
    require((polls > 0) == (first_poll is not None) == (latest_poll is not None),
            'quic poll boundary availability')
    end = next((record[k] for k in ('accepted_us', 'result_us', 'stopped_us')
                if record[k] is not None), stopped)
    if polls:
        require(latest_poll >= first_poll, 'quic poll time order')
        require(end is None or latest_poll <= end, 'quic poll after outcome')
    if polls > 1:
        require(gap is not None and gap <= latest_poll - first_poll, 'quic poll gap bound')
    else:
        require(gap is None, 'quic invented poll gap')
    pending = object_value(record.get('pending_observation'), 'quic Pending observation')
    count = uint(pending.get('polls'), 'quic Pending polls')
    first = uint(pending.get('first_us'), 'quic first Pending', True)
    latest = uint(pending.get('latest_us'), 'quic latest Pending', True)
    require(count <= polls, 'quic Pending exceeds actual polls')
    require((count > 0) == (first is not None) == (latest is not None),
            'quic Pending boundary availability')
    if count:
        require(first_poll <= first <= latest and (end is None or latest <= end),
                'quic Pending time order')
    a = pending.get('first_sample'); b = pending.get('latest_sample')
    require((a is None) == (b is None), 'quic Pending sample availability')
    require(count > 0 or a is None, 'quic sample without Pending')
    samples = []
    for value in (a, b):
        if value is None:
            continue
        value = object_value(value, 'quic Pending sample')
        begin = uint(value.get('begin_us'), 'quic sample begin')
        finish = uint(value.get('end_us'), 'quic sample end')
        require(first <= begin <= finish and (end is None or finish <= end),
                'quic sample outside held ticket')
        required = uint(value.get('required_payload_bytes'), 'quic required payload', True)
        if required is not None:
            require(required == record['bytes'], 'quic required payload identity')
        capacity = uint(value.get('configured_send_buffer_bytes'), 'quic send capacity')
        available = uint(value.get('available_payload_bytes'), 'quic available payload')
        require(available <= capacity, 'quic available exceeds configured bound')
        for name in ('rtt_us', 'cwnd_bytes', 'current_mtu_bytes') + COUNTERS:
            uint(value.get(name), 'quic sample ' + name)
        require(value.get('invalid') is False, 'quic invalid Pending sample')
        require('bytes_in_flight' in value and value['bytes_in_flight'] is None
                and 'pacing_deadline_us' in value and value['pacing_deadline_us'] is None,
                'quic unavailable cause fabricated')
        samples.append(value)
    if samples:
        a, b = samples
        # First and latest are identical until a later sample; they need not be disjoint.
        require(b['begin_us'] >= a['begin_us'] and b['end_us'] >= a['end_us'],
                'quic sample order')
        for name in COUNTERS:
            require(b[name] >= a[name], 'quic sample counter regression')
        for name in ('required_payload_bytes', 'configured_send_buffer_bytes'):
            require(a[name] == b[name], 'quic sample capability changed')
    return None if not count or end is None else end - first


def render(lines, rows, table):
    lines.extend(['', 'QUIC Pending snapshots use separate provider locks. They locate local '
                  'DATAGRAM admission delay; sampled cwnd/loss is context, not a causal split. '
                  'Poll gaps include scheduling. In-flight bytes and pacing remain unavailable.'])
    values = []
    for row in rows:
        record = row.get('maximum_pending')
        if record is None:
            continue
        pending = record['pending_observation']
        end = next(record[k] for k in ('accepted_us', 'result_us', 'stopped_us')
                   if record[k] is not None)
        first = pending['first_sample'] or {}; latest = pending['latest_sample'] or {}
        outcome = ('accepted' if record['accepted_us'] is not None else
                   'failed' if record['result_us'] is not None else 'censored')
        values.append([row['lane'], row['class'], row['consumer'],
                       record['identity']['serial'], outcome, end - pending['first_us'],
                       pending['polls'], record['maximum_poll_gap_us'],
                       first.get('available_payload_bytes'), latest.get('available_payload_bytes'),
                       first.get('cwnd_bytes'), latest.get('cwnd_bytes'),
                       first.get('lost_quic_packets'), latest.get('lost_quic_packets')])
    table(lines, ['Lane', 'Class', 'Consumer', 'Maximum ticket', 'Outcome', 'Pending us',
                  'Pending polls', 'Max poll gap us', 'First available B', 'Latest available B',
                  'First cwnd B', 'Latest cwnd B', 'First loss count', 'Latest loss count'], values)
