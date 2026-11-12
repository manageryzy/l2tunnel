"""Render selected complete three-seed configurations in three-objective views."""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
from math import isclose, isfinite
from pathlib import Path
import textwrap

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import plotly.graph_objects as go
from plotly.subplots import make_subplots

import tcp_syn_ping_report as report

PAYLOADS = (64, 256, 512, 1024, 1228, 1448)
LATENCY = report.LATENCY
CONCURRENT_GOODPUT = 'tcp_syn_ping_background_goodput_mbps'
GOODPUT = 'probe_interval_goodput_mbps'
OVERHEAD = 'probe_interval_extra_ip_pct'
METRICS = (LATENCY, GOODPUT, OVERHEAD)
MARKERS = ('o', 's', '^', 'D', 'v', 'P', '*', '<', '>')
PLOTLY_MARKERS = ('circle', 'square', 'diamond', 'circle-open', 'square-open', 'diamond-open')
PLOTLY_GLYPHS = ('●', '■', '◆', '○', '□', '◇')
PAYLOAD_MARKERS = dict(zip(PAYLOADS, ('o', 's', '^', 'D', 'v', '*')))
PAYLOAD_SYMBOLS = dict(zip(PAYLOADS, ('circle', 'square', 'triangle-up', 'diamond', 'triangle-down', 'star')))
STRATEGY_OVERVIEWS = {
    'Hash ordered mux': ('Hash', 'Ordered coding with endpoint hashing.'),
    'Round-robin ordered mux': ('RR', 'Ordered coding with round-robin connection assignment.'),
    'Independent-short mux': ('Ind', 'Independent release of short frames with coding and repetition.'),
    'Selective-copy mux': ('Select', 'Repeat context and independent short-frame records.'),
    'Packed-source mux': ('Pack', 'Aggregate before coding, with selective repetition and ACK coalescing.'),
    'Plain TCP': ('TCP', 'Native CUBIC TCP.'),
    'QUIC': ('QUIC', 'CUBIC with a shared ordered stream for inner TCP.'),
    'KCP': ('KCP', 'Fast ARQ, congestion control disabled, 128-segment window.'),
}
PROJECTIONS = (
    (LATENCY, GOODPUT, 'TCP SYN P99 (ms)', 'Goodput (Mbps)'),
    (OVERHEAD, GOODPUT, 'Extra forward IP bytes (%)', 'Goodput (Mbps)'),
    (LATENCY, OVERHEAD, 'TCP SYN P99 (ms)', 'Extra forward IP bytes (%)'),
)
EXPECTED_SEEDS = 3
FIXED_CONDITIONS = dict(forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model='iid', mtu=1500)
MEASUREMENT_PREFIX = 'tcp_syn_ping_measurement_'
CAPACITY_TOLERANCE_MBPS = 1e-6
MUX_RAW_FIELDS = ('flow_count', 'window_policy', 'total_window_bytes', 'transport',
    'tcp_syn_probe_transport', 'tcp_syn_probe_channel_policy', 'tcp_syn_probe_channels_used',
    'tcp_syn_probe_reverse_submitted_frames', 'tcp_syn_probe_stability_queue_model',
    'offered_frames', 'tcp_retransmissions', 'ack_transmitted')
CRC32_CLASSIFIER = 'CRC32(protocol + sorted IPv4 TCP endpoints) modulo channel_count'
MERGE_BASIS = ('Strategies are merged across recorded duration, warmup, flow count, offered load, source and endpoint models. '
               'The highlighted three-objective nondominated means describe these selected experiments. '
               'Conditions and full source receipts remain attached to every point.')
OVERHEAD_DEFINITION = ('Bandwidth, byte overhead and TCP SYN PING use the recorded post-stability probe interval. '
                       'Goodput is 8 × delivered application payload bytes / interval duration / 1e6. '
                       'Extra forward IP bytes (%) is 100 × (serialized forward IP service bytes / delivered application payload bytes − 1). '
                       'Serialization service includes fractional packets at interval boundaries. Whole-packet departures remain separate counters. '
                       'Configuration summaries pool measured payload bytes, IP service bytes and interval durations across all three seeds. '
                       'Every selected run uses 100/10 Mbps forward/reverse IP service, 70 ms RTT, 15% IID loss and MTU 1500. '
                       'Capacity checks allow 0.000001 Mbps floating-counter tolerance and retain the original measured values.')



def measured(row):
    return (row['tcp_syn_probe_steady_state_reached'] is True
            and all(isinstance(row.get(key), (int, float)) and isfinite(row[key]) for key in METRICS)
            and row[LATENCY] > 0 and row[GOODPUT] >= 0
            and row['status'] not in ('unsupported', 'tool failure', 'bound exhausted'))


def group_key(row):
    return row['cohort'], row['study'], row['original_profile']


def selection_keys(selection, section):
    return [('tcp-latency/' + entry['study'].removeprefix('tcp-latency/'), str(run_id))
            for entry in selection.get(section, []) for run_id in entry['run_ids']]


def select_rows(all_rows, selection, minimum_configurations):
    """Require complete primary cohorts and explicitly retain supplementary measurements."""
    requirements = selection.get('publication_requirements', {})
    unified = requirements.get('unified_mux_required', False)
    baselines = requirements.get('shared_transport_baselines_allowed', False)
    channel_limit = requirements.get('max_l2_channels')
    if not isinstance(unified, bool):
        raise ValueError('unified_mux_required must be boolean')
    if not isinstance(baselines, bool) or baselines and not unified:
        raise ValueError('Shared transport baselines require a unified mux comparison')
    if unified or channel_limit is not None:
        if not unified or type(channel_limit) is not int or not 1 <= channel_limit <= 256:
            raise ValueError('Unified mux publication requires an explicit integer max_l2_channels from 1 to 256')
    primary = selection_keys(selection, 'studies')
    supplementary = selection_keys(selection, 'supplementary_studies')
    coverage_keys = selection_keys(selection, 'coverage_only_studies')
    requested = primary + supplementary
    identities = requested + coverage_keys
    if not primary or len(set(identities)) != len(identities):
        raise ValueError('Selection must contain unique explicit study and run IDs')
    indexed = {(row['study'], str(row['run_id'])): row for row in all_rows}
    if len(indexed) != len(all_rows):
        raise ValueError('Loaded study and run identities are ambiguous')
    unknown = set(identities) - indexed.keys()
    if unknown:
        raise ValueError('Unknown selected study and run IDs ' + repr(sorted(unknown)))
    selected = [indexed[key] for key in requested]
    coverage = [indexed[key] for key in coverage_keys]
    if any(measured(row) for row in coverage):
        raise ValueError('Coverage-only selection cannot hide a measured run')
    bad = [row['id'] for row in selected if not measured(row)]
    if bad:
        raise ValueError('Selected rows lack finite measured three-axis coordinates ' + repr(bad))
    for row in selected + coverage:
        if any(row.get(key) != expected for key, expected in FIXED_CONDITIONS.items()):
            raise ValueError('Selected row violates fixed physical conditions ' + row['id'])
    for key, row in zip(requested, selected):
        row['publication_role'] = 'primary' if key in primary else 'supplementary'
        validate_capacity(row)
        if unified:
            kind = json.loads(row['original_profile']).get('kind')
            if baselines and kind in ('tcp', 'quic_inner', 'kcp_inner'):
                validate_transport_baseline(row, channel_limit)
                row['shared_transport_baseline_qualified'] = True
            else:
                validate_unified_mux(row, channel_limit)
                row['unified_mux_qualified'] = True
            row['joint_target_met'] = bool(row['eligible']
                and all(row[key] >= .8 * row['forward_mbps'] for key in ('goodput_mbps', CONCURRENT_GOODPUT, GOODPUT))
                and row[LATENCY] <= row['tcp_syn_ping_budget_ms']
                and row['tcp_syn_ping_deadline_miss_upper_pct'] is not None
                and row['tcp_syn_ping_deadline_miss_upper_pct'] <= 1)
    if any(row['payload_bytes'] not in PAYLOADS for row in selected):
        raise ValueError('Selected payload is outside the six requested payloads')
    available_groups, selected_groups = defaultdict(list), defaultdict(list)
    for row in all_rows:
        available_groups[group_key(row)].append(row)
    for row in selected:
        selected_groups[group_key(row)].append(row)
    seed_receipts, partial_receipts = [], []
    for key, rows in selected_groups.items():
        complete = available_groups[key]
        all_members = {row['id'] for row in rows} == {row['id'] for row in complete}
        primary_group = any(row['publication_role'] == 'primary' for row in rows)
        if primary_group and any(row['publication_role'] != 'primary' for row in rows):
            raise ValueError('A configuration cohort cannot mix primary and supplementary roles')
        if primary_group and not all_members:
            raise ValueError('Selection omits recorded members of a configuration cohort ' + rows[0]['label'])
        seeds = {str(row['seed']) for row in rows if row['seed'] is not None}
        three_seeds = len(rows) == EXPECTED_SEEDS and len(seeds) == EXPECTED_SEEDS
        if primary_group and not three_seeds:
            raise ValueError('Every selected configuration cohort requires exactly three distinct recorded seeds ' + rows[0]['label'])
        for row in rows:
            row['configuration_complete'] = all_members and three_seeds
            row['frontier_eligible'] = row['eligible'] and row['configuration_complete']
        receipt = dict(study=rows[0]['study'], payload_bytes=rows[0]['payload_bytes'],
            cohort=key[0], original_profile=key[2], seeds=sorted(seeds), raw_ids=[row['id'] for row in rows],
            recorded_raw_ids=[row['id'] for row in complete])
        (seed_receipts if all_members and three_seeds else partial_receipts).append(receipt)
    counts = {}
    for payload in PAYLOADS:
        count = len({row['original_profile'] for row in selected if row['payload_bytes'] == payload and row['configuration_complete']})
        counts[str(payload)] = count
        if count < minimum_configurations:
            raise ValueError(f'Payload {payload} requires {minimum_configurations} complete configurations, observed {count}')
    return selected, dict(expected_seeds_per_configuration=EXPECTED_SEEDS,
        configuration_counts=counts, configuration_seed_receipts=seed_receipts,
        selected_rows=len(selected), measured_rows=len(selected), coverage_only_rows=len(coverage),
        primary_rows=len(primary), supplementary_rows=len(supplementary), partial_configuration_receipts=partial_receipts,
        coverage_only_ids=[row['id'] for row in coverage],
        all_three_coordinates_finite=True, all_selected_configuration_cohorts_complete=not partial_receipts,
        all_primary_configuration_cohorts_complete=True,
        max_capacity_identity_error_mbps=max(row['capacity_identity_error_mbps'] for row in selected),
        all_forward_ip_capacity_bounds_passed=True, fixed_physical_conditions=FIXED_CONDITIONS,
        unified_mux_required=unified, max_l2_channels=channel_limit,
        shared_transport_baselines_allowed=baselines,
        shared_transport_baseline_validated_rows=sum(row.get('shared_transport_baseline_qualified', False) for row in selected),
        unified_mux_validated_rows=sum(row.get('unified_mux_qualified', False) for row in selected),
        mandatory_measurement_source_prefix=MEASUREMENT_PREFIX, capacity_tolerance_mbps=CAPACITY_TOLERANCE_MBPS)


def validate_transport_baseline(row, channel_limit):
    """Require native IP or shared finite QUIC/KCP record paths for comparison."""
    profile = json.loads(row['original_profile'])
    kind = profile.get('kind')
    count = profile.get('flow_count')
    if kind not in ('tcp', 'quic_inner', 'kcp_inner') or profile.get('mux') is not None:
        raise ValueError('Unknown native transport baseline ' + row['id'])
    if type(count) is not int or not 1 <= count <= channel_limit or row.get('flow_count') != count:
        raise ValueError('Baseline flow count differs or exceeds limit ' + row['id'])
    window = profile.get('window_bytes')
    if (type(window) is not int or window < count * row['payload_bytes']
            or row.get('window_policy') != 'fixed_total' or type(row.get('total_window_bytes')) is not int
            or row['total_window_bytes'] != window // row['payload_bytes'] * row['payload_bytes']):
        raise ValueError('Baseline total TCP window differs ' + row['id'])
    if kind == 'tcp':
        if row.get('transport') != 'direct_tcp' or row.get('tcp_syn_probe_transport') != 'native IPv4 TCP':
            raise ValueError('TCP baseline requires the native IP path ' + row['id'])
        row['baseline_internal_queue_observed'] = True
        return
    expected_transport = 'inner_tcp_over_' + kind.removesuffix('_inner')
    if (row.get('transport') != expected_transport or row.get('tunnel_protocol') != kind
            or row.get('tunnel_connection_count') != count or row.get('tunnel_shared_record_path') is not True
            or row.get('tunnel_inner_tcp') is not True or row.get('tunnel_probe_extra_connections') != 0
            or row.get('tunnel_probe_extra_streams') != 0
            or row.get('tunnel_tcp_total_window_bytes') != row['total_window_bytes']):
        raise ValueError('Baseline requires shared inner TCP record paths ' + row['id'])
    mux = row.get('tunnel_mux', {})
    if (not isinstance(mux, dict) or type(mux.get('mux_channel_count')) is not int
            or mux['mux_channel_count'] != count or mux.get('mux_mapping') != 'connection_round_robin'):
        raise ValueError('Baseline shared connection pool differs ' + row['id'])
    inventories = []
    for direction in ('forward', 'reverse'):
        metrics = mux.get('mux_' + direction, {})
        if not isinstance(metrics, dict):
            raise ValueError('Baseline admission evidence differs ' + row['id'])
        admitted, submitted = metrics.get('channel_ids'), metrics.get('submitted_channel_ids')
        for ids in (admitted, submitted):
            if (not isinstance(ids, list) or not ids
                    or any(type(value) is not int or not 0 <= value < count for value in ids)
                    or len(set(ids)) != len(ids)):
                raise ValueError('Baseline actual channel inventory differs ' + row['id'])
        if (type(metrics.get('channel_count')) is not int or metrics['channel_count'] != len(admitted)
                or not set(admitted) <= set(submitted)):
            raise ValueError('Baseline actual channel count differs ' + row['id'])
        for unit in ('frames', 'bytes'):
            counters = [metrics.get(stage + '_' + unit) for stage in ('submitted', 'admitted', 'delivered', 'queued')]
            if (any(type(value) is not int or value < 0 for value in counters)
                    or not counters[0] >= counters[1] >= counters[2] or counters[3] != counters[0] - counters[1]):
                raise ValueError('Baseline admission counter identity differs ' + row['id'])
            if row['fully_confirmed'] and not counters[0] == counters[1] == counters[2]:
                raise ValueError('Confirmed baseline has pending shared records ' + row['id'])
        inventories.append(metrics)
    probe_channels = row.get('tcp_syn_probe_channels_used')
    if (not isinstance(probe_channels, list)
            or not probe_channels and row.get('tcp_syn_ping_offered') != 0
            or any(type(value) is not int for value in probe_channels)
            or len(set(probe_channels)) != len(probe_channels)
            or not set(probe_channels) <= set(inventories[0]['submitted_channel_ids'])):
        raise ValueError('Baseline probe channels differ from shared forward inventory ' + row['id'])
    frame_fields = (('offered_frames', 'tcp_retransmissions', 'tcp_syn_probe_forward_frames'),
                    ('ack_transmitted', 'tcp_syn_probe_reverse_submitted_frames'))
    for metrics, fields in zip(inventories, frame_fields):
        values = [row.get(key) for key in fields]
        if (any(not isinstance(value, (int, float)) or isinstance(value, bool) or not isfinite(value)
                or value < 0 or value != int(value) for value in values)
                or metrics['submitted_frames'] != sum(values)):
            raise ValueError('Baseline bulk and probe frame totals differ from shared admission ' + row['id'])
    records = row.get('tunnel_protocol_records', [])
    if not isinstance(records, list) or len(records) != count or any(not isinstance(record, dict) for record in records):
        raise ValueError('Baseline per-connection evidence is missing ' + row['id'])
    queue_model = 'physical FIFO plus shared ingress and admitted protocol bytes not yet first transmitted'
    internal_queue_observed = (row.get('tunnel_stability_queue_model') == queue_model
        and row.get('tcp_syn_probe_stability_queue_model') == queue_model
        and all('pending_first_transmission_bytes' in record for record in records))
    row['baseline_internal_queue_observed'] = internal_queue_observed
    if not internal_queue_observed:
        reason = 'legacy queue gate omits admitted protocol bytes awaiting first transmission'
        reasons = [part for part in (row.get('exclusion_reason') or '').split(' | ') if part]
        if reason not in reasons:
            reasons.append(reason)
        row.update(eligible=False, frontier_eligible=False, joint_target_met=False,
                   exclusion_reason=' | '.join(reasons))
        if row.get('status') not in ('unsupported', 'tool failure', 'bound exhausted'):
            row['status'] = 'ineligible'
        if row.get('publication_role') == 'primary':
            raise ValueError('Primary baseline requires internal protocol queue observations ' + row['id'])
    if row['fully_confirmed'] and row.get('tunnel_all_confirmed') is not True:
        raise ValueError('Confirmed baseline lacks shared transport confirmation ' + row['id'])
    quic = kind == 'quic_inner'
    window_key, peak_key = (('sender_window_bytes', 'peak_outstanding_bytes') if quic
                            else ('sender_window_segments', 'peak_waiting_segments'))
    submitted_key, received_key = (('submitted_stream_bytes', 'received_stream_bytes') if quic
                                  else ('submitted_frame_bytes', 'received_frame_bytes'))
    totals = {submitted_key: [0, 0], received_key: [0, 0]}
    slots = window // row['payload_bytes']
    for index, record in enumerate(records):
        if quic and record.get('streams') != [[0], [0]]:
            raise ValueError('QUIC baseline requires the shared stream zero ' + row['id'])
        if type(record.get('confirmed')) is not bool or row['fully_confirmed'] and record['confirmed'] is not True:
            raise ValueError('Baseline per-connection confirmation differs ' + row['id'])
        expected_window = ((slots // count + (index < slots % count)) * (row['payload_bytes'] + 68)
                           if quic else profile.get('kcp', {}).get('window', 128))
        if type(record.get(window_key)) is not int or record[window_key] != expected_window or expected_window <= 0:
            raise ValueError('Baseline protocol sender window differs ' + row['id'])
        pair_keys = (peak_key, submitted_key, received_key, 'acknowledged_stream_bytes' if quic else 'retransmitted_segments')
        for key in pair_keys:
            pair = record.get(key)
            if not isinstance(pair, list) or len(pair) != 2 or any(type(value) is not int or value < 0 for value in pair):
                raise ValueError('Baseline directional protocol counter differs ' + row['id'])
        if internal_queue_observed:
            first_key = 'first_transmitted_stream_bytes' if quic else 'first_transmitted_frame_bytes'
            for key in ('pending_first_transmission_bytes', 'peak_pending_first_transmission_bytes', first_key):
                pair = record.get(key)
                if not isinstance(pair, list) or len(pair) != 2 or any(type(value) is not int or value < 0 for value in pair):
                    raise ValueError('Baseline internal protocol queue counter differs ' + row['id'])
            for direction in range(2):
                pending = record['pending_first_transmission_bytes'][direction]
                peak = record['peak_pending_first_transmission_bytes'][direction]
                if (pending > peak or record[first_key][direction] + pending != record[submitted_key][direction]
                        or quic and peak > expected_window or record['confirmed'] and pending):
                    raise ValueError('Baseline internal protocol queue identity differs ' + row['id'])
        if any(peak > expected_window for peak in record[peak_key]):
            raise ValueError('Baseline protocol sender window exceeded ' + row['id'])
        for direction in range(2):
            submitted_bytes, received_bytes = record[submitted_key][direction], record[received_key][direction]
            if received_bytes > submitted_bytes or record['confirmed'] and received_bytes != submitted_bytes:
                raise ValueError('Baseline per-connection byte confirmation differs ' + row['id'])
            if quic:
                acknowledged = record['acknowledged_stream_bytes'][direction]
                if acknowledged > received_bytes or record['confirmed'] and acknowledged != submitted_bytes:
                    raise ValueError('QUIC per-connection acknowledgement differs ' + row['id'])
            totals[submitted_key][direction] += submitted_bytes
            totals[received_key][direction] += received_bytes
    for direction, metrics in enumerate(inventories):
        framing = 2 if quic else 0
        submitted_bytes = metrics['admitted_bytes'] + framing * metrics['admitted_frames']
        received_bytes = metrics['delivered_bytes'] + framing * metrics['delivered_frames']
        if (totals[submitted_key][direction] != submitted_bytes or totals[received_key][direction] < received_bytes
                or (not quic or row['fully_confirmed']) and totals[received_key][direction] != received_bytes):
            raise ValueError('Baseline protocol bytes differ from shared frame admission ' + row['id'])


def validate_unified_mux(row, channel_limit):
    """Verify recorded shared admission and actual channel inventories in both directions."""
    profile = json.loads(row['original_profile'])
    configured = profile.get('mux')
    channels = configured.get('channels') if isinstance(configured, dict) else None
    if (type(channels) is not int or not 1 <= channels <= channel_limit
            or type(row.get('mux_channel_count')) is not int or row['mux_channel_count'] != channels
            or row.get('transport') != 'unified_duplex_mux_inner_tcp'):
        raise ValueError('Missing or inconsistent unified mux channel configuration ' + row['id'])
    mapping = configured.get('mapping', 'crc32')
    recorded_mapping = row.get('mux_mapping')
    if recorded_mapping is None and row.get('mux_classifier') == CRC32_CLASSIFIER:
        recorded_mapping = 'crc32'
    if mapping not in ('crc32', 'connection_round_robin') or recorded_mapping != mapping:
        raise ValueError('Unified mux mapping differs from the recorded classifier ' + row['id'])
    flows = row.get('flow_count')
    if (type(flows) is not int or not 1 <= flows <= channel_limit
            or type(profile.get('flow_count')) is not int or flows != profile['flow_count']):
        raise ValueError('Unified mux actual bulk flow count differs or exceeds limit ' + row['id'])
    window = profile.get('window_bytes')
    if (type(window) is not int or window < row['payload_bytes'] * flows
            or row.get('window_policy') != 'fixed_total' or type(row.get('total_window_bytes')) is not int
            or row['total_window_bytes'] != window // row['payload_bytes'] * row['payload_bytes']):
        raise ValueError('Unified mux total TCP window differs from fixed-total configuration ' + row['id'])
    probe = json.loads(row['tcp_syn_probe_config'])
    profile_probe = profile.get('tcp_syn_probe', {})
    if (type(profile.get('ack_copies')) is not int or profile['ack_copies'] != 1
            or profile.get('ack_aggregation') is not False
            or type(probe.get('reverse_copies')) is not int or probe['reverse_copies'] != 1
            or type(profile_probe.get('reverse_copies')) is not int or profile_probe['reverse_copies'] != 1):
        raise ValueError('Unified mux requires common copy protection and no separate ACK aggregator ' + row['id'])
    probe_channels = row.get('tcp_syn_probe_channels_used')
    inventories = []
    for direction in ('forward', 'reverse'):
        metadata = row.get('mux_' + direction)
        if not isinstance(metadata, dict):
            raise ValueError('Missing unified mux directional inventory ' + row['id'])
        admitted, submitted = metadata.get('channel_ids'), metadata.get('submitted_channel_ids')
        for ids in (admitted, submitted, probe_channels):
            if (not isinstance(ids, list) or not ids or any(type(value) is not int or not 0 <= value < channels for value in ids)
                    or len(set(ids)) != len(ids)):
                raise ValueError('Invalid unified mux actual channel IDs ' + row['id'])
        if (type(metadata.get('channel_count')) is not int or metadata['channel_count'] != len(admitted)
                or not set(admitted) <= set(submitted)):
            raise ValueError('Unified mux actual channel count differs from inventory ' + row['id'])
        counters = [metadata.get(key) for key in ('submitted_frames', 'admitted_frames', 'delivered_frames', 'queued_frames')]
        if (any(type(value) is not int or value < 0 for value in counters)
                or not counters[0] >= counters[1] >= counters[2]
                or counters[3] != counters[0] - counters[1]):
            raise ValueError('Inconsistent unified mux frame admission counters ' + row['id'])
        inventories.append(metadata)
    if not set(probe_channels) <= set(inventories[0]['submitted_channel_ids']):
        raise ValueError('Probe channels are outside the shared forward mux inventory ' + row['id'])
    forward = ('offered_frames', 'tcp_retransmissions', 'tcp_syn_probe_forward_frames')
    reverse = ('ack_transmitted', 'tcp_syn_probe_reverse_submitted_frames')
    for metadata, fields in zip(inventories, (forward, reverse)):
        values = [row.get(key) for key in fields]
        if (any(not isinstance(value, (int, float)) or isinstance(value, bool) or not isfinite(value)
                or value < 0 or value != int(value) for value in values)
                or metadata['submitted_frames'] != sum(values)):
            raise ValueError('Bulk and probe frames do not share the recorded mux admission counters ' + row['id'])


def validate_capacity(row):
    """Require interval identities and the physical forward IP service bound."""
    keys = (GOODPUT, OVERHEAD, 'probe_interval_payload_bytes', 'probe_interval_forward_ip_bytes',
            'probe_interval_duration_s', 'forward_mbps')
    if not all(isinstance(row.get(key), (int, float)) and isfinite(row[key]) for key in keys):
        raise ValueError('Missing finite probe-interval accounting ' + row['id'])
    payload = row['probe_interval_payload_bytes']
    wire = row['probe_interval_forward_ip_bytes']
    duration = row['probe_interval_duration_s']
    capacity = row['forward_mbps']
    if payload <= 0 or duration <= 0 or wire < 0 or capacity <= 0:
        raise ValueError('Invalid probe-interval accounting ' + row['id'])
    expected_goodput = payload * 8 / duration / 1e6
    expected_overhead = 100 * (wire / payload - 1)
    wire_rate = wire * 8 / duration / 1e6
    implied_rate = row[GOODPUT] * (1 + row[OVERHEAD] / 100)
    identities = ((row[GOODPUT], expected_goodput), (row[OVERHEAD], expected_overhead), (implied_rate, wire_rate))
    if not all(isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9) for actual, expected in identities):
        raise ValueError('Probe-interval capacity identity mismatch ' + row['id'])
    if wire_rate > capacity + CAPACITY_TOLERANCE_MBPS:
        raise ValueError('Forward IP capacity exceeded ' + row['id'])
    row['probe_interval_forward_ip_mbps'] = wire_rate
    row['capacity_identity_error_mbps'] = abs(implied_rate - wire_rate)


def audit_bytes(root, rows):
    """Require same-window source counters and independently verify snapshot deltas."""
    for row in rows:
        data = (root / row['source']).read_bytes()
        if sha256(data).hexdigest() != row['source_sha256']:
            raise ValueError('Raw source changed while loading ' + row['source'])
        raw = json.loads(data)
        row.update({key: value for key, value in raw.items() if key.startswith(('mux_', 'tunnel_')) or key in MUX_RAW_FIELDS})
        if 'mux_channel_count' in raw:
            row['unified_mux_evidence'] = report.canonical({key: value for key, value in raw.items()
                if key.startswith('mux_') or key in MUX_RAW_FIELDS})
        prefix = MEASUREMENT_PREFIX
        snapshots = raw.get(prefix + 'snapshots') or {}
        start, end = snapshots.get('start'), snapshots.get('end')
        snapshot_keys = ('at_s', 'delivered_payload_bytes', 'forward_serialized_ip_bytes',
                         'reverse_serialized_ip_bytes', 'forward_departed_ip_bytes', 'reverse_departed_ip_bytes')
        if not all(isinstance(item, dict) and all(isinstance(item.get(key), (int, float))
                   and isfinite(item[key]) for key in snapshot_keys) for item in (start, end)):
            raise ValueError('Missing finite same-window measurement snapshots ' + row['id'])
        duration = end['at_s'] - start['at_s']
        payload = end['delivered_payload_bytes'] - start['delivered_payload_bytes']
        if duration <= 0 or payload <= 0 or start['at_s'] != row['tcp_syn_probe_start_s'] or end['at_s'] != row['duration_s']:
            raise ValueError('Measurement interval differs from probe gate and traffic cutoff ' + row['id'])
        if start['at_s'] < row['warmup_s'] or raw.get('payload_bytes_per_frame') != row['payload_bytes']:
            raise ValueError('Measurement warmup or payload frame contract differs ' + row['id'])
        expected = dict(start_s=start['at_s'], end_s=end['at_s'], duration_s=duration, payload_bytes=payload)
        for direction in ('forward', 'reverse'):
            wire = end[direction + '_serialized_ip_bytes'] - start[direction + '_serialized_ip_bytes']
            departed = end[direction + '_departed_ip_bytes'] - start[direction + '_departed_ip_bytes']
            expected[direction + '_ip_bytes'] = wire
            expected[direction + '_departed_ip_bytes'] = departed
            expected[direction + '_mbps'] = wire * 8 / duration / 1e6
            if wire < 0 or departed < 0 or expected[direction + '_mbps'] > row[direction + '_mbps'] + CAPACITY_TOLERANCE_MBPS:
                raise ValueError('Snapshot service exceeds physical capacity ' + row['id'])
        expected['extra_forward_ip_pct'] = 100 * (expected['forward_ip_bytes'] / payload - 1)
        for key, value in expected.items():
            observed = raw.get(prefix + key)
            if not isinstance(observed, (int, float)) or not isfinite(observed) or not isclose(observed, value, rel_tol=1e-12, abs_tol=1e-6):
                raise ValueError('Missing or inconsistent same-window source field ' + prefix + key + ' ' + row['id'])
        goodput = payload * 8 / duration / 1e6
        if not isinstance(row.get(CONCURRENT_GOODPUT), (int, float)) or not isclose(row[CONCURRENT_GOODPUT], goodput, rel_tol=1e-12, abs_tol=1e-9):
            raise ValueError('Concurrent goodput differs from measurement payload interval ' + row['id'])
        row.update(probe_interval_payload_bytes=payload, probe_interval_forward_ip_bytes=expected['forward_ip_bytes'],
                   probe_interval_reverse_ip_bytes=expected['reverse_ip_bytes'], probe_interval_duration_s=duration,
                   probe_interval_start_s=start['at_s'], probe_interval_end_s=end['at_s'],
                   probe_interval_forward_departed_ip_bytes=expected['forward_departed_ip_bytes'],
                   probe_interval_reverse_departed_ip_bytes=expected['reverse_departed_ip_bytes'],
                   measurement_snapshots=snapshots, measurement_byte_accounting=raw.get(prefix + 'byte_accounting'))
        row[GOODPUT] = goodput
        row[OVERHEAD] = expected['extra_forward_ip_pct']
        validate_capacity(row)


def summarize(rows):
    means = report.summarize([row for row in rows if row.get('configuration_complete', True)])
    indexed = {row['id']: row for row in rows}
    for mean in means:
        members = [indexed[key] for key in json.loads(mean['raw_ids'])]
        for key in ('probe_interval_payload_bytes', 'probe_interval_forward_ip_bytes', 'probe_interval_reverse_ip_bytes',
                    'probe_interval_forward_departed_ip_bytes', 'probe_interval_reverse_departed_ip_bytes', 'probe_interval_duration_s'):
            mean[key] = sum(row[key] for row in members)
        mean[GOODPUT] = mean['probe_interval_payload_bytes'] * 8 / mean['probe_interval_duration_s'] / 1e6
        mean[OVERHEAD] = 100 * (mean['probe_interval_forward_ip_bytes'] / mean['probe_interval_payload_bytes'] - 1)
        mean[GOODPUT + '_n'] = mean[OVERHEAD + '_n'] = len(members)
        mean['interval_aggregation'] = 'Goodput 8 sum(payload) / sum(duration) / 1e6; extra IP 100 (sum(IP service) / sum(payload) - 1)'
        mean['latency_aggregation'] = 'Arithmetic mean of per-run completed-probe P99 values'
        validate_capacity(mean)
        mean['complete_three_seed_coordinates'] = (len(members) == EXPECTED_SEEDS
            and len({str(row['seed']) for row in members}) == EXPECTED_SEEDS and all(measured(row) for row in members))
        mean['exclusion_reasons'] = sorted({row['exclusion_reason'] for row in members if row['exclusion_reason']})
        mean['timeout_count'] = sum(row['tcp_syn_ping_timeouts'] for row in members)
        if any('mux_channel_count' in row for row in members):
            mean['mux_run_evidence'] = report.canonical([dict(raw_id=row['id'], **{
                key: value for key, value in row.items() if key.startswith('mux_') or key in MUX_RAW_FIELDS}) for row in members])
            mean['unified_mux_qualified'] = all(row.get('unified_mux_qualified') is True for row in members)
    return means


def frontier(means):
    candidates = [row for row in means if row['eligible'] and row['complete_three_seed_coordinates']]
    def dominates(left, right):
        return (left[LATENCY] <= right[LATENCY] and left[GOODPUT] >= right[GOODPUT]
            and left[OVERHEAD] <= right[OVERHEAD] and any((left[LATENCY] < right[LATENCY],
                left[GOODPUT] > right[GOODPUT], left[OVERHEAD] < right[OVERHEAD])))
    return [row for row in candidates if not any(dominates(other, row) for other in candidates)]


def condition(row):
    profile = json.loads(row['original_profile'])
    probe = json.loads(row['tcp_syn_probe_config'])
    mux = row.get('tunnel_mux', {}) if profile.get('kind') in ('quic_inner', 'kcp_inner') else row
    if profile.get('kind') == 'tcp':
        mux = {}
    rate = profile.get('payload_rate_mbps')
    load = (f'{rate:g} Mbps configured payload rate' if isinstance(rate, (int, float)) and rate > 0
            else 'Saturated / congestion-controlled, no fixed Mbps cap')
    gate = f"{probe['stability_windows']} × {probe['stability_window_s']:g} s"
    return dict(study=row['study'], source_version=row['engine_source_version'],
        duration_s=row['duration_s'], warmup_s=row['warmup_s'], drain_s=row['drain_s'],
        forward_mbps=row['forward_mbps'], reverse_mbps=row['reverse_mbps'], rtt_ms=row['rtt_ms'],
        loss_rate=row['loss_rate'], loss_model=row['loss_model'], flows=profile.get('flow_count'),
        payload_rate_mbps=rate, offered_load_label=load, stability_gate_label=gate,
        stability_windows=probe['stability_windows'], stability_window_s=probe['stability_window_s'],
        throughput_tolerance_pct=probe['throughput_tolerance_pct'], queue_tolerance_ms=probe['queue_tolerance_ms'],
        endpoint_dispatch=row['endpoint_dispatch'], probe_cpu_model=row['probe_cpu_model'],
        probe_model_detail=row['probe_model_detail'], actual_bulk_flows=row.get('flow_count'),
        mux_channels=mux.get('mux_channel_count'), mux_mapping=mux.get('mux_mapping'),
        mux_forward=mux.get('mux_forward'), mux_reverse=mux.get('mux_reverse'),
        total_window_bytes=row.get('total_window_bytes'), window_policy=row.get('window_policy'))


def strategy_labels(row):
    """Give the measured transport a concise name and a readable configuration overview."""
    profile = json.loads(row['original_profile'])
    compact = profile.get('compact', {})
    kind, recovery = profile.get('kind'), profile.get('recovery')
    flows = profile.get('flow_count')
    rate = profile.get('payload_rate_mbps')
    load = f'offered {rate:g} Mbps' if isinstance(rate, (int, float)) and rate > 0 else 'uncapped load'
    if isinstance(profile.get('mux'), dict):
        channels = profile['mux']['channels']
        mapping = profile['mux'].get('mapping', 'crc32')
        mapping_label = 'RR' if mapping == 'connection_round_robin' else 'Hash'
        mapping_detail = 'round-robin connection assignment' if mapping == 'connection_round_robin' else 'CRC32 endpoint mapping'
        ratio = compact.get('repair_ratio', 0) * 100
        copies = compact.get('short_source_copies', 1)
        threshold = compact.get('short_source_max_bytes', 0)
        tail = compact.get('tail_repair_delay_ms')
        independent = compact.get('independent_short_frame_bytes', 0)
        prefix = ('Ind' if mapping_label == 'RR' else 'IndHash') if independent else mapping_label
        name = f'{prefix}{channels}' + (f' TCP{flows}' if flows != channels else '') + f' r{ratio:g}×{copies if threshold > 0 else 1}'
        if tail is not None:
            name += f' Tail{tail:g}'
        window = row.get('total_window_bytes')
        window_label = f'{window:,} B total TCP window' if isinstance(window, int) else f"{profile.get('window_bytes'):,} B configured total TCP window"
        detail = (f'{flows} bulk flows, {window_label}, same {channels}-channel pool for bulk and probes in both directions, '
                  f'{mapping_detail}, {ratio:g}% repair, {compact.get("block_sources", 8192)}-source global window / '
                  f'{compact.get("repair_window_sources", 128)}-source repair window')
        if copies > 1 and threshold > 0:
            scope = compact.get('short_source_copy_scope', 'all_short')
            if scope == 'context_and_independent':
                detail += f', context and independent full-frame units ≤{threshold:g} B ×{copies} in both directions'
            else:
                detail += f', all sources ≤{threshold:g} B ×{copies} in both directions'
        packing = compact.get('pack_sources_max_delay_ms', 0)
        if packing or compact.get('short_source_copy_scope') == 'context_and_independent':
            name = f'Pack{packing:g}' if packing else 'Select'
            rate_label = f'{rate:g}M' if isinstance(rate, (int, float)) and rate > 0 else 'uncapped'
            name += f" {rate_label} A{profile.get('ack_every', 2)} C{profile.get('ack_coalesce_ms', 0):g}"
            if packing:
                detail += f', same-copy units packed before coding, {packing:g} ms maximum hold, 1460 B source limit'
        if tail is not None:
            detail += f', {tail:g} ms tail repair'
    elif kind == 'tcp':
        name, detail = 'TCP', f"{flows} flows, {profile.get('controller', 'cubic').upper()}, {profile.get('rto_min_ms', 1000):g} ms minimum RTO"
    elif kind == 'quic':
        name, detail = 'QUIC', f"{flows} connections, {profile.get('controller', 'cubic').upper()}, probe on auxiliary stream"
    elif kind == 'quic_inner':
        name, detail = 'QUIC', f'{flows} outer CUBIC connections, modeled inner TCP, one shared ordered stream 0 per connection for bulk and probes'
    elif kind == 'kcp_inner':
        settings = profile['kcp']
        name, detail = 'KCP', (f"{flows} upstream KCP conversations, modeled inner TCP, shared ordered message queues, "
            f"window {settings['window']}, nodelay {settings['nodelay']}, interval {settings['interval']} ms, "
            f"resend {settings['resend']}, nocwnd {settings['nocwnd']}")
    elif recovery == 'arq':
        name, detail = 'ARQ', f'{flows} flows, retransmission recovery'
    elif recovery == 'block':
        sources = compact.get('generation_sources', 5)
        name = f'FEC {sources}+1'
        detail = f"{flows} flows, up to {sources} data + 1 initial repair, {compact.get('idle_flush_ms', 2):g} ms idle flush, feedback repairs"
    elif recovery == 'rlnc':
        ratio = compact.get('repair_ratio', 0) * 100
        name, detail = f'RLNC {ratio:g}%', f'{flows} flows, {ratio:g}% configured repair ratio'
    elif recovery == 'shared_record_rlnc':
        copies = compact.get('short_source_copies', 1)
        tail = compact.get('tail_repair_delay_ms')
        name = 'Shared RLNC' if copies == 1 else f'Shared RLNC + Short×{copies}'
        if tail is not None:
            name += f' + Tail{tail:g}'
        detail = (f"{flows} flows, {compact.get('repair_ratio', 0) * 100:g}% repair, "
                  f"{compact.get('block_sources', 8192)}-source generation / {compact.get('repair_window_sources', 128)}-source repair window, "
                  f"≤{compact.get('short_source_max_bytes', 128)} B ×{copies}")
        if tail is not None:
            detail += f', {tail:g} ms tail repair'
        probe = json.loads(row['tcp_syn_probe_config'])
        detail += f", SYN-ACK ×{probe['reverse_copies']}"
    else:
        name, detail = profile['name'], f'{flows} flows'
    full_frame_limit = compact.get('independent_short_frame_bytes', 0)
    if full_frame_limit > 0:
        if not isinstance(profile.get('mux'), dict) or full_frame_limit != 128:
            name += f' + Full{full_frame_limit:g}'
        detail += (f', independent full Ethernet frames ≤{full_frame_limit:g} B, '
                   'protected source extent = frame length + 6 B')
    if isinstance(profile.get('mux'), dict) or full_frame_limit > 0:
        detail += (f", TCP ACK every {profile.get('ack_every', 2)} segments, "
                   f"{profile.get('ack_delay_ms', 10):g} ms ACK delay")
        if compact.get('pack_sources_max_delay_ms', 0) or compact.get('short_source_copy_scope') == 'context_and_independent':
            detail += f", {profile.get('ack_coalesce_ms', 0):g} ms advancing-ACK coalescing"
    if kind in ('quic_inner', 'kcp_inner') and row.get('baseline_internal_queue_observed') is False:
        name += ' old gate'
        detail += ', historical admission gate omitted protocol-internal unsent bytes'
    return name, detail + '. ' + load


def decorate(rows, means):
    keys = sorted({group_key(row) for row in rows})
    for row in rows:
        index = keys.index(group_key(row))
        name, overview = strategy_labels(row)
        profile = json.loads(row['original_profile'])
        if profile.get('kind') in ('tcp', 'quic_inner', 'kcp_inner'):
            name += f" {profile['payload_rate_mbps']:g}M {row['duration_s']:g}s"
        if isinstance(profile.get('mux'), dict):
            compact = profile.get('compact', {})
            if compact.get('pack_sources_max_delay_ms', 0):
                family, color = 'Packed-source mux', '#0891b2'
            elif compact.get('short_source_copy_scope') == 'context_and_independent':
                family, color = 'Selective-copy mux', '#9333ea'
            elif compact.get('independent_short_frame_bytes', 0):
                family, color = 'Independent-short mux', '#15803d'
            elif profile['mux'].get('mapping', 'crc32') == 'connection_round_robin':
                family, color = 'Round-robin ordered mux', '#d97706'
            else:
                family, color = 'Hash ordered mux', '#2563eb'
            row.update(color_group=family, color_label=family, color=color)
        elif profile.get('kind') in ('quic_inner', 'kcp_inner'):
            family, color = ('QUIC', '#f97316') if profile['kind'] == 'quic_inner' else ('KCP', '#dc2626')
            row.update(color_group=family, color_label=family, color=color)
        row.update(strategy_name=name, strategy_configuration=overview, series_configuration=f'C{index + 1:02d}', series_marker=MARKERS[index % len(MARKERS)],
            series_plotly_marker=PLOTLY_MARKERS[index % len(PLOTLY_MARKERS)],
            series_plotly_glyph=PLOTLY_GLYPHS[index % len(PLOTLY_GLYPHS)], conditions=condition(row))
    indexed = {row['id']: row for row in rows}
    for mean in means:
        first = indexed[json.loads(mean['raw_ids'])[0]]
        mean.update({key: first[key] for key in ('series_configuration', 'series_marker', 'series_plotly_marker', 'series_plotly_glyph', 'strategy_name', 'strategy_configuration', 'conditions', 'color_group', 'color_label', 'color')})


def configuration_rows(rows):
    representatives = {}
    for row in rows:
        representatives.setdefault(group_key(row), row)
    return list(representatives.values())


def strategy_families(rows):
    families = {}
    for row in rows:
        group = row['color_group']
        name, overview = STRATEGY_OVERVIEWS.get(group, (row['color_label'], row['color_label']))
        families.setdefault(group, dict(group=group, name=name, overview=overview, color=row['color']))
    return list(families.values())


def static_overview(configurations):
    return '', [family['name'] + ' — ' + family['overview'] for family in strategy_families(configurations)]


def hover(row, *, mean=False, nondominated=False):
    details = row['conditions']
    identity = f"Three-seed configuration summary {row['id']}" if mean else f"Run {row['run_id']} · seed {row['seed']}"
    failures = ', '.join(row['exclusion_reasons']) if mean else row['exclusion_reason']
    timeouts = row['timeout_count'] if mean else row['tcp_syn_ping_timeouts']
    return '<br>'.join(escape(str(value)) for value in (
        row['strategy_name'], row['strategy_configuration'], row['color_label'], identity,
        f"{row['payload_bytes']:g} B payload · {details['offered_load_label']}",
        f"TCP SYN P99 {row[LATENCY]:.4g} ms · probe-interval goodput {row[GOODPUT]:.4g} Mbps · extra IP {row[OVERHEAD]:.4g}%",
        ('Pooled measured traffic; arithmetic mean of per-run P99' if mean else 'Bandwidth and IP service use the same post-stability interval'),
        f"Frontier eligible {row.get('frontier_eligible', row['eligible'])} · nondominated {nondominated} · timeouts {timeouts:g}", failures,
        ('Complete three-seed configuration' if row.get('configuration_complete', True) else 'Supplementary individual run; configuration lacks a complete measured three-seed cohort'),
        f"{details['forward_mbps']:g}/{details['reverse_mbps']:g} Mbps · RTT {details['rtt_ms']:g} ms · loss {details['loss_rate'] * 100:g}% {details['loss_model']}",
        f"{details['flows']} flows · {details['offered_load_label']}",
        f"Duration {details['duration_s']:g} s · warmup {details['warmup_s']:g} s · drain {details['drain_s']:g} s",
        f"Stability {details['stability_gate_label']} · throughput tolerance {details['throughput_tolerance_pct']:g}% · queue tolerance {details['queue_tolerance_ms']:g} ms",
        details['study'], details['source_version'], details['endpoint_dispatch'],
        'Sources ' + (row['raw_ids'] if mean else row['source'] + ' · SHA256 ' + row['source_sha256'])))


def static_figure(output, payload, rows, means, boundary):
    figure, axes = plt.subplots(1, 3, figsize=(23, 11.7))
    projections = PROJECTIONS
    boundary_ids = {row['id'] for row in boundary}
    hidden_targets = set()
    capacity_curve_visible = False
    for axis, (x, y, xlabel, ylabel) in zip(axes, projections):
        for row in rows:
            axis.scatter(row[x], row[y], marker=(PAYLOAD_MARKERS[row['payload_bytes']] if payload is None else 'o') if row['eligible'] else 'x',
                s=38, color=row['color'], linewidths=1, alpha=.65, zorder=3)
        for row in means:
            if row['id'] in boundary_ids:
                axis.scatter(row[x], row[y], marker='o', s=280, facecolors='none', edgecolors='#172033', linewidths=1.7, zorder=4)
            if row['eligible']:
                axis.scatter(row[x], row[y], marker=PAYLOAD_MARKERS[row['payload_bytes']] if payload is None else 'o', s=125, edgecolors=row['color'],
                    facecolors='white', linewidths=2.1, zorder=5)
            else:
                axis.scatter(row[x], row[y], marker='x', s=125, color=row['color'], linewidths=2.1, zorder=5)
        if x == LATENCY:
            deadlines = sorted({row['rtt_ms'] * 1.5 for row in rows})
            bounds = [row[x] for row in rows] + deadlines
            low, high = min(bounds) * .75, max(bounds) * 1.5
            axis.set_xscale('log')
            axis.set_xlim(low, high)
            ticks = [value for value in report.LATENCY_TICKS if low <= value <= high]
            axis.set_xticks(ticks, [f'{value:g}' for value in ticks])
            axis.minorticks_off()
            for deadline in deadlines:
                axis.axvline(deadline, color='#b91c1c', linestyle=':', linewidth=1, alpha=.6)
        else:
            low, high = min(0, min(row[x] for row in rows)), max(row[x] for row in rows)
            axis.set_xlim(low - max(1, (high - low) * .05), high + max(1, (high - low) * .15))
        low, high = min(0, min(row[y] for row in rows)), max(row[y] for row in rows)
        if y == GOODPUT:
            targets = sorted({row['forward_mbps'] * .8 for row in rows})
            visible_targets = [target for target in targets if target <= high * 1.2]
            hidden_targets.update(set(targets) - set(visible_targets))
            if visible_targets:
                high = max(high, *visible_targets)
            for target in visible_targets:
                axis.axhline(target, color='#15803d', linestyle=':', linewidth=1)
        axis.set_ylim(low, high + max(1, (high - low) * .12))
        if x == OVERHEAD and y == GOODPUT:
            left, right = axis.get_xlim()
            left = max(left, -99)
            overhead_values = [left + (right - left) * index / 199 for index in range(200)]
            for capacity in sorted({row['forward_mbps'] for row in rows}):
                capacity_values = [capacity / (1 + value / 100) for value in overhead_values]
                capacity_curve_visible |= any(axis.get_ylim()[0] <= value <= axis.get_ylim()[1] for value in capacity_values)
                axis.plot(overhead_values, capacity_values,
                    color='#7c3aed', linestyle='-.', linewidth=1.2, zorder=1)
        axis.set(xlabel=xlabel, ylabel=ylabel)
        axis.grid(alpha=.2)
    configurations = configuration_rows(rows)
    families = strategy_families(rows)
    handles = [Line2D([], [], marker='o', color=family['color'], linestyle='none',
        markersize=8, label=family['name']) for family in families]
    if payload is None:
        handles.extend(Line2D([], [], marker=PAYLOAD_MARKERS[size], color='#475569', linestyle='none',
            markersize=8, label=f'{size} B') for size in PAYLOADS)
    common, overview_lines = static_overview(configurations)
    columns = (overview_lines[:(len(overview_lines) + 1) // 2], overview_lines[(len(overview_lines) + 1) // 2:])
    overview_columns = ['\n'.join('\n'.join(textwrap.wrap(line, 135)) for line in column) for column in columns]
    common_text = '\n'.join(textwrap.wrap(common, 280))
    common_height = (common_text.count('\n') + 1) * .16 + .12 if common else 0
    overview_height = common_height + max(text.count('\n') + 1 for text in overview_columns) * .16
    legend_height = .32 * ((len(handles) + 3) // 4) + .12
    height = 7.5 + overview_height + legend_height
    figure.set_size_inches(23, height)
    figure.legend(handles=handles, loc='lower center', bbox_to_anchor=(.5, (1.2 + overview_height) / height),
        ncol=4, frameon=False, fontsize=11, labelspacing=.9, handletextpad=.6, columnspacing=2.5)
    if common:
        figure.text(.055, (1.05 + overview_height) / height, common_text, ha='left', va='top', fontsize=9)
    for left, text in zip((.055, .525), overview_columns):
        figure.text(left, (1.05 + overview_height - common_height) / height, text, ha='left', va='top', fontsize=9)
    capacities = ' / '.join(f'{value:g}' for value in sorted({row['forward_mbps'] for row in rows}))
    reverse = ' / '.join(f'{value:g}' for value in sorted({row['reverse_mbps'] for row in rows}))
    subject = 'All payloads and offered loads' if payload is None else f'{payload} B payload'
    figure.suptitle(f'{subject} · {capacities}/{reverse} Mbps link', fontsize=17, y=1 - .25 / height)
    seed_note = 'complete three-seed means and supplementary runs' if any(not row.get('configuration_complete', True) for row in rows) else 'three runs per strategy'
    load_note = ' · load-controlled observations' if any(row.get('load_controlled_observation') for row in rows) else ''
    figure.text(.5, 1 - .6 / height, f'70 ms base RTT · 15% independent packet loss · {seed_note} · probes follow recorded admission gates{load_note}',
                ha='center', fontsize=11)
    target_note = ('The ' + ', '.join(f'{value:g} Mbps' for value in sorted(hidden_targets))
        + ' bandwidth target lies above the displayed range.' if hidden_targets
        else 'Dotted green lines mark 80% link capacity.')
    capacity_note = ('Purple curves show the 100 Mbps capacity limit.' if capacity_curve_visible
        else 'The 100 Mbps capacity bound lies above the displayed throughput range.')
    figure.text(.055, .43 / height,
        f"{len(rows)} runs · {sum(row['tcp_syn_ping_timeouts'] for row in rows):g} probe timeouts. Small markers show individual runs. Large markers summarize each strategy. "
        'Black rings mark each payload’s three-objective Pareto set. Crosses mark ineligible measurements.\n'
        'Goodput and extra IP bytes share the probe interval. Summaries pool traffic bytes/time and average per-run SYN P99. ' + capacity_note + '\n'
        'Dotted red lines mark 105 ms. ' + target_note + '\n'
        'Modeled TCP and FEC recovery; packet-processing CPU time excluded.'
        + (' Configured offered load limits the measured bandwidth.' if load_note else ''),
        ha='left', va='center', fontsize=8.5)
    figure.subplots_adjust(left=.055, right=.975, top=1 - .9 / height, bottom=(1.8 + overview_height + legend_height) / height, wspace=.29)
    filename = 'all-loads-pareto.png' if payload is None else f'payload-{payload}-pareto.png'
    figure.savefig(output / filename, dpi=160)
    plt.close(figure)
    return filename


def interactive(payload, rows, means, boundary, include_plotly):
    figure = make_subplots(rows=1, cols=3, horizontal_spacing=.09,
        subplot_titles=('Latency and goodput', 'Overhead and goodput', 'Latency and overhead'))
    boundary_ids = {row['id'] for row in boundary}
    families = strategy_families(rows)
    for column, (x, y, xlabel, ylabel) in enumerate(PROJECTIONS, 1):
        for family in families:
            cases = [row for row in rows if row['color_group'] == family['group']]
            averages = [row for row in means if row['color_group'] == family['group']]
            for role, points in (('raw', cases), ('mean', averages)):
                if not points:
                    continue
                symbols = [(PAYLOAD_SYMBOLS[row['payload_bytes']] if payload is None else 'circle')
                           if row['eligible'] else 'x' for row in points]
                figure.add_trace(go.Scatter(x=[row[x] for row in points], y=[row[y] for row in points],
                    mode='markers', name=family['name'], legendgroup=family['group'],
                    showlegend=column == 1 and role == 'raw', meta=dict(role=role, projection=column),
                    customdata=[row['id'] for row in points],
                    text=[hover(row, mean=role == 'mean', nondominated=row['id'] in boundary_ids) for row in points],
                    hovertemplate='%{text}<extra></extra>',
                    marker=dict(size=10 if role == 'mean' else 6, symbol=symbols,
                        color=[family['color'] if row['id'] in boundary_ids else 'white' for row in points]
                            if role == 'mean' else family['color'], opacity=1 if role == 'mean' else .6,
                        line=dict(color=['#172033' if row['id'] in boundary_ids else family['color'] for row in points],
                            width=[2.5 if row['id'] in boundary_ids else 1 for row in points]))), row=1, col=column)
        figure.update_xaxes(title_text=xlabel, type='log' if x == LATENCY else 'linear', row=1, col=column)
        figure.update_yaxes(title_text=ylabel, rangemode='tozero', row=1, col=column)
        if x == LATENCY:
            low, high = min(row[x] for row in rows) * .75, max(row[x] for row in rows) * 1.5
            ticks = [value for value in report.LATENCY_TICKS if low <= value <= high]
            figure.update_xaxes(tickmode='array', tickvals=ticks, ticktext=[f'{value:g}' for value in ticks],
                tickfont=dict(size=10), row=1, col=column)
            figure.add_vline(x=105, line_dash='dot', line_color='#b91c1c', opacity=.5, row=1, col=column)
        if y == GOODPUT:
            figure.add_hline(y=80, line_dash='dot', line_color='#15803d', opacity=.5, row=1, col=column)
    figure.update_layout(height=510, margin=dict(l=65, r=20, t=80, b=70), template='plotly_white',
        legend=dict(orientation='h', x=0, y=1.18, groupclick='togglegroup'), hoverlabel=dict(align='left'))
    plot_id = 'all-loads-2d' if payload is None else f'payload-{payload}-2d'
    shape_legend = ('<p class="payload-key">Payload shapes · ● 64 B · ■ 256 B · ▲ 512 B · ◆ 1024 B · ▼ 1228 B · ★ 1448 B</p>'
                    if payload is None else '')
    return shape_legend + figure.to_html(full_html=False, include_plotlyjs=include_plotly, div_id=plot_id,
        config=dict(responsive=True, displaylogo=False, scrollZoom=False), post_script="""
const plot = document.getElementById('{plot_id}');
const resize = () => {
    const width = plot.closest('section').clientWidth;
    const mobile = width < 800;
    plot.style.height = (mobile ? 1150 : 510) + 'px';
    const domains = mobile ? [[0, 1], [0, 1], [0, 1]] : [[0, .273], [.363, .637], [.727, 1]];
    const heights = mobile ? [[.74, 1], [.37, .63], [0, .26]] : [[0, 1], [0, 1], [0, 1]];
    const update = {width, height: mobile ? 1150 : 510,
        'margin.l': mobile ? 60 : 65, 'margin.r': mobile ? 15 : 20,
        'margin.t': mobile ? 135 : 80, 'legend.y': mobile ? 1.15 : 1.18};
    for (let index = 0; index < 3; index++) {
        const suffix = index ? String(index + 1) : '';
        update['xaxis' + suffix + '.domain'] = domains[index];
        update['yaxis' + suffix + '.domain'] = heights[index];
        update['annotations[' + index + '].x'] = (domains[index][0] + domains[index][1]) / 2;
        update['annotations[' + index + '].y'] = heights[index][1];
    }
    return Plotly.relayout(plot, update);
};
resize();
window.addEventListener('resize', resize);
""")


def condition_table(means):
    headers = ('Config / strategy', 'Mean per-run SYN P99 (ms)', 'Pooled probe-interval goodput (Mbps)', 'Pooled extra IP bytes (%)',
               'Link / RTT / loss', 'Flows / offered load', 'Duration / warmup / drain',
               'Stability gate', 'Source / dispatch', 'Eligibility / failures')
    parts = []
    for mean in means:
        item = mean['conditions']
        values = (mean['series_configuration'] + ' · ' + mean['color_label'] + ' · ' + mean['label'],
            f"{mean[LATENCY]:.9g}", f"{mean[GOODPUT]:.9g}", f"{mean[OVERHEAD]:.9g}",
            f"{item['forward_mbps']:g}/{item['reverse_mbps']:g} Mbps · {item['rtt_ms']:g} ms · {item['loss_rate'] * 100:g}% {item['loss_model']}",
            f"{item['flows']} · {item['offered_load_label']}" + (f" · {item['mux_channels']} shared mux channels · {item['mux_mapping']} · {item['total_window_bytes']:,} B total TCP window"
                if item['mux_channels'] is not None else ''),
            f"{item['duration_s']:g}/{item['warmup_s']:g}/{item['drain_s']:g} s",
            f"{item['stability_gate_label']} · {item['throughput_tolerance_pct']:g}% throughput / {item['queue_tolerance_ms']:g} ms queue",
            item['study'] + ' · ' + item['source_version'] + ' · ' + item['endpoint_dispatch'],
            f"Eligible {mean['eligible']} · {mean['timeout_count']:g} timeouts · " + ', '.join(mean['exclusion_reasons']))
        parts.append('<tr>' + ''.join('<td>' + escape(value) + '</td>' for value in values) + '</tr>')
    return '<div class="table-scroll"><table><thead><tr>' + ''.join('<th>'+escape(value)+'</th>' for value in headers) + '</tr></thead><tbody>' + ''.join(parts) + '</tbody></table></div>'


def render(root, selection_path, output, minimum_configurations=8):
    selection_bytes = selection_path.read_bytes()
    selection = json.loads(selection_bytes)
    sections = ('studies', 'supplementary_studies', 'coverage_only_studies')
    studies = list(dict.fromkeys(entry['study'].removeprefix('tcp-latency/')
        for section in sections for entry in selection.get(section, [])))
    all_rows, evidence, _, _ = report.load(root, studies)
    requested = set(selection_keys(selection, 'studies') + selection_keys(selection, 'supplementary_studies'))
    outside_keys = set(selection_keys(selection, 'coverage_only_studies'))
    outside = [row for row in all_rows if (row['study'], str(row['run_id'])) in outside_keys]
    auditable_outside = [row for row in outside if row['tcp_syn_probe_steady_state_reached'] is True
                        and isinstance(row.get(LATENCY), (int, float)) and isfinite(row[LATENCY])]
    audit_bytes(root, [row for row in all_rows if (row['study'], str(row['run_id'])) in requested] + auditable_outside)
    rows, gate = select_rows(all_rows, selection, minimum_configurations)
    load_controlled = selection.get('load_controlled_payloads', [])
    if any(payload not in PAYLOADS for payload in load_controlled):
        raise ValueError('Unknown load-controlled payload in selection')
    for row in rows:
        row['load_controlled_observation'] = row['payload_bytes'] in load_controlled
    for row in outside:
        row['publication_role'] = 'coverage only'
    means = summarize(rows)
    output.mkdir(parents=True, exist_ok=True)
    sections, figures, boundaries, point_data = [], [], [], {}
    for payload in PAYLOADS:
        selected = [row for row in rows if row['payload_bytes'] == payload]
        averages = [row for row in means if row['payload_bytes'] == payload]
        decorate(selected, averages)
        configurations = configuration_rows(selected)
        boundary = frontier(averages)
        boundaries.extend(boundary)
        filename = static_figure(output, payload, selected, averages, boundary)
        plot = interactive(payload, selected, averages, boundary, include_plotly=False)
        _, overview_lines = static_overview(configurations)
        sections.append(f'<section><h2>{payload} B payload</h2><p>{len(selected)} measured runs · '
            f'{len(averages)} complete three-seed means · {len(boundary)} eligible nondominated means · 0 missing coordinates</p>'
            + plot + '<h3>Strategy overview</h3><ul class="strategy-overview">'
            + ''.join('<li>' + escape(line) + '</li>' for line in overview_lines)
            + '</ul><details><summary>Exact configurations and source details</summary><ul>'
            + ''.join('<li><strong>' + escape(row['strategy_name']) + '</strong>. ' + escape(row['strategy_configuration'])
                + (' · individual runs only, incomplete measured seed cohort' if not row.get('configuration_complete', True) else '')
                + '</li>' for row in configurations)
            + '</ul><p>Exactly overlapping runs and means retain their original coordinates. '
            'The table lists every configuration mean separately, and CSV exports retain every seed.</p>'
            + ('<p>These are load-controlled observations at the listed offered rates. Configured offered load limits the measured bandwidth.</p>'
                if payload in load_controlled else '')
            + condition_table(averages) + '</details>'
            + f'<details><summary>Three pairwise projections</summary><a href="{filename}"><img src="{filename}" alt="{payload} B three-objective projections"></a></details></section>')
        figures.append(dict(filename=filename, payload_bytes=payload, measured=len(selected), coverage_only=0,
            mean_ids=[row['id'] for row in averages], frontier_ids=[row['id'] for row in boundary],
            raw_ids=[row['id'] for row in selected], source_cohorts=sorted({row['cohort'] for row in selected}),
            sha256=sha256((output / filename).read_bytes()).hexdigest()))
        point_data[str(payload)] = dict(runs=selected, means=averages, frontier_ids=[row['id'] for row in boundary])
    overview_filename = static_figure(output, None, rows, means, boundaries)
    overview_plot = interactive(None, rows, means, boundaries, include_plotly=True)
    _, overview_lines = static_overview(configuration_rows(rows))
    overview_section = ('<section id="all-loads"><h2>All payloads and offered loads</h2>'
        f'<p>{len(rows)} measured runs · {len(means)} three-seed summaries · 64–1448 B payloads. '
        'Color identifies strategy and shape identifies payload. Rings retain each payload’s Pareto set. '
        'Hover for offered load and configuration. Click a strategy to toggle its points.</p>'
        + overview_plot + '<ul class="strategy-overview">'
        + ''.join('<li>' + escape(line) + '</li>' for line in overview_lines)
        + f'</ul><p><a href="{overview_filename}">Download the combined PNG</a></p></section>')
    overview_receipt = dict(filename=overview_filename, measured=len(rows),
        raw_ids=[row['id'] for row in rows], mean_ids=[row['id'] for row in means],
        frontier_ids=[row['id'] for row in boundaries], frontier_scope='per-payload union',
        sha256=sha256((output / overview_filename).read_bytes()).hexdigest())
    report.archive.write_csv(output / 'current-series-coverage.csv', rows)
    report.archive.write_csv(output / 'current-series-means.csv', means)
    report.archive.write_csv(output / 'current-series-frontier.csv', boundaries)
    report.archive.write_csv(output / 'outside-plot-coverage.csv', outside)
    (output / 'selection-manifest.json').write_bytes(selection_bytes)
    source_dir = output / 'series-sources'
    source_dir.mkdir(exist_ok=True)
    sources = {}
    for path in (Path(__file__), Path(report.__file__), Path(report.archive.__file__),
                 Path(report.compact.__file__), Path(report.compact.aligned.__file__), Path(report.stats.__file__)):
        snapshot = source_dir / path.name
        snapshot.write_bytes(path.read_bytes())
        sources[snapshot.relative_to(output).as_posix()] = sha256(snapshot.read_bytes()).hexdigest()
    data_json = json.dumps(point_data, allow_nan=False).replace('<', '\\u003c')
    legacy_links = ' · '.join(report.link(output, path, label) for path, label in (
        (root / 'tcp-latency' / 'tcp-syn-ping-analysis' / 'report.html', 'Legacy probe archive'),
        (root / 'all-experiments' / 'report.html', 'Legacy full experiment archive')) if path.exists())
    legacy_section = ('<details><summary>Legacy records outside this fixed-link comparison</summary><p>'
        + legacy_links + '</p></details>' if legacy_links else '')
    audit = output / 'independent-audit.json'
    audit_link = report.link(output, audit, 'Independent same-window capacity audit') + ' · ' if audit.exists() else ''
    diagnosis = root / 'tcp-latency' / 'tcp-syn-fixed100-baselines' / 'quic-repeatability-diagnosis.json'
    reproducibility = {}
    reproducibility_section = ''
    if diagnosis.exists() and not gate['unified_mux_required']:
        note = ('QUIC run ordering depends on process object allocation. Ten of the 18 fresh QUIC runs differ from the earlier same-seed observations. '
                'A packetizer fixture demonstrates identity-dependent stream ordering, while historical traces cannot establish a unique cause for each difference. '
                'The charts retain all fresh measured runs.')
        reproducibility = dict(note=note, source=diagnosis.relative_to(root).as_posix(), sha256=sha256(diagnosis.read_bytes()).hexdigest())
        reproducibility_section = ('<details><summary>QUIC reproducibility limitation</summary><p>' + escape(note) + ' '
            + report.link(output, diagnosis, 'Repeatability diagnosis') + '</p></details>')
    metric_definitions = ('<table class="metrics"><thead><tr><th>Coordinate</th><th>Per run</th><th>Three-seed configuration summary</th></tr></thead><tbody>'
        '<tr><td>TCP SYN P99</td><td>P99 of completed SYN-to-SYN-ACK probes admitted after stability</td>'
        '<td>Arithmetic mean of the three per-run P99 values</td></tr>'
        '<tr><td>Goodput</td><td>8 P / T / 1e6 Mbps</td><td>8 sum(P) / sum(T) / 1e6 Mbps, time-weighted</td></tr>'
        '<tr><td>Extra forward IP bytes</td><td>100 (W / P − 1)%</td><td>100 (sum(W) / sum(P) − 1)%, payload-byte-weighted</td></tr>'
        '</tbody></table><p>P is delivered bulk application payload, W is serialized forward IP service, and T is the same post-stability interval duration. '
        'The three seed windows may differ in length.</p>')
    mux_subject = 'Coded strategies require a unified duplex mux.' if gate['shared_transport_baselines_allowed'] else 'Unified duplex mux is required for this comparison.'
    mux_scope = (f"<p>{mux_subject} Bulk TCP and fresh TCP SYN probes share at most {gate['max_l2_channels']} "
        'channels in both directions, with the same frame classifier, per-channel FIFO, round-robin admission and generic source-copy policy. '
        'Actual bulk flow counts, channel inventories and admission counters are retained for every run. '
        'Historical private-probe-channel observations are outside this goal qualification. '
        'Comparisons reflect complete configurations, including ACK frequency/delay, independent full-frame encoding and early release, '
        'repair ratio and size-based copies.</p><p>The mux accepts complete unfragmented Ethernet/IPv4/TCP frames. '
        'Ingress queues and connection-affinity records have no finite resource bound within these finite runs. '
        'Round-robin mapping explicitly rejects simultaneous opposite-direction connection initiation with conflicting affinity. '
        'Received frames are validated before the modeled TCP callback ledger dispatches them. '
        'Algebraic rank recovery materializes payloads from the sender ledger. Coding and packet-processing CPU cost is zero in this timing model.</p>'
        if gate['unified_mux_required'] else '')
    if gate['shared_transport_baselines_allowed']:
        mux_scope += ('<p>TCP sends native IP packets through the shared physical FIFO. QUIC and KCP carry modeled inner TCP '
            'over at most sixteen outer connections. Business data, TCP ACKs and fresh SYN probes share each connection’s '
            'ordered record path and finite send window. QUIC uses stream 0 and KCP uses its upstream ordered message queue. '
            'Every protocol datagram, retransmission and feedback packet consumes the recorded physical link service. '
            'QUIC outer connections are established before traffic measurement. KCP uses nodelay 1, interval 10 ms, '
            'resend 2 and nocwnd 1, with congestion control disabled and a finite 128-segment window per direction. '
            'QUIC uses byte windows derived from the per-flow inner TCP budget. Both use a 4 MiB total inner TCP window budget.</p>')
    load_scope = ''
    if load_controlled:
        loads = []
        for payload in load_controlled:
            rates = sorted({json.loads(row['original_profile'])['payload_rate_mbps'] for row in rows if row['payload_bytes'] == payload})
            loads.append(f'{payload} B at ' + '/'.join(f'{rate:g}' for rate in rates) + ' Mbps')
        load_scope = ('<p><strong>Load-controlled small-payload observations.</strong> ' + escape(', '.join(loads))
            + '. These configured offered loads bound the observed throughput.</p>')
    completeness = ('Each configuration mean includes all three recorded seeds with finite coordinates after its stability gate. '
        'Supplementary measured runs from incomplete seed cohorts appear individually and contribute no mean or frontier candidate.'
        if gate['supplementary_rows'] else 'Each configuration includes all three recorded seeds with finite coordinates after its stability gate.')
    outside_table = ''
    if outside:
        outside_table = ('<section><h2>Experiments outside the plotted coordinates</h2><p>'
            f'{len(outside)} recorded runs lack a complete measured coordinate tuple. '
            '<a href="outside-plot-coverage.csv">Coverage-only rows and source receipts</a></p>'
            + report.table(('Run', 'Strategy', 'Payload (B)', 'Status', 'Recorded reason', 'Raw source'), [(
                row['id'], row['label'], str(row['payload_bytes']), row['status'], row['exclusion_reason'], row['source']) for row in outside])
            + '</section>')
    html = ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Fixed 100/10 Mbps payload Pareto figures</title><style>body{font:15px/1.5 system-ui;margin:16px;color:#172033}'
        'main{max-width:1500px;margin:auto}section{border-top:1px solid #ccc;margin-top:30px}img{max-width:100%;height:auto}'
        'p,td{overflow-wrap:anywhere}table{border-collapse:collapse;min-width:1100px}td,th{padding:8px;border:1px solid #ddd;text-align:left;vertical-align:top}'
        '.metrics{min-width:0;width:100%}.table-scroll,.scroll{overflow-x:auto;max-width:100%;min-width:0}.plotly-graph-div{max-width:100%}.legend{list-style:none;padding:0}.legend li{overflow-wrap:anywhere}'
        '.strategy-overview{columns:2;column-gap:32px}.strategy-overview li{break-inside:avoid}summary{cursor:pointer}'
        '@media(max-width:800px){.strategy-overview{columns:1}}</style><main>'
        '<h1>Fixed 100/10 Mbps · bandwidth, extra transmission and TCP SYN latency</h1>'
        '<p>Forward IP service 100 Mbps · reverse IP service 10 Mbps · base RTT 70 ms · IID loss 15% · MTU 1500. '
        'This comparison contains only the fresh fixed-link reruns.</p>' + overview_section
        + '<details><summary>Measurement definitions and model details</summary>'
        + mux_scope + load_scope + '<p>' + escape(MERGE_BASIS) + '</p><p>'
        + escape(OVERHEAD_DEFINITION) + '</p>' + metric_definitions + '<p>' + completeness + ' '
        'Probe timeouts and incomplete confirmation exclude a configuration from the frontier and remain visible in its hover and table. '
        'P99 summarizes completed probes, with timeout counts reported alongside it. '
        'Small markers show runs and large labeled markers show three-seed configuration summaries. Dark outlines identify the eligible nondominated set. '
        'Color identifies family. The combined view uses payload shapes. Each two-dimensional panel supports zoom and hover.</p>'
        '<p>Coded transports use coefficient/rank recovery and sender-ledger payload materialization. TCP endpoints are modeled. Packet processing and codec CPU time are outside the timing model.</p>'
        '<p>The stability gate controls initial probe admission. Later one-second windows can fluctuate and remain in each raw run’s stability history. '
        'Repeated campaigns retain separate study identities and contribute separate three-seed summaries.</p>'
        '<p>' + audit_link + '<a href="selection-manifest.json">Explicit selected run IDs</a> · <a href="current-series-coverage.csv">Every selected run</a> · '
        '<a href="current-series-means.csv">Every three-seed mean</a> · <a href="current-series-frontier.csv">Descriptive nondominated means</a> · '
        '<a href="current-series-validation.json">Validation and source receipts</a></p></details>' + ''.join(sections) + outside_table + legacy_section
        + reproducibility_section + '</main><script>window.currentSeries=' + data_json + ';</script></html>')
    (output / 'report.html').write_text(html)
    (output / 'current-series-index.html').write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=report.html">'
        '<title>Current payload Pareto figures</title><a href="report.html">Open current three-objective payload figures</a>')
    receipt = dict(record_kind='fixed100_same_window_three_objective_payload_pareto_series',
        generated_utc=datetime.now(timezone.utc).isoformat(), studies=studies, source_evidence=evidence,
        merge_basis=MERGE_BASIS, overhead_definition=OVERHEAD_DEFINITION, publication_gate=gate, reproducibility=reproducibility,
        coordinate_keys=dict(latency=LATENCY, goodput=GOODPUT, extra_ip=OVERHEAD, source_concurrent_goodput=CONCURRENT_GOODPUT),
        mean_capacity_identity_max_error_mbps=max(mean['capacity_identity_error_mbps'] for mean in means),
        selection_manifest_sha256=sha256(selection_bytes).hexdigest(),
        raw_inputs={row['source']:row['source_sha256'] for row in rows + outside}, raw_runs=len(rows), figures=figures,
        overview_figure=overview_receipt, interactive_dimensions=2,
        outside_plot_rows=len(outside), load_controlled_payloads=load_controlled,
        renderer_sources=sources, minimum_configurations=minimum_configurations,
        generator_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        report_loader_sha256=sha256(Path(report.__file__).read_bytes()).hexdigest(),
        report_sha256=sha256((output / 'report.html').read_bytes()).hexdigest())
    (output / 'current-series-validation.json').write_text(json.dumps(receipt, indent=2, allow_nan=False)+'\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--minimum-configurations', type=int, default=8)
    args = parser.parse_args()
    receipt = render(args.root.resolve(), args.selection.resolve(), args.out.resolve(), args.minimum_configurations)
    print(json.dumps(dict(raw_runs=receipt['raw_runs'], publication_gate=receipt['publication_gate'],
        figures=[{key:item[key] for key in ('filename','measured','coverage_only')} for item in receipt['figures']]), indent=2))


if __name__ == '__main__':
    main()
