"""Validate the compact transport with congestion-controlled inner TCP."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
from random import Random

import numpy as np

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.compact_block import CompactBlockConfig, CompactBlockTransport
from l2tunnel_sim.compact_tcp import CompactTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure
from l2tunnel_sim.stats import mean_ci
from l2tunnel_sim.tcp import PlainTCP


def execute(task):
    scenario = Scenario(task['rtt_ms'], .15, task['loss_model'])
    payload_bytes = task.get('payload_bytes', 1448)
    traffic = Traffic(duration_s=task['duration_s'], drain_s=task['drain_s'],
                      payload_bytes=payload_bytes, frame_bytes=payload_bytes + 66,
                      window_bytes=task.get('window_bytes', 4 * 1048576),
                      frame_interval_ms=(payload_bytes * 8 / (task['payload_rate_mbps'] * 1000)
                                         if task.get('payload_rate_mbps') else 0))
    strategy = Strategy(task['name'], mode='tcp', tcp_cc=task['controller'],
                        tcp_rto_min_ms=task['rto_min_ms'])
    paths = (PathConfig(forward_mbps=task['forward_mbps'], reverse_mbps=10),)
    if task['compact'] is None:
        sim = PlainTCP(scenario, traffic, paths, strategy, task['seed'])
    else:
        transport_options = {}
        recovery = task.get('recovery', 'rlnc')
        config_type = CompactConfig
        if recovery == 'arq':
            transport_options['transport_type'] = CompactARQTransport
        elif recovery == 'block':
            config_type = CompactBlockConfig
            transport_options['transport_type'] = CompactBlockTransport
        sim = CompactTCP(scenario, traffic, paths, strategy, task['seed'],
                         config_type(**task['compact']), reliable_acks=task['reliable_acks'],
                         **transport_options)
    snapshots = {}

    def sample(when):
        snapshots[when] = {
            'payload': sim.tcp_received * sim.traffic.payload_bytes,
            'frames': sim.tcp_received,
            'packets': sum(sim.datagrams[False].values()),
            'sources': sim.datagrams[False]['source'],
            'wire': sum(sim.wire[False].values()),
        }

    sim.at(task['warmup_s'], sample, task['warmup_s'])
    sim.at(task['duration_s'], sample, task['duration_s'])
    sim.run()
    row = {**task, **measure(sim)}
    row['transport'] = 'compact_inner_tcp' if task['compact'] else 'direct_tcp'
    row['compact'] = json.dumps(task['compact'], sort_keys=True)
    interval = task['duration_s'] - task['warmup_s']
    start, end = snapshots[task['warmup_s']], snapshots[task['duration_s']]
    steady = {key: end[key] - start[key] for key in start}
    row['steady_tcp_mbps'] = 8 * steady['payload'] / (interval * 1e6)
    row['steady_forward_datagrams'] = steady['packets']
    row['steady_delivered_frames'] = steady['frames']
    row['steady_extra_packets_per_delivered_tcp_segment_pct'] = (
        100 * (steady['packets'] / steady['frames'] - 1) if steady['frames'] else None)
    row['full_tcp_capacity_pct'] = 100 * row['tcp_goodput_mbps'] / task['forward_mbps']
    row['steady_tcp_capacity_pct'] = 100 * row['steady_tcp_mbps'] / task['forward_mbps']
    row['extra_packets_per_delivered_tcp_segment_pct'] = (
        100 * (row['forward_datagrams'] / row['tcp_delivered_frames'] - 1)
        if row['tcp_delivered_frames'] else None)
    row['repair_and_control_packets_per_source_pct'] = (
        100 * (row['forward_datagrams'] / row['forward_source_datagrams'] - 1)
        if row['forward_source_datagrams'] else None)
    row['forward_payload_wire_pct'] = 100 * row['tcp_payload_efficiency'] if row['tcp_payload_efficiency'] else None
    row['extra_forward_wire_pct'] = (
        100 * (row['forward_wire_bytes'] / row['tcp_payload_bytes'] - 1)
        if row['tcp_payload_bytes'] else None)
    row['ack_rtt_p99_ms'] = float(np.percentile(sim.tcp_rtts, 99)) if sim.tcp_rtts else None
    row['steady_frame_p99_ms'] = None
    delays = [delay for sent_at, delay in zip(sim.sent_times, sim.forward.delays)
              if task['warmup_s'] <= sent_at < task['duration_s']]
    if delays:
        row['steady_frame_p99_ms'] = float(np.percentile(delays, 99))
    row['tcp_all_acknowledged'] = sim.tcp_acked == len(sim.sent_times)
    row['outer_all_confirmed'] = True
    if task['compact']:
        row['outer_all_confirmed'] = all(
            transport.base == len(transport.sources) and transport.buffer_bytes == 0
            for transport in (sim.compact_forward, sim.compact_reverse))
    complete = (row['tcp_delivery_fraction'] == 1 and row['tcp_all_acknowledged']
                and row['outer_all_confirmed'])
    packet_cost = row['extra_packets_per_delivered_tcp_segment_pct']
    affordable = packet_cost is not None and packet_cost <= 20
    measured_codec = task['compact'] is None or task['compact']['coding'] == 'gf256'
    row['full_target_met'] = (measured_codec and complete and affordable
                              and row['full_tcp_capacity_pct'] >= 80)
    steady_cost = row['steady_extra_packets_per_delivered_tcp_segment_pct']
    row['steady_target_met'] = (measured_codec and complete and steady_cost is not None and steady_cost <= 20
                                and row['steady_tcp_capacity_pct'] >= 80)
    if task['compact']:
        for label, transport in (('forward', sim.compact_forward), ('reverse', sim.compact_reverse)):
            row[label + '_scheduled_repairs'] = transport.scheduled_repairs
            row[label + '_tail_repairs'] = transport.tail_repairs
            row[label + '_compressed_record_bytes'] = transport.source_record_bytes
            row[label + '_profile_context_bytes'] = transport.profile_context_bytes
    return row


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    grouped = {}
    for row in rows:
        grouped.setdefault(row['name'], []).append(row)
    metrics = ('tcp_goodput_mbps', 'steady_tcp_mbps', 'full_tcp_capacity_pct',
               'steady_tcp_capacity_pct', 'extra_packets_per_delivered_tcp_segment_pct',
               'steady_extra_packets_per_delivered_tcp_segment_pct',
               'repair_and_control_packets_per_source_pct', 'forward_payload_wire_pct',
               'frame_p99_ms', 'steady_frame_p99_ms', 'tcp_timeouts', 'tcp_retransmissions')
    result = []
    for name, records in grouped.items():
        first = records[0]
        summary = {key: first[key] for key in ('name', 'controller', 'rtt_ms', 'loss_model',
                                              'forward_mbps', 'duration_s', 'warmup_s', 'rto_min_ms',
                                              'reliable_acks', 'compact')}
        summary['recovery'] = first.get('recovery', 'rlnc')
        summary['payload_rate_mbps'] = first.get('payload_rate_mbps')
        summary['replications'] = len(records)
        summary['confirmed_replications'] = sum(r['tcp_all_acknowledged'] and r['outer_all_confirmed']
                                               for r in records)
        summary['min_completion'] = min(r['tcp_delivery_fraction'] for r in records)
        summary['full_target_passes'] = sum(r['full_target_met'] for r in records)
        summary['steady_target_passes'] = sum(r['steady_target_met'] for r in records)
        for metric in metrics:
            estimate = mean_ci([r[metric] for r in records if r[metric] is not None])
            for key in ('mean', 'ci_low', 'ci_high'):
                summary[f'{metric}_{key}'] = estimate[key]
        result.append(summary)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--profiles', type=Path, required=True,
                        help='JSON list of named compact configurations and TCP settings')
    parser.add_argument('--replications', type=int, default=5)
    parser.add_argument('--duration', type=float, default=45)
    parser.add_argument('--warmup', type=float, default=5)
    parser.add_argument('--drain', type=float, default=20)
    parser.add_argument('--rtt', type=float, default=70)
    parser.add_argument('--bandwidth', type=float, default=100)
    parser.add_argument('--payload', type=int, default=1448)
    parser.add_argument('--loss-model', choices=('iid', 'burst'), default='iid')
    parser.add_argument('--workers', type=int, default=2)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error('warmup must be nonnegative and shorter than duration')
    profiles = json.loads(args.profiles.read_text())
    source_paths = [Path(__file__), *sorted((Path(__file__).parents[1] / 'src' / 'l2tunnel_sim').glob('*.py'))]
    provenance = {'python': platform.python_version(), 'sources': {
        str(path.relative_to(Path(__file__).parents[1])): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source_paths}}
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for profile in profiles:
        compact = profile.get('compact')
        if compact is not None:
            config_type = CompactBlockConfig if profile.get('recovery') == 'block' else CompactConfig
            compact = asdict(config_type(**compact))
        for replication, seed in enumerate(seeds, 1):
            tasks.append(dict(run_id=len(tasks) + 1, name=profile['name'],
                              recovery=profile.get('recovery', 'rlnc'),
                              payload_rate_mbps=profile.get('payload_rate_mbps'),
                              payload_bytes=args.payload,
                              window_bytes=profile.get('window_bytes', 4 * 1048576),
                              compact=compact, reliable_acks=profile.get('reliable_acks', True),
                              controller=profile.get('controller', 'cubic'),
                              rto_min_ms=profile.get('rto_min_ms', 200),
                              seed=seed, replication=replication, rtt_ms=args.rtt,
                              loss_model=args.loss_model, forward_mbps=args.bandwidth,
                              duration_s=args.duration, warmup_s=args.warmup, drain_s=args.drain))
    args.out.mkdir(parents=True, exist_ok=True)
    runs = args.out / 'runs'
    runs.mkdir(exist_ok=True)
    manifest_path = args.out / 'experiment.json'
    manifest = {'tasks': tasks, 'provenance': provenance}
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError('output directory contains a different experiment')
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    remaining = [task for task in tasks if not (runs / f"{task['run_id']:04d}.json").exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(execute, task): task for task in remaining}
        for future in as_completed(futures):
            task = futures[future]
            path = runs / f"{task['run_id']:04d}.json"
            temporary = path.with_suffix('.tmp')
            temporary.write_text(json.dumps(future.result(), indent=2) + '\n')
            temporary.replace(path)
            print(f"Completed {task['name']} replication {task['replication']}", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:04d}.json").read_text()) for task in tasks]
    write_csv(args.out / 'replications.csv', rows)
    write_csv(args.out / 'summary.csv', summarize(rows))
    print(f'Wrote {len(rows)} validated inner-TCP replications to {args.out}', flush=True)


if __name__ == '__main__':
    main()
