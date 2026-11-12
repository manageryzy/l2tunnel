"""Run and resume complete-Ethernet-frame bandwidth and overhead experiments."""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import asdict, replace
from importlib.metadata import version
import json
from pathlib import Path
from random import Random
from time import perf_counter

from l2tunnel_sim import __version__
from l2tunnel_sim.config import Experiment, PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure, simulation_type
from l2tunnel_sim.stats import mean_ci


def candidates():
    profiles = []
    for strategy in Experiment().strategies[:4]:
        profiles.append((strategy, 'Legacy', False))
    for cc in ('cubic', 'reno'):
        profiles.append((Strategy('QUIC L2 ' + cc.upper(), mode='quic', tcp_cc=cc), 'QUIC', False))
    base = Strategy('Cumulative SW33', mode='sliding', repair_every=3,
                    feedback_repair=True, cumulative_feedback=True)
    profiles.append((base, 'Feedback', False))
    profiles.append((Strategy('Cumulative ARQ', cumulative_feedback=True), 'Feedback', False))
    for every in (4, 5):
        profiles.append((replace(base, name=f'Lower FEC {100/every:g}%', repair_every=every,
                                 fec_wait_ms=10, reverse_batch=8), 'FEC rate', False))
    profiles.append((replace(base, name='Packed SW33', fragments=4, source_batch=3,
                             repair_batch=3, fec_wait_ms=10, reverse_batch=8), 'Packing', False))
    for window, every, repairs in ((64, 3, 1), (128, 3, 1), (255, 3, 1),
                                   (128, 10, 3), (255, 10, 3), (128, 2, 1), (128, 4, 1)):
        ratio = repairs / every
        name = f'Paced {ratio:.0%} W{window}'
        strategy = replace(base, name=name, long_window=window, repair_every=every,
                           repairs_per_group=repairs, fec_wait_ms=10, reverse_batch=8)
        profiles.append((strategy, 'Pacing and FEC', True))
    return profiles


def tasks(duration, drain, replications, long_check, refinement=False, interleaved=False,
          feedback_tuning=False):
    profiles = candidates()
    if feedback_tuning:
        profiles = []
        for every, repairs, window in ((3, 1, 255), (20, 9, 128)):
            strategy = Strategy(f'Batched feedback {100*repairs/every:g}% W{window}',
                                mode='sliding', repair_every=every, repairs_per_group=repairs,
                                long_window=window, feedback_repair=True, cumulative_feedback=True,
                                interleave_repairs=True, fec_wait_ms=10, reverse_batch=16,
                                pack_wait_ms=.8, feedback_wait_ms=1, feedback_batch=64)
            profiles.append((strategy, 'Feedback batching', True))
        conditions = [(100, 70, 'iid')] if long_check else [
            (rate, 70, loss) for rate in (10, 100, 300, 1000) for loss in ('iid', 'burst')]
    elif refinement:
        profiles = []
        for every, repairs in ((8, 3), (5, 2), (20, 9)):
            prefix = 'Interleaved' if interleaved else 'Paced'
            strategy = Strategy(f'{prefix} {100*repairs/every:g}% W128', mode='sliding',
                                repair_every=every, repairs_per_group=repairs,
                                long_window=128, feedback_repair=True,
                                cumulative_feedback=True, fec_wait_ms=10, reverse_batch=8,
                                interleave_repairs=interleaved)
            profiles.append((strategy, 'Pacing and FEC', True))
        conditions = [(100, 70, 'iid')]
    elif long_check:
        names = {'Sliding 33%', 'Paced 30% W255', 'Paced 33% W255', 'Paced 50% W128',
                 'QUIC L2 CUBIC', 'QUIC L2 RENO'}
        profiles = [p for p in profiles if p[0].name in names]
        conditions = [(100, 70, 'iid')]
    else:
        conditions = [(rate, 70, loss) for rate in (10, 100, 300, 1000) for loss in ('iid', 'burst')]
        conditions += [(100, rtt, 'iid') for rtt in (20, 150)]
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(replications)]
    result = []
    for scenario_id, (rate, rtt, loss_model) in enumerate(conditions, 1):
        for strategy, family, paced in profiles:
            traffic = Traffic(duration_s=duration, drain_s=drain)
            if paced:
                repair_ratio = strategy.repairs_per_group / strategy.repair_every
                interval = 1690 * (1 + repair_ratio) * 8 / (rate * 1000 * .92)
                traffic = replace(traffic, window_bytes=4 * 1048576, frame_interval_ms=interval)
            for replication, seed in enumerate(seeds, 1):
                result.append({
                    'run_id': len(result) + 1, 'scenario_id': scenario_id,
                    'forward_mbps': rate, 'reverse_mbps': 10,
                    'replication': replication, 'seed': seed, 'family': family,
                    'scenario': asdict(Scenario(rtt, .2, loss_model)),
                    'strategy': asdict(strategy), 'traffic': asdict(traffic),
                })
    return result


def execute(task):
    start = perf_counter()
    strategy = Strategy(**task['strategy'])
    sim = simulation_type(strategy.mode)(
        Scenario(**task['scenario']), Traffic(**task['traffic']),
        (PathConfig(forward_mbps=task['forward_mbps'], reverse_mbps=task['reverse_mbps']),),
        strategy, task['seed'],
    ).run()
    row = {key: value for key, value in task.items() if key not in ('strategy', 'traffic', 'scenario')}
    row.update(task['scenario'])
    row.update(strategy=strategy.name, **measure(sim))
    row['duration_s'] = sim.traffic.duration_s
    row['drain_s'] = sim.traffic.drain_s
    row['frame_interval_ms'] = sim.traffic.frame_interval_ms
    row['window_bytes'] = sim.traffic.window_bytes
    row['l2_extra_wire_pct'] = 100 * (1 / row['l2_efficiency'] - 1) if row['l2_efficiency'] else None
    row['l2_duplex_extra_wire_pct'] = (100 * ((row['forward_wire_bytes'] + row['reverse_wire_bytes'])
                                            / row['forward_l2_bytes'] - 1)
                                        if row['forward_l2_bytes'] else None)
    row['non_l2_share_pct'] = 100 * (1 - row['l2_efficiency']) if row['l2_efficiency'] else None
    row['packet_multiplier'] = row['forward_datagrams'] / row['released_frames'] if row['released_frames'] else None
    row['status'] = 'complete_at_cutoff' if row['tcp_delivery_fraction'] == 1 else 'incomplete_at_cutoff'
    row['compute_seconds'] = perf_counter() - start
    for direction in ('forward', 'reverse'):
        assert row[direction + '_wire_bytes'] == sum(row[f'{direction}_{kind}_bytes']
                 for kind in ('source', 'repair', 'retry', 'feedback'))
    assert row['tcp_acked_frames'] <= row['tcp_delivered_frames'] <= row['offered_frames']
    assert row['forward_l2_bytes'] == row['released_frames'] * 1514
    return row


def write_csv(path, rows):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row['scenario_id'], row['strategy']), []).append(row)
    summaries = []
    metrics = ('l2_goodput_mbps', 'tcp_goodput_mbps', 'l2_extra_wire_pct',
               'l2_duplex_extra_wire_pct', 'non_l2_share_pct', 'frame_p99_ms',
               'frame_delivery_fraction', 'packet_multiplier')
    for records in groups.values():
        row = {key: records[0][key] for key in ('scenario_id', 'forward_mbps', 'reverse_mbps',
               'rtt_ms', 'loss_rate', 'loss_model', 'strategy', 'family', 'duration_s', 'drain_s')}
        for metric in metrics:
            observed = [r[metric] for r in records if r[metric] is not None]
            stats = mean_ci(observed)
            for key in ('mean', 'ci_low', 'ci_high', 'n'):
                row[metric + '_' + key] = stats[key]
        row['min_delivery_fraction'] = min(r['frame_delivery_fraction'] for r in records)
        row['max_p99_ms'] = max(r['frame_p99_ms'] for r in records if r['frame_p99_ms'] is not None)
        row['complete_replications'] = sum(r['status'] == 'complete_at_cutoff' for r in records)
        summaries.append(row)
    return summaries


def frontier(rows, *, maximum_extra_delay=None):
    eligible = [r for r in rows if r['min_delivery_fraction'] >= .999
                and (maximum_extra_delay is None or r['max_p99_ms'] <= r['rtt_ms'] / 2 + maximum_extra_delay)]
    selected = []
    best_goodput = -1
    for row in sorted(eligible, key=lambda r: (r['l2_extra_wire_pct_mean'], -r['l2_goodput_mbps_mean'])):
        if row['l2_goodput_mbps_mean'] > best_goodput:
            selected.append(row)
            best_goodput = row['l2_goodput_mbps_mean']
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--replications', type=int, default=5)
    parser.add_argument('--duration', type=float, default=2)
    parser.add_argument('--drain', type=float, default=3)
    parser.add_argument('--long-check', action='store_true')
    parser.add_argument('--refinement', action='store_true')
    parser.add_argument('--interleaved', action='store_true')
    parser.add_argument('--feedback-tuning', action='store_true')
    args = parser.parse_args()
    plan = tasks(args.duration, args.drain, args.replications, args.long_check, args.refinement,
                 args.interleaved, args.feedback_tuning)
    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / 'experiment.json'
    manifest = {'simulator_version': __version__, 'runtime': {name: version(name) for name in
                ('aioquic', 'cryptography', 'numpy', 'scipy', 'plotly')}, 'tasks': plan}
    if manifest_path.exists():
        saved = json.loads(manifest_path.read_text())
        for task in saved['tasks']:
            task['strategy'] = asdict(Strategy(**task['strategy']))
        if saved != manifest:
            raise ValueError('existing study has a different configuration or runtime')
    else:
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    run_directory = args.out / 'runs'
    run_directory.mkdir(exist_ok=True)
    pending = [task for task in plan if not (run_directory / f"{task['run_id']:05d}.json").exists()]
    completed = len(plan) - len(pending)
    print(f'{completed}/{len(plan)} runs already complete', flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(execute, task): task for task in pending}
        for future in as_completed(futures):
            row = future.result()
            destination = run_directory / f"{row['run_id']:05d}.json"
            temporary = destination.with_suffix('.tmp')
            temporary.write_text(json.dumps(row) + '\n')
            temporary.replace(destination)
            completed += 1
            if completed % 20 == 0 or completed == len(plan):
                print(f'{completed}/{len(plan)} complete', flush=True)
    rows = [json.loads((run_directory / f"{task['run_id']:05d}.json").read_text()) for task in plan]
    summaries = summarize(rows)
    write_csv(args.out / 'replications.csv', rows)
    write_csv(args.out / 'summary.csv', summaries)
    pareto = []
    for scenario_id in dict.fromkeys(r['scenario_id'] for r in summaries):
        group = [r for r in summaries if r['scenario_id'] == scenario_id]
        for budget in (None, 5, 10, 20):
            for row in frontier(group, maximum_extra_delay=budget):
                pareto.append({'extra_delay_budget_ms': budget if budget is not None else 'unconstrained', **row})
    if pareto:
        write_csv(args.out / 'pareto.csv', pareto)
    print(f'Results written to {args.out}', flush=True)


if __name__ == '__main__':
    main()
