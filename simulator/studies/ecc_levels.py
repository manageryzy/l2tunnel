"""Compare finite MDS levels using exact loss distributions and the tunnel model."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import asdict
import json
from pathlib import Path
from random import Random
from time import perf_counter

import numpy as np
from scipy.stats import binom

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure
from l2tunnel_sim.model import Simulation, Tunnel
from l2tunnel_sim.stats import mean_ci


LEVELS = ((5, 1), (10, 2), (20, 4), (50, 10), (100, 20), (200, 40),
          (100, 10), (100, 15), (85, 15), (100, 25), (100, 30))


def loss_distribution(n, probability, model, mean_burst=4):
    """Joint distribution of the loss count and the next packet's loss state."""
    if model == 'iid':
        counts = binom.pmf(np.arange(n + 1), n, probability)
        return np.column_stack((counts * (1 - probability), counts * probability))
    if model != 'burst':
        raise ValueError(f'unsupported loss model {model}')
    leave = 1 / mean_burst
    enter = probability * leave / (1 - probability)
    joint = np.zeros((n + 1, 2))
    joint[0] = (1 - probability, probability)
    for packet in range(n):
        updated = np.zeros_like(joint)
        # The current state determines this packet. Transition follows its loss.
        updated[:packet + 1, 0] += joint[:packet + 1, 0] * (1 - enter)
        updated[:packet + 1, 1] += joint[:packet + 1, 0] * enter
        updated[1:packet + 2, 0] += joint[:packet + 1, 1] * leave
        updated[1:packet + 2, 1] += joint[:packet + 1, 1] * (1 - leave)
        joint = updated
    return joint


def ideal_block(k, repairs, probability, model='iid', mean_burst=4):
    """Perfect-feedback, infinite-field innovative-repair lower bound."""
    n = k + repairs
    joint = loss_distribution(n, probability, model, mean_burst)
    deficit = np.maximum(0, np.arange(n + 1) - repairs)
    success = joint[:repairs + 1].sum()
    if model == 'iid':
        extra = float(np.dot(joint.sum(axis=1), deficit) / (1 - probability))
    else:
        enter_over_leave = probability / (1 - probability)
        good_steps = deficit + np.maximum(0, deficit - 1) * enter_over_leave
        bad_steps = good_steps + (deficit > 0) * mean_burst
        extra = float(np.dot(joint[:, 0], good_steps) + np.dot(joint[:, 1], bad_steps))
    completed_packets = n + extra
    return {
        'source_symbols': k, 'proactive_repairs': repairs,
        'initial_packet_redundancy_pct': 100 * repairs / k,
        'loss_rate': probability, 'loss_model': model, 'mean_burst': mean_burst,
        'initial_block_recovery_probability': float(success),
        'initial_block_failure_probability': float(1 - success),
        'mean_rank_deficit_after_initial_block': float(np.dot(joint.sum(axis=1), deficit)),
        'ideal_additional_repair_packets': extra,
        'ideal_total_packet_redundancy_pct': 100 * (completed_packets / k - 1),
        'ideal_existing_layout_tcp_efficiency_pct': 100 * 1448 / (1690 * completed_packets / k),
        'gf256_initial_code_supported': n <= 256,
        'bound_requires_unlimited_innovative_repairs': True,
    }


class AuditedTunnel(Tunnel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code_blocks = Counter()

    def flush_code(self, generation):
        if generation == self.fec_generation and self.mode == 'block':
            self.code_blocks[len(self.block)] += 1
        super().flush_code(generation)


class MDSStudySimulation(Simulation):
    """Existing GF256 model, with an explicit end-of-input partial-block flush."""

    def make_transports(self, rng):
        return (
            AuditedTunnel(self, False, Random(rng.getrandbits(64)), self.on_data),
            Tunnel(self, True, Random(rng.getrandbits(64)), self.on_ack),
        )

    def flush_final_block(self):
        if self.forward.fec_count:
            self.forward.flush_code(self.forward.fec_generation)

    def run(self):
        self.at(self.traffic.duration_s, self.flush_final_block)
        return super().run()


def tasks(duration, drain, replications, long_check=False):
    conditions = [(100, 'iid')] if long_check else [
        (rate, model) for rate in (10, 100, 1000) for model in ('iid', 'burst')]
    levels = ((5, 1), (50, 10), (100, 10), (100, 20), (200, 40), (100, 30)) if long_check else LEVELS
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(replications)]
    plan = []
    for scenario_id, (rate, model) in enumerate(conditions, 1):
        for k, repairs in levels:
            # Leave 8% of link capacity for feedback and unscheduled recovery.
            interval = 1690 * (1 + repairs / k) * 8 / (rate * 1000 * .92)
            strategy = Strategy(
                f'MDS {k}+{repairs}', mode='block', block_size=k, block_repairs=repairs,
                fec_wait_ms=1000, cumulative_feedback=True, feedback_wait_ms=1,
                feedback_batch=64, reverse_batch=16, pack_wait_ms=.8,
            )
            traffic = Traffic(duration_s=duration, drain_s=drain,
                              frame_interval_ms=interval, window_bytes=4 * 1048576)
            for replication, seed in enumerate(seeds, 1):
                plan.append({
                    'run_id': len(plan) + 1, 'scenario_id': scenario_id,
                    'forward_mbps': rate, 'reverse_mbps': 10,
                    'source_symbols': k, 'proactive_repairs': repairs,
                    'replication': replication, 'seed': seed,
                    'scenario': asdict(Scenario(70, .15, model)),
                    'strategy_config': asdict(strategy), 'traffic_config': asdict(traffic),
                })
    return plan


def execute(task):
    started = perf_counter()
    sim = MDSStudySimulation(
        Scenario(**task['scenario']), Traffic(**task['traffic_config']),
        (PathConfig(task['forward_mbps'], task['reverse_mbps']),),
        Strategy(**task['strategy_config']), task['seed'],
    ).run()
    row = {key: value for key, value in task.items()
           if key not in ('scenario', 'strategy_config', 'traffic_config')}
    row.update(task['scenario'])
    row.update(strategy=sim.strategy.name, **measure(sim))
    row['duration_s'] = sim.traffic.duration_s
    row['drain_s'] = sim.traffic.drain_s
    row['initial_packet_redundancy_pct'] = 100 * sim.strategy.block_repairs / sim.strategy.block_size
    baseline = 2 * row['offered_frames']
    data_packets = sum(row[f'forward_{kind}_datagrams'] for kind in ('source', 'repair', 'retry'))
    row['source_packet_baseline'] = baseline
    row['forward_data_packet_redundancy_pct'] = 100 * (data_packets / baseline - 1)
    row['forward_total_packet_redundancy_pct'] = 100 * (row['forward_datagrams'] / baseline - 1)
    row['tcp_capacity_pct'] = 100 * row['tcp_goodput_mbps'] / row['forward_mbps']
    row['complete_at_cutoff'] = row['tcp_delivery_fraction'] == 1
    row['source_packet_baseline_complete'] = row['forward_source_datagrams'] == baseline
    row['code_blocks'] = sum(sim.forward.code_blocks.values())
    row['full_code_blocks'] = sim.forward.code_blocks[sim.strategy.block_size]
    row['partial_code_blocks'] = row['code_blocks'] - row['full_code_blocks']
    row['compute_seconds'] = perf_counter() - started
    return row


def summarize(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row['scenario_id'], row['strategy']), []).append(row)
    summaries = []
    metrics = ('tcp_goodput_mbps', 'tcp_capacity_pct', 'tcp_payload_efficiency',
               'frame_p99_ms', 'forward_data_packet_redundancy_pct',
               'forward_total_packet_redundancy_pct', 'initial_packet_redundancy_pct',
               'forward_repair_datagrams', 'forward_retry_datagrams', 'forward_feedback_datagrams',
               'frame_delivery_fraction')
    for records in groups.values():
        row = {key: records[0][key] for key in (
            'scenario_id', 'forward_mbps', 'reverse_mbps', 'loss_model', 'loss_rate',
            'rtt_ms', 'source_symbols', 'proactive_repairs', 'strategy', 'duration_s', 'drain_s')}
        for metric in metrics:
            stats = mean_ci([r[metric] for r in records if r[metric] is not None])
            for key in ('mean', 'ci_low', 'ci_high', 'n'):
                row[f'{metric}_{key}'] = stats[key]
        row['min_delivery_fraction'] = min(r['frame_delivery_fraction'] for r in records)
        row['complete_replications'] = sum(r['complete_at_cutoff'] for r in records)
        row['baseline_complete_replications'] = sum(r['source_packet_baseline_complete'] for r in records)
        row['max_p99_ms'] = max(r['frame_p99_ms'] for r in records if r['frame_p99_ms'] is not None)
        summaries.append(row)
    return summaries


def pareto(rows):
    """Three objectives, minimizing packet overhead and delay, maximizing goodput."""
    eligible = [r for r in rows if r['min_delivery_fraction'] >= .999
                and r['complete_replications'] == r['tcp_goodput_mbps_n']
                and r['baseline_complete_replications'] == r['tcp_goodput_mbps_n']]
    objectives = ('forward_total_packet_redundancy_pct_mean', 'frame_p99_ms_mean')
    result = []
    for row in eligible:
        dominated = any(
            other['scenario_id'] == row['scenario_id']
            and all(other[key] <= row[key] for key in objectives)
            and other['tcp_goodput_mbps_mean'] >= row['tcp_goodput_mbps_mean']
            and (any(other[key] < row[key] for key in objectives)
                 or other['tcp_goodput_mbps_mean'] > row['tcp_goodput_mbps_mean'])
            for other in eligible
        )
        if not dominated:
            result.append(row)
    return result


def write_csv(path, rows):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_report(out, theory, summaries, frontiers):
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    figure = make_subplots(rows=1, cols=2, subplot_titles=(
        'Measured TCP throughput vs total extra packets',
        'Measured P99 delivery delay vs total extra packets'))
    colors = ('#0072B2', '#D55E00', '#009E73', '#CC79A7', '#E69F00', '#56B4E9')
    for color, scenario_id in zip(colors, dict.fromkeys(row['scenario_id'] for row in summaries)):
        group = [r for r in summaries if r['scenario_id'] == scenario_id]
        label = f"{group[0]['forward_mbps']:g} Mbps / {group[0]['loss_model']}"
        overhead = [r['forward_total_packet_redundancy_pct_mean'] for r in group]
        names = [r['strategy'] for r in group]
        for column, metric in ((1, 'tcp_capacity_pct_mean'), (2, 'frame_p99_ms_mean')):
            figure.add_trace(go.Scatter(x=overhead, y=[r[metric] for r in group],
                mode='markers', name=label, text=names, legendgroup=label,
                marker={'color': color, 'size': 9},
                showlegend=column == 1, hovertemplate='%{text}<br>%{x:.2f}% extra packets<br>%{y:.3f}<extra>%{fullData.name}</extra>'), row=1, col=column)
            complete = [r for r in group if r['complete_replications'] == r['tcp_goodput_mbps_n']
                        and r['baseline_complete_replications'] == r['tcp_goodput_mbps_n']]
            projection = []
            best = -float('inf') if column == 1 else float('inf')
            for row in sorted(complete, key=lambda r: r['forward_total_packet_redundancy_pct_mean']):
                improves = row[metric] > best if column == 1 else row[metric] < best
                if improves:
                    projection.append(row)
                    best = row[metric]
            figure.add_trace(go.Scatter(
                x=[r['forward_total_packet_redundancy_pct_mean'] for r in projection],
                y=[r[metric] for r in projection], mode='lines', line={'color': color},
                name=label + ' Pareto', legendgroup=label, showlegend=False,
                hoverinfo='skip'), row=1, col=column)
    figure.add_vline(x=20, line_dash='dot', line_color='gray')
    figure.add_hline(y=80, line_dash='dot', line_color='gray', row=1, col=1)
    figure.update_xaxes(title_text='Extra forward IP packets above two source packets per frame (%)')
    figure.update_yaxes(title_text='TCP application throughput / forward link (%)', row=1, col=1)
    figure.update_yaxes(title_text='P99 complete-frame delivery delay (ms)', type='log', row=1, col=2)
    figure.update_layout(title='Finite MDS coding at 15% packet erasure', height=650)
    theory15 = [r for r in theory if r['loss_rate'] == .15 and r['loss_model'] == 'iid']
    theory_rows = ''.join(
        f"<tr><td>{r['source_symbols']}+{r['proactive_repairs']}</td>"
        f"<td>{r['initial_packet_redundancy_pct']:.3f}%</td>"
        f"<td>{100*r['initial_block_recovery_probability']:.3f}%</td>"
        f"<td>{r['ideal_total_packet_redundancy_pct']:.3f}%</td></tr>"
        for r in theory15)
    description = '''<h1>ECC level study</h1>
<p>The target is at most 20% extra forward packets at 15% erasure and TCP application throughput of at least 80% of forward link capacity. The measured study runs the existing coefficient-level GF(256) Cauchy MDS decoder, link serialization, reverse ACK tunnel, cumulative coding feedback, and reliable source retransmissions. Each complete Ethernet frame is 1514 bytes and has 1448 bytes of TCP application payload. It produces two 845-byte outer IP source packets. Forward capacity is 10, 100, or 1000 Mbps, reverse capacity is 10 Mbps, and RTT is 70 ms. Burst loss has a mean run of four lost packets.</p>
<p>Every result counts actual transmitted source, repair, retry, and feedback packets. The reference packet count is two source packets per offered Ethernet frame. Data-only overhead excludes feedback. Delivery and source-transmission completeness are separate columns in the CSV. The ideal throughput ceiling for this packet layout at 15% IID loss is 72.828%, before feedback or finite-code penalties. The measured traffic uses a fixed 4 MiB inner TCP flight window and rate pacing, so its TCP result models application data and ACK behavior without native TCP congestion control.</p>
<p>Source packets transmit immediately. Repairs follow the completed coding block. The block-fill timeout is 1000 ms and an explicit end-of-input event flushes the final partial block. This preserves large block sizes during active input. Partial blocks round repair counts upward and are counted in the raw output. Known-capacity pacing reserves 8% of the nominal link for unscheduled recovery. CPU coding cost is excluded from simulated latency. GF(256) initial codewords are limited to 256 total symbols.</p>
<p>The theoretical table uses exact binomial loss counts for IID loss. Its completed-recovery column assumes perfect feedback and an unlimited supply of independent innovative packets after the initial codeword. It is a lower bound and can require code lengths beyond the GF(256) implementation limit. A failed block requires an additional feedback round in a realizable adaptive protocol. The burst table uses an exact two-state Markov count distribution, stationary block starts, and conditional expected extra repair transmissions, with feedback and waiting time excluded.</p>
<p>The measured Pareto CSV contains the nondominated complete runs across total packet overhead, mean P99 delay, and TCP goodput within each link/loss condition. Confidence intervals use replication means. The plot includes all profiles, the two-objective projected Pareto curves, and the 20% / 80% objective lines. Native TCP throughput and latency require a full TCP endpoint model or real-stack validation after a candidate reaches the packet-level objective.</p>
<h2>Exact IID finite-block results</h2><table><tr><th>Sources + repairs</th><th>Initial overhead</th><th>Initial block recovery</th><th>Ideal completed overhead</th></tr>'''
    (out / 'report.html').write_text('<!doctype html><html><head><meta charset="utf-8">'
        '<style>body{font:16px system-ui;max-width:1400px;margin:30px auto;padding:0 20px}td,th{padding:6px 14px;text-align:right}p{max-width:1100px;line-height:1.5}</style>'
        '</head><body>' + description + theory_rows + '</table>'
        + figure.to_html(full_html=False, include_plotlyjs=True) + '</body></html>')
    (out / 'methodology.json').write_text(json.dumps({
        'packet_baseline': 'two source IP datagrams per offered 1514-byte Ethernet frame',
        'target_tcp_capacity_pct': 80,
        'target_total_packet_redundancy_pct': 20,
        'loss_rate': .15,
        'existing_layout_ideal_tcp_capacity_pct': 100 * (1 - .15) * 1448 / 1690,
        'theory': 'exact finite block loss count with perfect-feedback innovative-repair lower bound',
        'simulation': 'existing GF256 coefficient decoder, fixed TCP application flight window, serialization and ARQ',
        'pareto_objectives': ['minimize total packet redundancy', 'minimize P99 delivery delay', 'maximize TCP goodput'],
        'summary_rows': len(summaries), 'pareto_rows': len(frontiers),
    }, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--replications', type=int, default=3)
    parser.add_argument('--duration', type=float, default=1)
    parser.add_argument('--drain', type=float, default=3)
    parser.add_argument('--long-check', action='store_true')
    args = parser.parse_args()
    plan = tasks(args.duration, args.drain, args.replications, args.long_check)
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = {'study': 'finite MDS levels v1', 'tasks': plan}
    manifest_path = args.out / 'experiment.json'
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError('existing result directory has a different configuration')
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    runs = args.out / 'runs'
    runs.mkdir(exist_ok=True)
    pending = [task for task in plan if not (runs / f"{task['run_id']:05d}.json").exists()]
    print(f'{len(plan) - len(pending)}/{len(plan)} existing replications', flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(execute, task) for task in pending]
        for number, future in enumerate(as_completed(futures), len(plan) - len(pending) + 1):
            result = future.result()
            destination = runs / f"{result['run_id']:05d}.json"
            temporary = destination.with_suffix('.tmp')
            temporary.write_text(json.dumps(result) + '\n')
            temporary.replace(destination)
            if number % 20 == 0 or number == len(plan):
                print(f'{number}/{len(plan)} complete', flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in plan]
    summaries = summarize(rows)
    frontiers = pareto(summaries)
    theory = [ideal_block(k, repairs, probability, model)
              for probability in (.10, .15, .20) for model in ('iid', 'burst')
              for k, repairs in LEVELS]
    write_csv(args.out / 'replications.csv', rows)
    write_csv(args.out / 'summary.csv', summaries)
    write_csv(args.out / 'theory.csv', theory)
    if frontiers:
        write_csv(args.out / 'pareto.csv', frontiers)
    write_report(args.out, theory, summaries, frontiers)
    print(f'Results written to {args.out}', flush=True)


if __name__ == '__main__':
    main()
