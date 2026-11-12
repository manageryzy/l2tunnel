"""Create an interactive report and exportable scientific Pareto figure."""
import argparse
from collections import defaultdict
import csv
from html import escape
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2_pareto import frontier, write_csv

COLORS = {'Legacy': '#687383', 'QUIC': '#b854a5', 'Feedback': '#d88916',
          'FEC rate': '#9d623c', 'Packing': '#3d8d88', 'Pacing and FEC': '#1665ba',
          'Feedback batching': '#09845e'}
SOURCES = [
    ('Sliding-window coding', 'RFC 8680', 'https://www.rfc-editor.org/rfc/rfc8680.html',
     'Sliding coding can generate repair symbols while data arrives. The current study measures coding-window and scheduled-repair choices.'),
    ('Random linear coding', 'RFC 8681', 'https://www.rfc-editor.org/rfc/rfc8681.html',
     'GF(256) sliding-window RLC is standardized. This simulator uses its own packet cost model and coding construction.'),
    ('Feedback and elastic coding windows', 'RFC 9407', 'https://www.rfc-editor.org/rfc/rfc9407.html',
     'Experimental Tetrys uses feedback to maintain an elastic window of unacknowledged source symbols. A full Tetrys implementation is outside the measured candidates.'),
    ('QUIC recovery', 'RFC 9002', 'https://www.rfc-editor.org/rfc/rfc9002.html',
     'QUIC combines packet-number acknowledgments, loss detection, probe timeouts, and congestion control. The plotted QUIC points run aioquic 1.3.0.'),
    ('QUIC implementation', 'aioquic API', 'https://aioquic.readthedocs.io/en/latest/quic.html',
     'The connection API accepts datagrams and timer events without sockets. This permits the actual protocol stack to run over simulated links.'),
    ('Datagram transport direction', 'RFC 9221', 'https://www.rfc-editor.org/rfc/rfc9221.html',
     'QUIC DATAGRAM supports unreliable messages under congestion control. Carrying a 1514-byte frame through a 1500-byte IP MTU requires application fragmentation. DATAGRAM plus FEC is a research direction here.'),
    ('Rate control direction', 'BBRv3 draft', 'https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/',
     'BBR models delivery rate, RTT, and loss. The document remains an Internet-Draft. BBR is not included in the measured points. Fixed-capacity pacing in this study uses the configured link rate.'),
    ('FEC and congestion control', 'RFC 9265', 'https://www.rfc-editor.org/rfc/rfc9265.html',
     'The document discusses preserving congestion signals when using FEC. These experiments model isolated exogenous erasures and do not establish shared-bottleneck fairness.'),
]


def load_summary(directory):
    with (directory / 'summary.csv').open() as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        for key, value in row.items():
            if key not in ('strategy', 'family', 'loss_model'):
                row[key] = float(value) if value else None
    return rows


def latency_frontier(rows):
    best = float('inf')
    selected = []
    for row in sorted((r for r in rows if r['min_delivery_fraction'] >= .999),
                      key=lambda r: (r['l2_extra_wire_pct_mean'], r['frame_p99_ms_mean'])):
        if row['frame_p99_ms_mean'] < best:
            selected.append(row)
            best = row['frame_p99_ms_mean']
    return selected


def interactive(main, long):
    groups = defaultdict(list)
    for row in main + long:
        key = (row['duration_s'], row['forward_mbps'], row['rtt_ms'], row['loss_model'])
        groups[key].append(row)
    first = (20.0, 100.0, 70.0, 'iid')
    ordered = sorted(groups, key=lambda key: (key != first, key))
    fig = make_subplots(rows=1, cols=2, subplot_titles=('Throughput and overhead', 'Delay and overhead'),
                        horizontal_spacing=.13)
    spans = []
    for key in ordered:
        rows = groups[key]
        start = len(fig.data)
        visible = not spans
        for family, color in COLORS.items():
            points = [r for r in rows if r['family'] == family]
            if not points:
                continue
            for col, metric in ((1, 'l2_goodput_mbps'), (2, 'frame_p99_ms')):
                fig.add_trace(go.Scatter(
                    x=[r['l2_extra_wire_pct_mean'] for r in points],
                    y=[r[metric + '_mean'] for r in points],
                    text=[r['strategy'] for r in points],
                    customdata=[[r['min_delivery_fraction'] * 100, r['l2_duplex_extra_wire_pct_mean'],
                                 r['packet_multiplier_mean'], r['max_p99_ms']] for r in points],
                    mode='markers', name=family, legendgroup=family, showlegend=col == 1,
                    visible=visible, marker={'color': color, 'size': 11,
                    'symbol': ['circle' if r['min_delivery_fraction'] >= .999 else 'x' for r in points]},
                    error_x={'array': [r['l2_extra_wire_pct_ci_high'] - r['l2_extra_wire_pct_mean'] for r in points], 'thickness': 1},
                    error_y={'array': [r[metric + '_ci_high'] - r[metric + '_mean'] for r in points], 'thickness': 1},
                    hovertemplate='%{text}<br>Extra forward bytes %{x:.1f}%<br>Value %{y:.3f}'
                                  '<br>Minimum completion %{customdata[0]:.2f}%'
                                  '<br>Duplex extra bytes %{customdata[1]:.1f}%'
                                  '<br>Packets per delivered frame %{customdata[2]:.2f}'
                                  '<br>Worst replication P99 %{customdata[3]:.2f} ms<extra></extra>',
                ), row=1, col=col)
        for col, points, metric in ((1, frontier(rows), 'l2_goodput_mbps'),
                                    (2, latency_frontier(rows), 'frame_p99_ms')):
            fig.add_trace(go.Scatter(x=[r['l2_extra_wire_pct_mean'] for r in points],
                                     y=[r[metric + '_mean'] for r in points],
                                     text=[r['strategy'] for r in points], mode='lines',
                                     line={'color': '#192733', 'width': 2},
                                     name='Empirical frontier, completion >=99.9%',
                                     showlegend=col == 1, visible=visible,
                                     hovertemplate='%{text}<extra></extra>'), row=1, col=col)
        for budget, color in ((5, '#19a85a'), (10, '#db5247'), (20, '#8c62ba')):
            points = frontier(rows, maximum_extra_delay=budget)
            fig.add_trace(go.Scatter(x=[r['l2_extra_wire_pct_mean'] for r in points],
                                     y=[r['l2_goodput_mbps_mean'] for r in points],
                                     mode='lines+markers', marker={'size': 5},
                                     line={'color': color, 'dash': 'dash'},
                                     name=f'Frontier with P99 <= one-way + {budget} ms', visible=visible), row=1, col=1)
        duration, bandwidth, rtt, model = key
        label = f'{bandwidth:g} Mbps / 10 Mbps · RTT {rtt:g} ms · 20% {model} · {duration:g} s'
        spans.append((start, len(fig.data), label))
    fig.update_xaxes(title_text='Extra forward IP bytes per delivered L2 byte (%)')
    fig.update_yaxes(title_text='Delivered L2 goodput (Mbps)', row=1, col=1)
    fig.update_yaxes(title_text='P99 frame delivery delay (ms)', type='log', row=1, col=2)
    fig.update_layout(template='plotly_white', height=650, margin={'t': 120, 'b': 150},
                      legend={'orientation': 'h', 'y': -.25},
                      updatemenus=[{'x': 0, 'y': 1.18, 'buttons': [
                          {'label': label, 'method': 'update', 'args': [
                              {'visible': [start <= i < end for i in range(len(fig.data))]}]}
                          for start, end, label in spans]}])
    return fig


def bandwidth_figure(rows):
    selected = ('Sliding 33%', 'Cumulative SW33', 'Paced 30% W255', 'Paced 33% W255',
                'Batched feedback 33.3333% W255', 'Batched feedback 45% W128', 'QUIC L2 CUBIC')
    fig = make_subplots(rows=1, cols=2, subplot_titles=('Bandwidth sensitivity', 'Extra byte cost'))
    palette = ('#687383', '#d88916', '#1665ba', '#8c62ba', '#09845e', '#dc5a44', '#b854a5')
    for name, color in zip(selected, palette):
        for model, dash in (('iid', 'solid'), ('burst', 'dot')):
            points = sorted((r for r in rows if r['strategy'] == name and r['rtt_ms'] == 70
                             and r['loss_model'] == model), key=lambda r: r['forward_mbps'])
            for col, metric in ((1, 'l2_goodput_mbps'), (2, 'l2_extra_wire_pct')):
                fig.add_trace(go.Scatter(x=[r['forward_mbps'] for r in points],
                                         y=[r[metric + '_mean'] for r in points],
                                         name=name + ' · ' + model, legendgroup=name + model,
                                         showlegend=col == 1, mode='lines+markers',
                                         line={'dash': dash, 'color': color}), row=1, col=col)
    fig.update_xaxes(type='log', title_text='Forward link capacity (Mbps)')
    fig.update_yaxes(title_text='Delivered L2 goodput (Mbps)', row=1, col=1)
    fig.update_yaxes(title_text='Extra forward bytes (%)', row=1, col=2)
    fig.update_layout(template='plotly_white', height=540, legend={'orientation': 'h', 'y': -.3},
                      margin={'b': 140})
    return fig


def static_figure(rows, destination):
    points = [r for r in rows if r['forward_mbps'] == 100 and r['rtt_ms'] == 70 and r['loss_model'] == 'iid']
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.6), layout='constrained')
    for axis, metric, ylabel in zip(axes, ('l2_goodput_mbps', 'frame_p99_ms'),
                                     ('Delivered L2 goodput (Mbps)', 'P99 frame delivery delay (ms)')):
        for family, color in COLORS.items():
            family_points = [r for r in points if r['family'] == family]
            for complete in (True, False):
                group = [r for r in family_points if (r['min_delivery_fraction'] >= .999) == complete]
                if not group:
                    continue
                axis.scatter([r['l2_extra_wire_pct_mean'] for r in group],
                             [r[metric + '_mean'] for r in group],
                             color=color, marker='o' if complete else 'x', s=45, label=family)
        line = frontier(points) if metric == 'l2_goodput_mbps' else latency_frontier(points)
        axis.plot([r['l2_extra_wire_pct_mean'] for r in line], [r[metric + '_mean'] for r in line],
                  color='#192733', linewidth=1.3)
        labels = ('Sliding 33%', 'QUIC L2 CUBIC', 'Paced 30% W255', 'Batched feedback 45% W128')
        for r in points:
            if r['strategy'] in labels:
                label = r['strategy'].replace('Batched feedback', 'Batched')
                axis.annotate(label, (r['l2_extra_wire_pct_mean'], r[metric + '_mean']),
                              xytext=(4, 6), textcoords='offset points', fontsize=8)
        axis.set_xlabel('Extra forward IP bytes per delivered L2 byte (%)')
        axis.set_ylabel(ylabel)
        axis.grid(alpha=.2)
    axes[1].set_yscale('log')
    axes[1].axhline(35, color='#19a85a', linestyle='--', linewidth=1, label='35 ms propagation')
    for budget, color in ((5, '#19a85a'), (10, '#db5247'), (20, '#8c62ba')):
        selected = frontier(points, maximum_extra_delay=budget)
        axes[0].plot([r['l2_extra_wire_pct_mean'] for r in selected],
                     [r['l2_goodput_mbps_mean'] for r in selected],
                     marker='*', markersize=12, color=color, linestyle='--',
                     label=f'P99 <= 35 + {budget} ms')
    handles, labels = axes[0].get_legend_handles_labels()
    axes[0].legend(dict(zip(labels, handles)).values(), dict(zip(labels, handles)).keys(), fontsize=8, loc='lower right')
    fig.suptitle('Complete 1514-byte Ethernet frames · 1500-byte IP MTU\n100/10 Mbps · 70 ms RTT · 20% independent loss · 5 replications', fontsize=13)
    duration, drain = points[0]['duration_s'], points[0]['drain_s']
    fig.text(.5, -.025, f'Means over {duration:g}-second transfers with {drain:g}-second drain. Lines join eligible empirical frontier points. Crosses indicate incomplete delivery.',
             ha='center', fontsize=9)
    fig.savefig(destination, dpi=180, bbox_inches='tight')
    plt.close(fig)


def table(rows):
    body = []
    for r in sorted(rows, key=lambda r: (-r['duration_s'], -r['l2_goodput_mbps_mean'])):
        body.append('<tr>' + ''.join(f'<td>{escape(str(value))}</td>' for value in (
            f"{r['duration_s']:g}s", r['strategy'], f"{r['l2_goodput_mbps_mean']:.2f}",
            f"{r['l2_extra_wire_pct_mean']:.1f}%", f"{r['l2_duplex_extra_wire_pct_mean']:.1f}%",
            f"{r['frame_p99_ms_mean']:.1f}", f"{100*r['min_delivery_fraction']:.2f}%")) + '</tr>')
    headings = ('Transfer', 'Strategy', 'L2 Mbps', 'Extra forward bytes', 'Extra duplex bytes', 'Mean P99 ms', 'Minimum completion')
    return '<table><thead><tr>' + ''.join('<th>'+h+'</th>' for h in headings) + '</tr></thead><tbody>' + ''.join(body) + '</tbody></table>'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    rows = load_summary(args.root / 'main') + load_summary(args.root / 'feedback-batching')
    long = (load_summary(args.root / 'long-check') + load_summary(args.root / 'refinement')
            + load_summary(args.root / 'interleaved') + load_summary(args.root / 'feedback-long'))
    pareto = interactive(rows, long)
    bandwidth = bandwidth_figure(rows)
    static_figure(rows, args.root / 'pareto.png')
    static_figure(long, args.root / 'pareto-long.png')
    write_csv(args.root / 'combined-summary.csv', rows + long)
    groups = defaultdict(list)
    for row in rows + long:
        groups[(row['duration_s'], row['forward_mbps'], row['rtt_ms'], row['loss_model'])].append(row)
    frontiers = []
    for group in groups.values():
        for budget in (None, 5, 10, 20):
            frontiers.extend({'extra_delay_budget_ms': budget if budget is not None else 'unconstrained', **r}
                             for r in frontier(group, maximum_extra_delay=budget))
    write_csv(args.root / 'pareto-combined.csv', frontiers)
    focus = [r for r in rows + long if r['forward_mbps'] == 100 and r['rtt_ms'] == 70 and r['loss_model'] == 'iid']
    references = ''.join(f'<li><strong>{escape(direction)}</strong>. {escape(description)} '
                         f'<a href="{url}">{escape(title)}</a></li>' for direction,title,url,description in SOURCES)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>L2 overhead and performance Pareto study</title><style>
body{font:16px system-ui,sans-serif;color:#172638;max-width:1450px;margin:40px auto;padding:0 24px;line-height:1.6}
h1{font-size:30px}h2{margin-top:38px}p,li{max-width:1100px}.note{background:#eef4fa;padding:16px 22px;border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:9px;border-bottom:1px solid #d6dee6;text-align:right}td:nth-child(2),th:nth-child(2){text-align:left}
a{color:#165db1}.downloads{display:flex;gap:22px;flex-wrap:wrap}</style>
<h1>L2 overhead and performance Pareto study</h1>
<p>All measured tunnel candidates carry complete 1514-byte Ethernet frames through a 1500-byte outer IP MTU.
The sweep changes feedback, scheduled FEC, coding windows, packet packing, and pacing. QUIC points run real aioquic 1.3.0 CUBIC or Reno over the simulated links.</p>
<div class="downloads"><a href="pareto-long.png">Long-run Pareto figure</a><a href="pareto.png">Bandwidth-study Pareto figure</a><a href="main/replications.csv">900 baseline sweep replications</a><a href="feedback-batching/replications.csv">80 feedback-batching replications</a><a href="combined-summary.csv">Summary and 95% intervals</a><a href="pareto-combined.csv">Constrained frontiers</a><a href="long-check/replications.csv">30 longer replications</a><a href="refinement/replications.csv">15 grouped-repair refinements</a><a href="interleaved/replications.csv">15 interleaved-repair refinements</a><a href="feedback-long/replications.csv">10 feedback-batching validations</a><a href="main/experiment.json">Full configurations</a></div>
<h2>Metrics and eligibility</h2>
<p>Extra forward bytes = 100 × (completed forward IP bytes / complete delivered Ethernet bytes − 1).
A value of 100% means two forward wire bytes per delivered L2 byte. A value of 50% means 1.5 forward wire bytes.
The fraction of wire bytes that is overhead uses a different denominator. Duplex overhead also includes reverse traffic.</p>
<p>Goodput counts complete frames delivered during the traffic interval. Byte efficiency and completion include the drain period.
Delay starts when a frame enters the sender and ends when the complete frame is released.
P99 values are conditional on completed frames. Crosses mark a replication with completion below 99.9% at cutoff.
QUIC streams can have queued records at cutoff while retaining their protocol reliability.</p>
<p>Frontiers compare empirical means among eligible measured configurations. Eligibility requires at least 99.9% completion in every replication.
Latency-constrained curves additionally require every replication's P99 to fit the stated budget above nominal one-way propagation.
An absent constrained curve means no tested configuration met that constraint. The intervals are 95% Student-t intervals over independent replications.
Frontiers do not establish statistical dominance or a global optimum.</p>
'''
    page += pareto.to_html(full_html=False, include_plotlyjs=True, div_id='l2-pareto')
    page += '<h2>Bandwidth sensitivity</h2><p>Reverse capacity stays at 10 Mbps. Loss is 20% in each direction. Burst loss uses the existing stationary Markov model with mean run length four datagrams.</p>'
    page += bandwidth.to_html(full_html=False, include_plotlyjs=False, div_id='bandwidth-sensitivity')
    page += '<h2>100 Mbps comparison</h2><p>RTT is 70 ms, independent loss is 20%, and each strategy has five replications. Longer runs use 20 seconds of traffic and 10 seconds of drain.</p>' + table(focus)
    page += '''<h2>Interpretation and model boundaries</h2><div class="note">
<p>The low-overhead target must be assessed jointly with delay. At 20% independent erasure, ideal equal-size reliable delivery already requires at least 1/(1−0.2)=1.25 transmitted data-equivalents per delivered data-equivalent, before encapsulation and finite-window margin.
The existing two-fragment layout costs 1690 IP bytes per 1514-byte frame before repairs. Its corresponding idealized floor is approximately 39.5% extra forward bytes.</p>
<p>Paced candidates use the configured capacity to schedule source traffic at 92% of the source-plus-scheduled-FEC budget and allow a 4 MiB application window.
Other candidates use the existing 1 MiB window. This is a controlled-capacity pacing assumption. Tunnel traffic retains fixed inner flow control.
QUIC uses its implementation's congestion control, pacing, acknowledgments, and retransmissions. These policies have different sharing behavior.</p>
<p>QUIC uses one reliable stream carrying fixed-size L2 records. A lossless warmup establishes the connection before measurement, and its bytes are excluded.
Its packet bytes, ACK frames, and cryptographic overhead are generated by aioquic. Datagram counters classify packets containing any repeated stream bytes as retries, including a mixture of new and repeated bytes.
The separate retransmitted-stream counter counts repeated stream bytes exactly for this ordered single-stream sender.</p>
<p>Tunnel encapsulation assumes 88 bytes per datagram. GF(256) coding and decoding are modeled, with zero configured CPU delay.
QUIC encryption executes during the run but its computation time is excluded from virtual link time. There is no competing traffic or finite-router-buffer congestion model.
These results characterize simulated protocol and queue behavior. Native NIC throughput, decoder CPU limits, and shared-link fairness require additional system measurements.</p></div>
<h2>Research directions and implementation scope</h2><ul>'''
    page += references + '</ul><p>Sources checked on 2026-11-10. Fixed cumulative feedback, configurable grouped repair ratios, and the QUIC adapter are implemented in this workspace. The research-only directions have no plotted performance points.</p>'
    page += '</html>'
    (args.root / 'report.html').write_text(page, encoding='utf-8')
    (args.root / 'sources.json').write_text(json.dumps(SOURCES, indent=2) + '\n')
    print(f'Wrote {args.root / "report.html"}')


if __name__ == '__main__':
    main()
