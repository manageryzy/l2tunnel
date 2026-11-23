"""Run paired replications and export measurements with their provenance."""

from collections import defaultdict
import csv
from dataclasses import asdict
import json
from random import Random
import platform

import numpy as np
import plotly
import plotly.graph_objects as go
import scipy
from plotly.subplots import make_subplots

from . import __version__
from .model import Simulation
from .tcp import PlainTCP
from .stats import mean_ci, paired_difference


METRICS = (
    "tcp_goodput_mbps", "l2_goodput_mbps", "l2_efficiency", "tcp_payload_efficiency",
    "duplex_payload_efficiency", "frame_delivery_fraction", "tcp_delivery_fraction",
    "frame_p50_ms", "frame_p95_ms", "frame_p99_ms", "ack_rtt_p50_ms",
    "ack_rtt_p95_ms", "forward_peak_retained_bytes", "forward_peak_reorder_bytes",
    "tcp_retransmissions", "tcp_timeouts", "tcp_fast_retransmits",
)


def _percentiles(values, levels):
    if not values:
        return [None] * len(levels)
    return np.percentile(values, levels).tolist()


def measure(sim, *, segmented_payload=None):
    forward, reverse = sim.forward, sim.reverse
    sent = len(sim.sent_times)
    forward_wire = sum(sim.wire[False].values())
    reverse_wire = sum(sim.wire[True].values())
    if getattr(sim, "segment_offsets", None) is not None:
        segmented_payload = sim.byte_offset(sim.tcp_received)
    payload = sim.tcp_received * sim.traffic.payload_bytes if segmented_payload is None else segmented_payload
    frame_p50, frame_p95, frame_p99 = _percentiles(forward.delays, [50, 95, 99])
    rtt_p50, rtt_p95 = _percentiles(sim.tcp_rtts, [50, 95])
    row = {
        "tcp_goodput_mbps": sim.tcp_payload_bytes * 8 / (sim.traffic.duration_s * 1e6),
        "l2_goodput_mbps": forward.delivered_during_measurement_bytes * 8 / (sim.traffic.duration_s * 1e6),
        "l2_efficiency": forward.delivered_bytes / forward_wire if forward_wire else None,
        "tcp_payload_efficiency": payload / forward_wire if forward_wire else None,
        "duplex_payload_efficiency": payload / (forward_wire + reverse_wire)
        if forward_wire + reverse_wire else None,
        "frame_delivery_fraction": len(forward.delays) / sent if sent else None,
        "tcp_delivery_fraction": sim.tcp_received / sent if sent else None,
        "frame_p50_ms": frame_p50,
        "frame_p95_ms": frame_p95,
        "frame_p99_ms": frame_p99,
        "ack_rtt_p50_ms": rtt_p50,
        "ack_rtt_p95_ms": rtt_p95,
        "forward_peak_retained_bytes": forward.peak_pending_bytes,
        "forward_peak_reorder_bytes": forward.peak_reorder_bytes,
        "tcp_retransmissions": getattr(sim, "tcp_retransmissions", None),
        "tcp_timeouts": getattr(sim, "tcp_timeouts", None),
        "tcp_fast_retransmits": getattr(sim, "tcp_fast_retransmits", None),
        "tcp_final_cwnd_segments": getattr(sim, "cwnd", None),
        "transport": {"tcp": "direct_tcp", "quic": "quic_l2" if sim.strategy.quic_l2 else "direct_quic"}.get(sim.strategy.mode, "tunnel"),
        "tcp_controller": sim.strategy.tcp_cc if sim.strategy.mode in ("tcp", "quic") else "fixed_window",
        "tcp_path": sim.strategy.tcp_path if sim.strategy.mode in ("tcp", "quic") else None,
        "tcp_recovery": {"tcp": "newreno", "quic": "aioquic"}.get(sim.strategy.mode, "outer_arq"),
        "quic_retransmitted_stream_bytes": getattr(sim, "quic_retransmitted_stream_bytes", None),
        "quic_cwnd_bytes": getattr(sim, "quic_cwnd_bytes", None),
        "payload_bytes_per_frame": sim.traffic.payload_bytes if segmented_payload is None else None,
        "offered_frames": sent,
        "released_frames": len(forward.delays),
        "tcp_delivered_frames": sim.tcp_received,
        "tcp_acked_frames": sim.tcp_acked,
        "tcp_payload_bytes_during_measurement": sim.tcp_payload_bytes,
        "forward_l2_bytes": forward.delivered_bytes,
        "tcp_payload_bytes": payload,
    }
    for direction, tunnel, prefix in ((False, forward, "forward"), (True, reverse, "reverse")):
        row[f"{prefix}_wire_bytes"] = sum(sim.wire[direction].values())
        row[f"{prefix}_datagrams"] = sum(sim.datagrams[direction].values())
        row[f"{prefix}_lost_datagrams"] = sum(sim.erasures[direction].values())
        row[f"{prefix}_fec_recovered_symbols"] = tunnel.recovered_symbols
        row[f"{prefix}_unconfirmed_symbols"] = len(tunnel.pending)
        row[f"{prefix}_unconfirmed_bytes"] = tunnel.pending_bytes
        row[f"{prefix}_peak_retained_bytes"] = tunnel.peak_pending_bytes
        row[f"{prefix}_peak_reorder_bytes"] = tunnel.peak_reorder_bytes
        for kind in ("source", "repair", "retry", "feedback"):
            row[f"{prefix}_{kind}_bytes"] = sim.wire[direction][kind]
            row[f"{prefix}_{kind}_datagrams"] = sim.datagrams[direction][kind]
            row[f"{prefix}_{kind}_lost"] = sim.erasures[direction][kind]
    return row


CDF_LEVELS = [*range(100), 99.5, 99.9, 100]


def run_experiment(experiment, out):
    rng = Random(experiment.seed)
    replications, summary, comparisons, cdf = [], [], [], []
    baseline = experiment.strategies[0].name
    report_paws = any(strategy.tcp_data_paws for strategy in experiment.strategies)
    report_undo = any(strategy.tcp_partial_timestamp_undo for strategy in experiment.strategies)
    report_ack_heuristic = any(strategy.tcp_newreno_ack_heuristic for strategy in experiment.strategies)
    for scenario_id, scenario in enumerate(experiment.scenarios(), 1):
        keys = {"scenario_id": scenario_id, **asdict(scenario)}
        rows = defaultdict(list)
        delays = defaultdict(list)
        for replication in range(1, experiment.replications + 1):
            seed = rng.getrandbits(64)
            for strategy in experiment.strategies:
                simulation = simulation_type(strategy.mode)
                sim = simulation(scenario, experiment.traffic, experiment.paths, strategy, seed).run()
                row = {
                    **keys, "strategy": strategy.name, "replication": replication,
                    "seed": seed, **measure(sim),
                }
                if report_paws:
                    row["tcp_data_paws"] = strategy.tcp_data_paws
                    row["tcp_data_paws_rejections"] = (
                        sim.data_paws.rejections if strategy.tcp_data_paws else None)
                if report_undo:
                    row["tcp_partial_timestamp_undo"] = strategy.tcp_partial_timestamp_undo
                    row["tcp_partial_timestamp_undos"] = (
                        sim.tcp_partial_timestamp_undos if strategy.tcp_partial_timestamp_undo else None)
                if report_ack_heuristic:
                    row["tcp_newreno_ack_heuristic"] = strategy.tcp_newreno_ack_heuristic
                    row["tcp_newreno_ack_heuristic_entries"] = (
                        sim.tcp_newreno_ack_heuristic_entries if strategy.tcp_newreno_ack_heuristic else None)
                replications.append(row)
                rows[strategy.name].append(row)
                delays[strategy.name].extend(sim.forward.delays)
        for strategy, records in rows.items():
            for metric in METRICS:
                observed = [record[metric] for record in records if record[metric] is not None]
                summary.append({
                    **keys, "strategy": strategy, "metric": metric, **mean_ci(observed),
                })
                if strategy != baseline:
                    pairs = [
                        (left[metric], right[metric])
                        for left, right in zip(records, rows[baseline])
                        if left[metric] is not None and right[metric] is not None
                    ]
                    left, right = zip(*pairs) if pairs else ((), ())
                    comparisons.append({
                        **keys, "strategy": strategy, "baseline": baseline,
                        "metric": metric, **paired_difference(left, right),
                    })
            quantiles = _percentiles(delays[strategy], CDF_LEVELS)
            for percentile, delay in zip(CDF_LEVELS, quantiles):
                cdf.append({
                    **keys, "strategy": strategy, "percentile": percentile,
                    "delay_ms": delay, "delivered_frames": len(delays[strategy]),
                })

    out.mkdir(parents=True, exist_ok=False)
    _csv(out / "replications.csv", replications)
    _csv(out / "summary.csv", summary)
    comparison_fields = [*keys, "strategy", "baseline", "metric", "mean",
                         "ci_low", "ci_high", "n", "method"]
    _csv(out / "paired.csv", comparisons, comparison_fields)
    _csv(out / "latency_cdf.csv", cdf)
    _report(out / "report.html", summary, cdf)
    manifest = {
        "simulator_version": __version__,
        "runtime": {"python": platform.python_version(), "numpy": np.__version__,
                    "scipy": scipy.__version__, "plotly": plotly.__version__},
        "config": asdict(experiment),
    }
    if any(strategy.mode == "quic" for strategy in experiment.strategies):
        from importlib.metadata import version
        manifest["runtime"]["aioquic"] = version("aioquic")
        manifest["runtime"]["cryptography"] = version("cryptography")
    (out / "experiment.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def simulation_type(mode):
    if mode == "quic":
        from .quic import QUIC
        return QUIC
    return PlainTCP if mode == "tcp" else Simulation


def _csv(path, rows, columns=None):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns or list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _label(row):
    return f"{row['rtt_ms']:g} ms RTT · {row['loss_rate']:.0%} {row['loss_model']} · MTU {row['mtu']}"


def _report(path, summary, cdf):
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=("TCP goodput", "Forward delivery latency",
                        "Forward TCP payload efficiency", "TCP delivery at observation end"),
        vertical_spacing=0.20,
    )
    metric_panels = (
        ("tcp_goodput_mbps", 1, 1, 1, "Mbps"),
        ("tcp_payload_efficiency", 2, 1, 100, "%"),
        ("tcp_delivery_fraction", 2, 2, 100, "%"),
    )
    by_scenario = defaultdict(dict)
    curves = defaultdict(lambda: defaultdict(list))
    for row in summary:
        by_scenario[row["scenario_id"]].setdefault(row["metric"], []).append(row)
    for row in cdf:
        curves[row["scenario_id"]][row["strategy"]].append(row)

    spans = []
    for scenario, metrics in by_scenario.items():
        start = len(fig.data)
        visible = not spans
        for metric, row, col, scale, unit in metric_panels:
            entries = metrics[metric]
            fig.add_trace(go.Bar(
                x=[entry["strategy"] for entry in entries],
                y=[entry["mean"] * scale if entry["mean"] is not None else None
                   for entry in entries],
                error_y={"array": [
                    (entry["ci_high"] - entry["mean"]) * scale
                    if entry["ci_high"] is not None else None for entry in entries
                ]},
                customdata=[entry["n"] for entry in entries],
                hovertemplate=f"%{{x}}<br>%{{y:.3g}} {unit}<br>Replications %{{customdata}}<extra></extra>",
                showlegend=False, visible=visible,
            ), row=row, col=col)
            fig.update_yaxes(title_text=unit, row=row, col=col)
        for strategy, points in curves[scenario].items():
            fig.add_trace(go.Scatter(
                name=strategy, x=[point["delay_ms"] for point in points],
                y=[point["percentile"] for point in points],
                mode="lines", visible=visible,
                hovertemplate="%{x:.3f} ms<br>%{y:g} percentile<extra>%{fullData.name}</extra>",
            ), row=1, col=2)
        spans.append((start, len(fig.data), _label(metrics["tcp_goodput_mbps"][0])))

    fig.update_xaxes(title_text="Segment/frame submission to delivery (ms)", row=1, col=2)
    fig.update_yaxes(title_text="Percentile (delivered frames)", range=[0, 101], row=1, col=2)
    fig.update_layout(
        template="plotly_white", height=780, margin={"t": 145, "b": 110},
        title="L2 tunnel simulator · direct TCP and tunnel comparison · QUIC",
        updatemenus=[{"x": 0, "y": 1.13, "xanchor": "left", "buttons": [
            {"label": label, "method": "update",
             "args": [{"visible": [start <= index < end for index in range(len(fig.data))]}]}
            for start, end, label in spans
        ]}],
        annotations=[
            *fig.layout.annotations,
            {"text": "Bars show replication means with 95% Student-t intervals where estimable. "
                     "The latency curve pools delivered frames across replications.<br>"
                     "Direct TCP uses NewReno recovery. QUIC uses aioquic on established connections. Tunnel traffic uses a fixed flight window.",
             "xref": "paper", "yref": "paper", "x": 0, "y": -0.22, "showarrow": False},
        ],
    )
    fig.write_html(path, include_plotlyjs=True, div_id="l2tunnel-report", auto_open=False)
