"""Measure independent transport flow counts on one shared duplex bottleneck."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import asdict, replace
from hashlib import sha256
from importlib.metadata import version
import json
from pathlib import Path
from random import Random
from time import perf_counter

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.multiflow import MultiFlow
from l2tunnel_sim.stats import mean_ci


def tasks(duration, drain, replications):
    base = Strategy("Sliding 16.7% W255", mode="sliding", repair_every=6,
                    repairs_per_group=1, long_window=255, feedback_repair=True,
                    cumulative_feedback=True, interleave_repairs=True, fec_wait_ms=10,
                    feedback_wait_ms=1, feedback_batch=64, reverse_batch=16, pack_wait_ms=.8)
    profiles = [(replace(base, name=base.name + " unpaced"), False),
                (replace(base, name=base.name + " paced"), True),
                (Strategy("QUIC L2 CUBIC", mode="quic", tcp_cc="cubic"), False)]
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(replications)]
    plan = []
    for loss_rate in (.15, .20):
        for strategy, paced in profiles:
            traffic = Traffic(duration_s=duration, drain_s=drain, window_bytes=4 * 1048576)
            if paced:
                interval = 1690 * (1 + 1 / 6) * 8 / (100 * 1000 * .92)
                traffic = replace(traffic, frame_interval_ms=interval)
            for count in (1, 2, 4, 8, 16):
                for replication, seed in enumerate(seeds, 1):
                    plan.append(dict(run_id=len(plan) + 1, strategy=asdict(strategy),
                                     traffic=asdict(traffic), scenario=asdict(Scenario(70, loss_rate)),
                                     paths=[asdict(PathConfig())], flow_count=count,
                                     replication=replication, seed=seed, window_policy="fixed_total"))
    return plan


def execute(task):
    start = perf_counter()
    paths = tuple(PathConfig(**path) for path in task["paths"])
    sim = MultiFlow(Scenario(**task["scenario"]), Traffic(**task["traffic"]), paths,
                    Strategy(**task["strategy"]), task["seed"], task["flow_count"],
                    window_policy=task["window_policy"]).run()
    row = {key: task[key] for key in ("run_id", "replication", "seed")}
    row.update(task["scenario"], strategy=task["strategy"]["name"], **sim.measurements())
    row.update(forward_mbps=paths[0].forward_mbps, reverse_mbps=paths[0].reverse_mbps,
               duration_s=sim.traffic.duration_s, drain_s=sim.traffic.drain_s,
               frame_interval_ms=sim.traffic.frame_interval_ms,
               compute_seconds=perf_counter() - start)
    delivered = row["forward_l2_bytes"]
    source = row["forward_source_datagrams"]
    row["l2_extra_wire_pct"] = 100 * (row["forward_wire_bytes"] / delivered - 1) if delivered else None
    row["l2_duplex_extra_wire_pct"] = 100 * ((row["forward_wire_bytes"] + row["reverse_wire_bytes"])
                                            / delivered - 1) if delivered else None
    row["extra_forward_datagrams_pct"] = 100 * (row["forward_datagrams"] / source - 1) if source else None
    row["tcp_payload_capacity_pct"] = 100 * row["tcp_goodput_mbps"] / paths[0].forward_mbps
    row["forward_capacity_used_pct"] = (100 * row["forward_wire_bytes_during_measurement"]
                                         / (paths[0].forward_mbps * 125000 * sim.traffic.duration_s))
    row["status"] = "complete_at_cutoff" if row["tcp_delivery_fraction"] == 1 else "incomplete_at_cutoff"
    for reverse, prefix in ((False, "forward"), (True, "reverse")):
        assert row[prefix + "_wire_bytes"] == sum(row[f"{prefix}_{kind}_bytes"]
                                                  for kind in ("source", "repair", "retry", "feedback"))
        capacity = sim.links[reverse][0].bytes_per_s
        assert row[prefix + "_wire_bytes_during_measurement"] <= capacity * sim.traffic.duration_s
        assert row[prefix + "_wire_bytes"] <= capacity * (sim.traffic.duration_s + sim.traffic.drain_s)
    assert row["forward_l2_bytes"] == row["released_frames"] * 1514
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    return {"aggregate": row, "flows": sim.flow_measurements()}


METRICS = ("tcp_goodput_mbps", "l2_goodput_mbps", "tcp_payload_capacity_pct", "tcp_payload_efficiency",
           "l2_extra_wire_pct", "l2_duplex_extra_wire_pct", "extra_forward_datagrams_pct",
           "forward_source_datagrams", "forward_datagrams", "forward_wire_bytes", "reverse_wire_bytes",
           "frame_p99_ms", "frame_delivery_fraction", "tcp_delivery_fraction", "jain_goodput_fairness",
           "forward_capacity_used_pct")


def summarize(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row["loss_rate"], row["strategy"], row["flow_count"]), []).append(row)
    summaries = []
    for records in groups.values():
        summary = {key: records[0][key] for key in (
            "loss_rate", "strategy", "flow_count", "window_policy", "total_window_bytes",
            "duration_s", "drain_s", "frame_interval_ms", "rtt_ms", "forward_mbps", "reverse_mbps",
        )}
        for metric in METRICS:
            for key, value in mean_ci([row[metric] for row in records if row[metric] is not None]).items():
                if key != "method":
                    summary[metric + "_" + key] = value
        summary["min_delivery_fraction"] = min(row["frame_delivery_fraction"] for row in records)
        summary["complete_replications"] = sum(row["status"] == "complete_at_cutoff" for row in records)
        summaries.append(summary)
    return summaries


def frontier(rows):
    selected = []
    for loss in sorted({row["loss_rate"] for row in rows}):
        eligible = [row for row in rows if row["loss_rate"] == loss and row["min_delivery_fraction"] >= .999]
        best = -1
        for row in sorted(eligible, key=lambda row: (row["l2_extra_wire_pct_mean"], -row["tcp_goodput_mbps_mean"])):
            if row["tcp_goodput_mbps_mean"] > best:
                selected.append(row)
                best = row["tcp_goodput_mbps_mean"]
    return selected


def report(path, rows):
    fig = make_subplots(rows=2, cols=2, subplot_titles=(
        "TCP payload throughput", "Forward bytes beyond delivered L2 bytes",
        "P99 frame delivery latency", "Mean Pareto frontier, complete delivery"))
    for loss in sorted({row["loss_rate"] for row in rows}):
        for strategy in dict.fromkeys(row["strategy"] for row in rows):
            points = sorted([row for row in rows if row["loss_rate"] == loss and row["strategy"] == strategy],
                            key=lambda row: row["flow_count"])
            name = f"{strategy}, {loss:.0%} loss"
            for metric, panel in (("tcp_goodput_mbps", (1, 1)), ("l2_extra_wire_pct", (1, 2)),
                                  ("frame_p99_ms", (2, 1))):
                fig.add_trace(go.Scatter(
                    name=name, legendgroup=name, showlegend=panel == (1, 1), mode="lines+markers",
                    x=[row["flow_count"] for row in points], y=[row[metric + "_mean"] for row in points],
                    error_y={"array": [row[metric + "_ci_high"] - row[metric + "_mean"]
                                        if row[metric + "_ci_high"] is not None else None for row in points]},
                ), row=panel[0], col=panel[1])
            fig.add_trace(go.Scatter(name=name, legendgroup=name, showlegend=False, mode="markers+text",
                                    x=[row["l2_extra_wire_pct_mean"] for row in points],
                                    y=[row["tcp_goodput_mbps_mean"] for row in points],
                                    text=[str(row["flow_count"]) for row in points], textposition="top center",
                                    marker={"symbol": ["circle" if row["min_delivery_fraction"] >= .999 else "x"
                                                       for row in points]},
                                    customdata=[row["min_delivery_fraction"] for row in points],
                                    hovertemplate="%{text} flows<br>%{x:.2f}% extra bytes<br>%{y:.3f} Mbps<br>"
                                                  "Minimum delivery %{customdata:.2%}<extra>%{fullData.name}</extra>"),
                          row=2, col=2)
        boundary = [row for row in frontier(rows) if row["loss_rate"] == loss]
        fig.add_trace(go.Scatter(name=f"Frontier {loss:.0%} loss", mode="lines", line={"dash": "dash"},
                                x=[row["l2_extra_wire_pct_mean"] for row in boundary],
                                y=[row["tcp_goodput_mbps_mean"] for row in boundary]), row=2, col=2)
    for row, col in ((1, 1), (1, 2), (2, 1)):
        fig.update_xaxes(title="Independent connections", type="log", tickvals=[1, 2, 4, 8, 16], row=row, col=col)
    fig.update_yaxes(title="Mbps", row=1, col=1)
    fig.update_yaxes(title="Extra forward bytes (%)", row=1, col=2)
    fig.update_yaxes(title="ms", row=2, col=1)
    fig.update_xaxes(title="Extra forward bytes (%)", row=2, col=2)
    fig.update_yaxes(title="TCP payload Mbps", row=2, col=2)
    fig.update_layout(template="plotly_white", height=1000,
                      title="Independent flow count on one 100/10 Mbps link, RTT 70 ms",
                      legend={"orientation": "h", "y": -0.2}, margin={"b": 210},
                      annotations=[*fig.layout.annotations, dict(
                          text="Each point shares a fixed 4 MiB total window. Full 1514-byte Ethernet frames use a 1500-byte outer MTU.<br>"
                               "Error bars show 95% Student-t intervals. Pareto selection uses means and delivery >=99.9% in every replication.<br>"
                               "Crosses mark incomplete delivery. P99 uses delivered frames only. Throughput uses the traffic interval and excludes drain deliveries.",
                          x=0, y=-.36, xref="paper", yref="paper", showarrow=False, align="left")])
    fig.write_html(path, include_plotlyjs=True, auto_open=False, div_id="independent-flow-count")


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--replications", type=int, default=5)
    parser.add_argument("--duration", type=float, default=5)
    parser.add_argument("--drain", type=float, default=5)
    args = parser.parse_args()
    plan = tasks(args.duration, args.drain, args.replications)
    args.out.mkdir(parents=True, exist_ok=True)
    source_dir = Path(__file__).resolve().parents[1] / "src/l2tunnel_sim"
    source_paths = [source_dir / (name + ".py") for name in ("model", "config", "coding", "quic", "multiflow", "experiment")]
    manifest = dict(tasks=plan, runtime={name: version(name) for name in ("aioquic", "numpy", "scipy", "plotly")},
                    source_sha256={str(path.relative_to(source_dir.parent.parent)): sha256(path.read_bytes()).hexdigest()
                                   for path in source_paths},
                    semantics="Independent transport sessions with shared physical queues and erasure processes. "
                              "Window credit and offered pacing are divided across flows. QUIC uses one reliable stream per connection. "
                              "Peak retained/reorder byte counts sum per-flow peaks and are an upper bound on simultaneous use. "
                              "Packet redundancy uses total forward datagrams divided by source datagrams minus one.")
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing study has different parameters or source hashes")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    pending = [task for task in plan if not (runs / f"{task['run_id']:05d}.json").exists()]
    print(f"{len(plan) - len(pending)}/{len(plan)} runs complete", flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for completed, future in enumerate(as_completed([pool.submit(execute, task) for task in pending]),
                                           len(plan) - len(pending) + 1):
            result = future.result()
            destination = runs / f"{result['aggregate']['run_id']:05d}.json"
            temporary = destination.with_suffix(".tmp")
            temporary.write_text(json.dumps(result) + "\n")
            temporary.replace(destination)
            if completed % 10 == 0 or completed == len(plan):
                print(f"{completed}/{len(plan)} runs complete", flush=True)
    results = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in plan]
    rows = [result["aggregate"] for result in results]
    flow_rows = [dict(run_id=result["aggregate"]["run_id"], **row) for result in results for row in result["flows"]]
    summaries = summarize(rows)
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "per_flow.csv", flow_rows)
    write_csv(args.out / "summary.csv", summaries)
    pareto = frontier(summaries)
    if pareto:
        write_csv(args.out / "pareto.csv", pareto)
    report(args.out / "report.html", summaries)
    print(f"Complete results written to {args.out}", flush=True)


if __name__ == "__main__":
    main()
