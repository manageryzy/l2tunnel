"""Measure the latency/throughput frontier of bounded flight windows and pacing."""

import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial
from hashlib import sha256
from importlib.metadata import version
import json
from pathlib import Path
from random import Random
from time import perf_counter

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim import __version__
from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.multiflow import MultiFlow
from l2tunnel_sim.stats import mean_ci
from payload_sizes import ObservedCompactTCP, rtt_metrics, write_csv


class LatencyObservedTCP(ObservedCompactTCP):
    """Observe enqueue delay and ordered frame delivery without altering events."""

    def __init__(self, *args, **kwargs):
        self.queue_observations = [[], []]
        self.frame_observations = []
        super().__init__(*args, **kwargs)

    def send(self, reverse, size, kind, receive):
        link = min(self.links[reverse], key=lambda item: item.finish(self.now, size) + item.rtt / 2)
        self.queue_observations[reverse].append(
            (self.now, max(0, link.free_at - self.now) * 1000, kind))
        return super().send(reverse, size, kind, receive)

    def on_data(self, *args, **kwargs):
        before = len(self.forward.delays)
        super().on_data(*args, **kwargs)
        self.frame_observations.extend((self.now, delay) for delay in self.forward.delays[before:])


def execute(task):
    started = perf_counter()
    rate = task["payload_rate_mbps"]
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"],
                      window_bytes=round(task["window_mib"] * 1048576),
                      frame_interval_ms=1448 * 8 / (rate * 1000) if rate else 0)
    factory = partial(LatencyObservedTCP, compact_config=CompactConfig(
        header_profile="tcp_delta", repair_ratio=0), reliable_acks=False,
        transport_type=CompactARQTransport)
    sim = MultiFlow(Scenario(70, .15), traffic, (PathConfig(100, 10),),
                    Strategy(task["name"], mode="tcp", tcp_cc="cubic", tcp_rto_min_ms=1000),
                    task["seed"], task.get("flow_count", 16), simulation_factory=factory)
    snapshots = {}

    def sample(when):
        snapshots[when] = (sum(flow.tcp_received for flow in sim.flows),
                           sum(sum(flow.datagrams[False].values()) for flow in sim.flows),
                           sum(sum(flow.wire[False].values()) for flow in sim.flows))

    sim.flows[0].at(task["warmup_s"], sample, task["warmup_s"])
    sim.flows[0].at(task["duration_s"], sample, task["duration_s"])
    sim.run()
    row = dict(task, **sim.measurements(), **rtt_metrics(sim, task["warmup_s"]))
    row.update(strategy=task["name"], payload_bytes=1448, rto_min_ms=1000,
               forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500,
               controller="cubic", recovery="arq", reliable_acks=False,
               transport="compact_inner_tcp_multiflow", measurement_payload_kind="modeled TCP application data")
    for name in ("tcp_timeouts", "tcp_retransmissions", "tcp_fast_retransmits"):
        row[name] = sum(getattr(flow, name) for flow in sim.flows)
    for prefix, start, end in (("", 0, task["duration_s"]),
                               ("steady_", task["warmup_s"], task["duration_s"]),
                               ("with_drain_", 0, sim.flows[0].stop_at)):
        observations = {
            "frame": [record for flow in sim.flows for record in flow.frame_observations],
        }
        for direction, label in ((False, "forward"), (True, "reverse")):
            queue = [record for flow in sim.flows for record in flow.queue_observations[direction]]
            observations[f"{label}_queue"] = [(when, value) for when, value, kind in queue]
            for packet_kind in ("source", "retry", "feedback"):
                observations[f"{label}_{packet_kind}_queue"] = [
                    (when, value) for when, value, kind in queue if kind == packet_kind]
        for metric, records in observations.items():
            values = [value for when, value in records if start <= when <= end]
            for percentile in (50, 95, 99):
                row[f"{prefix}{metric}_p{percentile}_ms"] = float(np.percentile(values, percentile)) if values else None
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    row["outer_all_confirmed"] = all(transport.base == len(transport.sources) and transport.buffer_bytes == 0
                                      and not transport.pending for flow in sim.flows
                                      for transport in (flow.compact_forward, flow.compact_reverse))
    row["flow_confirmation"] = json.dumps([
        dict(flow_id=index, offered=len(flow.sent_times), received=flow.tcp_received,
             acknowledged=flow.tcp_acked, outer_pending=len(flow.compact_forward.pending))
        for index, flow in enumerate(sim.flows, 1)])
    start, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    row["steady_delivered_frames"] = end[0] - start[0]
    row["steady_forward_datagrams"] = end[1] - start[1]
    row["steady_forward_wire_bytes"] = end[2] - start[2]
    row["application_goodput_mbps"] = row["tcp_goodput_mbps"]
    row["steady_application_goodput_mbps"] = row["steady_delivered_frames"] * 1448 * 8 / (
        (task["duration_s"] - task["warmup_s"]) * 1e6)
    row["steady_tcp_mbps"] = row["steady_application_goodput_mbps"]
    row["extra_packets_per_delivered_tcp_segment_pct"] = 100 * (
        row["forward_datagrams"] / row["tcp_delivered_frames"] - 1)
    row["steady_extra_packets_per_delivered_tcp_segment_pct"] = 100 * (
        row["steady_forward_datagrams"] / row["steady_delivered_frames"] - 1)
    confirmed = row["tcp_delivery_fraction"] == 1 and row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
    row["full_target_met"] = confirmed and row["tcp_goodput_mbps"] >= 80 and row[
        "extra_packets_per_delivered_tcp_segment_pct"] <= 20
    row["steady_target_met"] = confirmed and row["steady_tcp_mbps"] >= 80 and row[
        "steady_extra_packets_per_delivered_tcp_segment_pct"] <= 20
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_wire_bytes_during_measurement"] <= 100 * 125000 * task["duration_s"]
    return row


def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[row["name"]].append(row)
    summaries = []
    for name, records in groups.items():
        row = {key: records[0][key] for key in ("name", "window_mib", "payload_rate_mbps", "duration_s", "flow_count",
                                                "warmup_s", "drain_s", "total_window_bytes")}
        row.update(replications=len(records), confirmed_replications=sum(
            item["tcp_all_acknowledged"] and item["outer_all_confirmed"] for item in records),
            full_target_passes=sum(item["full_target_met"] for item in records),
            steady_target_passes=sum(item["steady_target_met"] for item in records))
        for key, value in records[0].items():
            if key in row or key in ("seed", "run_id", "replication") or isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                estimate = mean_ci([item[key] for item in records if item[key] is not None])
                for suffix in ("mean", "ci_low", "ci_high"):
                    row[f"{key}_{suffix}"] = estimate[suffix]
        summaries.append(row)
    return summaries


def render_report(out, rows):
    fig = make_subplots(rows=1, cols=2, subplot_titles=("Throughput and TCP timestamp RTT P99", "Throughput and extra forward packets"))
    groups = list(dict.fromkeys((row["flow_count"], row["payload_rate_mbps"]) for row in rows))
    for flows, rate in groups:
        points = sorted((row for row in rows if (row["flow_count"], row["payload_rate_mbps"]) == (flows, rate)),
                        key=lambda row: row["window_mib"])
        name = f"{flows} flows, " + (f"paced {rate:g} Mbps" if rate else "unpaced")
        for column, metric in ((1, "tcp_timestamp_rtt_p99_ms"), (2, "extra_packets_per_delivered_tcp_segment_pct")):
            fig.add_trace(go.Scatter(x=[row["tcp_goodput_mbps_mean"] for row in points],
                                     y=[row[metric + "_mean"] for row in points], mode="markers+lines+text",
                                     text=[f"{row['window_mib']:g} MiB" for row in points], textposition="top center",
                                     name=name, legendgroup=name, showlegend=column == 1,
                                     customdata=[[row["confirmed_replications"], row["replications"]] for row in points],
                                     hovertemplate="%{text}<br>%{x:.3f} Mbps<br>%{y:.3f}<br>Confirmed %{customdata[0]}/%{customdata[1]}<extra>%{fullData.name}</extra>"), row=1, col=column)
    fig.update_xaxes(title="TCP application throughput (Mbps)")
    fig.update_yaxes(title="TCP timestamp RTT P99 (ms)", row=1, col=1)
    fig.update_yaxes(title="Extra forward datagrams (%)", row=1, col=2)
    fig.add_vline(x=80, line_dash="dot", line_color="green")
    fig.add_hline(y=20, line_dash="dot", line_color="green", row=1, col=2)
    fig.update_layout(template="plotly_white", height=600, margin={"t": 60, "b": 80})
    page = """<!doctype html><html lang="en"><meta charset="utf-8"><title>TCP window and latency</title>
<style>body{font:16px/1.5 system-ui;max-width:1500px;margin:30px auto;padding:0 24px}h1{font-size:28px}</style>
<h1>TCP flight window and pacing latency study</h1>
<p>Independent inner CUBIC TCP connections share one compact selective-repeat ARQ bottleneck. Flow count is explicit in the CSV. Forward capacity is 100 Mbps and reverse capacity is 10 Mbps, charged as IP bytes. Both directions have 15% independent erasures. Base RTT is 70 ms, payload is 1448 bytes, and minimum inner TCP RTO is 1 second. The total application flight-window budget is divided across connections. Compact delta header compression and cross-frame packing are enabled. Authentication adds zero bytes in this model.</p>
""" + fig.to_html(full_html=False, include_plotlyjs=True) + """
<p>Throughput includes startup and excludes delivery during drain. TCP timestamp RTT percentiles use estimator samples during the traffic interval. The raw metrics also include SRTT, ACK completion RTT, ordered frame delays and passive forward/reverse queue-delay observations at enqueue. Frame metrics with the with_drain prefix include the drain interval. Queue observations do not alter link scheduling.</p>
<p>Extra packet percentage counts every forward datagram through drain relative to uniquely delivered TCP segments. Full target eligibility requires all data delivered, every inner TCP segment acknowledged, all outer transport sources confirmed, throughput at least 80 Mbps, and at most 20% extra packets. Steady metrics count delivered segments and datagrams in the same post-warmup interval.</p>
<p><a href="replications.csv">Replication metrics</a> · <a href="summary.csv">Means and 95% Student-t intervals</a> · <a href="experiment.json">Configurations and source hashes</a> · <a href="latency-window.png">Static figure</a></p></html>"""
    (out / "report.html").write_text(page)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    figure, axes = plt.subplots(1, 2, figsize=(13, 5), layout="constrained")
    for flows, rate in groups:
        points = sorted((row for row in rows if (row["flow_count"], row["payload_rate_mbps"]) == (flows, rate)),
                        key=lambda row: row["window_mib"])
        name = f"{flows} flows, " + (f"paced {rate:g} Mbps" if rate else "unpaced")
        for axis, metric in zip(axes, ("tcp_timestamp_rtt_p99_ms", "extra_packets_per_delivered_tcp_segment_pct")):
            xs = [row["tcp_goodput_mbps_mean"] for row in points]
            ys = [row[metric + "_mean"] for row in points]
            axis.plot(xs, ys, "o-", label=name)
            for point, x, y in zip(points, xs, ys):
                axis.annotate(f"{point['window_mib']:g} MiB", (x, y), xytext=(3, 4), textcoords="offset points", fontsize=8)
    for axis in axes:
        axis.axvline(80, linestyle=":", color="green")
        axis.set_xlabel("TCP application throughput (Mbps)")
        axis.grid(alpha=.2)
        axis.legend(fontsize=8)
    axes[0].set_ylabel("TCP timestamp RTT P99 (ms)")
    axes[1].set_ylabel("Extra forward datagrams (%)")
    axes[1].axhline(20, linestyle=":", color="green")
    first = rows[0]
    flow_label = ", ".join(str(count) for count in dict.fromkeys(row["flow_count"] for row in rows))
    figure.suptitle(f"{flow_label} TCP flows · 100/10 Mbps · 70 ms base RTT · 15% IID loss\n"
                   f"{first['duration_s']:g}s traffic + {first['drain_s']:g}s drain · {first['replications']} replication(s)")
    figure.savefig(out / "latency-window.png", dpi=170)
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--windows", nargs="+", type=float, default=(.75, 1, 1.5, 2, 4))
    parser.add_argument("--rates", nargs="+", type=float, default=(0, 81.5))
    parser.add_argument("--flows", nargs="+", type=int, default=(16,))
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--drain", type=float, default=5)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--replications", type=int, default=1)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration or min(args.windows) <= 0 or min(args.rates) < 0 or min(args.flows) < 1:
        parser.error("invalid duration, window, or rate")
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(args.replications)]
    tasks = []
    for flow_count in args.flows:
        for window in args.windows:
            for rate in args.rates:
                name = f"Compact ARQ {flow_count} flows {window:g}MiB " + (f"paced{rate:g}" if rate else "unpaced")
                for replication, seed in enumerate(seeds, 1):
                    tasks.append(dict(run_id=len(tasks) + 1, name=name, window_mib=window, payload_rate_mbps=rate,
                                      flow_count=flow_count, duration_s=args.duration, warmup_s=args.warmup,
                                      drain_s=args.drain, replication=replication, seed=seed))
    args.out.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    sources = [Path(__file__).resolve(), root / "studies/payload_sizes.py", *sorted((root / "src/l2tunnel_sim").glob("*.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in sources}
    for task in tasks:
        task["model_version"] = __version__
        task["model_source_hash"] = sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        task["profile"] = json.dumps(dict(name=task["name"], flow_count=task["flow_count"], recovery="arq", reliable_acks=False,
                                          rto_min_ms=1000, controller="cubic", payload_bytes=1448,
                                          window_bytes=round(task["window_mib"] * 1048576),
                                          payload_rate_mbps=task["payload_rate_mbps"],
                                          compact=dict(header_profile="tcp_delta", repair_ratio=0)), sort_keys=True)
    manifest = dict(tasks=tasks, sources=hashes,
                    runtime={name: version(name) for name in ("numpy", "scipy", "plotly", "aioquic")},
                    window_policy="fixed total application bytes, rounded down to full segments across connections",
                    queue_observation="delay from enqueue to serialization start, observed without event mutation")
    target = args.out / "experiment.json"
    if target.exists() and json.loads(target.read_text()) != manifest:
        raise ValueError("source or task configuration changed for this output directory")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    remaining = [task for task in tasks if not (runs / f"{task['run_id']:05d}.json").exists()]
    print(f"{len(tasks) - len(remaining)}/{len(tasks)} complete", flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(execute, task) for task in remaining]
        for future in as_completed(futures):
            row = future.result()
            path = runs / f"{row['run_id']:05d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(path)
            print(f"{row['name']} seed{row['replication']} throughput={row['tcp_goodput_mbps']:.3f} "
                  f"steady={row['steady_tcp_mbps']:.3f} RTT99={row['tcp_timestamp_rtt_p99_ms']:.1f} "
                  f"extra={row['extra_packets_per_delivered_tcp_segment_pct']:.3f}% confirmed="
                  f"{row['tcp_all_acknowledged'] and row['outer_all_confirmed']}", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in tasks]
    summary = summarize(rows)
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summary)
    render_report(args.out, summary)
    print(f"Complete at {args.out}", flush=True)


if __name__ == "__main__":
    main()
