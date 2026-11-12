"""Reproducible compact-codec fixed-window ceiling study at 15% erasure."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from statistics import mean
import time

import numpy as np
import plotly.graph_objects as go
from scipy.stats import t

from l2tunnel_sim.compact import CompactConfig, CompactSimulation
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic


class ObservedCompact(CompactSimulation):
    def __init__(self, *args):
        self.arrivals = []
        super().__init__(*args)

    def on_data(self, index):
        before = self.tcp_received
        super().on_data(index)
        if self.tcp_received > before:
            self.arrivals.append((self.now, self.tcp_received - before))


def execute(task):
    config = CompactConfig(**task["config"])
    path = PathConfig(**task["path"])
    duration, warmup = task["duration_s"], task["warmup_s"]
    # Typical full-size frame is 1448 payload bytes plus 7--8 delta-header bytes.
    # Use 1456 conservatively for offered-load pacing. All sent bytes are counted
    # from the actual serialized header codec, including context and tail flush.
    symbol = 1500 - config.outer_header_bytes - config.authentication_bytes - 4
    source_size = symbol + config.outer_header_bytes + config.authentication_bytes
    interval = (1456 / (symbol - 2)
                * (source_size + config.repair_ratio * 1500)
                / (path.forward_mbps * 125 * 0.999))
    traffic = Traffic(duration_s=duration, drain_s=task["drain_s"],
                      window_bytes=16 * 1024 * 1024, frame_interval_ms=interval)
    scenario = Scenario(task["rtt_ms"], 0.15, task["loss_model"])
    started = time.monotonic()
    sim = ObservedCompact(scenario, traffic, (path,), Strategy("Compact GF256"),
                          task["seed"], config).run()
    delivered = sim.tcp_received
    packets = sum(sim.datagrams[False].values())
    wire = sum(sim.wire[False].values())
    steady = sum(count for when, count in sim.arrivals if warmup < when <= duration)
    result = {**task, "model": "fixed_window_payload", "coding": config.coding,
              "runtime_s": time.monotonic() - started,
              "offered_frames": len(sim.sent_times), "delivered_frames": delivered,
              "delivery_fraction": delivered / len(sim.sent_times),
              "goodput_mbps": sim.tcp_payload_bytes * 8 / duration / 1e6,
              "steady_goodput_mbps": steady * traffic.payload_bytes * 8 / (duration - warmup) / 1e6,
              "payload_capacity_pct": sim.tcp_payload_bytes * 8 / duration / 1e6 / path.forward_mbps * 100,
              "native_packet_extra_pct": (packets / delivered - 1) * 100,
              "source_packet_extra_pct": (packets / sim.datagrams[False]["source"] - 1) * 100,
              "forward_source_packets": sim.datagrams[False]["source"],
              "forward_repair_packets": sim.datagrams[False]["repair"],
              "forward_feedback_packets": sim.datagrams[False]["feedback"],
              "forward_packets": packets, "forward_wire_bytes": wire,
              "reverse_packets": sum(sim.datagrams[True].values()),
              "reverse_wire_bytes": sum(sim.wire[True].values()),
              "payload_wire_efficiency_pct": delivered * traffic.payload_bytes / wire * 100,
              "l2_extra_wire_pct": (wire / (delivered * traffic.frame_bytes) - 1) * 100,
              "frame_p99_ms": float(np.quantile(sim.forward.delays, 0.99)),
              "frame_p50_ms": float(np.quantile(sim.forward.delays, 0.50)),
              "scheduled_repairs": sim.forward.scheduled_repairs,
              "tail_repairs": sim.forward.tail_repairs,
              "compressed_record_header_bytes": sim.forward.source_record_bytes - len(sim.sent_times) * 1448,
              "context_bytes": sim.forward.profile_context_bytes,
              "unconfirmed_sources": len(sim.forward.pending)}
    result["meets_full_run_target"] = (result["goodput_mbps"] >= 80
                                        and result["native_packet_extra_pct"] <= 20
                                        and result["delivery_fraction"] == 1)
    result["meets_steady_target"] = (result["steady_goodput_mbps"] >= 80
                                      and result["native_packet_extra_pct"] <= 20
                                      and result["delivery_fraction"] == 1)
    assert sum(sim.datagrams[False].values()) == packets
    assert sim.forward.delivered_bytes == delivered * traffic.frame_bytes
    assert delivered <= len(sim.sent_times)
    return result


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    metrics = ("goodput_mbps", "steady_goodput_mbps", "native_packet_extra_pct",
               "source_packet_extra_pct", "payload_wire_efficiency_pct", "l2_extra_wire_pct",
               "frame_p99_ms", "forward_packets", "forward_source_packets", "forward_repair_packets",
               "forward_feedback_packets", "tail_repairs")
    summaries = []
    for rtt, model in sorted({(row["rtt_ms"], row["loss_model"]) for row in rows}):
        group = [row for row in rows if row["rtt_ms"] == rtt and row["loss_model"] == model]
        row = {"rtt_ms": rtt, "loss_model": model, "replications": len(group),
               "minimum_delivery_fraction": min(item["delivery_fraction"] for item in group),
               "maximum_native_packet_extra_pct": max(item["native_packet_extra_pct"] for item in group),
               "full_target_passes": sum(item["meets_full_run_target"] for item in group),
               "steady_target_passes": sum(item["meets_steady_target"] for item in group)}
        for metric in metrics:
            values = [item[metric] for item in group]
            center = mean(values)
            half = (float(t.ppf(0.975, len(values) - 1) * np.std(values, ddof=1) / np.sqrt(len(values)))
                    if len(values) > 1 else 0)
            row[metric] = center
            row[metric + "_ci_low"] = center - half
            row[metric + "_ci_high"] = center + half
        summaries.append(row)
    return summaries


def write_report(out, rows, summaries, manifest):
    figure = go.Figure()
    colors = {20: "#246bce", 70: "#d06725", 150: "#7653b9"}
    for metric, label in (("goodput_mbps", "Full measurement"),
                          ("steady_goodput_mbps", "After warmup")):
        for model, symbol in (("iid", "circle"), ("burst", "diamond")):
            group = [row for row in summaries if row["loss_model"] == model]
            figure.add_trace(go.Scatter(
                x=[row["native_packet_extra_pct"] for row in group],
                y=[row[metric] for row in group], mode="markers+text",
                text=[f'{row["rtt_ms"]} ms' for row in group], textposition="top center",
                marker=dict(color=[colors[row["rtt_ms"]] for row in group], size=12,
                            symbol=symbol if metric == "goodput_mbps" else symbol + "-open"),
                error_x=dict(type="data", array=[row["native_packet_extra_pct_ci_high"]
                                                 - row["native_packet_extra_pct"] for row in group]),
                error_y=dict(type="data", array=[row[metric + "_ci_high"] - row[metric] for row in group]),
                customdata=[[row["minimum_delivery_fraction"], row["frame_p99_ms"],
                             row["full_target_passes"], row["steady_target_passes"]] for row in group],
                name=f"{label}, {model}",
                hovertemplate=("Extra forward packets %{x:.3f}%<br>TCP payload %{y:.3f} Mbps"
                               "<br>Minimum delivery %{customdata[0]:.3%}"
                               "<br>Mean P99 %{customdata[1]:.1f} ms"
                               "<br>Full target passes %{customdata[2]}/5"
                               "<br>Post-warmup target passes %{customdata[3]}/5<extra>%{fullData.name}</extra>")))
    figure.add_vline(x=20, line_dash="dash", line_color="#555")
    figure.add_hline(y=80, line_dash="dash", line_color="#555")
    figure.update_layout(title="Compact GF256 coding at 15% packet erasure",
                         xaxis_title="Extra forward datagrams per unique delivered TCP segment (%)",
                         yaxis_title="TCP payload throughput on a 100 Mbps forward link (Mbps)",
                         template="plotly_white", height=720,
                         legend=dict(orientation="h", y=-0.18), margin=dict(b=140))
    first = rows[0]
    description = (
        "<h1>Compact coding goal study</h1>"
        f'<p>{len(rows)} runs, {first["duration_s"]:g} seconds of offered load, '
        f'{first["drain_s"]:g} seconds of drain. Open markers exclude the first '
        f'{first["warmup_s"]:g} seconds. Error bars show Student-t 95% intervals across five seeds.</p>'
        "<p>This is a fixed-window payload model. Full inner TCP congestion control is evaluated "
        "separately. The post-warmup interval can include data queued before its start. "
        "A short post-warmup result does not establish a stationary transfer rate.</p>"
        "<p>All source, repair, and control datagrams transmitted forward are counted against "
        "unique delivered TCP segments. Packet costs cover the full run and drain. The reliable "
        "reverse ACK stream uses the independent 10 Mbps reverse link and creates additional "
        "forward feedback packets. Every run delivered all offered frames.</p>"
        "<p>The packet model uses actual GF(256) coefficient rank. It packs byte records across "
        "frame boundaries. An executable reversible header codec determines each compressed "
        "record's length from its serialized Ethernet/IPv4/TCP frame. Payload bytes are unchanged. "
        "The compression context is sent within the same reliable ordered stream.</p>"
        "<p>The bulk data profile uses one 69-byte context, then a three-byte record prefix, "
        "one-byte field mask, and variable-length modular differences for changed header fields. "
        "The source outer header is 36 bytes, the repair header is 40 bytes, and each coded symbol "
        "contains a two-byte valid-length field. Outer IP packets remain within 1500 bytes and "
        "reconstructed Ethernet frames remain 1514 bytes.</p>"
        "<p>Authentication tags and coding CPU cost are excluded. The custom header codec supports "
        "the tested IPv4/TCP timestamp profile. It is an experimental implementation inspired "
        "by header compression and elastic coding concepts. Relevant primary specifications "
        'include <a href="https://www.rfc-editor.org/rfc/rfc6846.html">RFC 6846</a>, '
        '<a href="https://www.rfc-editor.org/rfc/rfc9407.html">RFC 9407</a>, and '
        '<a href="https://www.rfc-editor.org/rfc/rfc8681.html">RFC 8681</a>.</p>'
    )
    table = "<table><thead><tr><th>RTT ms</th><th>Loss</th><th>Full Mbps</th><th>Post-warmup Mbps</th><th>Extra packets %</th><th>P99 ms</th><th>Full passes</th><th>Post-warmup passes</th></tr></thead><tbody>"
    for row in summaries:
        table += (f'<tr><td>{row["rtt_ms"]}</td><td>{row["loss_model"]}</td>'
                  f'<td>{row["goodput_mbps"]:.3f}</td><td>{row["steady_goodput_mbps"]:.3f}</td>'
                  f'<td>{row["native_packet_extra_pct"]:.3f}</td><td>{row["frame_p99_ms"]:.1f}</td>'
                  f'<td>{row["full_target_passes"]}/5</td><td>{row["steady_target_passes"]}/5</td></tr>')
    table += "</tbody></table>"
    html = ("<!doctype html><html><head><meta charset='utf-8'><title>Compact coding goal study</title>"
            "<style>body{font:16px system-ui;margin:32px;max-width:1250px}p{line-height:1.5}"
            "table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:8px;text-align:right}"
            "th{background:#f4f6f8}</style></head><body>" + description
            + figure.to_html(full_html=False, include_plotlyjs=True) + table + "</body></html>")
    (out / "report.html").write_text(html)
    (out / "sources.json").write_text(json.dumps([
        {"title": "ROHC TCP/IP profile", "url": "https://www.rfc-editor.org/rfc/rfc6846.html"},
        {"title": "Experimental Tetrys elastic coding", "url": "https://www.rfc-editor.org/rfc/rfc9407.html"},
        {"title": "Sliding-window GF256 RLC", "url": "https://www.rfc-editor.org/rfc/rfc8681.html"},
    ], indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--replications", type=int, default=5)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--drain", type=float, default=5)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--ratio", type=float, default=0.195)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than measurement duration")
    args.out.mkdir(parents=True, exist_ok=True)
    run_dir = args.out / "runs"
    run_dir.mkdir(exist_ok=True)
    config = CompactConfig(repair_ratio=args.ratio, header_profile="tcp_delta")
    tasks = [dict(index=index, rtt_ms=rtt, loss_model=model, replication=replication,
                  seed=20261110 + replication * 1009, duration_s=args.duration,
                  drain_s=args.drain, warmup_s=args.warmup, config=asdict(config), path=asdict(PathConfig()))
             for index, (rtt, model, replication) in enumerate(
                 (rtt, model, replication) for rtt in (20, 70, 150)
                 for model in ("iid", "burst") for replication in range(args.replications))]
    manifest = {"tasks": tasks, "source_sha256": sha256(
        (Path(__file__).parents[1] / "src/l2tunnel_sim/compact.py").read_bytes()).hexdigest(),
        "assumptions": ["IPv4 UDP outer MTU 1500", "complete Ethernet frames 1514 bytes",
                        "TCP payload 1448 bytes", "actual reversible delta-header serialization",
                        "fixed 16 MiB flow window", "both directions use independent 15% erasures",
                        "no congestion controller", "no authentication tag", "coding CPU excluded",
                        "actual GF256 rank decoder",
                        "native packet denominator counts uniquely delivered application segments",
                        "steady throughput excludes configured warmup, packet counts cover full run and drain"]}
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise SystemExit("existing manifest differs, select a fresh output directory")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    pending = [task for task in tasks if not (run_dir / f'{task["index"]:04}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(execute, task): task for task in pending}
        for future in as_completed(futures):
            result = future.result()
            path = run_dir / f'{result["index"]:04}.json'
            temp = path.with_suffix(".tmp")
            temp.write_text(json.dumps(result, indent=2) + "\n")
            temp.replace(path)
            print(f'Completed {result["index"] + 1}/{len(tasks)} '
                  f'{result["loss_model"]} RTT {result["rtt_ms"]} ms '
                  f'{result["goodput_mbps"]:.3f} Mbps '
                  f'{result["native_packet_extra_pct"]:.3f}% extra packets', flush=True)
    rows = [json.loads(path.read_text()) for path in sorted(run_dir.glob("*.json"))]
    write_csv(args.out / "replications.csv", [{key: value for key, value in row.items()
                                               if key not in ("config", "path")} for row in rows])
    summaries = summarize(rows)
    write_csv(args.out / "summary.csv", summaries)
    write_report(args.out, rows, summaries, manifest)
    print(json.dumps({"completed": len(rows), "out": str(args.out)}), flush=True)


if __name__ == "__main__":
    main()
