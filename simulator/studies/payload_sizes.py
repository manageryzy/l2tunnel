"""Measure application throughput and protocol RTT across TCP payload sizes."""

import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from dataclasses import asdict
from functools import partial
from hashlib import sha256
from html import escape
from importlib.metadata import version
import json
from pathlib import Path
from random import Random
from time import perf_counter

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim.compact import CompactConfig
from l2tunnel_sim.compact_arq import CompactARQTransport
from l2tunnel_sim.compact_block import CompactBlockConfig, CompactBlockTransport
from l2tunnel_sim.compact_tcp import CompactTCP
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.experiment import measure
from l2tunnel_sim.multiflow import MultiFlow
from l2tunnel_sim.stats import mean_ci
from l2tunnel_sim.tcp import PlainTCP


SIZES = (64, 256, 512, 1024, 1448)
PERCENTILES = (50, 95, 99)
RTT_STEMS = {"tcp_ack": "tcp_ack_rtt", "tcp_timestamp": "tcp_timestamp_rtt",
             "tcp_srtt": "tcp_srtt", "quic_latest": "quic_latest_rtt"}


class TCPRTTObserver:
    def __init__(self, *args, **kwargs):
        self.ack_rtt_observations = []
        self.timestamp_rtt_observations = []
        super().__init__(*args, **kwargs)

    def on_ack(self, *args, **kwargs):
        before = len(self.tcp_rtts)
        super().on_ack(*args, **kwargs)
        self.ack_rtt_observations.extend((self.now, rtt) for rtt in self.tcp_rtts[before:])

    def update_rtt(self, sample):
        super().update_rtt(sample)
        self.timestamp_rtt_observations.append((self.now, sample * 1000, self.srtt * 1000))


class ObservedTCP(TCPRTTObserver, PlainTCP):
    pass


class ObservedCompactTCP(TCPRTTObserver, CompactTCP):
    pass


def _load_quic():
    """Import the optional maintained QUIC adapter only for QUIC consumers."""
    if "ObservedQUIC" in globals():
        return
    from l2tunnel_sim.quic import PacketLogger, PacketTrace, QUIC

    class RTTTrace(PacketTrace):
        def __init__(self, simulation, **kwargs):
            super().__init__(**kwargs)
            self.simulation = simulation
            self.rtt_observations = []

        def log_event(self, *, category, event, data):
            super().log_event(category=category, event=event, data=data)
            if (category == "recovery" and event == "metrics_updated" and "latest_rtt" in data
                    and not getattr(self.simulation, "warming_up", True)):
                # aioquic emits RTT keys only when ACK processing produces a new
                # sample. qlog encodes seconds as milliseconds in these fields.
                self.rtt_observations.append((self.simulation.now, data["latest_rtt"], data["smoothed_rtt"]))


    class RTTLogger(PacketLogger):
        def __init__(self, simulation):
            super().__init__()
            self.simulation = simulation

        def start_trace(self, is_client, odcid):
            self.trace = RTTTrace(self.simulation, is_client=is_client, odcid=odcid)
            return self.trace


    class ObservedQUIC(QUIC):
        def configuration(self, reverse):
            self.loggers[reverse] = RTTLogger(self)
            return super().configuration(reverse)

    for name, value in (("RTTTrace", RTTTrace), ("RTTLogger", RTTLogger),
                        ("ObservedQUIC", ObservedQUIC)):
        value.__qualname__ = name
        globals()[name] = value
    globals()["QUIC"] = QUIC


def __getattr__(name):
    if name in {"RTTTrace", "RTTLogger", "ObservedQUIC", "QUIC"}:
        _load_quic()
        return globals()[name]
    raise AttributeError(name)


def default_profiles():
    return [
        dict(name="Plain TCP CUBIC", kind="tcp", controller="cubic"),
        dict(name="QUIC L2 CUBIC", kind="quic", controller="cubic"),
        dict(name="Compact ARQ native ACK RTO1s", compact={"header_profile": "tcp_delta", "repair_ratio": 0},
             recovery="arq", reliable_acks=False, controller="cubic", rto_min_ms=1000),
        dict(name="Compact RLNC19 native ACK RTO1s", compact={"header_profile": "tcp_delta", "repair_ratio": .19},
             recovery="rlnc", reliable_acks=False, controller="cubic", rto_min_ms=1000),
    ]


def make_simulation(task):
    profile = task["profile"]
    kind = profile.get("kind", "compact" if profile.get("compact") is not None else "tcp")
    rate = profile.get("payload_rate_mbps")
    if profile.get("payload_rate_capacity_pct") is not None:
        if rate is not None:
            raise ValueError("choose either absolute or capacity-relative payload pacing")
        rate = task["forward_mbps"] * profile["payload_rate_capacity_pct"] / 100
    payload = task["payload_bytes"]
    traffic = Traffic(duration_s=task["duration_s"], drain_s=task["drain_s"],
                      frame_bytes=payload + 66, payload_bytes=payload,
                      window_bytes=profile.get("window_bytes", 4 * 1048576),
                      frame_interval_ms=payload * 8 / (rate * 1000) if rate else 0)
    scenario = Scenario(task["rtt_ms"], task["loss_rate"], task["loss_model"])
    strategy = Strategy(profile["name"], mode="quic" if kind == "quic" else "tcp",
                        tcp_cc=profile.get("controller", "cubic"), tcp_rto_min_ms=profile.get("rto_min_ms", 200))
    args = (scenario, traffic, (PathConfig(task["forward_mbps"], task["reverse_mbps"]),), strategy, task["seed"])
    if kind == "quic":
        _load_quic()
        factory = ObservedQUIC
    elif kind == "tcp":
        factory = ObservedTCP
    elif kind == "compact":
        recovery = profile.get("recovery", "rlnc")
        config_type = CompactBlockConfig if recovery == "block" else CompactConfig
        config = config_type(**profile["compact"])
        options = {}
        if recovery == "arq":
            options["transport_type"] = CompactARQTransport
        elif recovery == "block":
            options["transport_type"] = CompactBlockTransport
        elif recovery != "rlnc":
            raise ValueError("unknown compact recovery profile")
        factory = partial(ObservedCompactTCP, compact_config=config,
                          reliable_acks=profile.get("reliable_acks", True), **options)
    else:
        raise ValueError("unknown payload-study transport")
    count = profile.get("flow_count", 1)
    return MultiFlow(*args, count, simulation_factory=factory) if count > 1 else factory(*args)


def quantiles(values):
    return np.percentile(values, PERCENTILES).tolist() if values else [None] * len(PERCENTILES)


def _is_quic(flow):
    # An actual QUIC instance necessarily loaded its adapter already.
    import sys
    adapter = sys.modules.get("l2tunnel_sim.quic")
    return adapter is not None and isinstance(flow, adapter.QUIC)


def rtt_metrics(sim, warmup):
    flows = sim.flows if isinstance(sim, MultiFlow) else [sim]
    is_quic = _is_quic(flows[0])
    tcp = [sample for flow in flows for sample in getattr(flow, "ack_rtt_observations", [])]
    timestamp = [sample for flow in flows for sample in getattr(flow, "timestamp_rtt_observations", [])]
    smoothed = [(record[0], record[2]) for record in timestamp]
    quic = [sample for flow in flows for sample in flow.loggers[False].trace.rtt_observations] if is_quic else []
    row = {}
    for label, start, end in (("", 0, sim.traffic.duration_s),
                              ("steady_", warmup, sim.traffic.duration_s),
                              ("with_drain_", 0, sim.traffic.duration_s + sim.traffic.drain_s)):
        for protocol, records in (("tcp_ack", tcp), ("tcp_timestamp", timestamp),
                                  ("tcp_srtt", smoothed), ("quic_latest", quic)):
            samples = [record[1] for record in records if start <= record[0] <= end]
            stem = label + RTT_STEMS[protocol]
            row[stem + "_samples"] = len(samples)
            for percentile, value in zip(PERCENTILES, quantiles(samples)):
                row[f"{stem}_p{percentile}_ms"] = value
    row["rtt_protocol"] = "quic" if is_quic else "tcp"
    row["rtt_definition"] = ("aioquic qlog latest_rtt, ACK-delay adjusted"
                             if is_quic
                             else "TCP timestamp RTT estimator sample")
    row["tcp_ack_rtt_definition"] = "TCP ACK completion RTT from original segment submission, including retransmission waiting"
    final_srtt, measured_srtt, final_quic = [], [], []
    for flow in flows:
        records = getattr(flow, "timestamp_rtt_observations", [])
        if records:
            final_srtt.append(records[-1][2])
        measured = [record[2] for record in records if record[0] <= sim.traffic.duration_s]
        if measured:
            measured_srtt.append(measured[-1])
        if is_quic and flow.loggers[False].trace.rtt_observations:
            final_quic.append(flow.loggers[False].trace.rtt_observations[-1][2])
    row["tcp_srtt_final_ms"] = float(np.mean(final_srtt)) if final_srtt else None
    row["tcp_srtt_at_measurement_end_ms"] = float(np.mean(measured_srtt)) if measured_srtt else None
    row["quic_smoothed_rtt_final_ms"] = float(np.mean(final_quic)) if final_quic else None
    row["rtt_flow_aggregation"] = "RTT samples pooled across flows; terminal SRTT is the mean of per-flow final estimates"
    return row


def execute(task):
    started = perf_counter()
    sim = make_simulation(task)
    flows = sim.flows if isinstance(sim, MultiFlow) else [sim]
    snapshots = {}

    def sample(time):
        snapshots[time] = (sum(flow.tcp_received for flow in flows),
                           sum(sum(flow.datagrams[False].values()) for flow in flows),
                           sum(sum(flow.wire[False].values()) for flow in flows))

    flows[0].at(task["warmup_s"], sample, task["warmup_s"])
    flows[0].at(task["duration_s"], sample, task["duration_s"])
    sim.run()
    row = {key: value for key, value in task.items() if key != "profile"}
    row.update(profile=json.dumps(task["profile"], sort_keys=True), strategy=task["profile"]["name"],
               **(sim.measurements() if isinstance(sim, MultiFlow) else measure(sim)),
               **rtt_metrics(sim, task["warmup_s"]))
    row["flow_count"] = len(flows)
    row["total_window_bytes"] = sum(flow.traffic.window_bytes for flow in flows)
    for name in ("tcp_timeouts", "tcp_retransmissions", "tcp_fast_retransmits"):
        row[name] = sum(getattr(flow, name) for flow in flows) if not _is_quic(flows[0]) else None
    start, end = snapshots[task["warmup_s"]], snapshots[task["duration_s"]]
    steady_frames = end[0] - start[0]
    row["application_goodput_mbps"] = row["tcp_goodput_mbps"]
    row["application_capacity_pct"] = 100 * row["application_goodput_mbps"] / task["forward_mbps"]
    row["steady_application_goodput_mbps"] = 8 * steady_frames * task["payload_bytes"] / (
        (task["duration_s"] - task["warmup_s"]) * 1e6)
    row["steady_application_capacity_pct"] = 100 * row["steady_application_goodput_mbps"] / task["forward_mbps"]
    row["steady_forward_datagrams"] = end[1] - start[1]
    row["steady_delivered_frames"] = steady_frames
    row["extra_packets_per_delivered_record_pct"] = (100 * (row["forward_datagrams"] / row["tcp_delivered_frames"] - 1)
                                                      if row["tcp_delivered_frames"] else None)
    row["steady_extra_packets_per_delivered_record_pct"] = (100 * ((end[1] - start[1]) / steady_frames - 1)
                                                             if steady_frames else None)
    row["tcp_all_acknowledged"] = all(flow.tcp_acked == len(flow.sent_times) for flow in flows)
    row["outer_all_confirmed"] = True
    if isinstance(flows[0], CompactTCP):
        row["outer_all_confirmed"] = all(transport.base == len(transport.sources) and transport.buffer_bytes == 0
                                           and not transport.pending
                                           for flow in flows for transport in (flow.compact_forward, flow.compact_reverse))
        row["transport"] = "compact_inner_tcp"
    row["flow_confirmation"] = json.dumps([
        dict(flow_id=index, offered=len(flow.sent_times), received=flow.tcp_received, acknowledged=flow.tcp_acked,
             final_srtt_ms=flow.srtt * 1000 if getattr(flow, "srtt", None) is not None else None)
        for index, flow in enumerate(flows, 1)])
    row["measurement_payload_kind"] = "QUIC L2 record payload equivalent" if _is_quic(flows[0]) else "modeled TCP application data"
    row["compute_seconds"] = perf_counter() - started
    assert row["tcp_acked_frames"] <= row["tcp_delivered_frames"] <= row["offered_frames"]
    assert row["forward_l2_bytes"] == row["released_frames"] * (task["payload_bytes"] + 66)
    if isinstance(sim, MultiFlow):
        assert row["forward_wire_bytes_during_measurement"] <= task["forward_mbps"] * 125000 * task["duration_s"]
        assert row["reverse_wire_bytes_during_measurement"] <= task["reverse_mbps"] * 125000 * task["duration_s"]
    return row


def tasks(profiles, *, duration, warmup, drain, replications, pilot=False, bandwidths=False):
    conditions = [(100, 70)] if pilot else ([(10, 70), (1000, 70)] if bandwidths else [(100, 20), (100, 70), (100, 150)])
    rng = Random(20261110)
    seeds = [rng.getrandbits(64) for _ in range(replications)]
    result = []
    for bandwidth, rtt in conditions:
        for profile in profiles:
            for payload in SIZES:
                for replication, seed in enumerate(seeds, 1):
                    result.append(dict(run_id=len(result) + 1, profile=profile, forward_mbps=bandwidth,
                                       reverse_mbps=10, rtt_ms=rtt, loss_rate=.15, loss_model="iid",
                                       payload_bytes=payload, duration_s=duration, warmup_s=warmup, drain_s=drain,
                                       replication=replication, seed=seed))
    return result


METRICS = ("application_goodput_mbps", "application_capacity_pct", "steady_application_goodput_mbps",
           "steady_application_capacity_pct", "frame_p99_ms", "tcp_delivery_fraction",
           "extra_packets_per_delivered_record_pct", "steady_extra_packets_per_delivered_record_pct",
           "tcp_timeouts", "tcp_retransmissions",
           *(f"{prefix}{RTT_STEMS[protocol]}_p{percentile}_ms" for prefix in ("", "steady_", "with_drain_")
             for protocol in ("tcp_ack", "tcp_timestamp", "tcp_srtt", "quic_latest") for percentile in PERCENTILES),
           "tcp_srtt_final_ms", "tcp_srtt_at_measurement_end_ms")


def summarize(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["forward_mbps"], row["rtt_ms"], row["strategy"], row["payload_bytes"])].append(row)
    result = []
    for records in grouped.values():
        summary = {key: records[0][key] for key in ("forward_mbps", "reverse_mbps", "rtt_ms", "loss_rate", "loss_model",
                                                   "strategy", "payload_bytes", "duration_s", "warmup_s", "drain_s",
                                                   "rtt_protocol", "rtt_definition", "measurement_payload_kind",
                                                   "flow_count", "total_window_bytes")}
        for metric in METRICS:
            for key, value in mean_ci([row[metric] for row in records if row[metric] is not None]).items():
                if key != "method":
                    summary[metric + "_" + key] = value
        summary["replications"] = len(records)
        summary["confirmed_replications"] = sum(row["tcp_all_acknowledged"] and row["outer_all_confirmed"] for row in records)
        summary["min_delivery_fraction"] = min(row["tcp_delivery_fraction"] for row in records)
        result.append(summary)
    return result


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def report(out, rows):
    fig = make_subplots(rows=2, cols=2, subplot_titles=("Application throughput", "TCP RTT / SRTT metric from selector",
                                                     "Frame delivery P99", "QUIC qlog RTT"))
    spans = []
    conditions = list(dict.fromkeys((row["forward_mbps"], row["rtt_ms"]) for row in rows))
    selections = [(condition, metric, label) for condition in conditions for metric, label in (
        ("tcp_timestamp", "TCP timestamp RTT"), ("tcp_srtt", "TCP SRTT"), ("tcp_ack", "TCP ACK completion RTT"))]
    for condition, tcp_metric, tcp_label in selections:
        selected = [row for row in rows if (row["forward_mbps"], row["rtt_ms"]) == condition]
        start = len(fig.data)
        for strategy in dict.fromkeys(row["strategy"] for row in selected):
            points = sorted((row for row in selected if row["strategy"] == strategy), key=lambda row: row["payload_bytes"])
            panels = [("application_goodput_mbps", 1, 1, ""), ("frame_p99_ms", 2, 1, "")]
            for protocol, row, col in ((tcp_metric, 1, 2), ("quic_latest", 2, 2)):
                if points[0]["rtt_protocol"] == ("quic" if protocol == "quic_latest" else "tcp"):
                    panels.extend((f"{RTT_STEMS[protocol]}_p{p}_ms", row, col, f" P{p}") for p in PERCENTILES)
            for metric, row, col, suffix in panels:
                fig.add_trace(go.Scatter(
                    x=[point["payload_bytes"] for point in points], y=[point[metric + "_mean"] for point in points],
                    name=strategy + suffix, legendgroup=strategy + suffix, showlegend=(row, col) != (2, 1),
                    mode="lines+markers", visible=not spans,
                    line={"dash": "dot" if suffix == " P95" else "dash" if suffix == " P99" else "solid"},
                    error_y={"array": [point[metric + "_ci_high"] - point[metric + "_mean"]
                                       if point[metric + "_ci_high"] is not None else None for point in points]},
                    customdata=[[point["min_delivery_fraction"], point["replications"]] for point in points],
                    hovertemplate="Payload %{x} B<br>%{y:.4g}<br>Minimum delivery %{customdata[0]:.2%}<br>Replications %{customdata[1]}<extra>%{fullData.name}</extra>",
                ), row=row, col=col)
        spans.append((start, len(fig.data), f"{condition[0]:g}/10 Mbps · RTT {condition[1]:g} ms · 15% IID · {tcp_label}"))
    fig.update_xaxes(title="TCP/application payload per record (bytes)", tickvals=list(SIZES))
    fig.update_yaxes(title="Mbps", row=1, col=1)
    for row, col in ((1, 2), (2, 1), (2, 2)):
        fig.update_yaxes(title="ms", row=row, col=col)
    fig.update_layout(template="plotly_white", height=1000, margin={"t": 135, "b": 200},
                      legend={"orientation": "h", "y": -.2}, updatemenus=[{"x": 0, "y": 1.13, "buttons": [
                          {"label": label, "method": "update", "args": [
                              {"visible": [start <= index < end for index in range(len(fig.data))]}]}
                          for start, end, label in spans]}])
    page = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Payload size, throughput and protocol RTT</title><style>body{font:16px/1.5 system-ui;color:#243447;max-width:1450px;margin:30px auto;padding:0 24px}a{color:#1764ab}h1{font-size:28px}</style>
<h1>Payload size, throughput and protocol RTT</h1>
<p>Each frame contains its configured 64, 256, 512, 1024, or 1448 application bytes plus 66 Ethernet/IPv4/TCP header bytes. Every profile shares a total 4 MiB application flight-window budget across its connections. All connections share the physical directional queues and loss processes. IP MTU is 1500 bytes and reverse capacity is 10 Mbps. Forward and reverse packets independently experience 15% erasures.</p>
""" + fig.to_html(full_html=False, include_plotlyjs=True, div_id="payload-size-study") + """
<p>Throughput counts delivered application bytes during the traffic interval and excludes drain delivery. RTT percentiles in these plots use protocol samples observed during that same interval. Error bars show 95% Student-t intervals across replication statistics. Frame P99 includes all delivered frames through drain and is separate from RTT.</p>
<p>The selector switches the TCP panel among timestamp RTT samples, the smoothed RTT estimator (SRTT), and ACK completion RTT. Timestamp samples are the actual values passed to the TCP estimator after timestamp echo processing. SRTT records the estimator after each update. ACK completion RTT measures arrival of a new cumulative ACK relative to the original submission of its latest acknowledged segment and includes retransmission waiting. It is a distinct metric from timestamp RTT and SRTT.</p>
<p>QUIC RTT comes from aioquic recovery qlog latest_rtt after its ACK-delay adjustment, with the isolated TLS warmup excluded. The installed aioquic implementation includes RTT keys in metrics_updated only for newly generated RTT samples. QUIC has no inner TCP RTT metric here, so its TCP RTT columns are empty. Its application throughput is the payload-equivalent content of complete L2 records carried over one reliable QUIC stream.</p>
<p>TCP uses modeled CUBIC/NewReno. Compact recovery variants share the same lossy links and TCP state machine. GF256 checks coefficient rank without coded-payload or CPU-cost execution. The actual packet and coding overhead varies with payload size. Packet counts can be below one outer datagram per small application record because records are packed together.</p>
<p>CSV exports also contain post-warmup and drain-inclusive RTT P50/P95/P99, SRTT percentiles and final values, application throughput, TCP retransmissions/timeouts, minimum delivery, and terminal confirmation counts. Multi-flow RTT percentiles pool actual ACK samples from the independent TCP states. Final SRTT is the arithmetic mean of each connection's final estimate.</p>
<p><a href="payload-overview.png">Exportable throughput and RTT figure</a> · <a href="replications.csv">Raw replication metrics</a> · <a href="summary.csv">Means and 95% intervals</a> · <a href="experiment.json">Configurations, runtime and source hashes</a></p></html>"""
    (out / "payload-report.html").write_text(page)
    static_report(out / "payload-overview.png", rows)


def static_report(path, rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    conditions = list(dict.fromkeys((row["forward_mbps"], row["rtt_ms"]) for row in rows))
    names = list(dict.fromkeys(row["strategy"] for row in rows))
    colors = {name: plt.get_cmap("tab10")(index) for index, name in enumerate(names)}
    fig, axes = plt.subplots(len(conditions), 3, figsize=(18, 4.5 * len(conditions)),
                             squeeze=False, layout="constrained")
    for index, condition in enumerate(conditions):
        selected = [row for row in rows if (row["forward_mbps"], row["rtt_ms"]) == condition]
        for name in names:
            points = sorted((row for row in selected if row["strategy"] == name), key=lambda row: row["payload_bytes"])
            if not points:
                continue
            metrics = [("application_goodput_mbps", 0, "", "-")]
            protocol, column = ("tcp_timestamp", 1) if points[0]["rtt_protocol"] == "tcp" else ("quic_latest", 2)
            metrics.extend((f"{RTT_STEMS[protocol]}_p{p}_ms", column, f" P{p}", dash) for p, dash in ((50, "-"), (99, "--")))
            for metric, column, suffix, dash in metrics:
                observed = [point for point in points if point[metric + "_mean"] is not None]
                axes[index][column].errorbar(
                    [point["payload_bytes"] for point in observed], [point[metric + "_mean"] for point in observed],
                    yerr=[point[metric + "_ci_high"] - point[metric + "_mean"] if point[metric + "_ci_high"] is not None else 0
                          for point in observed], color=colors[name], marker="o", linestyle=dash,
                    markersize=4, capsize=2, label=name + suffix)
        for column, title, unit in ((0, "Application throughput", "Mbps"), (1, "TCP timestamp RTT", "ms"), (2, "QUIC qlog latest RTT", "ms")):
            axis = axes[index][column]
            axis.set(title=f"{title}\n{condition[0]:g}/10 Mbps, base RTT {condition[1]:g} ms, 15% IID loss",
                     xlabel="Payload bytes per record", ylabel=unit, xticks=list(SIZES))
            axis.grid(alpha=.2)
            handles, labels = axis.get_legend_handles_labels()
            if handles:
                axis.legend(fontsize=7)
    first = rows[0]
    fig.suptitle(f"Payload-size study · {first['duration_s']:g}s traffic + {first['drain_s']:g}s drain · "
                 f"{first['replications']} replications per point\nRTT samples and throughput use the traffic interval. "
                 "RTT panels show P50 and P99. Error bars are 95% Student-t intervals.", fontsize=13)
    fig.savefig(path, dpi=170, bbox_inches="tight")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profiles", type=Path)
    parser.add_argument("--replications", type=int, default=3)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--drain", type=float, default=5)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--bandwidths", action="store_true")
    parser.add_argument("--baselines-only", action="store_true")
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration:
        parser.error("warmup must be shorter than duration")
    profiles = json.loads(args.profiles.read_text()) if args.profiles else default_profiles()
    if args.baselines_only:
        profiles = [profile for profile in profiles if profile.get("kind") in ("tcp", "quic")]
    plan = tasks(profiles, duration=args.duration, warmup=args.warmup, drain=args.drain,
                 replications=args.replications, pilot=args.pilot, bandwidths=args.bandwidths)
    args.out.mkdir(parents=True, exist_ok=True)
    source_root = Path(__file__).resolve().parents[1]
    sources = [Path(__file__).resolve(), *sorted((source_root / "src/l2tunnel_sim").glob("*.py"))]
    manifest = dict(tasks=plan, runtime={name: version(name) for name in ("aioquic", "numpy", "scipy", "plotly")},
                    sources={str(path.relative_to(source_root)): sha256(path.read_bytes()).hexdigest() for path in sources},
                    rtt_semantics="TCP ACK timing and QUIC ACK-delay-adjusted qlog RTT are exported separately. "
                                  "QUIC samples exclude TLS warmup. Main RTT metrics exclude drain.")
    manifest_path = args.out / "experiment.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing study parameters or source versions differ")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    runs = args.out / "runs"
    runs.mkdir(exist_ok=True)
    remaining = [task for task in plan if not (runs / f"{task['run_id']:05d}.json").exists()]
    print(f"{len(plan) - len(remaining)}/{len(plan)} runs complete", flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for count, future in enumerate(as_completed([pool.submit(execute, task) for task in remaining]),
                                       len(plan) - len(remaining) + 1):
            row = future.result()
            path = runs / f"{row['run_id']:05d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row) + "\n")
            temporary.replace(path)
            if count % 10 == 0 or count == len(plan):
                print(f"{count}/{len(plan)} runs complete", flush=True)
    rows = [json.loads((runs / f"{task['run_id']:05d}.json").read_text()) for task in plan]
    summary = summarize(rows)
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summary)
    report(args.out, summary)
    print(f"Payload study complete at {args.out}", flush=True)


if __name__ == "__main__":
    main()
