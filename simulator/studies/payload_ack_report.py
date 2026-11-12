"""Compare paired native and reliable-compressed ACK payload-size studies."""

import argparse
from collections import defaultdict
from hashlib import sha256
from html import escape
import json
from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim.stats import mean_ci
from payload_sizes import write_csv


IDENTITY = ("forward_mbps", "reverse_mbps", "rtt_ms", "loss_rate", "loss_model",
            "payload_bytes", "duration_s", "warmup_s", "drain_s", "seed")
METRICS = ("application_goodput_mbps", "steady_application_goodput_mbps",
           "forward_ip_mbps", "reverse_ip_mbps", "forward_utilization_pct", "reverse_utilization_pct",
           "tcp_timestamp_rtt_p50_ms", "tcp_timestamp_rtt_p99_ms", "tcp_srtt_p99_ms", "frame_p99_ms",
           "extra_packets_per_delivered_record_pct", "forward_bytes_per_delivered_payload_byte",
           "bidirectional_bytes_per_delivered_payload_byte", "tcp_retransmissions", "tcp_timeouts",
           "forward_feedback_bytes", "forward_feedback_datagrams", "forward_retry_bytes", "forward_retry_datagrams",
           "reverse_feedback_bytes", "reverse_feedback_datagrams", "reverse_retry_bytes", "reverse_retry_datagrams",
           "forward_datagrams", "reverse_datagrams", "forward_wire_bytes", "reverse_wire_bytes")


def identity(task):
    return tuple(task[key] for key in IDENTITY)


def load_study(directory):
    manifest = json.loads((directory / "experiment.json").read_text())
    rows = {}
    for task in manifest["tasks"]:
        path = directory / "runs" / f"{task['run_id']:05d}.json"
        if path.exists():
            if identity(task) in rows:
                raise ValueError("comparison input must have one profile per condition and seed")
            rows[identity(task)] = (task, json.loads(path.read_text()))
    return manifest, rows


def add_metrics(row, label):
    row = dict(row, ack_mode=label)
    for direction in ("forward", "reverse"):
        row[f"{direction}_ip_mbps"] = row[f"{direction}_wire_bytes_during_measurement"] * 8 / (row["duration_s"] * 1e6)
        row[f"{direction}_utilization_pct"] = 100 * row[f"{direction}_ip_mbps"] / row[f"{direction}_mbps"]
    delivered_bytes = row["tcp_delivered_frames"] * row["payload_bytes"]
    row["forward_bytes_per_delivered_payload_byte"] = row["forward_wire_bytes"] / delivered_bytes
    row["bidirectional_bytes_per_delivered_payload_byte"] = (row["forward_wire_bytes"] + row["reverse_wire_bytes"]) / delivered_bytes
    row["all_confirmed"] = row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
    return row


def summarize(rows, keys):
    grouped = defaultdict(list)
    for row in rows:
        grouped[tuple(row[key] for key in keys)].append(row)
    result = []
    for identity_key, group in grouped.items():
        summary = dict(zip(keys, identity_key))
        summary["replications"] = len(group)
        summary["confirmed_replications"] = sum(row["all_confirmed"] for row in group)
        summary["minimum_delivery_fraction"] = min(row["tcp_delivery_fraction"] for row in group)
        for metric in METRICS:
            for stat, value in mean_ci([row[metric] for row in group]).items():
                if stat != "method":
                    summary[f"{metric}_{stat}"] = value
        result.append(summary)
    return result


def render(out, summaries):
    panels = (("application_goodput_mbps", "Application throughput", "Mbps"),
              ("tcp_timestamp_rtt_p99_ms", "TCP timestamp RTT P99", "ms"),
              ("forward_utilization_pct", "Forward IP service utilization", "%"),
              ("reverse_utilization_pct", "Reverse IP service utilization", "%"),
              ("forward_feedback_bytes", "Forward ARQ feedback through drain", "IP bytes"),
              ("frame_p99_ms", "Application-frame delivery P99 through drain", "ms"))
    fig = make_subplots(rows=3, cols=2, subplot_titles=[panel[1] for panel in panels], vertical_spacing=.1)
    modes = list(dict.fromkeys(row["ack_mode"] for row in summaries))
    colors = ("#4477AA", "#CC6677")
    for mode, color in zip(modes, colors):
        points = sorted((row for row in summaries if row["ack_mode"] == mode), key=lambda row: row["payload_bytes"])
        for index, (metric, _, unit) in enumerate(panels):
            row, column = divmod(index, 2)
            fig.add_trace(go.Scatter(
                x=[point["payload_bytes"] for point in points], y=[point[f"{metric}_mean"] for point in points],
                mode="lines+markers", name=mode, legendgroup=mode, showlegend=index == 0,
                line={"color": color}, error_y={"array": [point[f"{metric}_ci_high"] - point[f"{metric}_mean"] for point in points]},
                customdata=[[point["confirmed_replications"], point["replications"], point["minimum_delivery_fraction"]] for point in points],
                hovertemplate="Payload %{x} B<br>%{y:.4g}<br>Confirmed %{customdata[0]}/%{customdata[1]}<br>Minimum delivery %{customdata[2]:.3%}<extra>%{fullData.name}</extra>"),
                row=row + 1, col=column + 1)
            fig.update_yaxes(title=unit, row=row + 1, col=column + 1)
    fig.update_xaxes(title="TCP application payload per record (bytes)", tickvals=[64, 256, 512, 1024, 1448])
    fig.update_layout(template="plotly_white", height=1250, margin={"t": 70, "b": 80}, legend={"orientation": "h", "y": 1.07})
    table = "<table><thead><tr><th>ACK mode</th><th>Payload B</th><th>TCP Mbps</th><th>Forward IP Mbps</th><th>Reverse IP Mbps</th><th>RTT P99 ms</th><th>Extra forward packets %</th><th>Confirmed</th><th>Minimum delivery</th></tr></thead><tbody>"
    for row in summaries:
        table += (f"<tr><td>{escape(row['ack_mode'])}</td><td>{row['payload_bytes']}</td>"
                  f"<td>{row['application_goodput_mbps_mean']:.3f}</td><td>{row['forward_ip_mbps_mean']:.3f}</td>"
                  f"<td>{row['reverse_ip_mbps_mean']:.3f}</td><td>{row['tcp_timestamp_rtt_p99_ms_mean']:.1f}</td>"
                  f"<td>{row['extra_packets_per_delivered_record_pct_mean']:.3f}</td>"
                  f"<td>{row['confirmed_replications']}/{row['replications']}</td><td>{row['minimum_delivery_fraction']:.3%}</td></tr>")
    table += "</tbody></table>"
    html = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reliable compressed ACK comparison</title><style>body{font:16px/1.55 system-ui;color:#243447;max-width:1450px;margin:30px auto;padding:0 24px}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:8px;border-bottom:1px solid #ccd5dd;text-align:right}th:first-child,td:first-child{text-align:left}a{color:#1764ab}</style>
<h1>Reliable compressed ACK comparison</h1>
<p>Sixteen established CUBIC connections share a total 4 MiB application flight window. Each point uses 100/10 Mbps directional IP capacity, 70 ms propagation RTT, independent 15% packet erasures in both directions, a 1 s minimum inner TCP RTO, 10 s traffic, a separate 2 s warmup cutoff for steady metrics, and 5 s drain. Three paired seeds use identical source hashes and transport settings. The changed setting routes TCP ACK records through delta-header compression, packing, and selective ARQ. Both transports send their confirmation feedback through the real opposite lossy link.</p>
<p>Native cumulative TCP ACKs occupy 102 outer IP bytes per ACK in this profile. Reliable compressed ACKs can share outer datagrams and need retransmissions and opposite-direction ARQ feedback. The measured totals include these source, retry, and feedback costs.</p>
""" + table + fig.to_html(full_html=False, include_plotlyjs=True, div_id="ack-comparison") + """
<h2>Observed tradeoffs</h2>
<p>The reliable compressed ACK setting increases mean throughput from 11.984 to 58.668 Mbps at 64-byte payloads, and from 43.545 to 66.007 Mbps at 256-byte payloads. Reverse IP service usage falls from 9.305 to 4.500 Mbps and from 9.041 to 1.674 Mbps, respectively. All 15 reliable-ACK repetitions finish TCP acknowledgment and both outer confirmations. One matched native-ACK 64-byte repetition leaves a terminal TCP ACK pending, while every application record is delivered.</p>
<p>At 512, 1024, and 1448 bytes, reliable ACK throughput declines by 1.014, 2.554, and 2.587 Mbps. Their timestamp RTT P99 increases by 29.9, 87.3, and 124.7 ms. At 1448 bytes, the strict forward extra-packet metric rises from 17.543% to 26.036%, exceeding the requested 20% budget. The reverse transport produces an average 5426 forward confirmation packets and 0.284 MB of forward confirmation bytes through drain. Mean combined directional IP bytes per delivered payload byte still declines from 1.2553 to 1.2269. Packet and byte budgets therefore give different comparisons.</p>
<h2>Metric definitions and interpretation</h2>
<p>Application throughput counts unique TCP payload delivered during the 10 s traffic interval. Forward and reverse utilization use serialized IP bytes served during the same interval, divided by their respective directional capacities. A 2 s startup interval remains included in the main throughput. Separate steady throughput excludes it.</p>
<p>Feedback, retry, total-byte and packet counters in the CSV include drain. Their denominators use all uniquely delivered payload through drain. Forward feedback carries confirmations for the reverse reliable ACK transport. These whole-transfer counters have a different time horizon from utilization. Per-kind traffic-interval byte counts and direct queue-delay samples are unavailable in these saved runs. High utilization and rising protocol RTT together support a queueing interpretation, without isolating queue delay from recovery delay.</p>
<p>TCP timestamp RTT P99 pools actual ACK estimator samples from all connections within the traffic interval. Frames still awaiting delivery or ACK produce no completed RTT sample. Simulator timestamp callbacks retain continuous-time precision while encoded TCP timestamps have millisecond resolution, a difference below 1 ms. Frame delivery P99 includes completed records through drain. Error bars are 95% Student-t intervals across the three replication statistics. Paired differences use the same three seeds. Packet schedules change between variants, so matching seeds do not provide packet-for-packet identical erasures.</p>
<p>Confirmation requires every offered TCP record acknowledged and both compact transports fully confirmed with empty pending buffers by the 15 s deadline. Incomplete repetitions remain in reported averages and are explicitly counted in the table. Packing may yield fewer outer packets than application records for small payloads, so a negative extra-packet percentage is possible. Byte-per-payload ratios separately include framing and all control traffic.</p>
<p>The model includes slow start from 10 segments per connection. It excludes connection setup and teardown, authentication bytes, processing cost, and outer Ethernet framing, FCS, preamble, and inter-frame gap. Capacity results apply to the modeled IP service. These finite simulated runs characterize this profile and duration.</p>
<p><a href="occupancy-summary.csv">Paired means and confidence intervals</a> · <a href="paired-differences.csv">Reliable minus native paired differences</a> · <a href="comparison-replications.csv">Selected raw replications and derived occupancy metrics</a> · <a href="comparison-manifest.json">Comparison provenance</a> · <a href="experiment.json">Reliable ACK experiment manifest</a> · <a href="payload-report.html">Protocol RTT and throughput plots</a></p></html>"""
    (out / "ack-comparison.html").write_text(html)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--reliable", type=Path, required=True)
    args = parser.parse_args()
    baseline_manifest, baseline = load_study(args.baseline)
    reliable_manifest, reliable = load_study(args.reliable)
    if baseline_manifest["sources"] != reliable_manifest["sources"]:
        raise ValueError("simulator source hashes differ between studies")
    if len(reliable) != len(reliable_manifest["tasks"]):
        raise ValueError("reliable ACK experiment is incomplete")
    selected, differences, pairs = [], [], []
    for key, (task, row) in reliable.items():
        baseline_task, baseline_row = baseline[key]
        left = {k: v for k, v in task["profile"].items() if k not in ("name", "reliable_acks")}
        right = {k: v for k, v in baseline_task["profile"].items() if k not in ("name", "reliable_acks")}
        if left != right or not task["profile"]["reliable_acks"] or baseline_task["profile"]["reliable_acks"]:
            raise ValueError("paired profiles differ in more than ACK reliability")
        native = add_metrics(baseline_row, "Native TCP ACK")
        reliable_row = add_metrics(row, "Reliable compressed ACK")
        selected.extend((native, reliable_row))
        delta = {metric: reliable_row[metric] - native[metric] for metric in METRICS}
        delta.update(payload_bytes=row["payload_bytes"], all_confirmed=native["all_confirmed"] and reliable_row["all_confirmed"],
                     tcp_delivery_fraction=min(native["tcp_delivery_fraction"], reliable_row["tcp_delivery_fraction"]))
        differences.append(delta)
        pairs.append(dict(payload_bytes=row["payload_bytes"], seed=row["seed"], native_run_id=baseline_row["run_id"], reliable_run_id=row["run_id"]))
    summaries = summarize(selected, ("ack_mode", "payload_bytes"))
    summaries.sort(key=lambda row: (row["payload_bytes"], row["ack_mode"]))
    write_csv(args.reliable / "comparison-replications.csv", selected)
    write_csv(args.reliable / "occupancy-summary.csv", summaries)
    write_csv(args.reliable / "paired-differences.csv", summarize(differences, ("payload_bytes",)))
    manifest = dict(baseline=str(args.baseline), reliable=str(args.reliable), pairs=pairs,
                    simulator_source_hashes_match=True,
                    report_script_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
                    difference_definition="Reliable compressed ACK minus native TCP ACK for each paired seed",
                    utilization_interval="0 through traffic duration, measured serialized IP bytes",
                    counter_interval="0 through traffic duration plus drain")
    (args.reliable / "comparison-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    render(args.reliable, summaries)
    print(json.dumps([{k: row[k] for k in ("ack_mode", "payload_bytes", "application_goodput_mbps_mean", "forward_ip_mbps_mean",
                                           "reverse_ip_mbps_mean", "tcp_timestamp_rtt_p99_ms_mean", "frame_p99_ms_mean",
                                           "forward_feedback_bytes_mean", "confirmed_replications", "minimum_delivery_fraction")}
                      for row in summaries], indent=2))


if __name__ == "__main__":
    main()
