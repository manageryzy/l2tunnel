"""Combine completed same-condition sixteen-flow studies without rerunning models."""

import argparse
import csv
from hashlib import sha256
from html import escape
import json
from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from payload_sizes import mean_ci, summarize


LABELS = (
    "TCP CUBIC, RTO 200 ms",
    "TCP CUBIC, RTO 1 s",
    "QUIC L2 CUBIC",
    "Compact ARQ, unpaced",
    "Compact ARQ, 81.5 Mbps pacing",
)
COLORS = ("#6687ad", "#916fa8", "#d49b35", "#137f83", "#c44e52")


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        writer.writerows(rows)


def figures(out, summaries):
    figure = make_subplots(rows=1, cols=2, subplot_titles=(
        "Forward packet overhead and application throughput", "Delivered-frame latency and application throughput"))
    for label, color, row in zip(LABELS, COLORS, summaries):
        goodput = row["application_goodput_mbps_mean"]
        for column, metric in ((1, "extra_packets_per_delivered_record_pct"), (2, "frame_p99_ms")):
            value = row[metric + "_mean"]
            figure.add_trace(go.Scatter(
                x=[value], y=[goodput], mode="markers", name=label, legendgroup=label,
                showlegend=column == 1, marker=dict(color=color, size=12),
                error_x=dict(array=[row[metric + "_ci_high"] - value]),
                error_y=dict(array=[row["application_goodput_mbps_ci_high"] - goodput]),
                customdata=[[row["min_delivery_fraction"], row["confirmed_replications"]]],
                hovertemplate="%{fullData.name}<br>x %{x:.3f}<br>Application %{y:.4f} Mbps"
                              "<br>Minimum completion %{customdata[0]:.4%}"
                              "<br>Confirmed %{customdata[1]}/5<extra></extra>"), row=1, col=column)
    frontier = sorted((row for row in summaries if row["pareto_packet_throughput"]),
                      key=lambda row: row["extra_packets_per_delivered_record_pct_mean"])
    figure.add_trace(go.Scatter(
        x=[row["extra_packets_per_delivered_record_pct_mean"] for row in frontier],
        y=[row["application_goodput_mbps_mean"] for row in frontier],
        name="Observed Pareto frontier", mode="lines", line=dict(color="#333", dash="dot")), row=1, col=1)
    figure.add_vline(x=20, line_dash="dash", line_color="#888", row=1, col=1)
    figure.add_hline(y=80, line_dash="dash", line_color="#888")
    figure.update_xaxes(title="Extra forward datagrams per delivered native record (%)", row=1, col=1)
    figure.update_xaxes(title="Delivered-frame P99 (ms, log scale)", type="log", row=1, col=2)
    figure.update_yaxes(title="Application-equivalent Mbps", range=[0, 90])
    figure.update_layout(template="plotly_white", height=600, margin=dict(t=60, b=140),
                         legend=dict(orientation="h", y=-.25))

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    static, axes = plt.subplots(1, 2, figsize=(13, 5.7), layout="constrained")
    for label, color, row in zip(LABELS, COLORS, summaries):
        for axis, metric in zip(axes, ("extra_packets_per_delivered_record_pct", "frame_p99_ms")):
            axis.errorbar(row[metric + "_mean"], row["application_goodput_mbps_mean"],
                          xerr=row[metric + "_ci_high"] - row[metric + "_mean"],
                          yerr=row["application_goodput_mbps_ci_high"] - row["application_goodput_mbps_mean"],
                          color=color, marker="o", capsize=3, label=label)
    axes[0].plot([row["extra_packets_per_delivered_record_pct_mean"] for row in frontier],
                 [row["application_goodput_mbps_mean"] for row in frontier], ":", color="#333")
    axes[0].axvline(20, color="#888", linestyle="--", linewidth=.8)
    axes[0].set(xlabel="Extra forward datagrams per delivered record (%)", title="Packet-overhead Pareto comparison")
    axes[1].set(xlabel="Delivered-frame P99 (ms)", xscale="log", title="Delivery latency and throughput")
    for axis in axes:
        axis.set(ylabel="Application-equivalent Mbps", ylim=(0, 90))
        axis.axhline(80, color="#888", linestyle="--", linewidth=.8)
        axis.grid(alpha=.2)
    axes[0].legend(loc="upper right", fontsize=8)
    static.suptitle("16 flows · 100/10 Mbps · 70 ms propagation RTT · 15% IID loss each direction\n"
                    "60 s traffic + 20 s drain · 5 seeds · error bars show 95% replication intervals", fontsize=12)
    static.savefig(out / "comparison.png", dpi=180)
    plt.close(static)
    return figure.to_html(full_html=False, include_plotlyjs=True, div_id="transport-comparison")


def report(out, summaries):
    table = ("<table><thead><tr><th>Transport</th><th>Full Mbps<br>95% CI</th><th>Steady Mbps</th>"
             "<th>Extra forward packets</th><th>Payload / forward IP bytes</th>"
             "<th>Timestamp / QUIC RTT<br>P50 / P95 / P99 ms</th><th>TCP ACK completion<br>P99 ms</th>"
             "<th>Delivered-frame<br>P99 ms</th><th>Minimum delivery</th>"
             "<th>All ACK / outer confirmed</th><th>Full target passes</th></tr></thead><tbody>")
    for label, row in zip(LABELS, summaries):
        stem = "quic_latest_rtt" if row["rtt_protocol"] == "quic" else "tcp_timestamp_rtt"
        rtt = " / ".join(f'{row[f"{stem}_p{percentile}_ms_mean"]:.1f}' for percentile in (50, 95, 99))
        ack = row["tcp_ack_rtt_p99_ms_mean"]
        ack_text = "—" if ack is None else f"{ack:.1f}"
        table += (f'<tr><td>{escape(label)}</td><td>{row["application_goodput_mbps_mean"]:.3f}<br>'
                  f'[{row["application_goodput_mbps_ci_low"]:.3f}, {row["application_goodput_mbps_ci_high"]:.3f}]</td>'
                  f'<td>{row["steady_application_goodput_mbps_mean"]:.3f}</td>'
                  f'<td>{row["extra_packets_per_delivered_record_pct_mean"]:.3f}%</td>'
                  f'<td>{row["tcp_payload_efficiency_mean"]:.2%}</td><td>{rtt}</td><td>{ack_text}</td>'
                  f'<td>{row["frame_p99_ms_mean"]:.1f}</td><td>{row["min_delivery_fraction"]:.4%}</td>'
                  f'<td>{row["confirmed_replications"]}/5</td><td>{row["full_target_passes"]}/5</td></tr>')
    table += "</tbody></table>"
    body = """<h1>Sixteen-flow transport comparison</h1>
<p>All five profiles share 100 Mbps forward and 10 Mbps reverse capacity, 70 ms propagation RTT,
independent 15% packet erasures in each direction, outer IP MTU 1500, and a fixed aggregate 4 MiB
application window rounded down to complete segments. Each flow has its own CUBIC state.
Five identical seed identifiers are used per profile. Every run sends for 60 seconds and drains
for 20 seconds. The post-warmup interval spans seconds 5 through 60.</p>
<p>Both compact profiles use reversible Ethernet/IPv4/TCP timestamp-header compression,
cross-frame packing, selective-repeat outer ARQ, native lossy reverse TCP acknowledgements,
and a 1000 ms inner TCP minimum RTO. The pacing profile divides an aggregate 81.5 Mbps
source-payload rate across sixteen flows.</p>
<h2>Throughput, recovery cost, RTT and completion</h2>
<p>Every displayed percentile is the mean of five per-run percentiles. RTT samples are pooled
across flows within a run. Throughput counts application bytes delivered during seconds 0–60,
with initial slow start included. TCP connections are established at the start, and the QUIC
handshake completes before measurement. The post-warmup column uses seconds 5–60.</p>
""" + table + """
<p>Full packet overhead is 100 × (all forward datagrams through drain / unique delivered native
records through drain − 1). It includes packing, repair, retry, retransmission and control costs.
For QUIC, one native record is a complete 1514-byte L2 frame representing 1448 application bytes.
Its 82% packet overhead therefore includes fragmentation and transport controls as well as loss
recovery. The full-target column requires at least 80 Mbps, at most 20% packet overhead,
complete delivery, and all available protocol confirmations by the end of drain.</p>
<p>Timestamp RTT is the sample passed to the TCP sender's RTT estimator. Retransmission can
refresh the echoed timestamp, producing a short timestamp sample after a long delivery wait.
ACK completion RTT measures a new cumulative ACK against the original submission time of
its latest acknowledged segment. Frame P99 measures submission-to-delivery latency for
delivered records through drain. These distributions have different sampling populations.
Incomplete runs retain their completion fraction beside conditional latency quantiles.</p>
<p>QUIC RTT is the ACK-delay-adjusted latest_rtt recorded by aioquic recovery qlog. QUIC carries
complete L2 records over a reliable stream and reports their application-equivalent payload.
There is no inner TCP state machine in that profile.</p>
""" + figures(out, summaries) + """
<h2>Model and accounting scope</h2>
<p>The configured capacity serializes outer IP bytes. Outer Ethernet header, FCS, preamble and
inter-frame gap are excluded, so the 80 Mbps target is evaluated against this IP-byte service
budget. Payload efficiency divides all delivered application bytes by all forward IP bytes
through drain. Ordinary TCP uses the simulator's CUBIC/NewReno model without SACK or RACK.
QUIC uses actual aioquic CUBIC. CPU execution cost is excluded from virtual time. The compact
profile has no authentication tag, and these observations describe the tested packet model.</p>
<p>The connected Pareto points identify nondominated observed mean results among these five
profiles. The line is a visual connection between measured settings. Error bars show 95%
Student-t confidence intervals over the five replication statistics.</p>
<p><a href="replications.csv">All 25 replication measurements</a> ·
<a href="summary.csv">Means and confidence intervals</a> ·
<a href="comparison.png">Exportable comparison figure</a> ·
<a href="manifest.json">Raw inputs, hashes and source verification</a> ·
<a href="SHA256SUMS">Artifact checksums</a></p>
"""
    (out / "report.html").write_text(
        "<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Sixteen-flow transport comparison</title><style>body{font:16px/1.5 system-ui;margin:30px auto;"
        "max-width:1600px;padding:0 24px;color:#243447}p{max-width:1200px}table{border-collapse:collapse;"
        "font-size:13px;display:block;overflow-x:auto}td,th{padding:9px;border:1px solid #ddd;text-align:right}"
        "td:first-child{text-align:left}a{color:#1764ab}</style><body>" + body + "</body></html>")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baselines", type=Path, required=True)
    parser.add_argument("--unpaced", type=Path, required=True)
    parser.add_argument("--paced", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rows, inputs, source_checks = [], {}, {}
    for directory in (args.baselines, args.unpaced, args.paced):
        manifest_path = directory / "experiment.json"
        manifest = json.loads(manifest_path.read_text())
        inputs[str(manifest_path)] = digest(manifest_path)
        for filename, expected in manifest["sources"].items():
            actual = digest(Path(filename))
            source_checks[filename] = dict(expected=expected, actual=actual, matches=expected == actual)
            if expected != actual:
                raise ValueError(f"source changed since execution: {filename}")
        for path in sorted((directory / "runs").glob("*.json")):
            row = json.loads(path.read_text())
            inputs[str(path)] = digest(path)
            row.update(source_directory=str(directory), source_run_id=row["run_id"], run_id=len(rows) + 1)
            complete = row["tcp_delivery_fraction"] == 1 and row["tcp_all_acknowledged"] and row["outer_all_confirmed"]
            row["full_target_met"] = bool(complete and row["application_goodput_mbps"] >= 80
                                            and row["extra_packets_per_delivered_record_pct"] <= 20)
            rows.append(row)
    summaries = summarize(rows)
    if len(rows) != 25 or len(summaries) != 5:
        raise ValueError("expected five profiles with five replications each")
    for summary in summaries:
        selected = [row for row in rows if row["strategy"] == summary["strategy"]]
        summary["full_target_passes"] = sum(row["full_target_met"] for row in selected)
        for key, value in mean_ci([row["tcp_payload_efficiency"] for row in selected]).items():
            if key != "method":
                summary["tcp_payload_efficiency_" + key] = value
        summary["pareto_packet_throughput"] = not any(
            other["extra_packets_per_delivered_record_pct_mean"] <= summary["extra_packets_per_delivered_record_pct_mean"]
            and other["application_goodput_mbps_mean"] >= summary["application_goodput_mbps_mean"]
            and other is not summary for other in summaries)
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "summary.csv", summaries)
    manifest = dict(raw_inputs=inputs, source_verification=source_checks,
                    postprocessor={str(Path(__file__)): digest(Path(__file__))},
                    completed_runs=len(rows), source_hashes_match=True)
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    report(args.out, summaries)
    (args.out / "SHA256SUMS").write_text("".join(
        f"{digest(path)}  {path.name}\n" for path in sorted(args.out.iterdir())
        if path.is_file() and path.name != "SHA256SUMS"))
    print(json.dumps({"completed_runs": len(rows), "source_hashes_match": True, "out": str(args.out)}))


if __name__ == "__main__":
    main()
