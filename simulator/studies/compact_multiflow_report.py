"""Normalize the compact multi-flow matrix and write its comparison report."""

import argparse
import json
from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from compact_multiflow import summarize, write_csv


def compatible(row, source, run_id):
    result = {key: value for key, value in row.items() if key != "per_flow"}
    result.update(
        source_directory=str(source), source_run_id=row["run_id"], run_id=run_id,
        name=(f'Compact ARQ {row["flow_count"]} flows / RTO {row["rto_min_ms"]} ms / '
              + (f'{row["payload_rate_mbps"]:g} Mbps pacing' if row["payload_rate_mbps"] else "unpaced")),
        controller="cubic", reliable_acks=False, recovery="arq", forward_mbps=100,
        reverse_mbps=10, rtt_ms=70, loss_rate=.15, loss_model="iid", mtu=1500,
        steady_forward_datagrams=row["steady_forward_packets"], steady_frame_p99_ms=None,
        full_tcp_capacity_pct=row["tcp_goodput_mbps"],
        steady_tcp_capacity_pct=row["steady_tcp_mbps"],
    )
    return result


def frontier(rows, x, y):
    result, best = [], float("-inf")
    for row in sorted(rows, key=lambda row: (row[x], -row[y])):
        if row[y] > best:
            result.append(row)
            best = row[y]
    return result


def long_validation(source):
    originals = [json.loads(path.read_text()) for path in sorted((source / "runs").glob("*.json"))]
    rows = [compatible(row, source, index) for index, row in enumerate(originals, 1)]
    for row in rows:
        row["name"] += f' / {row["duration_s"]:g} s full run'
    write_csv(source / "replications.csv", rows)
    summaries = summarize(rows)
    for summary in summaries:
        summary.update({key: rows[0][key] for key in (
            "name", "controller", "reliable_acks", "recovery", "forward_mbps", "reverse_mbps",
            "rtt_ms", "loss_rate", "loss_model", "mtu", "duration_s", "warmup_s", "drain_s")})
    write_csv(source / "summary.csv", summaries)
    figure = go.Figure(go.Scatter(
        x=[row["extra_packets_per_delivered_tcp_segment_pct"] for row in rows],
        y=[row["tcp_goodput_mbps"] for row in rows], mode="markers+text",
        text=[f'Seed {row["replication"]}' for row in rows], textposition="top center",
        marker=dict(size=12, color="#287a49"), name="Complete independent replications",
        customdata=[[row["frame_p99_ms"], row["tcp_timeouts"], row["full_target_met"]] for row in rows],
        hovertemplate=("Extra packets %{x:.4f}%<br>Full-run TCP payload %{y:.4f} Mbps"
                       "<br>P99 %{customdata[0]:.1f} ms<br>TCP timeouts %{customdata[1]}"
                       "<br>Target passed %{customdata[2]}<extra></extra>")))
    summary = summaries[0]
    x, y = "extra_packets_per_delivered_tcp_segment_pct", "tcp_goodput_mbps"
    figure.add_trace(go.Scatter(
        x=[summary[x + "_mean"]], y=[summary[y + "_mean"]], mode="markers",
        marker=dict(size=15, symbol="diamond", color="#213c7a"), name="Mean and 95% Student-t CI",
        error_x=dict(type="data", array=[summary[x + "_ci_high"] - summary[x + "_mean"]]),
        error_y=dict(type="data", array=[summary[y + "_ci_high"] - summary[y + "_mean"]])))
    figure.add_vline(x=20, line_dash="dash", line_color="#777")
    figure.add_hline(y=80, line_dash="dash", line_color="#777")
    figure.update_layout(title="60-second full-run validation of 16-flow compact ARQ",
                         xaxis_title="All forward datagrams per unique delivered TCP segment, extra (%)",
                         yaxis_title="TCP application payload throughput including initial slow start (Mbps)",
                         xaxis_range=[17.5, 20.2], yaxis_range=[79.8, 81], template="plotly_white", height=630)
    description = (
        "<h1>Long-run validation of compact ARQ</h1>"
        "<p>Sixteen independent inner CUBIC flows share a 100 Mbps forward link, 10 Mbps reverse "
        "link, 70 ms RTT, and 15% independent packet erasures in both directions. The total "
        "flow-control window is fixed at 4 MiB. Traffic is unpaced. The minimum inner TCP "
        "retransmission timeout is one second. Native cumulative TCP ACKs traverse the lossy reverse link.</p>"
        "<p>Each run offers traffic for 60 seconds, including initial slow start in the measured "
        "throughput, then drains for 20 seconds. All forward packets transmitted through drain "
        "are charged against unique delivered TCP segments. Every offered segment was delivered "
        "and acknowledged, and every flow's outer source symbols were confirmed. Connections "
        "are established at time zero with an initial ten-segment congestion window.</p>"
        f'<p>{summary["full_target_passes"]} of {summary["replications"]} independent seeds met both requested thresholds. '
        f'Mean full-run payload throughput was {summary["tcp_goodput_mbps_mean"]:.3f} Mbps '
        f'with a 95% interval of {summary["tcp_goodput_mbps_ci_low"]:.3f}–'
        f'{summary["tcp_goodput_mbps_ci_high"]:.3f} Mbps. Mean extra forward packets were '
        f'{summary["extra_packets_per_delivered_tcp_segment_pct_mean"]:.3f}%, with a 95% interval '
        f'of {summary["extra_packets_per_delivered_tcp_segment_pct_ci_low"]:.3f}–'
        f'{summary["extra_packets_per_delivered_tcp_segment_pct_ci_high"]:.3f}%.</p>'
        f'<p>Mean per-run P99 frame delay was {summary["frame_p99_ms_mean"]:.1f} ms. '
        f'Mean inner TCP timeout count was {summary["tcp_timeouts_mean"]:.1f} across the sixteen flows. '
        "The result applies to this tested multi-flow configuration and RTO floor. Single-flow "
        "and 200 ms RTO configurations had lower throughput in the comparison matrix.</p>"
        "<p>The packet model retains complete 1514-byte Ethernet frames and a 1500-byte outer IP "
        "MTU. A reversible codec compresses the tested IPv4/TCP timestamp headers, with context "
        "bytes and all record metadata charged. Payload contents are unchanged. Authentication "
        "tags and processing CPU cost are excluded.</p>"
        '<p>Evidence includes <a href="replications.csv">all replications</a>, '
        '<a href="per_flow.csv">80 per-flow records</a>, <a href="summary.csv">confidence intervals</a>, '
        'and <a href="experiment.json">the full experiment and source hashes</a>.</p>'
    )
    html = ("<!doctype html><html><head><meta charset='utf-8'><title>Long compact ARQ validation</title>"
            "<style>body{font:16px system-ui;margin:32px;max-width:1250px}p{line-height:1.55}</style>"
            "</head><body>" + description + figure.to_html(full_html=False, include_plotlyjs=True) + "</body></html>")
    (source / "report.html").write_text(html)
    print(json.dumps({"runs": len(rows), "full_target_passes": summary["full_target_passes"],
                      "confirmed_replications": summary["confirmed_replications"], "out": str(source)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--long-validation", action="store_true")
    args = parser.parse_args()
    if args.long_validation:
        long_validation(args.out)
        return
    rows, flow_rows, sources = [], [], []
    for directory in ("unpaced", "priority-16", "paced-small-flows"):
        source = args.out / directory
        sources.append(str(source / "experiment.json"))
        for path in sorted((source / "runs").glob("*.json")):
            original = json.loads(path.read_text())
            if directory == "unpaced" and original["flow_count"] == 16:
                continue
            row = compatible(original, source, len(rows) + 1)
            rows.append(row)
            for item in original["per_flow"]:
                flow_rows.append({**item, "source_directory": str(source),
                                  "source_run_id": item["run_id"], "run_id": row["run_id"]})
    if len(rows) != 44:
        raise ValueError(f"expected 44 complete aggregate replications, found {len(rows)}")
    write_csv(args.out / "replications.csv", rows)
    write_csv(args.out / "per_flow.csv", flow_rows)
    summaries = summarize(rows)
    for summary in summaries:
        first = next(row for row in rows if all(row[key] == summary[key]
                     for key in ("flow_count", "rto_min_ms", "payload_rate_mbps")))
        summary.update({key: first[key] for key in (
            "name", "controller", "reliable_acks", "recovery", "forward_mbps", "reverse_mbps",
            "rtt_ms", "loss_rate", "loss_model", "mtu", "duration_s", "warmup_s", "drain_s")})
    write_csv(args.out / "summary.csv", summaries)
    old = [json.loads(path.read_text()) for path in (args.out / "unpaced/runs").glob("*.json")]
    audited = 0
    metric_keys = ("tcp_goodput_mbps", "steady_tcp_mbps", "forward_datagrams", "tcp_delivered_frames",
                   "tcp_retransmissions", "tcp_timeouts", "frame_p99_ms", "tcp_all_acknowledged", "outer_all_confirmed")
    for previous in old:
        if previous["flow_count"] != 16:
            continue
        current = next(row for row in rows if row["flow_count"] == 16
                       and row["payload_rate_mbps"] is None
                       and row["rto_min_ms"] == previous["rto_min_ms"] and row["seed"] == previous["seed"])
        if any(previous[key] != current[key] for key in metric_keys):
            raise AssertionError("unpaced validation changed across the paced-TCP correction")
        audited += 1
    (args.out / "manifest.json").write_text(json.dumps({
        "aggregate_replications": len(rows), "per_flow_records": len(flow_rows), "source_manifests": sources,
        "selection": "Three seeds for one and four flows, five seeds for sixteen flows, both RTO floors and pacing modes",
        "normalization": "Fixed scenario labels and compatible metric aliases added without changing computed results",
        "unpaced_before_after_tcp_fix_exact_matches": audited,
    }, indent=2) + "\n")
    figure = make_subplots(rows=1, cols=2, subplot_titles=("Full measurement", "After five-second warmup"))
    colors = {1: "#266bc2", 4: "#d16a27", 16: "#43803e"}
    pareto = []
    for column, (x, y) in enumerate((
            ("extra_packets_per_delivered_tcp_segment_pct", "tcp_goodput_mbps"),
            ("steady_extra_packets_per_delivered_tcp_segment_pct", "steady_tcp_mbps")), 1):
        for summary in summaries:
            symbol = "diamond" if summary["payload_rate_mbps"] else "circle"
            if summary["rto_min_ms"] == 1000:
                symbol += "-open"
            figure.add_trace(go.Scatter(
                x=[summary[x + "_mean"]], y=[summary[y + "_mean"]], mode="markers",
                marker=dict(symbol=symbol, size=12, color=colors[summary["flow_count"]]),
                error_x=dict(type="data", array=[summary[x + "_ci_high"] - summary[x + "_mean"]]),
                error_y=dict(type="data", array=[summary[y + "_ci_high"] - summary[y + "_mean"]]),
                name=summary["name"], showlegend=column == 1,
                hovertemplate="%{fullData.name}<br>Extra packets %{x:.3f}%<br>TCP payload %{y:.3f} Mbps<extra></extra>"), row=1, col=column)
        complete = [summary for summary in summaries if summary["confirmed_replications"] == summary["replications"]
                    and summary["min_completion"] == 1]
        edge = frontier(complete, x + "_mean", y + "_mean")
        figure.add_trace(go.Scatter(x=[row[x + "_mean"] for row in edge],
                                    y=[row[y + "_mean"] for row in edge], mode="lines",
                                    line=dict(color="#333", dash="dot"), name="Empirical mean frontier",
                                    showlegend=column == 1), row=1, col=column)
        pareto.extend(dict(interval="full" if column == 1 else "post_warmup", **row) for row in edge)
        figure.add_vline(x=20, line_dash="dash", line_color="#777", row=1, col=column)
        figure.add_hline(y=80, line_dash="dash", line_color="#777", row=1, col=column)
        figure.update_xaxes(title_text="Extra forward datagrams per delivered TCP segment (%)", row=1, col=column)
        figure.update_yaxes(title_text="TCP application payload (Mbps)", row=1, col=column)
    figure.update_layout(title="Compact selective-repeat ARQ with independent inner CUBIC flows",
                         template="plotly_white", height=670, margin=dict(l=70, r=30, t=90, b=80))
    write_csv(args.out / "pareto.csv", pareto)
    intro = (
        "<h1>Compact ARQ flow-count study</h1>"
        "<p>44 replications compare 1, 4, and 16 independent inner CUBIC connections. "
        "Every connection shares the same 100 Mbps forward link, 10 Mbps reverse link, "
        "70 ms RTT, and 15% independent packet-erasure process. The total flow-control "
        "window remains 4 MiB. The paced configurations share a total 81.5 Mbps source-payload rate.</p>"
        "<p>Runs offer traffic for 20 seconds and drain for 10 seconds. The right panel uses "
        "departures and deliveries within seconds 5 through 20. Short post-warmup intervals can "
        "include previously queued data. Confidence intervals use three independent seeds for "
        "one and four flows and five seeds for sixteen flows.</p>"
        "<p>Extra packets count every forward source, retransmission, repair, and control datagram "
        "against unique delivered native TCP segments. The full-run ratio includes drain traffic. "
        "Native cumulative TCP ACKs traverse the lossy reverse link directly. Each connection "
        "has independent CUBIC, TCP recovery, outer selective-repeat recovery, and compression state.</p>"
        "<p>Completion requires every offered TCP segment to be delivered and acknowledged and "
        "all outer source symbols to be confirmed. The frontier uses configurations with complete "
        "delivery and confirmation in every replication. Dashed thresholds mark the requested "
        "80 Mbps throughput and 20% extra-packet limits. Authentication and processing CPU cost "
        "are excluded. Header compression supports the modeled IPv4/TCP timestamp traffic.</p>"
        '<p>Data files include <a href="replications.csv">aggregate replications</a>, '
        '<a href="per_flow.csv">per-flow state</a>, <a href="summary.csv">means and intervals</a>, '
        'and <a href="manifest.json">provenance and selection</a>.</p>'
    )
    table = "<table><tr><th>Configuration</th><th>N</th><th>Full Mbps</th><th>Post-warmup Mbps</th><th>Full extra %</th><th>Post-warmup extra %</th><th>Full passes</th><th>Post-warmup passes</th></tr>"
    for row in summaries:
        table += (f'<tr><td>{row["name"]}</td><td>{row["replications"]}</td>'
                  f'<td>{row["tcp_goodput_mbps_mean"]:.3f}</td><td>{row["steady_tcp_mbps_mean"]:.3f}</td>'
                  f'<td>{row["extra_packets_per_delivered_tcp_segment_pct_mean"]:.3f}</td>'
                  f'<td>{row["steady_extra_packets_per_delivered_tcp_segment_pct_mean"]:.3f}</td>'
                  f'<td>{row["full_target_passes"]}</td><td>{row["steady_target_passes"]}</td></tr>')
    table += "</table>"
    html = ("<!doctype html><html><head><meta charset='utf-8'><title>Compact ARQ flow count</title>"
            "<style>body{font:16px system-ui;margin:32px}p{max-width:1100px;line-height:1.5}"
            "table{border-collapse:collapse}td,th{padding:8px;border:1px solid #ddd;text-align:right}"
            "td:first-child{text-align:left}</style></head><body>" + intro
            + figure.to_html(full_html=False, include_plotlyjs=True) + table + "</body></html>")
    (args.out / "report.html").write_text(html)
    print(json.dumps({"aggregate_runs": len(rows), "flow_records": len(flow_rows),
                      "exact_unpaced_regressions": audited, "out": str(args.out)}), flush=True)


if __name__ == "__main__":
    main()
