"""Build the 80%-throughput / 20%-packet-cost report from raw replications."""

import argparse
from collections import defaultdict
import csv
from html import escape
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from l2tunnel_sim.stats import mean_ci


COLORS = ("#1764ab", "#d37819", "#16816a", "#9953a2", "#cc4949", "#627183", "#b59a26", "#2395a4",
          "#864b35", "#c45285", "#4e680c", "#5f58b5", "#2c7185", "#9d7029", "#765572", "#35764a")
CONDITION_FIELDS = ("forward_mbps", "reverse_mbps", "rtt_ms", "loss_rate", "loss_model",
                    "duration_s", "warmup_s", "drain_s", "mtu")
CONDITION_DEFAULTS = {"reverse_mbps": 10, "loss_rate": .15, "mtu": 1500}
PERIODS = ("Whole transfer", "Post-warmup")


def number(row, key, default=None):
    value = row.get(key)
    return float(value) if value not in (None, "") else default


def truth(value):
    return str(value).lower() == "true"


def condition(row):
    return tuple(row[key] if key == "loss_model" else number(row, key, CONDITION_DEFAULTS.get(key))
                 for key in CONDITION_FIELDS)


def condition_label(key):
    forward, reverse, rtt, loss, model, duration, warmup, drain, mtu = key
    return (f"{forward:g}/{reverse:g} Mbps · RTT {rtt:g} ms · {loss:.0%} {model} · "
            f"{duration:g}s traffic / {warmup:g}s warmup / {drain:g}s drain · MTU {mtu:g}")


def read_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def load_studies(root, studies):
    rows, missing = [], []
    for study in dict.fromkeys(studies):
        directory = (root / study).resolve()
        if not directory.is_relative_to(root.resolve()):
            raise ValueError("TCP study directories must be inside the report root")
        path = directory / "replications.csv"
        if not path.exists():
            missing.append(study)
            continue
        for row in read_csv(path):
            row["study"] = study
            rows.append(row)
    return rows, missing


def observation(row, period):
    """Recompute packet cost and goodput, with explicit terminal confirmation."""
    compact = json.loads(row.get("compact") or "null")
    delivered = number(row, "tcp_delivered_frames", 0)
    offered = number(row, "offered_frames", 0)
    acknowledged = number(row, "tcp_acked_frames", 0)
    if not 0 <= acknowledged <= delivered <= offered:
        raise ValueError("TCP delivered/acknowledged counters are inconsistent")
    outer_known = compact is None or row.get("outer_all_confirmed") not in (None, "")
    outer_complete = compact is None or truth(row.get("outer_all_confirmed"))
    complete = offered > 0 and delivered == offered and acknowledged == offered and outer_complete
    measured = compact is None or compact.get("coding") == "gf256"
    payload_bytes = number(row, "payload_bytes_per_frame", 1448)
    if period == PERIODS[0]:
        packets = number(row, "forward_datagrams", 0)
        frames = delivered
        payload = number(row, "tcp_payload_bytes_during_measurement")
        if payload is not None and not 0 <= payload <= delivered * payload_bytes:
            raise ValueError("measurement payload exceeds delivered TCP payload")
        interval = number(row, "duration_s")
        p99 = number(row, "frame_p99_ms")
    else:
        packets = number(row, "steady_forward_datagrams")
        frames = number(row, "steady_delivered_frames")
        if packets is None or frames is None:
            return None
        payload = frames * payload_bytes
        interval = number(row, "duration_s") - number(row, "warmup_s")
        p99 = number(row, "steady_frame_p99_ms")
    if payload is None or interval <= 0 or frames <= 0:
        return None
    cost = 100 * (packets / frames - 1)
    capacity = 100 * payload * 8 / (interval * number(row, "forward_mbps") * 1e6)
    return dict(extra_packets_pct=cost, capacity_pct=capacity, p99_ms=p99,
                terminal_complete=complete, terminal_known=outer_known, measured=measured,
                target_met=complete and measured and cost <= 20 and capacity >= 80)


def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        profile = (row["study"], row["name"], row.get("compact"), row.get("controller"),
                   row.get("rto_min_ms"), row.get("reliable_acks"), row.get("recovery", "rlnc"))
        groups[(condition(row), profile)].append(row)
    summaries = []
    for (key, profile), records in groups.items():
        seeds = [row["seed"] for row in records]
        if len(set(seeds)) != len(seeds):
            raise ValueError(f"duplicate replication seeds in {profile[0]} / {profile[1]}")
        for period in PERIODS:
            values = [observation(row, period) for row in records]
            observed = [value for value in values if value is not None]
            if not observed:
                continue
            summary = dict(zip(CONDITION_FIELDS, key))
            summary.update(study=profile[0], name=profile[1], controller=profile[3],
                           rto_min_ms=profile[4], reliable_acks=profile[5], recovery=profile[6],
                           compact=profile[2], period=period, n=len(observed),
                           planned_replications=len(records),
                           confirmed_replications=sum(value["terminal_complete"] for value in observed),
                           confirmation_unknown=sum(not value["terminal_known"] for value in observed),
                           target_passes=sum(value["target_met"] for value in observed))
            summary["eligible"] = (len(observed) == len(records)
                                    and all(value["terminal_complete"] and value["measured"] for value in observed))
            for metric in ("extra_packets_pct", "capacity_pct", "p99_ms"):
                statistics = mean_ci([value[metric] for value in observed if value[metric] is not None])
                for name in ("mean", "ci_low", "ci_high"):
                    summary[metric + "_" + name] = statistics[name]
            summaries.append(summary)
    return summaries


def frontier(rows):
    best = float("-inf")
    selected = []
    for row in sorted((row for row in rows if row["eligible"]),
                      key=lambda row: (row["extra_packets_pct_mean"], -row["capacity_pct_mean"])):
        if row["capacity_pct_mean"] > best:
            selected.append(row)
            best = row["capacity_pct_mean"]
    return selected


def groups(rows):
    result = defaultdict(list)
    for row in rows:
        result[(condition(row), row["period"])].append(row)
    return result


def interval_error(row, metric):
    high = row[metric + "_ci_high"]
    return high - row[metric + "_mean"] if high is not None else 0


def profile_colors(rows):
    return {key: COLORS[index % len(COLORS)] for index, key in
            enumerate(dict.fromkeys((row["study"], row["name"]) for row in rows))}


def interactive(rows):
    fig = go.Figure()
    if not rows:
        fig.add_annotation(text="Validation replications are pending", x=.5, y=.5,
                           xref="paper", yref="paper", showarrow=False, font={"size": 21})
        fig.update_layout(template="plotly_white", height=480)
        return fig
    colors = profile_colors(rows)
    spans = []
    for (key, period), points in groups(rows).items():
        start = len(fig.data)
        for row in points:
            all_pass = row["target_passes"] == row["n"]
            symbol = "diamond" if all_pass else "circle" if row["eligible"] else "x"
            fig.add_trace(go.Scatter(
                x=[row["extra_packets_pct_mean"]], y=[row["capacity_pct_mean"]],
                error_x={"array": [interval_error(row, "extra_packets_pct")]},
                error_y={"array": [interval_error(row, "capacity_pct")]},
                name=row["name"], mode="markers", visible=not spans,
                marker={"color": colors[(row["study"], row["name"])], "size": 12, "symbol": symbol},
                customdata=[[row["study"], row["n"], row["confirmed_replications"], row["target_passes"],
                             row["rto_min_ms"], row["controller"], row["p99_ms_mean"]]],
                hovertemplate="%{fullData.name}<br>Extra forward packets %{x:.3f}%<br>TCP / capacity %{y:.3f}%"
                              "<br>n = %{customdata[1]}, confirmed %{customdata[2]}, target passes %{customdata[3]}"
                              "<br>Controller %{customdata[5]}, minimum RTO %{customdata[4]} ms"
                              "<br>Mean P99 %{customdata[6]:.2f} ms<br>%{customdata[0]}<extra></extra>",
            ))
        line = frontier(points)
        fig.add_trace(go.Scatter(x=[row["extra_packets_pct_mean"] for row in line],
                                 y=[row["capacity_pct_mean"] for row in line], mode="lines",
                                 line={"color": "#263848", "dash": "dash"},
                                 name="Empirical frontier, all terminal confirmations received", visible=not spans))
        spans.append((start, len(fig.data), period + " · " + condition_label(key)))
    fig.add_shape(type="rect", x0=-100, x1=20, y0=80, y1=110, fillcolor="#dcefe2", opacity=.6, line_width=0, layer="below")
    fig.add_vline(x=20, line_dash="dot", line_color="#158446")
    fig.add_hline(y=80, line_dash="dot", line_color="#158446")
    max_x = max(row["extra_packets_pct_mean"] + interval_error(row, "extra_packets_pct") for row in rows)
    min_x = min(row["extra_packets_pct_mean"] - interval_error(row, "extra_packets_pct") for row in rows)
    fig.update_xaxes(title="Extra forward IP datagrams per delivered TCP segment (%)", range=[min(0, min_x - 2), max(25, max_x + 2)])
    fig.update_yaxes(title="TCP application goodput / forward link capacity (%)", range=[0, 105])
    fig.update_layout(template="plotly_white", height=660, margin={"t": 135, "b": 160},
                      legend={"orientation": "h", "y": -.24},
                      title={"text": "80% throughput with at most 20% extra forward packets", "font": {"size": 20}},
                      updatemenus=[{"x": 0, "y": 1.16, "xanchor": "left", "buttons": [
                          {"label": label, "method": "update", "args": [
                              {"visible": [start <= index < end for index in range(len(fig.data))]}]}
                          for start, end, label in spans]}])
    return fig


def static(rows, destination):
    conditions = list(dict.fromkeys(condition(row) for row in rows))
    if not conditions:
        fig, axis = plt.subplots(figsize=(12, 5))
        axis.text(.5, .5, "Validation replications are pending", ha="center", va="center", transform=axis.transAxes, fontsize=19)
        axis.set_axis_off()
        fig.savefig(destination, dpi=180, bbox_inches="tight")
        plt.close(fig)
        return
    colors = profile_colors(rows)
    fig, axes = plt.subplots(len(conditions), 2, figsize=(15, 7 * len(conditions)), squeeze=False, layout="constrained")
    for index, key in enumerate(conditions):
        for column, period in enumerate(PERIODS):
            axis = axes[index][column]
            points = [row for row in rows if condition(row) == key and row["period"] == period]
            axis.add_patch(Rectangle((-100, 80), 120, 30, facecolor="#dcefe2", alpha=.65, zorder=0))
            for row in points:
                marker = "D" if row["target_passes"] == row["n"] else "o" if row["eligible"] else "x"
                axis.errorbar(row["extra_packets_pct_mean"], row["capacity_pct_mean"],
                              xerr=interval_error(row, "extra_packets_pct"), yerr=interval_error(row, "capacity_pct"),
                              fmt=marker, capsize=3, markersize=7, color=colors[(row["study"], row["name"])], label=row["name"])
            boundary = frontier(points)
            axis.plot([row["extra_packets_pct_mean"] for row in boundary],
                      [row["capacity_pct_mean"] for row in boundary], "--", color="#263848", linewidth=1.1)
            axis.axvline(20, color="#158446", linestyle=":", linewidth=1)
            axis.axhline(80, color="#158446", linestyle=":", linewidth=1)
            max_x = max((row["extra_packets_pct_mean"] + interval_error(row, "extra_packets_pct") for row in points), default=23)
            min_x = min((row["extra_packets_pct_mean"] - interval_error(row, "extra_packets_pct") for row in points), default=0)
            axis.set(xlim=(min(0, min_x - 2), max(25, max_x + 2)), ylim=(0, 105),
                     xlabel="Extra forward IP packets per delivered TCP segment (%)",
                     ylabel="TCP application goodput / forward capacity (%)",
                     title=period + "\n" + condition_label(key).replace(" · ", " | "))
            axis.title.set_fontsize(9)
            axis.grid(alpha=.2)
            passing = [row for row in points if row["target_passes"] == row["n"]]
            if len(passing) > 1:
                zoom = axis.inset_axes([.09, .57, .37, .33])
                zoom.set_facecolor("#eff8f1")
                for row in passing:
                    zoom.errorbar(row["extra_packets_pct_mean"], row["capacity_pct_mean"],
                                  xerr=interval_error(row, "extra_packets_pct"),
                                  yerr=interval_error(row, "capacity_pct"), fmt="D", capsize=2,
                                  markersize=4, color=colors[(row["study"], row["name"])])
                local = frontier(passing)
                zoom.plot([row["extra_packets_pct_mean"] for row in local],
                          [row["capacity_pct_mean"] for row in local], "--", color="#263848", linewidth=.8)
                zoom.axhline(80, color="#158446", linestyle=":", linewidth=.8)
                zoom.margins(x=.2, y=.2)
                zoom.set_title("All replications meet both targets", fontsize=7)
                zoom.tick_params(labelsize=7)
                zoom.grid(alpha=.2)
            if points:
                axis.legend(fontsize=8, loc="upper center", bbox_to_anchor=(.5, -.16))
            else:
                axis.text(.5, .5, "No comparable observations", transform=axis.transAxes, ha="center")
    fig.suptitle("Modeled CUBIC/NewReno TCP over a lossy link\nMeans with 95% Student-t intervals · diamonds meet both thresholds in every replication · crosses lack full confirmation", fontsize=12)
    fig.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(fig)


def reference_plot(root):
    fig = make_subplots(rows=1, cols=2, subplot_titles=("Independent connections, earlier packet layout",
                                                     "ECC levels, earlier packet layout"))
    path = root / "flow-count/summary.csv"
    if path.exists():
        rows = [row for row in read_csv(path) if number(row, "loss_rate") == .15]
        for strategy in dict.fromkeys(row["strategy"] for row in rows):
            points = sorted((row for row in rows if row["strategy"] == strategy), key=lambda row: number(row, "flow_count"))
            fig.add_trace(go.Scatter(x=[number(row, "flow_count") for row in points],
                                     y=[number(row, "tcp_payload_capacity_pct_mean") for row in points],
                                     mode="lines+markers", name=strategy), row=1, col=1)
    for study in ("ecc-levels", "ecc-levels-long"):
        path = root / study / "summary.csv"
        if not path.exists():
            continue
        rows = [row for row in read_csv(path) if number(row, "forward_mbps") == 100 and row["loss_model"] == "iid"]
        fig.add_trace(go.Scatter(x=[row["strategy"] for row in rows],
                                 y=[number(row, "tcp_capacity_pct_mean") for row in rows],
                                 mode="markers", name=study + (f" · {rows[0]['duration_s']}s" if rows else "")), row=1, col=2)
    fig.update_xaxes(title="Independent connections", type="log", tickvals=[1, 2, 4, 8, 16], row=1, col=1)
    fig.update_xaxes(title="Systematic MDS source + repair symbols", tickangle=-35, row=1, col=2)
    fig.update_yaxes(title="TCP payload / link capacity (%)")
    fig.update_layout(template="plotly_white", height=520, margin={"b": 160}, legend={"orientation": "h", "y": -.5})
    return fig


def format_number(value):
    return "—" if value is None else f"{value:.3f}"


def results_table(rows):
    headings = ("Study / profile", "Interval", "Condition", "n", "Extra packets %", "TCP / capacity %",
                "Mean P99 ms", "Confirmed runs", "80/20 passes")
    body = []
    for row in rows:
        metrics = []
        for metric in ("extra_packets_pct", "capacity_pct"):
            value = format_number(row[metric + "_mean"])
            if row[metric + "_ci_low"] is not None:
                value += f" [{row[metric + '_ci_low']:.3f}, {row[metric + '_ci_high']:.3f}]"
            metrics.append(value)
        values = (row["study"] + " / " + row["name"], row["period"], condition_label(condition(row)), row["n"],
                  *metrics, format_number(row["p99_ms_mean"]), f"{row['confirmed_replications']}/{row['n']}",
                  f"{row['target_passes']}/{row['n']}")
        body.append("<tr>" + "".join("<td>" + escape(str(value)) + "</td>" for value in values) + "</tr>")
    return ("<div class='table-scroll'><table><thead><tr>" + "".join("<th>" + h + "</th>" for h in headings)
            + "</tr></thead><tbody>" + "".join(body) + "</tbody></table></div>")


def data_links(root, studies):
    items = []
    for study in dict.fromkeys([*studies, "flow-count", "ecc-levels", "ecc-levels-long"]):
        directory = root / study
        if not directory.exists():
            continue
        links = []
        for path in [directory / "report.html", directory / "experiment.json", *sorted(directory.glob("*.csv"))]:
            if path.exists():
                links.append(f'<a href="{escape(path.relative_to(root).as_posix(), quote=True)}">{escape(path.name)}</a>')
        items.append("<li><strong>" + escape(study) + "</strong> " + " · ".join(links) + "</li>")
    return "<ul>" + "".join(items) + "</ul>"


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        fields = (list(rows[0]) if rows else ["study", "name", "period", "n", "eligible",
                                             "extra_packets_pct_mean", "capacity_pct_mean"])
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tcp-study", nargs="+", default=["compact-tcp/validation"],
                        help="Relative study directories, each containing replications.csv")
    args = parser.parse_args()
    raw, missing = load_studies(args.root, args.tcp_study)
    rows = summarize(raw)
    main_plot = interactive(rows).to_html(full_html=False, include_plotlyjs=True, div_id="tcp-goal-pareto")
    references = reference_plot(args.root).to_html(full_html=False, include_plotlyjs=False, div_id="earlier-layout-reference")
    args.root.mkdir(parents=True, exist_ok=True)
    static(rows, args.root / "goal-pareto.png")
    if rows:
        longest = max(row["duration_s"] for row in rows)
        static([row for row in rows if row["duration_s"] == longest], args.root / "goal-validation.png")
    write_csv(args.root / "goal-summary.csv", rows)
    pareto = [row for points in groups(rows).values() for row in frontier(points)]
    write_csv(args.root / "goal-frontier.csv", pareto)
    pending = ("<p class='pending'>Awaiting raw replication exports from " + escape(", ".join(missing)) + ".</p>") if missing else ""
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TCP throughput and packet cost</title><style>
body{font:16px/1.55 system-ui,sans-serif;color:#243447;background:#f7f9fb;margin:0}main{max-width:1440px;margin:auto;padding:28px}
h1{font-size:30px;margin:0 0 12px}h2{font-size:22px;margin-top:34px}p{max-width:1150px}a{color:#1764ab}
.panel{background:white;border:1px solid #dce3e9;border-radius:10px;padding:22px;margin:20px 0}.pending{background:#fff1cf;padding:12px}
.table-scroll{overflow:auto}table{border-collapse:collapse;font-size:13px;width:100%}td,th{padding:10px;border-bottom:1px solid #dce3e9;text-align:left;vertical-align:top}th{background:#eef3f8}
code{background:#eef3f8;padding:2px 4px}li{margin:8px 0}.subtle{color:#526474}
</style></head><body><main><h1>TCP throughput and packet cost</h1>
<p>The target is at least 80% of forward link capacity as delivered TCP application data, with at most 20% extra forward IP datagrams per original delivered TCP segment. The shaded region shows both thresholds. The TCP endpoints use the simulator's CUBIC/NewReno model.</p>
""" + pending + "<div class='panel'>" + main_plot + """</div>
<p>Use the selector to switch between whole-transfer and post-warmup observations and between comparable link conditions. Error bars are 95% Student-t intervals across independent replications. Diamonds meet both thresholds in every observed replication. Crosses indicate incomplete or unverified terminal confirmation.</p>
<p>The empirical frontier uses mean values and requires complete application delivery, every original TCP segment acknowledged, and all buffered outer records confirmed in every replication. Frontier lines remain within one bandwidth, RTT, loss process, MTU, traffic duration, warmup, and drain setting. Coding and recovery settings are candidate design choices. Statistical intervals describe finite replication variability.</p>
<div class='panel'><h2>Metric definitions</h2>
<p>Whole-transfer throughput counts application bytes received during the traffic interval and divides by its full duration. Its packet-cost numerator includes all forward source, repair, retry, and control packets sent through the end of drain. Its denominator counts unique TCP segments delivered by that cutoff. Drain deliveries contribute to completion and total recovery cost.</p>
<p>Post-warmup throughput and packet cost use counters from the same warmup-to-traffic-end interval. The packet-cost formula is <code>100 × (forward_datagrams / tcp_delivered_frames − 1)</code>. Post-warmup counters replace both quantities when that interval is selected. Boundary-crossing traffic can affect finite-window ratios. Completion and acknowledgement checks still use the final drain cutoff.</p>
<p>Delivery P99 covers delivered frames. The post-warmup P99 selects frames originally submitted after warmup and can include their drain delivery. Packet cost is a forward-only budget. Reverse ACK and feedback traffic consume the separately modeled reverse link.</p></div>
<div class='panel'><h2>Replication results</h2>""" + results_table(rows) + """</div>
<div class='panel'><h2>Earlier layout experiments</h2>
<p>These reference plots retain the previous two-fragment packet layout and fixed-window tunnel traffic. Independent-flow tests share one physical bottleneck and a fixed total window. The flow and ECC studies use different observation durations and recovery models, and have their own reports and Pareto frontiers.</p>
""" + references + """</div>
<div class='panel'><h2>Model scope</h2>
<p>The inner TCP engine models CUBIC or Reno congestion avoidance with NewReno recovery, delayed cumulative ACKs, timestamp RTT samples, and retransmission timers. These runs use a model of established connections. Linux SACK/RACK-TLP, PRR, and HyStart++ remain outside this engine. Real-kernel TCP performance remains unmeasured.</p>
<p>Link capacity is an IP-datagram service rate. Outer Ethernet headers, FCS, preamble, and inter-frame gaps require an additional physical-line byte budget. The 16-flow compact ARQ candidate uses a fixed aggregate 4 MiB window, a 1-second minimum TCP retransmission timeout, and no source pacing. Its 60-second observation includes initial congestion-window growth from 10 segments per flow.</p>
<p>GF(256) elimination checks the rank of the transmitted coding coefficients. The packet simulation uses record lengths and delivery callbacks, and does not calculate coded payload bytes or charge coding CPU time. The TCP header codec is separately checked for byte-exact reconstruction. Its compact profiles target established Ethernet/IPv4/TCP flows with timestamp options. Other frame types require full-frame records.</p>
<p>Authentication settings charge their configured byte budget. A 16-byte setting represents packet size overhead and does not execute authentication or encryption. The native ACK route sends complete ACK frame records on the actual lossy reverse link, without reliable outer coding. Later cumulative TCP ACKs provide recovery.</p>
<p>Loss represents exogenous per-packet erasures on an isolated configured-capacity link. Queueing, recovery, and reverse traffic consume modeled resources. Coding CPU throughput and fairness against competing production traffic remain unmeasured.</p></div>
<div class='panel'><h2>Data and reproducibility</h2>
<p><a href="goal-pareto.png">Exportable Pareto figure</a> · <a href="goal-summary.csv">Recomputed replication means and intervals</a> · <a href="goal-frontier.csv">Eligible frontier points</a></p>
<p><a href="goal-validation.png">Longest-duration validation figure</a> · <a href="payload-comparison/payload-report.html">Payload size, RTT, directional bandwidth, and ACK policy</a></p>
<p><a href="transport-comparison-16/report.html">Matched 16-connection TCP, QUIC, and compact ARQ comparison</a></p>
<p><a href="report.html">Earlier 20% loss study including QUIC</a> · <a href="compact-multiflow/report.html">Flow-count, RTO, and pacing comparisons</a></p>
""" + data_links(args.root, args.tcp_study) + "</div></main></body></html>"
    (args.root / "goal-report.html").write_text(page)
    print(f"Wrote {len(rows)} profile/interval summaries from {len(raw)} replications to {args.root}")


if __name__ == "__main__":
    main()
