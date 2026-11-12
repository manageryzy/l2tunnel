"""Report all completed aggregate-ACK pilot and validation points."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from plotly.subplots import make_subplots

import aligned_record_report as aligned
import all_experiments as archive
from l2tunnel_sim.stats import mean_ci


STUDIES = {"aggregate-ack-pilot": 6, "aggregate-ack-long": 6}
METRICS = (("tcp_all_segment_ack_p99_ms", "All-segment ACK P99 through drain (ms)", 105),
           ("reverse_measurement_mbps", "Reverse IP traffic during measurement (Mbps)", 10))
EXTRAS = ("ack_batch_records_mean", "ack_batch_hold_delays_ms_p99", "ack_batch_queue_delays_ms_p99")


def label(profile):
    mode = f"batch {profile['ack_batch_hold_ms']:g} ms" if profile["ack_aggregation"] else "individual"
    return f"{profile['flow_count']} flows · ACK×{profile['ack_copies']} · {mode}"


def charts(output, rows, means):
    names = list(dict.fromkeys(row["label"] for row in rows))
    colors = dict(zip(names, aligned.COLORS))
    interactive = make_subplots(rows=1, cols=2, subplot_titles=[title for _, title, _ in METRICS])
    figure, axes = plt.subplots(1, 2, figsize=(14, 7))
    figure.subplots_adjust(left=.07, right=.99, bottom=.24, top=.86, wspace=.24)
    coverage = []
    for column, ((metric, title, threshold), axis) in enumerate(zip(METRICS, axes), 1):
        for name in names:
            group = [row for row in rows if row["label"] == name]
            hover = [f"{row['id']}<br>{name}<br>{row['duration_s']:g}s traffic · seed {row['seed']}"
                     f"<br>{row['status']} · {row['tcp_deadline_miss_pct']:.3f}% deadline misses"
                     f"<br>Timestamp P99 through drain {row['tcp_rtt_p99_ms']:.3f} ms" for row in group]
            symbols = ["x" if not row["eligible"] else "square" if row["duration_s"] >= 60 else "circle"
                       for row in group]
            interactive.add_trace(go.Scatter(x=[row[metric] for row in group],
                y=[row["goodput_mbps"] for row in group], mode="markers", name=name, legendgroup=name,
                showlegend=column == 1, ids=[row["id"] for row in group],
                marker=dict(color=colors[name], size=9, symbol=symbols, opacity=.7), text=hover,
                hovertemplate="%{text}<br>X %{x:.3f}<br>Full goodput %{y:.3f} Mbps<extra></extra>"), row=1, col=column)
            for row in group:
                axis.scatter(row[metric], row["goodput_mbps"], color=colors[name], alpha=.7,
                             marker="x" if not row["eligible"] else "s" if row["duration_s"] >= 60 else "o", s=30)
                coverage.append(dict(id=row["id"], source=row["source"], payload_bytes=row["payload_bytes"], metric=metric))
            summary = [row for row in means if row["label"] == name]
            interactive.add_trace(go.Scatter(x=[row[metric] for row in summary],
                y=[row["goodput_mbps"] for row in summary], mode="markers", legendgroup=name, showlegend=False,
                marker=dict(color=colors[name], size=12, symbol="diamond-open"),
                text=[f"{row['study']} · mean n={row['n']} · {name}" for row in summary],
                hovertemplate="%{text}<br>X %{x:.3f}<br>Full goodput %{y:.3f} Mbps<extra></extra>"), row=1, col=column)
            axis.scatter([row[metric] for row in summary], [row["goodput_mbps"] for row in summary],
                         edgecolors=colors[name], facecolors="none", marker="D", s=70, label=name)
        for cohort in dict.fromkeys(row["cohort"] for row in means):
            frontier = archive.frontier([row for row in means if row["cohort"] == cohort], metric)
            interactive.add_trace(go.Scatter(x=[row[metric] for row in frontier],
                y=[row["goodput_mbps"] for row in frontier], mode="lines", showlegend=False,
                line=dict(color="#485468", dash="dash"), text=[row["cohort_label"] for row in frontier],
                hovertemplate="Matched mean frontier<br>%{text}<extra></extra>"), row=1, col=column)
            axis.plot([row[metric] for row in frontier], [row["goodput_mbps"] for row in frontier], "--",
                      color="#485468", linewidth=1)
        interactive.add_hline(y=80, line_dash="dot", line_color="#888", row=1, col=column)
        interactive.add_vline(x=threshold, line_dash="dot", line_color="#888", row=1, col=column)
        interactive.update_xaxes(title_text=title, row=1, col=column)
        interactive.update_yaxes(title_text="Full TCP application goodput (Mbps)", row=1, col=column)
        axis.axhline(80, color="#888", linestyle=":")
        axis.axvline(threshold, color="#888", linestyle=":")
        axis.set(xlabel=title, ylabel="Full TCP application goodput (Mbps)")
        axis.grid(alpha=.2)
    figure.suptitle("1448-byte payload · all 12 ACK aggregation runs\nPilot circles · long-run squares · configuration means as diamonds")
    handles, names = axes[0].get_legend_handles_labels()
    figure.legend(handles, names, loc="lower center", ncol=3, fontsize=9)
    figure.savefig(output / "payload-1448.png", dpi=180)
    plt.close(figure)
    interactive.update_layout(title="1448-byte payload · every pilot and long-run observation", height=620,
                              template="plotly_white", legend=dict(orientation="h", y=-.3),
                              margin=dict(t=90, b=145))
    return interactive.to_html(full_html=False, include_plotlyjs=True), coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    rows, evidence = aligned.load_studies(root, STUDIES)
    for row in rows:
        row["label"] = label(archive.object_value(row["profile"]))
        raw = json.loads((root / row["source"]).read_text())
        row.update({key: raw.get(key) for key in EXTRAS})
        row["joint_target_met"] = bool(row["joint_target_met"] and raw["tcp_timestamp_rtt_p99_ms"] is not None
                                        and raw["tcp_timestamp_rtt_p99_ms"] <= raw["latency_budget_ms"])
    means = aligned.summarize(rows)
    for mean in means:
        group = [row for row in rows if (row["study"], row["cohort"], row["profile"]) ==
                 (mean["study"], mean["cohort"], mean["profile"])]
        mean["raw_inputs"] = json.dumps([row["source"] for row in group])
        mean["raw_ids"] = json.dumps([row["id"] for row in group])
        mean["reverse_measurement_mbps_n"] = len(group)
        mean["traffic_timestamp_rtt_p99_ms"] = mean_ci([row["traffic_timestamp_rtt_p99_ms"] for row in group])["mean"]
        for metric in EXTRAS:
            mean[metric] = mean_ci([row[metric] for row in group if row[metric] is not None])["mean"]
    output = root / "tcp-latency/aggregate-ack-analysis"
    output.mkdir(parents=True, exist_ok=True)
    chart, coverage = charts(output, rows, means)
    frontiers = [dict(row, frontier_metric=metric) for cohort in dict.fromkeys(row["cohort"] for row in means)
                 for metric, _, _ in METRICS
                 for row in archive.frontier([row for row in means if row["cohort"] == cohort], metric)]
    for name, records in (("all-runs.csv", rows), ("configuration-means.csv", means),
                          ("frontiers.csv", frontiers), ("plot-coverage.csv", coverage)):
        archive.write_csv(output / name, records)
    headers = ["Study", "Profile", "n", "Full Mbps", "Steady Mbps", "All-segment P99 drain ms",
               "Timestamp P99 traffic ms", "Timestamp P99 drain ms",
               "Misses %", "Extra packets %", "Reverse Mbps", "Records/batch", "Batch queue P99 ms", "Joint passes"]
    summary_table = aligned.table(headers, [[row["study"].split("/")[-1], row["label"], row["n"],
        row["goodput_mbps"], row["steady_goodput_mbps"], row["tcp_all_segment_ack_p99_ms"],
        row["traffic_timestamp_rtt_p99_ms"], row["tcp_rtt_p99_ms"],
        row["tcp_deadline_miss_pct"], row["packet_extra_pct"], row["reverse_measurement_mbps"],
        row["ack_batch_records_mean"], row["ack_batch_queue_delays_ms_p99"],
        f"{row['joint_passes']}/{row['n']}"] for row in means])
    raw_table = aligned.table(["Raw source", "Profile", "Seed", "Full Mbps", "All-segment P99 drain ms",
                               "Timestamp P99 traffic ms", "Timestamp P99 drain ms", "Misses %", "Reverse Mbps", "Confirmed"],
        [[row["source"], row["label"], row["seed"], row["goodput_mbps"], row["tcp_all_segment_ack_p99_ms"],
          row["traffic_timestamp_rtt_p99_ms"], row["tcp_rtt_p99_ms"], row["tcp_deadline_miss_pct"],
          row["reverse_measurement_mbps"], row["fully_confirmed"]]
         for row in rows])
    long_rows = [row for row in rows if row["duration_s"] == 60]
    passes = sum(row["joint_target_met"] for row in rows)
    qualified = sum(row["goodput_mbps"] >= 80 for row in long_rows)
    timestamp_range = [row["tcp_rtt_p99_ms"] for row in long_rows]
    ack_range = [row["tcp_all_segment_ack_p99_ms"] for row in long_rows]
    source_links = " · ".join(f'<a href="../{name}/experiment.json">{name} task/source manifest</a> · '
                              f'<a href="../{name}/source-verification.json">source verification</a>' for name in STUDIES)
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>Cross-flow ACK aggregation</title>
<style>body{{font:16px/1.5 system-ui;color:#233447;max-width:1450px;margin:25px auto;padding:20px}}
.scroll{{overflow-x:auto}}table{{border-collapse:collapse;font-size:13px;width:100%}}th,td{{padding:8px;border-bottom:1px solid #d0d9e3;text-align:left}}
th{{background:#edf3f8;white-space:nowrap}}a{{color:#146a98}}.notice{{background:#edf5fa;padding:15px;border-left:5px solid #26729f}}</style>
<h1>Cross-flow ACK aggregation</h1>
<p class="notice">All 12 planned runs are preserved and source verified. The joint throughput and all-segment
latency target passes in {passes}/12 runs. Full goodput reaches 80 Mbps in {qualified}/6 long runs.</p>
<p>The long runs have all-segment ACK P99 from {min(ack_range):.3f} to {max(ack_range):.3f} ms and
drain-inclusive timestamp RTT P99 from {min(timestamp_range):.3f} to {max(timestamp_range):.3f} ms.
Both ranges exceed the 105 ms latency target.</p>
<p>Conditions are 100/10 Mbps, base RTT 70 ms, 15% IID loss, MTU 1500, 1448-byte application payload,
4 MiB total window, 80.18 Mbps source pacing and aligned context-length records with 20.8% repairs,
W128 and G16. Pilots run for 10 seconds with 2 seconds warmup and 10 seconds drain. Long confirmations
run for 60 seconds with 5 seconds warmup and 20 seconds drain across three paired seeds.</p>
<h2>All raw points and matched frontiers</h2>
<p>The latency target is 105 ms all-segment ACK P99. The right panel shows reverse-link consumption.
Circles are pilot runs, squares are long runs and diamonds are configuration means. Crosses mark
incomplete outcomes. Frontiers compare means only within identical conditions and archived source
versions. The overloaded 128-flow ACK×3 control remains visible. One-point frontiers have no line.</p>
{chart}<p><a href="payload-1448.png">PNG chart</a></p>
<h2>Configuration summaries</h2>{summary_table}
<p>Each mean averages per-run values, including each run's P99. Pilot configurations have one seed.
The long study changes flow count at ACK×2. The 64-flow pilot pair with ACK×3 isolates aggregation.
The 128-flow ACK×3 pilot tests the reverse-capacity limit. Timestamp RTT remains a separately sampled
estimator metric. The joint gate requires full goodput, all offered segments' ACK latency, the
traffic-interval timestamp P99 gate and complete confirmation. Both timestamp observation windows
are shown. The all-experiments portal uses the traffic-interval timestamp metric on its estimator axis.</p>
<h2>Reversible format and costs</h2>
<p>Each batch carries 28 IPv4/UDP bytes and a four-byte version/kind/count header. Every record adds
a one-byte channel, eight-byte ACK-event identifier and the complete checksum-valid 66-byte
Ethernet/IPv4/TCP ACK frame. Nineteen records fit in a 1457-byte IP packet. The maximum aggregation
hold is 0.5 ms, followed by ordinary link queueing and serialization. Every copy is charged and
independently encounters the model's packet loss. Loss of a batch correlates loss among its records.</p>
<p>Deduplication uses channel plus event identifier. Distinct duplicate-ACK events retain separate
identifiers and reach TCP independently. Parsed frame bytes must equal the submitted bytes before
the original TCP callback runs. This preserves the existing simulator's unwrapped sequence values
and sub-millisecond callback timestamps. Serialized TCP timestamps retain millisecond precision.
The callback interface is part of the model. Kernel TCP execution, CPU and GF256 payload arithmetic
remain excluded. Optional authentication bytes are zero in these runs.</p>
<p>At 80.18 Mbps, one ACK per 1448-byte segment produces about 6922 ACK events per second. With
fully occupied batches, three complete copies need about 12.74 Mbps and two need about 8.49 Mbps,
before transport feedback. Partial batches increase this cost. The actual occupancy and reverse
load are reported for every run.</p>
<h2>Metric and provenance definitions</h2>
<p>Full goodput counts application bytes delivered during the complete traffic interval. Steady goodput
uses the post-warmup interval. All-segment ACK latency starts at original submission and ends when a
cumulative ACK covers that segment. Drain observations and unresolved offered segments remain in the
cohort. Censored waits supply elapsed lower bounds and exclude a run from target success or frontiers.
Deadline misses count waits above 105 ms. Extra packets count all forward datagrams through drain
divided by unique delivered TCP segments, minus one. Reverse Mbps uses charged traffic-interval IP bytes.
Batch queue P99 includes drain and measures queueing before serialization. Later cumulative ACKs may
confirm data whose earlier ACK events were lost.</p>
<p>{source_links}. The pilot's CSV export needed a field-union correction after all six protocol runs
completed. Its <a href="../aggregate-ack-pilot/export-recovery.json">recovery receipt</a> preserves the
raw hashes and executed snapshot hash. The long study ran the corrected exporter with its own frozen
sources. The <a href="../aggregate-ack-pilot/sources/src/l2tunnel_sim/aggregate_ack.py">executed ACK module</a>
contains the byte parser, copy deduplication and charged transmission path.</p>
<p>After the long run's source verification, two follow-up checks were added to the live code.
Flush completion now requires every requested ACK-batch byte to have departed before cutoff, and
the study's target flag also checks the existing timestamp-P99 threshold. Every saved aggregate run
already has equal requested and departed bytes, and every saved run fails the all-segment gate.
The <a href="post-run-fixes.json">follow-up receipt</a> records the preserved raw hashes, revised
source hashes and regression result.</p>
<h2>Every raw execution</h2>{raw_table}
<p><a href="all-runs.csv">Raw-point CSV</a> · <a href="configuration-means.csv">Mean CSV</a> ·
<a href="frontiers.csv">Frontier CSV</a> · <a href="plot-coverage.csv">Plot coverage</a> ·
<a href="manifest.json">Report input audit</a></p></html>"""
    (output / "report.html").write_text(page)
    manifest = dict(record_kind="derived_aggregate_ack_report", raw_inputs=[row["source"] for row in rows],
                    saved_runs=len(rows), plotted_runs=len({row["id"] for row in coverage}),
                    plot_points=len(coverage), joint_passes=passes, studies=evidence,
                    generator_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
                    raw_sha256={row["source"]: row["raw_sha256"] for row in rows})
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Reported {len(rows)} runs in {output}")


if __name__ == "__main__":
    main()
