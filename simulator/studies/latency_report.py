"""Render the latency experiments and the matched 60-second comparison."""

import argparse
from collections import defaultdict
from html import escape
from pathlib import Path

import all_experiments as archive
from l2tunnel_sim.stats import paired_difference


BASELINE = "l2-pareto/transport-baselines-16/candidate-rtt"


def shared_record_validation(output, rows):
    """Expose sampled RTT and complete segment latency for the same executions."""
    selected = [row for row in rows if row["study"] == "tcp-latency/shared-record-long"]
    if not selected:
        return ""
    expected = dict(payload_bytes=1448, forward_mbps=100, reverse_mbps=10, rtt_ms=70,
                    loss_rate=.15, loss_model="iid", duration_s=60, warmup_s=5, drain_s=20)
    if any(row[key] != value for row in selected for key, value in expected.items()):
        raise ValueError("Shared-record validation figure requires matched recorded conditions")
    if len({row["version"] for row in selected}) != 1:
        raise ValueError("Shared-record validation figure requires matching recorded core versions")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    grouped = archive.summarize(selected)
    fig, axes = plt.subplots(1, 2, figsize=(13.5, 7))
    fig.subplots_adjust(left=.07, right=.99, top=.87, bottom=.22, wspace=.24)
    for axis, metric, label in ((axes[0], "tcp_rtt_p99_ms", "TCP timestamp RTT P99 (ms)"),
                                 (axes[1], "tcp_all_segment_ack_p99_ms", "All-segment ACK completion P99 through drain (ms)")):
        for index, mean in enumerate(grouped):
            color = ("#1764ab", "#ce761f", "#16816a", "#9953a2")[index % 4]
            records = [row for row in selected if row["name"] == mean["name"]]
            axis.scatter([r[metric] for r in records], [r["goodput_mbps"] for r in records], color=color, s=24, alpha=.6)
            axis.scatter(mean[metric], mean["goodput_mbps"], color=color, marker="D", s=50,
                         label=f"{mean['name']} (n={mean['n']})")
        boundary = archive.frontier(grouped, metric)
        axis.plot([r[metric] for r in boundary], [r["goodput_mbps"] for r in boundary],
                  color="#334155", linestyle="--", linewidth=1)
        axis.axhline(80, color="#64748b", linestyle=":", linewidth=1)
        axis.axvline(105, color="#64748b", linestyle=":", linewidth=1)
        axis.set(xlabel=label, ylabel="Full-interval TCP application goodput (Mbps)")
        axis.grid(alpha=.2)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", bbox_to_anchor=(.5, .02), fontsize=8)
    fig.suptitle("Shared-record latency validation · 1448 B · 100/10 Mbps · 70 ms RTT · 15% IID loss\n"
                 "Same raw runs and configuration means · 60 s traffic + 20 s drain", fontsize=12)
    fig.savefig(output / "shared-record-long.png", dpi=180)
    plt.close(fig)

    def number(value):
        return "—" if value is None else f"{value:.3f}"

    summary_rows = []
    for mean in grouped:
        records = [row for row in selected if row["name"] == mean["name"]]
        passed = sum(row["eligible"] and row["goodput_mbps"] >= 80
                     and row["tcp_rtt_p99_ms"] <= 105 and row["tcp_all_segment_ack_p99_ms"] <= 105
                     and row["tcp_deadline_miss_pct"] <= 1 for row in records)
        values = (mean["name"], mean["n"], number(mean["goodput_mbps"]), number(mean["packet_extra_pct"]),
                  number(mean["tcp_rtt_p99_ms"]), number(mean["tcp_all_segment_ack_p99_ms"]),
                  number(mean["tcp_deadline_miss_pct"]), f"{mean['confirmed']}/{mean['n']}", f"{passed}/{mean['n']}")
        summary_rows.append("<tr>" + "".join(f"<td>{escape(str(value))}</td>" for value in values) + "</tr>")
    return f"""<div class="panel"><h2>Shared records and the 1.5-RTT target</h2>
<p>The working target is full-interval application goodput of at least 80 Mbps and P99 ACK completion
within 105 ms for a 70 ms base RTT. The table checks both TCP timestamp RTT samples and every
cumulatively acknowledged segment, measured from its original submission. Deadline-miss fractions
include all submitted segments and unresolved waits through the drain cutoff. Each run must be fully
confirmed and have at most 1% late segments to pass the joint target.</p>
<img src="shared-record-long.png" alt="Matched throughput frontiers for timestamp samples and all-segment completion" style="width:100%">
<div class="scroll"><table><thead><tr><th>Profile</th><th>Runs</th><th>TCP Mbps</th>
<th>Extra packets %</th><th>Timestamp RTT P99 ms</th><th>All-segment ACK P99 ms</th>
<th>Deadline misses %</th><th>Confirmed</th><th>Joint passes</th></tr></thead><tbody>{''.join(summary_rows)}</tbody></table></div>
<p>The independent-channel format carries a five-byte channel/sequence/length record prefix and a
two-byte resynchronization anchor in each fixed-size source symbol. Padding and both redundant ACK
copies are charged. Actual byte parsing and frame reconstruction are verified. GF256 coefficient
elimination identifies recoverable symbols, while repair-payload arithmetic, coding CPU time,
authentication execution, and kernel/TAP behavior remain outside the model.</p>
<p>All short, unsuccessful, and incomplete protocol experiments remain in the charts below.
The separate coding-only analysis evaluates finite repair windows and independently recoverable
symbols without TCP or reverse ACK traffic. Its samples retain their analytical labels.
<a href="shared-record-long/replications.csv">Long-run raw observations</a> ·
<a href="shared-record-refinement/replications.csv">Refinement observations</a> ·
<a href="shared-record-pilot/replications.csv">Initial paired controls</a> ·
<a href="rtt-budget-analysis-v2/report.html">Coding-only delay analysis and all samples</a>.</p></div>"""


def validation_label(row):
    study = row["study"]
    profile = archive.object_value(row["profile"])
    if study == BASELINE:
        return "16 flows, 4 MiB, unpaced"
    if study == "tcp-latency/window/validation":
        return f"16 flows, {profile['window_bytes'] / 1048576:g} MiB, paced"
    if study == "tcp-latency/window/more-flows-validation":
        return "64 flows, 4 MiB, paced"
    if study == "tcp-latency/crossframe/long-paced4" and profile.get("variant") == "gap":
        return "16 flows, 4 MiB, paced, early feedback + first-flight recovery"
    return None


def validation_figure(output, rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    selected = [dict(row, name=validation_label(row)) for row in rows if validation_label(row)]
    expected = dict(payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
                    rtt_ms=70, loss_rate=.15, loss_model="iid", duration_s=60,
                    warmup_s=5, drain_s=20)
    if not selected or any(row[key] != value for row in selected for key, value in expected.items()):
        raise ValueError("Long validation figure requires matching recorded link and measurement conditions")
    if len({row["version"] for row in selected}) != 1:
        raise ValueError("Long validation figure requires a matching recorded core version")
    means = archive.summarize(selected)
    means.sort(key=lambda row: row["tcp_rtt_p99_ms"])
    fig, axes = plt.subplots(1, 2, figsize=(13.5, 7))
    fig.subplots_adjust(left=.07, right=.99, top=.87, bottom=.23, wspace=.22)
    colors = ["#14836e", "#ce761f", "#1764ab", "#9159a0", "#b23a48"]
    for axis, metric, label in ((axes[0], "packet_extra_pct", "Extra forward packets per delivered segment (%)"),
                                 (axes[1], "tcp_rtt_p99_ms", "TCP timestamp RTT P99 (ms)")):
        for mean, color in zip(means, colors):
            records = [row for row in selected if row["name"] == mean["name"]]
            axis.scatter([r[metric] for r in records], [r["goodput_mbps"] for r in records],
                         color=color, s=18, alpha=.55)
            x, y = mean[metric], mean["goodput_mbps"]
            xerr = [[x - mean[metric + "_low"]], [mean[metric + "_high"] - x]]
            yerr = [[y - mean["goodput_mbps_low"]], [mean["goodput_mbps_high"] - y]]
            axis.errorbar(x, y, xerr=xerr, yerr=yerr, marker="D", markersize=6,
                          color=color, capsize=3, label=f"{mean['name']} (n={mean['n']})")
        boundary = archive.frontier(means, metric)
        axis.plot([r[metric] for r in boundary], [r["goodput_mbps"] for r in boundary],
                  color="#334155", linestyle="--", linewidth=1, zorder=0)
        axis.axhline(80, color="#64748b", linestyle=":", linewidth=1)
        axis.set(xlabel=label, ylabel="Full-interval TCP application goodput (Mbps)")
        axis.grid(alpha=.2)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", bbox_to_anchor=(.5, .01), ncol=2, fontsize=8)
    fig.suptitle("1448-byte payload · 100/10 Mbps · 70 ms RTT · 15% independent loss\n"
                 "60 s traffic + 20 s drain · raw runs, means, and 95% replication intervals", fontsize=12)
    fig.savefig(output / "latency-validation.png", dpi=180)
    plt.close(fig)
    archive.write_csv(output / "latency-validation.csv", selected)
    archive.write_csv(output / "latency-validation-summary.csv", means)
    by_name = defaultdict(dict)
    for row in selected:
        by_name[row["name"]][row["seed"]] = row
    baseline = by_name["16 flows, 4 MiB, paced"]
    paired = []
    for name, observations in by_name.items():
        seeds = sorted(baseline.keys() & observations.keys())
        if name == "16 flows, 4 MiB, paced" or not seeds:
            continue
        for metric in ("goodput_mbps", "packet_extra_pct", "tcp_rtt_p99_ms"):
            paired.append(dict(candidate=name, baseline="16 flows, 4 MiB, paced", metric=metric,
                               **paired_difference([observations[s][metric] for s in seeds],
                                                   [baseline[s][metric] for s in seeds])))
    archive.write_csv(output / "latency-validation-paired.csv", paired)
    return means


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    output = args.root / "tcp-latency"
    output.mkdir(exist_ok=True)
    all_rows, inventory = archive.load_all(args.root, args.root / "all-experiments")
    rows = [row for row in all_rows if row["study"].startswith("tcp-latency/")
            or row["study"] == BASELINE]
    studies = {row["study"] for row in rows}
    inventory = [item for item in inventory if item["study"] in studies]
    means = archive.summarize(rows)
    frontiers = archive.frontier_rows(means)
    for filename, records in (("all-runs.csv", rows), ("configuration-means.csv", means),
                              ("frontiers.csv", frontiers), ("inventory.csv", inventory),
                              ("plot-coverage.csv", archive.plot_coverage(rows))):
        archive.write_csv(output / filename, records)
    archive.static_payloads(output, rows, means)
    archive.html_report(output, rows, means, frontiers, inventory)
    validation = validation_figure(output, rows)
    shared_panel = shared_record_validation(output, rows)
    table_rows = "".join(
        f"<tr><td>{escape(r['name'])}</td><td>{r['n']}</td><td>{r['goodput_mbps']:.3f}</td>"
        f"<td>{r['packet_extra_pct']:.3f}</td><td>{r['tcp_rtt_p99_ms']:.2f}</td>"
        f"<td>{r['frame_p99_ms']:.2f}</td>"
        f"<td>{r['confirmed']}/{r['n']}</td></tr>" for r in validation)
    ack_means = [r for r in means if r["study"] == "tcp-latency/ack-counted-validation"]
    ack_means.sort(key=lambda r: (r["payload_bytes"], r["name"]))
    ack_rows = "".join(
        f"<tr><td>{r['payload_bytes']:g}</td><td>{escape(r['name'])}</td>"
        f"<td>{r['goodput_mbps']:.3f}</td><td>{r['tcp_rtt_p99_ms']:.1f}</td>"
        f"<td>{r['frame_p99_ms']:.1f}</td><td>{r['confirmed']}/{r['n']}</td></tr>"
        for r in ack_means)
    panel = f"""<div class="panel"><h2>Matched long-run latency validation</h2>
<p><a href="../all-experiments/report.html">Open the complete historical archive and all payload frontiers</a>.</p>
<p>Each paced profile uses a configured 81.5 Mbps aggregate source cap. The runs use established CUBIC,
a 1-second minimum RTO, zero authentication-byte budget, and the recorded total application window.
The 64-flow result increases reverse-link use to about 8.01 Mbps of the available 10 Mbps.
Independent connection counts are part of the tested design.</p>
<img src="latency-validation.png" alt="Long-run throughput, packet cost, and TCP RTT frontiers" style="width:100%">
<div class="scroll"><table><thead><tr><th>Profile</th><th>Runs</th><th>TCP Mbps</th><th>Extra forward packets %</th>
<th>TCP RTT P99 ms</th><th>Delivered-frame P99 ms</th><th>Fully confirmed</th></tr></thead><tbody>{table_rows}</tbody></table></div>
<p>Diamonds show means of per-run P99 measurements. Error bars show 95% Student-t replication intervals.
The dashed curves are empirical mean frontiers within these common conditions. Their scope is the tested
configurations and recorded random seeds.
<a href="latency-validation.csv">Validation runs</a> · <a href="latency-validation-summary.csv">Means and intervals</a> ·
<a href="latency-validation-paired.csv">Paired changes against paced 16 flows</a>.</p>
<p>The measured low link-queue delays after pacing support a remaining recovery and ordered-delivery bottleneck.
The <a href="aligned-latency-stages/report.html">saved stage probes</a> record individual segment timing.
The <a href="latency-counterfactual/report.html">fixed-trajectory bounds</a> compare idealized reverse
delivery and ordering assumptions while retaining the recorded recovery times and reference throughput.
The combined
first-flight recovery and early gap-feedback variant changes mean P99 by about −4.8 ms in the three paired
long runs, with a 95% interval crossing zero. This comparison measures both changes together.</p>
<p>The FEC sweep retains its original 2 ms idle-flush runs. Per-connection pacing intervals exceed that timeout,
so groups often close before their configured size and rounding adds substantially more repair traffic.
Follow-up runs record actual group-size histograms. ACK experiments retain unsuccessful thinning variants,
charged redundant copies, and explicitly labeled optional acknowledged-segment slow-start controls.</p>
<p>ACK supersession also changes which timestamp RTT samples reach the sender. For large payloads,
a lower sampled RTT can coexist with unchanged or higher delivered-frame latency. Use the frame-delay
and ACK-completion views alongside the estimator RTT view to compare those candidates.</p>
<h2>Matched ACK-supersession validation</h2>
<p>These 10 s runs use 5 s drain, 16 connections, and a 4 MiB total window. Both groups enable the explicit
acknowledged-segment slow-start rule. The optimized variant coalesces advancing ACKs for 0.25 ms and sends
two deduplicated copies, with every copy charged. Frame P99 includes delivered frames through drain.
The native 64-byte control has two incomplete confirmations. All recorded outcomes contribute to the table.</p>
<div class="scroll"><table><thead><tr><th>Payload B</th><th>Profile</th><th>TCP Mbps</th>
<th>TCP RTT P99 ms</th><th>Delivered-frame P99 ms</th><th>Fully confirmed</th></tr></thead>
<tbody>{ack_rows}</tbody></table></div>
<p>For 1448-byte records, the paired frame-P99 change is +17.7 ms with a 95% interval of −5.8 to +41.2 ms.
For 64-byte records, it is −2358.3 ms with an interval of −3255.8 to −1460.8 ms.
<a href="ack-counted-validation/paired.csv">ACK paired statistics</a>.</p>
<p>The simulator executes recovery rank and header codecs with payload callbacks. Kernel/TAP behavior,
codec CPU cost, and authentication execution remain outside these measurements. The research references
inform the optional mechanisms. The implementation uses the source-defined subsets described in the profiles.
<a href="https://www.rfc-editor.org/rfc/rfc8985.html">RACK-TLP</a> ·
<a href="https://www.rfc-editor.org/rfc/rfc3449.html">TCP on asymmetric paths</a> ·
<a href="https://www.rfc-editor.org/rfc/rfc9407.html">Tetrys</a>.</p></div>"""
    report = output / "report.html"
    page = report.read_text().replace("All experiments and payload-specific Pareto frontiers", "TCP latency experiments and payload frontiers")
    aligned_panel = ""
    if (output / "aligned-record-analysis/report.html").is_file():
        aligned_panel = """<div class="panel"><h2>Aligned record validation</h2>
<p>The new source format keeps common 1448-byte application records within one outer source packet.
Matched controls isolate the framing change, and an additional candidate combines revised repair allocation
with three charged ACK copies. Small-payload results are included separately.</p>
<p><a href="aligned-record-analysis/report.html">Open the aligned-record results and matched Pareto curves</a> ·
<a href="sparse-coding-screen/report.html">Sparse-coefficient analytical screen</a> ·
<a href="structured-coding-screen/report.html">Diagonal-code analytical screen</a> ·
<a href="deadline-converse/report.html">Finite-deadline bounds and their scope</a></p></div>"""
    page = page.replace('<div class="panel controls">', aligned_panel + shared_panel + panel + '<div class="panel controls">', 1)
    report.write_text(page)
    print(f"Latency report includes {len(rows)} runs in {output}")


if __name__ == "__main__":
    main()
