"""Combine completed, duration-matched payload studies with visible completion checks."""

import argparse
from hashlib import sha256
from html import escape
import json
from pathlib import Path

from payload_sizes import RTT_STEMS, SIZES, report, summarize, write_csv
from l2tunnel_sim.stats import mean_ci


RTT_METHOD = (
    "Timestamp RTT is a sample from the modeled TCP estimator. The receive callback uses continuous "
    "simulation time, while the encoded TCP TSval is rounded down to integer milliseconds. RTT samples "
    "are therefore obtained from simulator state, and the sub-millisecond timestamp quantization error "
    "is omitted. SRTT records the estimator after each update."
)


def load_studies(root, studies):
    rows = []
    manifests = {}
    identities = set()
    periods = set()
    profiles = {}
    for study in studies:
        directory = root / study
        manifest_path = directory / "experiment.json"
        manifest = json.loads(manifest_path.read_text())
        manifests[study] = dict(sha256=sha256(manifest_path.read_bytes()).hexdigest(), manifest=manifest)
        for task in manifest["tasks"]:
            row = json.loads((directory / "runs" / f"{task['run_id']:05d}.json").read_text())
            profile = json.loads(row["profile"])
            if row["strategy"] in profiles and profiles[row["strategy"]] != profile:
                raise ValueError("one profile label refers to different transport configurations")
            profiles[row["strategy"]] = profile
            identity = (row["forward_mbps"], row["reverse_mbps"], row["rtt_ms"], row["loss_rate"],
                        row["strategy"], row["payload_bytes"], row["seed"])
            if identity in identities:
                raise ValueError("duplicate independent replication in input studies")
            identities.add(identity)
            periods.add((row["duration_s"], row["warmup_s"], row["drain_s"]))
            row["source_study"] = study
            rows.append(row)
    if len(periods) != 1:
        raise ValueError("combine only duration-, warmup-, and drain-matched payload studies")
    return rows, manifests


def number(value):
    return "—" if value is None else f"{value:.3f}"


def completion_table(summary):
    headings = ("Profile", "Independent flows", "Forward / reverse Mbps", "Base RTT ms", "Payload B", "Runs",
                "Delivered by drain, minimum", "All data ACKs + outer confirmed", "Throughput Mbps",
                "Post-warmup throughput Mbps", "Forward / reverse IP utilization %",
                "TCP timestamp RTT P50 / P99 ms", "QUIC RTT P50 / P99 ms")
    body = []
    for row in summary:
        values = (
            row["strategy"], row["flow_count"], f"{row['forward_mbps']:g} / {row['reverse_mbps']:g}", row["rtt_ms"],
            row["payload_bytes"], row["replications"], f"{row['min_delivery_fraction']:.2%}",
            f"{row['confirmed_replications']} / {row['replications']}",
            number(row["application_goodput_mbps_mean"]), number(row["steady_application_goodput_mbps_mean"]),
            " / ".join(number(row[f"{direction}_ip_utilization_pct_mean"]) for direction in ("forward", "reverse")),
            " / ".join(number(row[f"tcp_timestamp_rtt_p{p}_ms_mean"]) for p in (50, 99)),
            " / ".join(number(row[f"quic_latest_rtt_p{p}_ms_mean"]) for p in (50, 99)),
        )
        complete = row["confirmed_replications"] == row["replications"] and row["min_delivery_fraction"] == 1
        body.append(f'<tr class="{"complete" if complete else "incomplete"}">'
                    + "".join("<td>" + escape(str(value)) + "</td>" for value in values) + "</tr>")
    return ("<div class=scroll><table><thead><tr>" + "".join("<th>" + label + "</th>" for label in headings)
            + "</tr></thead><tbody>" + "".join(body) + "</tbody></table></div>")


def comparison_figure(path, rows, run_count):
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
            metrics.extend((f"{RTT_STEMS[protocol]}_p{p}_ms", column, f" P{p}", dash)
                           for p, dash in ((50, "-"), (99, "--")))
            for metric, column, suffix, dash in metrics:
                observed = [point for point in points if point[metric + "_mean"] is not None]
                axes[index][column].errorbar(
                    [point["payload_bytes"] for point in observed], [point[metric + "_mean"] for point in observed],
                    yerr=[point[metric + "_ci_high"] - point[metric + "_mean"] if point[metric + "_ci_high"] is not None else 0
                          for point in observed], color=colors[name], marker="o", linestyle=dash,
                    markersize=4, capsize=2, label=name + suffix)
        for column, title, unit in ((0, "Application throughput", "Mbps"), (1, "Modeled TCP estimator RTT", "ms"),
                                    (2, "QUIC qlog latest RTT", "ms")):
            axis = axes[index][column]
            axis.set(title=f"{title}\n{condition[0]:g}/10 Mbps, base RTT {condition[1]:g} ms, 15% IID loss",
                     xlabel="Payload bytes per record", ylabel=unit, xticks=list(SIZES))
            handles, labels = axis.get_legend_handles_labels()
            if handles:
                axis.grid(alpha=.2)
                axis.legend(fontsize=7)
            else:
                axis.set(xticks=[], yticks=[], xlabel="", ylabel="")
                axis.text(.5, .5, "No QUIC observations" if column == 2 else "No observations",
                          ha="center", va="center", transform=axis.transAxes, color="#64748b")
    first = rows[0]
    counts = sorted(set(row["replications"] for row in rows))
    count_label = str(counts[0]) if len(counts) == 1 else f"{counts[0]}–{counts[-1]}"
    fig.suptitle(f"Payload-size study · {first['duration_s']:g}s traffic + {first['drain_s']:g}s drain · "
                 f"{run_count} runs · {count_label} seeds per point\n"
                 "Traffic-interval throughput and RTT P50/P99. Error bars are 95% Student-t intervals.", fontsize=13)
    fig.supxlabel("Some points remain incomplete at the drain deadline. RTT includes received ACK samples, and excludes still-pending ACK waits.\n"
                  "TCP uses a simulated estimator with sub-millisecond timestamp quantization omitted. Capacity is the IP service rate.\n"
                  "Plain TCP / QUIC references use one connection; compact ARQ uses sixteen. See the HTML table for per-point confirmation.", fontsize=10)
    fig.savefig(path, dpi=170, bbox_inches="tight")
    plt.close(fig)


def build(root, studies, output="payload-comparison"):
    rows, manifests = load_studies(root, studies)
    summary = summarize(rows)
    for item in summary:
        records = [row for row in rows if all(row[key] == item[key] for key in
                   ("strategy", "forward_mbps", "rtt_ms", "payload_bytes"))]
        for direction in ("forward", "reverse"):
            field = direction + "_wire_bytes_during_measurement"
            values = [100 * row[field] * 8 / (row["duration_s"] * row[direction + "_mbps"] * 1e6)
                      for row in records if row.get(field) is not None]
            for key, value in mean_ci(values).items():
                if key != "method":
                    item[f"{direction}_ip_utilization_pct_{key}"] = value
    out = root / output
    out.mkdir(parents=True, exist_ok=True)
    # Multi-flow metrics contain additional fields absent from single-flow rows.
    fields = list(dict.fromkeys(key for row in rows for key in row))
    write_csv(out / "replications.csv", [{key: row.get(key) for key in fields} for row in rows])
    write_csv(out / "summary.csv", summary)
    (out / "experiment.json").write_text(json.dumps(dict(
        studies=manifests, rows=len(rows),
        report_source_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        rtt_method=RTT_METHOD,
        capacity_layer="IP service rate; outer Ethernet/FCS/preamble/inter-frame gap omitted",
    ), indent=2) + "\n")
    report(out, summary)
    comparison_figure(out / "payload-overview.png", summary, len(rows))
    links = " · ".join(f'<a href="../{escape(study, quote=True)}/replications.csv">{escape(study)} raw CSV</a>'
                       for study in studies)
    compact_profiles = {row["strategy"]: json.loads(row["profile"]) for row in rows
                        if "compact" in json.loads(row["profile"])}
    profile_notes = []
    for name, profile in compact_profiles.items():
        auth = profile["compact"].get("authentication_bytes", 0)
        route = "reliable reverse compact recovery" if profile.get("reliable_acks", True) else "native lossy reverse delivery"
        profile_notes.append("<li>" + escape(name) + f" uses {route} for TCP ACKs and an authentication budget of {auth} bytes per applicable compact datagram.</li>")
    details = f"""
<style>.scroll{{overflow-x:auto}}table{{border-collapse:collapse;font-size:12px;width:100%}}th,td{{padding:8px;border-bottom:1px solid #d9e2ec;text-align:right}}td:first-child,th:first-child{{text-align:left}}th{{background:#eef3f8}}tr.incomplete{{background:#fff3df}}button{{padding:6px 12px;margin-right:8px}}</style>
<h2>Measurement scope and terminal delivery</h2>
<p>The link capacity is the IP service rate. Outer Ethernet headers, FCS, preamble, and inter-frame gap are excluded from the link serialization budget. All study points use the same traffic, warmup, and drain durations. The table gives the actual replication count for each point.</p>
<p>The plain TCP and QUIC payload baselines each use one connection. The selected compact ARQ profile uses sixteen independent TCP connections. Connection counts are shown in the table. This sweep compares the selected complete configuration with those single-connection references.</p>
<p>{RTT_METHOD} Native-ACK profiles send TCP ACK packets over the lossy reverse link. Reliable-ACK profiles pass them through reverse compact recovery, whose feedback contributes to forward traffic. Sixteen-flow points retain independent TCP and outer ARQ states within the same total 4 MiB budget. Cryptographic CPU work is omitted.</p>
<ul>{''.join(profile_notes)}</ul>
<p>Amber rows have data or acknowledgments still outstanding at the drain deadline in at least one replication. Their throughput and RTT statistics describe the observed finite interval. Frame P99 is conditional on frames delivered by the deadline, and the full-transfer latency tail remains unknown. RTT statistics include received ACK samples, while waiting for an ACK that has yet to arrive is excluded. A low baseline RTT therefore cannot establish low overall delivery latency. All-data acknowledgment and outer confirmation are required for a complete-delivery claim.</p>
<p><button onclick="Plotly.relayout('payload-size-study',{{'yaxis.type':'linear'}})">Linear throughput axis</button><button onclick="Plotly.relayout('payload-size-study',{{'yaxis.type':'log'}})">Log throughput axis</button></p>
{completion_table(summary)}
<p>{links}</p>
<script>
const payloadChart = document.getElementById('payload-size-study');
const payloadTitles = payloadChart.layout.annotations.slice();
function markMissingQuic() {{
  const present = payloadChart.data.some(trace => trace.visible !== false && trace.yaxis === 'y4' && trace.y.some(value => value !== null));
  Plotly.relayout(payloadChart, {{'yaxis4.showticklabels':present, 'xaxis4.showticklabels':present,
    'annotations':present ? payloadTitles : payloadTitles.concat([{{text:'No QUIC observations',xref:'x4 domain',yref:'y4 domain',x:.5,y:.5,showarrow:false,font:{{size:18,color:'#64748b'}}}}])}});
}}
payloadChart.on('plotly_buttonclicked', () => setTimeout(markMissingQuic, 0));
markMissingQuic();
</script>
"""
    path = out / "payload-report.html"
    page = path.read_text().replace("Timestamp samples are the actual values passed to the TCP estimator after timestamp echo processing. SRTT records the estimator after each update.", RTT_METHOD)
    # Keep completeness visible before the interactive charts as well as in the table.
    incomplete = sum(row["confirmed_replications"] < row["replications"] or row["min_delivery_fraction"] < 1 for row in summary)
    page = page.replace("<h1>Payload size, throughput and protocol RTT</h1>",
                        "<h1>Payload size, throughput and protocol RTT</h1>"
                        + f"<p>{len(rows)} runs across {len(summary)} profile/payload/condition points. Each point has {min(row['replications'] for row in summary)}–{max(row['replications'] for row in summary)} independent seeds, as listed below.</p>"
                        + f"<p><strong>{incomplete} of {len(summary)} profile/payload/condition points have incomplete delivery or acknowledgments by the drain deadline.</strong> The terminal-delivery table below identifies every affected point.</p>")
    path.write_text(page.replace("</html>", details + "</html>"))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--studies", nargs="+", required=True)
    parser.add_argument("--output", default="payload-comparison")
    args = parser.parse_args()
    print(build(args.root, args.studies, args.output))


if __name__ == "__main__":
    main()
