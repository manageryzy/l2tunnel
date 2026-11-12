"""Report complete aligned-record studies with matched, payload-specific frontiers."""

import argparse
from collections import defaultdict
from hashlib import sha256
from html import escape
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from plotly.subplots import make_subplots

import all_experiments as archive
from l2tunnel_sim.stats import mean_ci, paired_difference


STUDIES = {"aligned-record-pilot": 9, "aligned-record-long": 9, "aligned-record-payloads": 5}
PLOTS = (("tcp_all_segment_ack_p99_ms", "All-segment ACK P99 through drain (ms)"),
         ("tcp_rtt_p99_ms", "Timestamp RTT P99 through drain (ms)"))
EXTRAS = ("steady_goodput_mbps", "forward_measurement_mbps", "reverse_measurement_mbps",
          "censored_segments", "fragmented_records", "fragment_sources", "context_records",
          "elided_length_records")
COLORS = ("#1764ab", "#17816a", "#ce761f", "#9159a0", "#b23a48", "#5d7190",
          "#7b831f", "#b14c89", "#2c8c9a")


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def label(profile):
    config = profile["compact"]
    wire = "Aligned" if profile["wire_format"] == "aligned_records" else "Shared"
    suffix = " length−2B" if config.get("elide_payload_length", False) else ""
    return (f"{wire} r{100 * config['repair_ratio']:g}% ACK×{profile['ack_copies']} "
            f"W{config['repair_window_sources']} G{config['global_repair_every']} "
            f"P{profile['payload_rate_mbps']:g}{suffix}")


def load_studies(root, studies):
    rows, evidence = [], []
    for name, expected in studies.items():
        study = "tcp-latency/" + name
        directory = root / study
        manifest_path = directory / "experiment.json"
        verification_path = directory / "source-verification.json"
        if not manifest_path.exists() or not verification_path.exists():
            raise ValueError(f"Study is awaiting final artifacts: {study}")
        manifest = json.loads(manifest_path.read_text())
        verification = json.loads(verification_path.read_text())
        if verification.get("changed_during_run") != []:
            raise ValueError(f"Source verification failed or is incomplete: {study}")
        tasks = manifest["tasks"]
        expected = len(tasks) if expected is None else expected
        if not expected or len(tasks) != expected or len({task["run_id"] for task in tasks}) != expected:
            raise ValueError(f"Unexpected or duplicate task plan: {study}")
        files = {path.name: path for path in (directory / "runs").glob("*.json")}
        planned = {f"{task['run_id']:05d}.json" for task in tasks}
        if set(files) != planned:
            raise ValueError(f"Saved runs differ from the task plan: {study}")
        for source, expected_hash in manifest["sources"].items():
            snapshot = directory / "sources" / source
            if not snapshot.is_file() or digest(snapshot) != expected_hash:
                raise ValueError(f"Missing or mismatched source snapshot: {snapshot}")
        source_version = sha256(json.dumps(manifest["sources"], sort_keys=True).encode()).hexdigest()[:12]
        for task in tasks:
            path = files[f"{task['run_id']:05d}.json"]
            raw = json.loads(path.read_text())
            profile = archive.object_value(raw["profile"])
            if profile != task["profile"] or any(raw[key] != value for key, value in task.items() if key != "profile"):
                raise ValueError(f"Saved run does not match its task: {path}")
            row = archive.normalize(raw, task, manifest, study, path.relative_to(root).as_posix(), 1)
            prefix = "with_drain_tcp_all_segment_ack_rtt_cohort_"
            censored = raw[prefix + "censored_segments"]
            row.update(
                label=label(profile), report_source_version=source_version, raw_sha256=digest(path),
                traffic_timestamp_rtt_p99_ms=raw["tcp_timestamp_rtt_p99_ms"],
                completed_segment_ack_p99_ms=raw["with_drain_tcp_all_segment_ack_rtt_p99_ms"],
                tcp_all_segment_ack_p99_ms=raw[prefix + "latency_lower_bound_p99_ms"],
                tcp_rtt_p99_ms=raw["with_drain_tcp_timestamp_rtt_p99_ms"],
                ack_p99_is_lower_bound=bool(censored), censored_segments=censored,
                fully_confirmed=raw["fully_confirmed"],
                tcp_deadline_miss_lower_pct=100 * raw[prefix + "miss_fraction_lower"],
                tcp_deadline_miss_pct=100 * raw[prefix + "miss_fraction_upper"],
                steady_goodput_mbps=raw["steady_application_goodput_mbps"],
                forward_measurement_mbps=raw["forward_measurement_mbps"],
                reverse_measurement_mbps=raw["reverse_measurement_mbps"],
                forward_wire_bytes=raw["forward_wire_bytes"], reverse_wire_bytes=raw["reverse_wire_bytes"],
                fragmented_records=raw.get("shared_fragmented_records", 0),
                fragment_sources=raw.get("shared_fragment_sources", 0),
                context_records=raw.get("shared_context_records", 0),
                elided_length_records=raw.get("shared_elided_length_records"),
                latency_periods="All-segment cohort lower-bound P99 and timestamp samples through drain",
            )
            row["eligible"] = row["eligible"] and raw["fully_confirmed"] and not censored
            if not raw["fully_confirmed"] or censored:
                row["status"] = "incomplete"
            row["joint_target_met"] = bool(row["eligible"] and row["goodput_mbps"] >= .8 * row["forward_mbps"]
                and row["tcp_all_segment_ack_p99_ms"] is not None
                and row["tcp_all_segment_ack_p99_ms"] <= 1.5 * row["rtt_ms"]
                and row["tcp_deadline_miss_pct"] <= 1)
            row["cohort"] = json.dumps([row["cohort"], source_version])
            row["cohort_label"] += " | all recorded sources " + source_version
            rows.append(row)
        evidence.append(dict(study=study, planned=expected, saved=len(files),
                             experiment_sha256=digest(manifest_path),
                             source_verification_sha256=digest(verification_path),
                             source_hashes=manifest["sources"]))
    return rows, evidence


def summarize(rows):
    means = archive.summarize(rows)
    for mean in means:
        group = [row for row in rows if (row["study"], row["cohort"], row["profile"]) ==
                 (mean["study"], mean["cohort"], mean["profile"])]
        mean["label"] = group[0]["label"]
        mean["duration_s"] = group[0]["duration_s"]
        mean["joint_passes"] = sum(row["joint_target_met"] for row in group)
        for metric in EXTRAS:
            mean[metric] = mean_ci([row[metric] for row in group if row[metric] is not None])["mean"]
    return means


def paired_comparisons(rows):
    groups = defaultdict(dict)
    for row in rows:
        if row["study"].endswith("aligned-record-long"):
            profile = archive.object_value(row["profile"])
            config = profile["compact"]
            key = (profile["wire_format"], config["repair_ratio"], profile["ack_copies"],
                   config["repair_window_sources"], config["global_repair_every"])
            groups[key][row["seed"]] = row
    baseline = groups[("shared_records", .2, 2, 128, 4)]
    aligned = groups[("aligned_records", .2, 2, 128, 4)]
    bundle = groups[("aligned_records", .205, 3, 128, 16)]
    pairs = (("Alignment only", aligned, baseline, "wire_format"),
             ("ACK and coding bundle", bundle, aligned,
              "ack_copies 2→3; repair_ratio 0.20→0.205; global_repair_every 4→16"))
    output = []
    for name, candidate, control, changes in pairs:
        if set(candidate) != set(control) or len(control) != 3:
            raise ValueError("Long-run comparison requires exactly three paired seeds")
        seeds = sorted(control)
        for seed in seeds:
            left, right = candidate[seed], control[seed]
            if left["cohort"] != right["cohort"]:
                raise ValueError("Paired comparison has unmatched conditions or sources")
            lp, rp = archive.object_value(left["profile"]), archive.object_value(right["profile"])
            lp.pop("name"); rp.pop("name")
            if name == "Alignment only":
                lp.pop("wire_format"); rp.pop("wire_format")
                if lp != rp:
                    raise ValueError("Alignment comparison changes another parameter")
            else:
                lp["ack_copies"] = rp["ack_copies"]
                for key in ("repair_ratio", "global_repair_every"):
                    lp["compact"][key] = rp["compact"][key]
                if lp != rp:
                    raise ValueError("Joint variant has additional undocumented changes")
        for metric in ("goodput_mbps", "steady_goodput_mbps", "tcp_all_segment_ack_p99_ms",
                       "tcp_rtt_p99_ms", "tcp_deadline_miss_pct", "packet_extra_pct", "reverse_measurement_mbps"):
            output.append(dict(comparison=name, changed_parameters=changes, metric=metric,
                               candidate=candidate[seeds[0]]["label"], baseline=control[seeds[0]]["label"],
                               seeds=json.dumps(seeds),
                               **paired_difference([candidate[seed][metric] for seed in seeds],
                                                   [control[seed][metric] for seed in seeds])))
    return output


def figures(output, rows, means):
    labels = list(dict.fromkeys(row["label"] for row in rows))
    colors = {name: COLORS[index % len(COLORS)] for index, name in enumerate(labels)}
    fragments, coverage = [], []
    for payload in sorted({row["payload_bytes"] for row in rows}):
        selected = [row for row in rows if row["payload_bytes"] == payload]
        summaries = [row for row in means if row["payload_bytes"] == payload]
        interactive = make_subplots(rows=1, cols=2, subplot_titles=[title for _, title in PLOTS])
        figure, axes = plt.subplots(1, 2, figsize=(14, 7.3))
        figure.subplots_adjust(left=.065, right=.99, top=.84, bottom=.28, wspace=.22)
        for column, ((metric, title), axis) in enumerate(zip(PLOTS, axes), 1):
            observed = [row[metric] for row in selected if row[metric] is not None]
            missing_x = max(observed + [1.5 * selected[0]["rtt_ms"]]) * 1.08
            for name in dict.fromkeys(row["label"] for row in selected):
                points = [row for row in selected if row["label"] == name]
                x = [row[metric] if row[metric] is not None else missing_x for row in points]
                y = [row["goodput_mbps"] for row in points]
                symbols = ["circle" if row["eligible"] else "x" for row in points]
                text = [f"{row['id']}<br>{row['label']}<br>seed {row['seed']} · {row['status']}"
                        f"<br>{row['duration_s']:g}s traffic · {row['drain_s']:g}s drain"
                        f"<br>{row['censored_segments']} censored · misses ≤{row['tcp_deadline_miss_pct']:.3f}%"
                        + ("<br>ACK percentile is a lower bound" if row["ack_p99_is_lower_bound"] else "")
                        + ("<br>Metric unavailable; shown in unmeasured strip" if row[metric] is None else "")
                        for row in points]
                interactive.add_trace(go.Scatter(x=x, y=y, mode="markers", name=name,
                    legendgroup=name, showlegend=column == 1, ids=[row["id"] for row in points],
                    marker=dict(color=colors[name], size=8, symbol=symbols, opacity=.65),
                    text=text, hovertemplate="%{text}<br>X %{x:.3f}<br>Full Mbps %{y:.3f}<extra></extra>"),
                    row=1, col=column)
                for row, px, py in zip(points, x, y):
                    axis.scatter(px, py, color=colors[name], s=25, alpha=.6,
                                 marker="o" if row["eligible"] else "x")
                    coverage.append(dict(id=row["id"], payload_bytes=payload, metric=metric,
                                         plot="measured" if row[metric] is not None else "unmeasured strip"))
                group = [row for row in summaries if row["label"] == name and row[metric] is not None]
                interactive.add_trace(go.Scatter(x=[row[metric] for row in group],
                    y=[row["goodput_mbps"] for row in group], mode="markers", name=name + " mean",
                    legendgroup=name, showlegend=False, marker=dict(color=colors[name], size=11, symbol="diamond-open"),
                    text=[f"Mean n={row['n']} · {row['duration_s']:g}s · {row['label']}" for row in group],
                    hovertemplate="%{text}<br>X %{x:.3f}<br>Full Mbps %{y:.3f}<extra></extra>"), row=1, col=column)
                axis.scatter([row[metric] for row in group], [row["goodput_mbps"] for row in group],
                             color=colors[name], marker="D", facecolors="none", s=65, label=name)
            for cohort in dict.fromkeys(row["cohort"] for row in summaries):
                boundary = archive.frontier([row for row in summaries if row["cohort"] == cohort], metric)
                interactive.add_trace(go.Scatter(x=[row[metric] for row in boundary],
                    y=[row["goodput_mbps"] for row in boundary], mode="lines", showlegend=False,
                    line=dict(color="#344256", dash="dash"),
                    text=[row["cohort_label"] for row in boundary],
                    hovertemplate="Matched-condition mean frontier<br>%{text}<extra></extra>"), row=1, col=column)
                axis.plot([row[metric] for row in boundary], [row["goodput_mbps"] for row in boundary],
                          color="#344256", linestyle="--", linewidth=1)
            capacity, budget = .8 * selected[0]["forward_mbps"], 1.5 * selected[0]["rtt_ms"]
            interactive.add_hline(y=capacity, line_dash="dot", line_color="#777", row=1, col=column)
            interactive.add_vline(x=budget, line_dash="dot", line_color="#777", row=1, col=column)
            interactive.update_xaxes(title_text=title, row=1, col=column)
            interactive.update_yaxes(title_text="Full TCP application goodput (Mbps)", row=1, col=column)
            axis.axhline(capacity, color="#777", linestyle=":", linewidth=1)
            axis.axvline(budget, color="#777", linestyle=":", linewidth=1)
            axis.set(xlabel=title, ylabel="Full TCP application goodput (Mbps)")
            axis.grid(alpha=.2)
            if len(observed) != len(selected):
                axis.axvspan(missing_x * .99, missing_x * 1.01, color="#eee", zorder=0)
                axis.text(missing_x, .02, "Unmeasured", transform=axis.get_xaxis_transform(),
                          ha="center", rotation=90, fontsize=8)
        title = f"{payload:g}-byte payload · all {len(selected)} saved runs"
        figure.suptitle(title + "\nRaw points and configuration means · frontiers stay within matched conditions", fontsize=13)
        handles, legend = axes[0].get_legend_handles_labels()
        figure.legend(handles, legend, loc="lower center", bbox_to_anchor=(.5, .01), ncol=3, fontsize=8)
        filename = f"payload-{payload:g}.png"
        figure.savefig(output / filename, dpi=180)
        plt.close(figure)
        interactive.update_layout(title=title, height=620, margin=dict(t=90, b=140),
                                  legend=dict(orientation="h", y=-.25), template="plotly_white")
        fragments.append(f'<section><h2>{payload:g}-byte payload</h2>'
                         + interactive.to_html(full_html=False, include_plotlyjs=True if len(fragments) == 0 else False)
                         + f'<p><a href="{filename}">PNG chart</a></p></section>')
    return "".join(fragments), coverage


def table(headers, records):
    def cell(value):
        return "—" if value is None else f"{value:.3f}" if isinstance(value, float) else str(value)
    return ('<div class="scroll"><table><thead><tr>'
            + "".join(f"<th>{escape(name)}</th>" for name in headers) + "</tr></thead><tbody>"
            + "".join("<tr>" + "".join(f"<td>{escape(cell(value))}</td>" for value in row) + "</tr>" for row in records)
            + "</tbody></table></div>")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--additional-study", action="append", default=[], metavar="DIRECTORY",
                        help="Add a completed study directory under root/tcp-latency, requiring its full task plan and source verification")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.out or root / "tcp-latency/aligned-record-analysis"
    studies = dict(STUDIES)
    for name in args.additional_study:
        if Path(name).name != name or name in (".", ".."):
            parser.error("Additional studies must be directory names under root/tcp-latency")
        studies.setdefault(name, None)
    rows, evidence = load_studies(root, studies)
    means = summarize(rows)
    paired = paired_comparisons(rows)
    output.mkdir(parents=True, exist_ok=True)
    panels, coverage = figures(output, rows, means)
    assert len(coverage) == 2 * len(rows)
    for filename, records in (("all-runs.csv", rows), ("configuration-means.csv", means),
                              ("paired.csv", paired), ("plot-coverage.csv", coverage),
                              ("frontiers.csv", [row for row in archive.frontier_rows(means)
                                                 if row["frontier_metric"] in dict(PLOTS)])):
        archive.write_csv(output / filename, records)
    long_means = [row for row in means if row["study"].endswith("aligned-record-long")]
    long_table = table(["Profile", "n", "Full Mbps", "Steady Mbps", "All-segment P99 ms", "Timestamp P99 ms",
                        "Misses %", "Extra packets %", "Reverse Mbps", "Confirmed", "Joint passes"], [
        [row["label"], row["n"], row["goodput_mbps"], row["steady_goodput_mbps"],
         row["tcp_all_segment_ack_p99_ms"], row["tcp_rtt_p99_ms"], row["tcp_deadline_miss_pct"],
         row["packet_extra_pct"], row["reverse_measurement_mbps"], f"{row['confirmed']}/{row['n']}",
         f"{row['joint_passes']}/{row['n']}"] for row in long_means])
    pair_table = table(["Comparison", "Metric", "Candidate − control", "95% CI low", "95% CI high", "Pairs"],
                       [[row["comparison"], row["metric"], row["mean"], row["ci_low"], row["ci_high"], row["n"]]
                        for row in paired])
    alignment_ack = next(row for row in paired if row["comparison"] == "Alignment only"
                         and row["metric"] == "tcp_all_segment_ack_p99_ms")
    alignment_miss = next(row for row in paired if row["comparison"] == "Alignment only"
                          and row["metric"] == "tcp_deadline_miss_pct")
    bundle = next(row for row in long_means if "r20.5%" in row["label"])
    conditions = {}
    for row in rows:
        key = (row["study"], row["payload_bytes"], row["duration_s"], row["warmup_s"], row["drain_s"])
        conditions.setdefault(key, []).append(row)
    condition_table = table(["Study", "Payload B", "Traffic s", "Warmup s", "Drain s", "Runs", "Seed IDs"],
                            [[*key, len(group), len({row["seed"] for row in group})]
                             for key, group in conditions.items()])
    elision_text = ""
    if any(archive.object_value(row["profile"])["compact"].get("elide_payload_length", False) for row in rows):
        elision_text = """<p>Optional profiles marked length−2B use kind6 to derive an eligible delta
record's payload length from its preceding channel context. They omit the two-byte payload-length
field only when that context agrees and the resulting record fits one source. The three-byte channel
prefix remains charged. The decoder waits for the channel's ordered context before expanding kind6.
Explicit-length kind3 records and fragmentation handle varying or oversized records. Unflagged
profiles retain their original record format. These refinement experiments have separate
source-version cohorts.</p>"""
    refinement_means = [row for row in means if row["study"].split("/")[-1] not in STUDIES]
    refinement_section = ""
    if refinement_means:
        refinement_section = """<h2>Additional completed refinements</h2>
<p>The table retains each study's duration and source-version cohort. P gives configured source
pacing in Mbps. The original 60-second comparisons above stay tied to their frozen source version.
The new format study's flag-off pilot provides its same-version control. Comparisons to earlier
long runs also span a source-version change.</p>""" + table(
            ["Study", "Profile", "Traffic s", "n", "Full Mbps", "Steady Mbps", "All-segment P99 ms",
             "Timestamp P99 ms", "Misses %", "Extra packets %", "Reverse Mbps", "Elided records", "Joint passes"],
            [[row["study"], row["label"], row["duration_s"], row["n"], row["goodput_mbps"],
              row["steady_goodput_mbps"], row["tcp_all_segment_ack_p99_ms"], row["tcp_rtt_p99_ms"],
              row["tcp_deadline_miss_pct"], row["packet_extra_pct"], row["reverse_measurement_mbps"],
              row["elided_length_records"], f"{row['joint_passes']}/{row['n']}"] for row in refinement_means])
        validated = [row for row in refinement_means if row["duration_s"] >= 60
                     and row["tcp_all_segment_ack_p99_ms"] is not None]
        if validated:
            candidate = min(validated, key=lambda row: row["tcp_all_segment_ack_p99_ms"])
            group = [row for row in rows if (row["study"], row["cohort"], row["profile"]) ==
                     (candidate["study"], candidate["cohort"], candidate["profile"])]
            throughput_passes = sum(row["goodput_mbps"] >= .8 * row["forward_mbps"] for row in group)
            timestamp_passes = sum(row["tcp_rtt_p99_ms"] is not None
                                   and row["tcp_rtt_p99_ms"] <= 1.5 * row["rtt_ms"] for row in group)
            refinement_section += f"""<p>Among the additional 60-second candidates,
{escape(candidate['label'])} has the smallest mean all-segment ACK P99. It averages
{candidate['goodput_mbps']:.3f} Mbps, {candidate['tcp_all_segment_ack_p99_ms']:.3f} ms all-segment ACK
P99 and {candidate['tcp_rtt_p99_ms']:.3f} ms timestamp RTT P99. Throughput passes in
{throughput_passes}/{len(group)} runs and timestamp RTT P99 is within 105 ms in
{timestamp_passes}/{len(group)} runs. The joint all-segment latency gate passes in
{candidate['joint_passes']}/{len(group)} runs. Its deadline-miss rate averages
{candidate['tcp_deadline_miss_pct']:.3f}%.</p>"""
    raw_table = table(["Run", "Profile", "Payload B", "Traffic s", "Seed", "Full Mbps", "Steady Mbps",
                      "All-segment P99 ms", "Timestamp P99 ms", "Misses lower %", "Misses upper %",
                      "Censored", "Extra packets %", "Forward Mbps", "Reverse Mbps", "Status"], [
        [row["id"], row["label"], row["payload_bytes"], row["duration_s"], row["seed"], row["goodput_mbps"],
         row["steady_goodput_mbps"], row["tcp_all_segment_ack_p99_ms"], row["tcp_rtt_p99_ms"],
         row["tcp_deadline_miss_lower_pct"], row["tcp_deadline_miss_pct"], row["censored_segments"],
         row["packet_extra_pct"], row["forward_measurement_mbps"], row["reverse_measurement_mbps"], row["status"]]
        for row in rows])
    passes = sum(row["joint_target_met"] for row in rows)
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>Aligned-record latency analysis</title>
<style>body{{font:16px/1.5 system-ui;color:#233447;max-width:1450px;margin:25px auto;padding:20px}}
section{{margin:30px 0}}.scroll{{overflow-x:auto}}table{{border-collapse:collapse;font-size:13px;width:100%}}
th,td{{padding:8px;border-bottom:1px solid #d0d9e3;text-align:left}}th{{background:#edf3f8;white-space:nowrap}}
a{{color:#146a98}}.notice{{background:#edf5fa;border-left:5px solid #26729f;padding:15px}}</style>
<h1>Aligned-record throughput and latency</h1>
<p class="notice">All {len(rows)} planned executions have saved results and clean source-verification files.
The joint throughput/all-segment latency gate passes in {passes}/{len(rows)} individual runs.
Every saved run appears in both plots for its payload, including unsuccessful and dominated outcomes.
The archive remains finite simulator evidence.</p>
<p>The target is full application goodput ≥80% of forward capacity and all-segment ACK P99 ≤1.5 times
base RTT, with at most 1% deadline misses and complete confirmation. Here that is 80 Mbps and 105 ms.
Timestamp RTT remains a separately sampled estimator metric. The 20% extra-packet threshold is a separate cost objective.</p>
<h2>Matched 60-second comparison</h2>{long_table}
<p>The alignment-only mean change in all-segment ACK P99 is {alignment_ack['mean']:+.3f} ms,
with a 95% paired interval from {alignment_ack['ci_low']:.3f} to {alignment_ack['ci_high']:.3f} ms.
Its deadline-miss rate changes by {alignment_miss['mean']:+.3f} percentage points. The bundled candidate
averages {bundle['goodput_mbps']:.3f} Mbps, {bundle['tcp_all_segment_ack_p99_ms']:.3f} ms all-segment
ACK P99 and {bundle['tcp_deadline_miss_pct']:.3f}% deadline misses. It clears the throughput threshold
in all three long runs and misses the all-segment latency threshold in all three.</p>
<p>The first pair changes the wire format from shared records to aligned records at identical
20% repair, ACK×2, W128, G4 and 80.2 Mbps pacing. Conditions, source versions and three seed IDs
are checked before computing paired changes. The third profile combines ACK×3, repair20.5% and G16
relative to the aligned control. Its effect belongs to that complete bundle.</p>
<p>The aligned format emits ready sources immediately. The alignment comparison therefore includes
its record-boundary placement and source-emission behavior.</p>
<p>W is the scheduled local repair window in source symbols. G is the period for global-window
repairs among scheduled repairs. Every fourth scheduled repair is global at G4, every sixteenth at
G16, and G0 disables that periodic choice. Reliable tail repairs retain their own charged behavior.</p>
{pair_table}<p>Intervals are 95% Student-t intervals over three paired seed differences. Negative latency
and cost changes indicate reductions. Positive goodput changes indicate increases. The table averages
per-run percentiles. It does not pool packets into an independent statistical sample.</p>
{refinement_section}
<h2>Payload-specific frontiers</h2>
<p>All runs use 100/10 Mbps, 70 ms base RTT, 15% IID loss and MTU 1500. The original payload study
is a three-second, single-seed screen at each smaller payload. Its isolated points provide no
cross-configuration trade-off estimate within those payloads.</p>{condition_table}
<p>Circles show raw runs and diamonds show configuration means. Crosses mark ineligible or incomplete
outcomes. Dashed frontiers use eligible means within identical payload, link, loss, MTU, duration,
warmup, drain and recorded source versions. Short pilot and long validation frontiers stay separate.
The two panels use drain-inclusive latency observations. A one-point frontier has no connecting
line. Hover each raw point for its study and seed.</p>
{panels}
<h2>Wire format and charged work</h2>
<p>An aligned source begins with a three-byte channel/sequence prefix. The existing reversible codec
is self-describing, so source framing uses its parsed length. The format has no source anchor or
additional valid-length field. Context records are separate short sources. Oversized codec records
use a five-byte fragment kind/total-length/offset header after the channel prefix, and every fragment
is charged. Channels reconstruct and decode their own ordered byte records.</p>
{elision_text}
<p>At MTU 1500, the common repair symbol is 1460 bytes. Source IP packets contain a 36-byte outer
header plus the actual aligned data, at most 1496 bytes. Repair IP packets contain a 40-byte outer
header plus the full 1460-byte symbol, totaling 1500 bytes. Zero extension is implicit in short source
packets and explicit in the full repair symbol budget. ACK copies, context sources, fragmentation,
tail repairs and feedback all contribute to their recorded direction's packet and byte totals.</p>
<p>The simulator checks exact codec parsing and reconstruction of serialized Ethernet/IPv4/TCP frames.
GF256 coefficient elimination determines symbol availability. Repair-payload arithmetic and codec CPU
time remain excluded, alongside kernel/TAP behavior and authentication execution.</p>
<h2>Metric definitions and every raw run</h2>
<p>Full goodput counts application bytes delivered during the complete traffic interval. Steady goodput
uses the post-warmup interval. Drain bytes enter confirmation and cost accounting. All-segment ACK
latency starts at each segment's original submission and ends when a cumulative ACK covers it.
Every offered segment remains in the cohort. Censored waits contribute elapsed-time lower bounds
to the plotted P99 and lower/upper deadline-miss bounds. Such outcomes are excluded from frontiers
and joint success. Timestamp RTT measures selected estimator updates through drain.</p>
<p>Extra packets equal all forward datagrams through drain divided by unique delivered TCP segments,
minus one. Forward/reverse Mbps in the table use charged IP bytes during the traffic interval.
The CSV also preserves total wire bytes through drain, source hashes, fragmentation and context counters.</p>
{raw_table}
<p><a href="all-runs.csv">Every raw run</a> · <a href="configuration-means.csv">Configuration means</a> ·
<a href="paired.csv">Paired comparisons</a> · <a href="frontiers.csv">Matched frontiers</a> ·
<a href="plot-coverage.csv">Per-run plot coverage</a> · <a href="manifest.json">Input and source audit</a></p>
</html>"""
    (output / "report.html").write_text(page)
    manifest = dict(record_kind="derived_aligned_record_report", planned_runs=sum(item["planned"] for item in evidence),
                    saved_runs=len(rows), plotted_runs=len({row["id"] for row in coverage}),
                    plot_points=len(coverage), joint_passes=passes, studies=evidence,
                    generator_sha256=digest(Path(__file__)),
                    input_sha256={row["source"]: row["raw_sha256"] for row in rows},
                    metric_notes="Both latency panels include drain; censored ACK cohorts use elapsed lower bounds")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Reported {len(rows)} runs and {len(means)} means in {output}")


if __name__ == "__main__":
    main()
