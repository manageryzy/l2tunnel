"""Backfill saved analytical cases in the v2 report without running a simulation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import plotly.graph_objects as go


METRICS = ("symbol_deadline_miss_fraction", "symbol_unresolved_at_horizon_fraction")
GENERATED = {
    "report.html", "confirmation/report.html", "historical-plot-points.csv",
    "historical-plot-coverage.json", "report-render-provenance.json",
    "historical-pilot.png", "browser-verification.json",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def csv_rows(path):
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def load_points(output):
    points = []
    checks = []
    for cohort, relative in (("main", Path(".")), ("confirmation", Path("confirmation"))):
        directory = output / relative
        manifest = json.loads((directory / "manifest.json").read_text())
        raw_files = sorted((directory / "cases").glob("*.json"))
        exported = csv_rows(directory / "analytic-cases.csv")
        by_id = {int(row["analytic_case_id"]): row for row in exported}
        expected = {task["analytic_case_id"] for task in manifest["analytic_tasks"]}
        assert len(by_id) == len(exported) == len(raw_files) == manifest["analytic_cases"]
        actual = set()
        for path in raw_files:
            row = json.loads(path.read_text())
            case_id = row["analytic_case_id"]
            actual.add(case_id)
            source = str(path.relative_to(output))
            for key in (*METRICS, "seed", "source_symbols", "measured_symbols"):
                assert float(by_id[case_id][key]) == row[key], (source, key)
            points.append(dict(
                record_kind="analytic_report_point", point_id=f"{cohort}-{case_id:04d}",
                cohort=cohort, original_case_id=case_id, source=source, source_row="",
                source_sha256=digest(path), raw_inputs=json.dumps([source]),
                policy=row["policy"], seed=row["seed"], source_symbols=row["source_symbols"],
                warmup_symbols=row["warmup_symbols"], measured_symbols=row["measured_symbols"],
                tail_symbols=row["tail_symbols"], loss_rate=row["loss_rate"],
                repair_per_source=row["repair_per_source"],
                **{key: row[key] for key in METRICS},
            ))
        assert actual == expected
        checks.append(dict(cohort=cohort, manifest_cases=len(expected), raw_cases=len(raw_files),
                           exported_cases=len(exported), raw_csv_metrics_match=True))
    pilot = output / "pilot-screen.csv"
    duplicate = output / "confirmation/pilot-screen.csv"
    assert pilot.read_bytes() == duplicate.read_bytes()
    historical = csv_rows(pilot)
    assert len(historical) == 4
    for index, row in enumerate(historical, start=1):
        window = int(row["window"])
        points.append(dict(
            record_kind="analytic_report_point", point_id=f"pilot-{index:04d}",
            cohort="historical-pilot", original_case_id="", source="pilot-screen.csv",
            source_row=index + 1, source_sha256=digest(pilot),
            raw_inputs=json.dumps([f"pilot-screen.csv#row-{index + 1}"]),
            policy=f"Band W{window}" if window else "Dense", seed=int(row["seed"]),
            **{key: int(row[key]) for key in (
                "source_symbols", "warmup_symbols", "measured_symbols", "tail_symbols")},
            **{key: float(row[key]) for key in ("loss_rate", "repair_per_source", *METRICS)},
        ))
    assert len({row["point_id"] for row in points}) == len(points) == 119
    return points, checks


def chart(points, chart_id, include_library):
    figure = go.Figure()
    for metric, label, color, symbol in (
        (METRICS[0], "35 ms deadline misses", "#bc4b32", "circle"),
        (METRICS[1], "Unresolved at horizon", "#176c93", "diamond-open"),
    ):
        figure.add_trace(go.Scatter(
            x=list(range(1, len(points) + 1)), y=[100 * row[metric] for row in points],
            mode="markers", name=label, ids=[row["point_id"] for row in points],
            customdata=[[row["point_id"], row["policy"], row["seed"], row["source"],
                         row["source_row"]] for row in points],
            marker=dict(color=color, symbol=symbol, size=9),
            hovertemplate="%{customdata[0]} · %{customdata[1]}<br>Seed %{customdata[2]}"
                          "<br>%{y:.5f}%<br>%{customdata[3]} %{customdata[4]}<extra>%{fullData.name}</extra>",
        ))
    figure.add_hline(y=1, line_dash="dot", line_color="#718096")
    figure.update_layout(
        template="plotly_white", height=340, margin=dict(l=55, r=15, t=15, b=100),
        legend=dict(orientation="h", y=-.28, x=0),
        xaxis_title="Case ordinal within this cohort", yaxis_title="Measured sources (%)",
        hovermode="closest", font=dict(size=12),
    )
    if len(points) <= 15:
        figure.update_xaxes(tickmode="array", tickvals=list(range(1, len(points) + 1)),
                            ticktext=[str(index) for index in range(1, len(points) + 1)])
    if points[0]["cohort"] == "historical-pilot":
        figure.update_xaxes(ticktext=[row["policy"] for row in points],
                            title="Historical pilot policy")
    return figure.to_html(full_html=False, include_plotlyjs=include_library, div_id=chart_id,
                          config=dict(responsive=True, displaylogo=False))


def pilot_png(points, output):
    figure, axis = plt.subplots(figsize=(8, 4.4), layout="constrained")
    x = list(range(1, 5))
    for metric, label, color, marker in (
        (METRICS[0], "35 ms deadline misses", "#bc4b32", "o"),
        (METRICS[1], "Unresolved at horizon", "#176c93", "x"),
    ):
        axis.scatter(x, [100 * row[metric] for row in points], label=label,
                     color=color, marker=marker, s=80)
    axis.axhline(1, linestyle=":", color="#718096", label="1% deadline-miss target")
    axis.set_xticks(x, [f"{row['policy']}\n{row['point_id']}" for row in points])
    axis.set_ylabel("Measured sources (%)")
    axis.set_title("Four historical coding-only pilots · 3,000 measured sources each")
    axis.set_ylim(-.4, 7.2)
    axis.grid(axis="y", alpha=.2)
    axis.legend(loc="upper right", fontsize=9)
    figure.savefig(output / "historical-pilot.png", dpi=170)
    plt.close(figure)


def mobile_layout(page):
    page = page.replace('<meta charset="utf-8">', '<meta charset="utf-8">'
                        '<meta name="viewport" content="width=device-width,initial-scale=1">', 1)
    styles = ".table-scroll{max-width:100%;overflow-x:auto}code,a{overflow-wrap:anywhere}"
    styles += ".historical-coverage{min-width:0}.plotly-graph-div{max-width:100%}"
    styles += "@media(max-width:600px){body{margin:0;padding:14px}h1{font-size:26px}}"
    page = page.replace("</style>", styles + "</style>", 1)
    page = re.sub(r"<table(?=[ >])", '<div class="table-scroll"><table', page)
    return page.replace("</table>", "</table></div>")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    history = output / "report-history"
    history.mkdir(exist_ok=True)
    baseline = history / "preserved-input-hashes.json"
    if not baseline.exists():
        preserved = {str(path.relative_to(output)): digest(path) for path in sorted(output.rglob("*"))
                     if path.is_file() and str(path.relative_to(output)) not in GENERATED
                     and path.relative_to(output).parts[0] not in ("report-history", "report-renderer")}
        baseline.write_text(json.dumps(preserved, indent=2) + "\n")
        (history / "main-before-pilot-backfill.html").write_bytes((output / "report.html").read_bytes())
        (history / "confirmation-before-pilot-backfill.html").write_bytes(
            (output / "confirmation/report.html").read_bytes())
    preserved = json.loads(baseline.read_text())
    assert all(digest(output / path) == expected for path, expected in preserved.items())
    points, checks = load_points(output)
    groups = {cohort: [row for row in points if row["cohort"] == cohort]
              for cohort in ("main", "confirmation", "historical-pilot")}
    with (output / "historical-plot-points.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(points[0]))
        writer.writeheader()
        writer.writerows(points)
    pilot_png(groups["historical-pilot"], output)
    section = '''<section id="historical-coverage" class="historical-coverage">
<h2>Historical coverage · 119 unique analytical cases</h2>
<p>The saved collection contains 100 main-screen cases, 15 longer confirmation cases and four earlier pilot records. All 119 have individually identified points below. Each case appears once per metric. Matched sample sizes remain in separate panels. The report backfill adds zero executions.</p>
<h3>Four earlier pilots</h3>
<p>These saved pilot records use seed 20261110, 4,000 sources, 500 warmup sources, 3,000 measured sources and 500 trailing sources, with 15% erasures and 20% repair/source. The CSV records the miss and unresolved fractions plotted here. P99, throughput, TCP RTT and an original pilot-specific source receipt are absent. The original study snapshot preserves the literal pilot rows that were exported again by the confirmation run.</p>
<p>The two pilot CSV files are byte-identical. Their four rows share the canonical IDs pilot-0001 through pilot-0004. The repeated export contributes zero additional cases. W256 and Dense have equal recorded metrics and remain distinct policy points.</p>
__PILOT__
<p><a href="historical-pilot.png">Four-pilot PNG</a> · <a href="pilot-screen.csv">Original pilot CSV</a> · <a href="confirmation/pilot-screen.csv">Identical confirmation export</a></p>
<h3>Main screen · 100 individual cases</h3>
<p>Each case has 10,000 sources and 6,000 measured sources. IDs main-0001 through main-0100 map directly to the preserved raw JSON files.</p>
__MAIN__
<h3>Longer confirmation · 15 individual cases</h3>
<p>Each case has 100,000 sources and 80,000 measured sources. IDs confirmation-0001 through confirmation-0015 use their own case namespace.</p>
__CONFIRMATION__
<p>All measured sources contribute to these fractions, including unresolved sources. The dotted line marks the 1% deadline-miss target. Source-symbol coding metrics describe the scope of these analytical panels.</p>
<p><a href="historical-plot-points.csv">All 119 plotted records and raw provenance</a> · <a href="historical-plot-coverage.json">Coverage and duplicate-export receipt</a> · <a href="report-render-provenance.json">Report-only provenance</a></p>
</section>'''
    section = section.replace("__PILOT__", chart(groups["historical-pilot"], "historical-pilot-chart", True))
    section = section.replace("__MAIN__", chart(groups["main"], "historical-main-chart", False))
    section = section.replace("__CONFIRMATION__", chart(groups["confirmation"], "historical-confirmation-chart", False))
    page = mobile_layout((history / "main-before-pilot-backfill.html").read_text())
    old = "The four earlier pilot cases remain in their CSV."
    assert old in page
    page = page.replace(old, "The four earlier pilot cases are plotted separately below with their recorded metrics and provenance.")
    page = page.replace("<h2>Policy and sender causality</h2>", section + "<h2>Policy and sender causality</h2>", 1)
    (output / "report.html").write_text(page)
    confirmation = mobile_layout((history / "confirmation-before-pilot-backfill.html").read_text())
    note = '''<section id="historical-coverage"><h2>Individual case coverage</h2>
<p>The 15 confirmation cases are individually plotted in the parent report using IDs confirmation-0001 through confirmation-0015. The local pilot-screen.csv repeats the parent's four historical pilot rows byte for byte. The collection has 119 unique cases after deduplication.</p>
<p><a href="../report.html#historical-coverage">All individual analytical plots and four historical pilots</a> · <a href="../historical-plot-coverage.json">Coverage receipt</a></p></section>'''
    confirmation = confirmation.replace("<h2>Policy and sender causality</h2>", note + "<h2>Policy and sender causality</h2>", 1)
    (output / "confirmation/report.html").write_text(confirmation)
    coverage = dict(
        record_kind="analytic_report_coverage", report_only=True, new_simulation_executions=0,
        unique_cases=119, main_cases=100, confirmation_cases=15, historical_pilot_cases=4,
        metric_marks=238, plotted_ids=[row["point_id"] for row in points],
        missing_case_ids=[], cohort_checks=checks,
        duplicate_export=dict(canonical="pilot-screen.csv", alias="confirmation/pilot-screen.csv",
                              sha256=digest(output / "pilot-screen.csv"), byte_identical=True,
                              rows=4, additional_cases=0,
                              evidence="Both frozen rtt_budget_analysis_v2.py snapshots export the same four literal historical pilot records."),
        pilot_provenance_limit="The historical CSV and literal frozen export are retained. An original pilot-specific execution source hash, raw JSON, P99 and throughput are absent.",
        exact_reference_rows=dict(main=len(csv_rows(output / "exact-generation-reference.csv")),
                                  confirmation=len(csv_rows(output / "confirmation/exact-generation-reference.csv")),
                                  classification="Deterministic formula references, excluded from sampled-case counts."),
        preserved_inputs=preserved, preserved_inputs_unchanged=True,
    )
    (output / "historical-plot-coverage.json").write_text(json.dumps(coverage, indent=2) + "\n")
    renderer = output / "report-renderer"
    renderer.mkdir(exist_ok=True)
    snapshot = renderer / Path(__file__).name
    snapshot.write_bytes(Path(__file__).read_bytes())
    generated = ["report.html", "confirmation/report.html", "historical-plot-points.csv",
                 "historical-pilot.png", "historical-plot-coverage.json"]
    provenance = dict(
        record_kind="analytic_report_render_provenance", report_only=True,
        rendered_at_utc=datetime.now(timezone.utc).isoformat(), new_simulation_executions=0,
        renderer=str(Path(__file__).resolve()), renderer_sha256=digest(snapshot),
        renderer_snapshot=str(snapshot.relative_to(output)),
        original_reports={str(path.relative_to(output)): digest(path) for path in history.glob("*.html")},
        outputs={name: digest(output / name) for name in generated},
        preserved_input_hashes="report-history/preserved-input-hashes.json",
        preserved_inputs_unchanged=all(digest(output / path) == expected for path, expected in preserved.items()),
    )
    assert provenance["preserved_inputs_unchanged"]
    (output / "report-render-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(json.dumps(dict(unique_cases=119, metric_marks=238, duplicate_pilot_rows=4,
                          new_executions=0, preserved_inputs=len(preserved))))


if __name__ == "__main__":
    main()
