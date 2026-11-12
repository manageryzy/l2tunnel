"""Finite GF256 heuristic using the LRSC causal staircase support pattern."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache
from hashlib import sha256
from html import escape
from itertools import product
import json
from pathlib import Path
import platform

import numpy as np

from l2tunnel_sim.coding import Decoder, block_coefficients

if __package__:
    from . import subpacket_convolutional as reference
else:
    import subpacket_convolutional as reference


GROUPS = (16, 32, 48)
PRIMARY_SOURCE = "https://arxiv.org/html/2109.03168v1"


@lru_cache(maxsize=3)
def coefficients(groups):
    """Gamma[i,j] = inverse(i XOR (5+j)) in the existing GF256 field."""
    if not 1 <= groups <= 251:
        raise ValueError("Cauchy dimensions must fit GF256")
    return tuple(block_coefficients(5, column) for column in range(groups))


def parity_equation(packet, groups):
    """Each source shard i first participates at source_time + 5 - i."""
    equation = {}
    for group, column in enumerate(coefficients(groups)):
        for shard, coefficient in enumerate(column):
            source_packet = packet - 5 - 6 * group + shard
            if source_packet >= 0:
                equation[source_packet * 5 + shard] = coefficient
    return equation


def execute(task):
    original = reference.parity_equation
    groups = task["profile"]["staircase_groups"]
    reference.parity_equation = lambda packet, memory, invariant: parity_equation(packet, groups)
    try:
        row = reference.execute(task)
    finally:
        reference.parity_equation = original
    row.update(record_kind="analytic_lrsc_staircase_case", coefficient_rule="GF256 Cauchy5xa; alpha_j=1",
               construction_guarantee="heuristic derivative; published field-tower guarantee does not apply",
               repair_source_byte_ratio=.2, maximum_parity_degree=5 * groups,
               minimum_parity_lag_packets=1, maximum_parity_lag_packets=6 * groups - 1,
               primary_construction_source=PRIMARY_SOURCE)
    for prefix in ("source", "record_local", "record_inorder"):
        count = row[prefix + "_count"]
        row[prefix + "_deadline_miss_count"] = round(count * row[prefix + "_deadline_miss_fraction"])
        row[prefix + "_unresolved_count"] = round(count * row[prefix + "_unresolved_fraction"])
    return row


def multiply(left, right):
    """Independent polynomial arithmetic, without repository lookup tables."""
    result = 0
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left & 256:
            left ^= 0x11D
    return result


def dense_identifiable(equations, values, symbols):
    """Independent dense Gauss-Jordan with four actual byte RHS columns."""
    matrix = []
    for equation in equations:
        row = [equation.get(index, 0) for index in range(symbols)] + [0] * 4
        for index, coefficient in equation.items():
            for byte in range(4):
                row[symbols + byte] ^= multiply(coefficient, values[index][byte])
        matrix.append(row)
    pivot_row = 0
    for column in range(symbols):
        selected = next((index for index in range(pivot_row, len(matrix)) if matrix[index][column]), None)
        if selected is None:
            continue
        matrix[pivot_row], matrix[selected] = matrix[selected], matrix[pivot_row]
        row = matrix[pivot_row]
        inverse = next(value for value in range(1, 256) if multiply(row[column], value) == 1)
        matrix[pivot_row] = [multiply(value, inverse) for value in row]
        row = matrix[pivot_row]
        for index in range(len(matrix)):
            if index != pivot_row and matrix[index][column]:
                factor = matrix[index][column]
                matrix[index] = [left ^ multiply(factor, right) for left, right in zip(matrix[index], row)]
        pivot_row += 1
    known = {}
    for row in matrix:
        nonzero = [index for index in range(symbols) if row[index]]
        if len(nonzero) == 1:
            known[nonzero[0]] = bytes(row[symbols:])
    return known, pivot_row


def validate():
    states = 0
    numeric_values = [bytes(((index * 17 + byte * 73 + 11) & 255) for byte in range(4))
                      for index in range(18 * 5)]
    for pattern in product((False, True), repeat=3):
        decoder, equations = Decoder(), []
        for packet in range(18):
            if packet >= 3 or not pattern[packet]:
                incoming = [{packet * 5 + shard: 1} for shard in range(5)] + [parity_equation(packet, 3)]
                for equation in incoming:
                    decoder.insert(equation)
                    equations.append(equation)
            if packet % 3 == 2:
                known, rank = dense_identifiable(equations, numeric_values, 18 * 5)
                assert set(known) == decoder.known
                assert rank == len(decoder.known) + len(decoder.rows)
                assert all(value == numeric_values[index] for index, value in known.items())
                states += 1
    decoder = Decoder()
    isolated_release = {}
    for packet in range(16):
        if packet == 10:
            continue
        for shard in range(5):
            decoder.insert({packet * 5 + shard: 1})
        for index in decoder.insert(parity_equation(packet, 48)):
            if index // 5 == 10:
                isolated_release[index % 5] = packet - 10
    assert isolated_release == {4: 1, 3: 2, 2: 3, 1: 4, 0: 5}
    return dict(independent_numeric_states=states, erasure_patterns=8, byte_rhs_columns=4,
                isolated_loss_release_lags=isolated_release, rank_and_payload_values_match=True,
                protocol_executions=0)


def configuration_frontier(rows, prefix):
    """Means of complete planned cohorts, minimizing misses and maximizing offered rate."""
    candidates = []
    for policy in dict.fromkeys(row["policy"] for row in rows):
        selected = [row for row in rows if row["policy"] == policy]
        complete = len(selected) == len(reference.SEEDS) and {row["seed"] for row in selected} == set(reference.SEEDS)
        complete = complete and all(row[metric + "_count"] > 0 and row[metric + "_unresolved_count"] == 0
                                    for row in selected for metric in ("source", "record_local", "record_inorder"))
        if complete:
            candidates.append(dict(policy=policy, n=len(selected),
                deadline_miss_percent=float(np.mean([100 * row[prefix + "_deadline_miss_fraction"] for row in selected])),
                offered_application_rate_mbps=float(np.mean([row["offered_application_rate_mbps_analytic"] for row in selected]))))
    return [point for point in candidates if not any(
        other["deadline_miss_percent"] <= point["deadline_miss_percent"] and
        other["offered_application_rate_mbps"] >= point["offered_application_rate_mbps"] and
        (other["deadline_miss_percent"] < point["deadline_miss_percent"] or
         other["offered_application_rate_mbps"] > point["offered_application_rate_mbps"])
        for other in candidates)]


def render(output, rows, summary):
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    figure = make_subplots(rows=2, cols=2, subplot_titles=(
        "Source deadline misses versus offered rate", "Complete-record local misses versus offered rate",
        "Every case ID and source deadline misses", "Every case ID and ordered-record deadline misses"))
    for index, groups in enumerate(GROUPS):
        selected = [row for row in rows if row["profile"]["staircase_groups"] == groups]
        color = ("#2b6c99", "#25846b", "#b47125")[index]
        for column, prefix in ((1, "source"), (2, "record_local")):
            figure.add_trace(go.Scatter(
                x=[100 * row[prefix + "_deadline_miss_fraction"] for row in selected],
                y=[row["offered_application_rate_mbps_analytic"] for row in selected], mode="markers",
                marker=dict(size=11, color=color), name=f"Cauchy a={groups}", legendgroup=str(groups),
                showlegend=column == 1,
                customdata=[[row["analytic_case_id"], row["seed"], row[prefix + "_count"],
                             row[prefix + "_deadline_miss_count"], row[prefix + "_unresolved_count"]]
                            for row in selected],
                hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}<br>Miss %{x:.4f}% · rate %{y:.5f} Mbps"
                              "<br>Misses %{customdata[3]}/%{customdata[2]} · unresolved %{customdata[4]}<extra></extra>"),
                row=1, col=column)
        for column, prefix in ((1, "source"), (2, "record_inorder")):
            figure.add_trace(go.Scatter(x=[row["analytic_case_id"] for row in selected],
                y=[100 * row[prefix + "_deadline_miss_fraction"] for row in selected], mode="markers+text",
                text=[str(row["analytic_case_id"]) for row in selected], textposition="top center",
                marker=dict(size=10, color=color), showlegend=False, legendgroup=str(groups),
                hovertemplate="Case %{x}<br>Deadline misses %{y:.4f}%<extra></extra>"), row=2, col=column)
    for column, prefix in ((1, "source"), (2, "record_local")):
        frontier = sorted(configuration_frontier(rows, prefix), key=lambda point: point["deadline_miss_percent"])
        figure.add_trace(go.Scatter(
            x=[point["deadline_miss_percent"] for point in frontier],
            y=[point["offered_application_rate_mbps"] for point in frontier],
            mode="lines+markers", name="Eligible mean frontier · offered rate", legendgroup="mean-frontier",
            showlegend=column == 1, marker=dict(symbol="diamond-open", size=18, color="#202b3a", line=dict(width=2)),
            line=dict(color="#202b3a", width=2),
            customdata=[[point["policy"], point["n"]] for point in frontier],
            meta=dict(trace_kind="configuration_mean_frontier", case_trace=False, metric=prefix),
            hovertemplate="%{customdata[0]} · %{customdata[1]} seeds<br>Mean miss %{x:.4f}%"
                          "<br>Offered rate %{y:.5f} Mbps<extra></extra>"), row=1, col=column)
    for column in (1, 2):
        figure.add_vline(x=1, row=1, col=column, line_dash="dash", line_color="#a44")
        figure.add_hline(y=80, row=1, col=column, line_dash="dash", line_color="#a44")
        figure.add_hline(y=1, row=2, col=column, line_dash="dash", line_color="#a44")
        figure.update_xaxes(title_text="Full-cohort deadline misses (%)", row=1, col=column)
        figure.update_yaxes(title_text="Offered application Mbps", row=1, col=column)
        figure.update_xaxes(title_text="Individual case ID", dtick=1, row=2, col=column)
        figure.update_yaxes(title_text="Full-cohort deadline misses (%)", row=2, col=column)
    figure.update_layout(height=850, width=1150, template="plotly_white", margin=dict(t=70, l=70, r=30, b=80),
                         legend=dict(orientation="h", y=-.1))
    plot = figure.to_html(full_html=False, include_plotlyjs=True, div_id="all-lrsc-cases")
    case_rows = []
    for row in rows:
        cells = [f'<a href="cases/{row["analytic_case_id"]:03d}.json">{row["analytic_case_id"]}</a>',
                 escape(row["policy"]), str(row["seed"])]
        for prefix in ("source", "record_local", "record_inorder"):
            cells.append(f'{row[prefix + "_deadline_miss_count"]}/{row[prefix + "_count"]} '
                         f'({100 * row[prefix + "_deadline_miss_fraction"]:.3f}%)')
            cells.append(str(row[prefix + "_unresolved_count"]))
        cells.append(f'{row["source_recovered_only_p99_ms"]:.3f}')
        case_rows.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>")
    summary_rows = []
    for item in summary:
        summary_rows.append("<tr>" + "".join(f"<td>{value}</td>" for value in (
            escape(item["policy"]), f'{100 * item["source_deadline_miss_fraction"]:.3f}%',
            f'{100 * item["record_local_deadline_miss_fraction"]:.3f}%',
            f'{100 * item["record_inorder_deadline_miss_fraction"]:.3f}%',
            f'{100 * item["source_unresolved_fraction"]:.3f}%')) + "</tr>")
    first = rows[0]
    (output / "report.html").write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>GF256 staircase partial-recovery screen</title>
<style>body{{font:16px/1.5 system-ui;max-width:1200px;margin:24px auto;padding:18px;color:#233748}}.scroll{{overflow-x:auto;max-width:100%}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border-bottom:1px solid #cbd4df;padding:8px;text-align:left}}th{{background:#edf3f7}}code{{overflow-wrap:anywhere;background:#edf3f7}}.notice{{padding:15px;background:#fff0d8;border-left:5px solid #a35e20}}a{{color:#12688d}}</style>
<h1>GF256 staircase partial recovery</h1>
<p class="notice">Nine finite coding-only cases use a heuristic derivative of a published LRSC support pattern. Its field-tower theorem does not apply to these GF256 coefficients. The offered rate is a byte-accounted input budget. Actual TCP goodput and cumulative ACK completion require a protocol experiment.</p>
<h2>Causal coefficients</h2><p><code>p[t] = sum(j=0..a−1, i=0..4) Gamma[i,j] s_i[t−5−6j+i]</code>, with negative-time sources zero. <code>Gamma[i,j] = inverse(i XOR (5+j))</code> uses GF256 and polynomial 0x11D. All coefficients are fixed by the profile, with no receiver-state input. Groups a=16,32,48 give maximum lags 95,191,287 packets. An isolated erased packet with a known past reveals its five coordinates separately in the next five successful packet positions.</p>
<p>The paper's construction uses the same staggered time indices and scales Cauchy columns by elements in successive extension fields. Its full guarantee requires field size <code>q^(2^(a−2))</code>, with <code>q ≥ a+4</code> here. This screen sets every column scale to one within GF256, preserving the causal support while testing the resulting finite-field rank directly. <a href="{PRIMARY_SOURCE}">Ramkumar, Vajha and Kumar, Eq. (4) and Construction 1</a></p>
<h2>Matched packet service</h2><p>Every IP datagram is 1500 bytes, comprising IPv4/UDP 28, FEC header 8 and six 244-byte vectors. Five vectors carry new source bytes and one carries parity. The entire datagram shares one 15% IID erasure event. All packets consume 100 Mbps service. The source block has a 4-byte valid-length/resynchronization header and 1216 record bytes. Actual full frame records, codec contexts, channel headers and padding follow the existing subpacket-convolutional study unchanged.</p>
<p>The same source stream offers {first['offered_application_rate_mbps_analytic']:.7f}Mbps after byte framing. Parity/source byte ratio is 20%, with no separate extra repair packets. This packing incurs at least {first['minimum_extra_packets_per_application_record_pct_analytic']:.4f}% extra datagrams per original 1448-byte application record. Authentication and codec CPU time are outside this model.</p>
<h2>Denominators and unrecovered tails</h2><p>Each run sends 12000 packets, with 2000 warmup and 2000 tail packets. The measured cohort retains every source block and every original complete record created in the middle 8000 packet slots. The 35 ms deadline starts at source creation and includes serialization. Unknown observations remain misses. Full source-block release requires all five vectors. Record-local release requires every touched block. Ordered release additionally waits for channel sequence and codec context. Existing received bytes are checked against the original complete frame. Partial bytes in an incomplete block remain withheld by the matched receiver policy.</p>
<p>Recovered-only source P99 excludes unresolved observations and is shown alongside their counts. Its value cannot establish a full-cohort latency target. Both rate-versus-miss panels retain every case, and the case-ID panels separate tied or overlapping coordinates.</p>
<p>Outlined diamonds mark the configuration-mean Pareto frontier for offered application rate versus deadline misses. Eligibility requires all three planned seeds and zero unresolved measured sources, local records and ordered records in every seed. Dominance minimizes misses and maximizes the offered rate. Exact tied nondominated configurations are retained. Here a32 dominates a48 at their identical offered rate, while a16 is ineligible because measured observations remain unresolved. These markers summarize input-rate tradeoffs and carry no measured TCP-throughput claim.</p>
<div class="scroll">{plot}</div>
<h2>Three-seed means</h2><div class="scroll"><table><tr><th>Policy</th><th>Source miss</th><th>Record-local miss</th><th>Ordered-record miss</th><th>Source unresolved</th></tr>{''.join(summary_rows)}</table></div>
<h2>Every executed case</h2><div class="scroll"><table><tr><th>JSON</th><th>Policy</th><th>Seed</th><th>Source misses/count</th><th>Source unresolved</th><th>Record-local misses/count</th><th>Local unresolved</th><th>Ordered misses/count</th><th>Ordered unresolved</th><th>Recovered-only source P99 ms</th></tr>{''.join(case_rows)}</table></div>
<h2>Validation and provenance</h2><p>An independent dense GF256 elimination implementation checks eight erasure patterns using four actual byte-valued right-hand sides, comparing recovered values, individual identifiability and rank with the simulator. A single-loss regression verifies coordinate recovery at lags 1, 2, 3, 4, 5. Source and loss hashes are paired with the saved M256 controls. No protocol source was changed.</p>
<p><a href="analytic-cases.csv">Every case CSV</a> · <a href="analytic-summary.csv">Seed means and intervals</a> · <a href="paired-controls.csv">Paired M256 comparisons</a> · <a href="manifest.json">Frozen task plan and sources</a> · <a href="validation-checks.json">Validation receipt</a> · <a href="../subpacket-convolutional-screen/report.html">Saved convolutional controls</a></p></html>''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2, choices=(1, 2))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "cases").mkdir(exist_ok=True)
    tasks = [dict(analytic_case_id=1 + group_index * 3 + seed_index, seed=seed, packet_count=12000,
                  warmup_packets=2000, tail_packets=2000, loss_rate=.15,
                  profile=dict(name=f"Cauchy staircase a{groups}", staircase_groups=groups,
                               memory=6 * groups - 1, invariant=True))
             for group_index, groups in enumerate(GROUPS) for seed_index, seed in enumerate(reference.SEEDS)]
    simulator = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(reference.__file__),
             *(simulator / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "shared_records.py", "stats.py"))]
    hashes = {str(path): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_lrsc_staircase_manifest", protocol_executions=0,
                    analytic_tasks=tasks, sources=hashes, python=platform.python_version(), numpy=np.__version__,
                    primary_sources=[PRIMARY_SOURCE],
                    guarantee="GF256 heuristic only; published field-tower theorem not adopted")
    manifest_path = args.out / "manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing frozen manifest differs")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    (args.out / "sources").mkdir(exist_ok=True)
    for path in files:
        (args.out / "sources" / path.name).write_bytes(path.read_bytes())
    validation = validate()
    print(f"Independent validation passed at {validation['independent_numeric_states']} numeric states", flush=True)
    rows, pending = [], []
    for task in tasks:
        path = args.out / "cases" / f"{task['analytic_case_id']:03d}.json"
        if path.exists():
            rows.append(json.loads(path.read_text()))
        else:
            pending.append(task)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            rows.append(row)
            path = args.out / "cases" / f"{row['analytic_case_id']:03d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row, indent=2))
            temporary.replace(path)
            print(f"Saved {row['analytic_case_id']:02d} {row['policy']} sourceMiss={100 * row['source_deadline_miss_fraction']:.3f}% recordMiss={100 * row['record_local_deadline_miss_fraction']:.3f}% seconds={row['compute_seconds']:.1f}", flush=True)
    rows.sort(key=lambda row: row["analytic_case_id"])
    summary = reference.summarize(rows)
    for item in summary:
        item["record_kind"] = "analytic_lrsc_staircase_summary"
    reference.write_csv(args.out / "analytic-cases.csv", rows)
    reference.write_csv(args.out / "analytic-summary.csv", summary)
    controls_dir = args.out.parent / "subpacket-convolutional-screen" / "cases"
    controls = [json.loads(path.read_text()) for path in sorted(controls_dir.glob("*.json"))]
    controls = {row["seed"]: row for row in controls if row["policy"] == "Time-varying M256"}
    paired = []
    for row in rows:
        control = controls[row["seed"]]
        for field in ("source_bytes_sha256", "erasure_trace_sha256", "forward_wire_bytes_analytic",
                      "offered_application_rate_mbps_analytic", "source_count", "record_local_count"):
            assert row[field] == control[field], field
        item = dict(record_kind="analytic_lrsc_paired_comparison", analytic_case_id=row["analytic_case_id"],
                    control_case_id=control["analytic_case_id"], seed=row["seed"], policy=row["policy"])
        for prefix in ("source", "record_local", "record_inorder"):
            field = prefix + "_deadline_miss_fraction"
            item[field + "_difference"] = row[field] - control[field]
        paired.append(item)
    reference.write_csv(args.out / "paired-controls.csv", paired)
    assert all(sha256(path.read_bytes()).hexdigest() == hashes[str(path)] for path in files)
    validation.update(source_hashes_unchanged=True, all_cases_paired_source_and_loss_hashes=True,
                      analytic_case_ids=[row["analytic_case_id"] for row in rows], plotted_point_instances=len(rows) * 4)
    (args.out / "validation-checks.json").write_text(json.dumps(validation, indent=2))
    render(args.out, rows, summary)


if __name__ == "__main__":
    main()
