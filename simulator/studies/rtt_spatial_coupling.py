"""Finite GF256 spatial-coupling screen with a charged causal parity pipeline."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache
from hashlib import sha256
from heapq import heappop, heappush
from html import escape
import importlib.util
import json
from pathlib import Path
from random import Random
from time import perf_counter

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

if __package__:
    from . import rtt_checkpoint_repairs as reference
else:
    import rtt_checkpoint_repairs as reference
from l2tunnel_sim.coding import Decoder, PRODUCT
from l2tunnel_sim.compact import coefficient
from l2tunnel_sim.stats import mean_ci, paired_difference


SEEDS = (20261110, 20261111, 20261112)
PROFILES = [dict(name="Fresh dense W128 G26", lift=0),
            dict(name="SC-LDPC M4 G26", lift=4), dict(name="SC-LDPC M8 G26", lift=8)]
COLORS = ("#1764ab", "#d16b25", "#16816a")
METRICS = ("deadline_miss_fraction", "unresolved_at_horizon_fraction",
           "recovered_only_created_to_known_p99_ms")
SOURCES = ("https://arxiv.org/pdf/1010.4548", "https://arxiv.org/pdf/1411.4373",
           "https://arxiv.org/pdf/2003.04421")


def alpha_power(exponent):
    result = 1
    for _ in range(exponent):
        result = PRODUCT[result][2]
    return result


@lru_cache(maxsize=512)
def block_entries(lift, lag, column, row):
    """Fixed weighted circulant lift of B0=222222, B1=010101, B2=101010."""
    if lag == 0:
        if column == 5:
            return ((row, 1), ((row + 1) % lift, 2))
        return (((row + column) % lift, 1),
                ((row + column + 3) % lift, alpha_power(column + 2)))
    if lag == 1 and column % 2 == 1:
        return (((row + column * column) % lift, alpha_power(column + 1)),)
    if lag == 2 and column % 2 == 0:
        return (((row + column * column + 2) % lift, alpha_power(column + 1)),)
    return ()


def parity_id(source_count, lift, section, index):
    return source_count + section * lift + index


def section_constraints(source_count, lift, section):
    """Public zero-RHS equations. Negative-time source/parity vectors are zero."""
    constraints = []
    for row in range(lift):
        equation = {}
        for lag in range(3):
            prior = section - lag
            if prior < 0:
                continue
            for column in range(6):
                for index, weight in block_entries(lift, lag, column, row):
                    symbol = (prior * 5 * lift + column * lift + index if column < 5
                              else parity_id(source_count, lift, prior, index))
                    equation[symbol] = weight
        constraints.append(equation)
    return constraints


def repair_slot(serial, lift):
    if serial % 26 == 0:
        return "global", None, None
    if not lift:
        return "dense", None, None
    ordinary = serial - serial // 26
    section = (ordinary - 1) // lift - 1
    return ("startup-zero" if section < 0 else "spatial"), section, (ordinary - 1) % lift


def execute(task):
    started = perf_counter()
    count, lift = task["source_count"], task["profile"]["lift"]
    decoder = Decoder()
    known_at = np.full(count, np.inf)
    queue_delay = np.zeros(count)
    forward_rng, reverse_rng = Random(task["seed"]), Random(task["seed"] ^ 0xFED123)
    erasure_hash, feedback_hash, arrival_hash = sha256(), sha256(), sha256()
    sender_base = receiver_prefix = next_constraint_section = 0
    now, last_report = 0., -5.
    pending_feedback = []
    reports = lost_reports = delivered_reports = credit = serial = 0
    minimum_feedback_age = np.inf
    modes, source_supports = Counter(), Counter()
    assembly_finished, first_parity_started = {}, {}
    structural_rows = structural_source_identifications = 0
    received_spatial = 0
    max_global_support = 0
    receiver_trace = sha256()

    def update_known(equation, finish):
        solved = decoder.insert(equation)
        for symbol in solved:
            if symbol < count:
                assert not np.isfinite(known_at[symbol])
                known_at[symbol] = finish
                receiver_trace.update(f"{symbol}/{finish:.12f};".encode())
        return sum(symbol < count for symbol in solved)

    def install_sections(section, finish):
        nonlocal next_constraint_section, structural_rows, structural_source_identifications
        while next_constraint_section <= section:
            for equation in section_constraints(count, lift, next_constraint_section):
                structural_source_identifications += update_known(equation, finish)
                structural_rows += 1
            next_constraint_section += 1

    def receive(equation, finish, section=None):
        nonlocal receiver_prefix, last_report, reports, lost_reports
        if section is not None:
            install_sections(section, finish)
        update_known(equation, finish)
        while receiver_prefix in decoder.known:
            receiver_prefix += 1
        if finish - last_report >= 5:
            last_report = finish
            reports += 1
            lost = reverse_rng.random() < .15
            feedback_hash.update(bytes([lost]))
            if lost:
                lost_reports += 1
            else:
                heappush(pending_feedback, (finish + 70 + 46 * 8 / 10000, receiver_prefix, finish))

    def receive_feedback():
        nonlocal sender_base, delivered_reports, minimum_feedback_age
        while pending_feedback and pending_feedback[0][0] <= now:
            due, prefix, generated = heappop(pending_feedback)
            sender_base = max(sender_base, prefix)
            delivered_reports += 1
            minimum_feedback_age = min(minimum_feedback_age, due - generated)

    def erased():
        lost = forward_rng.random() < .15
        erasure_hash.update(bytes([lost]))
        return lost

    for source in range(count):
        created = source * reference.ARRIVAL_MS
        arrival_hash.update(f"{source}/{created:.12f};".encode())
        now = max(now, created)
        receive_feedback()
        queue_delay[source] = now - created
        now += reference.SOURCE_MS
        if not erased():
            receive({source: 1}, now)
        if lift and (source + 1) % (5 * lift) == 0:
            assembly_finished[(source + 1) // (5 * lift) - 1] = now
        credit += 26
        if credit < 125:
            continue
        credit -= 125
        receive_feedback()
        serial += 1
        mode, section, index = repair_slot(serial, lift)
        modes[mode] += 1
        if mode == "spatial":
            assert (section + 1) * 5 * lift <= source + 1
            assert assembly_finished[section] <= now
            first_parity_started.setdefault(section, now)
        start = sender_base if mode == "global" else max(sender_base, source + 1 - 128)
        if mode in ("global", "dense"):
            assert 0 <= start < source + 1
            assert source + 1 - start <= 65535
            source_supports[source + 1 - start] += 1
            if mode == "global":
                max_global_support = max(max_global_support, source + 1 - start)
        now += reference.REPAIR_MS
        if erased():
            continue
        if mode in ("global", "dense"):
            seed = serial * 2654435761 & 0xffffffff
            receive({symbol: coefficient(seed, symbol) for symbol in range(start, source + 1)}, now)
        elif mode == "spatial":
            received_spatial += 1
            receive({parity_id(count, lift, section, index): 1}, now, section)
        else:
            # A scheduled known-zero vector still occupies a full repair packet.
            receive({}, now)

    selected = np.arange(task["warmup_sources"], count - task["tail_sources"])
    delay = known_at[selected] - selected * reference.ARRIVAL_MS
    finite = np.isfinite(delay)
    measured = len(selected)
    waits = [first_parity_started[section] - finish for section, finish in assembly_finished.items()
             if section in first_parity_started]
    assert serial == count * 26 // 125
    assert modes["global"] == serial // 26
    assert minimum_feedback_age >= 70
    assert structural_source_identifications == 0
    return dict(task, record_kind="analytic_spatial_coupling_case", protocol_executions=0,
        policy=task["profile"]["name"], payload_bytes=1448, forward_mbps=100, reverse_mbps=10,
        base_rtt_ms=70, loss_rate=.15, loss_model="iid", source_ip_bytes=1496,
        repair_ip_bytes=1500, source_symbol_bytes=1460, source_header_bytes=36,
        repair_header_bytes=40, feedback_ip_bytes=46, source_arrival_ms=reference.ARRIVAL_MS,
        source_arrival_trace_sha256=arrival_hash.hexdigest(), repair_packets=serial,
        repair_per_source=serial / count, global_repair_packets=modes["global"],
        dense_repair_packets=modes["dense"], spatial_repair_packets=modes["spatial"],
        charged_startup_zero_packets=modes["startup-zero"], startup_zero_wire_bytes=1500 * modes["startup-zero"],
        unassembled_partial_section_sources=count % (5 * lift) if lift else 0,
        assembled_unsent_parity_symbols=len(assembly_finished) * lift - modes["spatial"] if lift else 0,
        uncharged_termination_packets=0, all_scheduled_spatial_inputs_ready=True,
        section_source_count=5 * lift, same_section_parity_matrix="I + alpha*S" if lift else None,
        nominal_spatial_rate=5 / 6 if lift else None, structural_zero_rhs_rows=structural_rows,
        structural_source_identifications=structural_source_identifications,
        received_spatial_parity_value_observations=received_spatial,
        assembly_to_first_parity_start_min_ms=min(waits) if waits else None,
        assembly_to_first_parity_start_max_ms=max(waits) if waits else None,
        forward_total_wire_bytes=count * 1496 + serial * 1500,
        reverse_feedback_packets=reports, reverse_feedback_wire_bytes=reports * 46,
        lost_feedback_packets=lost_reports, delivered_feedback_reports=delivered_reports,
        pending_feedback_reports=len(pending_feedback), minimum_feedback_age_ms=minimum_feedback_age,
        erasure_trace_sha256=erasure_hash.hexdigest(), feedback_erasure_trace_sha256=feedback_hash.hexdigest(),
        source_recovery_trace_sha256=receiver_trace.hexdigest(), measured_sources=measured,
        coding_deadline_ms=35, deadline_miss_count=int(np.count_nonzero(delay > 35)),
        deadline_miss_fraction=float(np.mean(delay > 35)), unresolved_count=int(np.count_nonzero(~finite)),
        unresolved_at_horizon_fraction=float(np.mean(~finite)),
        recovered_only_created_to_known_p99_ms=float(np.percentile(delay[finite], 99)),
        unconditional_created_to_known_p99_ms=float(np.percentile(delay, 99)) if finite.all() else None,
        ideal_application_service_ceiling_mbps=1448 * 8 / reference.ARRIVAL_MS / 1000,
        sender_queue_p99_ms=float(np.percentile(queue_delay[selected], 99)),
        maximum_source_queue_ms=float(queue_delay.max()), horizon_ms=now,
        final_known_sources=int(np.count_nonzero(np.isfinite(known_at))),
        final_receiver_prefix=receiver_prefix, final_sender_confirmed_prefix=sender_base,
        final_known_parity_variables=sum(symbol >= count for symbol in decoder.known),
        remaining_decoder_rows=len(decoder.rows), maximum_global_source_support=max_global_support,
        source_only_repair_support_histogram=dict(source_supports), compute_seconds=perf_counter() - started)


def summarize(rows):
    control = {row["seed"]: row for row in rows if row["profile"]["lift"] == 0}
    summaries = []
    for profile in PROFILES:
        group = sorted((row for row in rows if row["policy"] == profile["name"]), key=lambda row: row["seed"])
        item = dict(record_kind="analytic_spatial_coupling_summary", policy=profile["name"], cases=len(group),
                    raw_inputs=[f"cases/{row['analytic_case_id']:03d}.json" for row in group],
                    frontier_eligible=all(row["unresolved_count"] == 0 for row in group))
        for metric in METRICS:
            item.update({metric + "_" + key: value for key, value in mean_ci([row[metric] for row in group]).items()})
        delta = paired_difference([row[METRICS[0]] for row in group], [control[row["seed"]][METRICS[0]] for row in group])
        item.update({"paired_miss_difference_" + key: value for key, value in delta.items()})
        summaries.append(item)
    return summaries


def render(output, rows, summaries):
    figure = make_subplots(rows=2, cols=2, subplot_titles=("35 ms source deadline", "Recovered-only source P99",
                                                           "Every original-source miss case", "Every unresolved case"))
    for profile, color in zip(PROFILES, COLORS):
        group = [row for row in rows if row["policy"] == profile["name"]]
        for grid_row, column, metric, scale in ((1, 1, METRICS[0], 100), (1, 2, METRICS[2], 1),
                                               (2, 1, METRICS[0], 100), (2, 2, METRICS[1], 100)):
            figure.add_trace(go.Scatter(
                x=[row[metric] * scale if grid_row == 1 else row["analytic_case_id"] for row in group],
                y=[row["ideal_application_service_ceiling_mbps"] if grid_row == 1 else row[metric] * scale for row in group],
                ids=[str(row["analytic_case_id"]) for row in group], text=[str(row["analytic_case_id"]) for row in group],
                mode="markers" if grid_row == 1 else "markers+text", textposition="top center",
                marker=dict(color=color, size=8), name=profile["name"], legendgroup=profile["name"],
                showlegend=grid_row == 1 and column == 1, meta=dict(kind="raw-case"),
                customdata=[[row["analytic_case_id"], row["seed"], row["deadline_miss_count"], row["unresolved_count"]] for row in group],
                hovertemplate="Case %{customdata[0]} · seed %{customdata[1]}<br>x %{x:.6g} · y %{y:.6g}"
                              "<br>Misses %{customdata[2]} / 16000<br>Unresolved %{customdata[3]} / 16000<extra>%{fullData.name}</extra>"),
                row=grid_row, col=column)
    eligible = [row for row in summaries if row["frontier_eligible"]]
    for column, metric, scale in ((1, METRICS[0], 100), (2, METRICS[2], 1)):
        if eligible:
            best = min(row[metric + "_mean"] for row in eligible)
            tied = [row for row in eligible if row[metric + "_mean"] == best]
            figure.add_trace(go.Scatter(x=[best * scale] * len(tied), y=[rows[0]["ideal_application_service_ceiling_mbps"]] * len(tied),
                text=[row["policy"] for row in tied], mode="markers", marker=dict(symbol="diamond-open", size=16, color="#203040"),
                meta=dict(kind="mean-frontier"), name="Eligible mean frontier", showlegend=column == 1,
                hovertemplate="%{text}<br>Fully recovered cohort mean<extra></extra>"), row=1, col=column)
    figure.update_xaxes(title_text="Original-source deadline misses (%)", row=1, col=1)
    figure.update_xaxes(title_text="Recovered-only creation-to-known P99 (ms)", row=1, col=2)
    for column in (1, 2):
        figure.update_yaxes(title_text="Optimistic service ceiling (Mbps)", row=1, col=column)
        figure.update_xaxes(title_text="Individual analytical case ID", row=2, col=column)
    figure.update_yaxes(title_text="Deadline misses (%)", row=2, col=1)
    figure.update_yaxes(title_text="Unresolved measured sources (%)", row=2, col=2)
    figure.add_vline(x=1, line_dash="dash", line_color="#a44", row=1, col=1)
    figure.update_layout(height=850, template="plotly_white", margin=dict(l=80, r=30, t=65, b=120),
                         legend=dict(orientation="h", y=-.2))
    table = "".join(f'<tr><td>{escape(row["policy"])}</td><td>{100*row[METRICS[0]+"_mean"]:.4f}%</td>'
                    f'<td>{100*row[METRICS[1]+"_mean"]:.4f}%</td><td>{row[METRICS[2]+"_mean"]:.3f}</td>'
                    f'<td>{100*row["paired_miss_difference_mean"]:.4f} '
                    f'[{100*row["paired_miss_difference_ci_low"]:.4f}, {100*row["paired_miss_difference_ci_high"]:.4f}]</td></tr>'
                    for row in summaries)
    budgets = "".join(f'<tr><td>{escape(row["policy"])}</td><td>{row["global_repair_packets"]}</td>'
                      f'<td>{row["dense_repair_packets"]}</td><td>{row["spatial_repair_packets"]}</td>'
                      f'<td>{row["charged_startup_zero_packets"]}</td><td>{row["assembled_unsent_parity_symbols"]}</td></tr>'
                      for row in rows if row["seed"] == SEEDS[0])
    passed = sum(row[METRICS[0]] <= .01 for row in rows)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spatially coupled parity-check screen</title><style>body{max-width:1250px;margin:25px auto;padding:18px;font:16px/1.5 system-ui;color:#213547}
.scroll{max-width:100%;overflow:auto}.chart{min-width:1100px}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}code,a{overflow-wrap:anywhere}</style>
<h1>Spatially coupled GF256 parity checks</h1>
<p>__PASS__ of nine coding-only cases meet the 1% original-source 35 ms miss threshold. Every case appears in all four panels, including unresolved and dominated outcomes. Three paired seeds per profile each contain 20,000 original sources, 2,000 warmup and 2,000 trailing sources. All 16,000 measured sources remain in the deadline denominator.</p>
<h2>Concrete construction and causal pipeline</h2>
<p>The fixed lift uses <code>B0=[2,2,2,2,2,2], B1=[0,1,0,1,0,1], B2=[1,0,1,0,1,0]</code>, with five source-vector columns and one parity-vector column per section. Its interior variable degree is three and check degree is eighteen. Lifts M4 and M8 are separate configurations. Each section has 5M complete 1460-byte source symbols and M parity symbols. The same-section parity matrix is <code>I+alpha*S</code>, where S is a cyclic shift and alpha=2 in GF256 with polynomial 0x11d. It is invertible for M4/M8 because alpha has order 255 and alpha^M differs from one. Exact weighted shifts are frozen in <code>block_entries</code>.</p>
<p>The encoder collects every source input of section t before emitting any parity from t. Ordinary repair ordinal o emits section <code>floor((o-1)/M)-1</code>, index <code>(o-1) mod M</code>. Its first M slots send known-zero startup packets at full cost. Source timestamps remain their fixed arrival times. Section collection and the pipeline delay therefore count toward each source's recovery delay. The stream has a known zero initial boundary and continuous later parity state. At the horizon, untransmitted or partial-section parity remains unavailable.</p>
<p>The receiver adds public zero-RHS parity-check constraints and observes a parity value only when its packet arrives. The actual GF256 Decoder retains latent parity variables and identifies any uniquely recoverable source. Finite numerical fixtures independently compare the source-only expanded generator with the augmented parity-check system, including erased parity and same-section inversion. The screen uses exact partial identifiability, with no decoder CPU delay.</p>
<p>The finite decoder offsets parity-variable IDs by the configured source count to keep its algebra namespaces disjoint. This internal mapping supplies no wire information. An online decoder can use tagged source/parity IDs derived from section and index. The fixtures verify an independent shifted parity namespace. Every saved case asserts zero source identifications from structural equations before the corresponding received parity-value observation.</p>
<h2>Charged schedule and matched control</h2>
<p>The unchanged integer 26/125 scheduler sends 25 ordinary repairs and one global source-prefix repair per 125 sources. The .200 ordinary and .008 global ratios sum to .208. Every source costs 1496 bytes and every repair, including startup zeros, costs 1500 bytes on the 100 Mbps forward link. Source arrivals remain 0.14464 ms apart. All nine cases send 36,160,000 forward bytes. Feedback costs 46 bytes, travels on 10 Mbps reverse service after both 35 ms propagation legs, and has independent 15% loss. Prefix feedback is delayed by at least 70.0368 ms.</p>
<p>Source framing uses 28-byte IPv4/UDP plus an 8-byte identifier and the 1460-byte coding symbol. Spatial repairs use 28-byte IPv4/UDP plus a 12-byte header containing type/version (2), section ID (4), parity index (2) and static profile ID (4), followed by 1460 coded bytes. Global repairs retain their 12-byte first-ID/window/seed/type header. This screen charges these sizes and models their identifiers through callbacks. It omits packet-byte serialization, parity-payload arithmetic and TCP. The reported 80.0885 Mbps axis is an optimistic one-1448-byte-payload-per-source service ceiling.</p>
<p>The matched dense control is W128/G26, sharing the exact local/global split. Historical W128/G16 uses a different split and is kept separate in the control comparison CSV. Every source, repair opportunity, forward erasure position and feedback budget is paired within seed. A diamond marks an empirical mean frontier only when all measured sources recover in every replication.</p>
<div class="scroll"><div class="chart">__CHART__</div></div>
<div class="scroll"><table><thead><tr><th>Policy</th><th>35 ms misses</th><th>Unresolved</th><th>Recovered-only P99 ms</th><th>Paired miss change pp [95% CI]</th></tr></thead><tbody>__TABLE__</tbody></table></div>
<h2>Every scheduled repair and the horizon</h2><div class="scroll"><table><thead><tr><th>Policy</th><th>Global</th><th>Dense</th><th>Spatial</th><th>Charged startup zeros</th><th>Assembled unsent parity symbols</th></tr></thead><tbody>__BUDGETS__</tbody></table></div>
<h2>Primary construction context</h2><p>Iyengar and colleagues motivate modified edge spreading with at least two earliest check edges per variable for windowed decoding. This heuristic lift follows that structural rule. Its source and parity variables both have degree three. The previously tested scalar repeat-accumulate recurrence gives parity variables degree two. <a href="https://arxiv.org/pdf/1010.4548">Iyengar et al., Section IV-A and Design Rule 1</a></p>
<p>Nonbinary protograph work motivates GF256 labels, while finite-length analyses emphasize the joint role of lift size and decoding-window size. Their reported thresholds and bit-erasure results do not establish this small-lift packet-erasure configuration's performance. The measured finite outcomes above govern this screen. <a href="https://arxiv.org/pdf/1411.4373">Wei et al.</a> · <a href="https://arxiv.org/pdf/2003.04421">Sokolovskii et al.</a></p>
<p><a href="analytic-cases.csv">All nine raw cases</a> · <a href="analytic-summary.csv">Means and paired intervals</a> · <a href="historical-control-comparison.csv">Separate G26/G16 control comparison</a> · <a href="manifest.json">Frozen source manifest</a> · <a href="validation-checks.json">Coverage and accounting receipt</a> · <a href="numerical-validation.json">Independent numerical validation</a></p></html>'''
    chart = figure.to_html(full_html=False, include_plotlyjs=True, div_id="spatial-coupling-pareto", config=dict(responsive=True))
    (output / "report.html").write_text(page.replace("__PASS__", str(passed)).replace("__CHART__", chart)
                                        .replace("__TABLE__", table).replace("__BUDGETS__", budgets))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    tasks = [dict(analytic_case_id=3 * index + replication + 1, profile=profile, seed=seed,
                  source_count=20000, warmup_sources=2000, tail_sources=2000)
             for index, profile in enumerate(PROFILES) for replication, seed in enumerate(SEEDS)]
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), Path(reference.__file__).resolve(), root / "tests/test_spatial_coupling.py",
             *(root / "src/l2tunnel_sim" / name for name in ("coding.py", "compact.py", "stats.py"))]
    hashes = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_spatial_coupling_manifest", protocol_executions=0,
                    analytic_cases=len(tasks), analytic_tasks=tasks, sources=hashes, primary_sources=SOURCES)
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "manifest.json"
    if target.exists() and json.loads(target.read_text()) != json.loads(json.dumps(manifest)):
        raise ValueError("existing sources or task matrix differ")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    for path in files:
        copy = args.out / "sources" / path.relative_to(root)
        copy.parent.mkdir(parents=True, exist_ok=True)
        if copy.exists() and copy.read_bytes() != path.read_bytes():
            raise ValueError("frozen source snapshot differs")
        copy.write_bytes(path.read_bytes())
    fixture_path = root / "tests/test_spatial_coupling.py"
    specification = importlib.util.spec_from_file_location("spatial_coupling_validation", fixture_path)
    fixtures = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(fixtures)
    numerical = fixtures.finite_validation()
    numerical.update(record_kind="analytic_finite_numeric_validation", protocol_executions=0,
                     fixture_source_sha256=hashes["tests/test_spatial_coupling.py"])
    (args.out / "numerical-validation.json").write_text(json.dumps(numerical, indent=2) + "\n")
    cases = args.out / "cases"
    cases.mkdir(exist_ok=True)
    pending = [task for task in tasks if not (cases / f'{task["analytic_case_id"]:03d}.json').exists()]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            row["execution_source_sha256"] = hashes
            target = cases / f'{row["analytic_case_id"]:03d}.json'
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
            temporary.replace(target)
            print(f'Case {row["analytic_case_id"]} {row["policy"]} miss={100*row[METRICS[0]]:.4f}% '
                  f'unresolved={100*row[METRICS[1]]:.4f}% seconds={row["compute_seconds"]:.2f}', flush=True)
    rows = [json.loads((cases / f'{task["analytic_case_id"]:03d}.json').read_text()) for task in tasks]
    for seed in SEEDS:
        paired = [row for row in rows if row["seed"] == seed]
        for field in ("erasure_trace_sha256", "feedback_erasure_trace_sha256", "source_arrival_trace_sha256",
                      "forward_total_wire_bytes", "reverse_feedback_wire_bytes", "measured_sources", "horizon_ms"):
            assert len({row[field] for row in paired}) == 1
    changed = [name for name, digest in hashes.items() if sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not changed, changed
    summaries = summarize(rows)
    reference.write_csv(args.out / "analytic-cases.csv", rows)
    reference.write_csv(args.out / "analytic-summary.csv", summaries)
    comparisons = []
    historical = args.out.parent / "rolling-accumulator-screen/cases"
    for path in sorted(historical.glob("*.json")):
        prior = json.loads(path.read_text())
        if prior["policy"] != "Fresh dense W128 G16":
            continue
        current = next(row for row in rows if row["profile"]["lift"] == 0 and row["seed"] == prior["seed"])
        comparisons.append(dict(record_kind="analytic_control_comparison", seed=prior["seed"],
            raw_inputs=[str(path.resolve()), str((cases / f'{current["analytic_case_id"]:03d}.json').resolve())],
            historical_policy=prior["policy"], current_policy=current["policy"],
            historical_miss_fraction=prior[METRICS[0]], current_miss_fraction=current[METRICS[0]],
            miss_difference_pp=100*(current[METRICS[0]]-prior[METRICS[0]]),
            historical_p99_ms=prior[METRICS[2]], current_p99_ms=current[METRICS[2]],
            same_forward_trace=prior["erasure_trace_sha256"] == current["erasure_trace_sha256"],
            same_forward_bytes=prior["forward_total_wire_bytes"] == current["forward_total_wire_bytes"],
            historical_raw_sha256=sha256(path.read_bytes()).hexdigest()))
    reference.write_csv(args.out / "historical-control-comparison.csv", comparisons)
    checks = dict(cases=len(rows), panels=4, points_per_panel=len(rows),
        plotted_case_ids=[row["analytic_case_id"] for row in rows], paired_forward_erasure_trace=True,
        paired_reverse_erasure_trace=True, fixed_source_arrivals=True, fixed_forward_byte_budget=True,
        paired_feedback_byte_budget=True, original_source_denominator=True, changed_during_run=changed,
        all_spatial_inputs_assembled_before_transmission=True, uncharged_termination_packets=0,
        structural_source_identifications=sum(row["structural_source_identifications"] for row in rows),
        raw_case_sha256={path.name: sha256(path.read_bytes()).hexdigest() for path in sorted(cases.glob("*.json"))})
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    render(args.out, rows, summaries)


if __name__ == "__main__":
    main()
