"""Phase-exact analytical busy periods and charged packet granularity.

The generic dense model releases lost originals when its information-deficit
queue empties. The FIFO model has impossible instantaneous loss knowledge.
Neither model is a universal converse or a TCP execution.
"""

import argparse
from collections import deque
import csv
from fractions import Fraction
from hashlib import sha256
from html import escape
import json
from math import ceil, gcd
from pathlib import Path
from random import Random

import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots


LOSS = .15
ORIGINAL_BYTES = 1448
TARGET_ARRIVAL_NS = 144800
SEEDS = (20261110, 20261111, 20261112)
FORMATS = [dict(name="Current protected record", record_bytes=1460, source_header=36, repair_header=40),
           dict(name="Ideal IPv4 UDP, no inner metadata", record_bytes=1448, source_header=28, repair_header=28),
           dict(name="Ideal raw IPv4, no coding metadata", record_bytes=1448, source_header=20, repair_header=20),
           dict(name="Hypothetical zero headers", record_bytes=1448, source_header=0, repair_header=0)]
COLORS = ("#1764ab", "#d16b25", "#16816a", "#8c53a0")
DEADLINES = (5, 10, 20, 35, 50, 70, 105)
RATIO_FORMATS = [dict(name="Proposed raw IPv4 packed mean-byte proxy", record_bytes=1454,
                     source_header=26, repair_header=28, source_ip_bytes=1479.5625, repair_ip_bytes=1488),
                 dict(name="Proposed UDP packed mean-byte proxy", record_bytes=1454,
                      source_header=30, repair_header=32, source_ip_bytes=1483.5625, repair_ip_bytes=1492),
                 FORMATS[3]]


def profile(format_index, chunks, ratio="0.208", template=None):
    fraction = Fraction(ratio)
    numerator, denominator = fraction.numerator, fraction.denominator
    period = denominator // gcd(chunks, denominator)
    result = dict(FORMATS[format_index] if template is None else template, chunks=chunks,
                  repair_numerator=numerator, repair_denominator=denominator,
                  repair_ratio=float(fraction), phase_period=period)
    size = ceil(result["record_bytes"] / chunks)
    result["chunk_bytes"] = [size] * (chunks - 1) + [result["record_bytes"] - size * (chunks - 1)]
    result["repair_bytes"] = size + result["repair_header"]
    if "repair_ip_bytes" in result:
        result["repair_bytes"] = result["repair_ip_bytes"]
    repairs = period * chunks * numerator // denominator
    source_bytes = result.get("source_ip_bytes", result["record_bytes"] + chunks * result["source_header"])
    period_bytes = period * source_bytes + repairs * result["repair_bytes"]
    result["period_bytes"] = period_bytes
    result["ip_bytes_per_original"] = period_bytes / period
    result["byte_service_ceiling_mbps"] = 100 * ORIGINAL_BYTES * period / period_bytes
    result["allows_80_mbps"] = period_bytes <= period * 1810
    # Infeasible formats use their charged service ceiling for the diagnostic.
    # Their offered original clock is explicitly slower and is recorded.
    result["arrival_ns"] = max(TARGET_ARRIVAL_NS, ceil(period_bytes * 80 / period))
    result["offered_application_mbps"] = ORIGINAL_BYTES * 8000 / result["arrival_ns"]
    result["equal_source_repair_header_budget_bytes"] = (1810 - result["record_bytes"] - float(fraction) * chunks * size) / ((1 + float(fraction)) * chunks)
    result["forward_datagrams_per_original"] = chunks * (1 + float(fraction))
    result["extra_forward_packets_pct"] = 100 * (result["forward_datagrams_per_original"] - 1)
    return result


def schedule(config, count):
    events, now, source = [], 0, 0
    numerator, denominator = config["repair_numerator"], config["repair_denominator"]
    for original in range(count):
        now = max(now, original * config["arrival_ns"])
        for chunk_bytes in config["chunk_bytes"]:
            size = config.get("source_ip_bytes", chunk_bytes + config["source_header"])
            service_ns = round(size * 80)
            assert abs(service_ns - size * 80) < 1e-8
            now += service_ns
            events.append((original, "source", source, now, size))
            source += 1
            if source * numerator // denominator > (source - 1) * numerator // denominator:
                now += config["repair_bytes"] * 80
                events.append((original, "repair", source - 1, now, config["repair_bytes"]))
    return events


def birth(values):
    result = values * (1 - LOSS)
    result[1:] += values[:-1] * LOSS
    return result


def death(values, absorb=False):
    result = values * LOSS
    result[:-1] += values[1:] * (1 - LOSS)
    if absorb:
        result[0] = 0
    else:
        result[0] += values[0] * (1 - LOSS)
    return result


def tagged_step(clear, waiting, kind, belongs_to_tag, model):
    """A tag completes only after every one of its lost chunks is identified."""
    if kind == "source":
        if belongs_to_tag:
            next_waiting = birth(waiting)
            next_waiting[1:] += clear[:-1] * LOSS
            return clear * (1 - LOSS), next_waiting
        if model == "dense":
            waiting = birth(waiting)
        return birth(clear), waiting
    released = waiting[1] * (1 - LOSS)
    clear = death(clear)
    clear[0] += released
    return clear, death(waiting, absorb=True)


def cohort_laws(config, queue_states=128, count=20000, warmup=2000, tail=2000):
    numerator, denominator = config["repair_numerator"], config["repair_denominator"]
    period = config["phase_period"]
    law = np.zeros(queue_states)
    law[0] = 1
    phases = np.zeros((period, queue_states))
    phase_counts = np.zeros(period, dtype=int)
    source = 0
    for original in range(count):
        if warmup <= original < count - tail:
            phases[original % period] += law
            phase_counts[original % period] += 1
        for _ in config["chunk_bytes"]:
            law = birth(law)
            source += 1
            if source * numerator // denominator > (source - 1) * numerator // denominator:
                law = death(law)
    assert np.all(phase_counts > 0)
    return phases / phase_counts[:, None], phase_counts, 1 - law.sum()


def exact_tails(config, deadlines=(35,), queue_states=128):
    laws, counts, defect = cohort_laws(config, queue_states)
    period = config["phase_period"]
    horizon = int(max(deadlines) * 1e6 / config["arrival_ns"]) + 2 * period + 5
    events = schedule(config, horizon)
    # Remove the empty-forward-queue startup cycle before extracting each phase.
    first = [next(index for index, event in enumerate(events) if event[0] == period + phase) for phase in range(period)]
    prior_cycle = [event for event in events if period <= event[0] < 2 * period]
    next_cycle = [event for event in events if 2 * period <= event[0] < 3 * period]
    if len(next_cycle) == len(prior_cycle):
        assert all(right[3] - left[3] == period * config["arrival_ns"] for left, right in zip(prior_cycle, next_cycle))
    result = {model: np.zeros(len(deadlines)) for model in ("dense", "fifo_oracle")}
    for phase, begin in enumerate(first):
        original = period + phase
        created = original * config["arrival_ns"]
        for model in result:
            clear, waiting = laws[phase].copy(), np.zeros(queue_states)
            position, tag_sources = begin, 0
            for index, deadline in enumerate(deadlines):
                cutoff = created + round(deadline * 1e6)
                while position < len(events) and events[position][3] <= cutoff:
                    event = events[position]
                    tagged = event[0] == original
                    clear, waiting = tagged_step(clear, waiting, event[1], tagged, model)
                    tag_sources += tagged and event[1] == "source"
                    position += 1
                missed = waiting.sum() if tag_sources == config["chunks"] else laws[phase].sum()
                result[model][index] += missed * counts[phase] / counts.sum()
    return result, defect


def trajectory(seed, config):
    if config["chunks"] != 1:
        raise ValueError("matched trajectory replay requires the original single-chunk packetization")
    count = 20000
    events = schedule(config, count)
    rng = Random(seed)
    pending, fifo = [], deque()
    deficit = 0
    dense = np.full(count, np.inf)
    selective = np.full(count, np.inf)
    erasure_hash = sha256()
    for original, kind, source, finish, _ in events:
        lost = rng.random() < LOSS
        erasure_hash.update(bytes([lost]))
        if kind == "source":
            if lost:
                deficit += 1
                pending.append(original)
                fifo.append(original)
            else:
                dense[original] = selective[original] = finish
        elif not lost and deficit:
            deficit -= 1
            selective[fifo.popleft()] = finish
            if not deficit:
                dense[pending] = finish
                pending.clear()
    rows = []
    measured = np.arange(2000, 18000)
    for model, known in (("dense", dense), ("fifo_oracle", selective)):
        delay = (known[measured] - measured * config["arrival_ns"]) / 1e6
        finite = np.isfinite(delay)
        rows.append(dict(record_kind="analytic_busy_period_trajectory", protocol_executions=0,
            model=model, seed=seed, original_count=count, measured_originals=len(measured),
            deadline_misses=int(np.count_nonzero(delay > 35)), deadline_miss_fraction=float(np.mean(delay > 35)),
            measured_unresolved=int(np.count_nonzero(~finite)), all_originals_unresolved=int(np.count_nonzero(~np.isfinite(known))),
            recovered_only_p99_ms=float(np.percentile(delay[finite], 99)), source_arrival_ns=config["arrival_ns"],
            erasure_trace_sha256=erasure_hash.hexdigest(), forward_wire_bytes=sum(event[4] for event in events),
            repair_packets=sum(event[1] == "repair" for event in events), final_deficit=deficit))
    return rows


def write_csv(path, rows):
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def render(output, rows, curves, replay, comparisons, ratio_rows):
    fig = make_subplots(rows=2, cols=2, subplot_titles=("Every granularity scenario", "Every scenario and original-segment misses", "Exact finite-cohort tail law", "Matched erasure trajectories"))
    for index, template in enumerate(FORMATS):
        group = [row for row in rows if row["format"] == template["name"]]
        for column in (1, 2):
            fig.add_trace(go.Scatter(x=[100 * row["dense_miss_fraction"] if column == 1 else row["analytic_case_id"] for row in group],
                y=[row["byte_service_ceiling_mbps"] if column == 1 else 100 * row["dense_miss_fraction"] for row in group],
                ids=[str(row["analytic_case_id"]) for row in group], text=[str(row["analytic_case_id"]) for row in group],
                mode="markers+text", textposition="top center", cliponaxis=False,
                name=template["name"], legendgroup=template["name"], showlegend=column == 1,
                marker=dict(color=COLORS[index], size=9), meta=dict(kind="granularity-case"),
                customdata=[[row["chunks"],row["offered_application_mbps"],row["fifo_oracle_miss_fraction"]] for row in group],
                hovertemplate="Case %{id}<br>Chunks %{customdata[0]}<br>Offered %{customdata[1]:.6f} Mbps<br>FIFO oracle miss %{customdata[2]:.3g}<extra>%{fullData.name}</extra>"),row=1,col=column)
    eligible = [row for row in rows if row["format"] != FORMATS[3]["name"]]
    frontier = [row for row in eligible if not any(other["dense_miss_fraction"] <= row["dense_miss_fraction"] and other["byte_service_ceiling_mbps"] >= row["byte_service_ceiling_mbps"] and (other["dense_miss_fraction"] < row["dense_miss_fraction"] or other["byte_service_ceiling_mbps"] > row["byte_service_ceiling_mbps"]) for other in eligible)]
    frontier.sort(key=lambda row:row["dense_miss_fraction"])
    fig.add_trace(go.Scatter(x=[100*row["dense_miss_fraction"] for row in frontier],y=[row["byte_service_ceiling_mbps"] for row in frontier],mode="lines+markers",name="IP-budget idealized frontier",meta=dict(kind="frontier"),marker=dict(symbol="diamond-open",size=13,color="#263544")),row=1,col=1)
    for model,color in (("dense",COLORS[0]),("fifo_oracle",COLORS[1])):
        selected=[row for row in curves if row["model"]==model]
        fig.add_trace(go.Scatter(x=[row["deadline_ms"] for row in selected],y=[100*row["miss_fraction"] for row in selected],ids=[row["curve_case_id"] for row in selected],mode="lines+markers",name=model,marker=dict(color=color),meta=dict(kind="law-point")),row=2,col=1)
    for model,color in (("dense",COLORS[0]),("fifo_oracle",COLORS[1]),("observed_gf256",COLORS[2])):
        selected=[row for row in replay if row["model"]==model]
        positions = [replay.index(row) + 1 for row in selected]
        fig.add_trace(go.Scatter(x=positions,y=[100*row["deadline_miss_fraction"] for row in selected],
            ids=[row["replay_case_id"] for row in selected],text=positions,mode="markers+text",
            textposition="top center",cliponaxis=False,customdata=[row["seed"] for row in selected],
            hovertemplate="%{id}<br>Seed %{customdata}<br>Misses %{y:.5f}%<extra>%{fullData.name}</extra>",
            name=model+" paired",marker=dict(color=color,size=10),meta=dict(kind="replay-point")),row=2,col=2)
    fig.update_xaxes(title_text="Dense-law original-segment misses at 35 ms (%)",row=1,col=1)
    fig.update_yaxes(title_text="Optimistic byte-service ceiling (Mbps)",row=1,col=1)
    fig.update_xaxes(title_text="Individual numerical scenario ID",row=1,col=2)
    fig.update_yaxes(title_text="Original-segment misses (%)",row=1,col=2)
    fig.update_xaxes(title_text="Deadline above propagation (ms)",row=2,col=1)
    fig.update_yaxes(title_text="Original-segment miss probability (%)",type="log",row=2,col=1)
    fig.update_xaxes(title_text="Individual replay observation ID",dtick=1,row=2,col=2)
    fig.update_yaxes(title_text="Original-source misses (%)",row=2,col=2)
    fig.add_hline(y=80,line_dash="dash",row=1,col=1)
    fig.add_vline(x=1,line_dash="dash",row=1,col=1)
    fig.update_layout(height=900,template="plotly_white",margin=dict(t=65,b=180),legend=dict(orientation="h",y=-.23))
    chart=fig.to_html(full_html=False,include_plotlyjs=True,div_id="busy-period-diagnostic",config=dict(responsive=True))
    ratio_figure = make_subplots(rows=1, cols=2, subplot_titles=("Every header-budget ratio case", "Every ratio case and source misses"))
    for index, template in enumerate(RATIO_FORMATS):
        selected = [row for row in ratio_rows if row["format"] == template["name"]]
        for column in (1, 2):
            ratio_figure.add_trace(go.Scatter(
                x=[100 * row["dense_miss_fraction"] if column == 1 else int(row["ratio_case_id"][1:]) for row in selected],
                y=[row["byte_service_ceiling_mbps"] if column == 1 else 100 * row["dense_miss_fraction"] for row in selected],
                ids=[row["ratio_case_id"] for row in selected], text=[row["ratio_case_id"] for row in selected],
                name=template["name"], legendgroup=template["name"], showlegend=column == 1,
                mode="lines+markers" if column == 1 else "markers+text", textposition="top center", cliponaxis=False,
                customdata=[[row["repair_ratio"],row["offered_application_mbps"]] for row in selected],
                hovertemplate="Case %{id}<br>Repair/source %{customdata[0]:.3f}<br>Offered %{customdata[1]:.6f} Mbps<extra>%{fullData.name}</extra>",
                marker=dict(color=COLORS[index], size=9), meta=dict(kind="ratio-case")), row=1, col=column)
    candidates = [row for row in ratio_rows if row["timing_scope"] == "mean-byte proxy"]
    best = [row for row in candidates if not any(
        other["dense_miss_fraction"] <= row["dense_miss_fraction"]
        and other["byte_service_ceiling_mbps"] >= row["byte_service_ceiling_mbps"]
        and (other["dense_miss_fraction"] < row["dense_miss_fraction"]
             or other["byte_service_ceiling_mbps"] > row["byte_service_ceiling_mbps"])
        for other in candidates)]
    best.sort(key=lambda row: row["dense_miss_fraction"])
    ratio_figure.add_trace(go.Scatter(x=[100*row["dense_miss_fraction"] for row in best],
        y=[row["byte_service_ceiling_mbps"] for row in best], mode="lines+markers",
        name="Mean-byte proxy frontier", meta=dict(kind="ratio-frontier"),
        marker=dict(symbol="diamond-open", size=14, color="#263544")), row=1, col=1)
    ratio_figure.update_xaxes(title_text="Dense-law 35 ms misses (%)", row=1, col=1)
    ratio_figure.update_yaxes(title_text="Mean-byte service ceiling (Mbps)", row=1, col=1)
    ratio_figure.update_xaxes(title_text="Individual ratio case ID", dtick=1, row=1, col=2)
    ratio_figure.update_yaxes(title_text="Original-source misses (%)", row=1, col=2)
    ratio_figure.add_hline(y=80, line_dash="dash", row=1, col=1)
    ratio_figure.add_vline(x=1, line_dash="dash", row=1, col=1)
    ratio_figure.add_hline(y=1, line_dash="dash", row=1, col=2)
    ratio_figure.update_layout(height=540, template="plotly_white", margin=dict(t=65,b=140), legend=dict(orientation="h",y=-.35))
    ratio_chart = ratio_figure.to_html(full_html=False, include_plotlyjs=False, div_id="busy-period-ratios", config=dict(responsive=True))
    table="".join(f'<tr><td>{row["analytic_case_id"]}</td><td>{escape(row["format"])}</td><td>{row["chunks"]}</td><td>{row["byte_service_ceiling_mbps"]:.4f}</td><td>{row["offered_application_mbps"]:.4f}</td><td>{100*row["dense_miss_fraction"]:.4f}%</td><td>{row["equal_source_repair_header_budget_bytes"]:.3f}</td></tr>' for row in rows)
    comparison="".join(f'<tr><td>{row["seed"]}</td><td>{row["dense_misses"]}</td><td>{row["observed_misses"]}</td><td>{row["fifo_misses"]}</td><td>{row["dense_p99_ms"]:.4f}</td><td>{row["observed_p99_ms"]:.4f}</td></tr>' for row in comparisons)
    ratio_table="".join(f'<tr><td>{row["ratio_case_id"]}</td><td>{escape(row["format"])}</td><td>{row["repair_ratio"]:.3f}</td><td>{row["byte_service_ceiling_mbps"]:.6f}</td><td>{100*row["dense_miss_fraction"]:.6f}%</td></tr>' for row in ratio_rows)
    baseline = rows[0]
    raw_high = next(row for row in ratio_rows if row["format"] == RATIO_FORMATS[0]["name"] and row["repair_ratio"] == .222)
    (output/'report.html').write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Systematic repair busy-period diagnostic</title>
<style>*{{box-sizing:border-box}}body{{max-width:1250px;margin:24px auto;padding:18px;font:16px/1.5 system-ui;color:#213547}}.scroll{{max-width:100%;overflow:auto}}.chart{{min-width:1120px}}table{{min-width:1000px;border-collapse:collapse}}th,td{{padding:8px;border-bottom:1px solid #ccd5df;text-align:left}}code{{overflow-wrap:anywhere}}a{{color:#12688d}}</style>
<h1>Systematic repair busy periods and packet granularity</h1>
<p>This coding-only diagnostic separates a generic dense decoder's batch-clearing delay from the service available to an instantaneous-loss FIFO oracle. It establishes the exact finite-cohort probability law of the specified deficit-queue model, subject to the recorded numerical state truncation. It establishes no universal infeasibility result and performs zero TCP executions.</p>
<p>The current 26/125 schedule gives a dense-model 35 ms miss probability of {100*baseline['dense_miss_fraction']:.6f}%. On the three matched saved erasure sequences, the ideal dense model and the actual GF256 control differ by exactly one missed original per seed, and their P99 delays agree to floating-point precision. The proposed raw-IP mean-byte proxy at repair/source 0.222 gives {100*raw_high['dense_miss_fraction']:.6f}% misses at a byte ceiling of {raw_high['byte_service_ceiling_mbps']:.6f} Mbps. Its {raw_high['byte_service_ceiling_mbps']-80:.6f} Mbps headroom is small. These figures support testing the concrete framing and higher repair rate, subject to the mean-byte assumptions below.</p>
<h2>Original-segment metric and causal dense model</h2>
<p>Every original segment contains 1448 application bytes and all of its chunks must finish by its original creation time plus 35 ms. Each chunk is sent systematically once. Integer rational credit determines repair count, with 26/125 used for every granularity case. A lost systematic chunk increments information deficit Q. Each received innovative repair decrements positive Q. The generic dense model identifies pending lost chunks when Q first returns to zero. Successfully received systematics identify immediately. Future erasures can extend a pending decoding batch. Finite-field dependence, restricted support, TCP ordering and reverse ACK costs are outside this ideal dense model.</p>
<p>The FIFO oracle instead spends each successful repair on the oldest missing chunk and knows losses instantly. This information is unavailable to the actual sender with 70 ms RTT. Its curve is a diagnostic comparator. Every systematic/repair erasure is IID with p=0.15, and every repair remains charged even while Q=0. The dense model needs no feedback to make these transmission choices.</p>
<p>For every original phase of the rational repair schedule, an exact birth/death recurrence propagates the queue distribution from an empty initial state through 20,000 originals. The 16,000-original cohort follows 2,000 warmup and precedes 2,000 trailing originals. Tagged-segment state records whether any of its erased chunks remains inside the active batch. Newly lost future chunks extend that batch, while an empty queue releases the tag. No lost or unresolved original is removed from the denominator. The retained trailing sources cover every measured deadline shown here.</p>
<h2>Charged geometry and its boundary</h2>
<p>Current originals use 1460 protected bytes, with 36-byte source and 40-byte repair overhead including IP. Other format rows explicitly grant all inner metadata free. The IPv4/UDP ideal grants 28 header bytes, raw IPv4 grants 20 bytes with all coding metadata free, and the zero-header row is hypothetical. Records split into k near-equal chunks. Each repair contains one full zero-extended chunk. Source and repair bytes serialize at 100 Mbps. Originals arrive at 80 Mbps when their format permits it. Otherwise their clock slows to the charged service ceiling, visibly recorded below. These slower cases fail the 80 Mbps requirement.</p>
<p>The final column gives the maximum equal source/repair header size that could fit 80 Mbps for that row's protected record and k. It follows directly from <code>record_bytes + k·H + (26/125)·k·(ceil(record_bytes/k)+H) ≤ 1810</code>. All k chunks share one original creation time. Subpacketizing a full datagram retains a shared erasure and does not gain the independent erasures modeled by separate smaller datagrams.</p>
<p>Independent chunk packetization also increases packet count. The forward datagram multiplier is k·1.208, giving 2.416 datagrams per original at k=2. Even k=1 uses 20.8% extra forward packets. Every granularity point therefore exceeds the earlier 20% extra-packet threshold. The CSV retains the exact multiplier and extra-packet percentage for each case.</p>
<p>Karzand and colleagues analyze coding busy periods by viewing information erasures as arrivals and successful coded packets as service. Their constant interleaving theorem motivates this diagnostic. Here the 26/125 event schedule, original bursts, serialization and all-chunks deadline are evaluated directly. <a href="https://arxiv.org/pdf/1509.00167">FEC for Lower In-Order Delivery Delay in Packet Networks</a></p>
<p>The 20-byte IPv4 minimum and 8-byte UDP header determine the ideal header comparisons. Coding and record metadata still require an implementable wire representation. <a href="https://www.rfc-editor.org/rfc/rfc791">RFC 791</a> · <a href="https://www.rfc-editor.org/rfc/rfc768">RFC 768</a></p>
<div class="scroll"><div class="chart">{chart}</div></div>
<p>Every numerical scenario appears individually, including byte-infeasible and hypothetical cases. The frontier excludes zero-header cases and remains an idealized model frontier. Full original-segment ACK latency and application goodput require protocol measurements.</p>
<div class="scroll"><table><thead><tr><th>ID</th><th>Format assumption</th><th>Chunks/original</th><th>Byte ceiling Mbps</th><th>Offered Mbps</th><th>Dense 35 ms misses</th><th>Equal header budget B</th></tr></thead><tbody>{table}</tbody></table></div>
<h2>Proposed framing and higher repair ratios</h2>
<p>The additional points use r=0.208, 0.218, 0.220 and 0.222 with one 1448-byte original per source. Raw IPv4 packed framing uses an explicit mean-byte timing proxy of 1479.5625 source bytes and 1488 regular-repair bytes. The proposed UDP proxy uses 1483.5625 and 1492 bytes. Each regular repair protects the full 1460-byte extent. The fractional source byte cost is a conservative rounded accounting surrogate from the separate framing audit. It grants context/retry overhead as average source padding and omits their distinct erasures and dependencies. Historical source-size histograms and timestamp-delta bounds were unavailable. These points therefore describe a mean-byte schedule, with no claim of an implemented wire format. The zero-header comparison is separately labeled hypothetical.</p>
<p>Source costs in the raw audit are about 1479.49–1479.50 bytes per original after packed prediction. The 1479.5625 proxy also covers the small repair-byte increment caused by extra context sources and retained tail repairs at these ratios. It rounds upward to a source serialization time of exactly 118365 ns. Each repair schedule uses its exact reduced fraction. Cases exceeding their 80 Mbps byte budget use the explicitly slower ceiling clock. Actual packet-size bursts, receiver context recovery, channel/TCP order and ACK return must be tested before a source-law result can qualify the 105 ms end-to-end target.</p>
<div class="scroll"><div class="chart">{ratio_chart}</div></div>
<div class="scroll"><table><thead><tr><th>ID</th><th>Timing assumption</th><th>Repair/source</th><th>Byte ceiling Mbps</th><th>Dense 35 ms misses</th></tr></thead><tbody>{ratio_table}</tbody></table></div>
<h2>Matched saved source trajectories</h2><p>The original full-vector partial-repair control has the exact same 0.1448 ms creation clock and 1496/1500-byte service. Its source observations are imported with hashes, with no protocol rerun. Each row has 16,000 measured originals. This comparison separates an expectation over all IID sequences from three particular retained sequences.</p>
<div class="scroll"><table><thead><tr><th>Seed</th><th>Dense misses</th><th>Observed GF256 misses</th><th>Oracle misses</th><th>Dense P99 ms</th><th>Observed P99 ms</th></tr></thead><tbody>{comparison}</tbody></table></div>
<p><a href="analytic-cases.csv">Every granularity case</a> · <a href="ratio-cases.csv">Every ratio case</a> · <a href="tail-curves.csv">Every exact-law point</a> · <a href="trajectory-cases.csv">Every trajectory point</a> · <a href="matched-comparisons.csv">Matched differences</a> · <a href="input-framing-budget.csv">Frozen framing-budget input</a> · <a href="manifest.json">Source and input provenance</a> · <a href="validation-checks.json">Finite checks</a></p></html>''')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True,exist_ok=True)
    files=[Path(__file__).resolve(),root/'tests/test_busy_period.py']
    hashes={str(path.relative_to(root)):sha256(path.read_bytes()).hexdigest() for path in files}
    inputs=root.parent/'work/results-20261110/tcp-latency/partial-repair-screen/cases'
    input_hashes={str(path.relative_to(root.parent)):sha256(path.read_bytes()).hexdigest() for path in sorted(inputs.glob('00[1-3].json'))}
    budget_path = root.parent/'work/results-20261110/tcp-latency/predictive-wire-budget/analytic-cases.csv'
    input_hashes[str(budget_path.relative_to(root.parent))] = sha256(budget_path.read_bytes()).hexdigest()
    with budget_path.open() as stream:
        budget_rows = list(csv.DictReader(stream))
    budget_checks = []
    for template, format_id in zip(RATIO_FORMATS[:2], ("compact_raw_crc32_packed", "compact_udp_packed")):
        selected = [row for row in budget_rows if row["format_id"] == format_id and float(row["repair_ratio"]) <= .222]
        costs = [float(row["forward_ip_bytes"]) / int(row["original_segments"])
                 - float(row["repair_ratio"]) * int(row["regular_repair_ip_bytes"]) for row in selected]
        assert selected and max(costs) <= template["source_ip_bytes"]
        budget_checks.append(dict(format_id=format_id, included_case_ids=[row["case_id"] for row in selected],
                                 maximum_effective_source_bytes=max(costs), proxy_source_bytes=template["source_ip_bytes"]))
    manifest=dict(record_kind='analytic_busy_period_manifest',protocol_executions=0,sources=hashes,inputs=input_hashes,granularity_cases=16,ratio_cases=12,law_curve_points=14,replayed_cases=6,imported_reference_cases=3)
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (args.out/'input-framing-budget.csv').write_bytes(budget_path.read_bytes())
    for path in files:
        target=args.out/'sources'/path.relative_to(root)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(path.read_bytes())
    rows=[]
    for index in range(len(FORMATS)):
        for chunks in (1,2,3,4):
            config=profile(index,chunks)
            tails,defect=exact_tails(config)
            row=dict(record_kind='analytic_busy_period_case',protocol_executions=0,analytic_case_id=len(rows)+1,
                format=config.pop('name'),**config,payload_bytes=1448,loss_rate=LOSS,deadline_ms=35,
                measured_originals=16000,queue_states=128,probability_mass_defect=defect,
                dense_miss_fraction=float(tails['dense'][0]),fifo_oracle_miss_fraction=float(tails['fifo_oracle'][0]))
            rows.append(row)
            (args.out/f'case-{len(rows):03d}.json').write_text(json.dumps(row,indent=2)+'\n')
            print(row['analytic_case_id'],row['format'],chunks,'ceiling',row['byte_service_ceiling_mbps'],'miss',row['dense_miss_fraction'],flush=True)
    ratio_rows = []
    for index, template in enumerate(RATIO_FORMATS):
        for ratio in ("0.208", "0.218", "0.220", "0.222"):
            config = profile(0, 1, ratio, template)
            tails, defect = exact_tails(config)
            row = dict(record_kind="analytic_busy_period_ratio_case", protocol_executions=0,
                ratio_case_id=f"R{len(ratio_rows)+1}", format=config.pop("name"), **config,
                timing_scope="mean-byte proxy" if index < 2 else "hypothetical zero headers",
                measured_originals=16000, deadline_ms=35, probability_mass_defect=defect,
                dense_miss_fraction=float(tails["dense"][0]), fifo_oracle_miss_fraction=float(tails["fifo_oracle"][0]))
            ratio_rows.append(row)
            (args.out/f'ratio-{len(ratio_rows):03d}.json').write_text(json.dumps(row,indent=2)+'\n')
            print(row['ratio_case_id'],row['format'],ratio,'ceiling',row['byte_service_ceiling_mbps'],'miss',row['dense_miss_fraction'],flush=True)
    tails,defect=exact_tails(profile(0,1),DEADLINES)
    curves=[dict(record_kind='analytic_busy_period_law_point',curve_case_id=f'{model}-{deadline}',model=model,deadline_ms=deadline,miss_fraction=float(value)) for model,values in tails.items() for deadline,value in zip(DEADLINES,values)]
    bigger,bigger_defect=exact_tails(profile(0,1),queue_states=256)
    replay=[]
    for seed in SEEDS:
        for row in trajectory(seed,profile(0,1)):
            row['replay_case_id']=f'{row["model"]}-{seed}'
            replay.append(row)
    comparisons=[]
    for path in sorted(inputs.glob('00[1-3].json')):
        observed=json.loads(path.read_text())
        dense=next(row for row in replay if row['seed']==observed['seed'] and row['model']=='dense')
        fifo=next(row for row in replay if row['seed']==observed['seed'] and row['model']=='fifo_oracle')
        assert dense['erasure_trace_sha256']==observed['common_source_and_repair_first_erasure_sha256']
        assert dense['forward_wire_bytes']==observed['forward_total_wire_bytes']
        replay.append(dict(record_kind='analytic_busy_period_imported_reference',protocol_executions=0,
            replay_case_id=f'observed-{observed["seed"]}',model='observed_gf256',seed=observed['seed'],
            original_count=observed['source_count'],measured_originals=observed['measured_sources'],
            deadline_misses=observed['deadline_miss_count'],deadline_miss_fraction=observed['deadline_miss_fraction'],
            measured_unresolved=observed['unresolved_at_horizon_count'],all_originals_unresolved=observed['source_count']-observed['all_input_known_sources'],
            recovered_only_p99_ms=observed['recovered_only_created_to_known_p99_ms'],source_path=str(path.relative_to(root.parent))))
        comparisons.append(dict(seed=observed['seed'],dense_misses=dense['deadline_misses'],observed_misses=observed['deadline_miss_count'],fifo_misses=fifo['deadline_misses'],dense_p99_ms=dense['recovered_only_p99_ms'],observed_p99_ms=observed['recovered_only_created_to_known_p99_ms']))
    for name,data in (('analytic-cases.csv',rows),('ratio-cases.csv',ratio_rows),('tail-curves.csv',curves),('trajectory-cases.csv',replay),('matched-comparisons.csv',comparisons)):
        write_csv(args.out/name,data)
    checks=dict(record_kind='analytic_busy_period_validation',probability_mass_defect=defect,
        queue_128_vs_256_max_difference=max(abs(float(bigger[model][0])-rows[0][model+'_miss_fraction']) for model in bigger),
        state_256_mass_defect=bigger_defect,exact_serialization_and_creation_units='nanoseconds',
        all_original_chunks_required=True,granularity_cases=len(rows),ratio_cases=len(ratio_rows),curve_points=len(curves),trajectory_points=len(replay),
        no_protocol_executions=True,source_hashes_unchanged=all(sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in hashes.items()))
    checks.update(framing_mean_budget_checks=budget_checks, finite_bruteforce_tagged_fixtures=18,
                  finite_independent_queue_recurrence=True)
    assert checks['queue_128_vs_256_max_difference']<1e-10
    (args.out/'validation-checks.json').write_text(json.dumps(checks,indent=2)+'\n')
    render(args.out,rows,curves,replay,comparisons,ratio_rows)


if __name__=='__main__':
    main()
