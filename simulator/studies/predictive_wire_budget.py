"""Reproduce a fixed-cohort framing budget without executing a protocol."""

import argparse
import csv
from fractions import Fraction
from hashlib import sha256
from html import escape
import json
from math import ceil, floor
from pathlib import Path
import shutil


FORMATS = {
    "current_udp": ("Current UDP framing", 36, 1500, 1500, 0, "realized format, analytical rate", "udp"),
    "predictive_udp": ("Current UDP + 3-byte predictor", 36, 1500, 1500, 3, "proposed", "udp"),
    "compact_udp": ("Compact UDP + 3-byte predictor", 30, 1492, 1500, 3, "proposed", "udp"),
    "compact_raw_crc32": ("Compact raw IPv4 + CRC32 + 3-byte predictor", 26, 1488, 1496, 3, "proposed", "raw_ipv4_crc32"),
    "compact_raw_unchecked": ("Raw IPv4 with relaxed integrity budget", 22, 1484, 1492, 3, "unrealized integrity relaxation", "raw_ipv4_relaxed"),
    "compact_udp_packed": ("Compact UDP + 4-byte predictor", 30, 1492, 1500, 4, "proposed", "udp"),
    "compact_raw_crc32_packed": ("Compact raw IPv4 + CRC32 + 4-byte predictor", 26, 1488, 1496, 4, "proposed", "raw_ipv4_crc32"),
    "compact_udp_extent1454": ("UDP predictor + conditional extent 1454", 30, 1492, 1500, 4, "unverified common-record extent bound", "udp"),
    "compact_udp_extent1456": ("UDP predictor + conditional extent 1456", 30, 1492, 1500, 4, "unverified common-record extent bound", "udp"),
    "compact_raw_crc32_extent1454": ("Raw CRC32 predictor + conditional extent 1454", 26, 1488, 1496, 4, "unverified common-record extent bound", "raw_ipv4_crc32"),
    "compact_raw_crc32_extent1456": ("Raw CRC32 predictor + conditional extent 1456", 26, 1488, 1496, 4, "unverified common-record extent bound", "raw_ipv4_crc32"),
}
RATIOS = ("0.208", "0.218", "0.22", "0.222", "0.225", "0.23", "0.24")
COLORS = ("#334155", "#8c6bb1", "#2171b5", "#238b45", "#b15928", "#06b6d4", "#84cc16", "#dd3497", "#7a0177", "#e6550d", "#a63603")


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def prediction_savings_count(run):
    """Conservative normal-entry bound excluding initial and retry neighbors."""
    profile = run["profile"]
    if isinstance(profile, str):
        profile = json.loads(profile)
    flows = profile["flow_count"]
    retries = run["tcp_retransmissions"]
    return max(0, run["offered_frames"] + retries - flows - 2 * retries)


def budget(run, format_id, ratio):
    label, source_header, repair_size, tail_size, predictive, status, encapsulation = FORMATS[format_id]
    count = run["offered_frames"]
    sources = run["forward_source_datagrams"]
    tails = run["shared_tail_repairs"]
    saved_records = prediction_savings_count(run) if predictive else 0
    source_bytes = run["forward_source_bytes"] - (36 - source_header) * sources - predictive * saved_records
    scheduled = floor(Fraction(str(ratio)) * sources)
    extent = int(format_id.split("extent")[-1]) if "extent" in format_id else 1460
    # Charge every global repair and tail at full length. Each exceptional
    # source can affect at most ceil(r*128)+1 scheduled local opportunities.
    exceptions = sources - saved_records
    full_length_repairs = min(scheduled, ceil(scheduled / 16) + exceptions * (ceil(float(ratio) * 128) + 1))
    shortened_repairs = scheduled - full_length_repairs if extent < 1460 else 0
    truncation_saved_bytes = shortened_repairs * (1460 - extent)
    total = source_bytes + scheduled * repair_size + tails * tail_size - truncation_saved_bytes
    ceiling = (count * 1448 / .8 - source_bytes - tails * tail_size) / (repair_size * sources)
    # The named ceiling always uses the unconditional full-length repair
    # budget. Conditional extent rows expose their own ratio-specific saving.
    return dict(case_id=f"{format_id}-run{run['run_id']}-r{ratio}", analysis_kind="fixed_cohort_wire_budget",
                format_id=format_id, format_name=label, format_status=status, encapsulation=encapsulation,
                source_run=run["run_id"], seed=run["seed"], original_segments=count,
                source_datagrams=sources, retained_tail_repairs=tails, scheduled_repairs=scheduled,
                source_header_bytes=source_header, regular_repair_ip_bytes=repair_size,
                tail_repair_ip_bytes=tail_size, protected_symbol_bytes=1460, protected_channel_bytes=3,
                predictive_bytes_per_eligible_record=predictive,
                predictive_eligible_lower_bound=saved_records, predictive_saved_bytes=predictive * saved_records,
                conditional_common_record_extent=extent, conditional_shortened_repairs=shortened_repairs,
                conditional_truncation_saved_bytes=truncation_saved_bytes,
                source_ip_bytes=source_bytes, forward_ip_bytes=total,
                repair_ratio=float(ratio), strict_extra_packets_pct=100 * ((sources + scheduled + tails) / count - 1),
                ip_bytes_per_original_segment=total / count, analytical_capacity_mbps=100 * 1448 * count / total,
                continuous_parity_ceiling_at_80_mbps=ceiling,
                reference_measured_app_mbps=run["application_goodput_mbps"],
                reference_all_segment_ack_p99_ms=run["with_drain_tcp_all_segment_ack_rtt_p99_ms"],
                candidate_measured_app_mbps=None, candidate_measured_latency_ms=None,
                protocol_frontier_eligible=False, forward_mbps=100, reverse_mbps=10, rtt_ms=70,
                loss_rate=.15, mtu=1500, payload_bytes=1448, duration_s=60, drain_s=20,
                authentication_bytes=0)


def ideal_bound(encapsulation, ratio):
    ip_payload = 1472 if encapsulation == "udp" else 1480
    return dict(case_id=f"ideal-{encapsulation}-r{ratio}", analysis_kind="metadata_free_equal_volume_bound",
                encapsulation=encapsulation, repair_ratio=float(ratio), format_status="unrealized metadata relaxation",
                analytical_capacity_mbps=100 * ip_payload / 1500 / (1 + float(ratio)),
                continuous_parity_ceiling_at_80_mbps=ip_payload / 1500 / .8 - 1,
                protocol_frontier_eligible=False)


def write_csv(path, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def check_sources(source):
    manifest = json.loads((source / "experiment.json").read_text())
    receipt = json.loads((source / "source-verification.json").read_text())
    if receipt["changed_during_run"]:
        raise ValueError("source study changed during execution")
    checked = []
    for relative, expected in manifest["sources"].items():
        path = source / "sources" / relative
        if digest(path) != expected:
            raise ValueError(f"source snapshot differs: {relative}")
        checked.append(dict(path=str(path.resolve()), sha256=expected))
    runs = []
    for run_id in (4, 5, 6):
        path = source / "runs" / f"{run_id:05d}.json"
        run = json.loads(path.read_text())
        task = next(task for task in manifest["tasks"] if task["run_id"] == run_id)
        expected = dict(forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15, mtu=1500,
                        payload_bytes=1448, duration_s=60, drain_s=20, warmup_s=5)
        if any(task[key] != value for key, value in expected.items()):
            raise ValueError("source scenario changed")
        if not run["fully_confirmed"] or run["seed"] != task["seed"]:
            raise ValueError("source cohort or seed mismatch")
        if run["forward_wire_bytes"] != run["forward_source_bytes"] + run["forward_repair_bytes"]:
            raise ValueError("source byte conservation mismatch")
        checked.append(dict(path=str(path.resolve()), sha256=digest(path)))
        runs.append(run)
    for name in ("experiment.json", "source-verification.json"):
        path = source / name
        checked.append(dict(path=str(path.resolve()), sha256=digest(path)))
    return runs, checked


def svg_plot(rows, ideal=False):
    width, height = 1000, 460
    xmin, xmax, ymin, ymax = 20.5, 24.2, 77.5, 81.7
    px = lambda x: 75 + (x - xmin) * 880 / (xmax - xmin)
    py = lambda y: 385 - (y - ymin) * 335 / (ymax - ymin)
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Analytical wire capacity by repair ratio">']
    for value in (78, 79, 80, 81):
        y = py(value)
        parts.append(f'<line x1="75" x2="955" y1="{y}" y2="{y}" stroke="#cbd5e1"/><text x="62" y="{y+4}" text-anchor="end">{value}</text>')
    parts.append(f'<line x1="75" x2="955" y1="{py(80)}" y2="{py(80)}" stroke="#dc2626" stroke-dasharray="5 4"/>')
    for value in (21, 22, 23, 24):
        parts.append(f'<text x="{px(value)}" y="410" text-anchor="middle">{value}</text>')
    parts.extend(['<text x="520" y="445" text-anchor="middle">Repair packets per source packet (%)</text>',
                  '<text transform="translate(20 225) rotate(-90)" text-anchor="middle">Analytical wire capacity (Mbps)</text>'])
    for row in rows:
        key = row["encapsulation"] if ideal else row["format_id"]
        color = ({"udp": "#6366f1", "raw_ipv4": "#a16207"}[key] if ideal else COLORS[list(FORMATS).index(key)])
        x, y = px(100 * row["repair_ratio"]), py(row["analytical_capacity_mbps"])
        title = f"{row['case_id']} | {row['analytical_capacity_mbps']:.6f} Mbps | {row['format_status']}"
        parts.append(f'<circle data-case-id="{escape(row["case_id"])}" data-x="{100*row["repair_ratio"]}" data-y="{row["analytical_capacity_mbps"]}" cx="{x:.6f}" cy="{y:.6f}" r="4" fill="{color}" fill-opacity=".7"><title>{escape(title)}</title></circle>')
    parts.append('</svg>')
    return "".join(parts)


def render(output, rows, ideal, observations, checks):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    figure, axes = plt.subplots(1, 2, figsize=(15, 7))
    for index, (key, config) in enumerate(FORMATS.items()):
        group = [row for row in rows if row["format_id"] == key]
        axes[0].scatter([100 * row["repair_ratio"] for row in group], [row["analytical_capacity_mbps"] for row in group],
                        color=COLORS[index], s=20, alpha=.65, label=config[0])
    for key, color in (("udp", "#6366f1"), ("raw_ipv4", "#a16207")):
        group = [row for row in ideal if row["encapsulation"] == key]
        axes[1].scatter([100 * row["repair_ratio"] for row in group], [row["analytical_capacity_mbps"] for row in group],
                        color=color, label=key)
    for axis, title in zip(axes, ("Fixed original cohorts · proposed byte budgets", "Metadata-free upper budgets")):
        axis.set(title=title, xlabel="Repair packets / source packet (%)", ylabel="Analytical wire capacity (Mbps)")
        axis.axhline(80, color="#dc2626", linestyle="--", linewidth=1)
        axis.grid(alpha=.2)
        axis.legend(fontsize=6, loc="lower left")
    figure.tight_layout()
    figure.savefig(output / "all-budget-points.png", dpi=170)
    plt.close(figure)
    table = []
    for key, config in FORMATS.items():
        group = [row for row in rows if row["format_id"] == key and row["repair_ratio"] == .22]
        table.append(f'<tr><td>{escape(config[0])}</td><td>{config[1]}</td><td>{config[2]}</td><td>{config[3]}</td>'
                     f'<td>{min(r["analytical_capacity_mbps"] for r in group):.6f}–{max(r["analytical_capacity_mbps"] for r in group):.6f}</td>'
                     f'<td>{100*min(r["continuous_parity_ceiling_at_80_mbps"] for r in group):.5f}–{100*max(r["continuous_parity_ceiling_at_80_mbps"] for r in group):.5f}%</td>'
                     f'<td>{escape(config[5])}</td></tr>')
    source_links = ''.join(f'<li><a href="{escape(__import__("os").path.relpath(item["path"], output))}">{escape(item["path"].split("aligned-record-elision-long/")[-1])}</a> · SHA256 <code>{item["sha256"]}</code></li>' for item in checks)
    observed = ''.join(f'<tr><td>{r["run_id"]}</td><td>{r["seed"]}</td><td>{r["application_goodput_mbps"]:.6f}</td><td>{r["with_drain_tcp_all_segment_ack_rtt_p99_ms"]:.6f}</td><td>{r["offered_frames"]}</td><td>Confirmed</td></tr>' for r in observations)
    legend = ''.join(f'<span style="color:{COLORS[i]}">● {escape(value[0])}</span> ' for i,value in enumerate(FORMATS.values()))
    html = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Predictive tunnel wire budget</title>
<style>body{{font:16px/1.5 system-ui;color:#172033;background:#f8fafc;margin:auto;padding:24px;max-width:1180px}}h1{{line-height:1.15}}section{{background:white;padding:20px;border-radius:12px;margin:18px 0}}.scroll{{overflow:auto;max-width:100%}}svg{{min-width:900px;width:100%;display:block;font:14px system-ui}}table{{border-collapse:collapse;min-width:850px;width:100%}}th,td{{text-align:left;border-bottom:1px solid #dbe2ea;padding:8px}}code{{overflow-wrap:anywhere}}li{{margin:8px 0;overflow-wrap:anywhere}}.notice{{border-left:5px solid #b45309}}.legend{{font-size:13px;display:flex;gap:14px;flex-wrap:wrap}}a{{color:#155e9b}}</style>
<h1>Predictive tunnel wire budget</h1><p>100/10 Mbps IPv4 service · 70 ms RTT · 15% IID loss · MTU 1500 · 1448-byte TCP payload</p>
<section class="notice"><strong>Analytical postprocessing with zero new protocol executions</strong><p>All {len(rows)} fixed-cohort cases and {len(ideal)} metadata-relaxed bounds appear below. Three archived 60-second source runs remain distinct. Proposed-format throughput, latency and complete-cohort confirmation require new protocol execution. Their latency fields remain empty. Authentication stays at the source profile's zero-byte setting.</p><p>The calculation retains every original submitted segment, context, retransmission, fragment source and observed tail repair. Header savings use a conservative count of predictable records. Newly required tails, startup, changed pacing and changed FEC recovery can lower achieved throughput. Full ACK P99 is measured from original submission through drain in the source observations.</p></section>
<section><h2>Every evaluated fixed-cohort case</h2><div class="legend">{legend}</div><div class="scroll">{svg_plot(rows)}</div><p>Hover each marker for its case ID and exact capacity. Three seed coordinates can overlap at this scale. These capacity coordinates measure a finite byte budget. Proposed-format latency remains unmeasured. Conditional-extent rows retain full-length global repairs and tails, and conservatively charge local repairs touching exceptional sources.</p><p><a href="analytic-cases.csv">All fixed-cohort cases</a> · <a href="format-ceilings.csv">Format ceilings</a> · <a href="all-budget-points.png">Static plot</a></p>
<div class="scroll"><table><thead><tr><th>Format</th><th>Source outer bytes</th><th>Regular repair IP bytes</th><th>Tail IP bytes</th><th>Capacity at r=.22, Mbps</th><th>Full-length-repair ceiling at 80 Mbps</th><th>Implementation status</th></tr></thead><tbody>{''.join(table)}</tbody></table></div></section>
<section><h2>Concrete proposed format</h2><ol><li>Keep 1460 protected bytes per coding symbol and the existing 3-byte protected channel/serial prefix. Preserve all full-frame escapes and fragment records. Predictive kind 7 asserts IPID = prior IPID + 1 modulo 2¹⁶ and TCP sequence = prior sequence + prior payload length modulo 2³². Use it only after exact byte comparison. The two-byte-length elision, mask and all remaining dynamic deltas stay explicit. Each qualifying frame saves exactly 3 bytes. Initial records and retry neighbors use the existing record forms.</li>
<li>The two-byte source/end field reserves its high bit for source-versus-repair type and carries a 15-bit source ID. A regular repair adds a two-byte field containing a tail-escape bit and 15-bit repair serial. Serial modulo 16 selects the global opportunity. The coefficient seed is defined from the transmitted serial, with absolute source indices in the existing coefficient generator. This finite serial alphabet repeats after 32768 repairs. Tail escape uses a total 12-byte header containing the two tagged fields, absolute end32 and seed32. Its full byte cost remains charged.</li>
<li>Local repairs cover the last 128 sources. Global repairs and tails cover the last 8192 sources, including already acknowledged bytes. Admission stops when end minus confirmed base reaches 8192. Every unresolved source remains covered. Sender and receiver retain known bytes long enough to encode and subtract these extra terms. Current feedback-driven source deallocation must be replaced. A fixed global range has the same unknown terms as the existing base-to-end range when this invariant holds.</li>
<li>UDP uses 20-byte IPv4 plus 8-byte UDP. The type bit distinguishes sources and repairs, including shortened repairs. Full source UDP payloads are at most 1462 bytes, regular repairs exactly 1464, and extended tail repairs exactly 1472. The escape bit selects the 12-byte tail header. Feedback uses a configured control UDP port with its existing 40-byte IP cost. The reverse TCP ACK format and every original ACK event remain unchanged.</li>
<li>The raw-IPv4 option uses one experimental IP protocol for forward coded packets, with a charged 4-byte CRC32 over its complete tunnel header and payload. The same explicit type and escape bits identify packet forms. The CRC covers source IDs and repair fields before they are trusted. Reverse feedback and TCP ACKs keep the archived UDP paths and costs. It saves 4 bytes per forward packet relative to the compact UDP form. A controlled experimental protocol number is configured explicitly.</li>
<li>The 15-bit source-ID payload uses a half-range 16384 with at most 8192 outstanding sources. The current scenario has one FIFO path and fixed propagation delay, so forward arrivals preserve transmission order. The transport must enforce these bounds and reject stale/ambiguous identifiers. A deployment with a larger reordering span requires an explicit extended-ID/session-epoch design and its extra wire cost. Unknown source expiry is prohibited by the admission invariant.</li><li>The packed variant also requires an unchanged TCP ACK number, which the archived one-way data entry point provides. Low three bits of the kind byte equal 7. Its upper five bits contain the presence mask for flags, window, urgent pointer, TSval and TSecr. Every selected delta remains an exact unsigned modular varint. This replaces the separate kind and mask bytes and saves one additional byte. A changed ACK number or failed prediction selects the existing kind6/full-frame escape.</li><li>Repair tail truncation is valid only when all source symbols in the actual support have encoded extents at or below the transmitted extent. Their remaining protected columns are implicit zero padding, so GF256 parity is also zero there. The receiver derives extent from IP/UDP length, validates it and zero-extends to 1460. Opaque payload bytes remain fully counted, including actual zero-valued payload bytes. For the conditional 1454/1456 cases, every global and tail repair stays full length, and exceptional source count E = source count minus predictor-eligible count can invalidate at most E × (ceil(128r)+1) local truncations. The recorded counters establish E, while the common-record timestamp-varint extent assumption requires future measurement.</li></ol>
<p>At r=.22 the raw-IPv4/CRC32 proposal has roughly 0.09 Mbps of analytical margin with the 3-byte predictor, or 0.14 Mbps with its packed 4-byte variant. It is a bounded implementation candidate. The preserved strict packet count is approximately 22%, above the earlier 20% packet-cost gate. Increasing parity changes repair coefficients, receiver progress and TCP feedback, so the archived latency values provide context only.</p></section>
<section><h2>Explicit metadata-free bounds</h2><div class="legend"><span style="color:#6366f1">● IPv4/UDP</span><span style="color:#a16207">● Raw IPv4</span></div><div class="scroll">{svg_plot(ideal, True)}</div><p>These separate idealizations remove all record and coding metadata and assume equally sized source and repair data. Raw IPv4 at r=.24 reaches only 79.569892 Mbps before metadata. Their scope is equal-volume parity at the stated IP service boundary. They leave other coding or payload-sharing constructions open.</p><p>At 20% erasure, even ideal erasure coding and zero inner metadata leave at most 80 × 1472/1500 = 78.506667 Mbps with IPv4/UDP, or 80 × 1480/1500 = 78.933333 Mbps with raw IPv4. These are asymptotic erasure-capacity upper budgets. The current study keeps the 15% scenario.</p><p><a href="ideal-bounds.csv">All idealized cases</a></p></section>
<section><h2>Archived full-TCP source observations</h2><div class="scroll"><table><thead><tr><th>Run</th><th>Seed</th><th>Application Mbps</th><th>All-segment ACK P99 ms</th><th>Original segments</th><th>Terminal state</th></tr></thead><tbody>{observed}</tbody></table></div><p>All three use r=.208, W128/G16, 64 flows, 60 seconds of traffic and 20 seconds of drain. The compact-header budgets retain their frame cohorts and do arithmetic on wire bytes. Their source and parity packet counts remain individually traceable.</p><p><a href="source-observations.csv">Source observations</a> · <a href="validation.json">Validation receipt</a> · <a href="analysis.json">Analysis metadata</a> · <a href="analysis-source.py">Frozen analysis source</a></p></section>
<section><h2>Primary-source constraints and provenance</h2><p>ROHC-TCP provides a precedent for explicitly signaled sequential-IPID and scaled-sequence compression. Its standardized packet examples retain CRC, MSN and dynamic fields. This report specifies a smaller special-case predictor inside the existing reliable per-channel context. <a href="https://www.rfc-editor.org/rfc/rfc6846.html">RFC 6846</a></p><p>Experimental IP protocol values 253 and 254 support controlled opt-in testing. A permanent deployment requires its own allocation and interoperability work. IPv4 Identification is reserved for fragmentation and reassembly, so this proposal carries its source identifier inside the tunnel payload. <a href="https://www.rfc-editor.org/rfc/rfc3692.html">RFC 3692</a> · <a href="https://www.rfc-editor.org/rfc/rfc6864.html">RFC 6864</a></p><details><summary>Verified source files and SHA256 receipts</summary><ul>{source_links}</ul></details></section></html>'''
    (output / "report.html").write_text(html)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("work/results-20261110/tcp-latency/aligned-record-elision-long"))
    parser.add_argument("--output", type=Path, default=Path("work/results-20261110/tcp-latency/predictive-wire-budget"))
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(__file__, output / "analysis-source.py")
    runs, checked = check_sources(args.source)
    rows = [budget(run, key, ratio) for key in FORMATS for run in runs for ratio in RATIOS]
    ideal = [ideal_bound(kind, ratio) for kind in ("udp", "raw_ipv4") for ratio in RATIOS]
    ceilings = [row for row in rows if row["repair_ratio"] == .22]
    observations = [{key: run[key] for key in ("run_id", "seed", "offered_frames", "application_goodput_mbps", "with_drain_tcp_all_segment_ack_rtt_p99_ms", "fully_confirmed")} for run in runs]
    write_csv(output / "analytic-cases.csv", rows)
    write_csv(output / "format-ceilings.csv", ceilings)
    write_csv(output / "ideal-bounds.csv", ideal)
    write_csv(output / "source-observations.csv", observations)
    metadata = dict(analysis_kind="wire_budget_only", protocol_executions=0,
                    source_run_ids=[run["run_id"] for run in runs], source_file_receipts=checked,
                    script_sha256=digest(Path(__file__)), ratios=RATIOS, candidate_case_count=len(rows),
                    ideal_case_count=len(ideal), original_segments=sum(run["offered_frames"] for run in runs),
                    byte_budget="1448 / 0.8 = 1810 IP bytes per original TCP segment",
                    ceiling_formula="(1810*N - proposed_source_bytes - original_tail_count*tail_ip_bytes) / (source_count*regular_repair_ip_bytes)")
    (output / "analysis.json").write_text(json.dumps(metadata, indent=2) + "\n")
    receipt = dict(source_snapshots_verified=len(checked), source_runs=3, source_runs_confirmed=3,
                   candidate_cases=len(rows), ideal_cases=len(ideal), all_case_ids_unique=len({r["case_id"] for r in rows + ideal}) == len(rows + ideal),
                   protocol_executions=0, original_segments=metadata["original_segments"],
                   script_snapshot_matches=digest(Path(__file__)) == digest(output / "analysis-source.py"))
    (output / "validation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    render(output, rows, ideal, runs, checked)
    if any(digest(Path(item["path"])) != item["sha256"] for item in checked):
        raise ValueError("source receipt changed while reading")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
