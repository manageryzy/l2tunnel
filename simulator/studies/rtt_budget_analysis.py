"""Reproducible analytical RTT budgets, separate from executed transport experiments."""

import argparse
import csv
from fractions import Fraction
from hashlib import sha256
from html import escape
import json
from math import floor
from pathlib import Path
import platform

import numpy as np
from scipy.sparse import csr_matrix, eye
from scipy.sparse.linalg import spsolve
from scipy.stats import binom


SOURCES = [
    dict(title="RFC 9407 — Tetrys", url="https://www.rfc-editor.org/rfc/rfc9407.html"),
    dict(title="RFC 8681 — Sliding Window RLC", url="https://www.rfc-editor.org/rfc/rfc8681.html"),
    dict(title="Karzand et al. — FEC for Lower In-Order Delivery Delay", url="https://arxiv.org/pdf/1509.00167"),
    dict(title="Fong et al. — Optimal Streaming Codes for Burst and Arbitrary Erasures", url="https://arxiv.org/pdf/1801.04241"),
]


def write_csv(path, rows):
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def schedule(ratio):
    """One source per arrival, evenly interspersed repairs from integer credit."""
    fraction = Fraction(str(ratio))
    pattern, credit = [], 0
    for _ in range(fraction.denominator):
        pattern.append(False)
        credit += fraction.numerator
        while credit >= fraction.denominator:
            pattern.append(True)
            credit -= fraction.denominator
    return np.array(pattern, dtype=bool)


def advance(distributions, repair, loss, absorb=False):
    """Update independent deficit chains, with zero absorbing for tagged delay."""
    repair = np.asarray(repair).reshape(-1, 1)
    result = distributions * np.where(repair, loss, 1 - loss)
    result[:, :-1] += distributions[:, 1:] * np.where(repair, 1 - loss, 0)
    result[:, 1:] += distributions[:, :-1] * np.where(repair, 0, loss)
    result[:, -1] += distributions[:, -1] * np.where(repair[:, 0], 0, loss)
    if absorb:
        result[:, 0] = 0
    else:
        result[:, 0] += distributions[:, 0] * np.where(repair[:, 0], 1 - loss, 0)
    return result


def stationary_deficit(pattern, loss, maximum):
    """Numerical stationary distribution for one full scheduling period."""
    transitions = np.eye(maximum + 1)
    for repair in pattern:
        transitions = advance(transitions, np.full(maximum + 1, repair), loss)
    assert np.max(np.abs(transitions.sum(axis=1) - 1)) < 1e-12
    equations = (csr_matrix(transitions.T) - eye(maximum + 1)).tolil()
    equations[-1, :] = 1
    rhs = np.zeros(maximum + 1)
    rhs[-1] = 1
    distribution = spsolve(equations.tocsr(), rhs)
    assert np.min(distribution) > -1e-10
    distribution = np.maximum(distribution, 0)
    distribution /= distribution.sum()
    residual = float(np.max(np.abs(distribution @ transitions - distribution)))
    assert residual < 1e-10
    return distribution, residual


def streaming_delay(ratio, loss, max_slots=20000, maximum=512):
    """Ideal innovative-repair deficit queue, with no wire protocol or CPU model.

    Every lost source adds one missing degree of freedom. Every received repair
    removes one while the deficit is positive. A record is released when the
    deficit first returns to zero. Later source erasures can prolong that wait.
    Stationary observations are uniform over source positions in the period.
    """
    result = dict(calculation="ideal_streaming_deficit_queue", loss_rate=loss, repair_per_source=ratio,
                  stationary=ratio * (1 - loss) > loss)
    if not result["stationary"]:
        return result, None
    pattern = schedule(ratio)
    stationary, residual = stationary_deficit(pattern, loss, maximum)
    if stationary[-1] > 1e-10:
        raise ValueError("Deficit truncation is too small for this parameter")
    coarse, _ = stationary_deficit(pattern, loss, maximum // 2)
    resolution_error = float(np.sum(np.abs(stationary[:len(coarse)] - coarse))
                             + np.sum(stationary[len(coarse):]))
    assert resolution_error < 1e-8
    distribution = stationary[None, :]
    initial, phases = [], []
    for phase, repair in enumerate(pattern):
        distribution = advance(distribution, [repair], loss)
        if not repair:
            tagged = distribution[0].copy()
            tagged[0] = 0
            initial.append(tagged)
            phases.append(phase)
    waiting = np.asarray(initial)
    phases = np.asarray(phases)
    survival = np.empty(max_slots + 1)
    overflow = 0.0
    for elapsed in range(max_slots + 1):
        survival[elapsed] = waiting.sum() / len(phases)
        next_repair = pattern[(phases + elapsed + 1) % len(pattern)]
        overflow += float((waiting[:, -1] * (~next_repair) * loss).sum() / len(phases))
        waiting = advance(waiting, next_repair, loss, absorb=True)
    assert np.max(np.diff(survival)) < 1e-10
    assert overflow < 1e-8
    result.update(period_sources=len(phases), period_repairs=int(pattern.sum()),
                  queue_truncation=maximum, stationary_boundary_mass=float(stationary[-1]),
                  stationary_resolution_l1_difference=resolution_error,
                  stationary_residual=residual, tagged_truncation_probability_bound=overflow,
                  remaining_tail_at_max_slots=float(survival[-1]), max_slots=max_slots)
    for percent in (50, 95, 99):
        indices = np.flatnonzero(survival <= 1 - percent / 100)
        result[f"coding_delay_p{percent}_slots"] = int(indices[0]) if len(indices) else None
    return result, survival


def capacity_rows():
    rows = []
    for loss in (.15, .20):
        for bandwidth in (10, 100, 1000):
            for name, useful in (("No packet headers", 1500), ("IPv4 UDP only, optimistic", 1472),
                                 ("One 1448-byte application record per full IP datagram", 1448)):
                rows.append(dict(calculation="asymptotic_erasure_capacity_upper_bound", loss_rate=loss,
                                 forward_mbps=bandwidth, ip_packet_bytes=1500, useful_bytes_per_packet=useful,
                                 budget=name, application_capacity_ceiling_mbps=bandwidth * (1 - loss) * useful / 1500,
                                 minimum_repair_per_source=loss / (1 - loss),
                                 target_application_mbps=.8 * bandwidth,
                                 asymptotic_capacity_allows_target=(1 - loss) * useful / 1500 >= .8))
    return rows


def block_rows():
    rows = []
    for loss in (.15, .20):
        for bandwidth in (10, 100, 1000):
            for base_rtt in (20, 70, 150):
                budget = .5 * base_rtt
                packets = floor(budget / (1500 * 8 / bandwidth / 1000))
                if packets < 1:
                    continue
                repairs = packets // 6
                required = next(r for r in range(packets) if loss * binom.sf(r - 1, packets - 1, loss) <= .01)
                rows.append(dict(calculation="isolated_systematic_ideal_mds_block", loss_rate=loss,
                    forward_mbps=bandwidth, base_rtt_ms=base_rtt, coding_budget_ms=budget,
                    packets_in_budget=packets, sources_at_20pct_limit=packets - repairs,
                    repairs_at_20pct_limit=repairs, actual_repair_per_source=repairs / (packets - repairs),
                    whole_block_failure_probability=float(binom.sf(repairs, packets, loss)),
                    erased_source_unresolved_probability=float(loss * binom.sf(repairs - 1, packets - 1, loss)),
                    repairs_for_one_pct_erased_source_unresolved=required,
                    required_repair_per_source=required / (packets - required),
                    application_rate_ceiling_at_required_repairs_mbps=bandwidth * (packets - required) / packets * 1448 / 1500))
    return rows


def reference_rows(root):
    rows = []
    directory = root / "window" / "more-flows-validation" / "runs"
    for path in sorted(directory.glob("*.json")):
        raw = json.loads(path.read_text())
        delivered = raw["tcp_delivered_frames"]
        source_count = raw["forward_source_datagrams"]
        multiplier = source_count / delivered
        rows.append(dict(calculation="existing_protocol_run_reference", source=str(path),
            sha256=sha256(path.read_bytes()).hexdigest(), seed=raw["seed"], flow_count=raw["flow_count"],
            observed_application_mbps=raw["application_goodput_mbps"],
            observed_timestamp_rtt_p99_ms=raw["tcp_timestamp_rtt_p99_ms"],
            observed_frame_p99_ms=raw.get("with_drain_frame_p99_ms", raw["frame_p99_ms"]),
            observed_forward_queue_p99_ms=raw["forward_queue_p99_ms"],
            observed_reverse_queue_p99_ms=raw["reverse_queue_p99_ms"],
            source_datagrams_per_delivered_record=multiplier,
            mean_source_ip_bytes=raw["forward_source_bytes"] / source_count,
            observed_strict_extra_packets_pct=100 * (raw["forward_datagrams"] / delivered - 1),
            maximum_fec_ratio_before_other_forward_packets=1.2 / multiplier - 1,
            tcp_all_acknowledged=raw["tcp_all_acknowledged"], outer_all_confirmed=raw["outer_all_confirmed"]))
    return rows


def table(rows, fields):
    head = "".join(f"<th>{escape(title)}</th>" for _, title in fields)
    body = []
    for row in rows:
        values = []
        for key, _ in fields:
            value = row.get(key)
            display = f"{value:.5g}" if isinstance(value, float) else "—" if value is None else str(value)
            values.append(f"<td>{escape(display)}</td>")
        body.append("<tr>" + "".join(values) + "</tr>")
    return "<table><thead><tr>" + head + "</tr></thead><tbody>" + "".join(body) + "</tbody></table>"


def plot_reference(output, rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    selected = [row for row in rows if row["loss_rate"] == .15 and row["forward_mbps"] == 100]
    fig, axis = plt.subplots(figsize=(10, 6), layout="constrained")
    axis.plot([row["ideal_source_ack_p99_ms"] for row in selected],
              [row["application_rate_ceiling_mbps"] for row in selected], "o-", color="#176b91")
    for row in selected:
        axis.annotate(f"{row['repair_per_source']:.0%}",
                      (row["ideal_source_ack_p99_ms"], row["application_rate_ceiling_mbps"]),
                      xytext=(5, 7), textcoords="offset points", fontsize=9)
    axis.axvline(105, linestyle="--", color="#a85b21", label="105 ms round-trip target")
    axis.axhline(80, linestyle="--", color="#417b4b", label="80 Mbps application target")
    axis.set(xlabel="Ideal source-to-ACK P99 with immediate successful ACK (ms)",
             ylabel="Application rate ceiling, 1448/1500 byte budget (Mbps)",
             title="Analytical streaming policy at 15% IID loss, 100 Mbps\n"
                   "Labels show repair/source ratio. Deterministic calculations with ideal innovation.", xscale="log")
    axis.grid(alpha=.2)
    axis.legend(loc="lower right", fontsize=9)
    fig.savefig(output / "ideal-streaming-tradeoff.png", dpi=160)
    plt.close(fig)


def report(output, stream, capacities, blocks, references):
    selected = [r for r in stream if r["forward_mbps"] == 100 and r["loss_rate"] == .15]
    block = [r for r in blocks if r["base_rtt_ms"] == 70 and r["loss_rate"] == .15]
    capacity = [r for r in capacities if r["forward_mbps"] == 100]
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>Finite RTT budget analysis</title>
<style>body{font:16px/1.55 system-ui;max-width:1200px;margin:36px auto;padding:0 20px;color:#203447}table{border-collapse:collapse;font-size:13px;width:100%;margin:20px 0}td,th{border-bottom:1px solid #ccd5df;padding:8px;text-align:right}th{background:#edf3f8}h1,h2{line-height:1.25}a{color:#126f9a}code{background:#edf3f8;padding:2px 4px}.notice{border-left:5px solid #a96918;padding:12px;background:#fff6e5}</style>
<h1>Finite RTT budget at 15% and 20% IID loss</h1>
<p class="notice">These are mathematical budget calculations. The protocol execution count is zero. An ideal coding queue, an isolated MDS block, and an asymptotic capacity bound answer different questions. Their points remain separate from the empirical all-history Pareto frontiers.</p>
<h2>Deadline and capacity</h2>
<p>The current target is 80 Mbps of TCP application data on a 100 Mbps forward IP service link, with a 10 Mbps reverse link, 70 ms propagation RTT, MTU 1500, 1448-byte TCP payloads, and 15% IID losses in both directions. A 105 ms round-trip target leaves 35 ms for source admission, serialization, queueing, coding, and ACK scheduling. Feedback-triggered repair of an erased forward packet requires approximately another propagation RTT before its acknowledgment can return. Even ideal immediate loss feedback therefore produces roughly 140 ms source-to-ACK completion. Tightening ARQ timers can remove avoidable waiting but cannot remove that propagation path.</p>
<p>For an IID packet-erasure channel carrying equal-size packets, the long-run useful information rate cannot exceed <code>C × (1 − p) × useful_bytes / IP_bytes</code>. Loss rate 20% leaves exactly 80 Mbps before any headers. IPv4/UDP headers alone lower that optimistic ceiling to 78.507 Mbps. The 15% reference retains a narrow feasible capacity margin. The loss fraction is relative to all transmissions, while repairs per original source must exceed <code>p / (1 − p)</code> for stable proactive coding. This is 17.647% at 15% loss and 25% at 20% loss. A hard deadline for every packet is impossible under an unbounded IID loss process, so the stated P99 target is essential.</p>
__CAPACITY__
<h2>Stationary ideal streaming queue</h2>
<p>The calculation uses periodic source/repair interleaving and an infinite innovative coding window. Lost source symbols increase a missing-degree-of-freedom queue. Successfully received repair symbols decrease it. A source becomes deliverable when the queue first reaches zero. Source arrivals continue during recovery. The source phase is sampled uniformly in stationarity. The script solves the finite-state stationary transition matrix and propagates the tagged waiting distribution, recording boundary mass, stationarity residual, and accumulated truncation mass. It assumes independent losses, perfect innovation, immediate processing, no packet queue, no source-header expansion, and a successful immediate reverse acknowledgment.</p>
<p>This queue describes a particular dense streaming recovery policy and gives an optimistic reference for that policy's rank and scheduling costs. Its conclusions apply to this dense streaming policy. Alternative codes require separate evaluation. The source-weighted coding-delay distribution also differs from TCP's selected timestamp samples. Adding 70 ms gives an ideal source-to-ACK completion value. Actual TCP timestamp RTT, ACK completion RTT, all-record delay, and deadline-miss fractions still need joint protocol measurement.</p>
__STREAM__
<p><a href="ideal-streaming-tradeoff.png"><img src="ideal-streaming-tradeoff.png" alt="Analytical coding latency and rate trade-off" style="max-width:100%"></a></p>
<p>The nominal 20% repair schedule approaches the 15% erasure capacity closely. Loss fluctuations create long recovery episodes despite low average link queues. Moving toward 25% repair improves the coding tail but lowers the 1448/1500 application-rate ceiling below 80 Mbps. Full-rate aggregate coding gives the time scale in the table. Dividing independent coding across many equal-rate flows lengthens each flow's packet-slot duration. Pooling flows for coding can reclaim that time scale while preserving separate codec contexts and per-flow record delivery.</p>
<h2>Finite isolated-block cross-check</h2>
<p>For a systematic ideal MDS block with n total transmissions and r repairs, whole-block failure is <code>P[Binomial(n,p) &gt; r]</code>. A tagged source remains erased with probability <code>p × P[Binomial(n−1,p) ≥ r]</code>. All source data are assumed available at block start and all transmissions fit in the residual RTT budget. This omits source collection time, ACK loss, and ordered-release amplification. Its conclusions apply to this isolated block design. Streaming codes require separate evaluation.</p>
__BLOCK__
<p>At 100 Mbps, 35 ms fits 291 full-size IP packets. A 243+48 block has 21.09% whole-block failure and 3.778% erased-source probability after its repairs. Reaching 1% erased-source probability needs 54 repairs for 237 sources, or 22.785% repair overhead, with an optimistic application rate of 78.620 Mbps. At 1000 Mbps the same wall-clock budget permits a much larger code, demonstrating that packet rate materially changes the finite-delay margin.</p>
<h2>Implementable directions</h2>
<ul><li><strong>Shared coding with separate per-flow delivery.</strong> A shared source/repair scheduler should account for each multiplexer header, keep exact per-flow compression contexts, and use one physical forward/reverse queue. Successfully reconstructed records should release according to their own flow ordering. A global byte-stream prefix creates avoidable cross-flow blocking. The actual coding matrix must determine decodability.</li>
<li><strong>Explicit deadline-aware coding windows.</strong> Test a bounded age or bounded source-count window with regular repair placement and age-prioritized repair opportunities. Preserve unrecovered old data for reliable fallback, and charge every additional repair. Tetrys provides a concrete elastic-window protocol with feedback-driven window updates. RFC 8681 specifies GF(256) and GF(2) sliding-window formats, coefficient generation, and operational guidance. Both require careful finite-window and repair-budget choices. <a href="https://www.rfc-editor.org/rfc/rfc9407.html">RFC 9407</a> · <a href="https://www.rfc-editor.org/rfc/rfc8681.html">RFC 8681</a></li>
<li><strong>Causal repair placement and individual-deadline code structure.</strong> Karzand and colleagues analyze interspersed coded packets and the near-capacity queueing trade-off. Fong and colleagues construct optimal delay-constrained codes under bounded sliding-window erasure assumptions. The latter gives a candidate construction direction, while IID channels can violate its bounded-erasure premise. Validation of the 15% IID P99 target requires separate statistical analysis and protocol experiments. <a href="https://arxiv.org/pdf/1509.00167">Karzand et al.</a> · <a href="https://arxiv.org/pdf/1801.04241">Fong et al.</a></li>
<li><strong>Budget the repair scheduler before changing the code rate.</strong> Compute source datagrams per delivered record and residual forward-feedback cost. The strict gate is <code>total_forward_datagrams / delivered_records − 1 ≤ .20</code>. A configured repair/source ratio of .20 can already exceed that gate after packetization, framing, tail repair, or reliable-ACK feedback. Reserve serialization opportunities for coding and keep total source plus repair load within link capacity.</li>
<li><strong>Guard against selective RTT improvements.</strong> Keep the nominal path, payload, loss process, and offered useful rate fixed. Report timestamp RTT together with per-record ACK completion, frame delay, deadline misses, throughput, packet overhead, delivery fraction, and both TCP/outer terminal confirmation. A lower timestamp percentile alone can reflect which ACKs produced samples.</li></ul>
<h2>Current executed reference</h2>
<p>The following rows are linked existing 64-flow observations. The all-history archive retains these observations under their original execution IDs. The current queues are only a few milliseconds at P99, while timestamp RTT is around 340 ms. Queue reduction alone leaves most of the remaining target gap.</p>
__REFERENCE__
<h2>Scope and reproducibility</h2>
<p>The capacity calculation shows why the historical 20% loss condition cannot sustain the requested application rate with finite headers. Feasibility of alternative 15% loss coding and scheduling strategies under both goals remains unresolved. Strict 20% packet overhead remains an unresolved additional feasibility constraint for the low-delay goal. The current simulator models TCP congestion control rather than a real kernel. Its GF(256) decoder computes rank, with payload coding arithmetic and CPU time omitted. These analytical tables further idealize innovation and reverse ACK delivery.</p>
<p><a href="capacity-bounds.csv">Capacity calculations</a> · <a href="block-budget.csv">Finite block calculations</a> · <a href="streaming-queue.csv">Streaming queue calculations</a> · <a href="existing-reference.csv">Existing run references</a> · <a href="analytical-results.json">All analytical values</a> · <a href="manifest.json">Provenance and assumptions</a></p>
</html>'''
    page = page.replace("__CAPACITY__", table(capacity, [("loss_rate", "Loss"), ("budget", "Packet budget"),
                          ("application_capacity_ceiling_mbps", "Application ceiling Mbps")]))
    page = page.replace("__STREAM__", table(selected, [("repair_per_source", "Repair/source"),
                          ("coding_delay_p50_ms", "Coding P50 ms"), ("coding_delay_p99_ms", "Coding P99 ms"),
                          ("ideal_source_ack_p99_ms", "Ideal source ACK P99 ms"),
                          ("exceeds_35ms_probability", "P(coding delay >35ms)"),
                          ("application_rate_ceiling_mbps", "Rate ceiling Mbps")]))
    page = page.replace("__BLOCK__", table(block, [("forward_mbps", "Link Mbps"), ("packets_in_budget", "Packet budget"),
                          ("erased_source_unresolved_probability", "Unresolved source probability"),
                          ("required_repair_per_source", "Repair/source for 1%"),
                          ("application_rate_ceiling_at_required_repairs_mbps", "Rate ceiling Mbps")]))
    page = page.replace("__REFERENCE__", table(references, [("seed", "Seed"), ("observed_application_mbps", "Application Mbps"),
                          ("observed_timestamp_rtt_p99_ms", "Timestamp RTT P99 ms"),
                          ("observed_forward_queue_p99_ms", "Forward queue P99 ms"),
                          ("observed_reverse_queue_p99_ms", "Reverse queue P99 ms"),
                          ("observed_strict_extra_packets_pct", "Strict extra packets %")]))
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--latency-root", type=Path, default=Path("work/results-20261110/tcp-latency"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    capacities, blocks, references = capacity_rows(), block_rows(), reference_rows(args.latency_root)
    stream = []
    for loss, ratios in ((.15, (.19, .20, .21, .22, .23, .24, .25, .30)), (.20, (.20, .25, .30))):
        for ratio in ratios:
            base, survival = streaming_delay(ratio, loss)
            for bandwidth in (10, 100, 1000):
                row = dict(base, forward_mbps=bandwidth, ip_packet_bytes=1500, payload_bytes=1448,
                           base_rtt_ms=70, target_round_trip_ms=105,
                           source_injection_rate_mbps=bandwidth * 1448 / 1500 / (1 + ratio),
                           application_rate_ceiling_mbps=bandwidth * 1448 / 1500 / (1 + ratio)
                           if base["stationary"] else None)
                if survival is not None:
                    slot_ms = 1500 * 8 / bandwidth / 1000
                    for percent in (50, 95, 99):
                        slots = base[f"coding_delay_p{percent}_slots"]
                        row[f"coding_delay_p{percent}_ms"] = slots * slot_ms if slots is not None else None
                    row["ideal_source_ack_p99_ms"] = 70 + row["coding_delay_p99_ms"] if row["coding_delay_p99_ms"] is not None else None
                    row["exceeds_35ms_probability"] = float(survival[floor(35 / slot_ms)])
                stream.append(row)
            print(f"Calculated loss={loss:g}, repairs/source={ratio:g}", flush=True)
    for name, rows in (("capacity-bounds", capacities), ("block-budget", blocks),
                       ("streaming-queue", stream), ("existing-reference", references)):
        write_csv(args.out / (name + ".csv"), rows)
    results = dict(capacity=capacities, isolated_blocks=blocks, streaming_queue=stream, existing_reference=references)
    (args.out / "analytical-results.json").write_text(json.dumps(results, indent=2, allow_nan=False))
    simulator = Path(__file__).resolve().parents[1]
    paths = [Path(__file__), *(simulator / "src/l2tunnel_sim" / name for name in
                              ("compact.py", "compact_arq.py", "compact_tcp.py", "compact_block.py"))]
    manifest = dict(analysis_kind="deterministic mathematical calculations", protocol_executions=0,
                    primary_sources=SOURCES, python=platform.python_version(),
                    sources={str(path): sha256(path.read_bytes()).hexdigest() for path in paths},
                    numerical_checks=["row stochastic transition matrices", "stationarity residual <1e-10",
                                      "stationary boundary mass <=1e-10", "tagged truncation mass <1e-8",
                                      "stationary Q256 versus Q512 L1 difference <1e-8",
                                      "monotone survival probability"],
                    limitations=["ideal innovative repair, no GF256 rank loss", "no queue or coding CPU",
                                 "uniform source observations, not selected TCP timestamp samples",
                                 "successful immediate reverse ACK", "no universal finite-delay converse"])
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    plot_reference(args.out, stream)
    report(args.out, stream, capacities, blocks, references)
    print(f"Wrote analytical report to {args.out}", flush=True)


if __name__ == "__main__":
    main()
