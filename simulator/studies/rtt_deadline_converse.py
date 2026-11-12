"""Coding-only necessary conditions for a 35 ms recovery deadline.

The finite-window bound is independent of coding and feedback policy within
its explicitly fixed-slot, fixed-arrival model. It is not an impossibility
proof for arbitrary TCP admission or variable packetization.
"""

import argparse
import csv
from fractions import Fraction
from hashlib import sha256
from html import escape
import json
from math import floor, log10
from pathlib import Path
import platform

import numpy as np
from scipy.special import logsumexp
from scipy.stats import binom


PRIMARY_SOURCES = [
    dict(title="Sahai, fixed-delay reliability with feedback",
         url="https://arxiv.org/pdf/cs/0610138",
         scope="Theorems 3.1–3.4 are asymptotic fixed-delay exponents"),
    dict(title="Polyanskiy, Poor and Verdu, finite-blocklength channel coding",
         url="https://people.lids.mit.edu/yp/homepage/data/finite_block.pdf",
         scope="Finite-blocklength message-error bounds require a specified block model"),
    dict(title="Fong et al., optimal streaming codes",
         url="https://arxiv.org/pdf/1801.04241",
         scope="Structured convolutional codes for bounded sliding-window erasures"),
    dict(title="Bhatnagar et al., burst and random erasure streaming codes",
         url="https://arxiv.org/pdf/2405.06621",
         scope="Diagonal embedding under a bounded sliding-window loss model"),
]


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def finite_cut(source_count, *, budget_ms=35, application_mbps=80,
               payload_bytes=1448, packet_bytes=1500, useful_bytes=1472,
               loss_rate=.15):
    """Expected unrecovered fraction from an entropy cut, not block failure.

    A group of K fresh messages arrives at a fixed application rate. We grant
    service throughout K arrival intervals plus the recovery budget, including
    an extra packet at time zero. This relaxes every earlier individual deadline.
    For S successful packets, zero-error partial decoding obeys
    E[unrecovered | S] >= max(0, K - S * useful_bytes / payload_bytes).
    """
    counts = np.asarray(source_count, dtype=np.int64)
    budget = Fraction(str(budget_ms))
    arrival_ms = Fraction(payload_bytes * 8, application_mbps * 1000)
    packet_ms = Fraction(packet_bytes * 8, 100 * 1000)
    windows = [floor((int(count) * arrival_ms + budget) / packet_ms) + 1
               for count in counts.reshape(-1)]
    packets = np.asarray(windows, dtype=np.int64).reshape(counts.shape)
    # Largest integer S with a strictly positive information deficit.
    threshold = (counts * payload_bytes - 1) // useful_bytes
    cdf = binom.cdf(threshold, packets, 1 - loss_rate)
    first_moment = packets * (1 - loss_rate) * binom.cdf(threshold - 1, packets - 1, 1 - loss_rate)
    bound = np.maximum(0, cdf - useful_bytes / (counts * payload_bytes) * first_moment)
    return packets, threshold, bound


def direct_cut(source_count, packet_count, *, useful_bytes=1472,
               payload_bytes=1448, loss_rate=.15):
    """Positive-term log sum checks subtraction in the fast CDF expression."""
    threshold = (source_count * payload_bytes - 1) // useful_bytes
    successes = np.arange(threshold + 1)
    remaining_fraction = (source_count * payload_bytes - successes * useful_bytes) / (source_count * payload_bytes)
    log_terms = binom.logpmf(successes, packet_count, 1 - loss_rate) + np.log(remaining_fraction)
    log_bound = float(logsumexp(log_terms))
    return float(np.exp(log_bound)), log_bound / np.log(10)


def window_cases(max_sources):
    counts = np.arange(1, max_sources + 1)
    cases, curves = [], []
    profiles = [("Current optimistic IPv4 UDP budget", 35, 1472),
                ("20 ms residual coding budget", 20, 1472),
                ("10 ms residual coding budget", 10, 1472),
                ("One 1448-byte record unit per packet", 35, 1448)]
    for name, budget, useful in profiles:
        packets, _, bounds = finite_cut(counts, budget_ms=budget, useful_bytes=useful)
        index = int(np.argmax(bounds))
        k, n = int(counts[index]), int(packets[index])
        value, logarithm = direct_cut(k, n, useful_bytes=useful)
        relative_error = abs(value - bounds[index]) / value
        assert relative_error < 1e-7
        cases.append(dict(record_kind="analytic_finite_window_entropy_cut", name=name,
                          application_rate_assumption_mbps=80, loss_rate=.15,
                          residual_budget_ms=budget, payload_bytes=1448,
                          fixed_slot_ip_bytes=1500, information_bytes_per_success=useful,
                          searched_source_counts=max_sources, selected_source_count=k,
                          granted_channel_uses=n, mean_unrecovered_fraction_lower_bound=value,
                          log10_lower_bound=logarithm, cdf_vs_positive_sum_relative_error=relative_error,
                          excludes_one_percent_target=value > .01))
        sampled = np.unique(np.concatenate((np.geomspace(1, max_sources, 160).astype(int) - 1, [index])))
        for position in sampled:
            curves.append(dict(record_kind="analytic_cut_curve", name=name,
                               source_count=int(counts[position]), granted_channel_uses=int(packets[position]),
                               mean_unrecovered_fraction_lower_bound=float(bounds[position])))
    return cases, curves


def blackout_cases():
    rows = []
    for minimum_ip_bytes, scope in ((28, "Any IPv4 UDP packet length in this channel model"),
                                    (1500, "Fixed full-MTU packet comparison only")):
        duration = Fraction(35, 1)
        packet_ms = Fraction(minimum_ip_bytes * 8, 100 * 1000)
        attempts = floor(duration / packet_ms) + 1
        for loss in (.15, .20):
            logarithm = attempts * log10(loss)
            rows.append(dict(record_kind="analytic_causal_blackout_bound", scope=scope,
                             minimum_ip_bytes=minimum_ip_bytes, budget_ms=35, loss_rate=loss,
                             maximum_transmission_starts=attempts,
                             zero_error_deadline_miss_lower_bound_expression=f"{loss}^{attempts}",
                             log10_lower_bound=logarithm))
    return rows


def envelope_cases():
    rows = []
    for loss in (.15, .20):
        payload, header, mtu, maximum_packets = 1448, 28, 1500, 1.2
        minimum_average = header + payload / ((1 - loss) * maximum_packets)
        rows.append(dict(record_kind="analytic_long_run_necessary_condition", loss_rate=loss,
                         useful_ip_bytes=mtu - header, application_payload_bytes=payload,
                         target_application_mbps=80, maximum_packets_per_delivered_segment=maximum_packets,
                         optimistic_application_capacity_mbps=100 * (1 - loss) * (mtu - header) / mtu,
                         minimum_packets_per_delivered_segment=payload / ((1 - loss) * (mtu - header)),
                         minimum_mean_ip_bytes_under_packet_gate=minimum_average,
                         maximum_fraction_packets_at_most_750_bytes=max(0, (mtu - minimum_average) / (mtu - 750)),
                         maximum_fraction_packets_at_most_256_bytes=max(0, (mtu - minimum_average) / (mtu - 256)),
                         maximum_loss_allowed_by_packet_gate=1 - payload / (maximum_packets * (mtu - header)),
                         packet_gate_capacity_feasible=minimum_average <= mtu,
                         bandwidth_capacity_feasible=100 * (1 - loss) * (mtu - header) / mtu >= 80))
    return rows


def self_checks():
    checks = {}
    counts = np.arange(1, 81)
    for loss in (0, .15, 1):
        packets, _, bound = finite_cut(counts, budget_ms=0, loss_rate=loss)
        direct = [direct_cut(int(k), int(n), loss_rate=loss)[0] for k, n in zip(counts, packets)]
        assert np.allclose(bound, direct, rtol=1e-9, atol=1e-14)
    checks["cdf_matches_positive_term_sum_on_small_cases"] = True
    assert np.all(finite_cut(counts, loss_rate=0)[2] == 0)
    assert np.all(finite_cut(counts, loss_rate=1)[2] == 1)
    checks["zero_and_total_erasure_edges"] = True
    assert np.all(finite_cut(counts, budget_ms=35)[2] <= finite_cut(counts, budget_ms=10)[2] + 1e-14)
    checks["additional_time_weakens_lower_bound"] = True
    assert blackout_cases()[0]["maximum_transmission_starts"] == 15626
    checks["exact_rational_time_rounding"] = True
    envelope = envelope_cases()
    assert envelope[0]["packet_gate_capacity_feasible"] and not envelope[1]["packet_gate_capacity_feasible"]
    assert envelope[0]["bandwidth_capacity_feasible"] and not envelope[1]["bandwidth_capacity_feasible"]
    checks["historical_twenty_percent_loss_capacity_separated"] = True
    return checks


def table(rows, columns):
    header = "".join(f"<th>{escape(title)}</th>" for _, title in columns)
    content = []
    for row in rows:
        cells = []
        for key, _ in columns:
            value = row[key]
            text = f"{value:.6g}" if isinstance(value, float) else str(value)
            cells.append(f"<td>{escape(text)}</td>")
        content.append("<tr>" + "".join(cells) + "</tr>")
    return "<table><thead><tr>" + header + "</tr></thead><tbody>" + "".join(content) + "</tbody></table>"


def report(output, cases, blackouts, envelopes):
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Finite-deadline necessary conditions</title>
<style>body{max-width:1120px;margin:35px auto;padding:20px;font:16px/1.55 system-ui;color:#24394a}h1,h2{line-height:1.2}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:9px;border-bottom:1px solid #cbd5de;text-align:left}th{background:#eaf1f6}code{background:#edf2f6;padding:3px}.notice{background:#fff0d8;padding:18px;border-left:5px solid #a36420}a{color:#126b94}</style>
<h1>Finite-deadline necessary conditions for the 80 Mbps goal</h1>
<p class="notice">No impossibility proof for the current 15% loss target was established. The derived general bounds are far below the allowed 1% late-segment fraction. All calculations are coding-only necessary conditions. This report contains zero protocol executions and zero protocol Pareto points.</p>
<h2>Target and assumptions</h2>
<p>The reference is 100 Mbps forward IP service, 10 Mbps reverse, 70 ms nominal RTT, 15% independent packet erasures, MTU 1500, 1448-byte TCP application payload, full application throughput at least 80 Mbps and all-original-segment ACK completion P99 at most 105 ms. Granting zero ACK serialization, zero ACK loss, zero queueing and zero codec time leaves a generous 35 ms forward recovery budget. Recovery by that time is necessary for the ACK deadline. Source payload is arbitrary fresh information when submitted, with no payload-dependent timing side channel and no advance receiver knowledge. Exact recovery is required.</p>
<h2>A finite entropy cut with explicit scope</h2>
<p>Consider K fresh independent messages of B bytes each, arriving at a fixed rate A. Grant the decoder every message outside this group. Allow arbitrary causal coding, arbitrary field size, arbitrary partial decoding and even ideal immediate feedback. For this cut only, the channel uses fixed 1500-byte slots, each successful use conveys at most U bytes of information, and source arrivals occur at fixed intervals. Grant service for K arrival intervals plus D ms, with an extra transmission at the start. Thus <code>n = floor((K·8B/A + D)/slot) + 1</code> and <code>S ~ Binomial(n, 1−p)</code>.</p>
<p>Condition on an erasure pattern with S successes. The output carries at most 8US bits about the group, while its input entropy is 8BK bits. If M messages remain undecodable under zero-error partial decoding, the residual entropy is at most 8B·E[M]. Therefore <code>E[M|S] ≥ (K−US/B)⁺</code>. Averaging gives the exact finite lower bound <code>E[M]/K ≥ E[(KB−US)⁺]/(KB)</code>. Messages unavailable even at the group's last deadline necessarily missed their individual deadlines. Applying the argument to consecutive groups bounds the mean late-message fraction within this fixed-arrival model. No full-rank-block decoding assumption is used.</p>
<p>The calculation grants U=1472 after only IPv4/UDP. Every coding, framing, authentication and record-header cost is omitted to make this cut optimistic. The second packet-budget reference grants one 1448-byte record unit per success. The script scans K from 1 through 20,000 and checks each selected maximum by a positive-term log-probability sum. The displayed maximum is over this finite scan. It is a valid lower bound even if a stronger cut exists elsewhere.</p>
__CUTS__
<p>Fixed slots and exogenous arrivals are substantive assumptions. MTU is a maximum size, and TCP submission times depend on feedback. Consequently these numeric fixed-slot cuts cannot be presented as bounds for every possible packetizer or TCP admission policy. Their already tiny magnitude provides no exclusion at the 1% target. Asymptotic throughput alone does not imply the fixed-arrival trace used here.</p>
<h2>A weaker bound that admits adaptive packetization</h2>
<p>Within this IPv4/UDP channel model, every datagram consumes at least 28 bytes of IP service. At most 15,626 transmission starts can occur in the 35 ms interval, including a freely granted start at its beginning. Couple any causal encoder and scheduler to an infinite IID erasure sequence. If its first 15,626 potential transmissions are erased, no information about a fresh message reaches the receiver by its deadline. This event has probability <code>p^15626</code>, regardless of how feedback changes the actual number, lengths or contents of transmissions. Exact decoding must fail on that event. This bound also permits noiseless immediate feedback and adaptive admission at any stopping time that cannot see future erasures. It excludes payload-dependent signaling through timing or headers outside the counted information channel.</p>
__BLACKOUTS__
<p>The probability is astronomically smaller than 1%. The full-MTU comparison applies only to fixed full-size transmissions. No universal 1% impossibility conclusion follows from either blackout calculation.</p>
<h2>Long-run bandwidth and packet-count envelope</h2>
<p>Let N datagrams deliver K arbitrary B-byte segments completely. Each successfully received datagram carries at most <code>L−28</code> information bytes, with L≤1500. IID erasures imply the necessary long-run condition <code>KB ≤ (1−p)·Σ(L−28)</code>. Combining it with N/K≤1.2 gives <code>mean(L) ≥ 28 + B/((1−p)·1.2)</code>. These are long-run expected or ergodic constraints, with finite boundary effects excluded.</p>
__ENVELOPE__
<p>At 15% loss, the average IP datagram must be at least 1447.608 bytes under the strict 20% packet gate, even after granting all tunnel metadata for free. At most 6.986% of datagrams can be 750 bytes or smaller if all others are 1500 bytes. Thus using small outer datagrams throughout the stream cannot satisfy that packet gate. Several smaller coding symbols may still be packed into one datagram, preserving the common erasure event. At historical 20% loss, the optimistic IP/UDP application capacity is 78.507 Mbps and the minimum packet multiplier exceeds 1.2. That historical condition fails both asymptotic gates.</p>
<h2>What the primary sources establish</h2>
<p>Sahai's Theorem 3.1 bounds asymptotic fixed-delay exponents without feedback. Theorems 3.2–3.4 treat feedback and show substantially different limits. Achievability with constant feedback delay concerns asymptotically large decoding delay. These statements do not supply a finite 35 ms, 70 ms-feedback, 1% packet-deadline test by substituting an exponent. The present entropy cut is derived above separately. <a href="https://arxiv.org/pdf/cs/0610138">Sahai, fixed-delay reliability with feedback</a></p>
<p>Finite-blocklength converses address specified message and block models. A whole-block error bound cannot be substituted for the mean missed-segment fraction of a causal stream with individual deadlines. <a href="https://people.lids.mit.edu/yp/homepage/data/finite_block.pdf">Polyanskiy, Poor and Verdu</a></p>
<p>Structured convolutional and diagonal-embedding constructions provide finite-deadline guarantees for bounded sliding-window erasure patterns. Their guarantees need an explicit mapping to IID loss probabilities, actual field size, charged subpacketization and the complete-record delivery metric. IID loss can violate their assumed pattern bounds. <a href="https://arxiv.org/pdf/1801.04241">Fong et al.</a> · <a href="https://arxiv.org/pdf/2405.06621">Bhatnagar et al.</a></p>
<h2>Implementation avenues that remain open</h2>
<p>These results leave structured deadline-aware convolutional codes, causal short/long protection mixes with reliable fallback, independent per-channel record release and improved reverse ACK scheduling open for investigation. Previous random-band failures constrain those tested policies. Current-loss feedback arrives too late for the original 35 ms coding budget, so protection that meets that deadline must be selected causally before receiving feedback about that loss. Older feedback can still inform the scheduler. Any proposed implementation must preserve the complete original-segment denominator and charge every wire byte and forward datagram.</p>
<p>Whether one practical design simultaneously reaches 80 Mbps, all-segment ACK P99≤105 ms and at most 20% extra forward packets at 15% loss remains unresolved.</p>
<p><a href="window-cuts.csv">Finite-window cases</a> · <a href="cut-curves.csv">Sampled cut curves</a> · <a href="blackout-bounds.csv">Blackout bounds</a> · <a href="capacity-envelope.csv">Capacity and packet envelope</a> · <a href="validation-checks.json">Finite checks</a> · <a href="manifest.json">Provenance</a></p></html>'''
    page = page.replace("__CUTS__", table(cases, [("name", "Analytical case"), ("selected_source_count", "K"),
                   ("granted_channel_uses", "n"), ("mean_unrecovered_fraction_lower_bound", "Late fraction lower bound")]))
    page = page.replace("__BLACKOUTS__", table(blackouts, [("scope", "Scope"), ("loss_rate", "Erasure p"),
                   ("maximum_transmission_starts", "Maximum starts"), ("log10_lower_bound", "log10 lower bound")]))
    page = page.replace("__ENVELOPE__", table(envelopes, [("loss_rate", "Loss"),
                   ("optimistic_application_capacity_mbps", "Application ceiling Mbps"),
                   ("minimum_packets_per_delivered_segment", "Minimum packet multiplier"),
                   ("minimum_mean_ip_bytes_under_packet_gate", "Minimum average IP bytes at 1.2 packets/segment")]))
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    checks = self_checks()
    cases, curves = window_cases(20000)
    blackouts, envelopes = blackout_cases(), envelope_cases()
    write_csv(args.out / "window-cuts.csv", cases)
    write_csv(args.out / "cut-curves.csv", curves)
    write_csv(args.out / "blackout-bounds.csv", blackouts)
    write_csv(args.out / "capacity-envelope.csv", envelopes)
    checks["selected_large_window_cdf_checks"] = all(row["cdf_vs_positive_sum_relative_error"] < 1e-7 for row in cases)
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2))
    source = Path(__file__).resolve()
    (args.out / source.name).write_bytes(source.read_bytes())
    manifest = dict(record_kind="analytical_deadline_converse_manifest", protocol_executions=0,
                    finite_window_analytic_cases=len(cases), python=platform.python_version(),
                    source_sha256=sha256(source.read_bytes()).hexdigest(), source=str(source),
                    primary_sources=PRIMARY_SOURCES,
                    assumptions=["arbitrary fresh payload and exact recovery", "100 Mbps IP service",
                                 "IID packet erasures independent of prior history", "no timing side channel",
                                 "fixed slots and fixed source arrivals for window-cut cases only",
                                 "ideal ACK path and ideal instantaneous feedback granted in converse"],
                    conclusion="No exclusion of the current 15% loss, 80 Mbps, 105 ms ACK-P99 target")
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    report(args.out, cases, blackouts, envelopes)
    print(json.dumps(dict(checks=checks, current_optimistic_cut=cases[0], packet_envelope=envelopes[0]), indent=2))


if __name__ == "__main__":
    main()
