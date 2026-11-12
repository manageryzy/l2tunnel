"""Coding-only systematic finite-memory subpacket convolutional screen."""

import argparse
from bisect import bisect_left, bisect_right
from collections import deque
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256, shake_256
from html import escape
import json
from pathlib import Path
import platform
from random import Random
import struct
from time import perf_counter

import numpy as np

from l2tunnel_sim.coding import Decoder
from l2tunnel_sim.compact import CompactHeaderCodec, tcp_profile_frame
from l2tunnel_sim.shared_records import RECORD_HEADER, SYMBOL_HEADER, NO_RECORD_HEADER, SharedRecordReceiver
from l2tunnel_sim.stats import mean_ci


K = 5
SHARD_BYTES = 244
SOURCE_BYTES = K * SHARD_BYTES
RECORD_CAPACITY = SOURCE_BYTES - SYMBOL_HEADER.size
IP_BYTES = 28 + 8 + (K + 1) * SHARD_BYTES
SLOT_MS = IP_BYTES * 8 / 100000
PAYLOAD_BYTES = 1448
CODE_SEED = b"L2SC-v1!"
PROFILES = [dict(name="Time-varying M64", memory=64, invariant=False),
            dict(name="Time-varying M128", memory=128, invariant=False),
            dict(name="Time-varying M256", memory=256, invariant=False),
            dict(name="Time-invariant M128", memory=128, invariant=True)]
SEEDS = [20261110, 20261111, 20261112]


def coefficient_bytes(packet, memory, invariant):
    """Public deterministic coefficients ordered by lag, then source shard."""
    identity = b"I" if invariant else b"V" + packet.to_bytes(6, "big")
    return shake_256(CODE_SEED + identity).digest(memory * K)


def parity_equation(packet, memory, invariant):
    values = coefficient_bytes(packet, memory, invariant)
    return {(packet - lag) * K + shard: values[(lag - 1) * K + shard]
            for lag in range(1, min(memory, packet) + 1) for shard in range(K)}


def build_stream(packet_count):
    """Pack actual reversible frame records using the existing shared format.

    Frames arrive just before their first coding source is assembled. Each
    channel has an independent codec and a complete 1514-byte input frame.
    Echo timestamps follow a specified synthetic 70 ms lag, without a TCP loop.
    """
    codecs = [CompactHeaderCodec(delta=True) for _ in range(128)]
    byte_buffer, starts, payloads, records, ends = bytearray(), deque(), [], [], []
    submitted = sent = padding = context_bytes = 0
    for packet in range(packet_count):
        while len(byte_buffer) < RECORD_CAPACITY:
            identifier = len(records)
            channel, serial = identifier % 128, identifier // 128
            timestamp = int(packet * SLOT_MS)
            frame = tcp_profile_frame(sequence=serial * PAYLOAD_BYTES, identification=serial,
                                      timestamp=timestamp, echoed_timestamp=max(0, timestamp - 70),
                                      payload_bytes=PAYLOAD_BYTES)
            body = codecs[channel].encode(frame)
            encoded = RECORD_HEADER.pack(channel, serial & 65535, len(body)) + body
            context_bytes += 69 if body[0] == 0 else 0
            starts.append(submitted)
            records.append(dict(channel=channel, serial=serial, created_slot=packet,
                                start=submitted, end=submitted + len(encoded), frame=frame))
            byte_buffer.extend(encoded)
            submitted += len(encoded)
        size = RECORD_CAPACITY
        end = sent + size
        split = next((start for start in starts if end - RECORD_HEADER.size < start < end), None)
        if split is not None:
            size = split - sent
        anchor = starts[0] - sent if starts and starts[0] - sent < size else NO_RECORD_HEADER
        payloads.append(SYMBOL_HEADER.pack(size, anchor) + bytes(byte_buffer[:size]) + bytes(RECORD_CAPACITY - size))
        del byte_buffer[:size]
        sent += size
        ends.append(sent)
        padding += RECORD_CAPACITY - size
        while starts and starts[0] < sent:
            starts.popleft()
    for record in records:
        record["first_source"] = bisect_right(ends, record["start"])
        record["last_source"] = bisect_left(ends, record["end"])
    return payloads, records, dict(padding_bytes=padding, context_bytes=context_bytes,
                                   packed_record_bytes=sent, submitted_record_bytes=submitted,
                                   trailing_unpacked_bytes=len(byte_buffer))


def latency_summary(delays, prefix):
    finite = np.isfinite(delays)
    values = delays[finite]
    return {prefix + "_count": len(delays),
            prefix + "_deadline_miss_fraction": float(np.mean(delays > 35)),
            prefix + "_unresolved_fraction": float(np.mean(~finite)),
            prefix + "_recovered_only_p99_ms": float(np.percentile(values, 99)) if len(values) else None,
            prefix + "_unconditional_p99_ms": float(np.percentile(delays, 99)) if finite.all() else None}


def execute(task):
    started = perf_counter()
    count, warmup, tail = task["packet_count"], task["warmup_packets"], task["tail_packets"]
    profile = task["profile"]
    payloads, records, packing = build_stream(count)
    decoder = Decoder()
    receiver = SharedRecordReceiver(RECORD_CAPACITY)
    rng = Random(task["seed"])
    source_remaining = np.full(count, K, dtype=int)
    source_known_ms = np.full(count, np.inf)
    record_delivered_ms = np.full(len(records), np.inf)
    expected = {(record["channel"], record["serial"]): index for index, record in enumerate(records)}
    erasure_digest = sha256()
    peak_rows = 0
    lost_packets = 0

    def accept_equation(equation, completed_ms):
        for symbol in decoder.insert(equation):
            source = symbol // K
            source_remaining[source] -= 1
            if source_remaining[source] == 0:
                source_known_ms[source] = completed_ms
                for channel, serial, frame in receiver.receive(source, payloads[source]):
                    index = expected[channel, serial]
                    assert frame == records[index]["frame"]
                    assert not np.isfinite(record_delivered_ms[index])
                    record_delivered_ms[index] = completed_ms

    for packet in range(count):
        lost = rng.random() < task["loss_rate"]
        erasure_digest.update(bytes([lost]))
        lost_packets += lost
        if lost:
            continue
        completed_ms = (packet + 1) * SLOT_MS
        # All five systematic shards and the parity share this one erasure.
        for shard in range(K):
            accept_equation({packet * K + shard: 1}, completed_ms)
        accept_equation(parity_equation(packet, profile["memory"], profile["invariant"]), completed_ms)
        peak_rows = max(peak_rows, len(decoder.rows))

    selected_sources = np.arange(warmup, count - tail)
    source_delays = source_known_ms[selected_sources] - selected_sources * SLOT_MS
    selected_records = [index for index, record in enumerate(records)
                        if warmup <= record["created_slot"] < count - tail]
    local_delays = []
    ordered_delays = []
    for index in selected_records:
        record = records[index]
        assert record["last_source"] < count
        local_completed = max(source_known_ms[record["first_source"]:record["last_source"] + 1])
        local_delays.append(local_completed - record["created_slot"] * SLOT_MS)
        ordered_delays.append(record_delivered_ms[index] - record["created_slot"] * SLOT_MS)
    record_bytes = sum(records[index]["end"] - records[index]["start"] for index in selected_records)
    payload_bytes = len(selected_records) * PAYLOAD_BYTES
    measured_slots = count - warmup - tail
    row = dict(task, record_kind="analytic_subpacket_convolutional_case", policy=profile["name"],
               source_shards_per_packet=K, parity_shards_per_packet=1, shard_bytes=SHARD_BYTES,
               ip_bytes_per_packet=IP_BYTES, forward_wire_bytes_analytic=IP_BYTES * count,
               source_header_bytes_per_packet=SYMBOL_HEADER.size,
               record_header_bytes=RECORD_HEADER.size, fec_header_bytes=8, ip_udp_header_bytes=28,
               record_stream_capacity_mbps=RECORD_CAPACITY * 8 / SLOT_MS / 1000,
               measured_record_expansion_bytes_per_frame=(record_bytes - payload_bytes) / len(selected_records),
               offered_application_rate_mbps_analytic=payload_bytes * 8 / (measured_slots * SLOT_MS) / 1000,
               long_run_packet_multiplier_analytic=IP_BYTES / RECORD_CAPACITY * record_bytes / payload_bytes * PAYLOAD_BYTES / IP_BYTES,
               minimum_extra_packets_per_application_record_pct_analytic=100 * (record_bytes / len(selected_records) / RECORD_CAPACITY - 1),
               coding_deadline_ms=35, slot_ms=SLOT_MS, memory_ms=profile["memory"] * SLOT_MS,
               erasure_trace_sha256=erasure_digest.hexdigest(), source_bytes_sha256=sha256(b"".join(payloads)).hexdigest(),
               lost_packets=lost_packets, final_known_shards=len(decoder.known), final_decoder_rows=len(decoder.rows),
               peak_decoder_rows=peak_rows, full_input_source_unresolved=int(np.sum(source_remaining > 0)),
               full_input_record_count=len(records), full_input_records_delivered=int(np.sum(np.isfinite(record_delivered_ms))),
               actual_reconstructed_frame_bytes=int(np.sum(np.isfinite(record_delivered_ms))) * (PAYLOAD_BYTES + 66),
               compute_seconds=perf_counter() - started, **packing)
    row.update(latency_summary(source_delays, "source"))
    row.update(latency_summary(np.asarray(local_delays), "record_local"))
    row.update(latency_summary(np.asarray(ordered_delays), "record_inorder"))
    return row


def write_csv(path, rows):
    import csv
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value
                         for key, value in row.items()} for row in rows)


def summarize(rows):
    result = []
    for policy in dict.fromkeys(row["policy"] for row in rows):
        group = [row for row in rows if row["policy"] == policy]
        item = dict(record_kind="analytic_subpacket_convolutional_summary", policy=policy, n=len(group))
        for field in ("source_deadline_miss_fraction", "source_unresolved_fraction", "source_recovered_only_p99_ms",
                      "record_local_deadline_miss_fraction", "record_local_unresolved_fraction",
                      "record_inorder_deadline_miss_fraction", "record_inorder_unresolved_fraction",
                      "offered_application_rate_mbps_analytic"):
            estimate = mean_ci([row[field] for row in group])
            item[field] = estimate["mean"]
            item[field + "_ci_low"], item[field + "_ci_high"] = estimate["ci_low"], estimate["ci_high"]
        result.append(item)
    return result


def render(output, rows, summary):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 5.8))
    colors = ["#31688e", "#21918c", "#bf7700", "#a34d78"]
    for index, item in enumerate(summary):
        group = [row for row in rows if row["policy"] == item["policy"]]
        for axis, prefix in zip(axes, ("source", "record_local")):
            x = [100 * row[prefix + "_deadline_miss_fraction"] for row in group]
            y = [row["offered_application_rate_mbps_analytic"] for row in group]
            axis.scatter(x, y, label=item["policy"], color=colors[index], s=65)
            for row, xp, yp in zip(group, x, y):
                axis.annotate(str(row["analytic_case_id"]), (xp, yp), xytext=(4, 3), textcoords="offset points", fontsize=8)
        axes[0].set_xlabel("Full source-block 35 ms deadline misses (%)")
        axes[1].set_xlabel("Full 1448 B record local 35 ms deadline misses (%)")
    for axis in axes:
        axis.set_ylabel("Offered application rate from charged framing (Mbps)")
        axis.axvline(1, color="#a33", linestyle="--", linewidth=1)
        axis.axhline(80, color="#a33", linestyle="--", linewidth=1)
        axis.grid(alpha=.2)
    fig.suptitle(f"Systematic subpacket convolutional coding · all {len(rows)} analytical cases", fontsize=14)
    fig.legend(loc="lower center", ncol=2, frameon=False)
    fig.tight_layout(rect=(0, .12, 1, .94))
    fig.savefig(output / "all-analytic-cases.png", dpi=160)
    plt.close(fig)
    table = []
    for item in summary:
        table.append("<tr>" + "".join(f"<td>{value}</td>" for value in
            (escape(item["policy"]), item["n"], f'{100 * item["source_deadline_miss_fraction"]:.3f}%',
             f'{100 * item["source_unresolved_fraction"]:.3f}%', f'{item["source_recovered_only_p99_ms"]:.3f}',
             f'{100 * item["record_local_deadline_miss_fraction"]:.3f}%',
             f'{100 * item["record_inorder_deadline_miss_fraction"]:.3f}%')) + "</tr>")
    case_table = []
    for row in rows:
        case_table.append("<tr>" + "".join(f"<td>{value}</td>" for value in
            (f'<a href="cases/{row["analytic_case_id"]:03d}.json">{row["analytic_case_id"]}</a>', escape(row["policy"]),
             row["seed"], f'{100 * row["source_deadline_miss_fraction"]:.3f}%',
             f'{100 * row["record_local_deadline_miss_fraction"]:.3f}%', row["full_input_source_unresolved"],
             f'{row["full_input_records_delivered"]}/{row["full_input_record_count"]}')) + "</tr>")
    first = rows[0]
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Subpacket convolutional coding screen</title>
<style>body{{max-width:1200px;margin:30px auto;padding:20px;font:16px/1.5 system-ui;color:#203748}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{padding:8px;border-bottom:1px solid #cbd4df}}th{{background:#edf3f7}}code{{background:#edf3f7;overflow-wrap:anywhere}}.notice{{padding:14px;background:#fff0d8;border-left:5px solid #a35e20}}a{{color:#12688d}}.table-scroll{{max-width:100%;overflow-x:auto}}</style>
<h1>Systematic finite-memory parity inside every packet</h1>
<p class="notice">All {len(rows)} cases are coding-only experiments. The plotted rate is offered application data inferred from a synthetic, byte-checked framing workload. It is not delivered TCP goodput. No TCP congestion control, reverse ACK traffic, authentication execution or codec CPU cost is modeled. Protocol executions are zero.</p>
<h2>Causal construction and packet loss</h2>
<p>Packet t contains five new 244-byte systematic vectors and one 244-byte parity vector. For memory M, <code>p[t] = sum(lag=1..M, i=0..4) a[t,lag,i] s[t-lag,i]</code>, with unavailable negative-time sources set to zero. Coefficients are bytes from SHAKE-256 of the fixed public seed <code>L2SC-v1!</code> and the 48-bit packet sequence, ordered by lag and shard. The time-invariant control uses one fixed lag coefficient vector. All operations use GF256 with polynomial 0x11D. The actual repository Decoder performs coefficient elimination and tests individual-source identifiability.</p>
<p>The entire six-vector packet shares one IID 15% erasure event. A successful packet reveals its five systematic vectors and one parity equation. Coefficients depend on sequence and the fixed profile, with no feedback or receiver state at the sender. Every past message's five vectors enter overlapping parity equations. The previous Cauchy diagonal screen placed each coordinate in a separate diagonal block code. Whole-symbol trailing RLNC used separate repair datagrams and a different packet-level erasure correlation.</p>
<h2>Charged byte layout and record mapping</h2>
<p>Each 1500-byte IP packet charges 28 bytes for IPv4/UDP, an 8-byte FEC header and six 244-byte vectors. The header can carry a version byte, a profile byte and a 48-bit packet sequence. Static profiles specify M, coefficients and vector sizes. Each 1220-byte systematic source block contains the existing four-byte valid-length/resynchronization anchor, leaving 1216 bytes for records. Its maximum record-stream rate is 81.0667 Mbps. Authentication bytes are zero.</p>
<p>The probe uses the existing five-byte channel/serial/length record header and reversible CompactHeaderCodec. It builds complete 1514-byte Ethernet/IPv4/TCP frames with 1448 application bytes, then packs their serialized records with the existing rule that a record header cannot straddle a source boundary. Context records, dynamic deltas, framing and padding are all charged. There are 128 independently ordered channels. Frame timestamps track the synthetic source clock, and their echoed timestamps use a prescribed 70 ms lag. These fields define a compression workload without implementing a TCP feedback loop.</p>
<p>The measured record expansion is {first['measured_record_expansion_bytes_per_frame']:.4f} bytes per 1448-byte application record. Actual offered application rate is {first['offered_application_rate_mbps_analytic']:.5f} Mbps after packing. The asymptotic packet-count cost is at least {first['minimum_extra_packets_per_application_record_pct_analytic']:.4f}% beyond one datagram per original application record, before recovery or ACK traffic. This is a separate constraint from the coding rate of 5/6.</p>
<h2>Deadline denominator and receiver behavior</h2>
<p>Each source block is complete only after all five vectors are identifiable. Delay starts at source creation, includes IP serialization, and excludes the common propagation offset. Unresolved blocks remain deadline misses. The 35 ms budget grants the entire difference between 105 ms and the 70 ms base RTT to forward coding. Actual ACK completion has further constraints.</p>
<p>A full-record local metric requires every source block touching that complete 1448-byte record to be available. The byte parser receives only fully identified source blocks, matching SharedRecordReceiver. It then reconstructs exact frame bytes and releases frames in channel sequence order. The ordered-record metric includes this additional channel and codec-context waiting. Partial bytes from a source block whose other vectors remain unknown are not released by this receiver policy.</p>
<p>Each case has {first['packet_count']} packets, {first['warmup_packets']} warmup packets and {first['tail_packets']} trailing packets. The source denominator has {first['source_count']} blocks. The record denominator has {first['record_local_count']} complete original application records whose creation times fall in the same interval. Unknown tails are preserved. Conditional P99 excludes unresolved observations and is labeled accordingly. Unconditional P99 is left empty whenever any observation remains unresolved.</p>
<div class="table-scroll"><table><thead><tr><th>Construction</th><th>Seeds</th><th>Source 35 ms misses</th><th>Source unresolved</th><th>Recovered-only source P99 ms</th><th>Full-record local misses</th><th>Ordered-record misses</th></tr></thead><tbody>{''.join(table)}</tbody></table></div>
<img src="all-analytic-cases.png" style="width:100%" alt="Every analytical case, offered rate versus source and full-record deadline misses">
<h2>Every case and terminal state</h2><div class="table-scroll"><table><thead><tr><th>JSON</th><th>Construction</th><th>Seed</th><th>Source misses</th><th>Record local misses</th><th>Full-input unresolved sources</th><th>Full-input records delivered</th></tr></thead><tbody>{''.join(case_table)}</tbody></table></div>
<h2>Primary-source context and scope</h2>
<p>Su and coauthors analyze finite-memory random streaming codes with finite decoding deadlines and distinguish complete source-vector recovery from aggregate rank. Their theoretical analysis assumes a generalized MDS condition in the large-field regime. The finite GF256 results here are computed by elimination and do not adopt that condition. <a href="https://engineering.purdue.edu/~chihw/pub_pdf/21C_ISIT_RLSCs.pdf">Su et al., ISIT 2021</a></p>
<p>Huang and coauthors analyze systematic streaming codes under whole-packet erasures, where every symbol in a packet is jointly received or erased. Their formulation also requires every coordinate of a source vector for complete recovery. The concrete finite-memory supports and finite GF256 coefficient generator here form an independently specified screen. <a href="https://arxiv.org/pdf/2509.01894">Huang et al., 2025 preprint</a></p>
<p>The decoder executes real GF256 rank operations. For a recovered source vector it exposes the original source bytes to the existing byte parser, as in the current simulator. It does not compute all 244 byte positions of every parity or benchmark an executable parity payload codec. Results are finite samples from these policies and are not a converse for all convolutional codes.</p>
<p><a href="analytic-cases.csv">Every case CSV</a> · <a href="analytic-summary.csv">Means and seed intervals</a> · <a href="manifest.json">Frozen sources and task plan</a> · <a href="validation-checks.json">Validation checks</a> · <a href="all-analytic-cases.png">All-point image</a></p></html>'''
    (output / "report.html").write_text(page)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--packets", type=int, default=12000)
    parser.add_argument("--warmup", type=int, default=2000)
    parser.add_argument("--tail", type=int, default=2000)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    if args.warmup < 0 or args.tail < 300 or args.warmup + args.tail >= args.packets or args.packets >= 2**48:
        parser.error("require nonempty cohort, at least 300 trailing packets, and a 48-bit packet sequence")
    args.out.mkdir(parents=True, exist_ok=True)
    cases = args.out / "cases"
    cases.mkdir(exist_ok=True)
    tasks = [dict(analytic_case_id=1 + index * len(SEEDS) + seed_index, profile=profile, seed=seed,
                  packet_count=args.packets, warmup_packets=args.warmup, tail_packets=args.tail, loss_rate=.15)
             for index, profile in enumerate(PROFILES) for seed_index, seed in enumerate(SEEDS)]
    simulator = Path(__file__).resolve().parents[1]
    files = [Path(__file__).resolve(), *(simulator / "src/l2tunnel_sim" / name for name in
             ("coding.py", "compact.py", "shared_records.py", "stats.py"))]
    hashes = {str(path): sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = dict(record_kind="analytic_subpacket_convolutional_manifest", protocol_executions=0,
                    analytic_tasks=tasks, sources=hashes, python=platform.python_version(), numpy=np.__version__,
                    primary_sources=["https://engineering.purdue.edu/~chihw/pub_pdf/21C_ISIT_RLSCs.pdf",
                                     "https://arxiv.org/pdf/2509.01894"],
                    assumptions=["100 Mbps IP service, MTU1500, 15% IID whole-packet loss",
                                 "all six shards share one packet erasure", "no receiver feedback or sender oracle",
                                 "actual GF256 coefficient elimination, source bytes exposed only after identifiability",
                                 "all created sources and complete-record cohorts retained including unresolved members",
                                 "synthetic reversible TCP-header byte workload, no congestion control or reverse ACK model",
                                 "no parity byte-vector arithmetic, CPU cost or authentication execution"])
    manifest_path = args.out / "manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise ValueError("existing frozen manifest differs")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    snapshots = args.out / "sources"
    snapshots.mkdir(exist_ok=True)
    for path in files:
        (snapshots / path.name).write_bytes(path.read_bytes())
    rows = []
    pending = []
    for task in tasks:
        path = cases / f"{task['analytic_case_id']:03d}.json"
        if path.exists():
            rows.append(json.loads(path.read_text()))
        else:
            pending.append(task)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(execute, task) for task in pending]):
            row = future.result()
            rows.append(row)
            path = cases / f"{row['analytic_case_id']:03d}.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(row, indent=2))
            temporary.replace(path)
            print(f"Saved {row['analytic_case_id']:02d} {row['policy']} sourceMiss={100*row['source_deadline_miss_fraction']:.3f}% recordMiss={100*row['record_local_deadline_miss_fraction']:.3f}% seconds={row['compute_seconds']:.1f}", flush=True)
    rows.sort(key=lambda row: row["analytic_case_id"])
    summary = summarize(rows)
    write_csv(args.out / "analytic-cases.csv", rows)
    write_csv(args.out / "analytic-summary.csv", summary)
    for seed in SEEDS:
        group = [row for row in rows if row["seed"] == seed]
        for key in ("erasure_trace_sha256", "source_bytes_sha256", "source_count", "record_local_count", "forward_wire_bytes_analytic"):
            assert len({row[key] for row in group}) == 1
    assert all(sha256(path.read_bytes()).hexdigest() == hashes[str(path)] for path in files)
    for profile in PROFILES:
        for packet in (0, 1, 7, 64, 256, 1000):
            equation = parity_equation(packet, profile["memory"], profile["invariant"])
            assert all(max(0, packet - profile["memory"]) * K <= symbol < packet * K for symbol in equation)
    checks = dict(frozen_source_hashes_unchanged=True, paired_whole_packet_loss_traces=True,
                  identical_source_bytes_and_cohorts=True, exact_fixed_wire_budget=True,
                  causal_finite_memory_supports=True, byte_exact_reconstructed_frames=True,
                  actual_protocol_executions=0)
    (args.out / "validation-checks.json").write_text(json.dumps(checks, indent=2))
    render(args.out, rows, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
