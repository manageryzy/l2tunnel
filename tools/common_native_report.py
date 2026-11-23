#!/usr/bin/env python3
"""Verify and tabulate common_native_cell.py results of one campaign directory.

The campaign directory holds ``runs/<label>/<row>/result.json`` cells, optional
``reports/<batch>/receipts.jsonl`` runner ledgers and ``frozen/source.json``.
Writes ``reports/per-flow.csv``, ``reports/cells.csv`` and ``reports/README.md``.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
from statistics import median
import struct
import tempfile


# Set by main() from --campaign.
ROOT = Path.cwd()
OUT = ROOT / "reports"
QUANTILES = ("p50_ms", "p95_ms", "p99_ms", "max_ms")
COHORTS = {
    "steady": "steady_completed_first_attempt_to_read",
    "all": "all_completed_first_attempt_to_read",
    "scheduled": "all_completed_scheduled_to_read",
}


def load(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (PermissionError, json.JSONDecodeError) as error:
        return {"read_error": str(error)}


def commit(path, data):
    # Readers may open the report while another case is running.
    with tempfile.NamedTemporaryFile(dir=path.parent, mode="w", encoding="utf-8",
                                     newline="", delete=False) as stream:
        stream.write(data)
        temporary = stream.name
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def as_table(rows, names):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=names, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def index(rows):
    return {row["flow_id"]: row for row in rows or [] if isinstance(row, dict) and "flow_id" in row}


def digest_verified(tx, rx):
    digest = tx.get("sent_sha256")
    return bool(isinstance(tx.get("sent"), int) and tx["sent"] > 0
                and tx["sent"] == rx.get("received") and tx.get("write_closed") and rx.get("eof")
                and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                and digest == rx.get("received_sha256"))


def show(value, decimals=2):
    return f"{value:.{decimals}f}" if isinstance(value, (int, float)) and math.isfinite(value) else "—"


def md(value):
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def socket(value):
    return f"{value[0]}:{value[1]}" if isinstance(value, list) and len(value) == 2 else None


def epoch(record, side):
    return (record.get(side) or {}).get("epoch")


def clock_ok(a, b):
    clock = b.get("clock", {})
    return bool(clock and a.get("clock") == clock
                and clock.get("end_ns", 0) > clock.get("measure_start_ns", 0) > 0
                and all(x.get("completed_ns", 0) >= clock["end_ns"] for x in (a, b)))


def trace_witness(path, count, clock, switch, observed_until):
    """Recover switch evidence from completed receiver records even if a later check failed."""
    requested = switch.get("requested_ns")
    if not clock or not isinstance(requested, int) or not isinstance(observed_until, int):
        return {}
    start, end = clock["measure_start_ns"], clock["end_ns"]
    if not start <= requested < end or observed_until < requested or not path.is_file():
        return {}
    pair = struct.Struct("!QQ")
    raw = path.read_bytes()
    if not isinstance(count, int) or len(raw) != count * pair.size:
        return {}
    settled = switch.get("settled_ns")
    post_observed = isinstance(settled, int) and requested <= settled < end and settled <= observed_until
    before = spanning = after = drain = 0
    previous = requested
    longest_gap = reads_during = 0
    for attempted, completed in pair.iter_unpack(raw):
        if not 0 < attempted <= completed <= observed_until:
            return {}
        before += start <= completed < requested
        spanning += attempted < requested <= completed
        if post_observed:
            if requested <= completed <= settled:
                if completed < previous:
                    return {}
                longest_gap = max(longest_gap, completed - previous)
                previous = completed
                reads_during += 1
            after += settled <= attempted <= completed < end
            drain += settled <= attempted and completed >= end
    return {"completed_before_request_in_steady": before,
            "attempted_before_request_completed_during_or_after": spanning,
            "attempted_and_completed_after_settlement_in_steady": after if post_observed else None,
            "attempted_after_settlement_completed_in_drain": drain if post_observed else None,
            "reads_during_switch": reads_during if post_observed else None,
            "longest_read_gap_ms": max(longest_gap, settled - previous) / 1e6 if post_observed else None,
            "record_trace_sha256": hashlib.sha256(raw).hexdigest()}


def flows_observed(rows, count, *fields):
    if not count or len(rows) != count or any(r[k] is None for r in rows for k in fields):
        return None
    return sum(all(r[k] > 0 for k in fields) for r in rows)


def link_condition(result, phase, summary):
    request = (summary.get("network") or {}).get("loss_percent_each_direction")
    before = phase.get("qdisc_before") or result.get("qdisc_before", {})
    readbacks = []
    for side in ("a", "b"):
        raw = (before.get(side) or {}).get("qdisc_text", "")
        line = next((s for s in raw.splitlines() if s.startswith("qdisc netem ")), None)
        match = re.search(r"\bloss (?:random )?([\d.]+)%", line or "")
        # tc omits the loss attribute entirely when random loss is zero.
        pct = float(match[1]) if match else (0.0 if line and "loss" not in line else None)
        netlink = (phase.get("netem_seeds", {}).get(side) or {}).get("loss_percent")
        if pct is None or (netlink is not None and pct != netlink):
            pct = None
        readbacks.append(pct)
    fwd, rev = readbacks
    verified = request is not None and fwd == rev == request
    condition = ("zero-loss control" if request == 0 else "impaired link") if verified else "unverified link"
    return {"link_condition": condition, "requested_loss_pct": request, "forward_netem_loss_pct": fwd,
            "reverse_netem_loss_pct": rev, "loss_verified": verified}


def terminal_observation(path):
    if not path.is_file():
        return None
    with path.open(errors="replace") as log:
        for line in log:
            if '"secure_udp_common_terminal"' not in line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "secure_udp_common_terminal":
                return (event.get("status") or {}).get("terminal") or event.get("outcome")


def get_count(tag, evidence, estimates):
    for key in ("requested_flows", "flow_count", "flows_per_phase", "inner_tcp_flows"):
        count = evidence.get(key)
        if isinstance(count, int) and count > 0:
            return count
    match = re.search(r"(?:^|[-_])(?:f(?:lows?)?|n)[-_]?(1|4|16)(?![0-9])", tag, re.I)
    if not match:
        match = re.search(r"[-_](1|4|16)$", tag)
    if match:
        return int(match[1])
    return len(estimates) if estimates else None


def read_cell(path):
    result = load(path)
    case_dir = path.parent
    run = case_dir.parent
    outer = load(run / "outer-isolation.json")
    summary = load(run / "results.json")
    row = result.get("row", {})
    phase = next((p for p in result.get("phases", []) if p.get("phase") == "forward"), {})
    link = link_condition(result, phase, summary)
    forward = (phase.get("throughput") or {}).get("a_to_b", {})
    checked = index(forward.get("per_flow", []))
    a, b = (load(case_dir / "forward" / f"{side}.json") for side in ("a", "b"))
    sender, receiver = index(a.get("flows")), index(b.get("flows"))
    latency = index((b.get("paced_records") or {}).get("per_flow"))
    tx_tuple = index((a.get("flow_identity") or {}).get("connections"))
    rx_tuple = index((b.get("flow_identity") or {}).get("connections"))
    switch = result.get("mode_switch") or {}
    count = get_count(run.name, {**summary, **result}, receiver)
    elapsed = (b.get("clock", {}).get("end_ns", 0) - b.get("clock", {}).get("measure_start_ns", 0)) / 1e9
    complete_clock = clock_ok(a, b)
    rx_clock = b.get("clock", {})
    trace_clock = load(case_dir / "forward" / "clock.json") if switch else {}
    if trace_clock != a.get("clock") or trace_clock != rx_clock:
        trace_clock = {}
    receiver_complete = elapsed > 0 and b.get("completed_ns", 0) >= rx_clock.get("end_ns", 0)
    progress = (phase.get("throughput_observed") or {}).get("a_to_b", {})
    observed = sum(x["measured"] for x in receiver.values()) if receiver and all(
        isinstance(x.get("measured"), int) for x in receiver.values()) else None
    if observed is None:
        observed = progress.get("receiver_unique_sample_bytes")
    if not b.get("clock") and progress.get("sample_window_completed") is True:
        receiver_complete = True
        elapsed = progress.get("configured_sample_seconds", 0)
    window_state = "complete" if receiver_complete else "partial" if observed is not None else "unobserved"
    flow_rows = []
    for fid in sorted(sender.keys() | receiver.keys() | checked.keys()):
        tx, rx = sender.get(fid, {}), receiver.get(fid, {})
        item = checked.get(fid, {})
        connection = tx_tuple.get(fid, {})
        peer = rx_tuple.get(fid, {})
        measured = rx.get("measured")
        matched = bool(connection.get("local") and connection.get("local") == peer.get("peer")
                       and connection.get("peer") == peer.get("local"))
        rec = {
            **link,
            "run": run.name, "profile": row.get("id", case_dir.name), "carrier": row.get("carrier"),
            "requested_flows": count, "flow_id": fid, "sender": socket(connection.get("local")),
            "receiver": socket(connection.get("peer")), "tuples_verified": matched,
            "measured_bytes": measured, "measured_seconds": elapsed or None,
            "goodput_mbit_s": measured * 8 / (elapsed * 1e6) if elapsed > 0 and receiver_complete and isinstance(measured, int) else None,
            "full_sent_bytes": tx.get("sent"), "full_received_bytes": rx.get("received"),
            "hash_eof_verified": digest_verified(tx, rx), "clock_completed": complete_clock,
            "receiver_window": window_state,
            "steady_retransmitted_segments": item.get("steady_retransmitted_segments"),
            "receipt": str(path.relative_to(ROOT)),
        }
        for short, key in COHORTS.items():
            cohort = item.get(key) or latency.get(fid, {}).get(key) or {}
            for metric in ("count", *QUANTILES):
                rec[f"{short}_{metric}"] = cohort.get(metric)
        witness = item.get("switch_delivery", {})
        evidence = {}
        if switch and matched and trace_clock:
            trace = case_dir / "forward" / f"flow-{fid:02}-record-times.bin"
            evidence = trace_witness(trace, latency.get(fid, {}).get("fully_read_records"),
                                     trace_clock, switch, b.get("completed_ns"))
            if witness and evidence and witness.get("record_trace_sha256") != evidence["record_trace_sha256"]:
                raise ValueError(f"Switch trace digest differs from phase receipt: {trace}")
            if not witness:
                witness = evidence
        rec.update(switch_pre_records=witness.get("completed_before_request_in_steady"),
                   switch_spanning_records=witness.get("attempted_before_request_completed_during_or_after"),
                   switch_post_records=witness.get("attempted_and_completed_after_settlement_in_steady"),
                   switch_post_drain_records=witness.get("attempted_after_settlement_completed_in_drain"),
                   switch_reads_during=evidence.get("reads_during_switch"),
                   switch_longest_read_gap_ms=evidence.get("longest_read_gap_ms"),
                   switch_trace_sha256=witness.get("record_trace_sha256"))
        flow_rows.append(rec)
    namespace = result.get("cleanup", {}).get("namespaces")
    switch_wanted = bool(switch) or summary.get("switch_during_phase") or "switch" in run.name.lower()
    measured_ok = bool(count and len(checked) == len(flow_rows) == count
                       and all(x["hash_eof_verified"] and x["tuples_verified"]
                               and x.get("steady_count", 0) is not None
                               and x["measured_bytes"] is not None for x in flow_rows)
                       and complete_clock and forward.get("receiver_unique_sample_bytes", 0) > 0
                       and sum(x["measured_bytes"] for x in flow_rows) == forward["receiver_unique_sample_bytes"]
                       and a.get("status") == b.get("status") == "passed")
    run_ok = bool(result.get("status") == phase.get("status") == "passed"
                  and outer.get("return_code") == 0 and outer.get("remaining_named_namespaces") == []
                  and namespace == "removed_after_identity_and_empty_pid_verification")
    switched_flows = flows_observed(flow_rows, count, "switch_pre_records", "switch_post_records")
    switch_ok = not switch_wanted or (switch.get("status") == "passed" and switch.get("replay_verified") is True
                                      and bool(count) and count == switched_flows)
    outcome = "qualified" if measured_ok and run_ok and switch_ok and link['loss_verified'] else (
        "diagnostic" if flow_rows else "no measurement")
    for rec in flow_rows:
        rec["qualification"] = outcome
        rec["latency_scope"] = ("verified complete run" if outcome == "qualified" else
                                "completed records only, run censored" if rec.get("steady_count") else "unavailable")
    valid_rates = [r["goodput_mbit_s"] for r in flow_rows if r["goodput_mbit_s"] is not None]
    reasons = [result.get("error"), phase.get("error"), switch.get("error"), result.get("read_error")]
    if outcome != "qualified":
        for side, probe in (("A", a), ("B", b)):
            if probe.get("error"):
                reasons.append(f"probe {side}: {probe['error']}")
            terminal = terminal_observation(case_dir / f"daemon-{side.lower()}.log")
            if terminal:
                reasons.append(f"daemon {side} terminal observation: {terminal}")
    if not link["loss_verified"]:
        reasons.append("Bidirectional loss readback missing or inconsistent with request")
    if result.get("status") == "passed" and not measured_ok:
        reasons.append("Incomplete matching window, flow identity, EOF, or byte evidence")
    if not outer:
        reasons.append("Private outer isolation receipt pending")
    if switch_wanted and not switch_ok and not switch.get("error"):
        reasons.append("Live switch or same-window pre/post delivery witness incomplete")
    data = {
        **link,
        "run": run.name, "profile": row.get("id", case_dir.name), "carrier": row.get("carrier"),
        "requested_flows": count, "flow_rows": len(flow_rows),
        "outstanding_credit_bytes": summary.get("outstanding_application_credit_bytes"),
        "qualification": outcome, "case_status": result.get("status"), "phase_status": phase.get("status"),
        "stage": result.get("stage"), "cleanup": namespace, "outer_return_code": outer.get("return_code"),
        "sample_seconds": elapsed or None, "measured_bytes": forward.get("receiver_unique_sample_bytes"),
        "aggregate_mbit_s": forward.get("goodput_mbit_s"),
        "receiver_window": window_state, "observed_receiver_bytes": observed,
        "observed_full_window_mbit_s": observed * 8 / (elapsed * 1e6) if receiver_complete and elapsed and observed is not None else None,
        "flow_min_mbit_s": min(valid_rates, default=None),
        "flow_median_mbit_s": median(valid_rates) if valid_rates else None, "flow_max_mbit_s": max(valid_rates, default=None),
        "switch_requested": switch_wanted, "switch_status": switch.get("status"),
        "initial_mode": switch.get("initial_row"), "target_mode": switch.get("target_row"),
        "before_a_epoch": epoch(switch.get("before", {}), "a"), "before_b_epoch": epoch(switch.get("before", {}), "b"),
        "after_a_epoch": epoch(switch.get("after", {}), "a"), "after_b_epoch": epoch(switch.get("after", {}), "b"),
        "switch_replay_verified": switch.get("replay_verified"), "switch_flows_with_pre_and_post": switched_flows,
        "switch_rpc_issued": isinstance(switch.get("requested_ns"), int) if switch_wanted else None,
        "switch_flows_with_pre": flows_observed(flow_rows, count, "switch_pre_records"),
        "switch_flows_with_post": flows_observed(flow_rows, count, "switch_post_records"),
        "switch_settle_ms": (switch["settled_ns"] - switch["requested_ns"]) / 1e6
            if all(isinstance(switch.get(k), int) for k in ("requested_ns", "settled_ns")) else None,
        "observed_flows_with_samples": sum((r["steady_count"] or 0) > 0 for r in flow_rows),
        "receipt": str(path.relative_to(ROOT)), "reason": " / ".join(dict.fromkeys(str(x) for x in reasons if x)),
    }
    return data, flow_rows


FLOW_FIELDS = [
    "run", "carrier", "profile", "requested_flows", "flow_id", "qualification",
    "link_condition", "requested_loss_pct", "forward_netem_loss_pct", "reverse_netem_loss_pct", "loss_verified", "receiver_window", "latency_scope",
    "sender", "receiver", "tuples_verified", "measured_seconds", "measured_bytes", "goodput_mbit_s",
    "full_sent_bytes", "full_received_bytes", "hash_eof_verified", "clock_completed",
    "steady_retransmitted_segments", *(f"{name}_{metric}" for name in COHORTS for metric in ("count", *QUANTILES)),
    "switch_pre_records", "switch_spanning_records", "switch_post_records", "switch_post_drain_records", "switch_trace_sha256",
    "switch_reads_during", "switch_longest_read_gap_ms", "receipt",
]
CELL_FIELDS = [
    "run", "carrier", "profile", "requested_flows", "outstanding_credit_bytes", "qualification", "case_status", "phase_status",
    "link_condition", "requested_loss_pct", "forward_netem_loss_pct", "reverse_netem_loss_pct", "loss_verified",
    "receiver_window", "observed_receiver_bytes", "observed_full_window_mbit_s",
    "stage", "cleanup", "outer_return_code", "sample_seconds", "measured_bytes", "aggregate_mbit_s",
    "flow_rows", "observed_flows_with_samples", "flow_min_mbit_s", "flow_median_mbit_s", "flow_max_mbit_s",
    "switch_requested", "switch_status", "initial_mode", "target_mode", "before_a_epoch", "before_b_epoch",
    "after_a_epoch", "after_b_epoch", "switch_settle_ms", "switch_replay_verified", "switch_rpc_issued",
    "switch_flows_with_pre", "switch_flows_with_post", "switch_flows_with_pre_and_post", "reason", "receipt",
]


def credit_text(cells):
    """Describe the recorded total application credits; 4 MiB is the runner default."""
    values = sorted({c.get("outstanding_credit_bytes") for c in cells} - {None}) or [4 * 1024 * 1024]
    def size(value):
        return f"{value // 1048576} MiB" if value % 1048576 == 0 else (
            f"{value // 1024} KiB" if value % 1024 == 0 else f"{value} bytes")
    text = " or ".join(size(v) for v in values)
    return text + (" (see the credit column)" if len(values) > 1 else "")


def markdown(cells, flows, awaiting):
    frozen = load(ROOT / "frozen" / "source.json")
    qualified = sum(c["qualification"] == "qualified" for c in cells)
    lines = [
        "# Common TCP/TLS and UDP closeout measurements", "",
        f"Updated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}. "
        f"{qualified} of {len(cells)} recorded runs qualified. "
        f"{len(awaiting)} additional run directories await a phase receipt.", "",
        f"The [source manifest](../frozen/source.json) records commit `{frozen.get('head', 'unknown')}`, "
        "local changes and the source snapshot digest. "
        "Measurements use local Linux network namespaces. UDP and TCP/TLS identify the selected outer carrier.", "",
        "The network provides 100 Mbit/s forward, 10 Mbit/s reverse and 35 ms one-way delay. "
        "Table groups use configured random loss read back on both endpoint WAN queues. "
        "The zero-loss control keeps the delay and rate limits. In each forward run, 1, 4 or 16 inner Linux CUBIC connections "
        f"share one outer carrier, a 90 Mbit/s offered load and {credit_text(cells)} of unconfirmed application data. The probe divides both budgets "
        "equally across the inner connections. Each configuration has one trial. The ten-second throughput window follows two seconds "
        "of warmup and counts unique application bytes at the receiver. The workload phase has a 60-second bound. "
        "The CSV includes the paired socket endpoints and actual sent and received bytes for each stream.", "",
        "For each 512-byte application record, latency runs from the sender's first write attempt to the receiver's complete read. "
        "The steady cohort selects records by their complete-read time inside the measurement window. "
        "Full-transfer latency also includes warmup and drain. "
        "The scheduled-offer metrics include sender admission delay. Empty latency cells mean no available sample. "
        "A per-flow quantile represents one connection. Quantiles across connections cannot be averaged to obtain pooled percentiles.", "",
        "[Per-flow measurements (CSV)](per-flow.csv) · [Run results (CSV)](cells.csv)", "",
    ]
    if (OUT / "fixed-flow-scaling.png").is_file():
        lines.extend(["![Fixed-mode goodput and record latency across concurrent inner flows](fixed-flow-scaling.png)", ""])
    if (OUT / "transport-observations.md").is_file():
        lines.extend(["[Single-flow transport observations and socket counters](transport-observations.md)", ""])
    if (OUT / "workspace-check.json").is_file():
        lines.extend(["[Local workspace check receipt](workspace-check.json) · [Full check output](workspace-check.log)", ""])
    if (OUT / "workspace-rust-tests.json").is_file():
        lines.extend(["[Independent Rust workspace test receipt](workspace-rust-tests.json) · [Rust test output](workspace-rust-tests.log)", ""])
    for condition in ("impaired link", "zero-loss control", "unverified link"):
        selected = [c for c in cells if (c.get("link_condition") or "unverified link") == condition]
        if not selected:
            continue
        lines.extend([f"## {condition.capitalize()}", "",
            "| Run | Outer | Inner flows | Loss forward / reverse | Qualification | Receiver total Mbit/s | Per-flow min / median / max Mbit/s | Per-flow P99 range, ms |",
            "|---|---|---:|---|---|---:|---:|---:|"])
        for cell in sorted(selected, key=lambda c: (bool(c['switch_requested']), c['profile'] or '', c['requested_flows'] or 0, c['run'])):
            is_pass = cell["qualification"] == "qualified"
            rows = [f for f in flows if f["receipt"] == cell["receipt"]]
            p99 = [r["steady_p99_ms"] for r in rows if (r.get("steady_count") or 0) > 0 and isinstance(r.get("steady_p99_ms"), (int, float))]
            span = (show(min(p99)) + "–" + show(max(p99))) if p99 else "—"
            if p99 and not is_pass:
                span += " (censored reads)"
            if cell.get("receiver_window") == "complete":
                rate = show(cell["aggregate_mbit_s"] if is_pass else cell.get("observed_full_window_mbit_s"))
                rates = " / ".join(show(cell[k]) for k in ("flow_min_mbit_s", "flow_median_mbit_s", "flow_max_mbit_s"))
                if not is_pass:
                    rate += " (observed)"
            else:
                rate = f"incomplete ({cell['observed_receiver_bytes']:,} B)" if cell.get("observed_receiver_bytes") is not None else "—"
                rates = "—"
            loss = " / ".join(f"{v:g}%" if isinstance(v, (int, float)) else "—" for v in (cell.get('forward_netem_loss_pct'), cell.get('reverse_netem_loss_pct')))
            lines.append(f"| [{md(cell['run'])}](../{cell['receipt']}) | {md(cell['carrier'])} | {cell['requested_flows'] or '—'} "
                         f"| {loss} | {md(cell['qualification'])} | {rate} | {rates} | {span} |")
        lines.append("")
    if not cells:
        lines.append("Awaiting case receipts.")
    lines += ["", "A qualified row has verified bidirectional loss settings, paired per-flow identity, a completed measurement window, matching payload "
              "hashes and EOF, successful phase and final case results, and verified cleanup. Positive bytes in a failed or "
              "incomplete run are diagnostic. An observed rate uses bytes received during the entire ten-second window despite a later failure. "
              "Partial-window bytes have no reported rate. Censored P99 includes only records completed by observation cutoff and omits outstanding writes.", ""]
    switches = [c for c in cells if c["switch_requested"]]
    if switches:
        lines += ["## Live mode switching", "",
                  "| Run | Initial → target | RPC issued | Bilateral switch check | Peer A / B epochs | Request to both peers settled, ms | Keyed replay | Flows before request | Flows after settlement | Same flows at both times |",
                  "|---|---|---|---|---|---:|---|---:|---:|---:|"]
        for c in switches:
            epochs = " / ".join(
                f"{c['before_'+side+'_epoch']} → {c['after_'+side+'_epoch']}"
                if c["before_"+side+"_epoch"] is not None and c["after_"+side+"_epoch"] is not None else "—"
                for side in ("a", "b"))
            counts = [f"{c[k]} / {c['requested_flows']}" if c[k] is not None else "N/A"
                      for k in ("switch_flows_with_pre", "switch_flows_with_post", "switch_flows_with_pre_and_post")]
            issued = {True: "Yes", False: "No", None: "N/A"}[c.get("switch_rpc_issued")]
            lines.append(f"| [{md(c['run'])}](../{c['receipt']}) | {md(c['initial_mode'])} → {md(c['target_mode'])} | {issued} "
                         f"| {md(c['switch_status']) or '—'} | {epochs} | {show(c['switch_settle_ms'])} "
                         f"| {str(c['switch_replay_verified']) if c['switch_replay_verified'] is not None else '—'} "
                         + "| " + " | ".join(counts) + " |")
        lines += ["", "Switch settlement measures the request through observed agreement of both peers. "
                  "The flow counts use receiver records in the measurement window. Before counts complete reads ahead of the request. "
                  "After counts records first attempted and fully read after settlement. Failed runs count observed deliveries through "
                  "their receiver cutoff. N/A indicates an unavailable boundary or incomplete trace evidence.", ""]
        successful = [c for c in switches if c["qualification"] == "qualified"]
        if successful:
            lines.extend(["### Application delivery during qualified switches", "",
                          "| Run | Records received between request and settlement | Longest gap per flow, min–max (ms) |",
                          "|---|---:|---:|"])
            for c in successful:
                rows = [r for r in flows if r["receipt"] == c["receipt"]]
                gaps = [r["switch_longest_read_gap_ms"] for r in rows]
                if gaps and all(v is not None for v in gaps):
                    lines.append(f"| [{c['run']}](../{c['receipt']}) | {sum(r['switch_reads_during'] for r in rows):,} "
                                 f"| {min(gaps):.1f}–{max(gaps):.1f} |")
            lines.extend(["", "Each gap measures time without a complete application record on that flow, "
                          "clipped to the request and settlement timestamps. Queueing and path loss can contribute.", ""])
    failed = [c for c in cells if c["qualification"] != "qualified"]
    if failed or awaiting:
        lines += ["## Incomplete measurements", ""]
        for c in failed:
            details = c["reason"] or c["case_status"] or "Incomplete receipt"
            lines.append(f"- [{md(c['run'])}](../{c['receipt']}) reached {md(c['stage']) or 'an unreported stage'}. {md(details)}.")
        for run in awaiting:
            lines.append(f"- `{md(run)}` has no case receipt yet.")
        lines += [""]
    return "\n".join(lines) + "\n"


def main(argv=None):
    import argparse
    global ROOT, OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    ROOT = parser.parse_args(argv).campaign.resolve(strict=True)
    OUT = ROOT / "reports"
    OUT.mkdir(exist_ok=True)
    cells, flows = [], []
    run_root = ROOT / "runs"
    recorded = set()
    for path in sorted(run_root.glob("*/*/result.json")):
        cell, per_flow = read_cell(path)
        recorded.add(path.parent.parent.name)
        cells.append(cell)
        flows.extend(per_flow)
    # A process can fail before it creates the inner run directory. Its enclosing
    # batch still records the invocation, return code and original log.
    for ledger in sorted(OUT.glob("*/receipts.jsonl")):
        for line in ledger.read_text().splitlines():
            try:
                attempt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if attempt.get("status") != "no_case_receipt":
                continue
            label = Path(attempt["output"]).name
            if label in recorded:
                continue
            log = ledger.parent / (attempt["label"] + ".log")
            errors = log.read_text(errors="replace").strip().splitlines() if log.is_file() else []
            failure = dict.fromkeys(CELL_FIELDS)
            failure.update(run=label, profile=attempt["row"], carrier=attempt["row"].rsplit("-", 1)[-1],
                           requested_flows=attempt["concurrency"], qualification="no measurement", case_status=attempt["status"],
                           stage="runner startup", outer_return_code=attempt.get("rc"), switch_requested="switch" in label,
                           observed_flows_with_samples=0, flow_rows=0, reason=(errors[-1][:400] if errors else "No inner receipt"),
                           receipt=str((log if log.is_file() else ledger).relative_to(ROOT)))
            cells.append(failure)
            recorded.add(label)
    awaiting = sorted(p.name for p in run_root.iterdir() if p.is_dir() and p.name not in recorded)
    commit(OUT / "per-flow.csv", as_table(flows, FLOW_FIELDS))
    commit(OUT / "cells.csv", as_table(cells, CELL_FIELDS))
    commit(OUT / "README.md", markdown(cells, flows, awaiting))
    print(json.dumps({"qualified": sum(c["qualification"] == "qualified" for c in cells),
                      "recorded": len(cells), "flow_rows": len(flows), "awaiting": awaiting}))


if __name__ == "__main__":
    main()


