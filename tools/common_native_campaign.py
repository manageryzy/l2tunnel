#!/usr/bin/env python3
"""Run a predeclared schedule of common_native_cell.py cells serially.

Replaces the per-campaign ``run_lab.py`` and ``run_batch.py`` copies. Each schedule
entry becomes one command

    sudo -n unshare --net --mount --fork --propagation private /usr/bin/python3 -B \
        tools/common_native_cell.py --manifest M --binary B --row R --flows N \
        --seed S --loss-percent L --outstanding-credit-bytes C [flags] --output OUT --apply

so every cell gets fresh outer net and mount namespaces. Without ``--apply`` (or
with ``--dry-run``) the commands are printed and nothing is created, locked or run.

Campaign layout (readable by ``common_native_report.py --campaign DIR``):

- ``DIR/runs/<label>/`` is the cell output (``<row>/result.json``, ``results.json``,
  ``outer-isolation.json``);
- ``DIR/reports/<batch>/receipts.jsonl`` is the batch ledger, one JSON object per
  attempted cell, with ``<label>.log`` beside it and ``inputs.json`` input hashes;
- ``DIR/trials.jsonl`` is the cumulative trial ledger across batches;
- ``DIR/serial.lock`` serializes campaign runners with ``flock``.

A run directory that is already closed (an outer isolation receipt with no remaining
namespaces and a case receipt) is skipped, so an interrupted batch resumes. A run
directory that exists without those receipts stops the batch. ``--retry-predata``
re-runs, as ``<label>-retry1``, only cells whose original attempt failed before any
phase started (no phase seeds, every phase ``not_run``). After each cell the receipts
are checked against the schedule (binary hash, netem seeds, loss, delay, credit and
socket buffers); a missing receipt or failed check is recorded and stops the batch.

Schedule: a JSON list (or ``{"entries": [...]}``) of objects with ``label`` and either
``row`` or ``carrier`` (with ``--stem``), plus optional ``manifest``, ``flows`` (1/4/16,
default 1), ``seed`` (or ``seeds`` ``{"a": .., "b": ..}``), ``loss`` (default 15),
``credit_bytes`` (default 4 MiB), ``switch``, ``capture``, ``raw_rst_observation``,
``txqueuelen``, ``forward_maxrate_mbit``, ``lab_id``, ``binary_sha256``, ``profile``
and ``extra`` (additional cell flags). Relative manifest paths resolve against the
schedule file's directory.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

TOOLS = Path(__file__).resolve().parent
CELL = TOOLS / "common_native_cell.py"
SEED_XOR = 0x9e3779b97f4a7c15
DEFAULT_SEED = 31248
DEFAULT_LOSS = 15
DEFAULT_CREDIT = 4 * 1024 * 1024
DEFAULT_DELAY_MS = 35
SOCKET_BUFFER = 16 * 1024 * 1024
FLOWS = (1, 4, 16)
OUTER = ["sudo", "-n", "unshare", "--net", "--mount", "--fork", "--propagation", "private"]
# Cell options owned by the campaign; schedule ``extra`` may not override them.
RESERVED = {"--manifest", "--binary", "--binary-sha256", "--row", "--flows", "--seed", "--loss-percent",
            "--outstanding-credit-bytes", "--output", "--apply"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
HASHED_TOOLS = ("common_native_campaign.py", "common_native_cell.py", "common_native_matrix.py",
                "common_native_probe.py", "common_native_single_flow.py", "common_native_c48.py",
                "common_native_observe.py", "common_native_netem_seed.py", "common_native_switch.py",
                "common_python_reference.py", "common_python_references.json", "netns_lab.py")


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


class Entry:
    """One validated schedule entry."""

    def __init__(self, raw, args, base):
        def fail(message):
            raise ValueError(f"schedule entry {raw.get('label')!r}: {message}")
        self.raw = raw
        self.label = raw.get("label")
        if not isinstance(self.label, str) or not NAME.fullmatch(self.label) or self.label.endswith("-retry1"):
            fail("label must be a plain name not ending in -retry1")
        manifest = raw.get("manifest") or args.manifest
        if manifest is None:
            fail("no manifest (entry field or --manifest)")
        manifest = Path(manifest)
        self.manifest = (manifest if manifest.is_absolute() else base / manifest).resolve(strict=True)
        if "row" in raw:
            self.row = raw["row"]
        elif "carrier" in raw and args.stem:
            self.row = f"{args.stem}-{raw['carrier']}"
        else:
            fail("needs row, or carrier with --stem")
        self.flows = raw.get("flows", 1)
        if self.flows not in FLOWS:
            fail("flows must be 1, 4 or 16")
        seeds = raw.get("seeds")
        self.seed = raw.get("seed", seeds["a"] if seeds else DEFAULT_SEED)
        if type(self.seed) is not int or not 0 < self.seed < 2**64:
            fail("seed must be within 1..2**64-1")
        self.seeds = {"a": self.seed, "b": self.seed ^ SEED_XOR}
        if seeds is not None and seeds != self.seeds:
            fail("seeds.b must equal seeds.a XOR 0x9e3779b97f4a7c15")
        self.loss = raw.get("loss", DEFAULT_LOSS)
        if type(self.loss) is not int or not 0 <= self.loss <= 100:
            fail("loss must be an integer percentage")
        self.credit = raw.get("credit_bytes", DEFAULT_CREDIT)
        if type(self.credit) is not int or self.credit // self.flows < 512:
            fail("credit_bytes must admit one 512-byte record per flow")
        self.binary_sha256 = raw.get("binary_sha256", args.binary_sha256)
        self.extra = list(raw.get("extra", []))
        if any(not isinstance(item, str) or item.split("=", 1)[0] in RESERVED for item in self.extra):
            fail("extra flags must be strings and may not set campaign-owned options")
        manifest_rows = {r["id"]: r for r in read_json(self.manifest)["rows"] if r.get("status") == "ready"}
        if self.row not in manifest_rows:
            fail(f"row {self.row} is not ready in {self.manifest}")
        if "carrier" in raw and manifest_rows[self.row].get("carrier") != raw["carrier"]:
            fail("row carrier differs from the schedule carrier")

    def command(self, args, output):
        command = [*OUTER, args.python, "-B", str(CELL), "--manifest", str(self.manifest),
                   "--binary", str(args.binary), "--row", self.row, "--flows", str(self.flows),
                   "--seed", str(self.seed), "--loss-percent", str(self.loss),
                   "--outstanding-credit-bytes", str(self.credit)]
        if self.binary_sha256:
            command += ["--binary-sha256", self.binary_sha256]
        for key, flag in (("switch", "--switch"), ("capture", "--capture"),
                          ("raw_rst_observation", "--raw-rst-observation")):
            if self.raw.get(key):
                command.append(flag)
        for key, flag in (("txqueuelen", "--txqueuelen"), ("forward_maxrate_mbit", "--forward-maxrate-mbit"),
                          ("lab_id", "--lab-id")):
            if key in self.raw:
                command += [flag, str(self.raw[key])]
        return [*command, *self.extra, "--output", str(output), "--apply"]


def load_schedule(args):
    document = read_json(args.schedule)
    raw = document["entries"] if isinstance(document, dict) else document
    base = args.schedule.parent
    entries = [Entry(item, args, base) for item in raw
               if (args.profile is None or item.get("profile") == args.profile)
               and (not args.only or item.get("label") in args.only)]
    labels = [entry.label for entry in entries]
    if len(labels) != len(set(labels)):
        raise ValueError("duplicate schedule labels")
    if args.only and set(args.only) - set(labels):
        raise ValueError(f"unknown --only labels: {sorted(set(args.only) - set(labels))}")
    return entries


def closed(out, row):
    """Return True when the run directory holds a closed isolation and a case receipt."""
    isolation = out / "outer-isolation.json"
    return (isolation.is_file() and (out / row / "result.json").is_file()
            and not read_json(isolation).get("remaining_named_namespaces"))


def started_data(result):
    """The run_lab predicate: a passed case or any phase that began counts as data."""
    return result.get("status") == "passed" or any(
        p.get("netem_seeds") or p.get("status") != "not_run" for p in result.get("phases", []))


def decide(entry, campaign, retry_predata):
    """Return (action, label, output) where action is run, skip_closed, skip_data or an error."""
    label, out = entry.label, campaign / "runs" / entry.label
    if retry_predata:
        original = out / entry.row / "result.json"
        if not original.is_file():
            return "missing_original", label, out
        if started_data(read_json(original)):
            return "skip_data", label, out
        label += "-retry1"
        out = campaign / "runs" / label
    if out.exists() or out.is_symlink():
        return ("skip_closed" if closed(out, entry.row) else "unclosed"), label, out
    return "run", label, out


def check_receipts(entry, out, delay_ms):
    """Compare closed receipts with the schedule; return a list of failed checks."""
    failures = []

    def expect(ok, message):
        if not ok:
            failures.append(message)
    isolation = read_json(out / "outer-isolation.json")
    expect(not isolation.get("remaining_named_namespaces") and isolation.get("initial_links") == ["lo"],
           "namespace lifecycle incomplete")
    case = read_json(out / "results.json") if (out / "results.json").is_file() else {}
    expect(case.get("original_binary_still_matches") is True, "binary changed during the run")
    if entry.binary_sha256:
        expect(case.get("binary_sha256") == entry.binary_sha256, "binary digest differs from the schedule")
    expect(case.get("netem_seeds") == entry.seeds, "plan netem seeds differ from the schedule")
    expect(case.get("outstanding_application_credit_bytes") == entry.credit, "plan credit differs from the schedule")
    expect(case.get("per_flow_credit_bytes") == entry.credit // entry.flows, "per-flow credit differs")
    expect(case.get("socket_buffer_before_syn_bytes") == SOCKET_BUFFER, "pre-SYN socket buffer differs")
    expect((case.get("network") or {}).get("loss_percent_each_direction") == entry.loss, "plan loss differs")
    result = read_json(out / entry.row / "result.json")
    phase = (result.get("phases") or [{}])[0]
    if phase.get("netem_seeds"):
        for side, seed in entry.seeds.items():
            readback = phase["netem_seeds"].get(side) or {}
            expect(readback.get("seed") == seed and readback.get("loss_percent") == entry.loss
                   and readback.get("delay_ms") == delay_ms, f"endpoint {side} netem readback differs")
    return failures


def input_hashes(entries, args):
    hashes = {"schedule": {str(args.schedule): file_hash(args.schedule)},
              "binary": {str(args.binary): file_hash(args.binary)},
              "tools": {name: file_hash(TOOLS / name) for name in HASHED_TOOLS if (TOOLS / name).is_file()},
              "manifests": {}}
    for manifest in sorted({entry.manifest for entry in entries}):
        rows = {r["id"]: r for r in read_json(manifest)["rows"]}
        files = {str(manifest): file_hash(manifest)}
        for entry in entries:
            if entry.manifest == manifest:
                row = rows[entry.row]
                for relative in [row.get("common_plan"), *(row.get("carrier_policy") or {}).values()]:
                    if relative and (manifest.parent / relative).is_file():
                        files[str(manifest.parent / relative)] = file_hash(manifest.parent / relative)
        hashes["manifests"][str(manifest)] = files
    return hashes


def parse(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--schedule", type=Path, required=True)
    p.add_argument("--campaign", type=Path, required=True, help="campaign directory (runs/, reports/, ledgers)")
    p.add_argument("--binary", type=Path, required=True, help="frozen l2tunnel daemon passed to every cell")
    p.add_argument("--binary-sha256", help="expected daemon digest (default for entries without binary_sha256)")
    p.add_argument("--batch", help="new batch name under reports/ (required with --apply)")
    p.add_argument("--manifest", type=Path, help="default manifest for entries without one")
    p.add_argument("--stem", help="row stem for entries that give only a carrier (row = STEM-CARRIER)")
    p.add_argument("--profile", help="only entries whose profile field matches")
    p.add_argument("--only", action="append", help="only this label (repeatable)")
    p.add_argument("--retry-predata", action="store_true",
                   help="re-run as LABEL-retry1 only cells whose original attempt failed before any data")
    p.add_argument("--python", default="/usr/bin/python3", help="interpreter run inside the outer namespaces")
    p.add_argument("--expected-delay-ms", type=int, default=DEFAULT_DELAY_MS)
    p.add_argument("--lock", type=Path, help="serial lock file (default CAMPAIGN/serial.lock)")
    p.add_argument("--continue-on-failure", action="store_true",
                   help="record a failed receipt check and continue (default: stop the batch)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="print commands only (default)")
    mode.add_argument("--apply", action="store_true", help="run the cells (requires sudo -n)")
    args = p.parse_args(argv)
    args.schedule = args.schedule.resolve(strict=True)
    args.binary = args.binary.resolve(strict=True)
    args.campaign = args.campaign.absolute()
    if args.manifest is not None:
        args.manifest = args.manifest.resolve(strict=True)
    if args.apply and not (args.batch and NAME.fullmatch(args.batch)):
        p.error("--apply requires a plain --batch name")
    if args.binary_sha256 and file_hash(args.binary) != args.binary_sha256:
        p.error("daemon digest mismatch")
    return args


def observe(entry, label, out, command, rc, elapsed):
    result_path = out / entry.row / "result.json"
    result = read_json(result_path) if result_path.is_file() else {}
    phase = next(iter(result.get("phases", [])), {})
    throughput = phase.get("throughput", {}).get("a_to_b", {})
    return {"label": label, "row": entry.row, "concurrency": entry.flows, "elapsed": round(elapsed, 3),
            "requested": command, "status": result.get("status", "no_case_receipt"), "phase": phase.get("status"),
            "rc": rc, "error": result.get("error") or phase.get("error"), "goodput": throughput.get("goodput_mbit_s"),
            "output": str(out), "manifest_sha256": file_hash(entry.manifest), "seed": entry.seed,
            "loss_percent": entry.loss, "credit_bytes": entry.credit,
            "retry_of": entry.label if label != entry.label else None}


def main(argv=None):
    args = parse(argv)
    entries = load_schedule(args)
    if not args.apply:
        blocked = False
        for entry in entries:
            action, label, out = decide(entry, args.campaign, args.retry_predata)
            print(f"# {label}: {action}")
            if action == "run":
                print(shlex.join(entry.command(args, out)))
            blocked = blocked or action in ("unclosed", "missing_original")
        return 2 if blocked else 0
    (args.campaign / "runs").mkdir(parents=True, exist_ok=True)
    with (args.lock or args.campaign / "serial.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return run_batch(args, entries)


def run_batch(args, entries):
    """Run the selected entries while holding the serial lock."""
    batch = args.campaign / "reports" / args.batch
    batch.mkdir(parents=True, exist_ok=False)
    (batch / "inputs.json").write_text(json.dumps(input_hashes(entries, args), indent=2, sort_keys=True) + "\n")
    for entry in entries:
        action, label, out = decide(entry, args.campaign, args.retry_predata)
        if action == "skip_closed":
            print("Previously closed:", label, flush=True)
            continue
        if action == "skip_data":
            continue
        if action != "run":
            print(f"STOP {label}: {action} previous trial at {out}", flush=True)
            return 2
        command = entry.command(args, out)
        print("START", label, flush=True)
        started = time.time()
        with (batch / f"{label}.log").open("x") as log:
            rc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
        elapsed = time.time() - started
        report = observe(entry, label, out, command, rc, elapsed)
        receipts = (out / "outer-isolation.json").is_file() and (out / entry.row / "result.json").is_file()
        report["assertions"] = check_receipts(entry, out, args.expected_delay_ms) if receipts else ["no closed receipts"]
        report["cleanup"] = receipts and "namespace lifecycle incomplete" not in report["assertions"]
        with (batch / "receipts.jsonl").open("a") as ledger:
            ledger.write(json.dumps(report) + "\n")
        with (args.campaign / "trials.jsonl").open("a") as ledger:
            ledger.write(json.dumps({"label": label, "row": entry.row, "rc": rc, "elapsed": round(elapsed, 2),
                                     "case": report["status"], "phase": report["phase"], "error": report["error"],
                                     "Mbps": report["goodput"], "cleanup": report["cleanup"],
                                     "manifest_sha256": report["manifest_sha256"], "batch": args.batch}) + "\n")
        print("FINISH", label, json.dumps({k: report[k] for k in ("status", "phase", "rc", "error", "goodput", "elapsed",
                                                                 "assertions")}), flush=True)
        if not receipts:
            print("Missing case or isolation receipt. Stop this batch for harness diagnosis.", flush=True)
            return 2
        if report["assertions"] and not args.continue_on_failure:
            print("Receipt checks failed. Stop this batch.", flush=True)
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
