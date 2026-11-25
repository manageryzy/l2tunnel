"""tools/merge_common_plans.py: multi-protocol plan merge rules and parity
with the two-member switch-plan composer."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools import common_native_switch_plans as switch
from tools import merge_common_plans as merge


def plan(descriptor: str, retained: int, **extra) -> dict:
    document = {"version": 1, "backend": "common_records_v2", "catalog": [descriptor], "initial_index": 0,
                "runtime": {"lifetime": {"lease_micros": 120_000_000}, "work": {"send_batch": 8}},
                "transaction": {"retained_bytes": retained, "max_operation_ms": 60_000},
                "compact_wire": {"version": 3}, "rolling_work": None}
    document.update(extra)
    return document


def row(name: str, descriptor: str, carrier: str = "udp") -> dict:
    return {"id": name, "status": "ready", "carrier": carrier, "duplex": "full", "layer": "tun",
            "required_cli": ["--record-profile", "common"], "policy_flag": None,
            "common_plan": f"{name}.common.json", "expected_descriptor_hex": descriptor,
            "parameters": {}, "carrier_policy": {"a": f"{name}.a.carrier.json", "b": f"{name}.b.carrier.json"}}


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="l2t-merge-")
        self.root = Path(self.directory.name)
        self.source = self.root / "export"
        self.source.mkdir()
        self.rows = []

    def tearDown(self):
        self.directory.cleanup()

    def add(self, name: str, descriptor: str, retained: int, carrier: str = "udp", policy=None, **extra):
        entry = row(name, descriptor, carrier)
        (self.source / entry["common_plan"]).write_text(json.dumps(plan(descriptor, retained, **extra)))
        for side in "ab":
            (self.source / entry["carrier_policy"][side]).write_text(json.dumps(policy or {"side": side}))
        self.rows.append(entry)
        (self.source / "manifest.json").write_text(json.dumps({"version": 1, "rows": self.rows}))

    def test_three_rows_merge_with_the_largest_budget_and_a_stable_digest(self):
        self.add("swift-arq-udp", "aa" * 8, 100)
        self.add("aligned-arq-udp", "bb" * 8, 300)
        self.add("packed-arq-udp", "cc" * 8, 200)
        out = self.root / "merged"
        merged = merge.merge(self.source, ["aligned-arq-udp", "swift-arq-udp", "packed-arq-udp"], "demo", out)
        document = json.loads((out / "demo.common.json").read_text())
        self.assertEqual(document["catalog"], ["bb" * 8, "aa" * 8, "cc" * 8], "first row is initial")
        self.assertEqual((document["initial_index"], document["transaction"]["retained_bytes"]), (0, 300))
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(manifest["rows"][0]["id"], "demo")
        self.assertEqual(merged["catalog_digest_hex"], merge.catalog_digest(["cc" * 8, "aa" * 8, "bb" * 8]),
                         "the digest does not depend on order")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            merge.merge(self.source, ["swift-arq-udp", "packed-arq-udp"], "demo", out)

    def test_digest_and_plan_match_the_two_member_switch_composer(self):
        self.add("packed-compact-udp", "11" * 8, 500)
        self.add("aligned-compact-udp", "22" * 8, 700)
        ours, theirs = self.root / "ours", self.root / "theirs"
        theirs.mkdir()
        merged = merge.merge(self.source, ["packed-compact-udp", "aligned-compact-udp"], "pair", ours)
        reference = switch.compose(self.source, "packed-compact-udp", "aligned-compact-udp", theirs)
        self.assertEqual(merged["catalog_digest_hex"], reference["catalog_digest_hex"])
        self.assertEqual(json.loads((ours / "pair.common.json").read_text()),
                         json.loads((theirs / reference["common_plan"]).read_text()))

    def test_incompatible_rows_are_refused_with_the_reason(self):
        self.add("swift-arq-udp", "aa" * 8, 100)
        self.add("rolling-udp", "bb" * 8, 100, rolling_work={"copies": 1})
        self.add("swift-arq-raw", "cc" * 8, 100, carrier="raw")
        self.add("swift-again-udp", "aa" * 8, 100)
        self.add("swift-fec-raw", "dd" * 8, 100, carrier="raw", policy={"other": True})
        out = self.root / "merged"
        for rows, reason in [
            (["swift-arq-udp", "rolling-udp"], "/rolling_work"),
            (["swift-arq-udp", "swift-arq-raw"], "carrier"),
            (["swift-arq-udp", "swift-again-udp"], "same descriptor"),
            (["swift-arq-raw", "swift-fec-raw"], "carrier policy"),
            (["swift-arq-udp"], "choose 2"),
            (["swift-arq-udp", "swift-arq-udp"], "named twice"),
            (["swift-arq-udp", "nope"], "unknown rows"),
        ]:
            with self.assertRaisesRegex(ValueError, reason, msg=str(rows)):
                merge.merge(self.source, rows, "bad", out)
        self.assertFalse(out.exists() and any(out.iterdir()), "nothing written on refusal")
        with self.assertRaisesRegex(ValueError, "name"):
            merge.merge(self.source, ["swift-arq-udp", "rolling-udp"], "Bad Name", out)

    def test_command_line_reports_refusals_with_exit_2(self):
        self.add("swift-arq-udp", "aa" * 8, 100)
        self.add("swift-fec-udp", "bb" * 8, 150)
        with self.assertRaises(SystemExit) as refused:
            merge.main(["--source", str(self.source), "--row", "swift-arq-udp", "--name", "x",
                        "--output", str(self.root / "o")])
        self.assertEqual(refused.exception.code, 2)
        self.assertEqual(merge.main(["--source", str(self.source), "--row", "swift-arq-udp", "--row",
                                     "swift-fec-udp", "--name", "x", "--output", str(self.root / "o")]), 0)


if __name__ == "__main__":
    unittest.main()
