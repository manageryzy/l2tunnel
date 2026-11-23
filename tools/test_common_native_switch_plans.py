import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from tools import common_native_switch_plans as plans


def export(directory: Path, pair: str, carriers=("udp", "tls", "raw")) -> Path:
    """Write a synthetic Rust-like export with singleton plans for one pair."""
    directory.mkdir()
    rows = []
    for index, prefix in enumerate(plans.PAIRS[pair]):
        for carrier in carriers:
            row_id = f"{prefix}-{carrier}"
            descriptor = f"{pair}{index}{carrier}".encode().hex()
            plan = {"catalog": [descriptor], "initial_index": 0,
                    "transaction": {"retained_bytes": 1000 + 24 * index}, "lease": 120}
            (directory / f"{row_id}.common.json").write_text(json.dumps(plan))
            row = {"id": row_id, "status": "ready", "carrier": carrier, "duplex": "full", "layer": "tun",
                   "required_cli": ["x"], "policy_flag": None, "common_plan": f"{row_id}.common.json",
                   "expected_descriptor_hex": descriptor, "parameters": {}, "carrier_policy": None}
            if carrier in ("tls", "raw"):
                row["carrier_policy"] = {}
                for side in ("a", "b"):
                    name = f"{row_id}.{side}.carrier.json"
                    (directory / name).write_text(json.dumps({"side": side, "carrier": carrier}))
                    row["carrier_policy"][side] = name
            rows.append(row)
    (directory / "manifest.json").write_text(json.dumps({"version": 1, "rows": rows}))
    return directory


def quiet_main(argv):
    with contextlib.redirect_stdout(io.StringIO()):
        plans.main(argv)


class SwitchPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.c48 = export(self.root / "c48", "c48")
        self.base = export(self.root / "base", "base")

    def tearDown(self):
        self.temp.cleanup()

    def run_main(self, *extra):
        output = self.root / "out"
        quiet_main(["--c48", str(self.c48), "--base", str(self.base), "--output", str(output), *extra])
        return output, json.loads((output / "manifest.json").read_text())

    def test_default_output_is_udp_then_tls_for_both_pairs(self):
        output, manifest = self.run_main()
        self.assertEqual(manifest["kind"], "closeout-live-mode-switch")
        self.assertEqual([r["id"] for r in manifest["rows"]], [
            "switch-packed-c48-queue-aware-to-packed-c48-control-udp",
            "switch-packed-compact-to-aligned-compact-udp",
            "switch-packed-c48-queue-aware-to-packed-c48-control-tls",
            "switch-packed-compact-to-aligned-compact-tls"])
        udp = manifest["rows"][0]
        self.assertIsNone(udp["carrier_policy"])
        tls = manifest["rows"][2]
        self.assertEqual(tls["carrier_policy"]["a"], f"{tls['id']}.a.carrier.json")
        self.assertTrue((output / tls["carrier_policy"]["b"]).is_file())
        self.assertFalse(any("raw" in path.name for path in output.iterdir()))

    def test_raw_rows_copy_policies_and_keep_raw_only_kind(self):
        output = self.root / "raw"
        quiet_main(["--c48", str(self.c48), "--output", str(output), "--carrier", "raw", "--pair", "c48"])
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["kind"], "closeout-live-raw-mode-switch")
        (row,) = manifest["rows"]
        self.assertEqual(row["id"], "switch-packed-c48-queue-aware-to-packed-c48-control-raw")
        self.assertEqual(row["mode_switch"]["initial_row"], "packed-c48-queue-aware-raw")
        self.assertEqual(row["parameters"]["runtime_retained_bytes"], 1024)
        combined = json.loads((output / row["common_plan"]).read_text())
        self.assertEqual(len(combined["catalog"]), 2)
        self.assertEqual(combined["transaction"]["retained_bytes"], 1024)
        for side in ("a", "b"):
            policy = json.loads((output / row["carrier_policy"][side]).read_text())
            self.assertEqual(policy, {"side": side, "carrier": "raw"})

    def test_carrier_order_is_canonical_and_base_optional_for_c48(self):
        output = self.root / "mixed"
        quiet_main(["--c48", str(self.c48), "--output", str(output),
                    "--carrier", "raw", "--carrier", "udp", "--pair", "c48"])
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual([r["carrier"] for r in manifest["rows"]], ["udp", "raw"])
        self.assertEqual(manifest["kind"], "closeout-live-mode-switch")
        with self.assertRaises(SystemExit):
            plans.parse(["--c48", str(self.c48), "--output", str(self.root / "x")])

    def test_differing_raw_policy_is_refused(self):
        (self.c48 / "packed-c48-control-raw.a.carrier.json").write_text('{"side": "changed"}')
        with self.assertRaisesRegex(ValueError, "carrier policy differs"):
            quiet_main(["--c48", str(self.c48), "--output", str(self.root / "bad"),
                        "--carrier", "raw", "--pair", "c48"])


if __name__ == "__main__":
    unittest.main()
