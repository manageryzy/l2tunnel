import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import common_native_cell as cell


class CellTests(unittest.TestCase):
    def fixture(self, root):
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"rows": [{"id": "ready-udp", "status": "ready"},
                                                 {"id": "refused-raw", "status": "plan_refused"}]}))
        binary = root / "l2tunneld"
        binary.write_bytes(b"daemon")
        return manifest, binary

    def test_forwards_selected_options_to_the_matrix_dry_run(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest, binary = self.fixture(root)
            a = cell.parse(["--manifest", str(manifest), "--binary", str(binary), "--row", "ready-udp",
                            "--flows", "4", "--seed", "48761", "--loss-percent", "0", "--switch",
                            "--raw-rst-observation", "--output", str(root / "out")])
            args = cell.matrix_args(a)
            for pair in (["--flow-count", "4"], ["--netem-seed", "48761"], ["--loss-percent", "0"],
                         ["--case", "ready-udp"], ["--phase", "forward"]):
                i = args.index(pair[0])
                self.assertEqual(args[i:i + 2], pair)
            i = args.index("--outstanding-credit-bytes")
            self.assertEqual(args[i + 1], str(4 * 1024 * 1024))
            a = cell.parse(["--manifest", str(manifest), "--binary", str(binary), "--row", "ready-udp",
                            "--flows", "1", "--outstanding-credit-bytes", "524288", "--output", str(root / "out")])
            args = cell.matrix_args(a)
            self.assertEqual(args[args.index("--outstanding-credit-bytes") + 1], "524288")
            a = cell.parse(["--manifest", str(manifest), "--binary", str(binary), "--row", "ready-udp",
                            "--flows", "4", "--seed", "48761", "--loss-percent", "0", "--switch",
                            "--raw-rst-observation", "--output", str(root / "out")])
            args = cell.matrix_args(a)
            for flag in ("--no-capture", "--switch-during-phase", "--raw-rst-observation"):
                self.assertIn(flag, args)
            self.assertNotIn("--apply", args)
            with patch.object(cell.subprocess, "call", return_value=0) as call:
                self.assertEqual(cell.main(["--manifest", str(manifest), "--binary", str(binary), "--row",
                                            "ready-udp", "--flows", "1", "--output", str(root / "out")]), 0)
            self.assertNotIn("--apply", call.call_args.args[0])

    def test_refuses_unready_rows_existing_output_wrong_digest_and_unisolated_apply(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest, binary = self.fixture(root)
            base = ["--manifest", str(manifest), "--binary", str(binary), "--flows", "1"]
            (root / "exists").mkdir()
            for extra in (["--row", "refused-raw", "--output", str(root / "o")],
                          ["--row", "ready-udp", "--output", str(root / "exists")],
                          ["--row", "ready-udp", "--output", str(root / "o"), "--binary-sha256", "0" * 64]):
                with self.assertRaises(SystemExit), patch("sys.stderr"):
                    cell.parse(base + extra)
            with patch.object(cell.os, "geteuid", return_value=1000), self.assertRaises(SystemExit):
                cell.main(base + ["--row", "ready-udp", "--output", str(root / "o"), "--apply"])
            self.assertFalse((root / "o").exists())


if __name__ == "__main__":
    unittest.main()
