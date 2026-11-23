import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import common_native_campaign as campaign, common_native_report as report

ROW = "packed-c48-queue-aware-raw"


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        plans = self.root / "plans"
        plans.mkdir()
        (plans / "p.common.json").write_text("{}")
        (plans / "manifest.json").write_text(json.dumps({"rows": [
            {"id": ROW, "status": "ready", "carrier": "raw", "common_plan": "p.common.json"},
            {"id": "packed-c48-queue-aware-udp", "status": "ready", "carrier": "udp", "common_plan": "p.common.json"},
            {"id": "refused-tls", "status": "plan_refused", "carrier": "tls"}]}))
        self.binary = self.root / "l2tunneld"
        self.binary.write_bytes(b"daemon")
        self.digest = campaign.file_hash(self.binary)
        self.schedule = self.root / "schedule.json"
        self.schedule.write_text(json.dumps([
            {"label": "s1-raw-1", "profile": "base", "carrier": "raw", "flows": 1,
             "seeds": {"a": 31248, "b": 31248 ^ campaign.SEED_XOR}},
            {"label": "s2-udp-4", "profile": "base", "manifest": "plans/manifest.json",
             "row": "packed-c48-queue-aware-udp", "flows": 4, "seed": 48761, "loss": 0,
             "credit_bytes": 524288, "switch": True, "extra": ["--raw-rst-observation"]},
            {"label": "other", "profile": "exp", "row": ROW}]))
        self.campaign = self.root / "campaign"

    def tearDown(self):
        self.temp.cleanup()

    def base(self, *extra):
        return ["--schedule", str(self.schedule), "--campaign", str(self.campaign), "--binary", str(self.binary),
                "--manifest", str(self.root / "plans" / "manifest.json"), "--stem", "packed-c48-queue-aware",
                "--profile", "base", *extra]

    def dry(self, *extra):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = campaign.main(self.base(*extra))
        return code, output.getvalue()

    def fake_cell(self, status="passed", receipts=True, seeds=None):
        def run(command, stdout, stderr):
            out = Path(command[command.index("--output") + 1])
            row = command[command.index("--row") + 1]
            flows = int(command[command.index("--flows") + 1])
            seed = int(command[command.index("--seed") + 1])
            loss = int(command[command.index("--loss-percent") + 1])
            credit = int(command[command.index("--outstanding-credit-bytes") + 1])
            if receipts:
                (out / row).mkdir(parents=True)
                plan = {"original_binary_still_matches": True, "binary_sha256": self.digest,
                        "netem_seeds": seeds or {"a": seed, "b": seed ^ campaign.SEED_XOR},
                        "outstanding_application_credit_bytes": credit, "per_flow_credit_bytes": credit // flows,
                        "socket_buffer_before_syn_bytes": campaign.SOCKET_BUFFER,
                        "network": {"loss_percent_each_direction": loss}}
                (out / "results.json").write_text(json.dumps(plan))
                (out / "outer-isolation.json").write_text(json.dumps(
                    {"initial_links": ["lo"], "remaining_named_namespaces": [], "return_code": 0}))
                phase = {"phase": "forward", "status": status,
                         "netem_seeds": {s: {"seed": v, "loss_percent": loss, "delay_ms": 35}
                                         for s, v in (("a", seed), ("b", seed ^ campaign.SEED_XOR))},
                         "throughput": {"a_to_b": {"goodput_mbit_s": 12.5}}}
                (out / row / "result.json").write_text(json.dumps({"status": status, "row": {"id": row},
                                                                   "phases": [phase]}))
            stdout.write("cell log\n")
            return subprocess.CompletedProcess(command, 0 if receipts else 1)
        return run

    def test_dry_run_prints_isolated_cell_commands_and_creates_nothing(self):
        code, text = self.dry("--binary-sha256", self.digest)
        self.assertEqual(code, 0)
        self.assertFalse(self.campaign.exists())
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(len(lines), 2)
        first, second = (line.split() for line in lines)
        self.assertEqual(first[:10], [*campaign.OUTER, "/usr/bin/python3", "-B"])
        self.assertEqual(first[10], str(campaign.CELL))
        for pair in (["--row", ROW], ["--flows", "1"], ["--seed", "31248"], ["--loss-percent", "15"],
                     ["--outstanding-credit-bytes", str(4 * 1024 * 1024)], ["--binary-sha256", self.digest]):
            i = first.index(pair[0])
            self.assertEqual(first[i:i + 2], pair)
        self.assertEqual(first[-3:], ["--output", str(self.campaign / "runs" / "s1-raw-1"), "--apply"])
        for flag in ("--switch", "--raw-rst-observation"):
            self.assertIn(flag, second)
        self.assertEqual(second[second.index("--outstanding-credit-bytes") + 1], "524288")
        self.assertNotIn("other", text)

    def test_schedule_validation_refuses_unready_rows_bad_seeds_and_reserved_flags(self):
        for bad in ({"label": "x", "row": "refused-tls"}, {"label": "x", "row": ROW, "seeds": {"a": 1, "b": 2}},
                    {"label": "x", "row": ROW, "extra": ["--apply"]}, {"label": "x", "row": ROW, "flows": 2},
                    {"label": "x", "carrier": "udp", "row": ROW}, {"label": "x-retry1", "row": ROW},
                    {"label": "x", "row": ROW, "flows": 16, "credit_bytes": 4096}):
            self.schedule.write_text(json.dumps([bad]))
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                campaign.main(["--schedule", str(self.schedule), "--campaign", str(self.campaign), "--binary",
                               str(self.binary), "--manifest", str(self.root / "plans" / "manifest.json")])
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            campaign.parse(self.base("--apply"))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            campaign.parse(self.base("--binary-sha256", "0" * 64))

    def test_apply_writes_report_readable_ledgers_and_resumes_closed_cells(self):
        with patch.object(campaign.subprocess, "run", side_effect=self.fake_cell()) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.main(self.base("--apply", "--batch", "b1")), 0)
        self.assertEqual(run.call_count, 2)
        ledger = [json.loads(line) for line in (self.campaign / "reports/b1/receipts.jsonl").read_text().splitlines()]
        keys = {"label", "row", "concurrency", "elapsed", "requested", "status", "phase", "rc", "error", "goodput", "output"}
        self.assertTrue(all(keys <= set(item) for item in ledger))
        self.assertEqual([item["assertions"] for item in ledger], [[], []])
        self.assertEqual(ledger[1]["goodput"], 12.5)
        self.assertTrue((self.campaign / "reports/b1/s1-raw-1.log").is_file())
        inputs = json.loads((self.campaign / "reports/b1/inputs.json").read_text())
        self.assertIn(str(self.binary), inputs["binary"])
        self.assertEqual(len((self.campaign / "trials.jsonl").read_text().splitlines()), 2)
        with patch.object(campaign.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(campaign.main(self.base("--apply", "--batch", "b2")), 0)
        run.assert_not_called()
        self.assertIn("Previously closed: s1-raw-1", out.getvalue())

    def test_missing_receipt_stops_and_report_reads_the_failed_attempt(self):
        with patch.object(campaign.subprocess, "run", side_effect=self.fake_cell(receipts=False)) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.main(self.base("--apply", "--batch", "b1")), 2)
        self.assertEqual(run.call_count, 1)
        (attempt,) = [json.loads(x) for x in (self.campaign / "reports/b1/receipts.jsonl").read_text().splitlines()]
        self.assertEqual((attempt["status"], attempt["rc"]), ("no_case_receipt", 1))
        with contextlib.redirect_stdout(io.StringIO()):
            report.main(["--campaign", str(self.campaign)])
        cells = (self.campaign / "reports/cells.csv").read_text()
        self.assertIn("s1-raw-1", cells)
        self.assertIn("no_case_receipt", cells)

    def test_receipt_mismatch_is_recorded_and_stops(self):
        with patch.object(campaign.subprocess, "run", side_effect=self.fake_cell(seeds={"a": 1, "b": 2})), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.main(self.base("--apply", "--batch", "b1")), 3)
        (attempt,) = [json.loads(x) for x in (self.campaign / "reports/b1/receipts.jsonl").read_text().splitlines()]
        self.assertIn("plan netem seeds differ from the schedule", attempt["assertions"])

    def test_retry_predata_reruns_only_cells_without_data(self):
        runs = self.campaign / "runs"
        for label, row, result in (
                ("s1-raw-1", ROW, {"status": "failed", "phases": [{"phase": "forward", "status": "not_run"}]}),
                ("s2-udp-4", "packed-c48-queue-aware-udp",
                 {"status": "failed", "phases": [{"phase": "forward", "status": "failed", "netem_seeds": {"a": {}}}]})):
            (runs / label / row).mkdir(parents=True)
            (runs / label / row / "result.json").write_text(json.dumps(result))
        code, text = self.dry("--retry-predata")
        self.assertEqual(code, 0)
        self.assertIn("# s1-raw-1-retry1: run", text)
        self.assertIn(str(runs / "s1-raw-1-retry1"), text)
        self.assertIn("# s2-udp-4: skip_data", text)
        with patch.object(campaign.subprocess, "run", side_effect=self.fake_cell()) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.main(self.base("--apply", "--batch", "r1", "--retry-predata")), 0)
        self.assertEqual(run.call_count, 1)
        (attempt,) = [json.loads(x) for x in (self.campaign / "reports/r1/receipts.jsonl").read_text().splitlines()]
        self.assertEqual((attempt["label"], attempt["retry_of"]), ("s1-raw-1-retry1", "s1-raw-1"))
        # A plain rerun sees the original unclosed directory and refuses.
        code, text = self.dry()
        self.assertEqual(code, 2)
        self.assertIn("# s1-raw-1: unclosed", text)


if __name__ == "__main__":
    unittest.main()
