"""Unprivileged tests for native_perf_profile.py; perf is never executed."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import native_perf_profile as perf


def stat_line(pid, user, system, start, name="l2tunnel native", state="S"):
    # Fields after "comm) ": state(0) ... utime(11) stime(12) ... starttime(19) ... >= 22 fields.
    fields = [state] + ["0"] * 10 + [str(user), str(system)] + ["0"] * 6 + [str(start)] + ["0"] * 5
    return f"{pid} ({name}) " + " ".join(fields)


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, *extra):
        return perf.parse(["--lab", str(self.root / "lab"), "--output", str(self.root / "out"), *extra])

    def test_mode_defaults_preserve_original_recorder_parameters(self):
        kernel = self.args("--mode", "kernel")
        self.assertEqual((kernel.event, kernel.max_size, kernel.chown), ("cycles:k", "16M", True))
        clean = self.args("--mode", "clean")
        self.assertEqual((clean.event, clean.max_size, clean.chown), ("cycles", "8M", True))
        impaired = self.args("--mode", "impaired")
        self.assertEqual((impaired.event, impaired.max_size, impaired.chown), ("cycles", "64M", False))
        self.assertEqual(impaired.fallback_event, "cpu-clock")
        self.assertEqual((impaired.edge_ns, impaired.min_window_ns, impaired.max_window_ns),
                         (2_000_000_000, 2_000_000_000, 17_000_000_000))
        self.assertEqual((impaired.expect_warmup_ns, impaired.expect_measure_ns), (5_000_000_000, 20_000_000_000))
        self.assertEqual(impaired.expect_plan, perf.DEFAULT_PLAN_CONTRACT)
        self.assertEqual(impaired.expect_policy, perf.DEFAULT_POLICY_CONTRACT)
        self.assertEqual(impaired.sides, ["a", "b"])

    def test_overrides_and_disabled_contracts(self):
        a = self.args("--mode", "impaired", "--event", "cpu-clock", "--fallback-event", "", "--max-size", "4M",
                      "--expect-plan", "{}", "--expect-policy", "null", "--expect-warmup-seconds", "any",
                      "--no-chown", "--sides", "a,b,c")
        self.assertEqual((a.event, a.fallback_event, a.max_size), ("cpu-clock", None, "4M"))
        self.assertEqual((a.expect_plan, a.expect_policy, a.expect_warmup_ns), ({}, None, None))
        self.assertFalse(a.chown)
        self.assertEqual(a.sides, ["a", "b", "c"])

    def test_rejects_existing_output_bad_bounds_and_unpinned_impaired_apply(self):
        (self.root / "out").mkdir()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.args("--mode", "kernel")
        (self.root / "out").rmdir()
        for bad in (["--mode", "clean", "--min-window-seconds", "20"],
                    ["--mode", "clean", "--frequency", "0"],
                    ["--mode", "clean", "--sides", "a,a"],
                    ["--mode", "impaired", "--apply"],
                    ["--mode", "impaired", "--expected-binary-sha256", "XYZ"]):
            with self.subTest(bad=bad), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.args(*bad)
        self.args("--mode", "impaired", "--apply", "--expected-binary-sha256", "a" * 64)


class CommandTests(unittest.TestCase):
    def ns(self, mode, *extra):
        with tempfile.TemporaryDirectory() as d:
            return perf.parse(["--mode", mode, "--lab", d + "/lab", "--output", d + "/out", *extra])

    def test_kernel_command_matches_original(self):
        out = Path("/o")
        self.assertEqual(perf.kernel_command(self.ns("kernel"), "11,22", out / "perf.data"), [
            "perf", "record", "-e", "cycles:k", "-F", "99", "--call-graph", "fp",
            "--per-thread", "--no-inherit", "--no-buildid", "--no-buildid-cache",
            "-m", "8", "--max-size", "16M", "--clockid", "mono", "-p", "11,22", "-o", "/o/perf.data"])

    def test_clean_command_matches_original(self):
        self.assertEqual(perf.clean_command(self.ns("clean"), "11,22", Path("/o/perf.data"), "9.5"), [
            "perf", "record", "-e", "cycles", "-F", "99", "--call-graph", "fp",
            "--no-buildid-cache", "--max-size", "8M", "--clockid", "mono",
            "-p", "11,22", "-o", "/o/perf.data", "--", "sleep", "9.5"])

    def test_impaired_command_matches_original_and_honours_overrides(self):
        a = self.ns("impaired")
        self.assertEqual(perf.impaired_command(a, "cycles", "11,12,22", Path("/o/perf-cycles.data")), [
            "perf", "record", "-e", "cycles", "-F", "99", "--call-graph", "fp",
            "--switch-events", "-T", "--sample-cpu", "--per-thread", "--no-inherit",
            "--no-buildid", "--no-buildid-cache", "-m", "8", "--max-size", "64M",
            "--clockid", "mono", "-t", "11,12,22", "-o", "/o/perf-cycles.data"])
        b = self.ns("impaired", "--frequency", "499", "--call-graph", "dwarf", "--mmap-pages", "16")
        argv = perf.impaired_command(b, "cpu-clock", "1", Path("/x"))
        for pair in (["-F", "499"], ["--call-graph", "dwarf"], ["-m", "16"], ["-e", "cpu-clock"]):
            i = argv.index(pair[0])
            self.assertEqual(argv[i:i + 2], pair)


class PureHelperTests(unittest.TestCase):
    def test_stat_fields_handles_parentheses_in_comm(self):
        parsed = perf.stat_fields(stat_line(42, 7, 3, 9000, name="odd) name ("))
        self.assertEqual(parsed, {"pid": 42, "state": "S", "user_ticks": 7, "system_ticks": 3,
                                  "starttime_ticks": 9000})
        with self.assertRaises(ValueError):
            perf.stat_fields("42 noparen S 1 2")
        with self.assertRaises(ValueError):
            perf.stat_fields("42 (x) S 1 2")

    def test_task_status_keeps_only_scheduling_fields(self):
        value = "Name:\tworker\nState:\tS (sleeping)\nVmRSS:\t100 kB\nvoluntary_ctxt_switches:\t5\n"
        self.assertEqual(perf.task_status(value), {"Name": "worker", "State": "S (sleeping)",
                                                   "voluntary_ctxt_switches": "5"})

    def test_window_and_containment(self):
        clock = {"start_ns": 100_000_000_000, "warmup_ns": 5_000_000_000, "measure_ns": 20_000_000_000}
        start, end = perf.window(clock, 2_000_000_000)
        self.assertEqual((start, end), (107_000_000_000, 123_000_000_000))
        self.assertTrue(perf.contained(end, start, 2_000_000_000, 17_000_000_000))
        self.assertFalse(perf.contained(end, end - 1_000_000_000, 2_000_000_000, 17_000_000_000))
        self.assertFalse(perf.contained(end, start - 2_000_000_000, 2_000_000_000, 17_000_000_000))

    def test_choose_tasks_ranks_cpu_delta_and_ignores_reused_tids(self):
        def snap(tasks):
            return {"processes": {"10": {"tasks": {tid: {"stat": stat_line(int(tid), u, s, st)}
                                                   for tid, (u, s, st) in tasks.items()}}}}
        first = snap({"10": (0, 0, 1), "11": (10, 0, 2), "12": (5, 5, 3), "13": (0, 0, 4)})
        second = snap({"10": (0, 0, 1), "11": (30, 5, 2), "12": (6, 5, 3), "13": (90, 0, 99), "14": (1, 0, 5)})
        all_tasks, selected = perf.choose_tasks(first, second, limit=2)
        self.assertEqual(all_tasks["10"], {"10": 1, "11": 2, "12": 3, "13": 99, "14": 5})
        # 13 reused its TID (new start time) and 14 is new: both count as zero delta.
        self.assertEqual(selected["10"], {"11": 2, "12": 3})
        _, everything = perf.choose_tasks(first, second, limit=8)
        self.assertEqual(set(everything["10"]), {"10", "11", "12"})

    def test_plan_contract(self):
        plan = dict(perf.DEFAULT_PLAN_CONTRACT, initial_policy=dict(perf.DEFAULT_POLICY_CONTRACT))
        perf.check_plan_contract(plan, perf.DEFAULT_PLAN_CONTRACT, perf.DEFAULT_POLICY_CONTRACT)
        with self.assertRaisesRegex(ValueError, "flows"):
            perf.check_plan_contract(dict(plan, flows=4), perf.DEFAULT_PLAN_CONTRACT, None)
        with self.assertRaisesRegex(ValueError, "policy"):
            perf.check_plan_contract(dict(plan, initial_policy={}), {}, perf.DEFAULT_POLICY_CONTRACT)
        perf.check_plan_contract({}, {}, None)

    def test_fallback_only_for_immediate_unsupported_primary_event(self):
        log = "Error: cycles event is not supported by the kernel"
        self.assertTrue(perf.should_fall_back("cycles", "cpu-clock", log, 200_000_000))
        self.assertFalse(perf.should_fall_back("cycles", "cpu-clock", log, 1_500_000_000))
        self.assertFalse(perf.should_fall_back("cpu-clock", "cpu-clock", log, 1))
        self.assertFalse(perf.should_fall_back("cycles", None, log, 1))
        self.assertFalse(perf.should_fall_back("cycles", "cpu-clock", "Segmentation fault", 1))
        self.assertTrue(perf.should_fall_back("cycles", "cpu-clock", "Access to performance monitoring "
                                              "and observability operations is limited", 1))

    def test_bounded_read_rejects_oversized_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "f"
            path.write_bytes(b"x" * 11)
            self.assertEqual(perf.raw(path, 11), b"x" * 11)
            with self.assertRaises(ValueError):
                perf.raw(path, 10)


class FakeChild:
    def __init__(self, waits):
        self.waits = list(waits)
        self.signals = []

    def poll(self):
        return None

    def send_signal(self, value):
        self.signals.append(("signal", value))

    def terminate(self):
        self.signals.append(("terminate", None))

    def kill(self):
        self.signals.append(("kill", None))

    def wait(self, timeout):
        outcome = self.waits.pop(0)
        if outcome == "timeout":
            raise perf.subprocess.TimeoutExpired("perf", timeout)
        return outcome


class FinishTests(unittest.TestCase):
    def test_graceful_sigint_returns_exit_code(self):
        child = FakeChild([0])
        self.assertEqual(perf.finish(child, 5, 2), 0)
        self.assertEqual(child.signals, [("signal", perf.signal.SIGINT)])

    def test_escalates_and_reports_a_finalize_timeout(self):
        child = FakeChild(["timeout", "timeout", -9])
        with self.assertRaisesRegex(TimeoutError, "graceful-stop"):
            perf.finish(child, 5, 2)
        self.assertEqual([s[0] for s in child.signals], ["signal", "terminate", "kill"])


class DryRunTests(unittest.TestCase):
    def test_dry_run_prints_plan_without_reading_lab_or_running_perf(self):
        with tempfile.TemporaryDirectory() as d:
            for mode, placeholder in (("kernel", "<PID_a>,<PID_b>"), ("clean", "<REMAINING_SECONDS>"),
                                      ("impaired", "<OWNED_TIDS>")):
                out = io.StringIO()
                with self.subTest(mode=mode), \
                        patch.object(perf.subprocess, "run", side_effect=AssertionError("ran")), \
                        patch.object(perf.subprocess, "Popen", side_effect=AssertionError("spawned")), \
                        contextlib.redirect_stdout(out):
                    rc = perf.main(["--mode", mode, "--lab", d + "/missing-lab", "--output", d + "/out"])
                self.assertEqual(rc, 0)
                planned = json.loads(out.getvalue())
                self.assertTrue(planned["dry_run"])
                self.assertEqual(planned["command"][:2], ["perf", "record"])
                self.assertIn(placeholder, planned["command"])
                self.assertFalse(Path(d, "out").exists())
            self.assertEqual(planned["clock_contract"], {"warmup_ns": 5_000_000_000, "measure_ns": 20_000_000_000})
            self.assertEqual(planned["fallback_event"], "cpu-clock")


class ApplyFailureTests(unittest.TestCase):
    def test_clean_apply_records_setup_timeout_without_running_perf(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "lab").mkdir()
            out = io.StringIO()
            with patch.object(perf.subprocess, "run", side_effect=AssertionError("ran")), \
                    contextlib.redirect_stdout(out):
                rc = perf.main(["--mode", "clean", "--apply", "--no-chown", "--setup-seconds", "0",
                                "--lab", str(root / "lab"), "--output", str(root / "out")])
            self.assertEqual(rc, 1)
            result = json.loads((root / "out" / "profile.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertIn("TimeoutError", result["error"])

    def test_kernel_apply_rejects_a_foreign_executable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            lab = root / "lab"
            lab.mkdir()
            (lab / "reference-clock.json").write_text(json.dumps(
                {"start_ns": 0, "warmup_ns": 0, "measure_ns": 0}))
            pid = perf.os.getpid()
            (lab / "receipt.json").write_text(json.dumps({"binary_sha256": "0" * 64, "initial_daemon_resources": {
                "a": {"pid": pid}, "b": {"pid": pid}}}))
            with patch.object(perf.subprocess, "Popen", side_effect=AssertionError("spawned")), \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = perf.main(["--mode", "kernel", "--apply", "--no-chown",
                                "--lab", str(lab), "--output", str(root / "out")])
            self.assertEqual(rc, 1)
            result = json.loads((root / "out" / "profile.json").read_text())
            self.assertIn("not owned copy", result["error"])
            self.assertEqual(result["files"], {})


if __name__ == "__main__":
    unittest.main()
