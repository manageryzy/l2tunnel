"""Unprivileged tests for deterministic plans and fail-closed ownership checks."""

from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import netns_lab as lab


class PlanTests(unittest.TestCase):
    def test_default_is_dry_run_without_subprocess_or_state(self) -> None:
        output = io.StringIO()
        with (
            patch.object(lab, "run", side_effect=AssertionError("must not execute")),
            patch.object(
                lab, "locked_state", side_effect=AssertionError("must not write")
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(lab.main(["--json"]), 0)
        document = json.loads(output.getvalue())
        self.assertEqual(document["status"], "topology_only_no_tunnel_daemon")
        self.assertEqual(document["parameters"]["base_rtt_ms"], 70)

    def test_plan_is_deterministic_and_all_changes_are_namespaced(self) -> None:
        spec = lab.LabSpec("test")
        self.assertEqual(lab.build_plan(spec), lab.build_plan(spec))
        names = set(spec.namespaces.values())
        for step in lab.build_plan(spec):
            command = step.argv
            self.assertEqual(command[0], "ip")
            if command[1:3] == ("netns", "add"):
                self.assertIn(command[3], names)
                self.assertEqual(step.creates_namespace, command[3])
            elif command[1] == "-n":
                self.assertIn(command[2], names)
                self.assertNotIn("default", command)
            else:
                self.assertEqual(command[1:3], ("netns", "exec"))
                self.assertIn(command[3], names)
                self.assertIn(command[4], {"tc", "sysctl"})
            self.assertNotIn("replace", command)
            self.assertNotIn("delete", command)
            self.assertNotIn("flush", command)

    def test_requested_topology_and_directional_profile(self) -> None:
        commands = [step.argv for step in lab.build_plan(lab.LabSpec())]
        self.assertEqual(
            sum(command[1:3] == ("netns", "add") for command in commands), 5
        )
        self.assertEqual(sum("tuntap" in command for command in commands), 2)
        self.assertEqual(sum("stp_state" in command for command in commands), 2)
        netem = [command for command in commands if "netem" in command]
        self.assertEqual(len(netem), 2)
        self.assertTrue(
            all(
                command[-5:] == ("delay", "35ms", "loss", "random", "15%")
                for command in netem
            )
        )
        rates = [
            command[command.index("rate") + 1]
            for command in commands
            if "rate" in command
        ]
        self.assertEqual(rates, ["100mbit", "10mbit"])
        self.assertTrue(
            all(
                command[command.index("mtu") + 1] == "1500"
                for command in commands
                if "mtu" in command
            )
        )
        for command in commands:
            if "veth" in command:
                self.assertEqual(command[-2], "netns")
                self.assertIn(command[-1], lab.LabSpec().namespaces.values())

    def test_loss_percent_selects_netem_loss_and_rejects_out_of_range(self) -> None:
        for loss in (0, 15):
            spec = lab.LabSpec("loss-test", loss_percent=loss)
            netem = [c for c in (s.argv for s in lab.build_plan(spec)) if "netem" in c]
            self.assertEqual(len(netem), 2)
            self.assertTrue(all(c[-3:] == ("loss", "random", f"{loss}%") for c in netem))
            self.assertEqual(
                lab.plan_document(spec)["parameters"]["iid_loss_percent_per_direction"], loss
            )
        for invalid in (-1, 101, 1.5, True):
            with self.assertRaises(ValueError):
                lab.LabSpec("loss-test", loss_percent=invalid)

    def test_invalid_names_never_reach_execution(self) -> None:
        for value in ("../host", "x;id", "", "a" * 21, "UPPER", "x/y", "--all"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                lab.LabSpec(value)

    def test_apply_requires_root_before_any_action(self) -> None:
        with (
            patch.object(lab.os, "geteuid", return_value=1000),
            patch.object(lab, "run", side_effect=AssertionError("must not execute")),
            self.assertRaisesRegex(RuntimeError, "require root"),
        ):
            lab.apply(lab.LabSpec(), Path("/does-not-exist"))

    def test_json_cannot_hide_apply_action(self) -> None:
        with (
            patch.object(lab, "apply", side_effect=AssertionError("must not apply")),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(lab.main(["--json", "--apply"]), 1)


class OwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = lab.LabSpec("test")
        self.name = self.spec.namespaces["endpoint_a"]
        self.identity = {"device": 123, "inode": 456}
        self.manifest = {
            "version": lab.STATE_VERSION,
            "lab_id": self.spec.lab_id,
            "uid": 0,
            "owned_namespaces": {self.name: self.identity},
        }

    def test_manifest_rejects_foreign_namespace(self) -> None:
        self.manifest["owned_namespaces"]["host-production"] = self.identity
        with self.assertRaisesRegex(RuntimeError, "unexpected namespace"):
            lab.validate_manifest(self.manifest, self.spec)

    def test_manifest_rejects_malformed_identity(self) -> None:
        self.manifest["owned_namespaces"][self.name] = {"device": "123", "inode": 456}
        with self.assertRaisesRegex(RuntimeError, "invalid namespace identity"):
            lab.validate_manifest(self.manifest, self.spec)

    def test_replaced_namespace_is_never_deleted(self) -> None:
        with (
            patch.object(
                lab, "namespace_identity", return_value={"device": 123, "inode": 789}
            ),
            patch.object(lab, "run") as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "replaced namespace"):
                lab.verify_cleanup(self.manifest)
            execute.assert_not_called()

    def test_running_process_prevents_cleanup(self) -> None:
        with (
            patch.object(lab, "namespace_identity", return_value=self.identity),
            patch.object(
                lab,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "1234\n", ""),
            ) as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "still has processes"):
                lab.verify_cleanup(self.manifest)
            execute.assert_called_once_with(["ip", "netns", "pids", self.name])

    def test_existing_state_prevents_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "test.json"
            path.write_text("existing state", encoding="utf-8")
            with (
                patch.object(lab, "require_root"),
                patch.object(lab.shutil, "which", return_value="present"),
                patch.object(lab, "locked_state", return_value=nullcontext(path)),
                patch.object(lab, "run") as execute,
            ):
                with self.assertRaisesRegex(RuntimeError, "state already exists"):
                    lab.apply(self.spec, Path(temporary))
                execute.assert_not_called()
            self.assertEqual(path.read_text(encoding="utf-8"), "existing state")

    def test_existing_namespace_is_not_adopted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / self.name).touch()
            path = directory / "test.json"
            with (
                patch.object(lab, "require_root"),
                patch.object(lab.shutil, "which", return_value="present"),
                patch.object(lab, "locked_state", return_value=nullcontext(path)),
                patch.object(lab, "NETNS_DIRECTORY", directory),
                patch.object(lab, "run") as execute,
            ):
                with self.assertRaisesRegex(RuntimeError, "namespace already exists"):
                    lab.apply(self.spec, directory)
                execute.assert_not_called()
            self.assertFalse(path.exists())

    def test_failed_apply_rolls_back_only_recorded_namespace(self) -> None:
        created = lab.Step(("ip", "netns", "add", self.name), self.name)
        failed = lab.Step(("ip", "-n", self.name, "link", "set", "lo", "up"))

        def fake_run(command):
            if tuple(command) == failed.argv:
                raise subprocess.CalledProcessError(
                    1, command, stderr="synthetic failure"
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "test.json"
            with (
                patch.object(lab, "require_root"),
                patch.object(lab.shutil, "which", return_value="present"),
                patch.object(lab, "locked_state", return_value=nullcontext(path)),
                patch.object(lab, "NETNS_DIRECTORY", directory),
                patch.object(lab, "build_plan", return_value=[created, failed]),
                patch.object(lab, "namespace_identity", return_value=self.identity),
                patch.object(lab, "run", side_effect=fake_run) as execute,
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    lab.apply(self.spec, directory)
            self.assertFalse(path.exists())
            self.assertEqual(
                [
                    call.args[0]
                    for call in execute.call_args_list
                    if "delete" in call.args[0]
                ],
                [["ip", "netns", "delete", self.name]],
            )


if __name__ == "__main__":
    unittest.main()
