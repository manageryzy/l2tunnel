"""Unprivileged preflight for the path bundle's fixed TUN traffic row."""

import json
import socket
import struct
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from . import path_bundle_netns_lab as bundle


class PathBundlePreflightTests(unittest.TestCase):
    def test_scheduler_trace_bounds_and_timer_slack_preserve_an_explicit_selection(self):
        valid = ["--paced-recovery", "--fair-members", "--trace", "--trace-scheduler-groups", "3000:3128", "--pacing-timer-slack-ns", "1"]
        with patch("sys.argv", ["lab", *valid]), redirect_stdout(StringIO()) as out:
            self.assertEqual(bundle.main(), 0)
            plan = json.loads(out.getvalue())
            for side in "ab":
                args = bundle.adapter_policy_args(plan, side)
                self.assertEqual(args[args.index("--pacing-timer-slack-ns") + 1], "1")
                self.assertEqual(args[args.index("--trace-scheduler-groups") + 1], "3000:3128")
        for flags in [["--pacing-timer-slack-ns", "1"], ["--paced-recovery", "--pacing-timer-slack-ns", "0"],
                      ["--trace-scheduler-groups", "1:2"], [*valid, "--trace-scheduler-groups", "0:129"],
                      [*valid, "--trace-scheduler-groups", "3:2"], [*valid, "--trace-scheduler-groups", "1:2:3"]]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    bundle.main()
        bundle.validate_timer_slack({}, None)
        bundle.validate_timer_slack({"timer_slack": {"before_ns": 50000, "requested_ns": 1, "effective_ns": 1}}, 1)
        with self.assertRaises(ValueError):
            bundle.validate_timer_slack({"timer_slack": {"before_ns": 50000, "requested_ns": 1, "effective_ns": 50000}}, 1)

    def test_named_debt_transfer_keeps_an_explicit_selection_and_observed_counter(self):
        required = ["--path-arq", "--fair-members", "--physical-rank-suppression"]
        for flags, enabled in [([], False), ([*required, "--transfer-named-path-debt"], True)]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stdout(StringIO()) as out:
                self.assertEqual(bundle.main(), 0)
                plan = json.loads(out.getvalue())
                self.assertIs(plan["transfer_named_path_debt"], enabled)
                self.assertEqual("--transfer-named-path-debt" in bundle.adapter_policy_args(plan, "a"), enabled)
        for missing in required:
            with patch("sys.argv", ["lab", "--transfer-named-path-debt", *(f for f in required if f != missing)]), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    bundle.main()
        bundle.validate_named_transfer({"config": {}}, False)
        bundle.validate_named_transfer({"config": {"transfer_named_path_debt": True}, "path_debts_transferred_to_named": 3}, True)
        for stats, selected in [({"config": {}, "path_debts_transferred_to_named": 1}, False),
                                ({"config": {"transfer_named_path_debt": True}}, True)]:
            with self.subTest(stats=stats), self.assertRaises(ValueError):
                bundle.validate_named_transfer(stats, selected)

    def test_underlay_observation_is_opt_in_and_requires_owned_router_queues(self):
        for flags, enabled in [([], False), (["--loss-after-shaper", "--observe-underlay"], True)]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stdout(StringIO()) as out:
                self.assertEqual(bundle.main(), 0)
                self.assertIs(json.loads(out.getvalue())["observe_underlay"], enabled)
        with patch("sys.argv", ["lab", "--observe-underlay"]), redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                bundle.main()

    def test_low_load_round_requires_all_four_policies_and_keeps_them_optional_otherwise(self):
        requirements = ["--paced-recovery", "--fair-members", "--path-arq", "--physical-rank-suppression"]
        for flags, enabled in [([], False), (requirements, False), (["--low-load-forward-round", *requirements], True)]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stdout(StringIO()) as out:
                self.assertEqual(bundle.main(), 0)
                plan = json.loads(out.getvalue())
                self.assertIs(plan["low_load_forward_round"], enabled)
                for side in "ab":
                    args = bundle.adapter_policy_args(plan, side)
                    self.assertEqual(args.count("--low-load-forward-round"), int(enabled))
                    if enabled:
                        self.assertTrue(all(flag in args for flag in requirements))
                        self.assertEqual(int(args[args.index("--wire-rate-bps") + 1]), plan["wire_rate_bps"][side])
        for missing in requirements:
            args = ["lab", "--low-load-forward-round", *(flag for flag in requirements if flag != missing)]
            with self.subTest(missing=missing), patch("sys.argv", args), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    bundle.main()

    def test_low_load_receipt_enforces_shared_payment_and_per_direction_allowance(self):
        path = {"low_load_round_packets": 128, "low_load_round_entries": 128, "low_load_round_ip_bytes": 12800,
                "paid_packets": 140, "paid_ip_bytes": 13300}
        stats = {"config": {"low_load_forward_round": True}, "paths": [path]}
        for side in "ab":
            bundle.validate_low_load_round(stats, side, True, 1)
        for name, value in [("low_load_round_entries", 129), ("paid_packets", 127), ("paid_ip_bytes", 12799)]:
            with self.subTest(name=name), patch.dict(path, {name: value}), self.assertRaises(ValueError):
                bundle.validate_low_load_round(stats, "a", True, 1)
        with self.assertRaises(ValueError):
            bundle.validate_low_load_round(stats, "a", False, 1)
        bundle.validate_low_load_round({"config": {}, "paths": [{}]}, "b", False, 1)
        with self.assertRaises(ValueError):
            bundle.validate_low_load_round({"config": {"low_load_forward_round": True}, "paths": [{}]}, "b", True, 1)

    def test_original_frontier_preference_is_explicit_and_requires_shared_pacing_and_member_fairness(self):
        for flags, enabled in [
            (["--paced-recovery", "--fair-members"], False),
            (["--pace-original-frontiers", "--paced-recovery", "--fair-members"], True),
        ]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stdout(StringIO()) as out:
                self.assertEqual(bundle.main(), 0)
                self.assertIs(json.loads(out.getvalue())["pace_original_frontiers"], enabled)
        for flags in [[], ["--fair-members"], ["--paced-recovery"]]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", "--pace-original-frontiers", *flags]), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    bundle.main()

    def test_physical_rank_suppression_requires_both_recovery_components(self):
        for flags, enabled in [
            ([], False),
            (["--path-arq", "--fair-members"], False),
            (["--physical-rank-suppression", "--path-arq", "--fair-members"], True),
        ]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stdout(StringIO()) as out:
                self.assertEqual(bundle.main(), 0)
                self.assertIs(json.loads(out.getvalue())["physical_rank_suppression"], enabled)
        for flags in [[], ["--path-arq"], ["--fair-members"]]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", "--physical-rank-suppression", *flags]), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    bundle.main()

    def test_shared_earned_burst_plan(self):
        for flags, frames in [
            ([], None),
            (["--paced-recovery"], 1),
            (["--paced-recovery", "--pacing-burst-frames", "2"], 2),
            (["--paced-recovery", "--pacing-burst-frames", "8"], 8),
        ]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stdout(StringIO()) as out:
                self.assertEqual(bundle.main(), 0)
                plan = json.loads(out.getvalue())
                self.assertEqual(plan["pacing_burst_frames"], frames)
                self.assertEqual(plan["pacing_initial_ethernet_bytes"], 1514 if frames else None)
                self.assertEqual(plan["pacing_burst_ethernet_bytes"], frames * 1514 if frames else None)
        for flags in [
            ["--pacing-burst-frames", "1"],
            ["--paced-recovery", "--pacing-burst-frames", "0"],
            ["--paced-recovery", "--pacing-burst-frames", "9"],
        ]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    bundle.main()

    def test_authenticated_path_gate_needs_pacing_and_waits_for_both_sides(self):
        for flags, enabled in [([], False), (["--authenticated-path-ready", "--paced-recovery"], True)]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stdout(StringIO()) as out:
                self.assertEqual(bundle.main(), 0)
                self.assertIs(json.loads(out.getvalue())["authenticated_path_ready"], enabled)
        with patch("sys.argv", ["lab", "--authenticated-path-ready"]), redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                bundle.main()
        case = Mock(value={})
        adapters = {side: {"process": Mock(pid=pid)} for side, pid in zip("ab", (10, 11))}
        for child in adapters.values():
            child["process"].poll.return_value = None
        case.wait_marker.side_effect = [None, TimeoutError("peer missing")]
        with self.assertRaises(TimeoutError):
            bundle.wait_for_authenticated_paths(case, adapters)
        gate = case.value["authenticated_path_gate"]
        self.assertEqual(list(gate["observed"]), ["a"])
        self.assertNotIn("both_observed_wall_ns", gate)
        self.assertEqual(case.wait_marker.call_args_list[0].args[2], case.wait_marker.call_args_list[1].args[2])
        case.wait_marker.reset_mock(side_effect=True)
        bundle.wait_for_authenticated_paths(case, adapters)
        self.assertEqual(set(case.value["authenticated_path_gate"]["observed"]), {"a", "b"})
        self.assertIn("both_observed_wall_ns", case.value["authenticated_path_gate"])

    def test_path_proof_counters_must_match_real_wire_bytes_on_every_slot(self):
        stats = {"config": {"outer_ipv4_bytes": 49}, "totals": {"authenticated_other_packets_before_path_ready": 0},
                 "authenticated_path_ready": {"ready": True, "paths": [
                     {"slot": 0, "ready_at_us": 123, "requests_paid": 2, "echoes_paid": 1}]},
                 "paths": [{"slot": 0, "path_ready_requests_paid": 2, "path_ready_echoes_paid": 1,
                            "path_ready_ip_bytes": 201, "path_ready_ethernet_bytes": 243, "paid_ip_bytes": 2350}]}
        bundle.validate_path_ready(stats, 1)
        with self.assertRaises(ValueError):
            bundle.validate_path_ready(stats, 2)
        stats["paths"][0]["path_ready_ip_bytes"] += 1
        with self.assertRaises(ValueError):
            bundle.validate_path_ready(stats, 1)

    def test_neighbor_capture_is_opt_in_on_both_ends_of_each_owned_link(self):
        for flags, selected in [([], False), (["--capture-neighbor-events"], True)]:
            with self.subTest(flags=flags), patch("sys.argv", ["lab", *flags]), redirect_stdout(StringIO()) as out:
                self.assertEqual(bundle.main(), 0)
                self.assertIs(json.loads(out.getvalue())["capture_neighbor_events"], selected)
        self.assertEqual(set(bundle.NEIGHBOR_SURFACES), {
            ("endpoint_a", "wan0"), ("router", "a0"), ("router", "b0"), ("endpoint_b", "wan0")})

    def test_neighbor_capture_distinguishes_absence_from_missing_or_truncated_packets(self):
        with TemporaryDirectory() as directory:
            pcap = Path(directory) / "arp.pcap"
            header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1)
            pcap.write_bytes(header)
            self.assertEqual(bundle.neighbor_events(pcap, 0), [])
            with self.assertRaises(ValueError):
                bundle.neighbor_events(pcap, 1)
            sender = bytes.fromhex("020000000001")
            frame = (bytes([255]) * 6 + sender + bytes.fromhex("08060001080006040001") + sender
                     + socket.inet_aton("192.0.2.2") + bytes(6) + socket.inet_aton("192.0.2.1"))
            rec = struct.pack("<IIII", 42, 1234, len(frame), len(frame)) + frame
            pcap.write_bytes(header + rec)
            event, = bundle.neighbor_events(pcap, 1)
            self.assertEqual((event["wall_ns"], event["opcode"], event["sender_ip"], event["target_ip"]),
                             (42_001_234_000, 1, "192.0.2.2", "192.0.2.1"))
            with self.assertRaises(ValueError):
                bundle.neighbor_events(pcap, 0)
            pcap.write_bytes(header + rec[:-1])
            with self.assertRaises(ValueError):
                bundle.neighbor_events(pcap, 1)

    def test_single_flow_case_records_tun_for_both_endpoints(self):
        row = bundle.tun_case_row(6, 5)
        for side in ("a", "b"):
            self.assertEqual(row["required_cli"][side], ["--layer", "tun"])
        with TemporaryDirectory() as directory:
            output = Path(directory)
            bundle.matrix.Case(row, bundle.matrix.lab.LabSpec("bundle-row"), output)
            receipt = json.loads((output / "result.json").read_text())
        self.assertEqual(receipt["id"], "path-bundle-6-5-single")
        self.assertEqual(receipt["native_layer"], "tun")
