"""Offline contracts for the optional owned-router underlay observation."""

import json
from pathlib import Path
import signal
import struct
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from . import path_bundle_netns_observe as observe


def netem(device):
    return dict(dev=device, kind="netem", handle="10:", root=True, bytes=600, packets=5,
                drops=1, overlimits=0, requeues=0, backlog=120, qlen=1)


class UnderlayObserverTests(unittest.TestCase):
    def queues(self, rows):
        with patch.object(observe.subprocess, "run", return_value=SimpleNamespace(
                stdout=json.dumps(rows).encode())) as run:
            try:
                return observe.router_queues()
            finally:
                run.assert_called_once_with(["tc", "-s", "-j", "qdisc", "show"],
                                            check=True, capture_output=True, timeout=1)

    def test_one_dump_reports_both_owned_netem_queues(self):
        a, b = netem("a0"), netem("b0")
        observed = self.queues([b, dict(dev="lo", kind="noqueue"), a])
        expected = {key: a[key] for key in ("bytes", "packets", "drops", "overlimits",
                                            "requeues", "backlog", "qlen")}
        self.assertEqual(observed, {"a0": expected, "b0": expected})

    def test_incomplete_or_misidentified_queues_and_invalid_counters_are_rejected(self):
        a, b = netem("a0"), netem("b0")
        for rows in ([a], [a, a, b], [a, dict(b, kind="pfifo")], [a, dict(b, root=False)],
                     [a, dict(b, handle="2:")], [a, dict(b, backlog=True)], [a, dict(b, drops=-1)]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.queues(rows)

    def test_clean_process_exit_requires_a_complete_sampler_footer(self):
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1)
        record = struct.pack("<IIII", 123, 0, 42, 42) + bytes(42)
        outcomes = ((b'{"mono_begin_ns":100}\n', False),
                    (b'{"mono_begin_ns":100}\n{"complete":true,"samples":1}\n', True))
        for contents, expected in outcomes:
            with self.subTest(complete=expected), TemporaryDirectory() as directory:
                base = Path(directory)
                children = {}
                info = {"sampler": {}, "captures": {}, "complete": False}
                for label in ("router-a0", "router-b0"):
                    output = base / (label + ".pcap")
                    output.write_bytes(header + record)
                    log = base / (label + ".log")
                    log.write_text("1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n")
                    children[label] = dict(capture=output, log=log, process=Mock(poll=lambda: None))
                    info["captures"][label] = {}
                sample = base / "sampler.jsonl"
                sample.write_bytes(contents)
                children["router-sampler"] = dict(capture=sample, process=Mock(poll=lambda: None))
                case = SimpleNamespace(value={"underlay_observer": info}, stop=Mock(return_value=0), save=Mock())
                self.assertIs(observe.finish(case, children), expected)
                self.assertIs(info["complete"], expected)
                self.assertTrue(all(row["complete"] for row in info["captures"].values()))
                if expected:
                    self.assertEqual(info["sampler"]["samples"], 1)
                    self.assertEqual(info["errors"], [])
                else:
                    self.assertEqual(info["errors"], ["router-sampler: missing complete sampler footer"])
                self.assertEqual([args.args[1] for args in case.stop.call_args_list], [signal.SIGINT] * 3)


if __name__ == "__main__":
    unittest.main()
