"""Unprivileged unit tests for tools/opengfw_lab.py."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock

from tools import opengfw_lab


class OpenGfwLabTests(unittest.TestCase):
    def test_dry_run_is_default_and_never_invokes_subprocess(self) -> None:
        buf = io.StringIO()
        with (
            mock.patch("subprocess.run", side_effect=AssertionError("dry-run must not run subprocess")),
            mock.patch("subprocess.Popen", side_effect=AssertionError("dry-run must not spawn subprocess")),
            contextlib.redirect_stdout(buf),
        ):
            rc = opengfw_lab.main(["--json"])
        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["mode"], "dry-run")
        self.assertEqual(doc["opengfw"]["commit"], opengfw_lab.OPENGFW_COMMIT)
        self.assertEqual(doc["topology"]["host_changes"], "none")
        self.assertEqual(doc["total_cells"], len(opengfw_lab.CARRIER_CASES) * len(opengfw_lab.RULESET_SPECS))

    def test_observe_all_references_every_analyzer(self) -> None:
        obs = opengfw_lab.RULESET_BY_ID["observe-all"]
        rendered = opengfw_lab.render_ruleset_yaml(obs)
        for analyzer in opengfw_lab.ALL_ANALYZERS:
            self.assertIn(f"{analyzer} != nil", rendered)
        self.assertNotIn("action: block", rendered)
        self.assertNotIn("action: drop", rendered)

    def test_config_yaml_disables_local_and_enables_rst(self) -> None:
        cfg = opengfw_lab.render_opengfw_config_yaml(rst=True, workers=2)
        self.assertIn("local: false", cfg)
        self.assertIn("rst: true", cfg)
        self.assertIn("count: 2", cfg)

    def test_selection_and_lab_id_validation(self) -> None:
        picked = opengfw_lab.select_items("tcp-google,quic", opengfw_lab.CARRIER_CASES, opengfw_lab.CARRIER_BY_ID, "carrier")
        self.assertEqual([c.id for c in picked], ["tcp-google", "quic"])
        with self.assertRaises(ValueError):
            opengfw_lab.select_items("nonexistent", opengfw_lab.CARRIER_CASES, opengfw_lab.CARRIER_BY_ID, "carrier")
        self.assertEqual(opengfw_lab.cell_lab_id("ogfw", 7), "ogfw-007")
        with self.assertRaises(ValueError):
            opengfw_lab.validate_lab_prefix("BAD_PREFIX")
        with self.assertRaises(ValueError):
            opengfw_lab.validate_lab_prefix("toolongprefix")

    def test_parse_opengfw_json_logs_tls_fet_and_block(self) -> None:
        sample = "\n".join(
            [
                json.dumps({"level": "info", "msg": "engine started"}),
                json.dumps({"level": "debug", "msg": "worker started", "id": 0}),
                json.dumps({"level": "debug", "msg": "worker stopped", "id": 0}),
                json.dumps({"level": "debug", "msg": "new TCP stream", "id": 101, "src": "192.0.2.2:50000", "dst": "192.0.2.6:24440"}),
                json.dumps(
                    {
                        "level": "debug",
                        "msg": "TCP stream property update",
                        "id": 101,
                        "src": "192.0.2.2:50000",
                        "dst": "192.0.2.6:24440",
                        "props": {
                            "tls": {"req": {"sni": "blocked.example", "alpn": ["h2"]}},
                            "fet": {"ex1": 3.91, "ex5": True, "yes": False},
                        },
                        "close": False,
                    }
                ),
                json.dumps(
                    {
                        "level": "info",
                        "msg": "ruleset log",
                        "name": "block-tls-sni",
                        "id": 101,
                        "src": "192.0.2.2:50000",
                        "dst": "192.0.2.6:24440",
                        "props": {"tls": {"req": {"sni": "blocked.example"}}},
                    }
                ),
                json.dumps(
                    {
                        "level": "info",
                        "msg": "TCP stream action",
                        "id": 101,
                        "src": "192.0.2.2:50000",
                        "dst": "192.0.2.6:24440",
                        "action": "block",
                        "noMatch": False,
                    }
                ),
            ]
        )
        parsed = opengfw_lab.parse_opengfw_log(sample)
        self.assertTrue(parsed["engine_started"])
        self.assertTrue(parsed["blocked_by_opengfw"])
        self.assertEqual(parsed["matched_analyzers"], ["fet", "tls"])
        summary = opengfw_lab.summarize_classification(parsed)
        self.assertIn("tls(sni=blocked.example, alpn=h2)", summary)
        self.assertIn("fet(yes=False, ex5=True", summary)

    def test_parse_opengfw_udp_openvpn_and_unclassified(self) -> None:
        sample = "\n".join(
            [
                json.dumps({"level": "info", "msg": "engine started"}),
                json.dumps({"level": "debug", "msg": "new UDP stream", "id": 202, "src": "192.0.2.2:24440", "dst": "192.0.2.6:24440"}),
                json.dumps(
                    {
                        "level": "debug",
                        "msg": "UDP stream property update",
                        "id": 202,
                        "src": "192.0.2.2:24440",
                        "dst": "192.0.2.6:24440",
                        "props": {"openvpn": {"tx_pkt_cnt": 5, "rx_pkt_cnt": 4}},
                        "close": False,
                    }
                ),
                json.dumps(
                    {
                        "level": "info",
                        "msg": "UDP stream action",
                        "id": 202,
                        "src": "192.0.2.2:24440",
                        "dst": "192.0.2.6:24440",
                        "action": "allow",
                        "noMatch": True,
                    }
                ),
            ]
        )
        parsed = opengfw_lab.parse_opengfw_log(sample)
        self.assertFalse(parsed["blocked_by_opengfw"])
        self.assertEqual(parsed["matched_analyzers"], ["openvpn"])
        self.assertIn("openvpn(tx=5, rx=4)", opengfw_lab.summarize_classification(parsed))

        unclassified = opengfw_lab.parse_opengfw_log(
            json.dumps({"level": "debug", "msg": "new UDP stream", "id": 303, "src": "192.0.2.2:1", "dst": "192.0.2.6:2"})
        )
        self.assertEqual(opengfw_lab.summarize_classification(unclassified), "unclassified (udp)")

        quic_nul = opengfw_lab.parse_opengfw_log(
            json.dumps(
                {
                    "level": "debug",
                    "msg": "UDP stream property update",
                    "id": 404,
                    "src": "192.0.2.2:1",
                    "dst": "192.0.2.6:2",
                    "props": {"quic": {"req": {"alpn": ["l2t-quic-v1\x00\x01"]}}},
                }
            )
        )
        self.assertEqual(
            opengfw_lab.summarize_classification(quic_nul),
            "quic(sni=none, alpn=l2t-quic-v1\\x00\\x01)",
        )

    def test_markdown_report_renders_classification_and_matrix(self) -> None:
        receipt = {
            "opengfw": {"repo": opengfw_lab.OPENGFW_REPO, "commit": opengfw_lab.OPENGFW_COMMIT, "sha256": "abc"},
            "binaries": {"l2tunneld_sha256": "def"},
            "carriers": [{"id": "tcp-google", "carrier": "tcp", "sni": "google.com", "description": "test"}],
            "rulesets": [
                {"id": "observe-all", "description": "obs"},
                {"id": "block-fet", "description": "fet"},
            ],
            "cells": [
                {
                    "carrier_id": "tcp-google",
                    "ruleset_id": "observe-all",
                    "verdict": "SURVIVED",
                    "survived": True,
                    "ping_received": 5,
                    "tcp_bytes": 65536,
                    "opengfw_summary": "tls(sni=google.com); fet(yes=False, ex5=True)",
                    "opengfw": {"streams": [{"proto": "tcp"}], "matched_analyzers": ["fet", "tls"]},
                },
                {
                    "carrier_id": "tcp-google",
                    "ruleset_id": "block-fet",
                    "verdict": "SURVIVED",
                    "survived": True,
                    "ping_received": 5,
                    "tcp_bytes": 65536,
                    "opengfw_summary": "tls(sni=google.com)",
                    "opengfw": {"streams": [{"proto": "tcp"}], "matched_analyzers": ["tls"]},
                },
            ],
        }
        md = opengfw_lab.render_markdown_report(receipt)
        self.assertIn("tls(sni=google.com)", md)
        self.assertIn("**PASS**", md)
        self.assertIn("1/1 (100%)", md)

    def test_run_matrix_requires_root(self) -> None:
        with mock.patch("os.geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                opengfw_lab.run_matrix(
                    carriers=[opengfw_lab.CARRIER_BY_ID["tcp-google"]],
                    rulesets=[opengfw_lab.RULESET_BY_ID["observe-all"]],
                    lab_prefix="ogfw",
                    opengfw_bin=Path("/nonexistent/opengfw"),
                    daemon_bin=Path("/nonexistent/l2tunneld"),
                    ctl_bin=Path("/nonexistent/l2tunnelctl"),
                    output_dir=Path("/tmp/unused"),
                    state_dir=Path("/run/l2tunnel-labs"),
                    handshake_timeout=5.0,
                )


if __name__ == "__main__":
    unittest.main()
