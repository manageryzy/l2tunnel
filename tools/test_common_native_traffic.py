"""Unit tests for uniform testcase naming and realistic traffic generators."""
from __future__ import annotations

import socket
import threading
import time
import unittest
import zlib

from tools import common_native_c48 as c48
from tools import common_native_traffic as traffic


class UniformTestcaseNamingTest(unittest.TestCase):
    def test_format_and_parse_round_trip(self):
        tc = traffic.format_testcase_id("raw-tls-like", "swift-fec", "mixed-real", 15, 70, 4, 60)
        self.assertEqual(tc, "raw-tls-like__swift-fec__mixed-real__l15_r70_f4_t60s")
        parsed = traffic.parse_testcase_id(tc)
        self.assertEqual(
            parsed,
            {
                "carrier": "raw-tls-like",
                "protocol": "swift-fec",
                "workload": "mixed-real",
                "loss": 15,
                "rtt_ms": 70,
                "flows": 4,
                "sample_seconds": 60,
            },
        )

    def test_row_id_aliasing_and_carrier_extraction(self):
        tc = traffic.testcase_id_for_row(
            "packed-c48-near8-headroom-fixed-anchor-ack-lz4-udp",
            "bulk-random",
            15,
            70,
            1,
            30,
        )
        self.assertEqual(tc, "udp__packed-c48-headroom__bulk-random__l15_r70_f1_t30s")
        tc2 = traffic.testcase_id_for_row("rolling-short-copies-raw-tls-like", "mixed-real", 15, 70, 4, 60)
        self.assertEqual(tc2, "raw-tls-like__rolling-short-copies__mixed-real__l15_r70_f4_t60s")

    def test_rejects_malformed_ids(self):
        with self.assertRaises(ValueError):
            traffic.parse_testcase_id("swift-fec-udp")
        with self.assertRaises(ValueError):
            traffic.format_testcase_id("badcarrier", "swift-fec", "bulk-random", 15, 70, 1, 30)


class RandomStreamsTest(unittest.TestCase):
    def test_random_stream_is_deterministic_non_repeating_and_incompressible(self):
        a = traffic.RandomStream(12345)
        b = traffic.RandomStream(12345)
        c = traffic.RandomStream(99999)
        chunk1 = a.take(100_000)
        chunk2 = a.take(100_000)
        self.assertEqual(chunk1, b.take(100_000))
        self.assertNotEqual(chunk1, chunk2)
        self.assertNotEqual(chunk1, c.take(100_000))
        # High entropy: zlib should not shrink 100 KB meaningfully.
        self.assertGreater(len(zlib.compress(chunk1, level=1)), 99_000)

    def test_compressible_stream_is_deterministic_and_compressible(self):
        a = traffic.CompressibleStream(12345)
        b = traffic.CompressibleStream(12345)
        data = a.take(65_536)
        self.assertEqual(data, b.take(65_536))
        self.assertLess(len(zlib.compress(data, level=1)), 35_000)


class BulkRandomFlowTest(unittest.TestCase):
    def test_bulk_random_records_and_time_series(self):
        start = 1_000_000_000
        clock = {
            "start_ns": start,
            "measure_start_ns": start + 2_000_000_000,
            "end_ns": start + 12_000_000_000,
        }
        tx = traffic.BulkRandomFlow(0, 1, clock, rate=10_000_000, traffic_seed=42)
        rx = traffic.BulkRandomFlow(0, 1, clock, rate=10_000_000, traffic_seed=42)
        seen_payloads = set()
        for idx in range(20):
            at = clock["measure_start_ns"] + idx * 100_000_000
            pkt = tx.offer(at)
            self.assertEqual(len(pkt), c48.SIZE)
            seen_payloads.add(pkt[c48.HEADER.size :])
            tx.accepted(len(pkt))
            rx.receive(pkt, at + 5_000_000)
        self.assertEqual(len(seen_payloads), 20)
        self.assertEqual(rx.incoming, 20)
        series = rx.time_series.report()
        self.assertEqual(len(series), 2)  # 10s / 5s = 2 buckets
        self.assertEqual(series[0]["items"], 20)
        self.assertGreater(series[0]["goodput_mbit_s"], 0.0)


class MixedRealLoopbackTest(unittest.TestCase):
    def test_mixed_real_end_to_end_over_loopback_tcp(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.listen(traffic.MIXED_FLOWS)

        server_sockets: list[socket.socket] = []

        def accept_all():
            for _ in range(traffic.MIXED_FLOWS):
                conn, _ = listener.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                server_sockets.append(conn)

        acc_thread = threading.Thread(target=accept_all, daemon=True)
        acc_thread.start()

        client_sockets = []
        for _ in range(traffic.MIXED_FLOWS):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect(("127.0.0.1", port))
            client_sockets.append(s)
        acc_thread.join(timeout=5)
        listener.close()

        now = time.monotonic_ns()
        clock = {
            "start_ns": now + 50_000_000,
            "measure_start_ns": now + 250_000_000,
            "end_ns": now + 1_250_000_000,
        }
        deadline = now + 15_000_000_000
        res_client: dict = {}
        res_server: dict = {}
        errors: list[BaseException] = []

        def run_side(socks, is_init, out):
            try:
                traffic.run_mixed_real_transfer(
                    socks, is_init, clock, deadline, out, traffic_seed=7777
                )
            except BaseException as exc:
                errors.append(exc)

        t1 = threading.Thread(target=run_side, args=(client_sockets, True, res_client))
        t2 = threading.Thread(target=run_side, args=(server_sockets, False, res_server))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        for s in client_sockets + server_sockets:
            s.close()

        self.assertEqual(errors, [])
        # Exact byte & SHA-256 parity in BOTH directions across all 4 flows.
        for i in range(traffic.MIXED_FLOWS):
            cf, sf = res_client["flows"][i], res_server["flows"][i]
            self.assertEqual(cf["sent"], sf["received"])
            self.assertEqual(cf["sent_sha256"], sf["receive_sha256"] if "receive_sha256" in sf else sf["received_sha256"])
            self.assertEqual(sf["sent"], cf["received"])
            self.assertEqual(sf["sent_sha256"], cf["received_sha256"])
            self.assertGreater(cf["sent"], 0)
        # Interactive RPC and web_burst received echo RTT replies on initiator!
        init_classes = res_client["mixed_real"]["classes"]
        resp_classes = res_server["mixed_real"]["classes"]
        self.assertGreater(init_classes["interactive_rpc"]["messages_received"], 0)
        self.assertIn("rtt_ms", init_classes["interactive_rpc"])
        self.assertGreater(init_classes["web_burst"]["messages_received"], 0)
        self.assertGreater(resp_classes["vbr_video"]["messages_received"], 0)
        self.assertGreater(resp_classes["bulk_bg"]["messages_received"], 0)
        for cname in traffic.CLASS_NAMES.values():
            self.assertEqual(resp_classes[cname]["remainder_bytes"], 0)
            self.assertEqual(init_classes[cname]["remainder_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
