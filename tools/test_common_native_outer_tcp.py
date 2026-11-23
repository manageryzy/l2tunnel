import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from tools import common_native_outer_tcp as outer

A, B = outer.DEFAULT_A, outer.DEFAULT_B


def frame(source, destination, seq, flags=0x10, payload=0, ethernet=True):
    tcp = struct.pack("!HHIIBBHHH", source[1], destination[1], seq, 0, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + payload, 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(source[0]), socket.inet_aton(destination[0]))
    header = ip + tcp
    if ethernet:
        header = b"\x00" * 12 + b"\x08\x00" + header
    return header, len(header) + payload


def pcap(records, link=1, nanoseconds=True):
    """records: (wall_ns, header bytes, wire length); headers are snapped like snaplen 96."""
    magic = b"\x4d\x3c\xb2\xa1" if nanoseconds else b"\xd4\xc3\xb2\xa1"
    value = bytearray(magic + struct.pack("<HHIIII", 2, 4, 0, 0, 96, link))
    for at, header, wire in records:
        fraction = at % 1_000_000_000 if nanoseconds else at % 1_000_000_000 // 1000
        value += struct.pack("<IIII", at // 1_000_000_000, fraction, len(header), wire) + header
    return bytes(value)


class OuterTcpTests(unittest.TestCase):
    def test_sequence_wrap_gap_backward_and_rst_per_direction(self):
        base = outer.SEQ_SPACE - 3000
        records = []
        t = 1_000_000_000
        for seq, flags, payload in ((base, 0x18, 1000), (base + 1000, 0x18, 1000),
                                    ((base + 2000) % outer.SEQ_SPACE, 0x18, 1000),  # 2**32 - 1000
                                    ((base + 3000) % outer.SEQ_SPACE, 0x18, 1000),  # raw wrap to 0
                                    (3000, 0x18, 500),                                  # 2000-byte gap
                                    (500, 0x18, 1000),                                  # retransmission
                                    (3500, 0x14, 0)):                                   # RST+ACK
            records.append((t, *frame(A, B, seq, flags, payload)))
            t += 1000
        records.append((t, *frame(B, A, 77, 0x10, 0)))
        records.append((t + 1, *frame(B, A, 77, 0x04, 0)))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "outer-tcp-headers.pcap"
            path.write_bytes(pcap(records))
            result = outer.analyze(path)
        forward = result["sequence"]["a_to_b"]
        self.assertEqual(result["packets"], 9)
        self.assertEqual(forward["first_seq"], base)
        self.assertEqual(forward["last_seq"], 3500)
        self.assertEqual(forward["raw_wraps"], 1)
        self.assertEqual(forward["max_relative_end"], 6500)
        self.assertEqual(forward["remaining_relative_space_to_2_32"], outer.SEQ_SPACE - 6500)
        self.assertEqual(forward["remaining_raw_space_from_first_to_2_32"], 3000)
        self.assertEqual((forward["forward_gaps"], forward["forward_gap_bytes"]), (1, 2000))
        self.assertEqual(forward["gap_examples"][0]["expected_relative_seq"], 4000)
        self.assertEqual(forward["backward_steps"], 1)
        self.assertEqual(forward["segments_below_highest_end"], 1)
        self.assertEqual(forward["rst"], {"rst": 1, "rst_with_ack": 1, "rst_with_payload": 0})
        reverse = result["sequence"]["b_to_a"]
        self.assertEqual((reverse["first_seq"], reverse["raw_wraps"], reverse["rst"]["rst"]), (77, 0, 1))
        self.assertEqual(result["counts"]["all"]["a_to_b"]["tcp_payload_bytes"], 5500)
        self.assertEqual(result["counts"]["all"]["b_to_a"]["pure_ack_no_payload"], 1)
        self.assertNotIn("steady", result["counts"])

    def test_case_mode_intervals_counters_and_cli_output(self):
        anchor = {"monotonic_before_ns": 1000, "wall_ns": 10_000_001_000, "monotonic_after_ns": 1000}
        clock = {"start_ns": 0, "measure_start_ns": 2_000_000_000, "end_ns": 3_000_000_000}
        ready = 11_000_000_000
        times = (10_500_000_000, 11_500_000_000, 12_500_000_000, 13_500_000_000)
        with tempfile.TemporaryDirectory() as d:
            case = Path(d) / "row"
            (case / "forward").mkdir(parents=True)
            (case / "forward" / "clock.json").write_text(json.dumps(clock))
            (case / "result.json").write_text(json.dumps({
                "status": "passed", "both_forwarding_observed_wall_ns": ready,
                "rst_rule_counters_before_transfer": {"a": "x"},
                "phases": [{"status": "passed", "clock_anchor": anchor}]}))
            records = [(at, *frame(A, B, 100 + 10 * i, 0x18, 10)) for i, at in enumerate(times)]
            (case / "outer-tcp-headers.pcap").write_bytes(pcap(records))
            (case / "outer-tcp-headers.log").write_text(
                "listening on a0\n4 packets captured\n4 packets received by filter\n0 packets dropped by kernel\n")
            output = Path(d) / "summary.json"
            self.assertEqual(outer.main([str(case), "--output", str(output)]), 0)
            value = json.loads(output.read_text())
            self.assertEqual([value["counts"][p]["a_to_b"]["packets"] for p in outer.PERIODS], [1, 1, 1, 1])
            self.assertEqual(value["steady_wall_ns"], [12_000_000_000, 13_000_000_000])
            self.assertEqual(value["capture_counters"]["captured"], 4)
            self.assertEqual(value["rst_rule_counters_before_transfer"], {"a": "x"})
            self.assertEqual(value["sequence"]["a_to_b"]["forward_gaps"], 0)
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                outer.main([str(case), "--output", str(output)])
            (case / "outer-tcp-headers.log").write_text("3 packets captured\n0 packets dropped by kernel\n")
            with self.assertRaisesRegex(ValueError, "record count"):
                outer.summarize(case, log=case / "outer-tcp-headers.log")

    def test_capture_only_raw_ip_microsecond_and_custom_tuple(self):
        a, b = ("10.0.0.1", 5000), ("10.0.0.2", 6000)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "x.pcap"
            path.write_bytes(pcap([(2_000_000_000, *frame(a, b, 5, 0x02, 0, ethernet=False))], link=101, nanoseconds=False))
            with redirect_stdout(io.StringIO()) as stream:
                outer.main(["--pcap", str(path), "--a-endpoint", "10.0.0.1:5000", "--b-endpoint", "10.0.0.2:6000"])
            value = json.loads(stream.getvalue())
            self.assertEqual(value["counts"]["all"]["a_to_b"]["syn"], 1)
            self.assertEqual(value["sequence"]["a_to_b"]["max_relative_end"], 1)
            with self.assertRaisesRegex(ValueError, "outside the outer tuple"):
                outer.analyze(path)

    def test_truncated_or_foreign_records_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.pcap"
            header, wire = frame(A, B, 1)
            path.write_bytes(pcap([(1, header, wire)])[:-4])
            with self.assertRaises(ValueError):
                outer.analyze(path)
            path.write_bytes(b"\x00" * 24)
            with self.assertRaisesRegex(ValueError, "classic pcap"):
                outer.analyze(path)


if __name__ == "__main__":
    unittest.main()
