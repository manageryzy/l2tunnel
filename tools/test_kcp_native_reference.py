"""Unprivileged contracts and optional real-C socket-pair fixture for the KCP reference."""

import contextlib
import io
import json
import os
from pathlib import Path
from random import Random
import selectors
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

try:
    from . import kcp_native_reference as ref
except ImportError:
    import kcp_native_reference as ref


class Contracts(unittest.TestCase):
    def test_private_copy_preflight_refuses_nonexecutable(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            candidate = Path(temporary) / "endpoint"
            candidate.write_bytes(b"not executable")
            candidate.chmod(0o600)
            with self.assertRaises(PermissionError):
                ref.preflight_executable(candidate)

    def test_pin_and_geometry(self):
        self.assertEqual(
            ref.build_inputs()["upstream_commit"],
            "8004f7eba5d1bf33f0691eef5f887f2cd3140cb5",
        )
        profile = ref.plan("raw")
        self.assertEqual(profile["kcp_mtu"] + 49, profile["ip_mtu"])
        self.assertEqual(profile["application_credit"], 4 * 1024**2)
        self.assertIsNone(profile["native_fq_maxrate"])

    def test_diagnostic_separates_lost_ack_duplicate_delivery_and_refused_timeout(self):
        def push(at, outcome, reason, pn, xmit, prior=0):
            return ref.Segment(at, at + 1, outcome, reason, at, pn, 81, 0, 8192, at, 0, 0, 100, 173,
                               xmit, prior, at + 20, 20)

        first = push(10, "paid", "fresh", 1, 1)
        refused = push(30, "refused", "timeout", 2, 2, 30)
        fast = push(35, "paid", "fast", 3, 3, 50)
        first_rx = first._replace(begin_ns=17, end_ns=18, outcome="input", reason="none", xmit=0)
        repeat_rx = fast._replace(begin_ns=42, end_ns=43, outcome="input", reason="none", xmit=0)
        ack = ref.Segment(21, 22, "paid", "none", 21, 1, 82, 0, 8192, 10, 0, 1, 0, 73, 0, 0, 0, 0)
        final = ack._replace(begin_ns=50, end_ns=51, pn=2)
        local = [first, refused, fast, final._replace(begin_ns=60, end_ns=61, outcome="input")]
        peer = [first_rx, ack, repeat_rx, final]
        stats = dict(fresh_push=1, retry_push=1, ack_segments=0, window_probes=0, window_reports=0,
                     socket_datagrams=2, socket_udp_payload_bytes=290, fresh_push_bytes=100,
                     retry_push_bytes=100, local_socket_drops=1, engine_retry_callbacks=2, engine_timeout_pushes=1)
        result = ref.analyze_direction(local, peer, stats)
        self.assertEqual(result["engine_retry_callbacks"], {"fast": 1, "timeout": 1})
        self.assertEqual(result["paid_retry_payload_bytes"], {"fast": 100})
        self.assertEqual(result["received_duplicate_push_payload_bytes"], 100)
        self.assertEqual(result["retry_payload_byte_conditions"]["earliest_covering_ack_datagram_never_arrived"], 100)
        self.assertEqual(result["first_retry_after_proven_peer_arrival"]["first_covering_ack_processed_ns"], 61)
        with self.assertRaises(ValueError):
            ref.analyze_direction(local, [first_rx._replace(ts=9), ack, repeat_rx], stats)

        # The process had already read the original while the peer's KCP input
        # still overlapped the local retry. A NIC or kernel timestamp is unavailable.
        for begin, end, category in [(31, 39, "prior_peer_recv_returned_but_input_in_progress_at_retry_callback"),
                                     (38, 39, "prior_peer_recv_returned_after_retry_callback")]:
            with self.subTest(category=category):
                peer_input = first_rx._replace(begin_ns=begin, end_ns=end)
                got = ref.analyze_direction(local, [peer_input, repeat_rx, final], stats)
                self.assertEqual(got["retry_payload_byte_conditions"], {category: 100})
                self.assertIsNone(got["first_retry_after_proven_peer_arrival"])

    def test_diagnostic_time_wrap_uses_pinned_half_range_and_trace_is_opt_in(self):
        self.assertFalse(ref.plan("raw")["trace"])
        self.assertTrue(ref.plan("raw", True)["trace"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.csv"
            meta = {"kcp_trace": {"enabled": True, "capacity": ref.TRACE_LIMIT, "rows": 1}}
            header = ",".join(ref.TRACE_FIELDS)
            path.write_text(header + "\n10,11,refused,timeout,3,2,81,0,8192,3,0,0,100,173,2,4294967293,20,17\n")
            self.assertEqual(ref.read_trace(path, meta)[0].reason, "timeout")
            path.write_text(path.read_text().replace("refused,timeout", "refused,fast"))
            with self.assertRaises(ValueError):
                ref.read_trace(path, meta)

    def test_socket_bytes_and_peer_custody(self):
        node = dict.fromkeys(ref.DEBT, 0)
        node.update(
            accepted_frames=2,
            injected_frames=2,
            native_read_bytes=1600,
            native_written_bytes=1600,
            fresh_push=1,
            retry_push=1,
            ack_segments=1,
            window_probes=0,
            window_reports=0,
            fresh_push_bytes=100,
            retry_push_bytes=100,
            socket_datagrams=2,
            socket_udp_payload_bytes=314,
        )
        self.assertEqual(
            ref.paid(node), {"ip_bytes": 370, "ethernet_bytes_without_fcs": 398}
        )
        self.assertTrue(ref.confirmed({"a": node, "b": node}))
        self.assertFalse(ref.confirmed({"a": dict(node, waitsnd=1), "b": node}))
        self.assertFalse(
            ref.confirmed({"a": dict(node, native_written_bytes=1599), "b": node})
        )
        with self.assertRaises(ValueError):
            ref.paid(dict(node, socket_datagrams=3))

    @unittest.skipUnless(
        os.environ.get("L2TUNNEL_KCP_REFERENCE_BINARY"),
        "pass a source-pinned built C reference",
    )
    def test_two_real_c_endpoints_recover_loss_authenticate_and_resist_replay(self):
        binary = os.environ["L2TUNNEL_KCP_REFERENCE_BINARY"]
        with tempfile.TemporaryDirectory(dir="/tmp") as private:
            candidate = Path(private) / "endpoint"
            candidate.write_bytes(Path(binary).read_bytes())
            candidate.chmod(0o700)
            self.assertEqual(ref.preflight_executable(candidate)["exitcode"], 2)
        with (
            tempfile.TemporaryDirectory() as tmp,
            selectors.DefaultSelector() as selector,
        ):
            root = Path(tmp)
            key = root / "private"
            key.touch(mode=0o600)
            key.write_bytes(os.urandom(64))
            data = [
                bytes.fromhex("0200000000020200000000010800")
                + Random(i).randbytes(n - 14)
                for i, n in enumerate((1514, 60, 1514))
            ]
            endpoints, taps, sockets, logs = {}, {}, {}, {}
            received = {s: [] for s in "ab"}
            expected = {"a": data[::-1], "b": data}
            erased = altered = duplicate = False
            try:
                for side in "ab":
                    tap, native = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                    wire, udp = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                    with native, udp:
                        taps[side], sockets[side] = tap, wire
                        logs[side] = (root / (side + ".log")).open("wb")
                        endpoints[side] = subprocess.Popen(
                            [
                                binary,
                                side,
                                "raw",
                                key,
                                root / (side + ".json"),
                                "--unix-fixture",
                                str(native.fileno()),
                                str(udp.fileno()),
                                "--trace-kcp", root / (side + "-kcp.csv"),
                            ],
                            pass_fds=(native.fileno(), udp.fileno()),
                            stdout=logs[side],
                            stderr=subprocess.STDOUT,
                        )
                    selector.register(wire, selectors.EVENT_READ, ("wire", side))
                    selector.register(tap, selectors.EVENT_READ, ("tap", side))
                    for frame in expected["b" if side == "a" else "a"]:
                        tap.send(frame)
                deadline = time.monotonic() + 2.8
                while time.monotonic() < deadline:
                    self.assertTrue(
                        all(proc.poll() is None for proc in endpoints.values()),
                        {s: (root / (s + ".log")).read_text() for s in endpoints},
                    )
                    for item, _ in selector.select(0.01):
                        kind, side = item.data
                        packet = item.fileobj.recv(2048)
                        if kind == "tap":
                            received[side].append(packet)
                            continue
                        peer = sockets["b" if side == "a" else "a"]
                        if side == "a" and not erased:
                            erased = True
                            continue
                        if side == "a" and not altered:
                            peer.send(packet[:-1] + bytes([packet[-1] ^ 255]))
                            altered = True
                        peer.send(packet)
                        if side == "a" and not duplicate:
                            peer.send(packet)
                            duplicate = True
                    if received == expected and all(
                        (root / (s + ".json")).exists() for s in "ab"
                    ):
                        rows = {
                            s: json.loads((root / (s + ".json")).read_text())
                            for s in "ab"
                        }
                        if ref.confirmed(rows):
                            break
                else:
                    self.fail(
                        "actual C KCP fixture failed to drain within bounded time"
                    )
                self.assertEqual(
                    (rows["b"]["bad_tags_or_extent"], rows["b"]["replays"]), (1, 1)
                )
                self.assertGreater(rows["a"]["retry_push"], 0)
                for row in rows.values():
                    self.assertGreater(ref.paid(row)["ip_bytes"], 0)
                    self.assertEqual(row["local_socket_drops"], 0)
            finally:
                for proc in endpoints.values():
                    if proc.poll() is None:
                        proc.terminate()
                for proc in endpoints.values():
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                for file in [*taps.values(), *sockets.values(), *logs.values()]:
                    file.close()
            final = {side: json.loads((root / (side + ".json")).read_text()) for side in "ab"}
            trace = ref.analyze_trace_files(root, final)
            self.assertEqual(trace["status"], "complete")
            self.assertEqual(sum(trace["a"]["paid_retry_segments"].values()), final["a"]["retry_push"])
            self.assertGreater(trace["files"]["a"]["rows"], 0)
            self.assertEqual((root / "a-kcp.csv").stat().st_mode & 0o777, 0o600)



class OptionalParameters(unittest.TestCase):
    """Optional paced/stream benchmark parameters; defaults must stay the original endpoint."""

    def test_defaults_add_no_endpoint_arguments(self):
        options = ref.resolve_options()
        self.assertEqual(options, ref.DEFAULTS)
        self.assertEqual(ref.adapter_args(options, "a"), [])
        self.assertEqual(ref.adapter_args(options, "b"), [])
        profile = ref.plan("raw")
        self.assertEqual((profile["kcp_window_segments"], profile["kcp_nodelay"]), (8192, [1, 10, 2, 1]))
        self.assertEqual((profile["warmup_s"], profile["steady_s"], profile["workload"]), (2, 10, "single-flow-4m"))
        self.assertIsNone(profile["admission_pacing"])
        self.assertEqual(ref.probe_limit_args(options), [])

    def test_preset_reproduces_recorded_paced_campaign_and_explicit_values_win(self):
        options = ref.resolve_options("optimized-20261121")
        self.assertEqual(ref.adapter_args(options, "a"), [
            "--stream", "--pace-mbit", "95.0", "--pace-burst-ms", "2.0", "--pace-reserve", "queued",
            "--native-queue", "4096", "--flush-us", "1000", "--max-wait-us", "100",
            "--udp-buffer-bytes", "4194304", "--sample-ms", "1000"])
        self.assertIn("9.5", ref.adapter_args(options, "b"))
        self.assertEqual((options["warmup_s"], options["steady_s"], options["max_bytes"]), (10, 60, 1024**3))
        self.assertEqual(ref.probe_limit_args(options), [
            "--max-samples", "512", "--deadline-seconds", "180", "--max-measure-seconds", "90"])
        changed = ref.resolve_options("optimized-20261121", native_queue_frames=0, pace_reserve="fixed",
                                      window=4096, nocwnd=0, inner_rto_min_ms=1000)
        args = ref.adapter_args(changed, "a")
        self.assertNotIn("--native-queue", args)
        self.assertEqual(args[:4], ["--window", "4096", "--nocwnd", "0"])
        self.assertIn("fixed", args)
        self.assertEqual(ref.plan("lz4", options=changed)["inner_tcp_rto_min_ms"], 1000)

    def test_invalid_combinations_fail_closed(self):
        for overrides in (dict(window=64), dict(window=32768), dict(nocwnd=2), dict(native_queue_frames=70000),
                          dict(flush_interval_us=10), dict(pace_reserve="none"), dict(loss_percent=101),
                          dict(steady_s=60), dict(max_bytes=1), dict(workload="secure-forward16", steady_s=60),
                          dict(workload="secure-forward16", warmup_s=11, probe_deadline_seconds=180,
                               probe_max_measure_seconds=90, workload_seconds=230),
                          dict(unknown_option=1)):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                ref.resolve_options(**overrides)
        with self.assertRaises(ValueError):
            ref.resolve_options("no-such-preset")
        accepted = ref.resolve_options(workload="secure-forward16", warmup_s=5, steady_s=20)
        self.assertEqual(ref.probe_limit_args(accepted), [])

    def test_cli_dry_run_records_selected_parameters(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ref.main(["run", "--mode", "raw", "--build-dir", "/nonexistent", "--output",
                                       "/nonexistent/out", "--preset", "optimized-20261121",
                                       "--inner-rto-min-ms", "1000", "--loss-percent", "0"]), 0)
        request = json.loads(out.getvalue())
        self.assertEqual(request["loss_percent"], 0)
        self.assertTrue(request["kcp_stream"])
        self.assertEqual(request["admission_pacing"]["forward_mbit"], 95.0)
        self.assertEqual(request["native_queue_frames"], 4096)
        self.assertEqual(request["inner_tcp_rto_min_ms"], 1000)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            ref.main(["run", "--mode", "raw", "--build-dir", "/x", "--output", "/y", "--steady-s", "60"])

    def test_extension_debt_blocks_confirmation(self):
        node = dict.fromkeys(ref.DEBT, 0)
        node.update(accepted_frames=1, injected_frames=1, native_read_bytes=60, native_written_bytes=60)
        clean = dict(node, extensions={"native_queue_frames": 0, "stream_reassembly_bytes": 0})
        self.assertTrue(ref.confirmed({"a": clean, "b": clean}))
        for key in ref.EXTENSION_DEBT:
            dirty = dict(node, extensions={key: 1})
            self.assertFalse(ref.confirmed({"a": dirty, "b": clean}))

    def test_owned_route_rto_and_udp_counters_use_endpoint_namespaces_only(self):
        class Case:
            def __init__(self):
                self.calls, self.value = [], {}

            def command(self, role, *args):
                self.calls.append((role, args))
                return "[]" if "-j" in args else "Udp: 0"

        case = Case()
        ref.set_inner_rto_min(case, 1000)
        changes = [args for _, args in case.calls if args[:3] == ("ip", "route", "change")]
        self.assertEqual(len(changes), 2)
        self.assertTrue(all(a[-2:] == ("rto_min", "1000ms") and "tun0" in a for a in changes))
        self.assertEqual({role for role, _ in case.calls}, {"endpoint_a", "endpoint_b"})
        self.assertEqual(set(ref.udp_snmp(case)), {"a", "b"})

    @unittest.skipUnless(shutil.which("cc") and shutil.which("pkg-config"), "C toolchain unavailable")
    def test_endpoint_builds_with_the_recorded_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            try:
                ref.build(Path(tmp) / "build")
            except subprocess.CalledProcessError as error:
                self.skipTest(f"OpenSSL/liblz4 development files unavailable: {error}")
            binary = Path(tmp) / "build" / "kcp-native-reference"
            probe = subprocess.run([binary], capture_output=True, timeout=3)
            self.assertEqual(probe.returncode, 2)
            self.assertIn(b"--pace-mbit", probe.stderr)
            bad = subprocess.run([binary, "a", "raw", "k", "s", "--window", "64"], capture_output=True, timeout=3)
            self.assertEqual(bad.returncode, 2)


def exchange(binary, mode, extra, frames, seconds=6.0):
    """Run two real C endpoints over socket pairs, dropping the first A datagram once."""
    with tempfile.TemporaryDirectory() as tmp, selectors.DefaultSelector() as selector:
        root = Path(tmp)
        key = root / "private"
        key.touch(mode=0o600)
        key.write_bytes(os.urandom(64))
        expected = {"a": frames[::-1], "b": frames}
        received = {s: [] for s in "ab"}
        endpoints, taps, sockets, logs = {}, {}, {}, {}
        erased = False
        rows = None
        try:
            for side in "ab":
                tap, native = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                wire, udp = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                with native, udp:
                    taps[side], sockets[side] = tap, wire
                    logs[side] = (root / (side + ".log")).open("wb")
                    endpoints[side] = subprocess.Popen(
                        [binary, side, mode, key, root / (side + ".json"), "--unix-fixture",
                         str(native.fileno()), str(udp.fileno()), *extra],
                        pass_fds=(native.fileno(), udp.fileno()), stdout=logs[side], stderr=subprocess.STDOUT)
                selector.register(wire, selectors.EVENT_READ, ("wire", side))
                selector.register(tap, selectors.EVENT_READ, ("tap", side))
            pending = {side: list(expected["b" if side == "a" else "a"]) for side in "ab"}
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                for side, proc in endpoints.items():
                    if proc.poll() is not None:
                        raise AssertionError((root / (side + ".log")).read_text())
                for side in "ab":
                    while pending[side]:
                        try:
                            taps[side].send(pending[side][0], socket.MSG_DONTWAIT)
                        except BlockingIOError:
                            break
                        pending[side].pop(0)
                for item, _ in selector.select(0.01):
                    kind, side = item.data
                    packet = item.fileobj.recv(4096)
                    if kind == "tap":
                        received[side].append(packet)
                    elif side == "a" and not erased:
                        erased = True
                    else:
                        sockets["b" if side == "a" else "a"].send(packet)
                if received == expected and all((root / (s + ".json")).exists() for s in "ab"):
                    rows = {s: json.loads((root / (s + ".json")).read_text()) for s in "ab"}
                    if ref.confirmed(rows):
                        break
            else:
                raise AssertionError(f"fixture did not drain: {[len(received[s]) for s in 'ab']}")
        finally:
            for proc in endpoints.values():
                if proc.poll() is None:
                    proc.terminate()
            for proc in endpoints.values():
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            for file in [*taps.values(), *sockets.values(), *logs.values()]:
                file.close()
        final = {side: json.loads((root / (side + ".json")).read_text()) for side in "ab"}
        stdout = {side: (root / (side + ".log")).read_text() for side in "ab"}
        return final, stdout


@unittest.skipUnless(os.environ.get("L2TUNNEL_KCP_REFERENCE_BINARY"), "pass a source-pinned built C reference")
class OptionalParametersRealC(unittest.TestCase):
    def frames(self, count, compressible=False):
        header = bytes.fromhex("0200000000020200000000010800")
        sizes = [1514 if i % 3 else 60 + i for i in range(count)]
        return [header + (bytes(n - 14) if compressible else Random(i).randbytes(n - 14))
                for i, n in enumerate(sizes)]

    def test_stream_paced_queued_endpoint_delivers_exact_frames(self):
        binary = os.environ["L2TUNNEL_KCP_REFERENCE_BINARY"]
        extra = ["--stream", "--pace-mbit", "40", "--pace-burst-ms", "2", "--native-queue", "64",
                 "--flush-us", "1000", "--max-wait-us", "100", "--window", "256", "--nocwnd", "0",
                 "--udp-buffer-bytes", "262144", "--sample-ms", "50"]
        final, stdout = exchange(binary, "raw", extra, self.frames(48))
        for side, row in final.items():
            ext = row["extensions"]
            self.assertEqual((ext["window"], ext["nocwnd"], ext["stream"]), (256, 0, True))
            self.assertEqual((ext["native_queue_frames"], ext["stream_reassembly_bytes"]), (0, 0))
            self.assertGreater(ext["native_queue_read_frames"], 0)
            self.assertGreater(ext["explicit_flushes"], 0)
            self.assertLessEqual(ext["pace_credit"], 40e6 / 8 * 0.002 + 1)
            self.assertEqual(row["local_socket_drops"], 0)
            self.assertGreater(ref.paid(row)["ip_bytes"], 0)
            samples = [json.loads(line) for line in stdout[side].splitlines() if line.startswith("{")]
            self.assertTrue(samples and "srtt_ms" in samples[0])
        self.assertGreater(final["a"]["retry_push"], 0)
        # Stream packing: fewer fresh segments than one-per-frame-fragment message mode.
        self.assertLess(final["b"]["fresh_push"], 48 + 32)

    def test_stream_lz4_and_fixed_reservation(self):
        binary = os.environ["L2TUNNEL_KCP_REFERENCE_BINARY"]
        extra = ["--stream", "--pace-mbit", "20", "--pace-reserve", "fixed", "--max-wait-us", "200"]
        final, _ = exchange(binary, "lz4", extra, self.frames(24, compressible=True))
        self.assertGreater(final["a"]["sent_lz4_frames"], 0)
        self.assertEqual(final["a"]["extensions"]["pace_reserve"], "fixed")
        self.assertNotIn("native_queue_frames", final["a"])

    def test_message_mode_native_queue_without_pacing(self):
        binary = os.environ["L2TUNNEL_KCP_REFERENCE_BINARY"]
        final, _ = exchange(binary, "raw", ["--native-queue", "8"], self.frames(30))
        self.assertLessEqual(final["a"]["extensions"]["native_queue_peak"], 8)
        self.assertFalse(final["a"]["extensions"]["stream"])

    def test_defaults_emit_no_extension_object(self):
        binary = os.environ["L2TUNNEL_KCP_REFERENCE_BINARY"]
        final, stdout = exchange(binary, "raw", [], self.frames(6))
        self.assertNotIn("extensions", final["a"])
        self.assertEqual(stdout["a"].strip(), "Ready")


if __name__ == "__main__":
    unittest.main()
