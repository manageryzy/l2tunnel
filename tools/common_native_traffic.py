"""Uniform testcase IDs and deterministic realistic traffic generators for native benchmarks.

Provides:
- Canonical uniform testcase naming:
    ``<carrier>__<protocol>__<workload>__l<loss>_r<rtt>_f<flows>_t<sec>s``
- ``bulk-random``: non-repeating seeded high-entropy 512-byte timed records with
  5-second steady-state time-series buckets.
- ``mixed-real``: 4 concurrent bidirectional realistic traffic classes over kernel
  TCP sockets (interactive RPC echo, bursty web/API mixed-entropy objects,
  30 fps VBR video GOP frames, and sustained high-entropy background bulk),
  with per-class latency/FCT/deadline metrics, 5-second time-series buckets,
  and full end-to-end SHA-256 verification.
"""
from __future__ import annotations

from array import array
import hashlib
import math
import random
import re
import selectors
import socket
from struct import Struct
import time

try:
    from . import common_native_c48 as c48
except ImportError:
    import common_native_c48 as c48

DEFAULT_TRAFFIC_SEED = 0x51A72026
TIME_SERIES_BUCKET_S = 5

TESTCASE_ID_RE = re.compile(
    r"^(?P<carrier>udp|raw|raw-tls-like|tls|quic)"
    r"__(?P<protocol>[a-z0-9][a-z0-9-]{0,47})"
    r"__(?P<workload>paced|bulk-random|mixed-real)"
    r"__l(?P<loss>[0-9]{1,3})_r(?P<rtt>[0-9]{1,4})_f(?P<flows>[0-9]{1,2})_t(?P<seconds>[0-9]{1,4})s$"
)

# Short canonical protocol labels for verbose manifest row stems.
PROTOCOL_ALIASES = {
    "packed-c48-near8-headroom-fixed-anchor-ack-lz4": "packed-c48-headroom",
    "packed-c48-near8-fixed-anchor-ack-lz4": "packed-c48-anchor-lz4",
}

CARRIER_SUFFIXES = ("-raw-tls-like", "-udp", "-raw", "-tls", "-quic")


def split_row_id(row_id: str) -> tuple[str, str]:
    """Return ``(carrier, canonical_protocol)`` from a manifest row ID."""
    for suffix in CARRIER_SUFFIXES:
        if row_id.endswith(suffix):
            carrier = suffix[1:]
            stem = row_id[: -len(suffix)]
            return carrier, PROTOCOL_ALIASES.get(stem, stem)
    raise ValueError(f"cannot extract carrier suffix from row ID: {row_id!r}")


def format_testcase_id(
    carrier: str,
    protocol: str,
    workload: str,
    loss: int,
    rtt_ms: int,
    flows: int,
    sample_seconds: int,
) -> str:
    """Build and validate a uniform testcase ID."""
    proto = PROTOCOL_ALIASES.get(protocol, protocol)
    tc_id = f"{carrier}__{proto}__{workload}__l{loss}_r{rtt_ms}_f{flows}_t{sample_seconds}s"
    if not TESTCASE_ID_RE.fullmatch(tc_id):
        raise ValueError(f"invalid uniform testcase ID: {tc_id!r}")
    return tc_id


def parse_testcase_id(testcase_id: str) -> dict[str, int | str]:
    """Parse a uniform testcase ID into typed fields."""
    match = TESTCASE_ID_RE.fullmatch(testcase_id)
    if not match:
        raise ValueError(f"invalid uniform testcase ID: {testcase_id!r}")
    data = match.groupdict()
    return {
        "carrier": data["carrier"],
        "protocol": data["protocol"],
        "workload": data["workload"],
        "loss": int(data["loss"]),
        "rtt_ms": int(data["rtt"]),
        "flows": int(data["flows"]),
        "sample_seconds": int(data["seconds"]),
    }


def testcase_id_for_row(
    row_id: str,
    workload: str,
    loss: int,
    rtt_ms: int,
    flows: int,
    sample_seconds: int,
) -> str:
    """Build a uniform testcase ID from a manifest row ID and run parameters."""
    carrier, protocol = split_row_id(row_id)
    return format_testcase_id(carrier, protocol, workload, loss, rtt_ms, flows, sample_seconds)


class RandomStream:
    """Deterministic, non-repeating high-entropy byte stream."""

    def __init__(self, seed: int):
        self._rng = random.Random(seed)
        self._buf = b""
        self._pos = 0

    def take(self, length: int) -> bytes:
        if length <= 0:
            return b""
        if self._pos + length <= len(self._buf):
            out = self._buf[self._pos : self._pos + length]
            self._pos += length
            return out
        # Refill a 64 KiB (or larger) chunk directly from C Mersenne Twister.
        chunks = []
        if self._pos < len(self._buf):
            chunks.append(self._buf[self._pos :])
            length -= len(self._buf) - self._pos
        chunk_size = max(65536, length)
        self._buf = self._rng.randbytes(chunk_size)
        self._pos = length
        chunks.append(self._buf[:length])
        return chunks[0] if len(chunks) == 1 else b"".join(chunks)


_JSON_TEMPLATE = (
    b'{"ts":%010d,"req":"%08x","service":"edge-api","region":"us-west-2",'
    b'"status":200,"cache":"MISS","trace":"%016x","items":[{"id":%04d,'
    b'"sku":"widget-%04d","qty":1,"price":1999,"tags":["fast","tls","net"]},'
    b'{"id":%04d,"sku":"sensor-%04d","qty":4,"price":4950}]}\n'
)


class CompressibleStream:
    """Deterministic structured JSON-like stream (~2.5x LZ4-compressible)."""

    def __init__(self, seed: int):
        self._rng = random.Random(seed ^ 0xA5A55A5A)
        self._seq = 0
        self._buf = bytearray()

    def take(self, length: int) -> bytes:
        if length <= 0:
            return b""
        while len(self._buf) < length:
            self._seq += 1
            r = self._rng
            line = _JSON_TEMPLATE % (
                1700000000 + self._seq,
                r.getrandbits(32),
                r.getrandbits(64),
                r.randrange(10000),
                r.randrange(10000),
                r.randrange(10000),
                r.randrange(10000),
            )
            self._buf.extend(line)
        out = bytes(self._buf[:length])
        del self._buf[:length]
        return out


class TimeSeriesAccumulator:
    """Collect fixed-width steady-state time-series buckets (default 5 s)."""

    def __init__(self, measure_start_ns: int, end_ns: int, bucket_seconds: int = TIME_SERIES_BUCKET_S):
        self.measure_start_ns = measure_start_ns
        self.end_ns = end_ns
        self.bucket_ns = bucket_seconds * 1_000_000_000
        span = max(0, end_ns - measure_start_ns)
        count = max(1, (span + self.bucket_ns - 1) // self.bucket_ns)
        self.bucket_seconds = bucket_seconds
        self.bytes_per_bucket = [0] * count
        self.items_per_bucket = [0] * count
        self.latencies: list[array] = [array("Q") for _ in range(count)]

    def record(self, at_ns: int, nbytes: int, latency_ns: int | None = None) -> None:
        if at_ns < self.measure_start_ns or at_ns >= self.end_ns:
            return
        idx = (at_ns - self.measure_start_ns) // self.bucket_ns
        if 0 <= idx < len(self.bytes_per_bucket):
            self.bytes_per_bucket[idx] += nbytes
            self.items_per_bucket[idx] += 1
            if latency_ns is not None and latency_ns >= 0:
                self.latencies[idx].append(latency_ns)

    def report(self) -> list[dict]:
        rows = []
        for idx, nbytes in enumerate(self.bytes_per_bucket):
            start_s = idx * self.bucket_seconds
            end_s = min((idx + 1) * self.bucket_seconds, (self.end_ns - self.measure_start_ns) / 1e9)
            dur_s = max(end_s - start_s, 1e-6)
            lat = c48.percentiles(self.latencies[idx])
            rows.append(
                {
                    "window_s": [round(start_s, 3), round(end_s, 3)],
                    "bytes": nbytes,
                    "goodput_mbit_s": round(nbytes * 8.0 / (dur_s * 1e6), 4),
                    "items": self.items_per_bucket[idx],
                    "latency_ms": lat,
                }
            )
        return rows


class BulkRandomFlow(c48.RecordFlow):
    """512-byte timed record flow carrying non-repeating high-entropy random payloads."""

    def __init__(self, identity: int, flows: int, clock: dict, rate: int | None = None, traffic_seed: int = DEFAULT_TRAFFIC_SEED):
        super().__init__(identity, flows, clock, rate)
        seed = (traffic_seed ^ ((identity + 1) * 0x9E3779B97F4A7C15)) & ((1 << 64) - 1)
        self._rand = RandomStream(seed)
        self._payload_size = c48.SIZE - c48.HEADER.size
        self.time_series = TimeSeriesAccumulator(clock["measure_start_ns"], clock["end_ns"])

    def offer(self, now: int, body: bytes = b"") -> bytes:
        del body
        if not self.pending and self.due_ns(self.outgoing) <= now < self.end:
            self.pending = c48.HEADER.pack(self.outgoing, now) + self._rand.take(self._payload_size)
        return self.pending

    def receive(self, chunk: bytes, now: int) -> None:
        data = self.remainder + chunk
        end = len(data) // c48.SIZE * c48.SIZE
        for offset in range(0, end, c48.SIZE):
            seq, offered = c48.HEADER.unpack_from(data, offset)
            scheduled = self.due_ns(self.incoming)
            if seq != self.incoming or not scheduled <= offered < self.end or offered > now:
                raise ValueError("invalid sequence or timestamp in bulk-random stream")
            delay = now - offered
            self.delivery.append(delay)
            self.scheduled_delivery.append(now - scheduled)
            self.time_series.record(now, c48.SIZE, delay)
            self.incoming += 1
        self.remainder = data[end:]


# ---------------------------------------------------------------------------
# Realistic mixed traffic workload (4 concurrent bidirectional classes)
# ---------------------------------------------------------------------------

MIXED_FLOWS = 4
MIXED_MAGIC = b"L2MT"
MIXED_HEADER = Struct("!4sBBHIIQ")  # 24 bytes: magic, class_id, flags, reserved, seq, payload_len, ts_ns
MIXED_HEADER_BYTES = MIXED_HEADER.size

CLASS_INTERACTIVE_RPC = 0
CLASS_WEB_BURST = 1
CLASS_VBR_VIDEO = 2
CLASS_BULK_BG = 3

CLASS_NAMES = {
    CLASS_INTERACTIVE_RPC: "interactive_rpc",
    CLASS_WEB_BURST: "web_burst",
    CLASS_VBR_VIDEO: "vbr_video",
    CLASS_BULK_BG: "bulk_bg",
}

FLAG_ONEWAY = 0
FLAG_ECHO_REQ = 1
FLAG_ECHO_REPLY = 2

MAX_MIXED_PAYLOAD = 256 * 1024  # 256 KiB per application message


class _MixedSenderFlow:
    """Produces realistic traffic frames for one class on one TCP socket."""

    def __init__(self, flow_id: int, clock: dict, traffic_seed: int):
        self.flow_id = flow_id
        self.class_id = flow_id
        self.start_ns = clock["start_ns"]
        self.measure_start_ns = clock["measure_start_ns"]
        self.end_ns = clock["end_ns"]
        base_seed = (traffic_seed ^ ((flow_id + 17) * 0x9E3779B97F4A7C15)) & ((1 << 64) - 1)
        self._rng = random.Random(base_seed)
        self._rand = RandomStream(base_seed ^ 0x1111_2222_3333_4444)
        self._comp = CompressibleStream(base_seed ^ 0x5555_6666_7777_8888)
        self.seq = 0
        self.pending = bytearray()
        self.pending_offset = 0
        self.next_due_ns = self.start_ns + flow_id * 2_000_000  # small stagger
        self.messages_sent = 0
        self.payload_bytes_sent = 0
        self.compressible_bytes_sent = 0
        self.high_entropy_bytes_sent = 0

    def has_pending(self) -> bool:
        return self.pending_offset < len(self.pending)

    def _schedule_next_and_build(self, now: int) -> tuple[int, bytes, bool]:
        """Return ``(flags, payload, is_compressible)`` and advance ``self.next_due_ns``."""
        r = self._rng
        if self.class_id == CLASS_INTERACTIVE_RPC:
            # Poisson arrivals (~25 ms mean, clamped 5..120 ms), small RPC payloads 64..1400 B.
            interval_ms = min(120.0, max(5.0, -25.0 * math.log(max(1e-9, r.random()))))
            self.next_due_ns = max(now, self.next_due_ns) + int(interval_ms * 1_000_000)
            # Log-normal-like small RPC size
            size = int(min(1400, max(64, math.exp(r.gauss(5.3, 0.7)))))
            return FLAG_ECHO_REQ, self._comp.take(size), True

        if self.class_id == CLASS_WEB_BURST:
            # Bursty web/API fetches: heavy-tail size + 40..300 ms think time.
            think_ms = r.uniform(40.0, 300.0)
            self.next_due_ns = max(now, self.next_due_ns) + int(think_ms * 1_000_000)
            u = r.random()
            if u < 0.50:
                size = r.randint(2048, 16384)
                return FLAG_ECHO_REQ, self._comp.take(size), True
            if u < 0.85:
                size = r.randint(16384, 65536)
                half = size // 2
                return FLAG_ECHO_REQ, self._comp.take(half) + self._rand.take(size - half), False
            size = r.randint(65536, 196608)
            return FLAG_ECHO_REQ, self._rand.take(size), False

        if self.class_id == CLASS_VBR_VIDEO:
            # 30 fps (33.333 ms cadence), 30-frame GOP: 1 I-frame + 29 P-frames.
            frame_idx = self.seq
            self.next_due_ns = self.start_ns + int((frame_idx + 1) * (1_000_000_000 / 30.0))
            if frame_idx % 30 == 0:
                size = r.randint(45000, 78000)
            else:
                size = r.randint(7000, 20000)
            return FLAG_ONEWAY, self._rand.take(size), False

        # CLASS_BULK_BG: sustained 16 KiB high-entropy random chunks paced at up to 90 Mbit/s.
        chunk_size = 16384
        # 16384 bytes @ 90 Mbit/s = 1.456 ms per chunk
        self.next_due_ns = max(now, self.next_due_ns + 1_456_355)
        return FLAG_ONEWAY, self._rand.take(chunk_size), False

    def offer(self, now: int) -> memoryview:
        if not self.has_pending() and self.next_due_ns <= now < self.end_ns:
            flags, payload, is_comp = self._schedule_next_and_build(now)
            hdr = MIXED_HEADER.pack(MIXED_MAGIC, self.class_id, flags, 0, self.seq, len(payload), now)
            self.pending = bytearray(hdr)
            self.pending.extend(payload)
            self.pending_offset = 0
            self.seq += 1
            self.messages_sent += 1
            self.payload_bytes_sent += len(payload)
            if is_comp:
                self.compressible_bytes_sent += len(payload)
            else:
                self.high_entropy_bytes_sent += len(payload)
        if self.has_pending():
            return memoryview(self.pending)[self.pending_offset :]
        return memoryview(b"")

    def accepted(self, count: int) -> None:
        self.pending_offset += count
        if self.pending_offset >= len(self.pending):
            self.pending.clear()
            self.pending_offset = 0


class _MixedReceiverFlow:
    """Parses binary messages, records per-class latency/time-series, and queues echo replies."""

    def __init__(self, flow_id: int, clock: dict, traffic_seed: int, is_responder: bool):
        self.flow_id = flow_id
        self.class_id = flow_id
        self.measure_start_ns = clock["measure_start_ns"]
        self.end_ns = clock["end_ns"]
        self.is_responder = is_responder
        self._buf = bytearray()
        self._reply_rng = random.Random((traffic_seed ^ (flow_id + 991)) & ((1 << 64) - 1))
        self._reply_comp = CompressibleStream((traffic_seed ^ (flow_id + 1993)) & ((1 << 64) - 1))
        self.expected_seq = 0
        self.messages_received = 0
        self.payload_bytes_received = 0
        self.oneway_latency_ns = array("Q")
        self.steady_oneway_latency_ns = array("Q")
        self.rtt_latency_ns = array("Q")
        self.steady_rtt_latency_ns = array("Q")
        self.deadline_miss_100ms = 0
        self.deadline_miss_250ms = 0
        self.steady_messages = 0
        self.time_series = TimeSeriesAccumulator(clock["measure_start_ns"], clock["end_ns"])
        self.reply_queue = bytearray()
        self.reply_offset = 0

    def has_reply_pending(self) -> bool:
        return self.reply_offset < len(self.reply_queue)

    def reply_view(self) -> memoryview:
        if self.has_reply_pending():
            return memoryview(self.reply_queue)[self.reply_offset :]
        return memoryview(b"")

    def reply_accepted(self, count: int) -> None:
        self.reply_offset += count
        if self.reply_offset >= len(self.reply_queue):
            self.reply_queue.clear()
            self.reply_offset = 0

    def receive(self, chunk: bytes, now: int) -> None:
        self._buf.extend(chunk)
        pos = 0
        buf_len = len(self._buf)
        while buf_len - pos >= MIXED_HEADER_BYTES:
            magic, class_id, flags, reserved, seq, plen, ts_ns = MIXED_HEADER.unpack_from(self._buf, pos)
            if magic != MIXED_MAGIC or class_id != self.class_id or reserved != 0 or plen > MAX_MIXED_PAYLOAD:
                raise ValueError(f"corrupt mixed-real frame header on flow {self.flow_id}")
            total = MIXED_HEADER_BYTES + plen
            if buf_len - pos < total:
                break
            pos += total
            if seq != self.expected_seq:
                raise ValueError(f"out-of-order mixed-real seq on flow {self.flow_id}: got {seq}, want {self.expected_seq}")
            self.expected_seq += 1
            self.messages_received += 1
            self.payload_bytes_received += plen
            elapsed = max(0, now - ts_ns)
            in_steady = self.measure_start_ns <= now < self.end_ns
            if flags == FLAG_ECHO_REPLY:
                # Initiator received echo reply: elapsed is full application RTT!
                self.rtt_latency_ns.append(elapsed)
                if in_steady:
                    self.steady_rtt_latency_ns.append(elapsed)
                    self.steady_messages += 1
                self.time_series.record(now, total, elapsed)
            else:
                self.oneway_latency_ns.append(elapsed)
                if in_steady:
                    self.steady_oneway_latency_ns.append(elapsed)
                    self.steady_messages += 1
                    if elapsed > 100_000_000:
                        self.deadline_miss_100ms += 1
                    if elapsed > 250_000_000:
                        self.deadline_miss_250ms += 1
                self.time_series.record(now, total, elapsed)
                if self.is_responder and flags == FLAG_ECHO_REQ:
                    reply_len = (
                        self._reply_rng.randint(64, 384)
                        if self.class_id == CLASS_INTERACTIVE_RPC
                        else 64
                    )
                    reply_hdr = MIXED_HEADER.pack(
                        MIXED_MAGIC, self.class_id, FLAG_ECHO_REPLY, 0, seq, reply_len, ts_ns
                    )
                    self.reply_queue.extend(reply_hdr)
                    self.reply_queue.extend(self._reply_comp.take(reply_len))
        if pos:
            del self._buf[:pos]

    def remainder_bytes(self) -> int:
        return len(self._buf)


def run_mixed_real_transfer(
    streams: list[socket.socket],
    is_initiator: bool,
    clock: dict,
    deadline_ns: int,
    result: dict,
    *,
    traffic_seed: int = DEFAULT_TRAFFIC_SEED,
    credit: int = 4 * 1024 * 1024,
    single_module=None,
    tcp_info_fn=None,
    max_samples: int = 240,
    max_bytes_per_flow: int = 1024 * 1024 * 1024,
) -> None:
    """Execute the 4-class bidirectional realistic traffic workload over 4 TCP sockets."""
    if len(streams) != MIXED_FLOWS:
        raise ValueError(f"mixed-real workload requires exactly {MIXED_FLOWS} TCP flows")
    states = [
        dict(
            flow_id=i,
            sent=0,
            received=0,
            warmup=0,
            measured=0,
            postwindow=0,
            write_closed=False,
            eof=False,
            write_closed_ns=None,
            peer_eof_ns=None,
            bound_exhausted=False,
            send_hash=hashlib.sha256(),
            receive_hash=hashlib.sha256(),
        )
        for i in range(MIXED_FLOWS)
    ]
    result["clock"], result["samples"] = clock, []
    result["workload"] = "mixed-real"
    result["traffic_seed"] = traffic_seed
    start, measured, end = clock["start_ns"], clock["measure_start_ns"], clock["end_ns"]

    # Apply outstanding credit cap on the background bulk socket (Flow 3) if single_module is supplied.
    windows = (
        [single_module.Window(stream, clock, credit // MIXED_FLOWS) for stream in streams]
        if single_module is not None
        else []
    )
    if single_module is not None:
        result["tcp_memory_scope"] = single_module.tcp_memory_scope()

    senders = [_MixedSenderFlow(i, clock, traffic_seed) for i in range(MIXED_FLOWS)] if is_initiator else []
    receivers = [_MixedReceiverFlow(i, clock, traffic_seed, is_responder=not is_initiator) for i in range(MIXED_FLOWS)]

    next_sample = start
    import resource

    with selectors.DefaultSelector() as poll:
        for idx, stream in enumerate(streams):
            stream.setblocking(False)
            poll.register(stream, selectors.EVENT_READ, idx)
        try:
            while not all(st["eof"] and st["write_closed"] for st in states):
                now = time.monotonic_ns()
                for window in windows:
                    window.sample_boundary(now)
                if now >= deadline_ns:
                    raise TimeoutError("original mixed-real TCP workload deadline exhausted")
                if now < start:
                    time.sleep(min((start - now) / 1e9, 0.01))
                    continue

                if now >= next_sample and len(result["samples"]) < max_samples:
                    usage = resource.getrusage(resource.RUSAGE_SELF)
                    sample = {
                        "at_ns": now,
                        "user_seconds": usage.ru_utime,
                        "system_seconds": usage.ru_stime,
                        "maxrss_kib": usage.ru_maxrss,
                    }
                    if tcp_info_fn is not None:
                        sample["flows"] = [tcp_info_fn(stream) for stream in streams]
                    if single_module is not None:
                        sample["tcp_ext"] = single_module.tcp_memory_counters()
                    result["samples"].append(sample)
                    next_sample = now + 500_000_000

                # Update write readiness and half-close completed streams.
                next_wake_ns = end
                for idx, (stream, st) in enumerate(zip(streams, states)):
                    if is_initiator:
                        sflow = senders[idx]
                        want_write = False
                        if not st["write_closed"]:
                            if now >= end and not sflow.has_pending():
                                st["bound_exhausted"] = st["sent"] >= max_bytes_per_flow and now < end
                                stream.shutdown(socket.SHUT_WR)
                                st["write_closed"] = True
                                st["write_closed_ns"] = time.monotonic_ns()
                            elif st["sent"] >= max_bytes_per_flow:
                                st["bound_exhausted"] = now < end
                                stream.shutdown(socket.SHUT_WR)
                                st["write_closed"] = True
                                st["write_closed_ns"] = time.monotonic_ns()
                            else:
                                view = sflow.offer(now)
                                view_len = len(view)
                                view.release()
                                if view_len > 0:
                                    if windows and idx == CLASS_BULK_BG:
                                        w = windows[idx]
                                        if w.blocked_until is None or now >= w.blocked_until:
                                            if w.allows(min(view_len, 16384)):
                                                want_write = True
                                            elif w.blocked_until is not None:
                                                next_wake_ns = min(next_wake_ns, w.blocked_until)
                                        else:
                                            next_wake_ns = min(next_wake_ns, w.blocked_until)
                                    else:
                                        want_write = True
                                else:
                                    next_wake_ns = min(next_wake_ns, sflow.next_due_ns)
                    else:
                        rflow = receivers[idx]
                        want_write = False
                        if not st["write_closed"]:
                            if rflow.has_reply_pending():
                                want_write = True
                            elif st["eof"]:
                                stream.shutdown(socket.SHUT_WR)
                                st["write_closed"] = True
                                st["write_closed_ns"] = time.monotonic_ns()

                    if st["eof"] and st["write_closed"]:
                        if stream.fileno() in poll.get_map():
                            poll.unregister(stream)
                    else:
                        mask = (selectors.EVENT_READ if not st["eof"] else 0) | (
                            selectors.EVENT_WRITE if want_write else 0
                        )
                        if mask:
                            poll.modify(stream, mask, idx)

                timeout = min(0.005, max(0.0005, (next_wake_ns - now) / 1e9), max(0.0, (deadline_ns - now) / 1e9))
                for key, events in poll.select(timeout):
                    idx = key.data
                    stream = key.fileobj
                    st = states[idx]
                    rflow = receivers[idx]
                    if events & selectors.EVENT_READ and not st["eof"]:
                        try:
                            chunk = stream.recv(65536)
                        except BlockingIOError:
                            chunk = None
                        at = time.monotonic_ns()
                        if chunk == b"":
                            st["eof"] = True
                            st["peer_eof_ns"] = at
                        elif chunk:
                            st["received"] += len(chunk)
                            if st["received"] > max_bytes_per_flow:
                                raise ValueError("peer exceeded per-flow byte cap in mixed-real")
                            st["receive_hash"].update(chunk)
                            rflow.receive(chunk, at)
                            bucket = "warmup" if at < measured else "measured" if at < end else "postwindow"
                            st[bucket] += len(chunk)

                    if events & selectors.EVENT_WRITE and not st["write_closed"]:
                        if is_initiator:
                            sflow = senders[idx]
                            view = sflow.offer(time.monotonic_ns())
                            if len(view) > 0:
                                to_send = view[: min(len(view), max_bytes_per_flow - st["sent"])]
                                if windows and idx == CLASS_BULK_BG:
                                    avail = max(0, windows[idx].credit - windows[idx].upper)
                                    to_send = to_send[:avail]
                                if len(to_send) > 0:
                                    try:
                                        sent = stream.send(to_send)
                                    except BlockingIOError:
                                        sent = 0
                                    if sent:
                                        st["send_hash"].update(to_send[:sent])
                                        st["sent"] += sent
                                        if windows and idx == CLASS_BULK_BG:
                                            windows[idx].accepted(sent)
                                    to_send.release()
                                    view.release()
                                    if sent:
                                        sflow.accepted(sent)
                                else:
                                    to_send.release()
                                    view.release()
                            else:
                                view.release()
                        else:
                            view = rflow.reply_view()
                            if len(view) > 0:
                                try:
                                    sent = stream.send(view)
                                except BlockingIOError:
                                    sent = 0
                                if sent:
                                    st["send_hash"].update(view[:sent])
                                    st["sent"] += sent
                                view.release()
                                if sent:
                                    rflow.reply_accepted(sent)
                            else:
                                view.release()
        finally:
            result["flows"] = [
                {
                    **{k: v for k, v in st.items() if not k.endswith("_hash")},
                    "sent_sha256": st["send_hash"].hexdigest(),
                    "received_sha256": st["receive_hash"].hexdigest(),
                }
                for st in states
            ]
            result["completed_ns"] = time.monotonic_ns()
            for window in windows:
                window.sample_boundary(time.monotonic_ns())
            if windows:
                result["flow_credit"] = [window.report() for window in windows]

            sample_s = max((end - measured) / 1e9, 1e-6)
            classes = {}
            for i in range(MIXED_FLOWS):
                cname = CLASS_NAMES[i]
                rflow = receivers[i]
                entry = {
                    "flow_id": i,
                    "class": cname,
                    "messages_received": rflow.messages_received,
                    "steady_messages": rflow.steady_messages,
                    "payload_bytes_received": rflow.payload_bytes_received,
                    "remainder_bytes": rflow.remainder_bytes(),
                    "measured_bytes": states[i]["measured"],
                    "goodput_mbit_s": round(states[i]["measured"] * 8.0 / (sample_s * 1e6), 4),
                    "time_series": rflow.time_series.report(),
                }
                if is_initiator:
                    sflow = senders[i]
                    entry.update(
                        messages_sent=sflow.messages_sent,
                        payload_bytes_sent=sflow.payload_bytes_sent,
                        compressible_bytes_sent=sflow.compressible_bytes_sent,
                        high_entropy_bytes_sent=sflow.high_entropy_bytes_sent,
                    )
                    if rflow.rtt_latency_ns:
                        entry["rtt_ms"] = c48.percentiles(rflow.rtt_latency_ns)
                        entry["steady_rtt_ms"] = c48.percentiles(rflow.steady_rtt_latency_ns)
                else:
                    entry["oneway_latency_ms"] = c48.percentiles(rflow.oneway_latency_ns)
                    entry["steady_oneway_latency_ms"] = c48.percentiles(rflow.steady_oneway_latency_ns)
                    if i == CLASS_VBR_VIDEO:
                        denom = max(1, rflow.steady_messages)
                        entry["deadline_miss_100ms"] = rflow.deadline_miss_100ms
                        entry["deadline_miss_250ms"] = rflow.deadline_miss_250ms
                        entry["deadline_miss_100ms_pct"] = round(100.0 * rflow.deadline_miss_100ms / denom, 3)
                        entry["deadline_miss_250ms_pct"] = round(100.0 * rflow.deadline_miss_250ms / denom, 3)
                classes[cname] = entry
            result["mixed_real"] = {
                "role": "initiator" if is_initiator else "responder",
                "traffic_seed": traffic_seed,
                "sample_seconds": sample_s,
                "bucket_seconds": TIME_SERIES_BUCKET_S,
                "classes": classes,
            }
