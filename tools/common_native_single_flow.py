"""Native single-flow socket credit and steady TCP counter boundaries."""

import fcntl
from pathlib import Path
import socket
import struct
import time

RATE = 90_000_000
# Default total unconfirmed application payload credit shared by all paced flows.
# Campaigns select another value with --outstanding-credit-bytes (e.g. 512 KiB).
CREDIT = 4 * 1024 * 1024
RECORD_BYTES = 512
MAX_CREDIT = 1 << 31
TRANSFER_CAP = 160 * 1024 * 1024
SOCKET_BUFFER = 16 * 1024 * 1024
RECHECK_NS = 500_000
TCP_EXT_COUNTERS = (
    "TCPMemoryPressures", "TCPMemoryPressuresChrono", "PruneCalled", "RcvPruned", "OfoPruned",
    "TCPHystartTrainDetect", "TCPHystartTrainCwnd", "TCPHystartDelayDetect", "TCPHystartDelayCwnd",
)


def credit_error(credit, flows):
    """Return why a total credit cannot be divided over ``flows`` paced writers, or None.

    Each flow's equal share must admit one whole 512-byte record; SIOCOUTQ is an
    unsigned 32-bit kernel count, so the total stays below 2**31.
    """
    if type(credit) is not int or not 0 < credit <= MAX_CREDIT:
        return f"outstanding credit must be within 1..{MAX_CREDIT} bytes"
    if credit // flows < RECORD_BYTES:
        return f"per-flow outstanding credit must admit one {RECORD_BYTES}-byte record"
    return None


def tcp_memory_scope(path=Path("/proc/sys/net/ipv4/tcp_mem")):
    """Record the shared TCP allocation watermarks if exposed in this namespace."""
    watermarks = None
    try:
        values = [int(value) for value in path.read_text().split()]
        if len(values) == 3 and 0 <= values[0] <= values[1] <= values[2]:
            watermarks = dict(zip(("low", "pressure", "high"), values))
    except (OSError, ValueError):
        pass
    return {
        "tcp_mem_pages": watermarks,
        "tcp_mem_scope": "Shared kernel TCP allocation watermarks in pages, as visible to this endpoint.",
        "tcp_ext_scope": "Cumulative /proc/self/net/netstat counters for the probe network namespace. "
                         "HyStart Detect counts events and Cwnd accumulates the recorded congestion windows "
                         "for the corresponding ACK-train or delay detector across sockets in this namespace. "
                         "A pressure transition may be charged to a different namespace. "
                         "These counters do not sample a socket or its memory cgroup pressure state.",
    }


def tcp_memory_counters(path=Path("/proc/self/net/netstat")):
    """Read the TcpExt pair only. Keep missing or inaccessible counters observable."""
    counters = dict.fromkeys(TCP_EXT_COUNTERS)
    try:
        with path.open() as rows:
            for header in rows:
                if header.startswith("TcpExt:"):
                    names = header.split()
                    values = next(rows, "").split()
                    if len(values) == len(names) and values[0] == names[0]:
                        for key, value in zip(names[1:], values[1:]):
                            if key in counters and value.isdecimal():
                                counters[key] = int(value)
                    break
    except OSError:
        pass
    return counters


def before_syn(stream):
    """Apply the historical large pre-SYN socket buffers, checking kernel readback."""
    settings = {}
    for option, force, name in (
        (socket.SO_SNDBUF, 32, "send"),
        (socket.SO_RCVBUF, 33, "receive"),
    ):
        stream.setsockopt(socket.SOL_SOCKET, option, SOCKET_BUFFER)
        forced = stream.getsockopt(socket.SOL_SOCKET, option) != 2 * SOCKET_BUFFER
        if forced:
            stream.setsockopt(socket.SOL_SOCKET, force, SOCKET_BUFFER)
        effective = stream.getsockopt(socket.SOL_SOCKET, option)
        if effective != 2 * SOCKET_BUFFER:
            raise ValueError(f"effective pre-SYN {name} buffer is {effective}")
        settings[name] = {
            "requested": SOCKET_BUFFER,
            "effective": effective,
            "forced": forced,
        }
    return settings


def outstanding(stream):
    return struct.unpack("=I", fcntl.ioctl(stream, 0x5411, bytes(4)))[0]  # SIOCOUTQ


class Window:
    """Single writer. Linux cumulative confirmations can only reduce its queued bytes."""

    def __init__(self, stream, clock, credit=CREDIT):
        self.credit = credit
        self.stream = stream
        self.upper = outstanding(stream)
        self.peak = self.upper
        self.denied = 0
        self.blocked_until = None
        self.needed = 0
        self.targets = (clock["measure_start_ns"], clock["end_ns"])
        self.edges = []

    def allows(self, needed):
        if self.upper + needed > self.credit:
            actual = outstanding(self.stream)
            if actual > self.upper or actual > self.credit:
                raise ValueError(
                    "single-flow outstanding payload exceeded credit bound"
                )
            self.upper = actual
            if actual + needed > self.credit:
                self.denied += 1
                self.needed = needed
                self.blocked_until = time.monotonic_ns() + RECHECK_NS
                return False
        self.blocked_until = None
        return True

    def accepted(self, count):
        self.upper += count
        if self.upper > self.credit:
            raise ValueError("write crossed single-flow payload credit")
        self.peak = max(self.peak, self.upper)

    def sample_boundary(self, now):
        i = len(self.edges)
        if i < len(self.targets) and now >= self.targets[i]:
            before = time.monotonic_ns()
            info = self.stream.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
            after = time.monotonic_ns()
            (total,) = struct.unpack_from("=I", info, 100)
            self.edges.append(
                {
                    "target_ns": self.targets[i],
                    "before_ns": before,
                    "after_ns": after,
                    "total_retrans": total,
                }
            )

    def report(self):
        return {
            "outstanding_payload_cap": self.credit,
            "max_outstanding_upper_bound": self.peak,
            "credit_denials": self.denied,
            "credit_recheck_ns": RECHECK_NS,
            "steady_tcp_info_edges": self.edges,
        }
