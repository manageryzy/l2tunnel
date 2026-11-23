#!/usr/bin/env python3
"""Two pinned C KCP endpoints transporting actual Ethernet/IPv4/UDP frame bytes in virtual time."""

import argparse
from collections import Counter, deque
from hashlib import sha256
from heapq import heappop, heappush
from itertools import count
import json
from math import ceil
from pathlib import Path
from random import Random
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "simulator/src"))
from l2tunnel_sim.kcp import KCPContext, library

# Explicit modeled budget per authenticated UDP datagram, excluding FCS/preamble/IFG.
IP_UDP = 28
ROUTE_PN = 5
AUTH_TAG = 16
ETHERNET_HEADER = 14
IP_MTU = 1500
KCP_HEADER = struct.Struct("<IBBHIIII")
FRAME_LIMIT = 1514
CORPUS_SEED = 0x4C325443


def body(frame, compressed):
    if not 14 <= len(frame) <= FRAME_LIMIT:
        raise ValueError("invalid Ethernet frame length")
    if compressed:
        from lz4 import block

        encoded = block.compress(frame, store_size=False)
        if len(encoded) + 5 < len(frame) + 3:
            return b"\x0a" + struct.pack("!HH", len(encoded), len(frame)) + encoded
    return b"\x02" + struct.pack("!H", len(frame)) + frame


def decode(record):
    if len(record) < 3:
        raise ValueError("missing native body header")
    size = int.from_bytes(record[1:3], "big")
    if record[0] == 2 and 14 <= size <= FRAME_LIMIT and len(record) == 3 + size:
        return record[3:]
    if record[0] == 10 and len(record) == 5 + size:
        from lz4 import block

        original = int.from_bytes(record[3:5], "big")
        if 14 <= original <= FRAME_LIMIT and size + 2 < original:
            frame = block.decompress(record[5:], uncompressed_size=original)
            if len(frame) == original:
                return frame
    raise ValueError("invalid independent L2 body")


def ethernet_frame(index, rng):
    """Generated link-layer frames with valid IPv4 header checksums and UDP lengths."""
    sizes = (1514, 1514, 1514, 310, 1514, 1514, 1514, 60)
    size = sizes[index % len(sizes)]
    payload_len = size - 42
    ident = struct.pack("!I", index)
    content = (
        (b"fixture.L2." * ((payload_len + 10) // 11))[: payload_len - 4]
        if index % 4 == 0
        else rng.randbytes(payload_len - 4)
    )
    udp = struct.pack("!HHHH", 32000, 32001, payload_len + 8, 0) + ident + content
    ip = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            len(udp) + 20,
            index % 65536,
            0x4000,
            64,
            17,
            0,
            bytes((198, 18, 0, 1)),
            bytes((198, 18, 0, 2)),
        )
    )
    checksum = sum(struct.unpack("!10H", ip))
    checksum = (checksum & 65535) + (checksum >> 16)
    checksum = (checksum & 65535) + (checksum >> 16)
    ip[10:12] = struct.pack("!H", 65535 - checksum)
    return bytes.fromhex("0200000000020200000000010800") + bytes(ip) + udp


def corpus(offer_ms, offer_mbps):
    rng = Random(CORPUS_SEED)
    when = 0
    data = []
    while when < offer_ms * 1_000_000:
        frame = ethernet_frame(len(data), rng)
        data.append((when, frame))
        when += ceil(len(frame) * 8_000 / offer_mbps)
    return data


def frame_digest(frames):
    digest = sha256()
    for frame in frames:
        digest.update(len(frame).to_bytes(2, "big"))
        digest.update(frame)
    return digest.hexdigest()


class NativeCredit:
    """Hold the original frame size until all its C KCP segments receive positive ACKs."""

    def __init__(self, limit, mss):
        self.limit = limit
        self.mss = mss
        self.bytes = self.peak = self.next_sn = self.emitted = self.una = 0
        self.segments = {}

    def fits(self, size):
        return self.limit is None or self.bytes + size <= self.limit

    def admit(self, native_size, body_size):
        if not self.fits(native_size):
            raise ValueError("native sender credit exceeded")
        count = ceil(body_size / self.mss)
        # ikcp_send in message mode assigns decreasing frg values. ikcp_flush
        # assigns sequence numbers when it moves queued segments into snd_buf.
        frame = [native_size, count]
        for ordinal in range(count):
            length = min(self.mss, body_size - ordinal * self.mss)
            self.segments[self.next_sn] = (frame, count - 1 - ordinal, length)
            self.next_sn += 1
        self.bytes += native_size
        self.peak = max(self.peak, self.bytes)

    def check_pushes(self, payload):
        offset = 0
        while offset < len(payload):
            _, cmd, frg, _, _, sn, _, size = KCP_HEADER.unpack_from(payload, offset)
            if cmd == 81 and sn >= self.emitted:
                if sn != self.emitted or self.segments[sn][1:] != (frg, size):
                    raise RuntimeError(
                        "observed C PUSH differs from admitted frame segmentation"
                    )
                self.emitted += 1
            offset += KCP_HEADER.size + size

    def _ack(self, sn):
        entry = self.segments.pop(sn, None)
        if entry is not None:
            frame = entry[0]
            frame[1] -= 1
            if frame[1] == 0:
                self.bytes -= frame[0]

    def input_delivered_to_sender(self, payload):
        offset = 0
        while offset < len(payload):
            _, cmd, _, _, _, sn, una, size = KCP_HEADER.unpack_from(payload, offset)
            if una > self.emitted or (cmd == 82 and sn >= self.emitted):
                raise RuntimeError(
                    "C peer acknowledged a segment that was never emitted"
                )
            while self.una < una:
                self._ack(self.una)
                self.una += 1
            if cmd == 82:
                self._ack(sn)
            offset += KCP_HEADER.size + size


class Link:
    def __init__(self, mbps, seed, loss, delay_ns, queue_packets, steady_ns):
        self.rate = mbps
        self.rng = Random(seed)
        self.loss = loss
        self.delay = delay_ns
        self.limit = queue_packets
        self.queued = deque()
        self.paid = Counter()
        self.attempt = Counter()
        self.seen = set()
        self.last = 0
        self.steady_ns = steady_ns
        self.steady = Counter()

    def submit(self, now, payload):
        ip = len(payload) + IP_UDP + ROUTE_PN + AUTH_TAG
        if ip > IP_MTU:
            raise ValueError("KCP datagram exceeds outer IP MTU")
        while self.queued and self.queued[0] <= now:
            self.queued.popleft()
        l2 = ip + ETHERNET_HEADER
        self.attempt["udp_callback_packets"] += 1
        self.attempt["udp_callback_l2_bytes"] += l2
        # Track real C retransmissions even if their first emission was rejected by this queue.
        charges = Counter()
        offset = 0
        while offset < len(payload):
            _, cmd, _, _, _, sn, _, length = KCP_HEADER.unpack_from(payload, offset)
            offset += KCP_HEADER.size + length
            if cmd == 81:
                role = "repeat" if sn in self.seen else "fresh"
                self.seen.add(sn)
                charges[role + "_push_segments"] += 1
                charges[role + "_push_body_bytes"] += length
                charges[role + "_push_header_bytes"] += KCP_HEADER.size
            elif cmd in (82, 83, 84) and length == 0:
                role = {82: "ack", 83: "window_probe", 84: "window_report"}[cmd]
                charges[role + "_segments"] += 1
                charges[role + "_header_bytes"] += KCP_HEADER.size
            else:
                raise ValueError("unexpected C KCP command")
        if offset != len(payload):
            raise ValueError("KCP output is not a complete segment train")
        if len(self.queued) >= self.limit:
            self.attempt["local_queue_drop_packets"] += 1
            self.attempt["local_queue_drop_l2_bytes"] += l2
            if self.steady_ns[0] <= now < self.steady_ns[1]:
                self.steady["local_queue_drop_packets_at_submit"] += 1
            return None
        end = max(self.last, now) + ceil(l2 * 8_000 / self.rate)
        self.queued.append(end)
        self.last = end
        c = self.paid
        c.update(charges)
        c["datagrams"] += 1
        c["kcp_payload_bytes"] += len(payload)
        c["outer_ip_udp_bytes"] += IP_UDP
        c["route_and_pn_bytes"] += ROUTE_PN
        c["tag_bytes"] += AUTH_TAG
        c["ethernet_header_bytes"] += ETHERNET_HEADER
        c["ip_bytes"] += ip
        c["l2_bytes"] += l2
        self.attempt["max_serializer_delay_ns"] = max(
            self.attempt["max_serializer_delay_ns"], end - now
        )
        self.attempt["max_queue_packets"] = max(
            self.attempt["max_queue_packets"], len(self.queued)
        )
        erased = self.rng.random() < self.loss
        if self.steady_ns[0] <= end < self.steady_ns[1]:
            self.steady.update(charges)
            self.steady.update(
                datagrams=1,
                l2_bytes=l2,
                ip_bytes=ip,
                erased_datagrams=int(erased),
                erased_l2_bytes=l2 if erased else 0,
            )
        if erased:
            c["erased_datagrams"] += 1
            c["erased_l2_bytes"] += l2
            return None
        return end + self.delay


def run(
    frames,
    seed,
    mode,
    *,
    offer_ms=1000,
    drain_ms=8000,
    window=128,
    loss=0.15,
    queue_packets=256,
    warmup_ms=0,
    native_cap=None,
):
    if mode not in ("raw", "lz4") or not frames or not 0 <= warmup_ms < offer_ms:
        raise ValueError("invalid workload or mode")
    settings = dict(
        mtu=IP_MTU - IP_UDP - ROUTE_PN - AUTH_TAG,
        window=window,
        nodelay=1,
        interval=10,
        resend=2,
        nocwnd=1,
    )
    peers = [KCPContext(0x4C325443, **settings) for _ in range(2)]
    steady_ns = (warmup_ms * 1_000_000, offer_ms * 1_000_000)
    links = [
        Link(rate, seed ^ salt, loss, 35_000_000, queue_packets, steady_ns)
        for rate, salt in ((100, 0), (10, 0x9E3779B97F4A7C15))
    ]
    encoded = [body(frame, mode == "lz4") for _, frame in frames]
    scheduled = accepted = delivered = timed_bytes = 0
    accepted_at = []
    delivered_at = []
    admissions = Counter()
    arrivals = []
    ties = count()
    digest = sha256()
    now = 0
    last_input = 0
    credit = NativeCredit(native_cap, peers[0].mss)
    stages = Counter()
    cutoff_credit = None
    try:
        for ms in range(offer_ms + drain_ms + 1):
            now = ms * 1_000_000
            # The integer KCP clock advances before input, so ACK RTT observations use current time.
            # Packet delivery is quantized upward to the next tick (at most one millisecond).
            for side, peer in enumerate(peers):
                for payload in peer.update(ms):
                    if side == 0:
                        credit.check_pushes(payload)
                    ts = links[side].submit(now, payload)
                    if ts is not None:
                        heappush(arrivals, (ts, next(ties), 1 - side, payload))
            while arrivals and arrivals[0][0] <= now:
                _, _, side, payload = heappop(arrivals)
                peers[side].input(payload)
                if side == 0:
                    credit.input_delivered_to_sender(payload)
                    if len(credit.segments) != peers[0].waiting:
                        raise RuntimeError("ACK ledger differs from ikcp_waitsnd")
                last_input = now
                while (record := peers[side].receive()) is not None:
                    frame = decode(record)
                    if (
                        side != 1
                        or delivered >= accepted
                        or frame != frames[delivered][1]
                    ):
                        raise ValueError(
                            "C KCP delivered unexpected complete frame bytes or order"
                        )
                    digest.update(len(frame).to_bytes(2, "big"))
                    digest.update(frame)
                    delivered += 1
                    delivered_at.append(now)
                    if ms < offer_ms:
                        timed_bytes += len(frame)
                        phase = "warmup" if ms < warmup_ms else "steady"
                        stages[phase + "_delivered_bytes"] += len(frame)
            if ms < offer_ms:
                while scheduled < len(frames) and frames[scheduled][0] <= now:
                    scheduled += 1
                while accepted < scheduled:
                    b = encoded[accepted]
                    if not credit.fits(len(frames[accepted][1])):
                        stages["blocked_native_credit_ticks"] += 1
                        break
                    if peers[0].waiting + ceil(len(b) / peers[0].mss) > window:
                        stages["blocked_segment_window_ticks"] += 1
                        break
                    peers[0].send(b)
                    credit.admit(len(frames[accepted][1]), len(b))
                    accepted_at.append(now)
                    admissions["lz4" if b[0] == 10 else "raw"] += 1
                    accepted += 1
            elif ms == offer_ms:
                cutoff_credit = credit.bytes
            if (
                ms >= offer_ms
                and delivered == accepted
                and not arrivals
                and now - last_input >= settings["interval"] * 1_000_000
                and not any(p.waiting for p in peers)
                and all(link.last <= now for link in links)
            ):
                break
        idle_for_ack_flush = now - last_input >= settings["interval"] * 1_000_000
        expected_digest = frame_digest(frame for _, frame in frames[:accepted])
        waits = sorted((t - accepted_at[i]) / 1e6 for i, t in enumerate(delivered_at))

        def q(p, samples=waits):
            return samples[ceil(p * len(samples)) - 1] if samples else None

        steady_waits = sorted(
            (t - accepted_at[i]) / 1e6
            for i, t in enumerate(delivered_at)
            if steady_ns[0] <= accepted_at[i] < steady_ns[1]
        )
        writer_waits = sorted(
            (t - frames[i][0]) / 1e6
            for i, t in enumerate(delivered_at)
            if steady_ns[0] <= accepted_at[i] < steady_ns[1]
        )
        return dict(
            seed=seed,
            mode=mode,
            kcp=settings,
            offered_frames=len(frames),
            offered_native_bytes=sum(len(f) for _, f in frames),
            offered_sha256=frame_digest(f for _, f in frames),
            native_accepted_frames=accepted,
            native_accepted_bytes=sum(len(f) for _, f in frames[:accepted]),
            accepted_body_bytes=sum(map(len, encoded[:accepted])),
            encoded_types=dict(admissions),
            unaccepted_offer_suffix_frames=len(frames) - accepted,
            unaccepted_offer_suffix_bytes=sum(len(f) for _, f in frames[accepted:]),
            delivered_frames=delivered,
            delivered_native_bytes=sum(len(f) for _, f in frames[:delivered]),
            accepted_not_delivered=accepted - delivered,
            accepted_digest=expected_digest,
            received_digest=digest.hexdigest(),
            byteexact_delivered_prefix=True,
            fully_confirmed=(
                idle_for_ack_flush
                and credit.bytes == 0
                and delivered == accepted
                and expected_digest == digest.hexdigest()
                and not any(p.waiting for p in peers)
                and not arrivals
                and all(link.last <= now for link in links)
            ),
            waiting_for_final_ack_flush_interval=not idle_for_ack_flush,
            pending_KCP_segments=[p.waiting for p in peers],
            undelivered_wire_datagrams=len(arrivals),
            residual_serializer_ns=[max(0, link.last - now) for link in links],
            last_simulated_ms=now // 1_000_000,
            timed_native_delivery_bytes=timed_bytes,
            timed_native_mbps=timed_bytes * 8 / (1000 * offer_ms),
            warmup_ms=warmup_ms,
            steady_ms=offer_ms - warmup_ms,
            steady_native_mbps=stages["steady_delivered_bytes"]
            * 8
            / (1000 * (offer_ms - warmup_ms)),
            steady_admitted_delivered_samples=len(steady_waits),
            steady_admitted_delivery_p99_ms=q(0.99, steady_waits),
            steady_admitted_offer_to_delivery_p99_ms=q(0.99, writer_waits),
            native_sender_credit=dict(
                cap=native_cap,
                peak=credit.peak,
                at_cutoff=cutoff_credit,
                remaining=credit.bytes,
                unchecked_first_pushes=credit.next_sn - credit.emitted,
            ),
            admission_ticks_and_delivery_bytes=dict(stages),
            accepted_to_delivery_ms={"p50": q(0.5), "p99": q(0.99), "max": q(1)},
            directions=[
                {
                    "udp": dict(link.attempt),
                    "wire": dict(link.paid),
                    "steady_serializer_completed": dict(link.steady),
                }
                for link in links
            ],
        )
    finally:
        for peer in peers:
            peer.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=(11891353551447149637, 10446470503212366402),
    )
    ap.add_argument("--offer-ms", type=int, default=1000)
    ap.add_argument("--drain-ms", type=int, default=8000)
    ap.add_argument("--offer-mbps", type=float, default=70)
    ap.add_argument(
        "--warmup-ms",
        type=int,
        default=0,
        help="Initial portion of total offer time excluded from steady metrics",
    )
    ap.add_argument("--window", type=int, default=128)
    ap.add_argument(
        "--native-cap",
        type=int,
        help="Maximum original native bytes with at least one unacknowledged segment",
    )
    args = ap.parse_args()
    if (
        not 1 <= args.offer_ms <= 10000
        or not 1 <= args.drain_ms <= 30000
        or not 0 < args.offer_mbps <= 100
    ):
        ap.error("offer and drain must be finite within study bounds")
    if (
        not 0 <= args.warmup_ms < args.offer_ms
        or args.native_cap is not None
        and args.native_cap < FRAME_LIMIT
    ):
        ap.error(
            "warmup must leave measurable time and credit must permit the largest frame"
        )
    if args.output.exists():
        raise FileExistsError(args.output)
    import lz4

    frames = corpus(args.offer_ms, args.offer_mbps)
    rows = [
        run(
            frames,
            s,
            mode,
            offer_ms=args.offer_ms,
            drain_ms=args.drain_ms,
            window=args.window,
            warmup_ms=args.warmup_ms,
            native_cap=args.native_cap,
        )
        for s in args.seeds
        for mode in ("raw", "lz4")
    ]
    receipt = dict(
        source_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        command=[sys.executable, *sys.argv],
        warmup_ms=args.warmup_ms,
        steady_ms=args.offer_ms - args.warmup_ms,
        window_segments=args.window,
        native_byte_cap=args.native_cap,
        credit_scope="Full native bytes held at C message admission until all its constituent PUSH SNs are covered by UNA or ACK received at the sender. First C PUSH SN/frg/length and KCP waitsnd after each peer feedback are checked. The C receiver can hold acknowledged frames behind an older ordered hole.",
        wrapper_sha256=sha256(
            (ROOT / "simulator/src/l2tunnel_sim/kcp.py").read_bytes()
        ).hexdigest(),
        lz4_python=lz4.__version__,
        lz4_library=lz4.library_version_string(),
        upstream=library().receipt,
        offer_ms=args.offer_ms,
        offer_mbps=args.offer_mbps,
        drain_ms=args.drain_ms,
        settings=dict(
            forward_mbps=100,
            reverse_mbps=10,
            rtt_ms=70,
            erasure_each_direction=0.15,
            initial_outer_ip_mtu=IP_MTU,
            outer_IP_UDP=IP_UDP,
            route_pn=ROUTE_PN,
            tag=AUTH_TAG,
            ethernet_header=ETHERNET_HEADER,
            queue_datagrams_per_direction=256,
        ),
        scope="Offline single ordered pinned upstream KCP association, no FEC. One native body per KCP message. Generated full Ethernet/IPv4/UDP frames, open-loop native offer and bounded FIFO admission until cutoff. Tags 2/10 use existing Rust raw/independent LZ4 grammar. Actual C datagrams are serialized then erased. Authentication and carrier are byte charges without crypto, sessions, or kernel execution; the study does not run the Rust CompactRecovery or model inner TCP.",
        cases=rows,
    )
    with args.output.open("x") as f:
        json.dump(receipt, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
