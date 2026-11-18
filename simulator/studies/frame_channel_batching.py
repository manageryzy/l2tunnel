"""Compare bounded per-channel Ethernet packing over one lossy datagram carrier."""

from __future__ import annotations

import argparse
from collections import Counter, deque
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sys

from frame_channel_recovery import distribution, ethernet
from l2tunnel_sim.frame_channel_link import FrameChannelLink, LinkConfig
from l2tunnel_sim.frame_channels import ChannelConfig, FrameChannels


ROOT = Path(__file__).resolve().parents[2]
SIZE = 256
LANES = 16
INPUT_FRAMES = 32
RETAINED_FRAMES = 128
FLUSH_SECONDS = .0025


def encode(frames):
    if not 1 <= len(frames) <= 4 or not all(0 < len(frame) <= 65535 for frame in frames):
        raise ValueError("invalid batched Ethernet lengths")
    return (bytes([len(frames)]) + b"".join(len(frame).to_bytes(2, "big") for frame in frames)
            + b"".join(frames))


def decode(data):
    if not data or not 1 <= data[0] <= 4 or 1 + 2 * data[0] > len(data):
        raise ValueError("invalid batch count or truncated lengths")
    end = 1 + 2 * data[0]
    sizes = [int.from_bytes(data[pos:pos + 2], "big") for pos in range(1, end, 2)]
    if not all(sizes) or sum(sizes) != len(data) - end:
        raise ValueError("Ethernet lengths differ from payload")
    frames = []
    for size in sizes:
        frames.append(data[end:end + size])
        end += size
    return frames


class PackedWorkload:
    def __init__(self, maximum, seed):
        self.maximum = maximum
        self.net = FrameChannelLink(LinkConfig(service_fixed_us=20), seed)
        self.core = FrameChannels(ChannelConfig(channels=LANES, window_frames=RETAINED_FRAMES,
                                  fragment_bytes=1200, parity=False, early_request_ms=2,
                                  request_repeat_ms=80, rto_ms=180, feedback_delay_ms=1),
                                  lambda: self.net.now, self.net.at, self.transmit, self.receive)
        self.core.on_credit = self.credit
        self.input = [deque() for _ in range(LANES)]
        self.flights = [deque() for _ in range(LANES)]
        self.retained = [0] * LANES
        self.peak_retained = 0
        self.deadlines = [None] * LANES
        self.admitted = {}
        self.samples = []
        self.records = Counter()
        self.offered = self.input_drops = 0
        self.dropped_ids = []

    def transmit(self, packet, receive):
        return self.net.send(packet.reverse, packet.kind, packet.identity, packet.wire_bytes, receive)

    def credit(self, lane):
        flights = self.flights[lane]
        prefix = self.core.lanes[lane].send_prefix
        while flights and flights[0][0] < prefix:
            _, size = flights.popleft()
            self.retained[lane] -= size
        self.pump(lane)

    def offer(self, frame_id):
        self.offered += 1
        lane = frame_id % LANES
        if len(self.input[lane]) == INPUT_FRAMES:
            self.input_drops += 1
            self.dropped_ids.append(self.net.now)
        else:
            self.input[lane].append((frame_id, self.net.now))
            self.pump(lane)

    def timeout(self, lane, target):
        if self.deadlines[lane] == target:
            self.deadlines[lane] = None
            self.pump(lane)

    def pump(self, lane):
        queue = self.input[lane]
        while queue and self.retained[lane] < RETAINED_FRAMES and self.core.can_offer(lane):
            limit = min(RETAINED_FRAMES - self.retained[lane], self.maximum)
            oldest_deadline = queue[0][1] + FLUSH_SECONDS
            if len(queue) < self.maximum and self.net.now < oldest_deadline:
                if self.deadlines[lane] != oldest_deadline:
                    self.deadlines[lane] = oldest_deadline
                    self.net.at(oldest_deadline, self.timeout, lane, oldest_deadline)
                return
            self.deadlines[lane] = None
            count = min(limit, len(queue))
            batch = [queue.popleft() for _ in range(count)]
            first, _ = batch[0]
            for frame_id, arrival in batch:
                self.admitted[frame_id] = (arrival, self.net.now)
            seq = self.core.lanes[lane].send_next
            payload = encode([ethernet(frame_id, SIZE) for frame_id, _ in batch])
            if not self.core.offer(lane, first, payload):
                raise RuntimeError("admission lost after credit check")
            self.retained[lane] += count
            self.peak_retained = max(self.peak_retained, self.retained[lane])
            self.flights[lane].append((seq, count))
            self.records[count] += 1

    def receive(self, record_id, data):
        for ordinal, frame in enumerate(decode(data)):
            frame_id = int.from_bytes(frame[14:18], "big")
            if (not ordinal and frame_id != record_id) or frame != ethernet(frame_id, SIZE):
                raise RuntimeError("Ethernet payload or record identifier mismatch")
            offered, admitted = self.admitted.pop(frame_id)
            self.samples.append((self.net.now, offered, admitted))

    def counts(self):
        return dict(offered=self.offered, input_drops=self.input_drops, delivered=len(self.samples),
                    admission_queue=sum(map(len, self.input)), awaiting_delivery=len(self.admitted),
                    retained_originals=sum(self.retained), unconfirmed_records=self.core.pending_frames)


def run(maximum, seed, load, warmup, duration, drain):
    job = PackedWorkload(maximum, seed)
    interval = SIZE * 8 / (load * 1e6)

    def generate(index):
        job.offer(index)
        when = (index + 1) * interval
        if when < duration:
            job.net.at(when, generate, index + 1)

    job.net.at(0, generate, 0)
    job.net.run(warmup)
    before = [job.net.serialized_bytes(rev) for rev in (False, True)]
    job.net.run(duration)
    active = job.counts()
    wire = [job.net.serialized_bytes(rev) - initial
            for rev, initial in zip((False, True), before)]
    job.net.run(duration + drain)
    end = job.counts()
    if end["offered"] != sum(end[k] for k in ("delivered", "input_drops", "admission_queue",
                                               "awaiting_delivery")):
        raise RuntimeError("Ethernet conservation failed")
    window = duration - warmup
    cohort = [(d, o, a) for d, o, a in job.samples if warmup <= o < duration]
    delivered = sum(warmup < d <= duration for d, _, _ in job.samples)
    return dict(seed=seed, maximum=maximum, load_mbps=load, config=asdict(job.core.config),
                link_config=asdict(job.net.config), offered_frame_bytes=SIZE,
                input_bound_frames_per_lane=INPUT_FRAMES, retained_bound_frames_per_lane=RETAINED_FRAMES,
                observed_peak_retained_frames_per_lane=job.peak_retained,
                flush_ms=FLUSH_SECONDS*1000, record_count_by_batch_size=job.records,
                goodput_mbps=delivered*SIZE*8/(1e6*window),
                serialized_mbps=[n*8/(1e6*window) for n in wire],
                frame_delivery_ms=distribution([(d-o)*1000 for d,o,a in cohort]),
                input_and_pack_ms=distribution([(a-o)*1000 for d,o,a in cohort]),
                admitted_to_delivery_ms=distribution([(d-a)*1000 for d,o,a in cohort]),
                cohort_input_drops=sum(warmup <= t < duration for t in job.dropped_ids),
                end_of_traffic=active, after_drain=end, recovery=dict(job.core.metrics),
                link=job.net.report())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--seeds", type=int, nargs="+", default=[17, 29, 43])
    parser.add_argument("--loads", type=float, nargs="+", default=[2, 48])
    parser.add_argument("--warmup", type=float, default=1)
    parser.add_argument("--duration", type=float, default=4)
    parser.add_argument("--drain", type=float, default=5)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration or args.drain < 0 or min(args.loads) <= 0:
        parser.error("invalid measurement window or offered load")
    args.output.mkdir(parents=True, exist_ok=False)

    def save(name, obj):
        (args.output/name).write_text(json.dumps(obj, indent=2, allow_nan=False) + "\n")

    files = [Path(__file__), Path(__file__).with_name("frame_channel_recovery.py"),
             *(ROOT / "simulator/src/l2tunnel_sim" / f for f in ("frame_channels.py", "frame_channel_link.py"))]
    hashes = {str(p.resolve().relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in files}
    sizes = {n: dict(table_bytes=1+2*n, body_bytes=1+2*n+n*SIZE,
                     record_bytes=1+2*n+n*SIZE+30, ip_bytes=1+2*n+n*SIZE+58)
             for n in range(1,5)}
    save("manifest.json", dict(argv=sys.argv, python=sys.version, source_sha256=hashes,
                               data_byte_lengths=sizes, **{k:v for k,v in vars(args).items() if k!="output"}))
    for load in args.loads:
        for seed in args.seeds:
            for maximum in (1,4):
                result = run(maximum, seed, load, args.warmup, args.duration, args.drain)
                save(f"load{load:g}-seed{seed}-max{maximum}.json", result)
                print(load, seed, maximum, round(result["goodput_mbps"],3), flush=True)


if __name__ == "__main__":
    main()
