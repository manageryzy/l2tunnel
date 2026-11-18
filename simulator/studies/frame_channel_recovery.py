"""Run paired causal fragment-recovery experiments on one asymmetric carrier."""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from math import ceil
from pathlib import Path
from struct import Struct

from l2tunnel_sim.frame_channel_link import FrameChannelLink, LinkConfig
from l2tunnel_sim.frame_channels import ChannelConfig, FrameChannels


ROOT = Path(__file__).resolve().parents[2]
STRIPE = Struct("!IHH")
FRAME_HEADER = bytes.fromhex("02000000000202000000000188b5")
PAD = bytes(range(251)) * 6


def ethernet(frame_id, size):
    return FRAME_HEADER + frame_id.to_bytes(4, "big") + PAD[:size - 18]


@dataclass(frozen=True)
class Profile:
    name: str
    channels: int = 16
    early_ms: float | None = 2
    repeat_ms: float = 80
    parity: bool = False
    stripes: int = 1
    service_us: float = 20
    window_per_lane: int = 32


BASE = Profile("lanes")
PROFILES = (
    replace(BASE, name="shared", channels=1, window_per_lane=512),
    BASE,
    replace(BASE, name="lanes-timeout", early_ms=None),
    replace(BASE, name="lanes-xor", parity=True),
    replace(BASE, name="striped", stripes=2, window_per_lane=64),
    replace(BASE, name="lanes-zero-cpu", service_us=0),
    replace(BASE, name="lanes-slow-cpu", service_us=180),
    replace(BASE, name="lanes-long-repeat", repeat_ms=180),
    replace(BASE, name="lanes-window64", window_per_lane=64),
)


def distribution(samples):
    ordered = sorted(samples)
    return {
        "n": len(ordered),
        "mean": sum(ordered) / len(ordered) if ordered else None,
        "p99": ordered[ceil(.99 * len(ordered)) - 1] if ordered else None,
        "max": ordered[-1] if ordered else None,
    }


class Study:
    def __init__(self, profile, seed, forced_loss=None, trace=False):
        self.profile = profile
        self.link = FrameChannelLink(LinkConfig(
            outer_bytes=28, service_fixed_us=profile.service_us,
            service_work_ns_per_byte=2 if profile.service_us else 0,
        ), seed, forced_loss)
        self.config = ChannelConfig(
            channels=profile.channels, window_frames=profile.window_per_lane,
            fragment_bytes=720, parity=profile.parity, early_request_ms=profile.early_ms,
            request_repeat_ms=profile.repeat_ms, rto_ms=180, feedback_delay_ms=1,
        )
        self.queues = [deque() for _ in range(16)]
        self.offered = self.dropped = self.admitted = self.delivered = 0
        self.frame_state = {}
        self.partial = {}
        self.times = []
        self.gaps = {}
        self.request_delays = []
        self.gap_count = 0
        self.trace = [] if trace else None
        self.next_flow = 0
        self.core = FrameChannels(self.config, lambda: self.link.now, self.link.at,
                                  self.transmit, self.receive, self.observe)
        self.core.on_credit = self.credit
        self.pump_pending = False

    def transmit(self, packet, receive):
        return self.link.send(packet.reverse, packet.kind, packet.identity, packet.wire_bytes,
                              receive, work_bytes=lambda: self.core.decode_xor_bytes(packet))

    def observe(self, event, channel, sequence, piece):
        key = channel, sequence
        if event == "gap_observed" and key not in self.gaps:
            self.gaps[key] = self.link.now
            self.gap_count += 1
        if event == "request" and self.gaps.get(key) is not None:
            self.request_delays.append((self.link.now - self.gaps[key]) * 1000)
            self.gaps[key] = None
        if event == "delivered":
            self.gaps.pop(key, None)
        if self.trace is not None:
            self.trace.append([round(self.link.now * 1000, 6), event, channel, sequence, piece])

    def credit(self, channel):
        if not self.pump_pending:
            self.pump_pending = True
            self.link.at(self.link.now, self.pump)

    def offer(self, frame_id, size):
        self.offered += 1
        queue = self.queues[frame_id % len(self.queues)]
        if len(queue) >= 32:
            self.dropped += 1
            return
        queue.append((frame_id, size, self.link.now))
        self.pump()

    def pump(self):
        self.pump_pending = False
        start = self.next_flow
        while True:
            advanced = False
            for step in range(len(self.queues)):
                flow = (start + step) % len(self.queues)
                if not self.queues[flow]:
                    continue
                p = self.profile
                lanes = [(flow + stripe) % p.channels for stripe in range(p.stripes)]
                if not all(self.core.can_offer(lane) for lane in lanes):
                    continue
                frame_id, size, offered = self.queues[flow].popleft()
                self.frame_state[frame_id] = (size, offered, self.link.now)
                body = ethernet(frame_id, size)
                for stripe, lane in enumerate(lanes):
                    record = body
                    if p.stripes > 1:
                        lo = size * stripe // p.stripes
                        hi = size * (stripe + 1) // p.stripes
                        record = STRIPE.pack(frame_id, stripe, p.stripes) + body[lo:hi]
                    if not self.core.offer(lane, frame_id * p.stripes + stripe, record):
                        raise RuntimeError("credit changed during admission")
                self.admitted += 1
                advanced = True
                self.next_flow = (flow + 1) % len(self.queues)
            if not advanced:
                return
            start = self.next_flow

    def receive(self, record_id, body):
        if self.profile.stripes == 1:
            frame_id = record_id
        else:
            frame_id, index, count = STRIPE.unpack_from(body)
            if (count != self.profile.stripes or index >= count
                    or record_id != frame_id * count + index):
                raise ValueError("invalid stripe descriptor")
            parts = self.partial.setdefault(frame_id, {})
            if index in parts:
                raise RuntimeError("duplicate stripe delivery")
            parts[index] = body[STRIPE.size:]
            if len(parts) < count:
                return
            body = b"".join(parts[i] for i in range(count))
            del self.partial[frame_id]
        size, offered, admitted = self.frame_state.pop(frame_id)
        if body != ethernet(frame_id, size):
            raise RuntimeError("Ethernet frame mismatch")
        self.times.append((self.link.now, offered, admitted, size))
        self.delivered += 1
        if self.trace is not None:
            self.trace.append([round(self.link.now * 1000, 6), "ethernet_delivery", frame_id])

    def counts(self):
        return dict(offered=self.offered, input_drops=self.dropped, admitted=self.admitted,
                    delivered=self.delivered, input_waiting=sum(map(len, self.queues)),
                    awaiting_delivery=len(self.frame_state), unconfirmed=self.core.pending_frames)


def run_load(profile, seed, *, load_mbps, duration, warmup, drain):
    study = Study(profile, seed)
    size = 1400
    period = size * 8 / (load_mbps * 1e6)

    def generate(frame_id):
        study.offer(frame_id, size)
        when = (frame_id + 1) * period
        if when < duration:
            study.link.at(when, generate, frame_id + 1)

    study.link.at(0, generate, 0)
    study.link.run(warmup)
    before = [study.link.serialized_bytes(rev) for rev in (False, True)]
    study.link.run(duration)
    active = study.counts()
    wire = [study.link.serialized_bytes(rev) - initial
            for rev, initial in zip((False, True), before)]
    study.link.run(duration + drain)
    delivered = [item for item in study.times if warmup < item[0] <= duration]
    cohort = [item for item in study.times if warmup <= item[1] < duration]
    confirmed = study.counts()
    if (confirmed["offered"] != confirmed["input_drops"] + confirmed["input_waiting"]
            + confirmed["awaiting_delivery"] + confirmed["delivered"]):
        raise RuntimeError("frame conservation failed")
    window = duration - warmup
    return dict(profile=asdict(profile), recovery_config=asdict(study.config),
                link_config=asdict(study.link.config), seed=seed,
                goodput_mbps=sum(item[3] for item in delivered) * 8 / (1e6 * window),
                wire_mbps=[n * 8 / (1e6 * window) for n in wire],
                original_to_delivery_ms=distribution([(d-o)*1000 for d,o,a,s in cohort]),
                admission_to_delivery_ms=distribution([(d-a)*1000 for d,o,a,s in cohort]),
                input_wait_ms=distribution([(a-o)*1000 for d,o,a,s in cohort]),
                gap_to_first_request_ms=distribution(study.request_delays),
                observed_gaps=study.gap_count, at_traffic_end=active, after_drain=confirmed,
                recovery_counters=dict(study.core.metrics), links=study.link.report())


def witness(profile, lose_first_request):
    def lost(reverse, kind, identity):
        return (kind == "source" or (lose_first_request and kind == "request")
                ) and identity == (0, 0, 1)

    study = Study(profile, 1, lost, trace=True)
    study.offer(0, 1400)
    study.link.at(.001, study.offer, 1, 1400)
    study.link.run(2)
    if study.delivered != 2 or study.core.pending_frames:
        raise RuntimeError("witness failed to deliver and confirm both frames")
    return dict(profile=profile.name, lose_first_request=lose_first_request,
                events=study.trace, links=study.link.report())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--seeds", type=int, nargs="+", default=[17, 29, 43])
    parser.add_argument("--duration", type=float, default=5)
    parser.add_argument("--warmup", type=float, default=1)
    parser.add_argument("--drain", type=float, default=5)
    parser.add_argument("--load-mbps", type=float, default=60)
    args = parser.parse_args()
    if not 0 <= args.warmup < args.duration or args.drain < 0 or args.load_mbps <= 0:
        parser.error("invalid window or load")
    args.output.mkdir(parents=True, exist_ok=False)
    inputs = [Path(__file__), *(ROOT / "simulator/src/l2tunnel_sim" / name
                              for name in ("frame_channel_link.py", "frame_channels.py"))]
    paths = {str(p.resolve().relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in inputs}
    def save(name, data):
        (args.output / name).write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")

    save("manifest.json", dict(source_sha256=paths, **{k: v for k, v in vars(args).items()
                                                      if k != "output"}))
    save("forced-loss.json", [witness(p, lost) for p in (*PROFILES[:4], PROFILES[-2])
                              for lost in (False, True)])
    for seed in args.seeds:
        for profile in PROFILES:
            result = run_load(profile, seed, duration=args.duration, warmup=args.warmup,
                              drain=args.drain, load_mbps=args.load_mbps)
            save(f"{profile.name}-{seed}.json", result)
            print(profile.name, seed, round(result["goodput_mbps"], 3), flush=True)


if __name__ == "__main__":
    main()
