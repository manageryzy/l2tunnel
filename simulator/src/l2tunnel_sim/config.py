"""Validated configuration for a repeatable experiment."""

from dataclasses import dataclass, fields
from itertools import product
from math import isfinite
from pathlib import Path
import tomllib


def _number(name, value, minimum, maximum=None, *, integer=False):
    allowed = int if integer else (int, float)
    if (
        isinstance(value, bool) or not isinstance(value, allowed)
        or (not integer and not isfinite(value))
        or value < minimum or (maximum is not None and value > maximum)
    ):
        raise ValueError(f"invalid {name}: {value!r}")


@dataclass(frozen=True)
class Traffic:
    duration_s: float = 2.0
    drain_s: float = 1.0
    frame_bytes: int = 1514
    payload_bytes: int = 1448
    window_bytes: int = 1048576
    ack_every: int = 2
    ack_delay_ms: float = 10.0
    frame_interval_ms: float = 0.0

    def __post_init__(self):
        _number("duration_s", self.duration_s, 0.001)
        _number("drain_s", self.drain_s, 0)
        _number("frame_bytes", self.frame_bytes, 1, 65535, integer=True)
        _number("payload_bytes", self.payload_bytes, 1, self.frame_bytes, integer=True)
        _number("window_bytes", self.window_bytes, self.payload_bytes, integer=True)
        _number("ack_every", self.ack_every, 1, integer=True)
        _number("ack_delay_ms", self.ack_delay_ms, 0)
        _number("frame_interval_ms", self.frame_interval_ms, 0)


@dataclass(frozen=True)
class PathConfig:
    forward_mbps: float = 100.0
    reverse_mbps: float = 10.0
    rtt_factor: float = 1.0
    jitter_ms: float = 0.0

    def __post_init__(self):
        _number("forward_mbps", self.forward_mbps, 0.001)
        _number("reverse_mbps", self.reverse_mbps, 0.001)
        _number("rtt_factor", self.rtt_factor, 0.001)
        _number("jitter_ms", self.jitter_ms, 0)


@dataclass(frozen=True)
class Strategy:
    name: str
    mode: str = "arq"
    streams: int = 1
    fragments: int = 2
    source_batch: int = 1
    repair_batch: int = 1
    reverse_batch: int = 1
    reverse_repair_batch: int = 1
    reverse_fec: bool = False
    reverse_ordered: bool = False
    pack_wait_ms: float = 0.2
    block_size: int = 20
    block_repairs: int = 10
    repair_every: int = 2
    repairs_per_group: int = 1
    interleave_repairs: bool = False
    short_window: int = 16
    long_window: int = 64
    long_every: int = 20
    fec_wait_ms: float = 2.0
    repair_spacing_ms: float = 0.0
    decode_us_per_symbol: float = 0.0
    feedback_repair: bool = False
    cumulative_feedback: bool = False
    feedback_batch: int = 16
    feedback_wait_ms: float = 0.2
    rto_factor: float = 2.5
    rto_min_ms: float = 20.0
    tcp_cc: str = "cubic"
    tcp_path: int = 0
    tcp_initial_cwnd: int = 10
    tcp_rto_min_ms: float = 200.0
    tcp_rto_initial_ms: float = 1000.0
    quic_l2: bool = True
    tcp_data_paws: bool = False
    tcp_partial_timestamp_undo: bool = False
    tcp_newreno_ack_heuristic: bool = False

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("strategy name must be nonempty")
        if self.mode not in ("arq", "block", "sliding", "hybrid", "tcp", "quic"):
            raise ValueError(f"unknown strategy mode: {self.mode!r}")
        if self.tcp_cc not in ("reno", "cubic"):
            raise ValueError(f"unknown TCP congestion controller: {self.tcp_cc!r}")
        if type(self.tcp_data_paws) is not bool or (self.tcp_data_paws and self.mode != "tcp"):
            raise ValueError("tcp_data_paws requires a boolean and a modeled TCP endpoint")
        if type(self.tcp_partial_timestamp_undo) is not bool or (self.tcp_partial_timestamp_undo and self.mode != "tcp"):
            raise ValueError("tcp_partial_timestamp_undo requires a boolean and a modeled TCP endpoint")
        if type(self.tcp_newreno_ack_heuristic) is not bool or (self.tcp_newreno_ack_heuristic and self.mode != "tcp"):
            raise ValueError("tcp_newreno_ack_heuristic requires a boolean and a modeled TCP endpoint")
        _number("tcp_path", self.tcp_path, 0, integer=True)
        _number("tcp_initial_cwnd", self.tcp_initial_cwnd, 1, integer=True)
        _number("tcp_rto_min_ms", self.tcp_rto_min_ms, 1, 60000)
        _number("tcp_rto_initial_ms", self.tcp_rto_initial_ms, self.tcp_rto_min_ms, 60000)
        for name in ("streams", "fragments", "source_batch", "repair_batch",
                     "reverse_batch", "reverse_repair_batch", "block_size",
                     "block_repairs", "repair_every", "repairs_per_group", "short_window",
                     "long_window", "long_every", "feedback_batch"):
            _number(name, getattr(self, name), 1, 255, integer=True)
        if self.block_size + self.block_repairs > 256:
            raise ValueError("block_size + block_repairs must be at most 256")
        if self.short_window > self.long_window:
            raise ValueError("short_window must be at most long_window")
        for name in ("pack_wait_ms", "fec_wait_ms", "repair_spacing_ms",
                     "decode_us_per_symbol", "feedback_wait_ms"):
            _number(name, getattr(self, name), 0)
        for name in ("reverse_fec", "reverse_ordered", "feedback_repair", "cumulative_feedback", "quic_l2", "interleave_repairs"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be boolean")
        _number("rto_factor", self.rto_factor, 1)
        _number("rto_min_ms", self.rto_min_ms, 0.001)


@dataclass(frozen=True)
class Scenario:
    rtt_ms: float
    loss_rate: float
    loss_model: str = "iid"
    mtu: int = 1500
    mean_burst: float = 4.0

    def __post_init__(self):
        _number("rtt_ms", self.rtt_ms, 0)
        _number("loss_rate", self.loss_rate, 0, 1)
        _number("mtu", self.mtu, 128, 65535, integer=True)
        _number("mean_burst", self.mean_burst, 1)
        if self.loss_model not in ("iid", "burst"):
            raise ValueError(f"unknown loss model: {self.loss_model!r}")
        if self.loss_model == "burst" and 0 < self.loss_rate < 1:
            if self.loss_rate > self.mean_burst / (1 + self.mean_burst):
                raise ValueError("mean_burst is too short for the requested stationary loss rate")


@dataclass(frozen=True)
class Experiment:
    replications: int = 3
    seed: int = 20261110
    rtt_ms: tuple[float, ...] = (20, 70, 150)
    loss_rates: tuple[float, ...] = (0.10, 0.15, 0.20)
    loss_models: tuple[str, ...] = ("iid",)
    mtus: tuple[int, ...] = (1500,)
    mean_burst: float = 4.0
    traffic: Traffic = Traffic()
    paths: tuple[PathConfig, ...] = (PathConfig(),)
    strategies: tuple[Strategy, ...] = (
        Strategy("ARQ"),
        Strategy("Block 20+10", mode="block"),
        Strategy("Sliding 33%", mode="sliding", repair_every=3, feedback_repair=True),
        Strategy("Hybrid 50%", mode="hybrid", feedback_repair=True),
        Strategy("Plain TCP CUBIC", mode="tcp"),
        Strategy("Plain TCP NewReno", mode="tcp", tcp_cc="reno"),
    )

    def __post_init__(self):
        _number("replications", self.replications, 1, integer=True)
        _number("seed", self.seed, 0, integer=True)
        for name in ("rtt_ms", "loss_rates", "loss_models", "mtus", "paths", "strategies"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        names = [strategy.name for strategy in self.strategies]
        if len(names) != len(set(names)):
            raise ValueError("strategy names must be unique")
        for strategy in self.strategies:
            if strategy.mode in ("tcp", "quic") and strategy.tcp_path >= len(self.paths):
                raise ValueError(f"TCP path index out of range for {strategy.name!r}")
            if strategy.mode == "quic" and min(self.mtus) < 1228:
                raise ValueError("QUIC requires an IPv4 MTU of at least 1228 bytes")
        scenarios = list(self.scenarios())
        if len(set(scenarios)) != len(scenarios):
            raise ValueError("scenario values must be unique")

    def scenarios(self):
        for rtt, loss, model, mtu in product(self.rtt_ms, self.loss_rates,
                                             self.loss_models, self.mtus):
            yield Scenario(rtt, loss, model, mtu, self.mean_burst)


def load_experiment(path: Path) -> Experiment:
    with path.open("rb") as stream:
        config = tomllib.load(stream)
    tables = {field.name for field in fields(Experiment)}
    unknown = config.keys() - tables
    if unknown:
        raise ValueError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
    if "traffic" in config:
        config["traffic"] = Traffic(**config["traffic"])
    for name, item_type in (("paths", PathConfig), ("strategies", Strategy)):
        if name in config:
            config[name] = tuple(item_type(**item) for item in config[name])
    for name in ("rtt_ms", "loss_rates", "loss_models", "mtus"):
        if name in config:
            if not isinstance(config[name], list):
                raise ValueError(f"{name} must be an array")
            config[name] = tuple(config[name])
    return Experiment(**config)
