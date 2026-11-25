//! The static v1 register catalog.
//!
//! Paths are named after the owning Rust component:
//! `crate.component[.instance...].meter[.qualifier...]`. Each root records the
//! buffer-inventory row and meter family as attributes, never as path
//! segments. Placeholders in patterns stand for one segment each:
//!
//! | Placeholder | Segment |
//! |---|---|
//! | `{lane}` | `laneN`, an authenticated carrier lane, or `shared` |
//! | `{ch}` | `chN`, a MUX channel |
//! | `{flow}` | `flowN`, an inner flow (numeric only) |
//! | `{class}` | [`CLASSES`] |
//! | `{dir}` | `tx` or `rx` |
//! | `{reason}` | [`REASONS`] |
//! | `{stream}` | [`STREAMS`] |
//! | `{store}` | [`STORES`] |
//! | `{bucket}` | `b00` to `b23` |
//! | `{owner}` | any segment |

use std::sync::OnceLock;

use crate::path;
use crate::wait::BUCKETS;

/// Catalog version carried in `meta.version`.
pub const VERSION: u64 = 1;

/// Traffic classes.
pub const CLASSES: [&str; 4] = ["shared", "user", "feedback", "management"];
/// Directions.
pub const DIRECTIONS: [&str; 2] = ["tx", "rx"];
/// Independently identified wait causes.
pub const REASONS: [&str; 19] = [
    "queue_full",
    "byte_capacity",
    "peer_credit",
    "io_pending",
    "flush_pending",
    "physical_receipt_pending",
    "consumer_pending",
    "policy_pacing",
    "work_budget",
    "buffer_capacity",
    "native_credit",
    "codec_stage",
    "recovery_window",
    "socket_write",
    "carrier_admission",
    "receipt_wait",
    "policy_credit",
    "dependency",
    "recovery_history_capacity",
];
/// Management control streams.
pub const STREAMS: [&str; 5] = [
    "transaction",
    "liveness",
    "data_feedback",
    "lifecycle",
    "meters",
];
/// Static capacity-only stores.
pub const STORES: [&str; 4] = ["scratch", "contexts", "replay", "rx_bitmap"];

/// Inner-flow state codes in `mux.{flow}.state`.
pub const FLOW_STATES: [&str; 4] = ["unknown", "active", "stopped", "retired"];

/// How a register value behaves over time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Sampled current value.
    Gauge,
    /// Operational capacity.
    Capacity,
    /// Highest sampled value.
    HighWater,
    /// Grows within one session generation.
    Counter,
    /// Accumulated or maximum duration.
    Duration,
    /// Histogram bucket count.
    Bucket,
    /// Enumerated code or boolean.
    State,
}

impl Kind {
    /// Stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gauge => "gauge",
            Self::Capacity => "capacity",
            Self::HighWater => "high_water",
            Self::Counter => "counter",
            Self::Duration => "duration",
            Self::Bucket => "bucket",
            Self::State => "state",
        }
    }
}

/// Unit of a register value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unit {
    /// Dimensionless count.
    Count,
    /// Items (records, packets, slots) held.
    Items,
    /// Bytes.
    Bytes,
    /// Packets or datagrams.
    Packets,
    /// Microseconds.
    Micros,
    /// Bytes per second.
    BytesPerSecond,
    /// Enumerated code.
    Code,
}

impl Unit {
    /// Stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Items => "items",
            Self::Bytes => "bytes",
            Self::Packets => "packets",
            Self::Micros => "us",
            Self::BytesPerSecond => "bytes_per_second",
            Self::Code => "code",
        }
    }
}

/// Meter family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// Buffer occupancy and backpressure.
    Buffer,
    /// Recovery and protocol counters.
    Recovery,
    /// Carrier and transport.
    Carrier,
    /// MUX channel and inner-flow traffic.
    Mux,
    /// CSR identity.
    Meta,
}

impl Family {
    /// Stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Buffer => "buffer",
            Self::Recovery => "recovery",
            Self::Carrier => "carrier",
            Self::Mux => "mux",
            Self::Meta => "meta",
        }
    }
}

/// Whether the meter is reported by some profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// Reported where the owner exists.
    Reported,
    /// Never reported; the reason says why. Never shown as zero.
    Unavailable(&'static str),
}

/// One counter definition inside a root.
#[derive(Clone, Copy, Debug)]
pub struct Meter {
    /// Last segment(s).
    pub name: &'static str,
    /// Value behavior.
    pub kind: Kind,
    /// Value unit.
    pub unit: Unit,
    /// Availability.
    pub state: State,
}

const fn counter(name: &'static str, unit: Unit) -> Meter {
    Meter {
        name,
        kind: Kind::Counter,
        unit,
        state: State::Reported,
    }
}

const fn gauge(name: &'static str, unit: Unit) -> Meter {
    Meter {
        name,
        kind: Kind::Gauge,
        unit,
        state: State::Reported,
    }
}

const fn unavailable(name: &'static str, unit: Unit, reason: &'static str) -> Meter {
    Meter {
        name,
        kind: Kind::Gauge,
        unit,
        state: State::Unavailable(reason),
    }
}

/// A group of registers under one root.
#[derive(Clone, Copy, Debug)]
pub enum Block {
    /// [`crate::Gauge`] registers.
    Occupancy,
    /// [`crate::Refusals`] registers.
    Refusals,
    /// `wait.{reason}` registers from [`crate::WaitSnapshot`].
    Wait,
    /// Root-specific counters.
    Counters(&'static [Meter]),
    /// Root-specific counters under `{dir}`.
    Directional(&'static [Meter]),
}

const BUFFER: &[Block] = &[Block::Occupancy, Block::Refusals, Block::Wait];

/// One component root.
#[derive(Clone, Copy, Debug)]
pub struct Root {
    /// `crate.component`.
    pub path: &'static str,
    /// Instance placeholders following the root, in order.
    pub instances: &'static [&'static str],
    /// Buffer-inventory row (`BP-01`..`BP-24`) or another ledger reference.
    pub row: &'static str,
    /// Family of this root's own counters; buffer blocks are always
    /// [`Family::Buffer`].
    pub family: Family,
    /// Register groups.
    pub blocks: &'static [Block],
}

macro_rules! site {
    ($path:literal, $row:literal) => {
        Root {
            path: $path,
            instances: &["{lane}", "{class}"],
            row: $row,
            family: Family::Buffer,
            blocks: BUFFER,
        }
    };
}

macro_rules! root {
    ($path:literal, [$($instance:literal),*], $row:literal, $family:ident, $blocks:expr) => {
        Root {
            path: $path,
            instances: &[$($instance),*],
            row: $row,
            family: Family::$family,
            blocks: $blocks,
        }
    };
}

const ARQ: &[Meter] = &[
    counter("records", Unit::Count),
    counter("retransmits", Unit::Count),
    counter("rto", Unit::Count),
    counter("acks", Unit::Count),
    counter("replay_rejects", Unit::Count),
    counter("deadline_losses", Unit::Count),
];
const REPAIR: &[Meter] = &[
    counter("repairs_sent", Unit::Count),
    counter("repairs_used", Unit::Count),
    counter("decode_failures", Unit::Count),
    counter("feedback", Unit::Count),
    counter("deadline_losses", Unit::Count),
];

/// Every v1 root.
pub const ROOTS: &[Root] = &[
    root!(
        "meta",
        [],
        "meter-csr",
        Meta,
        &[Block::Counters(&[
            Meter {
                name: "version",
                kind: Kind::State,
                unit: Unit::Code,
                state: State::Reported
            },
            gauge("sampled_us", Unit::Micros),
        ])]
    ),
    root!(
        "meta.owner",
        ["{owner}"],
        "meter-csr",
        Meta,
        &[Block::Counters(&[
            gauge("sampled_us", Unit::Micros),
            gauge("slots_used", Unit::Items),
            gauge("slot_capacity", Unit::Items),
            counter("slots_exhausted", Unit::Count),
            gauge("heap_bytes", Unit::Bytes),
            Meter {
                name: "invalid",
                kind: Kind::State,
                unit: Unit::Code,
                state: State::Reported,
            },
            counter("blocked_episodes", Unit::Count),
            Meter {
                name: "blocked_completed_us",
                kind: Kind::Duration,
                unit: Unit::Micros,
                state: State::Reported,
            },
            Meter {
                name: "blocked_censored_us",
                kind: Kind::Duration,
                unit: Unit::Micros,
                state: State::Reported,
            },
            Meter {
                name: "blocked_open_us",
                kind: Kind::Duration,
                unit: Unit::Micros,
                state: State::Reported,
            },
            Meter {
                name: "blocked_max_us",
                kind: Kind::Duration,
                unit: Unit::Micros,
                state: State::Reported,
            },
        ])]
    ),
    // BP-01 pipeline, MUX, scheduler and flow table.
    root!(
        "mux.channel",
        ["{ch}"],
        "BP-01",
        Mux,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Directional(&[
                counter("packets", Unit::Packets),
                counter("bytes", Unit::Bytes),
                counter("admitted", Unit::Count),
                counter("refused", Unit::Count),
                gauge("queued_bytes", Unit::Bytes),
            ]),
        ]
    ),
    root!(
        "mux",
        ["{flow}"],
        "BP-01",
        Mux,
        &[
            Block::Directional(&[
                counter("packets", Unit::Packets),
                counter("bytes", Unit::Bytes)
            ]),
            Block::Counters(&[Meter {
                name: "state",
                kind: Kind::State,
                unit: Unit::Code,
                state: State::Reported
            }]),
        ]
    ),
    root!(
        "qos.scheduler",
        ["{flow}"],
        "BP-01",
        Mux,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                gauge("deficit_bytes", Unit::Bytes),
                counter("served_packets", Unit::Packets),
                counter("served_bytes", Unit::Bytes),
            ]),
        ]
    ),
    root!(
        "packet.flow_table",
        [],
        "BP-01",
        Mux,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Counters(&[counter("evictions", Unit::Count)]),
        ]
    ),
    root!(
        "pipeline.queue",
        ["{ch}"],
        "BP-01",
        Buffer,
        &[Block::Occupancy, Block::Refusals, Block::Wait]
    ),
    // BP-02 ACK ingress.
    root!(
        "pipeline.ack_coalescing",
        ["{lane}"],
        "BP-02",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                counter("held", Unit::Count),
                counter("replaced", Unit::Count),
                gauge("replacement_age_max_us", Unit::Micros),
            ]),
        ]
    ),
    // BP-03 bank, native window and output tokens.
    root!(
        "l2tunnel.record_bank",
        [],
        "BP-03",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                gauge("epoch_slots", Unit::Items),
                gauge("draining_generations", Unit::Items)
            ]),
        ]
    ),
    root!(
        "runtime.native_window",
        [],
        "BP-03",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[gauge("output_tokens", Unit::Items)]),
        ]
    ),
    // BP-04 and BP-05 Aligned/Packed codec.
    root!(
        "codec.aligned_sender",
        ["{ch}"],
        "BP-04",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                counter("containers_sealed", Unit::Count),
                counter("fragments", Unit::Count)
            ]),
        ]
    ),
    root!(
        "codec.packed_sender",
        ["{ch}"],
        "BP-04",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                counter("containers_sealed", Unit::Count),
                counter("fragments", Unit::Count)
            ]),
        ]
    ),
    root!(
        "codec.aligned_receiver",
        ["{ch}"],
        "BP-05",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                gauge("proofs", Unit::Items),
                gauge("ordered_records", Unit::Items),
                gauge("pending_fragments", Unit::Items),
            ]),
        ]
    ),
    // BP-06 Reliable.
    root!("reliable.outgoing", ["{ch}"], "BP-06", Buffer, BUFFER),
    root!("reliable.restored", ["{ch}"], "BP-06", Buffer, BUFFER),
    root!(
        "reliable.decoder",
        ["{ch}"],
        "BP-06",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(REPAIR),
        ]
    ),
    // BP-07 ARQ.
    root!(
        "recovery.arq",
        ["{ch}"],
        "BP-07",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Directional(ARQ),
        ]
    ),
    root!(
        "reliable.compact_arq",
        ["{ch}"],
        "BP-07",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Directional(ARQ),
            Block::Counters(&[gauge("history_slots", Unit::Items)]),
        ]
    ),
    // BP-08 Swift.
    root!(
        "swift.sender",
        ["{ch}"],
        "BP-08",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                counter("retries", Unit::Count),
                counter("repairs_sent", Unit::Count),
                counter("feedback", Unit::Count),
            ]),
        ]
    ),
    root!(
        "swift.receiver",
        ["{ch}"],
        "BP-08",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(REPAIR),
        ]
    ),
    root!("swift.byte_queue", ["{ch}"], "BP-08", Buffer, BUFFER),
    // BP-09 Block FEC.
    root!(
        "fec.decoder",
        ["{ch}"],
        "BP-09",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                gauge("generations", Unit::Items),
                gauge("rank", Unit::Count),
                counter("repairs_used", Unit::Count),
                counter("decode_failures", Unit::Count),
            ]),
        ]
    ),
    // BP-10 Rolling.
    root!(
        "fec.rolling",
        ["{ch}"],
        "BP-10",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(REPAIR),
        ]
    ),
    root!(
        "l2tunnel.rolling_records",
        ["{ch}"],
        "BP-10",
        Buffer,
        BUFFER
    ),
    // BP-11 legacy sliding, recursive and parity.
    root!(
        "fec.legacy_sliding",
        ["{ch}"],
        "BP-11",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(REPAIR),
        ]
    ),
    root!(
        "fec.research",
        ["{ch}"],
        "BP-11",
        Recovery,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(REPAIR),
        ]
    ),
    // BP-12 fragment groups and reassembly.
    root!(
        "runtime.common_fragments",
        [],
        "BP-12",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                gauge("groups", Unit::Items),
                counter("reassembled", Unit::Count),
                counter("expired", Unit::Count),
            ]),
        ]
    ),
    // BP-13 connection owners.
    root!(
        "l2tunnel.connection_records",
        ["{flow}"],
        "BP-13",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[Meter {
                name: "incarnation",
                kind: Kind::State,
                unit: Unit::Code,
                state: State::Reported
            }]),
        ]
    ),
    // BP-14 and BP-15 native device path.
    root!(
        "runtime.native_ingress",
        ["{lane}", "{class}"],
        "BP-14",
        Buffer,
        BUFFER
    ),
    root!(
        "runtime.user_slot",
        ["{lane}", "{class}"],
        "BP-14",
        Buffer,
        BUFFER
    ),
    root!(
        "runtime.native_output",
        [],
        "BP-15",
        Buffer,
        &[Block::Counters(&[counter("would_block", Unit::Count)])]
    ),
    root!(
        "runtime.device",
        [],
        "BP-15",
        Carrier,
        &[Block::Counters(&[
            counter("read_packets", Unit::Packets),
            counter("written_packets", Unit::Packets),
            counter("oversize", Unit::Packets),
            counter("backpressure_drops", Unit::Packets),
            gauge("pending_packets", Unit::Packets),
            gauge("pending_bytes", Unit::Bytes),
        ])]
    ),
    // BP-16 management control streams.
    root!(
        "management.control_streams",
        ["{stream}"],
        "BP-16",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                counter("messages_sent", Unit::Count),
                counter("messages_received", Unit::Count),
                counter("fragments", Unit::Count),
                counter("retransmits", Unit::Count),
            ]),
        ]
    ),
    // BP-17 TCP proxy.
    root!("tcp_proxy.session", ["{flow}"], "BP-17", Buffer, BUFFER),
    // BP-18 raw TCP carrier.
    root!(
        "raw_tcp.engine",
        ["{lane}"],
        "BP-18",
        Carrier,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                counter("prepare_refusals", Unit::Count),
                counter("quota_refusals", Unit::Count),
                gauge("custody_latency_max_us", Unit::Micros),
            ]),
        ]
    ),
    // BP-19 OpenVPN carrier.
    root!(
        "openvpn.wire_carrier",
        ["{lane}", "{class}"],
        "BP-19",
        Carrier,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[counter("receive_drops", Unit::Packets)]),
        ]
    ),
    // BP-20 retained TLS.
    root!(
        "runtime.retained_tls",
        ["{lane}"],
        "BP-20",
        Carrier,
        &[Block::Counters(&[gauge("pending_writes", Unit::Items)])]
    ),
    // BP-21 QUIC.
    root!(
        "quic.connection",
        ["{lane}"],
        "BP-21",
        Carrier,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                gauge("rtt_us", Unit::Micros),
                gauge("cwnd_bytes", Unit::Bytes),
                counter("sent_packets", Unit::Packets),
                counter("lost_packets", Unit::Packets),
                counter("congestion_events", Unit::Count),
                unavailable(
                    "provider_send_queue_bytes",
                    Unit::Bytes,
                    "provider-private in Quinn"
                ),
                unavailable(
                    "provider_receive_queue_bytes",
                    Unit::Bytes,
                    "provider-private in Quinn"
                ),
            ]),
        ]
    ),
    // Runtime collector sites, one root per site, each per lane and class.
    site!("runtime.native_egress", "BP-15"),
    site!("runtime.codec.admission", "BP-04"),
    site!("runtime.codec.delivery", "BP-05"),
    site!("runtime.recovery.send", "BP-07"),
    site!("runtime.recovery.receive", "BP-07"),
    site!("runtime.management", "BP-16"),
    site!("runtime.common_prepared", "BP-03"),
    site!("runtime.maintained.submission", "BP-22"),
    site!("runtime.maintained.receipt", "BP-22"),
    site!("runtime.maintained.input", "BP-22"),
    site!("runtime.retained_tls.write", "BP-20"),
    site!("runtime.retained_tls.flush", "BP-20"),
    site!("runtime.retained_tls.submission", "BP-20"),
    site!("runtime.retained_tls.input", "BP-20"),
    site!("runtime.retained_tls.receipt", "BP-20"),
    site!("quic.connection.send", "BP-21"),
    site!("runtime.raw_carrier.send", "BP-18"),
    site!("runtime.raw_carrier.credit", "BP-18"),
    site!("runtime.raw_carrier.control_slot", "BP-18"),
    site!("runtime.proxy.admission", "BP-17"),
    site!("runtime.proxy.writer", "BP-17"),
    site!("runtime.proxy.physical_receipt", "BP-17"),
    site!("pipeline.admission", "BP-01"),
    site!("runtime.native_output.queue", "BP-15"),
    site!("runtime.native_output.device_write", "BP-15"),
    site!("runtime.deferred_feedback", "BP-02"),
    site!("runtime.wire_credit", "receiver-credit"),
    site!("flow_control.session_credit.window", "receiver-credit"),
    // BP-23 local service.
    root!(
        "client_core.local",
        [],
        "BP-23",
        Buffer,
        &[
            Block::Occupancy,
            Block::Refusals,
            Block::Wait,
            Block::Counters(&[
                counter("requests", Unit::Count),
                counter("refused", Unit::Count)
            ]),
        ]
    ),
    // BP-24 static capacity-only stores: no queue wait by definition.
    root!(
        "runtime.static",
        ["{store}"],
        "BP-24",
        Buffer,
        &[
            Block::Occupancy,
            Block::Counters(&[counter("evictions", Unit::Count)]),
        ]
    ),
    // Receiver credit: the send side applies the peer's grants, the receive
    // side issues this endpoint's grants.
    root!(
        "flow_control.session_credit.tx",
        [],
        "receiver-credit",
        Carrier,
        &[Block::Counters(&[
            gauge("limit", Unit::Packets),
            gauge("window_datagrams", Unit::Packets),
            gauge("bytes_above", Unit::Bytes),
            gauge("peer_processed", Unit::Packets),
            gauge("in_flight_bytes", Unit::Bytes),
            gauge("in_flight_datagrams", Unit::Packets),
            gauge("peer_drain_rate", Unit::BytesPerSecond),
            gauge("pacing_rate", Unit::BytesPerSecond),
            counter("accepted", Unit::Count),
            counter("stale", Unit::Count),
            counter("credit_blocked", Unit::Count),
            counter("pacing_blocked", Unit::Count),
            counter("declared_lost", Unit::Packets),
            gauge("range", Unit::Packets),
            counter("range_blocked", Unit::Count),
            counter("range_probes", Unit::Packets),
            gauge("min_rtt_us", Unit::Micros),
        ])]
    ),
    root!(
        "flow_control.session_credit.rx",
        [],
        "receiver-credit",
        Carrier,
        &[Block::Counters(&[
            gauge("processed", Unit::Packets),
            gauge("limit", Unit::Packets),
            gauge("bytes_above", Unit::Bytes),
            gauge("drain_rate", Unit::BytesPerSecond),
            gauge("drain_datagram_rate", Unit::Count),
            gauge("allowance_bytes", Unit::Bytes),
            counter("issued", Unit::Count),
            Meter {
                name: "frozen",
                kind: Kind::State,
                unit: Unit::Code,
                state: State::Reported,
            },
            counter("rejected", Unit::Count),
            counter("sender_restarts", Unit::Count),
            counter("unrecorded", Unit::Packets),
            gauge("rcvbuf_requested", Unit::Bytes),
            gauge("rcvbuf_readback", Unit::Bytes),
            Meter {
                name: "allowance_readback",
                kind: Kind::State,
                unit: Unit::Code,
                state: State::Reported,
            },
        ])]
    ),
    // Outer wire and UDP socket per lane.
    root!(
        "runtime.wire",
        ["{lane}"],
        "metrics",
        Carrier,
        &[Block::Counters(&[
            counter("sent_packets", Unit::Packets),
            counter("sent_bytes", Unit::Bytes),
            counter("accepted_packets", Unit::Packets),
            counter("accepted_bytes", Unit::Bytes),
            counter("send_drops", Unit::Packets),
            counter("received_packets", Unit::Packets),
            counter("receive_errors", Unit::Count),
            counter("rejected_packets", Unit::Packets),
            counter("replay_rejections", Unit::Packets),
        ])]
    ),
    root!(
        "udp.socket",
        ["{lane}"],
        "metrics",
        Carrier,
        &[Block::Counters(&[
            counter("socket_drops", Unit::Packets),
            gauge("rcvbuf_requested", Unit::Bytes),
            gauge("rcvbuf_granted", Unit::Bytes),
        ])]
    ),
    // Session-level rates and timing.
    root!(
        "runtime.session",
        [],
        "metrics",
        Carrier,
        &[Block::Counters(&[
            gauge("elapsed_us", Unit::Micros),
            gauge("send_rate", Unit::BytesPerSecond),
            gauge("receive_rate", Unit::BytesPerSecond),
            gauge("send_channels", Unit::Count),
            gauge("receive_channels", Unit::Count),
            gauge("rtt_us", Unit::Micros),
        ])]
    ),
];

/// One expanded catalog pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    /// Path pattern with placeholders.
    pub pattern: String,
    /// Value behavior.
    pub kind: Kind,
    /// Value unit.
    pub unit: Unit,
    /// Meter family.
    pub family: Family,
    /// Buffer-inventory row or ledger reference.
    pub row: &'static str,
    /// Availability.
    pub state: State,
}

const WAIT_SCALARS: [(&str, Kind, Unit); 8] = [
    ("episodes", Kind::Counter, Unit::Count),
    ("completed_episodes", Kind::Counter, Unit::Count),
    ("censored_episodes", Kind::Counter, Unit::Count),
    ("completed_us", Kind::Duration, Unit::Micros),
    ("censored_us", Kind::Duration, Unit::Micros),
    ("open_us", Kind::Duration, Unit::Micros),
    ("max_us", Kind::Duration, Unit::Micros),
    ("invalid", Kind::State, Unit::Code),
];
const OCCUPANCY: [(&str, Kind, Unit); 7] = [
    ("samples", Kind::Counter, Unit::Count),
    ("occupancy_items", Kind::Gauge, Unit::Items),
    ("capacity_items", Kind::Capacity, Unit::Items),
    ("high_water_items", Kind::HighWater, Unit::Items),
    ("occupancy_bytes", Kind::Gauge, Unit::Bytes),
    ("capacity_bytes", Kind::Capacity, Unit::Bytes),
    ("high_water_bytes", Kind::HighWater, Unit::Bytes),
];
const REFUSALS: [&str; 4] = ["refusals", "untimed_refusals", "drops", "progress"];

fn expand() -> Vec<Descriptor> {
    let mut out = Vec::new();
    for root in ROOTS {
        let mut base = String::from(root.path);
        for instance in root.instances {
            base.push('.');
            base.push_str(instance);
        }
        let mut push = |suffix: &str, kind, unit, family, state| {
            out.push(Descriptor {
                pattern: format!("{base}.{suffix}"),
                kind,
                unit,
                family,
                row: root.row,
                state,
            });
        };
        for block in root.blocks {
            match block {
                Block::Occupancy => {
                    for (name, kind, unit) in OCCUPANCY {
                        push(name, kind, unit, Family::Buffer, State::Reported);
                    }
                }
                Block::Refusals => {
                    for name in REFUSALS {
                        push(
                            name,
                            Kind::Counter,
                            Unit::Count,
                            Family::Buffer,
                            State::Reported,
                        );
                    }
                }
                Block::Wait => {
                    for (name, kind, unit) in WAIT_SCALARS {
                        push(
                            &format!("wait.{{reason}}.{name}"),
                            kind,
                            unit,
                            Family::Buffer,
                            State::Reported,
                        );
                    }
                    push(
                        "wait.{reason}.hist.{bucket}",
                        Kind::Bucket,
                        Unit::Count,
                        Family::Buffer,
                        State::Reported,
                    );
                }
                Block::Counters(meters) => {
                    for meter in *meters {
                        push(meter.name, meter.kind, meter.unit, root.family, meter.state);
                    }
                }
                Block::Directional(meters) => {
                    for meter in *meters {
                        push(
                            &format!("{{dir}}.{}", meter.name),
                            meter.kind,
                            meter.unit,
                            root.family,
                            meter.state,
                        );
                    }
                }
            }
        }
    }
    out
}

/// Every expanded pattern, in catalog order. Built once.
pub fn descriptors() -> &'static [Descriptor] {
    static CATALOG: OnceLock<Vec<Descriptor>> = OnceLock::new();
    CATALOG.get_or_init(expand)
}

/// Whether one path segment satisfies one pattern segment.
fn segment_matches(pattern: &str, segment: &str) -> bool {
    match pattern {
        "{lane}" => {
            segment == "shared"
                || path::instance(segment, "lane").is_some_and(|n| n <= u64::from(u16::MAX))
        }
        "{ch}" => path::instance(segment, "ch").is_some_and(|n| n <= u64::from(u16::MAX)),
        "{flow}" => path::instance(segment, "flow").is_some(),
        "{class}" => CLASSES.contains(&segment),
        "{dir}" => DIRECTIONS.contains(&segment),
        "{reason}" => REASONS.contains(&segment),
        "{stream}" => STREAMS.contains(&segment),
        "{store}" => STORES.contains(&segment),
        "{bucket}" => match segment.as_bytes() {
            [b'b', tens @ b'0'..=b'9', ones @ b'0'..=b'9'] => {
                usize::from(tens - b'0') * 10 + usize::from(ones - b'0') < BUCKETS
            }
            _ => false,
        },
        "{owner}" => !segment.is_empty() && segment.bytes().all(path::segment_byte),
        literal => literal == segment,
    }
}

/// Whether `path` is an instance of `pattern`.
pub fn matches(pattern: &str, path: &str) -> bool {
    let mut left = pattern.split('.');
    let mut right = path.split('.');
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(p), Some(s)) if segment_matches(p, s) => {}
            _ => return false,
        }
    }
}

/// The catalog entry describing `path`, if any.
pub fn lookup(path: &str) -> Option<&'static Descriptor> {
    descriptors()
        .iter()
        .find(|descriptor| matches(&descriptor.pattern, path))
}

/// Patterns under a query prefix. A pattern is listed when some instance of
/// it could lie under `prefix`.
pub fn under(prefix: &str) -> impl Iterator<Item = &'static Descriptor> + '_ {
    descriptors().iter().filter(move |descriptor| {
        if prefix.is_empty() {
            return true;
        }
        let mut pattern = descriptor.pattern.split('.');
        prefix
            .split('.')
            .all(|segment| pattern.next().is_some_and(|p| segment_matches(p, segment)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Longest concrete value each placeholder can take.
    fn widest(segment: &str) -> &str {
        match segment {
            "{lane}" => "lane65535",
            "{ch}" => "ch65535",
            "{flow}" => "flow18446744073709551615",
            "{class}" => "management",
            "{dir}" => "tx",
            "{reason}" => "recovery_history_capacity",
            "{stream}" => "data_feedback",
            "{store}" => "rx_bitmap",
            "{bucket}" => "b23",
            "{owner}" => "codec_aligned_receiver",
            literal => literal,
        }
    }

    #[test]
    fn every_pattern_fits_path_limits_and_is_unique() {
        let all = descriptors();
        assert!(all.len() > 500);
        for descriptor in all {
            let concrete: Vec<&str> = descriptor.pattern.split('.').map(widest).collect();
            let concrete = concrete.join(".");
            assert_eq!(path::validate(&concrete), Ok(()), "{concrete}");
            assert!(matches(&descriptor.pattern, &concrete), "{concrete}");
            assert_eq!(
                lookup(&concrete).map(|found| &found.pattern),
                Some(&descriptor.pattern),
                "ambiguous {concrete}"
            );
        }
    }

    #[test]
    fn lookup_examples() {
        let found = lookup("runtime.native_ingress.lane0.user.occupancy_bytes");
        assert_eq!(
            found.map(|d| (d.kind, d.unit, d.row)),
            Some((Kind::Gauge, Unit::Bytes, "BP-14"))
        );
        let hist = lookup("mux.channel.ch3.wait.queue_full.hist.b07");
        assert_eq!(hist.map(|d| d.kind), Some(Kind::Bucket));
        assert!(lookup("mux.channel.ch3.wait.queue_full.hist.b24").is_none());
        assert!(lookup("mux.channel.ch03.refusals").is_none());
        assert_eq!(
            lookup("recovery.arq.ch2.tx.retransmits").map(|d| d.family),
            Some(Family::Recovery)
        );
        assert_eq!(
            lookup("mux.flow42.rx.bytes").map(|d| d.family),
            Some(Family::Mux)
        );
        assert_eq!(
            lookup("quic.connection.lane1.provider_send_queue_bytes").map(|d| d.state),
            Some(State::Unavailable("provider-private in Quinn"))
        );
        assert!(lookup("runtime.static.replay.wait.queue_full.max_us").is_none());
        assert!(lookup("bp14.ingress.lane0.refusals").is_none());
    }

    #[test]
    fn prefix_listing() {
        assert!(under("").count() == descriptors().len());
        assert!(under("quic.connection.lane0").all(|d| d.pattern.starts_with("quic.connection.")));
        assert!(under("quic.connection.lane0").count() > 10);
        assert_eq!(under("nothing").count(), 0);
    }
}
