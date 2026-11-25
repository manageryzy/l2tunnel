//! Explicit current Common benchmark inputs; these are not product defaults.
//! This exporter opens no socket/device and makes no runtime qualification claim.
use l2tunnel::{
    aligned, codec, connection_records, fec, pipeline, record_configuration as c,
    record_engine as engine, research_records, rolling_records,
};
use l2tunnel_core::{Duplex, traffic};
use l2tunnel_management::Role;
use l2tunnel_recovery::{
    ArqConfig, CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming,
};
use l2tunnel_reliable::{CompactReliableConfig, ReliableConfig};
use ring::digest;
use serde_json::{Value, json};
use std::{error::Error, fs::OpenOptions, io::Write, path::Path, time::Duration};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MTU: usize = 1500;
const CHANNELS: u16 = 16;
const UNITS: u8 = 8;
const NATIVE_STALL_US: u64 = 10_000_000;
const ROW_MEMORY: usize = 512 << 20;
const DEFAULT_BURST_BYTES: usize = 64 << 10;
const BASELINE_FORWARD_RATE: u64 = 12_500_000;
const REVERSE_PACED_ID: &str = "packed-c48-near8-reverse-paced";

fn wire_burst(rate: u64, high_bdp: bool) -> usize {
    if !high_bdp {
        return DEFAULT_BURST_BYTES;
    }
    usize::try_from(rate / 100)
        .unwrap_or(4 << 20)
        .clamp(DEFAULT_BURST_BYTES, 4 << 20)
}

fn swift_flow_sources(peak_rate: u64) -> usize {
    if peak_rate <= BASELINE_FORWARD_RATE {
        return 1024;
    }
    let bdp_symbols = usize::try_from(peak_rate)
        .unwrap_or(usize::MAX)
        .saturating_mul(70)
        / 1_000
        / 1_400;
    (bdp_symbols.saturating_mul(3) / 2)
        .next_power_of_two()
        .clamp(2048, 4096)
}

fn parse_budget_mbps(value: &str) -> Result<(u64, u64)> {
    let parse_one = |part: &str| -> Result<u64> {
        let mbps = part
            .trim()
            .parse::<u64>()
            .map_err(|_| "--budget-mbps expects FWD/REV integer Mbit/s values")?;
        if !(1..=10_000).contains(&mbps) {
            return Err("--budget-mbps values must be within 1..=10000 Mbit/s".into());
        }
        Ok(mbps * 125_000)
    };
    if let Some((fwd, rev)) = value.split_once('/') {
        Ok((parse_one(fwd)?, parse_one(rev)?))
    } else {
        let rate = parse_one(value)?;
        Ok((rate, rate))
    }
}

#[derive(Clone, Copy)]
enum Carrier {
    Udp,
    Raw,
    RawTlsLike,
    Tls,
    Quic,
}
impl Carrier {
    fn id(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Raw => "raw",
            Self::RawTlsLike => "raw-tls-like",
            Self::Tls => "tls",
            Self::Quic => "quic",
        }
    }
    fn cli(self) -> &'static str {
        match self {
            Self::Udp => "quic-like",
            Self::Raw | Self::RawTlsLike => "raw-packet",
            Self::Tls => "tcp",
            Self::Quic => "quic",
        }
    }
    fn physical_allowance(self) -> usize {
        match self {
            Self::Udp => 28,
            Self::Raw => 40,
            Self::RawTlsLike => 45,
            Self::Tls => 70,
            Self::Quic => 156,
        }
    }
    fn overhead(self) -> usize {
        self.physical_allowance() + 21
    }
    fn symbol(self) -> usize {
        // Explicit room for maximum canonical Packed/Cauchy identities. The
        // actual selected owner planner checks the resulting packet maximum.
        MTU - self.overhead() - 200
    }
}

#[derive(Clone, Copy)]
enum Algorithm {
    KcpLikeL2(aligned::NativePolicy, aligned::NativeDelivery),
    Swift {
        fec: bool,
    },
    SwiftTap {
        fec: bool,
    },
    Aligned {
        packed: bool,
        fec: bool,
    },
    Compact {
        packed: bool,
        recovery: CompactRecovery,
    },
    Connections {
        raw_ack: bool,
    },
    Rolling {
        copies: bool,
    },
    PackedC48 {
        source_wire: fec::rolling::wire::SourceWire,
        reverse_wire: fec::rolling::wire::SourceWire,
        forward_headers: aligned::NativePolicy,
    },
    Research(fec::research::Profile),
    Striped {
        forward_cells: (u16, u16),
        forward_hold_micros: u64,
        forward_headers: aligned::NativePolicy,
    },
    PythonCompact,
}
struct Row {
    id: &'static str,
    family: &'static str,
    variant: &'static str,
    algorithm: Algorithm,
}
fn rows() -> Vec<Row> {
    let mut rows = vec![
        Row {
            id: "swift-arq",
            family: "swift",
            variant: "repair-ratio-zero",
            algorithm: Algorithm::Swift { fec: false },
        },
        Row {
            id: "swift-fec",
            family: "swift",
            variant: "repair-1-of-4",
            algorithm: Algorithm::Swift { fec: true },
        },
        Row {
            id: "aligned-arq",
            family: "aligned",
            variant: "selective-repeat-64",
            algorithm: Algorithm::Aligned {
                packed: false,
                fec: false,
            },
        },
        Row {
            id: "aligned-cauchy",
            family: "aligned",
            variant: "cauchy-8-plus-2",
            algorithm: Algorithm::Aligned {
                packed: false,
                fec: true,
            },
        },
        Row {
            id: "packed-arq",
            family: "packed",
            variant: "selective-repeat-64",
            algorithm: Algorithm::Aligned {
                packed: true,
                fec: false,
            },
        },
        Row {
            id: "packed-cauchy",
            family: "packed",
            variant: "cauchy-8-plus-2",
            algorithm: Algorithm::Aligned {
                packed: true,
                fec: true,
            },
        },
    ];
    for (id, family, packed, recovery, variant) in [
        (
            "aligned-compact",
            "aligned_compact",
            false,
            CompactRecovery::Guarded,
            "guarded",
        ),
        (
            "aligned-first-flight",
            "aligned_compact",
            false,
            CompactRecovery::FirstFlight,
            "first-flight",
        ),
        (
            "aligned-bounded-gap",
            "aligned_compact",
            false,
            CompactRecovery::BoundedGap {
                min_interval: Duration::from_millis(1),
            },
            "bounded-gap-1ms",
        ),
        (
            "packed-compact",
            "packed_compact",
            true,
            CompactRecovery::Guarded,
            "guarded",
        ),
        (
            "packed-first-flight",
            "packed_compact",
            true,
            CompactRecovery::FirstFlight,
            "first-flight",
        ),
        (
            "packed-bounded-gap",
            "packed_compact",
            true,
            CompactRecovery::BoundedGap {
                min_interval: Duration::from_millis(1),
            },
            "bounded-gap-1ms",
        ),
    ] {
        rows.push(Row {
            id,
            family,
            variant,
            algorithm: Algorithm::Compact { packed, recovery },
        });
    }
    rows.extend([
        Row {
            id: "connections-recovered",
            family: "per_connection_compact",
            variant: "16-independent-recovered-acks",
            algorithm: Algorithm::Connections { raw_ack: false },
        },
        Row {
            id: "connections-native-ack",
            family: "per_connection_compact",
            variant: "16-independent-lossy-native-acks",
            algorithm: Algorithm::Connections { raw_ack: true },
        },
        Row {
            id: "rolling",
            family: "rolling",
            variant: "8192-local128-global16",
            algorithm: Algorithm::Rolling { copies: false },
        },
        Row {
            id: "rolling-short-copies",
            family: "rolling_copies",
            variant: "three-context-and-independent-copies",
            algorithm: Algorithm::Rolling { copies: true },
        },
        Row {
            id: "research-recursive",
            family: "research",
            variant: "recursive-parity",
            algorithm: Algorithm::Research(fec::research::Profile::Recursive {
                taps: 4,
                width: 8,
                reset: 64,
                fresh_interval: 0,
            }),
        },
        Row {
            id: "research-fallback",
            family: "research",
            variant: "recursive-fresh-every16",
            algorithm: Algorithm::Research(fec::research::Profile::Recursive {
                taps: 4,
                width: 8,
                reset: 64,
                fresh_interval: 16,
            }),
        },
        Row {
            id: "research-accumulator",
            family: "research",
            variant: "accumulator-lanes8-window128",
            algorithm: Algorithm::Research(fec::research::Profile::Accumulator {
                lanes: 8,
                window: 128,
            }),
        },
        Row {
            id: "research-dense",
            family: "research",
            variant: "fresh-dense-control",
            algorithm: Algorithm::Research(fec::research::Profile::Recursive {
                taps: 0,
                width: 0,
                reset: 64,
                fresh_interval: 0,
            }),
        },
    ]);
    rows
}

fn receiver(symbol: usize, channels: u16, source_window: usize) -> codec::aligned_receiver::Limits {
    codec::aligned_receiver::Limits {
        body: codec::aligned_body::Config {
            max_frame_bytes: MTU,
            symbol_bytes: symbol,
            elide_payload_length: true,
            predictive: true,
            timestamp_pair_dictionary: true,
            independent_short_frame_bytes: 128,
        },
        channels,
        first_record: codec::aligned_receiver::RecordId(0),
        first_source: codec::aligned_receiver::SourceId(0),
        record_window: 8192,
        source_window,
        lookahead_records: 1024,
        lookahead_bytes: 4 << 20,
        lookahead_fragments: 4096,
        max_fragments_per_record: 4,
        lifetime_ticks: 30_000,
    }
}
fn source_max(symbol: usize, packed: bool) -> Result<usize> {
    Ok(if packed {
        codec::packed_envelope::Config {
            symbol_bytes: symbol,
            channels: CHANNELS,
            max_units: UNITS,
        }
        .max_source_bytes()?
    } else {
        codec::aligned_envelope::HEADER_BYTES + symbol
    })
}
/// Base-ARQ window from the lab's bandwidth-delay product: the forward rate
/// times the nominal RTT in full sources, tripled so loss repair and RTO
/// recovery do not stall the sender, rounded to a power of two and kept within
/// the wide-ACK range (more than 64 selects the wide ACK).
fn bdp_window(original: usize, peak_rate: u64) -> usize {
    const NOMINAL_RTT_MS: usize = 70;
    let rate = usize::try_from(peak_rate.max(BASELINE_FORWARD_RATE)).unwrap_or(usize::MAX);
    let bdp = rate.saturating_mul(NOMINAL_RTT_MS) / 1000;
    (3 * bdp.div_ceil(original)).next_power_of_two().clamp(
        l2tunnel_recovery::LEGACY_ACK_WINDOW,
        l2tunnel_recovery::MAX_ARQ_WINDOW,
    )
}
fn aligned_config(
    carrier: Carrier,
    packed: bool,
    with_fec: bool,
    peak_rate: u64,
) -> Result<aligned::Config> {
    let high_bdp = peak_rate > BASELINE_FORWARD_RATE;
    let symbol = carrier.symbol();
    let original = source_max(symbol, packed)?;
    let wrapped = original + l2tunnel_recovery::DATA_HEADER_BYTES;
    let window = bdp_window(original, peak_rate);
    let count = if with_fec { 8 } else { 1 };
    let repairs = if with_fec { 2 } else { 0 };
    let fec_packet = fec::HEADER_BYTES + count + 2 + wrapped;
    let recovery = ReliableConfig {
        arq: ArqConfig {
            max_source_bytes: original,
            send_bytes: window * original,
            receive_bytes: window * original,
            send_records: window,
            receive_records: window,
            // Maintained ordinary ARQ defaults, not shortened fixture timers.
            initial_rto: Duration::from_millis(200),
            maximum_rto: Duration::from_secs(3),
            ack_delay: Duration::from_millis(5),
            max_retries: 8,
        },
        fec: fec::DecoderConfig {
            block: fec::BlockConfig {
                max_sources: count,
                max_source_bytes: wrapped,
                max_packet_bytes: fec_packet,
                max_work_per_symbol: 1_000_000,
            },
            max_generations: if high_bdp { 64 } else { 16 },
            max_symbols_per_generation: count + repairs,
            max_reserved_bytes: if high_bdp { 64 << 20 } else { 16 << 20 },
            max_lifetime_ticks: 10_000,
            generation_window: if high_bdp { 1024 } else { 256 },
        },
        repair_symbols: repairs,
        flush_after: Duration::from_millis(1),
        max_restored_packets: window + count,
        max_restored_bytes: (window + count) * wrapped,
        outer_overhead_bytes: carrier.overhead(),
    };
    // The aligned receiver must hold the ARQ receive window plus every
    // restored source, so its source window follows the ARQ window.
    let source_window = (window + recovery.max_restored_packets)
        .next_power_of_two()
        .max(8192);
    let mut recv_limits = receiver(symbol, CHANNELS, source_window);
    if high_bdp {
        recv_limits.record_window = 16_384;
        recv_limits.lookahead_records = 4096;
        recv_limits.lookahead_bytes = 16 << 20;
        recv_limits.lookahead_fragments = 16_384;
    }
    Ok(aligned::Config {
        native_policy: aligned::NativePolicy::IpHeaders,
        receiver: recv_limits,
        max_recovery_packet_bytes: recovery.maximum_packet_bytes()?,
        recovery,
    })
}
fn compact_config(
    carrier: Carrier,
    packed: bool,
    recovery: CompactRecovery,
    independent: bool,
    python_reference: bool,
) -> Result<aligned::CompactConfig> {
    let symbol = carrier.symbol();
    let original = source_max(symbol, packed)?;
    let window = if independent && !python_reference {
        512
    } else {
        8192
    };
    let arq = CompactArqConfig::new(
        CompactBounds {
            max_source_bytes: original,
            send_bytes: window * original,
            receive_bytes: window * original,
            send_records: window,
            receive_records: window,
        },
        CompactTiming {
            nominal_rtt: Duration::from_millis(70),
            feedback_interval: Duration::from_millis(if python_reference { 5 } else { 1 }),
            feedback_packets: if python_reference { 64 } else { 16 },
        },
        l2tunnel_recovery::COMPACT_FEEDBACK_HEADER_BYTES + window.div_ceil(8),
        window * 16,
        9,
        recovery,
    )?;
    Ok(aligned::CompactConfig {
        native_delivery: aligned::NativeDelivery::ProfileDefault,
        native_policy: aligned::NativePolicy::IpHeaders,
        receiver: receiver(symbol, if independent { 1 } else { CHANNELS }, 8192),
        recovery: CompactReliableConfig::new(
            arq,
            carrier.overhead()
                + if independent {
                    connection_records::route::HEADER_BYTES
                } else {
                    0
                },
        )?,
        max_recovery_packet_bytes: original
            + l2tunnel_recovery::COMPACT_DATA_HEADER_BYTES
            + l2tunnel_reliable::ENVELOPE_BYTES,
        copies: codec::source_copy::Policy::ONE,
    })
}
fn packed(base: aligned::Config) -> aligned::packed::Config {
    aligned::packed::Config {
        base,
        hold_micros: 500,
        max_units: UNITS,
        work_limit: 32,
    }
}
fn compact_packed(base: aligned::CompactConfig) -> aligned::packed::CompactConfig {
    aligned::packed::CompactConfig {
        base,
        hold_micros: 500,
        max_units: UNITS,
        work_limit: 32,
    }
}

const ETHERNET_FRAME: usize = MTU + 14;
/// Maximum Ethernet frame carrying an 802.1Q/QinQ VLAN tag over a 1500-byte IP payload.
const ETHERNET_VLAN_FRAME: usize = MTU + 22;

fn kcp_like_rows() -> Vec<Row> {
    use aligned::NativeDelivery::{ChannelOrdered, ProfileDefault};
    use aligned::NativePolicy::{EthernetHeaders, Lz4Ethernet, RawEthernet};
    [
        (
            "kcp-like-l2-raw",
            "raw-ethernet",
            RawEthernet,
            ProfileDefault,
        ),
        (
            "kcp-like-l2-headers",
            "differential-ethernet-headers",
            EthernetHeaders,
            ProfileDefault,
        ),
        (
            "kcp-like-l2-lz4",
            "stateless-lz4-or-raw",
            Lz4Ethernet,
            ProfileDefault,
        ),
        (
            "kcp-like-l2-raw-ordered",
            "channel-ordered-raw-ethernet",
            RawEthernet,
            ChannelOrdered,
        ),
        (
            "kcp-like-l2-lz4-ordered",
            "channel-ordered-lz4-or-raw",
            Lz4Ethernet,
            ChannelOrdered,
        ),
    ]
    .map(|(id, variant, native, delivery)| Row {
        id,
        family: "kcp_like_l2",
        variant,
        algorithm: Algorithm::KcpLikeL2(native, delivery),
    })
    .into()
}

fn kcp_like_direction(
    carrier: Carrier,
    native: aligned::NativePolicy,
    delivery: aligned::NativeDelivery,
) -> Result<aligned::packed::CompactConfig> {
    // Explicit benchmark inputs, shared by the three native encodings and both directions.
    let shape =
        l2tunnel_client_core::kcp_like_l2::Geometry::new(MTU, carrier.overhead(), CHANNELS, UNITS)?;
    let window = 8192usize;
    let mut limits = receiver(shape.symbol_bytes(), CHANNELS, window);
    limits.body.max_frame_bytes = ETHERNET_FRAME;
    let differential = native == aligned::NativePolicy::EthernetHeaders;
    limits.body.elide_payload_length = differential;
    limits.body.predictive = differential;
    limits.body.timestamp_pair_dictionary = differential;
    limits.body.independent_short_frame_bytes = 0;
    let source = shape.max_source_bytes();
    let arq = CompactArqConfig::new(
        CompactBounds {
            max_source_bytes: source,
            send_bytes: 4 << 20,
            receive_bytes: 4 << 20,
            send_records: window,
            receive_records: window,
        },
        CompactTiming {
            nominal_rtt: Duration::from_millis(70),
            feedback_interval: Duration::from_millis(1),
            feedback_packets: 16,
        },
        l2tunnel_recovery::COMPACT_FEEDBACK_HEADER_BYTES + window.div_ceil(8),
        window * 16,
        9,
        CompactRecovery::KcpLike(l2tunnel_recovery::KcpLikeConfig {
            fast_resend: 2,
            interval_ms: 10,
            minimum_rto_ms: 30,
            maximum_rto_ms: 3000,
        }),
    )?;
    Ok(shape.direction_with_delivery(native, delivery, limits, arq, 500, 32)?)
}
fn rolling_direction(carrier: Carrier) -> Result<rolling_records::DirectionConfig> {
    let mut receiver = receiver(carrier.symbol(), CHANNELS, 16_384);
    // Rolling's injected receiver unit is microseconds; ordinary Aligned uses ms.
    receiver.lifetime_ticks = 30_000_000;
    let maximum = source_max(carrier.symbol(), true)?;
    Ok(rolling_records::DirectionConfig {
        native_release: Default::default(),
        return_guard: Default::default(),
        native_policy: aligned::NativePolicy::IpHeaders,
        receiver,
        packing: codec::packed_sender::Config {
            sender: codec::aligned_sender::Config {
                body: receiver.body,
                channels: CHANNELS,
                first_record: receiver.first_record,
            },
            packing: codec::packed::Config {
                symbol_bytes: carrier.symbol(),
                hold_micros: 500,
            },
            max_units: UNITS,
            first_unit: receiver.first_source,
            work_limit: 32,
        },
        codec_stage_micros: NATIVE_STALL_US,
        scheduler: fec::rolling::scheduler::Policy {
            recovery: fec::rolling::Config {
                window: 8192,
                local_window: 128,
                global_every: 16,
                max_payload: maximum,
                max_rows: 2048,
                repair_history: 8192,
                handoff_sources: 128,
                job_ticks: 5_000_000,
                debt_ticks: 10_000_000,
                handoff_ticks: NATIVE_STALL_US,
                memory_bytes: ROW_MEMORY,
            },
            repair_numerator: 26,
            repair_denominator: 125,
            tail_ticks: 10_000,
            feedback_ticks: 1000,
            feedback_packets: 16,
            memory_bytes: ROW_MEMORY,
            source_wire: fec::rolling::wire::SourceWire::Exact,
        },
    })
}
fn profile(algorithm: Algorithm, carrier: Carrier, peak_rate: u64) -> Result<c::Profile> {
    let high_bdp = peak_rate > BASELINE_FORWARD_RATE;
    Ok(match algorithm {
        Algorithm::KcpLikeL2(native, delivery) => {
            let selected = kcp_like_direction(carrier, native, delivery)?;
            c::Profile::PackedCompact {
                forward: selected,
                reverse: selected,
            }
        }
        Algorithm::Swift { fec } | Algorithm::SwiftTap { fec } => {
            let tap = matches!(algorithm, Algorithm::SwiftTap { .. });
            let max_native = if tap { ETHERNET_VLAN_FRAME } else { MTU };
            let flow_sources = swift_flow_sources(peak_rate);
            let queue_bytes = if high_bdp {
                usize::try_from(peak_rate / 64)
                    .unwrap_or(2 << 20)
                    .clamp(512 << 10, 2 << 20)
            } else {
                256 << 10
            };
            let selected = l2tunnel_swift::records::Config {
                channels: usize::from(CHANNELS),
                layer: if tap {
                    l2tunnel_swift::records::Layer::Ethernet
                } else {
                    l2tunnel_swift::records::Layer::Ip
                },
                max_native,
                codec: l2tunnel_swift::Config {
                    datagram_bytes: MTU - carrier.overhead(),
                    window: if high_bdp { 64 } else { 128 },
                    repair_numerator: u32::from(fec),
                    repair_denominator: 4,
                    flow_sources,
                    queue_bytes,
                    max_packet: max_native + l2tunnel_swift::header::MAX_EXPANSION,
                    flush_micros: if high_bdp { 250 } else { 500 },
                    feedback_micros: 1000,
                    tail_micros: 10_000,
                    min_rto_micros: if high_bdp { 80_000 } else { 140_000 },
                    max_rto_micros: 1_000_000,
                },
            };
            c::Profile::Swift {
                forward: selected,
                reverse: selected,
            }
        }
        Algorithm::Aligned {
            packed: is_packed,
            fec,
        } => {
            let base = aligned_config(carrier, is_packed, fec, peak_rate)?;
            if is_packed {
                let selected = packed(base);
                c::Profile::Packed {
                    forward: selected,
                    reverse: selected,
                }
            } else {
                c::Profile::Aligned {
                    forward: base,
                    reverse: base,
                }
            }
        }
        Algorithm::Compact {
            packed: is_packed,
            recovery,
        } => {
            let base = compact_config(carrier, is_packed, recovery, false, false)?;
            if is_packed {
                let selected = compact_packed(base);
                c::Profile::PackedCompact {
                    forward: selected,
                    reverse: selected,
                }
            } else {
                c::Profile::AlignedCompact {
                    forward: base,
                    reverse: base,
                }
            }
        }
        Algorithm::Connections { .. } | Algorithm::PythonCompact => {
            let named = matches!(algorithm, Algorithm::PythonCompact);
            let raw_ack = named || matches!(algorithm, Algorithm::Connections { raw_ack: true });
            let selected = connection_records::Direction {
                compact: compact_config(carrier, false, CompactRecovery::Guarded, true, named)?,
                owners: CHANNELS,
                incarnation: 1,
                unreliable: raw_ack.then_some(connection_records::UnreliableConfig {
                    max_bytes: 128,
                    hold_micros: NATIVE_STALL_US,
                }),
            };
            c::Profile::PerConnectionCompact {
                forward: selected,
                reverse: selected,
            }
        }
        Algorithm::Rolling { .. } | Algorithm::PackedC48 { .. } => {
            let mut selected = rolling_direction(carrier)?;
            let copies = match algorithm {
                Algorithm::PackedC48 { source_wire, .. } => {
                    selected.scheduler.repair_numerator = 41;
                    selected.scheduler.repair_denominator = 200;
                    selected.scheduler.feedback_packets = 64;
                    selected.scheduler.source_wire = source_wire;
                    true
                }
                Algorithm::Rolling { copies } => copies,
                _ => return Err("invalid rolling selection".into()),
            };
            let mut reverse = selected;
            if let Algorithm::PackedC48 {
                forward_headers,
                reverse_wire,
                ..
            } = algorithm
            {
                selected.native_policy = forward_headers;
                reverse.scheduler.source_wire = reverse_wire;
            }
            let config = rolling_records::Config {
                forward: selected,
                reverse,
                geometry: geometry(carrier),
                native_stall_micros: NATIVE_STALL_US,
            };
            if copies {
                let policy = codec::source_copy::Policy {
                    max_unit_bytes: 128,
                    copies: 3,
                    scope: codec::source_copy::Scope::ContextAndIndependent,
                };
                c::Profile::RollingCopies {
                    config,
                    stream: 1,
                    copies: rolling_records::CopyPolicies {
                        forward: policy,
                        reverse: policy,
                    },
                }
            } else {
                c::Profile::Rolling { config, stream: 1 }
            }
        }
        Algorithm::Striped {
            forward_cells,
            forward_hold_micros,
            forward_headers,
        } => {
            let overhead = carrier.overhead();
            let mixed = fec::mixed_datagram::Profile {
                data_cells: 4,
                parity_cells: 1,
                max_wire_bytes: MTU - overhead,
                max_body_bytes: MTU - overhead,
            };
            let original = fec::striped_group::original_limit(mixed)?;
            let symbol = original
                .checked_sub(12 + 8 * usize::from(UNITS))
                .ok_or("mixed source cannot fit a packed unit")?;
            let mut base = rolling_direction(carrier)?;
            base.receiver.body.symbol_bytes = symbol;
            base.packing.sender.body = base.receiver.body;
            base.packing.packing.symbol_bytes = symbol;
            let direction =
                |profile, native_policy, hold_micros| l2tunnel::striped_records::Direction {
                    native_policy,
                    receiver: base.receiver,
                    packing: base.packing,
                    profile,
                    first: fec::GenerationId(0),
                    source_limit: 8192,
                    expanded_limit: 48 << 20,
                    hold_micros,
                    timing: fec::striped_group::schedule::RecoveryTiming {
                        gap_delay: 1_000,
                        gap_repeat: 35_000,
                        ack_delay: 1_000,
                        quiet: 70_000,
                    },
                    overhead_bytes: overhead,
                    stream: 1,
                    codec_stage_micros: NATIVE_STALL_US,
                    native_stall_micros: NATIVE_STALL_US,
                };
            let mut forward = direction(
                fec::mixed_datagram::Profile {
                    data_cells: forward_cells.0,
                    parity_cells: forward_cells.1,
                    ..mixed
                },
                forward_headers,
                forward_hold_micros,
            );
            if forward_headers.is_stateless() {
                forward.receiver.body.predictive = false;
                forward.receiver.body.elide_payload_length = false;
                forward.receiver.body.timestamp_pair_dictionary = false;
                forward.packing.sender.body = forward.receiver.body;
            }
            c::Profile::Striped {
                forward,
                reverse: direction(mixed, aligned::NativePolicy::IpHeaders, 500),
            }
        }
        Algorithm::Research(policy) => {
            let rolling = rolling_direction(carrier)?;
            let selected = research_records::DirectionConfig {
                native_release: Default::default(),
                return_guard: Default::default(),
                // Hole abandonment loses records; anchored deltas keep later
                // records decodable (owner decision 2026-11-24).
                native_policy: aligned::NativePolicy::FixedAnchorIpHeaders,
                receiver: rolling.receiver,
                packing: rolling.packing,
                codec_stage_micros: rolling.codec_stage_micros,
                scheduler: fec::research::Config {
                    recovery: rolling.scheduler.recovery,
                    profile: policy,
                    feedback_ticks: 1000,
                    memory_bytes: ROW_MEMORY,
                    abandon_ticks: 1_000_000,
                },
            };
            c::Profile::Research {
                config: research_records::Config {
                    forward: selected,
                    reverse: selected,
                    geometry: geometry(carrier),
                    native_stall_micros: NATIVE_STALL_US,
                },
                stream: 1,
            }
        }
    })
}
fn geometry(carrier: Carrier) -> engine::Geometry {
    engine::Geometry {
        forward_overhead_bytes: carrier.overhead(),
        reverse_overhead_bytes: carrier.overhead(),
    }
}
fn direction(rate: u64, burst: usize, peak_rate: u64) -> Result<c::CommonDirection> {
    let high_bdp = peak_rate > BASELINE_FORWARD_RATE;
    let per_flow_bytes = if high_bdp {
        usize::try_from(rate / 16)
            .unwrap_or(8 << 20)
            .clamp(2 << 20, 8 << 20)
    } else {
        1 << 20
    };
    let queue_bytes = if high_bdp {
        usize::try_from(rate / 4)
            .unwrap_or(32 << 20)
            .clamp(16 << 20, 32 << 20)
    } else {
        8 << 20
    };
    Ok(c::CommonDirection::new(
        traffic::TrafficPolicy {
            layer: traffic::NetworkLayer::Tun,
            tcp: traffic::TcpControl::System,
            qos: traffic::Qos::WeightedDeficit,
        },
        pipeline::PipelineConfig {
            profile: pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                base_quantum_bytes: 1500,
                max_weight: 1,
                per_flow: pipeline::QueueLimits {
                    bytes: per_flow_bytes,
                    packets: if high_bdp { 4096 } else { 1024 },
                },
            }),
            flows: pipeline::FlowTableConfig {
                capacity: 64,
                channels: CHANNELS,
                mapping: pipeline::Mapping::ConnectionRoundRobinLearned,
                idle_timeout: Duration::from_secs(60),
            },
            parse: pipeline::ParseLimits {
                max_packet_bytes: MTU,
                ..pipeline::ParseLimits::default()
            },
            queue: pipeline::QueueLimits {
                bytes: queue_bytes,
                packets: if high_bdp { 32_768 } else { 8192 },
            },
        },
        rate,
        burst,
        c::NativeWindow::Disabled,
    )?)
}

fn mode_direction(
    algorithm: Algorithm,
    rate: u64,
    burst: usize,
    peak_rate: u64,
) -> Result<c::CommonDirection> {
    let original = direction(rate, burst, peak_rate)?;
    let max_frame = match algorithm {
        Algorithm::KcpLikeL2(..) => ETHERNET_FRAME,
        Algorithm::SwiftTap { .. } => ETHERNET_VLAN_FRAME,
        _ => return Ok(original),
    };
    let mut pipeline = original.pipeline();
    pipeline.profile = pipeline::Profile::TapSystem;
    pipeline.parse.max_packet_bytes = max_frame;
    if matches!(algorithm, Algorithm::SwiftTap { .. }) {
        // Real TAP/VXLAN networks generate many distinct outer UDP source ports
        // and L2/ARP/ND flows; 64 entries would stall under multi-VNI/VLAN traffic.
        pipeline.flows.capacity = 4096;
    }
    Ok(c::CommonDirection::new(
        traffic::TrafficPolicy::tap(),
        pipeline,
        rate,
        burst,
        c::NativeWindow::Disabled,
    )?)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}
fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn runtime_document(
    retained_bytes: usize,
    descriptor: &c::Descriptor,
    lease_micros: u64,
    peak_rate: u64,
) -> Value {
    let high_bdp = peak_rate > BASELINE_FORWARD_RATE;
    let message = json!({"max_message_bytes":4096,"max_outbound_messages":16,"max_outbound_bytes":131072,"max_fragments":32,"max_reassembly_bytes":65536,"max_incomplete_messages":8,"message_lifetime_micros":5_000_000,"work_per_call":32});
    let work = if high_bdp {
        json!({"receive_interval_micros":1000,"receive_packets":1024,"send_batch":256,"native_read_batch":256,"native_write_batch":256})
    } else {
        json!({"receive_interval_micros":1000,"receive_packets":256,"send_batch":64,"native_read_batch":64,"native_write_batch":64})
    };
    let pending_bytes: usize = if high_bdp { 8 << 20 } else { 1536000 };
    let credit = if high_bdp {
        let ceiling_datagrams = (peak_rate / 4_000).clamp(8_192, 32_768);
        let ceiling_bytes = (peak_rate / 2).clamp(16 << 20, 64 << 20);
        json!({"floor_datagrams":128,"ceiling_datagrams":ceiling_datagrams,"floor_bytes":204800,"ceiling_bytes":ceiling_bytes,"period_micros":5000,"idle_period_micros":250000})
    } else {
        json!({"floor_datagrams":64,"ceiling_datagrams":8192,"floor_bytes":102400,"ceiling_bytes":16777216,"period_micros":10000,"idle_period_micros":250000})
    };
    json!({
        "version":1,"backend":"common_records_v2","initial_index":0,
        "compact_wire":{"version":3,"data_protection":"chacha20-poly1305","max_forward_packets":2147483647u32,"max_failed_checks":4294967295u32},
        "transaction":{"retry_ms":200,"phase_timeout_ms":2000,"reconcile_timeout_ms":5000,"max_operation_ms":10000,"retained_bytes":retained_bytes},
        "runtime":{
            "control_epoch":1,"data_epoch":1,"legacy_policy":{"transaction_micros":10_000_000,"max_outbound":32},
            "security":{"packets_per_key":l2tunnel_security::MAX_PACKETS_PER_KEY,"max_body_bytes_per_key":l2tunnel_security::MAX_BODY_BYTES_PER_KEY},
            "control":{"recovery":{"max_source_bytes":256,"send_bytes":16384,"receive_bytes":16384,"send_records":64,"receive_records":64,"initial_rto_micros":120000,"maximum_rto_micros":500000,"ack_delay_micros":5000,"max_retries":8},"interval_micros":10000,"packets_per_interval":16,"bytes_per_interval":16384},
            "streams":{"transaction":message.clone(),"liveness":message.clone(),"data_feedback":message},
            "wire":{"initiator_burst_bytes":descriptor.local(Role::Client).send().common().burst_bytes(),"responder_burst_bytes":descriptor.local(Role::Server).send().common().burst_bytes()},
            "work":work,
            "native":{"pending_packets":1024,"pending_bytes":pending_bytes,"stall_timeout_micros":NATIVE_STALL_US},
            "lifetime":{"lease_micros":lease_micros,"ping_interval_micros":1_000_000,"pong_timeout_micros":5_000_000},
            "credit":credit,
            "report_interval_micros":1_000_000
        },"rolling_work":null
    })
}
fn policy(carrier: Carrier, client: bool) -> Option<Value> {
    match carrier {
        Carrier::Udp => None,
        Carrier::Raw | Carrier::RawTlsLike => {
            Some(json!({"version":1,"profile":"raw-common-carrier-v1",
            "forward":{"local":if client {"192.0.2.2:24440"} else {"192.0.2.6:24441"},"peer":if client {"192.0.2.6:24441"} else {"192.0.2.2:24440"}},"reverse":null,
            "packet":{"mtu":1500,"protection":"aead","queue_packets":64,"horizon_bytes":1048576,"minimum_transfer_bytes":65536,"bytes_per_second":12500000,"packets_per_second":100000,"burst_bytes":65536,"burst_packets":256,"max_key_packets":1073741824u64,"max_key_bytes":68719476736u64}}))
        }
        Carrier::Tls | Carrier::Quic => {
            let quic = matches!(carrier, Carrier::Quic);
            let physical = carrier.physical_allowance();
            Some(
                json!({"version":1,"first":{"client":"192.0.2.2:24440","server":"192.0.2.6:24441"},"second":null,
                "geometry":{"path_mtu":1500,"max_record_bytes":1500-physical,"max_bootstrap_bytes":1500-physical-if quic {48} else {0},"charged_overhead_bytes":physical,"bootstrap_overhead_bytes":physical+if quic {48} else {0},"framing_bytes":if quic {0} else {5}},
                "transport":if quic {json!({"kind":"quic","application_id":[76,50,84,66,69,78,67,72,77,65,84,82,73,88,48,49],"queued_datagrams":1024,"control_window_bytes":65536,"idle_timeout_micros":30000000,"io_timeout_micros":5_000_000})} else {json!({"kind":"tls","record_timeout_micros":5_000_000})}}),
            )
        }
    }
}
fn cli(carrier: Carrier, client: bool, algorithm: Algorithm) -> Vec<String> {
    let ethernet = matches!(
        algorithm,
        Algorithm::KcpLikeL2(..) | Algorithm::SwiftTap { .. }
    );
    let max_packet = match algorithm {
        Algorithm::KcpLikeL2(..) => "1514",
        Algorithm::SwiftTap { .. } => "1522",
        _ => "1500",
    };
    let compression = match algorithm {
        Algorithm::KcpLikeL2(native, _) if native.uses_lz4() => "lz4",
        _ => "off",
    };
    let mut result = vec![
        "--carrier",
        carrier.cli(),
        "--record-profile",
        "common",
        "--duplex",
        "full",
        "--compression",
        compression,
        "--layer",
        if ethernet { "tap" } else { "tun" },
        "--max-packet",
        max_packet,
        "--max-path-mtu",
        "1500",
        "--noise-profile",
        "ik",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    if matches!(carrier, Carrier::Udp) {
        result.extend(
            [
                "--udp-bind",
                if client {
                    "192.0.2.2:24440"
                } else {
                    "192.0.2.6:24441"
                },
                "--udp-peer",
                if client {
                    "192.0.2.6:24441"
                } else {
                    "192.0.2.2:24440"
                },
            ]
            .into_iter()
            .map(str::to_owned),
        );
    } else if matches!(carrier, Carrier::RawTlsLike) {
        result.extend(["--udp-cover", "tls-like"].into_iter().map(str::to_owned));
    } else {
        result.extend(["--udp-cover", "quic-like"].into_iter().map(str::to_owned));
    }
    if matches!(carrier, Carrier::Raw | Carrier::RawTlsLike) {
        result.extend(["--raw-mark", "305790977"].into_iter().map(str::to_owned));
    }
    result
}
fn export_row(
    directory: &Path,
    row: &Row,
    carrier: Carrier,
    reverse_burst: Option<usize>,
    lease_micros: u64,
    forward_rate: u64,
    reverse_rate: u64,
) -> Result<Value> {
    if matches!(row.algorithm, Algorithm::PackedC48 { source_wire, .. } if source_wire.is_near8())
        && !matches!(carrier, Carrier::Udp)
    {
        return Err("near8 needs an all-traffic complete-IP socket receipt".into());
    }
    let id = format!("{}-{}", row.id, carrier.id());
    let peak_rate = forward_rate.max(reverse_rate);
    let high_bdp = peak_rate > BASELINE_FORWARD_RATE;
    let selected = profile(row.algorithm, carrier, peak_rate)?;
    let descriptor = c::Descriptor::new(
        MTU,
        Duplex::Full,
        mode_direction(
            row.algorithm,
            forward_rate,
            wire_burst(forward_rate, high_bdp),
            peak_rate,
        )?,
        mode_direction(
            row.algorithm,
            reverse_rate,
            reverse_burst.unwrap_or_else(|| wire_burst(reverse_rate, high_bdp)),
            peak_rate,
        )?,
        selected,
    )?;
    let mut bytes = [0; c::DESCRIPTOR_BYTES];
    descriptor.encode_into(&mut bytes)?;
    let encoded = hex(&bytes);
    let catalog = c::Catalog::new(descriptor, &[descriptor])?;
    let configuration = c::Configuration::new(c::EnvelopeDigest::new([0x42; 32]), descriptor)?;
    let coded = matches!(
        row.algorithm,
        Algorithm::Rolling { .. } | Algorithm::PackedC48 { .. } | Algorithm::Research(_)
    );
    let ack = matches!(row.algorithm, Algorithm::PackedC48 { .. }).then_some(
        pipeline::ack_coalescing::Policy {
            selection: pipeline::ack_coalescing::Selection::Benchmark,
            interval: Duration::from_millis(5),
            max_hold: Duration::from_millis(20),
            max_flows: 64,
            max_ack_bytes: 128,
        },
    );
    let ingress = coded.then_some(rolling_records::IngressLimits {
        slots: 256,
        capacity_bytes: 1 << 20,
    });
    let mut plans = [0usize; 2];
    for (slot, role) in plans.iter_mut().zip([Role::Client, Role::Server]) {
        let plan = engine::storage::Plan::for_engine_with_compact_wire(
            configuration,
            engine::Context {
                session: 1,
                epoch: 1,
                role,
            },
            geometry(carrier),
            engine::NativeLimits {
                stall_micros: NATIVE_STALL_US,
            },
            ack,
            ingress,
            carrier.overhead(),
        )?;
        *slot = plan.capacity_bytes();
    }
    let retained = plans
        .into_iter()
        .max()
        .ok_or("missing role plan")?
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(64 << 20))
        .ok_or("runtime reserve overflow")?;
    let mut document = runtime_document(retained, &descriptor, lease_micros, peak_rate);
    document["catalog"] = json!([encoded]);
    if let Some(ack) = ack {
        let role = json!({"selection":"benchmark","interval_micros":ack.interval.as_micros(),
            "max_hold_micros":ack.max_hold.as_micros(),"max_flows":ack.max_flows,"max_ack_bytes":ack.max_ack_bytes});
        document["ack_coalescing"] = json!({"initiator":role,"responder":role});
    }
    if coded {
        document["rolling_work"] = json!({"field":65536,"copies":65536,"metadata":65536});
        document["rolling_ingress"] = json!({"initiator":{"slots":256,"capacity_bytes":1048576},"responder":{"slots":256,"capacity_bytes":1048576}});
    }
    if matches!(
        row.algorithm,
        Algorithm::Connections { raw_ack: true } | Algorithm::PythonCompact
    ) {
        document["connection_ingress"] = json!({"initiator":{"slots":256,"capacity_bytes":1048576},"responder":{"slots":256,"capacity_bytes":1048576}});
    }
    let plan_name = format!("{id}.common.json");
    write_json(&directory.join(&plan_name), &document)?;
    let mut policies = Value::Null;
    for (side, client) in [("a", true), ("b", false)] {
        if let Some(value) = policy(carrier, client) {
            let path = format!("{id}.{side}.carrier.json");
            #[cfg(unix)]
            if matches!(carrier, Carrier::Raw | Carrier::RawTlsLike) {
                l2tunnel_client_core::raw_packet::common::Settings::from_json(&serde_json::to_vec(
                    &value,
                )?)
                .map_err(|error| format!("raw carrier policy validation: {error}"))?;
            }
            write_json(&directory.join(&path), &value)?;
            if policies.is_null() {
                policies = json!({});
            }
            policies[side] = json!(path);
        }
    }
    let ordinary = matches!(row.algorithm, Algorithm::Aligned { .. });
    let ethernet = matches!(row.algorithm, Algorithm::KcpLikeL2(..));
    let mut result = json!({
        "id":id,"status":"ready","algorithm":row.family,"variant":row.variant,"carrier":carrier.id(),
        "layer":if ethernet {"tap"} else {"tun"},"duplex":"full","common_plan":plan_name,"carrier_policy":policies,
        "policy_flag":match carrier {Carrier::Udp=>Value::Null,Carrier::Raw|Carrier::RawTlsLike=>json!("--raw-policy"),Carrier::Tls|Carrier::Quic=>json!("--maintained-policy")},
        "required_cli":{"a":cli(carrier,true,row.algorithm),"b":cli(carrier,false,row.algorithm)},
        "expected_descriptor_hex":encoded,"descriptor_digest_hex":hex(digest::digest(&digest::SHA256,&bytes).as_ref()),
        "descriptor_digest_definition":"SHA256 of exact unanchored descriptor bytes; not the session H0",
        "catalog_digest_hex":hex(catalog.root().as_bytes()),"record_profile_debug":format!("{selected:?}"),
        "validation":"both selected compact Engine storage plans accepted; daemon inspection and real carrier/native execution remain required",
        "parameters":{"path_mtu":MTU,"maximum_native_bytes":MTU,"channels":CHANNELS,"symbol_capacity":carrier.symbol(),"max_packed_units":UNITS,"inner_payload_compression":"off","header_policy":"IpHeaders except Swift's own header codec","data_protection":"chacha20-poly1305","record_protection_overhead":21,"carrier_admission_allowance":carrier.physical_allowance(),"allowance_is_measured_wire_cost":false,"engine_capacity_bytes_by_role":plans,"runtime_retained_bytes":retained,"source_window":if ordinary {64} else if matches!(row.algorithm,Algorithm::Swift{..}|Algorithm::SwiftTap{..}) {swift_flow_sources(peak_rate)} else if matches!(row.algorithm,Algorithm::Connections{..}) {512} else {8192},"source_window_domain":if matches!(row.algorithm,Algorithm::Swift{..}|Algorithm::SwiftTap{..}) {"per Swift channel"} else if matches!(row.algorithm,Algorithm::Connections{..} | Algorithm::PythonCompact) {"per independent owner,16owners"} else {"shared recovery direction"}},
        "limitations":if ordinary {json!(["Ordinary selective-repeat has a production hard64-source window shared across channels; it may be BDP-limited well below100Mbit/s."])} else {json!([])},
        "evidence_scope":"canonical plan preflight only; not throughput, loss-recovery or native qualification"
    });
    if let Algorithm::KcpLikeL2(native, _) = row.algorithm {
        let effective = c::Descriptor::decode(&bytes)?;
        result["requested_mode"] = l2tunnel_client_core::kcp_like_l2::selected(&descriptor)
            .ok_or("missing requested KCP-like profile")?;
        result["effective_mode"] = l2tunnel_client_core::kcp_like_l2::selected(&effective)
            .ok_or("missing encoded KCP-like profile")?;
        result["effective_mode_scope"] = json!(
            "decoded and admitted descriptor; live session status is reported by service inspection"
        );
        result["parameters"]["symbol_capacity"] =
            result["effective_mode"]["forward"]["symbol_bytes"].clone();
        result["parameters"]["maximum_native_bytes"] = json!(ETHERNET_FRAME);
        result["parameters"]["recovery_byte_budget_domain"] =
            json!("encoded Compact source bytes retained per direction");
        result["parameters"]["inner_payload_compression"] = json!(if native.uses_lz4() {
            "lz4_only_if_smaller"
        } else {
            "off"
        });
        result["parameters"]["header_policy"] = json!(format!("{native:?}"));
    }
    if let c::Profile::Striped { forward, reverse } = selected {
        result["requested_directions"] =
            json!({"forward": striped_resources(forward)?, "reverse": striped_resources(reverse)?});
        result["parameters"]["symbol_capacity"] = json!(forward.packing.packing.symbol_bytes);
        result["parameters"]["header_policy"] = json!(format!(
            "{:?} forward, {:?} reverse",
            forward.native_policy, reverse.native_policy
        ));
    }
    if matches!(
        row.algorithm,
        Algorithm::PackedC48 {
            forward_headers: aligned::NativePolicy::FixedAnchorIpHeaders,
            ..
        }
    ) {
        result["parameters"]["header_policy"] =
            json!("FixedAnchorIpHeaders forward, IpHeaders reverse");
    }
    if matches!(row.algorithm, Algorithm::PackedC48 { reverse_wire, .. } if reverse_wire.compresses_packed_acks())
    {
        result["parameters"]["reverse_packed_source_encoding"] = json!(
            "LZ4 block only for eligible packed ACK sources when smaller; otherwise exact source"
        );
    }
    if reverse_burst.is_some() {
        let forward = descriptor.local(Role::Client).send().common();
        let reverse = descriptor.local(Role::Server).send().common();
        result["wire_pacing"] = json!({
            "forward_bytes_per_second":forward.bytes_per_second(),
            "reverse_bytes_per_second":reverse.bytes_per_second(),
            "forward_burst_bytes":forward.burst_bytes(),
            "reverse_burst_bytes":reverse.burst_bytes(),
        });
    }
    if matches!(row.algorithm, Algorithm::PythonCompact) {
        result["python_reference"] = json!({
            "schema":1,"id":"compact-arq-quic-overhead",
            "reference_sha256":"9e98202e40cff58c7506e1eedbbf31079e520019f97ebef786b717e6ed983df8",
            "claim":"algorithm_configuration_only",
            "actual":l2tunnel_client_core::python_reference::actual(&descriptor),
            "remaining_differences":["codec_geometry","real_crypto_wire","kernel_tcp","finite_retry_history","acceptance_clock","measurement_window"]
        });
    }
    Ok(result)
}
fn fixed_anchor_row(ack_lz4: bool) -> Row {
    use fec::rolling::wire::SourceWire;
    let (id, variant, reverse_wire) = if ack_lz4 {
        (
            "packed-c48-near8-fixed-anchor-ack-lz4",
            "targeted-near8-forward-fixed-anchor-reverse-packed-ack-lz4",
            SourceWire::TargetedExactAckLz4,
        )
    } else {
        (
            "packed-c48-near8-fixed-anchor",
            "targeted-near8-forward-fixed-anchor-headers",
            SourceWire::TargetedExact,
        )
    };
    Row {
        id,
        family: "rolling_copies",
        variant,
        algorithm: Algorithm::PackedC48 {
            source_wire: SourceWire::TargetedNear8,
            reverse_wire,
            forward_headers: aligned::NativePolicy::FixedAnchorIpHeaders,
        },
    }
}
fn headroom_row() -> Row {
    use fec::rolling::wire::SourceWire;
    Row {
        id: "packed-c48-near8-headroom-fixed-anchor-ack-lz4",
        family: "rolling_copies",
        variant: "targeted-near8-headroom-forward-fixed-anchor-reverse-packed-ack-lz4",
        algorithm: Algorithm::PackedC48 {
            source_wire: SourceWire::TargetedNear8Headroom,
            reverse_wire: SourceWire::TargetedExactAckLz4,
            forward_headers: aligned::NativePolicy::FixedAnchorIpHeaders,
        },
    }
}

fn striped_resources(direction: l2tunnel::striped_records::Direction) -> Result<Value> {
    let transmit =
        fec::striped_group::TransmitPlan::for_window(direction.profile, direction.source_limit)?;
    let receive = fec::striped_group::ReceivePlan::for_window(
        direction.profile,
        direction.source_limit,
        direction.expanded_limit,
    )?;
    Ok(json!({
        "data_cells": direction.profile.data_cells,
        "parity_cells": direction.profile.parity_cells,
        "source_limit": direction.source_limit,
        "group_hold_micros": direction.hold_micros,
        "packing_symbol_bytes": direction.packing.packing.symbol_bytes,
        "physical_overhead_bytes": direction.overhead_bytes,
        "mixed_plaintext_limit": direction.profile.max_wire_bytes,
        "transmit_window_planned_bytes": transmit.capacity_bytes(),
        "receive_window_planned_bytes":receive.capacity_bytes(),
        "receive_row_bytes":receive.row_bytes(),
        "receive_index_bytes":receive.index_bytes(),
        "receive_gf_scratch_bytes":receive.recovery_bytes(),
        "native_dependency_index_bytes":l2tunnel::striped_records::native::NativeReceiver::custody_planned_bytes(direction)?,
        "named_retry_and_wire_buffer_bytes":fec::striped_group::schedule::ScheduledSender::auxiliary_planned_bytes(direction.profile,direction.source_limit)?,
        "receive_timer_index_bytes":fec::striped_group::schedule::ScheduledReceiver::auxiliary_planned_bytes(direction.source_limit)?,
        "native_encoder_planned_bytes": direction.packing_plan()?.capacity_bytes(),
        "native_decoder_planned_bytes": direction.receiver_plan()?.capacity_bytes(),
        "receive_expanded_row_allowance_bytes": direction.expanded_limit
    }))
}
fn run() -> Result<()> {
    let raw_arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut arguments = Vec::with_capacity(raw_arguments.len());
    let mut lease_seconds: u64 = 120;
    let mut forward_rate: u64 = 12_500_000;
    let mut reverse_rate: u64 = 1_250_000;
    let mut idx = 0;
    while idx < raw_arguments.len() {
        if raw_arguments[idx] == "--lease-seconds" {
            let value = raw_arguments
                .get(idx + 1)
                .and_then(|arg| arg.to_str())
                .ok_or("missing --lease-seconds value")?;
            let parsed: u64 = value
                .parse()
                .map_err(|_| "invalid --lease-seconds integer")?;
            if !(30..=3600).contains(&parsed) {
                return Err("--lease-seconds must be within 30..=3600".into());
            }
            lease_seconds = parsed;
            idx += 2;
            continue;
        }
        if raw_arguments[idx] == "--symmetric-rate" {
            let value = raw_arguments
                .get(idx + 1)
                .and_then(|arg| arg.to_str())
                .ok_or("--symmetric-rate requires a bytes/second value")?;
            let parsed = value
                .parse::<u64>()
                .map_err(|_| "--symmetric-rate must be an integer bytes/second value")?;
            if !(1_250_000..=1_250_000_000).contains(&parsed) {
                return Err("--symmetric-rate must be between 1250000 and 1250000000 B/s".into());
            }
            forward_rate = parsed;
            reverse_rate = parsed;
            idx += 2;
            continue;
        }
        if raw_arguments[idx] == "--budget-mbps" {
            let value = raw_arguments
                .get(idx + 1)
                .and_then(|arg| arg.to_str())
                .ok_or("--budget-mbps requires FWD/REV (e.g. 200/20, 500/50, 1000/100)")?;
            let (fwd, rev) = parse_budget_mbps(value)?;
            forward_rate = fwd;
            reverse_rate = rev;
            idx += 2;
            continue;
        }
        arguments.push(raw_arguments[idx].clone());
        idx += 1;
    }
    let lease_micros = lease_seconds * 1_000_000;
    let c48_pair = arguments.len() == 3 && arguments[2] == "--packed-c48-pair";
    let striped = match arguments.get(2).and_then(|arg| arg.to_str()) {
        Some("--striped-5-4") => Some((
            "striped-5-4",
            "five-members-four-required-fixed-anchor",
            (4, 1),
            500,
            aligned::NativePolicy::FixedAnchorIpHeaders,
        )),
        Some("--striped-5-4-forward-hold") => Some((
            "striped-5-4-forward-hold",
            "five-members-four-required-forward-hold-1500us",
            (4, 1),
            1500,
            aligned::NativePolicy::FixedAnchorIpHeaders,
        )),
        Some("--striped-12-10") => Some((
            "striped-12-10",
            "twelve-members-ten-required-forward-hold-1500us",
            (10, 2),
            1500,
            aligned::NativePolicy::FixedAnchorIpHeaders,
        )),
        Some("--striped-12-10-raw-ip") => Some((
            "striped-12-10-raw-ip",
            "twelve-members-ten-required-forward-hold-1500us-raw-ip",
            (10, 2),
            1500,
            aligned::NativePolicy::RawIp,
        )),
        _ => None,
    };
    let headroom_pair = arguments.len() == 3 && arguments[2] == "--packed-c48-headroom-pair";
    let kcp_l2 = arguments.len() == 3 && arguments[2] == "--kcp-like-l2";
    let near8 = arguments.len() == 3 && arguments[2] == "--packed-c48-near8";
    let hold_pair = arguments.len() == 3 && arguments[2] == "--packed-c48-reorder-pair";
    let prefix_pair = arguments.len() == 3 && arguments[2] == "--packed-c48-prefix-pair";
    let reverse_pacing_pair =
        arguments.len() == 3 && arguments[2] == "--packed-c48-reverse-pacing-pair";
    let anchor_pair = arguments.len() == 3 && arguments[2] == "--packed-c48-fixed-anchor-pair";
    let ack_lz4_pair =
        arguments.len() == 3 && arguments[2] == "--packed-c48-fixed-anchor-ack-lz4-pair";
    let raw_tls_like = arguments.len() == 3 && arguments[2] == "--raw-tls-like";
    let swift_tap = arguments.len() == 3 && arguments[2] == "--swift-tap";
    let supported = match arguments.len() {
        2 | 4 => true,
        3 => {
            kcp_l2
                || swift_tap
                || c48_pair
                || striped.is_some()
                || headroom_pair
                || near8
                || hold_pair
                || prefix_pair
                || reverse_pacing_pair
                || anchor_pair
                || ack_lz4_pair
                || raw_tls_like
        }
        _ => false,
    };
    if !supported || arguments[0] != "--output-dir" {
        return Err("usage: common_benchmark_plan --output-dir NEW_DIRECTORY [--kcp-like-l2 | --striped-5-4 | --striped-5-4-forward-hold | --striped-12-10 | --striped-12-10-raw-ip | --packed-c48-pair | --packed-c48-near8 | --packed-c48-reorder-pair | --packed-c48-prefix-pair | --packed-c48-reverse-pacing-pair | --packed-c48-fixed-anchor-pair | --packed-c48-fixed-anchor-ack-lz4-pair | --packed-c48-headroom-pair | --python-reference compact-arq-quic-overhead]".into());
    }
    let named = arguments.len() == 4;
    if named
        && (arguments[2] != "--python-reference" || arguments[3] != "compact-arq-quic-overhead")
    {
        return Err("unsupported named Python reference; no fallback selection".into());
    }
    let selected_rows =
        if let Some((id, variant, forward_cells, forward_hold_micros, forward_headers)) = striped {
            vec![Row {
                id,
                family: "striped",
                variant,
                algorithm: Algorithm::Striped {
                    forward_cells,
                    forward_hold_micros,
                    forward_headers,
                },
            }]
        } else if kcp_l2 {
            kcp_like_rows()
        } else if swift_tap {
            vec![
                Row {
                    id: "swift-tap-arq",
                    family: "swift",
                    variant: "ethernet-vlan-repair-ratio-zero",
                    algorithm: Algorithm::SwiftTap { fec: false },
                },
                Row {
                    id: "swift-tap-fec",
                    family: "swift",
                    variant: "ethernet-vlan-repair-1-of-4",
                    algorithm: Algorithm::SwiftTap { fec: true },
                },
            ]
        } else if c48_pair {
            vec![
                Row {
                    id: "packed-c48-control",
                    family: "rolling_copies",
                    variant: "exact-regular-fec",
                    algorithm: Algorithm::PackedC48 {
                        source_wire: fec::rolling::wire::SourceWire::Exact,
                        reverse_wire: fec::rolling::wire::SourceWire::Exact,
                        forward_headers: aligned::NativePolicy::IpHeaders,
                    },
                },
                Row {
                    id: "packed-c48-queue-aware",
                    family: "rolling_copies",
                    variant: "targeted-queue-aware-fec",
                    algorithm: Algorithm::PackedC48 {
                        source_wire: fec::rolling::wire::SourceWire::TargetedExact,
                        reverse_wire: fec::rolling::wire::SourceWire::TargetedExact,
                        forward_headers: aligned::NativePolicy::IpHeaders,
                    },
                },
            ]
        } else if headroom_pair {
            vec![fixed_anchor_row(true), headroom_row()]
        } else if ack_lz4_pair {
            vec![fixed_anchor_row(false), fixed_anchor_row(true)]
        } else if near8 || hold_pair || prefix_pair || reverse_pacing_pair || anchor_pair {
            let mut selected = vec![Row {
                id: "packed-c48-near8",
                family: "rolling_copies",
                variant: "targeted-near8-forward",
                algorithm: Algorithm::PackedC48 {
                    source_wire: fec::rolling::wire::SourceWire::TargetedNear8,
                    reverse_wire: fec::rolling::wire::SourceWire::TargetedExact,
                    forward_headers: aligned::NativePolicy::IpHeaders,
                },
            }];
            if hold_pair {
                selected.push(Row {
                    id: "packed-c48-near8-hold35",
                    family: "rolling_copies",
                    variant: "targeted-near8-forward-tcp-hold35",
                    algorithm: Algorithm::PackedC48 {
                        source_wire: fec::rolling::wire::SourceWire::TargetedNear8Hold35,
                        reverse_wire: fec::rolling::wire::SourceWire::TargetedExact,
                        forward_headers: aligned::NativePolicy::IpHeaders,
                    },
                });
            }
            if reverse_pacing_pair {
                selected.push(Row {
                    id: REVERSE_PACED_ID,
                    family: "rolling_copies",
                    variant: "targeted-near8-reverse-burst-4096",
                    algorithm: selected[0].algorithm,
                });
            }
            if anchor_pair {
                selected.push(fixed_anchor_row(false));
            }
            if prefix_pair {
                selected.push(Row {
                    id: "packed-c48-near8-prefix",
                    family: "rolling_copies",
                    variant: "targeted-near8-confirmed-prefix",
                    algorithm: Algorithm::PackedC48 {
                        source_wire: fec::rolling::wire::SourceWire::TargetedNear8ConfirmedPrefix,
                        reverse_wire: fec::rolling::wire::SourceWire::TargetedExact,
                        forward_headers: aligned::NativePolicy::IpHeaders,
                    },
                });
            }
            selected
        } else if named {
            vec![Row {
                id: "python-compact-arq",
                family: "per_connection_compact",
                variant: "quic-overhead-8192-feedback5ms64-lossy-native-acks",
                algorithm: Algorithm::PythonCompact,
            }]
        } else {
            rows()
        };
    let carriers: &[Carrier] = if raw_tls_like {
        &[Carrier::RawTlsLike]
    } else if swift_tap {
        &[Carrier::Udp]
    } else {
        &[Carrier::Udp, Carrier::Raw, Carrier::Tls, Carrier::Quic]
    };
    let all_rows = selected_rows.len() * carriers.len();
    let directory = Path::new(&arguments[1]);
    std::fs::create_dir(directory)?;
    let mut exported = Vec::new();
    for row in selected_rows {
        let reverse_burst = reverse_pacing_pair.then_some(if row.id == REVERSE_PACED_ID {
            4096
        } else {
            DEFAULT_BURST_BYTES
        });
        for &carrier in carriers {
            match export_row(
                directory,
                &row,
                carrier,
                reverse_burst,
                lease_micros,
                forward_rate,
                reverse_rate,
            ) {
                Ok(value) => exported.push(value),
                Err(error) if error.is::<std::io::Error>() || error.is::<serde_json::Error>() => {
                    return Err(error);
                }
                Err(error) => {
                    let mut refusal = json!({"id":format!("{}-{}",row.id,carrier.id()),"status":"plan_refused","reason":error.to_string(),"algorithm":row.family,"variant":row.variant,"carrier":carrier.id(),"validation":"generated configuration refused; requires diagnosis and does not establish an unsupported algorithm"});
                    if matches!(row.algorithm, Algorithm::Striped { .. })
                        && let Ok(c::Profile::Striped { forward, reverse }) =
                            profile(row.algorithm, carrier, forward_rate.max(reverse_rate))
                    {
                        refusal["requested_directions"] = json!({
                            "forward": striped_resources(forward)?,
                            "reverse": striped_resources(reverse)?,
                        });
                        refusal["effective_mode"] = Value::Null;
                    }
                    exported.push(refusal);
                }
            }
        }
    }
    let ready = exported
        .iter()
        .filter(|value| value["status"] == "ready")
        .count();
    let manifest = json!({"version":1,"kind":"current-common-native-matrix","baseline":{"ip_family":4,"duplex":"full","layer":"tun","tcp_flows":16,"forward_mbit_s":forward_rate / 125_000,"reverse_mbit_s":reverse_rate / 125_000,"nominal_rtt_ms":70,"one_way_delay_ms":35,"loss_percent_each_way":15,"warmup_seconds":2,"sample_seconds":10,"directions":["forward","reverse","simultaneous"],"mtu":1500},"rows":exported,"ready_rows":ready,"all_rows":all_rows,"not_covered":["Unimplemented Python catalog modes remain parity gaps; these rows enumerate current connected owners, not all47 acceptance gates.","Windows, Android, public ISP classification and middlebox passage are not measured by this Linux namespace matrix.","Half duplex, compression-policy alternatives and proxy are separate functional selections; this manifest is the explicitly chosen Full native TUN baseline."],"metric_boundary":"Actual captured IP bytes and receiver application bytes; configured allowances are never substituted for physical wire bytes."});
    let mut manifest = manifest;
    if kcp_l2 {
        manifest["baseline"]["layer"] = json!("tap");
        manifest["baseline"]["tcp_flows"] = json!(1);
        manifest["baseline"]["maximum_native_frame_bytes"] = json!(ETHERNET_FRAME);
        manifest["not_covered"] = json!([
            "Export does not qualify native TAP execution, throughput or operating system support.",
            "The Common KCP-like recovery policy uses the authenticated tunnel wire format. Standard KCP wire interoperability is outside these profiles."
        ]);
    }
    write_json(&directory.join("manifest.json"), &manifest)?;
    println!(
        "{}",
        json!({"manifest":directory.join("manifest.json"),"ready_rows":ready,"all_rows":all_rows})
    );
    Ok(())
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_recovery::{
        CompactRepeat, EndpointRole, RecoveryContext, RecoveryEngine, SourceId,
    };

    fn descriptor(algorithm: Algorithm, carrier: Carrier) -> Result<c::Descriptor> {
        Ok(c::Descriptor::new(
            MTU,
            Duplex::Full,
            mode_direction(
                algorithm,
                BASELINE_FORWARD_RATE,
                DEFAULT_BURST_BYTES,
                BASELINE_FORWARD_RATE,
            )?,
            mode_direction(
                algorithm,
                1_250_000,
                DEFAULT_BURST_BYTES,
                BASELINE_FORWARD_RATE,
            )?,
            profile(algorithm, carrier, BASELINE_FORWARD_RATE)?,
        )?)
    }

    #[test]
    fn high_bdp_budgets_scale_swift_aligned_and_runtime_windows() -> Result<()> {
        for spec in ["200/20", "300/30", "500/50", "1000/100"] {
            let (fwd, rev) = parse_budget_mbps(spec)?;
            let peak = fwd.max(rev);
            for algorithm in [
                Algorithm::Swift { fec: false },
                Algorithm::Swift { fec: true },
                Algorithm::Aligned {
                    packed: false,
                    fec: true,
                },
                Algorithm::Aligned {
                    packed: true,
                    fec: true,
                },
            ] {
                let selected = profile(algorithm, Carrier::Udp, peak)?;
                let desc = c::Descriptor::new(
                    MTU,
                    Duplex::Full,
                    mode_direction(algorithm, fwd, wire_burst(fwd, true), peak)?,
                    mode_direction(algorithm, rev, wire_burst(rev, true), peak)?,
                    selected,
                )?;
                let mut bytes = [0; c::DESCRIPTOR_BYTES];
                desc.encode_into(&mut bytes)?;
                assert_eq!(c::Descriptor::decode(&bytes)?, desc);
                let doc = runtime_document(256 << 20, &desc, 120_000_000, peak);
                assert!(doc["runtime"]["work"]["receive_packets"].as_u64() >= Some(1024));
                assert!(doc["runtime"]["work"]["send_batch"].as_u64() >= Some(256));
                assert!(doc["runtime"]["credit"]["ceiling_datagrams"].as_u64() >= Some(8192));
            }
        }
        Ok(())
    }

    #[test]
    fn fixed_anchor_pair_negotiates_only_the_forward_header_change() -> Result<()> {
        let row = |forward_headers| {
            descriptor(
                Algorithm::PackedC48 {
                    source_wire: fec::rolling::wire::SourceWire::TargetedNear8,
                    reverse_wire: fec::rolling::wire::SourceWire::TargetedExact,
                    forward_headers,
                },
                Carrier::Udp,
            )
        };
        let ordinary = row(aligned::NativePolicy::IpHeaders)?;
        let anchored = row(aligned::NativePolicy::FixedAnchorIpHeaders)?;
        let mut bytes = [0; c::DESCRIPTOR_BYTES];
        anchored.encode_into(&mut bytes)?;
        assert_eq!(c::Descriptor::decode(&bytes)?, anchored);
        let c::Profile::RollingCopies {
            config: mut expected,
            stream,
            copies,
        } = *ordinary.profile()
        else {
            return Err("missing ordinary rolling configuration".into());
        };
        assert_eq!(
            expected.reverse.native_policy,
            aligned::NativePolicy::IpHeaders
        );
        expected.forward.native_policy = aligned::NativePolicy::FixedAnchorIpHeaders;
        assert_eq!(
            *anchored.profile(),
            c::Profile::RollingCopies {
                config: expected,
                stream,
                copies
            }
        );
        let envelope = c::EnvelopeDigest::new([0x42; 32]);
        assert_ne!(
            c::Configuration::new(envelope, ordinary)?.digest()?,
            c::Configuration::new(envelope, anchored)?.digest()?
        );
        Ok(())
    }

    #[test]
    fn kcp_like_l2_status_preserves_unrepresentable_or_fractional_microseconds() -> Result<()> {
        let algorithm = Algorithm::KcpLikeL2(
            aligned::NativePolicy::RawEthernet,
            aligned::NativeDelivery::ProfileDefault,
        );
        let ordinary = descriptor(algorithm, Carrier::Udp)?;
        let mut forward = kcp_like_direction(
            Carrier::Udp,
            aligned::NativePolicy::RawEthernet,
            aligned::NativeDelivery::ProfileDefault,
        )?;
        let reverse = forward;
        let original = forward.base.recovery;
        let arq = original.arq();
        let timing = CompactTiming {
            nominal_rtt: Duration::new(u64::MAX, 999_999_999),
            feedback_interval: Duration::new(0, 1_001),
            ..arq.timing()
        };
        forward.base.recovery = CompactReliableConfig::new(
            CompactArqConfig::new(
                arq.bounds(),
                timing,
                arq.maximum_feedback_bytes(),
                arq.history_entries(),
                arq.maximum_attempts(),
                arq.recovery(),
            )?,
            original.outer_overhead_bytes(),
        )?;
        let selected = c::Descriptor::new(
            MTU,
            Duplex::Full,
            *ordinary.direction(Role::Client).common(),
            *ordinary.direction(Role::Server).common(),
            c::Profile::PackedCompact { forward, reverse },
        )?;
        let mut bytes = [0; c::DESCRIPTOR_BYTES];
        selected.encode_into(&mut bytes)?;
        let decoded = c::Descriptor::decode(&bytes)?;
        let facts = l2tunnel_client_core::kcp_like_l2::selected(&decoded)
            .ok_or("missing KCP-like settings")?;
        let f = &facts["forward"];
        assert_eq!(f.get("nominal_rtt_us"), Some(&Value::Null));
        assert_eq!(
            f["nominal_rtt_exact"],
            json!({"seconds":u64::MAX,"subsec_nanos":999_999_999})
        );
        assert_eq!(f["ack_interval_us"], 1);
        assert_eq!(
            f["ack_interval_exact"],
            json!({"seconds":0,"subsec_nanos":1_001})
        );
        assert_eq!(facts["reverse"]["ack_interval_us"], 1000);
        assert!(facts["reverse"].get("ack_interval_exact").is_none());
        Ok(())
    }

    #[test]
    fn kcp_like_l2_profiles_bind_the_carrier_budget_and_native_bytes() -> Result<()> {
        use codec::aligned_body::{BodyKind, Decoder, Encoder, Padding};
        let mut state = 194_511_u32;
        let incompressible: Vec<u8> = (0..ETHERNET_FRAME)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        for carrier in [Carrier::Udp, Carrier::Raw, Carrier::Tls, Carrier::Quic] {
            let mut descriptors = std::collections::HashSet::new();
            for row in kcp_like_rows() {
                let selected = descriptor(row.algorithm, carrier)?;
                let mut bytes = [0; c::DESCRIPTOR_BYTES];
                selected.encode_into(&mut bytes)?;
                assert!(descriptors.insert(bytes));
                let decoded = c::Descriptor::decode(&bytes)?;
                let actual = l2tunnel_client_core::kcp_like_l2::selected(&decoded)
                    .ok_or("missing negotiated KCP-like settings")?;
                assert_eq!(actual["forward"], actual["reverse"]);
                assert_eq!(actual["forward"]["fast_resend"], 2);
                assert_eq!(actual["forward"]["repair_symbols"], 0);
                assert_eq!(actual["forward"]["send_bytes"], 4 << 20);
                assert_eq!(actual["forward"]["receive_bytes"], 4 << 20);
                assert_eq!(
                    decoded.direction(Role::Client).common().traffic().layer,
                    traffic::NetworkLayer::Tap
                );
                let c::Profile::PackedCompact { forward, .. } = decoded.profile() else {
                    return Err("wrong recovery owner".into());
                };
                let ordered = row.id.ends_with("-ordered");
                assert_eq!(
                    forward.base.native_delivery == aligned::NativeDelivery::ChannelOrdered,
                    ordered
                );
                assert_eq!(
                    actual["forward"]["native_delivery_policy"],
                    if ordered {
                        "channel_ordered"
                    } else {
                        "profile_default"
                    }
                );
                if ordered {
                    assert_eq!(actual["forward"]["native_delivery"], "per_channel_ordered");
                }
                for client in [true, false] {
                    let args = cli(carrier, client, row.algorithm);
                    let option = |name: &str| {
                        args.chunks_exact(2)
                            .find(|v| v[0] == name)
                            .map(|v| v[1].as_str())
                    };
                    assert_eq!(option("--layer"), Some("tap"));
                    assert_eq!(option("--max-packet"), Some("1514"));
                    assert_eq!(
                        option("--compression"),
                        Some(if forward.base.native_policy.uses_lz4() {
                            "lz4"
                        } else {
                            "off"
                        })
                    );
                }
                assert_eq!(
                    forward.base.recovery.compact_wire_maximum_data_bytes()? + carrier.overhead(),
                    MTU
                );
                if !forward.base.native_policy.is_stateless() {
                    continue;
                }
                let mut encoder = Encoder::new(forward.base.receiver.body)?;
                let mut decoder = Decoder::new(forward.base.receiver.body)?;
                for frame in [vec![0; ETHERNET_FRAME], incompressible.clone()] {
                    let mut body = vec![0; encoder.max_encoded_len()];
                    let lz4 = forward.base.native_policy.uses_lz4();
                    let encoded = if lz4 {
                        encoder.encode_lz4(&frame, &mut body)?
                    } else {
                        encoder.encode_raw(&frame, &mut body)?
                    };
                    let expected = if lz4 && frame[0] == 0 && frame.iter().all(|&b| b == 0) {
                        BodyKind::Lz4
                    } else {
                        BodyKind::Raw
                    };
                    assert_eq!(encoded.kind, expected);
                    let mut restored = vec![0xa5; frame.len()];
                    decoder.decode_body(
                        &body[..encoded.body_len],
                        Padding::Exact,
                        &mut restored,
                    )?;
                    assert_eq!(restored, frame);
                }
            }
        }
        assert!(l2tunnel_client_core::kcp_like_l2::Geometry::new(64, 61, CHANNELS, UNITS).is_err());
        Ok(())
    }

    #[test]
    fn ack_lz4_pair_changes_only_the_authenticated_reverse_selector() -> Result<()> {
        use fec::rolling::wire::SourceWire;
        use l2tunnel_client_core::secure_udp::common_status::RollingWireProfile;
        let control = descriptor(fixed_anchor_row(false).algorithm, Carrier::Udp)?;
        let candidate = descriptor(fixed_anchor_row(true).algorithm, Carrier::Udp)?;
        let c::Profile::RollingCopies {
            config,
            stream,
            copies,
        } = *control.profile()
        else {
            return Err("expected rolling copies".into());
        };
        let mut expected = config;
        expected.reverse.scheduler.source_wire = SourceWire::TargetedExactAckLz4;
        assert_eq!(
            serde_json::to_value(RollingWireProfile::from(
                expected.reverse.scheduler.source_wire
            ))?,
            "targeted_exact_ack_lz4"
        );
        assert_eq!(
            *candidate.profile(),
            c::Profile::RollingCopies {
                config: expected,
                stream,
                copies
            }
        );
        let mut old = [0; c::DESCRIPTOR_BYTES];
        let mut new = [0; c::DESCRIPTOR_BYTES];
        control.encode_into(&mut old)?;
        candidate.encode_into(&mut new)?;
        assert_eq!(c::Descriptor::decode(&new)?, candidate);
        assert_eq!(
            old.iter()
                .zip(new)
                .filter(|(a, b)| **a != *b)
                .map(|(a, b)| (*a, b))
                .collect::<Vec<_>>(),
            [(5, 9)]
        );
        let envelope = c::EnvelopeDigest::new([0x42; 32]);
        assert_ne!(
            c::Configuration::new(envelope, control)?.digest()?,
            c::Configuration::new(envelope, candidate)?.digest()?
        );
        assert!(c::Catalog::new(candidate, &[control]).is_err());
        let validate = |cfg, with_copies| {
            c::Descriptor::new(
                MTU,
                Duplex::Full,
                *control.direction(Role::Client).common(),
                *control.direction(Role::Server).common(),
                if with_copies {
                    c::Profile::RollingCopies {
                        config: cfg,
                        stream,
                        copies,
                    }
                } else {
                    c::Profile::Rolling {
                        config: cfg,
                        stream,
                    }
                },
            )
        };
        assert!(validate(expected, false).is_err());
        let mut wrong = expected;
        wrong.forward.native_policy = aligned::NativePolicy::IpHeaders;
        assert!(validate(wrong, true).is_err());
        wrong = expected;
        wrong.reverse.native_policy = aligned::NativePolicy::FixedAnchorIpHeaders;
        assert!(validate(wrong, true).is_err());
        wrong = expected;
        std::mem::swap(&mut wrong.forward, &mut wrong.reverse);
        assert!(validate(wrong, true).is_err());
        Ok(())
    }

    #[test]
    fn headroom_pair_binds_only_the_forward_repair_selector() -> Result<()> {
        use fec::rolling::wire::SourceWire;
        use l2tunnel_client_core::secure_udp::common_status::RollingWireProfile;

        let control = descriptor(fixed_anchor_row(true).algorithm, Carrier::Udp)?;
        let candidate = descriptor(headroom_row().algorithm, Carrier::Udp)?;
        let mut original = [0; c::DESCRIPTOR_BYTES];
        let mut selected = [0; c::DESCRIPTOR_BYTES];
        control.encode_into(&mut original)?;
        candidate.encode_into(&mut selected)?;
        let changes: Vec<_> = original
            .into_iter()
            .zip(selected)
            .filter(|(a, b)| a != b)
            .collect();
        assert_eq!(changes, [(6, 10)]);
        let decoded = c::Descriptor::decode(&selected)?;
        assert_eq!(decoded, candidate);
        let c::Profile::RollingCopies { config, .. } = decoded.profile() else {
            return Err("expected rolling copies".into());
        };
        assert_eq!(
            config.reverse.scheduler.source_wire,
            SourceWire::TargetedExactAckLz4
        );
        assert_eq!(
            config.forward.scheduler.source_wire.version(),
            SourceWire::TargetedNear8.version()
        );
        assert_eq!(
            serde_json::to_value(RollingWireProfile::from(
                config.forward.scheduler.source_wire
            ))?,
            "targeted_near8_headroom"
        );
        let envelope = c::EnvelopeDigest::new([0x42; 32]);
        assert_ne!(
            c::Configuration::new(envelope, control)?.digest()?,
            c::Configuration::new(envelope, candidate)?.digest()?
        );
        Ok(())
    }

    #[test]
    fn named_selection_roundtrips_and_ordinary_rows_remain_distinct() -> Result<()> {
        for carrier in [Carrier::Udp, Carrier::Raw, Carrier::Tls, Carrier::Quic] {
            let selected = descriptor(Algorithm::PythonCompact, carrier)?;
            let mut bytes = [0; c::DESCRIPTOR_BYTES];
            selected.encode_into(&mut bytes)?;
            let decoded = c::Descriptor::decode(&bytes)?;
            let actual = l2tunnel_client_core::python_reference::actual(&decoded);
            assert_eq!(actual["recovery"], "compact_arq_guarded");
            assert_eq!(actual["owners_per_direction"], 16);
            assert_eq!(actual["source_window_per_owner"], 8192);
            assert_eq!(actual["feedback_interval_us"], 5000);
            assert_eq!(actual["feedback_packets"], 64);
            assert_eq!(actual["reverse_ack_path"], "lossy_unrecovered");
            let ordinary = descriptor(
                Algorithm::Aligned {
                    packed: false,
                    fec: true,
                },
                carrier,
            )?;
            assert!(l2tunnel_client_core::python_reference::actual(&ordinary).is_null());
            let c::Profile::Aligned { forward, .. } = ordinary.profile() else {
                return Err("ordinary Cauchy replaced".into());
            };
            // Wide-ACK window sized from bandwidth x RTT, not the old 64 cap.
            let expected = if matches!(carrier, Carrier::Udp | Carrier::Raw) {
                2048
            } else {
                4096
            };
            assert_eq!(forward.recovery.arq.send_records, expected);
            assert!(forward.recovery.arq.wide_feedback());
            assert_eq!(forward.recovery.arq.initial_rto, Duration::from_millis(200));
            let old = descriptor(Algorithm::Connections { raw_ack: true }, carrier)?;
            assert_eq!(
                l2tunnel_client_core::python_reference::actual(&old)["source_window_per_owner"],
                512
            );
        }
        Ok(())
    }

    #[test]
    fn selected_compact_owner_crosses64_and_retries_without_exponential_backoff() -> Result<()> {
        let selected = descriptor(Algorithm::PythonCompact, Carrier::Udp)?;
        let c::Profile::PerConnectionCompact { forward, .. } = selected.profile() else {
            return Err("wrong selected recovery".into());
        };
        let policy = forward.compact.recovery.arq();
        let context = RecoveryContext {
            session: 1,
            epoch: 1,
            role: EndpointRole::Initiator,
        };
        let mut owner = CompactRepeat::new(policy, context)?;
        owner.submit(b"hole", Duration::ZERO)?;
        let mut packet = vec![0; owner.send_max_packet_bytes()];
        for attempt in 0..3 {
            let now = Duration::from_millis(attempt * 150);
            assert!(owner.poll_source(now, &mut packet)?.is_some());
            let token = owner
                .pending_transmission(SourceId(0))
                .ok_or("missing physical attempt")?;
            owner.confirm_transmission_at(now, now, token)?;
            assert_eq!(
                owner.source_deadline(),
                Some(now + Duration::from_millis(150))
            );
            assert_eq!(owner.timing()?.rto, Duration::from_millis(150));
        }
        for source in 1..=64 {
            assert_eq!(owner.submit(b"later", Duration::from_millis(300))?, source);
        }
        assert_eq!(owner.next_source_id()?, SourceId(65));
        assert!(owner.failure().is_none());
        Ok(())
    }
}
