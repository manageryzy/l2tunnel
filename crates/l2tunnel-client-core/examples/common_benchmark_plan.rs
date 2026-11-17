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

#[derive(Clone, Copy)]
enum Carrier {
    Udp,
    Raw,
    Tls,
    Quic,
}
impl Carrier {
    fn id(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Raw => "raw",
            Self::Tls => "tls",
            Self::Quic => "quic",
        }
    }
    fn cli(self) -> &'static str {
        match self {
            Self::Udp => "quic-like",
            Self::Raw => "raw-packet",
            Self::Tls => "tcp",
            Self::Quic => "quic",
        }
    }
    fn physical_allowance(self) -> usize {
        match self {
            Self::Udp => 28,
            Self::Raw => 40,
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
    Swift {
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
    Research(fec::research::Profile),
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
fn aligned_config(carrier: Carrier, packed: bool, with_fec: bool) -> Result<aligned::Config> {
    let symbol = carrier.symbol();
    let original = source_max(symbol, packed)?;
    let wrapped = original + l2tunnel_recovery::DATA_HEADER_BYTES;
    let count = if with_fec { 8 } else { 1 };
    let repairs = if with_fec { 2 } else { 0 };
    let fec_packet = fec::HEADER_BYTES + count + 2 + wrapped;
    let recovery = ReliableConfig {
        arq: ArqConfig {
            max_source_bytes: original,
            send_bytes: 64 * original,
            receive_bytes: 64 * original,
            send_records: 64,
            receive_records: 64,
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
            max_generations: 16,
            max_symbols_per_generation: count + repairs,
            max_reserved_bytes: 16 << 20,
            max_lifetime_ticks: 10_000,
            generation_window: 256,
        },
        repair_symbols: repairs,
        flush_after: Duration::from_millis(1),
        max_restored_packets: 64 + count,
        max_restored_bytes: (64 + count) * wrapped,
        outer_overhead_bytes: carrier.overhead(),
    };
    Ok(aligned::Config {
        native_policy: aligned::NativePolicy::IpHeaders,
        receiver: receiver(symbol, CHANNELS, 8192),
        max_recovery_packet_bytes: recovery.maximum_packet_bytes()?,
        recovery,
    })
}
fn compact_config(
    carrier: Carrier,
    packed: bool,
    recovery: CompactRecovery,
    independent: bool,
) -> Result<aligned::CompactConfig> {
    let symbol = carrier.symbol();
    let original = source_max(symbol, packed)?;
    let window = if independent { 512 } else { 8192 };
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
            feedback_interval: Duration::from_millis(1),
            feedback_packets: 16,
        },
        l2tunnel_recovery::COMPACT_FEEDBACK_HEADER_BYTES + window.div_ceil(8),
        window * 16,
        9,
        recovery,
    )?;
    Ok(aligned::CompactConfig {
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
fn rolling_direction(carrier: Carrier) -> Result<rolling_records::DirectionConfig> {
    let mut receiver = receiver(carrier.symbol(), CHANNELS, 16_384);
    // Rolling's injected receiver unit is microseconds; ordinary Aligned uses ms.
    receiver.lifetime_ticks = 30_000_000;
    let maximum = source_max(carrier.symbol(), true)?;
    Ok(rolling_records::DirectionConfig {
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
fn profile(algorithm: Algorithm, carrier: Carrier) -> Result<c::Profile> {
    Ok(match algorithm {
        Algorithm::Swift { fec } => {
            let selected = l2tunnel_swift::records::Config {
                channels: usize::from(CHANNELS),
                layer: l2tunnel_swift::records::Layer::Ip,
                max_native: MTU,
                codec: l2tunnel_swift::Config {
                    datagram_bytes: MTU - carrier.overhead(),
                    window: 128,
                    repair_numerator: u32::from(fec),
                    repair_denominator: 4,
                    flow_sources: 1024,
                    queue_bytes: 256 << 10,
                    max_packet: MTU + l2tunnel_swift::header::MAX_EXPANSION,
                    flush_micros: 500,
                    feedback_micros: 1000,
                    tail_micros: 10_000,
                    min_rto_micros: 140_000,
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
            let base = aligned_config(carrier, is_packed, fec)?;
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
            let base = compact_config(carrier, is_packed, recovery, false)?;
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
        Algorithm::Connections { raw_ack } => {
            let selected = connection_records::Direction {
                compact: compact_config(carrier, false, CompactRecovery::Guarded, true)?,
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
        Algorithm::Rolling { copies } => {
            let selected = rolling_direction(carrier)?;
            let config = rolling_records::Config {
                forward: selected,
                reverse: selected,
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
        Algorithm::Research(policy) => {
            let rolling = rolling_direction(carrier)?;
            let selected = research_records::DirectionConfig {
                native_policy: rolling.native_policy,
                receiver: rolling.receiver,
                packing: rolling.packing,
                codec_stage_micros: rolling.codec_stage_micros,
                scheduler: fec::research::Config {
                    recovery: rolling.scheduler.recovery,
                    profile: policy,
                    feedback_ticks: 1000,
                    memory_bytes: ROW_MEMORY,
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
fn direction(rate: u64) -> Result<c::CommonDirection> {
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
                    bytes: 1 << 20,
                    packets: 1024,
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
                bytes: 8 << 20,
                packets: 8192,
            },
        },
        rate,
        64 << 10,
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

fn runtime_document(retained_bytes: usize) -> Value {
    let message = json!({"max_message_bytes":4096,"max_outbound_messages":16,"max_outbound_bytes":131072,"max_fragments":32,"max_reassembly_bytes":65536,"max_incomplete_messages":8,"message_lifetime_micros":5_000_000,"work_per_call":32});
    json!({
        "version":1,"backend":"common_records_v2","initial_index":0,
        "compact_wire":{"version":3,"data_protection":"chacha20-poly1305","max_forward_packets":2147483647u32,"max_failed_checks":4294967295u32},
        "transaction":{"retry_ms":200,"phase_timeout_ms":2000,"reconcile_timeout_ms":5000,"max_operation_ms":10000,"retained_bytes":retained_bytes},
        "runtime":{
            "control_epoch":1,"data_epoch":1,"legacy_policy":{"transaction_micros":10_000_000,"max_outbound":32},
            "security":{"packets_per_key":l2tunnel_security::MAX_PACKETS_PER_KEY,"max_body_bytes_per_key":l2tunnel_security::MAX_BODY_BYTES_PER_KEY},
            "control":{"recovery":{"max_source_bytes":256,"send_bytes":16384,"receive_bytes":16384,"send_records":64,"receive_records":64,"initial_rto_micros":200000,"maximum_rto_micros":3000000,"ack_delay_micros":5000,"max_retries":8},"interval_micros":10000,"packets_per_interval":16,"bytes_per_interval":16384},
            "streams":{"transaction":message.clone(),"liveness":message.clone(),"data_feedback":message},
            "wire":{"initiator_burst_bytes":65536,"responder_burst_bytes":65536},
            "work":{"receive_interval_micros":1000,"receive_packets":256,"send_batch":64,"native_read_batch":64,"native_write_batch":64},
            "native":{"pending_packets":1024,"pending_bytes":1536000,"stall_timeout_micros":NATIVE_STALL_US},
            "lifetime":{"lease_micros":120_000_000,"ping_interval_micros":1_000_000,"pong_timeout_micros":5_000_000},
            "report_interval_micros":1_000_000
        },"rolling_work":null
    })
}
fn policy(carrier: Carrier, client: bool) -> Option<Value> {
    match carrier {
        Carrier::Udp => None,
        Carrier::Raw => Some(json!({"version":1,"profile":"raw-common-carrier-v1",
            "forward":{"local":if client {"192.0.2.2:24440"} else {"192.0.2.6:24441"},"peer":if client {"192.0.2.6:24441"} else {"192.0.2.2:24440"}},"reverse":null,
            "packet":{"mtu":1500,"protection":"aead","queue_packets":64,"horizon_bytes":1048576,"minimum_transfer_bytes":65536,"bytes_per_second":12500000,"packets_per_second":100000,"burst_bytes":65536,"burst_packets":256,"max_key_packets":1073741824u64,"max_key_bytes":68719476736u64}})),
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
fn cli(carrier: Carrier, client: bool) -> Vec<String> {
    let mut result = vec![
        "--carrier",
        carrier.cli(),
        "--record-profile",
        "common",
        "--duplex",
        "full",
        "--compression",
        "off",
        "--layer",
        "tun",
        "--max-packet",
        "1500",
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
    } else {
        result.extend(["--udp-cover", "quic-like"].into_iter().map(str::to_owned));
    }
    if matches!(carrier, Carrier::Raw) {
        result.extend(["--raw-mark", "305790977"].into_iter().map(str::to_owned));
    }
    result
}
fn export_row(directory: &Path, row: &Row, carrier: Carrier) -> Result<Value> {
    let id = format!("{}-{}", row.id, carrier.id());
    let selected = profile(row.algorithm, carrier)?;
    let descriptor = c::Descriptor::new(
        MTU,
        Duplex::Full,
        direction(12_500_000)?,
        direction(1_250_000)?,
        selected,
    )?;
    let mut bytes = [0; c::DESCRIPTOR_BYTES];
    descriptor.encode_into(&mut bytes)?;
    let encoded = hex(&bytes);
    let catalog = c::Catalog::new(descriptor, &[descriptor])?;
    let configuration = c::Configuration::new(c::EnvelopeDigest::new([0x42; 32]), descriptor)?;
    let coded = matches!(
        row.algorithm,
        Algorithm::Rolling { .. } | Algorithm::Research(_)
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
            None,
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
    let mut document = runtime_document(retained);
    document["catalog"] = json!([encoded]);
    if coded {
        document["rolling_work"] = json!({"field":65536,"copies":65536,"metadata":65536});
        document["rolling_ingress"] = json!({"initiator":{"slots":256,"capacity_bytes":1048576},"responder":{"slots":256,"capacity_bytes":1048576}});
    }
    if matches!(row.algorithm, Algorithm::Connections { raw_ack: true }) {
        document["connection_ingress"] = json!({"initiator":{"slots":256,"capacity_bytes":1048576},"responder":{"slots":256,"capacity_bytes":1048576}});
    }
    let plan_name = format!("{id}.common.json");
    write_json(&directory.join(&plan_name), &document)?;
    let mut policies = Value::Null;
    for (side, client) in [("a", true), ("b", false)] {
        if let Some(value) = policy(carrier, client) {
            let path = format!("{id}.{side}.carrier.json");
            #[cfg(unix)]
            if matches!(carrier, Carrier::Raw) {
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
    Ok(json!({
        "id":id,"status":"ready","algorithm":row.family,"variant":row.variant,"carrier":carrier.id(),
        "layer":"tun","duplex":"full","common_plan":plan_name,"carrier_policy":policies,
        "policy_flag":match carrier {Carrier::Udp=>Value::Null,Carrier::Raw=>json!("--raw-policy"),Carrier::Tls|Carrier::Quic=>json!("--maintained-policy")},
        "required_cli":{"a":cli(carrier,true),"b":cli(carrier,false)},
        "expected_descriptor_hex":encoded,"descriptor_digest_hex":hex(digest::digest(&digest::SHA256,&bytes).as_ref()),
        "descriptor_digest_definition":"SHA256 of exact unanchored descriptor bytes; not the session H0",
        "catalog_digest_hex":hex(catalog.root().as_bytes()),"record_profile_debug":format!("{selected:?}"),
        "validation":"both selected compact Engine storage plans accepted; daemon inspection and real carrier/native execution remain required",
        "parameters":{"path_mtu":MTU,"maximum_native_bytes":MTU,"channels":CHANNELS,"symbol_capacity":carrier.symbol(),"max_packed_units":UNITS,"inner_payload_compression":"off","header_policy":"IpHeaders except Swift's own header codec","data_protection":"chacha20-poly1305","record_protection_overhead":21,"carrier_admission_allowance":carrier.physical_allowance(),"allowance_is_measured_wire_cost":false,"engine_capacity_bytes_by_role":plans,"runtime_retained_bytes":retained,"source_window":if ordinary {64} else if matches!(row.algorithm,Algorithm::Swift{..}) {1024} else if matches!(row.algorithm,Algorithm::Connections{..}) {512} else {8192},"source_window_domain":if matches!(row.algorithm,Algorithm::Swift{..}) {"per Swift channel"} else if matches!(row.algorithm,Algorithm::Connections{..}) {"per independent owner,16owners"} else {"shared recovery direction"}},
        "limitations":if ordinary {json!(["Ordinary selective-repeat has a production hard64-source window shared across channels; it may be BDP-limited well below100Mbit/s."])} else {json!([])},
        "evidence_scope":"canonical plan preflight only; not throughput, loss-recovery or native qualification"
    }))
}
fn run() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != "--output-dir" {
        return Err("usage: common_benchmark_plan --output-dir NEW_DIRECTORY".into());
    }
    let directory = Path::new(&arguments[1]);
    std::fs::create_dir(directory)?;
    let mut exported = Vec::new();
    for row in rows() {
        for carrier in [Carrier::Udp, Carrier::Raw, Carrier::Tls, Carrier::Quic] {
            match export_row(directory, &row, carrier) {
                Ok(value) => exported.push(value),
                Err(error) if error.is::<std::io::Error>() || error.is::<serde_json::Error>() => return Err(error),
                Err(error) => exported.push(json!({"id":format!("{}-{}",row.id,carrier.id()),"status":"plan_refused","reason":error.to_string(),"algorithm":row.family,"variant":row.variant,"carrier":carrier.id(),"validation":"generated configuration refused; requires diagnosis and does not establish an unsupported algorithm"})),
            }
        }
    }
    let ready = exported
        .iter()
        .filter(|value| value["status"] == "ready")
        .count();
    let manifest = json!({"version":1,"kind":"current-common-native-matrix","baseline":{"ip_family":4,"duplex":"full","layer":"tun","tcp_flows":16,"forward_mbit_s":100,"reverse_mbit_s":10,"nominal_rtt_ms":70,"one_way_delay_ms":35,"loss_percent_each_way":15,"warmup_seconds":2,"sample_seconds":10,"directions":["forward","reverse","simultaneous"],"mtu":1500},"rows":exported,"ready_rows":ready,"all_rows":80,"not_covered":["Unimplemented Python catalog modes remain parity gaps; these rows enumerate current connected owners, not all47 acceptance gates.","Windows, Android, public ISP classification and middlebox passage are not measured by this Linux namespace matrix.","Half duplex, compression-policy alternatives and proxy are separate functional selections; this manifest is the explicitly chosen Full native TUN baseline."],"metric_boundary":"Actual captured IP bytes and receiver application bytes; configured allowances are never substituted for physical wire bytes."});
    write_json(&directory.join("manifest.json"), &manifest)?;
    println!(
        "{}",
        json!({"manifest":directory.join("manifest.json"),"ready_rows":ready,"all_rows":80})
    );
    Ok(())
}
fn main() -> Result<()> {
    run()
}
