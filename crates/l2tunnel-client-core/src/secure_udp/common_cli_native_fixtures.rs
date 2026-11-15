//! Public canonical inputs for the actual carrier CLI lab, never product defaults.
use super::*;
use l2tunnel::{
    aligned, codec, fec, pipeline, record_configuration as common, record_engine, rolling_records,
};
use l2tunnel_core::{Duplex, traffic};
use l2tunnel_device::PacketLayer;
use l2tunnel_management::Role as DataRole;

fn direction(layer: PacketLayer, native: usize, rate: u64) -> io::Result<common::CommonDirection> {
    let queue = pipeline::QueueLimits {
        bytes: 65_536,
        packets: 8,
    };
    let (traffic, profile) = match layer {
        PacketLayer::Ethernet => (traffic::TrafficPolicy::tap(), pipeline::Profile::TapSystem),
        PacketLayer::Ip => (
            traffic::TrafficPolicy {
                layer: traffic::NetworkLayer::Tun,
                tcp: traffic::TcpControl::System,
                qos: traffic::Qos::WeightedDeficit,
            },
            pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                base_quantum_bytes: native as u32,
                max_weight: 1,
                per_flow: queue,
            }),
        ),
    };
    common::CommonDirection::new(
        traffic,
        pipeline::PipelineConfig {
            profile,
            flows: pipeline::FlowTableConfig {
                // The native probe retains fourteen UDP flows plus IP/ARP probes.
                capacity: 64,
                channels: 2,
                mapping: pipeline::Mapping::ConnectionRoundRobin,
                idle_timeout: Duration::from_secs(5),
            },
            parse: pipeline::ParseLimits {
                max_packet_bytes: native,
                ..pipeline::ParseLimits::default()
            },
            queue,
        },
        rate,
        65_536,
        common::NativeWindow::Disabled,
    )
    .map_err(io::Error::other)
}
fn aligned(layer: PacketLayer, native: usize, overhead: usize, packed: bool) -> aligned::Config {
    let symbol = if packed { 320 } else { 256 };
    let original = if packed {
        56 + 8 * 3 + symbol
    } else {
        48 + symbol
    };
    let wrapped = 44 + original;
    let fec_packet = 56 + 2 + 2 + wrapped;
    aligned::Config {
        native_policy: if layer == PacketLayer::Ip {
            aligned::NativePolicy::RawIp
        } else {
            aligned::NativePolicy::EthernetHeaders
        },
        receiver: codec::aligned_receiver::Limits {
            body: codec::aligned_body::Config {
                max_frame_bytes: native,
                symbol_bytes: symbol,
                elide_payload_length: false,
                predictive: false,
                timestamp_pair_dictionary: false,
                independent_short_frame_bytes: 32,
            },
            channels: 2,
            first_record: codec::aligned_receiver::RecordId(0),
            first_source: codec::aligned_receiver::SourceId(0),
            record_window: 32,
            source_window: 32,
            lookahead_records: 4,
            lookahead_bytes: 4 * 65_535,
            lookahead_fragments: 64,
            max_fragments_per_record: 16,
            lifetime_ticks: 5000,
        },
        recovery: l2tunnel_reliable::ReliableConfig {
            arq: l2tunnel_recovery::ArqConfig {
                max_source_bytes: original,
                send_bytes: 8 * original,
                receive_bytes: 8 * original,
                send_records: 8,
                receive_records: 8,
                initial_rto: Duration::from_millis(10),
                maximum_rto: Duration::from_millis(100),
                ack_delay: Duration::from_millis(1),
                max_retries: 2,
            },
            fec: fec::DecoderConfig {
                block: fec::BlockConfig {
                    max_sources: 2,
                    max_source_bytes: wrapped,
                    max_packet_bytes: fec_packet,
                    max_work_per_symbol: 1_000_000,
                },
                max_generations: 4,
                max_symbols_per_generation: 3,
                max_reserved_bytes: 1_000_000,
                max_lifetime_ticks: 50,
                generation_window: 32,
            },
            repair_symbols: 0,
            flush_after: Duration::from_millis(1),
            max_restored_packets: 16,
            max_restored_bytes: 16 * wrapped,
            outer_overhead_bytes: overhead,
        },
        max_recovery_packet_bytes: 8 + fec_packet,
    }
}
fn rolling(packed: aligned::packed::Config) -> rolling_records::DirectionConfig {
    let mut receiver = packed.base.receiver;
    receiver.lifetime_ticks = 5_000_000;
    rolling_records::DirectionConfig {
        native_policy: packed.base.native_policy,
        receiver,
        packing: codec::packed_sender::Config {
            sender: codec::aligned_sender::Config {
                body: receiver.body,
                channels: receiver.channels,
                first_record: receiver.first_record,
            },
            packing: codec::packed::Config {
                symbol_bytes: receiver.body.symbol_bytes,
                hold_micros: packed.hold_micros,
            },
            max_units: packed.max_units,
            first_unit: receiver.first_source,
            work_limit: packed.work_limit,
        },
        codec_stage_micros: 1_000_000,
        scheduler: fec::rolling::scheduler::Policy {
            recovery: fec::rolling::Config {
                window: 16,
                local_window: 4,
                global_every: 2,
                max_payload: 1024,
                max_rows: 16,
                repair_history: 64,
                handoff_sources: 2,
                job_ticks: 1_000_000,
                debt_ticks: 10_000_000,
                handoff_ticks: 2_000_000,
                memory_bytes: 16 << 20,
            },
            repair_numerator: 1,
            repair_denominator: 2,
            tail_ticks: 1000,
            feedback_ticks: 100,
            feedback_packets: 2,
            memory_bytes: 16 << 20,
            source_wire: fec::rolling::wire::SourceWire::Exact,
        },
    }
}
fn geometry_inputs(
    layer: PacketLayer,
    appearance: l2tunnel_cover::Appearance,
    role: Role,
) -> io::Result<(
    ConnectionConfig,
    secure_udp::Settings,
    establish::Peers,
    usize,
    usize,
)> {
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(Zeroizing::new([21; 32])).public_key(),
        responder: hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key(),
    };
    let connection = ConnectionConfig {
        layer,
        duplex: Duplex::Full,
        max_packet: if layer == PacketLayer::Ip { 1500 } else { 1600 },
        compression: crate::Compression::None,
        handshake_timeout: Duration::from_secs(3),
    };
    let common = super::super::super::Common {
        appearance,
        role,
        local: if role == Role::Initiator {
            "10.77.0.1:4433"
        } else {
            "10.77.0.2:4433"
        }
        .parse()
        .map_err(io::Error::other)?,
        peer: if role == Role::Initiator {
            "10.77.0.2:4433"
        } else {
            "10.77.0.1:4433"
        }
        .parse()
        .map_err(io::Error::other)?,
        maximum_mtu: 9000,
        profile: hs::Profile::Ik,
    };
    let mut settings = common.raw(
        1500,
        connection.handshake_timeout,
        peers,
        l2tunnel_identity::MemberPublicKey([7; 32]),
    )?;
    let (overhead, body) = common.carrier_geometry(&mut settings, 1471)?;
    Ok((connection, settings, peers, body, overhead))
}
fn document(layer: PacketLayer, appearance: l2tunnel_cover::Appearance) -> io::Result<Value> {
    let (connection, _, _, _, overhead) = geometry_inputs(layer, appearance, Role::Initiator)?;
    let native = connection.max_packet;
    let base = aligned(layer, native, overhead, false);
    let packed = aligned::packed::Config {
        base: aligned(layer, native, overhead, true),
        hold_micros: 500,
        max_units: 3,
        work_limit: 4,
    };
    let swift = l2tunnel_swift::records::Config {
        channels: 2,
        layer: if layer == PacketLayer::Ip {
            l2tunnel_swift::records::Layer::Ip
        } else {
            l2tunnel_swift::records::Layer::Ethernet
        },
        max_native: native,
        codec: l2tunnel_swift::Config {
            datagram_bytes: 1024,
            window: 7,
            repair_numerator: 1,
            repair_denominator: 3,
            flow_sources: 64,
            queue_bytes: 8192,
            max_packet: native + l2tunnel_swift::header::MAX_EXPANSION,
            flush_micros: 123,
            feedback_micros: 5003,
            tail_micros: 10001,
            min_rto_micros: 20003,
            max_rto_micros: 1_000_007,
        },
    };
    let profiles = [
        common::Profile::Swift {
            forward: swift,
            reverse: swift,
        },
        common::Profile::Aligned {
            forward: base,
            reverse: base,
        },
        common::Profile::Packed {
            forward: packed,
            reverse: packed,
        },
        common::Profile::Rolling {
            config: rolling_records::Config {
                forward: rolling(packed),
                reverse: rolling(packed),
                geometry: record_engine::Geometry {
                    forward_overhead_bytes: overhead,
                    reverse_overhead_bytes: overhead,
                },
                native_stall_micros: 10_000_000,
            },
            stream: 17,
        },
    ];
    let mut catalog = Vec::new();
    for profile in profiles {
        for i in 0..16 {
            let common = direction(layer, native, 1_250_001 + i)?;
            let descriptor = common::Descriptor::new(1500, Duplex::Full, common, common, profile)
                .map_err(io::Error::other)?;
            catalog.push(hex(descriptor)?);
        }
    }
    let old = super::super::super::transaction_cli::test_plan_value();
    let mut value = json!({"version":1,"backend":"common_records_v2","initial_index":0,"catalog":catalog,"transaction":old["transaction"],"runtime":old["runtime"],"rolling_work":{"field":4096,"copies":4096,"metadata":4096}});
    value["runtime"]["report_interval_micros"] = json!(500_000);
    value["outer_carrier"] = outer_policy(&value);
    Ok(value)
}
#[test]
fn all_native_carrier_plans_validate_four_full_families_and_both_roles_before_export()
-> io::Result<()> {
    let mut exports = Vec::new();
    for (layer_name, layer) in [("tun", PacketLayer::Ip), ("tap", PacketLayer::Ethernet)] {
        for (cover_name, appearance) in [
            ("quic-like", l2tunnel_cover::Appearance::QuicLike),
            ("media-like", l2tunnel_cover::Appearance::MediaLike),
        ] {
            let value = document(layer, appearance)?;
            let plan = decode(&value)?;
            assert_eq!(plan.catalog.descriptors().len(), 64);
            for role in [Role::Initiator, Role::Responder] {
                let (connection, settings, peers, body, overhead) =
                    geometry_inputs(layer, appearance, role)?;
                let profile = plan.build(connection, settings, peers, body, overhead)?;
                let outer = plan.outer_config(&profile)?;
                assert_eq!(
                    (
                        outer.path_mtu,
                        outer.max_record_bytes,
                        outer.outer_overhead_bytes
                    ),
                    (1500, 1471, 29)
                );
                assert!(profile.carrier_binding().is_none());
                assert_eq!(
                    profile.requested_catalog().descriptors(),
                    plan.catalog.descriptors()
                );
                let mut families = [0; 4];
                for descriptor in plan.catalog.descriptors() {
                    let slot = match descriptor.profile() {
                        common::Profile::Swift { .. } => 0,
                        common::Profile::Aligned { .. } => 1,
                        common::Profile::Packed { .. } => 2,
                        common::Profile::Rolling { .. } | common::Profile::RollingCopies { .. } => {
                            3
                        }
                    };
                    families[slot] += 1;
                    for data_role in [DataRole::Client, DataRole::Server] {
                        assert_eq!(
                            descriptor.direction(data_role).max_native(),
                            connection.max_packet
                        );
                    }
                }
                assert_eq!(families, [16; 4]);
            }
            let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
            if bytes.len() > 256 * 1024 {
                return Err(invalid("native carrier fixture exceeds plan bound"));
            }
            exports.push((format!("{cover_name}-{layer_name}.json"), bytes));
        }
    }
    if let Some(directory) = std::env::var_os("L2TUNNEL_COMMON_CARRIER_NATIVE_FIXTURES") {
        let directory = std::path::PathBuf::from(directory);
        for (name, bytes) in exports {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(name))?;
            std::io::Write::write_all(&mut file, &bytes)?;
            file.sync_all()?;
        }
    }
    Ok(())
}
