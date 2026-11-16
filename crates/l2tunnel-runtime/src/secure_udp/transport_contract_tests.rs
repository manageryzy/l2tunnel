//! Complete local role/cover handoff validation, not authenticated runtime readiness.

use super::*;
use l2tunnel_management::{control_streams, delivery, messages};
use l2tunnel_swift::{self as swift, policy, records};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Inputs {
    config: Config,
    cover: cover::Config,
    catalog: Catalog,
    settings: TransactionSettings,
    role: security::Role,
    ipv6: bool,
}
impl Inputs {
    fn contract(&self) -> io::Result<TransactionContract> {
        TransactionContract::new(
            security::ConfigDigest([31; 32]),
            self.role,
            self.config,
            self.cover,
            self.ipv6,
            EnvelopeDigest::new([42; 32]),
            self.catalog.clone(),
            self.settings,
        )
    }
}

fn inputs(kind: cover::Appearance, role: security::Role, ipv6: bool) -> Result<Inputs> {
    let codec = swift::Config {
        datagram_bytes: 512,
        window: 8,
        repair_numerator: 1,
        repair_denominator: 3,
        flow_sources: 64,
        queue_bytes: 65536,
        max_packet: 513,
        flush_micros: 0,
        feedback_micros: 1000,
        tail_micros: 10000,
        min_rto_micros: 10000,
        max_rto_micros: 100000,
    };
    let forward = policy::Direction {
        records: records::Config {
            codec,
            channels: 2,
            layer: records::Layer::Ethernet,
            max_native: 512,
        },
        bytes_per_second: 1_000_001,
    };
    let mut reverse = forward;
    reverse.records.channels = 3;
    reverse.bytes_per_second = 500_013;
    reverse.records.codec.window = 7;
    let initial = Descriptor::new(1500, forward, reverse)?;
    let mut next_forward = forward;
    let mut next_reverse = reverse;
    next_forward.records.channels = 4;
    next_reverse.records.channels = 1;
    next_forward.records.codec.datagram_bytes = 640;
    next_reverse.records.codec.datagram_bytes = 700;
    next_forward.records.codec.repair_numerator = 2;
    next_forward.records.codec.repair_denominator = 7;
    next_reverse.records.codec.flush_micros = 17;
    let next = Descriptor::new(1600, next_forward, next_reverse)?;
    let overhead = if ipv6 { 48 } else { 28 }
        + l2tunnel::secure_record::ROUTE_BYTES
        + security::Protection::ChaCha20Poly1305.overhead_bytes()
        + if kind == cover::Appearance::QuicLike {
            13
        } else {
            14
        };
    let base = delivery::Settings {
        recovery: l2tunnel_recovery::ArqConfig {
            max_source_bytes: 192,
            send_bytes: 6144,
            receive_bytes: 6144,
            send_records: 32,
            receive_records: 32,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(100),
            ack_delay: Duration::from_millis(1),
            max_retries: 16,
        },
        interval: Duration::from_millis(1),
        packets_per_interval: 16,
        bytes_per_interval: 65536,
        wire_overhead: overhead,
    };
    let entry = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: base.wire_overhead + control_streams::HEADER_BYTES,
            ..base
        },
        path_mtu: 1500,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131072,
        max_fragments: 32,
        max_reassembly_bytes: 16384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(5),
        work_per_call: 8,
    };
    let config = Config {
        path_mtu: 1500,
        send: if role == security::Role::Initiator {
            forward
        } else {
            reverse
        },
        receive: if role == security::Role::Initiator {
            reverse
        } else {
            forward
        },
        policy: policy::Settings {
            transaction_micros: 1_000_000,
            max_outbound: 8,
        },
        security: security::Limits {
            max_body_bytes: 1300,
            packets_per_key: 8,
            max_body_bytes_per_key: 100000,
        },
        control: base,
        streams: Some(crate::secure_udp::control::Settings {
            streams: [entry; 3],
        }),
        control_epoch: security::Epoch(1),
        data_epoch: security::Epoch(2),
        wire: super::super::WireBudget { burst_bytes: 4096 },
        work: super::super::WorkBudget {
            receive_interval: Duration::from_millis(1),
            receive_packets: 64,
            send_batch: 16,
            native_read_batch: 16,
            native_write_batch: 16,
        },
        rolling_work: None,
        ack_coalescing: None,
        native: super::super::NativeBudget {
            pending_packets: 16,
            pending_bytes: 8192,
            stall_timeout: Duration::from_secs(1),
        },
        lifetime: super::super::Lifetime {
            lease: Duration::from_secs(5),
            ping_interval: Duration::from_millis(20),
            pong_timeout: Duration::from_millis(500),
        },
        report_interval: Some(Duration::from_millis(5)),
    };
    let local = if role == security::Role::Initiator {
        1
    } else {
        2
    };
    let peer = if local == 1 { 2 } else { 1 };
    let selected = cover::Config::new(
        kind,
        cover::ConnectionIds {
            local: cover::ConnectionId([local; 8]),
            peer: cover::ConnectionId([peer; 8]),
        },
        cover::MediaConfig {
            local_ssrc: cover::Ssrc(u32::from(local)),
            peer_ssrc: cover::Ssrc(u32::from(peer)),
            payload_type: 96,
        },
        cover::Limits {
            max_packet_bytes: 1600,
            max_protected_bytes: 1500,
        },
    )?;
    Ok(Inputs {
        config,
        cover: selected,
        catalog: Catalog::new(initial, &[next, initial])?,
        settings: TransactionSettings {
            protocol: transaction::Settings::default(),
            max_operation_ms: 1500,
            retained_bytes: 64 << 20,
        },
        role,
        ipv6,
    })
}

#[test]
fn exact_all_role_cover_and_ip_contracts_keep_h0_distinct_and_resolve_whole_catalog() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for role in [security::Role::Initiator, security::Role::Responder] {
            for ipv6 in [false, true] {
                let input = inputs(kind, role, ipv6)?;
                let value = input.contract()?;
                assert_eq!(
                    value.expected_configuration(),
                    security::ConfigDigest([31; 32])
                );
                assert_eq!(value.role(), role);
                assert_eq!(value.config(), input.config);
                assert_eq!(value.cover(), input.cover);
                assert_eq!(value.ipv6(), ipv6);
                assert_eq!(value.envelope(), EnvelopeDigest::new([42; 32]));
                assert_eq!(value.catalog().root(), input.catalog.root());
                assert_eq!(value.settings(), input.settings);
                assert_eq!(value.initial().descriptor(), input.catalog.initial());
                assert_eq!(
                    value.data_digest(),
                    transaction::configuration_digest(&value.initial())?
                );
                assert_ne!(value.data_digest().0, value.expected_configuration().0);
                assert_eq!(value.resolve(value.initial())?, input.config);
                for descriptor in input.catalog.descriptors() {
                    let c = Configuration::new(value.envelope(), *descriptor)?;
                    let resolved = value.resolve(c)?;
                    let (send, receive) = match role {
                        security::Role::Initiator => (descriptor.forward(), descriptor.reverse()),
                        security::Role::Responder => (descriptor.reverse(), descriptor.forward()),
                    };
                    assert_eq!(resolved.send, send);
                    assert_eq!(resolved.receive, receive);
                    assert_eq!(resolved.path_mtu, descriptor.path_mtu());
                    assert_eq!(
                        resolved.immutable_contract_digest()?,
                        input.config.immutable_contract_digest()?
                    );
                    assert_eq!(resolved.report_interval, input.config.report_interval);
                    for stream in resolved.streams.ok_or("streams lost")?.streams {
                        assert_eq!(stream.path_mtu, descriptor.path_mtu());
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn role_initial_stream_family_and_appearance_mismatches_refuse() -> Result {
    let base = inputs(
        cover::Appearance::QuicLike,
        security::Role::Initiator,
        false,
    )?;
    let mut role = inputs(
        cover::Appearance::QuicLike,
        security::Role::Initiator,
        false,
    )?;
    role.role = security::Role::Responder;
    assert!(role.contract().is_err());
    let mut initial = inputs(
        cover::Appearance::QuicLike,
        security::Role::Initiator,
        false,
    )?;
    let other = *initial
        .catalog
        .descriptors()
        .iter()
        .find(|d| **d != initial.catalog.initial())
        .ok_or("target missing")?;
    initial.catalog = Catalog::new(other, initial.catalog.descriptors())?;
    assert!(initial.contract().is_err());
    let mut streams = inputs(
        cover::Appearance::QuicLike,
        security::Role::Initiator,
        false,
    )?;
    streams.config.streams = None;
    assert!(streams.contract().is_err());
    let mut family = inputs(
        cover::Appearance::QuicLike,
        security::Role::Initiator,
        false,
    )?;
    family.ipv6 = true;
    assert!(family.contract().is_err());
    let mut appearance = inputs(
        cover::Appearance::QuicLike,
        security::Role::Initiator,
        false,
    )?;
    appearance.cover = inputs(
        cover::Appearance::MediaLike,
        security::Role::Initiator,
        false,
    )?
    .cover;
    assert!(appearance.contract().is_err());
    assert!(base.contract().is_ok());
    Ok(())
}

#[test]
fn every_catalog_member_must_fit_fixed_native_body_and_active_geometry() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for bad in 0..4 {
            let mut input = inputs(kind, security::Role::Initiator, false)?;
            let initial = input.catalog.initial();
            let mut forward = initial.forward();
            let mut reverse = initial.reverse();
            let mtu = if bad == 3 { 256 } else { 1500 };
            match bad {
                0 => {
                    forward.records.layer = records::Layer::Ip;
                    reverse.records.layer = records::Layer::Ip;
                }
                1 => {
                    for direction in [&mut forward, &mut reverse] {
                        direction.records.max_native += 1;
                        direction.records.codec.max_packet += 1;
                    }
                }
                2 => forward.records.codec.datagram_bytes = 1400,
                _ => {}
            }
            let other = Descriptor::new(mtu, forward, reverse)?;
            input.catalog = Catalog::new(initial, &[initial, other])?;
            assert!(input.contract().is_err(), "bad member {bad} was ignored");
        }
    }
    Ok(())
}

#[test]
fn foreign_envelope_unlisted_value_and_short_whole_message_capacity_refuse() -> Result {
    let mut input = inputs(
        cover::Appearance::QuicLike,
        security::Role::Initiator,
        false,
    )?;
    let value = input.contract()?;
    assert!(
        value
            .resolve(Configuration::new(
                EnvelopeDigest::new([99; 32]),
                input.catalog.initial()
            )?)
            .is_err()
    );
    let mut forward = input.catalog.initial().forward();
    forward.bytes_per_second += 1;
    let unlisted = Descriptor::new(1500, forward, input.catalog.initial().reverse())?;
    assert!(
        value
            .resolve(Configuration::new(value.envelope(), unlisted)?)
            .is_err()
    );
    input
        .config
        .streams
        .as_mut()
        .ok_or("missing streams")?
        .streams[0]
        .max_message_bytes = 512;
    input.config.validate()?;
    assert!(input.contract().is_err());
    let mut retained = inputs(
        cover::Appearance::QuicLike,
        security::Role::Initiator,
        false,
    )?;
    retained
        .config
        .streams
        .as_mut()
        .ok_or("missing streams")?
        .streams[0]
        .max_outbound_bytes = 512;
    retained.config.validate()?;
    assert!(retained.contract().is_err());
    Ok(())
}

#[test]
fn shared_setting_refusal_and_local_reporting_do_not_rewrite_d0_or_h0() -> Result {
    let mut input = inputs(
        cover::Appearance::MediaLike,
        security::Role::Responder,
        false,
    )?;
    let original = input.contract()?;
    input.config.report_interval = Some(Duration::from_secs(1));
    let report = input.contract()?;
    assert_eq!(report.data_digest(), original.data_digest());
    assert_eq!(
        report.expected_configuration(),
        original.expected_configuration()
    );
    assert_ne!(
        report.config().report_interval,
        original.config().report_interval
    );
    input.settings.retained_bytes = 0;
    assert!(input.contract().is_err());
    input.settings = original.settings();
    input.settings.max_operation_ms = 5001;
    assert!(input.contract().is_err());
    input.settings = original.settings();
    input.settings.protocol.retry_ms = 0;
    assert!(input.contract().is_err());
    Ok(())
}
