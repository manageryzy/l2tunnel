//! Genuine outer proofs bind an unchanged offline plan; no public Info is forged.
use super::*;
use l2tunnel::{aligned, codec::aligned_body};
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_management::{control_streams as streams, delivery, messages};
use l2tunnel_openvpn::{WireBudget, wire_carrier};
use std::time::Duration;
use tokio::{net::UdpSocket, time::Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn raw_config() -> wire_carrier::common::Config {
    wire_carrier::common::Config {
        base: l2tunnel_auth::SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([91; 32]),
        },
        path_mtu: 1500,
        outer_overhead_bytes: 29,
        max_record_bytes: 1471,
        control_arq: l2tunnel_recovery::ArqConfig {
            max_source_bytes: 512,
            send_bytes: 4096,
            receive_bytes: 4096,
            send_records: 8,
            receive_records: 8,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(100),
            ack_delay: Duration::from_millis(1),
            max_retries: 8,
        },
        handshake_timeout: Duration::from_secs(3),
        lifetime: Duration::from_secs(10),
        packet_slots: 8,
        stream_bytes: 16_384,
        poll_interval: Duration::from_millis(1),
        work_limit: 16,
        wire_budget: WireBudget {
            interval: Duration::from_millis(10),
            packets: 32,
            ip_bytes: 48_000,
            reserved_control_packets: 4,
            reserved_control_bytes: 6000,
            maximum_control_packets: 16,
        },
    }
}

async fn outers(
    member: &MemberKey,
    config: wire_carrier::common::Config,
) -> Result<[establish::carrier::Outer; 2]> {
    let cert = rcgen::generate_simple_self_signed(vec!["common-profile.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let allow = MemberAllowlist::new(&[member.public_key()])?;
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    a.connect(b.local_addr()?).await?;
    b.connect(a.local_addr()?).await?;
    let deadline = Instant::now() + config.handshake_timeout;
    let (a, b) = tokio::time::timeout_at(deadline, async {
        tokio::join!(
            establish::carrier::Outer::client(
                a,
                config,
                wire_carrier::ClientCredentials {
                    tls: &client_tls,
                    server_name: "common-profile.test",
                    member,
                },
                deadline,
            ),
            establish::carrier::Outer::server(
                b,
                config,
                wire_carrier::ServerCredentials {
                    tls: &server_tls,
                    members: &allow,
                },
                deadline,
            ),
        )
    })
    .await?;
    Ok([a?, b?])
}

fn selected(mut value: transport::Config) -> transport::Config {
    value.security.max_body_bytes = 1300;
    let entry = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: value.control.wire_overhead + streams::HEADER_BYTES,
            ..value.control
        },
        path_mtu: value.path_mtu,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131_072,
        max_fragments: 32,
        max_reassembly_bytes: 16_384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(5),
        work_per_call: 8,
    };
    value.streams = Some(l2tunnel_runtime::secure_udp::control::Settings {
        streams: [entry; 3],
    });
    value
}

fn aligned(overhead: usize, packed: bool) -> aligned::Config {
    let symbol = if packed { 320 } else { 256 };
    let source = if packed {
        56 + 8 * 3 + symbol
    } else {
        48 + symbol
    };
    let wrapped = 44 + source;
    let fec = 56 + 2 + 2 + wrapped;
    aligned::Config {
        native_policy: aligned::NativePolicy::RawIp,
        receiver: l2tunnel_codec::aligned_receiver::Limits {
            body: aligned_body::Config {
                max_frame_bytes: 1500,
                symbol_bytes: symbol,
                elide_payload_length: false,
                predictive: false,
                timestamp_pair_dictionary: false,
                independent_short_frame_bytes: 0,
            },
            channels: 2,
            first_record: l2tunnel_codec::aligned_receiver::RecordId(0),
            first_source: l2tunnel_codec::aligned_receiver::SourceId(0),
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
                max_source_bytes: source,
                send_bytes: 8 * source,
                receive_bytes: 8 * source,
                send_records: 8,
                receive_records: 8,
                initial_rto: Duration::from_millis(10),
                maximum_rto: Duration::from_millis(100),
                ack_delay: Duration::from_millis(1),
                max_retries: 2,
            },
            fec: l2tunnel_fec::DecoderConfig {
                block: l2tunnel_fec::BlockConfig {
                    max_sources: 2,
                    max_source_bytes: wrapped,
                    max_packet_bytes: fec,
                    max_work_per_symbol: 1_000_000,
                },
                max_generations: 4,
                max_symbols_per_generation: 3,
                max_reserved_bytes: 1_000_000,
                max_lifetime_ticks: 50,
                generation_window: 32,
            },
            repair_symbols: 1,
            flush_after: Duration::from_millis(1),
            max_restored_packets: 16,
            max_restored_bytes: 16 * wrapped,
            outer_overhead_bytes: overhead,
        },
        max_recovery_packet_bytes: 8 + fec,
    }
}

fn profile(
    path: l2tunnel_udp_control::Path,
    appearance: l2tunnel_cover::Appearance,
    member: l2tunnel_identity::MemberPublicKey,
) -> Result<Profile> {
    let (legacy, peers) = super::super::common_fixture::fixture(path, appearance, member)?;
    let mut connection = legacy.connection();
    connection.max_packet = 1500;
    let mut settings = legacy.settings();
    settings.application = ConfigDigest([81; 32]);
    // Explicit carrier-ready storage; no production binding shrinks these limits.
    settings.cover.max_packet_bytes = 1471;
    settings.cover.max_protected_bytes = 1400;
    let mut initiator = selected(legacy.runtime(security::Role::Initiator));
    let mut responder = selected(legacy.runtime(security::Role::Responder));
    initiator.work.send_batch = 7;
    responder.work.send_batch = 11;
    responder.work.native_write_batch = 3;
    let initial = super::super::common_status::tests::descriptor(1_250_001)?;
    let descriptor = |family| {
        common::Descriptor::new(
            initial.path_mtu(),
            initial.duplex(),
            *initial.direction(Role::Client).common(),
            *initial.direction(Role::Server).common(),
            family,
        )
    };
    let aligned = descriptor(common::Profile::Aligned {
        forward: aligned(initiator.control.wire_overhead, false),
        reverse: aligned(responder.control.wire_overhead, false),
    })?;
    let packed = descriptor(common::Profile::Packed {
        forward: aligned::packed::Config {
            base: self::aligned(initiator.control.wire_overhead, true),
            hold_micros: 503,
            max_units: 3,
            work_limit: 3,
        },
        reverse: aligned::packed::Config {
            base: self::aligned(responder.control.wire_overhead, true),
            hold_micros: 701,
            max_units: 3,
            work_limit: 3,
        },
    })?;
    Ok(Profile::new(
        connection,
        settings,
        peers,
        initiator,
        responder,
        Catalog::new(initial, &[packed, initial, aligned])?,
        transport::TransactionSettings {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 1000,
                reconcile_timeout_ms: 2000,
            },
            max_operation_ms: 3000,
            retained_bytes: 256 << 20,
        },
    )?)
}

fn with_settings(profile: &Profile, settings: Settings) -> io::Result<Profile> {
    Profile::new(
        profile.connection,
        settings,
        profile.peers,
        profile.initiator,
        profile.responder,
        profile.catalog.clone(),
        profile.parameters,
    )
}

#[tokio::test]
async fn genuine_outer_binds_both_roles_and_full_asymmetric_resources_without_changing_request()
-> Result {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
        let [a, b] = outers(&member, raw_config()).await?;
        let endpoints = a.authenticated().endpoints();
        let requested = profile(
            l2tunnel_udp_control::Path {
                client: endpoints.0,
                server: endpoints.1,
            },
            appearance,
            member.public_key(),
        )?;
        let old_settings = requested.settings();
        let old_h0 = requested.configuration()?;
        let old_e0 = requested.envelope();
        let old_c0 = requested.initial();
        let old_catalog = requested.catalog().clone();
        let x = requested.bind_outer(a.authenticated())?;
        let y = requested.bind_outer(b.authenticated())?;
        assert_eq!(x.configuration()?, y.configuration()?);
        assert_eq!(x.envelope(), y.envelope());
        assert_eq!(x.initial(), y.initial());
        assert_ne!(x.configuration()?, old_h0);
        assert_ne!(x.envelope(), old_e0);
        assert_ne!(x.initial(), old_c0);
        for (bound, role, outer) in [
            (&x, security::Role::Initiator, a.authenticated()),
            (&y, security::Role::Responder, b.authenticated()),
        ] {
            assert_eq!(bound.settings(), old_settings);
            assert_eq!(bound.requested_configuration()?, old_h0);
            assert_eq!(bound.requested_envelope(), old_e0);
            assert_eq!(bound.requested_catalog(), &old_catalog);
            assert_eq!(bound.carrier_binding(), Some(outer));
            assert_eq!(
                bound.catalog().descriptors().len(),
                old_catalog.descriptors().len()
            );
            let actual = bound.runtime_contract(role)?;
            let old = requested.runtime_contract(role)?;
            assert_eq!(actual.expected_configuration(), bound.configuration()?);
            assert_eq!(actual.initial(), bound.initial());
            assert_eq!(actual.data_digest(), bound.data_digest());
            assert_eq!(actual.compact_wire(), old.compact_wire());
            assert_eq!(
                actual.resources().work.send_batch,
                old.resources().work.send_batch
            );
            assert_eq!(actual.resources().security, old.resources().security);
            assert_eq!(
                actual.resources().control.wire_overhead,
                old.resources().control.wire_overhead
            );
            for (actual, old) in actual
                .resources()
                .streams
                .ok_or("streams")?
                .streams
                .into_iter()
                .zip(old.resources().streams.ok_or("old streams")?.streams)
            {
                assert_eq!(actual.delivery.wire_overhead, old.delivery.wire_overhead);
                assert_eq!(actual.max_message_bytes, old.max_message_bytes);
                assert_eq!(actual.max_fragments, old.max_fragments);
            }
            let setup = bound.establish_config(role)?;
            assert_eq!(setup.binding.configuration, bound.configuration()?.0);
            assert_eq!(setup.binding.outer, outer.binding());
            assert_eq!(
                setup.gate.outer_overhead,
                old_settings.gate.outer_overhead + 1
            );
            outer.expected_binding(
                setup,
                bound.peers(),
                l2tunnel_handshake::SessionId([17; 16]),
            )?;
            assert!(bound.bind_outer(outer).is_err());
            let other = if role == security::Role::Initiator {
                security::Role::Responder
            } else {
                security::Role::Initiator
            };
            assert!(bound.runtime_contract(other).is_err());
            assert!(bound.establish_config(other).is_err());
            for original in old_catalog.descriptors() {
                assert!(bound.catalog().descriptors().contains(original));
                actual.resolve(Configuration::new(bound.envelope(), *original)?)?;
            }
        }
        assert_eq!(requested.configuration()?, old_h0);
        assert_eq!(requested.initial(), old_c0);
        assert_eq!(requested.settings(), old_settings);
        assert!(requested.carrier_binding().is_none());
    }
    Ok(())
}

#[tokio::test]
async fn genuine_outer_refuses_member_endpoint_and_tight_capacity_without_mutating_requested_plan()
-> Result {
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let [a, _b] = outers(&member, raw_config()).await?;
    let outer = a.authenticated();
    let path = l2tunnel_udp_control::Path {
        client: outer.endpoints().0,
        server: outer.endpoints().1,
    };
    let requested = profile(
        path,
        l2tunnel_cover::Appearance::QuicLike,
        member.public_key(),
    )?;
    let mut changed = requested.settings();
    changed.member = l2tunnel_identity::MemberPublicKey([99; 32]);
    let wrong_member = with_settings(&requested, changed)?;
    assert!(wrong_member.bind_outer(outer).is_err());
    let mut changed = requested.settings();
    let port = changed.gate.path.client.port();
    changed
        .gate
        .path
        .client
        .set_port(if port == u16::MAX { port - 1 } else { port + 1 });
    let wrong_path = with_settings(&requested, changed)?;
    assert!(wrong_path.bind_outer(outer).is_err());
    let mut changed = requested.settings();
    changed.cover.max_packet_bytes += 1;
    let too_large = with_settings(&requested, changed)?;
    let before = too_large.settings();
    assert!(too_large.bind_outer(outer).is_err());
    assert_eq!(too_large.settings(), before);
    assert!(too_large.carrier_binding().is_none());
    Ok(())
}

#[path = "live_tuning_profile_tests.rs"]
mod live_tuning;
