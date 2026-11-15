//! Portable codec bounds and projection facts, not handshake or native acceptance.

use super::*;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn literal() -> Vec<u8> {
    let mut bytes = b"L2TC\x01\x01\x01\x00".to_vec();
    bytes.extend_from_slice(&[0xa5; 32]);
    for number in [
        1500_u64, 3, 1, 1500, 2_000_001, 1424, 7, 1, 3, 9, 65_537, 1501, 123, 5001, 10_001, 20_001,
        900_001, 2, 1, 1500, 1_000_002, 1200, 5, 2, 7, 11, 32_769, 1501, 17, 3007, 11_003, 30_001,
        700_003,
    ] {
        bytes.extend_from_slice(&number.to_be_bytes());
    }
    bytes
}
fn complete() -> Result<Configuration> {
    Ok(Configuration::decode(&literal())?)
}

#[test]
fn portable_complete_value_matches_independent_literal_and_roundtrips_without_rounding() -> Result {
    let value = complete()?;
    let canonical = CanonicalConfiguration::from_configuration(value)?;
    let mut expected = String::new();
    for byte in literal() {
        use std::fmt::Write;
        write!(&mut expected, "{byte:02x}")?;
    }
    assert_eq!(canonical.as_str(), expected);
    assert_eq!(canonical.as_str().len(), 608);
    assert_eq!(canonical.configuration()?, value);
    let encoded = serde_json::to_string(&canonical)?;
    assert_eq!(encoded, format!("\"{expected}\""));
    assert_eq!(
        serde_json::from_str::<CanonicalConfiguration>(&encoded)?,
        canonical
    );
    let descriptor = canonical.configuration()?.descriptor();
    assert_eq!(descriptor.forward().bytes_per_second, 2_000_001);
    assert_eq!(descriptor.reverse().bytes_per_second, 1_000_002);
    assert_eq!(descriptor.forward().records.codec.repair_denominator, 3);
    assert_eq!(descriptor.reverse().records.channels, 2);
    Ok(())
}

#[test]
fn portable_complete_value_rejects_lengths_case_types_and_existing_parser_failures() -> Result {
    let canonical = CanonicalConfiguration::from_configuration(complete()?)?;
    let text = canonical.as_str();
    let mut wrong_prefix = text.to_owned();
    wrong_prefix.replace_range(..2, "00");
    let mut wrong_fraction = text.to_owned();
    // Canonical offset104 is the complete forward repair denominator.
    wrong_fraction.replace_range(208..224, "0000000000000000");
    for invalid in [
        String::new(),
        text[..607].to_owned(),
        format!("{text}0"),
        text.to_ascii_uppercase(),
        format!("g{}", &text[1..]),
        wrong_prefix,
        wrong_fraction,
        format!(" {}", &text[1..]),
    ] {
        assert!(
            serde_json::from_str::<CanonicalConfiguration>(&serde_json::to_string(&invalid)?)
                .is_err()
        );
    }
    for invalid in ["0", "true", "null", "[]", "{}"] {
        assert!(serde_json::from_str::<CanonicalConfiguration>(invalid).is_err());
    }
    Ok(())
}

fn maximum_direction() -> Direction {
    Direction {
        bytes_per_second: 1_250_000_000,
        channels: 64,
        layer: Layer::Ethernet,
        max_native: 65_534,
        datagram_bytes: 65_000,
        window: 255,
        repair_numerator: 65_536,
        repair_denominator: 65_536,
        flow_sources: 65_535,
        queue_bytes: 1 << 30,
        max_packet: 65_535,
        flush_micros: 1_000_000,
        feedback_micros: u64::MAX,
        tail_micros: u64::MAX,
        min_rto_micros: 60_000_000,
        max_rto_micros: 60_000_000,
    }
}

fn maximum_status() -> Result<Status> {
    let scope = Scope {
        epoch: u64::MAX,
        configuration: [255; 32],
    };
    Ok(Status {
        generation: u64::MAX,
        carrier: "media-like".into(),
        algorithm: "swift".into(),
        protection: "chacha20-poly1305".into(),
        backend: "generic_swift_v1".into(),
        running: false,
        elapsed_micros: Some(u64::MAX),
        // Conservatively exceed every current bounded enum spelling.
        terminal: Some("x".repeat(64)),
        service_terminal: Some("x".repeat(64)),
        session: [255; 16],
        transcript: [255; 32],
        outer: [255; 32],
        member: [255; 32],
        initiator_noise: [255; 32],
        responder_noise: [255; 32],
        local: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535".into(),
        peer: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535".into(),
        configuration: [255; 32],
        catalog: [255; 32],
        catalog_members: 64,
        initial: CanonicalConfiguration::from_configuration(complete()?)?,
        current: Some(CanonicalConfiguration::from_configuration(complete()?)?),
        requested: Some(CanonicalConfiguration::from_configuration(complete()?)?),
        epoch: Some(u64::MAX),
        phase: Some(Phase::FollowerCommitted),
        operation: Some(Operation {
            role: "responder".into(),
            lane: u32::MAX,
            local_endpoint: u32::MAX,
            remote_endpoint: u32::MAX,
            attempt: u64::MAX,
            epoch: u64::MAX,
            configuration: [255; 32],
            origin: scope,
            expires_millis: u64::MAX,
        }),
        physical_scope: Some(scope),
        send: Some(maximum_direction()),
        receive: Some(maximum_direction()),
        storage: Some(Storage {
            limit_bytes: u64::MAX,
            fixed_bytes: u64::MAX,
            external_bytes: u64::MAX,
            engine_bytes: u64::MAX,
            building_bytes: u64::MAX,
            peak_bytes: u64::MAX,
        }),
        resource_preallocation_complete: false,
        native_storage_capacity_bytes: Some(u64::MAX),
        workspace_capacity_bytes: Some(u64::MAX),
        loop_input_capacity_bytes: Some(u64::MAX),
        wire: Some(Wire {
            packets: u64::MAX,
            ip_bytes: u64::MAX,
            socket_accepted_packets: u64::MAX,
            socket_accepted_ip_bytes: u64::MAX,
            socket_drops: u64::MAX,
            socket_receive_errors: u64::MAX,
            received_packets: u64::MAX,
            rejected_packets: u64::MAX,
            replay_rejections: u64::MAX,
        }),
        native: Some(Native {
            read: u64::MAX,
            written: u64::MAX,
            oversize: u64::MAX,
            backpressure_drops: u64::MAX,
            pending_packets: u64::MAX,
            pending_bytes: u64::MAX,
        }),
        control: Some(Control {
            send_records: u64::MAX,
            send_bytes: u64::MAX,
            receive_records: u64::MAX,
            receive_bytes: u64::MAX,
        }),
        security: Some(Security {
            user_number: Some(u64::MAX),
            control_number: Some(u64::MAX),
            user_generation: Some(u64::MAX),
            control_generation: Some(u64::MAX),
        }),
        liveness: Some(Liveness {
            ping: Some(u64::MAX),
            deadline_micros: Some(u64::MAX),
            last_verified_micros: Some(u64::MAX),
            last_pong_micros: Some(u64::MAX),
        }),
        swift_unconfirmed: Some(u64::MAX),
        configuration_change: true,
        coordinator: false,
        reconnect: true,
        cross_profile_switching: false,
        retained_state_recovery: false,
        fresh_rekey: false,
    })
}

#[test]
fn portable_status_preserves_strict_fields_and_leaves_room_in_the8192_byte_reply() -> Result {
    // Conservative numeric/string upper bounds, not a fabricated valid runtime.
    let value = maximum_status()?;
    let bytes = serde_json::to_vec(&value)?;
    assert!(
        bytes.len() <= 7800,
        "maximum portable status uses{}bytes",
        bytes.len()
    );
    assert_eq!(serde_json::from_slice::<Status>(&bytes)?, value);
    let mut altered = serde_json::to_value(&value)?;
    altered
        .as_object_mut()
        .ok_or("status object")?
        .insert("unknown".into(), true.into());
    assert!(serde_json::from_value::<Status>(altered).is_err());
    let mut altered = serde_json::to_value(&value)?;
    altered["wire"]
        .as_object_mut()
        .ok_or("wire object")?
        .insert("unknown".into(), true.into());
    assert!(serde_json::from_value::<Status>(altered).is_err());
    for forbidden in [
        "\"cookie\"",
        "\"private\"",
        "\"payload\"",
        "\"psk\"",
        "\"admission\"",
    ] {
        assert!(!std::str::from_utf8(&bytes)?.contains(forbidden));
    }
    Ok(())
}

#[test]
fn complete_v3_request_and_maximum_response_fit_existing_transport_bounds() -> Result {
    use crate::local;
    let request = local::Request {
        version: local::TRANSACTION_VERSION,
        action: local::Action::SwitchSwiftConfiguration {
            configuration: CanonicalConfiguration::from_configuration(complete()?)?,
        },
    };
    let bytes = serde_json::to_vec(&request)?;
    assert!(bytes.len() <= 4096);
    assert_eq!(serde_json::from_slice::<local::Request>(&bytes)?, request);
    let response = local::Response {
        version: local::TRANSACTION_VERSION,
        ok: false,
        code: "invalid_configuration".into(),
        state: Some(local::Snapshot {
            epoch: u64::MAX,
            phase: "authenticating".into(),
            compression: local::Compression::Off,
            active: None,
            proxy: None,
            openvpn_drain: None,
            raw_packet: None,
            rolling: None,
            #[cfg(unix)]
            swift: None,
            #[cfg(unix)]
            secure_udp: None,
            transaction: Some(maximum_status()?),
            common: None,
        }),
    };
    let bytes = serde_json::to_vec(&response)?;
    assert!(
        bytes.len() <= 8192,
        "maximum v3 response uses {} bytes",
        bytes.len()
    );
    assert_eq!(serde_json::from_slice::<local::Response>(&bytes)?, response);
    let canonical = CanonicalConfiguration::from_configuration(complete()?)?;
    for text in [
        format!(
            "{{\"version\":3,\"action\":{{\"command\":\"switch_swift_configuration\",\"configuration\":\"{}\",\"extra\":0}}}}",
            canonical.as_str()
        ),
        format!(
            "{{\"version\":3,\"action\":{{\"command\":\"switch_swift_configuration\",\"configuration\":\"{}\",\"configuration\":\"{}\"}}}}",
            canonical.as_str(),
            canonical.as_str()
        ),
    ] {
        assert!(serde_json::from_str::<local::Request>(&text).is_err());
    }
    Ok(())
}

#[cfg(unix)]
mod projection {
    use super::*;
    use crate::secure_udp::{member, transaction_profile};
    use l2tunnel::swift_configuration::{Catalog, Descriptor, EnvelopeDigest};
    use l2tunnel_core::Epoch;
    use l2tunnel_management::{self as mg, control_streams, delivery, messages, transaction};
    use l2tunnel_runtime::secure_udp::{establish, transport};
    use l2tunnel_security::{self as security, Role};
    use l2tunnel_swift::records;
    use std::time::Duration;

    fn profile(appearance: l2tunnel_cover::Appearance) -> Result<transaction_profile::Profile> {
        let (base, peers) = crate::secure_udp::profile::tests::fixture(
            l2tunnel_udp_control::Path {
                client: "127.0.0.1:41221".parse()?,
                server: "127.0.0.1:41222".parse()?,
            },
            appearance,
            l2tunnel_identity::MemberPublicKey([7; 32]),
        )?;
        let mut initiator = base.runtime(Role::Initiator);
        let mut responder = base.runtime(Role::Responder);
        let mut forward = initiator.send;
        let mut reverse = initiator.receive;
        forward.records.channels = 2;
        reverse.records.channels = 3;
        forward.bytes_per_second = 1_250_001;
        reverse.bytes_per_second = 625_013;
        forward.records.codec.repair_numerator = 1;
        forward.records.codec.repair_denominator = 3;
        reverse.records.codec.repair_numerator = 2;
        reverse.records.codec.repair_denominator = 7;
        let initial = Descriptor::new(1500, forward, reverse)?;
        forward.records.channels = 4;
        reverse.records.channels = 1;
        let target = Descriptor::new(1500, forward, reverse)?;
        initiator.send = initial.forward();
        initiator.receive = initial.reverse();
        responder.send = initial.reverse();
        responder.receive = initial.forward();
        for template in [&mut initiator, &mut responder] {
            let stream = messages::Settings {
                delivery: delivery::Settings {
                    wire_overhead: template.control.wire_overhead + control_streams::HEADER_BYTES,
                    ..template.control
                },
                path_mtu: template.path_mtu,
                max_message_bytes: 4096,
                max_outbound_messages: 4,
                max_outbound_bytes: 131_072,
                max_fragments: 32,
                max_reassembly_bytes: 16_384,
                max_incomplete_messages: 2,
                message_lifetime: Duration::from_secs(5),
                work_per_call: 8,
            };
            template.streams = Some(l2tunnel_runtime::secure_udp::control::Settings {
                streams: [stream; 3],
            });
        }
        Ok(transaction_profile::Profile::new(
            base.connection(),
            base.settings(),
            peers,
            initiator,
            responder,
            Catalog::new(initial, &[initial, target])?,
            transaction_profile::Parameters {
                protocol: transaction::Settings {
                    retry_ms: 10,
                    phase_timeout_ms: 500,
                    reconcile_timeout_ms: 1000,
                },
                max_operation_ms: 1500,
                retained_bytes: 16 << 20,
            },
        )?)
    }

    fn info(profile: &transaction_profile::Profile, role: Role) -> Result<member::Info> {
        let settings = profile.settings();
        let authenticated = settings
            .runtime(role, profile.peers())?
            .expected_binding(profile.peers(), security::SessionId([1; 16]))?;
        let path = settings.gate.path;
        let (local_addr, peer_addr) = match role {
            Role::Initiator => (path.client, path.server),
            Role::Responder => (path.server, path.client),
        };
        // Logical projection fixture only; actual service tests authenticate these facts.
        Ok(member::Info {
            binding: security::SessionBinding {
                session: security::SessionId([1; 16]),
                transcript: [2; 32],
            },
            authenticated: l2tunnel_handshake::Binding {
                session: security::SessionId([1; 16]),
                configuration: profile.configuration()?.0,
                carrier: authenticated.carrier,
                outer: authenticated.outer,
                member: authenticated.member,
            },
            member: settings.member,
            peers: profile.peers(),
            role,
            local_addr,
            peer_addr,
            statistics: establish::Statistics::default(),
        })
    }
    fn snapshot(
        profile: &transaction_profile::Profile,
        info: member::Info,
    ) -> Result<transport::TransactionSnapshot> {
        let config = profile.runtime_for(profile.initial(), info.role)?;
        Ok(transport::TransactionSnapshot {
            running: true,
            elapsed_micros: 1234,
            info,
            configuration: profile.configuration()?,
            physical_scope: l2tunnel::secure_record::Scope {
                epoch: security::Epoch(10),
                configuration: security::ConfigDigest(profile.data_digest().0),
            },
            current: profile.initial(),
            requested: None,
            operation: None,
            epoch: Epoch(10),
            phase: transaction::Phase::Idle,
            storage: l2tunnel_swift::storage::Usage {
                limit_bytes: 16 << 20,
                fixed_bytes: 101,
                external_bytes: 202,
                engine_bytes: 303,
                building_bytes: 0,
                peak_bytes: 606,
            },
            resource_preallocation_complete: false,
            send: config.send,
            receive: config.receive,
            swift: records::Stats::default(),
            swift_unconfirmed: 9,
            channels: Vec::new(),
            performance: transport::Performance::default(),
            control: l2tunnel_recovery::Retained {
                send_records: 5,
                send_bytes: 6,
                receive_records: 7,
                receive_bytes: 8,
            },
            counters: transport::Counters {
                wire_packets: 11,
                wire_bytes: 22,
                socket_accepted_packets: 10,
                socket_accepted_ip_bytes: 20,
                native_read: 15,
                native_written: 2,
                native_pending_packets: 3,
                native_pending_bytes: 44,
                native_storage_capacity_bytes: 1000,
                workspace_capacity_bytes: 2000,
                loop_input_capacity_bytes: 3000,
                user_number: Some(security::PacketNumber(123)),
                user_generation: Some(security::KeyGeneration(4)),
                ..transport::Counters::default()
            },
            liveness: transport::Liveness {
                outstanding: Some(51),
                deadline_micros: Some(6000),
                last_verified_micros: Some(1111),
                last_pong_micros: Some(1000),
            },
            terminal: None,
        })
    }

    #[test]
    fn absent_runtime_never_fabricates_current_epoch_counters_or_resource_readiness() -> Result {
        for appearance in [
            l2tunnel_cover::Appearance::QuicLike,
            l2tunnel_cover::Appearance::MediaLike,
        ] {
            let profile = profile(appearance)?;
            for role in [Role::Initiator, Role::Responder] {
                let info = info(&profile, role)?;
                let value = Status::observe(&profile, info, 17, None)?;
                assert_eq!(value.generation, 17);
                assert_eq!(value.initial.configuration()?, profile.initial());
                assert_eq!(value.catalog, *profile.catalog().root().as_bytes());
                assert_eq!(value.catalog_members, 2);
                assert_eq!(value.session, info.binding.session.0);
                assert_eq!(value.configuration, info.authenticated.configuration);
                assert_eq!(value.coordinator, role == Role::Initiator);
                assert!(!value.running);
                assert!(!value.resource_preallocation_complete);
                assert!(
                    !value.cross_profile_switching
                        && !value.retained_state_recovery
                        && !value.fresh_rekey
                );
                assert!(
                    value.current.is_none() && value.requested.is_none() && value.epoch.is_none()
                );
                assert!(
                    value.phase.is_none()
                        && value.operation.is_none()
                        && value.physical_scope.is_none()
                );
                assert!(
                    value.elapsed_micros.is_none()
                        && value.wire.is_none()
                        && value.native.is_none()
                );
                assert!(
                    value.control.is_none() && value.security.is_none() && value.liveness.is_none()
                );
                assert!(value.send.is_none() && value.receive.is_none() && value.storage.is_none());
                assert!(value.native_storage_capacity_bytes.is_none());
                assert!(
                    value.workspace_capacity_bytes.is_none()
                        && value.loop_input_capacity_bytes.is_none()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn projection_preserves_actual_crossing_operation_units_and_irreversible_native_facts() -> Result
    {
        for appearance in [
            l2tunnel_cover::Appearance::QuicLike,
            l2tunnel_cover::Appearance::MediaLike,
        ] {
            let profile = profile(appearance)?;
            let info = info(&profile, Role::Initiator)?;
            let mut snapshot = snapshot(&profile, info)?;
            let target = profile
                .catalog()
                .descriptors()
                .iter()
                .copied()
                .find(|value| *value != profile.initial().descriptor())
                .ok_or("target")?;
            let target = Configuration::new(profile.envelope(), target)?;
            let mut peer = transaction::Peer::new_leased_directional(
                transaction::Identity {
                    session: mg::SessionId(info.binding.session.0),
                    role: mg::Role::Client,
                    local: mg::EndpointId(1),
                    remote: mg::EndpointId(2),
                    lane: mg::LaneId(0),
                },
                Epoch(10),
                profile.initial(),
                &[profile.initial(), target],
                profile.parameters().protocol,
                transaction::LeaseSettings {
                    session_expires: transaction::Tick(10000),
                    max_operation_ms: 1500,
                    transaction_epoch: 4,
                },
                transaction::Tick(0),
            )?;
            let _ = peer.propose_until(target, transaction::Tick(10), transaction::Tick(1000))?;
            snapshot.current = target;
            snapshot.requested = Some(target);
            snapshot.epoch = Epoch(11);
            snapshot.phase = peer.phase();
            snapshot.operation = peer.operation();
            snapshot.send = profile.runtime_for(target, info.role)?.send;
            // Receive and physical scope deliberately retain their actual old values.
            snapshot.swift.receiver.packets = 100;
            snapshot.terminal = Some(transport::StopReason::PolicyTimeout);
            let value = Status::observe(&profile, info, 18, Some(&snapshot))?;
            assert_eq!(
                value.current.as_ref().ok_or("current")?.configuration()?,
                target
            );
            assert_eq!(
                value
                    .requested
                    .as_ref()
                    .ok_or("requested")?
                    .configuration()?,
                target
            );
            assert_eq!(value.epoch, Some(11));
            assert_eq!(value.physical_scope.ok_or("physical")?.epoch, 10);
            assert_eq!(
                value.physical_scope.ok_or("physical")?.configuration,
                profile.data_digest().0
            );
            assert_eq!(
                value.operation.as_ref().ok_or("operation")?.expires_millis,
                1000
            );
            assert_eq!(
                value
                    .operation
                    .as_ref()
                    .ok_or("operation")?
                    .origin
                    .configuration,
                profile.data_digest().0
            );
            assert_eq!(value.phase, Some(Phase::Staging));
            assert_eq!(value.send.ok_or("send")?.channels, 4);
            assert_eq!(value.receive.ok_or("receive")?.channels, 3);
            assert_eq!(value.send.ok_or("send")?.bytes_per_second, 1_250_001);
            assert_eq!(value.send.ok_or("send")?.repair_denominator, 3);
            assert_eq!(value.native.ok_or("native")?.written, 2);
            assert_eq!(value.native.ok_or("native")?.pending_packets, 3);
            assert_eq!(value.wire.ok_or("wire")?.ip_bytes, 22);
            assert_eq!(value.storage.ok_or("storage")?.external_bytes, 202);
            assert_eq!(value.native_storage_capacity_bytes, Some(1000));
            assert_eq!(value.workspace_capacity_bytes, Some(2000));
            assert_eq!(value.loop_input_capacity_bytes, Some(3000));
            assert_eq!(value.control.ok_or("control")?.send_records, 5);
            assert_eq!(value.security.ok_or("security")?.user_number, Some(123));
            assert_eq!(
                value.liveness.ok_or("liveness")?.deadline_micros,
                Some(6000)
            );
            assert_eq!(value.elapsed_micros, Some(1234));
            assert_eq!(value.terminal.as_deref(), Some("PolicyTimeout"));
            assert!(value.service_terminal.is_none());
            assert!(!value.resource_preallocation_complete);
        }
        Ok(())
    }

    #[test]
    fn projection_rejects_mismatched_actual_identity_snapshot_and_unlisted_values() -> Result {
        let profile = profile(l2tunnel_cover::Appearance::QuicLike)?;
        let info = info(&profile, Role::Initiator)?;
        let snapshot = snapshot(&profile, info)?;
        let mut wrong = info;
        wrong.peers.initiator.0[0] ^= 1;
        assert!(Status::observe(&profile, wrong, 1, None).is_err());
        let mut wrong = info;
        wrong.authenticated.configuration[0] ^= 1;
        assert!(Status::observe(&profile, wrong, 1, None).is_err());
        for field in 0..3 {
            let mut wrong = info;
            match field {
                0 => wrong.authenticated.carrier[0] ^= 1,
                1 => wrong.authenticated.outer[0] ^= 1,
                _ => wrong.authenticated.member = info.member.0,
            }
            assert!(Status::observe(&profile, wrong, 1, None).is_err());
        }
        let mut wrong = snapshot.clone();
        wrong.info.binding.transcript[0] ^= 1;
        assert!(Status::observe(&profile, info, 1, Some(&wrong)).is_err());
        let mut wrong = snapshot.clone();
        wrong.configuration = security::ConfigDigest([0; 32]);
        assert!(Status::observe(&profile, info, 1, Some(&wrong)).is_err());
        let mut forward = profile.initial().descriptor().forward();
        forward.bytes_per_second += 1;
        let unlisted = Configuration::new(
            profile.envelope(),
            Descriptor::new(1500, forward, profile.initial().descriptor().reverse())?,
        )?;
        let mut wrong = snapshot.clone();
        wrong.current = unlisted;
        assert!(Status::observe(&profile, info, 1, Some(&wrong)).is_err());
        let mut wrong = snapshot;
        wrong.requested = Some(Configuration::new(
            EnvelopeDigest::new([0; 32]),
            unlisted.descriptor(),
        )?);
        assert!(Status::observe(&profile, info, 1, Some(&wrong)).is_err());
        Ok(())
    }

    #[test]
    fn actual_phase_mapping_is_finite_distinct_and_strict() -> Result {
        let phases = [
            transaction::Phase::Idle,
            transaction::Phase::Staging,
            transaction::Phase::AwaitReady,
            transaction::Phase::Draining,
            transaction::Phase::AwaitBarrier,
            transaction::Phase::AwaitCommitAck,
            transaction::Phase::AwaitRetireAck,
            transaction::Phase::Aborting,
            transaction::Phase::Uncertain,
            transaction::Phase::FollowerStaging,
            transaction::Phase::FollowerReady,
            transaction::Phase::FollowerDraining,
            transaction::Phase::FollowerDrained,
            transaction::Phase::FollowerCommitted,
            transaction::Phase::Failed,
        ];
        let mut encodings = std::collections::BTreeSet::new();
        for phase in phases {
            let value = Phase::from(phase);
            let json = serde_json::to_string(&value)?;
            assert!(encodings.insert(json.clone()));
            assert_eq!(serde_json::from_str::<Phase>(&json)?, value);
        }
        assert!(serde_json::from_str::<Phase>("\"unknown\"").is_err());
        assert!(serde_json::from_str::<Phase>("1").is_err());
        Ok(())
    }
}
