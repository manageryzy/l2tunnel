use super::*;
use crate::cli::secure_udp_frontend::Selection;
use l2tunnel_handshake as hs;
use l2tunnel_identity as identity;
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) fn fixture(
    path: l2tunnel_udp_control::Path,
    appearance: l2tunnel_cover::Appearance,
    member: identity::MemberPublicKey,
) -> io::Result<(Profile, establish::Peers)> {
    let peers = establish::Peers {
        initiator: hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key(),
        responder: hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key(),
    };
    let selection = Selection {
        appearance,
        role: security::Role::Initiator,
        local: path.client,
        peer: path.server,
        policy: Policy {
            path_mtu: 1500,
            forward_kbit: 10_000,
            reverse_kbit: 5_000,
            channels: 4,
            window: 32,
            repair_permille: 0,
        },
        maximum_mtu: 2000,
        profile: hs::Profile::Ik,
        report: Some(Duration::from_millis(100)),
    };
    let connection = ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex: Duplex::Full,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    };
    Ok((selection.build(connection, peers, member)?, peers))
}
fn sample(appearance: l2tunnel_cover::Appearance) -> io::Result<(Profile, establish::Peers)> {
    fixture(
        l2tunnel_udp_control::Path {
            client: "127.0.0.1:41021".parse().map_err(io::Error::other)?,
            server: "127.0.0.1:41022".parse().map_err(io::Error::other)?,
        },
        appearance,
        identity::MemberPublicKey([7; 32]),
    )
}

#[test]
fn global_roles_exact_geometry_roundtrip_and_upward_capacity_are_bound() -> io::Result<()> {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let (profile, peers) = sample(appearance)?;
        let initial = profile.initial_policy()?;
        assert_eq!(
            profile.configuration(peers)?,
            profile.with_policy(&initial)?.configuration(peers)?
        );
        let a = profile
            .resolve(&initial, security::Role::Initiator, peers)
            .ok_or_else(|| invalid("initiator resolution"))?;
        let b = profile
            .resolve(&initial, security::Role::Responder, peers)
            .ok_or_else(|| invalid("responder resolution"))?;
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.send, b.receive);
        assert_eq!(a.receive, b.send);
        assert_eq!(
            a.send.records.codec.datagram_bytes,
            if appearance == l2tunnel_cover::Appearance::QuicLike {
                1424
            } else {
                1423
            }
        );
        let mut next = initial;
        next.path_mtu = 1800;
        next.forward_kbit += 1000;
        let upgraded = profile.with_policy(&next)?;
        assert_ne!(
            profile.configuration(peers)?,
            upgraded.configuration(peers)?
        );
        assert_eq!(
            upgraded.initiator.receive.bytes_per_second,
            profile.initiator.receive.bytes_per_second
        );
        assert_eq!(
            upgraded.initiator.send.records.codec.queue_bytes,
            profile.initiator.send.records.codec.queue_bytes
        );
        assert_eq!(
            upgraded.session.gate.path_mtu, 1500,
            "bootstrap MTU is independent of current data policy"
        );
        next.path_mtu = 2100;
        assert!(profile.with_policy(&next).is_err());
    }
    Ok(())
}

#[test]
fn both_runtime_contracts_and_exact_duration_resources_change_global_digest() -> io::Result<()> {
    let (profile, peers) = sample(l2tunnel_cover::Appearance::QuicLike)?;
    let mut initiator = profile.initiator;
    let mut responder = profile.responder;
    initiator.report_interval = None;
    responder.report_interval = Some(Duration::from_secs(2));
    let local = Profile::new(
        profile.connection,
        profile.session_with_seed(),
        initiator,
        responder,
    )?;
    assert_eq!(local.configuration(peers)?, profile.configuration(peers)?);
    initiator.lifetime.pong_timeout += Duration::from_nanos(1);
    responder.lifetime.pong_timeout += Duration::from_nanos(1);
    let changed = Profile::new(
        profile.connection,
        profile.session_with_seed(),
        initiator,
        responder,
    )?;
    assert_ne!(changed.configuration(peers)?, profile.configuration(peers)?);
    initiator.work.receive_packets += 1;
    assert!(
        Profile::new(
            profile.connection,
            profile.session_with_seed(),
            initiator,
            responder
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn partial_policy_api_rejects_unrepresentable_startup_without_rounding() -> io::Result<()> {
    let (profile, peers) = sample(l2tunnel_cover::Appearance::QuicLike)?;
    let mut maximum = profile.initial_policy()?;
    maximum.channels = 64;
    maximum.forward_kbit = 10_000_000;
    maximum.reverse_kbit = 64;
    let boundary = profile.with_policy(&maximum)?;
    assert_eq!(boundary.initial_policy()?, maximum);
    let unchanged = boundary.with_policy(&boundary.initial_policy()?)?;
    assert_eq!(
        boundary.configuration(peers)?,
        unchanged.configuration(peers)?
    );
    assert_eq!(boundary.initiator.send, unchanged.initiator.send);
    assert_eq!(boundary.initiator.receive, unchanged.initiator.receive);
    for field in 0..10 {
        let mut initiator = profile.initiator;
        let mut responder = profile.responder;
        match field {
            0 => {
                initiator.send.bytes_per_second += 1;
                responder.receive = initiator.send;
            }
            1 => {
                initiator.send.records.codec.repair_numerator = 1;
                initiator.send.records.codec.repair_denominator = 3;
                responder.receive = initiator.send;
            }
            2 => {
                initiator.receive.records.channels = 2;
                responder.send = initiator.receive;
            }
            3 => {
                initiator.receive.records.codec.window = 16;
                responder.send = initiator.receive;
            }
            4 => {
                initiator.receive.records.codec.repair_numerator = 1;
                responder.send = initiator.receive;
            }
            5 => {
                initiator.send.records.codec.datagram_bytes -= 1;
                responder.receive = initiator.send;
            }
            6 => {
                initiator.send.records.channels = 65;
                initiator.receive.records.channels = 65;
                responder.send = initiator.receive;
                responder.receive = initiator.send;
            }
            7 => {
                initiator.send.bytes_per_second = 63 * 125;
                responder.receive = initiator.send;
            }
            8 => {
                initiator.send.bytes_per_second = 10_000_001 * 125;
                responder.receive = initiator.send;
            }
            _ => {
                initiator.receive.bytes_per_second = (u64::from(u32::MAX) + 1) * 125;
                responder.send = initiator.receive;
            }
        }
        assert!(
            Profile::new(
                profile.connection,
                profile.session_with_seed(),
                initiator,
                responder
            )
            .is_err(),
            "unrepresentable startup field {field} was accepted"
        );
    }
    Ok(())
}

#[test]
fn cli_burst_credit_is_role_specific_fixed_and_bound_by_both_authenticated_contracts()
-> io::Result<()> {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let (base, peers) = sample(appearance)?;
        let path = base.session.gate.path;
        let selected = Selection {
            appearance,
            role: security::Role::Initiator,
            local: path.client,
            peer: path.server,
            policy: Policy {
                forward_kbit: 99_000,
                reverse_kbit: 9_900,
                channels: 16,
                window: 64,
                path_mtu: 1500,
                repair_permille: 0,
            },
            maximum_mtu: 9000,
            profile: hs::Profile::Ik,
            report: None,
        };
        let profile = selected.build(base.connection, peers, base.session.member)?;
        let a = profile.runtime(security::Role::Initiator);
        let b = profile.runtime(security::Role::Responder);
        let reserve = a.control.recovery.max_source_bytes
            + l2tunnel_recovery::DATA_HEADER_BYTES
            + l2tunnel_recovery::ACK_PACKET_BYTES
            + 2 * a.control.wire_overhead;
        // This positive assertion rejects the previous max-MTU-only forward cap.
        assert_eq!(a.wire.burst_bytes, 49_500 + reserve);
        assert!(a.wire.burst_bytes > 9000 + reserve);
        assert_eq!(b.wire.burst_bytes, 9000 + reserve);
        assert_eq!(a.send.bytes_per_second, 12_375_000);
        assert_eq!(b.send.bytes_per_second, 1_237_500);
        assert_eq!(a.send, b.receive);
        assert_eq!(a.receive, b.send);
        let opposite = Selection {
            role: security::Role::Responder,
            local: path.server,
            peer: path.client,
            ..selected
        }
        .build(base.connection, peers, base.session.member)?;
        assert_eq!(
            opposite.configuration(peers)?,
            profile.configuration(peers)?
        );
        for initiator in [false, true] {
            let mut a = a;
            let mut b = b;
            if initiator {
                a.wire.burst_bytes += 1;
            } else {
                b.wire.burst_bytes += 1;
            }
            let changed = Profile::new(profile.connection, profile.session_with_seed(), a, b)?;
            assert_ne!(changed.configuration(peers)?, profile.configuration(peers)?);
            assert_eq!(changed.initial_policy()?, profile.initial_policy()?);
        }
        let mut next = profile.initial_policy()?;
        next.forward_kbit = 50_000;
        let changed = profile.with_policy(&next)?;
        assert_eq!(changed.initiator.wire.burst_bytes, a.wire.burst_bytes);
        assert_eq!(changed.responder.wire.burst_bytes, b.wire.burst_bytes);
        for invalid in [1500 + reserve - 1, 16 * 1024 * 1024 + 1] {
            let mut invalid_a = a;
            invalid_a.wire.burst_bytes = invalid;
            assert!(
                Profile::new(
                    profile.connection,
                    profile.session_with_seed(),
                    invalid_a,
                    b
                )
                .is_err()
            );
            let mut invalid_b = b;
            invalid_b.wire.burst_bytes = invalid;
            assert!(
                Profile::new(
                    profile.connection,
                    profile.session_with_seed(),
                    a,
                    invalid_b
                )
                .is_err()
            );
        }
    }
    Ok(())
}

impl Profile {
    fn session_with_seed(self) -> Settings {
        Settings {
            application: self.seed,
            ..self.session
        }
    }
}

fn enable_streams(runtime: &mut transport::Config) -> io::Result<()> {
    let mut delivery = runtime.control;
    delivery.wire_overhead = delivery
        .wire_overhead
        .checked_add(l2tunnel_management::control_streams::HEADER_BYTES)
        .ok_or_else(|| invalid("stream overhead overflow"))?;
    let transaction = l2tunnel_management::messages::Settings {
        delivery,
        path_mtu: runtime.path_mtu,
        max_message_bytes: 2762,
        max_outbound_messages: 32,
        max_outbound_bytes: 1 << 20,
        max_fragments: 13,
        max_reassembly_bytes: 65_536,
        max_incomplete_messages: 1,
        message_lifetime: Duration::from_secs(30),
        work_per_call: 64,
    };
    let small = l2tunnel_management::messages::Settings {
        max_message_bytes: 192,
        max_fragments: 1,
        ..transaction
    };
    runtime.streams = Some(l2tunnel_runtime::secure_udp::control::Settings {
        streams: [transaction, small, small],
    });
    runtime.wire.burst_bytes = runtime
        .wire
        .burst_bytes
        .checked_add(2 * l2tunnel_management::control_streams::HEADER_BYTES)
        .ok_or_else(|| invalid("stream reserve overflow"))?;
    Ok(())
}

fn streamed_sample(
    appearance: l2tunnel_cover::Appearance,
) -> io::Result<(Profile, establish::Peers)> {
    let (base, peers) = sample(appearance)?;
    let mut initiator = base.initiator;
    let mut responder = base.responder;
    enable_streams(&mut initiator)?;
    enable_streams(&mut responder)?;
    Ok((
        Profile::new(
            base.connection,
            base.session_with_seed(),
            initiator,
            responder,
        )?,
        peers,
    ))
}

#[test]
fn legacy_none_keeps_pre_stream_runtime_digest_vectors() -> io::Result<()> {
    // These vectors freeze the pre-stream native-contract/v1 fixture, including
    // the original role-specific burst capacities. Selection must remain explicit.
    for (appearance, expected) in [
        (
            l2tunnel_cover::Appearance::QuicLike,
            [
                "5200a0f6a179b29423cdee4bae1d9fc73296ad48f5c6a2e5a29df95a45710faa",
                "df152296cd247c5fe30796a2280c88718c3e3aeb53f05a530ec0fea3b90fd701",
            ],
        ),
        (
            l2tunnel_cover::Appearance::MediaLike,
            [
                "2e18a5b7edd370bfb943941fe890f9873b3727e3767f1e2243e8951459c0ace4",
                "f46a6365072f4fb68b10c8892f5cb3626b263f4345c84cd1185f46ee4747c4d4",
            ],
        ),
    ] {
        let (base, _) = sample(appearance)?;
        for (runtime, expected) in [base.initiator, base.responder].into_iter().zip(expected) {
            assert!(runtime.streams.is_none());
            let actual: String = runtime
                .canonical_digest()?
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(actual, expected);
        }
    }
    Ok(())
}

#[test]
fn explicit_stream_contract_is_bound_by_both_role_profiles_without_fallback() -> io::Result<()> {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let (selected, peers) = streamed_sample(appearance)?;
        let mut legacy_a = selected.initiator;
        let mut legacy_b = selected.responder;
        legacy_a.streams = None;
        legacy_b.streams = None;
        let legacy = Profile::new(
            selected.connection,
            selected.session_with_seed(),
            legacy_a,
            legacy_b,
        )?;
        assert_ne!(selected.configuration(peers)?, legacy.configuration(peers)?);
        assert_ne!(
            selected.settings().application,
            legacy.settings().application
        );
        assert_eq!(selected.initial_policy()?, legacy.initial_policy()?);
        assert!(
            Profile::new(
                selected.connection,
                selected.session_with_seed(),
                selected.initiator,
                legacy_b,
            )
            .is_err(),
            "one selected role must not fall back to the legacy control contract"
        );
        let initial = selected.initial_policy()?;
        let unchanged = selected.with_policy(&initial)?;
        assert_eq!(
            selected.configuration(peers)?,
            unchanged.configuration(peers)?
        );
        for role in [security::Role::Initiator, security::Role::Responder] {
            assert!(selected.runtime(role).streams.is_some());
            let resolved = selected
                .resolve(&initial, role, peers)
                .ok_or_else(|| invalid("selected initial policy resolution"))?;
            assert_eq!(resolved.digest.0, selected.configuration(peers)?.0);
        }
    }
    Ok(())
}

#[test]
fn every_stream_whole_message_bound_changes_authenticated_profile() -> io::Result<()> {
    let (base, peers) = streamed_sample(l2tunnel_cover::Appearance::QuicLike)?;
    for stream in 0..3 {
        for field in 0..8 {
            let mut initiator = base.initiator;
            let mut responder = base.responder;
            for runtime in [&mut initiator, &mut responder] {
                let settings = &mut runtime
                    .streams
                    .as_mut()
                    .ok_or_else(|| invalid("missing selected streams"))?
                    .streams[stream];
                match field {
                    0 => settings.max_message_bytes += 1,
                    1 => settings.max_outbound_messages += 1,
                    2 => settings.max_outbound_bytes += 1,
                    3 => settings.max_fragments += 1,
                    4 => settings.max_reassembly_bytes += 1,
                    5 => settings.max_incomplete_messages += 1,
                    6 => settings.message_lifetime += Duration::from_nanos(1),
                    _ => settings.work_per_call += 1,
                }
            }
            let changed = Profile::new(
                base.connection,
                base.session_with_seed(),
                initiator,
                responder,
            )?;
            assert_ne!(
                changed.configuration(peers)?,
                base.configuration(peers)?,
                "stream {stream} field {field} was omitted from authentication"
            );
            assert_eq!(changed.initial_policy()?, base.initial_policy()?);
            assert!(
                Profile::new(
                    base.connection,
                    base.session_with_seed(),
                    initiator,
                    base.responder,
                )
                .is_err(),
                "role mismatch in stream {stream} field {field} was accepted"
            );
        }
    }
    Ok(())
}

#[test]
fn invalid_stream_resources_and_contexts_refuse_profile_construction() -> io::Result<()> {
    let (base, _) = streamed_sample(l2tunnel_cover::Appearance::MediaLike)?;
    for field in 0..15 {
        let mut initiator = base.initiator;
        let mut responder = base.responder;
        for runtime in [&mut initiator, &mut responder] {
            let settings = &mut runtime
                .streams
                .as_mut()
                .ok_or_else(|| invalid("missing selected streams"))?
                .streams[0];
            match field {
                0 => settings.max_message_bytes = 0,
                1 => settings.max_message_bytes = 65_537,
                2 => settings.max_outbound_messages = 0,
                3 => settings.max_outbound_messages = 65,
                4 => settings.max_outbound_bytes = 0,
                5 => settings.max_outbound_bytes = 16 * 1024 * 1024 + 1,
                6 => settings.max_fragments = 0,
                7 => settings.max_reassembly_bytes = 2 * settings.max_message_bytes - 1,
                8 => settings.max_incomplete_messages = 0,
                9 => settings.max_incomplete_messages = 65,
                10 => settings.message_lifetime = Duration::ZERO,
                11 => settings.work_per_call = 0,
                12 => settings.work_per_call = 4097,
                13 => settings.delivery.wire_overhead -= 1,
                _ => settings.path_mtu -= 1,
            }
        }
        assert!(
            Profile::new(
                base.connection,
                base.session_with_seed(),
                initiator,
                responder,
            )
            .is_err(),
            "invalid selected stream field {field} reached a prepared profile"
        );
    }
    let mut initiator = base.initiator;
    let mut responder = base.responder;
    initiator.control_epoch = security::Epoch(u64::MAX);
    responder.control_epoch = security::Epoch(u64::MAX);
    assert!(
        Profile::new(
            base.connection,
            base.session_with_seed(),
            initiator,
            responder,
        )
        .is_err(),
        "stream recovery context arithmetic must reject overflow before device work"
    );
    Ok(())
}

#[test]
fn streamed_control_requires_exact_additional_wrapper_reserve_and_path_mtu() -> io::Result<()> {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let (base, _) = sample(appearance)?;
        let mut initiator = base.initiator;
        let mut responder = base.responder;
        let legacy_reserve = initiator.control.recovery.max_source_bytes
            + l2tunnel_recovery::DATA_HEADER_BYTES
            + l2tunnel_recovery::ACK_PACKET_BYTES
            + 2 * initiator.control.wire_overhead;
        for runtime in [&mut initiator, &mut responder] {
            runtime.wire.burst_bytes = runtime.path_mtu + legacy_reserve;
        }
        Profile::new(
            base.connection,
            base.session_with_seed(),
            initiator,
            responder,
        )?;
        enable_streams(&mut initiator)?;
        enable_streams(&mut responder)?;
        let exact = initiator.path_mtu + legacy_reserve + 16;
        assert_eq!(initiator.wire.burst_bytes, exact);
        Profile::new(
            base.connection,
            base.session_with_seed(),
            initiator,
            responder,
        )?;
        for role in 0..2 {
            let mut too_small_a = initiator;
            let mut too_small_b = responder;
            if role == 0 {
                too_small_a.wire.burst_bytes -= 1;
            } else {
                too_small_b.wire.burst_bytes -= 1;
            }
            assert!(
                Profile::new(
                    base.connection,
                    base.session_with_seed(),
                    too_small_a,
                    too_small_b,
                )
                .is_err()
            );
        }

        // A control source that fits the original bare recovery contract exactly
        // must not acquire eight extra protected bytes by silently reducing data.
        let mut wide_a = base.initiator;
        let mut wide_b = base.responder;
        for runtime in [&mut wide_a, &mut wide_b] {
            runtime.control.recovery.max_source_bytes = runtime.path_mtu
                - runtime.control.wire_overhead
                - l2tunnel_recovery::DATA_HEADER_BYTES;
            let reserve = runtime.control.recovery.max_source_bytes
                + l2tunnel_recovery::DATA_HEADER_BYTES
                + l2tunnel_recovery::ACK_PACKET_BYTES
                + 2 * runtime.control.wire_overhead;
            runtime.control.bytes_per_interval = 2 * reserve;
            runtime.wire.burst_bytes = runtime.path_mtu + reserve;
        }
        Profile::new(base.connection, base.session_with_seed(), wide_a, wide_b)?;
        enable_streams(&mut wide_a)?;
        enable_streams(&mut wide_b)?;
        assert!(
            Profile::new(base.connection, base.session_with_seed(), wide_a, wide_b,).is_err(),
            "selected wrapper must fit the original explicit active MTU"
        );
    }
    Ok(())
}

#[test]
fn streamed_policy_preserves_numeric_range_and_all_fixed_owner_bounds() -> io::Result<()> {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let (base, peers) = streamed_sample(appearance)?;
        let mut policy = base.initial_policy()?;
        policy.channels = 64;
        policy.forward_kbit = 10_000_000;
        policy.reverse_kbit = 64;
        policy.window = 255;
        policy.repair_permille = 1000;
        policy.path_mtu = 1800;
        let changed = base.with_policy(&policy)?;
        assert_eq!(changed.initial_policy()?, policy);
        assert_ne!(changed.configuration(peers)?, base.configuration(peers)?);
        for role in [security::Role::Initiator, security::Role::Responder] {
            let original = base
                .runtime(role)
                .streams
                .ok_or_else(|| invalid("missing original streams"))?;
            let mut expected = original.streams;
            for settings in &mut expected {
                settings.path_mtu = usize::from(policy.path_mtu);
            }
            let runtime = changed.runtime(role);
            let actual = runtime
                .streams
                .ok_or_else(|| invalid("policy silently removed stream selection"))?;
            assert_eq!(actual.streams, expected);
            assert_eq!(runtime.control, base.runtime(role).control);
            assert_eq!(runtime.wire, base.runtime(role).wire);
            assert_eq!(
                runtime.send.records.codec.datagram_bytes,
                usize::from(policy.path_mtu) - runtime.control.wire_overhead
            );
            let resolved = base
                .resolve(&policy, role, peers)
                .ok_or_else(|| invalid("numeric selected policy resolution"))?;
            assert_eq!(resolved.digest.0, changed.configuration(peers)?.0);
        }
        let unchanged = changed.with_policy(&policy)?;
        assert_eq!(
            unchanged.configuration(peers)?,
            changed.configuration(peers)?
        );
        for field in 0..6 {
            let mut unsupported = policy;
            match field {
                0 => unsupported.channels = 65,
                1 => unsupported.forward_kbit = 63,
                2 => unsupported.reverse_kbit = 10_000_001,
                3 => unsupported.window = 0,
                4 => unsupported.repair_permille = 1001,
                _ => unsupported.path_mtu = 2100,
            }
            assert!(base.with_policy(&unsupported).is_err());
        }
    }
    Ok(())
}

#[path = "profile_stream_tests.rs"]
mod streamed_factories;
