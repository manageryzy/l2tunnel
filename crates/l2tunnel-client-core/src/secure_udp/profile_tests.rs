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
