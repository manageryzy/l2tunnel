use super::*;

fn settings() -> io::Result<(Settings, establish::Peers)> {
    let path = gate::Path {
        client: "127.0.0.1:41001".parse().map_err(invalid)?,
        server: "127.0.0.1:41002".parse().map_err(invalid)?,
    };
    let cover = Cover {
        appearance: cover::Appearance::QuicLike,
        initiator_connection: cover::ConnectionId([1; 8]),
        responder_connection: cover::ConnectionId([2; 8]),
        initiator_ssrc: cover::Ssrc(101),
        responder_ssrc: cover::Ssrc(202),
        payload_type: 96,
        max_packet_bytes: 1472,
        max_protected_bytes: 1400,
    };
    let mut gate = gate::Config::new(path, [4; 32], 1).map_err(invalid)?;
    gate.path_mtu = 1500;
    gate.outer_overhead = cover.bootstrap_overhead(false)?;
    let settings = Settings {
        gate,
        cover,
        profile: hs::Profile::Ik,
        application: ConfigDigest([5; 32]),
        outer: [6; 32],
        member: identity::MemberPublicKey([7; 32]),
        membership: Membership {
            retry_interval: Duration::from_millis(10),
            max_attempts: 32,
            receive_interval: Duration::from_millis(5),
            receive_packets_per_interval: 64,
        },
        bootstrap_receive_packets_per_interval: 64,
    };
    let peers = establish::Peers {
        initiator: hs::PeerKey([8; 32]),
        responder: hs::PeerKey([9; 32]),
    };
    Ok((settings, peers))
}

#[test]
fn global_contract_is_identical_for_complementary_role_views() -> io::Result<()> {
    let (mut selected, peers) = settings()?;
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        selected.cover.appearance = appearance;
        selected.gate.outer_overhead = selected.cover.bootstrap_overhead(false)?;
        let client = selected.runtime(security::Role::Initiator, peers)?;
        let server = selected.runtime(security::Role::Responder, peers)?;
        assert_eq!(client.binding, server.binding);
        assert_eq!(client.gate, server.gate);
        assert_eq!(client.cover.appearance(), appearance);
        assert_eq!(server.cover.appearance(), appearance);
        let mut wire = [0; 300];
        let size = client
            .cover
            .encode(
                cover::PacketMeta {
                    phase: cover::Phase::Handshake,
                    packet_number: cover::PacketNumber(0),
                    media_timestamp: cover::MediaTimestamp(0),
                },
                &[1; 145],
                &mut wire,
            )
            .map_err(invalid)?;
        assert_eq!(
            server
                .cover
                .decode(&wire[..size])
                .map_err(invalid)?
                .protected,
            &[1; 145]
        );
    }
    Ok(())
}

#[test]
fn all_public_policy_fields_change_the_digest_or_are_explicitly_rejected() -> io::Result<()> {
    let (selected, peers) = settings()?;
    let original = selected.configuration(peers)?;
    let mutations: [fn(&mut Settings); 41] = [
        |s| s.application.0[0] ^= 1,
        |s| s.outer[0] ^= 1,
        |s| s.member.0[0] ^= 1,
        |s| s.profile = hs::Profile::IkPsk2,
        |s| s.cover.appearance = cover::Appearance::MediaLike,
        |s| s.cover.initiator_connection.0[0] ^= 1,
        |s| s.cover.responder_connection.0[0] ^= 1,
        |s| s.cover.initiator_ssrc.0 += 1,
        |s| s.cover.responder_ssrc.0 += 1,
        |s| s.cover.payload_type += 1,
        |s| s.cover.max_packet_bytes -= 1,
        |s| s.cover.max_protected_bytes -= 1,
        |s| s.membership.retry_interval += Duration::from_nanos(1),
        |s| s.membership.receive_interval += Duration::from_nanos(1),
        |s| s.membership.max_attempts += 1,
        |s| s.membership.receive_packets_per_interval += 1,
        |s| s.bootstrap_receive_packets_per_interval += 1,
        |s| s.gate.base_profile[0] ^= 1,
        |s| s.gate.key_id += 1,
        |s| s.gate.path.client.set_port(41003),
        |s| s.gate.path.server.set_port(41004),
        |s| s.gate.cookie_ttl += Duration::from_nanos(1),
        |s| s.gate.handshake_timeout += Duration::from_nanos(1),
        |s| s.gate.pending_sessions += 1,
        |s| s.gate.interval += Duration::from_nanos(1),
        |s| s.gate.gate_responses += 1,
        |s| s.gate.initial_rto += Duration::from_nanos(1),
        |s| s.gate.maximum_rto += Duration::from_nanos(1),
        |s| s.gate.gate_attempts += 1,
        |s| s.gate.path_mtu += 1,
        |s| s.gate.outer_overhead += 1,
        |s| s.gate.arq.max_source_bytes += 1,
        |s| s.gate.arq.send_bytes += 1,
        |s| s.gate.arq.receive_bytes += 1,
        |s| s.gate.arq.send_records -= 1,
        |s| s.gate.arq.receive_records -= 1,
        |s| s.gate.arq.initial_rto += Duration::from_nanos(1),
        |s| s.gate.arq.maximum_rto += Duration::from_nanos(1),
        |s| s.gate.arq.ack_delay += Duration::from_nanos(1),
        |s| s.gate.arq.max_retries += 1,
        |s| s.gate.control_packets += 1,
    ];
    for (index, change) in mutations.into_iter().enumerate() {
        let mut changed = selected;
        change(&mut changed);
        if let Ok(digest) = changed.configuration(peers) {
            assert_ne!(digest, original, "unbound policy mutation {index}");
        }
    }
    let mut changed = selected;
    changed.gate.control_bytes += 1;
    assert_ne!(changed.configuration(peers)?, original);
    for direction in [true, false] {
        let mut changed = peers;
        if direction {
            changed.initiator.0[0] ^= 1;
        } else {
            changed.responder.0[0] ^= 1;
        }
        assert_ne!(selected.configuration(changed)?, original);
    }
    Ok(())
}

#[test]
fn invalid_limits_and_legacy_overhead_fail_before_socket_work() -> io::Result<()> {
    let (selected, peers) = settings()?;
    let invalids: [fn(&mut Settings); 11] = [
        |s| s.membership.retry_interval = Duration::ZERO,
        |s| s.membership.receive_interval = Duration::from_secs(2),
        |s| s.membership.max_attempts = 0,
        |s| s.membership.max_attempts = 1025,
        |s| s.membership.receive_packets_per_interval = 0,
        |s| s.membership.receive_packets_per_interval = 1025,
        |s| s.bootstrap_receive_packets_per_interval = 0,
        |s| s.bootstrap_receive_packets_per_interval = 4097,
        |s| s.cover.max_packet_bytes = usize::MAX,
        |s| s.cover.max_protected_bytes = usize::MAX,
        |s| s.gate.outer_overhead = 28,
    ];
    for (index, change) in invalids.into_iter().enumerate() {
        let mut changed = selected;
        change(&mut changed);
        assert!(
            changed.configuration(peers).is_err(),
            "invalid policy {index}"
        );
    }
    let mut media = selected.cover;
    media.appearance = cover::Appearance::MediaLike;
    assert_eq!(media.bootstrap_overhead(false)?, 43);
    assert_eq!(media.bootstrap_overhead(true)?, 63);
    Ok(())
}

#[test]
fn admitted_capacity_is_distinct_from_actual_bootstrap_path_mtu() -> io::Result<()> {
    let (mut selected, peers) = settings()?;
    selected.cover.max_packet_bytes = 8972;
    selected.cover.max_protected_bytes = 8942;
    assert!(selected.configuration(peers).is_ok());
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        selected.cover.appearance = appearance;
        selected.gate.outer_overhead = selected.cover.bootstrap_overhead(false)?;
        // Valid bootstrap control records exceed QUIC's one-byte length threshold.
        let header = selected.cover.bootstrap_overhead(false)? - 28 - 1;
        let source = selected.gate.path_mtu
            - 28
            - header
            - 1
            - gate::CONTROL_OVERHEAD
            - l2tunnel_recovery::DATA_HEADER_BYTES;
        selected.gate.arq.max_source_bytes = source;
        assert!(selected.configuration(peers).is_ok());
        selected.gate.arq.max_source_bytes = source + 1;
        assert!(selected.configuration(peers).is_err());
    }
    Ok(())
}
