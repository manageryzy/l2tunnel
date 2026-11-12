#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;

fn config() -> Config {
    Config::new(
        Path {
            client: "127.0.0.1:31001".parse().unwrap(),
            server: "127.0.0.1:31002".parse().unwrap(),
        },
        [9; 32],
        7,
    )
    .unwrap()
}
fn gates(config: Config, nonce: u8) -> (ClientGate, ServerGate) {
    (
        ClientGate::new(config, Secret::new([1; 32]), [nonce; 16], Duration::ZERO).unwrap(),
        ServerGate::new(
            config,
            Secret::new([1; 32]),
            Secret::new([2; 32]),
            Duration::ZERO,
        )
        .unwrap(),
    )
}
fn exchange(
    config: Config,
    client: &mut ClientGate,
    server: &mut ServerGate,
    now: Duration,
) -> (PathTicket, PathTicket, GateFrame) {
    let hello = client.poll(now).unwrap().unwrap();
    let GateEvent::Retry(retry) = server
        .receive(config.path.client, &hello, [3; 16], now)
        .unwrap()
    else {
        panic!("expected retry")
    };
    let client_ticket = client
        .receive_retry(config.path.server, &retry, now)
        .unwrap()
        .unwrap();
    let echo = client.poll(now).unwrap().unwrap();
    let GateEvent::Accepted(server_ticket) = server
        .receive(config.path.client, &echo, [4; 16], now)
        .unwrap()
    else {
        panic!("expected ticket")
    };
    assert_eq!(client_ticket.session(), server_ticket.session());
    (client_ticket, server_ticket, echo)
}
fn engines(config: Config) -> (ControlEngine, ControlEngine) {
    let (mut client, mut server) = gates(config, 8);
    let (a, b, _) = exchange(config, &mut client, &mut server, Duration::ZERO);
    (
        ControlEngine::new(a, Duration::ZERO).unwrap(),
        ControlEngine::new(b, Duration::ZERO).unwrap(),
    )
}

#[test]
fn gate_cookie_replay_quarantine_and_absolute_deadline() {
    let config = config();
    let (mut client, mut server) = gates(config, 8);
    let (a, b, echo) = exchange(config, &mut client, &mut server, Duration::ZERO);
    assert_eq!(b.deadline(), config.handshake_timeout);
    assert!(
        matches!(server.receive(config.path.client, &echo, [4; 16], Duration::from_secs(1)).unwrap(), GateEvent::Duplicate(id) if id == a.session())
    );
    server.finish(a.session(), Duration::from_secs(1)).unwrap();
    assert_eq!(server.statistics().retained_sessions, 1);
    assert!(matches!(
        server
            .receive(config.path.client, &echo, [4; 16], Duration::from_secs(2))
            .unwrap(),
        GateEvent::Ignored
    ));
    server.expire(config.cookie_ttl).unwrap();
    assert_eq!(server.statistics().retained_sessions, 0);
    assert!(matches!(
        server
            .receive(config.path.client, &echo, [4; 16], config.cookie_ttl)
            .unwrap(),
        GateEvent::Ignored
    ));
    assert!(matches!(
        server.expire(Duration::ZERO),
        Err(Error::TimeRegression)
    ));
    assert!(matches!(
        client.poll(config.handshake_timeout),
        Err(Error::Expired)
    ));
}

#[test]
fn gate_truncation_mac_tuple_profile_and_amplification_quota() {
    let mut config = config();
    config.gate_responses = 2;
    let (mut client, mut server) = gates(config, 8);
    let hello = client.poll(Duration::ZERO).unwrap().unwrap();
    for length in 0..GATE_BYTES {
        assert!(matches!(
            server
                .receive(
                    config.path.client,
                    &hello[..length],
                    [3; 16],
                    Duration::ZERO
                )
                .unwrap(),
            GateEvent::Ignored
        ));
    }
    for index in [0, 1, 2, 3, 4, 8, 48, 112, 143] {
        let mut forged = hello;
        forged[index] ^= 1;
        assert!(matches!(
            server
                .receive(config.path.client, &forged, [3; 16], Duration::ZERO)
                .unwrap(),
            GateEvent::Ignored
        ));
    }
    assert!(matches!(
        server
            .receive(config.path.server, &hello, [3; 16], Duration::ZERO)
            .unwrap(),
        GateEvent::Ignored
    ));
    for expected in [true, true, false] {
        assert_eq!(
            matches!(
                server
                    .receive(config.path.client, &hello, [3; 16], Duration::ZERO)
                    .unwrap(),
                GateEvent::Retry(_)
            ),
            expected
        );
    }
    let stats = server.statistics();
    assert_eq!(stats.response_bytes, 288);
    assert_eq!(stats.validated_request_bytes, 432);
    assert_eq!(stats.retained_sessions, 0);
    assert!(matches!(
        server
            .receive(config.path.client, &hello, [3; 16], config.interval)
            .unwrap(),
        GateEvent::Retry(_)
    ));
}

#[test]
fn gate_capacity_retry_attempts_and_config_arithmetic_are_bounded() {
    let mut config = config();
    config.pending_sessions = 1;
    let (mut client, mut server) = gates(config, 8);
    let (_, _, _) = exchange(config, &mut client, &mut server, Duration::ZERO);
    let mut second =
        ClientGate::new(config, Secret::new([1; 32]), [9; 16], Duration::ZERO).unwrap();
    let hello = second.poll(Duration::ZERO).unwrap().unwrap();
    assert!(matches!(
        server
            .receive(config.path.client, &hello, [3; 16], Duration::ZERO)
            .unwrap(),
        GateEvent::Ignored
    ));
    assert_eq!(server.statistics().retained_sessions, 1);
    let mut short = config;
    short.gate_attempts = 1;
    let (mut client, _) = gates(short, 7);
    client.poll(Duration::ZERO).unwrap();
    assert_eq!(client.poll(short.initial_rto), Err(Error::RetryExhausted));
    let mut invalid = config;
    invalid.outer_overhead = usize::MAX;
    assert_eq!(invalid.profile_digest(), Err(Error::Configuration));
    assert!(matches!(
        ClientGate::new(config, Secret::new([1; 32]), [9; 16], Duration::MAX),
        Err(Error::TimeOverflow)
    ));
}

#[test]
fn forged_cookie_even_with_admission_key_cannot_allocate() {
    let config = config();
    let (mut client, mut server) = gates(config, 8);
    let hello = client.poll(Duration::ZERO).unwrap().unwrap();
    let GateEvent::Retry(retry) = server
        .receive(config.path.client, &hello, [3; 16], Duration::ZERO)
        .unwrap()
    else {
        panic!("retry")
    };
    client
        .receive_retry(config.path.server, &retry, Duration::ZERO)
        .unwrap();
    let mut echo = client.poll(Duration::ZERO).unwrap().unwrap();
    echo[80] ^= 1;
    let tag = mac(
        &Secret::new([1; 32]),
        b"l2tunnel/openvpn-like/admission/v1\0",
        &echo[..112],
        config.path,
    );
    echo[112..].copy_from_slice(&tag);
    assert!(matches!(
        server
            .receive(config.path.client, &echo, [4; 16], Duration::ZERO)
            .unwrap(),
        GateEvent::Ignored
    ));
    assert_eq!(server.statistics().retained_sessions, 0);
}

#[test]
fn control_integrity_context_replay_and_partial_read() {
    let config = config();
    let (mut a, mut b) = engines(config);
    assert_eq!(
        a.write(b"arbitrary secret TLS bytes", Duration::ZERO)
            .unwrap(),
        26
    );
    let mut buffer = vec![0; a.max_datagram_bytes()];
    assert_eq!(
        a.poll(Duration::ZERO, &mut buffer[..10]),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(a.statistics().transmitted_packets, 0);
    let length = a.poll(Duration::ZERO, &mut buffer).unwrap().unwrap();
    let packet = &buffer[..length];
    for cut in 0..length {
        assert!(
            b.receive(config.path.client, &packet[..cut], Duration::ZERO)
                .is_err()
        );
    }
    let mut changed = packet.to_vec();
    changed[40] ^= 1;
    assert_eq!(
        b.receive(config.path.client, &changed, Duration::ZERO),
        Err(Error::Authentication)
    );
    assert_eq!(
        a.receive(config.path.server, packet, Duration::ZERO),
        Err(Error::Malformed)
    );
    assert_eq!(
        b.receive(config.path.server, packet, Duration::ZERO),
        Err(Error::Malformed)
    );
    assert_eq!(
        b.receive(config.path.client, packet, Duration::ZERO)
            .unwrap(),
        ReceiveOutcome::Fresh
    );
    assert_eq!(
        b.receive(config.path.client, packet, Duration::ZERO)
            .unwrap(),
        ReceiveOutcome::Replay
    );
    let mut output = Vec::new();
    let mut piece = [0; 3];
    loop {
        let count = b.read(&mut piece, Duration::ZERO).unwrap();
        if count == 0 {
            break;
        }
        output.extend_from_slice(&piece[..count]);
    }
    assert_eq!(output, b"arbitrary secret TLS bytes");
    assert_eq!(b.statistics().receive_bytes, 0);
    assert_eq!(b.statistics().received_packets, 1);
    assert_eq!(b.statistics().replay_packets, 1);
    assert_eq!(
        a.statistics().transmitted_ip_bytes,
        (length + config.outer_overhead) as u64
    );
}

#[test]
fn control_credit_reserve_and_retry_use_fresh_outer_numbers() {
    let mut config = config();
    config.control_packets = 2;
    config.control_bytes = config.path_mtu + config.ack_charge();
    let (mut a, mut b) = engines(config);
    let mut buffer = vec![0; a.max_datagram_bytes()];
    a.write(b"left", Duration::ZERO).unwrap();
    a.write(b"next", Duration::ZERO).unwrap();
    b.write(b"right", Duration::ZERO).unwrap();
    let n = a.poll(Duration::ZERO, &mut buffer).unwrap().unwrap();
    let first = buffer[..n].to_vec();
    b.receive(config.path.client, &first, Duration::ZERO)
        .unwrap();
    assert!(a.poll(Duration::ZERO, &mut buffer).unwrap().is_none());
    let n = b.poll(Duration::ZERO, &mut buffer).unwrap().unwrap();
    a.receive(config.path.server, &buffer[..n], Duration::ZERO)
        .unwrap();
    let n = a.poll(config.arq.ack_delay, &mut buffer).unwrap().unwrap();
    assert_eq!(buffer[0], 40); // Reserved feedback progresses despite exhausted source allowance.
    b.receive(config.path.client, &buffer[..n], config.arq.ack_delay)
        .unwrap();
    assert_eq!(a.statistics().transmitted_packets, 2);
    // Drop B's ACK for A; the eventual source retry keeps bytes but has a new outer PN.
    let n = a
        .poll(config.arq.initial_rto, &mut buffer)
        .unwrap()
        .unwrap();
    assert_ne!(&buffer[20..28], &first[20..28]);
    assert_eq!(&buffer[32..n - 32], &first[32..first.len() - 32]);
    assert_eq!(
        b.receive(config.path.client, &buffer[..n], config.arq.initial_rto)
            .unwrap(),
        ReceiveOutcome::Fresh
    );
}

#[test]
fn bidirectional_independent_bytes_survive_drops_reordering_and_duplicates() {
    let config = config();
    let (mut a, mut b) = engines(config);
    let left: Vec<_> = (0..40_000).map(|n| (n * 37) as u8).collect();
    let right: Vec<_> = (0..27_000).map(|n| (n * 71 + 13) as u8).collect();
    let (mut left_at, mut right_at) = (0, 0);
    let (mut got_left, mut got_right) = (Vec::new(), Vec::new());
    let mut network: Vec<(usize, bool, Vec<u8>)> = Vec::new();
    let mut emitted = 0;
    let mut scratch = vec![0; a.max_datagram_bytes()];
    for tick in 0..20_000 {
        let now = Duration::from_millis(tick as u64);
        left_at += a.write(&left[left_at..], now).unwrap();
        right_at += b.write(&right[right_at..], now).unwrap();
        for (toward_b, engine) in [(true, &mut a), (false, &mut b)] {
            for _ in 0..8 {
                let Some(n) = engine.poll(now, &mut scratch).unwrap() else {
                    break;
                };
                emitted += 1;
                if emitted % 7 == 0 {
                    continue;
                }
                network.push((tick + emitted % 11, toward_b, scratch[..n].to_vec()));
                if emitted % 13 == 0 {
                    network.push((tick + 13, toward_b, scratch[..n].to_vec()));
                }
            }
        }
        let mut index = network.len();
        while index > 0 {
            index -= 1;
            if network[index].0 > tick {
                continue;
            }
            let (_, toward_b, bytes) = network.swap_remove(index);
            let (target, peer) = if toward_b {
                (&mut b, config.path.client)
            } else {
                (&mut a, config.path.server)
            };
            target.receive(peer, &bytes, now).unwrap();
        }
        let mut piece = [0; 113];
        for (engine, output) in [(&mut b, &mut got_left), (&mut a, &mut got_right)] {
            for _ in 0..64 {
                let n = engine.read(&mut piece, now).unwrap();
                if n == 0 {
                    break;
                }
                output.extend_from_slice(&piece[..n]);
            }
            assert!(engine.statistics().send_bytes <= config.arq.send_bytes);
            assert!(
                engine.statistics().receive_bytes
                    <= config.arq.receive_bytes + config.arq.max_source_bytes
            );
        }
        if got_left.len() == left.len()
            && got_right.len() == right.len()
            && a.drained()
            && b.drained()
        {
            break;
        }
    }
    assert_eq!(got_left, left);
    assert_eq!(got_right, right);
    assert!(a.drained() && b.drained());
    assert!(emitted > (left.len() + right.len()) / config.arq.max_source_bytes);
}

#[test]
fn no_reader_and_no_ack_remain_bounded_and_fail_explicitly() {
    let mut config = config();
    config.arq.max_retries = 0;
    let (mut a, mut b) = engines(config);
    let source = vec![7; config.arq.max_source_bytes];
    for _ in 0..config.arq.send_records {
        assert_eq!(a.write(&source, Duration::ZERO).unwrap(), source.len());
    }
    assert_eq!(a.write(&source, Duration::ZERO).unwrap(), 0);
    let mut packet = vec![0; a.max_datagram_bytes()];
    let n = a.poll(Duration::ZERO, &mut packet).unwrap().unwrap();
    b.receive(config.path.client, &packet[..n], Duration::ZERO)
        .unwrap();
    assert_eq!(b.statistics().receive_bytes, source.len());
    assert!(matches!(
        a.poll(config.arq.initial_rto, &mut packet),
        Err(Error::Recovery(RecoveryError::RetryExhausted { .. }))
    ));
    assert_eq!(
        b.read(&mut [0; 1], config.handshake_timeout),
        Err(Error::Expired)
    );
}

#[test]
fn trusted_one_shot_promotion_preserves_packet_replay_recovery_and_absolute_expiry() {
    let config = config();
    let (mut a, mut b) = engines(config);
    a.write(b"retained before actual authentication", Duration::ZERO)
        .unwrap();
    let mut buffer = vec![0; a.max_datagram_bytes()];
    let n = a.poll(Duration::ZERO, &mut buffer).unwrap().unwrap();
    let first = buffer[..n].to_vec();
    b.receive(config.path.client, &first, Duration::ZERO)
        .unwrap();
    let original = a.statistics();
    let now = Duration::from_secs(1);
    let lease = Duration::from_secs(3600);
    a.promote_authenticated(lease, now).unwrap();
    b.promote_authenticated(lease, now).unwrap();
    assert_eq!(a.statistics(), original);
    assert_eq!(a.bootstrap_deadline(), config.handshake_timeout);
    assert_eq!(a.absolute_deadline(), now + lease);
    assert_eq!(
        a.promote_authenticated(lease, now),
        Err(Error::AlreadyPromoted)
    );
    let after_bootstrap = config.handshake_timeout + Duration::from_secs(1);
    let n = a.poll(after_bootstrap, &mut buffer).unwrap().unwrap();
    assert_ne!(&first[20..28], &buffer[20..28]);
    assert_eq!(&first[32..first.len() - 32], &buffer[32..n - 32]);
    assert_eq!(
        b.receive(config.path.client, &first, after_bootstrap)
            .unwrap(),
        ReceiveOutcome::Replay
    );
    assert_eq!(
        b.receive(config.path.client, &buffer[..n], after_bootstrap)
            .unwrap(),
        ReceiveOutcome::Fresh
    );
    let near_expiry = b.absolute_deadline() - Duration::from_micros(1);
    assert_eq!(
        b.receive(config.path.client, &first, near_expiry).unwrap(),
        ReceiveOutcome::Replay
    );
    assert_eq!(b.absolute_deadline(), now + lease);
    assert_eq!(b.read(&mut [0; 1], now + lease), Err(Error::Expired));
}

#[test]
fn promotion_rejects_late_regressed_invalid_and_overflow_without_changing_deadline() {
    let config = config();
    let (mut a, _) = engines(config);
    let original = a.absolute_deadline();
    assert_eq!(
        a.promote_authenticated(Duration::from_secs(3600), original),
        Err(Error::Expired)
    );
    assert_eq!(
        a.promote_authenticated(Duration::ZERO, Duration::ZERO),
        Err(Error::Configuration)
    );
    assert_eq!(
        a.promote_authenticated(Duration::from_secs(86_401), Duration::ZERO),
        Err(Error::Configuration)
    );
    a.write(b"x", Duration::from_secs(1)).unwrap();
    assert_eq!(
        a.promote_authenticated(Duration::from_secs(3600), Duration::ZERO),
        Err(Error::TimeRegression)
    );
    assert_eq!(a.absolute_deadline(), original);
    let now = Duration::from_micros(u64::MAX - 60_000_000);
    let mut client = ClientGate::new(config, Secret::new([1; 32]), [8; 16], now).unwrap();
    let mut server =
        ServerGate::new(config, Secret::new([1; 32]), Secret::new([2; 32]), now).unwrap();
    let (ticket, _, _) = exchange(config, &mut client, &mut server, now);
    let mut engine = ControlEngine::new(ticket, now).unwrap();
    let original = engine.absolute_deadline();
    assert_eq!(
        engine.promote_authenticated(Duration::from_secs(3600), now),
        Err(Error::TimeOverflow)
    );
    assert_eq!(engine.absolute_deadline(), original);
}
