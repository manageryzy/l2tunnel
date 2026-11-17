use super::*;
use l2tunnel_core::{ConfigDigest, Epoch};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn base() -> delivery::Settings {
    delivery::Settings {
        recovery: recovery::ArqConfig {
            max_source_bytes: 192,
            send_bytes: 768,
            receive_bytes: 768,
            send_records: 4,
            receive_records: 4,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(100),
            ack_delay: Duration::ZERO,
            max_retries: 64,
        },
        interval: Duration::from_millis(10),
        packets_per_interval: 2,
        bytes_per_interval: 2048,
        wire_overhead: 76,
    }
}
fn settings(base: delivery::Settings) -> Settings {
    let message = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: base.wire_overhead + 8,
            ..base
        },
        path_mtu: 1500,
        max_message_bytes: 65_536,
        max_outbound_messages: 3,
        max_outbound_bytes: 1024 * 1024,
        max_fragments: 512,
        max_reassembly_bytes: 2 * 65_536,
        max_incomplete_messages: 1,
        message_lifetime: Duration::from_secs(2),
        work_per_call: 4,
    };
    Settings {
        streams: [message; 3],
    }
}
fn scope(epoch: u64) -> sc::Scope {
    sc::Scope {
        epoch: Epoch(epoch),
        digest: ConfigDigest([epoch as u8; 32]),
    }
}
fn binding(role: mg::Role) -> delivery::Binding {
    delivery::Binding {
        session: mg::SessionId([0x61; 16]),
        lane: mg::LaneId(0),
        local_role: role,
        control_epoch: 1,
    }
}
fn verified(role: mg::Role) -> mg::Ingress {
    mg::Ingress::AuthenticatedManagement {
        session: binding(role).session,
        lane: binding(role).lane,
        sender: role,
    }
}
fn pair(base: delivery::Settings, selected: bool) -> Result<[Owner; 2]> {
    Ok([
        Owner::new(
            base,
            selected.then(|| settings(base)),
            binding(mg::Role::Client),
            scope(1),
            scope(1),
            Duration::ZERO,
            Duration::from_secs(10),
        )?,
        Owner::new(
            base,
            selected.then(|| settings(base)),
            binding(mg::Role::Server),
            scope(1),
            scope(1),
            Duration::ZERO,
            Duration::from_secs(10),
        )?,
    ])
}
fn profile(epoch: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    l2tunnel_swift::control::Message::Barrier {
        epoch,
        first_number: epoch * 3,
    }
    .encode(&mut bytes);
    bytes
}
fn submit_profile(owner: &mut Owner, epoch: u64, now: Duration) -> Result<Token> {
    owner
        .submit(
            scope(1),
            sc::Body::ProfileControl {
                tag: sc::ProfileTag::SwiftPolicyV1,
                bytes: &profile(epoch),
            },
            now,
            Duration::from_millis(1500),
            false,
        )?
        .ok_or_else(|| "unexpected profile admission pressure".into())
}
fn inspect(sender: mg::Role, frame: &[u8]) -> Result<recovery::PacketView<'_>> {
    Ok(recovery::inspect_packet(
        frame,
        recovery::RecoveryContext {
            session: u128::from_be_bytes(binding(sender).session.0),
            epoch: 4,
            role: if sender == mg::Role::Client {
                recovery::EndpointRole::Responder
            } else {
                recovery::EndpointRole::Initiator
            },
        },
        192,
    )?)
}

fn pump(peers: &mut [Owner; 2], now: Duration, drop_right_transaction: bool) -> Result<[usize; 2]> {
    let mut emitted = [0; 2];
    for (side, count) in emitted.iter_mut().enumerate() {
        let (left, right) = peers.split_at_mut(1);
        let (source, target, role) = if side == 0 {
            (&mut left[0], &mut right[0], mg::Role::Client)
        } else {
            (&mut right[0], &mut left[0], mg::Role::Server)
        };
        let mut allowance = 4096;
        let mut output = [0; 512];
        while let Some(emission) = source.poll(now, allowance, &mut output)? {
            assert_eq!(emission.wire_bytes, emission.bytes + base().wire_overhead);
            allowance -= emission.wire_bytes;
            *count += 1;
            let frame = streams::Frame::decode(
                &output[..emission.bytes],
                streams::Limits {
                    max_packet_bytes: 236,
                },
            )?;
            let drop = side == 1
                && drop_right_transaction
                && frame.stream == streams::Stream::Transaction
                && matches!(
                    inspect(role, frame.packet)?,
                    recovery::PacketView::Data { .. }
                );
            if !drop {
                target.receive(verified(role), &output[..emission.bytes], now)?;
            }
        }
    }
    Ok(emitted)
}

#[test]
fn selected_settings_preserve_global_service_and_real_maximum_message_geometry() -> Result {
    let selected = settings(base());
    selected.validate(base(), 1500, Duration::from_secs(10))?;
    assert!(
        selected
            .streams
            .iter()
            .all(|stream| stream.max_message_bytes == 65_536)
    );
    for changed in 0..4 {
        let mut invalid = selected;
        match changed {
            0 => invalid.streams[1].delivery.wire_overhead -= 8,
            1 => invalid.streams[2].delivery.packets_per_interval += 1,
            2 => invalid.streams[0].path_mtu -= 1,
            _ => invalid.streams[0].max_fragments = 1,
        }
        assert!(
            invalid
                .validate(base(), 1500, Duration::from_secs(10))
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn legacy_preserves_unwrapped_l2sc_bytes_and_source_completion() -> Result {
    let mut peers = pair(base(), false)?;
    let bytes = profile(1);
    let body = sc::Body::ProfileControl {
        tag: sc::ProfileTag::SwiftPolicyV1,
        bytes: &bytes,
    };
    let token = peers[0]
        .submit(
            scope(1),
            body,
            Duration::ZERO,
            Duration::from_secs(1),
            false,
        )?
        .ok_or("missing legacy source")?;
    assert_eq!(peers[0].legacy_next_sequence(), Some(2));
    let mut packet = [0; 512];
    let emission = peers[0]
        .poll(Duration::ZERO, 4096, &mut packet)?
        .ok_or("missing legacy packet")?;
    let view = recovery::inspect_packet(
        &packet[..emission.bytes],
        recovery::RecoveryContext {
            session: u128::from_be_bytes(binding(mg::Role::Client).session.0),
            epoch: 1,
            role: recovery::EndpointRole::Responder,
        },
        192,
    )?;
    let recovery::PacketView::Data { payload, .. } = view else {
        return Err("expected original legacy DATA".into());
    };
    let expected = sc::Envelope {
        binding: envelope_binding(binding(mg::Role::Client), 1, scope(1)),
        body,
    };
    let mut encoded = vec![0; expected.encoded_len(envelope_limits(192)?)?];
    expected.encode(&mut encoded, envelope_limits(192)?)?;
    assert_eq!(payload, encoded);
    peers[1].receive(
        verified(mg::Role::Client),
        &packet[..emission.bytes],
        Duration::ZERO,
    )?;
    let mut output = [0; 192];
    let incoming = peers[1]
        .next(Duration::ZERO, &mut output)?
        .ok_or("missing legacy delivery")?;
    assert_eq!(incoming.stream, None);
    assert_eq!(&output[..incoming.bytes], encoded);
    peers[1].accepted(incoming, Duration::ZERO)?;
    assert!(!peers[0].confirmed(token, Duration::ZERO)?);
    let ack = peers[1]
        .poll(Duration::ZERO, 4096, &mut packet)?
        .ok_or("missing legacy ACK")?;
    peers[0].receive(
        verified(mg::Role::Server),
        &packet[..ack.bytes],
        Duration::ZERO,
    )?;
    assert!(peers[0].confirmed(token, Duration::ZERO)?);
    peers[0].retire(token, Duration::ZERO)?;
    assert!(peers[0].legacy_mut().is_some());
    Ok(())
}

#[test]
fn source_acks_do_not_complete_a_streamed_policy_before_semantic_acceptance() -> Result {
    let mut peers = pair(base(), true)?;
    let token = submit_profile(&mut peers[0], 1, Duration::ZERO)?;
    let mut incoming = None;
    let mut output = vec![0; 65_536];
    let mut now = Duration::ZERO;
    for tick in 0..100 {
        now = Duration::from_millis(tick);
        pump(&mut peers, now, false)?;
        if incoming.is_none() {
            incoming = peers[1].next(now, &mut output)?;
        }
        if incoming.is_some() && peers[0].retained().send_records == 0 {
            break;
        }
    }
    let incoming = incoming.ok_or("whole policy did not arrive")?;
    assert_eq!(incoming.stream, Some(streams::Stream::Transaction));
    assert_eq!(peers[0].retained().send_records, 0);
    assert!(!peers[0].confirmed(token, now)?);
    assert!(peers[1].next(now, &mut output)?.is_none());
    assert!(peers[1].has_dispatched());
    peers[1].accepted(incoming, now)?;
    assert!(!peers[1].has_dispatched());
    for _ in 0..100 {
        now += Duration::from_millis(1);
        pump(&mut peers, now, false)?;
        if peers[0].confirmed(token, now)? {
            break;
        }
    }
    assert!(peers[0].confirmed(token, now)?);
    peers[0].retire(token, now)?;
    assert_eq!(peers[0].pending_deadline(), None);
    Ok(())
}

#[test]
fn refused_submission_does_not_burn_envelope_or_submission_identity() -> Result {
    let mut peers = pair(base(), true)?;
    let first = submit_profile(&mut peers[0], 1, Duration::ZERO)?;
    let _second = submit_profile(&mut peers[0], 2, Duration::ZERO)?;
    let _third = submit_profile(&mut peers[0], 3, Duration::ZERO)?;
    let before = match &peers[0].backend {
        Backend::Streamed(streamed) => streamed.next,
        _ => return Err("wrong backend".into()),
    };
    assert!(
        peers[0]
            .submit(
                scope(1),
                sc::Body::ProfileControl {
                    tag: sc::ProfileTag::SwiftPolicyV1,
                    bytes: &profile(4)
                },
                Duration::ZERO,
                Duration::from_millis(1500),
                false
            )?
            .is_none()
    );
    assert_eq!(
        match &peers[0].backend {
            Backend::Streamed(streamed) => streamed.next,
            _ => return Err("wrong backend".into()),
        },
        before
    );
    let mut output = vec![0; 65_536];
    for tick in 0..200 {
        let now = Duration::from_millis(tick);
        pump(&mut peers, now, false)?;
        while let Some(incoming) = peers[1].next(now, &mut output)? {
            peers[1].accepted(incoming, now)?;
        }
        if peers[0].confirmed(first, now)? {
            peers[0].retire(first, now)?;
            let fourth = submit_profile(&mut peers[0], 4, now)?;
            let TokenKind::Streamed { ticket, .. } = fourth.kind else {
                return Err("wrong token".into());
            };
            assert_eq!(ticket.submission(), messages::SubmissionId(4));
            return Ok(());
        }
    }
    Err("first message did not confirm".into())
}

#[test]
fn three_streams_share_the_original_packet_and_byte_quota() -> Result {
    let mut peers = pair(base(), true)?;
    submit_profile(&mut peers[0], 1, Duration::ZERO)?;
    peers[0]
        .submit(
            scope(1),
            sc::Body::Ping { nonce: 1 },
            Duration::ZERO,
            Duration::from_secs(1),
            true,
        )?
        .ok_or("missing Ping")?;
    let mut packet = [0; 512];
    let mut allowance = 4096;
    let mut emitted = Vec::new();
    while let Some(emission) = peers[0].poll(Duration::ZERO, allowance, &mut packet)? {
        allowance -= emission.wire_bytes;
        assert_eq!(emission.wire_bytes, emission.bytes + base().wire_overhead);
        emitted.push(
            streams::Frame::decode(
                &packet[..emission.bytes],
                streams::Limits {
                    max_packet_bytes: 236,
                },
            )?
            .stream,
        );
    }
    assert_eq!(
        emitted,
        [streams::Stream::Transaction, streams::Stream::Liveness]
    );
    assert_eq!(emitted.len(), base().packets_per_interval as usize);
    assert!(peers[0].deadline() >= base().interval);
    assert!(
        peers[0]
            .poll(Duration::from_millis(1), 4096, &mut packet)?
            .is_none()
    );
    Ok(())
}

#[test]
fn original_expiry_is_not_hidden_by_shared_quota_or_renewed_by_retries() -> Result {
    let mut peers = pair(base(), true)?;
    let token = peers[0]
        .submit(
            scope(1),
            sc::Body::Ping { nonce: 1 },
            Duration::ZERO,
            Duration::from_millis(5),
            true,
        )?
        .ok_or("missing Ping")?;
    let mut packet = [0; 512];
    peers[0].poll(Duration::ZERO, 4096, &mut packet)?;
    assert!(peers[0].deadline() <= Duration::from_millis(5));
    assert!(peers[0].confirmed(token, Duration::from_millis(5)).is_err());
    assert!(
        peers[0]
            .poll(Duration::from_millis(6), 4096, &mut packet)
            .is_err()
    );
    Ok(())
}

#[test]
fn small_output_and_wrong_verified_binding_cannot_consume_a_complete_message() -> Result {
    let mut peers = pair(base(), true)?;
    submit_profile(&mut peers[0], 1, Duration::ZERO)?;
    for tick in 0..20 {
        pump(&mut peers, Duration::from_millis(tick), false)?;
    }
    assert!(
        peers[1]
            .next(Duration::from_millis(20), &mut [0; 1])
            .is_err()
    );
    let mut output = vec![0; 65_536];
    let incoming = peers[1]
        .next(Duration::from_millis(20), &mut output)?
        .ok_or("lost held message")?;
    assert_eq!(
        sc::Envelope::decode(&output[..incoming.bytes], envelope_limits(65_536)?)?
            .binding
            .packet,
        mg::PacketNumber(1)
    );
    let mut other = binding(mg::Role::Client).session;
    other.0[15] ^= 1;
    for verified in [
        mg::Ingress::UserTraffic,
        mg::Ingress::AuthenticatedManagement {
            session: other,
            lane: mg::LaneId(0),
            sender: mg::Role::Client,
        },
    ] {
        assert!(
            peers[1]
                .receive(verified, &[], Duration::from_millis(21))
                .is_err()
        );
    }
    // Binding rejection happens before the wrapper parse or clock observation.
    peers[1].accepted(incoming, Duration::from_millis(20))?;
    Ok(())
}

#[test]
fn receipt_backpressure_keeps_processed_custody_without_presenting_again() -> Result {
    let mut config = base();
    config.recovery.send_records = 2;
    config.recovery.send_bytes = 237;
    let mut peers = pair(config, true)?;
    let right = submit_profile(&mut peers[1], 1, Duration::ZERO)?;
    let left = [
        submit_profile(&mut peers[0], 1, Duration::ZERO)?,
        submit_profile(&mut peers[0], 2, Duration::ZERO)?,
    ];
    let mut output = vec![0; 65_536];
    let mut deliveries = [0usize; 2];
    let mut blocked = false;
    let mut now = Duration::ZERO;
    for tick in 0..300 {
        now = Duration::from_millis(tick);
        pump(&mut peers, now, true)?;
        while let Some(incoming) = peers[1].next(now, &mut output)? {
            deliveries[1] += 1;
            peers[1].accepted(incoming, now)?;
        }
        if peers[1].has_dispatched() {
            blocked = true;
            break;
        }
    }
    assert!(blocked);
    assert_eq!(deliveries[1], 2);
    assert!(peers[1].next(now, &mut output)?.is_none());
    assert!(peers[1].pending_deadline().is_some());
    for _ in 0..400 {
        now += Duration::from_millis(1);
        pump(&mut peers, now, false)?;
        for side in 0..2 {
            while let Some(incoming) = peers[side].next(now, &mut output)? {
                deliveries[side] += 1;
                peers[side].accepted(incoming, now)?;
            }
        }
        if !peers[1].has_dispatched()
            && peers[0].confirmed(left[0], now)?
            && peers[0].confirmed(left[1], now)?
            && peers[1].confirmed(right, now)?
        {
            break;
        }
    }
    assert_eq!(deliveries, [1, 2]);
    assert!(!peers[1].has_dispatched());
    for token in left {
        assert!(peers[0].confirmed(token, now)?);
        peers[0].retire(token, now)?;
    }
    assert!(peers[1].confirmed(right, now)?);
    peers[1].retire(right, now)?;
    Ok(())
}

#[test]
fn data_scope_retirement_does_not_retire_the_equal_fixed_liveness_scope() -> Result {
    let mut peers = pair(base(), true)?;
    peers[0]
        .submit(
            scope(1),
            sc::Body::Ping { nonce: 1 },
            Duration::ZERO,
            Duration::from_secs(1),
            true,
        )?
        .ok_or("missing Ping")?;
    peers[0].advance_scope(scope(2))?;
    peers[0].retire_draining(scope(1))?;
    peers[0]
        .submit(
            scope(1),
            sc::Body::Pong { nonce: 1 },
            Duration::ZERO,
            Duration::from_secs(1),
            true,
        )?
        .ok_or("missing fixed-scope Pong")?;
    assert!(
        peers[0]
            .submit(
                scope(1),
                sc::Body::ProfileControl {
                    tag: sc::ProfileTag::SwiftPolicyV1,
                    bytes: &profile(1)
                },
                Duration::ZERO,
                Duration::from_secs(1),
                false
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn smaller_due_ack_keeps_its_wake_before_the_shared_byte_refill() -> Result {
    let mut config = base();
    config.recovery.ack_delay = Duration::from_millis(5);
    let mut peers = pair(config, true)?;
    for owner in &mut peers {
        owner
            .submit(
                scope(1),
                sc::Body::Ping { nonce: 1 },
                Duration::ZERO,
                Duration::from_secs(1),
                false,
            )?
            .ok_or("missing Ping")?;
    }
    let mut packet = [0; 512];
    // The first source releases this interval's first-source reservation.
    peers[0]
        .poll(Duration::ZERO, 4096, &mut packet)?
        .ok_or("missing local source")?;
    let incoming = peers[1]
        .poll(Duration::ZERO, 4096, &mut packet)?
        .ok_or("missing peer source")?;
    peers[0].receive(
        verified(mg::Role::Server),
        &packet[..incoming.bytes],
        Duration::ZERO,
    )?;
    let Backend::Streamed(streamed) = &mut peers[0].backend else {
        return Err("missing streams".into());
    };
    // Model the shared remaining allowance after other charged emissions:
    // 200 bytes fit a 132-byte ACK, but not a 320-byte maximum source.
    streamed.bytes_left = 200;
    streamed.packets_left = 1;
    for _ in 0..16 {
        assert!(peers[0].poll(Duration::ZERO, 4096, &mut packet)?.is_none());
    }
    assert_eq!(peers[0].deadline(), Duration::from_millis(5));
    assert!(
        peers[0]
            .poll(Duration::from_millis(4), 4096, &mut packet)?
            .is_none()
    );
    assert_eq!(peers[0].deadline(), Duration::from_millis(5));
    let ack = peers[0]
        .poll(Duration::from_millis(5), 4096, &mut packet)?
        .ok_or("ACK delayed until refill")?;
    assert_eq!(ack.wire_bytes, 132);
    let frame = streams::Frame::decode(
        &packet[..ack.bytes],
        streams::Limits {
            max_packet_bytes: 236,
        },
    )?;
    assert_eq!(frame.stream, streams::Stream::Liveness);
    assert!(matches!(
        recovery::inspect_packet(
            frame.packet,
            recovery::RecoveryContext {
                session: u128::from_be_bytes(binding(mg::Role::Client).session.0),
                epoch: 5,
                role: recovery::EndpointRole::Responder,
            },
            192
        )?,
        recovery::PacketView::Ack { .. }
    ));
    Ok(())
}

#[test]
fn poll_observes_original_expiry_and_backwards_time_before_short_output() -> Result {
    for selected in [false, true] {
        let mut peers = pair(base(), selected)?;
        let error = peers[0]
            .poll(Duration::from_secs(10), 4096, &mut [])
            .err()
            .ok_or("exact session expiry must precede capacity validation")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            error
                .to_string()
                .contains("original control session expiry")
        );
        let mut peers = pair(base(), selected)?;
        peers[0].observe(Duration::from_millis(1))?;
        let error = peers[0]
            .poll(Duration::ZERO, 4096, &mut [])
            .err()
            .ok_or("backwards time must precede capacity validation")?;
        assert!(error.to_string().contains("time moved backwards"));
    }
    let mut peers = pair(base(), true)?;
    peers[0]
        .submit(
            scope(1),
            sc::Body::Ping { nonce: 1 },
            Duration::ZERO,
            Duration::from_millis(5),
            true,
        )?
        .ok_or("missing short-lived Ping")?;
    let error = peers[0]
        .poll(Duration::from_millis(5), 4096, &mut [])
        .err()
        .ok_or("original message expiry must precede capacity validation")?;
    assert!(error.to_string().contains("Expired"));
    Ok(())
}

#[test]
fn automatic_retirement_checks_one_rotating_entry_per_observation() -> Result {
    let mut peers = pair(base(), true)?;
    let mut tokens = Vec::new();
    for nonce in 0..3 {
        tokens.push(
            peers[0]
                .submit(
                    scope(1),
                    sc::Body::Ping { nonce },
                    Duration::ZERO,
                    Duration::from_millis(1500),
                    false,
                )?
                .ok_or("missing retained Ping")?,
        );
    }
    let mut output = vec![0; 65_536];
    let mut now = Duration::ZERO;
    for tick in 0..300 {
        now = Duration::from_millis(tick);
        pump(&mut peers, now, false)?;
        for owner in &mut peers {
            while let Some(incoming) = owner.next(now, &mut output)? {
                owner.accepted(incoming, now)?;
            }
        }
        let mut complete = true;
        for token in &tokens {
            complete &= peers[0].confirmed(*token, now)?;
        }
        if complete {
            break;
        }
    }
    for token in &tokens {
        assert!(peers[0].confirmed(*token, now)?);
    }
    let Backend::Streamed(streamed) = &mut peers[0].backend else {
        return Err("missing streams".into());
    };
    let i = index(streams::Stream::Liveness);
    assert_eq!(streamed.outgoing[i].len(), 3);
    // All confirmations came from real DATA/Accepted/ACK exchange above.
    // Leave the first entry manual to prove it cannot starve later entries.
    streamed.outgoing[i][1].auto_retire = true;
    streamed.outgoing[i][2].auto_retire = true;
    streamed.auto_cursor = 0;
    for expected in [3, 2, 1] {
        peers[0].observe(now)?;
        let Backend::Streamed(streamed) = &peers[0].backend else {
            return Err("missing streams".into());
        };
        assert_eq!(streamed.outgoing[i].len(), expected);
    }
    assert!(peers[0].confirmed(tokens[0], now)?);
    peers[0].retire(tokens[0], now)?;
    Ok(())
}

#[test]
fn repeated_scope_advance_preserves_the_same_draining_custody() -> Result {
    let mut peers = pair(base(), true)?;
    submit_profile(&mut peers[0], 1, Duration::ZERO)?;
    peers[0].advance_scope(scope(2))?;
    assert_eq!(
        peers[0]
            .retire_draining(scope(1))
            .err()
            .ok_or("old profile still owns custody")?
            .kind(),
        io::ErrorKind::WouldBlock
    );
    peers[0].advance_scope(scope(2))?;
    assert!(peers[0].advance_scope(scope(3)).is_err());
    let Backend::Streamed(streamed) = &peers[0].backend else {
        return Err("missing streams".into());
    };
    assert_eq!(streamed.active, scope(2));
    assert_eq!(streamed.draining, Some(scope(1)));
    Ok(())
}

#[test]
fn staged_transaction_defers_without_gate_authority_while_liveness_passes() -> Result {
    let mut peers = pair(base(), true)?;
    peers[0].advance_scope(scope(2))?;
    peers[0].retire_draining(scope(1))?;
    peers[0]
        .submit(
            scope(2),
            sc::Body::ProfileControl {
                tag: sc::ProfileTag::SwiftPolicyV1,
                bytes: &profile(2),
            },
            Duration::ZERO,
            Duration::from_millis(1500),
            false,
        )?
        .ok_or("missing next-scope command")?;
    peers[0]
        .submit(
            scope(1),
            sc::Body::Ping { nonce: 9 },
            Duration::ZERO,
            Duration::from_millis(1500),
            false,
        )?
        .ok_or("missing Ping")?;
    for tick in 0..20 {
        pump(&mut peers, Duration::from_millis(tick), false)?;
    }
    let i = index(streams::Stream::Transaction);
    let (original_ticket, original_deadline) = {
        let Backend::Streamed(streamed) = &peers[1].backend else {
            return Err("missing streams".into());
        };
        let pending = streamed.owners[i]
            .pending()
            .ok_or("missing next-scope completion")?;
        assert_eq!(
            streamed.gate.highest_packet(streams::Stream::Transaction),
            None
        );
        (pending.ticket(), pending.deadline())
    };
    let mut output = vec![0; 65_536];
    let now = Duration::from_millis(20);
    assert!(peers[1].ready_for_dispatch(Some(scope(2)))?);
    let live = peers[1]
        .next_with_deferred_scope(now, &mut output, Some(scope(2)))?
        .ok_or("deferred transaction blocked Liveness")?;
    assert_eq!(live.stream, Some(streams::Stream::Liveness));
    assert_eq!(
        sc::Envelope::decode(&output[..live.bytes], envelope_limits(65_536)?)?.body,
        sc::Body::Ping { nonce: 9 }
    );
    peers[1].accepted(live, now)?;
    assert!(!peers[1].ready_for_dispatch(Some(scope(2)))?);
    assert!(peers[1].ready_for_dispatch(None)?);
    let original_expiry = peers[1].expiry();
    for tick in 20..30 {
        assert!(
            peers[1]
                .next_with_deferred_scope(Duration::from_millis(tick), &mut output, Some(scope(2)))?
                .is_none()
        );
        assert_eq!(peers[1].expiry(), original_expiry);
        let Backend::Streamed(streamed) = &peers[1].backend else {
            return Err("missing streams".into());
        };
        let pending = streamed.owners[i]
            .pending()
            .ok_or("deferral lost custody")?;
        assert_eq!(pending.ticket(), original_ticket);
        assert_eq!(pending.deadline(), original_deadline);
        assert_eq!(
            streamed.gate.highest_packet(streams::Stream::Transaction),
            None
        );
        assert_eq!(
            streamed.gate.highest_packet(streams::Stream::Liveness),
            Some(mg::PacketNumber(1))
        );
        assert!(streamed.held[i].is_none());
    }
    peers[1].advance_scope(scope(2))?;
    peers[1].retire_draining(scope(1))?;
    let now = Duration::from_millis(30);
    let incoming = peers[1]
        .next_with_deferred_scope(now, &mut output, None)?
        .ok_or("activated command was not released")?;
    assert!(!peers[1].ready_for_dispatch(None)?);
    assert_eq!(incoming.stream, Some(streams::Stream::Transaction));
    let envelope = sc::Envelope::decode(&output[..incoming.bytes], envelope_limits(65_536)?)?;
    assert_eq!(envelope.binding.scope, scope(2));
    assert_eq!(envelope.binding.packet, mg::PacketNumber(1));
    let Backend::Streamed(streamed) = &peers[1].backend else {
        return Err("missing streams".into());
    };
    assert_eq!(
        streamed.held[i].ok_or("missing admitted custody")?.deadline,
        original_deadline
    );
    assert_eq!(
        streamed.gate.highest_packet(streams::Stream::Transaction),
        Some(mg::PacketNumber(1))
    );
    peers[1].accepted(incoming, now)?;
    assert!(
        peers[1]
            .next_with_deferred_scope(now, &mut output, None)?
            .is_none()
    );
    Ok(())
}

#[test]
fn shorter_message_lifetimes_complete_and_reuse_both_streams_with_one_operation_cap() -> Result {
    let mut selected = settings(base());
    for setting in &mut selected.streams {
        setting.message_lifetime = Duration::from_millis(300);
    }
    let make = |role| {
        Owner::new(
            base(),
            Some(selected),
            binding(role),
            scope(1),
            scope(1),
            Duration::ZERO,
            Duration::from_secs(10),
        )
    };
    let mut peers = [make(mg::Role::Client)?, make(mg::Role::Server)?];
    let operation_cap = Duration::from_millis(1500);
    let first = [
        submit_profile(&mut peers[0], 1, Duration::ZERO)?,
        peers[0]
            .submit(
                scope(1),
                sc::Body::Ping { nonce: 1 },
                Duration::ZERO,
                operation_cap,
                false,
            )?
            .ok_or("short-lifetime Ping was refused")?,
    ];
    assert_eq!(peers[0].expiry(), Duration::from_millis(300));
    let Backend::Streamed(streamed) = &peers[0].backend else {
        return Err("missing streams".into());
    };
    for stream in [streams::Stream::Transaction, streams::Stream::Liveness] {
        assert_eq!(
            streamed.outgoing[index(stream)][0].deadline,
            Duration::from_millis(300)
        );
    }
    for tick in 0..20 {
        pump(&mut peers, Duration::from_millis(tick), false)?;
    }
    let mut output = vec![0; 65_536];
    let mut incoming = Vec::new();
    while let Some(message) = peers[1].next(Duration::from_millis(20), &mut output)? {
        incoming.push(message);
    }
    assert_eq!(incoming.len(), 2);
    let held_deadlines = {
        let Backend::Streamed(streamed) = &peers[1].backend else {
            return Err("missing streams".into());
        };
        [
            streamed.held[0].ok_or("missing held Transaction")?.deadline,
            streamed.held[1].ok_or("missing held Liveness")?.deadline,
        ]
    };
    for tick in 21..26 {
        assert!(
            peers[1]
                .next(Duration::from_millis(tick), &mut output)?
                .is_none()
        );
        let Backend::Streamed(streamed) = &peers[1].backend else {
            return Err("missing streams".into());
        };
        for (i, expected) in held_deadlines.into_iter().enumerate() {
            assert_eq!(
                streamed.held[i].ok_or("held custody disappeared")?.deadline,
                expected
            );
        }
    }
    for message in incoming {
        peers[1].accepted(message, Duration::from_millis(25))?;
    }
    for tick in 26..120 {
        pump(&mut peers, Duration::from_millis(tick), false)?;
    }
    for token in first {
        assert!(peers[0].confirmed(token, Duration::from_millis(119))?);
        peers[0].retire(token, Duration::from_millis(119))?;
    }
    // The first message lifetime is over, but the original operation cap is
    // still 1500 ms. A new immutable message gets its own 400+300 ms expiry.
    let start = Duration::from_millis(400);
    let second = [
        submit_profile(&mut peers[0], 2, start)?,
        peers[0]
            .submit(
                scope(1),
                sc::Body::Ping { nonce: 2 },
                start,
                operation_cap,
                false,
            )?
            .ok_or("later short-lifetime Ping was refused")?,
    ];
    assert_eq!(peers[0].expiry(), Duration::from_millis(700));
    let mut received = 0;
    for tick in 400..550 {
        let now = Duration::from_millis(tick);
        pump(&mut peers, now, false)?;
        while let Some(message) = peers[1].next(now, &mut output)? {
            assert_eq!(
                sc::Envelope::decode(&output[..message.bytes], envelope_limits(65_536)?)?
                    .binding
                    .packet,
                mg::PacketNumber(2)
            );
            peers[1].accepted(message, now)?;
            received += 1;
        }
    }
    assert_eq!(received, 2);
    for token in second {
        assert!(peers[0].confirmed(token, Duration::from_millis(549))?);
        peers[0].retire(token, Duration::from_millis(549))?;
    }
    assert_eq!(operation_cap, Duration::from_millis(1500));
    Ok(())
}

#[test]
fn earlier_operation_cap_remains_the_actual_message_expiry() -> Result {
    let bytes = profile(1);
    for body in [
        sc::Body::Ping { nonce: 1 },
        sc::Body::ProfileControl {
            tag: sc::ProfileTag::SwiftPolicyV1,
            bytes: &bytes,
        },
    ] {
        let mut peers = pair(base(), true)?;
        let cap = Duration::from_millis(5);
        let token = peers[0]
            .submit(scope(1), body, Duration::ZERO, cap, false)?
            .ok_or("missing capped message")?;
        assert_eq!(peers[0].expiry(), cap);
        peers[0].observe(Duration::from_millis(4))?;
        assert_eq!(peers[0].expiry(), cap);
        assert!(!peers[0].confirmed(token, Duration::from_millis(4))?);
        assert!(peers[0].confirmed(token, cap).is_err());
    }
    Ok(())
}

#[test]
fn session_expiry_bounds_each_new_message_even_with_a_later_operation_cap() -> Result {
    let mut peers = pair(base(), true)?;
    let now = Duration::from_secs(9);
    peers[0]
        .submit(
            scope(1),
            sc::Body::Ping { nonce: 1 },
            now,
            Duration::from_secs(20),
            false,
        )?
        .ok_or("session-clamped Ping was refused")?;
    assert_eq!(peers[0].expiry(), Duration::from_secs(10));
    assert!(
        peers[0]
            .poll(Duration::from_secs(10), 4096, &mut [0; 512])
            .is_err()
    );
    Ok(())
}

#[test]
fn absolute_expiry_is_independent_of_emission_work_and_outer_refills() -> Result {
    let mut peers = pair(base(), true)?;
    peers[0]
        .submit(
            scope(1),
            sc::Body::Ping { nonce: 1 },
            Duration::ZERO,
            Duration::from_millis(5),
            true,
        )?
        .ok_or("missing short-lived Ping")?;
    assert_eq!(peers[0].deadline(), Duration::ZERO);
    assert_eq!(peers[0].expiry(), Duration::from_millis(5));
    let mut output = [0; 512];
    peers[0]
        .poll(Duration::ZERO, 4096, &mut output)?
        .ok_or("missing source")?;
    assert_eq!(peers[0].expiry(), Duration::from_millis(5));
    let legacy = pair(base(), false)?;
    assert_eq!(legacy[0].expiry(), Duration::from_secs(10));
    Ok(())
}

#[test]
fn selected_settings_reject_wrapper_packet_overflow_before_owner_construction() -> Result {
    let mut config = base();
    config.recovery.max_source_bytes =
        65_535 - streams::HEADER_BYTES - recovery::DATA_HEADER_BYTES + 1;
    let error = settings(config)
        .validate(config, 1500, Duration::from_secs(10))
        .err()
        .ok_or("oversized wrapped packet was accepted")?;
    assert!(
        error
            .to_string()
            .contains("control stream wrapper error: Limits")
    );
    config.recovery.max_source_bytes = usize::MAX;
    let error = settings(config)
        .validate(config, 1500, Duration::from_secs(10))
        .err()
        .ok_or("packet arithmetic overflow was accepted")?;
    assert!(error.to_string().contains("control packet size overflow"));
    Ok(())
}

#[test]
fn control_expiry_snapshot_writes_only_bounded_scalar_stream_observations() -> Result {
    let mut peers = pair(base(), true)?;
    peers[0]
        .submit(
            scope(1),
            sc::Body::Ping {
                nonce: 0x8877_6655_4433_2211,
            },
            Duration::ZERO,
            Duration::from_millis(5),
            true,
        )?
        .ok_or("missing Ping")?;
    let error = peers[0]
        .poll(Duration::from_millis(5), 4096, &mut [])
        .err()
        .ok_or("missing expiry")?;
    assert_eq!(error.to_string(), "whole-message control error: Expired");
    let before = (peers[0].now, peers[0].retained(), peers[0].expiry());
    let mut bytes = Vec::new();
    peers[0].write_failure_snapshot(Duration::from_millis(6), &mut bytes)?;
    let text = std::str::from_utf8(&bytes)?;
    assert_eq!(text.lines().count(), 3);
    assert!(
        text.lines()
            .all(|line| line.starts_with("Common control terminal candidate:"))
    );
    assert!(text.contains("stream=Liveness"));
    assert!(text.contains("last_successful_at:"));
    assert!(text.contains("semantic_accepted: false"));
    assert!(!text.contains("8877"));
    assert!(!text.contains("digest"));
    assert_eq!(
        (peers[0].now, peers[0].retained(), peers[0].expiry()),
        before
    );
    Ok(())
}
