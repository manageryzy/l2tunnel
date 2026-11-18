use super::*;
use l2tunnel_codec::{packed as packer, packed_envelope as envelope};
use l2tunnel_datagram as datagram;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn config(symbol: usize) -> packed::Config {
    let mut base = tests::config(symbol);
    let original = 56 + 8 * 4 + symbol;
    base.recovery.arq.max_source_bytes = original;
    base.recovery.arq.send_bytes = 8 * original;
    base.recovery.arq.receive_bytes = 8 * original;
    base.recovery.fec.block.max_source_bytes = 44 + original;
    base.recovery.fec.block.max_packet_bytes = 56 + 3 + 2 + 44 + original;
    base.recovery.max_restored_bytes = 16 * (44 + original);
    base.max_recovery_packet_bytes = 8 + base.recovery.fec.block.max_packet_bytes;
    base.receiver.lookahead_records = 4;
    base.receiver.lookahead_bytes = 4 * 65535;
    base.receiver.lookahead_fragments = 4 * base.receiver.max_fragments_per_record;
    packed::Config {
        base,
        hold_micros: 500,
        max_units: 4,
        work_limit: 4,
    }
}
fn peers(config: packed::Config) -> Result<(packed::Endpoint, packed::Endpoint), Error> {
    Ok((
        packed::Endpoint::new(config, tests::context(EndpointRole::Initiator))?,
        packed::Endpoint::new(config, tests::context(EndpointRole::Responder))?,
    ))
}
fn budget(endpoint: &packed::Endpoint) -> OutboundBudget {
    OutboundBudget {
        packets: 64,
        wire_bytes: 64 * (endpoint.max_packet_bytes() + 256),
    }
}
fn emit(
    endpoint: &mut packed::Endpoint,
    now: u64,
    feedback: bool,
    allowance: &mut OutboundBudget,
) -> Result<Option<Vec<u8>>, Error> {
    let mut output = vec![0; endpoint.max_packet_bytes()];
    let result = if feedback {
        endpoint.poll_feedback(ms(now), &mut output, allowance)?
    } else {
        endpoint.poll_data(ms(now), &mut output, allowance)?
    };
    Ok(result.map(|n| {
        output.truncate(n);
        output
    }))
}
fn emissions(endpoint: &mut packed::Endpoint, now: u64) -> Result<Vec<Vec<u8>>, Error> {
    let mut allowance = budget(endpoint);
    let mut result = Vec::new();
    for _ in 0..64 {
        let Some(p) = emit(endpoint, now, false, &mut allowance)? else {
            break;
        };
        result.push(p);
    }
    Ok(result)
}
fn deliveries(endpoint: &mut packed::Endpoint, now: u64) -> Result<Vec<(u8, Vec<u8>)>, Error> {
    let mut frames = Vec::new();
    for _ in 0..64 {
        let mut progress = false;
        for c in 0..2 {
            match endpoint.prepare(ChannelId(c), ms(now), 8)? {
                Prepared::Ready => {
                    let d = endpoint.pending().ok_or(Error::Identity)?;
                    frames.push((d.channel.0, d.bytes.to_vec()));
                    endpoint.commit_delivery(ms(now))?;
                    progress = true;
                }
                Prepared::Progress => progress = true,
                Prepared::Idle => {}
            }
        }
        if !progress {
            break;
        }
    }
    Ok(frames)
}

#[test]
fn selected_compact_packed_wire_preserves_multiple_units_and_fec_repair() -> TestResult {
    let (mut left, mut right) = peers(config(128))?;
    left.enable_compact_wire(53)?;
    right.enable_compact_wire(53)?;
    let mut expected = Vec::new();
    for index in 0..12u8 {
        let frame = vec![index, 1, 0, 0];
        left.enqueue_admitted(ChannelId(index % 2), &frame, ms(0))?;
        expected.push((index % 2, frame));
    }
    let packets = emissions(&mut left, 0)?;
    assert_eq!(packets.len(), 5);
    for packet in &packets[..3] {
        let mut witnesses = [UnitWitness {
            identity: RecordIdentity {
                channel: ChannelId(0),
                record: receiver::RecordId(0),
            },
            index: 0,
            count: 1,
        }; 4];
        assert_eq!(left.outgoing_units(packet, &mut witnesses)?, 4);
    }
    for index in [2, 1, 3] {
        right.receive_authenticated(&packets[index], ms(1))?;
    }
    let actual = deliveries(&mut right, 1)?;
    for channel in 0..2 {
        assert_eq!(
            actual
                .iter()
                .filter(|item| item.0 == channel)
                .collect::<Vec<_>>(),
            expected
                .iter()
                .filter(|item| item.0 == channel)
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(right.statistics().repaired_unique_sources, 1);
    let mut budget = budget(&right);
    let before = budget.wire_bytes;
    let feedback = emit(&mut right, 2, true, &mut budget)?.ok_or("strong feedback")?;
    assert_eq!(before - budget.wire_bytes, feedback.len() + 53);
    left.receive_authenticated(&feedback, ms(2))?;
    assert!(left.drained() && right.drained());
    Ok(())
}

#[test]
fn packed_protected_sources_repair_before_rto_with_distinct_unit_ids_in_both_roles() -> TestResult {
    for cover in [
        datagram::CoverProfile::OpenVpnLike,
        datagram::CoverProfile::QuicLike,
    ] {
        for protection in [
            datagram::Protection::ChaCha20Poly1305,
            datagram::Protection::HmacSha256,
        ] {
            for from_client in [false, true] {
                let mut cfg = config(128);
                let profile = datagram::DatagramConfig {
                    context: datagram::KeyContext {
                        session: datagram::SessionId(0x1234u128.to_be_bytes()),
                        direction: if from_client {
                            datagram::Direction::ClientToServer
                        } else {
                            datagram::Direction::ServerToClient
                        },
                        lane: datagram::LaneId(1),
                        generation: datagram::KeyGeneration(0),
                    },
                    cover,
                    protection,
                    path_mtu: 1500,
                    outer_overhead_bytes: 28,
                    max_payload_bytes: cfg.base.max_recovery_packet_bytes,
                    max_packets_per_key: 1000,
                    max_payload_bytes_per_key: 1_000_000,
                };
                cfg.base.recovery.outer_overhead_bytes = 28 + profile.wire_overhead();
                let (mut left, mut right) = peers(cfg)?;
                let (send, receive) = if from_client {
                    (&mut left, &mut right)
                } else {
                    (&mut right, &mut left)
                };
                let mut expected = Vec::new();
                for i in 0..12u8 {
                    let frame = vec![i, 1, 0, 0];
                    send.enqueue_admitted(ChannelId(i % 2), &frame, Duration::ZERO)?;
                    expected.push((i % 2, frame));
                }
                assert_eq!(send.arq_statistics().submitted, 3);
                assert_eq!(
                    send.status().packing.ok_or("packing")?.next_unit,
                    Some(receiver::SourceId(12))
                );
                let packets = emissions(send, 0)?;
                assert_eq!(packets.len(), 5);
                let mut sealer = datagram::PacketSealer::new(profile, &[29; 32])?;
                let mut opener = datagram::PacketOpener::new(profile, &[29; 32])?;
                let sealed = packets
                    .iter()
                    .map(|p| sealer.seal_vec(p))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut plain = vec![0; cfg.base.max_recovery_packet_bytes];
                let mut bad = sealed[0].bytes.clone();
                let last = bad.len() - 1;
                bad[last] ^= 1;
                assert!(opener.open(&bad, &mut plain).is_err());
                for index in [2, 1] {
                    let opened = opener.open(&sealed[index].bytes, &mut plain)?;
                    receive.receive_authenticated(&plain[..opened.payload_len], ms(1))?;
                }
                assert!(deliveries(receive, 1)?.is_empty());
                let opened = opener.open(&sealed[3].bytes, &mut plain)?;
                receive.receive_authenticated(&plain[..opened.payload_len], ms(2))?;
                let actual = deliveries(receive, 2)?;
                for channel in 0..2 {
                    assert_eq!(
                        actual.iter().filter(|x| x.0 == channel).collect::<Vec<_>>(),
                        expected
                            .iter()
                            .filter(|x| x.0 == channel)
                            .collect::<Vec<_>>()
                    );
                }
                assert_eq!(receive.statistics().repaired_unique_sources, 1);
                assert_eq!(
                    receive.status().receiver.source_floor,
                    Some(receiver::SourceId(12))
                );
                assert_eq!(send.arq_statistics().retransmissions, 0);
                assert_eq!(
                    opener.open(&sealed[3].bytes, &mut plain),
                    Err(datagram::Error::Replay)
                );
                assert_eq!(
                    send.statistics().emitted_wire_bytes,
                    packets
                        .iter()
                        .map(|p| (p.len() + profile.wire_overhead() + 28) as u64)
                        .sum::<u64>()
                );
                assert!(sealed.iter().all(|p| p.bytes.len() + 28 <= 1500));
            }
        }
    }
    Ok(())
}

#[test]
fn packed_original_timer_budget_and_source_backpressure_never_reassign_units() -> TestResult {
    let cfg = config(128);
    let (mut left, _) = peers(cfg)?;
    left.enqueue_admitted(ChannelId(0), b"tiny", Duration::from_micros(100))?;
    left.enqueue_admitted(ChannelId(1), b"tail\0\0", Duration::from_micros(200))?;
    assert_eq!(left.deadline(), Some(Duration::from_micros(600)));
    left.tick(Duration::from_micros(599))?;
    assert_eq!(left.arq_statistics().submitted, 0);
    left.tick(Duration::from_micros(600))?;
    assert_eq!(left.arq_statistics().submitted, 1);
    let mut none = OutboundBudget::default();
    let mut out = vec![0; left.max_packet_bytes()];
    assert!(left.poll_data(ms(1), &mut out, &mut none)?.is_none());
    assert_eq!(left.statistics().emitted_wire_bytes, 0);
    // Fill actual reliable retention; the next sealed source remains codec-owned.
    for i in 0..7 {
        left.enqueue_admitted(ChannelId(0), &[i; 4], ms(1))?;
        left.flush(ms(1))?;
    }
    assert_eq!(left.arq_statistics().submitted, 8);
    left.enqueue_admitted(ChannelId(0), b"blocked", ms(1))?;
    left.flush(ms(1))?;
    let saved = left.status().packing.ok_or("packing")?;
    assert!(saved.packing.sealed);
    left.tick(ms(2))?;
    assert_eq!(left.status().packing, Some(saved));
    assert_eq!(left.arq_statistics().submitted, 8);
    assert!(!left.drained());
    let bytes = emissions(&mut left, 2)?;
    assert!(!bytes.is_empty());
    // Transmission alone does not create peer receipt or release the source window.
    assert_eq!(left.arq_statistics().submitted, 8);
    Ok(())
}

#[test]
fn packed_context_fragments_and_raw_native_pressure_retain_complete_frames() -> TestResult {
    for raw in [false, true] {
        let mut cfg = config(32);
        if raw {
            cfg.base.native_policy = NativePolicy::RawIp;
            cfg.base.receiver.body.elide_payload_length = false;
            cfg.base.receiver.body.predictive = false;
            cfg.base.receiver.body.timestamp_pair_dictionary = false;
        }
        let (mut left, _) = peers(cfg)?;
        let plan =
            storage::Plan::for_packed_duplex(cfg, cfg)?.with_receiver_handoff_diagnostics()?;
        let mut right = packed::Endpoint::new_reserved_with_plan(
            plan,
            tests::context(EndpointRole::Responder),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        let mut input = tests::native_frames()?;
        input.extend((0..12).map(|i| vec![i; 90]));
        input.push(vec![0; 500]);
        let (mut admitted, mut output, mut held, mut saw_stage, mut saw_handoff) =
            (0, Vec::new(), None::<Vec<u8>>, false, false);
        for time in 0..2000 {
            if admitted < input.len() && !left.status().staged_frame {
                left.enqueue_admitted(ChannelId(0), &input[admitted], ms(time))?;
                admitted += 1;
            }
            left.tick(ms(time))?;
            saw_stage |= left.status().staged_frame;
            let mut allowance = budget(&left);
            for _ in 0..2 {
                if let Some(p) = emit(&mut left, time, false, &mut allowance)? {
                    right.receive_authenticated(&p, ms(time))?;
                }
            }
            let mut reverse = budget(&right);
            if let Some(ack) = emit(&mut right, time, true, &mut reverse)? {
                left.receive_authenticated(&ack, ms(time))?;
            }
            right.prepare(ChannelId(0), ms(time), 8)?;
            saw_handoff |= right.status().retained_handoff;
            if let Some(d) = right.pending() {
                if time < 100 {
                    if let Some(p) = &held {
                        assert_eq!(p, d.bytes);
                    }
                    held = Some(d.bytes.to_vec());
                } else {
                    output.push(d.bytes.to_vec());
                    right.commit_delivery(ms(time))?;
                }
            }
            assert!(left.status().recovery.arq.send_records <= 8);
            assert!(right.status().receiver.retained_records <= 6);
            if output.len() == input.len() && left.drained() && right.drained() {
                break;
            }
        }
        assert_eq!(output, input);
        assert!(saw_stage && saw_handoff && held.is_some());
        assert!(left.drained() && right.drained());
        let observed = right
            .receiver_handoff_snapshot(ms(2000))
            .ok_or("Packed handoff observer")?;
        assert!(observed.packed && observed.refusals.iter().sum::<u64>() > 0);
        assert!(observed.totals.completed_episodes > 0 && observed.pending.is_none());
        assert_eq!(
            observed
                .maximum_completed
                .ok_or("Packed completed source")?
                .release,
            Some(receiver_handoff::Release::PackedBatch)
        );
        assert!(!observed.identity_mismatch && !observed.clock_regression);
        assert_eq!(
            right
                .storage_usage()
                .ok_or("actual reserved Packed")?
                .capacity_bytes,
            plan.capacity_bytes()
        );
    }
    Ok(())
}

#[test]
fn packed_late_semantic_failure_never_exposes_earlier_frame_or_advances_unit_floor() -> TestResult {
    let cfg = config(128);
    let plan = storage::Plan::for_packed_duplex(cfg, cfg)?.with_receiver_handoff_diagnostics()?;
    let mut endpoint = packed::Endpoint::new_reserved_with_plan(
        plan,
        tests::context(EndpointRole::Responder),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let scope = receiver::Scope {
        session: 0x1234u128.to_be_bytes(),
        epoch: Epoch(7),
        direction: receiver::Direction::InitiatorToResponder,
    };
    let good = [0, 0, 0, 2, 0, 1, 7];
    let bad = [1, 0, 0, 6, 0];
    let mut pack = packer::Packer::new(packer::Config {
        symbol_bytes: 128,
        hold_micros: 500,
    })?;
    assert_eq!(pack.push(&good, 1, 0)?, packer::Push::Accepted);
    assert_eq!(pack.push(&bad, 1, 0)?, packer::Push::Accepted);
    pack.flush();
    let mut source = vec![0; cfg.envelope().max_source_bytes()?];
    let n = envelope::encode(
        cfg.envelope(),
        envelope::Identity {
            scope,
            source: receiver::SourceId(0),
            first_unit: receiver::SourceId(0),
        },
        &[receiver::RecordId(0); 2],
        pack.pending().ok_or("source")?.payload,
        &mut source,
    )?;
    let mut recovery = Reliable::new(cfg.base.recovery, tests::context(EndpointRole::Initiator))?;
    recovery.submit(&source[..n], Duration::ZERO)?;
    let mut allowance = budget(&endpoint);
    let mut packet = vec![0; endpoint.max_packet_bytes()];
    assert!(
        recovery
            .poll_data(ms(0), &mut packet, &mut allowance)?
            .is_none()
    );
    let n = recovery
        .poll_data(ms(5), &mut packet, &mut allowance)?
        .ok_or("systematic")?;
    assert!(matches!(
        endpoint.receive_authenticated(&packet[..n], ms(5)),
        Err(Error::Receiver(receiver::Error::Body(_)))
    ));
    let status = endpoint.status();
    assert_eq!(status.receiver.source_floor, Some(receiver::SourceId(0)));
    assert_eq!(status.receiver.retained_records, 0);
    assert!(status.retained_handoff && status.failure.is_some());
    assert!(endpoint.pending().is_none());
    assert!(!endpoint.drained());
    let observed = endpoint
        .receiver_handoff_snapshot(ms(5))
        .ok_or("rollback observation")?;
    assert_eq!(observed.refusals, [0, 0]);
    assert_eq!(observed.totals, receiver_handoff::Totals::default());
    assert!(observed.pending.is_none() && observed.last_resolved.is_none());
    assert_eq!(
        observed.terminal,
        Some(receiver_handoff::Terminal::OwnerFailure)
    );
    Ok(())
}

#[test]
fn packed_configuration_binds_new_fields_and_guarantees_empty_batch_reservation() -> TestResult {
    let cfg = config(128);
    let digest = cfg.digest()?;
    assert_ne!(digest, tests::config(128).digest()?);
    for changed in [
        packed::Config {
            hold_micros: 501,
            ..cfg
        },
        packed::Config {
            work_limit: 3,
            ..cfg
        },
    ] {
        assert_ne!(changed.digest()?, digest);
    }
    let mut count = cfg;
    count.max_units = 3;
    assert!(count.validate().is_err()); // Count also changes exact source geometry.
    let source = count.envelope().max_source_bytes()?;
    count.base.recovery.arq.max_source_bytes = source;
    count.base.recovery.fec.block.max_source_bytes = 44 + source;
    assert_ne!(count.digest()?, digest);
    for field in 0..6 {
        let mut c = cfg;
        match field {
            0 => c.base.receiver.lookahead_records = 3,
            1 => c.base.receiver.lookahead_bytes = 3,
            2 => c.base.receiver.lookahead_fragments = 3,
            3 => c.base.receiver.record_window = 3,
            4 => c.base.receiver.source_window = 3,
            _ => c.base.recovery.arq.max_source_bytes -= 1,
        }
        assert!(c.validate().is_err());
    }
    assert!(cfg.codec_memory_bound_bytes()? <= 256 * 1024 * 1024);
    Ok(())
}

fn authenticated_source(
    cfg: packed::Config,
    source: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut sender = Reliable::new(cfg.base.recovery, tests::context(EndpointRole::Initiator))?;
    sender.submit(source, ms(0))?;
    let mut output = vec![0; cfg.base.max_recovery_packet_bytes];
    let mut allowance = OutboundBudget {
        packets: 4,
        wire_bytes: 4 * (output.len() + 256),
    };
    assert!(
        sender
            .poll_data(ms(0), &mut output, &mut allowance)?
            .is_none()
    );
    let n = sender
        .poll_data(ms(5), &mut output, &mut allowance)?
        .ok_or("source output")?;
    output.truncate(n);
    Ok(output)
}

#[test]
fn packed_exact_source_and_unit_identity_fail_before_native_admission() -> TestResult {
    let cfg = config(128);
    let scope = receiver::Scope {
        session: 0x1234u128.to_be_bytes(),
        epoch: Epoch(7),
        direction: receiver::Direction::InitiatorToResponder,
    };
    for (source_id, first_unit) in [(1, 0), (0, 1), (u64::MAX, 0), (0, u64::MAX)] {
        let (_, mut right) = peers(cfg)?;
        let mut bytes = vec![0; cfg.envelope().max_source_bytes()?];
        let n = envelope::encode(
            cfg.envelope(),
            envelope::Identity {
                scope,
                source: receiver::SourceId(source_id),
                first_unit: receiver::SourceId(first_unit),
            },
            &[receiver::RecordId(0)],
            &[0, 0, 0, 2, 0, 1, 7],
            &mut bytes,
        )?;
        let packet = authenticated_source(cfg, &bytes[..n])?;
        assert_eq!(
            right.receive_authenticated(&packet, ms(5)),
            Err(Error::Identity)
        );
        let status = right.status();
        assert_eq!(status.receiver.source_floor, Some(receiver::SourceId(0)));
        assert_eq!(status.receiver.retained_records, 0);
        assert!(status.retained_handoff);
        assert!(right.pending().is_none());
        assert!(!right.drained());
        assert_eq!(right.tick(ms(6)), Err(Error::Identity));
    }
    Ok(())
}

#[test]
fn packed_pending_native_expiry_and_actual_retry_exhaustion_are_terminal() -> TestResult {
    let cfg = config(128);
    let (mut left, mut right) = peers(cfg)?;
    left.enqueue_admitted(ChannelId(0), b"native owner", ms(0))?;
    left.flush(ms(0))?;
    assert!(emissions(&mut left, 0)?.is_empty());
    for packet in emissions(&mut left, 5)? {
        right.receive_authenticated(&packet, ms(5))?;
    }
    assert_eq!(right.prepare(ChannelId(0), ms(5), 8)?, Prepared::Ready);
    let retained = right.pending().ok_or("native")?.bytes.to_vec();
    right.tick(ms(5004))?;
    assert_eq!(right.pending().ok_or("retained native")?.bytes, retained);
    assert_eq!(
        right.commit_delivery(ms(5005)),
        Err(Error::Receiver(receiver::Error::Expired))
    );
    assert_eq!(
        right.tick(ms(5006)),
        Err(Error::Receiver(receiver::Error::Expired))
    );
    assert!(!right.drained());
    let mut terminal = None;
    for now in [105, 305, 705] {
        match emissions(&mut left, now) {
            Ok(packets) => assert!(!packets.is_empty()),
            Err(error) => {
                terminal = Some(error);
                break;
            }
        }
    }
    assert!(matches!(
        terminal,
        Some(Error::Recovery(l2tunnel_reliable::Error::Arq(
            RecoveryError::RetryExhausted { .. }
        )))
    ));
    assert_eq!(left.arq_statistics().retransmissions, 2);
    assert_eq!(left.status().failure, terminal);
    assert!(!left.drained());
    Ok(())
}

#[test]
fn packed_fresh_clock_rejection_preserves_time_but_owned_exhaustion_is_sticky() -> TestResult {
    let cfg = config(128);
    let (mut fresh, _) = peers(cfg)?;
    let before = fresh.status();
    assert_eq!(
        fresh.enqueue_admitted(ChannelId(0), b"fresh", Duration::from_micros(u64::MAX)),
        Err(Error::PackedSender(
            l2tunnel_codec::packed_sender::Error::Packing(packer::Error::ClockExhausted)
        ))
    );
    assert_eq!(fresh.status(), before);
    fresh.enqueue_admitted(ChannelId(0), b"valid", Duration::ZERO)?;
    let too_late = Duration::from_secs(u64::MAX);
    assert_eq!(fresh.tick(too_late), Err(Error::Time));
    assert_eq!(fresh.tick(ms(1)), Err(Error::Time));
    assert!(!fresh.drained());
    let mut slow = cfg;
    slow.work_limit = 1;
    let (mut owned, _) = peers(slow)?;
    let start = Duration::from_micros(u64::MAX - cfg.hold_micros);
    owned.enqueue_admitted(ChannelId(0), &[9; 500], start)?;
    assert!(owned.status().staged_frame);
    assert_eq!(owned.arq_statistics().submitted, 1);
    let error = Error::PackedSender(l2tunnel_codec::packed_sender::Error::Packing(
        packer::Error::ClockExhausted,
    ));
    assert_eq!(owned.tick(Duration::from_micros(u64::MAX)), Err(error));
    assert_eq!(owned.status().failure, Some(error));
    assert!(owned.status().staged_frame);
    assert!(!owned.drained());
    Ok(())
}

#[test]
fn packed_maximum_unit_batch_completes_a_fragment_behind_pending_native() -> TestResult {
    let cfg = config(128); // Exactly max_units lookahead records, plus channel-head reserves.
    let (mut left, mut right) = peers(cfg)?;
    left.enqueue_admitted(ChannelId(0), b"held native", ms(0))?;
    left.flush(ms(0))?;
    assert!(emissions(&mut left, 0)?.is_empty());
    for packet in emissions(&mut left, 5)? {
        right.receive_authenticated(&packet, ms(5))?;
    }
    assert_eq!(right.prepare(ChannelId(0), ms(5), 8)?, Prepared::Ready);
    let fragmented = vec![7; 130];
    left.enqueue_admitted(ChannelId(0), &fragmented, ms(5))?;
    assert!(left.status().staged_frame);
    left.tick(ms(5))?;
    assert!(!left.status().staged_frame);
    assert_eq!(left.status().packing.ok_or("packed")?.packing.units, 1);
    for value in [1, 2, 3] {
        left.enqueue_admitted(ChannelId(0), &[value], ms(5))?;
    }
    assert_eq!(left.arq_statistics().submitted, 3);
    assert!(emissions(&mut left, 5)?.is_empty());
    let mut incomplete_seen = false;
    for packet in emissions(&mut left, 10)? {
        right.receive_authenticated(&packet, ms(10))?;
        incomplete_seen |= right.status().receiver.source_floor == Some(receiver::SourceId(2));
        assert_eq!(
            right.pending().ok_or("original pending")?.bytes,
            b"held native"
        );
    }
    assert!(incomplete_seen);
    let status = right.status();
    assert_eq!(status.receiver.source_floor, Some(receiver::SourceId(6)));
    assert_eq!(status.receiver.retained_records, 5);
    assert!(!status.retained_handoff);
    right.commit_delivery(ms(10))?;
    assert_eq!(
        deliveries(&mut right, 10)?,
        vec![(0, fragmented), (0, vec![1]), (0, vec![2]), (0, vec![3])]
    );
    assert!(right.pending().is_none());
    Ok(())
}

#[test]
fn one_packed_source_exposes_both_sender_native_identities_without_context_credit() -> TestResult {
    // Both real native units fit the unchanged ordinary packed geometry.
    let cfg = config(256);
    let (mut endpoint, mut receiver) = peers(cfg)?;
    let a = endpoint.enqueue_identified(ChannelId(1), &[0x7a; 80], ms(0))?;
    let b = endpoint.enqueue_identified(ChannelId(0), &[0x6b; 40], ms(0))?;
    assert_ne!(a, b);
    endpoint.flush(Duration::from_micros(500))?;
    let mut witnesses = vec![
        UnitWitness {
            identity: a,
            index: 0,
            count: 1
        };
        4
    ];
    let mut together = false;
    for packet in emissions(&mut endpoint, 1)?
        .into_iter()
        .chain(emissions(&mut endpoint, 6)?)
    {
        receiver.receive_authenticated(&packet, ms(6))?;
        let n = endpoint.outgoing_units(&packet, &mut witnesses)?;
        let ids: Vec<_> = witnesses[..n].iter().map(|w| w.identity).collect();
        if ids.contains(&a) && ids.contains(&b) {
            assert_eq!(n, 2);
            assert!(witnesses[..n].iter().all(|w| w.index == 0 && w.count == 1));
            together = true;
        }
    }
    assert!(
        together,
        "a physical source must retain both native identities"
    );
    assert_eq!(receiver.prepare(ChannelId(0), ms(6), 8)?, Prepared::Ready);
    let small = receiver.pending().ok_or("small native")?;
    assert_eq!(small.channel, b.channel);
    assert_eq!(small.record, b.record);
    assert_eq!(small.bytes, &[0x6b; 40]);
    receiver.commit_delivery(ms(6))?;
    assert_eq!(receiver.prepare(ChannelId(1), ms(6), 8)?, Prepared::Ready);
    let large = receiver.pending().ok_or("large native")?;
    assert_eq!(large.channel, a.channel);
    assert_eq!(large.record, a.record);
    assert_eq!(large.bytes, &[0x7a; 80]);
    receiver.commit_delivery(ms(6))?;
    Ok(())
}
