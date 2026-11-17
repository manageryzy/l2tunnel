use super::*;
use l2tunnel_codec::{
    aligned_body,
    aligned_receiver::{RecordId, SourceId},
};
use l2tunnel_datagram as datagram;
use l2tunnel_fec as fec;
use l2tunnel_recovery::{ArqConfig, RecoveryEngine};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
pub(super) fn config(symbol: usize) -> Config {
    let original = 48 + symbol;
    let fec_packet = 56 + 3 + 2 + 44 + original;
    Config {
        native_policy: NativePolicy::EthernetHeaders,
        receiver: receiver::Limits {
            body: aligned_body::Config {
                max_frame_bytes: 4096,
                symbol_bytes: symbol,
                elide_payload_length: true,
                predictive: true,
                timestamp_pair_dictionary: true,
                independent_short_frame_bytes: 0,
            },
            channels: 2,
            first_record: RecordId(0),
            first_source: SourceId(0),
            record_window: 32,
            source_window: 32,
            lookahead_records: 8,
            lookahead_bytes: 8192,
            lookahead_fragments: 8192,
            max_fragments_per_record: 65535usize.div_ceil(symbol - 8),
            lifetime_ticks: 5000,
        },
        recovery: ReliableConfig {
            arq: ArqConfig {
                max_source_bytes: original,
                send_bytes: 8 * original,
                receive_bytes: 8 * original,
                send_records: 8,
                receive_records: 8,
                initial_rto: ms(100),
                maximum_rto: ms(400),
                ack_delay: ms(1),
                max_retries: 2,
            },
            fec: fec::DecoderConfig {
                block: fec::BlockConfig {
                    max_sources: 3,
                    max_source_bytes: 44 + original,
                    max_packet_bytes: fec_packet,
                    max_work_per_symbol: 1_000_000,
                },
                max_generations: 4,
                max_symbols_per_generation: 5,
                max_reserved_bytes: 1_000_000,
                max_lifetime_ticks: 50,
                generation_window: 32,
            },
            repair_symbols: 2,
            flush_after: ms(5),
            max_restored_packets: 16,
            max_restored_bytes: 16 * (44 + original),
            outer_overhead_bytes: 28,
        },
        max_recovery_packet_bytes: 8 + fec_packet,
    }
}
pub(super) fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x1234,
        epoch: 7,
        role,
    }
}
fn peers(config: Config) -> Result<(Endpoint, Endpoint), Error> {
    Ok((
        Endpoint::new(config, context(EndpointRole::Initiator))?,
        Endpoint::new(config, context(EndpointRole::Responder))?,
    ))
}
fn hex(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    (0..input.len())
        .step_by(2)
        .map(|offset| Ok(u8::from_str_radix(&input[offset..offset + 2], 16)?))
        .collect()
}
pub(super) fn native_frames() -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    include_str!("../../l2tunnel-codec/tests/data/aligned-sender-goldens.tsv")
        .lines()
        .filter(|line| line.starts_with("symbol128\t0\t") || line.starts_with("symbol128\t1\t"))
        .map(|line| hex(line.split('\t').nth(6).ok_or("frame")?))
        .collect()
}
fn emit(
    endpoint: &mut Endpoint,
    now: u64,
    feedback: bool,
    budget: &mut OutboundBudget,
) -> Result<Option<Vec<u8>>, Error> {
    let mut output = vec![0; endpoint.max_packet_bytes()];
    let result = if feedback {
        endpoint.poll_feedback(ms(now), &mut output, budget)?
    } else {
        endpoint.poll_data(ms(now), &mut output, budget)?
    };
    Ok(result.map(|length| {
        output.truncate(length);
        output
    }))
}
fn allowance(endpoint: &Endpoint) -> OutboundBudget {
    OutboundBudget {
        packets: 64,
        wire_bytes: 64 * (endpoint.max_packet_bytes() + endpoint.outer_overhead_bytes()),
    }
}
fn emissions(endpoint: &mut Endpoint, now: u64) -> Result<Vec<Vec<u8>>, Error> {
    let mut budget = allowance(endpoint);
    let mut result = Vec::new();
    for _ in 0..64 {
        let Some(packet) = emit(endpoint, now, false, &mut budget)? else {
            break;
        };
        result.push(packet);
    }
    Ok(result)
}
fn deliveries(endpoint: &mut Endpoint, now: u64) -> Result<Vec<(u8, Vec<u8>)>, Error> {
    let mut frames = Vec::new();
    for _ in 0..64 {
        let mut progress = false;
        for channel in 0..2 {
            match endpoint.prepare(ChannelId(channel), ms(now), 8)? {
                Prepared::Ready => {
                    let frame = endpoint.pending().ok_or(Error::Identity)?;
                    frames.push((frame.channel.0, frame.bytes.to_vec()));
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
fn selected_compact_wire_elides_identity_envelope_and_restores_lost_fec_source() -> TestResult {
    let (mut left, mut right) = peers(config(128))?;
    left.enable_compact_wire(51)?;
    right.enable_compact_wire(51)?;
    let frames = native_frames()?;
    for frame in &frames {
        left.enqueue_admitted(ChannelId(0), frame, ms(0))?;
    }
    let packets = emissions(&mut left, 0)?;
    assert_eq!(packets.len(), 5);
    let mut short_systematic = false;
    for packet in &packets[..3] {
        let record = left.recovery.inspect_output_record(packet)?;
        let symbol = record.fec.ok_or("actual systematic coding vector")?;
        assert_eq!(symbol.payload.len(), symbol.original_source()?.len() + 2);
        short_systematic |= symbol.payload.len() < symbol.coded_bytes;
        assert_eq!(
            left.inspect_output_extent(packet)?
                .recovery
                .systematic_coded_fill_bytes,
            0
        );
        let (source, payload) = record.source.ok_or("systematic source")?;
        assert!(
            payload.len() < 129,
            "the complete Python unit excludes generated padding"
        );
        assert_eq!(
            compact_wire::aligned(
                true,
                left.send_scope,
                receiver::SourceId(source.0),
                left.config.receiver,
                payload
            )?
            .identity
            .source
            .0,
            source.0
        );
        let mut witnesses = [UnitWitness {
            identity: RecordIdentity {
                channel: ChannelId(0),
                record: receiver::RecordId(0),
            },
            index: 0,
            count: 1,
        }; 1];
        assert_eq!(left.outgoing_units(packet, &mut witnesses)?, 1);
    }
    assert!(
        short_systematic,
        "unequal actual units elide only algebraic tails"
    );
    for index in [2, 1, 3] {
        right.receive_authenticated(&packets[index], ms(1))?;
    }
    assert_eq!(
        deliveries(&mut right, 1)?,
        frames
            .into_iter()
            .map(|frame| (0, frame))
            .collect::<Vec<_>>()
    );
    assert_eq!(right.statistics().repaired_unique_sources, 1);
    let mut budget = allowance(&right);
    let before = budget.wire_bytes;
    let feedback = emit(&mut right, 2, true, &mut budget)?.ok_or("strong feedback")?;
    assert_eq!(before - budget.wire_bytes, feedback.len() + 51);
    left.receive_authenticated(&feedback, ms(2))?;
    assert!(left.drained() && right.drained());
    Ok(())
}

#[path = "compact_extent_tests.rs"]
mod compact_extent;
#[test]
fn protected_independent_peers_restore_python_bytes_before_rto_in_both_roles() -> TestResult {
    for cover in [
        datagram::CoverProfile::OpenVpnLike,
        datagram::CoverProfile::QuicLike,
    ] {
        for protection in [
            datagram::Protection::ChaCha20Poly1305,
            datagram::Protection::HmacSha256,
        ] {
            for from_client in [true, false] {
                let mut config = config(128);
                let direction = if from_client {
                    datagram::Direction::ClientToServer
                } else {
                    datagram::Direction::ServerToClient
                };
                let profile = datagram::DatagramConfig {
                    context: datagram::KeyContext {
                        session: datagram::SessionId(0x1234u128.to_be_bytes()),
                        direction,
                        lane: datagram::LaneId(1),
                        generation: datagram::KeyGeneration(0),
                    },
                    cover,
                    protection,
                    path_mtu: 1500,
                    outer_overhead_bytes: 28,
                    max_payload_bytes: config.max_recovery_packet_bytes,
                    max_packets_per_key: 1000,
                    max_payload_bytes_per_key: 1_000_000,
                };
                config.recovery.outer_overhead_bytes = profile.wire_overhead() + 28;
                let (mut left, mut right) = peers(config)?;
                let (sender, receiver) = if from_client {
                    (&mut left, &mut right)
                } else {
                    (&mut right, &mut left)
                };
                let frames = native_frames()?;
                for frame in &frames {
                    sender.enqueue_admitted(ChannelId(0), frame, ms(0))?;
                }
                let packets = emissions(sender, 0)?;
                assert_eq!(packets.len(), 5);
                assert_eq!(sender.arq_statistics().submitted, 3);
                let mut sealer = datagram::PacketSealer::new(profile, &[19; 32])?;
                let mut opener = datagram::PacketOpener::new(profile, &[19; 32])?;
                let sealed: Vec<_> = packets
                    .iter()
                    .map(|packet| sealer.seal_vec(packet))
                    .collect::<Result<_, _>>()?;
                let mut plaintext = vec![0; config.max_recovery_packet_bytes];
                let mut altered = sealed[0].bytes.clone();
                let last = altered.len() - 1;
                altered[last] ^= 1;
                assert!(opener.open(&altered, &mut plaintext).is_err());
                assert_eq!(receiver.arq_statistics().received_unique, 0);
                for index in [2, 1] {
                    let opened = opener.open(&sealed[index].bytes, &mut plaintext)?;
                    receiver.receive_authenticated(&plaintext[..opened.payload_len], ms(1))?;
                }
                assert!(
                    deliveries(receiver, 1)?.is_empty(),
                    "ordered source gap must not claim early release"
                );
                let opened = opener.open(&sealed[3].bytes, &mut plaintext)?;
                receiver.receive_authenticated(&plaintext[..opened.payload_len], ms(2))?;
                assert_eq!(
                    deliveries(receiver, 2)?,
                    frames
                        .into_iter()
                        .map(|frame| (0, frame))
                        .collect::<Vec<_>>()
                );
                assert_eq!(receiver.statistics().repaired_unique_sources, 1);
                assert_eq!(sender.arq_statistics().retransmissions, 0);
                assert_eq!(
                    opener.open(&sealed[3].bytes, &mut plaintext),
                    Err(datagram::Error::Replay)
                );
                assert!(sealed.iter().all(|packet| packet.bytes.len() + 28 <= 1500));
                assert_eq!(
                    sender.statistics().emitted_wire_bytes,
                    packets
                        .iter()
                        .map(|packet| (packet.len() + profile.wire_overhead() + 28) as u64)
                        .sum::<u64>()
                );
            }
        }
    }
    Ok(())
}
#[test]
fn insufficient_rank_falls_back_to_original_source_ids_without_reencoding() -> TestResult {
    let (mut sender, mut receiver) = peers(config(128))?;
    let frames = native_frames()?;
    for frame in &frames {
        sender.enqueue_admitted(ChannelId(0), frame, ms(0))?;
    }
    let original = emissions(&mut sender, 0)?;
    receiver.receive_authenticated(&original[1], ms(1))?;
    let mut budget = allowance(&receiver);
    let ack = emit(&mut receiver, 2, true, &mut budget)?.ok_or("ACK")?;
    sender.receive_authenticated(&ack, ms(2))?;
    let retries = emissions(&mut sender, 100)?;
    assert_eq!(retries.len(), 2);
    for retry in retries.iter().rev() {
        assert_eq!(
            sender.inspect_output(retry)?,
            l2tunnel_reliable::RecordKind::Source
        );
        receiver.receive_authenticated(retry, ms(100))?;
    }
    assert_eq!(
        deliveries(&mut receiver, 100)?,
        frames
            .into_iter()
            .map(|frame| (0, frame))
            .collect::<Vec<_>>()
    );
    assert_eq!(receiver.statistics().repaired_unique_sources, 0);
    assert_eq!(sender.arq_statistics().submitted, 3);
    assert_eq!(sender.arq_statistics().retransmissions, 2);
    Ok(())
}
#[test]
fn one_shared_budget_charges_data_repair_feedback_and_zero_budget_blocks_all() -> TestResult {
    let (mut left, mut right) = peers(config(128))?;
    for frame in native_frames()? {
        left.enqueue_admitted(ChannelId(0), &frame, ms(0))?;
    }
    let packets = emissions(&mut left, 0)?;
    right.receive_authenticated(&packets[0], ms(0))?;
    right.enqueue_admitted(ChannelId(0), b"reply", ms(0))?;
    let mut zero = OutboundBudget {
        packets: 0,
        wire_bytes: 0,
    };
    assert!(emit(&mut right, 2, true, &mut zero)?.is_none());
    assert!(emit(&mut right, 2, false, &mut zero)?.is_none());
    let total = 2 * (right.max_packet_bytes() + 28);
    let mut common = OutboundBudget {
        packets: 2,
        wire_bytes: total,
    };
    let ack = emit(&mut right, 5, true, &mut common)?.ok_or("feedback")?;
    assert_eq!(ack.len(), 56);
    assert_eq!(common.wire_bytes, total - ack.len() - 28);
    assert!(emit(&mut right, 5, false, &mut common)?.is_none()); // starts partial-block timer
    let data = emit(&mut right, 10, false, &mut common)?.ok_or("systematic")?;
    assert_eq!(common.packets, 0);
    assert_eq!(common.wire_bytes, total - ack.len() - data.len() - 56);
    assert!(emit(&mut right, 10, false, &mut common)?.is_none());
    assert_eq!(right.statistics().repair_packets, 0);
    Ok(())
}
#[test]
fn authoritative_source_snapshot_is_unchanged_by_failed_submit_and_packet_retries() -> TestResult {
    let config = config(128);
    let mut reliable = Reliable::new(config.recovery, context(EndpointRole::Initiator))?;
    for id in 0..8 {
        assert_eq!(reliable.next_source_id()?, id);
        assert_eq!(reliable.submit(b"source", ms(0))?, id);
    }
    let before = reliable.storage();
    assert_eq!(reliable.next_source_id()?, 8);
    assert!(matches!(
        reliable.submit(b"blocked", ms(0)),
        Err(l2tunnel_reliable::Error::Arq(RecoveryError::Capacity(_)))
    ));
    assert_eq!(reliable.next_source_id()?, 8);
    assert_eq!(reliable.storage(), before);
    let mut arq = l2tunnel_recovery::SelectiveRepeat::new(
        config.recovery.arq,
        context(EndpointRole::Initiator),
    )?;
    assert_eq!(arq.next_source_id()?.0, 0);
    assert!(
        arq.submit(&vec![0; config.recovery.arq.max_source_bytes + 1], ms(0))
            .is_err()
    );
    assert_eq!(arq.next_source_id()?.0, 0);
    Ok(())
}
#[test]
fn bounded_fragment_and_native_backpressure_retain_exact_frames_until_commit() -> TestResult {
    let mut config = config(20);
    config.receiver.lookahead_records = 0;
    config.receiver.lookahead_bytes = 0;
    config.receiver.lookahead_fragments = 0;
    let (mut left, mut right) = peers(config)?;
    let input = [vec![17; 500], vec![29; 90], vec![33; 66]];
    let mut admitted = 0;
    let mut output = Vec::new();
    let mut held = None;
    let mut saw_stage = false;
    let mut saw_handoff = false;
    for time in 0..1000 {
        if admitted < input.len() && !left.status().staged_frame {
            left.enqueue_admitted(ChannelId(0), &input[admitted], ms(time))?;
            admitted += 1;
        }
        saw_stage |= left.status().staged_frame;
        let mut budget = OutboundBudget {
            packets: 2,
            wire_bytes: 2 * (left.max_packet_bytes() + 28),
        };
        for _ in 0..2 {
            if let Some(packet) = emit(&mut left, time, false, &mut budget)? {
                right.receive_authenticated(&packet, ms(time))?;
            }
        }
        let mut reverse = allowance(&right);
        if let Some(ack) = emit(&mut right, time, true, &mut reverse)? {
            left.receive_authenticated(&ack, ms(time))?;
        }
        right.prepare(ChannelId(0), ms(time), 8)?;
        saw_handoff |= right.status().retained_handoff;
        if let Some(pending) = right.pending() {
            if time < 80 {
                if let Some(previous) = &held {
                    assert_eq!(previous, pending.bytes);
                }
                held = Some(pending.bytes.to_vec());
            } else {
                output.push(pending.bytes.to_vec());
                right.commit_delivery(ms(time))?;
            }
        }
        assert!(left.status().recovery.arq.send_records <= 8);
        assert!(right.status().recovery.arq.receive_records <= 8);
        assert!(right.status().receiver.retained_records <= 2);
        if output.len() == input.len() && left.drained() && right.drained() {
            break;
        }
    }
    assert_eq!(output, input);
    assert!(saw_stage && saw_handoff && held.is_some());
    assert!(left.drained() && right.drained());
    Ok(())
}
#[test]
fn config_digest_binds_policy_and_lifetime_geometry_and_packet_caps_are_checked() -> TestResult {
    let baseline = config(128);
    let digest = baseline.digest()?;
    // Captured from the ordinary implementation before shared packed validation.
    assert_eq!(
        digest.0,
        [
            0x1b, 0xd8, 0xe1, 0xba, 0x05, 0x8a, 0x4f, 0x76, 0x1a, 0x2e, 0x97, 0xd6, 0x81, 0x7d,
            0x41, 0x8b, 0xcd, 0x21, 0xb8, 0x5c, 0x70, 0x6c, 0x22, 0xe6, 0x97, 0xa3, 0x03, 0xe0,
            0xda, 0xc5, 0x5b, 0xc0
        ]
    );
    let changes: [fn(&mut Config); 25] = [
        |c| c.receiver.body.max_frame_bytes += 1,
        |c| c.receiver.body.elide_payload_length = false,
        |c| c.receiver.body.predictive = false,
        |c| c.receiver.body.timestamp_pair_dictionary = false,
        |c| c.receiver.body.independent_short_frame_bytes = 10,
        |c| c.receiver.channels = 1,
        |c| c.receiver.first_record.0 = 1,
        |c| c.receiver.record_window += 1,
        |c| c.receiver.source_window += 1,
        |c| c.receiver.lookahead_records += 1,
        |c| c.receiver.lookahead_bytes += 1,
        |c| c.receiver.lookahead_fragments += 1,
        |c| c.receiver.max_fragments_per_record += 1,
        |c| c.receiver.lifetime_ticks += 1,
        |c| c.recovery.arq.send_bytes += 1,
        |c| c.recovery.arq.receive_bytes += 1,
        |c| c.recovery.arq.initial_rto += Duration::from_nanos(1),
        |c| c.recovery.arq.ack_delay += Duration::from_nanos(1),
        |c| c.recovery.fec.block.max_work_per_symbol += 1,
        |c| c.recovery.fec.max_generations += 1,
        |c| c.recovery.fec.max_reserved_bytes += 1,
        |c| c.recovery.flush_after += Duration::from_nanos(1),
        |c| c.recovery.max_restored_bytes += 1,
        |c| c.recovery.outer_overhead_bytes += 1,
        |c| c.max_recovery_packet_bytes += 1,
    ];
    for change in changes {
        let mut changed = baseline;
        change(&mut changed);
        if let Ok(actual) = changed.digest() {
            assert_ne!(actual, digest);
        }
    }
    let invalid: [fn(&mut Config); 8] = [
        |c| c.receiver.first_source.0 = 1,
        |c| c.receiver.source_window = 23,
        |c| c.receiver.max_fragments_per_record = 1,
        |c| c.receiver.lifetime_ticks = 705,
        |c| c.recovery.arq.max_retries = 257,
        |c| c.recovery.arq.max_source_bytes -= 1,
        |c| c.max_recovery_packet_bytes -= 1,
        |c| c.receiver.body.symbol_bytes = 8,
    ];
    for change in invalid {
        let mut changed = baseline;
        change(&mut changed);
        assert!(changed.validate().is_err());
    }
    assert_eq!(
        baseline.maximum_charged_bytes()?,
        baseline.max_recovery_packet_bytes + 28
    );
    Ok(())
}
#[test]
fn absolute_identity_scope_and_pending_native_expiry_fail_closed() -> TestResult {
    let config = config(128);
    let mut attacker = Reliable::new(config.recovery, context(EndpointRole::Initiator))?;
    let mut sender = sender::Sender::new(
        receiver::Scope {
            session: 0x1234u128.to_be_bytes(),
            epoch: Epoch(7),
            direction: receiver::Direction::InitiatorToResponder,
        },
        sender_config(config),
    )?;
    sender.stage(ChannelId(0), b"body")?;
    let mut bad = vec![0; config.recovery.arq.max_source_bytes];
    sender.write_pending(SourceId(9), &mut bad)?;
    attacker.submit(&bad, ms(0))?;
    let (_, mut receiver) = peers(config)?;
    let mut bytes = vec![0; config.max_recovery_packet_bytes];
    let mut budget = allowance(&receiver);
    assert!(
        attacker
            .poll_data(ms(0), &mut bytes, &mut budget)?
            .is_none()
    );
    let length = attacker
        .poll_data(ms(5), &mut bytes, &mut budget)?
        .ok_or("packet")?;
    assert_eq!(
        receiver.receive_authenticated(&bytes[..length], ms(5)),
        Err(Error::Identity)
    );
    assert_eq!(receiver.status().failure, Some(Error::Identity));
    assert_eq!(receiver.tick(ms(6)), Err(Error::Identity));
    let (mut left, mut right) = peers(config)?;
    left.enqueue_admitted(ChannelId(0), b"pending native", ms(0))?;
    assert!(emissions(&mut left, 0)?.is_empty());
    for packet in emissions(&mut left, 5)? {
        right.receive_authenticated(&packet, ms(5))?;
    }
    assert_eq!(right.prepare(ChannelId(0), ms(5), 8)?, Prepared::Ready);
    assert!(right.pending().is_some());
    assert!(
        right
            .deadline()
            .is_some_and(|deadline| deadline <= ms(5005))
    );
    assert_eq!(
        right.commit_delivery(ms(5005)),
        Err(Error::Receiver(receiver::Error::Expired))
    );
    assert!(right.pending().is_none());
    assert!(!right.drained());
    Ok(())
}

#[test]
fn raw_ip_policy_is_digest_bound_and_never_uses_ethernet_header_context() -> TestResult {
    let mut raw = config(128);
    let ethernet_digest = raw.digest()?;
    raw.native_policy = NativePolicy::RawIp;
    raw.receiver.body.elide_payload_length = false;
    raw.receiver.body.predictive = false;
    raw.receiver.body.timestamp_pair_dictionary = false;
    assert_ne!(raw.digest()?, ethernet_digest);
    let (mut left, mut right) = peers(raw)?;
    let native = native_frames()?.remove(0); // Even Ethernet-looking input is explicitly raw.
    left.enqueue_admitted_raw(ChannelId(0), &native, ms(0))?;
    assert_eq!(left.arq_statistics().submitted, 2); // two fragments, no context record
    assert!(emissions(&mut left, 0)?.is_empty());
    for packet in emissions(&mut left, 5)? {
        right.receive_authenticated(&packet, ms(5))?;
    }
    assert_eq!(deliveries(&mut right, 5)?, vec![(0, native)]);
    let (mut ethernet, _) = peers(config(128))?;
    assert_eq!(
        ethernet.enqueue_admitted_raw(ChannelId(0), b"body", ms(0)),
        Err(Error::Configuration)
    );
    assert_eq!(ethernet.arq_statistics().submitted, 0);
    Ok(())
}

#[test]
fn sender_native_identity_and_all_original_fragment_witnesses_survive_retry() -> TestResult {
    let mut endpoint = Endpoint::new(config(256), context(EndpointRole::Initiator))?;
    let native = vec![0x7a; 1500];
    let identity = endpoint.enqueue_identified(ChannelId(1), &native, ms(0))?;
    assert_eq!(identity.channel, ChannelId(1));
    let mut slots = [UnitWitness {
        identity,
        index: 0,
        count: 1,
    }];
    let mut seen = std::collections::BTreeSet::new();
    let mut count = None;
    for packet in emissions(&mut endpoint, 5)?
        .into_iter()
        .chain(emissions(&mut endpoint, 10)?)
    {
        let n = endpoint.outgoing_units(&packet, &mut slots)?;
        for witness in &slots[..n] {
            if witness.identity != identity {
                continue;
            }
            assert!(witness.index < witness.count);
            assert_eq!(*count.get_or_insert(witness.count), witness.count);
            seen.insert(witness.index);
        }
    }
    let count = count.ok_or("missing native witnesses")?;
    assert!(count > 1);
    assert_eq!(seen, (0..count).collect());
    let retry = emissions(&mut endpoint, 110)?;
    let mut retried_native = false;
    for packet in retry {
        let n = endpoint.outgoing_units(&packet, &mut slots)?;
        for witness in &slots[..n] {
            if witness.identity == identity {
                retried_native = true;
                assert_eq!(witness.count, count);
                assert!(seen.contains(&witness.index));
            }
        }
    }
    assert!(retried_native);
    Ok(())
}

#[test]
fn selected_compact_aligned_preview_preserves_gap_and_deduplicates_native_delivery() -> TestResult {
    let mut config = config(128);
    config.native_policy = NativePolicy::RawIp;
    config.receiver.body.elide_payload_length = false;
    config.receiver.body.predictive = false;
    config.receiver.body.timestamp_pair_dictionary = false;
    config.receiver.body.independent_short_frame_bytes = 32;
    let (mut left, mut right) = peers(config)?;
    left.enable_compact_wire(40)?;
    right.enable_compact_wire(40)?;
    left.enqueue_admitted_raw(ChannelId(0), &[11; 70], ms(0))?;
    left.enqueue_admitted_raw(ChannelId(0), b"tiny", ms(0))?;
    assert!(emissions(&mut left, 0)?.is_empty());
    let packets = emissions(&mut left, 5)?;
    right.receive_authenticated(&packets[1], ms(6))?;
    assert_eq!(right.prepare(ChannelId(0), ms(6), 1)?, Prepared::Ready);
    assert!(right.pending().ok_or("early native")?.early);
    assert_eq!(right.pending().ok_or("early native")?.bytes, b"tiny");
    right.commit_delivery(ms(7))?;
    right.receive_authenticated(&packets[0], ms(8))?;
    assert_eq!(deliveries(&mut right, 8)?, [(0, vec![11; 70])]);
    right.receive_authenticated(&packets[1], ms(9))?;
    assert_eq!(right.prepare(ChannelId(0), ms(9), 1)?, Prepared::Idle);
    assert_eq!(
        right.status().receiver.source_floor,
        Some(receiver::SourceId(2))
    );
    assert_eq!(right.status().receiver.early_tombstones, 0);
    Ok(())
}

#[test]
fn staged_source_wait_tracks_actual_capacity_refusal_then_same_source_admission() -> TestResult {
    let mut config = config(128);
    config.recovery.repair_symbols = 0;
    let mut sender = Endpoint::new(config, context(EndpointRole::Initiator))?;
    let mut peer = Reliable::new(config.recovery, context(EndpointRole::Responder))?;
    for source in 0..8 {
        assert_eq!(sender.recovery.submit(b"retained", ms(0))?, source);
    }
    let frames = native_frames()?;
    sender.enqueue_admitted(ChannelId(0), &frames[0], ms(0))?;
    let waiting = sender.staged_admission_snapshot(ms(0));
    let pending = waiting.pending.ok_or("actual blocked stage")?;
    assert_eq!(pending.source, 8);
    assert_eq!(pending.since, ms(0));
    assert_eq!(waiting.union.completed_episodes, 0);
    for packet in emissions(&mut sender, 1)? {
        peer.receive(&packet, ms(1))?;
    }
    let repeated = sender.staged_admission_snapshot(ms(1));
    assert_eq!(repeated.pending.map(|v| v.source), Some(8));
    assert_eq!(repeated.pending.map(|v| v.since), Some(ms(0)));
    assert!(repeated.refusals[0] > waiting.refusals[0]);
    let mut output = vec![0; sender.max_packet_bytes()];
    let mut budget = allowance(&sender);
    let length = peer
        .poll_feedback(ms(2), &mut output, &mut budget)?
        .ok_or("peer feedback")?;
    sender.receive_authenticated(&output[..length], ms(10))?;
    assert!(emit(&mut sender, 10, false, &mut budget)?.is_some());
    let completed = sender.staged_admission_snapshot(ms(10));
    assert_eq!(completed.union.completed_episodes, 1);
    assert_eq!(completed.union.completed, ms(10));
    assert_eq!(completed.union.censored_episodes, 0);
    assert!(
        matches!(completed.last_resolved, Some(staged_wait::Resolved {
        source: 8, since, at, bytes, censored: false,
    }) if since == ms(0) && at == ms(10) && bytes == pending.bytes)
    );
    assert!(!completed.identity_mismatch);
    assert!(!completed.clock_regression);
    Ok(())
}
