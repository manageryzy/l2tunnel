use super::*;
use l2tunnel_recovery::ACK_PACKET_BYTES;
#[path = "feedback_custody_tests.rs"]
mod feedback_custody;
#[path = "physical_tests.rs"]
mod physical;
#[path = "retry_enrichment_tests.rs"]
mod retry_enrichment;
#[path = "selected_wire_tests.rs"]
mod selected_wire;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> ReliableConfig {
    ReliableConfig {
        arq: ArqConfig {
            max_source_bytes: 64,
            send_bytes: 512,
            receive_bytes: 512,
            send_records: 8,
            receive_records: 8,
            initial_rto: time(100),
            maximum_rto: time(800),
            ack_delay: time(1),
            max_retries: 8,
        },
        fec: fec::DecoderConfig {
            block: fec::BlockConfig {
                max_sources: 3,
                max_source_bytes: 108,
                max_packet_bytes: 169,
                max_work_per_symbol: 4096,
            },
            max_generations: 4,
            max_symbols_per_generation: 6,
            max_reserved_bytes: 50_000,
            max_lifetime_ticks: 50,
            generation_window: 32,
        },
        repair_symbols: 2,
        flush_after: time(5),
        max_restored_packets: 16,
        max_restored_bytes: 4096,
        outer_overhead_bytes: 28,
    }
}

fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x1234,
        epoch: 7,
        role,
    }
}

fn endpoints() -> Result<(Reliable, Reliable), Error> {
    Ok((
        Reliable::new(config(), context(EndpointRole::Initiator))?,
        Reliable::new(config(), context(EndpointRole::Responder))?,
    ))
}

fn time(ticks: u64) -> Duration {
    Duration::from_millis(ticks)
}

#[test]
fn structural_views_reuse_live_inspection_and_expose_only_real_systematic_sources() -> TestResult {
    let (mut sender, _) = endpoints()?;
    sender.submit(b"L2PK is only opaque data in this parser", time(0))?;
    let mut packets = emissions(&mut sender, 5)?;
    packets.extend(emissions(&mut sender, 105)?);
    let mut seen = [false; 3];
    for packet in packets {
        let inspect = |bytes| {
            inspect_structural(
                bytes,
                EndpointRole::Initiator,
                sender.max_packet_bytes(),
                config().arq.max_source_bytes,
                config().fec.block,
            )
        };
        let view = inspect(&packet)?;
        assert_eq!(view.kind, sender.inspect_output(&packet)?);
        assert_eq!(view.sender, context(EndpointRole::Initiator));
        match view.kind {
            RecordKind::Source => seen[0] = true,
            RecordKind::Systematic => seen[1] = true,
            RecordKind::Repair => seen[2] = true,
            RecordKind::Feedback => return Err("unexpected feedback".into()),
        }
        if let Some((id, bytes)) = view.source {
            assert_eq!(id.0, 0);
            assert_eq!(bytes, b"L2PK is only opaque data in this parser");
        } else {
            assert_eq!(view.kind, RecordKind::Repair);
        }
        for end in 0..packet.len() {
            assert!(inspect(&packet[..end]).is_err());
        }
        assert!(
            inspect_structural(
                &packet,
                EndpointRole::Responder,
                sender.max_packet_bytes(),
                config().arq.max_source_bytes,
                config().fec.block
            )
            .is_err()
        );
        let mut excess = packet.clone();
        excess.push(0);
        assert!(inspect(&excess).is_err());
    }
    assert_eq!(seen, [true; 3]);
    Ok(())
}

fn emit(endpoint: &mut Reliable, ticks: u64) -> Result<Option<Vec<u8>>, Error> {
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: endpoint.max_packet_bytes() + 28,
    };
    let mut bytes = vec![0xa5; endpoint.max_packet_bytes()];
    Ok(endpoint
        .poll(time(ticks), &mut bytes, &mut budget)?
        .map(|length| {
            bytes.truncate(length);
            bytes
        }))
}

fn emissions(endpoint: &mut Reliable, ticks: u64) -> Result<Vec<Vec<u8>>, Error> {
    let mut packets = Vec::new();
    for _ in 0..128 {
        let Some(packet) = emit(endpoint, ticks)? else {
            return Ok(packets);
        };
        packets.push(packet);
    }
    Err(Error::Exhausted)
}

fn deliveries(endpoint: &mut Reliable) -> Result<Vec<(u64, Vec<u8>)>, Error> {
    let mut packets = Vec::new();
    let mut output = vec![0; 64];
    while let Some((identity, length)) = endpoint.poll_delivered(&mut output)? {
        packets.push((identity, output[..length].to_vec()));
    }
    Ok(packets)
}

fn sources() -> Vec<Vec<u8>> {
    vec![vec![0, 255, 13], vec![3; 64], vec![14, 8, 99, 1, 0]]
}

fn submit_all(endpoint: &mut Reliable, sources: &[Vec<u8>]) -> Result<(), Error> {
    for (identity, source) in sources.iter().enumerate() {
        assert_eq!(endpoint.submit(source, Duration::ZERO)?, identity as u64);
    }
    Ok(())
}

fn indexed(sources: &[Vec<u8>]) -> Vec<(u64, Vec<u8>)> {
    sources
        .iter()
        .enumerate()
        .map(|(i, bytes)| (i as u64, bytes.clone()))
        .collect()
}

#[test]
fn no_loss_preserves_nonuniform_bytes_and_identity_without_fresh_repair_credit() -> TestResult {
    let (mut sender, mut receiver) = endpoints()?;
    let input = sources();
    submit_all(&mut sender, &input)?;
    let packets = emissions(&mut sender, 0)?;
    assert_eq!(packets.len(), 5);
    assert_eq!(sender.arq_statistics().submitted, 3);
    assert_eq!(sender.arq_statistics().transmissions, 3);
    assert_eq!(sender.statistics().systematic_packets, 3);
    assert_eq!(sender.statistics().repair_packets, 2);
    for packet in &packets {
        receiver.receive(packet, Duration::ZERO)?;
    }
    assert_eq!(deliveries(&mut receiver)?, indexed(&input));
    assert_eq!(receiver.statistics().repaired_unique_sources, 0);
    let feedback = emit(&mut receiver, 1)?.ok_or("missing ACK")?;
    assert_eq!(feedback[5], 2);
    sender.receive(&feedback, time(1))?;
    assert!(sender.drained() && receiver.drained());
    assert_eq!(
        sender.statistics().emitted_wire_bytes,
        packets
            .iter()
            .map(|packet| (packet.len() + 28) as u64)
            .sum()
    );
    Ok(())
}

#[test]
fn lost_source_is_reconstructed_from_received_bytes_before_timeout() -> TestResult {
    let (mut sender, mut receiver) = endpoints()?;
    let input = sources();
    submit_all(&mut sender, &input)?;
    let packets = emissions(&mut sender, 0)?;
    receiver.receive(&packets[2], time(2))?;
    receiver.receive(&packets[1], time(3))?;
    assert!(deliveries(&mut receiver)?.is_empty());
    receiver.receive(&packets[3], time(4))?;
    assert_eq!(deliveries(&mut receiver)?, indexed(&input));
    assert_eq!(receiver.statistics().repaired_unique_sources, 1);
    assert_eq!(sender.arq_statistics().retransmissions, 0);
    let feedback = emit(&mut receiver, 5)?.ok_or("missing ACK")?;
    sender.receive(&feedback, time(5))?;
    assert!(sender.drained());
    Ok(())
}

#[test]
fn insufficient_rank_expires_then_direct_arq_retries_restore_original_records() -> TestResult {
    let (mut sender, mut receiver) = endpoints()?;
    let input = sources();
    submit_all(&mut sender, &input)?;
    let packets = emissions(&mut sender, 0)?;
    receiver.receive(&packets[2], Duration::ZERO)?;
    let feedback = emit(&mut receiver, 1)?.ok_or("missing selective ACK")?;
    sender.receive(&feedback, time(1))?;
    assert!(deliveries(&mut receiver)?.is_empty());
    let retries = emissions(&mut sender, 100)?;
    assert_eq!(retries.len(), 2);
    for retry in &retries {
        assert_eq!(retry[5], 1);
        receiver.receive(retry, time(100))?;
    }
    assert_eq!(deliveries(&mut receiver)?, indexed(&input));
    assert_eq!(receiver.statistics().expired_generations, 1);
    assert_eq!(receiver.statistics().repaired_unique_sources, 0);
    assert_eq!(sender.arq_statistics().submitted, 3);
    assert_eq!(sender.statistics().retry_packets, 2);
    let feedback = emit(&mut receiver, 101)?.ok_or("missing final ACK")?;
    sender.receive(&feedback, time(101))?;
    assert!(sender.drained() && receiver.drained());
    Ok(())
}

#[test]
fn partial_deadline_and_one_source_repair_do_not_discard_queued_sources() -> TestResult {
    for count in 1..=2 {
        let (mut sender, mut receiver) = endpoints()?;
        let input: Vec<_> = sources().into_iter().take(count).collect();
        submit_all(&mut sender, &input)?;
        assert!(emit(&mut sender, 0)?.is_none());
        assert_eq!(sender.storage().building_packets, count);
        assert_eq!(sender.deadline(), Some(time(5)));
        assert!(emit(&mut sender, 4)?.is_none());
        let packets = emissions(&mut sender, 5)?;
        assert_eq!(packets.len(), count + (count * 2).div_ceil(3));
        assert_eq!(sender.storage().building_packets, 0);
        for packet in packets.iter().skip(count) {
            receiver.receive(packet, time(5))?;
        }
        assert_eq!(deliveries(&mut receiver)?, indexed(&input));
        assert_eq!(receiver.statistics().repaired_unique_sources, count as u64);
    }
    Ok(())
}

#[test]
fn feedback_uses_exact_shared_budget_while_outgoing_generation_is_partial() -> TestResult {
    let (mut left, mut right) = endpoints()?;
    left.submit(b"left", Duration::ZERO)?;
    right.submit(b"right", Duration::ZERO)?;
    assert!(emit(&mut left, 0)?.is_none());
    assert!(emit(&mut right, 0)?.is_none());
    left.receive(&emit(&mut right, 5)?.ok_or("missing source")?, time(5))?;
    let charge = ENVELOPE_BYTES + ACK_PACKET_BYTES + 28;
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: charge - 1,
    };
    let mut output = vec![0xa5; left.max_packet_bytes()];
    assert_eq!(left.poll(time(6), &mut output, &mut budget)?, None);
    assert!(output.iter().all(|byte| *byte == 0xa5));
    budget.wire_bytes = charge;
    let length = left
        .poll(time(6), &mut output, &mut budget)?
        .ok_or("missing ACK")?;
    assert_eq!(output[5], 2);
    assert_eq!(length, ENVELOPE_BYTES + ACK_PACKET_BYTES);
    assert_eq!(budget, OutboundBudget::default());
    // A due block is sealed despite exhausted allowance and remains queued.
    assert_eq!(left.storage().outbound_packets, 2);
    assert_eq!(left.arq_statistics().submitted, 1);
    assert_eq!(emit(&mut left, 6)?.ok_or("missing source")?[5], 3);
    Ok(())
}

#[test]
fn every_copy_charges_packet_and_byte_caps_and_small_output_is_atomic() -> TestResult {
    let (mut sender, _) = endpoints()?;
    submit_all(&mut sender, &vec![vec![8; 64]; 3])?;
    let maximum = sender.max_packet_bytes();
    assert_eq!(maximum, 177);
    let mut output = vec![0xa5; maximum];
    let mut budget = OutboundBudget {
        packets: 7,
        wire_bytes: maximum + 28 - 1,
    };
    let before = sender.storage();
    assert_eq!(sender.poll(Duration::ZERO, &mut output, &mut budget)?, None);
    assert_eq!(sender.storage(), before);
    assert_eq!(sender.arq_statistics().transmissions, 0);
    budget.wire_bytes += 1;
    assert_eq!(
        sender.poll(Duration::ZERO, &mut output[..maximum - 1], &mut budget),
        Err(Error::OutputTooSmall { required: maximum })
    );
    assert_eq!(sender.storage(), before);
    assert!(output.iter().all(|byte| *byte == 0xa5));
    assert_eq!(
        sender.poll(Duration::ZERO, &mut output, &mut budget)?,
        Some(maximum)
    );
    assert_eq!(
        budget,
        OutboundBudget {
            packets: 6,
            wire_bytes: 0
        }
    );
    assert_eq!(sender.storage().outbound_packets, 4);
    let storage = sender.storage();
    let snapshot = output.clone();
    budget = OutboundBudget {
        packets: 0,
        wire_bytes: 100_000,
    };
    assert_eq!(sender.poll(Duration::ZERO, &mut output, &mut budget)?, None);
    assert_eq!(sender.storage(), storage);
    assert_eq!(output, snapshot);
    budget = OutboundBudget {
        packets: 4,
        wire_bytes: 4 * (maximum + 28),
    };
    for _ in 0..4 {
        assert_eq!(
            sender.poll(Duration::ZERO, &mut output, &mut budget)?,
            Some(maximum)
        );
    }
    assert_eq!(budget, OutboundBudget::default());
    assert_eq!(sender.statistics().emitted_packets, 5);
    assert_eq!(
        sender.statistics().emitted_wire_bytes,
        5 * (maximum as u64 + 28)
    );
    assert_eq!(sender.arq_statistics().submitted, 3);
    assert_eq!(sender.arq_statistics().transmissions, 3);
    Ok(())
}

#[test]
fn reordered_repair_first_and_duplicate_symbols_deliver_sources_once() -> TestResult {
    let (mut sender, mut receiver) = endpoints()?;
    let input = sources();
    submit_all(&mut sender, &input)?;
    let packets = emissions(&mut sender, 0)?;
    for packet in packets.iter().rev() {
        receiver.receive(packet, Duration::ZERO)?;
        receiver.receive(packet, Duration::ZERO)?;
    }
    assert_eq!(deliveries(&mut receiver)?, indexed(&input));
    assert!(deliveries(&mut receiver)?.is_empty());
    assert_eq!(receiver.arq_statistics().received_unique, 3);
    assert_eq!(receiver.statistics().repaired_unique_sources, 2);
    assert!(receiver.statistics().skipped_fec_packets > 0);
    Ok(())
}

fn direct_packet(identity: u64) -> Result<Vec<u8>, Error> {
    let mut sender = SelectiveRepeat::new(config().arq, context(EndpointRole::Initiator))?;
    sender.submit(&identity.to_be_bytes(), Duration::ZERO)?;
    let mut packet = vec![0; sender.max_packet_bytes()];
    let length = sender
        .poll_source(Duration::ZERO, &mut packet)?
        .ok_or(Error::Malformed)?;
    packet.truncate(length);
    // Adversarial fixture only; production uses authoritative inspect_packet.
    packet[32..40].copy_from_slice(&identity.to_be_bytes());
    Ok(wrap(1, &packet))
}

#[test]
fn stalled_application_has_finite_staging_and_feedback_survives() -> TestResult {
    let (_, mut receiver) = endpoints()?;
    for identity in 0..24 {
        receiver.receive(&direct_packet(identity)?, Duration::ZERO)?;
    }
    assert_eq!(receiver.storage().arq.receive_records, 8);
    assert_eq!(receiver.storage().restored_packets, 16);
    let before = receiver.storage();
    assert_eq!(
        receiver.receive(&direct_packet(24)?, Duration::ZERO),
        Err(Error::RestoredCapacity)
    );
    assert_eq!(receiver.storage(), before);
    assert!(receiver.failure().is_none());
    assert_eq!(emit(&mut receiver, 1)?.ok_or("missing pressure ACK")?[5], 2);
    let mut output = Vec::new();
    for _ in 0..3 {
        output.extend(deliveries(&mut receiver)?);
        let _ = emit(&mut receiver, 1)?;
    }
    assert_eq!(
        output,
        (0_u64..24)
            .map(|id| (id, id.to_be_bytes().to_vec()))
            .collect::<Vec<_>>()
    );
    assert_eq!(receiver.storage().restored_packets, 0);
    assert_eq!(receiver.storage().restored_bytes, 0);
    Ok(())
}

#[test]
fn malformed_truncated_reflected_and_wrong_inner_records_fail_closed() -> TestResult {
    let (mut sender, _) = endpoints()?;
    submit_all(&mut sender, &sources())?;
    let packet = emit(&mut sender, 0)?.ok_or("missing packet")?;
    for length in 0..packet.len() {
        let (_, mut receiver) = endpoints()?;
        assert!(receiver.receive(&packet[..length], Duration::ZERO).is_err());
        assert!(receiver.failure().is_some());
        assert_eq!(receiver.arq_statistics().received_unique, 0);
        assert_eq!(receiver.storage().restored_packets, 0);
    }
    for (offset, value) in [(0, 0), (4, 2), (5, 4), (6, 1), (7, 1), (12, 2)] {
        let (_, mut receiver) = endpoints()?;
        let mut invalid = packet.clone();
        invalid[offset] = value;
        assert!(receiver.receive(&invalid, Duration::ZERO).is_err());
        assert_eq!(receiver.arq_statistics().received_unique, 0);
    }
    let mut reflected = Reliable::new(config(), context(EndpointRole::Initiator))?;
    assert!(reflected.receive(&packet, Duration::ZERO).is_err());
    let (_, mut receiver) = endpoints()?;
    let mut wrong_kind = direct_packet(0)?;
    wrong_kind[5] = 2;
    assert_eq!(
        receiver.receive(&wrong_kind, Duration::ZERO),
        Err(Error::Malformed)
    );
    let (_, mut receiver) = endpoints()?;
    let mut oversized = packet;
    oversized.push(0);
    assert_eq!(
        receiver.receive(&oversized, Duration::ZERO),
        Err(Error::Malformed)
    );
    Ok(())
}

#[test]
fn restored_conflicts_and_noncontiguous_decoded_source_ids_are_terminal() -> TestResult {
    let (_, mut receiver) = endpoints()?;
    let original = direct_packet(8)?;
    receiver.receive(&original, Duration::ZERO)?;
    let mut conflict = original.clone();
    let end = conflict.len() - 1;
    conflict[end] ^= 0x80;
    assert_eq!(
        receiver.receive(&conflict, Duration::ZERO),
        Err(Error::SourceConflict)
    );
    assert_eq!(receiver.failure(), Some(Error::SourceConflict));
    let (_, mut receiver) = endpoints()?;
    let packets = [direct_packet(0)?, direct_packet(2)?];
    let borrowed: Vec<_> = packets
        .iter()
        .map(|packet| &packet[ENVELOPE_BYTES..])
        .collect();
    let mut encoder = fec::BlockEncoder::new(
        fec_context(context(EndpointRole::Initiator), false),
        fec::GenerationId(0),
        config().fec.block,
        &borrowed,
    )?;
    let first = encoder.repair(&fec::cauchy_coefficients(2, 0)?)?;
    let second = encoder.repair(&fec::cauchy_coefficients(2, 1)?)?;
    receiver.receive(&wrap(3, &first.bytes), Duration::ZERO)?;
    assert_eq!(
        receiver.receive(&wrap(3, &second.bytes), Duration::ZERO),
        Err(Error::SourceConflict)
    );
    assert_eq!(receiver.arq_statistics().received_unique, 0);
    assert_eq!(receiver.storage().restored_packets, 0);
    Ok(())
}

#[test]
fn protection_rejects_corruption_before_recovery_mutation() -> TestResult {
    use l2tunnel_datagram as datagram;
    let (mut sender, mut receiver) = endpoints()?;
    submit_all(&mut sender, &sources())?;
    let packet = emit(&mut sender, 0)?.ok_or("missing source")?;
    let protection = datagram::DatagramConfig {
        context: datagram::KeyContext {
            session: datagram::SessionId(context(EndpointRole::Initiator).session.to_be_bytes()),
            direction: datagram::Direction::ClientToServer,
            lane: datagram::LaneId(0),
            generation: datagram::KeyGeneration(0),
        },
        cover: datagram::CoverProfile::OpenVpnLike,
        protection: datagram::Protection::ChaCha20Poly1305,
        path_mtu: 1500,
        outer_overhead_bytes: 28,
        max_payload_bytes: sender.max_packet_bytes(),
        max_packets_per_key: 100,
        max_payload_bytes_per_key: 100_000,
    };
    let mut sealer = datagram::PacketSealer::new(protection, &[3; 32])?;
    let mut opener = datagram::PacketOpener::new(protection, &[3; 32])?;
    let sealed = sealer.seal_vec(&packet)?;
    let mut corrupted = sealed.bytes.clone();
    let end = corrupted.len() - 1;
    corrupted[end] ^= 1;
    let mut plaintext = vec![0xa5; sender.max_packet_bytes()];
    let before = receiver.storage();
    assert_eq!(
        opener.open(&corrupted, &mut plaintext),
        Err(datagram::Error::Authentication)
    );
    assert!(plaintext.iter().all(|byte| *byte == 0xa5));
    assert_eq!(receiver.storage(), before);
    let opened = opener.open(&sealed.bytes, &mut plaintext)?;
    receiver.receive(&plaintext[..opened.payload_len], Duration::ZERO)?;
    assert_eq!(deliveries(&mut receiver)?, vec![(0, sources()[0].clone())]);
    assert_eq!(
        opener.open(&sealed.bytes, &mut plaintext),
        Err(datagram::Error::Replay)
    );
    Ok(())
}

#[test]
fn canonical_cross_module_caps_and_time_arithmetic_are_checked() -> TestResult {
    let good = config();
    let cases: [fn(&mut ReliableConfig); 11] = [
        |c| c.fec.block.max_source_bytes -= 1,
        |c| c.fec.block.max_packet_bytes -= 1,
        |c| c.fec.block.max_work_per_symbol = 1,
        |c| c.fec.max_reserved_bytes = 1,
        |c| c.fec.max_symbols_per_generation = 4,
        |c| c.max_restored_packets = 10,
        |c| c.max_restored_bytes = 16 * 108 - 1,
        |c| c.repair_symbols = 254,
        |c| c.flush_after = c.arq.initial_rto,
        |c| c.flush_after = Duration::ZERO,
        |c| c.outer_overhead_bytes = usize::MAX,
    ];
    for change in cases {
        let mut invalid = good;
        change(&mut invalid);
        assert!(Reliable::new(invalid, context(EndpointRole::Initiator)).is_err());
    }
    let (mut sender, _) = endpoints()?;
    sender.submit(b"payload", time(9))?;
    let before = sender.storage();
    assert_eq!(
        sender.submit(b"again", time(8)),
        Err(Error::NonMonotonicTime)
    );
    assert_eq!(
        sender.submit(b"again", Duration::MAX),
        Err(Error::TimeOverflow)
    );
    assert_eq!(sender.storage(), before);
    assert!(sender.failure().is_none());
    Ok(())
}

#[test]
fn decoder_capacity_degrades_to_systematic_and_arq_without_fabricated_ack() -> TestResult {
    let (mut sender, _) = endpoints()?;
    let mut limited = config();
    limited.fec.max_generations = 1;
    let mut receiver = Reliable::new(limited, context(EndpointRole::Responder))?;
    let input: Vec<_> = (0..6).map(|byte| vec![byte; byte as usize + 1]).collect();
    submit_all(&mut sender, &input)?;
    let packets = emissions(&mut sender, 0)?;
    assert_eq!(packets.len(), 10);
    receiver.receive(&packets[0], Duration::ZERO)?;
    for packet in &packets[5..] {
        receiver.receive(packet, Duration::ZERO)?;
    }
    assert_eq!(receiver.arq_statistics().received_unique, 4);
    assert!(receiver.statistics().skipped_fec_packets >= 5);
    let ack = emit(&mut receiver, 1)?.ok_or("missing bounded-state ACK")?;
    sender.receive(&ack, time(1))?;
    let retries = emissions(&mut sender, 100)?;
    assert_eq!(retries.len(), 2);
    for retry in retries {
        receiver.receive(&retry, time(100))?;
    }
    assert_eq!(deliveries(&mut receiver)?, indexed(&input));
    assert_eq!(receiver.statistics().repaired_unique_sources, 0);
    Ok(())
}

#[test]
fn bidirectional_bounded_loss_reorder_and_duplicates_eventually_drain() -> TestResult {
    let (mut left, mut right) = endpoints()?;
    let left_sources: Vec<_> = (0..6).map(|id| vec![id + 1; id as usize + 2]).collect();
    let right_sources: Vec<_> = (0..6).map(|id| vec![id + 90; 10 - id as usize]).collect();
    submit_all(&mut left, &left_sources)?;
    submit_all(&mut right, &right_sources)?;
    let mut network: Vec<(u64, bool, Vec<u8>)> = Vec::new();
    let mut serial = 0;
    let mut at_left = Vec::new();
    let mut at_right = Vec::new();
    for tick in 0..1000 {
        for from_left in [true, false] {
            let endpoint = if from_left { &mut left } else { &mut right };
            let mut budget = OutboundBudget {
                packets: 2,
                wire_bytes: 2 * (177 + 28),
            };
            let mut output = vec![0; endpoint.max_packet_bytes()];
            for _ in 0..2 {
                if let Some(length) = endpoint.poll(time(tick), &mut output, &mut budget)? {
                    serial += 1;
                    if tick < 200 && serial % 5 == 0 {
                        continue;
                    }
                    network.push((tick + serial % 7, from_left, output[..length].to_vec()));
                    if serial % 4 == 0 {
                        network.push((tick + 8, from_left, output[..length].to_vec()));
                    }
                }
            }
        }
        for index in (0..network.len()).rev() {
            if network[index].0 <= tick {
                let (_, from_left, packet) = network.swap_remove(index);
                let receiver = if from_left { &mut right } else { &mut left };
                receiver.receive(&packet, time(tick))?;
            }
        }
        at_left.extend(deliveries(&mut left)?);
        at_right.extend(deliveries(&mut right)?);
        assert!(left.storage().outbound_packets <= 5);
        assert!(right.storage().outbound_packets <= 5);
        if network.is_empty() && left.drained() && right.drained() {
            break;
        }
    }
    assert_eq!(at_left, indexed(&right_sources));
    assert_eq!(at_right, indexed(&left_sources));
    assert!(left.drained() && right.drained());
    assert_eq!(left.arq_statistics().submitted, 6);
    assert_eq!(right.arq_statistics().submitted, 6);
    assert!(left.failure().is_none() && right.failure().is_none());
    Ok(())
}

#[test]
fn split_polling_keeps_feedback_independent_and_uses_authoritative_output_kinds() -> TestResult {
    let (mut sender, mut receiver) = endpoints()?;
    submit_all(&mut sender, &sources())?;
    let mut output = vec![0xa5; sender.max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 6,
        wire_bytes: 6 * (177 + 28),
    };
    assert_eq!(
        sender.poll_feedback(time(0), &mut output, &mut budget)?,
        None
    );
    assert_eq!(sender.arq_statistics().transmissions, 0);
    let mut packets = Vec::new();
    for index in 0..5 {
        let length = sender
            .poll_data(time(0), &mut output, &mut budget)?
            .ok_or("missing data")?;
        let packet = output[..length].to_vec();
        assert_eq!(
            sender.inspect_output(&packet)?,
            if index < 3 {
                RecordKind::Systematic
            } else {
                RecordKind::Repair
            }
        );
        assert!(receiver.inspect_output(&packet).is_err());
        assert_eq!(
            receiver.inspect_peer(&packet)?,
            sender.inspect_output(&packet)?
        );
        assert!(sender.inspect_peer(&packet).is_err());
        packets.push(packet);
    }
    assert_eq!(budget.packets, 1);
    for packet in &packets {
        receiver.receive(packet, time(0))?;
    }
    let mut allowance = OutboundBudget {
        packets: 1,
        wire_bytes: 84,
    };
    assert_eq!(
        receiver.poll_data(time(1), &mut output, &mut allowance)?,
        None
    );
    assert_eq!(
        allowance,
        OutboundBudget {
            packets: 1,
            wire_bytes: 84
        }
    );
    let length = receiver
        .poll_feedback(time(1), &mut output, &mut allowance)?
        .ok_or("missing ACK")?;
    assert_eq!(
        receiver.inspect_output(&output[..length])?,
        RecordKind::Feedback
    );
    assert_eq!(
        sender.inspect_peer(&output[..length])?,
        RecordKind::Feedback
    );
    assert_eq!(allowance, OutboundBudget::default());
    sender.receive(&output[..length], time(1))?;
    assert!(sender.drained());
    let mut wrong_kind = output[..length].to_vec();
    wrong_kind[5] = 1;
    assert_eq!(receiver.inspect_output(&wrong_kind), Err(Error::Malformed));
    for length in 0..packets[0].len() {
        assert!(sender.inspect_output(&packets[0][..length]).is_err());
        assert!(receiver.inspect_peer(&packets[0][..length]).is_err());
    }
    Ok(())
}

#[test]
fn reconstruction_headroom_rejection_does_not_mutate_decoder_or_staging() -> TestResult {
    let (mut sender, mut receiver) = endpoints()?;
    submit_all(&mut sender, &sources())?;
    let packets = emissions(&mut sender, 0)?;
    for identity in 8..22 {
        receiver.receive(&direct_packet(identity)?, time(0))?;
    }
    assert_eq!(receiver.storage().restored_packets, 14);
    let before = receiver.storage();
    let statistics = receiver.statistics();
    assert_eq!(
        receiver.receive(&packets[3], time(0)),
        Err(Error::RestoredCapacity)
    );
    assert_eq!(receiver.storage(), before);
    assert_eq!(receiver.statistics(), statistics);
    assert!(receiver.failure().is_none());
    Ok(())
}

#[test]
fn generation_exhaustion_is_explicit_and_never_reuses_a_context_identity() -> TestResult {
    let (mut sender, _) = endpoints()?;
    sender.next_generation = Some(fec::GenerationId(u64::MAX));
    submit_all(&mut sender, &sources())?;
    let packets = emissions(&mut sender, 0)?;
    assert_eq!(packets.len(), 5);
    for packet in packets {
        let view = fec::inspect(
            &packet[ENVELOPE_BYTES..],
            sender.send_fec,
            config().fec.block,
        )?;
        assert_eq!(view.generation, fec::GenerationId(u64::MAX));
    }
    let before = sender.storage();
    assert_eq!(
        sender.submit(b"cannot reuse", time(1)),
        Err(Error::Exhausted)
    );
    assert_eq!(sender.storage(), before);
    let retry = emit(&mut sender, 100)?.ok_or("last generation retry is still serviceable")?;
    assert_eq!(sender.inspect_output(&retry)?, RecordKind::Source);
    Ok(())
}

#[path = "diagnostics_tests.rs"]
mod block_diagnostics;

/// A legacy direction with small sources against a wide (above 64 records)
/// direction: local output must fit the wide ACK for the receive direction,
/// and the peer must parse it with its own wide send configuration.
#[test]
fn asymmetric_wide_receive_direction_fits_and_parses_wide_acks() -> TestResult {
    let legacy = ReliableConfig {
        repair_symbols: 0,
        ..config()
    };
    let base = config();
    let wide = ReliableConfig {
        arq: ArqConfig {
            send_records: 1024,
            receive_records: 1024,
            send_bytes: 1024 * 64,
            receive_bytes: 1024 * 64,
            ..base.arq
        },
        repair_symbols: 0,
        max_restored_packets: 1040,
        max_restored_bytes: 1040 * 108,
        ..base
    };
    assert!(!legacy.arq.wide_feedback() && wide.arq.wide_feedback());
    let legacy_source = DATA_HEADER_BYTES + legacy.arq.max_source_bytes;
    assert!(wide.arq.ack_packet_bytes() > legacy_source);
    for reserved in [false, true] {
        let make = |send, receive, role| -> Result<Reliable, Box<dyn std::error::Error>> {
            Ok(if reserved {
                let plan = storage::Plan::for_duplex(send, receive)?;
                Reliable::new_duplex_reserved(
                    send,
                    receive,
                    context(role),
                    storage::Limits {
                        capacity_bytes: plan.capacity_bytes(),
                    },
                )?
            } else {
                Reliable::new_duplex(send, receive, context(role))?
            })
        };
        // The initiator receives the wide direction and sends the legacy one.
        let mut initiator = make(legacy, wide, EndpointRole::Initiator)?;
        let mut responder = make(wide, legacy, EndpointRole::Responder)?;
        assert!(initiator.send_max_packet_bytes() >= ENVELOPE_BYTES + wide.arq.ack_packet_bytes());
        let total = 600_u64;
        let mut submitted = 0;
        let mut delivered = 0_u64;
        let mut largest_feedback = 0;
        let mut emitted = 0_u64;
        for tick in 0..4_000 {
            while submitted < total
                && responder
                    .submit(&[(submitted % 251) as u8; 8], time(tick))
                    .is_ok()
            {
                submitted += 1;
            }
            while let Some(packet) = emit(&mut responder, tick)? {
                emitted += 1;
                // Drop some early sources so feedback carries a real bitmap.
                if tick < 50 && emitted.is_multiple_of(9) {
                    continue;
                }
                initiator.receive(&packet, time(tick))?;
            }
            while let Some(packet) = emit(&mut initiator, tick)? {
                if initiator.inspect_output(&packet)? == RecordKind::Feedback {
                    largest_feedback = largest_feedback.max(packet.len());
                }
                responder.receive(&packet, time(tick))?;
            }
            for (identity, payload) in deliveries(&mut initiator)? {
                assert_eq!(identity, delivered);
                assert_eq!(payload, vec![(delivered % 251) as u8; 8]);
                delivered += 1;
            }
            if delivered == total && responder.drained() {
                break;
            }
        }
        assert_eq!(delivered, total, "reserved={reserved}");
        assert!(responder.drained());
        // At least one wide ACK was larger than the 48-byte legacy form.
        assert!(
            largest_feedback > ENVELOPE_BYTES + ACK_PACKET_BYTES,
            "{largest_feedback}"
        );
    }
    Ok(())
}
