//! Actual encoded sources exercise optional retry enrichment without changing wire limits.
use super::*;

fn long_policy() -> ReliableConfig {
    let mut policy = config();
    policy.fec.max_lifetime_ticks = 10_000;
    policy
}
fn pair(
    selected: bool,
    reserved: bool,
    policy: ReliableConfig,
) -> Result<(Reliable, Reliable), Box<dyn std::error::Error>> {
    let mut sender = physical::owner(policy, EndpointRole::Initiator, reserved)?;
    let mut receiver = physical::owner(policy, EndpointRole::Responder, reserved)?;
    sender.enable_physical_send_confirmation()?;
    receiver.enable_physical_send_confirmation()?;
    if selected {
        sender.enable_compact_wire_with_overheads(37, 49)?;
        receiver.enable_compact_wire_with_overheads(37, 49)?;
    }
    Ok((sender, receiver))
}
fn data(owner: &mut Reliable, tick: u64) -> Result<Vec<Vec<u8>>, Error> {
    let mut packets = Vec::new();
    let mut output = vec![0; owner.max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 64,
        wire_bytes: 1_000_000,
    };
    for _ in 0..64 {
        let Some(length) = owner.poll_data(time(tick), &mut output, &mut budget)? else {
            return Ok(packets);
        };
        packets.push(output[..length].to_vec());
        if let Some(token) = owner.pending_output() {
            owner.confirm_output(time(tick), token)?;
        }
    }
    Err(Error::Exhausted)
}
fn rank(owner: &Reliable) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(owner
        .decoder
        .as_ref()
        .ok_or("decoder")?
        .buffer_snapshot()
        .basis_rows)
}
fn original_records(sender: &Reliable, packets: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, Error> {
    packets
        .iter()
        .take(3)
        .map(|packet| {
            Ok(sender
                .inspect_output_record(packet)?
                .fec
                .ok_or(Error::Malformed)?
                .original_source()?
                .to_vec())
        })
        .collect()
}
fn encoder(
    sender: &Reliable,
    generation: u64,
    records: &[Vec<u8>],
) -> Result<fec::BlockEncoder, fec::Error> {
    let sources: Vec<_> = records.iter().map(Vec::as_slice).collect();
    fec::BlockEncoder::new(
        sender.send_fec,
        fec::GenerationId(generation),
        long_policy().fec.block,
        &sources,
    )
}

#[test]
fn retry_enrichment_completes_original_generation_before_expiry_and_reuses_slot() -> TestResult {
    for selected in [false, true] {
        for reserved in [false, true] {
            let mut policy = long_policy();
            policy.fec.max_generations = 1;
            let (mut sender, mut receiver) = pair(selected, reserved, policy)?;
            let input = sources();
            submit_all(&mut sender, &input)?;
            let packets = data(&mut sender, 0)?;
            receiver.receive(&packets[2], time(0))?;
            let usage = receiver.storage_usage();
            assert_eq!(rank(&receiver)?, 1);
            assert_eq!(receiver.expiry_deadline(), Some(time(10_000)));
            let retries = data(&mut sender, 100)?;
            assert_eq!(retries.len(), 3);
            let before = receiver.arq_statistics();
            receiver.receive(&retries[0], time(100))?;
            assert_eq!(receiver.arq_statistics().duplicates, before.duplicates);
            assert_eq!(rank(&receiver)?, 2);
            assert_eq!(receiver.expiry_deadline(), Some(time(10_000)));
            receiver.receive(&retries[1], time(100))?;
            assert_eq!(
                receiver
                    .decoder
                    .as_ref()
                    .ok_or("decoder")?
                    .generation_count(),
                0
            );
            assert_eq!(receiver.expiry_deadline(), None);
            assert_eq!(receiver.statistics().expired_generations, 0);
            assert_eq!(receiver.statistics().decoded_source_vectors, 3);
            assert_eq!(receiver.statistics().repaired_unique_sources, 0);
            assert_eq!(deliveries(&mut receiver)?, indexed(&input));
            let before = receiver.arq_statistics().received_unique;
            receiver.receive(&packets[3], time(101))?;
            receiver.receive(&retries[1], time(101))?;
            assert_eq!(receiver.arq_statistics().received_unique, before);
            assert!(deliveries(&mut receiver)?.is_empty());
            for source in &input {
                sender.submit(source, time(101))?;
            }
            let next = data(&mut sender, 101)?;
            receiver.receive(next.first().ok_or("next generation")?, time(101))?;
            assert_eq!(
                receiver
                    .decoder
                    .as_ref()
                    .ok_or("decoder")?
                    .generation_count(),
                1
            );
            assert_eq!(receiver.expiry_deadline(), Some(time(10_101)));
            assert_eq!(receiver.storage_usage(), usage);
        }
    }
    Ok(())
}

#[test]
fn retry_enrichment_keeps_original_expiry_and_skips_repair_only_or_ambiguous_mapping() -> TestResult
{
    for reserved in [false, true] {
        let (mut sender, mut receiver) = pair(false, reserved, long_policy())?;
        submit_all(&mut sender, &sources())?;
        let packets = data(&mut sender, 0)?;
        let records = original_records(&sender, &packets)?;
        receiver.receive(&packets[3], time(0))?;
        let retries = data(&mut sender, 100)?;
        receiver.receive(&retries[0], time(100))?;
        assert_eq!(rank(&receiver)?, 1);
        assert_eq!(receiver.fec_deadlines.retry_generation(0), None);
        receiver.receive(&packets[2], time(101))?;
        assert!(receiver.fec_deadlines.retry_generation(0).is_some());
        let other = encoder(&sender, 1, &records)?;
        receiver.receive(
            &wrap(3, &other.systematic(fec::SourceId(2))?.bytes),
            time(102),
        )?;
        let before = rank(&receiver)?;
        assert_eq!(receiver.fec_deadlines.retry_generation(1), None);
        receiver.receive(&retries[1], time(103))?;
        assert_eq!(rank(&receiver)?, before);
        assert_eq!(receiver.expiry_deadline(), Some(time(10_000)));
        receiver.receive(&retries[1], time(10_000))?;
        assert_eq!(receiver.statistics().expired_generations, 1);
        assert_eq!(receiver.expiry_deadline(), Some(time(10_102)));
        // The remaining candidate can now accept the retry but retains its own deadline.
        assert_eq!(
            receiver
                .decoder
                .as_ref()
                .ok_or("decoder")?
                .generation_count(),
            1
        );
    }
    Ok(())
}

#[test]
fn retry_enrichment_does_not_turn_staging_or_symbol_pressure_into_direct_refusal() -> TestResult {
    for reserved in [false, true] {
        let (mut sender, mut receiver) = pair(false, reserved, long_policy())?;
        submit_all(&mut sender, &sources())?;
        let packets = data(&mut sender, 0)?;
        receiver.receive(&packets[2], time(0))?;
        // A separate actual sender supplies canonical future records to fill the
        // bounded staging owner. Its wider policy is a hostile-input fixture,
        // not a claim of a negotiated deployment or valid sender-window parity.
        let mut wide = long_policy();
        wide.repair_symbols = 0;
        wide.arq.send_records = 32;
        wide.arq.receive_records = 32;
        wide.arq.send_bytes = 2048;
        wide.arq.receive_bytes = 2048;
        wide.max_restored_packets = 35;
        wide.max_restored_bytes = 4096;
        let (mut future, _) = pair(false, reserved, wide)?;
        for source in 0..22 {
            future.submit(&[source], time(0))?;
        }
        let future_packets = data(&mut future, 0)?;
        for packet in &future_packets[8..22] {
            receiver.receive(packet, time(1))?;
        }
        assert_eq!(receiver.restored.len(), 14);
        let retries = data(&mut sender, 100)?;
        receiver.receive(&retries[0], time(100))?;
        assert_eq!(rank(&receiver)?, 1);
        assert_eq!(receiver.arq_statistics().received_unique, 2);
        assert_eq!(receiver.failure(), None);
        assert_eq!(receiver.restored.len(), 14);
        assert_eq!(receiver.expiry_deadline(), Some(time(10_000)));

        let (mut sender, mut receiver) = pair(false, reserved, long_policy())?;
        submit_all(&mut sender, &sources())?;
        let packets = data(&mut sender, 0)?;
        let records = original_records(&sender, &packets)?;
        receiver.receive(&packets[2], time(0))?;
        let mut coding = encoder(&sender, 0, &records)?;
        for _ in 0..5 {
            receiver.receive(&wrap(3, &coding.repair(&[0, 0, 1])?.bytes), time(1))?;
        }
        let skipped = receiver.statistics().skipped_fec_packets;
        let retries = data(&mut sender, 100)?;
        receiver.receive(&retries[0], time(100))?;
        assert_eq!(receiver.statistics().skipped_fec_packets, skipped);
        assert_eq!(rank(&receiver)?, 1);
        assert_eq!(receiver.arq_statistics().received_unique, 2);
        assert_eq!(receiver.failure(), None);
        assert_eq!(receiver.expiry_deadline(), Some(time(10_000)));
    }
    Ok(())
}

#[test]
fn retry_enrichment_preserves_conflicting_equations_and_rejects_inconsistent_source_base()
-> TestResult {
    for reserved in [false, true] {
        let (mut sender, mut receiver) = pair(false, reserved, long_policy())?;
        submit_all(&mut sender, &sources())?;
        let packets = data(&mut sender, 0)?;
        let mut records = original_records(&sender, &packets)?;
        receiver.receive(&packets[0], time(0))?;
        *records[1].last_mut().ok_or("nonempty record")? ^= 1;
        let mut inconsistent = encoder(&sender, 0, &records)?;
        receiver.receive(&wrap(3, &inconsistent.repair(&[1, 1, 0])?.bytes), time(1))?;
        assert_eq!(rank(&receiver)?, 2);
        let scratch_capacity = receiver.scratch.capacity();
        let retries = data(&mut sender, 100)?;
        assert!(matches!(
            receiver.receive(&retries[1], time(100)),
            Err(Error::Fec(_))
        ));
        assert_eq!(rank(&receiver)?, 2);
        assert_eq!(receiver.scratch.capacity(), scratch_capacity);
        assert_eq!(receiver.statistics().decoded_source_vectors, 0);
        assert_eq!(receiver.statistics().expired_generations, 0);

        let (mut sender, mut receiver) = pair(false, reserved, long_policy())?;
        submit_all(&mut sender, &sources())?;
        let packets = data(&mut sender, 0)?;
        let mut records = original_records(&sender, &packets)?;
        records.swap(1, 2);
        let reordered = encoder(&sender, 0, &records)?;
        receiver.receive(
            &wrap(3, &reordered.systematic(fec::SourceId(0))?.bytes),
            time(0),
        )?;
        assert_eq!(
            receiver.receive(
                &wrap(3, &reordered.systematic(fec::SourceId(1))?.bytes),
                time(1)
            ),
            Err(Error::SourceConflict)
        );
        assert_eq!(receiver.arq_statistics().received_unique, 1);
        assert_eq!(receiver.statistics().decoded_source_vectors, 0);
    }
    Ok(())
}

#[test]
fn retry_enrichment_completion_keeps_direct_source_blocked_in_original_restored_custody()
-> TestResult {
    for selected in [false, true] {
        for reserved in [false, true] {
            let policy = long_policy();
            let (_, mut receiver) = pair(selected, reserved, policy)?;
            let mut wide = policy;
            wide.arq.send_records = 16;
            wide.arq.receive_records = 16;
            wide.arq.send_bytes = 1024;
            wide.arq.receive_bytes = 1024;
            wide.max_restored_packets = 19;
            wide.max_restored_bytes = 4096;
            let (mut sender, _) = pair(selected, reserved, wide)?;
            let input: Vec<_> = (0..12).map(|id| vec![id]).collect();
            submit_all(&mut sender, &input)?;
            let packets = data(&mut sender, 0)?;
            // The fourth actual generation lies beyond this receiver's original
            // ARQ delivery window. This intentionally exercises bounded custody.
            receiver.receive(&packets[15], time(0))?;
            assert_eq!(receiver.restored.len(), 1);
            assert_eq!(receiver.arq_statistics().received_unique, 0);
            let retries = data(&mut sender, 100)?;
            receiver.receive(&retries[10], time(100))?;
            assert_eq!(receiver.restored.len(), 2);
            assert_eq!(rank(&receiver)?, 2);
            receiver.receive(&retries[11], time(100))?;
            assert_eq!(receiver.restored.len(), 3);
            assert_eq!(
                receiver
                    .decoder
                    .as_ref()
                    .ok_or("decoder")?
                    .generation_count(),
                0
            );
            assert_eq!(receiver.arq_statistics().received_unique, 0);
            assert_eq!(receiver.statistics().decoded_source_vectors, 3);
            let mut delivered = Vec::new();
            for packet in &retries[..9] {
                receiver.receive(packet, time(101))?;
                delivered.extend(deliveries(&mut receiver)?);
            }
            assert_eq!(delivered, indexed(&input));
            assert!(receiver.restored.is_empty());
            assert_eq!(receiver.arq_statistics().received_unique, 12);
        }
    }
    Ok(())
}
