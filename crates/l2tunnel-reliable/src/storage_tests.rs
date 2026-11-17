use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x8765,
        epoch: 19,
        role,
    }
}
fn policy(bytes: usize, count: usize, repairs: usize, overhead: usize) -> ReliableConfig {
    let source = DATA_HEADER_BYTES + bytes;
    ReliableConfig {
        arq: ArqConfig {
            max_source_bytes: bytes,
            send_bytes: 4 * bytes,
            receive_bytes: 6 * bytes,
            send_records: 4,
            receive_records: 6,
            initial_rto: ms(100),
            maximum_rto: ms(800),
            ack_delay: ms(2),
            max_retries: 3,
        },
        fec: fec::DecoderConfig {
            block: fec::BlockConfig {
                max_sources: count,
                max_source_bytes: source,
                max_packet_bytes: fec::HEADER_BYTES + count + 2 + source,
                max_work_per_symbol: 1_000_000,
            },
            max_generations: 2,
            max_symbols_per_generation: count + repairs,
            max_reserved_bytes: 1_000_000,
            max_lifetime_ticks: 50,
            generation_window: 8,
        },
        repair_symbols: repairs,
        flush_after: ms(5),
        max_restored_packets: 16,
        max_restored_bytes: 16 * source,
        outer_overhead_bytes: overhead,
    }
}
fn make(
    send: ReliableConfig,
    receive: ReliableConfig,
    role: EndpointRole,
    reserved: bool,
) -> Result<Reliable, Box<dyn std::error::Error>> {
    Ok(if reserved {
        let p = storage::Plan::for_duplex(send, receive)?;
        Reliable::new_duplex_reserved(
            send,
            receive,
            context(role),
            storage::Limits {
                capacity_bytes: p.capacity_bytes(),
            },
        )?
    } else {
        Reliable::new_duplex(send, receive, context(role))?
    })
}
fn packets(e: &mut Reliable, now: Duration, feedback: bool) -> Result<Vec<Vec<u8>>, Error> {
    let mut result = Vec::new();
    let mut output = vec![0; e.send_max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 32,
        wire_bytes: 1_000_000,
    };
    for _ in 0..32 {
        let next = if feedback {
            e.poll_feedback(now, &mut output, &mut budget)?
        } else {
            e.poll_data(now, &mut output, &mut budget)?
        };
        let Some(n) = next else {
            return Ok(result);
        };
        result.push(output[..n].to_vec());
    }
    Err(Error::Exhausted)
}
fn delivered(e: &mut Reliable) -> Result<Vec<(u64, Vec<u8>)>, Error> {
    let mut result = Vec::new();
    let mut output = [0; 128];
    while let Some((id, n)) = e.poll_delivered(&mut output)? {
        result.push((id, output[..n].to_vec()));
    }
    Ok(result)
}

#[test]
fn complete_nested_plan_matches_actual_capacity_and_refuses_one_short() -> TestResult {
    let a = policy(32, 2, 1, 17);
    let b = policy(96, 3, 2, 73);
    let p = storage::Plan::for_duplex(a, b)?;
    assert_eq!(p.send_config(), a);
    assert_eq!(p.receive_config(), b);
    assert!(matches!(
        Reliable::new_duplex_reserved(
            a,
            b,
            context(EndpointRole::Initiator),
            storage::Limits {
                capacity_bytes: p.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    let e = make(a, b, EndpointRole::Initiator, true)?;
    assert_eq!(a.maximum_packet_bytes()?, e.send_max_packet_bytes());
    assert_eq!(b.maximum_packet_bytes()?, e.receive_max_packet_bytes());
    assert_eq!(
        a.maximum_packet_bytes()?,
        ENVELOPE_BYTES
            + fec::HEADER_BYTES
            + a.fec.block.max_sources
            + DATA_HEADER_BYTES
            + a.arq.max_source_bytes
            + 2
    );
    let actual = e.storage_usage().ok_or("usage")?;
    assert_eq!(actual.capacity_bytes, p.capacity_bytes());
    assert_eq!(actual.limit_bytes, p.capacity_bytes());
    let nested = e.arq.storage_usage().ok_or("ARQ usage")?.capacity_bytes
        + e.decoder
            .as_ref()
            .ok_or("decoder")?
            .storage_usage()
            .ok_or("decoder usage")?
            .capacity_bytes
        + e.encoder
            .as_ref()
            .ok_or("encoder")?
            .storage_usage()
            .ok_or("encoder usage")?
            .capacity_bytes;
    assert!(actual.capacity_bytes > nested);
    assert_eq!(
        make(a, b, EndpointRole::Initiator, false)?.storage_usage(),
        None
    );
    let mut bad = a;
    bad.arq.max_source_bytes = 0;
    assert!(matches!(
        Reliable::new_duplex_reserved(
            bad,
            b,
            context(EndpointRole::Initiator),
            storage::Limits { capacity_bytes: 0 }
        ),
        Err(storage::Error::Reliable(Error::Arq(
            RecoveryError::InvalidConfig
        )))
    ));
    assert!(Reliable::legacy_inline_bytes() > 0);
    Ok(())
}

#[test]
fn arq_only_emits_immediately_and_recovers_original_ids_without_coding_storage() -> TestResult {
    let c = policy(32, 2, 0, 17);
    for reserved in [false, true] {
        let mut left = make(c, c, EndpointRole::Initiator, reserved)?;
        let mut right = make(c, c, EndpointRole::Responder, reserved)?;
        assert!(left.encoder.is_none() && left.decoder.is_none());
        let maximum = ENVELOPE_BYTES + DATA_HEADER_BYTES + 32;
        assert_eq!(left.send_max_packet_bytes(), maximum);
        let originals = [b"first\0source".to_vec(), vec![0x72; 32]];
        for (id, bytes) in originals.iter().enumerate() {
            assert_eq!(left.submit(bytes, ms(0))?, id as u64);
        }
        let mut output = vec![0xa5; maximum];
        let mut blocked = OutboundBudget {
            packets: 1,
            wire_bytes: maximum + 16,
        };
        let before = left.arq_statistics();
        assert_eq!(left.poll_data(ms(0), &mut output, &mut blocked)?, None);
        assert!(output.iter().all(|byte| *byte == 0xa5));
        assert_eq!(left.arq_statistics(), before);
        let first = packets(&mut left, ms(0), false)?;
        assert_eq!(
            first.len(),
            2,
            "no partial-block deadline may delay ARQ-only sources"
        );
        for (id, bytes) in first.iter().enumerate() {
            assert_eq!(left.inspect_output(bytes)?, RecordKind::Source);
            let view =
                inspect_structural(bytes, EndpointRole::Initiator, maximum, 32, c.fec.block)?;
            assert_eq!(view.source.ok_or("source")?.0.0, id as u64);
            assert!(view.fec.is_none());
        }
        // Lose the first source; receiving a later source never acknowledges the gap.
        right.receive(&first[1], ms(1))?;
        assert!(delivered(&mut right)?.is_empty());
        let receipt = packets(&mut right, ms(3), true)?;
        assert_eq!(receipt.len(), 1);
        left.receive(&receipt[0], ms(3))?;
        assert_eq!(left.storage().arq.send_records, 1);
        assert!(packets(&mut left, ms(99), false)?.is_empty());
        let retry = packets(&mut left, ms(100), false)?;
        assert_eq!(retry, vec![first[0].clone()]);
        right.receive(&retry[0], ms(101))?;
        right.receive(&first[1], ms(101))?;
        assert_eq!(
            delivered(&mut right)?,
            vec![(0, originals[0].clone()), (1, originals[1].clone())]
        );
        let receipt = packets(&mut right, ms(103), true)?;
        assert_eq!(receipt.len(), 1);
        left.receive(&receipt[0], ms(103))?;
        assert!(left.drained() && right.drained());
        let stats = left.statistics();
        assert_eq!((stats.source_packets, stats.retry_packets), (2, 1));
        assert_eq!((stats.systematic_packets, stats.repair_packets), (0, 0));
        assert_eq!(
            stats.emitted_wire_bytes,
            first
                .iter()
                .chain(&retry)
                .map(|p| (p.len() + 17) as u64)
                .sum::<u64>()
        );
        let held = left.storage();
        assert_eq!(
            (
                held.building_packets,
                held.outbound_packets,
                held.fec_reserved_bytes
            ),
            (0, 0, 0)
        );
    }
    Ok(())
}

#[test]
fn arq_only_reserved_plan_is_exact_and_mixed_direction_keeps_real_fec() -> TestResult {
    let a = policy(32, 2, 0, 17);
    let b = policy(96, 3, 2, 73);
    let zero = storage::Plan::for_duplex(a, a)?;
    let mut coded = a;
    coded.repair_symbols = 1;
    coded.fec.max_symbols_per_generation += 1;
    assert!(zero.capacity_bytes() < storage::Plan::for_duplex(coded, coded)?.capacity_bytes());
    assert!(zero.encoder.is_none() && zero.decoder.is_none());
    assert!(matches!(
        Reliable::new_duplex_reserved(
            a,
            a,
            context(EndpointRole::Initiator),
            storage::Limits {
                capacity_bytes: zero.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    let endpoint = make(a, a, EndpointRole::Initiator, true)?;
    assert_eq!(
        endpoint.storage_usage().ok_or("usage")?.capacity_bytes,
        zero.capacity_bytes()
    );
    let mut left = make(a, b, EndpointRole::Initiator, true)?;
    let mut right = make(b, a, EndpointRole::Responder, true)?;
    assert!(left.encoder.is_none() && left.decoder.is_some());
    assert!(right.encoder.is_some() && right.decoder.is_none());
    left.submit(b"uncoded", ms(0))?;
    let p = packets(&mut left, ms(0), false)?;
    assert_eq!(p.len(), 1);
    right.receive(&p[0], ms(1))?;
    assert_eq!(delivered(&mut right)?, vec![(0, b"uncoded".to_vec())]);
    for bytes in [vec![7; 96], vec![0; 11], vec![9; 45]] {
        right.submit(&bytes, ms(1))?;
    }
    let p = packets(&mut right, ms(1), false)?;
    assert_eq!(p.len(), 5);
    for bytes in p.iter().skip(1) {
        left.receive(bytes, ms(2))?;
    }
    assert_eq!(
        delivered(&mut left)?,
        vec![(0, vec![7; 96]), (1, vec![0; 11]), (2, vec![9; 45])]
    );
    assert_eq!(left.statistics().repaired_unique_sources, 1);
    Ok(())
}

#[test]
fn arq_only_rejects_coding_records_and_retains_retry_exhaustion() -> TestResult {
    let c = policy(128, 2, 0, 17);
    let mut coded = c;
    coded.repair_symbols = 1;
    coded.fec.max_symbols_per_generation += 1;
    let mut sender = make(coded, coded, EndpointRole::Initiator, true)?;
    sender.submit(b"short", ms(0))?;
    assert!(packets(&mut sender, ms(0), false)?.is_empty());
    let p = packets(&mut sender, ms(5), false)?;
    let mut receiver = make(c, c, EndpointRole::Responder, true)?;
    assert!(p[0].len() < receiver.receive_max_packet_bytes());
    assert_eq!(receiver.inspect_peer(&p[0]), Err(Error::Malformed));
    let before = receiver.storage();
    assert_eq!(receiver.receive(&p[0], ms(6)), Err(Error::Malformed));
    assert_eq!(receiver.storage(), before);
    let mut sender = make(c, c, EndpointRole::Initiator, true)?;
    sender.submit(b"never acknowledged", ms(0))?;
    assert_eq!(packets(&mut sender, ms(0), false)?.len(), 1);
    for now in [100, 300, 700] {
        assert_eq!(packets(&mut sender, ms(now), false)?.len(), 1);
    }
    assert!(packets(&mut sender, ms(1500), false).is_err());
    assert!(sender.failure().is_some());
    assert_eq!(sender.storage().arq.send_records, 1);
    Ok(())
}

#[test]
fn every_wrapper_reservation_failure_leaves_existing_owner_unchanged() -> TestResult {
    let c = policy(32, 2, 1, 17);
    let p = storage::Plan::for_duplex(c, c)?;
    let mut old = make(c, c, EndpointRole::Initiator, true)?;
    old.submit(b"retained old source", ms(0))?;
    let before = (
        old.storage(),
        old.arq_statistics(),
        old.next_source_id()?,
        old.storage_usage(),
    );
    let mut a = storage::Allocation::new(p.capacity_bytes());
    let created = Reliable::reserved_with(c, c, context(EndpointRole::Responder), p, &mut a)?;
    let count = a.usage().allocations;
    drop(created);
    for fail in 1..=count {
        let mut a = storage::Allocation::failing(p.capacity_bytes(), fail);
        assert!(matches!(
            Reliable::reserved_with(c, c, context(EndpointRole::Responder), p, &mut a),
            Err(storage::Error::Allocation)
        ));
        assert_eq!(
            (
                old.storage(),
                old.arq_statistics(),
                old.next_source_id()?,
                old.storage_usage()
            ),
            before
        );
    }
    assert!(make(c, c, EndpointRole::Responder, true)?.drained());
    Ok(())
}

#[test]
fn asymmetric_reserved_and_legacy_traces_match_real_loss_repair_and_feedback() -> TestResult {
    let a = policy(32, 2, 1, 17);
    let b = policy(96, 3, 2, 73);
    let mut old_left = make(a, b, EndpointRole::Initiator, false)?;
    let mut left = make(a, b, EndpointRole::Initiator, true)?;
    let mut old_right = make(b, a, EndpointRole::Responder, false)?;
    let mut right = make(b, a, EndpointRole::Responder, true)?;
    let left_usage = left.storage_usage();
    let right_usage = right.storage_usage();
    for round in 0..12u64 {
        let start = round * 10;
        let at = ms(start + 5);
        for bytes in [b"left-one".as_slice(), b"left-two".as_slice()] {
            assert_eq!(
                old_left.submit(bytes, ms(start))?,
                left.submit(bytes, ms(start))?
            );
        }
        for bytes in [
            b"right-one".as_slice(),
            b"right-two".as_slice(),
            b"right-three".as_slice(),
        ] {
            assert_eq!(
                old_right.submit(bytes, ms(start))?,
                right.submit(bytes, ms(start))?
            );
        }
        let forward = packets(&mut left, at, false)?;
        assert_eq!(forward, packets(&mut old_left, at, false)?);
        let reverse = packets(&mut right, at, false)?;
        assert_eq!(reverse, packets(&mut old_right, at, false)?);
        assert_eq!(forward.len(), 3);
        assert_eq!(reverse.len(), 5);
        // Lose the first systematic; reverse the remaining real equations.
        for packet in forward.iter().skip(1).rev() {
            assert_eq!(old_right.receive(packet, at), right.receive(packet, at));
        }
        for packet in reverse.iter().skip(1).rev() {
            assert_eq!(old_left.receive(packet, at), left.receive(packet, at));
        }
        let got_left = delivered(&mut left)?;
        let got_right = delivered(&mut right)?;
        assert_eq!(delivered(&mut old_left)?, got_left);
        assert_eq!(delivered(&mut old_right)?, got_right);
        assert_eq!(
            got_left,
            vec![
                (round * 3, b"right-one".to_vec()),
                (round * 3 + 1, b"right-two".to_vec()),
                (round * 3 + 2, b"right-three".to_vec())
            ]
        );
        assert_eq!(
            got_right,
            vec![
                (round * 2, b"left-one".to_vec()),
                (round * 2 + 1, b"left-two".to_vec())
            ]
        );
        let at = ms(start + 7);
        let ack_left = packets(&mut left, at, true)?;
        assert_eq!(ack_left, packets(&mut old_left, at, true)?);
        let ack_right = packets(&mut right, at, true)?;
        assert_eq!(ack_right, packets(&mut old_right, at, true)?);
        for packet in ack_left {
            assert_eq!(old_right.receive(&packet, at), right.receive(&packet, at));
        }
        for packet in ack_right {
            assert_eq!(old_left.receive(&packet, at), left.receive(&packet, at));
        }
        assert_eq!(old_left.statistics(), left.statistics());
        assert_eq!(old_right.statistics(), right.statistics());
        assert_eq!(old_left.storage(), left.storage());
        assert_eq!(old_right.storage(), right.storage());
        assert!(left.drained());
        assert!(right.drained());
        assert_eq!(left.storage_usage(), left_usage);
        assert_eq!(right.storage_usage(), right_usage);
    }
    assert!(left.statistics().repaired_unique_sources > 0);
    assert!(right.statistics().repaired_unique_sources > 0);
    Ok(())
}

#[test]
fn reserved_output_refusal_partial_flush_retry_and_expiry_preserve_original_bounds() -> TestResult {
    let c = policy(32, 2, 1, 17);
    let mut old = make(c, c, EndpointRole::Initiator, false)?;
    let mut new = make(c, c, EndpointRole::Initiator, true)?;
    old.submit(b"partial", ms(0))?;
    new.submit(b"partial", ms(0))?;
    let mut output = vec![0xa5; c.maximum_packet()?];
    let before = output.clone();
    let mut budget = OutboundBudget {
        packets: 10,
        wire_bytes: 100_000,
    };
    assert_eq!(
        new.poll_data(ms(0), &mut output[..1], &mut budget),
        Err(Error::OutputTooSmall {
            required: new.send_max_packet_bytes()
        })
    );
    assert_eq!(output, before);
    assert_eq!(new.storage(), old.storage());
    assert_eq!(
        packets(&mut old, ms(0), false)?,
        packets(&mut new, ms(0), false)?
    );
    assert_eq!(
        packets(&mut old, ms(4), false)?,
        packets(&mut new, ms(4), false)?
    );
    assert_eq!(
        packets(&mut old, ms(5), false)?,
        packets(&mut new, ms(5), false)?
    );
    let retry = packets(&mut new, ms(100), false)?;
    assert_eq!(retry, packets(&mut old, ms(100), false)?);
    assert_eq!(
        new.inspect_output(retry.first().ok_or("retry")?)?,
        RecordKind::Source
    );
    let receiver = make(c, c, EndpointRole::Responder, true)?;
    assert!(receiver.storage_usage().is_some());
    Ok(())
}

#[test]
fn operational_block_capacities_match_lazy_and_reserved_in_both_directions() -> TestResult {
    for (send_repairs, receive_repairs) in [(0, 0), (0, 1), (1, 0), (1, 2)] {
        let send = policy(32, 2, send_repairs, 17);
        let receive = policy(96, 3, receive_repairs, 73);
        let mut lazy = make(send, receive, EndpointRole::Initiator, false)?;
        let mut reserved = make(send, receive, EndpointRole::Initiator, true)?;
        assert!(lazy.storage_usage().is_none());
        assert!(reserved.storage_usage().is_some());
        let expected_sources = if send_repairs == 0 { 0 } else { 2 };
        for at in [0, 5] {
            if at == 0 {
                assert_eq!(lazy.storage(), reserved.storage());
                lazy.submit(b"partial block", ms(at))?;
                reserved.submit(b"partial block", ms(at))?;
            }
            assert_eq!(
                packets(&mut lazy, ms(at), false)?,
                packets(&mut reserved, ms(at), false)?
            );
            assert_eq!(lazy.storage(), reserved.storage());
            for value in [lazy.storage(), reserved.storage()] {
                let block = value.block.ok_or("actual Direct/Block policy")?;
                assert_eq!(block.building_packets_capacity, expected_sources);
                assert_eq!(
                    block.outbound_packets_capacity,
                    expected_sources + send_repairs
                );
                assert_eq!(block.decoder_present, receive_repairs != 0);
                assert_eq!(
                    block.restored_packets_capacity,
                    receive.max_restored_packets
                );
                assert_eq!(block.restored_bytes_capacity, receive.max_restored_bytes);
                assert!(
                    block.decoder.is_none(),
                    "disabled detailed observation stays unavailable"
                );
            }
        }
    }
    Ok(())
}
