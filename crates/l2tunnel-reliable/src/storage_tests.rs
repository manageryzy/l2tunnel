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
