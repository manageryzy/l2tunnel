use super::*;
use l2tunnel_recovery::RecoveryEngine;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
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
            max_generations: 4,
            max_symbols_per_generation: count + repairs,
            max_reserved_bytes: 1_000_000,
            max_lifetime_ticks: 50,
            generation_window: 32,
        },
        repair_symbols: repairs,
        flush_after: ms(5),
        max_restored_packets: 16,
        max_restored_bytes: 16 * source,
        outer_overhead_bytes: overhead,
    }
}
fn packets(endpoint: &mut Reliable, now: Duration) -> Result<Vec<Vec<u8>>, Error> {
    let mut budget = OutboundBudget {
        packets: 32,
        wire_bytes: 1_000_000,
    };
    let mut result = Vec::new();
    for _ in 0..32 {
        let mut bytes = vec![0; endpoint.send_max_packet_bytes()];
        let Some(n) = endpoint.poll_data(now, &mut bytes, &mut budget)? else {
            break;
        };
        bytes.truncate(n);
        result.push(bytes);
    }
    Ok(result)
}
fn delivered(endpoint: &mut Reliable) -> Result<Vec<Vec<u8>>, Error> {
    let mut result = Vec::new();
    for _ in 0..16 {
        let mut bytes = vec![0; endpoint.legacy_receive()?.arq.max_source_bytes];
        let Some((id, n)) = endpoint.poll_delivered(&mut bytes)? else {
            break;
        };
        assert_eq!(id, result.len() as u64);
        bytes.truncate(n);
        result.push(bytes);
    }
    Ok(result)
}

#[test]
fn asymmetric_cauchy_restores_real_sources_before_rto_and_charges_local_egress() -> TestResult {
    let a = policy(32, 2, 1, 17);
    let mut b = policy(96, 3, 2, 73);
    b.arq.ack_delay = ms(7);
    b.arq.initial_rto = ms(150);
    b.flush_after = ms(9);
    let mut left = Reliable::new_duplex(a, b, context(EndpointRole::Initiator))?;
    let mut right = Reliable::new_duplex(b, a, context(EndpointRole::Responder))?;
    assert_eq!(
        left.send_max_packet_bytes(),
        right.receive_max_packet_bytes()
    );
    assert_eq!(
        left.receive_max_packet_bytes(),
        right.send_max_packet_bytes()
    );
    assert!(left.send_max_packet_bytes() < left.receive_max_packet_bytes());
    let forward = vec![vec![0, 255, 3, 0], vec![0x5a; 32]];
    let reverse = vec![vec![0x91; 96], vec![0, 1, 2, 3, 255], vec![0x72; 48]];
    for bytes in &forward {
        left.submit(bytes, ms(0))?;
    }
    for bytes in &reverse {
        right.submit(bytes, ms(0))?;
    }
    let sent_a = packets(&mut left, ms(0))?;
    let sent_b = packets(&mut right, ms(0))?;
    assert_eq!(sent_a.len(), 3);
    assert_eq!(sent_b.len(), 5);
    for (sender, peer, sent) in [(&left, &right, &sent_a), (&right, &left, &sent_b)] {
        for bytes in sent {
            assert_eq!(sender.inspect_output(bytes)?, peer.inspect_peer(bytes)?);
        }
        assert_eq!(
            sender.statistics().emitted_wire_bytes,
            sent.iter()
                .map(|bytes| (bytes.len() + sender.outer_overhead()) as u64)
                .sum::<u64>()
        );
    }
    // Drop each first systematic and deliver the remaining real equations backwards.
    for bytes in sent_a.iter().skip(1).rev() {
        right.receive(bytes, ms(1))?;
    }
    for bytes in sent_b.iter().skip(1).rev() {
        left.receive(bytes, ms(1))?;
    }
    assert_eq!(delivered(&mut right)?, forward);
    assert_eq!(delivered(&mut left)?, reverse);
    assert_eq!(left.arq_statistics().retransmissions, 0);
    assert_eq!(right.arq_statistics().retransmissions, 0);
    let mut bytes = vec![0; left.max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1_000,
    };
    assert_eq!(left.poll_feedback(ms(7), &mut bytes, &mut budget)?, None);
    let n = left
        .poll_feedback(ms(8), &mut bytes, &mut budget)?
        .ok_or("reverse receipt")?;
    assert_eq!(budget.wire_bytes, 1_000 - n - a.outer_overhead_bytes);
    right.receive(&bytes[..n], ms(8))?;
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1_000,
    };
    let n = right
        .poll_feedback(ms(8), &mut bytes, &mut budget)?
        .ok_or("forward receipt")?;
    assert_eq!(budget.wire_bytes, 1_000 - n - b.outer_overhead_bytes);
    left.receive(&bytes[..n], ms(8))?;
    assert_eq!(left.storage().arq.send_records, 0);
    assert_eq!(right.storage().arq.send_records, 0);
    Ok(())
}

#[test]
fn direct_source_cannot_borrow_the_larger_opposite_direction_cap() -> TestResult {
    let small = policy(32, 2, 1, 17);
    let large = policy(96, 3, 2, 73);
    let mut local = Reliable::new_duplex(large, small, context(EndpointRole::Initiator))?;
    let mut peer = SelectiveRepeat::new(large.arq, context(EndpointRole::Responder))?;
    peer.submit(&[0x67; 48], ms(0))?;
    let mut bytes = vec![0; peer.max_packet_bytes()];
    let n = peer.poll(ms(0), &mut bytes)?.ok_or("source")?;
    let packet = wrap(1, &bytes[..n]);
    assert!(packet.len() < local.receive_max_packet_bytes());
    let expected = Error::Arq(RecoveryError::SourceTooLarge);
    assert_eq!(local.inspect_peer(&packet), Err(expected));
    assert_eq!(local.failure(), None);
    let before = local.storage();
    assert_eq!(local.receive(&packet, ms(0)), Err(expected));
    assert_eq!(local.storage(), before);
    assert_eq!(local.arq_statistics().received_unique, 0);
    assert_eq!(local.failure(), Some(expected));
    Ok(())
}

#[test]
fn complete_validation_preserves_first_error_before_construction() -> TestResult {
    let good = policy(32, 2, 1, 17);
    let mut bad = good;
    bad.arq.max_source_bytes = 0;
    bad.fec.max_generations = 0;
    assert_eq!(
        bad.validate(),
        Err(Error::Arq(RecoveryError::InvalidConfig))
    );
    assert!(matches!(
        Reliable::new_duplex(bad, good, context(EndpointRole::Initiator)),
        Err(Error::Arq(RecoveryError::InvalidConfig))
    ));
    let mut bad = good;
    bad.fec.max_generations = 0;
    assert_eq!(bad.validate(), Err(Error::Fec(fec::Error::InvalidConfig)));
    assert!(matches!(
        Reliable::new_duplex(good, bad, context(EndpointRole::Initiator)),
        Err(Error::Fec(fec::Error::InvalidConfig))
    ));
    Ok(())
}

#[test]
fn equal_direction_constructor_preserves_emissions_errors_budgets_and_deadlines() -> TestResult {
    let config = policy(32, 2, 1, 17);
    let mut legacy = Reliable::new(config, context(EndpointRole::Initiator))?;
    let mut duplex = Reliable::new_duplex(config, config, context(EndpointRole::Initiator))?;
    for endpoint in [&mut legacy, &mut duplex] {
        assert_eq!(
            endpoint.submit(&[0; 33], ms(0)),
            Err(Error::Arq(RecoveryError::SourceTooLarge))
        );
        endpoint.submit(b"one", ms(0))?;
        endpoint.submit(b"two", ms(0))?;
    }
    for now in [0, 0, 0, 5, 100, 100, 300, 300] {
        let mut a = vec![0xa5; legacy.max_packet_bytes()];
        let mut b = a.clone();
        let mut a_budget = OutboundBudget {
            packets: 1,
            wire_bytes: 1_000,
        };
        let mut b_budget = a_budget;
        assert_eq!(
            legacy.poll(ms(now), &mut a, &mut a_budget),
            duplex.poll(ms(now), &mut b, &mut b_budget)
        );
        assert_eq!(a, b);
        assert_eq!(a_budget, b_budget);
        assert_eq!(legacy.storage(), duplex.storage());
        assert_eq!(legacy.statistics(), duplex.statistics());
        assert_eq!(legacy.arq_statistics(), duplex.arq_statistics());
        assert_eq!(legacy.deadline(), duplex.deadline());
        assert_eq!(legacy.failure(), duplex.failure());
    }
    Ok(())
}
