//! Actual selected R0 ownership, exact geometry and physical feedback races.
use super::*;
use l2tunnel_recovery::{CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn policy(size: usize, mode: CompactRecovery, nominal: u64) -> Result<CompactReliableConfig> {
    Ok(CompactReliableConfig::new(
        CompactArqConfig::new(
            CompactBounds {
                max_source_bytes: size,
                send_bytes: size * 8,
                receive_bytes: size * 8,
                send_records: 8,
                receive_records: 8,
            },
            CompactTiming {
                nominal_rtt: ms(nominal),
                feedback_interval: ms(5),
                feedback_packets: 64,
            },
            77,
            32,
            8,
            mode,
        )?,
        29,
    )?)
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: u128::MAX - 9,
        epoch: u64::MAX - 4,
        role,
    }
}
fn pair() -> Result<(Reliable, Reliable)> {
    let forward = policy(32, CompactRecovery::Guarded, 70)?;
    let reverse = policy(64, CompactRecovery::FirstFlight, 90)?;
    Ok((
        Reliable::new_compact_duplex(forward, reverse, context(EndpointRole::Initiator))?,
        Reliable::new_compact_duplex(reverse, forward, context(EndpointRole::Responder))?,
    ))
}
fn budget() -> OutboundBudget {
    OutboundBudget {
        packets: 10,
        wire_bytes: 100_000,
    }
}

fn assert_compact_descriptor(
    packet: &[u8],
    sender: EndpointRole,
    policy: CompactArqConfig,
) -> Result {
    let peer = match sender {
        EndpointRole::Initiator => EndpointRole::Responder,
        EndpointRole::Responder => EndpointRole::Initiator,
    };
    let inner = &packet[ENVELOPE_BYTES..];
    let descriptor = l2tunnel_recovery::inspect_compact_packet(inner, context(peer), policy)?;
    let mut encoded = vec![0xaa; inner.len()];
    assert_eq!(descriptor.legacy_encoded_len()?, inner.len());
    assert_eq!(
        descriptor.encode_legacy_into(context(sender), policy.recovery(), &mut encoded)?,
        inner.len(),
    );
    assert_eq!(encoded, inner);
    Ok(())
}

#[test]
fn compact_r0_duplex_geometry_budget_and_actual_storage_without_fec() -> Result {
    let forward = policy(32, CompactRecovery::Guarded, 70)?;
    let reverse = policy(64, CompactRecovery::FirstFlight, 90)?;
    let plan = storage::CompactPlan::for_duplex(forward, reverse)?;
    assert_eq!(plan.send_max_packet_bytes(), ENVELOPE_BYTES + 84);
    assert_eq!(plan.receive_max_packet_bytes(), ENVELOPE_BYTES + 116);
    assert!(matches!(
        Reliable::new_compact_duplex_reserved(
            forward,
            reverse,
            context(EndpointRole::Initiator),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    for extra in [0, 1] {
        let endpoint = Reliable::new_compact_duplex_reserved(
            forward,
            reverse,
            context(EndpointRole::Initiator),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes() + extra,
            },
        )?;
        let usage = endpoint.storage_usage().ok_or("actual usage")?;
        assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
        assert_eq!(usage.limit_bytes, plan.capacity_bytes() + extra);
        let nested = endpoint.arq.storage_usage().ok_or("nested usage")?;
        assert_eq!(usage.allocations, nested.allocations + 1);
        assert_eq!(usage.capacity_bytes, nested.capacity_bytes + 84);
        assert_eq!(endpoint.storage().building_packets, 0);
        assert_eq!(endpoint.storage().outbound_packets, 0);
        assert_eq!(endpoint.storage().restored_packets, 0);
        assert_eq!(endpoint.storage().fec_reserved_bytes, 0);
        assert!(endpoint.encoder.is_none() && endpoint.decoder.is_none());
    }
    let (mut a, mut b) = pair()?;
    assert_eq!(a.submit(b"real", ms(0))?, 0);
    let mut out = vec![0xaa; a.send_max_packet_bytes()];
    let original = out.clone();
    let before = a.arq_statistics();
    let charge = ENVELOPE_BYTES + 52 + 4 + 29;
    let mut short = OutboundBudget {
        packets: 1,
        wire_bytes: charge - 1,
    };
    assert_eq!(a.poll_data(ms(0), &mut out, &mut short)?, None);
    assert_eq!(out, original);
    assert_eq!(a.arq_statistics(), before);
    assert_eq!(
        short,
        OutboundBudget {
            packets: 1,
            wire_bytes: charge - 1
        }
    );
    let mut exact = OutboundBudget {
        packets: 1,
        wire_bytes: charge,
    };
    let length = a
        .poll_data(ms(0), &mut out, &mut exact)?
        .ok_or("actual source")?;
    assert_eq!(length, ENVELOPE_BYTES + 52 + 4);
    assert_eq!(exact, OutboundBudget::default());
    assert_eq!(out[ENVELOPE_BYTES + 4], 2);
    assert_eq!(a.inspect_output(&out[..length])?, RecordKind::Source);
    assert_compact_descriptor(&out[..length], EndpointRole::Initiator, forward.arq())?;
    let view = inspect_compact_structural(
        &out[..length],
        EndpointRole::Initiator,
        a.send_max_packet_bytes(),
        forward.arq(),
        reverse.arq(),
    )?;
    assert_eq!(view.sender, context(EndpointRole::Initiator));
    assert_eq!(
        view.source,
        Some((l2tunnel_recovery::SourceId(0), b"real".as_slice()))
    );
    assert!(view.fec.is_none());
    assert!(
        inspect_structural(
            &out[..length],
            EndpointRole::Initiator,
            a.send_max_packet_bytes(),
            32,
            fec::BlockConfig {
                max_sources: 1,
                max_source_bytes: 84,
                max_packet_bytes: 200,
                max_work_per_symbol: 1_000
            }
        )
        .is_err()
    );
    let token = a.pending_output().ok_or("source witness")?;
    assert_eq!(
        (token.bytes, token.wire_bytes, token.kind),
        (length, charge, RecordKind::Source)
    );
    a.confirm_output_at(ms(2), ms(1), token)?;
    b.receive_at(&out[..length], ms(3), ms(4))?;
    let mut delivered = [0; 64];
    assert_eq!(b.poll_delivered(&mut delivered)?, Some((0, 4)));
    assert_eq!(&delivered[..4], b"real");
    assert_eq!(a.statistics().emitted_wire_bytes, charge as u64);
    assert_eq!(
        a.statistics().systematic_packets + a.statistics().repair_packets,
        0
    );
    Ok(())
}

#[test]
fn compact_r0_deferred_feedback_keeps_original_arrival_and_exact_pending_output() -> Result {
    let (mut a, mut b) = pair()?;
    a.submit(b"real", ms(0))?;
    let mut source = vec![0; a.send_max_packet_bytes()];
    let source_length = a
        .poll_data(ms(0), &mut source, &mut budget())?
        .ok_or("source")?;
    let held = a.pending_output().ok_or("held source")?;
    b.receive_at(&source[..source_length], ms(10), ms(10))?;
    let mut feedback = vec![0; b.send_max_packet_bytes()];
    feedback.fill(0xaa);
    let original = feedback.clone();
    let before_feedback = (b.statistics(), b.arq_statistics());
    let mut short = OutboundBudget {
        packets: 1,
        wire_bytes: ENVELOPE_BYTES + 76 + 29 - 1,
    };
    assert_eq!(b.poll_feedback(ms(15), &mut feedback, &mut short)?, None);
    assert_eq!(feedback, original);
    assert_eq!((b.statistics(), b.arq_statistics()), before_feedback);
    let mut exact = OutboundBudget {
        packets: 1,
        wire_bytes: ENVELOPE_BYTES + 76 + 29,
    };
    let feedback_length = b
        .poll_feedback(ms(15), &mut feedback, &mut exact)?
        .ok_or("feedback")?;
    assert_eq!(exact, OutboundBudget::default());
    assert_eq!(feedback_length, ENVELOPE_BYTES + 76);
    assert_compact_descriptor(
        &feedback[..feedback_length],
        EndpointRole::Responder,
        policy(32, CompactRecovery::Guarded, 70)?.arq(),
    )?;
    let feedback_token = b.pending_output().ok_or("feedback witness")?;
    b.confirm_output(ms(15), feedback_token)?;
    let before = (a.now, a.statistics(), a.arq_statistics(), a.storage());
    assert_eq!(
        a.receive_at(&feedback[..feedback_length], ms(20), ms(100)),
        Err(Error::Arq(RecoveryError::FeedbackAwaitingPhysical))
    );
    assert_eq!(
        (a.now, a.statistics(), a.arq_statistics(), a.storage()),
        before
    );
    assert_eq!(a.pending_output(), Some(held));
    assert_eq!(a.failure(), None);
    a.confirm_output_at(ms(100), ms(1), held)?;
    a.receive_at(&feedback[..feedback_length], ms(20), ms(100))?;
    let recovery_owner::Owner::Compact(owner) = &a.arq else {
        return Err("selected owner".into());
    };
    assert!((owner.timing()?.srtt_seconds.ok_or("actual sample")? - 0.014).abs() < 1e-15);
    assert_eq!(a.storage().arq.send_records, 0);
    assert!(a.pending_output().is_none());
    assert!(a.confirm_output(ms(100), held).is_err());
    Ok(())
}

#[test]
fn compact_r0_held_data_keeps_independent_feedback_and_original_accepted_retry_timer() -> Result {
    let (mut a, mut b) = pair()?;
    a.submit(b"real", ms(0))?;
    b.submit(b"reverse", ms(0))?;
    let mut a_source = vec![0; a.send_max_packet_bytes()];
    let first_length = a
        .poll_data(ms(0), &mut a_source, &mut budget())?
        .ok_or("first source")?;
    let first = a_source[..first_length].to_vec();
    let held = a.pending_output().ok_or("held source")?;
    let mut b_source = vec![0; b.send_max_packet_bytes()];
    let reverse_length = b
        .poll_data(ms(0), &mut b_source, &mut budget())?
        .ok_or("reverse source")?;
    b.confirm_output_at(ms(1), ms(1), b.pending_output().ok_or("reverse witness")?)?;
    a.receive_at(&b_source[..reverse_length], ms(2), ms(2))?;
    assert_eq!(a.poll_data(ms(200), &mut a_source, &mut budget())?, None);
    assert_eq!(&a_source[..first_length], first);
    assert_eq!(a.arq.deadline(), Some(ms(7)));
    let mut feedback = vec![0; a.send_max_packet_bytes()];
    let feedback_length = a
        .poll_feedback_independent(ms(200), &mut feedback, &mut budget())?
        .ok_or("independent feedback")?;
    let feedback_token = a.pending_feedback_output().ok_or("independent witness")?;
    assert_eq!(a.pending_output(), Some(held));
    assert_eq!(feedback_token.kind, RecordKind::Feedback);
    b.receive_at(&feedback[..feedback_length], ms(201), ms(201))?;
    a.confirm_output_at(ms(202), ms(200), feedback_token)?;
    assert_eq!(a.pending_output(), Some(held));
    a.confirm_output_at(ms(300), ms(10), held)?;
    // The original150ms RTO was armed at10ms, already due at observation300ms.
    assert_eq!(a.arq.deadline(), Some(ms(160)));
    let before = a.statistics();
    let mut wire = budget();
    let wire_before = wire;
    let retry_length = a
        .poll_data(ms(300), &mut a_source, &mut wire)?
        .ok_or("accepted-time retry")?;
    assert_eq!(retry_length, first_length);
    assert_eq!(&a_source[ENVELOPE_BYTES + 52..retry_length], b"real");
    assert_ne!(
        &a_source[ENVELOPE_BYTES + 40..ENVELOPE_BYTES + 48],
        &first[ENVELOPE_BYTES + 40..ENVELOPE_BYTES + 48]
    );
    assert_eq!(wire.packets, wire_before.packets - 1);
    assert_eq!(wire.wire_bytes, wire_before.wire_bytes - retry_length - 29);
    assert_eq!(a.statistics().retry_packets, before.retry_packets + 1);
    assert_eq!(a.storage().arq.send_records, 1);
    Ok(())
}

#[test]
fn independent_wakes_preserve_each_actual_lane_and_original_accepted_source_timer() -> Result {
    let (mut a, mut b) = pair()?;
    let usage = a.storage_usage();
    a.submit(b"real", ms(0))?;
    b.submit(b"reverse", ms(0))?;
    let mut a_source = vec![0; a.send_max_packet_bytes()];
    let length = a
        .poll_data(ms(0), &mut a_source, &mut budget())?
        .ok_or("held original")?;
    let original = a_source[..length].to_vec();
    let data = a.pending_data_output().ok_or("actual data token")?;
    let mut reverse = vec![0; b.send_max_packet_bytes()];
    let reverse_length = b
        .poll_data(ms(0), &mut reverse, &mut budget())?
        .ok_or("peer source")?;
    b.confirm_output_at(ms(1), ms(1), b.pending_data_output().ok_or("peer token")?)?;
    a.receive_at(&reverse[..reverse_length], ms(2), ms(2))?;
    assert_eq!(a.arq.source_deadline(), None);
    assert_eq!(a.arq.feedback_deadline(), Some(ms(7)));
    // Combined callers still wait for their held main output. Independent
    // callers can wake the genuinely free feedback lane at its original time.
    assert_eq!(a.deadline(), None);
    assert_eq!(a.feedback_deadline(), None);
    assert_eq!(a.feedback_deadline_independent(), Some(ms(7)));
    assert_eq!(a.deadline_independent(), Some(ms(7)));
    let mut feedback = vec![0; a.send_max_packet_bytes()];
    a.poll_feedback_independent(ms(7), &mut feedback, &mut budget())?
        .ok_or("independent feedback")?;
    let ack = a.pending_feedback_output().ok_or("held feedback token")?;
    assert_eq!(a.pending_data_output(), Some(data));
    assert_eq!(a.deadline_independent(), None, "both actual lanes are held");
    assert_eq!(a.feedback_deadline_independent(), None);
    assert_eq!(&a_source[..length], original);

    a.confirm_output_at(ms(9), ms(1), data)?;
    assert_eq!(a.pending_feedback_output(), Some(ack));
    assert_eq!(a.arq.source_deadline(), Some(ms(151)));
    assert_eq!(a.arq.feedback_deadline(), Some(ms(12)));
    assert_eq!(a.deadline(), None, "combined-slot compatibility");
    assert_eq!(
        a.deadline_independent(),
        Some(ms(151)),
        "held ACK cannot hide a free data RTO"
    );
    assert_eq!(
        a.feedback_deadline_independent(),
        None,
        "held ACK repeat must not spin"
    );
    let mut wire = budget();
    let before = wire;
    let mut untouched = vec![0xa5; a.send_max_packet_bytes()];
    assert_eq!(
        a.poll_data_independent(ms(150), &mut untouched, &mut wire)?,
        None
    );
    assert!(untouched.iter().all(|byte| *byte == 0xa5));
    assert_eq!(wire, before);
    assert_eq!(a.deadline_independent(), Some(ms(151)));
    let retry = a
        .poll_data_independent(ms(151), &mut a_source, &mut wire)?
        .ok_or("actual due retry")?;
    assert_eq!(retry, length);
    assert_eq!(&a_source[ENVELOPE_BYTES + 52..retry], b"real");
    assert_eq!(wire.packets, before.packets - 1);
    assert_eq!(wire.wire_bytes, before.wire_bytes - retry - 29);
    assert_eq!(a.pending_feedback_output(), Some(ack));
    let retry_token = a.pending_data_output().ok_or("actual retry token")?;
    assert_eq!(
        a.deadline_independent(),
        None,
        "no eligible lane while both are held"
    );
    a.confirm_output_at(ms(153), ms(152), retry_token)?;
    assert_eq!(a.arq.source_deadline(), Some(ms(302)));
    assert_eq!(a.deadline_independent(), Some(ms(302)));
    assert_eq!(a.feedback_deadline_independent(), None);
    a.confirm_output_at(ms(154), ms(7), ack)?;
    assert_eq!(
        a.feedback_deadline_independent(),
        Some(ms(12)),
        "original overdue repeat reappears unchanged"
    );
    assert_eq!(a.deadline_independent(), Some(ms(12)));
    assert_eq!(
        a.arq.source_deadline(),
        Some(ms(302)),
        "opposite completion cannot rearm the source"
    );
    a.poll_feedback_independent(ms(154), &mut feedback, &mut budget())?
        .ok_or("original repeat")?;
    assert_eq!(a.deadline_independent(), Some(ms(302)));
    assert_eq!(a.storage_usage(), usage);
    assert!(!a.drained());
    Ok(())
}

#[test]
fn compact_crossed_feedback_geometry_accepts_exact_directional_limit_and_refuses_one_over() -> Result
{
    let original = policy(1, CompactRecovery::Guarded, 70)?;
    let reverse_arq = CompactArqConfig::new(
        original.arq().bounds(),
        original.arq().timing(),
        76,
        original.arq().history_entries(),
        original.arq().maximum_attempts(),
        original.arq().recovery(),
    )?;
    // A direction's advertised feedback is emitted on the opposite path.
    // The actual forward maximum84 plus this explicit overhead is exactly65535;
    // combining its own77-byte feedback with that overhead would be one over.
    let overhead = 65_535 - (ENVELOPE_BYTES + 76);
    let forward = CompactReliableConfig::new(original.arq(), overhead)?;
    let reverse = CompactReliableConfig::new(reverse_arq, 0)?;
    let plan = storage::CompactPlan::for_duplex(forward, reverse)?;
    assert_eq!(plan.send_max_packet_bytes(), ENVELOPE_BYTES + 76);
    assert_eq!(plan.receive_max_packet_bytes(), ENVELOPE_BYTES + 77);
    assert_eq!(plan.send_max_packet_bytes() + overhead, 65_535);
    assert!(storage::CompactPlan::for_duplex(forward, forward).is_err());
    let too_large = CompactReliableConfig::new(original.arq(), overhead + 1)?;
    assert!(matches!(
        storage::CompactPlan::for_duplex(too_large, reverse),
        Err(storage::Error::Reliable(Error::InvalidConfig))
    ));
    let mut a = Reliable::new_compact_duplex_reserved(
        forward,
        reverse,
        context(EndpointRole::Initiator),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let mut b = Reliable::new_compact_duplex(reverse, forward, context(EndpointRole::Responder))?;
    assert_eq!(
        a.storage_usage()
            .ok_or("actual asymmetric usage")?
            .capacity_bytes,
        plan.capacity_bytes()
    );
    let mut second = Vec::new();
    for (index, now) in [ms(0), ms(2)].into_iter().enumerate() {
        a.submit(&[index as u8], now)?;
        let mut bytes = vec![0; a.send_max_packet_bytes()];
        let charge = ENVELOPE_BYTES + 52 + 1 + overhead;
        let mut allowance = OutboundBudget {
            packets: 1,
            wire_bytes: charge,
        };
        let length = a
            .poll_data(now, &mut bytes, &mut allowance)?
            .ok_or("actual asymmetric source")?;
        assert_eq!(length + overhead, charge);
        assert_eq!(allowance, OutboundBudget::default());
        a.confirm_output_at(
            now + ms(1),
            now + ms(1),
            a.pending_data_output().ok_or("source token")?,
        )?;
        if index == 1 {
            second = bytes[..length].to_vec();
        }
    }
    // Genuine missing-first receipt generates a one-byte bitmap on the reverse
    // path, proving the advertised77-byte feedback uses the reverse overhead.
    b.receive_at(&second, ms(4), ms(4))?;
    let mut feedback = vec![0; b.send_max_packet_bytes()];
    let mut exact = OutboundBudget {
        packets: 1,
        wire_bytes: ENVELOPE_BYTES + 77,
    };
    let length = b
        .poll_feedback_independent(ms(9), &mut feedback, &mut exact)?
        .ok_or("actual crossed feedback")?;
    assert_eq!(length, ENVELOPE_BYTES + 77);
    assert_eq!(exact, OutboundBudget::default());
    b.confirm_output(ms(9), b.pending_feedback_output().ok_or("reverse token")?)?;
    a.receive_at(&feedback[..length], ms(10), ms(10))?;
    assert_eq!(a.storage().arq.send_records, 1);
    assert_eq!(a.storage().arq.send_bytes, 1);
    assert_eq!(
        a.statistics().systematic_packets + a.statistics().repair_packets,
        0
    );
    Ok(())
}

#[test]
fn compact_history_pressure_keeps_feedback_live_then_releases_exact_next_source_without_failure()
-> Result {
    let original = policy(32, CompactRecovery::Guarded, 70)?;
    let arq = original.arq();
    let selected = CompactReliableConfig::new(
        CompactArqConfig::new(
            arq.bounds(),
            arq.timing(),
            arq.maximum_feedback_bytes(),
            1,
            arq.maximum_attempts(),
            arq.recovery(),
        )?,
        original.outer_overhead_bytes(),
    )?;
    let mut a = Reliable::new_compact(selected, context(EndpointRole::Initiator))?;
    let mut b = Reliable::new_compact(selected, context(EndpointRole::Responder))?;
    let usage = a.storage_usage();
    assert_eq!(a.submit(b"first", ms(0))?, 0);
    assert_eq!(a.submit(b"second", ms(0))?, 1);
    assert_eq!(b.submit(b"reverse", ms(0))?, 0);
    let mut source = vec![0; a.send_max_packet_bytes()];
    let bytes = a
        .poll_data_independent(ms(0), &mut source, &mut budget())?
        .ok_or("actual first source")?;
    let token = a.pending_data_output().ok_or("actual source custody")?;
    a.confirm_output(ms(0), token)?;
    b.receive(&source[..bytes], ms(0))?;
    let mut reverse = vec![0; b.send_max_packet_bytes()];
    let bytes = b
        .poll_data_independent(ms(0), &mut reverse, &mut budget())?
        .ok_or("actual reverse source")?;
    let token = b.pending_data_output().ok_or("actual reverse custody")?;
    b.confirm_output(ms(0), token)?;
    a.receive(&reverse[..bytes], ms(0))?;

    // The public direct recovery call still reports exact transactional pressure.
    let mut core_out = [0xaa; 128];
    let before = a.arq_statistics();
    assert_eq!(
        a.arq.poll_source(ms(1), &mut core_out),
        Err(RecoveryError::HistoryCapacity)
    );
    assert_eq!(core_out, [0xaa; 128]);
    assert_eq!(a.arq_statistics(), before);
    source.fill(0xa5);
    let untouched = source.clone();
    let mut allowance = budget();
    let original_allowance = allowance;
    let before = (a.statistics(), a.arq_statistics());
    assert_eq!(
        a.poll_data_independent(ms(1), &mut source, &mut allowance)?,
        None
    );
    assert_eq!(source, untouched);
    assert_eq!(allowance, original_allowance);
    assert_eq!((a.statistics(), a.arq_statistics()), before);
    assert_eq!(a.failure(), None);
    assert_eq!(a.pending_data_output(), None);
    assert_eq!(a.storage_usage(), usage);
    assert_eq!(a.arq.source_deadline(), None);
    assert_eq!(a.deadline_independent(), Some(ms(5)));

    // Its own genuine reverse-direction ACK remains independently serviceable.
    let bytes = a
        .poll_feedback_independent(ms(5), &mut source, &mut budget())?
        .ok_or("feedback while source history is full")?;
    let token = a.pending_feedback_output().ok_or("feedback custody")?;
    a.confirm_output(ms(5), token)?;
    b.receive(&source[..bytes], ms(5))?;
    let bytes = b
        .poll_feedback_independent(ms(5), &mut reverse, &mut budget())?
        .ok_or("real echo releasing source history")?;
    let token = b.pending_feedback_output().ok_or("peer feedback custody")?;
    b.confirm_output(ms(5), token)?;
    a.receive(&reverse[..bytes], ms(5))?;
    assert_eq!(a.arq.source_deadline(), Some(ms(5)));
    let bytes = a
        .poll_data_independent(ms(5), &mut source, &mut budget())?
        .ok_or("exact next source after peer echo")?;
    let view = a.inspect_output_record(&source[..bytes])?;
    assert_eq!(view.kind, RecordKind::Source);
    assert_eq!(
        view.source,
        Some((l2tunnel_recovery::SourceId(1), b"second".as_slice()))
    );
    let recovery_owner::Owner::Compact(actual) = &a.arq else {
        return Err("actual Compact owner missing".into());
    };
    assert!(matches!(
        l2tunnel_recovery::inspect_compact_packet(
            &source[ENVELOPE_BYTES..bytes],
            context(EndpointRole::Responder),
            actual.send_config()?
        )?,
        l2tunnel_recovery::CompactPacketView::Data { serial: 2, .. }
    ));
    let token = a.pending_data_output().ok_or("same owner's next custody")?;
    a.confirm_output(ms(5), token)?;
    b.receive(&source[..bytes], ms(5))?;
    assert_eq!(a.failure(), None);
    assert_eq!(a.storage_usage(), usage);
    let mut delivered = [0; 32];
    assert_eq!(b.poll_delivered(&mut delivered)?, Some((0, 5)));
    assert_eq!(&delivered[..5], b"first");
    assert_eq!(b.poll_delivered(&mut delivered)?, Some((1, 6)));
    assert_eq!(&delivered[..6], b"second");

    // Full history must not hide an actually exhausted attempt's terminal path.
    let bounded = CompactReliableConfig::new(
        CompactArqConfig::new(
            arq.bounds(),
            arq.timing(),
            arq.maximum_feedback_bytes(),
            1,
            1,
            arq.recovery(),
        )?,
        original.outer_overhead_bytes(),
    )?;
    let mut failed = Reliable::new_compact(bounded, context(EndpointRole::Initiator))?;
    failed.submit(b"lost", ms(0))?;
    failed
        .poll_data_independent(ms(0), &mut source, &mut budget())?
        .ok_or("actual bounded source")?;
    let token = failed
        .pending_data_output()
        .ok_or("actual bounded custody")?;
    failed.confirm_output(ms(0), token)?;
    let expiry = failed
        .deadline_independent()
        .ok_or("original finite retry opportunity")?;
    assert!(matches!(
        failed.poll_data_independent(expiry, &mut source, &mut budget()),
        Err(Error::Arq(RecoveryError::RetryExhausted {
            source: l2tunnel_recovery::SourceId(0)
        }))
    ));
    assert!(matches!(
        failed.failure(),
        Some(Error::Arq(RecoveryError::RetryExhausted { .. }))
    ));
    Ok(())
}
