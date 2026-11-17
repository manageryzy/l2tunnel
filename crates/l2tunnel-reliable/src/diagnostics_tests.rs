use super::*;

fn observed(
    config: ReliableConfig,
    role: EndpointRole,
) -> Result<Reliable, Box<dyn std::error::Error>> {
    let plan = storage::Plan::for_duplex(config, config)?.with_output_diagnostics()?;
    let mut owner = Reliable::new_reserved_with_plan(
        plan,
        context(role),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    owner.enable_physical_send_confirmation()?;
    owner.enable_compact_wire_with_overheads(37, 49)?;
    Ok(owner)
}
fn budget() -> OutboundBudget {
    OutboundBudget {
        packets: 32,
        wire_bytes: 100_000,
    }
}

#[test]
fn block_output_diagnostics_follow_real_sealed_head_and_not_packing_or_custody() -> TestResult {
    let mut sender = observed(config(), EndpointRole::Initiator)?;
    let usage = sender.storage_usage();
    sender.submit(b"one short block source", time(0))?;
    let mut output = vec![0xa5; sender.max_packet_bytes()];
    assert_eq!(sender.poll_data(time(0), &mut output, &mut budget())?, None);
    assert_eq!(sender.storage().building_packets, 1);
    assert!(
        sender
            .output_wait_snapshot(time(4))
            .ok_or("observer")?
            .pending
            .is_none()
    );
    let n = sender
        .poll_data(time(5), &mut output, &mut budget())?
        .ok_or("partial flush")?;
    assert_eq!(
        sender.inspect_output_record(&output[..n])?.kind,
        RecordKind::Systematic
    );
    let token = sender.pending_data_output().ok_or("actual custody")?;
    assert_eq!(
        sender.poll_data(time(6), &mut output, &mut OutboundBudget::default())?,
        None
    );
    assert!(
        sender
            .output_wait_snapshot(time(6))
            .ok_or("observer")?
            .pending
            .is_none(),
        "held physical output is not a budget attempt"
    );
    sender.confirm_output_at(time(7), time(5), token)?;
    let untouched = output.clone();
    let before = sender.storage();
    for tick in [8, 9] {
        assert_eq!(
            sender.poll_data(time(tick), &mut output, &mut OutboundBudget::default())?,
            None
        );
    }
    assert_eq!(output, untouched);
    assert_eq!(sender.storage(), before);
    let waiting = sender.output_wait_snapshot(time(10)).ok_or("observer")?;
    let operation = waiting.pending.ok_or("sealed repair retained")?.operation;
    assert_eq!(waiting.refusals, [2, 2]);
    assert_eq!(waiting.pending.ok_or("pending")?.since, time(8));
    assert_eq!(waiting.union.completed_episodes, 0);
    let n = sender
        .poll_data(time(12), &mut output, &mut budget())?
        .ok_or("same repair emitted")?;
    let view = sender
        .inspect_output_record(&output[..n])?
        .fec
        .ok_or("repair")?;
    assert_eq!(
        (view.generation.0, view.symbol.0),
        (operation.generation, operation.symbol)
    );
    let complete = sender.output_wait_snapshot(time(12)).ok_or("observer")?;
    assert!(complete.pending.is_none());
    assert_eq!(complete.union.completed_episodes, 1);
    assert_eq!(complete.union.completed, time(4));
    assert_eq!(complete.reasons[0].completed, time(4));
    assert_eq!(complete.reasons[1].completed, time(4));
    assert!(
        sender.pending_data_output().is_some(),
        "emission completion is not physical acceptance"
    );
    assert_eq!(sender.storage_usage(), usage);
    Ok(())
}

#[test]
fn block_output_diagnostics_are_prepaid_and_terminal_censor_is_read_only() -> TestResult {
    let plain = storage::Plan::for_duplex(config(), config())?;
    let enabled = plain.with_output_diagnostics()?;
    assert_eq!(enabled, enabled.with_output_diagnostics()?);
    assert_eq!(
        enabled.capacity_bytes() - plain.capacity_bytes(),
        std::mem::size_of::<diagnostics::Snapshot>()
    );
    assert!(matches!(
        Reliable::new_reserved_with_plan(
            enabled,
            context(EndpointRole::Initiator),
            storage::Limits {
                capacity_bytes: plain.capacity_bytes()
            }
        ),
        Err(storage::Error::Limit { .. })
    ));
    let unobserved = Reliable::new_reserved_with_plan(
        plain,
        context(EndpointRole::Initiator),
        storage::Limits {
            capacity_bytes: plain.capacity_bytes(),
        },
    )?;
    assert!(unobserved.output_wait_snapshot(time(0)).is_none());
    let mut sender = observed(config(), EndpointRole::Initiator)?;
    sender.submit(b"retained", time(0))?;
    let mut bytes = vec![0; sender.max_packet_bytes()];
    sender.poll_data(time(0), &mut bytes, &mut budget())?;
    assert_eq!(
        sender.poll_data(time(5), &mut bytes, &mut OutboundBudget::default())?,
        None
    );
    let retained = sender.storage();
    let deadline = sender.deadline();
    let raw = sender.output_wait_snapshot(time(7)).ok_or("observer")?;
    let terminal = raw.censor(time(7));
    assert_eq!(terminal.union.censored_episodes, 1);
    assert_eq!(terminal.union.censored, time(2));
    assert!(terminal.pending.is_none());
    assert_eq!(terminal, terminal.censor(time(8)));
    assert_eq!(sender.storage(), retained);
    assert_eq!(sender.deadline(), deadline);
    assert!(
        sender
            .output_wait_snapshot(time(7))
            .ok_or("live")?
            .pending
            .is_some()
    );
    assert!(raw.observed(time(6)).clock_regression);
    Ok(())
}

#[test]
fn block_decoder_capacity_is_an_actual_count_not_a_wait_or_allocated_capacity() -> TestResult {
    let policy = ReliableConfig {
        fec: fec::DecoderConfig {
            max_generations: 1,
            ..config().fec
        },
        ..config()
    };
    let mut sender = observed(policy, EndpointRole::Initiator)?;
    let mut receiver = observed(policy, EndpointRole::Responder)?;
    submit_all(&mut sender, &sources())?;
    let mut output = vec![0; sender.max_packet_bytes()];
    let n = sender
        .poll_data(time(0), &mut output, &mut budget())?
        .ok_or("systematic")?;
    receiver.receive(&output[..n], time(0))?;
    let before = receiver
        .storage()
        .block
        .ok_or("block")?
        .decoder
        .ok_or("decoder")?;
    assert_eq!(before.generations, 1);
    assert_eq!(before.generations_capacity, 1);
    assert!(before.logical_reservation_bytes > 0);
    assert_eq!(
        before.logical_reservation_capacity,
        policy.fec.max_reserved_bytes
    );
    assert_ne!(
        Some(before.logical_reservation_bytes),
        before.allocated_capacity_bytes
    );
    let mut view = sender
        .inspect_output_record(&output[..n])?
        .fec
        .ok_or("symbol")?;
    view.generation = fec::GenerationId(1);
    let mut next = vec![0; receiver.max_packet_bytes()];
    let n = crate::selected_wire::encode_symbol(view, &mut next)?;
    receiver.receive(&next[..n], time(1))?;
    let after = receiver
        .storage()
        .block
        .ok_or("block")?
        .decoder
        .ok_or("decoder")?;
    assert_eq!(after, before);
    let snapshot = receiver.output_wait_snapshot(time(1)).ok_or("observer")?;
    assert_eq!(snapshot.capacity_refusals, [0, 1, 0, 0, 0]);
    assert!(snapshot.pending.is_none());
    assert_eq!(snapshot.union.completed_episodes, 0);
    assert_eq!(receiver.statistics().skipped_fec_packets, 1);
    Ok(())
}

fn direct_observed(role: EndpointRole) -> Result<Reliable, Box<dyn std::error::Error>> {
    let mut policy = config();
    policy.repair_symbols = 0;
    policy.arq.send_records = 2;
    policy.fec.block.max_sources = 2;
    observed(policy, role)
}
fn actual_source(owner: &mut Reliable, tick: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = vec![0; owner.max_packet_bytes()];
    let n = owner
        .poll_data(time(tick), &mut bytes, &mut budget())?
        .ok_or("actual source")?;
    let token = owner.pending_data_output().ok_or("actual source custody")?;
    owner.confirm_output(time(tick), token)?;
    bytes.truncate(n);
    Ok(bytes)
}
fn actual_feedback(owner: &mut Reliable, tick: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = vec![0; owner.max_packet_bytes()];
    let n = owner
        .poll_feedback(time(tick), &mut bytes, &mut budget())?
        .ok_or("actual feedback")?;
    let token = owner
        .pending_feedback_output()
        .ok_or("actual feedback custody")?;
    owner.confirm_output(time(tick), token)?;
    bytes.truncate(n);
    Ok(bytes)
}
#[test]
fn staged_source_identity_survives_sparse_span_shorter_episode_and_terminal_censor() -> TestResult {
    let mut sender = direct_observed(EndpointRole::Initiator)?;
    let mut peer = direct_observed(EndpointRole::Responder)?;
    let usage = sender.storage_usage();
    sender.submit(b"zero", time(0))?;
    sender.submit(b"one", time(0))?;
    let zero = actual_source(&mut sender, 0)?;
    peer.receive(&actual_source(&mut sender, 0)?, time(0))?;
    sender.receive(&actual_feedback(&mut peer, 1)?, time(1))?;
    assert_eq!(
        sender.submit(b"two", time(2)),
        Err(Error::Arq(RecoveryError::SequenceWindow))
    );
    let unit = diagnostics::staged::Unit {
        channel: 7,
        record: 12,
        native_record: 13,
        offset: 16,
        context: true,
    };
    sender.observe_staged_unit(2, 3, unit);
    sender.observe_native_provenance(
        7,
        13,
        diagnostics::staged::Native {
            flow: 100,
            received: time(0),
            queued: time(1),
            deadline: Some(time(50)),
        },
    );
    let pending = sender
        .output_wait_snapshot(time(2))
        .ok_or("observer")?
        .staged
        .pending
        .ok_or("pending")?;
    assert_eq!(
        (pending.first.records, pending.first.records_capacity),
        (1, 2)
    );
    assert!(
        !pending.first.records_full && !pending.first.bytes_full && pending.first.sequence_full
    );
    assert_eq!(pending.first.oldest.ok_or("held hole")?.source.0, 0);
    assert_eq!(pending.native.ok_or("original native")?.flow, 100);
    peer.receive(&zero, time(3))?;
    sender.receive(&actual_feedback(&mut peer, 4)?, time(12))?;
    assert_eq!(sender.submit(b"two", time(12))?, 2);
    sender.submit(b"three", time(12))?;
    assert!(matches!(
        sender.submit(b"four", time(13)),
        Err(Error::Arq(RecoveryError::Capacity(_)))
    ));
    peer.receive(&actual_source(&mut sender, 13)?, time(13))?;
    peer.receive(&actual_source(&mut sender, 13)?, time(13))?;
    sender.receive(&actual_feedback(&mut peer, 14)?, time(14))?;
    sender.submit(b"four", time(14))?;
    sender.submit(b"five", time(14))?;
    assert!(matches!(
        sender.submit(b"six", time(15)),
        Err(Error::Arq(RecoveryError::Capacity(_)))
    ));
    let live = sender
        .output_wait_snapshot(time(16))
        .ok_or("live observer")?;
    let winner = live.staged.maximum_completed.ok_or("maximum")?;
    assert_eq!(
        (
            winner.pending.source,
            winner.pending.unit,
            winner.pending.native
        ),
        (2, Some(unit), pending.native)
    );
    assert_eq!(winner.at - winner.pending.since, time(10));
    assert_eq!(
        winner.retirement.ok_or("real input retirement")?.kind,
        diagnostics::staged::RetirementKind::Input
    );
    assert_eq!(
        live.staged
            .last_resolved
            .ok_or("shorter completed")?
            .pending
            .source,
        4
    );
    assert_eq!(live.staged.pending.ok_or("terminal retained")?.source, 6);
    let terminal = live.censor(time(16));
    assert_eq!(terminal.staged.maximum_completed, Some(winner));
    let censored = terminal
        .staged
        .maximum_censored
        .ok_or("censored identity")?;
    assert_eq!(
        (
            censored.pending.source,
            censored.at - censored.pending.since
        ),
        (6, time(1))
    );
    assert!(censored.censored && terminal.staged.pending.is_none());
    assert_eq!(terminal, terminal.censor(time(17)));
    assert!(!terminal.staged.invalid);
    assert_eq!(sender.storage_usage(), usage);
    assert_eq!(
        sender.storage().arq.send_records,
        2,
        "observing/censoring did not release protocol custody"
    );
    Ok(())
}
#[test]
fn staged_retirement_is_not_inferred_from_ack_while_actual_retry_is_held() -> TestResult {
    let mut sender = direct_observed(EndpointRole::Initiator)?;
    let mut peer = direct_observed(EndpointRole::Responder)?;
    sender.submit(b"old copy", time(0))?;
    peer.receive(&actual_source(&mut sender, 0)?, time(0))?;
    let feedback = actual_feedback(&mut peer, 1)?;
    let mut output = vec![0; sender.max_packet_bytes()];
    sender
        .poll_data(time(100), &mut output, &mut budget())?
        .ok_or("retry")?;
    let token = sender.pending_data_output().ok_or("held retry")?;
    sender.receive(&feedback, time(101))?;
    assert_eq!(sender.storage().arq.send_records, 1);
    assert!(
        sender
            .output_wait_snapshot(time(101))
            .ok_or("observer")?
            .staged
            .last_retirement
            .is_none()
    );
    sender.confirm_output_at(time(102), time(101), token)?;
    let event = sender
        .output_wait_snapshot(time(102))
        .ok_or("observer")?
        .staged
        .last_retirement
        .ok_or("actual release")?;
    assert_eq!(
        (event.kind, event.records, event.bytes),
        (diagnostics::staged::RetirementKind::Physical, 1, 8)
    );
    assert_eq!(
        (event.accepted, event.observed, event.operation_succeeded),
        (Some(time(101)), time(102), true)
    );
    assert_eq!(
        sender.confirm_output(time(103), token),
        Err(Error::OutputToken)
    );
    assert_eq!(
        sender
            .output_wait_snapshot(time(103))
            .ok_or("observer")?
            .staged
            .last_retirement,
        Some(event)
    );
    Ok(())
}
