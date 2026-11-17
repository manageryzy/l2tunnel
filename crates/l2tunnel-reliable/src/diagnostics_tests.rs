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
