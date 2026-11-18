use super::*;
use rolling::wire::compact;

fn prepare(owner: &mut Endpoint, now: Tick) -> TestResult<(PreparedOutput, Vec<u8>)> {
    let mut buffer = vec![0; rolling::wire::MAX_RECORD_BYTES];
    let mut allowance = OutboundBudget {
        packets: 128,
        wire_bytes: 1 << 16,
    };
    let token = owner
        .prepare_output(
            now,
            now.0,
            true,
            &mut buffer,
            &mut allowance,
            &mut [witness(); 4],
        )?
        .ok_or("expected physical output")?;
    buffer.truncate(token.bytes);
    Ok((token, buffer))
}

fn emit_source(
    owner: &mut Endpoint,
    index: u64,
    length: usize,
) -> TestResult<(PreparedOutput, usize)> {
    let t = Tick(index);
    owner
        .enqueue_admitted_identified(t, 0, &packet(true, index as u8, length))?
        .ok_or("expected native admission")?;
    owner.flush(t)?;
    owner.step(t, work())?;
    let (token, bytes) = prepare(owner, t)?;
    let recovery::View::Source { original, .. } = owner.inspect_data(&bytes, true)? else {
        return Err("expected original".into());
    };
    owner.confirm_output(t, token)?;
    Ok((token, original.len()))
}

#[test]
fn targeted_repair_budget_prices_real_retries_and_suppresses_before_encoding() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::TargetedExact);
    let frame = |overhead| codec::FragmentConfig {
        path_mtu: 160,
        outer_overhead_bytes: overhead,
        max_message_bytes: 1024,
        max_fragments: 64,
    };
    let framing = OutputFraming {
        forward: frame(config.geometry.forward_overhead_bytes),
        reverse: frame(config.geometry.reverse_overhead_bytes),
    };
    let plan = storage::Plan::for_endpoint_with_output_framing(
        config,
        context(Role::Client),
        17,
        Tick(0),
        CopyPolicies::ONE,
        None,
        Some(framing),
    )?;
    let mut owner = Endpoint::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    owner.enable_compact_wire_with_overheads(config.geometry.forward_overhead_bytes, 79)?;
    assert_eq!(
        owner.enqueue_admitted_identified(Tick(0), 0, &packet(true, 0, 100)),
        Err(Error::Configuration)
    );
    owner.enable_queue_aware_repair_budget(160)?;
    let (original, source_len) = emit_source(&mut owner, 0, 119)?;
    assert!(original.packets > 1);
    for (index, age) in [(1, 5_000), (2, 15_000)] {
        let now = Tick(index);
        let request = scheduler::GapRequest {
            scope: owner.send_rolling_scope,
            id: scheduler::FeedbackId(index),
            prefix: 0,
            start: 0,
            mask: 1,
        };
        let mut bytes = [0; 64];
        let n = compact::encode_gap(config.forward.scheduler.recovery, request, &mut bytes)?;
        owner.observe_mux_wait_micros(age);
        owner.accept_authenticated(now, record_engine::EmissionKind::Feedback, &bytes[..n])?;
        owner.observe_mux_wait_micros(0);
        owner.step(now, work())?;
        // The prepared retry can wait for physical allowance while the MUX drains.
        owner.observe_mux_wait_micros(0);
        let before = owner.repair_budget_status().ok_or("selected budget")?;
        let (retry, _) = prepare(&mut owner, now)?;
        assert_eq!(retry.wire_bytes, original.wire_bytes);
        let (again, _) = prepare(&mut owner, now)?;
        assert_eq!(again, retry);
        owner.observe_mux_wait_micros(0);
        assert_eq!(owner.repair_budget_status(), Some(before));
        owner.confirm_output(now, retry)?;
        assert_eq!(owner.confirm_output(now, retry), Err(Error::Token));
    }
    let before = owner.repair_budget_status().ok_or("selected budget")?;
    assert_eq!(
        (before.half_weight_retries, before.full_weight_retries),
        (1, 1)
    );
    assert_eq!(before.balance_half_bytes, 3 * original.wire_bytes as u64);
    emit_source(&mut owner, 3, 80)?;
    let at_confirmation = owner
        .repair_budget_status()
        .ok_or("missing physical-receipt price")?;
    assert_eq!(at_confirmation.displaced_repairs, 1);
    let progress = owner.step(Tick(4), work())?;
    assert_eq!((progress.send.field, progress.send.copies), (0, 0));
    assert!(owner.sender.pending_output().is_none());
    let displaced = owner.repair_budget_status().ok_or("selected budget")?;
    let exact = compact::repair_len(rolling::RepairId(1), 2, source_len + 2)?;
    let charge = framing.forward.geometry(exact)?.wire_bytes() as u64;
    assert_eq!(displaced.displaced_repairs, 1);
    assert_eq!(displaced.displaced_wire_bytes, charge);
    assert_eq!(
        displaced.balance_half_bytes,
        before.balance_half_bytes - 2 * charge
    );
    emit_source(&mut owner, 5, 100)?;
    emit_source(&mut owner, 6, 100)?;
    owner.step(Tick(7), work())?;
    let (regular, bytes) = prepare(&mut owner, Tick(7))?;
    let compact::View::Data(rolling::wire::View::Repair(repair)) = compact::inspect(
        config.forward.scheduler.recovery,
        owner.send_rolling_scope,
        &bytes,
    )?
    else {
        return Err("expected transmitted regular repair".into());
    };
    assert_eq!(repair.id, rolling::RepairId(1));
    assert_eq!(
        repair.support,
        config
            .forward
            .scheduler
            .recovery
            .support(4, repair.id, false)?
    );
    owner.confirm_output(Tick(7), regular)?;
    let last = owner.repair_budget_status().ok_or("selected budget")?;
    assert_eq!(
        last.opportunity_wire_bytes,
        charge + regular.wire_bytes as u64
    );
    assert_eq!(last.regular_wire_bytes, regular.wire_bytes as u64);
    assert_eq!(
        last.requested_retry_wire_bytes,
        2 * original.wire_bytes as u64
    );
    assert_eq!(last.copy_wire_bytes, 0);
    let quiet_at = Tick(140_006);
    owner.step(quiet_at, work())?;
    let (probe, _) = prepare(&mut owner, quiet_at)?;
    owner.confirm_output(quiet_at, probe)?;
    let silent = owner.repair_budget_status().ok_or("selected budget")?;
    assert_eq!(silent.quiet_probes, 1);
    assert_eq!(silent.quiet_probe_wire_bytes, original.wire_bytes as u64);
    assert_eq!(silent.earned_half_bytes, last.earned_half_bytes);
    let ack = scheduler::Feedback {
        scope: owner.send_rolling_scope,
        id: scheduler::FeedbackId(3),
        prefix: 4,
        observed_end: 4,
        deficit: 0,
    };
    let mut bytes = [0; 64];
    let n = compact::encode_feedback(ack, &mut bytes)?;
    owner.accept_authenticated(quiet_at, record_engine::EmissionKind::Feedback, &bytes[..n])?;
    let final_status = owner.repair_budget_status().ok_or("selected budget")?;
    assert_eq!(final_status.balance_half_bytes, 0);
    assert_eq!(final_status.expired_half_bytes, last.balance_half_bytes);
    Ok(())
}

#[test]
fn overlapping_requests_own_their_tier_through_ack_and_physical_backpressure() -> TestResult {
    let mut config = config(true, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    let mut owner = endpoint(config, Role::Client)?;
    owner.enable_compact_wire(41)?;
    owner.enable_queue_aware_repair_budget(1500)?;
    let mut charges = Vec::new();
    for i in 0..4 {
        charges.push(emit_source(&mut owner, i, 90 + i as usize)?.0.wire_bytes as u64);
    }

    // No sender service between these requests. The last request repeats ID
    // zero while that ID's first solicited retry is still queued.
    for (serial, id, age) in [
        (1, 0, 14_999),
        (2, 1, 15_000),
        (3, 2, 5_001),
        (4, 3, 5_000),
        (5, 0, 25_000),
    ] {
        let request = scheduler::GapRequest {
            scope: owner.send_rolling_scope,
            id: scheduler::FeedbackId(serial),
            prefix: 0,
            start: id,
            mask: 1,
        };
        let mut wire = [0; 64];
        let n = compact::encode_gap(config.forward.scheduler.recovery, request, &mut wire)?;
        owner.observe_mux_wait_micros(age);
        owner.accept_authenticated(Tick(6), record_engine::EmissionKind::Feedback, &wire[..n])?;
    }
    for (index, weight) in [1, 2, 2, 1].into_iter().enumerate() {
        let now = Tick(7 + index as u64);
        let work = rolling::WorkBudget {
            metadata: 1,
            ..Default::default()
        };
        owner.step(now, work)?;
        let (retry, _) = prepare(&mut owner, now)?;
        assert_eq!(
            retry.id,
            OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(index as u32)))
        );
        let before = owner.repair_budget_status().ok_or("budget")?;
        if index == 0 {
            let ack = scheduler::Feedback {
                scope: owner.send_rolling_scope,
                id: scheduler::FeedbackId(6),
                prefix: 1,
                observed_end: 4,
                deficit: 1,
            };
            let mut wire = [0; 64];
            let n = compact::encode_feedback(ack, &mut wire)?;
            owner.observe_mux_wait_micros(0);
            owner.accept_authenticated(now, record_engine::EmissionKind::Feedback, &wire[..n])?;
            assert_eq!(owner.pending_output(), Some(retry));
            assert_eq!(owner.repair_budget_status(), Some(before));
        }
        owner.confirm_output(now, retry)?;
        let after = owner.repair_budget_status().ok_or("budget")?;
        assert_eq!(
            after.earned_half_bytes - before.earned_half_bytes,
            weight * charges[index]
        );
    }
    Ok(())
}

#[test]
fn one_copy_earning_source_publishes_its_own_larger_extent_before_pricing() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::TargetedExact);
    let mut owner = endpoint(config, Role::Client)?;
    owner.enable_compact_wire(41)?;
    owner.enable_queue_aware_repair_budget(1500)?;
    let (_, first) = emit_source(&mut owner, 0, 75)?;
    let (_, last) = emit_source(&mut owner, 1, 116)?;
    assert!(last > first);
    let status = owner.repair_budget_status().ok_or("repair budget")?;
    let inner = compact::repair_len(rolling::RepairId(1), 2, last + 2)?;
    assert_eq!(status.opportunity_wire_bytes, (inner + 41) as u64);
    assert_eq!(status.displaced_repairs, 0);
    owner.step(Tick(2), work())?;
    let (ready, bytes) = prepare(&mut owner, Tick(2))?;
    assert_eq!(ready.wire_bytes as u64, status.opportunity_wire_bytes);
    let compact::View::Data(rolling::wire::View::Repair(r)) = compact::inspect(
        config.forward.scheduler.recovery,
        owner.send_rolling_scope,
        &bytes,
    )?
    else {
        return Err("expected repair".into());
    };
    assert_eq!((r.id.0, r.support.end, r.bytes.len()), (1, 2, last + 2));
    owner.confirm_output(Tick(2), ready)?;
    Ok(())
}
