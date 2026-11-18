//! Real selected owners exercise exact refusal, same-ID progress and original caps.
use super::*;
use crate::fec::research;
use crate::rolling_records::waits::{Site, Terminal};

fn observed<P: RecoveryPolicy>(config: Config<P>, role: Role) -> TestResult<Endpoint<P>> {
    let plain = storage::Plan::for_endpoint(config, context(role), 17, Tick(0))?;
    let plan = plain.with_wait_diagnostics()?;
    assert_eq!(
        plan.capacity_bytes() - plain.capacity_bytes(),
        std::mem::size_of::<waits::Snapshot>()
    );
    assert!(matches!(
        Endpoint::new_reserved(
            plan,
            storage::Limits {
                capacity_bytes: plain.capacity_bytes()
            }
        ),
        Err(Error::Capacity { .. })
    ));
    let endpoint = Endpoint::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    assert_eq!(
        endpoint
            .storage_usage()
            .ok_or("reserved usage")?
            .capacity_bytes,
        plan.capacity_bytes()
    );
    assert_eq!(endpoint.waits.capacity(), 1);
    Ok(endpoint)
}
fn research_config(old: Config) -> Config<research::Config> {
    fn direction(old: DirectionConfig) -> DirectionConfig<research::Config> {
        DirectionConfig {
            native_policy: old.native_policy,
            receiver: old.receiver,
            packing: old.packing,
            codec_stage_micros: old.codec_stage_micros,
            scheduler: research::Config {
                recovery: old.scheduler.recovery,
                profile: research::Profile::Accumulator {
                    lanes: 2,
                    window: 4,
                },
                feedback_ticks: old.scheduler.feedback_ticks,
                memory_bytes: old.scheduler.memory_bytes,
            },
        }
    }
    Config {
        forward: direction(old.forward),
        reverse: direction(old.reverse),
        geometry: old.geometry,
        native_stall_micros: old.native_stall_micros,
    }
}
fn output<P: RecoveryPolicy>(
    endpoint: &mut Endpoint<P>,
    now: Tick,
) -> TestResult<(PreparedOutput, Vec<u8>)> {
    let mut bytes = [0; rolling::wire::MAX_RECORD_BYTES];
    let mut witnesses = [witness(); 4];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 10000,
    };
    let prepared = endpoint
        .prepare_output(now, 1, true, &mut bytes, &mut budget, &mut witnesses)?
        .ok_or("actual output")?;
    Ok((prepared, bytes[..prepared.bytes].to_vec()))
}
fn source_admission<P: RecoveryPolicy>(config: Config<P>) -> TestResult {
    let mut owner = observed(config, Role::Client)?;
    assert_eq!(
        owner
            .wait_snapshot(Tick(0))
            .ok_or("enabled diagnostics")?
            .sites[0]
            .pending,
        None
    );
    for (at, value) in [(1, 1), (10, 2)] {
        owner
            .enqueue_admitted_identified(Tick(at), 0, &packet(true, value, 48))?
            .ok_or("real native admission")?;
        owner.flush(Tick(at))?;
    }
    let refused = owner
        .wait_snapshot(Tick(10))
        .ok_or("actual source refusal")?;
    let pending = refused.sites[0].pending.ok_or("retained source")?;
    assert_eq!(pending.operation.id, 1);
    assert_eq!(pending.since, Tick(10));
    assert_eq!(pending.operation.deadline, owner.stage_deadline);
    // The downstream owner is still occupied. A temporary sentinel in the
    // private output slab detects a second encoding, even if it would have
    // produced identical bytes. Restore that byte before allowing admission.
    let original = owner.source[0];
    owner.source[0] = !original;
    owner.step(Tick(12), work())?;
    assert_eq!(owner.source[0], !original);
    owner.source[0] = original;
    assert_eq!(
        owner.wait_snapshot(Tick(12)).ok_or("retry")?.sites[0]
            .pending
            .ok_or("same source")?
            .since,
        Tick(10)
    );
    let (first, _) = output(&mut owner, Tick(20))?;
    owner.confirm_output(Tick(20), first)?;
    owner.step(Tick(21), work())?;
    let done = owner
        .wait_snapshot(Tick(21))
        .ok_or("actual successful admission")?;
    assert_eq!(done.sites[0].union.completed_episodes, 1);
    assert_eq!(done.sites[0].union.completed_us, 11);
    assert_eq!(
        done.sites[0]
            .last_resolved
            .ok_or("resolved identity")?
            .operation,
        pending.operation
    );
    assert!(done.sites[0].pending.is_none());
    assert!(!done.identity_mismatch);
    owner
        .enqueue_admitted_identified(Tick(30), 0, &packet(true, 3, 48))?
        .ok_or("third native")?;
    owner.flush(Tick(30))?;
    let pending = owner.wait_snapshot(Tick(30)).ok_or("third refused")?.sites[0]
        .pending
        .ok_or("third source")?;
    let failed_at = Tick(1_000_021);
    assert!(owner.step(failed_at, work()).is_err());
    let failed = owner
        .wait_snapshot(Tick(failed_at.0 + 100))
        .ok_or("failed snapshot")?
        .sites[0];
    assert_eq!(failed.union.completed_episodes, 1);
    assert_eq!(failed.union.censored_episodes, 1);
    assert_eq!(
        failed.last_resolved.ok_or("censored identity")?.operation,
        pending.operation
    );
    let terminal = owner
        .wait_snapshot(Tick(failed_at.0 + 200))
        .ok_or("terminal snapshot")?;
    assert_eq!(terminal.terminal, Some((failed_at, Terminal::OwnerFailure)));
    Ok(())
}
#[test]
fn actual_rolling_and_research_source_wait_keeps_identity_and_original_deadline() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    source_admission(config)?;
    source_admission(research_config(config))
}
fn receive_pressure<P: RecoveryPolicy>(config: Config<P>) -> TestResult {
    let mut sender = observed(config, Role::Client)?;
    let mut receiver = observed(config, Role::Server)?;
    for (at, value) in [(1, 1), (20, 2)] {
        sender
            .enqueue_admitted_identified(Tick(at), 0, &packet(true, value, 48))?
            .ok_or("native admission")?;
        sender.flush(Tick(at))?;
        let (prepared, wire) = output(&mut sender, Tick(at))?;
        sender.confirm_output(Tick(at), prepared)?;
        receiver.accept_authenticated(Tick(at), prepared.kind, &wire)?;
        for _ in 0..16 {
            receiver.step(Tick(at), work())?;
        }
    }
    let before = receiver.wait_snapshot(Tick(20)).ok_or("receive snapshot")?;
    let pending = before.sites[Site::DecodedHandoff.index()]
        .pending
        .ok_or("actual receiver capacity refusal")?;
    assert_eq!(pending.operation.id, 1);
    assert!(pending.operation.deadline.is_some());
    assert_eq!(pending.since, Tick(20));
    let mut native = [0; 1024];
    let mut committed = false;
    for _ in 0..8 {
        if let NativePreparation::Ready(prepared) =
            receiver.prepare_native(Tick(30), 16, Tick(10000), &mut native)?
        {
            receiver.commit_native(Tick(30), prepared.token())?;
            committed = true;
            break;
        }
    }
    assert!(committed);
    for _ in 0..16 {
        receiver.step(Tick(31), work())?;
    }
    let after = receiver
        .wait_snapshot(Tick(31))
        .ok_or("same decoded source handoff")?;
    let row = after.sites[Site::DecodedHandoff.index()];
    assert_eq!(row.union.completed_episodes, 1);
    assert!(row.pending.is_none());
    assert_eq!(
        row.last_resolved.ok_or("exact handoff")?.operation,
        pending.operation
    );
    assert!(!after.identity_mismatch);
    Ok(())
}
#[test]
fn actual_decoded_source_wait_ends_only_after_record_capacity_is_released() -> TestResult {
    let mut config = config(true, rolling::wire::SourceWire::Exact);
    for direction in [&mut config.forward, &mut config.reverse] {
        direction.receiver.lookahead_records = 0;
        direction.receiver.body.independent_short_frame_bytes = 0;
        direction.packing.sender.body = direction.receiver.body;
    }
    receive_pressure(config)?;
    receive_pressure(research_config(config))
}
fn feedback_budget<P: RecoveryPolicy>(config: Config<P>) -> TestResult {
    let mut sender = observed(config, Role::Client)?;
    let mut receiver = observed(config, Role::Server)?;
    let mut bytes = [0; rolling::wire::MAX_RECORD_BYTES];
    let mut witnesses = [witness(); 4];
    let mut empty = OutboundBudget {
        packets: 0,
        wire_bytes: 0,
    };
    assert!(
        receiver
            .prepare_output(Tick(0), 1, false, &mut bytes, &mut empty, &mut witnesses)?
            .is_none()
    );
    assert!(
        receiver.wait_snapshot(Tick(0)).ok_or("idle")?.sites[2]
            .pending
            .is_none()
    );
    sender
        .enqueue_admitted_identified(Tick(1), 0, &packet(true, 4, 48))?
        .ok_or("actual native")?;
    sender.flush(Tick(1))?;
    let (prepared, wire) = output(&mut sender, Tick(1))?;
    sender.confirm_output(Tick(1), prepared)?;
    receiver.accept_authenticated(Tick(1), prepared.kind, &wire)?;
    // Finish the staged decode at arrival time. Rolling starts its original
    // feedback delay when that decode commits, not when input is merely staged.
    for _ in 0..16 {
        receiver.step(Tick(1), work())?;
    }
    receiver.step(Tick(200), work())?;
    assert!(
        receiver
            .prepare_output(Tick(200), 2, false, &mut bytes, &mut empty, &mut witnesses)?
            .is_none()
    );
    let before = receiver
        .wait_snapshot(Tick(200))
        .ok_or("feedback refusal")?;
    let pending = before.sites[2].pending.ok_or("ready feedback")?;
    assert_eq!(pending.operation.id, 1);
    assert!(pending.operation.deadline.is_some());
    let mut exact = OutboundBudget {
        packets: pending.operation.packets,
        wire_bytes: pending.operation.wire_bytes,
    };
    let ready = receiver
        .prepare_output(Tick(207), 2, false, &mut bytes, &mut exact, &mut witnesses)?
        .ok_or("same feedback admitted")?;
    assert_eq!(ready.id, OutputId::Feedback(scheduler::FeedbackId(1)));
    assert_eq!(exact.packets, 0);
    assert_eq!(exact.wire_bytes, 0);
    assert_eq!(
        receiver.prepare_output(Tick(208), 3, false, &mut bytes, &mut empty, &mut witnesses)?,
        Some(ready)
    );
    let after = receiver
        .wait_snapshot(Tick(208))
        .ok_or("feedback progress")?;
    assert_eq!(after.sites[2].union.completed_episodes, 1);
    assert_eq!(after.sites[2].union.completed_us, 7);
    assert_eq!(after.sites[2].reasons[5].completed_us, 7);
    assert_eq!(after.sites[2].reasons[6].completed_us, 7);
    assert_eq!(
        after.sites[2]
            .last_resolved
            .ok_or("exact feedback")?
            .operation,
        pending.operation
    );
    assert!(after.sites[2].pending.is_none());
    let stopped = after.censor(Tick(208), Terminal::MetricStop);
    assert_eq!(stopped.sites[2].union.censored_episodes, 0);
    Ok(())
}
#[test]
fn actual_ready_feedback_budget_wait_does_not_include_idle_or_physical_receipt() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    feedback_budget(config)?;
    feedback_budget(research_config(config))
}

#[path = "ingress_wait_tests.rs"]
mod ingress_wait_tests;

#[path = "stage_deadline_tests.rs"]
mod stage_deadline_tests;
