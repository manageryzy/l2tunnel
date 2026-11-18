use super::*;
use std::time::Duration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn observed(config: Config) -> Result<Endpoint> {
    let plan = storage::Plan::for_duplex(config, config)?.with_receiver_handoff_diagnostics()?;
    Ok(Endpoint::new_reserved_with_plan(
        plan,
        tests::context(EndpointRole::Responder),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}

#[test]
fn receiver_handoff_actual_original_expiry_censors_only_the_refused_source() -> Result {
    let mut config = tests::config(20);
    config.receiver.lookahead_records = 0;
    config.receiver.lookahead_bytes = 0;
    config.receiver.lookahead_fragments = 0;
    let mut left = Endpoint::new(config, tests::context(EndpointRole::Initiator))?;
    let mut right = observed(config)?;
    let frames = [vec![17; 500], vec![29; 90], vec![33; 66]];
    let mut next = 0;
    let mut packet = vec![0; left.max_packet_bytes().max(right.max_packet_bytes())];
    for tick in 0..1000 {
        let now = Duration::from_millis(tick);
        if next < frames.len() && !left.status().staged_frame {
            left.enqueue_admitted(ChannelId(0), &frames[next], now)?;
            next += 1;
        }
        let mut budget = OutboundBudget {
            packets: 2,
            wire_bytes: 2 * (left.max_packet_bytes() + 28),
        };
        for _ in 0..2 {
            if let Some(bytes) = left.poll_data(now, &mut packet, &mut budget)? {
                right.receive_authenticated(&packet[..bytes], now)?;
            }
        }
        let mut budget = OutboundBudget {
            packets: 64,
            wire_bytes: 64 * (right.max_packet_bytes() + 28),
        };
        if let Some(bytes) = right.poll_feedback(now, &mut packet, &mut budget)? {
            left.receive_authenticated(&packet[..bytes], now)?;
        }
        right.prepare(ChannelId(0), now, 8)?;
        let snapshot = right
            .receiver_handoff_snapshot(now)
            .ok_or("enabled observer")?;
        let Some(pending) = snapshot.pending else {
            continue;
        };
        let (source, bytes, deadline) = right.handoff.ok_or("actual held source")?;
        assert_eq!(
            pending.identity,
            receiver_handoff::Identity {
                source,
                bytes,
                deadline
            }
        );
        // Another real refused attempt neither replaces the operation nor renews its cap.
        right.prepare(ChannelId(0), now + Duration::from_millis(1), 8)?;
        let repeated = right.receiver_handoff_snapshot(right.now).ok_or("repeat")?;
        assert_eq!(
            repeated.pending.ok_or("same source")?.identity,
            pending.identity
        );
        assert_eq!(repeated.pending.ok_or("same start")?.since, pending.since);
        assert_eq!(right.tick(deadline), Err(Error::Expired));
        let terminal = right
            .receiver_handoff_snapshot(deadline + Duration::from_secs(1))
            .ok_or("terminal")?;
        assert_eq!(terminal.terminal_at, Some(deadline));
        assert_eq!(
            terminal.terminal,
            Some(receiver_handoff::Terminal::OwnerFailure)
        );
        assert_eq!(terminal.totals.censored_episodes, 1);
        assert_eq!(
            terminal
                .maximum_censored
                .ok_or("original censored identity")?
                .pending
                .identity,
            pending.identity
        );
        assert_eq!(terminal.totals.completed_episodes, 0);
        assert!(terminal.pending.is_none());
        assert!(right.status().retained_handoff);
        return Ok(());
    }
    Err("real pressure did not reach an actual handoff refusal".into())
}

#[test]
fn receiver_handoff_empty_idle_and_disabled_owner_do_not_invent_waits() -> Result {
    let config = tests::config(128);
    let base = storage::Plan::for_duplex(config, config)?;
    let plan = base.with_receiver_handoff_diagnostics()?;
    assert_eq!(plan.with_receiver_handoff_diagnostics()?, plan);
    assert_eq!(
        plan.capacity_bytes() - base.capacity_bytes(),
        std::mem::size_of::<receiver_handoff::State>()
    );
    let mut enabled = observed(config)?;
    let disabled = Endpoint::new_reserved_with_plan(
        base,
        tests::context(EndpointRole::Responder),
        storage::Limits {
            capacity_bytes: base.capacity_bytes(),
        },
    )?;
    assert!(disabled.receiver_handoff_snapshot(Duration::ZERO).is_none());
    assert_eq!(
        enabled.prepare(ChannelId(0), Duration::from_millis(10), 8)?,
        Prepared::Idle
    );
    let snapshot = enabled
        .receiver_handoff_snapshot(Duration::from_millis(10))
        .ok_or("enabled")?;
    assert_eq!(snapshot.refusals, [0, 0]);
    assert_eq!(snapshot.totals, receiver_handoff::Totals::default());
    assert!(snapshot.pending.is_none());
    assert_eq!(
        enabled.storage_usage().ok_or("usage")?.allocations,
        disabled
            .storage_usage()
            .ok_or("disabled usage")?
            .allocations
            + 1
    );
    assert!(
        Endpoint::new_reserved_with_plan(
            plan,
            tests::context(EndpointRole::Responder),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn receiver_handoff_copy_censor_needs_fresh_time_and_never_changes_owner() {
    let scope = receiver::Scope {
        session: [1; 16],
        epoch: Epoch(7),
        direction: receiver::Direction::InitiatorToResponder,
    };
    let mut state = receiver_handoff::State::new(scope, false);
    let identity = receiver_handoff::Identity {
        source: 17,
        bytes: 83,
        deadline: Duration::from_secs(1),
    };
    state.refused(
        identity,
        Duration::from_micros(10),
        receiver_handoff::Reason::RecordWindow,
    );
    let fresh = state.snapshot(Duration::from_micros(20));
    let stale = fresh.censor(Duration::from_micros(21));
    assert!(stale.terminal_unavailable && stale.pending.is_some());
    assert_eq!(stale.totals.censored_episodes, 0);
    let terminal = fresh.censor(Duration::from_micros(20));
    assert_eq!(terminal.totals.censored, Duration::from_micros(10));
    assert_eq!(
        terminal.maximum_censored.map(|v| v.pending.identity),
        Some(identity)
    );
    assert_eq!(state.snapshot(Duration::from_micros(20)), fresh);
}
