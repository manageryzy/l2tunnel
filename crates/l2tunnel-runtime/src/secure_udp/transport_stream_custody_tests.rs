//! Rejected policy custody on the actual Driver and original protected UDP pair.

use super::*;

fn lose_proposal_ack(attempt: &Attempt) -> bool {
    attempt.side == Side::B
        && matches!(
            attempt.traffic,
            Traffic::Ack {
                stream: streams::Stream::Transaction,
                ..
            }
        )
}

// Reuse the fixture's actual socket send/receive and bounded trace. Only its
// receiving resolver changes: B genuinely refuses the requested policy. The
// intercepted attempt is marked delivered after the ordinary Driver dispatch.
async fn rejecting_turn(
    fixture: &mut FaultFixture,
    side: Side,
    at: u64,
    fault: &mut impl FnMut(&Attempt) -> bool,
) -> Result<bool> {
    let mut dispatch = false;
    let emitted = fixture
        .turn(side, at, &mut |attempt| {
            let dropped = fault(attempt);
            if side == Side::A && !dropped {
                dispatch = true;
                true
            } else {
                dropped
            }
        })
        .await?;
    if dispatch {
        let (left, right) = fixture.endpoints.split_at_mut(1);
        let attempt = fixture
            .attempts
            .last_mut()
            .ok_or("missing handed attempt")?;
        let length = attempt.wire_bytes - left[0].driver.ip;
        let packet = left[0].driver.wire[..length].to_vec();
        let receiver = &mut right[0].driver;
        let refuse: Resolver = Box::new(|_| None);
        assert!(receiver.check_expiry(at)?);
        receiver.receive(&packet, at, receiver.origin + duration(at), &refuse)?;
        receiver.collect_native(at)?;
        attempt.dropped = false;
    }
    Ok(emitted)
}

async fn rejecting_pump(
    fixture: &mut FaultFixture,
    at: u64,
    fault: &mut impl FnMut(&Attempt) -> bool,
) -> Result {
    for _ in 0..64 {
        let a = rejecting_turn(fixture, Side::A, at, fault).await?;
        let b = rejecting_turn(fixture, Side::B, at, fault).await?;
        if !a && !b {
            return Ok(());
        }
    }
    Err("rejected-policy fixture exceeded its per-time work bound".into())
}

async fn hold_rejected_proposal(
    fixture: &mut FaultFixture,
    response: &mut oneshot::Receiver<std::result::Result<u64, SwitchError>>,
    original: policy::Outbound,
    deadline: policy::Time,
) -> Result<u64> {
    for step in 0..200 {
        let at = fixture.start + step * 1_000;
        rejecting_pump(fixture, at, &mut lose_proposal_ack).await?;
        let lost_ack = fixture.attempts.iter().any(|attempt| {
            attempt.dropped
                && attempt.side == Side::B
                && matches!(attempt.traffic,
                    Traffic::Ack { stream: streams::Stream::Transaction, prefix } if prefix >= 1)
        });
        let driver = &mut fixture.endpoints[0].driver;
        if driver.coordinator.pending().is_some()
            || driver.pending_outcome != Some(policy::Outcome::Rejected)
            || driver.challenge.is_some()
            || !lost_ack
        {
            continue;
        }
        let pending = driver
            .policy_source
            .as_ref()
            .ok_or("Reject discarded the original transport token")?;
        let token = pending.source;
        assert_eq!(pending.id, original.id);
        assert_eq!(driver.coordinator.outbound(), Some(original));
        assert!(!driver.control.confirmed(token, duration(at))?);
        assert_eq!(driver.coordinator.deadline(), None);
        assert_eq!(driver.policy_cap, Some(deadline.0));
        assert_eq!(driver.coordinator.committed().epoch, policy::Epoch(0));
        assert_eq!(driver.source_scope, driver.records.active_data());
        assert_eq!(driver.feedback_scope, driver.records.active_data());
        assert!(driver.target.is_some());
        assert!(driver.records.additional_data().is_some());
        assert!(matches!(
            response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(lost_ack);
        assert!(fixture.attempts.iter().any(|attempt| {
            !attempt.dropped
                && attempt.side == Side::B
                && matches!(
                    attempt.traffic,
                    Traffic::Source {
                        stream: streams::Stream::Transaction,
                        kind: messages::ACCEPTED_KIND,
                        ..
                    }
                )
        }));
        assert!(fixture.attempts.iter().any(|attempt| {
            !attempt.dropped
                && attempt.side == Side::B
                && matches!(
                    attempt.traffic,
                    Traffic::Source {
                        stream: streams::Stream::Transaction,
                        kind: messages::FRAGMENT_KIND,
                        ..
                    }
                )
        }));
        return Ok(at);
    }
    Err("real Reject did not arrive while its original proposal ACK was lost".into())
}

#[tokio::test]
async fn reject_before_original_source_ack_keeps_custody_until_one_rejected_outcome() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = FaultFixture::new(appearance).await?;
        let mut response = fixture.request()?;
        let original = fixture.endpoints[0]
            .driver
            .coordinator
            .outbound()
            .ok_or("missing original proposal")?;
        let deadline = fixture.endpoints[0]
            .driver
            .coordinator
            .deadline()
            .ok_or("missing original deadline")?;
        let scope = fixture.endpoints[0].driver.records.active_data();
        let held = hold_rejected_proposal(&mut fixture, &mut response, original, deadline).await?;
        let mut observed = false;
        let mut finished = None;
        for step in 1..500 {
            let at = held + step * 1_000;
            rejecting_pump(&mut fixture, at, &mut |_| false).await?;
            if !observed {
                match response.try_recv() {
                    Ok(Err(SwitchError::Rejected)) => observed = true,
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    other => {
                        return Err(format!("unexpected rejected-policy result: {other:?}").into());
                    }
                }
            }
            if observed
                && fixture.endpoints.iter().all(|endpoint| {
                    let driver = &endpoint.driver;
                    driver.policy_source.is_none()
                        && driver.coordinator.outbound().is_none()
                        && driver.policy_cap.is_none()
                        && !driver.control.has_dispatched()
                })
            {
                finished = Some(at);
                break;
            }
        }
        let finished = finished.ok_or("recovered proposal ACK did not settle rejected custody")?;
        assert!(finished < deadline.0);
        assert!(matches!(
            response.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        for endpoint in &fixture.endpoints {
            let driver = &endpoint.driver;
            assert_eq!(driver.coordinator.committed().epoch, policy::Epoch(0));
            assert!(driver.coordinator.pending().is_none());
            assert_eq!(driver.coordinator.outbound(), None);
            assert_eq!(driver.records.active_data(), scope);
            assert_eq!(driver.source_scope, scope);
            assert_eq!(driver.feedback_scope, scope);
            assert!(driver.target.is_none());
            assert!(driver.records.additional_data().is_none());
            assert!(driver.pending_outcome.is_none());
            assert!(driver.transaction_origin.is_none());
            assert!(driver.terminal.is_none());
        }
        fixture.accounting(finished)?;
    }
    Ok(())
}

#[tokio::test]
async fn rejected_custody_wakes_and_expires_at_original_cap_without_wire_credit() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for late in [0, 1] {
            let mut fixture = FaultFixture::new(appearance).await?;
            let mut response = fixture.request()?;
            let original = fixture.endpoints[0]
                .driver
                .coordinator
                .outbound()
                .ok_or("missing original proposal")?;
            let deadline = fixture.endpoints[0]
                .driver
                .coordinator
                .deadline()
                .ok_or("missing original deadline")?;
            hold_rejected_proposal(&mut fixture, &mut response, original, deadline).await?;
            let driver = &mut fixture.endpoints[0].driver;
            let pending = driver
                .policy_source
                .as_ref()
                .ok_or("missing proposal custody")?;
            let token = pending.source;
            let before = deadline.0 - 200;
            // Trusted local scheduler setup: exhaust existing credit, and put
            // independent periodic wakes after D. No timeout or rate changes.
            driver.bucket.tokens = 0;
            driver.bucket.last = before;
            driver.next_ping = deadline.0 + 1_000_000;
            driver.next_report = None;
            assert!(driver.challenge.is_none());
            assert!(driver.native.is_empty());
            assert!(driver.swift.data_deadline().is_none());
            assert!(driver.swift.feedback_deadline().is_none());
            assert!(driver.bucket.ready_at(driver.reserve)? > deadline.0);
            assert!(driver.control.deadline() < duration(deadline.0));
            let wake = driver.wake(before)?;
            assert!(wake <= driver.origin + duration(deadline.0));
            assert!(driver.check_expiry(before)?);
            assert!(!driver.control.confirmed(token, duration(before))?);
            assert_eq!(driver.policy_cap, Some(deadline.0));
            assert_eq!(driver.coordinator.outbound(), Some(original));
            assert!(matches!(
                response.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            let error = driver
                .progress(deadline.0 + late)
                .err()
                .ok_or("original rejected-policy custody must expire before completion")?;
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(driver.terminal, Some(StopReason::PolicyTimeout));
            assert_eq!(
                driver.policy_source.as_ref().map(|pending| pending.id),
                Some(original.id)
            );
            assert_eq!(driver.coordinator.outbound(), Some(original));
            assert_eq!(driver.pending_outcome, Some(policy::Outcome::Rejected));
            assert_eq!(driver.coordinator.committed().epoch, policy::Epoch(0));
            assert!(matches!(
                response.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
        }
    }
    Ok(())
}
