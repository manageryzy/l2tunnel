//! Generic typed history and actual uncertain runtime completion boundaries.

use super::support::*;
use super::*;
use l2tunnel::swift_configuration::EnvelopeDigest;

fn assert_completed_forwarding(
    handle: &Handle,
    response: &local::Response,
    current: Configuration,
    epoch: u64,
) -> Result {
    assert_eq!(response.version, local::TRANSACTION_VERSION);
    let state = response
        .state
        .as_ref()
        .ok_or("missing completed transaction state")?;
    assert_eq!(state.phase, "forwarding");
    assert_eq!(state.epoch, epoch);
    let returned = state
        .transaction
        .as_ref()
        .ok_or("missing completed transaction status")?;
    assert_eq!(returned.epoch, Some(state.epoch));
    assert_current(returned, current, epoch)?;
    let settled = handle.snapshot();
    assert_eq!(settled.phase, Phase::Connected);
    assert!(settled.operation.is_none());
    let actual = status(handle)?;
    assert_eq!(returned.current, actual.current);
    assert_eq!(returned.epoch, actual.epoch);
    assert_eq!(returned.phase, actual.phase);
    assert_eq!(returned.operation, actual.operation);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn generic_connect_key_identity_history_and_future_bounds_use_real_prepared() -> Result {
    for appearance in appearances() {
        let hosts = hosts();
        let fixture = transaction_plans(appearance, &hosts)?;
        let equivalent = Prepared::secure_udp_transaction_server(
            fixture.profile.clone(),
            credentials::Server::new(
                credentials::NoiseIdentity::new(
                    Zeroizing::new([22; 32]),
                    fixture.profile.peers().initiator,
                    hs::Profile::Ik,
                    None,
                )?,
                credentials::Secret32::new(Zeroizing::new([44; 32]))?,
                credentials::Secret32::new(Zeroizing::new([55; 32]))?,
            )?,
            hosts[1].attachment(),
        )?;
        let plan = &fixture.plans[1];
        assert!(!Arc::ptr_eq(&plan.identity, &equivalent.identity));
        let (handle, run) = channel();
        let mut run = Box::pin(run);
        let key = handle.next_key().map_err(submit)?;
        let accepted = handle.connect(plan.clone(), key).map_err(submit)?;
        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(handle.connect(plan.clone(), key), Ok(accepted));
        assert_eq!(
            handle.connect(equivalent.clone(), key),
            Err(SubmitError::Conflict)
        );
        assert_eq!(
            handle.connect(plan.clone(), RequestKey::new(3).ok_or("invalid test key")?),
            Err(SubmitError::FutureKey)
        );
        handle.cancel(accepted.operation).map_err(submit)?;
        assert_eq!(
            single_result(&mut run, &handle, accepted.operation).await?,
            Completed::Cancelled
        );
        for _ in 1..40 {
            let next = handle
                .connect(plan.clone(), handle.next_key().map_err(submit)?)
                .map_err(submit)?;
            handle.cancel(next.operation).map_err(submit)?;
            assert_eq!(
                single_result(&mut run, &handle, next.operation).await?,
                Completed::Cancelled
            );
        }
        assert_eq!(handle.connect(plan.clone(), key), Err(SubmitError::Expired));
        assert_eq!(
            handle.wait(accepted.operation).await,
            Err(SubmitError::Expired)
        );
        assert_eq!(
            handle.connect(equivalent, RequestKey::new(40).ok_or("invalid test key")?),
            Err(SubmitError::Conflict)
        );
        assert_eq!(
            handle.connect(plan.clone(), RequestKey::new(42).ok_or("invalid test key")?),
            Err(SubmitError::FutureKey)
        );
        assert_eq!(handle.next_key().map_err(submit)?.value(), 41);
        assert_eq!(handle.0.lock().entries.len(), 32);
        assert_eq!(handle.0.lock().retired_through, 8);
        assert_unopened(&hosts);
        drop(run);
        assert_ports_free(fixture.addresses)?;
    }
    Ok(())
}

#[tokio::test]
async fn generic_apply_waiter_replay_catalog_and_replacement_preserve_one_actual_switch() -> Result
{
    for appearance in appearances() {
        let hosts = hosts();
        let fixture = transaction_plans(appearance, &hosts)?;
        let mut pair = Pair::new(fixture, hosts)?;
        pair.ready().await?;
        let initial = pair.fixture.initial;
        let target = pair.fixture.target;
        let before = status(&pair.handles[0])?;
        let key = pair.handles[0].next_key().map_err(submit)?;
        let foreign = Configuration::new(EnvelopeDigest::new([0xfd; 32]), target.descriptor())?;
        for outside in [pair.fixture.outside, foreign] {
            let history_before = history(&pair.handles[0]);
            assert_eq!(
                pair.handles[0].apply_transaction(outside, key),
                Err(SubmitError::InvalidConfiguration)
            );
            assert_eq!(history(&pair.handles[0]), history_before);
        }
        let accepted = pair.handles[0]
            .apply_transaction(target, key)
            .map_err(submit)?;
        let mut waiter = Box::pin(pair.handles[0].wait(accepted.operation));
        std::future::poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(waiter);
        assert_eq!(
            pair.handles[0].cancel(accepted.operation),
            Err(SubmitError::Unsupported)
        );
        assert_eq!(pair.handles[0].apply_transaction(target, key), Ok(accepted));
        assert_eq!(
            pair.handles[0].apply_transaction(initial, key),
            Err(SubmitError::Conflict)
        );
        let next = pair.handles[0].next_key().map_err(submit)?;
        assert_eq!(
            pair.handles[0].apply_transaction(target, next),
            Err(SubmitError::Busy)
        );
        assert_eq!(pair.handles[0].next_key().map_err(submit)?, next);
        let result = pair.result(0, accepted.operation).await?;
        let Completed::Applied(response) = &result else {
            return Err("real apply did not complete".into());
        };
        assert_eq!(response.code, "ok");
        let switched = transaction_response(response)?;
        assert_current(
            switched,
            target,
            before.epoch.ok_or("missing initial epoch")? + 1,
        )?;
        assert_completed_forwarding(
            &pair.handles[0],
            response,
            target,
            before.epoch.ok_or("missing initial epoch")? + 1,
        )?;
        pair.until(|pair| {
            Ok(status(&pair.handles[1])?.operation.is_none()
                && status(&pair.handles[1])?.phase == Some(transaction_status::Phase::Idle))
        })
        .await?;
        assert_eq!(pair.handles[0].apply_transaction(target, key), Ok(accepted));
        assert_eq!(
            pair.handles[0]
                .wait(accepted.operation)
                .await
                .map_err(submit)?,
            result
        );
        for side in 0..2 {
            let disconnected = pair.handles[side]
                .disconnect(pair.handles[side].next_key().map_err(submit)?)
                .map_err(submit)?;
            assert_eq!(
                pair.result(side, disconnected.operation).await?,
                Completed::Aborted
            );
        }
        for side in 0..2 {
            pair.accepted[side] = pair.handles[side]
                .submit_local_lifecycle(local::TRANSACTION_VERSION, true)
                .map_err(|_| "actual retained-plan reconnect was refused")?;
        }
        pair.ready().await?;
        let fresh = status(&pair.handles[0])?;
        assert_ne!(fresh.session, before.session);
        assert_ne!(fresh.transcript, before.transcript);
        assert_current(
            &fresh,
            initial,
            before.epoch.ok_or("missing initial epoch")?,
        )?;
        let history_before = history(&pair.handles[0]);
        assert_eq!(pair.handles[0].apply_transaction(target, key), Ok(accepted));
        assert_eq!(
            pair.handles[0]
                .wait(accepted.operation)
                .await
                .map_err(submit)?,
            result
        );
        assert_eq!(history(&pair.handles[0]), history_before);
        assert_eq!(status(&pair.handles[0])?, fresh);
        pair.exchange(0, 117).await?;
        pair.close()?;
    }
    Ok(())
}

async fn actual_pending_request(
    pair: &mut Pair,
    before: &transaction_status::Status,
) -> Result<transaction_status::Status> {
    timeout(Duration::from_secs(1), async {
        loop {
            pair.drive_side(0).await?;
            let actual = status(&pair.handles[0])?;
            if actual.operation.is_some()
                && actual.phase == Some(transaction_status::Phase::AwaitReady)
                && actual.security.and_then(|value| value.control_number)
                    > before.security.and_then(|value| value.control_number)
                && actual.wire.map(|value| value.socket_accepted_packets)
                    > before.wire.map(|value| value.socket_accepted_packets)
            {
                return Ok::<_, Error>(actual);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?
}

#[tokio::test]
async fn generic_actual_inflight_owner_loss_and_original_cap_expiry_are_unknown() -> Result {
    for appearance in appearances() {
        for expire in [false, true] {
            let hosts = hosts();
            let fixture = transaction_plans_with(
                appearance,
                &hosts,
                TransactionFixtureOptions {
                    report_interval: Some(Duration::from_millis(1)),
                    ..TransactionFixtureOptions::baseline()
                },
            )?;
            let mut pair = Pair::new(fixture, hosts)?;
            pair.ready().await?;
            let before = status(&pair.handles[0])?;
            let accepted = pair.handles[0]
                .apply_transaction(
                    pair.fixture.target,
                    pair.handles[0].next_key().map_err(submit)?,
                )
                .map_err(submit)?;
            // Keep the genuine peer's socket/runtime owned, but do not poll it.
            assert_eq!(
                std::net::UdpSocket::bind(pair.fixture.addresses[1])
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::AddrInUse)
            );
            let pending = actual_pending_request(&mut pair, &before).await?;
            let operation = pending
                .operation
                .as_ref()
                .ok_or("missing actual retained operation")?;
            assert_eq!(
                pending
                    .requested
                    .as_ref()
                    .map(|value| value.configuration())
                    .transpose()?,
                Some(pair.fixture.target)
            );
            assert_eq!(pending.current, before.current);
            assert_eq!(pending.epoch, before.epoch);
            if !expire {
                drop(pair.runs[0].take());
                let mut expected = pending;
                expected.running = false;
                expected.service_terminal = Some("Aborted".into());
                assert_eq!(status(&pair.handles[0])?, expected);
                assert_eq!(pair.handles[0].snapshot().phase, Phase::Closed);
                assert_eq!(pair.hosts[0].live.load(Ordering::SeqCst), 0);
            } else {
                let cap = operation.expires_millis;
                let elapsed = pending.elapsed_micros.ok_or("missing actual report time")?;
                let remaining = cap
                    .checked_mul(1000)
                    .and_then(|cap| cap.checked_sub(elapsed))
                    .ok_or("pending observation already exceeded original cap")?;
                tokio::time::pause();
                tokio::time::advance(Duration::from_micros(remaining) + Duration::from_millis(1))
                    .await;
                timeout(Duration::from_secs(1), async {
                    loop {
                        pair.drive_side(0).await?;
                        if completed(&pair.handles[0], accepted.operation).is_some() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Ok::<_, Error>(())
                })
                .await??;
                let stopped = status(&pair.handles[0])?;
                assert!(!stopped.running);
                assert_eq!(stopped.current, before.current);
                assert_eq!(stopped.epoch, before.epoch);
                assert_eq!(stopped.terminal.as_deref(), Some("PolicyTimeout"));
                let frame = pair.handles[0]
                    .snapshot()
                    .runtime
                    .and_then(|value| match value {
                        Observation::SecureUdpTransaction(frame) => Some(frame),
                        _ => None,
                    })
                    .ok_or("missing actual final frame")?;
                assert_eq!(
                    frame.service_terminal,
                    Some(Terminal::Failed(Failure {
                        kind: io::ErrorKind::TimedOut
                    }))
                );
                assert_eq!(
                    pending.operation.as_ref().map(|value| value.expires_millis),
                    Some(cap)
                );
                tokio::time::resume();
            }
            assert_eq!(
                pair.handles[0]
                    .wait(accepted.operation)
                    .await
                    .map_err(submit)?,
                Completed::OutcomeUnknown
            );
            pair.close()?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn generic_actual_follower_request_completes_not_coordinator_rejection() -> Result {
    for appearance in appearances() {
        let hosts = hosts();
        let fixture = transaction_plans(appearance, &hosts)?;
        let mut pair = Pair::new(fixture, hosts)?;
        pair.ready().await?;
        let before = [status(&pair.handles[0])?, status(&pair.handles[1])?];
        let key = pair.handles[1].next_key().map_err(submit)?;
        let accepted = pair.handles[1]
            .apply_transaction(pair.fixture.target, key)
            .map_err(submit)?;
        let result = pair.result(1, accepted.operation).await?;
        let Completed::Rejected(response) = &result else {
            return Err("follower request was not a definitive rejection".into());
        };
        assert_eq!(response.version, local::TRANSACTION_VERSION);
        assert!(!response.ok);
        assert_eq!(response.code, "not_coordinator");
        let returned = response
            .state
            .as_ref()
            .and_then(|state| state.transaction.as_ref())
            .ok_or("missing actual follower status")?;
        assert_eq!(returned.current, before[1].current);
        assert_eq!(returned.epoch, before[1].epoch);
        assert_completed_forwarding(
            &pair.handles[1],
            response,
            pair.fixture.initial,
            before[1].epoch.ok_or("missing initial follower epoch")?,
        )?;
        assert_eq!(
            pair.handles[1].apply_transaction(pair.fixture.target, key),
            Ok(accepted)
        );
        assert_eq!(
            pair.handles[1]
                .wait(accepted.operation)
                .await
                .map_err(submit)?,
            result
        );
        for (side, before) in before.iter().enumerate() {
            let after = status(&pair.handles[side])?;
            assert_eq!(after.current, before.current);
            assert_eq!(after.epoch, before.epoch);
            assert!(after.operation.is_none());
        }
        pair.close()?;
    }
    Ok(())
}
