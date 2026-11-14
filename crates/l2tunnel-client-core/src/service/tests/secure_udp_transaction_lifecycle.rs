//! Actual generic setup cancellation, inline ownership and fresh replacement.

use super::support::*;
use super::*;
use l2tunnel_runtime::secure_udp::diagnostics;

#[tokio::test]
async fn generic_cancel_queued_and_admission_releases_original_socket_and_freezes_record() -> Result
{
    for appearance in appearances() {
        for polled in [false, true] {
            let hosts = hosts();
            let fixture = transaction_plans(appearance, &hosts)?;
            let peer = std::net::UdpSocket::bind(fixture.addresses[1])?;
            peer.set_nonblocking(true)?;
            let local = if polled {
                None
            } else {
                Some(std::net::UdpSocket::bind(fixture.addresses[0])?)
            };
            let (handle, run) = channel();
            let mut run = Box::pin(run);
            let accepted = handle
                .connect(fixture.plans[0].clone(), handle.next_key().map_err(submit)?)
                .map_err(submit)?;
            if polled {
                timeout(Duration::from_secs(1), async {
                    loop {
                        drive_once(&mut run).await;
                        if observation(&handle, accepted.operation)?.stage == SetupStage::Admission
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    Ok::<_, Error>(())
                })
                .await??;
                assert_eq!(
                    std::net::UdpSocket::bind(fixture.addresses[0])
                        .err()
                        .map(|error| error.kind()),
                    Some(io::ErrorKind::AddrInUse)
                );
            }
            handle.cancel(accepted.operation).map_err(submit)?;
            assert_eq!(
                single_result(&mut run, &handle, accepted.operation).await?,
                Completed::Cancelled
            );
            let cancelled = observation(&handle, accepted.operation)?;
            assert_eq!(cancelled.outcome, SetupOutcome::Cancelled);
            assert_eq!(
                cancelled.stage,
                if polled {
                    SetupStage::Admission
                } else {
                    SetupStage::Accepted
                }
            );
            assert!(cancelled.failure.is_none());
            assert_eq!(cancelled.runtime.is_some(), polled);
            assert!(handle.snapshot().generation.is_none());
            let next = handle
                .connect(fixture.plans[0].clone(), handle.next_key().map_err(submit)?)
                .map_err(submit)?;
            let pending = observation(&handle, next.operation)?;
            crate::service::setup::stage(
                &handle.0,
                accepted.operation,
                SetupStage::DriverReadiness,
            );
            crate::service::setup::runtime(
                &handle.0,
                accepted.operation,
                diagnostics::Observation::new(diagnostics::Stage::Noise),
            );
            assert_eq!(observation(&handle, accepted.operation)?, cancelled);
            assert_eq!(observation(&handle, next.operation)?, pending);
            handle.cancel(next.operation).map_err(submit)?;
            assert_eq!(
                single_result(&mut run, &handle, next.operation).await?,
                Completed::Cancelled
            );
            if !polled {
                assert_eq!(
                    peer.recv_from(&mut [0; 1]).err().map(|error| error.kind()),
                    Some(io::ErrorKind::WouldBlock)
                );
            }
            assert_unopened(&hosts);
            drop(run);
            drop(local);
            drop(peer);
            assert_ports_free(fixture.addresses)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn generic_cancel_from_authenticated_opener_drops_actual_device_before_completion() -> Result
{
    for appearance in appearances() {
        let hosts = hosts();
        let mut fixture = transaction_plans(appearance, &hosts)?;
        let action = Arc::new(Mutex::new(None::<(Handle, OperationId)>));
        let callback = action.clone();
        let during = Arc::new(Mutex::new(None));
        let captured = during.clone();
        let original = hosts[0].attachment();
        Arc::get_mut(&mut fixture.plans[0].data)
            .ok_or("fixture already shared")?
            .attachment = Attachment::readable(PacketLayer::Ip, move || {
            let device = original.open_readable()?;
            let (handle, operation) = callback
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .cloned()
                .ok_or_else(|| io::Error::other("missing actual cancellation identity"))?;
            *captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                handle.setup_observation(operation).map_err(submit)?;
            handle.cancel(operation).map_err(submit)?;
            Ok(device)
        });
        let mut pair = Pair::new(fixture, hosts)?;
        *action
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((pair.handles[0].clone(), pair.accepted[0].operation));
        let operation = pair.accepted[0].operation;
        assert_eq!(pair.result(0, operation).await?, Completed::Cancelled);
        let during = during
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ok_or("authenticated opener was not called")?;
        assert_eq!(during.stage, SetupStage::Attachment);
        assert_eq!(
            during
                .runtime
                .ok_or("missing actual member completion")?
                .stage,
            diagnostics::Stage::Membership
        );
        let cancelled = observation(&pair.handles[0], operation)?;
        assert_eq!(cancelled.stage, SetupStage::DriverReadiness);
        assert_eq!(cancelled.outcome, SetupOutcome::Cancelled);
        assert!(cancelled.failure.is_none() && pair.handles[0].snapshot().generation.is_none());
        assert_eq!(pair.hosts[0].opened.load(Ordering::SeqCst), 1);
        assert_eq!(pair.hosts[0].live.load(Ordering::SeqCst), 0);
        drop(std::net::UdpSocket::bind(pair.fixture.addresses[0])?);
        pair.close()?;
        assert_eq!(observation(&pair.handles[0], operation)?, cancelled);
    }
    Ok(())
}

#[tokio::test]
async fn generic_run_drop_at_queued_admission_and_ready_boundaries_retains_truth() -> Result {
    for appearance in appearances() {
        for polled in [false, true] {
            let hosts = hosts();
            let fixture = transaction_plans(appearance, &hosts)?;
            let peer = std::net::UdpSocket::bind(fixture.addresses[1])?;
            let (handle, run) = channel();
            let mut run = Box::pin(run);
            let accepted = handle
                .connect(fixture.plans[0].clone(), handle.next_key().map_err(submit)?)
                .map_err(submit)?;
            if polled {
                drive_once(&mut run).await;
            }
            let before = observation(&handle, accepted.operation)?;
            assert_eq!(
                before.stage,
                if polled {
                    SetupStage::Admission
                } else {
                    SetupStage::Accepted
                }
            );
            drop(run);
            assert_eq!(
                handle.wait(accepted.operation).await.map_err(submit)?,
                Completed::Cancelled
            );
            let closed = observation(&handle, accepted.operation)?;
            assert_eq!(closed.outcome, SetupOutcome::OwnerClosed);
            assert_eq!(closed.stage, before.stage);
            assert_eq!(closed.runtime, before.runtime);
            assert!(closed.failure.is_none());
            assert_eq!(handle.snapshot().phase, Phase::Closed);
            assert_unopened(&hosts);
            drop(peer);
            assert_ports_free(fixture.addresses)?;
        }
        let hosts = hosts();
        let fixture = transaction_plans(appearance, &hosts)?;
        let mut pair = Pair::new(fixture, hosts)?;
        pair.ready().await?;
        pair.exchange(0, 81).await?;
        let old_setup = observation(&pair.handles[0], pair.accepted[0].operation)?;
        let mut expected = status(&pair.handles[0])?;
        drop(pair.runs[0].take());
        expected.running = false;
        expected.service_terminal = Some("Aborted".into());
        assert_eq!(status(&pair.handles[0])?, expected);
        assert_eq!(pair.handles[0].snapshot().phase, Phase::Closed);
        assert_eq!(pair.hosts[0].live.load(Ordering::SeqCst), 0);
        assert_eq!(
            pair.handles[0]
                .wait_stopped(pair.accepted[0].operation)
                .await
                .map_err(submit)?,
            Terminal::Aborted
        );
        assert_eq!(
            observation(&pair.handles[0], pair.accepted[0].operation)?,
            old_setup
        );
        pair.close()?;
    }
    Ok(())
}

#[tokio::test]
async fn generic_expired_queued_reconnect_preserves_old_owner_then_replaces_in_order() -> Result {
    for appearance in appearances() {
        let hosts = hosts();
        let mut fixture = transaction_plans(appearance, &hosts)?;
        for (side, host) in hosts.iter().enumerate() {
            let original = host.attachment();
            let host = host.clone();
            Arc::get_mut(&mut fixture.plans[side].data)
                .ok_or("fixture already shared")?
                .attachment = Attachment::readable(PacketLayer::Ip, move || {
                assert_eq!(
                    host.live.load(Ordering::SeqCst),
                    0,
                    "replacement opened before old owner drop"
                );
                original.open_readable()
            });
        }
        let mut pair = Pair::new(fixture, hosts)?;
        pair.ready().await?;
        pair.exchange(0, 91).await?;
        pair.exchange(1, 92).await?;
        let before = status(&pair.handles[0])?;
        let setup = observation(&pair.handles[0], pair.accepted[0].operation)?;
        let original_generation = pair.accepted[0].operation;
        let admission = admission_identity_now(&pair.fixture.plans[1])?;
        let runtime = pair
            .fixture
            .profile
            .runtime_contract(Role::Initiator)?
            .config();
        assert!(runtime.lifetime.lease > pair.fixture.profile.connection().handshake_timeout);
        assert!(
            runtime.lifetime.pong_timeout > pair.fixture.profile.connection().handshake_timeout
        );
        tokio::time::pause();
        let reconnect = pair.handles[0]
            .reconnect(
                pair.fixture.plans[0].clone(),
                pair.handles[0].next_key().map_err(submit)?,
            )
            .map_err(submit)?;
        tokio::time::advance(pair.fixture.profile.connection().handshake_timeout).await;
        pair.drive_side(0).await?;
        assert_eq!(
            completed(&pair.handles[0], reconnect.operation),
            Some(Completed::Failed(Failure {
                kind: io::ErrorKind::TimedOut
            }))
        );
        assert_eq!(
            pair.handles[0].snapshot().generation,
            Some(original_generation)
        );
        assert_eq!(status(&pair.handles[0])?.session, before.session);
        assert_eq!(pair.hosts[0].opened.load(Ordering::SeqCst), 1);
        assert_eq!(pair.hosts[0].live.load(Ordering::SeqCst), 1);
        let failed = observation(&pair.handles[0], reconnect.operation)?;
        assert_eq!(failed.stage, SetupStage::Accepted);
        assert_eq!(
            failed.failure.map(|failure| failure.reason),
            Some(SetupFailureReason::OriginalDeadline)
        );
        pair.exchange(0, 93).await?;
        for side in 0..2 {
            pair.accepted[side] = pair.handles[side]
                .reconnect(
                    pair.fixture.plans[side].clone(),
                    pair.handles[side].next_key().map_err(submit)?,
                )
                .map_err(submit)?;
        }
        pair.ready().await?;
        let fresh = status(&pair.handles[0])?;
        assert_ne!(fresh.session, before.session);
        assert_ne!(fresh.transcript, before.transcript);
        assert_eq!(admission_identity_now(&pair.fixture.plans[1])?, admission);
        assert_eq!(
            pair.handles[0]
                .wait_stopped(original_generation)
                .await
                .map_err(submit)?,
            Terminal::Aborted
        );
        assert_eq!(observation(&pair.handles[0], original_generation)?, setup);
        assert_eq!(observation(&pair.handles[0], reconnect.operation)?, failed);
        for host in &pair.hosts {
            assert_eq!(host.opened.load(Ordering::SeqCst), 2);
            assert_eq!(host.live.load(Ordering::SeqCst), 1);
        }
        pair.exchange(1, 94).await?;
        pair.close()?;
        tokio::time::resume();
    }
    Ok(())
}

#[tokio::test]
async fn generic_exact_plan_after_cancel_and_temporary_bind_failure_reuses_admission() -> Result {
    for appearance in appearances() {
        let hosts = hosts();
        let fixture = transaction_plans(appearance, &hosts)?;
        let mut pair = Pair::new(fixture, hosts)?;
        pair.drive_side(1).await?;
        assert_eq!(
            observation(&pair.handles[1], pair.accepted[1].operation)?.stage,
            SetupStage::Admission
        );
        assert_eq!(
            admission_identity_now(&pair.fixture.plans[1])
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        let cancelled = pair.accepted[1].operation;
        pair.handles[1].cancel(cancelled).map_err(submit)?;
        pair.drive_side(1).await?;
        assert_eq!(
            completed(&pair.handles[1], cancelled),
            Some(Completed::Cancelled)
        );
        let admission = admission_identity_now(&pair.fixture.plans[1])?;
        let stable = observation(&pair.handles[1], cancelled)?;
        let occupied = std::net::UdpSocket::bind(pair.fixture.addresses[0])?;
        pair.drive_side(0).await?;
        assert_eq!(
            completed(&pair.handles[0], pair.accepted[0].operation),
            Some(Completed::Failed(Failure {
                kind: io::ErrorKind::AddrInUse
            }))
        );
        drop(occupied);
        for side in 0..2 {
            pair.accepted[side] = pair.handles[side]
                .connect(
                    pair.fixture.plans[side].clone(),
                    pair.handles[side].next_key().map_err(submit)?,
                )
                .map_err(submit)?;
        }
        pair.ready().await?;
        pair.exchange(0, 101).await?;
        assert_eq!(admission_identity_now(&pair.fixture.plans[1])?, admission);
        assert_eq!(observation(&pair.handles[1], cancelled)?, stable);
        for host in &pair.hosts {
            assert_eq!(host.opened.load(Ordering::SeqCst), 1);
        }
        pair.close()?;
    }
    Ok(())
}
