//! Operation-bound setup evidence from real service owners and authenticated UDP.
use super::*;
use l2tunnel_runtime::secure_udp::diagnostics;

fn observation(handle: &Handle, operation: OperationId) -> Result<SetupObservation> {
    handle
        .setup_observation(operation)
        .map_err(submit)?
        .ok_or_else(|| "missing secure UDP setup observation".into())
}

async fn completion(handle: &Handle, operation: OperationId) -> Result<Completed> {
    Ok(timeout(Duration::from_secs(4), handle.wait(operation))
        .await?
        .map_err(submit)?)
}

fn appearances() -> [l2tunnel_cover::Appearance; 2] {
    [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ]
}

fn assert_unopened(hosts: &[Arc<Host>; 2]) {
    for host in hosts {
        assert_eq!(host.opened.load(Ordering::SeqCst), 0);
        assert_eq!(host.live.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn queued_exact_expiry_records_accepted_without_socket_or_provider_work() -> Result {
    for appearance in appearances() {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let ([client_plan, _], addresses) =
            plans(appearance, &hosts, Duration::from_millis(200), false)?;
        // Occupying both original ports makes accidental setup work observable:
        // a bind attempt would fail AddrInUse rather than the accepted deadline.
        let held = [
            std::net::UdpSocket::bind(addresses[0])?,
            std::net::UdpSocket::bind(addresses[1])?,
        ];
        held[1].set_nonblocking(true)?;
        let (handle, run) = channel();
        let accepted = handle
            .connect(client_plan, handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        let initial = observation(&handle, accepted.operation)?;
        assert_eq!(initial.stage, SetupStage::Accepted);
        assert_eq!(initial.outcome, SetupOutcome::Pending);
        assert_eq!(initial.elapsed_micros, 0);
        assert_eq!(initial.original_timeout_micros, 200_000);
        assert!(initial.runtime.is_none() && initial.failure.is_none());
        tokio::time::advance(Duration::from_millis(200)).await;
        let mut run = Box::pin(run);
        drive_once(&mut run).await;
        assert_eq!(
            handle.wait(accepted.operation).await.map_err(submit)?,
            Completed::Failed(Failure {
                kind: io::ErrorKind::TimedOut
            })
        );
        let expired = observation(&handle, accepted.operation)?;
        assert_eq!(expired.operation, accepted.operation);
        assert_eq!(expired.stage, SetupStage::Accepted);
        assert_eq!(expired.outcome, SetupOutcome::Failed);
        assert_eq!(expired.elapsed_micros, 200_000);
        assert_eq!(
            expired.original_timeout_micros,
            initial.original_timeout_micros
        );
        assert_eq!(
            expired.failure,
            Some(SetupFailure {
                kind: io::ErrorKind::TimedOut,
                reason: SetupFailureReason::OriginalDeadline,
            })
        );
        assert!(expired.runtime.is_none());
        assert_unopened(&hosts);
        let mut packet = [0; 1];
        assert_eq!(
            held[1]
                .recv_from(&mut packet)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(observation(&handle, accepted.operation)?, expired);
    }
    Ok(())
}

#[tokio::test]
async fn occupied_original_socket_reports_bind_local_io_without_authentication_claim() -> Result {
    for appearance in appearances() {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let ([client_plan, _], addresses) =
            plans(appearance, &hosts, Duration::from_secs(3), false)?;
        let _occupied = std::net::UdpSocket::bind(addresses[0])?;
        let (handle, run) = channel();
        let accepted = handle
            .connect(client_plan, handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        let task = tokio::spawn(run);
        assert_eq!(
            completion(&handle, accepted.operation).await?,
            Completed::Failed(Failure {
                kind: io::ErrorKind::AddrInUse
            })
        );
        let failed = observation(&handle, accepted.operation)?;
        assert_eq!(failed.stage, SetupStage::SocketBind);
        assert_eq!(failed.outcome, SetupOutcome::Failed);
        assert_eq!(
            failed.failure,
            Some(SetupFailure {
                kind: io::ErrorKind::AddrInUse,
                reason: SetupFailureReason::LocalIo,
            })
        );
        assert_eq!(failed.original_timeout_micros, 3_000_000);
        assert!(failed.runtime.is_none());
        assert!(handle.snapshot().generation.is_none());
        assert_unopened(&hosts);
        task.abort();
        let _ = task.await;
        assert_eq!(observation(&handle, accepted.operation)?, failed);
    }
    Ok(())
}

#[tokio::test]
async fn authenticated_attachment_failure_keeps_typed_stage_and_discards_provider_text() -> Result {
    const SENTINEL: &str = "PRIVATE_PROVIDER_SENTINEL cookie=do-not-copy key=do-not-copy";
    for appearance in appearances() {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let ([mut client_plan, server_plan], addresses) =
            plans(appearance, &hosts, Duration::from_secs(3), false)?;
        let opened = Arc::new(AtomicUsize::new(0));
        let count = opened.clone();
        Arc::get_mut(&mut client_plan.data)
            .ok_or("test plan unexpectedly shared")?
            .attachment = Attachment::readable(PacketLayer::Ip, move || {
            count.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::new(io::ErrorKind::PermissionDenied, SENTINEL))
        });
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let a = client
            .connect(client_plan, client.next_key().map_err(submit)?)
            .map_err(submit)?;
        server
            .connect(server_plan, server.next_key().map_err(submit)?)
            .map_err(submit)?;
        let client_task = tokio::spawn(client_run);
        let server_task = tokio::spawn(server_run);
        assert_eq!(
            completion(&client, a.operation).await?,
            Completed::Failed(Failure {
                kind: io::ErrorKind::PermissionDenied,
            })
        );
        assert_eq!(opened.load(Ordering::SeqCst), 1);
        let failed = observation(&client, a.operation)?;
        assert_eq!(failed.stage, SetupStage::Attachment);
        assert_eq!(failed.outcome, SetupOutcome::Failed);
        assert_eq!(
            failed.failure,
            Some(SetupFailure {
                kind: io::ErrorKind::PermissionDenied,
                reason: SetupFailureReason::LocalIo,
            })
        );
        let runtime = failed
            .runtime
            .ok_or("authenticated setup omitted actual runtime evidence")?;
        assert_eq!(runtime.stage, diagnostics::Stage::Membership);
        assert!(runtime.bootstrap.is_some() && runtime.member_attempts.is_some());
        assert!(!format!("{failed:?}").contains(SENTINEL));
        assert!(!format!("{failed:?}").contains("do-not-copy"));
        assert!(client.snapshot().generation.is_none());
        assert_eq!(hosts[0].opened.load(Ordering::SeqCst), 0);
        let rebound = std::net::UdpSocket::bind(addresses[0])?;
        drop(rebound);
        client_task.abort();
        server_task.abort();
        let _ = tokio::join!(client_task, server_task);
        assert_eq!(observation(&client, a.operation)?, failed);
    }
    Ok(())
}

/// A finite owned fixture with no OS descriptor to close and no unsafe code.
/// It exercises actual AsyncFd registration failure after successful membership.
struct InvalidDescriptor {
    dropped: Arc<AtomicUsize>,
    io_calls: Arc<AtomicUsize>,
}
impl Drop for InvalidDescriptor {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl AsRawFd for InvalidDescriptor {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        -1
    }
}
impl PacketDevice for InvalidDescriptor {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, _bytes: &mut [u8]) -> io::Result<Option<usize>> {
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::WouldBlock.into())
    }
    fn transmit(&mut self, _bytes: &[u8]) -> io::Result<()> {
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::WouldBlock.into())
    }
}

#[tokio::test]
async fn driver_registration_failure_is_not_promoted_to_ready_or_authentication_failure() -> Result
{
    for appearance in appearances() {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let ([mut client_plan, server_plan], addresses) =
            plans(appearance, &hosts, Duration::from_secs(3), false)?;
        let opened = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let io_calls = Arc::new(AtomicUsize::new(0));
        let (calls, drops, io) = (opened.clone(), dropped.clone(), io_calls.clone());
        Arc::get_mut(&mut client_plan.data)
            .ok_or("test plan unexpectedly shared")?
            .attachment = Attachment::readable(PacketLayer::Ip, move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::swift::Native::new(InvalidDescriptor {
                dropped: drops.clone(),
                io_calls: io.clone(),
            }))
        });
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let a = client
            .connect(client_plan, client.next_key().map_err(submit)?)
            .map_err(submit)?;
        server
            .connect(server_plan, server.next_key().map_err(submit)?)
            .map_err(submit)?;
        let client_task = tokio::spawn(client_run);
        let server_task = tokio::spawn(server_run);
        let actual = match completion(&client, a.operation).await? {
            Completed::Failed(failure) => failure,
            other => return Err(format!("invalid descriptor reached readiness: {other:?}").into()),
        };
        assert_ne!(actual.kind, io::ErrorKind::TimedOut);
        let failed = observation(&client, a.operation)?;
        assert_eq!(failed.stage, SetupStage::DriverReadiness);
        assert_eq!(failed.outcome, SetupOutcome::Failed);
        assert_eq!(
            failed.failure,
            Some(SetupFailure {
                kind: actual.kind,
                reason: SetupFailureReason::ReadinessEnded,
            })
        );
        assert_eq!(
            failed.runtime.ok_or("missing membership evidence")?.stage,
            diagnostics::Stage::Membership
        );
        assert_eq!(opened.load(Ordering::SeqCst), 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(io_calls.load(Ordering::SeqCst), 0);
        assert!(client.snapshot().generation.is_none());
        assert!(client.snapshot().runtime.is_none());
        let rebound = std::net::UdpSocket::bind(addresses[0])?;
        drop(rebound);
        client_task.abort();
        server_task.abort();
        let _ = tokio::join!(client_task, server_task);
        assert_eq!(observation(&client, a.operation)?, failed);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cancelled_observation_cannot_be_refreshed_or_overwritten_by_late_callbacks() -> Result {
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let ([client_plan, _], _) = plans(
        l2tunnel_cover::Appearance::QuicLike,
        &hosts,
        Duration::from_secs(3),
        false,
    )?;
    let (handle, run) = channel();
    let mut run = Box::pin(run);
    let first = handle
        .connect(client_plan.clone(), handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    handle.cancel(first.operation).map_err(submit)?;
    drive_once(&mut run).await;
    assert_eq!(
        handle.wait(first.operation).await.map_err(submit)?,
        Completed::Cancelled
    );
    let cancelled = observation(&handle, first.operation)?;
    assert_eq!(cancelled.stage, SetupStage::Accepted);
    assert_eq!(cancelled.outcome, SetupOutcome::Cancelled);
    assert!(cancelled.failure.is_none() && cancelled.runtime.is_none());
    let next = handle
        .connect(client_plan, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let pending = observation(&handle, next.operation)?;
    tokio::time::advance(Duration::from_millis(25)).await;
    // These are stale local observation callbacks, never a fabricated handshake.
    crate::service::setup::stage(&handle.0, first.operation, SetupStage::DriverReadiness);
    crate::service::setup::runtime(
        &handle.0,
        first.operation,
        diagnostics::Observation::new(diagnostics::Stage::Noise),
    );
    assert_eq!(observation(&handle, first.operation)?, cancelled);
    assert_eq!(observation(&handle, next.operation)?, pending);
    handle.cancel(next.operation).map_err(submit)?;
    drive_once(&mut run).await;
    assert_eq!(
        handle.wait(next.operation).await.map_err(submit)?,
        Completed::Cancelled
    );
    assert_unopened(&hosts);
    Ok(())
}

#[tokio::test]
async fn cancellation_from_authenticated_attachment_keeps_actual_stage_without_ready() -> Result {
    for appearance in appearances() {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let ([mut client_plan, server_plan], addresses) =
            plans(appearance, &hosts, Duration::from_secs(3), false)?;
        let action = Arc::new(Mutex::new(None::<(Handle, OperationId)>));
        let callback = action.clone();
        let during = Arc::new(Mutex::new(None));
        let captured = during.clone();
        let original = hosts[0].attachment();
        Arc::get_mut(&mut client_plan.data)
            .ok_or("test plan unexpectedly shared")?
            .attachment = Attachment::readable(PacketLayer::Ip, move || {
            let device = original.open_readable()?;
            let (handle, operation) = callback
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .cloned()
                .ok_or_else(|| io::Error::other("missing cancellation identity"))?;
            *captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                handle.setup_observation(operation).map_err(submit)?;
            handle.cancel(operation).map_err(submit)?;
            Ok(device)
        });
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let a = client
            .connect(client_plan, client.next_key().map_err(submit)?)
            .map_err(submit)?;
        *action
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((client.clone(), a.operation));
        server
            .connect(server_plan, server.next_key().map_err(submit)?)
            .map_err(submit)?;
        let client_task = tokio::spawn(client_run);
        let server_task = tokio::spawn(server_run);
        assert_eq!(
            completion(&client, a.operation).await?,
            Completed::Cancelled,
            "actual setup: {:?}",
            client.setup_observation(a.operation).map_err(submit)?,
        );
        let opened_at = during
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ok_or("attachment did not observe its operation")?;
        assert_eq!(opened_at.stage, SetupStage::Attachment);
        assert_eq!(opened_at.outcome, SetupOutcome::Pending);
        assert_eq!(
            opened_at.runtime.ok_or("missing actual membership")?.stage,
            diagnostics::Stage::Membership
        );
        let cancelled = observation(&client, a.operation)?;
        assert_eq!(cancelled.stage, SetupStage::DriverReadiness);
        assert_eq!(cancelled.outcome, SetupOutcome::Cancelled);
        assert!(cancelled.failure.is_none());
        assert!(client.snapshot().generation.is_none());
        assert_eq!(hosts[0].opened.load(Ordering::SeqCst), 1);
        assert_eq!(hosts[0].live.load(Ordering::SeqCst), 0);
        let rebound = std::net::UdpSocket::bind(addresses[0])?;
        drop(rebound);
        client_task.abort();
        server_task.abort();
        let _ = tokio::join!(client_task, server_task);
        assert_eq!(observation(&client, a.operation)?, cancelled);
    }
    Ok(())
}

#[tokio::test]
async fn owner_drop_terminalizes_queued_and_inflight_observations_without_provider_work() -> Result
{
    for polled in [false, true] {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let ([client_plan, _], addresses) = plans(
            l2tunnel_cover::Appearance::QuicLike,
            &hosts,
            Duration::from_secs(3),
            false,
        )?;
        let _peer = std::net::UdpSocket::bind(addresses[1])?;
        let (handle, run) = channel();
        let accepted = handle
            .connect(client_plan, handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        let mut run = Box::pin(run);
        if polled {
            drive_once(&mut run).await;
        }
        let before = observation(&handle, accepted.operation)?;
        if polled {
            assert_eq!(before.stage, SetupStage::Admission);
            assert!(before.runtime.is_some());
            assert_eq!(
                std::net::UdpSocket::bind(addresses[0])
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::AddrInUse)
            );
        } else {
            assert_eq!(before.stage, SetupStage::Accepted);
            assert!(before.runtime.is_none());
        }
        drop(run);
        assert_eq!(
            handle.wait(accepted.operation).await.map_err(submit)?,
            Completed::Cancelled
        );
        let closed = observation(&handle, accepted.operation)?;
        assert_eq!(closed.stage, before.stage);
        assert_eq!(closed.outcome, SetupOutcome::OwnerClosed);
        assert_eq!(closed.runtime, before.runtime);
        assert!(closed.failure.is_none());
        assert_eq!(handle.snapshot().phase, Phase::Closed);
        let rebound = std::net::UdpSocket::bind(addresses[0])?;
        drop(rebound);
        tokio::task::yield_now().await;
        assert_eq!(observation(&handle, accepted.operation)?, closed);
        assert_unopened(&hosts);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn setup_history_retirement_and_future_lookup_follow_existing_operation_bounds() -> Result {
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let ([client_plan, _], _) = plans(
        l2tunnel_cover::Appearance::MediaLike,
        &hosts,
        Duration::from_secs(3),
        false,
    )?;
    let (handle, run) = channel();
    let mut run = Box::pin(run);
    let mut first = None;
    let mut last = None;
    for _ in 0..40 {
        let accepted = handle
            .connect(client_plan.clone(), handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        first.get_or_insert(accepted.operation);
        let future = OperationId(accepted.operation.value() + 1);
        assert_eq!(
            handle.setup_observation(future),
            Err(SubmitError::FutureKey)
        );
        handle.cancel(accepted.operation).map_err(submit)?;
        drive_once(&mut run).await;
        assert_eq!(
            handle.wait(accepted.operation).await.map_err(submit)?,
            Completed::Cancelled
        );
        let value = observation(&handle, accepted.operation)?;
        assert_eq!(value.operation, accepted.operation);
        assert_eq!(value.stage, SetupStage::Accepted);
        assert_eq!(value.outcome, SetupOutcome::Cancelled);
        last = Some((accepted.operation, value));
    }
    assert_eq!(
        handle.setup_observation(first.ok_or("missing first operation")?),
        Err(SubmitError::Expired)
    );
    let (last, stable) = last.ok_or("missing final operation")?;
    assert_eq!(handle.0.lock().entries.len(), 32);
    assert_eq!(handle.0.lock().retired_through, 8);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(observation(&handle, last)?, stable);
    assert_unopened(&hosts);
    Ok(())
}

#[tokio::test]
async fn legacy_service_operations_do_not_invent_secure_udp_setup_observations() -> Result {
    let credentials = super::super::credentials()?;
    let native = Arc::new(super::super::Native::default());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let legacy = super::super::plan(
        &credentials,
        listener.local_addr()?,
        cfg(Duplex::Full),
        native.clone(),
    )?;
    let (handle, run) = channel();
    let accepted = handle
        .connect(legacy, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    assert_eq!(handle.setup_observation(accepted.operation), Ok(None));
    assert_eq!(native.opened.load(Ordering::SeqCst), 0);
    drop(run);
    assert_eq!(
        handle.wait(accepted.operation).await.map_err(submit)?,
        Completed::Cancelled
    );
    assert_eq!(handle.setup_observation(accepted.operation), Ok(None));
    assert_eq!(native.opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn fresh_reconnect_observation_cannot_adopt_or_refresh_the_previous_ready_operation() -> Result
{
    for appearance in appearances() {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let ([client_plan, server_plan], _) =
            plans(appearance, &hosts, Duration::from_secs(3), false)?;
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let a = client
            .connect(client_plan.clone(), client.next_key().map_err(submit)?)
            .map_err(submit)?;
        let b = server
            .connect(server_plan.clone(), server.next_key().map_err(submit)?)
            .map_err(submit)?;
        let client_task = tokio::spawn(client_run);
        let server_task = tokio::spawn(server_run);
        let (a, b) = tokio::try_join!(connected(&client, a), connected(&server, b))?;
        let originals = [observation(&client, a)?, observation(&server, b)?];
        for value in originals {
            assert_eq!(value.stage, SetupStage::ReadyPublication);
            assert_eq!(value.outcome, SetupOutcome::Ready);
            assert!(value.failure.is_none());
            assert_eq!(
                value
                    .runtime
                    .ok_or("ready operation omitted setup evidence")?
                    .stage,
                diagnostics::Stage::Membership
            );
        }
        let original_session = client
            .snapshot()
            .runtime
            .as_ref()
            .and_then(Observation::secure_udp)
            .ok_or("missing live secure UDP owner")?
            .status()?
            .session;
        let next_a = client
            .reconnect(client_plan, client.next_key().map_err(submit)?)
            .map_err(submit)?;
        let next_b = server
            .reconnect(server_plan, server.next_key().map_err(submit)?)
            .map_err(submit)?;
        assert!(next_a.operation > a && next_b.operation > b);
        for (handle, accepted) in [(&client, next_a), (&server, next_b)] {
            let fresh = observation(handle, accepted.operation)?;
            assert_eq!(fresh.stage, SetupStage::Accepted);
            assert_eq!(fresh.outcome, SetupOutcome::Pending);
            assert!(fresh.failure.is_none() && fresh.runtime.is_none());
            assert_eq!(fresh.elapsed_micros, 0);
            assert_eq!(fresh.original_timeout_micros, 3_000_000);
        }
        tokio::try_join!(connected(&client, next_a), connected(&server, next_b))?;
        assert_eq!(observation(&client, a)?, originals[0]);
        assert_eq!(observation(&server, b)?, originals[1]);
        let fresh = observation(&client, next_a.operation)?;
        assert_eq!(fresh.stage, SetupStage::ReadyPublication);
        assert_eq!(fresh.outcome, SetupOutcome::Ready);
        let fresh_session = client
            .snapshot()
            .runtime
            .as_ref()
            .and_then(Observation::secure_udp)
            .ok_or("missing replacement owner")?
            .status()?
            .session;
        assert_ne!(fresh_session, original_session);
        for host in &hosts {
            assert_eq!(host.opened.load(Ordering::SeqCst), 2);
            assert_eq!(host.live.load(Ordering::SeqCst), 1);
        }
        client_task.abort();
        server_task.abort();
        let _ = tokio::join!(client_task, server_task);
        assert_eq!(observation(&client, a)?, originals[0]);
        assert_eq!(observation(&server, b)?, originals[1]);
        assert_eq!(observation(&client, next_a.operation)?, fresh);
        for host in &hosts {
            assert_eq!(host.live.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}
