//! Foreground lifetime termination through real shared setup and device staging.
use super::*;
use crate::{input::Command, staging::Staging};
use tokio::sync::mpsc;

fn staged(c: &Credentials, address: SocketAddr, staging: &Staging) -> io::Result<Prepared> {
    Prepared::client(
        config(),
        Client {
            remote: address,
            tls: c.client.clone(),
            server_name: "foreground.test".into(),
            member: c.member.clone(),
        },
        staging.attachment(PacketLayer::Ip),
        Options::default(),
    )
}

fn opening(native: Arc<Native>) -> Staging {
    Staging::new(move || {
        assert_eq!(native.live.load(Ordering::SeqCst), 0);
        native.opened.fetch_add(1, Ordering::SeqCst);
        native.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Device(native.clone())))
    })
}

#[tokio::test]
async fn eof_during_device_creation_joins_and_drops_late_owner() -> TestResult {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let (sender, controls) = mpsc::channel(4);
    let (entered, started) = oneshot::channel();
    let entered = Mutex::new(Some(entered));
    let (release, resume) = std::sync::mpsc::channel();
    let resume = Mutex::new(resume);
    let owned = native.clone();
    let staging = Staging::new(move || {
        if let Some(entered) = entered
            .lock()
            .map_err(|_| io::Error::other("entered lock"))?
            .take()
        {
            let _ = entered.send(());
        }
        resume
            .lock()
            .map_err(|_| io::Error::other("resume lock"))?
            .recv()
            .map_err(io::Error::other)?;
        owned.opened.fetch_add(1, Ordering::SeqCst);
        owned.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Device(owned.clone())))
    });
    let plan = staged(&c, "127.0.0.1:1".parse()?, &staging)?;
    let mut final_closed = false;
    let run = controlled(
        plan,
        config(),
        Some(staging),
        Some(controls),
        std::future::pending(),
        |event| {
            if let Event::Status(snapshot) = event
                && snapshot.phase == Phase::Closed
            {
                assert_eq!(native.opened.load(Ordering::SeqCst), 1);
                assert_eq!(native.live.load(Ordering::SeqCst), 0);
                assert_eq!(snapshot.operation, None);
                assert_eq!(snapshot.generation, None);
                final_closed = true;
            }
        },
    );
    let close = async {
        started.await?;
        // The OS-call stand-in can finish independently of the blocked runtime
        // thread joining it. It has no way to refill the slot after shutdown.
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            let _ = release.send(());
        });
        drop(sender);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(worker)
    };
    let (outcome, worker) =
        timeout(Duration::from_secs(5), async { tokio::join!(run, close) }).await?;
    worker?.join().map_err(|_| "release worker panic")?;
    assert_eq!(outcome?, Outcome::Cancelled);
    assert!(final_closed);
    Ok(())
}

#[tokio::test]
async fn disconnect_during_authentication_releases_staged_device_and_socket() -> TestResult {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let staging = opening(native.clone());
    let plan = staged(&c, listener.local_addr()?, &staging)?;
    let (sender, controls) = mpsc::channel(4);
    let (accepted, observed) = oneshot::channel();
    let peer = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let (mut stream, _) = listener.accept().await?;
        let _ = accepted.send(());
        let mut bytes = [0; 4096];
        while stream.read(&mut bytes).await? != 0 {}
        Ok::<_, io::Error>(())
    });
    let mut cancelled = false;
    let mut rejected_busy = false;
    let mut sender = Some(sender);
    let commands = sender.as_ref().ok_or("sender missing")?.clone();
    let run = controlled(
        plan,
        config(),
        Some(staging),
        Some(controls),
        std::future::pending(),
        |event| match event {
            Event::Rejected { command, reason } => {
                assert_eq!(command, Command::Reconnect);
                assert_eq!(reason, SubmitError::Busy);
                rejected_busy = true;
            }
            Event::Completed {
                result: Completion::Cancelled,
                ..
            } => {
                assert_eq!(native.live.load(Ordering::SeqCst), 0);
                cancelled = true;
                drop(sender.take());
            }
            Event::Status(snapshot) if snapshot.phase == Phase::Closed => {
                assert_eq!(native.live.load(Ordering::SeqCst), 0);
            }
            _ => {}
        },
    );
    let input = async move {
        observed.await?;
        commands.send(Ok(Command::Status)).await?;
        commands.send(Ok(Command::Reconnect)).await?;
        commands.send(Ok(Command::Disconnect)).await?;
        drop(commands);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (outcome, input) =
        timeout(Duration::from_secs(5), async { tokio::join!(run, input) }).await?;
    input?;
    assert_eq!(outcome?, Outcome::Cancelled);
    timeout(Duration::from_secs(5), peer).await???;
    assert!(cancelled && rejected_busy);
    assert_eq!(native.opened.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn input_error_after_readiness_releases_device_before_final_status() -> TestResult {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let (_, peer, address) = server(&c, Arc::new(Native::default())).await?;
    let staging = opening(native.clone());
    let plan = staged(&c, address, &staging)?;
    let (sender, controls) = mpsc::channel(4);
    let mut sent = false;
    let mut released = false;
    let result = timeout(
        Duration::from_secs(5),
        controlled(
            plan,
            config(),
            Some(staging),
            Some(controls),
            std::future::pending(),
            |event| {
                if let Event::Status(snapshot) = event {
                    if snapshot.phase == Phase::Connected && !sent {
                        assert!(
                            sender
                                .try_send(Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "input fixture"
                                )))
                                .is_ok()
                        );
                        sent = true;
                    }
                    if snapshot.phase == Phase::Closed {
                        assert_eq!(native.live.load(Ordering::SeqCst), 0);
                        assert_eq!(snapshot.terminal, Some(Terminal::Aborted));
                        released = true;
                    }
                }
            },
        ),
    )
    .await?;
    stopped(peer).await;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert!(sent && released);
    Ok(())
}

#[tokio::test]
async fn already_cancelled_or_closed_input_never_starts_a_device() -> TestResult {
    for cancellation_ready in [false, true] {
        let c = credentials()?;
        let native = Arc::new(Native::default());
        let staging = opening(native.clone());
        let plan = staged(&c, "127.0.0.1:1".parse()?, &staging)?;
        let (sender, controls) = mpsc::channel(4);
        let sender = if cancellation_ready {
            Some(sender)
        } else {
            drop(sender);
            None
        };
        let cancellation = async move {
            if cancellation_ready {
                Ok(())
            } else {
                std::future::pending().await
            }
        };
        let result = controlled(
            plan,
            config(),
            Some(staging),
            Some(controls),
            cancellation,
            |_| {},
        )
        .await?;
        drop(sender);
        assert_eq!(result, Outcome::Cancelled);
        assert_eq!(native.opened.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn shutdown_reports_completion_even_after_service_clears_active_operation() -> TestResult {
    // Deterministically reproduce losing the request continuation after Run has
    // finished, but before the frontend has observed the retained completion.
    for after_disconnect in [false, true] {
        let c = credentials()?;
        let native = Arc::new(Native::default());
        let (_, peer, address) = server(&c, Arc::new(Native::default())).await?;
        let staging = opening(native.clone());
        staging.prepare().await?;
        let (handle, owner) = service::channel();
        let accepted = handle
            .connect(
                staged(&c, address, &staging)?,
                handle.next_key().map_err(service_error)?,
            )
            .map_err(service_error)?;
        let owner = tokio::spawn(owner);
        let connected = timeout(Duration::from_secs(5), handle.wait(accepted.operation))
            .await?
            .map_err(service_error)?;
        let Completed::Connected { generation } = connected else {
            return Err("client did not become live".into());
        };
        let operation = if after_disconnect {
            let disconnected = handle
                .disconnect(handle.next_key().map_err(service_error)?)
                .map_err(service_error)?;
            assert_eq!(
                timeout(Duration::from_secs(5), handle.wait(disconnected.operation))
                    .await?
                    .map_err(service_error)?,
                Completed::Aborted
            );
            disconnected.operation
        } else {
            accepted.operation
        };
        assert_eq!(handle.snapshot().operation, None);
        let receipt = Cell::new(Some(operation));
        let events = RefCell::new(Vec::new());
        timeout(
            Duration::from_secs(5),
            stop(&handle, Some(&staging), &receipt, &|event| {
                events.borrow_mut().push(event)
            }),
        )
        .await??;
        assert_eq!(receipt.get(), None);
        assert_eq!(native.live.load(Ordering::SeqCst), 0);
        let events = events.into_inner();
        let completions: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Completed {
                    operation: id,
                    result,
                } if *id == operation.value() => Some(result),
                _ => None,
            })
            .collect();
        assert_eq!(completions.len(), 1);
        let expected = if after_disconnect {
            Completion::Aborted
        } else {
            Completion::from(&connected)
        };
        assert_eq!(*completions[0], expected);
        assert!(events.iter().any(|event| matches!(event, Event::Terminal { generation: id, result: Terminal::Aborted } if *id == generation.value())));
        stopped(owner).await;
        stopped(peer).await;
    }
    Ok(())
}

#[tokio::test]
async fn platform_failure_stays_idle_and_explicit_retry_submits_first_shared_connect() -> TestResult
{
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let (_, peer, address) = server(&c, Arc::new(Native::default())).await?;
    let attempts = Arc::new(AtomicUsize::new(0));
    let openings = attempts.clone();
    let owned = native.clone();
    let staging = Staging::new(move || {
        if openings.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        assert_eq!(owned.live.load(Ordering::SeqCst), 0);
        owned.opened.fetch_add(1, Ordering::SeqCst);
        owned.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Device(owned.clone())))
    });
    let plan = staged(&c, address, &staging)?;
    let (sender, controls) = mpsc::channel(4);
    let mut sender = Some(sender);
    let mut accepted = Vec::new();
    let mut failures = 0;
    let result = timeout(
        Duration::from_secs(5),
        controlled(
            plan,
            config(),
            Some(staging),
            Some(controls),
            std::future::pending(),
            |event| match event {
                Event::Failed { kind } => {
                    assert_eq!(kind, io::ErrorKind::PermissionDenied);
                    assert_eq!(attempts.load(Ordering::SeqCst), 1);
                    assert_eq!(native.live.load(Ordering::SeqCst), 0);
                    failures += 1;
                    if let Some(sender) = &sender {
                        assert!(sender.try_send(Ok(Command::Reconnect)).is_ok());
                    }
                }
                Event::Accepted { action, operation } => accepted.push((action, operation)),
                Event::Completed {
                    result: Completion::Connected { .. },
                    ..
                } => drop(sender.take()),
                _ => {}
            },
        ),
    )
    .await;
    stopped(peer).await;
    assert_eq!(result??, Outcome::Aborted);
    assert_eq!(failures, 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(accepted, [(Action::Connect, 1), (Action::Disconnect, 2)]);
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn runtime_failure_keeps_status_available_without_automatic_reconnect() -> TestResult {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let (_, peer, address) = server(&c, Arc::new(Native::default())).await?;
    let staging = opening(native.clone());
    let plan = staged(&c, address, &staging)?;
    let (sender, controls) = mpsc::channel(4);
    let mut sender = Some(sender);
    let mut failed_statuses = 0;
    let result = timeout(
        Duration::from_secs(5),
        controlled(
            plan,
            config(),
            Some(staging),
            Some(controls),
            std::future::pending(),
            |event| {
                if let Event::Status(snapshot) = event {
                    if snapshot.phase == Phase::Connected {
                        native.fail.store(true, Ordering::SeqCst);
                    }
                    if snapshot.phase == Phase::Failed {
                        assert_eq!(native.live.load(Ordering::SeqCst), 0);
                        assert_eq!(native.opened.load(Ordering::SeqCst), 1);
                        assert!(matches!(snapshot.terminal, Some(Terminal::Failed(_))));
                        failed_statuses += 1;
                        if failed_statuses < 4 {
                            if let Some(sender) = &sender {
                                assert!(sender.try_send(Ok(Command::Status)).is_ok());
                            }
                        } else {
                            drop(sender.take());
                        }
                    }
                }
            },
        ),
    )
    .await;
    stopped(peer).await;
    assert_eq!(result??, Outcome::Aborted);
    assert!(failed_statuses >= 4);
    assert_eq!(native.opened.load(Ordering::SeqCst), 1);
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn repeated_disconnect_keeps_status_responsive_while_setup_is_joining() -> TestResult {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let waiting = Arc::new(AtomicBool::new(false));
    let owned = native.clone();
    let blocked = waiting.clone();
    let (entered, started) = oneshot::channel();
    let entered = Mutex::new(Some(entered));
    let (release, resume) = std::sync::mpsc::channel();
    let resume = Mutex::new(resume);
    let staging = Staging::new(move || {
        blocked.store(true, Ordering::SeqCst);
        if let Some(entered) = entered
            .lock()
            .map_err(|_| io::Error::other("entered lock"))?
            .take()
        {
            let _ = entered.send(());
        }
        let result = resume
            .lock()
            .map_err(|_| io::Error::other("resume lock"))?
            .recv_timeout(Duration::from_secs(3));
        blocked.store(false, Ordering::SeqCst);
        result.map_err(io::Error::other)?;
        owned.opened.fetch_add(1, Ordering::SeqCst);
        owned.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Device(owned.clone())))
    });
    let plan = staged(&c, "127.0.0.1:1".parse()?, &staging)?;
    let (sender, controls) = mpsc::channel(4);
    let (observed, mut statuses) = mpsc::channel(16);
    let mut accepted = 0;
    let run = controlled(
        plan,
        config(),
        Some(staging),
        Some(controls),
        std::future::pending(),
        |event| match event {
            Event::Status(snapshot) => {
                if snapshot.phase == Phase::Closed {
                    assert_eq!(native.live.load(Ordering::SeqCst), 0);
                    assert!(!waiting.load(Ordering::SeqCst));
                }
                assert!(!matches!(
                    observed.try_send(snapshot),
                    Err(mpsc::error::TrySendError::Full(_))
                ));
            }
            Event::Accepted { .. } => accepted += 1,
            _ => {}
        },
    );
    let driven_waiting = waiting.clone();
    let driver = async move {
        started.await?;
        while statuses.try_recv().is_ok() {}
        for _ in 0..2 {
            sender.send(Ok(Command::Disconnect)).await?;
            sender.send(Ok(Command::Status)).await?;
            let status = timeout(Duration::from_secs(1), statuses.recv())
                .await?
                .ok_or("missing status during setup join")?;
            assert_eq!(status.phase, Phase::Disconnected);
            assert_eq!(status.operation, None);
            assert!(driven_waiting.load(Ordering::SeqCst));
        }
        release.send(())?;
        drop(sender);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (outcome, driver) =
        timeout(Duration::from_secs(5), async { tokio::join!(run, driver) }).await?;
    driver?;
    assert_eq!(outcome?, Outcome::Cancelled);
    assert_eq!(accepted, 0);
    assert_eq!(native.opened.load(Ordering::SeqCst), 1);
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    Ok(())
}
