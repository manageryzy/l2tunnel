//! Real shared-TLS lifecycle with staged fake devices; no native Windows evidence.
use super::*;
use crate::{input, staging::Staging};
use tokio::sync::mpsc;

const WAIT: Duration = Duration::from_secs(5);

fn staged(native: Arc<Native>, before: Arc<Mutex<Vec<usize>>>) -> Staging {
    Staging::new(move || {
        before
            .lock()
            .map_err(|_| io::Error::other("test open observation lock"))?
            .push(native.live.load(Ordering::SeqCst));
        native.opened.fetch_add(1, Ordering::SeqCst);
        native.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Device(native.clone())))
    })
}

fn staged_client(
    c: &Credentials,
    address: SocketAddr,
    connection: ConnectionConfig,
    staging: &Staging,
) -> io::Result<Prepared> {
    Prepared::client(
        connection,
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

fn fixed_server(
    c: &Credentials,
    address: SocketAddr,
    connection: ConnectionConfig,
    native: Arc<Native>,
    members: MemberAllowlist,
) -> io::Result<Prepared> {
    Prepared::server(
        connection,
        Server {
            listen: address,
            tls: c.server.clone(),
            members,
        },
        attachment(native),
        Options::default(),
    )
}

async fn event(
    events: &mut mpsc::Receiver<Event>,
    predicate: impl Fn(&Event) -> bool,
) -> TestResult<Event> {
    timeout(WAIT, async {
        loop {
            let event = events.recv().await.ok_or("test observer ended")?;
            if predicate(&event) {
                return Ok(event);
            }
        }
    })
    .await?
}

fn exchanged(event: &Event) -> bool {
    matches!(event, Event::Status(status) if status.phase == Phase::Connected
        && status.managed.as_ref().is_some_and(|runtime|
            runtime.delivered == 1 && runtime.peer_delivered == 1))
}

fn connected_generation(event: &Event) -> Option<u64> {
    match event {
        Event::Completed {
            operation,
            result: Completion::Connected { generation },
        } => {
            assert_eq!(*operation, generation.value());
            Some(generation.value())
        }
        _ => None,
    }
}

async fn restart_peer(handle: &Handle, plan: Prepared, address: SocketAddr) -> TestResult {
    let mut changes = handle.subscribe();
    let accepted = handle
        .reconnect(plan, handle.next_key().map_err(service_error)?)
        .map_err(service_error)?;
    timeout(WAIT, async {
        loop {
            let snapshot = handle.snapshot();
            if let Some(listening) = snapshot.listening
                && listening.operation == accepted.operation
            {
                assert_eq!(listening.address, address);
                return Ok::<_, io::Error>(());
            }
            if snapshot.phase == Phase::Failed && snapshot.operation.is_none() {
                return Err(io::Error::other("test fixed-address restart failed"));
            }
            changes
                .changed()
                .await
                .map_err(|_| io::Error::other("test peer observation ended"))?;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn staged_disconnect_status_and_reconnect_release_original_owners_in_half_and_full()
-> TestResult {
    for duplex in [Duplex::Half, Duplex::Full] {
        reconnect_exchange(duplex).await?;
    }
    Ok(())
}

async fn reconnect_exchange(duplex: Duplex) -> TestResult {
    let connection = ConnectionConfig { duplex, ..config() };
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let peer_native = Arc::new(Native::default());
    native
        .incoming
        .lock()
        .map_err(|_| "incoming lock")?
        .push_back(packet(1));
    peer_native
        .incoming
        .lock()
        .map_err(|_| "incoming lock")?
        .push_back(packet(2));
    let (peer_handle, peer, address) =
        server_with_config(&c, peer_native.clone(), connection).await?;
    let replacement = fixed_server(
        &c,
        address,
        connection,
        peer_native.clone(),
        c.members.clone(),
    )?;
    let before = Arc::new(Mutex::new(Vec::new()));
    let staging = staged(native.clone(), before.clone());
    let plan = staged_client(&c, address, connection, &staging)?;
    let (commands, controls) = mpsc::channel(4);
    let (observe, mut events) = mpsc::channel(64);
    let mut observations = Vec::new();
    let foreground = controlled(
        plan,
        connection,
        Some(staging),
        Some(controls),
        std::future::pending(),
        |item| {
            // Final cleanup can outlive the command driver and its receiver.
            // Keep every event in observations; only bounded-queue overflow is
            // a delivery failure while the driver is still consuming events.
            observations.push(item.clone());
            if let Err(error) = observe.try_send(item) {
                assert!(matches!(error, mpsc::error::TrySendError::Closed(_)));
            }
        },
    );
    let driven_native = native.clone();
    let driven_peer = peer_native.clone();
    let driver =
        async move {
            let ready = event(&mut events, |item| connected_generation(item).is_some()).await?;
            let first = connected_generation(&ready).ok_or("missing first generation")?;
            event(&mut events, exchanged).await?;
            let peer_generation = peer_handle
                .snapshot()
                .generation
                .ok_or("missing peer generation")?;
            commands.send(Ok(input::Command::Disconnect)).await?;
            event(&mut events, |item| matches!(item,
            Event::Terminal { generation, result: Terminal::Aborted } if *generation == first
        )).await?;
            assert_eq!(driven_native.live.load(Ordering::SeqCst), 0);
            assert_eq!(driven_native.opened.load(Ordering::SeqCst), 1);
            // Remove already emitted idle snapshots, then demand a fresh explicit
            // status response while no generation or platform operation is running.
            while events.try_recv().is_ok() {}
            commands.send(Ok(input::Command::Status)).await?;
            event(&mut events, |item| {
                matches!(item,
                    Event::Status(status) if status.phase == Phase::Disconnected
                        && status.generation == Some(first)
                        && status.terminal == Some(Terminal::Aborted)
                )
            })
            .await?;
            timeout(WAIT, peer_handle.wait_stopped(peer_generation))
                .await?
                .map_err(service_error)?;
            assert_eq!(driven_peer.live.load(Ordering::SeqCst), 0);
            driven_native
                .incoming
                .lock()
                .map_err(|_| "incoming lock")?
                .push_back(packet(3));
            driven_peer
                .incoming
                .lock()
                .map_err(|_| "incoming lock")?
                .push_back(packet(4));
            restart_peer(&peer_handle, replacement, address).await?;
            commands.send(Ok(input::Command::Reconnect)).await?;
            let ready = event(&mut events, |item| connected_generation(item).is_some()).await?;
            let second = connected_generation(&ready).ok_or("missing second generation")?;
            assert_ne!(first, second);
            event(&mut events, exchanged).await?;
            assert_eq!(driven_native.live.load(Ordering::SeqCst), 1);
            assert_eq!(driven_native.opened.load(Ordering::SeqCst), 2);
            // Closing explicit control is a lifetime boundary even after reconnect.
            drop(commands);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second))
        };
    let joined = timeout(Duration::from_secs(15), async {
        tokio::join!(foreground, driver)
    })
    .await;
    stopped(peer).await;
    let (outcome, generations) = joined?;
    let (first, second) = generations?;
    assert_eq!(outcome?, Outcome::Aborted);
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    assert_eq!(peer_native.live.load(Ordering::SeqCst), 0);
    assert_eq!(peer_native.opened.load(Ordering::SeqCst), 2);
    assert_eq!(
        *before.lock().map_err(|_| "open observations lock")?,
        [0, 0]
    );
    assert_eq!(
        *native.received.lock().map_err(|_| "received lock")?,
        [packet(2), packet(4)]
    );
    assert_eq!(
        *peer_native.received.lock().map_err(|_| "received lock")?,
        [packet(1), packet(3)]
    );
    let first_terminal = observations
        .iter()
        .position(|item| {
            matches!(item,
                Event::Terminal { generation, result: Terminal::Aborted } if *generation == first
            )
        })
        .ok_or("missing first terminal")?;
    let second_preparing = observations
        .iter()
        .enumerate()
        .filter(|(_, item)| matches!(item, Event::DevicePreparing))
        .nth(1)
        .map(|(index, _)| index)
        .ok_or("missing second platform setup")?;
    assert!(first_terminal < second_preparing);
    assert!(observations.iter().any(|item| matches!(item,
        Event::Accepted { action: Action::Reconnect, operation } if *operation == second
    )));
    assert!(matches!(observations.last(), Some(Event::Status(status))
        if status.phase == Phase::Closed && status.generation == Some(second)
            && status.terminal == Some(Terminal::Aborted)));
    Ok(())
}

#[tokio::test]
async fn staged_authentication_failure_releases_device_and_waits_for_explicit_retry() -> TestResult
{
    let connection = config();
    let mut c = credentials()?;
    let valid_members = c.members.clone();
    let unrelated = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    c.members = MemberAllowlist::new(&[unrelated.public_key()])?;
    let native = Arc::new(Native::default());
    let peer_native = Arc::new(Native::default());
    let (peer_handle, peer, address) =
        server_with_config(&c, peer_native.clone(), connection).await?;
    let replacement = fixed_server(&c, address, connection, peer_native.clone(), valid_members)?;
    let before = Arc::new(Mutex::new(Vec::new()));
    let staging = staged(native.clone(), before.clone());
    let plan = staged_client(&c, address, connection, &staging)?;
    let (commands, controls) = mpsc::channel(4);
    let (observe, mut events) = mpsc::channel(64);
    let mut observations = Vec::new();
    let foreground = controlled(
        plan,
        connection,
        Some(staging),
        Some(controls),
        std::future::pending(),
        |item| {
            if let Event::Failed { kind } = &item {
                // Shared client-core maps non-timeout authentication errors
                // through io::Error::other; this must be a real rejection.
                assert_eq!(*kind, io::ErrorKind::Other);
                assert_eq!(native.live.load(Ordering::SeqCst), 0);
            }
            // Final cleanup can outlive the command driver and its receiver.
            // Keep every event in observations; only bounded-queue overflow is
            // a delivery failure while the driver is still consuming events.
            observations.push(item.clone());
            if let Err(error) = observe.try_send(item) {
                assert!(matches!(error, mpsc::error::TrySendError::Closed(_)));
            }
        },
    );
    let driven_native = native.clone();
    let driven_peer = peer_native.clone();
    let driver = async move {
        event(&mut events, |item| matches!(item, Event::Failed { .. })).await?;
        assert_eq!(driven_native.opened.load(Ordering::SeqCst), 1);
        assert_eq!(driven_native.live.load(Ordering::SeqCst), 0);
        assert_eq!(driven_peer.opened.load(Ordering::SeqCst), 0);
        for _ in 0..3 {
            while events.try_recv().is_ok() {}
            commands.send(Ok(input::Command::Status)).await?;
            event(&mut events, |item| {
                matches!(item, Event::Status(status)
                    if status.phase == Phase::Failed && status.generation.is_none()
                        && status.operation.is_none()
                )
            })
            .await?;
            assert_eq!(driven_native.opened.load(Ordering::SeqCst), 1);
            assert_eq!(driven_native.live.load(Ordering::SeqCst), 0);
        }
        let mut changes = peer_handle.subscribe();
        timeout(WAIT, async {
            while peer_handle.snapshot().phase != Phase::Failed {
                changes
                    .changed()
                    .await
                    .map_err(|_| io::Error::other("peer observation ended"))?;
            }
            Ok::<_, io::Error>(())
        })
        .await??;
        driven_native
            .incoming
            .lock()
            .map_err(|_| "incoming lock")?
            .push_back(packet(7));
        driven_peer
            .incoming
            .lock()
            .map_err(|_| "incoming lock")?
            .push_back(packet(8));
        restart_peer(&peer_handle, replacement, address).await?;
        commands.send(Ok(input::Command::Reconnect)).await?;
        event(&mut events, |item| connected_generation(item).is_some()).await?;
        event(&mut events, exchanged).await?;
        assert_eq!(driven_native.opened.load(Ordering::SeqCst), 2);
        drop(commands);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let joined = timeout(Duration::from_secs(15), async {
        tokio::join!(foreground, driver)
    })
    .await;
    stopped(peer).await;
    let (outcome, driven) = joined?;
    driven?;
    assert_eq!(outcome?, Outcome::Aborted);
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    assert_eq!(peer_native.live.load(Ordering::SeqCst), 0);
    assert_eq!(
        *before.lock().map_err(|_| "open observations lock")?,
        [0, 0]
    );
    assert_eq!(
        *native.received.lock().map_err(|_| "received lock")?,
        [packet(8)]
    );
    assert_eq!(
        *peer_native.received.lock().map_err(|_| "received lock")?,
        [packet(7)]
    );
    assert_eq!(
        observations
            .iter()
            .filter(|item| matches!(
                item,
                Event::Accepted {
                    action: Action::Connect | Action::Reconnect,
                    ..
                }
            ))
            .count(),
        2
    );
    assert_eq!(
        observations
            .iter()
            .filter(|item| matches!(
                item,
                Event::Completed {
                    result: Completion::Failed(_),
                    ..
                }
            ))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn live_reconnect_releases_before_blocked_replacement_then_forwards_fresh_generation()
-> TestResult {
    let connection = config();
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let peer_native = Arc::new(Native::default());
    native
        .incoming
        .lock()
        .map_err(|_| "incoming lock")?
        .push_back(packet(11));
    peer_native
        .incoming
        .lock()
        .map_err(|_| "incoming lock")?
        .push_back(packet(12));
    let (peer_handle, peer, address) =
        server_with_config(&c, peer_native.clone(), connection).await?;
    let replacement = fixed_server(
        &c,
        address,
        connection,
        peer_native.clone(),
        c.members.clone(),
    )?;
    let (release_constructor, constructor_gate) = std::sync::mpsc::channel();
    let constructor_gate = Mutex::new(constructor_gate);
    let (entered, constructor_started) = oneshot::channel();
    let entered = Mutex::new(Some(entered));
    let attempts = Arc::new(AtomicUsize::new(0));
    let before = Arc::new(Mutex::new(Vec::new()));
    let opening_native = native.clone();
    let opening_attempts = attempts.clone();
    let opening_before = before.clone();
    let staging = Staging::new(move || {
        let live = opening_native.live.load(Ordering::SeqCst);
        opening_before
            .lock()
            .map_err(|_| io::Error::other("open observation lock"))?
            .push(live);
        if live != 0 {
            return Err(io::Error::other("replacement began before native release"));
        }
        if opening_attempts.fetch_add(1, Ordering::SeqCst) == 1 {
            entered
                .lock()
                .map_err(|_| io::Error::other("constructor notification lock"))?
                .take()
                .ok_or_else(|| io::Error::other("constructor notification missing"))?
                .send(())
                .map_err(|_| io::Error::other("constructor observer ended"))?;
            // Driver errors drop the sole sender and release this wait. The
            // timeout also bounds cleanup if the whole test future is dropped
            // before its driver has been dropped.
            constructor_gate
                .lock()
                .map_err(|_| io::Error::other("constructor gate lock"))?
                .recv_timeout(WAIT)
                .map_err(|_| io::Error::other("constructor gate ended or expired"))?;
        }
        opening_native.opened.fetch_add(1, Ordering::SeqCst);
        opening_native.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Device(opening_native.clone())))
    });
    let plan = staged_client(&c, address, connection, &staging)?;
    let (commands, controls) = mpsc::channel(4);
    let (observe, mut events) = mpsc::channel(64);
    let mut observations = Vec::new();
    let foreground = controlled(
        plan,
        connection,
        Some(staging),
        Some(controls),
        std::future::pending(),
        |item| {
            observations.push(item.clone());
            if let Err(error) = observe.try_send(item) {
                assert!(matches!(error, mpsc::error::TrySendError::Closed(_)));
            }
        },
    );
    let driven_native = native.clone();
    let driven_peer = peer_native.clone();
    let driven_attempts = attempts.clone();
    let driver = async move {
        let ready = event(&mut events, |item| connected_generation(item).is_some()).await?;
        let first = connected_generation(&ready).ok_or("missing first generation")?;
        event(&mut events, exchanged).await?;
        let peer_generation = peer_handle
            .snapshot()
            .generation
            .ok_or("missing first peer generation")?;
        // There is no preceding Disconnect input: this command must perform
        // the existing shared disconnect sub-operation before native setup.
        commands.send(Ok(input::Command::Reconnect)).await?;
        event(&mut events, |item| {
            matches!(item, Event::Terminal {
                generation,
                result: Terminal::Aborted,
            } if *generation == first)
        })
        .await?;
        assert_eq!(driven_native.live.load(Ordering::SeqCst), 0);
        timeout(WAIT, constructor_started).await??;
        assert_eq!(driven_attempts.load(Ordering::SeqCst), 2);
        assert_eq!(driven_native.opened.load(Ordering::SeqCst), 1);
        assert_eq!(driven_native.live.load(Ordering::SeqCst), 0);
        timeout(WAIT, peer_handle.wait_stopped(peer_generation))
            .await?
            .map_err(service_error)?;
        assert_eq!(driven_peer.live.load(Ordering::SeqCst), 0);
        driven_native
            .incoming
            .lock()
            .map_err(|_| "incoming lock")?
            .push_back(packet(13));
        driven_peer
            .incoming
            .lock()
            .map_err(|_| "incoming lock")?
            .push_back(packet(14));
        restart_peer(&peer_handle, replacement, address).await?;
        release_constructor.send(())?;
        let ready = event(&mut events, |item| connected_generation(item).is_some()).await?;
        let second = connected_generation(&ready).ok_or("missing replacement generation")?;
        assert_ne!(first, second);
        event(&mut events, exchanged).await?;
        assert_eq!(driven_native.opened.load(Ordering::SeqCst), 2);
        drop(commands);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second))
    };
    let joined = timeout(Duration::from_secs(15), async {
        tokio::join!(foreground, driver)
    })
    .await;
    stopped(peer).await;
    let (outcome, driven) = joined?;
    let (first, second) = driven?;
    assert_eq!(outcome?, Outcome::Aborted);
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    assert_eq!(peer_native.live.load(Ordering::SeqCst), 0);
    assert_eq!(native.opened.load(Ordering::SeqCst), 2);
    assert_eq!(peer_native.opened.load(Ordering::SeqCst), 2);
    assert_eq!(
        *before.lock().map_err(|_| "open observations lock")?,
        [0, 0]
    );
    assert_eq!(
        *native.received.lock().map_err(|_| "received lock")?,
        [packet(12), packet(14)]
    );
    assert_eq!(
        *peer_native.received.lock().map_err(|_| "received lock")?,
        [packet(11), packet(13)]
    );
    let accepted: Vec<_> = observations
        .iter()
        .filter_map(|item| match item {
            Event::Accepted { action, operation } => Some((*action, *operation)),
            _ => None,
        })
        .collect();
    assert_eq!(accepted.len(), 4);
    assert_eq!(accepted[0], (Action::Connect, first));
    assert_eq!(accepted[1].0, Action::Disconnect);
    assert!(accepted[0].1 < accepted[1].1 && accepted[1].1 < second);
    assert_eq!(accepted[2], (Action::Reconnect, second));
    assert_eq!(accepted[3].0, Action::Disconnect);
    let terminal = observations
        .iter()
        .position(|item| {
            matches!(item,
                Event::Terminal { generation, result: Terminal::Aborted } if *generation == first
            )
        })
        .ok_or("missing original terminal")?;
    let preparing = observations
        .iter()
        .enumerate()
        .filter(|(_, item)| matches!(item, Event::DevicePreparing))
        .nth(1)
        .map(|(index, _)| index)
        .ok_or("missing replacement constructor")?;
    assert!(terminal < preparing);
    assert!(matches!(observations.last(), Some(Event::Status(status))
        if status.phase == Phase::Closed && status.generation == Some(second)
            && status.terminal == Some(Terminal::Aborted)));
    Ok(())
}
