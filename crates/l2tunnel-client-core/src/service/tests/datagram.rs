//! Base UDP ownership by the shared service: real loopback TLS bootstrap and UDP
//! sockets through the public factories, with injected packet devices.
use super::*;
use crate::udp::{CoverProfile, Endpoints, Protection, RecoveryMode, Settings};
use std::net::{SocketAddr, UdpSocket as Reservation};

/// Four distinct loopback UDP addresses, released just before the factories bind.
fn ports() -> io::Result<[SocketAddr; 4]> {
    let held = [
        crate::test_ports::reserve(false)?,
        crate::test_ports::reserve(false)?,
        crate::test_ports::reserve(false)?,
        crate::test_ports::reserve(false)?,
    ];
    Ok([
        held[0].local_addr()?,
        held[1].local_addr()?,
        held[2].local_addr()?,
        held[3].local_addr()?,
    ])
}
fn settings(duplex: Duplex, ports: [SocketAddr; 4], server: bool) -> Settings {
    let lane = |local: SocketAddr, peer: SocketAddr| {
        if server {
            Endpoints {
                local: peer,
                peer: local,
            }
        } else {
            Endpoints { local, peer }
        }
    };
    Settings {
        forward: lane(ports[0], ports[1]),
        reverse: (duplex == Duplex::Half).then(|| lane(ports[2], ports[3])),
        cover: CoverProfile::OpenVpnLike,
        protection: Protection::ChaCha20Poly1305,
        path_mtu: 1280,
        recovery: RecoveryMode::SelectiveRepeat,
    }
}
fn client_plan(
    c: &Credentials,
    remote: SocketAddr,
    config: ConnectionConfig,
    settings: Settings,
    native: Arc<Native>,
) -> io::Result<Prepared> {
    Prepared::udp_client(
        config,
        Client {
            remote,
            tls: c.client.clone(),
            server_name: "service-client.test".into(),
            member: c.member.clone(),
        },
        settings,
        crate::delivery_tests::policy(),
        attachment(native),
    )
}
fn server_plan(
    c: &Credentials,
    config: ConnectionConfig,
    settings: Settings,
    native: Arc<Native>,
) -> io::Result<Prepared> {
    Prepared::udp_server(
        config,
        Server {
            listen: "127.0.0.1:0".parse().map_err(io::Error::other)?,
            tls: c.server.clone(),
            members: c.members.clone(),
        },
        settings,
        crate::delivery_tests::policy(),
        attachment(native),
    )
}
/// Drive the caller-owned Run in this task until `future` completes. No service
/// work runs on any other task, so a later single poll is an exact witness.
async fn drive<T>(run: &mut Pin<Box<Run>>, future: impl Future<Output = T>) -> Result<T> {
    tokio::pin!(future);
    timeout(Duration::from_secs(8), async {
        tokio::select! {
            result = run.as_mut() => Err(format!("service owner ended: {result:?}").into()),
            value = &mut future => Ok(value),
        }
    })
    .await?
}
async fn listening(handle: &Handle, operation: OperationId) -> Result<SocketAddr> {
    let mut changed = handle.subscribe();
    timeout(Duration::from_secs(3), async {
        loop {
            if let Some(listening) = handle.snapshot().listening
                && listening.operation == operation
            {
                return Ok(listening.address);
            }
            changed.changed().await?;
        }
    })
    .await?
}
fn connected(result: Completed) -> Result<OperationId> {
    match result {
        Completed::Connected { generation } => Ok(generation),
        other => Err(format!("setup: {other:?}").into()),
    }
}
fn push(native: &Native, packet: Vec<u8>) {
    native
        .incoming
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push_back(packet);
}
fn switch() -> local::Request {
    local::Request {
        version: local::VERSION,
        action: local::Action::SwitchCompression {
            compression: local::Compression::Lz4,
        },
    }
}
fn rebind(addresses: &[SocketAddr]) -> io::Result<()> {
    for address in addresses {
        drop(Reservation::bind(address)?);
    }
    Ok(())
}
struct Pair {
    server: Handle,
    server_owner: tokio::task::JoinHandle<io::Result<()>>,
    server_native: Arc<Native>,
    server_generation: OperationId,
    client_generation: OperationId,
}
/// Server service on its own task; client Run stays owned by the calling test.
async fn connect_pair(
    c: &Credentials,
    config: ConnectionConfig,
    ports: [SocketAddr; 4],
    client: &Handle,
    run: &mut Pin<Box<Run>>,
    native: Arc<Native>,
) -> Result<Pair> {
    let (server, server_run) = channel();
    let server_owner = tokio::spawn(server_run);
    let server_native = Arc::new(Native::default());
    let accepted = server
        .connect(
            server_plan(
                c,
                config,
                settings(config.duplex, ports, true),
                server_native.clone(),
            )?,
            server.next_key().map_err(submit)?,
        )
        .map_err(submit)?;
    let remote = listening(&server, accepted.operation).await?;
    // An idle authenticated-factory wait is not readiness or a runtime status.
    assert_eq!(server.snapshot().phase, Phase::Authenticating);
    assert!(server.snapshot().runtime.is_none());
    assert!(server.snapshot().generation.is_none());
    let joined = client
        .connect(
            client_plan(
                c,
                remote,
                config,
                settings(config.duplex, ports, false),
                native,
            )?,
            client.next_key().map_err(submit)?,
        )
        .map_err(submit)?;
    let client_generation = connected(
        drive(run, client.wait(joined.operation))
            .await?
            .map_err(submit)?,
    )?;
    let server_generation = connected(
        drive(run, server.wait(accepted.operation))
            .await?
            .map_err(submit)?,
    )?;
    Ok(Pair {
        server,
        server_owner,
        server_native,
        server_generation,
        client_generation,
    })
}
fn assert_observed(handle: &Handle, generation: OperationId, expected: Settings) -> Result {
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.phase, Phase::Connected);
    assert_eq!(snapshot.generation, Some(generation));
    assert!(snapshot.operation.is_none() && snapshot.listening.is_none());
    let observed = snapshot
        .runtime
        .ok_or("live UDP generation has no observation")?;
    assert!(observed.managed().is_none(), "UDP reported as managed");
    let frame = observed.udp_frame().ok_or("UDP observation")?;
    let config = cfg(expected_duplex(expected));
    assert_eq!(frame.requested, expected);
    assert_eq!(
        frame.effective,
        crate::udp::runtime_config(config, expected)?
    );
    assert_eq!(frame.effective.cover, CoverProfile::OpenVpnLike);
    assert_eq!(frame.effective.protection, Protection::ChaCha20Poly1305);
    assert_eq!(frame.delivery, crate::delivery_tests::policy());
    match config.duplex {
        Duplex::Full => assert!(frame.lanes.lanes[0].is_some() && frame.lanes.lanes[1].is_none()),
        Duplex::Half => assert!(frame.lanes.lanes.iter().all(Option::is_some)),
    }
    // Three independent domains remain separately reported, not merged.
    let lane = frame.lanes.lanes[0].ok_or("first lane")?;
    assert_eq!(lane.local_queue_limit, config.runtime().queue_packets);
    assert!(handle.profile(generation).map_err(submit)?.is_none());
    assert!(
        handle
            .datagram_observer(generation)
            .map_err(submit)?
            .is_some()
    );
    Ok(())
}
fn expected_duplex(settings: Settings) -> Duplex {
    if settings.reverse.is_some() {
        Duplex::Half
    } else {
        Duplex::Full
    }
}

#[tokio::test]
async fn udp_ready_needs_published_lanes_apply_is_unsupported_and_abort_releases_sockets_inline()
-> Result {
    for duplex in [Duplex::Full, Duplex::Half] {
        let c = credentials()?;
        let config = cfg(duplex);
        let ports = ports()?;
        let native = Arc::new(Native::default());
        let (handle, run) = channel();
        let mut run = Box::pin(run);
        let pair = connect_pair(&c, config, ports, &handle, &mut run, native.clone()).await?;
        assert_observed(
            &handle,
            pair.client_generation,
            settings(duplex, ports, false),
        )?;
        assert_observed(
            &pair.server,
            pair.server_generation,
            settings(duplex, ports, true),
        )?;
        assert_eq!(native.opened.load(Ordering::SeqCst), 1);

        // A fixed-profile datagram backend rejects apply before reserving a key,
        // an operation slot or a queued command; nothing reaches the runtime.
        let key = handle.next_key().map_err(submit)?;
        assert_eq!(handle.apply(switch(), key), Err(SubmitError::Unsupported));
        assert_eq!(handle.next_key().map_err(submit)?, key);
        assert!(handle.0.lock().queued.is_none());
        assert_eq!(handle.0.lock().entries.len(), 1);
        assert_eq!(handle.snapshot().phase, Phase::Connected);
        assert_eq!(handle.request(switch()).await.code, "unsupported");
        let status = local::Request {
            version: local::VERSION,
            action: local::Action::Status {},
        };
        assert_eq!(handle.request(status).await.code, "unsupported");
        assert_eq!(handle.next_key().map_err(submit)?, key);

        // Exact native bytes in both directions through the service-owned runtime.
        push(&native, packet(7));
        drive(&mut run, received(&pair.server_native, &[packet(7)])).await??;
        push(&pair.server_native, packet(33));
        drive(&mut run, received(&native, &[packet(33)])).await??;

        // One owner poll, no yield: the abort result, device release and exact
        // UDP rebind must all already hold. Spawned children could not have
        // dropped their sockets before this task yields.
        let stopped = handle
            .disconnect(handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        drive_once(&mut run).await;
        let mut waiter = Box::pin(handle.wait(stopped.operation));
        let result = std::future::poll_fn(|cx| Poll::Ready(waiter.as_mut().poll(cx))).await;
        assert_eq!(result, Poll::Ready(Ok(Completed::Aborted)));
        drop(waiter);
        assert_eq!(native.live.load(Ordering::SeqCst), 0);
        let mine: &[SocketAddr] = if duplex == Duplex::Half {
            &[ports[0], ports[2]]
        } else {
            &[ports[0]]
        };
        rebind(mine)?;
        assert_eq!(handle.snapshot().phase, Phase::Disconnected);
        assert_eq!(
            handle
                .wait_stopped(pair.client_generation)
                .await
                .map_err(submit)?,
            Terminal::Aborted
        );
        // The last observation stays typed as UDP after the generation stopped.
        assert!(
            handle
                .snapshot()
                .runtime
                .is_some_and(|o| o.udp_frame().is_some())
        );

        // The peer observes a real runtime failure, never a clean close, and its
        // own inline children release the mirrored sockets before publication.
        match drive(&mut run, pair.server.wait_stopped(pair.server_generation))
            .await?
            .map_err(submit)?
        {
            Terminal::Failed(_) => {}
            other => return Err(format!("peer terminal: {other:?}").into()),
        }
        let theirs: &[SocketAddr] = if duplex == Duplex::Half {
            &[ports[1], ports[3]]
        } else {
            &[ports[1]]
        };
        rebind(theirs)?;
        assert_eq!(pair.server_native.live.load(Ordering::SeqCst), 0);

        // A new generation on the identical UDP addresses forwards new bytes.
        let again = pair
            .server
            .connect(
                server_plan(
                    &c,
                    config,
                    settings(duplex, ports, true),
                    pair.server_native.clone(),
                )?,
                pair.server.next_key().map_err(submit)?,
            )
            .map_err(submit)?;
        let remote = listening(&pair.server, again.operation).await?;
        let rejoin = handle
            .connect(
                client_plan(
                    &c,
                    remote,
                    config,
                    settings(duplex, ports, false),
                    native.clone(),
                )?,
                handle.next_key().map_err(submit)?,
            )
            .map_err(submit)?;
        let next = connected(
            drive(&mut run, handle.wait(rejoin.operation))
                .await?
                .map_err(submit)?,
        )?;
        assert_ne!(next, pair.client_generation);
        assert_eq!(
            handle.datagram_observer(pair.client_generation).err(),
            Some(SubmitError::State)
        );
        push(&native, packet(91));
        drive(
            &mut run,
            received(&pair.server_native, &[packet(7), packet(91)]),
        )
        .await??;
        drop(run);
        assert_eq!(native.live.load(Ordering::SeqCst), 0);
        rebind(mine)?;
        assert_eq!(handle.snapshot().phase, Phase::Closed);
        pair.server_owner.abort();
        let _ = pair.server_owner.await;
    }
    Ok(())
}

#[tokio::test]
async fn udp_idle_cancel_and_original_deadline_release_listener_and_sockets_without_device()
-> Result {
    let c = credentials()?;
    let ports = ports()?;
    // Idle acceptor: cancellation releases the bootstrap listener and UDP socket.
    let native = Arc::new(Native::default());
    let (handle, run) = channel();
    let mut run = Box::pin(run);
    let config = cfg(Duplex::Half);
    let accepted = handle
        .connect(
            server_plan(
                &c,
                config,
                settings(Duplex::Half, ports, true),
                native.clone(),
            )?,
            handle.next_key().map_err(submit)?,
        )
        .map_err(submit)?;
    let address = drive(&mut run, listening(&handle, accepted.operation)).await??;
    assert!(
        Reservation::bind(ports[1]).is_err(),
        "acceptor UDP not owned"
    );
    handle.cancel(accepted.operation).map_err(submit)?;
    drive_once(&mut run).await;
    let mut waiter = Box::pin(handle.wait(accepted.operation));
    let result = std::future::poll_fn(|cx| Poll::Ready(waiter.as_mut().poll(cx))).await;
    assert_eq!(result, Poll::Ready(Ok(Completed::Cancelled)));
    drop(waiter);
    drop(std::net::TcpListener::bind(address)?);
    rebind(&[ports[1], ports[3]])?;
    assert!(handle.snapshot().listening.is_none());
    assert!(handle.snapshot().runtime.is_none());
    assert_eq!(native.opened.load(Ordering::SeqCst), 0);

    // Initiator against a silent TCP peer: the accepted bound is not renewed by
    // the factory's own handshake timer, and expiry releases the bound socket.
    let silent = TcpListener::bind("127.0.0.1:0").await?;
    let config = ConnectionConfig {
        handshake_timeout: Duration::from_millis(300),
        ..cfg(Duplex::Full)
    };
    let started = tokio::time::Instant::now();
    let attempt = handle
        .connect(
            client_plan(
                &c,
                silent.local_addr()?,
                config,
                settings(Duplex::Full, ports, false),
                native.clone(),
            )?,
            handle.next_key().map_err(submit)?,
        )
        .map_err(submit)?;
    let deadline = attempt.deadline.ok_or("setup deadline")?;
    assert!(deadline >= started + config.handshake_timeout);
    assert!(deadline <= tokio::time::Instant::now() + config.handshake_timeout);
    let result = drive(&mut run, handle.wait(attempt.operation))
        .await?
        .map_err(submit)?;
    assert_eq!(
        result,
        Completed::Failed(Failure {
            kind: io::ErrorKind::TimedOut
        })
    );
    // The factory starts its own later timer; the earlier accepted bound wins.
    assert!(tokio::time::Instant::now() >= deadline);
    assert!(started.elapsed() < Duration::from_millis(900));
    rebind(&[ports[0]])?;
    assert_eq!(handle.snapshot().phase, Phase::Failed);
    assert!(handle.snapshot().generation.is_none());
    assert_eq!(native.opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn managed_results_replay_after_a_udp_generation_and_keys_stay_backend_independent() -> Result
{
    let c = credentials()?;
    let config = cfg(Duplex::Full);
    let native = Arc::new(Native::default());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (server, members) = (c.server.clone(), c.members.clone());
    let peer_native = Arc::new(Native::default());
    let peer_device = peer_native.clone();
    let peer = tokio::spawn(async move {
        let link = crate::accept(&listener, &server, &members, config).await?;
        let device = attachment(peer_device).open()?;
        let (_handle, requests) = managed::channel();
        let result = managed::run_managed(
            device,
            link,
            config.runtime(),
            managed::ManagedConfig {
                role: managed::Role::Server,
                initial_mode: config.mode()?,
                transaction_settings: managed::TransactionSettings::default(),
            },
            requests,
        )
        .await;
        assert!(result.is_err(), "local abort became clean managed closure");
        Ok::<_, io::Error>(())
    });
    let (handle, run) = channel();
    let mut run = Box::pin(run);
    let managed_plan = plan(&c, address, config, native.clone())?;
    let first_key = handle.next_key().map_err(submit)?;
    let first = handle
        .connect(managed_plan.clone(), first_key)
        .map_err(submit)?;
    let managed_generation = connected(
        drive(&mut run, handle.wait(first.operation))
            .await?
            .map_err(submit)?,
    )?;
    let apply_key = handle.next_key().map_err(submit)?;
    let applied = handle.apply(switch(), apply_key).map_err(submit)?;
    let original = drive(&mut run, handle.wait(applied.operation))
        .await?
        .map_err(submit)?;
    assert!(matches!(&original, Completed::Applied(response) if response.ok));
    let stopped = handle
        .disconnect(handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    assert_eq!(
        drive(&mut run, handle.wait(stopped.operation))
            .await?
            .map_err(submit)?,
        Completed::Aborted
    );
    timeout(Duration::from_secs(3), peer).await???;

    // Same service, next sequential key, different backend.
    let ports = ports()?;
    let pair = connect_pair(&c, config, ports, &handle, &mut run, native.clone()).await?;
    assert!(pair.client_generation > managed_generation);
    assert!(
        handle
            .snapshot()
            .runtime
            .is_some_and(|o| o.udp_frame().is_some())
    );
    // Retained managed keys resolve with their original fingerprint and result.
    assert_eq!(handle.connect(managed_plan.clone(), first_key), Ok(first));
    assert_eq!(
        handle.wait(first.operation).await.map_err(submit)?,
        Completed::Connected {
            generation: managed_generation
        }
    );
    assert_eq!(handle.apply(switch(), apply_key), Ok(applied));
    assert_eq!(
        handle.wait(applied.operation).await.map_err(submit)?,
        original
    );
    assert_eq!(
        handle
            .wait_stopped(managed_generation)
            .await
            .map_err(submit)?,
        Terminal::Aborted
    );
    // A UDP plan cannot reuse a managed key, and the old generation's profiler
    // or status is not reachable through the UDP generation.
    let foreign = client_plan(
        &c,
        address,
        config,
        settings(Duplex::Full, ports, false),
        native.clone(),
    )?;
    assert_eq!(
        handle.connect(foreign, first_key),
        Err(SubmitError::Conflict)
    );
    assert_eq!(
        handle.profile(managed_generation).err(),
        Some(SubmitError::State)
    );
    // A new apply on the live UDP generation still consumes nothing.
    let key = handle.next_key().map_err(submit)?;
    assert_eq!(handle.apply(switch(), key), Err(SubmitError::Unsupported));
    assert_eq!(handle.next_key().map_err(submit)?, key);
    push(&native, packet(5));
    drive(&mut run, received(&pair.server_native, &[packet(5)])).await??;
    pair.server_owner.abort();
    let _ = pair.server_owner.await;
    Ok(())
}

#[test]
fn readiness_requires_the_exact_published_lane_shape() -> Result {
    use l2tunnel_runtime::udp::Snapshot;
    let (observer, _reporter) = l2tunnel_runtime::udp::observations();
    let empty = observer.status();
    assert_eq!(empty, Snapshot::default());
    // A constructed observer's default snapshot is never readiness.
    assert!(!owner::lanes_ready(Duplex::Full, empty));
    assert!(!owner::lanes_ready(Duplex::Half, empty));
    Ok(())
}
