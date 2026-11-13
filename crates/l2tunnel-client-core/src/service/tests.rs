//! Real unprivileged TLS lifecycle and bounded replay regressions.
use super::*;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_core::Duplex;
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::TcpListener, time::timeout};
type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T = ()> = std::result::Result<T, Error>;
mod datagram;
#[cfg(unix)]
mod swift;
fn cfg(duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: crate::Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}
struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: Arc<MemberKey>,
    members: MemberAllowlist,
}
fn credentials() -> Result<Credentials> {
    let cert = rcgen::generate_simple_self_signed(vec!["service-client.test".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let member = Arc::new(MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?);
    Ok(Credentials {
        client: ClientTls::from_der_roots(&chain)?,
        server: ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?,
        members: MemberAllowlist::new(&[member.public_key()])?,
        member,
    })
}
#[derive(Default)]
struct Native {
    incoming: Mutex<VecDeque<Vec<u8>>>,
    received: Mutex<Vec<Vec<u8>>>,
    opened: AtomicUsize,
    live: AtomicUsize,
    events: Mutex<Vec<(bool, usize)>>,
}
struct Device {
    native: Arc<Native>,
    ordinal: usize,
}
impl Drop for Device {
    fn drop(&mut self) {
        self.native.live.fetch_sub(1, Ordering::SeqCst);
        self.native
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((false, self.ordinal));
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(self
            .native
            .incoming
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .map(|packet| {
                out[..packet.len()].copy_from_slice(&packet);
                packet.len()
            }))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.native
            .received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(packet.to_vec());
        Ok(())
    }
}
fn attachment(native: Arc<Native>) -> Attachment {
    Attachment::new(PacketLayer::Ip, move || {
        let ordinal = native.opened.fetch_add(1, Ordering::SeqCst) + 1;
        native.live.fetch_add(1, Ordering::SeqCst);
        native
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((true, ordinal));
        Ok(Box::new(Device {
            native: native.clone(),
            ordinal,
        }))
    })
}
fn plan(
    c: &Credentials,
    remote: std::net::SocketAddr,
    config: ConnectionConfig,
    native: Arc<Native>,
) -> io::Result<Prepared> {
    Prepared::client(
        config,
        Client {
            remote,
            tls: c.client.clone(),
            server_name: "service-client.test".into(),
            member: c.member.clone(),
        },
        attachment(native),
        Options::default(),
    )
}
fn submit(error: SubmitError) -> io::Error {
    io::Error::other(format!("unexpected service result: {error:?}"))
}
async fn drive_once(run: &mut Pin<Box<Run>>) {
    std::future::poll_fn(|cx| {
        assert!(run.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}
#[tokio::test(start_paused = true)]
async fn replay_retirement_identity_and_accepted_deadline_are_bounded() -> Result {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let peer = TcpListener::bind("127.0.0.1:0").await?;
    let p = plan(&c, peer.local_addr()?, cfg(Duplex::Full), native.clone())?;
    let equivalent = plan(&c, peer.local_addr()?, cfg(Duplex::Full), native.clone())?;
    let (handle, run) = channel();
    let mut run = Box::pin(run);
    let key = handle.next_key().map_err(submit)?;
    let first = handle.connect(p.clone(), key).map_err(submit)?;
    tokio::time::advance(Duration::from_millis(10)).await;
    assert_eq!(handle.connect(p.clone(), key), Ok(first));
    assert_eq!(
        handle.connect(equivalent.clone(), key),
        Err(SubmitError::Conflict)
    );
    assert_eq!(
        handle.connect(p.clone(), RequestKey::new(3).ok_or("key")?),
        Err(SubmitError::FutureKey)
    );
    handle.cancel(first.operation).map_err(submit)?;
    drive_once(&mut run).await;
    assert_eq!(
        handle.wait(first.operation).await.map_err(submit)?,
        Completed::Cancelled
    );
    for _ in 1..40 {
        let accepted = handle
            .connect(p.clone(), handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        handle.cancel(accepted.operation).map_err(submit)?;
        drive_once(&mut run).await;
        assert_eq!(
            handle.wait(accepted.operation).await.map_err(submit)?,
            Completed::Cancelled
        );
    }
    assert_eq!(handle.connect(p.clone(), key), Err(SubmitError::Expired));
    assert_eq!(
        handle.wait(first.operation).await,
        Err(SubmitError::Expired)
    );
    assert_eq!(
        handle.connect(equivalent, RequestKey::new(40).ok_or("key")?),
        Err(SubmitError::Conflict)
    );
    assert_eq!(
        handle.connect(p, RequestKey::new(42).ok_or("key")?),
        Err(SubmitError::FutureKey)
    );
    assert_eq!(handle.next_key().map_err(submit)?.value(), 41);
    assert_eq!(native.opened.load(Ordering::SeqCst), 0);
    assert_eq!(handle.0.lock().entries.len(), 32);
    assert_eq!(handle.0.lock().retired_through, 8);
    let mut accept = Box::pin(peer.accept());
    std::future::poll_fn(|cx| {
        assert!(accept.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn accepted_setup_expiry_precedes_first_socket_or_provider_poll() -> Result {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let config = ConnectionConfig {
        handshake_timeout: Duration::from_millis(200),
        ..cfg(Duplex::Half)
    };
    let (handle, run) = channel();
    let accepted = handle
        .connect(
            plan(&c, listener.local_addr()?, config, native.clone())?,
            handle.next_key().map_err(submit)?,
        )
        .map_err(submit)?;
    tokio::time::advance(Duration::from_millis(200)).await;
    let mut run = Box::pin(run);
    drive_once(&mut run).await;
    assert_eq!(
        handle.wait(accepted.operation).await.map_err(submit)?,
        Completed::Failed(Failure {
            kind: io::ErrorKind::TimedOut
        })
    );
    assert_eq!(native.opened.load(Ordering::SeqCst), 0);
    let mut accept = Box::pin(listener.accept());
    std::future::poll_fn(|cx| {
        assert!(accept.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    Ok(())
}
async fn eof<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result {
    timeout(Duration::from_secs(1), async {
        let mut bytes = [0; 4096];
        for _ in 0..32 {
            match stream.read(&mut bytes).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err("bounded EOF witness exhausted".into())
    })
    .await?
}
#[tokio::test]
async fn real_first_auth_then_cancel_releases_both_original_lanes_before_result() -> Result {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let config = cfg(Duplex::Half);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (handle, run) = channel();
    let accepted = handle
        .connect(
            plan(&c, listener.local_addr()?, config, native.clone())?,
            handle.next_key().map_err(submit)?,
        )
        .map_err(submit)?;
    let owner = tokio::spawn(run);
    let result = timeout(Duration::from_secs(5), async {
        let (first, _) = listener.accept().await?;
        first.set_nodelay(true)?;
        let mut first = l2tunnel_auth::server_accept(
            first,
            &c.server,
            &c.members,
            config.session()?,
            config.handshake_timeout,
        )
        .await?;
        let (mut second, _) = listener.accept().await?;
        second.set_nodelay(true)?;
        // A genuine first member proof and original second accepted socket exist.
        assert_eq!(first.info().config, config.session()?);
        assert!(handle.snapshot().runtime.is_none());
        handle.cancel(accepted.operation).map_err(submit)?;
        assert_eq!(
            handle.wait(accepted.operation).await.map_err(submit)?,
            Completed::Cancelled
        );
        assert_eq!(native.opened.load(Ordering::SeqCst), 0);
        eof(&mut first).await?;
        eof(&mut second).await?;
        Ok::<_, Error>(())
    })
    .await;
    owner.abort();
    let joined = owner.await;
    assert!(
        joined
            .as_ref()
            .err()
            .is_some_and(tokio::task::JoinError::is_cancelled)
    );
    result??;
    Ok(())
}
fn packet(seed: u8) -> Vec<u8> {
    let mut packet = vec![0; 83];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&83u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 2, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 2, 0, 2]);
    packet[20..22].copy_from_slice(&1100u16.to_be_bytes());
    packet[22..24].copy_from_slice(&2200u16.to_be_bytes());
    packet[24..26].copy_from_slice(&63u16.to_be_bytes());
    for (i, b) in packet[28..].iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    packet
}
async fn received(native: &Native, expected: &[Vec<u8>]) -> Result {
    timeout(Duration::from_secs(3), async {
        loop {
            if native
                .received
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice()
                == expected
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}
#[tokio::test]
async fn real_reconnect_releases_device_and_old_tls_before_replacement_bytes_and_apply() -> Result {
    for duplex in [Duplex::Full, Duplex::Half] {
        let c = credentials()?;
        let config = cfg(duplex);
        let native = Arc::new(Native::default());
        let remote_native = Arc::new(Native::default());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (old_closed, closed) = tokio::sync::oneshot::channel();
        let server = c.server.clone();
        let members = c.members.clone();
        let peer_native = remote_native.clone();
        let peer = tokio::spawn(async move {
            let mut closed = Some(old_closed);
            for _ in 0..2 {
                let link = crate::accept(&listener, &server, &members, config).await?;
                let device = attachment(peer_native.clone()).open()?;
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
                if let Some(signal) = closed.take() {
                    let _ = signal.send(());
                }
            }
            Ok::<_, io::Error>(())
        });
        let (handle, run) = channel();
        let owner = tokio::spawn(run);
        let plan = plan(&c, address, config, native.clone())?;
        let accepted = handle
            .connect(plan.clone(), handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        // An abandoned waiter/handle never cancels the accepted operation.
        let abandoned = handle.clone();
        let mut waiter = Box::pin(abandoned.wait(accepted.operation));
        std::future::poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(waiter);
        drop(abandoned);
        let result = timeout(Duration::from_secs(8), async {
            let generation = match handle.wait(accepted.operation).await.map_err(submit)? {
                Completed::Connected { generation } => generation,
                other => return Err(format!("setup: {other:?}").into()),
            };
            assert!(
                handle
                    .snapshot()
                    .runtime
                    .is_some_and(|s| s.managed().is_some_and(|s| s.running))
            );
            native
                .incoming
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_back(packet(7));
            received(&remote_native, &[packet(7)]).await?;
            assert_eq!(
                handle.apply(
                    local::Request {
                        version: local::VERSION,
                        action: local::Action::DrainProxy {}
                    },
                    handle.next_key().map_err(submit)?
                ),
                Err(SubmitError::Unsupported)
            );
            let request = local::Request {
                version: local::VERSION,
                action: local::Action::SwitchCompression {
                    compression: local::Compression::Lz4,
                },
            };
            let applied = handle
                .apply(request, handle.next_key().map_err(submit)?)
                .map_err(submit)?;
            assert_eq!(
                handle.cancel(applied.operation),
                Err(SubmitError::Unsupported)
            );
            match handle.wait(applied.operation).await.map_err(submit)? {
                Completed::Applied(response) => {
                    assert!(response.ok);
                    assert_eq!(response.state.as_ref().map(|s| s.epoch), Some(2));
                }
                other => return Err(format!("apply: {other:?}").into()),
            }
            let replacement = handle
                .reconnect(plan, handle.next_key().map_err(submit)?)
                .map_err(submit)?;
            let next = match handle.wait(replacement.operation).await.map_err(submit)? {
                Completed::Connected { generation } => generation,
                other => return Err(format!("reconnect: {other:?}").into()),
            };
            assert_ne!(generation, next);
            closed.await?;
            assert_eq!(
                handle.wait_stopped(generation).await.map_err(submit)?,
                Terminal::Aborted
            );
            let events = native
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            assert_eq!(events, vec![(true, 1), (false, 1), (true, 2)]);
            assert_eq!(native.live.load(Ordering::SeqCst), 1);
            assert_eq!(
                handle
                    .snapshot()
                    .runtime
                    .as_ref()
                    .and_then(|s| s.managed())
                    .map(|s| s.epoch.0),
                Some(1)
            );
            native
                .incoming
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_back(packet(91));
            received(&remote_native, &[packet(7), packet(91)]).await?;
            let stopped = handle
                .disconnect(handle.next_key().map_err(submit)?)
                .map_err(submit)?;
            assert_eq!(
                handle.wait(stopped.operation).await.map_err(submit)?,
                Completed::Aborted
            );
            assert_eq!(native.live.load(Ordering::SeqCst), 0);
            assert_eq!(
                handle.wait_stopped(next).await.map_err(submit)?,
                Terminal::Aborted
            );
            Ok::<_, Error>(())
        })
        .await;
        owner.abort();
        let _ = owner.await;
        match result {
            Ok(Ok(())) => {
                timeout(Duration::from_secs(1), peer).await???;
            }
            other => {
                peer.abort();
                let _ = peer.await;
                return Err(format!("lifecycle: {other:?}").into());
            }
        }
        assert_eq!(remote_native.live.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn server_idle_cancel_releases_original_listener_without_opening_device() -> Result {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let config = cfg(Duplex::Half);
    let plan = Prepared::server(
        config,
        Server {
            listen: "127.0.0.1:0".parse()?,
            tls: c.server,
            members: c.members,
        },
        attachment(native.clone()),
        Options::default(),
    )?;
    let (handle, run) = channel();
    let mut changed = handle.subscribe();
    let accepted = handle
        .connect(plan, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let owner = tokio::spawn(run);
    let result = timeout(Duration::from_secs(2), async {
        let address = loop {
            if let Some(address) = handle.snapshot().listening {
                assert_eq!(address.operation, accepted.operation);
                break address.address;
            }
            changed.changed().await?;
        };
        assert!(
            std::net::TcpListener::bind(address).is_err(),
            "actual listener was never owned"
        );
        handle.cancel(accepted.operation).map_err(submit)?;
        assert_eq!(
            handle.wait(accepted.operation).await.map_err(submit)?,
            Completed::Cancelled
        );
        let _rebound = std::net::TcpListener::bind(address)?;
        assert_eq!(native.opened.load(Ordering::SeqCst), 0);
        Ok::<_, Error>(())
    })
    .await;
    owner.abort();
    let _ = owner.await;
    result??;
    Ok(())
}

#[tokio::test]
async fn dropping_run_during_actual_pending_apply_reports_unknown_not_cancelled() -> Result {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let config = cfg(Duplex::Full);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (handle, run) = channel();
    let accepted = handle
        .connect(
            plan(&c, listener.local_addr()?, config, native.clone())?,
            handle.next_key().map_err(submit)?,
        )
        .map_err(submit)?;
    let owner = tokio::spawn(run);
    let result = timeout(Duration::from_secs(5), async {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let mut peer = l2tunnel_auth::server_accept(
            stream,
            &c.server,
            &c.members,
            config.session()?,
            config.handshake_timeout,
        )
        .await?;
        let generation = match handle.wait(accepted.operation).await.map_err(submit)? {
            Completed::Connected { generation } => generation,
            other => return Err(format!("setup: {other:?}").into()),
        };
        let applied = handle
            .apply(
                local::Request {
                    version: local::VERSION,
                    action: local::Action::SwitchCompression {
                        compression: local::Compression::Lz4,
                    },
                },
                handle.next_key().map_err(submit)?,
            )
            .map_err(submit)?;
        // Read a real authenticated TLS control record on the original peer;
        // intentionally withhold its management response. No fake handle result.
        let mut prefix = [0; 4];
        peer.read_exact(&mut prefix).await?;
        let length = u32::from_be_bytes(prefix) as usize;
        assert!((44..=44 + 4096).contains(&length));
        let mut record = vec![0; length];
        peer.read_exact(&mut record).await?;
        assert_eq!(&record[..4], &[1, 2, 0, 0]); // draft v1 Control header
        assert_eq!(&record[4..12], &[0; 8]); // dedicated management epoch
        assert_eq!(&record[20..36], &peer.info().session_id);
        assert_eq!(
            u32::from_be_bytes(record[40..44].try_into()?) as usize,
            length - 44
        );
        assert_eq!(handle.snapshot().phase, Phase::Applying);
        assert_eq!(
            handle.cancel(applied.operation),
            Err(SubmitError::Unsupported)
        );
        let mut waiting = Box::pin(handle.wait(applied.operation));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(waiting);
        Ok::<_, Error>((applied.operation, generation, peer))
    })
    .await;
    owner.abort();
    let _ = owner.await;
    let (operation, generation, mut peer) = result??;
    assert_eq!(
        handle.wait(operation).await.map_err(submit)?,
        Completed::OutcomeUnknown
    );
    assert_eq!(
        handle.wait_stopped(generation).await.map_err(submit)?,
        Terminal::Aborted
    );
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    assert_eq!(handle.snapshot().phase, Phase::Closed);
    assert!(handle.snapshot().listening.is_none());
    eof(&mut peer).await?;
    Ok(())
}

#[tokio::test]
async fn real_ready_then_cancel_never_publishes_unconnected_profile_or_generation() -> Result {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let config = cfg(Duplex::Full);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let prepared = Prepared::client(
        config,
        Client {
            remote: listener.local_addr()?,
            tls: c.client,
            server_name: "service-client.test".into(),
            member: c.member,
        },
        attachment(native.clone()),
        Options {
            delivery: None,
            profile_interval: Some(Duration::from_millis(100)),
        },
    )?;
    let (handle, _run) = channel();
    let accepted = handle
        .connect(prepared, handle.next_key().map_err(submit)?)
        .map_err(submit)?;
    let job = handle
        .0
        .lock()
        .queued
        .take()
        .ok_or("accepted setup missing")?;
    let Command::Connect(plan) = job.command else {
        return Err("wrong setup command".into());
    };
    // Drive the actual production setup boundary, retaining its ready owner just
    // before the same production atomic publish point used by Run.
    let (ready, peer) = timeout(Duration::from_secs(4), async {
        tokio::join!(owner::establish(handle.0.clone(), plan, accepted), async {
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true)?;
            l2tunnel_auth::server_accept(
                stream,
                &c.server,
                &c.members,
                config.session()?,
                config.handshake_timeout,
            )
            .await
            .map_err(io::Error::other)
        })
    })
    .await?;
    let ready = ready?;
    let mut peer = peer?;
    assert_eq!(native.live.load(Ordering::SeqCst), 1);
    assert!(
        handle.0.lock().backend.is_none(),
        "uncommitted setup leaked its profiler"
    );
    assert!(handle.snapshot().generation.is_none());
    handle.cancel(accepted.operation).map_err(submit)?;
    assert!(owner::publish_ready(&handle.0, ready, accepted).is_none());
    assert_eq!(
        handle.wait(accepted.operation).await.map_err(submit)?,
        Completed::Cancelled
    );
    assert!(handle.0.lock().backend.is_none());
    assert!(handle.snapshot().generation.is_none());
    assert!(handle.snapshot().listening.is_none());
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    eof(&mut peer).await?;
    Ok(())
}

#[test]
fn only_known_control_completions_can_claim_applied_or_definitely_rejected() {
    let make = |ok: bool, code: &str| local::Response {
        version: local::VERSION,
        ok,
        code: code.into(),
        state: None,
    };
    assert!(matches!(
        owner::classify_apply(make(true, "ok")),
        Completed::Applied(_)
    ));
    for code in [
        "busy",
        "not_coordinator",
        "aborted",
        "unsupported",
        "unsupported_version",
    ] {
        assert!(
            matches!(
                owner::classify_apply(make(false, code)),
                Completed::Rejected(_)
            ),
            "{code}"
        );
    }
    for code in ["closed", "uncertain", "accepted", "future_code", "ok"] {
        assert_eq!(
            owner::classify_apply(make(false, code)),
            Completed::OutcomeUnknown
        );
    }
    assert_eq!(
        owner::classify_apply(make(true, "accepted")),
        Completed::OutcomeUnknown
    );
}

#[tokio::test]
async fn dropping_full_terminal_history_keeps_capacity_and_latest_retired_results() -> Result {
    let (handle, run) = channel();
    // Seed the legal full-history teardown metadata. Actual TLS/device owner
    // release is independently covered by the lifecycle integration tests above.
    let original_capacity = {
        let mut state = handle.0.lock();
        for id in 1..=RETAINED as u64 {
            state
                .terminals
                .push_back((OperationId(id), Terminal::Aborted));
        }
        state.last_key = RETAINED as u64 + 1;
        state.snapshot.generation = Some(OperationId(state.last_key));
        state.snapshot.phase = Phase::Connected;
        state.terminals.capacity()
    };
    assert_eq!(original_capacity, RETAINED);
    drop(run);
    {
        let state = handle.0.lock();
        assert_eq!(state.terminals.len(), RETAINED);
        assert_eq!(
            state.terminals.capacity(),
            original_capacity,
            "teardown expanded bounded terminal storage"
        );
        assert_eq!(state.terminals.front().map(|(id, _)| id.value()), Some(2));
        assert_eq!(
            state.terminals.back().map(|(id, _)| id.value()),
            Some(RETAINED as u64 + 1)
        );
    }
    assert_eq!(
        handle.wait_stopped(OperationId(1)).await,
        Err(SubmitError::Expired)
    );
    assert_eq!(
        handle.wait_stopped(OperationId(17)).await.map_err(submit)?,
        Terminal::Aborted
    );
    assert_eq!(
        handle
            .wait_stopped(OperationId(RETAINED as u64 + 1))
            .await
            .map_err(submit)?,
        Terminal::Aborted
    );
    Ok(())
}
