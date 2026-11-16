//! Portable real-TLS foreground evidence; these are not Windows driver tests.
use super::*;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_client_core::service::{Attachment, Client, Options, Server};
use l2tunnel_core::Duplex;
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::timeout};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn config() -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex: Duplex::Full,
        max_packet: 1500,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}

struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: Arc<MemberKey>,
    members: MemberAllowlist,
}

fn credentials() -> TestResult<Credentials> {
    let cert = rcgen::generate_simple_self_signed(vec!["foreground.test".into()])?;
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
    opened: AtomicUsize,
    live: AtomicUsize,
    fail: AtomicBool,
    incoming: Mutex<VecDeque<Vec<u8>>>,
    received: Mutex<Vec<Vec<u8>>>,
}

struct Device(Arc<Native>);

impl Drop for Device {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl PacketDevice for Device {
    type Error = io::Error;

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        if self.0.fail.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "test device failed",
            ));
        }
        let packet = self
            .0
            .incoming
            .lock()
            .map_err(|_| io::Error::other("test incoming lock"))?
            .pop_front();
        packet
            .map(|packet| {
                let target = out
                    .get_mut(..packet.len())
                    .ok_or_else(|| io::Error::other("test packet exceeds read buffer"))?;
                target.copy_from_slice(&packet);
                Ok(packet.len())
            })
            .transpose()
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.0
            .received
            .lock()
            .map_err(|_| io::Error::other("test received lock"))?
            .push(packet.to_vec());
        Ok(())
    }
}

fn attachment(native: Arc<Native>) -> Attachment {
    Attachment::new(PacketLayer::Ip, move || {
        native.opened.fetch_add(1, Ordering::SeqCst);
        native.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Device(native.clone())))
    })
}

fn client(c: &Credentials, remote: SocketAddr, native: Arc<Native>) -> io::Result<Prepared> {
    client_with_config(c, remote, native, config())
}

fn client_with_config(
    c: &Credentials,
    remote: SocketAddr,
    native: Arc<Native>,
    connection: ConnectionConfig,
) -> io::Result<Prepared> {
    Prepared::client(
        connection,
        Client {
            remote,
            tls: c.client.clone(),
            server_name: "foreground.test".into(),
            member: c.member.clone(),
        },
        attachment(native),
        Options::default(),
    )
}

async fn server(
    c: &Credentials,
    native: Arc<Native>,
) -> TestResult<(Handle, JoinHandle<io::Result<()>>, SocketAddr)> {
    server_with_config(c, native, config()).await
}

async fn server_with_config(
    c: &Credentials,
    native: Arc<Native>,
    connection: ConnectionConfig,
) -> TestResult<(Handle, JoinHandle<io::Result<()>>, SocketAddr)> {
    let plan = Prepared::server(
        connection,
        Server {
            listen: "127.0.0.1:0".parse()?,
            tls: c.server.clone(),
            members: c.members.clone(),
        },
        attachment(native),
        Options::default(),
    )?;
    let (handle, owner) = service::channel();
    let mut changes = handle.subscribe();
    handle
        .connect(plan, handle.next_key().map_err(service_error)?)
        .map_err(service_error)?;
    let task = tokio::spawn(owner);
    let address = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(listener) = handle.snapshot().listening {
                return Ok::<_, io::Error>(listener.address);
            }
            changes
                .changed()
                .await
                .map_err(|_| io::Error::other("test service observation closed"))?;
        }
    })
    .await??;
    Ok((handle, task, address))
}

async fn stopped(task: JoinHandle<io::Result<()>>) {
    task.abort();
    let _ = task.await;
}

fn packet(identity: u8) -> Vec<u8> {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = identity;
    packet
}

#[tokio::test]
async fn rejected_membership_never_opens_packet_device() -> TestResult {
    let mut c = credentials()?;
    let unrelated = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    c.members = MemberAllowlist::new(&[unrelated.public_key()])?;
    let native = Arc::new(Native::default());
    let peer_native = Arc::new(Native::default());
    let (_, peer, address) = server(&c, peer_native.clone()).await?;
    let result = timeout(
        Duration::from_secs(5),
        run(
            client(&c, address, native.clone())?,
            config(),
            std::future::pending(),
            |_| {},
        ),
    )
    .await?;
    stopped(peer).await;
    assert!(result.is_err());
    assert_eq!(native.opened.load(Ordering::SeqCst), 0);
    assert_eq!(peer_native.opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn setup_cancellation_releases_unverified_socket_without_device() -> TestResult {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (accepted, cancellation) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _ = accepted.send(());
        // Keep this unauthenticated socket alive until the foreground owner
        // releases it; consume any ClientHello bytes preceding actual EOF.
        let mut input = [0_u8; 4096];
        use tokio::io::AsyncReadExt;
        while stream.read(&mut input).await? != 0 {}
        Ok::<_, io::Error>(())
    });
    let outcome = timeout(
        Duration::from_secs(5),
        run(
            client(&c, address, native.clone())?,
            config(),
            async {
                cancellation
                    .await
                    .map_err(|_| io::Error::other("test cancellation dropped"))
            },
            |_| {},
        ),
    )
    .await??;
    timeout(Duration::from_secs(5), peer).await???;
    assert_eq!(outcome, Outcome::Cancelled);
    assert_eq!(native.opened.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn connected_cancellation_waits_for_exact_packets_and_device_release() -> TestResult {
    for duplex in [Duplex::Half, Duplex::Full] {
        connected_cancellation(duplex).await?;
    }
    Ok(())
}

async fn connected_cancellation(duplex: Duplex) -> TestResult {
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
    let (_, peer, address) = server_with_config(&c, peer_native.clone(), connection).await?;
    let (stop, cancellation) = oneshot::channel();
    let mut stop = Some(stop);
    let mut observed = Vec::new();
    let mut requested_events = 0;
    let outcome = timeout(
        Duration::from_secs(5),
        run(
            client_with_config(&c, address, native.clone(), connection)?,
            connection,
            async {
                cancellation
                    .await
                    .map_err(|_| io::Error::other("test stop dropped"))
            },
            |event| {
                if let Event::Requested(requested) = &event {
                    requested_events += 1;
                    assert_eq!(requested.layer, connection.layer);
                    assert_eq!(requested.duplex, connection.duplex);
                    assert_eq!(requested.max_packet, connection.max_packet);
                    assert_eq!(requested.compression, connection.compression);
                    assert_eq!(requested.handshake_timeout, connection.handshake_timeout);
                }
                if let Event::Status(snapshot) = event {
                    if snapshot.managed.as_ref().is_some_and(|runtime| {
                        runtime.delivered == 1 && runtime.peer_delivered == 1
                    }) && let Some(stop) = stop.take()
                    {
                        let _ = stop.send(());
                    }
                    if snapshot.phase == Phase::Closed {
                        assert_eq!(native.live.load(Ordering::SeqCst), 0);
                    }
                    observed.push(snapshot);
                }
            },
        ),
    )
    .await??;
    stopped(peer).await;
    assert_eq!(requested_events, 1);
    assert_eq!(outcome, Outcome::Aborted);
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    assert_eq!(peer_native.live.load(Ordering::SeqCst), 0);
    assert_eq!(
        *native.received.lock().map_err(|_| "received lock")?,
        [packet(2)]
    );
    assert_eq!(
        *peer_native.received.lock().map_err(|_| "received lock")?,
        [packet(1)]
    );
    assert!(
        observed
            .iter()
            .any(|snapshot| snapshot.phase == Phase::Connected)
    );
    assert_eq!(
        observed.last().and_then(|snapshot| snapshot.terminal),
        Some(Terminal::Aborted)
    );
    Ok(())
}

#[tokio::test]
async fn actual_device_failure_exits_and_releases_owner() -> TestResult {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let peer_native = Arc::new(Native::default());
    let (_, peer, address) = server(&c, peer_native).await?;
    let result = timeout(
        Duration::from_secs(5),
        run(
            client(&c, address, native.clone())?,
            config(),
            std::future::pending(),
            |event| {
                if matches!(
                    event,
                    Event::Status(Status {
                        phase: Phase::Connected,
                        ..
                    })
                ) {
                    native.fail.store(true, Ordering::SeqCst);
                }
            },
        ),
    )
    .await?;
    stopped(peer).await;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::BrokenPipe)
    );
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn cancellation_source_error_still_releases_connected_device() -> TestResult {
    let c = credentials()?;
    let native = Arc::new(Native::default());
    let (_, peer, address) = server(&c, Arc::new(Native::default())).await?;
    let (stop, cancellation) = oneshot::channel();
    let mut stop = Some(stop);
    let result = timeout(
        Duration::from_secs(5),
        run(
            client(&c, address, native.clone())?,
            config(),
            async {
                cancellation
                    .await
                    .map_err(|_| io::Error::other("test stop dropped"))?;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test signal registration failed",
                ))
            },
            |event| {
                if matches!(
                    event,
                    Event::Status(Status {
                        phase: Phase::Connected,
                        ..
                    })
                ) && let Some(stop) = stop.take()
                {
                    let _ = stop.send(());
                }
            },
        ),
    )
    .await?;
    stopped(peer).await;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(native.live.load(Ordering::SeqCst), 0);
    Ok(())
}

#[path = "termination_tests.rs"]
mod termination;

#[path = "lifecycle_tests.rs"]
mod lifecycle;
