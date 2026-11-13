//! Swift ownership by the shared service: real loopback TLS bootstrap and UDP
//! sockets through the public factories, with readiness-capable devices.
use super::*;
use crate::swift::{Native as Readable, Settings};
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

/// A datagram socket standing in for a TAP/TUN descriptor.
struct Pipe(UnixDatagram);
impl AsRawFd for Pipe {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}
impl PacketDevice for Pipe {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match self.0.recv(buffer) {
            Ok(length) => Ok(Some(length)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.0.send(packet).map(drop)
    }
}
/// The application side of the most recently opened device and the count of
/// devices opened so far.
#[derive(Default)]
struct Host {
    application: Mutex<Option<UnixDatagram>>,
    opened: AtomicUsize,
}
impl Host {
    fn attachment(self: &Arc<Self>) -> Attachment {
        let host = self.clone();
        Attachment::readable(PacketLayer::Ip, move || {
            let (device, application) = UnixDatagram::pair()?;
            device.set_nonblocking(true)?;
            application.set_nonblocking(true)?;
            *host
                .application
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(application);
            host.opened.fetch_add(1, Ordering::SeqCst);
            Ok(Readable::new(Pipe(device)))
        })
    }
    fn with<T>(&self, action: impl FnOnce(&UnixDatagram) -> io::Result<T>) -> io::Result<T> {
        let guard = self
            .application
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        action(
            guard
                .as_ref()
                .ok_or_else(|| io::Error::other("no device"))?,
        )
    }
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.with(|socket| socket.send(packet).map(drop))
    }
    async fn expect(&self, packet: &[u8]) -> Result {
        timeout(Duration::from_secs(5), async {
            let mut buffer = [0; 2048];
            loop {
                match self.with(|socket| socket.recv(&mut buffer)) {
                    Ok(length) => {
                        assert_eq!(&buffer[..length], packet);
                        return;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(2)).await,
                }
            }
        })
        .await?;
        Ok(())
    }
}
fn settings(local: std::net::SocketAddr, peer: std::net::SocketAddr) -> Settings {
    Settings {
        local,
        peer,
        path_mtu: 1500,
        forward_kbit: 10_000,
        reverse_kbit: 10_000,
        channels: 4,
        window: 32,
        repair_permille: 0,
        report: None,
    }
}
fn ask(action: local::Action) -> local::Request {
    local::Request {
        version: local::VERSION,
        action,
    }
}
async fn connected(handle: &Handle, operation: OperationId) -> Result<OperationId> {
    match timeout(Duration::from_secs(5), handle.wait(operation))
        .await?
        .map_err(submit)?
    {
        Completed::Connected { generation } => Ok(generation),
        other => Err(format!("unexpected completion: {other:?}").into()),
    }
}

#[test]
fn swift_plan_requires_a_readable_attachment_and_bounds_listening() -> Result {
    let c = credentials()?;
    let ports = [
        crate::test_ports::reserve(false)?.local_addr()?,
        crate::test_ports::reserve(false)?.local_addr()?,
    ];
    let listen: std::net::SocketAddr = "127.0.0.1:0".parse().map_err(io::Error::other)?;
    let server = |attachment| {
        Prepared::swift_server(
            cfg(Duplex::Full),
            Server {
                listen,
                tls: c.server.clone(),
                members: c.members.clone(),
            },
            settings(ports[0], ports[1]),
            attachment,
        )
    };
    let plain = attachment(Arc::new(Native::default()));
    assert!(server(plain).is_err());
    let host = Arc::new(Host::default());
    let plan = server(host.attachment())?;
    assert_eq!(
        plan.setup_timeout(),
        SWIFT_LISTEN + cfg(Duplex::Full).handshake_timeout
    );
    // Validation opened nothing.
    assert_eq!(host.opened.load(Ordering::SeqCst), 0);
    let mut bad = settings(ports[0], ports[1]);
    bad.channels = 0;
    assert!(
        Prepared::swift_server(
            cfg(Duplex::Full),
            Server {
                listen: "127.0.0.1:0".parse().map_err(io::Error::other)?,
                tls: c.server.clone(),
                members: c.members.clone(),
            },
            bad,
            host.attachment(),
        )
        .is_err()
    );
    Ok(())
}

/// Two services forward both ways, report status through the local API,
/// disconnect, connect again with fresh devices and keys, and forward again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn swift_forwards_reports_disconnects_and_reconnects_through_the_service() -> Result {
    let c = credentials()?;
    let ports = [
        crate::test_ports::reserve(false)?.local_addr()?,
        crate::test_ports::reserve(false)?.local_addr()?,
    ];
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let listen = crate::test_ports::reserve(false)?.local_addr()?;
    let server_plan = Prepared::swift_server(
        cfg(Duplex::Full),
        Server {
            listen,
            tls: c.server.clone(),
            members: c.members.clone(),
        },
        settings(ports[1], ports[0]),
        hosts[1].attachment(),
    )?;
    let client_plan = Prepared::swift_client(
        cfg(Duplex::Full),
        Client {
            remote: listen,
            tls: c.client.clone(),
            server_name: "service-client.test".into(),
            member: c.member.clone(),
        },
        settings(ports[0], ports[1]),
        hosts[0].attachment(),
    )?;
    let (server, server_run) = channel();
    let (client, client_run) = channel();
    let tasks = [tokio::spawn(server_run), tokio::spawn(client_run)];
    let listening = |handle: Handle| async move {
        timeout(Duration::from_secs(5), async {
            let mut changed = handle.subscribe();
            while handle.snapshot().listening.is_none() {
                if changed.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
    };
    // Idle status carries the lifecycle phase and no counters.
    let idle = client
        .lifecycle_request(ask(local::Action::Status {}))
        .await;
    assert!(idle.ok);
    let state = idle.state.ok_or("no idle state")?;
    assert_eq!(state.phase, "disconnected");
    assert_eq!(state.swift, None);
    let refused = client
        .lifecycle_request(ask(local::Action::Reconnect {}))
        .await;
    assert_eq!((refused.ok, refused.code.as_str()), (false, "closed"));

    let first = server
        .connect(server_plan.clone(), server.next_key().map_err(submit)?)
        .map_err(submit)?;
    listening(server.clone()).await?;
    let accepted = client
        .connect(client_plan, client.next_key().map_err(submit)?)
        .map_err(submit)?;
    let generation = connected(&client, accepted.operation).await?;
    let server_generation = connected(&server, first.operation).await?;
    assert_eq!(hosts[0].opened.load(Ordering::SeqCst), 1);
    hosts[0].send(&packet(1))?;
    hosts[1].expect(&packet(1)).await?;
    hosts[1].send(&packet(2))?;
    hosts[0].expect(&packet(2)).await?;

    let frame = *client
        .snapshot()
        .runtime
        .as_ref()
        .and_then(Observation::swift)
        .ok_or("no swift observation")?;
    assert_eq!(frame.effective.channels, 4);
    assert!(frame.receive_buffer > 0);
    let status = client
        .lifecycle_request(ask(local::Action::Status {}))
        .await;
    assert!(status.ok);
    let state = status.state.ok_or("no state")?;
    assert_eq!(state.phase, "forwarding");
    assert_eq!(state.epoch, generation.value());
    assert_eq!(state.swift.ok_or("no swift status")?.channels, 4);
    // The fixed profile has no negotiated changes.
    let apply = client
        .lifecycle_request(ask(local::Action::SwitchCompression {
            compression: local::Compression::Lz4,
        }))
        .await;
    assert_eq!((apply.ok, apply.code.as_str()), (false, "unsupported"));

    // Disconnect releases the device and the control stream; the acceptor
    // observes the closed liveness stream as its own terminal.
    let reply = client
        .lifecycle_request(ask(local::Action::Disconnect {}))
        .await;
    assert!(reply.ok, "{}", reply.code);
    assert_eq!(reply.state.ok_or("no state")?.phase, "disconnected");
    assert_eq!(
        client.wait_stopped(generation).await.map_err(submit)?,
        Terminal::Aborted
    );
    assert!(hosts[0].send(&packet(3)).is_err());
    let terminal = timeout(
        Duration::from_secs(5),
        server.wait_stopped(server_generation),
    )
    .await?
    .map_err(submit)?;
    assert_eq!(
        terminal,
        Terminal::Failed(Failure {
            kind: io::ErrorKind::UnexpectedEof
        })
    );
    let again = client
        .lifecycle_request(ask(local::Action::Disconnect {}))
        .await;
    assert_eq!((again.ok, again.code.as_str()), (false, "state"));

    // The acceptor listens again; the initiator's local reconnect request
    // reuses its retained plan and completes only once actually forwarding.
    let second = server
        .connect(server_plan, server.next_key().map_err(submit)?)
        .map_err(submit)?;
    listening(server.clone()).await?;
    let reply = client
        .lifecycle_request(ask(local::Action::Reconnect {}))
        .await;
    assert!(reply.ok, "{}", reply.code);
    let state = reply.state.ok_or("no state")?;
    assert_eq!(state.phase, "forwarding");
    assert!(state.epoch > generation.value());
    connected(&server, second.operation).await?;
    assert_eq!(hosts[0].opened.load(Ordering::SeqCst), 2);
    assert_eq!(hosts[1].opened.load(Ordering::SeqCst), 2);
    hosts[0].send(&packet(4))?;
    hosts[1].expect(&packet(4)).await?;
    hosts[1].send(&packet(5))?;
    hosts[0].expect(&packet(5)).await?;

    // Operations are observable in order by a frontend that did not submit them.
    let (id, _) = client.wait_next(0).await.map_err(submit)?;
    assert_eq!(id, accepted.operation);
    for task in tasks {
        task.abort();
    }
    Ok(())
}
