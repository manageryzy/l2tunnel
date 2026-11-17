//! Actual service/PacketDevice owners; no fabricated root or native qualification.
use super::*;
#[path = "secure_udp_setup.rs"]
mod setup_diagnostics;
#[path = "secure_udp_transaction.rs"]
mod transaction;
use crate::{cli::secure_udp_frontend::Selection, secure_udp::credentials};
use l2tunnel_handshake as hs;
use l2tunnel_identity as identity;
use l2tunnel_security::Role;
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};
use zeroize::Zeroizing;

struct Pipe {
    socket: UnixDatagram,
    host: Arc<Host>,
}
impl AsRawFd for Pipe {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        self.host.live.fetch_sub(1, Ordering::SeqCst);
    }
}
impl PacketDevice for Pipe {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, bytes: &mut [u8]) -> io::Result<Option<usize>> {
        match self.socket.recv(bytes) {
            Ok(length) => Ok(Some(length)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.socket.send(bytes)? != bytes.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
}
#[derive(Default)]
struct Host {
    application: Mutex<Option<UnixDatagram>>,
    opened: AtomicUsize,
    live: AtomicUsize,
}
impl Host {
    fn attachment(self: &Arc<Self>) -> Attachment {
        let host = self.clone();
        Attachment::readable(PacketLayer::Ip, move || {
            let (socket, application) = UnixDatagram::pair()?;
            socket.set_nonblocking(true)?;
            application.set_nonblocking(true)?;
            *host
                .application
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(application);
            host.opened.fetch_add(1, Ordering::SeqCst);
            host.live.fetch_add(1, Ordering::SeqCst);
            Ok(crate::native::Native::new(Pipe {
                socket,
                host: host.clone(),
            }))
        })
    }
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let application = self
            .application
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let socket = application
            .as_ref()
            .ok_or_else(|| io::Error::other("native not opened"))?;
        if socket.send(packet)? != packet.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    async fn expect(&self, expected: &[u8]) -> Result {
        timeout(Duration::from_secs(3), async {
            let mut bytes = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
            loop {
                let received = self
                    .application
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .ok_or_else(|| io::Error::other("native not opened"))?
                    .recv(&mut bytes);
                match received {
                    Ok(length) => {
                        assert_eq!(&bytes[..length], expected);
                        return Ok::<_, io::Error>(());
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(1)).await
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await??;
        Ok(())
    }
}
fn packet(marker: u8, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
    bytes[20..24].copy_from_slice(&[0x91, marker, 0x92, marker]);
    bytes[24..26].copy_from_slice(&((length - 20) as u16).to_be_bytes());
    bytes[28..length - 2].fill(marker);
    bytes
}
fn current_profile(
    legacy: crate::secure_udp::common_fixture::Resources,
    peers: l2tunnel_runtime::secure_udp::establish::Peers,
) -> Result<crate::secure_udp::common_transaction_profile::Profile> {
    use l2tunnel::record_configuration::{Catalog, Descriptor, Profile};
    let mut a = transaction::streamed(legacy.runtime(Role::Initiator));
    let mut b = transaction::streamed(legacy.runtime(Role::Responder));
    // Match the finite integration pools used by transaction_plans. The Common
    // bank reserves both directions inside the unchanged 64 MiB fixture cap.
    for resource in [&mut a, &mut b] {
        for direction in [&mut resource.send, &mut resource.receive] {
            direction.records.codec.flow_sources = 64;
            direction.records.codec.queue_bytes = 65_536;
        }
    }
    let descriptor = |forward: l2tunnel_swift::policy::Direction,
                      reverse: l2tunnel_swift::policy::Direction|
     -> Result<Descriptor> {
        Ok(Descriptor::new(
            1500,
            Duplex::Full,
            transaction::common_service::common_direction(
                forward.records.channels as u16,
                legacy.connection().max_packet,
                forward.bytes_per_second,
            )?,
            transaction::common_service::common_direction(
                reverse.records.channels as u16,
                legacy.connection().max_packet,
                reverse.bytes_per_second,
            )?,
            Profile::Swift {
                forward: forward.records,
                reverse: reverse.records,
            },
        )?)
    };
    let initial = descriptor(a.send, a.receive)?;
    Ok(crate::secure_udp::common_transaction_profile::Profile::new(
        legacy.connection(),
        legacy.settings(),
        peers,
        a,
        b,
        Catalog::new(initial, &[initial])?,
        l2tunnel_runtime::secure_udp::transport::TransactionSettings {
            protocol: l2tunnel_management::transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: 64 * 1024 * 1024,
        },
    )?)
}
fn plans(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
    timeout: Duration,
    wrong_peer: bool,
) -> Result<([Prepared; 2], [std::net::SocketAddr; 2])> {
    let held = [
        crate::test_ports::reserve(false)?,
        crate::test_ports::reserve(false)?,
    ];
    let addresses = [held[0].local_addr()?, held[1].local_addr()?];
    let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
    let member = identity::IdentityKey::from_pkcs8(&encoded)?;
    let member_public = member.public_key();
    let actual_peer = hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key();
    let client_noise = credentials::NoiseIdentity::new(
        Zeroizing::new([11; 32]),
        if wrong_peer {
            hs::LocalSecret::new(Zeroizing::new([33; 32])).public_key()
        } else {
            actual_peer
        },
        hs::Profile::Ik,
        None,
    )?;
    let server_noise = credentials::NoiseIdentity::new(
        Zeroizing::new([22; 32]),
        hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key(),
        hs::Profile::Ik,
        None,
    )?;
    let build = |side: usize, peers| {
        let selection = Selection {
            appearance,
            role: if side == 0 {
                Role::Initiator
            } else {
                Role::Responder
            },
            local: addresses[side],
            peer: addresses[1 - side],
            policy: l2tunnel_swift::control::Policy {
                path_mtu: 1500,
                forward_kbit: 10_000,
                reverse_kbit: 5_000,
                channels: 4,
                window: 32,
                repair_permille: 0,
            },
            maximum_mtu: 2000,
            profile: hs::Profile::Ik,
            report: Some(Duration::from_millis(10)),
        };
        let mut connection = cfg(Duplex::Full);
        connection.handshake_timeout = timeout;
        current_profile(selection.build(connection, peers, member_public)?, peers)
    };
    let a = build(0, client_noise.peers(Role::Initiator))?;
    let b = build(1, server_noise.peers(Role::Responder))?;
    let client = Prepared::secure_udp_common_client(
        a,
        credentials::Client::new(
            client_noise,
            member,
            credentials::Secret32::new(Zeroizing::new([44; 32]))?,
        )?,
        hosts[0].attachment(),
    )?;
    let server = Prepared::secure_udp_common_server(
        b,
        credentials::Server::new(
            server_noise,
            credentials::Secret32::new(Zeroizing::new([44; 32]))?,
            credentials::Secret32::new(Zeroizing::new([55; 32]))?,
        )?,
        hosts[1].attachment(),
    )?;
    drop(held);
    Ok(([client, server], addresses))
}
async fn connected(handle: &Handle, accepted: Accepted) -> Result<OperationId> {
    match timeout(Duration::from_secs(4), handle.wait(accepted.operation))
        .await?
        .map_err(submit)?
    {
        Completed::Connected { generation } => Ok(generation),
        other => Err(format!("not actually ready: {other:?}").into()),
    }
}
async fn admission_identity(plan: &Prepared) -> Result<usize> {
    match &plan.data.endpoint {
        prepared::Endpoint::SecureServer(server) => {
            let guard = server.admission.lock().await;
            Ok(std::ptr::from_ref(guard.as_ref().ok_or("no retained admission")?) as usize)
        }
        _ => Err("not secure server".into()),
    }
}

#[test]
fn secure_udp_prepared_rejects_wrong_layer_or_unreadable_attachment_before_io() -> Result {
    // These sockets are test witnesses, never service owners. Both configured
    // ports remain occupied so an unintended setup bind cannot pass unnoticed.
    let held = [
        crate::test_ports::reserve(false)?,
        crate::test_ports::reserve(false)?,
    ];
    let path = l2tunnel_udp_control::Path {
        client: held[0].local_addr()?,
        server: held[1].local_addr()?,
    };
    for socket in &held {
        socket.set_nonblocking(true)?;
    }
    let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
    let member_public = identity::IdentityKey::from_pkcs8(&encoded)?.public_key();
    let opened = Arc::new(AtomicUsize::new(0));
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let (profile, peers) =
            crate::secure_udp::common_fixture::fixture(path, appearance, member_public)?;
        let profile = current_profile(profile, peers)?;
        profile.configuration()?;
        for role in [Role::Initiator, Role::Responder] {
            for wrong_layer in [true, false] {
                let calls = opened.clone();
                let attachment = if wrong_layer {
                    Attachment::readable(PacketLayer::Ethernet, move || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err(io::Error::other("invalid attachment opener was called"))
                    })
                } else {
                    Attachment::new(PacketLayer::Ip, move || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err(io::Error::other("unreadable attachment opener was called"))
                    })
                };
                let noise = credentials::NoiseIdentity::new(
                    Zeroizing::new(match role {
                        Role::Initiator => [11; 32],
                        Role::Responder => [22; 32],
                    }),
                    match role {
                        Role::Initiator => peers.responder,
                        Role::Responder => peers.initiator,
                    },
                    hs::Profile::Ik,
                    None,
                )?;
                let admission = credentials::Secret32::new(Zeroizing::new([44; 32]))?;
                let result = match role {
                    Role::Initiator => Prepared::secure_udp_common_client(
                        profile.clone(),
                        credentials::Client::new(
                            noise,
                            identity::IdentityKey::from_pkcs8(&encoded)?,
                            admission,
                        )?,
                        attachment,
                    ),
                    Role::Responder => Prepared::secure_udp_common_server(
                        profile.clone(),
                        credentials::Server::new(
                            noise,
                            admission,
                            credentials::Secret32::new(Zeroizing::new([55; 32]))?,
                        )?,
                        attachment,
                    ),
                };
                let error = match result {
                    Err(error) => error,
                    Ok(_) => {
                        return Err("new secure UDP plan accepted an invalid attachment".into());
                    }
                };
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert_eq!(opened.load(Ordering::SeqCst), 0);
                for socket in &held {
                    let mut packet = [0; 1];
                    assert_eq!(
                        socket
                            .recv_from(&mut packet)
                            .err()
                            .map(|error| error.kind()),
                        Some(io::ErrorKind::WouldBlock),
                        "invalid preparation emitted a UDP packet"
                    );
                    assert_eq!(
                        std::net::UdpSocket::bind(socket.local_addr()?)
                            .err()
                            .map(|error| error.kind()),
                        Some(io::ErrorKind::AddrInUse),
                        "fixture original socket ownership changed"
                    );
                }
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secure_udp_service_forwards_switches_reports_and_reconnects_same_owner() -> Result {
    assert_eq!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    );
    assert_eq!(tokio::runtime::Handle::current().metrics().num_workers(), 2);
    secure_udp_service_lifecycle_fixture().await
}

#[tokio::test]
async fn current_thread_secure_udp_service_preserves_full_lifecycle() -> Result {
    assert_eq!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::CurrentThread
    );
    assert_eq!(tokio::runtime::Handle::current().metrics().num_workers(), 1);
    secure_udp_service_lifecycle_fixture().await
}

async fn secure_udp_service_lifecycle_fixture() -> Result {
    transaction::transaction_service_lifecycle().await
}

struct ApiDirectory(std::path::PathBuf);
impl ApiDirectory {
    fn new() -> io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-secure-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for ApiDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn late_secure_udp_cancellation_releases_opened_device_before_readiness() -> Result {
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let ([mut client_plan, server_plan], addresses) = plans(
        l2tunnel_cover::Appearance::QuicLike,
        &hosts,
        Duration::from_secs(3),
        false,
    )?;
    let cancellation = Arc::new(Mutex::new(None::<(Handle, OperationId)>));
    let action = cancellation.clone();
    let original = hosts[0].attachment();
    Arc::get_mut(&mut client_plan.data)
        .ok_or("test plan unexpectedly shared")?
        .attachment = Attachment::readable(PacketLayer::Ip, move || {
        let device = original.open_readable()?;
        let cancel = action
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (handle, operation) = cancel
            .as_ref()
            .ok_or_else(|| io::Error::other("missing cancellation identity"))?;
        handle.cancel(*operation).map_err(submit)?;
        Ok(device)
    });
    let (client, client_run) = channel();
    let (server, server_run) = channel();
    let a = client
        .connect(client_plan, client.next_key().map_err(submit)?)
        .map_err(submit)?;
    *cancellation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((client.clone(), a.operation));
    server
        .connect(server_plan, server.next_key().map_err(submit)?)
        .map_err(submit)?;
    let client_task = tokio::spawn(client_run);
    let server_task = tokio::spawn(server_run);
    assert_eq!(
        timeout(Duration::from_secs(4), client.wait(a.operation))
            .await?
            .map_err(submit)?,
        Completed::Cancelled
    );
    assert_eq!(hosts[0].opened.load(Ordering::SeqCst), 1);
    assert_eq!(hosts[0].live.load(Ordering::SeqCst), 0);
    assert!(client.snapshot().generation.is_none());
    let rebound = std::net::UdpSocket::bind(addresses[0])?;
    drop(rebound);
    client_task.abort();
    server_task.abort();
    let _ = tokio::join!(client_task, server_task);
    Ok(())
}

#[tokio::test]
async fn secure_udp_cancel_and_wrong_pin_never_open_the_attachment() -> Result {
    let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
    let ([client_plan, server_plan], _) = plans(
        l2tunnel_cover::Appearance::QuicLike,
        &hosts,
        Duration::from_millis(300),
        true,
    )?;
    let (client, client_run) = channel();
    let (server, server_run) = channel();
    let client_task = tokio::spawn(client_run);
    let server_task = tokio::spawn(server_run);
    let a = client
        .connect(client_plan.clone(), client.next_key().map_err(submit)?)
        .map_err(submit)?;
    let b = server
        .connect(server_plan, server.next_key().map_err(submit)?)
        .map_err(submit)?;
    assert!(matches!(
        timeout(Duration::from_secs(2), client.wait(a.operation))
            .await?
            .map_err(submit)?,
        Completed::Failed(_)
    ));
    assert!(matches!(
        timeout(Duration::from_secs(2), server.wait(b.operation))
            .await?
            .map_err(submit)?,
        Completed::Failed(_)
    ));
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 0)
    );
    let a = client
        .connect(client_plan, client.next_key().map_err(submit)?)
        .map_err(submit)?;
    client.cancel(a.operation).map_err(submit)?;
    assert_eq!(
        timeout(Duration::from_secs(2), client.wait(a.operation))
            .await?
            .map_err(submit)?,
        Completed::Cancelled
    );
    assert!(
        hosts
            .iter()
            .all(|host| host.opened.load(Ordering::SeqCst) == 0)
    );
    client_task.abort();
    server_task.abort();
    let _ = tokio::join!(client_task, server_task);
    Ok(())
}
