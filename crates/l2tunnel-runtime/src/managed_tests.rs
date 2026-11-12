//! Real authenticated managed-runtime integration tests.
use super::*;
use l2tunnel_auth::{
    ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
};
use l2tunnel_management::transaction::{Event, Fence, Identity, Peer, Phase, Tick};
use l2tunnel_management::{EndpointId, Ingress, LaneId, MessageKind, SessionId};
use managed::{ControlError, ControlHandle, ManagedConfig, Role, TransactionSettings};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

fn runtime(layer: PacketLayer) -> RuntimeConfig {
    RuntimeConfig {
        layer,
        max_packet: 1600,
        compression: Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    }
}
fn management(runtime: RuntimeConfig, duplex: Duplex, role: Role) -> io::Result<ManagedConfig> {
    Ok(ManagedConfig {
        role,
        initial_mode: managed::mode_config(runtime, duplex)?,
        transaction_settings: TransactionSettings::default(),
    })
}
async fn connections(
    runtime: RuntimeConfig,
    duplex: Duplex,
) -> Result<Vec<(AuthenticatedConnection, AuthenticatedConnection)>, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["managed.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allowlist = MemberAllowlist::new(&[member.public_key()])?;
    let mode = managed::mode_config(runtime, duplex)?;
    let binding = managed::session_config(runtime, &mode)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut result = Vec::new();
    for _ in 0..if duplex == Duplex::Half { 2 } else { 1 } {
        let client_tcp = TcpStream::connect(listener.local_addr()?).await?;
        client_tcp.set_nodelay(true)?;
        let (server_tcp, _) = listener.accept().await?;
        server_tcp.set_nodelay(true)?;
        let (client, server) = tokio::try_join!(
            client_connect(
                client_tcp,
                &client_tls,
                "managed.test",
                &member,
                binding,
                Duration::from_secs(5)
            ),
            server_accept(
                server_tcp,
                &server_tls,
                &allowlist,
                binding,
                Duration::from_secs(5)
            ),
        )?;
        result.push((client, server));
    }
    Ok(result)
}
async fn links(runtime: RuntimeConfig, duplex: Duplex) -> Result<(Link, Link), TestError> {
    let mut connected = connections(runtime, duplex).await?.into_iter();
    let (first_client, first_server) = connected
        .next()
        .ok_or_else(|| invalid("missing test lane"))?;
    if duplex == Duplex::Half {
        let (second_client, second_server) = connected
            .next()
            .ok_or_else(|| invalid("missing second test lane"))?;
        Ok(tokio::try_join!(
            client_pair(first_client, second_client),
            server_pair(first_server, second_server)
        )?)
    } else {
        Ok((Link::full(first_client), Link::full(first_server)))
    }
}
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
    blocked: bool,
    receives: usize,
}
#[derive(Clone)]
struct Device {
    layer: PacketLayer,
    state: Arc<Mutex<Native>>,
}
impl Device {
    fn new(layer: PacketLayer) -> Self {
        Self {
            layer,
            state: Arc::new(Mutex::new(Native::default())),
        }
    }
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| invalid("poisoned test device"))?;
        Ok(f(&mut guard))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        self.change(|state| {
            state.receives += 1;
            state.outgoing.pop_front().map(|packet| {
                buffer[..packet.len()].copy_from_slice(&packet);
                packet.len()
            })
        })
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.change(|state| {
            if state.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            state.delivered.push(packet.to_vec());
            Ok(())
        })?
    }
}
fn packet(layer: PacketLayer, number: u8) -> Vec<u8> {
    let mut packet = vec![number; 400];
    if layer == PacketLayer::Ip {
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&400_u16.to_be_bytes());
    } else {
        packet[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
        packet[14..18].copy_from_slice(b"L2MC");
    }
    packet
}
async fn status_until(
    handle: &ControlHandle,
    predicate: impl Fn(&managed::Status) -> bool,
) -> Result<managed::Status, TestError> {
    let mut updates = handle.subscribe();
    Ok(tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(status) = updates
                .borrow_and_update()
                .as_ref()
                .filter(|status| predicate(status))
                .cloned()
            {
                return Ok::<_, io::Error>(status);
            }
            updates.changed().await.map_err(io::Error::other)?;
        }
    })
    .await??)
}
async fn delivered_until(device: &Device, count: usize) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(4), async {
        while device.change(|state| state.delivered.len())? < count {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(io::Error::other)?
}

#[tokio::test]
async fn actual_tls_full_and_half_tap_and_tun_switch_under_device_backpressure() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            let config = runtime(layer);
            let (client_link, server_link) = links(config, duplex).await?;
            let client_device = Device::new(layer);
            let server_device = Device::new(layer);
            let client_packets: Vec<_> = (1..=6).map(|value| packet(layer, value)).collect();
            let server_packets: Vec<_> = (11..=16).map(|value| packet(layer, value)).collect();
            client_device.change(|state| state.outgoing.extend(client_packets.clone()))?;
            server_device.change(|state| {
                state.outgoing.extend(server_packets.clone());
                state.blocked = true;
            })?;
            let (client_control, client_receiver) = managed::channel();
            let (server_control, server_receiver) = managed::channel();
            let client_task = tokio::spawn(managed::run_managed(
                client_device.clone(),
                client_link,
                config,
                management(config, duplex, Role::Client)?,
                client_receiver,
            ));
            let server_task = tokio::spawn(managed::run_managed(
                server_device.clone(),
                server_link,
                config,
                management(config, duplex, Role::Server)?,
                server_receiver,
            ));
            let before =
                status_until(&client_control, |s| s.admitted == 2 && s.flushed == 2).await?;
            assert_eq!(before.peer_delivered, 0);
            let request_handle = client_control.clone();
            let switch = tokio::spawn(async move {
                request_handle
                    .switch_compression(Compression::Lz4IfSmaller)
                    .await
            });
            let blocked = status_until(&client_control, |s| {
                s.phase == Phase::Draining || s.phase == Phase::AwaitBarrier
            })
            .await?;
            assert_eq!(blocked.epoch, Epoch(1));
            assert_eq!(blocked.admitted, 2);
            assert!(!switch.is_finished());
            assert_eq!(
                client_control.switch_compression(Compression::None).await,
                Err(ControlError::Busy)
            );
            assert_eq!(
                server_control
                    .switch_compression(Compression::Lz4IfSmaller)
                    .await,
                Err(ControlError::NotCoordinator)
            );
            server_device.change(|state| state.blocked = false)?;
            let changed = tokio::time::timeout(Duration::from_secs(4), switch).await???;
            assert_eq!(changed.epoch, Epoch(2));
            assert_eq!(changed.compression, Compression::Lz4IfSmaller);
            delivered_until(&client_device, server_packets.len()).await?;
            delivered_until(&server_device, client_packets.len()).await?;
            assert_eq!(
                client_device.change(|state| state.delivered.clone())?,
                server_packets
            );
            assert_eq!(
                server_device.change(|state| state.delivered.clone())?,
                client_packets
            );
            // User experimental EtherType and L2MC bytes above were delivered as opaque data.
            assert_eq!(
                client_control
                    .status()
                    .ok_or_else(|| invalid("missing status"))?
                    .epoch,
                Epoch(2)
            );
            let reverted = client_control.switch_compression(Compression::None).await?;
            assert_eq!(reverted.epoch, Epoch(3));
            client_device.change(|state| state.outgoing.push_back(packet(layer, 99)))?;
            delivered_until(&server_device, client_packets.len() + 1).await?;
            assert_eq!(
                server_device.change(|state| state.delivered.last().cloned())?,
                Some(packet(layer, 99))
            );
            let a = status_until(&client_control, |s| s.peer_delivered == 7).await?;
            let b = status_until(&server_control, |s| {
                s.epoch == Epoch(3) && s.phase == Phase::Idle
            })
            .await?;
            assert_eq!(a.epoch, b.epoch);
            assert_eq!(a.compression, b.compression);
            assert_eq!(a.admitted, 7);
            client_task.abort();
            server_task.abort();
            assert!(client_task.await.is_err());
            assert!(server_task.await.is_err());
            assert!(
                !client_control
                    .status()
                    .ok_or_else(|| invalid("missing status"))?
                    .running
            );
            assert!(
                !server_control
                    .status()
                    .ok_or_else(|| invalid("missing status"))?
                    .running
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn negotiated_digest_role_duplex_and_unsupported_modes_fail_before_device_reads() -> TestResult
{
    let config = runtime(PacketLayer::Ethernet);
    for changed in 0..4 {
        let (client, _server) = links(config, Duplex::Full).await?;
        let device = Device::new(config.layer);
        let (_, receiver) = managed::channel();
        let mut management = management(config, Duplex::Full, Role::Client)?;
        let mut altered = config;
        match changed {
            0 => altered.max_packet -= 1,
            1 => management.role = Role::Server,
            2 => management.initial_mode.duplex = Duplex::Half,
            _ => management.initial_mode.channels = 2,
        }
        assert!(
            managed::run_managed(device.clone(), client, altered, management, receiver)
                .await
                .is_err()
        );
        assert_eq!(device.change(|state| state.receives)?, 0);
    }
    let mode = managed::mode_config(config, Duplex::Full)?;
    let mut unsupported = mode.clone();
    unsupported.compression = l2tunnel_core::PayloadCompression::Zstd;
    assert!(managed::session_config(config, &unsupported).is_err());
    assert_ne!(
        managed::session_config(config, &mode)?.digest,
        managed::session_config(
            RuntimeConfig {
                max_packet: config.max_packet - 1,
                ..config
            },
            &mode
        )?
        .digest
    );
    Ok(())
}

async fn send_outer(
    stream: &mut AuthenticatedConnection,
    session: [u8; 16],
    number: &mut u64,
    kind: Kind,
    epoch: Epoch,
    payload: &[u8],
) -> io::Result<()> {
    let bytes = wire::encode(
        Header {
            kind,
            epoch,
            packet_number: *number,
            session,
            lane: 0,
        },
        payload,
    )
    .map_err(wire_error)?;
    *number += 1;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}
async fn drop_commit_acks(
    mut server: AuthenticatedConnection,
    config: RuntimeConfig,
    committed: tokio::sync::oneshot::Sender<()>,
) -> io::Result<()> {
    let session = SessionId(server.info().session_id);
    let initial = managed::mode_config(config, Duplex::Full)?;
    let mut next = initial.clone();
    next.compression = l2tunnel_core::PayloadCompression::Lz4;
    let mut peer = Peer::new(
        Identity {
            session,
            role: Role::Server,
            local: EndpointId(2),
            remote: EndpointId(1),
            lane: LaneId(0),
        },
        Epoch(1),
        initial.clone(),
        &[initial, next],
        TransactionSettings::default(),
        Tick(0),
    )
    .map_err(io::Error::other)?;
    let start = tokio::time::Instant::now();
    let mut number = 0;
    let mut committed = Some(committed);
    loop {
        let length = server.read_u32().await? as usize;
        if length > 4096 + wire::HEADER_LEN {
            return Err(invalid("test management bound"));
        }
        let mut bytes = vec![0; length];
        server.read_exact(&mut bytes).await?;
        let (header, payload) = wire::decode(&bytes, 4096).map_err(wire_error)?;
        if header.kind != Kind::Control {
            return Err(invalid("unexpected test data"));
        }
        let now = Tick(start.elapsed().as_millis() as u64);
        let mut effects = peer
            .receive(
                Ingress::AuthenticatedManagement {
                    session,
                    lane: LaneId(0),
                    sender: Role::Client,
                },
                payload,
                now,
            )
            .map_err(io::Error::other)?;
        loop {
            if let Some(out) = effects.outbound {
                let parsed = l2tunnel_management::Frame::decode(
                    &out,
                    l2tunnel_management::Limits::default(),
                )
                .map_err(io::Error::other)?;
                if parsed.header.kind != MessageKind::CommitAck {
                    send_outer(
                        &mut server,
                        session.0,
                        &mut number,
                        Kind::Control,
                        Epoch(0),
                        &out,
                    )
                    .await?;
                }
            }
            match effects.event {
                Some(Event::Stage { .. }) => {
                    effects = peer
                        .staged(Fence::new(&[0]).map_err(io::Error::other)?, now)
                        .map_err(io::Error::other)?
                }
                Some(Event::Drain {
                    local,
                    peer: remote,
                }) => {
                    effects = peer
                        .confirm_drained(&local, &remote, now)
                        .map_err(io::Error::other)?
                }
                Some(Event::Committed(_)) => {
                    assert_eq!(peer.active_epoch(), Epoch(2));
                    if let Some(sender) = committed.take() {
                        let _ = sender.send(());
                    }
                    break;
                }
                _ => break,
            }
        }
    }
}

#[tokio::test]
async fn actual_tls_lost_commit_ack_exposes_uncertainty_and_never_reports_local_success()
-> TestResult {
    let config = runtime(PacketLayer::Ethernet);
    let (client, server) = connections(config, Duplex::Full)
        .await?
        .pop()
        .ok_or_else(|| invalid("missing connection"))?;
    let (handle, receiver) = managed::channel();
    let mut settings = management(config, Duplex::Full, Role::Client)?;
    settings.transaction_settings = TransactionSettings {
        retry_ms: 20,
        phase_timeout_ms: 200,
        reconcile_timeout_ms: 600,
    };
    let task = tokio::spawn(managed::run_managed(
        Device::new(config.layer),
        Link::full(client),
        config,
        settings,
        receiver,
    ));
    let (committed, committed_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(drop_commit_acks(server, config, committed));
    let change_handle = handle.clone();
    let change = tokio::spawn(async move {
        change_handle
            .switch_compression(Compression::Lz4IfSmaller)
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), committed_rx).await??;
    let uncertain = status_until(&handle, |status| status.phase == Phase::Uncertain).await?;
    assert_eq!(uncertain.epoch, Epoch(1));
    assert_eq!(uncertain.compression, Compression::None);
    assert!(!change.is_finished());
    assert!(
        tokio::time::timeout(Duration::from_secs(3), task)
            .await??
            .is_err()
    );
    assert_eq!(change.await?, Err(ControlError::Closed));
    assert!(
        !handle
            .status()
            .ok_or_else(|| invalid("missing status"))?
            .running
    );
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn actual_tls_malformed_credit_and_old_epochs_fail_closed_and_eof_completes() -> TestResult {
    for case in 0..10 {
        let config = runtime(PacketLayer::Ethernet);
        let (client, mut server) = connections(config, Duplex::Full)
            .await?
            .pop()
            .ok_or_else(|| invalid("missing connection"))?;
        let session = server.info().session_id;
        let device = Device::new(config.layer);
        if case == 3 {
            device.change(|state| state.blocked = true)?;
        }
        let (handle, receiver) = managed::channel();
        let task = tokio::spawn(managed::run_managed(
            device.clone(),
            Link::full(client),
            config,
            management(config, Duplex::Full, Role::Client)?,
            receiver,
        ));
        status_until(&handle, |s| s.running).await?;
        match case {
            0 => {
                send_outer(
                    &mut server,
                    session,
                    &mut 0,
                    Kind::Feedback,
                    Epoch(0),
                    &1_u64.to_be_bytes(),
                )
                .await?
            }
            1 => {
                let payload = config.codec()?.encode_vec(&packet(config.layer, 1))?;
                send_outer(&mut server, session, &mut 0, Kind::Data, Epoch(2), &payload).await?;
            }
            2 => {
                server.shutdown().await?;
            }
            3 => {
                let payload = config.codec()?.encode_vec(&packet(config.layer, 1))?;
                let mut number = 0;
                for _ in 0..3 {
                    send_outer(
                        &mut server,
                        session,
                        &mut number,
                        Kind::Data,
                        Epoch(1),
                        &payload,
                    )
                    .await?;
                }
            }
            4 => {
                let payload = RuntimeConfig {
                    compression: Compression::Lz4IfSmaller,
                    ..config
                }
                .codec()?
                .encode_vec(&packet(config.layer, 1))?;
                assert_eq!(payload[4], 1);
                send_outer(&mut server, session, &mut 0, Kind::Data, Epoch(1), &payload).await?;
            }
            5 => {
                server.write_all(&[0, 0]).await?;
                server.shutdown().await?;
            }
            6 => {
                server.write_u32(u32::MAX).await?;
                server.flush().await?;
            }
            7 => {
                send_outer(
                    &mut server,
                    [0; 16],
                    &mut 0,
                    Kind::Feedback,
                    Epoch(0),
                    &0_u64.to_be_bytes(),
                )
                .await?
            }
            8 => {
                send_outer(
                    &mut server,
                    session,
                    &mut 1,
                    Kind::Feedback,
                    Epoch(0),
                    &0_u64.to_be_bytes(),
                )
                .await?
            }
            _ => {
                send_outer(
                    &mut server,
                    session,
                    &mut 0,
                    Kind::Control,
                    Epoch(0),
                    b"L2MC",
                )
                .await?
            }
        }
        let result = tokio::time::timeout(Duration::from_secs(3), task).await??;
        assert_eq!(result.is_ok(), case == 2);
        assert_eq!(device.change(|state| state.delivered.len())?, 0);
        assert!(
            !handle
                .status()
                .ok_or_else(|| invalid("missing status"))?
                .running
        );
    }
    Ok(())
}

#[tokio::test]
async fn bounded_local_queue_reports_pressure_and_closes_all_waiters() -> TestResult {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let (handle, receiver) = managed::channel();
    let mut waiting: Vec<_> = (0..8)
        .map(|_| Box::pin(handle.switch_compression(Compression::Lz4IfSmaller)))
        .collect();
    for request in &mut waiting {
        poll_fn(|cx| {
            assert!(request.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert_eq!(
        handle.switch_compression(Compression::None).await,
        Err(ControlError::Busy)
    );
    drop(receiver);
    for request in waiting {
        assert_eq!(request.await, Err(ControlError::Closed));
    }
    Ok(())
}

#[tokio::test]
async fn fragmented_authenticated_record_survives_ticks_and_eof_drains_native_delivery()
-> TestResult {
    let config = runtime(PacketLayer::Ethernet);
    let (client, mut server) = connections(config, Duplex::Full)
        .await?
        .pop()
        .ok_or_else(|| invalid("missing connection"))?;
    let session = server.info().session_id;
    let device = Device::new(config.layer);
    device.change(|state| state.blocked = true)?;
    let (handle, receiver) = managed::channel();
    let task = tokio::spawn(managed::run_managed(
        device.clone(),
        Link::full(client),
        config,
        management(config, Duplex::Full, Role::Client)?,
        receiver,
    ));
    let packet = packet(config.layer, 42);
    let payload = config.codec()?.encode_vec(&packet)?;
    let bytes = wire::encode(
        Header {
            kind: Kind::Data,
            epoch: Epoch(1),
            packet_number: 0,
            session,
            lane: 0,
        },
        &payload,
    )
    .map_err(wire_error)?;
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&bytes);
    for chunk in frame.chunks(17) {
        server.write_all(chunk).await?;
        server.flush().await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    server.shutdown().await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!task.is_finished());
    assert_eq!(device.change(|state| state.delivered.len())?, 0);
    device.change(|state| state.blocked = false)?;
    // TLS close_notify closes only this sender's write side. The runtime must
    // flush final cumulative delivery feedback before dropping its other half.
    tokio::time::timeout(Duration::from_secs(3), async {
        let length = server.read_u32().await? as usize;
        if length != wire::HEADER_LEN + 8 {
            return Err(invalid("missing final bounded delivery feedback"));
        }
        let mut bytes = vec![0; length];
        server.read_exact(&mut bytes).await?;
        let (header, payload) = wire::decode(&bytes, 8).map_err(wire_error)?;
        assert_eq!(header.kind, Kind::Feedback);
        assert_eq!(header.session, session);
        assert_eq!(header.epoch, Epoch(0));
        assert_eq!(payload, &1_u64.to_be_bytes());
        Ok::<(), io::Error>(())
    })
    .await??;
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    assert_eq!(
        device.change(|state| state.delivered.clone())?,
        vec![packet]
    );
    let final_status = handle.status().ok_or_else(|| invalid("missing status"))?;
    assert!(!final_status.running);
    assert_eq!(final_status.delivered, 1);
    Ok(())
}
