//! Finite native/device and same-original-UDP transport fixtures, without privileges.

use super::*;
use l2tunnel_handshake as hs;
use l2tunnel_identity as identity;
use l2tunnel_udp_control as gate;
use std::{
    net::{SocketAddr, UdpSocket as StdUdp},
    os::unix::net::UnixDatagram,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc as sync_mpsc,
    },
    thread,
};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Entropy(u8);
impl hs::Entropy for Entropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> std::result::Result<(), hs::EntropyError> {
        output.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}
fn key() -> Result<identity::IdentityKey> {
    // Public RFC8032 vector only, never deployed provisioning material.
    let text = "3051020101300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60812100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let bytes = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>>>()?;
    Ok(identity::IdentityKey::from_pkcs8(&bytes)?)
}
fn appearance(kind: cover::Appearance, client: bool) -> Result<cover::Config> {
    let (local, peer) = if client { (1, 2) } else { (2, 1) };
    Ok(cover::Config::new(
        kind,
        cover::ConnectionIds {
            local: cover::ConnectionId([local; 8]),
            peer: cover::ConnectionId([peer; 8]),
        },
        cover::MediaConfig {
            local_ssrc: cover::Ssrc(u32::from(local)),
            peer_ssrc: cover::Ssrc(u32::from(peer)),
            payload_type: 96,
        },
        cover::Limits {
            max_packet_bytes: 1500,
            max_protected_bytes: 1400,
        },
    )?)
}
fn config(kind: cover::Appearance) -> Config {
    let codec = swift::Config {
        datagram_bytes: 512,
        window: 8,
        repair_numerator: 1,
        repair_denominator: 4,
        flow_sources: 64,
        queue_bytes: 65536,
        max_packet: 513,
        flush_micros: 0,
        feedback_micros: 1000,
        tail_micros: 10000,
        min_rto_micros: 10000,
        max_rto_micros: 100000,
    };
    let direction = policy::Direction {
        records: records::Config {
            codec,
            channels: 2,
            layer: records::Layer::Ethernet,
            max_native: 512,
        },
        bytes_per_second: 1_000_000,
    };
    let overhead = 28
        + record::ROUTE_BYTES
        + security::Protection::ChaCha20Poly1305.overhead_bytes()
        + if kind == cover::Appearance::QuicLike {
            13
        } else {
            14
        };
    Config {
        path_mtu: 1500,
        send: direction,
        receive: direction,
        policy: policy::Settings {
            transaction_micros: 1_000_000,
            max_outbound: 8,
        },
        security: security::Limits {
            max_body_bytes: 1300,
            packets_per_key: 8,
            max_body_bytes_per_key: 100000,
        },
        control: delivery::Settings {
            recovery: recovery::ArqConfig {
                max_source_bytes: 192,
                send_bytes: 6144,
                receive_bytes: 6144,
                send_records: 32,
                receive_records: 32,
                initial_rto: Duration::from_millis(10),
                maximum_rto: Duration::from_millis(100),
                ack_delay: Duration::from_millis(1),
                max_retries: 16,
            },
            interval: Duration::from_millis(1),
            packets_per_interval: 16,
            bytes_per_interval: 65536,
            wire_overhead: overhead,
        },
        control_epoch: security::Epoch(1),
        data_epoch: security::Epoch(1),
        wire: WireBudget { burst_bytes: 4096 },
        work: WorkBudget {
            receive_interval: Duration::from_millis(1),
            receive_packets: 64,
            send_batch: 16,
            native_read_batch: 16,
            native_write_batch: 16,
        },
        native: NativeBudget {
            pending_packets: 16,
            pending_bytes: 8192,
            stall_timeout: Duration::from_secs(1),
        },
        lifetime: Lifetime {
            lease: Duration::from_secs(5),
            ping_interval: Duration::from_millis(20),
            pong_timeout: Duration::from_millis(500),
        },
        report_interval: Some(Duration::from_millis(5)),
    }
}
fn policy_value() -> swift::control::Policy {
    swift::control::Policy {
        path_mtu: 1500,
        forward_kbit: 8000,
        reverse_kbit: 8000,
        channels: 3,
        window: 12,
        repair_permille: 100,
    }
}
fn resolve(config: Config) -> Resolver {
    Box::new(move |requested| {
        if *requested != policy_value() {
            return None;
        }
        let mut send = config.send;
        send.records.channels = 3;
        send.records.codec.window = 12;
        send.records.codec.repair_numerator = 1;
        send.records.codec.repair_denominator = 10;
        Some(policy::Resolved {
            send,
            receive: send,
            digest: policy::Digest([91; 32]),
        })
    })
}
struct Device {
    socket: UnixDatagram,
    blocked: bool,
    wouldblock: Option<Arc<AtomicUsize>>,
}
impl AsRawFd for Device {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ethernet
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        match self.socket.recv(output) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.blocked {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let length = match self.socket.send(packet) {
            Ok(length) => length,
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock
                    && let Some(counter) = &self.wouldblock
                {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                return Err(error);
            }
        };
        if length == packet.len() {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::WriteZero))
        }
    }
}
fn context(established: &establish::Established) -> member::Settings {
    member::Settings {
        context: identity::Context {
            session: established.binding.session,
            transcript: established.binding.transcript,
            configuration: established.authenticated.configuration,
            carrier: established.authenticated.carrier,
            outer: established.authenticated.outer,
            initiator_noise: identity::NoisePublicKey(established.peers.initiator.0),
            responder_noise: identity::NoisePublicKey(established.peers.responder.0),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: 32,
        receive_interval: Duration::from_millis(1),
        receive_packets_per_interval: 64,
    }
}
async fn authenticated(
    socket: StdUdp,
    path: gate::Path,
    kind: cover::Appearance,
    client: bool,
) -> Result<member::Parts> {
    let local = hs::LocalSecret::new(Zeroizing::new(if client { [11; 32] } else { [22; 32] }));
    let initiator = hs::LocalSecret::new(Zeroizing::new([11; 32])).public_key();
    let responder = hs::LocalSecret::new(Zeroizing::new([22; 32])).public_key();
    let peers = establish::Peers {
        initiator,
        responder,
    };
    let mut gate = gate::Config::new(path, [30; 32], 1)?;
    gate.outer_overhead = 28
        + 1
        + if kind == cover::Appearance::QuicLike {
            30
        } else {
            14
        };
    gate.arq.max_source_bytes = 100;
    gate.arq.send_bytes = 3200;
    gate.arq.receive_bytes = 3200;
    gate.arq.initial_rto = Duration::from_millis(10);
    gate.arq.maximum_rto = Duration::from_millis(100);
    gate.arq.ack_delay = Duration::from_millis(1);
    gate.arq.max_retries = 32;
    gate.cookie_ttl = Duration::from_secs(2);
    gate.handshake_timeout = Duration::from_secs(2);
    gate.initial_rto = Duration::from_millis(10);
    gate.maximum_rto = Duration::from_millis(100);
    gate.gate_attempts = 32;
    let setup = establish::Config {
        gate,
        cover: appearance(kind, client)?,
        profile: hs::Profile::Ik,
        binding: establish::Binding {
            configuration: [3; 32],
            carrier: [4; 32],
            outer: [5; 32],
            member: [6; 32],
        },
        receive_packets_per_interval: 64,
    };
    let member_key = key()?;
    let allowlist = identity::Allowlist::new(&[member_key.public_key()])?;
    let identity = establish::Identity {
        local,
        peer: if client { responder } else { initiator },
        psk: None,
    };
    let now = Instant::now();
    let deadline = now + Duration::from_secs(2);
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    let mut entropy = Entropy(if client { 40 } else { 60 });
    let established = if client {
        establish::connect(
            socket,
            setup,
            identity,
            gate::Secret::new([7; 32]),
            deadline,
            &mut entropy,
        )
        .await?
    } else {
        let mut admission = establish::ServerAdmission::new(
            setup,
            peers,
            gate::Secret::new([7; 32]),
            gate::Secret::new([8; 32]),
            now,
        )?;
        establish::accept(socket, identity, &mut admission, deadline, &mut entropy).await?
    };
    let settings = context(&established);
    Ok(if client {
        member::connect(established, &member_key, settings).await?
    } else {
        member::accept(established, allowlist, settings).await?
    }
    .into_parts())
}
type Thread = thread::JoinHandle<std::result::Result<Stopped, String>>;
struct Pair {
    client: UnixDatagram,
    server: UnixDatagram,
    handle: ControlHandle,
    participant: ControlHandle,
    cancel: Option<oneshot::Sender<()>>,
    other_cancel: Option<oneshot::Sender<()>>,
    threads: Vec<Thread>,
    snapshots: Arc<Mutex<Vec<Snapshot>>>,
    addresses: (SocketAddr, SocketAddr),
    wouldblock: Arc<AtomicUsize>,
    send_buffer: Option<usize>,
}
impl Pair {
    fn start(
        kind: cover::Appearance,
        client_config: Config,
        server_config: Config,
    ) -> Result<Self> {
        Self::start_with_blocked_server(kind, client_config, server_config, false)
    }
    fn start_with_blocked_server(
        kind: cover::Appearance,
        client_config: Config,
        server_config: Config,
        blocked: bool,
    ) -> Result<Self> {
        Self::start_options(kind, client_config, server_config, blocked, false)
    }
    fn start_options(
        kind: cover::Appearance,
        client_config: Config,
        server_config: Config,
        blocked: bool,
        small_buffer: bool,
    ) -> Result<Self> {
        let a = StdUdp::bind("127.0.0.1:0")?;
        let b = StdUdp::bind("127.0.0.1:0")?;
        let path = gate::Path {
            client: a.local_addr()?,
            server: b.local_addr()?,
        };
        a.connect(path.server)?;
        b.connect(path.client)?;
        a.set_nonblocking(true)?;
        b.set_nonblocking(true)?;
        let (client_device, client) = UnixDatagram::pair()?;
        let (server_device, server) = UnixDatagram::pair()?;
        let send_buffer = if small_buffer {
            let socket = socket2::SockRef::from(&server_device);
            socket.set_send_buffer_size(1024)?;
            Some(socket.send_buffer_size()?)
        } else {
            None
        };
        for device in [&client_device, &server_device] {
            device.set_nonblocking(true)?;
        }
        for device in [&client, &server] {
            device.set_read_timeout(Some(Duration::from_secs(2)))?;
            device.set_write_timeout(Some(Duration::from_secs(2)))?;
        }
        let (handle, requests) = channel();
        let (participant, other_requests) = channel();
        let (cancel, cancelled) = oneshot::channel();
        let (other_cancel, other_cancelled) = oneshot::channel();
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let wouldblock = Arc::new(AtomicUsize::new(0));
        let (ready, readiness) = sync_mpsc::channel();
        let mut threads = Vec::new();
        for (socket, device, client_side, config, requests, shutdown) in [
            (a, client_device, true, client_config, requests, cancelled),
            (
                b,
                server_device,
                false,
                server_config,
                other_requests,
                other_cancelled,
            ),
        ] {
            let snapshots = snapshots.clone();
            let wouldblock = wouldblock.clone();
            let ready = ready.clone();
            threads.push(thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| error.to_string())?;
                runtime.block_on(async move {
                    let parts = authenticated(socket, path, kind, client_side)
                        .await
                        .map_err(|error| error.to_string())?;
                    let mut first = true;
                    run(
                        Device {
                            socket: device,
                            blocked: blocked && !client_side,
                            wouldblock: Some(wouldblock),
                        },
                        parts,
                        security::ConfigDigest([3; 32]),
                        config,
                        Some(requests),
                        resolve(config),
                        async {
                            let _ = shutdown.await;
                        },
                        move |snapshot| {
                            if snapshot.running && first {
                                first = false;
                                let _ = ready.send(());
                            }
                            if let Ok(mut snapshots) = snapshots.lock() {
                                snapshots.push(snapshot.clone());
                            }
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())
                })
            }));
        }
        drop(ready);
        let pair = Self {
            client,
            server,
            handle,
            participant,
            cancel: Some(cancel),
            other_cancel: Some(other_cancel),
            threads,
            snapshots,
            addresses: (path.client, path.server),
            wouldblock,
            send_buffer,
        };
        readiness.recv_timeout(Duration::from_secs(3))?;
        readiness.recv_timeout(Duration::from_secs(3))?;
        Ok(pair)
    }
    fn stop(mut self) -> Result<Vec<Stopped>> {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(cancel) = self.other_cancel.take() {
            let _ = cancel.send(());
        }
        let mut stopped = Vec::new();
        for thread in self.threads.drain(..) {
            stopped.push(
                thread
                    .join()
                    .map_err(|_| "runtime fixture thread panicked")?
                    .map_err(io::Error::other)?,
            );
        }
        Ok(stopped)
    }
}
impl Drop for Pair {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(cancel) = self.other_cancel.take() {
            let _ = cancel.send(());
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
fn ethernet(number: u8) -> Vec<u8> {
    let mut packet = vec![0; 256];
    packet[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    packet[6..12].copy_from_slice(&[7, 8, 9, 10, 11, 12]);
    packet[12..14].copy_from_slice(&[0x88, 0xb5]);
    packet[14..].fill(number);
    packet
}

#[test]
fn native_bidirectional_policy_liveness_and_ratchets_use_both_original_socket_pairs() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let config = config(kind);
        let pair = Pair::start(kind, config, config)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        assert_eq!(
            runtime.block_on(pair.participant.switch(policy_value())),
            Err(SwitchError::NotCoordinator)
        );
        for number in 0..24 {
            let packet = ethernet(number);
            pair.client.send(&packet)?;
            let mut input = [0; 1024];
            let length = pair.server.recv(&mut input)?;
            assert_eq!(&input[..length], packet);
            pair.server.send(&packet)?;
            let length = pair.client.recv(&mut input)?;
            assert_eq!(&input[..length], packet);
        }
        assert_eq!(
            runtime
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(2), pair.handle.switch(policy_value()))
                        .await
                })?
                .map_err(|error| io::Error::other(format!("policy switch: {error:?}")))?,
            1
        );
        for number in 24..32 {
            let packet = ethernet(number);
            pair.client.send(&packet)?;
            let mut input = [0; 1024];
            let length = pair.server.recv(&mut input)?;
            assert_eq!(&input[..length], packet);
        }
        thread::sleep(Duration::from_millis(40));
        let addresses = pair.addresses;
        let stopped = pair.stop()?;
        assert!(
            stopped
                .iter()
                .all(|done| done.reason == StopReason::Cancelled && !done.snapshot.running)
        );
        for done in &stopped {
            assert_eq!(done.snapshot.committed.epoch, policy::Epoch(1));
            assert_eq!(done.snapshot.send.records.channels, 3);
            assert_eq!(done.snapshot.receive.records.channels, 3);
            assert!(
                done.snapshot
                    .counters
                    .user_generation
                    .is_some_and(|generation| generation.0 > 0)
            );
            assert!(done.snapshot.counters.control_number.is_some());
            assert!(done.snapshot.liveness.last_pong_micros.is_some());
            assert_eq!(
                done.snapshot.counters.wire_bytes,
                done.snapshot.counters.socket_accepted_ip_bytes
            );
            assert_eq!(done.snapshot.info.authenticated.configuration, [3; 32]);
            if done.snapshot.info.role == security::Role::Initiator {
                assert_eq!(
                    (done.snapshot.info.local_addr, done.snapshot.info.peer_addr),
                    addresses
                );
            } else {
                assert_eq!(
                    (done.snapshot.info.peer_addr, done.snapshot.info.local_addr),
                    addresses
                );
            }
        }
    }
    Ok(())
}

#[test]
fn real_native_socket_backpressure_keeps_exact_fifo_and_bounded_pending_storage() -> Result {
    let kind = cover::Appearance::MediaLike;
    let config = config(kind);
    let pair = Pair::start_options(kind, config, config, false, true)?;
    assert!(pair.send_buffer.is_some_and(|bytes| bytes <= 65536));
    // Deliberately leave the receiver's finite AF_UNIX queue unread. The driver
    // must retain complete outputs until actual writable readiness returns.
    for number in 0..64 {
        pair.client.send(&ethernet(number))?;
    }
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while pair.wouldblock.load(Ordering::Relaxed) == 0 {
        if std::time::Instant::now() >= deadline {
            return Err("real native send never reached WouldBlock".into());
        }
        thread::sleep(Duration::from_millis(1));
    }
    // The OS error is an explicit precondition, not inferred from sampled queue
    // occupancy. Wait for the bounded observer to publish retained ownership too.
    while !pair
        .snapshots
        .lock()
        .map_err(|_| "snapshot lock poisoned")?
        .iter()
        .any(|snapshot| snapshot.counters.native_pending_packets > 0)
    {
        if std::time::Instant::now() >= deadline {
            return Err("real WouldBlock did not retain a native packet".into());
        }
        thread::sleep(Duration::from_millis(1));
    }
    {
        let snapshots = pair
            .snapshots
            .lock()
            .map_err(|_| "snapshot lock poisoned")?;
        assert!(
            snapshots
                .iter()
                .any(|snapshot| snapshot.counters.native_pending_packets > 0)
        );
        assert!(
            snapshots
                .iter()
                .all(|snapshot| snapshot.counters.native_pending_packets
                    <= config.native.pending_packets
                    && snapshot.counters.native_pending_bytes <= config.native.pending_bytes)
        );
    }
    for number in 0..64 {
        let mut input = [0; 1024];
        let length = pair.server.recv(&mut input)?;
        assert_eq!(&input[..length], ethernet(number));
    }
    let stopped = pair.stop()?;
    let server = stopped
        .iter()
        .find(|done| done.snapshot.info.role == security::Role::Responder)
        .ok_or("missing responder observation")?;
    assert_eq!(server.snapshot.counters.native_written, 64);
    Ok(())
}

#[test]
fn permanently_blocked_native_output_keeps_its_first_stall_deadline() -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut config = config(kind);
    config.native.stall_timeout = Duration::from_millis(50);
    // A deterministic nonblocking PacketDevice on a real registered descriptor
    // refuses output forever. The separate AF_UNIX pressure fixture tests the OS.
    let pair = Pair::start_with_blocked_server(kind, config, config, true)?;
    pair.client.send(&ethernet(1))?;
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    loop {
        let stopped = pair
            .snapshots
            .lock()
            .map_err(|_| "snapshot lock poisoned")?
            .iter()
            .any(|snapshot| snapshot.terminal == Some(StopReason::NativeStall));
        if stopped {
            let snapshots = pair
                .snapshots
                .lock()
                .map_err(|_| "snapshot lock poisoned")?;
            assert!(
                snapshots
                    .iter()
                    .any(|snapshot| snapshot.info.role == security::Role::Responder
                        && snapshot.counters.native_pending_packets == 1
                        && snapshot.counters.native_written == 0)
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err("native stall did not publish a bounded terminal observation".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    drop(pair);
    Ok(())
}

#[tokio::test]
async fn combined_readiness_preserves_the_opposite_direction_after_wouldblock() -> Result {
    let (socket, peer) = UnixDatagram::pair()?;
    socket.set_nonblocking(true)?;
    peer.set_nonblocking(true)?;
    peer.send(b"incoming")?;
    let mut descriptor = AsyncFd::with_interest(
        Device {
            socket,
            blocked: true,
            wouldblock: None,
        },
        Interest::READABLE.add(Interest::WRITABLE),
    )?;
    let mut guard = tokio::time::timeout(
        Duration::from_secs(1),
        descriptor.ready_mut(Interest::READABLE.add(Interest::WRITABLE)),
    )
    .await??;
    assert!(guard.ready().is_readable());
    assert!(guard.ready().is_writable());
    assert!(!try_native_write(&mut guard, b"blocked")?);
    assert!(guard.ready().is_readable());
    assert!(!guard.ready().is_writable());
    let mut input = [0; 32];
    assert_eq!(try_native_read(&mut guard, &mut input)?, Some(8));
    assert_eq!(&input[..8], b"incoming");
    drop(guard);
    let (socket, peer) = UnixDatagram::pair()?;
    socket.set_nonblocking(true)?;
    peer.set_nonblocking(true)?;
    peer.send(b"one")?;
    let mut descriptor = AsyncFd::with_interest(
        Device {
            socket,
            blocked: false,
            wouldblock: None,
        },
        Interest::READABLE.add(Interest::WRITABLE),
    )?;
    let mut guard = tokio::time::timeout(
        Duration::from_secs(1),
        descriptor.ready_mut(Interest::READABLE.add(Interest::WRITABLE)),
    )
    .await??;
    assert_eq!(try_native_read(&mut guard, &mut input)?, Some(3));
    assert_eq!(try_native_read(&mut guard, &mut input)?, None);
    assert!(guard.ready().is_writable());
    assert!(try_native_write(&mut guard, b"outgoing")?);
    let length = peer.recv(&mut input)?;
    assert_eq!(&input[..length], b"outgoing");
    Ok(())
}

#[test]
fn blocked_native_output_does_not_block_opposite_native_input_or_control() -> Result {
    let kind = cover::Appearance::MediaLike;
    let config = config(kind);
    let pair = Pair::start_with_blocked_server(kind, config, config, true)?;
    pair.client.send(&ethernet(1))?;
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while !pair
        .snapshots
        .lock()
        .map_err(|_| "snapshot lock poisoned")?
        .iter()
        .any(|snapshot| {
            snapshot.info.role == security::Role::Responder
                && snapshot.counters.native_pending_packets == 1
        })
    {
        if std::time::Instant::now() >= deadline {
            return Err("blocked output precondition not reached".into());
        }
        thread::sleep(Duration::from_millis(1));
    }
    let reverse = ethernet(2);
    pair.server.send(&reverse)?;
    let mut input = [0; 1024];
    let length = pair.client.recv(&mut input)?;
    assert_eq!(&input[..length], reverse);
    thread::sleep(Duration::from_millis(30));
    let snapshots = pair
        .snapshots
        .lock()
        .map_err(|_| "snapshot lock poisoned")?;
    assert!(
        snapshots
            .iter()
            .any(|snapshot| snapshot.info.role == security::Role::Responder
                && snapshot.liveness.last_pong_micros.is_some())
    );
    drop(snapshots);
    let stopped = pair.stop()?;
    assert!(
        stopped
            .iter()
            .all(|done| done.reason == StopReason::Cancelled)
    );
    Ok(())
}

#[test]
fn canonical_contract_changes_for_every_runtime_class_but_not_local_reporting() -> Result {
    let initial = config(cover::Appearance::QuicLike);
    let digest = initial.canonical_digest()?;
    let mut changed = initial;
    changed.report_interval = Some(Duration::from_millis(17));
    assert_eq!(changed.canonical_digest()?, digest);
    for change in [0, 1, 2, 3, 4, 5, 6, 7, 8] {
        let mut value = initial;
        match change {
            0 => value.send.bytes_per_second += 1,
            1 => value.receive.records.codec.tail_micros += 1,
            2 => value.native.pending_bytes += 1,
            3 => value.work.receive_packets += 1,
            4 => value.security.packets_per_key += 1,
            5 => value.control.recovery.max_retries += 1,
            6 => value.data_epoch.0 += 1,
            7 => value.lifetime.lease += Duration::from_nanos(1),
            _ => value.policy.transaction_micros += 1,
        };
        assert_ne!(value.canonical_digest()?, digest);
    }
    Ok(())
}
#[test]
fn admitted_capacity_is_distinct_from_active_mtu_and_preserves_requested_geometry() -> Result {
    let mut value = config(cover::Appearance::QuicLike);
    value.security.max_body_bytes = 8000;
    let cover = cover::Config::new(
        cover::Appearance::QuicLike,
        cover::ConnectionIds {
            local: cover::ConnectionId([1; 8]),
            peer: cover::ConnectionId([2; 8]),
        },
        cover::MediaConfig {
            local_ssrc: cover::Ssrc(1),
            peer_ssrc: cover::Ssrc(2),
            payload_type: 96,
        },
        cover::Limits {
            max_packet_bytes: 9000,
            max_protected_bytes: 8500,
        },
    )?;
    value.validate_cover(cover, false)?;
    value.send.records.codec.datagram_bytes = 1450;
    assert!(value.validate_cover(cover, false).is_err());
    assert_eq!(value.send.records.codec.datagram_bytes, 1450);
    value.send.records.codec.datagram_bytes = 512;
    value.control.wire_overhead += 1;
    assert!(value.validate_cover(cover, false).is_err());
    Ok(())
}
#[test]
fn bucket_is_exact_bounded_and_does_not_reset_credit_when_rate_changes() -> Result {
    let mut bucket = Bucket::new(8000, 2000);
    bucket.charge(2000)?;
    assert_eq!(bucket.allowance(), 0);
    assert_eq!(bucket.ready_at(80)?, 10000);
    bucket.refill(5000)?;
    assert_eq!(bucket.allowance(), 40);
    bucket.rate = 16000;
    bucket.refill(10000)?;
    assert_eq!(bucket.allowance(), 120);
    assert!(bucket.charge(121).is_err());
    assert_eq!(bucket.allowance(), 120);
    assert!(bucket.refill(9999).is_err());
    assert!(bucket.ready_at(2001).is_err());
    Ok(())
}

#[test]
fn fixed_resource_control_and_feedback_minima_are_not_silently_relaxed() -> Result {
    let initial = config(cover::Appearance::MediaLike);
    initial.validate_cover(appearance(cover::Appearance::MediaLike, true)?, false)?;
    for case in 0..6 {
        let mut value = initial;
        match case {
            0 => value.control_epoch.0 = 0,
            1 => value.data_epoch.0 = 0,
            2 => value.send.records.codec.datagram_bytes = 139,
            3 => value.control.recovery.max_source_bytes = 191,
            4 => value.work.receive_interval = Duration::ZERO,
            _ => value.native.pending_bytes = 511,
        };
        assert!(value.validate().is_err());
    }
    Ok(())
}

#[test]
fn submicrosecond_runtime_deadlines_never_become_zero_quota_or_lease() -> Result {
    for case in 0..6 {
        let mut value = config(cover::Appearance::QuicLike);
        match case {
            0 => value.lifetime.lease = Duration::from_nanos(999),
            1 => value.lifetime.ping_interval = Duration::from_nanos(1),
            2 => value.lifetime.pong_timeout = Duration::from_nanos(999),
            3 => value.native.stall_timeout = Duration::from_nanos(999),
            4 => value.work.receive_interval = Duration::from_nanos(999),
            _ => value.report_interval = Some(Duration::from_nanos(999)),
        };
        assert!(value.validate().is_err());
    }
    let mut value = config(cover::Appearance::QuicLike);
    value.work.receive_interval = Duration::from_micros(1);
    value.validate()?;
    Ok(())
}

async fn parts_pair(kind: cover::Appearance) -> Result<(member::Parts, member::Parts)> {
    let a = StdUdp::bind("127.0.0.1:0")?;
    let b = StdUdp::bind("127.0.0.1:0")?;
    let path = gate::Path {
        client: a.local_addr()?,
        server: b.local_addr()?,
    };
    a.connect(path.server)?;
    b.connect(path.client)?;
    a.set_nonblocking(true)?;
    b.set_nonblocking(true)?;
    tokio::try_join!(
        authenticated(a, path, kind, true),
        authenticated(b, path, kind, false)
    )
}
fn source(driver: &mut Driver, now: u64, number: u8) -> Result<Vec<u8>> {
    assert_eq!(
        driver.swift.offer(now, &ethernet(number))?,
        records::Admission::Accepted
    );
    let seed = driver.records.next_number(Class::User);
    let body = driver
        .swift
        .poll(now, records::RecordNumber(seed.0), true)?
        .ok_or_else(|| protocol("fixture source not emitted"))?;
    let mut wire = vec![0; driver.cover.limits().max_packet_bytes];
    let sealed = driver.records.seal_user_in(
        driver.source_scope,
        meta(driver.outer, cover::Phase::Established),
        body,
        &mut driver.seal,
        &mut wire,
    )?;
    driver.outer += 1;
    wire.truncate(sealed.bytes);
    Ok(wire)
}

#[tokio::test]
async fn replay_and_tamper_never_gain_control_authority_or_liveness() -> Result {
    let kind = cover::Appearance::QuicLike;
    let config = config(kind);
    let (a, b) = parts_pair(kind).await?;
    let now = Instant::now();
    let (_, mut a) = Driver::new(a, security::ConfigDigest([3; 32]), config, now)?;
    let (_, mut b) = Driver::new(b, security::ConfigDigest([3; 32]), config, now)?;
    let wire = source(&mut a, 0, 7)?;
    let mut bad = wire.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    b.receive(&bad, 1, now, &resolve(config))?;
    assert!(b.live.last_verified_micros.is_none());
    assert_eq!(b.control.retained().receive_records, 0);
    b.receive(&wire, 2, now, &resolve(config))?;
    assert_eq!(b.live.last_verified_micros, Some(2));
    b.receive(&wire, 3, now, &resolve(config))?;
    assert_eq!(b.live.last_verified_micros, Some(2));
    assert_eq!(b.counters.replay_rejections, 1);
    assert_eq!(b.control.retained().receive_records, 0);
    b.collect_native(3)?;
    assert_eq!(b.native.len(), 1);
    assert_eq!(
        b.native.front().map(|packet| packet.bytes.as_slice()),
        Some(ethernet(7).as_slice())
    );
    Ok(())
}

#[tokio::test]
async fn fresh_user_traffic_cannot_renew_the_original_matching_pong_deadline() -> Result {
    let kind = cover::Appearance::MediaLike;
    let config = config(kind);
    let (a, b) = parts_pair(kind).await?;
    let instant = Instant::now();
    let (_, mut a) = Driver::new(a, security::ConfigDigest([3; 32]), config, instant)?;
    let (_, mut b) = Driver::new(b, security::ConfigDigest([3; 32]), config, instant)?;
    b.challenge = Some(Challenge {
        nonce: 1,
        deadline: 10,
        submitted: true,
    });
    b.live.outstanding = Some(1);
    b.live.deadline_micros = Some(10);
    let wire = source(&mut a, 0, 1)?;
    b.receive(&wire, 9, instant, &resolve(config))?;
    assert_eq!(b.live.last_verified_micros, Some(9));
    assert_eq!(b.live.deadline_micros, Some(10));
    assert_eq!(
        b.progress(10).err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(b.terminal, Some(StopReason::PeerTimeout));
    Ok(())
}

#[tokio::test]
async fn no_allowance_cannot_keep_expired_bootstrap_or_joining_custody_alive() -> Result {
    let kind = cover::Appearance::QuicLike;
    let config = config(kind);
    let (a, b) = parts_pair(kind).await?;
    let end = b.deadline;
    let origin = Instant::now();
    let (_, mut a) = Driver::new(a, security::ConfigDigest([3; 32]), config, origin)?;
    let (_, mut b) = Driver::new(b, security::ConfigDigest([3; 32]), config, origin)?;
    a.bucket.tokens = 0;
    b.bucket.tokens = 0;
    assert!(a.tail(end)?.is_none());
    assert!(b.tail(end)?.is_none());
    assert!(a.bootstrap.deadline().is_none());
    assert!(b.bootstrap.deadline().is_none());
    assert!(a.joining.deadline().is_none());
    assert!(b.joining.deadline().is_none());
    assert_eq!(a.counters.wire_packets, 0);
    assert_eq!(b.counters.wire_packets, 0);
    let now = clock(origin, end)?;
    assert!(b.wake(now)? > end);
    assert!(
        b.wake(u64::MAX)
            .err()
            .and_then(|error| error.into_inner())
            .is_some_and(|error| error.is::<Exhausted>())
    );
    Ok(())
}

#[tokio::test]
async fn native_capacity_withholds_before_swift_accept_and_preserves_control_owner() -> Result {
    let kind = cover::Appearance::MediaLike;
    let mut config = config(kind);
    config.native.pending_packets = 1;
    config.native.pending_bytes = 512;
    let (a, b) = parts_pair(kind).await?;
    let instant = Instant::now();
    let (_, mut a) = Driver::new(a, security::ConfigDigest([3; 32]), config, instant)?;
    let (_, mut b) = Driver::new(b, security::ConfigDigest([3; 32]), config, instant)?;
    let first = source(&mut a, 0, 1)?;
    b.receive(&first, 1, instant, &resolve(config))?;
    b.collect_native(1)?;
    let second = source(&mut a, 2, 2)?;
    b.receive(&second, 2, instant, &resolve(config))?;
    assert_eq!(b.counters.native_backpressure_drops, 1);
    assert_eq!(b.native.len(), 1);
    assert_eq!(b.native_bytes, 256);
    assert_eq!(
        b.native.front().map(|packet| packet.bytes.as_slice()),
        Some(ethernet(1).as_slice())
    );
    assert_eq!(b.records.control_scope().epoch, security::Epoch(1));
    assert!(b.control.drained());
    Ok(())
}

#[tokio::test]
async fn authenticated_malformed_control_is_not_receipted_or_reclassified_as_user() -> Result {
    let kind = cover::Appearance::QuicLike;
    let config = config(kind);
    let (a, b) = parts_pair(kind).await?;
    let instant = Instant::now();
    let (_, mut a) = Driver::new(a, security::ConfigDigest([3; 32]), config, instant)?;
    let (_, mut b) = Driver::new(b, security::ConfigDigest([3; 32]), config, instant)?;
    a.control.submit(b"not an L2SC envelope", Duration::ZERO)?;
    let emitted = a
        .control
        .poll(Duration::ZERO, 4096, &mut a.control_wire)?
        .ok_or_else(|| protocol("control fixture not emitted"))?;
    let sealed = a.records.seal(
        Class::Control,
        meta(a.outer, cover::Phase::Established),
        &a.control_wire[..emitted.bytes],
        &mut a.seal,
        &mut a.wire,
    )?;
    assert_eq!(
        b.receive(&a.wire[..sealed.bytes], 1, instant, &resolve(config))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(b.counters.wire_packets, 0);
    assert_eq!(b.envelope_rx, 1);
    assert_eq!(b.swift.stats().receiver.packets, 0);
    Ok(())
}

#[tokio::test]
async fn forged_usage_guard_cannot_terminate_or_burn_the_next_valid_small_record() -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut config = config(kind);
    config.security.packets_per_key = 100;
    config.security.max_body_bytes_per_key = config.security.max_body_bytes as u64;
    let (a, b) = parts_pair(kind).await?;
    let instant = Instant::now();
    let (_, mut a) = Driver::new(a, security::ConfigDigest([3; 32]), config, instant)?;
    let (_, mut b) = Driver::new(b, security::ConfigDigest([3; 32]), config, instant)?;
    for number in 0..3 {
        let wire = source(&mut a, u64::from(number), number)?;
        b.receive(&wire, u64::from(number), instant, &resolve(config))?;
    }
    let valid = source(&mut a, 3, 3)?;
    let mut forged = valid.clone();
    forged.resize(1200, 0);
    assert_eq!(
        b.records.open(&forged, &mut b.open, &mut b.plain),
        Err(record::Error::Security(security::Error::KeyUsageExhausted))
    );
    let verified = b.live.last_verified_micros;
    b.receive(&forged, 4, instant, &resolve(config))?;
    assert_eq!(b.live.last_verified_micros, verified);
    assert!(b.terminal.is_none());
    b.receive(&valid, 5, instant, &resolve(config))?;
    assert_eq!(b.live.last_verified_micros, Some(5));
    assert!(b.terminal.is_none());
    Ok(())
}

#[tokio::test]
async fn full_native_queue_still_rejects_empty_unknown_user_and_services_control() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut config = config(kind);
        config.native.pending_packets = 1;
        config.native.pending_bytes = 512;
        let (a, b) = parts_pair(kind).await?;
        let instant = Instant::now();
        let (_, mut a) = Driver::new(a, security::ConfigDigest([3; 32]), config, instant)?;
        let (_, mut b) = Driver::new(b, security::ConfigDigest([3; 32]), config, instant)?;
        let first = source(&mut a, 0, 1)?;
        b.receive(&first, 1, instant, &resolve(config))?;
        b.collect_native(1)?;
        assert!(!b.native_room());
        for body in [&[][..], &[3][..]] {
            let sealed = a.records.seal(
                Class::User,
                meta(a.outer, cover::Phase::Established),
                body,
                &mut a.seal,
                &mut a.wire,
            )?;
            a.outer += 1;
            assert_eq!(
                b.receive(&a.wire[..sealed.bytes], 2, instant, &resolve(config))
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
            assert_eq!(b.counters.native_backpressure_drops, 0);
            assert_eq!(b.native.len(), 1);
        }
        let valid = source(&mut a, 3, 2)?;
        b.receive(&valid, 3, instant, &resolve(config))?;
        assert_eq!(b.counters.native_backpressure_drops, 1);
        assert_eq!(b.native.len(), 1);
        assert!(
            a.submit(
                4,
                a.records.control_scope(),
                control::Body::Ping { nonce: 1 }
            )?
            .is_some()
        );
        let emitted = a
            .control
            .poll(duration(4), 4096, &mut a.control_wire)?
            .ok_or_else(|| protocol("fixture Ping missing"))?;
        let sealed = a.records.seal(
            Class::Control,
            meta(a.outer, cover::Phase::Established),
            &a.control_wire[..emitted.bytes],
            &mut a.seal,
            &mut a.wire,
        )?;
        b.receive(&a.wire[..sealed.bytes], 4, instant, &resolve(config))?;
        assert_eq!(b.remote_ping, 1);
        assert_eq!(b.pong, Some(1));
        b.submit_control(5)?;
        assert_eq!(b.pong, None);
        assert_eq!(b.control.retained().send_records, 1);
        assert_eq!(b.native.len(), 1);
    }
    Ok(())
}
