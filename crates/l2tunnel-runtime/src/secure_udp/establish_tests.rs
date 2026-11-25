use super::*;
use std::cell::RefCell;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use zeroize::Zeroizing;

tokio::task_local! { static FAULTS: RefCell<Faults>; }
#[derive(Default)]
struct Faults {
    drop_first: u8,
    duplicate_first: u8,
    dropped: u8,
    duplicated: u8,
    path_errors: u8,
    path_failures: u8,
    reorder_response: bool,
    held: Option<Vec<Vec<u8>>>,
    reordered: bool,
    hold_confirmation_until_root: bool,
    root_released: bool,
    confirmations_held_before_root: u32,
}
#[derive(Clone, Copy, Debug, Default)]
struct FaultReport {
    dropped: u8,
    duplicated: u8,
    path_failures: u8,
    reordered: bool,
}
// Finite scripted loss/reordering still uses the real original connected sockets.
// This is not kernel/netem or real network performance evidence.
pub(super) fn outbound(bytes: &[u8]) -> Vec<Vec<u8>> {
    FAULTS
        .try_with(|faults| {
            let mut faults = faults.borrow_mut();
            let class = packet_class(bytes);
            if class == 1 << 5 && faults.hold_confirmation_until_root && !faults.root_released {
                faults.confirmations_held_before_root += 1;
                return Vec::new();
            }
            if faults.drop_first & class != 0 {
                faults.drop_first &= !class;
                faults.dropped |= class;
                return Vec::new();
            }
            let mut packets = if faults.duplicate_first & class != 0 {
                faults.duplicate_first &= !class;
                faults.duplicated |= class;
                vec![bytes.to_vec(), bytes.to_vec()]
            } else {
                vec![bytes.to_vec()]
            };
            if let Some(held) = faults.held.take() {
                faults.reordered = true;
                packets.extend(held);
                return packets;
            }
            if faults.reorder_response && class == 1 << 4 {
                faults.reorder_response = false;
                faults.held = Some(packets);
                return Vec::new();
            }
            packets
        })
        .unwrap_or_else(|_| vec![bytes.to_vec()])
}
pub(super) fn send_error(bytes: &[u8]) -> Option<io::Error> {
    FAULTS
        .try_with(|faults| {
            let mut faults = faults.borrow_mut();
            let class = packet_class(bytes);
            if faults.path_errors & class == 0 {
                return None;
            }
            faults.path_errors &= !class;
            faults.path_failures |= class;
            Some(io::Error::from(io::ErrorKind::ConnectionRefused))
        })
        .ok()
        .flatten()
}
fn packet_class(bytes: &[u8]) -> u8 {
    let offset = match bytes.first() {
        Some(0xc3) => 30,
        Some(0x80) => 14,
        _ => return 0,
    };
    let Some(body) = bytes.get(offset..) else {
        return 0;
    };
    match body.first() {
        Some(&GATE_TAG) => match body.get(3) {
            Some(1) => 1,
            Some(2) => 2,
            Some(3) => 4,
            _ => 0,
        },
        Some(&CONTROL_TAG) if body.get(1) == Some(&40) => 1 << 6,
        Some(&CONTROL_TAG) if body.get(1) == Some(&32) => {
            match body.get(1 + 32 + l2tunnel_recovery::DATA_HEADER_BYTES + 1) {
                Some(1) => 1 << 3,
                Some(2) => 1 << 4,
                Some(3) => 1 << 5,
                _ => 0,
            }
        }
        _ => 0,
    }
}
struct Entropy {
    seed: u8,
    calls: Arc<AtomicUsize>,
    fail: bool,
}
impl Entropy {
    fn new(seed: u8) -> Self {
        Self {
            seed,
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
        }
    }
}
impl hs::Entropy for Entropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> Result<(), hs::EntropyError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            return Err(hs::EntropyError);
        }
        output.fill(self.seed);
        self.seed = self.seed.wrapping_add(1);
        Ok(())
    }
}
fn local(role: hs::Role) -> hs::LocalSecret {
    hs::LocalSecret::new(Zeroizing::new(
        [if role == hs::Role::Initiator {
            0x41
        } else {
            0x42
        }; 32],
    ))
}
fn peers() -> Peers {
    Peers {
        initiator: local(hs::Role::Initiator).public_key(),
        responder: local(hs::Role::Responder).public_key(),
    }
}
fn identity(role: hs::Role, profile: hs::Profile) -> Identity {
    let peers = peers();
    Identity {
        local: local(role),
        peer: if role == hs::Role::Initiator {
            peers.responder
        } else {
            peers.initiator
        },
        psk: if profile == hs::Profile::IkPsk2 {
            Some(hs::Psk::new(Zeroizing::new([7; 32])))
        } else {
            None
        },
    }
}
fn config(
    path: gate::Path,
    appearance: cover::Appearance,
    role: hs::Role,
    profile: hs::Profile,
) -> Config {
    let initiator = role == hs::Role::Initiator;
    let cover = cover::Config::new(
        appearance,
        cover::ConnectionIds {
            local: cover::ConnectionId([if initiator { 1 } else { 2 }; 8]),
            peer: cover::ConnectionId([if initiator { 2 } else { 1 }; 8]),
        },
        cover::MediaConfig {
            local_ssrc: cover::Ssrc(if initiator { 101 } else { 202 }),
            peer_ssrc: cover::Ssrc(if initiator { 202 } else { 101 }),
            payload_type: 96,
        },
        cover::Limits {
            max_packet_bytes: 572,
            max_protected_bytes: 500,
        },
    )
    .expect("cover");
    let mut gate = gate::Config::new(path, [0x11; 32], 1).expect("gate defaults");
    gate.cookie_ttl = Duration::from_secs(2);
    gate.handshake_timeout = Duration::from_secs(2);
    gate.interval = Duration::from_millis(2);
    gate.initial_rto = Duration::from_millis(10);
    gate.maximum_rto = Duration::from_millis(40);
    gate.gate_attempts = 64;
    gate.path_mtu = 600;
    gate.outer_overhead = 28
        + 1
        + if appearance == cover::Appearance::QuicLike {
            30
        } else {
            14
        };
    gate.arq.max_source_bytes = FRAME_BYTES;
    gate.arq.send_bytes = 400;
    gate.arq.receive_bytes = 400;
    gate.arq.send_records = 4;
    gate.arq.receive_records = 4;
    gate.arq.initial_rto = Duration::from_millis(10);
    gate.arq.maximum_rto = Duration::from_millis(40);
    gate.arq.ack_delay = Duration::ZERO;
    gate.arq.max_retries = 32;
    gate.control_packets = 8;
    gate.control_bytes = 4800;
    Config {
        gate,
        cover,
        profile,
        binding: Binding {
            configuration: [3; 32],
            carrier: [if appearance == cover::Appearance::QuicLike {
                4
            } else {
                5
            }; 32],
            outer: [6; 32],
            member: [8; 32],
        },
        receive_packets_per_interval: 64,
    }
}
async fn pair() -> (UdpSocket, UdpSocket, gate::Path) {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("server bind");
    let path = gate::Path {
        client: client.local_addr().expect("client address"),
        server: server.local_addr().expect("server address"),
    };
    client.connect(path.server).await.expect("client connect");
    server.connect(path.client).await.expect("server connect");
    (client, server, path)
}
#[derive(Debug)]
struct Report {
    binding: security::SessionBinding,
    statistics: Statistics,
    faults: FaultReport,
    local: SocketAddr,
    peer: SocketAddr,
    drained: bool,
}
async fn service_tail(mut established: Established) -> Result<Report, Error> {
    let _ = FAULTS.try_with(|faults| {
        faults.borrow_mut().root_released = true;
    });
    let mut input = vec![0; established.cover.limits().max_packet_bytes + 1];
    let mut output = vec![0; established.tail.max_packet_bytes()];
    let quiet_end = Instant::now() + Duration::from_millis(300);
    loop {
        let now = Instant::now();
        before(now, established.deadline)?;
        while let Some(length) = established.tail.poll(
            Instant::now(),
            metadata(established.next_outer),
            &mut output,
        )? {
            let accepted =
                send(&established.socket, &output[..length], established.deadline).await?;
            sent(&mut established.tail.core.statistics, length, accepted);
            advance(&mut established.next_outer)?;
        }
        if now >= quiet_end && established.tail.drained() {
            break;
        }
        let wake = established
            .tail
            .deadline()
            .unwrap_or(established.deadline)
            .min(quiet_end.max(now + Duration::from_millis(2)));
        tokio::select! {
            received = established.socket.recv(&mut input) => {
                let length = received?;
                if let Ok(decoded) = established.cover.decode(&input[..length]) { established.tail.receive(decoded, Instant::now())?; }
            }
            _ = sleep_until(wake) => {}
        }
    }
    let faults = FAULTS
        .try_with(|value| {
            let value = value.borrow();
            FaultReport {
                dropped: value.dropped,
                duplicated: value.duplicated,
                path_failures: value.path_failures,
                reordered: value.reordered,
            }
        })
        .unwrap_or_default();
    Ok(Report {
        binding: established.binding,
        statistics: established.tail.statistics(),
        faults,
        local: established.socket.local_addr()?,
        peer: established.socket.peer_addr()?,
        drained: established.tail.drained(),
    })
}
async fn client_case(
    socket: UdpSocket,
    config: Config,
    faults: bool,
    seed: u8,
) -> Result<Report, Error> {
    FAULTS
        .scope(
            RefCell::new(Faults {
                drop_first: if faults { 127 } else { 0 },
                duplicate_first: if faults { 127 } else { 0 },
                path_errors: if faults { 127 } else { 0 },
                reorder_response: faults,
                ..Faults::default()
            }),
            async move {
                let mut entropy = Entropy::new(seed);
                let established = connect(
                    socket,
                    config,
                    identity(hs::Role::Initiator, config.profile),
                    gate::Secret::new([1; 32]),
                    Instant::now() + Duration::from_secs(2),
                    &mut entropy,
                )
                .await?;
                service_tail(established).await
            },
        )
        .await
}
async fn server_case(
    socket: UdpSocket,
    config: Config,
    faults: bool,
    seed: u8,
) -> Result<Report, Error> {
    FAULTS
        .scope(
            RefCell::new(Faults {
                drop_first: if faults { 127 } else { 0 },
                duplicate_first: if faults { 127 } else { 0 },
                path_errors: if faults { 127 } else { 0 },
                reorder_response: faults,
                ..Faults::default()
            }),
            async move {
                let mut entropy = Entropy::new(seed);
                let origin = Instant::now();
                let mut admission = ServerAdmission::new(
                    config,
                    peers(),
                    gate::Secret::new([1; 32]),
                    gate::Secret::new([2; 32]),
                    origin,
                )?;
                let established = accept(
                    socket,
                    identity(hs::Role::Responder, config.profile),
                    &mut admission,
                    origin + Duration::from_secs(2),
                    &mut entropy,
                )
                .await?;
                let report = service_tail(established).await?;
                let statistics = admission.statistics();
                assert!(statistics.response_bytes <= statistics.validated_request_bytes);
                assert_eq!(
                    statistics.retained_sessions, 1,
                    "finished cookie stays quarantined"
                );
                Ok(report)
            },
        )
        .await
}
fn assert_pair(client: &Report, server: &Report, path: gate::Path, faults: bool) {
    assert_eq!(client.binding, server.binding);
    assert_ne!(client.binding.session.0, [0; 16]);
    assert_eq!((client.local, client.peer), (path.client, path.server));
    assert_eq!((server.local, server.peer), (path.server, path.client));
    assert_eq!(client.statistics.noise_flights, 2);
    assert_eq!(server.statistics.noise_flights, 2);
    assert!(client.drained && server.drained);
    if faults {
        assert_eq!(
            client.faults.dropped | server.faults.dropped,
            127,
            "all seven wire classes lost at least once"
        );
        assert_eq!(
            client.faults.duplicated | server.faults.duplicated,
            127,
            "all seven wire classes duplicated"
        );
        assert_eq!(
            client.faults.path_failures | server.faults.path_failures,
            127,
            "transient send error for every class"
        );
        assert!(client.statistics.socket_drops > 0 && server.statistics.socket_drops > 0);
        assert!(
            server.faults.reordered,
            "server response held behind another datagram"
        );
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_original_udp_covers_profiles_loss_duplicates_and_final_tail() {
    let mut sessions = Vec::new();
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for profile in [hs::Profile::Ik, hs::Profile::IkPsk2] {
            let (client, server, path) = pair().await;
            let client_cfg = config(path, appearance, hs::Role::Initiator, profile);
            let server_cfg = config(path, appearance, hs::Role::Responder, profile);
            let (client, server) = tokio::join!(
                client_case(client, client_cfg, true, 21 + sessions.len() as u8),
                server_case(server, server_cfg, true, 81 + sessions.len() as u8)
            );
            let client = client.expect("lossy client establishment");
            let server = server.expect("lossy server establishment");
            assert_pair(&client, &server, path, true);
            assert!(
                !sessions.contains(&client.binding.session),
                "fresh ticket-derived session per attempt"
            );
            sessions.push(client.binding.session);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responder_root_release_retains_final_ciphertext_until_peer_can_finish() {
    let (client, server, path) = pair().await;
    let client_cfg = config(
        path,
        cover::Appearance::MediaLike,
        hs::Role::Initiator,
        hs::Profile::Ik,
    );
    let server_cfg = config(
        path,
        cover::Appearance::MediaLike,
        hs::Role::Responder,
        hs::Profile::Ik,
    );
    let responder = FAULTS.scope(
        RefCell::new(Faults {
            hold_confirmation_until_root: true,
            ..Faults::default()
        }),
        async move {
            let origin = Instant::now();
            let mut entropy = Entropy::new(91);
            let mut admission = ServerAdmission::new(
                server_cfg,
                peers(),
                gate::Secret::new([1; 32]),
                gate::Secret::new([2; 32]),
                origin,
            )?;
            let established = accept(
                server,
                identity(hs::Role::Responder, server_cfg.profile),
                &mut admission,
                origin + Duration::from_secs(2),
                &mut entropy,
            )
            .await?;
            assert!(FAULTS.with(|faults| faults.borrow().confirmations_held_before_root) > 0);
            assert!(
                !established.tail.drained(),
                "undelivered final ciphertext must remain retained after root release"
            );
            assert!(
                established.tail.confirmation.is_some(),
                "actual Noise cache remains in custody"
            );
            service_tail(established).await
        },
    );
    let (client, server) = tokio::join!(client_case(client, client_cfg, false, 31), responder);
    assert_pair(
        &client.expect("client completes using responder tail"),
        &server.expect("responder retains final custody"),
        path,
        false,
    );
}
#[test]
fn two_independent_runtime_threads_keep_original_socket_pair() {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for profile in [hs::Profile::Ik, hs::Profile::IkPsk2] {
            let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client bind");
            let server = std::net::UdpSocket::bind("127.0.0.1:0").expect("server bind");
            let path = gate::Path {
                client: client.local_addr().expect("client address"),
                server: server.local_addr().expect("server address"),
            };
            client.connect(path.server).expect("client connect");
            server.connect(path.client).expect("server connect");
            client.set_nonblocking(true).expect("client nonblocking");
            server.set_nonblocking(true).expect("server nonblocking");
            let client_cfg = config(path, appearance, hs::Role::Initiator, profile);
            let server_cfg = config(path, appearance, hs::Role::Responder, profile);
            let client = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("client runtime");
                runtime.block_on(async {
                    client_case(
                        UdpSocket::from_std(client).expect("client socket"),
                        client_cfg,
                        false,
                        31,
                    )
                    .await
                })
            });
            let server = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("server runtime");
                runtime.block_on(async {
                    server_case(
                        UdpSocket::from_std(server).expect("server socket"),
                        server_cfg,
                        false,
                        91,
                    )
                    .await
                })
            });
            assert_pair(
                &client
                    .join()
                    .expect("client thread")
                    .expect("client handshake"),
                &server
                    .join()
                    .expect("server thread")
                    .expect("server handshake"),
                path,
                false,
            );
        }
    }
}
#[tokio::test]
async fn failed_entropy_and_wrong_actual_tuple_emit_nothing() {
    let (client, server, path) = pair().await;
    let config = config(
        path,
        cover::Appearance::QuicLike,
        hs::Role::Initiator,
        hs::Profile::Ik,
    );
    let mut entropy = Entropy::new(1);
    entropy.fail = true;
    assert!(matches!(
        connect(
            client,
            config,
            identity(hs::Role::Initiator, config.profile),
            gate::Secret::new([1; 32]),
            Instant::now() + Duration::from_millis(100),
            &mut entropy
        )
        .await,
        Err(Error::Entropy)
    ));
    let mut input = [0; 600];
    assert!(
        timeout_at(
            Instant::now() + Duration::from_millis(20),
            server.recv(&mut input)
        )
        .await
        .is_err()
    );
    let (client, _server, path) = pair().await;
    let mut config = self::config(
        path,
        cover::Appearance::MediaLike,
        hs::Role::Initiator,
        hs::Profile::Ik,
    );
    config
        .gate
        .path
        .client
        .set_port(if path.client.port() == 1 { 2 } else { 1 });
    let mut entropy = Entropy::new(1);
    assert!(matches!(
        connect(
            client,
            config,
            identity(hs::Role::Initiator, config.profile),
            gate::Secret::new([1; 32]),
            Instant::now() + Duration::from_millis(100),
            &mut entropy
        )
        .await,
        Err(Error::Configuration(_))
    ));
    assert_eq!(entropy.calls.load(Ordering::Relaxed), 0);
}
#[tokio::test]
async fn hostile_oversized_input_is_quiet_bounded_and_original_deadline_wins() {
    let (client, server, path) = pair().await;
    let mut config = config(
        path,
        cover::Appearance::MediaLike,
        hs::Role::Responder,
        hs::Profile::Ik,
    );
    config.receive_packets_per_interval = 1;
    config.gate.interval = Duration::from_millis(10);
    let server_identity = identity(hs::Role::Responder, config.profile);
    let pinned = peers();
    // Real-clock deadlines cover the operation, not synchronous fixture key setup.
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    let mut admission = ServerAdmission::new(
        config,
        pinned,
        gate::Secret::new([1; 32]),
        gate::Secret::new([2; 32]),
        origin,
    )
    .expect("admission");
    let mut entropy = Entropy::new(9);
    let flood = async {
        while Instant::now() < end {
            match client.send(&[0x80; 900]).await {
                Ok(_) => {}
                Err(error) if path_loss(&error) => {}
                Err(error) => panic!("hostile-input fixture socket failed: {error}"),
            }
            // Ten times the configured receive quota keeps a bounded backlog
            // without consuming a CPU merely to generate hostile input.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    let (result, ()) = tokio::join!(
        accept(server, server_identity, &mut admission, end, &mut entropy),
        flood
    );
    assert!(
        matches!(&result, Err(Error::Deadline)),
        "hostile-input operation must reach its original deadline: {:?}",
        result.as_ref().err(),
    );
    assert!(Instant::now() >= end);
    assert!(Instant::now() < end + Duration::from_millis(200));
    assert_eq!(
        entropy.calls.load(Ordering::Relaxed),
        1,
        "discarded input does not consume fresh entropy or DH"
    );
    assert_eq!(admission.statistics(), gate::GateStatistics::default());
    let mut input = [0; 600];
    match timeout_at(
        Instant::now() + Duration::from_millis(10),
        client.recv(&mut input),
    )
    .await
    {
        Err(_) => {}
        Ok(Err(error)) if path_loss(&error) => {}
        result => panic!("hostile input received an unexpected response: {result:?}"),
    }
}
fn tickets(config: Config, now: Duration) -> (Setup, gate::PathTicket, gate::PathTicket) {
    let setup = setup(config, peers()).expect("setup");
    let mut client = gate::ClientGate::new(setup.gate, gate::Secret::new([1; 32]), [4; 16], now)
        .expect("client gate");
    let mut server = gate::ServerGate::new(
        setup.gate,
        gate::Secret::new([1; 32]),
        gate::Secret::new([2; 32]),
        now,
    )
    .expect("server gate");
    let hello = client.poll(now).expect("hello poll").expect("hello");
    let gate::GateEvent::Retry(retry) = server
        .receive(setup.gate.path.client, &hello, [5; 16], now)
        .expect("retry")
    else {
        panic!("retry required");
    };
    let client_ticket = client
        .receive_retry(setup.gate.path.server, &retry, now)
        .expect("retry receive")
        .expect("client ticket");
    let echo = client.poll(now).expect("echo poll").expect("echo");
    let gate::GateEvent::Accepted(server_ticket) = server
        .receive(setup.gate.path.client, &echo, [6; 16], now)
        .expect("echo receive")
    else {
        panic!("server ticket required");
    };
    (setup, client_ticket, server_ticket)
}
#[tokio::test]
async fn tail_output_preflight_preserves_attempt_and_expiry_retires_wakes() {
    let (_client, _server, path) = pair().await;
    let config = config(
        path,
        cover::Appearance::QuicLike,
        hs::Role::Initiator,
        hs::Profile::Ik,
    );
    let (setup, ticket, _) = tickets(config, Duration::ZERO);
    let origin = Instant::now();
    let mut core = Core::new(
        setup,
        ticket,
        origin,
        origin + Duration::from_secs(1),
        Statistics::default(),
    )
    .expect("core");
    core.control
        .as_mut()
        .expect("control")
        .write(&[1; FRAME_BYTES], elapsed(origin, core.last).expect("time"))
        .expect("source");
    let mut tail = BootstrapTail {
        core,
        confirmation: None,
        peer_confirmation: [0; MAX_CONFIRM_BYTES],
        peer_confirmation_len: hs::PLAIN_CONFIRM_BYTES,
        parser: Parser::new(),
        peer: path.server,
    };
    let now = tail.core.last;
    assert!(matches!(
        tail.poll(now, metadata(0), &mut [0; 8]),
        Err(Error::OutputTooSmall)
    ));
    assert_eq!(
        tail.core
            .control
            .as_ref()
            .expect("control")
            .statistics()
            .transmitted_packets,
        0
    );
    let mut output = vec![0; tail.max_packet_bytes()];
    let length = tail
        .poll(now, metadata(0), &mut output)
        .expect("valid output")
        .expect("packet");
    let peer_cover = self::config(
        path,
        cover::Appearance::QuicLike,
        hs::Role::Responder,
        hs::Profile::Ik,
    )
    .cover;
    let decoded = peer_cover
        .decode(&output[..length])
        .expect("covered source");
    assert_eq!(
        &decoded.protected[21..29],
        &[0; 8],
        "first MAC packet number was not consumed on failure"
    );
    let end = tail.core.end;
    assert_eq!(
        tail.poll(end, metadata(1), &mut [])
            .expect("expiry precedes capacity"),
        None
    );
    assert!(tail.drained());
    assert!(tail.deadline().is_none());
    assert!(tail.core.control.is_none());
}

#[test]
fn transient_receive_errors_are_counted_and_fatal_socket_errors_stay_errors() {
    let mut statistics = Statistics::default();
    for kind in [
        io::ErrorKind::WouldBlock,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::NetworkDown,
    ] {
        assert!(path_loss(&io::Error::from(kind)));
        assert_eq!(
            received_length(Err(io::Error::from(kind)), &mut statistics)
                .expect("bounded path loss"),
            None
        );
    }
    assert_eq!(statistics.socket_receive_errors, 6);
    assert!(matches!(
        received_length(
            Err(io::Error::from(io::ErrorKind::InvalidInput)),
            &mut statistics
        ),
        Err(Error::Io(_))
    ));
    assert_eq!(statistics.socket_receive_errors, 6);
}
#[tokio::test]
async fn mismatched_pinned_context_never_releases_a_root() {
    let (client, server, path) = pair().await;
    let client_cfg = config(
        path,
        cover::Appearance::QuicLike,
        hs::Role::Initiator,
        hs::Profile::Ik,
    );
    let server_cfg = config(
        path,
        cover::Appearance::QuicLike,
        hs::Role::Responder,
        hs::Profile::Ik,
    );
    let mut bad_identity = identity(hs::Role::Initiator, hs::Profile::Ik);
    bad_identity.peer = hs::LocalSecret::new(Zeroizing::new([0x61; 32])).public_key();
    let server_identity = identity(hs::Role::Responder, hs::Profile::Ik);
    let pinned = peers();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    let mut admission = ServerAdmission::new(
        server_cfg,
        pinned,
        gate::Secret::new([1; 32]),
        gate::Secret::new([2; 32]),
        origin,
    )
    .expect("admission");
    let mut client_entropy = Entropy::new(9);
    let mut server_entropy = Entropy::new(19);
    let (client, server) = tokio::join!(
        connect(
            client,
            client_cfg,
            bad_identity,
            gate::Secret::new([1; 32]),
            end,
            &mut client_entropy
        ),
        accept(
            server,
            server_identity,
            &mut admission,
            end,
            &mut server_entropy
        )
    );
    assert!(
        matches!(&client, Err(Error::Deadline)) && matches!(&server, Err(Error::Deadline)),
        "wrong pins must remain quiet until the unchanged deadline; client={:?}, server={:?}",
        client.as_ref().err(),
        server.as_ref().err(),
    );
    assert_eq!(
        admission.statistics(),
        gate::GateStatistics::default(),
        "different pins change admission context before DH allocation"
    );
    assert_eq!(server_entropy.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn wrong_psk_fails_after_return_path_without_releasing_either_root() {
    let (client, server, path) = pair().await;
    let client_cfg = config(
        path,
        cover::Appearance::MediaLike,
        hs::Role::Initiator,
        hs::Profile::IkPsk2,
    );
    let server_cfg = config(
        path,
        cover::Appearance::MediaLike,
        hs::Role::Responder,
        hs::Profile::IkPsk2,
    );
    let mut bad_identity = identity(hs::Role::Initiator, hs::Profile::IkPsk2);
    bad_identity.psk = Some(hs::Psk::new(Zeroizing::new([99; 32])));
    let server_identity = identity(hs::Role::Responder, hs::Profile::IkPsk2);
    let pinned = peers();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    let mut admission = ServerAdmission::new(
        server_cfg,
        pinned,
        gate::Secret::new([1; 32]),
        gate::Secret::new([2; 32]),
        origin,
    )
    .expect("admission");
    let mut client_entropy = Entropy::new(29);
    let mut server_entropy = Entropy::new(39);
    let (client, server) = tokio::join!(
        connect(
            client,
            client_cfg,
            bad_identity,
            gate::Secret::new([1; 32]),
            end,
            &mut client_entropy
        ),
        accept(
            server,
            server_identity,
            &mut admission,
            end,
            &mut server_entropy
        )
    );
    assert!(
        client.is_err() && server.is_err(),
        "neither mismatched-PSK endpoint may release a root"
    );
    assert!(
        matches!(&client, Err(Error::Noise(hs::Error::Authentication)))
            || matches!(&server, Err(Error::Noise(hs::Error::Authentication))),
        "wrong PSK must actually reach Noise authentication; client={:?}, server={:?}",
        client.as_ref().err(),
        server.as_ref().err(),
    );
    assert_eq!(
        admission.statistics().retained_sessions,
        1,
        "failed authentication does not erase gate quarantine"
    );
}

#[tokio::test]
async fn every_bound_context_difference_is_rejected_before_noise() {
    for field in 0..4 {
        let (client, server, path) = pair().await;
        let mut client_cfg = config(
            path,
            cover::Appearance::QuicLike,
            hs::Role::Initiator,
            hs::Profile::Ik,
        );
        let server_cfg = config(
            path,
            cover::Appearance::QuicLike,
            hs::Role::Responder,
            hs::Profile::Ik,
        );
        match field {
            0 => client_cfg.binding.configuration[0] ^= 1,
            1 => client_cfg.binding.carrier[0] ^= 1,
            2 => client_cfg.binding.outer[0] ^= 1,
            _ => client_cfg.binding.member[0] ^= 1,
        }
        let client_identity = identity(hs::Role::Initiator, hs::Profile::Ik);
        let server_identity = identity(hs::Role::Responder, hs::Profile::Ik);
        let pinned = peers();
        let origin = Instant::now();
        let end = origin + Duration::from_secs(2);
        let mut admission = ServerAdmission::new(
            server_cfg,
            pinned,
            gate::Secret::new([1; 32]),
            gate::Secret::new([2; 32]),
            origin,
        )
        .expect("admission");
        let mut client_entropy = Entropy::new(49);
        let mut server_entropy = Entropy::new(59);
        let (client, server) = tokio::join!(
            connect(
                client,
                client_cfg,
                client_identity,
                gate::Secret::new([1; 32]),
                end,
                &mut client_entropy
            ),
            accept(
                server,
                server_identity,
                &mut admission,
                end,
                &mut server_entropy
            )
        );
        assert!(
            matches!(&client, Err(Error::Deadline)) && matches!(&server, Err(Error::Deadline)),
            "bound context field {field} must remain quiet; client={:?}, server={:?}",
            client.as_ref().err(),
            server.as_ref().err(),
        );
        assert_eq!(admission.statistics(), gate::GateStatistics::default());
        assert_eq!(server_entropy.calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn authenticated_bad_tail_grammar_retires_but_bad_mac_does_not() {
    for header in [[1, 1, 0, 96], [1, 3, 0, 72], [2, 3, 0, 73]] {
        let (_client, _server, path) = pair().await;
        let client_cfg = config(
            path,
            cover::Appearance::MediaLike,
            hs::Role::Initiator,
            hs::Profile::Ik,
        );
        let server_cfg = config(
            path,
            cover::Appearance::MediaLike,
            hs::Role::Responder,
            hs::Profile::Ik,
        );
        let (setup, client_ticket, server_ticket) = tickets(client_cfg, Duration::ZERO);
        let origin = Instant::now();
        let core = Core::new(
            setup,
            client_ticket,
            origin,
            origin + Duration::from_secs(1),
            Statistics::default(),
        )
        .expect("client core");
        let now = core.last;
        let mut tail = BootstrapTail {
            core,
            confirmation: None,
            peer_confirmation: [0; MAX_CONFIRM_BYTES],
            peer_confirmation_len: hs::PLAIN_CONFIRM_BYTES,
            parser: Parser::new(),
            peer: path.server,
        };
        let mut control =
            gate::ControlEngine::new(server_ticket, elapsed(origin, now).expect("time"))
                .expect("server control");
        let mut frame = [0; FRAME_BYTES];
        frame[..4].copy_from_slice(&header);
        control
            .write(&frame, elapsed(origin, now).expect("time"))
            .expect("bad source");
        let mut body = vec![0; 1 + control.max_datagram_bytes()];
        body[0] = CONTROL_TAG;
        let length = control
            .poll(elapsed(origin, now).expect("time"), &mut body[1..])
            .expect("poll")
            .expect("source");
        body.truncate(1 + length);
        let mut wire = vec![0; client_cfg.cover.limits().max_packet_bytes];
        let length = server_cfg
            .cover
            .encode(metadata(0), &body, &mut wire)
            .expect("cover");
        wire[length - 1] ^= 1;
        assert!(
            !tail
                .receive(
                    client_cfg
                        .cover
                        .decode(&wire[..length])
                        .expect("bad MAC cover"),
                    now
                )
                .expect("bad MAC ignored")
        );
        assert!(tail.core.control.is_some());
        wire[length - 1] ^= 1;
        assert!(matches!(
            tail.receive(
                client_cfg
                    .cover
                    .decode(&wire[..length])
                    .expect("valid cover"),
                now
            ),
            Err(Error::Protocol)
        ));
        assert!(tail.core.control.is_none());
        assert!(tail.confirmation.is_none());
        assert!(tail.deadline().is_none());
    }
}

#[tokio::test]
async fn terminal_retry_exhaustion_retires_real_noise_final_custody() {
    let (client, server, path) = pair().await;
    let mut client_cfg = config(
        path,
        cover::Appearance::MediaLike,
        hs::Role::Initiator,
        hs::Profile::Ik,
    );
    let mut server_cfg = config(
        path,
        cover::Appearance::MediaLike,
        hs::Role::Responder,
        hs::Profile::Ik,
    );
    for config in [&mut client_cfg, &mut server_cfg] {
        config.gate.arq.initial_rto = Duration::from_millis(100);
        config.gate.arq.maximum_rto = Duration::from_millis(100);
        config.gate.arq.max_retries = 0;
    }
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    let mut admission = ServerAdmission::new(
        server_cfg,
        peers(),
        gate::Secret::new([1; 32]),
        gate::Secret::new([2; 32]),
        origin,
    )
    .expect("admission");
    let mut client_entropy = Entropy::new(29);
    let mut server_entropy = Entropy::new(39);
    let (client, server) = tokio::join!(
        connect(
            client,
            client_cfg,
            identity(hs::Role::Initiator, hs::Profile::Ik),
            gate::Secret::new([1; 32]),
            end,
            &mut client_entropy,
        ),
        accept(
            server,
            identity(hs::Role::Responder, hs::Profile::Ik),
            &mut admission,
            end,
            &mut server_entropy,
        )
    );
    let mut client = client.expect("client Noise completion");
    let server = server.expect("server Noise completion");
    assert_eq!(client.binding, server.binding);
    let now = Instant::now();
    let mut frame = [0; FRAME_BYTES];
    frame[..4].copy_from_slice(&[1, 3, 0, hs::PLAIN_CONFIRM_BYTES as u8]);
    let flight = client
        .tail
        .confirmation
        .as_mut()
        .expect("actual final Noise ciphertext cache")
        .retransmit(
            hs_time(client.tail.core.origin, now).expect("handshake time"),
            &mut frame[4..],
        )
        .expect("copy exact ciphertext without crypto");
    assert_eq!(flight.bytes, hs::PLAIN_CONFIRM_BYTES);
    assert_eq!(
        client
            .tail
            .core
            .control
            .as_mut()
            .expect("live bootstrap owner")
            .write(
                &frame[..4 + flight.bytes],
                elapsed(client.tail.core.origin, now).expect("control time"),
            )
            .expect("retain exact final flight"),
        4 + hs::PLAIN_CONFIRM_BYTES,
    );
    let mut output = vec![0; client.tail.max_packet_bytes()];
    let mut attempts = 0;
    while client
        .tail
        .poll(now, metadata(client.next_outer), &mut output)
        .expect("first bounded attempt")
        .is_some()
    {
        attempts += 1;
        advance(&mut client.next_outer).expect("outer counter");
        // Deliberately withhold physical handoff: retained ARQ must exhaust.
    }
    assert!(attempts > 0);
    assert!(client.tail.confirmation.is_some());
    let due = now + client_cfg.gate.arq.initial_rto;
    assert!(due < client.tail.core.end);
    assert!(matches!(
        client
            .tail
            .poll(due, metadata(client.next_outer), &mut output),
        Err(Error::Gate(gate::Error::Recovery(
            l2tunnel_recovery::RecoveryError::RetryExhausted { .. }
        )))
    ));
    assert!(client.tail.core.control.is_none());
    assert!(client.tail.confirmation.is_none());
    assert!(client.tail.deadline().is_none());
    assert!(client.tail.drained());
    assert_eq!(
        client
            .tail
            .poll(due + Duration::from_millis(1), metadata(0), &mut [])
            .expect("retired owner has no work or wake"),
        None,
    );
}

#[path = "establish_tuning_tests.rs"]
mod tuning;
