//! Test-only bounded transport bridge; this is not the standalone production runtime.
use super::*;
use l2tunnel_udp_control::{
    ClientGate, Config, ControlEngine, ControlStatistics, GateEvent, Path, Secret as GateSecret,
    ServerGate,
};
use tokio::{
    io::DuplexStream,
    net::UdpSocket,
    sync::watch,
    time::{Instant, MissedTickBehavior, interval},
};

#[derive(Default)]
struct BridgeStatistics {
    control: ControlStatistics,
    drops: usize,
    delays: usize,
    duplicates: usize,
}

/// One actor owns one engine/socket and finite duplex buffers. Reads/writes use
/// separate retained prefixes so a blocked TLS consumer never stalls UDP ACKs.
async fn bridge(
    mut engine: ControlEngine,
    socket: UdpSocket,
    peer: SocketAddr,
    io: DuplexStream,
    mut stop: watch::Receiver<bool>,
) -> Result<BridgeStatistics, TestError> {
    let started = Instant::now();
    let mut timer = interval(Duration::from_millis(1));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let (mut input, mut output) = tokio::io::split(io);
    let mut udp_input = vec![0; engine.max_datagram_bytes() + 1];
    let mut udp_output = vec![0; engine.max_datagram_bytes()];
    let mut from_tls = vec![0; 4096];
    let mut to_tls = vec![0; 4096];
    let (mut from_start, mut from_end, mut to_start, mut to_end) = (0, 0, 0, 0);
    let mut input_closed = false;
    let mut delayed = None::<(Duration, Vec<u8>)>;
    let mut count = 0_usize;
    let mut statistics = BridgeStatistics::default();
    loop {
        tokio::select! {
            changed = stop.changed() => {
                changed?;
                if *stop.borrow() { statistics.control = engine.statistics(); return Ok(statistics); }
            }
            result = input.read(&mut from_tls), if !input_closed && from_start == from_end => {
                from_end = result?; from_start = 0; input_closed = from_end == 0;
            }
            result = output.write(&to_tls[to_start..to_end]), if to_start != to_end => {
                let written = result?;
                if written == 0 { return Err("zero TLS bridge write".into()); }
                to_start += written;
            }
            result = socket.recv_from(&mut udp_input) => {
                let (length, source) = result?;
                engine.receive(source, &udp_input[..length], started.elapsed())?;
            }
            _ = timer.tick() => {}
        }
        let now = started.elapsed();
        if from_start != from_end {
            from_start += engine.write(&from_tls[from_start..from_end], now)?;
        }
        if to_start == to_end {
            to_start = 0;
            to_end = engine.read(&mut to_tls, now)?;
        }
        if delayed.as_ref().is_some_and(|(due, _)| now >= *due) {
            let (_, bytes) = delayed.take().ok_or("missing delayed datagram")?;
            if socket.send_to(&bytes, peer).await? != bytes.len() {
                return Err("partial UDP".into());
            }
        }
        for _ in 0..8 {
            let Some(length) = engine.poll(now, &mut udp_output)? else {
                break;
            };
            count += 1;
            if count.is_multiple_of(7) {
                statistics.drops += 1;
                continue;
            }
            if count.is_multiple_of(9) && delayed.is_none() {
                delayed = Some((
                    now + Duration::from_millis(12),
                    udp_output[..length].to_vec(),
                ));
                statistics.delays += 1;
                continue;
            }
            if socket.send_to(&udp_output[..length], peer).await? != length {
                return Err("partial UDP".into());
            }
            if count.is_multiple_of(11) {
                if socket.send_to(&udp_output[..length], peer).await? != length {
                    return Err("partial duplicate UDP".into());
                }
                statistics.duplicates += 1;
            }
        }
    }
}

/// Gate frames also traverse real UDP; fault injection starts on retained control.
async fn admitted_udp()
-> Result<(ControlEngine, ControlEngine, UdpSocket, UdpSocket, Config), TestError> {
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let config = Config::new(
        Path {
            client: client_socket.local_addr()?,
            server: server_socket.local_addr()?,
        },
        [0x53; 32],
        11,
    )?;
    let mut client = ClientGate::new(config, GateSecret::new([1; 32]), [2; 16], Duration::ZERO)?;
    let mut server = ServerGate::new(
        config,
        GateSecret::new([1; 32]),
        GateSecret::new([3; 32]),
        Duration::ZERO,
    )?;
    let mut frame = [0; 145];
    client_socket
        .send_to(
            &client.poll(Duration::ZERO)?.ok_or("Hello")?,
            config.path.server,
        )
        .await?;
    let (length, peer) = server_socket.recv_from(&mut frame).await?;
    let GateEvent::Retry(retry) =
        server.receive(peer, &frame[..length], [4; 16], Duration::ZERO)?
    else {
        return Err("Retry".into());
    };
    server_socket.send_to(&retry, config.path.client).await?;
    let (length, peer) = client_socket.recv_from(&mut frame).await?;
    let a = client
        .receive_retry(peer, &frame[..length], Duration::ZERO)?
        .ok_or("client ticket")?;
    client_socket
        .send_to(
            &client.poll(Duration::ZERO)?.ok_or("Echo")?,
            config.path.server,
        )
        .await?;
    let (length, peer) = server_socket.recv_from(&mut frame).await?;
    let GateEvent::Accepted(b) = server.receive(peer, &frame[..length], [5; 16], Duration::ZERO)?
    else {
        return Err("server ticket".into());
    };
    assert_eq!(server.statistics().response_bytes, 144);
    Ok((
        ControlEngine::new(a, Duration::ZERO)?,
        ControlEngine::new(b, Duration::ZERO)?,
        client_socket,
        server_socket,
        config,
    ))
}

#[tokio::test]
async fn actual_tls_member_exchange_over_lossy_reordered_duplicate_udp_without_tcp() -> TestResult {
    let (a, b, socket_a, socket_b, gate) =
        timeout(Duration::from_secs(2), admitted_udp()).await??;
    let (client_io, a_io) = tokio::io::duplex(4096);
    let (server_io, b_io) = tokio::io::duplex(4096);
    let (stop, stopped) = watch::channel(false);
    let a_task = tokio::spawn(bridge(a, socket_a, gate.path.server, a_io, stopped.clone()));
    let b_task = tokio::spawn(bridge(b, socket_b, gate.path.client, b_io, stopped));
    let result: Result<(), TestError> = async {
        let (client_tls, server_tls) = fixture()?;
        let member = member()?;
        let members = MemberAllowlist::new(&[member.public_key()])?;
        let cfg = SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest(gate.profile_digest()?),
        };
        let deadline = Duration::from_secs(15);
        let (client, server) = tokio::join!(
            client_connect_profile_io(
                client_io,
                &client_tls,
                "tunnel.test",
                &member,
                cfg,
                TlsIoProfile::OpenVpnLikeTls,
                deadline
            ),
            server_accept_profile_io(
                server_io,
                &server_tls,
                &members,
                cfg,
                TlsIoProfile::OpenVpnLikeTls,
                deadline
            ),
        );
        let mut client = client?;
        let mut server = server?;
        assert_eq!(client.info().session_id, server.info().session_id);
        assert_eq!(client.profile(), TlsIoProfile::OpenVpnLikeTls);
        match &server.stream {
            TlsStream::Server(tls) => assert_eq!(tls.get_ref().1.server_name(), None),
            TlsStream::Client(_) => return Err("server TLS type".into()),
        }
        assert_eq!(
            client
                .export_key(KeyPurpose::Data, Direction::ClientToServer, 0)?
                .expose_bytes(),
            server
                .export_key(KeyPurpose::Data, Direction::ClientToServer, 0)?
                .expose_bytes()
        );
        let forward: Vec<_> = (0..32_768).map(|i| (i * 31 + 5) as u8).collect();
        let reverse: Vec<_> = (0..24_576).map(|i| (i * 17 + 9) as u8).collect();
        let (mut cr, mut cw) = tokio::io::split(&mut client);
        let (mut sr, mut sw) = tokio::io::split(&mut server);
        let mut got_forward = vec![0; forward.len()];
        let mut got_reverse = vec![0; reverse.len()];
        timeout(Duration::from_secs(15), async {
            tokio::try_join!(
                async {
                    cw.write_all(&forward).await?;
                    cw.flush().await
                },
                async {
                    sw.write_all(&reverse).await?;
                    sw.flush().await
                },
                async { sr.read_exact(&mut got_forward).await.map(|_| ()) },
                async { cr.read_exact(&mut got_reverse).await.map(|_| ()) },
            )
        })
        .await??;
        assert_eq!(got_forward, forward);
        assert_eq!(got_reverse, reverse);
        Ok(())
    }
    .await;
    stop.send(true)?;
    let a = a_task.await??;
    let b = b_task.await??;
    result?;
    for stats in [a, b] {
        assert!(stats.drops > 0 && stats.delays > 0 && stats.duplicates > 0);
        assert!(stats.control.received_packets > 0);
        assert!(stats.control.transmitted_ip_bytes > 0);
        assert!(stats.control.replay_packets > 0);
    }
    Ok(())
}
