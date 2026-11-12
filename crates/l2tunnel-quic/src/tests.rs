use super::*;
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use std::time::Duration;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
fn base(layer: PacketLayer) -> SessionConfig {
    SessionConfig {
        layer,
        digest: ConfigDigest([7; 32]),
    }
}
fn profile() -> Profile {
    Profile::new(*b"test-opaque-id01")
}
fn fixture(
    p: Profile,
    limits: EndpointLimits,
) -> Result<(ClientEndpoint, ServerEndpoint, MemberKey, MemberAllowlist), TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client = ClientConfig::from_der_roots(&chain, p, limits)?;
    let server = ServerConfig::from_der(&chain, &cert.signing_key.serialize_der(), p, limits)?;
    let key = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[key.public_key()])?;
    Ok((
        ClientEndpoint::bind("127.0.0.1:0".parse()?, &client)?,
        ServerEndpoint::bind("127.0.0.1:0".parse()?, &server)?,
        key,
        members,
    ))
}
async fn pair(
    p: Profile,
    layer: PacketLayer,
) -> Result<(AuthenticatedConnection, AuthenticatedConnection), TestError> {
    let (client, server, key, members) = fixture(p, EndpointLimits::default())?;
    let (a, b) = tokio::join!(
        client.connect(server.local_addr()?, "quic.test", &key, base(layer)),
        server.accept(&members, base(layer))
    );
    Ok((a?, b?))
}

#[tokio::test]
async fn genuine_udp_only_full_and_half_tap_tun_auth_control_and_datagrams() -> TestResult {
    for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
        for traffic in [
            Traffic::FullDuplex,
            Traffic::HalfDuplex {
                sender: Direction::ClientToServer,
            },
            Traffic::HalfDuplex {
                sender: Direction::ServerToClient,
            },
        ] {
            let mut p = profile();
            p.traffic = traffic;
            let (a, b) = pair(p, layer).await?;
            assert_eq!(a.info().session_id, b.info().session_id);
            assert_eq!(a.info().config, session_config(base(layer), p)?);
            assert!(a.info().peer_member.is_none());
            assert_eq!(b.info().peer_member, Some(a.info().member));
            let (mut ac, mut at, mut ar) = a.into_parts();
            let (mut bc, mut bt, mut br) = b.into_parts();
            ac.write_all(b"control-a").await?;
            let mut control = [0; 9];
            bc.read_exact(&mut control).await?;
            assert_eq!(&control, b"control-a");
            bc.write_all(b"control-b").await?;
            ac.read_exact(&mut control).await?;
            assert_eq!(&control, b"control-b");
            let mut payload = vec![0; p.max_datagram_bytes];
            if traffic.allows(Direction::ClientToServer) {
                assert_eq!(at.send(b"a-native").await?, 0);
                assert_eq!(
                    br.receive(&mut payload).await?,
                    Received::Packet {
                        len: 8,
                        sequence: 0
                    }
                );
                assert_eq!(&payload[..8], b"a-native");
            } else {
                assert!(matches!(at.send(b"x").await, Err(Error::Direction)));
                assert!(matches!(
                    br.receive(&mut payload).await,
                    Err(Error::Direction)
                ));
            }
            if traffic.allows(Direction::ServerToClient) {
                assert_eq!(bt.send(b"b-native").await?, 0);
                assert_eq!(
                    ar.receive(&mut payload).await?,
                    Received::Packet {
                        len: 8,
                        sequence: 0
                    }
                );
                assert_eq!(&payload[..8], b"b-native");
            } else {
                assert!(matches!(bt.send(b"x").await, Err(Error::Direction)));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn wrong_server_name_roots_member_layer_digest_lane_and_alpn_fail_closed() -> TestResult {
    for mismatch in 0..7 {
        let p = profile();
        let limits = EndpointLimits {
            handshake_timeout: Duration::from_secs(1),
            ..EndpointLimits::default()
        };
        let (mut client, server, mut key, members) = fixture(p, limits)?;
        let mut cfg = base(PacketLayer::Ip);
        let mut name = "quic.test";
        match mismatch {
            0 => name = "wrong.test",
            1 => {
                let other = rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()])?;
                let replacement =
                    ClientConfig::from_der_roots(&[other.cert.der().to_vec()], p, limits)?;
                client = ClientEndpoint::bind("127.0.0.1:0".parse()?, &replacement)?;
            }
            2 => key = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?,
            3 => cfg.layer = PacketLayer::Ethernet,
            4 => cfg.digest.0[0] ^= 1,
            5 => client.config.profile.lane = 1,
            6 => {
                let mut changed = server.config.profile;
                changed.application_id[0] ^= 1;
                client.config.profile = changed;
            }
            _ => unreachable_case()?,
        }
        // Case 6 changes the auth-bound expected ALPN while retaining the actual negotiated one.
        let (a, b) = tokio::join!(
            client.connect(server.local_addr()?, name, &key, cfg),
            server.accept(&members, base(PacketLayer::Ip))
        );
        assert!(a.is_err(), "case {mismatch}");
        assert!(b.is_err(), "case {mismatch}");
    }
    Ok(())
}
fn unreachable_case() -> TestResult {
    Err("unreachable test case".into())
}

#[tokio::test]
async fn datagram_binding_replay_limits_direction_and_control_drop() -> TestResult {
    let (a, b) = pair(profile(), PacketLayer::Ip).await?;
    let (ac, mut at, mut ar) = a.into_parts();
    let (_bc, _bt, mut br) = b.into_parts();
    let mut out = vec![0; profile().max_datagram_bytes];
    assert!(matches!(at.send(&[]).await, Err(Error::Size)));
    assert!(matches!(
        at.send(&vec![0; profile().max_datagram_bytes + 1]).await,
        Err(Error::Size)
    ));
    assert!(matches!(br.receive(&mut [0; 4]).await, Err(Error::Size)));
    let packet = encode_datagram(&at.session, &at.token, 0, b"valid")?;
    for index in [0, 4, 5, 6, 8, 24] {
        let mut bad = packet.clone();
        bad[index] ^= 1;
        assert_eq!(br.admit(&bad, &mut out), Received::Discarded);
    }
    for length in 0..packet.len() {
        assert_eq!(br.admit(&packet[..length], &mut out), Received::Discarded);
    }
    assert_eq!(
        br.admit(&packet, &mut out),
        Received::Packet {
            len: 5,
            sequence: 0
        }
    );
    assert_eq!(br.admit(&packet, &mut out), Received::Discarded);
    let high = encode_datagram(&at.session, &at.token, 130, b"new")?;
    assert!(matches!(
        br.admit(&high, &mut out),
        Received::Packet { sequence: 130, .. }
    ));
    assert_eq!(br.admit(&packet, &mut out), Received::Discarded);
    let reordered = encode_datagram(&at.session, &at.token, 129, b"reordered")?;
    assert!(matches!(
        br.admit(&reordered, &mut out),
        Received::Packet { sequence: 129, .. }
    ));
    at.next = Some(u64::MAX);
    assert_eq!(at.send(b"last").await?, u64::MAX);
    assert!(matches!(at.send(b"overflow").await, Err(Error::Exhausted)));
    drop(ac);
    assert!(matches!(ar.receive(&mut out).await, Err(Error::Transport)));
    assert!(matches!(at.send(b"closed").await, Err(Error::Transport)));
    Ok(())
}

#[test]
fn canonical_profile_and_finite_construction_bounds() -> TestResult {
    let p = profile();
    let cfg = session_config(base(PacketLayer::Ip), p)?;
    for field in 0..9 {
        let mut changed = p;
        match field {
            0 => changed.application_id[0] ^= 1,
            1 => {
                changed.traffic = Traffic::HalfDuplex {
                    sender: Direction::ClientToServer,
                }
            }
            2 => changed.lane += 1,
            3 => changed.max_datagram_bytes -= 1,
            4 => changed.queued_datagrams += 1,
            5 => changed.control_window_bytes += 1,
            6 => changed.udp_payload_ceiling += 1,
            7 => changed.idle_timeout += Duration::from_nanos(1),
            8 => changed.io_timeout += Duration::from_nanos(1),
            _ => return Err("test field".into()),
        }
        assert_ne!(cfg, session_config(base(PacketLayer::Ip), changed)?);
    }
    for field in 0..7 {
        let mut bad = p;
        match field {
            0 => bad.application_id = [0; 16],
            1 => bad.udp_payload_ceiling = 1199,
            2 => bad.max_datagram_bytes = usize::MAX,
            3 => bad.queued_datagrams = usize::MAX,
            4 => bad.control_window_bytes = usize::MAX,
            5 => bad.idle_timeout = Duration::ZERO,
            6 => bad.io_timeout = Duration::from_secs(121),
            _ => return Err("test bound".into()),
        }
        assert!(bad.validate().is_err());
    }
    Ok(())
}

async fn raw_connect(
    client: &ClientEndpoint,
    server: &ServerEndpoint,
) -> Result<(quinn::Connection, Stream), TestError> {
    let connection = client
        .endpoint
        .connect(server.local_addr()?, "quic.test")?
        .await?;
    let (send, recv) = connection.open_bi().await?;
    Ok((connection, Stream { send, recv }))
}

#[tokio::test]
async fn malformed_control_timeout_and_cancellation_close_preauth_connections() -> TestResult {
    for malformed in [false, true] {
        let limits = EndpointLimits {
            handshake_timeout: Duration::from_millis(100),
            ..EndpointLimits::default()
        };
        let (client, server, _key, members) = fixture(profile(), limits)?;
        let attack = async {
            let (connection, mut stream) = raw_connect(&client, &server).await?;
            if malformed {
                stream.write_all(b"BAD!\0\0\0\0").await?;
            }
            timeout(Duration::from_secs(1), connection.closed()).await?;
            Ok::<_, TestError>(())
        };
        let (attack, result) = tokio::join!(attack, server.accept(&members, base(PacketLayer::Ip)));
        attack?;
        if malformed {
            assert!(matches!(result, Err(Error::Protocol(_))));
        } else {
            assert!(matches!(result, Err(Error::TimedOut)));
        }
    }
    let (client, server, _key, members) = fixture(profile(), EndpointLimits::default())?;
    let address = server.local_addr()?;
    let task = tokio::spawn(async move { server.accept(&members, base(PacketLayer::Ip)).await });
    let connection = client.endpoint.connect(address, "quic.test")?.await?;
    let (mut send, _recv) = connection.open_bi().await?;
    send.write_all(PRELUDE).await?;
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.is_err());
    timeout(Duration::from_secs(1), connection.closed()).await?;
    Ok(())
}

struct Recording {
    stream: Stream,
    written: Vec<u8>,
}
impl AsyncRead for Recording {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Recording {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = &result {
            self.written.extend_from_slice(&buf[..*count]);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn preauth_datagrams_are_discarded_and_captured_proof_fails_new_quic_session() -> TestResult {
    let (client, server, key, members) = fixture(profile(), EndpointLimits::default())?;
    let raw = async {
        let (connection, mut stream) = raw_connect(&client, &server).await?;
        connection.send_datagram(Bytes::from(vec![0; HEADER + 10]))?;
        let binding = channel_binding(&connection, server.config.identity)?;
        stream.write_all(PRELUDE).await?;
        let mut recording = Recording {
            stream,
            written: Vec::new(),
        };
        let info = auth::client_authenticate_channel(
            &mut recording,
            &key,
            session_config(base(PacketLayer::Ip), profile())?,
            &binding,
            Duration::from_secs(2),
        )
        .await?;
        let _tokens = client_gate(&mut recording.stream, info.session_id).await?;
        Ok::<_, TestError>((connection, recording))
    };
    let (raw, accepted) = tokio::join!(raw, server.accept(&members, base(PacketLayer::Ip)));
    let (_first, recording) = raw?;
    let (_control, _send, mut receive) = accepted?.into_parts();
    let mut out = vec![0; profile().max_datagram_bytes];
    assert_eq!(receive.receive(&mut out).await?, Received::Discarded);
    assert_eq!(&recording.written[..4], b"L2AU");
    let proof = recording.written[..169].to_vec();
    let attack = async {
        let (connection, mut stream) = raw_connect(&client, &server).await?;
        stream.write_all(PRELUDE).await?;
        let mut challenge = [0; 121];
        stream.read_exact(&mut challenge).await?;
        assert_eq!(&challenge[..4], b"L2AU");
        stream.write_all(&proof).await?;
        timeout(Duration::from_secs(1), connection.closed()).await?;
        Ok::<_, TestError>(())
    };
    let (attack, result) = tokio::join!(attack, server.accept(&members, base(PacketLayer::Ip)));
    attack?;
    assert!(matches!(
        result,
        Err(Error::Authentication(auth::Error::InvalidProof))
    ));
    Ok(())
}

#[tokio::test]
async fn local_capacity_retained_handles_deadlines_and_zero_sized_control_read() -> TestResult {
    let mut p = profile();
    p.io_timeout = Duration::from_millis(20);
    let limits = EndpointLimits {
        max_connections: 1,
        ..EndpointLimits::default()
    };
    let (client, server, key, members) = fixture(p, limits)?;
    let (a, b) = tokio::join!(
        client.connect(
            server.local_addr()?,
            "quic.test",
            &key,
            base(PacketLayer::Ip)
        ),
        server.accept(&members, base(PacketLayer::Ip))
    );
    let (mut ac, mut at, mut ar) = a?.into_parts();
    let (bc, bt, br) = b?.into_parts();
    assert!(matches!(
        client
            .connect(
                server.local_addr()?,
                "quic.test",
                &key,
                base(PacketLayer::Ip)
            )
            .await,
        Err(Error::Capacity)
    ));
    assert_eq!(ac.read(&mut []).await?, 0);
    at.send(b"still-open").await?;
    let mut out = vec![0; p.max_datagram_bytes];
    assert!(matches!(ar.receive(&mut out).await, Err(Error::TimedOut)));
    drop(ac);
    drop(bc);
    drop(bt);
    drop(br);
    assert!(matches!(
        client
            .connect(
                server.local_addr()?,
                "quic.test",
                &key,
                base(PacketLayer::Ip)
            )
            .await,
        Err(Error::Capacity)
    ));
    drop(at);
    drop(ar);
    let (a, b) = tokio::join!(
        client.connect(
            server.local_addr()?,
            "quic.test",
            &key,
            base(PacketLayer::Ip)
        ),
        server.accept(&members, base(PacketLayer::Ip))
    );
    a?;
    b?;
    Ok(())
}

#[tokio::test]
async fn exact_alpn_mismatch_is_rejected_by_tls_and_control_window_backpressures() -> TestResult {
    let cert = rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let p = profile();
    let mut other = p;
    other.application_id[0] ^= 1;
    let limits = EndpointLimits::default();
    let client = ClientEndpoint::bind(
        "127.0.0.1:0".parse()?,
        &ClientConfig::from_der_roots(&chain, other, limits)?,
    )?;
    let server = ServerEndpoint::bind(
        "127.0.0.1:0".parse()?,
        &ServerConfig::from_der(&chain, &cert.signing_key.serialize_der(), p, limits)?,
    )?;
    let key = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[key.public_key()])?;
    let (a, b) = tokio::join!(
        client.connect(
            server.local_addr()?,
            "quic.test",
            &key,
            base(PacketLayer::Ip)
        ),
        server.accept(&members, base(PacketLayer::Ip))
    );
    assert!(a.is_err());
    assert!(b.is_err());

    let mut p = p;
    p.queued_datagrams = 1;
    p.control_window_bytes = 1024;
    let (a, b) = pair(p, PacketLayer::Ip).await?;
    let (mut ac, mut at, _ar) = a.into_parts();
    let (_bc, _bt, mut br) = b.into_parts();
    let maximum = vec![0x45; p.max_datagram_bytes];
    at.send(&maximum).await?;
    let mut output = vec![0; p.max_datagram_bytes];
    assert!(
        matches!(br.receive(&mut output).await?,Received::Packet{len,..} if len == maximum.len())
    );
    assert_eq!(output, maximum);
    assert!(
        timeout(
            Duration::from_millis(30),
            ac.write_all(&vec![0; 1024 * 1024])
        )
        .await
        .is_err()
    );
    // The cancelled write may have emitted a prefix; callers own control framing.
    Ok(())
}

#[tokio::test]
async fn observed_control_eof_closes_data_and_unreachable_udp_has_total_deadline() -> TestResult {
    let (a, b) = pair(profile(), PacketLayer::Ip).await?;
    let (mut ac, mut at, _ar) = a.into_parts();
    let (mut bc, _bt, _br) = b.into_parts();
    // Exercise actual stream FIN without the public shutdown's whole-session close.
    bc.stream.send.finish()?;
    assert_eq!(
        timeout(Duration::from_secs(1), ac.read(&mut [0; 1])).await??,
        0
    );
    assert!(matches!(at.send(b"after-fin").await, Err(Error::Transport)));
    let limits = EndpointLimits {
        handshake_timeout: Duration::from_millis(40),
        ..EndpointLimits::default()
    };
    let (client, _server, key, _members) = fixture(profile(), limits)?;
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    assert!(matches!(
        client
            .connect(
                silent.local_addr()?,
                "quic.test",
                &key,
                base(PacketLayer::Ip)
            )
            .await,
        Err(Error::TimedOut)
    ));
    assert_eq!(client.permits.available_permits(), limits.max_connections);
    Ok(())
}
