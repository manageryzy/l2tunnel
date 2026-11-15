//! Actual TLS -> cookie/Noise -> member -> selected Records on one UDP tuple.
use super::*;
use establish::carrier::{self as factory, Outer};
use l2tunnel::{handshake as hs, secure_record as record};
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_openvpn::{
    WireBudget,
    wire_carrier::{ClientCredentials, ServerCredentials, common as openvpn},
};
use l2tunnel_udp_control as gate;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;

#[path = "member_carrier_initial_tests.rs"]
pub(in crate::secure_udp) mod initial;

struct Entropy(u8);
impl hs::Entropy for Entropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> Result<(), hs::EntropyError> {
        output.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}
struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: MemberKey,
    inner: identity::IdentityKey,
    members: MemberAllowlist,
}
fn credentials() -> TestResult<Credentials> {
    let certificate = rcgen::generate_simple_self_signed(vec!["carrier-factory.test".to_owned()])?;
    let roots = vec![certificate.cert.der().to_vec()];
    let encoded = MemberKey::generate_pkcs8()?;
    let member = MemberKey::from_pkcs8(&encoded)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    Ok(Credentials {
        client: ClientTls::from_der_roots(&roots)?,
        server: ServerTls::from_der(&roots, &certificate.signing_key.serialize_der())?,
        inner: identity::IdentityKey::from_pkcs8(&encoded)?,
        member,
        members,
    })
}
pub(in crate::secure_udp) fn outer_config() -> openvpn::Config {
    openvpn::Config {
        base: l2tunnel_auth::SessionConfig {
            layer: l2tunnel_device::PacketLayer::Ip,
            digest: l2tunnel_core::ConfigDigest([7; 32]),
        },
        path_mtu: 1280,
        outer_overhead_bytes: 29,
        max_record_bytes: 1024,
        control_arq: l2tunnel_recovery::ArqConfig {
            max_source_bytes: 512,
            send_bytes: 4096,
            receive_bytes: 4096,
            send_records: 8,
            receive_records: 8,
            initial_rto: Duration::from_millis(20),
            maximum_rto: Duration::from_millis(200),
            ack_delay: Duration::from_millis(1),
            max_retries: 8,
        },
        handshake_timeout: Duration::from_secs(3),
        lifetime: Duration::from_secs(10),
        packet_slots: 8,
        stream_bytes: 16384,
        poll_interval: Duration::from_millis(1),
        work_limit: 16,
        wire_budget: WireBudget {
            interval: Duration::from_millis(10),
            packets: 32,
            ip_bytes: 40960,
            reserved_control_packets: 4,
            reserved_control_bytes: 5120,
            maximum_control_packets: 16,
        },
    }
}
async fn sockets() -> io::Result<(UdpSocket, UdpSocket)> {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    a.connect(b.local_addr()?).await?;
    b.connect(a.local_addr()?).await?;
    Ok((a, b))
}
fn local(client: bool) -> hs::LocalSecret {
    hs::LocalSecret::new(Zeroizing::new([if client { 11 } else { 22 }; 32]))
}
fn peers() -> establish::Peers {
    establish::Peers {
        initiator: local(true).public_key(),
        responder: local(false).public_key(),
    }
}
fn noise(client: bool) -> establish::Identity {
    establish::Identity {
        local: local(client),
        peer: if client {
            peers().responder
        } else {
            peers().initiator
        },
        psk: Some(hs::Psk::new(Zeroizing::new([9; 32]))),
    }
}
fn selected() -> TestResult<hs::refresh::Selection> {
    Ok(hs::refresh::Selection::new(hs::refresh::SelectionSpec {
        lane: security::LaneId(3),
        limits: security::Limits {
            max_body_bytes: 256,
            packets_per_key: security::MAX_PACKETS_PER_KEY,
            max_body_bytes_per_key: security::MAX_BODY_BYTES_PER_KEY,
        },
        protection: security::Protection::ChaCha20Poly1305,
        control_epoch: security::Epoch(4),
        control_digest: security::ConfigDigest([19; 32]),
        envelope_digest: security::ConfigDigest([20; 32]),
        exchange_micros: 1_000_000,
        key_micros: 5_000_000,
        overlap_micros: 1_000,
        max_flight_copies: 8,
    })?)
}
pub(in crate::secure_udp) fn effective(
    outer: &factory::AuthenticatedOuter,
    client: bool,
) -> Result<establish::Config, establish::Error> {
    let (a, b) = outer.endpoints();
    let mut gate = gate::Config::new(
        gate::Path {
            client: a,
            server: b,
        },
        [30; 32],
        1,
    )?;
    gate.path_mtu = 1280;
    gate.outer_overhead = 28 + 1 + 1 + 30;
    gate.arq.max_source_bytes = 100;
    gate.arq.send_bytes = 3200;
    gate.arq.receive_bytes = 3200;
    gate.arq.initial_rto = Duration::from_millis(10);
    gate.arq.maximum_rto = Duration::from_millis(100);
    gate.arq.ack_delay = Duration::from_millis(1);
    gate.cookie_ttl = Duration::from_secs(2);
    gate.handshake_timeout = Duration::from_secs(2);
    gate.initial_rto = Duration::from_millis(10);
    gate.maximum_rto = Duration::from_millis(100);
    gate.gate_attempts = 32;
    let cover = cover::Config::new(
        cover::Appearance::QuicLike,
        cover::ConnectionIds {
            local: cover::ConnectionId([if client { 1 } else { 2 }; 8]),
            peer: cover::ConnectionId([if client { 2 } else { 1 }; 8]),
        },
        cover::MediaConfig {
            local_ssrc: cover::Ssrc(if client { 1 } else { 2 }),
            peer_ssrc: cover::Ssrc(if client { 2 } else { 1 }),
            payload_type: 96,
        },
        cover::Limits {
            max_packet_bytes: 1024,
            max_protected_bytes: 512,
        },
    )?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"test-only/carrier-factory/effective-H0\0");
    hash.update(&outer.binding());
    let mut configuration = [0; 32];
    configuration.copy_from_slice(hash.finish().as_ref());
    Ok(establish::Config {
        gate,
        cover,
        profile: hs::Profile::IkPsk2,
        binding: establish::Binding {
            configuration,
            carrier: [4; 32],
            outer: outer.binding(),
            member: [6; 32],
        },
        receive_packets_per_interval: 64,
    })
}
fn settings(established: &factory::Established) -> Settings {
    let binding = established.binding();
    let authenticated = established.authenticated();
    let peers = established.peers();
    Settings {
        context: identity::Context {
            session: binding.session,
            transcript: binding.transcript,
            configuration: authenticated.configuration,
            carrier: authenticated.carrier,
            outer: authenticated.outer,
            initiator_noise: identity::NoisePublicKey(peers.initiator.0),
            responder_noise: identity::NoisePublicKey(peers.responder.0),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: 32,
        receive_interval: Duration::from_millis(5),
        receive_packets_per_interval: 8,
    }
}
async fn established(
    credentials: &Credentials,
) -> TestResult<(factory::Established, factory::Established, Instant)> {
    let (a, b) = sockets().await?;
    let cap = Instant::now() + Duration::from_secs(3);
    let selection = selected()?;
    let mut a_entropy = Entropy(40);
    let mut b_entropy = Entropy(60);
    let mut client_observer = |_| {};
    let client = factory::connect(
        a,
        outer_config(),
        ClientCredentials {
            tls: &credentials.client,
            server_name: "carrier-factory.test",
            member: &credentials.member,
        },
        noise(true),
        gate::Secret::new([7; 32]),
        cap,
        &mut a_entropy,
        |outer| Ok((effective(outer, true)?, selection)),
        &mut client_observer,
    );
    let server = async {
        let outer = Outer::server(
            b,
            outer_config(),
            ServerCredentials {
                tls: &credentials.server,
                members: &credentials.members,
            },
            cap,
        )
        .await?;
        let config = effective(&outer.authenticated(), false)?;
        let mut admission = factory::ServerAdmission::new(
            &outer,
            config,
            selection,
            peers(),
            gate::Secret::new([7; 32]),
            gate::Secret::new([8; 32]),
            Instant::now(),
        )?;
        let result = outer
            .accept(noise(false), &mut admission, &mut b_entropy, &mut |_| {})
            .await?;
        assert_eq!(admission.config(), config);
        Ok::<_, establish::Error>(result)
    };
    let (a, b) = tokio::try_join!(client, server)?;
    assert_eq!(a.binding(), b.binding());
    assert_eq!(a.authenticated(), b.authenticated());
    assert_eq!(
        a.outer().expected_binding(
            effective(&a.outer(), true)?,
            peers(),
            a.authenticated().session
        )?,
        a.authenticated()
    );
    assert_eq!(a.outer().binding(), b.outer().binding());
    assert_eq!(a.outer().requested(), outer_config());
    assert_eq!(a.outer().info().session_id, b.outer().info().session_id);
    assert_eq!(a.deadline(), cap);
    assert_eq!(b.deadline(), cap);
    assert!(a.statistics().socket_sent_datagrams > 0);
    assert!(b.statistics().socket_sent_datagrams > 0);
    Ok((a, b, cap))
}
fn time(origin: Instant, at: Instant) -> io::Result<hs::Time> {
    joining_time(origin, at)
}
struct Live {
    socket: crate::secure_udp::original_datagram::OriginalDatagram,
    cover: cover::Config,
    bootstrap: establish::BootstrapTail,
    joining: JoiningTail,
    next_outer: u32,
    deadline: Instant,
    origin: Instant,
}
fn install(parts: Parts) -> TestResult<(Live, record::Records)> {
    let origin = parts.clock_origin();
    let spec = parts.initial.selection().spec();
    let records = record::Records::new_refreshable(
        parts.initial,
        spec.lane,
        spec.limits,
        spec.protection,
        parts.cover,
        record::Scope {
            epoch: spec.control_epoch,
            configuration: spec.control_digest,
        },
        record::Scope {
            epoch: security::Epoch(7),
            configuration: security::ConfigDigest([21; 32]),
        },
        time(origin, Instant::now())?,
        time(origin, parts.deadline)?,
    )?;
    Ok((
        Live {
            socket: parts.datagram,
            cover: parts.cover,
            bootstrap: parts.bootstrap,
            joining: parts.joining,
            next_outer: parts.next_outer,
            deadline: parts.deadline,
            origin,
        },
        records,
    ))
}
async fn physical(live: &Live, class: record::Class, packet: &[u8]) -> TestResult {
    let class = if class == record::Class::User {
        crate::secure_udp::original_datagram::SendClass::User
    } else {
        crate::secure_udp::original_datagram::SendClass::Control
    };
    let mut ticket = live.socket.begin_send(class, packet, live.deadline)?;
    let receipt = live.socket.wait_send(&mut ticket).await?;
    assert_eq!(receipt.datagram_bytes, packet.len());
    assert_eq!(receipt.udp_bytes, packet.len() + 1);
    assert_eq!(receipt.ip_bytes, packet.len() + 29);
    assert!(receipt.accepted_at < receipt.deadline);
    Ok(())
}
async fn send_record(
    live: &mut Live,
    records: &mut record::Records,
    class: record::Class,
    body: &[u8],
) -> TestResult<Vec<u8>> {
    let mut scratch = [0; 1024];
    let mut output = [0; 1024];
    let sealed = records.seal_at(
        time(live.origin, Instant::now())?,
        class,
        metadata(live.next_outer, cover::Phase::Established),
        body,
        &mut scratch,
        &mut output,
    )?;
    advance(&mut live.next_outer)?;
    physical(live, class, &output[..sealed.record.bytes]).await?;
    Ok(output[..sealed.record.bytes].to_vec())
}
async fn receive_record(
    live: &mut Live,
    records: &mut record::Records,
    class: record::Class,
    body: &[u8],
) -> TestResult {
    let mut input = [0; 1025];
    let mut output = [0; 1024];
    let mut scratch = [0; 1024];
    let mut plaintext = [0; 512];
    loop {
        let now = Instant::now();
        before(now, live.deadline)?;
        if let Some(length) = live.bootstrap.poll(
            now,
            metadata(live.next_outer, cover::Phase::Handshake),
            &mut output,
        )? {
            advance(&mut live.next_outer)?;
            physical(live, record::Class::Control, &output[..length]).await?;
        }
        if let Some(length) = live.joining.poll(
            now,
            metadata(live.next_outer, cover::Phase::Established),
            &mut output,
        )? {
            advance(&mut live.next_outer)?;
            physical(live, record::Class::Control, &output[..length]).await?;
        }
        let wake = live
            .bootstrap
            .deadline()
            .unwrap_or(live.deadline)
            .min(live.joining.deadline().unwrap_or(live.deadline))
            .min(live.deadline);
        tokio::select! {
            _ = sleep_until(wake) => {},
            received = std::future::poll_fn(|cx| live.socket.poll_receive(cx, &mut input)) => {
                let length = received?;
                let now = Instant::now();
                let decoded = live.cover.decode(&input[..length])?;
                if live.bootstrap.receive(decoded, now)? || live.joining.receive(decoded, now)? { continue; }
                let opened = records.open_at(time(live.origin, now)?, &input[..length], &mut scratch, &mut plaintext)?;
                assert_eq!(opened.record.class, class);
                assert_eq!(&plaintext[..opened.record.bytes], body);
                return Ok(());
            }
        }
    }
}

#[tokio::test]
async fn actual_openvpn_factory_member_parts_install_common_records_on_original_tuple() -> TestResult
{
    let credentials = credentials()?;
    let (a, b, cap) = established(&credentials).await?;
    let endpoints = a.outer().endpoints();
    let outer = a.outer();
    let (a_origin, b_origin) = (a.clock_origin(), b.clock_origin());
    let (a_settings, b_settings) = (settings(&a), settings(&b));
    let mut client_observer = |_| {};
    let mut server_observer = |_| {};
    let (a, b) = tokio::try_join!(
        connect(a, &credentials.inner, a_settings, &mut client_observer),
        accept(
            b,
            identity::Allowlist::new(&[credentials.inner.public_key()])?,
            b_settings,
            &mut server_observer
        )
    )?;
    assert_eq!(a.info().member, outer.info().member);
    assert_eq!(a.info().binding, b.info().binding);
    let (a, b) = (a.into_parts(), b.into_parts());
    assert_eq!((a.deadline, b.deadline), (cap, cap));
    assert_eq!((a.clock_origin(), b.clock_origin()), (a_origin, b_origin));
    assert_eq!(a.datagram.addresses(), endpoints);
    assert_eq!(b.datagram.addresses(), (endpoints.1, endpoints.0));
    assert_eq!(a.datagram.geometry().extra_wire_bytes, 1);
    let (mut a, mut a_records) = install(a)?;
    let (mut b, mut b_records) = install(b)?;
    let raw = send_record(
        &mut a,
        &mut a_records,
        record::Class::User,
        b"actual common plaintext",
    )
    .await?;
    assert!(
        !raw.windows(23)
            .any(|part| part == b"actual common plaintext")
    );
    receive_record(
        &mut b,
        &mut b_records,
        record::Class::User,
        b"actual common plaintext",
    )
    .await?;
    // Replaying an actual sealed body is rejected by the retained inner owner.
    let mut scratch = [0; 1024];
    let mut plaintext = [0; 512];
    assert!(
        b_records
            .open_at(
                time(b.origin, Instant::now())?,
                &raw,
                &mut scratch,
                &mut plaintext
            )
            .is_err()
    );
    send_record(
        &mut b,
        &mut b_records,
        record::Class::Control,
        b"authenticated management record",
    )
    .await?;
    receive_record(
        &mut a,
        &mut a_records,
        record::Class::Control,
        b"authenticated management record",
    )
    .await?;
    let user = a
        .socket
        .outer_physical_status()?
        .ok_or("missing real outer physical ledger")?;
    assert_eq!(user.user_datagrams, 1);
    assert!(user.common_control_datagrams > 0);
    let mut tls = [0; 3];
    let a_tls = a
        .socket
        .outer_control()
        .ok_or_else(|| invalid("missing actual TLS"))?;
    let b_tls = b
        .socket
        .outer_control()
        .ok_or_else(|| invalid("missing actual TLS"))?;
    let (write, read) = timeout_at(cap, async {
        tokio::join!(a_tls.write_all(b"tls"), b_tls.read_exact(&mut tls))
    })
    .await?;
    write?;
    read?;
    assert_eq!(&tls, b"tls");
    Ok(())
}

#[tokio::test]
async fn actual_outer_factory_refuses_unbound_effective_config_before_noise() -> TestResult {
    let credentials = credentials()?;
    let (a, b) = sockets().await?;
    let cap = Instant::now() + Duration::from_secs(3);
    let (a, b) = tokio::try_join!(
        Outer::client(
            a,
            outer_config(),
            ClientCredentials {
                tls: &credentials.client,
                server_name: "carrier-factory.test",
                member: &credentials.member
            },
            cap
        ),
        Outer::server(
            b,
            outer_config(),
            ServerCredentials {
                tls: &credentials.server,
                members: &credentials.members
            },
            cap
        )
    )?;
    let mut wrong = effective(&a.authenticated(), true)?;
    wrong.binding.outer = [0; 32];
    let mut entropy = Entropy(40);
    let result = a
        .connect(
            wrong,
            selected()?,
            noise(true),
            gate::Secret::new([7; 32]),
            &mut entropy,
            &mut |_| {},
        )
        .await;
    assert!(matches!(result, Err(establish::Error::Configuration(_))));
    assert_eq!(entropy.0, 40);
    assert_eq!(b.authenticated().deadline(), cap);
    Ok(())
}

#[tokio::test]
async fn actual_inner_member_cannot_replace_authenticated_outer_member() -> TestResult {
    let credentials = credentials()?;
    let other = identity::IdentityKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let (a, b, _) = established(&credentials).await?;
    let (a_settings, b_settings) = (settings(&a), settings(&b));
    let mut client_observer = |_| {};
    let mut server_observer = |_| {};
    let (a, b) = tokio::join!(
        connect(a, &other, a_settings, &mut client_observer),
        accept(
            b,
            identity::Allowlist::new(&[other.public_key()])?,
            b_settings,
            &mut server_observer
        )
    );
    assert_eq!(
        a.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        b.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}
