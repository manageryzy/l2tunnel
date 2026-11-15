use super::*;
use crate::{CoverProfile, KeyGeneration, LaneId, Protection, Traffic};
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
type Connections = (Result<Carrier, Error>, Result<Carrier, Error>);

fn config(protection: Protection) -> Config {
    Config {
        base: SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([7; 32]),
        },
        profile: Profile {
            traffic: Traffic::FullDuplex,
            cover: CoverProfile::OpenVpnLike,
            protection,
            lane: LaneId(7),
            generation: KeyGeneration(1),
            path_mtu: 1280,
            outer_overhead_bytes: 29,
            max_payload_bytes: 512,
            max_packets_per_key: 1024,
            max_payload_bytes_per_key: 524288,
        },
        control_arq: ArqConfig {
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

struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: MemberKey,
    members: MemberAllowlist,
}
fn credentials(authorized: bool) -> Result<Credentials, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["openvpn-wire.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client = ClientTls::from_der_roots(&chain)?;
    let server = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let other = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[if authorized {
        member.public_key()
    } else {
        other.public_key()
    }])?;
    Ok(Credentials {
        client,
        server,
        member,
        members,
    })
}
async fn sockets() -> Result<(UdpSocket, UdpSocket), std::io::Error> {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    a.connect(b.local_addr()?).await?;
    b.connect(a.local_addr()?).await?;
    Ok((a, b))
}
async fn connect(
    a: UdpSocket,
    b: UdpSocket,
    cfg: Config,
    credentials: &Credentials,
) -> Result<Connections, tokio::time::error::Elapsed> {
    timeout(Duration::from_secs(4), async {
        tokio::join!(
            client_connect(
                a,
                cfg,
                ClientCredentials {
                    tls: &credentials.client,
                    server_name: "openvpn-wire.test",
                    member: &credentials.member
                }
            ),
            server_accept(
                b,
                cfg,
                ServerCredentials {
                    tls: &credentials.server,
                    members: &credentials.members
                }
            ),
        )
    })
    .await
}

#[tokio::test]
async fn actual_reset_tls_member_and_protected_data_retain_original_udp_pair_and_tls_control()
-> TestResult {
    for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
        let credentials = credentials(true)?;
        let cfg = config(protection);
        let (socket_a, socket_b) = sockets().await?;
        let endpoints = (socket_a.local_addr()?, socket_b.local_addr()?);
        let (a, b) = connect(socket_a, socket_b, cfg, &credentials).await?;
        let (mut a, mut b) = (a?, b?);
        assert_eq!(a.info().session_id, b.info().session_id);
        assert_eq!(a.addresses(), endpoints);
        assert_eq!(b.addresses(), (endpoints.1, endpoints.0));
        assert_eq!(a.config(), cfg);
        // Arbitrary record bodies deliberately have no private carrier ARQ header.
        let forward = b"\0\xffswift-or-packed\0\0";
        let reverse = b"\x80management-or-feedback\0";
        timeout(Duration::from_secs(1), a.send(forward)).await??;
        assert_eq!(timeout(Duration::from_secs(1), b.recv()).await??, forward);
        timeout(Duration::from_secs(1), b.send(reverse)).await??;
        assert_eq!(timeout(Duration::from_secs(1), a.recv()).await??, reverse);
        let mut received = [0; 15];
        let (write, read) = timeout(Duration::from_secs(1), async {
            tokio::join!(
                b.control().write_all(b"control remains"),
                a.control().read_exact(&mut received)
            )
        })
        .await?;
        write?;
        read?;
        assert_eq!(&received, b"control remains");
        assert!(a.wire_status()?.admitted_datagrams > 0);
        assert!(b.wire_status()?.admitted_ip_bytes > 0);
    }
    Ok(())
}

#[tokio::test]
async fn half_direction_rejects_reverse_user_data_and_preserves_reverse_authenticated_control()
-> TestResult {
    let credentials = credentials(true)?;
    let mut cfg = config(Protection::ChaCha20Poly1305);
    cfg.profile.traffic = Traffic::HalfDuplex {
        sender: l2tunnel_datagram::Direction::ClientToServer,
    };
    let (socket_a, socket_b) = sockets().await?;
    let (a, b) = connect(socket_a, socket_b, cfg, &credentials).await?;
    let (mut a, mut b) = (a?, b?);
    assert!(matches!(
        b.send(b"disabled").await,
        Err(Error::DirectionDisabled)
    ));
    a.send(b"allowed").await?;
    assert_eq!(
        timeout(Duration::from_secs(1), b.recv()).await??,
        b"allowed"
    );
    let mut received = [0; 3];
    let (write, read) = timeout(Duration::from_secs(1), async {
        tokio::join!(
            b.control().write_all(b"ctl"),
            a.control().read_exact(&mut received)
        )
    })
    .await?;
    write?;
    read?;
    assert_eq!(&received, b"ctl");
    Ok(())
}

#[tokio::test]
async fn actual_member_refusal_never_returns_an_activated_data_owner() -> TestResult {
    let credentials = credentials(false)?;
    let cfg = config(Protection::ChaCha20Poly1305);
    let (a, b) = sockets().await?;
    let (a, b) = connect(a, b, cfg, &credentials).await?;
    assert!(a.is_err());
    assert!(b.is_err());
    assert!(
        matches!(a, Err(Error::Authentication(_))) || matches!(b, Err(Error::Authentication(_)))
    );
    Ok(())
}

#[test]
fn complete_bound_policy_changes_auth_digest_and_old_udp_overhead_is_refused() -> TestResult {
    let cfg = config(Protection::ChaCha20Poly1305);
    let bound = cfg.session_config()?;
    let mut changed = cfg;
    changed.profile.outer_overhead_bytes = 28;
    assert!(changed.validate().is_err());
    for changed in [
        Config {
            packet_slots: cfg.packet_slots + 1,
            ..cfg
        },
        Config {
            control_arq: ArqConfig {
                max_retries: cfg.control_arq.max_retries + 1,
                ..cfg.control_arq
            },
            ..cfg
        },
        Config {
            lifetime: cfg.lifetime + Duration::from_secs(1),
            ..cfg
        },
    ] {
        assert_ne!(changed.session_config()?, bound);
    }
    Ok(())
}
