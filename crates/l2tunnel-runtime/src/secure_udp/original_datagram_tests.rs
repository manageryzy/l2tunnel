//! Actual original socket/ticket custody, not a Common-session integration claim.
use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, timeout},
};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

async fn sockets() -> io::Result<(UdpSocket, UdpSocket)> {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    a.connect(b.local_addr()?).await?;
    b.connect(a.local_addr()?).await?;
    Ok((a, b))
}

#[tokio::test]
async fn actual_udp_ticket_keeps_exact_bytes_foreign_guard_and_separate_class_bounds() -> TestResult
{
    let (a, b) = sockets().await?;
    let addresses = (a.local_addr()?, b.local_addr()?);
    let a = OriginalDatagram::udp(a, 1280, 1252, 1)?;
    let mut b = OriginalDatagram::udp(b, 1280, 1252, 1)?;
    assert_eq!(a.geometry().full_ip_bytes(1252)?, 1280);
    assert!(a.geometry().full_ip_bytes(1253).is_err());
    assert_eq!(a.geometry().extra_wire_bytes, 0);
    let mut original = b"owned-before-write".to_vec();
    let expected = original.clone();
    let cap = Instant::now() + Duration::from_secs(1);
    let mut user = a.begin_send(SendClass::User, &original, cap)?;
    original.fill(0);
    assert_eq!(
        a.begin_send(SendClass::User, b"second", cap)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    let control = a.begin_send(SendClass::Control, b"separate", cap)?;
    assert_eq!(user.class(), SendClass::User);
    assert!(matches!(
        std::future::poll_fn(|cx| b.poll_send(cx, &mut user)).await,
        Err(SendFailure::Ticket)
    ));
    assert_eq!(user.deadline(), cap);
    drop(control);
    let receipt = timeout(Duration::from_secs(1), a.wait_send(&mut user)).await??;
    assert_eq!(
        (receipt.datagram_bytes, receipt.udp_bytes, receipt.ip_bytes),
        (expected.len(), expected.len(), expected.len() + 28)
    );
    assert!(receipt.accepted_at < cap);
    assert!(matches!(
        std::future::poll_fn(|cx| a.poll_send(cx, &mut user)).await,
        Err(SendFailure::Ticket)
    ));
    let mut input = [0; 1253];
    let bytes = timeout(
        Duration::from_secs(1),
        std::future::poll_fn(|cx| b.poll_receive(cx, &mut input)),
    )
    .await??;
    assert_eq!(&input[..bytes], expected.as_slice());
    assert_eq!(a.addresses(), addresses);
    assert_eq!(b.addresses(), (addresses.1, addresses.0));
    assert!(a.outer_wire_status()?.is_none());
    assert!(a.outer_physical_status()?.is_none());
    let next = a.begin_send(SendClass::User, b"reused", cap)?;
    drop(next);
    Ok(())
}

#[tokio::test]
async fn original_udp_expiry_and_unpolled_drop_release_custody_without_any_send() -> TestResult {
    let (a, b) = sockets().await?;
    let a = OriginalDatagram::udp(a, 1280, 1252, 1)?;
    let cap = Instant::now() + Duration::from_millis(10);
    let mut pending = a.begin_send(SendClass::User, b"must-not-send", cap)?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(matches!(
        std::future::poll_fn(|cx| a.poll_send(cx, &mut pending)).await,
        Err(SendFailure::Expired { accepted: None })
    ));
    let mut packet = [0; 1280];
    assert_eq!(
        b.try_recv(&mut packet).err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    let cap = Instant::now() + Duration::from_secs(1);
    let pending = a.begin_send(SendClass::User, b"dropped-before-write", cap)?;
    drop(pending);
    let mut actual = a.begin_send(SendClass::User, b"after-drop", cap)?;
    let receipt = a.wait_send(&mut actual).await?;
    assert_eq!(receipt.datagram_bytes, 10);
    let bytes = timeout(Duration::from_secs(1), b.recv(&mut packet)).await??;
    assert_eq!(&packet[..bytes], b"after-drop");
    assert_eq!(
        a.begin_send(SendClass::User, &[], cap)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}

fn outer_config() -> openvpn::Config {
    use l2tunnel_openvpn::WireBudget;
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

#[tokio::test]
async fn actual_openvpn_ticket_retains_tls_original_tuple_and_extra_opcode_geometry() -> TestResult
{
    use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
    use l2tunnel_openvpn::wire_carrier::{ClientCredentials, ServerCredentials};
    let cert = rcgen::generate_simple_self_signed(vec!["original-datagram.test".to_owned()])?;
    let roots = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&roots)?;
    let server_tls = ServerTls::from_der(&roots, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let (a, b) = sockets().await?;
    let addresses = (a.local_addr()?, b.local_addr()?);
    let cap = Instant::now() + Duration::from_secs(3);
    let (a, b) = timeout(Duration::from_secs(4), async {
        tokio::join!(
            openvpn::client_connect_until(
                a,
                outer_config(),
                ClientCredentials {
                    tls: &client_tls,
                    server_name: "original-datagram.test",
                    member: &member
                },
                cap
            ),
            openvpn::server_accept_until(
                b,
                outer_config(),
                ServerCredentials {
                    tls: &server_tls,
                    members: &members
                },
                cap
            )
        )
    })
    .await?;
    let (mut a, mut b) = (
        OriginalDatagram::openvpn(a?)?,
        OriginalDatagram::openvpn(b?)?,
    );
    assert_eq!(
        a.outer_info().map(|i| i.session_id),
        b.outer_info().map(|i| i.session_id)
    );
    assert_eq!(a.geometry().extra_wire_bytes, 1);
    assert_eq!(a.geometry().full_ip_bytes(1024)?, 1053);
    let cap = Instant::now() + Duration::from_secs(1);
    let mut pending = a.begin_send(SendClass::User, b"exact-common-ciphertext", cap)?;
    let receipt = timeout(Duration::from_secs(1), a.wait_send(&mut pending)).await??;
    assert_eq!(receipt.udp_bytes, receipt.datagram_bytes + 1);
    assert_eq!(receipt.ip_bytes, receipt.datagram_bytes + 29);
    let mut input = [0; 1025];
    let bytes = timeout(
        Duration::from_secs(1),
        std::future::poll_fn(|cx| b.poll_receive(cx, &mut input)),
    )
    .await??;
    assert_eq!(&input[..bytes], b"exact-common-ciphertext");
    assert_eq!(
        a.outer_physical_status()?
            .ok_or("missing outer physical ledger")?
            .user_datagrams,
        1
    );
    let mut tls = [0; 3];
    let a_tls = a.outer_control().ok_or("missing original TLS")?;
    let b_tls = b.outer_control().ok_or("missing original TLS")?;
    let (write, read) = timeout(Duration::from_secs(1), async {
        tokio::join!(a_tls.write_all(b"tls"), b_tls.read_exact(&mut tls))
    })
    .await?;
    write?;
    read?;
    assert_eq!(&tls, b"tls");
    assert_eq!(a.addresses(), addresses);
    assert_eq!(b.addresses(), (addresses.1, addresses.0));
    assert!(a.outer_wire_status()?.is_some());
    Ok(())
}
