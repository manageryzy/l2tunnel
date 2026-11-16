//! Actual socket/ticket adapter cases, separate from Common authority installation.
use super::*;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_openvpn::{
    WireBudget,
    wire_carrier::{ClientCredentials, ServerCredentials, common as raw},
};
use tokio::{net::UdpSocket, time::timeout_at};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;
fn config() -> raw::Config {
    raw::Config {
        base: l2tunnel_auth::SessionConfig {
            layer: PacketLayer::Ip,
            digest: core::ConfigDigest([7; 32]),
        },
        path_mtu: 1280,
        outer_overhead_bytes: 29,
        max_record_bytes: 1024,
        control_arq: recovery::ArqConfig {
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
#[tokio::test]
async fn actual_outer_io_keeps_separate_tickets_and_only_reports_whole_original_socket_writes()
-> TestResult {
    let cert = rcgen::generate_simple_self_signed(vec!["driver-carrier.test".to_owned()])?;
    let roots = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&roots)?;
    let server_tls = ServerTls::from_der(&roots, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let (a, b) = sockets().await?;
    let addresses = (a.local_addr()?, b.local_addr()?);
    let cap = Instant::now() + Duration::from_secs(3);
    let (a, b) = tokio::try_join!(
        raw::client_connect_until(
            a,
            config(),
            ClientCredentials {
                tls: &client_tls,
                server_name: "driver-carrier.test",
                member: &member
            },
            cap
        ),
        raw::server_accept_until(
            b,
            config(),
            ServerCredentials {
                tls: &server_tls,
                members: &members
            },
            cap
        )
    )?;
    let original = OriginalDatagram::openvpn(a)?;
    let plan = Plan::for_original(&original)?;
    let mut a = IoOwner::from_original(original)?;
    let mut b = IoOwner::from_original(OriginalDatagram::openvpn(b)?)?;
    assert_eq!(
        a.adapter_usage()?,
        Usage {
            capacity_bytes: plan.capacity_bytes(),
            allocations: 3
        }
    );
    assert_eq!(a.addresses()?, addresses);
    assert_eq!(b.addresses()?, (addresses.1, addresses.0));
    assert_eq!(a.extra_wire_bytes(), 1);
    assert_eq!(a.ip_wire_bytes()?, 29);
    assert_eq!(a.maximum_datagram_bytes(), Some(1024));
    let identity = UserIdentity {
        scope: Scope {
            epoch: security::Epoch(7),
            configuration: security::ConfigDigest([3; 32]),
        },
        number: security::PacketNumber(99),
        bytes: 4,
        deadline: cap,
    };
    assert!(matches!(
        a.try_user(identity, b"user")?,
        SendProgress::Pending
    ));
    assert!(a.user_pending());
    assert!(
        a.try_user(
            UserIdentity {
                number: security::PacketNumber(100),
                ..identity
            },
            b"user"
        )
        .is_err()
    );
    assert!(matches!(
        a.stage_control(b"control", 7 + 29, cap)?,
        SendProgress::Pending
    ));
    assert!(a.control_pending());
    assert!(a.stage_control(b"overwrite", 9 + 29, cap).is_err());
    let (mut user, mut control) = (false, false);
    for _ in 0..8 {
        timeout_at(cap, a.ready(false)).await??;
        if let Some((actual, progress)) = a.take_user()? {
            assert_eq!(actual, identity);
            let SendProgress::Whole { receipt, late } = progress else {
                return Err("queue admission became completion".into());
            };
            assert_eq!(
                (receipt.record_bytes, receipt.udp_bytes, receipt.ip_bytes),
                (4, Some(5), 33)
            );
            assert!(!late);
            assert!(receipt.accepted_at < cap);
            user = true;
        }
        if let Some((progress, cost)) = a.take_control()? {
            let SendProgress::Whole { receipt, late } = progress else {
                return Err("missing actual Control write".into());
            };
            assert_eq!(
                (
                    receipt.record_bytes,
                    receipt.udp_bytes,
                    receipt.ip_bytes,
                    cost
                ),
                (7, Some(8), 36, 36)
            );
            assert!(!late);
            control = true;
        }
        if user && control {
            break;
        }
    }
    assert!(user && control);
    assert!(a.take_user()?.is_none());
    assert!(a.take_control()?.is_none());
    let mut bodies = Vec::new();
    let mut input = [0; 1025];
    for _ in 0..2 {
        timeout_at(cap, b.ready(true)).await??;
        let length = b.try_receive(&mut input)?;
        bodies.push(input[..length].to_vec());
    }
    bodies.sort();
    assert_eq!(bodies, vec![b"control".to_vec(), b"user".to_vec()]);
    assert_eq!(
        a.adapter_usage()?,
        Usage {
            capacity_bytes: plan.capacity_bytes(),
            allocations: 3
        }
    );
    Ok(())
}

#[tokio::test]
async fn physical_late_projection_retains_actual_whole_udp_fact_without_success_relabeling()
-> TestResult {
    let (a, b) = sockets().await?;
    let a = OriginalDatagram::udp(a, 1280, 1024, 1)?;
    let cap = Instant::now() + Duration::from_secs(1);
    let mut ticket = a.begin_send(SendClass::User, b"fact", cap)?;
    let receipt = a.wait_send(&mut ticket).await?;
    let mut input = [0; 32];
    assert_eq!(timeout_at(cap, b.recv(&mut input)).await??, 4);
    // The write is real; only the typed late-result projection is injected here.
    let progress = complete(Err(SendFailure::Expired {
        accepted: Some(receipt),
    }))?;
    let SendProgress::Whole {
        receipt: observed,
        late,
    } = progress
    else {
        return Err("lost physical fact".into());
    };
    assert_eq!(observed, receipt.into());
    assert!(late);
    assert_eq!(
        complete(Err(SendFailure::Expired { accepted: None }))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}
