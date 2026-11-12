use super::*;
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::time::{sleep, timeout};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
fn bundle(seed: u8) -> io::Result<KeyBundle> {
    let mut b = [seed; 64];
    b[32..].fill(seed + 1);
    KeyBundle::from_bytes(b)
}
fn config(duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: super::super::Compression::Lz4IfSmaller,
        handshake_timeout: Duration::from_secs(3),
    }
}
async fn endpoints(
    ipv6: bool,
    duplex: Duplex,
) -> io::Result<(Settings, Settings, Vec<SocketAddr>)> {
    let host = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
    let mut sockets = Vec::new();
    for _ in 0..if duplex == Duplex::Half { 4 } else { 2 } {
        sockets.push(UdpSocket::bind(host).await?);
    }
    let addresses = sockets
        .iter()
        .map(UdpSocket::local_addr)
        .collect::<io::Result<Vec<_>>>()?;
    let a = Settings {
        forward: Endpoints {
            local: addresses[0],
            peer: addresses[1],
        },
        reverse: (duplex == Duplex::Half).then(|| Endpoints {
            local: addresses[2],
            peer: addresses[3],
        }),
        protection: if ipv6 {
            carrier::Protection::HmacSha256
        } else {
            carrier::Protection::ChaCha20Poly1305
        },
        path_mtu: if ipv6 { 1280 } else { 1200 },
        authenticated_lease: Duration::from_secs(3600),
    };
    let b = Settings {
        forward: Endpoints {
            local: a.forward.peer,
            peer: a.forward.local,
        },
        reverse: a.reverse.map(|r| Endpoints {
            local: r.peer,
            peer: r.local,
        }),
        ..a
    };
    Ok((a, b, addresses))
}
struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: MemberKey,
    members: MemberAllowlist,
}
fn credentials() -> Result<Credentials, TestError> {
    let certificate =
        rcgen::generate_simple_self_signed(vec!["standalone-client.test".to_owned()])?;
    let chain = vec![certificate.cert.der().to_vec()];
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    Ok(Credentials {
        client: ClientTls::from_der_roots(&chain)?,
        server: ServerTls::from_der(&chain, &certificate.signing_key.serialize_der())?,
        members: MemberAllowlist::new(&[member.public_key()])?,
        member,
    })
}
#[derive(Clone)]
struct Device(Arc<Mutex<Native>>);
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    received: Vec<Vec<u8>>,
}
impl Device {
    fn new(seed: u8) -> Self {
        let mut value = vec![seed; 1500];
        value[0] = 0x45;
        value[2..4].copy_from_slice(&1500u16.to_be_bytes());
        Self(Arc::new(Mutex::new(Native {
            outgoing: VecDeque::from([value]),
            received: Vec::new(),
        })))
    }
    fn received(&self) -> io::Result<Vec<Vec<u8>>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| invalid("test mutex"))?
            .received
            .clone())
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| invalid("test mutex"))?
            .outgoing
            .pop_front()
            .map(|b| {
                out[..b.len()].copy_from_slice(&b);
                b.len()
            }))
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| invalid("test mutex"))?
            .received
            .push(bytes.to_vec());
        Ok(())
    }
}
async fn rebind(addresses: Vec<SocketAddr>) -> io::Result<()> {
    timeout(Duration::from_secs(1), async {
        loop {
            let mut sockets = Vec::new();
            let mut okay = true;
            for a in &addresses {
                match UdpSocket::bind(a).await {
                    Ok(v) => sockets.push(v),
                    Err(_) => {
                        okay = false;
                        break;
                    }
                }
            }
            if okay {
                return Ok(());
            }
            drop(sockets);
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| invalid("owned UDP socket leaked"))?
}
#[tokio::test]
async fn actual_full_half_ipv4_ipv6_factories_forward_native_bytes() -> TestResult {
    for ipv6 in [false, true] {
        for duplex in [Duplex::Full, Duplex::Half] {
            let c = credentials()?;
            let config = config(duplex);
            let (a, b, addresses) = endpoints(ipv6, duplex).await?;
            let ((left, lc), (right, rc)) = tokio::try_join!(
                connect(
                    &c.client,
                    "standalone-client.test",
                    &c.member,
                    bundle(1)?,
                    config,
                    a
                ),
                accept(&c.server, &c.members, bundle(1)?, bundle(3)?, config, b)
            )?;
            let l = Device::new(5);
            let r = Device::new(9);
            let expected_l = l.0.lock().map_err(|_| invalid("test mutex"))?.outgoing[0].clone();
            let expected_r = r.0.lock().map_err(|_| invalid("test mutex"))?.outgoing[0].clone();
            let lt = tokio::spawn(runtime::run(l.clone(), left, lc));
            let rt = tokio::spawn(runtime::run(r.clone(), right, rc));
            timeout(Duration::from_secs(3), async {
                while l.received()?.is_empty() || r.received()?.is_empty() {
                    sleep(Duration::from_millis(2)).await;
                }
                Ok::<(), io::Error>(())
            })
            .await??;
            assert_eq!(l.received()?, vec![expected_r]);
            assert_eq!(r.received()?, vec![expected_l]);
            lt.abort();
            rt.abort();
            assert!(lt.await.is_err());
            assert!(rt.await.is_err());
            rebind(addresses).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn role_canonical_binding_and_policy_rejections_precede_socket_binding() -> TestResult {
    let c = config(Duplex::Half);
    let (a, b, _) = endpoints(false, c.duplex).await?;
    let ap = profiles(c, a, true)?;
    let bp = profiles(c, b, false)?;
    assert_eq!(ap.first.session_config()?, bp.first.session_config()?);
    assert_eq!(
        ap.second.ok_or("second")?.session_config()?,
        bp.second.ok_or("second")?.session_config()?
    );
    for mutation in 0..6 {
        let mut s = a;
        match mutation {
            0 => s.reverse = None,
            1 => s.reverse = Some(s.forward),
            2 => s.path_mtu = 575,
            3 => s.authenticated_lease = Duration::ZERO,
            4 => s.authenticated_lease = Duration::from_secs(86401),
            _ => s.forward.local.set_port(0),
        }
        assert!(runtime_config(c, s).is_err());
    }
    let mut s = a;
    s.path_mtu = 1500;
    assert_ne!(
        profiles(c, s, true)?.first.session_config()?,
        ap.first.session_config()?
    );
    s = a;
    s.authenticated_lease = Duration::from_secs(1200);
    assert_ne!(
        profiles(c, s, true)?.first.session_config()?,
        ap.first.session_config()?
    );
    assert!(KeyBundle::from_bytes([0; 64]).is_err());
    assert!(KeyBundle::from_bytes([7; 64]).is_err());
    Ok(())
}
#[tokio::test]
async fn wrong_admission_and_native_config_fail_with_one_absolute_deadline() -> TestResult {
    for mismatch in [false, true] {
        let c = credentials()?;
        let mut cfg = config(Duplex::Half);
        cfg.handshake_timeout = Duration::from_millis(200);
        let (a, b, addresses) = endpoints(false, cfg.duplex).await?;
        let mut peer = cfg;
        if mismatch {
            peer.max_packet = 1400;
        }
        let start = Instant::now();
        let (left, right) = tokio::join!(
            connect(
                &c.client,
                "standalone-client.test",
                &c.member,
                bundle(1)?,
                cfg,
                a
            ),
            accept(
                &c.server,
                &c.members,
                bundle(if mismatch { 1 } else { 7 })?,
                bundle(3)?,
                peer,
                b
            )
        );
        assert!(left.is_err() && right.is_err());
        assert!(start.elapsed() < Duration::from_millis(700));
        rebind(addresses).await?;
    }
    Ok(())
}
#[tokio::test]
async fn cookie_reuse_second_bind_failure_and_cancellation_release_owned_sockets() -> TestResult {
    let c = credentials()?;
    let cfg = config(Duplex::Half);
    let (a, b, addresses) = endpoints(false, cfg.duplex).await?;
    assert!(
        accept(&c.server, &c.members, bundle(1)?, bundle(1)?, cfg, b)
            .await
            .is_err()
    );
    let occupied = UdpSocket::bind(a.reverse.ok_or("reverse")?.local).await?;
    assert!(
        connect(
            &c.client,
            "standalone-client.test",
            &c.member,
            bundle(1)?,
            cfg,
            a
        )
        .await
        .is_err()
    );
    let first = UdpSocket::bind(a.forward.local).await?;
    drop(first);
    drop(occupied);
    let task = tokio::spawn(async move {
        connect(
            &c.client,
            "standalone-client.test",
            &c.member,
            bundle(1)?,
            cfg,
            a,
        )
        .await
    });
    sleep(Duration::from_millis(30)).await;
    task.abort();
    assert!(task.await.is_err());
    rebind(addresses).await?;
    Ok(())
}
