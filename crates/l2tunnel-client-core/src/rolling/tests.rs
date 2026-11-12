use super::*;
use crate::Compression;
use l2tunnel_core::Duplex;
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time::{sleep, timeout},
};
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn settings() -> io::Result<Settings> {
    Settings::from_json(include_bytes!("test-policy.json"))
}
fn connection(layer: PacketLayer, duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer,
        duplex,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}
fn endpoints(duplex: Duplex) -> io::Result<(udp::Settings, udp::Settings)> {
    let sockets = (0..4)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0"))
        .collect::<io::Result<Vec<_>>>()?;
    let forward = udp::Endpoints {
        local: sockets[0].local_addr()?,
        peer: sockets[1].local_addr()?,
    };
    let reverse = if duplex == Duplex::Half {
        Some(udp::Endpoints {
            local: sockets[2].local_addr()?,
            peer: sockets[3].local_addr()?,
        })
    } else {
        None
    };
    let flip = |e: udp::Endpoints| udp::Endpoints {
        local: e.peer,
        peer: e.local,
    };
    let a = udp::Settings {
        forward,
        reverse,
        cover: udp::CoverProfile::QuicLike,
        protection: udp::Protection::ChaCha20Poly1305,
        path_mtu: 1500,
        recovery: udp::RecoveryMode::SelectiveRepeat,
    };
    Ok((
        a,
        udp::Settings {
            forward: flip(forward),
            reverse: reverse.map(flip),
            ..a
        },
    ))
}
fn as_quic(s: udp::Settings) -> quic::Settings {
    quic::Settings {
        forward: s.forward,
        reverse: s.reverse,
        application_id: *b"rolling-test-001",
        path_mtu: s.path_mtu,
        recovery: s.recovery,
    }
}
type PacketQueues = (VecDeque<Vec<u8>>, Vec<Vec<u8>>);
#[derive(Clone, Default)]
struct Native(Arc<Mutex<PacketQueues>>);
impl Native {
    fn access<T>(&self, f: impl FnOnce(&mut PacketQueues) -> T) -> io::Result<T> {
        let mut s = self
            .0
            .lock()
            .map_err(|_| io::Error::other("test device lock"))?;
        Ok(f(&mut s))
    }
}
struct Device {
    native: Native,
    layer: PacketLayer,
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.native.access(|s| {
            s.0.pop_front().map(|bytes| {
                out[..bytes.len()].copy_from_slice(&bytes);
                bytes.len()
            })
        })
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.native.access(|s| s.1.push(bytes.to_vec()))
    }
}
fn packets(layer: PacketLayer, seed: u8) -> Vec<Vec<u8>> {
    (0..8)
        .map(|n| {
            let size = if n == 7 { 1600 } else { 64 + n as usize };
            let mut p = vec![seed + n; size];
            p[size - 4..].fill(0);
            if layer == PacketLayer::Ethernet {
                p[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
            } else {
                p[..28].fill(0);
                p[0] = 0x45;
                p[2..4].copy_from_slice(&(size as u16).to_be_bytes());
                p[8] = 64;
                p[9] = 17;
                p[12..16].copy_from_slice(&[10, 0, 0, seed + n]);
                p[16..20].copy_from_slice(&[10, 1, 0, seed + n]);
                p[20..22].copy_from_slice(&4000u16.to_be_bytes());
                p[22..24].copy_from_slice(&5000u16.to_be_bytes());
                p[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
            }
            p
        })
        .collect()
}
struct Credentials {
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
    member: MemberKey,
    members: MemberAllowlist,
}
fn credentials() -> Result<Credentials, Box<dyn std::error::Error + Send + Sync>> {
    let c = rcgen::generate_simple_self_signed(vec!["rolling-client.test".into()])?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    Ok(Credentials {
        chain: vec![c.cert.der().to_vec()],
        key: c.signing_key.serialize_der(),
        member,
        members,
    })
}
#[tokio::test]
async fn rolling_actual_udp_and_quic_shared_api_both_layers_and_duplexes() -> TestResult {
    let c = credentials()?;
    let client = ClientTls::from_der_roots(&c.chain)?;
    let server = ServerTls::from_der(&c.chain, &c.key)?;
    for is_quic in [false, true] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for duplex in [Duplex::Full, Duplex::Half] {
                let config = connection(layer, duplex);
                let settings = settings()?;
                let (a, b) = endpoints(duplex)?;
                let (first, second) = if is_quic {
                    let listener =
                        QuicListener::bind(&c.chain, &c.key, config, as_quic(b), &settings)?;
                    tokio::try_join!(
                        connect_quic(
                            &c.chain,
                            "rolling-client.test",
                            &c.member,
                            config,
                            as_quic(a),
                            &settings
                        ),
                        listener.accept(&c.members)
                    )?
                } else {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    tokio::try_join!(
                        connect_udp(
                            listener.local_addr()?,
                            &client,
                            "rolling-client.test",
                            &c.member,
                            config,
                            a,
                            &settings
                        ),
                        accept_udp(&listener, &server, &c.members, config, b, &settings)
                    )?
                };
                let observers = [first.observer(), second.observer()];
                assert_eq!(observers[0].snapshot().phase, Phase::Authenticated);
                assert_eq!(
                    observers[0].snapshot().digest,
                    observers[1].snapshot().digest
                );
                assert_eq!(
                    observers[0].snapshot().effective_carrier,
                    if is_quic { Carrier::Quic } else { Carrier::Udp }
                );
                assert_eq!(
                    observers[0].snapshot().pipeline,
                    if layer == PacketLayer::Ethernet {
                        PipelineProfile::TapSystem
                    } else {
                        PipelineProfile::TunDrr
                    }
                );
                let one = packets(layer, 1);
                let two = packets(layer, 40);
                let an = Native::default();
                let bn = Native::default();
                an.access(|s| s.0.extend(one.iter().cloned()))?;
                bn.access(|s| s.0.extend(two.iter().cloned()))?;
                let mut tasks = JoinSet::new();
                tasks.spawn(first.run(Device {
                    native: an.clone(),
                    layer,
                }));
                tasks.spawn(second.run(Device {
                    native: bn.clone(),
                    layer,
                }));
                let result=timeout(Duration::from_secs(5),async {loop {
            if an.access(|s|s.1.len())?==two.len() && bn.access(|s|s.1.len())?==one.len() {return Ok::<_,io::Error>(());}
            tokio::select! {result=tasks.join_next()=>return Err(io::Error::other(format!("premature runtime exit: {result:?}"))),_=sleep(Duration::from_millis(2))=>{}}
        }}).await;
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                result??;
                for (n, expected) in [(&an, &two), (&bn, &one)] {
                    let mut actual = n.access(|s| s.1.clone())?;
                    let mut expected = expected.clone();
                    actual.sort();
                    expected.sort();
                    assert_eq!(actual, expected);
                }
                for observer in observers {
                    let s = observer.snapshot();
                    assert_eq!(s.phase, Phase::Cancelled);
                    assert!(
                        !s.clean_drain
                            && !s.hot_reload
                            && !s.tcp_window_ownership
                            && !s.native_qualified
                            && !s.large_window_qualified
                    );
                }
            }
        }
    }
    Ok(())
}
#[test]
fn rolling_strict_policy_limits_nested_duplicates_and_pre_auth_geometry() -> TestResult {
    let bytes = include_bytes!("test-policy.json");
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    for pointer in [
        "/version",
        "/profile",
        "/recovery/window",
        "/scheduling/feedback_packets",
        "/service/field_work",
    ] {
        let mut missing = value.clone();
        let (parent, key) = pointer.rsplit_once('/').ok_or("pointer")?;
        missing
            .pointer_mut(parent)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("object")?
            .remove(key);
        assert!(
            Settings::from_json(&serde_json::to_vec(&missing)?).is_err(),
            "missing {pointer}"
        );
    }
    for parent in ["", "/recovery", "/scheduling", "/service"] {
        let mut unknown = value.clone();
        unknown
            .pointer_mut(parent)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("object")?
            .insert("unexpected".into(), 1.into());
        assert!(Settings::from_json(&serde_json::to_vec(&unknown)?).is_err());
    }
    let text = std::str::from_utf8(bytes)?;
    for (key, number) in [
        ("version", "1"),
        ("window", "8"),
        ("feedback_packets", "2"),
        ("field_work", "4096"),
    ] {
        let duplicated = text.replacen(
            &format!("\"{key}\":{number}"),
            &format!("\"{key}\":{number},\"{key}\":{number}"),
            1,
        );
        assert_ne!(text, duplicated);
        assert!(Settings::from_json(duplicated.as_bytes()).is_err());
    }
    for (pointer, number) in [
        ("/version", 2),
        ("/channels", 0),
        ("/recovery/window", 129),
        ("/service/field_work", 0),
        ("/service/passes_per_turn", 65),
        ("/scheduling/repair_denominator", 0),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).ok_or("pointer")? = number.into();
        assert!(
            Settings::from_json(&serde_json::to_vec(&bad)?).is_err(),
            "{pointer}"
        );
    }
    let mut exact = bytes.to_vec();
    exact.resize(MAX_POLICY_BYTES, b' ');
    Settings::from_json(&exact)?;
    exact.push(b' ');
    assert!(Settings::from_json(&exact).is_err());
    let connection = connection(PacketLayer::Ip, Duplex::Full);
    let (a, _) = endpoints(Duplex::Full)?;
    let original = settings()?;
    for (pointer, number) in [
        ("/recovery/max_payload", 4096),
        ("/recovery/memory_bytes", 1),
        ("/scheduling/memory_bytes", 1),
        ("/recovery/job_millis", 120001),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).ok_or("pointer")? = number.into();
        let bad: Settings = serde_json::from_value(bad)?;
        assert!(udp_config(connection, a, &bad).is_err(), "{pointer}");
        assert!(quic_config(connection, as_quic(a), &bad).is_err());
    }
    let (t, r) = udp_config(connection, a, &original)?;
    let digest = runtime::udp_base_session_config(connection.runtime(), t, r)?.digest;
    assert_ne!(
        digest,
        l2tunnel_runtime::udp::base_session_config(connection.runtime(), t)?.digest
    );
    for (pointer, number) in [
        ("/channels", 3),
        ("/stream", 4),
        ("/epoch", 10),
        ("/recovery/window", 9),
        ("/recovery/local_window", 3),
        ("/recovery/global_every", 5),
        ("/recovery/max_payload", 999),
        ("/recovery/max_rows", 7),
        ("/recovery/repair_history", 17),
        ("/recovery/handoff_sources", 1),
        ("/recovery/job_millis", 2999),
        ("/recovery/debt_millis", 9999),
        ("/recovery/handoff_millis", 2999),
        ("/recovery/memory_bytes", 33554433),
        ("/scheduling/repair_numerator", 0),
        ("/scheduling/repair_denominator", 3),
        ("/scheduling/tail_millis", 21),
        ("/scheduling/feedback_millis", 6),
        ("/scheduling/feedback_packets", 3),
        ("/scheduling/memory_bytes", 33554433),
        ("/service/field_work", 4095),
        ("/service/copy_work", 4095),
        ("/service/metadata_work", 4095),
        ("/service/passes_per_turn", 7),
    ] {
        let mut other = value.clone();
        *other.pointer_mut(pointer).ok_or("pointer")? = number.into();
        let other = Settings::from_json(&serde_json::to_vec(&other)?)?;
        let (t, r) = udp_config(connection, a, &other)?;
        assert_ne!(
            digest,
            runtime::udp_base_session_config(connection.runtime(), t, r)?.digest,
            "{pointer}"
        );
    }
    Ok(())
}
#[tokio::test]
async fn rolling_original_deadline_rejects_pending_and_ready_overrun() -> TestResult {
    let result = finish_before(
        Instant::now() + Duration::from_millis(20),
        std::future::pending::<io::Result<()>>(),
    )
    .await;
    assert_eq!(
        result.err().ok_or("timeout absent")?.kind(),
        io::ErrorKind::TimedOut
    );
    let result = finish_before(Instant::now() + Duration::from_millis(10), async {
        std::thread::sleep(Duration::from_millis(20));
        Ok(())
    })
    .await;
    assert_eq!(
        result.err().ok_or("ready overrun absent")?.kind(),
        io::ErrorKind::TimedOut
    );
    let polled = std::sync::atomic::AtomicBool::new(false);
    assert!(
        finish_before(Instant::now(), async {
            polled.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await
        .is_err()
    );
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

#[path = "failure_tests.rs"]
mod failure;
