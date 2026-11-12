//! Real client entry points, canonical bindings and nonblocking native endpoints.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/test_udp_bind.rs"));
use super::*;
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
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
fn connection(layer: PacketLayer, duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer,
        duplex,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}
fn recovery() -> udp::RecoveryMode {
    udp::RecoveryMode::Cauchy {
        sources: 4,
        repairs: 2,
        flush_after: Duration::from_millis(5),
    }
}
fn reverse(value: udp::Endpoints) -> udp::Endpoints {
    udp::Endpoints {
        local: value.peer,
        peer: value.local,
    }
}
fn endpoints(duplex: Duplex) -> io::Result<(udp::Settings, udp::Settings)> {
    // Keep every reservation alive while choosing ports; only then hand them to the clients.
    let sockets = (0..4)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0"))
        .collect::<io::Result<Vec<_>>>()?;
    let first = udp::Endpoints {
        local: sockets[0].local_addr()?,
        peer: sockets[1].local_addr()?,
    };
    let second = (duplex == Duplex::Half)
        .then(|| {
            Ok::<_, io::Error>(udp::Endpoints {
                local: sockets[2].local_addr()?,
                peer: sockets[3].local_addr()?,
            })
        })
        .transpose()?;
    let a = udp::Settings {
        forward: first,
        reverse: second,
        cover: udp::CoverProfile::QuicLike,
        protection: udp::Protection::ChaCha20Poly1305,
        path_mtu: 1500,
        recovery: recovery(),
    };
    Ok((
        a,
        udp::Settings {
            forward: reverse(first),
            reverse: second.map(reverse),
            ..a
        },
    ))
}
fn as_quic(value: udp::Settings) -> quic::Settings {
    quic::Settings {
        forward: value.forward,
        reverse: value.reverse,
        application_id: *b"client-align-001",
        path_mtu: value.path_mtu,
        recovery: value.recovery,
    }
}
type PacketQueues = (VecDeque<Vec<u8>>, Vec<Vec<u8>>);
#[derive(Clone, Default)]
struct Native {
    state: Arc<Mutex<PacketQueues>>,
}
impl Native {
    fn access<T>(&self, f: impl FnOnce(&mut PacketQueues) -> T) -> io::Result<T> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("test device lock"))?;
        Ok(f(&mut state))
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
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        if output.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(io::Error::other("missing sentinel"));
        }
        self.native.access(|state| {
            state.0.pop_front().map(|packet| {
                output[..packet.len()].copy_from_slice(&packet);
                packet.len()
            })
        })
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.native.access(|state| state.1.push(bytes.to_vec()))
    }
}
fn frame(layer: PacketLayer, value: u8) -> Vec<u8> {
    let mut bytes = vec![value; 1600];
    if layer == PacketLayer::Ethernet {
        bytes[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    } else {
        bytes[..28].fill(0);
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&1600u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 0, 0, value]);
        bytes[16..20].copy_from_slice(&[10, 1, 0, value]);
        bytes[20..22].copy_from_slice(&4000u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&5000u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&1580u16.to_be_bytes());
    }
    bytes
}
struct Credentials {
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
    member: MemberKey,
    members: MemberAllowlist,
}
fn credentials() -> Result<Credentials, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["aligned-client.test".into()])?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    Ok(Credentials {
        chain: vec![cert.cert.der().to_vec()],
        key: cert.signing_key.serialize_der(),
        member,
        members,
    })
}
async fn wait_delivery(
    a: &Native,
    b: &Native,
    first: &[u8],
    second: &[u8],
    tasks: &mut JoinSet<io::Result<()>>,
) -> TestResult {
    timeout(Duration::from_secs(5),async {
        loop {
            if a.access(|state|state.1.clone())?==vec![second.to_vec()] && b.access(|state|state.1.clone())?==vec![first.to_vec()] {return Ok::<_,TestError>(());}
            tokio::select! {
                result=tasks.join_next()=>return Err(format!("runtime exited before exact delivery: {result:?}").into()),
                _=sleep(Duration::from_millis(2))=>{}
            }
        }
    }).await??;
    // Tests end by explicit cancellation, never claim a graceful native drain.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
#[tokio::test]
async fn aligned_udp_clients_forward_both_layers_and_duplex_modes() -> TestResult {
    let credentials = credentials()?;
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
        for duplex in [Duplex::Full, Duplex::Half] {
            let config = connection(layer, duplex);
            let settings = Settings { channels: 4 };
            let ((a_link, transport, records), (b_link, _, _)) = retry_udp_startup!(8, {
                let (a, b) = endpoints(duplex)?;
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let links = timeout(Duration::from_secs(8), async {
                    tokio::try_join!(
                        connect_udp(
                            listener.local_addr()?,
                            &client,
                            "aligned-client.test",
                            &credentials.member,
                            config,
                            a,
                            settings
                        ),
                        accept_udp(
                            &listener,
                            &server,
                            &credentials.members,
                            config,
                            b,
                            settings
                        )
                    )
                })
                .await??;
                Ok(links)
            })?;
            let first = frame(layer, 1);
            let second = frame(layer, 2);
            let an = Native::default();
            let bn = Native::default();
            an.access(|state| state.0.push_back(first.clone()))?;
            bn.access(|state| state.0.push_back(second.clone()))?;
            let mut tasks = JoinSet::new();
            tasks.spawn(runtime::run_udp(
                Device {
                    native: an.clone(),
                    layer,
                },
                a_link,
                config.runtime(),
                transport,
                records,
            ));
            tasks.spawn(runtime::run_udp(
                Device {
                    native: bn.clone(),
                    layer,
                },
                b_link,
                config.runtime(),
                transport,
                records,
            ));
            wait_delivery(&an, &bn, &first, &second, &mut tasks).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn aligned_quic_clients_forward_both_layers_and_duplex_modes() -> TestResult {
    let credentials = credentials()?;
    for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
        for duplex in [Duplex::Full, Duplex::Half] {
            let config = connection(layer, duplex);
            let settings = Settings { channels: 4 };
            let ((a_link, transport, records), (b_link, _, _)) = retry_udp_startup!(8, {
                let (a, b) = endpoints(duplex)?;
                let listener = QuicListener::bind(
                    &credentials.chain,
                    &credentials.key,
                    config,
                    as_quic(b),
                    settings,
                )?;
                let links = timeout(Duration::from_secs(8), async {
                    tokio::try_join!(
                        connect_quic(
                            &credentials.chain,
                            "aligned-client.test",
                            &credentials.member,
                            config,
                            as_quic(a),
                            settings
                        ),
                        listener.accept(&credentials.members)
                    )
                })
                .await??;
                Ok(links)
            })?;
            let first = frame(layer, 1);
            let second = frame(layer, 2);
            let an = Native::default();
            let bn = Native::default();
            an.access(|state| state.0.push_back(first.clone()))?;
            bn.access(|state| state.0.push_back(second.clone()))?;
            let mut tasks = JoinSet::new();
            tasks.spawn(runtime::run_quic(
                Device {
                    native: an.clone(),
                    layer,
                },
                a_link,
                config.runtime(),
                transport,
                records,
            ));
            tasks.spawn(runtime::run_quic(
                Device {
                    native: bn.clone(),
                    layer,
                },
                b_link,
                config.runtime(),
                transport,
                records,
            ));
            wait_delivery(&an, &bn, &first, &second, &mut tasks).await?;
        }
    }
    Ok(())
}
#[test]
fn aligned_limits_and_binding_are_explicit() -> TestResult {
    let config = connection(PacketLayer::Ethernet, Duplex::Full);
    let (a, _) = endpoints(Duplex::Full)?;
    let settings = Settings { channels: 4 };
    let (transport, records) = udp_config(config, a, settings)?;
    let binding = runtime::udp_base_session_config(config.runtime(), transport, records)?;
    assert_ne!(
        binding,
        l2tunnel_runtime::udp::base_session_config(config.runtime(), transport)?
    );
    let (_, changed) = udp_config(config, a, Settings { channels: 2 })?;
    assert_ne!(
        binding,
        runtime::udp_base_session_config(config.runtime(), transport, changed)?
    );
    for channels in [0, 257, u16::MAX] {
        assert!(udp_config(config, a, Settings { channels }).is_err());
    }
    assert!(
        udp_config(
            ConnectionConfig {
                compression: Compression::Lz4IfSmaller,
                ..config
            },
            a,
            settings
        )
        .is_err()
    );
    assert!(
        udp_config(
            config,
            udp::Settings {
                recovery: udp::RecoveryMode::SelectiveRepeat,
                ..a
            },
            settings
        )
        .is_err()
    );
    assert!(udp_config(config, udp::Settings { path_mtu: 575, ..a }, settings).is_err());
    Settings { channels: 256 }.validate(config, recovery())?;
    let (quic, records) = quic_config(config, as_quic(a), settings)?;
    assert_ne!(
        runtime::quic_base_session_config(config.runtime(), quic, records)?,
        l2tunnel_runtime::quic::base_session_config(config.runtime(), quic)?
    );
    Ok(())
}
#[tokio::test]
async fn mismatched_aligned_channels_fail_authentication() -> TestResult {
    let credentials = credentials()?;
    let config = connection(PacketLayer::Ethernet, Duplex::Full);
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    let (first, second) = retry_udp_startup!(5, {
        let (a, b) = endpoints(Duplex::Full)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let results = timeout(Duration::from_secs(5), async {
            tokio::join!(
                connect_udp(
                    address,
                    &client,
                    "aligned-client.test",
                    &credentials.member,
                    config,
                    a,
                    Settings { channels: 4 }
                ),
                accept_udp(
                    &listener,
                    &server,
                    &credentials.members,
                    config,
                    b,
                    Settings { channels: 2 }
                )
            )
        });
        // Resolve local address before the joined operations so both paths must actually fail.
        let (first, second) = results.await?;
        if first
            .as_ref()
            .err()
            .is_some_and(|e| udp_startup_addr_in_use(e))
            || second
                .as_ref()
                .err()
                .is_some_and(|e| udp_startup_addr_in_use(e))
        {
            return Err(
                io::Error::new(io::ErrorKind::AddrInUse, "test startup bind collision").into(),
            );
        }
        Ok((first, second))
    })?;
    assert!(first.is_err());
    assert!(second.is_err());
    let (first, second) = retry_udp_startup!(5, {
        let (a, b) = endpoints(Duplex::Full)?;
        let listener = QuicListener::bind(
            &credentials.chain,
            &credentials.key,
            config,
            as_quic(b),
            Settings { channels: 2 },
        )?;
        let (first, second) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                connect_quic(
                    &credentials.chain,
                    "aligned-client.test",
                    &credentials.member,
                    config,
                    as_quic(a),
                    Settings { channels: 4 }
                ),
                listener.accept(&credentials.members)
            )
        })
        .await?;
        if first
            .as_ref()
            .err()
            .is_some_and(|e| udp_startup_addr_in_use(e))
            || second
                .as_ref()
                .err()
                .is_some_and(|e| udp_startup_addr_in_use(e))
        {
            return Err(
                io::Error::new(io::ErrorKind::AddrInUse, "test startup bind collision").into(),
            );
        }
        Ok((first, second))
    })?;
    assert!(first.is_err());
    assert!(second.is_err());
    Ok(())
}
#[tokio::test]
async fn frame_client_helpers_preserve_original_full_and_half_bindings() -> TestResult {
    let credentials = credentials()?;
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    for duplex in [Duplex::Full, Duplex::Half] {
        let config = connection(PacketLayer::Ethernet, duplex);
        retry_udp_startup!(8, {
            let (a, b) = endpoints(duplex)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            timeout(Duration::from_secs(8), async {
                tokio::try_join!(
                    udp::connect(
                        listener.local_addr()?,
                        &client,
                        "aligned-client.test",
                        &credentials.member,
                        config,
                        a
                    ),
                    udp::accept(&listener, &server, &credentials.members, config, b)
                )
            })
            .await??;
            Ok(())
        })?;
        retry_udp_startup!(8, {
            let (a, b) = endpoints(duplex)?;
            let listener =
                quic::Listener::bind(&credentials.chain, &credentials.key, config, as_quic(b))?;
            timeout(Duration::from_secs(8), async {
                tokio::try_join!(
                    quic::connect(
                        &credentials.chain,
                        "aligned-client.test",
                        &credentials.member,
                        config,
                        as_quic(a)
                    ),
                    listener.accept(&credentials.members)
                )
            })
            .await??;
            Ok(())
        })?;
    }
    assert!(
        quic::finish_pair(
            tokio::time::Instant::now(),
            std::future::pending::<io::Result<()>>()
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn udp_startup_retry_is_bounded_and_only_retries_bind_collisions() -> TestResult {
    let attempts = std::cell::Cell::new(0);
    let value = retry_udp_startup!(1, {
        attempts.set(attempts.get() + 1);
        if attempts.get() == 1 {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "injected pre-start bind").into());
        }
        Ok(7)
    })?;
    assert_eq!(value, 7);
    assert_eq!(attempts.get(), 2);
    for (kind, expected) in [
        (io::ErrorKind::AddrInUse, 4),
        (io::ErrorKind::PermissionDenied, 1),
    ] {
        attempts.set(0);
        let result: Result<(), TestError> = retry_udp_startup!(1, {
            attempts.set(attempts.get() + 1);
            Err(io::Error::new(kind, "injected startup error").into())
        });
        assert!(result.is_err());
        assert_eq!(attempts.get(), expected);
    }
    Ok(())
}

#[tokio::test]
async fn udp_startup_retries_cannot_renew_original_deadline() {
    let attempts = std::cell::Cell::new(0);
    let result: Result<(), TestError> = async {
        retry_udp_startup!(1, {
            attempts.set(attempts.get() + 1);
            sleep(Duration::from_millis(300)).await;
            Err::<(), _>(io::Error::new(io::ErrorKind::AddrInUse, "injected bind collision").into())
        })?;
        Ok(())
    }
    .await;
    assert!(result.as_ref().err().is_some_and(|error| {
        error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    }));
    assert_eq!(attempts.get(), 4);
}
