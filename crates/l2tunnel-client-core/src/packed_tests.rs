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
fn settings() -> Settings {
    Settings {
        channels: 4,
        delivery: crate::delivery_tests::policy(),
        packing: runtime::Options {
            hold_micros: 1000,
            max_units: 4,
            work_limit: 16,
        },
    }
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
        application_id: *b"client-pack-0001",
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
fn frames(layer: PacketLayer, seed: u8) -> Result<Vec<Vec<u8>>, TestError> {
    let mut frames = Vec::new();
    if layer == PacketLayer::Ethernet {
        for line in include_str!("../../l2tunnel-codec/tests/data/aligned-sender-goldens.tsv")
            .lines()
            .filter(|line| line.starts_with("symbol128\t0\t") || line.starts_with("symbol128\t1\t"))
        {
            let text = line.split('\t').nth(6).ok_or("missing native golden")?;
            frames.push(
                (0..text.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
    }
    for n in 0..8 {
        let mut bytes = frame(layer, seed + n);
        if n != 7 {
            bytes.truncate(64);
            bytes[60..].fill(0);
            if layer == PacketLayer::Ip {
                bytes[2..4].copy_from_slice(&64u16.to_be_bytes());
                bytes[24..26].copy_from_slice(&44u16.to_be_bytes());
            }
        }
        frames.push(bytes);
    }
    Ok(frames)
}
struct Credentials {
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
    member: MemberKey,
    members: MemberAllowlist,
}
fn credentials() -> Result<Credentials, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["packed-client.test".into()])?;
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
    first: &[Vec<u8>],
    second: &[Vec<u8>],
    tasks: &mut JoinSet<io::Result<()>>,
) -> TestResult {
    let result = timeout(Duration::from_secs(5),async {
        loop {
            if a.access(|state|state.1.len())?==second.len() && b.access(|state|state.1.len())?==first.len() {return Ok::<_,TestError>(());}
            tokio::select! {
                result=tasks.join_next()=>return Err(format!("runtime exited before exact delivery: {result:?}").into()),
                _=sleep(Duration::from_millis(2))=>{}
            }
        }
    }).await;
    // Tests end by explicit cancellation, never claim a graceful native drain.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result??;
    // Different common-MUX channels may deliver in different orders. Compare
    // the complete byte-exact multiset, including duplicate count; codec tests
    // separately prove per-channel ordered reconstruction and context state.
    for (native, expected) in [(a, second), (b, first)] {
        let mut actual = native.access(|state| state.1.clone())?;
        let mut expected = expected.to_vec();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected);
    }
    Ok(())
}
#[tokio::test]
async fn packed_udp_clients_forward_both_layers_and_duplex_modes() -> TestResult {
    let credentials = credentials()?;
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
        for duplex in [Duplex::Full, Duplex::Half] {
            let config = connection(layer, duplex);
            let settings = settings();
            let ((a_link, transport, records), (b_link, _, _)) = retry_udp_startup!(8, {
                let (a, b) = endpoints(duplex)?;
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let links = timeout(Duration::from_secs(8), async {
                    tokio::try_join!(
                        connect_udp(
                            listener.local_addr()?,
                            &client,
                            "packed-client.test",
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
            let first = frames(layer, 1)?;
            let second = frames(layer, 2)?;
            let an = Native::default();
            let bn = Native::default();
            an.access(|state| state.0.extend(first.iter().cloned()))?;
            bn.access(|state| state.0.extend(second.iter().cloned()))?;
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
async fn packed_quic_clients_forward_both_layers_and_duplex_modes() -> TestResult {
    let credentials = credentials()?;
    for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
        for duplex in [Duplex::Full, Duplex::Half] {
            let config = connection(layer, duplex);
            let settings = settings();
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
                            "packed-client.test",
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
            let first = frames(layer, 1)?;
            let second = frames(layer, 2)?;
            let an = Native::default();
            let bn = Native::default();
            an.access(|state| state.0.extend(first.iter().cloned()))?;
            bn.access(|state| state.0.extend(second.iter().cloned()))?;
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

#[path = "packed_failure_tests.rs"]
mod failure;
