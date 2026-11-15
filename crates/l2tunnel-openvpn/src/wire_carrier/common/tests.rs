use super::*;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use l2tunnel_handshake as hs;
use l2tunnel_security as security;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

fn config() -> Config {
    Config {
        base: SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([7; 32]),
        },
        path_mtu: 1280,
        outer_overhead_bytes: 29,
        max_record_bytes: 1024,
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
async fn sockets() -> Result<(UdpSocket, UdpSocket), std::io::Error> {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    a.connect(b.local_addr()?).await?;
    b.connect(a.local_addr()?).await?;
    Ok((a, b))
}
struct Entropy(u8);
impl hs::Entropy for Entropy {
    fn fill(&mut self, out: &mut [u8; 32]) -> Result<(), hs::EntropyError> {
        out.fill(self.0);
        Ok(())
    }
}
fn noise() -> Result<(hs::Handshake, hs::Handshake), TestError> {
    let a = hs::LocalSecret::new([11; 32].into());
    let b = hs::LocalSecret::new([22; 32].into());
    let peers = (a.public_key(), b.public_key());
    let config = |role| hs::Config {
        role,
        profile: hs::Profile::Ik,
        deadline: hs::Time(10000),
        binding: hs::Binding {
            session: security::SessionId([1; 16]),
            configuration: [2; 32],
            carrier: [3; 32],
            outer: [4; 32],
            member: [5; 32],
        },
    };
    Ok((
        hs::Handshake::new(
            config(security::Role::Initiator),
            a,
            peers.1,
            None,
            hs::Time(0),
            &mut Entropy(31),
        )?,
        hs::Handshake::new(
            config(security::Role::Responder),
            b,
            peers.0,
            None,
            hs::Time(0),
            &mut Entropy(42),
        )?,
    ))
}
async fn flight(
    sender: &mut hs::Handshake,
    receiver: &mut hs::Handshake,
    a: &Carrier,
    b: &mut Carrier,
) -> TestResult {
    let mut packet = [0; 1024];
    let flight = sender.write(hs::Time(1), &mut packet)?;
    a.send(Class::Control, &packet[..flight.bytes]).await?;
    let bytes = timeout(Duration::from_secs(1), b.recv()).await??;
    assert_eq!(bytes, &packet[..flight.bytes]);
    assert_eq!(
        receiver.read(hs::Time(1), flight.kind, &bytes)?,
        hs::ReadOutcome::Accepted
    );
    Ok(())
}

#[tokio::test]
async fn actual_common_noise_records_cross_raw_original_udp_without_exporter_resealing()
-> TestResult {
    let cert = rcgen::generate_simple_self_signed(vec!["openvpn-common.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let cfg = config();
    let (a, b) = sockets().await?;
    let tuple = (a.local_addr()?, b.local_addr()?);
    let (a, b) = timeout(Duration::from_secs(4), async {
        tokio::join!(
            client_connect(
                a,
                cfg,
                ClientCredentials {
                    tls: &client_tls,
                    server_name: "openvpn-common.test",
                    member: &member
                }
            ),
            server_accept(
                b,
                cfg,
                ServerCredentials {
                    tls: &server_tls,
                    members: &members
                }
            )
        )
    })
    .await?;
    let (mut a, mut b) = (a?, b?);
    assert_eq!(a.addresses(), tuple);
    assert_eq!(b.addresses(), (tuple.1, tuple.0));
    assert_eq!(a.outer_info().session_id, b.outer_info().session_id);
    assert_eq!(a.config(), cfg);
    let (mut x, mut y) = noise()?;
    flight(&mut x, &mut y, &a, &mut b).await?;
    flight(&mut y, &mut x, &b, &mut a).await?;
    flight(&mut x, &mut y, &a, &mut b).await?;
    flight(&mut y, &mut x, &b, &mut a).await?;
    let (mut x, mut y) = (x.finish(hs::Time(2))?, y.finish(hs::Time(2))?);
    let limits = security::Limits {
        max_body_bytes: 512,
        packets_per_key: 32,
        max_body_bytes_per_key: 16384,
    };
    let metadata = security::Metadata {
        epoch: security::Epoch(1),
        configuration: security::ConfigDigest([2; 32]),
        extra: b"actual common caller",
    };
    let mut sender = x.sender(
        security::Purpose::Data,
        security::LaneId(7),
        limits,
        security::Protection::ChaCha20Poly1305,
    )?;
    let mut receiver = y.receiver(
        security::Purpose::Data,
        security::LaneId(7),
        limits,
        security::Protection::ChaCha20Poly1305,
    )?;
    let mut cipher = [0; 1024];
    let sealed = sender.seal(metadata, b"\0actual common records\xff\0", &mut cipher)?;
    a.send(Class::User, &cipher[..sealed.bytes]).await?;
    let received = timeout(Duration::from_secs(1), b.recv()).await??;
    assert_eq!(received, &cipher[..sealed.bytes]);
    let mut plain = [0; 1024];
    let opened = receiver.open(metadata, &received, &mut plain)?;
    assert_eq!(&plain[..opened.bytes], b"\0actual common records\xff\0");
    // The substrate returns an exact duplicate; only the actual common receiver
    // decides replay acceptance, with no extra carrier packet number or cipher.
    a.send(Class::User, &cipher[..sealed.bytes]).await?;
    let duplicate = timeout(Duration::from_secs(1), b.recv()).await??;
    assert_eq!(duplicate, received);
    assert_eq!(
        receiver.open(metadata, &duplicate, &mut plain),
        Err(security::Error::Replay)
    );
    let mut management = y.sender(
        security::Purpose::Management,
        security::LaneId(7),
        limits,
        security::Protection::ChaCha20Poly1305,
    )?;
    let mut control = x.receiver(
        security::Purpose::Management,
        security::LaneId(7),
        limits,
        security::Protection::ChaCha20Poly1305,
    )?;
    let sealed = management.seal(metadata, b"bounded management body", &mut cipher)?;
    b.send(Class::Control, &cipher[..sealed.bytes]).await?;
    let received = timeout(Duration::from_secs(1), a.recv()).await??;
    let opened = control.open(metadata, &received, &mut plain)?;
    assert_eq!(&plain[..opened.bytes], b"bounded management body");
    let mut tls = [0; 3];
    let (write, read) = timeout(Duration::from_secs(1), async {
        tokio::join!(
            a.control().write_all(b"tls"),
            b.control().read_exact(&mut tls)
        )
    })
    .await?;
    write?;
    read?;
    assert_eq!(&tls, b"tls");
    assert_eq!(a.addresses(), tuple);
    Ok(())
}

#[tokio::test]
async fn actual_raw_emission_retains_wouldblock_bytes_and_exact_wire_charge_without_crypto_storage()
-> TestResult {
    let cfg = config();
    let budget = crate::budget::Budget::new(cfg.wire_budget, Instant::now());
    let mut data = Data::Opaque;
    let record = b"\0\xffalready-protected\0\0";
    let mut packet = vec![0xa5; cfg.path_mtu - (cfg.outer_overhead_bytes - 1)];
    let mut crypto = [];
    let length = actor::poll_data(
        &mut data,
        record,
        false,
        &budget,
        cfg.actor(),
        &mut crypto,
        &mut packet,
    )?
    .ok_or("no actual raw emission")?;
    assert_eq!(packet[0], 0x30);
    assert_eq!(&packet[1..length], record);
    assert!(crypto.is_empty());
    let original = packet.clone();
    let charged = budget.status()?;
    assert_eq!(
        charged,
        crate::WireStatus {
            admitted_datagrams: 1,
            admitted_ip_bytes: (record.len() + 29) as u64
        }
    );
    let (completion, mut result) = oneshot::channel();
    let mut pending = Some(actor::PendingData { length, completion });
    for _ in 0..2 {
        assert!(!actor::flush_data(&mut pending, &packet, |_| Err(
            std::io::ErrorKind::WouldBlock.into()
        ))?);
        assert!(pending.is_some());
        assert_eq!(packet, original);
        assert_eq!(budget.status()?, charged);
        assert!(matches!(
            result.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
    let (a, b) = sockets().await?;
    a.writable().await?;
    assert!(actor::flush_data(&mut pending, &packet, |bytes| a.try_send(bytes))?);
    result.await??;
    assert!(pending.is_none());
    assert_eq!(budget.status()?, charged);
    let mut wire = [0; 1280];
    let bytes = timeout(Duration::from_secs(1), b.recv(&mut wire)).await??;
    assert_eq!(&wire[..bytes], &original[..length]);
    assert_eq!(
        wire::decode(&wire[..bytes])?,
        wire::Packet::Data {
            key_id: 0,
            peer_id: None,
            payload: record
        }
    );
    let mut called = false;
    assert!(!actor::flush_data(&mut pending, &packet, |_| {
        called = true;
        Ok(0)
    })?);
    assert!(!called);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn raw_policy_has_distinct_binding_and_retains_control_reservation_after_user_saturation()
-> TestResult {
    let cfg = config();
    cfg.validate()?;
    let mut maximum = cfg;
    maximum.max_record_bytes = cfg.path_mtu - cfg.outer_overhead_bytes;
    maximum.validate()?;
    maximum.max_record_bytes += 1;
    assert!(maximum.validate().is_err());
    let protected = super::super::Config {
        base: cfg.base,
        profile: crate::Profile {
            traffic: crate::Traffic::FullDuplex,
            cover: crate::CoverProfile::OpenVpnLike,
            protection: crate::Protection::ChaCha20Poly1305,
            lane: crate::LaneId(7),
            generation: crate::KeyGeneration(1),
            path_mtu: cfg.path_mtu,
            outer_overhead_bytes: cfg.outer_overhead_bytes,
            max_payload_bytes: 512,
            max_packets_per_key: 1024,
            max_payload_bytes_per_key: 524288,
        },
        control_arq: cfg.control_arq,
        handshake_timeout: cfg.handshake_timeout,
        lifetime: cfg.lifetime,
        packet_slots: cfg.packet_slots,
        stream_bytes: cfg.stream_bytes,
        poll_interval: cfg.poll_interval,
        work_limit: cfg.work_limit,
        wire_budget: cfg.wire_budget,
    };
    assert_ne!(cfg.session_config()?, protected.session_config()?);
    let mut changed = cfg;
    changed.max_record_bytes -= 1;
    assert_ne!(cfg.session_config()?, changed.session_config()?);
    let budget = crate::budget::Budget::new(cfg.wire_budget, Instant::now());
    let mut data = Data::Opaque;
    let mut packet = vec![0; cfg.path_mtu - (cfg.outer_overhead_bytes - 1)];
    let mut crypto = [];
    for _ in 0..cfg.wire_budget.packets - cfg.wire_budget.reserved_control_packets {
        assert!(
            actor::poll_data(
                &mut data,
                b"user",
                false,
                &budget,
                cfg.actor(),
                &mut crypto,
                &mut packet
            )?
            .is_some()
        );
    }
    assert_eq!(
        actor::poll_data(
            &mut data,
            b"user",
            false,
            &budget,
            cfg.actor(),
            &mut crypto,
            &mut packet
        )?,
        None
    );
    assert!(
        actor::poll_data(
            &mut data,
            b"common management",
            true,
            &budget,
            cfg.actor(),
            &mut crypto,
            &mut packet
        )?
        .is_some()
    );
    assert_eq!(budget.status()?.admitted_datagrams, 29);
    Ok(())
}
