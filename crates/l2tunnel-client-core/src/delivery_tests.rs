//! Additive shared delivery-policy API and real retained TLS handshake tests.
use super::*;
use l2tunnel_flow_control::delivery_window::Config;
use l2tunnel_runtime::configuration::DeliveryConfig;
use tokio::time::{sleep, timeout};
type Failure = Box<dyn std::error::Error + Send + Sync>;
type Result<T = ()> = std::result::Result<T, Failure>;
pub(crate) fn policy() -> DeliveryConfig {
    let forward = Config {
        target_bandwidth_bps: 80_000_000,
        bootstrap_rtt_micros: 70_000,
        min_rtt_micros: 2_000,
        max_rtt_micros: 200_000,
        headroom_percent: 125,
        minimum_bytes: 1600,
        max_inflight_bytes: 4_000_000,
        max_records: 4096,
        max_packet_bytes: 1600,
        metadata_limit_bytes: 1_000_000,
        sample_ttl_micros: 1_000_000,
        flush_timeout_micros: 2_000_000,
    };
    DeliveryConfig {
        forward,
        reverse: Config {
            target_bandwidth_bps: 10_000_000,
            ..forward
        },
    }
}
fn config(duplex: Duplex, limit: Duration) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: limit,
    }
}
struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: MemberKey,
    allow: MemberAllowlist,
}
fn credentials() -> Result<Credentials> {
    let cert = rcgen::generate_simple_self_signed(vec!["delivery-client.test".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    Ok(Credentials {
        client: ClientTls::from_der_roots(&chain)?,
        server: ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?,
        allow: MemberAllowlist::new(&[member.public_key()])?,
        member,
    })
}
#[test]
fn canonical_delivery_pair_binds_every_field_without_changing_legacy_queue() -> Result {
    let cfg = config(Duplex::Half, Duration::from_secs(3));
    let base = policy();
    let legacy = cfg.session()?;
    let binding = cfg.session_with_delivery(base)?;
    assert_ne!(legacy, binding);
    assert_eq!(cfg.runtime().queue_packets, 64);
    assert_eq!(cfg.mode_with_delivery(base)?, cfg.mode()?);
    assert_eq!(cfg.session_with_delivery(base)?, binding);
    let swapped = DeliveryConfig {
        forward: base.reverse,
        reverse: base.forward,
    };
    assert_ne!(cfg.session_with_delivery(swapped)?, binding);
    // Valid changes must alter the binding; a packet limit incompatible with
    // the native runtime must reject before I/O. Both directions are covered.
    for reverse in [false, true] {
        for field in 0..12 {
            let mut changed = base;
            let c = if reverse {
                &mut changed.reverse
            } else {
                &mut changed.forward
            };
            match field {
                0 => c.target_bandwidth_bps += 1,
                1 => c.bootstrap_rtt_micros += 1,
                2 => c.min_rtt_micros += 1,
                3 => c.max_rtt_micros += 1,
                4 => c.headroom_percent += 1,
                5 => c.minimum_bytes += 1,
                6 => c.max_inflight_bytes += 1,
                7 => c.max_records += 1,
                8 => c.max_packet_bytes += 1,
                9 => c.metadata_limit_bytes += 1,
                10 => c.sample_ttl_micros += 1,
                _ => c.flush_timeout_micros += 1,
            }
            if field == 8 {
                assert!(cfg.session_with_delivery(changed).is_err());
            } else {
                assert_ne!(
                    cfg.session_with_delivery(changed)?,
                    binding,
                    "field{field},reverse{reverse}"
                );
            }
        }
    }
    assert_eq!(cfg.session()?, legacy);
    Ok(())
}
#[tokio::test]
async fn matching_delivery_wrappers_authenticate_actual_full_and_half_tls() -> Result {
    let c = credentials()?;
    for duplex in [Duplex::Full, Duplex::Half] {
        let cfg = config(duplex, Duration::from_secs(3));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (a, b) = timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                connect_with_delivery(
                    listener.local_addr()?,
                    &c.client,
                    "delivery-client.test",
                    &c.member,
                    cfg,
                    policy()
                ),
                accept_with_delivery(&listener, &c.server, &c.allow, cfg, policy())
            )
        })
        .await??;
        drop((a, b));
    }
    Ok(())
}
#[tokio::test]
async fn mismatched_canonical_direction_policy_fails_actual_tls_authentication() -> Result {
    let c = credentials()?;
    let cfg = config(Duplex::Full, Duration::from_secs(3));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut changed = policy();
    changed.reverse.target_bandwidth_bps += 1;
    let (a, b) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            connect_with_delivery(
                address,
                &c.client,
                "delivery-client.test",
                &c.member,
                cfg,
                policy()
            ),
            accept_with_delivery(&listener, &c.server, &c.allow, cfg, changed)
        )
    })
    .await?;
    assert!(a.is_err());
    assert!(b.is_err());
    Ok(())
}
#[tokio::test]
async fn delivery_validation_rejects_before_accept_and_first_accept_keeps_original_deadline()
-> Result {
    let c = credentials()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let cfg = config(Duplex::Full, Duration::from_millis(50));
    let mut bad = policy();
    bad.forward.max_records = 0;
    let invalid = accept_with_delivery(&listener, &c.server, &c.allow, cfg, bad)
        .await
        .err()
        .ok_or("invalid delivery policy accepted")?;
    assert_ne!(
        invalid.kind(),
        io::ErrorKind::TimedOut,
        "invalid policy must reject before entering accept"
    );
    let result = timeout(
        Duration::from_secs(1),
        accept_with_delivery(&listener, &c.server, &c.allow, cfg, policy()),
    )
    .await?;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}
#[tokio::test]
async fn delivery_half_pairing_cannot_restart_original_handshake_deadline() -> Result {
    let c = credentials()?;
    let cfg = config(Duplex::Half, Duration::from_millis(800));
    let binding = cfg.session_with_delivery(policy())?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let (first, _) = listener.accept().await?;
        sleep(Duration::from_millis(250)).await;
        let first =
            auth::server_accept(first, &c.server, &c.allow, binding, Duration::from_secs(3))
                .await?;
        let (second, _) = listener.accept().await?;
        sleep(Duration::from_millis(250)).await;
        let second =
            auth::server_accept(second, &c.server, &c.allow, binding, Duration::from_secs(3))
                .await?;
        sleep(Duration::from_millis(400)).await;
        Ok::<_, Failure>(l2tunnel_runtime::server_pair(first, second).await)
    };
    let (client, _peer) = timeout(Duration::from_secs(4), async {
        tokio::join!(
            connect_with_delivery(
                address,
                &c.client,
                "delivery-client.test",
                &c.member,
                cfg,
                policy()
            ),
            peer
        )
    })
    .await?;
    assert_eq!(
        client.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}
