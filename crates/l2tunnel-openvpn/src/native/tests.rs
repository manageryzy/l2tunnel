use super::*;
use crate::runtime::{Sources, State};
use crate::{Status, Terminal};
use tokio::{
    sync::Semaphore,
    time::{sleep, timeout},
};
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn shared() -> Arc<Shared> {
    Arc::new(Shared {
        state: Mutex::new(State {
            sources: Sources::default(),
            status: Status::default(),
            close_started: None,
            data_drained: false,
            tls_finished: false,
        }),
        terminal: watch::channel(None).0,
        receive_slots: Arc::new(Semaphore::new(2)),
        send_slots: Arc::new(Semaphore::new(2)),
    })
}
fn domain() -> Arc<Domain> {
    Domain::new([9; 32], shared(), shared(), 2, Duration::from_secs(1))
}
#[tokio::test]
async fn terminal_before_wait_and_receive_only_failure_wake_without_new_phase() -> TestResult {
    for first in [true, false] {
        let d = domain();
        let mut changes = d.changed.subscribe();
        if first {
            d.send.finish(Terminal::Timeout);
        } else {
            d.receive.finish(Terminal::Timeout);
        }
        assert!(matches!(
            timeout(Duration::from_millis(30), d.wait_changed(&mut changes)).await?,
            Err(Error::Timeout)
        ));
    }
    let d = domain();
    let mut changes = d.changed.subscribe();
    let other = d.clone();
    let result = timeout(Duration::from_millis(100), async {
        let waiter = d.wait_changed(&mut changes);
        let fail = async {
            tokio::task::yield_now().await;
            other.receive.finish(Terminal::Failed);
        };
        tokio::join!(waiter, fail).0
    })
    .await?;
    assert!(matches!(result, Err(Error::Closed)));
    Ok(())
}
#[tokio::test]
async fn send_seal_includes_reserved_slots_and_exact_prefix_and_cannot_reopen() -> TestResult {
    let d = domain();
    d.request()?;
    let slot = d.send.send_slots.clone().acquire_owned().await?;
    assert!(matches!(d.seal(), Err(Error::Busy)));
    d.send.modify(|s| {
        s.status.admitted_packets = 2;
        s.sources.admitted_bytes = 17;
        Ok(())
    })?;
    drop(slot);
    let seal = d.seal()?;
    assert_eq!((seal.sources(), seal.bytes()), (2, 17));
    assert!(d.send.modify(|s| Ok(s.sources.sealed))?);
    d.publish(1, 99, &seal)?;
    assert!(d.publish(2, 99, &seal).is_err());
    assert_eq!(
        d.state()?.local,
        Some(NativeFence {
            packets: 1,
            native_bytes: 99,
            sources: 2,
            source_bytes: 17
        })
    );
    Ok(())
}
#[tokio::test]
async fn fences_before_data_require_exact_consumption_and_duplicates_do_not_extend_deadline()
-> TestResult {
    let d = domain();
    let f = NativeFence {
        packets: 1,
        native_bytes: 100,
        sources: 2,
        source_bytes: 25,
    };
    assert!(d.accept(FENCE, f).is_err());
    assert!(d.accept(REQUEST, NativeFence::default())?);
    let deadline = d.state()?.deadline;
    sleep(Duration::from_millis(1)).await;
    assert!(!d.accept(REQUEST, NativeFence::default())?);
    assert_eq!(deadline, d.state()?.deadline);
    assert!(d.accept(FENCE, f)?);
    assert!(!d.accept(FENCE, f)?);
    assert!(
        d.accept(
            FENCE,
            NativeFence {
                source_bytes: 26,
                ..f
            }
        )
        .is_err()
    );
    let peer = d.state()?.peer.ok_or(Error::Closed)?;
    assert!(matches!(d.ack(&peer), Err(Error::Busy)));
    d.receive.modify(|s| {
        s.status.delivered_packets = 2;
        s.sources.consumed_bytes = 24;
        Ok(())
    })?;
    assert!(matches!(d.ack(&peer), Err(Error::Busy)));
    d.receive.modify(|s| {
        s.sources.consumed_bytes = 25;
        Ok(())
    })?;
    d.ack(&peer)?;
    assert!(d.state()?.peer_acknowledged);
    assert_eq!(d.receive.modify(|s| Ok(s.sources.ceiling))?, Some((2, 25)));
    Ok(())
}
#[test]
fn preaccepted_tail_and_geometry_are_rejected_without_installing_ceiling() -> TestResult {
    let d = domain();
    d.request()?;
    d.accept(REQUEST, NativeFence::default())?;
    d.receive.modify(|s| {
        s.sources.accepted_prefix = 3;
        Ok(())
    })?;
    assert!(
        d.accept(
            FENCE,
            NativeFence {
                packets: 1,
                native_bytes: 20,
                sources: 2,
                source_bytes: 30
            }
        )
        .is_err()
    );
    assert!(d.state()?.peer.is_none());
    assert!(d.receive.modify(|s| Ok(s.sources.ceiling))?.is_none());
    for f in [
        NativeFence {
            packets: 1,
            ..Default::default()
        },
        NativeFence {
            sources: 1,
            ..Default::default()
        },
        NativeFence {
            packets: 2,
            native_bytes: 1,
            sources: 2,
            source_bytes: 2,
        },
    ] {
        assert!(f.validate().is_err());
    }
    Ok(())
}
#[test]
fn peer_close_proof_tolerates_only_local_ack_flush_lag() -> TestResult {
    let d = domain();
    d.request()?;
    let seal = d.seal()?;
    d.publish(0, 0, &seal)?;
    d.accept(REQUEST, NativeFence::default())?;
    d.accept(FENCE, NativeFence::default())?;
    d.accept(NATIVE_ACK, NativeFence::default())?;
    assert!(!d.proof()?);
    d.ack(&d.state()?.peer.ok_or(Error::Closed)?)?;
    assert!(d.proof()?);
    assert!(!d.state()?.ready());
    assert!(matches!(d.deadline(), Err(Error::Busy)));
    for kind in [REQUEST, FENCE, NATIVE_ACK] {
        d.flushed(kind)?;
    }
    assert!(d.state()?.ready());
    assert!(
        d.deadline()?
            .checked_duration_since(Instant::now())
            .is_some()
    );
    assert!(!d.accept(NATIVE_ACK, NativeFence::default())?);
    Ok(())
}

struct Identity {
    client: l2tunnel_auth::ClientTls,
    server: l2tunnel_auth::ServerTls,
    member: l2tunnel_auth::MemberKey,
    members: l2tunnel_auth::MemberAllowlist,
}
impl Identity {
    fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert = rcgen::generate_simple_self_signed(vec!["native.test".to_owned()])?;
        let chain = vec![cert.cert.der().to_vec()];
        let member =
            l2tunnel_auth::MemberKey::from_pkcs8(&l2tunnel_auth::MemberKey::generate_pkcs8()?)?;
        Ok(Self {
            client: l2tunnel_auth::ClientTls::from_der_roots(&chain)?,
            server: l2tunnel_auth::ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?,
            members: l2tunnel_auth::MemberAllowlist::new(&[member.public_key()])?,
            member,
        })
    }
}
async fn sockets() -> Result<
    (tokio::net::UdpSocket, tokio::net::UdpSocket, Config),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let mut cfg = Config::new(
        l2tunnel_udp_control::Path {
            client: a.local_addr()?,
            server: b.local_addr()?,
        },
        SessionConfig {
            layer: l2tunnel_device::PacketLayer::Ip,
            digest: ConfigDigest([17; 32]),
        },
        crate::Protection::ChaCha20Poly1305,
    )?;
    cfg.bootstrap.arq.maximum_rto = Duration::from_millis(80);
    cfg.bootstrap.arq.initial_rto = Duration::from_millis(20);
    Ok((a, b, cfg))
}
async fn full_pair(
    timeout: Duration,
) -> Result<(NativeCarrier, NativeCarrier), Box<dyn std::error::Error + Send + Sync>> {
    let id = Identity::new()?;
    let (a, b, cfg) = sockets().await?;
    let cfg = NativeDrainConfig::new(cfg, timeout)?;
    let (a, b) = tokio::try_join!(
        client_connect_native(
            a,
            cfg,
            crate::ClientCredentials {
                tls: &id.client,
                server_name: "native.test",
                member: &id.member,
                admission: l2tunnel_udp_control::Secret::new([3; 32])
            }
        ),
        server_accept_native(
            b,
            cfg,
            crate::ServerCredentials {
                tls: &id.server,
                members: &id.members,
                admission: l2tunnel_udp_control::Secret::new([3; 32]),
                cookie: l2tunnel_udp_control::Secret::new([4; 32])
            }
        )
    )?;
    Ok((a, b))
}
async fn wait_ready(a: &Arc<Domain>, b: &Arc<Domain>) -> Result<(), Error> {
    timeout(Duration::from_secs(2), async {
        loop {
            for d in [a, b] {
                if let Some(peer) = d.state()?.peer {
                    d.ack(&peer)?;
                }
            }
            if a.state()?.ready() && b.state()?.ready() {
                return Ok(());
            }
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .map_err(|_| Error::Timeout)?
}
#[tokio::test]
async fn genuine_full_profile_source_fences_then_native_proof_and_retained_close() -> TestResult {
    for payload in [false, true] {
        let (a, b) = full_pair(Duration::from_secs(4)).await?;
        assert_eq!(a.info().session_id, b.info().session_id);
        let (ac, at, mut ar) = a.split();
        let (bc, bt, mut br) = b.split();
        if payload {
            at.send(b"accepted source").await?;
            bt.send(b"reverse source").await?;
            let mut bytes = [0; 64];
            assert_eq!(br.receive(&mut bytes).await?, 15);
            assert_eq!(&bytes[..15], b"accepted source");
            assert_eq!(ar.receive(&mut bytes).await?, 14);
            assert_eq!(&bytes[..14], b"reverse source");
        }
        ac.request_stop()?;
        bc.request_stop()?;
        ac.publish_fence(
            u64::from(payload),
            if payload { 15 } else { 0 },
            &ac.seal_send()?,
        )?;
        bc.publish_fence(
            u64::from(payload),
            if payload { 14 } else { 0 },
            &bc.seal_send()?,
        )?;
        assert!(matches!(at.send(b"after seal").await, Err(Error::Closed)));
        wait_ready(&ac.domain, &bc.domain).await?;
        let (a, b) = tokio::try_join!(ac.close(), bc.close())?;
        assert_eq!(a.status.terminal, Some(Terminal::Clean));
        assert_eq!(b.status.terminal, Some(Terminal::Clean));
    }
    Ok(())
}
#[tokio::test]
async fn genuine_paired_profile_uses_first_tls_control_and_actual_opposite_bulk_lanes() -> TestResult
{
    let id = Identity::new()?;
    let (a, b, mut first) = sockets().await?;
    let (c, d, mut second) = sockets().await?;
    first.profile.traffic = crate::Traffic::HalfDuplex {
        sender: l2tunnel_datagram::Direction::ClientToServer,
    };
    second.profile.traffic = crate::Traffic::HalfDuplex {
        sender: l2tunnel_datagram::Direction::ServerToClient,
    };
    second.profile.lane = crate::LaneId(1);
    let configs = [
        NativeDrainConfig::new(first, Duration::from_secs(4))?,
        NativeDrainConfig::new(second, Duration::from_secs(4))?,
    ];
    let (a, b) = tokio::try_join!(
        client_pair_native(
            [a, c],
            configs,
            crate::ClientPairCredentials {
                tls: &id.client,
                server_name: "native.test",
                member: &id.member,
                admissions: [
                    l2tunnel_udp_control::Secret::new([3; 32]),
                    l2tunnel_udp_control::Secret::new([5; 32])
                ]
            }
        ),
        server_pair_native(
            [b, d],
            configs,
            crate::ServerPairCredentials {
                tls: &id.server,
                members: &id.members,
                admissions: [
                    l2tunnel_udp_control::Secret::new([3; 32]),
                    l2tunnel_udp_control::Secret::new([5; 32])
                ],
                cookies: [
                    l2tunnel_udp_control::Secret::new([4; 32]),
                    l2tunnel_udp_control::Secret::new([6; 32])
                ]
            }
        )
    )?;
    assert_eq!(a.info().digest, b.info().digest);
    let (ac, at, mut ar) = a.split();
    let (bc, bt, mut br) = b.split();
    at.send(b"forward").await?;
    bt.send(b"reverse").await?;
    let mut bytes = [0; 32];
    assert_eq!(br.receive(&mut bytes).await?, 7);
    assert_eq!(&bytes[..7], b"forward");
    assert_eq!(ar.receive(&mut bytes).await?, 7);
    assert_eq!(&bytes[..7], b"reverse");
    ac.request_stop()?;
    timeout(Duration::from_secs(1), async {
        while bc.state()?.requested_at.is_none() {
            sleep(Duration::from_millis(2)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    ac.publish_fence(1, 7, &ac.seal_send()?)?;
    bc.publish_fence(1, 7, &bc.seal_send()?)?;
    wait_ready(&ac.domain, &bc.domain).await?;
    let (a, b) = tokio::try_join!(ac.close(), bc.close())?;
    assert!(
        a.into_iter()
            .chain(b)
            .all(|r| r.status.terminal == Some(Terminal::Clean))
    );
    Ok(())
}
#[tokio::test]
async fn missing_native_proof_expires_original_deadline_and_drop_cancels_handles() -> TestResult {
    let (a, b) = full_pair(Duration::from_millis(60)).await?;
    let (ac, at, _ar) = a.split();
    let (bc, _bt, _br) = b.split();
    ac.request_stop()?;
    let initial = ac.state()?.deadline;
    sleep(Duration::from_millis(20)).await;
    ac.request_stop()?;
    assert_eq!(initial, ac.state()?.deadline);
    timeout(Duration::from_secs(1), async {
        loop {
            if ac.state().is_err() {
                break;
            }
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    assert!(matches!(ac.state(), Err(Error::IncompleteClose)));
    assert!(at.send(b"late").await.is_err());
    drop((ac, bc));
    let (a, b) = full_pair(Duration::from_secs(1)).await?;
    let (ac, at, _ar) = a.split();
    drop(ac);
    assert!(matches!(at.send(b"canceled").await, Err(Error::Closed)));
    drop(b);
    Ok(())
}
#[tokio::test]
async fn native_policy_separates_all_legacy_fields_and_exact_deadline() -> TestResult {
    let (_, _, cfg) = sockets().await?;
    let before = cfg.session_config()?;
    let native = NativeDrainConfig::new(cfg, Duration::from_secs(1))?;
    assert_eq!(cfg.session_config()?, before);
    assert_eq!(native.carrier(), cfg);
    assert_ne!(native.session_config()?, before);
    assert_ne!(
        native.session_config()?,
        NativeDrainConfig::new(cfg, Duration::from_secs(2))?.session_config()?
    );
    let mut changed = cfg;
    changed.packet_bytes += 1;
    assert_ne!(
        native.session_config()?,
        NativeDrainConfig::new(changed, Duration::from_secs(1))?.session_config()?
    );
    for bad in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_secs(121),
    ] {
        assert!(NativeDrainConfig::new(cfg, bad).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn already_clean_lane_does_not_spin_pending_other_lane_phase_wait() -> TestResult {
    let d = domain();
    d.request()?;
    let mut changes = d.changed.subscribe();
    d.send.finish(Terminal::Clean);
    assert!(
        timeout(Duration::from_millis(15), d.wait_changed(&mut changes))
            .await
            .is_err()
    );
    let phase = d.clone();
    let waiting = d.wait_changed(&mut changes);
    let flush = async move {
        tokio::task::yield_now().await;
        phase.flushed(REQUEST)
    };
    let (state, flushed) = timeout(Duration::from_millis(100), async {
        tokio::join!(waiting, flush)
    })
    .await?;
    flushed?;
    assert!(!state?.ready());
    assert!(
        timeout(Duration::from_millis(15), d.wait_changed(&mut changes))
            .await
            .is_err()
    );
    Ok(())
}

struct BlockTls(std::net::SocketAddr);
impl Drop for BlockTls {
    fn drop(&mut self) {
        let _ = crate::test_wire::block_tls(self.0, false);
    }
}
#[tokio::test]
async fn secondary_close_overtakes_delayed_primary_native_ack_without_skipping_proof() -> TestResult
{
    paired_close_skew(true).await
}
#[tokio::test]
async fn deferred_secondary_close_expires_without_restarting_native_deadline() -> TestResult {
    paired_close_skew(false).await
}
async fn paired_close_skew(release: bool) -> TestResult {
    let id = Identity::new()?;
    let (a, b, mut first) = sockets().await?;
    let (c, d, mut second) = sockets().await?;
    first.profile.traffic = crate::Traffic::HalfDuplex {
        sender: l2tunnel_datagram::Direction::ClientToServer,
    };
    second.profile.traffic = crate::Traffic::HalfDuplex {
        sender: l2tunnel_datagram::Direction::ServerToClient,
    };
    second.profile.lane = crate::LaneId(1);
    let management_server = first.bootstrap.path.server;
    let duration = if release {
        Duration::from_secs(4)
    } else {
        Duration::from_millis(180)
    };
    let configs = [
        NativeDrainConfig::new(first, duration)?,
        NativeDrainConfig::new(second, duration)?,
    ];
    let (a, b) = tokio::try_join!(
        client_pair_native(
            [a, c],
            configs,
            crate::ClientPairCredentials {
                tls: &id.client,
                server_name: "native.test",
                member: &id.member,
                admissions: [
                    l2tunnel_udp_control::Secret::new([13; 32]),
                    l2tunnel_udp_control::Secret::new([15; 32])
                ]
            }
        ),
        server_pair_native(
            [b, d],
            configs,
            crate::ServerPairCredentials {
                tls: &id.server,
                members: &id.members,
                admissions: [
                    l2tunnel_udp_control::Secret::new([13; 32]),
                    l2tunnel_udp_control::Secret::new([15; 32])
                ],
                cookies: [
                    l2tunnel_udp_control::Secret::new([14; 32]),
                    l2tunnel_udp_control::Secret::new([16; 32])
                ]
            }
        )
    )?;
    let (ac, _at, _ar) = a.split();
    let (bc, _bt, _br) = b.split();
    ac.request_stop()?;
    bc.request_stop()?;
    ac.publish_fence(0, 0, &ac.seal_send()?)?;
    bc.publish_fence(0, 0, &bc.seal_send()?)?;
    timeout(Duration::from_secs(1), async {
        while ac.state()?.peer.is_none() || bc.state()?.peer.is_none() {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    ac.ack_peer_native(&ac.state()?.peer.ok_or(Error::Closed)?)?;
    timeout(Duration::from_secs(1), async {
        while !bc.state()?.local_acknowledged {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    crate::test_wire::block_tls(management_server, true)?;
    let blocked = BlockTls(management_server);
    bc.ack_peer_native(&bc.state()?.peer.ok_or(Error::Closed)?)?;
    timeout(Duration::from_secs(1), async {
        while !bc.state()?.ready() {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    assert!(!ac.state()?.ready());
    assert!(!ac.state()?.local_acknowledged);
    let original = ac.state()?.deadline;
    let server_close = tokio::spawn(bc.close());
    // Do not wait for both ready: only the ready server starts closing. Prove
    // the secondary Close arrived while its primary NativeAck remains missing.
    timeout(Duration::from_secs(1), async {
        while !ac.state()?.secondary_close_pending {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    assert!(!ac.state()?.ready());
    assert_eq!(original, ac.state()?.deadline);
    assert!(!ac.control.status()?.lanes[1].closing);
    assert!(!server_close.is_finished());
    if !release {
        let ended = timeout(Duration::from_secs(1), server_close).await??;
        assert!(matches!(ended, Err(Error::IncompleteClose)));
        assert!(
            Instant::now()
                < original
                    .ok_or(Error::Closed)?
                    .checked_add(Duration::from_millis(300))
                    .ok_or(Error::Closed)?
        );
        assert!(
            !ac.control
                .status()?
                .lanes
                .iter()
                .any(|s| s.terminal == Some(Terminal::Clean))
        );
        drop((ac, blocked));
        return Ok(());
    }
    assert!(crate::test_wire::block_tls(management_server, false)? > 0);
    drop(blocked);
    timeout(Duration::from_secs(1), async {
        while !ac.state()?.ready() {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    let client = ac.close().await?;
    let server = timeout(Duration::from_secs(2), server_close).await???;
    assert!(
        client
            .into_iter()
            .chain(server)
            .all(|receipt| receipt.status.terminal == Some(Terminal::Clean))
    );
    Ok(())
}

#[tokio::test]
async fn public_native_close_rejects_expired_deadline_even_after_inner_clean() -> TestResult {
    let (a, b) = full_pair(Duration::from_millis(350)).await?;
    let (ac, _at, _ar) = a.split();
    let (bc, _bt, _br) = b.split();
    ac.request_stop()?;
    bc.request_stop()?;
    ac.publish_fence(0, 0, &ac.seal_send()?)?;
    bc.publish_fence(0, 0, &bc.seal_send()?)?;
    wait_ready(&ac.domain, &bc.domain).await?;
    let deadline = ac.state()?.deadline.ok_or(Error::Closed)?;
    // Peer close also runs the local maintained carrier to Clean while its owner
    // remains unconsumed. Native close must not later mistake ready inner work
    // for completion within its already expired original deadline.
    assert_eq!(bc.close().await?.status.terminal, Some(Terminal::Clean));
    tokio::time::sleep_until(deadline + Duration::from_millis(2)).await;
    assert_eq!(ac.control.status()?.terminal, Some(Terminal::Clean));
    assert!(matches!(ac.close().await, Err(Error::IncompleteClose)));
    Ok(())
}
