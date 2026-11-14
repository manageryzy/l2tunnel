//! Actual generic setup faults; controlled protocol peers are named explicitly.

use super::support::*;
use super::*;
use l2tunnel_runtime::secure_udp::{diagnostics, establish, member};

#[tokio::test(start_paused = true)]
async fn generic_queued_exact_expiry_preserves_original_observation_before_socket_work() -> Result {
    for appearance in appearances() {
        let hosts = hosts();
        let fixture = transaction_plans_with(
            appearance,
            &hosts,
            TransactionFixtureOptions {
                setup_timeout: Duration::from_millis(200),
                ..TransactionFixtureOptions::baseline()
            },
        )?;
        let held = [
            std::net::UdpSocket::bind(fixture.addresses[0])?,
            std::net::UdpSocket::bind(fixture.addresses[1])?,
        ];
        held[1].set_nonblocking(true)?;
        let (handle, run) = channel();
        let accepted = handle
            .connect(fixture.plans[0].clone(), handle.next_key().map_err(submit)?)
            .map_err(submit)?;
        let original = observation(&handle, accepted.operation)?;
        assert_eq!(original.stage, SetupStage::Accepted);
        assert_eq!(original.original_timeout_micros, 200_000);
        tokio::time::advance(Duration::from_millis(200)).await;
        let mut run = Box::pin(run);
        assert_eq!(
            single_result(&mut run, &handle, accepted.operation).await?,
            Completed::Failed(Failure {
                kind: io::ErrorKind::TimedOut
            })
        );
        let failed = observation(&handle, accepted.operation)?;
        assert_eq!(failed.stage, SetupStage::Accepted);
        assert_eq!(failed.outcome, SetupOutcome::Failed);
        assert_eq!(failed.elapsed_micros, 200_000);
        assert_eq!(
            failed.original_timeout_micros,
            original.original_timeout_micros
        );
        assert_eq!(
            failed.failure,
            Some(SetupFailure {
                kind: io::ErrorKind::TimedOut,
                reason: SetupFailureReason::OriginalDeadline
            })
        );
        assert!(failed.runtime.is_none() && handle.snapshot().generation.is_none());
        assert_unopened(&hosts);
        assert_eq!(
            held[1]
                .recv_from(&mut [0; 1])
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(observation(&handle, accepted.operation)?, failed);
        drop(run);
        drop(held);
        assert_ports_free(fixture.addresses)?;
    }
    Ok(())
}

#[tokio::test]
async fn generic_bind_failure_for_each_role_never_opens_attachment() -> Result {
    for appearance in appearances() {
        for side in 0..2 {
            let hosts = hosts();
            let fixture = transaction_plans(appearance, &hosts)?;
            let occupied = std::net::UdpSocket::bind(fixture.addresses[side])?;
            let (handle, run) = channel();
            let mut run = Box::pin(run);
            let accepted = handle
                .connect(
                    fixture.plans[side].clone(),
                    handle.next_key().map_err(submit)?,
                )
                .map_err(submit)?;
            assert_eq!(
                single_result(&mut run, &handle, accepted.operation).await?,
                Completed::Failed(Failure {
                    kind: io::ErrorKind::AddrInUse
                })
            );
            let failed = observation(&handle, accepted.operation)?;
            assert_eq!(failed.stage, SetupStage::SocketBind);
            assert_eq!(
                failed.failure,
                Some(SetupFailure {
                    kind: io::ErrorKind::AddrInUse,
                    reason: SetupFailureReason::LocalIo
                })
            );
            assert!(failed.runtime.is_none() && handle.snapshot().generation.is_none());
            assert_unopened(&hosts);
            drop(run);
            drop(occupied);
            assert_ports_free(fixture.addresses)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn generic_admission_secret_mismatch_stops_before_noise_or_device() -> Result {
    for appearance in appearances() {
        let hosts = hosts();
        let fixture = transaction_plans_with(
            appearance,
            &hosts,
            TransactionFixtureOptions {
                setup_timeout: Duration::from_millis(300),
                admission: [[44; 32], [45; 32]],
                ..TransactionFixtureOptions::baseline()
            },
        )?;
        let mut pair = Pair::new(fixture, hosts)?;
        pair.until(|pair| {
            Ok((0..2).all(|side| {
                completed(&pair.handles[side], pair.accepted[side].operation).is_some()
            }))
        })
        .await?;
        for side in 0..2 {
            assert!(matches!(
                completed(&pair.handles[side], pair.accepted[side].operation),
                Some(Completed::Failed(_))
            ));
            let failed = observation(&pair.handles[side], pair.accepted[side].operation)?;
            assert_eq!(failed.outcome, SetupOutcome::Failed);
            assert_eq!(
                failed
                    .runtime
                    .ok_or("missing actual admission evidence")?
                    .stage,
                diagnostics::Stage::Admission
            );
            assert!(failed.failure.is_some());
            assert!(pair.handles[side].snapshot().generation.is_none());
        }
        assert_unopened(&pair.hosts);
        pair.close()?;
    }
    Ok(())
}

#[tokio::test]
async fn generic_ikpsk2_mismatch_and_matching_control_use_real_noise() -> Result {
    for appearance in appearances() {
        for mismatch in [false, true] {
            let hosts = hosts();
            let fixture = transaction_plans_with(
                appearance,
                &hosts,
                TransactionFixtureOptions {
                    setup_timeout: Duration::from_millis(700),
                    noise_profile: hs::Profile::IkPsk2,
                    psk: [Some([66; 32]), Some([if mismatch { 67 } else { 66 }; 32])],
                    ..TransactionFixtureOptions::baseline()
                },
            )?;
            let mut pair = Pair::new(fixture, hosts)?;
            if !mismatch {
                pair.ready().await?;
                pair.exchange(0, 37).await?;
                pair.exchange(1, 39).await?;
            } else {
                pair.until(|pair| {
                    Ok((0..2).all(|side| {
                        completed(&pair.handles[side], pair.accepted[side].operation).is_some()
                    }))
                })
                .await?;
                for side in 0..2 {
                    assert!(matches!(
                        completed(&pair.handles[side], pair.accepted[side].operation),
                        Some(Completed::Failed(_))
                    ));
                    let failed = observation(&pair.handles[side], pair.accepted[side].operation)?;
                    assert_eq!(
                        failed.runtime.ok_or("missing actual Noise evidence")?.stage,
                        diagnostics::Stage::Noise
                    );
                    assert!(failed.failure.is_some());
                    assert!(pair.handles[side].snapshot().generation.is_none());
                }
                assert_unopened(&pair.hosts);
            }
            pair.close()?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn controlled_nonallowlisted_member_is_rejected_by_actual_generic_server() -> Result {
    for appearance in appearances() {
        let hosts = hosts();
        let fixture = transaction_plans(appearance, &hosts)?;
        let prepared::Endpoint::SecureClient(credentials) = &fixture.plans[0].data.endpoint else {
            return Err("missing actual client identity".into());
        };
        let identity = credentials.noise().attempt();
        let admission = credentials.admission();
        let selected = fixture.profile.settings();
        let config = selected.runtime(Role::Initiator, fixture.profile.peers())?;
        let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
        let other = identity::IdentityKey::from_pkcs8(&encoded)?;
        assert_ne!(other.public_key(), selected.member);
        let (server, run) = channel();
        let mut run = Box::pin(run);
        let accepted = server
            .connect(fixture.plans[1].clone(), server.next_key().map_err(submit)?)
            .map_err(submit)?;
        let socket = tokio::net::UdpSocket::bind(fixture.addresses[0]).await?;
        socket.connect(fixture.addresses[1]).await?;
        let direct = async {
            let mut entropy = establish::RuntimeEntropy::new();
            let established = establish::connect(
                socket,
                config,
                identity,
                admission,
                Instant::now() + Duration::from_secs(3),
                &mut entropy,
            )
            .await?;
            let context = identity::Context {
                session: established.root.binding().session,
                transcript: established.root.binding().transcript,
                configuration: established.authenticated.configuration,
                carrier: established.authenticated.carrier,
                outer: established.authenticated.outer,
                initiator_noise: identity::NoisePublicKey(established.peers.initiator.0),
                responder_noise: identity::NoisePublicKey(established.peers.responder.0),
            };
            Ok::<_, Error>(
                member::connect(
                    established,
                    &other,
                    member::Settings {
                        context,
                        retry_interval: selected.membership.retry_interval,
                        max_attempts: selected.membership.max_attempts,
                        receive_interval: selected.membership.receive_interval,
                        receive_packets_per_interval: selected
                            .membership
                            .receive_packets_per_interval,
                    },
                )
                .await?,
            )
        };
        let mut direct = Some(Box::pin(direct));
        timeout(Duration::from_secs(4), async {
            loop {
                drive_once(&mut run).await;
                let result =
                    std::future::poll_fn(|cx| {
                        Poll::Ready(direct.as_mut().and_then(
                            |future| match future.as_mut().poll(cx) {
                                Poll::Ready(result) => Some(result),
                                Poll::Pending => None,
                            },
                        ))
                    })
                    .await;
                if let Some(result) = result {
                    assert!(result.is_err());
                    drop(direct.take());
                }
                if completed(&server, accepted.operation).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        assert!(matches!(
            completed(&server, accepted.operation),
            Some(Completed::Failed(_))
        ));
        let failed = observation(&server, accepted.operation)?;
        assert_eq!(failed.stage, SetupStage::Membership);
        assert_eq!(
            failed.failure,
            Some(SetupFailure {
                kind: io::ErrorKind::PermissionDenied,
                reason: SetupFailureReason::Runtime(diagnostics::Reason::Authentication)
            })
        );
        assert_unopened(&hosts);
        drop(direct);
        drop(run);
        assert_ports_free(fixture.addresses)?;
    }
    Ok(())
}

struct InvalidDescriptor {
    drops: Arc<AtomicUsize>,
    io_calls: Arc<AtomicUsize>,
}
impl Drop for InvalidDescriptor {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl AsRawFd for InvalidDescriptor {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        -1
    }
}
impl PacketDevice for InvalidDescriptor {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, _bytes: &mut [u8]) -> io::Result<Option<usize>> {
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::WouldBlock.into())
    }
    fn transmit(&mut self, _bytes: &[u8]) -> io::Result<()> {
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::WouldBlock.into())
    }
}

#[tokio::test]
async fn generic_authenticated_provider_descriptor_and_budget_failures_never_publish_ready()
-> Result {
    const SENTINEL: &str = "PRIVATE_GENERIC_PROVIDER_SENTINEL secret=do-not-copy";
    for appearance in appearances() {
        for cause in 0..3 {
            let hosts = hosts();
            let mut fixture = transaction_plans_with(
                appearance,
                &hosts,
                TransactionFixtureOptions {
                    retained_bytes: if cause == 2 { 1 } else { 16 * 1024 * 1024 },
                    ..TransactionFixtureOptions::baseline()
                },
            )?;
            let opened = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let io_calls = Arc::new(AtomicUsize::new(0));
            if cause < 2 {
                let (opened, drops, io_calls) = (opened.clone(), drops.clone(), io_calls.clone());
                Arc::get_mut(&mut fixture.plans[0].data)
                    .ok_or("fixture plan already shared")?
                    .attachment = Attachment::readable(PacketLayer::Ip, move || {
                    opened.fetch_add(1, Ordering::SeqCst);
                    if cause == 0 {
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, SENTINEL));
                    }
                    Ok(crate::swift::Native::new(InvalidDescriptor {
                        drops: drops.clone(),
                        io_calls: io_calls.clone(),
                    }))
                });
            }
            let mut pair = Pair::new(fixture, hosts)?;
            let operation = pair.accepted[0].operation;
            let result = pair.result(0, operation).await?;
            let Completed::Failed(failure) = result else {
                return Err("fault reached actual readiness".into());
            };
            let failed = observation(&pair.handles[0], operation)?;
            assert_eq!(failed.outcome, SetupOutcome::Failed);
            assert_eq!(
                failed
                    .runtime
                    .ok_or("post-auth fault omitted membership")?
                    .stage,
                diagnostics::Stage::Membership
            );
            assert!(pair.handles[0].snapshot().generation.is_none());
            assert!(pair.handles[0].snapshot().runtime.is_none());
            assert!(!format!("{failed:?}").contains(SENTINEL));
            assert!(!format!("{failed:?}").contains("do-not-copy"));
            let response = pair.handles[0]
                .lifecycle_request(v3(local::Action::Status {}))
                .await;
            let json = serde_json::to_string(&response)?;
            assert!(!json.contains(SENTINEL) && !json.contains("do-not-copy"));
            if cause == 0 {
                assert_eq!(failure.kind, io::ErrorKind::PermissionDenied);
                assert_eq!(failed.stage, SetupStage::Attachment);
                assert_eq!(
                    failed.failure.map(|failure| failure.reason),
                    Some(SetupFailureReason::LocalIo)
                );
            } else {
                assert_eq!(failed.stage, SetupStage::DriverReadiness);
                assert_eq!(
                    failed.failure.map(|failure| failure.reason),
                    Some(SetupFailureReason::ReadinessEnded)
                );
                assert_ne!(failure.kind, io::ErrorKind::TimedOut);
            }
            if cause < 2 {
                assert_eq!(opened.load(Ordering::SeqCst), 1);
            }
            if cause == 1 {
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert_eq!(io_calls.load(Ordering::SeqCst), 0);
            }
            if cause == 2 {
                // Known-budget admission preserves io::Error::other(Swift Budget).
                // The service exposes its kind; this is not an invalid layout or allocator failure.
                assert_eq!(failure.kind, io::ErrorKind::Other);
                assert_eq!(pair.hosts[0].opened.load(Ordering::SeqCst), 1);
                assert_eq!(pair.fixture.profile.parameters().retained_bytes, 1);
                assert_eq!(pair.fixture.profile.catalog().descriptors().len(), 2);
                for stream in pair
                    .fixture
                    .profile
                    .runtime_contract(Role::Initiator)?
                    .config()
                    .streams
                    .ok_or("missing actual bounded streams")?
                    .streams
                {
                    assert!(
                        l2tunnel_recovery::storage::Plan::for_arq(stream.delivery.recovery)?
                            .capacity_bytes()
                            > 1
                    );
                }
            }
            let _rebound = std::net::UdpSocket::bind(pair.fixture.addresses[0])?;
            drop(_rebound);
            pair.close()?;
        }
    }
    Ok(())
}
