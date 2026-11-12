use super::*;
use l2tunnel_auth::{
    AuthenticatedConnection, ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect,
    server_accept,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

mod failure;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

fn runtime() -> RuntimeConfig {
    RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: Compression::None,
        queue_packets: 8,
        poll_interval: Duration::from_millis(1),
    }
}
async fn connections(
    runtime: RuntimeConfig,
    settings: &Config,
) -> Result<Vec<(AuthenticatedConnection, AuthenticatedConnection)>, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["active.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allowlist = MemberAllowlist::new(&[member.public_key()])?;
    let binding = super::super::session_config(runtime, settings)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut result = Vec::new();
    for _ in 0..if settings.initial.duplex == Duplex::Half {
        2
    } else {
        1
    } {
        let client_tcp = TcpStream::connect(listener.local_addr()?).await?;
        client_tcp.set_nodelay(true)?;
        let (server_tcp, _) = listener.accept().await?;
        server_tcp.set_nodelay(true)?;
        let pair = tokio::try_join!(
            client_connect(
                client_tcp,
                &client_tls,
                "active.test",
                &member,
                binding,
                Duration::from_secs(5)
            ),
            server_accept(
                server_tcp,
                &server_tls,
                &allowlist,
                binding,
                Duration::from_secs(5)
            ),
        )?;
        result.push(pair);
    }
    Ok(result)
}
async fn links(runtime: RuntimeConfig, settings: &Config) -> Result<(Link, Link), TestError> {
    let mut connected = connections(runtime, settings).await?.into_iter();
    let (client, server) = connected.next().ok_or("missing authenticated lane")?;
    if settings.initial.duplex == Duplex::Half {
        let (client2, server2) = connected.next().ok_or("missing second lane")?;
        Ok(tokio::try_join!(
            crate::client_pair(client, client2),
            crate::server_pair(server, server2)
        )?)
    } else {
        Ok((Link::full(client), Link::full(server)))
    }
}
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
    blocked: bool,
    reads: usize,
    smallest_buffer: Option<usize>,
}
#[derive(Clone, Default)]
struct Device {
    state: Arc<Mutex<Native>>,
}
impl Device {
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("test device poisoned"))?;
        Ok(f(&mut state))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        self.change(|state| {
            state.reads += 1;
            state.smallest_buffer = Some(
                state
                    .smallest_buffer
                    .map_or(output.len(), |old| old.min(output.len())),
            );
            state.outgoing.pop_front().map(|packet| {
                output[..packet.len()].copy_from_slice(&packet);
                packet.len()
            })
        })
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.change(|state| {
            if state.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            state.delivered.push(packet.to_vec());
            Ok(())
        })?
    }
}
fn packet(port: u16, value: u8, reverse: bool, dscp: u8) -> Vec<u8> {
    let mut bytes = vec![value; 400];
    bytes[..40].fill(0);
    bytes[0] = 0x45;
    bytes[1] = dscp << 2;
    bytes[2..4].copy_from_slice(&400_u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    let (a, b, sport, dport) = if reverse {
        (2, 1, 443, port)
    } else {
        (1, 2, port, 443)
    };
    bytes[12..16].copy_from_slice(&[10, 0, 0, a]);
    bytes[16..20].copy_from_slice(&[10, 0, 0, b]);
    bytes[20..22].copy_from_slice(&sport.to_be_bytes());
    bytes[22..24].copy_from_slice(&dport.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    bytes
}

fn managed(runtime: RuntimeConfig, duplex: Duplex, adaptive: bool) -> io::Result<Config> {
    let initial = active::Settings {
        channels: 1,
        max_flows: 4,
        adaptive,
        ..active::Settings::new(runtime, duplex)?
    };
    let old = Mode::from_settings(initial);
    let mut wide = old;
    wide.channels = 256;
    wide.dscp_weights[8] = 4;
    let mut narrow = old;
    narrow.channels = 2;
    narrow.dscp_weights[8] = 2;
    Ok(Config {
        initial,
        supported: vec![old, wide, narrow],
        transaction: transaction::Settings::default(),
    })
}
async fn until(
    handle: &ControlHandle,
    predicate: impl Fn(&Status) -> bool,
) -> Result<Status, TestError> {
    let mut state = handle.subscribe();
    Ok(timeout(Duration::from_secs(5), async {
        loop {
            if let Some(value) = state
                .borrow_and_update()
                .clone()
                .filter(|value| predicate(value))
            {
                return Ok::<_, io::Error>(value);
            }
            state.changed().await.map_err(io::Error::other)?;
        }
    })
    .await??)
}
fn grouped(actual: &[Vec<u8>], expected: &[Vec<u8>]) -> bool {
    actual.len() == expected.len()
        && (1000_u16..1004).all(|port| {
            let select = |packet: &&Vec<u8>| {
                packet[20..22] == port.to_be_bytes() || packet[22..24] == port.to_be_bytes()
            };
            actual
                .iter()
                .filter(select)
                .eq(expected.iter().filter(select))
        })
}

#[tokio::test]
async fn actual_tls_switches_channel_count_and_weights_both_duplex_and_target_profiles()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for adaptive in [false, true] {
            let runtime = runtime();
            let config = managed(runtime, duplex, adaptive)?;
            let (ll, rl) = links(runtime, &config).await?;
            let left = Device::default();
            let right = Device::default();
            let (lh, lr) = channel();
            let (rh, rr) = channel();
            let mut jobs = JoinSet::new();
            jobs.spawn(run(left.clone(), ll, runtime, config.clone(), lr));
            jobs.spawn(run(right.clone(), rl, runtime, config.clone(), rr));
            let (mut originals, mut reversed) = (Vec::new(), Vec::new());
            for round in 0..3_u8 {
                let forward: Vec<_> = (1000..1004)
                    .map(|port| packet(port, round, false, 8))
                    .collect();
                let reverse: Vec<_> = (1000..1004)
                    .map(|port| packet(port, round, true, 8))
                    .collect();
                left.change(|s| s.outgoing.extend(forward.clone()))?;
                right.change(|s| s.outgoing.extend(reverse.clone()))?;
                originals.extend(forward);
                reversed.extend(reverse);
                until(&rh, |s| s.traffic.delivered == originals.len() as u64).await?;
                until(&lh, |s| s.traffic.delivered == reversed.len() as u64).await?;
                if round < 2 {
                    let mode = config.supported[usize::from(round) + 1];
                    let outcome = timeout(Duration::from_secs(5), lh.switch_policy(mode)).await??;
                    assert_eq!(outcome.mode, mode);
                    assert_eq!(outcome.epoch, Epoch(u64::from(round) + 2));
                    let follower = until(&rh, |s| s.epoch == outcome.epoch && s.admitting).await?;
                    assert_eq!(follower.mode, mode);
                    assert_eq!(follower.traffic.engine.incoming_flows, 0);
                    assert_eq!(follower.traffic.engine.outgoing_flows, 0);
                }
            }
            assert!(grouped(&right.change(|s| s.delivered.clone())?, &originals));
            assert!(grouped(&left.change(|s| s.delivered.clone())?, &reversed));
            assert_eq!(lh.status().ok_or("status")?.traffic.retired_flows, 8);
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
            assert!(!lh.status().ok_or("stopped")?.traffic.running);
        }
    }
    Ok(())
}

#[tokio::test]
async fn blocked_native_and_pending_originals_hold_old_epoch_until_exact_drain() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let runtime = runtime();
        let config = managed(runtime, duplex, false)?;
        let (ll, rl) = links(runtime, &config).await?;
        let left = Device::default();
        let right = Device::default();
        right.change(|s| s.blocked = true)?;
        let originals: Vec<_> = (0..40)
            .map(|n| packet(1000 + n % 4, n as u8, false, 8))
            .collect();
        left.change(|s| s.outgoing.extend(originals.clone()))?;
        let (lh, lr) = channel();
        let (rh, rr) = channel();
        let mut jobs = JoinSet::new();
        jobs.spawn(run(left.clone(), ll, runtime, config.clone(), lr));
        jobs.spawn(run(right.clone(), rl, runtime, config.clone(), rr));
        until(&rh, |s| s.traffic.engine.receiver_payload.records > 0).await?;
        let handle = lh.clone();
        let mode = config.supported[1];
        let proposal = tokio::spawn(async move { handle.switch_policy(mode).await });
        let frozen = until(&lh, |s| !s.admitting && s.phase != Phase::Idle).await?;
        let reads = left.change(|s| s.reads)?;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!proposal.is_finished());
        assert_eq!(lh.status().ok_or("phase")?.epoch, Epoch(1));
        assert_eq!(left.change(|s| s.reads)?, reads);
        assert_eq!(rh.status().ok_or("native")?.traffic.delivered, 0);
        right.change(|s| s.blocked = false)?;
        assert_eq!(
            timeout(Duration::from_secs(5), proposal).await???.epoch,
            Epoch(2)
        );
        until(&rh, |s| s.traffic.delivered == originals.len() as u64).await?;
        assert!(grouped(&right.change(|s| s.delivered.clone())?, &originals));
        assert!(frozen.traffic.admitted < originals.len() as u64);
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
    }
    Ok(())
}

#[tokio::test]
async fn unsupported_role_and_catalog_requests_do_not_start_or_mutate_transactions() -> TestResult {
    let runtime = runtime();
    let config = managed(runtime, Duplex::Half, false)?;
    let (ll, rl) = links(runtime, &config).await?;
    let (lh, lr) = channel();
    let (rh, rr) = channel();
    let mut jobs = JoinSet::new();
    jobs.spawn(run(Device::default(), ll, runtime, config.clone(), lr));
    jobs.spawn(run(Device::default(), rl, runtime, config.clone(), rr));
    until(&lh, |s| s.admitting).await?;
    until(&rh, |s| s.admitting).await?;
    let mut invalid_mode = config.supported[0];
    invalid_mode.dscp_weights[63] = 123;
    assert_eq!(
        lh.switch_policy(invalid_mode).await,
        Err(ControlError::Unsupported)
    );
    assert_eq!(
        rh.switch_policy(config.supported[1]).await,
        Err(ControlError::NotCoordinator)
    );
    assert_eq!(lh.status().ok_or("status")?.epoch, Epoch(1));
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    assert_eq!(
        lh.switch_policy(config.supported[1]).await,
        Err(ControlError::Closed)
    );
    Ok(())
}

#[tokio::test]
async fn authenticated_catalog_mismatch_fails_before_native_read() -> TestResult {
    let runtime = runtime();
    let config = managed(runtime, Duplex::Full, false)?;
    let (ll, _rl) = links(runtime, &config).await?;
    let mut mismatched = config.clone();
    mismatched.supported[1].dscp_weights[0] = 5;
    let device = Device::default();
    let (_handle, receiver) = channel();
    assert!(
        run(device.clone(), ll, runtime, mismatched, receiver)
            .await
            .is_err()
    );
    assert_eq!(device.change(|s| s.reads)?, 0);
    Ok(())
}

#[tokio::test]
async fn cancellation_during_drain_reports_closed_and_keeps_last_epoch() -> TestResult {
    let runtime = runtime();
    let config = managed(runtime, Duplex::Half, false)?;
    let (ll, rl) = links(runtime, &config).await?;
    let left = Device::default();
    let right = Device::default();
    left.change(|s| s.outgoing.push_back(packet(1000, 1, false, 0)))?;
    right.change(|s| s.blocked = true)?;
    let (lh, lr) = channel();
    let (rh, rr) = channel();
    let mut jobs = JoinSet::new();
    jobs.spawn(run(left, ll, runtime, config.clone(), lr));
    jobs.spawn(run(right, rl, runtime, config.clone(), rr));
    until(&rh, |s| s.traffic.engine.receiver_payload.records > 0).await?;
    let local = lh.clone();
    let mode = config.supported[1];
    let request = tokio::spawn(async move { local.switch_policy(mode).await });
    until(&lh, |s| s.phase != Phase::Idle).await?;
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    assert_eq!(request.await?, Err(ControlError::Closed));
    assert_eq!(lh.status().ok_or("state")?.epoch, Epoch(1));
    assert!(!lh.status().ok_or("state")?.admitting);
    Ok(())
}

#[tokio::test]
async fn precommit_timeout_never_installs_or_confirms_blocked_native_payload() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let runtime = runtime();
        let mut config = managed(runtime, duplex, false)?;
        config.transaction = transaction::Settings {
            retry_ms: 20,
            phase_timeout_ms: 120,
            reconcile_timeout_ms: 1000,
        };
        let (ll, rl) = links(runtime, &config).await?;
        let left = Device::default();
        let right = Device::default();
        let original = packet(1000, 19, false, 8);
        left.change(|s| s.outgoing.push_back(original.clone()))?;
        right.change(|s| s.blocked = true)?;
        let (lh, lr) = channel();
        let (rh, rr) = channel();
        let mut jobs = JoinSet::new();
        jobs.spawn(run(left, ll, runtime, config.clone(), lr));
        jobs.spawn(run(right.clone(), rl, runtime, config.clone(), rr));
        until(&rh, |s| s.traffic.engine.receiver_payload.records == 1).await?;
        let outcome = timeout(
            Duration::from_secs(2),
            lh.switch_policy(config.supported[1]),
        )
        .await?;
        assert!(matches!(
            outcome,
            Err(ControlError::Aborted | ControlError::Closed)
        ));
        assert_eq!(lh.status().ok_or("aborted status")?.epoch, Epoch(1));
        assert_eq!(
            rh.status()
                .ok_or("retained")?
                .traffic
                .engine
                .receiver_payload
                .records,
            1
        );
        assert!(right.change(|s| s.delivered.is_empty())?);
        // The preserved transaction machine can expire the follower's phase
        // first. That is terminal, not an authorized local rollback/resume.
        if outcome == Err(ControlError::Closed) {
            let ended = timeout(Duration::from_secs(1), jobs.join_next())
                .await?
                .ok_or("no failed task")??;
            assert!(ended.is_err());
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
            assert!(!lh.status().ok_or("closed state")?.admitting);
            continue;
        }
        right.change(|s| s.blocked = false)?;
        until(&rh, |s| s.traffic.delivered == 1 && s.admitting).await?;
        assert_eq!(right.change(|s| s.delivered.clone())?, vec![original]);
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
    }
    Ok(())
}

#[test]
fn bounded_management_retry_identity_ignores_only_replay_number_until_actual_flush() -> TestResult {
    let runtime = runtime();
    let config = managed(runtime, Duplex::Full, false)?;
    let catalog = config.catalog(runtime)?;
    let mut peer = Peer::new(
        Identity {
            session: SessionId([1; 16]),
            role: Role::Client,
            local: EndpointId(1),
            remote: EndpointId(2),
            lane: LaneId(0),
        },
        Epoch(1),
        catalog.initial.clone(),
        &catalog.policies,
        config.transaction,
        Tick(0),
    )?;
    peer.propose(catalog.policies[1].clone(), Tick(0))?;
    let message = peer
        .staged(Fence::new(&[0])?, Tick(0))?
        .outbound
        .ok_or("prepare")?;
    let (sender, mut receiver) = mpsc::channel(SLOTS);
    let (flushed, rx) = watch::channel(0);
    let mut output = Output {
        sender,
        flushed: rx,
        pending: VecDeque::new(),
        produced: 0,
    };
    output.send(message.clone())?;
    for n in 1..8 {
        let retry = peer
            .poll(Tick(n * config.transaction.retry_ms))?
            .outbound
            .ok_or("retry")?;
        output.send(retry)?;
    }
    assert_eq!(output.produced, 1);
    assert_eq!(output.pending.len(), 1);
    let queued = receiver.try_recv()?;
    assert_eq!(queued.body, message);
    assert!(!output.drained());
    let mut changed = message.clone();
    let end = changed.len() - 1;
    changed[end] ^= 1;
    assert!(output.send(changed).is_err());
    flushed.send_replace(1);
    assert!(output.drained());
    output.send(message)?;
    assert_eq!(output.produced, 2);
    Ok(())
}
