//! Explicit shared service composition using actual authenticated original UDP.
//! These unprivileged packet devices prove lifecycle/bytes, not native rwnd.
use super::*;

fn fixture(hosts: &[Arc<Host>; 2]) -> Result<([Prepared; 2], common_transaction_profile::Profile)> {
    fixture_selected(hosts, false)
}
pub(super) fn fixture_selected(
    hosts: &[Arc<Host>; 2],
    retained_close: bool,
) -> Result<([Prepared; 2], common_transaction_profile::Profile)> {
    fixture_profile(hosts, retained_close, false)
}
fn fixture_profile(
    hosts: &[Arc<Host>; 2],
    retained_close: bool,
    measured: bool,
) -> Result<([Prepared; 2], common_transaction_profile::Profile)> {
    let TransactionPlans {
        plans,
        profile: old,
        ..
    } = transaction_plans(l2tunnel_cover::Appearance::QuicLike, hosts)?;
    let mut resources = [
        old.runtime_contract(Role::Initiator)?.config(),
        old.runtime_contract(Role::Responder)?.config(),
    ];
    for resource in &mut resources {
        resource.report_interval = Some(Duration::from_millis(1));
        resource.path_mtu = 2000;
        if let Some(streams) = resource.streams.as_mut() {
            for stream in &mut streams.streams {
                stream.path_mtu = 2000;
            }
        }
    }
    let mut connection = old.connection();
    connection.max_packet = 1280;
    let native = 1600;
    let direction = |resource: transport::Config| -> Result<common::CommonDirection> {
        let original = common_direction(1, native, resource.send.bytes_per_second)?;
        Ok(common::CommonDirection::new(
            traffic::TrafficPolicy {
                tcp: traffic::TcpControl::SplitTcpProxy,
                ..original.traffic()
            },
            original.pipeline(),
            original.bytes_per_second(),
            original.burst_bytes(),
            common::NativeWindow::Disabled,
        )?)
    };
    let mut forward = aligned_direction(native, 1, resources[0].control.wire_overhead, false);
    let mut reverse = aligned_direction(native, 1, resources[1].control.wire_overhead, false);
    for policy in [&mut forward, &mut reverse] {
        policy.receiver.body.symbol_bytes = 1664;
        let original = 48 + policy.receiver.body.symbol_bytes;
        let wrapped = 44 + original;
        policy.recovery.arq.max_source_bytes = original;
        policy.recovery.arq.send_bytes = 8 * original;
        policy.recovery.arq.receive_bytes = 8 * original;
        policy.recovery.fec.block.max_source_bytes = wrapped;
        policy.recovery.fec.block.max_packet_bytes = 56 + 2 + 2 + wrapped;
        policy.recovery.repair_symbols = 0;
        policy.recovery.max_restored_bytes = policy.recovery.max_restored_packets * wrapped;
        policy.max_recovery_packet_bytes =
            policy.recovery.maximum_packet_bytes().map_err(|error| {
                io::Error::other(format!("Common proxy fixture recovery geometry: {error}"))
            })?;
    }
    let descriptor = common::Descriptor::new(
        2000,
        Duplex::Full,
        direction(resources[0])?,
        direction(resources[1])?,
        common::Profile::Aligned { forward, reverse },
    )?;
    let prefix = crate::proxy::IpPrefix::new("10.112.0.0".parse()?, 24)?;
    let mut fixed = crate::proxy::Settings::new(crate::proxy::RoutePolicy::new(vec![
        crate::proxy::RouteRule {
            source: prefix,
            destination: prefix,
            ports: crate::proxy::PortRange {
                first: 443,
                last: 443,
            },
        },
    ])?);
    fixed.channels = 1;
    let mut proxy = crate::proxy::runtime_config(connection, &fixed)?;
    proxy.relay.max_record_bytes = 512;
    proxy.relay.maximum = l2tunnel_tcp_proxy::Window {
        bytes: 2048,
        records: 8,
    };
    proxy.relay.initial = l2tunnel_tcp_proxy::Window {
        bytes: 1024,
        records: 4,
    };
    proxy.native.send_bytes = 4096;
    proxy.native.receive_bytes = 4096;
    if retained_close {
        // Explicit finite fixture policy, bound into the same authenticated H0;
        // production defaults and the old v1 fixture remain unchanged.
        proxy.timeouts.shutdown = Duration::from_secs(2);
    }
    let mut parameters = old.parameters();
    parameters.retained_bytes = 64 * 1024 * 1024;
    let catalog = common::Catalog::new(descriptor, &[descriptor])?;
    let legacy = common_transaction_profile::Profile::new_proxy(
        connection,
        old.settings(),
        old.peers(),
        resources[0],
        resources[1],
        catalog.clone(),
        parameters,
        proxy.clone(),
    )?;
    let profile = if measured {
        let selected = common_transaction_profile::Profile::new_proxy_measured_retained(
            connection,
            old.settings(),
            old.peers(),
            resources[0],
            resources[1],
            catalog,
            parameters,
            measured_common::config(proxy)?,
        )?;
        assert_ne!(selected.configuration()?, legacy.configuration()?);
        assert!(selected.proxy_retirement());
        selected
    } else if retained_close {
        let selected = common_transaction_profile::Profile::new_proxy_retained(
            connection,
            old.settings(),
            old.peers(),
            resources[0],
            resources[1],
            catalog,
            parameters,
            proxy,
        )?;
        assert_ne!(
            selected.configuration()?,
            legacy.configuration()?,
            "retained close must be selected before actual Noise/member admission"
        );
        assert!(!legacy.proxy_retirement());
        assert!(selected.proxy_retirement());
        selected
    } else {
        legacy
    };
    let convert = |plan: Prepared| -> Result<Prepared> {
        let data = Arc::try_unwrap(plan.data).map_err(|_| "unstarted plan unexpectedly shared")?;
        match data.endpoint {
            prepared::Endpoint::SecureClient(credentials) => Ok(Prepared::proxy_common_client(
                profile.clone(),
                credentials,
                data.attachment,
            )?),
            prepared::Endpoint::SecureServer(server) => Ok(Prepared::proxy_common_server(
                profile.clone(),
                server.credentials,
                data.attachment,
            )?),
            _ => Err("unstarted endpoint mismatch".into()),
        }
    };
    let [a, b] = plans;
    Ok(([convert(a)?, convert(b)?], profile))
}
pub(super) fn proxy_frame(handle: &Handle) -> Result<ProxyFrame> {
    handle
        .snapshot()
        .runtime
        .and_then(|value| value.proxy().cloned())
        .ok_or_else(|| "actual proxy observation missing".into())
}

#[test]
fn explicit_common_proxy_policy_is_bound_and_cannot_use_transparent_service() -> Result {
    let hosts = support::hosts();
    let ([client, _], profile) = fixture(&hosts)?;
    let config = profile
        .proxy_config()
        .ok_or("selected fixed proxy config")?;
    assert_eq!(config.mux.channels, 1);
    let mut changed = config.clone();
    changed.timeouts.control_idle += Duration::from_millis(1);
    assert_ne!(
        l2tunnel_runtime::proxy::session_config(config)?.digest,
        l2tunnel_runtime::proxy::session_config(&changed)?.digest
    );
    let data = Arc::try_unwrap(client.data).map_err(|_| "unstarted plan unexpectedly shared")?;
    let prepared::Endpoint::SecureClient(credentials) = data.endpoint else {
        return Err("client endpoint mismatch".into());
    };
    assert!(Prepared::secure_udp_common_client(profile, credentials, data.attachment).is_err());
    support::assert_unopened(&hosts);
    Ok(())
}

#[tokio::test]
async fn actual_common_proxy_shared_service_retains_bytes_liveness_and_release() -> Result {
    timeout(Duration::from_secs(35), async {
        let hosts = support::hosts();
        let ([a, b], profile) = fixture(&hosts)?;
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
        let accepted = [
            client
                .connect(a, client.next_key().map_err(submit)?)
                .map_err(submit)?,
            server
                .connect(b, server.next_key().map_err(submit)?)
                .map_err(submit)?,
        ];
        tokio::try_join!(
            connected(&client, accepted[0]),
            connected(&server, accepted[1])
        )?;
        let handles = [client, server];
        for (side, handle) in handles.iter().enumerate() {
            let frame = proxy_frame(handle)?;
            assert!(frame.common_record_composition);
            assert!(!frame.exact_tcp_rwnd_control);
            assert_eq!(frame.requested_digest, frame.effective_digest);
            let common = frame.common.ok_or("actual Common composition absent")?;
            assert!(common.installed && common.running && !common.hot_switch);
            assert!(!common.graceful_close);
            assert_eq!(common.requested_configuration, profile.configuration()?);
            assert_eq!(
                common.requested_configuration,
                common.effective_configuration
            );
            assert_eq!(common.requested_carrier, common.effective_carrier);
            assert_eq!(common.effective_cover, Some(common.requested_cover));
            let path = profile.settings().gate.path;
            assert_eq!(
                common.local_addr,
                if side == 0 { path.client } else { path.server }
            );
            assert_eq!(
                common.peer_addr,
                if side == 0 { path.server } else { path.client }
            );
            assert_eq!(
                handle.apply_common(profile.initial(), handle.next_key().map_err(submit)?),
                Err(SubmitError::Unsupported)
            );
        }
        for side in 0..2 {
            let mut bytes = vec![0x51 + side as u8; 120];
            bytes[..40].fill(0);
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&80_u16.to_be_bytes());
            bytes[6] = 253;
            bytes[7] = 64;
            bytes[8] = 0xfd;
            bytes[23] = 1;
            bytes[24] = 0xfd;
            bytes[39] = 2;
            hosts[side].send(&bytes)?;
            hosts[1 - side].expect(&bytes).await?;
        }
        exchange_native_tcp(&hosts, &handles).await?;
        for handle in &handles {
            assert_eq!(
                proxy_frame(handle)?
                    .runtime
                    .ok_or("actual actor status")?
                    .flows,
                1
            );
        }
        timeout(Duration::from_secs(3), async {
            while handles.iter().any(|handle| {
                proxy_frame(handle)
                    .ok()
                    .and_then(|f| f.common)
                    .is_none_or(|f| f.liveness.last_pong_micros.is_none())
            }) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        let accepted = handles[0]
            .apply(
                local::Request {
                    version: local::VERSION,
                    action: local::Action::DrainProxy {},
                },
                handles[0].next_key().map_err(submit)?,
            )
            .map_err(submit)?;
        assert!(matches!(
            handles[0].wait(accepted.operation).await.map_err(submit)?,
            Completed::Applied(_)
        ));
        timeout(Duration::from_secs(15), async {
            while handles
                .iter()
                .any(|handle| proxy_frame(handle).is_ok_and(|frame| !frame.released))
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        for handle in &handles {
            let frame = proxy_frame(handle)?;
            assert!(frame.released && !frame.releasing);
            assert!(
                matches!(frame.terminal, Some(local::ProxyTerminal::Failed { .. })),
                "unsupported Common graceful close must remain a failure: {frame:?}"
            );
            assert_eq!(
                frame.runtime.as_ref().map(|status| status.phase),
                Some(l2tunnel_runtime::proxy::Phase::Failed)
            );
            assert_eq!(handle.snapshot().phase, Phase::Failed);
            assert!(
                frame
                    .common
                    .is_some_and(|common| !common.running && !common.graceful_close)
            );
            let generation = handle.snapshot().generation.ok_or("retained generation")?;
            assert!(
                handle
                    .proxy_close_report(generation)
                    .map_err(submit)?
                    .is_none()
            );
        }
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        drop(handles);
        // Run deliberately keeps the local service available after release.
        // Drop that now-idle owner only after every actual backend join above.
        for task in tasks {
            task.abort();
            assert!(task.await.is_err_and(|error| error.is_cancelled()));
        }
        Ok::<_, Error>(())
    })
    .await??;
    Ok(())
}

// Independent maintained native endpoints drive the real packet attachment.
// This is test orchestration only; production still owns exactly one proxy Table.
pub(super) async fn exchange_native_tcp(hosts: &[Arc<Host>; 2], handles: &[Handle; 2]) -> Result {
    exchange_native_tcp_mtu(hosts, handles, 1280).await
}
pub(super) async fn exchange_native_tcp_mtu(
    hosts: &[Arc<Host>; 2],
    handles: &[Handle; 2],
    mtu: usize,
) -> Result {
    use l2tunnel_raw_tcp::{Error as TcpError, ReadOutcome, TcpEngine};
    use l2tunnel_tcp_proxy::{Millis, Role as TcpRole, TcpIpConfig};
    let local: std::net::SocketAddr = ([10, 112, 0, 1], 32001).into();
    let peer: std::net::SocketAddr = ([10, 112, 0, 2], 443).into();
    let make = |server| -> Result<TcpEngine> {
        Ok(TcpEngine::new_ip(
            TcpIpConfig {
                local: if server { peer } else { local },
                peer: if server { local } else { peer },
                mtu,
                send_bytes: 4096,
                receive_bytes: 4096,
                packet_slots: 8,
                random_seed: if server { 59 } else { 37 },
                ack_delay_millis: 0,
                keepalive_millis: 1000,
                idle_timeout_millis: 30000,
            },
            if server {
                TcpRole::Server
            } else {
                TcpRole::Client
            },
            Millis(0),
        )?)
    };
    let mut engines = [make(false)?, make(true)?];
    let inputs = [
        (0..7001).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
        (0..4099).map(|i| (i % 239) as u8).collect::<Vec<_>>(),
    ];
    let start = Instant::now();
    let mut sent = [0; 2];
    let mut got = [Vec::new(), Vec::new()];
    let mut closed = [false; 2];
    let mut eof = [false; 2];
    timeout(Duration::from_secs(15), async {
        loop {
            for side in 0..2 {
                let engine = &mut engines[side];
                if sent[side] < inputs[side].len() {
                    match engine.write(&inputs[side][sent[side]..]) {
                        Ok(bytes) => sent[side] += bytes,
                        Err(TcpError::NotConnected) => {}
                        Err(error) => return Err(Error::from(error)),
                    }
                }
                if sent[side] == inputs[side].len() && !closed[side] {
                    engine.close();
                    closed[side] = true;
                }
                let mut output = [0; 777];
                match engine.read(&mut output)? {
                    ReadOutcome::Data(bytes) => got[side].extend_from_slice(&output[..bytes]),
                    ReadOutcome::Eof => eof[side] = true,
                    ReadOutcome::Pending => {}
                }
                engine.poll(Millis(start.elapsed().as_millis().try_into()?), 16)?;
                while let Some(packet) = engine.pop_packet() {
                    hosts[side].send(&packet)?;
                }
                let mut packet = [0; 2048];
                let application = hosts[side]
                    .application
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let socket = application.as_ref().ok_or("native attachment not open")?;
                for _ in 0..4 {
                    match socket.recv(&mut packet) {
                        Ok(bytes) => engine.ingest(&packet[..bytes])?,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            if eof == [true, true] {
                return Ok::<_, Error>(());
            }
            for handle in handles {
                let frame = proxy_frame(handle)?;
                if frame
                    .runtime
                    .as_ref()
                    .is_some_and(|status| status.phase == l2tunnel_runtime::proxy::Phase::Failed)
                {
                    return Err(format!("actual Common proxy failed: {frame:?}").into());
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await??;
    assert_eq!(got[0], inputs[1]);
    assert_eq!(got[1], inputs[0]);
    Ok(())
}

#[tokio::test]
async fn common_proxy_abnormal_disconnect_observes_release_without_clean_close() -> Result {
    timeout(Duration::from_secs(10), async {
        let hosts = support::hosts();
        let ([a, b], profile) = fixture(&hosts)?;
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let tasks = [tokio::spawn(client_run), tokio::spawn(server_run)];
        let accepted = [
            client
                .connect(a, client.next_key().map_err(submit)?)
                .map_err(submit)?,
            server
                .connect(b, server.next_key().map_err(submit)?)
                .map_err(submit)?,
        ];
        tokio::try_join!(
            connected(&client, accepted[0]),
            connected(&server, accepted[1])
        )?;
        let handles = [client, server];
        for handle in &handles {
            let key = handle.next_key().map_err(submit)?;
            let accepted = handle.disconnect(key).map_err(submit)?;
            assert_eq!(handle.disconnect(key).map_err(submit)?, accepted);
            assert_eq!(
                handle.wait(accepted.operation).await.map_err(submit)?,
                Completed::Aborted
            );
            let frame = proxy_frame(handle)?;
            assert!(frame.released && !frame.releasing);
            assert_eq!(frame.release_deadline, accepted.deadline);
            assert!(matches!(
                frame.terminal,
                Some(local::ProxyTerminal::Failed { .. })
            ));
            assert!(
                frame
                    .common
                    .is_some_and(|common| common.installed && !common.running)
            );
        }
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        support::assert_ports_free([
            profile.settings().gate.path.client,
            profile.settings().gate.path.server,
        ])?;
        drop(handles);
        // Run deliberately keeps the local service available after release.
        // Drop that now-idle owner only after every actual backend join above.
        for task in tasks {
            task.abort();
            assert!(task.await.is_err_and(|error| error.is_cancelled()));
        }
        Ok::<_, Error>(())
    })
    .await??;
    Ok(())
}

#[path = "proxy_common_retirement.rs"]
mod retirement;

#[cfg(target_os = "linux")]
#[path = "proxy_common_cli.rs"]
mod cli;

#[path = "proxy_common_measured.rs"]
mod measured_common;

#[path = "proxy_common_measured_policy.rs"]
mod measured_policy;
