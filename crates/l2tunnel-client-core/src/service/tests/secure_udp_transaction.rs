//! Actual complete-configuration service, local API and original-socket owners.
//!
//! No privileged/native qualification or cross-profile SW-11 claim. This child
//! deliberately disables periodic reports: Applied must follow an actual final
//! runtime observation, rather than borrowing a later timer report.

use super::*;
use crate::secure_udp::{transaction_profile, transaction_status};
use l2tunnel::swift_configuration::{Catalog, Configuration, Descriptor};
use l2tunnel_management::{control_streams, delivery, messages, transaction};
use l2tunnel_runtime::secure_udp::transport;

#[path = "secure_udp_transaction_failures.rs"]
mod command_failures;
#[path = "secure_udp_transaction_lifecycle.rs"]
mod lifecycle_failures;
#[path = "secure_udp_transaction_setup.rs"]
mod setup_failures;
#[path = "secure_udp_transaction_support.rs"]
mod support;

#[derive(Clone, Copy)]
struct TransactionFixtureOptions {
    setup_timeout: Duration,
    noise_profile: hs::Profile,
    psk: [Option<[u8; 32]>; 2],
    admission: [[u8; 32]; 2],
    retained_bytes: usize,
    report_interval: Option<Duration>,
}
impl TransactionFixtureOptions {
    fn baseline() -> Self {
        Self {
            setup_timeout: Duration::from_secs(3),
            noise_profile: hs::Profile::Ik,
            psk: [None, None],
            admission: [[44; 32]; 2],
            retained_bytes: 16 * 1024 * 1024,
            report_interval: None,
        }
    }
}

struct TransactionPlans {
    plans: [Prepared; 2],
    addresses: [std::net::SocketAddr; 2],
    profile: transaction_profile::Profile,
    initial: Configuration,
    target: Configuration,
    outside: Configuration,
}

fn streamed(mut value: transport::Config) -> transport::Config {
    let entry = messages::Settings {
        delivery: delivery::Settings {
            wire_overhead: value.control.wire_overhead + control_streams::HEADER_BYTES,
            ..value.control
        },
        path_mtu: value.path_mtu,
        max_message_bytes: 4096,
        max_outbound_messages: 4,
        max_outbound_bytes: 131_072,
        max_fragments: 32,
        max_reassembly_bytes: 16_384,
        max_incomplete_messages: 2,
        message_lifetime: Duration::from_secs(5),
        work_per_call: 8,
    };
    value.streams = Some(l2tunnel_runtime::secure_udp::control::Settings {
        streams: [entry; 3],
    });
    value.report_interval = None;
    value.lifetime.ping_interval = Duration::from_millis(10);
    value
}

fn transaction_plans(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
) -> Result<TransactionPlans> {
    transaction_plans_with(appearance, hosts, TransactionFixtureOptions::baseline())
}

fn transaction_plans_with(
    appearance: l2tunnel_cover::Appearance,
    hosts: &[Arc<Host>; 2],
    options: TransactionFixtureOptions,
) -> Result<TransactionPlans> {
    let held = [
        crate::test_ports::reserve(false)?,
        crate::test_ports::reserve(false)?,
    ];
    let addresses = [held[0].local_addr()?, held[1].local_addr()?];
    let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
    let member = identity::IdentityKey::from_pkcs8(&encoded)?;
    let (legacy, peers) = crate::secure_udp::profile::tests::fixture(
        l2tunnel_udp_control::Path {
            client: addresses[0],
            server: addresses[1],
        },
        appearance,
        member.public_key(),
    )?;
    let mut settings = legacy.settings();
    settings.application = l2tunnel_core::ConfigDigest([31; 32]);
    settings.profile = options.noise_profile;
    let mut connection = legacy.connection();
    connection.handshake_timeout = options.setup_timeout;
    let mut initiator = streamed(legacy.runtime(Role::Initiator));
    let mut responder = streamed(legacy.runtime(Role::Responder));
    initiator.report_interval = options.report_interval;
    responder.report_interval = options.report_interval;
    let mut forward = initiator.send;
    let mut reverse = initiator.receive;
    // Finite integration geometry, separate from the CLI's production capacity.
    // The real reserved engine must provision this whole selected pool.
    forward.records.codec.flow_sources = 64;
    reverse.records.codec.flow_sources = 64;
    forward.records.codec.queue_bytes = 65_536;
    reverse.records.codec.queue_bytes = 65_536;
    forward.records.channels = 2;
    reverse.records.channels = 3;
    forward.records.codec.window = 7;
    reverse.records.codec.window = 11;
    forward.records.codec.repair_numerator = 1;
    forward.records.codec.repair_denominator = 3;
    reverse.records.codec.repair_numerator = 2;
    reverse.records.codec.repair_denominator = 7;
    let initial_descriptor = Descriptor::new(1500, forward, reverse)?;
    forward.records.channels = 4;
    reverse.records.channels = 1;
    let target_descriptor = Descriptor::new(1500, forward, reverse)?;
    let engine_bytes = l2tunnel_swift::storage::Plan::for_engine(
        initial_descriptor.forward().records,
        initial_descriptor.reverse().records,
    )?
    .capacity_bytes()
        + l2tunnel_swift::storage::Plan::for_engine(
            target_descriptor.forward().records,
            target_descriptor.reverse().records,
        )?
        .capacity_bytes();
    assert!(
        engine_bytes < 16 * 1024 * 1024,
        "fixture engines require {engine_bytes} bytes"
    );
    forward.bytes_per_second = forward
        .bytes_per_second
        .checked_add(1)
        .ok_or("rate exhausted")?;
    let outside_descriptor = Descriptor::new(1500, forward, reverse)?;
    initiator.send = initial_descriptor.forward();
    initiator.receive = initial_descriptor.reverse();
    responder.send = initial_descriptor.reverse();
    responder.receive = initial_descriptor.forward();
    let profile = transaction_profile::Profile::new(
        connection,
        settings,
        peers,
        initiator,
        responder,
        Catalog::new(initial_descriptor, &[initial_descriptor, target_descriptor])?,
        transaction_profile::Parameters {
            protocol: transaction::Settings {
                retry_ms: 10,
                phase_timeout_ms: 500,
                reconcile_timeout_ms: 1000,
            },
            max_operation_ms: 1500,
            retained_bytes: options.retained_bytes,
        },
    )?;
    let initial = profile.initial();
    let target = Configuration::new(profile.envelope(), target_descriptor)?;
    let outside = Configuration::new(profile.envelope(), outside_descriptor)?;
    for role in [Role::Initiator, Role::Responder] {
        assert_eq!(
            profile.runtime_contract(role)?.config().report_interval,
            options.report_interval
        );
    }
    let client_noise = credentials::NoiseIdentity::new(
        Zeroizing::new([11; 32]),
        peers.responder,
        options.noise_profile,
        options.psk[0].map(Zeroizing::new),
    )?;
    let server_noise = credentials::NoiseIdentity::new(
        Zeroizing::new([22; 32]),
        peers.initiator,
        options.noise_profile,
        options.psk[1].map(Zeroizing::new),
    )?;
    let client = Prepared::secure_udp_transaction_client(
        profile.clone(),
        credentials::Client::new(
            client_noise,
            member,
            credentials::Secret32::new(Zeroizing::new(options.admission[0]))?,
        )?,
        hosts[0].attachment(),
    )?;
    let server = Prepared::secure_udp_transaction_server(
        profile.clone(),
        credentials::Server::new(
            server_noise,
            credentials::Secret32::new(Zeroizing::new(options.admission[1]))?,
            credentials::Secret32::new(Zeroizing::new([55; 32]))?,
        )?,
        hosts[1].attachment(),
    )?;
    drop(held);
    Ok(TransactionPlans {
        plans: [client, server],
        addresses,
        profile,
        initial,
        target,
        outside,
    })
}

fn v3(action: local::Action) -> local::Request {
    local::Request {
        version: local::TRANSACTION_VERSION,
        action,
    }
}

fn status(handle: &Handle) -> Result<transaction_status::Status> {
    handle
        .snapshot()
        .runtime
        .as_ref()
        .and_then(Observation::secure_udp_transaction)
        .ok_or_else(|| io::Error::other("missing actual transaction frame"))?
        .status()
        .map_err(Into::into)
}

fn transaction_response(response: &local::Response) -> Result<&transaction_status::Status> {
    assert_eq!(response.version, local::TRANSACTION_VERSION);
    assert!(response.ok, "transaction response rejected: {response:?}");
    let state = response
        .state
        .as_ref()
        .ok_or("missing local transaction state")?;
    assert!(state.secure_udp.is_none() && state.swift.is_none());
    state
        .transaction
        .as_ref()
        .ok_or_else(|| "missing separate transaction DTO".into())
}

fn assert_current(
    value: &transaction_status::Status,
    expected: Configuration,
    epoch: u64,
) -> Result {
    assert!(value.running && value.configuration_change);
    assert_eq!(value.epoch, Some(epoch));
    assert_eq!(
        value
            .current
            .as_ref()
            .map(transaction_status::CanonicalConfiguration::configuration)
            .transpose()?,
        Some(expected)
    );
    assert_eq!(value.physical_scope.map(|scope| scope.epoch), Some(epoch));
    assert_eq!(value.phase, Some(transaction_status::Phase::Idle));
    assert!(value.operation.is_none());
    assert!(!value.cross_profile_switching && !value.retained_state_recovery && !value.fresh_rekey);
    Ok(())
}

async fn expect_follower_current(handle: &Handle, expected: Configuration, epoch: u64) -> Result {
    let mut changed = handle.subscribe();
    timeout(Duration::from_secs(3), async {
        loop {
            let actual = status(handle)?;
            if actual.epoch == Some(epoch)
                && actual.phase == Some(transaction_status::Phase::Idle)
                && actual.operation.is_none()
            {
                return assert_current(&actual, expected, epoch);
            }
            changed.changed().await?;
        }
    })
    .await?
}

fn channel_packet(channel: usize, width: usize, marker: u8) -> Result<Vec<u8>> {
    for port in 1..=u16::MAX {
        let mut bytes = packet(marker, 512);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        if l2tunnel_swift::flow::classify_ip(&bytes, width) == channel {
            return Ok(bytes);
        }
    }
    Err("bounded classifier search found no packet for channel".into())
}

async fn every_channel(hosts: &[Arc<Host>; 2], widths: [usize; 2], marker: u8) -> Result {
    for side in 0..2 {
        for channel in 0..widths[side] {
            let bytes = channel_packet(channel, widths[side], marker.wrapping_add(channel as u8))?;
            hosts[side].send(&bytes)?;
            hosts[1 - side].expect(&bytes).await?;
        }
    }
    Ok(())
}

fn assert_no_native_replay(host: &Host) -> Result {
    let application = host
        .application
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut bytes = [0; 1601];
    let error = application
        .as_ref()
        .ok_or("native attachment missing")?
        .recv(&mut bytes)
        .err()
        .ok_or("unexpected duplicate native output")?;
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    Ok(())
}

#[tokio::test]
async fn actual_transaction_service_switches_twice_without_periodic_reports_and_reconnects()
-> Result {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let hosts = [Arc::new(Host::default()), Arc::new(Host::default())];
        let TransactionPlans {
            plans: [client_plan, server_plan],
            addresses,
            profile,
            initial,
            target,
            outside,
        } = transaction_plans(appearance, &hosts)?;
        assert!(
            hosts
                .iter()
                .all(|host| host.opened.load(Ordering::SeqCst) == 0)
        );
        let (client, client_run) = channel();
        let (server, server_run) = channel();
        let client_task = tokio::spawn(client_run);
        let server_task = tokio::spawn(server_run);
        let a = client
            .connect(client_plan.clone(), client.next_key().map_err(submit)?)
            .map_err(submit)?;
        let b = server
            .connect(server_plan.clone(), server.next_key().map_err(submit)?)
            .map_err(submit)?;
        let (a, b) = tokio::try_join!(connected(&client, a), connected(&server, b))?;
        let retained_admission = admission_identity(&server_plan).await?;
        let before = status(&client)?;
        let first_epoch = before.epoch.ok_or("missing original epoch")?;
        assert_current(&before, initial, first_epoch)?;
        assert_eq!(before.configuration, profile.configuration()?.0);
        assert_eq!(
            (before.local, before.peer),
            (addresses[0].to_string(), addresses[1].to_string())
        );
        let old_session = before.session;
        let old_transcript = before.transcript;
        let old_setup = client.setup_observation(a).map_err(submit)?;
        for version in [local::VERSION, local::SECURE_UDP_VERSION] {
            let next = client.next_key().map_err(submit)?;
            let refused = client
                .lifecycle_request(local::Request {
                    version,
                    action: local::Action::Disconnect {},
                })
                .await;
            assert_eq!(refused.code, "requires_version_3");
            assert!(refused.state.is_none());
            assert_eq!(client.next_key().map_err(submit)?, next);
            assert_eq!(client.snapshot().generation, Some(a));
            assert_eq!(hosts[0].live.load(Ordering::SeqCst), 1);
        }
        // A checked but unsupported complete C is refused before key admission.
        let key = client.next_key().map_err(submit)?;
        assert_eq!(
            client.apply_transaction(outside, key),
            Err(SubmitError::InvalidConfiguration)
        );
        assert_eq!(client.next_key().map_err(submit)?, key);
        assert_eq!(status(&client)?.epoch, Some(first_epoch));
        every_channel(&hosts, [2, 3], 31).await?;
        // Let the actual fixed-control challenge run; the final report below is
        // the observation, not this delay or an inferred liveness success.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let accepted = client.apply_transaction(target, key).map_err(submit)?;
        assert_eq!(
            client.apply_transaction(target, key).map_err(submit)?,
            accepted
        );
        assert_eq!(
            client.apply_transaction(initial, key),
            Err(SubmitError::Conflict)
        );
        let completed = timeout(Duration::from_secs(3), client.wait(accepted.operation))
            .await?
            .map_err(submit)?;
        let Completed::Applied(first) = completed else {
            return Err(format!("actual first switch did not apply: {completed:?}").into());
        };
        let observed = transaction_response(&first)?;
        assert_current(observed, target, first_epoch + 1)?;
        assert!(
            observed
                .liveness
                .as_ref()
                .and_then(|value| value.last_pong_micros)
                .is_some()
        );
        assert_eq!(
            client.apply_transaction(target, key).map_err(submit)?,
            accepted
        );
        assert_eq!(
            client.wait(accepted.operation).await.map_err(submit)?,
            Completed::Applied(first.clone())
        );
        assert_current(&status(&client)?, target, first_epoch + 1)?;
        expect_follower_current(&server, target, first_epoch + 1).await?;
        every_channel(&hosts, [4, 1], 71).await?;

        // Actual bounded Unix local transport, not serde-only DTO evidence.
        let directory = ApiDirectory::new()?;
        let api_path = directory.0.join("transaction-api.sock");
        let api = local::Server::bind(&api_path)?;
        let api_handle = client.clone();
        let api_task = tokio::spawn(async move {
            api.serve(move |request| {
                let handle = api_handle.clone();
                async move { handle.lifecycle_request(request).await }
            })
            .await
        });
        let wire_status = local::request(&api_path, &v3(local::Action::Status {})).await?;
        assert_current(transaction_response(&wire_status)?, target, first_epoch + 1)?;
        let switched = timeout(
            Duration::from_secs(3),
            local::request(
                &api_path,
                &v3(local::Action::SwitchSwiftConfiguration {
                    configuration: transaction_status::CanonicalConfiguration::from_configuration(
                        initial,
                    )?,
                }),
            ),
        )
        .await??;
        assert_current(transaction_response(&switched)?, initial, first_epoch + 2)?;
        expect_follower_current(&server, initial, first_epoch + 2).await?;
        every_channel(&hosts, [2, 3], 111).await?;
        for host in &hosts {
            assert_no_native_replay(host)?;
        }

        let (left, right) = tokio::join!(
            client.lifecycle_request(v3(local::Action::Disconnect {})),
            server.lifecycle_request(v3(local::Action::Disconnect {})),
        );
        assert!(
            left.ok && right.ok,
            "actual release failed: {left:?} {right:?}"
        );
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        assert_eq!(
            client.wait_stopped(a).await.map_err(submit)?,
            Terminal::Aborted
        );
        assert_eq!(
            server.wait_stopped(b).await.map_err(submit)?,
            Terminal::Aborted
        );
        let stopped_frame = client
            .snapshot()
            .runtime
            .as_ref()
            .and_then(Observation::secure_udp_transaction)
            .ok_or("missing retained stopped generic frame")?
            .clone();
        let stopped_status = stopped_frame.status()?;
        assert!(!stopped_status.running);
        assert_eq!(stopped_status.service_terminal.as_deref(), Some("Aborted"));
        assert_eq!(
            stopped_status
                .current
                .as_ref()
                .map(transaction_status::CanonicalConfiguration::configuration)
                .transpose()?,
            Some(initial)
        );
        let held = [
            std::net::UdpSocket::bind(addresses[0])?,
            std::net::UdpSocket::bind(addresses[1])?,
        ];
        drop(held);
        let (left, right) = tokio::join!(
            client.lifecycle_request(v3(local::Action::Reconnect {})),
            server.lifecycle_request(v3(local::Action::Reconnect {})),
        );
        assert!(
            left.ok && right.ok,
            "actual fresh reconnect failed: {left:?} {right:?}"
        );
        let fresh = transaction_response(&left)?;
        assert_current(fresh, initial, first_epoch)?;
        assert_ne!(fresh.session, old_session);
        assert_ne!(fresh.transcript, old_transcript);
        assert!(fresh.generation > a.value());
        assert_eq!(admission_identity(&server_plan).await?, retained_admission);
        assert_eq!(client.setup_observation(a).map_err(submit)?, old_setup);
        assert_eq!(stopped_frame.status()?, stopped_status);
        assert!(
            hosts
                .iter()
                .all(|host| host.opened.load(Ordering::SeqCst) == 2
                    && host.live.load(Ordering::SeqCst) == 1)
        );
        for host in &hosts {
            assert_no_native_replay(host)?;
        }
        every_channel(&hosts, [2, 3], 151).await?;
        api_task.abort();
        let _ = api_task.await;
        client_task.abort();
        server_task.abort();
        let _ = tokio::join!(client_task, server_task);
        assert!(
            hosts
                .iter()
                .all(|host| host.live.load(Ordering::SeqCst) == 0)
        );
        for handle in [&client, &server] {
            let value = status(handle)?;
            assert!(!value.running);
            assert_eq!(value.service_terminal.as_deref(), Some("Aborted"));
        }
    }
    Ok(())
}
